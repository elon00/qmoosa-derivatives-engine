import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DerivativesEngine,
  AuthManager,
  WAD,
  FUNDING_INTERVAL_MS,
  DEFAULT_CHAIN_ID,
  DEFAULT_CONTRACT_ADDRESS
} from "../dist/index.js";

// Generate asymmetric keypairs for privileged roles
const adminKeys = AuthManager.generateKeyPair();
const oracleKeys = AuthManager.generateKeyPair();
const keeperKeys = AuthManager.generateKeyPair();

function createTestEngine() {
  return new DerivativesEngine({
    adminPublicKey: adminKeys.publicKey,
    oraclePublicKey: oracleKeys.publicKey,
    keeperPublicKey: keeperKeys.publicKey
  });
}

function createEnrolledUser(engine) {
  const account = AuthManager.generateAccountKeyPair();
  const operational = AuthManager.generateKeyPair();
  const proof = engine.auth.createEnrollmentProof(
    account.address,
    account.publicKey,
    account.privateKey,
    operational.publicKey,
    operational.privateKey
  );
  engine.auth.enrollAccount(proof);
  return { account, operational, address: account.address };
}

function registerTestMarket(engine, symbol = "ETH-USD", initialPrice = 3000n * WAD, insurance = 10_000n * WAD, timestamp = 0) {
  const intent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "ADMIN",
    "REGISTER_MARKET",
    {
      symbol: symbol.toUpperCase(),
      initialPrice,
      maintenanceMarginBps: 500n,
      initialInsuranceFundUsd: insurance,
      initialTimestamp: timestamp
    },
    adminKeys.privateKey
  );

  return engine.registerMarket({
    signedIntent: intent,
    symbol,
    initialPrice,
    maintenanceMarginBps: 500n,
    initialInsuranceFundUsd: insurance,
    initialTimestamp: timestamp
  });
}

test("1. Defensive copy integrity: mutating returned references does not corrupt engine state", () => {
  const engine = createTestEngine();
  registerTestMarket(engine, "ETH-USD", 3000n * WAD);

  // Enroll Alice with dual cryptographic proof
  const alice = createEnrolledUser(engine);

  const openParams = {
    account: alice.address,
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  };

  const intent = engine.auth.signIntent(
    engine.domain,
    alice.address,
    alice.address,
    "OPEN_POSITION",
    openParams,
    alice.operational.privateKey
  );

  const pos = engine.openPosition({
    signedIntent: intent,
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  // Attempt external mutation of returned reference
  pos.collateral = 999_999n * WAD;
  pos.size = 100n * WAD;

  const internalPos = engine.getPosition(pos.id);
  assert.equal(internalPos.collateral, 300n * WAD, "Internal collateral must remain immutable");
  assert.equal(internalPos.size, 1n * WAD, "Internal size must remain immutable");

  // Attempt market mutation
  const m = engine.getMarket("ETH-USD");
  m.markPrice = 1n * WAD;
  const internalMarket = engine.getMarket("ETH-USD");
  assert.equal(internalMarket.markPrice, 3000n * WAD, "Internal market price must remain immutable");
});

test("2. Verifiable account enrollment with cryptographic ownership proof (P0)", () => {
  const engine = createTestEngine();
  const aliceAccount = AuthManager.generateAccountKeyPair();
  const aliceOperational = AuthManager.generateKeyPair();

  const attackerAccount = AuthManager.generateAccountKeyPair();
  const attackerOperational = AuthManager.generateKeyPair();

  const now = Date.now();

  // Attack 1: Account takeover attempt — Attacker generates their own operational Ed25519 key
  // and attempts to bind it to Alice's address without Alice's secp256k1 signature
  const hostileTakeoverProof = {
    account: aliceAccount.address,
    accountPublicKey: attackerAccount.publicKey, // Attacker's secp256k1 key
    accountSignature: AuthManager.signAccountMessage(
      AuthManager.computeBindingChallenge(aliceAccount.address, attackerOperational.publicKey, now),
      attackerAccount.privateKey
    ),
    publicKey: attackerOperational.publicKey,
    enrollmentSignature: AuthManager.signMessage(
      AuthManager.computeEnrollmentChallenge(aliceAccount.address, now),
      attackerOperational.privateKey
    ),
    timestamp: now
  };

  // Must reject: attackerAccount public key does not derive to Alice's address
  assert.throws(() => {
    engine.auth.enrollAccount(hostileTakeoverProof);
  }, /ACCOUNT_OWNERSHIP_PROOF_INVALID: Claimed account/);

  // Attack 2: Attacker claims victim's address and victim's account public key, but provides forged account signature
  const forgedAccountSigProof = {
    account: aliceAccount.address,
    accountPublicKey: aliceAccount.publicKey,
    accountSignature: "deadbeef00112233445566778899aabbccddeeff",
    publicKey: attackerOperational.publicKey,
    enrollmentSignature: AuthManager.signMessage(
      AuthManager.computeEnrollmentChallenge(aliceAccount.address, now),
      attackerOperational.privateKey
    ),
    timestamp: now
  };

  assert.throws(() => {
    engine.auth.enrollAccount(forgedAccountSigProof);
  }, /ACCOUNT_OWNERSHIP_PROOF_INVALID: Invalid account owner authorization signature/);

  // Attack 3: Forged operational key possession signature
  const legitimateBindSig = AuthManager.signAccountMessage(
    AuthManager.computeBindingChallenge(aliceAccount.address, aliceOperational.publicKey, now),
    aliceAccount.privateKey
  );
  const forgedPossessionProof = {
    account: aliceAccount.address,
    accountPublicKey: aliceAccount.publicKey,
    accountSignature: legitimateBindSig,
    publicKey: aliceOperational.publicKey,
    enrollmentSignature: "deadbeef112233",
    timestamp: now
  };

  assert.throws(() => {
    engine.auth.enrollAccount(forgedPossessionProof);
  }, /Cryptographic enrollment verification failed: signature does not prove ownership of public key/);

  // Attack 4: Expired enrollment proof is rejected
  const expiredProof = engine.auth.createEnrollmentProof(
    aliceAccount.address,
    aliceAccount.publicKey,
    aliceAccount.privateKey,
    aliceOperational.publicKey,
    aliceOperational.privateKey,
    Date.now() - 400_000 // 6.6 minutes ago
  );

  assert.throws(() => {
    engine.auth.enrollAccount(expiredProof);
  }, /Enrollment proof timestamp expired/);

  // Legitimate enrollment succeeds: dual-signed by account owner (secp256k1) and operational key (Ed25519)
  const legitimateProof = engine.auth.createEnrollmentProof(
    aliceAccount.address,
    aliceAccount.publicKey,
    aliceAccount.privateKey,
    aliceOperational.publicKey,
    aliceOperational.privateKey
  );
  engine.auth.enrollAccount(legitimateProof);
  assert.equal(engine.auth.isAccountEnrolled(aliceAccount.address), true);

  // Attack 5: Hostile takeover / re-registration of enrolled account is strictly blocked
  assert.throws(() => {
    engine.auth.enrollAccount(legitimateProof);
  }, /already enrolled; re-enrollment without key rotation proof is prohibited/);
});

test("3. Privileged role authorization with asymmetric cryptographic signatures (P0)", () => {
  const engine = createTestEngine();
  const imposterKeys = AuthManager.generateKeyPair();

  // Attack: Imposter attempts to register market with forged admin signature
  const forgedAdminIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "ADMIN",
    "REGISTER_MARKET",
    {
      symbol: "BTC-USD",
      initialPrice: 60000n * WAD,
      maintenanceMarginBps: 500n,
      initialInsuranceFundUsd: 10_000n * WAD,
      initialTimestamp: 0
    },
    imposterKeys.privateKey // Signed with imposter private key
  );

  assert.throws(() => {
    engine.registerMarket({
      signedIntent: forgedAdminIntent,
      symbol: "BTC-USD",
      initialPrice: 60000n * WAD,
      maintenanceMarginBps: 500n,
      initialInsuranceFundUsd: 10_000n * WAD,
      initialTimestamp: 0
    });
  }, /Cryptographic verification failed: invalid signature for privileged role ADMIN/);

  // Attack: Imposter attempts to update prices with forged oracle signature
  registerTestMarket(engine, "ETH-USD", 3000n * WAD);
  const forgedOracleIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "ORACLE",
    "UPDATE_PRICES",
    {
      symbol: "ETH-USD",
      markPrice: 3500n * WAD,
      indexPrice: 3490n * WAD
    },
    imposterKeys.privateKey
  );

  assert.throws(() => {
    engine.updatePrices({
      signedIntent: forgedOracleIntent,
      symbol: "ETH-USD",
      markPrice: 3500n * WAD,
      indexPrice: 3490n * WAD
    });
  }, /Cryptographic verification failed: invalid signature for privileged role ORACLE/);

  // Attack: Imposter attempts to settle funding with forged keeper signature
  const forgedKeeperIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "KEEPER",
    "SETTLE_FUNDING",
    {
      symbol: "ETH-USD",
      currentTimestamp: 100_000
    },
    imposterKeys.privateKey
  );

  assert.throws(() => {
    engine.settleFunding({
      signedIntent: forgedKeeperIntent,
      symbol: "ETH-USD",
      currentTimestamp: 100_000
    });
  }, /Cryptographic verification failed: invalid signature for privileged role KEEPER/);
});

test("4. Operator approval security & actor authorization model with cryptographic intents", () => {
  const engine = createTestEngine();
  registerTestMarket(engine, "ETH-USD", 3000n * WAD);

  const alice = createEnrolledUser(engine);
  const attacker = createEnrolledUser(engine);
  const broker = createEnrolledUser(engine);

  // Security test P0: Third party caller cannot sign an operator approval for another account
  const attackerForgedIntent = engine.auth.signIntent(
    engine.domain,
    alice.address,
    attacker.address,
    "SET_OPERATOR",
    { account: alice.address, operator: broker.address, approved: true },
    attacker.operational.privateKey
  );

  assert.throws(() => {
    engine.setApprovedOperator({
      signedIntent: attackerForgedIntent,
      operator: broker.address,
      approved: true
    });
  }, /Unauthorized operator approval/);

  // Security test P0: Attacker cannot sign an intent where caller === alice with attacker's key
  const attackerSigningAsAlice = engine.auth.signIntent(
    engine.domain,
    alice.address,
    alice.address,
    "SET_OPERATOR",
    { account: alice.address, operator: broker.address, approved: true },
    attacker.operational.privateKey
  );

  assert.throws(() => {
    engine.setApprovedOperator({
      signedIntent: attackerSigningAsAlice,
      operator: broker.address,
      approved: true
    });
  }, /Cryptographic signature verification failed: invalid signature/);

  // Legitimate approval by Alice for Broker
  const aliceIntent = engine.auth.signIntent(
    engine.domain,
    alice.address,
    alice.address,
    "SET_OPERATOR",
    { account: alice.address, operator: broker.address, approved: true },
    alice.operational.privateKey
  );

  engine.setApprovedOperator({
    signedIntent: aliceIntent,
    operator: broker.address,
    approved: true
  });

  assert.equal(engine.isAuthorizedCaller(alice.address, broker.address), true);

  // Alice opens a position
  const openParams = {
    account: alice.address,
    symbol: "ETH-USD",
    isLong: true,
    size: 2n * WAD,
    collateral: 600n * WAD,
    leverage: 10n
  };

  const aliceOpenIntent = engine.auth.signIntent(
    engine.domain,
    alice.address,
    alice.address,
    "OPEN_POSITION",
    openParams,
    alice.operational.privateKey
  );

  const pos = engine.openPosition({ signedIntent: aliceOpenIntent, ...openParams });

  // Unapproved attacker attempts to close Alice's position
  const unapprovedCloseIntent = engine.auth.signIntent(
    engine.domain,
    alice.address,
    attacker.address,
    "CLOSE_POSITION",
    { account: alice.address, positionId: pos.id },
    alice.operational.privateKey
  );

  assert.throws(() => {
    engine.closePosition({
      signedIntent: unapprovedCloseIntent,
      positionId: pos.id
    });
  }, /is not authorized for account/);

  // Approved broker closes position on Alice's behalf
  const brokerCloseIntent = engine.auth.signIntent(
    engine.domain,
    alice.address,
    broker.address,
    "CLOSE_POSITION",
    { account: alice.address, positionId: pos.id },
    alice.operational.privateKey
  );

  const receipt = engine.closePosition({ signedIntent: brokerCloseIntent, positionId: pos.id });
  assert.equal(receipt.positionId, pos.id);
  assert.equal(receipt.account, alice.address.toLowerCase());
});

test("5. Cryptographic signature verification, replay defense, and domain binding", () => {
  const engine = createTestEngine();
  registerTestMarket(engine, "ETH-USD", 3000n * WAD);

  const alice = createEnrolledUser(engine);

  const openParams = {
    account: alice.address,
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  };

  const intent = engine.auth.signIntent(
    engine.domain,
    alice.address,
    alice.address,
    "OPEN_POSITION",
    openParams,
    alice.operational.privateKey,
    Date.now() + 60_000
  );

  // 1. First execution succeeds
  const pos = engine.openPosition({ signedIntent: intent, ...openParams });
  assert.ok(pos.id);

  // 2. Replay attack: Re-submitting the exact same intent must fail
  assert.throws(() => {
    engine.openPosition({ signedIntent: intent, ...openParams });
  }, /Invalid nonce: expected 2, got 1/);

  // 3. Domain binding attack: Submitting intent signed for different chain/contract
  const wrongDomain = { chainId: 1, contractAddress: "0xDifferentContract" };
  const wrongDomainIntent = engine.auth.signIntent(
    wrongDomain,
    alice.address,
    alice.address,
    "OPEN_POSITION",
    openParams,
    alice.operational.privateKey,
    Date.now() + 60_000
  );

  assert.throws(() => {
    engine.openPosition({ signedIntent: wrongDomainIntent, ...openParams });
  }, /Domain chainId mismatch/);

  // 4. Parameter tampering attack: Intent signed for 1 ETH, attacker attempts 5 ETH with matching nonce 2
  const signed1EthParams = { ...openParams, size: 1n * WAD };
  const freshIntent = engine.auth.signIntent(
    engine.domain,
    alice.address,
    alice.address,
    "OPEN_POSITION",
    signed1EthParams,
    alice.operational.privateKey,
    Date.now() + 60_000
  );

  const tampered5EthParams = { ...openParams, size: 5n * WAD };
  assert.throws(() => {
    engine.openPosition({ signedIntent: freshIntent, ...tampered5EthParams });
  }, /Parameter hash mismatch/);
});

test("6. Financial correctness: discrete epochs, monotonic timestamps, and atomic rollback on insolvency (P1)", () => {
  const epoch100Time = 100 * FUNDING_INTERVAL_MS;
  const engine = createTestEngine();
  registerTestMarket(engine, "ETH-USD", 3000n * WAD, 10_000n * WAD, epoch100Time);

  const alice = createEnrolledUser(engine);
  const bob = createEnrolledUser(engine);

  // Alice opens Long 1 ETH
  const aliceIntent = engine.auth.signIntent(
    engine.domain,
    alice.address,
    alice.address,
    "OPEN_POSITION",
    { account: alice.address, symbol: "ETH-USD", isLong: true, size: 1n * WAD, collateral: 300n * WAD, leverage: 10n },
    alice.operational.privateKey
  );
  const posAlice = engine.openPosition({
    signedIntent: aliceIntent,
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  // Bob opens Short 0.5 ETH
  const bobIntent = engine.auth.signIntent(
    engine.domain,
    bob.address,
    bob.address,
    "OPEN_POSITION",
    { account: bob.address, symbol: "ETH-USD", isLong: false, size: 5n * (WAD / 10n), collateral: 150n * WAD, leverage: 10n },
    bob.operational.privateKey
  );
  const posBob = engine.openPosition({
    signedIntent: bobIntent,
    symbol: "ETH-USD",
    isLong: false,
    size: 5n * (WAD / 10n),
    collateral: 150n * WAD,
    leverage: 10n
  });

  // Advance to Epoch 101
  const epoch101Time = 101 * FUNDING_INTERVAL_MS;
  const updatePricesIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "ORACLE",
    "UPDATE_PRICES",
    { symbol: "ETH-USD", markPrice: 3050n * WAD, indexPrice: 3000n * WAD },
    oracleKeys.privateKey
  );
  engine.updatePrices({
    signedIntent: updatePricesIntent,
    symbol: "ETH-USD",
    markPrice: 3050n * WAD,
    indexPrice: 3000n * WAD
  });

  const keeperIntent101 = engine.auth.signPrivilegedIntent(
    engine.domain,
    "KEEPER",
    "SETTLE_FUNDING",
    { symbol: "ETH-USD", currentTimestamp: epoch101Time },
    keeperKeys.privateKey
  );
  const receipt101 = engine.settleFunding({
    signedIntent: keeperIntent101,
    symbol: "ETH-USD",
    currentTimestamp: epoch101Time
  });

  assert.equal(receipt101.epoch, 101);
  assert.equal(receipt101.settledPositions, 2);

  // Negative control: Timestamps must be monotonic
  const nonMonotonicKeeperIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "KEEPER",
    "SETTLE_FUNDING",
    { symbol: "ETH-USD", currentTimestamp: epoch101Time - 1000 },
    keeperKeys.privateKey
  );
  assert.throws(() => {
    engine.settleFunding({
      signedIntent: nonMonotonicKeeperIntent,
      symbol: "ETH-USD",
      currentTimestamp: epoch101Time - 1000
    });
  }, /Monotonic timestamp violation/);

  // Negative control & Atomic Rollback: Insolvent Insurance Fund
  registerTestMarket(engine, "SOL-USD", 100n * WAD, 0n, 200 * FUNDING_INTERVAL_MS);
  const charlie = createEnrolledUser(engine);

  const charlieIntent = engine.auth.signIntent(
    engine.domain,
    charlie.address,
    charlie.address,
    "OPEN_POSITION",
    { account: charlie.address, symbol: "SOL-USD", isLong: true, size: 1000n * WAD, collateral: 10_000n * WAD, leverage: 10n },
    charlie.operational.privateKey
  );
  engine.openPosition({
    signedIntent: charlieIntent,
    symbol: "SOL-USD",
    isLong: true,
    size: 1000n * WAD,
    collateral: 10_000n * WAD,
    leverage: 10n
  });

  // Advance to Epoch 201 with negative funding (shorts pay longs, but no shorts exist -> deficit charged to insurance fund)
  const epoch201Time = 201 * FUNDING_INTERVAL_MS;
  const oracleSolIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "ORACLE",
    "UPDATE_PRICES",
    { symbol: "SOL-USD", markPrice: 90n * WAD, indexPrice: 100n * WAD },
    oracleKeys.privateKey
  );
  engine.updatePrices({
    signedIntent: oracleSolIntent,
    symbol: "SOL-USD",
    markPrice: 90n * WAD,
    indexPrice: 100n * WAD
  });

  const insolventKeeperIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "KEEPER",
    "SETTLE_FUNDING",
    { symbol: "SOL-USD", currentTimestamp: epoch201Time },
    keeperKeys.privateKey
  );

  // Fails closed due to insurance fund insolvency
  assert.throws(() => {
    engine.settleFunding({
      signedIntent: insolventKeeperIntent,
      symbol: "SOL-USD",
      currentTimestamp: epoch201Time
    });
  }, /Solvency violation: net funding imbalance/);

  // ATOMIC ROLLBACK VERIFICATION: State must be unchanged
  const solMarketAfter = engine.getMarket("SOL-USD");
  assert.equal(solMarketAfter.insuranceFundBalanceUsd, 0n, "Insurance fund must remain unchanged");
  assert.equal(solMarketAfter.lastSettledEpoch, 200, "Epoch must not advance on failure");
});

test("7. Liquidation of unhealthy position and protection of healthy position", () => {
  const engine = createTestEngine();
  registerTestMarket(engine, "ETH-USD", 3000n * WAD);

  const charlie = createEnrolledUser(engine);
  const liquidator = createEnrolledUser(engine);

  const charlieIntent = engine.auth.signIntent(
    engine.domain,
    charlie.address,
    charlie.address,
    "OPEN_POSITION",
    { account: charlie.address, symbol: "ETH-USD", isLong: true, size: 1n * WAD, collateral: 300n * WAD, leverage: 10n },
    charlie.operational.privateKey
  );

  const pos = engine.openPosition({
    signedIntent: charlieIntent,
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  // Attempt liquidation while position is healthy
  assert.throws(() => {
    engine.liquidatePosition({
      positionId: pos.id,
      liquidator: liquidator.address
    });
  }, /is healthy and cannot be liquidated/);

  // Price plunges to $2750 -> Position margin drops below maintenance margin
  const crashPriceIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "ORACLE",
    "UPDATE_PRICES",
    { symbol: "ETH-USD", markPrice: 2750n * WAD, indexPrice: 2750n * WAD },
    oracleKeys.privateKey
  );
  engine.updatePrices({
    signedIntent: crashPriceIntent,
    symbol: "ETH-USD",
    markPrice: 2750n * WAD,
    indexPrice: 2750n * WAD
  });

  const receipt = engine.liquidatePosition({
    positionId: pos.id,
    liquidator: liquidator.address
  });

  assert.equal(receipt.positionId, pos.id);
  assert.equal(receipt.liquidator, liquidator.address);
  assert.equal(receipt.liquidationPrice, 2750n * WAD);
  assert.throws(() => engine.getPosition(pos.id), /not found/);
});
