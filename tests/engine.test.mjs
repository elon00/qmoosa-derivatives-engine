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

  // Enroll Alice with cryptographic proof
  const aliceKeys = AuthManager.generateKeyPair();
  const proof = engine.auth.createEnrollmentProof("0xAlice", aliceKeys.publicKey, aliceKeys.privateKey);
  engine.auth.enrollAccount(proof);

  const openParams = {
    account: "0xalice",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  };

  const intent = engine.auth.signIntent(
    engine.domain,
    "0xAlice",
    "0xAlice",
    "OPEN_POSITION",
    openParams,
    aliceKeys.privateKey
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

test("2. Verifiable account enrollment with asymmetric cryptographic ownership proof (P0)", () => {
  const engine = createTestEngine();
  const aliceKeys = AuthManager.generateKeyPair();
  const attackerKeys = AuthManager.generateKeyPair();

  // Attack 1: Attacker tries to enroll Alice's account with attacker's key without Alice's signature
  const forgedProof = {
    account: "0xAlice",
    publicKey: attackerKeys.publicKey,
    enrollmentSignature: AuthManager.signMessage("random-fake-signature", attackerKeys.privateKey),
    timestamp: Date.now()
  };

  assert.throws(() => {
    engine.auth.enrollAccount(forgedProof);
  }, /Cryptographic enrollment verification failed/);

  // Attack 2: Expired enrollment proof is rejected
  const expiredProof = engine.auth.createEnrollmentProof(
    "0xAlice",
    aliceKeys.publicKey,
    aliceKeys.privateKey,
    Date.now() - 400_000 // 6.6 minutes ago
  );

  assert.throws(() => {
    engine.auth.enrollAccount(expiredProof);
  }, /Enrollment proof timestamp expired/);

  // Legitimate enrollment succeeds
  const legitimateProof = engine.auth.createEnrollmentProof("0xAlice", aliceKeys.publicKey, aliceKeys.privateKey);
  engine.auth.enrollAccount(legitimateProof);
  assert.equal(engine.auth.isAccountEnrolled("0xAlice"), true);

  // Attack 3: Hostile takeover / re-registration without proof is strictly blocked
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
      symbol: "ETH-USD",
      initialPrice: 3000n * WAD,
      maintenanceMarginBps: 500n,
      initialInsuranceFundUsd: 0n,
      initialTimestamp: 0
    },
    imposterKeys.privateKey
  );

  assert.throws(() => {
    engine.registerMarket({
      signedIntent: forgedAdminIntent,
      symbol: "ETH-USD",
      initialPrice: 3000n * WAD
    });
  }, /Cryptographic verification failed: invalid signature for privileged role ADMIN/);

  // Legitimate Admin registers market
  registerTestMarket(engine, "ETH-USD", 3000n * WAD);

  // Attack: Imposter attempts to update prices
  const forgedOracleIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "ORACLE",
    "UPDATE_PRICES",
    {
      symbol: "ETH-USD",
      markPrice: 3500n * WAD,
      indexPrice: 3500n * WAD
    },
    imposterKeys.privateKey
  );

  assert.throws(() => {
    engine.updatePrices({
      signedIntent: forgedOracleIntent,
      symbol: "ETH-USD",
      markPrice: 3500n * WAD,
      indexPrice: 3500n * WAD
    });
  }, /Cryptographic verification failed: invalid signature for privileged role ORACLE/);

  // Legitimate Oracle updates prices
  const oracleIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "ORACLE",
    "UPDATE_PRICES",
    {
      symbol: "ETH-USD",
      markPrice: 3100n * WAD,
      indexPrice: 3100n * WAD
    },
    oracleKeys.privateKey
  );

  engine.updatePrices({
    signedIntent: oracleIntent,
    symbol: "ETH-USD",
    markPrice: 3100n * WAD,
    indexPrice: 3100n * WAD
  });

  assert.equal(engine.getMarket("ETH-USD").markPrice, 3100n * WAD);

  // Attack: Imposter attempts to settle funding
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

  const aliceKeys = AuthManager.generateKeyPair();
  const attackerKeys = AuthManager.generateKeyPair();
  engine.auth.enrollAccount(engine.auth.createEnrollmentProof("0xAlice", aliceKeys.publicKey, aliceKeys.privateKey));
  engine.auth.enrollAccount(engine.auth.createEnrollmentProof("0xAttacker", attackerKeys.publicKey, attackerKeys.privateKey));

  // Security test P0: Third party cannot sign an operator approval for another account
  const attackerForgedIntent = engine.auth.signIntent(
    engine.domain,
    "0xAlice",
    "0xAttacker",
    "SET_OPERATOR",
    { account: "0xalice", operator: "0xmaliciousbroker", approved: true },
    attackerKeys.privateKey
  );

  assert.throws(() => {
    engine.setApprovedOperator({
      signedIntent: attackerForgedIntent,
      operator: "0xMaliciousBroker",
      approved: true
    });
  }, /Unauthorized operator approval: caller 0xattacker cannot approve operators for 0xalice/);

  // Direct owner legitimately signs operator approval
  const aliceApproveIntent = engine.auth.signIntent(
    engine.domain,
    "0xAlice",
    "0xAlice",
    "SET_OPERATOR",
    { account: "0xalice", operator: "0xbrokerbot", approved: true },
    aliceKeys.privateKey
  );

  engine.setApprovedOperator({
    signedIntent: aliceApproveIntent,
    operator: "0xBrokerBot",
    approved: true
  });

  // Alice opens position
  const openParams = {
    account: "0xalice",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  };

  const openIntent = engine.auth.signIntent(
    engine.domain,
    "0xAlice",
    "0xAlice",
    "OPEN_POSITION",
    openParams,
    aliceKeys.privateKey
  );

  const pos = engine.openPosition({
    signedIntent: openIntent,
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  // Unauthorized third-party cannot close position
  const attackerCloseIntent = engine.auth.signIntent(
    engine.domain,
    "0xAlice",
    "0xAttacker",
    "CLOSE_POSITION",
    { positionId: pos.id, account: "0xalice" },
    attackerKeys.privateKey
  );

  assert.throws(
    () => engine.closePosition({ signedIntent: attackerCloseIntent, positionId: pos.id }),
    /Unauthorized: caller 0xattacker is not authorized for account 0xalice/
  );

  // Approved operator with valid signed intent from Alice can close position
  const brokerCloseIntent = engine.auth.signIntent(
    engine.domain,
    "0xAlice",
    "0xBrokerBot",
    "CLOSE_POSITION",
    { positionId: pos.id, account: "0xalice" },
    aliceKeys.privateKey
  );

  const receipt = engine.closePosition({ signedIntent: brokerCloseIntent, positionId: pos.id });
  assert.equal(receipt.positionId, pos.id);
  assert.equal(receipt.account, "0xalice");
});

test("5. Cryptographic signature verification, replay defense, and domain binding", () => {
  const engine = createTestEngine();
  registerTestMarket(engine, "ETH-USD", 3000n * WAD);

  const aliceKeys = AuthManager.generateKeyPair();
  engine.auth.enrollAccount(engine.auth.createEnrollmentProof("0xAlice", aliceKeys.publicKey, aliceKeys.privateKey));

  const openParams = {
    account: "0xalice",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  };

  const intent = engine.auth.signIntent(
    engine.domain,
    "0xAlice",
    "0xAlice",
    "OPEN_POSITION",
    openParams,
    aliceKeys.privateKey,
    Date.now() + 60_000
  );

  // Legitimate cryptographic execution
  const pos = engine.openPosition({
    signedIntent: intent,
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });
  assert.equal(pos.account, "0xalice");

  // Replay of same signed intent strictly fails closed
  assert.throws(() => {
    engine.openPosition({
      signedIntent: intent,
      symbol: "ETH-USD",
      isLong: true,
      size: 1n * WAD,
      collateral: 300n * WAD,
      leverage: 10n
    });
  }, /Invalid nonce/);

  // Tampered parameters fail closed
  const tamperedIntent = engine.auth.signIntent(
    engine.domain,
    "0xAlice",
    "0xAlice",
    "OPEN_POSITION",
    openParams,
    aliceKeys.privateKey,
    Date.now() + 60_000
  );

  assert.throws(() => {
    engine.openPosition({
      signedIntent: tamperedIntent,
      symbol: "ETH-USD",
      isLong: true,
      size: 50n * WAD, // Tampered size
      collateral: 300n * WAD,
      leverage: 10n
    });
  }, /Parameter hash mismatch/);

  // Domain mismatch test: intent signed for different chain fails closed
  const otherChainDomain = { chainId: 1, contractAddress: engine.domain.contractAddress };
  const wrongChainIntent = engine.auth.signIntent(
    otherChainDomain,
    "0xAlice",
    "0xAlice",
    "OPEN_POSITION",
    openParams,
    aliceKeys.privateKey,
    Date.now() + 60_000
  );

  assert.throws(() => {
    engine.openPosition({
      signedIntent: wrongChainIntent,
      symbol: "ETH-USD",
      isLong: true,
      size: 1n * WAD,
      collateral: 300n * WAD,
      leverage: 10n
    });
  }, /Domain chainId mismatch/);
});

test("6. Financial correctness: discrete epochs, monotonic timestamps, and atomic rollback on insolvency (P1)", () => {
  const epoch100Time = 100 * FUNDING_INTERVAL_MS;
  const engine = createTestEngine();
  registerTestMarket(engine, "ETH-USD", 3000n * WAD, 10_000n * WAD, epoch100Time);

  const aliceKeys = AuthManager.generateKeyPair();
  const bobKeys = AuthManager.generateKeyPair();
  engine.auth.enrollAccount(engine.auth.createEnrollmentProof("0xAlice", aliceKeys.publicKey, aliceKeys.privateKey));
  engine.auth.enrollAccount(engine.auth.createEnrollmentProof("0xBob", bobKeys.publicKey, bobKeys.privateKey));

  // Alice opens Long 1 ETH
  const aliceIntent = engine.auth.signIntent(
    engine.domain,
    "0xAlice",
    "0xAlice",
    "OPEN_POSITION",
    { account: "0xalice", symbol: "ETH-USD", isLong: true, size: 1n * WAD, collateral: 300n * WAD, leverage: 10n },
    aliceKeys.privateKey
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
    "0xBob",
    "0xBob",
    "OPEN_POSITION",
    { account: "0xbob", symbol: "ETH-USD", isLong: false, size: 1n * (WAD / 2n), collateral: 150n * WAD, leverage: 10n },
    bobKeys.privateKey
  );
  const posBob = engine.openPosition({
    signedIntent: bobIntent,
    symbol: "ETH-USD",
    isLong: false,
    size: 1n * (WAD / 2n),
    collateral: 150n * WAD,
    leverage: 10n
  });

  // Oracle updates prices
  const oracleIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "ORACLE",
    "UPDATE_PRICES",
    { symbol: "ETH-USD", markPrice: 3030n * WAD, indexPrice: 3000n * WAD },
    oracleKeys.privateKey
  );
  engine.updatePrices({ signedIntent: oracleIntent, symbol: "ETH-USD", markPrice: 3030n * WAD, indexPrice: 3000n * WAD });

  // Monotonic timestamp check: settling in past timestamp fails
  const pastKeeperIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "KEEPER",
    "SETTLE_FUNDING",
    { symbol: "ETH-USD", currentTimestamp: epoch100Time },
    keeperKeys.privateKey
  );
  assert.throws(() => {
    engine.settleFunding({ signedIntent: pastKeeperIntent, symbol: "ETH-USD", currentTimestamp: epoch100Time });
  }, /Monotonic timestamp violation/);

  // Attempt settlement within same epoch: skipped
  const earlyTime = epoch100Time + (2 * 60 * 60 * 1000);
  const earlyKeeperIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "KEEPER",
    "SETTLE_FUNDING",
    { symbol: "ETH-USD", currentTimestamp: earlyTime },
    keeperKeys.privateKey
  );
  const resEarly = engine.settleFunding({ signedIntent: earlyKeeperIntent, symbol: "ETH-USD", currentTimestamp: earlyTime });
  assert.equal(resEarly.status, "SKIPPED_INTERVAL_NOT_ELAPSED");

  // Settle in next epoch (Epoch 101)
  const epoch101Time = 101 * FUNDING_INTERVAL_MS;
  const keeperIntent101 = engine.auth.signPrivilegedIntent(
    engine.domain,
    "KEEPER",
    "SETTLE_FUNDING",
    { symbol: "ETH-USD", currentTimestamp: epoch101Time },
    keeperKeys.privateKey
  );
  const res101 = engine.settleFunding({ signedIntent: keeperIntent101, symbol: "ETH-USD", currentTimestamp: epoch101Time });
  assert.equal(res101.status, "SETTLED");
  assert.equal(res101.epoch, 101);

  // Invariant assertion: insurance fund gained net imbalance
  const marketAfter = engine.getMarket("ETH-USD");
  assert.equal(marketAfter.insuranceFundBalanceUsd, 10_000n * WAD + res101.netImbalanceToInsuranceFund);

  // Negative control: Atomic rollback on insolvency
  // Create an insolvent market situation
  const epoch200Time = 200 * FUNDING_INTERVAL_MS;
  registerTestMarket(engine, "SOL-USD", 200n * WAD, 0n, epoch200Time); // 0 insurance fund

  const solShortIntent = engine.auth.signIntent(
    engine.domain,
    "0xAlice",
    "0xAlice",
    "OPEN_POSITION",
    { account: "0xalice", symbol: "SOL-USD", isLong: false, size: 10n * WAD, collateral: 200n * WAD, leverage: 10n },
    aliceKeys.privateKey
  );
  const solPos = engine.openPosition({
    signedIntent: solShortIntent,
    symbol: "SOL-USD",
    isLong: false,
    size: 10n * WAD,
    collateral: 200n * WAD,
    leverage: 10n
  });

  // Mark trades at premium -> Short should be credited by insurance fund, but insurance fund is 0!
  const solOracle = engine.auth.signPrivilegedIntent(
    engine.domain,
    "ORACLE",
    "UPDATE_PRICES",
    { symbol: "SOL-USD", markPrice: 210n * WAD, indexPrice: 200n * WAD },
    oracleKeys.privateKey
  );
  engine.updatePrices({ signedIntent: solOracle, symbol: "SOL-USD", markPrice: 210n * WAD, indexPrice: 200n * WAD });

  const epoch201Time = 201 * FUNDING_INTERVAL_MS;
  const solKeeperIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "KEEPER",
    "SETTLE_FUNDING",
    { symbol: "SOL-USD", currentTimestamp: epoch201Time },
    keeperKeys.privateKey
  );

  // Assert atomic failure: must throw Solvency violation
  assert.throws(() => {
    engine.settleFunding({ signedIntent: solKeeperIntent, symbol: "SOL-USD", currentTimestamp: epoch201Time });
  }, /Solvency violation/);

  // CRITICAL ATOMICITY CHECK: Assert zero state mutation on failure!
  const solPosAfter = engine.getPosition(solPos.id);
  assert.equal(solPosAfter.accruedFunding, 0n, "Position accrued funding must remain 0 (atomic rollback)");
  const solMarketAfter = engine.getMarket("SOL-USD");
  assert.equal(solMarketAfter.insuranceFundBalanceUsd, 0n, "Insurance fund must remain 0 (atomic rollback)");
  assert.equal(solMarketAfter.lastSettledEpoch, 200, "Epoch must not advance on failure");
});

test("7. Liquidation of unhealthy position and protection of healthy position", () => {
  const engine = createTestEngine();
  registerTestMarket(engine, "ETH-USD", 3000n * WAD);

  const charlieKeys = AuthManager.generateKeyPair();
  engine.auth.enrollAccount(engine.auth.createEnrollmentProof("0xCharlie", charlieKeys.publicKey, charlieKeys.privateKey));

  const charlieIntent = engine.auth.signIntent(
    engine.domain,
    "0xCharlie",
    "0xCharlie",
    "OPEN_POSITION",
    { account: "0xcharlie", symbol: "ETH-USD", isLong: true, size: 1n * WAD, collateral: 300n * WAD, leverage: 10n },
    charlieKeys.privateKey
  );

  const pos = engine.openPosition({
    signedIntent: charlieIntent,
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  // Healthy position cannot be liquidated
  assert.throws(() => {
    engine.liquidatePosition({ positionId: pos.id, liquidator: "0xLiquidator" });
  }, /is healthy and cannot be liquidated/);

  // Market crashes to $2800 (Oracle updates price with signed intent)
  const crashIntent = engine.auth.signPrivilegedIntent(
    engine.domain,
    "ORACLE",
    "UPDATE_PRICES",
    { symbol: "ETH-USD", markPrice: 2800n * WAD, indexPrice: 2800n * WAD },
    oracleKeys.privateKey
  );
  engine.updatePrices({ signedIntent: crashIntent, symbol: "ETH-USD", markPrice: 2800n * WAD, indexPrice: 2800n * WAD });

  const receipt = engine.liquidatePosition({ positionId: pos.id, liquidator: "0xLiquidator" });
  assert.equal(receipt.positionId, pos.id);
  assert.equal(receipt.liquidator, "0xLiquidator");
  assert.equal(receipt.liquidationPrice, 2800n * WAD);
  assert.equal(engine.listPositions().length, 0);
});
