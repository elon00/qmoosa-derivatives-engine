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

const ADMIN = "0xAdmin";
const ORACLE = "0xOracle";
const KEEPER = "0xKeeper";

function createTestEngine() {
  const engine = new DerivativesEngine({
    admin: ADMIN,
    oracleSigner: ORACLE,
    keeperSigner: KEEPER
  });
  return engine;
}

test("1. Defensive copy integrity: mutating returned references does not corrupt engine state", () => {
  const engine = createTestEngine();
  engine.registerMarket({ caller: ADMIN, symbol: "ETH-USD", initialPrice: 3000n * WAD });

  const secretAlice = "secret-alice-12345";
  engine.auth.registerAccountCredential("0xAlice", secretAlice);

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
    secretAlice
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

test("2. Operator approval security & actor authorization model with cryptographic intents", () => {
  const engine = createTestEngine();
  engine.registerMarket({ caller: ADMIN, symbol: "ETH-USD", initialPrice: 3000n * WAD });

  const secretAlice = "secret-alice-12345";
  const secretAttacker = "secret-attacker-666";
  engine.auth.registerAccountCredential("0xAlice", secretAlice);
  engine.auth.registerAccountCredential("0xAttacker", secretAttacker);

  // Security test P0: Third party cannot sign an operator approval for another account
  const attackerForgedIntent = engine.auth.signIntent(
    engine.domain,
    "0xAlice",
    "0xAttacker", // attacker tries to act as caller
    "SET_OPERATOR",
    { account: "0xalice", operator: "0xmaliciousbroker", approved: true },
    secretAttacker // signed with attacker's secret key!
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
    secretAlice
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
    secretAlice
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
    secretAttacker
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
    secretAlice
  );

  const receipt = engine.closePosition({ signedIntent: brokerCloseIntent, positionId: pos.id });
  assert.equal(receipt.positionId, pos.id);
  assert.equal(receipt.account, "0xalice");
});

test("3. Cryptographic signature verification, replay defense, domain binding, and credential immutability", () => {
  const engine = createTestEngine();
  engine.registerMarket({ caller: ADMIN, symbol: "ETH-USD", initialPrice: 3000n * WAD });

  const secretAlice = "super-secure-private-key-0xalice";
  engine.auth.registerAccountCredential("0xAlice", secretAlice);

  // Test P0: Credential overwrite attempt fails closed
  assert.throws(() => {
    engine.auth.registerAccountCredential("0xAlice", "malicious-replacement-key");
  }, /already registered; overwrite not permitted/);

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
    secretAlice,
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
    secretAlice,
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
    secretAlice,
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

test("4. Privileged role boundary enforcement (Admin, Oracle, Keeper)", () => {
  const engine = createTestEngine();

  // Non-admin cannot register market
  assert.throws(() => {
    engine.registerMarket({ caller: "0xRandomUser", symbol: "ETH-USD", initialPrice: 3000n * WAD });
  }, /Unauthorized: caller 0xRandomUser is not the market administrator/);

  // Admin registers market
  engine.registerMarket({ caller: ADMIN, symbol: "ETH-USD", initialPrice: 3000n * WAD });

  // Non-oracle cannot update prices
  assert.throws(() => {
    engine.updatePrices({ caller: "0xRandomUser", symbol: "ETH-USD", markPrice: 3100n * WAD, indexPrice: 3100n * WAD });
  }, /Unauthorized: caller 0xRandomUser is not the authorized oracle signer/);

  // Oracle updates prices
  engine.updatePrices({ caller: ORACLE, symbol: "ETH-USD", markPrice: 3100n * WAD, indexPrice: 3100n * WAD });
  assert.equal(engine.getMarket("ETH-USD").markPrice, 3100n * WAD);

  // Non-keeper cannot settle funding
  assert.throws(() => {
    engine.settleFunding({ caller: "0xRandomUser", symbol: "ETH-USD" });
  }, /Unauthorized: caller 0xRandomUser is not the authorized settlement keeper/);
});

test("5. Discrete deterministic 8-hour funding epochs, insurance balance, and solvency freeze", () => {
  const epoch100Time = 100 * FUNDING_INTERVAL_MS;
  const engine = createTestEngine();
  engine.registerMarket({
    caller: ADMIN,
    symbol: "ETH-USD",
    initialPrice: 3000n * WAD,
    maintenanceMarginBps: 500n,
    initialInsuranceFundUsd: 10_000n * WAD,
    initialTimestamp: epoch100Time
  });

  const secretAlice = "secret-alice-12345";
  const secretBob = "secret-bob-12345";
  engine.auth.registerAccountCredential("0xAlice", secretAlice);
  engine.auth.registerAccountCredential("0xBob", secretBob);

  // Alice opens Long 1 ETH ($3000 notional)
  const aliceIntent = engine.auth.signIntent(
    engine.domain,
    "0xAlice",
    "0xAlice",
    "OPEN_POSITION",
    { account: "0xalice", symbol: "ETH-USD", isLong: true, size: 1n * WAD, collateral: 300n * WAD, leverage: 10n },
    secretAlice
  );
  engine.openPosition({
    signedIntent: aliceIntent,
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  // Bob opens Short 0.5 ETH ($1500 notional)
  const bobIntent = engine.auth.signIntent(
    engine.domain,
    "0xBob",
    "0xBob",
    "OPEN_POSITION",
    { account: "0xbob", symbol: "ETH-USD", isLong: false, size: 1n * (WAD / 2n), collateral: 150n * WAD, leverage: 10n },
    secretBob
  );
  engine.openPosition({
    signedIntent: bobIntent,
    symbol: "ETH-USD",
    isLong: false,
    size: 1n * (WAD / 2n),
    collateral: 150n * WAD,
    leverage: 10n
  });

  // Mark price is $3030, Index is $3000 (+100 bps premium)
  engine.updatePrices({ caller: ORACLE, symbol: "ETH-USD", markPrice: 3030n * WAD, indexPrice: 3000n * WAD });

  // Attempt settlement within same epoch: must be skipped
  const resEarly = engine.settleFunding({
    caller: KEEPER,
    symbol: "ETH-USD",
    currentTimestamp: epoch100Time + (2 * 60 * 60 * 1000)
  });
  assert.equal(resEarly.status, "SKIPPED_INTERVAL_NOT_ELAPSED");
  assert.equal(resEarly.settledPositions, 0);

  // Settle in next epoch (Epoch 101)
  const epoch101Time = 101 * FUNDING_INTERVAL_MS;
  const resEpoch101 = engine.settleFunding({
    caller: KEEPER,
    symbol: "ETH-USD",
    currentTimestamp: epoch101Time
  });
  assert.equal(resEpoch101.status, "SETTLED");
  assert.equal(resEpoch101.epoch, 101);
  assert.equal(resEpoch101.settledPositions, 2);

  // Net imbalance credited to insurance fund
  assert.ok(resEpoch101.netImbalanceToInsuranceFund > 0n);
  const updatedMarket = engine.getMarket("ETH-USD");
  assert.equal(updatedMarket.insuranceFundBalanceUsd, 10_000n * WAD + resEpoch101.netImbalanceToInsuranceFund);

  // Duplicate settlement in Epoch 101 is blocked
  const resDup = engine.settleFunding({
    caller: KEEPER,
    symbol: "ETH-USD",
    currentTimestamp: epoch101Time + 1000
  });
  assert.equal(resDup.status, "SKIPPED_INTERVAL_NOT_ELAPSED");
});

test("6. Funding solvency freeze when insurance fund is insolvent", () => {
  const epoch200Time = 200 * FUNDING_INTERVAL_MS;
  const engine = createTestEngine();
  // Register market with 0 insurance fund
  engine.registerMarket({
    caller: ADMIN,
    symbol: "ETH-USD",
    initialPrice: 3000n * WAD,
    maintenanceMarginBps: 500n,
    initialInsuranceFundUsd: 0n,
    initialTimestamp: epoch200Time
  });

  const secretAlice = "secret-alice-12345";
  engine.auth.registerAccountCredential("0xAlice", secretAlice);

  // Alice opens Short 10 ETH ($30,000 notional)
  const aliceIntent = engine.auth.signIntent(
    engine.domain,
    "0xAlice",
    "0xAlice",
    "OPEN_POSITION",
    { account: "0xalice", symbol: "ETH-USD", isLong: false, size: 10n * WAD, collateral: 3000n * WAD, leverage: 10n },
    secretAlice
  );
  engine.openPosition({
    signedIntent: aliceIntent,
    symbol: "ETH-USD",
    isLong: false,
    size: 10n * WAD,
    collateral: 3000n * WAD,
    leverage: 10n
  });

  // Mark price is $3030, Index is $3000 (+100 bps premium) -> Longs pay shorts, but there are no longs!
  // Short is due to receive payment from insurance fund. But insurance fund is $0!
  engine.updatePrices({ caller: ORACLE, symbol: "ETH-USD", markPrice: 3030n * WAD, indexPrice: 3000n * WAD });

  const epoch201Time = 201 * FUNDING_INTERVAL_MS;
  // Solvency violation must throw and freeze funding settlement
  assert.throws(() => {
    engine.settleFunding({ caller: KEEPER, symbol: "ETH-USD", currentTimestamp: epoch201Time });
  }, /Solvency violation: net funding imbalance/);
});

test("7. Liquidation of unhealthy position and protection of healthy position", () => {
  const engine = createTestEngine();
  engine.registerMarket({ caller: ADMIN, symbol: "ETH-USD", initialPrice: 3000n * WAD });

  const secretCharlie = "secret-charlie-12345";
  engine.auth.registerAccountCredential("0xCharlie", secretCharlie);

  const charlieIntent = engine.auth.signIntent(
    engine.domain,
    "0xCharlie",
    "0xCharlie",
    "OPEN_POSITION",
    { account: "0xcharlie", symbol: "ETH-USD", isLong: true, size: 1n * WAD, collateral: 300n * WAD, leverage: 10n },
    secretCharlie
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

  // Market crashes to $2800 (Oracle updates price)
  engine.updatePrices({ caller: ORACLE, symbol: "ETH-USD", markPrice: 2800n * WAD, indexPrice: 2800n * WAD });

  const receipt = engine.liquidatePosition({ positionId: pos.id, liquidator: "0xLiquidator" });
  assert.equal(receipt.positionId, pos.id);
  assert.equal(receipt.liquidator, "0xLiquidator");
  assert.equal(receipt.liquidationPrice, 2800n * WAD);
  assert.equal(engine.listPositions().length, 0);
});
