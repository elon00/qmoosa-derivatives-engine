import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DerivativesEngine,
  AuthManager,
  WAD,
  FUNDING_INTERVAL_MS
} from "../dist/index.js";

test("1. Defensive copy integrity: mutating returned references does not corrupt engine state", () => {
  const engine = new DerivativesEngine();
  engine.registerMarket("ETH-USD", 3000n * WAD);

  const pos = engine.openPosition({
    account: "0xAlice",
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

test("2. Operator approval security & actor authorization model", () => {
  const engine = new DerivativesEngine();
  engine.registerMarket("ETH-USD", 3000n * WAD);

  // Security test P0: Third party cannot approve operators for another account
  assert.throws(() => {
    engine.setApprovedOperator({
      account: "0xAlice",
      caller: "0xAttacker",
      operator: "0xMaliciousBroker",
      approved: true
    });
  }, /Unauthorized operator approval: caller 0xAttacker cannot manage operators for 0xAlice/);

  // Direct owner can approve operator
  engine.setApprovedOperator({
    account: "0xAlice",
    caller: "0xAlice",
    operator: "0xBrokerBot",
    approved: true
  });

  const pos = engine.openPosition({
    account: "0xAlice",
    caller: "0xAlice",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  // Unauthorized third-party cannot close position
  assert.throws(
    () => engine.closePosition({ caller: "0xAttacker", positionId: pos.id }),
    /Unauthorized: caller 0xAttacker is not authorized/
  );

  // Approved operator successfully closes position
  const receipt = engine.closePosition({ caller: "0xBrokerBot", positionId: pos.id });
  assert.equal(receipt.positionId, pos.id);
  assert.equal(receipt.account, "0xAlice");
});

test("3. Cryptographic signature verification and replay defense", () => {
  const engine = new DerivativesEngine();
  engine.registerMarket("ETH-USD", 3000n * WAD);

  const secretKey = "super-secure-private-key-0xalice";
  engine.auth.registerAccountCredential("0xAlice", secretKey);

  const openParams = {
    account: "0xalice",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  };

  const intent = engine.auth.signIntent(
    "0xAlice",
    "0xAlice",
    "OPEN_POSITION",
    openParams,
    secretKey,
    Date.now() + 60_000
  );

  // Legitimate cryptographic execution
  const pos = engine.openPosition({
    ...openParams,
    signedIntent: intent
  });
  assert.equal(pos.account, "0xalice");

  // Replay of same signed intent strictly fails closed
  assert.throws(() => {
    engine.openPosition({
      ...openParams,
      signedIntent: intent
    });
  }, /Invalid nonce/);

  // Tampered parameters fail closed
  const tamperedIntent = engine.auth.signIntent(
    "0xAlice",
    "0xAlice",
    "OPEN_POSITION",
    openParams,
    secretKey,
    Date.now() + 60_000
  );

  assert.throws(() => {
    engine.openPosition({
      ...openParams,
      size: 50n * WAD, // Tampered size
      signedIntent: tamperedIntent
    });
  }, /Parameter hash mismatch/);
});

test("4. Enforce discrete deterministic 8-hour funding epochs and insurance balance", () => {
  // Epoch 100: starts at 100 * 8h = 2,880,000,000 ms
  const epoch100Time = 100 * FUNDING_INTERVAL_MS;
  const engine = new DerivativesEngine();
  engine.registerMarket("ETH-USD", 3000n * WAD, 500n, 10_000n * WAD, epoch100Time);

  // Alice opens Long 1 ETH ($3000 notional)
  engine.openPosition({
    account: "0xAlice",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  // Bob opens Short 0.5 ETH ($1500 notional)
  engine.openPosition({
    account: "0xBob",
    symbol: "ETH-USD",
    isLong: false,
    size: 1n * (WAD / 2n),
    collateral: 150n * WAD,
    leverage: 10n
  });

  // Mark price is $3030, Index is $3000 (+100 bps premium)
  engine.updatePrices("ETH-USD", 3030n * WAD, 3000n * WAD);

  // Attempt settlement within same epoch: must be skipped
  const resEarly = engine.settleFunding("ETH-USD", epoch100Time + (2 * 60 * 60 * 1000));
  assert.equal(resEarly.status, "SKIPPED_INTERVAL_NOT_ELAPSED");
  assert.equal(resEarly.settledPositions, 0);

  // Settle in next epoch (Epoch 101)
  const epoch101Time = 101 * FUNDING_INTERVAL_MS;
  const resEpoch101 = engine.settleFunding("ETH-USD", epoch101Time);
  assert.equal(resEpoch101.status, "SETTLED");
  assert.equal(resEpoch101.epoch, 101);
  assert.equal(resEpoch101.settledPositions, 2);

  // Net imbalance credited to insurance fund
  assert.ok(resEpoch101.netImbalanceToInsuranceFund > 0n);
  const updatedMarket = engine.getMarket("ETH-USD");
  assert.equal(updatedMarket.insuranceFundBalanceUsd, 10_000n * WAD + resEpoch101.netImbalanceToInsuranceFund);

  // Duplicate settlement in Epoch 101 is blocked
  const resDup = engine.settleFunding("ETH-USD", epoch101Time + 1000);
  assert.equal(resDup.status, "SKIPPED_INTERVAL_NOT_ELAPSED");
});

test("5. Liquidation of unhealthy position and protection of healthy position", () => {
  const engine = new DerivativesEngine();
  engine.registerMarket("ETH-USD", 3000n * WAD);

  const pos = engine.openPosition({
    account: "0xCharlie",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  // Healthy position cannot be liquidated
  assert.throws(() => {
    engine.liquidatePosition(pos.id, "0xLiquidator");
  }, /is healthy and cannot be liquidated/);

  // Market crashes to $2800
  engine.updatePrices("ETH-USD", 2800n * WAD, 2800n * WAD);

  const receipt = engine.liquidatePosition(pos.id, "0xLiquidator");
  assert.equal(receipt.positionId, pos.id);
  assert.equal(receipt.liquidator, "0xLiquidator");
  assert.equal(receipt.liquidationPrice, 2800n * WAD);
  assert.equal(engine.listPositions().length, 0);
});
