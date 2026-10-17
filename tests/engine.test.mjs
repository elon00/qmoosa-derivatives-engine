import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DerivativesEngine,
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

test("2. Actor authorization model for position closure and operator approval", () => {
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

  // Unauthorized third-party attempt
  assert.throws(
    () => engine.closePosition({ caller: "0xAttacker", positionId: pos.id }),
    /Unauthorized: caller 0xAttacker is not authorized/
  );

  // Set approved operator
  engine.setApprovedOperator("0xAlice", "0xBrokerBot", true);

  // Approved operator successfully closes position
  const receipt = engine.closePosition({ caller: "0xBrokerBot", positionId: pos.id });
  assert.equal(receipt.positionId, pos.id);
  assert.equal(receipt.account, "0xAlice");
});

test("3. Enforce 8-hour funding intervals, prevent duplicate settlement, and verify insurance fund balance", () => {
  const startTime = 1_000_000_000_000;
  const engine = new DerivativesEngine();
  engine.registerMarket("ETH-USD", 3000n * WAD, 500n, 10_000n * WAD, startTime);

  // Alice opens Long 1 ETH ($3000 notional)
  engine.openPosition({
    account: "0xAlice",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  // Bob opens Short 0.5 ETH ($1500 notional) -> Imbalance exists (Long 1.0 vs Short 0.5)
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

  // Attempt settlement after only 2 hours: must be skipped
  const resEarly = engine.settleFunding("ETH-USD", startTime + (2 * 60 * 60 * 1000));
  assert.equal(resEarly.status, "SKIPPED_INTERVAL_NOT_ELAPSED");
  assert.equal(resEarly.settledPositions, 0);

  // Settle exactly after 8 hours
  const res8h = engine.settleFunding("ETH-USD", startTime + FUNDING_INTERVAL_MS);
  assert.equal(res8h.status, "SETTLED");
  assert.equal(res8h.settledPositions, 2);

  // Long payment = 3030 * 100 / 10000 = +30.30 USD
  // Short payment = - (1515 * 100 / 10000) = -15.15 USD (short receives)
  // Net imbalance = +15.15 USD credited to insurance fund!
  assert.ok(res8h.netImbalanceToInsuranceFund > 0n);
  const updatedMarket = engine.getMarket("ETH-USD");
  assert.equal(updatedMarket.insuranceFundBalanceUsd, 10_000n * WAD + res8h.netImbalanceToInsuranceFund);

  // Immediate second settlement attempt within same epoch is blocked
  const resDup = engine.settleFunding("ETH-USD", startTime + FUNDING_INTERVAL_MS + 1000);
  assert.equal(resDup.status, "SKIPPED_INTERVAL_NOT_ELAPSED");
});

test("4. Liquidation of unhealthy position and protection of healthy position", () => {
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

test("5. Fail-closed: insufficient collateral and zero price boundaries", () => {
  const engine = new DerivativesEngine();
  engine.registerMarket("ETH-USD", 3000n * WAD);

  assert.throws(
    () => engine.openPosition({
      account: "0xUnderfunded",
      symbol: "ETH-USD",
      isLong: true,
      size: 1n * WAD,
      collateral: 50n * WAD, // Only $50 provided for $300 required
      leverage: 10n
    }),
    /Insufficient collateral/
  );

  assert.throws(
    () => engine.updatePrices("ETH-USD", 0n, 3000n * WAD),
    /strictly positive/
  );
});
