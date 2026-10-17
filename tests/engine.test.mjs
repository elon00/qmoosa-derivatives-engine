import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DerivativesEngine,
  WAD
} from "../dist/index.js";

test("1. Market registration and initial state validation", () => {
  const engine = new DerivativesEngine();
  const market = engine.registerMarket("ETH-USD", 3000n * WAD);

  assert.equal(market.symbol, "ETH-USD");
  assert.equal(market.markPrice, 3000n * WAD);
  assert.equal(market.fundingRateBps, 0n);
  assert.equal(engine.listMarkets().length, 1);
});

test("2. Open long position and enforce leverage & collateral constraints", () => {
  const engine = new DerivativesEngine();
  engine.registerMarket("ETH-USD", 3000n * WAD);

  // Opening 1 ETH position at $3000 with 10x leverage requires at least $300
  // Attempt with $200 should fail
  assert.throws(() => {
    engine.openPosition({
      account: "0xAlice",
      symbol: "ETH-USD",
      isLong: true,
      size: 1n * WAD,
      collateral: 200n * WAD,
      leverage: 10n
    });
  }, /Insufficient collateral/);

  // Legitimate open with $300 collateral
  const pos = engine.openPosition({
    account: "0xAlice",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  assert.equal(pos.account, "0xAlice");
  assert.equal(pos.isLong, true);
  assert.equal(pos.collateral, 300n * WAD);
  assert.equal(pos.entryPrice, 3000n * WAD);
  assert.equal(engine.listPositions().length, 1);
});

test("3. Price updates, funding calculation, and funding settlement", () => {
  const engine = new DerivativesEngine();
  engine.registerMarket("ETH-USD", 3000n * WAD);

  engine.openPosition({
    account: "0xAlice",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  // Mark price is $3030, Index price is $3000 (+100 bps premium)
  engine.updatePrices("ETH-USD", 3030n * WAD, 3000n * WAD);
  const market = engine.getMarket("ETH-USD");
  assert.equal(market.fundingRateBps, 100n);

  // Settle funding: Long pays 1% of notional ($3030 * 100 / 10000 = $30.30)
  const settlement = engine.settleFunding("ETH-USD");
  assert.equal(settlement.settledPositions, 1);

  const pos = engine.listPositions()[0];
  assert.ok(pos.accruedFunding > 30n * WAD);
});

test("4. Close position with profit and verify payout receipt", () => {
  const engine = new DerivativesEngine();
  engine.registerMarket("ETH-USD", 3000n * WAD);

  const pos = engine.openPosition({
    account: "0xBob",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 500n * WAD,
    leverage: 6n
  });

  // Price jumps to $3500 (+500 gain)
  engine.updatePrices("ETH-USD", 3500n * WAD, 3500n * WAD);

  const receipt = engine.closePosition(pos.id);
  assert.equal(receipt.realizedPnl, 500n * WAD);
  assert.equal(receipt.finalPayout, 1000n * WAD); // 500 collateral + 500 profit
  assert.equal(engine.listPositions().length, 0);
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

  // Market crashes to $2800 (equity = $100, maintenance margin on $2800 = $140 -> liquidatable!)
  engine.updatePrices("ETH-USD", 2800n * WAD, 2800n * WAD);

  const receipt = engine.liquidatePosition(pos.id, "0xLiquidator");
  assert.equal(receipt.positionId, pos.id);
  assert.equal(receipt.liquidator, "0xLiquidator");
  assert.equal(receipt.liquidationPrice, 2800n * WAD);
  assert.equal(engine.listPositions().length, 0);
});
