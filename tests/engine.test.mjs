import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DerivativesEngine,
  DeterministicClock,
  WAD,
  FUNDING_INTERVAL_MS
} from "../dist/index.js";

const ADMIN_AUTH = { actor: "0xAdmin", role: "ADMIN" };
const ALICE_AUTH = { actor: "0xAlice", role: "USER" };
const BOB_AUTH = { actor: "0xBob", role: "USER" };
const ATTACKER_AUTH = { actor: "0xAttacker", role: "USER" };

test("1. P0 Regression: Operator approval bypass blocked - users cannot approve themselves for other accounts", () => {
  const engine = new DerivativesEngine();
  engine.registerMarket(ADMIN_AUTH, "ETH-USD", 3000n * WAD);

  // Attacker tries to approve themselves as operator for Alice
  // Attempt 1: Calling setApprovedOperator with Attacker's auth only affects Attacker's approvals, not Alice's
  assert.throws(
    () => engine.setApprovedOperator(ATTACKER_AUTH, "0xAttacker", true),
    /Self-approval is invalid/
  );

  // Alice authorizes Bob
  engine.setApprovedOperator(ALICE_AUTH, "0xBob", true);
  assert.equal(engine.isApprovedOperator("0xAlice", "0xBob"), true);
  assert.equal(engine.isApprovedOperator("0xAlice", "0xAttacker"), false);

  // Alice revokes Bob
  engine.setApprovedOperator(ALICE_AUTH, "0xBob", false);
  assert.equal(engine.isApprovedOperator("0xAlice", "0xBob"), false);
});

test("2. P0 Regression: Caller impersonation strictly rejected on openPosition and closePosition", () => {
  const engine = new DerivativesEngine();
  engine.registerMarket(ADMIN_AUTH, "ETH-USD", 3000n * WAD);

  // Attacker attempts to open position using Alice's account
  assert.throws(
    () => engine.openPosition(ATTACKER_AUTH, {
      account: "0xAlice",
      symbol: "ETH-USD",
      isLong: true,
      size: 1n * WAD,
      collateral: 300n * WAD,
      leverage: 10n
    }),
    /Unauthorized: actor 0xAttacker is neither account owner nor approved operator for 0xAlice/
  );

  // Alice legitimately opens her position
  const pos = engine.openPosition(ALICE_AUTH, {
    account: "0xAlice",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });
  assert.equal(pos.account, "0xAlice");

  // Attacker attempts to close Alice's position
  assert.throws(
    () => engine.closePosition(ATTACKER_AUTH, pos.id),
    /Unauthorized: actor 0xAttacker cannot close position/
  );

  // Alice approves Bob, Bob closes it legitimately
  engine.setApprovedOperator(ALICE_AUTH, "0xBob", true);
  const receipt = engine.closePosition(BOB_AUTH, pos.id);
  assert.equal(receipt.positionId, pos.id);
  assert.equal(receipt.account, "0xAlice");
});

test("3. Deterministic clock, 8-hour epochs, duplicate prevention, and insurance solvency", () => {
  const clock = new DeterministicClock(1_700_000_000_000);
  const engine = new DerivativesEngine(clock);
  engine.registerMarket(ADMIN_AUTH, "ETH-USD", 3000n * WAD, 500n, 1000n * WAD);

  // Alice opens Long 1 ETH
  engine.openPosition(ALICE_AUTH, {
    account: "0xAlice",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  // Price rises to $3030 vs index $3000 (+100 bps premium)
  engine.updatePrices(ADMIN_AUTH, "ETH-USD", 3030n * WAD, 3000n * WAD);

  // Attempt duplicate settlement in current epoch -> SKIPPED
  const resSame = engine.settleFunding("ETH-USD");
  assert.equal(resSame.status, "SKIPPED_DUPLICATE_EPOCH");

  // Advance clock by 8 hours
  clock.advance(FUNDING_INTERVAL_MS + 1000);

  // Settlement in new epoch succeeds
  const resNew = engine.settleFunding("ETH-USD");
  assert.equal(resNew.status, "SETTLED");
  assert.equal(resNew.settledPositions, 1);
  assert.ok(resNew.insuranceFundBalanceUsd >= 1000n * WAD);

  // Solvency check: Insurance fund balance cannot be negative
  const market = engine.getMarket("ETH-USD");
  assert.ok(market.insuranceFundBalanceUsd >= 0n, "Insurance fund balance must be strictly non-negative");
});

test("4. Defensive copy integrity: mutating returned references does not alter internal engine state", () => {
  const engine = new DerivativesEngine();
  engine.registerMarket(ADMIN_AUTH, "ETH-USD", 3000n * WAD);

  const pos = engine.openPosition(ALICE_AUTH, {
    account: "0xAlice",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  pos.collateral = 999_999n * WAD;
  const internalPos = engine.getPosition(pos.id);
  assert.equal(internalPos.collateral, 300n * WAD);
});

test("5. Authenticated liquidation of unhealthy position and protection of healthy position", () => {
  const engine = new DerivativesEngine();
  engine.registerMarket(ADMIN_AUTH, "ETH-USD", 3000n * WAD);

  const pos = engine.openPosition(ALICE_AUTH, {
    account: "0xAlice",
    symbol: "ETH-USD",
    isLong: true,
    size: 1n * WAD,
    collateral: 300n * WAD,
    leverage: 10n
  });

  // Healthy position cannot be liquidated
  assert.throws(
    () => engine.liquidatePosition(ATTACKER_AUTH, pos.id),
    /is healthy and cannot be liquidated/
  );

  // Market crashes to $2800 -> unhealthy
  engine.updatePrices(ADMIN_AUTH, "ETH-USD", 2800n * WAD, 2800n * WAD);

  const liqReceipt = engine.liquidatePosition(BOB_AUTH, pos.id);
  assert.equal(liqReceipt.positionId, pos.id);
  assert.equal(liqReceipt.liquidator, "0xBob");
  assert.equal(engine.listPositions().length, 0);
});
