/**
 * QMOOSA Derivatives Engine — Margin Management, Position Ledger, Cryptographic Authentication & Liquidation State Machine
 */

import { AuthManager, SignedIntent } from "./auth.js";

export const WAD = 10n ** 18n;
export const BPS_DIVISOR = 10_000n;
export const MAX_LEVERAGE = 20n;
export const MIN_LEVERAGE = 1n;
export const DEFAULT_MAINTENANCE_MARGIN_BPS = 500n; // 5.00%
export const MAX_FUNDING_RATE_BPS = 500n; // +/- 5.00% cap
export const FUNDING_INTERVAL_MS = 8 * 60 * 60 * 1000; // 8 hours in milliseconds

export interface PositionState {
  isLong: boolean;
  size: bigint;
  collateral: bigint;
  entryPrice: bigint;
  accruedFunding: bigint;
}

export function calculateNotional(size: bigint, price: bigint): bigint {
  if (size <= 0n) throw new RangeError("Position size must be strictly positive");
  if (price <= 0n) throw new RangeError("Price must be strictly positive");
  return (size * price) / WAD;
}

export function calculateInitialMargin(notional: bigint, leverage: bigint): bigint {
  if (notional <= 0n) throw new RangeError("Notional must be strictly positive");
  if (leverage < MIN_LEVERAGE || leverage > MAX_LEVERAGE) {
    throw new RangeError(`Leverage must be between ${MIN_LEVERAGE}x and ${MAX_LEVERAGE}x (got ${leverage}x)`);
  }
  return notional / leverage;
}

export function calculateMaintenanceMargin(
  notional: bigint,
  maintenanceMarginBps: bigint = DEFAULT_MAINTENANCE_MARGIN_BPS
): bigint {
  if (notional <= 0n) throw new RangeError("Notional must be strictly positive");
  return (notional * maintenanceMarginBps) / BPS_DIVISOR;
}

export function calculateUnrealizedPnl(
  isLong: boolean,
  size: bigint,
  entryPrice: bigint,
  markPrice: bigint
): bigint {
  if (size <= 0n) throw new RangeError("Position size must be strictly positive");
  if (entryPrice <= 0n || markPrice <= 0n) throw new RangeError("Prices must be strictly positive");

  return isLong
    ? (size * (markPrice - entryPrice)) / WAD
    : (size * (entryPrice - markPrice)) / WAD;
}

export function calculateEquity(position: PositionState, markPrice: bigint): bigint {
  const pnl = calculateUnrealizedPnl(position.isLong, position.size, position.entryPrice, markPrice);
  return position.collateral + pnl - position.accruedFunding;
}

export function isLiquidatable(
  position: PositionState,
  markPrice: bigint,
  maintenanceMarginBps: bigint = DEFAULT_MAINTENANCE_MARGIN_BPS
): boolean {
  const equity = calculateEquity(position, markPrice);
  const notional = calculateNotional(position.size, markPrice);
  const maintenanceMargin = calculateMaintenanceMargin(notional, maintenanceMarginBps);
  return equity <= maintenanceMargin;
}

export function calculateFundingRate(
  markPrice: bigint,
  indexPrice: bigint,
  maxFundingBps: bigint = MAX_FUNDING_RATE_BPS
): bigint {
  if (markPrice <= 0n || indexPrice <= 0n) throw new RangeError("Prices must be strictly positive");
  const premiumBps = ((markPrice - indexPrice) * BPS_DIVISOR) / indexPrice;
  if (premiumBps > maxFundingBps) return maxFundingBps;
  if (premiumBps < -maxFundingBps) return -maxFundingBps;
  return premiumBps;
}

export function calculateFundingPayment(
  isLong: boolean,
  notional: bigint,
  fundingRateBps: bigint
): bigint {
  if (notional <= 0n) throw new RangeError("Notional must be strictly positive");
  const rawPayment = (notional * fundingRateBps) / BPS_DIVISOR;
  return isLong ? rawPayment : -rawPayment;
}

export interface MarketState {
  symbol: string;
  markPrice: bigint;
  indexPrice: bigint;
  fundingRateBps: bigint;
  maintenanceMarginBps: bigint;
  lastFundingSettledAt: number;
  lastSettledEpoch: number;
  insuranceFundBalanceUsd: bigint;
}

export interface Position extends PositionState {
  id: string;
  account: string;
  marketSymbol: string;
  openedAt: number;
}

export interface SettlementReceipt {
  positionId: string;
  account: string;
  marketSymbol: string;
  exitPrice: bigint;
  realizedPnl: bigint;
  accruedFunding: bigint;
  finalPayout: bigint;
}

export interface LiquidationReceipt {
  positionId: string;
  liquidatedAccount: string;
  liquidator: string;
  liquidationPrice: bigint;
  clearedDebt: bigint;
  liquidatorReward: bigint;
}

export class DerivativesEngine {
  private markets: Map<string, MarketState> = new Map();
  private positions: Map<string, Position> = new Map();
  private approvedOperators: Map<string, Set<string>> = new Map(); // account -> approved operators
  private nextPositionNonce: bigint = 1n;
  public readonly auth: AuthManager = new AuthManager();

  public registerMarket(
    symbol: string,
    initialPrice: bigint,
    maintenanceMarginBps: bigint = DEFAULT_MAINTENANCE_MARGIN_BPS,
    initialInsuranceFundUsd: bigint = 0n,
    initialTimestamp: number = 0
  ): MarketState {
    if (!symbol || symbol.trim().length === 0) {
      throw new Error("Invalid market symbol");
    }
    if (initialPrice <= 0n) {
      throw new RangeError("Initial price must be strictly positive");
    }

    const initialEpoch = Math.floor(initialTimestamp / FUNDING_INTERVAL_MS);

    const market: MarketState = {
      symbol: symbol.toUpperCase(),
      markPrice: initialPrice,
      indexPrice: initialPrice,
      fundingRateBps: 0n,
      maintenanceMarginBps,
      lastFundingSettledAt: initialTimestamp,
      lastSettledEpoch: initialEpoch,
      insuranceFundBalanceUsd: initialInsuranceFundUsd
    };

    this.markets.set(market.symbol, market);
    return { ...market };
  }

  /**
   * Approves or revokes an operator for an account.
   * STRICT SECURITY: Only the account owner itself (verified caller or signed intent) can approve operators.
   */
  public setApprovedOperator(params: {
    account: string;
    caller: string;
    operator: string;
    approved: boolean;
    signedIntent?: SignedIntent;
  }): void {
    const { account, caller, operator, approved, signedIntent } = params;
    if (!account || !operator || !caller) {
      throw new Error("Account, caller, and operator must be valid strings");
    }

    const acc = account.toLowerCase();
    const clr = caller.toLowerCase();
    const op = operator.toLowerCase();

    // Verify cryptographic intent or direct owner invocation
    if (signedIntent) {
      this.auth.verifyAndConsumeIntent(signedIntent, {
        account: acc,
        operator: op,
        approved
      });
    } else if (clr !== acc) {
      throw new Error(`Unauthorized operator approval: caller ${caller} cannot manage operators for ${account}`);
    }

    if (!this.approvedOperators.has(acc)) {
      this.approvedOperators.set(acc, new Set());
    }
    const ops = this.approvedOperators.get(acc)!;
    if (approved) {
      ops.add(op);
    } else {
      ops.delete(op);
    }
  }

  public isAuthorizedCaller(account: string, caller: string): boolean {
    const acc = account.toLowerCase();
    const c = caller.toLowerCase();
    if (acc === c) return true;
    const ops = this.approvedOperators.get(acc);
    return ops ? ops.has(c) : false;
  }

  public updatePrices(symbol: string, markPrice: bigint, indexPrice: bigint): MarketState {
    const s = symbol.toUpperCase();
    const market = this.markets.get(s);
    if (!market) throw new Error(`Market ${s} is not registered`);
    if (markPrice <= 0n || indexPrice <= 0n) {
      throw new RangeError("Prices must be strictly positive");
    }

    market.markPrice = markPrice;
    market.indexPrice = indexPrice;
    market.fundingRateBps = calculateFundingRate(markPrice, indexPrice);
    return { ...market };
  }

  public openPosition(params: {
    caller?: string;
    account: string;
    symbol: string;
    isLong: boolean;
    size: bigint;
    collateral: bigint;
    leverage: bigint;
    signedIntent?: SignedIntent;
  }): Position {
    const s = params.symbol.toUpperCase();
    const market = this.markets.get(s);
    if (!market) throw new Error(`Market ${s} is not registered`);

    if (!params.account || params.account.trim().length === 0) {
      throw new Error("Account address is required");
    }

    // Cryptographic intent verification if provided
    if (params.signedIntent) {
      this.auth.verifyAndConsumeIntent(params.signedIntent, {
        account: params.account.toLowerCase(),
        symbol: s,
        isLong: params.isLong,
        size: params.size,
        collateral: params.collateral,
        leverage: params.leverage
      });
    }

    // Actor authorization boundary
    const effectiveCaller = params.caller ?? (params.signedIntent ? params.signedIntent.caller : params.account);
    if (!this.isAuthorizedCaller(params.account, effectiveCaller)) {
      throw new Error(`Unauthorized: caller ${effectiveCaller} is not authorized for account ${params.account}`);
    }

    const notional = calculateNotional(params.size, market.markPrice);
    const requiredMargin = calculateInitialMargin(notional, params.leverage);

    if (params.collateral < requiredMargin) {
      throw new Error(
        `Insufficient collateral: provided ${params.collateral}, required ${requiredMargin} for ${params.leverage}x leverage`
      );
    }

    const positionId = `POS-${market.symbol}-${this.nextPositionNonce++}`;
    const position: Position = {
      id: positionId,
      account: params.account,
      marketSymbol: market.symbol,
      isLong: params.isLong,
      size: params.size,
      collateral: params.collateral,
      entryPrice: market.markPrice,
      accruedFunding: 0n,
      openedAt: Date.now()
    };

    this.positions.set(positionId, position);
    return { ...position };
  }

  /**
   * Settles dynamic funding across all positions in a market.
   * Enforces discrete deterministic 8-hour funding epochs:
   * currentEpoch = floor(currentTime / FUNDING_INTERVAL_MS).
   * Guarantees exact counterparty funding conservation against market insurance fund.
   */
  public settleFunding(
    symbol: string,
    currentTimestamp: number = Date.now()
  ): {
    settledPositions: number;
    fundingRateBps: bigint;
    epoch: number;
    totalLongPayment: bigint;
    totalShortPayment: bigint;
    netImbalanceToInsuranceFund: bigint;
    status: "SETTLED" | "SKIPPED_INTERVAL_NOT_ELAPSED";
  } {
    const s = symbol.toUpperCase();
    const market = this.markets.get(s);
    if (!market) throw new Error(`Market ${s} is not registered`);

    const currentEpoch = Math.floor(currentTimestamp / FUNDING_INTERVAL_MS);

    // Enforce that each discrete epoch is settled at most once
    if (currentEpoch <= market.lastSettledEpoch) {
      return {
        settledPositions: 0,
        fundingRateBps: market.fundingRateBps,
        epoch: currentEpoch,
        totalLongPayment: 0n,
        totalShortPayment: 0n,
        netImbalanceToInsuranceFund: 0n,
        status: "SKIPPED_INTERVAL_NOT_ELAPSED"
      };
    }

    let count = 0;
    let totalLongPayment = 0n;
    let totalShortPayment = 0n;

    for (const pos of this.positions.values()) {
      if (pos.marketSymbol === market.symbol) {
        const notional = calculateNotional(pos.size, market.markPrice);
        const payment = calculateFundingPayment(pos.isLong, notional, market.fundingRateBps);
        pos.accruedFunding += payment;
        if (pos.isLong) {
          totalLongPayment += payment;
        } else {
          totalShortPayment += payment;
        }
        count++;
      }
    }

    // Net funding imbalance: long payments + short payments (short payments are negative when receiving)
    const netImbalance = totalLongPayment + totalShortPayment;
    market.insuranceFundBalanceUsd += netImbalance;
    market.lastFundingSettledAt = currentTimestamp;
    market.lastSettledEpoch = currentEpoch;

    return {
      settledPositions: count,
      fundingRateBps: market.fundingRateBps,
      epoch: currentEpoch,
      totalLongPayment,
      totalShortPayment,
      netImbalanceToInsuranceFund: netImbalance,
      status: "SETTLED"
    };
  }

  /**
   * Closes an active position and returns net settlement receipt.
   * Enforces authenticated actor authorization boundary.
   */
  public closePosition(params: {
    caller: string;
    positionId: string;
    signedIntent?: SignedIntent;
  }): SettlementReceipt {
    if (!params.caller || params.caller.trim().length === 0) {
      throw new Error("Caller address is required for authorization");
    }

    const position = this.positions.get(params.positionId);
    if (!position) throw new Error(`Position ${params.positionId} not found`);

    if (params.signedIntent) {
      this.auth.verifyAndConsumeIntent(params.signedIntent, {
        positionId: params.positionId
      });
    }

    if (!this.isAuthorizedCaller(position.account, params.caller)) {
      throw new Error(`Unauthorized: caller ${params.caller} is not authorized to close position ${params.positionId}`);
    }

    const market = this.markets.get(position.marketSymbol)!;

    const realizedPnl = calculateUnrealizedPnl(
      position.isLong,
      position.size,
      position.entryPrice,
      market.markPrice
    );

    const netEquity = position.collateral + realizedPnl - position.accruedFunding;
    const finalPayout = netEquity > 0n ? netEquity : 0n;

    this.positions.delete(params.positionId);

    return {
      positionId: position.id,
      account: position.account,
      marketSymbol: position.marketSymbol,
      exitPrice: market.markPrice,
      realizedPnl,
      accruedFunding: position.accruedFunding,
      finalPayout
    };
  }

  public liquidatePosition(positionId: string, liquidator: string): LiquidationReceipt {
    const position = this.positions.get(positionId);
    if (!position) throw new Error(`Position ${positionId} not found`);

    const market = this.markets.get(position.marketSymbol)!;

    if (!liquidator || liquidator.trim().length === 0) {
      throw new Error("Liquidator address is required");
    }

    const liquidatable = isLiquidatable(position, market.markPrice, market.maintenanceMarginBps);
    if (!liquidatable) {
      throw new Error(`Position ${positionId} is healthy and cannot be liquidated`);
    }

    const equity = calculateEquity(position, market.markPrice);
    const liquidatorReward = equity > 0n ? (equity * 500n) / BPS_DIVISOR : 0n;

    this.positions.delete(positionId);

    return {
      positionId: position.id,
      liquidatedAccount: position.account,
      liquidator,
      liquidationPrice: market.markPrice,
      clearedDebt: position.collateral,
      liquidatorReward
    };
  }

  public getMarket(symbol: string): MarketState {
    const s = symbol.toUpperCase();
    const market = this.markets.get(s);
    if (!market) throw new Error(`Market ${s} is not registered`);
    return { ...market };
  }

  public getPosition(positionId: string): Position {
    const pos = this.positions.get(positionId);
    if (!pos) throw new Error(`Position ${positionId} not found`);
    return { ...pos };
  }

  public getAccountPositions(account: string): Position[] {
    const acc = account.toLowerCase();
    return Array.from(this.positions.values())
      .filter(p => p.account.toLowerCase() === acc)
      .map(p => ({ ...p }));
  }

  public listMarkets(): MarketState[] {
    return Array.from(this.markets.values()).map(m => ({ ...m }));
  }

  public listPositions(): Position[] {
    return Array.from(this.positions.values()).map(p => ({ ...p }));
  }
}
