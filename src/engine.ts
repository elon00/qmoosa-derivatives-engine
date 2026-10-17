/**
 * QMOOSA Derivatives Engine — Margin Management, Position Ledger, Authentication,
 * Deterministic Funding Clock, and Insurance Solvency State Machine
 */

export const WAD = 10n ** 18n;
export const BPS_DIVISOR = 10_000n;
export const MAX_LEVERAGE = 20n;
export const MIN_LEVERAGE = 1n;
export const DEFAULT_MAINTENANCE_MARGIN_BPS = 500n; // 5.00%
export const MAX_FUNDING_RATE_BPS = 500n; // +/- 5.00% cap
export const FUNDING_INTERVAL_MS = 8 * 60 * 60 * 1000; // 8-hour epoch

export interface AuthContext {
  readonly actor: string; // Authenticated address (verified at API/cryptographic boundary)
  readonly role?: "USER" | "ADMIN" | "OPERATOR";
}

export interface EngineClock {
  now(): number;
}

export class SystemClock implements EngineClock {
  public now(): number {
    return Date.now();
  }
}

export class DeterministicClock implements EngineClock {
  private currentTime: number;

  constructor(initialTime: number = 1_700_000_000_000) {
    this.currentTime = initialTime;
  }

  public now(): number {
    return this.currentTime;
  }

  public advance(ms: number): void {
    if (ms < 0) throw new RangeError("Time cannot move backward");
    this.currentTime += ms;
  }
}

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
  private approvedOperators: Map<string, Set<string>> = new Map(); // owner -> Set of approved operators
  private nextPositionNonce: bigint = 1n;
  private clock: EngineClock;

  constructor(clock: EngineClock = new SystemClock()) {
    this.clock = clock;
  }

  public registerMarket(
    auth: AuthContext,
    symbol: string,
    initialPrice: bigint,
    maintenanceMarginBps: bigint = DEFAULT_MAINTENANCE_MARGIN_BPS,
    initialInsuranceFundUsd: bigint = 0n
  ): MarketState {
    if (!auth || auth.role !== "ADMIN") {
      throw new Error("Unauthorized: only ADMIN can register markets");
    }
    if (!symbol || symbol.trim().length === 0) {
      throw new Error("Invalid market symbol");
    }
    if (initialPrice <= 0n) {
      throw new RangeError("Initial price must be strictly positive");
    }

    const currentEpoch = Math.floor(this.clock.now() / FUNDING_INTERVAL_MS);
    const market: MarketState = {
      symbol: symbol.toUpperCase(),
      markPrice: initialPrice,
      indexPrice: initialPrice,
      fundingRateBps: 0n,
      maintenanceMarginBps,
      lastSettledEpoch: currentEpoch,
      insuranceFundBalanceUsd: initialInsuranceFundUsd
    };

    this.markets.set(market.symbol, market);
    return { ...market };
  }

  /**
   * Authorizes an operator. Can ONLY be called by the authenticated account owner.
   */
  public setApprovedOperator(auth: AuthContext, operator: string, approved: boolean): void {
    if (!auth || !auth.actor || auth.actor.trim().length === 0) {
      throw new Error("Authentication required: valid auth.actor must be provided");
    }
    if (!operator || operator.trim().length === 0) {
      throw new Error("Operator address must be provided");
    }

    const owner = auth.actor.toLowerCase();
    const op = operator.toLowerCase();

    if (owner === op) {
      throw new Error("Self-approval is invalid");
    }

    if (!this.approvedOperators.has(owner)) {
      this.approvedOperators.set(owner, new Set());
    }

    const ops = this.approvedOperators.get(owner)!;
    if (approved) {
      ops.add(op);
    } else {
      ops.delete(op);
    }
  }

  public isApprovedOperator(owner: string, operator: string): boolean {
    const o = owner.toLowerCase();
    const op = operator.toLowerCase();
    const ops = this.approvedOperators.get(o);
    return ops ? ops.has(op) : false;
  }

  public isAuthorized(auth: AuthContext, targetAccount: string): boolean {
    if (!auth || !auth.actor) return false;
    const actor = auth.actor.toLowerCase();
    const target = targetAccount.toLowerCase();
    if (actor === target) return true;
    return this.isApprovedOperator(target, actor);
  }

  public updatePrices(auth: AuthContext, symbol: string, markPrice: bigint, indexPrice: bigint): MarketState {
    if (!auth || auth.role !== "ADMIN") {
      throw new Error("Unauthorized: oracle price updates require ADMIN role");
    }
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

  /**
   * Opens a new position. Requires authentic authorization for params.account.
   */
  public openPosition(
    auth: AuthContext,
    params: {
      account: string;
      symbol: string;
      isLong: boolean;
      size: bigint;
      collateral: bigint;
      leverage: bigint;
    }
  ): Position {
    if (!auth || !auth.actor) {
      throw new Error("Authentication required: missing auth context");
    }
    if (!params.account || params.account.trim().length === 0) {
      throw new Error("Account address is required");
    }

    if (!this.isAuthorized(auth, params.account)) {
      throw new Error(
        `Unauthorized: actor ${auth.actor} is neither account owner nor approved operator for ${params.account}`
      );
    }

    const s = params.symbol.toUpperCase();
    const market = this.markets.get(s);
    if (!market) throw new Error(`Market ${s} is not registered`);

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
      openedAt: this.clock.now()
    };

    this.positions.set(positionId, position);
    return { ...position };
  }

  /**
   * Closes an active position. Can ONLY be called by the authenticated owner or approved operator.
   */
  public closePosition(auth: AuthContext, positionId: string): SettlementReceipt {
    if (!auth || !auth.actor) {
      throw new Error("Authentication required: missing auth context");
    }

    const position = this.positions.get(positionId);
    if (!position) throw new Error(`Position ${positionId} not found`);

    if (!this.isAuthorized(auth, position.account)) {
      throw new Error(
        `Unauthorized: actor ${auth.actor} cannot close position ${positionId} owned by ${position.account}`
      );
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

    this.positions.delete(positionId);

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

  /**
   * Settles dynamic funding across all positions in a market for an elapsed 8-hour epoch.
   * Protects insurance fund from negative unbacked liabilities.
   */
  public settleFunding(symbol: string): {
    settledPositions: number;
    epoch: number;
    fundingRateBps: bigint;
    totalLongPayment: bigint;
    totalShortPayment: bigint;
    netImbalance: bigint;
    insuranceFundBalanceUsd: bigint;
    haircutApplied: boolean;
    status: "SETTLED" | "SKIPPED_DUPLICATE_EPOCH";
  } {
    const s = symbol.toUpperCase();
    const market = this.markets.get(s);
    if (!market) throw new Error(`Market ${s} is not registered`);

    const currentEpoch = Math.floor(this.clock.now() / FUNDING_INTERVAL_MS);

    if (currentEpoch <= market.lastSettledEpoch) {
      return {
        settledPositions: 0,
        epoch: currentEpoch,
        fundingRateBps: market.fundingRateBps,
        totalLongPayment: 0n,
        totalShortPayment: 0n,
        netImbalance: 0n,
        insuranceFundBalanceUsd: market.insuranceFundBalanceUsd,
        haircutApplied: false,
        status: "SKIPPED_DUPLICATE_EPOCH"
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

    const netImbalance = totalLongPayment + totalShortPayment;
    let haircutApplied = false;

    if (netImbalance >= 0n) {
      // Surplus credited to insurance fund
      market.insuranceFundBalanceUsd += netImbalance;
    } else {
      // Deficit: payers owe less than receivers are due
      const deficit = -netImbalance;
      if (market.insuranceFundBalanceUsd >= deficit) {
        market.insuranceFundBalanceUsd -= deficit;
      } else {
        // Insurance fund depleted: cap at zero, prevent negative unbacked liabilities
        market.insuranceFundBalanceUsd = 0n;
        haircutApplied = true;
      }
    }

    market.lastSettledEpoch = currentEpoch;

    return {
      settledPositions: count,
      epoch: currentEpoch,
      fundingRateBps: market.fundingRateBps,
      totalLongPayment,
      totalShortPayment,
      netImbalance,
      insuranceFundBalanceUsd: market.insuranceFundBalanceUsd,
      haircutApplied,
      status: "SETTLED"
    };
  }

  public liquidatePosition(auth: AuthContext, positionId: string): LiquidationReceipt {
    if (!auth || !auth.actor) {
      throw new Error("Authentication required: liquidator actor must be provided");
    }

    const position = this.positions.get(positionId);
    if (!position) throw new Error(`Position ${positionId} not found`);

    const market = this.markets.get(position.marketSymbol)!;

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
      liquidator: auth.actor,
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
