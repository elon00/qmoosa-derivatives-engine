/**
 * QMOOSA Derivatives Engine — Margin Management, Position Ledger, and Liquidation State Machine
 */

export const WAD = 10n ** 18n;
export const BPS_DIVISOR = 10_000n;
export const MAX_LEVERAGE = 20n;
export const MIN_LEVERAGE = 1n;
export const DEFAULT_MAINTENANCE_MARGIN_BPS = 500n; // 5.00%
export const MAX_FUNDING_RATE_BPS = 500n; // +/- 5.00% cap

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
  private nextPositionNonce: bigint = 1n;

  public registerMarket(
    symbol: string,
    initialPrice: bigint,
    maintenanceMarginBps: bigint = DEFAULT_MAINTENANCE_MARGIN_BPS
  ): MarketState {
    if (!symbol || symbol.trim().length === 0) {
      throw new Error("Invalid market symbol");
    }
    if (initialPrice <= 0n) {
      throw new RangeError("Initial price must be strictly positive");
    }

    const market: MarketState = {
      symbol: symbol.toUpperCase(),
      markPrice: initialPrice,
      indexPrice: initialPrice,
      fundingRateBps: 0n,
      maintenanceMarginBps,
      lastFundingSettledAt: Date.now()
    };

    this.markets.set(market.symbol, market);
    return market;
  }

  public updatePrices(symbol: string, markPrice: bigint, indexPrice: bigint): MarketState {
    const market = this.getMarket(symbol);
    if (markPrice <= 0n || indexPrice <= 0n) {
      throw new RangeError("Prices must be strictly positive");
    }

    market.markPrice = markPrice;
    market.indexPrice = indexPrice;
    market.fundingRateBps = calculateFundingRate(markPrice, indexPrice);
    return market;
  }

  public openPosition(params: {
    account: string;
    symbol: string;
    isLong: boolean;
    size: bigint;
    collateral: bigint;
    leverage: bigint;
  }): Position {
    const market = this.getMarket(params.symbol);
    if (!params.account || params.account.trim().length === 0) {
      throw new Error("Account address is required");
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
    return position;
  }

  public settleFunding(symbol: string): { settledPositions: number; fundingRateBps: bigint } {
    const market = this.getMarket(symbol);
    let count = 0;

    for (const pos of this.positions.values()) {
      if (pos.marketSymbol === market.symbol) {
        const notional = calculateNotional(pos.size, market.markPrice);
        const payment = calculateFundingPayment(pos.isLong, notional, market.fundingRateBps);
        pos.accruedFunding += payment;
        count++;
      }
    }

    market.lastFundingSettledAt = Date.now();
    return { settledPositions: count, fundingRateBps: market.fundingRateBps };
  }

  public closePosition(positionId: string): SettlementReceipt {
    const position = this.getPosition(positionId);
    const market = this.getMarket(position.marketSymbol);

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

  public liquidatePosition(positionId: string, liquidator: string): LiquidationReceipt {
    const position = this.getPosition(positionId);
    const market = this.getMarket(position.marketSymbol);

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
    return market;
  }

  public getPosition(positionId: string): Position {
    const pos = this.positions.get(positionId);
    if (!pos) throw new Error(`Position ${positionId} not found`);
    return pos;
  }

  public getAccountPositions(account: string): Position[] {
    return Array.from(this.positions.values()).filter(p => p.account.toLowerCase() === account.toLowerCase());
  }

  public listMarkets(): MarketState[] {
    return Array.from(this.markets.values());
  }

  public listPositions(): Position[] {
    return Array.from(this.positions.values());
  }
}
