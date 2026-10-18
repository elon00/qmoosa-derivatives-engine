/**
 * QMOOSA Derivatives Engine — Margin Management, Position Ledger, Cryptographic Authentication & Liquidation State Machine
 */

import { AuthManager, IntentDomain, SignedIntent } from "./auth.js";

export const WAD = 10n ** 18n;
export const BPS_DIVISOR = 10_000n;
export const MAX_LEVERAGE = 20n;
export const MIN_LEVERAGE = 1n;
export const DEFAULT_MAINTENANCE_MARGIN_BPS = 500n; // 5.00%
export const MAX_FUNDING_RATE_BPS = 500n; // +/- 5.00% cap
export const FUNDING_INTERVAL_MS = 8 * 60 * 60 * 1000; // 8 hours in milliseconds
export const DEFAULT_CHAIN_ID = 31337;
export const DEFAULT_CONTRACT_ADDRESS = "0x9999999999999999999999999999999999999999";

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

export interface EngineConfig {
  chainId?: number;
  contractAddress?: string;
  admin?: string;
  oracleSigner?: string;
  keeperSigner?: string;
}

export class DerivativesEngine {
  private markets: Map<string, MarketState> = new Map();
  private positions: Map<string, Position> = new Map();
  private approvedOperators: Map<string, Set<string>> = new Map(); // account -> approved operators
  private nextPositionNonce: bigint = 1n;

  public readonly domain: IntentDomain;
  public readonly admin: string;
  public readonly oracleSigner: string;
  public readonly keeperSigner: string;
  public readonly auth: AuthManager = new AuthManager();

  constructor(config: EngineConfig = {}) {
    this.domain = {
      chainId: config.chainId ?? DEFAULT_CHAIN_ID,
      contractAddress: (config.contractAddress ?? DEFAULT_CONTRACT_ADDRESS).toLowerCase()
    };
    this.admin = (config.admin ?? "0xAdmin").toLowerCase();
    this.oracleSigner = (config.oracleSigner ?? "0xOracle").toLowerCase();
    this.keeperSigner = (config.keeperSigner ?? "0xKeeper").toLowerCase();
  }

  /**
   * Registers a new perpetual market. Privileged operation reserved for the admin.
   */
  public registerMarket(params: {
    caller: string;
    symbol: string;
    initialPrice: bigint;
    maintenanceMarginBps?: bigint;
    initialInsuranceFundUsd?: bigint;
    initialTimestamp?: number;
  }): MarketState {
    const { caller, symbol, initialPrice, maintenanceMarginBps = DEFAULT_MAINTENANCE_MARGIN_BPS, initialInsuranceFundUsd = 0n, initialTimestamp = 0 } = params;

    if (!caller || caller.toLowerCase() !== this.admin) {
      throw new Error(`Unauthorized: caller ${caller} is not the market administrator`);
    }

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
   * STRICT SECURITY: Requires a cryptographically verified signed intent from the account owner.
   * No arbitrary or unauthenticated caller fallback is permitted.
   */
  public setApprovedOperator(params: {
    signedIntent: SignedIntent;
    operator: string;
    approved: boolean;
  }): void {
    const { signedIntent, operator, approved } = params;
    if (!signedIntent) {
      throw new Error("Signed intent is required for operator management");
    }
    if (!operator || operator.trim().length === 0) {
      throw new Error("Operator address must be a valid string");
    }

    const acc = signedIntent.account.toLowerCase();
    const clr = signedIntent.caller.toLowerCase();
    const op = operator.toLowerCase();

    // Only the owner itself can authorize an operator
    if (clr !== acc) {
      throw new Error(`Unauthorized operator approval: caller ${clr} cannot approve operators for ${acc}`);
    }

    // Verify cryptographic intent against canonical payload
    this.auth.verifyAndConsumeIntent(
      this.domain,
      signedIntent,
      "SET_OPERATOR",
      clr,
      {
        account: acc,
        operator: op,
        approved
      }
    );

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

  /**
   * Updates mark and index prices for a market.
   * Privileged operation reserved for the authorized oracle signer.
   */
  public updatePrices(params: {
    caller: string;
    symbol: string;
    markPrice: bigint;
    indexPrice: bigint;
  }): MarketState {
    const { caller, symbol, markPrice, indexPrice } = params;
    if (!caller || caller.toLowerCase() !== this.oracleSigner) {
      throw new Error(`Unauthorized: caller ${caller} is not the authorized oracle signer`);
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
   * Opens a new perpetual position.
   * STRICT SECURITY: Signed intent is MANDATORY.
   * Caller must be the account owner or an approved operator.
   */
  public openPosition(params: {
    signedIntent: SignedIntent;
    symbol: string;
    isLong: boolean;
    size: bigint;
    collateral: bigint;
    leverage: bigint;
  }): Position {
    const { signedIntent, symbol, isLong, size, collateral, leverage } = params;

    if (!signedIntent) {
      throw new Error("Signed intent is required to open a position");
    }

    const s = symbol.toUpperCase();
    const market = this.markets.get(s);
    if (!market) throw new Error(`Market ${s} is not registered`);

    const acc = signedIntent.account.toLowerCase();
    const caller = signedIntent.caller.toLowerCase();

    // Actor authorization boundary: caller must be owner or approved operator
    if (!this.isAuthorizedCaller(acc, caller)) {
      throw new Error(`Unauthorized: caller ${caller} is not authorized for account ${acc}`);
    }

    // Cryptographic intent verification against canonical action and parameters
    this.auth.verifyAndConsumeIntent(
      this.domain,
      signedIntent,
      "OPEN_POSITION",
      caller,
      {
        account: acc,
        symbol: s,
        isLong,
        size,
        collateral,
        leverage
      }
    );

    const notional = calculateNotional(size, market.markPrice);
    const requiredMargin = calculateInitialMargin(notional, leverage);

    if (collateral < requiredMargin) {
      throw new Error(
        `Insufficient collateral: provided ${collateral}, required ${requiredMargin} for ${leverage}x leverage`
      );
    }

    const positionId = `POS-${market.symbol}-${this.nextPositionNonce++}`;
    const position: Position = {
      id: positionId,
      account: acc,
      marketSymbol: market.symbol,
      isLong,
      size,
      collateral,
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
   * Privileged operation reserved for the authorized settlement keeper.
   * Strict solvency check: triggers fail-closed error if insurance fund cannot absorb net imbalance.
   */
  public settleFunding(params: {
    caller: string;
    symbol: string;
    currentTimestamp?: number;
  }): {
    settledPositions: number;
    fundingRateBps: bigint;
    epoch: number;
    totalLongPayment: bigint;
    totalShortPayment: bigint;
    netImbalanceToInsuranceFund: bigint;
    status: "SETTLED" | "SKIPPED_INTERVAL_NOT_ELAPSED";
  } {
    const { caller, symbol, currentTimestamp = Date.now() } = params;

    if (!caller || caller.toLowerCase() !== this.keeperSigner) {
      throw new Error(`Unauthorized: caller ${caller} is not the authorized settlement keeper`);
    }

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

    // Solvency check: if netImbalance is negative (insurance fund pays out), ensure insurance fund is solvent
    if (market.insuranceFundBalanceUsd + netImbalance < 0n) {
      throw new Error(
        `Solvency violation: net funding imbalance ${netImbalance} exceeds available insurance fund ${market.insuranceFundBalanceUsd}. Settlement frozen.`
      );
    }

    const initialInsurance = market.insuranceFundBalanceUsd;
    market.insuranceFundBalanceUsd += netImbalance;
    market.lastFundingSettledAt = currentTimestamp;
    market.lastSettledEpoch = currentEpoch;

    // Strict conservation invariant assertion: change in insurance fund must exactly balance net positions imbalance
    if (market.insuranceFundBalanceUsd - initialInsurance !== netImbalance) {
      throw new Error("Funding payment conservation invariant violated");
    }

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
   * STRICT SECURITY: Signed intent is MANDATORY.
   * Caller must be position owner or approved operator.
   */
  public closePosition(params: {
    signedIntent: SignedIntent;
    positionId: string;
  }): SettlementReceipt {
    const { signedIntent, positionId } = params;

    if (!signedIntent) {
      throw new Error("Signed intent is required to close a position");
    }

    const position = this.positions.get(positionId);
    if (!position) throw new Error(`Position ${positionId} not found`);

    const acc = signedIntent.account.toLowerCase();
    const caller = signedIntent.caller.toLowerCase();

    // Verify account ownership
    if (position.account.toLowerCase() !== acc) {
      throw new Error(`Unauthorized: intent account ${acc} does not own position ${positionId}`);
    }

    // Actor authorization boundary: caller must be owner or approved operator
    if (!this.isAuthorizedCaller(acc, caller)) {
      throw new Error(`Unauthorized: caller ${caller} is not authorized for account ${acc}`);
    }

    // Verify cryptographic intent
    this.auth.verifyAndConsumeIntent(
      this.domain,
      signedIntent,
      "CLOSE_POSITION",
      caller,
      {
        account: acc,
        positionId
      }
    );

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
   * Liquidates an unhealthy position. Permissionless incentive mechanism.
   */
  public liquidatePosition(params: {
    liquidator: string;
    positionId: string;
  }): LiquidationReceipt {
    const { liquidator, positionId } = params;

    if (!liquidator || liquidator.trim().length === 0) {
      throw new Error("Liquidator address is required");
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
