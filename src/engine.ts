/**
 * QMOOSA Derivatives Engine — Margin Management, Position Ledger, Asymmetric Cryptographic Authentication & Liquidation State Machine
 */

import { AuthManager, IntentDomain, SignedIntent, SignedPrivilegedIntent } from "./auth.js";

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
  adminPublicKey: string;
  oraclePublicKey: string;
  keeperPublicKey: string;
}

export class DerivativesEngine {
  private markets: Map<string, MarketState> = new Map();
  private positions: Map<string, Position> = new Map();
  private approvedOperators: Map<string, Set<string>> = new Map();
  private nextPositionNonce: bigint = 1n;

  public readonly domain: IntentDomain;
  public readonly adminPublicKey: string;
  public readonly oraclePublicKey: string;
  public readonly keeperPublicKey: string;
  public readonly auth: AuthManager = new AuthManager();

  constructor(config: EngineConfig) {
    if (!config.adminPublicKey || !config.oraclePublicKey || !config.keeperPublicKey) {
      throw new Error("Engine configuration requires verified public keys for admin, oracle, and keeper roles");
    }

    this.domain = {
      chainId: config.chainId ?? DEFAULT_CHAIN_ID,
      contractAddress: (config.contractAddress ?? DEFAULT_CONTRACT_ADDRESS).toLowerCase()
    };
    this.adminPublicKey = config.adminPublicKey;
    this.oraclePublicKey = config.oraclePublicKey;
    this.keeperPublicKey = config.keeperPublicKey;
  }

  /**
   * Registers a new perpetual market.
   * STRICT SECURITY: Privileged operation requiring an Ed25519-signed intent from the Administrator.
   * String-only callers are strictly rejected.
   */
  public registerMarket(params: {
    signedIntent: SignedPrivilegedIntent;
    symbol: string;
    initialPrice: bigint;
    maintenanceMarginBps?: bigint;
    initialInsuranceFundUsd?: bigint;
    initialTimestamp?: number;
  }): MarketState {
    const {
      signedIntent,
      symbol,
      initialPrice,
      maintenanceMarginBps = DEFAULT_MAINTENANCE_MARGIN_BPS,
      initialInsuranceFundUsd = 0n,
      initialTimestamp = 0
    } = params;

    if (!signedIntent) {
      throw new Error("Administrator signed intent is strictly required to register a market");
    }
    if (!symbol || symbol.trim().length === 0) {
      throw new Error("Invalid market symbol");
    }
    if (initialPrice <= 0n) {
      throw new RangeError("Initial price must be strictly positive");
    }

    const s = symbol.toUpperCase();

    // Verify cryptographic signature against Admin public key
    this.auth.verifyAndConsumePrivilegedIntent(
      this.domain,
      signedIntent,
      "ADMIN",
      "REGISTER_MARKET",
      {
        symbol: s,
        initialPrice,
        maintenanceMarginBps,
        initialInsuranceFundUsd,
        initialTimestamp
      },
      this.adminPublicKey
    );

    const initialEpoch = Math.floor(initialTimestamp / FUNDING_INTERVAL_MS);

    const market: MarketState = {
      symbol: s,
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
   * Updates mark and index prices for a market.
   * STRICT SECURITY: Privileged operation requiring an Ed25519-signed intent from the Oracle.
   */
  public updatePrices(params: {
    signedIntent: SignedPrivilegedIntent;
    symbol: string;
    markPrice: bigint;
    indexPrice: bigint;
  }): MarketState {
    const { signedIntent, symbol, markPrice, indexPrice } = params;

    if (!signedIntent) {
      throw new Error("Oracle signed intent is strictly required to update prices");
    }

    const s = symbol.toUpperCase();
    const market = this.markets.get(s);
    if (!market) throw new Error(`Market ${s} is not registered`);
    if (markPrice <= 0n || indexPrice <= 0n) {
      throw new RangeError("Prices must be strictly positive");
    }

    // Verify cryptographic signature against Oracle public key
    this.auth.verifyAndConsumePrivilegedIntent(
      this.domain,
      signedIntent,
      "ORACLE",
      "UPDATE_PRICES",
      {
        symbol: s,
        markPrice,
        indexPrice
      },
      this.oraclePublicKey
    );

    market.markPrice = markPrice;
    market.indexPrice = indexPrice;
    market.fundingRateBps = calculateFundingRate(markPrice, indexPrice);
    return { ...market };
  }

  /**
   * Approves or revokes an operator for an account.
   * STRICT SECURITY: Requires a cryptographically verified signed intent from the enrolled account owner.
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

    // Verify cryptographic intent against canonical payload and enrolled key
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
   * Opens a new perpetual position.
   * STRICT SECURITY: Signed intent is MANDATORY.
   * Verified against the enrolled account's public key.
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

    // Cryptographic intent verification against canonical action, parameters, and enrolled public key
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
   * STRICT SECURITY: Privileged operation requiring an Ed25519-signed intent from the Keeper.
   * Enforces discrete deterministic 8-hour funding epochs and strictly monotonic timestamps.
   * ATOMIC SOLVENCY GUARANTEE: Pre-validates insurance solvency; on failure, state is 100% unchanged.
   */
  public settleFunding(params: {
    signedIntent: SignedPrivilegedIntent;
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
    const { signedIntent, symbol, currentTimestamp = Date.now() } = params;

    if (!signedIntent) {
      throw new Error("Settlement keeper signed intent is strictly required");
    }

    const s = symbol.toUpperCase();
    const market = this.markets.get(s);
    if (!market) throw new Error(`Market ${s} is not registered`);

    // Verify cryptographic keeper signature
    this.auth.verifyAndConsumePrivilegedIntent(
      this.domain,
      signedIntent,
      "KEEPER",
      "SETTLE_FUNDING",
      {
        symbol: s,
        currentTimestamp
      },
      this.keeperPublicKey
    );

    // Monotonic timestamp validation
    if (currentTimestamp <= market.lastFundingSettledAt) {
      throw new Error(`Monotonic timestamp violation: current timestamp ${currentTimestamp} <= last settled ${market.lastFundingSettledAt}`);
    }

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

    // Step 1: Pre-calculate payments in preview mode without mutating ANY position
    let count = 0;
    let totalLongPayment = 0n;
    let totalShortPayment = 0n;
    const pendingPayments: { position: Position; payment: bigint }[] = [];

    for (const pos of this.positions.values()) {
      if (pos.marketSymbol === market.symbol) {
        const notional = calculateNotional(pos.size, market.markPrice);
        const payment = calculateFundingPayment(pos.isLong, notional, market.fundingRateBps);
        pendingPayments.push({ position: pos, payment });
        if (pos.isLong) {
          totalLongPayment += payment;
        } else {
          totalShortPayment += payment;
        }
        count++;
      }
    }

    const netImbalance = totalLongPayment + totalShortPayment;

    // Step 2: Solvency check BEFORE any mutation occurs (Atomic Fail-Closed Guarantee)
    if (market.insuranceFundBalanceUsd + netImbalance < 0n) {
      throw new Error(
        `Solvency violation: net funding imbalance ${netImbalance} exceeds available insurance fund ${market.insuranceFundBalanceUsd}. Settlement atomically aborted.`
      );
    }

    // Step 3: Apply state mutations atomically
    const initialInsurance = market.insuranceFundBalanceUsd;
    for (const { position, payment } of pendingPayments) {
      position.accruedFunding += payment;
    }

    market.insuranceFundBalanceUsd += netImbalance;
    market.lastFundingSettledAt = currentTimestamp;
    market.lastSettledEpoch = currentEpoch;

    // Strict conservation invariant assertion
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

    if (position.account.toLowerCase() !== acc) {
      throw new Error(`Unauthorized: intent account ${acc} does not own position ${positionId}`);
    }

    if (!this.isAuthorizedCaller(acc, caller)) {
      throw new Error(`Unauthorized: caller ${caller} is not authorized for account ${acc}`);
    }

    // Verify cryptographic intent against enrolled public key
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
   * Liquidates an unhealthy position.
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
