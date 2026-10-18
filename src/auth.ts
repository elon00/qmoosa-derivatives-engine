import crypto from "node:crypto";

export interface SignedIntent {
  account: string;
  caller: string;
  action: string;
  nonce: bigint;
  deadline: number;
  paramsHash: string;
  signature: string;
}

export class AuthManager {
  private accountNonces: Map<string, bigint> = new Map();
  private accountCredentials: Map<string, string> = new Map();

  /**
   * Registers a cryptographic key or secret for an account.
   */
  public registerAccountCredential(account: string, secretKey: string): void {
    if (!account || !secretKey) {
      throw new Error("Account and secret key are required");
    }
    this.accountCredentials.set(account.toLowerCase(), secretKey);
  }

  public getNonce(account: string): bigint {
    return this.accountNonces.get(account.toLowerCase()) ?? 0n;
  }

  public static hashParams(params: unknown): string {
    const canonical = JSON.stringify(params, (_, v) => (typeof v === "bigint" ? v.toString() : v));
    return crypto.createHash("sha256").update(canonical).digest("hex");
  }

  public static computeSignature(
    account: string,
    caller: string,
    action: string,
    nonce: bigint,
    deadline: number,
    paramsHash: string,
    secretKey: string
  ): string {
    const payload = `${account.toLowerCase()}:${caller.toLowerCase()}:${action}:${nonce}:${deadline}:${paramsHash}`;
    return crypto.createHmac("sha256", secretKey).update(payload).digest("hex");
  }

  /**
   * Helper to sign an intent for an account.
   */
  public signIntent(
    account: string,
    caller: string,
    action: string,
    params: unknown,
    secretKey: string,
    deadlineMs: number = Date.now() + 300_000 // 5 minutes validity
  ): SignedIntent {
    const nextNonce = this.getNonce(account) + 1n;
    const paramsHash = AuthManager.hashParams(params);
    const signature = AuthManager.computeSignature(
      account,
      caller,
      action,
      nextNonce,
      deadlineMs,
      paramsHash,
      secretKey
    );

    return {
      account: account.toLowerCase(),
      caller: caller.toLowerCase(),
      action,
      nonce: nextNonce,
      deadline: deadlineMs,
      paramsHash,
      signature
    };
  }

  /**
   * Verifies that the intent is signed by the registered account credential,
   * is within the valid time deadline, matches canonical parameters, and matches the sequential nonce.
   */
  public verifyAndConsumeIntent(
    intent: SignedIntent,
    expectedParams: unknown,
    currentTime: number = Date.now()
  ): void {
    const acc = intent.account.toLowerCase();
    const caller = intent.caller.toLowerCase();

    // Check expiration
    if (currentTime > intent.deadline) {
      throw new Error(`Signature expired: deadline ${intent.deadline} < current ${currentTime}`);
    }

    // Check nonce (replay defense)
    const expectedNonce = this.getNonce(acc) + 1n;
    if (intent.nonce !== expectedNonce) {
      throw new Error(`Invalid nonce: expected ${expectedNonce}, got ${intent.nonce}`);
    }

    // Check parameter integrity
    const expectedHash = AuthManager.hashParams(expectedParams);
    if (intent.paramsHash !== expectedHash) {
      throw new Error(`Parameter hash mismatch: intent does not match canonical payload`);
    }

    // Retrieve credential
    const secret = this.accountCredentials.get(acc);
    if (!secret) {
      throw new Error(`No credential registered for account ${acc}`);
    }

    // Cryptographic signature check
    const expectedSig = AuthManager.computeSignature(
      acc,
      caller,
      intent.action,
      intent.nonce,
      intent.deadline,
      expectedHash,
      secret
    );

    if (intent.signature !== expectedSig) {
      throw new Error("Cryptographic signature verification failed: invalid signature");
    }

    // Advance nonce
    this.accountNonces.set(acc, intent.nonce);
  }
}
