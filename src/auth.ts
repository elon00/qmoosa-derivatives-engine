import crypto from "node:crypto";

export interface IntentDomain {
  chainId: number;
  contractAddress: string;
}

export interface SignedIntent {
  domain: IntentDomain;
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
   * Secure enrollment: Once enrolled, an account's credential cannot be overwritten
   * without calling updateAccountCredential with proof of the current credential.
   */
  public registerAccountCredential(account: string, secretKey: string): void {
    if (!account || !secretKey) {
      throw new Error("Account and secret key are required");
    }
    const acc = account.toLowerCase();
    if (this.accountCredentials.has(acc)) {
      throw new Error(`Account ${acc} already registered; overwrite not permitted without authorization`);
    }
    this.accountCredentials.set(acc, secretKey);
  }

  /**
   * Updates an existing account credential requiring verification of the existing credential.
   */
  public updateAccountCredential(account: string, currentSecretKey: string, newSecretKey: string): void {
    if (!account || !currentSecretKey || !newSecretKey) {
      throw new Error("Account, current secret key, and new secret key are required");
    }
    const acc = account.toLowerCase();
    const existing = this.accountCredentials.get(acc);
    if (!existing) {
      throw new Error(`Account ${acc} is not registered`);
    }
    if (existing !== currentSecretKey) {
      throw new Error("Authorization failure: current credential mismatch");
    }
    this.accountCredentials.set(acc, newSecretKey);
  }

  public isAccountRegistered(account: string): boolean {
    return this.accountCredentials.has(account.toLowerCase());
  }

  public getNonce(account: string): bigint {
    return this.accountNonces.get(account.toLowerCase()) ?? 0n;
  }

  public static canonicalize(obj: unknown): unknown {
    if (obj === null || typeof obj !== "object") {
      return typeof obj === "bigint" ? obj.toString() : obj;
    }
    if (Array.isArray(obj)) {
      return obj.map(AuthManager.canonicalize);
    }
    const sortedKeys = Object.keys(obj as Record<string, unknown>).sort();
    const result: Record<string, unknown> = {};
    for (const key of sortedKeys) {
      result[key] = AuthManager.canonicalize((obj as Record<string, unknown>)[key]);
    }
    return result;
  }

  public static hashParams(params: unknown): string {
    const canonical = JSON.stringify(AuthManager.canonicalize(params));
    return crypto.createHash("sha256").update(canonical).digest("hex");
  }

  public static computeSignature(
    domain: IntentDomain,
    account: string,
    caller: string,
    action: string,
    nonce: bigint,
    deadline: number,
    paramsHash: string,
    secretKey: string
  ): string {
    const payload = `${domain.chainId}:${domain.contractAddress.toLowerCase()}:${account.toLowerCase()}:${caller.toLowerCase()}:${action}:${nonce}:${deadline}:${paramsHash}`;
    return crypto.createHmac("sha256", secretKey).update(payload).digest("hex");
  }

  /**
   * Helper to construct and sign an intent for an account.
   */
  public signIntent(
    domain: IntentDomain,
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
      domain,
      account,
      caller,
      action,
      nextNonce,
      deadlineMs,
      paramsHash,
      secretKey
    );

    return {
      domain: {
        chainId: domain.chainId,
        contractAddress: domain.contractAddress.toLowerCase()
      },
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
   * matches the target domain (chainId & contractAddress), matches expected action and caller,
   * is within the valid time deadline, matches canonical parameters, and matches sequential nonce.
   */
  public verifyAndConsumeIntent(
    expectedDomain: IntentDomain,
    intent: SignedIntent,
    expectedAction: string,
    expectedCaller: string,
    expectedParams: unknown,
    currentTime: number = Date.now()
  ): void {
    if (!intent) {
      throw new Error("Cryptographic intent is required");
    }

    // Check domain binding
    if (intent.domain.chainId !== expectedDomain.chainId) {
      throw new Error(`Domain chainId mismatch: expected ${expectedDomain.chainId}, got ${intent.domain.chainId}`);
    }
    if (intent.domain.contractAddress.toLowerCase() !== expectedDomain.contractAddress.toLowerCase()) {
      throw new Error(
        `Domain contractAddress mismatch: expected ${expectedDomain.contractAddress.toLowerCase()}, got ${intent.domain.contractAddress.toLowerCase()}`
      );
    }

    // Check action
    if (intent.action !== expectedAction) {
      throw new Error(`Action mismatch: expected ${expectedAction}, got ${intent.action}`);
    }

    const acc = intent.account.toLowerCase();
    const caller = intent.caller.toLowerCase();

    // Check caller binding
    if (caller !== expectedCaller.toLowerCase()) {
      throw new Error(`Caller mismatch: expected ${expectedCaller.toLowerCase()}, got ${caller}`);
    }

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
      expectedDomain,
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
