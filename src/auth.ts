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

export interface SignedPrivilegedIntent {
  domain: IntentDomain;
  role: "ADMIN" | "ORACLE" | "KEEPER";
  action: string;
  nonce: bigint;
  deadline: number;
  paramsHash: string;
  signature: string;
}

export interface EnrollmentProof {
  account: string;
  publicKey: string;
  enrollmentSignature: string;
  timestamp: number;
}

export class AuthManager {
  private accountNonces: Map<string, bigint> = new Map();
  private roleNonces: Map<string, bigint> = new Map();
  private accountPublicKeys: Map<string, string> = new Map();

  /**
   * Generates a standard Ed25519 asymmetric cryptographic keypair.
   */
  public static generateKeyPair(): { publicKey: string; privateKey: string } {
    return crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" }
    });
  }

  public static computeEnrollmentChallenge(account: string, timestamp: number): string {
    return `QMOOSA:ENROLL:${account.toLowerCase()}:${timestamp}`;
  }

  public static signMessage(message: string, privateKey: string): string {
    return crypto.sign(null, Buffer.from(message), privateKey).toString("hex");
  }

  public static verifySignature(message: string, publicKey: string, signatureHex: string): boolean {
    try {
      return crypto.verify(null, Buffer.from(message), publicKey, Buffer.from(signatureHex, "hex"));
    } catch {
      return false;
    }
  }

  /**
   * Creates a verifiable account enrollment proof signed by the account's private key.
   */
  public createEnrollmentProof(
    account: string,
    publicKey: string,
    privateKey: string,
    timestamp: number = Date.now()
  ): EnrollmentProof {
    const challenge = AuthManager.computeEnrollmentChallenge(account, timestamp);
    const enrollmentSignature = AuthManager.signMessage(challenge, privateKey);
    return {
      account: account.toLowerCase(),
      publicKey,
      enrollmentSignature,
      timestamp
    };
  }

  /**
   * Enrolls an account using an asymmetric cryptographic ownership proof.
   * Prohibits unverified registration or hostile takeover of accounts.
   */
  public enrollAccount(proof: EnrollmentProof, currentTime: number = Date.now()): void {
    if (!proof || !proof.account || !proof.publicKey || !proof.enrollmentSignature) {
      throw new Error("Invalid enrollment request: account, publicKey, and enrollmentSignature are required");
    }

    const acc = proof.account.toLowerCase();
    if (this.accountPublicKeys.has(acc)) {
      throw new Error(`Account ${acc} already enrolled; re-enrollment without key rotation proof is prohibited`);
    }

    // Verify timestamp freshness (within 5 minutes)
    if (Math.abs(currentTime - proof.timestamp) > 300_000) {
      throw new Error(`Enrollment proof timestamp expired or out of bounds (timestamp: ${proof.timestamp}, current: ${currentTime})`);
    }

    // Cryptographically verify ownership of the claimed public key
    const challenge = AuthManager.computeEnrollmentChallenge(acc, proof.timestamp);
    const isValid = AuthManager.verifySignature(challenge, proof.publicKey, proof.enrollmentSignature);
    if (!isValid) {
      throw new Error("Cryptographic enrollment verification failed: signature does not prove ownership of public key");
    }

    this.accountPublicKeys.set(acc, proof.publicKey);
  }

  public isAccountEnrolled(account: string): boolean {
    return this.accountPublicKeys.has(account.toLowerCase());
  }

  public getPublicKey(account: string): string | undefined {
    return this.accountPublicKeys.get(account.toLowerCase());
  }

  public getNonce(account: string): bigint {
    return this.accountNonces.get(account.toLowerCase()) ?? 0n;
  }

  public getRoleNonce(role: string): bigint {
    return this.roleNonces.get(role.toUpperCase()) ?? 0n;
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

  public static computeIntentPayload(
    domain: IntentDomain,
    account: string,
    caller: string,
    action: string,
    nonce: bigint,
    deadline: number,
    paramsHash: string
  ): string {
    return `${domain.chainId}:${domain.contractAddress.toLowerCase()}:${account.toLowerCase()}:${caller.toLowerCase()}:${action}:${nonce}:${deadline}:${paramsHash}`;
  }

  public static computePrivilegedPayload(
    domain: IntentDomain,
    role: string,
    action: string,
    nonce: bigint,
    deadline: number,
    paramsHash: string
  ): string {
    return `${domain.chainId}:${domain.contractAddress.toLowerCase()}:${role.toUpperCase()}:${action}:${nonce}:${deadline}:${paramsHash}`;
  }

  /**
   * Signs an intent using the account's Ed25519 private key.
   */
  public signIntent(
    domain: IntentDomain,
    account: string,
    caller: string,
    action: string,
    params: unknown,
    privateKey: string,
    deadlineMs: number = Date.now() + 300_000
  ): SignedIntent {
    const nextNonce = this.getNonce(account) + 1n;
    const paramsHash = AuthManager.hashParams(params);
    const payload = AuthManager.computeIntentPayload(
      domain,
      account,
      caller,
      action,
      nextNonce,
      deadlineMs,
      paramsHash
    );

    const signature = AuthManager.signMessage(payload, privateKey);

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
   * Signs a privileged intent (Admin, Oracle, Keeper) using the role's private key.
   */
  public signPrivilegedIntent(
    domain: IntentDomain,
    role: "ADMIN" | "ORACLE" | "KEEPER",
    action: string,
    params: unknown,
    privateKey: string,
    deadlineMs: number = Date.now() + 300_000
  ): SignedPrivilegedIntent {
    const nextNonce = this.getRoleNonce(role) + 1n;
    const paramsHash = AuthManager.hashParams(params);
    const payload = AuthManager.computePrivilegedPayload(
      domain,
      role,
      action,
      nextNonce,
      deadlineMs,
      paramsHash
    );

    const signature = AuthManager.signMessage(payload, privateKey);

    return {
      domain: {
        chainId: domain.chainId,
        contractAddress: domain.contractAddress.toLowerCase()
      },
      role,
      action,
      nonce: nextNonce,
      deadline: deadlineMs,
      paramsHash,
      signature
    };
  }

  /**
   * Verifies an intent signed by an enrolled account public key.
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

    if (intent.domain.chainId !== expectedDomain.chainId) {
      throw new Error(`Domain chainId mismatch: expected ${expectedDomain.chainId}, got ${intent.domain.chainId}`);
    }
    if (intent.domain.contractAddress.toLowerCase() !== expectedDomain.contractAddress.toLowerCase()) {
      throw new Error(
        `Domain contractAddress mismatch: expected ${expectedDomain.contractAddress.toLowerCase()}, got ${intent.domain.contractAddress.toLowerCase()}`
      );
    }

    if (intent.action !== expectedAction) {
      throw new Error(`Action mismatch: expected ${expectedAction}, got ${intent.action}`);
    }

    const acc = intent.account.toLowerCase();
    const caller = intent.caller.toLowerCase();

    if (caller !== expectedCaller.toLowerCase()) {
      throw new Error(`Caller mismatch: expected ${expectedCaller.toLowerCase()}, got ${caller}`);
    }

    if (currentTime > intent.deadline) {
      throw new Error(`Signature expired: deadline ${intent.deadline} < current ${currentTime}`);
    }

    const expectedNonce = this.getNonce(acc) + 1n;
    if (intent.nonce !== expectedNonce) {
      throw new Error(`Invalid nonce: expected ${expectedNonce}, got ${intent.nonce}`);
    }

    const expectedHash = AuthManager.hashParams(expectedParams);
    if (intent.paramsHash !== expectedHash) {
      throw new Error("Parameter hash mismatch: intent does not match canonical payload");
    }

    const publicKey = this.accountPublicKeys.get(acc);
    if (!publicKey) {
      throw new Error(`Account ${acc} is not enrolled: no verified public key registered`);
    }

    const payload = AuthManager.computeIntentPayload(
      expectedDomain,
      acc,
      caller,
      intent.action,
      intent.nonce,
      intent.deadline,
      expectedHash
    );

    const isValid = AuthManager.verifySignature(payload, publicKey, intent.signature);
    if (!isValid) {
      throw new Error("Cryptographic signature verification failed: invalid signature");
    }

    this.accountNonces.set(acc, intent.nonce);
  }

  /**
   * Verifies a privileged role intent (Admin, Oracle, Keeper) signed by the authorized role public key.
   */
  public verifyAndConsumePrivilegedIntent(
    expectedDomain: IntentDomain,
    intent: SignedPrivilegedIntent,
    expectedRole: "ADMIN" | "ORACLE" | "KEEPER",
    expectedAction: string,
    expectedParams: unknown,
    rolePublicKey: string,
    currentTime: number = Date.now()
  ): void {
    if (!intent) {
      throw new Error(`Privileged cryptographic intent is required for ${expectedRole}`);
    }

    if (intent.domain.chainId !== expectedDomain.chainId) {
      throw new Error(`Domain chainId mismatch: expected ${expectedDomain.chainId}, got ${intent.domain.chainId}`);
    }
    if (intent.domain.contractAddress.toLowerCase() !== expectedDomain.contractAddress.toLowerCase()) {
      throw new Error(`Domain contractAddress mismatch`);
    }

    if (intent.role !== expectedRole) {
      throw new Error(`Role mismatch: expected ${expectedRole}, got ${intent.role}`);
    }

    if (intent.action !== expectedAction) {
      throw new Error(`Action mismatch: expected ${expectedAction}, got ${intent.action}`);
    }

    if (currentTime > intent.deadline) {
      throw new Error(`Privileged signature expired`);
    }

    const expectedNonce = this.getRoleNonce(expectedRole) + 1n;
    if (intent.nonce !== expectedNonce) {
      throw new Error(`Invalid privileged nonce: expected ${expectedNonce}, got ${intent.nonce}`);
    }

    const expectedHash = AuthManager.hashParams(expectedParams);
    if (intent.paramsHash !== expectedHash) {
      throw new Error("Privileged parameter hash mismatch");
    }

    const payload = AuthManager.computePrivilegedPayload(
      expectedDomain,
      expectedRole,
      expectedAction,
      intent.nonce,
      intent.deadline,
      expectedHash
    );

    const isValid = AuthManager.verifySignature(payload, rolePublicKey, intent.signature);
    if (!isValid) {
      throw new Error(`Cryptographic verification failed: invalid signature for privileged role ${expectedRole}`);
    }

    this.roleNonces.set(expectedRole.toUpperCase(), intent.nonce);
  }
}
