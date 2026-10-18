/**
 * QMOOSA Post-Quantum Cryptography — NIST FIPS 204 ML-DSA TypeScript SDK
 *
 * Provides client abstractions, transaction authorization envelope creation,
 * canonical transaction serialization, and cryptographic signing utilities.
 */

import { createHash } from 'node:crypto';
import {
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
  getMlDsaParameters,
  constantTimeEqual,
  type MlDsaParameterName,
  type MlDsaParameters,
  type MlDsaKeyPair,
  type MlDsaSignatureResult,
  type Web4SignedTransactionEnvelope
} from '@qmoosa/pqc-mldsa-protocol';
import {
  MlDsaEngine,
  type KeyGenOptions,
  type SignOptions,
  type VerifyOptions
} from '@qmoosa/pqc-mldsa-engine';

export * from '@qmoosa/pqc-mldsa-protocol';
export * from '@qmoosa/pqc-mldsa-engine';

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error('INVALID_HEX_STRING: Length must be even');
  }
  return new Uint8Array(Buffer.from(clean, 'hex'));
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function base64UrlToBytes(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, 'base64url'));
}

export interface SerializedMlDsaKeyPair {
  readonly publicKeyHex: string;
  readonly secretKeyHex: string;
  readonly parameterSet: MlDsaParameterName;
}

export interface SerializedMlDsaSignature {
  readonly signatureHex: string;
  readonly parameterSet: MlDsaParameterName;
}

export interface UnsignedTransaction {
  readonly chainId: string;
  readonly nonce: number;
  readonly fromAddress: string;
  readonly toAddress: string;
  readonly value: string;
  readonly payloadHex: string;
  readonly contextString: string;
}

/**
 * Computes canonical SHA-256 hash of an unsigned transaction payload.
 * Guarantees deterministic field ordering for cross-platform signing.
 */
export function canonicalTransactionHash(tx: UnsignedTransaction): Uint8Array {
  const canonicalString = JSON.stringify({
    chainId: tx.chainId,
    contextString: tx.contextString,
    fromAddress: tx.fromAddress.toLowerCase(),
    nonce: tx.nonce,
    payloadHex: tx.payloadHex.toLowerCase().replace(/^0x/, ''),
    toAddress: tx.toAddress.toLowerCase(),
    value: tx.value
  });

  return new Uint8Array(createHash('sha256').update(canonicalString, 'utf8').digest());
}

export class MlDsaClient {
  private readonly engine: MlDsaEngine;

  constructor(engine?: MlDsaEngine) {
    this.engine = engine ?? new MlDsaEngine();
  }

  public createKeyPair(
    paramName: MlDsaParameterName = ML_DSA_65.name,
    options?: KeyGenOptions
  ): SerializedMlDsaKeyPair {
    const kp = this.engine.generateKeyPair(paramName, options);
    return Object.freeze({
      publicKeyHex: bytesToHex(kp.publicKey),
      secretKeyHex: bytesToHex(kp.secretKey),
      parameterSet: paramName
    });
  }

  public signMessage(
    messageBytes: Uint8Array,
    secretKeyHex: string,
    paramName: MlDsaParameterName = ML_DSA_65.name,
    options?: SignOptions
  ): SerializedMlDsaSignature {
    const sk = hexToBytes(secretKeyHex);
    const res = this.engine.sign(messageBytes, sk, paramName, options);
    return Object.freeze({
      signatureHex: bytesToHex(res.signature),
      parameterSet: paramName
    });
  }

  public verifySignature(
    signatureHex: string,
    messageBytes: Uint8Array,
    publicKeyHex: string,
    paramName: MlDsaParameterName = ML_DSA_65.name,
    options?: VerifyOptions
  ): boolean {
    const sig = hexToBytes(signatureHex);
    const pk = hexToBytes(publicKeyHex);
    return this.engine.verify(sig, messageBytes, pk, paramName, options);
  }

  /**
   * Signs a Web4 transaction and bundles it into an immutable authorization envelope.
   */
  public signTransaction(
    tx: UnsignedTransaction,
    secretKeyHex: string,
    publicKeyHex: string,
    paramName: MlDsaParameterName = ML_DSA_65.name,
    timestamp = Date.now()
  ): Web4SignedTransactionEnvelope {
    const txHash = canonicalTransactionHash(tx);
    const sig = this.signMessage(txHash, secretKeyHex, paramName, {
      context: tx.contextString
    });

    return Object.freeze({
      chainId: tx.chainId,
      nonce: tx.nonce,
      fromAddress: tx.fromAddress,
      toAddress: tx.toAddress,
      value: tx.value,
      payloadHex: tx.payloadHex,
      contextString: tx.contextString,
      parameterSet: paramName,
      publicKeyHex,
      signatureHex: sig.signatureHex,
      timestamp
    });
  }

  /**
   * Verifies an immutable Web4 transaction envelope against its post-quantum signature.
   */
  public verifyTransaction(envelope: Web4SignedTransactionEnvelope): boolean {
    const unsignedTx: UnsignedTransaction = {
      chainId: envelope.chainId,
      nonce: envelope.nonce,
      fromAddress: envelope.fromAddress,
      toAddress: envelope.toAddress,
      value: envelope.value,
      payloadHex: envelope.payloadHex,
      contextString: envelope.contextString
    };

    const txHash = canonicalTransactionHash(unsignedTx);
    return this.verifySignature(
      envelope.signatureHex,
      txHash,
      envelope.publicKeyHex,
      envelope.parameterSet,
      { context: envelope.contextString }
    );
  }
}
