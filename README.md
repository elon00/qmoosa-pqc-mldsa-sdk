# @qmoosa/pqc-mldsa-sdk

**QMOOSA Post-Quantum Cryptography — NIST FIPS 204 ML-DSA TypeScript SDK & Web4 Transaction Signer**

Part of the **QMOOSA-1000 Sovereign Web4 Infrastructure Portfolio** (Repository 058 / 1,000, Domain 2: Post-Quantum Cryptography & Zero-Knowledge Reality Gates, Batch 12).

---

## 1. Overview & Capabilities

`@qmoosa/pqc-mldsa-sdk` provides an application-level interface for integrating post-quantum digital signatures into Web4 decentralized applications, wallets, and smart contract execution layers.

- **Client Abstraction:** `MlDsaClient` wraps the audited engine to streamline key management, message signing, and signature verification.
- **Web4 Transaction Envelopes:** Canonical serialization and immutable signed transaction envelopes binding chain IDs, nonces, addresses, values, payloads, and domain separation context strings.
- **Serialization Utilities:** Constant-time and zero-allocation hex and base64url helpers.

---

## 2. Invariants & Reality Gates

1. **Deterministic Canonical Hashing:** Strict JSON attribute normalization ensures consistent payload hashing across heterogeneous clients.
2. **Context-Bound Signatures:** Replay attacks across distinct networks are prevented by cryptographically binding the target `chainId` into the FIPS 204 context string.
3. **Adversarial Negative Controls:** Built-in verification against payload tampering, nonce modification, and cross-chain replays.

---

## 3. Scorecard & Status

- **License:** MIT
- **Production Certification Status:** 0 / 1,000 (Locked from mainnet deployment until formal audit sign-offs).
- **Cost Incurred:** $0.00
