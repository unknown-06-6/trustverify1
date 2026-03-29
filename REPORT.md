# TrustVerify – Project Report

**Course:** Information security/ Applied Cryptography    
**Tool:** TrustVerify — A CLI for File Integrity & Digital Signatures

---

## 1. Why Hashing Alone Is Not Enough to Prove Identity

A cryptographic hash function like SHA-256 takes any input and produces a fixed-length
deterministic fingerprint (digest). If even a single byte of the file changes, the hash
changes completely — this property is called the **avalanche effect**. This makes hashing
excellent for detecting accidental corruption or deliberate tampering with file *content*.

However, hashing on its own provides **integrity** but **not authenticity**. Consider
the following attack scenario:

> Alice sends Bob a ZIP archive together with its SHA-256 hash.  
> A man-in-the-middle (Mallory) intercepts both, replaces the archive with a malicious
> one, recomputes a *new* SHA-256 of the fake archive, and forwards both to Bob.  
> Bob's hash check passes — the hash of the received file matches the hash Mallory sent.
> Bob has no way to know the file didn't come from Alice.

The fundamental problem is that **a hash carries no secret**. Anyone can compute
SHA-256. There is no cryptographic binding between the hash and its author.
To prove identity, we need a mechanism that only the legitimate sender can produce —
namely, a **digital signature**.

---

## 2. How the Private/Public Key Relationship Ensures Non-Repudiation

RSA asymmetric cryptography uses a mathematically linked key pair:

| Key | Held by | Used to |
|---|---|---|
| **Private key** | Sender only (secret) | *Sign* data |
| **Public key** | Anyone (shared freely) | *Verify* the signature |

### Signing Process (Sender – Alice)

1. Alice computes `H = SHA-256(metadata.json)`.
2. Alice encrypts `H` with her **private key** → produces a **signature** `S`.
3. Alice distributes: `metadata.json`, `manifest.sig` (= `S`), and `public_key.pem`.

### Verification Process (Receiver – Bob)

1. Bob recomputes `H' = SHA-256(metadata.json)` from the file he received.
2. Bob decrypts `S` using Alice's **public key** → recovers `H_original`.
3. If `H' == H_original` → the manifest is authentic **and** untampered.

### Why This Guarantees Non-Repudiation

- **Only Alice's private key can produce a valid signature** that Alice's public key
  verifies. No one else — including Bob — can forge it.
- If the manifest is modified after signing, `H'` will differ from `H_original`
  and verification fails immediately.
- Because only Alice possesses the private key, she cannot later deny having signed
  the manifest. This property is called **non-repudiation**.
- Mallory's attack from Section 1 is now defeated: even if Mallory replaces the
  manifest, she cannot produce a valid signature without Alice's private key.

### TrustVerify Implementation Summary

| Task | Command | Library |
|---|---|---|
| Hash a file (SHA-256) | `trustverify hash <file>` | `hashlib` |
| Generate manifest | `trustverify manifest <dir>` | `hashlib`, `json` |
| Check integrity | `trustverify check <dir>` | `hashlib`, `json` |
| Generate RSA key pair | `trustverify keygen` | `cryptography` |
| Sign manifest | `trustverify sign <manifest> --key <priv>` | `cryptography` (PSS/SHA-256) |
| Verify signature | `trustverify verify <manifest> --sig <sig> --pubkey <pub>` | `cryptography` |

The RSA signature uses **PSS padding with SHA-256**, which is the modern recommended
scheme (stronger than the older PKCS#1 v1.5 padding).

---

