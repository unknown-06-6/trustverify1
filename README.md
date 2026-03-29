# TrustVerify 🔐

A Python CLI tool for file integrity verification and RSA digital signatures.

## Install

```bash
pip install cryptography
```

## Quick Start

```bash
# 1. Hash a single file
python trustverify.py hash myfile.pdf

# 2. Generate a manifest for a directory
python trustverify.py manifest ./myfiles/

# 3. Check integrity (run again after changes to detect tampering)
python trustverify.py check ./myfiles/

# 4. Generate RSA key pair (run once as the "Sender")
python trustverify.py keygen --out ./keys/

# 5. Sign the manifest
python trustverify.py sign ./myfiles/metadata.json --key ./keys/private_key.pem

# 6. Verify (run as the "Receiver" with the Sender's public key)
python trustverify.py verify ./myfiles/metadata.json \
    --sig ./myfiles/manifest.sig \
    --pubkey ./keys/public_key.pem
```

## Demo: Tampering Detection

```bash
# After signing, tamper with a file:
echo "MALICIOUS CONTENT" >> myfiles/hello.txt

# Integrity check catches it:
python trustverify.py check ./myfiles/
# [✗] TAMPERED: hello.txt

# Signature verification also catches manifest changes:
python trustverify.py verify ./myfiles/metadata.json ...
# [✗] Signature INVALID
```

## Project Structure

```
trustverify/
├── trustverify.py    # Main CLI tool (all 6 tasks)
├── requirements.txt  # cryptography library
├── REPORT.md         # 2-page report
└── README.md
```
