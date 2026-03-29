#!/usr/bin/env python3
"""
TrustVerify - A CLI Tool for File Integrity and Digital Signatures
Implements SHA-256 hashing + RSA digital signatures for file verification.
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from datetime import datetime

# RSA / cryptography imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64


# ──────────────────────────────────────────────
# PART 1 – Hashing & Local Integrity
# ──────────────────────────────────────────────

def hash_file(filepath: str) -> str:
    """Task 1 – Generate SHA-256 hash of any file (text, PDF, image)."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_manifest(directory: str, output: str = "metadata.json") -> dict:
    """Task 2 – Scan a directory and produce metadata.json with filename → hash mapping."""
    directory = Path(directory).resolve()
    if not directory.is_dir():
        print(f"[ERROR] '{directory}' is not a valid directory.")
        sys.exit(1)

    manifest = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "directory": str(directory),
        "files": {}
    }

    for file in sorted(directory.iterdir()):
        if file.is_file() and file.name != output:
            rel = file.name
            manifest["files"][rel] = hash_file(str(file))
            print(f"  [+] Hashed: {rel}  →  {manifest['files'][rel][:16]}…")

    out_path = directory / output
    with open(out_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n[✓] Manifest written → {out_path}")
    return manifest


def check_integrity(directory: str, manifest_file: str = "metadata.json") -> bool:
    """Task 3 – Compare current file hashes against metadata.json; report tampering."""
    directory = Path(directory).resolve()
    manifest_path = directory / manifest_file

    if not manifest_path.exists():
        print(f"[ERROR] Manifest not found: {manifest_path}")
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    all_ok = True
    recorded = manifest.get("files", {})

    # Check each recorded file
    for filename, expected_hash in recorded.items():
        filepath = directory / filename
        if not filepath.exists():
            print(f"  [✗] MISSING : {filename}")
            all_ok = False
        else:
            actual_hash = hash_file(str(filepath))
            if actual_hash == expected_hash:
                print(f"  [✓] OK      : {filename}")
            else:
                print(f"  [✗] TAMPERED: {filename}")
                print(f"       expected: {expected_hash}")
                print(f"       actual  : {actual_hash}")
                all_ok = False

    # Detect new (unrecorded) files
    for file in sorted(directory.iterdir()):
        if file.is_file() and file.name not in recorded and file.name != manifest_file:
            print(f"  [!] NEW FILE: {file.name}  (not in manifest)")
            all_ok = False

    if all_ok:
        print("\n[✓] Integrity check PASSED – no tampering detected.")
    else:
        print("\n[✗] Integrity check FAILED – tampering or changes detected!")

    return all_ok


# ──────────────────────────────────────────────
# PART 2 – Digital Signatures (RSA)
# ──────────────────────────────────────────────

def generate_keypair(output_dir: str = ".") -> None:
    """Task 4 – Generate RSA-2048 public/private key pair and save to PEM files."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save private key (no passphrase for demo simplicity)
    priv_path = output_dir / "private_key.pem"
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    pub_path = output_dir / "public_key.pem"
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"[✓] Key pair generated:")
    print(f"    Private key → {priv_path}")
    print(f"    Public key  → {pub_path}")
    print("[!] Keep your private key secret!")


def sign_manifest(manifest_path: str, private_key_path: str, sig_output: str = "manifest.sig") -> None:
    """Task 5 – Hash the manifest and sign it with the sender's private key."""
    manifest_path = Path(manifest_path)
    if not manifest_path.exists():
        print(f"[ERROR] Manifest not found: {manifest_path}")
        sys.exit(1)

    # Compute SHA-256 of the manifest file itself
    manifest_hash = hash_file(str(manifest_path))
    print(f"[i] Manifest SHA-256: {manifest_hash}")

    # Load private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    # Sign the hash (as bytes)
    signature = private_key.sign(
        manifest_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Save signature (base64-encoded for portability)
    sig_path = manifest_path.parent / sig_output
    with open(sig_path, "wb") as f:
        f.write(base64.b64encode(signature))

    print(f"[✓] Manifest signed → {sig_path}")


def verify_manifest(manifest_path: str, sig_path: str, public_key_path: str) -> bool:
    """Task 6 – Verify the manifest's signature using the sender's public key."""
    manifest_path = Path(manifest_path)
    sig_path = Path(sig_path)

    # Re-compute current hash of manifest
    manifest_hash = hash_file(str(manifest_path))
    print(f"[i] Current manifest SHA-256: {manifest_hash}")

    # Load signature
    with open(sig_path, "rb") as f:
        signature = base64.b64decode(f.read())

    # Load public key
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    # Verify
    try:
        public_key.verify(
            signature,
            manifest_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[✓] Signature VALID – manifest is authentic and untampered.")
        return True
    except InvalidSignature:
        print("[✗] Signature INVALID – manifest may have been altered or key mismatch!")
        return False


# ──────────────────────────────────────────────
# CLI Entry Point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="trustverify",
        description="TrustVerify – File Integrity & Digital Signature CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python trustverify.py hash myfile.pdf
  python trustverify.py manifest ./myfiles/
  python trustverify.py check ./myfiles/
  python trustverify.py keygen --out ./keys/
  python trustverify.py sign ./myfiles/metadata.json --key ./keys/private_key.pem
  python trustverify.py verify ./myfiles/metadata.json --sig ./myfiles/manifest.sig --pubkey ./keys/public_key.pem
        """
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # hash
    p_hash = sub.add_parser("hash", help="Hash a single file with SHA-256")
    p_hash.add_argument("file", help="Path to the file")

    # manifest
    p_manifest = sub.add_parser("manifest", help="Generate metadata.json for a directory")
    p_manifest.add_argument("directory", help="Directory to scan")
    p_manifest.add_argument("--out", default="metadata.json", help="Output manifest filename")

    # check
    p_check = sub.add_parser("check", help="Verify file integrity against metadata.json")
    p_check.add_argument("directory", help="Directory to check")
    p_check.add_argument("--manifest", default="metadata.json", help="Manifest filename")

    # keygen
    p_keygen = sub.add_parser("keygen", help="Generate RSA key pair")
    p_keygen.add_argument("--out", default=".", help="Output directory for keys")

    # sign
    p_sign = sub.add_parser("sign", help="Sign metadata.json with private key")
    p_sign.add_argument("manifest", help="Path to metadata.json")
    p_sign.add_argument("--key", required=True, help="Path to private key PEM")
    p_sign.add_argument("--sig", default="manifest.sig", help="Output signature filename")

    # verify
    p_verify = sub.add_parser("verify", help="Verify manifest signature with public key")
    p_verify.add_argument("manifest", help="Path to metadata.json")
    p_verify.add_argument("--sig", required=True, help="Path to signature file")
    p_verify.add_argument("--pubkey", required=True, help="Path to sender's public key PEM")

    args = parser.parse_args()

    print()
    if args.command == "hash":
        h = hash_file(args.file)
        print(f"SHA-256({args.file})\n  = {h}")

    elif args.command == "manifest":
        generate_manifest(args.directory, args.out)

    elif args.command == "check":
        ok = check_integrity(args.directory, args.manifest)
        sys.exit(0 if ok else 1)

    elif args.command == "keygen":
        generate_keypair(args.out)

    elif args.command == "sign":
        sign_manifest(args.manifest, args.key, args.sig)

    elif args.command == "verify":
        ok = verify_manifest(args.manifest, args.sig, args.pubkey)
        sys.exit(0 if ok else 1)

    print()


if __name__ == "__main__":
    main()
