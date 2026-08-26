#!/usr/bin/env python3
"""Generate a tenant entry for AEGIS_TENANTS.

Usage:
  python scripts/gen_tenant.py --id acme --scopes chat+rag
  python scripts/gen_tenant.py --id acme --scopes chat+rag --key my-secret-key
If --key not given, a random sk-... is generated.
"""
import argparse
import hashlib
import secrets

parser = argparse.ArgumentParser()
parser.add_argument("--id", default="demo")
parser.add_argument("--scopes", default="chat+rag", help="scopes joined by +")
parser.add_argument("--key", default="")
args = parser.parse_args()

key = args.key or f"sk-{secrets.token_hex(16)}"
key_hash = hashlib.sha256(key.encode()).hexdigest()
entry = f"{args.id}:{key_hash}:{args.scopes}"
print(f"API key (store securely, shown once): {key}")
print(f"AEGIS_TENANTS entry: {entry}")
print(f"Header: Authorization: Bearer {key}")
