#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pyotp",
#     "cryptography",
#     "rich",
# ]
#
# ///
"""TOTP CLI main entry point.

Usage:
  totty add <file|->
  totty get [search]

The *add* subcommand reads lines containing *otpauth://* URIs from a file (or
stdin with "-") and inserts them into a local SQLite database. The *get*
subcommand queries the database and prints currently valid TOTP codes.
"""

import argparse
import base64
import getpass
import hashlib
import os
import sqlite3
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

import pyotp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich import print as rich_print


def _default_db_path() -> str:
    """Return a platform-appropriate default database path following XDG spec."""
    cfg_home = os.environ.get("XDG_CONFIG_HOME", os.path.join(Path.home(), ".config"))
    dir_path = Path(cfg_home) / "totty"
    dir_path.mkdir(parents=True, exist_ok=True)
    return str(dir_path / "totp.db")


DB_PATH = _default_db_path()
ENC_PREFIX = "ENC::"
_password_cache: str | None = None


def _get_password(prompt: str = "Master password: ") -> str:
    """Cache and return the master password from the user or environment variable."""
    global _password_cache
    if _password_cache is None:
        env_password = os.environ.get("TOTP_PASSWORD")
        if env_password:
            _password_cache = env_password
        else:
            _password_cache = getpass.getpass(prompt)
    return _password_cache


# ==== Encryption helpers ====================================================


def _encrypt_secret(secret: str, password: str) -> str:
    """Encrypt *secret* with AES-CFB, return ENC::<salt_b64>::<cipher_b64>."""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(secret.encode()) + encryptor.finalize()
    payload = base64.b64encode(iv + ct).decode()
    return f"{ENC_PREFIX}{base64.b64encode(salt).decode()}::{payload}"


def _decrypt_secret(enc_value: str, password: str) -> str:
    """Decrypt a value previously returned by :func:`_encrypt_secret`."""
    try:
        _, salt_b64, cipher_b64 = enc_value.split("::", 2)
    except ValueError as err:
        raise ValueError("Invalid encrypted value format") from err

    salt = base64.b64decode(salt_b64)
    cipher_text = base64.b64decode(cipher_b64)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode())

    iv, ct = cipher_text[:16], cipher_text[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plain = decryptor.update(ct) + decryptor.finalize()
    try:
        return plain.decode()
    except UnicodeDecodeError as err:
        # Likely an incorrect password or corrupted data
        raise ValueError("Incorrect master password or corrupted data") from err


# ==== Database helpers ======================================================


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS totp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            account_name TEXT,
            issuer TEXT,
            secret TEXT,
            algorithm TEXT,
            digits INTEGER,
            period INTEGER,
            counter INTEGER
        )
        """
    )
    conn.commit()


# ==== otpauth parser ========================================================


def parse_otpauth_uri(uri: str) -> dict[str, Any]:
    """Return components parsed from an *otpauth://* URI."""
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "otpauth":
        raise ValueError("Invalid URI scheme: expected 'otpauth'")

    otp_type = parsed.netloc.lower()
    label = urllib.parse.unquote(parsed.path[1:])
    if ":" in label:
        issuer_from_label, account_name = [p.strip() for p in label.split(":", 1)]
    else:
        issuer_from_label, account_name = None, label.strip()

    qs = urllib.parse.parse_qs(parsed.query)
    if "secret" not in qs:
        raise ValueError("Missing required parameter: secret")

    secret = qs["secret"][0]
    issuer = qs.get("issuer", [issuer_from_label])[0]
    algorithm = qs.get("algorithm", ["SHA1"])[0].upper()
    digits = int(qs.get("digits", [6])[0])
    period = int(qs.get("period", [30])[0])
    counter = qs.get("counter", [None])[0]
    if counter is not None:
        counter = int(counter)

    return {
        "type": otp_type,
        "account_name": account_name,
        "issuer": issuer,
        "secret": secret,
        "algorithm": algorithm,
        "digits": digits,
        "period": period,
        "counter": counter,
    }


# ==== CRUD operations =======================================================


def insert_into_db(data: dict[str, Any], db_path: str = DB_PATH) -> None:
    secret_val = data["secret"].strip()
    if not secret_val.startswith(ENC_PREFIX):
        secret_val = _encrypt_secret(secret_val, _get_password())
        data = {**data, "secret": secret_val}

    with _connect(db_path) as conn:
        _ensure_schema(conn)
        conn.execute(
            """
            INSERT INTO totp_codes (type, account_name, issuer, secret, algorithm, digits, period, counter)
            VALUES (:type, :account_name, :issuer, :secret, :algorithm, :digits, :period, :counter)
            """,
            data,
        )
        conn.commit()


def fetch_totp_records(search: str | None = None, db_path: str = DB_PATH):
    with _connect(db_path) as conn:
        if search:
            like = f"%{search.lower()}%"
            cur = conn.execute(
                """
                SELECT * FROM totp_codes
                WHERE LOWER(issuer) LIKE ? OR LOWER(account_name) LIKE ?
                ORDER BY issuer, account_name
                """,
                (like, like),
            )
        else:
            cur = conn.execute("SELECT * FROM totp_codes ORDER BY issuer, account_name")
        return cur.fetchall()


# ==== Display helper ========================================================


def format_output(row: sqlite3.Row, password: str) -> str:
    secret_raw = row["secret"].strip()
    if secret_raw.startswith(ENC_PREFIX):
        secret = _decrypt_secret(secret_raw, password)
    else:
        secret = secret_raw.replace(" ", "").upper()

    algo_map = {
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
    }
    digest_fn = algo_map.get(row["algorithm"].upper(), hashlib.sha1)

    totp = pyotp.TOTP(
        secret, digits=row["digits"], interval=row["period"], digest=digest_fn
    )
    code = totp.now()
    seconds_remaining = int(totp.interval - (time.time() % totp.interval))
    header = f"{row['issuer'] or ''} {row['account_name'] or ''}".strip()
    if seconds_remaining > 15:
        color = "green"
    elif seconds_remaining > 8:
        color = "yellow"
    else:
        color = "red"
    return f"{header}: [{color}]{code}[/{color}] (expires in [{color}]{seconds_remaining}s)[/{color}]"


# ==== CLI ===================================================================


def _cmd_add(args: argparse.Namespace) -> None:
    source = args.file
    if source == "-":
        lines = sys.stdin.readlines()
    else:
        with open(source, "r", encoding="utf-8") as fh:
            lines = fh.readlines()

    inserted = 0
    for raw in lines:
        line = raw.strip()
        if not line or not line.lower().startswith("otpauth://"):
            continue
        try:
            data = parse_otpauth_uri(line)
            insert_into_db(data, db_path=args.db)
            inserted += 1
        except Exception as exc:
            print(f"Skipping invalid line: {line}\n  Reason: {exc}", file=sys.stderr)

    print(f"Inserted {inserted} record{'s' if inserted != 1 else ''} into {args.db}.")


def _cmd_get(args: argparse.Namespace) -> None:
    password = _get_password()
    # Early validation of the master password if any encrypted records exist
    # This provides a clearer error message instead of failing later during decryption.
    preview_rows = fetch_totp_records(args.search, db_path=args.db)
    for _r in preview_rows:
        if _r["secret"].strip().startswith(ENC_PREFIX):
            try:
                _decrypt_secret(_r["secret"].strip(), password)
            except ValueError:
                print(
                    "Invalid master password – unable to decrypt stored secrets.",
                    file=sys.stderr,
                )
                sys.exit(1)
            break
    # Use previously fetched rows for further processing
    rows = preview_rows
    if not rows:
        print("No matching TOTP entries found.")
        sys.exit(1)

    if args.search is None:
        # Only list stored entries (issuer/account) without revealing codes
        for r in rows:
            header = f"{r['issuer'] or ''} {r['account_name'] or ''}".strip()
            print(header)
    else:
        for row in rows:
            try:
                rich_print(format_output(row, password))
            except ValueError as err:
                print(
                    f"{row['issuer']} {row['account_name']}: <decryption failed> ({err})",
                    file=sys.stderr,
                )


def main(argv: list[str] | None = None) -> None:  # noqa: D401 – simple CLI
    parser = argparse.ArgumentParser(
        prog="totty", description="Manage and query TOTP secrets."
    )
    parser.add_argument(
        "--db", default=DB_PATH, help="Path to SQLite database (default: %(default)s)"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="Import otpauth URIs from a file or stdin (-)")
    p_add.add_argument("file", help="Path to text file or '-' for stdin")
    p_add.set_defaults(func=_cmd_add)

    p_get = sub.add_parser("get", help="Display TOTP codes matching a search string.")
    p_get.add_argument("search", nargs="?", help="Issuer or account substring to match")
    p_get.set_defaults(func=_cmd_get)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
