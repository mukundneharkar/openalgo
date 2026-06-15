"""
Import a daily Zerodha access token into OpenAlgo's encrypted auth database.

This is for self-hosted OpenAlgo deployments where another trusted local
process creates the daily Zerodha/Kite access token before market open.
The token is never printed. OpenAlgo stores Zerodha auth as:

    api_key:access_token

Usage:
    cd /path/to/openalgo
    python scripts/import_zerodha_token.py \
      --token-file ~/.zerodha_token.json \
      --account Mukund \
      --openalgo-user Mukund
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse
from zoneinfo import ZoneInfo


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
IST = ZoneInfo("Asia/Kolkata")


@dataclass(frozen=True)
class TokenRecord:
    account_key: str
    account_name: str
    api_key: str
    access_token: str
    request_token: str | None
    timestamp: str | None

    @property
    def kite_auth(self) -> str:
        return f"{self.api_key}:{self.access_token}"


def mask(value: str | None) -> str:
    if not value:
        return "<empty>"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def load_env() -> None:
    """Load OpenAlgo .env and make relative sqlite paths resolve from repo root."""
    os.chdir(REPO_ROOT)
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    env_file = REPO_ROOT / ".env"
    if not env_file.exists():
        raise RuntimeError(f"OpenAlgo .env not found at {env_file}")

    try:
        from dotenv import load_dotenv

        load_dotenv(env_file, override=True)
    except ImportError:
        load_env_file_without_dotenv(env_file)

    if not os.getenv("API_KEY_PEPPER"):
        load_env_file_without_dotenv(env_file)

    if (os.getenv("LOG_FORMAT") or "").strip().lower() == "json":
        os.environ["LOG_FORMAT"] = "[%(asctime)s] %(levelname)s in %(module)s: %(message)s"


def load_env_file_without_dotenv(env_file: Path) -> None:
    """Minimal .env reader for OpenAlgo's simple KEY='value' format."""
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, raw_value = line.split("=", 1)
        key = key.strip()
        value = raw_value.strip()

        if not key:
            continue

        if value.startswith("'"):
            end = value.find("'", 1)
            value = value[1:end] if end != -1 else value[1:]
        elif value.startswith('"'):
            end = value.find('"', 1)
            value = value[1:end] if end != -1 else value[1:]
        else:
            value = value.split(" #", 1)[0].strip()

        os.environ[key] = value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import a daily Zerodha access token into OpenAlgo."
    )
    parser.add_argument(
        "--token-file",
        "--token-json",
        dest="token_file",
        default="~/.zerodha_token.json",
        help="Path to the JSON file containing account token records, or '-' for stdin.",
    )
    parser.add_argument(
        "--account",
        default="Mukund",
        help="Account key inside the token JSON. Default: Mukund.",
    )
    parser.add_argument(
        "--openalgo-user",
        help="OpenAlgo username/auth row to update. Defaults to account_name, then --account.",
    )
    parser.add_argument(
        "--allow-stale",
        action="store_true",
        help="Allow importing a token whose timestamp is not today's IST date.",
    )
    parser.add_argument(
        "--strict-env-api-key",
        action="store_true",
        help="Fail if token JSON api_key differs from BROKER_API_KEY in OpenAlgo .env.",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip the live Zerodha profile validation call before storing.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and show what would be updated without writing to the DB.",
    )
    return parser.parse_args()


def read_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        return json.load(handle)


def select_token_record(payload: Any, account: str) -> TokenRecord:
    if not isinstance(payload, dict):
        raise ValueError("Token JSON must be an object.")

    if account in payload and isinstance(payload[account], dict):
        raw = payload[account]
        account_key = account
    elif {"api_key", "access_token"}.issubset(payload.keys()):
        raw = payload
        account_key = account
    else:
        available = ", ".join(sorted(str(key) for key in payload.keys()))
        raise ValueError(f"Account {account!r} not found. Available accounts: {available}")

    status = str(raw.get("status", "")).lower()
    if status and status != "success":
        raise ValueError(f"Account {account_key!r} status is {status!r}, not 'success'.")

    api_key = str(raw.get("api_key") or "").strip()
    access_token = str(raw.get("access_token") or "").strip()
    if not api_key:
        raise ValueError(f"Account {account_key!r} is missing api_key.")
    if not access_token:
        raise ValueError(f"Account {account_key!r} is missing access_token.")

    account_name = str(raw.get("account_name") or account_key).strip()
    request_token = raw.get("request_token")
    timestamp = raw.get("timestamp")

    return TokenRecord(
        account_key=account_key,
        account_name=account_name,
        api_key=api_key,
        access_token=access_token,
        request_token=str(request_token).strip() if request_token else None,
        timestamp=str(timestamp).strip() if timestamp else None,
    )


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    formats = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")
    for fmt in formats:
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.replace(tzinfo=IST)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=IST)
    except ValueError:
        return None


def validate_timestamp(record: TokenRecord, allow_stale: bool) -> None:
    parsed = parse_timestamp(record.timestamp)
    if not parsed:
        if allow_stale:
            return
        raise ValueError(
            "Token timestamp is missing or unparseable. Use --allow-stale to import anyway."
        )

    token_date = parsed.astimezone(IST).date()
    today = datetime.now(IST).date()
    if token_date != today and not allow_stale:
        raise ValueError(
            f"Token timestamp date is {token_date}, but today's IST date is {today}. "
            "Use --allow-stale only if you are deliberately testing."
        )


def validate_with_zerodha(record: TokenRecord) -> dict[str, Any] | None:
    import requests

    response = requests.get(
        "https://api.kite.trade/user/profile",
        headers={
            "X-Kite-Version": "3",
            "Authorization": f"token {record.kite_auth}",
        },
        timeout=15,
    )
    response.raise_for_status()
    data = response.json()
    if data.get("status") != "success":
        raise RuntimeError("Zerodha profile validation did not return success.")
    return data.get("data") or {}


def update_openalgo_auth(
    openalgo_user: str,
    record: TokenRecord,
    profile: dict[str, Any] | None,
    dry_run: bool,
) -> int | None:
    if dry_run:
        return None

    if not os.getenv("API_KEY_PEPPER"):
        raise RuntimeError("API_KEY_PEPPER is not set. Check OpenAlgo .env loading.")

    try:
        from database.auth_db import init_db, upsert_auth
    except ImportError as exc:
        print(
            "WARNING: OpenAlgo auth_db dependencies are not fully installed "
            f"({exc}). Using direct SQLite auth update fallback. If OpenAlgo "
            "is already running, restart it after this import so in-process "
            "auth caches are refreshed.",
            file=sys.stderr,
        )
        return update_openalgo_auth_direct_sqlite(openalgo_user, record, profile)

    init_db()
    user_id = None
    if profile:
        user_id = profile.get("user_id") or profile.get("user_shortname")

    return upsert_auth(
        name=openalgo_user,
        auth_token=record.kite_auth,
        broker="zerodha",
        feed_token=None,
        user_id=user_id,
        revoke=False,
    )


def update_openalgo_auth_direct_sqlite(
    openalgo_user: str,
    record: TokenRecord,
    profile: dict[str, Any] | None,
) -> int:
    """Update auth table without importing OpenAlgo auth_db.

    This keeps the EC2 utility usable when system Python does not have all
    OpenAlgo dependencies installed. It intentionally supports only the
    default SQLite deployment.
    """
    db_path = resolve_sqlite_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    encrypted_auth = encrypt_token_like_openalgo(record.kite_auth)
    user_id = None
    if profile:
        user_id = profile.get("user_id") or profile.get("user_shortname")

    with sqlite3.connect(db_path) as conn:
        ensure_auth_table(conn)
        existing = conn.execute("SELECT id FROM auth WHERE name = ?", (openalgo_user,)).fetchone()
        if existing:
            row_id = int(existing[0])
            conn.execute(
                """
                UPDATE auth
                   SET auth = ?,
                       feed_token = NULL,
                       broker = 'zerodha',
                       user_id = ?,
                       is_revoked = 0
                 WHERE id = ?
                """,
                (encrypted_auth, user_id, row_id),
            )
        else:
            cur = conn.execute(
                """
                INSERT INTO auth (name, auth, feed_token, broker, user_id, is_revoked)
                VALUES (?, ?, NULL, 'zerodha', ?, 0)
                """,
                (openalgo_user, encrypted_auth, user_id),
            )
            row_id = int(cur.lastrowid)
        conn.commit()

    return row_id


def resolve_sqlite_db_path() -> Path:
    database_url = (os.getenv("DATABASE_URL") or "sqlite:///db/openalgo.db").strip()
    parsed = urlparse(database_url)
    if parsed.scheme != "sqlite":
        raise RuntimeError(
            "Direct fallback only supports SQLite DATABASE_URL. Install OpenAlgo "
            "dependencies and run via the project venv for non-SQLite deployments."
        )

    if database_url.startswith("sqlite:////"):
        path = Path(unquote(parsed.path))
    elif database_url.startswith("sqlite:///"):
        path = REPO_ROOT / unquote(database_url.removeprefix("sqlite:///"))
    else:
        raise RuntimeError(f"Unsupported SQLite DATABASE_URL format: {database_url!r}")

    return path.resolve()


def encrypt_token_like_openalgo(token: str) -> str:
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError as exc:
        raise RuntimeError(
            "Missing cryptography package. Run this script with OpenAlgo's venv "
            "or install dependencies: pip install cryptography"
        ) from exc

    pepper = os.getenv("API_KEY_PEPPER")
    if not pepper:
        raise RuntimeError("API_KEY_PEPPER is not set. Check OpenAlgo .env loading.")

    raw_salt = (os.getenv("FERNET_SALT") or "").strip()
    salt = b"openalgo_static_salt"
    if raw_salt and len(raw_salt) >= 32:
        try:
            salt = bytes.fromhex(raw_salt)
        except ValueError:
            pass

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(pepper.encode()))
    return Fernet(key).encrypt(token.encode()).decode()


def ensure_auth_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS auth (
            id INTEGER NOT NULL,
            name VARCHAR(255) NOT NULL,
            auth TEXT NOT NULL,
            feed_token TEXT,
            broker VARCHAR(20) NOT NULL,
            user_id VARCHAR(255),
            is_revoked BOOLEAN,
            secret_api_key TEXT,
            primary_ip VARCHAR(45),
            secondary_ip VARCHAR(45),
            ip_updated_at DATETIME,
            aux_param1 TEXT,
            aux_param2 TEXT,
            aux_param3 TEXT,
            aux_param4 TEXT,
            PRIMARY KEY (id),
            UNIQUE (name)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_broker ON auth (broker)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_user_id ON auth (user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_is_revoked ON auth (is_revoked)")


def main() -> int:
    args = parse_args()
    load_env()

    payload = read_json(args.token_file)
    record = select_token_record(payload, args.account)
    openalgo_user = args.openalgo_user or record.account_name or record.account_key

    validate_timestamp(record, allow_stale=args.allow_stale)

    env_api_key = (os.getenv("BROKER_API_KEY") or "").strip()
    if env_api_key and env_api_key != record.api_key:
        message = (
            "WARNING: token JSON api_key does not match OpenAlgo BROKER_API_KEY. "
            "REST calls can still work because the stored auth includes the JSON api_key, "
            "but Zerodha WebSocket uses BROKER_API_KEY from .env and may fail until .env "
            "is aligned with this Kite app."
        )
        if args.strict_env_api_key:
            raise ValueError(message)
        print(message, file=sys.stderr)

    profile = None
    if not args.no_validate:
        profile = validate_with_zerodha(record)

    row_id = update_openalgo_auth(
        openalgo_user=openalgo_user,
        record=record,
        profile=profile,
        dry_run=args.dry_run,
    )

    print("Zerodha token import complete." if not args.dry_run else "Dry run complete.")
    print(f"  account        : {record.account_key}")
    print(f"  openalgo_user  : {openalgo_user}")
    print("  broker         : zerodha")
    print(f"  api_key        : {mask(record.api_key)}")
    print(f"  env key match  : {'yes' if env_api_key == record.api_key else 'no'}")
    print(f"  validated      : {'no' if args.no_validate else 'yes'}")
    if profile:
        print(f"  zerodha_user   : {profile.get('user_id') or '<unknown>'}")
    if row_id is not None:
        print(f"  auth_row_id    : {row_id}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
