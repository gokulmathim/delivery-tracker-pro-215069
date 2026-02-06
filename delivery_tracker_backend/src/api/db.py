import os
import re
from pathlib import Path
from typing import AsyncGenerator, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine


def _parse_psql_command_to_dsn(psql_command_line: str) -> str:
    """
    Convert a db_connection.txt line that looks like:
        'psql postgresql://user:pass@host:port/db'
    into:
        'postgresql://user:pass@host:port/db'
    """
    line = psql_command_line.strip()
    if not line:
        raise ValueError("db_connection.txt is empty")

    # Common case: "psql <dsn>"
    if line.startswith("psql "):
        line = line[len("psql ") :].strip()

    # If they included flags, try to find the DSN token
    # (keeps this resilient to future changes).
    match = re.search(r"(postgresql://\S+)", line)
    if match:
        return match.group(1)

    if line.startswith("postgres://") or line.startswith("postgresql://"):
        return line

    raise ValueError(f"Could not parse PostgreSQL DSN from db_connection.txt line: {psql_command_line!r}")


def _sync_to_async_sqlalchemy_url(sync_dsn: str) -> str:
    """
    SQLAlchemy async engine for Postgres expects:
      postgresql+asyncpg://...
    """
    if sync_dsn.startswith("postgresql+asyncpg://"):
        return sync_dsn
    if sync_dsn.startswith("postgresql://"):
        return "postgresql+asyncpg://" + sync_dsn[len("postgresql://") :]
    if sync_dsn.startswith("postgres://"):
        # normalize deprecated prefix
        return "postgresql+asyncpg://" + sync_dsn[len("postgres://") :]
    raise ValueError(f"Unsupported DSN scheme: {sync_dsn}")


# Resolved at import time to keep config simple and centralized.
_DB_DSN_SYNC: Optional[str] = None
_ENGINE: Optional[AsyncEngine] = None
_SESSIONMAKER: Optional[async_sessionmaker[AsyncSession]] = None


# PUBLIC_INTERFACE
def get_db_dsn_sync() -> str:
    """Return the synchronous PostgreSQL DSN (postgresql://...) parsed from db_connection.txt."""
    global _DB_DSN_SYNC
    if _DB_DSN_SYNC is not None:
        return _DB_DSN_SYNC

    # Backend workspace: delivery-tracker-pro-215069/delivery_tracker_backend
    # DB workspace:      delivery-tracker-pro-215070/delivery_tracker_database
    backend_dir = Path(__file__).resolve().parents[3]  # .../delivery_tracker_backend
    db_connection_path = backend_dir.parents[1] / "delivery-tracker-pro-215070" / "delivery_tracker_database" / "db_connection.txt"

    # Allow override for unusual deployments (still defaults to db_connection.txt).
    override_path = os.getenv("DB_CONNECTION_TXT_PATH")
    if override_path:
        db_connection_path = Path(override_path)

    if not db_connection_path.exists():
        raise FileNotFoundError(
            f"Expected db_connection.txt at {db_connection_path}. "
            "If running in a different layout, set DB_CONNECTION_TXT_PATH env var."
        )

    raw = db_connection_path.read_text(encoding="utf-8")
    _DB_DSN_SYNC = _parse_psql_command_to_dsn(raw.splitlines()[0])
    return _DB_DSN_SYNC


# PUBLIC_INTERFACE
def get_engine() -> AsyncEngine:
    """Return a singleton SQLAlchemy AsyncEngine."""
    global _ENGINE
    if _ENGINE is None:
        async_url = _sync_to_async_sqlalchemy_url(get_db_dsn_sync())
        _ENGINE = create_async_engine(async_url, pool_pre_ping=True)

        # Assign sessionmaker via module global without declaring it global here to satisfy flake8 F824
        # (the name is assigned by attribute lookup in this scope).
        globals()["_SESSIONMAKER"] = async_sessionmaker(_ENGINE, expire_on_commit=False)
    return _ENGINE


# PUBLIC_INTERFACE
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an AsyncSession with proper cleanup."""
    if _SESSIONMAKER is None:
        get_engine()
    assert _SESSIONMAKER is not None
    async with _SESSIONMAKER() as session:
        yield session


def _split_sql_statements(sql_text: str) -> list[str]:
    """
    Naive-but-practical SQL splitter that respects:
      - single quotes
      - dollar-quoted blocks ($$ ... $$ or $tag$ ... $tag$)
      - line comments (-- ...)
      - block comments (/* ... */)

    It is sufficient for the provided schema_and_seed.sql (contains DO $$ blocks).
    """
    statements: list[str] = []
    buf: list[str] = []

    i = 0
    n = len(sql_text)

    in_single_quote = False
    in_line_comment = False
    in_block_comment = False
    dollar_tag: Optional[str] = None

    while i < n:
        ch = sql_text[i]
        nxt = sql_text[i + 1] if i + 1 < n else ""

        # Handle line comments
        if not in_single_quote and dollar_tag is None and not in_block_comment:
            if not in_line_comment and ch == "-" and nxt == "-":
                in_line_comment = True
                buf.append(ch)
                i += 1
                buf.append(nxt)
                i += 1
                continue
        if in_line_comment:
            buf.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        # Handle block comments
        if not in_single_quote and dollar_tag is None and not in_line_comment:
            if not in_block_comment and ch == "/" and nxt == "*":
                in_block_comment = True
                buf.append(ch)
                i += 1
                buf.append(nxt)
                i += 1
                continue
        if in_block_comment:
            buf.append(ch)
            if ch == "*" and nxt == "/":
                i += 1
                buf.append(nxt)
                i += 1
                in_block_comment = False
                continue
            i += 1
            continue

        # Handle dollar-quoted blocks start/end
        if not in_single_quote and not in_line_comment and not in_block_comment:
            if dollar_tag is None and ch == "$":
                # Try to parse $tag$ pattern
                j = i + 1
                while j < n and (sql_text[j].isalnum() or sql_text[j] == "_"):
                    j += 1
                if j < n and sql_text[j] == "$":
                    tag = sql_text[i : j + 1]  # includes both dollars
                    dollar_tag = tag
                    buf.append(tag)
                    i = j + 1
                    continue
            elif dollar_tag is not None and ch == "$":
                # check if we are closing with same tag
                if sql_text.startswith(dollar_tag, i):
                    buf.append(dollar_tag)
                    i += len(dollar_tag)
                    dollar_tag = None
                    continue

        # Handle single quotes
        if dollar_tag is None and not in_line_comment and not in_block_comment:
            if ch == "'":
                if in_single_quote:
                    # handle escaped single quote ''
                    if nxt == "'":
                        buf.append(ch)
                        buf.append(nxt)
                        i += 2
                        continue
                    in_single_quote = False
                else:
                    in_single_quote = True

        # Statement terminator
        if ch == ";" and not in_single_quote and dollar_tag is None and not in_line_comment and not in_block_comment:
            current = "".join(buf).strip()
            if current:
                statements.append(current)
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)

    # Remove pure comments/empty
    cleaned: list[str] = []
    for st in statements:
        if st.strip():
            cleaned.append(st.strip())
    return cleaned


# PUBLIC_INTERFACE
async def apply_schema_if_needed() -> None:
    """
    Apply schema_and_seed.sql on startup if the schema is not present.

    Heuristic: if 'users' table exists, assume schema already exists.
    """
    engine = get_engine()

    backend_dir = Path(__file__).resolve().parents[3]  # .../delivery_tracker_backend
    schema_path = backend_dir.parents[1] / "delivery-tracker-pro-215070" / "delivery_tracker_database" / "schema_and_seed.sql"

    override_path = os.getenv("SCHEMA_SQL_PATH")
    if override_path:
        schema_path = Path(override_path)

    if not schema_path.exists():
        # If schema file isn't available, don't crash the app; health/version should still respond.
        return

    async with engine.begin() as conn:
        exists = await conn.execute(
            text(
                """
                SELECT EXISTS (
                  SELECT 1
                  FROM information_schema.tables
                  WHERE table_schema = 'public' AND table_name = 'users'
                ) AS users_exists
                """
            )
        )
        users_exists = bool(exists.scalar_one())
        if users_exists:
            return

        sql_text = schema_path.read_text(encoding="utf-8")
        statements = _split_sql_statements(sql_text)

        # Execute each statement individually to keep failures pinpointed.
        for stmt in statements:
            await conn.execute(text(stmt))
