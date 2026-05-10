import logging
import re

import aiosqlite

from .config import settings

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT,
    provider TEXT NOT NULL DEFAULT 'microsoft',
    cache_blob TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    kind TEXT NOT NULL DEFAULT 'audit',     -- 'audit' or 'purge'
    status TEXT NOT NULL,
    cursor_before TEXT,
    error TEXT,
    result_data TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_user ON tasks(user_id);

CREATE TABLE IF NOT EXISTS sender_rules (
    user_id TEXT NOT NULL REFERENCES users(user_id),
    target TEXT NOT NULL,            -- email address (lowercased) or domain
    target_type TEXT NOT NULL,       -- 'address' or 'domain'
    verdict TEXT NOT NULL,           -- 'allow' or 'deny'
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, target, target_type)
);
CREATE INDEX IF NOT EXISTS idx_sender_rules_user ON sender_rules(user_id);

CREATE TABLE IF NOT EXISTS sender_stats (
    user_id TEXT NOT NULL REFERENCES users(user_id),
    target TEXT NOT NULL,            -- email address (lowercased) or domain
    target_type TEXT NOT NULL,       -- 'address' or 'domain'
    seen INTEGER NOT NULL DEFAULT 0,
    spam INTEGER NOT NULL DEFAULT 0,
    deleted INTEGER NOT NULL DEFAULT 0,
    unsubscribed INTEGER NOT NULL DEFAULT 0,
    auto_deleted INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, target_type, target)
);
CREATE INDEX IF NOT EXISTS idx_sender_stats_user ON sender_stats(user_id);
CREATE INDEX IF NOT EXISTS idx_sender_stats_spam ON sender_stats(user_id, spam DESC, seen DESC);

CREATE TABLE IF NOT EXISTS suggestion_dismissals (
    user_id TEXT NOT NULL,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,         -- 'address' or 'domain'
    suggestion_kind TEXT NOT NULL,     -- 'block' for v1
    dismissed_at TEXT NOT NULL,
    PRIMARY KEY (user_id, target_type, target, suggestion_kind)
);
CREATE INDEX IF NOT EXISTS idx_dismissals_user ON suggestion_dismissals(user_id);
"""

_FORWARD_COMPAT_ALTERS = (
    "ALTER TABLE tasks ADD COLUMN cursor_before TEXT",
    "ALTER TABLE tasks ADD COLUMN kind TEXT NOT NULL DEFAULT 'audit'",
    "ALTER TABLE users ADD COLUMN schedule_interval_hours INTEGER",   # legacy
    "ALTER TABLE users ADD COLUMN schedule_interval_minutes INTEGER",
    "ALTER TABLE users ADD COLUMN provider TEXT NOT NULL DEFAULT 'microsoft'",
)


def _split_statements(script: str) -> list[str]:
    """Split a SQL script into individual statements on `;` boundaries,
    stripping `--` line comments and skipping empty fragments. Naive but
    sufficient for our hand-written schema (no embedded semicolons in strings).
    """
    out: list[str] = []
    for raw in script.split(";"):
        stripped = "\n".join(
            line.split("--", 1)[0] for line in raw.splitlines()
        ).strip()
        if stripped:
            out.append(stripped)
    return out


_TABLE_NAME_RE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(\w+)", re.IGNORECASE
)


async def _table_exists(db: aiosqlite.Connection, name: str) -> bool:
    cur = await db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    )
    row = await cur.fetchone()
    return row is not None


_PRAGMAS = (
    # WAL handles concurrent readers + writer cleanly and is much more
    # resilient than the default rollback journal on filesystems that
    # don't honor fsync precisely (e.g. macOS Docker Desktop bind mounts,
    # which were responsible for "database disk image is malformed" in
    # earlier builds).
    "PRAGMA journal_mode = WAL",
    # NORMAL sync gives us durability across crashes while WAL'd; FULL
    # would be safer but ~3x slower for our write pattern.
    "PRAGMA synchronous = NORMAL",
    # 5s busy timeout so concurrent writers (Worker + Scheduler + UI
    # request handlers) wait politely instead of returning SQLITE_BUSY.
    "PRAGMA busy_timeout = 5000",
    # Enforce REFERENCES clauses we declared on tasks.user_id, etc.
    "PRAGMA foreign_keys = ON",
)


async def init_db() -> None:
    async with aiosqlite.connect(settings.db_path) as db:
        for pragma in _PRAGMAS:
            await db.execute(pragma)
        # Run each schema statement individually instead of executescript so
        # any failure is attributable + we can log new-table creations
        # explicitly. CREATE TABLE/INDEX IF NOT EXISTS is idempotent.
        for stmt in _split_statements(SCHEMA):
            m = _TABLE_NAME_RE.match(stmt)
            existed_before = (
                await _table_exists(db, m.group(1)) if m else None
            )
            await db.execute(stmt)
            if m and not existed_before:
                logger.info("created table %s", m.group(1))

        for stmt in _FORWARD_COMPAT_ALTERS:
            try:
                await db.execute(stmt)
            except aiosqlite.OperationalError:
                pass  # column already exists

        # Migrate any pre-existing hours-based schedules into the minutes column.
        try:
            await db.execute(
                """UPDATE users
                   SET schedule_interval_minutes = schedule_interval_hours * 60
                   WHERE schedule_interval_minutes IS NULL
                     AND schedule_interval_hours IS NOT NULL"""
            )
        except aiosqlite.OperationalError:
            pass
        await db.commit()
