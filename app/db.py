import aiosqlite

from .config import settings

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
"""

_FORWARD_COMPAT_ALTERS = (
    "ALTER TABLE tasks ADD COLUMN cursor_before TEXT",
    "ALTER TABLE users ADD COLUMN schedule_interval_hours INTEGER",   # legacy
    "ALTER TABLE users ADD COLUMN schedule_interval_minutes INTEGER",
    "ALTER TABLE users ADD COLUMN provider TEXT NOT NULL DEFAULT 'microsoft'",
)


async def init_db() -> None:
    async with aiosqlite.connect(settings.db_path) as db:
        await db.executescript(SCHEMA)
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
