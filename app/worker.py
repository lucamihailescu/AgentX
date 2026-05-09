import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

import aiosqlite

from .auth import TokenAcquisitionError, acquire_access_token
from .config import settings
from .graph_client import GraphClient, GraphError
from .rules import load_rule_index
from .tasks import auto_delete_blocked, classify_messages, fetch_messages, generate_report

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Worker:
    def __init__(self) -> None:
        self._stop = asyncio.Event()

    async def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        while not self._stop.is_set():
            try:
                claimed = await self._claim_next()
                if claimed is None:
                    await asyncio.sleep(settings.worker_poll_interval_seconds)
                    continue
                await self._process(claimed)
            except Exception:
                logger.exception("Worker loop error")
                await asyncio.sleep(settings.worker_poll_interval_seconds)

    async def _claim_next(self) -> dict | None:
        async with aiosqlite.connect(settings.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT task_id, user_id, cursor_before FROM tasks "
                "WHERE status = 'queued' ORDER BY created_at LIMIT 1"
            )
            row = await cur.fetchone()
            if row is None:
                return None
            await db.execute(
                "UPDATE tasks SET status='processing', updated_at=? WHERE task_id=?",
                (_now(), row["task_id"]),
            )
            await db.commit()
            return dict(row)

    async def _process(self, task: dict) -> None:
        task_id = task["task_id"]
        user_id = task["user_id"]

        async def token_provider() -> str:
            return await acquire_access_token(user_id)

        cursor_before = task.get("cursor_before")
        try:
            async with GraphClient(token_provider) as graph:
                messages = await fetch_messages(graph, cursor_before=cursor_before)
                messages = await auto_delete_blocked(graph, messages)
            rules = await load_rule_index(user_id)
            classified = await classify_messages(messages, rules)
            report = await generate_report(classified)
            await self._update(
                task_id, status="completed", result_data=json.dumps(report)
            )
        except TokenAcquisitionError as exc:
            await self._update(task_id, status="failed", error=f"Auth: {exc}")
        except GraphError as exc:
            await self._update(task_id, status="failed", error=str(exc))

    @staticmethod
    async def _update(
        task_id: str,
        *,
        status: str,
        error: str | None = None,
        result_data: str | None = None,
    ) -> None:
        async with aiosqlite.connect(settings.db_path) as db:
            await db.execute(
                """UPDATE tasks
                   SET status=?, error=?, result_data=COALESCE(?, result_data), updated_at=?
                   WHERE task_id=?""",
                (status, error[:1000] if error else None, result_data, _now(), task_id),
            )
            await db.commit()


class Scheduler:
    """Inserts queued audit tasks for users on a configurable interval.

    Per-user override (`users.schedule_interval_minutes`) wins; when unset,
    `AGENT_DEFAULT_SCHEDULE_INTERVAL_MINUTES` is used. If neither is set, the
    user is skipped.

    Wakes every `AGENT_SCHEDULER_TICK_SECONDS` (default 60); skips users with
    an audit already queued or processing to avoid pile-up.
    """

    def __init__(self) -> None:
        self._stop = asyncio.Event()

    async def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception:
                logger.exception("Scheduler tick failed")
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=settings.scheduler_tick_seconds
                )
            except asyncio.TimeoutError:
                pass

    async def _tick(self) -> None:
        default_minutes = settings.default_schedule_interval_minutes
        async with aiosqlite.connect(settings.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT u.user_id, u.schedule_interval_minutes,
                          (SELECT MAX(created_at) FROM tasks t
                              WHERE t.user_id = u.user_id) AS last_at,
                          EXISTS(SELECT 1 FROM tasks t2
                                 WHERE t2.user_id = u.user_id
                                   AND t2.status IN ('queued', 'processing')) AS in_flight
                   FROM users u"""
            )
            users = await cur.fetchall()

        now = datetime.now(timezone.utc)
        for u in users:
            user_minutes = u["schedule_interval_minutes"]
            interval_minutes = user_minutes if user_minutes else default_minutes
            if not interval_minutes or interval_minutes <= 0:
                continue
            if u["in_flight"]:
                continue
            interval = timedelta(minutes=interval_minutes)
            if u["last_at"]:
                last = datetime.fromisoformat(u["last_at"].replace("Z", "+00:00"))
                if now - last < interval:
                    continue
            await self._insert_task(u["user_id"])
            logger.info(
                "scheduler queued audit for %s (interval=%smin, source=%s)",
                u["user_id"],
                interval_minutes,
                "user" if user_minutes else "default",
            )

    @staticmethod
    async def _insert_task(user_id: str) -> None:
        task_id = str(uuid.uuid4())
        now = _now()
        async with aiosqlite.connect(settings.db_path) as db:
            await db.execute(
                """INSERT INTO tasks
                   (task_id, user_id, status, created_at, updated_at)
                   VALUES (?, ?, 'queued', ?, ?)""",
                (task_id, user_id, now, now),
            )
            await db.commit()
