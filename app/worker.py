import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

import aiosqlite

from .config import settings
from .providers import get_provider
from .providers.base import AuthError
from .rules import load_rule_index
from . import sender_stats
from .tasks import (
    auto_delete,
    classify_messages,
    fetch_messages,
    generate_report,
    purge_mailbox,
)

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
                """SELECT t.task_id, t.user_id, t.cursor_before, t.kind, u.provider
                   FROM tasks t JOIN users u ON t.user_id = u.user_id
                   WHERE t.status = 'queued' ORDER BY t.created_at LIMIT 1"""
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
        try:
            provider = get_provider(task.get("provider"))
        except ValueError as exc:
            await self._update(task_id, status="failed", error=f"Provider: {exc}")
            return
        try:
            if task.get("kind") == "purge":
                await self._process_purge(task, provider)
            else:
                await self._process_audit(task, provider)
        except AuthError as exc:
            await self._update(task_id, status="failed", error=f"Auth: {exc}")
        except Exception as exc:
            logger.exception("Task %s failed", task_id)
            await self._update(task_id, status="failed", error=str(exc))

    async def _process_audit(self, task: dict, provider) -> None:
        task_id = task["task_id"]
        user_id = task["user_id"]
        cursor_before = task.get("cursor_before")
        messages = await fetch_messages(
            provider, user_id, cursor_before=cursor_before
        )
        rules = await load_rule_index(user_id)
        messages = await auto_delete(provider, user_id, messages, rules)
        classified = await classify_messages(messages, rules)
        report = await generate_report(classified)
        await self._update(task_id, status="completed", result_data=json.dumps(report))
        await sender_stats.record_audit_completion(user_id, report)

    async def _process_purge(self, task: dict, provider) -> None:
        task_id = task["task_id"]
        user_id = task["user_id"]
        rules = await load_rule_index(user_id)

        async def on_progress(snapshot: dict) -> None:
            await self._update(
                task_id, status="processing", result_data=json.dumps(snapshot)
            )

        async def on_page(page_messages: list[dict]) -> None:
            # Stream per-page sender stats so /ui/senders updates live during
            # the purge. Reuses the audit accumulator — it already knows how
            # to bump `seen` for every walked message and `auto_deleted` for
            # every match.
            await sender_stats.record_audit_completion(
                user_id, {"messages": page_messages}
            )

        summary = await purge_mailbox(
            provider, user_id, rules, on_progress=on_progress, on_page=on_page
        )
        await self._update(
            task_id, status="completed", result_data=json.dumps(summary)
        )

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
    `AGENT_DEFAULT_SCHEDULE_INTERVAL_MINUTES` is used.
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
