import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import aiosqlite

from .config import settings
from . import calibration
from . import digest as digest_module
from . import feedback
from . import search_index
from .providers import get_provider
from .providers.base import AuthError
from .rules import load_rule_index
from . import sender_stats
from .tasks import (
    fetch_messages,
    fetch_new_messages,
    generate_report,
    purge_mailbox,
    run_pipeline,
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
        await self._reap_orphans()
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

    async def _reap_orphans(self) -> None:
        """Recover tasks orphaned by a hard process death.

        A task is claimed by flipping 'queued' -> 'processing' (see
        `_claim_next`). If the process is killed mid-run (container stop,
        OOM, power loss) the row is stranded in 'processing' with no worker
        owning it, and nothing would ever pick it back up. Clean failures go
        through `_process`'s try/except and are marked 'failed', so a row
        still in 'processing' at startup is always orphaned, never live —
        this runs once before the claim loop, while no task is executing,
        and the deployment is single-worker.

        Reset them to 'queued' so the loop re-runs them. Audits/digests are
        safe to re-run; purges resume from the top (already idempotent —
        they only delete blocklisted senders).
        """
        async with aiosqlite.connect(settings.db_path) as db:
            cur = await db.execute(
                "UPDATE tasks SET status='queued', updated_at=? "
                "WHERE status='processing'",
                (_now(),),
            )
            await db.commit()
            if cur.rowcount:
                logger.warning(
                    "reaped %d orphaned task(s) left in 'processing' by a "
                    "previous run; re-queued for retry",
                    cur.rowcount,
                )

    async def _claim_next(self) -> dict | None:
        async with aiosqlite.connect(settings.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT t.task_id, t.user_id, t.cursor_before, t.kind,
                          t.payload, u.provider
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
        kind = task.get("kind")
        if kind == "digest":
            try:
                await self._process_digest(task)
            except Exception as exc:
                logger.exception("Digest task %s failed", task_id)
                await self._update(task_id, status="failed", error=str(exc))
            return
        try:
            provider = get_provider(task.get("provider"))
        except ValueError as exc:
            await self._update(task_id, status="failed", error=f"Provider: {exc}")
            return
        try:
            if kind == "purge":
                await self._process_purge(task, provider)
            elif kind == "scan":
                await self._process_scan(task, provider)
            else:
                await self._process_audit(task, provider)
        except AuthError as exc:
            await self._update(task_id, status="failed", error=f"Auth: {exc}")
        except Exception as exc:
            logger.exception("Task %s failed", task_id)
            await self._update(task_id, status="failed", error=str(exc))

    async def _process_digest(self, task: dict) -> None:
        task_id = task["task_id"]
        user_id = task["user_id"]
        result = await digest_module.generate_digest(
            user_id, settings.digest_window_hours
        )
        await self._update(
            task_id, status="completed", result_data=json.dumps(result)
        )

    async def _process_audit(self, task: dict, provider) -> None:
        task_id = task["task_id"]
        user_id = task["user_id"]
        cursor_before = task.get("cursor_before")
        messages = await fetch_messages(
            provider, user_id, cursor_before=cursor_before
        )
        rules = await load_rule_index(user_id)
        examples = await feedback.collect_examples(
            user_id, settings.ollama_examples_per_class
        )
        priors = await calibration.load_priors(user_id)
        if examples[0] or examples[1]:
            logger.info(
                "audit %s using %d ham + %d spam few-shot examples",
                task_id, len(examples[0]), len(examples[1]),
            )
        if priors:
            logger.info(
                "audit %s using calibration priors for %d sender(s)",
                task_id, len(priors),
            )
        report = await run_pipeline(
            provider, user_id, messages,
            rules=rules, examples=examples, priors=priors,
        )
        await self._update(task_id, status="completed", result_data=json.dumps(report))
        await sender_stats.record_audit_completion(user_id, report)
        # Index for semantic search (best-effort; never fails the audit).
        try:
            await search_index.index_messages(user_id, task_id, report["messages"])
        except Exception:
            logger.exception("search indexing failed for %s", task_id)

    async def _process_scan(self, task: dict, provider) -> None:
        """Process a real-time scan task — the focused equivalent of an audit
        over just the new messages the Poller captured in `payload`. Same
        pipeline (classify → phishing → label), same report shape, so it lists
        and renders like an audit."""
        task_id = task["task_id"]
        user_id = task["user_id"]
        try:
            messages = json.loads(task.get("payload") or "[]")
        except json.JSONDecodeError:
            messages = []
        if not messages:
            await self._update(
                task_id, status="completed",
                result_data=json.dumps(await generate_report([])),
            )
            return
        rules = await load_rule_index(user_id)
        examples = await feedback.collect_examples(
            user_id, settings.ollama_examples_per_class
        )
        priors = await calibration.load_priors(user_id)
        report = await run_pipeline(
            provider, user_id, messages,
            rules=rules, examples=examples, priors=priors,
        )
        report["kind"] = "scan"
        await self._update(task_id, status="completed", result_data=json.dumps(report))
        await sender_stats.record_audit_completion(user_id, report)
        try:
            await search_index.index_messages(user_id, task_id, report["messages"])
        except Exception:
            logger.exception("search indexing failed for scan %s", task_id)

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
        await self._tick_audits()
        await self._tick_digests()

    async def _tick_audits(self) -> None:
        default_minutes = settings.default_schedule_interval_minutes
        async with aiosqlite.connect(settings.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT u.user_id, u.schedule_interval_minutes,
                          (SELECT MAX(created_at) FROM tasks t
                              WHERE t.user_id = u.user_id
                                AND t.kind IN ('audit', 'purge')) AS last_at,
                          EXISTS(SELECT 1 FROM tasks t2
                                 WHERE t2.user_id = u.user_id
                                   AND t2.kind IN ('audit', 'purge')
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

    async def _tick_digests(self) -> None:
        """Queue one digest per user each morning at `digest_hour` local time.

        Fires on the first tick at/after the configured hour, and the
        "already produced today" guard keeps it to a single digest per local
        day. Fails closed (skips) on an unrecognized timezone rather than
        silently falling back to UTC and mailing at the wrong hour.
        """
        if not settings.digest_enabled:
            return
        try:
            tz = ZoneInfo(settings.digest_timezone)
        except Exception:
            logger.warning(
                "Invalid AGENT_DIGEST_TIMEZONE %r; skipping digest tick",
                settings.digest_timezone,
            )
            return
        now_local = datetime.now(tz)
        if now_local.hour < settings.digest_hour:
            return  # before this morning's send time; nothing to do yet
        today_local = now_local.date()

        async with aiosqlite.connect(settings.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT u.user_id,
                          (SELECT MAX(created_at) FROM tasks t
                              WHERE t.user_id = u.user_id
                                AND t.kind = 'digest') AS last_at
                   FROM users u"""
            )
            users = await cur.fetchall()

        for u in users:
            if u["last_at"]:
                last = datetime.fromisoformat(u["last_at"].replace("Z", "+00:00"))
                if last.astimezone(tz).date() >= today_local:
                    continue  # already produced today's digest
            await self._insert_digest_task(u["user_id"])
            logger.info(
                "scheduler queued daily digest for %s (%02d:00 %s)",
                u["user_id"],
                settings.digest_hour,
                settings.digest_timezone,
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

    @staticmethod
    async def _insert_digest_task(user_id: str) -> None:
        task_id = str(uuid.uuid4())
        now = _now()
        async with aiosqlite.connect(settings.db_path) as db:
            await db.execute(
                """INSERT INTO tasks
                   (task_id, user_id, kind, status, created_at, updated_at)
                   VALUES (?, ?, 'digest', 'queued', ?, ?)""",
                (task_id, user_id, now, now),
            )
            await db.commit()


class Poller:
    """Near-real-time inbox polling.

    For each user with polling enabled, fetch the newest message headers,
    detect mail that arrived since the last poll (a received-timestamp
    watermark stored on `users.poll_cursor`), and queue a focused `scan` task
    for just those messages. Reuses the same metadata fetch as audits — no
    public webhook endpoint required, so it works on localhost. Scheduled
    audits remain the backstop for anything missed while polling was off, the
    process was down, or a burst exceeded `poll_fetch_limit`.

    Per-user interval override (`users.poll_interval_seconds`) wins; otherwise
    `AGENT_DEFAULT_POLL_INTERVAL_SECONDS`. Either way the effective interval is
    floored at `poll_min_interval_seconds`, which is also the loop's tick rate.
    """

    def __init__(self) -> None:
        self._stop = asyncio.Event()
        # In-memory last-poll time per user; the durable state (the watermark)
        # lives in users.poll_cursor, so a restart just re-baselines timing.
        self._last_poll: dict[str, datetime] = {}

    async def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception:
                logger.exception("Poller tick failed")
            try:
                await asyncio.wait_for(
                    self._stop.wait(),
                    timeout=max(settings.poll_min_interval_seconds, 1),
                )
            except asyncio.TimeoutError:
                pass

    async def _tick(self) -> None:
        if not settings.poll_enabled:
            return
        default_iv = settings.default_poll_interval_seconds
        async with aiosqlite.connect(settings.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT u.user_id, u.provider, u.poll_interval_seconds,
                          u.poll_cursor,
                          EXISTS(SELECT 1 FROM tasks t
                                 WHERE t.user_id = u.user_id
                                   AND t.kind = 'scan'
                                   AND t.status IN ('queued', 'processing')) AS scan_in_flight
                   FROM users u"""
            )
            users = await cur.fetchall()

        now = datetime.now(timezone.utc)
        for u in users:
            iv = u["poll_interval_seconds"] or default_iv
            if not iv or iv <= 0:
                continue
            iv = max(int(iv), settings.poll_min_interval_seconds)
            last = self._last_poll.get(u["user_id"])
            if last and (now - last).total_seconds() < iv:
                continue
            # Space polls by the interval even when a scan is still running.
            self._last_poll[u["user_id"]] = now
            if u["scan_in_flight"]:
                continue
            try:
                await self._poll_user(dict(u))
            except AuthError as exc:
                logger.warning("poll for %s failed (auth): %s", u["user_id"], exc)
            except Exception:
                logger.exception("poll for %s failed", u["user_id"])

    async def _poll_user(self, u: dict) -> None:
        user_id = u["user_id"]
        try:
            provider = get_provider(u["provider"])
        except ValueError:
            return
        cursor = u["poll_cursor"]
        new_msgs, new_cursor = await fetch_new_messages(
            provider, user_id, cursor=cursor, limit=settings.poll_fetch_limit
        )
        # Advance the watermark first so the same messages aren't re-detected
        # next tick even if enqueuing/processing fails (worst case: a scan is
        # missed and the scheduled audit catches it — never a reprocess loop).
        if new_cursor and new_cursor != cursor:
            await self._set_cursor(user_id, new_cursor)
        if not new_msgs:
            return
        await self._enqueue_scan(user_id, new_msgs)
        logger.info(
            "poll: queued scan of %d new message(s) for %s", len(new_msgs), user_id
        )

    @staticmethod
    async def _set_cursor(user_id: str, cursor: str) -> None:
        async with aiosqlite.connect(settings.db_path) as db:
            await db.execute(
                "UPDATE users SET poll_cursor = ?, updated_at = ? WHERE user_id = ?",
                (cursor, _now(), user_id),
            )
            await db.commit()

    @staticmethod
    async def _enqueue_scan(user_id: str, messages: list[dict]) -> None:
        task_id = str(uuid.uuid4())
        now = _now()
        async with aiosqlite.connect(settings.db_path) as db:
            await db.execute(
                """INSERT INTO tasks
                   (task_id, user_id, kind, status, payload, created_at, updated_at)
                   VALUES (?, ?, 'scan', 'queued', ?, ?, ?)""",
                (task_id, user_id, json.dumps(messages), now, now),
            )
            await db.commit()
