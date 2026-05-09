import asyncio
import json
import logging
from datetime import datetime, timezone

import aiosqlite

from .auth import TokenAcquisitionError, acquire_access_token
from .config import settings
from .graph_client import GraphClient, GraphError
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
            classified = await classify_messages(messages)
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
