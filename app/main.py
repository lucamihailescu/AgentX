import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from .auth import (
    CLITokenError,
    TokenAcquisitionError,
    acquire_access_token,
    build_auth_code_flow,
    complete_auth_code_flow,
    issue_cli_token,
    verify_cli_token,
)
from .config import settings
from .db import init_db
from .graph_client import GraphClient, GraphError
from . import rules as rules_module
from .unsubscribe import UnsubscribeError, perform_unsubscribe
from .worker import Scheduler, Worker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("agentx")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


class CreateTaskResponse(BaseModel):
    task_id: str
    status: str


class TaskStatus(BaseModel):
    task_id: str
    status: str
    cursor_before: str | None = None
    error: str | None = None
    result: dict | None = None
    created_at: str
    updated_at: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    worker = Worker()
    scheduler = Scheduler()
    worker_task = asyncio.create_task(worker.run(), name="worker")
    scheduler_task = asyncio.create_task(scheduler.run(), name="scheduler")
    logger.info("agent started; authority=%s", settings.authority)
    try:
        yield
    finally:
        await worker.stop()
        await scheduler.stop()
        for t in (worker_task, scheduler_task):
            t.cancel()
        await asyncio.gather(worker_task, scheduler_task, return_exceptions=True)


app = FastAPI(title="agentx — consumer Outlook agent", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret)


def _require_user(request: Request) -> str:
    user_id = request.session.get("user_id")
    if user_id:
        return user_id
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        try:
            return verify_cli_token(auth_header.split(" ", 1)[1].strip())
        except CLITokenError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
    raise HTTPException(
        status_code=401,
        detail="Sign in at /auth/login (browser) or pass Authorization: Bearer <cli-token>",
    )


async def _insert_task(user_id: str, cursor_before: str | None = None) -> str:
    task_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            """INSERT INTO tasks
               (task_id, user_id, status, cursor_before, created_at, updated_at)
               VALUES (?, ?, 'queued', ?, ?, ?)""",
            (task_id, user_id, cursor_before, now, now),
        )
        await db.commit()
    return task_id


async def _load_task(user_id: str, task_id: str) -> dict:
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,))
        row = await cur.fetchone()
    if row is None or row["user_id"] != user_id:
        raise HTTPException(status_code=404, detail="Task not found")
    task = dict(row)
    task["result"] = json.loads(task["result_data"]) if task["result_data"] else None
    return task


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return templates.TemplateResponse("login.html", {"request": request})
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT task_id, status, cursor_before, created_at, updated_at
               FROM tasks WHERE user_id = ?
               ORDER BY created_at DESC LIMIT 10""",
            (user_id,),
        )
        rows = [dict(r) for r in await cur.fetchall()]
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "tasks": rows,
            "username": request.session.get("username"),
        },
    )


@app.get("/auth/login")
async def auth_login(request: Request):
    flow = build_auth_code_flow()
    request.session["auth_flow"] = flow
    return RedirectResponse(flow["auth_uri"])


@app.get("/auth/callback")
async def auth_callback(request: Request):
    flow = request.session.pop("auth_flow", None)
    if flow is None:
        raise HTTPException(status_code=400, detail="No auth flow in session")
    try:
        user_id, username = await complete_auth_code_flow(flow, dict(request.query_params))
    except TokenAcquisitionError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    request.session["user_id"] = user_id
    request.session["username"] = username
    return RedirectResponse("/")


@app.post("/auth/logout")
async def auth_logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@app.get("/auth/cli-token")
async def auth_cli_token(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Sign in at /auth/login first")
    token, ttl = issue_cli_token(user_id)
    return {
        "token": token,
        "expires_in_seconds": ttl,
        "usage": f'curl -H "Authorization: Bearer {token}" http://localhost:8080/tasks',
    }


@app.post("/ui/tasks")
async def ui_create_task(request: Request):
    user_id = _require_user(request)
    task_id = await _insert_task(user_id)
    return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)


@app.get("/ui/tasks/{task_id}", response_class=HTMLResponse)
async def ui_task_detail(task_id: str, request: Request):
    user_id = _require_user(request)
    task = await _load_task(user_id, task_id)
    raw_json = json.dumps(task["result"], indent=2) if task["result"] else None
    return templates.TemplateResponse(
        "task.html",
        {
            "request": request,
            "task": task,
            "raw_json": raw_json,
            "username": request.session.get("username"),
        },
    )


def _find_message(task: dict, message_id: str) -> dict:
    if not task["result"]:
        raise HTTPException(status_code=404, detail="Task has no result")
    target = next(
        (m for m in task["result"].get("messages", []) if m.get("id") == message_id),
        None,
    )
    if target is None:
        raise HTTPException(status_code=404, detail="Message not in task report")
    return target


async def _save_result(task_id: str, result: dict) -> None:
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            "UPDATE tasks SET result_data=?, updated_at=? WHERE task_id=?",
            (json.dumps(result), datetime.now(timezone.utc).isoformat(), task_id),
        )
        await db.commit()


async def _graph_delete_message(user_id: str, message_id: str) -> None:
    async def token_provider() -> str:
        return await acquire_access_token(user_id)

    try:
        async with GraphClient(token_provider) as graph:
            await graph.request("DELETE", f"/me/messages/{message_id}")
    except (TokenAcquisitionError, GraphError) as exc:
        raise HTTPException(status_code=502, detail=f"Delete failed: {exc}")


async def _do_unsubscribe(target: dict) -> None:
    if not target.get("unsubscribe_url"):
        raise HTTPException(status_code=400, detail="No unsubscribe URL on this message")
    try:
        await perform_unsubscribe(
            target["unsubscribe_url"], bool(target.get("unsubscribe_one_click"))
        )
    except UnsubscribeError as exc:
        raise HTTPException(status_code=502, detail=f"Unsubscribe failed: {exc}")
    target["unsubscribed"] = True
    target["unsubscribed_at"] = datetime.now(timezone.utc).isoformat()


@app.post("/ui/tasks/{task_id}/messages/{message_id}/delete")
async def ui_delete_message(task_id: str, message_id: str, request: Request):
    user_id = _require_user(request)
    task = await _load_task(user_id, task_id)
    target = _find_message(task, message_id)
    if target.get("deleted"):
        return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)
    await _graph_delete_message(user_id, message_id)
    target["deleted"] = True
    target["deleted_at"] = datetime.now(timezone.utc).isoformat()
    await _save_result(task_id, task["result"])
    return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)


@app.post("/ui/tasks/{task_id}/messages/{message_id}/unsubscribe")
async def ui_unsubscribe_message(task_id: str, message_id: str, request: Request):
    user_id = _require_user(request)
    task = await _load_task(user_id, task_id)
    target = _find_message(task, message_id)
    if target.get("unsubscribed"):
        return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)
    await _do_unsubscribe(target)
    await _save_result(task_id, task["result"])
    return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)


_BULK_ACTIONS = {
    "delete",
    "unsubscribe",
    "unsubscribe-and-delete",
    "allow",
    "deny",
}


@app.post("/ui/tasks/{task_id}/bulk/{action}")
async def ui_bulk_action(task_id: str, action: str, request: Request):
    if action not in _BULK_ACTIONS:
        raise HTTPException(status_code=400, detail="Unknown bulk action")
    user_id = _require_user(request)
    form = await request.form()
    message_ids = form.getlist("messages")
    if not message_ids:
        return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)

    task = await _load_task(user_id, task_id)
    if not task["result"]:
        raise HTTPException(status_code=404, detail="Task has no result")

    by_id = {m.get("id"): m for m in task["result"].get("messages", [])}
    targets = [by_id[mid] for mid in message_ids if mid in by_id]

    async def token_provider() -> str:
        return await acquire_access_token(user_id)

    semaphore = asyncio.Semaphore(4)
    do_unsub = action in {"unsubscribe", "unsubscribe-and-delete"}
    do_delete = action in {"delete", "unsubscribe-and-delete", "deny"}
    do_rule = action in {"allow", "deny"}

    if do_rule:
        seen: set[str] = set()
        for target in targets:
            sender = (target.get("from") or "").strip().lower()
            if not sender or sender in seen:
                continue
            seen.add(sender)
            try:
                await rules_module.upsert_rule(user_id, sender, "address", action)
            except ValueError:
                continue
            target["rule_applied"] = action
            if action == "allow":
                target["spam"] = False
                target["reason"] = "allowlisted sender"

    async with GraphClient(token_provider) as graph:

        async def _process(target: dict) -> None:
            if not target.get("id"):
                return
            async with semaphore:
                if (
                    do_unsub
                    and target.get("unsubscribe_url")
                    and not target.get("unsubscribed")
                ):
                    try:
                        await perform_unsubscribe(
                            target["unsubscribe_url"],
                            bool(target.get("unsubscribe_one_click")),
                        )
                        target["unsubscribed"] = True
                        target["unsubscribed_at"] = datetime.now(timezone.utc).isoformat()
                    except UnsubscribeError as exc:
                        logger.warning("bulk unsub failed for %s: %s", target["id"], exc)

                if do_delete and not target.get("deleted"):
                    try:
                        await graph.request("DELETE", f"/me/messages/{target['id']}")
                        target["deleted"] = True
                        target["deleted_at"] = datetime.now(timezone.utc).isoformat()
                    except (GraphError, TokenAcquisitionError) as exc:
                        logger.warning("bulk delete failed for %s: %s", target["id"], exc)

        await asyncio.gather(*(_process(t) for t in targets))

    await _save_result(task_id, task["result"])
    return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)


@app.post("/ui/tasks/{task_id}/messages/{message_id}/rule/{verdict}")
async def ui_set_rule(task_id: str, message_id: str, verdict: str, request: Request):
    if verdict not in {"allow", "deny"}:
        raise HTTPException(status_code=400, detail="Invalid verdict")
    user_id = _require_user(request)
    task = await _load_task(user_id, task_id)
    target = _find_message(task, message_id)
    sender = (target.get("from") or "").strip().lower()
    if not sender:
        raise HTTPException(status_code=400, detail="Message has no sender address")
    try:
        await rules_module.upsert_rule(user_id, sender, "address", verdict)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    target["rule_applied"] = verdict
    if verdict == "allow":
        target["spam"] = False
        target["reason"] = "allowlisted sender"
    else:  # deny → also delete the surfaced message
        if not target.get("deleted"):
            await _graph_delete_message(user_id, message_id)
            target["deleted"] = True
            target["deleted_at"] = datetime.now(timezone.utc).isoformat()
        target["reason"] = "denylisted sender"

    await _save_result(task_id, task["result"])
    return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)


@app.get("/ui/senders", response_class=HTMLResponse)
async def ui_senders(request: Request):
    user_id = _require_user(request)

    senders: dict[str, dict] = {}
    domains: dict[str, dict] = {}

    async with aiosqlite.connect(settings.db_path) as db:
        cur = await db.execute(
            "SELECT result_data FROM tasks "
            "WHERE user_id = ? AND result_data IS NOT NULL",
            (user_id,),
        )
        rows = await cur.fetchall()

    def _bucket(target: dict, m: dict) -> None:
        target["seen"] += 1
        if m.get("spam") is True:
            target["spam"] += 1
        if m.get("deleted"):
            target["deleted"] += 1
        if m.get("unsubscribed"):
            target["unsubscribed"] += 1
        if m.get("auto_deleted"):
            target["auto_deleted"] += 1
        if m.get("received") and (
            target["last_seen"] is None or m["received"] > target["last_seen"]
        ):
            target["last_seen"] = m["received"]

    def _empty(name: str) -> dict:
        return {
            "target": name,
            "seen": 0,
            "spam": 0,
            "deleted": 0,
            "unsubscribed": 0,
            "auto_deleted": 0,
            "last_seen": None,
        }

    for (raw,) in rows:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        for m in data.get("messages", []):
            sender = (m.get("from") or "").strip().lower()
            if not sender:
                continue
            _bucket(senders.setdefault(sender, _empty(sender)), m)
            if "@" in sender:
                domain = sender.split("@", 1)[-1]
                _bucket(domains.setdefault(domain, _empty(domain)), m)

    rule_index = await rules_module.load_rule_index(user_id)
    for s in senders.values():
        s["rule"] = rule_index.get(("address", s["target"]))
    for d in domains.values():
        d["rule"] = rule_index.get(("domain", d["target"]))

    senders_sorted = sorted(senders.values(), key=lambda s: (-s["spam"], -s["seen"]))[:100]
    domains_sorted = sorted(domains.values(), key=lambda d: (-d["spam"], -d["seen"]))[:50]

    return templates.TemplateResponse(
        "senders.html",
        {
            "request": request,
            "senders": senders_sorted,
            "domains": domains_sorted,
            "username": request.session.get("username"),
        },
    )


@app.get("/ui/rules", response_class=HTMLResponse)
async def ui_rules(request: Request):
    user_id = _require_user(request)
    rules = await rules_module.list_rules(user_id)
    return templates.TemplateResponse(
        "rules.html",
        {
            "request": request,
            "rules": rules,
            "username": request.session.get("username"),
        },
    )


@app.post("/ui/rules/add")
async def ui_rule_add(request: Request):
    user_id = _require_user(request)
    form = await request.form()
    target = (form.get("target") or "").strip().lower()
    target_type = form.get("target_type") or "address"
    verdict = form.get("verdict") or "allow"
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    try:
        await rules_module.upsert_rule(user_id, target, target_type, verdict)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/ui/rules", status_code=303)


@app.post("/ui/rules/delete")
async def ui_rule_delete(request: Request):
    user_id = _require_user(request)
    form = await request.form()
    target = (form.get("target") or "").strip().lower()
    target_type = form.get("target_type") or "address"
    if target:
        await rules_module.delete_rule(user_id, target, target_type)
    return RedirectResponse("/ui/rules", status_code=303)


@app.post("/ui/tasks/{task_id}/messages/{message_id}/unsubscribe-and-delete")
async def ui_unsubscribe_and_delete(task_id: str, message_id: str, request: Request):
    user_id = _require_user(request)
    task = await _load_task(user_id, task_id)
    target = _find_message(task, message_id)
    if target.get("deleted"):
        return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)
    if not target.get("unsubscribed"):
        await _do_unsubscribe(target)
    await _graph_delete_message(user_id, message_id)
    target["deleted"] = True
    target["deleted_at"] = datetime.now(timezone.utc).isoformat()
    await _save_result(task_id, task["result"])
    return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)


@app.post("/tasks", response_model=CreateTaskResponse, status_code=202)
async def create_task(request: Request):
    user_id = _require_user(request)
    task_id = await _insert_task(user_id)
    return CreateTaskResponse(task_id=task_id, status="queued")


@app.get("/tasks/{task_id}", response_model=TaskStatus)
async def get_task(task_id: str, request: Request):
    user_id = _require_user(request)
    task = await _load_task(user_id, task_id)
    return TaskStatus(
        task_id=task["task_id"],
        status=task["status"],
        cursor_before=task.get("cursor_before"),
        error=task["error"],
        result=task["result"],
        created_at=task["created_at"],
        updated_at=task["updated_at"],
    )


@app.post("/ui/tasks/{task_id}/next")
async def ui_next_page(task_id: str, request: Request):
    user_id = _require_user(request)
    parent = await _load_task(user_id, task_id)
    if not parent["result"]:
        raise HTTPException(status_code=400, detail="Parent audit has no result")
    received = [
        m["received"]
        for m in parent["result"].get("messages", [])
        if m.get("received")
    ]
    if not received:
        raise HTTPException(status_code=400, detail="Parent audit has no message timestamps")
    cursor = min(received)  # ISO 8601 timestamps sort lexically as datetimes
    new_id = await _insert_task(user_id, cursor_before=cursor)
    return RedirectResponse(f"/ui/tasks/{new_id}", status_code=303)


@app.get("/ui/settings", response_class=HTMLResponse)
async def ui_settings(request: Request):
    user_id = _require_user(request)
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT schedule_interval_minutes FROM users WHERE user_id = ?", (user_id,)
        )
        row = await cur.fetchone()
        cur = await db.execute(
            """SELECT MAX(created_at) AS last_at FROM tasks WHERE user_id = ?""",
            (user_id,),
        )
        last_row = await cur.fetchone()
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "username": request.session.get("username"),
            "schedule_interval_minutes": row["schedule_interval_minutes"] if row else None,
            "default_schedule_interval_minutes": settings.default_schedule_interval_minutes,
            "last_audit_at": last_row["last_at"] if last_row else None,
        },
    )


@app.post("/ui/settings")
async def ui_settings_save(request: Request):
    user_id = _require_user(request)
    form = await request.form()
    raw = (form.get("schedule_interval_minutes") or "").strip()
    interval: int | None
    if not raw:
        interval = None
    else:
        try:
            interval = int(raw)
        except ValueError:
            raise HTTPException(status_code=400, detail="interval must be an integer")
        if interval <= 0:
            interval = None
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            "UPDATE users SET schedule_interval_minutes = ?, updated_at = ? WHERE user_id = ?",
            (interval, datetime.now(timezone.utc).isoformat(), user_id),
        )
        await db.commit()
    return RedirectResponse("/ui/settings", status_code=303)


_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
    '<rect width="64" height="64" rx="14" fill="#0c0d10"/>'
    '<rect x="12" y="14" width="40" height="5" rx="2" fill="#f0b842"/>'
    '<rect x="12" y="25" width="24" height="5" rx="2" fill="#8a8f9c"/>'
    '<rect x="12" y="36" width="36" height="5" rx="2" fill="#f0b842"/>'
    '<rect x="12" y="47" width="16" height="5" rx="2" fill="#8a8f9c"/>'
    "</svg>"
)


@app.get("/favicon.svg", include_in_schema=False)
async def favicon_svg():
    return Response(
        content=_FAVICON_SVG,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.get("/favicon.ico", include_in_schema=False)
async def favicon_ico():
    # Browsers fall back to /favicon.ico when there's no <link rel="icon">.
    # We serve the SVG via the link tag in base.html; this exists to silence
    # 404 noise without serving a real ICO.
    return Response(status_code=204)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
