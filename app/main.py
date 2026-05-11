import asyncio
import json
import logging
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from .auth import (
    CLITokenError,
    TokenAcquisitionError,
    get_user_provider_name,
    issue_cli_token,
    verify_cli_token,
)
from .config import settings
from .db import init_db
from . import chat as chat_module
from . import rules as rules_module
from . import sender_stats
from . import suggestions
from .providers import PROVIDERS, get_provider
from .providers.base import AuthError
from .unsubscribe import UnsubscribeError, perform_unsubscribe
from .worker import Scheduler, Worker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("agentx")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


_AUDIT_CITATION_RE = re.compile(
    r"\[audit:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\]"
)


def render_citations(text: str) -> Markup:
    """Convert `[audit:<uuid>]` tokens in chat content into clickable links.
    Operates on already-HTML-escaped text so the surrounding content stays
    safe; `Markup(...)` marks the result trusted for Jinja."""
    safe = str(escape(text))
    rendered = _AUDIT_CITATION_RE.sub(
        lambda m: (
            f'<a href="/ui/tasks/{m.group(1)}" class="citation">'
            f'audit {m.group(1)[:8]}</a>'
        ),
        safe,
    )
    return Markup(rendered)


templates.env.filters["citations"] = render_citations


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
    enabled = [n for n, p in PROVIDERS.items() if p.is_configured()]
    logger.info("agent started; providers=%s", enabled or "(none configured)")
    try:
        yield
    finally:
        await worker.stop()
        await scheduler.stop()
        for t in (worker_task, scheduler_task):
            t.cancel()
        await asyncio.gather(worker_task, scheduler_task, return_exceptions=True)
        for p in PROVIDERS.values():
            await p.aclose()


app = FastAPI(title="agentx — multi-provider mailbox agent", lifespan=lifespan)
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
        detail="Sign in at / (browser) or pass Authorization: Bearer <cli-token>",
    )


async def _user_provider(user_id: str):
    name = await get_user_provider_name(user_id)
    if not name:
        raise HTTPException(status_code=404, detail="Unknown user")
    try:
        return get_provider(name)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


async def _insert_task(
    user_id: str,
    cursor_before: str | None = None,
    kind: str = "audit",
) -> str:
    task_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            """INSERT INTO tasks
               (task_id, user_id, kind, status, cursor_before, created_at, updated_at)
               VALUES (?, ?, ?, 'queued', ?, ?, ?)""",
            (task_id, user_id, kind, cursor_before, now, now),
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


# ── pages ────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        provider_buttons = [
            {"name": p.NAME, "label": p.DISPLAY_NAME}
            for p in PROVIDERS.values() if p.is_configured()
        ]
        return templates.TemplateResponse(
            request,
            "login.html",
            {"providers": provider_buttons},
        )
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT task_id, kind, status, cursor_before, created_at, updated_at
               FROM tasks WHERE user_id = ?
               ORDER BY created_at DESC LIMIT 10""",
            (user_id,),
        )
        rows = [dict(r) for r in await cur.fetchall()]
    block_suggestions = await suggestions.list_block_suggestions(user_id)
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "tasks": rows,
            "block_suggestions": block_suggestions,
            "username": request.session.get("username"),
        },
    )


# ── auth (parameterized per provider) ────────────────────────────────────
@app.get("/auth/{provider_name}/login")
async def auth_login(provider_name: str, request: Request):
    try:
        provider = get_provider(provider_name)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    if not provider.is_configured():
        raise HTTPException(
            status_code=503, detail=f"{provider.DISPLAY_NAME} is not configured"
        )
    try:
        flow = await provider.build_auth_flow()
    except AuthError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    request.session["auth_flow"] = flow
    request.session["auth_provider"] = provider_name
    return RedirectResponse(flow["auth_uri"])


@app.get("/auth/callback")
async def auth_callback_legacy(request: Request):
    """Backward-compat for the pre-multi-provider redirect URI.

    The original (Microsoft-only) build used `/auth/callback`; existing Entra
    app registrations still have that as their redirect URI. Delegate to the
    Microsoft callback handler so users don't have to re-configure Entra.
    """
    return await auth_callback("microsoft", request)


@app.get("/auth/{provider_name}/callback")
async def auth_callback(provider_name: str, request: Request):
    flow = request.session.pop("auth_flow", None)
    expected = request.session.pop("auth_provider", None)
    if flow is None or expected != provider_name:
        raise HTTPException(status_code=400, detail="No matching auth flow in session")
    try:
        provider = get_provider(provider_name)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    try:
        user_id, username = await provider.complete_auth_flow(
            flow, dict(request.query_params)
        )
    except AuthError as exc:
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
        raise HTTPException(status_code=401, detail="Sign in first")
    token, ttl = issue_cli_token(user_id)
    return {
        "token": token,
        "expires_in_seconds": ttl,
        "usage": f'curl -H "Authorization: Bearer {token}" http://localhost:8080/tasks',
    }


# ── tasks UI ─────────────────────────────────────────────────────────────
@app.post("/ui/tasks")
async def ui_create_task(request: Request):
    user_id = _require_user(request)
    task_id = await _insert_task(user_id)
    return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)


@app.post("/ui/tasks/purge")
async def ui_create_purge(request: Request):
    user_id = _require_user(request)
    task_id = await _insert_task(user_id, kind="purge")
    return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)


@app.get("/ui/tasks/{task_id}", response_class=HTMLResponse)
async def ui_task_detail(task_id: str, request: Request):
    user_id = _require_user(request)
    task = await _load_task(user_id, task_id)
    raw_json = json.dumps(task["result"], indent=2) if task["result"] else None
    # A message is "actionable" if the user might still want to teach the
    # system about it: spam-flagged or unclassified (Ollama failure / no
    # verdict), not yet deleted or auto-deleted. Already-allowed/denied
    # senders are excluded because the rule is in place.
    has_actionable = bool(task["result"]) and any(
        m.get("id")
        and (m.get("spam") is True or m.get("spam") is None)
        and not m.get("deleted")
        and not m.get("auto_deleted")
        and not m.get("rule_applied")
        for m in (task["result"] or {}).get("messages", [])
    )
    return templates.TemplateResponse(
        request,
        "task.html",
        {
            "task": task,
            "raw_json": raw_json,
            "has_actionable": has_actionable,
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


async def _delete_message(user_id: str, message_id: str) -> None:
    provider = await _user_provider(user_id)
    try:
        await provider.delete_message(user_id, message_id)
    except AuthError as exc:
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


@app.get("/ui/tasks/{task_id}/messages/{message_id}/body", response_class=HTMLResponse)
async def ui_message_body(task_id: str, message_id: str, request: Request):
    """Render a single message's body in a self-contained HTML doc, designed
    to be loaded inside a sandboxed iframe. Strict CSP blocks scripts, images
    (including tracking pixels), fonts, and external stylesheets."""
    user_id = _require_user(request)
    task = await _load_task(user_id, task_id)
    _find_message(task, message_id)  # 404 if message isn't in this user's task
    provider = await _user_provider(user_id)
    try:
        body = await provider.fetch_message_body(user_id, message_id)
    except AuthError as exc:
        raise HTTPException(status_code=502, detail=f"Body fetch failed: {exc}")
    return templates.TemplateResponse(
        request,
        "message_body.html",
        {
            "subject": body.get("subject"),
            "from_addr": body.get("from"),
            "received": body.get("received"),
            "html_body": body.get("html"),
            "text_body": body.get("text"),
        },
        headers={
            "Content-Security-Policy": (
                "default-src 'none'; "
                "style-src 'unsafe-inline'; "
                "img-src 'none'; font-src 'none'; "
                "frame-ancestors 'self'"
            ),
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )


@app.post("/ui/tasks/{task_id}/messages/{message_id}/delete")
async def ui_delete_message(task_id: str, message_id: str, request: Request):
    user_id = _require_user(request)
    task = await _load_task(user_id, task_id)
    target = _find_message(task, message_id)
    if target.get("deleted"):
        return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)
    await _delete_message(user_id, message_id)
    target["deleted"] = True
    target["deleted_at"] = datetime.now(timezone.utc).isoformat()
    await _save_result(task_id, task["result"])
    await sender_stats.bump_action(user_id, target.get("from"), deleted=1)
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
    await sender_stats.bump_action(user_id, target.get("from"), unsubscribed=1)
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

    provider = await _user_provider(user_id)

    semaphore = asyncio.Semaphore(4)
    do_unsub = action in {"unsubscribe", "unsubscribe-and-delete"}
    do_delete = action in {"delete", "unsubscribe-and-delete", "deny"}
    do_rule = action in {"allow", "deny"}

    if do_rule:
        senders_for_rule: set[str] = set()
        for target in targets:
            sender = (target.get("from") or "").strip().lower()
            if not sender or sender in senders_for_rule:
                continue
            senders_for_rule.add(sender)
            try:
                await rules_module.upsert_rule(user_id, sender, "address", action)
            except ValueError:
                continue
        # Propagate the verdict to every same-sender row in the audit so
        # they stop appearing as actionable. Only senders we successfully
        # added a rule for (senders_for_rule) — failed upserts don't taint
        # the rest of the report.
        for m in task["result"].get("messages", []):
            if (m.get("from") or "").strip().lower() not in senders_for_rule:
                continue
            if m.get("deleted") or m.get("auto_deleted"):
                continue
            m["rule_applied"] = action
            if action == "allow":
                m["spam"] = False
                m["reason"] = "allowlisted sender"
            else:
                m["spam"] = True
                m["reason"] = "denylisted sender"

    bumps: list[tuple[str | None, int, int]] = []  # (sender, deleted, unsub)

    async def _process(target: dict) -> None:
        if not target.get("id"):
            return
        sender = target.get("from")
        bumped_unsub = 0
        bumped_del = 0
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
                    bumped_unsub = 1
                except UnsubscribeError as exc:
                    logger.warning("bulk unsub failed for %s: %s", target["id"], exc)

            if do_delete and not target.get("deleted"):
                try:
                    await provider.delete_message(user_id, target["id"])
                    target["deleted"] = True
                    target["deleted_at"] = datetime.now(timezone.utc).isoformat()
                    bumped_del = 1
                except AuthError as exc:
                    logger.warning("bulk delete failed for %s: %s", target["id"], exc)
        if bumped_del or bumped_unsub:
            bumps.append((sender, bumped_del, bumped_unsub))

    await asyncio.gather(*(_process(t) for t in targets))
    await _save_result(task_id, task["result"])
    for sender, d, u in bumps:
        await sender_stats.bump_action(user_id, sender, deleted=d, unsubscribed=u)
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

    # Propagate the rule to every same-sender row in this audit so they
    # stop appearing as actionable spam in the UI. No extra API calls — for
    # `deny`, only the clicked message is removed via Graph/Gmail; the
    # rest get cleaned up by the next audit or a manual cleanup.
    for m in task["result"].get("messages", []):
        if (m.get("from") or "").strip().lower() != sender:
            continue
        if m.get("deleted") or m.get("auto_deleted"):
            continue
        m["rule_applied"] = verdict
        if verdict == "allow":
            m["spam"] = False
            m["reason"] = "allowlisted sender"
        else:
            m["spam"] = True
            m["reason"] = "denylisted sender"

    bumped_delete = 0
    if verdict == "deny" and not target.get("deleted"):
        await _delete_message(user_id, message_id)
        target["deleted"] = True
        target["deleted_at"] = datetime.now(timezone.utc).isoformat()
        bumped_delete = 1

    await _save_result(task_id, task["result"])
    if bumped_delete:
        await sender_stats.bump_action(user_id, sender, deleted=1)
    return RedirectResponse(f"/ui/tasks/{task_id}", status_code=303)


# ── senders / rules / settings ───────────────────────────────────────────
@app.get("/ui/senders", response_class=HTMLResponse)
async def ui_senders(request: Request):
    user_id = _require_user(request)
    senders_rows = await sender_stats.list_top(user_id, "address", limit=100)
    domains_rows = await sender_stats.list_top(user_id, "domain", limit=50)
    rule_index = await rules_module.load_rule_index(user_id)
    for r in senders_rows:
        r["rule"] = rule_index.get(("address", r["target"]))
    for r in domains_rows:
        r["rule"] = rule_index.get(("domain", r["target"]))
    return templates.TemplateResponse(
        request,
        "senders.html",
        {
            "senders": senders_rows,
            "domains": domains_rows,
            "username": request.session.get("username"),
        },
    )


@app.get("/ui/rules", response_class=HTMLResponse)
async def ui_rules(request: Request):
    user_id = _require_user(request)
    rules = await rules_module.list_rules(user_id)
    return templates.TemplateResponse(
        request,
        "rules.html",
        {
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


@app.post("/ui/suggestions/block")
async def ui_suggestion_block(request: Request):
    """Accept a suggestion → create the corresponding deny rule, redirect home."""
    user_id = _require_user(request)
    form = await request.form()
    target = (form.get("target") or "").strip().lower()
    target_type = form.get("target_type") or "address"
    if target:
        try:
            await rules_module.upsert_rule(user_id, target, target_type, "deny")
        except ValueError:
            pass
    return RedirectResponse("/", status_code=303)


@app.post("/ui/suggestions/dismiss")
async def ui_suggestion_dismiss(request: Request):
    user_id = _require_user(request)
    form = await request.form()
    target = (form.get("target") or "").strip().lower()
    target_type = form.get("target_type") or "address"
    kind = form.get("kind") or "block"
    if target:
        await suggestions.dismiss(user_id, target, target_type, kind)
    return RedirectResponse("/", status_code=303)


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
    bumped_unsub = 0
    if not target.get("unsubscribed"):
        await _do_unsubscribe(target)
        bumped_unsub = 1
    await _delete_message(user_id, message_id)
    target["deleted"] = True
    target["deleted_at"] = datetime.now(timezone.utc).isoformat()
    await _save_result(task_id, task["result"])
    await sender_stats.bump_action(
        user_id, target.get("from"), deleted=1, unsubscribed=bumped_unsub
    )
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
    cursor = min(received)
    new_id = await _insert_task(user_id, cursor_before=cursor)
    return RedirectResponse(f"/ui/tasks/{new_id}", status_code=303)


async def _load_chat_history(user_id: str, limit: int) -> list[dict]:
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT role, content, created_at FROM chat_messages
               WHERE user_id = ?
               ORDER BY message_id DESC LIMIT ?""",
            (user_id, limit),
        )
        rows = await cur.fetchall()
    # rows are newest-first; flip to oldest-first for display + LLM context.
    return [dict(r) for r in reversed(rows)]


async def _persist_chat_message(user_id: str, role: str, content: str) -> None:
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            """INSERT INTO chat_messages (user_id, role, content, created_at)
               VALUES (?, ?, ?, ?)""",
            (user_id, role, content, datetime.now(timezone.utc).isoformat()),
        )
        await db.commit()


@app.get("/ui/chat", response_class=HTMLResponse)
async def ui_chat(request: Request):
    user_id = _require_user(request)
    history = await _load_chat_history(user_id, limit=50)
    return templates.TemplateResponse(
        request,
        "chat.html",
        {
            "history": history,
            "username": request.session.get("username"),
        },
    )


@app.post("/ui/chat/send")
async def ui_chat_send(request: Request, background_tasks: BackgroundTasks):
    user_id = _require_user(request)
    form = await request.form()
    user_message = (form.get("message") or "").strip()
    if not user_message:
        return RedirectResponse("/ui/chat", status_code=303)

    # Persist the user message immediately so it shows up if the LLM stalls.
    await _persist_chat_message(user_id, "user", user_message)

    history_for_llm = await _load_chat_history(
        user_id, limit=settings.chat_history_window
    )
    # Drop the just-inserted message so chat() can append it itself.
    history_for_llm = [
        {"role": h["role"], "content": h["content"]}
        for h in history_for_llm
        if not (h["role"] == "user" and h["content"] == user_message)
    ]

    accept = request.headers.get("accept", "")
    if "text/plain" in accept or "text/event-stream" in accept:
        # Streaming path — JS hijacked the form submit.
        return StreamingResponse(
            _stream_chat_reply(user_id, user_message, history_for_llm),
            media_type="text/plain",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # Non-streaming fallback (no JS) — block until full reply, then redirect.
    try:
        reply = await chat_module.chat_with_tools(
            user_id, history_for_llm, user_message
        )
    except chat_module.OllamaChatError as exc:
        logger.warning("chat: %s", exc)
        reply = f"⚠ {exc}"
    except Exception as exc:
        logger.exception("chat failed")
        reply = f"Sorry — I hit an unexpected error: {exc}"

    await _persist_chat_message(user_id, "assistant", reply)
    background_tasks.add_task(chat_module.remember, user_id, user_message, reply)
    return RedirectResponse("/ui/chat", status_code=303)


async def _stream_chat_reply(
    user_id: str, user_message: str, history_for_llm: list[dict]
):
    """Async generator that proxies tool-call progress + the final reply to
    the client and persists + schedules memory update once the stream
    completes (or fails)."""
    collected: list[str] = []
    try:
        async for fragment in chat_module.chat_with_tools_stream(
            user_id, history_for_llm, user_message
        ):
            collected.append(fragment)
            yield fragment
    except chat_module.OllamaChatError as exc:
        logger.warning("chat stream: %s", exc)
        msg = f"\n\n⚠ {exc}"
        collected.append(msg)
        yield msg
    except Exception as exc:
        logger.exception("chat streaming failed")
        msg = f"\n\n⚠ Unexpected error: {exc}"
        collected.append(msg)
        yield msg
    finally:
        full_reply = "".join(collected).strip()
        if full_reply:
            try:
                await _persist_chat_message(user_id, "assistant", full_reply)
            except Exception:
                logger.exception("failed to persist streamed reply")
            try:
                # Fire-and-forget — BackgroundTasks attached to a streaming
                # response don't reliably run, so we kick off the memory
                # update via a bare task instead.
                asyncio.create_task(
                    chat_module.remember(user_id, user_message, full_reply)
                )
            except Exception:
                logger.exception("failed to schedule memory update")


@app.post("/ui/chat/clear")
async def ui_chat_clear(request: Request):
    user_id = _require_user(request)
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            "DELETE FROM chat_messages WHERE user_id = ?", (user_id,)
        )
        await db.commit()
    return RedirectResponse("/ui/chat", status_code=303)


@app.get("/ui/settings", response_class=HTMLResponse)
async def ui_settings(request: Request):
    user_id = _require_user(request)
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT schedule_interval_minutes, provider FROM users WHERE user_id = ?",
            (user_id,),
        )
        row = await cur.fetchone()
        cur = await db.execute(
            """SELECT MAX(created_at) AS last_at FROM tasks WHERE user_id = ?""",
            (user_id,),
        )
        last_row = await cur.fetchone()
    provider_label = None
    if row and row["provider"]:
        try:
            provider_label = get_provider(row["provider"]).DISPLAY_NAME
        except ValueError:
            provider_label = row["provider"]
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "username": request.session.get("username"),
            "schedule_interval_minutes": row["schedule_interval_minutes"] if row else None,
            "default_schedule_interval_minutes": settings.default_schedule_interval_minutes,
            "last_audit_at": last_row["last_at"] if last_row else None,
            "provider_label": provider_label,
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
    return Response(status_code=204)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
