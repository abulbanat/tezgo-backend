#!/usr/bin/env python3
"""
TezGo backend — FastAPI + PostgreSQL.
Made by CoreStack Labs.

Provides:
  • Admin web panel (login) with read APIs: stats, orders, customers, drivers,
    driver applications (pending), and per-order chat history.
  • In-app chat (customer <-> driver), text + image, fully stored in the DB,
    with a real-time WebSocket channel per order.

Env vars:
  DATABASE_URL   (required) Postgres connection string (Railway injects this)
  ADMIN_USER     (default: admin)
  ADMIN_PASS     (default: generated & logged on first boot)
  JWT_SECRET     (default: derived) — signs admin sessions
  CHAT_SECRET    (default: derived) — signs per-order chat links
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncpg
import jwt
from fastapi import (
    Depends, FastAPI, File, Form, HTTPException, UploadFile, WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tezgo-backend")

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
ADMIN_USER = os.environ.get("ADMIN_USER", "admin").strip()
ADMIN_PASS = os.environ.get("ADMIN_PASS", "").strip()
JWT_SECRET = os.environ.get("JWT_SECRET", "").strip() or secrets.token_hex(32)
CHAT_SECRET = os.environ.get("CHAT_SECRET", "").strip() or JWT_SECRET
HERE = Path(__file__).parent

pool: asyncpg.Pool | None = None
# order_code -> set of live websockets
_sockets: dict[str, set[WebSocket]] = {}


# --------------------------------------------------------------------------- #
# Password hashing (stdlib, no external dep)
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return f"pbkdf2${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split("$", 2)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
        return hmac.compare_digest(dk.hex(), h)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Chat link token: hmac(CHAT_SECRET, "code:role")
# --------------------------------------------------------------------------- #
def chat_token(code: str, role: str) -> str:
    msg = f"{code}:{role}".encode()
    return hmac.new(CHAT_SECRET.encode(), msg, hashlib.sha256).hexdigest()[:32]


def verify_chat_token(code: str, role: str, token: str) -> bool:
    return role in ("customer", "driver") and hmac.compare_digest(chat_token(code, role), token or "")


# --------------------------------------------------------------------------- #
# Startup / DB init
# --------------------------------------------------------------------------- #
@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5)
    schema = (HERE / "schema.sql").read_text()
    async with pool.acquire() as con:
        await con.execute(schema)
        # Seed / update the admin account.
        global ADMIN_PASS
        if not ADMIN_PASS:
            ADMIN_PASS = secrets.token_urlsafe(9)
            log.warning("ADMIN_PASS not set — generated one: %s (set ADMIN_PASS env to fix)", ADMIN_PASS)
        row = await con.fetchrow("SELECT id FROM admins WHERE username=$1", ADMIN_USER)
        if row is None:
            await con.execute(
                "INSERT INTO admins(username, password_hash, name) VALUES($1,$2,$3)",
                ADMIN_USER, hash_password(ADMIN_PASS), "Owner",
            )
            log.info("Seeded admin '%s'.", ADMIN_USER)
    log.info("TezGo backend ready.")
    yield
    await pool.close()


app = FastAPI(title="TezGo backend", lifespan=lifespan)
bearer = HTTPBearer(auto_error=False)


# --------------------------------------------------------------------------- #
# Admin auth
# --------------------------------------------------------------------------- #
def make_jwt(username: str) -> str:
    payload = {"sub": username, "exp": datetime.now(timezone.utc) + timedelta(days=7)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


async def require_admin(cred: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    if cred is None:
        raise HTTPException(401, "Missing token")
    try:
        data = jwt.decode(cred.credentials, JWT_SECRET, algorithms=["HS256"])
        return data["sub"]
    except Exception:
        raise HTTPException(401, "Invalid or expired token")


@app.post("/api/login")
async def login(payload: dict):
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    async with pool.acquire() as con:
        row = await con.fetchrow("SELECT password_hash FROM admins WHERE username=$1", username)
    if not row or not verify_password(password, row["password_hash"]):
        raise HTTPException(401, "Login yoki parol noto'g'ri")
    return {"token": make_jwt(username), "username": username}


# --------------------------------------------------------------------------- #
# Admin read APIs
# --------------------------------------------------------------------------- #
def _rows(records) -> list[dict]:
    return [dict(r) for r in records]


@app.get("/api/stats")
async def stats(_: str = Depends(require_admin)):
    async with pool.acquire() as con:
        return {
            "orders_total": await con.fetchval("SELECT count(*) FROM orders"),
            "orders_active": await con.fetchval(
                "SELECT count(*) FROM orders WHERE status IN ('pending','accepted','enroute','arrived')"),
            "orders_completed": await con.fetchval("SELECT count(*) FROM orders WHERE status='completed'"),
            "customers": await con.fetchval("SELECT count(*) FROM customers"),
            "drivers_approved": await con.fetchval("SELECT count(*) FROM drivers WHERE status='approved'"),
            "drivers_pending": await con.fetchval("SELECT count(*) FROM drivers WHERE status='pending'"),
            "messages": await con.fetchval("SELECT count(*) FROM messages"),
        }


@app.get("/api/orders")
async def orders(status: str | None = None, limit: int = 100, _: str = Depends(require_admin)):
    q = ("SELECT o.*, c.name AS customer_name, d.full_name AS driver_name "
         "FROM orders o LEFT JOIN customers c ON c.id=o.customer_id "
         "LEFT JOIN drivers d ON d.id=o.driver_id ")
    args = []
    if status:
        q += "WHERE o.status=$1 "
        args.append(status)
    q += f"ORDER BY o.created_at DESC LIMIT {int(limit)}"
    async with pool.acquire() as con:
        return _rows(await con.fetch(q, *args))


@app.get("/api/orders/{code}/messages")
async def order_messages(code: str, _: str = Depends(require_admin)):
    async with pool.acquire() as con:
        oid = await con.fetchval("SELECT id FROM orders WHERE code=$1", code)
        if not oid:
            raise HTTPException(404, "Order not found")
        return _rows(await con.fetch(
            "SELECT id, sender_role, type, body, image_url, created_at "
            "FROM messages WHERE order_id=$1 ORDER BY created_at", oid))


@app.get("/api/customers")
async def customers(_: str = Depends(require_admin)):
    async with pool.acquire() as con:
        return _rows(await con.fetch("SELECT * FROM customers ORDER BY created_at DESC LIMIT 500"))


@app.get("/api/drivers")
async def drivers(status: str | None = None, _: str = Depends(require_admin)):
    q = "SELECT * FROM drivers "
    args = []
    if status:
        q += "WHERE status=$1 "
        args.append(status)
    q += "ORDER BY created_at DESC LIMIT 500"
    async with pool.acquire() as con:
        return _rows(await con.fetch(q, *args))


@app.get("/api/applications")
async def applications(_: str = Depends(require_admin)):
    """Pending driver registration requests (with all submitted data)."""
    async with pool.acquire() as con:
        return _rows(await con.fetch("SELECT * FROM drivers WHERE status='pending' ORDER BY created_at"))


@app.post("/api/drivers/{driver_id}/approve")
async def approve_driver(driver_id: int, admin: str = Depends(require_admin)):
    async with pool.acquire() as con:
        await con.execute(
            "UPDATE drivers SET status='approved', approved_at=now() WHERE id=$1", driver_id)
    return {"ok": True}


@app.post("/api/drivers/{driver_id}/reject")
async def reject_driver(driver_id: int, payload: dict, admin: str = Depends(require_admin)):
    async with pool.acquire() as con:
        await con.execute(
            "UPDATE drivers SET status='rejected', reject_reason=$2 WHERE id=$1",
            driver_id, (payload or {}).get("reason", ""))
    return {"ok": True}


# --------------------------------------------------------------------------- #
# In-app chat (customer <-> driver) — token-scoped per order
# --------------------------------------------------------------------------- #
async def _store_message(code: str, role: str, mtype: str, body: str | None,
                         image_bytes: bytes | None, mime: str | None) -> dict:
    async with pool.acquire() as con:
        order = await con.fetchrow("SELECT id, customer_id, driver_id FROM orders WHERE code=$1", code)
        if not order:
            raise HTTPException(404, "Order not found")
        sender_id = order["customer_id"] if role == "customer" else order["driver_id"]
        image_url = None
        row = await con.fetchrow(
            "INSERT INTO messages(order_id, sender_role, sender_id, type, body, image_url) "
            "VALUES($1,$2,$3,$4,$5,$6) RETURNING id, created_at",
            order["id"], role, sender_id, mtype, body, None)
        mid = row["id"]
        if mtype == "image" and image_bytes is not None:
            await con.execute("INSERT INTO chat_images(message_id, mime, data) VALUES($1,$2,$3)",
                              mid, mime or "image/jpeg", image_bytes)
            image_url = f"/api/chat-image/{mid}"
            await con.execute("UPDATE messages SET image_url=$2 WHERE id=$1", mid, image_url)
    return {"id": mid, "role": role, "type": mtype, "body": body,
            "image_url": image_url, "created_at": row["created_at"].isoformat()}


async def _broadcast(code: str, message: dict):
    dead = []
    for ws in _sockets.get(code, set()):
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            dead.append(ws)
    for ws in dead:
        _sockets.get(code, set()).discard(ws)


@app.get("/api/chat/{code}")
async def chat_history(code: str, role: str, t: str):
    if not verify_chat_token(code, role, t):
        raise HTTPException(403, "Invalid chat token")
    async with pool.acquire() as con:
        order = await con.fetchrow(
            "SELECT o.code, o.status, o.pickup_address, o.dest_address, "
            "c.name AS customer_name, d.full_name AS driver_name "
            "FROM orders o LEFT JOIN customers c ON c.id=o.customer_id "
            "LEFT JOIN drivers d ON d.id=o.driver_id WHERE o.code=$1", code)
        if not order:
            raise HTTPException(404, "Order not found")
        oid = await con.fetchval("SELECT id FROM orders WHERE code=$1", code)
        msgs = await con.fetch(
            "SELECT id, sender_role, type, body, image_url, created_at "
            "FROM messages WHERE order_id=$1 ORDER BY created_at", oid)
    return {"order": dict(order), "messages": _rows(msgs)}


@app.post("/api/chat/{code}/message")
async def chat_send(code: str, payload: dict):
    role, t = payload.get("role"), payload.get("t")
    if not verify_chat_token(code, role, t):
        raise HTTPException(403, "Invalid chat token")
    body = (payload.get("body") or "").strip()
    if not body:
        raise HTTPException(400, "Empty message")
    msg = await _store_message(code, role, "text", body, None, None)
    await _broadcast(code, msg)
    return msg


@app.post("/api/chat/{code}/image")
async def chat_image(code: str, role: str = Form(...), t: str = Form(...),
                     file: UploadFile = File(...)):
    if not verify_chat_token(code, role, t):
        raise HTTPException(403, "Invalid chat token")
    data = await file.read()
    if len(data) > 8 * 1024 * 1024:
        raise HTTPException(413, "Rasm juda katta (max 8MB)")
    msg = await _store_message(code, role, "image", None, data, file.content_type)
    await _broadcast(code, msg)
    return msg


@app.get("/api/chat-image/{message_id}")
async def chat_image_get(message_id: int):
    async with pool.acquire() as con:
        row = await con.fetchrow("SELECT mime, data FROM chat_images WHERE message_id=$1", message_id)
    if not row:
        raise HTTPException(404, "Not found")
    return Response(content=row["data"], media_type=row["mime"])


@app.websocket("/ws/chat/{code}")
async def ws_chat(ws: WebSocket, code: str, role: str, t: str):
    if not verify_chat_token(code, role, t):
        await ws.close(code=4403)
        return
    await ws.accept()
    _sockets.setdefault(code, set()).add(ws)
    try:
        while True:
            raw = await ws.receive_text()
            try:
                data = json.loads(raw)
            except Exception:
                continue
            body = (data.get("body") or "").strip()
            if body:
                msg = await _store_message(code, role, "text", body, None, None)
                await _broadcast(code, msg)
    except WebSocketDisconnect:
        pass
    finally:
        _sockets.get(code, set()).discard(ws)


# --------------------------------------------------------------------------- #
# Static pages
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
async def root():
    return '<meta http-equiv="refresh" content="0; url=/admin">'


@app.get("/admin", response_class=HTMLResponse)
async def admin_page():
    return (HERE / "admin.html").read_text()


@app.get("/chat", response_class=HTMLResponse)
async def chat_page():
    return (HERE / "chat.html").read_text()


@app.get("/health")
async def health():
    return {"ok": True}
