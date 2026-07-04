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
import httpx
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
DRIVER_BOT_TOKEN = os.environ.get("DRIVER_BOT_TOKEN", "").strip()  # driver bot: photos, dispatch, notify drivers
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()                # customer bot: notify customers
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
        # Seed / sync the admin account.
        # If ADMIN_PASS is explicitly set, always sync it (create or update the
        # password). Otherwise generate one only if the admin doesn't exist yet.
        explicit = bool(os.environ.get("ADMIN_PASS", "").strip())
        pw = ADMIN_PASS or secrets.token_urlsafe(9)
        row = await con.fetchrow("SELECT id FROM admins WHERE username=$1", ADMIN_USER)
        if row is None:
            await con.execute(
                "INSERT INTO admins(username, password_hash, name) VALUES($1,$2,$3)",
                ADMIN_USER, hash_password(pw), "Owner",
            )
            log.info("Seeded admin '%s'.", ADMIN_USER)
            if not explicit:
                log.warning("ADMIN_PASS not set — generated password: %s", pw)
        elif explicit:
            await con.execute(
                "UPDATE admins SET password_hash=$2 WHERE username=$1",
                ADMIN_USER, hash_password(ADMIN_PASS),
            )
            log.info("Synced admin '%s' password from ADMIN_PASS.", ADMIN_USER)
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
            "orders_cancelled": await con.fetchval("SELECT count(*) FROM orders WHERE status='cancelled'"),
            "revenue_som": await con.fetchval("SELECT COALESCE(SUM(fare_som),0) FROM orders WHERE status='completed'"),
            "customers": await con.fetchval("SELECT count(*) FROM customers"),
            "drivers_approved": await con.fetchval("SELECT count(*) FROM drivers WHERE status='approved'"),
            "drivers_online": await con.fetchval("SELECT count(*) FROM drivers WHERE status='approved' AND is_online=true"),
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


async def notify_driver(telegram_id, text: str):
    """Send a Telegram message to a driver via the driver bot (best-effort)."""
    if not DRIVER_BOT_TOKEN or not telegram_id:
        return
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            await c.post(f"https://api.telegram.org/bot{DRIVER_BOT_TOKEN}/sendMessage",
                         json={"chat_id": telegram_id, "text": text})
    except Exception as exc:  # noqa: BLE001
        log.warning("notify_driver failed: %s", exc)


@app.post("/api/drivers/{driver_id}/approve")
async def approve_driver(driver_id: int, admin: str = Depends(require_admin)):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "UPDATE drivers SET status='approved', approved_at=now() WHERE id=$1 "
            "RETURNING telegram_id", driver_id)
    if row:
        await notify_driver(
            row["telegram_id"],
            "✅ Tabriklaymiz! Arizangiz tasdiqlandi — endi TezGo haydovchisiz.\n\n"
            "Buyurtma olishni boshlash uchun:\n"
            "1) /selfie — bugungi selfi rasmingizni yuboring\n"
            "2) /online — buyurtma qabul qilishni yoqing\n"
            "/offline — buyurtma qabul qilishni to'xtatish")
    return {"ok": True}


@app.post("/api/drivers/{driver_id}/reject")
async def reject_driver(driver_id: int, payload: dict, admin: str = Depends(require_admin)):
    reason = (payload or {}).get("reason", "")
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "UPDATE drivers SET status='rejected', reject_reason=$2 WHERE id=$1 "
            "RETURNING telegram_id", driver_id, reason)
    if row:
        await notify_driver(
            row["telegram_id"],
            "❌ Afsuski, arizangiz rad etildi.\n"
            f"Sabab: {reason or 'ko`rsatilmagan'}\n\n"
            "Ma'lumotlarni to'g'rilab, /reregister buyrug'i orqali qayta yuborishingiz mumkin.")
    return {"ok": True}


@app.post("/api/drivers/{driver_id}/block")
async def block_driver(driver_id: int, admin: str = Depends(require_admin)):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "UPDATE drivers SET status='blocked', is_online=false WHERE id=$1 RETURNING telegram_id",
            driver_id)
    if row:
        await notify_driver(row["telegram_id"], "⛔️ Hisobingiz bloklandi. Batafsil ma'lumot uchun admin bilan bog'laning.")
    return {"ok": True}


@app.post("/api/drivers/{driver_id}/unblock")
async def unblock_driver(driver_id: int, admin: str = Depends(require_admin)):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "UPDATE drivers SET status='approved', reject_reason=NULL WHERE id=$1 RETURNING telegram_id",
            driver_id)
    if row:
        await notify_driver(row["telegram_id"], "✅ Hisobingiz qayta faollashtirildi. /selfie va /online bilan davom eting.")
    return {"ok": True}


@app.post("/api/drivers/{driver_id}/offline")
async def force_offline(driver_id: int, admin: str = Depends(require_admin)):
    async with pool.acquire() as con:
        await con.execute("UPDATE drivers SET is_online=false WHERE id=$1", driver_id)
    return {"ok": True}


@app.post("/api/orders/{code}/cancel")
async def admin_cancel_order(code: str, admin: str = Depends(require_admin)):
    async with pool.acquire() as con:
        order = await con.fetchrow(
            "SELECT o.id, o.status, o.driver_id, c.telegram_id AS cust_tg FROM orders o "
            "JOIN customers c ON c.id=o.customer_id WHERE o.code=$1", code)
        if not order:
            return {"ok": False, "error": "notfound"}
        await con.execute("UPDATE orders SET status='cancelled', cancelled_by='admin' WHERE id=$1", order["id"])
        drv_tg = None
        if order["driver_id"]:
            drv_tg = await con.fetchval("SELECT telegram_id FROM drivers WHERE id=$1", order["driver_id"])
    await tg_send(BOT_TOKEN, order["cust_tg"], f"⚠️ Buyurtmangiz {code} operator tomonidan bekor qilindi.")
    if drv_tg:
        await tg_send(DRIVER_BOT_TOKEN, drv_tg, f"⚠️ {code} buyurtma operator tomonidan bekor qilindi.")
    return {"ok": True}


_photo_cache: dict[str, bytes] = {}


@app.get("/api/tg-photo/{file_id}")
async def tg_photo(file_id: str):
    """Fetch a driver's document photo from Telegram (by file_id) and serve it.
    Used by the admin panel to review driver documents. file_ids are long and
    unguessable, so they act as capability tokens for the images."""
    if not DRIVER_BOT_TOKEN:
        raise HTTPException(503, "DRIVER_BOT_TOKEN not configured on backend")
    if file_id in _photo_cache:
        return Response(content=_photo_cache[file_id], media_type="image/jpeg",
                        headers={"Cache-Control": "public, max-age=86400"})
    try:
        async with httpx.AsyncClient(timeout=25) as c:
            meta = (await c.get(
                f"https://api.telegram.org/bot{DRIVER_BOT_TOKEN}/getFile",
                params={"file_id": file_id})).json()
            if not meta.get("ok"):
                raise HTTPException(404, "File not found")
            path = meta["result"]["file_path"]
            img = await c.get(f"https://api.telegram.org/file/bot{DRIVER_BOT_TOKEN}/{path}")
            data = img.content
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"Telegram fetch failed: {exc}")
    if len(_photo_cache) < 200:
        _photo_cache[file_id] = data
    return Response(content=data, media_type="image/jpeg",
                    headers={"Cache-Control": "public, max-age=86400"})


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
# Orders: create (from customer bot) + dispatch to online drivers + accept
# --------------------------------------------------------------------------- #
import random
import string

CAR_LABELS = {"economy": "Ekonom", "comfort": "Komfort", "business": "Biznes"}


def gen_code() -> str:
    return "TG-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def fmt_som(n) -> str:
    try:
        return f"{int(round(float(n))):,}".replace(",", " ")
    except Exception:
        return str(n)


async def tg_send(token: str, chat_id, text: str, reply_markup: dict | None = None):
    if not token or not chat_id:
        return
    body = {"chat_id": chat_id, "text": text}
    if reply_markup:
        body["reply_markup"] = reply_markup
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            await c.post(f"https://api.telegram.org/bot{token}/sendMessage", json=body)
    except Exception as exc:  # noqa: BLE001
        log.warning("tg_send failed: %s", exc)


def render_order_for_driver(code: str, o: dict) -> str:
    cls = CAR_LABELS.get(o.get("class"), o.get("class") or "")
    return (
        f"🆕 Yangi buyurtma — {code}\n\n"
        f"📍 Qayerdan: {o['pickup'].get('address', '')}\n"
        f"🏁 Qayerga: {o['destination'].get('address', '')}\n"
        f"🚘 Sinf: {cls}\n"
        f"📏 {float(o.get('distance_km', 0)):.1f} km · ⏱ ~{int(o.get('duration_min', 0))} daq\n"
        f"💰 {fmt_som(o.get('fare_som', 0))} so'm"
    )


@app.post("/api/orders")
async def create_order(payload: dict):
    """Called by the customer bot when a rider confirms an order.
    Stores the order and dispatches it to online approved drivers."""
    cust = payload.get("customer") or {}
    p = payload.get("pickup") or {}
    d = payload.get("destination") or {}
    code = gen_code()
    async with pool.acquire() as con:
        crow = await con.fetchrow(
            "INSERT INTO customers(telegram_id,name,username) VALUES($1,$2,$3) "
            "ON CONFLICT (telegram_id) DO UPDATE SET name=EXCLUDED.name, username=EXCLUDED.username "
            "RETURNING id", cust.get("telegram_id"), cust.get("name"), cust.get("username"))
        await con.execute(
            "INSERT INTO orders(code,customer_id,pickup_lat,pickup_lon,pickup_address,"
            "dest_lat,dest_lon,dest_address,car_class,distance_km,duration_min,fare_som,status) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending')",
            code, crow["id"], p.get("lat"), p.get("lon"), p.get("address"),
            d.get("lat"), d.get("lon"), d.get("address"), payload.get("class"),
            payload.get("distance_km"), payload.get("duration_min"), payload.get("fare_som"))
        drivers = await con.fetch(
            "SELECT telegram_id FROM drivers WHERE status='approved' AND is_online=true")
    text = render_order_for_driver(code, {"pickup": p, "destination": d, **payload})
    kb = {"inline_keyboard": [[{"text": "🚕 Qabul qilish", "callback_data": f"accept:{code}"}]]}
    for dr in drivers:
        await tg_send(DRIVER_BOT_TOKEN, dr["telegram_id"], text, kb)
        await _send_location(DRIVER_BOT_TOKEN, dr["telegram_id"], p.get("lat"), p.get("lon"))
    return {"ok": True, "code": code, "drivers_notified": len(drivers)}


async def _send_location(token, chat_id, lat, lon):
    if not (token and chat_id and lat and lon):
        return
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            await c.post(f"https://api.telegram.org/bot{token}/sendLocation",
                         json={"chat_id": chat_id, "latitude": lat, "longitude": lon})
    except Exception:  # noqa: BLE001
        pass


@app.post("/api/orders/{code}/accept")
async def accept_order_api(code: str, payload: dict):
    """Called by the driver bot when a driver taps 'Qabul qilish'. First-come wins."""
    driver_tg = payload.get("driver_telegram_id")
    async with pool.acquire() as con:
        order = await con.fetchrow(
            "SELECT o.id, o.status, c.telegram_id AS cust_tg FROM orders o "
            "JOIN customers c ON c.id=o.customer_id WHERE o.code=$1", code)
        if not order:
            return {"ok": False, "error": "notfound"}
        if order["status"] != "pending":
            return {"ok": False, "error": "taken"}
        drv = await con.fetchrow(
            "SELECT id, full_name, phone, car_make, car_color, car_plate "
            "FROM drivers WHERE telegram_id=$1 AND status='approved'", driver_tg)
        if not drv:
            return {"ok": False, "error": "not_driver"}
        await con.execute(
            "UPDATE orders SET driver_id=$2, status='accepted', accepted_at=now() WHERE id=$1",
            order["id"], drv["id"])
    car = f"{drv['car_make'] or ''} {drv['car_color'] or ''} {drv['car_plate'] or ''}".strip()
    await tg_send(BOT_TOKEN, order["cust_tg"],
                  f"🚗 Buyurtmangizni haydovchi qabul qildi!\n"
                  f"Haydovchi: {drv['full_name'] or ''}\nMashina: {car}\n"
                  "Tez orada yetib boradi.")
    return {"ok": True, "driver": {"name": drv["full_name"], "phone": drv["phone"], "car": car}}


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
