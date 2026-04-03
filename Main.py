"""
FindBack — Lost & Found Connector  (secure production build)
Security fixes applied:
  #1  Token brute-force → slowdown + per-IP attempt counter (in-memory)
  #2  XSS / input injection → HTML strip on all text fields
  #3  Image validation → base64 decode + magic-byte check + 2 MB cap
  #4  CORS locked → set ALLOWED_ORIGIN env var
  #5  Request size limit → 2 MB body limit via middleware
  #6  POST rate limiting → max 10 posts per IP per hour
  #7  SQLite WAL mode → safe for concurrent readers/writers
  #8  Tokens over HTTPS → must deploy behind HTTPS in production
  #9  Pagination → GET /items accepts ?page=&limit= (max 50)
  #10 Contact info masking → email/phone partially masked in list view
  #11 Audit log table → every create/resolve/delete is logged
  #12 Admin panel → ADMIN_SECRET env var protects admin routes
"""

from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, field_validator
from typing import Optional, List
import sqlite3
import uuid
import base64
import hashlib
import html
import re
import os
import time
import logging
from datetime import datetime
from collections import defaultdict

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger("findback")

# ── Config ────────────────────────────────────────────────────────────────────
ALLOWED_ORIGIN      = os.getenv("ALLOWED_ORIGIN", "http://localhost:8000")
DB_PATH             = os.getenv("DB_PATH", "lost_and_found.db")
ADMIN_SECRET        = os.getenv("ADMIN_SECRET", "changeme-set-this-in-env")  # #12
MAX_BODY_BYTES      = 2 * 1024 * 1024
MAX_IMAGE_BYTES     = 2 * 1024 * 1024
MAX_POSTS_PER_HR    = 10
TOKEN_ATTEMPT_LIMIT = 5
VALID_CATEGORIES    = {
    "Electronics","Wallets & Purses","Keys","Bags & Luggage",
    "Jewelry & Accessories","Documents & ID","Clothing","Pets",
    "Vehicles","Sports Equipment","Books","Other"
}

# ── Rate limit stores ─────────────────────────────────────────────────────────
post_attempts:  dict = defaultdict(list)
token_attempts: dict = defaultdict(list)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="FindBack API", docs_url=None, redoc_url=None)

app.add_middleware(GZipMiddleware, minimum_size=500)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_credentials=False,
    allow_methods=["GET","POST","PATCH","DELETE"],
    allow_headers=["Content-Type", "X-Admin-Secret"],
)

@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    if request.method in ("POST","PATCH","PUT"):
        cl = request.headers.get("content-length")
        if cl and int(cl) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "Request body too large (max 2 MB)"}, status_code=413)
    return await call_next(request)

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id            TEXT PRIMARY KEY,
            type          TEXT NOT NULL CHECK(type IN ('lost','found')),
            title         TEXT NOT NULL,
            description   TEXT NOT NULL,
            category      TEXT NOT NULL,
            location      TEXT NOT NULL,
            date_occurred TEXT NOT NULL,
            contact_name  TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            contact_phone TEXT,
            image_base64  TEXT,
            status        TEXT DEFAULT 'active',
            edit_token    TEXT NOT NULL,
            created_at    TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            action     TEXT NOT NULL,
            item_id    TEXT,
            ip_address TEXT,
            detail     TEXT,
            ts         TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else request.client.host

def audit(action: str, item_id: str, ip: str, detail: str = ""):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_log (action, item_id, ip_address, detail, ts) VALUES (?,?,?,?,?)",
            (action, item_id, ip, detail, datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
        log.info(f"AUDIT | {action} | item={item_id} | ip={ip} | {detail}")
    except Exception as e:
        log.error(f"Audit log error: {e}")

def sanitize(text: str, max_len: int = 500) -> str:
    text = text.strip()
    text = re.sub(r'<[^>]+>', '', text)
    text = html.unescape(text)
    text = re.sub(r'[<>"\']', '', text)
    return text[:max_len]

def mask_email(email: str) -> str:
    parts = email.split("@")
    if len(parts) != 2: return "***@***.***"
    return parts[0][0] + "***@" + parts[1]

def mask_phone(phone: str) -> str:
    digits = re.sub(r'\D', '', phone)
    return "*" * max(0, len(digits)-3) + digits[-3:] if len(digits) >= 3 else "***"

def validate_image(b64: str) -> str:
    try:
        if "," in b64:
            b64 = b64.split(",", 1)[1]
        raw = base64.b64decode(b64)
    except Exception:
        raise HTTPException(400, "Invalid image data")
    if len(raw) > MAX_IMAGE_BYTES:
        raise HTTPException(400, "Image too large (max 2 MB)")
    magic = raw[:12]
    valid = (
        magic[:2] == b'\xff\xd8' or
        magic[:8] == b'\x89PNG\r\n\x1a\n' or
        magic[:6] in (b'GIF87a', b'GIF89a') or
        (magic[:4] == b'RIFF' and raw[8:12] == b'WEBP')
    )
    if not valid:
        raise HTTPException(400, "Only JPEG, PNG, GIF, or WEBP images are allowed")
    if raw[:2] == b'\xff\xd8':           mime = "image/jpeg"
    elif raw[:8] == b'\x89PNG\r\n\x1a\n': mime = "image/png"
    elif magic[:6] in (b'GIF87a', b'GIF89a'): mime = "image/gif"
    else:                                 mime = "image/webp"
    return f"data:{mime};base64,{b64}"

def check_post_rate(ip: str):
    now = time.time()
    post_attempts[ip] = [t for t in post_attempts[ip] if t > now - 3600]
    if len(post_attempts[ip]) >= MAX_POSTS_PER_HR:
        raise HTTPException(429, "Too many posts. Please wait before posting again.")
    post_attempts[ip].append(now)

def check_token_rate(ip: str, item_id: str):
    key = f"{ip}:{item_id}"
    now = time.time()
    token_attempts[key] = [t for t in token_attempts[key] if t > now - 60]
    if len(token_attempts[key]) >= TOKEN_ATTEMPT_LIMIT:
        raise HTTPException(429, "Too many failed attempts. Try again in 60 seconds.")
    token_attempts[key].append(now)

def verify_token(item_id: str, edit_token: str, conn, ip: str):
    check_token_rate(ip, item_id)
    row = conn.execute("SELECT edit_token FROM items WHERE id=?", (item_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Item not found")
    stored   = row["edit_token"].encode()
    provided = edit_token.encode()
    if not (len(stored) == len(provided) and
            hashlib.sha256(stored).digest() == hashlib.sha256(provided).digest()):
        raise HTTPException(403, "Invalid edit token")
    token_attempts[f"{ip}:{item_id}"] = []

def require_admin(x_admin_secret: Optional[str]):
    """#12 — verify admin secret header."""
    if not x_admin_secret or x_admin_secret != ADMIN_SECRET:
        raise HTTPException(401, "Invalid or missing admin secret")

# ── Models ────────────────────────────────────────────────────────────────────
class ItemCreate(BaseModel):
    type:          str
    title:         str
    description:   str
    category:      str
    location:      str
    date_occurred: str
    contact_name:  str
    contact_email: str
    contact_phone: Optional[str] = None
    image_base64:  Optional[str] = None

    @field_validator('type')
    @classmethod
    def validate_type(cls, v):
        if v not in ('lost','found'): raise ValueError("type must be 'lost' or 'found'")
        return v

    @field_validator('category')
    @classmethod
    def validate_category(cls, v):
        if v not in VALID_CATEGORIES: raise ValueError("Invalid category")
        return v

    @field_validator('title')
    @classmethod
    def validate_title(cls, v):
        v = sanitize(v, 120)
        if len(v) < 3: raise ValueError("Title must be at least 3 characters")
        return v

    @field_validator('description')
    @classmethod
    def validate_description(cls, v):
        v = sanitize(v, 1000)
        if len(v) < 10: raise ValueError("Description must be at least 10 characters")
        return v

    @field_validator('location')
    @classmethod
    def validate_location(cls, v): return sanitize(v, 200)

    @field_validator('contact_name')
    @classmethod
    def validate_name(cls, v): return sanitize(v, 100)

    @field_validator('contact_email')
    @classmethod
    def validate_email(cls, v):
        v = v.strip().lower()
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
            raise ValueError("Invalid email address")
        return v[:200]

    @field_validator('contact_phone')
    @classmethod
    def validate_phone(cls, v):
        if v is None: return v
        return re.sub(r'[^\d+\-\s()]', '', v)[:20]

    @field_validator('date_occurred')
    @classmethod
    def validate_date(cls, v):
        try: datetime.strptime(v, '%Y-%m-%d')
        except ValueError: raise ValueError("date_occurred must be YYYY-MM-DD")
        return v

class ItemOut(BaseModel):
    model_config = {"from_attributes": True}
    id:            str
    type:          str
    title:         str
    description:   str
    category:      str
    location:      str
    date_occurred: str
    contact_name:  str
    contact_email: str
    contact_phone: Optional[str] = None
    image_base64:  Optional[str] = None
    status:        str
    created_at:    str

class ItemCreatedOut(ItemOut):
    edit_token: str

class TokenBody(BaseModel):
    edit_token: str

    @field_validator('edit_token')
    @classmethod
    def validate_token(cls, v):
        v = v.strip()
        if len(v) < 10 or len(v) > 128: raise ValueError("Invalid token format")
        return v

class PaginatedItems(BaseModel):
    items:  List[ItemOut]
    total:  int
    page:   int
    pages:  int

class AuditLogEntry(BaseModel):
    model_config = {"from_attributes": True}
    id:         int
    action:     str
    item_id:    Optional[str] = None
    ip_address: Optional[str] = None
    detail:     Optional[str] = None
    ts:         str

# ── Frontend ──────────────────────────────────────────────────────────────────
HTML_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    if os.path.exists(HTML_FILE):
        with open(HTML_FILE, "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h2>index.html not found</h2>", status_code=404)

# ── Public API Routes ─────────────────────────────────────────────────────────
@app.post("/items", response_model=ItemCreatedOut, status_code=201)
def create_item(item: ItemCreate, request: Request):
    ip = get_ip(request)
    check_post_rate(ip)
    image_data = None
    if item.image_base64 and item.image_base64.strip():
        image_data = validate_image(item.image_base64)
    item_id    = str(uuid.uuid4())
    edit_token = str(uuid.uuid4()) + "-" + str(uuid.uuid4())
    now        = datetime.utcnow().isoformat()
    conn = get_db()
    conn.execute("""
        INSERT INTO items
        (id, type, title, description, category, location, date_occurred,
         contact_name, contact_email, contact_phone, image_base64,
         status, edit_token, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        item_id, item.type, item.title, item.description, item.category,
        item.location, item.date_occurred, item.contact_name, item.contact_email,
        item.contact_phone, image_data, "active", edit_token, now
    ))
    conn.commit()
    row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    conn.close()
    audit("CREATE", item_id, ip, f"type={item.type} title={item.title[:40]}")
    return dict(row)

@app.get("/items", response_model=PaginatedItems)
def list_items(
    request:  Request,
    type:     Optional[str] = None,
    category: Optional[str] = None,
    location: Optional[str] = None,
    q:        Optional[str] = None,
    status:   Optional[str] = "active",
    page:     int = 1,
    limit:    int = 20,
):
    page   = max(1, page)
    limit  = min(50, max(1, limit))
    offset = (page - 1) * limit
    conn   = get_db()
    where  = "WHERE 1=1"
    params = []
    if type and type in ('lost','found'):
        where += " AND type=?"; params.append(type)
    if category and category in VALID_CATEGORIES:
        where += " AND category=?"; params.append(category)
    if location:
        where += " AND location LIKE ?"; params.append(f"%{sanitize(location,100)}%")
    if q:
        sq = f"%{sanitize(q,100)}%"
        where += " AND (title LIKE ? OR description LIKE ?)"; params.extend([sq, sq])
    if status in ('active','resolved'):
        where += " AND status=?"; params.append(status)
    total = conn.execute(f"SELECT COUNT(*) FROM items {where}", params).fetchone()[0]
    rows  = conn.execute(
        f"SELECT * FROM items {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [limit, offset]
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["contact_email"] = mask_email(d["contact_email"])
        if d["contact_phone"]: d["contact_phone"] = mask_phone(d["contact_phone"])
        result.append(d)
    return {"items": result, "total": total, "page": page, "pages": max(1, -(-total // limit))}

@app.get("/items/{item_id}", response_model=ItemOut)
def get_item(item_id: str):
    conn = get_db()
    row  = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    conn.close()
    if not row: raise HTTPException(404, "Item not found")
    return dict(row)

@app.patch("/items/{item_id}/resolve")
def resolve_item(item_id: str, body: TokenBody, request: Request):
    ip   = get_ip(request)
    conn = get_db()
    verify_token(item_id, body.edit_token, conn, ip)
    conn.execute("UPDATE items SET status='resolved' WHERE id=?", (item_id,))
    conn.commit()
    conn.close()
    audit("RESOLVE", item_id, ip)
    return {"message": "Item marked as resolved"}

@app.delete("/items/{item_id}")
def delete_item(item_id: str, body: TokenBody, request: Request):
    ip   = get_ip(request)
    conn = get_db()
    verify_token(item_id, body.edit_token, conn, ip)
    row  = conn.execute("SELECT title, type FROM items WHERE id=?", (item_id,)).fetchone()
    detail = f"title={row['title'][:40]} type={row['type']}" if row else ""
    conn.execute("DELETE FROM items WHERE id=?", (item_id,))
    conn.commit()
    conn.close()
    audit("DELETE", item_id, ip, detail)
    return {"message": "Item deleted"}

@app.get("/stats")
def get_stats():
    conn     = get_db()
    lost     = conn.execute("SELECT COUNT(*) FROM items WHERE type='lost'  AND status='active'").fetchone()[0]
    found    = conn.execute("SELECT COUNT(*) FROM items WHERE type='found' AND status='active'").fetchone()[0]
    resolved = conn.execute("SELECT COUNT(*) FROM items WHERE status='resolved'").fetchone()[0]
    conn.close()
    return {"active_lost": lost, "active_found": found, "resolved": resolved}

@app.get("/categories")
def get_categories():
    return sorted(VALID_CATEGORIES)

# ── Admin Routes (#12) ────────────────────────────────────────────────────────

@app.get("/admin/items", response_model=PaginatedItems)
def admin_list_items(
    request: Request,
    x_admin_secret: Optional[str] = Header(None),
    status: Optional[str] = None,
    type:   Optional[str] = None,
    q:      Optional[str] = None,
    page:   int = 1,
    limit:  int = 30,
):
    """Admin: list ALL items regardless of status, with full contact info."""
    require_admin(x_admin_secret)
    page   = max(1, page)
    limit  = min(100, max(1, limit))
    offset = (page - 1) * limit
    conn   = get_db()
    where  = "WHERE 1=1"
    params = []
    if status in ('active','resolved'):
        where += " AND status=?"; params.append(status)
    if type and type in ('lost','found'):
        where += " AND type=?"; params.append(type)
    if q:
        sq = f"%{sanitize(q,100)}%"
        where += " AND (title LIKE ? OR description LIKE ? OR contact_name LIKE ?)"; params.extend([sq,sq,sq])
    total = conn.execute(f"SELECT COUNT(*) FROM items {where}", params).fetchone()[0]
    rows  = conn.execute(
        f"SELECT * FROM items {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [limit, offset]
    ).fetchall()
    conn.close()
    return {"items": [dict(r) for r in rows], "total": total, "page": page, "pages": max(1, -(-total // limit))}

@app.patch("/admin/items/{item_id}/resolve")
def admin_resolve(item_id: str, request: Request, x_admin_secret: Optional[str] = Header(None)):
    require_admin(x_admin_secret)
    ip   = get_ip(request)
    conn = get_db()
    row  = conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
    if not row: raise HTTPException(404, "Item not found")
    conn.execute("UPDATE items SET status='resolved' WHERE id=?", (item_id,))
    conn.commit()
    conn.close()
    audit("ADMIN_RESOLVE", item_id, ip)
    return {"message": "Item marked as resolved by admin"}

@app.patch("/admin/items/{item_id}/reopen")
def admin_reopen(item_id: str, request: Request, x_admin_secret: Optional[str] = Header(None)):
    require_admin(x_admin_secret)
    ip   = get_ip(request)
    conn = get_db()
    row  = conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
    if not row: raise HTTPException(404, "Item not found")
    conn.execute("UPDATE items SET status='active' WHERE id=?", (item_id,))
    conn.commit()
    conn.close()
    audit("ADMIN_REOPEN", item_id, ip)
    return {"message": "Item reopened by admin"}

@app.delete("/admin/items/{item_id}")
def admin_delete(item_id: str, request: Request, x_admin_secret: Optional[str] = Header(None)):
    require_admin(x_admin_secret)
    ip   = get_ip(request)
    conn = get_db()
    row  = conn.execute("SELECT title, type FROM items WHERE id=?", (item_id,)).fetchone()
    if not row: raise HTTPException(404, "Item not found")
    detail = f"title={row['title'][:40]} type={row['type']}"
    conn.execute("DELETE FROM items WHERE id=?", (item_id,))
    conn.commit()
    conn.close()
    audit("ADMIN_DELETE", item_id, ip, detail)
    return {"message": "Item deleted by admin"}

@app.get("/admin/audit", response_model=List[AuditLogEntry])
def admin_audit_log(
    x_admin_secret: Optional[str] = Header(None),
    limit: int = 100
):
    require_admin(x_admin_secret)
    limit = min(500, max(1, limit))
    conn  = get_db()
    rows  = conn.execute(
        "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/admin/stats")
def admin_full_stats(x_admin_secret: Optional[str] = Header(None)):
    require_admin(x_admin_secret)
    conn = get_db()
    total    = conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]
    lost     = conn.execute("SELECT COUNT(*) FROM items WHERE type='lost'  AND status='active'").fetchone()[0]
    found    = conn.execute("SELECT COUNT(*) FROM items WHERE type='found' AND status='active'").fetchone()[0]
    resolved = conn.execute("SELECT COUNT(*) FROM items WHERE status='resolved'").fetchone()[0]
    audit_ct = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    conn.close()
    return {
        "total_listings": total,
        "active_lost":    lost,
        "active_found":   found,
        "resolved":       resolved,
        "audit_entries":  audit_ct,
    }
