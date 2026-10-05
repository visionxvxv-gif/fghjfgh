"""
Mysterious Key Server
FastAPI backend — handles key validation, HWID binding, and cloud configs.
Run with:  uvicorn server:app --host 0.0.0.0 --port 8000
"""

import os
import time
import secrets
import string
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import databases
import sqlalchemy
from dotenv import load_dotenv

load_dotenv()

# ── config ────────────────────────────────────────────────────────────────────
ADMIN_SECRET = os.environ["ADMIN_SECRET"]   # set in .env — keep it private
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./keys.db")

# ── database ──────────────────────────────────────────────────────────────────
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

keys_table = sqlalchemy.Table(
    "keys", metadata,
    sqlalchemy.Column("key",        sqlalchemy.String,  primary_key=True),
    sqlalchemy.Column("hwid",       sqlalchemy.String,  nullable=True),
    sqlalchemy.Column("note",       sqlalchemy.String,  nullable=True),   # e.g. discord username
    sqlalchemy.Column("created_at", sqlalchemy.Integer, nullable=False),
    sqlalchemy.Column("expires_at", sqlalchemy.Integer, nullable=True),   # None = lifetime
    sqlalchemy.Column("revoked",    sqlalchemy.Boolean, default=False),
)

configs_table = sqlalchemy.Table(
    "configs", metadata,
    sqlalchemy.Column("key",  sqlalchemy.String, nullable=False),
    sqlalchemy.Column("name", sqlalchemy.String, nullable=False),
    sqlalchemy.Column("data", sqlalchemy.Text,   nullable=False),
    sqlalchemy.UniqueConstraint("key", "name"),
)

engine = sqlalchemy.create_engine(
    DATABASE_URL.replace("sqlite:///", "sqlite:///"),
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
metadata.create_all(engine)

# ── app ───────────────────────────────────────────────────────────────────────
app = FastAPI(docs_url=None, redoc_url=None)   # hide docs in production

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# ── helpers ───────────────────────────────────────────────────────────────────
def generate_key() -> str:
    """Generate a key in the format MYST-XXXX-XXXX-XXXX-XXXX"""
    chars = string.ascii_uppercase + string.digits
    segments = ["".join(secrets.choice(chars) for _ in range(4)) for _ in range(4)]
    return "MYST-" + "-".join(segments)

def require_admin(x_admin_secret: Optional[str] = Header(None)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="forbidden")

# ── models ────────────────────────────────────────────────────────────────────
class ValidateRequest(BaseModel):
    key:  str
    hwid: str

class CreateKeyRequest(BaseModel):
    note:       Optional[str] = None   # e.g. "DiscordUser#1234"
    days:       Optional[int] = None   # None = lifetime key
    x_admin_secret: Optional[str] = None

class RevokeKeyRequest(BaseModel):
    key: str

class ResetHwidRequest(BaseModel):
    key: str

class ConfigSaveRequest(BaseModel):
    name: str
    data: dict

# ── routes — public ───────────────────────────────────────────────────────────
@app.post("/api/validate")
async def validate(req: ValidateRequest):
    row = await database.fetch_one(
        keys_table.select().where(keys_table.c.key == req.key)
    )

    if row is None:
        raise HTTPException(status_code=403, detail="invalid_key")

    if row["revoked"]:
        raise HTTPException(status_code=403, detail="revoked")

    if row["expires_at"] and int(time.time()) > row["expires_at"]:
        raise HTTPException(status_code=403, detail="expired")

    if row["hwid"] is None:
        # first auth — bind HWID
        await database.execute(
            keys_table.update()
                .where(keys_table.c.key == req.key)
                .values(hwid=req.hwid)
        )
    elif row["hwid"] != req.hwid:
        raise HTTPException(status_code=403, detail="hwid_mismatch")

    expires_in = None
    if row["expires_at"]:
        expires_in = row["expires_at"] - int(time.time())

    return {"valid": True, "expires_in": expires_in}

# ── routes — config ───────────────────────────────────────────────────────────
async def _get_validated_key(x_key: Optional[str]):
    """Shared auth check for config endpoints."""
    if not x_key:
        raise HTTPException(status_code=401, detail="missing key header")
    row = await database.fetch_one(
        keys_table.select().where(keys_table.c.key == x_key)
    )
    if not row or row["revoked"]:
        raise HTTPException(status_code=403, detail="invalid_key")
    if row["expires_at"] and int(time.time()) > row["expires_at"]:
        raise HTTPException(status_code=403, detail="expired")
    return x_key

@app.post("/api/config/save")
async def config_save(req: ConfigSaveRequest, x_key: Optional[str] = Header(None)):
    key = await _get_validated_key(x_key)
    import json
    data_str = json.dumps(req.data)

    # upsert
    existing = await database.fetch_one(
        configs_table.select()
            .where(configs_table.c.key == key)
            .where(configs_table.c.name == req.name)
    )
    if existing:
        await database.execute(
            configs_table.update()
                .where(configs_table.c.key == key)
                .where(configs_table.c.name == req.name)
                .values(data=data_str)
        )
    else:
        await database.execute(
            configs_table.insert().values(key=key, name=req.name, data=data_str)
        )
    return {"ok": True}

@app.get("/api/config/load")
async def config_load(name: str = "default", x_key: Optional[str] = Header(None)):
    key = await _get_validated_key(x_key)
    import json
    row = await database.fetch_one(
        configs_table.select()
            .where(configs_table.c.key == key)
            .where(configs_table.c.name == name)
    )
    if not row:
        raise HTTPException(status_code=404, detail="config_not_found")
    return json.loads(row["data"])

@app.get("/api/config/list")
async def config_list(x_key: Optional[str] = Header(None)):
    key = await _get_validated_key(x_key)
    rows = await database.fetch_all(
        configs_table.select().where(configs_table.c.key == key)
    )
    return {"configs": [r["name"] for r in rows]}

# ── routes — admin ────────────────────────────────────────────────────────────
@app.post("/api/admin/create_key")
async def admin_create_key(req: CreateKeyRequest, x_admin_secret: Optional[str] = Header(None)):
    require_admin(x_admin_secret)
    key = generate_key()
    expires_at = int(time.time()) + req.days * 86400 if req.days else None
    await database.execute(
        keys_table.insert().values(
            key=key,
            hwid=None,
            note=req.note,
            created_at=int(time.time()),
            expires_at=expires_at,
            revoked=False,
        )
    )
    return {"key": key, "expires_at": expires_at, "note": req.note}

@app.post("/api/admin/revoke_key")
async def admin_revoke_key(req: RevokeKeyRequest, x_admin_secret: Optional[str] = Header(None)):
    require_admin(x_admin_secret)
    result = await database.execute(
        keys_table.update()
            .where(keys_table.c.key == req.key)
            .values(revoked=True)
    )
    return {"ok": True}

@app.post("/api/admin/reset_hwid")
async def admin_reset_hwid(req: ResetHwidRequest, x_admin_secret: Optional[str] = Header(None)):
    require_admin(x_admin_secret)
    await database.execute(
        keys_table.update()
            .where(keys_table.c.key == req.key)
            .values(hwid=None)
    )
    return {"ok": True}

@app.get("/api/admin/list_keys")
async def admin_list_keys(x_admin_secret: Optional[str] = Header(None)):
    require_admin(x_admin_secret)
    rows = await database.fetch_all(keys_table.select())
    now = int(time.time())
    out = []
    for r in rows:
        expired = bool(r["expires_at"] and now > r["expires_at"])
        out.append({
            "key":        r["key"],
            "note":       r["note"],
            "hwid":       r["hwid"],
            "revoked":    r["revoked"],
            "expired":    expired,
            "expires_at": r["expires_at"],
            "created_at": r["created_at"],
        })
    return {"keys": out}

@app.get("/api/admin/key_info")
async def admin_key_info(key: str, x_admin_secret: Optional[str] = Header(None)):
    require_admin(x_admin_secret)
    row = await database.fetch_one(
        keys_table.select().where(keys_table.c.key == key)
    )
    if not row:
        raise HTTPException(status_code=404, detail="not_found")
    now = int(time.time())
    configs = await database.fetch_all(
        configs_table.select().where(configs_table.c.key == key)
    )
    return {
        "key":        row["key"],
        "note":       row["note"],
        "hwid":       row["hwid"],
        "revoked":    row["revoked"],
        "expired":    bool(row["expires_at"] and now > row["expires_at"]),
        "expires_at": row["expires_at"],
        "created_at": row["created_at"],
        "configs":    [c["name"] for c in configs],
    }
