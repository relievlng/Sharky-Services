#!/usr/bin/env python3
"""
XZX / Sharky Services — Delivery Bot (single process).

Flow:
  buyer -> /login -> Discord OAuth -> /callback (verify, mint signed claim, redirect to checkout)
        -> Stripe Checkout (claim + product in metadata)
        -> Stripe checkout.session.completed -> /stripe (verify Stripe sig, extract claim+product)
        -> internal deliver(): resolve claim -> Discord ID -> generate key -> DM key + file
           (file attached if small, signed expiring download link if large)

Everything logs to a rotating file and a Discord log channel.
"""

import os
import io
import base64
import asyncio
import sqlite3
import secrets
import string
import hmac
import hashlib
import time
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime, timezone, timedelta

import discord
from discord import app_commands
from discord.ext import commands
import aiohttp
from aiohttp import web

# ===================== Config =====================
TOKEN = os.environ.get("DISCORD_TOKEN")
GUILD_ID = int(os.environ.get("GUILD_ID", "0"))
ADMIN_ROLE = os.environ.get("ADMIN_ROLE", "Staff")
DB_PATH = os.environ.get("DB_PATH", "licenses.db")
PRODUCTS_DIR = Path(os.environ.get("PRODUCTS_DIR", "products"))
KEY_PREFIX = os.environ.get("KEY_PREFIX", "SS")

LOG_CHANNEL_ID = int(os.environ.get("LOG_CHANNEL_ID", "0"))
LOG_FILE = os.environ.get("LOG_FILE", "xzx-delivery.log")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# HTTP
HTTP_HOST = os.environ.get("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.environ.get("PORT", os.environ.get("HTTP_PORT", "8080")))
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "")   # e.g. https://xzx.yourdomain.com

# File delivery
ATTACH_LIMIT_BYTES = int(os.environ.get("ATTACH_LIMIT_BYTES", str(24 * 1024 * 1024)))
LINK_SECRET = os.environ.get("LINK_SECRET", secrets.token_hex(32))
LINK_TTL = int(os.environ.get("LINK_TTL", "3600"))

# OAuth2
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")
OAUTH_REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "")   # https://xzx.yourdomain.com/callback
OAUTH_STATE_SECRET = os.environ.get("OAUTH_STATE_SECRET", secrets.token_hex(32))
DISCORD_API = "https://discord.com/api"

# Checkout handoff
STORE_CHECKOUT_URL = os.environ.get("STORE_CHECKOUT_URL", "")
CLAIM_TTL = int(os.environ.get("CLAIM_TTL", "1800"))

# Stripe
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")  # whsec_...
STRIPE_SIG_TOLERANCE = int(os.environ.get("STRIPE_SIG_TOLERANCE", "300"))

# Branding / tickets
LOGO_URL = os.environ.get(
    "LOGO_URL",
    "https://cdn.discordapp.com/avatars/1567155897011015700/a2d69d6a45d15b27cc05a1b78f4f0b4a.png?size=512",
)
BRAND_NAME = os.environ.get("BRAND_NAME", "Sharky Services")
BRAND_COLOR = int(os.environ.get("BRAND_COLOR", "0x2b2d31"), 16)
TICKET_CATEGORY_ID = int(os.environ.get("TICKET_CATEGORY_ID", "0"))  # optional category for tickets

# License verification API (your macros POST their key here to check validity)
VERIFY_API_KEY = os.environ.get("VERIFY_API_KEY", "")  # if set, callers must send it as X-Api-Key
HWID_LOCK = os.environ.get("HWID_LOCK", "1") != "0"    # bind each key to the first machine that uses it

# Subscription durations (days). None = lifetime / never expires.
DURATIONS = {
    "day":      1,
    "week":     7,
    "month":    30,
    "lifetime": None,
}

# Products are stored in the database and managed with /product add|remove|list.
# Files live in PRODUCTS_DIR. Nothing is hardcoded — the owner adds their own.

LOG_COLORS = {
    "key_generated":  0x5865F2,
    "linked":         0x5865F2,
    "log_setup":      0x57F287,
    "ticket_open":    0x5865F2,
    "ticket_claim":   0x5865F2,
    "ticket_close":   0xFEE75C,
    "delivered":      0x57F287,
    "delivered_link": 0x57F287,
    "delivered_chan": 0x57F287,
    "closed_dms":     0xFEE75C,
    "key_revoked":    0xED4245,
    "key_unrevoked":  0x57F287,
    "hwid_reset":     0x5865F2,
    "verify_ok":      0x57F287,
    "verify_fail":    0xFEE75C,
    "failed":         0xED4245,
    "webhook_reject": 0xED4245,
    # server logs
    "member_join":    0x57F287,
    "member_leave":   0xE67E22,
    "member_ban":     0xED4245,
    "member_unban":   0x57F287,
    "msg_delete":     0xED4245,
    "msg_edit":       0xFEE75C,
    "role_change":    0x5865F2,
    "channel_change": 0x5865F2,
    "nick_change":    0x5865F2,
    "automod":        0xED4245,
    "mod_action":     0xE67E22,
    "warn":           0xFEE75C,
}

# Which saved log channel each event goes to. Missing -> general feed.
LOG_ROUTES = {
    # shop / purchase feed
    "key_generated": "log_shop", "delivered": "log_shop", "delivered_link": "log_shop",
    "delivered_chan": "log_shop", "closed_dms": "log_shop", "webhook_reject": "log_shop",
    # license-key feed
    "verify_ok": "log_key", "verify_fail": "log_key", "key_revoked": "log_key",
    "key_unrevoked": "log_key", "hwid_reset": "log_key",
    # server feed
    "member_join": "log_server", "member_leave": "log_server", "member_ban": "log_server",
    "member_unban": "log_server", "msg_delete": "log_server", "msg_edit": "log_server",
    "role_change": "log_server", "channel_change": "log_server", "nick_change": "log_server",
    "automod": "log_server", "mod_action": "log_server", "warn": "log_server",
}

# ===================== Logging =====================
log = logging.getLogger("xzx-delivery")
log.setLevel(LOG_LEVEL)
_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
_fh = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
_fh.setFormatter(_fmt); log.addHandler(_fh)
_ch = logging.StreamHandler(); _ch.setFormatter(_fmt); log.addHandler(_ch)

# ===================== Database =====================
def db_init():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key         TEXT PRIMARY KEY,
            product     TEXT NOT NULL,
            discord_id  INTEGER,
            created_at  TEXT NOT NULL,
            redeemed    INTEGER DEFAULT 0
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS links (
            discord_id  INTEGER PRIMARY KEY,
            username    TEXT,
            linked_at   TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            number      INTEGER PRIMARY KEY,
            channel_id  INTEGER,
            opener_id   INTEGER,
            invoice_id  TEXT,
            status      TEXT DEFAULT 'open',
            created_at  TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS purchases (
            invoice_id  TEXT PRIMARY KEY,
            discord_id  INTEGER,
            product     TEXT,
            key         TEXT,
            source      TEXT,
            stripe_ref  TEXT,
            created_at  TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS products (
            name         TEXT PRIMARY KEY,
            display_name TEXT,
            filename     TEXT,
            price_id     TEXT,
            created_at   TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS warnings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id    INTEGER,
            user_id     INTEGER,
            mod_id      INTEGER,
            reason      TEXT,
            created_at  TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS plans (
            plan_key     TEXT PRIMARY KEY,
            product      TEXT,
            duration     TEXT,
            payment_link TEXT,
            label        TEXT,
            created_at   TEXT NOT NULL
        )
    """)
    # Migration-safe column adds for existing databases.
    existing = {r[1] for r in con.execute("PRAGMA table_info(licenses)").fetchall()}
    if "hwid" not in existing:
        con.execute("ALTER TABLE licenses ADD COLUMN hwid TEXT")
    if "revoked" not in existing:
        con.execute("ALTER TABLE licenses ADD COLUMN revoked INTEGER DEFAULT 0")
    if "last_used_at" not in existing:
        con.execute("ALTER TABLE licenses ADD COLUMN last_used_at TEXT")
    if "expires_at" not in existing:
        con.execute("ALTER TABLE licenses ADD COLUMN expires_at TEXT")
    if "duration" not in existing:
        con.execute("ALTER TABLE licenses ADD COLUMN duration TEXT DEFAULT 'lifetime'")
    tcols = {r[1] for r in con.execute("PRAGMA table_info(tickets)").fetchall()}
    if "claimed_by" not in tcols:
        con.execute("ALTER TABLE tickets ADD COLUMN claimed_by INTEGER")
    con.commit(); con.close()


def generate_key(product: str, duration: str = "lifetime") -> str:
    now = datetime.now(timezone.utc)
    days = DURATIONS.get(duration)
    expires_at = (now + timedelta(days=days)).isoformat() if days else None
    con = sqlite3.connect(DB_PATH)
    try:
        for _ in range(10):
            body = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
            key = f"{KEY_PREFIX}-{product[:4].upper()}-{body[:4]}-{body[4:8]}-{body[8:12]}-{body[12:]}"
            try:
                con.execute(
                    "INSERT INTO licenses (key, product, created_at, duration, expires_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (key, product, now.isoformat(), duration, expires_at))
                con.commit()
                return key
            except sqlite3.IntegrityError:
                continue
        raise RuntimeError("Could not generate a unique key after 10 attempts")
    finally:
        con.close()


def human_expiry(row: dict) -> str:
    """Readable expiry for a license row."""
    exp = row.get("expires_at")
    if not exp:
        return "Lifetime"
    try:
        dt = datetime.fromisoformat(exp)
    except ValueError:
        return "Lifetime"
    if dt < datetime.now(timezone.utc):
        return "Expired"
    return dt.strftime("%Y-%m-%d")


def bind_key(key: str, discord_id: int):
    con = sqlite3.connect(DB_PATH)
    con.execute("UPDATE licenses SET discord_id = ? WHERE key = ?", (discord_id, key))
    con.commit(); con.close()


def get_key(key: str):
    """Return the license row as a dict, or None."""
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM licenses WHERE key = ?", (key,)).fetchone()
    con.close()
    return dict(row) if row else None


def keys_for_user(discord_id: int):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT * FROM licenses WHERE discord_id = ? ORDER BY created_at DESC", (discord_id,)
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def set_key_revoked(key: str, revoked: bool) -> bool:
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("UPDATE licenses SET revoked = ? WHERE key = ?", (1 if revoked else 0, key))
    con.commit(); changed = cur.rowcount; con.close()
    return changed > 0


def reset_key_hwid(key: str) -> bool:
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("UPDATE licenses SET hwid = NULL WHERE key = ?", (key,))
    con.commit(); changed = cur.rowcount; con.close()
    return changed > 0


def verify_key(key: str, hwid: str = None):
    """
    Validate a key for the macros. Returns (ok: bool, product|None, reason).
    Binds the HWID on first use when HWID_LOCK is on; rejects a mismatch after that.
    """
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM licenses WHERE key = ?", (key,)).fetchone()
    if row is None:
        con.close()
        return False, None, "invalid_key"
    row = dict(row)
    if row.get("revoked"):
        con.close()
        return False, row["product"], "revoked"

    exp = row.get("expires_at")
    if exp:
        try:
            if datetime.fromisoformat(exp) < datetime.now(timezone.utc):
                con.close()
                return False, row["product"], "expired"
        except ValueError:
            pass

    if HWID_LOCK and hwid:
        bound = row.get("hwid")
        if not bound:
            con.execute("UPDATE licenses SET hwid = ? WHERE key = ?", (hwid, key))
        elif bound != hwid:
            con.close()
            return False, row["product"], "hwid_mismatch"

    con.execute("UPDATE licenses SET last_used_at = ? WHERE key = ?",
                (datetime.now(timezone.utc).isoformat(), key))
    con.commit(); con.close()
    return True, row["product"], "ok"


# ----- Purchases / invoices (ties an invoice to the Discord buyer) -----
def generate_invoice_id() -> str:
    """A short, human-typable invoice id unique in the purchases table."""
    con = sqlite3.connect(DB_PATH)
    try:
        for _ in range(12):
            body = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8))
            inv = f"INV-{body[:4]}-{body[4:]}"
            exists = con.execute("SELECT 1 FROM purchases WHERE invoice_id = ?", (inv,)).fetchone()
            if not exists:
                return inv
        raise RuntimeError("Could not generate a unique invoice id")
    finally:
        con.close()


def record_purchase(invoice_id: str, discord_id: int, product: str, key: str,
                    source: str, stripe_ref: str = None):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT OR REPLACE INTO purchases "
        "(invoice_id, discord_id, product, key, source, stripe_ref, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (invoice_id, discord_id, product, key, source, stripe_ref,
         datetime.now(timezone.utc).isoformat()),
    )
    con.commit(); con.close()


def get_purchase(invoice_id: str):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM purchases WHERE invoice_id = ?",
                      (invoice_id.strip(),)).fetchone()
    con.close()
    return dict(row) if row else None


def invoice_for_key(key: str):
    con = sqlite3.connect(DB_PATH)
    row = con.execute(
        "SELECT invoice_id FROM purchases WHERE key = ? ORDER BY created_at DESC LIMIT 1",
        (key,)).fetchone()
    con.close()
    return row[0] if row else None


def verify_invoice(invoice_id: str, discord_id: int):
    """
    Check an invoice entered at ticket time.
    Returns (status, purchase|None) where status is one of:
      'ok'        - exists and belongs to this Discord user
      'not_found' - no such invoice
      'mismatch'  - exists but was bought by a different Discord user
    """
    p = get_purchase(invoice_id)
    if p is None:
        return "not_found", None
    if p.get("discord_id") and int(p["discord_id"]) != int(discord_id):
        return "mismatch", p
    return "ok", p


def check_key_for_ticket(key: str, discord_id: int):
    """
    Verify a license key entered at ticket time.
    Returns (status, row|None):
      'ok'        - real key, belongs to this user (or unbound)
      'revoked'   - real key but revoked (still their key)
      'mismatch'  - real key bound to a different user
      'not_found' - no such key
    """
    row = get_key((key or "").strip())
    if row is None:
        return "not_found", None
    if row.get("discord_id") and int(row["discord_id"]) != int(discord_id):
        return "mismatch", row
    if row.get("revoked"):
        return "revoked", row
    return "ok", row


# ----- Products (owner-managed; nothing hardcoded) -----
def add_product(name: str, display_name: str, filename: str, price_id: str = None):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT OR REPLACE INTO products (name, display_name, filename, price_id, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (name, display_name, filename, price_id, datetime.now(timezone.utc).isoformat()),
    )
    con.commit(); con.close()


def remove_product(name: str) -> bool:
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("DELETE FROM products WHERE name = ?", (name,))
    con.commit(); changed = cur.rowcount; con.close()
    return changed > 0


def get_product(name: str):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM products WHERE name = ?", (name,)).fetchone()
    con.close()
    return dict(row) if row else None


def list_products():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM products ORDER BY name").fetchall()
    con.close()
    return [dict(r) for r in rows]


def product_by_price_id(price_id: str):
    if not price_id:
        return None
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT name FROM products WHERE price_id = ?", (price_id,)).fetchone()
    con.close()
    return row[0] if row else None


def product_file_path(name: str):
    p = get_product(name)
    if not p or not p.get("filename"):
        return None
    return PRODUCTS_DIR / p["filename"]


def slugify_product(name: str) -> str:
    out = "".join(c.lower() if c.isalnum() else "_" for c in name).strip("_")
    while "__" in out:
        out = out.replace("__", "_")
    return out or "product"


# ----- Plans (a purchase option: product + duration + Stripe payment link) -----
def add_plan(plan_key: str, product: str, duration: str, payment_link: str, label: str = None):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT OR REPLACE INTO plans (plan_key, product, duration, payment_link, label, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (plan_key, product, duration, payment_link, label or plan_key.title(),
         datetime.now(timezone.utc).isoformat()),
    )
    con.commit(); con.close()


def get_plan(plan_key: str):
    if not plan_key:
        return None
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM plans WHERE plan_key = ?", (plan_key,)).fetchone()
    con.close()
    return dict(row) if row else None


def list_plans():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM plans ORDER BY created_at").fetchall()
    con.close()
    return [dict(r) for r in rows]


def remove_plan(plan_key: str) -> bool:
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("DELETE FROM plans WHERE plan_key = ?", (plan_key,))
    con.commit(); changed = cur.rowcount; con.close()
    return changed > 0


def slugify_plan(name: str) -> str:
    out = "".join(c.lower() if (c.isalnum() or c == "-") else "" for c in (name or ""))[:40]
    return out


def save_link(discord_id: int, username: str):
    con = sqlite3.connect(DB_PATH)
    con.execute("INSERT OR REPLACE INTO links (discord_id, username, linked_at) VALUES (?, ?, ?)",
                (discord_id, username, datetime.now(timezone.utc).isoformat()))
    con.commit(); con.close()


def is_linked(discord_id: int) -> bool:
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT 1 FROM links WHERE discord_id = ?", (discord_id,)).fetchone()
    con.close()
    return row is not None


def get_setting(key: str):
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    con.close()
    return row[0] if row else None


def set_setting(key: str, value: str):
    con = sqlite3.connect(DB_PATH)
    con.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    con.commit(); con.close()


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def resolve_log_channel_id(event: str = None):
    """
    Pick the log channel for an event: the specific feed (server/key/shop) if set,
    else the general feed (/setup logs), else the LOG_CHANNEL_ID env var.
    """
    route_key = LOG_ROUTES.get(event) if event else None
    if route_key:
        cid = _as_int(get_setting(route_key))
        if cid:
            return cid
    cid = _as_int(get_setting("log_channel_id"))
    if cid:
        return cid
    return LOG_CHANNEL_ID or None


def resolve_ticket_category(guild):
    """Ticket category from /setup, else the TICKET_CATEGORY_ID env var."""
    cid = _as_int(get_setting("ticket_category")) or (TICKET_CATEGORY_ID or None)
    cat = guild.get_channel(cid) if cid else None
    return cat if isinstance(cat, discord.CategoryChannel) else None


def resolve_staff_role(guild):
    """The configured staff role (/setup staffrole), else a role named ADMIN_ROLE."""
    rid = _as_int(get_setting("staff_role_id"))
    role = guild.get_role(rid) if rid else None
    return role or discord.utils.get(guild.roles, name=ADMIN_ROLE)


def is_staff(interaction: discord.Interaction) -> bool:
    """Server owner, anyone with Administrator/Manage Server, ADMIN_ROLE, or the configured staff role."""
    member = interaction.user
    guild = interaction.guild
    if guild is not None and member.id == guild.owner_id:
        return True
    perms = getattr(member, "guild_permissions", None)
    if perms is not None and (perms.administrator or perms.manage_guild):
        return True
    member_roles = getattr(member, "roles", [])
    if ADMIN_ROLE in [r.name for r in member_roles]:
        return True
    rid = _as_int(get_setting("staff_role_id"))
    return bool(rid) and any(r.id == rid for r in member_roles)


def member_is_staff(member: discord.Member) -> bool:
    """Staff check for a Member object (automod exemption)."""
    guild = getattr(member, "guild", None)
    if guild is not None and member.id == guild.owner_id:
        return True
    perms = getattr(member, "guild_permissions", None)
    if perms is not None and (perms.administrator or perms.manage_guild or perms.manage_messages):
        return True
    roles = getattr(member, "roles", [])
    if ADMIN_ROLE in [r.name for r in roles]:
        return True
    rid = _as_int(get_setting("staff_role_id"))
    return bool(rid) and any(r.id == rid for r in roles)


def brand_embed(title: str, description: str = None, color: int = None) -> discord.Embed:
    """A dark, clean embed branded with the logo as a circular icon (no big white image)."""
    e = discord.Embed(title=title, description=description,
                      color=color if color is not None else BRAND_COLOR,
                      timestamp=datetime.now(timezone.utc))
    e.set_author(name=BRAND_NAME, icon_url=LOGO_URL)
    e.set_footer(text=BRAND_NAME, icon_url=LOGO_URL)
    return e


def next_ticket_number() -> int:
    n = int(get_setting("ticket_counter") or "0") + 1
    set_setting("ticket_counter", str(n))
    return n


def record_ticket(number: int, channel_id: int, opener_id: int, invoice_id: str):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT OR REPLACE INTO tickets (number, channel_id, opener_id, invoice_id, status, created_at) "
        "VALUES (?, ?, ?, ?, 'open', ?)",
        (number, channel_id, opener_id, invoice_id, datetime.now(timezone.utc).isoformat()),
    )
    con.commit(); con.close()


def close_ticket_record(channel_id: int):
    con = sqlite3.connect(DB_PATH)
    con.execute("UPDATE tickets SET status = 'closed' WHERE channel_id = ?", (channel_id,))
    con.commit(); con.close()


def open_ticket_for(opener_id: int):
    """Return (number, channel_id) of this user's open ticket, or None."""
    con = sqlite3.connect(DB_PATH)
    row = con.execute(
        "SELECT number, channel_id FROM tickets WHERE opener_id = ? AND status = 'open' "
        "ORDER BY number DESC LIMIT 1", (opener_id,)
    ).fetchone()
    con.close()
    return row


def set_ticket_claimed(channel_id: int, staff_id: int):
    con = sqlite3.connect(DB_PATH)
    con.execute("UPDATE tickets SET claimed_by = ? WHERE channel_id = ?", (staff_id, channel_id))
    con.commit(); con.close()


def ticket_opener(channel_id: int):
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT opener_id FROM tickets WHERE channel_id = ?", (channel_id,)).fetchone()
    con.close()
    return row[0] if row else None


def add_warning(guild_id: int, user_id: int, mod_id: int, reason: str) -> int:
    con = sqlite3.connect(DB_PATH)
    cur = con.execute(
        "INSERT INTO warnings (guild_id, user_id, mod_id, reason, created_at) VALUES (?, ?, ?, ?, ?)",
        (guild_id, user_id, mod_id, reason, datetime.now(timezone.utc).isoformat()))
    con.commit()
    count = con.execute("SELECT COUNT(*) FROM warnings WHERE guild_id=? AND user_id=?",
                        (guild_id, user_id)).fetchone()[0]
    con.close()
    return count


def list_warnings(guild_id: int, user_id: int):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT * FROM warnings WHERE guild_id=? AND user_id=? ORDER BY id DESC",
        (guild_id, user_id)).fetchall()
    con.close()
    return [dict(r) for r in rows]


def clear_warnings(guild_id: int, user_id: int) -> int:
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("DELETE FROM warnings WHERE guild_id=? AND user_id=?", (guild_id, user_id))
    con.commit(); n = cur.rowcount; con.close()
    return n


# ===================== Signed tokens (links / state / claims) =====================
def _sign(secret: str, msg: str) -> str:
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def make_download_url(product: str) -> str:
    exp = int(time.time()) + LINK_TTL
    sig = _sign(LINK_SECRET, f"{product}:{exp}")
    return f"{PUBLIC_BASE_URL.rstrip('/')}/dl/{product}?e={exp}&s={sig}"


def verify_link(product: str, expires: str, sig: str) -> bool:
    try:
        exp = int(expires)
    except (TypeError, ValueError):
        return False
    if exp < int(time.time()):
        return False
    return hmac.compare_digest(_sign(LINK_SECRET, f"{product}:{exp}"), sig or "")


def make_state(plan: str = "") -> str:
    nonce = secrets.token_urlsafe(16); ts = str(int(time.time()))
    sig = _sign(OAUTH_STATE_SECRET, f"{nonce}:{ts}:{plan}")
    return f"{nonce}.{ts}.{plan}.{sig}"


def verify_state(state: str, max_age: int = 600):
    """Return the plan string (possibly empty) if valid, else None."""
    try:
        nonce, ts, plan, sig = state.split(".")
    except (ValueError, AttributeError):
        return None
    if int(time.time()) - int(ts) > max_age:
        return None
    if not hmac.compare_digest(_sign(OAUTH_STATE_SECRET, f"{nonce}:{ts}:{plan}"), sig):
        return None
    return plan


def mint_claim(discord_id: int, plan: str = "") -> str:
    """URL/Stripe-safe signed token carrying the Discord ID and chosen plan."""
    exp = int(time.time()) + CLAIM_TTL
    body = f"{discord_id}:{exp}:{plan}"
    sig = _sign(OAUTH_STATE_SECRET, body)
    raw = f"{body}:{sig}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def verify_claim(token: str):
    """Return (discord_id, plan) if valid, else None."""
    try:
        pad = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token + pad).decode()
        did, exp, plan, sig = raw.split(":")
    except Exception:
        return None
    if int(time.time()) > int(exp):
        return None
    if not hmac.compare_digest(_sign(OAUTH_STATE_SECRET, f"{did}:{exp}:{plan}"), sig):
        return None
    return int(did), plan


# ===================== Bot =====================
# Server logs (joins/leaves, message edits/deletes) need privileged intents.
# These are OFF by default so the bot can never crash on boot. To turn them on:
#   1) set SERVER_LOGS=1 in Railway
#   2) enable "Server Members Intent" and "Message Content Intent" in the
#      Discord Developer Portal -> your app -> Bot.
SERVER_LOGS = os.environ.get("SERVER_LOGS", "0") != "0"
intents = discord.Intents.default()
if SERVER_LOGS:
    intents.members = True
    intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)


async def log_event(event: str, *, user=None, product=None, key=None, detail=None):
    parts = [f"event={event}"]
    if user:    parts.append(f"user={user} ({getattr(user, 'id', '?')})")
    if product: parts.append(f"product={product}")
    if key:     parts.append(f"key={key}")
    if detail:  parts.append(f"detail={detail}")
    (log.error if event in ("failed", "webhook_reject") else log.info)(" ".join(parts))

    channel_id = resolve_log_channel_id(event)
    if not channel_id:
        return
    channel = bot.get_channel(channel_id)
    if channel is None:
        log.error("Log channel %s not found", channel_id); return
    embed = discord.Embed(title=f"Log — {event.replace('_', ' ').title()}",
                          color=LOG_COLORS.get(event, 0x2b2d31),
                          timestamp=datetime.now(timezone.utc))
    if user and hasattr(user, "mention"):
        embed.add_field(name="User", value=f"{user.mention} (`{user.id}`)", inline=False)
    elif user:
        embed.add_field(name="User", value=f"`{getattr(user, 'id', user)}`", inline=False)
    if product: embed.add_field(name="Product", value=product, inline=True)
    if key:     embed.add_field(name="Key", value=f"`{key}`", inline=False)
    if detail:  embed.add_field(name="Detail", value=detail, inline=False)
    try:
        await channel.send(embed=embed)
    except discord.HTTPException as e:
        log.error("Could not post to log channel: %s", e)


async def deliver(user: discord.abc.User, product: str,
                  source: str = "manual", stripe_ref: str = None,
                  duration: str = "lifetime") -> tuple[bool, str]:
    prod = get_product(product)
    if prod is None:
        await log_event("failed", user=user, product=product, detail="unknown product")
        return False, f"Unknown product: {product}"
    if duration not in DURATIONS:
        duration = "lifetime"
    # Website purchases must be OAuth-verified. Staff deliveries are trusted and
    # always DM, even if the recipient never linked their account.
    if source == "stripe" and not is_linked(user.id):
        await log_event("failed", user=user, product=product, detail="not linked via oauth")
        return False, "buyer has not linked their Discord account"

    file_path = PRODUCTS_DIR / prod["filename"]
    if not file_path.exists():
        await log_event("failed", user=user, product=product, detail="file missing on disk")
        return False, f"Product file not found for {product}"

    key = generate_key(product, duration)
    bind_key(key, user.id)
    invoice_id = generate_invoice_id()
    record_purchase(invoice_id, user.id, product, key, source, stripe_ref)
    await log_event("key_generated", user=user, product=product, key=key,
                    detail=f"invoice {invoice_id} • {duration}")

    size = file_path.stat().st_size
    use_link = size > ATTACH_LIMIT_BYTES
    if use_link and not PUBLIC_BASE_URL:
        await log_event("failed", user=user, product=product, key=key,
                        detail=f"file {size}B over limit, PUBLIC_BASE_URL unset")
        return False, "file too large and no download host configured"

    title = prod.get("display_name") or product.replace("_", " ").title()

    plan_label = "Lifetime" if duration == "lifetime" else f"1 {duration}"

    def build_embed() -> discord.Embed:
        e = brand_embed("Purchase Delivered",
                        f"Thanks for buying **{title}**. Keep your key private — one key, one user.")
        e.add_field(name="Invoice ID", value=f"`{invoice_id}`", inline=True)
        e.add_field(name="Product", value=title, inline=True)
        e.add_field(name="Plan", value=plan_label, inline=True)
        e.add_field(name="License Key", value=f"```{key}```", inline=False)
        if use_link:
            e.add_field(name="Download",
                        value=f"[Download {file_path.name}]({make_download_url(product)})\n"
                              f"Link expires in {LINK_TTL // 60} min.", inline=False)
        else:
            e.add_field(name="File", value=file_path.name, inline=False)
        return e

    async def send_to(dest, content=None):
        if use_link:
            await dest.send(content=content, embed=build_embed())
        else:
            await dest.send(content=content, embed=build_embed(), file=discord.File(file_path))

    # 1) Try the DM.
    try:
        await send_to(user)
        await log_event("delivered" if not use_link else "delivered_link",
                        user=user, product=product, key=key, detail=f"invoice {invoice_id}")
        return True, key
    except discord.Forbidden:
        pass  # DMs closed — fall through to channel delivery
    except discord.HTTPException as e:
        await log_event("failed", user=user, product=product, key=key, detail=str(e))
        return False, f"send_failed: {e}"

    # 2) DMs are closed: deliver into a private channel so the paid buyer still gets it.
    guild = bot.get_guild(GUILD_ID) if GUILD_ID else None
    member = guild.get_member(user.id) if guild else None
    if guild is None or member is None:
        await log_event("closed_dms", user=user, product=product, key=key,
                        detail="DMs closed and buyer not reachable in the server")
        return False, "closed_dms"

    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        member: discord.PermissionOverwrite(view_channel=True, read_message_history=True),
        guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, manage_channels=True),
    }
    staff_role = resolve_staff_role(guild)
    if staff_role:
        overwrites[staff_role] = discord.PermissionOverwrite(view_channel=True, send_messages=True)
    category = resolve_ticket_category(guild)

    try:
        channel = await guild.create_text_channel(
            name=f"delivery-{invoice_id.split('-')[-1].lower()}",
            overwrites=overwrites, category=category,
            topic=f"Delivery for {member} • Invoice {invoice_id}",
            reason="Buyer has DMs closed; delivering in a private channel",
        )
        await send_to(channel, content=f"{member.mention} your DMs are closed, so here's your order:")
        await log_event("delivered_chan", user=user, product=product, key=key,
                        detail=f"invoice {invoice_id} in #{channel.name}")
        return True, key
    except discord.Forbidden:
        await log_event("closed_dms", user=user, product=product, key=key,
                        detail="DMs closed and no Manage Channels permission for fallback")
        return False, "closed_dms"
    except discord.HTTPException as e:
        await log_event("failed", user=user, product=product, key=key, detail=str(e))
        return False, f"send_failed: {e}"


async def product_autocomplete(interaction: discord.Interaction, current: str):
    current = (current or "").lower()
    return [
        app_commands.Choice(name=p["display_name"] or p["name"], value=p["name"])
        for p in list_products()
        if current in p["name"].lower() or current in (p["display_name"] or "").lower()
    ][:25]


# ---- Slash command: manual delivery ----
@bot.tree.command(name="deliver", description="Deliver a product + key to a buyer (staff only).")
@app_commands.describe(member="Who bought it", product="Which product")
@app_commands.autocomplete(product=product_autocomplete)
async def deliver_cmd(interaction: discord.Interaction, member: discord.Member, product: str):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True); return
    if get_product(product) is None:
        await interaction.response.send_message(
            f"No product named `{product}`. Add it with `/product add`.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    ok, result = await deliver(member, product, source="manual")
    if ok:
        await interaction.followup.send(
            f"Delivered **{product}** to {member.mention}. Key: `{result}`", ephemeral=True)
    elif result == "closed_dms":
        await interaction.followup.send(
            f"{member.mention} has DMs closed and couldn't be reached. Key + invoice saved.", ephemeral=True)
    else:
        await interaction.followup.send(f"Failed: {result}", ephemeral=True)


# ---- Slash command: stats ----
@bot.tree.command(description="Show keys issued and deliveries per product (staff only).")
async def stats(interaction: discord.Interaction):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)

    con = sqlite3.connect(DB_PATH)
    try:
        per_product = con.execute(
            "SELECT product, COUNT(*), COUNT(discord_id) "
            "FROM licenses GROUP BY product ORDER BY COUNT(*) DESC"
        ).fetchall()
        total_keys = con.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
        total_linked = con.execute("SELECT COUNT(*) FROM links").fetchone()[0]
    finally:
        con.close()

    embed = discord.Embed(title="Stats", color=0x5865F2, timestamp=datetime.now(timezone.utc))
    if per_product:
        lines = "\n".join(
            f"**{p.replace('_', ' ').title()}** — {total} keys ({bound} delivered)"
            for p, total, bound in per_product
        )
        embed.add_field(name="Per Product", value=lines, inline=False)
    else:
        embed.add_field(name="Per Product", value="No keys issued yet.", inline=False)
    embed.add_field(name="Total Keys", value=str(total_keys), inline=True)
    embed.add_field(name="Linked Accounts", value=str(total_linked), inline=True)
    await interaction.followup.send(embed=embed, ephemeral=True)


# ---- Slash command group: /setup ----
setup_group = app_commands.Group(name="setup", description="Bot setup commands (staff only).")


@setup_group.command(name="logs", description="Use the current channel for the bot's log feed.")
async def setup_logs(interaction: discord.Interaction):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    channel = interaction.channel
    if channel is None:
        await interaction.response.send_message(
            "Run this inside the text channel you want logs in.", ephemeral=True)
        return
    set_setting("log_channel_id", str(channel.id))
    await interaction.response.send_message(
        f"Done. Logs will now post in {channel.mention}. "
        f"This overrides the LOG_CHANNEL_ID variable, so you don't need to set it.",
        ephemeral=True)
    # Post a confirmation entry into the newly chosen channel as a live test.
    await log_event("log_setup",
                    detail=f"Log channel set to #{getattr(channel, 'name', channel.id)} "
                           f"by {interaction.user}")


@setup_group.command(name="status", description="Show what's configured and what's still missing.")
async def setup_status(interaction: discord.Interaction):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return

    def feed(key, label):
        cid = _as_int(get_setting(key))
        return f"**{label}:** {'<#' + str(cid) + '>' if cid else 'not set'}"

    cat_id = _as_int(get_setting("ticket_category"))
    staff_rid = _as_int(get_setting("staff_role_id"))
    lines = [
        f"**Staff role:** {'<@&' + str(staff_rid) + '>' if staff_rid else 'role named ' + ADMIN_ROLE}",
        feed("log_server", "Server logs"),
        feed("log_key", "Key logs"),
        feed("log_shop", "Shop logs"),
        feed("log_channel_id", "General logs"),
        f"**Ticket category:** {'set' if cat_id else 'not set'}",
        f"**Products:** {len(list_products())} added",
        f"**OAuth login:** {'configured' if OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET else 'not set'}",
        f"**Public URL:** {PUBLIC_BASE_URL or 'not set'}",
        f"**Stripe payments:** {'configured' if STRIPE_WEBHOOK_SECRET else 'not set (optional)'}",
        f"**Server logs intent:** {'on' if SERVER_LOGS else 'off (set SERVER_LOGS=1)'}",
    ]
    embed = brand_embed("Setup Status", "\n".join(lines))
    await interaction.response.send_message(embed=embed, ephemeral=True)


@setup_group.command(name="all",
                     description="One-click: create every log channel, a tickets area, and the panel.")
async def setup_all(interaction: discord.Interaction):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message("Run this in a server.", ephemeral=True)
        return
    if not guild.me.guild_permissions.manage_channels:
        await interaction.response.send_message(
            "I need the **Manage Channels** permission first, then run this again.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)

    staff_role = resolve_staff_role(guild)
    staff_view = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True),
    }
    if staff_role:
        staff_view[staff_role] = discord.PermissionOverwrite(view_channel=True)

    created = []
    try:
        logs_cat = await guild.create_category("\N{CLIPBOARD} Sharky Logs", overwrites=staff_view)
        feeds = {
            "log_server": await guild.create_text_channel("server-logs", category=logs_cat, overwrites=staff_view),
            "log_key":    await guild.create_text_channel("key-logs", category=logs_cat, overwrites=staff_view),
            "log_shop":   await guild.create_text_channel("shop-logs", category=logs_cat, overwrites=staff_view),
            "log_channel_id": await guild.create_text_channel("bot-logs", category=logs_cat, overwrites=staff_view),
        }
        for setting_key, ch in feeds.items():
            set_setting(setting_key, str(ch.id))
            created.append(ch)

        tickets_cat = await guild.create_category("\N{ADMISSION TICKETS} Tickets")
        set_setting("ticket_category", str(tickets_cat.id))
        support_view = {
            guild.default_role: discord.PermissionOverwrite(view_channel=True, send_messages=False),
            guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True),
        }
        support_ch = await guild.create_text_channel("support", category=tickets_cat, overwrites=support_view)
        await support_ch.send(embed=ticket_panel_embed(), view=TicketLauncher())
        created.append(support_ch)
    except discord.Forbidden:
        await interaction.followup.send(
            "I ran out of permissions partway through. Make sure I have **Manage Channels** "
            "and try again.", ephemeral=True)
        return
    except discord.HTTPException as e:
        await interaction.followup.send(f"Something went wrong creating channels: {e}", ephemeral=True)
        return

    body = "\n".join(f"• {c.mention}" for c in created)
    await interaction.followup.send(
        f"**Setup complete!** Everything's wired automatically:\n{body}\n\n"
        f"Server, key, and shop logs now route to their own channels. "
        f"Next: add products with `/product add`.", ephemeral=True)
    await log_event("log_setup", user=interaction.user, detail="ran /setup all")


@setup_group.command(name="staffrole",
                     description="Set the staff role that sees tickets and gets pinged on new ones.")
@app_commands.describe(role="The role to treat as staff")
async def setup_staffrole(interaction: discord.Interaction, role: discord.Role):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    set_setting("staff_role_id", str(role.id))
    await interaction.response.send_message(
        f"Staff role set to {role.mention}. They'll be added to new tickets and pinged when one opens.",
        ephemeral=True)


@setup_group.command(name="automod", description="Toggle automod: invite links, spam, and mass mentions.")
@app_commands.describe(invites="Delete Discord invite links",
                       spam="Timeout users sending messages too fast",
                       mentions="Delete + timeout mass-mention messages")
async def setup_automod(interaction: discord.Interaction, invites: bool = None,
                        spam: bool = None, mentions: bool = None):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    changed = []
    for name, val in (("automod_invites", invites), ("automod_spam", spam), ("automod_mentions", mentions)):
        if val is not None:
            set_setting(name, "1" if val else "0")
            changed.append(f"{name.split('_')[1]} {'on' if val else 'off'}")
    if not changed:
        state = {n: get_setting("automod_" + n) == "1"
                 for n in ("invites", "spam", "mentions")}
        lines = "\n".join(f"**{k.title()}:** {'on' if v else 'off'}" for k, v in state.items())
        await interaction.response.send_message(embed=brand_embed("Automod", lines), ephemeral=True)
        return
    note = "" if SERVER_LOGS else ("\n\N{WARNING SIGN} Invite/spam filters need message content: set "
                                   "`SERVER_LOGS=1` and enable the **Message Content Intent**.")
    await interaction.response.send_message("Automod updated: " + ", ".join(changed) + note, ephemeral=True)


@setup_group.command(name="welcome", description="Set the welcome channel and message for new members.")
@app_commands.describe(channel="Where to post welcomes",
                       message="Message. Use {user} {server} {count}. Leave blank for a default.",
                       also_dm="Also DM the new member (default no)")
async def setup_welcome(interaction: discord.Interaction, channel: discord.TextChannel,
                        message: str = None, also_dm: bool = False):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    set_setting("welcome_channel_id", str(channel.id))
    if message:
        set_setting("welcome_message", message)
    set_setting("welcome_dm", "1" if also_dm else "0")
    note = "" if SERVER_LOGS else ("\n\N{WARNING SIGN} Set `SERVER_LOGS=1` and enable the "
                                   "**Server Members Intent** so the bot sees joins.")
    await interaction.response.send_message(
        f"Welcomes will post in {channel.mention}{' and DM new members' if also_dm else ''}.{note}",
        ephemeral=True)


@setup_group.command(name="verify", description="Post a verification panel; the button grants a role.")
@app_commands.describe(role="Role to give when someone verifies")
async def setup_verify(interaction: discord.Interaction, role: discord.Role):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    if role >= interaction.guild.me.top_role:
        await interaction.response.send_message(
            "That role is above my highest role, so I can't assign it. Move my bot role above it first.",
            ephemeral=True)
        return
    set_setting("verified_role_id", str(role.id))
    embed = brand_embed(
        "\N{WHITE HEAVY CHECK MARK} Verification",
        f"Click the button below to verify and unlock the rest of the server. "
        f"You'll get the {role.mention} role.")
    await interaction.channel.send(embed=embed, view=VerifyView())
    await interaction.response.send_message(
        f"Verification panel posted. Verified members get {role.mention}.", ephemeral=True)


@setup_group.command(name="tickets", description="Post the support ticket panel in this channel.")
async def setup_tickets(interaction: discord.Interaction):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    await interaction.channel.send(embed=ticket_panel_embed(), view=TicketLauncher())
    await interaction.response.send_message("Ticket panel posted.", ephemeral=True)


bot.tree.add_command(setup_group)


# ===================== Product management =====================
product_group = app_commands.Group(name="product", description="Manage products (staff only).")


@product_group.command(name="add", description="Add a product and upload its file.")
@app_commands.describe(name="Short internal name", file="The file buyers receive",
                       display_name="Nice name shown to buyers (optional)",
                       price_id="Stripe price id, e.g. price_123 (optional)")
async def product_add(interaction: discord.Interaction, name: str, file: discord.Attachment,
                      display_name: str = None, price_id: str = None):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    slug = slugify_product(name)
    PRODUCTS_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = f"{slug}_{file.filename}".replace("/", "_").replace("\\", "_")
    try:
        await file.save(PRODUCTS_DIR / safe_name)
    except Exception as e:
        await interaction.followup.send(f"Couldn't save the file: {e}", ephemeral=True)
        return
    add_product(slug, display_name or name, safe_name, price_id)
    await interaction.followup.send(
        f"Added **{display_name or name}** as `{slug}` ({file.filename}, "
        f"{file.size // 1024} KB).\nUse this name in `/deliver` and as `product` in Stripe metadata.",
        ephemeral=True)


@product_group.command(name="remove", description="Remove a product.")
@app_commands.autocomplete(name=product_autocomplete)
async def product_remove(interaction: discord.Interaction, name: str):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    prod = get_product(name)
    if prod and prod.get("filename"):
        try:
            (PRODUCTS_DIR / prod["filename"]).unlink(missing_ok=True)
        except OSError:
            pass
    ok = remove_product(name)
    await interaction.response.send_message(
        f"Removed `{name}`." if ok else f"No product named `{name}`.", ephemeral=True)


@product_group.command(name="list", description="List all products.")
async def product_list(interaction: discord.Interaction):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    prods = list_products()
    if not prods:
        await interaction.response.send_message(
            "No products yet. Add one with `/product add`.", ephemeral=True)
        return
    lines = []
    for p in prods:
        price = f" • `{p['price_id']}`" if p.get("price_id") else ""
        lines.append(f"**{p['display_name'] or p['name']}** — `{p['name']}` ({p['filename']}){price}")
    await interaction.response.send_message(
        embed=brand_embed("Products", "\n".join(lines)), ephemeral=True)


bot.tree.add_command(product_group)


# ===================== Plans (purchase options) =====================
plan_group = app_commands.Group(name="plan", description="Manage purchase plans (staff only).")


async def plan_autocomplete(interaction: discord.Interaction, current: str):
    current = (current or "").lower()
    return [app_commands.Choice(name=p["plan_key"], value=p["plan_key"])
            for p in list_plans() if current in p["plan_key"].lower()][:25]


@plan_group.command(name="add", description="Add a purchase plan linked to a Stripe payment link.")
@app_commands.describe(key="Short plan key, e.g. day", product="Which product this plan delivers",
                       duration="Access length", payment_link="The Stripe payment link URL",
                       label="Nice label shown to buyers (optional)")
@app_commands.autocomplete(product=product_autocomplete)
@app_commands.choices(duration=[app_commands.Choice(name=d, value=d) for d in DURATIONS])
async def plan_add(interaction: discord.Interaction, key: str, product: str,
                   duration: app_commands.Choice[str], payment_link: str, label: str = None):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    plan_key = slugify_plan(key)
    if not plan_key:
        await interaction.response.send_message("Give the plan a simple key like `day`.", ephemeral=True)
        return
    if get_product(product) is None:
        await interaction.response.send_message(
            f"No product named `{product}`. Add it with `/product add` first.", ephemeral=True)
        return
    if not payment_link.startswith("https://"):
        await interaction.response.send_message("The payment link should be a full https URL.", ephemeral=True)
        return
    add_plan(plan_key, product, duration.value, payment_link, label)
    base = PUBLIC_BASE_URL.rstrip("/") if PUBLIC_BASE_URL else ""
    await interaction.response.send_message(
        f"Added plan **{label or plan_key}** (`{plan_key}`): {duration.value} of **{product}**.\n"
        f"Link your buy button to `{base}/buy?plan={plan_key}`.", ephemeral=True)


@plan_group.command(name="list", description="List all purchase plans.")
async def plan_list(interaction: discord.Interaction):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    plans = list_plans()
    if not plans:
        await interaction.response.send_message("No plans yet. Add one with `/plan add`.", ephemeral=True)
        return
    lines = [f"**{p['label'] or p['plan_key']}** (`{p['plan_key']}`) — {p['duration']} of `{p['product']}`"
             for p in plans]
    await interaction.response.send_message(
        embed=brand_embed("Plans", "\n".join(lines)), ephemeral=True)


@plan_group.command(name="remove", description="Remove a purchase plan.")
@app_commands.autocomplete(key=plan_autocomplete)
async def plan_remove(interaction: discord.Interaction, key: str):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    ok = remove_plan(slugify_plan(key))
    await interaction.response.send_message(
        f"Removed plan `{key}`." if ok else f"No plan named `{key}`.", ephemeral=True)


bot.tree.add_command(plan_group)


# ===================== Key management =====================
async def send_existing_key(user: discord.abc.User, row: dict) -> tuple[bool, str]:
    """Re-send an existing key + file to its owner (used by /key resend)."""
    prod = get_product(row["product"])
    if not prod:
        return False, "product no longer exists"
    key = row["key"]
    fp = PRODUCTS_DIR / prod["filename"]
    e = brand_embed("Your License",
                    f"Here's your **{prod.get('display_name') or row['product']}** again. "
                    f"Keep your key private — one key, one user.")
    inv = invoice_for_key(key)
    if inv:
        e.add_field(name="Invoice ID", value=f"`{inv}`", inline=True)
    e.add_field(name="Product", value=prod.get("display_name") or row["product"], inline=True)
    e.add_field(name="License Key", value=f"```{key}```", inline=False)
    try:
        if fp.exists() and fp.stat().st_size <= ATTACH_LIMIT_BYTES:
            await user.send(embed=e, file=discord.File(fp))
        elif fp.exists() and PUBLIC_BASE_URL:
            e.add_field(name="Download",
                        value=f"[Download {fp.name}]({make_download_url(row['product'])})", inline=False)
            await user.send(embed=e)
        else:
            await user.send(embed=e)
        return True, "ok"
    except discord.Forbidden:
        return False, "closed_dms"
    except discord.HTTPException as ex:
        return False, str(ex)


key_group = app_commands.Group(name="key", description="Manage license keys (staff only).")


@key_group.command(name="lookup", description="Look up a license key.")
async def key_lookup(interaction: discord.Interaction, key: str):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    row = get_key(key.strip())
    if not row:
        await interaction.response.send_message("No such key.", ephemeral=True)
        return
    owner = f"<@{row['discord_id']}>" if row.get("discord_id") else "unbound"
    e = brand_embed("Key Lookup")
    e.add_field(name="Key", value=f"`{row['key']}`", inline=False)
    e.add_field(name="Product", value=row.get("product") or "—", inline=True)
    e.add_field(name="Owner", value=owner, inline=True)
    e.add_field(name="Revoked", value="yes" if row.get("revoked") else "no", inline=True)
    e.add_field(name="HWID", value=f"`{row['hwid']}`" if row.get("hwid") else "not bound", inline=False)
    e.add_field(name="Last used", value=(row.get("last_used_at") or "never")[:19], inline=True)
    await interaction.response.send_message(embed=e, ephemeral=True)


@key_group.command(name="revoke", description="Revoke a key so it stops validating.")
async def key_revoke(interaction: discord.Interaction, key: str):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    ok = set_key_revoked(key.strip(), True)
    if ok:
        await log_event("key_revoked", user=interaction.user, key=key.strip())
    await interaction.response.send_message(
        f"Revoked `{key}`." if ok else "No such key.", ephemeral=True)


@key_group.command(name="unrevoke", description="Re-enable a revoked key.")
async def key_unrevoke(interaction: discord.Interaction, key: str):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    ok = set_key_revoked(key.strip(), False)
    if ok:
        await log_event("key_unrevoked", user=interaction.user, key=key.strip())
    await interaction.response.send_message(
        f"Re-enabled `{key}`." if ok else "No such key.", ephemeral=True)


@key_group.command(name="resethwid", description="Clear a key's machine lock so it can be used on a new PC.")
async def key_resethwid(interaction: discord.Interaction, key: str):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    ok = reset_key_hwid(key.strip())
    if ok:
        await log_event("hwid_reset", user=interaction.user, key=key.strip())
    await interaction.response.send_message(
        f"Reset the machine lock on `{key}`." if ok else "No such key.", ephemeral=True)


@key_group.command(name="resend", description="Re-send a key and its file to the buyer's DMs.")
async def key_resend(interaction: discord.Interaction, key: str):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    row = get_key(key.strip())
    if not row:
        await interaction.response.send_message("No such key.", ephemeral=True)
        return
    if not row.get("discord_id"):
        await interaction.response.send_message("That key isn't bound to a user.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    try:
        user = await bot.fetch_user(int(row["discord_id"]))
    except discord.HTTPException:
        await interaction.followup.send("Couldn't find that user.", ephemeral=True)
        return
    ok, reason = await send_existing_key(user, row)
    await interaction.followup.send(
        f"Re-sent to {user.mention}." if ok else f"Couldn't send: {reason}", ephemeral=True)


@key_group.command(name="generate", description="Generate a key for a product, bound to a member.")
@app_commands.describe(member="Who the key is for", product="Which product",
                       duration="Plan length", dm="DM the key + file to them (default yes)")
@app_commands.autocomplete(product=product_autocomplete)
@app_commands.choices(duration=[app_commands.Choice(name=d, value=d) for d in DURATIONS])
async def key_generate(interaction: discord.Interaction, member: discord.Member,
                       product: str, duration: app_commands.Choice[str] = None, dm: bool = True):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    if get_product(product) is None:
        await interaction.response.send_message(
            f"No product named `{product}`. Add it with `/product add`.", ephemeral=True)
        return
    dur = duration.value if duration else "lifetime"
    await interaction.response.defer(ephemeral=True)
    key = generate_key(product, dur)
    bind_key(key, member.id)
    invoice_id = generate_invoice_id()
    record_purchase(invoice_id, member.id, product, key, "admin")
    await log_event("key_generated", user=member, product=product, key=key,
                    detail=f"admin-issued by {interaction.user} • invoice {invoice_id} • {dur}")
    sent = ""
    if dm:
        ok, reason = await send_existing_key(member, get_key(key))
        sent = "\n\N{WHITE HEAVY CHECK MARK} DMed to them." if ok else f"\n\N{WARNING SIGN} DM failed: {reason}"
    plan = "Lifetime" if dur == "lifetime" else f"1 {dur}"
    await interaction.followup.send(
        f"Generated a **{product}** key ({plan}) bound to {member.mention}:\n`{key}`\n"
        f"Invoice: `{invoice_id}`{sent}", ephemeral=True)


bot.tree.add_command(key_group)


@bot.tree.command(name="keys", description="List a member's license keys (staff only).")
@app_commands.describe(member="Whose keys to list")
async def keys_cmd(interaction: discord.Interaction, member: discord.Member):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True)
        return
    rows = keys_for_user(member.id)
    if not rows:
        await interaction.response.send_message(f"{member.mention} has no keys.", ephemeral=True)
        return
    lines = []
    for r in rows:
        flags = " \N{CROSS MARK} revoked" if r.get("revoked") else ""
        lines.append(f"`{r['key']}` — {r.get('product') or '—'}{flags}")
    await interaction.response.send_message(
        embed=brand_embed(f"Keys for {member.display_name}", "\n".join(lines[:25])), ephemeral=True)


@bot.tree.command(name="help", description="Show what this bot can do.")
async def help_cmd(interaction: discord.Interaction):
    staff = is_staff(interaction)
    e = brand_embed(f"{BRAND_NAME} — Help",
                    "Buy from the website and the bot DMs you your product and license key. "
                    "Open a ticket for support using your invoice ID.")
    e.add_field(name="Everyone",
                value="`/help` — this menu", inline=False)
    if staff:
        e.add_field(
            name="Setup (staff)",
            value="`/setup all` — create all log channels, a tickets area, and the panel\n"
                  "`/setup logs` — use the current channel for logs\n"
                  "`/setup staffrole` — set the staff role that's pinged on tickets\n"
                  "`/setup tickets` — post a ticket panel here\n"
                  "`/setup status` — what's configured", inline=False)
        e.add_field(
            name="Products & delivery (staff)",
            value="`/product add` — add a product + file\n"
                  "`/product list` · `/product remove`\n"
                  "`/plan add` — link a Stripe payment link to a product + duration\n"
                  "`/plan list` · `/plan remove`\n"
                  "`/deliver` — manually deliver to a buyer\n"
                  "`/stats` — sales stats", inline=False)
        e.add_field(
            name="Keys (staff)",
            value="`/key generate` — issue a key bound to a member\n"
                  "`/key lookup` · `/key revoke` · `/key unrevoke`\n"
                  "`/key resethwid` · `/key resend` · `/keys @user`", inline=False)
    await interaction.response.send_message(embed=e, ephemeral=True)


# ===================== Ticket system =====================
# Ticket topics shown as buttons on the panel.
TICKET_TOPICS = {
    "sharky_tkt_key":   ("Key Support", "\N{KEY}", "Key Support"),
    "sharky_tkt_macro": ("Macro Support", "\N{VIDEO GAME}", "Macro Support"),
    "sharky_tkt_other": ("Other", "\N{SPEECH BALLOON}", "Other"),
}


class TicketModal(discord.ui.Modal):
    license_key = discord.ui.TextInput(
        label="License Key",
        placeholder="Your license key (e.g. SS-....) — we'll check it's legit",
        required=False, max_length=120,
    )
    invoice_id = discord.ui.TextInput(
        label="Invoice ID (optional)",
        placeholder="The invoice ID from your purchase (e.g. INV-XXXX-XXXX)",
        required=False, max_length=120,
    )
    issue = discord.ui.TextInput(
        label="What do you need help with?",
        style=discord.TextStyle.paragraph,
        required=False, max_length=1000,
    )

    def __init__(self, topic: str = "Support"):
        super().__init__(title=f"Open a Ticket — {topic}"[:45])
        self.topic = topic

    async def on_submit(self, interaction: discord.Interaction):
        await create_ticket(interaction, str(self.invoice_id), str(self.issue),
                            self.topic, str(self.license_key))


class TicketLauncher(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
        for cid, (label, emoji, topic) in TICKET_TOPICS.items():
            self.add_item(TicketTopicButton(cid, label, emoji, topic))


class TicketTopicButton(discord.ui.Button):
    def __init__(self, custom_id: str, label: str, emoji: str, topic: str):
        super().__init__(label=label, emoji=emoji,
                         style=discord.ButtonStyle.secondary, custom_id=custom_id)
        self.topic = topic

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.send_modal(TicketModal(self.topic))


def ticket_panel_embed() -> discord.Embed:
    return brand_embed(
        "\N{ADMISSION TICKETS} Support",
        "Need a hand? Pick the topic that fits and we'll open a private ticket for you.\n\n"
        "\N{KEY} **Key Support** — key not working or machine-locked\n"
        "\N{VIDEO GAME} **Macro Support** — help with the macro itself\n"
        "\N{SPEECH BALLOON} **Other** — anything else\n\n"
        "You'll be asked for your **license key** so we can check it's legit. "
        "One open ticket at a time.",
    )


# ===================== Welcome + verification =====================
def format_welcome(template: str, member: discord.Member) -> str:
    t = template or "Welcome {user} to **{server}**! You're member #{count}. \N{WAVING HAND SIGN}"
    return (t.replace("{user}", member.mention)
             .replace("{server}", member.guild.name)
             .replace("{count}", str(member.guild.member_count or "")))


async def send_welcome(member: discord.Member):
    if member.bot:
        return
    wid = _as_int(get_setting("welcome_channel_id"))
    channel = bot.get_channel(wid) if wid else None
    if channel:
        try:
            e = brand_embed(f"Welcome, {member.display_name}!",
                            format_welcome(get_setting("welcome_message"), member))
            e.set_thumbnail(url=member.display_avatar.url)
            await channel.send(content=member.mention, embed=e)
        except discord.HTTPException:
            pass
    if get_setting("welcome_dm") == "1":
        try:
            await member.send(embed=brand_embed(
                f"Welcome to {member.guild.name}!",
                format_welcome(get_setting("welcome_message"), member)))
        except discord.HTTPException:
            pass


class VerifyView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Verify", style=discord.ButtonStyle.success,
                       emoji="\N{WHITE HEAVY CHECK MARK}", custom_id="sharky_verify")
    async def verify(self, interaction: discord.Interaction, button: discord.ui.Button):
        rid = _as_int(get_setting("verified_role_id"))
        role = interaction.guild.get_role(rid) if rid else None
        if role is None:
            await interaction.response.send_message(
                "Verification isn't set up yet. Ask an admin to run `/setup verify`.", ephemeral=True)
            return
        if role in interaction.user.roles:
            await interaction.response.send_message("You're already verified. \N{WHITE HEAVY CHECK MARK}",
                                                    ephemeral=True)
            return
        try:
            await interaction.user.add_roles(role, reason="Verified via button")
            await interaction.response.send_message(
                f"You're verified — welcome in! {role.mention}", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message(
                "I couldn't add the role. My role needs to be **above** the verified role and have "
                "**Manage Roles**.", ephemeral=True)


class TicketControls(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Claim", style=discord.ButtonStyle.success,
                       emoji="\N{RAISED HAND}", custom_id="sharky_claim_ticket")
    async def claim(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not is_staff(interaction):
            await interaction.response.send_message("Only staff can claim tickets.", ephemeral=True)
            return
        set_ticket_claimed(interaction.channel.id, interaction.user.id)
        await log_event("ticket_claim", user=interaction.user,
                        detail=f"#{getattr(interaction.channel, 'name', '')}")
        await interaction.response.send_message(
            f"\N{RAISED HAND} Ticket claimed by {interaction.user.mention}.")

    @discord.ui.button(label="Close", style=discord.ButtonStyle.danger,
                       emoji="\N{LOCK}", custom_id="sharky_close_ticket")
    async def close(self, interaction: discord.Interaction, button: discord.ui.Button):
        channel = interaction.channel
        opener_id = ticket_opener(channel.id)
        if not (is_staff(interaction) or interaction.user.id == opener_id):
            await interaction.response.send_message(
                "Only staff or the ticket opener can close this.", ephemeral=True)
            return
        await interaction.response.send_message("Saving transcript and closing in 5 seconds…")
        await save_ticket_transcript(channel)
        close_ticket_record(channel.id)
        await log_event("ticket_close", user=interaction.user,
                        detail=f"closed #{getattr(channel, 'name', channel.id)}")
        await asyncio.sleep(5)
        try:
            await channel.delete(reason=f"Ticket closed by {interaction.user}")
        except discord.HTTPException as e:
            log.error("Failed to delete ticket channel %s: %s", channel.id, e)


async def save_ticket_transcript(channel):
    """Build a plain-text transcript and post it to the log feed before deletion."""
    try:
        lines = []
        async for m in channel.history(limit=1000, oldest_first=True):
            ts = m.created_at.strftime("%Y-%m-%d %H:%M")
            content = m.content or ("[embed]" if m.embeds else "")
            if m.attachments:
                content += " [" + ", ".join(a.filename for a in m.attachments) + "]"
            lines.append(f"[{ts}] {m.author}: {content}")
        text = "\n".join(lines) or "(no messages)"
    except discord.HTTPException:
        text = "(could not read channel history)"
    log_id = resolve_log_channel_id("ticket_close")
    ch = bot.get_channel(log_id) if log_id else None
    if ch:
        e = brand_embed("Ticket Transcript",
                        f"Transcript for **{getattr(channel, 'name', channel.id)}**.")
        try:
            await ch.send(embed=e, file=discord.File(io.BytesIO(text.encode()),
                                                     filename=f"{getattr(channel,'name','ticket')}.txt"))
        except discord.HTTPException as ex:
            log.error("Could not post transcript: %s", ex)


async def create_ticket(interaction: discord.Interaction, invoice_id: str, issue: str,
                        topic: str = "Support", license_key: str = ""):
    guild = interaction.guild
    opener = interaction.user
    if guild is None:
        await interaction.response.send_message("Tickets can only be opened in a server.", ephemeral=True)
        return

    # One open ticket per user.
    existing = open_ticket_for(opener.id)
    if existing:
        ch = guild.get_channel(existing[1])
        if ch:
            await interaction.response.send_message(
                f"You already have an open ticket: {ch.mention}", ephemeral=True)
            return
        close_ticket_record(existing[1])  # stale record; channel was deleted

    license_key = (license_key or "").strip()
    invoice_id = (invoice_id or "").strip()
    if not license_key and not invoice_id:
        await interaction.response.send_message(
            "Please enter your **license key** (or invoice ID) so we can verify your purchase.",
            ephemeral=True)
        return

    # Verify the license key — must be a real key, and yours.
    key_line = None
    purchase = {}
    if license_key:
        kstatus, krow = check_key_for_ticket(license_key, opener.id)
        if kstatus == "not_found":
            await interaction.response.send_message(
                "That license key isn't recognised. Check it and try again.", ephemeral=True)
            await log_event("verify_fail", user=opener, detail=f"ticket key not found: {license_key}")
            return
        if kstatus == "mismatch":
            await interaction.response.send_message(
                "That key belongs to a different account — you can only open a ticket for your own key.",
                ephemeral=True)
            await log_event("verify_fail", user=opener, detail=f"ticket key mismatch: {license_key}")
            return
        if kstatus == "revoked":
            key_line = f"`{license_key}` \N{WARNING SIGN} legit but **revoked**"
        else:
            key_line = f"`{license_key}` \N{WHITE HEAVY CHECK MARK} legit key"
        purchase = {"product": krow.get("product")}
        await log_event("verify_ok", user=opener, key=license_key,
                        product=krow.get("product"), detail="ticket key verified")

    # Optional invoice check (if they gave one).
    invoice_line = None
    if invoice_id:
        istatus, ipur = verify_invoice(invoice_id, opener.id)
        if istatus == "mismatch":
            await interaction.response.send_message(
                "That invoice belongs to a different account.", ephemeral=True)
            return
        if istatus == "ok":
            invoice_line = f"`{invoice_id}` \N{WHITE HEAVY CHECK MARK} verified"
            purchase = ipur
        else:
            invoice_line = f"`{invoice_id}` \N{WARNING SIGN} not found"

    number = next_ticket_number()
    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        opener: discord.PermissionOverwrite(view_channel=True, send_messages=True, attach_files=True),
        guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, manage_channels=True),
    }
    staff_role = resolve_staff_role(guild)
    if staff_role:
        overwrites[staff_role] = discord.PermissionOverwrite(view_channel=True, send_messages=True)

    category = resolve_ticket_category(guild)

    uname = "".join(c for c in opener.name.lower() if c.isalnum() or c == "-")[:24] or "user"

    try:
        channel = await guild.create_text_channel(
            name=f"ticket-{number:04d}-{uname}",
            overwrites=overwrites,
            category=category,
            topic=f"Ticket #{number} • {opener} • {topic}",
            reason=f"Support ticket opened by {opener}",
        )
    except discord.Forbidden:
        await interaction.response.send_message(
            "I don't have permission to create channels. Give me the **Manage Channels** permission.",
            ephemeral=True)
        return

    record_ticket(number, channel.id, opener.id, invoice_id or license_key)

    prod = get_product(purchase.get("product") or "")
    product_label = (prod or {}).get("display_name") or purchase.get("product") or "—"
    embed = brand_embed(
        f"Ticket #{number:04d} — {topic}",
        f"Thanks {opener.mention} — a staff member will be with you shortly.",
    )
    embed.add_field(name="Topic", value=topic, inline=True)
    embed.add_field(name="Product", value=product_label, inline=True)
    if key_line:
        embed.add_field(name="License Key", value=key_line, inline=False)
    if invoice_line:
        embed.add_field(name="Invoice", value=invoice_line, inline=False)
    if issue.strip():
        embed.add_field(name="Issue", value=issue[:1024], inline=False)

    ping = opener.mention + (f" {staff_role.mention}" if staff_role else "")
    await channel.send(content=ping, embed=embed, view=TicketControls())
    await interaction.response.send_message(f"Ticket created: {channel.mention}", ephemeral=True)
    await log_event("ticket_open", user=opener,
                    detail=f"#{channel.name} • {topic} • key={license_key or '-'}")


# ===================== Server logs (joins, leaves, edits, deletes, bans) =====================
@bot.event
async def on_member_join(member: discord.Member):
    await log_event("member_join", user=member,
                    detail=f"Account created {discord.utils.format_dt(member.created_at, 'R')}")
    await send_welcome(member)


@bot.event
async def on_member_remove(member: discord.Member):
    roles = [r.name for r in getattr(member, "roles", []) if r.name != "@everyone"]
    await log_event("member_leave", user=member,
                    detail="Roles: " + (", ".join(roles) if roles else "none"))


@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.abc.User):
    await log_event("member_ban", user=user, detail=f"Banned from {guild.name}")


@bot.event
async def on_member_unban(guild: discord.Guild, user: discord.abc.User):
    await log_event("member_unban", user=user, detail=f"Unbanned from {guild.name}")


@bot.event
async def on_message_delete(message: discord.Message):
    if message.author.bot or message.guild is None:
        return
    content = (message.content or "").strip() or "*(no text / attachment only)*"
    await log_event("msg_delete", user=message.author,
                    detail=f"In {message.channel.mention}:\n{content[:1000]}")


@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message):
    if after.author.bot or after.guild is None or before.content == after.content:
        return
    await log_event("msg_edit", user=after.author,
                    detail=f"In {after.channel.mention}\n**Before:** {(before.content or '')[:450]}\n"
                           f"**After:** {(after.content or '')[:450]}")


@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    if before.nick != after.nick:
        await log_event("nick_change", user=after,
                        detail=f"`{before.nick or before.name}` → `{after.nick or after.name}`")
    else:
        b, a = set(before.roles), set(after.roles)
        added = [r.name for r in a - b]
        removed = [r.name for r in b - a]
        if added or removed:
            parts = []
            if added:   parts.append("➕ " + ", ".join(added))
            if removed: parts.append("➖ " + ", ".join(removed))
            await log_event("role_change", user=after, detail=" • ".join(parts))


# ===================== HTTP handlers =====================
async def handle_login(request):
    if not OAUTH_CLIENT_ID or not OAUTH_REDIRECT_URI:
        return web.Response(status=500, text="OAuth not configured")
    plan = slugify_plan(request.query.get("plan", ""))
    params = (f"client_id={OAUTH_CLIENT_ID}&redirect_uri={OAUTH_REDIRECT_URI}"
              f"&response_type=code&scope=identify&state={make_state(plan)}&prompt=consent")
    raise web.HTTPFound(f"{DISCORD_API}/oauth2/authorize?{params}")


async def handle_callback(request):
    if request.query.get("error"):
        return web.Response(status=400, text=f"Authorization cancelled: {request.query['error']}")
    code, state = request.query.get("code"), request.query.get("state")
    plan_key = verify_state(state)
    if not code or plan_key is None:
        await log_event("webhook_reject", detail="oauth: bad code/state")
        return web.Response(status=400, text="Invalid or expired login. Please try again.")

    data = {"client_id": OAUTH_CLIENT_ID, "client_secret": OAUTH_CLIENT_SECRET,
            "grant_type": "authorization_code", "code": code, "redirect_uri": OAUTH_REDIRECT_URI}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    async with aiohttp.ClientSession() as session:
        async with session.post(f"{DISCORD_API}/oauth2/token", data=data, headers=headers) as r:
            if r.status != 200:
                await log_event("failed", detail=f"oauth token exchange {r.status}")
                return web.Response(status=502, text="Login failed at token exchange.")
            token = await r.json()
        async with session.get(f"{DISCORD_API}/users/@me",
                               headers={"Authorization": f"Bearer {token['access_token']}"}) as r:
            if r.status != 200:
                await log_event("failed", detail=f"oauth identity fetch {r.status}")
                return web.Response(status=502, text="Login failed reading your profile.")
            me = await r.json()

    discord_id = int(me["id"]); username = me.get("username", "unknown")
    save_link(discord_id, username)
    await log_event("linked", user=await bot.fetch_user(discord_id), detail="account linked via oauth")

    claim = mint_claim(discord_id, plan_key)

    # Buying a plan: send them to that plan's Stripe payment link with the claim attached.
    plan = get_plan(plan_key) if plan_key else None
    if plan_key and plan and plan.get("payment_link"):
        url = plan["payment_link"]
        sep = "&" if "?" in url else "?"
        raise web.HTTPFound(f"{url}{sep}client_reference_id={claim}")
    if plan_key and not plan:
        return web.Response(
            text=f"Linked as {username}. That plan isn't set up yet — contact support.",
            content_type="text/plain")

    # Legacy custom checkout (optional).
    if STORE_CHECKOUT_URL:
        sep = "&" if "?" in STORE_CHECKOUT_URL else "?"
        resp = web.HTTPFound(f"{STORE_CHECKOUT_URL}{sep}client_reference_id={claim}")
        resp.set_cookie("xzx_claim", claim, max_age=CLAIM_TTL, httponly=True, secure=True, samesite="Lax")
        raise resp

    return web.Response(text=f"Linked as {username}. Verified. You can head back and pick a plan.",
                        content_type="text/plain")


def verify_stripe_signature(payload: bytes, sig_header: str) -> bool:
    try:
        parts = dict(p.split("=", 1) for p in sig_header.split(","))
        ts, v1 = parts["t"], parts["v1"]
    except (ValueError, KeyError):
        return False
    if abs(time.time() - int(ts)) > STRIPE_SIG_TOLERANCE:
        return False
    signed = f"{ts}.{payload.decode()}".encode()
    expected = hmac.new(STRIPE_WEBHOOK_SECRET.encode(), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1)


async def handle_stripe(request):
    payload = await request.read()
    if not STRIPE_WEBHOOK_SECRET or not verify_stripe_signature(payload, request.headers.get("Stripe-Signature", "")):
        await log_event("webhook_reject", detail="bad stripe signature")
        return web.json_response({"error": "bad signature"}, status=400)

    event = json.loads(payload.decode())
    if event.get("type") != "checkout.session.completed":
        return web.json_response({"ignored": event.get("type")}, status=200)

    session = event["data"]["object"]
    if session.get("payment_status") != "paid":
        return web.json_response({"ignored": "unpaid"}, status=200)

    meta = session.get("metadata") or {}
    # Payment Links carry the Discord claim in client_reference_id; Checkout Sessions in metadata.
    claim = session.get("client_reference_id") or meta.get("xzx_claim") or meta.get("claim")

    if not claim:
        await log_event("webhook_reject", detail=f"no claim on session {session.get('id')}")
        return web.json_response({"error": "no claim token"}, status=400)
    decoded = verify_claim(claim)
    if decoded is None:
        await log_event("webhook_reject", detail="invalid/expired claim token")
        return web.json_response({"error": "invalid claim"}, status=400)
    discord_id, plan_key = decoded

    # Resolve product + duration: from the plan the buyer chose, else from metadata.
    plan = get_plan(plan_key) if plan_key else None
    if plan:
        product, duration = plan["product"], (plan["duration"] or "lifetime").lower()
    else:
        product = meta.get("product") or product_by_price_id((session.get("line_items") or {}).get("price_id"))
        duration = (meta.get("duration") or "lifetime").lower()

    if get_product(product) is None:
        await log_event("webhook_reject",
                        detail=f"unknown product/plan on session {session.get('id')} (plan={plan_key})")
        return web.json_response({"error": "unknown product"}, status=400)

    try:
        user = await bot.fetch_user(discord_id)
    except (discord.NotFound, discord.HTTPException):
        await log_event("failed", product=product, detail=f"could not fetch user {discord_id}")
        return web.json_response({"error": "user not found"}, status=404)

    ok, result = await deliver(user, product, source="stripe",
                               stripe_ref=session.get("id"), duration=duration)
    # Always 200 so Stripe doesn't retry; the bot has logged the outcome.
    return web.json_response({"ok": ok, "result": result}, status=200)


async def handle_verify(request):
    """Your macros POST {key, hwid} here to check a license. Returns {valid, product, reason}."""
    if VERIFY_API_KEY and request.headers.get("X-Api-Key") != VERIFY_API_KEY:
        return web.json_response({"valid": False, "reason": "unauthorized"}, status=401)
    data = {}
    try:
        data = await request.json()
    except Exception:
        pass
    key = (data.get("key") or request.query.get("key") or "").strip()
    hwid = (data.get("hwid") or request.query.get("hwid") or "").strip() or None
    if not key:
        return web.json_response({"valid": False, "reason": "missing_key"}, status=400)
    ok, product, reason = verify_key(key, hwid)
    await log_event("verify_ok" if ok else "verify_fail", key=key, product=product,
                    detail=f"hwid={hwid or '-'} • {reason}")
    return web.json_response({"valid": ok, "product": product, "reason": reason},
                            status=200 if ok else 403)


async def handle_download(request):
    product = request.match_info.get("product", "")
    prod = get_product(product)
    if prod is None:
        return web.Response(status=404, text="not found")
    if not verify_link(product, request.query.get("e"), request.query.get("s")):
        return web.Response(status=403, text="invalid or expired link")
    file_path = PRODUCTS_DIR / prod["filename"]
    if not file_path.exists():
        return web.Response(status=404, text="not found")
    return web.FileResponse(file_path,
                            headers={"Content-Disposition": f'attachment; filename="{file_path.name}"'})


LANDING_PAGE = Path(__file__).resolve().parent / "web" / "index.html"


async def handle_home(_request):
    if LANDING_PAGE.exists():
        return web.FileResponse(LANDING_PAGE, headers={"Cache-Control": "public, max-age=300"})
    return web.Response(text=f"{BRAND_NAME} is online.", content_type="text/plain")


async def handle_health(_r):
    return web.json_response({"status": "ok"})


async def start_http():
    app = web.Application()
    app.router.add_get("/login", handle_login)
    app.router.add_get("/buy", handle_login)
    app.router.add_get("/callback", handle_callback)
    app.router.add_post("/stripe", handle_stripe)
    app.router.add_post("/verify", handle_verify)
    app.router.add_get("/verify", handle_verify)
    app.router.add_get("/dl/{product}", handle_download)
    app.router.add_get("/", handle_home)
    app.router.add_get("/home", handle_home)
    app.router.add_get("/health", handle_health)
    runner = web.AppRunner(app); await runner.setup()
    await web.TCPSite(runner, HTTP_HOST, HTTP_PORT).start()
    log.info("HTTP server on %s:%s", HTTP_HOST, HTTP_PORT)


_ready_once = False


@bot.event
async def on_ready():
    global _ready_once
    db_init()
    if _ready_once:
        # Reconnect — don't re-sync, re-register views, or rebind the port.
        log.info("Reconnected as %s", bot.user)
        return
    _ready_once = True

    # Register persistent views so their buttons work across restarts.
    bot.add_view(TicketLauncher())
    bot.add_view(TicketControls())
    bot.add_view(VerifyView())

    try:
        if GUILD_ID:
            bot.tree.copy_global_to(guild=discord.Object(id=GUILD_ID))
            await bot.tree.sync(guild=discord.Object(id=GUILD_ID))
        else:
            await bot.tree.sync()
    except Exception as e:
        log.error("Command sync failed: %s", e)
    await start_http()
    log.info("Logged in as %s", bot.user)


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Set DISCORD_TOKEN")
    PRODUCTS_DIR.mkdir(parents=True, exist_ok=True)
    bot.run(TOKEN)
