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
from datetime import datetime, timezone

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
KEY_PREFIX = os.environ.get("KEY_PREFIX", "XZX")

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

# product name -> filename inside PRODUCTS_DIR
PRODUCTS = {
    "metal_detector": "XZX_MetalDetector.ahk",
    "alt_click":      "XZX_AltClick.ahk",
    "fishing":        "XZX_Fishing.ahk",
}

# Stripe price id -> internal product (fallback; prefer product in metadata)
PRICE_TO_PRODUCT = {
    "price_metaldetector": "metal_detector",
    "price_altclick":      "alt_click",
    "price_fishing":       "fishing",
}

LOG_COLORS = {
    "key_generated":  0x5865F2,
    "linked":         0x5865F2,
    "log_setup":      0x57F287,
    "delivered":      0x57F287,
    "delivered_link": 0x57F287,
    "closed_dms":     0xFEE75C,
    "failed":         0xED4245,
    "webhook_reject": 0xED4245,
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
    con.commit(); con.close()


def generate_key(product: str) -> str:
    con = sqlite3.connect(DB_PATH)
    try:
        for _ in range(10):
            body = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
            key = f"{KEY_PREFIX}-{product[:4].upper()}-{body[:4]}-{body[4:8]}-{body[8:12]}-{body[12:]}"
            try:
                con.execute("INSERT INTO licenses (key, product, created_at) VALUES (?, ?, ?)",
                            (key, product, datetime.now(timezone.utc).isoformat()))
                con.commit()
                return key
            except sqlite3.IntegrityError:
                continue
        raise RuntimeError("Could not generate a unique key after 10 attempts")
    finally:
        con.close()


def bind_key(key: str, discord_id: int):
    con = sqlite3.connect(DB_PATH)
    con.execute("UPDATE licenses SET discord_id = ? WHERE key = ?", (discord_id, key))
    con.commit(); con.close()


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


def resolve_log_channel_id():
    """Log channel set by /setup logs takes priority; else the LOG_CHANNEL_ID env var."""
    stored = get_setting("log_channel_id")
    if stored:
        try:
            return int(stored)
        except ValueError:
            return None
    return LOG_CHANNEL_ID or None


def is_staff(interaction: discord.Interaction) -> bool:
    """Allow the server owner, anyone with Administrator/Manage Server, or the ADMIN_ROLE."""
    member = interaction.user
    guild = interaction.guild
    if guild is not None and member.id == guild.owner_id:
        return True
    perms = getattr(member, "guild_permissions", None)
    if perms is not None and (perms.administrator or perms.manage_guild):
        return True
    return ADMIN_ROLE in [r.name for r in getattr(member, "roles", [])]


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


def make_state() -> str:
    nonce = secrets.token_urlsafe(16); ts = str(int(time.time()))
    return f"{nonce}.{ts}.{_sign(OAUTH_STATE_SECRET, f'{nonce}:{ts}')}"


def verify_state(state: str, max_age: int = 600) -> bool:
    try:
        nonce, ts, sig = state.split(".")
    except (ValueError, AttributeError):
        return False
    if int(time.time()) - int(ts) > max_age:
        return False
    return hmac.compare_digest(_sign(OAUTH_STATE_SECRET, f"{nonce}:{ts}"), sig)


def mint_claim(discord_id: int) -> str:
    exp = int(time.time()) + CLAIM_TTL
    return f"{discord_id}.{exp}.{_sign(OAUTH_STATE_SECRET, f'{discord_id}:{exp}')}"


def verify_claim(token: str):
    try:
        did, exp, sig = token.split(".")
    except (ValueError, AttributeError):
        return None
    if int(time.time()) > int(exp):
        return None
    if not hmac.compare_digest(_sign(OAUTH_STATE_SECRET, f"{did}:{exp}"), sig):
        return None
    return int(did)


# ===================== Bot =====================
intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)


async def log_event(event: str, *, user=None, product=None, key=None, detail=None):
    parts = [f"event={event}"]
    if user:    parts.append(f"user={user} ({getattr(user, 'id', '?')})")
    if product: parts.append(f"product={product}")
    if key:     parts.append(f"key={key}")
    if detail:  parts.append(f"detail={detail}")
    (log.error if event in ("failed", "webhook_reject") else log.info)(" ".join(parts))

    channel_id = resolve_log_channel_id()
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


async def deliver(user: discord.abc.User, product: str) -> tuple[bool, str]:
    if product not in PRODUCTS:
        await log_event("failed", user=user, product=product, detail="unknown product")
        return False, f"Unknown product: {product}"
    if not is_linked(user.id):
        await log_event("failed", user=user, product=product, detail="not linked via oauth")
        return False, "buyer has not linked their Discord account"

    file_path = PRODUCTS_DIR / PRODUCTS[product]
    if not file_path.exists():
        await log_event("failed", user=user, product=product, detail="file missing on disk")
        return False, f"Product file not found for {product}"

    key = generate_key(product)
    bind_key(key, user.id)
    await log_event("key_generated", user=user, product=product, key=key)

    size = file_path.stat().st_size
    use_link = size > ATTACH_LIMIT_BYTES

    embed = discord.Embed(title="Purchase Delivered",
                          description=f"Thanks for buying **{product.replace('_', ' ').title()}**.",
                          color=0x2b2d31)
    embed.add_field(name="Your License Key", value=f"```{key}```", inline=False)

    try:
        if use_link:
            if not PUBLIC_BASE_URL:
                await log_event("failed", user=user, product=product, key=key,
                                detail=f"file {size}B over limit, PUBLIC_BASE_URL unset")
                return False, "file too large and no download host configured"
            url = make_download_url(product)
            embed.add_field(name="Download",
                            value=f"[Download {file_path.name}]({url})\nLink expires in {LINK_TTL // 60} min.",
                            inline=False)
            embed.set_footer(text="Keep your key private. One key = one user.")
            await user.send(embed=embed)
            await log_event("delivered_link", user=user, product=product, key=key)
        else:
            embed.add_field(name="Product", value=file_path.name, inline=False)
            embed.set_footer(text="Keep your key private. One key = one user.")
            await user.send(embed=embed, file=discord.File(file_path))
            await log_event("delivered", user=user, product=product, key=key)
        return True, key
    except discord.Forbidden:
        await log_event("closed_dms", user=user, product=product, key=key,
                        detail="DMs closed — key generated but not delivered")
        return False, "closed_dms"
    except discord.HTTPException as e:
        await log_event("failed", user=user, product=product, key=key, detail=str(e))
        return False, f"send_failed: {e}"


# ---- Slash command: manual delivery ----
@bot.tree.command(description="Deliver a product + key to a buyer (staff only).")
@app_commands.describe(member="Who bought it", product="Which product")
@app_commands.choices(product=[app_commands.Choice(name=p, value=p) for p in PRODUCTS])
async def deliver_cmd(interaction: discord.Interaction, member: discord.Member,
                      product: app_commands.Choice[str]):
    if not is_staff(interaction):
        await interaction.response.send_message("You can't use this.", ephemeral=True); return
    await interaction.response.defer(ephemeral=True)
    ok, result = await deliver(member, product.value)
    if ok:
        await interaction.followup.send(
            f"Delivered **{product.value}** to {member.mention}. Key: `{result}`", ephemeral=True)
    elif result == "closed_dms":
        await interaction.followup.send(
            f"{member.mention} has DMs closed. Key saved — they open DMs, then re-run.", ephemeral=True)
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
    log_id = resolve_log_channel_id()
    lines = [
        f"**Logs:** {'<#' + str(log_id) + '>' if log_id else 'not set — run `/setup logs`'}",
        f"**OAuth login:** {'configured' if OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET else 'not set'}",
        f"**Public URL:** {PUBLIC_BASE_URL or 'not set'}",
        f"**Stripe payments:** {'configured' if STRIPE_WEBHOOK_SECRET else 'not set (set up later)'}",
    ]
    embed = discord.Embed(title="Setup Status", color=0x5865F2,
                          description="\n".join(lines),
                          timestamp=datetime.now(timezone.utc))
    await interaction.response.send_message(embed=embed, ephemeral=True)


bot.tree.add_command(setup_group)


# ===================== HTTP handlers =====================
async def handle_login(_request):
    if not OAUTH_CLIENT_ID or not OAUTH_REDIRECT_URI:
        return web.Response(status=500, text="OAuth not configured")
    params = (f"client_id={OAUTH_CLIENT_ID}&redirect_uri={OAUTH_REDIRECT_URI}"
              f"&response_type=code&scope=identify&state={make_state()}&prompt=consent")
    raise web.HTTPFound(f"{DISCORD_API}/oauth2/authorize?{params}")


async def handle_callback(request):
    if request.query.get("error"):
        return web.Response(status=400, text=f"Authorization cancelled: {request.query['error']}")
    code, state = request.query.get("code"), request.query.get("state")
    if not code or not verify_state(state):
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

    claim = mint_claim(discord_id)
    if STORE_CHECKOUT_URL:
        sep = "&" if "?" in STORE_CHECKOUT_URL else "?"
        resp = web.HTTPFound(f"{STORE_CHECKOUT_URL}{sep}xzx_claim={claim}")
        resp.set_cookie("xzx_claim", claim, max_age=CLAIM_TTL, httponly=True, secure=True, samesite="Lax")
        raise resp
    return web.Response(text=f"Linked as {username}. Verified.\n\nClaim token:\n{claim}\n\nReturn to checkout.",
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
    claim = meta.get("xzx_claim") or meta.get("claim")
    product = meta.get("product") or PRICE_TO_PRODUCT.get((session.get("line_items") or {}).get("price_id"))

    if not claim:
        await log_event("webhook_reject", detail=f"no claim on session {session.get('id')}")
        return web.json_response({"error": "no claim token"}, status=400)
    discord_id = verify_claim(claim)
    if discord_id is None:
        await log_event("webhook_reject", detail="invalid/expired claim token")
        return web.json_response({"error": "invalid claim"}, status=400)
    if product not in PRODUCTS:
        await log_event("webhook_reject", detail=f"unknown product on session {session.get('id')}")
        return web.json_response({"error": "unknown product"}, status=400)

    try:
        user = await bot.fetch_user(discord_id)
    except (discord.NotFound, discord.HTTPException):
        await log_event("failed", product=product, detail=f"could not fetch user {discord_id}")
        return web.json_response({"error": "user not found"}, status=404)

    ok, result = await deliver(user, product)
    # Always 200 so Stripe doesn't retry; the bot has logged the outcome.
    return web.json_response({"ok": ok, "result": result}, status=200)


async def handle_download(request):
    product = request.match_info.get("product", "")
    if product not in PRODUCTS:
        return web.Response(status=404, text="not found")
    if not verify_link(product, request.query.get("e"), request.query.get("s")):
        return web.Response(status=403, text="invalid or expired link")
    file_path = PRODUCTS_DIR / PRODUCTS[product]
    if not file_path.exists():
        return web.Response(status=404, text="not found")
    return web.FileResponse(file_path,
                            headers={"Content-Disposition": f'attachment; filename="{file_path.name}"'})


async def handle_health(_r):
    return web.json_response({"status": "ok"})


async def start_http():
    app = web.Application()
    app.router.add_get("/login", handle_login)
    app.router.add_get("/callback", handle_callback)
    app.router.add_post("/stripe", handle_stripe)
    app.router.add_get("/dl/{product}", handle_download)
    app.router.add_get("/health", handle_health)
    runner = web.AppRunner(app); await runner.setup()
    await web.TCPSite(runner, HTTP_HOST, HTTP_PORT).start()
    log.info("HTTP server on %s:%s", HTTP_HOST, HTTP_PORT)


@bot.event
async def on_ready():
    db_init()
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
    PRODUCTS_DIR.mkdir(exist_ok=True)
    bot.run(TOKEN)
