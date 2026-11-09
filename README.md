# Sharky Services — Delivery Bot

Discord bot that delivers a license key + product file to a buyer after a verified
purchase. One process runs the Discord bot and an HTTP server together.

## Flow

```
buyer -> /login -> Discord OAuth -> /callback
         (verify identity, mint signed claim token, redirect to checkout)
      -> Stripe Checkout (claim + product carried in session metadata)
      -> Stripe checkout.session.completed -> /stripe
         (verify Stripe signature, extract claim + product)
      -> deliver(): resolve claim -> real Discord ID -> generate key
      -> DM buyer: license key + file
         (file attached if small; signed expiring download link if large)
```

The buyer's Discord ID is never supplied in a forgeable way — it is signed by the
bot at OAuth time and only the bot can validate it.

## HTTP routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/login` | GET | Starts Discord OAuth login |
| `/callback` | GET | OAuth redirect target; links account, mints claim, redirects to checkout |
| `/stripe` | POST | Stripe webhook (`checkout.session.completed`) |
| `/dl/{product}` | GET | Serves a product file via a signed, expiring link |
| `/health` | GET | Health check |

## Slash commands (all staff-gated; owner/admins always allowed)

Setup
- `/setup all` — one click: creates server/key/shop/general log channels, a tickets
  category, and posts the ticket panel. Wires every setting automatically.
- `/setup logs` — use the current channel as the general log feed
- `/setup tickets` — post a ticket panel in this channel
- `/setup status` — what's configured and what's missing

Products & delivery
- `/product add name file [display_name] [price_id]` — add a product and upload its file
- `/product list` · `/product remove`
- `/deliver member product` — manually deliver to a buyer
- `/stats` — keys issued / delivered per product

Keys
- `/key lookup|revoke|unrevoke|resethwid|resend`
- `/keys @member` — list a member's keys

Other
- `/help` — menu

## Products

Nothing is hardcoded. Add your own with `/product add`, uploading the file as an
attachment. Files are stored under the volume so they survive redeploys. Use the
product's short name in `/deliver` and as `product` in Stripe metadata.

## License verification API

Your macros POST to `/verify` to check a key:

```
POST https://<your-domain>/verify
{ "key": "XZX-....", "hwid": "optional-machine-id" }
-> { "valid": true, "product": "fishing", "reason": "ok" }
```

The first machine to use a key binds its HWID (set `HWID_LOCK=0` to disable). Set
`VERIFY_API_KEY` to require callers to send it as an `X-Api-Key` header.

## Logs

Three feeds, created by `/setup all`: **server-logs** (joins, leaves, edits, deletes,
bans, role/nick changes), **key-logs** (verify / revoke / HWID), and **shop-logs**
(purchases and deliveries). Server logs need privileged intents: set `SERVER_LOGS=1`
and enable "Server Members Intent" + "Message Content Intent" in the Developer Portal.

## Tickets

`/setup all` posts a Support panel. Buyers open a ticket and enter their **invoice ID**,
which the bot verifies against the purchase record (must exist and belong to them).
Each ticket is a private channel with Claim and Close buttons; closing saves a
transcript to the log feed. One open ticket per user.

## Minimum to run

The bot only needs `DISCORD_TOKEN` to boot. OAuth and Stripe are optional. Set the
token, deploy, grant the bot **Manage Channels**, then run `/setup all`.

## Products

Edit the `PRODUCTS` dict in `bot.py` (internal name -> filename) and drop the files
into `products/`. Edit `PRICE_TO_PRODUCT` to map Stripe price IDs to those names.

## Environment variables

See `.env.example`. Generate the two signing secrets once and pin them:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Set that value for both `OAUTH_STATE_SECRET` and `LINK_SECRET` (use two different
values). If unset they default to random, which means a restart invalidates every
live token and download link.

## Checkout integration

When you create the Stripe Checkout Session, attach the claim token and product:

```python
session = stripe.checkout.Session.create(
    mode="payment",
    line_items=[{"price": "price_fishing", "quantity": 1}],
    success_url="https://xzx.yourdomain.com/thanks",
    cancel_url="https://xzx.yourdomain.com/cancel",
    metadata={
        "xzx_claim": claim_token,   # from /callback (query param or cookie)
        "product": "fishing",
    },
)
```

## Deploy (Railway)

1. Push this repo to GitHub.
2. Point Railway at the repo (it reads `railway.json` / `Dockerfile`).
3. Set the env vars in the Railway dashboard.
4. **Add a volume mounted at `/app/data`** so the SQLite DB and logs survive
   redeploys. Without it, issued keys are lost on every restart.
5. Developer Portal -> OAuth2: register `OAUTH_REDIRECT_URI`, copy client ID + secret.
6. Stripe -> Webhooks: add an endpoint at `https://.../stripe` for
   `checkout.session.completed`, copy the `whsec_...` secret.

## Deploy (Docker, e.g. OVH VPS)

```bash
docker build -t sharky-services .
docker run -d --env-file .env -p 8080:8080 \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/products:/app/products" \
  --name sharky sharky-services
```
