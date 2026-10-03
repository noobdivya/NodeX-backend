<h1 align="center">NodeX — Backend</h1>

<p align="center">
  <strong>The two small Go services behind NodeX, a decentralized peer-to-peer chat app.</strong><br>
  No database. No user accounts. No messages.
</p>

<p align="center">
  <img alt="Status" src="https://img.shields.io/badge/status-in%20development-orange">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.27-00ADD8">
  <img alt="P2P" src="https://img.shields.io/badge/P2P-go--libp2p-2dd4bf">
</p>

The app itself, and everything about identities, chat and privacy, is in the **[NodeX-frontend](https://github.com/noobdivya/NodeX-frontend)** repository. In NodeX, accounts, contacts and messages live on users' devices; this repository only has:

| Service | Folder | What it does |
|---|---|---|
| **P2P node** | [`p2p-node/`](p2p-node) | A libp2p peer that browsers join the network through. It holds the DHT of public, signed handle records (in memory) and relays connections between browsers. |
| **Email verifier** | [`email-verifier/`](email-verifier) | Sends and checks the 6-digit sign-up code. Stateless: no database, stores no users. |

```
        Browsers (NodeX-frontend)
          │                     │
 sign-up only: send/check code  │ libp2p (WebSockets, Noise, Yamux)
          ▼                     ▼
┌── Email verifier ──┐   ┌──────────── P2P node ────────────┐
│ no database        │   │ DHT /nodex/kad/1.0.0 (server)     │
│ HMAC-signed tokens │   │ signed handle records, in memory  │
│ rate limits        │   │ validates every record            │
│ SMTP (e.g. Gmail)  │   │ circuit relay for browsers        │
└────────────────────┘   └───────────────────────────────────┘
```

---

## P2P node

Browsers can't accept incoming connections, so they can't hold a DHT by themselves. They join by dialling always-on libp2p peers like this one, the same role bootstrap and DHT-server nodes play in IPFS. Anyone can run one, and several nodes linked with `NODE_PEERS` share the DHT.

- **DHT:** protocol prefix `/nodex`, server mode. Records live under `/nodex/<lowercase handle>` and are kept in memory (up to 48 hours; browsers republish every 6 hours).
- **Record validation** (`record.go`), before anything is stored:
  - the signature matches the key inside the Peer ID
  - the record is stored under its own handle
  - the handle's tag re-derives from the Peer ID and email commitment (PBKDF2, 600k iterations)
  - not oversized, not dated in the future; the newest `seq` wins
- **Relay:** circuit relay v2, so browsers can set up WebRTC with each other; relayed data stays end-to-end encrypted. Limits: 10 minutes and 16 MB per relayed connection.
- **Identity:** a stable key so its address doesn't change (`node.key`, or `NODE_KEY`).

### Configuration

| Variable | Default | Description |
|---|---|---|
| `NODE_LISTEN` | `/ip4/0.0.0.0/tcp/4001,/ip4/0.0.0.0/tcp/4002/ws`, or `/ip4/0.0.0.0/tcp/$PORT/ws` when `PORT` is set | Listen addresses (TCP for nodes, WebSockets for browsers) |
| `NODE_ANNOUNCE` | `/dns4/$RENDER_EXTERNAL_HOSTNAME/tcp/443/wss` on Render | Public address(es) to advertise behind a proxy |
| `NODE_KEY_FILE` | `node.key` | Where the node's identity is kept (created on first run) |
| `NODE_KEY` | – | Node identity: 64 hex characters, or any random secret of 32+ characters (overrides the key file) |
| `NODE_PEERS` | – | Other NodeX nodes to link with (comma-separated multiaddrs) |

On start it prints the address browsers need:

```
browsers (local dev): NEXT_PUBLIC_BOOTSTRAP_PEERS=/ip4/127.0.0.1/tcp/4002/ws/p2p/12D3KooW…
```

> Browsers on an `https://` site can only use **secure** WebSockets, so in production the node must be reachable as `wss://` (Render provides this).

---

## Email verifier

Used once, during sign-up, to confirm a user owns their email. Codes are carried in **HMAC-signed tokens**, so the verifier needs no database; a little in-memory state handles cooldowns and single use.

### API

| Method | Endpoint | Request | Response |
|---|---|---|---|
| `POST` | `/api/v1/otp/send` | `{ "email": "…" }` | `{ "otp_token", "expires_in_seconds", "resend_in_seconds" }` |
| `POST` | `/api/v1/otp/verify` | `{ "otp_token": "…", "otp": "123456" }` | `{ "verified": true }` |
| `GET` | `/healthz` | – | `{ "status": "ok" }` |

Errors look like `{ "error": { "code": "otp_invalid", "message": "…" } }`.

**Limits:** codes expire after **10 minutes** and work once; **5 attempts** per code; a new code every **60 seconds**; requests rate-limited per IP.

### Configuration (`email-verifier/.env`)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Port to listen on |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed frontend origins (comma-separated) |
| `RATE_LIMIT_PER_MINUTE` | `20` | Requests per minute per IP |
| `OTP_SECRET` | random per run | HMAC key for code tokens, at least 32 characters. **Required in production.** |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` | – | Email sending. **Required in production.** |
| `APP_ENV` | `development` | `production` enforces the required settings |
| `TRUST_PROXY` | – | `true` behind a hosting proxy (e.g. Render), so rate limiting uses the visitor's address from `X-Forwarded-For` |

---

## Running locally

Prerequisite: [Go](https://go.dev/dl/) 1.27 or newer.

```bash
git clone https://github.com/noobdivya/NodeX-backend.git
cd NodeX-backend
```

**Terminal 1 — P2P node**

```bash
cd p2p-node
go run .
```

Copy the `NEXT_PUBLIC_BOOTSTRAP_PEERS=…` line it prints into the frontend's `.env.local`. The node creates `node.key` on first run; keep it private (it's git-ignored).

**Terminal 2 — email verifier**

```bash
cd email-verifier
cp .env.example .env
go run ./cmd/server
```

It listens on **http://localhost:8080**. If `SMTP_HOST` is empty, codes are printed in this terminal instead of being emailed, so no email setup is needed for local testing.

### Sending real emails with Gmail

1. Turn on [2-Step Verification](https://myaccount.google.com/security) for the Gmail account.
2. Create an **App Password** at <https://myaccount.google.com/apppasswords>.
3. Fill in `email-verifier/.env`:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=you@gmail.com
SMTP_PASSWORD=your-16-character-app-password
SMTP_FROM=NodeX <you@gmail.com>
```

**Never commit `.env` or `node.key`**; both are git-ignored.

---

## Deploying on Render

[`render.yaml`](render.yaml) is a Render Blueprint for both services (Docker builds).

1. **Render → New → Blueprint**, pick this repository. It creates `nodex-node` and `nodex-verifier`, generates `NODE_KEY` and `OTP_SECRET`, and asks for:
   - `SMTP_USERNAME`, `SMTP_PASSWORD` (a Gmail App Password), `SMTP_FROM`
   - `CORS_ORIGINS`: your Vercel address (use a placeholder until the frontend is deployed)
2. When both are live, open **nodex-node → Logs** and copy the value after `browsers: NEXT_PUBLIC_BOOTSTRAP_PEERS=`. It looks like `/dns4/nodex-node-xxxx.onrender.com/tcp/443/wss/p2p/12D3KooW…`.
3. Use it, plus the verifier's `https://…onrender.com` address, when deploying the frontend on Vercel.
4. Set `CORS_ORIGINS` to the final Vercel address (no trailing slash).

Notes:
- **Free instances sleep after about 15 minutes without traffic.** For the node this means a slow first visit and an empty handle directory until people open the app again. A paid instance keeps it always on.
- **Email on the free plan:** if codes don't arrive and the verifier's logs show a timeout connecting to the SMTP server, the free plan is blocking outgoing email ports; use a paid instance for the verifier.

---

## Testing

```bash
cd email-verifier && go test ./...
cd ../p2p-node && go test ./...
```

- **Email verifier:** sending and checking codes, single use, the 5-attempt lockout, expiry, the resend cooldown and tamper-proof tokens.
- **P2P node:** valid records, case-insensitive keys, and rejected forgeries — a handle claimed by another key, a swapped Peer ID, a wrong key, a future-dated record, garbage and oversized values — plus "newest record wins".

---

## Project structure

```
render.yaml                    Render Blueprint for both services
p2p-node/
├── main.go                    Host, WebSockets/TCP, DHT, relay, node key, announce address
├── record.go                  Handle-record validation (mirrors the frontend's lib/p2p/record.ts)
├── record_test.go
└── Dockerfile
email-verifier/
├── cmd/server/main.go         Startup and routes
├── internal/
│   ├── otp/                   Send and verify codes (HMAC-signed tokens)
│   ├── mailer/                SMTP email sending
│   ├── httpx/                 JSON helpers, CORS, rate limiting
│   └── config/                Settings and .env loading
└── Dockerfile
```

---

## Security notes

- **Neither service sees private keys, recovery phrases, contacts or messages.** Those never leave users' devices.
- **The node stores only public, signed handle records**, and rejects any record that isn't signed by the key its handle belongs to. Relayed traffic is end-to-end encrypted between browsers.
- **The verifier stores no emails.** Each address is used only to send its code; tokens are signed with `OTP_SECRET`, so keep that secret private.
- **Running more nodes makes the network more resilient.** With a single node, search depends on that node being up.

## License

No license has been chosen yet. Until one is added, all rights are reserved by the author.
