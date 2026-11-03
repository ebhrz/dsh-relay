# dsh-relay

[![tests](https://github.com/ebhrz/dsh-relay/actions/workflows/test.yml/badge.svg)](https://github.com/ebhrz/dsh-relay/actions/workflows/test.yml)

**Control the DeepSeek Harness (DSH) running on your own machine from your phone — through a relay you host yourself.**

No accounts, no third-party services, no inbound ports on your laptop, and the relay only ever sees ciphertext. Scan a QR code, get a phone-first page for chatting with your agent, approving tool calls, answering questions and streaming output; fall back to the full desktop UI when you need it.

<p align="center">
  <img src="docs/mobile/shots/mobile-01-chat.png" width="240" alt="Chat with tool cards and streaming output">
  <img src="docs/mobile/shots/mobile-03-approval.png" width="240" alt="Approval card">
  <img src="docs/mobile/shots/mobile-02-sessions.png" width="240" alt="Session drawer grouped by project">
</p>

On the phone you get:

- **Projects, not a flat list.** Sessions are grouped by workspace; groups collapse, and sessions outside a project fall into one bucket.
- **Model switching per session.** The chip above the composer opens a provider-grouped picker; a new session shows the deployment default instead of an empty prompt, and inherits the last model you picked.
- **Permission switching per session.** The chip beside it offers the host's presets (read only, workspace write, full access, plus auto review when mounted); full access is highlighted.
- **Branch a conversation.** Long-press a message (or use the row menu) to fork the history up to that point into a new session; the branch inherits the project and opens right away.
- **Choose what the transcript shows.** Settings gives reasoning and tool calls three states each — hidden, collapsed with a one-line preview, or expanded.
- Chat with streaming output, tool cards, approvals, questions, image attachments, renaming and a small terminal.

---

## The problem

DSH is a desktop harness: the agent runs on your machine, edits your files, and runs your commands. That is exactly what makes remote access awkward. You do not want to expose your laptop to the internet, you do not want your conversations sitting on someone else's server, and you do not want a mobile client that reimplements the agent.

dsh-relay splits the problem in three:

| Piece | Where it runs | What it does |
|---|---|---|
| `dsh-relay-server` | A small VPS you own | Dumb router: parses one request line, forwards bytes, stores nothing |
| `dsh-relay-bridge` | Your machine, inside `dsh web` | Identity, pairing, encryption, replay to the local DSH |
| Phone page | Your phone's browser | Talks to the DSH host API through end-to-end encrypted frames |

## How it works

```
phone browser ──HTTP(S)──► dsh-relay-server (your VPS, dumb router)
                              │  WSS (self-signed TLS + pinned fingerprint + HMAC gate)
                              ▼
                    dsh-relay-bridge (inside your dsh web)
                      ├─ auth gate: PSK challenge-response → encrypted cookie
                      ├─ mobile page:   /c/<id>/m + sealed RPC/WS → host session API
                      ├─ sealed pump:   Host/Origin rewrite, replay to ctx.webServer
                      ├─ boot injection: patched fetch/WS, all API and WS payloads sealed
                      └─ files:         /relay-bridge/files?p=<absolute path>
```

The bridge dials **out** to the relay, so your machine needs no public port and no inbound firewall rule. The relay pairs a phone connection with the agent's outbound connection by device id and shovels bytes between them; it never parses HTTP bodies, never terminates the envelope encryption, and keeps no database.

## Security model

| Layer | Mechanism |
|---|---|
| Relay abuse | Server starts with `--key`; an agent must prove knowledge of it with an HMAC challenge-response before registering |
| Scanner noise | Phone URLs carry `?g=<gate>`, derived from the device PSK; the relay drops requests without it before they reach your machine |
| Phone ↔ desktop auth | The QR fragment carries the PSK; a two-step challenge-response (replay-resistant) exchanges it for an encrypted ticket cookie valid for 30 days |
| Confidentiality | Every API request/response body and WebSocket frame is sealed with a key derived from the PSK (`tweetnacl` secretbox) |
| Relay ↔ desktop | Self-signed TLS with certificate pinning on first use (TOFU); if the fingerprint ever changes, the channel halts instead of reconnecting blindly |
| Revocation | "Regenerate" in the panel rotates the PSK, which invalidates every paired phone at once |

**What the relay can see:** device ids, gates, connection metadata, request sizes and timing, and client IPs. Not your prompts, tool output, or file contents.

**Residual risks you should know about:**

- **Without TLS in front of the relay, the HTML/JS shell is delivered in clear text.** Encrypted API data does not help if an active man-in-the-middle can serve you different JavaScript. Put the relay behind a domain with TLS (Caddy is one line), or use a private network such as Tailscale. The threat model is "passive network observers and a curious relay operator", not "an attacker who can rewrite your traffic".
- The page shell is served by your own bridge over the relay, so anyone who can reach the relay *and* guess a device id still cannot pair without the PSK — but they will see the pairing page.
- A phone that has paired stays paired for 30 days. Rotate the identity when a device is lost.

## Quick start

Requirements: Node.js ≥ 22 where DSH runs, a machine with a public IP for the relay, and `openssl` on the relay host (for the self-signed agent certificate).

### 1. Relay server

```sh
git clone https://github.com/ebhrz/dsh-relay.git
cd dsh-relay
npm install --workspace dsh-relay-server

# keep this key: the bridge needs the same value
KEY="$(openssl rand -hex 24)"
node packages/relay/src/index.mjs --port 8889 --agent-port 9000 --key "$KEY"
```

Open **two** ports: `8889` for phones and `9000` for agents. To terminate TLS in front of the phone port, either pass `--tls-cert/--tls-key` (the relay then speaks HTTPS/WSS directly) or run the included terminator behind a certificate you already have:

```sh
node packages/relay/src/tls-terminator.mjs --port 8443 --upstream 8889 --cert-dir /path/to/certs
```

Run either process under systemd, `tmux`, or your supervisor of choice; there is no state to back up except the generated agent certificate in `~/.dsh-relay`.

### 2. Local bridge

```sh
cd dsh-relay
npm install --workspace dsh-relay-bridge
dsh plugin --profile web add link:./packages/plugin
```

That registers the plugin bundle; restart `dsh web` (the plugin is host-side code). Then open the tokenised URL `dsh web` prints, and go to `/relay-bridge/panel` on that origin. Fill in the relay scheme, host, phone port (`8889`), agent port (`9000`) and the key from step 1.

### 3. Phone

Scan the QR code in the panel. It opens the mobile page, pairs once, and stores the ticket. The full desktop UI stays reachable from the drawer ("Open full desktop UI") or at `/c/<id>/?desktop=1`.

## Configuration

Ordered by precedence: the panel's saved `config.json` wins over the defaults in `cordis.patch.yml`.

| Key | Default | Meaning |
|---|---|---|
| `relayScheme` | `http` | `http` or `https` for the phone-facing relay port |
| `relayHost` | — | Relay hostname or IP |
| `relayPort` | — | Relay phone port (e.g. `8889`) |
| `agentPort` | `relayPort + 1` | Relay agent port (e.g. `9000`) |
| `relayKey` | — | Shared key, must match the server's `--key` |
| `autoStart` | `true` | Connect on startup; leave `false` to connect only from the panel |
| `dshHost` / `dshPort` | `127.0.0.1` / `3080` | Legacy fallbacks; the pump targets `ctx.webServer` when available |

State lives in `~/.dsh/plugin-data/dsh-relay-bridge/` (`DSH_HOME` overrides `~/.dsh`): `identity.json`, `config.json`, `sessions.json`, `audit.log`. Deleting `identity.json` is equivalent to rotating the device identity.

## Repository layout

```
packages/relay/      dsh-relay-server — phone listener, agent listener, TLS terminator
packages/plugin/     dsh-relay-bridge — identity, pairing, sealed pump, files, panel
  src/mobile/        phone page, host bridge, event folding, static assets
  src/client/        the small client bundle DSH loads in the browser
  test/              hermetic test suite (no relay, no dsh web)
  scripts/           mock host, CDP probes, live-environment probes
docs/mobile/         phone page design notes
```

## Development

Everything below runs without a relay or a running `dsh web`:

```sh
npm test          # compatibility, keep-alive, mobile patch, bridge, transport
npm run check     # node --check over every source file
npm run test:ui   # end-to-end UI test against the mock host (needs Chrome; skips if absent)
npm run dev:mock  # print a URL for the mock host, so you can open the phone page locally
```

The UI test and CDP probes need a Chromium-family browser; set `CHROME_BIN` if it is not in a standard location.

Probes that *do* need a real deployment read the local identity and take the relay URL from the environment:

```sh
RELAY_BASE_URL=https://relay.example.com:8889 node packages/plugin/scripts/probe-sealed.mjs
RELAY_BASE_URL=https://relay.example.com:8889 node packages/plugin/scripts/probe-ws.mjs
node packages/plugin/scripts/probe-relay-integration.mjs   # fake DSH behind a real relay client
```

## Compatibility

- **DSH**: `^0.2.1-rc.2`. The bridge uses the host services `webServer`, `connection`, `sessionController`, `userQuestions` and `terminals`; the boot injection targets the `{entries, batches}` boot payload introduced in 0.2.
- **Node.js**: ≥ 22 for the bridge (DSH's own floor), ≥ 18 for the relay.
- **Browsers**: any current mobile browser. The page is a single document plus three static assets.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).
