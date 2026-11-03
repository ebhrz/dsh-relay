# Architecture notes

This is the "how it actually works" companion to the README: the moving parts, the byte formats, and the failure modes. Read it before changing the wire protocol.

## Processes

```
                 ┌─────────────────────────── your VPS ───────────────────────────┐
 phone ──TCP──►  │ relay :8889  ──┐                                              │
                 │                ├─ phoneByStream: sid → PhoneConn              │
                 │ relay :9000 ───┘ agents: device id → AgentEntry              │
                 └───────────────────────▲───────────────────────────────────────┘
                                         │ one WSS per device
                 ┌───────────────────────┴────────── your machine ───────────────┐
                 │ dsh web                                                      │
                 │  ├─ RelayBridgeService  (src/index.js)                        │
                 │  ├─ RelayClient         (outbound WSS, TOFU pin, reconnect)   │
                 │  ├─ PumpManager         (HTTP/WS ↔ streams)                   │
                 │  ├─ MobileRouter        (/m, /__relay/m/*)                    │
                 │  ├─ MobileBridge        (sessionController adapter)           │
                 │  └─ webServer           (loopback DSH, random port in 0.2)     │
                 └──────────────────────────────────────────────────────────────┘
```

The relay accepts two kinds of connections and joins them:

- **Phone connections** carry a first line like `GET /c/<device>/m?g=<gate> HTTP/1.1`. The relay parses only that line: it strips the `/c/<device>` prefix and the `g=` parameter, registers the socket under a fresh 32-bit `sid`, and forwards everything else verbatim.
- **Agent connections** are a WSS upgrade to `/agent`, gated by an HMAC challenge over the shared key. Once registered, the agent multiplexes every phone stream onto that one socket.

Multiplexing is dead simple: a binary frame is a 4-byte big-endian `sid` followed by stream bytes; a text frame is a JSON control message (`agent registered`, `ping`, stream lifecycle). Nothing is parsed as HTTP by the relay.

## Keys

Everything is derived from the device PSK (32 random bytes, generated once, never sent to the relay):

| Value | Derivation | Used for |
|---|---|---|
| `gate` | `HMAC-SHA256(psk, "gate:" + id)` | The `?g=` routing token the relay checks |
| `envelopeKey` | `SHA-512(psk ‖ "envelope")[:32]` | `nacl.secretbox` for every API body and WS frame |
| `ticketKey` | `SHA-256(psk ‖ "ticket")` | Sealing the pairing ticket cookie |
| session key | `SHA-256(psk ‖ context ‖ clientNonce ‖ serverNonce)` | Pairing proof binding |

Both ends use `tweetnacl`, so the host's `SHA-512` and the browser's `nacl.hash` agree byte for byte. That is not a coincidence to rely on casually: `nacl.hash` is SHA-512 in tweetnacl, and the comment in `crypto.js` records the coupling.

## Pairing

1. The QR code encodes `.../c/<id>/m?g=<gate>#k=<psk ‖ ed25519 public key>`. The `#` fragment never reaches the relay.
2. `POST /__relay/challenge` with a client nonce returns a server nonce (kept for 60 s).
3. `POST /__relay/verify` with `proof = SHA-512(psk ‖ "cnonce|snonce|verify")` returns `__relay_t` (HttpOnly, SameSite=Strict, 30 days) plus `__relay_g` / `__relay_i`.
4. Every later request carries the ticket. The pump validates it before anything else; no ticket means the pairing page, not your page.

The session table is persisted next to `identity.json`, so a host restart does not orphan paired phones.

## Envelope

A sealed body is `nonce (24 bytes) ‖ secretbox(payload, nonce, envelopeKey)`. Two headers carry the metadata:

- `x-relay-enc: 1` — the body/response is sealed
- `x-relay-ct: <content-type>` — the inner response's content type

The pump seals the *whole inner HTTP response* (status line, headers, body), so a phone sees exactly what the loopback DSH would have answered, minus anything the pump deliberately rewrites.

WebSocket frames use the same primitive inside JSON text frames: `{"__relay": "<base64 envelope>"}`. The mobile page's own push channel (`/__relay/m/ws`) does the same.

## Request routing in the pump

After the head is parsed, one path is chosen:

| Condition | Behaviour |
|---|---|
| `/__relay/*` | Handled locally: pairing handshake, ping |
| No valid ticket | Bootstrap pairing page (all other paths) |
| `/m`, `/m/<asset>`, `/__relay/m/rpc`, `/__relay/m/ws` | Served by `MobileRouter` — never reaches DSH |
| `/relay-bridge/*` | Panel, API, files |
| `x-relay-enc: 1` | Open the request envelope, replay to loopback, seal the response |
| Document navigation | Buffer the response, inject boot script + mobile patch into `<head>` |
| WebSocket upgrade | Strip `permessage-deflate`, re-frame with sealed payloads |
| Anything else | Plain byte replay with `Host`/`Origin` rewritten to loopback |

Keep-alive matters on a mobile link: one stream is one phone TCP connection, and each new connection costs a TLS handshake. The pump serves successive requests on the existing stream and closes idle ones after 45 s.

## Boot injection

The browser bundle does not know it is being relayed. Instead, every HTML document gets a script injected at the top of `<head>` that:

- replaces `window.__DSH_BOOT__` entries so plugin/asset URLs point back through `/c/<id>/`, keeping the original query bytes
- patches `fetch` and `WebSocket` so API traffic is sealed and unsealed transparently
- reports a small boot state (`__dshRelayBoot`) the panel and the probes can read

`<link rel="manifest">` is removed on the way through: the browser fetches a manifest without cookies, which would hit the ticket gate and be parsed as JSON.

## Mobile page

`/c/<id>/m` is a single document plus `app.css`, `app.js` and `nacl.js`. It speaks JSON-RPC over `POST /__relay/m/rpc` (sealed) and receives live events on `/__relay/m/ws` (sealed frames). `MobileBridge` translates those calls into `ctx.sessionController`, `ctx.userQuestions` and `ctx.terminals` on the host; `fold.js` turns the durable event log into renderable rows.

This exists because replaying the desktop UI into a 390 px viewport is a losing battle: three columns, dozens of bundles, and a layout patched through CSS overrides.

## Failure modes worth knowing

| Symptom | Cause |
|---|---|
| Panel says `idle` | No `relayHost`/`relayKey`, or `autoStart` off |
| `fingerprint-mismatch`, channel halted | Relay's agent certificate changed (reinstall, new cert) — accept the new pin from the panel if that was expected |
| Pairing page loops | Ticket cookie rejected: identity rotated, or `sessions.json` lost |
| `envelope open failed` | Phone and host disagree on the PSK — re-scan the QR |
| Relay logs `agent rejected` | `relayKey` differs from the server's `--key` |
| Relay logs `404-noprefix` | Something requested a path without `/c/<id>/`; the fallback usually catches it, but it means an asset URL escaped rewriting |

See [troubleshooting.md](troubleshooting.md) for the diagnostic order.
