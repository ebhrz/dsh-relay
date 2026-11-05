# Troubleshooting

Work down the stack: phone → relay → agent link → pump → DSH. Each layer tells you something different, and the first one that looks wrong is almost always the culprit.

## 1. Is the relay up?

```sh
curl -sS -o /dev/null -w '%{http_code}\n' https://<relay-host>:8889/
ss -tln | grep -E ':(8889|9000)\b'      # on the relay host
```

A connection refused means the process is not running or the port is closed. A TLS handshake that dies after the ClientHello (`curl` exit 35) usually means the network path, not your configuration: some networks reset connections to non-standard HTTPS ports. Try port 443 with the TLS terminator, or a different route.

## 2. Is the agent connected?

On the relay, `agent registered id=<id>` followed by no `agent gone` means the bridge is connected. `agent rejected: ...` means the shared key does not match: compare the panel's key field with the server's `--key`.

If the relay never sees the agent, the outbound WSS from your machine is failing. Run the bridge with host logging visible and watch for `relay: connecting` / `relay: fingerprint-mismatch`.

## 3. Is the phone request reaching the right device?

Relay log lines worth knowing:

| Line | Meaning |
|---|---|
| `agent registered id=<id>` | Bridge connected and authenticated |
| `agent gone id=<id>` | Bridge disconnected (network, sleep, restart) |
| `agent rejected: <reason>` | Registration gate failed — key mismatch or malformed proof |
| `phone-start sid=<n> firstLine="..."` | A phone connection opened; the first line shows what was requested |
| `404-noprefix <method> <path>` | A request arrived without `/c/<id>/`; the fallback usually handles it, but it means a URL escaped rewriting |
| `fallback-prefix <id> /c/...` | The fallback caught such a request (recovery, not a failure) |
| `400-malformed line=...` | The first line could not be parsed |

## 4. Is the pump doing its job?

Set `DSH_RELAY_DEBUG=1` before starting `dsh web` to get per-request tracing from the pump. Without it, only state transitions and errors are logged (the pump sees every phone request, so unconditional tracing would flood the console).

The panel at `/relay-bridge/panel` shows the current status and the last transition, and `~/.dsh/plugin-data/dsh-relay-phone/audit.log` keeps the history across restarts.

## 5. Common symptoms

| Symptom | Likely cause | What to do |
|---|---|---|
| Panel shows `idle`, phone cannot connect | No relay host/key, or `autoStart: false` | Fill the panel and save; it connects immediately |
| `fingerprint-mismatch`, nothing else happens | Relay's agent certificate changed (reinstall, new host, new cert) | Accept the new pin in the panel if the change was expected; otherwise treat it as an attack |
| Phone shows the pairing page on every visit | Ticket cookie rejected or absent | Check the device clock, then re-scan the QR; rotating the identity also invalidates every old cookie |
| `envelope open failed` in the browser console | Phone and host derive different keys | Re-scan the QR: the QR carries the current PSK |
| Page loads but stays on "Loading plugins…" | Assets requested without the gate, or the boot payload was not rewritten | Look for `404-noprefix` on the relay; check the boot state via `window.__dshRelayBoot` |
| Settings/credentials panes say "unavailable in this browser" | DSH treats non-loopback origins as untrusted | The bridge marks relay-booted pages as trusted; if this regresses, check the `connection.isRelayBooted()` seam in your DSH build |
| Streaming stops mid-message | Keep-alive dropped an idle stream, or a NAT timeout killed it | Expect a reconnect; if it happens constantly, check the phone's network for aggressive NAT timeouts |
| Mobile page renders but images do not | Attachment fetch went upstream without the ticket | Reproduce with `DSH_RELAY_DEBUG=1` and watch for a plain request that should have been sealed |
| "Open full console" shows a blank window in the desktop app | The app blocks cross-origin navigation and hands `http(s)` targets to the system browser, so a host-rewritten link (`127.0.0.1` ↔ `localhost`) leaves the app — and the external browser may not reach `localhost` | Open the console same-origin: `<dsh origin>/relay-bridge/panel`. Current clients navigate in place and the page has a "back to DSH" link |
| Panel shows `idle` with an empty relay host after upgrading | Relay settings lived in the plugin's `cordis.patch.yml`; they now belong to the panel's saved config | Enter host/port/key once and save: it persists to `config.json` and reconnects immediately |
| Phone shows no reasoning or tool calls | Display settings hide them, or the session predates the fold that produces those rows | Open Settings → 显示 and pick 折叠 or 展开; the setting is per browser, stored in `localStorage`. Streaming reasoning ignores 折叠 |
| Tool command is cut off with "…" | That is the collapsed one-line preview | Tap anywhere on the card: the expanded body starts with the raw command, then the JSON arguments |
| An expanded tool card still shows only the one-line preview | The `open` class lives on the card, but the CSS opened the detail from `.item.tool.open`, which never matched, so the detail stayed `display:none` (fixed in 0.9.9) | Check that `.card.open .tool-detail` has a non-zero `offsetHeight`; the CDP test asserts exactly that, since `textContent` is readable through `display:none` and hid the bug |
| An expanded tool card snaps shut by itself | The host pushed a new item for that tool (result arrived), and the page rebuilds the node from it | Fixed in 0.8.1 by remembering expansion per session; older builds lose the state on every update |
| Composer sits above a black band, is clipped, or the whole page scrolls away while typing | `visualViewport` on iOS is not reliable (measured 104/157/174/332 across four focus sessions on one device), so any layout derived from it was wrong in one direction or the other; a `fixed` layer is also carried along by iOS's page scroll (the fixed debug bar sat mid-screen at `sy=497`) | Fixed in 0.9.6: the app lives in the document (absolute, full height), the composer sits at its bottom, and iOS's own scroll on focus puts it above the keyboard; blur scrolls back to the top. `#debug` shows `ih / vv / off / kbd / sy` live |
| Composer hidden behind the keyboard on the first tap | The page applied the pre-keyboard layout height at focus, before the layout settled | Fixed in 0.9.0: focus schedules a delayed apply instead of applying immediately |
| Phone has no permission switcher | The deployment does not mount `@deepseek-ai/dsh-permission-presets`, or the host still runs a bridge from before 0.6.0 | The chip shows 「权限」 as soon as a session is open; if it is missing entirely, restart `dsh web`. If tapping it says the sheet cannot switch, the preset service is not mounted — use the desktop `/permission` command |
| Permission chip shows 「权限」 instead of a preset | The client read the projection's host-internal shape (`{preset, sandbox, approval}`) while the wire view is `{currentValue}`; every field came back undefined, so nothing matched a preset (fixed in 0.9.1). Earlier causes on the way: a missing abort signal (0.8.4) | The page posts what it received (`perm session preset=… sandbox=…`) to the audit log. A cache checkpoint under `~/.dsh/storages/session_projcache/sessions/` holds the host-side state and proves whether the projection was ever empty |
| Phone terminal shows garbage such as `[?1004h` or `[4;22H` | The panel is a line buffer, not a terminal emulator, so the VT control sequences a shell emits were printed as text | Fixed in 0.10.3: the page strips CSI/OSC/naked-ESC sequences and normalises CR before display; the wire still carries the raw bytes |
| New session shows an empty "choose a model" | The model catalog could not be read, so the deployment default is unknown | Check that `model.catalog` answers; the chip falls back to the last model this phone picked, then to the host default |
| The relay panel returns `403` inside the desktop UI opened from a phone | The console prints the pairing URL (it embeds the PSK) and can change the relay key, so relayed requests are refused on purpose | Open `/relay-bridge/panel` on the machine running DSH instead |
| Relay says the key is unknown or disabled | The key matches no tenant on that relay, or the tenant was disabled | `dsh-relay-server tenant list` shows each key id; the panel prints the relay reason verbatim |
| Relay says today's traffic is used up | The tenant hit its daily quota (default 50 MB, UTC day). The relay cuts the connection and refuses re-registration until tomorrow | `dsh-relay-server tenant reset <name>` gives the day back; `tenant add --quota` changes the limit |
| Phone requests fail with `429 Too Many Requests` | The tenant hit its concurrent stream cap (`--max-streams-default`, default 32, `0` = unlimited): every open phone socket counts | Close extra tabs, or raise it with `tenant set <name> --max-streams 64` |
| Everything disconnects at once and the log says `egress limit reached` | The relay hit `--egress-limit`, the process-wide daily brake that does not depend on the per-tenant ledger | Wait for the next UTC day, raise the flag, and use `tenant list` to see which tenant was busy |
| Two machines share one tenant key | The relay allows one agent per tenant: the newest registration replaces and drops the older connection | Give each machine its own `tenant add` |

| A new session ignores the model you picked last | The host persists the pick through `agentDefaultModel.saveSelection`, which needs a writable profile config | Check the desktop picker applies it as well; the phone also caches the pick in `localStorage` (`dshRelayLastModel`) |

## 6. Resetting things

| Goal | Action |
|---|---|
| Re-pair one phone | Scan the QR again (same identity) |
| Revoke every phone | Panel → regenerate identity (deletes `identity.json`, rotates the PSK) |
| Change the relay key | Generate a new key on the relay, restart it, update the panel, restart `dsh web` |
| Start clean on the host | Stop `dsh web`, remove `~/.dsh/plugin-data/dsh-relay-phone/`, restart, pair again |

Rotating the identity keeps the relay's device registry entry until the new device id registers; the old entry is harmless but can be dropped from the relay's in-memory registry by restarting it.

## 7. Reproducing without a phone

The probes under `packages/plugin/scripts/` replay the important paths from a shell:

```sh
RELAY_BASE_URL=https://<relay-host>:8889 node packages/plugin/scripts/probe-sealed.mjs
RELAY_BASE_URL=https://<relay-host>:8889 node packages/plugin/scripts/probe-ws.mjs
```

They read the local identity, so they exercise the same keys the phone would. For UI-level problems, `npm run dev:mock` serves the page against a fixture host with no relay involved — if a bug also reproduces there, it is in the page, not the transport.
