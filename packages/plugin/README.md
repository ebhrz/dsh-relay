# dsh-relay-phone

DSH plugin that makes your local DeepSeek Harness reachable from your phone through a relay you host yourself.

It owns the device identity, the outbound connection to [`dsh-relay-server`](../relay), the pairing handshake, the encryption layer, and a phone-first page for chatting with the agent and answering its approvals.

Part of [dsh-relay](https://github.com/ebhrz/dsh-relay). Read the [main README](https://github.com/ebhrz/dsh-relay#readme) for the architecture, security model and deployment steps.

**Try it without running a relay:** <https://dshrelay.com:8443/> hands out a free
50 MB/day key (10 a day, resets at 00:00 UTC). Self-hosting is free too — that is
what the rest of this repository is for.

## Install

```sh
dsh plugin --profile web add dsh-relay-phone
```

From a checkout of the repository, point at the package instead:

```sh
dsh plugin --profile web add link:./packages/plugin
```

Restart `dsh web` afterwards (the plugin is host-side code), then configure it at `/relay-bridge/panel`. The panel is deliberately **desktop-only**: it prints the pairing link, which carries the device key, so requests that arrive through the relay are refused.

## Configuration

Saved by the panel to `~/.dsh/plugin-data/dsh-relay-phone/config.json`, which overrides the defaults in `cordis.patch.yml`:

| Key | Meaning |
|---|---|
| `relayScheme` | `http` or `https` |
| `relayHost`, `relayPort` | Relay address for phones |
| `agentPort` | Relay port for agent connections |
| `relayKey` | The key this deployment was given: a tenant key from `dsh-relay-server tenant add`, or the server's admin `--key` |
| `autoStart` | Connect on startup (default `true`) |

A paired phone opens the mobile page; the full desktop UI stays reachable at `/c/<id>/?desktop=1` (or the drawer's "Open full desktop UI"), which is also how the entry link works in a desktop browser.

## Tests

```sh
npm test          # hermetic: no relay, no dsh web, no network
npm run check     # syntax check every source file
npm run test:ui   # CDP-driven UI test against the mock host (needs Chrome)
```

## License

Apache-2.0
