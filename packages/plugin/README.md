# dsh-relay-bridge

DSH plugin that makes your local DeepSeek Harness reachable from your phone through a relay you host yourself.

It owns the device identity, the outbound connection to [`dsh-relay-server`](../relay), the pairing handshake, the encryption layer, and a phone-first page for chatting with the agent and answering its approvals.

Part of [dsh-relay](https://github.com/ebhrz/dsh-relay). Read the [main README](https://github.com/ebhrz/dsh-relay#readme) for the architecture, security model and deployment steps.

## Install

```sh
dsh plugin --profile web add link:./packages/plugin   # from a clone
```

Restart `dsh web` afterwards (the plugin is host-side code), then configure it at `/relay-bridge/panel`.

## Configuration

Saved by the panel to `~/.dsh/plugin-data/dsh-relay-bridge/config.json`, which overrides the defaults in `cordis.patch.yml`:

| Key | Meaning |
|---|---|
| `relayScheme` | `http` or `https` |
| `relayHost`, `relayPort` | Relay address for phones |
| `agentPort` | Relay port for agent connections |
| `relayKey` | Shared key, must match the server's `--key` |
| `autoStart` | Connect on startup (default `true`) |

## Tests

```sh
npm test          # hermetic: no relay, no dsh web, no network
npm run check     # syntax check every source file
npm run test:ui   # CDP-driven UI test against the mock host (needs Chrome)
```

## License

Apache-2.0
