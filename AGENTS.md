# Notes for AI coding agents

This repository is a small, security-sensitive codebase. Read this before changing anything.

## Ground rules

- **Never restart or kill the `dsh web` process you are running inside.** If you are an agent hosted by DSH, that process is your own host: killing it ends your session and takes the GUI down with it. When a change needs host-side code reloaded, say so in your final message and let the human restart it.
- **Do not put secrets in the tree.** No live relay keys, hostnames, deployment paths, or personal home directories. Configuration that identifies a deployment belongs in `~/.dsh/plugin-data/dsh-relay-bridge/config.json`, never in `cordis.patch.yml` or a test.
- **Keep tests hermetic.** `npm test` must pass with no relay, no network, and no running DSH. Anything that needs a deployment goes in `scripts/` as a probe, never in `test/`.

## Layout

| Path | Contains |
|---|---|
| `packages/relay/src/` | Phone listener, agent listener, TLS terminator |
| `packages/plugin/src/` | Host services: identity, crypto, pairing, pump, files, panel |
| `packages/plugin/src/mobile/` | Phone page transport, host bridge, event folding, assets |
| `packages/plugin/test/` | Hermetic tests, run by `test/run.mjs` |
| `packages/plugin/scripts/` | Mock host, CDP probes, live probes, syntax check |

## Commands

```sh
npm test            # hermetic suite
npm run check       # node --check on every source file
npm run test:ui     # CDP-driven UI test against the mock host (Chrome required)
npm run dev:mock    # run the mock host and print an entry URL
```

## Style

ES modules, two-space indent, single quotes, no semicolons, no build step. Comments explain why a thing is done (protocol quirks, version fences), not what the line does.

## When editing text files on Windows

Windows PowerShell 5.1 reads and writes UTF-8 files as GB2312/ANSI, which corrupts non-ASCII text: an em dash, arrow, or full-width question mark becomes a lone `?` and the file stops being valid UTF-8. Use PowerShell 7 (`pwsh`), Node.js, or the file-editing tools instead of `Get-Content | Set-Content` round trips.
