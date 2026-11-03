# Contributing

Thanks for taking a look. This is a small codebase with an unusually security-sensitive job, so the rules are mostly about keeping the wire protocol honest.

## Development setup

```sh
git clone https://github.com/ebhrz/dsh-relay.git
cd dsh-relay
npm install                # both workspaces
npm test                   # hermetic suite, no relay and no dsh web needed
npm run check              # node --check over every source file
```

To exercise the phone page without a deployment:

```sh
npm run dev:mock           # prints a URL; open it in a mobile browser or device mode
npm run test:ui            # drives that mock host over CDP, writes screenshots to .tmp/mobile-ui
```

`test:ui` and the CDP probes need a Chromium-family browser. Set `CHROME_BIN` if it is not in a standard location; the UI test skips with a message when it cannot find one.

## Code style

- ES modules only; no build step, no bundler, no TypeScript.
- Two-space indent, single quotes, no semicolons, no trailing commas in parameters.
- Comments explain *why* (protocol quirks, DSH version fences, failure modes), not *what*.
- Client-side assets (`src/mobile/assets/`, `src/client/`) are hand-written and shipped as-is.

There is no linter yet; match the surrounding file instead.

## What needs tests

The hermetic suite must stay green. When you change behaviour, prefer a test in `packages/plugin/test/` that runs without any external service:

- `compat.test.mjs` — HTTP-level rewriting (query bytes, auth cookie, injection, relative assets)
- `keepalive.test.mjs` — connection reuse and self-delimiting responses
- `mobile-patch.test.mjs` — injected mobile patches
- `mobile-bridge.test.mjs` — host bridge against a fake Cordis context
- `mobile-transport.test.mjs` — page, assets, sealed RPC/WS over a fake relay

Probes under `packages/plugin/scripts/` are for manual checks against a real deployment and are not part of CI.

## Protocol changes

The wire format is shared by three moving parts (relay, pump, browser client). If you touch one of these, say so in the pull request and update the others in the same change:

- the `/c/<id>/` prefix and `?g=` gate handling
- the `x-relay-enc` / `x-relay-ct` envelope headers
- the `{__relay: <base64>}` WebSocket frame shape
- the boot payload keys (`__dshRelayBoot`, `__dshRelayMobile`)

## Security issues

Please do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contribution is licensed under the Apache License 2.0.
