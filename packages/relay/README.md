# dsh-relay-server

A zero-knowledge relay for [`dsh-relay-phone`](../plugin): it pairs a phone connection with your machine's outbound agent connection and forwards bytes, without accounts, a database of message content, or the ability to read payloads.

Part of [dsh-relay](https://github.com/ebhrz/dsh-relay). Read the [main README](https://github.com/ebhrz/dsh-relay#readme) for the architecture and security model.

## Run

```sh
npx dsh-relay-server --port 8889 --agent-port 9000
```

Two listeners:

| Port | Purpose |
|---|---|
| `--port` (default 8889) | Phones. Plain HTTP unless `--tls-cert`/`--tls-key` are given |
| `--agent-port` (default `port + 1`) | Agents. Always TLS; the certificate is self-signed and generated on first run unless provided |

State lives in `--data-dir` (default `~/.dsh-relay`): the generated agent certificate and the tenant ledger.

## Tenants (one key per user)

Each user gets their own relay key, a daily traffic quota, and their own agent
registration. Keys are stored as `sha256(key)` only — the plaintext key appears
once, in the output of `tenant add`.

```sh
dsh-relay-server tenant add --name alice --quota 100MB --note "demo"
# → prints alice's key; paste it into the DSH panel's relay key field

dsh-relay-server tenant list
dsh-relay-server tenant disable alice     # kicked on next reconnect
dsh-relay-server tenant enable alice
dsh-relay-server tenant reset alice       # zero today's usage
dsh-relay-server tenant remove alice
```

The agent sends a 12-character key id (the hash prefix) in `hello`, so the relay
finds the tenant without ever seeing the key. Both sides derive the same HMAC
secret from the key, so nothing changes on the client beyond the key itself.

Enforcement, in order:

1. **One agent per tenant.** A second agent with the same key replaces the first;
   the older connection is dropped. A demo machine is therefore never reachable
   twice.
2. **Daily quota** (`--quota-default`, default 100MB, UTC day). Bytes are counted
   in both directions and the connection is cut the moment the limit is reached:
   the agent gets `{t:'rejected', reason:'quota-exceeded'}` and the phone stream
   closes. It cannot re-register until the next day or a `tenant reset`.
3. **Disabled keys** are refused at `hello`, before a challenge is issued.

A single admin key can still be passed with `--key` (no quota, no tenant record)
— convenient for a personal deployment that does not need metering. The plugin
sends a key id either way; if it matches no tenant, the admin key is tried.

Usage is written to `<data-dir>/tenants.json` every 15 seconds and when a
connection closes, so a restart does not lose the day's ledger.

## TLS for phones

Either terminate TLS in the relay itself:

```sh
node src/index.mjs --port 8443 --agent-port 9000 --tls-cert cert.pem --tls-key key.pem
```

or run the bundled terminator in front of a plain listener, with certificates from acme.sh/certbot:

```sh
node src/tls-terminator.mjs --port 8443 --upstream 8889 --cert-dir /etc/letsencrypt/live/example.com
```

The terminator reloads certificates when they change, so renewals need no restart.

## Tests

```sh
npm test --workspace dsh-relay-server    # tenant ledger + a live loopback relay run
```

`relay-live.test.mjs` starts the real server on loopback ports: it registers a
tenant, routes a phone request, checks metering, then exhausts the quota and
asserts the cut-off and the refused re-registration.

## License

Apache-2.0
