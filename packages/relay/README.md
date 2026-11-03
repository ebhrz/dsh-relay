# dsh-relay-server

A zero-knowledge relay for [`dsh-relay-bridge`](../plugin): it pairs a phone connection with your machine's outbound agent connection and forwards bytes, without accounts, a database, or the ability to read payloads.

Part of [dsh-relay](https://github.com/ebhrz/dsh-relay). Read the [main README](https://github.com/ebhrz/dsh-relay#readme) for the architecture and security model.

## Run

```sh
KEY="$(openssl rand -hex 24)"
npx dsh-relay-server --port 8889 --agent-port 9000 --key "$KEY"

# or from a clone
node src/index.mjs --port 8889 --agent-port 9000 --key "$KEY"
```

Two listeners:

| Port | Purpose |
|---|---|
| `--port` (default 8889) | Phones. Plain HTTP unless `--tls-cert`/`--tls-key` are given |
| `--agent-port` (default `port + 1`) | Agents. Always TLS; the certificate is self-signed and generated on first run unless provided |

State is limited to the generated agent certificate in `--data-dir` (default `~/.dsh-relay`); everything else is in memory.

## TLS for phones

Either terminate TLS in the relay itself:

```sh
node src/index.mjs --port 8443 --agent-port 9000 --key "$KEY" --tls-cert cert.pem --tls-key key.pem
```

or run the bundled terminator in front of a plain listener, with certificates from acme.sh/certbot:

```sh
node src/tls-terminator.mjs --port 8443 --upstream 8889 --cert-dir /etc/letsencrypt/live/example.com
```

The terminator reloads certificates when they change, so renewals need no restart.

## License

Apache-2.0
