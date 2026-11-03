# Security policy

## Reporting a vulnerability

Email **ebhrz1@163.com** with the details, or open a private security advisory on GitHub. Please do not file a public issue.

Include what you did, what you observed, and what an attacker gains. A proof of concept helps; so does the version (`packages/plugin/package.json`) and how the relay is exposed (TLS terminator, reverse proxy, plain HTTP, private network).

Expect an initial reply within a few days. This is a personal project, not a company with an on-call rotation.

## Threat model

What dsh-relay is designed to defend against:

- **A curious or compromised relay operator.** The relay routes bytes; payloads are sealed end to end with a key derived from the phone's PSK. The relay learns device ids, gates, connection metadata, sizes, timing and client IPs.
- **Passive network observers.** API bodies and WebSocket frames are ciphertext on the wire in every mode.
- **Scanner noise and opportunistic abuse.** Without the shared agent key an agent cannot register; without the `?g=` gate a request never reaches a machine.
- **Replay against the pairing handshake.** Challenge-response with a server nonce, a 60-second challenge window, and a ticket cookie that is only issued after proof.

What it does **not** defend against:

- **An active attacker who can rewrite the page shell.** In the default no-domain mode the HTML/JS is delivered over the same channel as the ciphertext, so someone who can rewrite traffic can serve different JavaScript. Put a real TLS certificate in front of the relay (or use a private network) if that is in your threat model. This is documented in the README as a residual risk, not a bug.
- **A compromised phone.** A paired device holds a ticket for 30 days and has the same authority as the desktop UI it drives. Rotate the identity from the panel when a device is lost.
- **A compromised local machine.** The bridge runs inside `dsh web` with your user's privileges; the file endpoints read whatever that user can read.
- **Denial of service against the relay.** There is no rate limiting; anyone who can reach the phone port can consume connections.

## Hardening checklist for operators

- Terminate TLS in front of the phone port, or keep the relay on a private network.
- Use a long random `--key` (`openssl rand -hex 24`) and do not reuse it elsewhere.
- Keep the agent port reachable only by your machine if your network allows it.
- Watch the relay log for `agent rejected`, and the panel's audit log for unexpected pairing.
- Rotate the device identity after losing a phone.
