#!/usr/bin/env node
// TLS terminator for dsh-relay.
//
// Terminates TLS on a public port and pipes the decrypted byte stream to the
// relay's phone listener. It exists for the common deployment where the relay
// itself runs plain HTTP on loopback and a certificate lives on the same host:
//
//   phone ──TLS:8443──► tls-terminator ──plain TCP──► relay --port 8889
//
// Node's tls.createServer hands the connection callback DECRYPTED sockets, so
// this is a pure byte pipe with no HTTP parsing in between. The certificate
// files are watched and reloaded when their mtime changes, so an acme.sh/certbot
// renewal takes effect without restarting anything.
//
// Usage:
//   node src/tls-terminator.mjs --port 8443 --upstream 8889 \
//     --cert-dir ~/.dsh-relay/certs [--cert fullchain.pem] [--key privkey.pem]
//
// Any option can also come from the environment (DSH_RELAY_CERT_DIR,
// DSH_RELAY_CERT_FILE, DSH_RELAY_KEY_FILE).
//
// Design notes:
//   * handshakeTimeout drops scanners that open TCP and never finish the
//     ClientHello. Without it those sockets are held forever, and a public
//     port leaks file descriptors until it can no longer accept handshakes.
//   * keepalive detects peers that vanished without FIN/RST (mobile radio
//     drops, NAT timeouts) instead of holding half-open tunnels forever.
//   * close handlers use end() rather than destroy() so a pending chunked
//     response is flushed instead of reset.

import tls from 'node:tls'
import fs from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import os from 'node:os'

const VERSION = '0.1.0'

function usage() {
  return `dsh-relay TLS terminator ${VERSION}

  --port <n>            public TLS port (default 8443)
  --upstream <n>        plain port of the relay phone listener (default 8889)
  --upstream-host <ip>  where that listener runs (default 127.0.0.1)
  --cert-dir <dir>      directory holding the cert and key
                        (default ~/.dsh-relay/certs)
  --cert <file>         certificate file name inside --cert-dir
                        (default fullchain.pem)
  --key <file>          private key file name inside --cert-dir
                        (default privkey.pem)

Environment: DSH_RELAY_CERT_DIR, DSH_RELAY_CERT_FILE, DSH_RELAY_KEY_FILE.`
}

const args = {
  port: 8443,
  upstreamHost: '127.0.0.1',
  upstreamPort: 8889,
  certDir: process.env.DSH_RELAY_CERT_DIR ?? path.join(os.homedir(), '.dsh-relay', 'certs'),
  certFile: process.env.DSH_RELAY_CERT_FILE ?? 'fullchain.pem',
  keyFile: process.env.DSH_RELAY_KEY_FILE ?? 'privkey.pem',
}

const flags = {
  '--port': (v) => { args.port = Number(v) },
  '--upstream': (v) => { args.upstreamPort = Number(v) },
  '--upstream-host': (v) => { args.upstreamHost = v },
  '--cert-dir': (v) => { args.certDir = v },
  '--cert': (v) => { args.certFile = v },
  '--key': (v) => { args.keyFile = v },
}

for (let i = 2; i < process.argv.length; i += 1) {
  const flag = process.argv[i]
  if (flag === '--help' || flag === '-h') {
    console.log(usage())
    process.exit(0)
  }
  if (flag === '--version') {
    console.log(VERSION)
    process.exit(0)
  }
  const apply = flags[flag]
  if (!apply) {
    console.error(`unknown argument ${flag}\n\n${usage()}`)
    process.exit(1)
  }
  if (i + 1 >= process.argv.length) {
    console.error(`missing value for ${flag}`)
    process.exit(1)
  }
  i += 1
  apply(process.argv[i])
}

if (!Number.isInteger(args.port) || args.port <= 0) {
  console.error('--port must be a positive integer')
  process.exit(1)
}
if (!Number.isInteger(args.upstreamPort) || args.upstreamPort <= 0) {
  console.error('--upstream must be a positive integer')
  process.exit(1)
}

const certPath = path.resolve(args.certDir, args.certFile)
const keyPath = path.resolve(args.certDir, args.keyFile)

function loadCerts() {
  return { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) }
}

function log(...parts) {
  console.log(new Date().toISOString(), '[tls-term]', ...parts)
}

let server = null
let certMtime = ''

function stamp() {
  return `${fs.statSync(certPath).mtimeMs}/${fs.statSync(keyPath).mtimeMs}`
}

function start() {
  const certs = loadCerts()
  certMtime = stamp()
  // The terminator is a raw TLS pipe, so one address opening sockets is exactly as
  // cheap for it as for the relay: bound both the total and the per-address count
  // at accept, or a single host can fill every pre-auth slot behind it.
  const socketsByIp = new Map()
  const MAX_SOCKETS_PER_IP = Number(process.env.DSH_RELAY_TERMINATOR_PER_IP ?? 32)
  const MAX_TOTAL = Number(process.env.DSH_RELAY_TERMINATOR_MAX ?? 512)
  let open = 0
  server = tls.createServer({ ...certs, handshakeTimeout: 15_000 }, (socket) => {
    open += 1
    const ip = socket.remoteAddress ?? 'unknown'
    const perIp = (socketsByIp.get(ip) ?? 0) + 1
    socketsByIp.set(ip, perIp)
    let released = false
    socket.once('close', () => {
      if (released) return
      released = true
      open -= 1
      const left = (socketsByIp.get(ip) ?? 1) - 1
      if (left <= 0) socketsByIp.delete(ip)
      else socketsByIp.set(ip, left)
    })
    if (perIp > MAX_SOCKETS_PER_IP || open > MAX_TOTAL) {
      log(`too many connections (${ip} -> ${perIp}, total ${open}) -> refusing`)
      try { socket.destroy() } catch {}
      return
    }
    const upstream = net.connect({ host: args.upstreamHost, port: args.upstreamPort })
    upstream.setNoDelay(true)
    socket.setNoDelay(true)
    socket.setKeepAlive(true, 60_000)
    upstream.setKeepAlive(true, 60_000)
    socket.pipe(upstream)
    upstream.pipe(socket)
    const die = () => {
      try { socket.destroy() } catch {}
      try { upstream.destroy() } catch {}
    }
    socket.on('error', die)
    upstream.on('error', die)
    // Graceful halves: end() flushes pending write buffers before FIN;
    // destroy() would RST and truncate an in-flight chunked response.
    socket.on('close', () => { try { upstream.end() } catch { try { upstream.destroy() } catch {} } })
    upstream.on('close', () => { try { socket.end() } catch { try { socket.destroy() } catch {} } })
  })
  server.listen(args.port, '0.0.0.0', () => {
    log(`listening :${args.port} -> ${args.upstreamHost}:${args.upstreamPort}`)
    log(`cert ${certPath}`)
  })
  server.on('tlsClientError', (err) => {
    // Handshake failures are routine scanner noise on a public port; Node
    // destroys the socket. Only the timeout cause is worth a log line.
    if (err?.code === 'ERR_TLS_HANDSHAKE_TIMEOUT') log('handshake timeout (probe dropped)')
  })
  server.on('error', (e) => { log('server error', e.message); process.exit(1) })
}

// Hot reload, without dropping anyone.
//
// The old version closed the listener and called closeAllConnections() two
// seconds later, so a renewal cut every live phone stream — and a certificate
// file that failed to parse took the whole listener down with it. setSecureContext
// swaps the certificate for *new* handshakes only; established tunnels keep the
// context they negotiated with, and a failed load keeps the previous one.
setInterval(() => {
  try {
    if (stamp() === certMtime) return
    let certs
    try {
      certs = loadCerts()
    } catch (error) {
      log(`cert reload failed, keeping the current certificate: ${error.message}`)
      return
    }
    try {
      server.setSecureContext(certs)
    } catch (error) {
      log(`cert reload rejected, keeping the current certificate: ${error.message}`)
      return
    }
    certMtime = stamp()
    log('certificate reloaded for new connections (established ones kept)')
  } catch (error) {
    log(`cert watch error: ${error.message}`)
  }
}, Number(process.env.DSH_RELAY_CERT_POLL_MS ?? 60_000))

start()
