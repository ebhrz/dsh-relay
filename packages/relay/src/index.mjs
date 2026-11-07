#!/usr/bin/env node
// dsh-relay-server — zero-knowledge relay for dsh-relay-phone.
//
// Two listeners:
//   --port (HTTP, phones)   /c/<id>/<path>?g=<gate>  → raw TCP relay into the
//                           agent's multiplexed WSS connection. Only request
//                           line 1 is parsed (to route + strip the /c/<id>
//                           prefix and the g= query); every other byte flows
//                           untouched, so the relay never needs to understand
//                           the payload (it is end-to-end encrypted anyway).
//   --agent-port (WSS)      agent registration gated by an HMAC challenge over
//                           --key; then carries control frames (JSON text) and
//                           stream data frames (4-byte big-endian sid prefix).
//
// No accounts, no database, no content inspection.

import https from 'node:https'
import net from 'node:net'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { execFileSync } from 'node:child_process'
import { WebSocketServer } from 'ws'
import {
  DEFAULT_MAX_STREAMS,
  DEFAULT_QUOTA_BYTES,
  TenantStore,
  formatBytes,
  parseQuota,
} from './tenants.js'

// Read from the manifest so a release bump cannot leave --version or the boot
// log claiming an older build.
const VERSION = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version

// How much unread data a phone may accumulate before its stream is dropped.
// Bounds relay memory when a client opens a stream and stops reading.
const MAX_PHONE_BACKLOG = 4 * 1024 * 1024

function parseArgs(argv) {
  const args = {
    host: '0.0.0.0',
    agentHost: null, // default: 0.0.0.0 even when --host is loopback
    port: 8889,
    agentPort: null, // default: port + 1
    key: process.env.DSH_RELAY_KEY ?? null,
    quotaDefault: DEFAULT_QUOTA_BYTES,
    maxStreamsDefault: DEFAULT_MAX_STREAMS,
    egressLimit: 0, // 0 = no process-wide brake
    maxConnections: 512, // per listener; 0 = unlimited
    preAuthTimeoutMs: 15_000, // a client must send a request line within this
    dataDir: path.join(os.homedir(), '.dsh-relay'),
    tlsCert: null,
    tlsKey: null,
  }
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i]
    const next = () => {
      if (i + 1 >= argv.length) fail(`missing value for ${a}`)
      i += 1
      return argv[i]
    }
    switch (a) {
      case '--port': args.port = Number(next()); break
      case '--agent-port': args.agentPort = Number(next()); break
      case '--host': args.host = next(); break
      case '--agent-host': args.agentHost = next(); break
      case '--key': args.key = next(); break
      case '--quota-default': {
        const parsed = parseQuota(next())
        if (!parsed) fail('bad --quota-default (use e.g. 100MB)')
        args.quotaDefault = parsed
        break
      }
      case '--max-streams-default': {
        const parsed = Number(next())
        if (!Number.isInteger(parsed) || parsed < 0) fail('bad --max-streams-default (0 = unlimited)')
        args.maxStreamsDefault = parsed
        break
      }
      case '--egress-limit': {
        const raw = next()
        if (/^(0|off|unlimited)$/i.test(raw)) {
          args.egressLimit = 0
          break
        }
        const parsed = parseQuota(raw)
        if (!parsed) fail('bad --egress-limit (use e.g. 2GB, or 0 to disable)')
        args.egressLimit = parsed
        break
      }
      case '--max-connections': {
        const parsed = Number(next())
        if (!Number.isInteger(parsed) || parsed < 0) fail('bad --max-connections (0 = unlimited)')
        args.maxConnections = parsed
        break
      }
      case '--pre-auth-timeout': {
        const parsed = Number(next())
        if (!Number.isInteger(parsed) || parsed < 1000) fail('bad --pre-auth-timeout (milliseconds, >= 1000)')
        args.preAuthTimeoutMs = parsed
        break
      }
      case '--data-dir': args.dataDir = next(); break
      case '--tls-cert': args.tlsCert = next(); break
      case '--tls-key': args.tlsKey = next(); break
      case '--version': console.log(VERSION); process.exit(0)
      case '--help':
      case '-h':
        console.log(usage()); process.exit(0)
      default: fail(`unknown argument ${a}`)
    }
  }
  if (args.key != null && args.key.length < 8) {
    fail('--key must be at least 8 chars (or omit it and use tenants instead)')
  }
  if (args.agentPort == null) args.agentPort = args.port + 1
  if (args.agentHost == null) args.agentHost = "0.0.0.0"
  return args
}

function usage() {
  return `dsh-relay-server ${VERSION}

  --port <n>          HTTP listener for phones (default 8889)
  --agent-port <n>    WSS listener for agents (default port+1)
  --host <addr>       bind address for the PHONE listener (default 0.0.0.0;
                      put it behind a TLS proxy and use 127.0.0.1)
  --agent-host <addr> bind address for the AGENT listener (default 0.0.0.0:
                      agents dial in from outside)
  --key <secret>      admin registration key (optional; tenants are the normal path)
  --quota-default <n> daily quota for new tenants (default 50MB; 0 = unlimited)
  --max-streams-default <n> concurrent streams per tenant (default 32; 0 = unlimited)
  --egress-limit <n>  process-wide daily byte brake across all connections,
                      admin key included (default 0 = off; e.g. 2GB for a demo)
  --max-connections <n> socket cap per listener (default 512; 0 = unlimited)
  --pre-auth-timeout <ms> drop a phone connection that sends no request line
                      within this window (default 15000)
  --tls-cert <pem>    custom TLS cert for the agent listener (default: auto
                      self-signed into --data-dir)
  --tls-key <pem>     custom TLS key for the agent listener
  --data-dir <dir>    state dir for the cert and the tenant ledger (default ~/.dsh-relay)
  --version           print the version and exit

Tenants (one key per user, each with a daily quota and a stream cap):

  dsh-relay-server tenant add --name <name> [--quota 100MB] [--max-streams 32] [--note text]
  dsh-relay-server tenant list
  dsh-relay-server tenant show <name>
  dsh-relay-server tenant set <name> [--quota 200MB] [--max-streams 0]
  dsh-relay-server tenant disable <name> | enable <name>
  dsh-relay-server tenant reset <name>      (zero today's usage)
  dsh-relay-server tenant remove <name>

  Changes apply to a running server immediately; 0 means unlimited for both limits.
`
}

function fail(message) {
  console.error(`dsh-relay-server: ${message}`)
  process.exit(1)
}

function log(...parts) {
  console.log(new Date().toISOString(), ...parts)
}

function timingSafeEqual(a, b) {
  const ba = Buffer.from(a ?? '')
  const bb = Buffer.from(b ?? '')
  if (ba.length !== bb.length || ba.length === 0) return false
  return crypto.timingSafeEqual(ba, bb)
}

/**
 * `?g=<gate>` is a bearer credential for the phone path: it is fine on the wire,
 * but it has no business in a log line.
 */
function redactGate(text) {
  return String(text).replace(/([?&]g=)[0-9a-fA-F]{16,}/g, '$1<redacted>')
}

// ---------------------------------------------------------------------------
// Self-signed certificate for the agent listener (the agent pins the
// fingerprint, so a CA-signed cert is unnecessary). openssl on first run.
// ---------------------------------------------------------------------------

function ensureSelfSignedCert(args) {
  if (args.tlsCert && args.tlsKey) {
    return { cert: fs.readFileSync(args.tlsCert), key: fs.readFileSync(args.tlsKey) }
  }
  fs.mkdirSync(args.dataDir, { recursive: true })
  const certPath = path.join(args.dataDir, 'agent-cert.pem')
  const keyPath = path.join(args.dataDir, 'agent-key.pem')
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    log('generating self-signed cert via openssl ...')
    // Some Windows installs ship an openssl whose OPENSSL_CONF points at a file
    // that does not exist, which makes any invocation fail. A config of our own
    // removes that dependency without touching the machine's settings.
    const confPath = path.join(args.dataDir, 'openssl.cnf')
    fs.writeFileSync(confPath, [
      '[req]',
      'distinguished_name = dn',
      'x509_extensions = v3',
      'prompt = no',
      '[dn]',
      'CN = dsh-relay-agent',
      '[v3]',
      'basicConstraints = critical,CA:TRUE',
      'keyUsage = digitalSignature,keyEncipherment',
      'subjectAltName = DNS:dsh-relay-agent',
      '',
    ].join('\n'))
    try {
      execFileSync('openssl', [
        'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
        '-keyout', keyPath, '-out', certPath,
        '-days', '3650', '-nodes', '-subj', '/CN=dsh-relay-agent',
        '-config', confPath,
      ], { stdio: 'pipe' })
    } catch (error) {
      fail(`cannot generate self-signed cert (openssl missing or misconfigured): ${error.message}\n` +
        'Provide --tls-cert/--tls-key instead, or point OPENSSL_CONF at a working openssl.cnf.')
    }
  }
  return { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) }
}

// ---------------------------------------------------------------------------
// Agent registry + stream bookkeeping
// ---------------------------------------------------------------------------

class AgentEntry {
  constructor(ws, gate, tenant = null, id = '') {
    this.ws = ws
    this.gate = gate // hex string supplied by the agent (derived from its PSK)
    this.streams = new Set() // sids owned by this connection
    this.alive = true
    this.tenant = tenant // null for the legacy admin --key
    this.quotaTripped = false
    this.id = id
    this.key = '' // registry key: tenant-scoped, so two tenants can reuse a device id
  }
}

/**
 * Agents are registered per (tenant, device id), not per device id. Two tenants
 * may legitimately pick the same 8-character id; keying only by id let one of
 * them knock the other's connection offline and made the phone dispatch
 * ambiguous.
 */
const agents = new Map() // `${tenantId}:${deviceId}` -> AgentEntry
const deviceIndex = new Map() // deviceId -> Set of registry keys
const phoneByStream = new Map() // sid -> PhoneConn
const tenantAgent = new Map() // tenant id -> { id, entry }
/**
 * Devices the relay cut on purpose, keyed by device id, so the phone gets a
 * precise answer ("your quota is used up") instead of the generic "device is
 * offline" that also covers a machine that simply has not reconnected.
 * Entries are cleared when the device registers again and ignored after the UTC
 * day rollover.
 */
const blockedDevices = new Map() // device id -> { reason, day }
let tenantStore = null // set in main()
let nextSid = 1

function agentKey(tenant, id) {
  return `${tenant ? tenant.id : '*admin*'}:${id}`
}

function indexEntry(entry) {
  agents.set(entry.key, entry)
  let set = deviceIndex.get(entry.id)
  if (!set) {
    set = new Set()
    deviceIndex.set(entry.id, set)
  }
  set.add(entry.key)
}

function forgetEntry(entry) {
  agents.delete(entry.key)
  const set = deviceIndex.get(entry.id)
  if (!set) return
  set.delete(entry.key)
  if (set.size === 0) deviceIndex.delete(entry.id)
}

/** Every live agent claiming this device id (one per tenant at most). */
function entriesForDevice(id) {
  const keys = deviceIndex.get(id)
  if (!keys) return []
  const out = []
  for (const key of keys) {
    const entry = agents.get(key)
    if (entry) out.push(entry)
  }
  return out
}

/**
 * Process-wide egress fail-safe. Per-tenant quotas are the policy; this is the
 * brake that does not depend on the ledger being right — if the whole process
 * has pushed more than `--egress-limit` bytes today, everything is cut.
 * 0 means unlimited (the default), which keeps a personal relay untouched.
 */
let egressDay = ''
let egressBytes = 0
let egressTripped = false

function chargeEgress(bytes) {
  if (!(bytes > 0)) return egressTripped
  const day = quotaDayNow()
  if (egressDay !== day) {
    // A new day gets a fresh budget, including the latch: otherwise the brake
    // would fire once per process lifetime and stay silent forever after.
    egressDay = day
    egressBytes = 0
    egressTripped = false
  }
  egressBytes += bytes
  const over = args.egressLimit > 0 && egressBytes >= args.egressLimit
  if (over && !egressTripped) {
    egressTripped = true
    log(`egress limit reached: ${formatBytes(egressBytes)} today >= ${formatBytes(args.egressLimit)}; closing every connection`)
    for (const live of agents.values()) closeEntry(live, 'egress-limit')
    tenantStore?.saveIfDirty()
  }
  return over
}

/** True while the brake is holding everything shut for today. */
function egressBlocked() {
  return egressTripped && egressDay === quotaDayNow()
}


function allocSid() {
  const sid = nextSid
  nextSid = nextSid + 1
  if (nextSid > 0xffffffff) nextSid = 1
  return sid
}

/** Drop one agent connection and every phone stream riding on it. */
function closeEntry(entry, reason) {
  if (!entry) return
  entry.alive = false
  // Remember why this device was cut, so its phone can be told the reason
  // instead of reading a generic "offline" page.
  if (entry.id) blockedDevices.set(entry.id, { reason, day: quotaDayNow() })
  for (const sid of [...entry.streams]) {
    const phone = phoneByStream.get(sid)
    if (phone) phone.destroy(false)
  }
  // Tell the agent why before the socket goes away. `terminate()` right after
  // `send()` can drop the frame — the client would then retry without knowing
  // it was cut for quota or because the key was disabled.
  try { entry.ws.send(JSON.stringify({ t: 'rejected', reason })) } catch {}
  try { entry.ws.close() } catch {}
  const kill = setTimeout(() => { try { entry.ws.terminate() } catch {} }, 500)
  kill.unref?.()
}

/**
 * Book bytes against the tenant's day and cut the connection the moment the
 * quota is reached — once, not on every later frame.
 *
 * The process-wide brake is charged first and for every entry, including the
 * admin --key path that has no tenant record: the README promises that it
 * counts every byte the relay carries, and an unmetered admin path would make
 * that promise false exactly where a cloud bill is at stake.
 */
function charge(entry, bytes) {
  if (!(bytes > 0)) return
  const tenant = entry?.tenant
  const over = tenant && tenantStore ? tenantStore.charge(tenant, bytes).over : false
  if (chargeEgress(bytes)) return
  if (!over || entry.quotaTripped) return
  entry.quotaTripped = true
  log(`quota exhausted tenant=${tenant.id} used=${formatBytes(tenant.usedBytesDay)} limit=${formatBytes(tenant.quotaBytesDay)}`)
  tenantStore.saveIfDirty()
  closeEntry(entry, 'quota-exceeded')
}

function sidPrefix(sid) {
  const b = Buffer.alloc(4)
  b.writeUInt32BE(sid >>> 0, 0)
  return b
}

function sendStream(entry, sid, chunk) {
  if (!entry.alive || entry.ws.readyState !== 1) return
  entry.ws.send(Buffer.concat([sidPrefix(sid), chunk]), { binary: true })
}

function sendControl(entry, object) {
  if (!entry.alive || entry.ws.readyState !== 1) return
  entry.ws.send(JSON.stringify(object))
}

// ---------------------------------------------------------------------------
// Phone connection: one hijacked TCP socket bridged into one agent stream.
// ---------------------------------------------------------------------------

class PhoneConn {
  constructor(socket, entry, sid, firstLine, remainder) {
    this.socket = socket
    this.entry = entry
    this.sid = sid
    this.closed = false
    socket.setNoDelay(true)
    socket.on('data', (chunk) => {
      if (this.closed || entry.ws.readyState !== 1) return
      charge(entry, chunk.length)
      if (this.closed) return
      sendStream(entry, sid, chunk)
    })
    const finish = () => this.destroy(true)
    socket.on('close', finish)
    socket.on('error', finish)
    // The rewritten request line (or the full buffered head for cookie-gate
    // requests) and anything behind it go upstream. These bytes cross the relay
    // too, so they are booked like every other frame.
    const head = Buffer.isBuffer(firstLine) ? firstLine : Buffer.from(firstLine, 'latin1')
    charge(entry, head.length + remainder.length)
    if (this.closed) return
    sendStream(entry, sid, head)
    if (remainder.length > 0) sendStream(entry, sid, remainder)
  }

  sendToClient(chunk) {
    if (this.closed) return
    // A phone that opens a stream and then never reads must not make the relay
    // buffer it forever: past this much pending data the stream is dropped and
    // the agent is told, which is what a stalled HTTP client deserves.
    if (this.socket.writableLength > MAX_PHONE_BACKLOG) {
      log(`phone-backlog sid=${this.sid} pending=${this.socket.writableLength} -> closing`)
      this.destroy(true)
      return
    }
    this.socket.write(chunk)
  }

  // notifyAgent=false when the agent itself asked to close this stream.
  destroy(notifyAgent = true) {
    if (this.closed) return
    this.closed = true
    phoneByStream.delete(this.sid)
    this.entry.streams.delete(this.sid)
    // Graceful close: end() flushes any pending write buffer before FIN —
    // destroy() would RST and truncate large in-flight responses.
    try {
      this.socket.once('error', () => { try { this.socket.destroy() } catch {} })
      this.socket.end()
    } catch {
      try { this.socket.destroy() } catch {}
    }
    if (notifyAgent) sendControl(this.entry, { t: 'close', sid: this.sid })
  }
}

// ---------------------------------------------------------------------------
// Phone listener (raw TCP; only request line 1 is interpreted)
// ---------------------------------------------------------------------------

function startPhoneListener(args) {
  // Plain HTTP by design: in the TLS deployment a reverse proxy (Caddy with
  // automatic Let's Encrypt) terminates TLS in front of this port.
  const server = net.createServer((socket) => handlePhoneSocket(args, socket))
  // Bound the socket count: without this an unauthenticated client can open
  // connections until file descriptors run out.
  if (args.maxConnections > 0) server.maxConnections = args.maxConnections

  server.listen(args.port, args.host, () => {
    log(`phone listener: http://${args.host}:${args.port}/c/<id>/?g=<gate> (max ${args.maxConnections} conns)`)
  })
  return server
}

function handlePhoneSocket(args, socket) {
  socket.setNoDelay(true)
  // Nothing is authenticated until a request line arrives, and the concurrency
  // cap only applies after that: a client that connects and stays silent would
  // otherwise hold a descriptor forever (slowloris).
  socket.setTimeout(args.preAuthTimeoutMs, () => {
    if (socket.destroyed) return
    log('phone-timeout: no complete request line, closing')
    socket.destroy()
  })
    let buffer = Buffer.alloc(0)

    const onFirstLine = (line, gateCookie, fullHead) => {
      // line: "METHOD /c/<id>/path?query HTTP/1.1"
      // Pure routing only: the id/gate are read to decide whether the
      // connection may be bridged, but the request line is forwarded
      // UNCHANGED — prefix and gate stripping is the agent pump's job.
      // The gate comes from ?g= when present, else from the __relay_g cookie
      // (set at pairing; relative ES-module imports drop the query).
      // Fallback routing: an app request that escapes the boot URL-rewrite
      // layer arrives WITHOUT the /c/<id> prefix but still carries the
      // pairing cookies — rewrite the first line under the prefix and route.
      const sp = line.indexOf(' ')
      const sp2 = line.indexOf(' ', sp + 1)
      if (sp <= 0 || sp2 <= sp) {
        log(`400-malformed line=${JSON.stringify(line.slice(0, 80))}`)
        return tinyResponse(socket, 400, 'Bad Request', 'malformed request line\n')
      }
      let target = line.slice(sp + 1, sp2)
      let q = target.indexOf('?')
      let rawPath = q === -1 ? target : target.slice(0, q)
      let rawQuery = q === -1 ? '' : target.slice(q + 1)

      if (rawPath === '/' || rawPath === '/healthz') {
        return tinyResponse(socket, 200, 'OK', 'dsh-relay-server running\n')
      }
      let m = rawPath.match(/^\/c\/([A-Za-z0-9]{4,16})(\/.*)?$/)
      if (!m && fullHead) {
        // No prefix and no query gate: the cookie-recovery path already
        // buffered the full head — look for the identity cookies.
        const headText = fullHead.toString('latin1')
        const cookieLine = headText.match(/(?:^|\r\n)cookie:\s*([^\r\n]*)/i)
        const cid = cookieLine ? /(?:^|;\s*)__relay_i=([A-Za-z0-9]{4,16})(?:;|$)/.exec(cookieLine[1])?.[1] : ''
        const cgate = cookieLine ? /(?:^|;\s*)__relay_g=([a-f0-9]{16,128})(?:;|$)/.exec(cookieLine[1])?.[1] : ''
        if (cid && cgate) {
          // Several tenants may use the same device id, so the cookie gate
          // decides which one this browser belongs to.
          const centry = entriesForDevice(cid).find((candidate) => timingSafeEqual(cgate, candidate.gate))
          if (centry) {
            const rewritten = `/c/${cid}${rawPath === '' ? '/' : rawPath}`
            const rQuery = rawQuery === '' ? '' : `?${rawQuery}`
            line = `${line.slice(0, sp + 1)}${rewritten}${rQuery} ${line.slice(sp2 + 1)}`
            // PhoneConn ships fullHead — replace its first line with the
            // rewritten one or the prefix never reaches the pump.
            const firstLineEnd = fullHead.indexOf('\r\n')
            fullHead = Buffer.concat([
              Buffer.from(`${line}\r\n`, 'latin1'),
              fullHead.subarray(firstLineEnd === -1 ? fullHead.length : firstLineEnd + 2),
            ])
            target = `${rewritten}${rQuery}`
            rawPath = rewritten
            m = rewritten.match(/^\/c\/([A-Za-z0-9]{4,16})(\/.*)?$/)
            gateCookie = cgate
            log(`fallback-prefix ${cid} ${rewritten.slice(0, 40)}`)
          }
        }
      }
      if (!m) {
        var headText2 = fullHead ? fullHead.toString('latin1') : ''
        var refLine = headText2.match(/referer:\s*([^\r\n]*)/i)
        log(`404-noprefix ${line.split(' ').slice(0, 2).join(' ')} ref=${refLine ? refLine[1].slice(0, 70) : 'none'}`)
        return tinyResponse(socket, 404, 'Not Found',
          `dsh-relay: unknown path ${rawPath}. Phones open /c/<id>/?g=<gate> links from the dsh-relay-phone settings page.\n`)
      }
      const id = m[1]
      if (egressBlocked()) {
        return tinyResponse(socket, 503, 'Service Unavailable',
          'dsh-relay: the whole relay has used up its daily traffic budget. It resets at 00:00 UTC.\n')
      }
      const candidates = entriesForDevice(id)
      if (!candidates.length) {
        // A device that was cut on purpose gets the real reason; anything else
        // is simply not connected right now.
        const blocked = blockedDevices.get(id)
        if (blocked && blocked.day === quotaDayNow()) {
          if (blocked.reason === 'egress-limit') {
            return tinyResponse(socket, 503, 'Service Unavailable',
              'dsh-relay: the whole relay has used up its daily traffic budget. It resets at 00:00 UTC.\n')
          }
          if (blocked.reason === 'quota-exceeded') {
            return tinyResponse(socket, 429, 'Too Many Requests',
              "dsh-relay: this key's traffic for today is used up. It resets at 00:00 UTC.\n")
          }
          if (blocked.reason === 'key-disabled') {
            return tinyResponse(socket, 403, 'Forbidden',
              'dsh-relay: this key is disabled on the relay.\n')
          }
        }
        return tinyResponse(socket, 503, 'Service Unavailable',
          'dsh-relay: device is offline (its dsh-relay-phone is not connected). Retry later.\n')
      }
      const params = new URLSearchParams(rawQuery)
      const gate = params.get('g') ?? gateCookie
      // The gate names the deployment; with tenant-scoped registrations the same
      // device id can exist in several tenants, and the gate picks the right one.
      const entry = /^[a-f0-9]{16,128}$/.test(gate ?? '')
        ? candidates.find((candidate) => timingSafeEqual(gate, candidate.gate))
        : null
      if (!entry) {
        log(`403 id=${id} candidates=${candidates.length} gatePresent=${Boolean(gate)}`)
        return tinyResponse(socket, 403, 'Forbidden', 'dsh-relay: bad gate.\n')
      }
      // Concurrency cap: one stream is one phone socket held open on this box.
      // The admin key (no tenant) is never capped; a tenant with maxStreams 0 is
      // unlimited too.
      const maxStreams = entry.tenant?.maxStreams ?? 0
      if (maxStreams > 0 && entry.streams.size >= maxStreams) {
        log(`429-streams id=${id} tenant=${entry.tenant.id} active=${entry.streams.size} limit=${maxStreams}`)
        return tinyResponse(socket, 429, 'Too Many Requests',
          `dsh-relay: this key allows ${maxStreams} concurrent streams (${entry.streams.size} in use). Close another tab or retry in a moment.\n`)
      }
      const sid = allocSid()
      entry.streams.add(sid)
      const firstBytes = fullHead ?? Buffer.from(`${line}\r\n`, 'latin1')
      log(`phone-start sid=${sid} firstLine=${JSON.stringify(redactGate(firstBytes.subarray(0, 90).toString('latin1').split('\\r\\n')[0]))}`)
      // The request is in and the stream is bridged: the pre-auth deadline is
      // gone, a long-lived streaming response is normal from here on.
      socket.setTimeout(0)
      phoneByStream.set(sid, new PhoneConn(socket, entry, sid, firstBytes, remainderBytes))
    }

    let remainderBytes = Buffer.alloc(0)
    socket.on('data', function first(chunk) {
      buffer = Buffer.concat([buffer, chunk])
      const idx = buffer.indexOf('\r\n')
      if (idx === -1) {
        if (buffer.length > 16384) tinyResponse(socket, 431, 'Too Large', 'request line too long\n')
        return
      }
      const line = buffer.subarray(0, idx).toString('latin1')

      // Fast path: gate present in the query.
      const q1 = line.indexOf('?')
      const q2 = q1 === -1 ? -1 : line.indexOf(' ', q1)
      const query = q1 === -1 ? '' : line.slice(q1 + 1, q2 === -1 ? undefined : q2)
      if (query === '' || !/(^|&)g=/.test(query)) {
        // No gate: the gate/id may arrive as cookies. Wait for the whole
        // head inside THIS single accumulating buffer (no second buffer —
        // double-buffering across chunks corrupts the stream).
        const headEnd = buffer.indexOf('\r\n\r\n')
        if (headEnd === -1) {
          if (buffer.length > 65536) tinyResponse(socket, 431, 'Too Large', 'head too large\n')
          return
        }
        const head = buffer.subarray(0, headEnd).toString('latin1')
        const cookieMatch = head.match(/(?:^|\r\n)cookie:\s*([^\r\n]*)/i)
        const gateCookie = cookieMatch
          ? /(?:^|;\s*)__relay_g=([a-f0-9]{16,128})(?:;|$)/.exec(cookieMatch[1])?.[1] ?? ''
          : ''
        const fullHead = buffer.subarray(0, headEnd + 4)
        remainderBytes = buffer.subarray(headEnd + 4)
        socket.removeListener('data', first)
        onFirstLine(line, gateCookie, fullHead)
        return
      }

      remainderBytes = buffer.subarray(idx + 2)
      socket.removeListener('data', first)
      onFirstLine(line, '')
    })
    socket.on('error', () => { try { socket.destroy() } catch {} })
}

function tinyResponse(socket, status, reason, body) {
  const text = `HTTP/1.1 ${status} ${reason}\r\ncontent-type: text/plain; charset=utf-8\r\nconnection: close\r\ncontent-length: ${Buffer.byteLength(body)}\r\n\r\n${body}`
  socket.end(text)
}

// ---------------------------------------------------------------------------
// Agent listener (WSS + HMAC registration gate)
// ---------------------------------------------------------------------------

function startAgentListener(args, tls) {
  const server = https.createServer(
    { cert: tls.cert, key: tls.key },
    (req, res) => {
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
      res.end('dsh-relay agent endpoint: connect with wss:// and register\n')
    },
  )
  // Two bounds a TLS listener needs: connections whose handshake never
  // completes, and the total socket count.
  if (args.maxConnections > 0) server.maxConnections = args.maxConnections
  server.headersTimeout = Math.max(args.preAuthTimeoutMs, 5000)
  server.requestTimeout = args.preAuthTimeoutMs * 2
  const wss = new WebSocketServer({ noServer: true })

  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://x')
    if (url.pathname !== '/agent') {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n')
      socket.destroy()
      return
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req))
  })

  wss.on('connection', (ws) => {
    let entry = null
    let id = null
    let helloGate = null // gate arrives in hello; used when register completes
    let helloKeyId = null // tenant key id from hello (absent for the admin key)
    let pendingChallenge = null
    let registered = false
    let pongMisses = 0
    ws._socket.setNoDelay(true)

    const failConn = (reason) => {
      log(`agent rejected: ${reason}`)
      try { ws.send(JSON.stringify({ t: 'rejected', reason })) } catch {}
      setTimeout(() => ws.terminate(), 250)
    }

    const heartbeat = setInterval(() => {
      if (ws.readyState !== 1) return
      pongMisses += 1
      if (pongMisses > 2) ws.terminate()
      else ws.ping()
    }, 20000)
    ws.on('pong', () => { pongMisses = 0 })

    ws.on('message', (data, isBinary) => {
      if (!isBinary) {
        let msg
        try { msg = JSON.parse(data.toString()) } catch { return failConn('bad json') }

        if (msg.t === 'hello') {
          // A key may have been created a moment ago by the CLI; pick it up now
          // rather than making the first connection attempt wait for the timer.
          tenantStore?.reloadIfChanged()
          // The daily brake stays shut for the rest of the UTC day: a reconnect
          // after the cut must not slip back in and keep the meter running.
          if (egressBlocked()) return failConn('egress-limit')
          id = String(msg.id ?? '')
          if (!/^[A-Za-z0-9]{4,16}$/.test(id)) return failConn('bad id')
          if (typeof msg.gate !== 'string' || !/^[a-f0-9]{16,128}$/.test(msg.gate)) {
            return failConn('bad gate')
          }
          helloKeyId = typeof msg.keyId === 'string' ? msg.keyId : null
          if (helloKeyId !== null && !/^[a-f0-9]{12}$/.test(helloKeyId)) return failConn('bad key id')
          // Refuse a spent or suspended tenant before spending a challenge on
          // it. An unknown key id is NOT refused here: it may be the admin
          // --key, which is verified at register time (the hash is not the key).
          if (helloKeyId) {
            const tenant = tenantStore?.byKeyId(helloKeyId) ?? null
            if (tenant) {
              const blocked = tenantStore.blocked(tenant)
              if (blocked) return failConn(blocked)
            }
          }
          helloGate = msg.gate
          pendingChallenge = crypto.randomBytes(24).toString('hex')
          ws.send(JSON.stringify({ t: 'challenge', nonce: pendingChallenge }))
          return
        }

        if (msg.t === 'register' && pendingChallenge && !registered) {
          // A tenant sends the id of its key; the legacy/admin key sends either
          // nothing or an id that matches no tenant.
          let tenant = helloKeyId ? (tenantStore?.byKeyId(helloKeyId) ?? null) : null
          let secret = null
          if (tenant) {
            const blocked = tenantStore.blocked(tenant)
            if (blocked) {
              pendingChallenge = null
              return failConn(blocked)
            }
            secret = tenant.secret
          } else if (args.key) {
            secret = args.key
          } else {
            pendingChallenge = null
            return failConn('unknown-key')
          }
          const expected = crypto.createHmac('sha256', secret)
            .update(`${pendingChallenge}|${id}`).digest('hex')
          const proofOk = timingSafeEqual(String(msg.proof ?? ''), expected)
          pendingChallenge = null
          if (!proofOk) return failConn('bad key proof')

          // One agent per tenant: the newest connection wins and the previous
          // one is dropped (a demo machine should never be reachable twice).
          if (tenant) {
            const current = tenantAgent.get(tenant.id)
            if (current && current.entry !== entry) {
              log(`tenant ${tenant.id}: replacing agent ${current.id} with ${id}`)
              closeEntry(current.entry, 'replaced')
              if (agents.get(current.entry.key) === current.entry) forgetEntry(current.entry)
            }
          }
          // The registry is tenant-scoped, so two tenants may use the same
          // device id without evicting each other; only the same tenant
          // reconnecting with the same id replaces its own previous entry.
          const key = agentKey(tenant, id)
          const previous = agents.get(key)
          if (previous) {
            previous.alive = false
            for (const sid of [...previous.streams]) {
              const phone = phoneByStream.get(sid)
              if (phone && phone.entry === previous) phone.destroy(false)
            }
            try { previous.ws.terminate() } catch {}
            forgetEntry(previous)
          }
          entry = new AgentEntry(ws, helloGate, tenant, id)
          entry.key = key
          indexEntry(entry)
          blockedDevices.delete(id)
          if (tenant) {
            tenantAgent.set(tenant.id, { id, entry })
            tenant.lastSeenAt = new Date().toISOString()
            tenantStore.dirty = true
          }
          registered = true
          log(`agent registered id=${id}${tenant ? ` tenant=${tenant.id}` : ' (admin key)'}`)
          ws.send(JSON.stringify({ t: 'registered' }))
          return
        }

        if (msg.t === 'close' && entry && registered) {
          const sid = msg.sid >>> 0
          // Ownership check: a stream id belongs to the connection that opened
          // it. Without this, any tenant could close another tenant's phone
          // stream by guessing a sequential sid.
          if (!entry.streams.has(sid)) return
          entry.streams.delete(sid)
          const phone = phoneByStream.get(sid)
          if (phone && phone.entry === entry) phone.destroy(false)
          return
        }
        return
      }

      // Binary frame: stream bytes going back to a phone.
      if (!entry || !registered || data.length < 4) return
      charge(entry, data.length)
      if (!entry.alive) return
      const sid = data.readUInt32BE(0)
      // Same ownership check as above: never write into another tenant's phone
      // socket, whatever sid the frame claims.
      if (!entry.streams.has(sid)) return
      const phone = phoneByStream.get(sid)
      if (phone && phone.entry === entry) phone.sendToClient(data.subarray(4))
    })

    ws.on('close', () => {
      clearInterval(heartbeat)
      if (entry && agents.get(entry.key) === entry) {
        forgetEntry(entry)
        for (const sid of [...entry.streams]) {
          const phone = phoneByStream.get(sid)
          if (phone && phone.entry === entry) phone.destroy(false)
        }
        if (entry.tenant && tenantAgent.get(entry.tenant.id)?.entry === entry) {
          tenantAgent.delete(entry.tenant.id)
        }
        log(`agent gone id=${id}${entry.tenant ? ` tenant=${entry.tenant.id}` : ''}`)
        tenantStore?.saveIfDirty()
      }
    })
  })

  server.listen(args.agentPort, args.agentHost, () => {
    log(`agent listener: wss://${args.agentHost ?? '0.0.0.0'}:${args.agentPort}/agent (self-signed; agents pin the fingerprint)`)
  })
  return server
}

// ---------------------------------------------------------------------------
// Tenant CLI (runs before any listener starts)
// ---------------------------------------------------------------------------

function runTenantCli(argv) {
  let dataDir = path.join(os.homedir(), '.dsh-relay')
  let quotaDefault = DEFAULT_QUOTA_BYTES
  let maxStreamsDefault = DEFAULT_MAX_STREAMS
  const rest = []
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]
    if (a === '--data-dir') {
      if (i + 1 >= argv.length) fail('missing value for --data-dir')
      dataDir = argv[i + 1]
      i += 1
    } else if (a === '--quota-default') {
      if (i + 1 >= argv.length) fail('missing value for --quota-default')
      const parsed = parseQuota(argv[i + 1])
      if (!parsed) fail('bad --quota-default (use e.g. 100MB)')
      quotaDefault = parsed
      i += 1
    } else if (a === '--max-streams-default') {
      if (i + 1 >= argv.length) fail('missing value for --max-streams-default')
      const parsed = Number(argv[i + 1])
      if (!Number.isInteger(parsed) || parsed < 0) fail('bad --max-streams-default (0 = unlimited)')
      maxStreamsDefault = parsed
      i += 1
    } else {
      rest.push(a)
    }
  }

  const [sub, ...tail] = rest
  const flags = {}
  const positional = []
  for (let i = 0; i < tail.length; i += 1) {
    if (tail[i].startsWith('--')) {
      const name = tail[i].slice(2)
      const value = tail[i + 1] !== undefined && !tail[i + 1].startsWith('--') ? tail[(i += 1)] : 'true'
      flags[name] = value
    } else {
      positional.push(tail[i])
    }
  }

  const store = new TenantStore(path.join(dataDir, 'tenants.json'), { quotaDefault, maxStreamsDefault })

  const printList = () => {
    const rows = store.list()
    if (!rows.length) {
      console.log('no tenants. Create one with: dsh-relay-server tenant add --name <name>')
      return
    }
    console.log(['name', 'status', 'today', 'quota', 'streams', 'last seen', 'key id'].join('\t'))
    for (const tenant of rows) {
      const used = tenant.day === quotaDayNow() ? tenant.usedBytesDay : 0
      console.log([
        tenant.id,
        tenant.status,
        `${formatBytes(used)}${tenant.day === quotaDayNow() ? '' : ' (new day)'}`,
        tenant.quotaBytesDay > 0 ? formatBytes(tenant.quotaBytesDay) : 'unlimited',
        tenant.maxStreams > 0 ? String(tenant.maxStreams) : 'unlimited',
        tenant.lastSeenAt ?? 'never',
        tenant.keyId,
      ].join('\t'))
    }
  }

  switch (sub) {
    case undefined:
    case 'list': {
      printList()
      return
    }
    case '--help':
    case '-h':
    case 'help': {
      console.log(usage())
      return
    }
    case 'add': {
      const name = flags.name ?? positional[0]
      if (!name) fail('tenant add needs --name <name>')
      const quota = parseLimitFlag(flags.quota, quotaDefault, 'quota')
      const maxStreams = parseStreamsFlag(flags['max-streams'], maxStreamsDefault)
      const { tenant, key } = store.add({ name, quotaBytesDay: quota, maxStreams, note: flags.note ?? '' })
      console.log(`tenant ${tenant.id} created`)
      console.log(`  quota:   ${tenant.quotaBytesDay > 0 ? formatBytes(tenant.quotaBytesDay) : 'unlimited'} per day`)
      console.log(`  streams: ${tenant.maxStreams > 0 ? tenant.maxStreams + ' concurrent' : 'unlimited'}`)
      console.log(`  key id:  ${tenant.keyId}`)
      console.log('')
      console.log('  relay key (shown once, store it in the DSH panel):')
      console.log(`  ${key}`)
      console.log('')
      return
    }
    case 'set': {
      const ref = flags.name ?? positional[0]
      if (!ref) fail('tenant set needs a name')
      const patch = {}
      if (flags.quota !== undefined) patch.quotaBytesDay = parseLimitFlag(flags.quota, quotaDefault, 'quota')
      if (flags['max-streams'] !== undefined) patch.maxStreams = parseStreamsFlag(flags['max-streams'], maxStreamsDefault)
      if (!Object.keys(patch).length) fail('tenant set needs --quota and/or --max-streams')
      const tenant = store.setLimits(ref, patch)
      console.log(`tenant ${tenant.id}: quota ${tenant.quotaBytesDay > 0 ? formatBytes(tenant.quotaBytesDay) + '/day' : 'unlimited'}, streams ${tenant.maxStreams > 0 ? tenant.maxStreams : 'unlimited'}`)
      console.log('applies to new connections immediately (the running server reloads within 15s)')
      return
    }
    case 'show': {
      const tenant = store.resolve(flags.name ?? positional[0])
      if (!tenant) fail(`no tenant ${flags.name ?? positional[0]}`)
      const used = tenant.day === quotaDayNow() ? tenant.usedBytesDay : 0
      console.log(JSON.stringify({ ...tenant, usedToday: used, today: quotaDayNow() }, null, 2))
      return
    }
    case 'disable':
    case 'enable': {
      const tenant = store.setStatus(flags.name ?? positional[0], sub === 'disable' ? 'disabled' : 'active')
      console.log(`tenant ${tenant.id} is now ${tenant.status}`)
      console.log('takes effect on the next agent reconnect; existing connections keep running until then')
      return
    }
    case 'reset': {
      const tenant = store.reset(flags.name ?? positional[0])
      console.log(`tenant ${tenant.id}: today's usage reset to 0 (${formatBytes(tenant.quotaBytesDay)} quota)`)
      return
    }
    case 'remove': {
      const tenant = store.remove(flags.name ?? positional[0])
      console.log(`tenant ${tenant.id} removed`)
      return
    }
    default:
      fail(`unknown tenant command ${sub}. Try: add, list, show, disable, enable, reset, remove`)
  }
}

function quotaDayNow() {
  return new Date().toISOString().slice(0, 10)
}

/** `--quota 100MB` / `--quota unlimited` -> bytes (0 means unlimited). */
function parseLimitFlag(raw, fallback, label) {
  if (raw === undefined) return fallback
  if (raw === 'unlimited' || raw === '0') return 0
  const parsed = parseQuota(raw)
  if (parsed === null) fail(`bad --${label} (use e.g. 100MB, or unlimited)`)
  return parsed
}

/** `--max-streams 8` / `--max-streams 0` (0 means unlimited). */
function parseStreamsFlag(raw, fallback) {
  if (raw === undefined) return fallback
  const parsed = Number(raw)
  if (!Number.isInteger(parsed) || parsed < 0) fail('bad --max-streams (integer >= 0; 0 = unlimited)')
  return parsed
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

if (process.argv[2] === 'tenant') {
  try {
    runTenantCli(process.argv.slice(3))
  } catch (error) {
    // Operator mistakes are not crashes: print the reason, no stack trace.
    fail(error?.message ?? String(error))
  }
  process.exit(0)
}

const args = parseArgs(process.argv)
tenantStore = new TenantStore(path.join(args.dataDir, 'tenants.json'), {
  quotaDefault: args.quotaDefault,
  maxStreamsDefault: args.maxStreamsDefault,
})
const tls = ensureSelfSignedCert(args)
startPhoneListener(args)
startAgentListener(args, tls)
const tenantCount = tenantStore.list().length
log(`dsh-relay-server ${VERSION} ready (${tenantCount} tenant${tenantCount === 1 ? '' : 's'}${args.key ? ' + admin key' : ''})`)
if (!tenantCount && !args.key) {
  log('warning: no tenants and no --key — nobody can register. Try: dsh-relay-server tenant add --name <name>')
}

// One `stat` per second so a key created by the CLI works on the next attempt.
// (A signal would be cheaper but SIGHUP does not exist on Windows, and this box
// and the operator's machine are not always the same platform.)
//
// Reload BEFORE saving: the CLI writes the same file, and saving first would
// overwrite a key that was just added with our older in-memory copy.
const saveTimer = setInterval(() => {
  if (tenantStore.reloadIfChanged()) log(`tenants reloaded: ${tenantStore.list().length} tenant(s)`)
  tenantStore.saveIfDirty()
  // Yesterday's cut reasons mean nothing today, and this map would otherwise
  // grow by one entry per device ever cut.
  const today = quotaDayNow()
  for (const [deviceId, record] of blockedDevices) {
    if (record.day !== today) blockedDevices.delete(deviceId)
  }
  // `tenant disable` and `tenant remove` mean "stop now", not "stop on the next
  // reconnect": a connection that is already live would otherwise keep routing
  // traffic (and burning the day's quota) until it happened to drop.
  for (const entry of [...agents.values()]) {
    const tenant = entry.tenant
    if (!tenant) continue
    const live = tenantStore.byKeyId(tenant.keyId)
    if (!live || live.status !== 'active') {
      log(`closing live agent tenant=${tenant.id} (${live ? 'disabled' : 'removed'})`)
      closeEntry(entry, 'key-disabled')
    }
  }
}, 1000)
saveTimer.unref?.()

const shutdown = () => {
  tenantStore.saveIfDirty()
  process.exit(0)
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
