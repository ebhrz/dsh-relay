// Guards on the relayed surface: the plugin's own management console hands out
// pairing links (they embed the device PSK), so a phone must never reach it.
//
// Pure loopback, no relay server required.

import assert from 'node:assert/strict'
import http from 'node:http'
import { PumpManager } from '../src/pump.js'

const GATE = 'a'.repeat(64)
const ID = 'ABCD1234'

const listen = (handler) => new Promise((resolve) => {
  const server = http.createServer(handler)
  server.listen(0, '127.0.0.1', () => resolve(server))
})

function harness(port, options = {}) {
  const pump = new PumpManager({
    resolveTarget: () => ({ host: '127.0.0.1', port, authority: `127.0.0.1:${port}`, protocol: 'http:' }),
    resolveAuthCookie: () => 'dsh-auth=test',
    pairing: { sessionForHeaders: () => ({ did: 'test' }), handle: () => null },
    cryptoBox: {},
    ...options,
  })
  const out = []
  const closed = []
  pump.setClient({
    sendStream: (_sid, chunk) => { out.push(Buffer.from(chunk)) },
    closeStream: (sid) => { closed.push(sid) },
  })
  return { pump, text: () => Buffer.concat(out).toString('latin1'), closed, reset: () => { out.length = 0 } }
}

const waitFor = (check, timeout = 3000) => new Promise((resolve, reject) => {
  const started = Date.now()
  const tick = () => {
    if (check()) return resolve()
    if (Date.now() - started > timeout) return reject(new Error('timeout'))
    setTimeout(tick, 5)
  }
  tick()
})

const request = (path, extra = '') => Buffer.from(
  `GET /c/${ID}${path}?g=${GATE} HTTP/1.1\r\nHost: relay.example:8889\r\nConnection: close\r\n${extra}\r\n`,
)

// ── 1. the console is unreachable from a relayed request ────────────────
{
  const hits = []
  const server = await listen((req, res) => {
    hits.push(req.url)
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '2' })
    res.end('ok')
  })
  const h = harness(server.address().port)

  h.pump.handleStreamData(21, request('/relay-bridge/api'))
  await waitFor(() => h.closed.includes(21))
  assert.match(h.text(), /403 Forbidden/, 'the panel API is refused over the relay')
  assert.deepEqual(hits, [], 'the host never sees the request')

  h.reset()
  h.pump.handleStreamData(22, request('/relay-bridge/panel'))
  await waitFor(() => h.closed.includes(22))
  assert.match(h.text(), /403 Forbidden/, 'the panel page is refused over the relay')
  assert.deepEqual(hits, [], 'still nothing reaches the host')

  // A plaintext API call must not reach the host: the relay sees the ticket, so
  // forwarding one would let it act as the user.
  h.reset()
  h.pump.handleStreamData(23, request('/api/status'))
  await waitFor(() => h.closed.includes(23))
  assert.match(h.text(), /403 Forbidden/, 'plaintext /api traffic is refused over the relay')
  assert.deepEqual(hits, [], 'the host never sees it')

  // Documents and their assets are what a browser fetches by itself, so they
  // still pass — and are marked as relayed.
  h.reset()
  h.pump.handleStreamData(24, request('/assets/app.js'))
  // Wait for the forwarded response, not just for the upstream to be hit: those
  // are separate events, and the gap is wide enough to flake on CI.
  await waitFor(() => /200 OK/.test(h.text()))
  assert.deepEqual(hits, ['/assets/app.js'])

  server.close()
  h.pump.handleStreamClose(24)
  console.log('ok 1: /relay-bridge/* and plaintext APIs are blocked over the relay, documents forward')
}

// ── 2. the relayed marker cannot be forged by the client ───────────────
{
  const seen = []
  const server = await listen((req, res) => {
    seen.push(String(req.headers['x-dsh-relay'] ?? ''))
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '2' })
    res.end('ok')
  })
  const h = harness(server.address().port)
  h.pump.handleStreamData(31, request('/assets/app.js', 'x-dsh-relay: 0\r\n'))
  await waitFor(() => seen.length === 1)
  assert.equal(seen[0], '1', 'the pump sets its own marker')
  server.close()
  h.pump.handleStreamClose(31)
  console.log('ok 2: a client-supplied x-dsh-relay header is replaced')
}

// ── 3. plaintext writes are refused; a websocket handshake passes ────────
{
  const hits = []
  const server = await listen((req, res) => {
    hits.push(req.url)
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '2' })
    res.end('ok')
  })
  const h = harness(server.address().port)

  const post = (path) => Buffer.from(
    `POST /c/${ID}${path}?g=${GATE} HTTP/1.1\r\nHost: relay.example\r\n`
    + 'content-type: application/json\r\ncontent-length: 2\r\nConnection: close\r\n\r\n{}',
  )

  // A mutation with a ticket but no envelope would reach DSH with the host cookie.
  h.pump.handleStreamData(41, post('/api/session'))
  await waitFor(() => h.closed.includes(41))
  assert.match(h.text(), /403 Forbidden/, 'plaintext API writes are refused')
  assert.deepEqual(hits, [], 'the host never sees them')

  // A websocket handshake *is* allowed: it is a GET with no body, so an envelope
  // has nowhere to ride. What must not pass is an unsealed data frame, and the
  // codec closes the stream when one does not open.
  h.reset()
  h.pump.handleStreamData(42, Buffer.from(
    `GET /c/${ID}/api/remote.mux?g=${GATE} HTTP/1.1\r\nHost: relay.example\r\n`
    + 'Upgrade: websocket\r\nConnection: Upgrade\r\n'
    + 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n',
  ))
  await waitFor(() => /101 Switching Protocols/.test(h.text()) || h.closed.includes(42), 'the handshake is forwarded')
  assert.deepEqual(hits, ['/api/remote.mux'], 'the upgrade reaches the host')
  assert.ok(!/403 Forbidden/.test(h.text()), 'upgrades are no longer refused')

  server.close()
  console.log('ok 3: plaintext writes refused; the mux handshake is forwarded')
}

// ── 4. the opt-in that restores the old desktop replay ──────────────────
{
  const hits = []
  const server = await listen((req, res) => {
    hits.push(req.url)
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '2' })
    res.end('{}')
  })
  const h = harness(server.address().port, { allowDesktopPlaintext: true })
  h.pump.handleStreamData(51, Buffer.from(
    `GET /c/${ID}/api/status?g=${GATE} HTTP/1.1\r\nHost: relay.example\r\nConnection: close\r\n\r\n`,
  ))
  await waitFor(() => /200 OK/.test(h.text()))
  assert.deepEqual(hits, ['/api/status'], 'the opt-in forwards the desktop UI calls')
  server.close()
  h.pump.handleStreamClose(51)
  console.log('ok 4: allowDesktopPlaintext restores the desktop replay (documented risk)')
}
