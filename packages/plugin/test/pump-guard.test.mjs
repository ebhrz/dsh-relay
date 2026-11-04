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

function harness(port) {
  const pump = new PumpManager({
    resolveTarget: () => ({ host: '127.0.0.1', port, authority: `127.0.0.1:${port}`, protocol: 'http:' }),
    resolveAuthCookie: () => 'dsh-auth=test',
    resolveIndexToken: () => 'test-token',
    pairing: { sessionForHeaders: () => ({ did: 'test' }), handle: () => null },
    cryptoBox: {},
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

  // The ordinary DSH surface keeps working, and is marked as relayed.
  h.reset()
  h.pump.handleStreamData(23, request('/api/status'))
  await waitFor(() => hits.length === 1)
  assert.deepEqual(hits, ['/api/status'])
  assert.match(h.text(), /200 OK/)

  server.close()
  h.pump.handleStreamClose(23)
  console.log('ok 1: /relay-bridge/* is blocked over the relay, the rest forwards')
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
  h.pump.handleStreamData(31, request('/api/status', 'x-dsh-relay: 0\r\n'))
  await waitFor(() => seen.length === 1)
  assert.equal(seen[0], '1', 'the pump sets its own marker')
  server.close()
  h.pump.handleStreamClose(31)
  console.log('ok 2: a client-supplied x-dsh-relay header is replaced')
}

// ── 3. a relayed desktop document gets the root token ─────────────────
// DSH 0.2 only serves an authenticated shell when the index request carries its
// root token; a browser arriving through the relay has none of its own.
{
  const seen = []
  const server = await listen((req, res) => {
    seen.push({ url: req.url, dest: req.headers['sec-fetch-dest'] })
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': '9' })
    res.end('<html></h')
  })
  const h = harness(server.address().port)

  h.pump.handleStreamData(41, Buffer.from(
    `GET /c/${ID}/?g=${GATE}&desktop=1 HTTP/1.1\r\nHost: relay.example:8889\r\n`
    + 'sec-fetch-dest: document\r\nConnection: close\r\n\r\n'))
  await waitFor(() => seen.length === 1)
  assert.match(seen[0].url, /^\/\?/, 'still the index path')
  assert.match(seen[0].url, /(?:^|[?&])token=test-token(?:&|$)/, 'the document request carries the token')
  assert.match(seen[0].url, /desktop=1/, 'other query parameters survive')

  // A non-document request to the same path must not get the token.
  h.reset()
  seen.length = 0
  h.pump.handleStreamData(42, Buffer.from(
    `GET /c/${ID}/?g=${GATE} HTTP/1.1\r\nHost: relay.example:8889\r\n`
    + 'accept: application/json\r\nConnection: close\r\n\r\n'))
  await waitFor(() => seen.length === 1)
  assert.equal(seen[0].url, '/', 'only documents get the token')

  // And a document for another path keeps its own URL.
  h.reset()
  seen.length = 0
  h.pump.handleStreamData(43, Buffer.from(
    `GET /c/${ID}/assets/app.js?g=${GATE} HTTP/1.1\r\nHost: relay.example:8889\r\n`
    + 'sec-fetch-dest: document\r\nConnection: close\r\n\r\n'))
  await waitFor(() => seen.length === 1)
  assert.equal(seen[0].url, '/assets/app.js', 'the token is only for the index')

  server.close()
  for (const sid of [41, 42, 43]) h.pump.handleStreamClose(sid)
  console.log('ok 3: the index document is replayed with the root token')
}
