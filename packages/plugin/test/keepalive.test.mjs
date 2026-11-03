// Keep-alive checks for the pump: one relay stream (one phone TCP connection)
// must serve successive requests instead of forcing a new TLS handshake per
// asset. Run with: node packages/plugin/test-keepalive.mjs
//
// Pure loopback: no relay server and no running dsh web required.

import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'
import nacl from 'tweetnacl'
import { PumpManager, injectBootScript } from '../src/pump.js'

const GATE = 'a'.repeat(64)
const ID = 'ABCD1234'

const listen = (handler) => new Promise((resolve) => {
  const server = http.createServer(handler)
  server.listen(0, '127.0.0.1', () => resolve(server))
})

/** Pump wired to a loopback upstream and a fake relay client. */
function harness(port, { cryptoBox = {} } = {}) {
  const pump = new PumpManager({
    resolveTarget: () => ({ host: '127.0.0.1', port, authority: `127.0.0.1:${port}`, protocol: 'http:' }),
    resolveAuthCookie: () => 'dsh-auth=test',
    pairing: { sessionForHeaders: () => ({ did: 'test' }), handle: () => null },
    cryptoBox,
  })
  const out = []
  const closed = []
  pump.setClient({
    sendStream: (_sid, chunk) => { out.push(Buffer.from(chunk)) },
    closeStream: (sid) => { closed.push(sid) },
  })
  return {
    pump,
    text: () => Buffer.concat(out).toString('latin1'),
    reset: () => { out.length = 0 },
    closed,
  }
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

const responseCount = (text) => (text.match(/HTTP\/1\.1 /g) ?? []).length

// 1. Two sequential requests on one stream: both answered, stream stays open,
//    and the rewritten head tells the browser it may reuse the socket.
{
  const hits = []
  const server = await listen((req, res) => {
    hits.push(req.url)
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '3' })
    res.end('hit')
  })
  const h = harness(server.address().port)
  const sid = 11
  const req = (path) => Buffer.from(
    `GET /c/${ID}${path}?g=${GATE} HTTP/1.1\r\nHost: relay.example:8889\r\n`
    + 'Connection: keep-alive\r\n\r\n')

  h.pump.handleStreamData(sid, req('/a.js'))
  await waitFor(() => responseCount(h.text()) === 1)
  assert.deepEqual(hits, ['/a.js'])
  assert.equal(h.closed.length, 0, 'connection stays open after the first response')
  assert.match(h.text(), /Connection: keep-alive/i, 'browser is told it may reuse the socket')
  assert.match(h.text(), /content-length: 3/i, 'framing preserved for reuse')

  h.reset()
  h.pump.handleStreamData(sid, req('/b.css'))
  await waitFor(() => responseCount(h.text()) === 1)
  assert.deepEqual(hits, ['/a.js', '/b.css'], 'second request rode the same stream')
  assert.equal(h.closed.length, 0)
  server.close()
  h.pump.handleStreamClose(sid)
  console.log('ok 1: sequential requests share one relay stream (no per-asset handshake)')
}

// 2. `Connection: close` requests still terminate the stream (curl, HTTP/1.0).
{
  const server = await listen((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '2' })
    res.end('ok')
  })
  const h = harness(server.address().port)
  h.pump.handleStreamData(12, Buffer.from(
    `GET /c/${ID}/x?g=${GATE} HTTP/1.1\r\nHost: relay.example\r\nConnection: close\r\n\r\n`))
  await waitFor(() => h.closed.includes(12))
  assert.match(h.text(), /Connection: close/i)
  server.close()
  console.log('ok 2: connection-close requests still close the stream')
}

// 3. A request pipelined behind an in-flight response is not lost: it is
//    replayed once the first response completes.
{
  const hits = []
  const server = await listen((req, res) => {
    hits.push(req.url)
    // Answer after a beat so the second request definitely arrives mid-flight.
    setTimeout(() => {
      res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '2' })
      res.end('ok')
    }, 60)
  })
  const h = harness(server.address().port)
  const sid = 13
  const one = Buffer.from(
    `GET /c/${ID}/one?g=${GATE} HTTP/1.1\r\nHost: relay.example\r\nConnection: keep-alive\r\n\r\n`)
  const two = Buffer.from(
    `GET /c/${ID}/two?g=${GATE} HTTP/1.1\r\nHost: relay.example\r\nConnection: keep-alive\r\n\r\n`)
  h.pump.handleStreamData(sid, Buffer.concat([one, two]))
  await waitFor(() => responseCount(h.text()) === 2)
  assert.deepEqual(hits, ['/one', '/two'])
  server.close()
  h.pump.handleStreamClose(sid)
  console.log('ok 3: pipelined request replayed after the first response')
}

// 4. Sealed round trips keep the connection too, and the envelope still opens.
{
  const key = nacl.randomBytes(32)
  const cryptoBox = {
    envelopeKey: key,
    open: (_k, sealed) => {
      const plain = nacl.secretbox.open(sealed.subarray(24), sealed.subarray(0, 24), key)
      return plain ? Buffer.from(plain) : null
    },
    seal: (_k, plain) => {
      const nonce = nacl.randomBytes(24)
      const box = nacl.secretbox(new Uint8Array(plain), nonce, key)
      return Buffer.concat([Buffer.from(nonce), Buffer.from(box)])
    },
  }
  const server = await listen((req, res) => {
    let body = ''
    req.on('data', (c) => { body += c })
    req.on('end', () => {
      const payload = JSON.stringify({ echo: body })
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)) })
      res.end(payload)
    })
  })
  const h = harness(server.address().port, { cryptoBox })
  const sid = 14
  const sealBody = (text) => cryptoBox.seal(key, Buffer.from(text, 'utf8'))
  const sealedReq = (text) => {
    const body = sealBody(text)
    return Buffer.concat([
      Buffer.from(`POST /c/${ID}/api/ping?g=${GATE} HTTP/1.1\r\nHost: relay.example\r\n`
        + 'x-relay-enc: 1\r\nx-relay-ct: application/json\r\n'
        + `content-length: ${body.length}\r\nConnection: keep-alive\r\n\r\n`, 'latin1'),
      body,
    ])
  }

  h.pump.handleStreamData(sid, sealedReq('{"n":1}'))
  await waitFor(() => responseCount(h.text()) === 1)
  assert.match(h.text(), /x-relay-enc: 1/i)
  assert.equal(h.closed.length, 0, 'sealed response keeps the connection')
  assert.match(h.text(), /Connection: keep-alive/i)

  h.reset()
  h.pump.handleStreamData(sid, sealedReq('{"n":2}'))
  await waitFor(() => responseCount(h.text()) === 1)
  const sealedBody = h.pump.cryptoBox
  assert.ok(sealedBody)
  server.close()
  h.pump.handleStreamClose(sid)
  console.log('ok 4: sealed API round trips reuse the stream')
}

// 5. The injected document is length-framed so it can ride a kept-alive socket.
{
  const html = Buffer.from('HTTP/1.1 200 OK\r\ncontent-type: text/html\r\nconnection: close\r\n\r\n'
    + '<!doctype html><html><head><title>x</title></head><body>hi</body></html>', 'latin1')
  const out = injectBootScript(html, { id: ID, gate: GATE }, { keepAlive: true }).toString('latin1')
  const split = out.indexOf('\r\n\r\n')
  const head = out.slice(0, split)
  const body = out.slice(split + 4)
  assert.match(head, /Connection: keep-alive/i)
  const declared = Number(/content-length:\s*(\d+)/i.exec(head)?.[1])
  assert.equal(declared, Buffer.byteLength(body, 'latin1'), 'declared length matches the injected body')
  assert.match(body, /__dshRelayBoot/)
  console.log('ok 5: injected documents are self-delimited for keep-alive')
}

// 6. Close-delimited upstream responses fall back to closing the stream.
{
  // A raw socket, because Node's http server always adds content-length or
  // chunked framing. This response is delimited only by the close.
  const raw = net.createServer((socket) => {
    socket.once('data', () => {
      socket.write('HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\nloose')
      setTimeout(() => socket.end(), 20)
    })
  })
  await new Promise((resolve) => raw.listen(0, '127.0.0.1', resolve))
  const h = harness(raw.address().port)
  const sid = 15
  h.pump.handleStreamData(sid, Buffer.from(
    `GET /c/${ID}/loose?g=${GATE} HTTP/1.1\r\nHost: relay.example\r\nConnection: keep-alive\r\n\r\n`))
  await waitFor(() => h.closed.includes(sid))
  assert.match(h.text(), /Connection: close/i, 'close-delimited body downgrades to close')
  raw.close()
  console.log('ok 6: close-delimited responses downgrade safely')
}

console.log('\nall keep-alive checks passed')
