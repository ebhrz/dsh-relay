// The relayed HTTP surface, exercised with a real CryptoBox and a fake host:
// which requests may pass unsealed, and what a sealed one may claim.
//
// Everything here was a finding: a forged Upgrade, an empty body standing in for
// an envelope, a malformed content-length, and a GET that only seals its response.

import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import http from 'node:http'
import { CryptoBox } from '../src/crypto.js'
import { PumpManager } from '../src/pump.js'


// Same framing the boot patch produces: 0x02 | u32 len | {m,t,c} | body.
const sealBound = (box, method, target, contentType, bytes) => {
  const header = Buffer.from(JSON.stringify({ m: method, t: target, c: contentType }), 'utf8')
  const prefix = Buffer.alloc(5)
  prefix[0] = 0x02
  prefix.writeUInt32BE(header.length, 1)
  return box.seal(box.envelopeKey, Buffer.concat([prefix, header, bytes]))
}

const GATE = 'b'.repeat(64)
const ID = 'HTTP0001'

const waitFor = (check, label = 'condition', timeout = 3000) => new Promise((resolve, reject) => {
  const started = Date.now()
  const tick = () => {
    if (check()) return resolve()
    if (Date.now() - started > timeout) return reject(new Error(`timeout waiting for ${label}`))
    setTimeout(tick, 10)
  }
  tick()
})

const makeBox = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  return new CryptoBox({
    id: ID,
    psk: crypto.randomBytes(32).toString('hex'),
    gate: GATE,
    signJwk: {
      public: publicKey.export({ format: 'jwk' }),
      private: privateKey.export({ format: 'jwk' }),
    },
  })
}

async function harness(handler) {
  const hits = []
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on('data', (chunk) => chunks.push(chunk))
    req.on('end', () => {
      hits.push({ method: req.method, url: req.url, body: Buffer.concat(chunks), headers: req.headers })
      handler(req, res)
    })
  })
  // Node reports a websocket handshake as 'upgrade', not 'request'.
  server.on('upgrade', (req, socket) => {
    hits.push({ method: req.method, url: req.url, body: Buffer.alloc(0), headers: req.headers, upgrade: true })
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    setTimeout(() => { try { socket.destroy() } catch {} }, 50)
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  const box = makeBox()
  const pump = new PumpManager({
    resolveTarget: () => ({ host: '127.0.0.1', port, authority: `127.0.0.1:${port}`, protocol: 'http:' }),
    resolveAuthCookie: () => 'dsh-session=host-authority',
    pairing: { sessionForHeaders: () => ({ did: ID }), handle: () => null },
    cryptoBox: box,
  })
  const out = []
  const closed = []
  pump.setClient({
    sendStream: (_sid, chunk) => out.push(Buffer.from(chunk)),
    closeStream: (sid) => closed.push(sid),
  })
  return {
    pump,
    box,
    hits,
    closed,
    bytes: () => Buffer.concat(out),
    text: () => Buffer.concat(out).toString('latin1'),
    reset: () => { out.length = 0 },
    stop: () => { server.close(); pump.dispose() },
    url: (path) => `/c/${ID}${path}?g=${GATE}`,
  }
}

const request = (method, path, headers = {}, body = null) => {
  const lines = [`${method} ${path} HTTP/1.1`, 'Host: relay.example', ...headers]
  if (body) lines.push(`content-length: ${body.length}`)
  lines.push('Connection: close')
  return Buffer.concat([Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'latin1'), body ?? Buffer.alloc(0)])
}

let failures = 0
const scenario = async (label, fn) => {
  try {
    await fn()
    console.log(`ok ${label}`)
  } catch (error) {
    failures += 1
    console.log(`FAIL ${label}: ${error.message}`)
  }
}

await scenario('a forged Upgrade on an API path never reaches the host', async () => {
  const h = await harness((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '2' })
    res.end('{}')
  })
  try {
    // Complete handshake fields, but the path is not a socket.
    h.pump.handleStreamData(1, request('GET', h.url('/api/private'), [
      'Connection: Upgrade',
      'Upgrade: websocket',
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
      'Sec-WebSocket-Version: 13',
    ]))
    await waitFor(() => h.closed.includes(1), 'forged upgrade refused')
    assert.match(h.text(), /403/, 'the forged upgrade is refused')
    assert.equal(h.hits.length, 0, 'the host never saw it')

    // A real handshake on the mux endpoint is still allowed.
    h.reset()
    h.pump.handleStreamData(2, request('GET', h.url('/api/remote.mux'), [
      'Connection: Upgrade',
      'Upgrade: websocket',
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
      'Sec-WebSocket-Version: 13',
    ]))
    await waitFor(() => h.hits.length === 1, 'mux handshake forwarded')
    assert.equal(h.hits[0].url, '/api/remote.mux', 'the mux handshake is forwarded')

    // Missing handshake fields are not a handshake either.
    h.pump.handleStreamData(3, request('GET', h.url('/api/remote.mux'), ['Upgrade: websocket']))
    await waitFor(() => h.closed.includes(3), 'incomplete handshake refused')
    assert.equal(h.hits.length, 1, 'an incomplete handshake is refused')
  } finally {
    h.stop()
  }
})

await scenario('a sealed GET carries no body and seals its response', async () => {
  const h = await harness((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '11' })
    res.end('{"ok":true}')
  })
  try {
    // A bare here-doc: no Content-Length, no body.
    const proof = sealBound(h.box, 'GET', '/api/sessions', '', Buffer.alloc(8))
    h.pump.handleStreamData(4, request('GET', h.url('/api/sessions'), [
      'x-relay-enc: 1',
      'x-relay-ct: application/json',
      `x-relay-bind: ${proof.toString('base64')}`,
    ]))
    await waitFor(() => h.hits.length === 1, 'mux handshake forwarded')
    assert.equal(h.hits[0].method, 'GET', 'the read was forwarded')
    await waitFor(() => /x-relay-enc: 1/i.test(h.text()), 'sealed response')
    assert.match(h.text(), /content-type: application\/octet-stream/i, 'the sealed body is opaque')
    assert.ok(!h.text().includes('{"ok":true}'), 'the plaintext never appears on the wire')
  } finally {
    h.stop()
  }
})

await scenario('a state-changing request still needs an envelope', async () => {
  const h = await harness((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '2' })
    res.end('{}')
  })
  try {
    for (const [sid, extra] of [
      [5, ['x-relay-enc: 1', 'content-length: 0']],
      [6, ['x-relay-enc: 1']],
      [7, ['x-relay-enc: 1', 'content-length: 0x28']],
      [8, ['x-relay-enc: 1', 'content-length: 40', 'content-length: 40']],
    ]) {
      h.pump.handleStreamData(sid, request('POST', h.url('/api/state-changing'), extra))
      await waitFor(() => h.closed.includes(sid), `request ${sid} is refused`)
    }
    assert.equal(h.hits.length, 0, 'none of them reached the host')

    // The legitimate shape: a real envelope, even for an empty plaintext.
    h.reset()
    const envelope = sealBound(h.box, 'POST', '/api/state-changing', 'application/json', Buffer.alloc(0))
    h.pump.handleStreamData(9, Buffer.concat([
      Buffer.from(`POST ${h.url('/api/state-changing')} HTTP/1.1\r\nHost: relay.example\r\n`
        + `x-relay-enc: 1\r\nx-relay-ct: application/json\r\ncontent-length: ${envelope.length}\r\n`
        + 'Connection: close\r\n\r\n', 'latin1'),
      envelope,
    ]))
    await waitFor(() => h.hits.length === 1, 'mux handshake forwarded')
    assert.equal(h.hits[0].body.length, 0, 'the empty plaintext arrived as a bodyless request')
  } finally {
    h.stop()
  }
})

await scenario('random bytes that are not an envelope are refused', async () => {
  const h = await harness((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '2' })
    res.end('{}')
  })
  try {
    const junk = crypto.randomBytes(64)
    h.pump.handleStreamData(10, Buffer.concat([
      Buffer.from(`POST ${h.url('/api/state-changing')} HTTP/1.1\r\nHost: relay.example\r\n`
        + `x-relay-enc: 1\r\ncontent-length: ${junk.length}\r\nConnection: close\r\n\r\n`, 'latin1'),
      junk,
    ]))
    await waitFor(() => h.closed.includes(10))
    assert.equal(h.hits.length, 0, 'the host never saw it')
  } finally {
    h.stop()
  }
})

await scenario('the boot script is only injected into html', async () => {
  const h = await harness((req, res) => {
    if (req.url.includes('.js')) {
      res.writeHead(200, { 'content-type': 'application/javascript', 'content-length': '18' })
      res.end('export const a = 1')
      return
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': '26' })
    res.end('<html><body>hi</body></html>')
  })
  try {
    // Claiming `document` for a JS asset must not corrupt the bundle.
    h.pump.handleStreamData(11, request('GET', h.url('/assets/app.js'), ['Sec-Fetch-Dest: document']))
    await waitFor(() => h.text().includes('export const a = 1'))
    assert.ok(!h.text().includes('__dshRelayBoot'), 'no boot script in front of JavaScript')

    h.reset()
    h.pump.handleStreamData(12, request('GET', h.url('/'), ['Sec-Fetch-Dest: document']))
    await waitFor(() => h.text().includes('<html>'))
    assert.match(h.text(), /__dshRelayBoot/, 'html does get the boot script')
  } finally {
    h.stop()
  }
})

// The audit's third finding: the ciphertext did not name the request it belonged
// to, so a captured envelope could be re-submitted to another endpoint.
await scenario('a sealed request is bound to its method and path', async () => {
  const h = await harness((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '2' })
    res.end('{}')
  })

  const bind = (method, target, contentType, bytes) => sealBound(h.box, method, target, contentType, bytes)

  const send = (sid, method, path, body) => {
    h.pump.handleStreamData(sid, Buffer.concat([
      Buffer.from(`${method} ${h.url(path)} HTTP/1.1\r\nHost: relay.example\r\n`
        + `x-relay-enc: 1\r\nx-relay-ct: application/json\r\ncontent-length: ${body.length}\r\n`
        + 'Connection: close\r\n\r\n', 'latin1'),
      body,
    ]))
  }

  try {
    // 1. the envelope names a different path than the request it arrived on
    send(13, 'POST', '/api/approve', bind('POST', '/api/read-only', 'application/json', Buffer.from('{}')))
    await waitFor(() => h.closed.includes(13), 're-routed envelope refused')
    assert.equal(h.hits.length, 0, 'the host never saw the re-routed request')

    // 2. same path, different method
    send(14, 'DELETE', '/api/state', bind('POST', '/api/state', 'application/json', Buffer.from('{}')))
    await waitFor(() => h.closed.includes(14), 'method swap refused')
    assert.equal(h.hits.length, 0, 'the host never saw the method swap')

    // 3. a correct binding is unwrapped: the prefix never reaches the host
    send(15, 'POST', '/api/state', bind('POST', '/api/state', 'application/json', Buffer.from('{"v":1}')))
    await waitFor(() => h.hits.length === 1, 'bound POST forwarded')
    assert.equal(h.hits[0].url, '/api/state', 'the sealed target was honoured')
    assert.equal(h.hits[0].method, 'POST', 'the sealed method was honoured')
    assert.deepEqual(h.hits[0].body, Buffer.from('{"v":1}'), 'the prefix is stripped before forwarding')

    // The header is client-supplied and the relay can rewrite it, so the sealed
    // content-type must win.
    h.reset()
    send(17, 'POST', '/api/state', bind('POST', '/api/state', 'application/json', Buffer.from('{}')))
    // Rewrite the outer header to something else, as a hostile relay would.
    h.pump.handleStreamData(18, Buffer.concat([
      Buffer.from(`POST ${h.url('/api/state')} HTTP/1.1\r\nHost: relay.example\r\n`
        + `x-relay-enc: 1\r\nx-relay-ct: text/plain\r\ncontent-length: ${bind('POST', '/api/state', 'application/json', Buffer.from('{}')).length}\r\n`
        + 'Connection: close\r\n\r\n', 'latin1'),
      bind('POST', '/api/state', 'application/json', Buffer.from('{}')),
    ]))
    await waitFor(() => h.hits.length === 3, 'both bound posts arrive')
    assert.equal(h.hits[2].headers['content-type'], 'application/json', 'the sealed content-type wins')

    // 4. an unbound envelope cannot reach DSH at all any more
    h.reset()
    const seen = h.hits.length
    const binary = Buffer.from([0x02, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02])
    send(16, 'POST', '/api/upload', h.box.seal(h.box.envelopeKey, binary))
    await waitFor(() => h.closed.includes(16), 'unbound envelope refused')
    assert.equal(h.hits.length, seen, 'nothing reached the host')

    // 5. a body that merely starts with 0x02 but IS bound still forwards intact
    send(19, 'POST', '/api/upload', sealBound(h.box, 'POST', '/api/upload', 'application/octet-stream', binary))
    await waitFor(() => h.hits.length === seen + 1, 'bound binary forwarded')
    assert.deepEqual(h.hits[seen].body, binary, 'the bound body is forwarded without its prefix')
  } finally {
    h.stop()
  }
})


// The audit's path claim: the allowlist matched raw strings, so an asset path with
// dot segments could be normalized upstream into a private API.
await scenario('a traversal path cannot reach an API', async () => {
  const h = await harness((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '8' })
    res.end('private!')
  })
  try {
    for (const [sid, path] of [
      [21, '/assets/../api/private'],
      [22, '/assets/..%2f..%2fapi/private'],
      [23, '/api/private/../secrets.json'],
      [24, '//api/private'],
      [25, '/assets/app.js%00.png'],
    ]) {
      h.pump.handleStreamData(sid, request('GET', h.url(path), ['Sec-Fetch-Dest: document']))
      await waitFor(() => h.closed.includes(sid), `\${path} refused`)
    }
    assert.equal(h.hits.length, 0, 'no traversal reached the host')
    assert.ok(!h.text().includes('private!'), 'no private body came back')

    // A normal asset still passes.
    h.reset()
    h.pump.handleStreamData(26, request('GET', h.url('/assets/app.js'), ['Sec-Fetch-Dest: document']))
    await waitFor(() => h.hits.length === 1, 'a normal asset forwards')
    assert.equal(h.hits[0].url, '/assets/app.js')
  } finally {
    h.stop()
  }
})


await scenario('a sealed read needs a proof the relay cannot mint', async () => {
  const h = await harness((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '2' })
    res.end('{}')
  })
  try {
    // No proof at all: refused, nothing reaches the host.
    h.pump.handleStreamData(31, request('GET', h.url('/api/sessions'), ['x-relay-enc: 1']))
    await waitFor(() => h.closed.includes(31), 'a read without a proof is refused')
    assert.equal(h.hits.length, 0, 'the host never saw it')

    // A proof sealed for another path is a re-routing attempt.
    const stolen = sealBound(h.box, 'GET', '/api/other', '', Buffer.alloc(8))
    h.pump.handleStreamData(32, request('GET', h.url('/api/sessions'), [
      'x-relay-enc: 1',
      `x-relay-bind: ${stolen.toString('base64')}`,
    ]))
    await waitFor(() => h.closed.includes(32), 'a proof for another path is refused')
    assert.equal(h.hits.length, 0, 'the host never saw it')

    // A valid proof works once.
    const proof = sealBound(h.box, 'GET', '/api/sessions', '', Buffer.alloc(8))
    h.pump.handleStreamData(33, request('GET', h.url('/api/sessions'), [
      'x-relay-enc: 1',
      `x-relay-bind: ${proof.toString('base64')}`,
    ]))
    await waitFor(() => h.hits.length === 1, 'a valid proof forwards')

    // The same header again is a replay: the nonce cache already covers it.
    h.pump.handleStreamData(34, request('GET', h.url('/api/sessions'), [
      'x-relay-enc: 1',
      `x-relay-bind: ${proof.toString('base64')}`,
    ]))
    await waitFor(() => h.closed.includes(34), 'a replayed proof is refused')
    assert.equal(h.hits.length, 1, 'the replay never reached the host')
  } finally {
    h.stop()
  }
})


await scenario('a sealed target carrying the relay prefix is accepted', async () => {
  const h = await harness((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '2' })
    res.end('{}')
  })
  try {
    // What a page at /c/<id>/ actually seals for a relative call: prefix included.
    const prefixed = sealBound(h.box, 'GET', '/c/HTTP0001/api/settings/describe', '', Buffer.alloc(8))
    h.pump.handleStreamData(41, request('GET', h.url('/api/settings/describe'), [
      'x-relay-enc: 1',
      `x-relay-bind: ${prefixed.toString('base64')}`,
    ]))
    await waitFor(() => h.hits.length === 1, 'the prefixed target is accepted')
    assert.equal(h.hits[0].url, '/api/settings/describe', 'the forwarded path is the stripped one')

    // A different path is still a mismatch, prefix or not.
    h.reset()
    const other = sealBound(h.box, 'GET', '/c/HTTP0001/api/other', '', Buffer.alloc(8))
    h.pump.handleStreamData(42, request('GET', h.url('/api/settings/describe'), [
      'x-relay-enc: 1',
      `x-relay-bind: ${other.toString('base64')}`,
    ]))
    await waitFor(() => h.closed.includes(42), 'a real mismatch is still refused')
    assert.equal(h.hits.length, 1, 'nothing reached the host')
  } finally {
    h.stop()
  }
})

console.log(failures === 0 ? 'all pump http checks passed' : `${failures} pump http check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
