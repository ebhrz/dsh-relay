// Replay defence: a captured envelope must not work twice.
//
// The relay terminates TLS and sees the pairing ticket, so it can record any
// request the phone sends and submit it again verbatim without knowing the PSK.
// Every envelope carries a fresh random nonce; the host now remembers the nonces
// it has opened, so the second submission is refused exactly like a garbage one.

import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { CryptoBox } from '../src/crypto.js'
import { PumpManager } from '../src/pump.js'

const GATE = 'a'.repeat(64)
const ID = 'REPLAY01'

function makeBox() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  const identity = {
    id: ID,
    psk: crypto.randomBytes(32).toString('hex'),
    gate: GATE,
    signJwk: {
      public: publicKey.export({ format: 'jwk' }),
      private: privateKey.export({ format: 'jwk' }),
    },
  }
  return { box: new CryptoBox(identity), identity }
}

const waitFor = (check, timeout = 3000) => new Promise((resolve, reject) => {
  const started = Date.now()
  const tick = () => {
    if (check()) return resolve()
    if (Date.now() - started > timeout) return reject(new Error('timeout'))
    setTimeout(tick, 10)
  }
  tick()
})

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

await scenario('the same sealed body is accepted once and refused on replay', async () => {
  const { box } = makeBox()
  const plain = Buffer.from(JSON.stringify({ create: 'terminal' }), 'utf8')
  const sealed = box.seal(box.envelopeKey, plain)

  const first = box.open(box.envelopeKey, sealed)
  assert.ok(first && first.equals(plain), 'the first open succeeds')
  const second = box.open(box.envelopeKey, sealed)
  assert.equal(second, null, 'the replay is refused')
})

await scenario('two seals of the same body both work (fresh nonces)', async () => {
  const { box } = makeBox()
  const plain = Buffer.from('same bytes', 'utf8')
  const a = box.seal(box.envelopeKey, plain)
  const b = box.seal(box.envelopeKey, plain)
  assert.ok(box.open(box.envelopeKey, a), 'first copy opens')
  assert.ok(box.open(box.envelopeKey, b), 'the second copy opens too')
})

await scenario('the replay cache is bounded', async () => {
  const { box } = makeBox()
  const plain = Buffer.from('x', 'utf8')
  const total = 50_000 + 5
  let oldest = null
  for (let i = 0; i < total; i += 1) {
    const sealed = box.seal(box.envelopeKey, plain)
    if (i === 0) oldest = sealed
    assert.ok(box.open(box.envelopeKey, sealed), `open #${i}`)
  }
  assert.ok(box.openedNonces.size <= 50_000, `bounded, got ${box.openedNonces.size}`)
  // The oldest fell out of the window, so it is no longer recognised as a replay;
  // that is the documented bound, not a regression.
  assert.ok(box.open(box.envelopeKey, oldest), 'entries older than the window are forgotten')
})

await scenario('a replayed RPC over the pump reaches the host once', async () => {
  const { box, identity } = makeBox()
  const hits = []
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on('data', (chunk) => chunks.push(chunk))
    req.on('end', () => {
      hits.push(req.url)
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': '2' })
      res.end('{}')
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port

  const pump = new PumpManager({
    resolveTarget: () => ({ host: '127.0.0.1', port, authority: `127.0.0.1:${port}`, protocol: 'http:' }),
    resolveAuthCookie: () => 'dsh-auth=test',
    // A paired session, so the request is routed as the app surface would be.
    pairing: { sessionForHeaders: () => ({ did: ID }), handle: () => null },
    cryptoBox: box,
  })
  const out = []
  pump.setClient({ sendStream: (_sid, chunk) => out.push(Buffer.from(chunk)), closeStream: () => {} })

  const body = box.seal(box.envelopeKey, Buffer.from(JSON.stringify({ op: 'approve' }), 'utf8'))
  const request = () => Buffer.concat([
    Buffer.from(`POST /c/${ID}/api/ping?g=${GATE} HTTP/1.1\r\nHost: relay.example\r\n`
      + `x-relay-enc: 1\r\nx-relay-ct: application/json\r\ncontent-length: ${body.length}\r\n`
      + 'Connection: close\r\n\r\n', 'latin1'),
    body,
  ])

  try {
    pump.handleStreamData(61, request())
    await waitFor(() => hits.length === 1)
    assert.equal(hits.length, 1, 'the first submission is executed')

    out.length = 0
    pump.handleStreamData(62, request())
    // The replay must not reach the host again.
    await new Promise((done) => setTimeout(done, 300))
    assert.equal(hits.length, 1, 'the replay never reached the host')
    assert.match(Buffer.concat(out).toString('latin1'), /envelope|sealed|400|403/i, 'the client is told it failed')
  } finally {
    server.close()
    pump.handleStreamClose(61)
    pump.handleStreamClose(62)
  }
})

// The audit's second finding: `x-relay-enc: 1` with a zero-length body used to
// skip decryption entirely, so a ticket alone could POST an empty body to any
// local API path — with the host cookie attached.
await scenario('an empty body cannot stand in for an envelope', async () => {
  const { box, identity } = makeBox()
  const hits = []
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on('data', (chunk) => chunks.push(chunk))
    req.on('end', () => {
      hits.push({ url: req.url, body: Buffer.concat(chunks) })
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': '2' })
      res.end('{}')
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port

  const pump = new PumpManager({
    resolveTarget: () => ({ host: '127.0.0.1', port, authority: `127.0.0.1:${port}`, protocol: 'http:' }),
    resolveAuthCookie: () => 'dsh-auth=test',
    pairing: { sessionForHeaders: () => ({ did: ID }), handle: () => null },
    cryptoBox: box,
  })
  const out = []
  pump.setClient({ sendStream: (_sid, chunk) => out.push(Buffer.from(chunk)), closeStream: () => {} })

  const head = (extra) => Buffer.from(
    `POST /c/${ID}/api/shutdown?g=${GATE} HTTP/1.1\r\nHost: relay.example\r\n`
    + 'x-relay-enc: 1\r\nx-relay-ct: application/json\r\n'
    + `${extra}Connection: close\r\n\r\n`,
    'latin1',
  )

  try {
    // 1. content-length: 0
    pump.handleStreamData(71, head('content-length: 0\r\n'))
    await new Promise((done) => setTimeout(done, 200))
    assert.equal(hits.length, 0, 'a zero-length sealed body never reaches the host')
    assert.match(Buffer.concat(out).toString('latin1'), /400|403/, 'the client is told it failed')

    // 2. no content-length at all
    out.length = 0
    pump.handleStreamData(72, head(''))
    await new Promise((done) => setTimeout(done, 200))
    assert.equal(hits.length, 0, 'a missing content-length never reaches the host')

    // 3. a legitimate empty *plaintext* still works, because its envelope is 40 bytes
    out.length = 0
    const emptyEnvelope = box.seal(box.envelopeKey, Buffer.alloc(0))
    assert.equal(emptyEnvelope.length, 40, 'an empty plaintext seals to 40 bytes')
    pump.handleStreamData(73, Buffer.concat([
      head(`content-length: ${emptyEnvelope.length}\r\n`),
      emptyEnvelope,
    ]))
    await waitFor(() => hits.length === 1)
    assert.equal(hits[0].body.length, 0, 'the host received the empty plaintext')

    // 4. and that envelope is single-use like any other
    pump.handleStreamData(74, Buffer.concat([
      head(`content-length: ${emptyEnvelope.length}\r\n`),
      emptyEnvelope,
    ]))
    await new Promise((done) => setTimeout(done, 200))
    assert.equal(hits.length, 1, 'replaying the empty-plaintext envelope is refused')
  } finally {
    server.close()
    pump.handleStreamClose(71)
    pump.handleStreamClose(72)
    pump.handleStreamClose(73)
    pump.handleStreamClose(74)
  }
})

console.log(failures === 0 ? 'all replay checks passed' : `${failures} replay check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
