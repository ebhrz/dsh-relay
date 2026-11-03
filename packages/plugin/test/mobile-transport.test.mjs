#!/usr/bin/env node
// Transport-level checks for the mobile app surface (no relay, no dsh web).
//
//   node test-mobile-transport.mjs
//
// Stands up the real PumpManager + PairingService + MobileRouter behind a fake
// "relay": a plain TCP listener that forwards phone bytes into the pump and
// writes pump output back, which is exactly what RelayClient does over WSS.
// Then it plays the phone: pairing handshake, page/assets, sealed RPC, and the
// sealed WebSocket push channel.

import assert from 'node:assert/strict'
import net from 'node:net'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import nacl from 'tweetnacl'
import { WebSocket } from 'ws'

// Keep audit/identity writes out of the live ~/.dsh.
const TEST_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-relay-mobile-'))
process.env.DSH_HOME = TEST_HOME

const { PumpManager } = await import('../src/pump.js')
const { MobileRouter } = await import('../src/mobile/index.js')
const { CryptoBox } = await import('../src/crypto.js')
const { PairingService } = await import('../src/pairing.js')
const { createIdentity } = await import('../src/identity.js')

const identity = createIdentity()
const cryptoBox = new CryptoBox(identity)
const pairing = new PairingService(cryptoBox, identity)
const GATE = identity.gate
const ID = identity.id

const envKey = new Uint8Array(
  crypto.createHash('sha512').update(Buffer.from(identity.psk, 'hex'))
    .update(Buffer.from('envelope')).digest().subarray(0, 32),
)
const seal = (bytes) => {
  const nonce = nacl.randomBytes(24)
  const box = nacl.secretbox(bytes, nonce, envKey)
  const out = new Uint8Array(24 + box.length)
  out.set(nonce, 0); out.set(box, 24)
  return out
}
const open = (bytes) => {
  const opened = nacl.secretbox.open(bytes.subarray(24), bytes.subarray(0, 24), envKey)
  return opened ? new Uint8Array(opened) : null
}

// -- fake mobile bridge ------------------------------------------------------
const subscribed = new Map() // sid -> { sessionId, emit }
const fakeBridge = {
  upstreamReady: () => true,
  async rpc(method, params) {
    if (method === 'boom') throw Object.assign(new Error('planned failure'), { code: 'test-failure' })
    return { echo: method, params, phone: true }
  },
  subscribe(sid, sessionId, emit) { subscribed.set(sid, { sessionId, emit }) },
  unsubscribe(sid) { subscribed.delete(sid) },
  onPhoneOpen() { fakeBridge.openCount = (fakeBridge.openCount ?? 0) + 1 },
  onPhoneClose() { fakeBridge.closeCount = (fakeBridge.closeCount ?? 0) + 1 },
}

const mobile = new MobileRouter({ cryptoBox, bridge: fakeBridge })
const pump = new PumpManager({
  resolveTarget: () => ({ host: '127.0.0.1', port: 1, authority: '127.0.0.1:1', protocol: 'http:' }),
  resolveAuthCookie: () => null,
  pairing,
  cryptoBox,
  mobile,
})

// -- fake relay: TCP in/out must be one phone "stream" -----------------------
const sockets = new Map()
let nextSid = 1
const relay = net.createServer((socket) => {
  const sid = nextSid++
  sockets.set(sid, socket)
  socket.on('data', (chunk) => pump.handleStreamData(sid, chunk))
  socket.on('close', () => { sockets.delete(sid); pump.handleStreamClose(sid) })
  socket.on('error', () => {})
})
pump.setClient({
  sendStream(sid, chunk) { sockets.get(sid)?.write(chunk) },
  closeStream(sid) { sockets.get(sid)?.end() },
})
await new Promise((resolve) => relay.listen(0, '127.0.0.1', resolve))
const PORT = relay.address().port
const BASE = `http://127.0.0.1:${PORT}/c/${ID}`

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// -- pairing -----------------------------------------------------------------
async function pair() {
  const post = (name, body) => fetch(`${BASE}/__relay/${name}?g=${GATE}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
  const psk = Buffer.from(identity.psk, 'hex')
  const cnonce = crypto.randomBytes(12).toString('base64')
  const { snonce } = await (await post('challenge', { cnonce })).json()
  const proof = crypto.createHash('sha512').update(psk)
    .update(Buffer.from(`${cnonce}|${snonce}|verify`)).digest('hex')
  const res = await post('verify', { cnonce, snonce, proof })
  assert.equal(res.status, 200)
  const cookies = []
  for (const raw of res.headers.getSetCookie()) cookies.push(raw.split(';')[0])
  return cookies.join('; ')
}
const cookie = await pair()
console.log('ok 1: pairing handshake over the fake relay')

// -- unauthenticated page request -> pairing page, not the app --------------
{
  const res = await fetch(`${BASE}/m?g=${GATE}`)
  const text = await res.text()
  assert.match(text, /配对/)
  assert.doesNotMatch(text, /id="app"/)
  console.log('ok 2: unauthenticated mobile request gets the pairing page')
}

// -- page + assets -----------------------------------------------------------
{
  const res = await fetch(`${BASE}/m?g=${GATE}`, { headers: { cookie } })
  assert.equal(res.status, 200)
  assert.match(res.headers.get('content-type'), /text\/html/)
  const html = await res.text()
  assert.match(html, /id="app"/)
  assert.match(html, /\/m\/app\.js/)
  assert.match(html, /\/m\/app\.css/)
  assert.match(html, /\/m\/nacl\.js/)

  const app = await fetch(`${BASE}/m/app.js?g=${GATE}`, { headers: { cookie } })
  assert.equal(app.status, 200)
  assert.match(app.headers.get('content-type'), /javascript/)
  assert.match(app.headers.get('cache-control'), /immutable/)
  const etag = app.headers.get('etag')
  const revalidated = await fetch(`${BASE}/m/app.js?g=${GATE}`, { headers: { cookie, 'if-none-match': etag } })
  assert.equal(revalidated.status, 304)
  const missing = await fetch(`${BASE}/m/nope.js?g=${GATE}`, { headers: { cookie } })
  assert.equal(missing.status, 404)
  console.log('ok 3: page rendered with hashed assets; immutable cache + 304 + 404')
}

// -- sealed RPC --------------------------------------------------------------
async function rpc(method, params = {}) {
  const body = seal(Buffer.from(JSON.stringify({ id: 7, method, params })))
  const res = await fetch(`${BASE}/__relay/m/rpc?g=${GATE}`, {
    method: 'POST',
    headers: {
      cookie,
      'content-type': 'application/octet-stream',
      'x-relay-enc': '1',
      'x-relay-ct': 'application/json',
    },
    body,
  })
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('x-relay-enc'), '1')
  const inner = open(new Uint8Array(await res.arrayBuffer()))
  assert.ok(inner, 'sealed response opens')
  const text = Buffer.from(inner).toString('utf8')
  assert.match(text, /^HTTP\/1\.1 200 OK/)
  const json = JSON.parse(text.slice(text.indexOf('\r\n\r\n') + 4))
  return json
}
{
  const reply = await rpc('hello', { a: 1 })
  assert.equal(reply.ok, true)
  assert.deepEqual(reply.result, { echo: 'hello', params: { a: 1 }, phone: true })
  assert.equal(reply.id, 7)

  const bad = await rpc('boom')
  assert.equal(bad.ok, false)
  assert.equal(bad.error.code, 'test-failure')

  // Keep-alive: a second RPC on the same phone socket must work (the pump
  // recycles after each sealed reply instead of closing).
  const again = await rpc('hello2')
  assert.equal(again.result.echo, 'hello2')
  console.log('ok 4: sealed RPC round trips (success, surfaced failure, keep-alive reuse)')
}

// -- plaintext API call is refused ------------------------------------------
{
  const res = await fetch(`${BASE}/__relay/m/rpc?g=${GATE}`, {
    method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: '{"method":"hello"}',
  })
  assert.equal(res.status, 400)
  console.log('ok 5: unsealed mobile API calls are rejected')
}

// -- sealed WebSocket push channel ------------------------------------------
{
  const ws = new WebSocket(`ws://127.0.0.1:${PORT}/c/${ID}/__relay/m/ws?g=${GATE}`, {
    headers: { cookie },
  })
  const frames = []
  const waiters = []
  ws.on('message', (data) => {
    const parsed = JSON.parse(String(data))
    const plain = open(Buffer.from(parsed.__relay, 'base64'))
    const event = JSON.parse(Buffer.from(plain).toString('utf8'))
    frames.push(event)
    for (const w of waiters.splice(0)) w()
  })
  const waitFor = (predicate) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('ws timeout')), 3000)
    const check = () => {
      const found = frames.find(predicate)
      if (found) { clearTimeout(timer); resolve(found); return }
      waiters.push(check)
    }
    check()
  })
  await new Promise((resolve, reject) => { ws.on('open', resolve); ws.on('error', reject) })
  const subscribe = seal(Buffer.from(JSON.stringify({ t: 'subscribe', sessionId: 'session-1' })))
  ws.send(JSON.stringify({ __relay: Buffer.from(subscribe).toString('base64') }))
  await sleep(80)
  assert.equal(subscribed.size, 1)
  assert.equal([...subscribed.values()][0].sessionId, 'session-1')

  // The bridge emits a projected event; the router seals and pushes it.
  const entry = [...subscribed.values()][0]
  entry.emit({ t: 'event', sessionId: 'session-1', item: { kind: 'assistant', text: '你好' } })
  const event = await waitFor((e) => e.t === 'event')
  assert.equal(event.item.text, '你好')

  // Ping/pong over the same sealed channel.
  const ping = seal(Buffer.from(JSON.stringify({ t: 'ping' })))
  ws.send(JSON.stringify({ __relay: Buffer.from(ping).toString('base64') }))
  await waitFor((e) => e.t === 'pong')

  ws.close()
  await sleep(120)
  assert.equal(fakeBridge.openCount, 1)
  assert.equal(subscribed.size, 0, 'subscription released on close')
  console.log('ok 6: sealed WebSocket subscribe/push/ping + close cleanup')
}

// -- unauthenticated WS upgrade is refused ----------------------------------
{
  const ws = new WebSocket(`ws://127.0.0.1:${PORT}/c/${ID}/__relay/m/ws?g=${GATE}`)
  const status = await new Promise((resolve) => {
    ws.on('unexpected-response', (_req, res) => resolve(res.statusCode))
    ws.on('open', () => resolve(101))
    ws.on('error', () => {})
  })
  assert.notEqual(status, 101, 'ticketless websocket must not be accepted')
  try { ws.terminate() } catch {}
  console.log('ok 7: ticketless WebSocket upgrade refused')
}

// -- paired phone opening the legacy root URL lands on the mobile page ------
{
  const res = await fetch(`${BASE}/?g=${GATE}`, {
    headers: {
      cookie,
      'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
      accept: 'text/html',
    },
    redirect: 'manual',
  })
  assert.equal(res.status, 302)
  assert.equal(res.headers.get('location'), `/c/${ID}/m?g=${GATE}`)
  console.log('ok 8: a paired phone opening / is redirected to the mobile page')
  // ...and the escape hatch keeps the full desktop UI (the fake upstream is
  // unreachable here, so only the redirect decision is asserted).
  const desktop = await fetch(`${BASE}/?g=${GATE}&desktop=1`, {
    headers: { cookie, 'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7) Mobile/15E148', accept: 'text/html' },
    redirect: 'manual',
  })
  assert.notEqual(desktop.status, 302, '?desktop=1 does not redirect')
  console.log('ok 9: ?desktop=1 opts out of the mobile redirect')
}

relay.close()
for (const socket of sockets.values()) socket.destroy()
fs.rmSync(TEST_HOME, { recursive: true, force: true })
console.log('\nall mobile transport checks passed')
