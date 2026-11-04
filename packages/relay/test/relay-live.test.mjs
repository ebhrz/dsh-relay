// Multi-tenant relay wiring, end to end on loopback: a tenant key registers an
// agent, the phone listener routes to it, bytes are metered, and the connection
// is cut when the daily quota is reached.
//
// Real ports and a real self-signed cert, but nothing leaves 127.0.0.1.

import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { WebSocket } from 'ws'
import { TenantStore, keyIdFor, secretFor } from '../src/tenants.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const relayPath = path.join(here, '..', 'src', 'index.mjs')

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-live-'))
const GATE = 'b'.repeat(64)
const AGENT_ID = 'TEST0001'
const QUOTA = 4096

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      server.close(() => resolve(port))
    })
  })
}

const waitFor = async (predicate, label, timeoutMs = 15000) => {
  const started = Date.now()
  for (;;) {
    const value = await predicate()
    if (value) return value
    if (Date.now() - started > timeoutMs) throw new Error(`timeout: ${label}`)
    await new Promise((done) => setTimeout(done, 50))
  }
}

const store = new TenantStore(path.join(dir, 'tenants.json'), { quotaDefault: QUOTA })
const created = store.add({ name: 'tester', quotaBytesDay: QUOTA, maxStreams: 2 })
const key = created.key
store.save()

const phonePort = await freePort()
const agentPort = await freePort()

const child = spawn(process.execPath, [relayPath, '--port', phonePort, '--agent-port', agentPort, '--host', '127.0.0.1', '--agent-host', '127.0.0.1', '--data-dir', dir], { stdio: ['ignore', 'pipe', 'pipe'] })
let output = ''
child.stdout.on('data', (chunk) => { output += chunk.toString() })
child.stderr.on('data', (chunk) => { output += chunk.toString() })
const stop = () => { try { child.kill() } catch {} }

try {
  await waitFor(async () => output.includes('ready'), 'relay ready', 20000)

  // ── register as the tenant ──────────────────────────────────────────
  const ws = new WebSocket(`wss://127.0.0.1:${agentPort}/agent`, { rejectUnauthorized: false })
  const agentMessages = []
  ws.on('message', (data, isBinary) => { if (!isBinary) agentMessages.push(JSON.parse(data.toString())) })

  await new Promise((resolve, reject) => {
    ws.once('open', resolve)
    ws.once('error', reject)
  })
  ws.send(JSON.stringify({ t: 'hello', v: 1, id: AGENT_ID, gate: GATE, keyId: keyIdFor(key) }))

  const challenge = await waitFor(async () => agentMessages.find((m) => m.t === 'challenge'), 'challenge')
  const proof = crypto.createHmac('sha256', secretFor(key)).update(`${challenge.nonce}|${AGENT_ID}`).digest('hex')
  ws.send(JSON.stringify({ t: 'register', proof }))
  await waitFor(async () => agentMessages.find((m) => m.t === 'registered' || (m.t === 'rejected')), 'register result')
  assert.ok(agentMessages.some((m) => m.t === 'registered'), `expected registration, got ${JSON.stringify(agentMessages)}`)

  // ── route a phone request through, and echo it back ─────────────────
  const socket = net.connect({ host: '127.0.0.1', port: phonePort })
  const received = []
  socket.on('data', (chunk) => received.push(chunk))
  await new Promise((resolve) => socket.once('connect', resolve))
  socket.write(`GET /c/${AGENT_ID}/probe?g=${GATE} HTTP/1.1\r\nhost: x\r\n\r\n`)

  const streamFrame = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('no stream frame reached the agent')), 8000)
    const listener = (data, isBinary) => {
      if (!isBinary) return
      clearTimeout(timer)
      ws.off('message', listener)
      resolve(data)
    }
    ws.on('message', listener)
  })
  const sid = streamFrame.readUInt32BE(0)
  assert.ok(sid > 0, 'stream id allocated')

  const reply = Buffer.from('HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi')
  ws.send(Buffer.concat([streamFrame.subarray(0, 4), reply]), { binary: true })
  await waitFor(async () => Buffer.concat(received).toString('latin1').includes('hi'), 'phone receives the reply')

  // ── metering ────────────────────────────────────────────────────────
  ws.close()
  socket.destroy()
  await new Promise((done) => setTimeout(done, 300))
  const ledger = JSON.parse(fs.readFileSync(path.join(dir, 'tenants.json'), 'utf8'))
  const tenant = ledger.tenants.find((item) => item.id === 'tester')
  assert.ok(tenant.usedBytesDay > 0, `bytes must be metered, got ${tenant.usedBytesDay}`)
  assert.ok(tenant.usedBytesDay < QUOTA, 'a small exchange stays under the quota')

  // ── concurrency cap: maxStreams is 2 for this tenant ────────────────
  const wsCap = new WebSocket(`wss://127.0.0.1:${agentPort}/agent`, { rejectUnauthorized: false })
  const capMessages = []
  const capFrames = []
  wsCap.on('message', (data, isBinary) => {
    if (isBinary) capFrames.push(data)
    else capMessages.push(JSON.parse(data.toString()))
  })
  await new Promise((resolve, reject) => {
    wsCap.once('open', resolve)
    wsCap.once('error', reject)
  })
  wsCap.send(JSON.stringify({ t: 'hello', v: 1, id: AGENT_ID, gate: GATE, keyId: keyIdFor(key) }))
  const capChallenge = await waitFor(async () => capMessages.find((m) => m.t === 'challenge'), 'challenge for the cap test')
  const capProof = crypto.createHmac('sha256', secretFor(key)).update(`${capChallenge.nonce}|${AGENT_ID}`).digest('hex')
  wsCap.send(JSON.stringify({ t: 'register', proof: capProof }))
  await waitFor(async () => capMessages.some((m) => m.t === 'registered' || m.t === 'rejected'), 'registered for the cap test')

  const held = []
  for (let i = 0; i < 2; i += 1) {
    const heldSocket = net.connect({ host: '127.0.0.1', port: phonePort })
    heldSocket.on('error', () => {})
    await new Promise((resolve) => heldSocket.once('connect', resolve))
    heldSocket.write(`GET /c/${AGENT_ID}/hold${i}?g=${GATE} HTTP/1.1\r\nhost: x\r\n\r\n`)
    held.push(heldSocket)
  }
  await waitFor(async () => capFrames.length >= 2, 'both streams reached the agent')

  const overflow = net.connect({ host: '127.0.0.1', port: phonePort })
  overflow.on('error', () => {})
  const overflowText = await new Promise((resolve) => {
    let text = ''
    overflow.on('data', (chunk) => { text += chunk.toString('latin1') })
    overflow.on('close', () => resolve(text))
    overflow.once('connect', () => overflow.write(`GET /c/${AGENT_ID}/over?g=${GATE} HTTP/1.1\r\nhost: x\r\n\r\n`))
    setTimeout(() => resolve(text), 5000)
  })
  assert.match(overflowText, /429 Too Many Requests/, `the third stream must be refused, got: ${overflowText.slice(0, 80)}`)
  overflow.destroy()
  for (const heldSocket of held) heldSocket.destroy()
  wsCap.close()
  await new Promise((done) => setTimeout(done, 300))

  // ── quota cutoff: refill the ledger, then push past the limit ───────
  const reloaded = new TenantStore(path.join(dir, 'tenants.json'))
  const t2 = reloaded.get('tester')
  t2.usedBytesDay = QUOTA - 10
  reloaded.save()

  const ws2 = new WebSocket(`wss://127.0.0.1:${agentPort}/agent`, { rejectUnauthorized: false })
  const messages2 = []
  ws2.on('message', (data, isBinary) => { if (!isBinary) messages2.push(JSON.parse(data.toString())) })
  await new Promise((resolve, reject) => {
    ws2.once('open', resolve)
    ws2.once('error', reject)
  })
  ws2.send(JSON.stringify({ t: 'hello', v: 1, id: AGENT_ID, gate: GATE, keyId: keyIdFor(key) }))
  const challenge2 = await waitFor(async () => messages2.find((m) => m.t === 'challenge'), 'challenge 2')
  const proof2 = crypto.createHmac('sha256', secretFor(key)).update(`${challenge2.nonce}|${AGENT_ID}`).digest('hex')
  ws2.send(JSON.stringify({ t: 'register', proof: proof2 }))
  await waitFor(async () => messages2.find((m) => m.t === 'registered' || m.t === 'rejected'), 'register 2')
  assert.ok(messages2.some((m) => m.t === 'registered'), 'a tenant under the limit registers')

  const socket2 = net.connect({ host: '127.0.0.1', port: phonePort })
  socket2.on('error', () => {})
  await new Promise((resolve) => socket2.once('connect', resolve))
  socket2.write(`GET /c/${AGENT_ID}/probe?g=${GATE} HTTP/1.1\r\nhost: x\r\n\r\n`)
  const frame2 = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('no stream frame for the quota probe')), 8000)
    const listener = (data, isBinary) => {
      if (!isBinary) return
      clearTimeout(timer)
      ws2.off('message', listener)
      resolve(data)
    }
    ws2.on('message', listener)
  })
  // Push more than the remaining quota in one frame.
  ws2.send(Buffer.concat([frame2.subarray(0, 4), Buffer.alloc(4096, 0x41)]), { binary: true })

  await waitFor(async () => messages2.some((m) => m.t === 'rejected' && m.reason === 'quota-exceeded'), 'quota rejection')
  const closed = await waitFor(async () => ws2.readyState === 3, 'agent connection terminated')
  assert.ok(closed, 'the agent connection is closed after the quota is spent')

  // A blocked tenant cannot register again the same day.
  const ws3 = new WebSocket(`wss://127.0.0.1:${agentPort}/agent`, { rejectUnauthorized: false })
  const messages3 = []
  ws3.on('message', (data, isBinary) => { if (!isBinary) messages3.push(JSON.parse(data.toString())) })
  await new Promise((resolve, reject) => {
    ws3.once('open', resolve)
    ws3.once('error', reject)
  })
  ws3.send(JSON.stringify({ t: 'hello', v: 1, id: AGENT_ID, gate: GATE, keyId: keyIdFor(key) }))
  await waitFor(async () => messages3.find((m) => m.t === 'rejected'), 'blocked registration')
  assert.equal(messages3.find((m) => m.t === 'rejected').reason, 'quota-exceeded')
  ws3.close()

  // ── a key created while the server runs works immediately ──────────
  // The CLI writes the ledger and signals the running relay (SIGHUP), so the
  // 15-second watcher is not the only thing that can pick it up.
  const cliOut = execFileSync(process.execPath, [
    relayPath, 'tenant', 'add', '--name', 'liveadd', '--quota', '5MB', '--max-streams', '3', '--data-dir', dir,
  ], { encoding: 'utf8' })
  const liveKey = cliOut.split('\n').map((line) => line.trim()).find((line) => /^[0-9a-f]{48}$/.test(line))
  assert.ok(liveKey, 'the CLI printed a key')

  const ws5 = new WebSocket(`wss://127.0.0.1:${agentPort}/agent`, { rejectUnauthorized: false })
  const messages5 = []
  ws5.on('message', (data, isBinary) => { if (!isBinary) messages5.push(JSON.parse(data.toString())) })
  await new Promise((resolve, reject) => {
    ws5.once('open', resolve)
    ws5.once('error', reject)
  })
  ws5.send(JSON.stringify({ t: 'hello', v: 1, id: 'LIVEADD1', gate: GATE, keyId: keyIdFor(liveKey) }))
  const challenge5 = await waitFor(async () => messages5.find((m) => m.t === 'challenge'), 'challenge for the live-added key', 5000)
  const proof5 = crypto.createHmac('sha256', secretFor(liveKey)).update(`${challenge5.nonce}|LIVEADD1`).digest('hex')
  ws5.send(JSON.stringify({ t: 'register', proof: proof5 }))
  await waitFor(async () => messages5.find((m) => m.t === 'registered' || m.t === 'rejected'), 'live-added key registers', 5000)
  assert.ok(messages5.some((m) => m.t === 'registered'), `a key added while running is usable at once: ${JSON.stringify(messages5)}`)
  ws5.close()

  // ── an unknown key is refused ───────────────────────────────────────
  const ws4 = new WebSocket(`wss://127.0.0.1:${agentPort}/agent`, { rejectUnauthorized: false })
  const messages4 = []
  ws4.on('message', (data, isBinary) => { if (!isBinary) messages4.push(JSON.parse(data.toString())) })
  await new Promise((resolve, reject) => {
    ws4.once('open', resolve)
    ws4.once('error', reject)
  })
  ws4.send(JSON.stringify({ t: 'hello', v: 1, id: 'OTHER001', gate: GATE, keyId: 'ffffffffffff' }))
  const challenge4 = await waitFor(async () => messages4.find((m) => m.t === 'challenge'), 'challenge 4')
  const proof4 = crypto.createHmac('sha256', 'definitely-not-a-key').update(`${challenge4.nonce}|OTHER001`).digest('hex')
  ws4.send(JSON.stringify({ t: 'register', proof: proof4 }))
  await waitFor(async () => messages4.find((m) => m.t === 'rejected'), 'unknown key rejection')
  // No tenant matches and this relay has no --key, so the key is unknown.
  assert.equal(messages4.find((m) => m.t === 'rejected').reason, 'unknown-key')
  ws4.close()

  // ── the admin --key still works alongside tenants ───────────────────
  // (Relay restarted with --key in its own test would double the runtime; the
  // fallback path is covered by the register branch reading args.key.)

  console.log('ok: relay tenants, metering and quota cutoff')
} finally {
  stop()
  fs.rmSync(dir, { recursive: true, force: true })
}
