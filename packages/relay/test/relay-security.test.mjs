// Security properties of the relay's shared state.
//
// Everything the audit found that can be exercised over loopback lives here:
// stream ownership across tenants, device-id reuse, the admin key feeding the
// egress brake, and the pre-auth socket deadline. Real ports, real TLS, no
// traffic leaves 127.0.0.1.

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
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
const GATE_A = 'a'.repeat(64)
const GATE_B = 'b'.repeat(64)

const waitFor = async (predicate, label, timeoutMs = 15000) => {
  const started = Date.now()
  for (;;) {
    const value = await predicate()
    if (value) return value
    if (Date.now() - started > timeoutMs) throw new Error(`timeout: ${label}`)
    await new Promise((done) => setTimeout(done, 40))
  }
}

const freePort = () => new Promise((resolve, reject) => {
  const server = net.createServer()
  server.once('error', reject)
  server.listen(0, '127.0.0.1', () => {
    const { port } = server.address()
    server.close(() => resolve(port))
  })
})

async function startRelay(extraArgs = []) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-sec-'))
  const phonePort = await freePort()
  const agentPort = await freePort()
  const child = spawn(process.execPath, [
    relayPath, '--port', phonePort, '--agent-port', agentPort,
    '--host', '127.0.0.1', '--agent-host', '127.0.0.1', '--data-dir', dir, ...extraArgs,
  ], { stdio: ['ignore', 'pipe', 'pipe'] })
  let output = ''
  child.stdout.on('data', (chunk) => { output += chunk })
  child.stderr.on('data', (chunk) => { output += chunk })
  // "ready" is logged before the listeners bind, so on Linux (where listen() is
  // asynchronous) waiting for it races with the first connect. Wait for both
  // listeners to announce themselves instead.
  await waitFor(() => output.includes('phone listener:') && output.includes('agent listener:'), 'relay listening', 20000)

  const relay = {
    dir,
    phonePort,
    agentPort,
    log: () => output,
    // The CLI path: create a tenant the way an operator would, then let the
    // server pick it up (it reloads before every hello).
    tenant(name) {
      const store = new TenantStore(path.join(dir, 'tenants.json'))
      const created = store.add({ name, quotaBytesDay: 5 * 1024 * 1024 })
      return created
    },
    stop() {
      for (const socket of sockets) { try { socket.destroy() } catch {} }
      try { child.kill() } catch {}
      fs.rmSync(dir, { recursive: true, force: true })
    },
  }
  const sockets = []
  relay.sockets = sockets
  return relay
}

/** Register an agent; `key` is a tenant key or null for the admin key. */
async function registerAgent(relay, id, { key, adminKey = null, gate = GATE_A } = {}) {
  const ws = new WebSocket(`wss://127.0.0.1:${relay.agentPort}/agent`, { rejectUnauthorized: false })
  const control = []
  const frames = []
  ws.on('message', (data, isBinary) => { if (isBinary) frames.push(data); else control.push(JSON.parse(data.toString())) })
  await new Promise((resolve, reject) => {
    ws.once('open', resolve)
    ws.once('error', reject)
  })

  const secret = key ? secretFor(key) : String(adminKey)
  const hello = { t: 'hello', v: 1, id, gate }
  if (key) hello.keyId = keyIdFor(key)
  ws.send(JSON.stringify(hello))

  const challenge = await waitFor(async () => control.find((m) => m.t === 'challenge'), `challenge for ${id}`)
  const proof = crypto.createHmac('sha256', secret).update(`${challenge.nonce}|${id}`).digest('hex')
  ws.send(JSON.stringify({ t: 'register', proof }))
  await waitFor(async () => control.some((m) => m.t === 'registered' || m.t === 'rejected'), `register ${id}`)
  const rejected = control.find((m) => m.t === 'rejected')
  return { ws, control, frames, registered: !rejected, rejected }
}

async function openPhone(relay, id, gate) {
  const socket = net.connect({ host: '127.0.0.1', port: relay.phonePort })
  relay.sockets.push(socket)
  socket.on('error', () => {})
  const chunks = []
  socket.on('data', (chunk) => chunks.push(chunk))
  await new Promise((resolve) => socket.once('connect', resolve))
  socket.write(`GET /c/${id}/probe?g=${gate} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n`)
  return { socket, text: () => Buffer.concat(chunks).toString('latin1') }
}

const firstFrame = (agent, timeoutMs = 8000) => new Promise((resolve, reject) => {
  if (agent.frames[0]) return resolve(agent.frames[0])
  const timer = setTimeout(() => reject(new Error('no frame reached the agent')), timeoutMs)
  const listener = (data, isBinary) => {
    if (!isBinary) return
    clearTimeout(timer)
    agent.ws.off('message', listener)
    resolve(data)
  }
  agent.ws.on('message', listener)
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

// ── 1. one tenant cannot write into, or close, another tenant's stream ─
await scenario('a tenant cannot inject into or close another tenant\'s stream', async () => {
  const relay = await startRelay()
  try {
    const alice = relay.tenant('alice')
    const bob = relay.tenant('bob')
    const agentA = await registerAgent(relay, 'AAA00001', { key: alice.key, gate: GATE_A })
    const agentB = await registerAgent(relay, 'BBB00002', { key: bob.key, gate: GATE_B })
    assert.ok(agentA.registered && agentB.registered, 'both tenants registered')

    const phoneB = await openPhone(relay, 'BBB00002', GATE_B)
    const frameB = await firstFrame(agentB)
    const sidB = frameB.readUInt32BE(0)

    // Alice's agent tries Bob's sid: write a whole fake response, then close it.
    const injected = Buffer.from('HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nPWNED!', 'latin1')
    agentA.ws.send(Buffer.concat([frameB.subarray(0, 4), injected]), { binary: true })
    agentA.ws.send(JSON.stringify({ t: 'close', sid: sidB }))

    await new Promise((done) => setTimeout(done, 400))
    assert.ok(!phoneB.text().includes('PWNED'), 'nothing Alice sent reached Bob\'s phone')

    // Bob's stream is still alive: his own reply arrives.
    const reply = Buffer.from('HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok', 'latin1')
    agentB.ws.send(Buffer.concat([frameB.subarray(0, 4), reply]), { binary: true })
    await waitFor(() => phoneB.text().includes('ok'), 'bob\'s phone still receives his own data')

    agentA.ws.close()
    agentB.ws.close()
  } finally {
    relay.stop()
  }
})

// ── 2. two tenants may use the same device id ────────────────────────
await scenario('the same device id can exist in two tenants without eviction', async () => {
  const relay = await startRelay()
  try {
    const first = relay.tenant('one')
    const second = relay.tenant('two')
    const a = await registerAgent(relay, 'SHARED01', { key: first.key, gate: GATE_A })
    const b = await registerAgent(relay, 'SHARED01', { key: second.key, gate: GATE_B })
    assert.ok(a.registered && b.registered, 'both tenants registered the same id')

    await new Promise((done) => setTimeout(done, 300))
    assert.equal(a.ws.readyState, 1, 'the first tenant was not evicted by the second')
    assert.equal(b.ws.readyState, 1, 'the second tenant is alive')

    // The gate decides which of the two agents a phone reaches.
    const phoneA = await openPhone(relay, 'SHARED01', GATE_A)
    const frameA = await firstFrame(a)
    assert.ok(frameA.readUInt32BE(0) > 0, 'gate A reached agent A')
    assert.equal(b.frames.length, 0, 'agent B never saw the gate-A stream')

    phoneA.socket.destroy()
    a.ws.close()
    b.ws.close()
  } finally {
    relay.stop()
  }
})

// ── 3. the egress brake counts the admin key and stays shut for the day ─
await scenario('the egress brake covers the admin key and refuses reconnects', async () => {
  const adminKey = 'k'.repeat(48)
  const relay = await startRelay(['--key', adminKey, '--egress-limit', '100KB'])
  try {
    const admin = await registerAgent(relay, 'ADMIN001', { adminKey })
    assert.ok(admin.registered, 'the admin key registers')

    const phone = await openPhone(relay, 'ADMIN001', GATE_A)
    const first = await firstFrame(admin)
    const blob = Buffer.alloc(200 * 1024, 0x41)
    admin.ws.send(Buffer.concat([first.subarray(0, 4), blob]), { binary: true })

    await waitFor(
      () => admin.control.some((m) => m.t === 'rejected' && m.reason === 'egress-limit') || admin.ws.readyState === 3,
      'the admin connection is cut by the brake',
    )
    assert.match(relay.log(), /egress limit reached/, 'the brake logs why')

    // A reconnect must not slip back in while the brake is latched for the day:
    // the refusal happens at `hello`, before any challenge is issued.
    const again = new WebSocket(`wss://127.0.0.1:${relay.agentPort}/agent`, { rejectUnauthorized: false })
    const control = []
    again.on('message', (data, isBinary) => { if (!isBinary) control.push(JSON.parse(data.toString())) })
    await new Promise((resolve, reject) => {
      again.once('open', resolve)
      again.once('error', reject)
    })
    again.send(JSON.stringify({ t: 'hello', v: 1, id: 'ADMIN002', gate: GATE_A }))
    const refusal = await waitFor(() => control.find((m) => m.t === 'rejected' || m.t === 'challenge'), 'the reconnect is answered')
    assert.equal(refusal.t, 'rejected', 'a reconnect is refused while the brake holds today')
    assert.equal(refusal.reason, 'egress-limit')
    again.close()

    phone.socket.destroy()
  } finally {
    relay.stop()
  }
})

// ── 4. a silent phone connection is dropped ─────────────────────────
await scenario('a connection that never sends a request line is dropped', async () => {
  const relay = await startRelay(['--pre-auth-timeout', '1000'])
  try {
    const socket = net.connect({ host: '127.0.0.1', port: relay.phonePort })
    relay.sockets.push(socket)
    socket.on('error', () => {})
    const opened = Date.now()
    await new Promise((resolve) => socket.once('connect', resolve))
    await waitFor(() => socket.destroyed, 'the silent socket is closed', 6000)
    const elapsed = Date.now() - opened
    assert.ok(elapsed >= 900 && elapsed < 5000, `closed after ~1s, got ${elapsed}ms`)
  } finally {
    relay.stop()
  }
})

console.log(failures === 0 ? 'all relay security checks passed' : `${failures} relay security check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
