// Security properties of the relay's shared state.
//
// Everything the audit found that can be exercised over loopback lives here:
// stream ownership across tenants, device-id reuse, the admin key feeding the
// egress brake, and the pre-auth socket deadline. Real ports, real TLS, no
// traffic leaves 127.0.0.1.

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

// ── 5. dripping one byte at a time does not extend the deadline ─────
await scenario('a slow-dripping pre-auth connection is still cut', async () => {
  const relay = await startRelay(['--pre-auth-timeout', '1500'])
  try {
    const socket = net.connect({ host: '127.0.0.1', port: relay.phonePort })
    relay.sockets.push(socket)
    socket.on('error', () => {})
    const opened = Date.now()
    await new Promise((resolve) => socket.once('connect', resolve))
    // An idle timeout would be refreshed by every byte; an absolute deadline is not.
    const drip = setInterval(() => { if (!socket.destroyed) socket.write('G') }, 100)
    try {
      await waitFor(() => socket.destroyed, 'the dripping socket is closed', 8000)
    } finally {
      clearInterval(drip)
    }
    const elapsed = Date.now() - opened
    assert.ok(elapsed >= 1200 && elapsed < 5000, `cut at the deadline, not on idle: ${elapsed}ms`)
  } finally {
    relay.stop()
  }
})

// ── 6. an agent that upgrades but never registers is dropped ────────
await scenario('an agent that never registers is dropped', async () => {
  process.env.DSH_RELAY_REGISTRATION_MS = '800'
  const relay = await startRelay()
  try {
    const ws = new WebSocket(`wss://127.0.0.1:${relay.agentPort}/agent`, { rejectUnauthorized: false })
    const closed = new Promise((resolve) => ws.once('close', resolve))
    await new Promise((resolve, reject) => {
      ws.once('open', resolve)
      ws.once('error', reject)
    })
    const opened = Date.now()
    await Promise.race([
      closed,
      new Promise((_, reject) => setTimeout(() => reject(new Error('still open after 6s')), 6000)),
    ])
    assert.ok(Date.now() - opened < 5000, 'closed by the registration deadline')
  } finally {
    delete process.env.DSH_RELAY_REGISTRATION_MS
    relay.stop()
  }
})

// ── 7. an oversized agent frame is refused ──────────────────────────
await scenario('a frame above maxPayload closes the agent connection', async () => {
  const relay = await startRelay()
  try {
    const created = relay.tenant('bulk')
    const agent = await registerAgent(relay, 'BULK0001', { key: created.key })
    assert.ok(agent.registered, 'agent registered')
    const closed = new Promise((resolve) => agent.ws.once('close', resolve))
    agent.ws.send(Buffer.alloc(9 * 1024 * 1024, 0x41), { binary: true })
    await Promise.race([
      closed,
      new Promise((_, reject) => setTimeout(() => reject(new Error('connection stayed open')), 8000)),
    ])
  } finally {
    relay.stop()
  }
})

// ── 8. the ledger is private and the CLI never prints the secret ────
await scenario('the tenant ledger is 0600 in a 0700 directory and never echoed', async () => {
  const relay = await startRelay()
  try {
    relay.tenant('modes')
    if (process.platform !== 'win32') {
      const file = path.join(relay.dir, 'tenants.json')
      const fileMode = fs.statSync(file).mode & 0o777
      const dirMode = fs.statSync(relay.dir).mode & 0o777
      assert.equal(fileMode, 0o600, `ledger mode ${fileMode.toString(8)}`)
      assert.equal(dirMode, 0o700, `directory mode ${dirMode.toString(8)}`)
    }
    const shown = execFileSync(process.execPath, [
      relayPath, 'tenant', 'show', 'modes', '--data-dir', relay.dir,
    ], { encoding: 'utf8' })
    assert.ok(!/[0-9a-f]{64}/.test(shown), 'no 64-hex secret in the output')
    assert.match(shown, /"keyId"/, 'the non-secret key id is still there')
  } finally {
    relay.stop()
  }
})

// ── 9. a 404 log line does not leak the gate ───────────────────────
await scenario('the 404 log line redacts the gate', async () => {
  const relay = await startRelay()
  try {
    const gate = 'f'.repeat(64)
    const socket = net.connect({ host: '127.0.0.1', port: relay.phonePort })
    relay.sockets.push(socket)
    socket.on('error', () => {})
    await new Promise((resolve) => socket.once('connect', resolve))
    socket.write(`GET /nope?g=${gate} HTTP/1.1\r\nhost: x\r\nreferer: https://x/c/A/?g=${gate}\r\n\r\n`)
    await waitFor(() => relay.log().includes('404-noprefix'), 'the 404 is logged')
    await new Promise((done) => setTimeout(done, 200))
    assert.ok(!relay.log().includes(gate), 'the gate never appears in the log')
    assert.match(relay.log(), /<redacted>/, 'the log marks the redaction')
  } finally {
    relay.stop()
  }
})

// ── 10. garbage on the agent port does not kill the process ─────────
await scenario('a malformed upgrade and a null message leave the relay running', async () => {
  const relay = await startRelay()
  try {
    // `new URL()` throws on this; before the guard the throw escaped the 'upgrade'
    // listener and exited the process that serves every tenant.
    await new Promise((resolve) => {
      const socket = net.connect({ host: '127.0.0.1', port: relay.agentPort })
      relay.sockets.push(socket)
      socket.on('error', () => resolve())
      socket.on('close', resolve)
      socket.on('connect', () => {
        socket.write('GET http://[ HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
          + 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n')
      })
      setTimeout(resolve, 3000)
    })

    // `JSON.parse('null')` succeeds, and `msg.t` on null throws inside the listener.
    const ws = new WebSocket(`wss://127.0.0.1:${relay.agentPort}/agent`, { rejectUnauthorized: false })
    await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject) })
    const closed = new Promise((resolve) => ws.once('close', resolve))
    ws.send('null')
    await Promise.race([closed, new Promise((resolve) => setTimeout(resolve, 4000))])

    // The relay must still be serving: a fresh tenant registers and a phone
    // request still reaches that agent.
    const created = relay.tenant('alive')
    const agent = await registerAgent(relay, 'ALIVE001', { key: created.key, gate: GATE_A })
    assert.ok(agent.registered, 'the agent port still registers after the garbage')
    const phone = await openPhone(relay, 'ALIVE001', GATE_A)
    const frame = await firstFrame(agent)
    assert.ok(frame.length > 4, 'the phone request still reaches the agent')
    phone.socket.destroy()
    assert.ok(!/kept alive/.test(relay.log()), 'neither case reached the last-resort handler')
  } finally {
    relay.stop()
  }
})

console.log(failures === 0 ? 'all relay security checks passed' : `${failures} relay security check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
