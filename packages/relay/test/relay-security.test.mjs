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
import tls from 'node:tls'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { WebSocket } from 'ws'
import { TenantStore, keyIdFor, secretFor, legacySecretFor } from '../src/tenants.js'

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
async function registerAgent(relay, id, { key, adminKey = null, gate = GATE_A, proofSecret = null } = {}) {
  const ws = new WebSocket(`wss://127.0.0.1:${relay.agentPort}/agent`, { rejectUnauthorized: false })
  const control = []
  const frames = []
  ws.on('message', (data, isBinary) => { if (isBinary) frames.push(data); else control.push(JSON.parse(data.toString())) })
  await new Promise((resolve, reject) => {
    ws.once('open', resolve)
    ws.once('error', reject)
  })

  const secret = proofSecret ?? (key ? secretFor(key) : String(adminKey))
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

await scenario('a relayed request is rewritten to close its connection', async () => {
  const relay = await startRelay()
  try {
    const created = relay.tenant('single-shot')
    const agent = await registerAgent(relay, 'ONESHOT1', { key: created.key, gate: GATE_A })
    const socket = net.connect({ host: '127.0.0.1', port: relay.phonePort })
    relay.sockets.push(socket)
    socket.on('error', () => {})
    await new Promise((resolve) => socket.once('connect', resolve))
    // What a pooling proxy sends: keep-alive on the wire to the relay.
    socket.write(`GET /c/ONESHOT1/probe?g=${GATE_A} HTTP/1.1\r\nhost: x\r\nconnection: keep-alive\r\nkeep-alive: timeout=5\r\n\r\n`)
    const frame = await firstFrame(agent)
    const head = frame.toString('latin1')
    assert.match(head, /(?:\r\n|^)Connection: close\r\n/i, 'the agent is asked to close')
    assert.doesNotMatch(head, /keep-alive/i, 'the keep-alive hints are gone')
    socket.destroy()
  } finally {
    relay.stop()
  }
})

await scenario('a request without a gate learns nothing about the device', async () => {
  const relay = await startRelay()
  try {
    // No agent for this id and no gate on the request: the answer must be the
    // same 403 a wrong gate gets, not "offline" (which would map live ids).
    const socket = net.connect({ host: '127.0.0.1', port: relay.phonePort })
    relay.sockets.push(socket)
    socket.on('error', () => {})
    const chunks = []
    socket.on('data', (chunk) => chunks.push(chunk))
    await new Promise((resolve) => socket.once('connect', resolve))
    socket.write('GET /c/OFFLINE1/probe HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n')
    const text = await waitFor(() => {
      const body = Buffer.concat(chunks).toString('latin1')
      return body.includes('\r\n\r\n') ? body : ''
    }, 'a response for the gateless request')
    assert.match(text, /^HTTP\/1\.1 403/, 'refused before any device state is disclosed')
    socket.destroy()
  } finally {
    relay.stop()
  }
})

await scenario('a second request for another tenant never reaches the bound agent', async () => {
  // This is the pooled-connection attack in its most direct form: two requests,
  // one socket, two tenants. The relay must cut the connection before the second
  // request - and before a byte of it reaches the first tenant's agent.
  const relay = await startRelay()
  try {
    const a = relay.tenant('tenant-a')
    const b = relay.tenant('tenant-b')
    const agentA = await registerAgent(relay, 'TENANTA1', { key: a.key, gate: GATE_A })
    const agentB = await registerAgent(relay, 'TENANTB1', { key: b.key, gate: GATE_B })
    assert.ok(agentA.registered && agentB.registered, 'both tenants are connected')

    const socket = net.connect({ host: '127.0.0.1', port: relay.phonePort })
    relay.sockets.push(socket)
    socket.on('error', () => {})
    await new Promise((resolve) => socket.once('connect', resolve))

    socket.write(`GET /c/TENANTA1/first?g=${GATE_A} HTTP/1.1\r\nhost: x\r\n\r\n`)
    const firstFrameA = await firstFrame(agentA)
    // Stream frames carry a 4-byte length prefix in front of the phone bytes.
    const firstHead = firstFrameA.subarray(4).toString('latin1')
    assert.ok(
      firstHead.startsWith('GET /c/TENANTA1/first'),
      `the first request reached A (head: ${JSON.stringify(firstHead.slice(0, 90))})`,
    )

    // Same socket, different tenant. A hostile agent would keep this socket open
    // exactly like this.
    const framesBefore = agentA.frames.length
    socket.write(`GET /c/TENANTB1/second?g=${GATE_B} HTTP/1.1\r\nhost: x\r\n\r\n`)

    await waitFor(() => socket.destroyed || socket.readableEnded, 'the relay ends the reused connection')
    await new Promise((done) => setTimeout(done, 200))

    const leaked = agentA.frames.slice(framesBefore).map((frame) => frame.toString('latin1')).join('')
    assert.equal(/TENANTB1/.test(leaked), false, "B's request never reached A's agent")
    assert.equal(agentB.frames.length, 0, "B's agent never received it either")
  } finally {
    relay.stop()
  }
})

await scenario('a second request for the same tenant is still allowed', async () => {
  const relay = await startRelay()
  try {
    const a = relay.tenant('same-tenant')
    const agentA = await registerAgent(relay, 'SAMETEN1', { key: a.key, gate: GATE_A })
    const socket = net.connect({ host: '127.0.0.1', port: relay.phonePort })
    relay.sockets.push(socket)
    socket.on('error', () => {})
    await new Promise((resolve) => socket.once('connect', resolve))
    socket.write(`GET /c/SAMETEN1/one?g=${GATE_A} HTTP/1.1\r\nhost: x\r\n\r\n`)
    await firstFrame(agentA)
    const before = agentA.frames.length
    socket.write(`GET /c/SAMETEN1/two?g=${GATE_A} HTTP/1.1\r\nhost: x\r\n\r\n`)
    await waitFor(() => agentA.frames.length > before, 'the same-tenant request is forwarded')
    const all = agentA.frames.map((frame) => frame.toString('latin1')).join('')
    assert.match(all, /\/two/, 'the second request arrived')
    socket.destroy()
  } finally {
    relay.stop()
  }
})

await scenario('a request body that looks like another request is not cut', async () => {
  const relay = await startRelay()
  try {
    const a = relay.tenant('sneaky-body')
    const agentA = await registerAgent(relay, 'SNEAKY01', { key: a.key, gate: GATE_A })
    const socket = net.connect({ host: '127.0.0.1', port: relay.phonePort })
    relay.sockets.push(socket)
    socket.on('error', () => {})
    await new Promise((resolve) => socket.once('connect', resolve))
    const body = `hello\r\n\r\nGET /c/OTHER999/ HTTP/1.1\r\n\r\nworld`
    socket.write(`POST /c/SNEAKY01/upload?g=${GATE_A} HTTP/1.1\r\nhost: x\r\ncontent-length: ${Buffer.byteLength(body)}\r\n\r\n${body}`)
    await waitFor(() => agentA.frames.map((f) => f.toString('latin1')).join('').includes('world'), 'the body arrived')
    assert.equal(socket.destroyed, false, 'the connection was not cut by a request line inside a body')
    socket.destroy()
  } finally {
    relay.stop()
  }
})

await scenario('an agent that only knows the v1 proof secret is still accepted', async () => {
  // Rollout order: tenants created before the v2 derivation have no raw key left,
  // and agents keep arriving that ignore `v`. Both must keep working, or the
  // upgrade becomes a flag day.
  const relay = await startRelay()
  try {
    const created = relay.tenant('legacy-proof')
    const oldAgent = await registerAgent(relay, 'LEGACY01', {
      key: created.key,
      gate: GATE_A,
      proofSecret: legacySecretFor(created.key),
    })
    assert.ok(oldAgent.registered, 'the v1 proof is accepted for a v2 tenant')
    assert.match(relay.log(), /proved itself with the v1 secret/, 'and the relay asks for an upgrade once')

    // The same tenant also accepts the v2 proof, so an updated agent works too.
    const newAgent = await registerAgent(relay, 'LEGACY02', { key: created.key, gate: GATE_A })
    assert.ok(newAgent.registered, 'the v2 proof is accepted as well')
  } finally {
    relay.stop()
  }
})

await scenario('a fake upgrade answered with 200 does not open a tunnel', async () => {
  // The second audit's bypass: request an upgrade, have the (attacker's) agent
  // answer 200 OK, and a pooling proxy treats the socket as reusable - so the
  // victim's next request lands on it. The relay now only stops inspecting after
  // a real 101.
  const relay = await startRelay()
  try {
    const evil = relay.tenant('evil')
    const good = relay.tenant('victim')
    const evilAgent = await registerAgent(relay, 'EVIL0001', { key: evil.key, gate: GATE_A })
    const victimAgent = await registerAgent(relay, 'VICTIM01', { key: good.key, gate: GATE_B })

    const socket = net.connect({ host: '127.0.0.1', port: relay.phonePort })
    relay.sockets.push(socket)
    socket.on('error', () => {})
    // A paused socket never sees the FIN, so the "connection was cut" check has
    // to read.
    socket.resume()
    await new Promise((resolve) => socket.once('connect', resolve))

    socket.write(`GET /c/EVIL0001/x?g=${GATE_A} HTTP/1.1\r\nhost: x\r\nconnection: Upgrade\r\nupgrade: websocket\r\n\r\n`)
    const upgradeFrame = await firstFrame(evilAgent)
    const sid = upgradeFrame.readUInt32BE(0)
    // Not a 101: the switch never happens, so the socket stays an HTTP connection.
    evilAgent.ws.send(Buffer.concat([
      Buffer.from([sid >>> 24 & 0xff, sid >>> 16 & 0xff, sid >>> 8 & 0xff, sid & 0xff]),
      Buffer.from('HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nok', 'latin1'),
    ]))
    await new Promise((done) => setTimeout(done, 200))

    const before = evilAgent.frames.length
    socket.write(`GET /c/VICTIM01/m?g=${GATE_B} HTTP/1.1\r\nhost: x\r\n\r\n`)
    try {
      await waitFor(() => socket.destroyed || socket.readableEnded, 'the reused connection is cut', 5000)
    } catch (error) {
      console.log('debug relay log:\n' + relay.log().split('\n').slice(-12).join('\n'))
      console.log('debug socket:', { destroyed: socket.destroyed, ended: socket.readableEnded, frames: evilAgent.frames.length })
      throw error
    }
    await new Promise((done) => setTimeout(done, 200))

    const leaked = evilAgent.frames.slice(before).map((frame) => frame.toString('latin1')).join('')
    assert.equal(leaked.includes('VICTIM01'), false, "the victim's request never reached the evil agent")
    assert.equal(victimAgent.frames.length, 0, 'and never reached its own agent either')
  } finally {
    relay.stop()
  }
})

await scenario('malformed upgrade attempts do not lock the address out', async () => {
  // Each bad handshake used to leak one slot, so 32 of them permanently blocked
  // every agent behind that address.
  const previous = process.env.DSH_RELAY_AGENT_SOCKETS_PER_IP
  process.env.DSH_RELAY_AGENT_SOCKETS_PER_IP = '4'
  const relay = await startRelay()
  try {
    for (let i = 0; i < 12; i += 1) {
      const raw = tls.connect({ host: '127.0.0.1', port: relay.agentPort, rejectUnauthorized: false })
      relay.sockets.push(raw)
      raw.on('error', () => {})
      await new Promise((resolve) => raw.once('secureConnect', resolve))
      // No Sec-WebSocket-Key: ws answers 400 itself and never calls the upgrade
      // callback, which is exactly the path that leaked.
      raw.write('GET /agent HTTP/1.1\r\nhost: x\r\nconnection: Upgrade\r\nupgrade: websocket\r\n\r\n')
      await new Promise((done) => { raw.once('close', done); setTimeout(done, 300) })
    }
    const created = relay.tenant('after-bad')
    const agent = await registerAgent(relay, 'AFTERBAD', { key: created.key, gate: GATE_A })
    assert.ok(agent.registered, 'a legitimate agent still registers after 12 malformed upgrades')
  } finally {
    relay.stop()
    if (previous === undefined) delete process.env.DSH_RELAY_AGENT_SOCKETS_PER_IP
    else process.env.DSH_RELAY_AGENT_SOCKETS_PER_IP = previous
  }
})

await scenario('a crafted chunked trailer cannot capture the next request', async () => {
  // The third audit's desync: a trailer line was consumed as the end of the body
  // and the rest of the trailer block parsed as the next request head.
  const relay = await startRelay()
  try {
    const evil = relay.tenant('trailer-evil')
    const good = relay.tenant('trailer-victim')
    const evilAgent = await registerAgent(relay, 'TREVIL01', { key: evil.key, gate: GATE_A })
    const victimAgent = await registerAgent(relay, 'TRVICT01', { key: good.key, gate: GATE_B })

    const socket = net.connect({ host: '127.0.0.1', port: relay.phonePort })
    relay.sockets.push(socket)
    socket.on('error', () => {})
    socket.resume()
    await new Promise((resolve) => socket.once('connect', resolve))

    const crafted = [
      `POST /c/TREVIL01/upload?g=${GATE_A} HTTP/1.1`,
      'host: x',
      'transfer-encoding: chunked',
      '',
      '0',
      'X-A: 1',
      `X-B: /c/TRVICT01/x?g=${GATE_B}`,
      'Content-Length: 999999',
      '',
      '',
    ].join('\r\n')
    socket.write(crafted)
    await new Promise((done) => setTimeout(done, 150))

    const before = evilAgent.frames.map((frame) => frame.toString('latin1')).join('').length
    socket.write(`GET /c/TRVICT01/m?g=${GATE_B} HTTP/1.1\r\nhost: x\r\ncookie: __relay_t=secret\r\n\r\n`)
    await waitFor(() => socket.destroyed || socket.readableEnded, 'the connection is cut', 5000)
    await new Promise((done) => setTimeout(done, 200))

    const afterEvil = evilAgent.frames.map((frame) => frame.toString('latin1')).join('')
    // The trailer text itself is part of the upload the client sent, so the evil
    // agent legitimately sees it. What must never arrive is the victim's *request*.
    assert.ok(before > 0, 'the honest upload head reached the agent')
    assert.equal(afterEvil.includes('GET /c/TRVICT01/m'), false, "the victim's request never reached the evil agent")
    assert.equal(afterEvil.includes('__relay_t=secret'), false, "and neither did the victim's cookie")
    assert.equal(victimAgent.frames.length, 0, "the victim's agent never saw the smuggled request")
  } finally {
    relay.stop()
  }
})

await scenario('a first request with broken body framing is refused outright', async () => {
  const relay = await startRelay()
  try {
    const created = relay.tenant('broken-first')
    const agent = await registerAgent(relay, 'BROKEN01', { key: created.key, gate: GATE_A })
    const socket = net.connect({ host: '127.0.0.1', port: relay.phonePort })
    relay.sockets.push(socket)
    socket.on('error', () => {})
    socket.resume()
    await new Promise((resolve) => socket.once('connect', resolve))
    // Both framings at once: the scanner cannot know where the body ends, so the
    // request must not be forwarded with its body parsed as the next request.
    socket.write(`POST /c/BROKEN01/upload?g=${GATE_A} HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\ncontent-length: 5\r\n\r\nGET /c/OTHER01/ HTTP/1.1\r\n\r\n`)
    await waitFor(() => socket.destroyed || socket.readableEnded, 'the connection is cut', 5000)
    assert.equal(agent.frames.length, 0, 'the agent received nothing')
    assert.match(relay.log(), /both transfer-encoding and content-length/)
  } finally {
    relay.stop()
  }
})

console.log(failures === 0 ? 'all relay security checks passed' : `${failures} relay security check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
