// The real plugin client against the real relay.
//
// This is the one test that would have caught the tenant-key derivation bug: the
// relay verifies a tenant proof with sha256(key) as the HMAC key, while the
// plugin used the raw key, so every tenant login failed with "bad key proof" and
// only the admin --key path worked. Both packages live here, so test them
// together.

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { TenantStore } from '../src/tenants.js'
import { RelayClient } from '../../plugin/src/relay-client.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const relayPath = path.join(here, '..', 'src', 'index.mjs')

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-integration-'))
  const phonePort = await freePort()
  const agentPort = await freePort()
  const child = spawn(process.execPath, [
    relayPath, '--port', phonePort, '--agent-port', agentPort,
    '--host', '127.0.0.1', '--agent-host', '127.0.0.1', '--data-dir', dir, ...extraArgs,
  ], { stdio: ['ignore', 'pipe', 'pipe'] })
  let output = ''
  child.stdout.on('data', (chunk) => { output += chunk })
  child.stderr.on('data', (chunk) => { output += chunk })
  await waitFor(
    () => output.includes('phone listener:') && output.includes('agent listener:'),
    'relay listening',
    20000,
  )
  return {
    phonePort,
    agentPort,
    dir,
    log: () => output,
    tenant(name) {
      const store = new TenantStore(path.join(dir, 'tenants.json'))
      return store.add({ name, quotaBytesDay: 5 * 1024 * 1024 })
    },
    stop() { try { child.kill() } catch {} },
  }
}

// The plugin's client asks for a pump; it only needs the callbacks it uses.
function makePump() {
  const stats = { data: 0, closed: 0 }
  return {
    stats,
    handleStreamData() { stats.data += 1 },
    handleStreamClose() { stats.closed += 1 },
  }
}

const identity = (id) => ({ id, gate: 'a'.repeat(64), psk: 'b'.repeat(64), certFingerprint: null })

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

await scenario('the real plugin client registers with a tenant key', async () => {
  const relay = await startRelay()
  try {
    const tenant = relay.tenant('pluginuser')
    const client = new RelayClient({
      host: '127.0.0.1',
      agentPort: relay.agentPort,
      relayKey: tenant.key,
      identity: identity('PLUGIN01'),
      pump: makePump(),
      onIdentityChange: () => {},
    })
    const statuses = []
    client.addEventListener('status', (event) => statuses.push(event.detail))
    client.start()
    await waitFor(() => statuses.some((s) => s.status === 'connected'), `plugin connects (${JSON.stringify(statuses.slice(-2))})`)
    assert.match(relay.log(), /agent registered id=PLUGIN01 tenant=pluginuser/)
    client.stop()
  } finally {
    relay.stop()
  }
})

await scenario('the real plugin client registers with the admin key', async () => {
  const adminKey = 'z'.repeat(48)
  const relay = await startRelay(['--key', adminKey])
  try {
    const client = new RelayClient({
      host: '127.0.0.1',
      agentPort: relay.agentPort,
      relayKey: adminKey,
      identity: identity('PLUGIN02'),
      pump: makePump(),
      onIdentityChange: () => {},
    })
    const statuses = []
    client.addEventListener('status', (event) => statuses.push(event.detail))
    client.start()
    await waitFor(() => statuses.some((s) => s.status === 'connected'), `plugin connects (${JSON.stringify(statuses.slice(-2))})`)
    assert.match(relay.log(), /agent registered id=PLUGIN02 \(admin key\)/)
    client.stop()
  } finally {
    relay.stop()
  }
})

await scenario('a wrong key is refused, not silently accepted', async () => {
  const relay = await startRelay()
  try {
    const tenant = relay.tenant('someone')
    const client = new RelayClient({
      host: '127.0.0.1',
      agentPort: relay.agentPort,
      relayKey: tenant.key.slice(0, -1) + (tenant.key.endsWith('0') ? '1' : '0'),
      identity: identity('PLUGIN03'),
      pump: makePump(),
      onIdentityChange: () => {},
    })
    const statuses = []
    client.addEventListener('status', (event) => statuses.push(event.detail))
    client.start()
    await waitFor(() => statuses.some((s) => s.status === 'rejected'), 'the wrong key is rejected')
    assert.match(relay.log(), /agent rejected: bad key proof|unknown-key/)
    client.stop()
  } finally {
    relay.stop()
  }
})

console.log(failures === 0 ? 'all plugin↔relay integration checks passed' : `${failures} integration check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
