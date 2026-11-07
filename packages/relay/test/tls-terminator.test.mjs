// Certificate rotation must not drop live tunnels, and a broken certificate must
// not take the listener down.
//
// Needs `openssl` on PATH (the relay already uses it to mint the agent
// certificate). Everything runs on loopback with throwaway certificates.

import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import tls from 'node:tls'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const terminator = path.join(here, '..', 'src', 'tls-terminator.mjs')

const waitFor = async (predicate, label, timeoutMs = 15000) => {
  const started = Date.now()
  for (;;) {
    const value = await predicate()
    if (value) return value
    if (Date.now() - started > timeoutMs) throw new Error(`timeout: ${label}`)
    await new Promise((done) => setTimeout(done, 60))
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

/** A self-signed certificate for `name`, written into `dir`. */
function makeCert(dir, name) {
  const key = path.join(dir, `${name}.key`)
  const crt = path.join(dir, `${name}.crt`)
  // Windows' openssl has no usable default config, and -subj alone fails there,
  // so hand it a minimal one (the relay does the same for the agent certificate).
  const conf = path.join(dir, `${name}.cnf`)
  fs.writeFileSync(conf, [
    '[req]',
    'distinguished_name = dn',
    'x509_extensions = v3',
    'prompt = no',
    '[dn]',
    `CN = ${name}`,
    '[v3]',
    'basicConstraints = critical,CA:TRUE',
    'keyUsage = digitalSignature,keyEncipherment',
    `subjectAltName = DNS:${name}`,
    '',
  ].join('\n'))
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', key, '-out', crt, '-days', '1',
    '-config', conf,
  ], { stdio: 'ignore' })
  return { key, crt }
}

const fingerprint = (socket) => socket.getPeerCertificate().fingerprint256

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

await scenario('a new certificate is used without cutting the live tunnel', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'terminator-'))
  const first = makeCert(dir, 'first')
  const second = makeCert(dir, 'second')
  const live = path.join(dir, 'live')
  fs.mkdirSync(live)
  fs.copyFileSync(first.crt, path.join(live, 'fullchain.pem'))
  fs.copyFileSync(first.key, path.join(live, 'privkey.pem'))

  // A plain echo upstream stands in for the relay's phone listener.
  const upstream = net.createServer((socket) => { socket.on('error', () => {}); socket.pipe(socket) })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  const upstreamPort = upstream.address().port
  const port = await freePort()

  const child = spawn(process.execPath, [terminator,
    '--port', String(port), '--upstream', String(upstreamPort),
    '--cert-dir', live,
  ], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, DSH_RELAY_CERT_POLL_MS: '200' },
  })
  let log = ''
  child.stdout.on('data', (chunk) => { log += chunk })
  child.stderr.on('data', (chunk) => { log += chunk })

  try {
    await waitFor(() => log.includes('listening'), 'terminator listening', 20000)

    const connect = () => new Promise((resolve, reject) => {
      const socket = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false }, () => resolve(socket))
      socket.once('error', reject)
      // Later errors (a destroyed peer) are expected here; without a listener they
      // would crash the test process.
      socket.on('error', () => {})
    })

    const a = await connect()
    const firstPrint = fingerprint(a)
    const answered = new Promise((resolve) => a.once('data', resolve))
    a.write('ping')
    assert.equal((await answered).toString(), 'ping', 'the tunnel carries bytes')

    // Rotate the files underneath the running process.
    fs.copyFileSync(second.crt, path.join(live, 'fullchain.pem'))
    fs.copyFileSync(second.key, path.join(live, 'privkey.pem'))
    await waitFor(() => log.includes('certificate reloaded'), 'reload noticed', 15000)

    // The old tunnel still works and still has its old certificate.
    const stillThere = new Promise((resolve) => a.once('data', resolve))
    a.write('again')
    assert.equal((await stillThere).toString(), 'again', 'the established tunnel survived the rotation')
    assert.equal(fingerprint(a), firstPrint, 'the live tunnel keeps the certificate it negotiated')

    // A new handshake sees the new one.
    const b = await connect()
    const secondPrint = fingerprint(b)
    assert.notEqual(secondPrint, firstPrint, 'new connections present the new certificate')
    b.destroy()
    a.destroy()
  } finally {
    child.kill()
    upstream.close()
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

await scenario('a broken certificate keeps the old one serving', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'terminator-bad-'))
  const good = makeCert(dir, 'good')
  const live = path.join(dir, 'live')
  fs.mkdirSync(live)
  fs.copyFileSync(good.crt, path.join(live, 'fullchain.pem'))
  fs.copyFileSync(good.key, path.join(live, 'privkey.pem'))

  const upstream = net.createServer((socket) => { socket.on('error', () => {}); socket.pipe(socket) })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  const port = await freePort()
  const child = spawn(process.execPath, [terminator,
    '--port', String(port), '--upstream', String(upstream.address().port),
    '--cert-dir', live,
  ], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, DSH_RELAY_CERT_POLL_MS: '200' },
  })
  let log = ''
  child.stdout.on('data', (chunk) => { log += chunk })
  child.stderr.on('data', (chunk) => { log += chunk })

  try {
    await waitFor(() => log.includes('listening'), 'terminator listening', 20000)
    fs.writeFileSync(path.join(live, 'fullchain.pem'), 'not a certificate\n')
    await waitFor(() => log.includes('keeping the current certificate'), 'the failure is logged', 15000)

    const socket = await new Promise((resolve, reject) => {
      const s = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false }, () => resolve(s))
      s.once('error', reject)
      s.on('error', () => {})
    })
    const echoed = new Promise((resolve) => socket.once('data', resolve))
    socket.write('still')
    assert.equal((await echoed).toString(), 'still', 'the listener still serves with the old certificate')
    socket.destroy()
  } finally {
    child.kill()
    upstream.close()
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

console.log(failures === 0 ? 'all tls terminator checks passed' : `${failures} tls terminator check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
