#!/usr/bin/env node
// End-to-end harness for pump changes: a fake DSH behind a real RelayClient
// registered on a real relay, plus the real PumpManager + PairingService. Point
// a browser at the printed entry URL to exercise the whole relay path without
// restarting the dsh web you are developing against.
//
//   node scripts/probe-relay-integration.mjs
//
// Reads the relay coordinates the panel saved (relayHost/relayPort/agentPort/
// relayKey) from $DSH_HOME/plugin-data/dsh-relay-bridge/config.json, and uses a
// throwaway device identity so the real identity.json is never touched.
import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import nacl from 'tweetnacl'
import { WebSocketServer } from 'ws'
import { PumpManager } from '../src/pump.js'
import { RelayClient } from '../src/relay-client.js'
import { CryptoBox } from '../src/crypto.js'
import { PairingService } from '../src/pairing.js'
import { createIdentity, identityDir } from '../src/identity.js'

const UPSTREAM_PORT = 62999
const LOCAL_ENTRY_PORT = Number(process.env.ENTRY_PORT ?? 18899)
const ASSETS = 12

const configPath = path.join(identityDir(), 'config.json')
let config
try {
  config = JSON.parse(fs.readFileSync(configPath, 'utf8'))
} catch {
  console.error(`no relay config at ${configPath}`)
  console.error('Configure the relay in the panel once (it persists this file), then retry.')
  process.exit(2)
}
const identity = createIdentity()
const cryptoBox = new CryptoBox(identity)
const pairing = new PairingService(cryptoBox, identity)
const pskB64 = Buffer.concat([
  Buffer.from(identity.psk, 'hex'),
  Buffer.from(identity.signJwk.public.x, 'base64url'),
]).toString('base64url')

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const seen = { paths: [], connections: 0 }

// ---- fake DSH --------------------------------------------------------------
const html = `<!doctype html><html><head><title>fake dsh</title>
${Array.from({ length: ASSETS }, (_, i) => `<script src="/a${i}.js"></script>`).join('\n')}
<link rel="stylesheet" href="/s.css">
</head><body><div id="root">fake</div>
<script>
window.__assetCount = 0
window.__log = []
const t0 = performance.now()
Promise.all(Array.from({length:8}, (_, i) =>
  fetch('/api/echo', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({ i }) })
    .then((r) => r.json()).then((j) => { window.__log.push(j); return j })
)).then(() => { window.__apiDone = Math.round(performance.now() - t0) })
try {
  const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/api/remote.mux')
  ws.onopen = () => ws.send(JSON.stringify({ t: 'hello' }))
  ws.onmessage = (ev) => { window.__wsOk = String(ev.data).includes('echo') }
} catch (e) { window.__wsErr = String(e) }
</script></body></html>`
const asset = (i) => `window.__assetCount += 1; window.__assets = (window.__assets||[]).concat(${i});`

const server = http.createServer((req, res) => {
  seen.paths.push(req.url)
  if (req.url === '/' ) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': String(Buffer.byteLength(html)) })
    return res.end(html)
  }
  if (/^\/a\d+\.js$/.test(req.url)) {
    const body = asset(Number(req.url.match(/a(\d+)/)[1]))
    res.writeHead(200, { 'content-type': 'application/javascript', 'content-length': String(body.length) })
    return res.end(body)
  }
  if (req.url === '/s.css') {
    const body = 'body{color:#111}'
    res.writeHead(200, { 'content-type': 'text/css', 'content-length': String(body.length) })
    return res.end(body)
  }
  if (req.url === '/api/echo') {
    let raw = ''
    req.on('data', (c) => { raw += c })
    req.on('end', () => {
      const body = JSON.stringify({ ok: true, echo: raw, connection: req.headers.connection })
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) })
      res.end(body)
    })
    return
  }
  res.writeHead(404, { 'content-type': 'text/plain' })
  res.end('nope')
})
const wss = new WebSocketServer({ server, path: '/api/remote.mux' })
wss.on('connection', (socket) => {
  socket.on('message', (data, isBinary) => {
    const text = String(data)
    socket.send(`echo:${text}`, { binary: isBinary })
  })
})
server.on('connection', () => { seen.connections += 1 })
await new Promise((r) => server.listen(UPSTREAM_PORT, '127.0.0.1', r))

// ---- pump + relay client ---------------------------------------------------
const pump = new PumpManager({
  resolveTarget: () => ({ host: '127.0.0.1', port: UPSTREAM_PORT, authority: `127.0.0.1:${UPSTREAM_PORT}`, protocol: 'http:' }),
  resolveAuthCookie: () => 'fake-session=1',
  pairing,
  cryptoBox,
})
const client = new RelayClient({
  host: config.relayHost,
  agentPort: config.agentPort || config.relayPort + 1,
  relayKey: config.relayKey,
  identity,
  pump,
  onIdentityChange: () => {},
})
pump.setClient(client)
// One sid == one phone TCP connection. Counting distinct sids is the metric
// keep-alive targets: the browser should stop opening one per asset.
const sids = new Set()
const handleStreamData = pump.handleStreamData.bind(pump)
pump.handleStreamData = (sid, chunk) => {
  sids.add(sid)
  return handleStreamData(sid, chunk)
}
client.addEventListener('status', (e) => {
  const { status, detail } = e.detail
  console.log(`[agent] ${status} ${detail ?? ''}`)
  if (status === 'connected') {
    const k = pskB64
    console.log(`\nENTRY=http://127.0.0.1:${LOCAL_ENTRY_PORT}/c/${identity.id}/?g=${identity.gate}#k=${k}\n`)
  }
})
client.start()

process.on('SIGTERM', () => { client.stop(); server.close(); process.exit(0) })
process.on('SIGINT', () => { client.stop(); server.close(); process.exit(0) })
// Report counters when the harness is asked to finish.
process.on('SIGUSR2', () => {
  console.log('STATS ' + JSON.stringify({
    requests: seen.paths.length,
    phoneConnections: sids.size,
    keepAlive: process.env.DSH_RELAY_NO_KEEPALIVE !== '1',
    tcpConnections: seen.connections,
    paths: seen.paths,
  }))
})
