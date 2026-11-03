// Compatibility checks for the DSH 0.2 upgrade. Run with:
//   node packages/plugin/test-compat.mjs
//
// Pure loopback: no relay server and no running dsh web required.

import assert from 'node:assert/strict'
import http from 'node:http'
import { PumpManager, stripGateParam, injectBootScript } from '../src/pump.js'

const GATE = 'a'.repeat(64)

function listen(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler)
    server.listen(0, '127.0.0.1', () => resolve(server))
  })
}

function pumpAgainst(port, { authCookie = 'dsh-auth-test=v1.test.sig' } = {}) {
  const pump = new PumpManager({
    resolveTarget: () => ({
      host: '127.0.0.1',
      port,
      authority: `127.0.0.1:${port}`,
      protocol: 'http:',
    }),
    resolveAuthCookie: () => authCookie,
    pairing: { sessionForHeaders: () => ({ did: 'test' }) },
    cryptoBox: {},
  })
  const chunks = []
  let closed = false
  pump.setClient({
    sendStream: (_sid, chunk) => chunks.push(Buffer.from(chunk)),
    closeStream: () => { closed = true },
  })
  return { pump, chunks, isClosed: () => closed }
}

function waitFor(check, timeout = 2000) {
  const started = Date.now()
  return new Promise((resolve, reject) => {
    const tick = () => {
      if (check()) return resolve()
      if (Date.now() - started > timeout) return reject(new Error('timeout'))
      setTimeout(tick, 10)
    }
    tick()
  })
}

/** Wait until the pump has written `needle` to this stream (keep-alive: the
 *  stream itself no longer closes after one response). */
function waitForText(chunks, needle) {
  return waitFor(() => Buffer.concat(chunks).toString('latin1').includes(needle))
}

// 1. The raw query survives prefix/gate stripping. DSH 0.2 addresses its
//    boot combos as /plugins/??pkg/client.js&rev=... — URLSearchParams would
//    re-encode the whole thing and 404 the bundle route.
{
  const seen = []
  const server = await listen((req, res) => {
    seen.push({ url: req.url, headers: req.headers })
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '2' })
    res.end('ok')
  })
  const { pump, chunks, isClosed } = pumpAgainst(server.address().port)
  pump.handleStreamData(7, Buffer.from(
    `GET /c/ABCD1234/plugins/??dsh-relay-bridge/client.js&rev=deadbeef&g=${GATE} HTTP/1.1\r\n`
    + 'Host: relay.example:8889\r\n'
    + 'Origin: http://relay.example:8889\r\n'
    + 'Cookie: __relay_t=relay-ticket\r\n'
    + 'Connection: keep-alive\r\n\r\n'))
  await waitForText(chunks, '\r\n\r\nok')
  assert.equal(seen.length, 1)
  assert.equal(seen[0].url, '/plugins/??dsh-relay-bridge/client.js&rev=deadbeef')
  assert.equal(seen[0].headers.host, `127.0.0.1:${server.address().port}`)
  assert.equal(seen[0].headers.origin, `http://127.0.0.1:${server.address().port}`)
  assert.equal(seen[0].headers.cookie, 'dsh-auth-test=v1.test.sig', 'upstream carries the DSH session cookie, not the relay ticket')
  assert.ok(chunks.length > 0)
  assert.equal(isClosed(), false, 'keep-alive request keeps the phone connection open')
  pump.handleStreamClose(7)
  server.close()
  console.log('ok 1: raw ?? combo query preserved; Host/Origin/Cookie rewritten; connection kept')
}

// 2. stripGateParam leaves every other byte alone (including encoded values).
{
  assert.deepEqual(stripGateParam(''), { gate: '', cleanQuery: '' })
  assert.deepEqual(stripGateParam(`g=${GATE}`), { gate: GATE, cleanQuery: '' })
  assert.deepEqual(
    stripGateParam(`??pkg/client.js&rev=abc&g=${GATE}`),
    { gate: GATE, cleanQuery: '??pkg/client.js&rev=abc' })
  assert.deepEqual(
    stripGateParam(`a=%2F%3F&g=${GATE}&b=1`),
    { gate: GATE, cleanQuery: 'a=%2F%3F&b=1' })
  console.log('ok 2: gate stripping is byte-preserving')
}

// 3. Document injection still inserts the boot + mobile scripts and rewrites
//    both root-absolute and document-relative asset URLs under the prefix.
{
  const html = Buffer.from('HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: 120\r\n\r\n'
    + '<!doctype html><html><head><title>x</title>'
    + '<script type="module" src="./assets/index.js"></script>'
    + '<script src="plugins/??app/client.js&rev=1"></script>'
    + '<link rel="stylesheet" href="/assets/app.css">'
    + '</head><body></body></html>', 'latin1')
  const out = injectBootScript(html, { id: 'ABCD1234', gate: GATE }).toString('latin1')
  assert.match(out, /__dshRelayBoot/)
  assert.match(out, new RegExp(`src="/c/ABCD1234/assets/index\\.js\\?g=${GATE}`))
  assert.match(out, new RegExp(`src="/c/ABCD1234/plugins/\\?\\?app/client\\.js&rev=1&g=${GATE}`))
  assert.match(out, new RegExp(`href="/c/ABCD1234/assets/app\\.css\\?g=${GATE}`))
  console.log('ok 3: boot/mobile injection and relative asset rewriting')
}

// 4. A document response replays the DSH session cookie upstream.
{
  const seen = []
  const server = await listen((req, res) => {
    seen.push(req.headers)
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<!doctype html><html><head></head><body>ok</body></html>')
  })
  const { pump, isClosed, chunks } = pumpAgainst(server.address().port)
  pump.handleStreamData(8, Buffer.from(
    `GET /c/ABCD1234/?g=${GATE} HTTP/1.1\r\nHost: relay.example:8889\r\n`
    + 'Sec-Fetch-Dest: document\r\nAccept: text/html\r\n\r\n'))
  await waitForText(chunks, '__dshRelayBoot')
  assert.equal(seen.length, 1)
  assert.equal(seen[0].cookie, 'dsh-auth-test=v1.test.sig')
  assert.ok(chunks.join('').includes('__dshRelayBoot'))
  pump.handleStreamClose(8)
  server.close()
  console.log('ok 4: document request authenticated and boot-injected')
}

console.log('\nall compatibility checks passed')
