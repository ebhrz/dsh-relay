// The request scanner is a security boundary: it decides which request a byte
// belongs to, so every state it cannot frame must be a refusal, never a
// pass-through. These cases are the ones the second audit used to bypass 0.10.0.
import assert from 'node:assert/strict'
import { RequestScanner, identityOfHead } from '../src/http-split.js'

let failures = 0
const scenario = (label, fn) => {
  try {
    fn()
    console.log(`ok ${label}`)
  } catch (error) {
    failures += 1
    console.log(`FAIL ${label}: ${error.message}`)
  }
}

const request = (line, extra = '') => `GET ${line} HTTP/1.1\r\nhost: x\r\n${extra}\r\n`
const head = (line, extra = '') => Buffer.from(request(line, extra), 'latin1')
const primed = (line, extra = '') => {
  const scanner = new RequestScanner()
  scanner.startWith(Buffer.from(request(line, extra).replace(/\r\n\r\n$/, ''), 'latin1'))
  return scanner
}
const acceptAll = () => null

scenario('a second request for another tenant is refused before forwarding', () => {
  const scanner = primed('/c/AAAA/api/x?g=abc')
  const result = scanner.feed(head('/c/BBBB/api/y?g=def'), (h) => (identityOfHead(h).id === 'BBBB' ? 'other tenant' : null))
  assert.equal(result.refused, 'other tenant')
  assert.equal(result.forward.length, 0)
})

scenario('the refused request stops before its head, keeping earlier bytes', () => {
  const scanner = primed('/c/AAAA/upload?g=abc', 'content-length: 4\r\n')
  const chunk = Buffer.concat([Buffer.from('abcd', 'latin1'), head('/c/BBBB/api/y?g=def')])
  const result = scanner.feed(chunk, () => 'refused')
  assert.equal(result.forward.toString('latin1'), 'abcd')
})

scenario('a body that contains a request line is not treated as one', () => {
  const body = Buffer.from('hello\r\n\r\nGET /c/BBBB/api/y HTTP/1.1\r\n\r\nworld')
  const scanner = primed('/c/AAAA/upload?g=abc', `content-length: ${body.length}\r\n`)
  const seen = []
  const result = scanner.feed(body, (h) => { seen.push(h); return null })
  assert.equal(result.refused, null)
  assert.deepEqual(seen, [])
  assert.deepEqual(result.forward, body)
})

// ── upgrades: the socket only stops being HTTP once the agent said 101 ──────

const upgradeHead = (line) => Buffer.from(
  `GET ${line} HTTP/1.1\r\nhost: x\r\nconnection: Upgrade\r\nupgrade: websocket\r\n\r\n`,
  'latin1',
)

scenario('an upgrade request waits for the switch instead of going blind', () => {
  const scanner = new RequestScanner()
  scanner.feed(upgradeHead('/c/AAAA/api/remote.mux?g=abc'), acceptAll)
  assert.equal(scanner.mode, 'await-switch')
  assert.equal(scanner.awaitingSwitch, true)
})

scenario('a request arriving before the switch is refused', () => {
  const scanner = new RequestScanner()
  scanner.feed(upgradeHead('/c/AAAA/api/remote.mux?g=abc'), acceptAll)
  // What a fake upgrade followed by a pooled victim request looks like.
  const result = scanner.feed(head('/c/BBBB/m?g=def'), () => 'other tenant')
  assert.equal(result.refused, 'data before the upgrade switch')
  assert.equal(result.forward.length, 0, 'no byte of the smuggled request goes upstream')
})

scenario('after the agent answers 101 the stream becomes a tunnel', () => {
  const scanner = new RequestScanner()
  scanner.feed(upgradeHead('/c/AAAA/api/remote.mux?g=abc'), acceptAll)
  scanner.allowTunnel()
  assert.equal(scanner.mode, 'tunnel')
  const frames = Buffer.from('\r\n\r\nGET /c/BBBB/ HTTP/1.1\r\n\r\n', 'latin1')
  const seen = []
  const result = scanner.feed(frames, (h) => { seen.push(h); return null })
  assert.deepEqual(seen, [], 'tunnel bytes are never parsed')
  assert.deepEqual(result.forward, frames)
})

scenario('an Upgrade header without Connection: upgrade is an ordinary request', () => {
  const scanner = new RequestScanner()
  scanner.feed(Buffer.from('GET /c/AAAA/x?g=abc HTTP/1.1\r\nhost: x\r\nupgrade: websocket\r\n\r\n', 'latin1'), acceptAll)
  assert.equal(scanner.mode, 'head', 'the switch was never negotiated')
})

// ── malformed framing is refused, not passed through ─────────────────────────

const malformed = [
  ['negative content-length', 'GET /x HTTP/1.1\r\ncontent-length: -5\r\n\r\n'],
  ['non-numeric content-length', 'GET /x HTTP/1.1\r\ncontent-length: 5x\r\n\r\n'],
  ['conflicting content-length', 'GET /x HTTP/1.1\r\ncontent-length: 5\r\ncontent-length: 6\r\n\r\n'],
  ['chunked with content-length', 'GET /x HTTP/1.1\r\ntransfer-encoding: chunked\r\ncontent-length: 5\r\n\r\n'],
]
for (const [label, text] of malformed) {
  scenario(`a request with ${label} is refused`, () => {
    const scanner = new RequestScanner()
    const result = scanner.feed(Buffer.from(text, 'latin1'), acceptAll)
    assert.ok(result.refused, `expected a refusal, got ${JSON.stringify(result.refused)}`)
  })
}

scenario('an oversized head is refused', () => {
  const scanner = new RequestScanner()
  const huge = Buffer.concat([Buffer.from('GET /x HTTP/1.1\r\n'), Buffer.alloc(70 * 1024, 0x61)])
  const result = scanner.feed(huge, acceptAll)
  assert.equal(result.refused, 'request head too long')
})

scenario('a malformed chunk size is refused', () => {
  const scanner = primed('/c/AAAA/upload?g=abc', 'transfer-encoding: chunked\r\n')
  const result = scanner.feed(Buffer.from('zz\r\nhello\r\n0\r\n\r\n', 'latin1'), acceptAll)
  assert.equal(result.refused, 'malformed chunk size')
})

scenario('a bad chunk terminator is refused', () => {
  const scanner = primed('/c/AAAA/upload?g=abc', 'transfer-encoding: chunked\r\n')
  const result = scanner.feed(Buffer.from('5\r\nhelloXX', 'latin1'), acceptAll)
  assert.equal(result.refused, 'malformed chunk terminator')
})

// ── chunked framing across TCP fragments keeps its bytes ─────────────────────

scenario('a chunk-size line split across packets keeps its first half', () => {
  const scanner = primed('/c/AAAA/upload?g=abc', 'transfer-encoding: chunked\r\n')
  const first = scanner.feed(Buffer.from('5', 'latin1'), acceptAll)
  assert.equal(first.forward.toString('latin1'), '', 'nothing is forwarded before the line proves valid')
  const second = scanner.feed(Buffer.from('\r\nhello\r\n0\r\n\r\n', 'latin1'), acceptAll)
  assert.equal(second.refused, null)
  assert.equal(second.forward.toString('latin1'), '5\r\nhello\r\n0\r\n\r\n', 'the split line is forwarded intact')
})

scenario('the CRLF that ends chunk data split across packets is not a tunnel', () => {
  const scanner = primed('/c/AAAA/upload?g=abc', 'transfer-encoding: chunked\r\n')
  scanner.feed(Buffer.from('5\r\nhello', 'latin1'), acceptAll)
  const first = scanner.feed(Buffer.from('\r', 'latin1'), acceptAll)
  assert.equal(first.refused, null, 'a lone CR waits for its partner')
  const second = scanner.feed(Buffer.from('\n', 'latin1'), acceptAll)
  assert.equal(second.refused, null)
  assert.equal(second.forward.toString('latin1'), '\r\n')
  assert.equal(scanner.mode, 'chunk-size')
})

scenario('a chunked body split mid-data resumes correctly', () => {
  const scanner = primed('/c/AAAA/upload?g=abc', 'transfer-encoding: chunked\r\n')
  scanner.feed(Buffer.from('8\r\nabcd', 'latin1'), acceptAll)
  const result = scanner.feed(Buffer.from('efgh\r\n0\r\n\r\n', 'latin1'), acceptAll)
  assert.equal(result.refused, null)
  assert.equal(result.forward.toString('latin1'), 'efgh\r\n0\r\n\r\n')
  assert.equal(scanner.mode, 'head')
})

scenario('identityOfHead accepts a path without a trailing slash', () => {
  assert.equal(identityOfHead(head(`/c/AV5FVHCP?g=${'a'.repeat(64)}`)).id, 'AV5FVHCP')
})

console.log(failures === 0 ? 'all http split checks passed' : `${failures} http split check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
