// The request scanner is what stops a pooled connection (or a hostile agent) from
// delivering one tenant's request to another tenant's agent.
//
// The relay forwards request #1 itself (it had to parse it to route), primes the
// scanner with that head, and feeds everything after it. So `accept` is only ever
// called for request #2 onwards.
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

/** The relay's own first request: forwarded by hand, then primed. */
const primed = (line, extra = '') => {
  const scanner = new RequestScanner()
  scanner.startWith(Buffer.from(request(line, extra).replace(/\r\n\r\n$/, ''), 'latin1'))
  return scanner
}

scenario('the primed request stays in head mode', () => {
  const scanner = primed('/c/AAAA/api/x?g=abc')
  assert.equal(scanner.mode, 'head')
})

scenario('a second request is presented to the caller for a decision', () => {
  const scanner = primed('/c/AAAA/api/x?g=abc')
  const seen = []
  const second = scanner.feed(head('/c/BBBB/api/y?g=def'), (h) => { seen.push(identityOfHead(h).id); return null })
  assert.equal(second.refused, null)
  assert.deepEqual(seen, ['BBBB'], 'the second head is inspected before forwarding')
  assert.match(second.forward.toString('latin1'), /^GET \/c\/BBBB\/api\/y/)
})

scenario('a request naming another tenant is refused before it is forwarded', () => {
  const scanner = primed('/c/AAAA/api/x?g=abc')
  const result = scanner.feed(head('/c/BBBB/api/y?g=def'), (h) => (identityOfHead(h).id === 'BBBB' ? 'other tenant' : null))
  assert.equal(result.refused, 'other tenant')
  assert.equal(result.forward.length, 0, 'not one byte of the foreign request is forwarded')
})

scenario('the refused request stops before its head, keeping earlier bytes', () => {
  // The previous request's last body bytes and the foreign head arrive together.
  const scanner = primed('/c/AAAA/upload?g=abc', 'content-length: 4\r\n')
  const chunk = Buffer.concat([Buffer.from('abcd', 'latin1'), head('/c/BBBB/api/y?g=def')])
  const result = scanner.feed(chunk, () => 'refused')
  assert.equal(result.forward.toString('latin1'), 'abcd', 'only the earlier body bytes go upstream')
})

scenario('a body that contains a request line is not treated as one', () => {
  const body = Buffer.from('hello\r\n\r\nGET /c/BBBB/api/y HTTP/1.1\r\n\r\nworld')
  const scanner = primed('/c/AAAA/upload?g=abc', `content-length: ${body.length}\r\n`)
  const seen = []
  const result = scanner.feed(body, (h) => { seen.push(identityOfHead(h).id); return null })
  assert.equal(result.refused, null)
  assert.deepEqual(seen, [], 'nothing inside the body is inspected')
  assert.deepEqual(result.forward, body, 'the whole body is forwarded')
  assert.equal(scanner.mode, 'head', 'the scanner is back at a request boundary')
})

scenario('a chunked body is framed, and the request after it is inspected', () => {
  const scanner = primed('/c/AAAA/upload?g=abc', 'transfer-encoding: chunked\r\n')
  const seen = []
  const chunked = Buffer.from('5\r\nhello\r\n0\r\n\r\n', 'latin1')
  scanner.feed(chunked, (h) => { seen.push(identityOfHead(h).id); return null })
  assert.deepEqual(seen, [], 'the chunked body is not mistaken for a request')
  scanner.feed(head('/c/BBBB/api/y?g=def'), (h) => { seen.push(identityOfHead(h).id); return null })
  assert.deepEqual(seen, ['BBBB'], 'the request after the body is inspected')
})

scenario('an upgrade turns the socket into a tunnel', () => {
  const scanner = new RequestScanner()
  const upgrade = Buffer.from('GET /c/AAAA/api/remote.mux?g=abc HTTP/1.1\r\nconnection: Upgrade\r\nupgrade: websocket\r\n\r\n', 'latin1')
  scanner.feed(upgrade, () => null)
  assert.equal(scanner.mode, 'tunnel')
  const frames = Buffer.from('\r\n\r\nGET /c/BBBB/ HTTP/1.1\r\n\r\n', 'latin1')
  const seen = []
  const result = scanner.feed(frames, (h) => { seen.push(h); return null })
  assert.deepEqual(seen, [], 'tunnel bytes are never parsed')
  assert.deepEqual(result.forward, frames, 'and they pass through untouched')
})

scenario('identityOfHead reads the prefix, the query gate and the cookies', () => {
  const direct = identityOfHead(head('/c/AV5FVHCP/api/x?g=' + 'a'.repeat(64)))
  assert.deepEqual([direct.id, direct.gate], ['AV5FVHCP', 'a'.repeat(64)])
  const cookies = identityOfHead(Buffer.from(
    `GET /api/x HTTP/1.1\r\ncookie: __relay_i=ZZZZ0001; __relay_g=${'b'.repeat(64)}\r\n\r\n`,
    'latin1',
  ))
  assert.deepEqual([cookies.id, cookies.gate], ['ZZZZ0001', 'b'.repeat(64)])
})

console.log(failures === 0 ? 'all http split checks passed' : `${failures} http split check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
