// The desktop-only endpoints must answer the desktop only: loopback peer *and*
// loopback Host, which is what a DNS-rebinding name or a forwarding proxy breaks.
import assert from 'node:assert/strict'
import { isLocalRequest, isLoopbackAddress, isLoopbackHost } from '../src/local-request.js'

const cases = [
  [{ remoteAddress: '127.0.0.1', host: 'localhost:55969' }, true, 'the desktop itself'],
  [{ remoteAddress: '127.0.0.1', host: '127.0.0.1:55969' }, true, 'numeric loopback host'],
  [{ remoteAddress: '::1', host: '[::1]:55969' }, true, 'ipv6 loopback'],
  [{ remoteAddress: '::ffff:127.0.0.1', host: 'localhost:1' }, true, 'mapped loopback'],
  [{ remoteAddress: '127.0.0.1', host: 'evil.example' }, false, 'a rebound name'],
  [{ remoteAddress: '127.0.0.1', host: 'evil.example:55969' }, false, 'a rebound name with a port'],
  [{ remoteAddress: '192.168.1.9', host: 'localhost:55969' }, false, 'a LAN peer'],
  [{ remoteAddress: '::1', host: 'example.com' }, false, 'ipv6 loopback with a foreign host'],
  [{ remoteAddress: undefined, host: 'localhost' }, false, 'no peer address'],
  [{ remoteAddress: '127.0.0.1', host: undefined }, false, 'no host header'],
]

let failures = 0
for (const [request, expected, label] of cases) {
  const actual = isLocalRequest(request)
  if (actual !== expected) {
    failures += 1
    console.log(`FAIL ${label}: expected ${expected}, got ${actual}`)
  }
}

assert.equal(isLoopbackAddress('127.0.0.53'), true, '127.0.0.0/8 is loopback')
assert.equal(isLoopbackHost('LOCALHOST:80'), true, 'host matching is case-insensitive')
assert.equal(isLoopbackHost('localhost.evil.example'), false, 'suffix tricks do not pass')

console.log(failures === 0 ? 'all local-request checks passed' : `${failures} local-request check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
