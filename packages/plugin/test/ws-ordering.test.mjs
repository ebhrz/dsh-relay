// A websocket frame must not overtake the host's 101.
//
// The pump used to flush the phone's buffered frames as soon as the upstream TCP
// connection opened, i.e. before the host answered the handshake. A byte written
// at that moment looks like a pipelined HTTP request, so a strict host closes the
// connection - which is why the desktop mux sometimes sat silent and the page
// then retried. Frames now wait for the 101.

import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import net from 'node:net'
import { CryptoBox } from '../src/crypto.js'
import { PumpManager } from '../src/pump.js'
import { buildFrame, OPCODES } from '../src/ws-codec.js'

const GATE = 'c'.repeat(64)
const ID = 'WSTEST01'

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
const box = new CryptoBox({
  id: ID,
  psk: crypto.randomBytes(32).toString('hex'),
  gate: GATE,
  signJwk: {
    public: publicKey.export({ format: 'jwk' }),
    private: privateKey.export({ format: 'jwk' }),
  },
})

// A deliberately strict fake host: it answers 101 after a delay and records every
// byte that arrives before it does.
let beforeHead = null
let afterHead = null
const server = net.createServer((socket) => {
  let received = Buffer.alloc(0)
  let answered = false
  socket.on('data', (chunk) => {
    received = Buffer.concat([received, chunk])
    if (!answered) {
      const idx = received.indexOf('\r\n\r\n')
      if (idx === -1) return
      beforeHead = received.subarray(idx + 4)
      answered = true
      setTimeout(() => {
        socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
      }, 300)
      return
    }
    afterHead = Buffer.concat([afterHead ?? Buffer.alloc(0), chunk])
  })
  socket.on('error', () => {})
})
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
const port = server.address().port

const pump = new PumpManager({
  resolveTarget: () => ({ host: '127.0.0.1', port, authority: `127.0.0.1:${port}`, protocol: 'http:' }),
  resolveAuthCookie: () => 'dsh-session=host-authority',
  pairing: { sessionForHeaders: () => ({ did: ID }), handle: () => null },
  cryptoBox: box,
})
pump.setClient({ sendStream: () => {}, closeStream: () => {} })

// A sealed client frame, exactly as the boot patch sends it.
const plaintext = Buffer.from(JSON.stringify({ t: 'hello', v: 1 }), 'utf8')
const sealed = box.seal(box.envelopeKey, plaintext)
const frame = buildFrame(OPCODES.OP_TEXT, Buffer.from(JSON.stringify({ __relay: sealed.toString('base64') })), { mask: true })

// Request head and first frame in one write, which is what a browser does.
const head = [
  `GET /c/${ID}/api/remote.mux?g=${GATE} HTTP/1.1`,
  'Host: relay.example',
  'Connection: Upgrade',
  'Upgrade: websocket',
  'Sec-WebSocket-Version: 13',
  'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
  '',
  '',
].join('\r\n')
pump.handleStreamData(1, Buffer.concat([Buffer.from(head, 'latin1'), frame]))

await new Promise((done) => setTimeout(done, 900))

let failures = 0
try {
  assert.ok(beforeHead !== null, 'the host saw the handshake')
  assert.equal(beforeHead.length, 0, `nothing was written before the 101 (got ${beforeHead.length} bytes)`)
  // The pump forwards the *decrypted* payload, re-framed as a masked text frame.
  assert.ok(afterHead, 'the frame arrived after the 101')
  assert.equal(afterHead[0] & 0x0f, OPCODES.OP_TEXT, 'it is a text frame')
  assert.ok(afterHead[1] & 0x80, 'a client frame is masked')
  const length = afterHead[1] & 0x7f
  const mask = afterHead.subarray(2, 6)
  const payload = Buffer.from(afterHead.subarray(6, 6 + length))
  for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i & 3]
  assert.deepEqual(payload, plaintext, 'the host received the decrypted payload')
  console.log('ok: a websocket frame waits for the host 101')
} catch (error) {
  failures += 1
  console.log(`FAIL: ${error.message}`)
}

server.close()
pump.dispose()
console.log(failures === 0 ? 'all ws ordering checks passed' : `${failures} ws ordering check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
