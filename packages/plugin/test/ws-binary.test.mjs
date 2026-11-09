// Binary messages have to stay binary across the seal.
//
// The client sets binaryType="arraybuffer" and the account avatar arrives that
// way. Sealing every frame and decoding it as text corrupted the bytes, and the
// host then rejected the frame - which is what killed the mux when the account
// panel was opened.

import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import net from 'node:net'
import { CryptoBox } from '../src/crypto.js'
import { PumpManager } from '../src/pump.js'
import { buildFrame, parseFrame, OPCODES } from '../src/ws-codec.js'

const GATE = 'b'.repeat(64)
const ID = 'WSBIN001'
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

const binaryPayload = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0x7f, 0x80, 0x0a])
let hostSocket = null
let hostFrames = Buffer.alloc(0)

const server = net.createServer((socket) => {
  hostSocket = socket
  let handshakeDone = false
  socket.on('data', (chunk) => {
    if (!handshakeDone) {
      const index = chunk.indexOf('\r\n\r\n')
      if (index === -1) return
      handshakeDone = true
      socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
      // Host -> phone: a binary message, like the avatar fetch.
      socket.write(buildFrame(OPCODES.OP_BINARY, binaryPayload, { mask: false }))
      hostFrames = chunk.subarray(index + 4)
      return
    }
    hostFrames = Buffer.concat([hostFrames, chunk])
  })
  socket.on('error', () => {})
})
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
const port = server.address().port

const toPhone = []
const pump = new PumpManager({
  resolveTarget: () => ({ host: '127.0.0.1', port, authority: `127.0.0.1:${port}`, protocol: 'http:' }),
  resolveAuthCookie: () => null,
  pairing: { sessionForHeaders: () => ({ did: ID }), handle: () => null },
  cryptoBox: box,
})
pump.setClient({
  sendStream: (_sid, bytes) => toPhone.push(Buffer.from(bytes)),
  closeStream: () => {},
})

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
pump.handleStreamData(1, Buffer.from(head, 'latin1'))

const sealedBinary = box.seal(box.envelopeKey, binaryPayload)
const clientBinary = buildFrame(
  OPCODES.OP_TEXT,
  Buffer.from(JSON.stringify({ __relay: sealedBinary.toString('base64'), __bin: 1 })),
  { mask: true },
)
await new Promise((done) => setTimeout(done, 400))
pump.handleStreamData(1, clientBinary)
await new Promise((done) => setTimeout(done, 400))

let failures = 0
const check = (label, fn) => {
  try { fn(); console.log(`ok: ${label}`) } catch (error) { failures += 1; console.log(`FAIL ${label}: ${error.message}`) }
}

check('binary from the host is sealed and flagged', () => {
  const handshake = toPhone.shift() // the 101 head the pump forwards first
  assert.ok(handshake, 'the 101 head reached the phone')
  const frame = parseFrame(toPhone[0])
  assert.ok(frame, 'a frame reached the phone')
  assert.equal(frame.frame.opcode, OPCODES.OP_TEXT, 'the envelope travels as text')
  const wrapped = JSON.parse(frame.frame.payload.toString('utf8'))
  assert.equal(wrapped.__bin, 1, 'the binary flag is set')
  const nonce = Buffer.from(wrapped.__relay, 'base64').subarray(0, 24)
  const sealed = Buffer.from(wrapped.__relay, 'base64').subarray(24)
  const opened = box.open(box.envelopeKey, Buffer.concat([nonce, sealed]))
  assert.deepEqual(Buffer.from(opened), binaryPayload, 'the bytes survived')
})

check('binary from the phone reaches the host as binary', () => {
  const parsed = parseFrame(hostFrames)
  assert.ok(parsed, 'the host received a frame')
  assert.equal(parsed.frame.opcode, OPCODES.OP_BINARY, 'the opcode stayed binary')
  assert.deepEqual(Buffer.from(parsed.frame.payload), binaryPayload, 'the payload is unchanged')
})

check('the host socket saw exactly one frame from the phone', () => {
  const parsed = parseFrame(hostFrames)
  assert.equal(parsed.rest.length, 0, 'no extra bytes')
})

server.close()
hostSocket?.destroy()
pump.dispose()
console.log(failures === 0 ? 'all ws binary checks passed' : `${failures} ws binary check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
