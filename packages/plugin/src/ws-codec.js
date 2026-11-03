// Minimal RFC 6455 frame codec for the pump's WebSocket sealing layer.
//
// After an upgraded stream, the pump re-frames WebSocket traffic:
//   phone -> DSH:  data frames carry {b: base64(sealed)} JSON text from the
//                  patched client; the pump unseals and re-frames the plaintext
//                  as a masked binary frame for the server.
//   DSH -> phone:  server data frames are unsealed upstream, sealed with the
//                  envelope key, and re-framed as {b} text frames.
//   Control frames (ping/pong/close) are re-framed untouched.
//
// permessage-deflate is stripped from upgrade requests, so payloads are raw
// and frame lengths are meaningful. Fragmented messages are reassembled
// before sealing and re-emitted as single frames.

const OP_TEXT = 0x1
const OP_BINARY = 0x2
const OP_CLOSE = 0x8
const OP_PING = 0x9
const OP_PONG = 0xa

export function isDataFrame(opcode) {
  return opcode === OP_TEXT || opcode === OP_BINARY
}

export function isControlFrame(opcode) {
  return (opcode & 0x8) !== 0
}

// Parse one frame from buffer. Returns { frame, rest } or null if incomplete.
// frame: { fin, opcode, masked, maskKey, payload }
export function parseFrame(buffer) {
  if (buffer.length < 2) return null
  const b0 = buffer[0]
  const b1 = buffer[1]
  const fin = (b0 & 0x80) !== 0
  const opcode = b0 & 0x0f
  const masked = (b1 & 0x80) !== 0
  let length = b1 & 0x7f
  let offset = 2
  if (length === 126) {
    if (buffer.length < 4) return null
    length = buffer.readUInt16BE(2)
    offset = 4
  } else if (length === 127) {
    if (buffer.length < 10) return null
    const big = buffer.readBigUInt64BE(2)
    if (big > 64n * 1024n * 1024n) throw new Error('ws frame too large')
    length = Number(big)
    offset = 10
  }
  const maskKey = masked ? buffer.subarray(offset, offset + 4) : null
  if (masked) offset += 4
  if (buffer.length < offset + length) return null
  let payload = buffer.subarray(offset, offset + length)
  if (masked) {
    const unmasked = Buffer.allocUnsafe(length)
    for (let i = 0; i < length; i += 1) unmasked[i] = payload[i] ^ maskKey[i & 3]
    payload = unmasked
  }
  return { frame: { fin, opcode, masked, maskKey, payload }, rest: buffer.subarray(offset + length) }
}

export function buildFrame(opcode, payload, { mask = false, fin = true } = {}) {
  const length = payload.length
  let header
  if (length < 126) {
    header = Buffer.alloc(2)
    header[1] = length
  } else if (length < 65536) {
    header = Buffer.alloc(4)
    header[1] = 126
    header.writeUInt16BE(length, 2)
  } else {
    header = Buffer.alloc(10)
    header[1] = 127
    header.writeBigUInt64BE(BigInt(length), 2)
  }
  header[0] = (fin ? 0x80 : 0x00) | opcode
  let maskKey = null
  if (mask) {
    header[1] |= 0x80
    maskKey = Buffer.from([Math.random() * 256 | 0, Math.random() * 256 | 0, Math.random() * 256 | 0, Math.random() * 256 | 0])
    const masked = Buffer.allocUnsafe(length)
    for (let i = 0; i < length; i += 1) masked[i] = payload[i] ^ maskKey[i & 3]
    payload = masked
    return Buffer.concat([header, maskKey, payload])
  }
  return Buffer.concat([header, payload])
}

export const OPCODES = { OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG }
