#!/usr/bin/env node
// Sealed WebSocket probe.
//
// Opens a WebSocket through the relay to DSH's events endpoint and speaks the
// patched client's {__relay: base64} frame protocol, so both the upgrade path
// and the frame codec are exercised end to end.
//
//   RELAY_BASE_URL=https://relay.example.com:8889 node scripts/probe-ws.mjs
//
// Needs: a running relay, the plugin connected to it, and a local identity.

import crypto from 'node:crypto'
import nacl from 'tweetnacl'
import { WebSocket } from 'ws'
import { entryBaseOrExit } from './lib/relay-env.mjs'

const { identity, base } = entryBaseOrExit()
const GATE = identity.gate
const psk = Buffer.from(identity.psk, 'hex')
const envKey = nacl.hash(Buffer.concat([psk, Buffer.from('envelope')])).slice(0, 32)

const seal = (bytes) => {
  const nonce = nacl.randomBytes(24)
  const box = nacl.secretbox(bytes, nonce, envKey)
  const out = new Uint8Array(24 + box.length)
  out.set(nonce, 0)
  out.set(box, 24)
  return out
}
const open = (bytes) => {
  const opened = nacl.secretbox.open(bytes.slice(24), bytes.slice(0, 24), envKey)
  return opened ? new Uint8Array(opened) : null
}

// --- pair -------------------------------------------------------------------
const post = (name, body) => fetch(`${base}/__relay/${name}?g=${GATE}`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(body),
})
const cnonce = crypto.randomBytes(12).toString('base64')
const { snonce } = await (await post('challenge', { cnonce })).json()
const proof = crypto.createHash('sha512').update(psk)
  .update(Buffer.from(`${cnonce}|${snonce}|verify`)).digest('hex')
const verified = await post('verify', { cnonce, snonce, proof })
const cookie = /__relay_t=([^;]+)/.exec(verified.headers.get('set-cookie'))?.[1]
if (!cookie) {
  console.error('pairing failed: no __relay_t cookie')
  process.exit(1)
}
console.log('pair: ok')

// --- upgraded WS through the relay -----------------------------------------
const wsBase = base.replace(/^http/, 'ws')
const ws = new WebSocket(`${wsBase}/api/events.mux?g=${GATE}`, {
  headers: { cookie: `__relay_t=${cookie}` },
})

let sealedFrames = 0
let plainFrames = 0
ws.on('open', () => {
  console.log('ws: open (upgrade + codec path live)')
  // A sealed text frame, like the patched client sends.
  ws.send(JSON.stringify({
    __relay: Buffer.from(seal(new TextEncoder().encode('{"type":"ping"}'))).toString('base64'),
  }))
})
ws.on('message', (data) => {
  const text = data.toString('utf8')
  try {
    const parsed = JSON.parse(text)
    if (parsed && typeof parsed.__relay === 'string') {
      const plain = open(Buffer.from(parsed.__relay, 'base64'))
      sealedFrames += 1
      console.log('sealed frame from server:',
        plain ? new TextDecoder().decode(plain).slice(0, 100) : '(open failed)')
      return
    }
  } catch {}
  plainFrames += 1
  console.log('plain frame from server:', text.slice(0, 100))
})
ws.on('close', (code, reason) => console.log('ws close:', code, reason.toString().slice(0, 80)))
ws.on('error', (error) => console.log('ws error:', error.message))

setTimeout(() => {
  console.log(`summary: sealed=${sealedFrames} plain=${plainFrames}`)
  ws.terminate()
  process.exit(0)
}, 8000)
