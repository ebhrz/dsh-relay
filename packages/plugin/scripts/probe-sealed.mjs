#!/usr/bin/env node
// Sealed round trip from outside the browser.
//
// Pairs with the relay the way a phone does, then exercises the same encrypted
// envelope the injected boot code uses for every API call: a sealed GET, a
// plain document GET (boot injection), and a sealed POST. Useful to prove that
// pairing, sealing and the pump still line up end to end.
//
//   RELAY_BASE_URL=https://relay.example.com:8889 node scripts/probe-sealed.mjs
//
// Needs: a running relay, the plugin connected to it, and a local identity
// (DSH_HOME default ~/.dsh).

import crypto from 'node:crypto'
import nacl from 'tweetnacl'
import { entryBaseOrExit } from './lib/relay-env.mjs'

const { identity, base } = entryBaseOrExit()
const GATE = identity.gate
const psk = Buffer.from(identity.psk, 'hex')
// Matches CryptoBox in src/crypto.js and the boot injection:
// SHA-512(psk || "envelope")[:32]. tweetnacl's hash is SHA-512, so the two
// implementations agree byte for byte.
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

// --- 1. pair: challenge/response over the PSK --------------------------------
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
  console.error('pairing failed: no __relay_t cookie (relay key or identity mismatch?)')
  process.exit(1)
}
const headers = { cookie: `__relay_t=${cookie}` }
console.log('pair: ok')

// --- 2. sealed GET: what the patched fetch does for every API call -----------
const sealed = await fetch(`${base}/?g=${GATE}`, { headers: { ...headers, 'x-relay-enc': '1' } })
console.log('sealed GET outer:', sealed.status, sealed.headers.get('content-type'),
  'enc=', sealed.headers.get('x-relay-enc'))
const plain = open(new Uint8Array(await sealed.arrayBuffer()))
if (!plain) {
  console.error('envelope open failed (sealed key mismatch)')
  process.exit(1)
}
const text = new TextDecoder().decode(plain)
console.log('inner:', text.split('\r\n')[0], '| title:', /<title>([^<]*)<\/title>/.exec(text)?.[1])

// --- 3. plain document GET: boot injection ----------------------------------
const doc = await fetch(`${base}/?g=${GATE}`, { headers: { ...headers, accept: 'text/html' } })
const docText = await doc.text()
console.log('document:', doc.status, docText.length, 'bytes, boot injected:', docText.includes('__dshRelayBoot'))

// --- 4. sealed POST ---------------------------------------------------------
const posted = await fetch(`${base}/api/some/endpoint?g=${GATE}`, {
  method: 'POST',
  headers: {
    ...headers,
    'content-type': 'application/octet-stream',
    'x-relay-enc': '1',
    'x-relay-ct': 'application/json',
  },
  body: seal(new TextEncoder().encode(JSON.stringify({ q: 'probe' }))),
})
console.log('sealed POST outer:', posted.status)
if (posted.headers.get('x-relay-enc') === '1') {
  const inner = new TextDecoder().decode(open(new Uint8Array(await posted.arrayBuffer())))
  console.log('inner:', inner.split('\r\n')[0], '| body:', inner.split('\r\n\r\n')[1]?.slice(0, 80))
} else {
  console.log('(unsealed response — passthrough path)')
}
console.log('ALL DONE')
