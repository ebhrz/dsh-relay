// A captured envelope must stay dead across a host restart.
//
// The replay memory used to be in-process only, while a pairing ticket lives for
// 30 days: a relay that recorded a write before a restart could replay it after
// one. The set is now flushed to disk and reloaded.

import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { CryptoBox } from '../src/crypto.js'

function identity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  return {
    id: 'NONCE001',
    psk: crypto.randomBytes(32).toString('hex'),
    gate: 'a'.repeat(64),
    signJwk: {
      public: publicKey.export({ format: 'jwk' }),
      private: privateKey.export({ format: 'jwk' }),
    },
  }
}

let failures = 0
const scenario = async (label, fn) => {
  try {
    await fn()
    console.log(`ok ${label}`)
  } catch (error) {
    failures += 1
    console.log(`FAIL ${label}: ${error.message}`)
  }
}

await scenario('a captured envelope stays dead across a restart', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nonce-'))
  try {
    const noncePath = path.join(dir, 'seen.json')
    const id = identity()

    const before = new CryptoBox(id, { noncePath })
    const captured = before.seal(before.envelopeKey, Buffer.from('write: terminal'))
    assert.ok(before.open(before.envelopeKey, captured), 'the original request opens once')
    before.flushNonces()

    // A new instance is what a restart looks like.
    const after = new CryptoBox(id, { noncePath })
    assert.equal(after.open(after.envelopeKey, captured), null, 'the replay is refused after the restart')

    // New traffic is unaffected.
    const fresh = after.seal(after.envelopeKey, Buffer.from('write: second'))
    assert.ok(after.open(after.envelopeKey, fresh), 'new envelopes still open')
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

await scenario('a corrupt cache starts empty instead of failing', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nonce-bad-'))
  try {
    const noncePath = path.join(dir, 'seen.json')
    fs.writeFileSync(noncePath, 'not json at all')
    const box = new CryptoBox(identity(), { noncePath })
    const sealed = box.seal(box.envelopeKey, Buffer.from('x'))
    assert.ok(box.open(box.envelopeKey, sealed), 'the box still works')
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

console.log(failures === 0 ? 'all nonce persistence checks passed' : `${failures} nonce persistence check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
