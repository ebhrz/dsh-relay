// Device identity for dsh-relay-phone.
//
// Everything here stays on this machine (0600 file under $DSH_HOME/plugin-data):
//   id        8-char device id shown in the entry URL
//   psk       32-byte pre-shared key carried inside the QR fragment (never
//             sent to the relay); seeds session keys and the client gate
//   gate      HMAC(psk, "gate:"+id) — the ONLY value the relay learns, used to
//             reject scanner noise before it ever reaches this agent
//   signJwk   Ed25519 key pair for shell/firmware signatures (used from M2)
//   certFingerprint  TOFU pin of the relay's agent TLS certificate
//
// Rotating the identity (regenerate) revokes every previously paired phone.

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'

const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789' // no ambiguous glyphs

function randomId(length = 8) {
  const bytes = crypto.randomBytes(length)
  let out = ''
  for (let i = 0; i < length; i += 1) out += ALPHABET[bytes[i] % ALPHABET.length]
  return out
}

function dshHome() {
  return process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh')
}

export function identityDir() {
  return path.join(dshHome(), 'plugin-data', 'dsh-relay-phone')
}

export function identityPath() {
  return path.join(identityDir(), 'identity.json')
}

export function createIdentity() {
  const psk = crypto.randomBytes(32).toString('hex')
  const id = randomId()
  const gate = crypto.createHmac('sha256', psk).update(`gate:${id}`).digest('hex')
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  const signJwk = {
    public: publicKey.export({ format: 'jwk' }),
    private: privateKey.export({ format: 'jwk' }),
  }
  return { id, psk, gate, signJwk, certFingerprint: null, createdAt: new Date().toISOString() }
}

export function loadOrCreateIdentity() {
  const file = identityPath()
  fs.mkdirSync(path.dirname(file), { recursive: true })
  if (fs.existsSync(file)) {
    try {
      const identity = JSON.parse(fs.readFileSync(file, 'utf8'))
      if (identity.id && identity.psk && identity.gate) return identity
    } catch {
      // fall through: regenerate a broken file
    }
  }
  const identity = createIdentity()
  saveIdentity(identity)
  return identity
}

export function saveIdentity(identity) {
  const file = identityPath()
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, JSON.stringify(identity, null, 2) + '\n', { mode: 0o600 })
  try { fs.chmodSync(file, 0o600) } catch {}
}

export function auditLog(line) {
  try {
    const dir = identityDir()
    fs.mkdirSync(dir, { recursive: true })
    fs.appendFileSync(path.join(dir, 'audit.log'), `${new Date().toISOString()} ${line}\n`)
  } catch {
    // auditing must never break the data path
  }
}
