// Crypto core for dsh-relay-phone (host side).
//
// Uses tweetnacl on BOTH ends deliberately: the phone reaches us over plain
// HTTP to a bare IP in the common deployment, where WebCrypto (crypto.subtle)
// and Service Workers are unavailable (non-secure context). tweetnacl is pure
// JS, audited, and identical on both sides — no isomorphism bugs.
//
//   session keys   sha256(PSK | context | clientNonce | serverNonce)
//   envelopes      nacl.secretbox (XSalsa20-Poly1305), 24-byte random nonce
//   cookies        sealed ticket { did, exp } under a PSK-derived ticket key
//   shell updates  nacl.sign (Ed25519), public key travels in the QR fragment

import nacl from 'tweetnacl'
import crypto from 'node:crypto'
import fs from 'node:fs'

const sha256 = (...parts) => {
  const hash = crypto.createHash('sha256')
  for (const part of parts) hash.update(part)
  return new Uint8Array(hash.digest())
}

// How many opened envelopes to remember for replay detection. 50k * ~70 B
// is a few megabytes, and on a personal relay it covers weeks of traffic.
const REPLAY_MEMORY = 50_000

export class CryptoBox {
  constructor(identity, options = {}) {
    this.psk = Buffer.from(identity.psk, 'hex') // 32 bytes
    if (this.psk.length !== 32) throw new Error('identity psk must be 32 bytes')
    this.signJwk = identity.signJwk
    this.ticketKey = sha256(this.psk, Buffer.from('ticket'))
    // Static envelope key for request/response/WS payload sealing. Derived
    // from the PSK (never transmitted); rotating the identity rotates it.
    // Must match the browser boot: nacl.hash(psk || 'envelope').slice(0, 32).
    this.envelopeKey = new Uint8Array(
      crypto.createHash('sha512').update(this.psk).update(Buffer.from('envelope')).digest().subarray(0, 32),
    )
    this.sessions = new Map() // did -> { key, createdAt }
    // Tickets are sealed for 30 days, but the did->session table used to live
    // only in memory: every host restart orphaned every paired phone's cookie
    // (ws upgrades then looped on "unauthenticated -> pairing page" until the
    // page was reloaded). Persist the table beside identity.json so a restart
    // keeps phones paired.
    this.sessionsPath = options.sessionsPath ?? null
    // Replay defence. Every envelope carries a fresh random nonce, so seeing the
    // same nonce twice means the ciphertext was captured and re-submitted by
    // someone who cannot forge one — the relay is exactly that someone. Remember
    // what has been opened and refuse a repeat; the set is bounded by count (an
    // entry falls out only after REPLAY_MEMORY newer envelopes), which for a
    // personal relay is days of traffic.
    this.openedNonces = new Set()
    this.#loadSessions()
  }

  /**
   * False when this nonce has been opened before, i.e. the ciphertext is a copy.
   * Bounded memory: oldest entries are dropped first, so a long-running process
   * cannot grow without limit.
   */
  acceptNonce(nonce) {
    const id = nonce.toString('hex')
    if (this.openedNonces.has(id)) return false
    this.openedNonces.add(id)
    if (this.openedNonces.size > REPLAY_MEMORY) {
      const excess = this.openedNonces.size - REPLAY_MEMORY
      let dropped = 0
      for (const old of this.openedNonces) {
        this.openedNonces.delete(old)
        if (++dropped >= excess) break
      }
    }
    return true
  }

  #loadSessions() {
    if (!this.sessionsPath) return
    try {
      const raw = JSON.parse(fs.readFileSync(this.sessionsPath, 'utf8'))
      for (const [did, entry] of Object.entries(raw)) {
        if (typeof did !== 'string' || did === '' || !entry
          || typeof entry.key !== 'string' || typeof entry.createdAt !== 'number') continue
        this.sessions.set(did, { key: new Uint8Array(Buffer.from(entry.key, 'base64')), createdAt: entry.createdAt })
      }
    } catch {
      // missing/corrupt file starts from an empty table; phones re-pair on load
    }
  }

  #saveSessions() {
    if (!this.sessionsPath) return
    try {
      const raw = {}
      for (const [did, session] of this.sessions) {
        raw[did] = { key: Buffer.from(session.key).toString('base64'), createdAt: session.createdAt }
      }
      const tmp = `${this.sessionsPath}.tmp`
      fs.writeFileSync(tmp, `${JSON.stringify(raw)}\n`, { mode: 0o600 })
      try { fs.chmodSync(tmp, 0o600) } catch {}
      fs.renameSync(tmp, this.sessionsPath)
    } catch {
      // persistence must never break the data path
    }
  }

  deriveSessionKey(clientNonceB64, serverNonceB64) {
    return sha256(
      this.psk,
      Buffer.from('session'),
      Buffer.from(clientNonceB64, 'base64'),
      Buffer.from(serverNonceB64, 'base64'),
    )
  }

  createSession() {
    const did = crypto.randomBytes(12).toString('base64url')
    const key = sha256(this.psk, Buffer.from('device'), crypto.randomBytes(16))
    this.sessions.set(did, { key, createdAt: Date.now() })
    this.#saveSessions()
    return { did, key }
  }

  registerPairingSession(clientNonceB64, serverNonceB64) {
    const did = crypto.randomBytes(12).toString('base64url')
    const key = this.deriveSessionKey(clientNonceB64, serverNonceB64)
    this.sessions.set(did, { key, createdAt: Date.now() })
    this.#saveSessions()
    return { did, key }
  }

  // Drop sessions older than maxAgeMs (called opportunistically).
  sweepSessions(maxAgeMs = 30 * 24 * 3600 * 1000) {
    const now = Date.now()
    let removed = false
    for (const [did, session] of this.sessions) {
      if (now - session.createdAt > maxAgeMs) { this.sessions.delete(did); removed = true }
    }
    if (removed) this.#saveSessions()
  }

  // Identity rotation revokes every paired device: start from an empty table
  // and overwrite any persisted file from the previous identity.
  resetSessions() {
    this.sessions.clear()
    this.#saveSessions()
  }

  // -- tickets (encrypted cookies) -------------------------------------------
  sealTicket(did, ttlSeconds) {
    const payload = Buffer.from(JSON.stringify({
      did,
      exp: Date.now() + ttlSeconds * 1000,
    }))
    const nonce = crypto.randomBytes(nacl.secretbox.nonceLength)
    const box = nacl.secretbox(payload, nonce, this.ticketKey)
    return Buffer.concat([nonce, Buffer.from(box)]).toString('base64url')
  }

  openTicket(ticket) {
    if (!ticket) return null
    try {
      const raw = Buffer.from(ticket, 'base64url')
      const nonce = raw.subarray(0, nacl.secretbox.nonceLength)
      const box = raw.subarray(nacl.secretbox.nonceLength)
      const opened = nacl.secretbox.open(box, nonce, this.ticketKey)
      if (!opened) return null
      const data = JSON.parse(Buffer.from(opened).toString('utf8'))
      if (typeof data.did !== 'string' || typeof data.exp !== 'number') return null
      if (Date.now() > data.exp) return null
      return data
    } catch {
      return null
    }
  }

  sessionForTicket(ticket) {
    const data = this.openTicket(ticket)
    if (!data) return null
    return this.sessions.get(data.did) ?? null
  }

  // -- envelopes --------------------------------------------------------------
  seal(key, plaintext) {
    const nonce = crypto.randomBytes(nacl.secretbox.nonceLength)
    const box = nacl.secretbox(plaintext, nonce, key)
    return Buffer.concat([nonce, Buffer.from(box)])
  }

  open(key, sealed) {
    if (sealed.length < nacl.secretbox.nonceLength + nacl.secretbox.overheadLength) return null
    const nonce = sealed.subarray(0, nacl.secretbox.nonceLength)
    const box = sealed.subarray(nacl.secretbox.nonceLength)
    const opened = nacl.secretbox.open(box, nonce, key)
    if (!opened) return null
    // A valid envelope that has been seen before is a replay: the relay recorded
    // it and sent it again. Refusing it here covers every unseal path — HTTP
    // bodies, the mobile RPC and websocket frames all come through `open`.
    if (!this.acceptNonce(nonce)) return null
    return Buffer.from(opened)
  }

  // -- shell signatures (Ed25519 over boot.js) --------------------------------
  // Host side uses node:crypto with the Ed25519 JWK from the identity; the
  // browser verifies with the raw public key carried in the QR fragment.
  signBoot(source) {
    const privateKey = crypto.createPrivateKey({ key: this.signJwk.private, format: 'jwk' })
    return crypto.sign(null, Buffer.from(source, 'utf8'), privateKey).toString('base64')
  }

  get signJwk() { return this._signJwk }
  set signJwk(jwk) { this._signJwk = jwk }
}

export function randomNonceB64() {
  return crypto.randomBytes(16).toString('base64')
}
