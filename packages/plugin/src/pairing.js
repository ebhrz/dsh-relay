// Pairing protocol between the phone bootstrap page and the pump.
//
// Two-step PSK challenge-response (the gate query param travels on the wire
// and is only an anti-scanner measure for the relay; real authentication
// proves knowledge of the PSK from the QR fragment):
//
//   POST /__relay/challenge {cnonce}        -> {snonce}      (snonce single-use)
//   POST /__relay/verify  {cnonce, snonce,
//        proof=sha512(psk|cnonce|snonce|verify)} -> Set-Cookie ticket + {ok}
//
// The session key for envelopes is derived from the same nonce pair, so M2b's
// boot script can recompute it locally from the PSK stored at first visit.
//
// sha512 is implemented inline (pure JS) because the page runs in a
// non-secure context where crypto.subtle is unavailable.

import crypto from 'node:crypto'
import { auditLog } from './identity.js'

export const TICKET_TTL_SECONDS = 30 * 24 * 3600
export const COOKIE_NAME = '__relay_t'
const CHALLENGE_TTL_MS = 60000
const BODY_LIMIT = 64 * 1024

export class PairingService {
  constructor(cryptoBox, identity) {
    this.box = cryptoBox
    this.identity = identity
    this.challenges = new Map() // snonce -> { cnonce, createdAt }
  }

  sweepChallenges() {
    const now = Date.now()
    for (const [snonce, entry] of this.challenges) {
      if (now - entry.createdAt > CHALLENGE_TTL_MS) this.challenges.delete(snonce)
    }
  }

  proofHex(cnonce, snonce) {
    return crypto.createHash('sha512')
      .update(this.box.psk)
      .update(Buffer.from(`${cnonce}|${snonce}|verify`))
      .digest('hex')
  }

  // Returns a plain object response or null when the path is not ours.
  // { status, contentType, body, setCookie? }
  handle(path, method, headers, bodyBuffer) {
    this.sweepChallenges()
    this.box.sweepSessions()

    if (path === '/__relay/challenge' && method === 'POST') {
      const payload = parseJson(bodyBuffer)
      const cnonce = String(payload?.cnonce ?? '')
      if (!/^[A-Za-z0-9+/=]{8,64}$/.test(cnonce)) {
        return badRequest('bad cnonce')
      }
      const snonce = crypto.randomBytes(16).toString('base64')
      this.challenges.set(snonce, { cnonce, createdAt: Date.now() })
      return json({ snonce })
    }

    if (path === '/__relay/verify' && method === 'POST') {
      const payload = parseJson(bodyBuffer)
      const cnonce = String(payload?.cnonce ?? '')
      const snonce = String(payload?.snonce ?? '')
      const proof = String(payload?.proof ?? '')
      const entry = this.challenges.get(snonce)
      this.challenges.delete(snonce) // single use
      if (!entry || entry.cnonce !== cnonce) {
        auditLog(`pair-verify rejected (challenge mismatch)`)
        return { status: 403, contentType: JSON_TYPE, body: '{"ok":false,"error":"challenge"}' }
      }
      const expected = this.proofHex(cnonce, snonce)
      const a = Buffer.from(proof)
      const b = Buffer.from(expected)
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        auditLog('pair-verify rejected (bad proof)')
        return { status: 403, contentType: JSON_TYPE, body: '{"ok":false,"error":"proof"}' }
      }
      const { did } = this.box.registerPairingSession(cnonce, snonce)
      const ticket = this.box.sealTicket(did, TICKET_TTL_SECONDS)
      auditLog(`paired device did=${did.slice(0, 6)}…`)
      // Two cookies: the encrypted ticket (auth) and the plain gate — the
      // gate cookie lets the relay route browser-native loads (ES module
      // imports, subresources) whose URLs dropped the ?g= query. The gate is
      // not a secret: it already travels in the entry URL.
      const identity = this.identity
      const gateCookie = `__relay_g=${identity.gate}; Path=/; SameSite=Strict; Max-Age=${TICKET_TTL_SECONDS}`
      const idCookie = `__relay_i=${identity.id}; Path=/; SameSite=Strict; Max-Age=${TICKET_TTL_SECONDS}`
      return json({ ok: true }, {
        'set-cookie': [
          `${COOKIE_NAME}=${ticket}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${TICKET_TTL_SECONDS}`,
          gateCookie,
          idCookie,
        ].join('\r\nset-cookie: '),
      })
    }

    if (path === '/__relay/ping') {
      const session = this.sessionForHeaders(headers)
      if (!session) return { status: 401, contentType: JSON_TYPE, body: '{"ok":false}' }
      return json({ ok: true, id: this.identity.id, ts: Date.now() })
    }

    if (path === '/__relay/diag' && method === 'POST') {
      const payload = parseJson(bodyBuffer) ?? {}
      auditLog(`diag ua=${String(payload.ua ?? '').slice(0, 120)} gate=${payload.gate} cookie=${payload.cookie} note=${String(payload.note ?? '').slice(0, 80)}`)
      return json({ ok: true })
    }

    return null
  }

  sessionForHeaders(headers) {
    // Accepts both the pump's Headers instance and Node's plain-object
    // req.headers ({ cookie: '...' }) from the local webServer handlers.
    const cookieHeader = typeof headers?.get === 'function'
      ? headers.get('cookie') ?? ''
      : String(headers?.cookie ?? '')
    const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([A-Za-z0-9_-]+)`))
    if (!match) return null
    return this.box.sessionForTicket(match[1])
  }
}

const JSON_TYPE = 'application/json; charset=utf-8'

function parseJson(buffer) {
  try { return JSON.parse(buffer.toString('utf8')) } catch { return null }
}

function json(value, extraHeaders = {}) {
  return { status: 200, contentType: JSON_TYPE, body: JSON.stringify(value), headers: extraHeaders }
}

function badRequest(error) {
  return { status: 400, contentType: JSON_TYPE, body: JSON.stringify({ ok: false, error }) }
}

export { BODY_LIMIT }
