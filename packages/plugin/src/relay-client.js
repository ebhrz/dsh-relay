// WSS client from the local agent to the relay.
//
// Security: the relay's agent endpoint uses a self-signed certificate. This
// client pins the certificate fingerprint on first contact (TOFU, like ssh)
// and refuses the connection if it ever changes. Registration is gated by an
// HMAC challenge over the shared relay key.

import crypto from 'node:crypto'
import { WebSocket } from 'ws'
import { auditLog } from './identity.js'

const CONNECT_TIMEOUT = 15000
const HEARTBEAT_INTERVAL = 20000

export class RelayClient extends EventTarget {
  constructor(options) {
    super()
    this.host = options.host
    this.agentPort = options.agentPort
    this.relayKey = options.relayKey
    this.identity = options.identity // { id, gate, psk, certFingerprint, ... }
    this.onIdentityChange = options.onIdentityChange ?? (() => {})
    this.pump = options.pump // { handleStreamData(sid, chunk), handleStreamClose(sid) }

    this.ws = null
    this.stopped = true
    this.status = 'idle'
    this.detail = ''
    this.backoff = 1000
    this.heartbeatTimer = null
    this.pongMisses = 0
    this.reconnectTimer = null
  }

  // -- events ---------------------------------------------------------------
  emitStatus(status, detail = '') {
    this.status = status
    this.detail = detail
    this.dispatchEvent(new CustomEvent('status', { detail: { status, detail } }))
  }

  // -- lifecycle ------------------------------------------------------------
  start() {
    this.stopped = false
    this.connect()
  }

  stop() {
    this.stopped = true
    clearTimeout(this.reconnectTimer)
    clearInterval(this.heartbeatTimer)
    if (this.ws) {
      try { this.ws.terminate() } catch {}
      this.ws = null
    }
    this.emitStatus('stopped')
  }

  restart() {
    this.stop()
    this.start()
  }

  connected() {
    return this.ws != null && this.ws.readyState === WebSocket.OPEN
  }

  // -- connection -----------------------------------------------------------
  connect() {
    if (this.stopped) return
    const url = `wss://${this.host}:${this.agentPort}/agent`
    this.emitStatus('connecting', url)
    let ws
    try {
      ws = new WebSocket(url, { rejectUnauthorized: false, handshakeTimeout: CONNECT_TIMEOUT })
    } catch (error) {
      this.scheduleReconnect(String(error))
      return
    }
    this.ws = ws

    const fail = (detail) => {
      try { ws.terminate() } catch {}
      if (this.ws === ws) this.ws = null
      this.scheduleReconnect(detail)
    }

    ws.on('unexpected-response', (_req, res) => {
      fail(`unexpected response ${res.statusCode}`)
    })
    ws.on('error', (error) => {
      if (this.status !== 'connected') return // already failed via another path
      fail(error.message)
    })
    ws.on('close', () => {
      clearInterval(this.heartbeatTimer)
      if (this.ws === ws) {
        this.ws = null
        this.scheduleReconnect('closed')
      }
    })

    ws.on('open', () => {
      // Small request/response chunks dominate this socket (one write per
      // proxy hop); Nagle would hold each of them for a delayed ACK, which
      // costs ~40ms per request on a mobile link. Disable it, and keep the
      // long-lived agent socket alive across NAT/carrier idle timers.
      try {
        ws._socket?.setNoDelay(true)
        ws._socket?.setKeepAlive(true, 30_000)
      } catch {}
      // TOFU pin the relay certificate fingerprint.
      let fingerprint = null
      try {
        fingerprint = ws._socket.getPeerCertificate().fingerprint256 ?? null
      } catch {}
      if (fingerprint && this.identity.certFingerprint && fingerprint !== this.identity.certFingerprint) {
        this.emitStatus('fingerprint-mismatch',
          `relay certificate changed: pinned ${this.identity.certFingerprint} saw ${fingerprint}`)
        this.stopped = true // never auto-proceed on a possible MITM
        try { ws.terminate() } catch {}
        return
      }
      if (fingerprint && !this.identity.certFingerprint) {
        this.identity.certFingerprint = fingerprint
        this.onIdentityChange(this.identity)
      }

      this.pongMisses = 0
      this.heartbeatTimer = setInterval(() => {
        if (ws.readyState !== WebSocket.OPEN) return
        this.pongMisses += 1
        // Tolerate a couple of lost pongs (mobile/NAT jitter) before declaring
        // the agent link dead; an unnecessary reconnect makes every phone
        // session briefly see "device offline" through the relay.
        if (this.pongMisses > 3) {
          auditLog(`relay heartbeat: no pong for ${this.pongMisses} intervals, reconnecting`)
          try { ws.terminate() } catch {}
        } else ws.ping()
      }, HEARTBEAT_INTERVAL)
      ws.on('pong', () => { this.pongMisses = 0 })

      ws.send(JSON.stringify({ t: 'hello', v: 1, id: this.identity.id, gate: this.identity.gate }))
    })

    ws.on('message', (data, isBinary) => {
      if (!isBinary) {
        let msg
        try { msg = JSON.parse(data.toString()) } catch { return }
        if (msg.t === 'challenge') {
          const proof = crypto.createHmac('sha256', this.relayKey)
            .update(`${msg.nonce}|${this.identity.id}`).digest('hex')
          ws.send(JSON.stringify({ t: 'register', proof }))
          return
        }
        if (msg.t === 'registered') {
          this.backoff = 1000
          this.emitStatus('connected', url)
          return
        }
        if (msg.t === 'rejected') {
          this.emitStatus('rejected', msg.reason ?? 'rejected by relay')
          return
        }
        if (msg.t === 'close' && typeof msg.sid === 'number') {
          this.pump.handleStreamClose(msg.sid)
          return
        }
        return
      }
      if (data.length < 4) return
      const sid = data.readUInt32BE(0)
      try {
        this.pump.handleStreamData(sid, data.subarray(4))
      } catch (error) {
        // A bug in stream handling must never take the whole connection down.
        console.error('[dsh-relay-phone] stream error', sid, error)
        this.pump.handleStreamClose(sid)
        this.closeStream(sid)
      }
    })
  }

  scheduleReconnect(detail) {
    if (this.stopped) return
    this.emitStatus('reconnecting', detail)
    const delay = Math.min(30000, this.backoff) * (0.75 + Math.random() * 0.5)
    this.backoff = Math.min(30000, this.backoff * 2)
    this.reconnectTimer = setTimeout(() => this.connect(), delay)
  }

  // -- data -----------------------------------------------------------------
  sendStream(sid, chunk) {
    if (!this.connected()) return false
    const head = Buffer.alloc(4)
    head.writeUInt32BE(sid >>> 0, 0)
    this.ws.send(Buffer.concat([head, chunk]), { binary: true })
    return true
  }

  closeStream(sid) {
    if (!this.connected()) return
    this.ws.send(JSON.stringify({ t: 'close', sid }))
  }
}
