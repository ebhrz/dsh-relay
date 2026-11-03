// Mobile web app transport: a purpose-built phone page plus its local API.
//
// The desktop DSH UI replayed through the sealed pump is a poor phone client
// (three-column layout, heavy bundles). This module serves a small standalone
// page at /c/<device>/m and answers its calls from the plugin's own host
// services — the "native" DSH API, not the replayed DSH frontend.
//
// Everything here is LOCAL to the plugin (the pump intercepts these paths
// before they can reach the DSH upstream):
//
//   GET  /m                      page shell (only after the pairing ticket gate)
//   GET  /m/<asset>              cached static assets (immutable, ?v=<hash>)
//   POST /__relay/m/rpc          sealed JSON round trip (same envelope as /api)
//   WS   /__relay/m/ws           sealed push channel for live agent events
//
// The transport deliberately reuses the existing crypto box, pairing sessions
// and envelope framing, so the phone still needs a paired ticket and the relay
// still only forwards ciphertext.

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { buildFrame, parseFrame, isDataFrame, OPCODES } from '../ws-codec.js'

const ASSET_DIR = fileURLToPath(new URL('./assets/', import.meta.url))
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
const WS_IDLE_MS = 120_000
const RPC_LIMIT = 1024 * 1024
const DEBUG = process.env.DSH_RELAY_DEBUG === '1'

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.webmanifest': 'application/manifest+json',
  '.woff2': 'font/woff2',
}

/** Root-relative paths owned by the mobile app. */
export const MOBILE_PAGE_PATH = '/m'
export const MOBILE_RPC_PATH = '/__relay/m/rpc'
export const MOBILE_WS_PATH = '/__relay/m/ws'

/**
 * Serve the mobile app and bridge its phone connection to the host-side
 * {@link MobileBridge} (`bridge.rpc`, `bridge.subscribe`, `bridge.unsubscribe`).
 */
export class MobileRouter {
  constructor({ cryptoBox, bridge, logger }) {
    this.cryptoBox = cryptoBox
    this.bridge = bridge
    this.log = logger ?? console
    this.assets = new Map() // name -> { body, type, etag }
    this.ws = new Map() // sid -> connection state
  }

  /** True when this HTTP path belongs to the mobile surface. */
  handles(pathName) {
    return pathName === MOBILE_PAGE_PATH
      || pathName.startsWith(`${MOBILE_PAGE_PATH}/`)
      || pathName === MOBILE_RPC_PATH
      || pathName === MOBILE_WS_PATH
  }

  handlesUpgrade(pathName) {
    return pathName === MOBILE_WS_PATH
  }

  // -- static surface -----------------------------------------------------
  asset(name) {
    const clean = name.replace(/^\/+/, '')
    if (clean.includes('..') || clean.includes('\0')) return null
    try {
      const file = clean === 'nacl.js' ? naclPath() : path.join(ASSET_DIR, clean)
      if (!file) return null
      // Client-side iteration should not need a host restart: revalidate by
      // mtime/size and re-read the file when it changed. Assets are tiny and
      // requested a handful of times per page load.
      const stat = fs.statSync(file)
      const stamp = `${stat.mtimeMs}:${stat.size}`
      const cached = this.assets.get(clean)
      if (cached && cached.stamp === stamp) return cached
      const body = fs.readFileSync(file)
      const type = MIME[path.extname(clean).toLowerCase()] ?? 'application/octet-stream'
      const etag = `"${crypto.createHash('sha1').update(body).digest('base64url').slice(0, 16)}"`
      const entry = { body, type, etag, stamp }
      this.assets.set(clean, entry)
      return entry
    } catch {
      return null
    }
  }

  /**
   * Render the page shell. Asset URLs carry the relay device prefix and gate
   * when known (so a static asset never depends on the relay's cookie
   * fallback), plus a content hash for immutable caching.
   */
  renderPage({ upstream, relay }) {
    let html
    try {
      html = fs.readFileSync(path.join(ASSET_DIR, 'app.html'), 'utf8')
    } catch (error) {
      return `<!doctype html><meta charset="utf-8"><body style="font-family:system-ui;background:#0e1117;color:#e6e9f2;padding:24px">mobile app assets missing: ${escapeHtml(error.message)}</body>`
    }
    const prefix = relay ? `/c/${relay.id}` : ''
    const gate = relay ? `g=${relay.gate}&` : ''
    const assetUrl = (name) => {
      const asset = this.asset(name)
      const hash = asset ? asset.etag.replace(/"/g, '') : '0'
      return `${prefix}/m/${name}?${gate}v=${hash}`
    }
    return html
      .replaceAll('{{CSS}}', assetUrl('app.css'))
      .replaceAll('{{JS}}', assetUrl('app.js'))
      .replaceAll('{{NACL}}', assetUrl('nacl.js'))
      .replaceAll('{{ICON}}', assetUrl('icon.svg'))
      .replaceAll('{{UPSTREAM}}', upstream ? '1' : '0')
  }

  /**
   * Serve a page or asset request. Called by the pump for a ticketed request.
   * @returns the HTTP body/headers to send (100% local, never proxied).
   */
  pageResponse(pathName, { method, headers, relay } = {}) {
    if (pathName === MOBILE_PAGE_PATH || pathName === `${MOBILE_PAGE_PATH}/`) {
      return {
        status: 200,
        contentType: 'text/html; charset=utf-8',
        body: this.renderPage({ upstream: this.bridge?.upstreamReady?.() ?? false, relay }),
        headers: { 'cache-control': 'no-store' },
      }
    }
    const name = pathName.slice(MOBILE_PAGE_PATH.length + 1)
    const asset = this.asset(name)
    if (!asset) return { status: 404, contentType: 'text/plain; charset=utf-8', body: 'not found\n', headers: { 'cache-control': 'no-store' } }
    const inm = String(headers?.get?.('if-none-match') ?? '')
    if (inm && inm === asset.etag) {
      return { status: 304, contentType: asset.type, body: '', headers: { etag: asset.etag, 'cache-control': 'public, max-age=31536000, immutable' } }
    }
    return {
      status: 200,
      contentType: asset.type,
      body: asset.body,
      headers: { etag: asset.etag, 'cache-control': 'public, max-age=31536000, immutable' },
    }
  }

  // -- sealed RPC ---------------------------------------------------------
  /**
   * Handle one sealed RPC round trip. The pump has already opened the request
   * envelope; the reply is sealed as a complete inner HTTP response, exactly
   * like the DSH API forwarding path.
   */
  async rpc(sid, plaintext, pump) {
    let request
    try {
      request = JSON.parse(plaintext.toString('utf8'))
    } catch {
      return pump.replySealed(sid, 200, JSON.stringify({ ok: false, error: { code: 'bad-json', message: 'bad json' } }))
    }
    if (!request || typeof request.method !== 'string') {
      return pump.replySealed(sid, 200, JSON.stringify({ ok: false, error: { code: 'bad-request', message: 'missing method' } }))
    }
    const started = Date.now()
    let payload
    try {
      const result = await this.bridge.rpc(request.method, request.params ?? {}, { sid })
      payload = JSON.stringify({ id: request.id ?? null, ok: true, result: result ?? null })
    } catch (error) {
      const code = error?.code ?? 'internal'
      payload = JSON.stringify({
        id: request.id ?? null,
        ok: false,
        error: { code, message: String(error?.message ?? error) },
      })
      if (DEBUG) this.log.warn?.(`[relay-mobile] rpc ${request.method} failed: ${error?.message ?? error}`)
    }
    if (DEBUG) this.log.info?.(`[relay-mobile] rpc ${request.method} ${Date.now() - started}ms ${Buffer.byteLength(payload)}B`)
    return pump.replySealed(sid, 200, payload)
  }

  // -- sealed push channel -------------------------------------------------
  /** Accept the WebSocket upgrade locally (never touching the DSH upstream). */
  openUpgrade(sid, stream, info, pump) {
    const key = info.headers.get('sec-websocket-key')
    const version = info.headers.get('sec-websocket-version')
    if (!key || version !== '13') {
      pump.respondInline(sid, 400, 'Bad Request', 'bad websocket handshake\n')
      pump.closeStream(sid)
      return
    }
    const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64')
    pump.send(sid, Buffer.from(
      'HTTP/1.1 101 Switching Protocols\r\n'
      + 'Upgrade: websocket\r\n'
      + 'Connection: Upgrade\r\n'
      + `Sec-WebSocket-Accept: ${accept}\r\n\r\n`, 'latin1'))
    const state = {
      sid,
      pump,
      stream,
      buffer: Buffer.alloc(0),
      closed: false,
      lastSeen: Date.now(),
      pongAt: Date.now(),
      timer: null,
      sessionId: null,
    }
    this.ws.set(sid, state)
    // Keep the stream out of the HTTP state machine: all further bytes are
    // WebSocket frames for this connection.
    stream.mobile = state
    pump.setPhase(sid, stream, 'mobile-ws')
    state.timer = setInterval(() => this.wsTick(sid), 25_000)
    state.timer.unref?.()
    this.bridge?.onPhoneOpen?.({ sid })
    this.log.info?.(`[relay-mobile] ws open sid=${sid}`)
  }

  wsTick(sid) {
    const state = this.ws.get(sid)
    if (!state) return
    if (Date.now() - state.lastSeen > WS_IDLE_MS) {
      this.closeWs(sid, 1001, 'idle')
      return
    }
    if (Date.now() - state.pongAt > 60_000) {
      // No pong from the phone: the link is gone even if TCP lingers.
      this.closeWs(sid, 1001, 'timeout')
      return
    }
    this.sendWsFrame(state, OPCODES.OP_PING, Buffer.alloc(0))
  }

  handleWsBytes(sid, chunk) {
    const state = this.ws.get(sid)
    if (!state) return
    state.lastSeen = Date.now()
    state.buffer = Buffer.concat([state.buffer, chunk])
    for (;;) {
      const parsed = parseFrame(state.buffer)
      if (!parsed) return
      state.buffer = parsed.rest
      const { frame } = parsed
      if (frame.opcode === OPCODES.OP_CLOSE) {
        this.closeWs(sid, 1000, 'peer-close')
        return
      }
      if (frame.opcode === OPCODES.OP_PING) {
        this.sendWsFrame(state, OPCODES.OP_PONG, frame.payload)
        continue
      }
      if (frame.opcode === OPCODES.OP_PONG) {
        state.pongAt = Date.now()
        continue
      }
      if (!isDataFrame(frame.opcode)) continue
      this.onPhoneMessage(state, frame.payload)
    }
  }

  onPhoneMessage(state, bytes) {
    let message
    try {
      const parsed = JSON.parse(bytes.toString('utf8'))
      if (!parsed || typeof parsed.__relay !== 'string') return
      const plain = this.cryptoBox.open(
        this.cryptoBox.envelopeKey, Buffer.from(parsed.__relay, 'base64'))
      if (!plain) {
        this.sendEvent(state.sid, { t: 'error', message: 'envelope open failed' })
        return
      }
      message = JSON.parse(plain.toString('utf8'))
    } catch {
      return
    }
    if (!message || typeof message.t !== 'string') return
    if (message.t === 'subscribe' && typeof message.sessionId === 'string') {
      state.sessionId = message.sessionId
      this.bridge?.subscribe?.(state.sid, state.sessionId, (event) => this.sendEvent(state.sid, event))
      return
    }
    if (message.t === 'unsubscribe') {
      this.bridge?.unsubscribe?.(state.sid)
      state.sessionId = null
      return
    }
    if (message.t === 'ping') {
      this.sendEvent(state.sid, { t: 'pong', time: Date.now() })
      return
    }
    this.bridge?.onPhoneMessage?.(state.sid, message)
  }

  sendEvent(sid, event) {
    const state = this.ws.get(sid)
    if (!state || state.closed) return
    const sealed = this.cryptoBox.seal(
      this.cryptoBox.envelopeKey, Buffer.from(JSON.stringify(event), 'utf8'))
    const payload = Buffer.from(JSON.stringify({ __relay: sealed.toString('base64') }))
    this.sendWsFrame(state, OPCODES.OP_TEXT, payload)
  }

  /** Broadcast to every open phone socket. */
  broadcast(event) {
    for (const sid of this.ws.keys()) this.sendEvent(sid, event)
  }

  sendWsFrame(state, opcode, payload) {
    if (state.closed) return
    state.pump.send(state.sid, buildFrame(opcode, payload, { mask: false }))
  }

  closeWs(sid, code = 1000, reason = '') {
    const state = this.ws.get(sid)
    if (!state) return
    state.closed = true
    clearInterval(state.timer)
    if (code !== 1000 || reason !== 'peer-close') {
      const payload = Buffer.alloc(2)
      payload.writeUInt16BE(code, 0)
      this.sendWsFrame(state, OPCODES.OP_CLOSE, payload)
    }
    this.ws.delete(sid)
    this.bridge?.unsubscribe?.(sid)
    this.bridge?.onPhoneClose?.({ sid })
    state.pump.closeStream(sid)
    this.log.info?.(`[relay-mobile] ws close sid=${sid} ${code} ${reason}`)
  }

  /** The phone's TCP stream vanished (relay close, network drop). */
  handleStreamGone(sid) {
    if (this.ws.has(sid)) this.closeWs(sid, 1001, 'stream-gone')
  }

  phoneCount() {
    return this.ws.size
  }
}

function escapeHtml(text) {
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

/** tweetnacl on disk, shared verbatim with the pairing page and boot injection. */
let naclFile
function naclPath() {
  if (naclFile !== undefined) return naclFile
  const candidates = [
    new URL('../../node_modules/tweetnacl/nacl-fast.min.js', import.meta.url),
    new URL('../../node_modules/tweetnacl/nacl.min.js', import.meta.url),
  ]
  for (const url of candidates) {
    try {
      fs.accessSync(fileURLToPath(url))
      naclFile = fileURLToPath(url)
      return naclFile
    } catch {}
  }
  naclFile = null
  return null
}
