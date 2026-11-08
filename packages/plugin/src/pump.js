// HTTP-aware pump with the full sealing layer.
//
// Each relay stream (one phone TCP connection) is one HTTP request/response or
// one WebSocket session against the loopback DSH. Routing after head parse:
//
//   /__relay/*            handled locally (pairing handshake, ping)
//   no valid ticket       bootstrap pairing page
//   x-relay-enc: 1        sealed round trip: request body envelope is opened,
//                         the whole upstream response is sealed back
//   document navigation   response buffered, boot <script> + mobile touch
//                         patch injected into <head>
//   websocket upgrade     permessage-deflate stripped; both directions are
//                         re-framed with payload sealed (see ws-codec)
//   anything else         plain byte replay (Host/Origin rewritten)
//
// Plain (unsealed) traffic remains for native script/link loads on the first
// visits — a documented residual risk of the no-TLS mode; see README.

import net from 'node:net'
import { buildPairingPage } from './pairing-page.js'
import { buildBootSource } from './boot-source.js'
import { MOBILE_CSS, MOBILE_JS, enhanceViewportMeta } from './mobile-patch.js'
import { BODY_LIMIT } from './pairing.js'
import { parseFrame, buildFrame, isDataFrame, OPCODES } from './ws-codec.js'
import { auditLog } from './identity.js'
import { MOBILE_RPC_PATH, MOBILE_WS_PATH } from './mobile/index.js'

const HEAD_LIMIT = 1024 * 1024
const RESPONSE_LIMIT = 64 * 1024 * 1024
// Keep-alive: a relay stream is one phone TCP connection, and over a mobile
// link every fresh connection costs a TLS handshake (2 RTT) plus the relay
// proxy's CONNECT. Serving successive requests on the stream the phone already
// has turns a ~50 request cold load from one handshake per asset into one per
// parallel slot. Idle connections are dropped after this long.
const KEEPALIVE_IDLE_MS = 45_000
const PENDING_LIMIT = 1024 * 1024
// Sealed bodies carry normal API JSON and base64 image attachments (prompts
// with a phone screenshot are easily several hundred KB; the old 256KB ceiling
// rejected them with a bare 400 before they ever reached DSH).
const SEALED_BODY_LIMIT = 32 * 1024 * 1024
const RPC_LIMIT = 32 * 1024 * 1024
const EMPTY = Buffer.alloc(0)
// Per-request tracing stays off unless explicitly requested: the pump sees
// every phone request, so unconditional logging floods the host console.
const DEBUG = process.env.DSH_RELAY_DEBUG === '1'

// Requests the phone's browser makes by itself (documents and their assets) can
// never be sealed, so they are the only plaintext traffic allowed through from a
// paired phone. Anything that can change state or return private data must carry
// a sealed envelope; otherwise the relay — which terminates TLS and sees the
// ticket — could replay a ticket and act as the user against the local DSH.
const PLAINTEXT_DOCUMENT = new RegExp(
  '^(?:' +
  '/|' + // index document
  '/index\\.html|' +
  '/favicon\\.ico|' +
  '/assets/[A-Za-z0-9._@/-]+|' + // built UI bundles
  '/plugins/[A-Za-z0-9._@/%-]*|' + // client bundle entry (/plugins/??pkg/file.js)
  // "open in app" menu icons: plain <img> loads, no extension, no session data
  '/open-in-app/icon/[A-Za-z0-9._-]+|' +
  '/[^?]*\\.(?:js|mjs|css|map|json|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf)' +
  ')$',
)

export class PumpManager {
  constructor(options) {
    this.dshPort = options.dshPort ?? 3080
    this.dshHost = options.dshHost ?? '127.0.0.1'
    // The owner computes the real loopback endpoint from its webServer
    // service (0.2 may bind an OS-assigned port) and mints the DSH browser
    // session cookie the upstream now requires. Both are lazy so the pump
    // can be constructed before the listener has bound.
    this.resolveTarget = options.resolveTarget ?? (() => ({
      host: this.dshHost,
      port: this.dshPort,
      authority: `${this.dshHost}:${this.dshPort}`,
      protocol: 'http:',
    }))
    this.resolveAuthCookie = options.resolveAuthCookie ?? (() => null)
    this.pairing = options.pairing // PairingService
    this.cryptoBox = options.cryptoBox
    this.client = options.client
    // Mobile app surface (purpose-built phone page + its local API). Optional:
    // without it the pump only replays the desktop DSH UI.
    this.mobile = options.mobile ?? null
    // Escape hatch for "replay the desktop UI over the relay": that UI talks to
    // /api/* in plaintext, so allowing it means the relay can act as the user.
    // Off by default; the phone page is the supported remote experience.
    this.allowDesktopPlaintext = options.allowDesktopPlaintext === true
      || process.env.DSH_RELAY_ALLOW_PLAINTEXT === '1'
    this.streams = new Map()
  }

  /** Snapshot the upstream endpoint for one request. */
  target() {
    const target = this.resolveTarget()
    const authority = target.authority ?? `${target.host}:${target.port}`
    return {
      host: target.host,
      port: target.port,
      authority,
      protocol: target.protocol ?? 'http:',
      origin: `${target.protocol ?? 'http:'}//${authority}`,
    }
  }

  setClient(client) {
    this.client = client
  }

  // -- inbound from relay ------------------------------------------------------
  handleStreamData(sid, chunk) {
    let stream = this.streams.get(sid)
    if (!stream) {
      stream = this.newStream()
      this.streams.set(sid, stream)
    }
    try {
      this.step(sid, stream, chunk)
    } catch (error) {
      console.error('[dsh-relay-phone] stream error', sid, error)
      auditLog(`stream-error sid=${sid} ${error.message}`)
      this.closeStream(sid)
    }
  }

  /** A stream is one phone connection; it may carry many sequential requests. */
  newStream() {
    return {
      phase: 'head',
      buffer: Buffer.alloc(0),
      pending: null,
      upstream: null,
      info: null,
      idle: null,
    }
  }

  /**
   * Serve the next request on a connection the phone kept open: drop the
   * upstream, return to head parsing, and replay any bytes that raced ahead of
   * the previous response's end.
   */
  recycle(sid, stream) {
    if (this.streams.get(sid) !== stream) return
    stream.phase = 'head'
    stream.info = null
    stream.upstream = null
    stream.respHead = null
    stream.streaming = false
    const pending = stream.pending ?? Buffer.alloc(0)
    stream.pending = null
    stream.buffer = pending
    this.armIdle(sid, stream)
    if (pending.length > 0) this.step(sid, stream, Buffer.alloc(0))
  }

  armIdle(sid, stream) {
    this.clearIdle(stream)
    stream.idle = setTimeout(() => {
      stream.idle = null
      this.closeStream(sid)
    }, KEEPALIVE_IDLE_MS)
    stream.idle.unref?.()
  }

  clearIdle(stream) {
    if (stream?.idle) {
      clearTimeout(stream.idle)
      stream.idle = null
    }
  }

  /** Bytes that arrived before we were ready for them (next pipelined request). */
  holdPending(stream, chunk) {
    if (!chunk || chunk.length === 0) return
    stream.pending = stream.pending ? Buffer.concat([stream.pending, chunk]) : Buffer.from(chunk)
    if (stream.pending.length > PENDING_LIMIT) throw new Error('pending request too large')
  }

  /**
   * Split the bytes that followed a request head into this request's body and
   * any pipelined bytes that belong to the *next* request on the same stream.
   * @returns the body bytes to forward upstream now.
   */
  splitBody(stream, rest, length) {
    const take = Math.min(Math.max(0, length), rest.length)
    stream.reqRemaining = Math.max(0, length) - take
    if (rest.length > take) this.holdPending(stream, rest.subarray(take))
    return rest.subarray(0, take)
  }

  /** Take at most the still-missing request body bytes; hold the rest aside. */
  capChunk(stream, chunk) {
    const remaining = stream.reqRemaining ?? 0
    if (remaining <= 0) {
      this.holdPending(stream, chunk)
      return EMPTY
    }
    if (chunk.length <= remaining) {
      stream.reqRemaining = remaining - chunk.length
      return chunk
    }
    stream.reqRemaining = 0
    this.holdPending(stream, chunk.subarray(remaining))
    return chunk.subarray(0, remaining)
  }

  step(sid, stream, chunk) {
    switch (stream.phase) {
      case 'head': {
        stream.buffer = Buffer.concat([stream.buffer, chunk])
        const idx = stream.buffer.indexOf('\r\n\r\n')
        if (idx === -1) {
          if (stream.buffer.length > HEAD_LIMIT) {
            this.respondInline(sid, 431, 'Request Header Fields Too Large')
            this.closeStream(sid)
          }
          return
        }
        this.clearIdle(stream)
        const headText = stream.buffer.subarray(0, idx).toString('latin1')
        const rest = stream.buffer.subarray(idx + 4)
        stream.buffer = Buffer.alloc(0)
        this.route(sid, stream, headText, rest)
        return
      }
      case 'local-body': {
        stream.buffer = Buffer.concat([stream.buffer, this.capChunk(stream, chunk)])
        this.maybeFinishLocal(sid, stream)
        return
      }
      case 'req-body': {
        stream.buffer = Buffer.concat([stream.buffer, this.capChunk(stream, chunk)])
        this.maybeFinishSealedRequest(sid, stream)
        return
      }
      case 'ws-up': {
        // Request head forwarded; waiting for more phone bytes is handled in
        // 'ws' once the upgrade completes. Bytes here go to the codec buffer.
        stream.wsPhoneBuf = Buffer.concat([stream.wsPhoneBuf ?? Buffer.alloc(0), chunk])
        this.pumpPhoneWs(sid, stream)
        return
      }
      case 'body': {
        const body = this.capChunk(stream, chunk)
        if (body.length === 0) return
        if (stream.upstream && !stream.upstream.destroyed) {
          if (stream.upstreamPending) {
            // Head not flushed yet — queue body bytes behind it so the
            // upstream never sees body-before-head reordering.
            stream.upstreamPending.push(body)
          } else {
            stream.upstream.write(body)
          }
        }
        return
      }
      case 'mobile-ws': {
        this.mobile?.handleWsBytes(sid, chunk)
        return
      }
      case 'mobile-rpc-pending': {
        // The bridge is still answering; bytes here belong to the next
        // request on a reused connection and must wait their turn.
        this.holdPending(stream, chunk)
        return
      }
      default:
        // resp-head / resp-buffer / req-body tail: the response of the current
        // request is still in flight, so the next request (rare) waits its turn.
        if (chunk.length > 0) this.holdPending(stream, chunk)
    }
  }

  handleStreamClose(sid) {
    const stream = this.streams.get(sid)
    if (!stream) return
    this.streams.delete(sid)
    this.clearIdle(stream)
    if (stream.upstream) {
      stream.upstream.removeAllListeners('data')
      try { stream.upstream.destroy() } catch {}
    }
    if (stream.mobile || this.mobile) this.mobile?.handleStreamGone?.(sid)
  }

  closeStream(sid) {
    this.handleStreamClose(sid)
    this.client?.closeStream(sid)
  }

  dispose() {
    for (const sid of [...this.streams.keys()]) this.handleStreamClose(sid)
  }

  /** Write raw bytes to the phone (mobile app push channel, inline replies). */
  send(sid, chunk) {
    this.client?.sendStream(sid, chunk)
  }

  setPhase(sid, stream, phase) {
    if (this.streams.get(sid) === stream) stream.phase = phase
  }

  /**
   * Seal a JSON reply for a mobile RPC call as a complete inner HTTP response,
   * mirroring the format the sealed DSH forwarding path uses (and the phone's
   * envelope opener already understands).
   */
  replySealed(sid, innerStatus, jsonBody) {
    const stream = this.streams.get(sid)
    if (!stream || stream.phase !== 'mobile-rpc-pending') return
    const reason = REASONS[innerStatus] ?? 'OK'
    const body = Buffer.from(String(jsonBody), 'utf8')
    const inner = Buffer.concat([
      Buffer.from(
        `HTTP/1.1 ${innerStatus} ${reason}\r\n`
        + 'content-type: application/json; charset=utf-8\r\n'
        + `content-length: ${body.length}\r\n\r\n`, 'latin1'),
      body,
    ])
    const sealed = this.cryptoBox.seal(this.cryptoBox.envelopeKey, inner)
    this.respond(sid, 200, 'application/octet-stream', sealed, { 'x-relay-enc': '1' }, { keepAlive: stream.keepAlive })
    this.finishResponse(sid, stream)
  }

  // -- routing -------------------------------------------------------------------
  route(sid, stream, headText, rest) {
    const info = parseHead(headText)
    if (!info) {
      if (DEBUG) console.log('[relay-dbg] 400@parsehead sid=%s head=%j', sid, headText.slice(0, 100))
      this.respondInline(sid, 400, 'Bad Request')
      this.closeStream(sid)
      return
    }
    stream.info = info
    // The phone's own connection can carry further requests after this one:
    // that is what saves a TLS handshake per asset on a mobile link.
    // DSH_RELAY_NO_KEEPALIVE=1 restores the old one-request-per-connection
    // behaviour (diagnostics, or a middlebox that mangles reused connections).
    stream.keepAlive = wantsKeepAlive(info) && process.env.DSH_RELAY_NO_KEEPALIVE !== '1'

    // The relay forwards the original request line: strip our /c/<id> prefix
    // and the g= gate param before doing anything else, and remember them for
    // HTML injection (asset rewrites + boot constants).
    const pm = info.path.match(/^\/c\/([A-Za-z0-9]{4,16})(\/.*)?$/)
    if (pm) {
      const { gate, cleanQuery } = stripGateParam(info.query)
      if (DEBUG) console.log('[relay-dbg] prefix route: path=%s query=%j gate=%s ok=%s',
        info.path, info.query.slice(0, 40), gate.slice(0, 8), /^[a-f0-9]{16,128}$/.test(gate))
      if (/^[a-f0-9]{16,128}$/.test(gate)) {
        stream.relay = { id: pm[1], gate }
      }
      const cleanPath = pm[2] || '/'
      const cleanTarget = cleanQuery === '' ? cleanPath : `${cleanPath}?${cleanQuery}`
      info.path = cleanPath
      info.query = cleanQuery
      info.target = cleanTarget
      info.requestLine = `${info.method} ${cleanTarget} ${info.version}`
      headText = `${info.requestLine}\r\n${info.rawHeaders.join('\r\n')}`
    }

    const sealed = info.headers.get('x-relay-enc') === '1'
    const isUpgrade = /^websocket$/i.test(info.headers.get('upgrade') ?? '')
    const session = this.pairing.sessionForHeaders(info.headers)

    // The mobile surface is served entirely by this plugin (page, assets, RPC,
    // sealed push channel). It still sits behind the same ticket gate: a phone
    // without a paired session gets the pairing page, never the app.
    if (this.mobile && this.mobile.handles(info.path)) {
      if (!session) {
        auditLog(`unauthenticated mobile ${info.method} ${info.path} -> pairing page`)
        this.respond(sid, 200, 'text/html; charset=utf-8',
          buildPairingPage(stream.relay?.id, stream.relay?.gate), {})
        this.closeStream(sid)
        return
      }
      this.routeMobile(sid, stream, info, rest, { sealed, isUpgrade })
      return
    }

    if (info.path.startsWith('/__relay/')) {
      stream.phase = 'local-body'
      stream.reqLength = Number(info.headers.get('content-length') ?? '0')
      stream.buffer = this.splitBody(stream, rest, stream.reqLength)
      this.maybeFinishLocal(sid, stream)
      return
    }

    // The plugin's own console is a desktop tool: it prints the pairing URL
    // (which carries the device PSK) and can change the relay key. A phone that
    // reached it would be able to pair unlimited extra devices, so relayed
    // requests never see it, ticketed or not.
    if (stream.relay && info.path.startsWith('/relay-bridge/')) {
      auditLog(`relayed request to the management panel blocked: ${info.path}`)
      this.respondInline(sid, 403, 'Forbidden', 'dsh-relay-phone: the management panel is desktop-only\n')
      this.closeStream(sid)
      return
    }

    if (!session) {
      auditLog(`unauthenticated ${info.method} ${info.path} -> pairing page`)
      this.respond(sid, 200, 'text/html; charset=utf-8',
        buildPairingPage(stream.relay?.id, stream.relay?.gate), {})
      this.closeStream(sid)
      return
    }

    if (info.path === '/api/x') {
      if (DEBUG) console.log('[relay-dbg] /api/x: sealed=%s ct=%s line=%s',
        sealed, info.headers.get('content-type'), info.requestLine.slice(0, 120))
    }
    // A paired phone that opens the old entry URL gets the phone-first page
    // instead of the three-column desktop UI; `?desktop=1` (or a desktop
    // browser) keeps the full interface.
    if (!sealed && !isUpgrade && info.path === '/'
      && stream.relay && isMobileUserAgent(info.headers)
      && !/(?:^|&)desktop=1(?:&|$)/.test(info.query)) {
      const location = `/c/${stream.relay.id}/m?g=${stream.relay.gate}`
      this.respond(sid, 302, 'text/plain; charset=utf-8', '', {
        location,
        'cache-control': 'no-store',
      }, { keepAlive: stream.keepAlive })
      this.finishResponse(sid, stream)
      return
    }
    const isDocument = info.headers.get('sec-fetch-dest') === 'document'
      || (/\btext\/html\b/.test(info.headers.get('accept') ?? '') && !sealed)

    if (sealed && !isUpgrade) {
      this.prepareSealedForward(sid, stream, info, headText, rest)
      return
    }

    // Anything unsealed past this point would be forwarded to the local DSH with
    // the host's own browser cookie attached. The relay sees the ticket and the
    // gate, so it could mint the same request itself: plaintext is limited to
    // the documents and assets a browser fetches on its own.
    if (!this.allowDesktopPlaintext && !this.isPlaintextDocument(info, isUpgrade)) {
      auditLog(`relayed plaintext ${info.method} ${info.path} refused (sealed only)`)
      this.respondInline(
        sid, 403, 'Forbidden',
        'dsh-relay-phone: only documents and static assets may travel unsealed.\n' +
        'The phone page seals everything it sends; if a desktop-UI request lands here, it bypassed the\n' +
        'boot patch. Set "allowDesktopPlaintext": true in the plugin config to accept that risk.\n',
      )
      this.closeStream(sid)
      return
    }
    this.plainForward(sid, stream, info, headText, rest, { isUpgrade, isDocument, relay: stream.relay })
  }

  /**
   * True for the GET/HEAD document + asset traffic a phone browser issues by
   * itself, and for WebSocket handshakes.
   *
   * A WebSocket handshake is an HTTP GET with an Upgrade header: there is no
   * body, so an envelope cannot ride along. Sealing happens per frame instead,
   * and `pumpPhoneWs` refuses any data frame that does not open — which is why
   * the handshake may pass while the payload stays mandatory-sealed. (DSH's own
   * event mux, `/api/remote.mux`, is such a WebSocket; blocking the handshake
   * broke the desktop UI with "Reconnecting".)
   */
  isPlaintextDocument(info, isUpgrade) {
    if (isUpgrade) return info.method === 'GET'
    if (info.method !== 'GET' && info.method !== 'HEAD') return false
    if (info.path.startsWith('/api/')) return false
    return PLAINTEXT_DOCUMENT.test(info.path)
  }

  /** Route one ticketed request that belongs to the mobile app surface. */
  routeMobile(sid, stream, info, rest, { sealed, isUpgrade }) {
    if (isUpgrade) {
      if (!this.mobile.handlesUpgrade(info.path)) {
        this.respondInline(sid, 426, 'Upgrade Required')
        this.closeStream(sid)
        return
      }
      this.mobile.openUpgrade(sid, stream, info, this)
      return
    }
    if (info.path === MOBILE_RPC_PATH) {
      // API calls must be sealed: the phone's own UI is the only legitimate
      // caller and it always has the PSK.
      if (!sealed) {
        this.respondInline(sid, 400, 'Bad Request', 'sealed requests only\n')
        this.closeStream(sid)
        return
      }
      this.prepareMobileRpc(sid, stream, info, rest)
      return
    }
    if (info.path === MOBILE_WS_PATH) {
      this.respondInline(sid, 426, 'Upgrade Required', 'websocket only\n')
      this.closeStream(sid)
      return
    }
    const result = this.mobile.pageResponse(info.path, {
      method: info.method, headers: info.headers, relay: stream.relay,
    })
    const body = info.method === 'HEAD' ? '' : result.body
    this.respond(sid, result.status, result.contentType, body, result.headers ?? {}, { keepAlive: stream.keepAlive })
    this.finishResponse(sid, stream)
  }

  /** Collect one sealed mobile RPC body, then hand it to the bridge. */
  prepareMobileRpc(sid, stream, info, rest) {
    const length = Number(info.headers.get('content-length') ?? '0')
    if (!Number.isFinite(length) || length < 0 || length > RPC_LIMIT) {
      this.respondInline(sid, 400, 'Bad Request', 'bad rpc body size\n')
      this.closeStream(sid)
      return
    }
    stream.phase = 'req-body'
    stream.reqLength = length
    stream.buffer = this.splitBody(stream, rest, length)
    this.maybeFinishSealedRequest(sid, stream)
  }

  maybeFinishLocal(sid, stream) {
    const info = stream.info
    const length = Number(info.headers.get('content-length') ?? '0')
    if (!Number.isFinite(length) || length < 0 || length > BODY_LIMIT) {
      this.respond(sid, 400, 'text/plain; charset=utf-8', 'bad content-length\n')
      this.closeStream(sid)
      return
    }
    if (stream.buffer.length < length) return
    const body = stream.buffer.subarray(0, length)
    const result = this.pairing.handle(info.path, info.method, info.headers, body)
    if (!result) {
      this.respond(sid, 404, 'text/plain; charset=utf-8', 'unknown relay endpoint\n', {}, { keepAlive: stream.keepAlive })
    } else {
      this.respond(sid, result.status, result.contentType, result.body, result.headers ?? {}, { keepAlive: stream.keepAlive })
    }
    this.finishResponse(sid, stream)
  }

  /** End a response: keep the phone's connection for the next request or drop it. */
  finishResponse(sid, stream) {
    if (stream.keepAlive) this.recycle(sid, stream)
    else this.closeStream(sid)
  }

  // -- sealed round trips ----------------------------------------------------------
  prepareSealedForward(sid, stream, info, headText, rest) {
    const length = Number(info.headers.get('content-length') ?? '0')
    if (!Number.isFinite(length) || length < 0 || length > SEALED_BODY_LIMIT) {
      if (DEBUG) console.log('[relay-dbg] 400@prepare sid=%s len=%s ct=%s', sid, length, info.headers.get('content-type'))
      this.respondInline(sid, 400, 'Bad Request')
      this.closeStream(sid)
      return
    }
    stream.phase = 'req-body'
    stream.reqLength = length
    stream.buffer = this.splitBody(stream, rest, length)
    this.maybeFinishSealedRequest(sid, stream)
  }

  maybeFinishSealedRequest(sid, stream) {
    if (stream.buffer.length < stream.reqLength) return
    const sealedBody = stream.buffer.subarray(0, stream.reqLength)
    let plain = Buffer.alloc(0)
    if (stream.reqLength > 0) {
      plain = this.cryptoBox.open(this.cryptoBox.envelopeKey, sealedBody)
      if (!plain) {
        auditLog(`sealed request body failed to open (${stream.info.path})`)
        if (DEBUG) console.log('[relay-dbg] 400@open sid=%s path=%s len=%s bodyHead=%s', sid, stream.info.path, stream.reqLength, sealedBody.subarray(0, 16).toString('hex'))
        this.respondInline(sid, 400, 'Bad Request')
        this.closeStream(sid)
        return
      }
    }
    const info = stream.info
    // A sealed call to the mobile app's own API is answered here, not proxied
    // to DSH: the mobile bridge talks to host services directly.
    if (this.mobile && info.path === MOBILE_RPC_PATH) {
      stream.phase = 'mobile-rpc-pending'
      Promise.resolve()
        .then(() => this.mobile.rpc(sid, plain, this))
        .catch((error) => {
          if (DEBUG) console.log('[relay-mobile] rpc failed sid=%s %s', sid, error?.message ?? error)
          this.replySealed(sid, 500, JSON.stringify({ ok: false, error: { code: 'internal', message: 'rpc failed' } }))
        })
      return
    }
    const target = this.target()
    const authCookie = this.resolveAuthCookie()
    const headers = []
    for (const line of info.rawHeaders) {
      const lower = line.toLowerCase()
      if (lower.startsWith('host:')) continue
      if (lower.startsWith('origin:')) continue
      if (lower.startsWith('cookie:')) continue
      if (lower.startsWith('content-length:')) continue
      if (lower.startsWith('content-type:')) continue
      if (lower.startsWith('connection:')) continue
      if (lower.startsWith('accept-encoding:')) continue
      if (lower.startsWith('x-relay-enc:') || lower.startsWith('x-relay-ct:')) continue
      if (lower.startsWith('x-dsh-relay:')) continue // the pump sets its own
      headers.push(line)
    }
    headers.unshift(`Host: ${target.authority}`)
    headers.unshift(`Origin: ${target.origin}`)
    headers.push('x-dsh-relay: 1')
    if (authCookie) headers.push(`Cookie: ${authCookie}`)
    headers.push(`Content-Type: ${info.headers.get('x-relay-ct') ?? 'text/plain;charset=UTF-8'}`)
    headers.push(`Content-Length: ${plain.length}`)
    headers.push('Connection: close')
    const head = `${info.requestLine}\r\n${headers.join('\r\n')}\r\n\r\n`
    this.bufferedForward(sid, stream, Buffer.from(head, 'latin1'), plain, { sealResponse: true, target })
  }

  bufferedForward(sid, stream, headBuffer, bodyBuffer, { sealResponse, injectBoot, target }) {
    const upstream = net.connect({ host: target.host, port: target.port })
    stream.upstream = upstream
    stream.phase = 'resp-buffer'
    stream.respBuffer = Buffer.alloc(0)
    stream.sealResponse = !!sealResponse
    stream.injectBoot = !!injectBoot
    upstream.setNoDelay(true)
    upstream.on('connect', () => {
      upstream.write(headBuffer)
      if (bodyBuffer.length > 0) upstream.write(bodyBuffer)
    })
    upstream.on('data', (data) => {
      stream.respBuffer = Buffer.concat([stream.respBuffer, data])
      if (stream.respBuffer.length > RESPONSE_LIMIT) {
        this.respondInline(sid, 502, 'Bad Gateway', 'response too large')
        this.closeStream(sid)
      }
    })
    upstream.on('close', () => {
      if (this.streams.get(sid)?.upstream !== upstream) return
      stream.upstream = null
      let out = normalizeResponse(stream.respBuffer)
      // Documents are the only relayed requests a browser navigates to, so a
      // status here explains "the desktop UI is blank" reports: a 401/302 means
      // the host did not accept the session the pump injected.
      if (stream.relay && stream.injectBoot) {
        const status = out.toString('latin1').split('\r\n', 1)[0]
        auditLog(`document ${status} cookie=${this.resolveAuthCookie() ? 'yes' : 'no'} path=${stream.info?.path ?? '?'}`)
      }
      if (stream.sealResponse) {
        out = this.cryptoBox.seal(this.cryptoBox.envelopeKey, out)
        this.respond(sid, 200, 'application/octet-stream', out, { 'x-relay-enc': '1' }, { keepAlive: stream.keepAlive })
      } else if (stream.injectBoot && /^HTTP\/[\d.]+\s+200/.test(out.toString('latin1').slice(0, 32))) {
        const injected = injectBootScript(out, stream.relay, { keepAlive: stream.keepAlive })
        this.client?.sendStream(sid, injected)
      } else {
        const rewritten = rewriteBufferedResponse(out, stream.keepAlive)
        stream.keepAlive = rewritten.keepAlive
        this.client?.sendStream(sid, rewritten.buffer)
      }
      this.finishResponse(sid, stream)
    })
    upstream.on('error', () => {
      if (this.streams.get(sid)?.upstream === upstream) {
        this.streams.delete(sid)
        this.clearIdle(stream)
        this.respondInline(sid, 502, 'Bad Gateway', 'dsh-relay-phone: upstream failed')
        this.client?.closeStream(sid)
      }
    })
  }

  // -- plain forwarding + upgrades ---------------------------------------------------
  plainForward(sid, stream, info, headText, rest, { isUpgrade, isDocument }) {
    const target = this.target()
    const authCookie = this.resolveAuthCookie()
    const lines = headText.split('\r\n')
    let hasHost = false
    let hasConnection = false
    const rewritten = []
    for (let i = 1; i < lines.length; i += 1) {
      const line = lines[i]
      if (/^host:/i.test(line)) {
        rewritten.push(`Host: ${target.authority}`)
        hasHost = true
      } else if (/^origin:/i.test(line)) {
        rewritten.push(`Origin: ${target.origin}`)
      } else if (/^x-dsh-relay:/i.test(line)) {
        // Dropped: the pump adds its own marker below.
      } else if (/^cookie:/i.test(line)) {
        // The phone's relay ticket authenticates it to the pump, not to DSH;
        // upstream speaks the browser-session credential instead.
        continue
      } else if (/^sec-websocket-extensions:/i.test(line) && isUpgrade) {
        // Keep frame payloads raw so the codec can seal them.
        continue
      } else if (/^connection:/i.test(line) && !isUpgrade) {
        rewritten.push('Connection: close')
        hasConnection = true
      } else if (/^accept-encoding:/i.test(line) && isDocument) {
        continue // inject into uncompressed HTML only
      } else {
        rewritten.push(line)
      }
    }
    if (!hasHost) rewritten.unshift(`Host: ${target.authority}`)
    if (!isUpgrade && !hasConnection) rewritten.push('Connection: close')
    // Mark the request as relayed. The plugin's own console uses this to refuse
    // phone-side access: it hands out pairing links, which embed the device PSK.
    // Any inbound copy was dropped in the loop above, so a client cannot forge it.
    rewritten.push('x-dsh-relay: 1')
    if (authCookie) rewritten.push(`Cookie: ${authCookie}`)
    const out = `${lines[0]}\r\n${rewritten.join('\r\n')}\r\n\r\n`

    if (isUpgrade) {
      const upstream = net.connect({ host: target.host, port: target.port })
      stream.upstream = upstream
      stream.phase = 'ws-up'
      stream.wsPhoneBuf = rest
      stream.wsServerBuf = Buffer.alloc(0)
      stream.wsFragment = null
      stream.wsHandshakeDone = false // the 101 head passes through raw first
      upstream.setNoDelay(true)
      upstream.on('connect', () => {
        upstream.write(out)
        this.pumpPhoneWs(sid, stream)
      })
      upstream.on('data', (data) => {
        stream.wsServerBuf = Buffer.concat([stream.wsServerBuf, data])
        if (!stream.wsHandshakeDone) {
          const idx = stream.wsServerBuf.indexOf('\r\n\r\n')
          if (idx === -1) {
            if (stream.wsServerBuf.length > HEAD_LIMIT) this.closeStream(sid)
            return
          }
          this.client?.sendStream(sid, stream.wsServerBuf.subarray(0, idx + 4))
          stream.wsServerBuf = stream.wsServerBuf.subarray(idx + 4)
          stream.wsHandshakeDone = true
        }
        this.pumpServerWs(sid, stream)
      })
      const gone = () => this.closeStream(sid)
      upstream.on('close', gone)
      upstream.on('error', gone)
      return
    }

    if (isDocument) {
      // Buffer the whole document so the boot script can be injected.
      const body = this.splitBody(stream, rest, Number(info.headers.get('content-length') ?? '0'))
      this.bufferedForward(sid, stream, Buffer.from(out, 'latin1'), body, { injectBoot: true, target })
      return
    }

    // Plain passthrough (native asset loads in no-TLS mode). The upstream is
    // opened per request (loopback, so it is nearly free) while the phone's
    // connection is reused: the response head is rewritten so the browser sees
    // a keep-alive message and can send its next request on the same socket.
    const body = this.splitBody(stream, rest, Number(info.headers.get('content-length') ?? '0'))
    const upstream = net.connect({ host: target.host, port: target.port })
    stream.upstream = upstream
    stream.phase = 'body'
    stream.respHead = Buffer.alloc(0)
    stream.streaming = false
    stream.upstreamPending = [] // body frames that raced ahead of the head
    upstream.setNoDelay(true)
    upstream.on('connect', () => {
      upstream.write(out)
      if (body.length > 0) upstream.write(body)
      for (const chunk of stream.upstreamPending) upstream.write(chunk)
      stream.upstreamPending = null
    })
    upstream.on('data', (data) => {
      if (stream.streaming) {
        this.client?.sendStream(sid, data)
        return
      }
      stream.respHead = Buffer.concat([stream.respHead, data])
      const idx = stream.respHead.indexOf('\r\n\r\n')
      if (idx === -1) {
        if (stream.respHead.length > HEAD_LIMIT) {
          this.respondInline(sid, 502, 'Bad Gateway', 'response head too large')
          this.closeStream(sid)
        }
        return
      }
      const head = stream.respHead.subarray(0, idx).toString('latin1')
      const body = stream.respHead.subarray(idx + 4)
      const framed = rewriteResponseHead(head, stream.keepAlive)
      if (framed.downgrade) {
        // Framing could not survive keep-alive: fall back to closing after it.
        stream.keepAlive = false
      }
      this.client?.sendStream(sid, Buffer.from(`${framed.text}\r\n\r\n`, 'latin1'))
      if (body.length > 0) this.client?.sendStream(sid, body)
      stream.streaming = true
      stream.respHead = null
    })
    const gone = (hadError) => {
      if (this.streams.get(sid)?.upstream !== upstream) return
      stream.upstream = null
      if (!hadError && stream.streaming && stream.keepAlive) {
        this.recycle(sid, stream)
        return
      }
      this.streams.delete(sid)
      this.clearIdle(stream)
      this.client?.closeStream(sid)
      if (hadError) this.respondInline(sid, 502, 'Bad Gateway', 'dsh-relay-phone: upstream failed')
    }
    upstream.on('close', () => gone(false))
    upstream.on('error', () => gone(true))
  }

  // -- websocket sealing ---------------------------------------------------------------
  pumpPhoneWs(sid, stream) {
    if (!stream.upstream || stream.upstream.destroyed) return
    for (;;) {
      const parsed = parseFrame(stream.wsPhoneBuf)
      if (!parsed) return
      stream.wsPhoneBuf = parsed.rest
      const { frame } = parsed
      let out
      if (isDataFrame(frame.opcode)) {
        let plain = null
        try {
          const json = JSON.parse(frame.payload.toString('utf8'))
          if (json && typeof json.__relay === 'string') {
            plain = this.cryptoBox.open(this.cryptoBox.envelopeKey, Buffer.from(json.__relay, 'base64'))
          }
        } catch {}
        if (!plain) {
          // Only the explicit "desktop UI over the relay" mode may pass an
          // unsealed frame upstream; otherwise a failure here is an attack on the
          // sealed channel, not a legacy client.
          if (!this.allowDesktopPlaintext) {
            auditLog('sealed websocket frame could not be opened; closing the stream')
            this.closeStream(sid)
            return
          }
          plain = frame.payload
        }
        // DSH 0.2's API gateway closes a binary frame with 1003 ("text
        // messages required"). The boot patch always sends JSON text, so
        // re-frame the decrypted payload as text upstream.
        out = buildFrame(OPCODES.OP_TEXT, plain, { mask: true })
      } else {
        out = buildFrame(frame.opcode, frame.payload, { mask: true, fin: frame.fin })
      }
      stream.upstream.write(out)
    }
  }

  pumpServerWs(sid, stream) {
    for (;;) {
      const parsed = parseFrame(stream.wsServerBuf)
      if (!parsed) return
      stream.wsServerBuf = parsed.rest
      const { frame } = parsed

      if (isDataFrame(frame.opcode)) {
        // Reassemble fragments before sealing.
        if (!frame.fin) {
          stream.wsFragment = {
            opcode: frame.opcode,
            payload: Buffer.from(frame.payload),
          }
          continue
        }
        const payload = stream.wsFragment
          ? Buffer.concat([stream.wsFragment.payload, frame.payload])
          : frame.payload
        stream.wsFragment = null
        const sealed = this.cryptoBox.seal(this.cryptoBox.envelopeKey, payload)
        const json = Buffer.from(JSON.stringify({ __relay: sealed.toString('base64') }))
        this.client?.sendStream(sid, buildFrame(OPCODES.OP_TEXT, json, { mask: false }))
        continue
      }

      // Control frames pass through untouched (re-framed unmasked).
      this.client?.sendStream(sid, buildFrame(frame.opcode, frame.payload, { mask: false, fin: frame.fin }))
    }
  }

  // -- inline responses -----------------------------------------------------------------
  respond(sid, status, contentType, body, headers = {}, { keepAlive = false } = {}) {
    const reason = REASONS[status] ?? 'OK'
    const extra = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n')
    const head =
      `HTTP/1.1 ${status} ${reason}\r\n` +
      `content-type: ${contentType}\r\n` +
      `content-length: ${Buffer.byteLength(body)}\r\n` +
      `connection: ${keepAlive ? 'keep-alive' : 'close'}\r\n` +
      `cache-control: no-store\r\n` +
      (extra ? `${extra}\r\n` : '') +
      `\r\n`
    this.client?.sendStream(sid, Buffer.concat([Buffer.from(head, 'latin1'), Buffer.from(body)]))
  }

  respondInline(sid, status, reason, body = '') {
    const text = `HTTP/1.1 ${status} ${reason}\r\nconnection: close\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: ${Buffer.byteLength(body)}\r\n\r\n${body}`
    this.client?.sendStream(sid, Buffer.from(text))
  }
}

/**
 * Whether the phone asked to keep its connection open after this request.
 * @param info - parsed request head.
 * @returns true when HTTP/1.1 without an explicit `Connection: close`.
 */
function wantsKeepAlive(info) {
  if (info.version !== 'HTTP/1.1') return false
  const tokens = String(info.headers.get('connection') ?? '').toLowerCase().split(',')
  return !tokens.some((token) => token.trim() === 'close')
}

/** Phone-class browsers (the relay's primary client) — iPadOS reports as Mac. */
function isMobileUserAgent(headers) {
  const ua = String(headers?.get?.('user-agent') ?? '')
  if (!ua) return false
  if (/Android|iPhone|iPod|Mobile|HarmonyOS|MiuiBrowser|MicroMessenger|WeChat/i.test(ua)) return true
  // iPadOS 13+ masquerades as desktop Safari, but is touch-only.
  return /Macintosh/.test(ua) && /Mobile\//.test(ua)
}

/**
 * Rewrite an upstream response head for a kept-alive phone connection.
 * The upstream is always asked for `Connection: close` (one short-lived socket
 * per request), so its head must not tell the browser to drop the connection.
 * A response is only reusable when the browser can delimit it by itself.
 * @param head - response head text without the trailing blank line.
 * @param keepAlive - whether the phone connection should be reused.
 * @returns the head to send and whether the connection must close instead.
 */
function rewriteResponseHead(head, keepAlive) {
  const lines = head.split('\r\n')
  const status = Number((lines[0] ?? '').split(' ')[1] ?? '200')
  const selfDelimited = status === 204 || status === 304
    || /^content-length:/im.test(head)
    || /^transfer-encoding:\s*chunked/im.test(head)
  const keep = keepAlive && selfDelimited
  const out = lines.filter((line) => !/^connection:/i.test(line))
  out.push(`Connection: ${keep ? 'keep-alive' : 'close'}`)
  return { text: out.join('\r\n'), downgrade: keepAlive && !keep }
}

/** Apply {@link rewriteResponseHead} to a completely buffered response. */
function rewriteBufferedResponse(buffer, keepAlive) {
  const split = buffer.indexOf('\r\n\r\n')
  if (split === -1) return { buffer, keepAlive: false }
  const head = buffer.subarray(0, split).toString('latin1')
  const body = buffer.subarray(split + 4)
  const framed = rewriteResponseHead(head, keepAlive)
  return {
    buffer: Buffer.concat([Buffer.from(`${framed.text}\r\n\r\n`, 'latin1'), body]),
    keepAlive: keepAlive && !framed.downgrade,
  }
}

// Normalize a buffered HTTP response: decode chunked bodies back to raw
// bytes and restate the length, so sealed/injected consumers never see
// transfer framing.
function normalizeResponse(responseBuffer) {  const split = responseBuffer.indexOf('\r\n\r\n')
  if (split === -1) return responseBuffer
  const headText = responseBuffer.subarray(0, split).toString('latin1')
  if (!/^transfer-encoding:\s*chunked/im.test(headText)) return responseBuffer
  let rest = responseBuffer.subarray(split + 4)
  const chunks = []
  for (;;) {
    const line = rest.indexOf('\r\n')
    if (line === -1) break
    const size = parseInt(rest.subarray(0, line).toString('latin1').split(';')[0].trim(), 16)
    if (!Number.isFinite(size)) break
    rest = rest.subarray(line + 2)
    if (size === 0) break
    chunks.push(rest.subarray(0, size))
    rest = rest.subarray(size + 2)
  }
  const body = Buffer.concat(chunks)
  const head = headText
    .split('\r\n')
    .filter((line) => !/^transfer-encoding:/i.test(line) && !/^content-length:/i.test(line))
    .join('\r\n')
  return Buffer.concat([
    Buffer.from(`${head}\r\ncontent-length: ${body.length}\r\n\r\n`, 'latin1'),
    body,
  ])
}

// Inject the boot script right after <head...> (or prepend to the document)
// and rewrite root-absolute asset URLs (src/href) so they stay under the
// /c/<id> prefix with the gate attached. The response head is rewritten too:
// the upstream length is dropped (the body grew) and restated from the final
// bytes, so the message stays self-delimiting for keep-alive. The mobile
// enhancement (viewport meta + touch CSS + drawer JS) rides along in the same
// insertion. Exported for tests.
export function injectBootScript(responseBuffer, relay, { keepAlive = false } = {}) {
  const boot = relay
    ? `\n<script>${buildBootSource(relay.id, relay.gate)}</script>\n`
    : `\n<script>${buildBootSource()}</script>\n`
  const mobile = `\n<style id="__dshr_mobile">${MOBILE_CSS}</style>\n` +
    `\n<script>${MOBILE_JS}</script>\n`
  const text = responseBuffer.toString('latin1')
  const split = text.indexOf('\r\n\r\n')
  if (split === -1) return Buffer.concat([Buffer.from(boot + mobile, 'latin1'), responseBuffer])
  let head = text.slice(0, split)
  let body = text.slice(split + 4)
  head = head
    .split('\r\n')
    .filter((line) => !/^content-length:/i.test(line) && !/^transfer-encoding:/i.test(line) && !/^connection:/i.test(line))
    .join('\r\n')

  if (relay) {
    body = rewriteAssetUrls(body, relay)
  }
  body = stripManifestLink(body)
  body = enhanceViewportMeta(body)

  const bodyHeadOpen = body.search(/<head[^>]*>/i)
  const insertAt = bodyHeadOpen !== -1 ? body.indexOf('>', bodyHeadOpen) + 1 : 0
  const payload = boot + mobile
  const newBody = insertAt === 0
    ? payload + body
    : body.slice(0, insertAt) + payload + body.slice(insertAt)
  const length = Buffer.byteLength(newBody, 'latin1')
  head += `\r\nContent-Length: ${length}\r\nConnection: ${keepAlive ? 'keep-alive' : 'close'}`
  return Buffer.from(`${head}\r\n\r\n${newBody}`, 'latin1')
}

// Drop <link rel="manifest">: the browser's manifest fetch omits cookies, so
// through the relay it would fail the ticket gate and parse the pairing page
// as JSON ("Manifest: syntax error"). A PWA manifest is meaningless on the
// relayed origin anyway.
function stripManifestLink(html) {
  return html.replace(/<link\b[^>]*\brel=(["'])manifest\1[^>]*>\s*/gi, '')
}

// Root-absolute src/href="/x" → "/c/<id>/x?g=<gate>" so browser-native loads
// (script/link/img) stay routable through the relay.
function rewriteAssetUrls(html, relay) {
  const prefix = `/c/${relay.id}`
  return html.replace(
    // Root-absolute and document-relative ("./assets/x", "plugins/??...")
    // references alike: DSH 0.2 addresses its boot combos document-relatively
    // and a bare relative request would reach the relay without the gate. Skip
    // schemes, protocol-relative, fragments, and query-only references.
    /(\s(?:src|href)\s*=\s*)(["'])((?!\/\/|[a-z][a-z0-9+.-]*:|#|\?)[^"']*)\2/gi,
    (whole, attrName, quote, rest) => {
      if (!rest || /^#/.test(rest)) return whole
      const hashSplit = rest.split('#')
      const pathAndQuery = hashSplit[0] || ''
      const hash = hashSplit.length > 1 ? `#${hashSplit.slice(1).join('#')}` : ''
      const q = pathAndQuery.indexOf('?')
      const rawPath = q === -1 ? pathAndQuery : pathAndQuery.slice(0, q)
      const pathPart = rawPath.startsWith('./') ? rawPath.slice(2) : rawPath
      if (!pathPart || pathPart.startsWith('../') || pathPart.startsWith('/c/')) return whole
      const existing = q === -1 ? '' : pathAndQuery.slice(q + 1)
      const hasGate = /(?:^|&)g=/.test(existing)
      const query = hasGate ? existing : (existing === '' ? `g=${relay.gate}` : `${existing}&g=${relay.gate}`)
      const target = `${prefix}${pathPart.startsWith('/') ? pathPart : `/${pathPart}`}`
      return `${attrName}${quote}${target}${query ? `?${query}` : ''}${hash}${quote}`
    },
  )
}

/**
 * Split the relay gate out of a raw query string without re-encoding the
 * remaining bytes. DSH 0.2's boot graph addresses plugin combos as
 * `plugins/??pkg/client.js&rev=...`: URLSearchParams would turn that into an
 * unrelated `%3F%3F...` query, so only the literal `g=` segment is removed.
 * @param query - raw query text, without the leading `?`.
 * @returns the gate value ('' when absent) and the remaining raw query.
 */
export function stripGateParam(query) {
  const gate = new URLSearchParams(query).get('g') ?? ''
  const cleanQuery = query
    .split('&')
    .filter((part) => !/^g=/.test(part))
    .join('&')
  return { gate, cleanQuery }
}

const REASONS = {
  200: 'OK', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
  404: 'Not Found', 431: 'Request Header Fields Too Large', 502: 'Bad Gateway',
}

function parseHead(headText) {
  const lines = headText.split('\r\n')
  const requestLine = lines[0] ?? ''
  const sp = requestLine.indexOf(' ')
  const sp2 = requestLine.indexOf(' ', sp + 1)
  if (sp <= 0 || sp2 <= sp) return null
  const method = requestLine.slice(0, sp)
  const target = requestLine.slice(sp + 1, sp2)
  const version = requestLine.slice(sp2 + 1)
  const q = target.indexOf('?')
  const path = q === -1 ? target : target.slice(0, q)
  const query = q === -1 ? '' : target.slice(q + 1)
  const headers = new Map()
  for (let i = 1; i < lines.length; i += 1) {
    const colon = lines[i].indexOf(':')
    if (colon <= 0) continue
    headers.set(lines[i].slice(0, colon).trim().toLowerCase(), lines[i].slice(colon + 1).trim())
  }
  return { method, path, query, target, version, requestLine, headers, rawHeaders: lines.slice(1) }
}
