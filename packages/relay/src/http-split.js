// Split a phone connection's byte stream into HTTP requests.
//
// The relay binds a stream to one tenant at its first request line and then pipes
// bytes. A reverse proxy that pools upstream connections, or a hostile agent that
// keeps its socket open, could otherwise deliver the *next* request on that socket
// to the previous tenant's agent. Rewriting each request to `Connection: close`
// stops honest clients from reusing the socket; this scanner is what stops a
// malicious peer, because the relay decides where a request ends and refuses one
// that names another tenant before a single byte of it is forwarded.
//
// It is a security boundary, so every state it cannot frame is a refusal, never a
// pass-through: a parser that goes blind on malformed input is exactly what an
// attacker would reach for.
//
// An upgrade is the one case where the relay must stop looking - but only after
// the agent actually answered `101`. Until then the socket is still an ordinary
// HTTP connection, and a request arriving on it is checked like any other.

const MAX_HEAD = 64 * 1024
const CRLFCRLF = Buffer.from('\r\n\r\n', 'latin1')

const refused = (reason) => ({ forward: Buffer.alloc(0), refused: reason, head: null })

export class RequestScanner {
  constructor() {
    // head | body | chunk-size | chunk-data | chunk-data-end | await-switch | tunnel
    this.mode = 'head'
    this.head = Buffer.alloc(0)
    this.remaining = 0
    this.held = Buffer.alloc(0)
  }

  /**
   * Prime the scanner with the head the relay already routed, so the following
   * bytes are framed as that request's body.
   * @param {Buffer} head without the trailing CRLFCRLF
   * @returns {string|null} a refusal reason when the head cannot be framed
   */
  startWith(head) {
    return this.#startBody(Buffer.from(head))
  }

  /** The agent answered 101: from here the socket carries frames, not requests. */
  allowTunnel() {
    if (this.mode === 'await-switch') this.mode = 'tunnel'
  }

  /** True while this stream is an upgrade that has not switched yet. */
  get awaitingSwitch() {
    return this.mode === 'await-switch'
  }

  /**
   * Feed raw bytes from the phone.
   * @param {Buffer} chunk
   * @param {(head: Buffer) => (string|null)} accept returns a refusal reason, or
   *   null to let the request through. Called for every subsequent request.
   * @returns {{ forward: Buffer, refused: string|null }}
   */
  feed(chunk, accept) {
    const out = []
    let offset = 0
    while (offset < chunk.length) {
      if (this.mode === 'tunnel') {
        out.push(chunk.subarray(offset))
        break
      }
      if (this.mode === 'await-switch') {
        // After an upgrade request the client must wait for 101. Bytes here mean
        // either a client that ignores that, or a second request being smuggled
        // in - and the relay cannot tell which, so it stops.
        return { forward: Buffer.concat(out), refused: 'data before the upgrade switch', head: null }
      }
      if (this.mode === 'body') {
        const take = Math.min(this.remaining, chunk.length - offset)
        out.push(chunk.subarray(offset, offset + take))
        offset += take
        this.remaining -= take
        if (this.remaining === 0) this.mode = 'head'
        continue
      }
      if (this.mode === 'chunk-data') {
        const take = Math.min(this.remaining, chunk.length - offset)
        out.push(chunk.subarray(offset, offset + take))
        offset += take
        this.remaining -= take
        if (this.remaining === 0) this.mode = 'chunk-data-end'
        continue
      }
      if (this.mode === 'chunk-data-end') {
        // The CRLF that closes a chunk's data may itself be split across packets.
        const need = 2 - this.held.length
        const take = Math.min(need, chunk.length - offset)
        this.held = Buffer.concat([this.held, chunk.subarray(offset, offset + take)])
        offset += take
        if (this.held.length < 2) continue
        const pair = this.held
        this.held = Buffer.alloc(0)
        if (pair[0] !== 0x0d || pair[1] !== 0x0a) {
          return { forward: Buffer.concat(out), refused: 'malformed chunk terminator', head: null }
        }
        out.push(pair)
        this.mode = 'chunk-size'
        continue
      }
      if (this.mode === 'chunk-size') {
        const end = chunk.indexOf('\r\n', offset)
        if (end === -1) {
          this.held = Buffer.concat([this.held, chunk.subarray(offset)])
          if (this.held.length > MAX_HEAD) {
            return { forward: Buffer.concat(out), refused: 'chunk header too long', head: null }
          }
          offset = chunk.length
          continue
        }
        const line = Buffer.concat([this.held, chunk.subarray(offset, end)])
        const head = Buffer.concat([this.held, chunk.subarray(offset, end + 2)])
        this.held = Buffer.alloc(0)
        // Strict hex only: `parseInt` accepts `0x10`, `0xyz` and `-0`, and any
        // disagreement with the upstream parser is a smuggling primitive. The
        // bytes are forwarded only after the size line proved valid.
        const token = line.toString('latin1').split(';')[0].trim()
        if (!/^[0-9a-fA-F]{1,12}$/.test(token)) {
          return { forward: Buffer.concat(out), refused: 'malformed chunk size', head: null }
        }
        out.push(head)
        const size = Number.parseInt(token, 16)
        offset = end + 2
        if (size === 0) {
          // The last chunk is followed by optional trailers and then a blank
          // line. The trailer state consumes those lines one by one; taking a
          // shortcut here (consuming one line and going back to `head`) let a
          // crafted trailer line be parsed as the next request.
          this.mode = 'trailer'
        } else {
          this.remaining = size
          this.mode = 'chunk-data'
        }
        continue
      }
      if (this.mode === 'trailer') {
        const end = chunk.indexOf('\r\n', offset)
        if (end === -1) {
          this.held = Buffer.concat([this.held, chunk.subarray(offset)])
          if (this.held.length > MAX_HEAD) {
            return { forward: Buffer.concat(out), refused: 'chunk trailer too long', head: null }
          }
          offset = chunk.length
          continue
        }
        const line = Buffer.concat([this.held, chunk.subarray(offset, end)])
        this.held = Buffer.alloc(0)
        out.push(Buffer.concat([line, Buffer.from('\r\n', 'latin1')]))
        offset = end + 2
        // An empty line ends the chunked message body.
        if (line.length === 0) this.mode = 'head'
        continue
      }

      // mode === 'head': accumulate until the blank line.
      const end = chunk.indexOf(CRLFCRLF, offset)
      if (end === -1) {
        this.held = Buffer.concat([this.held, chunk.subarray(offset)])
        if (this.held.length > MAX_HEAD) {
          return { forward: Buffer.concat(out), refused: 'request head too long', head: null }
        }
        offset = chunk.length
        continue
      }
      const head = Buffer.concat([this.held, chunk.subarray(offset, end)])
      this.held = Buffer.alloc(0)
      const refusal = accept(head)
      if (refusal) {
        // Nothing of this request goes upstream - not even its head.
        return { forward: Buffer.concat(out), refused: refusal, head }
      }
      // Frame the body BEFORE forwarding the head: a head the scanner cannot
      // frame must not reach the agent, or the relay has forwarded a request it
      // does not understand and the next bytes get misattributed.
      const error = this.#startBody(head)
      if (error) return { forward: Buffer.concat(out), refused: error, head }
      out.push(Buffer.concat([head, Buffer.from('\r\n\r\n', 'latin1')]))
      offset = end + 4
    }
    return { forward: Buffer.concat(out), refused: null, head: null }
  }

  /** Decide how many bytes belong to the request whose head just ended. */
  #startBody(head) {
    const text = head.toString('latin1')
    const lines = text.split('\r\n')
    const headers = new Map()
    for (const line of lines.slice(1)) {
      const colon = line.indexOf(':')
      if (colon === -1) continue
      const name = line.slice(0, colon).trim().toLowerCase()
      const value = line.slice(colon + 1).trim()
      // Duplicate Content-Length with different values is the classic smuggling
      // primitive; a repeated one must at least agree.
      if (headers.has(name)) {
        if (name === 'content-length' && headers.get(name) !== value) return 'conflicting content-length'
        headers.set(name, `${headers.get(name)},${value}`)
        continue
      }
      headers.set(name, value)
    }

    const upgrade = headers.get('upgrade')
    const connection = (headers.get('connection') ?? '').toLowerCase()
    if (upgrade && connection.split(',').some((token) => token.trim() === 'upgrade')) {
      // The switch is not real yet: only the agent's 101 makes it one.
      this.mode = 'await-switch'
      return null
    }

    const encoding = (headers.get('transfer-encoding') ?? '').toLowerCase()
    const lengthHeader = headers.get('content-length')
    if (encoding.includes('chunked')) {
      if (lengthHeader !== undefined) return 'both transfer-encoding and content-length'
      this.mode = 'chunk-size'
      this.remaining = 0
      return null
    }
    if (lengthHeader === undefined) {
      this.mode = 'head'
      return null
    }
    if (!/^\d+$/.test(lengthHeader)) return 'malformed content-length'
    const length = Number(lengthHeader)
    if (!Number.isSafeInteger(length) || length < 0) return 'malformed content-length'
    if (length > 0) {
      this.mode = 'body'
      this.remaining = length
      return null
    }
    this.mode = 'head'
    return null
  }
}

/** Request line and Cookie-gate identity of a head, for the relay's comparison. */
export function identityOfHead(head) {
  const text = head.toString('latin1')
  const line = text.split('\r\n')[0]
  // A head is only a request if its first line is one. Without this check an
  // ordinary header line such as `X-B: /c/evil/x?g=...` would be read as a
  // request line and could name another tenant.
  if (!/^[A-Z]+ \S+ HTTP\/1\.[01]$/.test(line)) {
    return { id: '', gate: '', path: '', valid: false }
  }
  const space = line.indexOf(' ')
  const target = space === -1 ? '' : line.slice(space + 1).split(' ')[0]
  const q = target.indexOf('?')
  const path = q === -1 ? target : target.slice(0, q)
  const query = q === -1 ? '' : target.slice(q + 1)
  const cookie = /(?:^|\r\n)cookie:\s*([^\r\n]*)/i.exec(text)?.[1] ?? ''
  const prefixed = /^\/c\/([A-Za-z0-9]{4,16})(?:\/|$)/.exec(path)
  const cookieId = /(?:^|;\s*)__relay_i=([A-Za-z0-9]{4,16})(?:;|$)/.exec(cookie)?.[1] ?? ''
  const cookieGate = /(?:^|;\s*)__relay_g=([a-f0-9]{16,128})(?:;|$)/.exec(cookie)?.[1] ?? ''
  const queryGate = /(?:^|&)g=([a-f0-9]{16,128})(?:&|$)/.exec(query)?.[1] ?? ''
  return {
    id: prefixed?.[1] ?? cookieId,
    gate: queryGate || cookieGate,
    path,
    valid: true,
  }
}
