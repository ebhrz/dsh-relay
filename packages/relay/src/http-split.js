// Split a phone connection's byte stream into HTTP requests.
//
// The relay binds a stream to one tenant at its first request line and then pipes
// bytes. A reverse proxy that pools upstream connections (or a hostile agent that
// keeps its socket open) can therefore deliver the *next* request on that socket
// to the previous tenant's agent - which is how one tenant could serve another's
// page. Rewriting each request to `Connection: close` stops honest clients from
// reusing the socket; this scanner is what stops a *malicious* peer, because the
// relay itself decides where a request ends and refuses one that names another
// tenant before a single byte of it is forwarded.
//
// It only understands what it must: the request head, `Content-Length`,
// `Transfer-Encoding: chunked`, and the point where an upgrade turns the socket
// into an opaque tunnel.

const MAX_HEAD = 64 * 1024
const CRLFCRLF = Buffer.from('\r\n\r\n', 'latin1')

export class RequestScanner {
  constructor() {
    this.mode = 'head' // head | body | chunk-size | chunk-data | chunk-data-end | tunnel
    this.head = Buffer.alloc(0)
    this.remaining = 0
    this.held = Buffer.alloc(0) // head bytes not yet forwarded
  }

  /**
   * Prime the scanner with a head that has already been accepted (the relay's
   * first request), so the following bytes are treated as that request's body.
   * @param {Buffer} head without the trailing CRLFCRLF
   * @returns {string|null} an error when the head cannot be framed
   */
  startWith(head) {
    return this.#startBody(Buffer.from(head))
  }

  /**
   * Feed raw bytes from the phone.
   * @param {Buffer} chunk
   * @param {(head: Buffer) => (string|null)} accept returns a refusal reason, or
   *   null to let the request through. Called for every *subsequent* request.
   * @returns {{ forward: Buffer, refused: string|null }}
   *   `forward` is the part of this chunk that may be sent upstream; on refusal
   *   it stops just before the offending head.
   */
  feed(chunk, accept) {
    const out = []
    let offset = 0
    while (offset < chunk.length) {
      if (this.mode === 'tunnel') {
        out.push(chunk.subarray(offset))
        break
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
        // The CRLF that closes a chunk's data.
        if (chunk[offset] === 0x0d && chunk[offset + 1] === 0x0a) {
          out.push(chunk.subarray(offset, offset + 2))
          offset += 2
          this.mode = 'chunk-size'
          continue
        }
        // Malformed framing: stop interpreting, stay out of the way.
        this.mode = 'tunnel'
        continue
      }
      if (this.mode === 'chunk-size') {
        const end = chunk.indexOf('\r\n', offset)
        if (end === -1) {
          this.held = Buffer.concat([this.held, chunk.subarray(offset)])
          offset = chunk.length
          continue
        }
        const line = Buffer.concat([this.held, chunk.subarray(offset, end)]).toString('latin1')
        this.held = Buffer.alloc(0)
        const size = Number.parseInt(line.split(';')[0].trim(), 16)
        if (!Number.isFinite(size) || size < 0) {
          this.mode = 'tunnel'
          continue
        }
        out.push(chunk.subarray(offset, end + 2))
        offset = end + 2
        if (size === 0) {
          // The last chunk is followed by optional trailers and a blank line;
          // treat everything up to the next head as body-free framing.
          const tail = chunk.indexOf('\r\n', offset)
          if (tail === -1) {
            this.held = Buffer.concat([this.held, chunk.subarray(offset)])
            offset = chunk.length
            this.mode = 'body'
            this.remaining = 2
            continue
          }
          out.push(chunk.subarray(offset, tail + 2))
          offset = tail + 2
          this.mode = 'head'
        } else {
          this.remaining = size
          this.mode = 'chunk-data'
        }
        continue
      }

      // mode === 'head': accumulate until the blank line.
      const end = chunk.indexOf(CRLFCRLF, offset)
      if (end === -1) {
        this.held = Buffer.concat([this.held, chunk.subarray(offset)])
        if (this.held.length > MAX_HEAD) this.mode = 'tunnel'
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
      out.push(Buffer.from(`${head.toString('latin1')}\r\n\r\n`, 'latin1'))
      offset = end + 4
      const error = this.#startBody(head)
      if (error) return { forward: Buffer.concat(out), refused: error, head }
    }
    return { forward: Buffer.concat(out), refused: null }
  }

  /** Decide how many bytes belong to the request whose head just ended. */
  #startBody(head) {
    const text = head.toString('latin1')
    const lines = text.split('\r\n')
    const headers = new Map()
    for (const line of lines.slice(1)) {
      const colon = line.indexOf(':')
      if (colon === -1) continue
      headers.set(line.slice(0, colon).trim().toLowerCase(), line.slice(colon + 1).trim())
    }
    if (headers.get('upgrade')) {
      this.mode = 'tunnel'
      return null
    }
    const encoding = (headers.get('transfer-encoding') ?? '').toLowerCase()
    if (encoding.includes('chunked')) {
      this.mode = 'chunk-size'
      this.remaining = 0
      return null
    }
    const length = Number(headers.get('content-length') ?? '0')
    if (Number.isFinite(length) && length > 0) {
      this.mode = 'body'
      this.remaining = length
      return null
    }
    if (!Number.isFinite(length)) {
      // Nonsense length: stop interpreting rather than guess.
      this.mode = 'tunnel'
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
  const space = line.indexOf(' ')
  const target = space === -1 ? '' : line.slice(space + 1).split(' ')[0]
  const q = target.indexOf('?')
  const path = q === -1 ? target : target.slice(0, q)
  const query = q === -1 ? '' : target.slice(q + 1)
  const cookie = /(?:^|\r\n)cookie:\s*([^\r\n]*)/i.exec(text)?.[1] ?? ''
  const prefixed = /^\/c\/([A-Za-z0-9]{4,16})\//.exec(path)
  const cookieId = /(?:^|;\s*)__relay_i=([A-Za-z0-9]{4,16})(?:;|$)/.exec(cookie)?.[1] ?? ''
  const cookieGate = /(?:^|;\s*)__relay_g=([a-f0-9]{16,128})(?:;|$)/.exec(cookie)?.[1] ?? ''
  const queryGate = /(?:^|&)g=([a-f0-9]{16,128})(?:&|$)/.exec(query)?.[1] ?? ''
  return {
    id: prefixed?.[1] ?? cookieId,
    gate: queryGate || cookieGate,
    path,
  }
}
