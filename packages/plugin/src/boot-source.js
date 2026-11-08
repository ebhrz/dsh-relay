// Browser boot: the sealing + URL-routing layer injected into every DSH HTML
// document served through the relay.
//
// Two jobs:
//   1. URL routing — the DSH app speaks in root-absolute paths (/api/...,
//      /assets/...). Through the relay every request must live under
//      /c/<id>/...?g=<gate>, so fetch / WebSocket / XHR URLs are rewritten
//      with the PREFIX/GATE constants the pump embeds below.
//   2. Sealing — every same-origin request body, response body and WebSocket
//      data payload travels as a nacl.secretbox envelope under a key derived
//      from the PSK (which only the phone and the local agent know).
//
// Residual risk on plain HTTP (documented in the README): the HTML/JS that
// runs this boot is delivered in the clear; an active MITM could alter the
// page. Running the relay behind TLS (domain + Caddy) closes that window.

import { naclBundleSource } from './nacl-bundle.js'

let naclJsCache = null

function naclJs() {
  if (naclJsCache === null) naclJsCache = naclBundleSource()
  return naclJsCache
}

export function buildBootSource(id, gate) {
  if (!naclJs()) throw new Error('tweetnacl bundle not found in plugin node_modules')
  const prefixConst = id ? `'${id}'` : 'null'
  const gateConst = gate ? `'${gate}'` : 'null'
  return `(function () {
  'use strict'
  if (window.__dshRelayBoot) return
  window.__dshRelayBoot = true

  // Per-section status + global error capture, reported to the host so
  // browser-specific boot failures are diagnosable remotely.
  var bootState = { errors: [] }
  window.addEventListener('error', function (ev) {
    try { bootState.errors.push(String(ev.message).slice(0, 120)) } catch (e) {}
  })

  // Plain-HTTP origins lose secure-context APIs; the DSH frontend calls
  // crypto.randomUUID() in workspace/model flows. getRandomValues survives
  // in non-secure contexts, so polyfill UUID v4 on top of it.
  try {
    if (window.crypto && !window.crypto.randomUUID) {
      window.crypto.randomUUID = function () {
        var bytes = new Uint8Array(16)
        if (window.crypto.getRandomValues) window.crypto.getRandomValues(bytes)
        else for (var k = 0; k < 16; k += 1) bytes[k] = Math.random() * 256 | 0
        bytes[6] = (bytes[6] & 0x0f) | 0x40
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        var hex = []
        for (var i = 0; i < 16; i += 1) hex.push(('0' + bytes[i].toString(16)).slice(-2))
        return hex.slice(0, 4).join('') + '-' + hex.slice(4, 6).join('') + '-'
          + hex.slice(6, 8).join('') + '-' + hex.slice(8, 10).join('') + '-'
          + hex.slice(10, 16).join('')
      }
    }
  } catch (e) { bootState.errors.push('uuid:' + e.message) }

  ${naclJs()}

  var PREFIX_ID = ${prefixConst}
  var GATE = ${gateConst}
  var PREFIX = PREFIX_ID ? '/c/' + PREFIX_ID : null

  function relayUrl(urlText) {
    if (!PREFIX || !GATE) return urlText
    try {
      var u = new URL(urlText, location.href)
      // WebSocket URLs arrive here with ws:/wss: after the app flips the
      // scheme; compare against the page origin with the scheme mapped back,
      // otherwise every ws URL looks cross-origin and skips the gate append
      // (remote.mux then loops on "unauthenticated" at the pump).
      var cmpProto = u.protocol === 'wss:' ? 'https:' : u.protocol === 'ws:' ? 'http:' : u.protocol
      if (cmpProto + '//' + u.host !== location.origin) return urlText
      if (u.pathname.indexOf(PREFIX) !== 0) u.pathname = PREFIX + u.pathname
      if (u.search.indexOf('g=') === -1) {
        u.search = u.search === '' ? ('?g=' + GATE) : (u.search + '&g=' + GATE)
      }
      return u.href
    } catch (e) { return urlText }
  }

  // -- dynamic resource interception ------------------------------------------
  // Plugin bundles are injected at runtime as <script src="/plugins/...">
  // by the client-modules service. Hook the element property setters so ANY
  // root-absolute script/link URL gets rewritten under our prefix, no matter
  // which field the app read it from.
  if (PREFIX && GATE) {
    try {
      function hookAssetProperty(proto, prop) {
        var desc = Object.getOwnPropertyDescriptor(proto, prop)
        if (!desc || !desc.set) { bootState.errors.push('nodesc:' + prop); return }
        Object.defineProperty(proto, prop, {
          configurable: true,
          enumerable: desc.enumerable,
          get: function () { return desc.get.call(this) },
          set: function (value) {
            try {
              if (typeof value === 'string' && value.charAt(0) === '/') {
                value = relayUrl(new URL(value, location.href).href)
              }
            } catch (e) {}
            desc.set.call(this, value)
          },
        })
      }
      hookAssetProperty(window.HTMLScriptElement && HTMLScriptElement.prototype, 'src')
      hookAssetProperty(window.HTMLLinkElement && HTMLLinkElement.prototype, 'href')
      hookAssetProperty(window.HTMLImageElement && HTMLImageElement.prototype, 'src')
      bootState.domProps = 'ok'
    } catch (e) { bootState.errors.push('domProps:' + e.message) }

    try {
      var origSetAttribute = window.Element && Element.prototype.setAttribute
      if (origSetAttribute) {
        Element.prototype.setAttribute = function (name, value) {
          try {
            var lower = String(name).toLowerCase()
            var tag = this.tagName
            if ((lower === 'src' || lower === 'href') && typeof value === 'string'
                && value.charAt(0) === '/'
                && (/^(SCRIPT|LINK|IMG)$/.test(tag))) {
              value = relayUrl(new URL(value, location.href).href)
            }
          } catch (e) {}
          return origSetAttribute.call(this, name, value)
        }
        bootState.setAttr = 'ok'
      }
    } catch (e) { bootState.errors.push('setAttr:' + e.message) }

    // NOTE: no createElement('script') crossorigin hook. DSH loads its plugin
    // bundles as same-origin classic scripts (no crossorigin), and its own
    // preload links match that mode; forcing crossorigin=anonymous here made
    // every preload unused ("credentials mode does not match").
  }

  // -- DSH boot manifest interception -----------------------------------------
  // DSH 0.2 composes the browser boot graph as { rev, entries, batches }
  // (0.1 used { plugins }). Entry and initial combo URLs are usually
  // document-relative ("plugins/??pkg/client.js&rev=...") but the relay may
  // also see root-absolute forms. Route both through relayUrl so every
  // bundle is fetched under /c/<id>/ with the gate attached.
  if (PREFIX && GATE) {
    try {
      function rewriteBootRow(row) {
        if (!row || typeof row.url !== 'string' || row.url === '') return
        row.url = relayUrl(row.url)
      }
      var realBootManifest
      Object.defineProperty(window, '__DSH_BOOT__', {
        configurable: true,
        get: function () { return realBootManifest },
        set: function (value) {
          try {
            if (value) {
              var rows = value.plugins || value.entries
              if (rows && rows.length) {
                for (var i = 0; i < rows.length; i += 1) rewriteBootRow(rows[i])
              }
              if (value.batches && value.batches.length) {
                for (var j = 0; j < value.batches.length; j += 1) rewriteBootRow(value.batches[j])
              }
            }
          } catch (e) {}
          realBootManifest = value
        },
      })
      bootState.manifest = 'ok'
    } catch (e) { bootState.errors.push('manifest:' + e.message) }
  }

  // -- key material -----------------------------------------------------------
  function fragmentOf(urlText) {
    var m = urlText.match(/#k=([A-Za-z0-9_-]+)/)
    return m ? m[1] : null
  }
  function pskFromFragment(k) {
    try {
      var b64 = k.replace(/-/g, '+').replace(/_/g, '/')
      while (b64.length % 4) b64 += '='
      var raw = atob(b64)
      var bytes = new Uint8Array(raw.length)
      for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i)
      return bytes.slice(0, 32)
    } catch (e) { return null }
  }
  var fromUrl = fragmentOf(location.href)
  if (fromUrl) localStorage.setItem('dshRelayK', fromUrl)
  var saved = localStorage.getItem('dshRelayK')
  var psk = saved ? pskFromFragment(saved) : null
  if (!psk) return // unpaired; the pairing page flow will handle it

  var envKey = nacl.hash(new Uint8Array([].concat(Array.prototype.slice.call(psk),
      Array.prototype.slice.call(new TextEncoder().encode('envelope'))))).slice(0, 32)

  // Replay defence on this side too: the relay could re-submit an old *response*
  // (a stale approval result, a stale session list). Remember the nonces we have
  // opened and refuse a repeat; bounded so a long session cannot grow forever.
  var seenNonces = typeof Set === 'function' ? new Set() : null
  var SEEN_LIMIT = 20000

  function openEnvelope(bytes) {
    try {
      if (bytes.length < 24 + 16) return null
      var nonce = bytes.slice(0, 24)
      var box = bytes.slice(24)
      var opened = nacl.secretbox.open(box, nonce, envKey)
      if (!opened) return null
      if (seenNonces) {
        var id = ''
        for (var i = 0; i < 24; i++) id += (nonce[i] < 16 ? '0' : '') + nonce[i].toString(16)
        if (seenNonces.has(id)) return null
        seenNonces.add(id)
        if (seenNonces.size > SEEN_LIMIT) {
          var excess = seenNonces.size - SEEN_LIMIT
          var it = seenNonces.values()
          for (var d = 0; d < excess; d++) seenNonces.delete(it.next().value)
        }
      }
      return new Uint8Array(opened)
    } catch (e) { return null }
  }
  function sealEnvelope(bytes) {
    var nonce = nacl.randomBytes(24)
    var box = nacl.secretbox(bytes, nonce, envKey)
    var out = new Uint8Array(24 + box.length)
    out.set(nonce, 0); out.set(box, 24)
    return out
  }

  // -- fetch patch ------------------------------------------------------------
  var origFetch = window.fetch
  try {
    // Split an inner HTTP response on BYTES. Text-decoding the whole envelope
    // corrupts binary bodies (attachments, images) and mis-slices any body
    // containing multibyte UTF-8.
    function splitResponse(bytes) {
      var split = -1
      for (var i = 0; i + 3 < bytes.length; i += 1) {
        if (bytes[i] === 13 && bytes[i + 1] === 10 && bytes[i + 2] === 13 && bytes[i + 3] === 10) {
          split = i
          break
        }
      }
      if (split === -1) return null
      var headText = new TextDecoder().decode(bytes.subarray(0, split))
      var headLines = headText.split('\\r\\n')
      var statusLine = headLines[0] || ''
      var status = parseInt((statusLine.split(' ')[1] || '200'), 10) || 200
      var headers = {}
      for (var i = 1; i < headLines.length; i += 1) {
        var colon = headLines[i].indexOf(':')
        if (colon > 0) {
          var key = headLines[i].slice(0, colon).trim().toLowerCase()
          if (key !== 'content-length' && key !== 'transfer-encoding') {
            headers[key] = headLines[i].slice(colon + 1).trim()
          }
        }
      }
      return { status: status, headers: headers, body: bytes.subarray(split + 4) }
    }

    function requestBody(value) {
      if (value === undefined || value === null) {
        return Promise.resolve({ bytes: new Uint8Array(0), type: null })
      }
      if (typeof value === 'string') {
        return Promise.resolve({ bytes: new TextEncoder().encode(value), type: 'text/plain;charset=UTF-8' })
      }
      if (typeof Blob !== 'undefined' && value instanceof Blob) {
        return value.arrayBuffer().then(function (buf) {
          return { bytes: new Uint8Array(buf), type: value.type || null }
        })
      }
      if (typeof FormData !== 'undefined' && value instanceof FormData) {
        var response = new Response(value)
        return response.arrayBuffer().then(function (buf) {
          return { bytes: new Uint8Array(buf), type: response.headers.get('content-type') }
        })
      }
      if (typeof URLSearchParams !== 'undefined' && value instanceof URLSearchParams) {
        return Promise.resolve({
          bytes: new TextEncoder().encode(value.toString()),
          type: 'application/x-www-form-urlencoded;charset=UTF-8',
        })
      }
      if (value instanceof ArrayBuffer) {
        return Promise.resolve({ bytes: new Uint8Array(value), type: null })
      }
      if (ArrayBuffer.isView(value)) {
        return Promise.resolve({
          bytes: new Uint8Array(value.buffer, value.byteOffset, value.byteLength), type: null,
        })
      }
      if (typeof ReadableStream !== 'undefined' && value instanceof ReadableStream) {
        return new Response(value).arrayBuffer().then(function (buf) {
          return { bytes: new Uint8Array(buf), type: null }
        })
      }
      return Promise.resolve({ bytes: new TextEncoder().encode(String(value)), type: null })
    }

    function fetchOptions(init, request) {
      var options = {
        method: String(init.method || (request && request.method) || 'GET').toUpperCase(),
        credentials: init.credentials !== undefined ? init.credentials : (request ? request.credentials : undefined),
        signal: init.signal !== undefined ? init.signal : (request ? request.signal : undefined),
      }
      if (init.cache !== undefined) options.cache = init.cache
      if (init.mode !== undefined) options.mode = init.mode
      if (init.redirect !== undefined) options.redirect = init.redirect
      if (init.keepalive !== undefined) options.keepalive = init.keepalive
      return options
    }

    window.fetch = function (input, init) {
      var request = null
      var rawUrl
      try {
        if (typeof input === 'string' || input instanceof URL) rawUrl = String(input)
        else if (input && typeof input.url === 'string') { request = input; rawUrl = input.url }
      } catch (e) { rawUrl = null }
      if (!rawUrl) return origFetch(input, init)
      var absolute
      try { absolute = new URL(rawUrl, location.href) } catch (e) { return origFetch(input, init) }
      // Sealing is a same-origin contract; never alter cross-origin traffic.
      if (absolute.origin !== location.origin) return origFetch(input, init)
      var finalUrl = relayUrl(absolute.href)

      init = init || {}
      var options = fetchOptions(init, request)
      var headers = new Headers((request && request.headers) || init.headers || {})
      var originalType = headers.get('content-type')
      headers.set('x-relay-enc', '1')
      headers.delete('accept-encoding')

      var sourceBody = init.body
      var bodyPromise
      if (sourceBody !== undefined) {
        bodyPromise = requestBody(sourceBody)
      } else if (request && options.method !== 'GET' && options.method !== 'HEAD') {
        bodyPromise = request.clone().arrayBuffer().then(function (buf) {
          return { bytes: new Uint8Array(buf), type: null }
        })
      } else {
        bodyPromise = Promise.resolve(null)
      }

      return bodyPromise.then(function (body) {
        if (body === null) {
          // GET/HEAD: response only is sealed.
          return origFetch(finalUrl, Object.assign({}, options, { headers: headers }))
            .then(maybeUnwrap)
        }
        headers.set('content-type', 'application/octet-stream')
        headers.set('x-relay-ct', originalType || body.type || 'text/plain;charset=UTF-8')
        return origFetch(finalUrl, Object.assign({}, options, {
          headers: headers,
          body: sealEnvelope(body.bytes),
        })).then(maybeUnwrap)
      }).catch(function (error) {
        // A body-serialization failure must not silently downgrade to plaintext.
        throw error
      })
    }

    function maybeUnwrap(res) {
      if (res.headers.get('x-relay-enc') !== '1') return res
      return res.arrayBuffer().then(function (buf) {
        var plain = openEnvelope(new Uint8Array(buf))
        if (!plain) throw new Error('envelope open failed')
        var parts = splitResponse(plain)
        if (!parts) throw new Error('bad inner response')
        var body = (parts.status === 204 || parts.status === 304 || parts.status === 101)
          ? null
          : parts.body
        return new Response(body, { status: parts.status, headers: parts.headers })
      })
    }
  } catch (e) { bootState.errors.push('fetch:' + e.message) }

  // -- XHR patch ---------------------------------------------------------------
  try {
    var OrigXHR = window.XMLHttpRequest
    var origOpen = OrigXHR.prototype.open
    OrigXHR.prototype.open = function (method, url) {
      arguments[1] = relayUrl(new URL(url, location.href).href)
      return origOpen.apply(this, arguments)
    }
    bootState.xhr = 'ok'
  } catch (e) { bootState.errors.push('xhr:' + e.message) }

  // -- WebSocket patch ----------------------------------------------------------
  try {
    var OrigWebSocket = window.WebSocket
  function PatchedWebSocket(url, protocols) {
    var finalUrl = relayUrl(new URL(url, location.href).href)
    var target = protocols === undefined ? new OrigWebSocket(finalUrl) : new OrigWebSocket(finalUrl, protocols)
    var userHandlers = []
    var userListener = null

    function deliverRaw(data) {
      var ev = new MessageEvent('message', { data: data })
      if (userListener) { try { userListener(ev) } catch (e) { console.error(e) } }
      for (var i = 0; i < userHandlers.length; i++) {
        try { userHandlers[i](ev) } catch (e) { console.error(e) }
      }
    }
    function deliverSealed(b64) {
      var bin = atob(b64)
      var bytes = new Uint8Array(bin.length)
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
      var plain = openEnvelope(bytes)
      if (!plain) return
      deliverRaw(new TextDecoder().decode(plain))
    }
    target.addEventListener('message', function (ev) {
      if (typeof ev.data !== 'string') return deliverRaw(ev.data)
      try {
        var parsed = JSON.parse(ev.data)
        if (parsed && typeof parsed.__relay === 'string') return deliverSealed(parsed.__relay)
      } catch (e) {}
      deliverRaw(ev.data)
    })

    var origSend = target.send.bind(target)
    target.send = function (data) {
      var bytes = typeof data === 'string'
        ? new TextEncoder().encode(data)
        : new Uint8Array(data)
      var sealed = sealEnvelope(bytes)
      var bin = ''
      for (var i = 0; i < sealed.length; i++) bin += String.fromCharCode(sealed[i])
      origSend(JSON.stringify({ __relay: btoa(bin) }))
    }
    Object.defineProperty(target, 'onmessage', {
      get: function () { return userListener },
      set: function (fn) { userListener = typeof fn === 'function' ? fn : null },
      configurable: true,
    })
    var origAdd = target.addEventListener.bind(target)
    target.addEventListener = function (type, listener, options) {
      if (type === 'message' && typeof listener === 'function') {
        userHandlers.push(listener)
        return
      }
      return origAdd(type, listener, options)
    }
    return target
  }
  PatchedWebSocket.prototype = OrigWebSocket.prototype
  PatchedWebSocket.CONNECTING = 0
  PatchedWebSocket.OPEN = 1
  PatchedWebSocket.CLOSING = 2
  PatchedWebSocket.CLOSED = 3
  window.WebSocket = PatchedWebSocket
  bootState.ws = 'ok'
  } catch (e) { bootState.errors.push('ws:' + e.message) }

  // Report boot state for remote diagnosis AFTER all patches are installed.
  try {
    setTimeout(function () {
      var diagBody = JSON.stringify({
        ua: navigator.userAgent,
        gate: Boolean(GATE),
        cookie: document.cookie.indexOf('__relay_g=') !== -1,
        note: 'boot2 ' + JSON.stringify(bootState).slice(0, 250)
          + ' fetchHooked=' + (window.fetch.toString().indexOf('x-relay-enc') !== -1)
          + ' wsHooked=' + (String(window.WebSocket).indexOf('Patched') !== -1),
      })
      origFetch(PREFIX + '/__relay/diag?g=' + GATE, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: diagBody,
      }).catch(function () {})
    }, 1500)
  } catch (e) {}
})()
`
}
