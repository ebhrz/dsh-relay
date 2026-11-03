// The bootstrap pairing page served to unauthenticated phones.
//
// It is intentionally tiny and self-contained: read the PSK from the URL
// fragment (which never travels over the network), prove knowledge of it via
// the challenge/verify handshake, receive the encrypted ticket cookie, then
// reload into the real DSH app. tweetnacl is inlined from the plugin's own
// node_modules so both ends share one sha512 implementation.

import fs from 'node:fs'
import { fileURLToPath } from 'node:url'

let naclJsCache = null

function naclJs() {
  if (naclJsCache !== null) return naclJsCache
  const candidates = [
    new URL('../node_modules/tweetnacl/nacl-fast.min.js', import.meta.url),
    new URL('../node_modules/tweetnacl/nacl.min.js', import.meta.url),
  ]
  for (const url of candidates) {
    try {
      naclJsCache = fs.readFileSync(fileURLToPath(url), 'utf8')
      return naclJsCache
    } catch {}
  }
  naclJsCache = ''
  return naclJsCache
}

export function buildPairingPage(id, gate) {
  const hasNacl = naclJs() !== ''
  const idConst = id ? `'${id}'` : 'null'
  const gateConst = gate ? `'${gate}'` : 'null'
  return `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>dsh-relay 配对</title>
<meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0a0d13" media="(prefers-color-scheme: dark)">
<style>
  :root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--line:#e3e7ee;--text:#101828;--muted:#5b6577;
        --accent:#4d6bfe;--ok:#14934f;--err:#d92d20;--sunken:#f4f6f9}
  @media (prefers-color-scheme: dark){
    :root{color-scheme:dark;--bg:#0a0d13;--card:#131a30;--line:#26325a;--text:#e6e9f2;--muted:#9aa7c7;
          --accent:#4d6bfe;--ok:#8ce99a;--err:#ff9a9a;--sunken:#0b1020}
  }
  body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);
       display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}
  .card{max-width:420px;width:100%;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:28px;
        box-shadow:0 10px 30px rgba(16,24,40,.08)}
  h1{font-size:18px;margin:0 0 6px}
  p{font-size:14px;color:var(--muted);margin:6px 0}
  #status{margin-top:18px;font-size:14px;padding:12px;border-radius:10px;background:var(--sunken)}
  .err{color:var(--err)} .ok{color:var(--ok)}
  input{width:100%;box-sizing:border-box;margin-top:10px;padding:10px;border-radius:8px;border:1px solid var(--line);
        background:var(--card);color:var(--text);font-size:14px}
  button{margin-top:10px;width:100%;padding:10px;border:0;border-radius:8px;background:var(--accent);color:#fff;font-size:15px}
</style>
</head>
<body>
<div class="card">
  <h1>DSH Remote · 配对</h1>
  <p id="hint">正在使用链接中的密钥与你的电脑配对…</p>
  <div id="status" class="ok">…</div>
  <div id="manual" style="display:none">
    <input id="tokenInput" placeholder="粘贴完整的入口链接（含 #k=…）">
    <button onclick="retryWithToken()">重新配对</button>
  </div>
</div>
<script>
${hasNacl ? naclJs() : 'window.nacl=null;'}
</script>
<script>
(function () {
  var EMBEDDED_ID = ${idConst}
  var EMBEDDED_GATE = ${gateConst}
  var PREFIX = EMBEDDED_ID ? '/c/' + EMBEDDED_ID
    : (location.pathname.match(/^\\/c\\/[^/]+/) || ['/'])[0]
  var GATE = EMBEDDED_GATE || new URLSearchParams(location.search).get('g') || ''
  var $ = function (id) { return document.getElementById(id) }
  function setStatus(text, ok) { $('status').textContent = text; $('status').className = ok ? 'ok' : 'err' }

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
      if (bytes.length < 32) return null
      return bytes.slice(0, 32)
    } catch (e) { return null }
  }

  function randomB64(n) {
    var bytes = new Uint8Array(n)
    for (var i = 0; i < n; i++) bytes[i] = Math.floor(Math.random() * 256)
    var s = ''
    for (var j = 0; j < n; j++) s += String.fromCharCode(bytes[j])
    return btoa(s)
  }

  function toHex(bytes) {
    var s = ''
    for (var i = 0; i < bytes.length; i++) s += ('0' + bytes[i].toString(16)).slice(-2)
    return s
  }

  function proofHex(psk, cnonce, snonce) {
    var msg = cnonce + '|' + snonce + '|verify'
    var msgBytes = new TextEncoder().encode(msg)
    var input = new Uint8Array(psk.length + msgBytes.length)
    input.set(psk, 0); input.set(msgBytes, psk.length)
    return toHex(nacl.hash(input))
  }

  function api(name, body) {
    return fetch(PREFIX + '/__relay/' + name + '?g=' + encodeURIComponent(GATE), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body || {}),
      credentials: 'include',
    }).then(function (res) {
      if (!res.ok) throw new Error(name + ' HTTP ' + res.status)
      return res.json()
    })
  }

  function pair(k) {
    var psk = pskFromFragment(k)
    if (!psk) { setStatus('链接里的密钥格式不对', false); return }
    if (!window.nacl) { setStatus('内部错误：加密库未加载', false); return }
    var cnonce = randomB64(16)
    setStatus('正在验证…', true)
    api('challenge', { cnonce: cnonce })
      .then(function (r) {
        return api('verify', {
          cnonce: cnonce,
          snonce: r.snonce,
          proof: proofHex(psk, cnonce, r.snonce),
        })
      })
      .then(function (r) {
        if (!r.ok) throw new Error('verify failed')
        setStatus('配对成功，正在进入…', true)
        setTimeout(function () { location.replace(location.pathname + location.search) }, 300)
      })
      .catch(function (e) {
        setStatus('配对失败：' + (e && e.message ? e.message : e), false)
        $('hint').textContent = '请从 DSH 设置页重新扫码，或在下面粘贴新的入口链接。'
        $('manual').style.display = 'block'
      })
  }

  window.retryWithToken = function () {
    var text = $('tokenInput').value
    var k = fragmentOf(text)
    if (!k) { setStatus('没找到 #k= 密钥部分', false); return }
    localStorage.setItem('dshRelayK', k)
    pair(k)
  }

  var fromUrl = fragmentOf(location.href)
  if (fromUrl) localStorage.setItem('dshRelayK', fromUrl)
  var saved = localStorage.getItem('dshRelayK')
  try {
    fetch(PREFIX + '/__relay/diag?g=' + encodeURIComponent(GATE), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ua: navigator.userAgent,
        gate: Boolean(GATE),
        cookie: document.cookie.indexOf('__relay_t=') !== -1,
        note: 'pairing-page',
      }),
    }).catch(function () {})
  } catch (e) {}
  if (saved) {
    pair(saved)
  } else {
    setStatus('此链接缺少密钥', false)
    $('hint').textContent = '请从 DSH 设置页重新扫码，或在下面粘贴完整的入口链接。'
    $('manual').style.display = 'block'
  }
})()
</script>
</body>
</html>`
}
