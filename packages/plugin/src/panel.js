// Local management panel: http://127.0.0.1:3080/relay-bridge/panel
//
// Server-rendered (no DSH client bundle needed): relay connection status,
// the phone entry URL + QR, config editing and identity rotation.

import crypto from 'node:crypto'
import QRCode from 'qrcode'
import { identityDir } from './identity.js'
import { COOKIE_NAME, TICKET_TTL_SECONDS } from './pairing.js'
import fs from 'node:fs'
import path from 'node:path'

const KEY_RE = /^[A-Za-z0-9_-]{4,128}$/

// Loopback addresses (IPv4/IPv6) — the only way the DSH web server is
// reachable besides the relay pump, which already ticket-gates everything.
function isLoopback(remoteAddress) {
  const address = String(remoteAddress ?? '')
  return address === '::1'
    || address === '::ffff:127.0.0.1'
    || address.startsWith('127.')
    || address.startsWith('::ffff:127.')
}

export function entryUrl(config, identity, { path = '/m' } = {}) {
  if (!config.relayHost || !config.relayPort) return null
  const scheme = config.relayScheme ?? 'http'
  const psk = Buffer.from(identity.psk, 'hex')
  const pubRaw = Buffer.from(identity.signJwk.public.x, 'base64url')
  const k = Buffer.concat([psk, pubRaw]).toString('base64url')
  const agentPort = config.agentPort || config.relayPort + 1
  void agentPort
  return `${scheme}://${config.relayHost}:${config.relayPort}/c/${identity.id}${path}?g=${identity.gate}#k=${k}`
}

/** Phone-first entry (the dedicated mobile page) and the full desktop UI. */
export function mobileEntryUrl(config, identity) {
  return entryUrl(config, identity, { path: '/m' })
}

export function desktopEntryUrl(config, identity) {
  return entryUrl(config, identity, { path: '/' })
}

export async function registerPanel(ctx, service) {
  const readConfig = () => {
    try {
      return JSON.parse(fs.readFileSync(path.join(identityDir(), 'config.json'), 'utf8'))
    } catch {
      return {}
    }
  }
  const writeConfig = (config) => {
    fs.mkdirSync(identityDir(), { recursive: true })
    fs.writeFileSync(path.join(identityDir(), 'config.json'), JSON.stringify(config, null, 2) + '\n', { mode: 0o600 })
  }

  const snapshot = async () => {
    const config = service.config
    const identity = service.identity
    const url = mobileEntryUrl(config, identity)
    let qr = null
    if (url) {
      try { qr = await QRCode.toDataURL(url, { margin: 1, width: 320 }) } catch { qr = null }
    }
    return {
      status: service.lastStatus ?? { status: 'idle', detail: '' },
      connected: service.client?.connected() ?? false,
      id: identity.id,
      config: {
        relayScheme: config.relayScheme ?? 'http',
        relayHost: config.relayHost,
        relayPort: config.relayPort,
        agentPort: config.agentPort,
        relayKeySet: Boolean(config.relayKey),
        dshPort: service.upstreamTarget().port,
        upstreamHost: service.upstreamTarget().host,
      },
      upstreamAuth: Boolean(service.upstreamAuthCookie()),
      entryUrl: url,
      desktopEntryUrl: desktopEntryUrl(config, identity),
      mobileVersion: service.mobileVersion ?? '0',
      phones: service.mobile?.phoneCount?.() ?? 0,
      qr,
    }
  }

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/relay-bridge/panel',
    handler: async (req, res) => {
      // Desktop-only. This page hands out the pairing entry URL, which embeds
      // the device PSK (`#k=`); a relayed request is a phone, and a phone that
      // could read it would be able to pair unlimited extra devices. The pump
      // marks relayed requests, so this cannot be forged by the client.
      if (req.headers['x-dsh-relay']) {
        res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
        res.end('dsh-relay: the management panel is desktop-only. Open it on 127.0.0.1.\n')
        return
      }
      // Same ticket policy as /relay-bridge/api: a local page load mints one so
      // its write actions authenticate.
      if (!service.pairing.sessionForHeaders(req.headers)) {
        if (!isLoopback(req.socket?.remoteAddress ?? '')) {
          res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
          res.end('unauthorized\n')
          return
        }
        const { did } = service.cryptoBox.createSession()
        const ticket = service.cryptoBox.sealTicket(did, TICKET_TTL_SECONDS)
        res.setHeader('set-cookie',
          `${COOKIE_NAME}=${ticket}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${TICKET_TTL_SECONDS}`)
      }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      res.end(buildPage())
    },
  }), 'dsh-relay-phone: panel page')

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/relay-bridge/api',
    handler: async (req, res) => {
      const reply = (code, value) => {
        res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
        res.end(JSON.stringify(value))
      }

      // Desktop-only, for the same reason as the page: the snapshot contains
      // the pairing URL with the device PSK, and the relay key can be changed
      // from here.
      if (req.headers['x-dsh-relay']) {
        return reply(403, { ok: false, error: 'desktop-only' })
      }

      // Pairing-ticket gate. Requests arriving through the relay already
      // carry a valid ticket (the pump refuses ticketless traffic), so this
      // check only ever fires for DIRECT local access — the local user's own
      // browser, which holds no ticket (tickets are issued to phones at
      // pairing). A local GET mints one on the spot; write actions require an
      // existing ticket (SameSite=Strict keeps it out of cross-site requests,
      // so a malicious webpage cannot CSRF them). Non-loopback callers
      // without a ticket get 401.
      const session = service.pairing.sessionForHeaders(req.headers)
      if (!session && !isLoopback(req.socket?.remoteAddress ?? '')) {
        return reply(401, { ok: false, error: 'unauthorized' })
      }
      if (!session && req.method !== 'POST') {
        const { did } = service.cryptoBox.createSession()
        const ticket = service.cryptoBox.sealTicket(did, TICKET_TTL_SECONDS)
        res.setHeader('set-cookie',
          `${COOKIE_NAME}=${ticket}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${TICKET_TTL_SECONDS}`)
      }
      if (req.method === 'GET') {
        return reply(200, await snapshot())
      }
      if (req.method !== 'POST') return reply(405, { ok: false, error: 'method' })
      if (!service.pairing.sessionForHeaders(req.headers)) {
        return reply(401, { ok: false, error: 'unauthorized' })
      }

      const chunks = []
      for await (const chunk of req) chunks.push(chunk)
      let body
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { return reply(400, { ok: false, error: 'bad json' }) }

      if (body.action === 'save-config') {
        const c = body.config ?? {}
        const stored = readConfig()
        if (c.relayHost !== undefined) {
          if (!/^[A-Za-z0-9.:-]{1,128}$/.test(String(c.relayHost))) return reply(400, { ok: false, error: 'bad relayHost' })
          stored.relayHost = String(c.relayHost)
        }
        if (c.relayPort !== undefined) {
          const port = Number(c.relayPort)
          if (!Number.isInteger(port) || port < 1 || port > 65535) return reply(400, { ok: false, error: 'bad relayPort' })
          stored.relayPort = port
        }
        if (c.agentPort !== undefined) {
          const port = Number(c.agentPort)
          if (!Number.isInteger(port) || port < 1 || port > 65535) return reply(400, { ok: false, error: 'bad agentPort' })
          stored.agentPort = port
        }
        if (c.relayKey !== undefined && c.relayKey !== '') {
          if (!KEY_RE.test(String(c.relayKey))) return reply(400, { ok: false, error: 'bad relayKey' })
          stored.relayKey = String(c.relayKey)
        }
        if (c.relayScheme !== undefined) stored.relayScheme = c.relayScheme === 'https' ? 'https' : 'http'
        if (c.dshPort !== undefined) {
          const port = Number(c.dshPort)
          if (!Number.isInteger(port) || port < 1 || port > 65535) return reply(400, { ok: false, error: 'bad dshPort' })
          stored.dshPort = port
        }
        writeConfig(stored)
        service.applyConfig(stored)
        return reply(200, { ok: true, snapshot: await snapshot() })
      }

      if (body.action === 'regenerate') {
        service.rotateIdentity()
        return reply(200, { ok: true, snapshot: await snapshot() })
      }

      if (body.action === 'accept-fingerprint') {
        const ok = service.acceptFingerprint()
        if (!ok) return reply(409, { ok: false, error: 'not in fingerprint-mismatch state' })
        return reply(200, { ok: true, snapshot: await snapshot() })
      }

      if (body.action === 'reconnect') {
        service.startChannel()
        return reply(200, { ok: true, snapshot: await snapshot() })
      }

      return reply(404, { ok: false, error: 'unknown action' })
    },
  }), 'dsh-relay-phone: panel api')
}

function buildPage() {
  return `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>dsh-relay-phone 控制台</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--line:#e3e7ee;--text:#101828;--muted:#5b6577;
        --accent:#4d6bfe;--ok:#14934f;--bad:#d92d20;--sunken:#f4f6f9;--soft:#eef1f6;--link:#2f4bd6;--warn:#b42318}
  @media (prefers-color-scheme: dark){
    :root{color-scheme:dark;--bg:#0b1020;--card:#131a30;--line:#26325a;--text:#e6e9f2;--muted:#9aa7c7;
          --accent:#4d6bfe;--ok:#2fbf71;--bad:#e5484d;--sunken:#0b1020;--soft:#1b2440;--link:#9db2ff;--warn:#a5372b}
  }
  body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);padding:28px}
  .wrap{max-width:860px;margin:0 auto;display:grid;gap:18px}
  h1{font-size:20px;margin:0}
  h2{font-size:15px;margin:0 0 10px;color:var(--muted)}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px}
  .row{display:flex;gap:14px;flex-wrap:wrap;align-items:center}
  .dot{width:10px;height:10px;border-radius:50%;background:var(--muted);display:inline-block;margin-right:6px}
  .dot.ok{background:var(--ok);box-shadow:0 0 8px var(--ok)}
  .dot.bad{background:var(--bad)}
  code{background:var(--sunken);padding:2px 6px;border-radius:6px;font-size:12px;word-break:break-all}
  input{padding:8px 10px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--text);font-size:14px;width:100%;box-sizing:border-box}
  label{font-size:12px;color:var(--muted);display:block;margin:10px 0 4px}
  button{padding:9px 14px;border:0;border-radius:8px;background:var(--accent);color:#fff;font-size:14px;cursor:pointer}
  button.warn{background:var(--warn)}
  button:disabled{opacity:.5;cursor:default}
  a.plain{display:inline-flex;align-items:center;padding:9px 14px;border-radius:8px;background:var(--soft);color:var(--link);text-decoration:none;font-size:14px}
  a.plain:hover{filter:brightness(0.97)}
  img{border-radius:12px;background:#fff;padding:8px;width:200px;height:200px}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px}
  .muted{color:var(--muted);font-size:12px}
</style>
</head>
<body>
<div class="wrap">
  <h1>DSH Relay Bridge 控制台</h1>
  <div class="muted">
    <a class="plain" href="#" onclick="goBack();return false">← 返回 DSH</a>
  </div>

  <div class="card">
    <h2>连接状态</h2>
    <div class="row"><span class="dot" id="dot"></span><span id="statusText">…</span></div>
    <div class="muted" id="detail" style="margin-top:6px"></div>
    <div class="muted" id="authText" style="margin-top:6px"></div>
    <div class="muted" id="mobileText" style="margin-top:6px"></div>
    <div class="row" style="margin-top:10px;display:none" id="fpRow">
      <button class="warn" onclick="acceptFp()">我确认更换了服务器，接受新证书指纹</button>
    </div>
  </div>

  <div class="card">
    <h2>手机入口（扫码或复制链接）</h2>
    <div class="row">
      <img id="qr" alt="QR" style="display:none">
      <div style="flex:1;min-width:260px">
        <div><code id="entryUrl">（先配置 relay 地址）</code></div>
        <div class="row" style="margin-top:10px">
          <button onclick="copyUrl()">复制链接</button>
          <a class="plain" id="desktopLink" href="#" target="_blank" style="display:none">桌面完整界面</a>
          <button class="warn" onclick="regenerate()">重新生成密钥（吊销所有已配对设备）</button>
        </div>
        <p class="muted">扫码进入为手机优化的聊天页；旧入口链接仍可打开完整桌面界面。密钥在链接 # 号之后，不会发送到服务器；重新生成后旧设备全部失效。</p>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Relay 服务器配置</h2>
    <div class="grid">
      <div><label>协议</label><input id="f_scheme" placeholder="http"></div>
      <div><label>地址</label><input id="f_host" placeholder="relay.example.com"></div>
      <div><label>端口（手机入口）</label><input id="f_port" placeholder="8889"></div>
      <div><label>Agent 端口（留空=端口+1）</label><input id="f_agentPort" placeholder="8890"></div>
      <div><label>注册 Key（与服务器 --key 一致；留空保持不变）</label><input id="f_key" type="password" placeholder=""></div>
      <div><label>本地 DSH 端口（自动检测）</label><input id="f_dshPort" disabled></div>
    </div>
    <div class="row" style="margin-top:14px">
      <button onclick="save()">保存并重连</button>
      <button onclick="reconnect()">仅重连</button>
    </div>
  </div>
</div>
<script>
var S = null
async function refresh() {
  S = await (await fetch('/relay-bridge/api')).json()
  var dot = document.getElementById('dot')
  dot.className = 'dot ' + (S.connected ? 'ok' : 'bad')
  document.getElementById('statusText').textContent =
    (S.connected ? '已连接 ' : '') + S.status.status + ' · 设备 ' + S.id
  document.getElementById('detail').textContent = S.status.detail || ''
  document.getElementById('authText').textContent = S.upstreamAuth
    ? '上游 DSH 鉴权：已就绪'
    : '上游 DSH 鉴权：未就绪（DSH 0.2 的 /api 会拒绝请求）'
  document.getElementById('mobileText').textContent =
    '手机页 v' + (S.mobileVersion || '0') + ' · 当前在线手机 ' + (S.phones || 0) + ' 台'
  var desktopLink = document.getElementById('desktopLink')
  if (S.desktopEntryUrl) { desktopLink.href = S.desktopEntryUrl; desktopLink.style.display = 'inline-flex' }
  document.getElementById('fpRow').style.display =
    S.status.status === 'fingerprint-mismatch' ? 'flex' : 'none'
  document.getElementById('entryUrl').textContent = S.entryUrl || '（先配置 relay 地址）'
  var qr = document.getElementById('qr')
  if (S.qr) { qr.src = S.qr; qr.style.display = 'inline' } else { qr.style.display = 'none' }
  document.getElementById('f_scheme').value = S.config.relayScheme || 'http'
  document.getElementById('f_host').value = S.config.relayHost || ''
  document.getElementById('f_port').value = S.config.relayPort || ''
  document.getElementById('f_agentPort').value = S.config.agentPort || ''
  document.getElementById('f_dshPort').value = S.config.dshPort || 3080
}
async function post(body) {
  var r = await fetch('/relay-bridge/api', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  var j = await r.json()
  if (!j.ok) alert(j.error || 'failed')
  S = j.snapshot || S
  await refresh()
}
function save() {
  post({ action: 'save-config', config: {
    relayScheme: document.getElementById('f_scheme').value.trim(),
    relayHost: document.getElementById('f_host').value.trim(),
    relayPort: Number(document.getElementById('f_port').value.trim() || 0) || undefined,
    agentPort: Number(document.getElementById('f_agentPort').value.trim() || 0) || undefined,
    relayKey: document.getElementById('f_key').value,
  } })
}
function reconnect() { post({ action: 'reconnect' }) }
function acceptFp() { post({ action: 'accept-fingerprint' }) }
function regenerate() {
  if (confirm('重新生成密钥将吊销所有已配对的手机，确定？')) post({ action: 'regenerate' })
}
function copyUrl() {
  if (!S || !S.entryUrl) return
  navigator.clipboard.writeText(S.entryUrl).then(function () { alert('已复制') })
}
// The console opens in the same window inside the desktop app (it blocks
// cross-origin navigation), so give the user a way back to the DSH UI.
function goBack() {
  if (history.length > 1) history.back()
  else location.assign('/')
}
refresh()
setInterval(refresh, 5000)
</script>
</body>
</html>`
}
