// Local file shuttle: /relay-bridge/files?p=<absolute path>
//
// Directories render a simple browsable listing; files stream with a
// content-type guessed from the extension. Auth is the channel's: phone
// traffic passes the pump's ticket gate, local use rides machine trust.
// Every access is audited.

import fs from 'node:fs'
import path from 'node:path'
import { auditLog } from './identity.js'
import { isLocalRequest } from './local-request.js'

const MIME = {
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
  '.webp': 'image/webp', '.svg': 'image/svg+xml', '.bmp': 'image/bmp',
  '.pdf': 'application/pdf', '.txt': 'text/plain; charset=utf-8', '.md': 'text/plain; charset=utf-8',
  '.json': 'application/json', '.csv': 'text/csv', '.html': 'text/html; charset=utf-8',
  '.mp4': 'video/mp4', '.webm': 'video/webm', '.mp3': 'audio/mpeg', '.wav': 'audio/wav',
  '.log': 'text/plain; charset=utf-8', '.yaml': 'text/plain; charset=utf-8', '.yml': 'text/plain; charset=utf-8',
}

export function registerFiles(ctx) {
  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/relay-bridge/files',
    handler: (req, res) => {
      // This handler will read any absolute path the caller names, so who the
      // caller is decides everything. Loopback peer plus loopback Host: a proxy
      // forwarding to 127.0.0.1, or a rebound domain, is refused.
      if (req.headers['x-dsh-relay'] || !isLocalRequest({
        remoteAddress: req.socket?.remoteAddress,
        host: req.headers.host,
      })) {
        res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
        res.end('dsh-relay: the file shuttle answers on localhost only.\n')
        return
      }
      const url = new URL(req.url ?? '/', 'http://x')
      const raw = url.searchParams.get('p') ?? ''
      if (!raw || raw.includes('\0')) {
        res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('missing ?p=<absolute path>')
        return
      }
      const target = path.resolve(raw)
      let stat
      try {
        stat = fs.statSync(target)
      } catch (error) {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
        res.end(`not found: ${error.message}`)
        return
      }
      auditLog(`file ${stat.isDirectory() ? 'dir' : 'get'} ${target}`)

      if (stat.isDirectory()) {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
        res.end(renderListing(target))
        return
      }

      const type = MIME[path.extname(target).toLowerCase()] ?? 'application/octet-stream'
      res.writeHead(200, {
        'content-type': type,
        'content-length': stat.size,
        'cache-control': 'no-store',
      })
      fs.createReadStream(target).pipe(res)
    },
  }), 'dsh-relay-phone: file shuttle')
}

function renderListing(dir) {
  let entries = []
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true })
      .map((e) => ({ name: e.name, dir: e.isDirectory() }))
      .sort((a, b) => (a.dir === b.dir ? a.name.localeCompare(b.name) : a.dir ? -1 : 1))
  } catch (error) {
    return `<!doctype html><body style="font-family:monospace">无法读取目录: ${error.message}</body>`
  }
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;')
  const link = (p) => encodeURIComponent(p)
  const rows = entries.map((e) => {
    const full = path.join(dir, e.name)
    return `<tr><td>${e.dir ? '📁' : '📄'}</td><td><a href="/relay-bridge/files?p=${link(full)}">${esc(e.name)}</a></td></tr>`
  }).join('\n')
  const parent = path.dirname(dir)
  return `<!doctype html>
<html lang="zh"><head><meta charset="utf-8"><title>${esc(dir)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,monospace;background:#0b1020;color:#e6e9f2;padding:16px}
a{color:#7aa2ff;text-decoration:none}td{padding:4px 10px;border-bottom:1px solid #1c2440}
h2{font-size:14px;word-break:break-all}button{background:#4d6bfe;color:#fff;border:0;border-radius:8px;padding:8px 14px;font-size:14px}
.pathbar{position:sticky;top:0;background:#0b1020;padding:10px 0;border-bottom:1px solid #1c2440;margin-bottom:10px}</style></head>
<body>
<div class="pathbar">
  <h2>📁 ${esc(dir)}</h2>
  <button onclick="copyPath()">复制此目录路径</button>
  <a href="/relay-bridge/files?p=${link(parent)}">⬆ 上级</a>
</div>
<table>${rows}</table>
<script>
function copyPath() {
  var p = new URLSearchParams(location.search).get('p')
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(p).then(function () { alert('已复制: ' + p) })
  } else {
    prompt('长按复制:', p)
  }
}
</script>
</body></html>`
}
