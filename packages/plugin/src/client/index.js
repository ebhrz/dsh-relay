// dsh-relay-phone browser half: pins the phone-entry action (entry link +
// QR) into the DSH web sidebar's `sidebar.footer.action` list.
//
// DSH 0.2 ships its own right-sidebar terminal, so the relay no longer renders
// or serves a terminal view. The remaining browser surface is the phone entry:
// same /relay-bridge/api snapshot as the standalone console page, polled while
// the card is open, so the QR/link stay in sync.
//
// Hand-written in the client module registration format
// (window.__ModuleLoader__.load, factory(require) → plugin exports) so the
// plugin needs no bundler.

window.__ModuleLoader__.load({
  id: 'dsh-relay-phone',
  factory: (require) => {
    const React = require('react')
    const { createPortal } = require('react-dom')
    const { useCallback, useEffect, useRef, useState } = React
    const h = React.createElement
    const Fragment = React.Fragment

    const NS = 'relayPanel'
    const zh = {
      trigger: '手机入口',
      title: 'DSH Relay 手机入口',
      loading: '加载中…',
      unconfigured: '（先配置 relay 地址）',
      configure: '去控制台配置',
      openPanel: '打开完整控制台',
      copy: '复制链接',
      copied: '已复制',
      regenerate: '重新生成密钥',
      regenerateConfirm: '重新生成密钥将吊销所有已配对的手机，确定？',
      statusIdle: '未连接',
      statusOpen: '已连接',
      close: '关闭',
      remoteTitle: '远程无法使用',
      remoteBody: '手机入口只在电脑上的 DSH 里可用。通过 relay 打开时，控制台不会把配对链接发出去——那串链接里带着设备密钥。请在电脑上打开这个面板。',
    }
    const en = {
      trigger: 'Phone Entry',
      title: 'DSH Relay Phone Entry',
      loading: 'loading…',
      unconfigured: '(configure the relay address first)',
      configure: 'Open console to configure',
      openPanel: 'Open full console',
      copy: 'Copy link',
      copied: 'Copied',
      regenerate: 'Regenerate key',
      regenerateConfirm: 'Regenerating the key revokes every paired phone. Continue?',
      statusIdle: 'not connected',
      statusOpen: 'connected',
      close: 'Close',
      remoteTitle: 'Not available remotely',
      remoteBody: 'The phone entry only works from DSH on the host machine. Over the relay the console refuses to hand out the pairing link, because that link carries the device key. Open this panel on the computer instead.',
    }

    // The console (/relay-bridge/panel) is a standalone page on this same
    // server, so the URL stays same-origin on purpose. The desktop app blocks
    // cross-origin navigation and hands http(s) targets to the system browser;
    // rewriting the host (127.0.0.1 <-> localhost) therefore made the console
    // open outside the app — or nowhere at all. Same-origin navigation is
    // allowed in-window, so Electron navigates in place and a plain browser
    // gets a new tab.
    const isElectron = navigator.userAgent.includes('Electron')

    function consoleUrl() {
      try {
        return new URL('/relay-bridge/panel', window.location.href).toString()
      } catch {
        return '/relay-bridge/panel'
      }
    }

    function openConsole(event) {
      if (event) event.preventDefault()
      const url = consoleUrl()
      if (isElectron) window.location.assign(url)
      else window.open(url, '_blank', 'noopener')
    }

    if (!document.getElementById('dsh-relay-panel-style')) {
      const style = document.createElement('style')
      style.id = 'dsh-relay-panel-style'
      // Lets the 0.2 module system evict this stylesheet when the plugin is
      // disabled; it only owns tags it can identify.
      style.setAttribute('data-plugin', 'dsh-relay-phone')
      style.textContent = `
.dsh-relay-entry-btn{display:flex;align-items:center;gap:8px;width:100%;padding:8px 10px;background:transparent;border:0;border-radius:8px;color:inherit;cursor:pointer;font-size:13px;line-height:1;text-align:left}
.dsh-relay-entry-btn:hover{background:rgba(127,127,127,.15)}
.dsh-relay-entry-btn.on{background:rgba(77,107,254,.16)}
.dsh-relay-qr-view{--r-bg:#fff;--r-head:#fff;--r-fg:#101828;--r-line:#e3e7ee;--r-muted:#5b6577;--r-code:#f4f6f9;--r-chip:#4d6bfe;--r-err:#b42318;--r-err-bg:#fdeeec;--r-shadow:0 12px 32px rgba(16,24,40,.14)}
.dsh-relay-qr-view.dsh-relay-dark{--r-bg:#131a30;--r-head:#131a30;--r-fg:#e6e9f2;--r-line:#26325a;--r-muted:#9aa7c7;--r-code:#0b1020;--r-chip:#4d6bfe;--r-err:#ff8f88;--r-err-bg:#231318;--r-shadow:0 12px 32px rgba(0,0,0,.35)}
.dsh-relay-qr-view{position:fixed;right:16px;bottom:12px;width:350px;max-width:calc(100vw - 32px);z-index:200;display:flex;flex-direction:column;background:var(--r-bg);color:var(--r-fg);border:1px solid var(--r-line);border-radius:14px;box-shadow:var(--r-shadow);font-family:system-ui,-apple-system,'Segoe UI',sans-serif}
.dsh-relay-qr-head{display:flex;gap:6px;align-items:center;padding:8px 12px;background:var(--r-head);border-bottom:1px solid var(--r-line);border-radius:14px 14px 0 0}
.dsh-relay-qr-title{font-size:13px;font-weight:600;margin-right:2px;white-space:nowrap}
.dsh-relay-qr-status{display:flex;align-items:center;gap:5px;font-size:11px;color:var(--r-muted);white-space:nowrap}
.dsh-relay-qr-dot{width:7px;height:7px;border-radius:50%;background:var(--r-muted);flex:none}
.dsh-relay-qr-dot.on{background:#35c46f}
.dsh-relay-qr-close{background:transparent;color:var(--r-muted);border:0;border-radius:6px;padding:6px 8px;font-size:14px;cursor:pointer}
.dsh-relay-qr-close:hover{color:var(--r-fg);background:rgba(127,127,127,.15)}
.dsh-relay-qr-body{display:flex;flex-direction:column;gap:10px;padding:14px;align-items:center}
.dsh-relay-qr-img{width:200px;height:200px;background:#fff;border-radius:10px;padding:8px}
.dsh-relay-qr-url{display:flex;gap:8px;align-items:flex-start;width:100%}
.dsh-relay-qr-code{flex:1;background:var(--r-code);padding:6px 8px;border-radius:8px;font-size:11px;word-break:break-all;border:1px solid var(--r-line);line-height:1.4}
.dsh-relay-qr-btn{background:var(--r-chip);color:#fff;border:0;border-radius:8px;padding:7px 12px;font-size:12px;cursor:pointer;white-space:nowrap;text-decoration:none;display:inline-flex;align-items:center}
.dsh-relay-qr-btn.dsh-relay-qr-warn{background:#a5372b}
.dsh-relay-qr-actions{display:flex;gap:8px;width:100%}
.dsh-relay-qr-actions .dsh-relay-qr-btn{flex:1;justify-content:center}
.dsh-relay-qr-muted{color:var(--r-muted);font-size:12px;text-align:center}
.dsh-relay-qr-link{color:var(--r-chip);text-decoration:none}
.dsh-relay-qr-link:hover{text-decoration:underline}
.dsh-relay-qr-err{padding:8px 12px;font-size:11px;color:var(--r-err);background:var(--r-err-bg);border-top:1px solid var(--r-line);white-space:pre-wrap;width:100%;box-sizing:border-box;border-radius:0 0 14px 14px}
.dsh-relay-qr-remote{display:flex;flex-direction:column;gap:6px;padding:4px 2px 2px}
.dsh-relay-qr-remote-title{font-size:13px;font-weight:600;color:var(--r-fg)}
.dsh-relay-qr-remote-body{font-size:12px;line-height:1.55;color:var(--r-muted)}
`
      document.head.appendChild(style)
    }

    function QrIcon() {
      return h('svg', {
        width: 14, height: 14, viewBox: '0 0 16 16', fill: 'none',
        'aria-hidden': 'true',
      },
        h('rect', { x: 1.5, y: 1.5, width: 5, height: 5, rx: 1, stroke: 'currentColor', strokeWidth: 1.3 }),
        h('rect', { x: 9.5, y: 1.5, width: 5, height: 5, rx: 1, stroke: 'currentColor', strokeWidth: 1.3 }),
        h('rect', { x: 1.5, y: 9.5, width: 5, height: 5, rx: 1, stroke: 'currentColor', strokeWidth: 1.3 }),
        h('path', { d: 'M9.5 9.5h2M13.5 9.5h1M9.5 11.5v1M11.5 11.5h2M9.5 14.5h3M13.5 13v1.5', stroke: 'currentColor', strokeWidth: 1.3, strokeLinecap: 'round' }))
    }

    /**
     * Whether the host UI behind the panel is dark, decided from the nearest
     * opaque background colour. DSH's own stylesheet exposes no palette tokens,
     * so sampling is the only way to stay consistent if it ever ships a dark
     * theme; the panel is light otherwise.
     */
    function hostIsDark() {
      try {
        const dark = (node) => {
          if (!node) return null
          const match = /rgba?\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)(?:[,\s/]+([\d.]+))?/.exec(getComputedStyle(node).backgroundColor || '')
          if (!match) return null
          const alpha = match[4] === undefined ? 1 : Number(match[4])
          if (!(alpha > 0.5)) return null
          const luma = 0.2126 * Number(match[1]) + 0.7152 * Number(match[2]) + 0.0722 * Number(match[3])
          return luma < 128
        }
        for (const node of [document.body, document.documentElement]) {
          const found = dark(node)
          if (found !== null) return found
        }
      } catch (error) {}
      return false
    }

    /**
     * Popover card with the phone entry: QR, link, copy, rotate, and a link to
     * the full console. Feeds the same /relay-bridge/api snapshot as the
     * standalone panel page, so both stay in sync.
     */
    function RelayPanelView({ onClose, t }) {
      const [snap, setSnap] = useState(null)
      const [error, setError] = useState('')
      const [remote, setRemote] = useState(false)
      const remoteRef = useRef(false)
      const [copied, setCopied] = useState(false)
      const [dark] = useState(hostIsDark)

      const refresh = useCallback(async () => {
        // Every poll is a sealed round trip through the relay, so a hidden tab
        // has no reason to ask: phones keep this card open for a long time.
        if (typeof document !== 'undefined' && document.hidden) return
        // Once refused, stop asking: a poll from a phone is a 403 over the
        // relay every 15 seconds, and the answer will not change.
        if (remoteRef.current) return
        try {
          const res = await fetch('/relay-bridge/api')
          // Relayed requests are refused on purpose. Reporting that beats the
          // raw parse error a JSON body would have produced here.
          if (res.status === 403) {
            remoteRef.current = true
            setRemote(true)
            setSnap(null)
            setError('')
            return
          }
          if (!res.ok) throw new Error(`HTTP ${res.status}`)
          const j = await res.json()
          setRemote(false)
          setSnap(j)
          setError('')
        } catch (e) {
          setError(String((e && e.message) || e))
        }
      }, [])

      useEffect(() => {
        void refresh()
        const id = window.setInterval(refresh, 15000)
        return () => window.clearInterval(id)
      }, [refresh])

      useEffect(() => {
        const onKey = (ev) => { if (ev.key === 'Escape') onClose() }
        window.addEventListener('keydown', onKey)
        return () => window.removeEventListener('keydown', onKey)
      }, [onClose])

      const copy = async () => {
        if (!snap || !snap.entryUrl) return
        const text = String(snap.entryUrl)
        try {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text)
          } else {
            // Non-secure context (plain-http relay pages): textarea fallback.
            const area = document.createElement('textarea')
            area.value = text
            area.style.position = 'fixed'
            area.style.opacity = '0'
            document.body.appendChild(area)
            area.select()
            const ok = document.execCommand('copy')
            document.body.removeChild(area)
            if (!ok) throw new Error('execCommand copy failed')
          }
          setCopied(true)
          window.setTimeout(() => setCopied(false), 1500)
        } catch (e) {
          setError(String((e && e.message) || e))
        }
      }

      const regenerate = async () => {
        if (remote) return
        if (!window.confirm(t('regenerateConfirm'))) return
        try {
          const res = await fetch('/relay-bridge/api', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ action: 'regenerate' }),
          })
          if (res.status === 403) {
            setRemote(true)
            setSnap(null)
            return
          }
          const j = await res.json()
          if (!j.ok) throw new Error(j.error || 'regenerate failed')
          setSnap(j.snapshot || snap)
          await refresh()
        } catch (e) {
          setError(String((e && e.message) || e))
        }
      }

      const entry = snap && snap.entryUrl
      const connected = Boolean(snap && snap.connected)

      return h('div', {
        className: `dsh-relay-qr-view${dark ? ' dsh-relay-dark' : ''}`,
        'data-dsh-relay-panel': 'view',
      },
        h('div', { className: 'dsh-relay-qr-head' },
          h('span', { className: 'dsh-relay-qr-title' }, t('title')),
          h('span', { style: { flex: 1 } }),
          remote
            ? null
            : h('span', { className: 'dsh-relay-qr-status' },
              h('span', { className: `dsh-relay-qr-dot${connected ? ' on' : ''}` }),
              connected ? t('statusOpen') : t('statusIdle')),
          h('button', {
            type: 'button', className: 'dsh-relay-qr-close', 'aria-label': t('close'), onClick: onClose,
          }, '✕')),
        h('div', { className: 'dsh-relay-qr-body' },
          remote
            ? h('div', { className: 'dsh-relay-qr-remote' },
              h('div', { className: 'dsh-relay-qr-remote-title' }, t('remoteTitle')),
              h('div', { className: 'dsh-relay-qr-remote-body' }, t('remoteBody')))
            : !snap
            ? h('div', { className: 'dsh-relay-qr-muted' }, t('loading'))
            : h(Fragment, null,
              entry && snap.qr
                ? h('img', { className: 'dsh-relay-qr-img', src: snap.qr, alt: 'QR' })
                : null,
              entry
                ? h('div', { className: 'dsh-relay-qr-url' },
                  h('code', { className: 'dsh-relay-qr-code' }, entry),
                  h('button', { type: 'button', className: 'dsh-relay-qr-btn', onClick: copy },
                    copied ? t('copied') : t('copy')))
                : h('div', { className: 'dsh-relay-qr-muted' },
                  t('unconfigured'), ' ',
                  h('a', {
                    className: 'dsh-relay-qr-link',
                    href: consoleUrl(),
                    target: isElectron ? undefined : '_blank',
                    rel: 'noopener',
                    onClick: openConsole,
                  }, t('configure'))),
              h('div', { className: 'dsh-relay-qr-actions' },
                h('a', {
                  className: 'dsh-relay-qr-btn',
                  href: consoleUrl(),
                  target: isElectron ? undefined : '_blank',
                  rel: 'noopener',
                  onClick: openConsole,
                }, t('openPanel')),
                h('button', {
                  type: 'button', className: 'dsh-relay-qr-btn dsh-relay-qr-warn', onClick: regenerate,
                }, t('regenerate'))))),
        error ? h('div', { className: 'dsh-relay-qr-err', role: 'alert' }, error) : null)
    }

    function RelayPanelEntry({ wide, t }) {
      const [open, setOpen] = useState(false)
      return h(Fragment, null,
        h('button', {
          type: 'button',
          className: `dsh-relay-entry-btn${open ? ' on' : ''}`,
          'data-dsh-relay-panel': 'entry',
          'aria-label': t('trigger'),
          'aria-expanded': open ? 'true' : 'false',
          title: t('trigger'),
          onClick: () => setOpen((v) => !v),
        },
          h(QrIcon, null),
          wide ? h('span', null, t('trigger')) : null),
        open
          ? createPortal(
            h(RelayPanelView, { t, onClose: () => setOpen(false) }), document.body)
          : null)
    }

    function apply(ctx) {
      ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-relay-phone: panel dictionaries')
      // `sidebar.footer.action` is the sidebar shell's list slot above
      // Settings; `slots.inject` waits for ui-sidebar's declaration so load
      // order between the two plugins never matters.
      ctx.slots.inject('sidebar.footer.action', () => {
        ctx.slots.register({
          name: 'sidebar.footer.action',
          id: 'relay-panel',
          order: 10,
          locale: NS,
        }, RelayPanelEntry)
      })
    }

    return { inject: ['slots', 'locale'], apply }
  },
})
