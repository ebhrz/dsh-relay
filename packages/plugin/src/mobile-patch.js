// Mobile enhancement patch injected into every DSH HTML document together
// with the boot script (pump.js). DSH itself is a desktop three-column shell
// that we deliberately do not modify; this layer adapts it on phones only:
//
//   viewport meta   viewport-fit=cover + interactive-widget=resizes-content
//                   (the latter makes Android Chrome shrink the layout
//                   viewport for the keyboard, lifting the sticky composer)
//   MOBILE_CSS      ① pins the AppFrame grid to rail+center below 760px
//                   (an !important stylesheet rule — the solver's inline
//                   style keeps its value but loses the cascade, so React
//                   stays the source of truth and nothing fights observers)
//                   ② hides the 8px drag strips, 44px touch targets, 16px
//                   control font (stops iOS focus zoom), safe-area padding
//   MOBILE_JS       ① iOS keyboard shim (visualViewport → <html> height)
//                   ② Enter inserts a newline on touch keyboards (the
//                     desktop binding needs Shift, which phones lack)
//                   ③ drawer mode: watches the frame's inline
//                     grid-template-columns — React's statement of intent —
//                     and whenever it asks for a wide sidebar or a visible
//                     details column on a phone, that column is dressed as a
//                     fixed overlay drawer. The backdrop closes through the
//                     panel's own toggle/close button click, so React state
//                     stays consistent.
//
// Selectors use [class*="..."] because CSS Modules keep the local class name
// inside the generated name in both dev (`Foo_handle__x`) and build
// (`_handle_x_12`) modes; exact hashes are not knowable at inject time.
// Everything is scoped to (max-width) / (pointer: coarse) media so desktop
// rendering through the relay stays pixel-identical to what DSH ships.

const NARROW = 760
const RAIL = 56 // AppFrame SIDEBAR_COLLAPSED (columns.ts)

export const MOBILE_CSS = `
@media (max-width: ${NARROW}px) {
  /* The frame grid: "<sidebar>px minmax(0, 1fr) <details>px" inline. On a
     phone any wider ask becomes a drawer (MOBILE_JS), so the grid itself is
     always rail + full-width center + closed details here. The inline style
     is left untouched — it is the intent signal the drawer layer reads. */
  [style*="minmax(0, 1fr)"] {
    grid-template-columns: ${RAIL}px minmax(0, 1fr) 0px !important;
  }
  /* Panel drag strips are 8px wide — unhittable by finger, and the drawer
     layer replaces resizing below this width anyway. */
  [class*="handle"][data-side] { display: none !important; }
  html, body { overflow-x: hidden !important; }
  body {
    padding: env(safe-area-inset-top) env(safe-area-inset-right)
      env(safe-area-inset-bottom) env(safe-area-inset-left) !important;
  }
}
@media (pointer: coarse) {
  /* 44px targets for the small icon controls (send 34px, attach 28px,
     message actions 28px, sidebar toggle 28px by default). */
  button[class*="primary"], button[class*="add"], button[class*="iconButton"],
  button[class*="toggle"], button[class*="action"], button[class*="close"],
  button[class*="retry"] {
    min-height: 44px;
    min-width: 44px;
  }
  select[class*="select"] { min-height: 44px; }
  /* iOS zooms the whole page when an input smaller than 16px gets focus. */
  input, select, textarea { font-size: 16px !important; }
  /* Kill the double-tap-zoom delay on controls without disabling pinch. */
  button, a, [role="button"] { touch-action: manipulation; }
}
`

export const MOBILE_JS = `
(function () {
'use strict'
if (window.__dshRelayMobile) return
window.__dshRelayMobile = true
var coarse = false
try { coarse = matchMedia('(pointer: coarse)').matches } catch (e) {}

// 1. iOS keyboard: the shell is a height:100% chain and Safari does not
//    shrink the layout viewport for the keyboard, so the sticky composer
//    ends up underneath it. Shrinking <html> to the visual viewport lifts
//    the whole shell (Android already handles this via the viewport meta).
try {
  if (coarse && window.visualViewport) {
    var vv = window.visualViewport
    var vvApply = function () {
      if (window.innerHeight - vv.height > 80) {
        document.documentElement.style.height = Math.round(vv.height) + 'px'
      } else {
        document.documentElement.style.height = ''
      }
    }
    vv.addEventListener('resize', vvApply)
  }
} catch (e) {}

// 2. Enter = newline on touch (desktop: Enter sends, Shift+Enter breaks the
//    line — a phone keyboard has no Shift). execCommand keeps React's
//    controlled textarea in sync; the native-setter fallback covers engines
//    where execCommand fails. The send button still sends.
try {
  if (coarse) {
    var nativeSetter = null
    try {
      nativeSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set
    } catch (e) {}
    document.addEventListener('keydown', function (ev) {
      if (ev.key !== 'Enter' || ev.shiftKey || ev.ctrlKey || ev.metaKey || ev.altKey) return
      // IME composition: Enter here confirms the pinyin candidates, it must
      // reach the editor untouched (matches DSH's own isComposing guard).
      if (ev.isComposing || ev.keyCode === 229) return
      var ta = ev.target
      if (!ta || ta.tagName !== 'TEXTAREA' || ta.readOnly || ta.disabled) return
      ev.preventDefault()
      var ok = false
      try { ok = document.execCommand('insertText', false, '\\n') } catch (e) {}
      if (!ok && nativeSetter) {
        var start = ta.selectionStart, end = ta.selectionEnd
        nativeSetter.call(ta, ta.value.slice(0, start) + '\\n' + ta.value.slice(end))
        ta.selectionStart = ta.selectionEnd = start + 1
        ta.dispatchEvent(new Event('input', { bubbles: true }))
      }
    }, true)
  }
} catch (e) {}

// 3. Drawer mode below ${NARROW}px. The AppFrame writes its solved column
//    widths as an inline grid-template-columns on the frame element
//    ("<sidebar>px minmax(0, 1fr) <details>px"; DOM children sidebar,
//    center, details, then a [data-shell-overlay] layer). MOBILE_CSS pins
//    the rendered grid; this layer READS that inline value as React's
//    intent and dresses the asking column as a fixed drawer. Closing goes
//    through the panel's own toggle/close buttons, so React state stays
//    the source of truth and re-renders converge by themselves.
try {
  var GRID_RE = /^(\\d+)px minmax\\(0, 1fr\\) (\\d+)px$/
  var frame = null, sidebarCol = null, detailsCol = null
  var backdrop = null
  var mqNarrow = matchMedia('(max-width: ${NARROW}px)')

  function findFrame() {
    if (frame && document.contains(frame) && frame.querySelector('[data-shell-overlay]')) {
      var kids = frame.children
      if (kids.length >= 3) { sidebarCol = kids[0]; detailsCol = kids[2]; return true }
    }
    frame = null; sidebarCol = null; detailsCol = null
    var nodes = document.querySelectorAll('[style*="minmax(0, 1fr)"]')
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].querySelector('[data-shell-overlay]') && nodes[i].children.length >= 3) {
        frame = nodes[i]
        sidebarCol = frame.children[0]
        detailsCol = frame.children[2]
        return true
      }
    }
    return false
  }

  function ensureBackdrop() {
    if (backdrop && backdrop.isConnected) return backdrop
    backdrop = document.createElement('div')
    var s = backdrop.style
    s.position = 'fixed'; s.inset = '0'
    s.background = 'rgba(0,0,0,.45)'
    s.zIndex = '2147482999'
    s.display = 'none'
    backdrop.addEventListener('click', function () {
      // Close the transient one first: details, then sidebar.
      if (detailsCol && detailsCol.style.position === 'fixed') {
        var closeBtn = detailsCol.querySelector('button[class*="close"]')
        if (closeBtn) { closeBtn.click(); return }
      }
      if (sidebarCol && sidebarCol.style.position === 'fixed') {
        var toggle = sidebarCol.querySelector('button[class*="toggle"]')
        if (toggle) toggle.click()
      }
    })
    ;(document.body || document.documentElement).appendChild(backdrop)
    return backdrop
  }

  function dress(col, side, width) {
    var s = col.style
    s.position = 'fixed'
    s.top = '0'
    s.bottom = 'env(safe-area-inset-bottom, 0px)'
    s[side] = '0'
    s.width = width
    s.maxWidth = '100vw'
    s.zIndex = '2147483000'
    s.background = 'var(--dsw-alias-bg-base, #fff)'
    s.boxShadow = '0 0 32px rgba(0,0,0,.35)'
  }

  function undress(col, side) {
    if (!col) return
    var s = col.style
    s.position = ''; s.top = ''; s.bottom = ''; s[side] = ''
    s.width = ''; s.maxWidth = ''; s.zIndex = ''; s.background = ''
    s.boxShadow = ''
  }

  function apply() {
    if (!mqNarrow.matches) { teardown(); return }
    if (!findFrame()) { teardown(); return }
    var m = GRID_RE.exec(frame.style.gridTemplateColumns || '')
    if (!m) { teardown(); return }
    var sidebarW = +m[1], detailsW = +m[2]
    var anyDrawer = false

    if (sidebarW > ${RAIL}) {
      dress(sidebarCol, 'left', sidebarW + 'px')
      anyDrawer = true
    } else {
      undress(sidebarCol, 'left')
    }
    if (detailsW > 0) {
      dress(detailsCol, 'right', 'min(92vw, ' + detailsW + 'px)')
      anyDrawer = true
    } else {
      undress(detailsCol, 'right')
    }

    ensureBackdrop().style.display = anyDrawer ? 'block' : 'none'
  }

  function teardown() {
    undress(sidebarCol, 'left')
    undress(detailsCol, 'right')
    if (backdrop) backdrop.style.display = 'none'
  }

  // The frame mounts late (client modules load after the shell HTML), so
  // poll cheaply until it exists, then watch its style attribute.
  var timer = setInterval(function () {
    try {
      if (frame) return // the style observer owns updates from here on
      apply()
      if (frame) {
        new MutationObserver(apply).observe(frame, { attributes: true, attributeFilter: ['style'] })
        mqNarrow.addEventListener('change', apply)
        clearInterval(timer)
      }
    } catch (e) {}
  }, 700)
} catch (e) {}
})()
`

/**
 * Upgrade the document's viewport meta for phone ergonomics:
 * viewport-fit=cover (safe-area insets become usable) and
 * interactive-widget=resizes-content (Android Chrome resizes the layout
 * viewport when the keyboard opens instead of covering the page).
 * Idempotent; returns the body unchanged when no viewport meta exists.
 */
export function enhanceViewportMeta(body) {
  const tagMatch = /<meta\s+[^>]*name=["']viewport["'][^>]*>/i.exec(body)
  if (!tagMatch) return body
  const tag = tagMatch[0]
  const content = /content=["']([^"']*)["']/i.exec(tag)?.[1] ?? ''
  const parts = content.split(',').map((p) => p.trim()).filter(Boolean)
  const has = (key) => parts.some((p) => p === key || p.startsWith(`${key}=`))
  let changed = false
  for (const extra of ['viewport-fit=cover', 'interactive-widget=resizes-content']) {
    const key = extra.split('=')[0]
    if (!has(key)) { parts.push(extra); changed = true }
  }
  if (!changed) return body
  const rebuilt = tag.replace(/content=["'][^"']*["']/i, `content="${parts.join(', ')}"`)
  return body.replace(tag, rebuilt)
}
