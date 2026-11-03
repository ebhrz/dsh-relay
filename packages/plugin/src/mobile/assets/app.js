/* DSH Remote — purpose-built mobile companion for DeepSeek Harness.
 *
 * Talks only to the plugin's own mobile API (`/__relay/m/rpc` + a sealed
 * WebSocket), so the phone renders a small native-feeling chat UI instead of
 * replaying the desktop three-column web app. No frameworks, no build step:
 * this file is served directly by dsh-relay-bridge under /c/<device>/m.
 *
 * Wire frames (host side: packages/plugin/src/mobile/bridge.js):
 *   rpc  {id, method, params} -> {id, ok, result|error}
 *   ws   {t:'session'|'items'|'assistant-stream'|'status'|'title'|'row'|
 *            'row-changed'|'row-removed'|'interaction'|'interaction-done'|
 *            'toast'|'error'}
 */
(function () {
  'use strict'

  // ── environment ────────────────────────────────────────────────────────
  var pathname = location.pathname.replace(/\/m\/?$/, '') || ''
  var PREFIX = pathname
  var GATE = new URLSearchParams(location.search).get('g') || ''
  var app = document.getElementById('app')
  var $ = function (id) { return document.getElementById(id) }
  var itemsEl = $('items')
  var streamEl = $('stream')
  var inputEl = $('input')
  var sendBtn = $('sendBtn')
  var stopBtn = $('stopBtn')
  var scrim = $('scrim')
  var drawer = $('drawer')

  var state = {
    booted: false,
    connected: false,
    connection: 'connecting',
    sessions: [],
    currentId: null,
    title: null,
    meta: {},
    running: false,
    items: [],
    byId: new Map(),
    pendingUsers: new Map(),
    cursor: -1,
    hasMore: false,
    oldestSeq: null,
    streaming: null,
    interactions: new Map(),
    loadingOlder: false,
    drawerOpen: false,
    stick: true,
    version: null,
    deviceId: null,
    upstream: true,
    fatal: false,
    model: null,
    modelCatalog: null,
    modelDefault: null,
    lastModel: loadLastModel(),
    openCards: new Set(),
    closedCards: new Set(),
    settings: loadSettings(),
    permissionCatalog: null,
    permissions: null,
    workspaces: [],
    collapsed: loadCollapsedProjects(),
    pendingImages: [],
    imageCache: new Map(),
    terminal: {
      open: false,
      id: null,
      name: null,
      polling: false,
      timer: null,
      busy: false,
    },
  }

  // ── crypto ─────────────────────────────────────────────────────────────
  var envKey = null
  var psk = null

  function readPsk() {
    try {
      var saved = localStorage.getItem('dshRelayK')
      if (!saved) return null
      var b64 = saved.replace(/-/g, '+').replace(/_/g, '/')
      while (b64.length % 4) b64 += '='
      var raw = atob(b64)
      var bytes = new Uint8Array(raw.length)
      for (var i = 0; i < raw.length; i += 1) bytes[i] = raw.charCodeAt(i)
      if (bytes.length < 32) return null
      return bytes.slice(0, 32)
    } catch (error) {
      return null
    }
  }

  function initCrypto() {
    psk = readPsk()
    if (!psk || !window.nacl) return false
    var msg = new Uint8Array(psk.length + 8)
    msg.set(psk, 0)
    msg.set(new TextEncoder().encode('envelope'), psk.length)
    envKey = nacl.hash(msg).slice(0, 32)
    return true
  }

  function seal(bytes) {
    var nonce = nacl.randomBytes(24)
    var box = nacl.secretbox(bytes, nonce, envKey)
    var out = new Uint8Array(24 + box.length)
    out.set(nonce, 0)
    out.set(box, 24)
    return out
  }

  function openEnvelope(bytes) {
    try {
      if (bytes.length < 24 + 16) return null
      var opened = nacl.secretbox.open(bytes.slice(24), bytes.slice(0, 24), envKey)
      return opened ? new Uint8Array(opened) : null
    } catch (error) {
      return null
    }
  }

  // ── transport: sealed RPC ──────────────────────────────────────────────
  var rpcSeq = 0

  async function rpc(method, params) {
    if (!envKey) throw new Error('未配对：缺少密钥')
    var id = ++rpcSeq
    var payload = JSON.stringify({ id: id, method: method, params: params || {} })
    var body = seal(new TextEncoder().encode(payload))
    var res = await fetch(PREFIX + '/__relay/m/rpc?g=' + encodeURIComponent(GATE), {
      method: 'POST',
      credentials: 'include',
      cache: 'no-store',
      headers: {
        'content-type': 'application/octet-stream',
        'x-relay-enc': '1',
        'x-relay-ct': 'application/json',
      },
      body: body,
    })
    if (!res.ok) throw transportError('HTTP ' + res.status)
    var plain = openEnvelope(new Uint8Array(await res.arrayBuffer()))
    if (!plain) throw transportError('无法解密响应（可能需要重新配对）')
    var text = new TextDecoder().decode(plain)
    var split = text.indexOf('\r\n\r\n')
    if (split === -1) throw transportError('响应格式错误')
    var status = Number((text.slice(0, split).match(/^HTTP\/[\d.]+\s+(\d+)/) || [])[1] || 0)
    var json
    try {
      json = JSON.parse(text.slice(split + 4))
    } catch (error) {
      throw transportError('响应不是 JSON')
    }
    if (status !== 200 || !json || json.ok !== true) {
      var error = json && json.error ? json.error : { code: 'http-' + status, message: '请求失败' }
      throw rpcError(error.code, error.message)
    }
    return json.result
  }

  function transportError(message) {
    var error = new Error(message)
    error.code = 'transport'
    return error
  }

  function rpcError(code, message) {
    var error = new Error(message || code)
    error.code = code
    return error
  }

  // ── transport: sealed push channel ─────────────────────────────────────
  var ws = null
  var wsRetry = 0
  var wsRetryTimer = null
  var wsPingTimer = null
  var pendingSubscribe = false

  function wsUrl() {
    var scheme = location.protocol === 'https:' ? 'wss:' : 'ws:'
    return scheme + '//' + location.host + PREFIX + '/__relay/m/ws?g=' + encodeURIComponent(GATE)
  }

  function connectWs() {
    if (state.fatal) return
    clearTimeout(wsRetryTimer)
    setConnection('connecting')
    var socket
    try {
      socket = new WebSocket(wsUrl())
    } catch (error) {
      scheduleReconnect()
      return
    }
    ws = socket
    socket.onopen = function () {
      wsRetry = 0
      setConnection('open')
      startPing()
      if (state.currentId) sendWs({ t: 'subscribe', sessionId: state.currentId })
      // Reconnect after a drop: re-read the row list (status may have moved).
      refreshSessions().catch(function () {})
    }
    socket.onmessage = function (event) {
      if (typeof event.data !== 'string') return
      var frame
      try {
        var outer = JSON.parse(event.data)
        var plain = outer && typeof outer.__relay === 'string'
          ? openEnvelope(base64ToBytes(outer.__relay))
          : null
        if (!plain) return
        frame = JSON.parse(new TextDecoder().decode(plain))
      } catch (error) {
        return
      }
      handleFrame(frame)
    }
    socket.onclose = function () {
      if (ws === socket) ws = null
      stopPing()
      setConnection('closed')
      scheduleReconnect()
    }
    socket.onerror = function () {
      try { socket.close() } catch (error) {}
    }
  }

  function scheduleReconnect() {
    if (state.fatal) return
    clearTimeout(wsRetryTimer)
    wsRetry += 1
    var delay = Math.min(8000, 500 * Math.pow(1.6, Math.min(wsRetry, 8)))
    wsRetryTimer = setTimeout(connectWs, delay)
  }

  function startPing() {
    stopPing()
    wsPingTimer = setInterval(function () {
      if (ws && ws.readyState === 1) sendWs({ t: 'ping' })
    }, 20000)
  }

  function stopPing() {
    clearInterval(wsPingTimer)
    wsPingTimer = null
  }

  function sendWs(message) {
    if (!ws || ws.readyState !== 1 || !envKey) return false
    var sealed = seal(new TextEncoder().encode(JSON.stringify(message)))
    ws.send(JSON.stringify({ __relay: bytesToBase64(sealed) }))
    return true
  }

  function subscribe(sessionId) {
    if (!sessionId) return
    if (!sendWs({ t: 'subscribe', sessionId: sessionId })) pendingSubscribe = true
  }

  function bytesToBase64(bytes) {
    var bin = ''
    for (var i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i])
    return btoa(bin)
  }

  function base64ToBytes(text) {
    var bin = atob(text)
    var out = new Uint8Array(bin.length)
    for (var i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i)
    return out
  }

  function setConnection(value) {
    var changed = state.connection !== value
    state.connection = value
    state.connected = value === 'open'
    var dot = $('connDot')
    if (dot) dot.setAttribute('data-state', value)
    if (value === 'closed' && changed) {
      setBanner('连接已断开，正在重连…')
    } else if (value === 'open') {
      clearBanner()
      if (pendingSubscribe && state.currentId) {
        pendingSubscribe = false
        subscribe(state.currentId)
      }
      if (state.booted) refreshSessions().catch(function () {})
    }
    updateComposer()
  }

  // ── frame handling ─────────────────────────────────────────────────────
  function handleFrame(frame) {
    if (!frame || typeof frame.t !== 'string') return
    switch (frame.t) {
      case 'session':
        onSessionFrame(frame)
        break
      case 'items':
        onItemsFrame(frame)
        break
      case 'assistant-stream':
        onStreamFrame(frame)
        break
      case 'status':
        onStatusFrame(frame)
        break
      case 'title':
        onTitleFrame(frame)
        break
      case 'permission':
        onPermissionFrame(frame)
        break
      case 'row':
        upsertSession(frame.row)
        break
      case 'row-changed':
        scheduleSessionRefresh()
        break
      case 'row-removed':
        state.sessions = state.sessions.filter(function (row) { return row.id !== frame.sessionId })
        renderSessions()
        break
      case 'interaction':
        upsertInteraction(frame.interaction)
        break
      case 'interaction-done':
        finishInteraction(frame.key)
        break
      case 'toast':
        toast(frame.message)
        break
      case 'error':
        setBanner(frame.message || '出错了', true)
        break
      case 'pong':
        break
      default:
        break
    }
  }

  function onSessionFrame(frame) {
    if (frame.sessionId !== state.currentId) return
    state.title = frame.title || state.title
    state.meta = frame.meta || {}
    state.running = frame.running === true
    state.cursor = Number.isFinite(frame.cursor) ? frame.cursor : -1
    state.hasMore = frame.hasMore === true
    state.streaming = normalizeInitialStream(frame.stream)
    var projectedModel = frame.projections && frame.projections.modelSelection
    state.model = (projectedModel && projectedModel.lastUsed) || (findSession(state.currentId) || {}).model || null
    if (!state.model) adoptDefaultDisplay()
    state.permissions = frame.permissions
      || (frame.projections && frame.projections.permissions)
      || null
    state.items = Array.isArray(frame.items) ? frame.items.slice() : []
    state.byId = new Map()
    for (var i = 0; i < state.items.length; i += 1) state.byId.set(state.items[i].id, state.items[i])
    state.pendingUsers.clear()
    state.oldestSeq = oldestSeqOf(state.items)
    renderAll()
    updateSessionChrome()
    if (state.stick) scrollToBottom(true)
    else showJump(true)
    // Continued/pending interactions for this session follow as frames; keep
    // the ones already shown, drop stale ones from other sessions.
    renderInteractions()
  }

  function normalizeInitialStream(stream) {
    if (!stream || (!stream.text && !stream.reasoning)) return null
    return {
      attemptId: stream.attemptId || 'snapshot',
      revision: stream.revision,
      text: stream.text || '',
      reasoning: stream.reasoning || '',
    }
  }

  function onItemsFrame(frame) {
    if (frame.sessionId !== state.currentId) return
    var added = Array.isArray(frame.added) ? frame.added : []
    var updated = Array.isArray(frame.updated) ? frame.updated : []
    var appended = []
    for (var i = 0; i < added.length; i += 1) {
      var item = added[i]
      if (!item || !item.id || state.byId.has(item.id)) continue
      if (item.kind === 'user' && item.requestId) removePendingUser(item.requestId)
      state.items.push(item)
      state.byId.set(item.id, item)
      appended.push(item)
      if (item.seq && (!state.oldestSeq || item.seq < state.oldestSeq)) state.oldestSeq = item.seq
    }
    if (Number.isFinite(frame.cursor)) state.cursor = frame.cursor
    if (appended.length) appendItemElements(appended)
    for (var j = 0; j < updated.length; j += 1) {
      var patch = updated[j]
      var existing = state.byId.get(patch && patch.id)
      if (!existing) continue
      Object.assign(existing, patch)
      updateItemElement(existing)
    }
    // A committed assistant message supersedes the streamed partial once the
    // stream ends; clearing here too covers a dropped 'end' frame.
    if (appended.some(function (item) { return item.kind === 'assistant' })) {
      if (state.streaming && lastStreamFrameTime < Date.now() - 500) clearStreaming()
    }
    if (state.stick) scrollToBottom(false)
    else if (appended.length) showJump(true)
  }

  var lastStreamFrameTime = 0

  function onStreamFrame(frame) {
    if (frame.sessionId !== state.currentId || !frame.frame) return
    var inner = frame.frame
    lastStreamFrameTime = Date.now()
    if (inner.type === 'start') {
      state.streaming = { attemptId: inner.attemptId, revision: inner.revision, text: '', reasoning: '' }
      renderStreaming()
      if (state.stick) scrollToBottom(false)
      setTyping(false)
      return
    }
    if (!state.streaming) {
      if (inner.type === 'chunk') {
        state.streaming = { attemptId: inner.attemptId, revision: inner.revision, text: '', reasoning: '' }
      } else {
        return
      }
    }
    if (inner.attemptId && state.streaming.attemptId && inner.attemptId !== state.streaming.attemptId) {
      state.streaming = { attemptId: inner.attemptId, revision: inner.revision, text: '', reasoning: '' }
    }
    if (inner.type === 'chunk' && inner.chunk) {
      var chunk = inner.chunk
      if (chunk.type === 'text-delta' && typeof chunk.text === 'string') {
        state.streaming.text += chunk.text
      } else if (chunk.type === 'reasoning-delta' && typeof chunk.text === 'string') {
        state.streaming.reasoning += chunk.text
      }
      scheduleStreamingRender()
      if (state.stick) scrollToBottom(false)
      return
    }
    if (inner.type === 'end') {
      var outcome = inner.outcome || {}
      if (outcome.kind === 'committed' || outcome.kind === 'abandoned') {
        clearStreaming()
      }
    }
  }

  var streamRenderQueued = false

  function scheduleStreamingRender() {
    if (streamRenderQueued) return
    streamRenderQueued = true
    requestAnimationFrame(function () {
      streamRenderQueued = false
      renderStreaming()
    })
  }

  function onStatusFrame(frame) {
    if (frame.sessionId === state.currentId) {
      state.running = frame.running === true
      if (!state.running) setTyping(false)
      updateSessionChrome()
    }
    for (var i = 0; i < state.sessions.length; i += 1) {
      if (state.sessions[i].id === frame.sessionId) {
        state.sessions[i].running = frame.running === true
        state.sessions[i].updatedAt = Math.max(state.sessions[i].updatedAt || 0, Date.now())
        break
      }
    }
    renderSessions()
  }

  function onTitleFrame(frame) {
    if (frame.sessionId === state.currentId) {
      state.title = frame.title
      updateSessionChrome()
    }
    for (var i = 0; i < state.sessions.length; i += 1) {
      if (state.sessions[i].id === frame.sessionId) state.sessions[i].title = frame.title
    }
    renderSessions()
  }

  // ── sessions list ──────────────────────────────────────────────────────
  var refreshTimer = null
  var refreshPending = false

  function scheduleSessionRefresh() {
    if (refreshTimer) { refreshPending = true; return }
    refreshTimer = setTimeout(function () {
      refreshTimer = null
      refreshSessions().catch(function () {})
      if (refreshPending) { refreshPending = false; scheduleSessionRefresh() }
    }, 600)
  }

  async function refreshSessions() {
    var result = await rpc('sessions', {})
    var next = Array.isArray(result.sessions) ? result.sessions : []
    // Keep local live flags when the list is briefly stale.
    for (var i = 0; i < next.length; i += 1) {
      var local = findSession(next[i].id)
      if (local && local.running) next[i].running = true
    }
    state.sessions = next
    state.workspaces = Array.isArray(result.workspaces) ? result.workspaces : []
    renderSessions()
    if (!state.currentId && next.length) {
      selectSession(pickInitialSession(next))
    } else if (state.currentId && !findSession(state.currentId)) {
      state.currentId = null
      renderAll()
      if (next.length) selectSession(pickInitialSession(next))
    }
    if (!next.length) renderEmpty('empty')
  }

  function pickInitialSession(rows) {
    for (var i = 0; i < rows.length; i += 1) {
      if (!rows[i].blank && rows[i].id) return rows[i].id
    }
    return rows[0] && rows[0].id
  }

  function findSession(id) {
    for (var i = 0; i < state.sessions.length; i += 1) {
      if (state.sessions[i].id === id) return state.sessions[i]
    }
    return null
  }

  function upsertSession(row) {
    if (!row || !row.id) return
    var found = false
    for (var i = 0; i < state.sessions.length; i += 1) {
      if (state.sessions[i].id === row.id) {
        state.sessions[i] = Object.assign({}, state.sessions[i], row)
        found = true
        break
      }
    }
    if (!found) state.sessions.push(row)
    state.sessions.sort(function (a, b) { return (b.updatedAt || 0) - (a.updatedAt || 0) })
    renderSessions()
    if (state.currentId === row.id) updateSessionChrome()
  }

  function selectSession(id) {
    if (!id || id === state.currentId) { if (id) subscribe(id); closeDrawer(); return }
    state.currentId = id
    var row = findSession(id)
    state.title = row && row.title ? row.title : null
    state.model = (row && row.model) || null
    clearPendingImages()
    if (state.terminal.open) closeTerminal()
    state.running = Boolean(row && row.running)
    state.items = []
    state.byId = new Map()
    state.pendingUsers.clear()
    state.streaming = null
    state.openCards.clear()
    state.closedCards.clear()
    state.interactions.clear()
    state.cursor = -1
    state.hasMore = false
    state.oldestSeq = null
    state.stick = true
    itemsEl.innerHTML = ''
    renderInteractions()
    updateSessionChrome()
    renderEmpty('loading')
    subscribe(id)
    closeDrawer()
    refreshSessions().catch(function () {})
  }

  async function createSession() {
    try {
      var result = await rpc('create', {})
      await refreshSessions()
      if (result.sessionId) selectSession(result.sessionId)
    } catch (error) {
      toast(error.message || '新建会话失败')
    }
  }

  // ── rendering: chrome ──────────────────────────────────────────────────
  function setBanner(text, isError) {
    var banner = $('banner')
    if (!text) { banner.hidden = true; return }
    banner.hidden = false
    banner.textContent = text
    banner.className = 'banner' + (isError ? ' err' : '')
  }

  function clearBanner() {
    setBanner('')
  }

  function updateSessionChrome() {
    var title = state.title || (state.currentId ? '会话' : 'DSH Remote')
    $('sessionTitle').textContent = title
    var pieces = []
    if (state.running) pieces.push('运行中')
    if (state.meta && state.meta.cwd) pieces.push(basename(state.meta.cwd))
    if (state.version) pieces.push('v' + state.version)
    if (!state.currentId) pieces.push('未选择会话')
    $('sessionSub').textContent = pieces.join(' · ') || 'DSH Remote'
    updateComposer()
    updateModelChip()
    updatePermChip()
    renderSessions()
  }

  function updateComposer() {
    var hasContent = inputEl.value.trim() !== '' || state.pendingImages.length > 0
    sendBtn.disabled = !(state.connected && !state.fatal && hasContent)
    stopBtn.hidden = !state.running
    inputEl.disabled = state.fatal
    var attach = $('attachBtn')
    if (attach) attach.disabled = !state.connected || !state.currentId || state.fatal
  }

  // ── rendering: empty / fatal ───────────────────────────────────────────
  function renderEmpty(mode) {
    var empty = $('empty')
    if (mode === null) { empty.hidden = true; return }
    empty.hidden = false
    var html = ''
    if (mode === 'loading') {
      html = '<div class="typing"><i></i><i></i><i></i></div><div class="small">正在打开会话…</div>'
    } else if (mode === 'fatal') {
      html = '<div class="logo">!</div><div class="big">无法连接</div>'
        + '<div class="small">' + escapeHtml(state.fatalMessage || '手机页初始化失败') + '</div>'
        + '<button class="btn primary" id="retryBtn" style="margin-top:10px">重试</button>'
    } else if (mode === 'empty-session') {
      html = '<div class="logo">DSH</div><div class="big">开始对话</div>'
        + '<div class="small">在下面输入内容，让 agent 开始工作。运行中可以随时查看工具卡片、审批和提问。</div>'
    } else {
      html = '<div class="logo">DSH</div><div class="big">远程控制你的 DSH</div>'
        + '<div class="small">选一个会话，或从左上角新建会话开始。手机页只保留聊天、工具卡片和审批这些常用能力。</div>'
        + '<button class="btn primary" id="newFromEmpty" style="margin-top:14px">新建会话</button>'
    }
    empty.innerHTML = html
    var retry = $('retryBtn')
    if (retry) retry.addEventListener('click', function () { location.reload() })
    var createBtn = $('newFromEmpty')
    if (createBtn) createBtn.addEventListener('click', createSession)
  }

  function fatal(message) {
    state.fatal = true
    state.fatalMessage = message
    renderEmpty('fatal')
    setConnection('closed')
    updateComposer()
  }

  // ── rendering: session items ───────────────────────────────────────────
  function renderAll() {
    itemsEl.innerHTML = ''
    var frag = document.createDocumentFragment()
    for (var i = 0; i < state.items.length; i += 1) {
      var node = buildItem(state.items[i])
      if (node) frag.appendChild(node)
    }
    var pending = state.pendingUsers.values()
    for (var next = pending.next(); !next.done; next = pending.next()) {
      frag.appendChild(buildItem(next.value))
    }
    itemsEl.appendChild(frag)
    renderStreaming()
    renderInteractions()
    if (state.items.length === 0 && !state.streaming) {
      renderEmpty('empty-session')
    } else {
      renderEmpty(null)
    }
  }

  function renderEmptyForSession() {
    renderEmpty('empty-session')
  }

  function appendItemElements(list) {
    var frag = document.createDocumentFragment()
    for (var i = 0; i < list.length; i += 1) {
      var node = buildItem(list[i])
      if (node) frag.appendChild(node)
    }
    itemsEl.appendChild(frag)
    if (list.length > 0) renderEmpty(null)
    renderInteractions()
  }

  function updateItemElement(item) {
    var node = itemsEl.querySelector('[data-item-id="' + cssEscape(item.id) + '"]')
    if (!node) { appendItemElements([item]); return }
    var replacement = buildItem(item)
    if (replacement) node.replaceWith(replacement)
  }

  function buildItem(item) {
    if (!item || !item.kind) return null
    // Display settings decide whether these rows exist at all; the default
    // keeps them as one collapsed line so nothing is silently dropped.
    if (item.kind === 'reasoning' && state.settings.reasoning === 'hidden') return null
    if (item.kind === 'tool' && state.settings.tools === 'hidden') return null
    var node = document.createElement('div')
    node.className = 'item ' + item.kind
    node.setAttribute('data-item-id', item.id)
    if (item.pending && item.requestId) node.setAttribute('data-pending-request', item.requestId)
    switch (item.kind) {
      case 'user': {
        var bubble = document.createElement('div')
        bubble.className = 'bubble'
        bubble.textContent = item.text
        node.appendChild(bubble)
        break
      }
      case 'assistant': {
        var who = document.createElement('div')
        who.className = 'who'
        who.innerHTML = '<span class="mark">DSH</span><span>' + escapeHtml(modelLabel(item.model)) + '</span>'
        var body = document.createElement('div')
        body.className = 'body'
        body.innerHTML = renderMarkdown(item.text || '')
        if (item.interrupted) {
          var stopped = document.createElement('span')
          stopped.className = 'stopped'
          stopped.textContent = '（已中断）'
          body.appendChild(stopped)
        }
        node.appendChild(who)
        node.appendChild(body)
        break
      }
      case 'reasoning': {
        var head = document.createElement('div')
        head.className = 'r-head'
        head.innerHTML = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3a6 6 0 0 0-3.5 10.9V17h7v-3.1A6 6 0 0 0 12 3Z"/><path d="M9 21h6"/></svg><span>思考</span>'
        // A preview line keeps the reasoning recognizable while collapsed.
        var rpreview = document.createElement('span')
        rpreview.className = 'r-preview'
        rpreview.textContent = cut(String(item.text || '').replace(/\s+/g, ' ').trim(), 90)
        head.appendChild(rpreview)
        var rbody = document.createElement('div')
        rbody.className = 'r-body'
        rbody.textContent = item.text || ''
        if (itemOpen(item, state.settings.reasoning)) node.classList.add('open')
        head.addEventListener('click', function () {
          node.classList.toggle('open')
          item.open = node.classList.contains('open')
        })
        node.appendChild(head)
        node.appendChild(rbody)
        break
      }
      case 'tool':
        node.appendChild(buildToolCard(item))
        break
      case 'image':
        return buildImageItem(item)
      case 'status': {
        node.textContent = item.text || ''
        break
      }
      case 'divider': {
        node.textContent = item.text || ''
        break
      }
      case 'error': {
        var card = document.createElement('div')
        card.className = 'card'
        card.textContent = item.text || '出错了'
        node.appendChild(card)
        break
      }
      case 'approval-history': {
        var ac = document.createElement('div')
        ac.className = 'card'
        ac.innerHTML = '<strong>审批 · ' + escapeHtml(item.toolName) + '</strong>'
          + (item.reason ? '<div style="color:var(--muted);font-size:13px;margin-top:3px">' + escapeHtml(item.reason) + '</div>' : '')
          + (item.outcome ? '<div style="font-size:12px;margin-top:4px;color:var(--muted)">结果：' + escapeHtml(approvalOutcomeLabel(item.outcome)) + '</div>' : '')
        ac.style.padding = '9px 12px'
        ac.style.fontSize = '13px'
        ac.style.background = 'var(--card)'
        node.appendChild(ac)
        break
      }
      default:
        return null
    }
    // Long-press a turn to fork the conversation at that point (or copy it).
    if (item.kind === 'user' || item.kind === 'assistant') {
      attachLongPress(node, function () { openItemActions(item) })
    }
    return node
  }

  function buildToolCard(item) {
    var wrap = document.createElement('div')
    wrap.className = 'card'
    if (cardOpen(item, state.settings.tools)) wrap.classList.add('open')
    wrap.classList.add('tool-card')
    var head = document.createElement('div')
    head.className = 'tool-head'
    var stateText = item.status === 'running' ? '运行中' : item.status === 'error' ? '失败' : '完成'
    var stateClass = item.status === 'running' ? 'run' : item.status === 'error' ? 'err' : 'ok'
    head.innerHTML = '<span class="tool-ico">' + toolIcon(item.name) + '</span>'
      + '<span class="tool-name">' + escapeHtml(shortToolName(item.name)) + '</span>'
      + '<span class="tool-state ' + stateClass + '">' + stateText + '</span>'
      + '<svg class="tool-chev" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>'
    var detail = document.createElement('div')
    detail.className = 'tool-detail'
    // The command/path is the reason people open the card, so it gets its own
    // unescaped block before the raw JSON (which is hard to read on a phone).
    var primary = toolPrimary(item)
    if (primary) {
      detail.appendChild(labelEl(primary.label))
      var command = preEl(primary.value)
      command.classList.add('tool-primary')
      detail.appendChild(command)
    }
    if (item.args) {
      detail.appendChild(labelEl(primary ? '参数（原始 JSON）' : '参数'))
      detail.appendChild(preEl(item.args))
    }
    if (item.result) {
      detail.appendChild(labelEl(item.isError ? '错误输出' : '输出'))
      var pre = preEl(truncate(item.result, 12000))
      if (item.isError) pre.classList.add('failed')
      detail.appendChild(pre)
    }
    if (item.error) {
      detail.appendChild(labelEl('错误'))
      detail.appendChild(preEl(item.error))
    }
    // The whole card toggles: the head alone was a small target, and tapping the
    // command preview (the obvious place) did nothing. Text inside the expanded
    // output stays selectable.
    wrap.addEventListener('click', function (event) {
      var target = event.target
      if (target && target.closest && target.closest('pre, code, a')) return
      wrap.classList.toggle('open')
      item.open = wrap.classList.contains('open')
      setCardOpen(item, item.open)
    })
    // The command/path stays visible while collapsed: "which command ran" is
    // the question the phone is usually opened to answer.
    var preview = document.createElement('div')
    preview.className = 'tool-preview'
    preview.textContent = toolPreview(item)
    wrap.appendChild(head)
    if (preview.textContent) wrap.appendChild(preview)
    wrap.appendChild(detail)
    return wrap
  }

  /** One line that identifies the call: command, path, pattern, or raw args. */
  var TOOL_PRIMARY_KEYS = [
    ['command', '命令'], ['cmd', '命令'],
    ['path', '路径'], ['file_path', '路径'],
    ['pattern', '匹配'], ['query', '查询'],
    ['url', '地址'],
  ]

  /** The human-readable argument of a tool call, when it has one. */
  function toolPrimary(item) {
    var raw = String(item.args || '')
    if (!raw) return null
    var parsed
    try {
      parsed = JSON.parse(raw)
    } catch (error) {
      return { key: 'raw', label: '参数', value: raw }
    }
    if (!parsed || typeof parsed !== 'object') return null
    for (var i = 0; i < TOOL_PRIMARY_KEYS.length; i += 1) {
      var value = parsed[TOOL_PRIMARY_KEYS[i][0]]
      if (typeof value === 'string' && value !== '') {
        return { key: TOOL_PRIMARY_KEYS[i][0], label: TOOL_PRIMARY_KEYS[i][1], value: value }
      }
    }
    if (Array.isArray(parsed.argv)) return { key: 'argv', label: '命令', value: parsed.argv.join(' ') }
    return null
  }

  function toolPreview(item) {
    var primary = toolPrimary(item)
    if (primary) return cut(primary.value.split('\n')[0], 110)
    var raw = String(item.args || '')
    if (!raw) return cut(String(item.result || '').split('\n')[0] || '', 110)
    return cut(raw.replace(/\s+/g, ' '), 110)
  }

  function labelEl(text) {
    var node = document.createElement('div')
    node.className = 'tool-label'
    node.textContent = text
    return node
  }

  function preEl(text) {
    var pre = document.createElement('pre')
    pre.textContent = text
    return pre
  }

  // ── rendering: streaming assistant ─────────────────────────────────────
  var streamingNode = null

  function clearStreaming() {
    state.streaming = null
    if (streamingNode && streamingNode.parentNode) streamingNode.parentNode.removeChild(streamingNode)
    streamingNode = null
    setTyping(false)
  }

  function renderStreaming() {
    if (!state.streaming || (!state.streaming.text && !state.streaming.reasoning)) {
      if (streamingNode && streamingNode.parentNode) streamingNode.parentNode.removeChild(streamingNode)
      streamingNode = null
      return
    }
    renderEmpty(null)
    if (!streamingNode) {
      streamingNode = document.createElement('div')
      streamingNode.className = 'item assistant'
      streamingNode.setAttribute('data-streaming', '1')
      itemsEl.appendChild(streamingNode)
    }
    var html = '<div class="who"><span class="mark">DSH</span><span>正在回复…</span></div>'
    if (state.streaming.reasoning && state.settings.reasoning !== 'hidden') {
      // Reasoning renders while it streams, not only after the turn commits:
      // the 折叠/展开 setting governs finished messages, streaming is always live.
      html += '<div class="r-head"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3a6 6 0 0 0-3.5 10.9V17h7v-3.1A6 6 0 0 0 12 3Z"/><path d="M9 21h6"/></svg><span>' + (state.running ? '思考中…' : '思考') + '</span></div>'
      html += '<div class="r-body">' + escapeHtml(state.streaming.reasoning) + '</div>'
    }
    html += '<div class="body cursor">' + renderMarkdown(state.streaming.text || '') + '</div>'
    streamingNode.innerHTML = html
    // Keep the newest reasoning line in view inside its own scroll box.
    var thinking = streamingNode.querySelector('.r-body')
    if (thinking) thinking.scrollTop = thinking.scrollHeight
  }

  var typingNode = null

  function setTyping(on) {
    if (on && !typingNode) {
      typingNode = document.createElement('div')
      typingNode.className = 'item'
      typingNode.innerHTML = '<div class="typing"><i></i><i></i><i></i></div>'
      itemsEl.appendChild(typingNode)
    } else if (!on && typingNode) {
      if (typingNode.parentNode) typingNode.parentNode.removeChild(typingNode)
      typingNode = null
    }
  }

  // ── rendering: interactions ────────────────────────────────────────────
  var interactionNodes = new Map() // key -> element

  function clearInteractionNodes() {
    interactionNodes.forEach(function (node) {
      if (node.parentNode) node.parentNode.removeChild(node)
    })
    interactionNodes.clear()
  }

  function upsertInteraction(interaction) {
    if (!interaction || !interaction.key) return
    if (interaction.sessionId && interaction.sessionId !== state.currentId) return
    state.interactions.set(interaction.key, interaction)
    renderEmpty(null)
    renderInteraction(interaction)
    renderSessions()
    if (state.stick) scrollToBottom(false)
  }

  function renderInteraction(interaction) {
    var existing = interactionNodes.get(interaction.key)
    if (existing && existing.parentNode) existing.parentNode.removeChild(existing)
    var node = buildInteraction(interaction)
    if (!node) return
    interactionNodes.set(interaction.key, node)
    itemsEl.appendChild(node)
  }

  function finishInteraction(key) {
    var interaction = state.interactions.get(key)
    if (!interaction) return
    interaction.done = true
    var node = interactionNodes.get(key)
    if (node) node.classList.add('done')
    renderSessions()
    setTimeout(function () {
      if (state.interactions.get(key) === interaction) {
        state.interactions.delete(key)
        var element = interactionNodes.get(key)
        if (element && element.parentNode) element.parentNode.removeChild(element)
        interactionNodes.delete(key)
      }
    }, 2200)
  }

  function renderInteractions() {
    // Session switch: previous nodes belong to another transcript.
    clearInteractionNodes()
    state.interactions.forEach(function (interaction) {
      if (interaction.done) return
      renderInteraction(interaction)
    })
  }

  function buildInteraction(interaction) {
    var node = document.createElement('div')
    node.className = 'interaction' + (interaction.done ? ' done' : '')
    node.setAttribute('data-interaction-key', interaction.key)
    var card = document.createElement('div')
    card.className = 'card'
    if (interaction.kind === 'approval') {
      card.innerHTML = '<div class="i-head">⚠ 需要你的确认</div>'
        + '<div class="i-body"><strong>' + escapeHtml(interaction.toolName || '工具调用') + '</strong>'
        + (interaction.reason ? '\n' + escapeHtml(interaction.reason) : '') + '</div>'
      var actions = document.createElement('div')
      actions.className = 'i-actions'
      var reject = document.createElement('button')
      reject.className = 'btn danger'
      reject.textContent = '拒绝'
      reject.addEventListener('click', function () { answerApproval(interaction, 'reject') })
      var allow = document.createElement('button')
      allow.className = 'btn primary'
      allow.textContent = '允许一次'
      allow.addEventListener('click', function () { answerApproval(interaction, 'allow') })
      actions.appendChild(reject)
      actions.appendChild(allow)
      card.appendChild(actions)
      if (interaction.args) {
        var args = document.createElement('div')
        args.className = 'i-args'
        args.textContent = interaction.args
        card.appendChild(args)
      }
    } else {
      card.appendChild(buildQuestionCard(interaction))
    }
    node.appendChild(card)
    return node
  }

  function buildQuestionCard(interaction) {
    var wrap = document.createElement('div')
    var headText = interaction.state === 'continued' ? '问题待回答（已超时，仍可回答）' : '需要你的回答'
    wrap.innerHTML = '<div class="i-head">💬 ' + headText + '</div>'
    var questions = Array.isArray(interaction.questions) ? interaction.questions : []
    var selections = {}
    var custom = {}
    questions.forEach(function (question, index) {
      selections[question.id] = []
      var body = document.createElement('div')
      body.className = 'i-body'
      body.innerHTML = '<div class="i-question">' + escapeHtml(question.question || question.header || '问题') + '</div>'
        + (question.detail ? '<div style="font-size:12.5px;color:var(--muted);white-space:pre-wrap;margin-top:6px;max-height:160px;overflow:auto">' + escapeHtml(question.detail) + '</div>' : '')
      wrap.appendChild(body)
      var multi = question.multiSelect === true
      ;(question.options || []).forEach(function (option) {
        var label = typeof option === 'string' ? option : (option.label || option.value || '')
        var row = document.createElement('button')
        row.type = 'button'
        row.className = 'i-option'
        row.innerHTML = '<span class="mark">✓</span><span>' + escapeHtml(label) + '</span>'
        row.addEventListener('click', function () {
          var selected = selections[question.id]
          var at = selected.indexOf(label)
          if (multi) {
            if (at === -1) selected.push(label)
            else selected.splice(at, 1)
          } else {
            selections[question.id] = at === -1 ? [label] : []
          }
          var siblings = wrap.querySelectorAll('[data-q-index="' + index + '"]')
          for (var i = 0; i < siblings.length; i += 1) {
            siblings[i].classList.toggle('sel', selections[question.id].indexOf(siblings[i].getAttribute('data-label')) !== -1)
          }
        })
        row.setAttribute('data-q-index', String(index))
        row.setAttribute('data-label', label)
        wrap.appendChild(row)
      })
      var input = document.createElement('input')
      input.className = 'input'
      input.style.margin = '0 12px 8px'
      input.style.width = 'calc(100% - 24px)'
      input.style.borderRadius = '10px'
      input.style.fontSize = '15px'
      input.placeholder = question.options && question.options.length ? '其他补充（可选）' : '输入回答…'
      input.addEventListener('input', function () { custom[question.id] = input.value })
      wrap.appendChild(input)
    })
    var actions = document.createElement('div')
    actions.className = 'i-actions'
    var cancel = document.createElement('button')
    cancel.className = 'btn ghost'
    cancel.textContent = '稍后回答'
    cancel.addEventListener('click', function () { cancelQuestion(interaction) })
    var submit = document.createElement('button')
    submit.className = 'btn primary'
    submit.textContent = '提交'
    submit.addEventListener('click', function () { answerQuestion(interaction, questions, selections, custom) })
    actions.appendChild(cancel)
    actions.appendChild(submit)
    wrap.appendChild(actions)
    return wrap
  }

  async function answerApproval(interaction, outcome) {
    interaction.busy = true
    try {
      await rpc('interaction.answer', { key: interaction.key, outcome: outcome })
    } catch (error) {
      toast(error.message || '审批提交失败')
    }
  }

  async function cancelQuestion(interaction) {
    // A `continued` question has no live waterfall waiter left; closing the
    // card is purely local (it stays answerable from the session projection).
    if (interaction.state !== 'continued') {
      try {
        await rpc('interaction.cancel', { key: interaction.key })
      } catch (error) {
        toast(error.message || '操作失败')
        return
      }
    }
    finishInteraction(interaction.key)
  }

  async function answerQuestion(interaction, questions, selections, custom) {
    var answers = questions.map(function (question) {
      var answer = { id: question.id, selected: (selections[question.id] || []).slice() }
      if (custom[question.id]) answer.custom = custom[question.id]
      return answer
    })
    try {
      await rpc('interaction.answer', { key: interaction.key, callId: interaction.callId, answers: answers })
    } catch (error) {
      toast(error.message || '回答提交失败')
    }
  }

  // ── rendering: drawer ──────────────────────────────────────────────────
  // Sessions are grouped by workspace (a project is a directory the user works
  // in). Hosts without a workspace registry return no `workspaces`, and the
  // drawer then falls back to the flat recent list.
  var COLLAPSE_KEY = 'dshRelayCollapsedProjects'

  function loadCollapsedProjects() {
    try {
      var raw = localStorage.getItem(COLLAPSE_KEY)
      var parsed = raw ? JSON.parse(raw) : null
      return parsed && typeof parsed === 'object' ? parsed : {}
    } catch (error) {
      return {}
    }
  }

  function saveCollapsedProjects() {
    try { localStorage.setItem(COLLAPSE_KEY, JSON.stringify(state.collapsed)) } catch (error) {}
  }

  function isCollapsed(groupId) {
    return state.collapsed[groupId] === true
  }

  /** Split the visible sessions into project groups; unclaimed rows go last. */
  function groupSessions(rows) {
    var byId = {}
    rows.forEach(function (row) { byId[row.id] = row })
    var claimed = {}
    var groups = []
    ;(state.workspaces || []).forEach(function (workspace) {
      var members = []
      ;(workspace.sessionIds || []).forEach(function (id) {
        var row = byId[id]
        if (!row || claimed[id]) return
        claimed[id] = true
        members.push(row)
      })
      if (members.length) groups.push({ id: workspace.id, workspace: workspace, rows: members })
    })
    var loose = rows.filter(function (row) { return !claimed[row.id] })
    if (loose.length) groups.push({ id: '__loose', workspace: null, rows: loose })
    return groups
  }

  function groupElement(group) {
    var wrap = document.createElement('div')
    wrap.className = 'session-group' + (isCollapsed(group.id) ? ' collapsed' : '')
    var head = document.createElement('button')
    head.type = 'button'
    head.className = 'session-group-head'
    head.setAttribute('aria-expanded', String(!isCollapsed(group.id)))
    var chev = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    chev.setAttribute('viewBox', '0 0 24 24')
    chev.setAttribute('class', 'g-chev')
    chev.setAttribute('aria-hidden', 'true')
    var path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
    path.setAttribute('d', 'M6 9l6 6 6-6')
    chev.appendChild(path)
    var name = document.createElement('span')
    name.className = 'g-name'
    name.textContent = group.workspace
      ? (group.workspace.title || basename(group.workspace.path) || '项目')
      : '未归类'
    var count = document.createElement('span')
    count.className = 'g-count'
    count.textContent = String(group.rows.length)
    head.appendChild(chev)
    head.appendChild(name)
    head.appendChild(count)
    head.addEventListener('click', function () {
      if (isCollapsed(group.id)) delete state.collapsed[group.id]
      else state.collapsed[group.id] = true
      saveCollapsedProjects()
      renderSessions()
    })
    wrap.appendChild(head)
    return wrap
  }

  function buildSessionRow(row, flat) {
    var node = document.createElement('div')
    node.className = 'session' + (row.id === state.currentId ? ' active' : '')
    node.setAttribute('role', 'button')
    node.setAttribute('tabindex', '0')
    var title = document.createElement('div')
    title.className = 's-title'
    title.textContent = row.title || (row.blank ? '新会话' : '未命名会话')
    if (row.parentSessionId) {
      var forkBadge = document.createElement('span')
      forkBadge.className = 's-fork'
      forkBadge.textContent = '分支'
      title.appendChild(forkBadge)
    }
    var meta = document.createElement('div')
    meta.className = 's-meta'
    var bits = []
    if (flat && row.cwd) bits.push(basename(row.cwd))
    bits.push(relativeTime(row.updatedAt))
    if (row.model && row.model.model) bits.push(row.model.model)
    meta.textContent = bits.join(' · ')
    var main = document.createElement('div')
    main.className = 's-main'
    main.appendChild(title)
    main.appendChild(meta)
    node.appendChild(main)
    var hasInteraction = false
    state.interactions.forEach(function (interaction) {
      if (interaction.sessionId === row.id && !interaction.done) hasInteraction = true
    })
    if (row.running || hasInteraction) {
      var dot = document.createElement('span')
      dot.className = 's-state ' + (hasInteraction ? 'attention' : 'running')
      node.appendChild(dot)
    }
    var more = document.createElement('button')
    more.type = 'button'
    more.className = 's-actions'
    more.setAttribute('aria-label', '会话操作')
    more.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true">'
      + '<circle cx="12" cy="5" r="1.7"/><circle cx="12" cy="12" r="1.7"/><circle cx="12" cy="19" r="1.7"/></svg>'
    more.addEventListener('click', function (event) {
      event.stopPropagation()
      openSessionActions(row)
    })
    node.appendChild(more)
    node.addEventListener('click', function () { selectSession(row.id) })
    node.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault()
        selectSession(row.id)
      }
    })
    return node
  }

  function renderSessions() {
    var box = $('sessions')
    if (!box) return
    box.innerHTML = ''
    var rows = state.sessions.slice().sort(function (a, b) { return (b.updatedAt || 0) - (a.updatedAt || 0) })
    if (!rows.length) {
      var empty = document.createElement('div')
      empty.className = 'drawer-empty'
      empty.textContent = '还没有会话'
      box.appendChild(empty)
      return
    }
    var groups = groupSessions(rows)
    var hasProjects = groups.some(function (group) { return Boolean(group.workspace) })
    if (!hasProjects) {
      var label = document.createElement('div')
      label.className = 'session-list-label'
      label.textContent = '最近'
      box.appendChild(label)
      rows.forEach(function (row) { box.appendChild(buildSessionRow(row, true)) })
      return
    }
    groups.forEach(function (group) {
      var wrap = groupElement(group)
      if (!isCollapsed(group.id)) {
        group.rows.forEach(function (row) { wrap.appendChild(buildSessionRow(row, false)) })
      }
      box.appendChild(wrap)
    })
  }

  // ── actions: rename / fork / copy ──────────────────────────────────────
  function openActions(title, items) {
    $('actionTitle').textContent = title
    var list = $('actionList')
    list.innerHTML = ''
    items.forEach(function (item) {
      if (!item) return
      var row = document.createElement('button')
      row.type = 'button'
      row.className = 'action-row' + (item.danger ? ' danger' : '')
      if (item.id) row.setAttribute('data-action', item.id)
      var label = document.createElement('span')
      label.textContent = item.label
      row.appendChild(label)
      if (item.hint) {
        var hint = document.createElement('span')
        hint.className = 'a-hint'
        hint.textContent = item.hint
        row.appendChild(hint)
      }
      row.addEventListener('click', function () {
        closeActions()
        // Let the sheet close before an action that opens another one.
        setTimeout(function () {
          try { item.onSelect() } catch (error) { toast(error.message || '操作失败') }
        }, 0)
      })
      list.appendChild(row)
    })
    $('actionSheet').hidden = false
  }

  function closeActions() {
    $('actionSheet').hidden = true
  }

  if ($('actionClose')) $('actionClose').addEventListener('click', closeActions)

  function openSessionActions(row) {
    openActions(row.title || '会话', [
      {
        id: 'model',
        label: '切换模型',
        hint: (row.model && row.model.model) || '',
        onSelect: function () {
          if (state.currentId !== row.id) selectSession(row.id)
          setTimeout(function () { openModelSheet() }, 0)
        },
      },
      {
        id: 'rename',
        label: '重命名',
        onSelect: function () {
          promptText('重命名会话', row.title || '', function (next) {
            rpc('rename', { sessionId: row.id, title: next }).then(function (result) {
              upsertSession({ id: row.id, title: result.title })
              if (state.currentId === row.id) {
                state.title = result.title
                updateSessionChrome()
              }
              toast('已重命名')
            }).catch(function (error) { toast(error.message || '重命名失败') })
          })
        },
      },
      {
        id: 'fork',
        label: '分叉会话',
        hint: '最近回合',
        onSelect: function () { forkSession(row.id) },
      },
      {
        id: 'copy-path',
        label: '复制工作目录',
        onSelect: function () { copyText(row.cwd || '') },
      },
    ].filter(function (item) { return item.id !== 'copy-path' || Boolean(row.cwd) }))
  }

  function openItemActions(item) {
    if (!item || (item.kind !== 'user' && item.kind !== 'assistant')) return
    var actions = [{
      id: 'fork-here',
      label: '从此处分叉',
      hint: typeof item.seq === 'number' ? '#' + item.seq : '',
      onSelect: function () { forkSession(state.currentId, item.seq) },
    }]
    if (item.text) {
      actions.push({ id: 'copy-text', label: '复制文本', onSelect: function () { copyText(item.text) } })
    }
    openActions(item.kind === 'user' ? '你的消息' : '助手消息', actions)
  }

  async function forkSession(sessionId, atSeq) {
    if (!sessionId) return
    try {
      toast(atSeq === undefined ? '正在分叉…' : '正在从该处分叉…')
      var params = { sessionId: sessionId }
      if (typeof atSeq === 'number' && atSeq >= 0) params.atSeq = atSeq
      var result = await rpc('fork', params)
      await refreshSessions()
      if (result && result.sessionId) {
        closeDrawer()
        selectSession(result.sessionId)
      }
      toast(atSeq === undefined ? '已创建分支' : '已从该消息创建分支')
    } catch (error) {
      toast(forkErrorText(error))
    }
  }

  function forkErrorText(error) {
    var code = error && error.code
    if (code === 'session/fork-unavailable') return '这里还不能分叉：选一条已结束回合之后的消息'
    if (code === 'session/not-found') return '会话不存在或已删除'
    if (code === 'session/workspace-attach-failed') return '分支已创建，但未能放回原项目'
    return (error && error.message) || '分叉失败'
  }

  function copyText(text) {
    if (!text) return
    var done = function () { toast('已复制') }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () {
        if (fallbackCopy(text)) done()
        else toast('复制失败')
      })
      return
    }
    if (fallbackCopy(text)) done()
    else toast('复制失败')
  }

  function fallbackCopy(text) {
    try {
      var area = document.createElement('textarea')
      area.value = text
      area.setAttribute('readonly', '')
      area.style.position = 'fixed'
      area.style.top = '-1000px'
      document.body.appendChild(area)
      area.select()
      var ok = document.execCommand('copy')
      document.body.removeChild(area)
      return ok
    } catch (error) {
      return false
    }
  }

  /** Long-press (or right-click) opens the message actions. */
  function attachLongPress(node, handler) {
    var timer = null
    var moved = false
    function cancel() {
      if (timer) clearTimeout(timer)
      timer = null
    }
    node.addEventListener('touchstart', function () {
      moved = false
      cancel()
      timer = setTimeout(function () {
        timer = null
        if (!moved) handler()
      }, 520)
    }, { passive: true })
    node.addEventListener('touchmove', function () { moved = true; cancel() }, { passive: true })
    node.addEventListener('touchend', cancel)
    node.addEventListener('touchcancel', cancel)
    node.addEventListener('contextmenu', function (event) {
      event.preventDefault()
      handler()
    })
  }

  function promptText(title, value, onDone) {
    $('modalTitle').textContent = title
    var body = $('modalBody')
    body.textContent = ''
    var input = document.createElement('input')
    input.className = 'prompt-input'
    input.type = 'text'
    input.maxLength = 120
    input.value = value || ''
    input.addEventListener('keydown', function (event) {
      if (event.key === 'Enter') {
        event.preventDefault()
        $('modalOk').click()
      }
    })
    body.appendChild(input)
    $('modal').hidden = false
    modalConfirm = function () {
      var next = input.value.trim()
      if (next) onDone(next)
    }
    setTimeout(function () {
      try { input.focus(); input.select() } catch (error) {}
    }, 40)
  }

  function openDrawer() {
    state.drawerOpen = true
    drawer.hidden = false
    scrim.hidden = false
    $('deviceLine').textContent = (state.deviceId ? '设备 ' + state.deviceId : 'DSH Remote')
      + (state.version ? ' · v' + state.version : '')
    renderSessions()
  }

  function closeDrawer() {
    state.drawerOpen = false
    drawer.hidden = true
    scrim.hidden = true
  }

  // ── scrolling ──────────────────────────────────────────────────────────
  function isNearBottom() {
    return streamEl.scrollHeight - streamEl.scrollTop - streamEl.clientHeight < 90
  }

  function scrollToBottom(force) {
    if (!force && !state.stick) return
    streamEl.scrollTop = streamEl.scrollHeight
    state.stick = true
    showJump(false)
  }

  function showJump(show) {
    $('jumpBtn').hidden = !show
  }

  streamEl.addEventListener('scroll', function () {
    var near = isNearBottom()
    state.stick = near
    showJump(!near)
    if (streamEl.scrollTop < 40 && state.hasMore && !state.loadingOlder) loadOlder()
  }, { passive: true })

  $('jumpBtn').addEventListener('click', function () { scrollToBottom(true) })

  async function loadOlder() {
    if (!state.currentId || state.loadingOlder || !state.hasMore) return
    state.loadingOlder = true
    var before = streamEl.scrollHeight
    try {
      var result = await rpc('older', {
        sessionId: state.currentId,
        throughSeq: state.cursor,
        beforeSeq: state.oldestSeq === null ? undefined : state.oldestSeq,
        maxMessages: 40,
      })
      var older = Array.isArray(result.items) ? result.items : []
      if (older.length) {
        var filtered = older.filter(function (item) { return !state.byId.has(item.id) })
        state.items = filtered.concat(state.items)
        filtered.forEach(function (item) { state.byId.set(item.id, item) })
        state.oldestSeq = oldestSeqOf(state.items)
        renderAll()
        state.stick = false
        streamEl.scrollTop = streamEl.scrollHeight - before
      }
      state.hasMore = result.hasMore === true
    } catch (error) {
      toast(error.message || '加载更早消息失败')
    } finally {
      state.loadingOlder = false
    }
  }

  // ── composer ───────────────────────────────────────────────────────────
  function autoGrow() {
    inputEl.style.height = 'auto'
    inputEl.style.height = Math.min(148, Math.max(42, inputEl.scrollHeight)) + 'px'
  }

  function updateSendState() {
    updateComposer()
  }

  function removePendingUser(requestId) {
    if (!state.pendingUsers.has(requestId)) return
    state.pendingUsers.delete(requestId)
    var nodes = itemsEl.querySelectorAll('[data-pending-request="' + cssEscape(requestId) + '"]')
    for (var i = 0; i < nodes.length; i += 1) nodes[i].remove()
  }

  async function sendMessage() {
    var text = inputEl.value.trim()
    var images = state.pendingImages.slice()
    if ((!text && images.length === 0) || !state.connected) return
    if (!state.currentId) {
      await createSession()
      if (!state.currentId) return
    }
    var sessionId = state.currentId
    var requestId = uuid()
    var optimisticItems = []
    images.forEach(function (image, index) {
      optimisticItems.push({
        kind: 'image',
        id: 'pending:' + requestId + ':img:' + index,
        requestId: requestId,
        pending: true,
        preview: image.preview,
        mediaType: image.mediaType,
        width: image.width,
        height: image.height,
        own: true,
        time: Date.now(),
      })
    })
    if (text) {
      optimisticItems.push({
        kind: 'user',
        id: 'pending:' + requestId,
        text: text,
        time: Date.now(),
        requestId: requestId,
        pending: true,
      })
    }
    var nodes = []
    optimisticItems.forEach(function (item) {
      var node = buildItem(item)
      if (node) { itemsEl.appendChild(node); nodes.push(node) }
    })
    if (nodes.length) renderEmpty(null)
    state.pendingUsers.set(requestId, { items: optimisticItems, nodes: nodes })
    inputEl.value = ''
    clearPendingImages()
    autoGrow()
    updateComposer()
    state.stick = true
    scrollToBottom(true)
    try {
      await rpc('prompt', {
        sessionId: sessionId,
        text: text,
        images: images.map(function (image) {
          return { mediaType: image.mediaType, data: image.data, name: image.name }
        }),
        requestId: requestId,
        clientTimeZone: timezone(),
      })
      setTyping(true)
    } catch (error) {
      removePendingUser(requestId)
      inputEl.value = text
      state.pendingImages = images
      renderPendingImages()
      autoGrow()
      updateComposer()
      toast(promptErrorText(error))
      if (error.code === 'session/not-found' || error.code === 'session/writer-held') {
        refreshSessions().catch(function () {})
      }
    }
  }

  async function stopRun() {
    if (!state.currentId) return
    try {
      await rpc('stop', { sessionId: state.currentId })
      toast('已请求停止')
    } catch (error) {
      toast(error.code === 'session/not-found' ? '当前没有正在运行的 agent' : (error.message || '停止失败'))
      refreshSessions().catch(function () {})
    }
  }

  sendBtn.addEventListener('click', sendMessage)
  stopBtn.addEventListener('click', stopRun)

  inputEl.addEventListener('input', function () {
    autoGrow()
    updateSendState()
  })

  // Touch keyboards use Enter as a newline (the send button is the only way
  // to submit); a hardware keyboard keeps Enter-to-send with Shift+Enter for
  // a newline, matching the desktop DSH composer.
  var coarsePointer = Boolean(window.matchMedia && window.matchMedia('(pointer: coarse)').matches)
  inputEl.setAttribute('enterkeyhint', coarsePointer ? 'enter' : 'send')
  inputEl.addEventListener('keydown', function (event) {
    if (event.key !== 'Enter') return
    if (event.isComposing) return
    if (coarsePointer) return
    if (event.shiftKey || event.altKey) return
    event.preventDefault()
    sendMessage()
  })

  $('menuBtn').addEventListener('click', openDrawer)
  $('drawerClose').addEventListener('click', closeDrawer)
  scrim.addEventListener('click', closeDrawer)
  $('newBtn').addEventListener('click', createSession)
  $('attachBtn').addEventListener('click', function () { $('fileInput').click() })
  $('fileInput').addEventListener('change', function (event) {
    var files = event.target.files ? Array.prototype.slice.call(event.target.files) : []
    event.target.value = ''
    addImageFiles(files)
  })
  $('modelBtn').addEventListener('click', openModelSheet)
  $('modelClose').addEventListener('click', closeModelSheet)
  $('modelSheet').addEventListener('click', function (event) {
    if (event.target === $('modelSheet')) closeModelSheet()
  })
  $('permBtn').addEventListener('click', openPermissionSheet)
  $('permClose').addEventListener('click', closePermissionSheet)
  $('permSheet').addEventListener('click', function (event) {
    if (event.target === $('permSheet')) closePermissionSheet()
  })
  $('settingsLink').addEventListener('click', openSettings)
  $('settingsClose').addEventListener('click', closeSettings)
  $('settingsSheet').addEventListener('click', function (event) {
    if (event.target === $('settingsSheet')) closeSettings()
  })
  $('terminalLink').addEventListener('click', openTerminal)
  $('terminalBack').addEventListener('click', closeTerminal)
  $('terminalSend').addEventListener('click', terminalSend)
  $('terminalCtrlC').addEventListener('click', terminalCtrlC)
  $('terminalNew').addEventListener('click', terminalNew)
  $('terminalClose').addEventListener('click', terminalKill)
  $('terminalInput').addEventListener('keydown', function (event) {
    if (event.key !== 'Enter' || event.isComposing) return
    event.preventDefault()
    terminalSend()
  })
  $('imageViewer').addEventListener('click', function () { $('imageViewer').hidden = true })
  $('desktopLink').addEventListener('click', function () {
    location.href = PREFIX + '/?g=' + encodeURIComponent(GATE) + '&desktop=1'
  })
  $('rotateLink').addEventListener('click', function () {
    showModal('重新配对', '请在电脑上打开 DSH 控制台 → 手机入口，重新扫码。当前手机页将在密钥更新后失效。', function () {
      try { localStorage.removeItem('dshRelayK') } catch (error) {}
      location.href = PREFIX + '/m?g=' + encodeURIComponent(GATE)
    })
  })

  // ── modal / toast ──────────────────────────────────────────────────────
  var modalConfirm = null

  function showModal(title, body, onOk) {
    $('modalTitle').textContent = title
    $('modalBody').textContent = body
    $('modal').hidden = false
    modalConfirm = onOk
  }

  function hideModal() {
    $('modal').hidden = true
    modalConfirm = null
  }

  $('modalCancel').addEventListener('click', hideModal)
  $('modalOk').addEventListener('click', function () {
    var action = modalConfirm
    hideModal()
    if (action) action()
  })

  var toastTimer = null
  function toast(message) {
    var node = $('toast')
    node.textContent = String(message)
    node.hidden = false
    clearTimeout(toastTimer)
    toastTimer = setTimeout(function () { node.hidden = true }, 2600)
  }

  // ── markdown (small, safe subset) ──────────────────────────────────────
  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
  }

  function renderMarkdown(source) {
    var text = String(source == null ? '' : source).replace(/\r\n?/g, '\n')
    var lines = text.split('\n')
    var out = []
    var index = 0
    var paragraph = []
    var list = null

    function flushParagraph() {
      if (!paragraph.length) return
      out.push('<p>' + inline(paragraph.join('\n')) + '</p>')
      paragraph = []
    }

    function flushList() {
      if (!list) return
      out.push('<' + list.tag + '>' + list.items.map(function (item) { return '<li>' + inline(item) + '</li>' }).join('') + '</' + list.tag + '>')
      list = null
    }

    while (index < lines.length) {
      var line = lines[index]
      var fence = /^```\s*([\w+.-]*)\s*$/.exec(line)
      if (fence) {
        flushParagraph(); flushList()
        var code = []
        index += 1
        while (index < lines.length && !/^```\s*$/.test(lines[index])) {
          code.push(lines[index])
          index += 1
        }
        index += 1
        out.push('<pre><code' + (fence[1] ? ' class="language-' + escapeHtml(fence[1]) + '"' : '') + '>'
          + escapeHtml(code.join('\n')) + '</code></pre>')
        continue
      }
      if (/^\s*$/.test(line)) { flushParagraph(); flushList(); index += 1; continue }
      var heading = /^(#{1,4})\s+(.*)$/.exec(line)
      if (heading) {
        flushParagraph(); flushList()
        var level = heading[1].length + 1
        if (level > 4) level = 4
        out.push('<h' + level + '>' + inline(heading[2]) + '</h' + level + '>')
        index += 1
        continue
      }
      if (/^\s*([-*_])\s*\1\s*\1[\s-]*$/.test(line) || /^---+\s*$/.test(line)) {
        flushParagraph(); flushList()
        out.push('<hr>')
        index += 1
        continue
      }
      if (/^>\s?/.test(line)) {
        flushParagraph(); flushList()
        var quote = []
        while (index < lines.length && /^>\s?/.test(lines[index])) {
          quote.push(lines[index].replace(/^>\s?/, ''))
          index += 1
        }
        out.push('<blockquote>' + inline(quote.join('\n')) + '</blockquote>')
        continue
      }
      var ordered = /^\s*\d+[.)]\s+(.*)$/.exec(line)
      var unordered = /^\s*[-*+]\s+(.*)$/.exec(line)
      if (ordered || unordered) {
        flushParagraph()
        var tag = ordered ? 'ol' : 'ul'
        if (list && list.tag !== tag) flushList()
        if (!list) list = { tag: tag, items: [] }
        list.items.push((ordered || unordered)[1])
        index += 1
        continue
      }
      if (/^\|.*\|$/.test(line) && index + 1 < lines.length && /^\|[\s:|-]+\|$/.test(lines[index + 1])) {
        flushParagraph(); flushList()
        var header = splitTableRow(line)
        index += 2
        var rows = []
        while (index < lines.length && /^\|.*\|$/.test(lines[index])) {
          rows.push(splitTableRow(lines[index]))
          index += 1
        }
        var table = '<table><thead><tr>' + header.map(function (cell) { return '<th>' + inline(cell) + '</th>' }).join('') + '</tr></thead><tbody>'
          + rows.map(function (row) {
            return '<tr>' + row.map(function (cell) { return '<td>' + inline(cell) + '</td>' }).join('') + '</tr>'
          }).join('') + '</tbody></table>'
        out.push(table)
        continue
      }
      paragraph.push(line)
      index += 1
    }
    flushParagraph()
    flushList()
    return out.join('')
  }

  function splitTableRow(line) {
    return line.replace(/^\|/, '').replace(/\|$/, '').split('|').map(function (cell) { return cell.trim() })
  }

  function inline(raw) {
    var text = escapeHtml(raw)
    var slots = []
    text = text.replace(/`([^`]+)`/g, function (_whole, code) {
      slots.push('<code>' + code + '</code>')
      return '\u0000' + (slots.length - 1) + '\u0000'
    })
    text = text.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    text = text.replace(/__([^_]+)__/g, '<strong>$1</strong>')
    text = text.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>')
    text = text.replace(/(^|[^_])_([^_\n]+)_/g, '$1<em>$2</em>')
    text = text.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
    text = text.replace(/(^|\s)(https?:\/\/[^\s<]+)/g, function (whole, lead, url) {
      return lead + '<a href="' + url + '" target="_blank" rel="noopener noreferrer">' + url + '</a>'
    })
    text = text.replace(/\u0000(\d+)\u0000/g, function (_whole, at) { return slots[Number(at)] || '' })
    text = text.replace(/\n/g, '<br>')
    return text
  }

  // ── images ────────────────────────────────────────────────────────────
  function addImageFiles(files) {
    files.forEach(function (file) {
      prepareImage(file).then(function (image) {
        if (state.pendingImages.length >= 8) { toast('最多 8 张图片'); return }
        state.pendingImages.push(image)
        renderPendingImages()
        updateComposer()
      }).catch(function (error) {
        toast('图片处理失败：' + (error.message || error))
      })
    })
  }

  function prepareImage(file) {
    return new Promise(function (resolve, reject) {
      if (!/^image\//.test(file.type || '')) { reject(new Error('不是图片文件')); return }
      var reader = new FileReader()
      reader.onerror = function () { reject(new Error('读取失败')) }
      reader.onload = function () {
        var img = new Image()
        img.onload = function () {
          try {
            var max = 1600
            var width = img.naturalWidth || img.width
            var height = img.naturalHeight || img.height
            var scale = Math.min(1, max / Math.max(width, height))
            var cw = Math.max(1, Math.round(width * scale))
            var ch = Math.max(1, Math.round(height * scale))
            var canvas = document.createElement('canvas')
            canvas.width = cw
            canvas.height = ch
            var context = canvas.getContext('2d')
            context.fillStyle = '#ffffff'
            context.fillRect(0, 0, cw, ch)
            context.drawImage(img, 0, 0, cw, ch)
            var dataUrl = canvas.toDataURL('image/jpeg', 0.85)
            resolve({
              mediaType: 'image/jpeg',
              data: dataUrl.slice(dataUrl.indexOf(',') + 1),
              preview: dataUrl,
              name: file.name || 'photo.jpg',
              width: cw,
              height: ch,
            })
          } catch (error) {
            reject(error)
          }
        }
        img.onerror = function () { reject(new Error('解码失败')) }
        img.src = String(reader.result)
      }
      reader.readAsDataURL(file)
    })
  }

  function clearPendingImages() {
    state.pendingImages = []
    renderPendingImages()
  }

  function renderPendingImages() {
    var box = $('pendingImages')
    if (!box) return
    box.innerHTML = ''
    box.hidden = state.pendingImages.length === 0
    state.pendingImages.forEach(function (image, index) {
      var cell = document.createElement('div')
      cell.className = 'pending-image'
      var img = document.createElement('img')
      img.src = image.preview
      img.alt = ''
      var remove = document.createElement('button')
      remove.type = 'button'
      remove.textContent = '×'
      remove.setAttribute('aria-label', '移除图片')
      remove.addEventListener('click', function () {
        state.pendingImages.splice(index, 1)
        renderPendingImages()
        updateComposer()
      })
      cell.appendChild(img)
      cell.appendChild(remove)
      box.appendChild(cell)
    })
  }

  function buildImageItem(item) {
    var node = document.createElement('div')
    node.className = 'item image' + (item.own ? ' own' : '')
    node.setAttribute('data-item-id', item.id)
    if (item.pending && item.requestId) node.setAttribute('data-pending-request', item.requestId)
    var mediaType = item.mediaType || 'image/jpeg'
    if (item.preview) {
      node.appendChild(imageElement(item.preview, mediaType, item))
      return node
    }
    var cached = state.imageCache.get(item.attachmentId)
    if (cached) {
      node.appendChild(imageElement(cached, mediaType, item))
      return node
    }
    var placeholder = document.createElement('div')
    placeholder.className = 'loading'
    placeholder.textContent = '加载图片…'
    node.appendChild(placeholder)
    var sessionId = state.currentId
    rpc('image.get', { sessionId: sessionId, attachmentId: item.attachmentId }).then(function (result) {
      if (state.currentId !== sessionId) return
      var url = 'data:' + (result.mediaType || mediaType) + ';base64,' + result.data
      state.imageCache.set(item.attachmentId, url)
      var fresh = imageElement(url, result.mediaType || mediaType, item)
      if (placeholder.parentNode) placeholder.replaceWith(fresh)
    }).catch(function (error) {
      placeholder.textContent = '图片加载失败'
      placeholder.title = error.message || ''
    })
    return node
  }

  function imageElement(url, mediaType, item) {
    var img = document.createElement('img')
    img.src = url
    img.alt = ''
    img.loading = 'lazy'
    if (item.width && item.height) {
      img.width = Math.min(item.width, 360)
      img.height = Math.round((item.height / item.width) * img.width)
    }
    img.addEventListener('click', function () {
      var viewer = $('imageViewer')
      $('imageViewerImg').src = url
      viewer.hidden = false
    })
    return img
  }

  // ── model picker ──────────────────────────────────────────────────────
  var LAST_MODEL_KEY = 'dshRelayLastModel'

  function loadLastModel() {
    try {
      var raw = localStorage.getItem(LAST_MODEL_KEY)
      var parsed = raw ? JSON.parse(raw) : null
      if (!parsed || typeof parsed.provider !== 'string' || typeof parsed.model !== 'string') return null
      return { provider: parsed.provider, model: parsed.model }
    } catch (error) {
      return null
    }
  }

  function saveLastModel() {
    try { localStorage.setItem(LAST_MODEL_KEY, JSON.stringify(state.lastModel)) } catch (error) {}
  }

  /**
   * The model a session with no explicit selection will actually use: the
   * deployment default, with the last manual pick as the instant fallback.
   * `selectModel` saves that pick as the deployment default, so the two agree
   * once the next catalog read lands.
   */
  function pickDefaultModel(catalog) {
    var hostDefault = catalog && catalog.default
    if (hostDefault && hostDefault.provider && hostDefault.model) {
      return { provider: hostDefault.provider, model: hostDefault.model }
    }
    return state.lastModel
  }

  var catalogRequest = null

  async function ensureModelCatalog() {
    if (state.modelCatalog) return state.modelCatalog
    if (catalogRequest) return catalogRequest
    catalogRequest = rpc('model.catalog', {}).then(function (catalog) {
      catalogRequest = null
      if (catalog && Array.isArray(catalog.groups)) state.modelCatalog = catalog
      state.modelDefault = pickDefaultModel(catalog)
      return state.modelCatalog
    }, function (error) {
      catalogRequest = null
      throw error
    })
    return catalogRequest
  }

  /** Show the effective model on a session that has not selected one yet. */
  function adoptDefaultDisplay() {
    if (state.model || !state.currentId) return
    var fallback = state.modelDefault || state.lastModel
    if (fallback) {
      state.model = fallback
      updateModelChip()
      return
    }
    ensureModelCatalog().then(function () {
      if (state.model || !state.currentId) return
      if (state.modelDefault) {
        state.model = state.modelDefault
        updateModelChip()
      }
    }).catch(function () {})
  }

  function modelDisplayName(model) {
    if (!model) return ''
    if (typeof model === 'string') return model
    return model.name || model.model || ''
  }

  function updateModelChip() {
    var button = $('modelBtn')
    var name = $('modelName')
    if (!button || !name) return
    button.hidden = !state.currentId
    name.textContent = modelDisplayName(state.model) || '选择模型'
    button.title = state.model && state.model.provider
      ? state.model.provider + ' / ' + (state.model.model || '')
      : '选择模型'
  }

  async function openModelSheet() {
    if (!state.currentId) return
    $('modelSheet').hidden = false
    var list = $('modelList')
    list.innerHTML = '<div class="drawer-empty">加载模型列表…</div>'
    try {
      // Always re-read: provider credentials and routable models change while
      // the page is open, and a stale list is worse than a round trip.
      var catalog = await rpc('model.catalog', {})
      if (catalog && Array.isArray(catalog.groups)) state.modelCatalog = catalog
      state.modelDefault = pickDefaultModel(catalog)
      renderModelList()
    } catch (error) {
      if (state.modelCatalog) {
        renderModelList()
        toast('模型列表没能刷新，显示上次结果')
      } else {
        list.innerHTML = '<div class="drawer-empty">' + escapeHtml(error.message || '加载失败') + '</div>'
      }
    }
  }

  function closeModelSheet() {
    $('modelSheet').hidden = true
  }

  function renderModelList() {
    var list = $('modelList')
    list.innerHTML = ''
    var catalog = state.modelCatalog || {}
    var groups = Array.isArray(catalog.groups) ? catalog.groups : []
    var current = state.model || {}
    if (!groups.length) {
      list.innerHTML = '<div class="drawer-empty">没有可用模型</div>'
      return
    }
    groups.forEach(function (group) {
      var label = document.createElement('div')
      label.className = 'model-group-label'
      label.textContent = group.name || group.id || '模型'
      list.appendChild(label)
      ;(group.models || []).forEach(function (model) {
        var row = document.createElement('button')
        row.type = 'button'
        var isCurrent = current.model === model.id && (!current.provider || current.provider === group.id)
        row.className = 'model-row' + (isCurrent ? ' current' : '')
        row.innerHTML = '<div class="m-main"><div class="m-name">' + escapeHtml(model.name || model.id) + '</div>'
          + '<div class="m-id">' + escapeHtml(model.id) + (model.description ? ' · ' + escapeHtml(model.description) : '') + '</div></div>'
          + (isCurrent ? '<span class="m-check">✓</span>' : '')
        row.addEventListener('click', function () {
          selectModel(group.id, model).catch(function (error) {
            toast(error.message || '切换失败')
          })
        })
        list.appendChild(row)
      })
    })
  }

  async function selectModel(provider, model) {
    var sessionId = state.currentId
    if (!sessionId) return
    closeModelSheet()
    try {
      var result = await rpc('model.select', {
        sessionId: sessionId,
        selection: {
          provider: provider,
          model: model.id,
          ...(model.defaultReasoningEffort ? { reasoningEffort: model.defaultReasoningEffort } : {}),
        },
      })
      state.model = (result && result.selected) || { provider: provider, model: model.id }
      // The host saves every manual pick as the deployment default, so a new
      // session inherits it; remember it locally for the instant case.
      state.lastModel = { provider: state.model.provider, model: state.model.model }
      saveLastModel()
      state.modelDefault = state.lastModel
      var row = findSession(sessionId)
      if (row) {
        row.model = state.model
        renderSessions()
      }
      updateModelChip()
      toast('已切换模型：' + (model.name || model.id))
    } catch (error) {
      toast(error.code === 'session/model-unavailable' ? '该模型当前不可用' : (error.message || '切换失败'))
      throw error
    }
  }

  // ── settings: display + permissions ───────────────────────────────────
  var SETTINGS_KEY = 'dshRelaySettings'
  var DISPLAY_MODES = ['hidden', 'collapsed', 'open']
  var THEME_MODES = ['system', 'light', 'dark']
  var PERMISSION_LABELS = {
    'read-only': '仅可查看',
    'workspace-write': '工作区内修改',
    'danger-full-access': '完全权限',
    auto: '自动审查',
    custom: '自定义',
  }
  var PERMISSION_HINTS = {
    'read-only': '只读，不能修改文件',
    'workspace-write': '工作目录内可改，越界操作要审批',
    'danger-full-access': '不再逐条确认，谨慎使用',
    auto: '无沙箱运行，每次工具调用先由模型审查',
    custom: '当前沙箱与审批组合不匹配任何预设',
  }
  var SANDBOX_LABELS = {
    'read-only': '只读',
    'workspace-write': '工作区可写',
    'danger-full-access': '完全访问',
  }

  function loadSettings() {
    var defaults = { reasoning: 'collapsed', tools: 'collapsed', theme: 'system' }
    try {
      var raw = localStorage.getItem(SETTINGS_KEY)
      var parsed = raw ? JSON.parse(raw) : null
      if (!parsed || typeof parsed !== 'object') return defaults
      DISPLAY_MODES.forEach(function (mode) {
        if (DISPLAY_MODES.indexOf(parsed.reasoning) === -1) parsed.reasoning = defaults.reasoning
        if (DISPLAY_MODES.indexOf(parsed.tools) === -1) parsed.tools = defaults.tools
      })
      var theme = THEME_MODES.indexOf(parsed.theme) === -1 ? defaults.theme : parsed.theme
      return { reasoning: parsed.reasoning, tools: parsed.tools, theme: theme }
    } catch (error) {
      return defaults
    }
  }

  function saveSettings() {
    try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(state.settings)) } catch (error) {}
  }

  /**
   * Apply the appearance choice. `system` follows the OS; the other two override
   * it. The attribute is read by app.css, and the same value has to reach the
   * `<meta name="theme-color">` so the status bar matches.
   */
  function applyTheme() {
    var theme = state.settings.theme || 'system'
    var dark = theme === 'dark'
      || (theme === 'system' && window.matchMedia
        && window.matchMedia('(prefers-color-scheme: dark)').matches)
    var root = document.documentElement
    if (dark) root.setAttribute('data-theme', 'dark')
    else root.removeAttribute('data-theme')
    var meta = document.getElementById('themeColor')
    if (meta) meta.setAttribute('content', dark ? '#0a0d13' : '#ffffff')
  }

  /** Effective preset id for the folded knobs the host projects. */
  function currentPresetId(permissions) {
    if (!permissions) return null
    if (permissions.preset) return permissions.preset
    var sandbox = permissions.sandbox
    var approval = permissions.approval
    if (sandbox === 'read-only' && approval === 'ask') return 'read-only'
    if (sandbox === 'workspace-write' && approval === 'ask') return 'workspace-write'
    if (sandbox === 'danger-full-access' && approval === 'never') return 'danger-full-access'
    if (sandbox === 'danger-full-access' && approval === 'ask') return 'auto'
    return null
  }

  function permissionLabel(id) {
    return PERMISSION_LABELS[id] || id || '权限'
  }

  function permissionDetail(permissions) {
    if (!permissions) return ''
    var bits = []
    if (permissions.sandbox) bits.push('沙箱：' + (SANDBOX_LABELS[permissions.sandbox] || permissions.sandbox))
    if (permissions.approval) bits.push('审批：' + (permissions.approval === 'never' ? '从不询问' : '逐条询问'))
    return bits.join(' · ')
  }

  function updatePermChip() {
    var button = $('permBtn')
    var name = $('permName')
    if (!button || !name) return
    if (!state.currentId) {
      button.hidden = true
      button.className = 'chip'
      return
    }
    var preset = currentPresetId(state.permissions)
    var detail = permissionDetail(state.permissions)
    button.hidden = false
    button.className = 'chip' + (preset === 'danger-full-access' || preset === 'auto' ? ' warn' : '')
    button.title = preset
      ? '权限模式：' + permissionLabel(preset) + (detail ? '（' + detail + '）' : '')
      : '权限模式'
    // Shown even before the state arrives: hiding it made the control look absent.
    name.textContent = preset ? permissionLabel(preset) : '权限'
  }

  function onPermissionFrame(frame) {
    if (frame.sessionId && frame.sessionId !== state.currentId) return
    state.permissions = frame.permissions || null
    updatePermChip()
    if (!$('permSheet').hidden) renderPermissionSheet()
  }

  function openSettings() {
    closeDrawer()
    $('settingsSheet').hidden = false
    renderSettings()
  }

  function closeSettings() {
    $('settingsSheet').hidden = true
  }

  /** Permission belongs to one session, so it opens from the chip beside the model. */
  async function openPermissionSheet() {
    if (!state.currentId) return
    closeDrawer()
    $('permSheet').hidden = false
    renderPermissionSheet()
    if (!state.permissionCatalog) await loadPermissionCatalog()
  }

  function closePermissionSheet() {
    $('permSheet').hidden = true
  }

  async function loadPermissionCatalog() {
    try {
      state.permissionCatalog = await rpc('permission.catalog', {})
    } catch (error) {
      state.permissionCatalog = { available: false, options: [], error: error.message || String(error) }
    }
    if (!$('permSheet').hidden) renderPermissionSheet()
  }

  function renderSettings() {
    var body = $('settingsBody')
    if (!body) return
    body.innerHTML = ''
    body.appendChild(themeSection())
    body.appendChild(displaySection())
    var note = document.createElement('div')
    note.className = 'perm-note'
    note.textContent = '这些是这台手机自己的偏好；权限在模型 chip 旁边，按会话生效。'
    body.appendChild(note)
  }

  function themeSection() {
    var section = document.createElement('div')
    section.className = 'set-section'
    section.appendChild(sectionTitle('外观'))
    var row = document.createElement('div')
    row.className = 'set-row'
    var main = document.createElement('div')
    main.className = 'set-label'
    main.textContent = '主题'
    var sub = document.createElement('div')
    sub.className = 'set-sub'
    sub.textContent = '跟随系统，或固定浅色 / 夜间'
    main.appendChild(sub)
    row.appendChild(main)
    row.appendChild(segmented([
      { id: 'system', label: '系统' },
      { id: 'light', label: '浅色' },
      { id: 'dark', label: '夜间' },
    ], state.settings.theme, function (next) {
      state.settings.theme = next
      saveSettings()
      applyTheme()
      renderSettings()
    }))
    section.appendChild(row)
    return section
  }

  function renderPermissionSheet() {
    var body = $('permBody')
    if (!body) return
    body.innerHTML = ''
    body.appendChild(permissionSection())
  }

  function displaySection() {
    var section = document.createElement('div')
    section.className = 'set-section'
    section.appendChild(sectionTitle('显示'))
    section.appendChild(displayRow('思考过程', 'reasoning', '模型的推理过程'))
    section.appendChild(displayRow('工具调用', 'tools', '命令、参数和输出'))
    return section
  }

  function sectionTitle(text) {
    var title = document.createElement('div')
    title.className = 'set-title'
    title.textContent = text
    return title
  }

  function displayRow(label, key, hint) {
    var row = document.createElement('div')
    row.className = 'set-row'
    var main = document.createElement('div')
    main.className = 'set-label'
    main.textContent = label
    var sub = document.createElement('div')
    sub.className = 'set-sub'
    sub.textContent = hint
    main.appendChild(sub)
    row.appendChild(main)
    row.appendChild(segmented([
      { id: 'hidden', label: '隐藏' },
      { id: 'collapsed', label: '折叠' },
      { id: 'open', label: '展开' },
    ], state.settings[key], function (next) {
      state.settings[key] = next
      saveSettings()
      renderSettings()
      renderAll()
    }))
    return row
  }

  function segmented(options, current, onPick) {
    var seg = document.createElement('div')
    seg.className = 'seg'
    options.forEach(function (option) {
      var button = document.createElement('button')
      button.type = 'button'
      button.textContent = option.label
      if (option.id === current) button.className = 'on'
      button.addEventListener('click', function () { onPick(option.id) })
      seg.appendChild(button)
    })
    return seg
  }

  function permissionSection() {
    var section = document.createElement('div')
    section.className = 'set-section'
    if (!state.permissionCatalog) {
      var loading = document.createElement('div')
      loading.className = 'perm-note'
      loading.textContent = '正在读取权限列表…'
      section.appendChild(loading)
      return section
    }
    if (!state.permissionCatalog.available) {
      var missing = document.createElement('div')
      missing.className = 'perm-note'
      missing.textContent = '这个 DSH 没有挂载权限预设，只能在桌面端切换。'
      section.appendChild(missing)
      return section
    }
    if (!state.currentId) {
      var none = document.createElement('div')
      none.className = 'perm-note'
      none.textContent = '先打开一个会话，再切换权限。'
      section.appendChild(none)
      return section
    }
    var current = currentPresetId(state.permissions)
    if (!state.permissions) {
      var waiting = document.createElement('div')
      waiting.className = 'perm-note'
      waiting.textContent = '正在读取当前会话的权限状态…'
      section.appendChild(waiting)
    }
    state.permissionCatalog.options.forEach(function (option) {
      section.appendChild(permissionRow(option, option.id === current))
    })
    if (!current && state.permissions) {
      var custom = document.createElement('div')
      custom.className = 'perm-note'
      custom.textContent = '当前是自定义组合' + (permissionDetail(state.permissions) ? '（' + permissionDetail(state.permissions) + '）' : '') + '，选一个预设即可覆盖。'
      section.appendChild(custom)
    }
    var foot = document.createElement('div')
    foot.className = 'perm-note'
    foot.textContent = '只影响当前会话；新会话的默认权限由桌面端决定。'
    section.appendChild(foot)
    return section
  }

  function permissionRow(option, isCurrent) {
    var row = document.createElement('button')
    row.type = 'button'
    row.className = 'perm-row' + (isCurrent ? ' current' : '')
    row.setAttribute('data-preset', option.id)
    var main = document.createElement('div')
    main.className = 'p-main'
    var name = document.createElement('div')
    name.className = 'p-name'
    name.textContent = permissionLabel(option.id)
    main.appendChild(name)
    var hint = PERMISSION_HINTS[option.id] || option.description || ''
    if (hint) {
      var desc = document.createElement('div')
      desc.className = 'p-desc'
      desc.textContent = hint
      main.appendChild(desc)
    }
    row.appendChild(main)
    if (isCurrent) {
      var check = document.createElement('span')
      check.className = 'p-check'
      check.textContent = '✓'
      row.appendChild(check)
    }
    row.addEventListener('click', function () { setPermission(option.id) })
    return row
  }

  async function setPermission(preset) {
    if (!state.currentId) return
    if (preset === currentPresetId(state.permissions)) return
    try {
      await rpc('permission.set', { sessionId: state.currentId, preset: preset })
      // The host appends permission/preset plus knob events; prime the chip so
      // the switch feels immediate and let the next frame correct the details.
      state.permissions = { preset: preset, sandbox: null, approval: null, seeded: true }
      updatePermChip()
      closePermissionSheet()
      toast('权限已切换：' + permissionLabel(preset))
    } catch (error) {
      toast(error.code === 'permission/denied' ? (error.message || '切换被拒绝') : (error.message || '切换失败'))
    }
  }

  // ── terminal ──────────────────────────────────────────────────────────
  async function openTerminal() {
    if (!state.currentId) return
    closeDrawer()
    var panel = $('terminalPanel')
    panel.hidden = false
    state.terminal.open = true
    $('terminalOut').textContent = '正在连接终端…'
    $('terminalTitle').textContent = '终端'
    try {
      await ensureTerminal()
      await refreshTerminal()
      startTerminalPoll()
    } catch (error) {
      $('terminalOut').textContent = '终端不可用：' + (error.message || error)
    }
  }

  function closeTerminal() {
    $('terminalPanel').hidden = true
    state.terminal.open = false
    stopTerminalPoll()
  }

  function startTerminalPoll() {
    stopTerminalPoll()
    state.terminal.timer = setInterval(function () {
      if (!state.terminal.open) return
      refreshTerminal().catch(function () {})
    }, 1000)
  }

  function stopTerminalPoll() {
    clearInterval(state.terminal.timer)
    state.terminal.timer = null
  }

  async function ensureTerminal() {
    if (state.terminal.id) return
    var listed = await rpc('terminal.list', { sessionId: state.currentId })
    var terminals = Array.isArray(listed.terminals) ? listed.terminals : []
    var existing = terminals.find(function (item) { return item.status !== 'exited' }) || terminals[0]
    if (existing) {
      state.terminal.id = existing.id
      state.terminal.name = existing.name || existing.type
      state.terminal.backends = listed.backends || []
      return
    }
    var created = await rpc('terminal.create', { sessionId: state.currentId, type: listed.backends && listed.backends[0] })
    state.terminal.id = created.id
    state.terminal.name = created.name || created.type
    state.terminal.backends = listed.backends || []
    $('terminalOut').textContent = plainTerminalText(created.motd)
  }

  /**
   * The panel is a plain <pre>, not a terminal emulator, so VT control
   * sequences emitted by the shell (cursor moves, mode switches, colours) would
   * otherwise show as garbage like `[?1004h` or `[4;22H`. They are stripped for
   * display only: the wire keeps the raw bytes so a real emulator can be
   * swapped in later.
   */
  function plainTerminalText(text) {
    return String(text == null ? '' : text)
      .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?/g, '')
      .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
      .replace(/\u001b[=>]/g, '')
      .replace(/\u001b[@-_]/g, '')
      .replace(/\r\n?/g, '\n')
      .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
      // A sequence cut off by the poll boundary: drop the leftover prefix.
      .replace(/\u001b(\[[0-9;?]*)?$/g, '')
  }

  async function refreshTerminal() {
    if (!state.terminal.id || !state.terminal.open) return
    var result = await rpc('terminal.read', {
      sessionId: state.currentId,
      terminalId: state.terminal.id,
      count: 300,
    })
    var out = $('terminalOut')
    var text = plainTerminalText(result.text) || '(无输出)'
    if (out.textContent !== text) {
      out.textContent = text
      out.scrollTop = out.scrollHeight
    }
    $('terminalTitle').textContent = '终端' + (state.terminal.name ? ' · ' + state.terminal.name : '')
  }

  async function terminalSend() {
    var input = $('terminalInput')
    var text = input.value
    if (!text || state.terminal.busy || !state.terminal.id) return
    input.value = ''
    state.terminal.busy = true
    try {
      await rpc('terminal.send', {
        sessionId: state.currentId,
        terminalId: state.terminal.id,
        text: text,
        submit: true,
        waitMs: 400,
      })
    } catch (error) {
      toast('终端发送失败：' + (error.message || error))
    } finally {
      state.terminal.busy = false
      refreshTerminal().catch(function () {})
      input.focus()
    }
  }

  async function terminalCtrlC() {
    if (!state.terminal.id) return
    try {
      await rpc('terminal.cancel', { sessionId: state.currentId, terminalId: state.terminal.id })
    } catch (error) {
      toast('中断失败：' + (error.message || error))
    }
    refreshTerminal().catch(function () {})
  }

  async function terminalNew() {
    try {
      var created = await rpc('terminal.create', { sessionId: state.currentId })
      state.terminal.id = created.id
      state.terminal.name = created.name || created.type
      $('terminalOut').textContent = created.motd || ''
      toast('已新建终端')
    } catch (error) {
      toast('新建终端失败：' + (error.message || error))
    }
    refreshTerminal().catch(function () {})
  }

  async function terminalKill() {
    if (!state.terminal.id) { closeTerminal(); return }
    try {
      await rpc('terminal.close', { sessionId: state.currentId, terminalId: state.terminal.id })
    } catch (error) {
      // The process may already be gone; closing locally is still right.
    }
    state.terminal.id = null
    closeTerminal()
    toast('终端已关闭')
  }

  // ── small utilities ────────────────────────────────────────────────────
  function basename(where) {
    if (!where) return ''
    var parts = String(where).split('/')
    return parts[parts.length - 1] || where
  }

  function relativeTime(at) {
    if (!at) return '刚刚'
    var diff = Date.now() - at
    if (diff < 60 * 1000) return '刚刚'
    if (diff < 60 * 60 * 1000) return Math.floor(diff / 60000) + ' 分钟前'
    if (diff < 24 * 60 * 60 * 1000) return Math.floor(diff / 3600000) + ' 小时前'
    if (diff < 7 * 24 * 60 * 60 * 1000) return Math.floor(diff / 86400000) + ' 天前'
    var date = new Date(at)
    return (date.getMonth() + 1) + '/' + date.getDate()
  }

  /** Whether a foldable row starts open: explicit user choice, else the setting. */
  function itemOpen(item, mode) {
    if (item.open === true) return true
    if (item.open === false) return false
    return mode === 'open'
  }

  // Tool cards are re-created from frame payloads, which replaces the item
  // object and would drop a per-item `open` flag. Remember the user's choice
  // per session instead, so an expanded card stays expanded.
  function cardKey(item) {
    return state.currentId + ':' + item.id
  }

  function cardOpen(item, mode) {
    if (state.openCards.has(cardKey(item))) return true
    if (state.closedCards.has(cardKey(item))) return false
    return mode === 'open'
  }

  function setCardOpen(item, open) {
    var key = cardKey(item)
    if (open) {
      state.openCards.add(key)
      state.closedCards.delete(key)
    } else {
      state.closedCards.add(key)
      state.openCards.delete(key)
    }
  }

  function cut(text, max) {
    var value = String(text == null ? '' : text)
    if (value.length <= max) return value
    return value.slice(0, max) + '…'
  }

  function truncate(text, max) {
    var value = String(text == null ? '' : text)
    if (value.length <= max) return value
    return value.slice(0, max) + '\n…（已截断）'
  }

  function oldestSeqOf(items) {
    var min = null
    for (var i = 0; i < items.length; i += 1) {
      var seq = items[i] && items[i].seq
      if (Number.isFinite(seq) && (min === null || seq < min)) min = seq
    }
    return min
  }

  function uuid() {
    if (window.crypto && window.crypto.randomUUID) return window.crypto.randomUUID()
    var bytes = new Uint8Array(16)
    if (window.crypto && window.crypto.getRandomValues) window.crypto.getRandomValues(bytes)
    else for (var i = 0; i < 16; i += 1) bytes[i] = Math.random() * 256 | 0
    bytes[6] = (bytes[6] & 0x0f) | 0x40
    bytes[8] = (bytes[8] & 0x3f) | 0x80
    var hex = []
    for (var j = 0; j < 16; j += 1) hex.push(('0' + bytes[j].toString(16)).slice(-2))
    return hex.slice(0, 4).join('') + '-' + hex.slice(4, 6).join('') + '-' + hex.slice(6, 8).join('')
      + '-' + hex.slice(8, 10).join('') + '-' + hex.slice(10, 16).join('')
  }

  function timezone() {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || undefined } catch (error) { return undefined }
  }

  function modelLabel(model) {
    if (!model) return '助手'
    if (typeof model === 'string') return model
    return model.model || '助手'
  }

  function toolIcon(name) {
    var key = String(name || '').toLowerCase()
    if (/bash|shell|terminal|pwsh|powershell|exec/.test(key)) {
      return '<svg viewBox="0 0 24 24"><path d="M4 7l5 5-5 5M11 17h9"/></svg>'
    }
    if (/edit|write|str_replace|apply|patch|file/.test(key)) {
      return '<svg viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16v4Z"/><path d="M13.5 6.5l4 4"/></svg>'
    }
    if (/read|cat|open/.test(key)) {
      return '<svg viewBox="0 0 24 24"><path d="M4 5h16v14H4z"/><path d="M8 9h8M8 13h5"/></svg>'
    }
    if (/search|grep|glob|find/.test(key)) {
      return '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="6"/><path d="M16 16l4 4"/></svg>'
    }
    if (/web|fetch|http|browse/.test(key)) {
      return '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><path d="M4 12h16M12 4c3 3 3 13 0 16M12 4c-3 3-3 13 0 16"/></svg>'
    }
    if (/todo|task|plan/.test(key)) {
      return '<svg viewBox="0 0 24 24"><path d="M5 7h14M5 12h14M5 17h9"/></svg>'
    }
    if (/job|background/.test(key)) {
      return '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/></svg>'
    }
    if (/subagent|agent|team/.test(key)) {
      return '<svg viewBox="0 0 24 24"><circle cx="9" cy="9" r="3"/><circle cx="16" cy="14" r="3"/><path d="M4 19c1.5-3 4-4 5-4M19 7c0 2-1 3-2 4"/></svg>'
    }
    return '<svg viewBox="0 0 24 24"><path d="M12 3l2.5 5.5L20 11l-5.5 2.5L12 19l-2.5-5.5L4 11l5.5-2.5z"/></svg>'
  }

  function shortToolName(name) {
    return String(name || 'tool')
  }

  function approvalOutcomeLabel(outcome) {
    if (outcome === 'allowed-once') return '已允许'
    if (outcome === 'rejected') return '已拒绝'
    if (outcome === 'cancelled') return '已取消'
    return String(outcome || '未知')
  }

  function promptErrorText(error) {
    var code = error && error.code
    if (code === 'session/not-found') return '会话已不存在，请刷新列表'
    if (code === 'session/writer-held') return '该会话正被其他窗口占用，请先在桌面端关闭'
    if (code === 'session/agent-busy') return '这是一个子代理会话，不能直接输入'
    if (code === 'session/model-unavailable') return '当前模型不可用，请在桌面端切换模型'
    if (code === 'transport') return '网络异常，请稍后重试'
    return (error && error.message) || '发送失败'
  }

  function cssEscape(text) {
    if (window.CSS && window.CSS.escape) return window.CSS.escape(text)
    return String(text).replace(/["\\]/g, '\\$&')
  }

  // ── boot ───────────────────────────────────────────────────────────────
  function boot() {
    // Re-assert the theme on boot: the inline head script already set it before
    // first paint, this also refreshes the status-bar colour.
    applyTheme()
    if (window.matchMedia) {
      var scheme = window.matchMedia('(prefers-color-scheme: dark)')
      var onScheme = function () { if (state.settings.theme === 'system') applyTheme() }
      if (scheme.addEventListener) scheme.addEventListener('change', onScheme)
      else if (scheme.addListener) scheme.addListener(onScheme)
    }
    if (!initCrypto()) {
      fatal('缺少配对密钥或加密库未加载。请从电脑上的 DSH 控制台重新扫码配对。')
      return
    }
    renderEmpty('loading')
    connectWs()
    rpc('hello', {}).then(function (hello) {
      state.booted = true
      state.version = hello.version
      state.deviceId = hello.device && hello.device.id
      state.upstream = hello.upstream !== false
      if (!state.upstream) {
        setBanner('DSH 会话服务尚未就绪：请重启 dsh web 以加载新版 relay 插件。', true)
      }
      updateSessionChrome()
      return refreshSessions()
    }).then(function () {
      if (!state.currentId && !state.sessions.length) renderEmpty('empty')
    }).catch(function (error) {
      if (error && error.code === 'unavailable') {
        setBanner('DSH 会话服务不可用：请重启 dsh web 加载新版 relay 插件。', true)
        return
      }
      setBanner((error && error.message) || '连接失败', true)
      renderEmpty('empty')
    })
    observeViewport()
  }

  // Keyboard handling. Two platform behaviours must both work:
  //  - Android Chrome with interactive-widget=resizes-content resizes the
  //    layout viewport itself (visualViewport.height == innerHeight), so the
  //    app simply fills it;
  //  - older iOS keeps the layout viewport and shrinks only the visual one, and
  //    may also scroll it, so the app follows the visual viewport.
  //
  // Recent iOS (17+) shrinks `innerHeight` together with the keyboard but keeps
  // reporting a visualViewport that is smaller still, and during the animation
  // it reports values that are smaller than the keyboard could ever make it.
  // Taking that number at face value is what squeezed the page: the composer
  // ended up near the top with a large empty area under it. So the visual
  // viewport is only trusted when it plausibly means "layout minus keyboard"
  // (60%..100% of the layout viewport); otherwise the layout viewport, which
  // already excludes the keyboard, is the answer. `#debug` shows the numbers.
  function observeViewport() {
    var vv = window.visualViewport
    var settle = null
    var applied = ''
    var debugNode = null
    // Largest visible height this phone has ever shown above the keyboard.
    //
    // The keyboard does not change between attempts, but the numbers the page
    // gets do: the same keyboard produced `sy=322` (composer correctly above it)
    // and `sy=480` (composer mid-screen) in consecutive attempts, with the
    // visible height reported as 332 and 174. Overshoot is always caused by a
    // *smaller* visible height, so the largest value seen is the closest to the
    // truth; it is remembered across sessions and only ever grows.
    var VISIBLE_KEY = 'dshRelayVisibleHint'
    var visibleHint = 0
    var shift = 0
    try {
      var stored = parseInt(window.localStorage.getItem(VISIBLE_KEY) || '0', 10)
      if (stored > 100) visibleHint = stored
    } catch (error) {}

    function rememberVisible(value, layout) {
      if (!(value > 100) || value >= layout - 80) return
      if (value <= visibleHint) return
      visibleHint = value
      try { window.localStorage.setItem(VISIBLE_KEY, String(value)) } catch (error) {}
    }

    function metrics() {
      var layout = Math.max(window.innerHeight, document.documentElement.clientHeight || 0)
      var visual = vv ? Math.round(vv.height) || 0 : layout
      var offset = vv ? Math.max(0, Math.round(vv.offsetTop) || 0) : 0
      return {
        layout: layout,
        visual: visual,
        offset: offset,
        scroll: Math.round(window.scrollY || 0),
      }
    }

    function apply() {
      var m = metrics()
      var focused = document.activeElement === inputEl
      // iOS scrolls the page on focus to reveal the composer, but how far it
      // scrolls is not reproducible (322 one time, 480 the next), and every
      // value derived from `visualViewport` produced a wrong layout sooner or
      // later. So: the app stays in the document at full height, and the scroll
      // position is set here — the composer is placed at the bottom of the
      // remembered visible area. The browser's own scroll is just a head start.
      if (focused) {
        rememberVisible(m.visual, m.layout)
        var visible = visibleHint > 0 ? visibleHint : m.visual
        if (!(visible > 100) || visible >= m.layout) visible = m.layout
        // Where the app would have to sit so its bottom lands on the visible
        // area's lower edge. Expressed as a transform instead of a scroll: it
        // needs no scrollable document and cannot fight iOS's own scroll, which
        // is what varies between attempts.
        shift = m.scroll - (m.layout - visible)
      } else {
        shift = 0
      }
      var next = 'abs|' + m.layout
      if (next !== applied) {
        applied = next
        app.style.position = 'absolute'
        app.style.top = '0px'
        app.style.height = m.layout + 'px'
        app.style.paddingBottom = ''
      }
      var transform = Math.abs(shift) > 1 ? 'translateY(' + Math.round(shift) + 'px)' : ''
      if (transform !== app.style.transform) app.style.transform = transform
      if (debugNode) {
        var perm = state.permissions
        debugNode.textContent = 'ih=' + m.layout + ' vv=' + m.visual + ' off=' + m.offset
          + ' hint=' + visibleHint + ' shift=' + Math.round(shift) + ' sy=' + m.scroll
          + ' focus=' + (focused ? '1' : '0')
          + ' dpr=' + (window.devicePixelRatio || 1)
          + ' perm=' + (perm ? (perm.preset || '-') : 'null')
      }
    }

    // Coalesce the burst of resize events an animation produces, then apply the
    // settled value.
    function schedule(delay) {
      clearTimeout(settle)
      settle = setTimeout(apply, delay)
    }

    if (vv) {
      vv.addEventListener('resize', function () { schedule(220) })
      vv.addEventListener('scroll', function () { schedule(120) })
    }
    // iOS may scroll the document itself while editing, which changes the value
    // both viewport heights are measured against.
    window.addEventListener('scroll', function () { schedule(60) }, { passive: true })
    // No immediate apply on focus: the layout can still change while the
    // keyboard animates (Android shrinks it), so the settled value is applied.
    window.addEventListener('focusin', function () { schedule(320); setTimeout(apply, 900) })
    // `blur` does not bubble, so it is caught in the capture phase as well as
    // the bubbled `focusout`: losing focus must restore the fixed layout, and
    // the document scroll iOS introduced has to be undone or the transcript
    // stays shifted up after the keyboard is gone.
    function releaseScroll() {
      if (window.scrollY > 0) {
        try { window.scrollTo(0, 0) } catch (error) {}
      }
    }
    window.addEventListener('focusout', function () { releaseScroll(); setTimeout(apply, 150) })
    window.addEventListener('blur', function () { releaseScroll(); setTimeout(apply, 150) }, true)
    window.addEventListener('orientationchange', function () { apply(); schedule(300) })
    setInterval(function () { if (document.activeElement === inputEl) apply() }, 700)
    apply()

    // `#debug` on the URL shows the live numbers, for screenshots from a phone
    // whose keyboard behaviour cannot be reproduced elsewhere. It lives inside
    // the app so the iOS page scroll cannot move it away (a `fixed` bar drifts
    // with that scroll), and it never reports anything anywhere.
    if (location.hash === '#debug') {
      debugNode = document.createElement('div')
      debugNode.id = 'viewport-debug'
      debugNode.style.cssText = 'position:absolute;left:0;right:0;top:0;z-index:9999;'
        + 'padding:4px 8px;background:rgba(0,0,0,.85);color:#9db2ff;font:11px/1.4 monospace;'
        + 'pointer-events:none;white-space:pre-wrap'
      app.appendChild(debugNode)
      apply()
    }
  }

  // Periodic relative-time refresh for the drawer list.
  setInterval(function () { if (state.drawerOpen) renderSessions() }, 60000)

  boot()
})()
