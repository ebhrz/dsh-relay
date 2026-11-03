// Host-side bridge between the mobile page and the DSH native session APIs.
//
// The page never talks to the DSH web frontend: this module calls the live
// host services in-process and pushes a small, stable frame vocabulary over the
// sealed phone channel.
//
//   list      ctx.sessionController.list
//   open      ctx.sessionController.follow        (snapshot + durable events + live token stream)
//   older     ctx.sessionController.page
//   prompt    ctx.sessionController.prompt        (includes cold-session resume)
//   stop      ctx.sessionController.cancel
//   approvals ctx.on('approval/request')          waterfall, phone-first
//   questions ctx.on('user-questions/request')    waterfall, phone-first
//
// Everything else (title/model projections, row status) comes from the live
// events documented in docs/mobile/native-api.md.

import crypto from 'node:crypto'
import { SessionView, foldSnapshot, headerMeta } from './fold.js'
import { auditLog } from '../identity.js'

const FOLLOW_RETRY_MS = 2500
const APPROVAL_DEADLINE_MS = 10 * 60 * 1000
const MAX_PROMPT_CHARS = 100_000
const MAX_IMAGE_BYTES = 8 * 1024 * 1024
const MAX_TOTAL_IMAGE_BYTES = 16 * 1024 * 1024

/** A structured, phone-safe error (code survives to the UI). */
function fail(code, message) {
  const error = new Error(message ?? code)
  error.code = code
  return error
}

function compactRow(row) {
  return {
    id: row.sessionId,
    title: row.projections?.values?.title ?? null,
    updatedAt: row.updatedAt ?? 0,
    running: row.running === true,
    agentAvailable: row.agentAvailable === true,
    blank: row.blank === true,
    cwd: row.cwd ?? null,
    formatStatus: row.formatStatus ?? 'current',
    model: row.projections?.values?.modelSelection?.lastUsed ?? null,
    parentSessionId: row.parentSessionId ?? null,
    origin: row.origin ?? null,
  }
}

/**
 * Preset from the `permissions` session projection.
 *
 * A projection has two shapes: the host-internal state (`{preset, sandbox,
 * approval, seeded}`) and the **wire view** clients actually receive, which for
 * this unit is `{currentValue: "<preset>"}` (see `wire.view` in
 * `@deepseek-ai/dsh-permission-presets`). Follow snapshots and
 * `sessionController.projections()` both carry the wire shape, so `currentValue`
 * is the field to read; the knob fields only appear in host-internal state.
 */
function normalizePermissions(state) {
  if (!state || typeof state !== 'object') return null
  const preset = typeof state.currentValue === 'string' && state.currentValue !== ''
    ? state.currentValue
    : (typeof state.preset === 'string' ? state.preset : null)
  return {
    preset,
    sandbox: typeof state.sandbox === 'string' ? state.sandbox : null,
    approval: typeof state.approval === 'string' ? state.approval : null,
    seeded: state.seeded === true,
  }
}

export class MobileBridge {
  /**
   * @param ctx - the plugin's Cordis context (child of the root host context).
   * @param options - { version, logger }
   */
  constructor(ctx, options = {}) {
    this.ctx = ctx
    this.version = options.version ?? '0'
    this.log = options.logger ?? ctx.logger ?? console
    this.subs = new Map() // phone sid -> subscription
    this.pending = new Map() // interaction key -> entry
    this.continued = new Map() // key (`q:<callId>`) -> {sessionId, callId, questions}
    this.titles = new Map() // sessionId -> title from list rows
    this.ownTerminals = new Map() // `${sessionId}:${id}` -> plugin-owned fallback PTY
    this.disposers = []
    this.started = false
    this.phoneCount = 0
    // Several 0.2.1 controller entry points call `signal.throwIfAborted()`
    // unconditionally (prompt/page/follow). A real long-lived signal is
    // mandatory; passing undefined crashes inside the host, not here.
    this.abort = new AbortController()
  }

  /** Host-call cancellation signal shared by unary controller calls. */
  signal() {
    return this.abort.signal
  }

  // -- service lookup -------------------------------------------------------
  controller() {
    const controller = this.ctx.get('sessionController')
    if (!controller) throw fail('unavailable', 'session controller unavailable in this composition')
    return controller
  }

  workspaces() {
    return this.ctx.get('workspaceRegistry')
  }

  agents() {
    return this.ctx.get('agents')
  }

  questions() {
    return this.ctx.get('userQuestions')
  }

  upstreamReady() {
    return Boolean(this.ctx.get('sessionController'))
  }

  /** Install live-event taps and interaction answerers (idempotent). */
  install() {
    if (this.started) return
    this.started = true
    const ctx = this.ctx
    const disposers = this.disposers

    disposers.push(ctx.on('session/event', (session, event) => this.onDurable(session, event)))
    disposers.push(ctx.on('agent/assistant-stream', (payload) => this.onAssistantStream(payload)))
    disposers.push(ctx.on('agent/status', (payload) => this.onAgentStatus(payload)))
    disposers.push(ctx.on('api-session/added', (row) => this.onRowAdded(row)))
    disposers.push(ctx.on('api-session/removed', (sessionId) => this.broadcast({ t: 'row-removed', sessionId })))
    disposers.push(ctx.on('api-session/status', (sessionId, running) => {
      this.broadcast({ t: 'status', sessionId, running: running === true })
    }))
    disposers.push(ctx.on('api-session/activity', (sessionId, updatedAt) => {
      this.broadcast({ t: 'row-changed', sessionId, updatedAt })
    }))
    disposers.push(ctx.on('api-session/error', (sessionId, message) => {
      this.broadcast({ t: 'toast', sessionId, message: String(message ?? 'error') })
    }))

    // Approval / question waterfalls: prepend, phone-first, delegate to the
    // rest of the chain whenever no phone is watching that session.
    this.onApprovalEvent = (req, next) => this.handleApproval(req, next)
    this.onQuestionEvent = (request, next) => this.handleQuestion(request, next)
    ctx.on('approval/request', this.onApprovalEvent, { prepend: true })
    ctx.on('user-questions/request', this.onQuestionEvent, { prepend: true })
  }

  dispose() {
    for (const owned of this.ownTerminals.values()) {
      try { owned.handle?.terminate?.() } catch {}
    }
    this.ownTerminals.clear()
    try { this.abort.abort() } catch {}
    for (const sub of this.subs.values()) this.stopSub(sub)
    this.subs.clear()
    for (const entry of this.pending.values()) this.settlePending(entry, entry.kind === 'approval' ? 'cancelled' : undefined, true)
    this.pending.clear()
    for (const dispose of this.disposers) {
      try { dispose() } catch {}
    }
    this.disposers = []
    this.started = false
  }

  // -- phone socket lifecycle ----------------------------------------------
  onPhoneOpen() {
    this.phoneCount += 1
  }

  onPhoneClose({ sid }) {
    this.phoneCount = Math.max(0, this.phoneCount - 1)
    this.unsubscribe(sid)
  }

  subscribersFor(sessionId) {
    const out = []
    for (const sub of this.subs.values()) {
      if (sub.sessionId === sessionId) out.push(sub)
    }
    return out
  }

  hasPhoneFor(sessionId) {
    for (const sub of this.subs.values()) {
      if (sub.sessionId === sessionId) return true
    }
    return false
  }

  sendTo(sessionId, frame) {
    for (const sub of this.subscribersFor(sessionId)) this.safeSend(sub, frame)
  }

  broadcast(frame) {
    for (const sub of this.subs.values()) this.safeSend(sub, frame)
  }

  safeSend(sub, frame) {
    try { sub.send(frame) } catch (error) {
      this.log.warn?.(`[relay-mobile] send failed: ${error?.message ?? error}`)
    }
  }

  /** Phone opened a session: start the durable+live follow stream. */
  subscribe(sid, sessionId, send) {
    this.unsubscribe(sid)
    const sub = {
      sid,
      sessionId,
      send,
      abort: new AbortController(),
      view: null,
      timer: null,
      // Latest folded permission knobs ({preset, sandbox, approval, seeded});
      // the snapshot carries the projection, later events keep it current.
      permissions: null,
    }
    this.subs.set(sid, sub)
    this.runFollow(sub)
  }

  unsubscribe(sid) {
    const sub = this.subs.get(sid)
    if (!sub) return
    this.subs.delete(sid)
    this.stopSub(sub, { releaseInteractions: !this.hasPhoneFor(sub.sessionId) })
  }

  stopSub(sub, { releaseInteractions = true } = {}) {
    try { sub.abort.abort() } catch {}
    clearTimeout(sub.timer)
    if (releaseInteractions) this.releaseSessionInteractions(sub.sessionId)
  }

  /** Settle interactions whose phone went away (otherwise a turn hangs). */
  releaseSessionInteractions(sessionId) {
    for (const entry of this.pending.values()) {
      if (entry.sessionId !== sessionId) continue
      if (entry.kind === 'approval') {
        this.settlePending(entry, 'cancelled')
      } else {
        this.settlePending(entry, undefined, true)
      }
    }
  }

  async runFollow(sub) {
    if (!this.subs.has(sub.sid) || this.subs.get(sub.sid) !== sub) return
    let controller
    try {
      controller = this.controller()
    } catch (error) {
      this.safeSend(sub, { t: 'error', code: error.code ?? 'unavailable', message: error.message })
      return
    }
    try {
      const stream = controller.follow({
        address: { kind: 'session', sessionId: sub.sessionId },
        assistantStream: true,
        maxMessages: 40,
      }, sub.abort.signal)
      for await (const frame of stream) {
        if (sub.abort.signal.aborted || this.subs.get(sub.sid) !== sub) return
        this.acceptFollowFrame(sub, frame)
      }
    } catch (error) {
      if (sub.abort.signal.aborted) return
      this.safeSend(sub, { t: 'error', code: error?.code ?? 'follow-failed', message: String(error?.message ?? error) })
      // A dropped follow stream must not silently freeze the chat: retry with
      // a fresh snapshot after a short backoff.
      sub.timer = setTimeout(() => this.runFollow(sub), FOLLOW_RETRY_MS)
    }
  }

  acceptFollowFrame(sub, frame) {
    if (!frame || typeof frame.type !== 'string') return
    if (frame.type === 'snapshot') {
      const snapshot = foldSnapshot(frame)
      sub.permissions = normalizePermissions(frame.projections?.values?.permissions)
      sub.view = new SessionView()
      sub.view.items = snapshot.items
      sub.view.byId = new Map(snapshot.items.map((item) => [item.id, item]))
      sub.view.cursor = snapshot.cursor
      sub.view.hasMore = snapshot.hasMore
      sub.view.meta = snapshot.meta
      sub.view.title = snapshot.title
      sub.view.stream = snapshot.stream
      this.safeSend(sub, {
        t: 'session',
        sessionId: sub.sessionId,
        title: snapshot.title ?? this.titles.get(sub.sessionId) ?? null,
        meta: snapshot.meta,
        items: snapshot.items,
        cursor: snapshot.cursor,
        hasMore: snapshot.hasMore,
        stream: snapshot.stream,
        running: this.agents()?.get?.(sub.sessionId)?.status === 'running',
        projections: frame.projections?.values ?? {},
        permissions: sub.permissions,
      })
      this.noteProjectionQuestions(sub.sessionId, frame.projections?.values?.userQuestions)
      this.hydratePermissions(sub)
      this.replayInteractions(sub)
      return
    }
    if (frame.type === 'event' && frame.event) {
      this.onDurableForSub(sub, frame.event)
      return
    }
    if (frame.type === 'assistant-stream' && frame.frame) {
      const streamFrame = frame.frame
      this.safeSend(sub, {
        t: 'assistant-stream',
        sessionId: sub.sessionId,
        frame: {
          type: streamFrame.type,
          attemptId: streamFrame.attemptId,
          revision: streamFrame.revision,
          ...(streamFrame.type === 'chunk' ? { chunk: streamFrame.chunk } : {}),
          ...(streamFrame.type === 'start' ? { turn: streamFrame.turn, step: streamFrame.step } : {}),
          ...(streamFrame.type === 'end' ? { outcome: streamFrame.outcome } : {}),
        },
      })
    }
  }

  onDurableForSub(sub, event) {
    this.trackPermission(sub, event)
    if (!sub.view) return
    const ops = sub.view.apply(event)
    if (ops.added.length === 0 && ops.updated.length === 0) return
    this.safeSend(sub, {
      t: 'items',
      sessionId: sub.sessionId,
      added: ops.added,
      updated: ops.updated,
      cursor: sub.view.cursor,
    })
  }

  /**
   * The follow snapshot only carries projections when its source computed them,
   * and a cold session often has none. Read the `permissions` projection once
   * per subscription so the phone still knows the current preset.
   */
  async hydratePermissions(sub) {
    if (sub.permissions) return
    if (!this.ctx.get('permissionPresets')) {
      auditLog(`mobile permission: no permissionPresets service for ${sub.sessionId}`)
      return
    }
    const controller = this.controller()
    if (typeof controller.projections !== 'function') return
    try {
      // `projections()` calls `signal.throwIfAborted()` before reading anything,
      // so this must pass the shared signal: without it the call throws and the
      // chip silently stays empty.
      const extra = await controller.projections({ sessionId: sub.sessionId }, this.signal())
      if (this.subs.get(sub.sid) !== sub) return
      const permissions = normalizePermissions(extra?.values?.permissions)
      if (!permissions || !permissions.preset) {
        auditLog(`mobile permission: projection ${extra?.kind ?? 'none'} without a preset for ${sub.sessionId}: ${JSON.stringify(extra?.values?.permissions ?? null).slice(0, 120)}`)
        return
      }
      sub.permissions = permissions
      this.safeSend(sub, { t: 'permission', sessionId: sub.sessionId, permissions })
    } catch (error) {
      // Permission state is a nicety: a projection read must never break the chat,
      // but a silent failure is what kept this chip blank for two releases.
      auditLog(`mobile permission: projection read failed for ${sub.sessionId}: ${String(error?.message ?? error)}`)
    }
  }

  /**
   * Keep the phone's copy of the permission knobs current. The preset change and
   * its two knob writes are separate durable events, so the phone gets the same
   * folded state the host projection would expose on the next snapshot.
   */
  trackPermission(sub, event) {
    const type = event?.type
    if (type !== 'permission/preset' && type !== 'sandbox/mode'
      && type !== 'approval/policy' && type !== 'session/end-seed') return
    const next = {
      preset: null, sandbox: null, approval: null, seeded: false,
      ...(sub.permissions ?? {}),
    }
    if (type === 'permission/preset') next.preset = event.data?.preset ?? null
    else if (type === 'sandbox/mode') next.sandbox = event.data?.mode ?? null
    else if (type === 'approval/policy') next.approval = event.data?.policy ?? null
    else next.seeded = true
    sub.permissions = next
    this.safeSend(sub, { t: 'permission', sessionId: sub.sessionId, permissions: next })
  }

  // -- live broadcast taps --------------------------------------------------
  onDurable(session, event) {
    if (!session || !event) return
    // Durable rows for a followed session arrive through that session's own
    // gap-free `follow` stream; forwarding the global event too would apply
    // every event twice. The global tap only maintains cross-subscriber
    // metadata (titles) that follow snapshots do not push incrementally.
    if (event.type === 'session/title' && typeof event.data?.title === 'string') {
      this.titles.set(session.id, event.data.title)
      this.sendTo(session.id, { t: 'title', sessionId: session.id, title: event.data.title })
    }
  }

  onAssistantStream(payload) {
    const agent = payload?.agent
    const frame = payload?.frame
    if (!agent || !frame) return
    for (const sub of this.subscribersFor(agent.id)) {
      if (!sub.view) continue
      this.safeSend(sub, {
        t: 'assistant-stream',
        sessionId: agent.id,
        frame: {
          type: frame.type,
          attemptId: frame.attemptId,
          revision: frame.revision,
          ...(frame.type === 'chunk' ? { chunk: frame.chunk } : {}),
          ...(frame.type === 'start' ? { turn: frame.turn, step: frame.step } : {}),
          ...(frame.type === 'end' ? { outcome: frame.outcome } : {}),
        },
      })
    }
  }

  onAgentStatus(payload) {
    const agent = payload?.agent
    if (!agent) return
    this.broadcast({ t: 'status', sessionId: agent.id, running: payload.status === 'running' })
  }

  onRowAdded(row) {
    if (!row) return
    const compact = compactRow(row)
    if (compact.title) this.titles.set(compact.id, compact.title)
    this.broadcast({ t: 'row', row: compact })
  }

  // -- RPC surface ----------------------------------------------------------
  async rpc(method, params, { sid } = {}) {
    switch (method) {
      case 'hello':
        return {
          device: { id: this.deviceId },
          version: this.version,
          now: Date.now(),
          phoneConnected: this.subs.size > 0,
          upstream: this.upstreamReady(),
        }
      case 'sessions':
        return this.listSessions()
      case 'open':
        return this.openSession(params?.sessionId)
      case 'older':
        return this.olderPage(params)
      case 'prompt':
        return this.prompt(params, sid)
      case 'stop':
        return this.stop(params)
      case 'create':
        return this.createSession(params)
      case 'rename':
        return this.renameSession(params)
      case 'fork':
        return this.forkSession(params)
      case 'interaction.answer':
        return this.answerInteraction(params)
      case 'interaction.cancel':
        return this.cancelInteraction(params)
      case 'tool.detail':
        return this.toolDetail(params, sid)
      case 'image.get':
        return this.imageGet(params)
      case 'terminal.list':
        return this.terminalList(params)
      case 'terminal.create':
        return this.terminalCreate(params)
      case 'terminal.read':
        return this.terminalRead(params)
      case 'terminal.send':
        return this.terminalSend(params)
      case 'terminal.cancel':
        return this.terminalCancel(params)
      case 'terminal.close':
        return this.terminalClose(params)
      case 'model.catalog':
        return this.modelCatalog()
      case 'model.select':
        return this.selectModel(params)
      case 'permission.catalog':
        return this.permissionCatalog()
      case 'permission.set':
        return this.permissionSet(params)
      default:
        throw fail('method-not-found', `unknown method ${method}`)
    }
  }

  async listSessions() {
    const controller = this.controller()
    const registry = this.workspaces()
    let rows = []
    try {
      rows = (await controller.list({}, this.signal())).items ?? []
    } catch (error) {
      throw fail(error?.code ?? 'list-failed', String(error?.message ?? error))
    }
    const archived = new Set(registry?.archivedSessionIds ?? [])
    return {
      sessions: rows
        // Subagent sessions are separate transcripts, not conversations the
        // phone should open. Forks are ordinary sessions and must stay visible
        // even though they carry a parentSessionId.
        .filter((row) => row.origin !== 'subagent')
        .filter((row) => !archived.has(row.sessionId))
        .map(compactRow),
      workspaces: (registry?.list?.() ?? []).map((workspace) => ({
        id: workspace.id,
        title: workspace.title ?? null,
        path: workspace.path ?? null,
        // Ordered ids: the host keeps newest-first inside a project, and the
        // phone uses this both to group sessions and to show empty projects.
        sessionIds: Array.isArray(workspace.sessionIds) ? workspace.sessionIds.slice() : [],
      })),
    }
  }

  async openSession(sessionId) {
    if (typeof sessionId !== 'string' || sessionId === '') throw fail('bad-request', 'sessionId required')
    // The follow stream is started by the phone's WS subscribe; this call just
    // returns the row metadata the composer needs before that lands.
    const { sessions } = await this.listSessions()
    const row = sessions.find((item) => item.id === sessionId)
    if (!row) throw fail('session/not-found', 'session not found')
    return { session: row }
  }

  async olderPage(params) {
    const controller = this.controller()
    const sessionId = params?.sessionId
    if (typeof sessionId !== 'string') throw fail('bad-request', 'sessionId required')
    const throughSeq = Number(params?.throughSeq)
    if (!Number.isFinite(throughSeq)) throw fail('bad-request', 'throughSeq required')
    const request = {
      address: { kind: 'session', sessionId },
      throughSeq,
      maxMessages: clampInt(params?.maxMessages, 20, 100, 40),
    }
    if (Number.isFinite(Number(params?.beforeSeq))) request.beforeSeq = Number(params.beforeSeq)
    const page = await controller.page(request, this.signal())
    const view = new SessionView()
    for (const record of page?.records ?? []) {
      const event = record && record.type === 'event' ? record.event : null
      if (event) view.apply(event)
    }
    return {
      items: view.wireItems(),
      hasMore: page?.hasMore === true,
      oldestSeq: view.items.length ? seqOfFirstEvent(page.records) : null,
    }
  }

  async prompt(params, sid) {
    const controller = this.controller()
    const sessionId = params?.sessionId
    if (typeof sessionId !== 'string' || sessionId === '') throw fail('bad-request', 'sessionId required')
    const text = String(params?.text ?? '')
    if (text.length > MAX_PROMPT_CHARS) throw fail('bad-request', 'oversized prompt')
    const images = this.validateImages(params?.images)
    if (text.trim() === '' && images.length === 0) throw fail('bad-request', 'empty prompt')
    if (params?.mode !== undefined && params.mode !== 'queue' && params.mode !== 'steer') {
      throw fail('bad-request', 'mode must be queue or steer')
    }
    const mode = params?.mode === 'steer' ? 'steer' : 'queue'
    const requestId = typeof params?.requestId === 'string' && /^[A-Za-z0-9-]{8,64}$/.test(params.requestId)
      ? params.requestId
      : crypto.randomUUID()
    let clientTimeZone = params?.clientTimeZone
    if (typeof clientTimeZone === 'string') {
      try {
        new Intl.DateTimeFormat('en', { timeZone: clientTimeZone })
      } catch {
        clientTimeZone = undefined
      }
    } else {
      clientTimeZone = undefined
    }
    const content = []
    if (text.trim() !== '') content.push({ type: 'text', text })
    for (const image of images) content.push({ type: 'image', mediaType: image.mediaType, data: image.data, ...(image.name ? { name: image.name } : {}) })
    try {
      await controller.prompt({
        requestId,
        sessionId,
        mode,
        content,
        ...(clientTimeZone === undefined ? {} : { clientTimeZone }),
      }, this.signal())
    } catch (error) {
      throw fail(error?.code ?? error?.name ?? 'prompt-failed', String(error?.message ?? error))
    }
    return { accepted: true, requestId }
  }

  /**
   * Validate phone-supplied images for a prompt. The host re-validates size and
   * modality; this only keeps obviously bad input and oversized uploads out of
   * the in-process call (wire schema validation does not run here).
   */
  validateImages(raw) {
    if (raw === undefined || raw === null) return []
    if (!Array.isArray(raw)) throw fail('bad-request', 'images must be an array')
    if (raw.length > 8) throw fail('bad-request', 'too many images (max 8)')
    const allowed = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif'])
    const out = []
    let total = 0
    for (const item of raw) {
      const mediaType = String(item?.mediaType ?? 'image/jpeg')
      if (!allowed.has(mediaType)) throw fail('bad-request', 'unsupported image type ' + mediaType)
      const data = String(item?.data ?? '').replace(/^data:[^;]+;base64,/, '')
      if (data === '' || !/^[A-Za-z0-9+/=]+$/.test(data)) throw fail('bad-request', 'bad image data')
      const bytes = Buffer.from(data, 'base64').length
      if (bytes > MAX_IMAGE_BYTES) throw fail('bad-request', 'image too large (max 8MB each)')
      total += bytes
      if (total > MAX_TOTAL_IMAGE_BYTES) throw fail('bad-request', 'images too large in total (max 16MB)')
      out.push({ mediaType, data, ...(typeof item?.name === 'string' ? { name: item.name.slice(0, 120) } : {}) })
    }
    return out
  }

  /** Read one image the session log references (bubbles render it inline). */
  async imageGet(params) {
    const controller = this.controller()
    const sessionId = params?.sessionId
    const attachmentId = params?.attachmentId
    if (typeof sessionId !== 'string' || typeof attachmentId !== 'string') throw fail('bad-request', 'sessionId and attachmentId required')
    try {
      const value = await controller.attachment({ sessionId, attachmentId }, this.signal())
      return {
        attachment: value?.attachment ?? null,
        mediaType: value?.attachment?.mediaType ?? 'image/jpeg',
        data: value?.data ?? '',
      }
    } catch (error) {
      throw fail(error?.code ?? 'attachment-failed', String(error?.message ?? error))
    }
  }

  async stop(params) {
    const controller = this.controller()
    const sessionId = params?.sessionId
    if (typeof sessionId !== 'string' || sessionId === '') throw fail('bad-request', 'sessionId required')
    try {
      await controller.cancel({ sessionId }, undefined)
    } catch (error) {
      throw fail(error?.code ?? 'cancel-failed', String(error?.message ?? error))
    }
    return { accepted: true }
  }

  async createSession() {
    const controller = this.controller()
    // Prefer the desktop "new session" behaviour; fall back to reusing a blank
    // row when create is not available or the composition has no workspace.
    try {
      const created = await controller.create({}, undefined)
      if (created?.sessionId) return { sessionId: created.sessionId }
    } catch (error) {
      this.log.warn?.(`[relay-mobile] session create failed, reusing blank row: ${error?.message ?? error}`)
    }
    const { sessions } = await this.listSessions()
    const blank = sessions.find((row) => row.blank)
    if (blank) return { sessionId: blank.id, reused: true }
    throw fail('create-failed', 'could not create a session')
  }

  async renameSession(params) {
    const controller = this.controller()
    const sessionId = params?.sessionId
    const title = String(params?.title ?? '').trim()
    if (typeof sessionId !== 'string' || title === '' || title.length > 120) throw fail('bad-request', 'bad rename')
    const result = await controller.rename({ sessionId, title }, undefined)
    this.titles.set(sessionId, result?.title ?? title)
    this.sendTo(sessionId, { t: 'title', sessionId, title: this.titles.get(sessionId) })
    return { title: this.titles.get(sessionId) }
  }

  /**
   * Copy the conversation up to an event boundary into a new session.
   *
   * `atSeq` is an inclusive session-event sequence; omitted means "the latest
   * completed turn", which is what the phone's "fork from here" offers by
   * default. The host attaches the child to the source's workspace and seeds it
   * with the inherited history, so the phone just switches to the new id.
   */
  async forkSession(params) {
    const controller = this.controller()
    const sessionId = params?.sessionId
    if (typeof sessionId !== 'string' || sessionId === '') throw fail('bad-request', 'sessionId required')
    const request = { sessionId }
    const atSeq = Number(params?.atSeq)
    if (Number.isInteger(atSeq) && atSeq >= 0) request.atSeq = atSeq
    let result
    try {
      result = await controller.fork(request)
    } catch (error) {
      throw fail(error?.code ?? 'fork-failed', String(error?.message ?? error))
    }
    const childId = result?.sessionId
    if (typeof childId !== 'string' || childId === '') throw fail('fork-failed', 'fork returned no session id')
    auditLog(`mobile fork ${sessionId}${request.atSeq === undefined ? '' : `@${request.atSeq}`} -> ${childId}`)
    return { sessionId: childId, from: sessionId, atSeq: request.atSeq ?? null }
  }

  async modelCatalog() {
    const controller = this.controller()
    try {
      return await controller.modelCatalog(undefined)
    } catch (error) {
      throw fail(error?.code ?? 'catalog-failed', String(error?.message ?? error))
    }
  }

  async selectModel(params) {
    const controller = this.controller()
    const sessionId = params?.sessionId
    if (typeof sessionId !== 'string') throw fail('bad-request', 'sessionId required')
    try {
      const selection = params?.selection ?? {}
      await controller.selectModel({ sessionId, ...selection }, undefined)
      return { selected: selection }
    } catch (error) {
      throw fail(error?.code ?? 'select-failed', String(error?.message ?? error))
    }
  }

  /**
   * Permission presets the host offers for the current session: read-only,
   * workspace-write, full access, plus Auto review when that integration is
   * mounted. Labels come from the host; the page localizes known ids.
   */
  async permissionCatalog() {
    const service = this.ctx.get('permissionPresets')
    if (!service || typeof service.catalog !== 'function') {
      return { available: false, options: [], defaultPreset: null }
    }
    let catalog
    try {
      catalog = service.catalog()
    } catch (error) {
      return { available: false, options: [], defaultPreset: null, error: String(error?.message ?? error) }
    }
    const options = Array.isArray(catalog?.options)
      ? catalog.options.map((option) => ({
        id: String(option?.value ?? ''),
        label: option?.name ?? String(option?.value ?? ''),
        description: option?.description ?? null,
      })).filter((option) => option.id !== '')
      : []
    return { available: true, options, defaultPreset: catalog?.defaultPreset ?? null }
  }

  async permissionSet(params) {
    const sessionId = params?.sessionId
    const preset = String(params?.preset ?? '')
    if (typeof sessionId !== 'string' || sessionId === '') throw fail('bad-request', 'sessionId required')
    if (preset === '') throw fail('bad-request', 'preset required')
    const service = this.ctx.get('permissionPresets')
    if (!service || typeof service.set !== 'function') {
      throw fail('permission-unavailable', 'permission presets are not mounted in this deployment')
    }
    const agent = await this.resolveLiveAgent(sessionId)
    const session = agent?.session ?? agent
    if (!session) throw fail('session/not-found', 'session unavailable')
    try {
      service.set(session, preset)
    } catch (error) {
      throw fail(error?.code ?? 'permission/denied', String(error?.message ?? error))
    }
    auditLog(`mobile permission ${sessionId} -> ${preset}`)
    return { preset }
  }

  async toolDetail(params, sid) {
    const sub = this.subs.get(sid)
    if (!sub || !sub.view || sub.sessionId !== params?.sessionId) throw fail('not-subscribed', 'open the session first')
    const item = sub.view.byId.get(`tool:${params?.callId}`)
    if (!item) throw fail('not-found', 'tool call not in the loaded window')
    return {
      callId: item.callId,
      name: item.name,
      args: item.args,
      result: item.result,
      status: item.status,
    }
  }

  // -- terminal --------------------------------------------------------------
  async resolveLiveAgent(sessionId) {
    const controller = this.controller()
    const found = await controller.resolveAgent(sessionId)
    if (found?.error || !found?.agent) {
      throw fail(found?.error?.code ?? 'session/not-found', 'cannot resolve the session agent')
    }
    return found.agent
  }

  terminalActive() {
    if (!this.pendingSends) this.pendingSends = new Map()
    return this.pendingSends
  }

  /**
   * Preferred: the preset-scoped terminal registry (minimal-style presets).
   * Returns undefined for presets that do not mount it (e.g. `standard`).
   */
  presetTerminals(agent) {
    const direct = agent?.ctx?.get?.('terminals')
    if (direct) return direct
    const presets = this.ctx.get('agentPresets')
    return presets?.serviceFor?.(agent, 'terminals') ?? this.ctx.get('terminals') ?? undefined
  }

  /**
   * Fallback terminal for presets without the terminal registry: own a PTY
   * through the root subprocess service. The plugin keeps the handle, consumes
   * its output into a bounded buffer, and exposes the same list/read/send/
   * cancel/close surface to the phone.
   */
  async spawnOwnTerminal(sessionId, agent, params) {
    const subprocess = this.ctx.get('subprocess')
    if (!subprocess || typeof subprocess.spawnTerminal !== 'function') {
      throw fail('unavailable', 'terminal service unavailable for this agent')
    }
    let cwd = null
    try {
      const workingDirectory = this.ctx.get('workingDirectory')
      if (workingDirectory && agent?.session) cwd = workingDirectory.get(agent.session)
    } catch {}
    if (!cwd) cwd = agent?.session?.header?.cwd ?? null
    if (!cwd) cwd = this.ctx.get('workingDirectory')?.defaultDirectory ?? process.cwd()
    const environment = await subprocess.terminalEnvironment?.()
    const platform = environment?.platform ?? (process.platform === 'win32' ? 'windows' : 'posix')
    const shell = environment?.defaultShell
      || (platform === 'windows' ? 'pwsh' : (process.env.SHELL || '/bin/bash'))
    const handle = await subprocess.spawnTerminal({
      argv: [shell, ...(platform === 'windows' ? [] : ['-l'])],
      cwd,
      rows: 40,
      cols: 120,
      terminalType: 'xterm-256color',
      graceMs: 2000,
      shellActivity: true,
      signal: this.signal(),
    })
    const id = `mterm-${crypto.randomBytes(4).toString('hex')}`
    const owned = {
      id,
      sessionId,
      type: shell === 'pwsh' || shell.endsWith('powershell.exe') ? 'pwsh' : 'bash',
      name: 'mobile',
      pid: handle.pid ?? null,
      status: { kind: 'running' },
      buffer: '',
      handle,
    }
    const append = (text) => {
      owned.buffer += text
      if (owned.buffer.length > 200_000) owned.buffer = owned.buffer.slice(-160_000)
    }
    try {
      handle.output?.on?.('data', (chunk) => append(String(chunk)))
      handle.output?.on?.('end', () => {})
    } catch {}
    handle.done?.then((outcome) => {
      owned.status = {
        kind: 'exited',
        exitCode: outcome?.exitCode ?? null,
        signal: outcome?.signal ?? null,
      }
      this.ownTerminals.delete(`${sessionId}:${id}`)
      this.sendTo(sessionId, { t: 'terminal-exit', sessionId, terminalId: id })
    }).catch(() => {})
    this.ownTerminals.set(`${sessionId}:${id}`, owned)
    return {
      id,
      name: owned.name,
      type: owned.type,
      pid: owned.pid,
      status: 'running',
      motd: owned.buffer.slice(-4000),
    }
  }

  ownTerminal(sessionId, id) {
    return this.ownTerminals.get(`${sessionId}:${id}`)
  }

  /** Bounded backward page over the owned fallback terminal's scrollback. */
  readOwnTerminal(owned, offset, count) {
    const lines = owned.buffer.split('\n')
    const total = lines.length
    const end = Math.max(0, total - Math.max(0, offset))
    const begin = Math.max(0, end - count)
    return {
      text: lines.slice(begin, end).join('\n'),
      totalLines: total,
      lineBegin: begin,
      lineEnd: end,
      truncated: owned.buffer.length >= 200_000,
    }
  }

  async terminalList(params) {
    const sessionId = params?.sessionId
    if (typeof sessionId !== 'string') throw fail('bad-request', 'sessionId required')
    const agent = await this.resolveLiveAgent(sessionId)
    const own = []
    for (const owned of this.ownTerminals.values()) {
      if (owned.sessionId !== sessionId) continue
      own.push({
        id: owned.id,
        name: owned.name,
        type: owned.type,
        pid: owned.pid,
        status: owned.status?.kind ?? 'running',
      })
    }
    const registry = this.presetTerminals(agent)
    let sessions = own
    if (registry) {
      try { sessions = sessions.concat(registry.list(agent).map((item) => ({
        id: item.sessionId,
        name: item.name ?? null,
        type: item.type,
        pid: item.pid ?? null,
        status: item.status?.kind ?? 'running',
      }))) } catch {}
    }
    return {
      terminals: sessions,
      backends: registry?.listBackends?.() ?? ['subprocess'],
      fallback: !registry,
    }
  }

  async terminalCreate(params) {
    const sessionId = params?.sessionId
    if (typeof sessionId !== 'string') throw fail('bad-request', 'sessionId required')
    const agent = await this.resolveLiveAgent(sessionId)
    const registry = this.presetTerminals(agent)
    if (registry) {
      const backends = registry.listBackends?.() ?? []
      const type = typeof params?.type === 'string' && backends.includes(params.type)
        ? params.type
        : backends.includes('bash') ? 'bash' : backends[0]
      if (type) {
        let cwd = typeof params?.cwd === 'string' && params.cwd !== '' ? params.cwd : undefined
        if (cwd === undefined) {
          try { cwd = this.ctx.get('workingDirectory')?.get(agent.session) } catch {}
        }
        const spawned = await registry.spawn(agent, { type, ...(cwd ? { cwd } : {}) }, this.signal())
        return {
          id: spawned.sessionId,
          name: spawned.name ?? null,
          type: spawned.type,
          pid: spawned.pid ?? null,
          status: spawned.status?.kind ?? 'running',
          motd: spawned.motd ?? '',
          fallback: false,
        }
      }
    }
    const owned = await this.spawnOwnTerminal(sessionId, agent, params)
    return { ...owned, fallback: true }
  }

  async terminalRead(params) {
    const sessionId = params?.sessionId
    const id = params?.terminalId
    if (typeof sessionId !== 'string' || typeof id !== 'string') throw fail('bad-request', 'sessionId and terminalId required')
    const owned = this.ownTerminal(sessionId, id)
    if (owned) return this.readOwnTerminal(owned, Number.isFinite(params?.offset) ? params.offset : 0, clampInt(params?.count, 20, 400, 120))
    const agent = await this.resolveLiveAgent(sessionId)
    const registry = this.presetTerminals(agent)
    if (!registry) throw fail('unavailable', 'terminal service unavailable for this agent')
    const result = registry.read(agent, id, {
      offset: Number.isFinite(params?.offset) ? params.offset : 0,
      count: clampInt(params?.count, 20, 400, 120),
    })
    return {
      text: result?.text ?? '',
      totalLines: result?.totalLines ?? 0,
      lineBegin: result?.lineBegin ?? 0,
      lineEnd: result?.lineEnd ?? 0,
      truncated: result?.truncated === true,
    }
  }

  async terminalSend(params) {
    const sessionId = params?.sessionId
    const id = params?.terminalId
    if (typeof sessionId !== 'string' || typeof id !== 'string') throw fail('bad-request', 'sessionId and terminalId required')
    const text = String(params?.text ?? '')
    if (text.length > 32_000) throw fail('bad-request', 'terminal input too large')
    const owned = this.ownTerminal(sessionId, id)
    if (owned) {
      const before = owned.buffer.length
      await owned.handle.write(text + (params?.submit === false ? '' : '\r'))
      await new Promise((resolve) => setTimeout(resolve, clampInt(params?.waitMs, 100, 3000, 500)))
      return {
        delta: owned.buffer.slice(before),
        pending: owned.status?.kind === 'running',
        waitReason: 'stdin_read',
        sessionStatus: owned.status?.kind ?? 'running',
        truncated: false,
      }
    }
    const agent = await this.resolveLiveAgent(sessionId)
    const registry = this.presetTerminals(agent)
    if (!registry) throw fail('unavailable', 'terminal service unavailable for this agent')
    const active = this.terminalActive()
    const key = `${sessionId}:${id}`
    if (active.has(key)) {
      const existing = active.get(key)
      return { ...existing.snapshot(), pending: true }
    }
    const operation = registry.startSend(agent, id, {
      text,
      submit: params?.submit !== false,
    })
    active.set(key, operation)
    const deadlineMs = clampInt(params?.waitMs, 200, 10_000, 1800)
    let delta = ''
    const done = await Promise.race([
      operation.done.then((result) => ({ result })).catch((error) => ({ error })),
      new Promise((resolve) => setTimeout(() => resolve(null), deadlineMs)),
    ])
    try { delta += operation.readOutput().delta ?? '' } catch {}
    active.delete(key)
    if (done === null) {
      operation.done.then((result) => {
        this.sendTo(sessionId, { t: 'terminal-exit', sessionId, terminalId: id, viewport: result?.viewport ?? '' })
      }).catch(() => {})
      return { delta, pending: true, waitReason: 'running', sessionStatus: 'running', truncated: false }
    }
    if (done.error) throw fail('terminal-send-failed', String(done.error?.message ?? done.error))
    return {
      delta: delta + (done.result?.viewport ?? ''),
      pending: false,
      waitReason: done.result?.waitReason ?? null,
      sessionStatus: done.result?.sessionStatus?.kind ?? 'running',
      truncated: done.result?.truncated === true,
    }
  }

  async terminalCancel(params) {
    const sessionId = params?.sessionId
    const terminalId = params?.terminalId
    if (typeof sessionId !== 'string' || typeof terminalId !== 'string') throw fail('bad-request', 'sessionId and terminalId required')
    const owned = this.ownTerminal(sessionId, terminalId)
    if (owned) {
      try {
        const pgid = await owned.handle.signalForeground('SIGINT')
        return { cancelled: Number.isFinite(pgid) }
      } catch (error) {
        return { cancelled: false }
      }
    }
    const key = `${sessionId}:${terminalId}`
    const operation = this.terminalActive().get(key)
    if (operation) return { cancelled: operation.cancel() === true }
    const agent = await this.resolveLiveAgent(sessionId)
    const registry = this.presetTerminals(agent)
    if (!registry) throw fail('unavailable', 'terminal service unavailable for this agent')
    const result = await registry.signal(agent, terminalId, 'SIGINT')
    return { cancelled: result?.delivered === true }
  }

  async terminalClose(params) {
    const sessionId = params?.sessionId
    const terminalId = params?.terminalId
    if (typeof sessionId !== 'string' || typeof terminalId !== 'string') throw fail('bad-request', 'sessionId and terminalId required')
    const owned = this.ownTerminal(sessionId, terminalId)
    if (owned) {
      this.ownTerminals.delete(`${sessionId}:${terminalId}`)
      try { await owned.handle.terminate() } catch {}
      return { closed: true }
    }
    const agent = await this.resolveLiveAgent(sessionId)
    const registry = this.presetTerminals(agent)
    if (!registry) throw fail('unavailable', 'terminal service unavailable for this agent')
    const killed = await registry.kill(agent, terminalId, 'user')
    return { closed: killed === true }
  }

  // -- interactions ---------------------------------------------------------
  replayInteractions(sub) {
    // Pending live questions/approvals and continued questions from the
    // projection baseline are rebuilt for a (re)connected phone.
    for (const entry of this.pending.values()) {
      if (entry.sessionId !== sub.sessionId) continue
      this.safeSend(sub, { t: 'interaction', interaction: entry.wire() })
    }
    for (const item of this.continued.values()) {
      if (item.sessionId !== sub.sessionId) continue
      this.safeSend(sub, {
        t: 'interaction',
        interaction: {
          kind: 'question',
          key: `q:${item.callId}`,
          sessionId: item.sessionId,
          callId: item.callId,
          questions: item.questions,
          state: 'continued',
        },
      })
    }
  }

  async handleApproval(req, next) {
    const agent = req?.agent
    const sessionId = agent?.id
    if (typeof sessionId !== 'string' || !this.hasPhoneFor(sessionId)) return next()
    const key = `ap:${sessionId}:${req.callId ?? crypto.randomUUID()}`
    return new Promise((resolve) => {
      const sub = this.subscribersFor(sessionId)[0]
      const entry = {
        kind: 'approval',
        key,
        sessionId,
        createdAt: Date.now(),
        settle: (outcome) => {
          if (this.pending.get(key) !== entry) return
          this.pending.delete(key)
          clearTimeout(entry.timer)
          resolve(outcome)
          this.sendTo(sessionId, { t: 'interaction-done', key, outcome })
        },
        wire: () => ({
          kind: 'approval',
          key,
          sessionId,
          toolName: String(req.toolName ?? 'tool'),
          callId: req.callId ?? null,
          reason: String(req.reason ?? ''),
          displayReason: req.displayReason ?? null,
          args: sub?.view?.toolArgs?.(req.callId) ?? '',
          state: 'open',
        }),
      }
      this.pending.set(key, entry)
      req.signal?.addEventListener('abort', () => entry.settle('cancelled'), { once: true })
      entry.timer = setTimeout(() => entry.settle('cancelled'), APPROVAL_DEADLINE_MS)
      entry.timer.unref?.()
      // Race the desktop chain: if a desktop client is watching, its own card
      // can answer first. `unavailable` just means nobody upstream answered —
      // the phone card stays authoritative until it does.
      Promise.resolve().then(() => next()).then((outcome) => {
        if (!outcome || outcome === 'unavailable') return
        entry.settle(outcome)
      }).catch(() => {})
      for (const target of this.subscribersFor(sessionId)) {
        this.safeSend(target, { t: 'interaction', interaction: entry.wire() })
      }
    })
  }

  async handleQuestion(request, next) {
    const agent = request?.agent
    const sessionId = agent?.id
    if (typeof sessionId !== 'string' || !this.hasPhoneFor(sessionId)) return next()
    const callId = request.wait?.callId
    const key = callId === undefined ? `q:${crypto.randomUUID()}` : `q:${callId}`
    const claim = new AbortController()
    if (callId !== undefined && request.wait?.timed === true && this.questions()) {
      this.claimWait(agent, callId, claim.signal)
    }
    return new Promise((resolve, reject) => {
      const entry = {
        kind: 'question',
        key,
        callId,
        sessionId,
        claim,
        createdAt: Date.now(),
        settle: (answer, error) => {
          if (this.pending.get(key) !== entry) return
          this.pending.delete(key)
          try { claim.abort() } catch {}
          if (error) reject(error)
          else resolve(answer)
          this.sendTo(sessionId, { t: 'interaction-done', key, outcome: error ? 'cancelled' : 'answered' })
        },
        wire: () => ({
          kind: 'question',
          key,
          sessionId,
          callId: callId ?? null,
          questions: request.questions ?? [],
          timed: request.wait?.timed === true,
          state: 'open',
        }),
      }
      this.pending.set(key, entry)
      request.signal?.addEventListener('abort', () => {
        entry.settle(undefined, Object.assign(new Error('ask aborted'), { code: 'ASK_ABORTED' }))
      }, { once: true })
      // Let the desktop answerers run too (first real answer wins); the
      // phone card does not block the desktop when both are open.
      Promise.resolve().then(() => next()).then((answer) => {
        if (!answer || !Array.isArray(answer.answers)) return
        entry.settle(answer)
      }).catch(() => {})
      for (const target of this.subscribersFor(sessionId)) {
        this.safeSend(target, { t: 'interaction', interaction: entry.wire() })
      }
    })
  }

  async claimWait(agent, callId, signal) {
    try {
      const stream = this.questions().attachWait(agent, callId, signal)
      for await (const tick of stream) {
        this.sendTo(agent.id, { t: 'question-tick', callId, ...tick })
      }
    } catch {
      // The question already settled, or the claim was released.
    }
  }

  settlePending(entry, outcome, asQuestionReject = false) {
    if (this.pending.get(entry.key) !== entry) return
    if (entry.kind === 'approval') {
      entry.settle(outcome ?? 'cancelled')
    } else if (asQuestionReject) {
      const error = Object.assign(new Error('ask cancelled'), { code: 'ASK_TIMED_OUT' })
      entry.settle(undefined, error)
    } else {
      entry.settle(outcome, undefined)
    }
  }

  async answerInteraction(params) {
    const key = String(params?.key ?? '')
    const entry = this.pending.get(key)
    if (entry?.kind === 'approval') {
      const outcome = params?.outcome === 'allow' ? 'allowed-once' : 'rejected'
      entry.settle(outcome)
      return { accepted: true, settled: 'live' }
    }
    if (entry?.kind === 'question') {
      const answers = this.normalizeAnswers(params?.answers)
      entry.settle({ answers }, undefined)
      return { accepted: true, settled: 'live' }
    }
    // A question from the projection baseline (`state: 'continued'`): the
    // foreground waiter is gone, so deliver through userQuestions.answer().
    const callId = String(params?.callId ?? '')
    const continued = this.continued.get(key) ?? (callId ? this.continued.get(`q:${callId}`) : undefined)
    if (continued) {
      const answers = this.normalizeAnswers(params?.answers)
      const controller = this.controller()
      const found = await controller.resolveAgent(continued.sessionId)
      if (found?.error || !found?.agent) throw fail(found?.error?.code ?? 'session/not-found', 'cannot resolve agent')
      await this.questions().answer(found.agent, continued.callId, { answers })
      this.continued.delete(key)
      this.sendTo(continued.sessionId, { t: 'interaction-done', key, outcome: 'answered' })
      return { accepted: true, settled: 'continued' }
    }
    throw fail('interaction-not-found', 'interaction is no longer pending')
  }

  /**
   * "Answer later" for a question: leave the host wait (a timed ask becomes
   * `continued`, answerable from the projection card later) instead of making
   * the tool fail with a bogus empty answer.
   */
  async cancelInteraction(params) {
    const key = String(params?.key ?? '')
    const entry = this.pending.get(key)
    if (!entry) return { accepted: false }
    if (entry.kind === 'question' && entry.callId !== undefined) {
      this.continued.set(key, {
        sessionId: entry.sessionId,
        callId: entry.callId,
        questions: entry.wire().questions,
      })
    }
    if (entry.kind === 'question') {
      this.settlePending(entry, undefined, true)
    } else {
      this.settlePending(entry, 'cancelled')
    }
    return { accepted: true }
  }

  normalizeAnswers(raw) {    if (!Array.isArray(raw)) throw fail('bad-answer', 'answers must be an array')
    return raw.map((answer) => {
      const out = {
        id: String(answer?.id ?? ''),
        selected: Array.isArray(answer?.selected) ? answer.selected.map(String) : [],
      }
      if (typeof answer?.custom === 'string' && answer.custom !== '') out.custom = answer.custom
      return out
    })
  }

  /** Track continued questions surfaced by a session snapshot projection. */
  noteProjectionQuestions(sessionId, userQuestions) {
    const active = userQuestions?.active ?? []
    for (const entry of active) {
      if (entry.state !== 'continued' || entry.callId === undefined) continue
      this.continued.set(`q:${entry.callId}`, {
        sessionId,
        callId: entry.callId,
        questions: entry.questions ?? [],
      })
    }
  }
}

function clampInt(value, min, max, fallback) {
  const number = Number(value)
  if (!Number.isFinite(number)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(number)))
}

function seqOfFirstEvent(records) {
  for (const record of records ?? []) {
    if (record?.type === 'event' && Number.isFinite(record.event?.seq)) return record.event.seq
  }
  return null
}
