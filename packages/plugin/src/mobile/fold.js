// Durable session-log → phone chat rows.
//
// The mobile page renders a deliberately small vocabulary (user / assistant /
// reasoning / tool / status / divider), folded from the DSH session event log
// on the HOST side. Keeping the fold here means the phone ships no DSH
// knowledge and a protocol change is a one-file fix.
//
// Rules mirrored from the desktop client:
//   * only append-origin surface events become bubbles (compaction replacement
//     copies must not erase what the user already saw);
//   * `user/message` with source.kind !== 'user' is injected context, not a
//     human bubble;
//   * tool cards pair `tool/call` with `tool/result` by callId;
//   * unknown event/block types are skipped, never errors.

/** Concatenate text blocks of a message content array. */
export function textOf(content) {
  if (!Array.isArray(content)) return ''
  let out = ''
  for (const block of content) {
    if (block && block.type === 'text' && typeof block.text === 'string') {
      out += (out === '' ? '' : '\n\n') + block.text
    }
  }
  return out
}

/** Image blocks of a message content array, as phone render rows. */
export function imagesOf(content, seq, prefix) {
  if (!Array.isArray(content)) return []
  const out = []
  let index = 0
  for (const block of content) {
    if (!block || block.type !== 'image' || !block.attachment) continue
    const attachment = block.attachment
    out.push({
      kind: 'image',
      id: `img:${prefix}:${seq}:${index}`,
      seq,
      attachmentId: attachment.attachmentId,
      mediaType: attachment.mediaType ?? 'image/jpeg',
      width: attachment.width ?? null,
      height: attachment.height ?? null,
      name: attachment.name ?? null,
      own: prefix === 'user',
    })
    index += 1
  }
  return out
}

/** Concatenate reasoning blocks of a message content array. */
export function reasoningOf(content) {
  if (!Array.isArray(content)) return ''
  let out = ''
  for (const block of content) {
    if (block && block.type === 'reasoning' && typeof block.text === 'string') {
      out += (out === '' ? '' : '\n\n') + block.text
    }
  }
  return out
}

/** Pretty-print a tool's raw JSON arguments for the card body. */
export function displayArgs(raw) {
  if (typeof raw !== 'string' || raw === '') return ''
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}

/** Compact metadata for a session header. */
export function headerMeta(header) {
  if (!header || typeof header !== 'object') return {}
  return {
    sessionId: header.id,
    cwd: header.cwd ?? null,
    createdAt: header.createdAt ?? null,
    parentSessionId: header.parentSession ?? null,
    agentPreset: header.agentPreset ?? null,
    origin: header.origin ?? null,
  }
}

/**
 * Rebuild the in-progress assistant text from the compact stream records the
 * follow snapshot carries (a phone that reconnects mid-stream starts here).
 * @returns {null | {text: string, reasoning: string, attemptId?: string, revision?: number}}
 */
export function initialStream(assistantStream) {
  const attempt = assistantStream?.activeAttempt
  if (!attempt) return null
  let text = ''
  let reasoning = ''
  for (const record of attempt.stream ?? []) {
    if (!record || typeof record !== 'object') continue
    if (record.type === 'text-chunks') {
      text += (record.texts ?? []).join('')
    } else if (record.type === 'reasoning-chunks') {
      reasoning += (record.texts ?? []).join('')
    }
  }
  return {
    attemptId: attempt.attemptId,
    revision: assistantStream.revision,
    text,
    reasoning,
  }
}

/**
 * Per-subscription fold of one session. `reset()` installs a snapshot;
 * `apply()` consumes one durable event and returns the rows the page must
 * add or replace.
 */
export class SessionView {
  constructor() {
    this.items = []
    this.byId = new Map()
    this.cursor = -1
    this.hasMore = false
    this.meta = {}
    this.stream = null
    this.title = null
  }

  reset(frame) {
    this.items = []
    this.byId.clear()
    this.cursor = Number.isFinite(frame?.cursor) ? frame.cursor : -1
    this.hasMore = Boolean(frame?.hasMore)
    this.meta = headerMeta(frame?.header)
    this.title = frame?.projections?.values?.title ?? null
    this.stream = initialStream(frame?.assistantStream)
    const records = Array.isArray(frame?.records) ? frame.records : []
    for (const record of records) {
      const event = record && record.type === 'event' ? record.event : null
      if (event) this.apply(event)
    }
    return this
  }

  push(item) {
    this.items.push(item)
    if (item.id) this.byId.set(item.id, item)
  }

  /**
   * Fold one durable event.
   * @returns {{added: object[], updated: object[]}} rows changed by this event
   */
  apply(event) {
    const added = []
    const updated = []
    if (!event || typeof event.type !== 'string') return { added, updated }
    const data = event.data ?? {}
    const time = event.time ?? Date.now()

    switch (event.type) {
      case 'user/message': {
        if (event.surfaceOp !== 'append') break
        const source = data.source ?? {}
        if (source.kind !== 'user') {
          // user-question replies / approval answers / injected context: show
          // as a subtle status row instead of pretending the human typed it.
          if (source.kind === 'user-question-reply') {
            const item = { kind: 'status', id: `q-reply:${event.seq}`, seq: event.seq, text: '已回答问题', time }
            this.push(item); added.push(item)
          }
          break
        }
        for (const image of imagesOf(data.content, event.seq, 'user')) {
          this.push(image); added.push(image)
        }
        const item = {
          kind: 'user',
          id: `u:${event.seq}`,
          seq: event.seq,
          text: textOf(data.content),
          time,
          requestId: source.rpcId ?? null,
        }
        this.push(item); added.push(item)
        break
      }
      case 'assistant/message': {
        if (event.surfaceOp !== 'append') break
        const content = data.message?.content ?? []
        for (const image of imagesOf(content, event.seq, 'assistant')) {
          this.push(image); added.push(image)
        }
        const reasoning = reasoningOf(content)
        if (reasoning) {
          const item = { kind: 'reasoning', id: `r:${event.seq}`, seq: event.seq, text: reasoning, time, done: true }
          this.push(item); added.push(item)
        }
        const text = textOf(content)
        if (text || data.interrupted === true) {
          const item = {
            kind: 'assistant',
            id: `a:${event.seq}`,
            seq: event.seq,
            text,
            time,
            interrupted: data.interrupted === true,
            model: data.message?.source?.model ?? null,
          }
          this.push(item); added.push(item)
        }
        break
      }
      case 'tool/call': {
        const id = `tool:${data.callId}`
        if (this.byId.has(id)) break
        const item = {
          kind: 'tool',
          id,
          seq: event.seq,
          callId: data.callId,
          name: String(data.name ?? 'tool'),
          args: displayArgs(data.arguments),
          status: 'running',
          result: '',
          isError: false,
          time,
        }
        this.push(item); added.push(item)
        break
      }
      case 'tool/result': {
        const callId = data.message?.toolCallId
        for (const image of imagesOf(data.message?.content, event.seq, 'tool')) {
          this.push(image); added.push(image)
        }
        const item = this.byId.get(`tool:${callId}`)
        if (!item) {
          // Result for a call outside the loaded window: show the outcome only.
          const late = {
            kind: 'tool',
            id: `tool:${callId}`,
            seq: event.seq,
            callId,
            name: 'tool',
            args: '',
            status: data.message?.isError ? 'error' : 'ok',
            result: textOf(data.message?.content),
            isError: data.message?.isError === true,
            time,
          }
          this.push(late); added.push(late)
          break
        }
        item.status = data.message?.isError ? 'error' : 'ok'
        item.isError = data.message?.isError === true
        item.result = textOf(data.message?.content)
        if (data.error) item.error = String(data.error.reason ?? data.error.code ?? data.error.name ?? '')
        updated.push(item)
        break
      }
      case 'turn/end': {
        const reason = data.reason ?? {}
        if (reason.kind === 'aborted' && reason.reason?.kind === 'user') {
          const item = { kind: 'status', id: `stop:${event.seq}`, seq: event.seq, text: '已停止', time }
          this.push(item); added.push(item)
        } else if (reason.kind === 'error') {
          const message = reason.error?.message ?? '运行出错'
          const item = { kind: 'error', id: `err:${event.seq}`, seq: event.seq, text: String(message), time }
          this.push(item); added.push(item)
        } else if (reason.kind === 'max-tokens') {
          const item = { kind: 'status', id: `maxtok:${event.seq}`, seq: event.seq, text: '输出达到上限', time }
          this.push(item); added.push(item)
        }
        break
      }
      case 'compaction/summary': {
        const item = { kind: 'divider', id: `compact:${event.seq}`, seq: event.seq, text: '上下文已压缩', time }
        this.push(item); added.push(item)
        break
      }
      case 'session/title': {
        this.title = data.title ?? this.title
        break
      }
      case 'model/selection': {
        this.model = data
        break
      }
      case 'approval/asked': {
        const item = {
          kind: 'approval-history',
          id: `ap:${data.id}`,
          seq: event.seq,
          approvalId: data.id,
          toolName: data.toolName ?? 'tool',
          reason: data.reason ?? '',
          time,
        }
        this.push(item); added.push(item)
        break
      }
      case 'approval/decided': {
        const item = this.byId.get(`ap:${data.id}`)
        if (item) {
          item.outcome = data.outcome ?? null
          updated.push(item)
        }
        break
      }
      default:
        break
    }
    if (Number.isFinite(event.seq) && event.seq > this.cursor) this.cursor = event.seq
    return { added, updated }
  }

  /** Find the args of a not-yet-resulted tool call (approval cards show them). */
  toolArgs(callId) {
    if (!callId) return ''
    return this.byId.get(`tool:${callId}`)?.args ?? ''
  }

  /** Snapshot rows for the initial `session` frame. */
  wireItems() {
    return this.items.map((item) => ({ ...item }))
  }
}

/**
 * Split a follow snapshot's history frame into the rows the phone renders.
 * @returns {{items: object[], cursor: number, hasMore: boolean, meta: object, title: string|null, stream: object|null}}
 */
export function foldSnapshot(frame) {
  const view = new SessionView().reset(frame)
  return {
    items: view.wireItems(),
    cursor: view.cursor,
    hasMore: view.hasMore,
    meta: view.meta,
    title: view.title,
    stream: view.stream,
  }
}
