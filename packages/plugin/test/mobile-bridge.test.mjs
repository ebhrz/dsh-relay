#!/usr/bin/env node
// Unit checks for the host-side mobile bridge against a fake Cordis context.
// Verifies the DSH 0.2.1 service calls, frame shapes and interaction waterfalls
// without loading a real DSH host:
//
//   node test-mobile-bridge.mjs

import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { MobileBridge } from '../src/mobile/bridge.js'
import { foldSnapshot } from '../src/mobile/fold.js'

// Audit/identity writes must never reach the developer's real ~/.dsh.
process.env.DSH_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-relay-bridge-test-'))

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function deferred() {
  let resolve
  let reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

// ── fake host services ────────────────────────────────────────────────────
function makeController() {
  const calls = { prompt: [], promptSignals: [], cancel: [], page: [], pageSignals: [], create: 0, rename: [], fork: [], selectModel: [], resolveAgent: [], attachment: [], permission: [], projections: [] }
  const followFrames = []
  const controller = {
    calls,
    async list(request, signal) {
      calls.listSignals = calls.listSignals ?? []
      calls.listSignals.push(signal)
      return {
        items: [
          {
            sessionId: 's-main', updatedAt: 2000, running: true, agentAvailable: true, blank: false,
            cwd: '/work/main', formatStatus: 'current',
            projections: { values: { title: 'Main session', modelSelection: { lastUsed: { provider: 'deepseek', model: 'deepseek-flash' } } } },
          },
          { sessionId: 's-cold', updatedAt: 1000, running: false, agentAvailable: false, blank: false, cwd: '/work/cold' },
          { sessionId: 's-sub', updatedAt: 900, running: false, agentAvailable: true, blank: false, parentSessionId: 's-main', origin: 'subagent' },
          // A fork keeps its parent link but is an ordinary, openable session.
          { sessionId: 's-fork', updatedAt: 850, running: false, agentAvailable: false, blank: false, cwd: '/work/main', parentSessionId: 's-main' },
          { sessionId: 's-archived', updatedAt: 800, running: false, agentAvailable: false, blank: false, cwd: '/work/old' },
        ],
      }
    },
    follow(request, signal) {
      const frames = [
        {
          type: 'snapshot',
          header: { version: 4, id: request.address.sessionId, createdAt: 100, cwd: '/work/main', isSeeded: false },
          cursor: 12,
          hasMore: true,
          records: [
            { type: 'event', event: { type: 'user/message', seq: 10, time: 1000, data: { id: 'm1', role: 'user', content: [{ type: 'text', text: 'hello' }], source: { kind: 'user', rpcId: 'r1' } }, surfaceOp: 'append' } },
            { type: 'event', event: { type: 'assistant/message', seq: 11, time: 1100, data: { turn: 1, step: 1, message: { id: 'm2', role: 'assistant', content: [{ type: 'text', text: 'hi there' }], source: { kind: 'model', provider: 'deepseek', model: 'deepseek-flash' } } }, surfaceOp: 'append' } },
            { type: 'event', event: { type: 'tool/call', seq: 12, time: 1200, data: { turn: 1, step: 1, callId: 'c1', name: 'bash', arguments: '{"command":"ls"}' } } },
          ],
          projections: { asOfSeq: 12, values: { title: 'Main session', userQuestions: { active: [{ callId: 'q-old', state: 'continued', questions: [{ id: 'q1', question: 'old?' }] }], settled: [] } } },
          assistantStream: { revision: 3, activeAttempt: { attemptId: 'att1', startedAfterSeq: 12, turn: 1, step: 1, nextIndex: 1, stream: [{ type: 'text-chunks', time0: 1300, index: 0, dt: [1], texts: ['partial'] }] } },
        },
        { type: 'event', event: { type: 'tool/result', seq: 13, time: 1300, data: { turn: 1, step: 1, message: { id: 'm3', role: 'tool', toolCallId: 'c1', content: [{ type: 'text', text: 'file-a' }], source: { kind: 'tool', callId: 'c1' }, isError: false } } } },
        { type: 'assistant-stream', frame: { type: 'start', attemptId: 'att2', revision: 4, startedAfterSeq: 13, turn: 1, step: 1 } },
        { type: 'assistant-stream', frame: { type: 'chunk', attemptId: 'att2', revision: 4, index: 0, chunk: { type: 'text-delta', index: 0, text: 'more' } } },
        { type: 'assistant-stream', frame: { type: 'end', attemptId: 'att2', revision: 4, outcome: { kind: 'committed', eventType: 'assistant/message', seq: 14 } } },
      ]
      return (async function* followStream() {
        for (const frame of frames) {
          if (signal?.aborted) return
          followFrames.push(frame)
          yield frame
          await sleep(5)
        }
        // keep the stream open like a live host would
        await new Promise((resolve) => {
          signal?.addEventListener('abort', resolve, { once: true })
        })
      })()
    },
    async page(request, signal) {
      calls.page.push(request)
      calls.pageSignals.push(signal)
      return {
        records: [
          { type: 'event', event: { type: 'user/message', seq: 2, time: 500, data: { id: 'old1', role: 'user', content: [{ type: 'text', text: 'older' }], source: { kind: 'user' } }, surfaceOp: 'append' } },
        ],
        hasMore: false,
      }
    },
    async prompt(request, signal) { calls.prompt.push(request); calls.promptSignals.push(signal); return { accepted: true } },
    async attachment(request) {
      calls.attachment.push(request)
      return { attachment: { attachmentId: request.attachmentId, mediaType: 'image/png', width: 2, height: 2 }, data: 'aGVsbG8=' }
    },
    async cancel(request) { calls.cancel.push(request); return { accepted: true } },
    async create() { calls.create += 1; return { sessionId: 's-new' } },
    async rename(request) { calls.rename.push(request); return { title: request.title } },
    async fork(request) {
      calls.fork.push(request)
      if (request.sessionId === 's-missing') {
        const error = new Error(`session "${request.sessionId}" not found`)
        error.code = 'session/not-found'
        throw error
      }
      return { sessionId: 's-fork-new' }
    },
    async selectModel(request) { calls.selectModel.push(request); return { selected: request } },
    async modelCatalog() { return { groups: [] } },
    async projections(request, signal) {
      calls.projections.push({ request, signal })
      // The `permissions` projection's wire view is `{currentValue}`, not the
      // host-internal `{preset, sandbox, approval, seeded}` state.
      return { kind: 'sequenced', asOfSeq: 42, values: { permissions: { currentValue: 'read-only' } } }
    },
    async resolveAgent(sessionId) {
      calls.resolveAgent.push(sessionId)
      return { agent: { id: sessionId, session: { header: { cwd: '/work/main' } }, ctx: { get: (name) => (name === 'terminals' && sessionId === 's-main' ? services.terminals : undefined) } } }
    },
  }
  return controller
}

function makeCtx(controller) {
  const listeners = new Map()
  const services = {
    sessionController: controller,
    workspaceRegistry: {
      archivedSessionIds: new Set(['s-archived']),
      list: () => [{
        id: 'w-main', title: 'Main project', path: '/work/main',
        sessionIds: ['s-main', 's-fork'],
      }],
    },
    agents: { get: (id) => (id === 's-main' ? { status: 'running' } : undefined) },
    agentPresets: {
      serviceFor: (agent, name) => (name === 'terminals' && agent?.id === 's-main' ? services.terminals : undefined),
    },
    permissionPresets: {
      catalog: () => ({
        options: [
          { value: 'read-only', name: 'read-only' },
          { value: 'workspace-write', name: 'workspace-write' },
          { value: 'danger-full-access', name: 'danger-full-access', description: 'no confirmation' },
        ],
        defaultOptions: [],
        defaultPreset: 'workspace-write',
      }),
      set: (session, name) => { controller.calls.permission.push({ session, name }) },
    },
    terminals: {
      listBackends: () => ['bash'],
      list: () => [{ sessionId: 'term-1', name: 'bash', type: 'bash', pid: 42, status: { kind: 'running' } }],
      spawn: async () => ({ sessionId: 'term-new', name: 'bash', type: 'bash', pid: 43, status: { kind: 'running' }, motd: 'motd' }),
      read: (owner, id, request) => ({ text: '$ ls\nfile-a', totalLines: 2, lineBegin: 0, lineEnd: 2, truncated: false }),
      startSend: () => ({
        done: Promise.resolve({ viewport: 'done-output', waitReason: 'idle', sessionStatus: { kind: 'running' }, truncated: false }),
        readOutput: () => ({ delta: 'delta-output', truncated: false }),
        cancel: () => true,
      }),
      signal: async () => ({ delivered: true, targetPgid: 42 }),
      kill: async () => true,
    },
    subprocess: {
      terminalEnvironment: async () => ({ platform: 'posix', defaultShell: '/bin/bash' }),
      spawnTerminal: async () => {
        const output = new (await import('node:events')).EventEmitter()
        const done = new Promise(() => {})
        const handle = {
          pid: 555,
          output,
          done,
          write: async (text) => { output.emit('data', '$ ' + text + '\r\nhello\r\n') },
          resize: async () => {},
          inspectForeground: async () => undefined,
          inspectActivity: async () => ({ state: 'unknown', revision: 0 }),
          signalForeground: async () => 123,
          terminate: async () => {},
        }
        return handle
      },
    },
    userQuestions: {
      attachWait() {
        return (async function* waitTicks() {
          yield { remainingMs: 5000 }
          await sleep(1000)
        })()
      },
      answer(agent, callId, answer) {
        services.userQuestions.answered = { agent, callId, answer }
      },
    },
  }
  const ctx = {
    logger: { info() {}, warn() {}, error() {} },
    get: (name) => (name === 'terminals' ? undefined : services[name]),
    on(event, fn, options) {
      const list = listeners.get(event) ?? []
      list.push({ fn, options })
      listeners.set(event, list)
      return () => {
        const current = listeners.get(event) ?? []
        listeners.set(event, current.filter((entry) => entry.fn !== fn))
      }
    },
    effect() {},
  }
  return { ctx, listeners, services }
}

function subscribersOf(bridge) {
  return [...bridge.subs.values()]
}

// ── tests ─────────────────────────────────────────────────────────────────
const controller = makeController()
const { ctx, listeners, services } = makeCtx(controller)
const bridge = new MobileBridge(ctx, { version: '9.9.9' })
bridge.deviceId = 'TESTDEV'
bridge.install()

// 1. listeners + prepend flags
{
  assert.ok(listeners.get('session/event')?.length === 1, 'session/event tapped')
  assert.ok(listeners.get('agent/assistant-stream')?.length === 1, 'assistant-stream tapped')
  const approvals = listeners.get('approval/request')
  assert.equal(approvals?.length, 1, 'approval waterfall installed')
  assert.equal(approvals[0].options?.prepend, true, 'approval listener is prepended')
  const questions = listeners.get('user-questions/request')
  assert.equal(questions?.[0].options?.prepend, true, 'question listener is prepended')
  console.log('ok 1: live-event taps and prepended interaction waterfalls installed')
}

// 2. hello + session list
{
  const hello = await bridge.rpc('hello', {})
  assert.equal(hello.device.id, 'TESTDEV')
  assert.equal(hello.version, '9.9.9')
  assert.equal(hello.upstream, true)
  const list = await bridge.rpc('sessions', {})
  assert.deepEqual(list.sessions.map((row) => row.id), ['s-main', 's-cold', 's-fork'])
  assert.equal(list.sessions[0].title, 'Main session')
  assert.equal(list.sessions[0].running, true)
  assert.equal(list.sessions[0].model.model, 'deepseek-flash')
  assert.equal(list.sessions[0].cwd, '/work/main')
  // Forks stay visible (they are ordinary sessions); subagents and archived
  // sessions do not.
  assert.equal(list.sessions[2].parentSessionId, 's-main')
  assert.deepEqual(list.workspaces, [{
    id: 'w-main', title: 'Main project', path: '/work/main', sessionIds: ['s-main', 's-fork'],
  }])
  console.log('ok 2: session list drops subagent/archived rows, keeps forks, passes workspaces through')
}

// 3. subscribe -> snapshot + durable + stream frames
{
  const frames = []
  bridge.subscribe(7, 's-main', (frame) => frames.push(JSON.parse(JSON.stringify(frame))))
  for (let i = 0; i < 100 && frames.filter((frame) => frame.t === 'assistant-stream').length < 3; i += 1) await sleep(10)
  const session = frames.find((frame) => frame.t === 'session')
  assert.ok(session, 'snapshot session frame sent')
  assert.equal(session.sessionId, 's-main')
  assert.equal(session.cursor, 12)
  assert.equal(session.hasMore, true)
  assert.equal(session.title, 'Main session')
  assert.deepEqual(session.items.map((item) => item.kind), ['user', 'assistant', 'tool'])
  assert.equal(session.items[2].status, 'running')
  assert.equal(session.stream.text, 'partial', 'mid-stream snapshot carries partial text')
  assert.equal(session.running, true)
  assert.ok(frames.some((frame) => frame.t === 'items' && frame.updated.some((item) => item.id === 'tool:c1' && item.status === 'ok')),
    'tool/result updates the running tool row')
  assert.equal(frames.filter((frame) => frame.t === 'assistant-stream').length >= 3, true, 'stream start/chunk/end forwarded')
  // continued question from the projection baseline is replayed
  assert.ok(frames.some((frame) => frame.t === 'interaction' && frame.interaction.state === 'continued' && frame.interaction.callId === 'q-old'),
    'continued question from projections replayed')
  console.log('ok 3: follow snapshot folded; tool updates, stream frames and continued questions forwarded')
}

// 3b. the global session/event tap must not double-apply followed sessions
{
  const sessionListener = listeners.get('session/event')[0].fn
  const frames = []
  bridge.subscribe(8, 's-main', (frame) => frames.push(JSON.parse(JSON.stringify(frame))))
  await sleep(40)
  const before = frames.length
  sessionListener({ id: 's-main' }, { type: 'user/message', seq: 30, time: 3000, data: { id: 'dup', role: 'user', content: [{ type: 'text', text: 'dup' }], source: { kind: 'user' } }, surfaceOp: 'append' })
  await sleep(30)
  // Stream frames from the mock host keep arriving on their own timers, so the
  // check is scoped to what the durable event itself would have produced.
  const forwarded = frames.slice(before).filter((frame) => frame.t === 'items' && JSON.stringify(frame).includes('"dup"'))
  assert.equal(forwarded.length, 0, 'global durable event is not forwarded twice for a followed session')
  sessionListener({ id: 's-main' }, { type: 'session/title', seq: 31, time: 3100, data: { title: 'Renamed by host' } })
  await sleep(30)
  assert.ok(frames.some((frame) => frame.t === 'title' && frame.title === 'Renamed by host'), 'title changes still pushed')
  bridge.unsubscribe(8)
  // Re-subscribe for the following tests that expect the shared subscription.
  bridge.subscribe(7, 's-main', () => {})
  await sleep(30)
  console.log('ok 3b: durable events are not double-applied; title frames still flow')
}

// 4. older page
{
  const page = await bridge.rpc('older', { sessionId: 's-main', throughSeq: 12, beforeSeq: 10, maxMessages: 20 })
  assert.equal(controller.calls.page.length, 1)
  assert.deepEqual(controller.calls.page[0], {
    address: { kind: 'session', sessionId: 's-main' },
    throughSeq: 12,
    beforeSeq: 10,
    maxMessages: 20,
  })
  assert.equal(page.items[0].text, 'older')
  assert.equal(page.hasMore, false)
  console.log('ok 4: older history calls sessionController.page with the snapshot cursor')
}

// 5. prompt validation + payload
{
  await assert.rejects(bridge.rpc('prompt', { sessionId: 's-main', text: '   ' }), (error) => error.code === 'bad-request')
  await assert.rejects(bridge.rpc('prompt', { sessionId: 's-main', text: 'x', mode: 'bogus', clientTimeZone: 'Not/AZone' }), () => true)
  const accepted = await bridge.rpc('prompt', {
    sessionId: 's-main', text: 'do it', mode: 'steer', requestId: 'req-12345678', clientTimeZone: 'Asia/Shanghai',
  })
  assert.equal(accepted.accepted, true)
  assert.equal(accepted.requestId, 'req-12345678')
  assert.deepEqual(controller.calls.prompt[0], {
    requestId: 'req-12345678',
    sessionId: 's-main',
    mode: 'steer',
    content: [{ type: 'text', text: 'do it' }],
    clientTimeZone: 'Asia/Shanghai',
  })
  // An invalid IANA zone is dropped rather than forwarded.
  await bridge.rpc('prompt', { sessionId: 's-main', text: 'again', requestId: 'req-87654321', clientTimeZone: 'Not/AZone' })
  assert.equal(controller.calls.prompt[1].clientTimeZone, undefined)
  console.log('ok 5: prompt validated and forwarded with idempotency key + IANA timezone')
}

// 6. stop
{
  const result = await bridge.rpc('stop', { sessionId: 's-main' })
  assert.equal(result.accepted, true)
  assert.deepEqual(controller.calls.cancel[0], { sessionId: 's-main' })
  console.log('ok 6: stop calls sessionController.cancel')
}

// 7. approval waterfall: phone-first, answered via RPC
{
  const approvalListener = listeners.get('approval/request')[0].fn
  const frames = []
  bridge.subscribe(9, 's-main', (frame) => frames.push(JSON.parse(JSON.stringify(frame))))
  await sleep(30)
  let nextCalled = false
  const req = {
    agent: { id: 's-main' },
    toolName: 'read_file',
    callId: 'c1',
    reason: 'read it',
    signal: new AbortController().signal,
  }
  const outcome = deferred()
  const listenerResult = Promise.resolve(approvalListener(req, async () => {
    nextCalled = true
    return 'unavailable' // no desktop client answered: the phone stays authoritative
  }))
  listenerResult.then((value) => outcome.resolve(value))
  await sleep(30)
  const interaction = frames.find((frame) => frame.t === 'interaction' && frame.interaction.kind === 'approval')
  assert.ok(interaction, 'approval card pushed to the phone')
  assert.equal(interaction.interaction.toolName, 'read_file')
  assert.match(interaction.interaction.args, /"command": "ls"/, 'approval card carries the pending call args')
  assert.equal(nextCalled, true, 'desktop chain is also offered the ask (first real answer wins)')
  const answered = await bridge.rpc('interaction.answer', { key: interaction.interaction.key, outcome: 'allow' })
  assert.equal(answered.accepted, true)
  assert.equal(await outcome.promise, 'allowed-once', 'approval resolves allowed-once')
  console.log('ok 7: approval is phone-first, carries tool args, answers allowed-once')
}

// 8. approval delegates without a phone
{
  const approvalListener = listeners.get('approval/request')[0].fn
  for (const sid of [...bridge.subs.keys()]) bridge.unsubscribe(sid)
  await sleep(20)
  let delegated = 0
  const resulting = await approvalListener({ agent: { id: 's-main' }, toolName: 'bash', signal: new AbortController().signal }, async () => {
    delegated += 1
    return 'rejected'
  })
  assert.equal(delegated, 1, 'delegates when no phone is subscribed')
  assert.equal(resulting, 'rejected')
  console.log('ok 8: approval delegates to the desktop chain when no phone watches the session')
}

// 9. question waterfall + answer
{
  const questionListener = listeners.get('user-questions/request')[0].fn
  const frames = []
  bridge.subscribe(10, 's-main', (frame) => frames.push(JSON.parse(JSON.stringify(frame))))
  await sleep(30)
  const abort = new AbortController()
  const request = {
    agent: { id: 's-main' },
    questions: [{ id: 'q1', question: 'ship?', options: [{ label: 'yes' }, { label: 'no' }] }],
    wait: { callId: 'call-q', timed: true },
    signal: abort.signal,
  }
  let settled
  Promise.resolve(questionListener(request, () => { throw new Error('should not delegate') })).then((answer) => { settled = answer })
  await sleep(40)
  const card = frames.find((frame) => frame.t === 'interaction' && frame.interaction.kind === 'question' && frame.interaction.state === 'open')
  assert.ok(card, 'question card pushed to the phone')
  assert.equal(card.interaction.timed, true)
  const result = await bridge.rpc('interaction.answer', {
    key: card.interaction.key,
    answers: [{ id: 'q1', selected: ['yes'] }],
  })
  assert.equal(result.settled, 'live')
  assert.deepEqual(settled, { answers: [{ id: 'q1', selected: ['yes'] }] })
  console.log('ok 9: question waterfall claims the timed wait and returns the phone answer')
}

// 10. continued question answered through userQuestions.answer
{
  const frames = []
  bridge.unsubscribe(10)
  bridge.subscribe(11, 's-main', (frame) => frames.push(JSON.parse(JSON.stringify(frame))))
  await sleep(40)
  // answer the "q-old" continued question replayed from the projection
  const result = await bridge.rpc('interaction.answer', {
    key: 'q:q-old',
    callId: 'q-old',
    answers: [{ id: 'q1', selected: ['ok'] }],
  })
  assert.equal(result.settled, 'continued')
  assert.equal(controller.calls.resolveAgent[0], 's-main')
  assert.equal(services.userQuestions.answered.callId, 'q-old')
  assert.deepEqual(services.userQuestions.answered.answer, { answers: [{ id: 'q1', selected: ['ok'] }] })
  console.log('ok 10: continued question resolves the live agent and uses userQuestions.answer')
}

// 11. phone disconnect settles a pending approval as cancelled
{
  const approvalListener = listeners.get('approval/request')[0].fn
  const frames = []
  bridge.unsubscribe(11)
  bridge.subscribe(12, 's-main', (frame) => frames.push(JSON.parse(JSON.stringify(frame))))
  await sleep(30)
  let resolved
  Promise.resolve(approvalListener({ agent: { id: 's-main' }, toolName: 'bash', signal: new AbortController().signal }, () => 'unavailable'))
    .then((value) => { resolved = value })
  await sleep(30)
  bridge.unsubscribe(12)
  await sleep(30)
  assert.equal(resolved, 'cancelled', 'disconnect frees the turn instead of hanging')
  console.log('ok 11: phone disconnect settles a pending approval as cancelled')
}

// 12. tool detail + unknown methods + rename + fork
{
  bridge.subscribe(13, 's-main', () => {})
  await sleep(40)
  const detail = await bridge.rpc('tool.detail', { sessionId: 's-main', callId: 'c1' }, { sid: 13 })
  assert.match(detail.args, /"command": "ls"/)
  assert.equal(detail.status, 'ok')
  await assert.rejects(bridge.rpc('nope', {}), (error) => error.code === 'method-not-found')
  const renamed = await bridge.rpc('rename', { sessionId: 's-main', title: 'Renamed' })
  assert.equal(renamed.title, 'Renamed')

  // Fork from an exact event boundary, and the default "latest completed turn".
  const forked = await bridge.rpc('fork', { sessionId: 's-main', atSeq: 12 })
  assert.deepEqual(forked, { sessionId: 's-fork-new', from: 's-main', atSeq: 12 })
  assert.deepEqual(controller.calls.fork.at(-1), { sessionId: 's-main', atSeq: 12 })
  const latest = await bridge.rpc('fork', { sessionId: 's-main' })
  assert.equal(latest.atSeq, null)
  assert.equal(Object.prototype.hasOwnProperty.call(controller.calls.fork.at(-1), 'atSeq'), false, 'omitted atSeq stays omitted')
  // Negative/absent ids are rejected before the host call.
  await assert.rejects(bridge.rpc('fork', { atSeq: 3 }), (error) => error.code === 'bad-request')
  await assert.rejects(bridge.rpc('fork', { sessionId: 's-missing' }), (error) => error.code === 'session/not-found')
  console.log('ok 12: tool detail, unknown-method error, rename and fork')
}

// 13. snapshot folding handles injected context, unknown events, interrupted
{
  const folded = foldSnapshot({
    header: { id: 's', version: 4, createdAt: 1, isSeeded: false },
    cursor: 3,
    hasMore: false,
    records: [
      { type: 'event', event: { type: 'user/message', seq: 1, time: 1, data: { id: 'x', role: 'user', content: [{ type: 'text', text: 'injected' }], source: { kind: 'user-question-reply' } }, surfaceOp: 'append' } },
      { type: 'event', event: { type: 'assistant/message', seq: 2, time: 2, data: { turn: 1, step: 1, message: { id: 'y', role: 'assistant', content: [{ type: 'reasoning', text: 'thinking' }, { type: 'text', text: 'answer' }] }, interrupted: true }, surfaceOp: 'append' } },
      { type: 'event', event: { type: 'unknown/future', seq: 3, time: 3, data: {} } },
    ],
    projections: { values: {} },
  })
  assert.deepEqual(folded.items.map((item) => item.kind), ['status', 'reasoning', 'assistant'])
  assert.equal(folded.items[2].interrupted, true)
  assert.equal(folded.cursor, 3)
  console.log('ok 13: injected context, reasoning blocks, interruption and unknown events fold safely')
}

// 14. controller calls receive a real AbortSignal (0.2.1 calls signal.throwIfAborted)
{
  assert(controller.calls.promptSignals.every((signal) => signal && typeof signal.throwIfAborted === 'function'),
    'prompt got an AbortSignal')
  assert(controller.calls.pageSignals[0] && typeof controller.calls.pageSignals[0].throwIfAborted === 'function',
    'page got an AbortSignal')
  assert((controller.calls.listSignals ?? []).every((signal) => signal && typeof signal.throwIfAborted === 'function'),
    'list got an AbortSignal')
  console.log('ok 14: unary session calls always receive a real AbortSignal')
}

// 15. image prompts + attachment reads
{
  const images = [{ mediaType: 'image/png', data: 'aGVsbG8=', name: 'shot.png' }]
  const accepted = await bridge.rpc('prompt', { sessionId: 's-main', text: '', images })
  assert.equal(accepted.accepted, true)
  const sent = controller.calls.prompt[controller.calls.prompt.length - 1]
  assert.deepEqual(sent.content, [{ type: 'image', mediaType: 'image/png', data: 'aGVsbG8=', name: 'shot.png' }])
  await assert.rejects(bridge.rpc('prompt', { sessionId: 's-main', text: 'x', images: [{ mediaType: 'image/heic', data: 'aGVsbG8=' }] }),
    (error) => error.code === 'bad-request')
  const image = await bridge.rpc('image.get', { sessionId: 's-main', attachmentId: 'att-1' })
  assert.equal(image.data, 'aGVsbG8=')
  assert.equal(image.mediaType, 'image/png')
  assert.deepEqual(controller.calls.attachment[0], { sessionId: 's-main', attachmentId: 'att-1' })
  console.log('ok 15: image prompt parts validated and attachment bytes readable')
}

// 16. terminal bridge (owner-scoped terminals service)
{
  const listed = await bridge.rpc('terminal.list', { sessionId: 's-main' })
  assert.deepEqual(listed.terminals.map((item) => item.id), ['term-1'])
  assert.deepEqual(listed.backends, ['bash'])
  const created = await bridge.rpc('terminal.create', { sessionId: 's-main' })
  assert.equal(created.id, 'term-new')
  assert.equal(created.motd, 'motd')
  const read = await bridge.rpc('terminal.read', { sessionId: 's-main', terminalId: 'term-1' })
  assert.match(read.text, /file-a/)
  const send = await bridge.rpc('terminal.send', { sessionId: 's-main', terminalId: 'term-1', text: 'ls', submit: true })
  assert.equal(send.pending, false)
  assert.match(send.delta, /delta-output|done-output/)
  const cancelled = await bridge.rpc('terminal.cancel', { sessionId: 's-main', terminalId: 'term-1' })
  assert.equal(cancelled.cancelled, true)
  const closed = await bridge.rpc('terminal.close', { sessionId: 's-main', terminalId: 'term-1' })
  assert.equal(closed.closed, true)
  console.log('ok 16: terminal list/create/read/send/cancel/close bridge works')
}

// 17. fold emits image rows from both sides
{
  const folded = foldSnapshot({
    header: { id: 's', version: 4, createdAt: 1, isSeeded: false },
    cursor: 2,
    hasMore: false,
    records: [
      { type: 'event', event: { type: 'user/message', seq: 1, time: 1, data: { id: 'u', role: 'user', content: [{ type: 'image', attachment: { attachmentId: 'a1', mediaType: 'image/png', width: 10, height: 20 } }, { type: 'text', text: 'look' }], source: { kind: 'user' } }, surfaceOp: 'append' } },
      { type: 'event', event: { type: 'assistant/message', seq: 2, time: 2, data: { turn: 1, step: 1, message: { id: 'a', role: 'assistant', content: [{ type: 'image', attachment: { attachmentId: 'a2', mediaType: 'image/jpeg', width: 3, height: 4 } }, { type: 'text', text: 'done' }] }, stream: [] }, surfaceOp: 'append' } },
    ],
    projections: { values: {} },
  })
  assert.deepEqual(folded.items.map((item) => item.kind), ['image', 'user', 'image', 'assistant'])
  assert.equal(folded.items[0].attachmentId, 'a1')
  assert.equal(folded.items[0].own, true)
  assert.equal(folded.items[2].attachmentId, 'a2')
  console.log('ok 17: image blocks fold into rows for user and assistant messages')
}

// 18. presets without the terminal registry fall back to an owned subprocess PTY
{
  const listed = await bridge.rpc('terminal.list', { sessionId: 's-fallback' })
  assert.deepEqual(listed.backends, ['subprocess'])
  assert.equal(listed.fallback, true)
  const created = await bridge.rpc('terminal.create', { sessionId: 's-fallback' })
  assert.match(created.id, /^mterm-/)
  assert.equal(created.fallback, true)
  const sent = await bridge.rpc('terminal.send', { sessionId: 's-fallback', terminalId: created.id, text: 'echo hi', waitMs: 100 })
  assert.match(sent.delta, /hello/)
  const read = await bridge.rpc('terminal.read', { sessionId: 's-fallback', terminalId: created.id })
  assert.match(read.text, /hello/)
  const cancelled = await bridge.rpc('terminal.cancel', { sessionId: 's-fallback', terminalId: created.id })
  assert.equal(cancelled.cancelled, true)
  const closed = await bridge.rpc('terminal.close', { sessionId: 's-fallback', terminalId: created.id })
  assert.equal(closed.closed, true)
  console.log('ok 18: subprocess-PTY terminal fallback works for presets without the registry')
}

// 19. permission presets: catalog, switch, and the folded-knob push frame
{
  const catalog = await bridge.rpc('permission.catalog', {})
  assert.equal(catalog.available, true)
  assert.equal(catalog.defaultPreset, 'workspace-write')
  assert.deepEqual(catalog.options.map((option) => option.id), ['read-only', 'workspace-write', 'danger-full-access'])
  assert.equal(catalog.options[2].description, 'no confirmation')

  const switched = await bridge.rpc('permission.set', { sessionId: 's-main', preset: 'danger-full-access' })
  assert.deepEqual(switched, { preset: 'danger-full-access' })
  assert.equal(controller.calls.permission.at(-1).name, 'danger-full-access')
  assert.equal(controller.calls.permission.at(-1).session.header.cwd, '/work/main', 'switch targets the resolved session')

  // Missing arguments are rejected before the host call.
  await assert.rejects(bridge.rpc('permission.set', { preset: 'x' }), (error) => error.code === 'bad-request')
  await assert.rejects(bridge.rpc('permission.set', { sessionId: 's-main' }), (error) => error.code === 'bad-request')

  // The three knob events are separate; each pushes the folded state the phone
  // renders, so the chip updates without waiting for a new snapshot.
  const frames = []
  const sub = { sid: 'perm-test', sessionId: 's-main', send: (frame) => frames.push(frame), permissions: null }
  bridge.trackPermission(sub, { type: 'permission/preset', data: { preset: 'danger-full-access' } })
  bridge.trackPermission(sub, { type: 'sandbox/mode', data: { mode: 'danger-full-access' } })
  bridge.trackPermission(sub, { type: 'approval/policy', data: { policy: 'never' } })
  bridge.trackPermission(sub, { type: 'tool/call', data: { callId: 'c' } })
  assert.equal(frames.length, 3, 'only permission events push')
  assert.deepEqual(frames.at(-1), {
    t: 'permission',
    sessionId: 's-main',
    permissions: { preset: 'danger-full-access', sandbox: 'danger-full-access', approval: 'never', seeded: false },
  })

  // A follow snapshot can omit projections (cold sessions often do); the bridge
  // reads them once per subscription so the chip is never left blank.
  const hydrated = []
  const hydrateSub = { sid: 'perm-hydrate', sessionId: 's-main', send: (frame) => hydrated.push(frame), permissions: null }
  bridge.subs.set('perm-hydrate', hydrateSub)
  await bridge.hydratePermissions(hydrateSub)
  const projectionCall = controller.calls.projections.at(-1)
  assert.deepEqual(projectionCall.request, { sessionId: 's-main' })
  // `projections()` throws on a missing signal, which is exactly how the chip
  // stayed blank for two releases: it must receive a real AbortSignal.
  assert.ok(projectionCall.signal instanceof AbortSignal, 'projection read gets the shared abort signal')
  assert.equal(hydrated.length, 1)
  assert.deepEqual(hydrated[0], {
    t: 'permission',
    sessionId: 's-main',
    permissions: { preset: 'read-only', sandbox: null, approval: null, seeded: false },
  })
  // Already known: no second read, no duplicate frame.
  await bridge.hydratePermissions(hydrateSub)
  assert.equal(hydrated.length, 1)
  console.log('ok 19: permission catalog, preset switch and folded-knob frame')
}

bridge.dispose()
assert(bridge.signal().aborted, 'dispose aborts the shared host-call signal')
console.log('\nall mobile bridge checks passed')
