#!/usr/bin/env node
// Mock host for the mobile page: swaps the real DSH bridge for scripted fixture
// data so the phone UI can be developed and screenshotted without touching the
// live dsh web process.
//
//   node test-mobile-mock.mjs [--port 0] [--quiet]
//
// Prints an entry URL you can open in a phone browser (or Chrome device mode):
//   http://127.0.0.1:<port>/c/<id>/m?g=<gate>#k=<psk>
// The URL carries the pairing key; the page pairs once and stores it.
//
// Reused by test-mobile-ui.mjs as a module.

import net from 'node:net'
import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { PumpManager } from '../src/pump.js'
import { MobileRouter } from '../src/mobile/index.js'
import { CryptoBox } from '../src/crypto.js'
import { PairingService } from '../src/pairing.js'
import { createIdentity } from '../src/identity.js'

const HERE = path.dirname(fileURLToPath(import.meta.url))

const now = Date.now()

function fixtureItems() {
  return [
    {
      kind: 'user', id: 'u:10', seq: 10, time: now - 9 * 60_000,
      text: '帮我看一下 relay 泵在手机上为什么这么难用，然后给个改进方案。',
      requestId: 'req-fixture-1',
    },
    {
      kind: 'image', id: 'img:user:10:0', seq: 10, time: now - 9 * 60_000,
      attachmentId: 'att-fixture-1', mediaType: 'image/png', width: 240, height: 120,
      name: 'diagram.png', own: true,
    },
    {
      kind: 'reasoning', id: 'r:11', seq: 11, time: now - 8 * 60_000,
      text: '先确认现有泵的注入层做了什么：移动补丁只在窄屏生效，但桌面三栏布局本身就不适合手机；再考虑单独页面。',
    },
    {
      kind: 'assistant', id: 'a:12', seq: 12, time: now - 7 * 60_000,
      text: '现在的手机体验主要卡在三点：\n\n1. 桌面三栏布局在 390px 下中栏被挤到不可用；\n2. 首屏要下载整套 DSH 前端 bundle；\n3. 移动补丁只能打补丁，改不了信息架构。\n\n建议做一个**独立的手机页**：原生调用宿主会话 API，只保留聊天、工具卡片和审批。',
      model: { model: 'deepseek-flash' },
    },
    {
      kind: 'tool', id: 'tool:call-1', seq: 13, time: now - 6 * 60_000,
      callId: 'call-1', name: 'bash',
      args: JSON.stringify({ command: 'ss -tlnp | grep 3080' }, null, 2),
      status: 'ok', isError: false,
      result: 'LISTEN 0 511 127.0.0.1:3080 0.0.0.0:*',
    },
    {
      kind: 'tool', id: 'tool:call-2', seq: 14, time: now - 5 * 60_000,
      callId: 'call-2', name: 'read_file',
      args: JSON.stringify({ path: 'packages/plugin/src/pump.js', limit: 40 }, null, 2),
      status: 'running', isError: false, result: '',
    },
    {
      kind: 'assistant', id: 'a:15', seq: 15, time: now - 4 * 60_000,
      text: '这条是流式输出的示例。手机页通过密封 WebSocket 接收 `agent/assistant-stream` 的增量帧，合并成一条消息，不经过桌面前端。',
      model: { model: 'deepseek-flash' },
    },
    { kind: 'status', id: 'stop:16', seq: 16, time: now - 3 * 60_000, text: '已停止' },
  ]
}

/**
 * Build the scripted bridge that MobileRouter talks to. Each RPC/subscription
 * advances a tiny in-memory conversation so the UI can be driven end to end.
 */
export function createMockBridge() {
  const sessions = [
    {
      id: 'session-a', title: '把手机页做出来', updatedAt: now - 60_000, running: true,
      agentAvailable: true, blank: false, cwd: '/home/dev/projects/dsh-relay',
      formatStatus: 'current', model: { provider: 'deepseek', model: 'deepseek-flash' },
    },
    {
      id: 'session-b', title: '梳理 relay 泵的 keep-alive', updatedAt: now - 2 * 3600_000, running: false,
      agentAvailable: false, blank: false, cwd: '/home/dev/projects/dsh-relay',
      formatStatus: 'current', model: { provider: 'deepseek', model: 'deepseek-chat' },
    },
    {
      id: 'session-c', title: '新会话', updatedAt: now - 26 * 3600_000, running: false,
      agentAvailable: false, blank: true, cwd: '/home/dev', formatStatus: 'current',
    },
  ]
  const items = new Map([
    ['session-a', fixtureItems().slice()],
    ['session-b', [{
      kind: 'assistant', id: 'a:100', seq: 100, time: now - 2 * 3600_000,
      text: '## 连接复用\n\n泵把同一部手机的多个请求复用到一条 TCP 连接上，`KEEPALIVE_IDLE_MS = 45s`。',
      model: { model: 'deepseek-chat' },
    }]],
  ])
  let subscription = null
  let terminalReads = 0
  let running = { 'session-a': true, 'session-b': false }
  // Mirrors the host's folded `permissions` projection, per session.
  const permissionState = new Map([
    ['session-a', { preset: 'workspace-write', sandbox: 'workspace-write', approval: 'ask', seeded: true }],
    ['session-b', { preset: 'danger-full-access', sandbox: 'danger-full-access', approval: 'never', seeded: true }],
    ['session-c', { preset: null, sandbox: 'workspace-write', approval: 'ask', seeded: true }],
  ])
  const timers = new Set()
  const later = (fn, ms) => {
    const timer = setTimeout(() => { timers.delete(timer); fn() }, ms)
    timer.unref?.()
    timers.add(timer)
    return timer
  }

  function send(frame) {
    if (subscription) subscription.send(frame)
  }

  const bridge = {
    upstreamReady: () => true,
    phoneCount: 0,
    onPhoneOpen() { bridge.phoneCount += 1 },
    onPhoneClose() { bridge.phoneCount = Math.max(0, bridge.phoneCount - 1) },
    async rpc(method, params) {
      switch (method) {
        case 'hello':
          return { device: { id: 'MOCKDEV1' }, version: '0.2.1-mock', now: Date.now(), phoneConnected: true, upstream: true }
        case 'sessions':
          return {
            sessions: sessions.slice(),
            // Mirrors the host workspace registry: ordered session ids per
            // project, plus one session that belongs to no project.
            workspaces: [
              {
                id: 'w-relay', title: 'dsh-relay', path: '/home/dev/projects/dsh-relay',
                sessionIds: ['session-a', 'session-b'],
              },
              { id: 'w-empty', title: '空项目', path: '/home/dev/empty', sessionIds: [] },
            ],
          }
        case 'open':
          return { session: sessions.find((row) => row.id === params.sessionId) }
        case 'create': {
          const id = 'session-new-' + Date.now()
          sessions.unshift({
            id, title: '新会话', updatedAt: Date.now(), running: false, agentAvailable: false,
            blank: true, cwd: '/home/dev', formatStatus: 'current',
          })
          items.set(id, [])
          return { sessionId: id }
        }
        case 'prompt': {
          running[params.sessionId] = true
          const userItem = {
            kind: 'user', id: 'u:' + Date.now(), seq: Date.now(), time: Date.now(),
            text: String(params.text ?? ''), requestId: params.requestId,
          }
          const list = items.get(params.sessionId) ?? []
          list.push(userItem)
          items.set(params.sessionId, list)
          // Durable user/message lands at turn claim time on a real host; the
          // delay lets the UI test observe the optimistic bubble first.
          later(() => {
            send({ t: 'items', sessionId: params.sessionId, added: [userItem], updated: [], cursor: userItem.seq })
            send({ t: 'status', sessionId: params.sessionId, running: true })
          }, 500)
          later(() => {
            const attemptId = 'attempt-' + Date.now()
            send({ t: 'assistant-stream', sessionId: params.sessionId, frame: { type: 'start', attemptId, revision: 1 } })
            // Reasoning streams first, like a real model: the phone shows it live.
            const reasoning = ['先看手机页现在缺什么：', '权限入口、思考过程、命令详情。', '把这些放进两个面板。']
            const chunks = ['收到，', '这是 mock 的回复流，', '\n\n- 手机端 RPC 正常\n', '- 密封 WebSocket 正常\n', '- 审批卡片正常']
            let reasoningIndex = 0
            let index = 0
            const tickReasoning = () => {
              if (reasoningIndex >= reasoning.length) {
                later(tick, 40)
                return
              }
              const delta = reasoning[reasoningIndex]
              reasoningIndex += 1
              send({
                t: 'assistant-stream', sessionId: params.sessionId,
                frame: {
                  type: 'chunk', attemptId, revision: 1,
                  chunk: { type: 'reasoning-delta', index: 0, text: delta },
                },
              })
              later(tickReasoning, 180)
            }
            const tick = () => {
              if (index >= chunks.length) {
                send({ t: 'assistant-stream', sessionId: params.sessionId, frame: { type: 'end', attemptId, revision: 1, outcome: { kind: 'committed' } } })
                const text = chunks.join('')
                const seq = Date.now()
                const item = { kind: 'assistant', id: 'a:' + seq, seq, time: Date.now(), text, model: { model: 'deepseek-flash' } }
                const current = items.get(params.sessionId) ?? []
                current.push(item)
                items.set(params.sessionId, current)
                send({ t: 'items', sessionId: params.sessionId, added: [item], updated: [], cursor: seq })
                send({ t: 'status', sessionId: params.sessionId, running: false })
                running[params.sessionId] = false
                const row = sessions.find((entry) => entry.id === params.sessionId)
                if (row) row.running = false
                return
              }
              const text = chunks[index]
              index += 1
              send({
                t: 'assistant-stream', sessionId: params.sessionId,
                frame: {
                  type: 'chunk', attemptId, revision: 1,
                  chunk: { type: 'text-delta', index: 0, text },
                },
              })
              later(tick, 260)
            }
            tickReasoning()
          }, 1100)
          return { accepted: true, requestId: params.requestId }
        }
        case 'stop':
          send({ t: 'status', sessionId: params.sessionId, running: false })
          send({
            t: 'items', sessionId: params.sessionId, added: [{
              kind: 'status', id: 'stop:' + Date.now(), seq: Date.now(), time: Date.now(), text: '已停止',
            }], updated: [], cursor: Date.now(),
          })
          return { accepted: true }
        case 'interaction.answer':
          send({ t: 'interaction-done', key: params.key, outcome: params.outcome ?? 'answered' })
          // The approved tool finishes: a real host replaces the item, which is
          // exactly the frame that used to collapse an expanded card.
          if (String(params.key ?? '').includes('call-2')) {
            const target = subscription?.sessionId ?? params.sessionId
            const list = items.get(target) ?? []
            const tool = list.find((entry) => entry.id === 'tool:call-2')
            if (tool) {
              tool.status = 'ok'
              tool.result = '// pump.js excerpt\nconst KEEPALIVE_IDLE_MS = 45_000'
              send({ t: 'items', sessionId: target, added: [], updated: [{ ...tool }], cursor: tool.seq })
            }
          }
          return { accepted: true }
        case 'older':
          return {
            items: [{
              kind: 'user', id: 'u:1', seq: 1, time: now - 3 * 3600_000,
              text: '更早的一条历史消息（分页加载）。',
            }],
            hasMore: false,
          }
        case 'rename':
          return { title: params.title }
        case 'fork': {
          const source = sessions.find((row) => row.id === params.sessionId)
          if (!source) {
            const missing = new Error(`session "${params.sessionId}" not found`)
            missing.code = 'session/not-found'
            throw missing
          }
          const atSeq = Number.isFinite(Number(params.atSeq)) ? Number(params.atSeq) : undefined
          const id = 'session-fork-' + Date.now()
          sessions.unshift({
            id,
            title: (source.title || '会话') + ' · 分支',
            updatedAt: Date.now(),
            running: false,
            agentAvailable: false,
            blank: false,
            cwd: source.cwd,
            formatStatus: 'current',
            model: source.model,
            parentSessionId: source.id,
          })
          const copied = (items.get(params.sessionId) ?? [])
            .filter((item) => atSeq === undefined || typeof item.seq !== 'number' || item.seq <= atSeq)
            .map((item) => Object.assign({}, item, { id: item.id + ':fork' }))
          items.set(id, copied)
          return { sessionId: id, from: source.id, atSeq: atSeq ?? null }
        }
        case 'model.catalog':
          return {
            default: { provider: 'deepseek', model: 'deepseek-flash' },
            routableProviders: ['deepseek'],
            groups: [{
              id: 'deepseek', name: 'DeepSeek',
              models: [
                { id: 'deepseek-flash', name: 'DeepSeek Flash', description: '快速日常' },
                { id: 'deepseek-chat', name: 'DeepSeek Chat', description: '通用' },
                { id: 'deepseek-reasoner', name: 'DeepSeek Reasoner', description: '深度推理' },
              ],
            }],
            failures: [],
          }
        case 'model.select':
          return { selected: { provider: params?.selection?.provider ?? 'deepseek', model: params?.selection?.model ?? 'deepseek-flash' } }
        case 'permission.catalog':
          return {
            available: true,
            defaultPreset: 'workspace-write',
            options: [
              { id: 'read-only', label: 'read-only', description: null },
              { id: 'workspace-write', label: 'workspace-write', description: null },
              { id: 'danger-full-access', label: 'danger-full-access', description: null },
            ],
          }
        case 'permission.set': {
          const preset = String(params?.preset ?? '')
          const known = {
            'read-only': { sandbox: 'read-only', approval: 'ask' },
            'workspace-write': { sandbox: 'workspace-write', approval: 'ask' },
            'danger-full-access': { sandbox: 'danger-full-access', approval: 'never' },
          }
          if (!known[preset]) {
            const bad = new Error(`unknown preset "${preset}"`)
            bad.code = 'permission/denied'
            throw bad
          }
          const next = { preset, ...known[preset], seeded: true }
          permissionState.set(params.sessionId, next)
          send({ t: 'permission', sessionId: params.sessionId, permissions: next })
          return { preset }
        }
        case 'image.get': {
          // 1x1 transparent PNG (valid); the row's width/height attrs scale it.
          const png = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
          return { mediaType: 'image/png', data: png, attachment: { attachmentId: params.attachmentId, mediaType: 'image/png', width: 240, height: 120 } }
        }
        case 'terminal.list':
          return { terminals: [], backends: ['bash'] }
        case 'terminal.create':
          return { id: 'term-1', name: 'bash', type: 'bash', pid: 4242, status: 'running', motd: 'mock bash — 输入命令试试（这里不会真的执行）\n$ ' }
        case 'terminal.read': {
          // Real shells emit VT control sequences; the page has to strip them
          // because it renders into a plain <pre>. The reply also mimics the
          // bridge's delta mode: the first read is a full snapshot, later ones
          // carry only new lines (`appended: true`).
          terminalReads += 1
          if (params?.reset === true) terminalReads = 1
          if (terminalReads === 1) {
            return {
              text: '\u001b[1t\u001b[?1004h\u001b[?7l mock bash — terminal output\u001b[?7h\r\n'
                + '$ echo hello\r\nhello\r\n\u001b[4;22H$ \u001b]9001;CmdNotFound;ls\u0007',
              totalLines: 4,
              lineBegin: 0,
              lineEnd: 4,
              truncated: false,
              appended: false,
            }
          }
          if (terminalReads === 2) {
            return {
              text: '$ tail -n 1\nappended-by-poll', totalLines: 6, lineBegin: 4, lineEnd: 6, truncated: false, appended: true,
            }
          }
          return { text: '', totalLines: 6, lineBegin: 4, lineEnd: 6, truncated: false, appended: true }
        }
        case 'terminal.send':
          return { delta: '', pending: false, waitReason: 'idle', sessionStatus: 'running', truncated: false }
        case 'terminal.cancel':
          return { cancelled: true }
        case 'terminal.close':
          return { closed: true }
        default:
          throw Object.assign(new Error('mock: unknown method ' + method), { code: 'method-not-found' })
      }
    },
    subscribe(sid, sessionId, emit) {
      subscription = { sid, sessionId, send: emit }
      later(() => {
        if (!subscription || subscription.sessionId !== sessionId) return
        send({
          t: 'session',
          sessionId,
          title: sessions.find((row) => row.id === sessionId)?.title ?? null,
          meta: {
            sessionId,
            cwd: sessions.find((row) => row.id === sessionId)?.cwd ?? null,
            createdAt: now - 86400_000,
          },
          items: items.get(sessionId) ?? [],
          cursor: 16,
          hasMore: sessionId === 'session-a',
          stream: null,
          running: running[sessionId] === true,
          permissions: permissionState.get(sessionId) ?? null,
          projections: sessionId === 'session-a'
            ? {
              modelSelection: { lastUsed: { provider: 'deepseek', model: 'deepseek-flash' } },
              permissions: permissionState.get(sessionId) ?? null,
            }
            : { permissions: permissionState.get(sessionId) ?? null },
        })
        if (sessionId !== 'session-a') return
        // An approval and a question arrive while the "agent" is running.
        later(() => send({
          t: 'interaction',
          interaction: {
            kind: 'approval', key: 'ap:session-a:call-2', sessionId,
            toolName: 'read_file', callId: 'call-2', state: 'open',
            reason: '读取 relay 泵源码（只读）', displayReason: '读取文件',
            args: JSON.stringify({ path: 'packages/plugin/src/pump.js', limit: 40 }, null, 2),
          },
        }), 1200)
        later(() => send({
          t: 'interaction',
          interaction: {
            kind: 'question', key: 'q:call-q1', sessionId, callId: 'call-q1',
            state: 'open', timed: true,
            questions: [{
              id: 'q1',
              question: '手机页要不要保留完整文件浏览？',
              header: '范围确认',
              multiSelect: false,
              options: [{ label: '只保留聊天与审批' }, { label: '保留文件浏览' }, { label: '先不做，后续再加' }],
            }],
          },
        }), 2200)
      }, 120)
    },
    unsubscribe() { subscription = null },
    dispose() { for (const timer of timers) clearTimeout(timer) },
  }
  return bridge
}

/** Start the mock host behind a fake relay (plain TCP) and return its info. */
export async function startMockServer({ port = 0 } = {}) {
  // Keep audit/identity writes out of the live ~/.dsh.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-relay-mock-'))
  process.env.DSH_HOME = home

  const identity = createIdentity()
  const cryptoBox = new CryptoBox(identity)
  const pairing = new PairingService(cryptoBox, identity)
  const bridge = createMockBridge()
  const mobile = new MobileRouter({ cryptoBox, bridge })
  const pump = new PumpManager({
    resolveTarget: () => ({ host: '127.0.0.1', port: 1, authority: '127.0.0.1:1', protocol: 'http:' }),
    resolveAuthCookie: () => null,
    pairing,
    cryptoBox,
    mobile,
  })
  const sockets = new Map()
  let nextSid = 1
  const relay = net.createServer((socket) => {
    const sid = nextSid++
    sockets.set(sid, socket)
    socket.on('data', (chunk) => pump.handleStreamData(sid, chunk))
    socket.on('close', () => { sockets.delete(sid); pump.handleStreamClose(sid) })
    socket.on('error', () => {})
  })
  pump.setClient({
    sendStream(sid, chunk) { sockets.get(sid)?.write(chunk) },
    closeStream(sid) { sockets.get(sid)?.end() },
  })
  await new Promise((resolve) => relay.listen(port, '127.0.0.1', resolve))
  const actualPort = relay.address().port
  const pskB64 = Buffer.concat([
    Buffer.from(identity.psk, 'hex'),
    Buffer.from(identity.signJwk.public.x, 'base64url'),
  ]).toString('base64url')
  const url = `http://127.0.0.1:${actualPort}/c/${identity.id}/m?g=${identity.gate}#k=${pskB64}`
  return {
    url,
    port: actualPort,
    identity,
    bridge,
    close() {
      relay.close()
      for (const socket of sockets.values()) socket.destroy()
      bridge.dispose()
      fs.rmSync(home, { recursive: true, force: true })
    },
  }
}

// CLI: serve until Ctrl+C.
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  const server = await startMockServer({ port: Number(process.env.MOCK_PORT ?? 0) })
  console.log('\nMOBILE_MOCK_URL=' + server.url + '\n')
  const shutdown = () => { server.close(); process.exit(0) }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}
