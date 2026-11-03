#!/usr/bin/env node
// End-to-end UI check for the mobile page, driven over CDP against the mock
// host (scripts/mobile-mock.mjs): load + pair, chat rendering, drawer, approval
// answer, question answer, send/streaming, stop.
//
//   node test/mobile-ui.test.mjs [--keep] [--out .tmp/mobile-ui]
//
// Screenshots are written to --out (default .tmp/mobile-ui). No live dsh web
// or relay is involved.

import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import { WebSocket } from 'ws'
import { startMockServer } from '../scripts/mobile-mock.mjs'
import { launchChrome, pageTargetWsUrl } from '../scripts/lib/chrome.mjs'

const args = process.argv.slice(2)
const OUT = (() => {
  const at = args.indexOf('--out')
  return path.resolve(at === -1 ? '.tmp/mobile-ui' : args[at + 1])
})()
fs.mkdirSync(OUT, { recursive: true })

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

const server = await startMockServer()
const profile = path.join(OUT, 'chrome-profile')
fs.rmSync(profile, { recursive: true, force: true })
const chrome = launchChrome({ profileDir: profile })
if (!chrome) {
  console.log('SKIP: no Chrome/Chromium found (set CHROME_BIN to run the UI test)')
  server.close()
  process.exit(0)
}
const wsUrl = await pageTargetWsUrl(chrome.port)
if (!wsUrl) {
  chrome.child.kill('SIGKILL')
  server.close()
  throw new Error('chrome devtools not reachable')
}

const ws = new WebSocket(wsUrl)
await new Promise((resolve) => ws.once('open', resolve))

let messageId = 0
const pending = new Map()
const consoleErrors = []
ws.on('message', (data) => {
  const message = JSON.parse(data.toString())
  if (message.id && pending.has(message.id)) {
    const entry = pending.get(message.id)
    pending.delete(message.id)
    if (message.error) entry.reject(new Error(message.error.message))
    else entry.resolve(message.result)
    return
  }
  if (message.method === 'Runtime.exceptionThrown') {
    consoleErrors.push('exception: ' + (message.params.exceptionDetails.exception?.description
      ?? message.params.exceptionDetails.text))
  } else if (message.method === 'Runtime.consoleAPICalled' && message.params.type === 'error') {
    consoleErrors.push('console: ' + message.params.args.map((arg) => arg.value ?? arg.description ?? '').join(' '))
  } else if (message.method === 'Log.entryAdded' && message.params.entry.level === 'error') {
    const text = message.params.entry.text
    // Ignore expected noise: the browser asks for a favicon/manifest we do not
    // serve, and a pooled keep-alive connection can be closed by the pump's
    // idle timeout just as Chrome reuses it (ERR_EMPTY_RESPONSE). Chrome
    // retries the request; the functional assertions below would fail if it
    // mattered.
    if (!/favicon|manifest|net::ERR_EMPTY_RESPONSE/.test(text)) consoleErrors.push('log: ' + text)
  }
})

function cdp(method, params = {}) {
  const id = ++messageId
  ws.send(JSON.stringify({ id, method, params }))
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }))
}

async function evaluate(expression) {
  const result = await cdp('Runtime.evaluate', {
    expression,
    awaitPromise: true,
    returnByValue: true,
    userGesture: true,
  })
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text + ' ' + (result.exceptionDetails.exception?.description ?? ''))
  return result.result?.value
}

async function waitFor(expression, description, timeout = 15000) {
  const started = Date.now()
  let last
  while (Date.now() - started < timeout) {
    try {
      last = await evaluate(expression)
      if (last) return last
    } catch (error) {
      last = error.message
    }
    await sleep(120)
  }
  throw new Error(`timeout waiting for ${description} (last=${JSON.stringify(last)})`)
}

async function screenshot(name) {
  const result = await cdp('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false })
  fs.writeFileSync(path.join(OUT, name), Buffer.from(result.data, 'base64'))
  console.log('  screenshot ' + path.join(OUT, name))
}

function crc32(buffer) {
  let crc = 0xffffffff
  for (const byte of buffer) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1))
  }
  return (crc ^ 0xffffffff) >>> 0
}

function pngChunk(type, data) {
  const length = Buffer.alloc(4)
  length.writeUInt32BE(data.length, 0)
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data])
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(crc32(body), 0)
  return Buffer.concat([length, body, crc])
}

/** A small valid PNG (gradient) so the composer's image path is exercised. */
function makePng(width, height) {
  const raw = Buffer.alloc((width * 3 + 1) * height)
  let at = 0
  for (let y = 0; y < height; y += 1) {
    raw[at++] = 0
    for (let x = 0; x < width; x += 1) {
      raw[at++] = Math.round((x / width) * 220) + 20
      raw[at++] = Math.round((y / height) * 180) + 40
      raw[at++] = 200
    }
  }
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(width, 0)
  ihdr.writeUInt32BE(height, 4)
  ihdr[8] = 8
  ihdr[9] = 2
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(raw)),
    pngChunk('IEND', Buffer.alloc(0)),
  ])
}

function assert(condition, message) {
  if (!condition) throw new Error('ASSERT: ' + message)
  console.log('ok: ' + message)
}

let failed = false
try {
  await cdp('Runtime.enable')
  await cdp('Log.enable')
  await cdp('Page.enable')
  await cdp('Emulation.setDeviceMetricsOverride', {
    width: 390, height: 844, deviceScaleFactor: 2, mobile: true,
  })
  await cdp('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 })
  await cdp('Page.navigate', { url: server.url })

  // ── 1. pairing + first session load ──────────────────────────────────
  await waitFor(
    'document.getElementById("sessionTitle") && document.getElementById("sessionTitle").textContent.includes("把手机页做出来")',
    'session title after pairing', 20000,
  )
  await waitFor('document.querySelectorAll(".item.user").length >= 1', 'fixture transcript')
  assert(await evaluate('document.getElementById("empty").hidden === true'), 'empty placeholder hides once the transcript has rows')
  // composer layout: input and send button must stay inside the viewport with
  // the model chip on its own line above them
  {
    const layout = await evaluate(`(function () {
      var chip = document.getElementById('modelBtn')
      var input = document.getElementById('input')
      var send = document.getElementById('sendBtn')
      var c = chip.getBoundingClientRect(), i = input.getBoundingClientRect(), s = send.getBoundingClientRect()
      return { chipBottom: c.bottom, inputTop: i.top, inputRight: i.right, sendLeft: s.left, sendRight: s.right, width: window.innerWidth, chipW: c.width, inputW: i.width }
    })()`)
    assert(layout.chipBottom <= layout.inputTop + 4, 'model chip sits on its own line above the input')
    assert(layout.sendRight <= layout.width + 1, 'send button stays on screen')
    assert(layout.inputW > 120, 'input keeps a usable width')
  }
  assert(await evaluate('document.body.innerText.includes("独立的手机页")'), 'assistant markdown rendered')
  assert(await evaluate('document.querySelectorAll(".item.tool").length >= 2'), 'tool cards rendered')
  assert(await evaluate('document.querySelector(".item.tool .tool-state.run") !== null'), 'running tool state shown')
  await screenshot('01-chat.png')

  // ── 1a. tapping a collapsed tool card opens it ───────────────────────
  await evaluate('document.querySelector(".item.tool .tool-preview").click()')
  await sleep(150)
  assert(await evaluate('document.querySelector(".item.tool .card.open") !== null'), 'tapping the command preview expands the tool card')
  // Visibility, not just presence: `textContent` is readable on a `display:none`
  // subtree, which is exactly how a selector mismatch shipped unnoticed.
  assert(await evaluate('document.querySelector(".item.tool .card.open .tool-detail").offsetHeight > 0'), 'expanded card actually renders the detail block')
  assert(await evaluate('getComputedStyle(document.querySelector(".item.tool .card.open .tool-preview")).display === "none"'), 'the collapsed preview is hidden while expanded')
  assert(await evaluate('document.querySelector(".item.tool .card.open .tool-detail").textContent.length > 0'), 'expanded card shows the arguments')
  assert(await evaluate('document.querySelector(".item.tool .card.open .tool-primary").textContent === "ss -tlnp | grep 3080"'), 'expanded card shows the whole command, not the cut preview')
  await evaluate('document.querySelector(".item.tool .card.open .tool-head").click()')
  await sleep(150)
  assert(await evaluate('document.querySelectorAll(".item.tool .card.open").length === 0'), 'tapping the header closes it again')
  assert(await evaluate('getComputedStyle(document.querySelector(".item.tool .tool-detail")).display === "none"'), 'closing hides the detail again')
  assert(await evaluate('document.querySelector(".item.tool .tool-preview").offsetHeight > 0'), 'closing brings the preview back')

  // Leave the running card open: the approval answer later updates that item,
  // and the expanded state must survive the rebuild.
  await evaluate('(function () { var cards = document.querySelectorAll(".item.tool .card"); cards[1].click() })()')
  await sleep(150)
  assert(await evaluate('document.querySelectorAll(".item.tool .card.open").length === 1'), 'second card opens for the persistence check')

  // ── 1b. permission sheet (per session, beside the model chip) ────────
  // Captured before anything raises a toast, so the doc shot stays clean.
  await evaluate('document.getElementById("permBtn").click()')
  await waitFor('!document.getElementById("permSheet").hidden', 'permission sheet open')
  await waitFor('document.querySelector("#permBody .perm-row.current") !== null', 'permission catalog loaded (doc shot)')
  await sleep(350) // sheetUp animation
  assert(await evaluate('document.querySelectorAll("#permBody .perm-row").length === 3'), 'permission sheet lists the host presets')
  await screenshot('19b-permission-sheet.png')
  await evaluate('document.getElementById("permClose").click()')
  await waitFor('document.getElementById("permSheet").hidden', 'permission sheet closed again')

  // ── 2. drawer with session list ──────────────────────────────────────
  await evaluate('document.getElementById("menuBtn").click()')
  await waitFor('!document.getElementById("drawer").hidden', 'drawer open')
  await sleep(350) // let the slide-in animation settle before the screenshot
  assert(await evaluate('document.querySelectorAll("#sessions .session").length >= 3'), 'drawer lists sessions')
  assert(await evaluate('document.querySelectorAll("#sessions .session-group").length >= 2'), 'drawer groups sessions into projects')
  assert(await evaluate('document.querySelector("#sessions .session-group-head .g-name").textContent.includes("dsh-relay")'), 'project header shows the workspace title')
  await screenshot('02-drawer.png')
  await evaluate('document.getElementById("drawerClose").click()')
  await waitFor('document.getElementById("drawer").hidden', 'drawer closed')

  // ── 3. approval card + answer ────────────────────────────────────────
  await waitFor('document.querySelector(".interaction:not(.done) .btn.primary") !== null', 'approval card', 10000)
  assert(await evaluate('document.body.innerText.includes("需要你的确认")'), 'approval card headline')
  await evaluate('document.querySelector(".interaction:not(.done) .btn.danger").scrollIntoView({block:"center"})')
  await screenshot('03-approval.png')
  await evaluate('document.querySelector(".interaction:not(.done) .btn.danger").click()')
  await waitFor('document.querySelector(".interaction") === null || document.querySelector(".interaction.done") !== null', 'approval settled')
  // Answering the approval makes the tool finish; the host then replaces that
  // item, so the card rebuilt from the new frame must stay expanded.
  await waitFor('document.querySelector(".item.tool[data-item-id=\\"tool:call-2\\"]").textContent.includes("完成")', 'tool card reflects the settled state', 8000)
  assert(await evaluate('document.querySelector(".item.tool[data-item-id=\\"tool:call-2\\"] .card.open") !== null'), 'expanded card survives the item update')

  // ── 4. question card ─────────────────────────────────────────────────
  await waitFor('document.body.innerText.includes("手机页要不要保留完整文件浏览")', 'question card', 12000)
  await sleep(300)
  await evaluate('document.querySelectorAll(".interaction")[document.querySelectorAll(".interaction").length - 1].scrollIntoView({block:"start"})')
  await sleep(150)
  await evaluate('document.querySelectorAll(".interaction .i-option")[0].click()')
  assert(await evaluate('document.querySelectorAll(".interaction .i-option.sel").length === 1'), 'question option selects')
  await screenshot('04-question.png')
  await evaluate('document.querySelector(".interaction:not(.done) .btn.primary").click()')
  await waitFor('document.querySelector(".interaction.done") !== null || document.querySelector(".interaction") === null', 'question settled')

  // ── 4b. blank session: empty placeholder -> first message hides it ──
  await evaluate('document.getElementById("menuBtn").click()')
  await waitFor('!document.getElementById("drawer").hidden', 'drawer open (blank session)')
  await sleep(250)
  await evaluate(`
    (function () {
      var rows = document.querySelectorAll('#sessions .session')
      for (var i = 0; i < rows.length; i += 1) {
        if (rows[i].textContent.includes('新会话')) { rows[i].click(); return }
      }
    })()
  `)
  await waitFor('document.getElementById("empty").hidden === false && document.getElementById("empty").innerText.includes("开始对话")', 'empty placeholder on blank session', 8000)
  assert(true, 'blank session shows the empty placeholder')
  // A brand-new session has no selection of its own: the chip shows the model
  // the host will actually use instead of an empty "choose a model" prompt.
  await waitFor('document.getElementById("modelName").textContent.includes("deepseek-flash")', 'new session shows the default model', 8000)
  assert(await evaluate('document.getElementById("modelName").textContent !== "选择模型"'), 'new session never shows the empty model placeholder')
  await evaluate(`
    (function () {
      var input = document.getElementById('input')
      input.value = '第一条消息'
      input.dispatchEvent(new Event('input', { bubbles: true }))
      document.getElementById('sendBtn').click()
    })()
  `)
  await waitFor('document.getElementById("empty").hidden === true', 'empty placeholder hidden after first message', 8000)
  await screenshot('15-blank-session-first-message.png')
  // back to the main session for the remaining checks
  await evaluate('document.getElementById("menuBtn").click()')
  await waitFor('!document.getElementById("drawer").hidden', 'drawer open (back)')
  await sleep(200)
  await evaluate(`
    (function () {
      var rows = document.querySelectorAll('#sessions .session')
      for (var i = 0; i < rows.length; i += 1) {
        if (rows[i].textContent.includes('把手机页做出来')) { rows[i].click(); return }
      }
    })()
  `)
  await waitFor('document.getElementById("sessionTitle").textContent.includes("把手机页做出来")', 'back on the main session', 8000)
  await sleep(500)

  // ── 5. send a prompt + streaming reply ──────────────────────────────
  await evaluate(`
    (function () {
      var input = document.getElementById('input')
      input.value = '手机上现在能直接聊天了吗？'
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })()
  `)
  assert(await evaluate('document.getElementById("sendBtn").disabled === false'), 'send button enabled with text')
  await evaluate('document.getElementById("sendBtn").click()')
  await waitFor('document.body.innerText.includes("手机上现在能直接聊天了吗")', 'optimistic user bubble')
  await screenshot('05-sent.png')
  await waitFor('document.querySelector("[data-streaming]") !== null', 'streaming assistant bubble', 8000)
  // Reasoning renders while the turn is still running, not after it commits.
  await waitFor('document.querySelector(".item.assistant .r-body") !== null', 'reasoning streams live', 8000)
  assert(await evaluate('document.getElementById("stopBtn").hidden === false'), 'reasoning is visible while the turn is still running')
  assert(await evaluate('document.querySelector(".item.assistant .r-body").textContent.length > 0'), 'live reasoning carries text')
  await evaluate('document.getElementById("stream").scrollTop = document.getElementById("stream").scrollHeight')
  await sleep(200)
  await screenshot('06-streaming.png')
  await waitFor('document.querySelector("[data-streaming]") === null && document.body.innerText.includes("密封 WebSocket 正常")', 'streamed reply committed', 12000)
  await screenshot('07-replied.png')

  // ── 6. stop button + status row ─────────────────────────────────────
  await evaluate(`
    (function () {
      var input = document.getElementById('input')
      input.value = '再跑一个长任务'
      input.dispatchEvent(new Event('input', { bubbles: true }))
      document.getElementById('sendBtn').click()
    })()
  `)
  await waitFor('document.querySelector("[data-streaming]") !== null', 'second stream started', 8000)
  await waitFor('document.getElementById("stopBtn").hidden === false', 'stop button visible', 4000)
  await screenshot('08-running.png')
  await evaluate('document.getElementById("stopBtn").click()')
  await waitFor('document.body.innerText.includes("已停止")', 'stop status row', 8000)

  // ── 7. older-history pagination ────────────────────────────────────
  // The scroll event is dispatched explicitly: setting `scrollTop` to a value it
  // already holds fires nothing, which made this step flaky.
  await evaluate('(function () { var s = document.getElementById("stream"); s.scrollTop = 0; s.dispatchEvent(new Event("scroll")) })()')
  await sleep(300)
  await waitFor('document.body.innerText.includes("更早的一条历史消息") || !document.getElementById("jumpBtn").hidden', 'older page trigger', 6000)

  // ── 8. inline image rendering + fullscreen viewer ─────────────────
  await waitFor('document.querySelector(".item.image img") !== null', 'inline image rendered', 8000)
  assert(await evaluate('document.querySelectorAll(".item.image img").length >= 1'), 'image attachment rendered in transcript')
  await evaluate('document.querySelector(".item.image img").click()')
  await waitFor('document.getElementById("imageViewer").hidden === false', 'image viewer open')
  await screenshot('10-image-viewer.png')
  await evaluate('document.getElementById("imageViewer").click()')

  // ── 9. model picker ────────────────────────────────────────────────
  await waitFor('document.getElementById("modelBtn").hidden === false', 'model chip visible')
  assert(await evaluate('document.getElementById("modelName").textContent.includes("deepseek-flash")'), 'current model shown on the chip')
  await evaluate('document.getElementById("modelBtn").click()')
  await waitFor('document.querySelectorAll("#modelList .model-row").length >= 3', 'model catalog rendered', 8000)
  await screenshot('11-model-picker.png')
  await evaluate(`
    (function () {
      var rows = document.querySelectorAll('#modelList .model-row')
      for (var i = 0; i < rows.length; i += 1) {
        if (rows[i].textContent.includes('DeepSeek Chat')) { rows[i].click(); return }
      }
    })()
  `)
  await waitFor('document.getElementById("modelName").textContent.includes("deepseek-chat")', 'model switched', 5000)
  {
    const afterModel = await evaluate(`(function () {
      var input = document.getElementById('input')
      var send = document.getElementById('sendBtn')
      return { inputRight: input.getBoundingClientRect().right, sendRight: send.getBoundingClientRect().right, width: window.innerWidth }
    })()`)
    assert(afterModel.inputRight <= afterModel.width + 1, 'input still fits after model selection')
    assert(afterModel.sendRight <= afterModel.width + 1, 'send button still reachable after model selection')
  }

  // ── 9b. settings: display toggles + permission switch ───────────────
  await evaluate('document.getElementById("menuBtn").click()')
  await waitFor('!document.getElementById("drawer").hidden', 'drawer for settings')
  await sleep(200)
  await evaluate('document.getElementById("settingsLink").click()')
  await waitFor('!document.getElementById("settingsSheet").hidden', 'settings sheet open')
  await sleep(300)
  assert(await evaluate('document.body.innerText.includes("思考过程")'), 'settings list the display toggles')
  assert(await evaluate('document.body.innerText.includes("工具调用")'), 'settings list the tool toggle')
  assert(await evaluate('document.body.innerText.includes("主题")'), 'settings list the appearance choice')
  // Permissions are per session, so they live beside the model chip — never in
  // the drawer's global settings sheet.
  assert(await evaluate('document.querySelectorAll("#settingsBody .perm-row").length === 0'), 'settings sheet stays global (no permission rows)')
  await screenshot('19-settings.png')

  // appearance: night, then light, then back to following the system
  await evaluate(`document.querySelectorAll('#settingsBody .set-row')[0].querySelectorAll('.seg button')[2].click()`)
  await sleep(200)
  assert(await evaluate('document.documentElement.getAttribute("data-theme") === "dark"'), 'picking night mode switches the palette')
  assert(await evaluate('getComputedStyle(document.body).backgroundColor === "rgb(10, 13, 19)"'), 'night mode paints the dark background')
  await evaluate(`document.querySelectorAll('#settingsBody .set-row')[0].querySelectorAll('.seg button')[1].click()`)
  await sleep(200)
  assert(await evaluate('document.documentElement.getAttribute("data-theme") === null'), 'picking light leaves the dark attribute off')
  assert(await evaluate('getComputedStyle(document.body).backgroundColor === "rgb(255, 255, 255)"'), 'light mode paints the white background')
  await evaluate(`document.querySelectorAll('#settingsBody .set-row')[0].querySelectorAll('.seg button')[0].click()`)
  await sleep(150)

  // hide reasoning, then collapse it again
  await evaluate(`document.querySelectorAll('#settingsBody .set-row')[1].querySelectorAll('.seg button')[0].click()`)
  await sleep(200)
  assert(await evaluate('document.querySelectorAll(".item.reasoning").length === 0'), 'hiding reasoning removes those rows')
  await evaluate(`document.querySelectorAll('#settingsBody .set-row')[1].querySelectorAll('.seg button')[1].click()`)
  await sleep(200)
  assert(await evaluate('document.querySelectorAll(".item.reasoning").length > 0'), 'collapsing reasoning brings the rows back')
  assert(await evaluate('document.querySelector(".item.reasoning .r-preview").textContent.length > 0'), 'collapsed reasoning keeps a preview')

  // expand tool cards by default
  await evaluate(`document.querySelectorAll('#settingsBody .set-row')[2].querySelectorAll('.seg button')[2].click()`)
  await sleep(200)
  assert(await evaluate('document.querySelectorAll(".item.tool .card.open").length > 0'), 'tool cards expand when asked')
  await evaluate(`document.querySelectorAll('#settingsBody .set-row')[2].querySelectorAll('.seg button')[1].click()`)
  await sleep(150)
  assert(await evaluate('document.querySelectorAll(".item.tool .card.open").length === 0'), 'tool cards collapse again')

  // permission sheet opens from the chip next to the model
  await evaluate('document.getElementById("settingsClose").click()')
  await waitFor('document.getElementById("settingsSheet").hidden', 'settings closed')
  await evaluate('document.getElementById("permBtn").click()')
  await waitFor('!document.getElementById("permSheet").hidden', 'permission sheet open')
  await waitFor('document.querySelector("#permBody .perm-row.current") !== null', 'permission catalog loaded')
  assert(await evaluate('document.querySelector("#permBody .perm-row.current").textContent.includes("工作区")'), 'current permission is marked')

  // switch the session permission
  await evaluate(`document.querySelector('#permBody .perm-row[data-preset="danger-full-access"]').click()`)
  await waitFor('document.getElementById("permName").textContent.includes("完全权限")', 'permission chip switched', 6000)
  assert(await evaluate('document.getElementById("permBtn").className.includes("warn")'), 'full access is highlighted')
  await waitFor('document.getElementById("permSheet").hidden', 'permission sheet closes after the switch')
  await screenshot('20-permission.png')
  // restore the default preset for the steps that follow
  await evaluate('document.getElementById("permBtn").click()')
  await waitFor('!document.getElementById("permSheet").hidden', 'permission sheet reopened')
  await sleep(200)
  await evaluate(`document.querySelector('#permBody .perm-row[data-preset="workspace-write"]').click()`)
  await waitFor('document.getElementById("permName").textContent.includes("工作区")', 'permission restored', 6000)
  await waitFor('document.getElementById("permSheet").hidden', 'permission sheet closed again')

  // ── 10. attach a photo and send it ─────────────────────────────────
  const pngPath = path.join(OUT, 'attachment.png')
  fs.writeFileSync(pngPath, makePng(480, 240))
  const doc = await cdp('DOM.getDocument', { depth: -1 })
  const fileNode = await cdp('DOM.querySelector', { nodeId: doc.root.nodeId, selector: '#fileInput' })
  await cdp('DOM.setFileInputFiles', { nodeId: fileNode.nodeId, files: [pngPath] })
  await waitFor('document.querySelectorAll("#pendingImages .pending-image").length === 1', 'pending image chip', 8000)
  await screenshot('12-attach.png')
  await evaluate('document.getElementById("sendBtn").click()')
  await waitFor('document.querySelectorAll(".item.image").length >= 2', 'optimistic image bubble', 8000)
  await screenshot('13-image-sent.png')

  // ── 11. terminal panel ─────────────────────────────────────────────
  await evaluate('document.getElementById("menuBtn").click()')
  await waitFor('!document.getElementById("drawer").hidden', 'drawer open for terminal')
  await sleep(250)
  await evaluate('document.getElementById("terminalLink").click()')
  await waitFor('document.getElementById("terminalOut").textContent.includes("mock bash")', 'terminal opened', 8000)
  // The mock returns real VT sequences; the panel renders into a <pre>, so none
  // of them may survive into the text.
  assert(await evaluate('!/[\\u001b\\u0007]/.test(document.getElementById("terminalOut").textContent)'), 'terminal output has no control characters')
  assert(await evaluate('!/\\[[0-9;?]*[A-Za-z]/.test(document.getElementById("terminalOut").textContent)'), 'terminal output has no escape remnants')
  assert(await evaluate('document.getElementById("terminalOut").textContent.includes("mock bash — terminal output")'), 'terminal keeps the readable output')
  await evaluate(`
    (function () {
      var input = document.getElementById('terminalInput')
      input.value = 'ls -la'
      input.dispatchEvent(new Event('input', { bubbles: true }))
      document.getElementById('terminalSend').click()
    })()
  `)
  await sleep(400)
  await screenshot('14-terminal.png')
  await evaluate('document.getElementById("terminalBack").click()')
  await waitFor('document.getElementById("terminalPanel").hidden === true', 'terminal closed')

  // ── 12. narrow-phone layout (360x640) ───────────────────────────────
  await cdp('Emulation.setDeviceMetricsOverride', {
    width: 360, height: 640, deviceScaleFactor: 2, mobile: true,
  })
  await sleep(300)
  await evaluate('document.getElementById("stream").scrollTop = document.getElementById("stream").scrollHeight')
  await sleep(200)
  assert(await evaluate('document.getElementById("input").getBoundingClientRect().bottom <= window.innerHeight + 1'), 'composer stays on screen at 360x640')
  assert(await evaluate('Math.abs(parseFloat(document.getElementById("app").style.height) - window.innerHeight) <= 1'), 'app fills the layout viewport while the input is idle')
  // With no keyboard (the mock page has none) the app covers the layout viewport
  // and no bottom padding is added. It is absolutely positioned at the current
  // scroll offset so iOS's page scroll cannot carry it away. The keyboard branch
  // needs a real visual viewport, which the CDP harness cannot fake, so it is
  // covered by the device diagnostics instead.
  assert(await evaluate('document.getElementById("app").style.position === "absolute"'), 'app tracks the document scroll instead of the viewport')
  assert(await evaluate('document.getElementById("app").style.paddingBottom === ""'), 'no keyboard padding without a keyboard')
  await screenshot('09-small.png')

  // ── 13. project grouping, row actions and fork ──────────────────────
  await cdp('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true })
  await evaluate('document.getElementById("menuBtn").click()')
  await waitFor('!document.getElementById("drawer").hidden', 'drawer open for projects')
  await sleep(250)

  // collapse / expand the first project
  const expandedRows = await evaluate('document.querySelectorAll("#sessions .session").length')
  await evaluate('document.querySelector("#sessions .session-group-head").click()')
  const collapsedRows = await evaluate('document.querySelectorAll("#sessions .session").length')
  assert(collapsedRows < expandedRows, 'collapsing a project hides its sessions')
  await evaluate('document.querySelector("#sessions .session-group-head").click()')
  assert(await evaluate('document.querySelectorAll("#sessions .session").length === ' + expandedRows), 'expanding restores them')

  // rename the second session from its row menu
  await evaluate('document.querySelectorAll("#sessions .session")[1].querySelector(".s-actions").click()')
  await waitFor('!document.getElementById("actionSheet").hidden', 'row action sheet')
  assert(await evaluate('document.body.innerText.includes("分叉会话")'), 'row actions include fork')
  await sleep(320) // let sheetUp finish, so the screenshot is fully opaque
  await screenshot('16-row-actions.png')
  await evaluate(`document.querySelector('[data-action="rename"]').click()`)
  await waitFor('!document.getElementById("modal").hidden', 'rename prompt')
  await evaluate(`(function () {
    var input = document.querySelector('#modalBody .prompt-input')
    input.value = 'renamed-by-test'
  })()`)
  await evaluate('document.getElementById("modalOk").click()')
  await waitFor('document.body.innerText.includes("renamed-by-test")', 'renamed row', 6000)

  // fork the conversation from that row, then from a specific message
  await evaluate('document.querySelectorAll("#sessions .session")[1].querySelector(".s-actions").click()')
  await waitFor('!document.getElementById("actionSheet").hidden', 'row action sheet again')
  await evaluate(`document.querySelector('[data-action="fork"]').click()`)
  await waitFor('document.getElementById("sessionTitle").textContent.includes("分支")', 'forked session opened', 8000)
  assert(await evaluate('document.querySelector("#sessions .s-fork") !== null'), 'fork badge shown in the session list')
  await screenshot('17-forked.png')

  // back to the main session, then fork from one specific message
  await evaluate('document.getElementById("menuBtn").click()')
  await waitFor('!document.getElementById("drawer").hidden', 'drawer open for message fork')
  await sleep(200)
  await evaluate(`(function () {
    var rows = document.querySelectorAll('#sessions .session')
    for (var i = 0; i < rows.length; i += 1) {
      if (rows[i].textContent.includes('把手机页做出来')) { rows[i].click(); return }
    }
  })()`)
  await waitFor('document.querySelectorAll(".item.user").length >= 1', 'main transcript back', 8000)
  await evaluate(`(function () {
    var item = document.querySelector('.item.user')
    item.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true }))
  })()`)
  await waitFor('!document.getElementById("actionSheet").hidden', 'message action sheet')
  await sleep(320)
  assert(await evaluate('document.body.innerText.includes("从此处分叉")'), 'message actions include fork-at-point')
  await screenshot('18-message-actions.png')
  await evaluate(`document.querySelector('[data-action="fork-here"]').click()`)
  await waitFor('document.getElementById("sessionTitle").textContent.includes("分支")', 'message fork opened', 8000)

  assert(consoleErrors.length === 0, 'no console errors or uncaught exceptions: ' + JSON.stringify(consoleErrors))

  console.log('\nALL MOBILE UI CHECKS PASSED')
} catch (error) {
  failed = true
  console.error('\nMOBILE UI CHECK FAILED:', error.message)
  if (consoleErrors.length) console.error('console errors:', consoleErrors)
  try { await screenshot('99-failure.png') } catch {}
} finally {
  ws.close()
  if (!args.includes('--keep')) {
    chrome.child.kill('SIGKILL')
    server.close()
  }
  process.exit(failed ? 1 : 0)
}
