#!/usr/bin/env node
// Ad-hoc CDP probe: load a URL, run sequential page-side steps, print results.
//
//   node scripts/cdp-probe.mjs "<url>" '[{"wait":1000},{"eval":"location.href"}]'
//
// Supported steps: {wait:ms}, {eval:"expr", label?}, {key:"Escape"},
// {ime:"text"} (active IME composition), {insertText:"text"}, {screenshot:"x.png"}.

import { WebSocket } from 'ws'
import { launchChrome, pageTargetWsUrl } from './lib/chrome.mjs'

const [URL_STRING, STEPS_JSON] = process.argv.slice(2)
if (!URL_STRING || !STEPS_JSON) {
  console.error('usage: node scripts/cdp-probe.mjs "<url>" \'[{"eval":"1+1"}]\'')
  process.exit(2)
}
const steps = JSON.parse(STEPS_JSON)

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

const chrome = launchChrome({ extraArgs: ['--window-size=1440,900'] })
if (!chrome) {
  console.error('no Chrome/Chromium found (set CHROME_BIN)')
  process.exit(2)
}
const wsUrl = await pageTargetWsUrl(chrome.port, { tries: 40, delayMs: 300 })
if (!wsUrl) {
  chrome.child.kill('SIGKILL')
  console.error('chrome devtools not reachable')
  process.exit(1)
}

const ws = new WebSocket(wsUrl)
await new Promise((resolve) => ws.once('open', resolve))

let id = 0
const pending = new Map()
ws.on('message', (data) => {
  const message = JSON.parse(data.toString())
  if (message.id && pending.has(message.id)) {
    pending.get(message.id)(message.result)
    pending.delete(message.id)
    return
  }
  if (message.method === 'Runtime.consoleAPICalled' && ['warning', 'error'].includes(message.params.type)) {
    console.log(`[console.${message.params.type}]`,
      message.params.args.map((arg) => arg.value ?? arg.description ?? '').join(' ').slice(0, 200))
  }
})
const send = (method, params = {}) => {
  const messageId = ++id
  ws.send(JSON.stringify({ id: messageId, method, params }))
  return new Promise((resolve) => pending.set(messageId, resolve))
}
const evaluate = async (expression) => {
  const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
  if (result?.exceptionDetails) {
    return 'EVAL-ERROR: '
      + JSON.stringify(result.exceptionDetails.exception?.description ?? result.exceptionDetails).slice(0, 300)
  }
  return result?.result?.value
}

await send('Runtime.enable')
await send('Page.enable')
await send('Input.enable')
await send('Page.navigate', { url: URL_STRING })
await sleep(11000)

for (const step of steps) {
  if (step.wait) {
    await sleep(step.wait)
    continue
  }
  if (step.ime !== undefined) {
    // Set an active IME composition in the focused textarea, like a phone
    // pinyin keyboard mid-composition.
    await send('Input.imeSetComposition', {
      text: step.ime,
      selectionStart: step.ime.length,
      selectionEnd: step.ime.length,
      replacementStart: 0,
      replacementEnd: 0,
    })
    continue
  }
  if (step.insertText !== undefined) {
    // Commit text like an IME commit (composition end).
    await send('Input.insertText', { text: step.insertText })
    continue
  }
  if (step.key !== undefined) {
    await send('Input.dispatchKeyEvent', {
      type: 'keyDown',
      key: step.key,
      text: step.key.length === 1 ? step.key : undefined,
    })
    await send('Input.dispatchKeyEvent', { type: 'keyUp', key: step.key })
    continue
  }
  if (step.eval) {
    const value = await evaluate(step.eval)
    console.log(step.label ? `${step.label}: ` : '',
      typeof value === 'string' ? value : JSON.stringify(value))
  }
  if (step.screenshot) {
    const shot = await send('Page.captureScreenshot', { format: 'png' })
    const { writeFileSync } = await import('node:fs')
    writeFileSync(step.screenshot, Buffer.from(shot.data, 'base64'))
    console.log(`screenshot: ${step.screenshot}`)
  }
}
chrome.child.kill('SIGKILL')
process.exit(0)
