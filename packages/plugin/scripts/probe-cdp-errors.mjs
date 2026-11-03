#!/usr/bin/env node
// Page error capture: load the entry URL in headless Chrome and print every
// console error/exception and failed network request.
//
//   node scripts/probe-cdp-errors.mjs "<entry url>" [seconds]

import { WebSocket } from 'ws'
import { launchChrome, pageTargetWsUrl } from './lib/chrome.mjs'

const URL_STRING = process.argv[2]
if (!URL_STRING) {
  console.error('usage: node scripts/probe-cdp-errors.mjs "<entry url>" [seconds]')
  process.exit(2)
}
const SETTLE_MS = Number(process.argv[3] ?? 12) * 1000

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

const chrome = launchChrome()
if (!chrome) {
  console.error('no Chrome/Chromium found (set CHROME_BIN)')
  process.exit(2)
}
const wsUrl = await pageTargetWsUrl(chrome.port)
if (!wsUrl) {
  chrome.child.kill('SIGKILL')
  console.error('chrome devtools not reachable')
  process.exit(1)
}

const ws = new WebSocket(wsUrl)
await new Promise((resolve) => ws.once('open', resolve))

let id = 0
const pending = new Map()
function send(method, params = {}) {
  const messageId = ++id
  ws.send(JSON.stringify({ id: messageId, method, params }))
  return new Promise((resolve) => pending.set(messageId, resolve))
}

ws.on('message', (data) => {
  const message = JSON.parse(data.toString())
  if (message.id && pending.has(message.id)) {
    pending.get(message.id)(message.result)
    pending.delete(message.id)
    return
  }
  if (message.method === 'Runtime.exceptionThrown') {
    const detail = message.params.exceptionDetails
    console.log('[exception]', detail.text, detail.exception?.description?.slice(0, 300) ?? '')
  } else if (message.method === 'Runtime.consoleAPICalled'
    && (message.params.type === 'error' || message.params.type === 'warning')) {
    console.log(`[console.${message.params.type}]`,
      message.params.args.map((arg) => arg.value ?? arg.description ?? '').join(' ').slice(0, 300))
  } else if (message.method === 'Log.entryAdded' && ['error', 'warning'].includes(message.params.entry.level)) {
    console.log(`[log.${message.params.entry.level}]`, message.params.entry.source,
      message.params.entry.text.slice(0, 300), message.params.entry.url ?? '')
  } else if (message.method === 'Network.loadingFailed') {
    console.log('[net-failed]', message.params.errorText, message.params.type, message.params.requestId)
  }
})

await send('Runtime.enable')
await send('Log.enable')
await send('Page.enable')
await send('Network.enable')
await send('Page.navigate', { url: URL_STRING })
await sleep(SETTLE_MS)
chrome.child.kill('SIGKILL')
process.exit(0)
