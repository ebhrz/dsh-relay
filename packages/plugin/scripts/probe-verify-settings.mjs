#!/usr/bin/env node
// Check whether the relay-booted page treats settings RPCs as loopback-trusted:
// load the entry URL in headless Chrome, then evaluate in-page that the
// settings.describe request actually went out and came back 200.
//
//   node scripts/probe-verify-settings.mjs "<entry url>"
//
// The entry URL is the one the panel shows (…/c/<device>/m?g=…#k=…).

import { WebSocket } from 'ws'
import { launchChrome, pageTargetWsUrl } from './lib/chrome.mjs'

const URL_STRING = process.argv[2]
if (!URL_STRING) {
  console.error('usage: node scripts/probe-verify-settings.mjs "<entry url>"')
  process.exit(2)
}

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
  }
})

await send('Runtime.enable')
await send('Page.enable')
await send('Page.navigate', { url: URL_STRING })
await sleep(15000)

const evaluate = async (expression) => {
  const result = await send('Runtime.evaluate', { expression, returnByValue: true })
  return result?.result?.value
}

const report = await evaluate(`(() => {
  const entries = performance.getEntriesByType('resource')
  const api = entries.filter((entry) => entry.name.includes('/api/')).map((entry) =>
    entry.name.replace(/^https?:\\/\\/[^/]+/, '').split('?')[0].slice(0, 60) + ' ' + (entry.responseStatus ?? '?'))
  const picker = entries.filter((entry) => entry.name.includes('directory-picker')).map((entry) =>
    entry.name.split('/').slice(-2).join('/').slice(0, 60) + ' ' + (entry.responseStatus ?? '?'))
  return JSON.stringify({
    relayBoot: !!window.__dshRelayBoot,
    rootLen: document.getElementById('root')?.innerHTML.length ?? 0,
    api, picker,
  })
})()`)
console.log(report ?? 'eval failed')

chrome.child.kill('SIGKILL')
process.exit(0)
