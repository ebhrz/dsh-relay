// Locate and launch a Chromium-family browser with the DevTools protocol on.
//
// The test/probe scripts only need "a headless Chrome with CDP on a given
// port". Keeping the lookup here means one place to teach about a new platform
// or a non-standard install.
//
// Resolution order: CHROME_BIN, then the platform's usual install paths, then
// the executable names on PATH.

import { spawn, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const byPlatform = {
  win32: [
    `${process.env.ProgramFiles}\\Google\\Chrome\\Application\\chrome.exe`,
    `${process.env['ProgramFiles(x86)']}\\Google\\Chrome\\Application\\chrome.exe`,
    `${process.env.LOCALAPPDATA}\\Google\\Chrome\\Application\\chrome.exe`,
    `${process.env.ProgramFiles}\\Microsoft\\Edge\\Application\\msedge.exe`,
    `${process.env['ProgramFiles(x86)']}\\Microsoft\\Edge\\Application\\msedge.exe`,
  ],
  darwin: [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  ],
  linux: ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'microsoft-edge'],
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

// Extra flags for a single run, e.g. CHROME_ARGS=--force-dark-mode to check the
// night palette without touching the test.
const envArgs = () => (process.env.CHROME_ARGS ?? '').split(/\s+/).filter(Boolean)

/** Absolute path of a usable browser, or null when none is installed. */
export function resolveChromeBinary() {
  const fromEnv = process.env.CHROME_BIN
  if (fromEnv) return fs.existsSync(fromEnv) ? fromEnv : null
  for (const candidate of byPlatform[process.platform] ?? byPlatform.linux) {
    if (!candidate) continue
    if (candidate.includes('/') || candidate.includes('\\')) {
      if (fs.existsSync(candidate)) return candidate
      continue
    }
    // A bare name: ask the shell whether it resolves.
    const probe = spawnSync(candidate, ['--version'], { stdio: 'ignore' })
    if (probe.status === 0) return candidate
  }
  return null
}

/**
 * Launch the browser headless with CDP enabled.
 * @returns {{child: import('node:child_process').ChildProcess, port: number, profileDir: string}|null}
 *   null when no browser is installed.
 */
export function launchChrome({ port, profileDir, extraArgs = [] } = {}) {
  const binary = resolveChromeBinary()
  if (!binary) return null
  const cdpPort = port ?? 9300 + Math.floor(Math.random() * 600)
  const profile = profileDir ?? fs.mkdtempSync(path.join(os.tmpdir(), 'relay-chrome-'))
  fs.mkdirSync(profile, { recursive: true })
  const child = spawn(binary, [
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
    '--hide-scrollbars',
    `--remote-debugging-port=${cdpPort}`,
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    ...envArgs(),
    ...extraArgs,
    'about:blank',
  ], { stdio: 'ignore' })
  child.unref()
  return { child, port: cdpPort, profileDir: profile }
}

/** WebSocket debugger URL of the first page target (null on timeout). */
export async function pageTargetWsUrl(port, { tries = 60, delayMs = 200 } = {}) {
  for (let attempt = 0; attempt < tries; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`)
      const targets = await response.json()
      const page = targets.find((target) => target.type === 'page')
      if (page?.webSocketDebuggerUrl) return page.webSocketDebuggerUrl
    } catch {}
    await sleep(delayMs)
  }
  return null
}
