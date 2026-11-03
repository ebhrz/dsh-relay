#!/usr/bin/env node
// Unit-level checks for the injected mobile patch: run a synthetic DSH-style
// response through injectBootScript and assert on the product. No live relay
// needed (unlike test-sealed.mjs et al.).
import assert from 'node:assert/strict'
import { injectBootScript } from '../src/pump.js'
import { MOBILE_JS } from '../src/mobile-patch.js'
import { enhanceViewportMeta } from '../src/mobile-patch.js'

const relay = { id: 'TESTDEV1', gate: 'a'.repeat(32) }

const sample = Buffer.from(
  'HTTP/1.1 200 OK\r\n' +
  'content-type: text/html; charset=utf-8\r\n' +
  'content-length: 999\r\n' +
  '\r\n' +
  '<!doctype html>\n<html lang="en">\n<head>\n' +
  '<meta charset="utf-8" />\n' +
  '<meta name="viewport" content="width=device-width, initial-scale=1" />\n' +
  '<link rel="manifest" href="/manifest.webmanifest" />\n' +
  '<script type="module" src="/src/main.ts"></script>\n' +
  '</head>\n<body>\n<div id="root"></div>\n</body>\n</html>\n',
  'latin1',
)

// --- 1. boot + mobile patch ride together ------------------------------------
const out = injectBootScript(sample, relay).toString('latin1')
assert.ok(out.includes('__dshRelayBoot'), 'boot script injected')
assert.ok(out.includes('id="__dshr_mobile"'), 'mobile style injected')
assert.ok(out.includes('__dshRelayMobile'), 'mobile script injected')

// head rewrite: the stale upstream length is replaced with the injected length
{
  const split = out.indexOf('\r\n\r\n')
  const head = out.slice(0, split)
  const body = out.slice(split + 4)
  const match = /\r\ncontent-length:\s*(\d+)/i.exec(head)
  assert.ok(match, 'content-length restated')
  assert.equal(Number(match[1]), Buffer.byteLength(body, 'latin1'), 'content-length matches injected body')
}

// --- 2. viewport meta enhancement --------------------------------------------
const vp = /<meta\s+name="viewport"\s+content="([^"]*)"/.exec(out)?.[1] ?? ''
assert.ok(vp.includes('width=device-width'), 'original keys kept')
assert.ok(vp.includes('viewport-fit=cover'), 'viewport-fit added')
assert.ok(vp.includes('interactive-widget=resizes-content'), 'interactive-widget added')

// idempotent: a second pass does not duplicate keys
const once = enhanceViewportMeta('<meta name="viewport" content="' + vp + '">')
assert.equal((once.match(/viewport-fit=/g) ?? []).length, 1, 'no duplicate viewport-fit')
assert.equal((once.match(/interactive-widget=/g) ?? []).length, 1, 'no duplicate interactive-widget')

// no viewport meta at all → untouched
assert.equal(enhanceViewportMeta('<html><head></head></html>'), '<html><head></head></html>')

// --- 3. asset rewriting still intact alongside the patch ----------------------
// The manifest link is stripped on purpose: a cookie-less manifest fetch would
// hit the ticket gate and be parsed as JSON by the browser.
assert.equal(/rel=(["'])manifest\1/i.test(out), false, 'manifest link dropped')
assert.ok(out.includes(`src="/c/${relay.id}/src/main.ts?g=${relay.gate}"`), 'root-absolute src rewritten with gate')

// --- 4. injection point: payload sits right after <head>, before content ------
const headIdx = out.indexOf('<head>')
const bootStart = out.indexOf('<script>', headIdx)
assert.ok(bootStart !== -1 && bootStart < out.indexOf('<meta charset'), 'injection precedes document content')

// --- 5. the injected JS must not break out of its <script> element -----------
assert.ok(!MOBILE_JS.includes('</scr' + 'ipt'), 'no closing-script sequence inside MOBILE_JS')

// --- 6. headless document (no <head>) gets the payload prepended -------------
const bare = Buffer.from('HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n<p>hi</p>', 'latin1')
const bareOut = injectBootScript(bare, relay).toString('latin1')
assert.ok(bareOut.includes('__dshRelayBoot') && bareOut.includes('__dshr_mobile'), 'headless document still patched')
assert.ok(bareOut.endsWith('<p>hi</p>'), 'body preserved after payload')

console.log('all mobile patch injection checks passed')
