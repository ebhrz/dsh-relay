// Terminal delta reads: the panel polls once a second and used to re-send the
// last 300 lines every time. slimTerminal must send only the new lines, and must
// fall back to a full snapshot whenever the gap cannot be expressed.
//
// Pure logic against a bare object; no bridge instance, no terminals.

import assert from 'node:assert/strict'
import { MobileBridge } from '../src/mobile/bridge.js'

const bridge = { terminalCursors: new Map(), slimTerminal: MobileBridge.prototype.slimTerminal }
const read = (fresh) => bridge.slimTerminal('s:1', fresh)

// First read: everything, page replaces its buffer.
let out = read({ text: 'a\nb\nc', totalLines: 3, lineBegin: 0, lineEnd: 3, truncated: false })
assert.equal(out.appended, false)
assert.equal(out.text, 'a\nb\nc')

// Nothing new: empty payload, still "appended" so the page keeps its buffer.
out = read({ text: 'a\nb\nc', totalLines: 3, lineBegin: 0, lineEnd: 3, truncated: false })
assert.equal(out.appended, true)
assert.equal(out.text, '')

// Two new lines arrive inside the same 300-line window.
out = read({ text: 'a\nb\nc\nd\ne', totalLines: 5, lineBegin: 0, lineEnd: 5, truncated: false })
assert.equal(out.appended, true)
assert.equal(out.text, 'd\ne')

// The window scrolled: only the part the page has not seen survives.
out = read({ text: 'd\ne\nf', totalLines: 6, lineBegin: 3, lineEnd: 6, truncated: false })
assert.equal(out.appended, true)
assert.equal(out.text, 'f')

// A jump in lineBegin means the ring buffer dropped lines the page never saw:
// send a full snapshot instead of hiding the gap.
out = read({ text: 'x\ny', totalLines: 50, lineBegin: 48, lineEnd: 50, truncated: true })
assert.equal(out.appended, false)
assert.equal(out.text, 'x\ny')

// reset starts over
bridge.terminalCursors.delete('s:1')
out = read({ text: 'fresh', totalLines: 51, lineBegin: 50, lineEnd: 51, truncated: false })
assert.equal(out.appended, false)
assert.equal(out.text, 'fresh')

// Cursors are per terminal, so two terminals do not steal each other's delta.
assert.equal(bridge.slimTerminal('s:2', { text: 'one', totalLines: 1, lineBegin: 0, lineEnd: 1 }).appended, false)
assert.equal(bridge.slimTerminal('s:1', { text: 'fresh2', totalLines: 52, lineBegin: 51, lineEnd: 52 }).text, 'fresh2')

console.log('ok: terminal delta reads')
