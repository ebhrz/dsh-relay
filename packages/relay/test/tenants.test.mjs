// Tenant registry: keys are derived, quota is per UTC day, and a crossing must
// be reported exactly once so the relay can cut a connection a single time.
//
// Pure filesystem + crypto; no relay process and no network.

import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  DEFAULT_MAX_STREAMS,
  DEFAULT_QUOTA_BYTES,
  TenantStore,
  formatBytes,
  keyIdFor,
  legacySecretFor,
  parseQuota,
  quotaDay,
  secretFor,
} from '../src/tenants.js'

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-tenants-'))
const file = path.join(dir, 'tenants.json')
const cleanup = () => fs.rmSync(dir, { recursive: true, force: true })

try {
  // ── quota parsing ────────────────────────────────────────────────────
  assert.equal(parseQuota('100MB'), 100 * 1024 * 1024)
  assert.equal(parseQuota('1.5 GB'), Math.round(1.5 * 1024 ** 3))
  assert.equal(parseQuota('2048'), 2048)
  assert.equal(parseQuota('2048 kb'), 2048 * 1024)
  assert.equal(parseQuota('0'), null)
  assert.equal(parseQuota('nope'), null)
  assert.equal(formatBytes(100 * 1024 * 1024), '100.0 MB')

  // ── key derivation: what the agent sends and what the relay stores ───
  const key = 'a'.repeat(48)
  assert.equal(keyIdFor(key).length, 12)
  // Version 2 exists so the id reveals nothing about the secret: the id is
  // sha256(key)[0..12] and the secret is derived from a different prefix.
  assert.notEqual(keyIdFor(key), secretFor(key).slice(0, 12))
  assert.equal(legacySecretFor(key), crypto.createHash('sha256').update(key).digest('hex'))
  assert.equal(legacySecretFor(key).slice(0, 12), keyIdFor(key), 'v1 leaked the first 48 bits; v2 must not')
  assert.notEqual(secretFor(key), legacySecretFor(key))
  assert.notEqual(keyIdFor(key), keyIdFor(`${key}b`))

  // ── create / resolve ────────────────────────────────────────────────
  const store = new TenantStore(file)
  const { tenant, key: aliceKey } = store.add({ name: 'alice', quotaBytesDay: 100 * 1024 * 1024 })
  assert.equal(tenant.id, 'alice')
  assert.equal(tenant.status, 'active')
  assert.equal(tenant.usedBytesDay, 0)
  assert.equal(tenant.day, quotaDay())
  assert.equal(tenant.keyId, keyIdFor(aliceKey))
  assert.equal(tenant.secret, secretFor(aliceKey))
  assert.ok(!JSON.stringify(store.list()).includes(aliceKey), 'the plaintext key must never be stored')

  assert.throws(() => store.add({ name: 'alice' }), /already exists/)
  assert.throws(() => store.add({ name: 'x' }), /2-32 chars/)

  assert.equal(store.byKeyId(tenant.keyId).id, 'alice')
  assert.equal(store.byKeyId('000000000000'), null)
  assert.equal(store.resolve('alice').id, 'alice')
  assert.equal(store.resolve(tenant.keyId).id, 'alice')

  // ── quota accounting ────────────────────────────────────────────────
  assert.equal(store.blocked(tenant), null)
  let result = store.charge(tenant, 60 * 1024 * 1024)
  assert.equal(result.over, false)
  assert.equal(tenant.usedBytesDay, 60 * 1024 * 1024)
  result = store.charge(tenant, 50 * 1024 * 1024)
  assert.equal(result.over, true, 'crossing the limit must be reported')
  assert.equal(store.blocked(tenant), 'quota-exceeded')

  // A new day gives the quota back without an explicit reset.
  tenant.day = '2000-01-01'
  assert.equal(store.blocked(tenant), null, 'a stale day is not enforced')
  store.charge(tenant, 1)
  assert.equal(tenant.usedBytesDay, 1, 'the first byte of a new day resets the counter')
  assert.equal(tenant.day, quotaDay())

  // ── admin actions ───────────────────────────────────────────────────
  store.setStatus('alice', 'disabled')
  assert.equal(store.blocked(tenant), 'key-disabled')
  store.setStatus('alice', 'active')
  assert.equal(store.blocked(tenant), null)

  store.charge(tenant, 1000)
  assert.ok(tenant.usedBytesDay > 0)
  store.reset('alice')
  assert.equal(tenant.usedBytesDay, 0)

  // ── persistence round trip ──────────────────────────────────────────
  store.save()
  const reloaded = new TenantStore(file)
  const again = reloaded.get('alice')
  assert.ok(again, 'tenant survives a reload')
  assert.equal(again.keyId, tenant.keyId)
  assert.equal(again.secret, tenant.secret)
  assert.equal(again.quotaBytesDay, tenant.quotaBytesDay)
  assert.equal(reloaded.byKeyId(tenant.keyId).id, 'alice')

  // ── defaults ────────────────────────────────────────────────────────
  const defaults = new TenantStore(path.join(dir, 'default.json'))
  assert.equal(defaults.add({ name: 'bob' }).tenant.quotaBytesDay, DEFAULT_QUOTA_BYTES)
  assert.equal(defaults.get('bob').maxStreams, DEFAULT_MAX_STREAMS, 'a new tenant gets the stream cap')

  // ── configurable limits ─────────────────────────────────────────────
  // 0 means unlimited on both axes, which is how the owner runs their own key.
  const own = defaults.add({ name: 'owner', quotaBytesDay: 0, maxStreams: 0 }).tenant
  assert.equal(own.maxStreams, 0)
  assert.equal(own.quotaBytesDay, 0)
  assert.equal(defaults.blocked(own), null, 'unlimited tenants are never blocked by quota')
  defaults.charge(own, 10 * 1024 * 1024 * 1024)
  assert.equal(defaults.blocked(own), null, 'an unlimited tenant stays usable')
  defaults.setLimits('owner', { maxStreams: 5 })
  assert.equal(defaults.get('owner').maxStreams, 5)
  assert.equal(defaults.get('owner').quotaBytesDay, 0, 'setLimits leaves the untouched field alone')

  // ── the stream cap survives a reload and a CLI edit ─────────────────
  const capped = new TenantStore(path.join(dir, 'default.json'))
  assert.equal(capped.get('owner').maxStreams, 5)
  capped.setLimits('owner', { maxStreams: 9 })
  assert.equal(capped.reloadIfChanged(), false, 'our own write is not a foreign change')

  // ── unknown keys must not resolve ───────────────────────────────────
  assert.equal(reloaded.byKeyId(keyIdFor('not-a-tenant')), null)

  // ── a running server picks up CLI edits ─────────────────────────────
  // The CLI writes the same file the server holds in memory, so a reload must
  // merge rather than replace (live connections keep their tenant object).
  const live = new TenantStore(file)
  const liveTenant = live.get('alice')
  live.charge(liveTenant, 500)
  const cli = new TenantStore(file)
  assert.equal(live.reloadIfChanged(), false, 'nothing changed yet')
  cli.setStatus('alice', 'disabled')
  assert.equal(live.reloadIfChanged(), true, 'the edit is noticed')
  assert.equal(live.get('alice'), liveTenant, 'the live object is kept')
  assert.equal(liveTenant.status, 'disabled')
  assert.equal(liveTenant.usedBytesDay, 500, 'bytes charged in memory survive the merge')

  fs.rmSync(file)
  assert.equal(live.reloadIfChanged(), false, 'a missing file is not an error')

  // ── a second writer must not lose the first one's changes ────────────
  // The relay, the CLI and the demo's dispenser all write this file. A save that
  // overwrites a newer file loses keys that were just handed out, and can undo a
  // `disable`.
  {
    const path2 = path.join(dir, 'shared.json')
    const processA = new TenantStore(path2)
    processA.add({ name: 'alice' })
    const processB = new TenantStore(path2) // loaded before the next write
    const guest = processA.add({ name: 'guest-abc' })
    processB.setStatus('alice', 'disabled')
    const merged = new TenantStore(path2)
    assert.ok(merged.get('guest-abc'), "B's save did not erase the key A just created")
    assert.equal(merged.get('guest-abc').keyId, guest.tenant.keyId)
    assert.equal(merged.get('alice').status, 'disabled', "A's later save did not undo B's disable")
  }

  // ── an explicit reset is not merged away ─────────────────────────────
  {
    const path3 = path.join(dir, 'reset.json')
    const relay = new TenantStore(path3)
    const created = relay.add({ name: 'carol', quotaBytesDay: 1000 })
    relay.charge(created.tenant, 900)
    const cli = new TenantStore(path3)
    cli.reset('carol')
    relay.reloadIfChanged()
    assert.equal(relay.get('carol').usedBytesDay, 0, 'the reset reached the running relay')
    assert.equal(relay.get('carol').resetSeq, 1, 'and its sequence advanced')
    // A second reset keeps working even after the relay charged more.
    relay.charge(relay.get('carol'), 500)
    const cli2 = new TenantStore(path3)
    cli2.reset('carol')
    relay.reloadIfChanged()
    assert.equal(relay.get('carol').usedBytesDay, 0, 'resets stay effective')
  }

  // ── a record without identity is refused, not defaulted ──────────────
  {
    const path4 = path.join(dir, 'broken.json')
    fs.writeFileSync(path4, JSON.stringify({
      version: 1,
      tenants: [
        { id: 'ok1', keyId: 'abcdabcdabcd', secret: 'f'.repeat(64) },
        { secret: 'e'.repeat(64) },
      ],
    }))
    const store = new TenantStore(path4)
    assert.ok(store.get('ok1'), 'the good record loads')
    assert.equal(store.list().length, 1, 'the record without an id is skipped')
  }

  console.log('ok: tenant registry')
} finally {
  cleanup()
}
