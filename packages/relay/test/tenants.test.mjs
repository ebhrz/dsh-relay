// Tenant registry: keys are derived, quota is per UTC day, and a crossing must
// be reported exactly once so the relay can cut a connection a single time.
//
// Pure filesystem + crypto; no relay process and no network.

import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  DEFAULT_QUOTA_BYTES,
  TenantStore,
  formatBytes,
  keyIdFor,
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
  assert.equal(keyIdFor(key), secretFor(key).slice(0, 12))
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

  console.log('ok: tenant registry')
} finally {
  cleanup()
}
