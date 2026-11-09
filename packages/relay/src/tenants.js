// Tenant registry: one relay key per user, a daily byte quota, and the state the
// relay needs to enforce both.
//
// Only a hash of each key is stored. The plaintext key exists exactly once: in
// the output of `tenant add`. Anyone with the relay's disk therefore learns who
// exists and how much they used, never how to connect as them.
//
// The quota window is the UTC day, matching the "N MB per day" a tenant is told.

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const STALE_LOCK_MS = 10_000 // a lock older than this is from a writer that died
export const DEFAULT_QUOTA_BYTES = 50 * 1024 * 1024
// A phone page holds a handful of connections at once (assets, API calls, the
// mux WebSocket) and a browser may open six per origin; 32 leaves room for a
// second tab without letting one tenant fill the process with sockets.
export const DEFAULT_MAX_STREAMS = 32

/** Public identifier of a key: what the agent sends in `hello`. */
export function keyIdFor(key) {
  return hashKey(key).slice(0, 12)
}

/**
 * The HMAC secret both sides derive from the key, version 2.
 *
 * Version 1 used `sha256(key)` for the secret and its first 48 bits as the key
 * id, so anyone who learned a key id knew part of the secret - and key ids are
 * printed by `tenant list` and sent in every hello. Version 2 domain-separates
 * the two: the id stays `sha256(key)[0..12]`, the secret becomes
 * `sha256('dsh-relay:hmac:v2:' + key)`.
 */
export function secretFor(key) {
  return crypto.createHash('sha256').update(`dsh-relay:hmac:v2:${String(key)}`).digest('hex')
}

/** The version-1 secret, kept so a client that has not updated still works. */
export function legacySecretFor(key) {
  return hashKey(key)
}

function hashKey(key) {
  return crypto.createHash('sha256').update(String(key)).digest('hex')
}

/** 48 hex characters, same shape the hand-written --key always had. */
export function newKey() {
  return crypto.randomBytes(24).toString('hex')
}

export function quotaDay(now = Date.now()) {
  return new Date(now).toISOString().slice(0, 10)
}

/** "100MB", "1.5 GB", "2048" -> bytes. */
export function parseQuota(text) {
  const match = /^\s*(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?\s*$/i.exec(String(text))
  if (!match) return null
  const value = Number(match[1])
  const unit = (match[2] ?? 'b').toLowerCase()
  const scale = unit === 'gb' ? 1024 ** 3 : unit === 'mb' ? 1024 ** 2 : unit === 'kb' ? 1024 : 1
  const bytes = Math.round(value * scale)
  return Number.isFinite(bytes) && bytes > 0 ? bytes : null
}

export function formatBytes(bytes) {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GB`
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KB`
  return `${bytes} B`
}

export class TenantStore {
  constructor(file, { quotaDefault = DEFAULT_QUOTA_BYTES, maxStreamsDefault = DEFAULT_MAX_STREAMS } = {}) {
    this.file = file
    this.quotaDefault = quotaDefault
    this.maxStreamsDefault = maxStreamsDefault
    this.tenants = new Map() // name -> tenant
    this.dirty = false
    this.mtimeMs = 0
    this.load()
  }

  load() {
    const raw = (() => {
      try {
        return JSON.parse(fs.readFileSync(this.file, 'utf8'))
      } catch (error) {
        if (error.code !== 'ENOENT') console.error(`tenant store: ${error.message}`)
        return null
      }
    })()
    if (!raw) return
    for (const tenant of raw.tenants ?? []) {
      // One corrupt record must not take the whole registry with it: skip it, say
      // so, and let every other tenant keep working.
      try {
        this.tenants.set(tenant.id, normalize(tenant, this.quotaDefault, this.maxStreamsDefault))
      } catch (error) {
        console.error(`tenant store: skipping record: ${error.message}`)
      }
    }
    this.mtimeMs = this.statMtime()
  }

  statMtime() {
    try {
      return fs.statSync(this.file).mtimeMs
    } catch {
      return 0
    }
  }

  /**
   * Pick up `tenant add`/`disable`/`reset` made by the CLI while the server is
   * running. Objects are merged in place because live connections hold a
   * reference to their tenant; replacing the map would orphan them.
   */
  reloadIfChanged(force = false) {
    const mtimeMs = this.statMtime()
    if (!mtimeMs) return false
    if (!force && mtimeMs === this.mtimeMs) return false
    this.mtimeMs = mtimeMs
    let raw
    try {
      raw = JSON.parse(fs.readFileSync(this.file, 'utf8'))
    } catch {
      return false
    }
    const seen = new Set()
    for (const record of raw.tenants ?? []) {
      // One corrupt record (a hand-edited ledger, a half-finished migration) must
      // not throw from the reload timer or from every hello: skip it and keep the
      // rest of the registry working.
      let next
      try {
        next = normalize(record, this.quotaDefault, this.maxStreamsDefault)
      } catch (error) {
        console.error(`tenant store: skipping record: ${error.message}`)
        continue
      }
      const live = this.tenants.get(next.id)
      if (live) {
        // A rotated key changes keyId. Connections opened with the old key must
        // not keep running after the rotation - that is the point of rotating.
        const rotated = live.keyId !== next.keyId
        live.quotaBytesDay = next.quotaBytesDay
        live.maxStreams = next.maxStreams
        live.status = next.status
        live.note = next.note
        live.keyId = next.keyId
        live.secret = next.secret
        // Both halves of the v2 derivation have to travel together: a live tenant
        // left on v1 with no legacy secret would advertise a version it cannot
        // verify after the key was rotated underneath it.
        live.legacySecret = next.legacySecret
        live.proofVersion = next.proofVersion
        const previousResetSeq = live.resetSeq ?? 0
        if (next.day > live.day) {
          live.day = next.day
          live.usedBytesDay = next.usedBytesDay
        } else if (next.day === live.day) {
          if (next.resetSeq > previousResetSeq) {
            // An explicit reset is newer than anything we charged: take it.
            live.usedBytesDay = next.usedBytesDay
          } else {
            // Never lose bytes this process already charged.
            live.usedBytesDay = Math.max(live.usedBytesDay, next.usedBytesDay)
          }
        }
        live.resetSeq = Math.max(previousResetSeq, next.resetSeq ?? 0)
        if (rotated) this.onRotate?.(live)
      } else {
        this.tenants.set(next.id, next)
      }
      seen.add(next.id)
    }
    for (const id of [...this.tenants.keys()]) {
      if (!seen.has(id)) this.tenants.delete(id)
    }
    return true
  }

  /**
   * Atomic write; a crash mid-save must not lose the quota ledger.
   *
   * Several processes write this file - the relay itself, `tenant` CLI runs, and
   * the demo's key dispenser - so a plain read-modify-write loses their changes:
   * a key handed out seconds ago would vanish, and a `disable` would be silently
   * undone. Everything that changes the registry therefore runs through #mutate:
   * take the lock, read what is on disk, apply the change, write. The temporary
   * name is unique per process, so two writers can never rename a half-written
   * file over the ledger.
   *
   * The file holds each tenant's HMAC key — the value the relay itself verifies a
   * registration proof against, so whoever reads it can impersonate that tenant
   * to this relay. It is written 0600 inside a 0700 directory; a world-readable
   * ledger would be a credential leak, not just a privacy one.
   */
  save() {
    // Nothing to change: fold in whatever is on disk and write the result (this is
    // the relay's periodic flush of charged bytes).
    this.#mutate(() => {})
  }

  #mutate(change) {
    const dir = path.dirname(this.file)
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
    try { fs.chmodSync(dir, 0o700) } catch {}
    const release = this.#lock()
    try {
      // Read under the lock: another process may have written since our last
      // load, and the change must be applied on top of that state, not instead.
      this.reloadIfChanged()
      const result = change()
      const payload = {
        version: 1,
        tenants: [...this.tenants.values()].sort((a, b) => a.id.localeCompare(b.id)),
      }
      const tmp = `${this.file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`
      fs.writeFileSync(tmp, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 })
      fs.renameSync(tmp, this.file)
      try { fs.chmodSync(this.file, 0o600) } catch {}
      this.dirty = false
      this.mtimeMs = this.statMtime()
      return result
    } finally {
      release()
    }
  }

  /**
   * Take the ledger lock, or throw. A stale lock (a writer that died) is broken
   * after STALE_LOCK_MS so one crash cannot freeze every future write.
   */
  #lock() {
    const lockPath = `${this.file}.lock`
    for (let attempt = 0; attempt < 400; attempt += 1) {
      try {
        const fd = fs.openSync(lockPath, 'wx', 0o600)
        fs.writeSync(fd, String(process.pid))
        fs.closeSync(fd)
        let released = false
        return () => {
          if (released) return
          released = true
          try { fs.unlinkSync(lockPath) } catch {}
        }
      } catch (error) {
        if (error.code !== 'EEXIST') throw error
        try {
          const age = Date.now() - fs.statSync(lockPath).mtimeMs
          if (age > STALE_LOCK_MS) {
            fs.unlinkSync(lockPath)
            continue
          }
        } catch {}
        // Waiting a few milliseconds is enough: the critical section is one
        // small file write.
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5)
      }
    }
    throw new Error('tenant store: the ledger lock is held by another process')
  }

  saveIfDirty() {
    if (!this.dirty) return
    try {
      this.save()
    } catch (error) {
      console.error(`tenant store: save failed: ${error.message}`)
    }
  }

  /** Creates a tenant and returns the only copy of its key. */
  add({ name, quotaBytesDay = this.quotaDefault, maxStreams = this.maxStreamsDefault, note = '' }) {
    const id = String(name ?? '').trim()
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{1,31}$/.test(id)) {
      throw new Error('name must be 2-32 chars: letters, digits, dot, dash, underscore')
    }
    return this.#mutate(() => {
      // Checked under the lock: another process may have created it meanwhile.
      if (this.tenants.has(id)) throw new Error(`tenant ${id} already exists`)
      const key = newKey()
      const tenant = {
        id,
        keyId: keyIdFor(key),
        secret: secretFor(key),
        // Kept so an agent built before the v2 derivation still proves itself.
        legacySecret: legacySecretFor(key),
        proofVersion: 2,
        resetSeq: 0,
        quotaBytesDay,
        maxStreams,
        usedBytesDay: 0,
        day: quotaDay(),
        status: 'active',
        note,
        createdAt: new Date().toISOString(),
        lastSeenAt: null,
      }
      this.tenants.set(id, tenant)
      this.dirty = true
      return { tenant, key }
    })
  }

  /** Changes the limits of an existing tenant without touching its key. */
  setLimits(ref, { quotaBytesDay, maxStreams }) {
    return this.#mutate(() => {
      const tenant = this.resolve(ref)
      if (!tenant) throw new Error(`no tenant ${ref}`)
      if (Number.isFinite(quotaBytesDay)) tenant.quotaBytesDay = quotaBytesDay
      if (Number.isFinite(maxStreams)) tenant.maxStreams = maxStreams
      this.dirty = true
      return tenant
    })
  }

  byKeyId(keyId) {
    for (const tenant of this.tenants.values()) {
      if (tenant.keyId === keyId) return tenant
    }
    return null
  }

  get(id) {
    return this.tenants.get(id) ?? null
  }

  resolve(ref) {
    if (!ref) return null
    return this.tenants.get(ref) ?? this.byKeyId(ref) ?? null
  }

  list() {
    return [...this.tenants.values()].sort((a, b) => a.id.localeCompare(b.id))
  }

  setStatus(ref, status) {
    return this.#mutate(() => {
      const tenant = this.resolve(ref)
      if (!tenant) throw new Error(`no tenant ${ref}`)
      tenant.status = status
      this.dirty = true
      return tenant
    })
  }

  reset(ref) {
    return this.#mutate(() => {
      const tenant = this.resolve(ref)
      if (!tenant) throw new Error(`no tenant ${ref}`)
      tenant.usedBytesDay = 0
      tenant.day = quotaDay()
      // A running relay merges a same-day reload by taking the larger usage count
      // ("never lose charged bytes"), so a reset that only writes 0 would be
      // ignored by the next merge. The sequence number tells the relay that this
      // record is newer than what it holds.
      tenant.resetSeq = (tenant.resetSeq ?? 0) + 1
      this.dirty = true
      return tenant
    })
  }

  remove(ref) {
    return this.#mutate(() => {
      const tenant = this.resolve(ref)
      if (!tenant) throw new Error(`no tenant ${ref}`)
      this.tenants.delete(tenant.id)
      this.dirty = true
      return tenant
    })
  }

  /**
   * Books `bytes` against today's quota. Returns the tenant plus whether this
   * call crossed the limit, so the caller can cut the connection exactly once.
   */
  charge(tenant, bytes) {
    if (!tenant || !(bytes > 0)) return { tenant, over: false }
    const day = quotaDay()
    if (tenant.day !== day) {
      tenant.day = day
      tenant.usedBytesDay = 0
    }
    tenant.usedBytesDay += bytes
    this.dirty = true
    const over = tenant.quotaBytesDay > 0 && tenant.usedBytesDay >= tenant.quotaBytesDay
    return { tenant, over }
  }

  /** True when the tenant may not open new connections right now. */
  blocked(tenant) {
    if (!tenant) return 'unknown-key'
    if (tenant.status !== 'active') return 'key-disabled'
    const day = quotaDay()
    if (tenant.day !== day) return null
    if (tenant.quotaBytesDay > 0 && tenant.usedBytesDay >= tenant.quotaBytesDay) return 'quota-exceeded'
    return null
  }
}

function normalize(tenant, quotaDefault, maxStreamsDefault = DEFAULT_MAX_STREAMS) {
  // A record written before v2 has `secret = sha256(key)` and no raw key left, so
  // it cannot be re-derived: it keeps that secret and is advertised as version 1.
  // A record that still carries the raw key (`tenant.key`) is migrated now, and
  // keeps the v1 secret alongside so an agent that has not updated still proves
  // itself correctly.
  let secret
  let legacySecret = tenant.legacySecret ?? null
  let proofVersion = 1
  if (tenant.key) {
    secret = secretFor(tenant.key)
    legacySecret = legacySecretFor(tenant.key)
    proofVersion = 2
  } else {
    secret = tenant.secret ?? null
    if (tenant.proofVersion === 2) proofVersion = 2
  }
  // Fail closed. hashKey('') is sha256 of the empty string - a value anyone can
  // compute - so a record carrying neither a key nor a secret (a hand-edited
  // ledger, a half-finished migration) would let anyone register as that tenant.
  if (!secret) {
    throw new Error(`tenant ${tenant.id ?? '(no id)'} has neither a key nor a secret`)
  }
  // Fail closed on identity too: a record with no id, and one with neither a key
  // id nor a raw key to derive it from, would otherwise collapse onto
  // keyIdFor('') = e3b0c44298fc and let several broken records answer the same
  // hello.
  if (!tenant.id) throw new Error('tenant record has no id')
  const keyId = tenant.keyId ?? (tenant.key ? keyIdFor(tenant.key) : null)
  if (!keyId) throw new Error(`tenant ${tenant.id} has no key id`)
  return {
    id: tenant.id,
    keyId,
    secret,
    legacySecret,
    proofVersion,
    resetSeq: Number.isFinite(tenant.resetSeq) ? tenant.resetSeq : 0,
    quotaBytesDay: Number.isFinite(tenant.quotaBytesDay) ? tenant.quotaBytesDay : quotaDefault,
    maxStreams: Number.isFinite(tenant.maxStreams) ? tenant.maxStreams : maxStreamsDefault,
    usedBytesDay: Number.isFinite(tenant.usedBytesDay) ? tenant.usedBytesDay : 0,
    day: tenant.day ?? quotaDay(),
    status: tenant.status === 'disabled' ? 'disabled' : 'active',
    note: tenant.note ?? '',
    createdAt: tenant.createdAt ?? new Date().toISOString(),
    lastSeenAt: tenant.lastSeenAt ?? null,
  }
}
