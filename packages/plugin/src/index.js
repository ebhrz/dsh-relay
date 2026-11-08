// dsh-relay-phone host side.
//
// Owns the device identity, the outbound relay connection (TOFU-pinned WSS,
// HMAC registration gate), the pairing/auth service, the sealing pump that
// replays phone traffic to the loopback DSH, and the local management panel
// at /relay-bridge/panel (status, QR, config, identity rotation).

import { Service } from '@deepseek-ai/cordis'
import fs from 'node:fs'
import path from 'node:path'
import { RelayClient } from './relay-client.js'
import { PumpManager } from './pump.js'
import { CryptoBox } from './crypto.js'
import { PairingService } from './pairing.js'
import { loadOrCreateIdentity, saveIdentity, createIdentity, identityDir, auditLog } from './identity.js'
import { registerPanel } from './panel.js'
import { registerFiles } from './files.js'
import { MobileRouter } from './mobile/index.js'
import { MobileBridge } from './mobile/bridge.js'

function configFile() {
  return path.join(identityDir(), 'config.json')
}

/** Plugin version shown on the mobile page's connection card. */
function readPluginVersion() {
  try {
    const file = new URL('../package.json', import.meta.url)
    return JSON.parse(fs.readFileSync(file, 'utf8')).version ?? '0'
  } catch {
    return '0'
  }
}

function readStoredConfig() {
  try {
    return JSON.parse(fs.readFileSync(configFile(), 'utf8'))
  } catch {
    return {}
  }
}

/** Render an HTTP authority for a bind host (IPv6 literals need brackets). */
function authorityOf(host, port) {
  const text = String(host)
  const bracketed = text.includes(':') && !text.startsWith('[') ? `[${text}]` : text
  return `${bracketed}:${port}`
}

export default class RelayBridgeService extends Service {
  static inject = ['webServer']

  constructor(ctx, config = {}) {
    super(ctx, 'relayBridge')
    const stored = readStoredConfig()
    this.config = this.mergeConfig(config, stored)

    this.identity = loadOrCreateIdentity()
    this.cryptoBox = new CryptoBox(this.identity, {
      sessionsPath: path.join(identityDir(), 'sessions.json'),
      // Replay memory has to outlive the process, because a ticket does.
      noncePath: path.join(identityDir(), 'seen-nonces.json'),
    })
    this.pairing = new PairingService(this.cryptoBox, this.identity)
    this.pump = null
    this.client = null
    this.lastStatus = { status: 'idle', detail: '' }
    // DSH 0.2 authenticates every browser/API request with a cookie minted
    // from the per-process launch token (dsh-client-connection). The pump
    // replays phone traffic from loopback, so it must carry that cookie
    // upstream; the phone's own relay ticket never leaves the relay side.
    this.upstreamCookie = null
    this.authWarningLogged = false

    // Dedicated phone surface: a purpose-built page plus a host-side bridge to
    // the DSH native session API (docs/mobile/native-api.md). The desktop UI
    // replay stays available at `/` for full-feature use.
    this.mobileVersion = readPluginVersion()
    this.mobileBridge = new MobileBridge(ctx, {
      version: this.mobileVersion,
      logger: ctx.logger,
    })
    this.mobileBridge.deviceId = this.identity.id
    this.mobile = new MobileRouter({
      cryptoBox: this.cryptoBox,
      bridge: this.mobileBridge,
      logger: ctx.logger,
    })
    this.mobileBridge.install()

    ctx.effect(() => () => {
      this.stopChannel()
      this.mobileBridge.dispose()
    }, 'dsh-relay-phone: relay channel')
    registerPanel(ctx, this)
    registerFiles(ctx)

    if (this.config.autoStart && this.config.relayHost) {
      this.startChannel()
    } else {
      this.lastStatus = { status: 'idle', detail: 'configure the relay in /relay-bridge/panel' }
    }
  }

  /**
   * Loopback endpoint of the DSH web server that owns this plugin. The stored
   * dshPort is only a fallback: DSH 0.2 may bind an OS-assigned port, and the
   * webServer service is the only reliable source of truth.
   */
  upstreamTarget() {
    const server = this.ctx.webServer
    const port = Number(server?.port ?? this.config.dshPort ?? 3080)
    const bindHost = String(server?.host ?? this.config.dshHost ?? '127.0.0.1')
    const host = bindHost === 'localhost' ? '127.0.0.1' : bindHost
    return {
      host,
      port,
      authority: authorityOf(host, port),
      protocol: server?.protocol ?? 'http:',
    }
  }

  /**
   * Mint (once) the browser-session cookie DSH 0.2 requires on the index
   * exchange and every /api request. `authorizeIndex` is the same synchronous
   * token exchange the frontend-static fallback uses; feed it a synthetic
   * root-token request and retain only the Set-Cookie value. Older DSH
   * versions without the auth service return no cookie and replay unchanged.
   */
  upstreamAuthCookie() {
    if (this.upstreamCookie) return this.upstreamCookie
    const connection = this.ctx.get('connection')
    if (!connection
      || typeof connection.authenticatedUrl !== 'function'
      || typeof connection.authorizeIndex !== 'function') return null
    const target = this.upstreamTarget()
    try {
      const tokenUrl = new URL(connection.authenticatedUrl(`${target.protocol}//${target.authority}/`))
      const token = tokenUrl.searchParams.get('token')
      if (!token) return null
      const headers = {}
      const response = {
        writeHead(_status, values) {
          if (!values || typeof values !== 'object') return
          for (const [name, value] of Object.entries(values)) headers[name.toLowerCase()] = value
        },
        setHeader(name, value) { headers[String(name).toLowerCase()] = value },
        getHeader(name) { return headers[String(name).toLowerCase()] },
        end() {},
      }
      const request = {
        method: 'GET',
        url: `/?token=${encodeURIComponent(token)}`,
        headers: { host: target.authority },
      }
      connection.authorizeIndex(request, response)
      const setCookie = headers['set-cookie']
      const raw = Array.isArray(setCookie) ? setCookie[0] : setCookie
      if (!raw) return null
      this.upstreamCookie = String(raw).split(';')[0]
      this.ctx.logger.info('relay: upstream DSH browser session authenticated')
      return this.upstreamCookie
    } catch (error) {
      if (!this.authWarningLogged) {
        this.authWarningLogged = true
        this.ctx.logger.warn(`relay: cannot mint upstream DSH auth cookie: ${error?.message ?? error}`)
      }
      return null
    }
  }

  mergeConfig(base, stored) {
    return {
      relayScheme: stored.relayScheme ?? base.relayScheme ?? 'http',
      relayHost: stored.relayHost ?? base.relayHost ?? '',
      relayPort: Number(stored.relayPort ?? base.relayPort ?? 0),
      agentPort: Number(stored.agentPort ?? base.agentPort ?? 0),
      relayKey: stored.relayKey ?? base.relayKey ?? '',
      dshHost: stored.dshHost ?? base.dshHost ?? '127.0.0.1',
      dshPort: Number(stored.dshPort ?? base.dshPort ?? 3080),
      autoStart: base.autoStart !== false,
      // Opt-in only: replaying the desktop UI over the relay forwards its
      // plaintext /api/* calls with the host cookie, so the relay operator could
      // act as the user. The phone page never needs this.
      allowDesktopPlaintext: stored.allowDesktopPlaintext ?? base.allowDesktopPlaintext ?? false,
    }
  }

  applyConfig(stored) {
    this.config = this.mergeConfig(this.config, stored)
    auditLog(`config updated relay=${this.config.relayHost}:${this.config.relayPort}`)
    this.startChannel()
  }

  rotateIdentity() {
    this.stopChannel()
    this.identity = createIdentity()
    saveIdentity(this.identity)
    auditLog(`identity rotated -> ${this.identity.id} (all paired devices revoked)`)
    this.cryptoBox = new CryptoBox(this.identity, {
      sessionsPath: path.join(identityDir(), 'sessions.json'),
      noncePath: path.join(identityDir(), 'seen-nonces.json'),
    })
    this.cryptoBox.resetSessions() // rotation revokes every paired device
    this.pairing = new PairingService(this.cryptoBox, this.identity)
    this.mobile.cryptoBox = this.cryptoBox
    this.mobileBridge.deviceId = this.identity.id
    if (this.config.autoStart && this.config.relayHost) this.startChannel()
  }

  // Explicitly accept a changed relay certificate (TOFU re-pin). Only valid
  // while the channel is halted on a fingerprint mismatch.
  acceptFingerprint() {
    if (this.lastStatus?.status !== 'fingerprint-mismatch') return false
    auditLog(`relay certificate re-pinned (was ${this.identity.certFingerprint})`)
    this.identity.certFingerprint = null
    saveIdentity(this.identity)
    this.startChannel()
    return true
  }

  startChannel() {
    this.stopChannel()
    if (!this.config.relayHost || !this.config.relayKey) {
      this.lastStatus = { status: 'idle', detail: 'relay host/key not configured' }
      return
    }
    this.pump = new PumpManager({
      dshHost: this.config.dshHost,
      dshPort: this.config.dshPort,
      resolveTarget: () => this.upstreamTarget(),
      resolveAuthCookie: () => this.upstreamAuthCookie(),
      pairing: this.pairing,
      cryptoBox: this.cryptoBox,
      mobile: this.mobile,
    })
    this.client = new RelayClient({
      host: this.config.relayHost,
      agentPort: this.config.agentPort || this.config.relayPort + 1,
      relayKey: this.config.relayKey,
      identity: this.identity,
      pump: this.pump,
      onIdentityChange: (identity) => saveIdentity(identity),
    })
    this.pump.setClient(this.client)
    let lastLoggedStatus = null
    this.client.addEventListener('status', (event) => {
      this.lastStatus = event.detail
      this.ctx.logger.info(`relay: ${event.detail.status} ${event.detail.detail}`)
      // Audit every transition (not every retry with an unchanged detail) so
      // intermittent agent↔relay drops are diagnosable after the fact.
      const key = `${event.detail.status}|${event.detail.detail}`
      if (event.detail.status !== 'connecting' && event.detail.status !== 'reconnecting') lastLoggedStatus = null
      if (key !== lastLoggedStatus) {
        lastLoggedStatus = key
        auditLog(`relay ${event.detail.status} ${event.detail.detail ?? ''}`.trim())
      }
    })
    this.client.start()
  }

  stopChannel() {
    this.client?.stop()
    this.client = null
    this.pump?.dispose()
    this.pump = null
  }

  status() {
    const s = this.lastStatus ?? { status: 'idle', detail: '' }
    const target = this.upstreamTarget()
    return {
      ...s,
      id: this.identity.id,
      relayHost: this.config.relayHost,
      relayPort: this.config.relayPort,
      agentPort: this.config.agentPort,
      upstreamHost: target.host,
      upstreamPort: target.port,
      connected: this.client?.connected() ?? false,
    }
  }
}
