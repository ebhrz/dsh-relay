// Shared environment plumbing for the live-environment probes.
//
// These scripts talk to a real relay deployment and a real dsh web process, so
// they need two things the tests do not: the local device identity and the
// relay's base URL. Both come from the machine, never from the repository.
//
//   DSH_HOME        where the plugin keeps identity.json
//                   (default ~/.dsh, same as dsh itself)
//   RELAY_BASE_URL  relay origin, without the /c/<device> part
//                   e.g. https://relay.example.com:8889

import fs from 'node:fs'
import { identityPath } from '../../src/identity.js'

/** Load the paired device identity or exit with a pointer to what is missing. */
export function loadIdentityOrExit() {
  const file = identityPath()
  try {
    const identity = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (!identity.id || !identity.psk || !identity.gate) throw new Error('incomplete')
    return identity
  } catch {
    console.error(`no usable device identity at ${file}`)
    console.error('Run dsh web with the plugin loaded and pair a phone once, then retry.')
    console.error('(Set DSH_HOME if the plugin does not use the default ~/.dsh.)')
    process.exit(2)
  }
}

/** Relay origin from RELAY_BASE_URL, or exit with usage. */
export function relayBaseUrlOrExit() {
  const value = process.env.RELAY_BASE_URL
  if (!value) {
    console.error('RELAY_BASE_URL is required, e.g. https://relay.example.com:8889')
    process.exit(2)
  }
  return value.replace(/\/+$/, '')
}

/** Relay origin plus the device-scoped prefix every request is routed under. */
export function entryBaseOrExit() {
  const identity = loadIdentityOrExit()
  return { identity, base: `${relayBaseUrlOrExit()}/c/${identity.id}` }
}
