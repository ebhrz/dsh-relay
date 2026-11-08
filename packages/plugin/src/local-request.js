// "Is this request from the desktop itself?"
//
// The management panel and the local file shuttles are desktop tools: they hand
// out the pairing link (which embeds the device PSK) and let the caller read
// files. Both are registered on DSH's own web server, so whatever binds that
// server decides who can reach them - a LAN exposure, a reverse proxy, or a
// browser at another origin all end up looking like ordinary requests.
//
// Two independent facts must hold: the TCP peer must be loopback, and the Host
// header must be a loopback name. The second one is what defeats DNS rebinding -
// `evil.example` resolving to 127.0.0.1 arrives with `Host: evil.example`, which
// is not a name the desktop would ever use.

const LOOPBACK_ADDRESSES = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1'])
const LOOPBACK_HOST = /^(?:localhost|127\.0\.0\.1|\[::1\])(?::\d{1,5})?$/i

export function isLoopbackAddress(address) {
  const value = String(address ?? '')
  if (LOOPBACK_ADDRESSES.has(value)) return true
  // 127.0.0.0/8 is all loopback; a resolved name may present any of it.
  return /^127(?:\.\d{1,3}){3}$/.test(value)
}

export function isLoopbackHost(host) {
  return LOOPBACK_HOST.test(String(host ?? ''))
}

/** Loopback peer AND loopback Host: the desktop, not a proxy or a rebound name. */
export function isLocalRequest({ remoteAddress, host } = {}) {
  return isLoopbackAddress(remoteAddress) && isLoopbackHost(host)
}
