// Locate tweetnacl's browser bundle.
//
// It used to be built from a fixed relative path (`../node_modules/tweetnacl`),
// which only holds while the dependency sits inside the package directory. A
// consumer install may hoist it to the project root, and pnpm keeps it in a
// store, so resolution goes through Node instead — it finds the file in every
// layout. tweetnacl has no `exports` map, so the subpath is legal.
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
let resolved

/** Absolute path of nacl-fast.min.js (or nacl.min.js), or null when missing. */
export function naclBundlePath() {
  if (resolved !== undefined) return resolved
  for (const specifier of ['tweetnacl/nacl-fast.min.js', 'tweetnacl/nacl.min.js']) {
    try {
      resolved = require.resolve(specifier)
      return resolved
    } catch {}
  }
  resolved = null
  return null
}

/** The bundle source, or '' when the dependency is missing. */
export function naclBundleSource() {
  const file = naclBundlePath()
  if (!file) return ''
  try {
    return require('node:fs').readFileSync(file, 'utf8')
  } catch {
    return ''
  }
}
