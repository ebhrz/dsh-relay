#!/usr/bin/env node
// Hermetic test suite: nothing here needs a relay, a running dsh web, or network
// access. Each file is a standalone script that exits non-zero on failure, so
// this runner only has to spawn them in order and keep score.
//
//   npm test

import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))

const SUITE = [
  'compat.test.mjs',
  'keepalive.test.mjs',
  'mobile-patch.test.mjs',
  'mobile-bridge.test.mjs',
  'mobile-transport.test.mjs',
]

const failures = []
for (const name of SUITE) {
  process.stdout.write(`\n=== ${name} ===\n`)
  const result = spawnSync(process.execPath, [path.join(here, name)], { stdio: 'inherit' })
  if (result.status !== 0) failures.push(`${name} (exit ${result.status ?? result.signal})`)
}

if (failures.length > 0) {
  console.error(`\n${failures.length} of ${SUITE.length} test files failed:`)
  for (const failure of failures) console.error(`  - ${failure}`)
  process.exit(1)
}
console.log(`\nall ${SUITE.length} test files passed`)
