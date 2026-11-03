#!/usr/bin/env node
// Syntax-check every shipped source file. Cheap, platform-independent, and it
// catches the class of breakage that a runtime-only test suite misses in files
// no test imports yet.
//
//   npm run check

import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function walk(dir) {
  const out = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) out.push(...walk(full))
    else if (entry.name.endsWith('.js') || entry.name.endsWith('.mjs')) out.push(full)
  }
  return out
}

const targets = [...walk(path.join(root, 'src')), ...walk(path.join(root, 'scripts')), ...walk(path.join(root, 'test'))]
const failures = []
for (const file of targets) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' })
  if (result.status !== 0) failures.push({ file, output: (result.stderr ?? '').trim() })
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`\n${path.relative(root, failure.file)}`)
    console.error(failure.output.split('\n').slice(0, 6).join('\n'))
  }
  console.error(`\n${failures.length} of ${targets.length} files failed the syntax check`)
  process.exit(1)
}
console.log(`syntax ok: ${targets.length} files`);
