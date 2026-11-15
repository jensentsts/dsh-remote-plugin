import { readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
// All .test files are offline/local-loopback; live-* and benchmarks opt in
// separately. Inherit stdio so no pipe transport or hidden output is required.
const available = readdirSync(resolve(root, 'test')).filter(name => /\.test\.(?:ts|mjs)$/u.test(name)).sort()
const selected = process.argv.slice(2)
for (const name of selected) if (!available.includes(name)) throw new Error(`Unknown test file: ${name}`)
const tests = selected.length ? selected : available
const failed = []
for (const name of tests) {
  console.log(`\n======== ${name} ========`)
  const exit = await new Promise((done, reject) => {
    const child = spawn(process.execPath, [...process.execArgv, resolve(root, 'test', name)], { cwd: root, stdio: 'inherit', windowsHide: true })
    const timer = setTimeout(() => { child.kill(); }, 120_000)
    child.on('error', error => { clearTimeout(timer); reject(error) })
    child.on('exit', code => { clearTimeout(timer); done(code) })
  })
  if (exit !== 0) failed.push(name)
}
console.log(`\n${tests.length - failed.length}/${tests.length} test files passed`)
if (failed.length) { console.error('Failed:', failed.join(', ')); process.exitCode = 1 }
