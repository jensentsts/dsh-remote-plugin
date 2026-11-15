/** Built filesystem foundation: real temporary files, no peer network, exec or installed profile. */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { FileSystem, FsError } from '@deepseek-ai/dsh-fs'
import { FederatedFileSystem } from '../lib/peer-fs.js'
import { WorkspaceReferences } from '../../dsh-workspace-reference/references.js'

test('built Federated filesystem inherits exact alias support, preserves local guards and shared FsError identity without touching remote URI routing', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dshr-fs-foundation-'))
  const previous = process.env.DSH_HOME; process.env.DSH_HOME = root
  const ctx = new Context()
  let mode = 'danger-full-access'
  ctx.provide('sandboxPolicy', { defaultMode: mode, resolve: () => ({ mode, workspaceRoot: root, additionalWritableRoots: [] }) })
  let fiber
  try {
    const offlinePeer = { host: '127.0.0.1', port: 1, maxPermission: 1, autoGenerateKey: false }
    fiber = ctx.plugin(FederatedFileSystem, { cwd: root, defaultPeer: 'fixture', peers: { fixture: offlinePeer, ws: offlinePeer, workspace: offlinePeer } })
    await fiber
    const fs = ctx.fs
    assert.ok(fs instanceof FileSystem, 'external FileSystem identity is shared')
    assert.equal(typeof fs.registerPathAlias, 'function')
    const registered = join(root, 'registered'); await mkdir(registered)
    const references = new WorkspaceReferences({ registry: () => ({ list: () => [{ id: 'workspaceID', title: 'Research', path: registered, sessionIds: [] }] }), filesystem: () => fs })
    const resolver = (path, options, backend) => references.translate(path, { ...options, fs: backend })
    const aliases = ctx.plugin({ name: 'fixture-path-alias', inject: ['fs'], apply(scope) { scope.fs.registerPathAlias(resolver) } }); await aliases
    const target = await fs.resolve('@ws:Research{workspaceID}/file.txt')
    assert.equal(target.targetKey, (await fs.resolve(join(registered, 'file.txt'))).targetKey)
    for (const alias of ['@workspace:Research/file.txt', '@Research/file.txt', '@ws:Research{workspaceID}/file.txt']) {
      assert.equal((await fs.resolve(alias)).targetKey, target.targetKey)
    }
    await mkdir(join(root, 'Research')); await writeFile(join(root, 'Research', 'local.txt'), 'local')
    assert.equal(await fs.readText(await fs.resolve('@./Research/local.txt')), 'local')
    await assert.rejects(fs.resolve('@Research/file.txt'), /workspace-or-local-directory/)
    assert.equal((await fs.resolve('@workspace:Research/file.txt')).targetKey, target.targetKey)
    const written = await fs.writeText(target, 'alpha', { kind: 'createIfAbsent' })
    assert.equal(await fs.readText(target), 'alpha')
    const edited = await fs.editText(await fs.resolve('@ws:Research{workspaceID}/file.txt'), { oldString: 'alpha', newString: 'beta', replaceAll: false }, { version: written.version })
    assert.notEqual(edited.version, written.version)
    await assert.rejects(fs.writeText(target, 'stale', { kind: 'replaceIfVersion', version: written.version }), error => error instanceof FsError && error.code === 'FS_STALE_VERSION')
    assert.equal(await fs.readText(target), 'beta')
    mode = 'read-only'
    await assert.rejects(fs.writeText(target, 'blocked'), error => error instanceof FsError && error.code === 'FS_SANDBOX_DENIED')
    mode = 'danger-full-access'
    const outside = join(root, 'outside'); await mkdir(outside); await writeFile(join(outside, 'secret'), 'outside')
    await symlink(outside, join(registered, 'escape'), process.platform === 'win32' ? 'junction' : 'dir')
    await assert.rejects(fs.resolve('@ws:Research{workspaceID}/escape/secret'), error => error instanceof FsError && error.code === 'FS_PERMISSION_DENIED')
    const remoteBefore = await fs.resolve('rmt:/C:/data/file.txt')
    const mountedBefore = await fs.resolve('/rmt/fixture/C:/data/file.txt')
    assert.equal(String(remoteBefore.targetKey), 'peer:fixture:C:/data/file.txt')
    assert.equal(String(mountedBefore.targetKey), 'peer:fixture:C:/data/file.txt')
    const scp = await fs.resolve('fixture:/C:/data/file.txt')
    assert.equal(scp.targetKey, remoteBefore.targetKey)
    assert.equal(fs.fileUrl(remoteBefore), 'peer://fixture/C:/data/file.txt')
    assert.equal(fs.processPath(remoteBefore), 'peer://fixture/C:/data/file.txt')
    await aliases.dispose()
    assert.equal((await fs.normalizePathAlias('@ws:Research{workspaceID}/file.txt')).path, '@ws:Research{workspaceID}/file.txt')
    assert.equal((await fs.resolve('rmt:/C:/data/file.txt')).targetKey, remoteBefore.targetKey)
    assert.equal(await fs.readText(await fs.resolve(join(registered, 'file.txt'))), 'beta')
    await fiber.dispose(); assert.equal(ctx.get('fs'), undefined)
  } finally {
    await ctx.fiber.dispose()
    if (previous === undefined) delete process.env.DSH_HOME; else process.env.DSH_HOME = previous
    assert.ok(root.startsWith(join(tmpdir(), 'dshr-fs-foundation-')))
    await rm(root, { recursive: true, force: true })
  }
})
