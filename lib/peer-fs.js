// src/peer-fs.ts
import { FsError as FsError5, FsTargetKey as FsTargetKey2, FsVersion as FsVersion3 } from "@deepseek-ai/dsh-fs";

// ../../upstream/dsh-0.2.2-rc.1/packages/fs/fs-local/src/index.ts
import { applyHunks } from "@deepseek-ai/dsh-fs-patch";
import { constants as bufferConstants } from "node:buffer";
import { once } from "node:events";
import { watch } from "chokidar";
import { dirname as dirname2, isAbsolute as isAbsolute2, relative, resolve as resolve2, sep as sep2 } from "node:path";
import { pathToFileURL } from "node:url";
import z from "@deepseek-ai/schemastery";
import { FileSystem, FsError as FsError2, FsVersion as FsVersion2 } from "@deepseek-ai/dsh-fs";

// ../../upstream/dsh-0.2.2-rc.1/packages/fs/fs-local/src/fsio.ts
import { randomUUID } from "node:crypto";
import { createReadStream, realpath as realpathCallback } from "node:fs";
import { chmod, link, lstat, mkdir, open, readFile, readdir, rename, rm, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { TextDecoder, promisify } from "node:util";
import { homedir } from "node:os";
import { FsError, FsTargetKey, FsVersion } from "@deepseek-ai/dsh-fs";

// ../../upstream/dsh-0.2.2-rc.1/packages/fs/fs-local/src/win32.ts
import { toNamespacedPath } from "node:path";
var DACL_SECURITY_INFORMATION = 4;
var PROTECTED_DACL_SECURITY_INFORMATION = 2147483648;
var ERROR_FILE_NOT_FOUND = 2;
var ERROR_PATH_NOT_FOUND = 3;
var ERROR_ACCESS_DENIED = 5;
var bindings;
async function win32() {
  if (bindings !== void 0) return bindings;
  const koffi = (await import("koffi")).default;
  const advapi32 = koffi.load("advapi32.dll");
  const kernel32 = koffi.load("kernel32.dll");
  bindings = {
    getFileSecurityW: advapi32.func("int __stdcall GetFileSecurityW(const char16_t *path, uint32_t requested, void *descriptor, uint32_t length, _Out_ uint32_t *needed)"),
    setFileSecurityW: advapi32.func("int __stdcall SetFileSecurityW(const char16_t *path, uint32_t information, const void *descriptor)"),
    replaceFileW: kernel32.func("int __stdcall ReplaceFileW(const char16_t *replaced, const char16_t *replacement, const char16_t *backup, uint32_t flags, void *exclude, void *reserved)"),
    getLastError: kernel32.func("uint32_t __stdcall GetLastError()")
  };
  return bindings;
}
function errnoCode(win32Code) {
  switch (win32Code) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
      return "ENOENT";
    case ERROR_ACCESS_DENIED:
      return "EACCES";
    default:
      return "EIO";
  }
}
function win32Error(syscall, win32Code, path) {
  const code = errnoCode(win32Code);
  const error = new Error(`${syscall} ${code} (Win32 ${win32Code}): ${path}`);
  error.code = code;
  error.errno = win32Code;
  error.syscall = syscall;
  error.path = path;
  error.win32Code = win32Code;
  return error;
}
async function readFileDaclWin32(path) {
  const api = await win32();
  const nativePath = toNamespacedPath(path);
  const needed = [0];
  api.getFileSecurityW(nativePath, DACL_SECURITY_INFORMATION, null, 0, needed);
  if (needed[0] === 0) throw win32Error("GetFileSecurityW", api.getLastError(), path);
  const descriptor = Buffer.alloc(needed[0]);
  if (api.getFileSecurityW(nativePath, DACL_SECURITY_INFORMATION, descriptor, descriptor.length, needed) === 0) {
    throw win32Error("GetFileSecurityW", api.getLastError(), path);
  }
  return descriptor.subarray(0, needed[0]);
}
async function copyFileDaclWin32(source, destination) {
  const descriptor = await readFileDaclWin32(source);
  const api = await win32();
  const information = (DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION) >>> 0;
  if (api.setFileSecurityW(toNamespacedPath(destination), information, descriptor) === 0) {
    throw win32Error("SetFileSecurityW", api.getLastError(), destination);
  }
}
async function replaceFileWin32(replaced, replacement) {
  const api = await win32();
  if (api.replaceFileW(
    toNamespacedPath(replaced),
    toNamespacedPath(replacement),
    null,
    0,
    null,
    null
  ) === 0) {
    throw win32Error("ReplaceFileW", api.getLastError(), replaced);
  }
}

// ../../upstream/dsh-0.2.2-rc.1/packages/fs/fs-local/src/fsio.ts
var BINARY_SAMPLE_BYTES = 8192;
var realpath = promisify(realpathCallback.native);
var DIFF_BASIS_READ_CHUNK_BYTES = 64 * 1024;
function isENOENT(error) {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}
function isEEXIST(error) {
  return error instanceof Error && "code" in error && error.code === "EEXIST";
}
function isENOTDIR(error) {
  return error instanceof Error && "code" in error && error.code === "ENOTDIR";
}
function isAbortError(error) {
  return error instanceof Error && error.name === "AbortError";
}
function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
function isPermissionError(error) {
  return error instanceof Error && "code" in error && (error.code === "EACCES" || error.code === "EPERM");
}
function throwIfAborted(signal, verb) {
  if (signal?.aborted) throw new FsError(`${verb} aborted`, "FS_ABORTED");
}
async function readFileAbortable(absolutePath, verb, signal) {
  try {
    return await readFile(absolutePath, signal ? { signal } : {});
  } catch (error) {
    if (!isAbortError(error)) throw error;
    throw new FsError(`${verb} aborted`, "FS_ABORTED");
  }
}
function versionOf(info) {
  return FsVersion(`${info.dev}:${info.ino}:${info.size}:${info.mtimeNs}:${info.ctimeNs}`);
}
function expandHomePrefix(path) {
  if (path === "~" || path.startsWith("~/") || process.platform === "win32" && path.startsWith("~\\")) return `${homedir()}${path.slice(1)}`;
  return path;
}
function localDisplayPath(cwd, path) {
  const absoluteCwd = isAbsolute(cwd) ? cwd : `${process.cwd()}${sep}${cwd}`;
  const raw = isAbsolute(path) ? path : `${absoluteCwd}${sep}${path}`;
  const physicalSpelling = /(?:^|[\\/])\.\.(?:[\\/]|$)/u.test(raw) ? raw : resolve(cwd, path);
  return process.platform === "win32" ? resolve(cwd, path) : physicalSpelling;
}
async function resolveLocalTarget(cwd, path) {
  if (path.trim().length === 0) throw new FsError("file_path must be a non-empty string", "FS_NOT_FOUND");
  const displayPath = localDisplayPath(cwd, path);
  try {
    return { displayPath, targetKey: FsTargetKey(await realpath(displayPath)) };
  } catch (error) {
    if (isENOTDIR(error)) throw new FsError(`cannot resolve "${displayPath}": a parent path segment is not a directory`, "FS_NOT_FOUND");
    if (!isENOENT(error)) throw error;
  }
  const missing = [basename(displayPath)];
  let ancestor = dirname(displayPath);
  while (true) {
    try {
      const realAncestor = await realpath(ancestor);
      if (missing.includes("..")) throw new FsError(`cannot resolve "${displayPath}": parent traversal crosses a missing directory`, "FS_NOT_FOUND");
      if (process.platform === "win32") {
        const parentInfo = await stat(realAncestor);
        if (!parentInfo.isDirectory()) {
          throw new FsError(`cannot resolve "${displayPath}": a parent path segment is not a directory`, "FS_NOT_FOUND");
        }
      }
      return { displayPath, targetKey: FsTargetKey(join(realAncestor, ...missing)) };
    } catch (error) {
      if (error instanceof FsError) throw error;
      if (!isENOENT(error)) throw error;
      const parent = dirname(ancestor);
      if (parent === ancestor) return { displayPath, targetKey: FsTargetKey(displayPath) };
      missing.unshift(basename(ancestor));
      ancestor = parent;
    }
  }
}
function pathType(info) {
  if (info.isFile()) return "file";
  if (info.isDirectory()) return "directory";
  return "other";
}
function pathLinkType(info) {
  if (info.isSymbolicLink()) return "symlink";
  return pathType(info);
}
async function probeStats(absolutePath, readStats) {
  try {
    return await readStats(absolutePath);
  } catch (error) {
    if (!isENOENT(error) && !isENOTDIR(error)) throw error;
    return null;
  }
}
async function probe(absolutePath) {
  const info = await probeStats(absolutePath, (path) => stat(path, { bigint: true }));
  if (!info) return null;
  return {
    version: versionOf(info),
    mode: Number(info.mode & 0o777n),
    type: pathType(info),
    size: Number(info.size)
  };
}
async function probeNoFollow(absolutePath) {
  const info = await probeStats(absolutePath, (path) => lstat(path, { bigint: true }));
  if (!info) return null;
  return {
    version: versionOf(info),
    mode: Number(info.mode & 0o777n),
    type: pathLinkType(info),
    size: Number(info.size)
  };
}
function listingIoError(displayPath, error) {
  if (error instanceof FsError) return error;
  if (isENOENT(error) || isENOTDIR(error)) return new FsError(`cannot list "${displayPath}": not found`, "FS_NOT_FOUND", { cause: error });
  if (isPermissionError(error)) return new FsError(`cannot list "${displayPath}": permission denied`, "FS_PERMISSION_DENIED", { cause: error });
  return new FsError(`cannot list "${displayPath}": ${errorMessage(error)}`, "FS_IO_ERROR", { cause: error });
}
async function resolveListedChildTarget(parent, name2) {
  const identity = await resolveLocalTarget(parent.targetKey, name2);
  return { displayPath: localDisplayPath(parent.displayPath, name2), targetKey: identity.targetKey };
}
async function listDirectory(target, signal) {
  throwIfAborted(signal, "list");
  let info;
  try {
    info = await probe(target.targetKey);
  } catch (error) {
    throw listingIoError(target.displayPath, error);
  }
  if (!info) throw new FsError(`cannot list "${target.displayPath}": not found`, "FS_NOT_FOUND");
  if (info.type !== "directory") throw new FsError(`cannot list "${target.displayPath}": not a directory`, "FS_NOT_DIRECTORY");
  let entries;
  try {
    entries = await readdir(target.targetKey, { withFileTypes: true, encoding: "utf8" });
  } catch (error) {
    throw listingIoError(target.displayPath, error);
  }
  throwIfAborted(signal, "list");
  const result = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    throwIfAborted(signal, "list");
    try {
      const childTarget = await resolveListedChildTarget(target, entry.name);
      const childInfo = await probe(childTarget.targetKey);
      result.push({
        name: entry.name,
        type: childInfo?.type ?? "other",
        target: childTarget,
        ...childInfo ? { version: childInfo.version } : {},
        ...childInfo?.type === "file" ? { size: childInfo.size } : {}
      });
    } catch (error) {
      throw listingIoError(localDisplayPath(target.displayPath, entry.name), error);
    }
    throwIfAborted(signal, "list");
  }
  return result;
}
function notTextError(verb, displayPath) {
  return new FsError(`cannot ${verb} "${displayPath}": invalid UTF-8 text`, "FS_NOT_TEXT");
}
function decodeUtf8(buffer, verb, displayPath) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
    throw notTextError(verb, displayPath);
  }
}
function decodeUtf8Stream(decoder, chunk, verb, displayPath) {
  try {
    return chunk ? decoder.decode(chunk, { stream: true }) : decoder.decode();
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
    throw notTextError(verb, displayPath);
  }
}
async function statRegularFile(target, verb, signal) {
  throwIfAborted(signal, verb);
  let info;
  try {
    info = await stat(target.targetKey);
  } catch (error) {
    if (!isENOENT(error)) throw error;
    throw new FsError(`cannot ${verb} "${target.displayPath}": not found`, "FS_NOT_FOUND");
  }
  if (!info.isFile()) throw new FsError(`cannot ${verb} "${target.displayPath}": not a regular file`, "FS_NOT_REGULAR_FILE");
  return info;
}
async function readWholeText(target, signal) {
  await statRegularFile(target, "read", signal);
  const raw = await readFileAbortable(target.targetKey, "read", signal);
  throwIfAborted(signal, "read");
  if (raw.subarray(0, BINARY_SAMPLE_BYTES).includes(0)) {
    throw new FsError(`cannot read "${target.displayPath}": binary file`, "FS_NOT_TEXT");
  }
  return decodeUtf8(raw, "read", target.displayPath);
}
async function readWholeBytes(target, signal, maxBytes, internals = {}) {
  const info = await statRegularFile(target, "read", signal);
  if (info.size > maxBytes) {
    throw new FsError(`cannot read "${target.displayPath}": ${info.size} bytes exceeds the ${maxBytes}-byte limit`, "FS_TOO_LARGE");
  }
  await internals.inspectReadBytesAfterStat?.(target);
  const stream = createReadStream(target.targetKey, {
    end: maxBytes,
    ...signal ? { signal } : {}
  });
  const chunks = [];
  let bytes = 0;
  try {
    for await (const chunk of stream) {
      bytes += chunk.length;
      if (bytes > maxBytes) {
        throw new FsError(`cannot read "${target.displayPath}": content exceeds the ${maxBytes}-byte limit`, "FS_TOO_LARGE");
      }
      chunks.push(chunk);
    }
  } catch (error) {
    if (isAbortError(error)) throw new FsError("read aborted", "FS_ABORTED");
    throw error;
  }
  return Buffer.concat(chunks, bytes);
}
async function readByteWindow(target, range, signal) {
  await statRegularFile(target, "read", signal);
  if (range.length === 0) return new Uint8Array(0);
  const stream = createReadStream(target.targetKey, {
    start: range.offset,
    end: range.offset + range.length - 1,
    ...signal ? { signal } : {}
  });
  const chunks = [];
  let bytes = 0;
  try {
    for await (const chunk of stream) {
      chunks.push(chunk);
      bytes += chunk.length;
    }
  } catch (error) {
    if (isAbortError(error)) throw new FsError("read aborted", "FS_ABORTED");
    throw error;
  }
  return Buffer.concat(chunks, bytes);
}
async function* streamWholeText(target, signal) {
  await statRegularFile(target, "read", signal);
  const stream = createReadStream(target.targetKey, signal ? { signal } : {});
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let sampledBytes = 0;
  function scanBinarySample(chunk) {
    if (sampledBytes >= BINARY_SAMPLE_BYTES) return;
    const sample = chunk.subarray(0, Math.min(chunk.length, BINARY_SAMPLE_BYTES - sampledBytes));
    if (sample.includes(0)) {
      throw new FsError(`cannot read "${target.displayPath}": binary file`, "FS_NOT_TEXT");
    }
    sampledBytes += sample.length;
  }
  try {
    for await (const chunk of stream) {
      scanBinarySample(chunk);
      yield decodeUtf8Stream(decoder, chunk, "read", target.displayPath);
    }
    yield decodeUtf8Stream(decoder, void 0, "read", target.displayPath);
  } catch (error) {
    if (isAbortError(error)) throw new FsError("read aborted", "FS_ABORTED");
    throw error;
  }
}
async function removeStagingDirOrThrow(stagingDir, originalError, removeStagingDir) {
  try {
    await removeStagingDir(stagingDir);
  } catch (cleanupError) {
    throw new FsError(`write failed (${errorMessage(originalError)}) and temp cleanup failed (${errorMessage(cleanupError)})`, "FS_NOT_FOUND", { cause: originalError });
  }
  throw originalError;
}
async function throwGuardedCreateFailure(error, absolutePath, displayPath, inspectPublicationTarget) {
  let existing;
  try {
    existing = await inspectPublicationTarget(absolutePath);
  } catch (metadataError) {
    if (!isENOENT(metadataError) && !isENOTDIR(metadataError)) {
      throw new FsError(`cannot write "${displayPath}": ${errorMessage(metadataError)}`, "FS_IO_ERROR", { cause: metadataError });
    }
  }
  if (existing !== void 0) {
    if (!existing.isFile()) {
      throw new FsError(`cannot write "${displayPath}": not a regular file`, "FS_NOT_REGULAR_FILE", { cause: error });
    }
    throw new FsError(
      `cannot overwrite existing "${displayPath}" without reading it first`,
      "FS_NOT_OBSERVED",
      { cause: error }
    );
  }
  if (isEEXIST(error)) {
    throw new FsError(
      `cannot overwrite existing "${displayPath}" without reading it first`,
      "FS_NOT_OBSERVED",
      { cause: error }
    );
  }
  throw new FsError(`cannot write "${displayPath}": ${errorMessage(error)}`, "FS_IO_ERROR", { cause: error });
}
function writeIoError(path, error) {
  if (error instanceof FsError) return error;
  if (isPermissionError(error)) return new FsError(`cannot write "${path}": permission denied`, "FS_PERMISSION_DENIED", { cause: error });
  if (error instanceof Error && "code" in error && typeof error.code === "string") {
    return new FsError(`cannot write "${path}": ${error.message}`, "FS_IO_ERROR", { cause: error });
  }
  return error;
}
async function writeFileAtomic(absolutePath, content, mode, signal, internals = {}, options = {}) {
  const displayPath = options.displayPath ?? absolutePath;
  const existingDestination = options.existingDestination ?? mode !== void 0;
  throwIfAborted(signal, "write");
  const directory = dirname(absolutePath);
  try {
    await mkdir(directory, { recursive: true });
  } catch (error) {
    throw writeIoError(displayPath, error);
  }
  throwIfAborted(signal, "write");
  const stagingDirName = internals.tempDirName?.(absolutePath) ?? `.${basename(absolutePath)}.${process.pid}.${randomUUID()}.tmpdir`;
  const stagingDir = join(directory, stagingDirName);
  const tempName = internals.tempName?.(absolutePath) ?? `${basename(absolutePath)}.tmp`;
  const tempPath = join(stagingDir, tempName);
  const platform = internals.platform ?? process.platform;
  const copyFileDacl = internals.copyFileDacl ?? copyFileDaclWin32;
  const replaceFile = internals.replaceFile ?? replaceFileWin32;
  const linkFile = internals.linkFile ?? link;
  const inspectPublicationTarget = internals.inspectPublicationTarget ?? ((path) => lstat(path, { bigint: true }));
  const removeStagingDir = internals.removeStagingDir ?? ((path) => rm(path, { recursive: true, force: true }));
  let handle;
  let stagingCreated = false;
  try {
    await mkdir(stagingDir, { mode: 448 });
    stagingCreated = true;
    await chmod(stagingDir, 448);
    handle = await open(tempPath, "wx", 384);
    await handle.chmod(384);
    if (platform === "win32" && existingDestination) {
      await copyFileDacl(absolutePath, tempPath);
    }
    await handle.writeFile(content, { encoding: "utf8", ...signal ? { signal } : {} });
    await handle.sync();
    await internals.inspectTemp?.({ stagingDir, tempPath });
    if (mode !== void 0) await handle.chmod(mode);
    await handle.close();
    handle = void 0;
    throwIfAborted(signal, "write");
    if (options.createIfAbsent) {
      try {
        await linkFile(tempPath, absolutePath);
      } catch (error) {
        await throwGuardedCreateFailure(error, absolutePath, displayPath, inspectPublicationTarget);
      }
    } else if (platform === "win32" && existingDestination) {
      try {
        await replaceFile(absolutePath, tempPath);
      } catch (error) {
        if (!isENOENT(error)) throw error;
        await rename(tempPath, absolutePath);
      }
    } else {
      await rename(tempPath, absolutePath);
    }
    try {
      await removeStagingDir(stagingDir);
    } catch (_committedStagingCleanupFailure) {
    }
  } catch (error) {
    let failure = isAbortError(error) ? new FsError("write aborted", "FS_ABORTED") : writeIoError(displayPath, error);
    if (handle) {
      try {
        await handle.close();
      } catch (closeError) {
        failure = new FsError(`write failed (${errorMessage(failure)}) and temp close failed (${errorMessage(closeError)})`, "FS_NOT_FOUND", { cause: failure });
      }
    }
    if (!stagingCreated) throw failure;
    return removeStagingDirOrThrow(stagingDir, failure, removeStagingDir);
  }
}
async function removeFile(absolutePath, displayPath, internals = {}) {
  try {
    await (internals.removeFile ?? rm)(absolutePath);
  } catch (error) {
    throw new FsError(
      `cannot delete "${displayPath}": ${errorMessage(error)}`,
      isPermissionError(error) ? "FS_PERMISSION_DENIED" : "FS_IO_ERROR",
      { cause: error }
    );
  }
}
function normalizeLineEndings(content) {
  return content.replaceAll("\r\n", "\n");
}
function detectLineEndings(raw) {
  const sample = raw.slice(0, 4096);
  const crlfCount = sample.split("\r\n").length - 1;
  const lfCount = sample.split("\n").length - 1 - crlfCount;
  return crlfCount > lfCount ? "CRLF" : "LF";
}
function restoreLineEndings(content, lineEndings) {
  return lineEndings === "LF" ? content : normalizeLineEndings(content).split("\n").join("\r\n");
}
function countOccurrences(content, needle) {
  let count = 0;
  let index = 0;
  while (true) {
    const found = content.indexOf(needle, index);
    if (found === -1) return count;
    count += 1;
    index = found + needle.length;
  }
}
async function readForEdit(absolutePath, displayPath, signal) {
  throwIfAborted(signal, "edit");
  const buffer = await readFileAbortable(absolutePath, "edit", signal);
  throwIfAborted(signal, "edit");
  if (buffer.includes(0)) throw new FsError(`cannot edit "${displayPath}": binary file`, "FS_NOT_TEXT");
  const raw = decodeUtf8(buffer, "edit", displayPath);
  return { content: normalizeLineEndings(raw), lineEndings: detectLineEndings(raw) };
}
async function readTextForDiff(absolutePath, maxBytes, signal) {
  throwIfAborted(signal, "read");
  try {
    const handle = await open(absolutePath, "r");
    let buffer;
    let total = 0;
    let openedSize = 0;
    try {
      throwIfAborted(signal, "read");
      const info = await handle.stat();
      throwIfAborted(signal, "read");
      if (!info.isFile()) return null;
      if (info.size >= maxBytes) return null;
      openedSize = info.size;
      buffer = Buffer.allocUnsafe(openedSize + 1);
      while (total < buffer.length) {
        throwIfAborted(signal, "read");
        const length = Math.min(buffer.length - total, DIFF_BASIS_READ_CHUNK_BYTES);
        const { bytesRead } = await handle.read(buffer, total, length, null);
        if (bytesRead === 0) break;
        total += bytesRead;
      }
    } finally {
      await handle.close();
    }
    throwIfAborted(signal, "read");
    if (total !== openedSize) return null;
    const basis = buffer.subarray(0, total);
    if (basis.includes(0)) return null;
    try {
      return normalizeLineEndings(new TextDecoder("utf-8", { fatal: true }).decode(basis));
    } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      return null;
    }
  } catch (error) {
    if (error instanceof FsError) throw error;
    if (error instanceof Error && "code" in error) return null;
    throw error;
  }
}
function applyLiteralEdit(content, oldString, newString, replaceAll, displayPath) {
  const oldNorm = normalizeLineEndings(oldString);
  if (oldNorm.length === 0) {
    throw new FsError("old_string must be a non-empty string", "FS_EDIT_NOT_FOUND");
  }
  const newNorm = normalizeLineEndings(newString);
  const replacements = countOccurrences(content, oldNorm);
  if (replacements === 0) {
    throw new FsError(`old_string was not found in "${displayPath}"`, "FS_EDIT_NOT_FOUND");
  }
  if (!replaceAll && replacements > 1) {
    throw new FsError(`old_string matched ${replacements} times in "${displayPath}"; provide a more specific old_string or set replace_all to true`, "FS_AMBIGUOUS_EDIT");
  }
  return { content: content.split(oldNorm).join(newNorm), replacements };
}

// ../../upstream/dsh-0.2.2-rc.1/packages/fs/fs-local/src/index.ts
var DEFAULT_DIFF_BASIS_MAX_BYTES = 10 * 1024 * 1024;
var MAX_DIFF_BASIS_BYTES = Math.min(
  bufferConstants.MAX_LENGTH,
  bufferConstants.MAX_STRING_LENGTH
);
var LocalFileSystem = class extends FileSystem {
  pathAliases = /* @__PURE__ */ new Map();
  registerPathAlias(resolver) {
    return this.ctx.effect(() => {
      this.pathAliases.set(resolver, (this.pathAliases.get(resolver) ?? 0) + 1);
      return () => {
        const remaining = (this.pathAliases.get(resolver) ?? 1) - 1;
        if (remaining === 0) this.pathAliases.delete(resolver);
        else this.pathAliases.set(resolver, remaining);
      };
    }, "fs: path alias");
  }
  async normalizePathAlias(path, options = {}) {
    options.signal?.throwIfAborted();
    let matched;
    for (const resolver of this.pathAliases.keys()) {
      const candidate = await resolver(path, options, this);
      options.signal?.throwIfAborted();
      if (candidate === void 0) continue;
      if (matched !== void 0) throw new FsError2("Multiple filesystem aliases claim this path; use an explicit namespace.", "FS_IO_ERROR");
      matched = candidate;
    }
    return matched ?? { path };
  }
  async watch(target, changed, signal) {
    signal.throwIfAborted();
    const path = resolve2(this.processPath(target));
    const directory = (await this.stat(target, signal))?.type === "directory";
    signal.throwIfAborted();
    const root = directory ? path : dirname2(path);
    const watcher = watch(root, {
      ignoreInitial: true,
      depth: 0,
      ignored: (entry) => !directory && resolve2(entry) !== root && resolve2(entry) !== path
    });
    watcher.on("all", (_event, entry) => {
      if (directory || resolve2(entry) === path) changed();
    });
    watcher.on("error", (error) => {
      changed(error instanceof Error ? error : new Error(String(error)));
    });
    try {
      await once(watcher, "ready", { signal });
      return () => watcher.close();
    } catch (error) {
      await watcher.close();
      throw error;
    }
  }
  static Config = z.object({
    cwd: z.string().default(process.cwd()),
    diffBasisMaxBytes: z.number().default(DEFAULT_DIFF_BASIS_MAX_BYTES)
  });
  /** Validated config (schemastery applied the defaults before construction). */
  config;
  /** Test hook forwarded to fsio for atomic-publication boundaries. */
  internals = {};
  /** Per-targetKey tail promise: serializes mutating ops so the read→guard→write
   * window can't interleave, making concurrent writes/edits deterministically
   * ordered (one wins, the rest see the new version and reject as stale). */
  locks = /* @__PURE__ */ new Map();
  constructor(ctx, config) {
    super(ctx);
    const resolved = config;
    if (!Number.isSafeInteger(resolved.diffBasisMaxBytes) || resolved.diffBasisMaxBytes <= 0 || resolved.diffBasisMaxBytes > MAX_DIFF_BASIS_BYTES) {
      throw new Error(`fs-local: diffBasisMaxBytes must be a positive safe integer no greater than ${MAX_DIFF_BASIS_BYTES}`);
    }
    this.config = resolved;
  }
  /** Run one mutation under the same lock ordering as multi-target operations. */
  withLock(targetKey, op) {
    return this.withLocks([targetKey], op);
  }
  /** Acquire distinct keys in lexical order and release inner locks before outer locks. */
  withLocks(keys, op) {
    const ordered = [...new Set(keys)].sort();
    const acquire = async (index) => {
      const key = ordered[index];
      if (key === void 0) return op();
      const prior = this.locks.get(key) ?? Promise.resolve();
      const run = prior.then(() => acquire(index + 1));
      const tail = run.then(() => void 0, () => void 0);
      this.locks.set(key, tail);
      try {
        return await run;
      } finally {
        if (this.locks.get(key) === tail) this.locks.delete(key);
      }
    };
    return acquire(0);
  }
  async resolve(path, opts) {
    if (opts?.signal?.aborted) throw new FsError2("resolve aborted", "FS_ABORTED");
    const cwd = opts?.cwd ?? this.config.cwd;
    const alias = await this.normalizePathAlias(path, { ...opts, cwd });
    const local = await resolveLocalTarget(cwd, expandHomePrefix(alias.path));
    if (alias.root !== void 0) {
      const root = await resolveLocalTarget(cwd, expandHomePrefix(alias.root));
      if (!this.contains(root, local)) throw new FsError2("Aliased path resolves outside its registered directory.", "FS_PERMISSION_DENIED");
    }
    if (opts?.signal?.aborted) throw new FsError2("resolve aborted", "FS_ABORTED");
    return { targetKey: local.targetKey, displayPath: local.displayPath };
  }
  processPath(target) {
    return String(target.targetKey);
  }
  processPathFromHostPath(hostPath) {
    return isAbsolute2(hostPath) ? resolve2(hostPath) : void 0;
  }
  fileUrl(target) {
    return pathToFileURL(this.processPath(target)).href;
  }
  contains(parent, child) {
    const path = relative(this.processPath(parent), this.processPath(child));
    return path === "" || path !== ".." && !path.startsWith(`..${sep2}`) && !isAbsolute2(path);
  }
  async stat(target, signal) {
    if (signal?.aborted) throw new FsError2("stat aborted", "FS_ABORTED");
    const info = await probe(target.targetKey);
    if (signal?.aborted) throw new FsError2("stat aborted", "FS_ABORTED");
    if (!info) return void 0;
    return { version: info.version, type: info.type, size: info.size };
  }
  async lstat(path, opts, signal) {
    if (signal?.aborted) throw new FsError2("lstat aborted", "FS_ABORTED");
    if (path.trim().length === 0) throw new FsError2("file_path must be a non-empty string", "FS_NOT_FOUND");
    const cwd = opts?.cwd ?? this.config.cwd;
    const alias = await this.normalizePathAlias(path, { cwd, ...signal === void 0 ? {} : { signal } });
    if (alias.root !== void 0) {
      const root = await resolveLocalTarget(cwd, expandHomePrefix(alias.root));
      const parent = await resolveLocalTarget(cwd, dirname2(localDisplayPath(cwd, expandHomePrefix(alias.path))));
      const direct = localDisplayPath(cwd, expandHomePrefix(alias.path)) === localDisplayPath(cwd, expandHomePrefix(alias.root));
      if (!direct && !this.contains(root, parent)) throw new FsError2("Aliased path resolves outside its registered directory.", "FS_PERMISSION_DENIED");
    }
    const info = await probeNoFollow(localDisplayPath(cwd, expandHomePrefix(alias.path)));
    if (signal?.aborted) throw new FsError2("lstat aborted", "FS_ABORTED");
    if (!info) return void 0;
    return { version: info.version, type: info.type, size: info.size };
  }
  async readText(target, signal) {
    return readWholeText({ displayPath: target.displayPath, targetKey: target.targetKey }, signal);
  }
  streamText(target, signal) {
    return Promise.resolve(streamWholeText({ displayPath: target.displayPath, targetKey: target.targetKey }, signal));
  }
  async readBytes(target, signal, maxBytes) {
    return readWholeBytes({ displayPath: target.displayPath, targetKey: target.targetKey }, signal, maxBytes, this.internals);
  }
  async readByteRange(target, range, signal) {
    return readByteWindow({ displayPath: target.displayPath, targetKey: target.targetKey }, range, signal);
  }
  async listDir(target, signal) {
    const entries = await listDirectory({ displayPath: target.displayPath, targetKey: target.targetKey }, signal);
    return entries.map((entry) => ({
      name: entry.name,
      type: entry.type,
      target: { targetKey: entry.target.targetKey, displayPath: entry.target.displayPath },
      ...entry.version !== void 0 ? { version: entry.version } : {},
      ...entry.size !== void 0 ? { size: entry.size } : {}
    }));
  }
  async writeText(target, content, expected, signal) {
    return this.withLock(target.targetKey, async () => {
      const existing = await this.writeTarget(target, expected);
      const diffable = existing !== null && Buffer.byteLength(content, "utf8") < this.config.diffBasisMaxBytes;
      const before = diffable ? await readTextForDiff(target.targetKey, this.config.diffBasisMaxBytes, signal) : null;
      await writeFileAtomic(
        target.targetKey,
        content,
        existing?.mode,
        signal,
        this.internals,
        { displayPath: target.displayPath, createIfAbsent: expected?.kind === "createIfAbsent" }
      );
      const after = await probe(target.targetKey);
      return {
        operation: existing ? "update" : "create",
        version: this.versionAfterWrite(after, target),
        before,
        // LF-normalized to share the diff basis with `before` (also LF): a CRLF
        // overwrite must not read as every line changed. Line-ending restoration
        // is a storage detail the applied-hunk diff ignores.
        after: normalizeLineEndings(content)
      };
    });
  }
  async editText(target, edit, expected, signal) {
    return this.withLock(target.targetKey, async () => {
      const existing = await probe(target.targetKey);
      if (!existing) throw new FsError2(`cannot edit "${target.displayPath}": file changed since it was read`, "FS_STALE_VERSION");
      if (existing.type !== "file") throw new FsError2(`cannot edit "${target.displayPath}": not a regular file`, "FS_NOT_REGULAR_FILE");
      if (expected && existing.version !== expected.version) {
        throw new FsError2(`cannot edit "${target.displayPath}": file changed since it was read`, "FS_STALE_VERSION");
      }
      const original = await readForEdit(target.targetKey, target.displayPath, signal);
      const edited = applyLiteralEdit(original.content, edit.oldString, edit.newString, edit.replaceAll, target.displayPath);
      const content = restoreLineEndings(edited.content, original.lineEndings);
      await writeFileAtomic(target.targetKey, content, existing.mode, signal, this.internals, { displayPath: target.displayPath });
      const after = await probe(target.targetKey);
      return {
        version: this.versionAfterWrite(after, target),
        // The LF-normalized before/after text (the applied-hunk diff basis);
        // line-ending restoration is a storage detail the diff ignores.
        before: original.content,
        after: edited.content
      };
    });
  }
  async patchText(target, hunks, expected, signal) {
    return this.withLock(target.targetKey, async () => {
      const existing = await this.requireFile(target, expected, "patch");
      const original = await readForEdit(target.targetKey, target.displayPath, signal);
      const after = this.patchContent(target, original.content, hunks);
      await writeFileAtomic(
        target.targetKey,
        restoreLineEndings(after, original.lineEndings),
        existing.mode,
        signal,
        this.internals,
        { displayPath: target.displayPath }
      );
      return { version: this.versionAfterWrite(await probe(target.targetKey), target), before: original.content, after };
    });
  }
  async deleteFile(target, expected, signal) {
    return this.withLock(target.targetKey, async () => {
      await this.requireFile(target, expected, "delete");
      const before = await readTextForDiff(target.targetKey, this.config.diffBasisMaxBytes, signal);
      await this.internals.inspectBeforeMutation?.(target);
      if (signal?.aborted) throw new FsError2("delete aborted", "FS_ABORTED");
      await removeFile(target.targetKey, target.displayPath, this.internals);
      return { before };
    });
  }
  async moveFile(source, destination, options, signal) {
    if (source.targetKey === destination.targetKey) {
      throw new FsError2(`cannot move "${source.displayPath}" to itself`, "FS_SAME_TARGET");
    }
    return this.withLocks([source.targetKey, destination.targetKey], async () => {
      const sourceInfo = await this.requireFile(source, options.expectedSource, "move");
      const existing = await this.writeTarget(destination, options.expectedDestination);
      const original = await readForEdit(source.targetKey, source.displayPath, signal);
      const after = options.hunks === void 0 ? original.content : this.patchContent(source, original.content, options.hunks);
      const content = restoreLineEndings(after, original.lineEndings);
      const before = existing && Buffer.byteLength(content, "utf8") < this.config.diffBasisMaxBytes ? await readTextForDiff(destination.targetKey, this.config.diffBasisMaxBytes, signal) : null;
      await this.internals.inspectBeforeMutation?.(source);
      if (signal?.aborted) throw new FsError2("move aborted", "FS_ABORTED");
      await writeFileAtomic(destination.targetKey, content, sourceInfo.mode, void 0, this.internals, {
        displayPath: destination.displayPath,
        createIfAbsent: options.expectedDestination?.kind === "createIfAbsent",
        existingDestination: existing !== null
      });
      const outcome = {
        operation: existing ? "update" : "create",
        version: this.versionAfterWrite(await probe(destination.targetKey), destination),
        before,
        after
      };
      const sourceBefore = Buffer.byteLength(original.content, "utf8") < this.config.diffBasisMaxBytes ? original.content : null;
      try {
        await removeFile(source.targetKey, source.displayPath, this.internals);
      } catch (error) {
        if (!(error instanceof FsError2)) throw error;
        return { sourceBefore, destination: outcome, sourceDeleted: false, sourceFailure: { code: error.code, message: error.message } };
      }
      return { sourceBefore, destination: outcome, sourceDeleted: true };
    });
  }
  async writeTarget(target, expected) {
    const existing = await probe(target.targetKey);
    if (existing && existing.type !== "file") {
      throw new FsError2(`cannot write "${target.displayPath}": not a regular file`, "FS_NOT_REGULAR_FILE");
    }
    if (expected?.kind === "replaceIfVersion") {
      if (!existing) throw new FsError2(`cannot write "${target.displayPath}": file no longer exists`, "FS_STALE_VERSION");
      if (existing.version !== expected.version) {
        throw new FsError2(`cannot write "${target.displayPath}": file changed since it was read`, "FS_STALE_VERSION");
      }
    } else if (expected?.kind === "createIfAbsent" && existing) {
      throw new FsError2(`cannot overwrite existing "${target.displayPath}" without reading it first`, "FS_NOT_OBSERVED");
    }
    return existing;
  }
  async requireFile(target, expected, verb) {
    const existing = await probe(target.targetKey);
    if (!existing) throw new FsError2(`cannot ${verb} "${target.displayPath}": file changed since it was read`, "FS_STALE_VERSION");
    if (existing.type !== "file") throw new FsError2(`cannot ${verb} "${target.displayPath}": not a regular file`, "FS_NOT_REGULAR_FILE");
    if (expected && existing.version !== expected.version) {
      throw new FsError2(`cannot ${verb} "${target.displayPath}": file changed since it was read`, "FS_STALE_VERSION");
    }
    return existing;
  }
  patchContent(target, before, hunks) {
    const result = applyHunks(before, hunks);
    if (!result.ok) {
      throw new FsError2(`cannot patch "${target.displayPath}": hunk at patch line ${result.failure.hunkLineNumber} (${result.failure.stage}) does not match`, "FS_PATCH_MISMATCH");
    }
    return result.after;
  }
  /* v8 ignore next 5 -- the post-write probe finding the file absent requires a
   * concurrent unlink between rename and stat; fall back to a sentinel version. */
  versionAfterWrite(after, target) {
    if (after) return after.version;
    return FsVersion2(`missing:${target.targetKey}`);
  }
};

// ../../upstream/dsh-0.2.2-rc.1/packages/fs/fs-sandbox/src/index.ts
import { FsError as FsError3 } from "@deepseek-ai/dsh-fs";
import { writableRoots } from "@deepseek-ai/dsh-sandbox";

// ../../upstream/dsh-0.2.2-rc.1/packages/fs/fs-sandbox/src/containment.ts
import { stat as stat2 } from "node:fs/promises";
import { dirname as dirname3, sep as sep3 } from "node:path";
var MISSING_CODES = /* @__PURE__ */ new Set(["ENOENT", "ENOTDIR"]);
function isMissing(error) {
  const code = error.code;
  return MISSING_CODES.has(code);
}
function comparablePath(path, caseSensitive) {
  return caseSensitive ? path : path.toLowerCase();
}
function isLexicallyUnder(path, root, caseSensitive) {
  const comparableTarget = comparablePath(path, caseSensitive);
  const comparableRoot = comparablePath(root, caseSensitive);
  if (comparableTarget === comparableRoot) return true;
  const prefix = comparableRoot.endsWith(sep3) ? comparableRoot : comparableRoot + sep3;
  return comparableTarget.startsWith(prefix);
}
async function statIfPresent(path) {
  try {
    return await stat2(path, { bigint: true });
  } catch (error) {
    if (isMissing(error)) return void 0;
    throw error;
  }
}
function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}
async function isPathUnder(path, root, caseSensitive = process.platform !== "win32") {
  if (isLexicallyUnder(path, root, caseSensitive)) return true;
  const rootInfo = await statIfPresent(root);
  if (!rootInfo) return false;
  let ancestor = path;
  while (true) {
    const ancestorInfo = await statIfPresent(ancestor);
    if (ancestorInfo && sameIdentity(ancestorInfo, rootInfo)) return true;
    const parent = dirname3(ancestor);
    if (parent === ancestor) return false;
    ancestor = parent;
  }
}

// ../../upstream/dsh-0.2.2-rc.1/packages/fs/fs-sandbox/src/index.ts
var SandboxedFileSystem = class extends LocalFileSystem {
  static inject = ["sandboxPolicy"];
  defaultMode;
  constructor(ctx, config) {
    super(ctx, config);
    this.defaultMode = ctx.sandboxPolicy.defaultMode;
  }
  /** The deployment default mode — the capability fact the tool layer reads to advertise escalation. */
  get sandboxMode() {
    return this.defaultMode;
  }
  /**
   * Fence the write by the per-call policy, then delegate to the inherited
   * atomic write. See {@link checkedTarget}.
   * @param target - the resolved target to write.
   * @param content - the full new file content.
   * @param expected - the write intent guarding the write; omit for unconditional.
   * @param signal - aborts before atomic publication takes effect.
   * @param sandboxPolicy - the per-call mode and workspace root; omit to use
   *   the deployment fallback.
   * @returns the write outcome from the inherited backend.
   */
  async writeText(target, content, expected, signal, sandboxPolicy) {
    return super.writeText(await this.checkedTarget(target, sandboxPolicy), content, expected, signal);
  }
  /**
   * Fence the edit by the per-call policy, then delegate to the inherited
   * atomic edit. See {@link checkedTarget}.
   * @param target - the resolved target to edit.
   * @param edit - the literal search/replace request.
   * @param expected - the version guard; omit for an unconditional edit.
   * @param signal - aborts before atomic publication takes effect.
   * @param sandboxPolicy - the per-call mode and workspace root; omit to use
   *   the deployment fallback.
   * @returns the edit outcome from the inherited backend.
   */
  async editText(target, edit, expected, signal, sandboxPolicy) {
    return super.editText(await this.checkedTarget(target, sandboxPolicy), edit, expected, signal);
  }
  /**
   * Fence the mutation before delegating to the local provider.
   * @param sandboxPolicy - per-call mode and workspace root; omit for the deployment fallback.
   */
  async patchText(target, hunks, expected, signal, sandboxPolicy) {
    return super.patchText(await this.checkedTarget(target, sandboxPolicy), hunks, expected, signal);
  }
  /**
   * Fence the mutation before delegating to the local provider.
   * @param sandboxPolicy - per-call mode and workspace root; omit for the deployment fallback.
   */
  async deleteFile(target, expected, signal, sandboxPolicy) {
    return super.deleteFile(await this.checkedTarget(target, sandboxPolicy), expected, signal);
  }
  /**
   * Fence the mutation before delegating to the local provider.
   * @param sandboxPolicy - per-call mode and workspace root; omit for the deployment fallback.
   */
  async moveFile(source, destination, options, signal, sandboxPolicy) {
    const checkedSource = await this.checkedTarget(source, sandboxPolicy);
    const checkedDestination = await this.checkedTarget(destination, sandboxPolicy);
    return super.moveFile(checkedSource, checkedDestination, options, signal);
  }
  /**
   * Enforce the per-call policy against `target` and return the EXACT target the
   * mutation must use, so the checked identity is the mutated one (no
   * check-here-write-there TOCTOU). `read-only` denies; `workspace-write`
   * re-canonicalizes NOW (`resolve` realpaths the deepest existing ancestor,
   * reflecting a concurrently swapped symlink), requires containment under a
   * writable root, and returns THAT fresh target; `danger-full-access` returns
   * the caller's target unfenced. Throws the structured `FS_SANDBOX_DENIED` on
   * refusal — the tool layer maps it to the model-facing `[sandbox: …]` marker
   * and the escalation hint.
   */
  async checkedTarget(target, sandboxPolicy) {
    const policy = sandboxPolicy ?? this.ctx.sandboxPolicy.resolve();
    const { mode } = policy;
    if (mode === "danger-full-access") return target;
    if (mode === "read-only") {
      throw new FsError3(`cannot write "${target.displayPath}": file access denied under read-only mode`, "FS_SANDBOX_DENIED");
    }
    const fresh = await this.resolve(target.displayPath);
    let contained = false;
    for (const root of writableRoots(policy)) {
      if (await isPathUnder(fresh.targetKey, root)) {
        contained = true;
        break;
      }
    }
    if (!contained) {
      throw new FsError3(`cannot write "${target.displayPath}": file access denied under workspace-write mode`, "FS_SANDBOX_DENIED");
    }
    return fresh;
  }
};

// src/peer-fs.ts
import z3 from "@deepseek-ai/schemastery";
import { StringDecoder } from "node:string_decoder";
import { gunzipSync as gunzipSync2 } from "node:zlib";

// src/keys.ts
import { createPublicKey as createPublicKey2 } from "node:crypto";
import { chmodSync, closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readSync, writeFileSync } from "node:fs";
import { homedir as homedir2 } from "node:os";
import { dirname as dirname4, isAbsolute as isAbsolute3, join as join2, resolve as resolve3 } from "node:path";

// src/protocol.ts
import { KeyObject, createCipheriv, createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes, timingSafeEqual } from "node:crypto";
import { TextDecoder as TextDecoder2 } from "node:util";
var MAGIC = Buffer.from("DSHR2", "ascii");
var INFO = Buffer.from("dshr2", "ascii");
var DIR_C2S = Buffer.from("C2S", "ascii");
var DIR_S2C = Buffer.from("S2C", "ascii");
var NONCE_LEN = 32;
var TAG_LEN = 32;
var MAX_FRAME = 256 * 1024 * 1024;
var DEFAULT_MAX_FRAME_BYTES = 32 * 1024 * 1024;
var DEFAULT_FRAME_TIMEOUT_MS = 3e4;
var HANDSHAKE_TIMEOUT_MS = 15e3;
var MAX_SEQUENCE = Number.MAX_SAFE_INTEGER;
var MAX_TIMER_MS = 2147483647;
var ZERO_SALT = Buffer.alloc(32);
var HandshakeError = class extends Error {
  name = "HandshakeError";
};
function hmac(key, data) {
  return createHmac("sha256", key).update(data).digest();
}
function hkdf(ikm, salt, info, length) {
  if (!Buffer.isBuffer(ikm) || !Buffer.isBuffer(salt) || !Buffer.isBuffer(info) || !Number.isSafeInteger(length) || length < 1 || length > 255 * 32) throw new HandshakeError("invalid HKDF parameters");
  const prk = hmac(salt, ikm);
  const blocks = [];
  let block = Buffer.alloc(0);
  let counter = 1;
  let total = 0;
  while (total < length) {
    block = hmac(prk, Buffer.concat([block, info, Buffer.from([counter])]));
    blocks.push(block);
    total += block.length;
    counter += 1;
  }
  return Buffer.concat(blocks).subarray(0, length);
}
function deriveSessionKey(shared, cNonce, sNonce) {
  return hkdf(shared, Buffer.concat([cNonce, sNonce]), INFO, 32);
}
function handshakeTag(key, who, transcript) {
  return hmac(key, Buffer.concat([who, transcript]));
}
function requireKey(key, role) {
  if (!(key instanceof KeyObject) || key.type !== role || key.asymmetricKeyType !== "x25519") throw new HandshakeError(`expected an X25519 ${role} key`);
}
function rawPublic(key) {
  requireKey(key, "public");
  const der = key.export({ type: "spki", format: "der" });
  const prefix = Buffer.from("302a300506032b656e032100", "hex");
  if (der.length !== prefix.length + 32 || !der.subarray(0, prefix.length).equals(prefix)) throw new HandshakeError("invalid X25519 public key encoding");
  return Buffer.from(der.subarray(prefix.length));
}
function publicFromRaw(raw) {
  if (!Buffer.isBuffer(raw) || raw.length !== 32) throw new HandshakeError("X25519 public key must be exactly 32 bytes");
  const prefix = Buffer.from("302a300506032b656e032100", "hex");
  try {
    return createPublicKey({ key: Buffer.concat([prefix, raw]), format: "der", type: "spki" });
  } catch {
    throw new HandshakeError("invalid X25519 public key encoding");
  }
}
function generateKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  return { privateKey, publicKey };
}
function parsePrivateKey(text2) {
  try {
    const trimmed = keyText(text2);
    let key;
    if (trimmed.startsWith("-----BEGIN")) {
      if (!/^-----BEGIN PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PRIVATE KEY-----$/u.test(trimmed)) throw new HandshakeError("expected one unencrypted PKCS8 private key");
      key = createPrivateKey(trimmed);
    } else {
      const raw = decodeRaw(trimmed, "private");
      const prefix = Buffer.from("302e020100300506032b656e04220420", "hex");
      key = createPrivateKey({ key: Buffer.concat([prefix, raw]), format: "der", type: "pkcs8" });
    }
    requireKey(key, "private");
    return key;
  } catch {
    throw new HandshakeError("invalid X25519 private key; expected PKCS8 PEM, 64 hex characters or canonical base64 of 32 bytes");
  }
}
function parsePublicKey(text2) {
  try {
    const trimmed = keyText(text2);
    let key;
    if (trimmed.startsWith("-----BEGIN")) {
      if (!/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PUBLIC KEY-----$/u.test(trimmed)) throw new HandshakeError("expected one SPKI public key");
      key = createPublicKey(trimmed);
    } else key = publicFromRaw(decodeRaw(trimmed, "public"));
    requireKey(key, "public");
    return key;
  } catch {
    throw new HandshakeError("invalid X25519 public key; expected SPKI PEM, 64 hex characters or canonical base64 of 32 bytes");
  }
}
function keyText(text2) {
  if (typeof text2 !== "string" || text2.length > 8192 || text2.trim() === "") throw new HandshakeError("invalid key text");
  return text2.trim();
}
function decodeRaw(text2, what) {
  if (/^[0-9a-fA-F]{64}$/u.test(text2)) return Buffer.from(text2, "hex");
  if (/^[A-Za-z0-9+/]{43}=$/u.test(text2)) {
    const decoded = Buffer.from(text2, "base64");
    if (decoded.length === 32 && decoded.toString("base64") === text2) return decoded;
  }
  throw new HandshakeError(`invalid canonical X25519 ${what} key encoding`);
}
function privateToPem(key) {
  requireKey(key, "private");
  return key.export({ type: "pkcs8", format: "pem" }).toString();
}
var closingSockets = /* @__PURE__ */ new WeakMap();
function destroySocket(socket, alreadyClosed = false) {
  if (!alreadyClosed && !closingSockets.has(socket)) {
    const ignore = () => {
    };
    const cleanup = () => {
      socket.off("error", ignore);
      socket.off("close", cleanup);
      closingSockets.delete(socket);
    };
    closingSockets.set(socket, cleanup);
    socket.on("error", ignore);
    socket.once("close", cleanup);
  }
  socket.destroy();
  if (alreadyClosed) closingSockets.get(socket)?.();
}
var ByteReader = class {
  ended = false;
  disposed = false;
  busy = false;
  failure;
  waiting;
  sock;
  finish = () => {
    this.ended = true;
    this.waiting?.();
  };
  failed = () => {
    this.failure = new HandshakeError("socket read failed");
    this.finish();
  };
  constructor(sock) {
    this.sock = sock;
    sock.pause();
    sock.on("end", this.finish);
    sock.on("close", this.finish);
    sock.on("error", this.failed);
  }
  /** Detach every owned listener and release any pending reader immediately. */
  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    this.ended = true;
    this.sock.off("end", this.finish);
    this.sock.off("close", this.finish);
    this.sock.off("error", this.failed);
    this.waiting?.();
  }
  async readable(deadline) {
    if (deadline !== 0 && deadline <= Date.now()) throw new HandshakeError("socket read deadline exceeded");
    await new Promise((resolve4, reject) => {
      let timer;
      let settled = false;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        if (timer !== void 0) clearTimeout(timer);
        this.sock.off("readable", wake);
        this.waiting = void 0;
        if (error === void 0) resolve4();
        else reject(error);
      };
      const wake = () => {
        finish();
      };
      this.waiting = wake;
      this.sock.once("readable", wake);
      if (deadline !== 0) timer = setTimeout(() => finish(new HandshakeError("socket read deadline exceeded")), Math.max(1, deadline - Date.now()));
      if (this.ended || this.disposed || this.sock.destroyed || this.sock.readableEnded || this.sock.readableLength !== 0) wake();
    });
  }
  /**
   * Read exactly n bytes; null means EOF before any byte, never a partial read.
   * timeoutMs=0 allows idle waits. A frame header may defer a positive deadline
   * until its first byte; body reads never defer. No flowing data listener or
   * application-owned backlog is installed, so TCP backpressure remains active.
   */
  async read(n, timeoutMs = 0, options = {}) {
    if (!Number.isSafeInteger(n) || n < 0 || n > MAX_FRAME || !Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > MAX_TIMER_MS) throw new HandshakeError("invalid socket read parameters");
    if (this.busy) throw new HandshakeError("concurrent socket reads are not allowed");
    if (n === 0) return Buffer.alloc(0);
    if (this.disposed) throw new HandshakeError("socket reader is closed");
    this.busy = true;
    let deadline = timeoutMs > 0 && options.startTimeoutOnData !== true ? Date.now() + timeoutMs : 0;
    const output = Buffer.allocUnsafe(n);
    let offset = 0;
    try {
      while (offset < n) {
        if (this.disposed) {
          if (offset === 0 && this.sock.readableEnded && this.failure === void 0) return null;
          throw new HandshakeError("socket reader is closed");
        }
        if (this.failure !== void 0) throw this.failure;
        if (deadline !== 0 && Date.now() >= deadline) throw new HandshakeError("socket read deadline exceeded");
        const available = this.sock.readableLength;
        if (available > 0) {
          const chunk = this.sock.read(Math.min(n - offset, available, 64 * 1024));
          if (chunk !== null) {
            if (offset === 0) {
              if (deadline === 0 && timeoutMs > 0) deadline = Date.now() + timeoutMs;
              options.onFirstByte?.();
            }
            chunk.copy(output, offset);
            offset += chunk.length;
            continue;
          }
        }
        if (this.ended || this.sock.destroyed || this.sock.readableEnded) {
          if (offset === 0) {
            this.dispose();
            return null;
          }
          throw new HandshakeError("peer truncated a socket field");
        }
        await this.readable(deadline);
      }
      return output;
    } catch (error) {
      destroySocket(this.sock);
      this.dispose();
      throw error instanceof HandshakeError ? error : new HandshakeError("socket read failed");
    } finally {
      this.busy = false;
    }
  }
};
function seal(key, counter, direction, plaintext) {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const nonce = Buffer.concat([Buffer.alloc(4), counterBuf]);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.concat([direction, counterBuf]));
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}
function open2(key, counter, direction, body) {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const nonce = Buffer.concat([Buffer.alloc(4), counterBuf]);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(Buffer.concat([direction, counterBuf]));
  decipher.setAuthTag(body.subarray(body.length - 16));
  return Buffer.concat([decipher.update(body.subarray(0, body.length - 16)), decipher.final()]);
}
function sessionOptions(options) {
  const maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;
  const output = {
    maxFrameBytes,
    frameTimeoutMs: options.frameTimeoutMs ?? DEFAULT_FRAME_TIMEOUT_MS,
    maxQueuedBytes: options.maxQueuedBytes ?? 2 * (maxFrameBytes + 4),
    maxPendingSends: options.maxPendingSends ?? 64
  };
  for (const [value, minimum, maximum] of [
    [output.maxFrameBytes, 18, MAX_FRAME],
    [output.frameTimeoutMs, 1, MAX_TIMER_MS],
    [output.maxQueuedBytes, 22, 2 * (MAX_FRAME + 4)],
    [output.maxPendingSends, 1, 1024]
  ]) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new HandshakeError("invalid encrypted session limits");
  }
  return output;
}
function jsonRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
async function writeSocket(socket, frame, timeoutMs) {
  await new Promise((resolve4, reject) => {
    let finished = false;
    let returned = false;
    let callbackDone = false;
    let drained = false;
    const finish = (error) => {
      if (finished) return;
      if (error === void 0 && (!returned || !callbackDone || !drained)) return;
      finished = true;
      clearTimeout(timer);
      socket.off("drain", drain);
      socket.off("close", closed);
      socket.off("error", failed);
      if (error === void 0) resolve4();
      else reject(error);
    };
    const drain = () => {
      drained = true;
      finish();
    };
    const closed = () => finish(new HandshakeError("socket closed during write"));
    const failed = () => finish(new HandshakeError("socket write failed"));
    const timer = setTimeout(() => {
      finish(new HandshakeError("socket write deadline exceeded"));
      destroySocket(socket);
    }, timeoutMs);
    socket.on("drain", drain);
    socket.once("close", closed);
    socket.once("error", failed);
    if (socket.destroyed || !socket.writable) {
      closed();
      return;
    }
    try {
      const accepted = socket.write(frame, (error) => {
        callbackDone = true;
        if (error !== void 0 && error !== null) failed();
        else finish();
      });
      returned = true;
      if (accepted) drained = true;
      finish();
    } catch {
      failed();
    }
  });
}
var Session = class {
  sendCounter = 0;
  recvCounter = 0;
  sendKey;
  recvKey;
  sendDir;
  recvDir;
  limits;
  queue = [];
  queuedBytes = 0;
  pendingSends = 0;
  sending = false;
  receiving = false;
  failure;
  onClose = () => {
    this.terminate(new HandshakeError("encrypted session closed"), true);
  };
  onError = () => {
    this.terminate(new HandshakeError("encrypted socket failed"));
  };
  bytesSent = 0;
  bytesReceived = 0;
  socket;
  reader;
  constructor(socket, reader, key, initiator, options = {}) {
    if (!Buffer.isBuffer(key) || key.length !== 32 || typeof initiator !== "boolean") throw new HandshakeError("invalid encrypted session parameters");
    this.limits = sessionOptions(options);
    this.socket = socket;
    this.reader = reader;
    const kC2S = hkdf(key, ZERO_SALT, Buffer.concat([INFO, Buffer.from(" c2s")]), 32);
    const kS2C = hkdf(key, ZERO_SALT, Buffer.concat([INFO, Buffer.from(" s2c")]), 32);
    this.sendKey = initiator ? kC2S : kS2C;
    this.recvKey = initiator ? kS2C : kC2S;
    this.sendDir = initiator ? DIR_C2S : DIR_S2C;
    this.recvDir = initiator ? DIR_S2C : DIR_C2S;
    socket.once("close", this.onClose);
    socket.on("error", this.onError);
  }
  terminate(error, alreadyClosed = false) {
    if (this.failure !== void 0) return this.failure;
    this.failure = error;
    for (const item of this.queue.splice(0)) {
      this.pendingSends--;
      this.queuedBytes -= item.bytes;
      item.plaintext.fill(0);
      item.reject(error);
    }
    this.socket.off("close", this.onClose);
    this.socket.off("error", this.onError);
    this.reader.dispose();
    destroySocket(this.socket, alreadyClosed);
    this.sendKey.fill(0);
    this.recvKey.fill(0);
    return error;
  }
  /** Serialize immediately, but admit only a bounded count/byte queue. */
  async send(payload) {
    if (this.failure !== void 0) throw this.failure;
    if (this.pendingSends >= this.limits.maxPendingSends) throw new HandshakeError("encrypted send queue is full");
    if (!jsonRecord(payload)) throw new HandshakeError("encrypted messages must be JSON records");
    let serialized;
    try {
      serialized = JSON.stringify(payload);
      if (typeof serialized !== "string") throw new Error();
    } catch {
      throw new HandshakeError("encrypted message is not serializable JSON");
    }
    const bytes = Buffer.byteLength(serialized, "utf8") + 20;
    if (bytes - 4 > this.limits.maxFrameBytes) throw new HandshakeError("encrypted message exceeds frame limit");
    if (bytes + this.queuedBytes > this.limits.maxQueuedBytes) throw new HandshakeError("encrypted send byte queue is full");
    try {
      if (!jsonRecord(JSON.parse(serialized))) throw new Error();
    } catch {
      throw new HandshakeError("encrypted messages must serialize to JSON records");
    }
    await new Promise((resolve4, reject) => {
      this.queue.push({ plaintext: Buffer.from(serialized, "utf8"), bytes, resolve: resolve4, reject });
      this.queuedBytes += bytes;
      this.pendingSends++;
      void this.flush();
    });
  }
  async flush() {
    if (this.sending) return;
    this.sending = true;
    try {
      while (this.queue.length !== 0 && this.failure === void 0) {
        const item = this.queue.shift();
        try {
          if (!Number.isSafeInteger(this.sendCounter) || this.sendCounter < 0 || this.sendCounter >= MAX_SEQUENCE) throw new HandshakeError("encrypted send sequence exhausted");
          const next = this.sendCounter + 1;
          const body = seal(this.sendKey, next, this.sendDir, item.plaintext);
          const frame = Buffer.allocUnsafe(body.length + 4);
          frame.writeUInt32BE(body.length, 0);
          body.copy(frame, 4);
          this.sendCounter = next;
          await writeSocket(this.socket, frame, this.limits.frameTimeoutMs);
          if (this.failure !== void 0) throw this.failure;
          this.bytesSent += frame.length;
          item.resolve();
        } catch (error) {
          item.reject(this.terminate(error instanceof HandshakeError ? error : new HandshakeError("encrypted send failed")));
        } finally {
          this.pendingSends--;
          this.queuedBytes -= item.bytes;
          item.plaintext.fill(0);
        }
      }
    } finally {
      this.sending = false;
    }
  }
  /** Receive one record. Only EOF before a new header is a clean null result. */
  async recv(timeoutMs = 0) {
    if (this.failure !== void 0) throw this.failure;
    if (this.receiving) throw new HandshakeError("concurrent encrypted receives are not allowed");
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > MAX_TIMER_MS) throw new HandshakeError("invalid receive deadline");
    this.receiving = true;
    const total = timeoutMs === 0 ? this.limits.frameTimeoutMs : Math.min(timeoutMs, this.limits.frameTimeoutMs);
    let deadline = timeoutMs === 0 ? 0 : Date.now() + total;
    try {
      if (!Number.isSafeInteger(this.recvCounter) || this.recvCounter < 0 || this.recvCounter >= MAX_SEQUENCE) throw new HandshakeError("encrypted receive sequence exhausted");
      const header = await this.reader.read(4, total, {
        startTimeoutOnData: timeoutMs === 0,
        onFirstByte: () => {
          if (deadline === 0) deadline = Date.now() + total;
        }
      });
      if (header === null) {
        this.close();
        return null;
      }
      const length = header.readUInt32BE(0);
      if (length < 18 || length > this.limits.maxFrameBytes) throw new HandshakeError("encrypted frame length exceeds allowed bounds");
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new HandshakeError("encrypted frame deadline exceeded");
      const body = await this.reader.read(length, remaining);
      if (body === null) throw new HandshakeError("peer truncated an encrypted frame");
      const next = this.recvCounter + 1;
      const plaintext = open2(this.recvKey, next, this.recvDir, body);
      let payload;
      try {
        payload = JSON.parse(new TextDecoder2("utf-8", { fatal: true }).decode(plaintext));
      } finally {
        plaintext.fill(0);
      }
      if (!jsonRecord(payload)) throw new HandshakeError("encrypted message is not a JSON record");
      this.recvCounter = next;
      this.bytesReceived += 4 + length;
      return payload;
    } catch (error) {
      throw this.terminate(error instanceof HandshakeError ? error : new HandshakeError("encrypted frame authentication or JSON parsing failed"));
    } finally {
      this.receiving = false;
    }
  }
  /** Fail queued work, release listeners and destroy the underlying socket. */
  close() {
    this.terminate(new HandshakeError("encrypted session closed"));
  }
};
function ecdh(privateKey, publicKey) {
  requireKey(privateKey, "private");
  requireKey(publicKey, "public");
  try {
    return diffieHellman({ privateKey, publicKey });
  } catch {
    throw new HandshakeError("X25519 key agreement failed");
  }
}
function handshakeRemaining(deadline) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new HandshakeError("DSHR2 handshake deadline exceeded");
  return remaining;
}
function transcriptOf(cEphPub, sEphPub, cNonce, sNonce) {
  return Buffer.concat([MAGIC, cEphPub, sEphPub, cNonce, sNonce]);
}
async function clientHandshake(socket, clientKey, serverKey, options = {}) {
  const reader = new ByteReader(socket);
  const deadline = Date.now() + HANDSHAKE_TIMEOUT_MS;
  let key;
  try {
    requireKey(clientKey, "private");
    requireKey(serverKey, "public");
    sessionOptions(options);
    const eph = generateKeyPair();
    const cEphRaw = rawPublic(eph.publicKey);
    const cNonce = randomBytes(NONCE_LEN);
    await writeSocket(socket, Buffer.concat([MAGIC, cEphRaw, cNonce]), handshakeRemaining(deadline));
    const reply = await reader.read(MAGIC.length + 32 + NONCE_LEN + TAG_LEN, handshakeRemaining(deadline));
    if (reply === null) throw new HandshakeError("peer closed during handshake");
    if (!reply.subarray(0, MAGIC.length).equals(MAGIC)) throw new HandshakeError("peer did not answer with the protocol magic");
    const sEphRaw = reply.subarray(MAGIC.length, MAGIC.length + 32);
    const sNonce = reply.subarray(MAGIC.length + 32, MAGIC.length + 32 + NONCE_LEN);
    const tagS = reply.subarray(reply.length - TAG_LEN);
    const shared = Buffer.concat([
      ecdh(eph.privateKey, publicFromRaw(sEphRaw)),
      ecdh(eph.privateKey, serverKey),
      ecdh(clientKey, publicFromRaw(sEphRaw))
    ]);
    try {
      key = deriveSessionKey(shared, cNonce, sNonce);
    } finally {
      shared.fill(0);
    }
    const transcript = transcriptOf(cEphRaw, sEphRaw, cNonce, sNonce);
    const expected = handshakeTag(key, Buffer.from("dshr2 server"), transcript);
    if (!timingSafeEqual(tagS, expected)) throw new HandshakeError("server authentication FAILED \u2014 wrong pinned server key, or a man-in-the-middle on the tunnel");
    await writeSocket(socket, handshakeTag(key, Buffer.from("dshr2 client"), transcript), handshakeRemaining(deadline));
    return new Session(socket, reader, key, true, options);
  } catch (error) {
    destroySocket(socket);
    reader.dispose();
    throw error instanceof HandshakeError ? error : new HandshakeError("DSHR2 client handshake failed");
  } finally {
    key?.fill(0);
  }
}

// src/keys.ts
function text(value) {
  return value === void 0 || value.trim() === "" ? void 0 : value;
}
function dshHomePath(...segments) {
  const home = text(process.env.DSH_HOME) ?? join2(homedir2(), ".dsh");
  return join2(home, ...segments);
}
function absolute(path) {
  return isAbsolute3(path) ? path : resolve3(process.cwd(), path);
}
function harden(path) {
  try {
    chmodSync(path, 384);
  } catch {
  }
}
function readKeyFile(file, privateMaterial) {
  const link2 = lstatSync(file);
  if (!link2.isFile() || link2.isSymbolicLink() || link2.size > 16384) throw new Error("dsh-remote: key file must be a regular file of at most 16 KiB");
  const fd = openSync(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > 16384 || info.dev !== link2.dev || info.ino !== link2.ino) throw new Error("dsh-remote: key file changed while opening");
    if (privateMaterial && process.platform !== "win32" && (info.mode & 63) !== 0) throw new Error("dsh-remote: private key permissions must be owner-only (chmod 600)");
    const bytes = Buffer.alloc(16385);
    let length = 0;
    for (; ; ) {
      const count = readSync(fd, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
      if (length > 16384) throw new Error("dsh-remote: key file exceeds 16 KiB");
    }
    return bytes.subarray(0, length).toString("utf8");
  } finally {
    closeSync(fd);
  }
}
function resolvePrivateKey(settings, defaultFileName) {
  const inline = text(settings.privateKey);
  if (inline !== void 0) {
    const key = parsePrivateKey(inline);
    return {
      key,
      publicKey: createPublicKey2(key),
      pem: privateToPem(key),
      generated: false
    };
  }
  const file = absolute(
    text(settings.privateKeyFile) ?? dshHomePath("dsh-remote", defaultFileName)
  );
  if (existsSync(file)) {
    const key = parsePrivateKey(readKeyFile(file, true));
    return {
      key,
      publicKey: createPublicKey2(key),
      pem: privateToPem(key),
      generated: false,
      file
    };
  }
  if (settings.autoGenerateKey === false) {
    throw new Error(
      `dsh-remote: no private key configured and autoGenerateKey is off (looked for ${file})`
    );
  }
  const { privateKey } = generateKeyPair();
  const pem = privateToPem(privateKey);
  mkdirSync(dirname4(file), { recursive: true, mode: 448 });
  try {
    writeFileSync(file, pem, { encoding: "utf8", mode: 384, flag: "wx" });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const existing = parsePrivateKey(readKeyFile(file, true));
    return { key: existing, publicKey: createPublicKey2(existing), pem: privateToPem(existing), generated: false, file };
  }
  harden(file);
  return { key: privateKey, publicKey: createPublicKey2(privateKey), pem, generated: true, file };
}
function resolvePeerPublicKey(settings, defaultFileName) {
  const inline = text(settings.peerPublicKey);
  if (inline !== void 0) return parsePublicKey(inline);
  const file = absolute(
    text(settings.peerPublicKeyFile) ?? dshHomePath("dsh-remote", defaultFileName)
  );
  if (existsSync(file)) return parsePublicKey(readKeyFile(file, false));
  throw new Error(
    `dsh-remote: no peer public key configured (looked for ${file}). Copy the peer's public key there, or paste it into the peerPublicKey setting.`
  );
}

// src/link.ts
import { createHash as createHash2 } from "node:crypto";
var KEY_SELECTOR_MAGIC = Buffer.from("DSHP1", "ascii");
var KEY_SELECTOR_ACK = Buffer.from("DSHA1", "ascii");
var KEY_SELECTOR_DENIED = Buffer.from("DSHD1", "ascii");
async function readHandshakeField(socket, bytes) {
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > 4096) throw new HandshakeError("invalid handshake field size");
  return await new Promise((resolve4, reject) => {
    let settled = false;
    const finish = (value, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.off("readable", readable);
      socket.off("end", ended);
      socket.off("close", ended);
      socket.off("error", failed);
      if (error !== void 0) reject(error);
      else resolve4(value);
    };
    const readable = () => {
      const data = socket.read(bytes);
      if (data !== null) finish(data);
      else if (socket.destroyed || socket.readableEnded) finish(null);
    };
    const ended = () => {
      finish(null);
    };
    const failed = (error) => {
      finish(null, error);
    };
    const timer = setTimeout(() => {
      finish(null, new HandshakeError("key selector timed out"));
    }, HANDSHAKE_TIMEOUT_MS);
    timer.unref?.();
    socket.on("readable", readable);
    socket.once("end", ended);
    socket.once("close", ended);
    socket.once("error", failed);
    readable();
  });
}
var PeerResponseError = class extends Error {
};
var RequestTimeoutError = class extends Error {
};
var REPLAY_SAFE_OPS = /* @__PURE__ */ new Set([
  "ping",
  "sysinfo",
  "fs.read",
  "fs.list",
  "fs.stat",
  "fs.hash",
  "fs.get",
  "journal.read",
  "caps.list",
  "references.list",
  "agent.events",
  "agent.sessions",
  "agent.presets",
  "usage.read"
]);
var MAX_PENDING_REQUESTS = 256;
var MAX_TIMER_MS2 = 2147483647;
function boundedTimeout(value, fallback, maximum = MAX_TIMER_MS2) {
  const number = value === void 0 ? fallback : value;
  if (typeof number !== "number" || !Number.isSafeInteger(number) || number < 1 || number > maximum) {
    throw new HandshakeError(`invalid timeout: expected an integer from 1 to ${maximum} ms`);
  }
  return number;
}
var LinkClient = class {
  session;
  dialing;
  generation = 0;
  counter = 0;
  connecting = /* @__PURE__ */ new Set();
  admitted = /* @__PURE__ */ new Map();
  expiryTimer;
  disposed = false;
  waiting = /* @__PURE__ */ new Map();
  /** Handler for frames the PEER initiates (anything carrying a `kind`). */
  eventHandler;
  disconnectHandler;
  socketFactory;
  // Plain fields rather than constructor parameter properties: this plugin is
  // loaded as raw TS by a harness that strips types in Node's strip-only mode,
  // where parameter properties are a hard load error.
  read;
  log;
  label;
  /**
   * @param read - live accessor for the endpoint; re-read on every dial so a
   *   settings change takes effect without reloading the module.
   * @param log - one-line logger for connect/failure notices.
   * @param label - prefix used in log messages and errors (usually the plugin
   *   name, or `peer <name>` for a federated endpoint).
   */
  constructor(read, log, label = "dsh-remote", socketFactory) {
    this.read = read;
    this.log = log;
    this.label = label;
    this.socketFactory = socketFactory;
  }
  /** Open a fresh authenticated session. */
  async dial() {
    const { connect } = await import("node:net");
    const config = this.read();
    const host = text(config.host);
    const port = config.port ?? 0;
    const timeout = boundedTimeout(config.timeoutMs, 12e4, 6e5);
    const maxSessionMs = boundedTimeout(config.maxSessionMs, 36e5, 36e5);
    if (maxSessionMs < 100) throw new HandshakeError("maximum session lifetime must be at least 100 ms");
    const routed = text(config.relayTarget);
    if (config.relayTarget !== void 0 && config.relayTarget !== "" && routed === void 0) throw new HandshakeError("invalid relay target identity");
    if (routed !== void 0 && (!/^[A-Za-z0-9._-]{2,128}$/u.test(routed) || ["rmt", ".", "..", "__proto__", "constructor", "prototype"].includes(routed.toLowerCase()))) throw new HandshakeError("invalid relay target identity");
    if (routed !== void 0 && this.socketFactory === void 0) throw new HandshakeError("mesh transport is unavailable; enable the mesh plugin before using relayTarget");
    if (routed === void 0 && (host === void 0 || /[\u0000-\u0020\u007f]/u.test(host) || !Number.isInteger(port) || port < 1 || port > 65535)) {
      throw new HandshakeError(
        `${this.label}: set \`host\` and \`port\` to the peer's reachable endpoint. Fill them in \u2014 for example the host:port your frp tunnel hands out.`
      );
    }
    let identity;
    let pinned;
    try {
      identity = resolvePrivateKey(config, "client.key");
      pinned = resolvePeerPublicKey(config, "server.pub");
    } catch (error) {
      throw new HandshakeError(`${this.label}: invalid key configuration (${error instanceof Error ? error.message : "unavailable"})`);
    }
    const open3 = async () => {
      if (this.disposed) throw new HandshakeError(`${this.label}: link disposed`);
      if (routed !== void 0) {
        const startedGeneration = this.generation;
        let expired = false;
        let timer;
        const pending = this.socketFactory(config).then((socket3) => {
          if (expired || this.disposed || startedGeneration !== this.generation) {
            socket3.destroy();
            throw new HandshakeError("mesh dial was cancelled");
          }
          this.connecting.add(socket3);
          socket3.once("close", () => {
            this.connecting.delete(socket3);
          });
          socket3.setNoDelay(true);
          socket3.setTimeout(0);
          return socket3;
        });
        try {
          return await Promise.race([pending, new Promise((_resolve, reject) => {
            timer = setTimeout(() => {
              expired = true;
              reject(new HandshakeError("mesh dial timed out"));
            }, timeout);
          })]);
        } finally {
          if (timer !== void 0) clearTimeout(timer);
        }
      }
      const socket2 = connect({ host, port });
      this.connecting.add(socket2);
      socket2.once("close", () => {
        this.connecting.delete(socket2);
      });
      try {
        await new Promise((resolve4, reject) => {
          const clean = () => {
            clearTimeout(timer);
            socket2.off("connect", connected);
            socket2.off("error", failed);
            socket2.off("close", closed);
          };
          const connected = () => {
            clean();
            resolve4();
          };
          const failed = (error) => {
            clean();
            reject(error);
          };
          const closed = () => {
            clean();
            reject(new HandshakeError(`${this.label}: connection closed while dialing`));
          };
          const timer = setTimeout(() => {
            clean();
            socket2.destroy();
            reject(new Error(`${this.label}: connect to ${host}:${port} timed out after ${timeout} ms`));
          }, timeout);
          socket2.once("connect", connected);
          socket2.once("error", failed);
          socket2.once("close", closed);
        });
        socket2.setNoDelay(true);
        socket2.setTimeout(0);
        return socket2;
      } catch (error) {
        socket2.destroy();
        throw error;
      }
    };
    let socket = await open3();
    let authenticationTimedOut = false;
    const authenticationDeadline = setTimeout(() => {
      authenticationTimedOut = true;
      socket.destroy();
    }, HANDSHAKE_TIMEOUT_MS);
    authenticationDeadline.unref?.();
    try {
      socket.write(Buffer.concat([KEY_SELECTOR_MAGIC, rawPublic(identity.publicKey), Buffer.alloc(32)]));
      const ack = await readHandshakeField(socket, KEY_SELECTOR_ACK.length);
      if (ack !== null && ack.equals(KEY_SELECTOR_DENIED)) {
        throw new HandshakeError("server refused the selected client key");
      }
      if (ack === null || !ack.equals(KEY_SELECTOR_ACK)) {
        if (authenticationTimedOut || config.allowLegacyHandshake !== true) {
          throw new HandshakeError("peer did not acknowledge key selection; legacy handshake is disabled");
        }
        socket.destroy();
        socket = await open3();
      }
      if (authenticationTimedOut) throw new HandshakeError("authentication deadline exceeded");
      const session = await clientHandshake(socket, identity.key, pinned);
      if (authenticationTimedOut) {
        session.close();
        throw new HandshakeError("authentication deadline exceeded");
      }
      this.connecting.delete(socket);
      this.admitted.set(session, {
        config: this.configurationId(config),
        identity: this.keyId(identity.publicKey),
        pin: this.keyId(pinned),
        expiresAt: Date.now() + maxSessionMs
      });
      this.log(`${this.label}: authenticated with ${routed === void 0 ? `${host}:${port}` : `mesh node ${routed}`}`);
      return session;
    } catch (error) {
      socket.destroy();
      if (authenticationTimedOut) throw new HandshakeError("authentication deadline exceeded");
      throw error;
    } finally {
      clearTimeout(authenticationDeadline);
    }
  }
  keyId(key) {
    return createHash2("sha256").update(rawPublic(key)).digest("hex");
  }
  configurationId(config) {
    return createHash2("sha256").update(JSON.stringify([
      config.host,
      config.port,
      config.privateKey,
      config.privateKeyFile,
      config.autoGenerateKey,
      config.peerPublicKey,
      config.peerPublicKeyFile,
      config.allowLegacyHandshake === true,
      config.maxSessionMs ?? 36e5,
      config.relayTarget ?? ""
    ])).digest("hex");
  }
  /** Revalidate live pins, including files, before reusing a channel. */
  validateSession(session) {
    const admitted = this.admitted.get(session);
    const current = this.read();
    try {
      if (admitted === void 0 || Date.now() >= admitted.expiresAt || this.configurationId(current) !== admitted.config || this.keyId(resolvePeerPublicKey(current, "server.pub")) !== admitted.pin || this.keyId(resolvePrivateKey({ ...current, autoGenerateKey: false }, "client.key").publicKey) !== admitted.identity) {
        throw new HandshakeError(`${this.label}: authenticated peer identity changed or connection expired`);
      }
    } catch (error) {
      const failure = error instanceof HandshakeError ? error : new HandshakeError(`${this.label}: peer identity is no longer valid`);
      this.failSession(session, failure);
      throw failure;
    }
  }
  async ensure() {
    if (this.disposed) throw new HandshakeError(`${this.label}: link disposed`);
    if (this.session !== void 0) {
      this.validateSession(this.session);
      return this.session;
    }
    if (this.dialing === void 0) {
      const generation = this.generation;
      const dialing = this.dial().then((session) => {
        if (generation !== this.generation) {
          session.close();
          throw new Error(`${this.label}: link closed while connecting`);
        }
        this.validateSession(session);
        this.session = session;
        const admitted = this.admitted.get(session);
        this.expiryTimer = setTimeout(() => this.failSession(session, new HandshakeError(`${this.label}: authenticated connection lifetime expired`)), Math.max(1, admitted.expiresAt - Date.now()));
        this.expiryTimer.unref?.();
        this.startPump(session);
        return session;
      }).finally(() => {
        if (this.dialing === dialing) this.dialing = void 0;
      });
      this.dialing = dialing;
    }
    return this.dialing;
  }
  /**
   * Own the session's reader for as long as it lives.
   *
   * Exactly one loop may call `recv()`: it is the only place the receive counter
   * advances, and routing by id is what lets callers run concurrently.
   * @param session - the freshly established session.
   */
  startPump(session) {
    void (async () => {
      try {
        for (; ; ) {
          const reply = await session.recv();
          if (reply === null) throw new Error("peer closed the link");
          if (this.session !== session) return;
          this.validateSession(session);
          this.settle(reply);
        }
      } catch (error) {
        this.failSession(session, error instanceof Error ? error : new Error(String(error)));
      }
    })();
  }
  /** Hand one inbound frame to whoever it belongs to. */
  settle(reply) {
    if (!Object.hasOwn(reply, "id") && Object.hasOwn(reply, "kind")) {
      if (typeof reply.kind !== "string" || !["ask", "note", "interrupt", "caps.changed", "relay.offer", "relay.data", "relay.closed"].includes(reply.kind) || Object.hasOwn(reply, "op")) throw new HandshakeError("invalid peer event envelope");
      this.eventHandler?.(reply);
      return;
    }
    const id = typeof reply.id === "number" ? reply.id : void 0;
    if (id === void 0 || !Number.isSafeInteger(id) || id <= 0 || typeof reply.ok !== "boolean") throw new HandshakeError("invalid peer response envelope");
    const waiter = this.waiting.get(id);
    if (waiter === void 0) return;
    this.waiting.delete(id);
    clearTimeout(waiter.timer);
    if (reply.ok !== true) {
      const failure = new PeerResponseError(String(reply.error ?? "peer reported failure"));
      if (typeof reply.code === "string") {
        failure.peerCode = reply.code;
      }
      waiter.reject(failure);
      return;
    }
    waiter.resolve(reply);
  }
  /** Fail only the callers from one connection generation. */
  failSession(session, error) {
    for (const [id, waiter] of this.waiting) {
      if (waiter.session !== session) continue;
      this.waiting.delete(id);
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
    this.admitted.delete(session);
    session.close();
    if (this.session === session) {
      if (this.expiryTimer !== void 0) clearTimeout(this.expiryTimer);
      this.expiryTimer = void 0;
      this.session = void 0;
      try {
        this.disconnectHandler?.(error);
      } catch {
      }
    }
  }
  /** Fail every parked caller and drop the session they were waiting on. */
  failAll(error) {
    const parked = [...this.waiting.values()];
    this.waiting.clear();
    for (const waiter of parked) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
    this.drop();
  }
  /** Drop the current session so the next request redials. */
  drop() {
    if (this.expiryTimer !== void 0) clearTimeout(this.expiryTimer);
    this.expiryTimer = void 0;
    if (this.session !== void 0) this.failSession(this.session, new HandshakeError(`${this.label}: link closed`));
  }
  /** Withdraw one waiter without settling it (the write itself failed). */
  withdraw(id) {
    const waiter = this.waiting.get(id);
    if (waiter === void 0) return;
    this.waiting.delete(id);
    clearTimeout(waiter.timer);
  }
  /**
   * Send one request and return its result. Only allowlisted observations may
   * retry once after transport failure. Concurrent callers use distinct ids.
   * @param op - the server-side operation name.
   * @param args - its arguments.
   * @param timeoutMs - override for the peer-side operation timeout.
   * @param options - `retries` (default 1) permits a single observation retry;
   *   0 disables it. Mutating operations are never replayed regardless of this
   *   option because their body may already have run before a lost reply.
   * @returns the peer's result object.
   */
  async request(op, args = {}, timeoutMs, options = {}) {
    if (!/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$/u.test(op) || op.length > 64) throw new HandshakeError("invalid remote operation name");
    if (args === null || typeof args !== "object" || Array.isArray(args)) throw new HandshakeError("request arguments must be a JSON object");
    const generation = this.generation;
    const timeout = boundedTimeout(timeoutMs ?? this.read().timeoutMs, 12e4);
    const retries = options.retries ?? 1;
    if (!Number.isInteger(retries) || retries < 0 || retries > 1) throw new HandshakeError("retries must be 0 or 1");
    const attempts = REPLAY_SAFE_OPS.has(op) ? retries + 1 : 1;
    let lastError;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        return await this.exchange(op, args, timeout);
      } catch (error) {
        lastError = error;
        if (generation !== this.generation || attempt === attempts || error instanceof PeerResponseError || error instanceof RequestTimeoutError || error instanceof HandshakeError) break;
        this.log(`${this.label}: ${op} failed (${error instanceof Error ? error.message : String(error)}); reconnecting`);
      }
    }
    throw lastError instanceof Error ? lastError : new Error(String(lastError));
  }
  /** One attempt: park on the id, send, await that id's reply. */
  async exchange(op, args, timeout) {
    const session = await this.ensure();
    if (this.waiting.size >= MAX_PENDING_REQUESTS) throw new HandshakeError("too many pending remote requests");
    if (this.counter >= Number.MAX_SAFE_INTEGER) {
      this.failSession(session, new HandshakeError("request sequence exhausted"));
      throw new HandshakeError("request sequence exhausted");
    }
    this.counter += 1;
    const id = this.counter;
    const reply = new Promise((resolve4, reject) => {
      const timer = setTimeout(() => {
        this.waiting.delete(id);
        reject(new RequestTimeoutError(`${this.label}: ${op} timed out after ${timeout} ms`));
      }, timeout);
      this.waiting.set(id, { resolve: resolve4, reject, timer, session });
    });
    void reply.catch(() => {
    });
    try {
      await session.send({ ...args, id, op });
    } catch (error) {
      this.withdraw(id);
      this.failSession(session, error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
    return await reply;
  }
  /** True while a session is believed live. */
  get connected() {
    return this.session !== void 0;
  }
  /**
   * Register the handler for frames the peer initiates.
   *
   * One handler, because there is one connection: the peer's questions (and
   * anything else it pushes) arrive here, and the caller fans them out.
   * @param handler - called with every frame that carries a `kind`.
   */
  onEvent(handler) {
    this.eventHandler = handler;
  }
  /** Observe loss of the active authenticated channel, once per generation. */
  onDisconnect(handler) {
    this.disconnectHandler = handler;
  }
  /**
   * Send a frame that expects no reply. Used to answer a peer-initiated frame,
   * which by definition has no request id to be answered by.
   * @param payload - the frame to send.
   */
  async notify(payload) {
    const session = await this.ensure();
    await session.send(payload);
  }
  /** Number of requests currently awaiting a reply. */
  get inFlight() {
    return this.waiting.size;
  }
  /** Close the session and let it die. */
  close() {
    this.generation += 1;
    this.dialing = void 0;
    for (const socket of this.connecting) socket.destroy();
    this.connecting.clear();
    this.failAll(new HandshakeError(`${this.label}: link closed`));
  }
  /** Permanently retire a transport so old closures cannot resurrect old trust. */
  dispose() {
    this.disposed = true;
    this.close();
  }
};

// src/mesh-transport.ts
function meshSocketFactory(ctx) {
  return async (config) => {
    const target = config.relayTarget;
    if (typeof target !== "string" || target === "") throw new Error("A mesh target identity is required");
    const mesh = ctx.get("dshRemoteMesh");
    if (mesh === void 0) throw new Error("Enable and configure the mesh connection before using relayTarget");
    return await mesh.open(target);
  };
}

// src/peers.ts
import { Service } from "@deepseek-ai/cordis";
import { FsError as FsError4 } from "@deepseek-ai/dsh-fs";
import z2 from "@deepseek-ai/schemastery";
import { posix } from "node:path";
var MIN_PERMISSION = 1;
var MAX_PERMISSION = 3;
var DEFAULT_PERMISSION = MIN_PERMISSION;
var PeerProfileSchema = z2.object({
  host: z2.string().default(""),
  port: z2.number().default(0),
  relayTarget: z2.string().default(""),
  maxPermission: z2.number().default(DEFAULT_PERMISSION),
  workspaceRoot: z2.string().default(""),
  privateKey: z2.string().role("secret").default(""),
  privateKeyFile: z2.string().default(dshHomePath("dsh-remote", "client.key")),
  autoGenerateKey: z2.boolean().default(true),
  peerPublicKey: z2.string().default(""),
  peerPublicKeyFile: z2.string().default(dshHomePath("dsh-remote", "server.pub")),
  timeoutMs: z2.number().default(12e4),
  allowLegacyHandshake: z2.boolean().default(false),
  maxSessionMs: z2.number().default(36e5)
});
var LEVEL_3_OPS = /* @__PURE__ */ new Set([
  "exec",
  // Stopping a command is part of running one: a read-only controller could
  // never have started it, yet it could still kill a human's own command here.
  "exec.cancel",
  "agent.prompt",
  // Injecting a message into a running conversation drives its agent just as
  // much as a prompt does: it can change what that agent does next.
  "agent.note",
  "agent.ensure",
  "agent.interrupt",
  // Running the peer's own registered tool directly is exactly as powerful as
  // driving its agent (the tool body is the capability), and cancelling one is
  // part of running it — the same reasoning as `exec`/`exec.cancel`.
  "caps.call",
  "caps.cancel"
]);
var LEVEL_2_OPS = /* @__PURE__ */ new Set([
  "fs.write",
  "fs.edit",
  // The chunked-transfer fast path. `fs.put.begin` carries the target `path`,
  // which is what the level-2 workspace fence checks; `chunk`/`commit`/`abort`
  // carry only an `uploadId`, whose path was already fenced at begin (and which
  // cannot be pointed at a different file later). `fs.get` is a read, so it
  // stays at the default level 1 like `fs.read`.
  "fs.put.begin",
  "fs.put.chunk",
  "fs.put.commit",
  "fs.put.abort"
]);
function requiredLevel(op) {
  if (LEVEL_3_OPS.has(op)) return MAX_PERMISSION;
  if (LEVEL_2_OPS.has(op)) return 2;
  return MIN_PERMISSION;
}
function levelName(level) {
  if (level >= MAX_PERMISSION) return "danger-full-access";
  if (level === 2) return "workspace-write";
  return "read-only";
}
function normalizePermission(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return DEFAULT_PERMISSION;
  const floored = Math.trunc(numeric);
  if (floored < MIN_PERMISSION) return DEFAULT_PERMISSION;
  return Math.min(floored, MAX_PERMISSION);
}
function isRemoteUnder(child, root) {
  const normalizedRoot = root.trim();
  if (normalizedRoot === "") return true;
  const fold = (value) => posix.normalize(value.replace(/\\/g, "/")).replace(/\/+$/, "").toLowerCase();
  const haystack = fold(child);
  const needle = fold(normalizedRoot);
  if (needle === "") return true;
  return haystack === needle || haystack.startsWith(`${needle}/`);
}
function assertPeerOperation(ceiling, op, context = {}) {
  const level = normalizePermission(ceiling);
  const needed = requiredLevel(op);
  const who = context.peer === void 0 ? "this peer" : `peer "${context.peer}"`;
  if (needed > level) {
    throw new FsError4(
      `refusing ${op} on ${who}: it needs permission level ${needed} (${levelName(needed)}) but the ceiling is ${level} (${levelName(level)})`,
      "FS_PERMISSION_DENIED"
    );
  }
  if (level === 2 && needed === 2 && context.path !== void 0 && !isRemoteUnder(context.path, context.workspaceRoot ?? "")) {
    throw new FsError4(
      `refusing ${op} on ${who}: "${context.path}" is outside the declared workspace "${context.workspaceRoot ?? ""}" (level 2 is confined)`,
      "FS_PERMISSION_DENIED"
    );
  }
}
var PeerRegistryConfig = z2.object({
  peers: z2.dict(PeerProfileSchema).default({}),
  defaultPeer: z2.string().default("")
});

// src/transfer-client.ts
import { createHash as createHash3, randomBytes as randomBytes2 } from "node:crypto";
import { gunzipSync, gzipSync } from "node:zlib";

// src/transfer-codec.ts
function decodeTransferBlock(value, decodedLimit) {
  if (!Number.isSafeInteger(decodedLimit) || decodedLimit < 0 || decodedLimit > 8 * 1024 * 1024) throw new Error("transfer: invalid block size limit");
  const wireLimit = decodedLimit + 65536;
  const textLimit = 4 * Math.ceil(wireLimit / 3);
  if (typeof value !== "string" || value.length > textLimit || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) {
    throw new Error("transfer: invalid or oversized base64 block");
  }
  const data = Buffer.from(value, "base64");
  if (data.length > wireLimit || data.toString("base64") !== value) throw new Error("transfer: invalid or oversized base64 block");
  return data;
}

// src/transfer-client.ts
var DEFAULT_CHUNK_BYTES = 1024 * 1024;
var MIN_CHUNK_BYTES = 64 * 1024;
var MAX_CHUNK_BYTES = 8 * 1024 * 1024;
var DEFAULT_CONCURRENCY = 4;
var MAX_CONCURRENCY = 8;
var DEFAULT_TIMEOUT_MS = 6e5;
var MAX_RETRIES = 2;
var RETRY_DELAYS_MS = [50, 150];
var COMPRESSION_RATIO = 0.95;
var DEFAULT_PROBE_TTL_MS = 10 * 6e4;
var TRANSFER_OPS = [
  "fs.put.begin",
  "fs.put.chunk",
  "fs.put.commit",
  "fs.put.abort",
  "fs.get"
];
function supportsFastTransfer(ops) {
  return TRANSFER_OPS.every((op) => ops.includes(op));
}
function abortError() {
  const error = new Error("transfer aborted");
  error.name = "AbortError";
  return error;
}
function isAbortError2(error) {
  return error instanceof Error && error.name === "AbortError";
}
function throwIfAborted2(signal) {
  if (signal?.aborted === true) throw abortError();
}
function abortable(work, signal) {
  if (signal === void 0) return work;
  if (signal.aborted === true) return Promise.reject(abortError());
  return new Promise((resolve4, reject) => {
    const onAbort = () => {
      reject(abortError());
    };
    signal.addEventListener("abort", onAbort, { once: true });
    work.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve4(value);
      },
      (error) => {
        signal.removeEventListener("abort", onAbort);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    );
  });
}
function sleep(ms, signal) {
  if (signal === void 0) return new Promise((resolve4) => setTimeout(resolve4, ms));
  throwIfAborted2(signal);
  return new Promise((resolve4, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve4();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortError());
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}
function resolveChunkSize(chunkSize) {
  if (chunkSize === void 0 || !Number.isFinite(chunkSize)) return DEFAULT_CHUNK_BYTES;
  return Math.min(MAX_CHUNK_BYTES, Math.max(MIN_CHUNK_BYTES, Math.floor(chunkSize)));
}
function resolveConcurrency(concurrency) {
  if (concurrency === void 0 || !Number.isFinite(concurrency)) return DEFAULT_CONCURRENCY;
  return Math.min(MAX_CONCURRENCY, Math.max(1, Math.floor(concurrency)));
}
function resolveTimeout(timeoutMs) {
  if (timeoutMs === void 0 || !Number.isFinite(timeoutMs) || timeoutMs <= 0) return DEFAULT_TIMEOUT_MS;
  return Math.floor(timeoutMs);
}
function rateMbpsOf(bytes, durationMs) {
  if (bytes <= 0 || durationMs <= 0) return 0;
  return Math.round(bytes * 8 / 1e6 / (durationMs / 1e3) * 100) / 100;
}
function sha256Hex(data) {
  return createHash3("sha256").update(data).digest("hex");
}
function transferError(message, peerCode) {
  const error = new Error(message);
  if (peerCode !== void 0) error.peerCode = peerCode;
  return error;
}
function planChunks(size, chunkSize) {
  const total = Number.isFinite(size) && size > 0 ? Math.floor(size) : 0;
  return planChunksWithStep(total, resolveChunkSize(chunkSize));
}
function planChunksWithStep(total, step) {
  const chunks = [];
  if (total <= 0) return chunks;
  const safeStep = Math.max(1, Math.floor(step));
  for (let offset = 0, index = 0; offset < total; offset += safeStep, index += 1) {
    chunks.push({ index, offset, length: Math.min(safeStep, total - offset) });
  }
  return chunks;
}
function compressChunk(raw, compression) {
  if (!compression || raw.length === 0) return { data: raw, encoding: "raw" };
  let gzipped;
  try {
    gzipped = gzipSync(raw);
  } catch {
    return { data: raw, encoding: "raw" };
  }
  if (gzipped.length >= raw.length * COMPRESSION_RATIO) return { data: raw, encoding: "raw" };
  return { data: gzipped, encoding: "gzip" };
}
function createOpProbe(request, ttlMs = DEFAULT_PROBE_TTL_MS) {
  let cached;
  let pending;
  return async () => {
    const hit = cached;
    if (hit !== void 0 && Date.now() - hit.at < ttlMs) return hit.supported;
    if (pending !== void 0) return await pending;
    const started = (async () => {
      try {
        const info = await request("sysinfo", {}, 3e4);
        const ops = Array.isArray(info.ops) ? info.ops.map(String) : [];
        const supported = supportsFastTransfer(ops);
        cached = { at: Date.now(), supported };
        return supported;
      } catch {
        return false;
      }
    })();
    pending = started;
    try {
      return await started;
    } finally {
      if (pending === started) pending = void 0;
    }
  };
}
async function requestChunk(request, op, args, options) {
  const timeoutMs = resolveTimeout(options.timeoutMs);
  let lastError;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt += 1) {
    throwIfAborted2(options.signal);
    try {
      return await abortable(request(op, args, timeoutMs), options.signal);
    } catch (error) {
      lastError = error;
      if (isAbortError2(error)) throw error;
      if (attempt === MAX_RETRIES) break;
      await sleep(RETRY_DELAYS_MS[attempt] ?? 150, options.signal);
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}
async function runPool(total, concurrency, worker) {
  if (total <= 0) return;
  const lanes = Math.min(total, Math.max(1, concurrency));
  let next = 0;
  let failed = false;
  let failure;
  const lane = async () => {
    for (; ; ) {
      if (failed) return;
      const index = next;
      next += 1;
      if (index >= total) return;
      try {
        await worker(index);
      } catch (error) {
        if (!failed) {
          failed = true;
          failure = error;
        }
        return;
      }
    }
  };
  await Promise.all(Array.from({ length: lanes }, () => lane()));
  if (failed) throw failure instanceof Error ? failure : new Error(String(failure));
}
async function abortUpload(request, uploadId) {
  try {
    await request("fs.put.abort", { uploadId }, 3e4);
  } catch {
  }
}
async function uploadSource(request, remotePath, source, options) {
  const startedAt = Date.now();
  const signal = options.signal;
  throwIfAborted2(signal);
  const compression = options.compression !== false;
  const timeoutMs = resolveTimeout(options.timeoutMs);
  const requestedChunkSize = resolveChunkSize(options.chunkSize);
  const beginArgs = {
    path: remotePath,
    size: source.size,
    sha256: source.sha256,
    chunkSize: requestedChunkSize,
    encoding: compression ? "gzip" : "raw",
    ...options.createOnly === true ? { createOnly: true } : {},
    ...options.expectedVersion === void 0 ? {} : { expectedVersion: options.expectedVersion }
  };
  const begun = await abortable(request("fs.put.begin", beginArgs, timeoutMs), signal);
  const uploadId = typeof begun.uploadId === "string" && begun.uploadId !== "" ? begun.uploadId : void 0;
  if (uploadId === void 0) throw new Error("transfer: fs.put.begin returned no uploadId");
  const proposed = Number(begun.chunkSize);
  const chunkSize = Number.isFinite(proposed) && proposed > 0 ? Math.floor(proposed) : requestedChunkSize;
  const chunks = planChunksWithStep(source.size, chunkSize);
  const total = source.size;
  let doneBytes = 0;
  let committed = false;
  let phase = "begin";
  try {
    phase = "chunk";
    await runPool(chunks.length, resolveConcurrency(options.concurrency), async (index) => {
      const chunk = chunks[index];
      if (chunk === void 0) return;
      throwIfAborted2(signal);
      const raw = await source.read(chunk.offset, chunk.length);
      if (raw.length !== chunk.length) {
        throw new Error("transfer: local file changed size while uploading");
      }
      const packed = compressChunk(raw, compression);
      await requestChunk(request, "fs.put.chunk", {
        uploadId,
        index: chunk.index,
        dataB64: Buffer.from(packed.data).toString("base64"),
        encoding: packed.encoding
      }, options);
      doneBytes += raw.length;
      try {
        options.onProgress?.(doneBytes, total);
      } catch {
      }
    });
    phase = "commit";
    const commit = await abortable(request("fs.put.commit", { uploadId }, timeoutMs), signal);
    committed = true;
    phase = "done";
    const remoteSha = typeof commit.sha256 === "string" ? commit.sha256.toLowerCase() : "";
    if (remoteSha !== "" && remoteSha !== source.sha256) {
      throw new Error("transfer: checksum mismatch");
    }
    const remoteSize = Number(commit.size);
    if (Number.isFinite(remoteSize) && remoteSize !== source.size) {
      throw new Error("transfer: size mismatch after commit");
    }
    const durationMs = Math.max(0, Date.now() - startedAt);
    return {
      uploadId,
      bytes: source.size,
      sha256: source.sha256,
      created: commit.created === true,
      version: typeof commit.version === "string" ? commit.version : null,
      path: typeof commit.path === "string" ? commit.path : remotePath,
      before: typeof commit.before === "string" ? commit.before : null,
      beforeBytes: Number.isFinite(Number(commit.beforeBytes)) ? Number(commit.beforeBytes) : 0,
      chunkSize,
      durationMs,
      rateMbps: rateMbpsOf(source.size, durationMs)
    };
  } catch (error) {
    if (!committed) await abortUpload(request, uploadId);
    if (error instanceof Error) {
      error.transferPhase = phase;
    }
    throw error;
  }
}
async function uploadBuffer(request, remotePath, data, options = {}) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  return await uploadSource(request, remotePath, {
    size: bytes.length,
    sha256: sha256Hex(bytes),
    read: async (offset, length) => bytes.subarray(offset, offset + length)
  }, options);
}
async function remoteSizeOf(request, remotePath, options, maxBytes) {
  const timeoutMs = resolveTimeout(options.timeoutMs);
  const info = await abortable(request("fs.stat", { path: remotePath }, timeoutMs), options.signal);
  if (info.exists !== true) {
    throw transferError(`cannot read "${remotePath}": not found`, "FS_NOT_FOUND");
  }
  if (info.isDir === true) {
    throw transferError(`cannot read "${remotePath}": not a regular file`, "FS_NOT_REGULAR_FILE");
  }
  const size = Number(info.size);
  if (!Number.isFinite(size) || size < 0) throw new Error(`transfer: peer reported an invalid size for "${remotePath}"`);
  if (maxBytes !== void 0 && Number.isFinite(maxBytes) && size > maxBytes) {
    throw transferError(
      `cannot read "${remotePath}": file exceeds ${maxBytes} bytes`,
      "FS_TOO_LARGE"
    );
  }
  throwIfAborted2(options.signal);
  return Math.floor(size);
}
async function fetchChunk(request, remotePath, chunk, options) {
  const compression = options.compression !== false;
  const reply = await requestChunk(request, "fs.get", {
    path: remotePath,
    offset: chunk.offset,
    length: chunk.length,
    encoding: compression ? "gzip" : "raw"
  }, options);
  const encoded = decodeTransferBlock(reply.dataB64, chunk.length);
  if (reply.encoding !== "gzip" && reply.encoding !== "raw") throw new Error("transfer: unknown chunk encoding");
  const encoding = reply.encoding;
  let data;
  if (encoding === "gzip") {
    try {
      data = new Uint8Array(gunzipSync(encoded, { maxOutputLength: chunk.length + 1 }));
    } catch {
      throw new Error("transfer: corrupt gzip chunk from peer");
    }
  } else {
    data = new Uint8Array(encoded);
  }
  const declaredBytes = Number(reply.bytes);
  if (Number.isFinite(declaredBytes) && declaredBytes !== data.length) {
    throw new Error(`transfer: chunk ${chunk.index} size mismatch (${data.length} != ${declaredBytes})`);
  }
  if (data.length > chunk.length) {
    throw new Error(`transfer: chunk ${chunk.index} is longer than requested`);
  }
  const replyOffset = Number(reply.offset);
  if (Number.isFinite(replyOffset) && replyOffset !== chunk.offset) {
    throw new Error(`transfer: chunk ${chunk.index} offset mismatch`);
  }
  return { data, eof: reply.eof === true };
}
async function verifyRemoteHash(request, remotePath, localSha, options) {
  const reply = await abortable(
    request("fs.hash", { path: remotePath }, resolveTimeout(options.timeoutMs)),
    options.signal
  );
  const remoteSha = typeof reply.hash === "string" ? reply.hash.toLowerCase() : "";
  if (remoteSha === "") throw new Error("transfer: fs.hash returned no digest");
  if (remoteSha !== localSha) throw new Error("transfer: checksum mismatch");
}
async function downloadToBuffer(request, remotePath, options = {}) {
  const size = await remoteSizeOf(request, remotePath, options, options.maxBytes);
  const chunks = planChunks(size, options.chunkSize ?? DEFAULT_CHUNK_BYTES);
  const buffer = new Uint8Array(size);
  let effectiveSize = size;
  let doneBytes = 0;
  await runPool(chunks.length, resolveConcurrency(options.concurrency), async (index) => {
    const chunk = chunks[index];
    if (chunk === void 0) return;
    throwIfAborted2(options.signal);
    const fetched = await fetchChunk(request, remotePath, chunk, options);
    buffer.set(fetched.data, chunk.offset);
    if (fetched.eof && fetched.data.length < chunk.length) {
      effectiveSize = Math.min(effectiveSize, chunk.offset + fetched.data.length);
    }
    doneBytes += fetched.data.length;
    try {
      options.onProgress?.(doneBytes, size);
    } catch {
    }
  });
  const data = effectiveSize === size ? buffer : buffer.slice(0, effectiveSize);
  const sha256 = sha256Hex(data);
  await verifyRemoteHash(request, remotePath, sha256, options);
  return { data, size: effectiveSize, sha256 };
}

// src/remote-path.ts
var REMOTE_SCHEME = "rmt:";
function parseRemotePath(path) {
  if (!path.toLowerCase().startsWith(REMOTE_SCHEME)) return void 0;
  const after = path.slice(REMOTE_SCHEME.length);
  let separator = "/";
  let remote = after;
  if (after.startsWith("\\")) {
    separator = "\\";
    remote = after.slice(1);
  } else if (after.startsWith("/")) {
    remote = after.slice(1);
  }
  return { remote, separator };
}
function parseScpPath(path, isPeer) {
  const match = /^([A-Za-z0-9._-]{2,}):([\\/])?(.*)$/su.exec(path);
  if (match === null) return void 0;
  const peer = match[1];
  if (!isPeer(peer)) return void 0;
  const separator = match[2] === "\\" ? "\\" : "/";
  const remote = (match[3] ?? "").replace(/\\/gu, "/");
  return { peer, remote, separator };
}
var MOUNT_PREFIX = "/rmt";
function parseMountPath(path, isPeer) {
  const match = /^\/rmt(?:\/([\s\S]*))?$/iu.exec(path);
  if (match === null) return void 0;
  const after = match[1] ?? "";
  if (after === "") return void 0;
  if (after.startsWith("/")) return { remote: after, isDefaultPeer: true };
  const slash = after.indexOf("/");
  const first = slash < 0 ? after : after.slice(0, slash);
  if (isPeer(first)) {
    return { peer: first, remote: after.slice(first.length + 1), isDefaultPeer: false };
  }
  return { remote: after, isDefaultPeer: true };
}
function mountPathFor(peer, remote, isDefaultPeer) {
  return isDefaultPeer ? `${MOUNT_PREFIX}/${remote}` : `${MOUNT_PREFIX}/${peer}/${remote}`;
}

// src/reference-query.ts
function parseHostReference(query, peers) {
  const colon = query.indexOf(":");
  if (colon < 2) return void 0;
  const peer = query.slice(0, colon);
  if (!peers.includes(peer)) return void 0;
  const tail = query.slice(colon + 1).replace(/\\/gu, "/");
  if (tail.startsWith("/")) return { peer, kind: "path", path: tail.slice(1) };
  const typed = /^(workspace|plugin):(.*)$/su.exec(tail);
  if (typed?.[1] === "plugin") return { peer, kind: "plugin", query: typed[2] ?? "", relative: "" };
  const content = typed?.[2] ?? tail;
  const slash = content.startsWith("@") && typed === null ? -1 : content.indexOf("/");
  return {
    peer,
    kind: typed?.[1] === "workspace" ? "workspace" : "search",
    query: slash < 0 ? content : content.slice(0, slash),
    relative: slash < 0 ? "" : content.slice(slash + 1)
  };
}
var DEFAULT_REFERENCE_TOKEN_BOUNDS = Object.freeze({ maxChars: 65536, maxQueryLength: 2048, maxMentions: 20 });

// src/peer-fs.ts
var name = "dsh-remote-peer-fs";
var DEFAULT_MAX_PERMISSION = 1;
var PEER_KEY_PREFIX = "peer:";
var DEFAULT_READ_WINDOW = 256 * 1024;
var STREAM_READ_WINDOW = 256 * 1024;
var STREAM_CHUNK = 64 * 1024;
var DEFAULT_TRANSFER_FAST_PATH_BYTES = 512 * 1024;
var PeerProfileSchema2 = z3.object({
  host: z3.string().default(""),
  port: z3.number().default(0),
  relayTarget: z3.string().default(""),
  maxPermission: z3.number().default(DEFAULT_MAX_PERMISSION),
  workspaceRoot: z3.string().default(""),
  privateKey: z3.string().role("secret").default(""),
  privateKeyFile: z3.string().default(dshHomePath("dsh-remote", "client.key")),
  autoGenerateKey: z3.boolean().default(true),
  peerPublicKey: z3.string().default(""),
  peerPublicKeyFile: z3.string().default(dshHomePath("dsh-remote", "server.pub")),
  timeoutMs: z3.number().default(12e4),
  allowLegacyHandshake: z3.boolean().default(false),
  maxSessionMs: z3.number().default(36e5)
});
var Config = z3.object({
  cwd: z3.string().default(process.cwd()),
  diffBasisMaxBytes: z3.number().default(10 * 1024 * 1024),
  peerRoot: z3.string().default("/peers"),
  defaultPeer: z3.string().default(""),
  peers: z3.dict(PeerProfileSchema2).default({}),
  transferFastPathBytes: z3.number().default(DEFAULT_TRANSFER_FAST_PATH_BYTES),
  transferChunkBytes: z3.number().default(1024 * 1024),
  transferConcurrency: z3.number().default(4),
  transferCompression: z3.boolean().default(true)
});
function parsePeerPath(path, peerRoot) {
  if (!path.startsWith(`${peerRoot}/`)) return void 0;
  const rest = path.slice(peerRoot.length + 1);
  const slash = rest.indexOf("/");
  if (slash <= 0) return void 0;
  const peer = rest.slice(0, slash);
  if (!/^[A-Za-z0-9._-]+$/.test(peer)) return void 0;
  const remote = rest.slice(slash + 1);
  if (remote === "") return void 0;
  return { peer, remote };
}
function peerTargetKey(peer, remote) {
  return `${PEER_KEY_PREFIX}${peer}:${remote}`;
}
function splitPeerTargetKey(key) {
  if (!key.startsWith(PEER_KEY_PREFIX)) return void 0;
  const rest = key.slice(PEER_KEY_PREFIX.length);
  const colon = rest.indexOf(":");
  if (colon <= 0) return void 0;
  return { peer: rest.slice(0, colon), remote: rest.slice(colon + 1) };
}
function peerVersion(peer, remote, mtime, size) {
  return FsVersion3(`pv1:${peer}:${String(mtime ?? 0)}:${String(size ?? 0)}:${remote}`);
}
function peerVersionOf(reply, parsed) {
  const raw = reply.version;
  if (typeof raw === "string" && raw !== "") return FsVersion3(raw);
  return peerVersion(parsed.peer, parsed.remote, peerMtime(reply), reply.size);
}
function peerType(reply) {
  return (reply.isDir ?? reply.dir) === true ? "directory" : "file";
}
function peerMtime(reply) {
  return reply.mtimeMs ?? reply.mtime;
}
var FederatedFileSystem = class extends SandboxedFileSystem {
  static inject = ["sandboxPolicy"];
  /** Mount point without a trailing slash. */
  peerRoot;
  /**
   * Fallback declarations from this plugin's own config. Normally empty: the
   * deployment declares peers once, in the client plugin, which publishes them
   * through {@link PeerRegistry}. Kept so this provider also works standalone
   * (tests, or a deployment that mounts peers without the client plugin).
   */
  profiles;
  /** One reusable link per peer, created on first use. */
  links = /* @__PURE__ */ new Map();
  /** Cached "does this peer advertise the chunked transfer ops?" probes. */
  fastProbes = /* @__PURE__ */ new Map();
  /** Fast-path knobs from config; read per transfer, not captured at boot. */
  transferConfig;
  /** Configured default peer for `rmt:` paths; empty means "the first declared". */
  configuredDefaultPeer;
  /**
   * Marker the file-reference provider checks before offering `rmt:` completion:
   * only this backend can resolve such paths, and a bare local backend must not
   * advertise candidates it cannot read.
   */
  supportsRemotePaths = true;
  constructor(ctx, config) {
    super(ctx, config);
    this.transferConfig = config;
    this.configuredDefaultPeer = String(config.defaultPeer ?? "");
    const raw = String(config.peerRoot ?? "/peers");
    this.peerRoot = raw.replace(/\/+$/, "") === "" ? "/peers" : raw.replace(/\/+$/, "");
    this.profiles = config.peers ?? {};
    const own = Object.keys(this.profiles);
    const shared = this.registry()?.list() ?? [];
    const declared = shared.length > 0 ? shared : own;
    ctx.on("loader/volatile-update", () => {
      for (const link2 of this.links.values()) link2.dispose();
      this.links.clear();
      this.fastProbes.clear();
    });
    ctx.effect(() => () => {
      for (const link2 of this.links.values()) link2.dispose();
      this.links.clear();
    }, "dsh-remote-peer-fs: close links");
    this.ctx.logger.info(
      declared.length === 0 ? `${name}: no peers declared \u2014 ${this.peerRoot}/* is not mounted` : `${name}: mounting ${declared.length} peer(s) at ${this.peerRoot}: ${declared.join(", ")}` + (shared.length > 0 ? " (from the shared registry)" : " (from this plugin's own config)")
    );
  }
  /**
   * The peer a bare `rmt:/…` path addresses.
   *
   * An explicit `defaultPeer` wins; otherwise the first declared peer is the
   * default, which is exactly the single-peer deployment's only peer.
   * @returns the peer name.
   * @throws FsError when no peer is declared at all.
   */
  defaultPeerName() {
    const shared = this.registry()?.defaultPeerName?.();
    if (typeof shared === "string" && shared !== "") return shared;
    const wanted = this.configuredDefaultPeer.trim();
    if (wanted !== "") return wanted;
    const declared = [.../* @__PURE__ */ new Set([...this.registry()?.list() ?? [], ...Object.keys(this.profiles)])];
    if (declared.length === 0) {
      throw new FsError5(
        "no remote peer is declared: add `peers` (or `host`/`port`) to the dsh-remote-client settings before using rmt: paths",
        "FS_NOT_FOUND"
      );
    }
    return declared[0];
  }
  /** The shared declarations, when the client plugin published them. */
  registry() {
    return this.ctx.get("dshRemotePeers");
  }
  /**
   * The declaration for a peer. The shared registry wins; this plugin's own
   * config is the fallback, so a deployment never writes an address twice.
   * @param peerName - the name from the path.
   * @returns the profile.
   * @throws FsError when the peer is declared in neither place.
   */
  profileOf(peerName) {
    const shared = this.registry();
    if (shared !== void 0 && shared.has(peerName)) return shared.profile(peerName);
    const own = this.profiles[peerName];
    if (own !== void 0) return own;
    const declared = [.../* @__PURE__ */ new Set([...shared?.list() ?? [], ...Object.keys(this.profiles)])];
    throw new FsError5(
      `unknown peer "${peerName}": declare it under peers in the dsh-remote-client settings` + (declared.length === 0 ? " (none are declared)" : ` (declared: ${declared.join(", ")})`),
      "FS_NOT_FOUND"
    );
  }
  /**
   * The reusable link for a peer, created on first use.
   * @param peerName - the name from the path.
   * @returns the link.
   * @throws FsError when the peer is not declared.
   */
  linkFor(peerName) {
    const existing = this.links.get(peerName);
    if (existing !== void 0) return existing;
    this.profileOf(peerName);
    const link2 = new LinkClient(
      // Resolved per dial, so a declaration changed in settings is picked up.
      () => this.profileOf(peerName),
      (message) => this.ctx.logger.info(message),
      `dsh-remote peer ${peerName}`,
      meshSocketFactory(this.ctx)
    );
    this.links.set(peerName, link2);
    return link2;
  }
  /** The declared ceiling for a peer, normalized by the shared rule. */
  ceilingOf(peerName) {
    return normalizePermission(this.profileOf(peerName).maxPermission ?? DEFAULT_MAX_PERMISSION);
  }
  /**
   * Check one operation against a peer's ceiling.
   *
   * The same function the controlled side runs on arrival, so the two ends
   * cannot disagree — and this side refuses before spending a round trip.
   * @param parsed - the peer and the path it targets.
   * @param op - the wire operation name.
   * @throws FsError when the operation exceeds the ceiling.
   */
  assertPeer(parsed, op) {
    assertPeerOperation(this.ceilingOf(parsed.peer), op, {
      peer: parsed.peer,
      path: parsed.remote,
      workspaceRoot: String(this.profileOf(parsed.peer).workspaceRoot ?? "")
    });
  }
  /** `link.request` in the shape the transfer module expects. */
  transferRequestOf(peerName) {
    return (op, args, timeoutMs) => this.linkFor(peerName).request(op, args, timeoutMs);
  }
  /** Fast-path knobs; the transfer module clamps them to its own safe ranges. */
  transferOptionsOf(signal) {
    return {
      chunkSize: this.transferConfig.transferChunkBytes,
      concurrency: this.transferConfig.transferConcurrency,
      compression: this.transferConfig.transferCompression !== false,
      ...signal === void 0 ? {} : { signal }
    };
  }
  /**
   * Does this peer advertise the chunked transfer ops?
   *
   * Probed once per peer and cached inside the probe itself, so a read or write
   * does not pay a `sysinfo` round trip every time. A failed probe is NOT
   * cached: a tunnel that blinks must not downgrade the provider for minutes.
   */
  fastTransferSupported(peerName) {
    let probe2 = this.fastProbes.get(peerName);
    if (probe2 === void 0) {
      probe2 = createOpProbe(this.transferRequestOf(peerName));
      this.fastProbes.set(peerName, probe2);
    }
    return probe2();
  }
  /**
   * Is this failure "the peer turned out not to know the fast ops"?
   *
   * Only then may a call fall back to the legacy single-frame op. A real error
   * (permission, stale version, checksum, an ambiguous commit) must surface: a
   * silent rewrite could clobber a target the peer already replaced.
   */
  isUnknownTransferOp(error) {
    const code = error?.peerCode;
    if (code === "FS_UNSUPPORTED" || code === "FS_UNKNOWN_OP") return true;
    const message = error instanceof Error ? error.message : String(error);
    return /unknown op|unsupported op|not supported|no such op/iu.test(message);
  }
  /**
   * Read a whole peer file through the legacy windowed `fs.read` op.
   *
   * The old single request capped itself at one window, which silently truncated
   * a larger text file. Looping until the peer reports a short window (or the
   * requested cap) is the honest behaviour for the fallback path.
   */
  async readPeerAllBytes(parsed, signal, maxBytes = Number.MAX_SAFE_INTEGER) {
    const chunks = [];
    let offset = 0;
    for (; ; ) {
      if (signal?.aborted === true) throw new FsError5("read aborted", "FS_ABORTED");
      const window = await this.readPeerBytes(parsed, { offset, length: DEFAULT_READ_WINDOW }, signal);
      if (window.length === 0) break;
      chunks.push(Buffer.from(window));
      offset += window.length;
      if (offset >= maxBytes) break;
      if (window.length < DEFAULT_READ_WINDOW) break;
    }
    return new Uint8Array(Buffer.concat(chunks).subarray(0, Math.min(offset, maxBytes)));
  }
  /** Every declared peer name, shared registry first, in declaration order. */
  declaredPeerNames() {
    return [.../* @__PURE__ */ new Set([...this.registry()?.list() ?? [], ...Object.keys(this.profiles)])];
  }
  /** Whether a token is a declared peer name (case-sensitive, like the paths). */
  isDeclaredPeer(name2) {
    return this.registry()?.has(name2) === true || this.profiles[name2] !== void 0;
  }
  /**
   * The declared peers, for a completion provider that wants to offer
   * `peer:/…` spellings without duplicating the registry. The default peer
   * (`rmt:`) comes first so prefix hints prefer it.
   * @returns peer names, default first.
   */
  remotePeerNames() {
    const declared = this.declaredPeerNames();
    try {
      const fallback = this.defaultPeerName();
      if (fallback !== "") return [fallback, ...declared.filter((name2) => name2 !== fallback)];
    } catch {
    }
    return declared;
  }
  /**
   * The peer a bare `rmt:` path addresses, for a completion provider that wants
   * to label the default namespace.
   * @returns the peer name, or empty when none is declared.
   */
  remoteDefaultPeerName() {
    try {
      return this.defaultPeerName();
    } catch {
      return "";
    }
  }
  /**
   * Resolve one mount-spelling path (`/rmt/E:/x`, `/rmt/<peer>/E:/x`).
   *
   * This is the spelling the chat's Markdown image route can serve: it is
   * OS-absolute, so `/api/file?path=` accepts it, and it routes through this same
   * federated backend.
   * @param path - the mount-spelling path.
   * @returns the peer, its normalized path, and the canonical display path.
   * @throws FsError when the spelling names no remote path.
   */
  mountAliasTarget(path) {
    const parsed = parseMountPath(path, (name2) => this.isDeclaredPeer(name2));
    if (parsed === void 0) throw new FsError5(`"${path}" is not a mount path`, "FS_NOT_FOUND");
    if (parsed.remote === "") {
      throw new FsError5(`"${path}" names no remote path: use e.g. /rmt/E:/dir/file`, "FS_NOT_FOUND");
    }
    const peer = parsed.peer ?? this.defaultPeerName();
    this.profileOf(peer);
    return {
      peer,
      remote: parsed.remote,
      displayPath: mountPathFor(peer, parsed.remote, peer === this.defaultPeerName())
    };
  }
  /**
   * Resolve one scp/rsync-style path (`peer:/E:/x`) to its peer target.
   * @param path - the model-supplied path.
   * @returns the peer, its normalized path, and the canonical display path.
   * @throws FsError when the spelling names no path.
   */
  scpAliasTarget(path) {
    const parsed = parseScpPath(path, (name2) => this.isDeclaredPeer(name2));
    if (parsed === void 0) throw new FsError5(`"${path}" is not a peer path`, "FS_NOT_FOUND");
    if (parsed.remote === "") {
      throw new FsError5(`"${path}" names no remote path: use e.g. ${parsed.peer}:/E:/dir/file`, "FS_NOT_FOUND");
    }
    this.profileOf(parsed.peer);
    return { peer: parsed.peer, remote: parsed.remote, displayPath: `${parsed.peer}:/${parsed.remote}` };
  }
  /**
   * Resolve one `rmt:` path to its peer target.
   *
   * The display path keeps the alias spelling canonicalized to forward slashes
   * (`rmt:/E:/dir`), so tool results show exactly what the user can type again.
   * @param path - the model-supplied `rmt:` path.
   * @returns the peer, its verbatim path, and the canonical display path.
   * @throws FsError when the spelling names no path or no peer is declared.
   */
  remoteAliasTarget(path) {
    const parsed = parseRemotePath(path);
    if (parsed === void 0) {
      throw new FsError5(`"${path}" is not a remote path`, "FS_NOT_FOUND");
    }
    const remote = parsed.remote.trim();
    if (remote === "") {
      throw new FsError5(
        `"${path}" names no remote path: use e.g. rmt:/E:/dir/file`,
        "FS_NOT_FOUND"
      );
    }
    const normalized = remote.replace(/\\/gu, "/");
    const peer = this.defaultPeerName();
    this.profileOf(peer);
    return { peer, remote: normalized, displayPath: `rmt:/${normalized}` };
  }
  async resolve(path, opts) {
    const expression = parseHostReference(path, this.declaredPeerNames());
    if (expression !== void 0 && expression.kind !== "path") {
      if (expression.kind === "plugin") throw new FsError5("A plugin reference is not a file path; use remote_capabilities or remote_tool_call", "FS_NOT_FOUND");
      if (expression.query === "") throw new FsError5("A workspace name is required after the host colon", "FS_NOT_FOUND");
      opts?.signal?.throwIfAborted();
      this.assertPeer({ peer: expression.peer, remote: "" }, "references.list");
      const reply = await this.linkFor(expression.peer).request("references.list", {
        kind: "workspace",
        query: expression.query,
        relative: expression.relative,
        resolve: true,
        limit: 200
      }, 15e3);
      opts?.signal?.throwIfAborted();
      if (reply.status === "ambiguous") throw new FsError5("Multiple workspaces share this name; select the workspace by its full ID", "FS_NOT_FOUND");
      if (reply.status !== "resolved" || typeof reply.path !== "string") throw new FsError5("Workspace reference could not be resolved on its host", "FS_NOT_FOUND");
      return { targetKey: FsTargetKey2(peerTargetKey(expression.peer, reply.path)), displayPath: mountPathFor(expression.peer, reply.path, false) };
    }
    const parsed = parsePeerPath(path, this.peerRoot);
    if (parsed === void 0 && parseMountPath(path, (name2) => this.isDeclaredPeer(name2)) !== void 0) {
      if (opts?.signal?.aborted === true) throw new FsError5("resolve aborted", "FS_ABORTED");
      const alias = this.mountAliasTarget(path);
      return {
        targetKey: FsTargetKey2(peerTargetKey(alias.peer, alias.remote)),
        displayPath: alias.displayPath
      };
    }
    if (parsed === void 0 && parseRemotePath(path) !== void 0) {
      if (opts?.signal?.aborted === true) throw new FsError5("resolve aborted", "FS_ABORTED");
      const alias = this.remoteAliasTarget(path);
      return {
        targetKey: FsTargetKey2(peerTargetKey(alias.peer, alias.remote)),
        displayPath: alias.displayPath
      };
    }
    if (parsed === void 0 && parseScpPath(path, (name2) => this.isDeclaredPeer(name2)) !== void 0) {
      if (opts?.signal?.aborted === true) throw new FsError5("resolve aborted", "FS_ABORTED");
      const alias = this.scpAliasTarget(path);
      return {
        targetKey: FsTargetKey2(peerTargetKey(alias.peer, alias.remote)),
        displayPath: alias.displayPath
      };
    }
    if (parsed === void 0) return await super.resolve(path, opts);
    if (opts?.signal?.aborted === true) throw new FsError5("resolve aborted", "FS_ABORTED");
    this.profileOf(parsed.peer);
    return {
      targetKey: FsTargetKey2(peerTargetKey(parsed.peer, parsed.remote)),
      displayPath: path
    };
  }
  processPath(target) {
    const parsed = splitPeerTargetKey(String(target.targetKey));
    if (parsed === void 0) return super.processPath(target);
    return `peer://${parsed.peer}/${parsed.remote}`;
  }
  fileUrl(target) {
    const parsed = splitPeerTargetKey(String(target.targetKey));
    if (parsed === void 0) return super.fileUrl(target);
    return `peer://${parsed.peer}/${parsed.remote}`;
  }
  contains(parent, child) {
    const a = splitPeerTargetKey(String(parent.targetKey));
    const b = splitPeerTargetKey(String(child.targetKey));
    if (a === void 0 || b === void 0) {
      if (a === void 0 && b === void 0) return super.contains(parent, child);
      return false;
    }
    if (a.peer !== b.peer) return false;
    if (a.remote === b.remote) return true;
    const prefix = a.remote.endsWith("/") ? a.remote : `${a.remote}/`;
    return b.remote.startsWith(prefix);
  }
  async stat(target, signal) {
    const parsed = splitPeerTargetKey(String(target.targetKey));
    if (parsed === void 0) return await super.stat(target, signal);
    if (signal?.aborted === true) throw new FsError5("stat aborted", "FS_ABORTED");
    const reply = await this.linkFor(parsed.peer).request("fs.stat", { path: parsed.remote });
    if (reply.exists !== true) return void 0;
    const size = typeof reply.size === "number" ? reply.size : void 0;
    return {
      version: peerVersionOf(reply, parsed),
      type: peerType(reply),
      ...size === void 0 ? {} : { size }
    };
  }
  async lstat(path, opts, signal) {
    const parsed = parsePeerPath(path, this.peerRoot);
    if (parsed === void 0 && parseMountPath(path, (name2) => this.isDeclaredPeer(name2)) !== void 0) {
      const alias = this.mountAliasTarget(path);
      const info2 = await this.stat(
        { targetKey: FsTargetKey2(peerTargetKey(alias.peer, alias.remote)), displayPath: alias.displayPath },
        signal
      );
      if (info2 === void 0) return void 0;
      return {
        version: info2.version,
        type: info2.type,
        ...info2.size === void 0 ? {} : { size: info2.size }
      };
    }
    if (parsed === void 0 && parseRemotePath(path) !== void 0) {
      const alias = this.remoteAliasTarget(path);
      const info2 = await this.stat(
        { targetKey: FsTargetKey2(peerTargetKey(alias.peer, alias.remote)), displayPath: alias.displayPath },
        signal
      );
      if (info2 === void 0) return void 0;
      return {
        version: info2.version,
        type: info2.type,
        ...info2.size === void 0 ? {} : { size: info2.size }
      };
    }
    if (parsed === void 0 && parseScpPath(path, (name2) => this.isDeclaredPeer(name2)) !== void 0) {
      const alias = this.scpAliasTarget(path);
      const info2 = await this.stat(
        { targetKey: FsTargetKey2(peerTargetKey(alias.peer, alias.remote)), displayPath: alias.displayPath },
        signal
      );
      if (info2 === void 0) return void 0;
      return {
        version: info2.version,
        type: info2.type,
        ...info2.size === void 0 ? {} : { size: info2.size }
      };
    }
    if (parsed === void 0) return await super.lstat(path, opts, signal);
    const info = await this.stat(
      { targetKey: FsTargetKey2(peerTargetKey(parsed.peer, parsed.remote)), displayPath: path },
      signal
    );
    if (info === void 0) return void 0;
    return {
      version: info.version,
      type: info.type,
      ...info.size === void 0 ? {} : { size: info.size }
    };
  }
  async listDir(target, signal) {
    const parsed = splitPeerTargetKey(String(target.targetKey));
    if (parsed === void 0) return await super.listDir(target, signal);
    if (signal?.aborted === true) throw new FsError5("listDir aborted", "FS_ABORTED");
    const reply = await this.linkFor(parsed.peer).request("fs.list", { path: parsed.remote });
    const entries = Array.isArray(reply.entries) ? reply.entries : [];
    return entries.map((entry) => {
      const childName = String(entry.name ?? "");
      const childRemote = parsed.remote.endsWith("/") ? `${parsed.remote}${childName}` : `${parsed.remote}/${childName}`;
      const size = typeof entry.size === "number" ? entry.size : void 0;
      return {
        name: childName,
        type: peerType(entry),
        target: {
          targetKey: FsTargetKey2(peerTargetKey(parsed.peer, childRemote)),
          displayPath: `${target.displayPath.replace(/\/+$/, "")}/${childName}`
        },
        version: peerVersion(parsed.peer, childRemote, peerMtime(entry), entry.size),
        ...size === void 0 ? {} : { size }
      };
    });
  }
  async readText(target, signal) {
    const parsed = splitPeerTargetKey(String(target.targetKey));
    if (parsed === void 0) return await super.readText(target, signal);
    const info = await this.stat(target, signal);
    if (info === void 0) throw new FsError5(`cannot read "${target.displayPath}": not found`, "FS_NOT_FOUND");
    if (info.type !== "file") {
      throw new FsError5(`cannot read "${target.displayPath}": not a regular file`, "FS_NOT_REGULAR_FILE");
    }
    this.assertPeer(parsed, "fs.get");
    const fastPathBytes = this.transferConfig.transferFastPathBytes ?? DEFAULT_TRANSFER_FAST_PATH_BYTES;
    const large = info.size !== void 0 && info.size > Math.max(fastPathBytes, DEFAULT_READ_WINDOW);
    if (large && await this.fastTransferSupported(parsed.peer)) {
      const result = await downloadToBuffer(
        this.transferRequestOf(parsed.peer),
        parsed.remote,
        this.transferOptionsOf(signal)
      );
      return decodePeerText(result.data, target.displayPath);
    }
    const bytes = await this.readPeerAllBytes(parsed, signal);
    return decodePeerText(bytes, target.displayPath);
  }
  async streamText(target, signal) {
    const parsed = splitPeerTargetKey(String(target.targetKey));
    if (parsed === void 0) return await super.streamText(target, signal);
    if (!await this.fastTransferSupported(parsed.peer)) {
      const text2 = await this.readText(target, signal);
      return (async function* chunks() {
        for (let at = 0; at < text2.length; at += STREAM_CHUNK) {
          if (signal?.aborted === true) throw new FsError5("stream aborted", "FS_ABORTED");
          yield text2.slice(at, at + STREAM_CHUNK);
        }
      })();
    }
    this.assertPeer(parsed, "fs.get");
    const request = this.transferRequestOf(parsed.peer);
    const options = this.transferOptionsOf(signal);
    const remote = parsed.remote;
    return (async function* chunks() {
      const decoder = new StringDecoder("utf8");
      let offset = 0;
      for (; ; ) {
        if (signal?.aborted === true) throw new FsError5("stream aborted", "FS_ABORTED");
        const reply = await request("fs.get", {
          path: remote,
          offset,
          length: STREAM_READ_WINDOW,
          encoding: options.compression === false ? "raw" : "gzip"
        }, 6e5);
        const encoded = Buffer.from(String(reply.dataB64 ?? ""), "base64");
        const data = reply.encoding === "gzip" ? gunzipSync2(encoded) : encoded;
        if (data.length === 0) break;
        offset += data.length;
        const piece = decoder.write(data);
        if (piece !== "") yield piece;
        if (reply.eof === true) break;
      }
      const tail = decoder.end();
      if (tail !== "") yield tail;
    })();
  }
  async readBytes(target, signal, maxBytes) {
    const parsed = splitPeerTargetKey(String(target.targetKey));
    if (parsed === void 0) return await super.readBytes(target, signal, maxBytes);
    const info = await this.stat(target, signal);
    if (info === void 0) throw new FsError5(`cannot read "${target.displayPath}": not found`, "FS_NOT_FOUND");
    if (info.type !== "file") {
      throw new FsError5(`cannot read "${target.displayPath}": not a regular file`, "FS_NOT_REGULAR_FILE");
    }
    if (info.size !== void 0 && info.size > maxBytes) {
      throw new FsError5(`cannot read "${target.displayPath}": file exceeds ${maxBytes} bytes`, "FS_TOO_LARGE");
    }
    const fastPathBytes = this.transferConfig.transferFastPathBytes ?? DEFAULT_TRANSFER_FAST_PATH_BYTES;
    const large = info.size !== void 0 && info.size > fastPathBytes;
    if (large && await this.fastTransferSupported(parsed.peer)) {
      const result = await downloadToBuffer(
        this.transferRequestOf(parsed.peer),
        parsed.remote,
        { ...this.transferOptionsOf(signal), maxBytes }
      );
      return result.data;
    }
    return await this.readPeerAllBytes(parsed, signal, maxBytes);
  }
  async readByteRange(target, range, signal) {
    const parsed = splitPeerTargetKey(String(target.targetKey));
    if (parsed === void 0) return await super.readByteRange(target, range, signal);
    return await this.readPeerBytes(parsed, range, signal);
  }
  /**
   * One bounded byte read over the link.
   * @param parsed - the peer and its path.
   * @param range - `offset` and the largest `length` to transfer.
   * @param signal - aborts before the request is sent.
   * @returns the window's bytes.
   */
  async readPeerBytes(parsed, range, signal) {
    if (signal?.aborted === true) throw new FsError5("read aborted", "FS_ABORTED");
    this.assertPeer(parsed, "fs.read");
    const length = Math.max(0, Math.min(range.length, Number.MAX_SAFE_INTEGER));
    const reply = await this.linkFor(parsed.peer).request("fs.read", {
      path: parsed.remote,
      offset: range.offset,
      length: length === Number.MAX_SAFE_INTEGER ? DEFAULT_READ_WINDOW : length
    });
    const encoded = typeof reply.dataB64 === "string" ? reply.dataB64 : "";
    return Uint8Array.from(Buffer.from(encoded, "base64"));
  }
  /**
   * One peer request, with the peer's typed failure code preserved.
   * @param parsed - the peer and the path it targets.
   * @param op - the wire operation name.
   * @param args - its arguments.
   * @returns the peer's reply.
   * @throws FsError carrying the peer's own code when it refused.
   */
  async peerRequest(parsed, op, args) {
    try {
      return await this.linkFor(parsed.peer).request(op, args);
    } catch (error) {
      const code = error.peerCode;
      if (typeof code === "string" && /^FS_[A-Z_]+$/.test(code)) {
        throw new FsError5(error instanceof Error ? error.message : String(error), code);
      }
      throw error;
    }
  }
  // `sandboxPolicy` is part of the seam: the tool layer resolves the session's
  // per-call policy and passes it in. Dropping it here did not fail loudly —
  // the local branch fell back to the *deployment* default, so a read-only
  // session could be allowed to write and a workspace-write session denied,
  // with the containment root taken from config instead of the session cwd.
  // Peer targets deliberately keep bypassing the fence (the peer enforces its
  // own), so the parameter is only forwarded on the local branch.
  async writeText(target, content, expected, signal, sandboxPolicy) {
    const parsed = splitPeerTargetKey(String(target.targetKey));
    if (parsed === void 0) return await super.writeText(target, content, expected, signal, sandboxPolicy);
    if (signal?.aborted === true) throw new FsError5("write aborted", "FS_ABORTED");
    this.assertPeer(parsed, "fs.write");
    const data = Buffer.from(content, "utf8");
    const fastPathBytes = this.transferConfig.transferFastPathBytes ?? DEFAULT_TRANSFER_FAST_PATH_BYTES;
    if (data.length >= fastPathBytes && await this.fastTransferSupported(parsed.peer)) {
      try {
        const result = await uploadBuffer(this.transferRequestOf(parsed.peer), parsed.remote, data, {
          ...this.transferOptionsOf(signal),
          ...expected?.kind === "createIfAbsent" ? { createOnly: true } : {},
          ...expected?.kind === "replaceIfVersion" ? { expectedVersion: String(expected.version) } : {}
        });
        let version = result.version;
        if (version === null) {
          const info = await this.stat(target, signal);
          version = info === void 0 ? null : String(info.version);
        }
        if (version === null) throw new FsError5("peer committed the write but reported no version", "FS_IO_ERROR");
        return {
          operation: result.created ? "create" : "update",
          version: FsVersion3(version),
          before: result.before,
          after: content
        };
      } catch (error) {
        if (!this.isUnknownTransferOp(error)) throw error;
      }
    }
    const reply = await this.peerRequest(parsed, "fs.write", {
      path: parsed.remote,
      dataB64: data.toString("base64"),
      ...expected?.kind === "createIfAbsent" ? { createOnly: true } : {},
      ...expected?.kind === "replaceIfVersion" ? { expectedVersion: String(expected.version) } : {}
    });
    return {
      operation: reply.created === true ? "create" : "update",
      version: peerVersionOf(reply, parsed),
      before: typeof reply.before === "string" ? reply.before : null,
      after: typeof reply.after === "string" ? reply.after : content
    };
  }
  async editText(target, edit, expected, signal, sandboxPolicy) {
    const parsed = splitPeerTargetKey(String(target.targetKey));
    if (parsed === void 0) return await super.editText(target, edit, expected, signal, sandboxPolicy);
    if (signal?.aborted === true) throw new FsError5("edit aborted", "FS_ABORTED");
    this.assertPeer(parsed, "fs.edit");
    const reply = await this.peerRequest(parsed, "fs.edit", {
      path: parsed.remote,
      oldString: edit.oldString,
      newString: edit.newString,
      replaceAll: edit.replaceAll === true,
      ...expected === void 0 ? {} : { expectedVersion: String(expected.version) }
    });
    return {
      version: peerVersionOf(reply, parsed),
      before: String(reply.before ?? ""),
      after: String(reply.after ?? "")
    };
  }
};
function decodePeerText(bytes, displayPath) {
  if (bytes.includes(0)) {
    throw new FsError5(`cannot read "${displayPath}": not a text file`, "FS_NOT_TEXT");
  }
  return Buffer.from(bytes).toString("utf8");
}
export {
  Config,
  DEFAULT_MAX_PERMISSION,
  FederatedFileSystem,
  decodePeerText,
  FederatedFileSystem as default,
  name,
  parsePeerPath,
  peerTargetKey,
  splitPeerTargetKey
};
