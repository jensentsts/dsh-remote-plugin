/**
 * The `rmt:` path scheme: remote paths spelled the way a user types them.
 *
 * `rmt:/E:/data/archives/` and `rmt:\E:\data\archives\` both name the same
 * path **on the peer machine**, while the same string without the scheme names
 * a local file. Keeping the parser in its own module lets the filesystem backend
 * (which resolves such paths) and the file-reference provider (which completes
 * them) agree on one spelling, and lets both be tested without cordis.
 *
 * @module dsh-remote/remote-path
 */

/** The scheme that marks a remote path. Case-insensitive, colon mandatory. */
export const REMOTE_SCHEME = 'rmt:'

/** One parsed remote reference. */
export interface ParsedRemotePath {
  /** The peer-side path, verbatim: `E:/data/archives/` or `\\server\share`. */
  remote: string
  /** The separator the user wrote after the scheme, `/` or `\`. */
  separator: '/' | '\\'
}

/**
 * Parse a path that uses the remote scheme.
 *
 * The single separator right after `rmt:` is part of the scheme spelling, not
 * the path: `rmt:/E:/x` → `E:/x`, `rmt:\E:\x` → `E:\x`. A second leading
 * separator is preserved, which is how a POSIX peer's absolute path is spelled:
 * `rmt://home/u/x` → `/home/u/x`. Anything without the scheme returns undefined,
 * so callers can fall back to their own path handling.
 *
 * @param path - a model- or UI-supplied path.
 * @returns the parsed remote path, or undefined when the scheme is absent.
 */
export function parseRemotePath(path: string): ParsedRemotePath | undefined {
  if (!path.toLowerCase().startsWith(REMOTE_SCHEME)) return undefined
  const after = path.slice(REMOTE_SCHEME.length)
  let separator: '/' | '\\' = '/'
  let remote = after
  if (after.startsWith('\\')) {
    separator = '\\'
    remote = after.slice(1)
  } else if (after.startsWith('/')) {
    remote = after.slice(1)
  }
  return { remote, separator }
}

/**
 * Whether a path is spelled as a remote reference (scheme only).
 * @param path - the candidate path.
 * @returns true when it starts with `rmt:`.
 */
export function isRemotePath(path: string): boolean {
  return path.toLowerCase().startsWith(REMOTE_SCHEME)
}

/** One query parsed for remote `@` completion. */
export interface RemoteReferenceQuery {
  /** Text typed before the last separator, including the scheme and that separator. */
  prefix: string
  /** The partial last segment being completed. */
  partial: string
  /** The path part after the scheme, with `/` separators (no leading separator). */
  rest: string
  /** The separator style the user is writing in. */
  separator: '/' | '\\'
}

/**
 * Parse the text after `@` when it is a remote reference query.
 *
 * Only `rmt:` (or the bare `rmt`/`rmt:/` root spelling) qualifies. The split is
 * kept relative to the user's own typing so candidate paths can be emitted as
 * `prefix + name`: backslash input stays backslash, forward-slash input stays
 * forward-slash.
 *
 * @param query - the text after the `@` token.
 * @returns the parsed query, or undefined for a non-remote query.
 */
export function parseRemoteReferenceQuery(query: string): RemoteReferenceQuery | undefined {
  const scheme = /^rmt:/i.exec(query)
  if (scheme === null) return undefined
  const separator: '/' | '\\' = /^rmt:[\\]/i.test(query) ? '\\' : '/'
  const afterScheme = query.slice(scheme[0].length)
  const typedPrefix = query.slice(0, scheme[0].length + (afterScheme.startsWith('/') || afterScheme.startsWith('\\') ? 1 : 0))
  const restRaw = afterScheme.replace(/^[\\/]/u, '')
  const rest = restRaw.replace(/\\/gu, '/')
  const cut = Math.max(restRaw.lastIndexOf('/'), restRaw.lastIndexOf('\\'))
  const partial = cut >= 0 ? restRaw.slice(cut + 1) : restRaw
  const prefix = cut >= 0 ? typedPrefix + restRaw.slice(0, cut + 1) : typedPrefix
  return { prefix, partial, rest, separator }
}

/** One path in the scp/rsync spelling: `peer:/E:/x`. */
export interface ParsedScpPath {
  /** The declared peer name before the colon. */
  peer: string
  /** The peer-side path, normalized to `/` separators. */
  remote: string
  /** The separator the user wrote after the colon. */
  separator: '/' | '\\'
}

/**
 * Recognise the `peer:/…` (scp/rsync) spelling.
 *
 * Only a token that `isPeer` accepts becomes a remote path, which is what keeps
 * `E:/…` a local Windows path: a drive letter is one character, and peer names
 * are at least two. The path after `peer:` behaves like `rmt:`'s — one separator
 * belongs to the scheme, so `peer:/E:/x` → `E:/x` and `peer://home/u` →
 * `/home/u`.
 *
 * @param path - the model- or UI-supplied path.
 * @param isPeer - whether a token is a declared peer name.
 * @returns the parsed path, or undefined when this is not peer-addressed.
 */
export function parseScpPath(path: string, isPeer: (name: string) => boolean): ParsedScpPath | undefined {
  const match = /^([A-Za-z0-9._-]{2,}):([\\/])?(.*)$/su.exec(path)
  if (match === null) return undefined
  const peer = match[1]!
  if (!isPeer(peer)) return undefined
  const separator: '/' | '\\' = match[2] === '\\' ? '\\' : '/'
  const remote = (match[3] ?? '').replace(/\\/gu, '/')
  return { peer, remote, separator }
}

/** One `@` query in the scp/rsync spelling. */
export interface ScpReferenceQuery extends RemoteReferenceQuery {
  /** The peer name the query addresses. */
  peer: string
  /** The path form to feed the filesystem backend: `<peer>:/<rest>`. */
  alias: string
}

/**
 * Parse an `@` query in the scp/rsync spelling.
 *
 * Two shapes are recognised:
 *
 *  - `peer:` (or `peer:/…`) — a full query for a declared peer;
 *  - `peer-name-prefix` — no colon yet; returns a hint so completion can offer
 *    the peer itself, and callers keep the local matches alongside it.
 *
 * @param query - the text after `@`.
 * @param isPeer - whether a token is a declared peer name.
 * @returns the parsed query (or peer-name hint), or undefined.
 */
export function parseScpReferenceQuery(
  query: string,
  names: readonly string[],
): (ScpReferenceQuery & { peerHint?: never }) | { peerHint: string } | undefined {
  const match = /^([A-Za-z0-9._-]{2,}):([\\/])?(.*)$/su.exec(query)
  if (match !== null) {
    const peer = names.find(name => name === match[1])
    if (peer === undefined) return undefined
    const separator: '/' | '\\' = match[2] === '\\' ? '\\' : '/'
    const afterScheme = match[3] ?? ''
    const typedPrefix = query.slice(0, query.length - afterScheme.length)
    const restRaw = afterScheme
    const rest = restRaw.replace(/\\/gu, '/')
    const cut = Math.max(restRaw.lastIndexOf('/'), restRaw.lastIndexOf('\\'))
    const partial = cut >= 0 ? restRaw.slice(cut + 1) : restRaw
    const prefix = cut >= 0 ? typedPrefix + restRaw.slice(0, cut + 1) : typedPrefix
    return { peer, prefix, partial, rest, separator, alias: `${peer}:/` }
  }
  // No colon yet: offer a peer name that the typed token is a prefix of.
  if (!/^[A-Za-z0-9._-]{2,}$/u.test(query)) return undefined
  const hint = names.find(name => name.toLowerCase().startsWith(query.toLowerCase()))
  return hint === undefined ? undefined : { peerHint: hint }
}

/**
 * Mount-point spelling shared with DSH's UI: `/rmt/E:/x`, `/rmt/<peer>/E:/x`.
 *
 * This is the only remote spelling the chat can render: Markdown images go
 * through the host's `/api/file?path=` route, which rejects anything that is not
 * an OS-absolute path. `/rmt/…` is absolute everywhere, so the same spelling
 * works for `@` mentions, `read`/`write`, and Markdown.
 */
export const MOUNT_PREFIX = '/rmt'

/** One path in the mount-point spelling. */
export interface ParsedMountPath {
  /** The declared peer named by the path; undefined means the default peer. */
  peer?: string
  /** The peer-side path, normalized to `/`. */
  remote: string
  /** Whether the default peer is the one addressed. */
  isDefaultPeer: boolean
}

/**
 * Parse `/rmt/<peer?>/<remote path>`.
 *
 * `/rmt/E:/x` and `/rmt//home/u` address the default peer; `/rmt/<peer>/E:/x`
 * names a declared peer. A first segment that is not a declared peer is treated
 * as the default peer's own path, so `E:` keeps its drive meaning.
 *
 * @param path - the candidate path.
 * @param isPeer - whether a token is a declared peer name.
 * @returns the parsed path, or undefined when the mount prefix is absent.
 */
export function parseMountPath(path: string, isPeer: (name: string) => boolean): ParsedMountPath | undefined {
  const match = /^\/rmt(?:\/([\s\S]*))?$/iu.exec(path)
  if (match === null) return undefined
  const after = match[1] ?? ''
  if (after === '') return undefined
  // `/rmt//home/u` — the second slash belongs to a POSIX absolute peer path.
  if (after.startsWith('/')) return { remote: after, isDefaultPeer: true }
  const slash = after.indexOf('/')
  const first = slash < 0 ? after : after.slice(0, slash)
  if (isPeer(first)) {
    return { peer: first, remote: after.slice(first.length + 1), isDefaultPeer: false }
  }
  return { remote: after, isDefaultPeer: true }
}

/**
 * Compose the canonical mount spelling of one peer path.
 * @param peer - peer name.
 * @param remote - peer-side path (may start with `/` for a POSIX absolute path).
 * @param isDefaultPeer - omit the peer segment when true.
 * @returns the `/rmt/…` spelling.
 */
export function mountPathFor(peer: string, remote: string, isDefaultPeer: boolean): string {
  return isDefaultPeer ? `${MOUNT_PREFIX}/${remote}` : `${MOUNT_PREFIX}/${peer}/${remote}`
}

/**
 * Compose the scp/rsync spelling of one peer path: `<peer>:/<remote>`.
 *
 * This is what `@` completion inserts, because it names its host explicitly:
 * `@studio:/E:/x` cannot be mistaken for a local path or for the default
 * peer's, and the federated backend resolves it exactly like the mount form.
 *
 * @param peer - declared peer name.
 * @param remote - peer-side path, or the empty string for the peer's roots.
 * @returns the `<peer>:/…` spelling.
 */
export function scpPathFor(peer: string, remote: string): string {
  return `${peer}:/${remote}`
}

/** One `@` query in the mount-point spelling. */
export interface MountReferenceQuery {
  /** Peer addressed, or empty for the default peer / the mount root. */
  peer: string
  /** Whether the default peer is addressed. */
  isDefaultPeer: boolean
  /** True for the bare `/rmt` or `/rmt/` root query. */
  root: boolean
  /** Typed text to append a candidate name to. */
  prefix: string
  /** The partial last segment being completed. */
  partial: string
  /** Remote path text after any peer segment (normalized to `/`). */
  rest: string
  /** When set, this is a peer-name prefix hint, not a path query. */
  peerHint?: string
}

/** Split typed text into `prefix + partial`, keeping the user's separators. */
function splitTyped(restRaw: string, base: string): { prefix: string, partial: string } {
  const cut = Math.max(restRaw.lastIndexOf('/'), restRaw.lastIndexOf('\\'))
  return cut >= 0
    ? { prefix: base + restRaw.slice(0, cut + 1), partial: restRaw.slice(cut + 1) }
    : { prefix: base, partial: restRaw }
}

/**
 * Parse an `@` query written in the mount spelling.
 *
 * Recognises the root (`/rmt/` → peer directories), a peer-name prefix
 * (`/rmt/thi` → `/rmt/home-pc`), a named peer (`/rmt/home-pc/…`), and the
 * default peer's own path (`/rmt/E:/…`).
 *
 * @param query - the text after `@`.
 * @param names - declared peer names, default peer first.
 * @param defaultPeer - the default peer name.
 * @returns the parsed query, or undefined when it is not a mount query.
 */
export function parseMountReferenceQuery(
  query: string,
  names: readonly string[],
  defaultPeer: string,
): MountReferenceQuery | undefined {
  const match = /^\/rmt(?:\/([\s\S]*))?$/iu.exec(query)
  if (match === null) return undefined
  const after = match[1] ?? ''
  if (after === '') {
    return { peer: '', isDefaultPeer: true, root: true, prefix: `${MOUNT_PREFIX}/`, partial: '', rest: '' }
  }
  const slash = after.indexOf('/')
  const first = slash < 0 ? after : after.slice(0, slash)
  const declared = names.find(name => name === first)
  if (declared !== undefined) {
    const restRaw = after.slice(declared.length + 1)
    const { prefix, partial } = splitTyped(restRaw, `${MOUNT_PREFIX}/${declared}/`)
    return {
      peer: declared,
      isDefaultPeer: declared === defaultPeer,
      root: false,
      prefix,
      partial,
      rest: restRaw.replace(/\\/gu, '/'),
    }
  }
  if (slash < 0 && first !== '') {
    const hint = names.find(name => name.toLowerCase().startsWith(first.toLowerCase()))
    if (hint !== undefined) {
      return { peer: '', isDefaultPeer: true, root: false, prefix: `${MOUNT_PREFIX}/`, partial: first, rest: '', peerHint: hint }
    }
  }
  const { prefix, partial } = splitTyped(after, `${MOUNT_PREFIX}/`)
  return {
    peer: '',
    isDefaultPeer: true,
    root: false,
    prefix,
    partial,
    rest: after.replace(/\\/gu, '/'),
  }
}
