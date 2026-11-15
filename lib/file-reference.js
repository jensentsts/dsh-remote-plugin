// src/file-reference.ts
import z from "@deepseek-ai/schemastery";
import LocalFileReferenceService from "@deepseek-ai/dsh-file-reference-local";
import {
  DEFAULT_FILE_SEARCH_EXCLUDED_DIRECTORIES,
  DEFAULT_FILE_SEARCH_MAX_ENTRIES,
  DEFAULT_FILE_SEARCH_MAX_RESULTS
} from "@deepseek-ai/dsh-file-reference-local";

// src/remote-path.ts
function parseRemoteReferenceQuery(query) {
  const scheme = /^rmt:/i.exec(query);
  if (scheme === null) return void 0;
  const separator = /^rmt:[\\]/i.test(query) ? "\\" : "/";
  const afterScheme = query.slice(scheme[0].length);
  const typedPrefix = query.slice(0, scheme[0].length + (afterScheme.startsWith("/") || afterScheme.startsWith("\\") ? 1 : 0));
  const restRaw = afterScheme.replace(/^[\\/]/u, "");
  const rest = restRaw.replace(/\\/gu, "/");
  const cut = Math.max(restRaw.lastIndexOf("/"), restRaw.lastIndexOf("\\"));
  const partial = cut >= 0 ? restRaw.slice(cut + 1) : restRaw;
  const prefix = cut >= 0 ? typedPrefix + restRaw.slice(0, cut + 1) : typedPrefix;
  return { prefix, partial, rest, separator };
}
function parseScpReferenceQuery(query, names) {
  const match = /^([A-Za-z0-9._-]{2,}):([\\/])?(.*)$/su.exec(query);
  if (match !== null) {
    const peer = names.find((name2) => name2 === match[1]);
    if (peer === void 0) return void 0;
    const separator = match[2] === "\\" ? "\\" : "/";
    const afterScheme = match[3] ?? "";
    const typedPrefix = query.slice(0, query.length - afterScheme.length);
    const restRaw = afterScheme;
    const rest = restRaw.replace(/\\/gu, "/");
    const cut = Math.max(restRaw.lastIndexOf("/"), restRaw.lastIndexOf("\\"));
    const partial = cut >= 0 ? restRaw.slice(cut + 1) : restRaw;
    const prefix = cut >= 0 ? typedPrefix + restRaw.slice(0, cut + 1) : typedPrefix;
    return { peer, prefix, partial, rest, separator, alias: `${peer}:/` };
  }
  if (!/^[A-Za-z0-9._-]{2,}$/u.test(query)) return void 0;
  const hint = names.find((name2) => name2.toLowerCase().startsWith(query.toLowerCase()));
  return hint === void 0 ? void 0 : { peerHint: hint };
}
var MOUNT_PREFIX = "/rmt";
function scpPathFor(peer, remote) {
  return `${peer}:/${remote}`;
}
function splitTyped(restRaw, base) {
  const cut = Math.max(restRaw.lastIndexOf("/"), restRaw.lastIndexOf("\\"));
  return cut >= 0 ? { prefix: base + restRaw.slice(0, cut + 1), partial: restRaw.slice(cut + 1) } : { prefix: base, partial: restRaw };
}
function parseMountReferenceQuery(query, names, defaultPeer) {
  const match = /^\/rmt(?:\/([\s\S]*))?$/iu.exec(query);
  if (match === null) return void 0;
  const after = match[1] ?? "";
  if (after === "") {
    return { peer: "", isDefaultPeer: true, root: true, prefix: `${MOUNT_PREFIX}/`, partial: "", rest: "" };
  }
  const slash = after.indexOf("/");
  const first = slash < 0 ? after : after.slice(0, slash);
  const declared = names.find((name2) => name2 === first);
  if (declared !== void 0) {
    const restRaw = after.slice(declared.length + 1);
    const { prefix: prefix2, partial: partial2 } = splitTyped(restRaw, `${MOUNT_PREFIX}/${declared}/`);
    return {
      peer: declared,
      isDefaultPeer: declared === defaultPeer,
      root: false,
      prefix: prefix2,
      partial: partial2,
      rest: restRaw.replace(/\\/gu, "/")
    };
  }
  if (slash < 0 && first !== "") {
    const hint = names.find((name2) => name2.toLowerCase().startsWith(first.toLowerCase()));
    if (hint !== void 0) {
      return { peer: "", isDefaultPeer: true, root: false, prefix: `${MOUNT_PREFIX}/`, partial: first, rest: "", peerHint: hint };
    }
  }
  const { prefix, partial } = splitTyped(after, `${MOUNT_PREFIX}/`);
  return {
    peer: "",
    isDefaultPeer: true,
    root: false,
    prefix,
    partial,
    rest: after.replace(/\\/gu, "/")
  };
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
function parseReferenceCatalog(value) {
  const rows = (v) => Array.isArray(v) ? v.filter((row) => row !== null && typeof row === "object") : [];
  return {
    available: value.available !== false,
    workspaces: rows(value.workspaces).flatMap((row) => typeof row.id === "string" && typeof row.title === "string" && typeof row.path === "string" ? [{ id: row.id, title: row.title, path: row.path }] : []),
    plugins: rows(value.plugins).flatMap((row) => typeof row.id === "string" && typeof row.name === "string" ? [{
      id: row.id,
      name: row.name,
      enabled: row.enabled === "conditional" ? "conditional" : row.enabled !== false,
      ...typeof row.title === "string" ? { title: row.title } : {},
      ...typeof row.presetId === "string" ? { presetId: row.presetId } : {}
    }] : []),
    truncated: value.truncated === true
  };
}
function matchingWorkspaces(rows, name2) {
  const id = rows.filter((row) => row.id === name2);
  return id.length > 0 ? id : rows.filter((row) => row.title === name2);
}
function workspaceChildPath(root, relative) {
  const suffix = relative.replace(/\\/gu, "/");
  if (suffix.startsWith("/") || /[\u0000-\u001f\u007f:]/u.test(suffix) || suffix.split("/").some((segment) => segment === ".." || segment === ".")) {
    throw new Error("Workspace child paths must be relative and cannot contain traversal or drive prefixes");
  }
  const base = root.replace(/\\/gu, "/").replace(/\/+$/u, "");
  if (!/^(?:[A-Za-z]:\/|\/)/u.test(`${base}/`)) throw new Error("Workspace registry returned a non-absolute path");
  return suffix === "" ? base || "/" : `${base}/${suffix}`;
}
var DEFAULT_REFERENCE_TOKEN_BOUNDS = Object.freeze({ maxChars: 65536, maxQueryLength: 2048, maxMentions: 20 });

// src/file-reference.ts
var name = "dsh-remote-file-reference";
var REMOTE_REFERENCE_PROMPT = "Remote references: @host:/C:/path is a path on that configured host; @host:workspace/child resolves a DSH named workspace; @host:plugin names a remote plugin. Use remote_references(query) to discover or resolve names; ambiguous titles require the workspace ID, and explicit host:workspace:ID / host:plugin:package disambiguate types. References discover metadata only, never create sessions or execute tools. remote_capabilities(peer) and remote_tool_call(peer, name, arguments) target that host. Markdown files/images must use absolute /rmt/<host>/C:/path; /rmt/C:/path and rmt:/\u2026 address the configured default host. Never assume a local path exists remotely.";
var DRIVE_CACHE_MS = 5 * 6e4;
var DRIVE_LETTERS = "CDEFGHIJKLMNOPQRSTUVWXYZ".split("");
var Config = z.object({
  maxResults: z.number().step(1).min(1).default(DEFAULT_FILE_SEARCH_MAX_RESULTS),
  maxEntries: z.number().step(1).min(1).default(DEFAULT_FILE_SEARCH_MAX_ENTRIES),
  excludedDirectories: z.array(z.string()).default([...DEFAULT_FILE_SEARCH_EXCLUDED_DIRECTORIES])
});
var RemoteFileReferenceService = class extends LocalFileReferenceService {
  supportsWorkspaceReferences = true;
  owner;
  remoteMaxResults;
  remotePromptFibers = /* @__PURE__ */ new Map();
  driveCaches = /* @__PURE__ */ new Map();
  warnedAt = 0;
  constructor(ctx, config = {}) {
    super(ctx, config);
    this.owner = ctx;
    this.remoteMaxResults = config.maxResults ?? DEFAULT_FILE_SEARCH_MAX_RESULTS;
    const installPrompt = (agent) => {
      if (this.remotePromptFibers.has(agent)) return;
      try {
        const fiber = agent.ctx.inject(["systemPrompt", "tools"], (scope) => {
          scope.systemPrompt.section({
            name: "context:file-reference-remote",
            order: scope.systemPrompt.getSectionOrder("FILE_REFERENCE") + 1,
            text: () => {
              if (this.fsService() === void 0) return "";
              return scope.tools.get("read", agent) === void 0 ? "" : REMOTE_REFERENCE_PROMPT;
            }
          });
        });
        this.remotePromptFibers.set(agent, fiber);
      } catch (error) {
        ctx.logger.debug(`dsh-remote-file-reference: could not install remote guidance: ${String(error)}`);
      }
    };
    const disposePrompt = (agent) => {
      const fiber = this.remotePromptFibers.get(agent);
      if (fiber === void 0) return;
      this.remotePromptFibers.delete(agent);
      void fiber.dispose().catch((error) => {
        ctx.logger.warn(`dsh-remote-file-reference: prompt cleanup failed: ${error instanceof Error ? error.message : String(error)}`);
      });
    };
    for (const agent of this.agentsList()) installPrompt(agent);
    ctx.on("agent/created", ({ agent }) => {
      installPrompt(agent);
      return void 0;
    });
    ctx.on("agent/disposed", ({ agent }) => {
      disposePrompt(agent);
      return void 0;
    });
    ctx.effect(() => async () => {
      const fibers = [...this.remotePromptFibers.values()];
      this.remotePromptFibers.clear();
      await Promise.all(fibers.map((fiber) => fiber.dispose()));
    }, "dsh-remote-file-reference: guidance");
  }
  /** The live agent list, when the registry is present. */
  agentsList() {
    try {
      const agents = this.owner.get?.("agents");
      const list = agents?.list?.();
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  }
  /** The mounted filesystem backend, only when it can resolve `rmt:` paths. */
  fsService() {
    try {
      const service = this.owner.get?.("fs");
      return service?.supportsRemotePaths === true ? service : void 0;
    } catch {
      return void 0;
    }
  }
  /**
   * Complete one `@` query.
   *
   * Three namespaces, in order:
   *  - a declared peer name spelled scp/rsync style (`home-pc:/E:/…`) — the
   *    default, so the completion menu offers a Linux-tooling-looking path;
   *  - a peer name being typed (`thi` → `home-pc:`), merged with local matches;
   *  - the `rmt:` alias for the default peer (kept for compatibility).
   * Everything else is the shipped local provider's, untouched.
   * @param agent - the agent whose completion is requested.
   * @param query - the text after `@`.
   * @param signal - caller cancellation.
   * @returns path-only candidates.
   */
  async list(agent, query, signal) {
    const fs = this.fsService();
    const peerNames = fs?.remotePeerNames?.() ?? [];
    const defaultPeer = fs?.remoteDefaultPeerName?.() ?? peerNames[0] ?? "";
    signal.throwIfAborted();
    const host = parseHostReference(query, peerNames);
    if (host !== void 0 && host.kind !== "path") {
      const service = this.owner.get("dshRemoteReferences");
      if (service !== void 0) {
        try {
          const reply = await service.list(host.peer, {
            query: host.query,
            kind: host.kind === "search" ? "all" : host.kind,
            limit: this.remoteMaxResults
          }, signal);
          const catalog = parseReferenceCatalog(reply);
          if (!catalog.available) return [];
          const exact = matchingWorkspaces(catalog.workspaces, host.query);
          if (host.relative !== "" || query.endsWith("/")) {
            if (exact.length !== 1 || catalog.truncated) return [];
            const workspace = exact[0];
            workspaceChildPath(workspace.path, host.relative);
            const end = host.relative.endsWith("/") ? host.relative.length : host.relative.lastIndexOf("/") + 1;
            const directory = host.relative.slice(0, end);
            const partial = host.relative.slice(end);
            const resolved = await service.list(host.peer, {
              query: workspace.id,
              kind: "workspace",
              relative: directory,
              resolve: true,
              limit: 2
            }, signal);
            if (resolved.status !== "resolved" || typeof resolved.path !== "string" || resolved.kind !== "directory") return [];
            const rest = `${resolved.path.replace(/\\/gu, "/").replace(/\/+$/u, "")}/${partial}`;
            return this.listRemote(fs, { peer: host.peer, isDefaultPeer: false, partial, rest }, signal);
          }
          const workspaceRows = catalog.workspaces.map((workspace) => ({
            path: scpPathFor(host.peer, workspace.path.replace(/\\/gu, "/").replace(/\/+$/u, "")),
            kind: "directory"
          }));
          const pluginRows = catalog.plugins.map((plugin) => ({ path: `${host.peer}:plugin:${plugin.name}`, kind: "file" }));
          return [...new Map([...workspaceRows, ...pluginRows].map((row) => [row.path, row])).values()].slice(0, this.remoteMaxResults);
        } catch (error) {
          return this.remoteFailure(error, signal);
        }
      }
      if (host.query !== "") return [];
    }
    const mount = parseMountReferenceQuery(query, peerNames, defaultPeer);
    if (mount !== void 0) {
      try {
        if (mount.root) return this.peerMentions(peerNames);
        if (mount.peerHint !== void 0) {
          return [{ path: `${mount.peerHint}:`, kind: "directory" }];
        }
        return await this.listRemote(fs, {
          peer: mount.peer === "" ? defaultPeer : mount.peer,
          isDefaultPeer: mount.peer === "" || mount.peer === defaultPeer,
          partial: mount.partial,
          rest: mount.rest
        }, signal);
      } catch (error) {
        return this.remoteFailure(error, signal);
      }
    }
    const scp = parseScpReferenceQuery(query, peerNames);
    if (scp !== void 0) {
      if ("peerHint" in scp) {
        const local = await super.list(agent, query, signal).catch(() => []);
        return [...local, { path: `${scp.peerHint}:`, kind: "directory" }];
      }
      try {
        return await this.listRemote(fs, {
          peer: scp.peer,
          isDefaultPeer: scp.peer === defaultPeer,
          partial: scp.partial,
          rest: scp.rest
        }, signal);
      } catch (error) {
        return this.remoteFailure(error, signal);
      }
    }
    if (/^rmt$/iu.test(query)) {
      const local = await super.list(agent, query, signal).catch(() => []);
      if (defaultPeer === "") return [...local, { path: MOUNT_PREFIX, kind: "directory" }];
      return [...local, { path: `${defaultPeer}:`, kind: "directory" }];
    }
    const parsed = parseRemoteReferenceQuery(query);
    if (parsed === void 0) {
      const workspaces = this.owner.get("workspaceReferences");
      const extra = await workspaces?.list(agent, query, signal);
      if (extra === void 0) return super.list(agent, query, signal);
      if (workspaces?.match?.(query) === "path" || /[\/\\]/u.test(query)) return extra;
      const local = await super.list(agent, query, signal);
      return [...new Map([...extra, ...local].map((row) => [row.path, row])).values()].slice(0, this.remoteMaxResults);
    }
    try {
      return await this.listRemote(fs, {
        peer: defaultPeer,
        isDefaultPeer: true,
        partial: parsed.partial,
        rest: parsed.rest
      }, signal);
    } catch (error) {
      return this.remoteFailure(error, signal);
    }
  }
  /** Peer directories offered for the mount root and for name hints. */
  peerMentions(peerNames) {
    return peerNames.map((name2) => ({ path: `${name2}:`, kind: "directory" }));
  }
  /** Log a remote-completion failure once a minute and return no candidates. */
  remoteFailure(error, signal) {
    if (error?.name === "AbortError" || signal.aborted) throw error;
    const now = Date.now();
    if (now - this.warnedAt > 6e4) {
      this.warnedAt = now;
      this.owner.logger.debug(`dsh-remote-file-reference: remote completion failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    return [];
  }
  /** Complete one remote query, emitting `host:/…` candidates it can be typed from. */
  async listRemote(fs, parsed, signal) {
    if (fs === void 0) return [];
    if (signal.aborted) throw signal.reason ?? new Error("aborted");
    if (parsed.peer === "") return [];
    const base = scpPathFor(parsed.peer, "");
    const rest = parsed.rest;
    if (rest === "" || /^[A-Za-z]:?$/u.test(rest)) {
      const roots = await this.driveRoots(fs, base, signal);
      const partial2 = rest.toLowerCase();
      return roots.filter((root) => root.toLowerCase().startsWith(partial2)).slice(0, this.remoteMaxResults).map((root) => ({
        // The mention formatter appends `/` to a directory; a candidate that
        // already carried one would render as `//`.
        path: `${base}${root.replace(/\/+$/u, "")}`,
        kind: "directory"
      }));
    }
    const directoryEnd = rest.endsWith("/") ? rest.length : rest.lastIndexOf("/") + 1;
    const directory = rest.slice(0, directoryEnd);
    const partial = rest.slice(directoryEnd).toLowerCase();
    const target = await fs.resolve(`${base}${directory}`, { signal });
    const entries = await fs.listDir(target, signal);
    const matched = entries.filter((entry) => entry.name.toLowerCase().startsWith(partial)).sort((left, right) => {
      const leftDir = left.type === "directory" ? 0 : 1;
      const rightDir = right.type === "directory" ? 0 : 1;
      return leftDir === rightDir ? left.name.localeCompare(right.name) : leftDir - rightDir;
    }).slice(0, this.remoteMaxResults);
    return matched.map((entry) => ({
      // Directory candidates are path-only too: the mention formatter owns the
      // trailing separator (and keeps a quoted directory open for descending).
      path: `${base}${directory}${entry.name}`,
      kind: entry.type === "directory" ? "directory" : "file"
    }));
  }
  /**
   * Drive roots on the peer, probed once per cache window and alias form.
   *
   * The peer protocol has no "list volumes" op; a directory probe per letter is
   * the cheap, read-only way to discover them, and the result changes rarely
   * enough to cache.
   */
  async driveRoots(fs, aliasBase, signal) {
    const cached = this.driveCaches.get(aliasBase);
    if (cached !== void 0 && Date.now() - cached.at < DRIVE_CACHE_MS) return cached.roots;
    const probes = await Promise.all(DRIVE_LETTERS.map(async (letter) => {
      const root = `${letter}:/`;
      try {
        const target = await fs.resolve(`${aliasBase}${root}`, { signal });
        const info = await fs.stat(target, signal);
        return info?.type === "directory" ? root : void 0;
      } catch {
        return void 0;
      }
    }));
    const roots = probes.filter((root) => root !== void 0);
    this.driveCaches.set(aliasBase, { at: Date.now(), roots });
    return roots;
  }
};
var file_reference_default = RemoteFileReferenceService;
export {
  Config,
  REMOTE_REFERENCE_PROMPT,
  RemoteFileReferenceService,
  file_reference_default as default,
  name
};
