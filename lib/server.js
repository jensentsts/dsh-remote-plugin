// src/server.ts
import { AsyncLocalStorage } from "node:async_hooks";
import { execFile } from "node:child_process";
import { createHash as createHash5, randomUUID as randomUUID3 } from "node:crypto";
import { appendFileSync as appendFileSync2, mkdirSync as mkdirSync4, writeFileSync as writeFileSync4 } from "node:fs";
import { readFile as readFile2, readdir, realpath, stat as stat2, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { dirname as dirname4, isAbsolute as isAbsolute2, relative, resolve as resolve2, sep } from "node:path";
import { isVolatile } from "@deepseek-ai/cosmokit";
import z2 from "@deepseek-ai/schemastery";
import { installModelSelection } from "@deepseek-ai/dsh-agent";
import { createUserMessage } from "@deepseek-ai/dsh-llm";
import { SessionId } from "@deepseek-ai/dsh-session";

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
function fingerprint(key) {
  const digest = createHash("sha256").update(rawPublic(key)).digest("hex");
  return `SHA256:${digest}`;
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
function publicToPem(key) {
  requireKey(key, "public");
  return key.export({ type: "spki", format: "pem" }).toString();
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
    await new Promise((resolve3, reject) => {
      let timer;
      let settled = false;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        if (timer !== void 0) clearTimeout(timer);
        this.sock.off("readable", wake);
        this.waiting = void 0;
        if (error === void 0) resolve3();
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
function open(key, counter, direction, body) {
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
  await new Promise((resolve3, reject) => {
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
      if (error === void 0) resolve3();
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
    await new Promise((resolve3, reject) => {
      this.queue.push({ plaintext: Buffer.from(serialized, "utf8"), bytes, resolve: resolve3, reject });
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
      const plaintext = open(this.recvKey, next, this.recvDir, body);
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
async function serverHandshake(socket, serverKey, clientKey, options = {}) {
  const reader = new ByteReader(socket);
  const deadline = Date.now() + HANDSHAKE_TIMEOUT_MS;
  let key;
  try {
    requireKey(serverKey, "private");
    requireKey(clientKey, "public");
    sessionOptions(options);
    const hello = await reader.read(MAGIC.length + 32 + NONCE_LEN, handshakeRemaining(deadline));
    if (hello === null) throw new HandshakeError("peer closed during handshake");
    if (!hello.subarray(0, MAGIC.length).equals(MAGIC)) throw new HandshakeError("peer did not speak the protocol magic");
    const cEphRaw = hello.subarray(MAGIC.length, MAGIC.length + 32);
    const cNonce = hello.subarray(MAGIC.length + 32);
    const eph = generateKeyPair();
    const sEphRaw = rawPublic(eph.publicKey);
    const sNonce = randomBytes(NONCE_LEN);
    const shared = Buffer.concat([
      ecdh(eph.privateKey, publicFromRaw(cEphRaw)),
      ecdh(serverKey, publicFromRaw(cEphRaw)),
      ecdh(eph.privateKey, clientKey)
    ]);
    try {
      key = deriveSessionKey(shared, cNonce, sNonce);
    } finally {
      shared.fill(0);
    }
    const transcript = transcriptOf(cEphRaw, sEphRaw, cNonce, sNonce);
    await writeSocket(socket, Buffer.concat([MAGIC, sEphRaw, sNonce, handshakeTag(key, Buffer.from("dshr2 server"), transcript)]), handshakeRemaining(deadline));
    const tagC = await reader.read(TAG_LEN, handshakeRemaining(deadline));
    if (tagC === null) throw new HandshakeError("peer closed before confirming");
    const expected = handshakeTag(key, Buffer.from("dshr2 client"), transcript);
    if (!timingSafeEqual(tagC, expected)) throw new HandshakeError("client authentication FAILED \u2014 unknown client key");
    return new Session(socket, reader, key, false, options);
  } catch (error) {
    destroySocket(socket);
    reader.dispose();
    throw error instanceof HandshakeError ? error : new HandshakeError("DSHR2 server handshake failed");
  } finally {
    key?.fill(0);
  }
}

// src/keys.ts
import { createPublicKey as createPublicKey2 } from "node:crypto";
import { chmodSync, closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
function text(value) {
  return value === void 0 || value.trim() === "" ? void 0 : value;
}
function dshHomePath(...segments) {
  const home = text(process.env.DSH_HOME) ?? join(homedir(), ".dsh");
  return join(home, ...segments);
}
function absolute(path) {
  return isAbsolute(path) ? path : resolve(process.cwd(), path);
}
function harden(path) {
  try {
    chmodSync(path, 384);
  } catch {
  }
}
function readKeyFile(file, privateMaterial) {
  const link = lstatSync(file);
  if (!link.isFile() || link.isSymbolicLink() || link.size > 16384) throw new Error("dsh-remote: key file must be a regular file of at most 16 KiB");
  const fd = openSync(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > 16384 || info.dev !== link.dev || info.ino !== link.ino) throw new Error("dsh-remote: key file changed while opening");
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
  mkdirSync(dirname(file), { recursive: true, mode: 448 });
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
function describeIdentity(resolved) {
  const where = resolved.file === void 0 ? "inline setting" : resolved.file;
  return `fingerprint ${fingerprint(resolved.publicKey)} from ${where}` + (resolved.generated ? " (generated just now)" : "");
}

// src/link.ts
var KEY_SELECTOR_MAGIC = Buffer.from("DSHP1", "ascii");
var KEY_SELECTOR_ACK = Buffer.from("DSHA1", "ascii");
var KEY_SELECTOR_DENIED = Buffer.from("DSHD1", "ascii");
async function readHandshakeField(socket, bytes) {
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > 4096) throw new HandshakeError("invalid handshake field size");
  return await new Promise((resolve3, reject) => {
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
      else resolve3(value);
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

// src/reference-query.ts
function matchingWorkspaces(rows, name2) {
  const id = rows.filter((row) => row.id === name2);
  return id.length > 0 ? id : rows.filter((row) => row.title === name2);
}
function workspaceChildPath(root, relative2) {
  const suffix = relative2.replace(/\\/gu, "/");
  if (suffix.startsWith("/") || /[\u0000-\u001f\u007f:]/u.test(suffix) || suffix.split("/").some((segment) => segment === ".." || segment === ".")) {
    throw new Error("Workspace child paths must be relative and cannot contain traversal or drive prefixes");
  }
  const base = root.replace(/\\/gu, "/").replace(/\/+$/u, "");
  if (!/^(?:[A-Za-z]:\/|\/)/u.test(`${base}/`)) throw new Error("Workspace registry returned a non-absolute path");
  return suffix === "" ? base || "/" : `${base}/${suffix}`;
}
var DEFAULT_REFERENCE_TOKEN_BOUNDS = Object.freeze({ maxChars: 65536, maxQueryLength: 2048, maxMentions: 20 });

// src/reference-catalog.ts
var presentable = (value) => value !== "" && !/[\u0000-\u001f\u007f"]/u.test(value);
function resourceMatches(query, ...names) {
  const needle = query.toLocaleLowerCase();
  return needle === "" || names.some((name2) => name2?.toLocaleLowerCase().includes(needle));
}
async function listReferenceCatalog(ctx, args, signal) {
  signal?.throwIfAborted();
  const query = typeof args.query === "string" ? args.query.slice(0, 300) : "";
  const limitValue = Number(args.limit ?? 40);
  const limit = Number.isFinite(limitValue) ? Math.max(1, Math.min(200, Math.trunc(limitValue))) : 40;
  const kind = args.kind === "workspace" || args.kind === "plugin" ? args.kind : "all";
  const get = (name2) => ctx.get(name2);
  const workspaces = [];
  const plugins = [];
  const errors = [];
  let workspaceAvailable = false;
  let pluginAvailable = false;
  if (kind !== "plugin") {
    const registry = get("workspaceRegistry");
    workspaceAvailable = registry !== void 0;
    for (const row of registry?.list() ?? []) {
      if (presentable(row.id) && resourceMatches(query, row.id, row.title)) {
        workspaces.push({ id: row.id, title: row.title, path: row.path });
      }
    }
  }
  if (kind !== "workspace") {
    const manager = get("pluginManager");
    const presets = get("agentPresets");
    pluginAvailable = manager !== void 0 || presets !== void 0;
    if (manager !== void 0) {
      try {
        for (const row of await manager.listPlugins()) {
          const rawTitle = row.meta?.title;
          const title = typeof rawTitle === "string" ? rawTitle : rawTitle !== null && typeof rawTitle === "object" ? Object.values(rawTitle).filter((value) => typeof value === "string").join(" \xB7 ") : void 0;
          if (!presentable(row.moduleName) || /^(?:file:|[A-Za-z]:[\\/]|\/)/u.test(row.moduleName)) continue;
          if (!resourceMatches(query, row.entryId, row.moduleName, title)) continue;
          plugins.push({
            id: row.entryId,
            name: row.moduleName,
            enabled: row.enabled,
            ...title === void 0 ? {} : { title }
          });
        }
      } catch {
        errors.push("host-plugin-inventory-unavailable");
      }
    }
    if (presets !== void 0) {
      try {
        for (const preset of await presets.compositionInventory()) {
          for (const row of preset.rows) {
            if (!presentable(row.moduleName) || /^(?:file:|[A-Za-z]:[\\/]|\/)/u.test(row.moduleName)) continue;
            if (!resourceMatches(query, row.entryId ?? void 0, row.moduleName)) continue;
            plugins.push({ id: row.entryId ?? row.moduleName, name: row.moduleName, enabled: row.enabled, presetId: preset.id });
          }
        }
      } catch {
        errors.push("preset-plugin-inventory-unavailable");
      }
    }
  }
  signal?.throwIfAborted();
  if (args.resolve === true && kind === "workspace") {
    const exact = matchingWorkspaces(workspaces, query);
    if (exact.length !== 1) return { available: true, status: exact.length === 0 ? "not-found" : "ambiguous", workspaces: exact.slice(0, limit), plugins: [], truncated: exact.length > limit };
    const workspace = exact[0];
    const fs = get("fs");
    if (fs === void 0) return { available: false, reason: "filesystem-unavailable", workspaces: [], plugins: [], truncated: false };
    const relative2 = typeof args.relative === "string" ? args.relative : "";
    const root = await fs.resolve(workspace.path, { signal });
    const target = await fs.resolve(workspaceChildPath(workspace.path, relative2), { signal });
    if (!fs.contains(root, target)) throw new Error("Workspace reference escapes its registered directory");
    const info = await fs.stat(target, signal);
    if (info === void 0) return { available: true, status: "not-found", workspaces: [workspace], plugins: [], truncated: false };
    return { available: true, status: "resolved", path: target.displayPath, kind: info.type, workspaces: [workspace], plugins: [], truncated: false };
  }
  const unique = [...new Map(plugins.map((row) => [`${row.presetId ?? ""}\0${row.id}\0${row.name}`, row])).values()];
  return {
    available: workspaceAvailable || pluginAvailable,
    workspaceAvailable,
    pluginAvailable,
    workspaces: workspaces.slice(0, limit),
    plugins: unique.slice(0, limit),
    truncated: workspaces.length > limit || unique.length > limit,
    ...errors.length === 0 ? {} : { errors }
  };
}

// src/network-guard.ts
function boundedInteger(value, fallback, min, max) {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(min, Math.min(max, Math.trunc(value))) : fallback;
}
function networkLimits(settings) {
  return {
    maxConnections: boundedInteger(settings.maxConnections, 64, 1, 1024),
    maxPendingHandshakes: boundedInteger(settings.maxPendingHandshakes, 8, 1, 128),
    maxConnectionsPerAddress: boundedInteger(settings.maxConnectionsPerAddress, 16, 1, 256),
    maxHandshakesPerMinute: boundedInteger(settings.maxHandshakesPerMinute, 120, 1, 6e3),
    maxTrackedAddresses: boundedInteger(settings.maxTrackedAddresses, 1024, 16, 65536),
    maxHandshakeFailures: boundedInteger(settings.maxHandshakeFailures, 8, 1, 100),
    lockoutMs: boundedInteger(settings.lockoutSeconds, 900, 1, 86400) * 1e3,
    handshakeTimeoutMs: boundedInteger(settings.handshakeTimeoutMs, 15e3, 50, 6e4),
    maxInFlightPerPrincipal: boundedInteger(settings.maxInFlightPerPrincipal, 16, 1, 128),
    maxSessionMs: boundedInteger(settings.maxSessionMs, 36e5, 100, 36e5)
  };
}
var NetworkGuard = class {
  read;
  now;
  addresses = /* @__PURE__ */ new Map();
  live = /* @__PURE__ */ new Map();
  active = 0;
  pending = 0;
  constructor(read, now = Date.now) {
    this.read = read;
    this.now = now;
  }
  trim(max, now) {
    for (const [address, budget] of this.addresses) {
      if (!this.live.has(address) && budget.lockedUntil <= now && now - budget.lastSeen > 6e4) this.addresses.delete(address);
    }
    while (this.addresses.size >= max) {
      const oldest = [...this.addresses].find(([address, budget]) => !this.live.has(address) && budget.lockedUntil <= now);
      if (oldest === void 0) break;
      this.addresses.delete(oldest[0]);
    }
  }
  admit(address) {
    const limits = networkLimits(this.read());
    if (this.active >= limits.maxConnections || this.pending >= limits.maxPendingHandshakes || (this.live.get(address) ?? 0) >= limits.maxConnectionsPerAddress) return void 0;
    const now = this.now();
    let budget = this.addresses.get(address);
    if (budget === void 0) {
      this.trim(limits.maxTrackedAddresses, now);
      if (this.addresses.size >= limits.maxTrackedAddresses) return void 0;
      budget = { tokens: limits.maxHandshakesPerMinute, refilled: now, lastSeen: now, failures: 0, firstFailure: now, lockedUntil: 0 };
      this.addresses.set(address, budget);
    }
    budget.tokens = Math.min(limits.maxHandshakesPerMinute, budget.tokens + Math.max(0, now - budget.refilled) * limits.maxHandshakesPerMinute / 6e4);
    budget.refilled = now;
    budget.lastSeen = now;
    if (budget.lockedUntil > now || budget.tokens < 1) return void 0;
    budget.tokens -= 1;
    this.active += 1;
    this.pending += 1;
    this.live.set(address, (this.live.get(address) ?? 0) + 1);
    let waiting = true;
    let released = false;
    const authenticated = () => {
      if (released || !waiting) return;
      waiting = false;
      this.pending -= 1;
    };
    return {
      authenticated,
      failed: () => {
        if (released || !waiting) return;
        const current = this.now();
        if (current - budget.firstFailure >= limits.lockoutMs) {
          budget.failures = 0;
          budget.firstFailure = current;
        }
        budget.failures += 1;
        if (budget.failures >= limits.maxHandshakeFailures) {
          budget.lockedUntil = current + limits.lockoutMs;
          budget.failures = 0;
          budget.firstFailure = current;
        }
        authenticated();
      },
      release: () => {
        if (released) return;
        authenticated();
        released = true;
        this.active -= 1;
        const remaining = (this.live.get(address) ?? 1) - 1;
        if (remaining <= 0) this.live.delete(address);
        else this.live.set(address, remaining);
      }
    };
  }
  /** Finite diagnostics, useful for deterministic resource-budget assertions. */
  snapshot() {
    return { active: this.active, pending: this.pending, addresses: this.addresses.size };
  }
};
function validateRequestEnvelope(value, lastId) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("request must be a JSON object");
  const request = value;
  if (request.kind === "answer" || !Object.hasOwn(request, "op") && Object.hasOwn(request, "kind")) {
    if (request.kind !== "answer" || Object.hasOwn(request, "id") || Object.hasOwn(request, "op") || typeof request.qid !== "string" || !/^[A-Za-z0-9-]{1,128}$/.test(request.qid) || !Object.hasOwn(request, "answer")) throw new Error("invalid answer envelope");
    return { type: "answer", request, qid: request.qid };
  }
  if (!Number.isSafeInteger(request.id) || request.id <= lastId || request.id <= 0) {
    throw new Error("request id must be a strictly increasing positive safe integer");
  }
  if (typeof request.op !== "string" || !/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$/.test(request.op) || request.op.length > 64) throw new Error("invalid request operation");
  return { type: "request", request, id: request.id, op: request.op };
}
async function withAuthorization(promise, signal) {
  signal.throwIfAborted();
  let abort = () => {
  };
  const cancelled = new Promise((_resolve, reject) => {
    abort = () => reject(signal.reason instanceof Error ? signal.reason : new Error("authorization revoked"));
    signal.addEventListener("abort", abort, { once: true });
  });
  try {
    return await Promise.race([promise, cancelled]);
  } finally {
    signal.removeEventListener("abort", abort);
  }
}
function expirationTime(value) {
  if (value === void 0 || value === "") return void 0;
  const match = typeof value === "string" ? /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?([Zz]|[+-]\d{2}:\d{2})$/.exec(value) : null;
  if (match === null) throw new Error("validUntil must be an RFC3339 timestamp with a time zone");
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const zone = match[7];
  const calendar = /* @__PURE__ */ new Date(0);
  calendar.setUTCFullYear(year, month - 1, day);
  if (calendar.getUTCFullYear() !== year || calendar.getUTCMonth() + 1 !== month || calendar.getUTCDate() !== day || hour > 23 || minute > 59 || second > 59 || zone === "-00:00" || zone.length > 1 && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4, 6)) > 59)) throw new Error("validUntil is invalid");
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error("validUntil is invalid");
  return parsed;
}
function allowedOperations(value) {
  if (value === void 0) return [];
  if (!Array.isArray(value) || value.length > 64 || value.some((op) => typeof op !== "string" || op.length > 64 || !/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$/.test(op))) throw new Error("allowedOps must contain at most 64 exact operation names");
  return [...new Set(value)].sort();
}

// src/relay-hub.ts
import { randomUUID } from "node:crypto";
var RELAY_MAX_BLOCK_BYTES = 48 * 1024;
var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
var RESERVED = /* @__PURE__ */ new Set(["rmt", "__proto__", "constructor", "prototype", ".", ".."]);
function validName(name2) {
  return typeof name2 === "string" && /^[A-Za-z0-9._-]{2,128}$/u.test(name2) && !RESERVED.has(name2.toLowerCase());
}
function record(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("relay: arguments must be an object");
  return value;
}
function tunnelId(value) {
  if (typeof value !== "string" || !UUID.test(value)) throw new Error("relay: invalid tunnel id");
  return value;
}
function blockBytes(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4 * Math.ceil(RELAY_MAX_BLOCK_BYTES / 3) || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) throw new Error("relay: invalid or oversized canonical base64 block");
  const bytes = Buffer.from(value, "base64");
  if (bytes.length > RELAY_MAX_BLOCK_BYTES || bytes.toString("base64") !== value) throw new Error("relay: invalid or oversized canonical base64 block");
  return bytes.length;
}
var RelayHub = class {
  options;
  now;
  limits;
  holders = /* @__PURE__ */ new Map();
  names = /* @__PURE__ */ new Map();
  principals = /* @__PURE__ */ new Map();
  tunnels = /* @__PURE__ */ new Map();
  pending = /* @__PURE__ */ new Set();
  pendingBytes = 0;
  disposed = false;
  timer;
  constructor(options) {
    if (typeof options?.authorize !== "function") throw new Error("relay: a live authorization callback is required");
    this.options = options;
    this.now = options.now ?? Date.now;
    const l = options.limits ?? {};
    this.limits = {
      maxNodes: boundedInteger(l.maxNodes, 128, 1, 128),
      maxTunnels: boundedInteger(l.maxTunnels, 128, 1, 128),
      maxTunnelsPerPrincipal: boundedInteger(l.maxTunnelsPerPrincipal, 16, 1, 16),
      maxPendingBytes: boundedInteger(l.maxPendingBytes, 1024 * 1024, 1, 1024 * 1024),
      maxPendingSends: boundedInteger(l.maxPendingSends, 128, 1, 128),
      openTimeoutMs: boundedInteger(l.openTimeoutMs, 15e3, 1, 15e3),
      idleTimeoutMs: boundedInteger(l.idleTimeoutMs, 6e5, 1, 6e5),
      sendTimeoutMs: boundedInteger(l.sendTimeoutMs, 15e3, 1, 15e3),
      sweepIntervalMs: boundedInteger(l.sweepIntervalMs, 250, 1, 1e3)
    };
    this.timer = setInterval(() => this.sweep(), Math.min(this.limits.sweepIntervalMs, this.limits.openTimeoutMs, this.limits.idleTimeoutMs));
    this.timer.unref?.();
  }
  active() {
    if (this.disposed) throw new Error("relay: hub is disposed");
  }
  same(holder, owner) {
    return owner.session === holder.session && owner.principal === holder.principal && owner.name === holder.name && owner.multi === true;
  }
  policy(holder, op) {
    try {
      if (!this.same(holder, holder.owner) || this.holders.get(holder.session) !== holder) throw new Error();
      const policy = this.options.authorize(holder.owner, op);
      if (!policy || !Array.isArray(policy.targets) || policy.targets.length > 64) throw new Error();
      const seen = /* @__PURE__ */ new Set();
      for (const target of policy.targets) {
        if (!validName(target) || seen.has(target.toLowerCase())) throw new Error();
        seen.add(target.toLowerCase());
      }
      return [...policy.targets];
    } catch {
      this.drop(holder, "authorization revoked");
      throw new Error("relay: authorization denied");
    }
  }
  owned(owner, op) {
    this.active();
    const holder = this.holders.get(owner?.session);
    if (holder === void 0 || !this.same(holder, owner)) throw new Error("relay: this authenticated session is not registered");
    this.policy(holder, op);
    return holder;
  }
  route(tunnel) {
    const source = this.policy(tunnel.source, "relay.open");
    const target = this.policy(tunnel.target, "relay.accept");
    if (!source.includes(tunnel.target.name) || !target.includes(tunnel.source.name)) {
      this.finish(tunnel, "route no longer authorized");
      throw new Error("relay: route requires both exact target allowlists");
    }
  }
  expired(tunnel) {
    const now = this.now();
    if (tunnel.state === "opening" ? now >= tunnel.deadline : now - tunnel.touched >= this.limits.idleTimeoutMs) {
      this.finish(tunnel, tunnel.state === "opening" ? "accept deadline exceeded" : "idle deadline exceeded");
      return true;
    }
    return false;
  }
  member(owner, args, op) {
    const holder = this.owned(owner, op);
    const tunnel = this.tunnels.get(tunnelId(args.tunnelId));
    if (tunnel === void 0 || tunnel.source !== holder && tunnel.target !== holder) throw new Error("relay: tunnel is not owned by this registered session");
    if (this.expired(tunnel)) throw new Error("relay: tunnel deadline exceeded");
    this.route(tunnel);
    return { holder, tunnel };
  }
  register(owner) {
    this.active();
    this.sweep();
    if (!owner || owner.multi !== true || !validName(owner.name) || typeof owner.principal !== "string" || owner.principal.length === 0 || owner.principal.length > 256 || !owner.session || typeof owner.session.send !== "function") throw new Error("relay: a named, proven multi-controller identity is required");
    const current = this.holders.get(owner.session);
    if (current !== void 0) {
      if (!this.same(current, owner)) throw new Error("relay: registration identity cannot change");
      this.policy(current, "relay.register");
      return { nodeId: current.name };
    }
    if (this.names.has(owner.name.toLowerCase()) || this.principals.has(owner.principal)) throw new Error("relay: a live node registration cannot be taken over");
    if (this.holders.size >= this.limits.maxNodes) throw new Error("relay: node registration budget exceeded");
    const holder = { owner, session: owner.session, principal: owner.principal, name: owner.name };
    this.holders.set(holder.session, holder);
    this.names.set(holder.name.toLowerCase(), holder);
    this.principals.set(holder.principal, holder);
    this.policy(holder, "relay.register");
    return { nodeId: holder.name };
  }
  open(owner, value) {
    try {
      this.sweep();
      const source = this.owned(owner, "relay.open");
      const args = record(value);
      if (!validName(args.target)) throw new Error("relay: invalid target node");
      const target = this.names.get(args.target.toLowerCase());
      if (target === void 0 || target.name !== args.target || target === source) throw new Error("relay: target is unavailable");
      const sourceTargets = this.policy(source, "relay.open");
      const targetTargets = this.policy(target, "relay.accept");
      if (!sourceTargets.includes(target.name) || !targetTargets.includes(source.name)) throw new Error("relay: route requires both exact target allowlists");
      if (this.tunnels.size >= this.limits.maxTunnels || [source, target].some((holder) => this.count(holder) >= this.limits.maxTunnelsPerPrincipal)) {
        throw new Error("relay: tunnel budget exceeded");
      }
      let resolve3;
      let reject;
      const result = new Promise((yes, no) => {
        resolve3 = yes;
        reject = no;
      });
      void result.catch(() => {
      });
      const now = this.now();
      const tunnel = {
        id: randomUUID(),
        source,
        target,
        state: "opening",
        deadline: now + this.limits.openTimeoutMs,
        touched: now,
        sourceSeq: 0,
        targetSeq: 0,
        resolve: resolve3,
        reject
      };
      this.tunnels.set(tunnel.id, tunnel);
      void this.send(target, { kind: "relay.offer", tunnelId: tunnel.id, from: source.name }, tunnel.id).catch(() => this.finish(tunnel, "offer delivery failed"));
      return result;
    } catch (error) {
      return Promise.reject(error);
    }
  }
  async accept(owner, value) {
    const { holder, tunnel } = this.member(owner, record(value), "relay.accept");
    if (holder !== tunnel.target || tunnel.state !== "opening") throw new Error("relay: only the offered target may accept once");
    tunnel.state = "open";
    tunnel.touched = this.now();
    tunnel.resolve({ tunnelId: tunnel.id });
    return { accepted: true };
  }
  async write(owner, value) {
    const args = record(value);
    const { holder, tunnel } = this.member(owner, args, "relay.write");
    try {
      if (tunnel.state !== "open") throw new Error("relay: tunnel is not accepted");
      const key = holder === tunnel.source ? "sourceSeq" : "targetSeq";
      if (!Number.isSafeInteger(args.seq) || args.seq < 1 || tunnel[key] >= Number.MAX_SAFE_INTEGER || args.seq !== tunnel[key] + 1) {
        throw new Error("relay: sequence must increase by exactly one");
      }
      blockBytes(args.dataB64);
      tunnel[key] = args.seq;
      tunnel.touched = this.now();
      const destination = holder === tunnel.source ? tunnel.target : tunnel.source;
      await this.send(destination, { kind: "relay.data", tunnelId: tunnel.id, seq: args.seq, dataB64: args.dataB64 }, tunnel.id);
      if (this.tunnels.get(tunnel.id) !== tunnel) throw new Error("relay: tunnel closed during write");
      this.route(tunnel);
      return { written: true };
    } catch (error) {
      this.finish(tunnel, "write failed");
      throw error;
    }
  }
  async close(owner, value) {
    const holder = this.owned(owner, "relay.close");
    const id = tunnelId(record(value).tunnelId);
    const tunnel = this.tunnels.get(id);
    if (tunnel === void 0) return { closed: false };
    if (tunnel.source !== holder && tunnel.target !== holder) throw new Error("relay: tunnel is not owned by this registered session");
    this.finish(tunnel, "closed by endpoint");
    return { closed: true };
  }
  status(owner) {
    this.sweep();
    const holder = this.owned(owner, "relay.status");
    const allowed = this.policy(holder, "relay.open");
    const targets = [];
    for (const candidate of this.holders.values()) {
      if (candidate === holder || !allowed.includes(candidate.name)) continue;
      try {
        if (this.policy(candidate, "relay.accept").includes(holder.name)) targets.push(candidate.name);
      } catch {
      }
    }
    return { nodeId: holder.name, targets: targets.sort(), tunnels: [...this.tunnels.values()].filter((tunnel) => tunnel.source === holder || tunnel.target === holder).map((tunnel) => ({ tunnelId: tunnel.id, target: tunnel.source === holder ? tunnel.target.name : tunnel.source.name, state: tunnel.state })) };
  }
  /** Transport lifetime is session-local, not a same-key reconnect's lifetime. */
  detach(session) {
    const holder = this.holders.get(session);
    if (holder !== void 0) this.drop(holder, "endpoint disconnected");
  }
  revoke(principal) {
    const holder = this.principals.get(principal);
    if (holder !== void 0) this.drop(holder, "authorization revoked");
  }
  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    clearInterval(this.timer);
    for (const tunnel of this.tunnels.values()) this.finish(tunnel, "hub disposed");
    this.holders.clear();
    this.names.clear();
    this.principals.clear();
    for (const pending of this.pending) pending.cancel(new Error("relay: hub disposed"));
  }
  count(holder) {
    let count = 0;
    for (const tunnel of this.tunnels.values()) if (tunnel.source.principal === holder.principal || tunnel.target.principal === holder.principal) count++;
    return count;
  }
  drop(holder, reason) {
    if (this.holders.get(holder.session) !== holder) return;
    this.holders.delete(holder.session);
    this.names.delete(holder.name.toLowerCase());
    this.principals.delete(holder.principal);
    for (const tunnel of this.tunnels.values()) if (tunnel.source === holder || tunnel.target === holder) this.finish(tunnel, reason);
    for (const pending of this.pending) if (pending.session === holder.session) pending.cancel(new Error("relay: endpoint disconnected"));
  }
  finish(tunnel, reason) {
    if (this.tunnels.get(tunnel.id) !== tunnel) return;
    this.tunnels.delete(tunnel.id);
    tunnel.reject(new Error(`relay: ${reason}`));
    for (const pending of this.pending) if (pending.tunnelId === tunnel.id) pending.cancel(new Error(`relay: ${reason}`));
    for (const holder of [tunnel.source, tunnel.target]) {
      if (this.holders.get(holder.session) !== holder) continue;
      void this.send(holder, { kind: "relay.closed", tunnelId: tunnel.id, reason }, tunnel.id).catch(() => {
      });
    }
  }
  sweep() {
    if (this.disposed) return;
    for (const holder of this.holders.values()) {
      try {
        this.policy(holder, "relay.register");
      } catch {
      }
    }
    for (const tunnel of this.tunnels.values()) {
      if (this.expired(tunnel)) continue;
      try {
        this.route(tunnel);
      } catch {
        this.finish(tunnel, "authorization revoked");
      }
    }
  }
  send(holder, event, id) {
    const bytes = Buffer.byteLength(JSON.stringify(event), "utf8");
    if (this.pending.size >= this.limits.maxPendingSends || this.pendingBytes + bytes > this.limits.maxPendingBytes) return Promise.reject(new Error("relay: pending send budget exceeded"));
    let resolve3;
    let reject;
    const result = new Promise((yes, no) => {
      resolve3 = yes;
      reject = no;
    });
    let finished = false;
    const settle = (error) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (error === void 0) resolve3();
      else reject(error);
    };
    const pending = { tunnelId: id, session: holder.session, bytes, cancel: (error) => settle(error) };
    const release = () => {
      if (this.pending.delete(pending)) this.pendingBytes -= bytes;
    };
    const timer = setTimeout(() => settle(new Error("relay: send deadline exceeded")), this.limits.sendTimeoutMs);
    timer.unref?.();
    this.pending.add(pending);
    this.pendingBytes += bytes;
    try {
      Promise.resolve(holder.session.send(event)).then(() => {
        release();
        settle();
      }, () => {
        release();
        settle(new Error("relay: event delivery failed"));
      });
    } catch {
      release();
      settle(new Error("relay: event delivery failed"));
    }
    return result;
  }
};

// src/server.ts
import { FsError as FsError2 } from "@deepseek-ai/dsh-fs";

// src/peers.ts
import { Service } from "@deepseek-ai/cordis";
import { FsError } from "@deepseek-ai/dsh-fs";
import z from "@deepseek-ai/schemastery";
import { posix } from "node:path";
var MIN_PERMISSION = 1;
var MAX_PERMISSION = 3;
var DEFAULT_PERMISSION = MIN_PERMISSION;
function validatePeerNames(names) {
  const seen = /* @__PURE__ */ new Set();
  for (const name2 of names) {
    const folded = name2.toLowerCase();
    if (!/^[A-Za-z0-9._-]{2,}$/.test(name2) || name2 === "." || name2 === ".." || ["rmt", "__proto__", "constructor", "prototype"].includes(folded)) {
      throw new Error(`invalid peer name ${JSON.stringify(name2)}: use at least two ASCII letters, digits, dots, underscores or hyphens; rmt, . and .. are reserved`);
    }
    if (seen.has(folded)) throw new Error(`duplicate peer name ${JSON.stringify(name2)} (names are case-insensitive)`);
    seen.add(folded);
  }
}
var PeerProfileSchema = z.object({
  host: z.string().default(""),
  port: z.number().default(0),
  relayTarget: z.string().default(""),
  maxPermission: z.number().default(DEFAULT_PERMISSION),
  workspaceRoot: z.string().default(""),
  privateKey: z.string().role("secret").default(""),
  privateKeyFile: z.string().default(dshHomePath("dsh-remote", "client.key")),
  autoGenerateKey: z.boolean().default(true),
  peerPublicKey: z.string().default(""),
  peerPublicKeyFile: z.string().default(dshHomePath("dsh-remote", "server.pub")),
  timeoutMs: z.number().default(12e4),
  allowLegacyHandshake: z.boolean().default(false),
  maxSessionMs: z.number().default(36e5)
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
    throw new FsError(
      `refusing ${op} on ${who}: it needs permission level ${needed} (${levelName(needed)}) but the ceiling is ${level} (${levelName(level)})`,
      "FS_PERMISSION_DENIED"
    );
  }
  if (level === 2 && needed === 2 && context.path !== void 0 && !isRemoteUnder(context.path, context.workspaceRoot ?? "")) {
    throw new FsError(
      `refusing ${op} on ${who}: "${context.path}" is outside the declared workspace "${context.workspaceRoot ?? ""}" (level 2 is confined)`,
      "FS_PERMISSION_DENIED"
    );
  }
}
var PeerRegistryConfig = z.object({
  peers: z.dict(PeerProfileSchema).default({}),
  defaultPeer: z.string().default("")
});

// src/exec-registry.ts
var ExecRegistry = class {
  running = /* @__PURE__ */ new Map();
  /**
   * Track one child.
   * @param id - the caller's id for this execution.
   * @param child - the handle to cancel.
   * @returns the disposer to call when the child settles; idempotent, and a
   *   stale disposer can never remove a newer entry that reused the id.
   */
  add(id, child) {
    if (id === "") return () => {
    };
    this.running.set(id, child);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      if (this.running.get(id) === child) this.running.delete(id);
    };
  }
  /**
   * Cancel one running child.
   * @param id - the id the execution was registered under.
   * @returns true when something was running and was asked to stop.
   */
  cancel(id) {
    const child = this.running.get(id);
    if (child === void 0) return false;
    this.running.delete(id);
    try {
      child.cancel();
    } catch {
    }
    return true;
  }
  /** How many children are tracked (for logs and tests). */
  get size() {
    return this.running.size;
  }
  /** Whether an id is currently running. */
  has(id) {
    return this.running.has(id);
  }
  /** Cancel everything; used when the process itself is going away. */
  cancelAll() {
    const ids = [...this.running.keys()];
    for (const id of ids) this.cancel(id);
    return ids.length;
  }
};

// src/journal.ts
import { appendFileSync, mkdirSync as mkdirSync2, readFileSync, renameSync, statSync, writeFileSync as writeFileSync2 } from "node:fs";
import { dirname as dirname2 } from "node:path";
var DEFAULT_MAX_BYTES = 8 * 1024 * 1024;
var DEFAULT_RING = 5e3;
var DETAIL_LIMIT = 2e3;
function clip(value, limit = DETAIL_LIMIT) {
  return value.length <= limit ? value : `${value.slice(0, limit)}\u2026(+${value.length - limit})`;
}
function safeDetail(value, depth = 0) {
  if (typeof value === "string") return clip(value);
  if (value === null || typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return depth > 3 ? `[${value.length} items]` : value.slice(0, 20).map((item) => safeDetail(item, depth + 1));
  if (typeof value === "object") {
    if (depth > 3) return "[deep]";
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (key === "dataB64" || key === "content" || key === "stdout" || key === "stderr") {
        out[key] = typeof item === "string" ? `${item.length} chars` : safeDetail(item, depth + 1);
        continue;
      }
      out[key] = safeDetail(item, depth + 1);
    }
    return out;
  }
  return void 0;
}
function summarizeOp(op, args, outcome) {
  const bits = [];
  if (op === "exec") bits.push(String(args.cmd ?? "").split("\n")[0]?.slice(0, 120) ?? "");
  else if (op === "caps.call") bits.push(String(args.name ?? "").slice(0, 120));
  else if (typeof args.path === "string") bits.push(clip(args.path, 200));
  else if (typeof args.sessionId === "string") bits.push(String(args.sessionId));
  else if (typeof args.execId === "string") bits.push(String(args.execId));
  const target = bits.filter((part) => part !== "").join(" ");
  const result = outcome.result ?? {};
  const facts = [];
  if (outcome.ok) {
    if (typeof result.exit === "number" || result.exit === null) facts.push(`exit ${String(result.exit)}`);
    if (result.cancelled === true) facts.push("cancelled");
    if (result.timedOut === true) facts.push("timed out");
    if (typeof result.reply === "string") facts.push(`${result.reply.length} chars reply`);
    if (typeof result.count === "number") facts.push(`${result.count} items`);
    if (typeof result.written === "number") facts.push(`${result.written} bytes`);
    if (typeof result.sessionId === "string") facts.push(`session ${result.sessionId}`);
    if (result.created === true) facts.push("created");
    if (result.interrupted === true) facts.push("interrupted");
  } else {
    facts.push(`FAILED ${clip(outcome.error ?? "", 160)}`);
  }
  const summary = `${op}${target === "" ? "" : ` ${target}`} \u2192 ${facts.length === 0 ? outcome.ok ? "ok" : "failed" : facts.join(", ")}`;
  return {
    summary: clip(summary, 400),
    detail: { args: safeDetail(args), ...outcome.result === void 0 ? {} : { result: safeDetail(outcome.result) } }
  };
}
function summarizeEvent(type, data) {
  const payload = data ?? {};
  if (type === "turn/end") {
    const reason = payload.reason;
    const cause = reason?.reason?.kind;
    return {
      kind: reason?.kind === "aborted" ? "interrupt" : "turn",
      summary: `turn ${String(payload.turn ?? "?")} ended: ${String(reason?.kind ?? "unknown")}${cause === void 0 ? "" : ` (${cause})`}`,
      detail: { reason: safeDetail(reason) }
    };
  }
  if (type === "assistant/message") {
    const message = payload.message;
    const blocks = message?.content ?? [];
    const text2 = blocks.filter((block) => block.type === "text").map((block) => block.text ?? "").join("");
    const calls = blocks.filter((block) => block.type === "tool-call").map((block) => String(block.name ?? "?")).filter((name2) => name2 !== "?");
    return {
      kind: "model",
      summary: `model replied: ${text2.length} chars${calls.length === 0 ? "" : `, tools: ${calls.slice(0, 6).join(", ")}`}`,
      detail: { text: clip(text2, 800) }
    };
  }
  if (type === "user/message") {
    const blocks = payload.content ?? [];
    const text2 = blocks.filter((block) => block.type === "text").map((block) => block.text ?? "").join("");
    const source = payload.source;
    const human = source?.kind === "user" && typeof source.rpcId === "string";
    return {
      kind: "note",
      summary: `${human ? "this machine's user" : "injected"} message: ${clip(text2.replace(/\s+/gu, " "), 160)}`,
      detail: { text: clip(text2, 800) }
    };
  }
  return void 0;
}
var Journal = class {
  file;
  maxBytes;
  ringSize;
  now;
  ring = [];
  next = 1;
  written = 0;
  bytes = 0;
  /** @param options - file location, rotation ceiling, ring size, clock. */
  constructor(options) {
    this.file = options.file;
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
    this.ringSize = options.ringSize ?? DEFAULT_RING;
    this.now = options.now ?? (() => /* @__PURE__ */ new Date());
  }
  /** Resume `seq` and `count` from the file; never throws. */
  load() {
    try {
      const size = statSync(this.file).size;
      this.bytes = size;
      const text2 = readFileSync(this.file, "utf8");
      const lines = text2.split("\n").filter((line) => line.trim() !== "");
      for (const line of lines.slice(-this.ringSize)) {
        try {
          const entry = JSON.parse(line);
          if (typeof entry?.seq === "number") this.ring.push(entry);
        } catch {
        }
      }
      const last = this.ring.at(-1);
      this.next = (last?.seq ?? 0) + 1;
      this.written = lines.length;
    } catch {
    }
  }
  /** Append one entry, assigning its seq and instant. */
  append(entry) {
    const full = {
      seq: this.next,
      at: entry.at ?? this.now().toISOString(),
      ...entry
    };
    this.next += 1;
    this.written += 1;
    this.ring.push(full);
    while (this.ring.length > this.ringSize) this.ring.shift();
    try {
      mkdirSync2(dirname2(this.file), { recursive: true });
      const line = `${JSON.stringify(full)}
`;
      if (this.bytes + line.length > this.maxBytes) this.rotate();
      appendFileSync(this.file, line, "utf8");
      this.bytes += Buffer.byteLength(line);
    } catch {
    }
    return full;
  }
  /** Keep one previous file so a reader can still walk back one generation. */
  rotate() {
    try {
      renameSync(this.file, `${this.file}.1`);
      writeFileSync2(this.file, "", "utf8");
      this.bytes = 0;
    } catch {
    }
  }
  /** Highest seq assigned so far. */
  get lastSeq() {
    return this.next - 1;
  }
  /** Entries this process has written (including rotated-away ones). */
  get writtenCount() {
    return this.written;
  }
  /**
   * Read entries after `fromSeq`.
   *
   * Served from the in-memory tail when possible, otherwise by scanning the file
   * (and its one rotated predecessor), so a fresh process can still answer a read
   * for history it did not write.
   *
   * @param fromSeq - exclusive lower bound; 0 means "from the beginning".
   * @param limit - maximum entries to return.
   * @param full - include `detail`.
   */
  read(fromSeq, limit, full) {
    const start = Number.isFinite(fromSeq) && fromSeq > 0 ? Math.floor(fromSeq) : 0;
    const cap = Number.isFinite(limit) && limit > 0 ? Math.min(Math.floor(limit), 500) : 100;
    const source = this.ring.some((entry) => entry.seq > start) ? this.ring : this.readFileEntries();
    const selected = source.filter((entry) => entry.seq > start).slice(0, cap);
    const entries = full ? selected : selected.map((entry) => stripDetail(entry));
    return {
      fromSeq: start,
      nextSeq: entries.at(-1)?.seq ?? start,
      total: this.written,
      count: entries.length,
      entries
    };
  }
  readFileEntries() {
    const out = [];
    for (const path of [`${this.file}.1`, this.file]) {
      try {
        for (const line of readFileSync(path, "utf8").split("\n")) {
          if (line.trim() === "") continue;
          try {
            const entry = JSON.parse(line);
            if (typeof entry?.seq === "number") out.push(entry);
          } catch {
          }
        }
      } catch {
      }
    }
    return out.sort((a, b) => a.seq - b.seq).slice(-this.ringSize);
  }
};
function stripDetail(entry) {
  if (entry.detail === void 0) return entry;
  const { detail: _detail, ...rest } = entry;
  return rest;
}

// src/transfer-server.ts
import { createHash as createHash2, randomUUID as randomUUID2 } from "node:crypto";
import { mkdirSync as mkdirSync3, renameSync as renameSync2, unlinkSync, writeFileSync as writeFileSync3 } from "node:fs";
import { open as open2, readFile, stat } from "node:fs/promises";
import { dirname as dirname3 } from "node:path";
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

// src/transfer-server.ts
var MIN_CHUNK_BYTES = 64 * 1024;
var MAX_CHUNK_BYTES = 8 * 1024 * 1024;
var DEFAULT_CHUNK_BYTES = 1024 * 1024;
var SWEEP_INTERVAL_MS = 6e4;
var TransferFsError = class extends Error {
  code;
  constructor(message, code) {
    super(message);
    this.name = "FsError";
    this.code = code;
  }
};
function versionOf(info) {
  return `${info.mtimeMs}:${info.size}`;
}
function clamp(value, low, high) {
  return Math.min(Math.max(value, low), high);
}
function limitOf(value, fallback) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) return fallback;
  return Math.floor(numeric);
}
function stringArg(op, value, field) {
  if (typeof value !== "string" || value === "") {
    throw new Error(`${op}: ${field} is required`);
  }
  return value;
}
function encodingOf(op, value, fallback) {
  if (value === void 0) return fallback;
  if (value === "gzip" || value === "raw") return value;
  throw new Error(`${op}: encoding must be "gzip" or "raw"`);
}
function createTransferServer(options) {
  const uploads = /* @__PURE__ */ new Map();
  const limit = (key, fallback) => {
    try {
      return limitOf(options.read()[key], fallback);
    } catch {
      return fallback;
    }
  };
  const log = (level, message) => {
    try {
      options.log?.[level](message);
    } catch {
    }
  };
  const forget = (upload) => {
    uploads.delete(upload.uploadId);
    try {
      unlinkSync(upload.tempPath);
    } catch {
    }
  };
  const digestOf = async (path) => {
    const handle = await open2(path, "r");
    try {
      const hash = createHash2("sha256");
      const buffer = Buffer.allocUnsafe(1024 * 1024);
      let position = 0;
      let total = 0;
      for (; ; ) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
        if (bytesRead === 0) break;
        hash.update(buffer.subarray(0, bytesRead));
        position += bytesRead;
        total += bytesRead;
      }
      return { hash: hash.digest("hex"), bytes: total };
    } finally {
      await handle.close();
    }
  };
  const failCommit = (upload, message, code) => {
    forget(upload);
    throw code === void 0 ? new Error(message) : new TransferFsError(message, code);
  };
  const begin = async (args) => {
    const path = stringArg("fs.put.begin", args.path, "path");
    const maxBytes = limit("transferMaxBytes", 1024 * 1024 * 1024);
    const declared = Number(args.size);
    if (!Number.isSafeInteger(declared) || declared < 0) {
      throw new Error("fs.put.begin: size must be a non-negative safe integer");
    }
    if (declared > maxBytes) {
      throw new Error(`fs.put.begin: size ${declared} exceeds transferMaxBytes (${maxBytes})`);
    }
    const sha256 = String(args.sha256 ?? "").toLowerCase();
    if (!/^[0-9a-f]{64}$/u.test(sha256)) {
      throw new Error("fs.put.begin: sha256 must be 64 hexadecimal characters");
    }
    let chunkSize = DEFAULT_CHUNK_BYTES;
    if (args.chunkSize !== void 0) {
      const asked = Number(args.chunkSize);
      if (Number.isFinite(asked)) chunkSize = Math.floor(clamp(asked, MIN_CHUNK_BYTES, MAX_CHUNK_BYTES));
    }
    const encoding = encodingOf("fs.put.begin", args.encoding, "gzip");
    const createOnly = args.createOnly === true;
    const expectedVersion = typeof args.expectedVersion === "string" && args.expectedVersion !== "" ? args.expectedVersion : void 0;
    const maxActive = Math.max(1, limit("transferMaxActive", 8));
    if (uploads.size >= maxActive) {
      throw new Error("fs.put.begin: too many active transfers");
    }
    mkdirSync3(dirname3(path), { recursive: true });
    const uploadId = randomUUID2();
    const tempPath = `${path}.${uploadId}.dshremote-upload`;
    writeFileSync3(tempPath, Buffer.alloc(0), { flag: "wx", mode: 384 });
    const upload = {
      uploadId,
      path,
      tempPath,
      size: declared,
      sha256,
      chunkSize,
      encoding,
      createOnly,
      expectedVersion,
      chunks: /* @__PURE__ */ new Map(),
      received: 0,
      lastActive: Date.now()
    };
    uploads.set(uploadId, upload);
    log("debug", `dsh-remote-transfer: begin ${uploadId} ${path} (${declared} bytes, ${chunkSize}-byte ${encoding} blocks)`);
    return { uploadId, chunkSize, size: declared };
  };
  const chunk = async (args) => {
    const uploadId = stringArg("fs.put.chunk", args.uploadId, "uploadId");
    const upload = uploads.get(uploadId);
    if (upload === void 0) throw new Error("fs.put.chunk: unknown uploadId");
    const index = Number(args.index);
    const blockCount = Math.ceil(upload.size / upload.chunkSize);
    if (!Number.isSafeInteger(index) || index < 0 || index >= blockCount) {
      throw new Error(`fs.put.chunk: index must be an integer in 0..${Math.max(0, blockCount - 1)}`);
    }
    if (typeof args.dataB64 !== "string") {
      throw new Error("fs.put.chunk: dataB64 must be a base64 string");
    }
    const expected = Math.min(upload.chunkSize, upload.size - index * upload.chunkSize);
    const encoding = encodingOf("fs.put.chunk", args.encoding, upload.encoding);
    const wire = decodeTransferBlock(args.dataB64, expected);
    let data;
    if (encoding === "gzip") {
      try {
        data = gunzipSync(wire, { maxOutputLength: expected + 1 });
      } catch {
        throw new Error(`fs.put.chunk: block ${index} is not valid gzip`);
      }
      if (data.length !== expected) {
        throw new Error(`fs.put.chunk: block ${index} inflated to ${data.length} bytes, expected ${expected}`);
      }
    } else {
      data = wire;
      if (data.length !== expected) {
        throw new Error(`fs.put.chunk: block ${index} is ${data.length} bytes, expected ${expected}`);
      }
    }
    const handle = await open2(upload.tempPath, "r+");
    try {
      const { bytesWritten } = await handle.write(data, 0, data.length, index * upload.chunkSize);
      if (bytesWritten !== data.length) {
        throw new Error(`fs.put.chunk: short write for block ${index} (${bytesWritten}/${data.length})`);
      }
    } finally {
      await handle.close();
    }
    if (uploads.get(uploadId) !== upload) throw new Error("fs.put.chunk: upload was aborted");
    const previous = upload.chunks.get(index);
    if (previous === void 0) {
      upload.chunks.set(index, expected);
      upload.received += expected;
    }
    upload.lastActive = Date.now();
    return { uploadId, index, received: expected };
  };
  const commit = async (args) => {
    const uploadId = stringArg("fs.put.commit", args.uploadId, "uploadId");
    const upload = uploads.get(uploadId);
    if (upload === void 0) throw new Error("fs.put.commit: unknown uploadId");
    let tempInfo;
    try {
      tempInfo = await stat(upload.tempPath);
    } catch {
      return failCommit(upload, `fs.put.commit: staging file for ${upload.path} is gone`);
    }
    if (!tempInfo.isFile()) {
      return failCommit(upload, `fs.put.commit: staging path for ${upload.path} is not a regular file`);
    }
    if (tempInfo.size !== upload.size) {
      return failCommit(
        upload,
        `fs.put.commit: ${upload.path} is ${tempInfo.size} bytes, expected ${upload.size}`
      );
    }
    let digest;
    try {
      digest = await digestOf(upload.tempPath);
    } catch (error) {
      return failCommit(upload, `fs.put.commit: could not read the staged bytes: ${messageOf(error)}`);
    }
    if (digest.bytes !== upload.size) {
      return failCommit(upload, `fs.put.commit: staged ${digest.bytes} bytes, expected ${upload.size}`);
    }
    if (digest.hash !== upload.sha256) {
      return failCommit(upload, `fs.put.commit: sha256 mismatch for ${upload.path} (got ${digest.hash})`);
    }
    const existing = await stat(upload.path).catch(() => void 0);
    const beforeBytes = existing === void 0 ? 0 : existing.size;
    if (upload.createOnly && existing !== void 0) {
      return failCommit(
        upload,
        `cannot overwrite existing "${upload.path}" without reading it first`,
        "FS_NOT_OBSERVED"
      );
    }
    if (upload.expectedVersion !== void 0) {
      if (existing === void 0) {
        return failCommit(upload, `cannot write "${upload.path}": file no longer exists`, "FS_STALE_VERSION");
      }
      if (versionOf(existing) !== upload.expectedVersion) {
        return failCommit(upload, `cannot write "${upload.path}": file changed since it was read`, "FS_STALE_VERSION");
      }
    }
    const beforeMax = limit("transferBeforeMaxBytes", 1024 * 1024);
    let before = null;
    if (existing !== void 0 && existing.isFile() && existing.size <= beforeMax) {
      before = await readFile(upload.path).then((bytes) => bytes.toString("utf8")).catch(() => null);
    }
    try {
      renameSync2(upload.tempPath, upload.path);
    } catch (error) {
      return failCommit(upload, `fs.put.commit: could not replace "${upload.path}": ${messageOf(error)}`);
    }
    uploads.delete(uploadId);
    const after = await stat(upload.path).catch(() => void 0);
    const version = after === void 0 ? versionOf(tempInfo) : versionOf(after);
    log("debug", `dsh-remote-transfer: commit ${uploadId} ${upload.path} (${digest.bytes} bytes, sha256 ${digest.hash.slice(0, 12)})`);
    return {
      uploadId,
      size: upload.size,
      sha256: digest.hash,
      created: existing === void 0,
      version,
      path: upload.path,
      before,
      beforeBytes
    };
  };
  const abort = async (args) => {
    const uploadId = String(args.uploadId ?? "");
    const upload = uploadId === "" ? void 0 : uploads.get(uploadId);
    if (upload === void 0) return { uploadId, aborted: false };
    forget(upload);
    log("debug", `dsh-remote-transfer: abort ${uploadId} ${upload.path}`);
    return { uploadId, aborted: true };
  };
  const get = async (args) => {
    const path = stringArg("fs.get", args.path, "path");
    const rawOffset = args.offset === void 0 ? 0 : Number(args.offset);
    if (!Number.isSafeInteger(rawOffset) || rawOffset < 0) {
      throw new Error("fs.get: offset must be a non-negative safe integer");
    }
    const offset = rawOffset;
    const maxChunk = Math.max(1, limit("transferMaxChunkBytes", MAX_CHUNK_BYTES));
    const askedLength = args.length === void 0 ? maxChunk : Number(args.length);
    const length = Number.isFinite(askedLength) ? clamp(Math.floor(askedLength), 1, maxChunk) : maxChunk;
    const encoding = encodingOf("fs.get", args.encoding, "raw");
    let info;
    try {
      info = await stat(path);
    } catch (error) {
      const code = error.code;
      if (code === "ENOENT") throw new TransferFsError(`cannot read "${path}": not found`, "FS_NOT_FOUND");
      throw new TransferFsError(`cannot read "${path}": ${messageOf(error)}`, "FS_IO_ERROR");
    }
    if (!info.isFile()) {
      throw new TransferFsError(`cannot read "${path}": not a regular file`, "FS_NOT_REGULAR_FILE");
    }
    const size = info.size;
    if (offset >= size) {
      return { dataB64: "", encoding: "raw", offset, bytes: 0, size, eof: true };
    }
    const want = Math.min(length, size - offset);
    let data = Buffer.alloc(want);
    const handle = await open2(path, "r");
    try {
      let filled = 0;
      while (filled < want) {
        const { bytesRead } = await handle.read(data, filled, want - filled, offset + filled);
        if (bytesRead === 0) break;
        filled += bytesRead;
      }
      if (filled < want) data = data.subarray(0, filled);
    } finally {
      await handle.close();
    }
    let payload = data;
    let wire = "raw";
    if (encoding === "gzip") {
      const packed = gzipSync(data);
      if (packed.length < Math.floor(data.length * 0.95)) {
        payload = packed;
        wire = "gzip";
      }
    }
    return {
      dataB64: payload.toString("base64"),
      encoding: wire,
      offset,
      bytes: data.length,
      size,
      eof: offset + data.length >= size
    };
  };
  const sweep = () => {
    const ttl = Math.max(0, limit("transferUploadTtlMs", 6e5));
    const now = Date.now();
    for (const upload of [...uploads.values()]) {
      if (now - upload.lastActive <= ttl) continue;
      forget(upload);
      log("debug", `dsh-remote-transfer: expired ${upload.uploadId} ${upload.path}`);
    }
  };
  const sweeper = setInterval(sweep, SWEEP_INTERVAL_MS);
  sweeper.unref();
  return {
    begin,
    chunk,
    commit,
    abort,
    get,
    dispose() {
      clearInterval(sweeper);
      for (const upload of [...uploads.values()]) forget(upload);
      uploads.clear();
    }
  };
}
function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

// src/reuse.ts
function normalizePath(value) {
  return value.replace(/\\/gu, "/").replace(/\/+$/u, "").toLowerCase();
}
function familyMatches(prefix, sessionId) {
  const family = prefix.trim();
  if (family === "") return true;
  return sessionId === family || sessionId.startsWith(`${family}-`);
}
function orderReusableSessions(accounts, options) {
  const wanted = options.workspace === void 0 || options.workspace.trim() === "" ? void 0 : normalizePath(options.workspace);
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const account of accounts) {
    if (wanted !== void 0 && normalizePath(account.path) !== wanted) continue;
    for (const rawId of account.sessionIds) {
      const sessionId = String(rawId);
      if (sessionId === "" || seen.has(sessionId)) continue;
      if (!familyMatches(options.prefix, sessionId)) continue;
      seen.add(sessionId);
      out.push({ sessionId, cwd: account.path });
    }
  }
  return out;
}

// src/session-usage.ts
var DEFAULT_LIMIT = 500;
var MAX_LIMIT = 2e3;
function asRecord(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return void 0;
  return value;
}
function normalizeTokenCount(value) {
  if (typeof value !== "number") return void 0;
  return Number.isSafeInteger(value) && value >= 0 ? value : void 0;
}
function nonEmptyString(value) {
  return typeof value === "string" && value !== "" ? value : void 0;
}
function optionalBucket(value) {
  if (value === void 0 || value === null) return 0;
  const count = normalizeTokenCount(value);
  return count === void 0 ? null : count;
}
function normalizeUsage(raw) {
  const usage = asRecord(raw);
  if (usage === void 0) return void 0;
  const input = normalizeTokenCount(usage.inputTokens);
  const output = normalizeTokenCount(usage.outputTokens);
  if (input === void 0 || output === void 0) return void 0;
  const cacheRead = optionalBucket(usage.cacheReadTokens);
  const cacheWrite = optionalBucket(usage.cacheWriteTokens);
  const reasoning = optionalBucket(usage.reasoningTokens);
  if (cacheRead === null || cacheWrite === null || reasoning === null) return void 0;
  return { input, output, cacheRead, cacheWrite, reasoning };
}
function readPosition(data) {
  return {
    turn: normalizeTokenCount(data.turn) ?? null,
    step: normalizeTokenCount(data.step) ?? null
  };
}
function callKey(seq, turn, step) {
  return turn !== null && step !== null ? `call:${turn}:${step}` : `seq:${seq}`;
}
function eventTime(event) {
  const time = event.time;
  return typeof time === "number" && Number.isFinite(time) && time > 0 ? time : void 0;
}
function sameUsage(a, b) {
  return a.input === b.input && a.output === b.output && a.cacheRead === b.cacheRead && a.cacheWrite === b.cacheWrite && a.reasoning === b.reasoning;
}
function extractUsageRecords(events, options = {}) {
  const fromSeq = normalizeTokenCount(options.fromSeq) ?? 0;
  const requestedLimit = normalizeTokenCount(options.limit);
  const limit = requestedLimit === void 0 || requestedLimit === 0 ? DEFAULT_LIMIT : Math.min(requestedLimit, MAX_LIMIT);
  let routeProvider = "";
  let routeModel = "";
  let scanned = 0;
  let maxSeq = fromSeq;
  let last;
  const all = [];
  for (const entry of events) {
    scanned += 1;
    const event = asRecord(entry);
    if (event === void 0) continue;
    const seq = normalizeTokenCount(event.seq);
    if (seq === void 0) continue;
    if (seq > maxSeq) maxSeq = seq;
    const type = typeof event.type === "string" ? event.type : "";
    if (type === "request/header") {
      const header = asRecord(asRecord(event.data)?.header);
      const config = asRecord(header?.config);
      const provider = nonEmptyString(config?.provider);
      const model = nonEmptyString(config?.model);
      if (provider !== void 0) routeProvider = provider;
      if (model !== void 0) routeModel = model;
      continue;
    }
    const data = asRecord(event.data);
    if (data === void 0) continue;
    if (type === "assistant/message") {
      const usage = normalizeUsage(data.usage);
      if (usage === void 0) continue;
      const at = eventTime(event);
      if (at === void 0) continue;
      const source = asRecord(asRecord(data.message)?.source);
      const provider = nonEmptyString(source?.provider) ?? (routeProvider === "" ? void 0 : routeProvider);
      const model = nonEmptyString(source?.model) ?? (routeModel === "" ? void 0 : routeModel);
      if (provider === void 0 || model === void 0) continue;
      const { turn, step } = readPosition(data);
      const key = callKey(seq, turn, step);
      if (last !== void 0 && last.key === key && last.provider === provider && last.model === model && sameUsage(last.usage, usage)) {
        continue;
      }
      all.push({ seq, at, provider, model, turn, step, kind: "call", usage });
      last = { key, provider, model, usage };
      continue;
    }
    if (type === "assistant/chunk") {
      const chunk = asRecord(data.chunk);
      if (chunk === void 0 || chunk.type !== "usage") continue;
      const usage = normalizeUsage(chunk.usage);
      if (usage === void 0) continue;
      const at = eventTime(event);
      if (at === void 0) continue;
      const provider = routeProvider === "" ? void 0 : routeProvider;
      const model = routeModel === "" ? void 0 : routeModel;
      if (provider === void 0 || model === void 0) continue;
      const { turn, step } = readPosition(data);
      const key = callKey(seq, turn, step);
      if (last !== void 0 && last.key === key && last.provider === provider && last.model === model && sameUsage(last.usage, usage)) {
        continue;
      }
      all.push({ seq, at, provider, model, turn, step, kind: "call", usage });
      last = { key, provider, model, usage };
      continue;
    }
    if (type === "compaction/summary") {
      const usage = normalizeUsage(data.usage);
      if (usage === void 0) continue;
      const at = eventTime(event);
      if (at === void 0) continue;
      const source = asRecord(asRecord(data.message)?.source);
      const provider = nonEmptyString(source?.provider) ?? nonEmptyString(data.provider);
      const model = nonEmptyString(source?.model) ?? nonEmptyString(data.model);
      if (provider === void 0 || model === void 0) continue;
      all.push({ seq, at, provider, model, turn: null, step: null, kind: "compaction", usage });
      last = { key: `compaction:${seq}`, provider, model, usage };
      continue;
    }
  }
  const visible = fromSeq === 0 ? all : all.filter((sample) => sample.seq > fromSeq);
  const records = visible.length > limit ? visible.slice(0, limit) : visible;
  const newest = records[records.length - 1];
  const nextSeq = newest !== void 0 && records.length < visible.length ? newest.seq : maxSeq;
  return { records, scanned, nextSeq };
}

// src/reply-codec.ts
var record2 = (value) => value !== null && typeof value === "object" && !Array.isArray(value) ? value : void 0;
var natural = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
var nonempty = (value) => typeof value === "string" && value !== "";
function publicContent(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const raw of value) {
    const block = record2(raw);
    if (block?.type === "text" && typeof block.text === "string") {
      if (block.text !== "") out.push({ type: "text", text: block.text });
      continue;
    }
    const ref = record2(block?.attachment);
    if (ref === void 0 || !nonempty(ref.attachmentId) || !natural(ref.bytes)) continue;
    if (block?.type === "file" && typeof ref.name === "string") {
      out.push({ type: "file", attachment: { attachmentId: ref.attachmentId, name: ref.name, bytes: ref.bytes } });
    } else if (block?.type === "image" && ["image/png", "image/jpeg", "image/webp", "image/gif"].includes(String(ref.mediaType)) && natural(ref.width) && ref.width > 0 && natural(ref.height) && ref.height > 0) {
      const original = record2(ref.originalDimensions);
      out.push({ type: "image", attachment: {
        attachmentId: ref.attachmentId,
        mediaType: ref.mediaType,
        bytes: ref.bytes,
        width: ref.width,
        height: ref.height,
        ...typeof ref.name === "string" ? { name: ref.name } : {},
        ...original !== void 0 && natural(original.width) && original.width > 0 && natural(original.height) && original.height > 0 ? { originalDimensions: { width: original.width, height: original.height } } : {}
      } });
    }
  }
  return out;
}
function contentText(content) {
  return content.filter((block) => block.type === "text").map((block) => block.text).join("");
}
function replyOf(event, sessionId) {
  if (event.type !== "assistant/message" || !natural(event.seq) || !natural(event.time)) return void 0;
  const data = record2(event.data);
  const message = record2(data?.message);
  const source = record2(message?.source);
  if (data?.interrupted === true || message?.role !== "assistant" || !nonempty(message.id) || source?.kind !== "model" || !nonempty(source.provider) || !nonempty(source.model) || !natural(data?.turn) || !natural(data?.step)) return void 0;
  const content = publicContent(message.content);
  if (content.length === 0) return void 0;
  const usage = record2(data.usage);
  const tokens = usage === void 0 ? void 0 : Object.fromEntries(Object.entries(usage).filter(([key, value]) => ["inputTokens", "outputTokens", "totalTokens", "cacheReadTokens", "cacheWriteTokens", "reasoningTokens"].includes(key) && natural(value)));
  return {
    version: 1,
    sessionId,
    seq: event.seq,
    time: event.time,
    turn: data.turn,
    step: data.step,
    messageId: message.id,
    source: { kind: "model", provider: source.provider, model: source.model },
    provider: source.provider,
    model: source.model,
    content,
    text: contentText(content),
    attachmentScope: "remote-session",
    ...tokens === void 0 || Object.keys(tokens).length === 0 ? {} : { usage: tokens }
  };
}
function summarizeReplies(events, firstSeq, sessionId) {
  let started = false;
  const replies = [];
  let reason = null;
  let error = null;
  let interruptCause = null;
  for (const event of events) {
    if (event.seq < firstSeq) continue;
    if (event.type === "turn/start") {
      started = true;
      continue;
    }
    if (!started) continue;
    const reply = replyOf(event, sessionId);
    if (reply !== void 0) replies.push(reply);
    if (event.type !== "turn/end") continue;
    const why = record2(record2(event.data)?.reason);
    reason = typeof why?.kind === "string" ? why.kind : null;
    interruptCause = why?.kind === "aborted" ? String(record2(why.reason)?.kind ?? "legacy") : null;
    const failure = record2(why?.error);
    if (failure !== void 0) error = `${String(failure.code ?? "")}: ${String(failure.message ?? "")}`.replace(/^: /, "");
  }
  return { text: replies.map((reply) => reply.text).filter(Boolean).join("\n\n"), replies, replyFormat: "committed-assistant-v1", reason, error, interruptCause };
}
function extractPublicEvents(events, fromSeq, limit, sessionId) {
  const out = [];
  let turn;
  let step;
  const bounded = Number.isFinite(limit) && limit > 0 ? Math.min(1e3, Math.floor(limit)) : 400;
  for (const event of events) {
    const data = record2(event.data);
    if (event.type === "turn/start") {
      turn = typeof data?.turn === "number" ? data.turn : void 0;
      step = void 0;
    }
    if (event.type === "step/start") step = typeof data?.step === "number" ? data.step : void 0;
    if (event.seq < fromSeq || event.type === "assistant/attempt") continue;
    const base = { seq: event.seq, type: event.type, time: event.time, ...turn === void 0 ? {} : { turn }, ...step === void 0 ? {} : { step } };
    if (event.type === "assistant/message") {
      const reply = replyOf(event, sessionId);
      if (reply === void 0) continue;
      Object.assign(base, reply);
    } else if (event.type === "user/message") {
      const content = publicContent(data?.content);
      const source = record2(data?.source);
      base.messageId = data?.id;
      base.content = content;
      base.text = contentText(content);
      base.attachmentScope = "remote-session";
      base.source = source === void 0 ? null : Object.fromEntries(Object.entries(source).filter(([key, field]) => key !== "replayState" && (typeof field === "string" || typeof field === "number" || typeof field === "boolean")));
    } else if (event.type === "tool/call") {
      base.name = typeof data?.name === "string" ? data.name : "";
      base.arguments = typeof data?.arguments === "string" ? data.arguments.slice(0, 4e3) : "";
    } else if (event.type === "tool/result") {
      const message = record2(data?.message);
      base.text = contentText(publicContent(message?.content)).slice(0, 4e3);
      base.isError = message?.isError === true;
    } else if (event.type === "turn/end") {
      base.reason = record2(data?.reason)?.kind ?? null;
    }
    out.push(base);
    if (out.length >= bounded) break;
  }
  return out;
}

// src/agent-delivery.ts
function isDefiniteSessionNotFound(error, sessionId) {
  if (!(error instanceof Error)) return false;
  const value = error;
  if (value.name === "SessionPersistenceNotFoundError") return value.sessionId === sessionId;
  return value.code === "session/not-found" && value.details?.sessionId === sessionId;
}
function inputMode(value) {
  if (value === void 0 || value === "auto") return "auto";
  if (value === "queue" || value === "steer") return value;
  throw new Error("agent.note: mode must be queue, steer or auto");
}
function deliverInput(agent, message, requested, busy) {
  const mode = requested === "auto" ? busy ? "steer" : "queue" : requested;
  if (mode === "steer") {
    if (typeof agent.steer !== "function") throw new Error("agent.note: this Agent has no steering capability");
    agent.steer(message);
  } else agent.followup(message);
  return { mode, processing: busy ? mode === "steer" ? "next-step" : "next-turn" : "starting" };
}

// src/message-traces.ts
import { createHash as createHash3 } from "node:crypto";
function traceKey(trace) {
  return createHash3("sha256").update(JSON.stringify([trace.principal, trace.sessionId, trace.messageId])).digest("hex");
}
async function admitTracked(store, trace, admit) {
  const key = traceKey(trace);
  const previous = store.get(key);
  if (previous !== void 0) throw new Error(`dsh-remote: message ${trace.messageId} already has an admission record (${previous.state}); not replaying`);
  await store.put(key, { ...trace, state: "admitting" });
  try {
    admit();
  } catch (error) {
    await store.put(key, { ...trace, state: "unknown" });
    throw error;
  }
  const accepted = { ...trace, state: "accepted" };
  try {
    await store.put(key, accepted);
  } catch (error) {
    throw new Error(`dsh-remote: input may have been admitted but its receipt could not be stored; do not resend (${String(error)})`);
  }
  return accepted;
}
function createMessageTraces(ctx) {
  let opening;
  let closed = false;
  let writes = Promise.resolve();
  const persist = (records, key, value) => {
    const writing = writes.then(async () => {
      const current = records.get(key);
      await records.put(key, current?.state === "committed" && value.state !== "committed" ? { ...value, seq: current.seq, time: current.time, state: "committed" } : value);
    });
    writes = writing.catch(() => {
    });
    return writing;
  };
  const table = async () => {
    if (closed) throw new Error("dsh-remote: message trace domain is closed");
    opening ??= (async () => {
      const facility = ctx.get("storageDomain");
      if (facility === void 0) throw new Error("dsh-remote: storageDomain is required before admitting remote input");
      const { z: z3 } = await import("zod");
      const id = z3.string().min(1);
      const schema = z3.object({
        version: z3.literal(1),
        traceId: id,
        principal: id,
        sessionId: id,
        remoteSessionId: id,
        messageId: id,
        seq: z3.number().int().nonnegative().nullable(),
        time: z3.number().nonnegative(),
        operation: z3.enum(["agent.prompt", "agent.note"]),
        requestedMode: z3.enum(["queue", "steer", "auto"]),
        mode: z3.enum(["queue", "steer"]),
        state: z3.enum(["admitting", "accepted", "committed", "unknown"])
      }).strict();
      return facility.open({ name: "dsh_remote_message_traces", version: 1, layout: "per-record", tables: { traces: { valueSchema: schema } } });
    })();
    const attempt = opening;
    try {
      return (await attempt).table("traces");
    } catch (error) {
      if (opening === attempt) opening = void 0;
      throw error;
    }
  };
  return {
    store: async () => {
      const records = await table();
      return { get: (key) => records.get(key), put: (key, value) => persist(records, key, value) };
    },
    anchor: async (principal, sessionId, messageId, seq, time) => {
      const records = await table();
      const key = traceKey({ principal, sessionId, messageId });
      const previous = records.get(key);
      if (previous === void 0) return false;
      await persist(records, key, { ...previous, seq, time, state: "committed" });
      return true;
    },
    close: async () => {
      closed = true;
      await writes;
      if (opening !== void 0) await (await opening).close();
    }
  };
}

// src/remote-io.ts
import { createHash as createHash4 } from "node:crypto";
var IO_TRANSPORT_ID = "dsh-remote";
var IO_CONTRACT_VERSION = 1;
function ioBindingId(principal, localId) {
  return `dsh-remote-${createHash4("sha256").update(JSON.stringify([principal, localId])).digest("hex").slice(0, 40)}`;
}
function remoteReplyOf(value) {
  const reply = value;
  if (reply === null || typeof reply !== "object" || reply.version !== 1 || typeof reply.sessionId !== "string" || reply.sessionId === "") return void 0;
  return replyOf({
    type: "assistant/message",
    seq: Number(reply.seq),
    time: Number(reply.time),
    data: {
      turn: reply.turn,
      step: reply.step,
      message: {
        id: reply.messageId,
        role: "assistant",
        source: reply.source,
        content: reply.content
      },
      ...reply.usage === void 0 ? {} : { usage: reply.usage }
    }
  }, reply.sessionId);
}
var errorCode = (error) => {
  const code = error?.code;
  return typeof code === "string" ? code : "";
};
var errorMessage = (error) => error instanceof Error ? error.message : String(error);
var FALLBACK_RECEIVE_CODES = /* @__PURE__ */ new Set(["DISABLED", "BINDING_NOT_FOUND", "INVALID_CONTENT", "CONTENT_TOO_LARGE", "INVALID_INPUT"]);
function createRemoteIoBridge(ctx, hooks) {
  let closed = false;
  let service;
  let dropTransport;
  let offVolatile;
  const bindings = /* @__PURE__ */ new Map();
  const byBinding = /* @__PURE__ */ new Map();
  const initialized = /* @__PURE__ */ new Set();
  const resolve3 = () => {
    if (closed || !hooks.enabled()) return void 0;
    let candidate;
    try {
      candidate = ctx.get("superAgentIo");
    } catch {
      return void 0;
    }
    if (candidate == null || candidate.contractVersion !== IO_CONTRACT_VERSION || typeof candidate.registerTransport !== "function" || typeof candidate.putBinding !== "function" || typeof candidate.receive !== "function") return void 0;
    return candidate;
  };
  const sync = () => {
    if (closed || !hooks.enabled()) {
      try {
        dropTransport?.();
      } catch {
      }
      dropTransport = void 0;
      service = void 0;
      return void 0;
    }
    const current = resolve3();
    if (current === void 0) {
      try {
        dropTransport?.();
      } catch {
      }
      dropTransport = void 0;
      service = void 0;
      return void 0;
    }
    if (service === current && dropTransport !== void 0) return current;
    try {
      dropTransport?.();
    } catch {
    }
    dropTransport = void 0;
    service = current;
    initialized.clear();
    try {
      dropTransport = current.registerTransport({
        id: IO_TRANSPORT_ID,
        deliver: async (delivery, { signal }) => {
          if (closed || !hooks.enabled()) return { state: "unknown", reason: "DSH_REMOTE_DISABLED" };
          if (signal.aborted) return { state: "unknown", reason: "DSH_REMOTE_ABORTED" };
          const binding = byBinding.get(delivery.bindingId);
          if (binding === void 0) return { state: "unknown", reason: "DSH_REMOTE_UNKNOWN_BINDING" };
          const reply = remoteReplyOf(delivery.reply);
          if (reply === void 0) return { state: "failed", reason: "DSH_REMOTE_INVALID_REPLY" };
          let result;
          try {
            result = await hooks.deliver(binding, delivery, reply);
          } catch (error) {
            hooks.log(`dsh-remote-server: super-agent-io reply delivery failed (${errorMessage(error)})`, "warn");
            result = "unknown";
          }
          if (result === "delivered") {
            return { state: "delivered", externalMessageId: `dsh-remote:${delivery.deliveryId}` };
          }
          return {
            state: result,
            reason: result === "failed" ? "DSH_REMOTE_NO_CONTROLLER" : "DSH_REMOTE_SEND_OUTCOME_UNKNOWN"
          };
        }
      });
      hooks.log("dsh-remote-server: super-agent-io transport registered");
    } catch (error) {
      dropTransport = void 0;
      hooks.log(`dsh-remote-server: super-agent-io transport unavailable (${errorMessage(error)})`, "warn");
    }
    return current;
  };
  const ensureBinding = async (principal, localId, wireId, label) => {
    const io = sync();
    if (io === void 0) return void 0;
    const bindingId = ioBindingId(principal, localId);
    let binding = bindings.get(localId);
    if (binding === void 0 || binding.bindingId !== bindingId) {
      binding = { bindingId, principal, localId, wireId };
      bindings.set(localId, binding);
      byBinding.set(bindingId, binding);
    }
    if (initialized.has(bindingId)) return binding;
    try {
      await io.putBinding({
        id: bindingId,
        transport: IO_TRANSPORT_ID,
        // Stable, principal-scoped and non-secret: the adapter's own identity.
        endpoint: `dsh-remote:${principal}`,
        sessionId: localId,
        label: label.slice(0, 160),
        enabled: true,
        // Output is still gated by IO's global send switch and this binding's
        // sendEnabled flag; asking for it does not bypass either gate.
        sendEnabled: true,
        preload: false,
        mode: "auto",
        routing: "exclusive-turn"
      });
      if (closed) {
        if (byBinding.get(bindingId) === binding) byBinding.delete(bindingId);
        if (bindings.get(localId) === binding) bindings.delete(localId);
        return void 0;
      }
      initialized.add(bindingId);
      return binding;
    } catch (error) {
      if (byBinding.get(bindingId) === binding) byBinding.delete(bindingId);
      if (bindings.get(localId) === binding) bindings.delete(localId);
      hooks.log(`dsh-remote-server: super-agent-io binding unavailable (${errorMessage(error)})`, "warn");
      return void 0;
    }
  };
  const receive = async (binding, request) => {
    const io = sync();
    if (io === void 0) return { kind: "unavailable", reason: "super-agent-io service is unavailable" };
    if (request.text.trim() === "") return { kind: "unavailable", reason: "empty input cannot be admitted through IO" };
    const input = {
      bindingId: binding.bindingId,
      externalMessageId: request.externalMessageId,
      content: [{ type: "text", text: request.text }],
      mode: request.mode,
      senderId: binding.principal
    };
    try {
      const receipt = await io.receive(input);
      if (receipt.state === "accepted") return { kind: "accepted", receipt };
      if (receipt.state === "failed") {
        return { kind: "unavailable", reason: receipt.reason ?? "IO admission failed before send" };
      }
      return { kind: "unknown", reason: receipt.reason ?? `IO admission ended as ${receipt.state}` };
    } catch (error) {
      const code = errorCode(error);
      if (code === "BINDING_NOT_FOUND") {
        initialized.delete(binding.bindingId);
        const refreshed = await ensureBinding(binding.principal, binding.localId, binding.wireId, `dsh-remote ${binding.wireId}`);
        if (refreshed !== void 0) {
          try {
            const receipt = await io.receive(input);
            if (receipt.state === "accepted") return { kind: "accepted", receipt };
            if (receipt.state === "failed") return { kind: "unavailable", reason: receipt.reason ?? "IO admission failed before send" };
            return { kind: "unknown", reason: receipt.reason ?? `IO admission ended as ${receipt.state}` };
          } catch (retryError) {
            return FALLBACK_RECEIVE_CODES.has(errorCode(retryError)) ? { kind: "unavailable", reason: errorMessage(retryError) } : { kind: "unknown", reason: errorMessage(retryError) };
          }
        }
      }
      if (FALLBACK_RECEIVE_CODES.has(code)) return { kind: "unavailable", reason: errorMessage(error) };
      return { kind: "unknown", reason: errorMessage(error) };
    }
  };
  try {
    offVolatile = ctx.on("loader/volatile-update", () => {
      sync();
    });
  } catch {
  }
  sync();
  return {
    sync,
    ensureBinding,
    receive,
    available: () => sync() !== void 0,
    dispose: () => {
      closed = true;
      try {
        offVolatile?.();
      } catch {
      }
      offVolatile = void 0;
      try {
        dropTransport?.();
      } catch {
      }
      dropTransport = void 0;
      service = void 0;
      bindings.clear();
      byBinding.clear();
      initialized.clear();
    }
  };
}

// src/server.ts
var name = "dsh-remote-server";
var DSH_REMOTE_SERVER_SETTINGS_NAMESPACE = "dsh-remote-server";
var SERVER_VERSION = "0.5.2";
var BUILD = "r27";
var NOT_JOURNALED_OPS = /* @__PURE__ */ new Set(["journal.read", "fs.put.chunk", "fs.get", "caps.list", "references.list", "relay.write", "relay.status"]);
var DENIED_TOOL_PREFIXES = ["remote_", "remote__"];
var DEFAULT_DENIED_TOOLS = ["ask_user_question", "exit_plan_mode", "present"];
var CONTROLLED_GUIDANCE = [
  "## \u4F60\u6B63\u88AB\u8FDC\u7AEF\u9A71\u52A8\uFF08dsh-remote \u53D7\u63A7\u7AEF\uFF09",
  "\u672C\u4F1A\u8BDD\u7531\u53E6\u4E00\u53F0\u673A\u5668\u4E0A\u7684 DSH agent\uFF08\u63A7\u5236\u65B9\uFF09\u4EE5\u300Csubagent / task\u300D\u7684\u65B9\u5F0F\u9A71\u52A8\uFF1A\u5B83\u6D3E\u6D3B\u3001\u4F60\u4EA4\u4ED8\uFF0C",
  +"\u628A\u5B83\u5F53\u4F5C\u4F60\u7684\u7528\u6237\uFF0C\u4F46\u4E0D\u8981\u5047\u8BBE\u5B83\u80FD\u770B\u5230\u672C\u673A\u5C4F\u5E55\u6216\u672C\u673A\u4E0A\u4E0B\u6587\u3002",
  "\u4EA4\u4ED8\u8981\u81EA\u6210\u4E00\u4F53\uFF1A\u7ED3\u8BBA\u3001\u5173\u952E\u547D\u4EE4\u8F93\u51FA\u3001\u6D89\u53CA\u7684\u6587\u4EF6\u8DEF\u5F84\u90FD\u5199\u8FDB\u56DE\u590D\uFF1B",
  +"\u5BF9\u65B9\u62FF\u5230\u7684\u5C31\u662F\u4F60\u8FD9\u4E00\u8F6E\u7684\u56DE\u590D\u548C\u4F60\u7559\u5728\u4F1A\u8BDD\u91CC\u7684\u4E8B\u4EF6\u3002",
  "\u53EA\u505A\u88AB\u8981\u6C42\u7684\u4E8B\uFF0C\u4E0D\u8981\u64C5\u81EA\u6269\u5927\u8303\u56F4\uFF1B\u9700\u8981\u4EBA\u62CD\u677F\u65F6\u7528 ask_user_question \u63D0\u95EE",
  +"\uFF08\u5B83\u4F1A\u8F6C\u4EA4\u7ED9\u63A7\u5236\u65B9\uFF0C\u7531\u63A7\u5236\u65B9\u6216\u5176\u7528\u6237\u56DE\u7B54\uFF09\uFF0C\u4E0D\u8981\u81EA\u5DF1\u66FF\u7528\u6237\u51B3\u5B9A\u3002",
  "\u672C\u673A\u53EF\u80FD\u6709\u771F\u4EBA\u6B63\u5728\u770B\u8FD9\u4E2A\u4F1A\u8BDD\uFF0C\u4E5F\u53EF\u80FD\u76F4\u63A5\u63D2\u8BDD\u6216\u6309\u505C\u3002",
  +"**\u4EFB\u4F55\u4E00\u4FA7\u7528\u6237\u7684\u6253\u65AD\u4E0E\u65B0\u6307\u793A\u4F18\u5148\u7EA7\u6700\u9AD8**\uFF1A\u88AB\u4E2D\u65AD\u5C31\u7ACB\u523B\u505C\u624B\u3001\u4E0D\u8981\u7EE7\u7EED\u3001\u4E0D\u8981\u91CD\u8BD5\uFF1B",
  +"\u51FA\u73B0\u65B0\u6307\u793A\u65F6\u4EE5\u5B83\u4E3A\u51C6\uFF0C\u91CD\u65B0\u89C4\u5212\u3002"
].join("\n");
var inject = [
  "agentDefaultModel",
  "agentPresets",
  "agents",
  "sessions",
  // Needed so a remotely created session is owned by a workspace; without
  // that ownership the GUI has nothing to list it under.
  "workspaceRegistry"
];
var Config = z2.object({
  host: z2.string().default("127.0.0.1").volatile(),
  port: z2.number().default(11325).volatile(),
  // `role('secret')` keeps the value out of settings-GUI wire payloads.
  privateKey: z2.string().role("secret").default("").volatile(),
  privateKeyFile: z2.string().default(dshHomePath("dsh-remote", "server.key")).volatile(),
  autoGenerateKey: z2.boolean().default(true).volatile(),
  peerPublicKey: z2.string().default("").volatile(),
  peerPublicKeyFile: z2.string().default(dshHomePath("dsh-remote", "client.pub")).volatile(),
  authorizedPeers: z2.dict(z2.object({
    peerPublicKey: z2.string().default(""),
    peerPublicKeyFile: z2.string().default(""),
    maxPermission: z2.number().default(1),
    workspaceRoot: z2.string().default(""),
    readRoots: z2.array(z2.string()).default([]),
    allowedOps: z2.array(z2.string()).default([]),
    disabled: z2.boolean().default(false),
    validUntil: z2.string().default(""),
    relayTargets: z2.array(z2.string()).default([])
  })).default({}).volatile(),
  relayEnabled: z2.boolean().default(false).volatile(),
  readRoots: z2.array(z2.string()).default([]).volatile(),
  allowLegacyHandshake: z2.boolean().default(false).volatile(),
  maxConnections: z2.number().default(64).volatile(),
  maxPendingHandshakes: z2.number().default(8).volatile(),
  maxConnectionsPerAddress: z2.number().default(16).volatile(),
  maxHandshakesPerMinute: z2.number().default(120).volatile(),
  maxTrackedAddresses: z2.number().default(1024).volatile(),
  handshakeTimeoutMs: z2.number().default(15e3).volatile(),
  maxInFlightPerPrincipal: z2.number().default(16).volatile(),
  maxSessionMs: z2.number().default(36e5).volatile(),
  workspace: z2.string().default("").volatile(),
  defaultPreset: z2.string().default("").volatile(),
  maxHandshakeFailures: z2.number().default(8).volatile(),
  lockoutSeconds: z2.number().default(900).volatile(),
  maxExecTimeoutMs: z2.number().default(6e5).volatile(),
  // 3 preserves today's behaviour; lower it to actually fence this machine.
  maxPermission: z2.number().default(3).volatile(),
  auditFile: z2.string().default(dshHomePath("dsh-remote", "server-audit.log")).volatile(),
  audit: z2.boolean().default(true).volatile(),
  promptGuidance: z2.boolean().default(true).volatile(),
  superAgentIo: z2.boolean().default(false).volatile(),
  journal: z2.boolean().default(true).volatile(),
  journalFile: z2.string().default(dshHomePath("dsh-remote", "journal.jsonl")).volatile(),
  heartbeatFile: z2.string().default(dshHomePath("dsh-remote", "server-heartbeat.json")).volatile(),
  /**
   * Largest file the chunked-transfer path accepts, in bytes (default 1 GiB).
   *
   * `fs.put.begin` refuses a declared size above it before any staging file is
   * created, so a typo in a controller cannot fill this machine's disk.
   */
  transferMaxBytes: z2.number().default(1073741824).volatile(),
  /** Largest block `fs.get` serves, and the cap on a caller's `length` (8 MiB). */
  transferMaxChunkBytes: z2.number().default(8 * 1024 * 1024).volatile(),
  /** How many uploads may be in flight at once (default 8). */
  transferMaxActive: z2.number().default(8).volatile(),
  /** Idle lifetime of an unfinished upload before it is discarded (10 min). */
  transferUploadTtlMs: z2.number().default(6e5).volatile(),
  /** Largest original file whose text is returned as `before` by a commit (1 MiB). */
  transferBeforeMaxBytes: z2.number().default(1048576).volatile(),
  capabilities: z2.boolean().default(true).volatile(),
  capabilityPreset: z2.string().default("").volatile(),
  deniedTools: z2.array(z2.string()).default([...DEFAULT_DENIED_TOOLS]).volatile(),
  maxToolCallTimeoutMs: z2.number().default(6e5).volatile()
});
function plainConfig(config) {
  return Object.fromEntries(
    Object.entries(config).map(([key, value]) => [key, isVolatile(value) ? value.get() : value])
  );
}
function messageText(message) {
  if (message === void 0) return "";
  const content = message.content;
  const blocks = Array.isArray(content) ? content : content === void 0 ? [] : [content];
  let out = "";
  for (const block of blocks) {
    const b = block;
    if (b?.type === "text" && typeof b.text === "string") out += b.text;
  }
  return out;
}
var KILL_SWEEP_TIMEOUT_MS = 2e4;
var BUSY_PROBE_MS = 25;
async function agentBusy(agent) {
  if (typeof agent.whenIdle !== "function") return true;
  let idle = false;
  void Promise.resolve(agent.whenIdle()).then(() => {
    idle = true;
  }, () => {
    idle = true;
  });
  await new Promise((resolve3) => {
    setTimeout(resolve3, BUSY_PROBE_MS);
  });
  return !idle;
}
function killTree(child) {
  const pid = child.pid;
  if (process.platform !== "win32" || typeof pid !== "number") {
    try {
      child.kill();
    } catch {
    }
    return;
  }
  const sweep = () => {
    try {
      execFile("taskkill", ["/PID", String(pid), "/T", "/F"], () => {
      });
    } catch {
    }
  };
  const script = [
    "$all = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId,ParentProcessId",
    `$queue = New-Object System.Collections.Queue; $queue.Enqueue(${pid})`,
    "$seen = New-Object 'System.Collections.Generic.HashSet[int]'",
    "$kill = New-Object System.Collections.ArrayList",
    "while ($queue.Count -gt 0) {",
    "  $cur = $queue.Dequeue()",
    "  foreach ($p in $all) { if ($p.ParentProcessId -eq $cur -and $seen.Add([int]$p.ProcessId)) { $queue.Enqueue([int]$p.ProcessId); [void]$kill.Add([int]$p.ProcessId) } }",
    "}",
    `[void]$kill.Add(${pid})`,
    "foreach ($id in $kill) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }",
    'Write-Output ("stopped " + $kill.Count + " process(es)")'
  ].join("\n");
  try {
    execFile(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      { windowsHide: true, timeout: KILL_SWEEP_TIMEOUT_MS },
      () => {
        sweep();
      }
    );
  } catch {
    sweep();
  }
}
function apply(ctx, config) {
  const read = () => plainConfig(config);
  const guard = new NetworkGuard(read);
  const sockets = /* @__PURE__ */ new Set();
  const pendingSockets = /* @__PURE__ */ new Set();
  const principalInFlight = /* @__PURE__ */ new Map();
  let disposed = false;
  const requests = new AsyncLocalStorage();
  const connection = () => {
    const current = requests.getStore();
    if (current === void 0) throw new Error("dsh-remote-server: missing authenticated request context");
    return current;
  };
  const principalResources = /* @__PURE__ */ new Map();
  const resources = () => {
    const principal = connection().principal;
    let owned = principalResources.get(principal);
    if (owned === void 0) {
      owned = {
        execs: new ExecRegistry(),
        activeToolCalls: /* @__PURE__ */ new Map(),
        transfers: createTransferServer({ read, log: ctx.logger, home: dshHomePath() }),
        uploadPaths: /* @__PURE__ */ new Map(),
        generation: new AbortController()
      };
      principalResources.set(principal, owned);
    }
    return owned;
  };
  let identity = resolvePrivateKey(read(), "server.key");
  ctx.logger.info(`dsh-remote-server: identity ${describeIdentity(identity)}`);
  ctx.logger.info(
    `dsh-remote-server: public key (give this to the client)
${publicToPem(identity.publicKey)}`
  );
  const states = /* @__PURE__ */ new Map();
  const ensuring = /* @__PURE__ */ new Map();
  const messageTraces = createMessageTraces(ctx);
  ctx.effect(() => () => messageTraces.close());
  const fullKeyId = (key) => createHash5("sha256").update(rawPublic(key)).digest("hex");
  const pinnedControllers = () => {
    const declared = read().authorizedPeers ?? {};
    validatePeerNames(Object.keys(declared));
    const seen = /* @__PURE__ */ new Set();
    return Object.entries(declared).map(([name2, profile]) => {
      if (text(profile.peerPublicKey) === void 0 && text(profile.peerPublicKeyFile) === void 0) {
        throw new Error(`authorizedPeers.${name2}: a pinned public key or file is required`);
      }
      const key = resolvePeerPublicKey(profile, "client.pub");
      const principal = fullKeyId(key);
      if (seen.has(principal)) throw new Error("authorizedPeers: each public key must identify exactly one peer");
      seen.add(principal);
      return { name: name2, key, principal };
    });
  };
  pinnedControllers();
  const policyFor = (controller) => {
    const current = read();
    if (disposed || controller.serverIdentity !== fullKeyId(identity.publicKey)) {
      throw new FsError2("authenticated connection expired or server identity changed", "FS_PERMISSION_DENIED");
    }
    const pinned = pinnedControllers();
    let ceiling = normalizePermission(current.maxPermission);
    let workspaceRoot = text(current.workspace) ?? "";
    let allowedOps = [];
    let readRoots = current.readRoots ?? [];
    let expiresAt;
    if (controller.multi) {
      const match = pinned.find((peer) => peer.principal === controller.principal);
      if (match === void 0 || match.name !== controller.name) throw new FsError2("controller key or named identity is no longer authorized", "FS_PERMISSION_DENIED");
      const profile = current.authorizedPeers[match.name];
      if (profile.disabled === true) throw new FsError2("controller key is disabled", "FS_PERMISSION_DENIED");
      expiresAt = expirationTime(profile.validUntil);
      if (expiresAt !== void 0 && expiresAt <= Date.now()) throw new FsError2("controller key has expired", "FS_PERMISSION_DENIED");
      ceiling = Math.min(ceiling, normalizePermission(profile.maxPermission));
      workspaceRoot = text(profile.workspaceRoot) ?? "";
      allowedOps = allowedOperations(profile.allowedOps);
      readRoots = profile.readRoots ?? [];
    } else if (pinned.length !== 0 || fullKeyId(resolvePeerPublicKey(current, "client.pub")) !== controller.principal) {
      throw new FsError2("legacy controller key is no longer authorized", "FS_PERMISSION_DENIED");
    }
    if (!Array.isArray(readRoots) || readRoots.length > 32 || readRoots.some((root) => typeof root !== "string" || root.length > 4096 || /[\u0000-\u001f\u007f]/.test(root) || !isAbsolute2(root))) {
      throw new FsError2("readRoots must contain at most 32 absolute paths of at most 4096 characters", "FS_PERMISSION_DENIED");
    }
    return {
      ceiling,
      workspaceRoot,
      allowedOps,
      readRoots,
      ...expiresAt === void 0 ? {} : { expiresAt },
      signature: JSON.stringify([
        ceiling,
        workspaceRoot,
        allowedOps,
        readRoots,
        expiresAt ?? null,
        current.capabilities,
        current.deniedTools,
        current.relayEnabled,
        controller.multi ? current.authorizedPeers[controller.name]?.relayTargets : []
      ])
    };
  };
  const assertControllerOperation = (controller, op) => {
    const policy = policyFor(controller);
    assertPeerOperation(policy.ceiling, op, { peer: controller.name });
    if (policy.allowedOps.length !== 0 && !policy.allowedOps.includes(op)) {
      throw new FsError2(`operation ${JSON.stringify(op)} is not in this controller's allowedOps`, "FS_PERMISSION_DENIED");
    }
    return policy;
  };
  const relayHub = new RelayHub({
    authorize: (owner, op) => {
      const controller = owner;
      if (controller.signal.aborted) throw new FsError2("mesh connection closed", "FS_PERMISSION_DENIED");
      assertControllerOperation(controller, op);
      if (read().relayEnabled !== true || !controller.multi) throw new FsError2("mesh forwarding requires relayEnabled and a named pinned identity", "FS_PERMISSION_DENIED");
      const profile = read().authorizedPeers[controller.name];
      if (profile === void 0) throw new FsError2("mesh identity is no longer authorized", "FS_PERMISSION_DENIED");
      return { targets: profile.relayTargets ?? [] };
    }
  });
  const scopedSessionId = (wireId) => {
    const controller = connection();
    if (!controller.multi) return wireId;
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(wireId)) {
      throw new FsError2("invalid remote session id", "FS_PERMISSION_DENIED");
    }
    return `remote-${controller.principal}-${wireId}`;
  };
  const wireSessionId = (id, controller = connection()) => {
    if (!controller.multi) {
      const known = states.get(id);
      return known === void 0 || known.principal === controller.principal ? id : void 0;
    }
    const prefix = `remote-${controller.principal}-`;
    return id.startsWith(prefix) ? id.slice(prefix.length) : void 0;
  };
  const ownState = (wireId) => {
    const state = states.get(scopedSessionId(wireId));
    return state?.principal === connection().principal ? state : void 0;
  };
  const fencedPath = async (path, root) => {
    const denied = () => {
      throw new FsError2("write is outside the declared workspace root", "FS_PERMISSION_DENIED");
    };
    if (root === "" || !isAbsolute2(root) || !isAbsolute2(path) || /[\u0000-\u001f]/.test(path)) return denied();
    if (root.length > 4096 || path.length > 4096 || /[\u0000-\u001f\u007f]/.test(root) || path.replace(/\\/g, "/").split("/").some((part) => part === "..")) return denied();
    if (process.platform === "win32" && (/^[\\/]{2}/.test(path) || path.slice(2).includes(":") || path.replace(/\\/g, "/").split("/").slice(1).some((part) => /[. ]$/.test(part) || /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(part)))) return denied();
    const under = (child, parent) => {
      const diff = relative(parent, child);
      return diff === "" || !isAbsolute2(diff) && diff !== ".." && !diff.startsWith(`..${sep}`);
    };
    const absoluteRoot = resolve2(root);
    const target = resolve2(path);
    if (!under(target, absoluteRoot)) return denied();
    const canonicalRoot = await realpath(absoluteRoot);
    let ancestor = target;
    for (; ; ) {
      try {
        const canonical = await realpath(ancestor);
        if (!under(canonical, canonicalRoot)) return denied();
        return target;
      } catch (error) {
        const code = error.code;
        if (code !== "ENOENT") throw error;
        const parent = dirname4(ancestor);
        if (parent === ancestor) return denied();
        ancestor = parent;
      }
    }
  };
  const controllers = /* @__PURE__ */ new Map();
  const principalPolicies = /* @__PURE__ */ new Map();
  const cancelPrincipal = (principal, reason) => {
    relayHub.revoke(principal);
    const owned = principalResources.get(principal);
    if (owned !== void 0) {
      owned.generation.abort(reason);
      owned.execs.cancelAll();
      for (const call of owned.activeToolCalls.values()) call.abort(reason);
      owned.transfers.dispose();
      owned.uploadPaths.clear();
      principalResources.delete(principal);
    }
    for (const [localId, state] of states) {
      if (state.principal !== principal) continue;
      stopRequested.set(localId, Date.now());
      try {
        state.handle?.agent?.cancel({ kind: "hook", reason: reason.message });
      } catch {
      }
    }
    for (const controller of controllers.values()) {
      if (controller.principal === principal) controller.session.close();
    }
  };
  const enforcePolicies = () => {
    const cancelled = /* @__PURE__ */ new Set();
    for (const controller of principalPolicies.values()) {
      if (cancelled.has(controller.principal)) continue;
      try {
        const next = policyFor(controller);
        if (next.signature !== controller.policy.signature) throw new Error("controller policy changed; reconnect required");
      } catch (error) {
        cancelled.add(controller.principal);
        principalPolicies.delete(controller.principal);
        cancelPrincipal(controller.principal, error instanceof Error ? error : new Error(String(error)));
      }
    }
  };
  const relayed = /* @__PURE__ */ new Map();
  const injected = /* @__PURE__ */ new Map();
  const REMEMBERED_INJECTIONS = 64;
  const rememberInjection = (localId, messageId) => {
    let known = injected.get(localId);
    if (known === void 0) {
      known = /* @__PURE__ */ new Set();
      injected.set(localId, known);
    }
    known.add(messageId);
    while (known.size > REMEMBERED_INJECTIONS) {
      const oldest = known.values().next();
      if (oldest.done === true) break;
      known.delete(oldest.value);
    }
  };
  const pendingIoInputs = /* @__PURE__ */ new Set();
  const rememberIoInput = (externalMessageId) => {
    pendingIoInputs.add(externalMessageId);
    while (pendingIoInputs.size > REMEMBERED_INJECTIONS) {
      const oldest = pendingIoInputs.values().next();
      if (oldest.done === true) break;
      pendingIoInputs.delete(oldest.value);
    }
  };
  const selfInterrupted = /* @__PURE__ */ new Map();
  const SELF_INTERRUPT_TTL_MS = 6e4;
  const stopRequested = /* @__PURE__ */ new Map();
  const STOP_LATCH_TTL_MS = 3e4;
  const consumeStop = (sessionId) => {
    const askedAt = stopRequested.get(sessionId);
    if (askedAt === void 0) return false;
    stopRequested.delete(sessionId);
    return Date.now() - askedAt < STOP_LATCH_TTL_MS;
  };
  const pushToControllers = (frame) => {
    const localId = String(frame.sessionId ?? "");
    const state = states.get(localId);
    if (state === void 0) return;
    for (const controller of controllers.values()) {
      if (controller.principal !== state.principal) continue;
      try {
        policyFor(controller);
      } catch {
        continue;
      }
      void controller.session.send({ ...frame, sessionId: state.wireId }).catch((error) => {
        ctx.logger.debug(`dsh-remote-server: could not push ${String(frame.kind ?? "?")}: ${String(error)}`);
      });
    }
  };
  const deliverIoReply = async (binding, delivery, reply) => {
    const wireReply = { ...reply, sessionId: binding.wireId };
    let sent = 0;
    let uncertain = false;
    for (const controller of controllers.values()) {
      if (controller.principal !== binding.principal) continue;
      try {
        policyFor(controller);
      } catch {
        continue;
      }
      try {
        await controller.session.send({
          kind: "assistant.reply",
          sessionId: binding.wireId,
          deliveryId: delivery.deliveryId,
          reply: wireReply,
          ...delivery.traceIds === void 0 || delivery.traceIds.length === 0 ? {} : { traceIds: delivery.traceIds }
        });
        sent += 1;
      } catch (error) {
        uncertain = true;
        ctx.logger.debug(`dsh-remote-server: could not push an IO reply: ${String(error)}`);
      }
    }
    if (sent > 0) return "delivered";
    return uncertain ? "unknown" : "failed";
  };
  const ioBridge = createRemoteIoBridge(ctx, {
    enabled: () => read().superAgentIo === true,
    log: (message, level) => {
      try {
        if (level === "warn") ctx.logger.warn(message);
        else if (level === "debug") ctx.logger.debug(message);
        else ctx.logger.info(message);
      } catch {
      }
    },
    deliver: (binding, delivery, reply) => deliverIoReply(binding, delivery, reply)
  });
  try {
    ctx.effect(() => () => ioBridge.dispose(), "dsh-remote-server: super-agent-io bridge");
  } catch (error) {
    ctx.logger.warn(`dsh-remote-server: could not register super-agent-io teardown (${String(error)})`);
  }
  const admitViaIo = async (request) => {
    if (read().superAgentIo !== true) return { kind: "unavailable", reason: "super-agent-io integration is disabled" };
    if (request.text.trim() === "") return { kind: "unavailable", reason: "empty input" };
    rememberIoInput(request.externalMessageId);
    const binding = await ioBridge.ensureBinding(request.principal, request.localId, request.wireId, `dsh-remote ${request.wireId}`);
    if (binding === void 0) {
      pendingIoInputs.delete(request.externalMessageId);
      return { kind: "unavailable", reason: "super-agent-io binding is unavailable" };
    }
    const outcome = await ioBridge.receive(binding, {
      text: request.text,
      mode: request.mode,
      externalMessageId: request.externalMessageId
    });
    if (outcome.kind === "unavailable") {
      pendingIoInputs.delete(request.externalMessageId);
      if (read().superAgentIo === true) {
        try {
          ctx.logger.debug(`dsh-remote-server: super-agent-io admission unavailable; using the ordinary path (${outcome.reason})`);
        } catch {
        }
      }
    }
    return outcome;
  };
  let capsPushTimer;
  const pushCapsChanged = () => {
    if (read().capabilities === false) return;
    if (capsPushTimer !== void 0) clearTimeout(capsPushTimer);
    capsPushTimer = setTimeout(() => {
      capsPushTimer = void 0;
      const frame = { kind: "caps.changed", build: BUILD };
      for (const controller of controllers.values()) {
        try {
          policyFor(controller);
        } catch {
          continue;
        }
        void controller.session.send(frame).catch((error) => {
          ctx.logger.debug(`dsh-remote-server: could not push caps.changed: ${String(error)}`);
        });
      }
    }, 800);
    capsPushTimer.unref?.();
  };
  try {
    ctx.on("tools/change", pushCapsChanged);
  } catch (error) {
    ctx.logger.warn(`dsh-remote-server: could not watch tools/change (${String(error)})`);
  }
  ctx.on("session/event", (session, event) => {
    const sessionId = String(session.id ?? "");
    if (sessionId === "" || !states.has(sessionId)) return;
    try {
      const shaped = summarizeEvent(event.type, event.data);
      if (shaped !== void 0) {
        const state = states.get(sessionId);
        record3({
          kind: shaped.kind,
          summary: shaped.summary,
          sessionId: state.wireId,
          detail: { ...shaped.detail, principal: state.principal }
        });
      }
      if (event.type === "turn/end") {
        const why = event.data.reason;
        if (why?.kind !== "aborted") return;
        const cause = typeof why.reason?.kind === "string" ? why.reason.kind : "legacy";
        const askedAt = selfInterrupted.get(sessionId);
        if (askedAt !== void 0 && Date.now() - askedAt < SELF_INTERRUPT_TTL_MS) {
          selfInterrupted.delete(sessionId);
          stopRequested.delete(sessionId);
          pushToControllers({ kind: "interrupt", sessionId, cause, origin: "controller" });
          return;
        }
        selfInterrupted.delete(sessionId);
        pushToControllers({ kind: "interrupt", sessionId, cause, origin: "remote-user", at: Date.now() });
        return;
      }
      if (event.type !== "user/message") return;
      const message = event.data;
      const id = String(message.id ?? "");
      if (message.source?.kind === "dsh-remote") {
        const state = states.get(sessionId);
        void messageTraces.anchor(state.principal, sessionId, id, event.seq, event.time).catch((error) => {
          ctx.logger.warn(`dsh-remote-server: input trace could not be anchored: ${String(error)}`);
        });
        return;
      }
      if (message.source?.kind === "super-agent-io") {
        const externalId = typeof message.source.externalMessageId === "string" ? message.source.externalMessageId : "";
        if (message.source.transport === "dsh-remote" || externalId !== "" && pendingIoInputs.has(externalId)) {
          if (id !== "") rememberInjection(sessionId, id);
          return;
        }
      }
      if (id !== "" && injected.get(sessionId)?.has(id) === true) return;
      const body = messageText(message);
      if (body === "") return;
      pushToControllers({
        kind: "note",
        sessionId,
        human: message.source?.kind === "user" && typeof message.source.rpcId === "string",
        text: body.slice(0, 2e3),
        at: Date.now()
      });
    } catch (error) {
      ctx.logger.debug(`dsh-remote-server: session/event handling failed: ${String(error)}`);
    }
  }, { global: true });
  const QUESTION_RELAY_TIMEOUT_MS = 30 * 6e4;
  const sessionIdOfAgent = (agent) => {
    for (const [sessionId, state] of states) {
      if (state.handle?.agent === agent) return sessionId;
    }
    return void 0;
  };
  ctx.on("user-questions/request", async (request, next) => {
    const agent = request.agent;
    const sessionId = agent === void 0 ? void 0 : sessionIdOfAgent(agent);
    if (sessionId === void 0) return next();
    const state = states.get(sessionId);
    const controller = [...controllers.values()].reverse().find((candidate) => {
      if (candidate.principal !== state.principal) return false;
      try {
        return policyFor(candidate).ceiling >= 3;
      } catch {
        return false;
      }
    })?.session;
    if (controller === void 0) return next();
    const qid = randomUUID3();
    const answer = await new Promise((resolve3, reject) => {
      const finish = (settle) => {
        clearTimeout(timer);
        request.signal?.removeEventListener("abort", onAbort);
        settle();
      };
      const onAbort = () => {
        relayed.delete(qid);
        finish(() => {
          reject(new Error("dsh-remote-server: the relayed question was aborted"));
        });
      };
      const timer = setTimeout(() => {
        relayed.delete(qid);
        finish(() => {
          reject(new Error("dsh-remote-server: the controller did not answer the relayed question"));
        });
      }, QUESTION_RELAY_TIMEOUT_MS);
      timer.unref?.();
      relayed.set(qid, {
        controller,
        resolve: (value) => {
          finish(() => {
            resolve3(value);
          });
        },
        reject: (error) => {
          finish(() => {
            reject(error);
          });
        }
      });
      if (request.signal?.aborted === true) {
        onAbort();
        return;
      }
      request.signal?.addEventListener("abort", onAbort, { once: true });
      void controller.send({ kind: "ask", qid, sessionId: state.wireId, questions: request.questions }).catch((error) => {
        const pending = relayed.get(qid);
        if (pending === void 0) return;
        relayed.delete(qid);
        finish(() => {
          reject(error instanceof Error ? error : new Error(String(error)));
        });
      });
    });
    return answer;
  }, { global: true, prepend: true });
  const audit = (peer, op, ok, extra) => {
    if (read().audit === false) return;
    try {
      const file = read().auditFile ?? dshHomePath("dsh-remote", "server-audit.log");
      mkdirSync4(dirname4(file), { recursive: true });
      appendFileSync2(
        file,
        `${JSON.stringify({ ts: (/* @__PURE__ */ new Date()).toISOString(), peer, op, ok, ...extra ?? {} })}
`,
        "utf8"
      );
    } catch {
    }
  };
  const journal = new Journal({
    file: read().journalFile ?? dshHomePath("dsh-remote", "journal.jsonl")
  });
  journal.load();
  const record3 = (entry) => {
    if (read().journal === false) return;
    try {
      journal.append(entry);
    } catch {
    }
  };
  record3({
    kind: "note",
    summary: `server half started (build ${BUILD}); port ${read().port ?? 0}, workspace ${text(read().workspace) ?? process.cwd()}`
  });
  const ensureAgent = async (sessionId, presetId, workspace) => {
    const controller = connection();
    const generation = resources().generation.signal;
    generation.throwIfAborted();
    const wireId = sessionId;
    sessionId = scopedSessionId(wireId);
    const existing = states.get(sessionId);
    if (existing !== void 0) {
      if (existing.principal !== controller.principal) throw new FsError2("session belongs to another controller", "FS_PERMISSION_DENIED");
      return { handle: existing.handle, created: false };
    }
    const pending = ensuring.get(sessionId);
    if (pending !== void 0) {
      const resolved = await pending;
      if (states.get(sessionId)?.principal !== controller.principal) {
        throw new FsError2("session belongs to another controller", "FS_PERMISSION_DENIED");
      }
      return resolved;
    }
    const creating = Promise.resolve().then(async () => {
      const agents = ctx.get("agents");
      const presets = ctx.get("agentPresets");
      if (agents === void 0) throw new Error("dsh-remote-server: the `agents` service is unavailable");
      const wantedPreset = text(presetId) ?? text(read().defaultPreset);
      const defaults = ctx.get("agentDefaultModel")?.currentSelection();
      const setup = async (agentCtx) => {
        installModelSelection(agentCtx);
        if (read().promptGuidance !== false) {
          try {
            agentCtx.systemPrompt.section({
              name: "dsh-remote:controlled",
              // Free slot before the first-party tool guidance (900/1000 are taken).
              order: 960,
              text: CONTROLLED_GUIDANCE
            });
          } catch (error) {
            ctx.logger.debug(`dsh-remote-server: prompt guidance skipped: ${String(error)}`);
          }
        }
        if (presets === void 0) return;
        const preset = await presets.resolve(wantedPreset);
        await presets.mount(agentCtx, preset.id);
      };
      const requested = text(workspace) ?? text(read().workspace) ?? process.cwd();
      const registry = ctx.get("workspaceRegistry");
      let owner;
      if (registry !== void 0) {
        try {
          owner = await registry.create(requested);
        } catch (error) {
          ctx.logger.warn(`dsh-remote-server: workspace registry refused ${requested}: ${String(error)}`);
        }
      }
      const cwd = typeof owner?.path === "string" ? owner.path : requested;
      let handle;
      let created = false;
      try {
        policyFor(controller);
        generation.throwIfAborted();
        handle = await agents.resume({
          resumeSessionId: SessionId(sessionId),
          setup,
          signal: generation,
          ...defaults === void 0 ? {} : { agentOptions: defaults }
        });
      } catch (error) {
        generation.throwIfAborted();
        policyFor(controller);
        if (!isDefiniteSessionNotFound(error, sessionId)) throw error;
        ctx.logger.debug(`dsh-remote-server: session ${sessionId} definitely absent; creating`);
        const preset = presets === void 0 ? void 0 : await presets.resolve(wantedPreset);
        handle = await agents.create({
          sessionId: SessionId(sessionId),
          signal: generation,
          ...defaults === void 0 ? {} : { agentOptions: defaults },
          meta: {
            cwd,
            ...preset === void 0 ? {} : { agentPreset: preset.id }
          },
          setup
        });
        created = true;
        try {
          await owner?.attachSession(SessionId(sessionId));
        } catch (attachError) {
          ctx.logger.warn(`dsh-remote-server: attachSession failed: ${String(attachError)}`);
        }
        try {
          const session = handle.agent.session;
          ctx.get("sessionTitle")?.rename(session, `remote: ${sessionId}`);
        } catch (titleError) {
          ctx.logger.debug(`dsh-remote-server: title rename skipped: ${String(titleError)}`);
        }
      }
      if (generation.aborted) {
        try {
          handle.agent?.cancel({ kind: "hook", reason: "controller authorization revoked" });
        } catch {
        }
        generation.throwIfAborted();
      }
      policyFor(controller);
      states.set(sessionId, { handle, tail: Promise.resolve(), principal: controller.principal, wireId });
      return { handle, created };
    });
    ensuring.set(sessionId, creating);
    try {
      return await creating;
    } finally {
      if (ensuring.get(sessionId) === creating) ensuring.delete(sessionId);
    }
  };
  const prompt = async (sessionId, promptText, timeoutMs, presetId, workspace) => {
    const generation = resources().generation.signal;
    const { handle, created } = await ensureAgent(sessionId, presetId, workspace);
    const localId = scopedSessionId(sessionId);
    const state = ownState(sessionId);
    const resumeOf = state.tail;
    let release = () => {
    };
    state.tail = new Promise((resolve3) => {
      release = resolve3;
    });
    await withAuthorization(resumeOf, generation);
    try {
      const agent = handle.agent;
      const sessions = ctx.get("sessions");
      const startedAt = Date.now();
      await withAuthorization(agent.whenIdle(), generation);
      if (consumeStop(localId)) {
        return {
          sessionId,
          created,
          reply: "",
          replies: [],
          replyFormat: "committed-assistant-v1",
          reason: "aborted",
          error: null,
          interrupted: true,
          interruptCause: "user",
          seq: agent.session.seq,
          durationMs: Date.now() - startedAt
        };
      }
      generation.throwIfAborted();
      assertControllerOperation(connection(), "agent.prompt");
      const principal = connection().principal;
      const firstSeq = agent.session.seq;
      const ioAdmission = await admitViaIo({
        principal,
        localId,
        wireId: sessionId,
        text: promptText,
        mode: "queue",
        externalMessageId: randomUUID3()
      });
      if (ioAdmission.kind === "unknown") {
        throw new Error(`dsh-remote-server: super-agent-io admission outcome is unknown; do not resend (${ioAdmission.reason})`);
      }
      let inputMessageId;
      let inputTraceId;
      let inputTransport;
      if (ioAdmission.kind === "accepted") {
        inputMessageId = ioAdmission.receipt.messageId;
        inputTraceId = ioAdmission.receipt.traceId;
        inputTransport = "super-agent-io";
        rememberInjection(localId, inputMessageId);
      } else {
        const message = createUserMessage({
          content: [{ type: "text", text: promptText }],
          source: {
            kind: "dsh-remote",
            version: 1,
            principal,
            remoteSessionId: sessionId,
            operation: "agent.prompt",
            traceId: randomUUID3()
          }
        });
        inputMessageId = String(message.id);
        inputTraceId = message.source.traceId;
        inputTransport = "dsh-remote";
        rememberInjection(localId, inputMessageId);
        await admitTracked(await messageTraces.store(), {
          version: 1,
          traceId: message.source.traceId,
          principal,
          sessionId: localId,
          remoteSessionId: sessionId,
          messageId: inputMessageId,
          seq: null,
          time: Date.now(),
          operation: "agent.prompt",
          requestedMode: "queue",
          mode: "queue",
          state: "admitting"
        }, () => {
          generation.throwIfAborted();
          assertControllerOperation(connection(), "agent.prompt");
          agent.followup(message);
        });
      }
      if (timeoutMs > 0) {
        await Promise.race([
          withAuthorization(agent.whenIdle(), generation),
          new Promise((_resolve, reject) => {
            const timer = setTimeout(() => reject(new Error(`prompt timed out after ${timeoutMs} ms`)), timeoutMs);
            timer.unref?.();
          })
        ]);
      } else {
        await withAuthorization(agent.whenIdle(), generation);
      }
      if (sessions !== void 0) await sessions.flush(agent.session);
      const events = agent.session.snapshotEvents();
      const outcome = summarizeReplies(events, firstSeq, sessionId);
      const input = events.find((event) => event.type === "user/message" && event.data.id === inputMessageId);
      if (input !== void 0 && inputTransport === "dsh-remote") {
        await messageTraces.anchor(principal, localId, inputMessageId, input.seq, input.time);
      }
      return {
        sessionId,
        created,
        reply: outcome.text,
        input: { messageId: inputMessageId, traceId: inputTraceId, seq: input?.seq ?? null, transport: inputTransport },
        replies: outcome.replies,
        replyFormat: outcome.replyFormat,
        reason: outcome.reason,
        error: outcome.error,
        // A cancelled turn is not a reply: say so, and say who cancelled it, so
        // the controller stops instead of reading an empty answer as a result.
        ...outcome.interruptCause === null ? {} : { interrupted: true, interruptCause: outcome.interruptCause },
        seq: agent.session.seq,
        durationMs: Date.now() - startedAt
      };
    } finally {
      release();
    }
  };
  const decodeOutput = (buf) => {
    if (buf.length === 0) return "";
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(buf);
    } catch {
    }
    for (const encoding of ["gbk", "big5", "shift_jis", "windows-1252"]) {
      try {
        return new TextDecoder(encoding).decode(buf);
      } catch {
      }
    }
    return buf.toString("utf8");
  };
  const exec = (command, shell, timeoutMs, cwd, execId) => new Promise((resolve3, reject) => {
    const execs = resources().execs;
    if (execId !== void 0 && execs.has(execId)) {
      reject(new Error("execId is already running"));
      return;
    }
    const cap = read().maxExecTimeoutMs ?? 6e5;
    const limit = Math.min(timeoutMs > 0 ? timeoutMs : 12e4, cap);
    const argv = shell === "cmd" ? ["cmd", "/c", command] : ["powershell", "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Continue';${command}`];
    const startedAt = Date.now();
    let cancelled = false;
    let release = () => {
    };
    const child = execFile(
      argv[0],
      argv.slice(1),
      {
        timeout: limit,
        cwd: text(cwd) ?? void 0,
        windowsHide: true,
        maxBuffer: 64 * 1024 * 1024,
        // Capture raw bytes: the decoder above needs to see them undamaged.
        encoding: "buffer"
      },
      (error, stdoutRaw, stderrRaw) => {
        release();
        const stdout = decodeOutput(stdoutRaw);
        const stderr = decodeOutput(stderrRaw);
        const killed = error !== null && error.killed === true;
        if (cancelled || killed && cancelled) {
          resolve3({
            exit: null,
            timedOut: false,
            cancelled: true,
            stdout,
            stderr: `${stderr}
[dsh-remote] stopped by the controller`,
            durationMs: Date.now() - startedAt
          });
          return;
        }
        if (killed) {
          resolve3({
            exit: null,
            timedOut: true,
            stdout,
            stderr: `${stderr}
[dsh-remote] timed out after ${limit} ms`,
            durationMs: Date.now() - startedAt
          });
          return;
        }
        if (error !== null && typeof error.code !== "number") {
          reject(error);
          return;
        }
        resolve3({
          exit: error === null ? 0 : error.code ?? null,
          timedOut: false,
          stdout,
          stderr,
          durationMs: Date.now() - startedAt
        });
      }
    );
    if (execId !== void 0 && execId !== "") {
      release = execs.add(execId, {
        cancel: () => {
          cancelled = true;
          killTree(child);
        }
      });
    }
  });
  const fsVersionOf = async (path) => {
    const info = await stat2(path);
    return `${info.mtimeMs}:${info.size}`;
  };
  const deniedToolReason = (name2) => {
    for (const prefix of DENIED_TOOL_PREFIXES) {
      if (name2.startsWith(prefix)) return "it is dsh-remote's own bridge tool; calling it would loop controllers back around";
    }
    for (const entry of read().deniedTools ?? []) {
      const pattern = typeof entry === "string" ? entry.trim() : "";
      if (pattern === "") continue;
      const matches = pattern.endsWith("*") ? name2.startsWith(pattern.slice(0, -1)) : name2 === pattern;
      if (matches) return "this machine's configuration denies direct calls to it";
    }
    return void 0;
  };
  const capabilityPresetArg = (presetId) => typeof presetId === "string" && presetId.trim() !== "" ? presetId.trim() : text(read().capabilityPreset) ?? "";
  const acquireCapabilityScope = async (presetId) => {
    const presets = ctx.get("agentPresets");
    if (presets === void 0) throw new Error("dsh-remote-server: the `agentPresets` service is unavailable");
    const wanted = capabilityPresetArg(presetId);
    const lease = await presets.acquireScope(wanted === "" ? void 0 : wanted);
    try {
      const resolved = await presets.resolve(wanted === "" ? void 0 : wanted);
      return {
        key: lease.key,
        presetId: resolved.id,
        release: async () => {
          await lease[Symbol.asyncDispose]();
        }
      };
    } catch (error) {
      await lease[Symbol.asyncDispose]();
      throw error;
    }
  };
  const capabilityCatalog = async (presetId) => {
    if (read().capabilities === false) {
      return {
        available: false,
        reason: "direct capability calls are disabled on this machine (dsh-remote-server: capabilities=false)",
        presetId: ""
      };
    }
    const presets = ctx.get("agentPresets");
    const tools = ctx.get("tools");
    if (presets === void 0 || tools === void 0) {
      return {
        available: false,
        reason: "this DSH does not provide the `tools`/`agentPresets` services",
        presetId: ""
      };
    }
    const lease = await acquireCapabilityScope(presetId);
    try {
      const rows = tools.schemas(lease.key).map((schema) => {
        const reason = deniedToolReason(schema.name);
        const definition = tools.get(schema.name, lease.key);
        const globalDefinition = tools.get(schema.name);
        return {
          name: schema.name,
          description: schema.description,
          parameters: schema.parameters,
          origin: definition !== void 0 && definition === globalDefinition ? "global" : "preset",
          callable: reason === void 0,
          ...reason === void 0 ? {} : { reason }
        };
      }).sort((left, right) => left.name.localeCompare(right.name));
      const roster = await presets.list();
      const presetsRows = roster.map((preset) => ({
        id: preset.id,
        ...preset.name === void 0 ? {} : { name: preset.name },
        ...preset.description === void 0 ? {} : { description: preset.description },
        isDefault: preset.id === presets.defaultId,
        ...preset.broken === void 0 ? {} : { broken: preset.broken }
      }));
      const plugins = (await presets.compositionInventory()).map((row) => ({
        presetId: row.id,
        ...row.name === void 0 ? {} : { name: row.name },
        isDefault: row.isDefault,
        ...row.broken === void 0 ? {} : { broken: row.broken },
        rows: row.rows.map((plugin) => ({
          id: plugin.entryId,
          name: plugin.moduleName,
          enabled: plugin.enabled,
          ...plugin.condition === void 0 ? {} : { condition: plugin.condition }
        }))
      }));
      const sessions = (ctx.get("agents")?.list() ?? []).flatMap((agent) => {
        const exposedId = wireSessionId(String(agent.id));
        if (exposedId === void 0) return [];
        const agentPreset = presets.composedPreset(agent.ctx);
        const cwd = agent.session.header.cwd;
        return {
          sessionId: exposedId,
          status: String(agent.status),
          ...agentPreset === void 0 ? {} : { presetId: agentPreset },
          ...typeof cwd === "string" && cwd !== "" ? { cwd } : {}
        };
      });
      const subagentProviders = (ctx.get("subagents")?.list() ?? []).map((name2) => String(name2));
      return {
        available: true,
        build: BUILD,
        presetId: lease.presetId,
        presets: presetsRows,
        tools: rows,
        plugins,
        sessions,
        subagentProviders
      };
    } finally {
      await lease.release();
    }
  };
  const wireJson = (value) => {
    try {
      return JSON.parse(JSON.stringify(value ?? null));
    } catch {
      return [{ type: "text", text: String(value) }];
    }
  };
  const callCapability = async (args) => {
    const activeToolCalls = resources().activeToolCalls;
    if (read().capabilities === false) {
      throw new Error("dsh-remote-server: direct capability calls are disabled on this machine (capabilities=false)");
    }
    const name2 = String(args.name ?? "");
    if (name2 === "") throw new Error("caps.call: `name` is required");
    const denial = deniedToolReason(name2);
    if (denial !== void 0) throw new Error(`caps.call: refusing ${JSON.stringify(name2)}: ${denial}`);
    const tools = ctx.get("tools");
    if (tools === void 0) throw new Error("dsh-remote-server: the `tools` service is unavailable");
    const callId = typeof args.callId === "string" && args.callId !== "" ? args.callId : randomUUID3();
    if (activeToolCalls.has(callId)) throw new Error(`caps.call: callId ${JSON.stringify(callId)} is already running`);
    const callArgs = args.arguments === void 0 || args.arguments === null ? {} : args.arguments;
    const ceiling = Math.max(1e3, read().maxToolCallTimeoutMs ?? 6e5);
    const requested = Number(args.timeoutMs ?? ceiling);
    const timeoutMs = Number.isFinite(requested) ? Math.min(Math.max(Math.floor(requested), 1e3), ceiling) : ceiling;
    const controller = new AbortController();
    activeToolCalls.set(callId, controller);
    let lease;
    try {
      lease = await acquireCapabilityScope(args.presetId);
      if (controller.signal.aborted) throw controller.signal.reason;
      const definition = tools.get(name2, lease.key);
      if (definition === void 0) {
        throw new Error(
          `caps.call: the peer exposes no tool named ${JSON.stringify(name2)} in preset ${JSON.stringify(lease.presetId)}`
        );
      }
      const timer = setTimeout(() => {
        const timeout = new Error(`the peer's ${name2} call timed out after ${timeoutMs} ms`);
        timeout.name = "AbortError";
        controller.abort(timeout);
      }, timeoutMs);
      timer.unref?.();
      const startedAt = Date.now();
      const signal = controller.signal;
      const callIdBrand = connection().multi ? `remote-${connection().principal}-${createHash5("sha256").update(callId).digest("hex")}` : callId;
      const exec2 = {
        token: /* @__PURE__ */ Symbol("dsh-remote:caps.call"),
        callId: callIdBrand,
        rootCallId: callIdBrand,
        name: name2,
        arguments: callArgs,
        signal,
        deferContext: () => {
        },
        concludeTurn: () => {
        }
      };
      try {
        assertControllerOperation(connection(), "caps.call");
        const body = definition.execute(callArgs, exec2).then((value2) => {
          const content2 = definition.output.render(callArgs, value2);
          return { value: value2, content: content2 };
        });
        body.catch(() => {
        });
        const aborted = new Promise((_resolve, reject) => {
          const onAbort = () => {
            reject(signal.reason instanceof Error ? signal.reason : new Error(`the peer cancelled ${name2}`));
          };
          if (signal.aborted) {
            onAbort();
            return;
          }
          signal.addEventListener("abort", onAbort, { once: true });
        });
        const { value, content } = await Promise.race([body, aborted]);
        return {
          callId,
          ...value === void 0 ? {} : { value: wireJson(value) },
          content: wireJson(content),
          durationMs: Date.now() - startedAt
        };
      } finally {
        clearTimeout(timer);
      }
    } finally {
      if (activeToolCalls.get(callId) === controller) activeToolCalls.delete(callId);
      await lease?.release();
    }
  };
  const ops = {
    "relay.register": async () => relayHub.register(connection()),
    "relay.open": async (args) => relayHub.open(connection(), args),
    "relay.accept": async (args) => relayHub.accept(connection(), args),
    "relay.write": async (args) => relayHub.write(connection(), args),
    "relay.close": async (args) => relayHub.close(connection(), args),
    "relay.status": async () => relayHub.status(connection()),
    ping: async () => ({ pong: true, version: SERVER_VERSION, pid: process.pid }),
    sysinfo: async () => ({
      hostname: process.env.COMPUTERNAME ?? process.env.HOSTNAME ?? "",
      platform: process.platform,
      arch: process.arch,
      node: process.version,
      pid: process.pid,
      cwd: process.cwd(),
      dshHome: dshHomePath(),
      identity: fingerprint(identity.publicKey),
      build: BUILD,
      features: { replies: "committed-assistant-v1", inputSource: "dsh-remote-v1", noteModes: ["queue", "steer", "auto"] },
      sessions: [...states.values()].filter((state) => state.principal === connection().principal).map((state) => state.wireId),
      // Advertised so a controller can tell an op exists BEFORE spending a round
      // trip on it: `agent.sessions` is what lets an older controller fall back
      // to the plain `sessions` list above instead of erroring.
      ops: Object.keys(ops)
    }),
    exec: async (args) => exec(
      String(args.cmd ?? ""),
      String(args.shell ?? "powershell"),
      Number(args.timeoutMs ?? 12e4),
      typeof args.cwd === "string" ? args.cwd : void 0,
      // Optional: without it the command simply cannot be stopped later.
      typeof args.execId === "string" ? args.execId : void 0
    ),
    /**
     * Read the trajectory journal.
     *
     * The cheap way to pull this machine's history into a controller's context.
     * `fromSeq` omitted means "the tail" (the newest `limit` entries) — what a
     * reader that has never looked wants; pass the `nextSeq` from the previous
     * read and only what is new comes back. Entries are one line each unless
     * `full` asks for the detail.
     */
    "journal.read": async (args) => {
      const limit = Number(args.limit ?? 100);
      const asked = args.fromSeq;
      const bounded = Number.isFinite(limit) && limit > 0 ? Math.min(Math.floor(limit), 500) : 100;
      const from = asked === void 0 ? Math.max(0, journal.lastSeq - bounded) : Number(asked);
      const page = journal.read(from, bounded, true);
      const entries = page.entries.filter((entry) => entry.detail?.principal === connection().principal || !connection().multi && entry.detail?.principal === void 0).map((entry) => {
        const detail = entry.detail === void 0 ? void 0 : { ...entry.detail };
        if (detail !== void 0) delete detail.principal;
        const { detail: _private, ...compact } = entry;
        return args.full === true ? { ...compact, ...detail === void 0 ? {} : { detail } } : compact;
      });
      return {
        ...page,
        entries,
        count: entries.length,
        total: connection().multi ? entries.length : page.total,
        ...asked === void 0 ? { tail: true } : {},
        lastSeq: journal.lastSeq,
        written: journal.writtenCount
      };
    },
    /**
     * Stop a command this half is running for a controller.
     *
     * The counterpart of the local Stop: the controller settles its own call at
     * once (it cannot wait for a reply that may be minutes away) and then asks
     * here, so the work actually stops instead of running to its timeout.
     */
    "exec.cancel": async (args) => {
      const execId = String(args.execId ?? "");
      if (execId === "") throw new Error("exec.cancel: execId is required");
      return { execId, cancelled: resources().execs.cancel(execId) };
    },
    "fs.read": async (args) => {
      const path = String(args.path ?? "");
      const data = await readFile2(path);
      const offset = Number(args.offset ?? 0);
      const length = Number(args.length ?? data.length);
      const slice = data.subarray(offset, offset + length);
      return {
        size: data.length,
        offset,
        read: slice.length,
        eof: offset + slice.length >= data.length,
        dataB64: slice.toString("base64")
      };
    },
    "fs.write": async (args) => {
      const path = String(args.path ?? "");
      const data = Buffer.from(String(args.dataB64 ?? ""), "base64");
      const offset = Number(args.offset ?? 0);
      const expectedVersion = typeof args.expectedVersion === "string" ? args.expectedVersion : void 0;
      const createOnly = args.createOnly === true;
      const before = await readFile2(path).catch(() => void 0);
      if (createOnly && before !== void 0) {
        throw new FsError2(`cannot overwrite existing "${path}" without reading it first`, "FS_NOT_OBSERVED");
      }
      if (expectedVersion !== void 0) {
        if (before === void 0) {
          throw new FsError2(`cannot write "${path}": file no longer exists`, "FS_STALE_VERSION");
        }
        if (await fsVersionOf(path) !== expectedVersion) {
          throw new FsError2(`cannot write "${path}": file changed since it was read`, "FS_STALE_VERSION");
        }
      }
      mkdirSync4(dirname4(path), { recursive: true });
      if (offset > 0) {
        const existing = before ?? Buffer.alloc(0);
        const merged = Buffer.concat([existing.subarray(0, offset), data]);
        await writeFile(path, merged);
      } else {
        await writeFile(path, data);
      }
      return {
        written: data.length,
        size: (await stat2(path)).size,
        version: await fsVersionOf(path),
        created: before === void 0,
        before: before === void 0 || offset > 0 ? null : decodeOutput(before)
      };
    },
    "fs.edit": async (args) => {
      const path = String(args.path ?? "");
      const oldString = String(args.oldString ?? "");
      const newString = String(args.newString ?? "");
      const replaceAll = args.replaceAll === true;
      const expectedVersion = typeof args.expectedVersion === "string" ? args.expectedVersion : void 0;
      if (oldString === "") throw new FsError2("oldString must not be empty", "FS_EDIT_NOT_FOUND");
      const before = await readFile2(path).catch(() => void 0);
      if (before === void 0) {
        throw new FsError2(`cannot edit "${path}": file changed since it was read`, "FS_STALE_VERSION");
      }
      if (expectedVersion !== void 0 && await fsVersionOf(path) !== expectedVersion) {
        throw new FsError2(`cannot edit "${path}": file changed since it was read`, "FS_STALE_VERSION");
      }
      const text2 = decodeOutput(before);
      const count = text2.split(oldString).length - 1;
      if (count === 0) {
        throw new FsError2(`cannot edit "${path}": the text to replace was not found`, "FS_EDIT_NOT_FOUND");
      }
      if (count > 1 && !replaceAll) {
        throw new FsError2(`cannot edit "${path}": the text to replace appears ${count} times`, "FS_AMBIGUOUS_EDIT");
      }
      const after = replaceAll ? text2.split(oldString).join(newString) : text2.replace(oldString, newString);
      await writeFile(path, Buffer.from(after, "utf8"));
      return { version: await fsVersionOf(path), before: text2, after };
    },
    "fs.list": async (args) => {
      const path = String(args.path ?? ".");
      const entries = await readdir(path, { withFileTypes: true });
      const rows = await Promise.all(entries.map(async (entry) => {
        const info = await stat2(`${path}/${entry.name}`).catch(() => void 0);
        return {
          name: entry.name,
          isDir: entry.isDirectory(),
          size: info?.size ?? 0,
          mtimeMs: info?.mtimeMs ?? 0
        };
      }));
      rows.sort((a, b) => a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1);
      return { path, count: rows.length, entries: rows };
    },
    "fs.stat": async (args) => {
      const path = String(args.path ?? "");
      try {
        const info = await stat2(path);
        return {
          exists: true,
          isDir: info.isDirectory(),
          size: info.size,
          mtimeMs: info.mtimeMs,
          version: `${info.mtimeMs}:${info.size}`
        };
      } catch {
        return { exists: false };
      }
    },
    "fs.hash": async (args) => {
      const data = await readFile2(String(args.path ?? ""));
      return {
        algo: "sha256",
        hash: createHash5("sha256").update(data).digest("hex"),
        bytes: data.length
      };
    },
    /**
     * Chunked, per-block-compressed transfers — the fast path for large files.
     *
     * These are NEW ops on purpose: `fs.read`/`fs.write` stay exactly as they
     * were, so a controller that does not know these (or an old peer that does
     * not advertise them) keeps working. A controller capability-negotiates from
     * `sysinfo.ops`. Permissions: `begin` is fenced on its `path` like any write;
     * `chunk`/`commit`/`abort` carry only an `uploadId`, which cannot name a
     * different path because the path was fixed at `begin`.
     */
    "fs.put.begin": async (args) => {
      const owned = resources();
      const result = await owned.transfers.begin(args);
      owned.uploadPaths.set(String(result.uploadId), String(args.path));
      return result;
    },
    "fs.put.chunk": async (args) => resources().transfers.chunk(args),
    "fs.put.commit": async (args) => {
      const owned = resources();
      try {
        return await owned.transfers.commit(args);
      } finally {
        owned.uploadPaths.delete(String(args.uploadId ?? ""));
      }
    },
    "fs.put.abort": async (args) => {
      const owned = resources();
      try {
        return await owned.transfers.abort(args);
      } finally {
        owned.uploadPaths.delete(String(args.uploadId ?? ""));
      }
    },
    "fs.get": async (args) => resources().transfers.get(args),
    // Authenticated read-only metadata; never mounts or creates an Agent.
    "references.list": async (args) => listReferenceCatalog(ctx, args, connection().signal),
    "preset.list": async () => {
      const presets = ctx.get("agentPresets");
      if (presets === void 0) return { available: false, presets: [] };
      const list = await presets.list();
      return {
        available: true,
        defaultId: presets.defaultId,
        presets: list.map((preset) => ({
          id: preset.id,
          name: preset.name ?? "",
          broken: preset.broken ?? null
        }))
      };
    },
    /**
     * This machine's function-call surface, for a controller to mirror locally.
     *
     * Read-only and session-free: the answer is the set of tools one agent
     * preset contributes (plus host-level tools), that preset's plugin
     * inventory, the deployment's presets (its subagent types), its subagent
     * providers, and the live sessions that exist right now — the last purely as
     * information; nothing here drives them.
     *
     * `callable:false` is reported rather than omitted: a controller should be
     * able to tell "the peer has this tool but refuses it" from "the peer does
     * not have it", especially for the bridge tools whose absence prevents a
     * loop.
     */
    "caps.list": async (args) => capabilityCatalog(args.presetId),
    /**
     * Run ONE of this machine's registered tools directly.
     *
     * The peer's own tool body executes here with no agent and no session. This
     * is the fast path a controller uses instead of spending a whole remote turn
     * on "please run tool X": the tool's schema was already mirrored locally, so
     * the model called it as if it were local, and only the body ran here.
     *
     * `callId` is caller-chosen so a local stop can address this exact call with
     * `caps.cancel`; it is required for that to work but optional for the call
     * itself (a random id is minted).
     */
    "caps.call": async (args) => callCapability(args),
    /**
     * Stop one direct tool call this half is running for a controller.
     *
     * Best effort, like `exec.cancel`: the controller has already settled its
     * own call, and this asks the work here to stop instead of letting it run to
     * its timeout. A body that ignores its AbortSignal still drains; nothing in
     * the same process can hard-kill it.
     */
    "caps.cancel": async (args) => {
      const callId = String(args.callId ?? "");
      if (callId === "") throw new Error("caps.cancel: callId is required");
      const controller = resources().activeToolCalls.get(callId);
      if (controller === void 0) return { callId, cancelled: false };
      const reason = new Error("the controller cancelled this tool call");
      reason.name = "AbortError";
      controller.abort(reason);
      return { callId, cancelled: true };
    },
    "agent.prompt": async (args) => {
      const sessionId = String(args.sessionId ?? "");
      if (sessionId === "") throw new Error("agent.prompt: sessionId is required");
      return prompt(
        sessionId,
        String(args.text ?? ""),
        Number(args.timeoutMs ?? 0),
        typeof args.presetId === "string" ? args.presetId : void 0,
        typeof args.workspace === "string" ? args.workspace : void 0
      );
    },
    /**
     * Inject one controller message WITHOUT waiting for a turn to finish.
     *
     * The sibling of `agent.prompt` for the "send_message to a running remote
     * subagent" flow: the controller is driving a long turn and has new
     * instructions, but must not block on the delivery. queue uses followup for
     * the next turn; steer uses the nearest admitted step; auto steers a busy
     * Agent and queues an idle Agent. Steering does not cancel a prepared request.
     * The returned mode and processing fields describe the actual placement.
     *
     * Input normally carries producer source kind:dsh-remote and persists its
     * admission trace before waking the Agent; when the optional superAgentIo
     * adapter is active it uses IO's real external source instead. Unknown
     * admission is never retried or re-injected here.
     */
    "agent.note": async (args) => {
      const sessionId = String(args.sessionId ?? "");
      if (sessionId === "") throw new Error("agent.note: sessionId is required");
      const noteText = String(args.text ?? "");
      if (noteText.trim() === "") throw new Error("agent.note: text is required");
      const requestedMode = inputMode(args.mode);
      const generation = resources().generation.signal;
      const { handle, created } = await ensureAgent(
        sessionId,
        typeof args.presetId === "string" ? args.presetId : void 0,
        typeof args.workspace === "string" ? args.workspace : void 0
      );
      const agent = handle.agent;
      const busy = await agentBusy(agent);
      generation.throwIfAborted();
      assertControllerOperation(connection(), "agent.note");
      const principal = connection().principal;
      const localId = scopedSessionId(sessionId);
      const mode = requestedMode === "auto" ? busy ? "steer" : "queue" : requestedMode;
      const ioAdmission = await admitViaIo({
        principal,
        localId,
        wireId: sessionId,
        text: noteText,
        mode: requestedMode,
        externalMessageId: randomUUID3()
      });
      if (ioAdmission.kind === "unknown") {
        throw new Error(`dsh-remote-server: super-agent-io admission outcome is unknown; do not resend (${ioAdmission.reason})`);
      }
      if (ioAdmission.kind === "accepted") {
        const actual = ioAdmission.receipt.mode;
        rememberInjection(localId, ioAdmission.receipt.messageId);
        return {
          sessionId,
          created,
          accepted: true,
          messageId: ioAdmission.receipt.messageId,
          traceId: ioAdmission.receipt.traceId,
          seq: agent.session.seq,
          requestedMode,
          mode: actual,
          processing: busy ? actual === "steer" ? "next-step" : "next-turn" : "starting",
          transport: "super-agent-io"
        };
      }
      const message = createUserMessage({
        content: [{ type: "text", text: noteText }],
        source: {
          kind: "dsh-remote",
          version: 1,
          principal,
          remoteSessionId: sessionId,
          operation: "agent.note",
          traceId: randomUUID3()
        }
      });
      rememberInjection(localId, String(message.id));
      let placement = { mode, processing: busy ? mode === "steer" ? "next-step" : "next-turn" : "starting" };
      await admitTracked(await messageTraces.store(), {
        version: 1,
        traceId: message.source.traceId,
        principal,
        sessionId: localId,
        remoteSessionId: sessionId,
        messageId: String(message.id),
        seq: null,
        time: Date.now(),
        operation: "agent.note",
        requestedMode,
        mode,
        state: "admitting"
      }, () => {
        generation.throwIfAborted();
        assertControllerOperation(connection(), "agent.note");
        placement = deliverInput(agent, message, requestedMode, busy);
      });
      return {
        sessionId,
        created,
        accepted: true,
        messageId: String(message.id),
        traceId: message.source.traceId,
        seq: agent.session.seq,
        requestedMode,
        transport: "dsh-remote",
        ...placement
      };
    },
    "agent.ensure": async (args) => {
      const sessionId = String(args.sessionId ?? "");
      if (sessionId === "") throw new Error("agent.ensure: sessionId is required");
      const { created } = await ensureAgent(
        sessionId,
        typeof args.presetId === "string" ? args.presetId : void 0,
        typeof args.workspace === "string" ? args.workspace : void 0
      );
      return { sessionId, created };
    },
    /**
     * Existing conversations on this machine, newest first.
     *
     * Read-only, and deliberately the cheapest useful answer to "may I continue
     * something instead of opening another session?": the controlling half calls
     * it when it has no session id to reuse. Rows come from the workspace
     * registry (that is where sessions created on request are accounted, live or
     * not), each workspace in `sessionIds` order — newest attached first — with
     * live handles this server owns appended for anything the registry does not
     * know about. A caller that needs an exact workspace should pass
     * `workspace`, because the cross-workspace order is otherwise just registry
     * order.
     */
    "agent.sessions": async (args) => {
      const prefix = typeof args.prefix === "string" ? args.prefix.trim() : "";
      const requested = typeof args.workspace === "string" ? args.workspace.trim() : "";
      const wanted = requested === "" ? void 0 : normalizePath(requested);
      const rows = [];
      const seen = /* @__PURE__ */ new Set();
      const add = (rawId, cwd) => {
        const localId = String(rawId);
        const sessionId = wireSessionId(localId);
        if (sessionId === void 0 || sessionId === "" || seen.has(sessionId)) return;
        if (!familyMatches(prefix, sessionId)) return;
        seen.add(sessionId);
        const live = ctx.get("sessions")?.get(SessionId(localId));
        const headerCwd = live?.header?.cwd;
        rows.push({
          sessionId,
          cwd: cwd ?? (typeof headerCwd === "string" ? headerCwd : null),
          live: live !== void 0,
          seq: typeof live?.seq === "number" ? live.seq : 0
        });
      };
      const accounts = (ctx.get("workspaceRegistry")?.list() ?? []).map((workspace) => ({
        path: workspace.path,
        sessionIds: workspace.sessionIds.map(String).filter((id) => wireSessionId(id) !== void 0)
      }));
      for (const reusable of orderReusableSessions(accounts, { prefix: "", workspace: requested })) {
        add(reusable.sessionId, reusable.cwd);
      }
      for (const [sessionId, state] of states) {
        if (state.principal !== connection().principal || seen.has(state.wireId) || !familyMatches(prefix, state.wireId)) continue;
        const cwd = state.handle?.agent?.session?.header?.cwd;
        const known = typeof cwd === "string" ? cwd : void 0;
        if (wanted !== void 0 && known !== void 0 && normalizePath(known) !== wanted) continue;
        add(sessionId, known);
      }
      return { prefix, workspace: requested, count: rows.length, sessions: rows };
    },
    "agent.interrupt": async (args) => {
      const sessionId = String(args.sessionId ?? "");
      const state = ownState(sessionId);
      const localId = scopedSessionId(sessionId);
      if (state === void 0) return { interrupted: false, reason: "no live handle for that session" };
      const agent = state.handle.agent;
      const busy = await agentBusy(agent);
      assertControllerOperation(connection(), "agent.interrupt");
      selfInterrupted.set(localId, Date.now());
      stopRequested.set(localId, Date.now());
      agent.cancel({ kind: "user" });
      return busy ? { interrupted: true } : { interrupted: false, latched: true, reason: "that session had no turn running; the stop is latched for the next one" };
    },
    "agent.events": async (args) => {
      const sessionId = String(args.sessionId ?? "");
      const state = ownState(sessionId);
      if (state === void 0) throw new Error("agent.events: no live handle for that session");
      const session = state.handle.agent.session;
      const events = session.snapshotEvents();
      return {
        sessionId,
        seq: session.seq,
        fromSeq: Number(args.fromSeq ?? 0),
        events: extractPublicEvents(events, Number(args.fromSeq ?? 0), Number(args.limit ?? 400), sessionId),
        replyFormat: "committed-assistant-v1"
      };
    },
    /**
     * Token usage for every model call in one live session.
     *
     * This is the read side of the controller's cost meter. Only tokens and the
     * route that produced them are reported — never a price: price tables and
     * peak/off-peak windows live on the controlling machine, where they can be
     * updated without redeploying this one. The controller polls with `fromSeq`
     * as an exclusive cursor; `records` never repeats a call the streaming
     * chunk and final message both reported (see session-usage.ts).
     *
     * `nextSeq` is the cursor for the next poll, and it is deliberately NOT
     * always `seq`. When the page was truncated by `limit` it is the seq of the
     * last returned record — advancing to `seq` there would skip every record
     * the line could not fit. Only an untruncated pass may jump to the newest
     * scanned event seq (or `fromSeq` when nothing newer exists), so a poller
     * can leave a quiet session without rescanning it forever. Callers must use
     * `nextSeq` as the next call's `fromSeq`.
     *
     * A session with no live handle is a normal answer, not an error: the
     * controller may still be finishing a call for a session whose handle was
     * torn down, and it should see `available: false` rather than a failed op.
     * The response keeps the same field set in both cases (`nextSeq = fromSeq`)
     * so the controller needs no branch just to move its cursor.
     */
    "usage.read": async (args) => {
      const sessionId = String(args.sessionId ?? "");
      if (sessionId === "") throw new Error("usage.read: sessionId is required");
      const requestedFrom = Number(args.fromSeq ?? 0);
      const fromSeq = Number.isSafeInteger(requestedFrom) && requestedFrom >= 0 ? requestedFrom : 0;
      const state = ownState(sessionId);
      if (state === void 0) {
        return {
          sessionId,
          available: false,
          reason: "no live handle for that session",
          seq: 0,
          fromSeq,
          // Nothing was scanned, so the cursor must not move.
          nextSeq: fromSeq,
          records: []
        };
      }
      const session = state.handle.agent.session;
      const events = session.snapshotEvents();
      const extracted = extractUsageRecords(events, {
        fromSeq,
        limit: Number(args.limit ?? 500)
      });
      return {
        sessionId,
        available: true,
        seq: Number(session.seq ?? 0),
        fromSeq,
        nextSeq: extracted.nextSeq,
        records: extracted.records
      };
    }
  };
  const serve = async (socket, peer, lease) => {
    const handshakeIdentity = identity;
    const deadline = setTimeout(() => {
      socket.destroy();
    }, networkLimits(read()).handshakeTimeoutMs);
    deadline.unref?.();
    let session;
    let registered;
    let authenticated;
    const lifetime = new AbortController();
    try {
      socket.setNoDelay(true);
      const declared = pinnedControllers();
      const multi = declared.length !== 0;
      const prefix = await readHandshakeField(socket, MAGIC.length);
      let key;
      let name2 = "legacy";
      if (prefix !== null && prefix.equals(KEY_SELECTOR_MAGIC)) {
        const selected = await readHandshakeField(socket, 64);
        if (selected === null) throw new HandshakeError("peer closed during key selection");
        const selectedId = fullKeyId(publicFromRaw(selected.subarray(0, 32)));
        const allowed = multi ? declared.find((candidate) => candidate.principal === selectedId) : void 0;
        key = allowed?.key ?? (multi ? publicFromRaw(selected.subarray(0, 32)) : resolvePeerPublicKey(read(), "client.pub"));
        if (multi && allowed === void 0 || fullKeyId(key) !== selectedId) {
          socket.write(KEY_SELECTOR_DENIED);
          throw new HandshakeError("unknown client public key");
        }
        name2 = allowed?.name ?? name2;
        socket.write(KEY_SELECTOR_ACK);
      } else if (prefix !== null && prefix.equals(MAGIC) && !multi && read().allowLegacyHandshake === true) {
        socket.unshift(prefix);
        key = resolvePeerPublicKey(read(), "client.pub");
      } else {
        throw new HandshakeError("peer must select an authorized key before the DSHR2 handshake");
      }
      session = await serverHandshake(socket, handshakeIdentity.key, key);
      socket.setTimeout(0);
      authenticated = {
        session,
        principal: fullKeyId(key),
        name: name2,
        multi,
        signal: lifetime.signal,
        serverIdentity: fullKeyId(handshakeIdentity.publicKey),
        authenticatedAt: Date.now(),
        policy: {}
      };
      authenticated.policy = policyFor(authenticated);
      lease.authenticated();
      clearTimeout(deadline);
      pendingSockets.delete(socket);
      principalPolicies.set(authenticated.principal, authenticated);
      ctx.logger.info(`dsh-remote-server: ${peer} authenticated as ${name2}`);
      registered = session;
      controllers.set(session, authenticated);
      beatHeartbeat();
    } catch (error) {
      clearTimeout(deadline);
      pendingSockets.delete(socket);
      lease.failed();
      audit(peer, "-", false, {
        reason: error instanceof HandshakeError ? "handshake_failed" : "handshake_error",
        detail: error instanceof Error ? error.message : String(error)
      });
      socket.destroy();
      return;
    }
    const handleRequest = async (link, request) => {
      const id = request.id;
      const op = String(request.op ?? "");
      const handler = Object.hasOwn(ops, op) ? ops[op] : void 0;
      if (handler === void 0) {
        try {
          await link.send({ id, ok: false, error: `unknown op ${JSON.stringify(op)}` });
        } catch {
        }
        audit(peer, op, false, { reason: "unknown_op" });
        return;
      }
      const startedAt = Date.now();
      try {
        const result = await requests.run(authenticated, async () => {
          const policy = assertControllerOperation(authenticated, op);
          const args = { ...request };
          if (policy.ceiling < 3 && ["fs.read", "fs.hash", "fs.get", "fs.stat", "fs.list"].includes(op)) {
            let accepted;
            for (const root of policy.readRoots) {
              try {
                accepted = await fencedPath(String(request.path ?? ""), root);
                break;
              } catch {
              }
            }
            if (accepted === void 0) throw new FsError2("file read is outside the authorized readRoots", "FS_PERMISSION_DENIED");
            args.path = accepted;
          }
          if (policy.ceiling === 2 && requiredLevel(op) === 2) {
            const upload = op.startsWith("fs.put.") && op !== "fs.put.begin";
            const target = upload ? resources().uploadPaths.get(String(request.uploadId ?? "")) : typeof request.path === "string" ? request.path : void 0;
            if (target === void 0) throw new FsError2("unknown upload or missing confined path", "FS_PERMISSION_DENIED");
            const canonical = await fencedPath(target, policy.workspaceRoot);
            if (!upload) args.path = canonical;
          }
          authenticated.signal.throwIfAborted();
          if (assertControllerOperation(authenticated, op).signature !== policy.signature) {
            throw new FsError2("controller policy changed before dispatch", "FS_PERMISSION_DENIED");
          }
          return await handler(args);
        });
        await link.send({ id, ok: true, ...result });
        const ms = Date.now() - startedAt;
        audit(peer, op, true, { ms });
        journalizeOp(op, request, { ok: true, ms, result });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const code = error.code;
        try {
          await link.send({
            id,
            ok: false,
            error: message,
            ...typeof code === "string" && /^FS_[A-Z_]+$/.test(code) ? { code } : {}
          });
        } catch {
        }
        const ms = Date.now() - startedAt;
        audit(peer, op, false, { ms, error: message.slice(0, 500) });
        journalizeOp(op, request, { ok: false, ms, error: message });
      }
    };
    function journalizeOp(op, request, outcome) {
      if (NOT_JOURNALED_OPS.has(op)) return;
      const { summary, detail } = summarizeOp(op, request, outcome);
      record3({
        kind: "op",
        summary,
        op,
        ok: outcome.ok,
        ms: outcome.ms,
        ...typeof request.sessionId === "string" && request.sessionId !== "" ? { sessionId: request.sessionId } : {},
        detail: { ...detail, principal: authenticated.principal }
      });
    }
    const remaining = Math.min(
      networkLimits(read()).maxSessionMs,
      authenticated.policy.expiresAt === void 0 ? Number.MAX_SAFE_INTEGER : authenticated.policy.expiresAt - Date.now()
    );
    const expiryTimer = setTimeout(() => {
      enforcePolicies();
      session.close();
    }, Math.max(1, remaining));
    expiryTimer.unref?.();
    try {
      let lastId = 0;
      for (; ; ) {
        const request = await session.recv();
        if (request === null) break;
        const envelope = validateRequestEnvelope(request, lastId);
        enforcePolicies();
        if (envelope.type === "answer") {
          const pending = relayed.get(envelope.qid);
          if (pending !== void 0 && pending.controller === session) {
            assertControllerOperation(authenticated, "agent.prompt");
            relayed.delete(envelope.qid);
            pending.resolve(request.answer);
          }
          continue;
        }
        lastId = envelope.id;
        const controls = envelope.op === "exec.cancel" || envelope.op === "caps.cancel" || envelope.op === "agent.interrupt" || envelope.op === "relay.accept" || envelope.op === "relay.close";
        const active = principalInFlight.get(authenticated.principal) ?? 0;
        if (!controls && active >= networkLimits(read()).maxInFlightPerPrincipal) {
          await session.send({ id: envelope.id, ok: false, error: "principal request concurrency limit exceeded" });
          continue;
        }
        if (controls) {
          await handleRequest(session, request);
          continue;
        }
        principalInFlight.set(authenticated.principal, active + 1);
        void handleRequest(session, request).finally(() => {
          const current = (principalInFlight.get(authenticated.principal) ?? 1) - 1;
          if (current <= 0) principalInFlight.delete(authenticated.principal);
          else principalInFlight.set(authenticated.principal, current);
        });
      }
    } catch (error) {
      ctx.logger.debug(`dsh-remote-server: ${peer} session ended: ${String(error)}`);
    } finally {
      clearTimeout(expiryTimer);
      lifetime.abort(new Error("controller connection closed"));
      if (registered !== void 0) {
        relayHub.detach(registered);
        controllers.delete(registered);
        for (const [qid, pending] of relayed) {
          if (pending.controller !== registered) continue;
          relayed.delete(qid);
          pending.reject(new Error("dsh-remote-server: the controller disconnected before answering"));
        }
      }
      socket.destroy();
    }
  };
  let listener;
  let listeningAt = "";
  const stop = () => {
    listener?.close();
    listener = void 0;
    listeningAt = "";
    for (const socket of sockets) socket.destroy();
  };
  const beatHeartbeat = () => {
    try {
      const file = read().heartbeatFile ?? dshHomePath("dsh-remote", "server-heartbeat.json");
      mkdirSync4(dirname4(file), { recursive: true });
      writeFileSync4(file, `${JSON.stringify({
        build: BUILD,
        at: (/* @__PURE__ */ new Date()).toISOString(),
        pid: process.pid,
        port: read().port ?? 0,
        host: read().host ?? "127.0.0.1",
        controllers: controllers.size,
        journalSeq: journal.lastSeq
      })}
`, "utf8");
    } catch {
    }
  };
  const start = () => {
    stop();
    const current = read();
    const server = createServer((socket) => {
      const peer = `${socket.remoteAddress ?? "?"}:${socket.remotePort ?? 0}`;
      const lease = disposed ? void 0 : guard.admit(socket.remoteAddress ?? "?");
      if (lease === void 0) {
        socket.destroy();
        return;
      }
      sockets.add(socket);
      pendingSockets.add(socket);
      socket.once("close", () => {
        sockets.delete(socket);
        pendingSockets.delete(socket);
        lease.release();
      });
      void serve(socket, peer, lease).catch((error) => {
        ctx.logger.debug(`dsh-remote-server: connection failed: ${String(error)}`);
        socket.destroy();
      });
    });
    server.on("error", (error) => {
      ctx.logger.error(`dsh-remote-server: listener error: ${error.message}`);
    });
    server.listen(current.port ?? 11325, current.host ?? "127.0.0.1", () => {
      ctx.logger.info(
        `dsh-remote-server: listening on ${current.host ?? "127.0.0.1"}:${current.port ?? 11325}`
      );
      beatHeartbeat();
    });
    listener = server;
    listeningAt = JSON.stringify([current.host, current.port]);
  };
  const refreshPolicy = () => {
    try {
      const next = resolvePrivateKey(read(), "server.key");
      if (fullKeyId(next.publicKey) !== fullKeyId(identity.publicKey)) {
        identity = next;
        for (const principal of principalPolicies.keys()) cancelPrincipal(principal, new Error("server identity rotated"));
        principalPolicies.clear();
        for (const socket of pendingSockets) socket.destroy();
      }
    } catch (error) {
      for (const principal of principalPolicies.keys()) cancelPrincipal(principal, new Error("server identity is unavailable"));
      principalPolicies.clear();
      stop();
      ctx.logger.warn(`dsh-remote-server: identity update rejected: ${String(error)}`);
      return;
    }
    enforcePolicies();
    const current = read();
    if (listeningAt !== JSON.stringify([current.host, current.port])) start();
  };
  ctx.on("loader/volatile-update", refreshPolicy);
  start();
  const policyTimer = setInterval(() => {
    if (!disposed) refreshPolicy();
  }, 100);
  policyTimer.unref?.();
  try {
    ctx.effect(() => () => {
      disposed = true;
      relayHub.dispose();
      clearInterval(policyTimer);
      for (const principal of principalPolicies.keys()) cancelPrincipal(principal, new Error("server disposed"));
      principalPolicies.clear();
      stop();
    }, "dsh-remote-server: stop listener");
  } catch (error) {
    ctx.logger.warn(`dsh-remote-server: could not register teardown (${String(error)})`);
  }
  try {
    ctx.effect(() => () => {
      if (capsPushTimer !== void 0) clearTimeout(capsPushTimer);
      for (const controller of controllers.keys()) controller.close();
      for (const owned of principalResources.values()) {
        owned.execs.cancelAll();
        for (const call of owned.activeToolCalls.values()) call.abort(new Error("server disposed"));
        owned.transfers.dispose();
        owned.uploadPaths.clear();
      }
      principalResources.clear();
    }, "dsh-remote-server: transfers");
  } catch (error) {
    ctx.logger.warn(`dsh-remote-server: could not register transfer teardown (${String(error)})`);
  }
}
export {
  BUILD,
  Config,
  DSH_REMOTE_SERVER_SETTINGS_NAMESPACE,
  SERVER_VERSION,
  apply,
  inject,
  killTree,
  name
};
