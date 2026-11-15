// src/client.ts
import { isVolatile } from "@deepseek-ai/cosmokit";
import { createHash as createHash6, randomUUID as randomUUID3 } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import { mkdir as mkdir2, open as open3, readFile, rename as rename2, rm as rm2 } from "node:fs/promises";
import { dirname as dirname5 } from "node:path";
import z2 from "@deepseek-ai/schemastery";
import { defineTool as defineTool5 } from "@deepseek-ai/dsh-tools";

// src/protocol.ts
import { KeyObject, createCipheriv, createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes, timingSafeEqual } from "node:crypto";
import { TextDecoder } from "node:util";
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
    await new Promise((resolve2, reject) => {
      let timer;
      let settled = false;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        if (timer !== void 0) clearTimeout(timer);
        this.sock.off("readable", wake);
        this.waiting = void 0;
        if (error === void 0) resolve2();
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
  await new Promise((resolve2, reject) => {
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
      if (error === void 0) resolve2();
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
    await new Promise((resolve2, reject) => {
      this.queue.push({ plaintext: Buffer.from(serialized, "utf8"), bytes, resolve: resolve2, reject });
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
        payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
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

// src/link.ts
import { createHash as createHash2 } from "node:crypto";

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
  return await new Promise((resolve2, reject) => {
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
      else resolve2(value);
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
    const open4 = async () => {
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
        await new Promise((resolve2, reject) => {
          const clean2 = () => {
            clearTimeout(timer);
            socket2.off("connect", connected);
            socket2.off("error", failed);
            socket2.off("close", closed);
          };
          const connected = () => {
            clean2();
            resolve2();
          };
          const failed = (error) => {
            clean2();
            reject(error);
          };
          const closed = () => {
            clean2();
            reject(new HandshakeError(`${this.label}: connection closed while dialing`));
          };
          const timer = setTimeout(() => {
            clean2();
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
    let socket = await open4();
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
        socket = await open4();
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
    const reply = new Promise((resolve2, reject) => {
      const timer = setTimeout(() => {
        this.waiting.delete(id);
        reject(new RequestTimeoutError(`${this.label}: ${op} timed out after ${timeout} ms`));
      }, timeout);
      this.waiting.set(id, { resolve: resolve2, reject, timer, session });
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
var PeerRegistry = class extends Service {
  peers;
  configuredDefaultPeer;
  constructor(ctx, config) {
    super(ctx, "dshRemotePeers");
    const peers = config.peers ?? {};
    const wanted = String(config.defaultPeer ?? "").trim();
    validatePeerNames(Object.keys(peers));
    if (wanted !== "" && !Object.hasOwn(peers, wanted)) {
      throw new FsError(`unknown default peer ${JSON.stringify(wanted)}`, "FS_NOT_FOUND");
    }
    this.peers = peers;
    this.configuredDefaultPeer = wanted;
  }
  /**
   * Replace the live declarations (a committed settings edit).
   *
   * The registry is what the filesystem provider and the completion provider
   * read per call, so updating it here applies a changed `defaultPeer` without a
   * restart. Renaming or adding a peer still needs a restart: the tool layer and
   * the worker pool snapshot declarations at load.
   * @param config - the new declarations.
   */
  update(config) {
    const peers = config.peers ?? this.peers;
    const wanted = String(config.defaultPeer ?? "").trim();
    validatePeerNames(Object.keys(peers));
    if (wanted !== "" && !Object.hasOwn(peers, wanted)) {
      throw new FsError(`unknown default peer ${JSON.stringify(wanted)}`, "FS_NOT_FOUND");
    }
    this.peers = peers;
    this.configuredDefaultPeer = wanted;
  }
  /** Declared peer names, in declaration order. */
  list() {
    return Object.keys(this.peers);
  }
  /**
   * The peer a bare `rmt:` path addresses.
   *
   * An explicit `defaultPeer` wins, otherwise the first declared peer — which is
   * the only peer in the common single-peer deployment.
   * @returns the peer name, or empty when nothing is declared.
   */
  defaultPeerName() {
    const wanted = this.configuredDefaultPeer.trim();
    if (wanted !== "") {
      if (!this.has(wanted)) throw new FsError(`unknown default peer ${JSON.stringify(wanted)}`, "FS_NOT_FOUND");
      return wanted;
    }
    return this.list()[0] ?? "";
  }
  /** True when `name` is declared. */
  has(name2) {
    return Object.hasOwn(this.peers, name2);
  }
  /**
   * The declaration for a peer.
   * @param name - the peer name.
   * @returns the profile.
   * @throws FsError when the peer is not declared.
   */
  profile(name2) {
    const profile = Object.hasOwn(this.peers, name2) ? this.peers[name2] : void 0;
    if (profile === void 0) {
      const declared = this.list();
      throw new FsError(
        `unknown peer "${name2}"` + (declared.length === 0 ? ": no peers are declared" : `: declared peers are ${declared.join(", ")}`),
        "FS_NOT_FOUND"
      );
    }
    return profile;
  }
  /** The peer's ceiling, normalized. */
  ceilingOf(name2) {
    return normalizePermission(this.profile(name2).maxPermission);
  }
  /** The peer's declared write boundary (may be empty). */
  workspaceRootOf(name2) {
    return String(this.profile(name2).workspaceRoot ?? "");
  }
  /**
   * Check one operation against a peer's ceiling.
   * @param name - the peer name.
   * @param op - the wire operation name.
   * @param path - the peer-side target path, when the operation has one.
   * @throws FsError when the operation exceeds the ceiling.
   */
  assert(name2, op, path) {
    assertPeerOperation(this.ceilingOf(name2), op, {
      peer: name2,
      ...path === void 0 ? {} : { path },
      workspaceRoot: this.workspaceRootOf(name2)
    });
  }
  /** A one-line summary of every declaration, for the boot log. */
  describe() {
    const declared = this.list();
    if (declared.length === 0) return "no peers declared";
    return declared.map((peerName) => `${peerName} (level ${this.ceilingOf(peerName)}/${levelName(this.ceilingOf(peerName))})`).join(", ");
  }
};

// src/peer-configuration.ts
function configuredPeers(config) {
  const peers = Object.fromEntries(Object.entries(config.peers ?? {}).map(([name2, value]) => [name2, { ...value }]));
  const legacy = config.peerName?.trim() || "default";
  if (!Object.hasOwn(peers, legacy) && (config.host?.trim() || Number(config.port) > 0 || config.relayTarget)) {
    peers[legacy] = {
      host: config.host,
      port: config.port,
      relayTarget: config.relayTarget,
      privateKey: config.privateKey,
      privateKeyFile: config.privateKeyFile,
      autoGenerateKey: config.autoGenerateKey,
      peerPublicKey: config.peerPublicKey,
      peerPublicKeyFile: config.peerPublicKeyFile,
      timeoutMs: config.timeoutMs,
      maxPermission: 3,
      allowLegacyHandshake: config.allowLegacyHandshake,
      maxSessionMs: config.maxSessionMs
    };
  }
  return peers;
}
function configuredDefaultPeer(config) {
  const peers = configuredPeers(config);
  const wanted = config.defaultPeer?.trim();
  if (wanted) {
    if (!Object.hasOwn(peers, wanted)) throw new Error(`Unknown default peer "${wanted}"`);
    return wanted;
  }
  return Object.keys(peers)[0] ?? "";
}
function defaultEndpoint(config) {
  const peers = configuredPeers(config);
  const name2 = configuredDefaultPeer(config);
  return name2 === "" ? {} : peers[name2];
}

// src/reference-tool.ts
import { defineTool } from "@deepseek-ai/dsh-tools";

// src/remote-path.ts
var MOUNT_PREFIX = "/rmt";
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
function tokenBounds(options) {
  const resolved = { ...DEFAULT_REFERENCE_TOKEN_BOUNDS, ...options };
  for (const [key, maximum] of [["maxChars", 1048576], ["maxQueryLength", 8192], ["maxMentions", 100]]) {
    const value = resolved[key];
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new TypeError(`${key} must be an integer from 1 to ${maximum}`);
  }
  return resolved;
}
function referenceProse(text2) {
  const mask = (value) => value.replace(/[^\r\n]/g, "\0");
  const lines = [];
  let fence;
  for (const line of text2.split(/(?<=\n)/u)) {
    const marker = /^ {0,3}(`{3,}|~{3,})(.*)$/u.exec(line.replace(/\r?\n$/u, ""));
    if (fence !== void 0) {
      lines.push(mask(line));
      if (marker?.[1]?.[0] === fence.character && marker[1].length >= fence.length && marker[2]?.trim() === "") fence = void 0;
    } else if (marker?.[1] !== void 0 && (marker[1][0] !== "`" || !marker[2]?.includes("`"))) {
      fence = { character: marker[1][0], length: marker[1].length };
      lines.push(mask(line));
    } else lines.push(/^(?: {4}|\t)/u.test(line) ? mask(line) : line);
  }
  const fenced = lines.join("");
  const runs = [];
  for (const match of fenced.matchAll(/`+/gu)) runs.push({ start: match.index, end: match.index + match[0].length, length: match[0].length });
  const nextByLength = /* @__PURE__ */ new Map();
  for (let index = runs.length - 1; index >= 0; index--) {
    const run = runs[index];
    const next = nextByLength.get(run.length);
    if (next !== void 0) run.next = next;
    nextByLength.set(run.length, index);
  }
  const output = [];
  let cursor = 0;
  for (let index = 0; index < runs.length; index++) {
    const run = runs[index];
    if (run.start < cursor) continue;
    output.push(fenced.slice(cursor, run.start));
    const close = run.next === void 0 ? void 0 : runs[run.next];
    const newline = close === void 0 ? fenced.indexOf("\n", run.end) : -1;
    const end = close?.end ?? (newline < 0 ? fenced.length : newline);
    output.push(mask(fenced.slice(run.start, end)));
    cursor = end;
    if (run.next !== void 0) index = run.next;
  }
  output.push(fenced.slice(cursor));
  return output.join("");
}
function extractReferenceTokens(text2, options = {}) {
  const { maxChars, maxQueryLength, maxMentions } = tokenBounds(options);
  const bounded2 = text2.slice(0, maxChars);
  const prose = referenceProse(bounded2);
  const tokens = [];
  const seen = /* @__PURE__ */ new Set();
  let truncated = text2.length > maxChars;
  for (let index = 0; index < prose.length; index++) {
    if (prose[index] !== "@" || index > 0 && !/\s/u.test(prose[index - 1])) continue;
    const quoted = prose[index + 1] === '"';
    const start = index + (quoted ? 2 : 1);
    let end = start;
    if (quoted) {
      while (end < prose.length && prose[end] !== '"' && prose[end] !== "\r" && prose[end] !== "\n") end++;
      const closed = prose[end] === '"';
      const queryEnd = end;
      if (closed) end++;
      else if (end !== text2.length || text2[end - 1] !== "/") {
        index = end;
        continue;
      }
      if (end < text2.length && !/\s/u.test(text2[end])) {
        index = end;
        continue;
      }
      if (queryEnd - start > maxQueryLength) {
        truncated = true;
        index = end - 1;
        continue;
      }
      const query = text2.slice(start, queryEnd);
      if (query === "" || /[\u0000-\u001f\u007f-\u009f"]/u.test(prose.slice(start, queryEnd))) {
        index = end - 1;
        continue;
      }
      if (!seen.has(query)) {
        if (tokens.length >= maxMentions) {
          truncated = true;
          break;
        }
        tokens.push(query);
        seen.add(query);
      }
    } else {
      while (end < prose.length && !/\s/u.test(prose[end])) end++;
      if (end === prose.length && end < text2.length && !/\s/u.test(text2[end])) {
        index = end - 1;
        continue;
      }
      if (end - start > maxQueryLength) {
        truncated = true;
        index = end - 1;
        continue;
      }
      const query = text2.slice(start, end);
      if (query === "" || /[\u0000-\u001f\u007f-\u009f"]/u.test(prose.slice(start, end))) {
        index = end - 1;
        continue;
      }
      if (!seen.has(query)) {
        if (tokens.length >= maxMentions) {
          truncated = true;
          break;
        }
        tokens.push(query);
        seen.add(query);
      }
    }
    index = end - 1;
  }
  return { tokens, truncated };
}

// src/reference-tool.ts
var shortName = (name2) => name2.replace(/^@[^/]+\//u, "");
var pluginExact = (row, query) => row.id === query || row.name === query || row.title === query || shortName(row.name) === query;
function resolveCatalogReference(parsed, catalog) {
  if (parsed.kind === "path") return { status: "resolved", kind: "path", peer: parsed.peer, path: mountPathFor(parsed.peer, parsed.path, false) };
  const workspaces = parsed.kind === "plugin" ? [] : matchingWorkspaces(catalog.workspaces, parsed.query);
  const plugins = parsed.kind === "workspace" || parsed.relative !== "" ? [] : catalog.plugins.filter((row) => pluginExact(row, parsed.query));
  if (workspaces.length === 1 && plugins.length === 0 && !catalog.truncated) {
    const workspace = workspaces[0];
    return {
      status: "resolved",
      kind: "workspace",
      peer: parsed.peer,
      workspace,
      path: mountPathFor(parsed.peer, workspaceChildPath(workspace.path, parsed.relative), false)
    };
  }
  if (workspaces.length === 0 && plugins.length > 0) {
    const names = new Set(plugins.map((row) => row.name));
    return { status: names.size === 1 && !catalog.truncated ? "resolved" : "ambiguous", kind: "plugin", peer: parsed.peer, plugins, truncated: catalog.truncated };
  }
  if (workspaces.length > 0 || plugins.length > 0) {
    return { status: "ambiguous", peer: parsed.peer, workspaces, plugins, truncated: catalog.truncated };
  }
  return { status: "not-found", peer: parsed.peer, workspaces: catalog.workspaces, plugins: catalog.plugins, truncated: catalog.truncated };
}
async function resolveRemoteReference(deps, parsed, signal, limit = 40) {
  signal?.throwIfAborted();
  if (parsed.kind === "path") return resolveCatalogReference(parsed, { available: true, workspaces: [], plugins: [], truncated: false });
  const catalog = parseReferenceCatalog(await deps.list(parsed.peer, {
    query: parsed.query,
    kind: parsed.kind === "search" ? "all" : parsed.kind,
    limit
  }, signal));
  if (!catalog.available) return { status: "unavailable", peer: parsed.peer };
  const result = resolveCatalogReference(parsed, catalog);
  if (result.status !== "resolved" || result.kind !== "workspace") return result;
  const resolved = await deps.list(parsed.peer, {
    query: result.workspace.id,
    kind: "workspace",
    relative: parsed.relative,
    resolve: true,
    limit: 2
  }, signal);
  signal?.throwIfAborted();
  if (resolved.status !== "resolved" || typeof resolved.path !== "string") {
    return { status: resolved.status === "ambiguous" ? "ambiguous" : "unavailable", peer: parsed.peer };
  }
  return { ...result, path: mountPathFor(parsed.peer, resolved.path, false), fileKind: resolved.kind };
}
function createReferenceTool(deps) {
  return defineTool({
    name: "remote_references",
    description: "\u68C0\u7D22\u6216\u89E3\u6790 @\u4E3B\u673A:\u63D2\u4EF6\u540D\u3001@\u4E3B\u673A:\u5DE5\u4F5C\u533A\u540D/\u5B50\u8DEF\u5F84\uFF0C\u8FD4\u56DE\u5E26\u7C7B\u578B\u7684\u5019\u9009\u4E0E\u7EDD\u5BF9\u8FDC\u7A0B\u8DEF\u5F84\uFF1B\u91CD\u540D\u8FD4\u56DE\u6B67\u4E49\uFF0C\u4E0D\u521B\u5EFA\u4F1A\u8BDD\u3001\u4E0D\u8BFB\u6587\u4EF6\u5185\u5BB9\u3002",
    parameters: {
      query: { type: "string", required: true, description: "\u5B8C\u6574\u5F15\u7528\uFF08\u53EF\u5E26 @\uFF09\uFF0C\u6216\u914D\u5408 peer \u4F7F\u7528\u7684\u8D44\u6E90\u540D\u3002\u7C7B\u578B\u91CD\u540D\u65F6\u53EF\u5199 \u4E3B\u673A:workspace:ID \u6216 \u4E3B\u673A:plugin:\u5305\u540D\u3002" },
      peer: { type: "string", description: "\u68C0\u7D22\u7684\u5DF2\u914D\u7F6E\u4E3B\u673A\u540D\uFF1Bquery \u5DF2\u542B\u4E3B\u673A\u65F6\u53EF\u7701\u7565\u3002" },
      kind: { type: "string", enum: ["all", "workspace", "plugin"], description: "\u53EA\u68C0\u7D22\u8BE5\u7C7B\u578B\uFF1B\u9ED8\u8BA4 all\u3002" },
      limit: { type: "number", description: "\u6BCF\u7C7B\u5019\u9009\u4E0A\u9650\uFF0C1\u2013200\uFF0C\u9ED8\u8BA4 40\u3002" }
    },
    output: { schema: { type: "json" }, render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }] },
    async execute(args, exec) {
      if (args.query.length > 2048 || /[\u0000-\u001f\u007f]/u.test(args.query)) throw new Error("Reference query exceeds its safe length or contains control characters");
      let raw = args.query;
      if (raw.startsWith('@"') && raw.endsWith('"')) raw = raw.slice(2, -1);
      else if (raw.startsWith("@") && parseHostReference(raw.slice(1), deps.peers()) !== void 0) raw = raw.slice(1);
      const existing = parseHostReference(raw, deps.peers());
      if (existing !== void 0 && args.peer !== void 0 && args.peer !== existing.peer) throw new Error("The query host and peer parameter disagree");
      const query = existing !== void 0 || args.peer === void 0 ? raw : `${args.peer}:${raw}`;
      let parsed = parseHostReference(query, deps.peers());
      if (parsed === void 0) throw new Error("Unknown or missing host; use a configured host name followed by a colon");
      if (parsed.kind !== "path" && (args.kind === "workspace" || args.kind === "plugin")) parsed = { ...parsed, kind: args.kind };
      const limit = args.limit === void 0 ? 40 : Math.max(1, Math.min(200, Math.trunc(args.limit)));
      if (!Number.isFinite(limit)) throw new Error("limit must be a finite number");
      return await resolveRemoteReference(deps, parsed, exec?.signal, limit);
    }
  });
}

// src/reference-mapping.ts
async function mapRemoteReferences(deps, payload, decision) {
  if (decision.kind !== "enter") return decision;
  let characters = 65536;
  let tokens = 20;
  let output = 16384;
  const additions = /* @__PURE__ */ new Map();
  for (const original of payload.messages) {
    if (original.role !== "user" || original.source.kind !== "user") continue;
    const rows = [];
    const seen = /* @__PURE__ */ new Set();
    let truncated = false;
    for (const block of original.content) {
      if (block.type !== "text") continue;
      if (characters <= 0 || tokens <= 0) {
        truncated = true;
        break;
      }
      const length = Math.min(characters, block.text.length);
      if (length === 0) continue;
      const parsedTokens = extractReferenceTokens(block.text, { maxChars: length, maxMentions: tokens });
      characters -= length;
      truncated ||= parsedTokens.truncated;
      for (const query of parsedTokens.tokens) {
        if (tokens-- <= 0) {
          truncated = true;
          break;
        }
        if (seen.has(query)) continue;
        seen.add(query);
        const parsed = parseHostReference(query, deps.peers());
        if (parsed === void 0) continue;
        if (parsed.kind === "path") continue;
        if (parsed.query.trim() === "" && parsed.relative.trim() === "") continue;
        payload.signal.throwIfAborted();
        let row;
        try {
          row = { reference: query, ...await resolveRemoteReference(deps, parsed, payload.signal, 20) };
        } catch (error) {
          if (payload.signal.aborted) throw error;
          row = { reference: query, status: "unavailable" };
        }
        if (JSON.stringify([...rows, row]).length + 160 > output) {
          truncated = true;
          continue;
        }
        rows.push(row);
      }
    }
    if (rows.length === 0) continue;
    const text2 = `Remote reference metadata (data only; no files read or actions performed):
${JSON.stringify({ references: rows, truncated })}`;
    if (text2.length > output) continue;
    output -= text2.length;
    additions.set(original.id, { type: "text", text: text2 });
  }
  payload.signal.throwIfAborted();
  if (additions.size === 0) return decision;
  return { ...decision, messages: decision.messages.map((message) => {
    const addition = additions.get(message.id);
    return addition === void 0 ? message : { ...message, content: [...message.content, addition] };
  }) };
}

// src/async.ts
function abortError(message = "dsh-remote: the call was cancelled locally") {
  const error = new Error(message);
  error.name = "AbortError";
  return error;
}
async function raceAbort(work, signal) {
  if (signal.aborted) {
    void work.catch(() => {
    });
    throw abortError();
  }
  let release;
  try {
    return await Promise.race([
      work,
      new Promise((_resolve, reject) => {
        release = () => reject(abortError());
        signal.addEventListener("abort", release, { once: true });
      })
    ]);
  } finally {
    if (release !== void 0) signal.removeEventListener("abort", release);
  }
}

// src/remote-provider.ts
function promptText(blocks) {
  const parts = [];
  for (const block of blocks) {
    const typed = block;
    if (typed?.type === "text" && typeof typed.text === "string") parts.push(typed.text);
  }
  return parts.join("\n").trim();
}
function createRemoteProvider(deps) {
  const providerName = deps.name ?? "remote";
  return {
    name: providerName,
    capabilities: deps.kit.NO_START_CAPABILITIES,
    // The peer has its own context: it does not see this chat's history.
    inheritsParentContext: false,
    async start(request) {
      const parentSessionId = String(request.parent.session.id);
      const sessionId = deps.sessionFor(parentSessionId);
      const text2 = promptText(request.prompt);
      let output = [];
      let diagnostic;
      let cancelled = false;
      let stopRequest;
      let stopNeeded = false;
      let settled = false;
      const askPeerToStop = () => {
        stopRequest ??= Promise.resolve().then(() => deps.interrupt(sessionId)).catch((error) => {
          deps.log(`${providerName}: could not interrupt ${sessionId} on the peer (${String(error)})`);
        });
        return stopRequest;
      };
      const local = new AbortController();
      const onAbort = () => {
        cancelled = true;
        stopNeeded = true;
        local.abort();
        void askPeerToStop();
      };
      request.signal.addEventListener("abort", onAbort, { once: true });
      if (request.signal.aborted) onAbort();
      const result = deps.kit.settleRunResult({
        signal: request.signal,
        onAbort,
        cancelled: () => cancelled,
        collectOutput: () => output,
        collectDiagnostic: () => diagnostic,
        onError: (error) => {
          diagnostic = `${providerName}: ${error.message}`;
        },
        attempt: async () => {
          let outcome;
          try {
            outcome = await raceAbort(
              deps.prompt({ sessionId, text: text2, signal: local.signal }),
              local.signal
            );
          } catch (error) {
            stopNeeded = true;
            throw error;
          }
          if (outcome.interrupted === true) {
            stopNeeded = false;
            settled = true;
            return {
              output: [],
              stopReason: "aborted",
              ...outcome.replies === void 0 ? {} : { replies: outcome.replies },
              ...outcome.replyFormat === void 0 ? {} : { replyFormat: outcome.replyFormat }
            };
          }
          output = outcome.replies === void 0 ? outcome.reply === "" ? [] : [{ type: "text", text: outcome.reply }] : outcome.replies.flatMap((reply) => reply.content.map((block) => block.type === "text" ? block : { type: "text", text: `[remote ${block.type}: ${JSON.stringify(block.attachment)}; session ${reply.sessionId}]` }));
          const messages = {
            ...outcome.replies === void 0 ? {} : { replies: outcome.replies },
            ...outcome.replyFormat === void 0 ? {} : { replyFormat: outcome.replyFormat }
          };
          if (outcome.reason === "error" || outcome.reason === "blocked") {
            stopNeeded = true;
            settled = true;
            diagnostic = `${providerName}: the peer's turn ended with reason "${String(outcome.reason)}"`;
            return { output, diagnostic, stopReason: "error", ...messages };
          }
          stopNeeded = false;
          settled = true;
          return { output, stopReason: "completed", ...messages };
        }
      });
      return deps.kit.subprocessRunHandle({
        id: sessionId,
        result,
        signal: request.signal,
        onAbort,
        // Local cancellation: settle the run now; the peer is stopped by
        // teardown, which the seam always awaits. Only a dispose that arrives
        // BEFORE the attempt settled means "cancel the work".
        requestCancel: () => {
          if (!settled) stopNeeded = true;
          cancelled = true;
          local.abort();
        },
        teardown: async () => {
          if (stopNeeded) await askPeerToStop();
        }
      });
    }
  };
}

// src/reply-codec.ts
var record = (value) => value !== null && typeof value === "object" && !Array.isArray(value) ? value : void 0;
var natural = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
var nonempty = (value) => typeof value === "string" && value !== "";
function publicContent(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const raw of value) {
    const block = record(raw);
    if (block?.type === "text" && typeof block.text === "string") {
      if (block.text !== "") out.push({ type: "text", text: block.text });
      continue;
    }
    const ref = record(block?.attachment);
    if (ref === void 0 || !nonempty(ref.attachmentId) || !natural(ref.bytes)) continue;
    if (block?.type === "file" && typeof ref.name === "string") {
      out.push({ type: "file", attachment: { attachmentId: ref.attachmentId, name: ref.name, bytes: ref.bytes } });
    } else if (block?.type === "image" && ["image/png", "image/jpeg", "image/webp", "image/gif"].includes(String(ref.mediaType)) && natural(ref.width) && ref.width > 0 && natural(ref.height) && ref.height > 0) {
      const original = record(ref.originalDimensions);
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
  const data = record(event.data);
  const message = record(data?.message);
  const source = record(message?.source);
  if (data?.interrupted === true || message?.role !== "assistant" || !nonempty(message.id) || source?.kind !== "model" || !nonempty(source.provider) || !nonempty(source.model) || !natural(data?.turn) || !natural(data?.step)) return void 0;
  const content = publicContent(message.content);
  if (content.length === 0) return void 0;
  const usage = record(data.usage);
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
function replyFields(value) {
  const envelope = record(value);
  if (!Array.isArray(envelope?.replies)) return { replyFormat: "legacy-text" };
  if (envelope.replyFormat !== "committed-assistant-v1") return { replyFormat: "invalid-replies" };
  const replies = [];
  let previous = -1;
  const ids = /* @__PURE__ */ new Set();
  for (const raw of envelope.replies) {
    const row = record(raw);
    if (row?.version !== 1 || !nonempty(row.sessionId) || !natural(row.seq) || row.seq <= previous || typeof envelope.sessionId === "string" && row.sessionId !== envelope.sessionId || !nonempty(row.messageId) || ids.has(`${row.sessionId}\0${row.messageId}`)) return { replyFormat: "invalid-replies" };
    const reply = replyOf({ type: "assistant/message", seq: row.seq, time: row.time, data: {
      turn: row.turn,
      step: row.step,
      message: { id: row.messageId, role: "assistant", source: row.source, content: row.content },
      usage: row.usage
    } }, row.sessionId);
    if (reply === void 0) return { replyFormat: "invalid-replies" };
    previous = reply.seq;
    ids.add(`${reply.sessionId}\0${reply.messageId}`);
    replies.push(reply);
  }
  return { replies, replyFormat: "committed-assistant-v1" };
}
function replyFrame(value, sessionId) {
  return replyFields({ sessionId, replyFormat: "committed-assistant-v1", replies: [value] }).replies?.[0];
}
function mergeReplyFrames(value, frames) {
  if (frames.length === 0) return value;
  const fields = replyFields(value);
  if (fields.replyFormat !== "committed-assistant-v1" || fields.replies === void 0) return value;
  const merged = /* @__PURE__ */ new Map();
  for (const reply of fields.replies) merged.set(`${reply.sessionId}\0${reply.messageId}`, reply);
  for (const reply of frames) {
    const key = `${reply.sessionId}\0${reply.messageId}`;
    if (!merged.has(key)) merged.set(key, reply);
  }
  const replies = [...merged.values()].sort((left, right) => left.seq - right.seq);
  if (replies.length === fields.replies.length) return value;
  return {
    ...value,
    replies,
    reply: replies.map((reply) => reply.text).filter(Boolean).join("\n\n")
  };
}
function renderRemoteReplies(value) {
  const envelope = record(value);
  const fields = replyFields(value);
  if (fields.replies === void 0) {
    const legacy = typeof envelope?.reply === "string" && envelope.reply !== "" ? envelope.reply : "(empty reply)";
    return `--- ${fields.replyFormat === "legacy-text" ? "legacy reply (message boundaries unavailable)" : "invalid reply metadata; legacy text only"} ---
${legacy}`;
  }
  const replies = fields.replies;
  if (replies.length === 0) return "--- committed remote replies: 0 ---";
  return replies.map((reply, index) => {
    const lines = [
      `--- remote reply ${index + 1}/${replies.length} [assistant \xB7 ${reply.provider}/${reply.model}] ---`,
      `session: ${reply.sessionId}  messageId: ${reply.messageId}  seq: ${reply.seq}  turn: ${reply.turn}  step: ${reply.step}  time: ${reply.time}`
    ];
    for (const block of reply.content) {
      if (block.type === "text") lines.push(block.text);
      else lines.push(`[remote ${block.type}: ${JSON.stringify(block.attachment)}; attachment belongs to remote session]`);
    }
    return lines.join("\n");
  }).join("\n\n");
}

// src/remote-inbound.ts
import { createHash as createHash3 } from "node:crypto";
var INBOUND_TRANSPORT_ID = "dsh-remote-inbound";
var errorCode = (error) => {
  const code = error?.code;
  return typeof code === "string" ? code : "";
};
var errorMessage = (error) => error instanceof Error ? error.message : String(error);
var bounded = (raw) => raw.length <= 512 ? raw : `dsh-remote:${createHash3("sha256").update(raw).digest("hex").slice(0, 64)}`;
function inboundBindingId(peer, localSession) {
  return `dsh-remote-inbound-${createHash3("sha256").update(JSON.stringify([peer, localSession])).digest("hex").slice(0, 40)}`;
}
function inboundExternalId(peer, remoteSession, messageId) {
  return bounded(`dsh-remote:${JSON.stringify([peer, remoteSession, messageId])}`);
}
function inboundSenderId(peer, reply) {
  return bounded(`dsh-remote:${peer}:${reply.provider}/${reply.model}`);
}
function inboundText(reply) {
  return reply.content.map((block) => block.type === "text" ? block.text : `
[remote ${block.type}: ${block.attachment.name ?? block.type} \xB7 ${block.attachment.attachmentId}]
`).join("");
}
function inboundReplySource(actor, reply) {
  const { provider, model, sessionId, messageId, seq, turn, step } = reply;
  return { actor, provider, model, sessionId, messageId, seq, turn, step };
}
var RETRYABLE_INBOUND_CODES = /* @__PURE__ */ new Set(["DISABLED", "BINDING_NOT_FOUND", "INVALID_CONTENT", "CONTENT_TOO_LARGE", "INVALID_INPUT"]);
function createInboundIoAdapter(ctx, hooks) {
  let closed = false;
  let service;
  const bindings = /* @__PURE__ */ new Map();
  const initialized = /* @__PURE__ */ new Set();
  const resolve2 = () => {
    if (closed || !hooks.enabled()) return void 0;
    let candidate;
    try {
      candidate = ctx.get("superAgentIo");
    } catch {
      return void 0;
    }
    if (candidate == null || candidate.contractVersion !== 1 || typeof candidate.putBinding !== "function" || typeof candidate.receive !== "function") return void 0;
    return candidate;
  };
  const sync = () => {
    const current = resolve2();
    if (current !== service) initialized.clear();
    service = current;
    return current;
  };
  const keyOf = (peer, localSession) => `${peer}\0${localSession}`;
  const ensureBinding = async (peer, localSession, remoteSession) => {
    const io = sync();
    if (io === void 0) return void 0;
    const bindingId = inboundBindingId(peer, localSession);
    const key = keyOf(peer, localSession);
    let binding = bindings.get(key);
    if (binding === void 0 || binding.bindingId !== bindingId) {
      binding = { bindingId, peer, localSession, remoteSession };
      bindings.set(key, binding);
    }
    if (initialized.has(bindingId)) return binding;
    try {
      await io.putBinding({
        id: bindingId,
        transport: INBOUND_TRANSPORT_ID,
        endpoint: `dsh-remote-inbound:${peer}`,
        sessionId: localSession,
        label: `dsh-remote inbound ${peer} ${remoteSession}`.slice(0, 160),
        enabled: true,
        // This is an INBOUND-only binding: local assistant output must never be
        // routed back to the remote peer automatically.
        sendEnabled: false,
        receiveOnly: true,
        preload: false,
        mode: "queue",
        routing: "exclusive-turn"
      });
      if (closed) {
        if (bindings.get(key) === binding) bindings.delete(key);
        return void 0;
      }
      initialized.add(bindingId);
      return binding;
    } catch (error) {
      if (bindings.get(key) === binding) bindings.delete(key);
      hooks.log(`dsh-remote-client: inbound IO binding unavailable (${errorMessage(error)})`, "warn");
      return void 0;
    }
  };
  const receive = async (binding, request) => {
    const io = sync();
    if (io === void 0) return { kind: "unavailable", reason: "super-agent-io service is unavailable" };
    if (request.text.trim() === "") return { kind: "unavailable", reason: "empty inbound text" };
    const input = {
      bindingId: binding.bindingId,
      externalMessageId: request.externalMessageId,
      content: [{ type: "text", text: request.text }],
      mode: "queue",
      senderId: request.senderId,
      replySource: request.replySource
    };
    try {
      const receipt = await io.receive(input);
      if (receipt.state === "accepted") return { kind: "accepted", receipt };
      if (receipt.state === "failed") return { kind: "unavailable", reason: receipt.reason ?? "inbound admission failed before send" };
      return { kind: "unknown", reason: receipt.reason ?? `inbound admission ended as ${receipt.state}` };
    } catch (error) {
      const code = errorCode(error);
      if (code === "BINDING_NOT_FOUND") {
        initialized.delete(binding.bindingId);
        const refreshed = await ensureBinding(binding.peer, binding.localSession, binding.remoteSession);
        const retryIo = refreshed === void 0 ? void 0 : sync();
        if (retryIo !== void 0) {
          try {
            const receipt = await retryIo.receive(input);
            if (receipt.state === "accepted") return { kind: "accepted", receipt };
            if (receipt.state === "failed") return { kind: "unavailable", reason: receipt.reason ?? "inbound admission failed before send" };
            return { kind: "unknown", reason: receipt.reason ?? `inbound admission ended as ${receipt.state}` };
          } catch (retryError) {
            return RETRYABLE_INBOUND_CODES.has(errorCode(retryError)) ? { kind: "unavailable", reason: errorMessage(retryError) } : { kind: "unknown", reason: errorMessage(retryError) };
          }
        }
      }
      return RETRYABLE_INBOUND_CODES.has(code) ? { kind: "unavailable", reason: errorMessage(error) } : { kind: "unknown", reason: errorMessage(error) };
    }
  };
  return {
    ensureBinding,
    receive,
    dispose: () => {
      closed = true;
      service = void 0;
      bindings.clear();
      initialized.clear();
    }
  };
}

// src/exec-client.ts
async function runCancellableExec(options) {
  const pending = options.send({ ...options.args, execId: options.execId }, options.timeoutMs);
  if (options.signal === void 0) return await pending;
  try {
    return await raceAbort(pending, options.signal);
  } catch (error) {
    if (error.name === "AbortError") options.cancelRemote(options.execId);
    throw error;
  }
}

// src/subagent-tool.ts
import { defineTool as defineTool2 } from "@deepseek-ai/dsh-tools";
function resultText(output) {
  const parts = [];
  for (const block of output) {
    const typed = block;
    if (typed?.type === "text" && typeof typed.text === "string") parts.push(typed.text);
  }
  return parts.join("\n").trim();
}
var REMOTE_SUBAGENT_TOOL = "subagent_remote";
function createRemoteSubagentTool(subagents, providerName = "remote") {
  return defineTool2({
    name: REMOTE_SUBAGENT_TOOL,
    description: "\u628A\u4E00\u4E2A\u5B50\u4EFB\u52A1**\u59D4\u6D3E\u7ED9\u5BF9\u7AEF harness** \u6267\u884C\u2014\u2014\u8FDC\u7AEF\u5BF9\u8BDD\u5728\u672C\u673A\u5C31\u662F\u4E00\u4E2A subagent / task\uFF1A\u4F60\u6D3E\u6D3B\u3001\u5B83\u4EA4\u4ED8\uFF0C\u6700\u540E\u628A\u7ED3\u8BBA\u5E26\u56DE\u672C\u673A\u4E0A\u4E0B\u6587\u3002\n\u4F1A\u8BDD\u89C4\u5219\uFF08\u4E25\u683C\uFF09\uFF1A**\u540C\u4E00\u4E2A\u672C\u673A chat \u6C38\u8FDC\u590D\u7528\u540C\u4E00\u6BB5\u8FDC\u7AEF\u5BF9\u8BDD**\uFF08\u63D2\u4EF6\u6309\u672C\u673A\u4F1A\u8BDD\u63A8\u5BFC id\uFF09\uFF0C\u6240\u4EE5\u8FDE\u7EED\u59D4\u6D3E\u662F\u63A5\u7740\u540C\u4E00\u4E2A\u4E0A\u4E0B\u6587\uFF0C\u4E0D\u4F1A\u6BCF\u6B21\u65B0\u5F00\u3002\n\u672C\u673A\u4F18\u5148\uFF1A\u80FD\u5728\u672C\u673A\u4E0A\u4E0B\u6587\u91CC\u5B8C\u6210\u7684\u4E8B\u4E0D\u8981\u59D4\u6D3E\uFF1B\u59D4\u6D3E\u65F6\u5199\u6E05\u76EE\u6807\u3001\u8FB9\u754C\u548C\u4EA4\u4ED8\u7269\u3002\n\u6253\u65AD\uFF1A\u672C\u673A\u7528\u6237\u4E2D\u65AD\u4F1A\u540C\u65F6\u4E2D\u65AD\u5BF9\u7AEF\u90A3\u4E00\u8F6E\uFF1B\u82E5\u8FD4\u56DE\u91CC\u5E26 interrupted \u6807\u8BB0\uFF0C\u7ACB\u523B\u505C\u4E0B\u3001\u4E0D\u8981\u91CD\u8BD5\uFF0C\u628A\u51B3\u5B9A\u6743\u4EA4\u56DE\u7528\u6237\u3002",
    parameters: {
      description: { type: "string", required: true, description: "\u8FD9\u6B21\u59D4\u6D3E\u7684\u7B80\u77ED\u6807\u9898\uFF083-5 \u4E2A\u8BCD\uFF09\u3002" },
      prompt: { type: "string", required: true, description: "\u4EA4\u7ED9\u5BF9\u7AEF agent \u7684\u5B8C\u6574\u4EFB\u52A1\u63CF\u8FF0\u3002" }
    },
    output: {
      schema: { type: "json" },
      render: (_args, value) => {
        const v = value;
        const head = [
          `session: ${v.sessionId ?? "?"}`,
          `stop   : ${v.stopReason ?? "?"}${v.interrupted === true ? "  (interrupted)" : ""}`
        ];
        if (v.diagnostic !== void 0 && v.diagnostic !== null && v.diagnostic !== "") {
          head.push(`error  : ${v.diagnostic}`);
        }
        if (v.interrupted === true) {
          head.push("\u26A0\uFE0F \u8FDC\u7AEF\u8FD9\u4E00\u8F6E\u88AB\u4E2D\u65AD\uFF0C\u6CA1\u6709\u53EF\u7528\u7684\u4EA4\u4ED8\u3002\u7ACB\u523B\u505C\u6B62\uFF0C\u7B49\u7528\u6237\u7684\u65B0\u6307\u793A\u3002");
        }
        head.push("--- deliverable ---");
        return [{ type: "text", text: [...head, renderRemoteReplies(value)].join("\n") }];
      }
    },
    async execute(args, exec) {
      const parent = exec?.agent;
      if (parent === void 0) {
        throw new Error(`${REMOTE_SUBAGENT_TOOL}: no calling agent, so there is nobody to delegate from`);
      }
      const run = await subagents.start(providerName, {
        label: args.description,
        prompt: [{ type: "text", text: args.prompt }],
        parent,
        signal: exec.signal ?? new AbortController().signal
      });
      try {
        const result = await run.result;
        return {
          sessionId: run.id,
          stopReason: result.stopReason,
          interrupted: result.stopReason === "aborted",
          diagnostic: result.diagnostic ?? null,
          reply: resultText(result.output),
          ...result.replies === void 0 ? {} : { replies: result.replies },
          ...result.replyFormat === void 0 ? {} : { replyFormat: result.replyFormat }
        };
      } finally {
        await run.dispose();
      }
    }
  });
}

// src/remote-runs.ts
import { randomUUID } from "node:crypto";
import { defineTool as defineTool3 } from "@deepseek-ai/dsh-tools";

// src/agent-delivery.ts
function inputMode(value) {
  if (value === void 0 || value === "auto") return "auto";
  if (value === "queue" || value === "steer") return value;
  throw new Error("agent.note: mode must be queue, steer or auto");
}

// src/remote-runs.ts
var DEFAULT_MAX_SETTLED = 32;
var DEFAULT_SETTLED_TTL_MS = 24 * 60 * 60 * 1e3;
var MAX_STATUS_WAIT_MS = 6e5;
function isActive(record2) {
  return record2.status === "running" || record2.status === "cancelling";
}
function previewOf(value, limit) {
  const flat = value.replace(/\s+/gu, " ").trim();
  if (flat.length <= limit) return flat;
  return `${flat.slice(0, Math.max(0, limit - 1))}\u2026`;
}
function snapshotOf(record2) {
  return { ...record2, ...record2.replies === void 0 ? {} : { replies: structuredClone(record2.replies) } };
}
function toRunRow(record2, previewLimit = 160) {
  const row = {
    runId: record2.id,
    sessionId: record2.sessionId,
    status: record2.status,
    description: record2.description,
    startedAt: record2.startedAt
  };
  if (record2.settledAt !== void 0) row.settledAt = record2.settledAt;
  if (record2.reply !== void 0 && record2.reply !== "") {
    row.replyPreview = previewOf(record2.reply, previewLimit);
  } else if (record2.diagnostic !== void 0 && record2.diagnostic !== "") {
    row.replyPreview = previewOf(record2.diagnostic, previewLimit);
  }
  return row;
}
function clampStatusWait(waitMs) {
  if (waitMs === void 0 || !Number.isFinite(waitMs) || waitMs <= 0) return 0;
  return Math.min(MAX_STATUS_WAIT_MS, Math.floor(waitMs));
}
function createRunRegistry(options) {
  const now = options.now ?? (() => Date.now());
  const maxSettled = Math.max(1, Math.floor(options.maxSettled ?? DEFAULT_MAX_SETTLED));
  const settledTtlMs = Math.max(0, Math.floor(options.settledTtlMs ?? DEFAULT_SETTLED_TTL_MS));
  const makeRunId = options.makeRunId ?? (() => `run-${randomUUID()}`);
  const records = /* @__PURE__ */ new Map();
  const waiters = /* @__PURE__ */ new Map();
  const prune = (at) => {
    let dropped = 0;
    const settled = [];
    for (const record2 of records.values()) {
      if (isActive(record2)) continue;
      if (record2.settledAt !== void 0 && at - record2.settledAt > settledTtlMs) {
        records.delete(record2.id);
        dropped += 1;
        continue;
      }
      settled.push(record2);
    }
    settled.sort((left, right) => (left.settledAt ?? left.startedAt) - (right.settledAt ?? right.startedAt));
    while (settled.length > maxSettled) {
      const oldest = settled.shift();
      if (oldest === void 0) break;
      records.delete(oldest.id);
      dropped += 1;
    }
    return dropped;
  };
  const wake = (id) => {
    const parked = waiters.get(id);
    if (parked === void 0) return;
    const record2 = records.get(id);
    waiters.delete(id);
    if (record2 === void 0) return;
    for (const resolve2 of [...parked]) resolve2(snapshotOf(record2));
  };
  const get = (id) => {
    prune(now());
    const record2 = records.get(id);
    return record2 === void 0 ? void 0 : snapshotOf(record2);
  };
  const list = () => {
    prune(now());
    const active = [];
    const settled = [];
    for (const record2 of records.values()) {
      if (isActive(record2)) active.push(record2);
      else settled.push(record2);
    }
    active.sort((left, right) => right.startedAt - left.startedAt);
    settled.sort((left, right) => (right.settledAt ?? right.startedAt) - (left.settledAt ?? left.startedAt));
    return [...active, ...settled].map(snapshotOf);
  };
  const activeCount = () => {
    let count = 0;
    for (const record2 of records.values()) if (isActive(record2)) count += 1;
    return count;
  };
  const start = (input) => {
    const at = now();
    prune(at);
    const ceiling = Math.max(1, Math.floor(options.maxRuns()));
    const active = activeCount();
    if (active >= ceiling) {
      throw new Error(
        `remote_run_start: \u5DF2\u6709 ${active} \u4E2A\u540E\u53F0\u8FDC\u7AEF\u8FD0\u884C\uFF08\u4E0A\u9650 ${ceiling}\uFF09\uFF0C\u5148 remote_run_status \u6536\u4E00\u4E2A\uFF0C\u6216\u8C03\u5927 maxBackgroundRuns\u3002`
      );
    }
    const sessionId = input.sessionId.trim();
    if (sessionId === "") throw new Error("remote_run_start: sessionId must not be empty");
    if (input.description.trim() === "") throw new Error("remote_run_start: description must not be empty");
    const record2 = {
      id: makeRunId(),
      sessionId,
      description: input.description.trim(),
      textPreview: previewOf(input.text, 120),
      status: "running",
      startedAt: at
    };
    records.set(record2.id, record2);
    return snapshotOf(record2);
  };
  const settle = (id, outcome) => {
    const record2 = records.get(id);
    if (record2 === void 0 || !isActive(record2)) return void 0;
    const at = now();
    record2.status = outcome.status;
    record2.settledAt = at;
    record2.durationMs = Math.max(0, at - record2.startedAt);
    if (outcome.reply !== void 0) record2.reply = outcome.reply;
    if (outcome.replies !== void 0) record2.replies = structuredClone(outcome.replies);
    if (outcome.replyFormat !== void 0) record2.replyFormat = outcome.replyFormat;
    if (outcome.interrupted !== void 0) record2.interrupted = outcome.interrupted;
    if (outcome.reason !== void 0) record2.reason = outcome.reason;
    if (outcome.diagnostic !== void 0) record2.diagnostic = outcome.diagnostic;
    options.log?.(
      `dsh-remote-client: background run ${id} ${record2.status} (session ${record2.sessionId}, ${record2.durationMs} ms)`
    );
    wake(id);
    prune(at);
    return snapshotOf(record2);
  };
  const cancel = (id) => {
    const record2 = records.get(id);
    if (record2 === void 0 || record2.status !== "running") return false;
    record2.status = "cancelling";
    return true;
  };
  const waitFor = (id, waitMs) => {
    const current = get(id);
    if (current === void 0 || !isActive(current) || waitMs <= 0) return Promise.resolve(current);
    return new Promise((resolve2) => {
      let timer;
      const done = (record2) => {
        if (timer !== void 0) clearTimeout(timer);
        const parked2 = waiters.get(id);
        parked2?.delete(done);
        if (parked2 !== void 0 && parked2.size === 0) waiters.delete(id);
        resolve2(record2);
      };
      const parked = waiters.get(id) ?? /* @__PURE__ */ new Set();
      parked.add(done);
      waiters.set(id, parked);
      timer = setTimeout(() => {
        timer = void 0;
        done(get(id) ?? current);
      }, Math.floor(waitMs));
    });
  };
  return {
    start,
    settle,
    get,
    list,
    cancel,
    prune: () => prune(now()),
    waitFor,
    activeCount
  };
}
function renderText(value) {
  return [{ type: "text", text: value }];
}
function clean(value) {
  if (typeof value !== "string") return void 0;
  const trimmed = value.trim();
  return trimmed === "" ? void 0 : trimmed;
}
function runIdOf(args) {
  return clean(args.run_id);
}
function createRunTools(deps) {
  const registry = createRunRegistry({
    maxRuns: deps.maxRuns,
    log: deps.log,
    ...deps.now === void 0 ? {} : { now: deps.now },
    ...deps.makeRunId === void 0 ? {} : { makeRunId: deps.makeRunId }
  });
  const runStart = defineTool3({
    name: "remote_run_start",
    description: "\u5728**\u8FDC\u7AEF harness \u540E\u53F0**\u542F\u52A8\u4E00\u4E2A\u4EFB\u52A1\uFF1A\u7ACB\u5373\u8FD4\u56DE runId\uFF0C\u4E0D\u963B\u585E\u672C\u8F6E\uFF1B\u9002\u5408\u8DD1\u5F97\u4E45\u3001\u6216\u672C\u673A\u4E0D\u9700\u8981\u4E00\u76F4\u7B49\u7740\u7684\u8FDC\u7AEF\u5DE5\u4F5C\u3002\n\u4F1A\u8BDD\u89C4\u5219\u4E0E `remote_agent_prompt` **\u5B8C\u5168\u4E00\u81F4**\uFF1A\u7701\u7565 session_id \u65F6\u7EED\u63A5\u672C chat \u81EA\u5DF1\u90A3\u6BB5\u8FDC\u7AEF\u5BF9\u8BDD\uFF0C\u6240\u4EE5\u4E0D\u8981\u4E3A\u4E86\u300C\u9694\u79BB\u300D\u4F20 session_id\u3002\n\u4E0E `subagent_remote` \u7684\u5206\u5DE5\uFF1A\u8981**\u4EA4\u4ED8\u8FDB\u672C\u5BF9\u8BDD**\u3001\u503C\u5F97\u7B49\u5F85\u7ED3\u679C\u7684\u6574\u5757\u5B50\u4EFB\u52A1\u7528 subagent_remote\uFF1B\u957F\u4EFB\u52A1 / \u60F3\u5E76\u884C\u63A8\u8FDB / \u4E0D\u60F3\u5360\u7528\u672C\u8F6E\u7684\u7528 remote_run_start\u3002\n\u53D6\u7ED3\u679C\u7528 `remote_run_status(run_id=...)`\uFF08\u53EF\u5E26 wait_ms \u7B49\u5F85\uFF09\uFF0C\u8FFD\u52A0\u6307\u793A\u7528 `remote_send_message(run_id=...)`\uFF0C\u6253\u65AD\u7528 `remote_run_cancel(run_id=...)`\u3002",
    parameters: {
      description: { type: "string", required: true, description: "\u8FD9\u6B21\u540E\u53F0\u8FD0\u884C\u7684\u7B80\u77ED\u6807\u9898\uFF083-5 \u4E2A\u8BCD\uFF09\u3002" },
      text: { type: "string", required: true, description: "\u4EA4\u7ED9\u5BF9\u7AEF agent \u7684\u7528\u6237\u53D1\u8A00 / \u4EFB\u52A1\u63CF\u8FF0\u3002" },
      session_id: { type: "string", description: "\u5BF9\u7AEF\u4F1A\u8BDD id\u3002\u4E00\u822C**\u4E0D\u8981\u4F20**\uFF1A\u7701\u7565\u5373\u590D\u7528\u672C chat \u81EA\u5DF1\u90A3\u4E00\u4E2A\u5BF9\u8BDD\u3002" },
      timeout_ms: { type: "number", description: "\u5BF9\u7AEF\u8FD9\u4E00\u8F6E\u7684\u8D85\u65F6\u6BEB\u79D2\u6570\uFF1B0\uFF08\u9ED8\u8BA4\uFF09= \u4E0D\u9650\u3002" }
    },
    output: {
      schema: { type: "json" },
      render: (_args, value) => {
        const v = value;
        return renderText([
          `\u5DF2\u542F\u52A8\u540E\u53F0\u8FDC\u7AEF\u8FD0\u884C ${v.runId}`,
          `session: ${v.sessionId}${v.origin === void 0 ? "" : `  (${v.origin})`}`,
          "status : running\uFF08\u672C\u8F6E\u4E0D\u5FC5\u7B49\u5B83\uFF09",
          `\u53D6\u7ED3\u679C\uFF1Aremote_run_status(run_id="${v.runId}")`,
          "\u8FFD\u52A0\u6307\u793A\uFF1Aremote_send_message\uFF1B\u6253\u65AD\uFF1Aremote_run_cancel\u3002"
        ].join("\n"));
      }
    },
    async execute(args, exec) {
      const description = clean(args.description);
      if (description === void 0) throw new Error("remote_run_start: description must not be empty");
      if (clean(args.text) === void 0) throw new Error("remote_run_start: text must not be empty");
      const explicit = clean(args.session_id);
      const resolved = await deps.resolveSession(
        explicit === void 0 ? {} : { session_id: explicit },
        exec
      );
      const record2 = registry.start({
        sessionId: resolved.sessionId,
        description,
        text: args.text
      });
      const timeoutMs = typeof args.timeout_ms === "number" && Number.isFinite(args.timeout_ms) && args.timeout_ms > 0 ? Math.floor(args.timeout_ms) : 0;
      try {
        deps.startPrompt({
          runId: record2.id,
          sessionId: record2.sessionId,
          text: args.text,
          timeoutMs,
          ...exec?.signal === void 0 ? {} : { signal: exec.signal },
          onCancelling: () => {
            registry.cancel(record2.id);
          },
          onSettled: (outcome) => {
            registry.settle(record2.id, outcome);
          }
        });
      } catch (error) {
        registry.settle(record2.id, {
          status: "error",
          diagnostic: error instanceof Error ? error.message : String(error)
        });
        throw error;
      }
      deps.rememberScope(exec, record2.sessionId);
      return {
        runId: record2.id,
        sessionId: record2.sessionId,
        origin: resolved.origin,
        status: "running"
      };
    }
  });
  const runStatus = defineTool3({
    name: "remote_run_status",
    description: '\u67E5\u540E\u53F0\u8FDC\u7AEF\u8FD0\u884C\uFF1A\u65E0 run_id \u65F6\u8FD4\u56DE\u6700\u8FD1\u7684\u8FD0\u884C\u5217\u8868\uFF08\u5148 running \u540E\u5DF2\u7ED3\u675F\uFF09\uFF1B\u6709 run_id \u65F6\u8FD4\u56DE\u8BE5\u8FD0\u884C\u7684\u5B8C\u6574\u72B6\u6001\uFF08\u542B reply \u5168\u6587 / \u9519\u8BEF\u4FE1\u606F / interrupted / reason\uFF09\u3002wait_ms>0 \u65F6\u6700\u591A\u7B49\u8FD9\u4E48\u4E45\uFF08\u4E0A\u9650 600000\uFF09\uFF1B\u5230\u70B9\u4ECD\u5728\u8FD0\u884C\u5C31\u8FD4\u56DE status:"running"\uFF0C\u4E0D\u62A5\u9519\u3002**\u7ED3\u679C\u4E0D\u4F1A\u81EA\u52A8\u6CE8\u5165\u672C\u5BF9\u8BDD**\u2014\u2014\u5FC5\u987B\u7531\u4F60\u8C03\u7528\u672C\u5DE5\u5177\u53D6\u56DE\u3002',
    parameters: {
      run_id: { type: "string", description: "remote_run_start \u8FD4\u56DE\u7684 runId\uFF1B\u7701\u7565\u5219\u5217\u51FA\u6700\u8FD1\u8FD0\u884C\u3002" },
      wait_ms: { type: "number", description: "\u6700\u591A\u7B49\u5F85\u591A\u5C11\u6BEB\u79D2\uFF080..600000\uFF09\uFF1B\u4EC5\u5728\u6709 run_id \u65F6\u751F\u6548\u3002" }
    },
    output: {
      schema: { type: "json" },
      render: (_args, value) => {
        const v = value;
        if (Array.isArray(v.runs)) {
          if (v.runs.length === 0) {
            return renderText("\uFF08\u6CA1\u6709\u540E\u53F0\u8FDC\u7AEF\u8FD0\u884C\uFF09\u7528 remote_run_start \u542F\u52A8\u4E00\u4E2A\u3002");
          }
          const lines = [
            `\u540E\u53F0\u8FDC\u7AEF\u8FD0\u884C\uFF1A${v.running ?? 0} \u4E2A\u8FDB\u884C\u4E2D\uFF0C${v.settled ?? 0} \u4E2A\u5DF2\u7ED3\u675F`
          ];
          for (const row of v.runs) {
            const mark = row.status === "running" ? "\u25B6" : row.status === "cancelling" ? "\u23F9" : row.status === "completed" ? "\u2714" : "\u2716";
            const elapsed = row.settledAt === void 0 ? "\uFF08\u8FDB\u884C\u4E2D\uFF09" : `${Math.max(0, row.settledAt - row.startedAt)} ms`;
            lines.push(`${mark} ${row.runId}  [${row.status}]  ${row.sessionId}  ${row.description}  ${elapsed}`);
            if (row.replyPreview !== void 0 && row.replyPreview !== "") lines.push(`    ${row.replyPreview}`);
          }
          lines.push('\u7528 remote_run_status(run_id="...") \u53D6\u5B8C\u6574\u4EA4\u4ED8\uFF1Bremote_run_cancel \u6253\u65AD\uFF1Bremote_send_message \u8FFD\u52A0\u6307\u793A\u3002');
          return renderText(lines.join("\n"));
        }
        const head = [
          `run    : ${v.runId ?? "?"}`,
          `session: ${v.sessionId ?? "?"}`,
          `status : ${v.status ?? "?"}${v.interrupted === true ? "  (interrupted)" : ""}${v.durationMs === void 0 ? "" : `   ${v.durationMs} ms`}`,
          `title  : ${v.description ?? ""}`
        ];
        if (v.reason !== void 0 && v.reason !== null && v.reason !== "") head.push(`reason : ${v.reason}`);
        if (v.diagnostic !== void 0 && v.diagnostic !== "") head.push(`error  : ${v.diagnostic}`);
        if (v.status === "running" || v.status === "cancelling") {
          head.push("\uFF08\u4ECD\u5728\u8FD0\u884C\uFF1B\u53EF\u7528 remote_run_status(run_id, wait_ms) \u7B49\u5F85\uFF0C\u6216 remote_run_cancel \u6253\u65AD\uFF09");
          return renderText(head.join("\n"));
        }
        if (v.interrupted === true) {
          head.push("\u26A0\uFE0F \u8FD9\u4E00\u8F6E\u5728\u8FDC\u7AEF\u88AB\u7528\u6237\u6253\u65AD\uFF0C\u6CA1\u6709\u53EF\u7528\u7684\u4EA4\u4ED8\u3002\u4E0D\u8981\u91CD\u8BD5\u3001\u4E0D\u8981\u81EA\u52A8\u7EE7\u7EED\uFF0C\u628A\u72B6\u6001\u4EA4\u7ED9\u7528\u6237\u3002");
        }
        head.push(renderRemoteReplies(value));
        return renderText(head.join("\n"));
      }
    },
    async execute(args) {
      const runId = runIdOf(args);
      if (runId === void 0) {
        const all = registry.list();
        const running = all.filter((record3) => isActive(record3)).length;
        return {
          runs: all.map((record3) => toRunRow(record3)),
          running,
          settled: all.length - running,
          maxRuns: deps.maxRuns()
        };
      }
      const wait = clampStatusWait(args.wait_ms);
      const record2 = wait > 0 ? await registry.waitFor(runId, wait) : registry.get(runId);
      if (record2 === void 0) {
        throw new Error(
          `remote_run_status: \u6CA1\u6709 id \u4E3A "${runId}" \u7684\u540E\u53F0\u8FDC\u7AEF\u8FD0\u884C\uFF08\u53EF\u80FD\u5DF2\u7ED3\u7B97\u5E76\u88AB\u6E05\u7406\uFF0C\u6216 id \u5199\u9519\u4E86\uFF09\u3002\u4E0D\u5E26 run_id \u53EF\u5217\u51FA\u6700\u8FD1\u7684\u8FD0\u884C\u3002`
        );
      }
      return { ...record2, runId: record2.id };
    }
  });
  const runCancel = defineTool3({
    name: "remote_run_cancel",
    description: "\u6253\u65AD\u4E00\u4E2A\u540E\u53F0\u8FDC\u7AEF\u8FD0\u884C\u5F53\u524D\u6B63\u5728\u8DD1\u7684\u8F6E\u6B21\uFF1A\u5BF9\u5B83\u7684\u8FDC\u7AEF\u4F1A\u8BDD\u8C03 `agent.interrupt`\uFF0C\u628A\u8FD0\u884C\u6807\u8BB0\u4E3A cancelling \u5E76\u7ACB\u5373\u8FD4\u56DE\uFF08\u4E0D\u7B49\u5F85\u7ED3\u7B97\uFF09\u3002\u4E4B\u540E\u7528 remote_run_status \u67E5\u770B\u6700\u7EC8\u72B6\u6001\uFF1B\u5DF2\u7ED3\u675F\u7684\u8FD0\u884C\u4E0D\u4F1A\u88AB\u518D\u6B21\u6253\u65AD\u3002",
    parameters: {
      run_id: { type: "string", required: true, description: "remote_run_start \u8FD4\u56DE\u7684 runId\u3002" }
    },
    output: {
      schema: { type: "json" },
      render: (_args, value) => {
        const v = value;
        if (v.cancelled) {
          return renderText(
            `\u5DF2\u8BF7\u6C42\u53D6\u6D88 ${v.runId}\uFF08session ${v.sessionId ?? "?"}\uFF09\uFF1B\u7528 remote_run_status \u67E5\u770B\u7ED3\u7B97\uFF0C\u4E0D\u8981\u7ACB\u5373\u91CD\u8BD5\u540C\u4E00\u4E2A\u4EFB\u52A1\u3002`
          );
        }
        return renderText(`${v.runId} \u5F53\u524D\u72B6\u6001\u662F ${v.status ?? "?"}\uFF0C\u6CA1\u6709\u9700\u8981\u53D6\u6D88\u7684\u8FD0\u884C\u3002`);
      }
    },
    async execute(args) {
      const runId = runIdOf(args);
      if (runId === void 0) throw new Error("remote_run_cancel: run_id must not be empty");
      const record2 = registry.get(runId);
      if (record2 === void 0) {
        throw new Error(`remote_run_cancel: \u6CA1\u6709 id \u4E3A "${runId}" \u7684\u540E\u53F0\u8FDC\u7AEF\u8FD0\u884C`);
      }
      if (!registry.cancel(runId)) {
        return { cancelled: false, runId, sessionId: record2.sessionId, status: record2.status };
      }
      void deps.interrupt(record2.sessionId).catch((error) => {
        deps.log(
          `dsh-remote-client: could not interrupt ${record2.sessionId} for ${runId} (${error instanceof Error ? error.message : String(error)})`
        );
      });
      return { cancelled: true, runId, sessionId: record2.sessionId, status: "cancelling" };
    }
  });
  const sendMessage = defineTool3({
    name: "remote_send_message",
    description: "\u7ED9**\u6B63\u5728\u8DD1\u7684\u8FDC\u7AEF\u4EFB\u52A1\u8FFD\u52A0\u6307\u793A**\uFF0C\u6216\u7ED9\u7A7A\u95F2\u7684\u8FDC\u7AEF\u4F1A\u8BDD\u53D1\u4E00\u6761\u65B0\u6D88\u606F\uFF1B\u4E0E `remote_agent_prompt` \u7684\u533A\u522B\u662F**\u4E0D\u963B\u585E\u7B49\u4EA4\u4ED8**\uFF1A\u6D88\u606F\u585E\u8FDB\u5BF9\u7AEF\u7684\u6536\u4EF6\u7BB1\u5C31\u8FD4\u56DE\uFF0C\u9ED8\u8BA4\u5728\u5FD9\u65F6\u9001\u5230\u4E0B\u4E00\u6B65\u3001\u95F2\u65F6\u5F00\u59CB\u65B0\u8F6E\uFF1Bmode\u53EF\u663E\u5F0F\u6392\u4E0B\u4E00\u8F6E\u6216steer\u5F53\u524D\u8F6E\u3002\n\u5B9A\u4F4D\u4F1A\u8BDD\u7684\u4F18\u5148\u7EA7\uFF1Arun_id\uFF08\u8BE5\u8FD0\u884C\u6240\u7528\u7684\u8FDC\u7AEF\u4F1A\u8BDD\uFF09\u2192 session_id \u2192 \u672C chat \u81EA\u5DF1\u90A3\u6BB5\u8FDC\u7AEF\u5BF9\u8BDD\u3002\u591A\u6761\u4E0D\u540C\u6307\u793A\u53EF\u4EE5\u8FDE\u7EED\u53D1\uFF0C\u4F46\u524D\u63D0\u662F\u771F\u6709\u5FC5\u8981\uFF1B\u4E0D\u8981\u7528\u5B83\u91CD\u590D `remote_agent_prompt` \u5DF2\u7ECF\u53D1\u8FC7\u7684\u4EFB\u52A1\u3002",
    parameters: {
      message: { type: "string", required: true, description: "\u8981\u8FFD\u52A0\u7ED9\u5BF9\u7AEF agent \u7684\u7528\u6237\u6D88\u606F\u3002" },
      session_id: { type: "string", description: "\u5BF9\u7AEF\u4F1A\u8BDD id\u3002\u7701\u7565\u5219\u7528\u672C chat \u81EA\u5DF1\u7684\u8FDC\u7AEF\u5BF9\u8BDD\u3002" },
      run_id: { type: "string", description: "\u540E\u53F0\u8FD0\u884C\u7684 runId\uFF1B\u7ED9\u4E86\u5C31\u53D1\u7ED9\u8BE5\u8FD0\u884C\u6240\u7528\u7684\u4F1A\u8BDD\u3002" },
      mode: { type: "string", enum: ["queue", "steer", "auto"], description: "auto\uFF08\u9ED8\u8BA4\uFF09\u5FD9\u65F6steer\u3001\u95F2\u65F6queue\uFF1Bqueue\u4E0B\u4E00\u8F6E\uFF0Csteer\u4E0B\u4E00\u5DF2\u51C6\u5165step\u3002\u65E7peer\u4E0D\u652F\u6301\u663E\u5F0Fsteer\u5219\u62D2\u7EDD\u3002" }
    },
    output: {
      schema: { type: "json" },
      render: (_args, value) => {
        const v = value;
        const lines = [
          `\u5DF2\u5411\u8FDC\u7AEF\u4F1A\u8BDD ${v.sessionId} \u8FFD\u52A0\u6D88\u606F\uFF08method: ${v.method ?? "?"}; mode: ${v.mode ?? "?"}; processing: ${v.processing ?? "?"}\uFF09`
        ];
        if (v.note !== void 0 && v.note !== "") lines.push(v.note);
        lines.push("\u7528 remote_run_status / remote_agent_prompt \u67E5\u770B\u5BF9\u7AEF\u5982\u4F55\u6D88\u5316\u8FD9\u6761\u6D88\u606F\u3002");
        return renderText(lines.join("\n"));
      }
    },
    async execute(args, exec) {
      const message = clean(args.message);
      if (message === void 0) throw new Error("remote_send_message: message must not be empty");
      const runId = runIdOf(args);
      let sessionId;
      if (runId !== void 0) {
        const record2 = registry.get(runId);
        if (record2 === void 0) {
          throw new Error(`remote_send_message: \u6CA1\u6709 id \u4E3A "${runId}" \u7684\u540E\u53F0\u8FDC\u7AEF\u8FD0\u884C`);
        }
        sessionId = record2.sessionId;
      } else {
        const explicit = clean(args.session_id);
        const resolved = await deps.resolveSession(
          explicit === void 0 ? {} : { session_id: explicit },
          exec
        );
        sessionId = resolved.sessionId;
      }
      deps.rememberScope(exec, sessionId);
      const result = await deps.sendMessage({
        sessionId,
        text: message,
        mode: inputMode(args.mode),
        ...exec?.signal === void 0 ? {} : { signal: exec.signal }
      });
      return {
        sessionId,
        accepted: result.accepted !== false,
        ...result.method === void 0 ? {} : { method: result.method },
        ...result.mode === void 0 ? {} : { mode: result.mode },
        ...result.processing === void 0 ? {} : { processing: result.processing },
        ...result.note === void 0 ? {} : { note: result.note },
        ...runId === void 0 ? {} : { runId }
      };
    }
  });
  return [runStart, runStatus, runCancel, sendMessage];
}

// src/remote-pool.ts
import { defineTool as defineTool4 } from "@deepseek-ai/dsh-tools";

// src/reuse.ts
import { createHash as createHash4 } from "node:crypto";
import { mkdirSync as mkdirSync2, readFileSync, writeFileSync as writeFileSync2 } from "node:fs";
import { dirname as dirname2 } from "node:path";
function normalizePath(value) {
  return value.replace(/\\/gu, "/").replace(/\/+$/u, "").toLowerCase();
}
function familyMatches(prefix, sessionId) {
  const family = prefix.trim();
  if (family === "") return true;
  return sessionId === family || sessionId.startsWith(`${family}-`);
}
function scopeKey(scope) {
  return JSON.stringify([scope.prefix.trim(), scope.localSession ?? ""]);
}
function anchorSessionId(prefix, localSession) {
  const family = prefix.trim() === "" ? "remote" : prefix.trim();
  const local = typeof localSession === "string" ? localSession.trim() : "";
  if (local === "") return family;
  const digest = createHash4("sha256").update(local, "utf8").digest("hex").slice(0, 12);
  return `${family}-${digest}`;
}
function freshSessionId(prefix, now = Date.now()) {
  const family = prefix.trim() === "" ? "remote" : prefix.trim();
  return `${family}-${now.toString(36)}`;
}
function pickReusableSession(candidates, options) {
  const wanted = options.workspace === void 0 || options.workspace.trim() === "" ? void 0 : normalizePath(options.workspace);
  for (const candidate of candidates) {
    const sessionId = typeof candidate?.sessionId === "string" ? candidate.sessionId : "";
    if (sessionId === "") continue;
    if (options.skip?.has(sessionId) === true) continue;
    if (!familyMatches(options.prefix, sessionId)) continue;
    if (wanted !== void 0 && candidate.cwd !== void 0 && normalizePath(candidate.cwd) !== wanted) continue;
    return { ...candidate, sessionId };
  }
  return void 0;
}
var SessionMemory = class {
  entries = /* @__PURE__ */ new Map();
  file;
  limit;
  /**
   * @param file - JSON file to persist under; the caller owns the location.
   * @param limit - most recent scopes kept; older ones are pruned on write.
   */
  constructor(file, limit = 200) {
    this.file = file;
    this.limit = limit;
  }
  /** Read the file, tolerating every failure. */
  load() {
    try {
      const parsed = JSON.parse(readFileSync(this.file, "utf8"));
      for (const [key, value] of Object.entries(parsed.sessions ?? {})) {
        if (typeof value === "string" && value !== "") this.entries.set(key, value);
      }
    } catch {
    }
  }
  /**
   * The session this scope used last.
   * @param key - a {@link scopeKey}.
   * @returns the session id, or undefined.
   */
  get(key) {
    return this.entries.get(key);
  }
  /**
   * Record the session a scope is using now and persist.
   * @param key - a {@link scopeKey}.
   * @param sessionId - the id to remember.
   */
  set(key, sessionId) {
    if (key === "" || sessionId === "") return;
    if (this.entries.get(key) === sessionId) return;
    this.entries.delete(key);
    this.entries.set(key, sessionId);
    while (this.entries.size > this.limit) {
      const oldest = this.entries.keys().next();
      if (oldest.done === true) break;
      this.entries.delete(oldest.value);
    }
    this.save();
  }
  /** Number of remembered scopes (for logs and tests). */
  get size() {
    return this.entries.size;
  }
  /**
   * Every session id any scope currently remembers.
   *
   * Lets a caller keep two scopes apart: an existing conversation already
   * claimed by another scope is not adopted a second time.
   * @returns a fresh set.
   */
  inUse() {
    return new Set(this.entries.values());
  }
  /**
   * The most recently used local Session whose remembered remote conversation is
   * `sessionId`.
   *
   * Used by the optional inbound adapter: an asynchronous remote reply must land
   * in the local conversation that memory already maps to that peer Session.
   * Entries are kept least-recently-used first, so the last match is the latest
   * mapping. A supplied `prefix` must match the session-id family exactly so
   * two peers sharing a wire id cannot route into each other's local chats.
   * Malformed scope keys are ignored.
   * @param sessionId - the wire remote session id.
   * @param prefix - optional session-id family (the peer-specific prefix).
   * @returns the local session id, or undefined when nothing maps it.
   */
  latestLocalSessionFor(sessionId, prefix) {
    if (sessionId === "") return void 0;
    let found;
    for (const [key, value] of this.entries) {
      if (value !== sessionId) continue;
      try {
        const parsed = JSON.parse(key);
        if (!Array.isArray(parsed) || prefix !== void 0 && parsed[0] !== prefix) continue;
        const local = parsed[1];
        if (typeof local !== "string" || local === "") continue;
        found = local;
      } catch {
      }
    }
    return found;
  }
  save() {
    try {
      mkdirSync2(dirname2(this.file), { recursive: true });
      writeFileSync2(
        this.file,
        `${JSON.stringify({ version: 1, sessions: Object.fromEntries(this.entries) }, null, 2)}
`,
        "utf8"
      );
    } catch {
    }
  }
};

// src/remote-pool.ts
var MAX_POOL_WORKERS = 8;
var REMOTE_WORKERS_TOOL = "remote_workers";
var REMOTE_WORKER_PROMPT_TOOL = "remote_worker_prompt";
var REMOTE_POOL_DISPATCH_TOOL = "remote_pool_dispatch";
var REMOTE_TEAM_DISPATCH_TOOL = "remote_team_dispatch";
function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}
function isAbortError(error) {
  return error instanceof Error && error.name === "AbortError";
}
var NEVER_ABORT = new AbortController().signal;
function renderText2(text2) {
  return [{ type: "text", text: text2 }];
}
function excerpt(value, max = 100) {
  const flat = value.replace(/\s+/gu, " ").trim();
  if (flat === "") return "(empty)";
  return flat.length <= max ? flat : `${flat.slice(0, Math.max(0, max - 1))}\u2026`;
}
function firstLine(value) {
  for (const line of value.split(/\r?\n/u)) {
    const trimmed = line.trim();
    if (trimmed !== "") return trimmed;
  }
  return "";
}
function peerSessionId(prefix, peer, localSessionId) {
  const family = typeof prefix === "string" && prefix.trim() !== "" ? prefix.trim() : "remote";
  const name2 = typeof peer === "string" && peer.trim() !== "" ? peer.trim() : "peer";
  const local = typeof localSessionId === "string" ? localSessionId : "";
  return anchorSessionId(family, `${name2}\0${local}`);
}
function orderedPeerNames(peers, requested) {
  const declared = Object.keys(peers);
  if (requested === void 0) {
    if (declared.length === 0) {
      throw new Error(
        "\u6CA1\u6709\u58F0\u660E\u4EFB\u4F55 peer\uFF1A\u5148\u5728 dsh-remote-client \u7684 `peers` \u91CC\u58F0\u660E\u81F3\u5C11\u4E00\u4E2A peer \uFF08\u6216\u914D\u7F6E\u5355 peer \u7684 host/port\uFF09\u3002"
      );
    }
    return declared;
  }
  if (requested.length === 0) {
    throw new Error("peers \u4E3A\u7A7A\uFF1A\u8BF7\u81F3\u5C11\u7ED9\u4E00\u4E2A peer \u540D\uFF1B\u7701\u7565 peers \u8868\u793A\u4F7F\u7528\u5168\u90E8\u5DF2\u58F0\u660E\u7684 peer\u3002");
  }
  const seen = /* @__PURE__ */ new Set();
  const ordered = [];
  for (const raw of requested) {
    const name2 = typeof raw === "string" ? raw.trim() : "";
    if (name2 === "") throw new Error("peers \u91CC\u6709\u7A7A\u540D\u5B57\uFF1A\u6BCF\u4E2A peer \u540D\u90FD\u5FC5\u987B\u975E\u7A7A\u3002");
    if (seen.has(name2)) {
      throw new Error(`peer "${name2}" \u5728 peers \u91CC\u91CD\u590D\u4E86\uFF1A\u6BCF\u4E2A peer \u53EA\u80FD\u51FA\u73B0\u4E00\u6B21\u3002`);
    }
    if (!Object.hasOwn(peers, name2)) {
      throw new Error(
        `\u672A\u77E5 peer "${name2}"\uFF1A` + (declared.length === 0 ? "\u5F53\u524D\u6CA1\u6709\u58F0\u660E\u4EFB\u4F55 peer\u3002" : `\u5DF2\u58F0\u660E\u7684 peer \u662F ${declared.join(", ")}\u3002`)
      );
    }
    seen.add(name2);
    ordered.push(name2);
  }
  return ordered;
}
function normalizedPrefix(deps) {
  const value = deps.prefix();
  return typeof value === "string" && value.trim() !== "" ? value.trim() : "remote";
}
function profileOf(peers, name2) {
  const profile = peers[name2];
  if (profile === void 0) {
    throw new Error(`\u672A\u77E5 peer "${name2}"\uFF1A\u5B83\u4E0D\u5728\u5F53\u524D\u58F0\u660E\u7684 peers \u91CC\u3002`);
  }
  return profile;
}
function teamAgentOf(exec) {
  const agent = exec?.agent;
  if (agent === void 0 || agent === null || typeof agent !== "object") return void 0;
  return agent;
}
function summaryTextOf(workers) {
  const lines = [];
  for (const worker of workers) {
    if (worker.ok) {
      lines.push(`${worker.peer}: \u6210\u529F\uFF08${worker.durationMs} ms\uFF09\u2014 ${excerpt(worker.reply, 160)}`);
      continue;
    }
    const reason = worker.error ?? (worker.interrupted === true ? "\u88AB\u8FDC\u7AEF\u7528\u6237\u6253\u65AD" : "\u672A\u77E5\u9519\u8BEF");
    lines.push(`${worker.peer}: \u5931\u8D25 \u2014 ${reason}`);
  }
  return lines.join("\n");
}
function dispatchSubject(description, prompt) {
  const fromDescription = description.trim();
  if (fromDescription !== "") return fromDescription;
  const fromPrompt = firstLine(prompt);
  return fromPrompt === "" ? "\u8FDC\u7AEF worker \u6C60\u5E76\u884C\u6D3E\u53D1" : fromPrompt;
}
function dispatchTaskDescription(description, prompt, peers) {
  const parts = [];
  const trimmed = description.trim();
  if (trimmed !== "") parts.push(`\u8BF4\u660E: ${trimmed}`);
  parts.push(`\u53C2\u4E0E peer\uFF08${peers.length}\uFF09: ${peers.join(", ")}`);
  parts.push(`prompt:
${prompt}`);
  return parts.join("\n\n");
}
function createPoolTools(deps) {
  const interruptWorker = (link, peer, sessionId) => {
    void link.request("agent.interrupt", { sessionId }, 1e4).then(() => {
      deps.log(`dsh-remote-pool: \u5DF2\u5411 peer "${peer}" \u53D1\u9001 agent.interrupt\uFF08${sessionId}\uFF09`);
    }).catch((error) => {
      deps.log(
        `dsh-remote-pool: \u4E2D\u65AD peer "${peer}" \u4E0A\u7684 ${sessionId} \u5931\u8D25\uFF08${messageOf(error)}\uFF09`
      );
    });
  };
  const assertCanPrompt = (peer, profile) => {
    assertPeerOperation(normalizePermission(profile.maxPermission), "agent.prompt", {
      peer,
      path: void 0,
      workspaceRoot: typeof profile.workspaceRoot === "string" ? profile.workspaceRoot : ""
    });
  };
  const runWorker = async (task) => {
    const startedAt = Date.now();
    const base = (patch) => ({
      peer: task.peer,
      sessionId: task.sessionId,
      ok: false,
      reply: "",
      stopReason: "error",
      durationMs: Math.max(0, Date.now() - startedAt),
      ...patch
    });
    try {
      assertCanPrompt(task.peer, task.profile);
    } catch (error) {
      return base({ error: messageOf(error) });
    }
    let pending;
    try {
      pending = task.link.request("agent.prompt", {
        sessionId: task.sessionId,
        text: task.text,
        // 0 = 不设对端侧超时：worker 轮次可以跑很久，前台等它结束。
        timeoutMs: 0
      });
    } catch (error) {
      return base({ error: messageOf(error) });
    }
    const onAbort = () => {
      interruptWorker(task.link, task.peer, task.sessionId);
    };
    const signal = task.signal;
    if (signal?.aborted === true) onAbort();
    else signal?.addEventListener("abort", onAbort, { once: true });
    try {
      const response = await raceAbort(pending, signal ?? NEVER_ABORT);
      const reply = typeof response.reply === "string" ? response.reply : "";
      const interrupted = response.interrupted === true;
      const peerError = typeof response.error === "string" && response.error.trim() !== "" ? response.error : void 0;
      const reason = typeof response.reason === "string" && response.reason !== "" ? response.reason : void 0;
      const ok = !interrupted && peerError === void 0;
      return base({
        ok,
        reply,
        ...replyFields(response),
        stopReason: interrupted ? "aborted" : peerError !== void 0 ? "error" : reason ?? "completed",
        ...interrupted ? { interrupted: true } : {},
        ...peerError === void 0 ? {} : { error: peerError }
      });
    } catch (error) {
      if (isAbortError(error)) {
        return base({ stopReason: "aborted", aborted: true, error: "\u672C\u673A\u53D6\u6D88" });
      }
      return base({ error: messageOf(error) });
    } finally {
      signal?.removeEventListener("abort", onAbort);
    }
  };
  const contextOf = (exec) => ({
    peers: deps.peers(),
    prefix: normalizedPrefix(deps),
    localSessionId: deps.localSessionOf(exec)
  });
  const runDispatch = async (request) => {
    const { peers, prefix, localSessionId } = contextOf(request.exec);
    const signal = request.exec.signal;
    const tasks = request.names.map((peer) => {
      const profile = profileOf(peers, peer);
      return {
        peer,
        profile,
        link: deps.linkFor(peer),
        sessionId: peerSessionId(prefix, peer, localSessionId),
        text: request.text,
        signal
      };
    });
    const teamAgent = teamAgentOf(request.exec);
    const hooks = deps.teamTask;
    let token;
    let beginError;
    if (hooks !== void 0) {
      try {
        token = await hooks.begin(teamAgent, {
          subject: dispatchSubject(request.description, request.text),
          description: dispatchTaskDescription(request.description, request.text, request.names)
        });
      } catch (error) {
        beginError = messageOf(error);
        if (!request.strictTeam) {
          deps.log(`dsh-remote-pool: \u770B\u677F\u4EFB\u52A1 begin \u5931\u8D25\uFF08${beginError}\uFF09\uFF1B\u7EE7\u7EED\u6D3E\u53D1`);
        }
      }
    }
    if (request.strictTeam && token === void 0) {
      throw new Error(
        `${request.toolName}: \u5F53\u524D\u4F1A\u8BDD\u4E0D\u5728 Agent Teams \u91CC\uFF08\u6216\u6CA1\u6709 agentTeams \u670D\u52A1\uFF09\uFF0C\u8BF7\u7528 remote_pool_dispatch / remote_worker_prompt` + (beginError === void 0 ? "" : `\uFF1Bbegin \u5931\u8D25\uFF1A${beginError}`)
      );
    }
    deps.log(
      `dsh-remote-pool: \u5E76\u884C\u6D3E\u53D1\u5230 ${request.names.length} \u4E2A peer\uFF08${request.names.join(", ")}\uFF09` + (token === void 0 ? "" : `\uFF1B\u770B\u677F\u4EFB\u52A1 ${token.taskId}`)
    );
    const settled = await Promise.allSettled(tasks.map((task) => runWorker(task)));
    const workers = [];
    let aborted = signal?.aborted === true;
    for (let index = 0; index < tasks.length; index += 1) {
      const task = tasks[index];
      if (task === void 0) continue;
      const outcome = settled[index];
      if (outcome === void 0) continue;
      if (outcome.status === "fulfilled") {
        workers.push(outcome.value);
        if (outcome.value.aborted === true) aborted = true;
        continue;
      }
      if (isAbortError(outcome.reason)) aborted = true;
      workers.push({
        peer: task.peer,
        sessionId: task.sessionId,
        ok: false,
        reply: "",
        stopReason: "error",
        durationMs: 0,
        error: messageOf(outcome.reason)
      });
    }
    const okCount = workers.filter((worker) => worker.ok).length;
    const failedCount = workers.length - okCount;
    const summary = { total: workers.length, ok: okCount, failed: failedCount };
    const summaryText = aborted ? `\u672C\u673A\u53D6\u6D88\uFF1A\u5DF2\u5411\u6240\u6709\u5728\u9014 worker \u53D1\u9001 agent.interrupt
${summaryTextOf(workers)}` : summaryTextOf(workers);
    if (hooks !== void 0) {
      try {
        await hooks.finish(teamAgent, token, {
          ok: okCount,
          failed: failedCount,
          summary: summaryText
        });
      } catch (error) {
        deps.log(`dsh-remote-pool: \u770B\u677F\u4EFB\u52A1 finish \u5931\u8D25\uFF08${messageOf(error)}\uFF09\uFF1B\u7ED3\u679C\u4E0D\u53D7\u5F71\u54CD`);
      }
    }
    if (aborted) {
      throw abortError(
        `${request.toolName}: \u672C\u673A\u53D6\u6D88\uFF0C\u5DF2\u5411\u6240\u6709\u5728\u9014 worker \u53D1\u9001 agent.interrupt\uFF1B\u5DF2\u53D1\u51FA\u7684\u8BF7\u6C42\u4E0D\u4F1A\u91CD\u8BD5`
      );
    }
    deps.log(
      `dsh-remote-pool: \u6D3E\u53D1\u5B8C\u6210\uFF1A${okCount} \u6210\u529F / ${failedCount} \u5931\u8D25\uFF08\u5171 ${workers.length}\uFF09`
    );
    return { description: request.description, workers, summary, taskId: token?.taskId };
  };
  return [
    defineTool4({
      name: REMOTE_WORKERS_TOOL,
      description: "\u5217\u51FA\u90E8\u7F72\u58F0\u660E\u7684\u6240\u6709\u8FDC\u7AEF peer\uFF08worker \u6C60\uFF09\uFF1A`{ name, host, port, connected, maxPermission, sessionForThisChat }`\u3002\n`sessionForThisChat` \u662F\u672C chat\uFF08\u8C03\u7528\u65B9\u4F1A\u8BDD\uFF09\u5728\u6BCF\u4E2A peer \u4E0A\u56FA\u5B9A\u590D\u7528\u7684\u8FDC\u7AEF\u4F1A\u8BDD id \u2014\u2014 \u4E00\u4E2A\u672C\u673A chat \u5728\u6BCF\u4E2A peer \u4E0A\u5404\u6709\u4E00\u6BB5\u5BF9\u8BDD\uFF0C\u4E0D\u540C peer \u7684 id \u4E0D\u540C\u3002\n\u8FB9\u754C\uFF1A\u8FDC\u7AEF peer **\u4E0D\u5728 Agent Teams roster \u91CC**\uFF0C\u5B83\u4E0D\u662F\u672C\u673A teammate\uFF1Bworker \u6C60\u7684\u4EFB\u52A1\u53EA\u4F1A\u4EE5**\u8C03\u7528\u65B9\uFF08Lead/\u6210\u5458\uFF09\u540D\u4E49**\u51FA\u73B0\u5728\u770B\u677F\u4E0A\uFF0Cowner \u662F\u8C03\u7528\u65B9\u800C\u4E0D\u662F\u8FDC\u7AEF\u3002",
      parameters: {},
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          const workers = Array.isArray(v.workers) ? v.workers : [];
          if (workers.length === 0) {
            return renderText2("\u6CA1\u6709\u58F0\u660E\u4EFB\u4F55 peer\uFF1A\u5148\u5728 dsh-remote-client \u7684 `peers` \u91CC\u58F0\u660E\u81F3\u5C11\u4E00\u4E2A\u3002");
          }
          const lines = [`\u8FDC\u7AEF worker \u6C60\uFF1A${workers.length} \u4E2A peer`];
          for (const worker of workers) {
            const endpoint = worker.host === "" ? "(\u672A\u914D\u7F6E host)" : `${worker.host}:${worker.port}`;
            lines.push(
              `- ${worker.name}  ${endpoint}  ${levelName(worker.maxPermission)}  ${worker.connected ? "\u5DF2\u8FDE\u63A5" : "\u672A\u8FDE\u63A5"}  session=${worker.sessionForThisChat ?? "(\u65E0\u8C03\u7528\u65B9 chat)"}`
            );
          }
          lines.push("\u8FDC\u7AEF peer \u4E0D\u5728 Team roster \u91CC\uFF1A\u770B\u677F\u4EFB\u52A1\u53EA\u8BB0\u5728\u8C03\u7528\u65B9\u540D\u4E0B\u3002");
          return renderText2(lines.join("\n"));
        }
      },
      async execute(_args, exec) {
        const { peers, prefix, localSessionId } = contextOf(exec);
        const names = Object.keys(peers);
        if (names.length === 0) {
          throw new Error(
            "\u6CA1\u6709\u58F0\u660E\u4EFB\u4F55 peer\uFF1A\u5148\u5728 dsh-remote-client \u7684 `peers` \u91CC\u58F0\u660E\u81F3\u5C11\u4E00\u4E2A peer \uFF08\u6216\u914D\u7F6E\u5355 peer \u7684 host/port\uFF09\u3002"
          );
        }
        const workers = names.map((name2) => {
          const profile = peers[name2] ?? { name: name2 };
          let connected = false;
          try {
            connected = deps.linkFor(name2).connected;
          } catch (error) {
            deps.log(`dsh-remote-pool: \u8BFB\u53D6 peer "${name2}" \u94FE\u63A5\u5931\u8D25\uFF08${messageOf(error)}\uFF09`);
          }
          return {
            name: name2,
            host: typeof profile.host === "string" ? profile.host : "",
            port: typeof profile.port === "number" && Number.isFinite(profile.port) ? profile.port : 0,
            connected,
            maxPermission: normalizePermission(profile.maxPermission),
            // 没有调用方 chat 时给 null：此时 id 在 peer 内共享，必须让调用方看得见。
            sessionForThisChat: localSessionId === void 0 || localSessionId === "" ? null : peerSessionId(prefix, name2, localSessionId)
          };
        });
        return { count: workers.length, workers };
      }
    }),
    defineTool4({
      name: REMOTE_WORKER_PROMPT_TOOL,
      description: "\u5728**\u67D0\u4E2A\u6307\u5B9A peer** \u7684\u786E\u5B9A\u6027\u4F1A\u8BDD\u4E0A\u505A\u4E00\u6B21**\u524D\u53F0** `agent.prompt`\uFF0C\u7B49\u8FD9\u4E00\u8F6E\u7ED3\u675F\u5E76\u53D6\u56DE\u56DE\u590D\u3002\n\u4F1A\u8BDD id \u7531\uFF08\u672C\u673A chat, peer \u540D\uFF09\u5171\u540C\u63A8\u5BFC\uFF1A\u540C\u4E00\u4E2A chat \u53CD\u590D\u8C03\u7528\u540C\u4E00\u4E2A peer \u4F1A\u7EED\u63A5\u540C\u4E00\u6BB5\u8FDC\u7AEF\u5BF9\u8BDD\uFF0C\u4E0D\u540C peer \u5404\u81EA\u4E00\u6BB5\u3002\n\u7528\u9014\uFF1A\u660E\u786E\u77E5\u9053\u8BE5\u627E\u54EA\u53F0\u673A\u5668\u65F6\u5355\u72EC\u6D3E\u6D3B\uFF1B\u8981\u540C\u65F6\u95EE\u591A\u4E2A peer \u7528 remote_pool_dispatch\u3002\n\u6743\u9650\uFF1A\u8C03\u7528\u524D\u6309\u8BE5 peer \u7684 maxPermission \u68C0\u67E5 `agent.prompt`\uFF08\u9700\u8981 level 3 / danger-full-access\uFF09\uFF0C\u5931\u8D25\u4FE1\u606F\u4E0E\u5355 peer \u4E3B\u8DEF\u5F84\u4E00\u81F4\u3002\n\u6253\u65AD\uFF1A\u672C\u673A\u7528\u6237\u4E2D\u65AD\u65F6\uFF0C\u4F1A\u5BF9\u8BE5 peer \u53D1 `agent.interrupt` \u5E76\u4EE5 AbortError \u7ED3\u675F\u3002\n\u8FB9\u754C\uFF1A\u8FDC\u7AEF peer **\u4E0D\u5728 Agent Teams roster \u91CC**\uFF1B\u82E5\u8C03\u7528\u65B9\u5728 Team \u4E2D\uFF0C\u4EFB\u52A1\u53EA\u4F1A\u4EE5\u8C03\u7528\u65B9\u540D\u4E49\u51FA\u73B0\u3002",
      parameters: {
        peer: { type: "string", required: true, description: "\u8981\u6D3E\u6D3B\u7684 peer \u540D\uFF08\u7528 remote_workers \u67E5\u770B\uFF09\u3002" },
        text: { type: "string", required: true, description: "\u4EA4\u7ED9\u8BE5 peer agent \u7684\u7528\u6237\u53D1\u8A00\u3002" },
        description: { type: "string", description: "\u8FD9\u6B21\u6D3E\u6D3B\u7684\u7B80\u77ED\u6807\u9898\uFF0C\u53EA\u7528\u4E8E\u65E5\u5FD7/\u770B\u677F\u4EFB\u52A1\u6807\u9898\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          const lines = [
            `peer   : ${v.peer}`,
            `session: ${v.sessionId}`,
            `reason : ${v.reason ?? "(none)"}${v.interrupted ? "  (interrupted)" : ""}   ${v.durationMs} ms`
          ];
          if (v.interrupted) {
            lines.push("\u26A0\uFE0F \u8FD9\u4E00\u8F6E\u5728\u8FDC\u7AEF\u88AB\u7528\u6237\u6253\u65AD\uFF0C\u6CA1\u6709\u53EF\u7528\u7684\u56DE\u590D\u3002\u7ACB\u523B\u505C\u6B62\uFF1A\u4E0D\u8981\u91CD\u8BD5\u3001\u4E0D\u8981\u81EA\u52A8\u7EE7\u7EED\uFF0C\u7B49\u7528\u6237\u7684\u65B0\u6307\u793A\u3002");
          }
          lines.push(renderRemoteReplies(value));
          return renderText2(lines.join("\n"));
        }
      },
      async execute(args, exec) {
        const { peers, prefix, localSessionId } = contextOf(exec);
        const [peer] = orderedPeerNames(peers, [args.peer]);
        if (peer === void 0) throw new Error("remote_worker_prompt: peer \u540D\u65E0\u6548\u3002");
        const profile = profileOf(peers, peer);
        const sessionId = peerSessionId(prefix, peer, localSessionId);
        if (typeof args.text !== "string" || args.text.trim() === "") {
          throw new Error("remote_worker_prompt: text \u4E0D\u80FD\u4E3A\u7A7A\u3002");
        }
        const label = typeof args.description === "string" && args.description.trim() !== "" ? args.description.trim() : firstLine(args.text);
        deps.log(`dsh-remote-pool: \u6D3E\u6D3B\u7ED9 peer "${peer}"\uFF08${sessionId}\uFF09\uFF1A${excerpt(label, 80)}`);
        const result = await runWorker({
          peer,
          profile,
          link: deps.linkFor(peer),
          sessionId,
          text: args.text,
          signal: exec?.signal
        });
        if (result.aborted === true) {
          throw abortError(`remote_worker_prompt: \u672C\u673A\u53D6\u6D88\uFF0C\u5DF2\u5411 peer "${peer}" \u53D1\u9001 agent.interrupt`);
        }
        if (!result.ok) {
          throw new Error(
            `remote_worker_prompt: peer "${peer}" \u4E0A\u7684\u8FDC\u7AEF\u8F6E\u6B21\u5931\u8D25\uFF1A${result.error ?? "\u672A\u77E5\u9519\u8BEF"}`
          );
        }
        return {
          peer,
          sessionId,
          reply: result.reply,
          ...result.replies === void 0 ? {} : { replies: result.replies },
          ...result.replyFormat === void 0 ? {} : { replyFormat: result.replyFormat },
          interrupted: result.interrupted === true,
          reason: result.stopReason,
          durationMs: result.durationMs
        };
      }
    }),
    defineTool4({
      name: REMOTE_POOL_DISPATCH_TOOL,
      description: "\u628A\u540C\u4E00\u4E2A prompt **\u5E76\u884C**\u6D3E\u53D1\u7ED9\u591A\u4E2A\u8FDC\u7AEF peer\uFF08\u9ED8\u8BA4\u5168\u90E8\u5DF2\u58F0\u660E\u7684 peer\uFF09\uFF0C\u7B49\u6240\u6709 worker \u7ED3\u675F\u540E\u805A\u5408\u7ED3\u679C\u3002\n\u6BCF\u4E2A worker \u6709\u81EA\u5DF1\u72EC\u7ACB\u7684\u786E\u5B9A\u6027\u4F1A\u8BDD\uFF08seed \u540C\u65F6\u542B peer \u540D\u548C\u672C\u673A chat\uFF09\uFF0C\u4E92\u4E0D\u5E72\u6270\uFF1B\u5355\u4E2A worker \u5931\u8D25\u53EA\u51FA\u73B0\u5728\u5B83\u81EA\u5DF1\u7684\u7ED3\u679C\u884C\u91CC\uFF0C\u4E0D\u4F1A\u8BA9\u6574\u4E2A\u5DE5\u5177\u5931\u8D25\uFF0C\u4E5F\u4E0D\u5F71\u54CD\u5176\u4ED6 worker\u3002\n\u6700\u591A 8 \u4E2A worker\uFF08\u8D85\u8FC7\u76F4\u63A5\u62A5\u9519\uFF0C\u4E0D\u9759\u9ED8\u622A\u65AD\uFF09\uFF1Bpeers \u672A\u58F0\u660E/\u91CD\u590D/\u4E3A\u7A7A\u90FD\u62A5\u53EF\u8BFB\u9519\u8BEF\u3002\n\u6743\u9650\uFF1A\u6BCF\u4E2A worker \u8C03\u7528\u524D\u6309\u8BE5 peer \u7684 maxPermission \u68C0\u67E5 `agent.prompt`\uFF08level 3\uFF09\u3002\n\u6253\u65AD\uFF1A\u672C\u673A\u53D6\u6D88\u65F6\u5BF9\u6240\u6709\u5728\u9014 worker \u5C3D\u529B\u53D1 `agent.interrupt`\uFF0C\u6574\u4F53\u4EE5 AbortError \u7ED3\u675F\uFF0C\u5DF2\u53D1\u7684\u8BF7\u6C42\u4E0D\u91CD\u8BD5\u3002\n\u8FD9\u662F**\u524D\u53F0\u5E76\u884C**\uFF0C\u6CA1\u6709\u540E\u53F0 run\uFF1B\u9700\u8981\u540E\u53F0\u4EFB\u52A1\u7528 remote_run_start\u3002\n\u8FB9\u754C\uFF1A\u8FDC\u7AEF peer **\u4E0D\u5728 Agent Teams roster \u91CC**\u3002\u82E5\u542F\u7528 Agent Teams \u4E14\u8C03\u7528\u65B9\u662F\u6210\u5458\uFF0C\u672C\u6B21\u6D3E\u53D1\u4F1A\u8BB0\u6210\u4E00\u6761\u770B\u677F\u4EFB\u52A1\uFF08subject \u524D\u7F00 `\u8FDC\u7AEF: `\uFF09\uFF0C\u4F46 owner \u662F**\u8C03\u7528\u65B9**\uFF0C\u4E0D\u662F\u8FDC\u7AEF worker\u3002",
      parameters: {
        prompt: { type: "string", required: true, description: "\u8981\u5E76\u884C\u6D3E\u53D1\u7ED9\u6240\u6709 worker \u7684\u5B8C\u6574\u4EFB\u52A1\u63CF\u8FF0\u3002" },
        peers: {
          type: "array",
          items: { type: "string" },
          description: `\u8981\u53C2\u4E0E\u7684 peer \u540D\u5217\u8868\uFF08\u6700\u591A ${MAX_POOL_WORKERS} \u4E2A\uFF09\uFF1B\u7701\u7565\u8868\u793A\u5168\u90E8\u5DF2\u58F0\u660E\u7684 peer\u3002`
        },
        description: { type: "string", description: "\u8FD9\u6B21\u6D3E\u53D1\u7684\u7B80\u77ED\u6807\u9898\uFF0C\u53EA\u7528\u4E8E\u65E5\u5FD7/\u770B\u677F\u4EFB\u52A1\u6807\u9898\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          const workers = Array.isArray(v.workers) ? v.workers : [];
          const total = v.summary?.total ?? workers.length;
          const okCount = v.summary?.ok ?? workers.filter((worker) => worker.ok).length;
          const failedCount = v.summary?.failed ?? total - okCount;
          const title = v.description?.trim() === "" || v.description === void 0 ? "\u8FDC\u7AEF worker \u6C60\u5E76\u884C\u6D3E\u53D1" : `\u8FDC\u7AEF worker \u6C60\u5E76\u884C\u6D3E\u53D1\uFF1A${v.description.trim()}`;
          const lines = [
            `${title}\uFF08${total} \u4E2A worker\uFF0C${okCount} \u6210\u529F / ${failedCount} \u5931\u8D25\uFF09`
          ];
          for (const worker of workers) {
            const status = worker.ok ? "[ok]  " : "[fail]";
            const head = `- ${status} ${worker.peer}  session=${worker.sessionId}  ${worker.durationMs} ms`;
            if (worker.ok) {
              lines.push(`${head}  reply: ${excerpt(worker.reply)}`);
            } else if (worker.error !== void 0 && worker.error !== "") {
              lines.push(`${head}  error: ${excerpt(worker.error, 160)}`);
            } else if (worker.interrupted === true) {
              lines.push(`${head}  interrupted: \u8FDC\u7AEF\u7528\u6237\u6253\u65AD`);
            } else {
              lines.push(head);
            }
          }
          if (failedCount > 0) {
            lines.push("\u5931\u8D25\u7684 worker \u4E0D\u963B\u585E\u5176\u4ED6 worker\uFF1B\u9700\u8981\u65F6\u5BF9\u5931\u8D25 peer \u5355\u72EC\u91CD\u8BD5\uFF08remote_worker_prompt\uFF09\u3002");
          }
          lines.push("\u8FDC\u7AEF peer \u4E0D\u5728 Team roster \u91CC\uFF1A\u770B\u677F\u4EFB\u52A1\u53EA\u8BB0\u5728\u8C03\u7528\u65B9\u540D\u4E0B\u3002");
          return renderText2(lines.join("\n"));
        }
      },
      async execute(args, exec) {
        if (typeof args.prompt !== "string" || args.prompt.trim() === "") {
          throw new Error("remote_pool_dispatch: prompt \u4E0D\u80FD\u4E3A\u7A7A\u3002");
        }
        const { peers } = contextOf(exec);
        const names = orderedPeerNames(peers, args.peers);
        if (names.length > MAX_POOL_WORKERS) {
          throw new Error(
            `remote_pool_dispatch: \u4E00\u6B21\u6700\u591A ${MAX_POOL_WORKERS} \u4E2A worker\uFF0C\u8FD9\u6B21\u70B9\u540D\u4E86 ${names.length} \u4E2A\uFF08${names.join(", ")}\uFF09\uFF1B\u8BF7\u62C6\u6210\u591A\u6B21\u6D3E\u53D1\u3002`
          );
        }
        const description = typeof args.description === "string" ? args.description : "";
        const result = await runDispatch({
          names,
          text: args.prompt,
          description,
          exec,
          strictTeam: false,
          toolName: REMOTE_POOL_DISPATCH_TOOL
        });
        return {
          description: result.description,
          workers: result.workers,
          summary: result.summary
        };
      }
    }),
    defineTool4({
      name: REMOTE_TEAM_DISPATCH_TOOL,
      description: "\u5728 **Agent Teams \u770B\u677F**\u4E0A\u663E\u5F0F\u767B\u8BB0\u4E00\u6B21\u8FDC\u7AEF\u5DE5\u4F5C\uFF08\u5355 peer\uFF09\uFF1A\u7528**\u8C03\u7528\u65B9\u8EAB\u4EFD**\u5EFA\u4EFB\u52A1\u5E76 claim\uFF0C\u5728\u8FDC\u7AEF\u8DD1\u4E00\u6B21\u524D\u53F0 prompt\uFF0C\u7ED3\u675F\u540E\u628A\u7ED3\u679C\u6458\u8981\u5199\u56DE\u4EFB\u52A1\u63CF\u8FF0\u5E76 complete\uFF0C\u8FD4\u56DE `taskId` \u4FBF\u4E8E\u4E4B\u540E\u7528 `team_task_get` \u67E5\u3002\n\u8981\u6C42\u5F53\u524D\u4F1A\u8BDD\u771F\u7684\u5728 Agent Teams \u91CC\uFF08\u6709 agentTeams \u670D\u52A1\u4E14\u8C03\u7528\u65B9\u662F lead/teammate\uFF09\uFF1B\u5426\u5219**\u76F4\u63A5\u62A5\u9519**\uFF0C\u4E0D\u4F1A\u9759\u9ED8\u9000\u5316\u6210\u666E\u901A\u6D3E\u53D1\u2014\u2014\u90A3\u53EA\u4F1A\u767D\u82B1\u4E00\u6B21\u8FDC\u7AEF\u8F6E\u6B21\u3002\n`peer` \u7701\u7565\u65F6\u4F7F\u7528\u7B2C\u4E00\u4E2A\u5DF2\u58F0\u660E\u7684 peer\uFF1B\u8981\u5E76\u884C\u591A\u4E2A peer \u8BF7\u7528 remote_pool_dispatch\u3002\n\u6743\u9650\u4E0E\u6253\u65AD\u8BED\u4E49\u540C remote_worker_prompt\uFF1A\u6309\u8BE5 peer \u7684 maxPermission \u68C0\u67E5 `agent.prompt`\uFF08level 3\uFF09\uFF0C\u672C\u673A\u53D6\u6D88\u65F6\u53D1 `agent.interrupt` \u5E76\u4EE5 AbortError \u7ED3\u675F\u3002\n\u8FB9\u754C\uFF1A\u8FDC\u7AEF peer **\u4E0D\u5728 Agent Teams roster \u91CC**\uFF0C\u4E0D\u662F\u672C\u673A teammate\uFF1B\u770B\u677F\u4EFB\u52A1 owner \u662F**\u8C03\u7528\u65B9**\uFF0C\u4E0D\u662F\u8FDC\u7AEF worker\u3002",
      parameters: {
        description: { type: "string", required: true, description: "\u770B\u677F\u4EFB\u52A1\u6807\u9898\uFF08\u4F1A\u81EA\u52A8\u52A0 `\u8FDC\u7AEF: ` \u524D\u7F00\uFF09\u3002" },
        prompt: { type: "string", required: true, description: "\u4EA4\u7ED9\u8BE5 peer agent \u7684\u5B8C\u6574\u4EFB\u52A1\u63CF\u8FF0\u3002" },
        peer: { type: "string", description: "\u8981\u6D3E\u6D3B\u7684 peer \u540D\uFF1B\u7701\u7565\u8868\u793A\u7B2C\u4E00\u4E2A\u5DF2\u58F0\u660E\u7684 peer\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          const workers = Array.isArray(v.workers) ? v.workers : [];
          const total = v.summary?.total ?? workers.length;
          const okCount = v.summary?.ok ?? workers.filter((worker) => worker.ok).length;
          const failedCount = v.summary?.failed ?? total - okCount;
          const task = typeof v.taskId === "string" && v.taskId !== "" ? `task ${v.taskId}` : "(\u6CA1\u6709 taskId)";
          const lines = [
            `\u8FDC\u7AEF Team \u6D3E\u53D1\u5DF2\u767B\u8BB0\uFF1A${task}\uFF08${total} \u4E2A worker\uFF0C${okCount} \u6210\u529F / ${failedCount} \u5931\u8D25\uFF09`
          ];
          for (const worker of workers) {
            const status = worker.ok ? "[ok]  " : "[fail]";
            const head = `- ${status} ${worker.peer}  session=${worker.sessionId}  ${worker.durationMs} ms`;
            if (worker.ok) {
              lines.push(`${head}  reply: ${excerpt(worker.reply)}`);
            } else if (worker.error !== void 0 && worker.error !== "") {
              lines.push(`${head}  error: ${excerpt(worker.error, 160)}`);
            } else if (worker.interrupted === true) {
              lines.push(`${head}  interrupted: \u8FDC\u7AEF\u7528\u6237\u6253\u65AD`);
            } else {
              lines.push(head);
            }
          }
          if (failedCount > 0) {
            lines.push("\u5931\u8D25\u7684 worker \u4E0D\u963B\u585E\u5176\u4ED6 worker\uFF1B\u9700\u8981\u65F6\u5BF9\u8BE5 peer \u5355\u72EC\u91CD\u8BD5\uFF08remote_worker_prompt\uFF09\u3002");
          }
          lines.push("\u8FDC\u7AEF peer \u4E0D\u5728 roster \u91CC\uFF1B\u770B\u677F\u4EFB\u52A1 owner \u662F\u8C03\u7528\u65B9\uFF08\u4E0D\u662F\u8FDC\u7AEF worker\uFF09\u3002");
          return renderText2(lines.join("\n"));
        }
      },
      async execute(args, exec) {
        if (typeof args.description !== "string" || args.description.trim() === "") {
          throw new Error("remote_team_dispatch: description \u4E0D\u80FD\u4E3A\u7A7A\u3002");
        }
        if (typeof args.prompt !== "string" || args.prompt.trim() === "") {
          throw new Error("remote_team_dispatch: prompt \u4E0D\u80FD\u4E3A\u7A7A\u3002");
        }
        const { peers } = contextOf(exec);
        const requested = typeof args.peer === "string" && args.peer.trim() !== "" ? [args.peer] : void 0;
        const selected = orderedPeerNames(peers, requested);
        const peer = selected[0];
        if (peer === void 0) throw new Error("remote_team_dispatch: \u6CA1\u6709\u53EF\u7528\u7684 peer\u3002");
        const result = await runDispatch({
          names: [peer],
          text: args.prompt,
          description: args.description.trim(),
          exec,
          strictTeam: true,
          toolName: REMOTE_TEAM_DISPATCH_TOOL
        });
        if (result.taskId === void 0) {
          throw new Error(`${REMOTE_TEAM_DISPATCH_TOOL}: \u770B\u677F\u4EFB\u52A1\u6CA1\u6709\u767B\u8BB0\u6210\u529F\u3002`);
        }
        return {
          taskId: result.taskId,
          workers: result.workers,
          summary: result.summary
        };
      }
    })
  ];
}

// src/remote-team.ts
var TEAM_SUBJECT_PREFIX = "\u8FDC\u7AEF: ";
var MAX_TEAM_SUBJECT_CHARS = 200;
var MAX_TEAM_DESCRIPTION_CHARS = 2e3;
var DEFAULT_MAX_SUMMARY_CHARS = 800;
var MAX_REMEMBERED_DESCRIPTIONS = 64;
function messageOf2(error) {
  return error instanceof Error ? error.message : String(error);
}
function clampText(value, max) {
  const limit = Math.max(1, Math.trunc(max));
  if (value.length <= limit) return value;
  return `${value.slice(0, Math.max(0, limit - 1))}\u2026`;
}
function createTeamTaskHooks(deps) {
  const remembered = /* @__PURE__ */ new Map();
  const remember = (taskId, description) => {
    remembered.delete(taskId);
    remembered.set(taskId, description);
    while (remembered.size > MAX_REMEMBERED_DESCRIPTIONS) {
      const oldest = remembered.keys().next();
      if (oldest.done === true) break;
      remembered.delete(oldest.value);
    }
  };
  const summaryLimit = (() => {
    const configured = deps.maxSummaryChars;
    if (configured === void 0 || !Number.isFinite(configured)) return DEFAULT_MAX_SUMMARY_CHARS;
    return Math.max(80, Math.trunc(configured));
  })();
  const activeFacade = () => {
    try {
      return deps.team();
    } catch (error) {
      deps.log(`dsh-remote-team: \u8BFB\u53D6 agentTeams \u5931\u8D25\uFF08${messageOf2(error)}\uFF09\uFF1B\u8FD9\u6B21\u4E0D\u8BB0\u770B\u677F`);
      return void 0;
    }
  };
  const isTeamMember = (facade, agent) => {
    try {
      const membership = facade.membership(agent);
      return membership.role === "lead" || membership.role === "teammate";
    } catch (error) {
      deps.log(`dsh-remote-team: \u8C03\u7528\u65B9\u4E0D\u5728 Agent Teams \u91CC\uFF08${messageOf2(error)}\uFF09\uFF1B\u8FD9\u6B21\u4E0D\u8BB0\u770B\u677F`);
      return false;
    }
  };
  return {
    async begin(agent, request) {
      if (agent === void 0) return void 0;
      const facade = activeFacade();
      if (facade === void 0) return void 0;
      if (!isTeamMember(facade, agent)) return void 0;
      const rawSubject = typeof request.subject === "string" ? request.subject.trim() : "";
      const subject = clampText(
        `${TEAM_SUBJECT_PREFIX}${rawSubject === "" ? "\u8FDC\u7AEF worker \u6D3E\u53D1" : rawSubject}`,
        MAX_TEAM_SUBJECT_CHARS
      );
      const description = clampText(
        typeof request.description === "string" ? request.description : "",
        MAX_TEAM_DESCRIPTION_CHARS
      );
      let created;
      try {
        created = await facade.createTask(agent, { subject, description });
      } catch (error) {
        deps.log(`dsh-remote-team: \u521B\u5EFA\u770B\u677F\u4EFB\u52A1\u5931\u8D25\uFF08${messageOf2(error)}\uFF09\uFF1B\u8FDC\u7AEF\u5DE5\u4F5C\u7EE7\u7EED`);
        return void 0;
      }
      if (typeof created?.id !== "string" || created.id === "") {
        deps.log("dsh-remote-team: createTask \u6CA1\u6709\u8FD4\u56DE\u4EFB\u52A1 id\uFF1B\u8FDC\u7AEF\u5DE5\u4F5C\u7EE7\u7EED");
        return void 0;
      }
      remember(created.id, description);
      try {
        const claimed = await facade.updateTask(agent, {
          taskId: created.id,
          expectedRevision: created.revision,
          action: "claim"
        });
        return { taskId: created.id, revision: claimed.revision };
      } catch (error) {
        remembered.delete(created.id);
        deps.log(`dsh-remote-team: \u8BA4\u9886\u770B\u677F\u4EFB\u52A1 ${created.id} \u5931\u8D25\uFF08${messageOf2(error)}\uFF09\uFF1B\u8FDC\u7AEF\u5DE5\u4F5C\u7EE7\u7EED`);
        return void 0;
      }
    },
    async finish(agent, token, result) {
      if (agent === void 0 || token === void 0) return;
      const facade = activeFacade();
      if (facade === void 0) {
        remembered.delete(token.taskId);
        return;
      }
      const summary = clampText(
        [
          `\u8FDC\u7AEF\u7ED3\u679C\uFF1A\u6210\u529F ${result.ok} \u4E2A\uFF0C\u5931\u8D25 ${result.failed} \u4E2A`,
          typeof result.summary === "string" ? result.summary : ""
        ].filter((part) => part !== "").join("\n"),
        summaryLimit
      );
      const original = remembered.get(token.taskId) ?? "";
      const description = clampText(
        original === "" ? summary : `${original}

${summary}`,
        MAX_TEAM_DESCRIPTION_CHARS
      );
      let edited;
      try {
        edited = await facade.updateTask(agent, {
          taskId: token.taskId,
          expectedRevision: token.revision,
          action: "edit",
          description
        });
      } catch (error) {
        remembered.delete(token.taskId);
        deps.log(`dsh-remote-team: \u5199\u7ED3\u679C\u6458\u8981\u5931\u8D25\uFF08${messageOf2(error)}\uFF09\uFF1B\u770B\u677F\u4EFB\u52A1\u4FDD\u6301\u539F\u72B6`);
        return;
      }
      const nextRevision = Number(edited?.revision);
      if (!Number.isFinite(nextRevision)) {
        remembered.delete(token.taskId);
        deps.log(`dsh-remote-team: edit \u6CA1\u6709\u8FD4\u56DE\u6709\u6548 revision\uFF08${String(edited?.revision)}\uFF09\uFF1B\u4E0D complete`);
        return;
      }
      try {
        await facade.updateTask(agent, {
          taskId: token.taskId,
          expectedRevision: nextRevision,
          action: "complete"
        });
        deps.log(`dsh-remote-team: \u770B\u677F\u4EFB\u52A1 ${token.taskId} \u5DF2\u5B8C\u6210\uFF08\u6210\u529F ${result.ok} / \u5931\u8D25 ${result.failed}\uFF09`);
      } catch (error) {
        deps.log(`dsh-remote-team: complete \u770B\u677F\u4EFB\u52A1 ${token.taskId} \u5931\u8D25\uFF08${messageOf2(error)}\uFF09`);
      } finally {
        remembered.delete(token.taskId);
      }
    }
  };
}

// src/transfer-client.ts
import { createHash as createHash5, randomBytes as randomBytes2 } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, open as open2, rename, rm, stat } from "node:fs/promises";
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
function abortError2() {
  const error = new Error("transfer aborted");
  error.name = "AbortError";
  return error;
}
function isAbortError2(error) {
  return error instanceof Error && error.name === "AbortError";
}
function throwIfAborted(signal) {
  if (signal?.aborted === true) throw abortError2();
}
function abortable(work, signal) {
  if (signal === void 0) return work;
  if (signal.aborted === true) return Promise.reject(abortError2());
  return new Promise((resolve2, reject) => {
    const onAbort = () => {
      reject(abortError2());
    };
    signal.addEventListener("abort", onAbort, { once: true });
    work.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve2(value);
      },
      (error) => {
        signal.removeEventListener("abort", onAbort);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    );
  });
}
function sleep(ms, signal) {
  if (signal === void 0) return new Promise((resolve2) => setTimeout(resolve2, ms));
  throwIfAborted(signal);
  return new Promise((resolve2, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve2();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortError2());
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
  return createHash5("sha256").update(data).digest("hex");
}
function isMissingFile(error) {
  return error?.code === "ENOENT";
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
    throwIfAborted(options.signal);
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
  throwIfAborted(signal);
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
      throwIfAborted(signal);
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
async function hashFile(path, signal) {
  const hash = createHash5("sha256");
  const stream = createReadStream(path);
  try {
    for await (const chunk of stream) {
      throwIfAborted(signal);
      hash.update(chunk);
    }
  } finally {
    stream.destroy();
  }
  return hash.digest("hex");
}
async function uploadFile(request, localPath, remotePath, options = {}) {
  throwIfAborted(options.signal);
  const info = await stat(localPath);
  if (!info.isFile()) throw new Error(`transfer: "${localPath}" is not a regular file`);
  const sha256 = await hashFile(localPath, options.signal);
  const handle = await open2(localPath, "r");
  try {
    return await uploadSource(request, remotePath, {
      size: info.size,
      sha256,
      read: async (offset, length) => {
        const buffer = Buffer.allocUnsafe(length);
        let filled = 0;
        while (filled < length) {
          const { bytesRead } = await handle.read(buffer, filled, length - filled, offset + filled);
          if (bytesRead === 0) break;
          filled += bytesRead;
        }
        if (filled !== length) throw new Error("transfer: local file changed size while uploading");
        return buffer.subarray(0, filled);
      }
    }, options);
  } finally {
    await handle.close().catch(() => {
    });
  }
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
  throwIfAborted(options.signal);
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
async function writeAt(handle, offset, data) {
  let written = 0;
  while (written < data.length) {
    const { bytesWritten } = await handle.write(data, written, data.length - written, offset + written);
    if (bytesWritten <= 0) throw new Error("transfer: local write made no progress");
    written += bytesWritten;
  }
}
async function replaceFile(tempPath, targetPath) {
  try {
    await rename(tempPath, targetPath);
    return;
  } catch (error) {
    const code = error.code;
    const retryable = code === "EEXIST" || code === "EPERM" || code === "EACCES" || code === "EBUSY";
    if (!retryable) throw error;
  }
  await rm(targetPath, { force: true });
  await rename(tempPath, targetPath);
}
async function downloadToFile(request, remotePath, localPath, options = {}) {
  const startedAt = Date.now();
  throwIfAborted(options.signal);
  if (options.overwrite === false) {
    const existing = await stat(localPath).catch((error) => {
      if (isMissingFile(error)) return void 0;
      throw error;
    });
    if (existing !== void 0) {
      throw new Error(`transfer: refusing to overwrite existing "${localPath}"`);
    }
  }
  await mkdir(dirname3(localPath), { recursive: true });
  const tempPath = `${localPath}.${randomBytes2(6).toString("hex")}.dshremote-tmp`;
  const handle = await open2(tempPath, "wx");
  let closed = false;
  let renamed = false;
  try {
    const size = await remoteSizeOf(request, remotePath, options);
    const chunks = planChunks(size, options.chunkSize ?? DEFAULT_CHUNK_BYTES);
    let effectiveSize = size;
    let doneBytes = 0;
    const sink = {
      write: async (offset, data) => {
        await writeAt(handle, offset, data);
      }
    };
    await runPool(chunks.length, resolveConcurrency(options.concurrency), async (index) => {
      const chunk = chunks[index];
      if (chunk === void 0) return;
      throwIfAborted(options.signal);
      const fetched = await fetchChunk(request, remotePath, chunk, options);
      const writable = Math.max(0, Math.min(fetched.data.length, effectiveSize - chunk.offset));
      if (writable > 0) await sink.write(chunk.offset, fetched.data.subarray(0, writable));
      if (fetched.eof && fetched.data.length < chunk.length) {
        effectiveSize = Math.min(effectiveSize, chunk.offset + fetched.data.length);
      }
      doneBytes += fetched.data.length;
      try {
        options.onProgress?.(doneBytes, size);
      } catch {
      }
    });
    if (effectiveSize < size) await handle.truncate(effectiveSize);
    await handle.close();
    closed = true;
    throwIfAborted(options.signal);
    const sha256 = await hashFile(tempPath, options.signal);
    await verifyRemoteHash(request, remotePath, sha256, options);
    await replaceFile(tempPath, localPath);
    renamed = true;
    const durationMs = Math.max(0, Date.now() - startedAt);
    return {
      bytes: effectiveSize,
      sha256,
      size: effectiveSize,
      durationMs,
      rateMbps: rateMbpsOf(effectiveSize, durationMs)
    };
  } finally {
    if (!closed) await handle.close().catch(() => {
    });
    if (!renamed) await rm(tempPath, { force: true }).catch(() => {
    });
  }
}

// src/journal.ts
var DEFAULT_MAX_BYTES = 8 * 1024 * 1024;
function formatJournal(view) {
  if (view.unsupported === true) {
    return [
      "\u5BF9\u7AEF\u8FD8\u6CA1\u6709 journal.read\uFF08\u9700\u8981\u53D7\u63A7\u7AEF r14+\uFF09\u3002",
      "\u73B0\u5728\u80FD\u7528\u7684\u66FF\u4EE3\uFF1Aremote_agent_events \u8BFB\u67D0\u4E2A\u4F1A\u8BDD\u7684\u4E8B\u4EF6\u6D41\uFF0C\u6216 remote_exec \u76F4\u63A5\u770B\u6587\u4EF6\u3002"
    ];
  }
  const entries = Array.isArray(view.entries) ? view.entries : [];
  const lines = [
    `remote journal \u2014 \u5171\u8BB0\u5F55 ${view.written ?? "?"} \u6761\uFF0C\u672C\u6B21 ${view.count ?? entries.length} \u6761${view.tail === true ? "\uFF08\u5C3E\u90E8\uFF09" : ""}\uFF0C\u6E38\u6807 nextSeq=${view.nextSeq ?? "?"}`
  ];
  if (entries.length === 0) lines.push("\uFF08\u6CA1\u6709\u65B0\u6761\u76EE\uFF09");
  for (const entry of entries) {
    const time = typeof entry.at === "string" ? entry.at.slice(11, 19) : "--:--:--";
    const kind = String(entry.kind ?? "?");
    lines.push(`#${entry.seq ?? "?"} ${time} ${kind.padEnd(9)} ${String(entry.summary ?? "")}`);
  }
  lines.push("\u4E0B\u6B21\u7701\u7565 from_seq \u5373\u4ECE\u8FD9\u91CC\u7EE7\u7EED\uFF1B\u8981\u7EC6\u8282\u52A0 full=true\u3002");
  return lines;
}

// src/capabilities.ts
var asRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value) ? value : void 0;
var asString = (value) => typeof value === "string" && value !== "" ? value : void 0;
var asArray = (value) => Array.isArray(value) ? value : [];
function parseCatalog(reply) {
  const available = reply.available !== false;
  const presetId = asString(reply.presetId) ?? "";
  const tools = [];
  for (const raw of asArray(reply.tools)) {
    const row = asRecord(raw);
    const name2 = asString(row?.name);
    if (row === void 0 || name2 === void 0) continue;
    const reason = asString(row.reason);
    tools.push({
      name: name2,
      description: asString(row.description) ?? "",
      parameters: asRecord(row.parameters) ?? { type: "object", properties: {} },
      origin: row.origin === "global" ? "global" : "preset",
      callable: row.callable !== false,
      ...reason === void 0 ? {} : { reason }
    });
  }
  const presets = [];
  for (const raw of asArray(reply.presets)) {
    const row = asRecord(raw);
    const id = asString(row?.id);
    if (row === void 0 || id === void 0) continue;
    presets.push({
      id,
      ...asString(row.name) === void 0 ? {} : { name: String(row.name) },
      ...asString(row.description) === void 0 ? {} : { description: String(row.description) },
      isDefault: row.isDefault === true,
      ...asString(row.broken) === void 0 ? {} : { broken: String(row.broken) }
    });
  }
  const plugins = [];
  for (const raw of asArray(reply.plugins)) {
    const row = asRecord(raw);
    const presetIdOfRow = asString(row?.presetId);
    if (row === void 0 || presetIdOfRow === void 0) continue;
    const rows = [];
    for (const rawRow of asArray(row.rows)) {
      const pluginRow = asRecord(rawRow);
      const name2 = asString(pluginRow?.name);
      if (pluginRow === void 0 || name2 === void 0) continue;
      const enabled = pluginRow.enabled;
      rows.push({
        id: typeof pluginRow.id === "string" ? pluginRow.id : null,
        name: name2,
        enabled: enabled === "conditional" ? "conditional" : enabled !== false
      });
    }
    plugins.push({
      presetId: presetIdOfRow,
      ...asString(row.name) === void 0 ? {} : { name: String(row.name) },
      isDefault: row.isDefault === true,
      ...asString(row.broken) === void 0 ? {} : { broken: String(row.broken) },
      rows
    });
  }
  const sessions = [];
  for (const raw of asArray(reply.sessions)) {
    const row = asRecord(raw);
    const sessionId = asString(row?.sessionId);
    if (row === void 0 || sessionId === void 0) continue;
    sessions.push({
      sessionId,
      ...asString(row.presetId) === void 0 ? {} : { presetId: String(row.presetId) },
      ...asString(row.status) === void 0 ? {} : { status: String(row.status) },
      ...asString(row.cwd) === void 0 ? {} : { cwd: String(row.cwd) }
    });
  }
  const subagentProviders = asArray(reply.subagentProviders).map((value) => asString(value)).filter((value) => value !== void 0);
  return {
    available,
    ...asString(reply.reason) === void 0 ? {} : { reason: String(reply.reason) },
    ...asString(reply.build) === void 0 ? {} : { build: String(reply.build) },
    presetId,
    presets,
    tools,
    plugins,
    sessions,
    subagentProviders
  };
}
function parseCallResult(reply) {
  return {
    content: asArray(reply.content),
    ...typeof reply.durationMs === "number" ? { durationMs: reply.durationMs } : {},
    ...reply.value === void 0 ? {} : { value: reply.value }
  };
}
function contentToText(blocks) {
  const parts = [];
  for (const raw of blocks) {
    const block = asRecord(raw);
    if (block === void 0) continue;
    const type = asString(block.type) ?? "unknown";
    if (type === "text") {
      const text2 = asString(block.text);
      if (text2 !== void 0) parts.push(text2);
      continue;
    }
    const label = asString(block.title) ?? asString(block.name) ?? asString(block.alt) ?? asString(block.text);
    parts.push(label === void 0 ? `[${type}]` : `[${type}: ${label}]`);
  }
  return parts.length === 0 ? "(the peer returned no content)" : parts.join("\n");
}
function proxyResultText(result) {
  const body = contentToText(result.content);
  return result.durationMs === void 0 ? body : `${body}

(executed on the remote host in ${result.durationMs} ms)`;
}
function createProxySpecs(catalog, call, taken) {
  const specs = [];
  const skipped = [];
  const seen = /* @__PURE__ */ new Set();
  for (const tool of catalog.tools) {
    if (seen.has(tool.name)) {
      skipped.push({ name: tool.name, reason: "the peer listed it twice" });
      continue;
    }
    seen.add(tool.name);
    if (!tool.callable) {
      skipped.push({ name: tool.name, reason: tool.reason ?? "the peer marked it not callable" });
      continue;
    }
    if (taken(tool.name)) {
      skipped.push({ name: tool.name, reason: "a local plugin already owns this global tool name", local: true });
      continue;
    }
    specs.push({
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
      call: (args, signal) => call(tool.name, args, signal)
    });
  }
  specs.sort((a, b) => a.name.localeCompare(b.name));
  skipped.sort((a, b) => a.name.localeCompare(b.name));
  return { specs, skipped };
}
function oneLine(description, limit = 100) {
  const flat = description.replace(/\s+/gu, " ").trim();
  const sentence = flat.split(/(?<=[.!。！?])\s/u)[0] ?? flat;
  const body = sentence.length > 0 ? sentence : flat;
  return body.length <= limit ? body : `${body.slice(0, limit)}\u2026`;
}
function formatCatalog(catalog, options = {}) {
  const shadowed = options.shadowed ?? /* @__PURE__ */ new Set();
  const lines = [];
  if (!catalog.available) {
    return `\u8FDC\u7AEF\u80FD\u529B\u76EE\u5F55\u4E0D\u53EF\u7528\uFF1A${catalog.reason ?? "\u5BF9\u7AEF\u6CA1\u6709\u56DE\u7B54 caps.list"}`;
  }
  if (options.tool !== void 0) {
    const wanted = catalog.tools.find((tool) => tool.name === options.tool);
    if (wanted === void 0) return `\u8FDC\u7AEF\u80FD\u529B\u76EE\u5F55\u91CC\u6CA1\u6709\u540D\u4E3A ${options.tool} \u7684\u5DE5\u5177`;
    lines.push(`## ${wanted.name}`);
    lines.push(wanted.description === "" ? "(no description)" : wanted.description);
    lines.push(`- origin: ${wanted.origin}`);
    lines.push(`- callable: ${wanted.callable ? "yes" : `no (${wanted.reason ?? "refused"})`}`);
    lines.push(`- local mirror: ${wanted.callable && !shadowed.has(wanted.name) ? wanted.name : shadowed.has(wanted.name) ? "hidden \u2014 a local tool owns this name" : "none"}`);
    lines.push("- parameters:");
    lines.push("```json");
    lines.push(JSON.stringify(wanted.parameters, null, 2));
    lines.push("```");
    return lines.join("\n");
  }
  const callable = catalog.tools.filter((tool) => tool.callable);
  const refused = catalog.tools.filter((tool) => !tool.callable);
  const preset = catalog.presets.find((row) => row.id === catalog.presetId);
  const defaultPreset = catalog.presets.find((row) => row.isDefault)?.id;
  lines.push("## \u8FDC\u7AEF capability \u76EE\u5F55");
  lines.push(
    `preset ${catalog.presetId}${preset?.name === void 0 ? "" : ` (${preset.name})`}${defaultPreset === void 0 ? "" : ` \xB7 \u90E8\u7F72\u9ED8\u8BA4 preset: ${defaultPreset}`}${catalog.build === void 0 ? "" : ` \xB7 build ${catalog.build}`} \xB7 tools ${catalog.tools.length}`
  );
  lines.push("");
  lines.push("### \u53EF\u76F4\u63A5\u8C03\u7528\uFF08\u672C\u673A\u5DF2\u6709\u540C\u540D\u5DE5\u5177\u65F6\uFF0C\u672C\u5730\u5DE5\u5177\u4F18\u5148\uFF09");
  if (callable.length === 0) lines.push("(none)");
  for (const tool of callable) {
    const tag = shadowed.has(tool.name) ? "  [\u672C\u673A\u540C\u540D\u5DE5\u5177\u4F18\u5148\uFF0C\u5DF2\u9690\u85CF]" : "";
    const origin = tool.origin === "global" ? "  (host)" : "";
    lines.push(`- ${tool.name}${origin} \u2014 ${oneLine(tool.description)}${tag}`);
  }
  if (refused.length > 0) {
    lines.push("");
    lines.push("### \u8FDC\u7AEF\u6807\u8BB0\u4E3A\u4E0D\u53EF\u8C03\u7528");
    for (const tool of refused) lines.push(`- ${tool.name} \u2014 ${tool.reason ?? "refused"}`);
  }
  lines.push("");
  lines.push("### Agent preset\uFF08\u5B50\u667A\u80FD\u4F53\u7C7B\u578B\uFF09");
  for (const row of catalog.presets) {
    lines.push(
      `- ${row.id}${row.isDefault ? " (default)" : ""}${row.name === void 0 ? "" : ` \u2014 ${row.name}`}${row.broken === void 0 ? "" : `  [broken: ${oneLine(row.broken, 80)}]`}`
    );
  }
  if (catalog.subagentProviders.length > 0) {
    lines.push("");
    lines.push(`### \u5B50\u667A\u80FD\u4F53 provider: ${catalog.subagentProviders.join(", ")}`);
  }
  if (catalog.plugins.length > 0) {
    lines.push("");
    lines.push("### \u63D2\u4EF6\u6E05\u5355\uFF08\u6309 preset\uFF09");
    for (const row of catalog.plugins) {
      const enabled = row.rows.filter((plugin) => plugin.enabled !== false).length;
      const names = row.rows.filter((plugin) => plugin.enabled !== false).map((plugin) => plugin.id ?? plugin.name).slice(0, 12);
      lines.push(
        `- ${row.presetId}${row.isDefault ? " (default)" : ""}: ${enabled}/${row.rows.length} enabled${names.length === 0 ? "" : ` \u2014 ${names.join(", ")}${row.rows.length > names.length ? ", \u2026" : ""}`}${row.broken === void 0 ? "" : `  [broken: ${oneLine(row.broken, 80)}]`}`
      );
    }
  }
  if (catalog.sessions.length > 0) {
    lines.push("");
    lines.push("### \u8FDC\u7AEF\u6D3B\u8DC3\u4F1A\u8BDD\uFF08\u53EA\u8BFB\u4FE1\u606F\uFF0C\u672C\u5DE5\u5177\u4E0D\u4F1A\u9A71\u52A8\u5B83\u4EEC\uFF09");
    for (const row of catalog.sessions.slice(0, 20)) {
      lines.push(
        `- ${row.sessionId}${row.presetId === void 0 ? "" : ` \xB7 preset ${row.presetId}`}${row.status === void 0 ? "" : ` \xB7 ${row.status}`}${row.cwd === void 0 ? "" : ` \xB7 ${row.cwd}`}`
      );
    }
  }
  lines.push("");
  lines.push(
    "\u8C03\u7528\u65B9\u5F0F\uFF1A\u4E0A\u9762\u5217\u51FA\u7684\u5DE5\u5177\u5DF2\u76F4\u63A5\u6CE8\u518C\u6210\u672C\u673A\u5DE5\u5177\uFF0C\u53EF\u76F4\u63A5 function call\uFF1B\u8981\u6309\u540D\u5B57\u8C03\u7528\uFF08\u4F8B\u5982\u672C\u673A\u540C\u540D\u5DE5\u5177\u906E\u6321\u65F6\uFF09\uFF0C\u7528 `remote_tool_call(name, arguments)`\u3002"
  );
  return lines.join("\n");
}

// src/cost-report.ts
import { randomUUID as randomUUID2 } from "node:crypto";
import { mkdirSync as mkdirSync3, readFileSync as readFileSync2, renameSync, unlinkSync, writeFileSync as writeFileSync3 } from "node:fs";
import { basename, dirname as dirname4, join as join2 } from "node:path";
var MAX_STORE_RECORDS = 2e3;
var MAX_SNAPSHOT_RECORDS = 2e3;
var MAX_SNAPSHOT_BYTES = 45e4;
var MAX_SOURCE_NAME = 64;
var MAX_AGE_MS = 30 * 864e5;
var MAX_FUTURE_MS = 3e5;
var MAX_TOKEN_COUNT = 1e12;
var MAX_RECORD_ID = 128;
var STORE_VERSION = 1;
var LOCAL_PROVIDER_IDS = /* @__PURE__ */ new Set([
  "local",
  "lmstudio",
  "ollama",
  "jan",
  "gpt4all",
  "koboldcpp",
  "llamacpp",
  "llama-cpp",
  "localai",
  "vllm",
  "sglang",
  "tabbyapi",
  "lmdeploy",
  "oobabooga",
  "text-generation-webui",
  "llama-server"
]);
var LOCAL_MODEL_PREFIXES = [
  "lmstudio:",
  "lmstudio/",
  "ollama:",
  "ollama/",
  "jan:",
  "jan/",
  "gpt4all:",
  "gpt4all/",
  "koboldcpp:",
  "koboldcpp/",
  "llamacpp:",
  "llamacpp/",
  "llama-cpp:",
  "llama-cpp/",
  "localai:",
  "localai/",
  "vllm:",
  "vllm/",
  "sglang:",
  "sglang/",
  "tabbyapi:",
  "tabbyapi/",
  "lmdeploy:",
  "oobabooga/",
  "text-generation-webui/",
  "llama-server:",
  "gguf:",
  "local:"
];
function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function tokenCount(value) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= MAX_TOKEN_COUNT ? value : null;
}
function timestampMs(value) {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) return Math.trunc(value);
  if (typeof value === "string" && value !== "") {
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
  }
  return null;
}
function modelText(value) {
  return value.normalize("NFKC").toLowerCase().trim();
}
function isLocalInference(provider, model) {
  const raw = provider.trim().toLowerCase();
  const normalized = raw.startsWith("llm-") ? raw.slice(4) : raw;
  if (LOCAL_PROVIDER_IDS.has(normalized)) return true;
  const name2 = modelText(model);
  return LOCAL_MODEL_PREFIXES.some((prefix) => name2.startsWith(prefix));
}
function sanitizeSample(raw, sessionId) {
  if (!isObject(raw)) return null;
  if (typeof sessionId !== "string" || sessionId === "") return null;
  const provider = typeof raw.provider === "string" ? raw.provider.trim() : "";
  const model = typeof raw.model === "string" ? raw.model.trim() : "";
  if (provider === "" || model === "") return null;
  if (isLocalInference(provider, model)) return null;
  const seq = typeof raw.seq === "number" ? raw.seq : Number.NaN;
  if (!Number.isSafeInteger(seq) || seq < 0) return null;
  const id = `${sessionId}:${seq}`;
  if (id.length > MAX_RECORD_ID) return null;
  const at = timestampMs(raw.at);
  if (at === null || at > Date.now() + MAX_FUTURE_MS) return null;
  const buckets = isObject(raw.usage) ? raw.usage : raw;
  const cachedRaw = buckets.cacheRead ?? buckets.cached ?? 0;
  const input = tokenCount(buckets.input);
  const output = tokenCount(buckets.output);
  const cached = tokenCount(cachedRaw);
  if (input === null || output === null || cached === null) return null;
  const cacheWrite = buckets.cacheWrite === void 0 ? void 0 : tokenCount(buckets.cacheWrite);
  if (cacheWrite === null) return null;
  const reasoning = buckets.reasoning === void 0 ? void 0 : tokenCount(buckets.reasoning);
  if (reasoning === null) return null;
  return {
    id,
    at,
    provider,
    model,
    input,
    output,
    cached,
    ...cacheWrite === void 0 ? {} : { cacheWrite },
    ...reasoning === void 0 ? {} : { reasoning },
    sessionId,
    turn: safeSmallInt(raw.turn),
    step: safeSmallInt(raw.step)
  };
}
function safeSmallInt(value) {
  const number = typeof value === "number" ? value : Number.NaN;
  return Number.isFinite(number) && number >= 0 ? Math.trunc(number) : 0;
}
function sourceNameOf(value) {
  if (typeof value !== "string") return null;
  const name2 = value.trim();
  if (name2.length < 1 || name2.length > MAX_SOURCE_NAME) return null;
  return name2;
}
function isoAt(ms) {
  return new Date(ms).toISOString();
}
function sortRecords(records) {
  return [...records].sort((a, b) => a.at === b.at ? a.id < b.id ? -1 : a.id > b.id ? 1 : 0 : a.at - b.at);
}
function dedupeRecords(records) {
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const record2 of records) {
    if (seen.has(record2.id)) continue;
    seen.add(record2.id);
    out.push(record2);
  }
  return sortRecords(out);
}
function snapshotSafeRecord(record2, now) {
  if (typeof record2.id !== "string" || record2.id === "" || record2.id.length > MAX_RECORD_ID) return false;
  if (typeof record2.provider !== "string" || record2.provider.trim() === "") return false;
  if (typeof record2.model !== "string" || record2.model.trim() === "") return false;
  if (isLocalInference(record2.provider, record2.model)) return false;
  if (!Number.isFinite(record2.at) || record2.at <= 0 || record2.at > now + MAX_FUTURE_MS) return false;
  if (tokenCount(record2.input) === null || tokenCount(record2.output) === null || tokenCount(record2.cached) === null) return false;
  if (record2.cacheWrite !== void 0 && tokenCount(record2.cacheWrite) === null) return false;
  if (record2.reasoning !== void 0 && tokenCount(record2.reasoning) === null) return false;
  return true;
}
function normalizePreserved(raw, seen) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const item of raw) {
    if (!isObject(item)) continue;
    const source = sourceNameOf(item.source);
    if (source === null || seen.has(source)) continue;
    const hasDays = isObject(item.days);
    const hasRecords = Array.isArray(item.records);
    if (hasDays === hasRecords) continue;
    seen.add(source);
    out.push(item);
  }
  return out;
}
function buildSnapshot(fetchedAt, ours, preserved) {
  const ourSources = ours.map((entry) => ({
    source: entry.source,
    records: entry.records.map((record2) => ({
      id: record2.id,
      at: isoAt(record2.at),
      provider: record2.provider,
      model: record2.model,
      input: record2.input,
      output: record2.output,
      cached: record2.cached,
      ...record2.cacheWrite === void 0 ? {} : { cacheWrite: record2.cacheWrite },
      ...record2.reasoning === void 0 ? {} : { reasoning: record2.reasoning }
    }))
  }));
  const sources = [...ourSources, ...preserved].sort((a, b) => {
    const left = String(a.source);
    const right = String(b.source);
    return left < right ? -1 : left > right ? 1 : 0;
  });
  return { fetchedAt, sources };
}
function snapshotBytes(snapshot) {
  return Buffer.byteLength(JSON.stringify(snapshot), "utf8");
}
function flattenOwn(ours) {
  const flat = [];
  for (const entry of ours) {
    for (const record2 of entry.records) flat.push({ source: entry.source, record: record2 });
  }
  flat.sort((a, b) => a.record.at === b.record.at ? a.record.id < b.record.id ? -1 : a.record.id > b.record.id ? 1 : 0 : a.record.at - b.record.at);
  return flat;
}
function regroupOwn(flat, sources) {
  const grouped = /* @__PURE__ */ new Map();
  for (const name2 of sources) grouped.set(name2, []);
  for (const { source, record: record2 } of flat) grouped.get(source)?.push(record2);
  return sources.map((source) => ({ source, records: grouped.get(source) ?? [] }));
}
function keepNewest(flat, count) {
  return count >= flat.length ? flat : flat.slice(flat.length - count);
}
function composeSnapshot(input) {
  const now = Date.now();
  let fetchedAt = Number.isFinite(input.fetchedAt) ? Math.trunc(input.fetchedAt) : now;
  if (fetchedAt > now + MAX_FUTURE_MS || now - fetchedAt > MAX_AGE_MS) fetchedAt = now;
  const stamp = isoAt(fetchedAt);
  const ours = [];
  const seenOwn = /* @__PURE__ */ new Set();
  for (const entry of input.sources ?? []) {
    const name2 = sourceNameOf(entry.source);
    if (name2 === null || seenOwn.has(name2) || !Array.isArray(entry.records)) continue;
    seenOwn.add(name2);
    const records = dedupeRecords(entry.records).filter((record2) => snapshotSafeRecord(record2, now));
    ours.push({ source: name2, records });
  }
  ours.sort((a, b) => a.source < b.source ? -1 : a.source > b.source ? 1 : 0);
  if (ours.length === 0) ours.push({ source: "remote/default", records: [] });
  if (ours.length > 8) ours.length = 8;
  const seenSources = new Set(ours.map((entry) => entry.source));
  const preserved = normalizePreserved(input.preserved, seenSources).sort((a, b) => {
    const left = String(a.source);
    const right = String(b.source);
    return left < right ? -1 : left > right ? 1 : 0;
  }).slice(0, Math.max(0, 8 - ours.length));
  const ownNames = ours.map((entry) => entry.source);
  let flat = flattenOwn(ours);
  if (flat.length > MAX_SNAPSHOT_RECORDS) flat = keepNewest(flat, MAX_SNAPSHOT_RECORDS);
  let built = buildSnapshot(stamp, regroupOwn(flat, ownNames), preserved);
  let bytes = snapshotBytes(built);
  if (bytes > MAX_SNAPSHOT_BYTES) {
    let low = 0;
    let high = flat.length;
    let keep = 0;
    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      const candidate = buildSnapshot(stamp, regroupOwn(keepNewest(flat, mid), ownNames), preserved);
      if (snapshotBytes(candidate) <= MAX_SNAPSHOT_BYTES) {
        keep = mid;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    flat = keepNewest(flat, keep);
    built = buildSnapshot(stamp, regroupOwn(flat, ownNames), preserved);
    bytes = snapshotBytes(built);
  }
  let removable = preserved.length;
  while (bytes > MAX_SNAPSHOT_BYTES && removable > 0) {
    removable -= 1;
    built = buildSnapshot(stamp, regroupOwn(flat, ownNames), preserved.slice(0, removable));
    bytes = snapshotBytes(built);
  }
  return { json: built, bytes };
}
function writeJsonAtomic(file, value, log) {
  const dir = dirname4(file);
  const temp = join2(dir, `.${basename(file)}.${process.pid}.${randomUUID2().slice(0, 8)}.tmp`);
  try {
    mkdirSync3(dir, { recursive: true });
    writeFileSync3(temp, `${JSON.stringify(value)}
`, "utf8");
    renameSync(temp, file);
  } catch (error) {
    try {
      unlinkSync(temp);
    } catch {
    }
    log?.(`cost-report: could not write ${file} (${error instanceof Error ? error.message : String(error)})`);
  }
}
function readJsonFile(file) {
  try {
    return JSON.parse(readFileSync2(file, "utf8"));
  } catch {
    return null;
  }
}
function loadRecord(raw) {
  if (!isObject(raw)) return null;
  const id = typeof raw.id === "string" ? raw.id : "";
  const sessionId = typeof raw.sessionId === "string" ? raw.sessionId : "";
  const provider = typeof raw.provider === "string" ? raw.provider : "";
  const model = typeof raw.model === "string" ? raw.model : "";
  if (id === "" || id.length > MAX_RECORD_ID || sessionId === "" || provider === "" || model === "") return null;
  const at = timestampMs(raw.at);
  const input = tokenCount(raw.input);
  const output = tokenCount(raw.output);
  const cached = tokenCount(raw.cached);
  if (at === null || input === null || output === null || cached === null) return null;
  const cacheWrite = raw.cacheWrite === void 0 ? void 0 : tokenCount(raw.cacheWrite);
  if (cacheWrite === null) return null;
  const reasoning = raw.reasoning === void 0 ? void 0 : tokenCount(raw.reasoning);
  if (reasoning === null) return null;
  return {
    id,
    at,
    provider,
    model,
    input,
    output,
    cached,
    ...cacheWrite === void 0 ? {} : { cacheWrite },
    ...reasoning === void 0 ? {} : { reasoning },
    sessionId,
    turn: safeSmallInt(raw.turn),
    step: safeSmallInt(raw.step)
  };
}
var RemoteCostStore = class {
  /** The peer's snapshot source name, normalized to a legal value. */
  sourceName;
  /** Prefix that marks a snapshot source as ours (exact by convention). */
  sourcePrefix;
  storeFile;
  snapshotFile;
  log;
  sessions = /* @__PURE__ */ new Map();
  loaded = false;
  chain = Promise.resolve();
  /**
   * @param options - file locations, source naming and an optional logger.
   */
  constructor(options) {
    this.storeFile = options.storeFile;
    this.snapshotFile = options.snapshotFile;
    this.log = options.log;
    const prefix = options.sourcePrefix === "" ? "remote/" : options.sourcePrefix;
    this.sourcePrefix = prefix;
    const name2 = sourceNameOf(options.sourceName);
    this.sourceName = name2 ?? "remote/default";
  }
  /** Load the store, tolerating a missing, corrupt or future-version file. */
  load() {
    this.loaded = true;
    this.sessions.clear();
    const parsed = readJsonFile(this.storeFile);
    if (!isObject(parsed) || parsed.version !== STORE_VERSION || !isObject(parsed.sessions)) return;
    for (const [sessionId, rawSession] of Object.entries(parsed.sessions)) {
      if (sessionId === "" || !isObject(rawSession) || !Array.isArray(rawSession.records)) continue;
      const cursor = safeSmallInt(rawSession.cursor);
      const records = [];
      for (const rawRecord of rawSession.records) {
        const record2 = loadRecord(rawRecord);
        if (record2 !== null && record2.sessionId === sessionId) records.push(record2);
      }
      if (cursor === 0 && records.length === 0) continue;
      this.sessions.set(sessionId, { cursor, records });
    }
    this.trim();
  }
  /** The last peer event sequence accounted for in a session (0 when new). */
  cursorOf(sessionId) {
    this.ensureLoaded();
    return this.sessions.get(sessionId)?.cursor ?? 0;
  }
  /** How much this plugin has recorded for this peer (no IO, no network). */
  summary() {
    this.ensureLoaded();
    let records = 0;
    let newest = 0;
    for (const session of this.sessions.values()) {
      records += session.records.length;
      for (const record2 of session.records) {
        if (record2.at > newest) newest = record2.at;
      }
    }
    return {
      source: this.sourceName,
      records,
      lastAt: newest === 0 ? null : isoAt(newest)
    };
  }
  /**
   * Merge one page of samples, advance the session cursor, persist the store,
   * then rewrite the snapshot. Dedupes by record id, so replaying a page (or a
   * `usage.read` that returns a slightly older `fromSeq`) cannot double-count.
   *
   * @param sessionId - the remote session the samples belong to.
   * @param samples - sanitized records (see {@link sanitizeSample}).
   * @param nextSeq - the peer's event sequence after this page.
   * @returns a promise that settles when both writes are done; never rejects.
   */
  record(sessionId, samples, nextSeq) {
    return this.enqueue(async () => {
      this.ensureLoaded();
      const session = this.sessions.get(sessionId) ?? { cursor: 0, records: [] };
      const known = new Set(session.records.map((record2) => record2.id));
      let changed = false;
      for (const sample of samples) {
        if (known.has(sample.id)) continue;
        known.add(sample.id);
        session.records.push(sample);
        changed = true;
      }
      const cursor = Number.isFinite(nextSeq) && nextSeq > session.cursor ? Math.trunc(nextSeq) : session.cursor;
      const cursorMoved = cursor !== session.cursor;
      if (!changed && !cursorMoved) return;
      session.cursor = cursor;
      this.sessions.set(sessionId, session);
      this.trim();
      this.writeStore();
      await this.writeSnapshot();
    });
  }
  /**
   * Re-assemble the snapshot from the current store without adding records.
   *
   * Called once at plugin start so a snapshot left by the previous process is
   * refreshed (cost-meter marks one older than 24 hours as stale) even if no
   * remote prompt runs in this session.
   *
   * @returns a promise that settles when the write is attempted; never rejects.
   */
  refreshSnapshot() {
    return this.enqueue(async () => {
      this.ensureLoaded();
      await this.writeSnapshot();
    });
  }
  /** Trim the persisted records to the newest {@link MAX_STORE_RECORDS} by `at`. */
  trim() {
    const all = [];
    for (const [sessionId, session] of this.sessions) {
      for (const record2 of session.records) all.push({ sessionId, record: record2 });
    }
    if (all.length <= MAX_STORE_RECORDS) return;
    all.sort((a, b) => a.record.at === b.record.at ? a.record.id < b.record.id ? 1 : -1 : b.record.at - a.record.at);
    const kept = all.slice(0, MAX_STORE_RECORDS);
    const cursors = /* @__PURE__ */ new Map();
    for (const [sessionId, session] of this.sessions) cursors.set(sessionId, session.cursor);
    this.sessions.clear();
    for (const { sessionId, record: record2 } of kept) {
      const session = this.sessions.get(sessionId) ?? { cursor: cursors.get(sessionId) ?? 0, records: [] };
      session.records.push(record2);
      this.sessions.set(sessionId, session);
    }
  }
  /** Serialize and atomically replace the store file. */
  writeStore() {
    const sessions = {};
    for (const sessionId of [...this.sessions.keys()].sort()) {
      const session = this.sessions.get(sessionId);
      if (session === void 0) continue;
      sessions[sessionId] = { cursor: session.cursor, records: sortRecords(session.records) };
    }
    const file = { version: STORE_VERSION, sessions };
    writeJsonAtomic(this.storeFile, file, this.log);
  }
  /** Assemble and atomically replace the external-usage snapshot. */
  async writeSnapshot() {
    try {
      const existing = readJsonFile(this.snapshotFile);
      const preserved = this.preservedSources(existing);
      const records = this.allRecords();
      const snapshot = composeSnapshot({
        fetchedAt: Date.now(),
        sources: [{ source: this.sourceName, records }],
        preserved
      });
      writeJsonAtomic(this.snapshotFile, snapshot.json, this.log);
    } catch (error) {
      this.log?.(`cost-report: snapshot assembly failed (${error instanceof Error ? error.message : String(error)})`);
    }
  }
  /** Every stored record across sessions, at-ascending and id-deduped. */
  allRecords() {
    const out = [];
    for (const session of this.sessions.values()) out.push(...session.records);
    return dedupeRecords(out);
  }
  /**
   * Foreign sources already in the snapshot file.
   *
   * Only sources that do NOT use this plugin's prefix are preserved: our own
   * source is replaced wholesale by the fresh store contents. Both the
   * `sources` array shape and cost-meter's single-top-level-source shape are
   * accepted, so a file written by an older/more lenient producer still
   * contributes instead of being clobbered.
   */
  preservedSources(existing) {
    if (!isObject(existing)) return [];
    const raw = Array.isArray(existing.sources) ? existing.sources : [existing];
    const out = [];
    for (const item of raw) {
      if (!isObject(item)) continue;
      const source = typeof item.source === "string" ? item.source : "";
      if (source === this.sourceName || source.startsWith(this.sourcePrefix)) continue;
      out.push(item);
    }
    return out;
  }
  /** Ensure the store was read before the first use (load() is idempotent-ish). */
  ensureLoaded() {
    if (!this.loaded) this.load();
  }
  /** Run one task after every previously enqueued task; never rejects. */
  enqueue(task) {
    const next = this.chain.then(task).catch((error) => {
      this.log?.(`cost-report: ${error instanceof Error ? error.message : String(error)}`);
    });
    this.chain = next;
    return next;
  }
};

// src/client.ts
var name = "dsh-remote-client";
var DSH_REMOTE_CLIENT_SETTINGS_NAMESPACE = "dsh-remote-client";
var CLIENT_VERSION = "0.5.2";
var BUILD = "c20";
var Config = z2.object({
  // No defaults: the link is a per-deployment fact, not a product constant.
  host: z2.string().default("").volatile(),
  port: z2.number().default(0).volatile(),
  relayTarget: z2.string().default("").volatile(),
  // `role('secret')` keeps the value out of settings-GUI wire payloads.
  privateKey: z2.string().role("secret").default("").volatile(),
  privateKeyFile: z2.string().default(dshHomePath("dsh-remote", "client.key")).volatile(),
  autoGenerateKey: z2.boolean().default(true).volatile(),
  peerPublicKey: z2.string().default("").volatile(),
  peerPublicKeyFile: z2.string().default(dshHomePath("dsh-remote", "server.pub")).volatile(),
  timeoutMs: z2.number().default(12e4).volatile(),
  allowLegacyHandshake: z2.boolean().default(false).volatile(),
  maxSessionMs: z2.number().default(36e5).volatile(),
  transferChunkBytes: z2.number().default(1048576).volatile(),
  transferConcurrency: z2.number().default(4).volatile(),
  transferCompression: z2.boolean().default(true).volatile(),
  transferFastPathBytes: z2.number().default(524288).volatile(),
  toolEnabled: z2.boolean().default(true),
  sessionPrefix: z2.string().default("remote").volatile(),
  reuseSessions: z2.boolean().default(true).volatile(),
  adoptExistingSessions: z2.boolean().default(false).volatile(),
  sessionMemoryFile: z2.string().default(dshHomePath("dsh-remote", "client-sessions.json")).volatile(),
  promptGuidance: z2.boolean().default(true).volatile(),
  superAgentIoInbound: z2.boolean().default(false).volatile(),
  subagentProvider: z2.boolean().default(true).volatile(),
  backgroundRuns: z2.boolean().default(true).volatile(),
  maxBackgroundRuns: z2.number().default(8).volatile(),
  costReporting: z2.boolean().default(true).volatile(),
  costSourcePrefix: z2.string().default("remote/").volatile(),
  costStoreFile: z2.string().default(dshHomePath("dsh-remote", "client-cost.json")).volatile(),
  costSnapshotFile: z2.string().default(dshHomePath("storages", "cost-meter", "external_usage.json")).volatile(),
  peerName: z2.string().default("default").volatile(),
  peers: z2.dict(PeerProfileSchema).default({}).volatile(),
  defaultPeer: z2.string().default("").volatile(),
  remoteCapabilities: z2.boolean().default(true).volatile(),
  capabilityPreset: z2.string().default("").volatile(),
  capabilityRefreshSeconds: z2.number().default(300).volatile(),
  capabilityTimeoutMs: z2.number().default(6e5).volatile(),
  capabilityDeny: z2.array(z2.string()).default([]).volatile()
});
function plainConfig(config) {
  return Object.fromEntries(
    Object.entries(config).map(([key, value]) => [key, isVolatile(value) ? value.get() : value])
  );
}
function renderText3(text2) {
  return [{ type: "text", text: text2 }];
}
function fmtBytes(size) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}
function apply(ctx, config) {
  const read = () => plainConfig(config);
  const log = (message) => {
    ctx.logger.info(message);
  };
  try {
    const identity = resolvePrivateKey(read(), "client.key");
    log(`dsh-remote-client: identity ${describeIdentity(identity)}`);
    resolvePeerPublicKey(read(), "server.pub");
  } catch (error) {
    log(`dsh-remote-client: ${error instanceof Error ? error.message : String(error)}`);
  }
  const peersNow = () => configuredPeers(read());
  const defaultPeerNow = () => configuredDefaultPeer(read());
  const endpointNow = () => defaultEndpoint(read());
  const sessionPrefixNow = () => {
    const current = read();
    const base = text(current.sessionPrefix) ?? "remote";
    const peer = operationPeer.getStore()?.name ?? defaultPeerNow();
    const legacy = text(current.peerName) ?? "default";
    return peer === legacy ? base : `${base}-${createHash6("sha256").update(peer).digest("hex").slice(0, 10)}`;
  };
  validatePeerNames(Object.keys(peersNow()));
  if (Object.keys(peersNow()).length === 0) {
    log(
      "dsh-remote-client: no peer endpoint configured yet \u2014 set `host` and `port` in this plugin's settings (dsh-remote-client) before calling remote_* tools."
    );
  }
  const operationPeer = new AsyncLocalStorage();
  const controlLinks = /* @__PURE__ */ new Map();
  const sessionBindings = /* @__PURE__ */ new Map();
  let retired = false;
  const authorityOf = (profile) => createHash6("sha256").update(JSON.stringify([
    profile.host,
    profile.port,
    profile.relayTarget ?? "",
    profile.allowLegacyHandshake === true,
    rawPublic(resolvePeerPublicKey(profile, "server.pub")).toString("hex"),
    rawPublic(resolvePrivateKey(profile, "client.key").publicKey).toString("hex")
  ])).digest("hex");
  let onControlEvent = () => {
  };
  const controlFor = (name2 = defaultPeerNow()) => {
    if (retired) throw new Error("Remote plugin disposed; old callbacks cannot reconnect");
    const latest = peersNow()[name2];
    if (latest === void 0) throw new Error(`Unknown or revoked peer "${name2}"`);
    const profile = { ...latest };
    const key = `${name2}\0${createHash6("sha256").update(JSON.stringify(profile)).digest("hex")}`;
    let entry = controlLinks.get(key);
    if (entry === void 0) {
      const transport = new LinkClient(() => {
        const live = peersNow()[name2];
        if (live === void 0) throw new Error("Remote host was revoked");
        return live;
      }, log, `dsh-remote:${name2}`, meshSocketFactory(ctx));
      transport.onEvent((frame) => operationPeer.run({ name: name2, profile, link: transport }, () => onControlEvent(frame)));
      entry = { profile, link: transport };
      controlLinks.set(key, entry);
    }
    return { name: name2, ...entry };
  };
  const link = {
    async request(op, args = {}, timeoutMs, options = {}) {
      if (retired) throw new Error("Remote plugin disposed");
      const current = operationPeer.getStore() ?? controlFor();
      const sessionId = typeof args.sessionId === "string" ? args.sessionId : void 0;
      const binding = sessionId === void 0 ? void 0 : sessionBindings.get(sessionId);
      if (binding !== void 0 && (op === "agent.prompt" || op === "agent.ensure") && binding.name !== current.name) {
        throw new Error("This remote session ID is bound to another host; choose its original host or a distinct explicit session ID");
      }
      const target = binding === void 0 ? current : controlFor(binding.name);
      const latest = peersNow()[target.name];
      if (latest === void 0) throw new Error("Remote host was revoked");
      const authority = authorityOf(latest);
      if (authority !== authorityOf(target.profile) || binding !== void 0 && authority !== binding.authority) {
        throw new Error("Remote identity or endpoint changed; an existing session cannot migrate to new trust automatically");
      }
      if (sessionId !== void 0 && (op === "agent.prompt" || op === "agent.ensure")) sessionBindings.set(sessionId, { name: target.name, authority });
      assertPeerOperation(latest.maxPermission ?? 1, op, {
        peer: target.name,
        workspaceRoot: latest.workspaceRoot ?? "",
        ...typeof args.path === "string" ? { path: args.path } : {}
      });
      return target.link.request(op, args, timeoutMs, options);
    },
    get connected() {
      return (operationPeer.getStore() ?? controlFor()).link.connected;
    },
    notify(payload) {
      if (retired) throw new Error("Remote plugin disposed");
      const qid = typeof payload.qid === "string" ? payload.qid : "";
      const question = relayedQuestions.get(qid);
      const binding = question === void 0 ? void 0 : sessionBindings.get(question.sessionId);
      const target = binding === void 0 ? operationPeer.getStore() ?? controlFor() : controlFor(binding.name);
      const latest = peersNow()[target.name];
      if (latest === void 0 || binding !== void 0 && authorityOf(latest) !== binding.authority) throw new Error("Question destination is no longer authorized");
      assertPeerOperation(latest.maxPermission ?? 1, "agent.prompt", { peer: target.name });
      return target.link.notify(payload);
    },
    onEvent(handler) {
      onControlEvent = handler;
    },
    close() {
      for (const entry of controlLinks.values()) entry.link.dispose();
      controlLinks.clear();
    },
    dispose() {
      retired = true;
      this.close();
    }
  };
  const bindOperation = (definition) => ({
    ...definition,
    execute: async (args, exec) => operationPeer.run(operationPeer.getStore() ?? controlFor(), () => definition.execute(args, exec))
  });
  const capabilityPresetArg = () => text(read().capabilityPreset);
  const capabilityCallTimeout = () => {
    const configured = Number(read().capabilityTimeoutMs ?? 6e5);
    return Number.isFinite(configured) && configured > 0 ? Math.floor(configured) : 6e5;
  };
  const endpointConfigured = () => {
    try {
      const endpoint = endpointNow();
      return text(endpoint.host) !== void 0 && (endpoint.port ?? 0) > 0;
    } catch {
      return false;
    }
  };
  const capabilityDeniedLocally = (name2) => {
    for (const entry of read().capabilityDeny ?? []) {
      const pattern = typeof entry === "string" ? entry.trim() : "";
      if (pattern === "") continue;
      if (pattern.endsWith("*") ? name2.startsWith(pattern.slice(0, -1)) : name2 === pattern) return true;
    }
    return false;
  };
  let capabilityCatalog;
  let capabilityGeneration = 0;
  let capabilityCatalogAt = 0;
  let capabilityInFlight;
  let capabilityCatalogFingerprint = "";
  let capabilityUnsupported = false;
  let capabilityWarned = false;
  let capabilityMirrorSummary = "";
  let capabilityWatch;
  const agentMirrors = /* @__PURE__ */ new Map();
  const liveAgents = () => {
    try {
      const service = ctx.get?.("agents");
      const list = service?.list?.();
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  };
  const teardownAgentMirrors = async (agent) => {
    const entry = agentMirrors.get(agent);
    if (entry === void 0) return;
    agentMirrors.delete(agent);
    try {
      await entry.dispose();
    } catch (error) {
      ctx.logger.debug(`dsh-remote-client: could not withdraw one agent's mirrors (${String(error)})`);
    }
  };
  const withdrawCapabilityMirrors = async () => {
    for (const agent of [...agentMirrors.keys()]) await teardownAgentMirrors(agent);
    capabilityMirrorSummary = "";
  };
  const callPeerTool = async (name2, args, signal, options = {}) => {
    const callId = `caps-${randomUUID3()}`;
    const presetId = options.presetId ?? capabilityPresetArg();
    const requested = options.timeoutMs !== void 0 && Number.isFinite(options.timeoutMs) && options.timeoutMs > 0 ? Math.floor(options.timeoutMs) : capabilityCallTimeout();
    const destination = options.peer === void 0 || options.peer === defaultPeerNow() ? link : poolLinkFor(options.peer);
    const pending = destination.request(
      "caps.call",
      {
        callId,
        name: name2,
        arguments: args,
        ...presetId === void 0 ? {} : { presetId }
      },
      Math.min(requested, capabilityCallTimeout()),
      { retries: 0 }
    );
    try {
      const reply = signal === void 0 ? await pending : await raceAbort(pending, signal);
      return parseCallResult(reply);
    } catch (error) {
      if (error?.name === "AbortError") {
        void destination.request("caps.cancel", { callId }, 1e4, { retries: 0 }).catch(() => {
        });
      }
      throw error;
    }
  };
  const mirrorDefinition = (spec) => ({
    name: spec.name,
    description: spec.description,
    parameters: spec.parameters,
    output: {
      schema: {},
      render: (_args, value) => renderText3(proxyResultText(
        parseCallResult(value)
      ))
    },
    async execute(args, exec) {
      const result = await spec.call(args ?? {}, exec?.signal);
      return {
        content: result.content,
        ...result.durationMs === void 0 ? {} : { durationMs: result.durationMs }
      };
    }
  });
  const catalogIdentity = (catalog) => createHash6("sha256").update(JSON.stringify({
    presetId: catalog.presetId,
    tools: [...catalog.tools].sort((left, right) => left.name.localeCompare(right.name)).map((tool) => [tool.name, tool.callable, tool.description, tool.parameters])
  })).digest("hex");
  const installAgentMirrors = (agent) => {
    if (read().remoteCapabilities === false) return;
    const catalog = capabilityCatalog;
    if (catalog === void 0 || !catalog.available) return;
    if (typeof agent?.ctx?.inject !== "function") return;
    const key = agent;
    if (agentMirrors.has(key)) return;
    const names = /* @__PURE__ */ new Set();
    const skipped = [];
    const installedGeneration = capabilityGeneration;
    const destination = controlFor();
    const fiber = agent.ctx.inject(["tools"], (toolsCtx) => {
      const visible = new Set(toolsCtx.tools.schemas(agent).map((row) => row.name));
      const allowed = catalog.tools.filter((tool) => !capabilityDeniedLocally(tool.name));
      const denied = catalog.tools.filter((tool) => capabilityDeniedLocally(tool.name)).map((tool) => ({ name: tool.name, reason: "denied by this controller (capabilityDeny)" }));
      const result = createProxySpecs({ ...catalog, tools: allowed }, (name2, args, signal) => {
        if (installedGeneration !== capabilityGeneration) throw new Error("Remote configuration changed; refresh the capability catalog before calling this tool");
        return operationPeer.run(destination, () => callPeerTool(name2, args, signal));
      }, (name2) => visible.has(name2));
      skipped.push(...result.skipped, ...denied);
      for (const spec of result.specs) {
        try {
          toolsCtx.tools.register(mirrorDefinition(spec));
          names.add(spec.name);
        } catch (error) {
          skipped.push({
            name: spec.name,
            reason: `could not register locally: ${error instanceof Error ? error.message : String(error)}`
          });
        }
      }
      skipped.sort((left, right) => left.name.localeCompare(right.name));
    });
    agentMirrors.set(key, {
      names,
      skipped,
      dispose: () => {
        const disposable = fiber;
        if (typeof disposable === "function") return disposable();
        return disposable?.dispose?.();
      }
    });
  };
  const installAgentMirrorsSafe = (agent) => {
    try {
      installAgentMirrors(agent);
    } catch (error) {
      ctx.logger.debug(`dsh-remote-client: could not mirror into one agent scope (${String(error)})`);
    }
  };
  const syncCapabilityMirrors = async (force = false) => {
    const catalog = capabilityCatalog;
    if (read().remoteCapabilities === false || catalog === void 0 || !catalog.available) {
      await withdrawCapabilityMirrors();
      return;
    }
    const identity = catalogIdentity(catalog);
    if (!force && identity === capabilityCatalogFingerprint) {
      for (const agent of liveAgents()) installAgentMirrorsSafe(agent);
      return;
    }
    capabilityCatalogFingerprint = identity;
    await withdrawCapabilityMirrors();
    for (const agent of liveAgents()) installAgentMirrorsSafe(agent);
    const mirrored = /* @__PURE__ */ new Set();
    let worstSkipped = 0;
    for (const entry of agentMirrors.values()) {
      for (const name2 of entry.names) mirrored.add(name2);
      worstSkipped = Math.max(worstSkipped, entry.skipped.length);
    }
    const summary = `${mirrored.size}/${catalog.tools.length}/${worstSkipped}/${agentMirrors.size}`;
    if (summary !== capabilityMirrorSummary) {
      capabilityMirrorSummary = summary;
      log(
        `dsh-remote-client: mirrored ${mirrored.size}/${catalog.tools.length} remote tools into ${agentMirrors.size} agent scope(s)` + (worstSkipped === 0 ? "" : ` (${worstSkipped} skipped per agent)`)
      );
    }
  };
  const refreshCapabilityCatalog = async (force = false) => {
    if (read().remoteCapabilities === false || capabilityUnsupported) return capabilityCatalog;
    if (!endpointConfigured()) return capabilityCatalog;
    const seconds = Number(read().capabilityRefreshSeconds ?? 300);
    const ttlMs = (Number.isFinite(seconds) && seconds > 0 ? Math.max(30, seconds) : 300) * 1e3;
    if (!force && capabilityCatalog !== void 0 && Date.now() - capabilityCatalogAt < ttlMs) return capabilityCatalog;
    if (capabilityInFlight !== void 0) return await capabilityInFlight;
    const generation = capabilityGeneration;
    capabilityInFlight = (async () => {
      try {
        const presetId = capabilityPresetArg();
        const reply = await link.request(
          "caps.list",
          presetId === void 0 ? {} : { presetId },
          Math.max(read().timeoutMs ?? 12e4, 3e4)
        );
        if (generation !== capabilityGeneration) return capabilityCatalog;
        capabilityCatalog = parseCatalog(reply);
        capabilityCatalogAt = Date.now();
        capabilityWarned = false;
        if (!capabilityCatalog.available) {
          ctx.logger.debug(
            `dsh-remote-client: peer capability catalog unavailable: ${capabilityCatalog.reason ?? "no reason given"}`
          );
        }
        await syncCapabilityMirrors();
        return capabilityCatalog;
      } catch (error) {
        if (generation !== capabilityGeneration) return capabilityCatalog;
        const message = error instanceof Error ? error.message : String(error);
        if (/unknown op|unsupported op/iu.test(message)) {
          capabilityUnsupported = true;
          log(
            "dsh-remote-client: the peer predates capability federation (no caps.list); remote tools are not mirrored"
          );
        } else if (!capabilityWarned) {
          capabilityWarned = true;
          log(`dsh-remote-client: capability catalog fetch failed (${message}); will retry`);
        }
        return capabilityCatalog;
      } finally {
        if (generation === capabilityGeneration) capabilityInFlight = void 0;
      }
    })();
    return await capabilityInFlight;
  };
  const startCapabilityWatch = () => {
    if (capabilityWatch !== void 0) return;
    const seconds = Number(read().capabilityRefreshSeconds ?? 300);
    if (!Number.isFinite(seconds) || seconds <= 0) return;
    capabilityWatch = setInterval(() => {
      void refreshCapabilityCatalog(true);
    }, Math.max(30, seconds) * 1e3);
    capabilityWatch.unref?.();
  };
  const attachCapabilityMirrors = () => {
    if (read().remoteCapabilities === false) return;
    try {
      ctx.on("agent/created", ({ agent }) => {
        installAgentMirrorsSafe(agent);
      });
      ctx.on("agent/disposed", ({ agent }) => {
        void teardownAgentMirrors(agent);
      });
    } catch (error) {
      ctx.logger.warn(`dsh-remote-client: could not watch agent lifecycle (${String(error)})`);
    }
    void syncCapabilityMirrors();
    void refreshCapabilityCatalog(capabilityCatalog === void 0);
    startCapabilityWatch();
  };
  const mirroredNamesFor = (agent) => {
    if (agent === void 0 || agent === null) return /* @__PURE__ */ new Set();
    const entry = agentMirrors.get(agent);
    return new Set(entry?.names ?? []);
  };
  const renderCapabilityCatalog = (tool, agent) => {
    const catalog = capabilityCatalog;
    if (catalog === void 0) {
      return endpointConfigured() ? "\u8FD8\u6CA1\u6709\u53D6\u5230\u8FDC\u7AEF\u80FD\u529B\u76EE\u5F55\uFF1B\u8FD9\u901A\u5E38\u610F\u5473\u7740\u5BF9\u7AEF\u8FDE\u4E0D\u4E0A\u6216\u7248\u672C\u8FC7\u65E7\u3002" : "\u8FD8\u6CA1\u6709\u914D\u7F6E\u5BF9\u7AEF host/port\uFF0C\u65E0\u6CD5\u8BFB\u53D6\u8FDC\u7AEF\u80FD\u529B\u76EE\u5F55\u3002";
    }
    const mirrored = mirroredNamesFor(agent);
    const shadowed = new Set(catalog.tools.filter((toolRow) => toolRow.callable && !mirrored.has(toolRow.name) && !capabilityDeniedLocally(toolRow.name)).map((toolRow) => toolRow.name));
    return formatCatalog(catalog, { ...tool === void 0 ? {} : { tool }, shadowed });
  };
  const readPeerCatalog = async (presetId, peer) => {
    const destination = peer === void 0 || peer === defaultPeerNow() ? link : poolLinkFor(peer);
    const reply = await destination.request(
      "caps.list",
      presetId === void 0 || presetId === "" ? {} : { presetId },
      Math.max(read().timeoutMs ?? 12e4, 3e4)
    );
    return parseCatalog(reply);
  };
  const catalogSummary = (catalog, agent) => {
    const mirrored = mirroredNamesFor(agent);
    return {
      available: catalog.available,
      ...catalog.reason === void 0 ? {} : { reason: catalog.reason },
      presetId: catalog.presetId,
      tools: catalog.tools.map((tool) => ({
        name: tool.name,
        callable: tool.callable,
        origin: tool.origin,
        mirrored: mirrored.has(tool.name),
        ...tool.reason === void 0 ? {} : { reason: tool.reason }
      })),
      presets: catalog.presets,
      plugins: catalog.plugins,
      sessions: catalog.sessions,
      subagentProviders: catalog.subagentProviders
    };
  };
  const transferRequest = (op, args, timeoutMs) => link.request(op, args, timeoutMs);
  const fastTransferSupported = createOpProbe(transferRequest);
  const transferOptions = (signal) => ({
    chunkSize: read().transferChunkBytes,
    concurrency: read().transferConcurrency,
    compression: read().transferCompression !== false,
    ...signal === void 0 ? {} : { signal }
  });
  const isUnknownTransferOp = (error) => {
    if (isAbortError2(error)) return false;
    const code = error?.peerCode;
    if (code === "FS_UNSUPPORTED" || code === "FS_UNKNOWN_OP") return true;
    const message = error instanceof Error ? error.message : String(error);
    return /unknown op|unsupported op|not supported|no such op/iu.test(message);
  };
  const throwIfAborted2 = (signal) => {
    if (signal?.aborted !== true) return;
    const error = new Error("transfer aborted");
    error.name = "AbortError";
    throw error;
  };
  const commitOutcomeUnknown = (error) => error?.transferPhase === "commit";
  const ambiguousCommitError = (error) => new Error(
    `${error instanceof Error ? error.message : String(error)}\uFF1B\u76EE\u6807\u53EF\u80FD\u5DF2\u5199\u5165\uFF08commit \u7ED3\u679C\u672A\u77E5\uFF09\uFF0C\u8BF7\u5148\u67E5\u770B/\u6821\u9A8C\u76EE\u6807\u6587\u4EF6\u518D\u51B3\u5B9A\u662F\u5426\u91CD\u8BD5`
  );
  const rateMbps = (bytes, durationMs) => bytes <= 0 || durationMs <= 0 ? 0 : Math.round(bytes * 8 / 1e6 / (durationMs / 1e3) * 100) / 100;
  const tempPathFor = (localPath) => `${localPath}.${randomUUID3().replace(/-/gu, "").slice(0, 12)}.dshremote-tmp`;
  const replaceLocalFile = async (tempPath, targetPath) => {
    try {
      await rename2(tempPath, targetPath);
      return;
    } catch (error) {
      const code = error.code;
      if (code !== "EEXIST" && code !== "EPERM" && code !== "EACCES" && code !== "EBUSY") throw error;
    }
    await rm2(targetPath, { force: true });
    await rename2(tempPath, targetPath);
  };
  const legacyUploadFile = async (localPath, remotePath, signal) => {
    const startedAt = Date.now();
    throwIfAborted2(signal);
    const data = await readFile(localPath);
    throwIfAborted2(signal);
    const reply = await link.request("fs.write", {
      path: remotePath,
      dataB64: data.toString("base64")
    });
    const durationMs = Math.max(0, Date.now() - startedAt);
    return {
      bytes: data.length,
      sha256: createHash6("sha256").update(data).digest("hex"),
      created: reply.created === true,
      version: typeof reply.version === "string" ? reply.version : null,
      durationMs,
      rateMbps: rateMbps(data.length, durationMs),
      legacy: true
    };
  };
  const legacyDownloadFile = async (remotePath, localPath, signal) => {
    const startedAt = Date.now();
    throwIfAborted2(signal);
    const info = await link.request("fs.stat", { path: remotePath });
    if (info.exists !== true) {
      const error = new Error(`cannot read "${remotePath}": not found`);
      error.peerCode = "FS_NOT_FOUND";
      throw error;
    }
    if (info.isDir === true) throw new Error(`cannot read "${remotePath}": not a regular file`);
    const size = Number(info.size);
    if (!Number.isFinite(size) || size < 0) {
      throw new Error(`transfer: peer reported an invalid size for "${remotePath}"`);
    }
    const tempPath = tempPathFor(localPath);
    await mkdir2(dirname5(localPath), { recursive: true });
    const handle = await open3(tempPath, "wx");
    const hash = createHash6("sha256");
    let closed = false;
    let renamed = false;
    try {
      let offset = 0;
      while (offset < size) {
        throwIfAborted2(signal);
        const reply = await link.request("fs.read", {
          path: remotePath,
          offset,
          length: Math.min(1048576, size - offset)
        });
        const data = Buffer.from(String(reply.dataB64 ?? ""), "base64");
        if (data.length === 0) break;
        await handle.write(data, 0, data.length, offset);
        hash.update(data);
        offset += data.length;
        if (reply.eof === true) break;
      }
      await handle.close();
      closed = true;
      const localSha = hash.digest("hex");
      const remote = await link.request("fs.hash", { path: remotePath });
      if (String(remote.hash ?? "").toLowerCase() !== localSha) {
        throw new Error("transfer: checksum mismatch");
      }
      throwIfAborted2(signal);
      await replaceLocalFile(tempPath, localPath);
      renamed = true;
      const durationMs = Math.max(0, Date.now() - startedAt);
      return {
        bytes: offset,
        sha256: localSha,
        durationMs,
        rateMbps: rateMbps(offset, durationMs),
        legacy: true
      };
    } finally {
      if (!closed) await handle.close().catch(() => {
      });
      if (!renamed) await rm2(tempPath, { force: true }).catch(() => {
      });
    }
  };
  const costSourceName = () => {
    const current = read();
    const prefix = text(current.costSourcePrefix) ?? "remote/";
    const peer = defaultPeerNow() || "default";
    return `${prefix}${peer}`;
  };
  let costStore;
  let costStoreKey = "";
  const currentCostStore = () => {
    const current = read();
    const storeFile = text(current.costStoreFile) ?? dshHomePath("dsh-remote", "client-cost.json");
    const snapshotFile = text(current.costSnapshotFile) ?? dshHomePath("storages", "cost-meter", "external_usage.json");
    const prefix = text(current.costSourcePrefix) ?? "remote/";
    const sourceName = costSourceName();
    const key = `${storeFile}\0${snapshotFile}\0${prefix}\0${sourceName}`;
    if (costStore === void 0 || costStoreKey !== key) {
      const created = new RemoteCostStore({
        storeFile,
        snapshotFile,
        sourceName,
        sourcePrefix: prefix,
        log: (message) => {
          ctx.logger.debug(`dsh-remote-client: ${message}`);
        }
      });
      created.load();
      costStore = created;
      costStoreKey = key;
    }
    return costStore;
  };
  const USAGE_OP_TTL_MS = 10 * 6e4;
  let usageOpProbe;
  const usageOpSupported = async () => {
    const cached = usageOpProbe;
    if (cached !== void 0 && Date.now() - cached.at < USAGE_OP_TTL_MS) return cached.supported;
    try {
      const info = await link.request("sysinfo", {}, 3e4);
      const ops = Array.isArray(info.ops) ? info.ops.map(String) : [];
      const supported = ops.includes("usage.read");
      usageOpProbe = { at: Date.now(), supported };
      return supported;
    } catch (error) {
      ctx.logger.debug(
        `dsh-remote-client: usage capability probe failed (${error instanceof Error ? error.message : String(error)})`
      );
      return false;
    }
  };
  const collectRemoteUsage = (sessionId) => {
    if (text(sessionId) === void 0 || read().costReporting !== true) return;
    void (async () => {
      try {
        if (!await usageOpSupported()) return;
        const store = currentCostStore();
        const fromSeq = store.cursorOf(sessionId);
        const reply = await link.request(
          "usage.read",
          { sessionId, fromSeq },
          Math.max(read().timeoutMs ?? 12e4, 3e4)
        );
        if (reply.available === false) return;
        const samples = [];
        let lastRecordSeq = 0;
        for (const raw of Array.isArray(reply.records) ? reply.records : []) {
          const sample = sanitizeSample(raw, sessionId);
          if (sample !== null) samples.push(sample);
          const seq = Number(raw?.seq);
          if (Number.isFinite(seq) && seq > lastRecordSeq) lastRecordSeq = seq;
        }
        const nextSeq = Number(reply.nextSeq);
        const cursor = Number.isFinite(nextSeq) ? nextSeq : lastRecordSeq > 0 ? lastRecordSeq : fromSeq;
        await store.record(sessionId, samples, cursor);
      } catch (error) {
        ctx.logger.debug(
          `dsh-remote-client: usage collection for ${sessionId} failed (${error instanceof Error ? error.message : String(error)})`
        );
      }
    })();
  };
  const inFlight = /* @__PURE__ */ new Map();
  const relayedQuestions = /* @__PURE__ */ new Map();
  const pendingInterrupts = /* @__PURE__ */ new Map();
  const pendingRemoteNotes = /* @__PURE__ */ new Map();
  const streamedReplies = /* @__PURE__ */ new Map();
  const STREAMED_REPLY_LIMIT = 64;
  const clearStreamedReplies = (sessionId) => {
    streamedReplies.delete(sessionId);
  };
  const addStreamedReply = (sessionId, reply) => {
    const current = streamedReplies.get(sessionId) ?? [];
    if (current.some((item) => item.sessionId === reply.sessionId && item.messageId === reply.messageId)) return;
    current.push(reply);
    if (current.length > STREAMED_REPLY_LIMIT) current.splice(0, current.length - STREAMED_REPLY_LIMIT);
    streamedReplies.set(sessionId, current);
  };
  const takeStreamedReplies = (sessionId) => {
    const current = streamedReplies.get(sessionId) ?? [];
    streamedReplies.delete(sessionId);
    return current;
  };
  const rpcReplyIds = /* @__PURE__ */ new Set();
  const inboundReplyIds = /* @__PURE__ */ new Set();
  const inboundChains = /* @__PURE__ */ new Map();
  const DELIVERED_REPLY_LIMIT = 1024;
  const deliveredKey = (sessionId, messageId) => `${sessionId}\0${messageId}`;
  const rememberBounded = (set, key) => {
    if (set.has(key)) return;
    set.add(key);
    while (set.size > DELIVERED_REPLY_LIMIT) {
      const oldest = set.values().next();
      if (oldest.done === true) break;
      set.delete(oldest.value);
    }
  };
  const rememberRpcReplies = (replies) => {
    for (const reply of replies ?? []) rememberBounded(rpcReplyIds, deliveredKey(reply.sessionId, reply.messageId));
  };
  const wasRpcReply = (sessionId, messageId) => rpcReplyIds.has(deliveredKey(sessionId, messageId));
  const wasInboundReply = (sessionId, messageId) => inboundReplyIds.has(deliveredKey(sessionId, messageId));
  const rememberInboundReply = (sessionId, messageId) => rememberBounded(inboundReplyIds, deliveredKey(sessionId, messageId));
  const forgetInboundReply = (sessionId, messageId) => {
    inboundReplyIds.delete(deliveredKey(sessionId, messageId));
  };
  const mergeStreamedReplyValue = (sessionId, value) => {
    const frames = takeStreamedReplies(sessionId).filter((reply) => !wasInboundReply(reply.sessionId, reply.messageId));
    const merged = frames.length > 0 ? mergeReplyFrames(value, frames) : value;
    rememberRpcReplies(replyFields(merged).replies);
    return merged;
  };
  const memory = new SessionMemory(
    text(read().sessionMemoryFile) ?? dshHomePath("dsh-remote", "client-sessions.json")
  );
  memory.load();
  const inboundLog = (message, level = "info") => {
    try {
      if (level === "warn") ctx.logger.warn(message);
      else if (level === "debug") ctx.logger.debug(message);
      else log(message);
    } catch {
    }
  };
  const inboundIo = createInboundIoAdapter(ctx, {
    enabled: () => read().superAgentIoInbound === true,
    log: inboundLog
  });
  const injectAsyncInboundReply = (remoteSessionId, reply) => {
    if (retired || read().superAgentIoInbound !== true) return;
    if (inFlight.has(remoteSessionId)) return;
    if (wasRpcReply(remoteSessionId, reply.messageId) || wasInboundReply(remoteSessionId, reply.messageId)) return;
    const producer = operationPeer.getStore();
    if (producer === void 0) return;
    const peer = producer.name;
    const livePeer = peersNow()[peer];
    if (livePeer === void 0 || authorityOf(livePeer) !== authorityOf(producer.profile)) return;
    const localSession = memory.latestLocalSessionFor(remoteSessionId, sessionPrefixNow());
    if (localSession === void 0) {
      inboundLog(
        `dsh-remote-client: no local session is mapped to ${remoteSessionId}; asynchronous remote reply ${reply.messageId} was not injected`,
        "debug"
      );
      return;
    }
    rememberInboundReply(remoteSessionId, reply.messageId);
    const run = async () => {
      try {
        const binding = await inboundIo.ensureBinding(peer, localSession, remoteSessionId);
        if (binding === void 0) {
          forgetInboundReply(remoteSessionId, reply.messageId);
          return;
        }
        if (wasRpcReply(remoteSessionId, reply.messageId)) {
          forgetInboundReply(remoteSessionId, reply.messageId);
          return;
        }
        const outcome = await inboundIo.receive(binding, {
          externalMessageId: inboundExternalId(peer, remoteSessionId, reply.messageId),
          senderId: inboundSenderId(peer, reply),
          text: inboundText(reply),
          replySource: inboundReplySource(peer, reply)
        });
        if (outcome.kind === "accepted") {
          inboundLog(
            `dsh-remote-client: remote reply ${reply.messageId} (${reply.provider}/${reply.model}) from ${peer} admitted into local session ${localSession}`
          );
          return;
        }
        if (outcome.kind === "unavailable") forgetInboundReply(remoteSessionId, reply.messageId);
        inboundLog(
          `dsh-remote-client: asynchronous remote reply ${reply.messageId} was not injected (${outcome.kind}: ${outcome.reason})`,
          "debug"
        );
      } catch (error) {
        forgetInboundReply(remoteSessionId, reply.messageId);
        inboundLog(
          `dsh-remote-client: asynchronous remote reply ${reply.messageId} injection failed (${error instanceof Error ? error.message : String(error)})`,
          "debug"
        );
      }
    };
    const chainKey = `${peer}\0${localSession}`;
    const previous = inboundChains.get(chainKey) ?? Promise.resolve();
    const next = previous.then(run, run);
    inboundChains.set(chainKey, next);
    const cleanup = () => {
      if (inboundChains.get(chainKey) === next) inboundChains.delete(chainKey);
    };
    void next.then(cleanup, cleanup);
  };
  const journalMemory = new SessionMemory(dshHomePath("dsh-remote", "client-journal.json"));
  journalMemory.load();
  const localSessionOf = (exec) => {
    const agent = exec?.agent;
    const id = agent?.session?.id;
    return typeof id === "string" && id !== "" ? id : void 0;
  };
  const scopeOf = (exec, prefix) => {
    const localSession = localSessionOf(exec);
    return {
      prefix,
      ...localSession === void 0 ? {} : { localSession }
    };
  };
  const toCandidates = (raw) => {
    if (!Array.isArray(raw)) return [];
    const out = [];
    for (const item of raw) {
      if (typeof item === "string") {
        if (item !== "") out.push({ sessionId: item });
        continue;
      }
      if (item === null || typeof item !== "object") continue;
      const row = item;
      const sessionId = typeof row.sessionId === "string" ? row.sessionId : "";
      if (sessionId === "") continue;
      out.push({
        sessionId,
        ...typeof row.cwd === "string" && row.cwd !== "" ? { cwd: row.cwd } : {},
        ...typeof row.live === "boolean" ? { live: row.live } : {},
        ...typeof row.seq === "number" ? { seq: row.seq } : {}
      });
    }
    return out;
  };
  const discoverSessions = async (prefix) => {
    const info = await link.request("sysinfo", {}, 3e4);
    const ops = Array.isArray(info.ops) ? info.ops.map(String) : [];
    if (ops.includes("agent.sessions")) {
      const listed = await link.request("agent.sessions", {
        ...prefix === "" ? {} : { prefix }
      }, 3e4);
      return toCandidates(listed.sessions);
    }
    return toCandidates(info.sessions).reverse();
  };
  const resolveDefaultSession = async (scope) => {
    const own = anchorSessionId(scope.prefix, scope.localSession);
    const remembered = memory.get(scopeKey(scope));
    if (remembered !== void 0 && !inFlight.has(remembered)) {
      return { sessionId: remembered, origin: "remembered" };
    }
    if (read().adoptExistingSessions !== true) {
      return { sessionId: own, origin: "anchor" };
    }
    try {
      const candidates = await discoverSessions(scope.prefix);
      if (candidates.some((candidate) => candidate.sessionId === own)) {
        return { sessionId: own, origin: "anchor" };
      }
      const picked = pickReusableSession(candidates, {
        prefix: scope.prefix,
        skip: /* @__PURE__ */ new Set([...inFlight.keys(), ...memory.inUse()])
      });
      if (picked !== void 0) return { sessionId: picked.sessionId, origin: "peer" };
    } catch (error) {
      ctx.logger.debug(
        `dsh-remote-client: session discovery failed (${error instanceof Error ? error.message : String(error)})`
      );
    }
    return { sessionId: own, origin: "anchor" };
  };
  link.onEvent((frame) => {
    const kind = String(frame.kind ?? "");
    const sessionId = String(frame.sessionId ?? "");
    if (kind === "caps.changed") {
      void refreshCapabilityCatalog(true);
      return;
    }
    if (sessionId === "") return;
    if (kind === "assistant.reply") {
      const reply = replyFrame(frame.reply, sessionId);
      if (reply !== void 0) {
        addStreamedReply(sessionId, reply);
        if (!inFlight.has(sessionId)) {
          try {
            injectAsyncInboundReply(sessionId, reply);
          } catch (error) {
            inboundLog(
              `dsh-remote-client: could not start asynchronous reply injection (${error instanceof Error ? error.message : String(error)})`,
              "debug"
            );
          }
        }
      }
      return;
    }
    if (kind === "ask") {
      const qid = String(frame.qid ?? "");
      if (qid === "") return;
      relayedQuestions.set(qid, { sessionId, questions: frame.questions });
      inFlight.get(sessionId)?.ask(frame);
      return;
    }
    if (kind === "interrupt") {
      if (String(frame.origin ?? "") === "controller") return;
      const parked = inFlight.get(sessionId);
      if (parked !== void 0) {
        parked.interrupt(frame);
        return;
      }
      pendingInterrupts.set(sessionId, frame);
      return;
    }
    if (kind === "note") {
      const text2 = String(frame.text ?? "");
      if (text2 === "") return;
      const notes = pendingRemoteNotes.get(sessionId) ?? [];
      notes.push(text2);
      pendingRemoteNotes.set(sessionId, notes);
    }
  });
  const interruptRemote = (sessionId) => link.request("agent.interrupt", { sessionId }, 1e4).then(() => {
    log(`dsh-remote-client: interrupted ${sessionId} on the peer`);
  }).catch((error) => {
    ctx.logger.debug(
      `dsh-remote-client: could not interrupt ${sessionId} on the peer (${error instanceof Error ? error.message : String(error)})`
    );
  });
  const stopRemoteExec = (execId) => link.request("exec.cancel", { execId }, 1e4).then((reply) => {
    if (reply.cancelled === true) log(`dsh-remote-client: stopped ${execId} on the peer`);
  }).catch((error) => {
    ctx.logger.debug(
      `dsh-remote-client: could not stop ${execId} on the peer (${error instanceof Error ? error.message : String(error)})`
    );
  });
  const parkPrompt = (sessionId, pending) => {
    let onAsk = () => {
    };
    let onInterrupt = () => {
    };
    const asked = new Promise((resolve2) => {
      onAsk = resolve2;
    });
    const stopped = new Promise((resolve2) => {
      onInterrupt = resolve2;
    });
    inFlight.set(sessionId, { prompt: pending, ask: onAsk, interrupt: onInterrupt });
    return { asked, stopped };
  };
  const sessionForProvider = (parentSessionId) => {
    const prefix = sessionPrefixNow();
    const scope = { prefix, localSession: parentSessionId };
    return memory.get(scopeKey(scope)) ?? anchorSessionId(prefix, parentSessionId);
  };
  const promptForProvider = async (request) => {
    clearStreamedReplies(request.sessionId);
    const pending = link.request("agent.prompt", {
      sessionId: request.sessionId,
      text: request.text,
      timeoutMs: 0
    }, Math.max(read().timeoutMs ?? 12e4, 3e4));
    let onAsk = () => {
    };
    let onInterrupt = () => {
    };
    const asked = new Promise((resolve2) => {
      onAsk = resolve2;
    });
    const stopped = new Promise((resolve2) => {
      onInterrupt = resolve2;
    });
    inFlight.set(request.sessionId, { prompt: pending, ask: onAsk, interrupt: onInterrupt });
    try {
      const outcome = await Promise.race([
        pending.then((reply2) => ({ kind: "reply", reply: reply2 })),
        asked.then((frame) => ({ kind: "ask", frame })),
        stopped.then((frame) => ({ kind: "stop", frame }))
      ]);
      if (outcome.kind === "stop") {
        inFlight.delete(request.sessionId);
        clearStreamedReplies(request.sessionId);
        collectRemoteUsage(request.sessionId);
        return { reply: "", interrupted: true, reason: "aborted" };
      }
      if (outcome.kind === "ask") {
        const questions = Array.isArray(outcome.frame.questions) ? outcome.frame.questions : [];
        const lines = [
          "\u8FDC\u7AEF agent \u5728\u7B49\u4E00\u4E2A\u56DE\u7B54\uFF0C\u6240\u4EE5\u8FD9\u6B21\u59D4\u6D3E\u5148\u8FD4\u56DE\u5B83\u7684\u63D0\u95EE\uFF1A",
          `qid: ${String(outcome.frame.qid ?? "")}`
        ];
        for (const question of questions) {
          lines.push(`- [${String(question.id ?? "?")}] ${String(question.question ?? "")}`);
        }
        lines.push("\u7528 remote_answer_question \u4F5C\u7B54\uFF1B\u7B54\u6848\u4F1A\u56DE\u5230\u5BF9\u7AEF\u90A3\u4E2A\u8FD8\u505C\u7740\u7684\u8F6E\u6B21\u3002");
        return { reply: lines.join("\n"), reason: "completed" };
      }
      inFlight.delete(request.sessionId);
      collectRemoteUsage(request.sessionId);
      const reply = outcome.reply;
      const merged = mergeStreamedReplyValue(request.sessionId, reply);
      return {
        reply: String(merged.reply ?? reply.reply ?? ""),
        ...replyFields(merged),
        ...merged.interrupted === true ? { interrupted: true } : {},
        ...merged.created === true ? { created: true } : {},
        reason: typeof merged.reason === "string" ? merged.reason : null
      };
    } catch (error) {
      inFlight.delete(request.sessionId);
      clearStreamedReplies(request.sessionId);
      throw error;
    }
  };
  const LINK_FOREVER_MS = 2147e6;
  const linkDeadlineFor = (turnTimeoutMs) => turnTimeoutMs > 0 ? Math.max(read().timeoutMs ?? 12e4, turnTimeoutMs + 3e4) : LINK_FOREVER_MS;
  const NOTE_OP_TTL_MS = 10 * 6e4;
  const noteOpProbes = /* @__PURE__ */ new Map();
  const noteOpSupported = async (sessionId) => {
    const binding = sessionBindings.get(sessionId);
    const target = binding === void 0 ? operationPeer.getStore() ?? controlFor() : controlFor(binding.name);
    const cached = noteOpProbes.get(target.link);
    if (cached !== void 0 && Date.now() - cached.at < NOTE_OP_TTL_MS) return cached;
    try {
      const info = await operationPeer.run(target, () => link.request("sysinfo", {}, 3e4));
      const ops = Array.isArray(info.ops) ? info.ops.map(String) : [];
      const supported = ops.includes("agent.note");
      const features = info.features;
      const noteModes = features?.noteModes;
      const modes = Array.isArray(noteModes) && ["queue", "steer", "auto"].every((mode) => noteModes.includes(mode));
      const found = { at: Date.now(), supported, modes };
      noteOpProbes.set(target.link, found);
      return found;
    } catch (error) {
      ctx.logger.debug(
        `dsh-remote-client: note capability probe failed (${error instanceof Error ? error.message : String(error)})`
      );
      throw error;
    }
  };
  const isUnknownPeerOp = (error) => {
    const code = error?.peerCode;
    if (code === "FS_UNKNOWN_OP") return true;
    const message = error instanceof Error ? error.message : String(error);
    return /^unknown op ["']agent\.note["']$/u.test(message);
  };
  const orphanNotePrompts = /* @__PURE__ */ new Set();
  const sendMessageToSession = async (request) => {
    if (request.signal?.aborted === true) {
      const cancelled = new Error("remote_send_message: cancelled locally");
      cancelled.name = "AbortError";
      throw cancelled;
    }
    const noteSupport = await noteOpSupported(request.sessionId);
    const supported = noteSupport.supported;
    const mode = request.mode ?? "auto";
    if (mode === "steer" && (!supported || !noteSupport.modes)) {
      throw new Error("remote_send_message: peer does not advertise steering; upgrade it or explicitly choose queue");
    }
    if (supported) {
      try {
        const reply = await link.request("agent.note", {
          sessionId: request.sessionId,
          text: request.text,
          ...noteSupport.modes ? { mode } : {}
        }, 3e4);
        return {
          accepted: reply.accepted !== false,
          method: "agent.note",
          ...reply.mode === "queue" || reply.mode === "steer" ? { mode: reply.mode } : { mode: "queue" },
          ...typeof reply.processing === "string" ? { processing: reply.processing } : {},
          ...noteSupport.modes ? {} : { note: "\u65E7peer\u4EC5\u652F\u6301followup\u6392\u4E0B\u4E00\u8F6E\uFF0C\u4E0D\u5BA3\u79F0next-step steering" }
        };
      } catch (error) {
        if (!isUnknownPeerOp(error) || mode === "steer") throw error;
        ctx.logger.debug(
          `dsh-remote-client: agent.note unavailable, queueing through agent.prompt (${error instanceof Error ? error.message : String(error)})`
        );
      }
    }
    const queued = link.request("agent.prompt", {
      sessionId: request.sessionId,
      text: request.text,
      timeoutMs: 0
    }, LINK_FOREVER_MS);
    orphanNotePrompts.add(queued);
    void queued.then(
      () => {
        orphanNotePrompts.delete(queued);
      },
      () => {
        orphanNotePrompts.delete(queued);
      }
    );
    return {
      accepted: true,
      method: "agent.prompt",
      mode: "queue",
      processing: "next-turn",
      note: "\u5BF9\u7AEF\u65E7\u7248\u672C\uFF1B\u6D88\u606F\u5DF2\u6392\u961F\uFF0C\u4F46\u5B8C\u6210\u65F6\u95F4\u4E0D\u53EF\u89C2\u6D4B"
    };
  };
  const startRunPrompt = (request) => {
    if (request.signal?.aborted === true) {
      request.onSettled({
        status: "aborted",
        interrupted: true,
        reason: "aborted",
        diagnostic: "\u672C\u673A\u5DF2\u4E2D\u65AD\uFF0C\u540E\u53F0\u8FD0\u884C\u672A\u542F\u52A8"
      });
      return;
    }
    clearStreamedReplies(request.sessionId);
    const pending = link.request("agent.prompt", {
      sessionId: request.sessionId,
      text: request.text,
      timeoutMs: request.timeoutMs
    }, linkDeadlineFor(request.timeoutMs));
    const parked = parkPrompt(request.sessionId, pending);
    let finished = false;
    const cleanup = () => {
      if (finished) return;
      finished = true;
      request.signal?.removeEventListener("abort", onAbort);
      if (inFlight.get(request.sessionId)?.prompt === pending) inFlight.delete(request.sessionId);
    };
    const settle = (outcome) => {
      if (finished) return;
      cleanup();
      collectRemoteUsage(request.sessionId);
      request.onSettled(outcome);
    };
    const onAbort = () => {
      request.onCancelling();
      void interruptRemote(request.sessionId);
    };
    request.signal?.addEventListener("abort", onAbort, { once: true });
    void (async () => {
      try {
        const outcome = await Promise.race([
          pending.then((reply2) => ({ kind: "reply", reply: reply2 })),
          parked.stopped.then((frame) => ({ kind: "stop", frame }))
        ]);
        if (outcome.kind === "stop") {
          clearStreamedReplies(request.sessionId);
          settle({
            status: "aborted",
            interrupted: true,
            reason: String(outcome.frame.cause ?? "user")
          });
          return;
        }
        const reply = outcome.reply;
        const merged = mergeStreamedReplyValue(request.sessionId, reply);
        const reason = typeof merged.reason === "string" ? merged.reason : null;
        const body = typeof merged.reply === "string" ? merged.reply : "";
        if (merged.interrupted === true) {
          settle({ status: "aborted", interrupted: true, reply: body, ...replyFields(merged), reason: reason ?? "aborted" });
          return;
        }
        if (reason === "error" || reason === "blocked" || typeof merged.error === "string") {
          settle({
            status: "error",
            reply: body,
            ...replyFields(merged),
            reason,
            diagnostic: typeof merged.error === "string" && merged.error !== "" ? merged.error : `dsh-remote-client: the peer's turn ended with reason "${String(reason)}"`
          });
          return;
        }
        settle({ status: "completed", reply: body, ...replyFields(merged), reason });
      } catch (error) {
        clearStreamedReplies(request.sessionId);
        const message = error instanceof Error ? error.message : String(error);
        if (request.signal?.aborted === true) {
          settle({
            status: "aborted",
            interrupted: true,
            reason: "aborted",
            diagnostic: `\u672C\u673A\u4E2D\u65AD\uFF1A${message}`
          });
          return;
        }
        settle({ status: "error", diagnostic: message });
      }
    })();
  };
  const runToolDeps = {
    async resolveSession(args, exec) {
      const prefix = sessionPrefixNow();
      const explicit = args.session_id;
      if (explicit !== void 0) return { sessionId: explicit, origin: "explicit" };
      const scope = scopeOf(exec, prefix);
      try {
        return await resolveDefaultSession(scope);
      } catch {
        return { sessionId: anchorSessionId(prefix, scope.localSession), origin: "anchor" };
      }
    },
    startPrompt: startRunPrompt,
    sendMessage: sendMessageToSession,
    interrupt: interruptRemote,
    rememberScope(exec, sessionId) {
      memory.set(scopeKey(scopeOf(exec, sessionPrefixNow())), sessionId);
    },
    log,
    maxRuns: () => {
      const value = Number(read().maxBackgroundRuns ?? 8);
      return Number.isFinite(value) && value >= 1 ? Math.floor(value) : 8;
    }
  };
  const resolved = read();
  let peers = peersNow();
  ctx.plugin(PeerRegistry, { peers, defaultPeer: text(resolved.defaultPeer) ?? "" });
  const teamService = () => {
    try {
      return ctx.get("agentTeams");
    } catch {
      return void 0;
    }
  };
  const poolPeers = () => Object.fromEntries(Object.entries(peersNow()).map(([name2, profile]) => [name2, { ...profile, name: name2 }]));
  const pooledLinks = /* @__PURE__ */ new Map();
  const poolLinkFor = (peerName) => {
    if (retired) throw new Error("Remote plugin disposed");
    const existing = pooledLinks.get(peerName);
    if (existing !== void 0) return existing;
    const created = new LinkClient(() => {
      const profile = poolPeers()[peerName];
      return profile === void 0 ? {} : {
        host: profile.host,
        port: profile.port,
        relayTarget: profile.relayTarget,
        privateKey: profile.privateKey,
        privateKeyFile: profile.privateKeyFile,
        autoGenerateKey: profile.autoGenerateKey,
        peerPublicKey: profile.peerPublicKey,
        peerPublicKeyFile: profile.peerPublicKeyFile,
        timeoutMs: profile.timeoutMs,
        allowLegacyHandshake: profile.allowLegacyHandshake,
        maxSessionMs: profile.maxSessionMs
      };
    }, (message) => log(message), `dsh-remote:peer ${peerName}`, meshSocketFactory(ctx));
    const rawRequest = created.request.bind(created);
    created.request = async (op, args = {}, timeoutMs, options = {}) => {
      const profile = peersNow()[peerName];
      if (profile === void 0) throw new Error(`Unknown peer "${peerName}"`);
      assertPeerOperation(profile.maxPermission ?? 1, op, {
        peer: peerName,
        workspaceRoot: profile.workspaceRoot ?? "",
        ...typeof args.path === "string" ? { path: args.path } : {}
      });
      return rawRequest(op, args, timeoutMs, options);
    };
    pooledLinks.set(peerName, created);
    return created;
  };
  const referenceService = {
    names: () => Object.keys(peersNow()),
    async list(peer, args, signal) {
      if (!Object.hasOwn(peersNow(), peer)) throw new Error(`Unknown peer "${peer}"`);
      signal?.throwIfAborted();
      const pending = poolLinkFor(peer).request("references.list", args, 15e3);
      return signal === void 0 ? pending : raceAbort(pending, signal);
    }
  };
  const provide = ctx.provide;
  if (typeof provide === "function") provide.call(ctx, "dshRemoteReferences", referenceService);
  ctx.on("agent/pre-step", async (payload, next) => mapRemoteReferences({
    peers: referenceService.names,
    list: referenceService.list
  }, payload, await next()));
  const teamTaskHooks = createTeamTaskHooks({
    team: teamService,
    log: (message) => ctx.logger.debug(`dsh-remote-client: ${message}`)
  });
  const poolDeps = {
    peers: poolPeers,
    prefix: () => text(read().sessionPrefix) ?? "remote",
    localSessionOf,
    linkFor: poolLinkFor,
    log,
    teamTask: teamTaskHooks
  };
  const tools = [
    defineTool5({
      name: "remote_ping",
      description: "Check the link to the peer harness: version, build tag, hostname, live sessions, and this side's key fingerprint.",
      parameters: {},
      output: {
        schema: { type: "json" },
        render: (_args, value) => renderText3(JSON.stringify(value, null, 2))
      },
      async execute(_args, exec) {
        const info = await link.request("sysinfo", {}, 3e4);
        const localSession = localSessionOf(exec);
        return {
          clientVersion: CLIENT_VERSION,
          clientBuild: BUILD,
          connected: link.connected,
          // Which remote conversation THIS chat owns — the mapping the guidance
          // promises, made checkable without spending a prompt on it.
          remoteSessionForThisChat: localSession === void 0 ? `${sessionPrefixNow()} (no calling session; shared)` : anchorSessionId(sessionPrefixNow(), localSession),
          // Whether remote usage is being forwarded to the local cost-meter, and
          // how much this plugin has recorded — readable without any network IO,
          // so "is the reporting loop working?" is one `remote_ping` away.
          remoteCost: (() => {
            const summary = currentCostStore().summary();
            return {
              enabled: read().costReporting === true,
              source: summary.source,
              records: summary.records,
              lastAt: summary.lastAt
            };
          })(),
          ...info
        };
      }
    }),
    defineTool5({
      name: "remote_exec",
      description: "\u5728\u8FDC\u7AEF\u4E3B\u673A\u4E0A\u6267\u884C PowerShell\uFF08\u6216 cmd\uFF09\u547D\u4EE4\uFF0C\u8FD4\u56DE stdout / stderr / \u9000\u51FA\u7801\u3002\u8FD9\u662F\u5728\u5BF9\u7AEF\u673A\u5668\u4E0A\u8DD1\u547D\u4EE4\uFF0C\u4E0D\u662F\u672C\u673A\u3002\u672C\u673A\u88AB\u7528\u6237\u4E2D\u65AD\u65F6\uFF0C\u8FD9\u6761\u547D\u4EE4\u4F1A\u901A\u8FC7\u5BF9\u7AEF\u7684 `exec.cancel` \u4E00\u8D77\u88AB\u505C\u6389\uFF08\u5BF9\u7AEF\u7248\u672C\u8FC7\u8001\u5219\u53EA\u80FD\u505C\u6389\u672C\u673A\u8FD9\u4E00\u4FA7\uFF09\u3002",
      parameters: {
        command: { type: "string", required: true, description: "\u8981\u6267\u884C\u7684\u547D\u4EE4\u3002" },
        shell: { type: "string", description: "powershell\uFF08\u9ED8\u8BA4\uFF09\u6216 cmd\u3002" },
        timeout_ms: { type: "number", description: "\u8D85\u65F6\u6BEB\u79D2\u6570\uFF0C\u9ED8\u8BA4 120000\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          const parts = [
            `exit_code: ${v.exit === null ? "(none)" : v.exit}${v.cancelled === true ? "  (STOPPED)" : v.timedOut ? "  (TIMED OUT)" : ""}`,
            `duration_ms: ${v.durationMs}`
          ];
          if (v.stdout.trim() !== "") parts.push("--- stdout ---", v.stdout.trimEnd());
          if (v.stderr.trim() !== "") parts.push("--- stderr ---", v.stderr.trimEnd());
          if (v.stdout.trim() === "" && v.stderr.trim() === "") parts.push("(no output)");
          return renderText3(parts.join("\n"));
        }
      },
      async execute(args, exec) {
        return await runCancellableExec({
          execId: `exec-${randomUUID3()}`,
          args: {
            cmd: args.command,
            shell: args.shell ?? "powershell",
            timeoutMs: args.timeout_ms ?? 12e4
          },
          timeoutMs: Math.max(read().timeoutMs ?? 12e4, (args.timeout_ms ?? 0) + 3e4),
          ...exec?.signal === void 0 ? {} : { signal: exec.signal },
          send: (requestArgs, timeout) => link.request("exec", requestArgs, timeout),
          cancelRemote: (execId) => {
            void stopRemoteExec(execId);
          }
        });
      }
    }),
    defineTool5({
      name: "remote_agent_prompt",
      description: '\u628A\u4E00\u6BB5\u7528\u6237\u53D1\u8A00\u4EA4\u7ED9**\u8FDC\u7AEF harness \u7684 agent**\uFF0C\u7B49\u5B83\u8DD1\u5B8C\u8FD9\u4E00\u8F6E\uFF0C\u53D6\u56DE\u56DE\u590D\u3002\u8F93\u5165\u5728\u5BF9\u7AEF\u6807\u8BB0\u4E3A dsh-remote \u6765\u6E90\uFF08\u4E0D\u662F\u5BF9\u7AEF\u672C\u5730\u771F\u4EBA\uFF09\uFF1B**\u628A\u8FDC\u7AEF\u5BF9\u8BDD\u5F53\u4F5C\u672C\u673A\u7684\u4E00\u4E2A subagent / task**\uFF1A\u4F60\u6D3E\u6D3B\u3001\u5B83\u4EA4\u4ED8\uFF0C\u6700\u540E\u628A\u7ED3\u8BBA\u5E26\u56DE\u672C\u673A\u4E0A\u4E0B\u6587\u3002\n\u4F1A\u8BDD\u89C4\u5219\uFF08\u4E25\u683C\uFF09\uFF1A**\u4E00\u4E2A\u672C\u673A chat \u53EA\u5BF9\u5E94\u4E00\u4E2A\u8FDC\u7AEF\u5BF9\u8BDD**\u3002\u7701\u7565 session_id \u65F6\uFF0C\u672C\u63D2\u4EF6\u6309\u672C\u673A\u4F1A\u8BDD\u63A8\u5BFC\u51FA\u56FA\u5B9A id \u5E76\u590D\u7528\u2014\u2014\u5BF9\u7AEF\u5DF2\u6709\u5C31\u7EED\u63A5\uFF0C\u6CA1\u6709\u624D\u521B\u5EFA\u3002\u6240\u4EE5\u4E0D\u8981\u4E3A\u4E86"\u9694\u79BB/\u6362\u4E2A\u8BDD\u9898"\u800C\u6539 session_id\uFF1A\u90A3\u53EA\u4F1A\u8BA9\u5BF9\u7AEF\u591A\u5F00\u4E00\u6BB5\u5BF9\u8BDD\u3002\u53EA\u6709\u7528\u6237\u660E\u786E\u8981\u6C42\u53E6\u8D77\u4E00\u6BB5\u65F6\uFF0C\u624D\u4F20 new_session=true\uFF08\u6216\u663E\u5F0F\u7ED9\u4E00\u4E2A\u65B0 id\uFF09\u3002\n\u672C\u673A\u4F18\u5148\uFF1A\u80FD\u5728\u672C\u673A\u4E0A\u4E0B\u6587\u91CC\u505A\u7684\u4E8B\u5C31\u5728\u672C\u673A\u505A\uFF1B\u53EA\u6709\u786E\u5B9E\u5FC5\u987B\u8DD1\u5728\u5BF9\u7AEF\u673A\u5668\u4E0A\u7684\u52A8\u4F5C\uFF08\u5BF9\u7AEF\u7684\u6587\u4EF6\u3001\u5BF9\u7AEF\u7684\u73AF\u5883\u3001\u5BF9\u7AEF\u5DF2\u6709\u7684\u4F1A\u8BDD\uFF09\u624D\u7528 remote_*\u3002\u8FDC\u7AEF\u53EA\u505A\u4EA4\u4ED8\uFF0C\u522B\u628A\u5B83\u5F53\u6210\u672C\u673A\u7F16\u6392\u7684\u6267\u884C\u5668\u3002\n\u6253\u65AD\uFF1A\u672C\u673A\u88AB\u7528\u6237\u4E2D\u65AD\u65F6\uFF0C\u8FD9\u4E00\u8F6E\u4F1A\u540C\u65F6\u4E2D\u65AD\u8FDC\u7AEF\uFF1B\u8FDC\u7AEF\u7528\u6237\u6253\u65AD\u65F6\uFF0C\u8FD4\u56DE\u91CC\u4F1A\u5E26 interrupted \u6807\u8BB0\u2014\u2014\u90A3\u65F6\u7ACB\u523B\u505C\u4E0B\u3001\u4E0D\u8981\u81EA\u52A8\u91CD\u8BD5\u6216\u7EE7\u7EED\uFF0C\u628A\u51B3\u5B9A\u6743\u4EA4\u56DE\u7528\u6237\u3002',
      parameters: {
        text: { type: "string", required: true, description: "\u4EA4\u7ED9\u5BF9\u7AEF agent \u7684\u7528\u6237\u53D1\u8A00\u3002" },
        session_id: { type: "string", description: "\u5BF9\u7AEF\u4F1A\u8BDD id\u3002\u4E00\u822C**\u4E0D\u8981\u4F20**\uFF1A\u7701\u7565\u5373\u590D\u7528\u672C chat \u81EA\u5DF1\u90A3\u4E00\u4E2A\u5BF9\u8BDD\u3002" },
        new_session: { type: "boolean", description: "true = \u5728\u5BF9\u7AEF\u53E6\u5F00\u4E00\u6BB5\u5BF9\u8BDD\u3002\u4EC5\u5728\u7528\u6237\u660E\u786E\u8981\u6C42\u53E6\u8D77\u4E00\u6BB5\u65F6\u4F7F\u7528\u3002" },
        preset_id: { type: "string", description: "\u4EC5\u9996\u6B21\u521B\u5EFA\u4F1A\u8BDD\u65F6\u751F\u6548\u7684 preset id\uFF0C\u5982 cordis\u3002" },
        workspace: { type: "string", description: "\u5BF9\u7AEF\u4F1A\u8BDD\u7684\u5DE5\u4F5C\u76EE\u5F55\uFF08\u4EC5\u9996\u6B21\u521B\u5EFA\u65F6\u751F\u6548\uFF09\u3002" },
        timeout_ms: { type: "number", description: "\u7B49\u5F85\u8FD9\u4E00\u8F6E\u7ED3\u675F\u7684\u8D85\u65F6\u6BEB\u79D2\u6570\uFF1B0 \u8868\u793A\u4E0D\u9650\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          const tag = v.created === true ? "(created)" : v.origin === "fresh" ? "(new)" : `(reused${v.origin === void 0 || v.origin === "explicit" ? "" : `: ${v.origin}`})`;
          const stopLines = [];
          if (v.priorInterrupt !== void 0) {
            stopLines.push(
              `\u26A0\uFE0F \u4E0A\u4E00\u8F6E\u5728\u8FDC\u7AEF\u88AB\u7528\u6237\u6253\u65AD\u4E86\uFF08cause: ${v.priorInterrupt.cause ?? "unknown"}\uFF09\uFF1B\u8FD9\u662F\u90A3\u6B21\u6253\u65AD\u7684\u56DE\u62A5\uFF0C\u4E0D\u662F\u65B0\u7ED3\u679C\u3002`
            );
          }
          if (v.interrupted === true || v.interruptedByRemote === true) {
            stopLines.push(
              "\u26A0\uFE0F \u8FD9\u4E00\u8F6E\u5728\u8FDC\u7AEF\u88AB\u7528\u6237\u6253\u65AD\uFF0C\u6CA1\u6709\u53EF\u7528\u7684\u56DE\u590D\u3002**\u7ACB\u523B\u505C\u6B62**\uFF1A\u4E0D\u8981\u91CD\u8BD5\u3001\u4E0D\u8981\u81EA\u52A8\u7EE7\u7EED\u3001\u4E0D\u8981\u6362 session_id \u91CD\u53D1\uFF1B\u628A\u5F53\u524D\u72B6\u6001\u544A\u8BC9\u7528\u6237\uFF0C\u7B49\u7528\u6237\u7ED9\u51FA\u65B0\u6307\u793A\u3002"
            );
          }
          if ((v.remoteUserNotes?.length ?? 0) > 0) {
            stopLines.push("\u8FDC\u7AEF\u7528\u6237\u5728\u8FD9\u4E2A\u5BF9\u8BDD\u91CC\u53D1\u4E86\u6D88\u606F\uFF08\u4E0D\u662F\u672C\u63D2\u4EF6\u6CE8\u5165\u7684\uFF09\uFF1A");
            for (const note of v.remoteUserNotes ?? []) stopLines.push(`  \xB7 ${note}`);
            stopLines.push("\u4EE5\u7528\u6237\u7684\u65B0\u6307\u793A\u4E3A\u51C6\uFF0C\u91CD\u65B0\u89C4\u5212\uFF1B\u4E0D\u8981\u8986\u76D6\u6216\u5FFD\u7565\u5B83\u3002");
          }
          if (v.pendingQuestion !== void 0) {
            const lines = [
              `session: ${v.sessionId} ${tag}`,
              ...stopLines,
              "reason : \u5BF9\u7AEF agent \u6B63\u5728\u7B49\u4F60\u56DE\u7B54\uFF08\u5B83\u8C03\u7528\u4E86 ask_user_question\uFF09",
              `qid    : ${v.pendingQuestion.qid}`,
              "--- questions ---"
            ];
            for (const [index, question] of v.pendingQuestion.questions.entries()) {
              const header = question.header === void 0 || question.header === "" ? "" : `[${question.header}] `;
              lines.push(`${index + 1}. ${header}${question.question}`);
              lines.push(`   id: ${question.id}`);
              if (question.detail !== void 0 && question.detail !== "") lines.push(`   ${question.detail}`);
              for (const [optionIndex, option] of (question.options ?? []).entries()) {
                lines.push(`   ${optionIndex + 1}) ${option.label}${option.description === void 0 ? "" : ` \u2014 ${option.description}`}`);
              }
              if (question.multiSelect === true) lines.push("   (\u53EF\u591A\u9009)");
            }
            lines.push("");
            lines.push(`\u5BA1\u67E5\u540E\u4F5C\u7B54\uFF1Aremote_answer_question(question_id="${v.pendingQuestion.qid}", answers={answers:[{id, selected:[...], custom?}]})`);
            lines.push("\u9700\u8981\u7528\u6237\u62CD\u677F\u65F6\uFF1A\u5148\u8C03\u672C\u673A ask_user_question \u95EE\u7528\u6237\uFF0C\u518D\u628A\u5B83\u7684\u8FD4\u56DE\u8F6C\u4EA4\u7ED9 remote_answer_question\u3002");
            return renderText3(lines.join("\n"));
          }
          const head = [
            `session: ${v.sessionId} ${tag}`,
            `reason : ${v.reason ?? "(none)"}   seq: ${v.seq ?? "?"}   ${v.durationMs ?? "?"} ms`,
            ...stopLines
          ];
          if (v.error !== null && v.error !== void 0 && v.error !== "") {
            head.push(`error  : ${v.error}`);
          }
          return renderText3([...head, renderRemoteReplies(value)].join("\n"));
        }
      },
      async execute(args, exec) {
        const prefix = sessionPrefixNow();
        const explicit = text(args.session_id);
        const workspace = text(args.workspace);
        const preset = text(args.preset_id);
        const scope = scopeOf(exec, prefix);
        const reuse = read().reuseSessions !== false && args.new_session !== true;
        let sessionId;
        let origin;
        if (explicit !== void 0) {
          sessionId = explicit;
          origin = "explicit";
        } else if (!reuse) {
          sessionId = freshSessionId(prefix);
          origin = "fresh";
        } else {
          try {
            ({ sessionId, origin } = await resolveDefaultSession(scope));
          } catch {
            sessionId = anchorSessionId(prefix, scope.localSession);
            origin = "anchor";
          }
        }
        const priorInterrupt = pendingInterrupts.get(sessionId);
        if (priorInterrupt !== void 0) pendingInterrupts.delete(sessionId);
        const remoteUserNotes = pendingRemoteNotes.get(sessionId) ?? [];
        if (remoteUserNotes.length > 0) pendingRemoteNotes.delete(sessionId);
        clearStreamedReplies(sessionId);
        const request = link.request("agent.prompt", {
          sessionId,
          text: args.text,
          timeoutMs: args.timeout_ms ?? 0,
          ...preset === void 0 ? {} : { presetId: args.preset_id },
          ...workspace === void 0 ? {} : { workspace: args.workspace }
        }, Math.max(read().timeoutMs ?? 12e4, (args.timeout_ms ?? 0) + 3e4));
        const parked = parkPrompt(sessionId, request);
        const signal = exec?.signal;
        let onAbortLocal = () => {
        };
        const aborted = new Promise((resolve2) => {
          onAbortLocal = () => resolve2({ kind: "abort" });
        });
        const onAbort = () => {
          inFlight.delete(sessionId);
          void interruptRemote(sessionId);
          onAbortLocal();
        };
        if (signal !== void 0) {
          if (signal.aborted === true) onAbort();
          else signal.addEventListener("abort", onAbort, { once: true });
        }
        try {
          const outcome = await Promise.race([
            request.then((reply) => ({ kind: "reply", reply })),
            parked.asked.then((frame) => ({ kind: "ask", frame })),
            parked.stopped.then((frame) => ({ kind: "stop", frame })),
            aborted
          ]);
          if (outcome.kind === "abort") {
            const cancelled = new Error("remote_agent_prompt: interrupted locally; the peer turn was cancelled");
            cancelled.name = "AbortError";
            throw cancelled;
          }
          if (outcome.kind === "stop") {
            inFlight.delete(sessionId);
            clearStreamedReplies(sessionId);
            memory.set(scopeKey(scope), sessionId);
            collectRemoteUsage(sessionId);
            return {
              sessionId,
              origin,
              interrupted: true,
              interruptCause: String(outcome.frame.cause ?? "user"),
              ...remoteUserNotes.length > 0 ? { remoteUserNotes } : {},
              ...priorInterrupt === void 0 ? {} : { priorInterrupt },
              note: "\u8FDC\u7AEF\u7528\u6237\u6253\u65AD\u8FD9\u4E00\u8F6E\uFF1A\u4E0D\u8981\u91CD\u8BD5\u3001\u4E0D\u8981\u81EA\u52A8\u7EE7\u7EED\uFF1B\u628A\u60C5\u51B5\u544A\u8BC9\u7528\u6237\uFF0C\u7B49\u7528\u6237\uFF08\u8FDC\u7AEF\u6216\u672C\u673A\uFF09\u7ED9\u51FA\u65B0\u6307\u793A\u3002"
            };
          }
          if (outcome.kind === "reply") {
            inFlight.delete(sessionId);
            memory.set(scopeKey(scope), sessionId);
            collectRemoteUsage(sessionId);
            const merged = mergeStreamedReplyValue(sessionId, outcome.reply);
            return {
              ...merged,
              ...replyFields(merged),
              origin,
              sessionId,
              ...remoteUserNotes.length > 0 ? { remoteUserNotes } : {},
              ...priorInterrupt === void 0 ? {} : { priorInterrupt }
            };
          }
          memory.set(scopeKey(scope), sessionId);
          return {
            sessionId,
            origin,
            ...remoteUserNotes.length > 0 ? { remoteUserNotes } : {},
            ...priorInterrupt === void 0 ? {} : { priorInterrupt },
            pendingQuestion: {
              qid: String(outcome.frame.qid ?? ""),
              questions: outcome.frame.questions ?? []
            },
            note: "\u5BF9\u7AEF agent \u6B63\u5728\u7B49\u4F60\u56DE\u7B54\u8FD9\u4E2A\u63D0\u95EE\u3002\u5148\u5BA1\u67E5\uFF1A\u80FD\u81EA\u884C\u5224\u65AD\u5C31\u76F4\u63A5\u7528 remote_answer_question \u4F5C\u7B54\uFF1B\u9700\u8981\u7528\u6237\u62CD\u677F\u5C31\u7528\u672C\u673A ask_user_question \u95EE\u7528\u6237\uFF0C\u518D\u628A\u5B83\u7684\u8FD4\u56DE\u4EA4\u7ED9 remote_answer_question\u3002"
          };
        } catch (error) {
          inFlight.delete(sessionId);
          clearStreamedReplies(sessionId);
          throw error;
        } finally {
          signal?.removeEventListener("abort", onAbort);
        }
      }
    }),
    defineTool5({
      name: "remote_answer_question",
      description: "\u628A\u5BF9\u7AEF\u7684\u63D0\u95EE\u7B54\u590D\u56DE\u53BB\uFF08\u5BF9\u7AEF\u6B63\u5728\u7B49\uFF09\uFF0C\u5E76\u7EE7\u7EED\u7B49\u8FD9\u4E00\u8F6E\u7ED3\u675F\u3001\u53D6\u56DE\u6700\u7EC8\u56DE\u590D\u3002question_id \u7528 remote_agent_prompt \u8FD4\u56DE\u7684 pendingQuestion.qid\uFF1Banswers \u662F {answers:[{id, selected:[...], custom?}]} \u5F62\u72B6\uFF0C\u4E5F\u53EF\u4EE5\u76F4\u63A5\u4F20\u672C\u673A ask_user_question \u7684\u8FD4\u56DE\u3002",
      parameters: {
        question_id: { type: "string", required: true, description: "pendingQuestion.qid\u3002" },
        answers: {
          type: "json",
          required: true,
          description: "\u5BF9\u6BCF\u4E2A\u95EE\u9898\u7684\u4F5C\u7B54 {answers:[{id, selected:[...], custom?}]}\uFF1B\u4E5F\u53EF\u76F4\u63A5\u4F20\u672C\u673A ask_user_question \u7684\u8FD4\u56DE\u3002"
        }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          const head = [
            `session: ${v.sessionId}`,
            `reason : ${v.reason ?? "(none)"}   seq: ${v.seq}   ${v.durationMs} ms`
          ];
          if (v.error !== null && v.error !== void 0 && v.error !== "") {
            head.push(`error  : ${v.error}`);
          }
          return renderText3([...head, renderRemoteReplies(value)].join("\n"));
        }
      },
      async execute(args) {
        const qid = text(args.question_id);
        const pending = qid === void 0 ? void 0 : relayedQuestions.get(qid);
        if (qid === void 0 || pending === void 0) {
          throw new Error(
            "remote_answer_question: no relayed question with that id (already answered, expired, or never asked)"
          );
        }
        const entry = inFlight.get(pending.sessionId);
        if (entry === void 0) {
          throw new Error(`remote_answer_question: no prompt in flight for session ${pending.sessionId}`);
        }
        await link.notify({ kind: "answer", qid, answer: args.answers });
        relayedQuestions.delete(qid);
        try {
          const reply = await entry.prompt;
          const merged = mergeStreamedReplyValue(pending.sessionId, reply);
          return { ...merged, ...replyFields(merged) };
        } finally {
          inFlight.delete(pending.sessionId);
          clearStreamedReplies(pending.sessionId);
        }
      }
    }),
    defineTool5({
      name: "remote_agent_ensure",
      description: "\u5728\u5BF9\u7AEF harness \u4E0A\u521B\u5EFA\u6216\u7EED\u63A5\u4E00\u4E2A agent \u4F1A\u8BDD\uFF0C\u4F46\u5148\u4E0D\u53D1\u8A00\u3002\u7528\u4E8E\u63D0\u524D\u628A\u4F1A\u8BDD\u5EFA\u597D\uFF08\u53EF\u6307\u5B9A preset\uFF09\uFF0C\u4E4B\u540E\u7528 remote_agent_prompt \u590D\u7528\u540C\u4E00\u4E2A session_id\u3002",
      parameters: {
        session_id: { type: "string", required: true, description: "\u5BF9\u7AEF\u4F1A\u8BDD id\u3002" },
        preset_id: { type: "string", description: "\u4EC5\u9996\u6B21\u521B\u5EFA\u65F6\u751F\u6548\u7684 preset id\u3002" },
        workspace: { type: "string", description: "\u4F1A\u8BDD\u7684\u5DE5\u4F5C\u76EE\u5F55\uFF08\u4EC5\u9996\u6B21\u521B\u5EFA\u65F6\u751F\u6548\uFF09\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          return renderText3(`session ${v.sessionId}: ${v.created ? "created" : "resumed"}`);
        }
      },
      async execute(args, exec) {
        const result = await link.request("agent.ensure", {
          sessionId: args.session_id,
          ...text(args.preset_id) === void 0 ? {} : { presetId: args.preset_id },
          ...text(args.workspace) === void 0 ? {} : { workspace: args.workspace }
        });
        memory.set(scopeKey(scopeOf(exec, sessionPrefixNow())), args.session_id);
        return result;
      }
    }),
    defineTool5({
      name: "remote_agent_events",
      description: "\u8BFB\u53D6\u5BF9\u7AEF\u67D0\u4E2A\u4F1A\u8BDD\u7684\u4E8B\u4EF6\u6D41\uFF08\u53EA\u542B\u5FC5\u8981\u5B57\u6BB5\uFF1A\u6D88\u606F\u6587\u672C\u3001\u5DE5\u5177\u8C03\u7528\u3001turn \u7ED3\u675F\u539F\u56E0\uFF09\u3002\u7528\u4E8E\u628A\u5BF9\u7AEF\u4E0A\u4E0B\u6587\u53D6\u56DE\u672C\u673A\u3001\u538B\u7F29\u540E\u518D\u6295\u9012\u56DE\u53BB\u3002\u9700\u8981\u8BE5\u4F1A\u8BDD\u5728\u5BF9\u7AEF\u6709\u6D3B\u52A8\u53E5\u67C4\uFF08\u5148 remote_agent_prompt \u6216 remote_agent_ensure \u8FC7\uFF09\u3002",
      parameters: {
        session_id: { type: "string", required: true, description: "\u5BF9\u7AEF\u4F1A\u8BDD id\u3002" },
        from_seq: { type: "number", description: "\u4ECE\u8BE5\u5E8F\u53F7\u5F00\u59CB\u53D6\uFF0C\u9ED8\u8BA4 0\u3002" },
        limit: { type: "number", description: "\u6700\u591A\u53D6\u591A\u5C11\u6761\uFF0C\u9ED8\u8BA4 400\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          const lines = [`session ${v.sessionId}  head_seq=${v.seq}  events=${v.events.length}`];
          for (const event of v.events) {
            const body = typeof event.text === "string" && event.text !== "" ? event.text.replace(/\s+/g, " ").slice(0, 160) : typeof event.name === "string" ? `${event.name} ${String(event.arguments ?? "").slice(0, 120)}` : typeof event.reason === "string" ? event.reason : "";
            lines.push(`${String(event.seq).padStart(5)}  ${String(event.type).padEnd(18)} ${body}`);
          }
          return renderText3(lines.join("\n"));
        }
      },
      async execute(args) {
        return await link.request("agent.events", {
          sessionId: args.session_id,
          fromSeq: args.from_seq ?? 0,
          limit: args.limit ?? 400
        });
      }
    }),
    defineTool5({
      name: "remote_journal",
      description: "\u8BFB**\u8FDC\u7AEF\u7684\u6267\u884C\u8F68\u8FF9**\uFF1A\u90A3\u53F0\u673A\u5668\u4E0A\u88AB\u6267\u884C\u7684\u6307\u4EE4\u3001\u6587\u4EF6\u8BFB\u5199\u3001\u88AB\u9A71\u52A8\u7684\u8F6E\u6B21\u3001\u6A21\u578B\u8C03\u7528\u4E0E\u7528\u6237\u6253\u65AD\uFF0C\u7531\u5BF9\u7AEF\u63D2\u4EF6\u5728\u64CD\u4F5C\u53D1\u751F\u65F6\u8FFD\u52A0\u2014\u2014**\u4E0D\u6D88\u8017\u4EFB\u4F55\u6A21\u578B\u8C03\u7528**\u3002\n\u9ED8\u8BA4\u53EA\u8FD4\u56DE**\u4F60\u4E0A\u6B21\u8BFB\u4E4B\u540E\u7684\u65B0\u6761\u76EE**\uFF08\u672C\u63D2\u4EF6\u6309 chat \u8BB0\u4F4F\u6E38\u6807\uFF09\uFF0C\u6240\u4EE5\u53CD\u590D\u8C03\u7528\u5F88\u4FBF\u5B9C\uFF1B\u8981\u770B\u7EC6\u8282\u4F20 full=true\uFF0C\u8981\u4ECE\u5934\u770B\u4F20 from_seq=0\u3002",
      parameters: {
        from_seq: { type: "number", description: "\u53EA\u8BFB\u8BE5\u5E8F\u53F7\u4E4B\u540E\u7684\u6761\u76EE\u3002\u7701\u7565 = \u63A5\u7740\u4E0A\u6B21\u8BFB\u5230\u7684\u4F4D\u7F6E\uFF1B0 = \u4ECE\u5934\u8BFB\u3002" },
        limit: { type: "number", description: "\u6700\u591A\u8FD4\u56DE\u591A\u5C11\u6761\uFF0C\u9ED8\u8BA4 50\uFF08\u4E0A\u9650 500\uFF09\u3002" },
        full: { type: "boolean", description: "true = \u5E26\u4E0A\u6BCF\u6761\u7684\u64CD\u4F5C\u7EC6\u8282\uFF08\u66F4\u5360\u4E0A\u4E0B\u6587\uFF09\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => renderText3(formatJournal(value).join("\n"))
      },
      async execute(args, exec) {
        const key = scopeKey(scopeOf(exec, sessionPrefixNow()));
        const remembered = journalMemory.get(key);
        const from = typeof args.from_seq === "number" ? args.from_seq : remembered === void 0 ? void 0 : Number(remembered);
        let reply;
        try {
          reply = await link.request("journal.read", {
            ...from === void 0 || !Number.isFinite(from) ? {} : { fromSeq: from },
            limit: args.limit ?? 50,
            ...args.full === true ? { full: true } : {}
          }, 3e4);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          if (/unknown op/iu.test(message)) return { unsupported: true, error: message };
          throw error;
        }
        const next = Number(reply.nextSeq);
        if (Number.isFinite(next)) journalMemory.set(key, String(next));
        return reply;
      }
    }),
    defineTool5({
      name: "remote_agent_interrupt",
      description: "\u6253\u65AD\u5BF9\u7AEF\u67D0\u4E2A\u4F1A\u8BDD\u6B63\u5728\u8DD1\u7684 turn\u3002",
      parameters: {
        session_id: { type: "string", required: true, description: "\u5BF9\u7AEF\u4F1A\u8BDD id\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          return renderText3(v.interrupted ? "interrupted" : `not interrupted: ${v.reason ?? "unknown"}`);
        }
      },
      async execute(args) {
        return await link.request("agent.interrupt", { sessionId: args.session_id });
      }
    }),
    defineTool5({
      name: "remote_preset_list",
      description: '\u5217\u51FA\u5BF9\u7AEF harness \u53EF\u7528\u7684 agent preset\uFF08\u60F3\u77E5\u9053"\u521B\u9020\u6A21\u5F0F"\u7684 id \u5C31\u7528\u5B83\uFF09\u3002',
      parameters: {},
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          if (!v.available) return renderText3("peer has no agentPresets service mounted");
          const lines = [`default: ${v.defaultId ?? "(none)"}`];
          for (const preset of v.presets) {
            lines.push(`- ${preset.id}${preset.name === "" ? "" : `\uFF08${preset.name}\uFF09`}${preset.broken === null ? "" : ` \u26A0\uFE0F ${preset.broken}`}`);
          }
          return renderText3(lines.join("\n"));
        }
      },
      async execute() {
        return await link.request("preset.list", {});
      }
    }),
    defineTool5({
      name: "remote_fs_list",
      description: "\u5217\u51FA\u8FDC\u7AEF\u76EE\u5F55\u5185\u5BB9\u3002",
      parameters: {
        path: { type: "string", required: true, description: "\u8FDC\u7AEF\u76EE\u5F55\u8DEF\u5F84\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          const lines = [`${v.path}  (${v.count} entries)`];
          for (const entry of v.entries) {
            const when = entry.mtimeMs === 0 ? "" : new Date(entry.mtimeMs).toISOString().slice(0, 19).replace("T", " ");
            lines.push(`${entry.isDir ? "dir " : "file"}  ${(entry.isDir ? "" : fmtBytes(entry.size)).padStart(10)}  ${when}  ${entry.name}`);
          }
          return renderText3(lines.join("\n"));
        }
      },
      async execute(args) {
        return await link.request("fs.list", { path: args.path });
      }
    }),
    defineTool5({
      name: "remote_fs_write",
      description: "\u628A\u6587\u672C\u5199\u5165\u8FDC\u7AEF\u6587\u4EF6\uFF08\u81EA\u52A8\u5EFA\u7236\u76EE\u5F55\uFF09\u3002\u5BF9\u7AEF\u652F\u6301\u65F6\uFF0C\u5927\u5185\u5BB9\u8D70\u5206\u5757+\u538B\u7F29\u7684\u5FEB\u8DEF\u5F84\u3002",
      parameters: {
        path: { type: "string", required: true, description: "\u8FDC\u7AEF\u6587\u4EF6\u8DEF\u5F84\u3002" },
        content: { type: "string", required: true, description: "\u8981\u5199\u5165\u7684\u6587\u672C\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          const legacy = `wrote ${v.written} bytes (remote size now ${v.size})`;
          if (v.fastPath !== true) return renderText3(legacy);
          const duration = typeof v.durationMs === "number" ? v.durationMs : 0;
          const rate = typeof v.rateMbps === "number" ? v.rateMbps.toFixed(2) : "0.00";
          return renderText3(`${legacy}
\u4F20\u8F93\uFF1A\u5206\u5757\u5FEB\u8DEF\u5F84\uFF0C\u8017\u65F6 ${duration} ms\uFF0C\u901F\u7387 ${rate} Mbit/s`);
        }
      },
      async execute(args, exec) {
        const data = Buffer.from(args.content, "utf8");
        const threshold = Number(read().transferFastPathBytes ?? 524288);
        if (data.length >= threshold) {
          try {
            if (await fastTransferSupported()) {
              const result = await uploadBuffer(transferRequest, args.path, data, {
                ...transferOptions(exec?.signal)
              });
              return {
                written: result.bytes,
                size: result.bytes,
                sha256: result.sha256,
                fastPath: true,
                durationMs: result.durationMs,
                rateMbps: result.rateMbps,
                created: result.created,
                version: result.version
              };
            }
          } catch (error) {
            if (commitOutcomeUnknown(error) && !isAbortError2(error)) {
              throw ambiguousCommitError(error);
            }
            if (!isUnknownTransferOp(error)) throw error;
            ctx.logger.debug(
              `dsh-remote-client: fast write unavailable, falling back to fs.write (${error instanceof Error ? error.message : String(error)})`
            );
          }
        }
        return await link.request("fs.write", {
          path: args.path,
          dataB64: data.toString("base64")
        });
      }
    }),
    defineTool5({
      name: "remote_put_file",
      description: "\u628A**\u672C\u673A**\u6587\u4EF6\u6D41\u5F0F\u4E0A\u4F20\u5230\u8FDC\u7AEF\uFF08\u5206\u5757 + \u9010\u5757 gzip + sha256 \u6821\u9A8C\uFF09\u3002\u9002\u5408\u5927\u6587\u4EF6\uFF1B\u5C0F\u6587\u672C\u4ECD\u7528 remote_fs_write \u66F4\u7701\u4E00\u6B21\u5F80\u8FD4\u3002\u9700\u8981 r19+ \u5BF9\u7AEF\u5E7F\u544A\u5206\u5757\u4F20\u8F93 op\uFF1B\u65E7\u5BF9\u7AEF\u4F1A\u62A5 unknown op\uFF0C\u6B64\u65F6\u6539\u7528 remote_exec \u7B49\u65B9\u5F0F\u3002",
      parameters: {
        local_path: { type: "string", required: true, description: "\u672C\u673A\u6E90\u6587\u4EF6\u8DEF\u5F84\u3002" },
        remote_path: { type: "string", required: true, description: "\u8FDC\u7AEF\u76EE\u6807\u6587\u4EF6\u8DEF\u5F84\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          const rate = typeof v.rateMbps === "number" ? `\uFF0C\u901F\u7387 ${v.rateMbps.toFixed(2)} Mbit/s` : "";
          return renderText3(
            `\u4E0A\u4F20 ${fmtBytes(v.bytes)}\uFF08${v.bytes} \u5B57\u8282\uFF09\uFF0C\u8017\u65F6 ${v.durationMs} ms${rate}${v.created === true ? "\uFF08\u65B0\u5EFA\uFF09" : ""}
sha256 ${v.sha256}`
          );
        }
      },
      async execute(args, exec) {
        throwIfAborted2(exec?.signal);
        if (!await fastTransferSupported()) {
          return await legacyUploadFile(args.local_path, args.remote_path, exec?.signal);
        }
        try {
          const result = await uploadFile(transferRequest, args.local_path, args.remote_path, {
            ...transferOptions(exec?.signal)
          });
          return {
            bytes: result.bytes,
            sha256: result.sha256,
            created: result.created,
            version: result.version,
            durationMs: result.durationMs,
            rateMbps: result.rateMbps
          };
        } catch (error) {
          if (commitOutcomeUnknown(error) && !isAbortError2(error)) {
            throw ambiguousCommitError(error);
          }
          if (!isUnknownTransferOp(error)) throw error;
          ctx.logger.debug(
            `dsh-remote-client: chunked upload unavailable, falling back to fs.write (${error instanceof Error ? error.message : String(error)})`
          );
          return await legacyUploadFile(args.local_path, args.remote_path, exec?.signal);
        }
      }
    }),
    defineTool5({
      name: "remote_get_file",
      description: "\u628A\u8FDC\u7AEF\u6587\u4EF6\u6D41\u5F0F\u4E0B\u8F7D\u5230**\u672C\u673A**\uFF08\u5206\u5757\u5E76\u884C + sha256 \u6821\u9A8C\uFF09\u3002\u5148\u5199\u4E34\u65F6\u6587\u4EF6\u3001\u6821\u9A8C\u901A\u8FC7\u540E\u518D\u6539\u540D\u8986\u76D6\uFF0C\u4E2D\u65AD\u4E0D\u4F1A\u7559\u4E0B\u534A\u6210\u54C1\uFF1B\u9002\u5408\u5927\u6587\u4EF6\u3002\u9700\u8981 r19+ \u5BF9\u7AEF\u5E7F\u544A\u5206\u5757\u4F20\u8F93 op\uFF1B\u65E7\u5BF9\u7AEF\u4F1A\u62A5 unknown op\u3002",
      parameters: {
        remote_path: { type: "string", required: true, description: "\u8FDC\u7AEF\u6E90\u6587\u4EF6\u8DEF\u5F84\u3002" },
        local_path: { type: "string", required: true, description: "\u672C\u673A\u76EE\u6807\u6587\u4EF6\u8DEF\u5F84\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => {
          const v = value;
          const rate = typeof v.rateMbps === "number" ? `\uFF0C\u901F\u7387 ${v.rateMbps.toFixed(2)} Mbit/s` : "";
          return renderText3(
            `\u4E0B\u8F7D ${fmtBytes(v.bytes)}\uFF08${v.bytes} \u5B57\u8282\uFF09\uFF0C\u8017\u65F6 ${v.durationMs} ms${rate}
sha256 ${v.sha256}`
          );
        }
      },
      async execute(args, exec) {
        throwIfAborted2(exec?.signal);
        if (!await fastTransferSupported()) {
          return await legacyDownloadFile(args.remote_path, args.local_path, exec?.signal);
        }
        try {
          const result = await downloadToFile(transferRequest, args.remote_path, args.local_path, {
            ...transferOptions(exec?.signal)
          });
          return {
            bytes: result.bytes,
            sha256: result.sha256,
            durationMs: result.durationMs,
            rateMbps: result.rateMbps
          };
        } catch (error) {
          if (!isUnknownTransferOp(error)) throw error;
          ctx.logger.debug(
            `dsh-remote-client: chunked download unavailable, falling back to fs.read (${error instanceof Error ? error.message : String(error)})`
          );
          return await legacyDownloadFile(args.remote_path, args.local_path, exec?.signal);
        }
      }
    }),
    defineTool5({
      name: "remote_capabilities",
      description: '\u5217\u51FA\u8FDC\u7AEF harness \u53EF\u76F4\u63A5 function call \u7684\u80FD\u529B\uFF1A\u8FDC\u7AEF\u67D0\u4E00 agent preset \u7684\u5DE5\u5177\uFF08\u542B\u53C2\u6570 schema\uFF09\u3001\u63D2\u4EF6\u6E05\u5355\u3001preset\uFF08\u5373\u5B50\u667A\u80FD\u4F53\u7C7B\u578B\uFF09\u3001\u5B50\u667A\u80FD\u4F53 provider\uFF0C\u4EE5\u53CA\u8FDC\u7AEF\u5F53\u524D\u6D3B\u8DC3\u4F1A\u8BDD\uFF08\u53EA\u8BFB\u4FE1\u606F\uFF09\u3002\n\u8FDC\u7AEF\u72EC\u6709\u5DE5\u5177\u5DF2\u76F4\u63A5\u6CE8\u518C\u8FDB\u5404 agent \u7684\u4F5C\u7528\u57DF\uFF08\u540C\u540D\u65F6\u672C\u673A\u5DE5\u5177\u4F18\u5148\uFF0C\u6765\u81EA\u672C\u673A/\u8FDC\u7AEF\u7684\u540C\u540D\u8005\u90FD\u4E0D\u4F1A\u4E92\u76F8\u8986\u76D6\uFF09\uFF1B\u8981\u6309\u540D\u5B57\u8C03\u7528\u3001\u6216\u770B\u67D0\u4E2A\u5DE5\u5177\u7684\u5B8C\u6574 schema\uFF0C\u7528 `remote_tool_call` / \u672C\u5DE5\u5177\u7684 `tool` \u53C2\u6570\u3002\n\u6CE8\u610F\uFF1A\u8FD9\u4E0D\u662F"\u8BA9\u8FDC\u7AEF\u5F00\u4E00\u6BB5\u5BF9\u8BDD"\uFF0C\u8BFB\u76EE\u5F55\u53EA\u5728\u8FDC\u7AEF\u6302\u8D77\u4E00\u4E2A preset scope\uFF0C\u4E0D\u521B\u5EFA/\u7EED\u63A5\u4EFB\u4F55\u4F1A\u8BDD\u3002',
      parameters: {
        peer: { type: "string", description: "\u5DF2\u914D\u7F6E\u7684\u4E3B\u673A\u540D\uFF1B\u7701\u7565\u4F7F\u7528\u9ED8\u8BA4\u4E3B\u673A\u3002" },
        preset_id: { type: "string", description: "\u8FDC\u7AEF preset id\uFF1B\u7701\u7565 = \u8FDC\u7AEF\u9ED8\u8BA4 preset\uFF08\u4E0D\u5F71\u54CD\u5DF2\u955C\u50CF\u5DE5\u5177\uFF09\u3002" },
        refresh: { type: "boolean", description: "true = \u7ACB\u5373\u91CD\u65B0\u62C9\u53D6\u76EE\u5F55\uFF08\u9ED8\u8BA4\u7528\u7F13\u5B58\uFF0C\u8FC7\u671F\u624D\u91CD\u62C9\uFF09\u3002" },
        tool: { type: "string", description: "\u53EA\u770B\u8FD9\u4E00\u4E2A\u8FDC\u7AEF\u5DE5\u5177\u7684\u5B8C\u6574\u53C2\u6570 schema\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => renderText3(String(value?.text ?? ""))
      },
      async execute(args, exec) {
        if (read().remoteCapabilities === false) {
          return { available: false, text: "\u672C\u673A\u5DF2\u5173\u95ED\u8FDC\u7AEF\u80FD\u529B\u955C\u50CF\uFF08dsh-remote-client: remoteCapabilities=false\uFF09\u3002" };
        }
        const requestedPreset = typeof args.preset_id === "string" ? args.preset_id.trim() : "";
        if (requestedPreset !== "" || args.peer !== void 0) {
          const catalog2 = await readPeerCatalog(requestedPreset, args.peer);
          return {
            ...catalogSummary(catalog2, exec?.agent),
            text: formatCatalog(catalog2, args.tool === void 0 ? {} : { tool: args.tool })
          };
        }
        await refreshCapabilityCatalog(args.refresh === true);
        const catalog = capabilityCatalog;
        if (catalog === void 0) {
          return { available: false, text: renderCapabilityCatalog(args.tool, exec?.agent) };
        }
        return {
          ...catalogSummary(catalog, exec?.agent),
          text: renderCapabilityCatalog(args.tool, exec?.agent)
        };
      }
    }),
    defineTool5({
      name: "remote_tool_call",
      description: "\u5728\u8FDC\u7AEF harness \u4E0A**\u6309\u540D\u5B57\u76F4\u63A5\u8C03\u7528\u4E00\u4E2A\u5DF2\u6CE8\u518C\u5DE5\u5177**\uFF0C\u8FD4\u56DE\u5B83\u6E32\u67D3\u597D\u7684\u7ED3\u679C\u3002\u7528\u4E8E\uFF1A\u672C\u673A\u540C\u540D\u5DE5\u5177\u628A\u8FDC\u7AEF\u5DE5\u5177\u906E\u6321\u3001\u5DE5\u5177\u56E0\u8FDC\u7AEF\u62D2\u7EDD\u7B56\u7565\u6CA1\u88AB\u955C\u50CF\u3001\u6216\u60F3\u663E\u5F0F\u6307\u5B9A\u8FDC\u7AEF preset\u3002\n\u8C03\u7528\u76F4\u63A5\u5728\u5BF9\u7AEF\u6267\u884C\u5DE5\u5177\u672C\u4F53\uFF1A\u4E0D\u65B0\u5EFA/\u7EED\u63A5\u8FDC\u7AEF\u5BF9\u8BDD\uFF0C\u4E0D\u6D88\u8017\u8FDC\u7AEF\u6A21\u578B\u8F6E\u6B21\uFF1B\u5BF9\u7AEF\u9700\u8981 session \u7684\u5DE5\u5177\uFF08\u5982 subagent\u3001todo_write\uFF09\u4F1A\u660E\u786E\u62A5\u9519\u800C\u4E0D\u662F\u66FF\u4F60\u5F00\u4F1A\u8BDD\u3002",
      parameters: {
        peer: { type: "string", description: "\u5DF2\u914D\u7F6E\u7684\u4E3B\u673A\u540D\uFF1B\u7701\u7565\u4F7F\u7528\u9ED8\u8BA4\u4E3B\u673A\u3002" },
        name: { type: "string", required: true, description: "\u8FDC\u7AEF\u5DE5\u5177\u540D\uFF08\u89C1 remote_capabilities\uFF09\u3002" },
        arguments: { type: "json", description: "\u4F20\u7ED9\u8BE5\u5DE5\u5177\u7684\u53C2\u6570\u5BF9\u8C61\u3002" },
        preset_id: { type: "string", description: "\u8FDC\u7AEF preset id\uFF1B\u7701\u7565 = \u672C\u63D2\u4EF6\u914D\u7F6E\u7684/\u8FDC\u7AEF\u9ED8\u8BA4 preset\u3002" },
        timeout_ms: { type: "number", description: "\u672C\u6B21\u8C03\u7528\u7684\u8D85\u65F6\u6BEB\u79D2\u6570\uFF08\u5BF9\u7AEF\u4ECD\u4F1A\u6309\u81EA\u5DF1\u7684\u4E0A\u9650\u518D\u5939\u4E00\u6B21\uFF09\u3002" }
      },
      output: {
        schema: { type: "json" },
        render: (_args, value) => renderText3(String(value?.text ?? ""))
      },
      async execute(args, exec) {
        if (read().remoteCapabilities === false) {
          throw new Error("\u672C\u673A\u5DF2\u5173\u95ED\u8FDC\u7AEF\u80FD\u529B\u955C\u50CF\uFF08dsh-remote-client: remoteCapabilities=false\uFF09");
        }
        const name2 = typeof args.name === "string" ? args.name.trim() : "";
        if (name2 === "") throw new Error("remote_tool_call: `name` \u4E0D\u80FD\u4E3A\u7A7A");
        const presetId = typeof args.preset_id === "string" && args.preset_id.trim() !== "" ? args.preset_id.trim() : void 0;
        const result = await callPeerTool(
          name2,
          args.arguments ?? {},
          exec?.signal,
          {
            ...presetId === void 0 ? {} : { presetId },
            ...args.timeout_ms === void 0 ? {} : { timeoutMs: args.timeout_ms },
            ...args.peer === void 0 ? {} : { peer: args.peer }
          }
        );
        return {
          content: result.content,
          ...result.durationMs === void 0 ? {} : { durationMs: result.durationMs },
          text: proxyResultText(result)
        };
      }
    })
  ];
  const runTools = read().backgroundRuns === false ? [] : createRunTools(runToolDeps);
  const poolTools = createPoolTools(poolDeps);
  const referenceTool = createReferenceTool({
    peers: () => Object.keys(peersNow()),
    list: referenceService.list
  });
  const allTools = [...tools, ...runTools, ...poolTools, referenceTool];
  ctx.on("loader/volatile-update", () => {
    link.close();
    dropSubagentIfDisabled();
    ensureSubagent();
    for (const pooled of pooledLinks.values()) pooled.dispose();
    pooledLinks.clear();
    capabilityGeneration += 1;
    capabilityInFlight = void 0;
    capabilityCatalog = void 0;
    capabilityCatalogAt = 0;
    capabilityUnsupported = false;
    capabilityCatalogFingerprint = "";
    try {
      const next = peersNow();
      validatePeerNames(Object.keys(next));
      const registry = ctx.get("dshRemotePeers");
      registry?.update({ peers: next, defaultPeer: text(read().defaultPeer) ?? "" });
      peers = next;
    } catch (error) {
      const registry = ctx.get("dshRemotePeers");
      registry?.update({ peers: {}, defaultPeer: "" });
      peers = {};
      ctx.logger.warn(`dsh-remote-client: invalid peer update; all mounts revoked (${String(error)})`);
    }
    if (read().remoteCapabilities === false) {
      void withdrawCapabilityMirrors();
    } else {
      void refreshCapabilityCatalog(true);
    }
  });
  const safeEffect = (fn, label) => {
    try {
      ctx.effect(fn, label);
    } catch (error) {
      ctx.logger.warn(`dsh-remote-client: could not register teardown (${String(error)})`);
    }
  };
  safeEffect(() => () => inboundIo.dispose(), "dsh-remote-client: release inbound IO adapter");
  safeEffect(() => () => {
    for (const pooled of pooledLinks.values()) pooled.dispose();
  }, "dsh-remote-client: close pooled peer links");
  let dropSubagent;
  let subagentPending = false;
  const ensureSubagent = () => {
    if (read().subagentProvider !== true || dropSubagent !== void 0 || subagentPending) return;
    subagentPending = true;
    try {
      ctx.inject(["subagents"], (subagentsCtx) => {
        void (async () => {
          try {
            const kit = await import("@deepseek-ai/dsh-subagent");
            const provider = createRemoteProvider({
              kit,
              name: "remote",
              sessionFor: sessionForProvider,
              prompt: (request) => operationPeer.run(operationPeer.getStore() ?? controlFor(), () => promptForProvider(request)),
              interrupt: interruptRemote,
              log
            });
            const dropProvider = subagentsCtx.subagents.registerProvider(
              provider
            );
            let dropTool;
            if (config.toolEnabled !== false) {
              ctx.inject(["tools"], (toolsCtx) => {
                dropTool = toolsCtx.tools.register(createRemoteSubagentTool(
                  subagentsCtx.subagents,
                  "remote"
                ));
                log(`dsh-remote-client: registered ${REMOTE_SUBAGENT_TOOL}`);
              });
            }
            dropSubagent = () => {
              dropTool?.();
              dropProvider();
            };
            log('dsh-remote-client: registered subagent provider "remote"');
          } catch (error) {
            ctx.logger.warn(
              `dsh-remote-client: subagent provider NOT registered (${error instanceof Error ? error.message : String(error)}); link \`@deepseek-ai/dsh-subagent\` into this plugin to enable it`
            );
          } finally {
            subagentPending = false;
          }
        })();
      });
    } catch (error) {
      subagentPending = false;
      ctx.logger.warn(`dsh-remote-client: could not register the subagent provider (${String(error)})`);
    }
  };
  const dropSubagentIfDisabled = () => {
    if (read().subagentProvider === true) return;
    try {
      dropSubagent?.();
    } catch (error) {
      ctx.logger.warn(`dsh-remote-client: could not drop the subagent provider (${String(error)})`);
    }
    dropSubagent = void 0;
  };
  ensureSubagent();
  try {
    const store = currentCostStore();
    if (read().costReporting === true && store.summary().records > 0) {
      void store.refreshSnapshot();
    }
  } catch (error) {
    ctx.logger.debug(
      `dsh-remote-client: cost snapshot refresh failed (${error instanceof Error ? error.message : String(error)})`
    );
  }
  if (config.toolEnabled === false) {
    safeEffect(() => () => link.dispose(), "dsh-remote-client: close link");
    return;
  }
  ctx.inject(["tools"], (toolsCtx) => {
    for (const tool of allTools) toolsCtx.tools.register(bindOperation(tool));
    log(
      `dsh-remote-client: registered ${allTools.length} tools (peer ${text(read().host) ?? "?"}:${read().port ?? 0}, fingerprint ${fingerprintSafe(read)})`
    );
    attachCapabilityMirrors();
  });
  if (read().promptGuidance !== false) {
    ctx.inject(["systemPrompt"], (promptCtx) => {
      promptCtx.systemPrompt.section({
        name: "dsh-remote:controller",
        // A free slot just before the first-party tool guidance (900 is taken by
        // file references, 1000 by the bash tool).
        order: 960,
        text: (context) => {
          const current = read();
          const peers2 = peersNow();
          if (Object.keys(peers2).length === 0) return "";
          const prefix = sessionPrefixNow();
          const session = context.agent?.session?.id;
          const own = typeof session === "string" && session !== "" ? anchorSessionId(prefix, session) : void 0;
          const endpoint = text(current.host) === void 0 || (current.port ?? 0) <= 0 ? `\u5DF2\u58F0\u660E ${Object.keys(peers2).length} \u4E2A peer` : `\u5BF9\u7AEF ${text(current.host)}:${current.port}`;
          return [
            "## \u8FDC\u7AEF harness\uFF08dsh-remote \u63D2\u4EF6\uFF09",
            `\u672C\u673A\u53EF\u4EE5\u9A71\u52A8\u53E6\u4E00\u53F0\u673A\u5668\u4E0A\u7684 DSH \u5B9E\u4F8B\uFF08${endpoint}\uFF09\u3002\u628A\u6BCF\u6BB5\u8FDC\u7AEF\u5BF9\u8BDD\u5F53\u4F5C**\u4F60\u81EA\u5DF1\u7684\u4E00\u4E2A subagent / task**\uFF1A\u4F60\u6D3E\u6D3B\u3001\u5B83\u4EA4\u4ED8\uFF0C\u7ED3\u8BBA\u4E0E\u4EA7\u7269\u6458\u8981\u5FC5\u987B\u5E26\u56DE\u672C\u673A\u4E0A\u4E0B\u6587\uFF0C\u4E0D\u8981\u628A\u5B83\u5F53\u6210\u672C\u673A\u7F16\u6392\u7684\u6267\u884C\u5668\u3002`,
            "**\u4E00\u4E2A chat \u53EA\u5BF9\u5E94\u4E00\u4E2A\u8FDC\u7AEF\u5BF9\u8BDD\uFF08\u4E25\u683C\u8981\u6C42\uFF09\u3002**" + (own === void 0 ? "\u672C chat \u7684\u8FDC\u7AEF\u4F1A\u8BDD\u6309\u672C\u673A\u4F1A\u8BDD\u63A8\u5BFC\uFF0C\u7701\u7565 session_id \u65F6\u4F1A\u81EA\u52A8\u7EED\u63A5\u5B83\u3002" : `\u672C chat \u7684\u8FDC\u7AEF\u4F1A\u8BDD\u56FA\u5B9A\u662F \`${own}\`\uFF0C\u7701\u7565 session_id \u5373\u7EED\u63A5\u5B83\u3002`),
            "\u4E0D\u8981\u4E3A\u4E86\u300C\u9694\u79BB\u300D\u6216\u300C\u6362\u4E2A\u8BDD\u9898\u300D\u800C\u4F20 session_id / new_session \u2014\u2014 \u90A3\u53EA\u4F1A\u8BA9\u5BF9\u7AEF\u591A\u5F00\u4E00\u6BB5\u5BF9\u8BDD\u3002\u53EA\u6709\u7528\u6237\u660E\u786E\u8981\u6C42\u53E6\u8D77\u4E00\u6BB5\u65F6\uFF0C\u624D\u7528 new_session=true\u3002",
            "**\u672C\u673A\u4F18\u5148**\uFF1A\u80FD\u5728\u672C\u673A\u4E0A\u4E0B\u6587\u91CC\u5B8C\u6210\u7684\u4E8B\u5C31\u5728\u672C\u673A\u505A\uFF1B\u53EA\u6709\u786E\u5B9E\u5FC5\u987B\u8DD1\u5728\u5BF9\u7AEF\u673A\u5668\u4E0A\u7684\u52A8\u4F5C\uFF08\u5BF9\u7AEF\u7684\u6587\u4EF6\u3001\u5BF9\u7AEF\u7684\u73AF\u5883\u3001\u5BF9\u7AEF\u5DF2\u6709\u7684\u4F1A\u8BDD\uFF09\u624D\u7528 remote_* \u5DE5\u5177\u3002\u975E\u5FC5\u8981\u4E0D\u65B0\u5F00\u5BF9\u8BDD\uFF0C\u4E5F\u4E0D\u8981\u4E3A\u7410\u788E\u6B65\u9AA4\u53CD\u590D\u5F80\u8FD4\u3002",
            ...read().remoteCapabilities !== false ? ["**\u8FDC\u7AEF\u80FD\u529B\u76F4\u8FDE**\uFF1A\u5BF9\u7AEF\u72EC\u6709\u5DE5\u5177\u5DF2\u6CE8\u518C\u8FDB\u672C agent \u7684\u4F5C\u7528\u57DF\uFF08\u672C\u673A\u540C\u540D\u5DE5\u5177\u4F18\u5148\uFF0C\u65E0\u524D\u7F00\uFF09\uFF1B`remote_capabilities` \u5217\u5BF9\u7AEF\u80FD\u529B\uFF08\u5DE5\u5177/\u63D2\u4EF6/preset/provider\uFF09\uFF0C`remote_tool_call(name, arguments)` \u6309\u540D\u8C03\u7528\uFF08\u672C\u673A\u906E\u6321\u65F6\u7528\u5B83\uFF09\u3002\u8FD9\u4E9B\u8C03\u7528\u76F4\u63A5\u6267\u884C\u5BF9\u7AEF\u5DE5\u5177\u672C\u4F53\uFF0C\u4E0D\u65B0\u5EFA/\u7EED\u63A5\u8FDC\u7AEF\u5BF9\u8BDD\u3001\u4E0D\u6D88\u8017\u8FDC\u7AEF\u6A21\u578B\u8F6E\u6B21\uFF1B\u9700\u8981\u4F1A\u8BDD\u7684\u5DE5\u5177\uFF08subagent \u7B49\uFF09\u4F1A\u62A5\u9519\u800C\u4E0D\u662F\u66FF\u4F60\u5F00\u4F1A\u8BDD\u3002"] : [],
            ...read().subagentProvider !== false ? ["\u6574\u5757\u5B50\u4EFB\u52A1\u7528 `subagent_remote(description, prompt)` \u59D4\u6D3E\u2014\u2014\u5B83\u4F1A\u4F5C\u4E3A subagent \u51FA\u73B0\u5728\u672C\u5BF9\u8BDD\u91CC\uFF1B\u96F6\u6563\u7684\u4E00\u8F6E\u53D1\u8A00\u6216\u8FFD\u95EE\u7528 `remote_agent_prompt`\u3002\u4E24\u8005\u6253\u7684\u662F\u540C\u4E00\u6BB5\u8FDC\u7AEF\u5BF9\u8BDD\u3002"] : [],
            ...read().backgroundRuns !== false ? ["**\u957F\u4EFB\u52A1 / \u4E0D\u60F3\u963B\u585E\u672C\u8F6E**\u7528 `remote_run_start`\uFF1A\u5B83\u7ACB\u5373\u8FD4\u56DE runId\uFF0C\u540E\u53F0\u7EE7\u7EED\u8DD1\uFF1B\u4E4B\u540E\u7528 `remote_run_status(run_id, wait_ms?)` \u53D6\u4EA4\u4ED8\uFF08\u7ED3\u679C\u4E0D\u4F1A\u81EA\u52A8\u51FA\u73B0\uFF09\uFF0C`remote_send_message(run_id=...)` \u8FFD\u52A0\u6307\u793A\uFF0C`remote_run_cancel(run_id=...)` \u6253\u65AD\u3002\u8981**\u4EA4\u4ED8\u8FDB\u672C\u5BF9\u8BDD**\u3001\u503C\u5F97\u7B49\u5F85\u7684\u6574\u5757\u4EFB\u52A1\u4ECD\u7528 `subagent_remote`\uFF0C\u4E0D\u8981\u4E24\u8005\u6DF7\u7528\u540C\u4E00\u4E2A\u4EFB\u52A1\u3002"] : [],
            ...Object.keys(peers2).length > 1 ? ["**\u591A\u4E2A\u8FDC\u7AEF worker**\uFF1A`remote_workers` \u5217\u51FA\u5DF2\u58F0\u660E\u7684 peer\uFF1B`remote_worker_prompt(peer, text)` \u6307\u5B9A\u4E00\u53F0\uFF1B`remote_pool_dispatch(prompt, peers?)` \u628A\u540C\u4E00\u4EFB\u52A1\u5E76\u884C\u6D3E\u7ED9\u591A\u53F0\u5E76\u805A\u5408\u7ED3\u679C\uFF08\u5355\u53F0\u5931\u8D25\u4E0D\u5F71\u54CD\u5176\u4ED6\u53F0\uFF09\u3002"] : [],
            ...teamService() === void 0 ? [] : ["\u5728 **Agent Teams** \u4F1A\u8BDD\u91CC\uFF0C`remote_team_dispatch(description, prompt, peer?)` \u4F1A\u628A\u8FD9\u6B21\u8FDC\u7AEF\u5DE5\u4F5C\u767B\u8BB0\u5230\u5171\u4EAB\u4EFB\u52A1\u677F\uFF08\u5EFA\u4EFB\u52A1\u2192\u8BA4\u9886\u2192\u5B8C\u6210\u540E\u5199\u56DE\u6458\u8981\uFF09\uFF0C\u8FD4\u56DE\u7684 taskId \u53EF\u7528 `team_task_get` \u67E5\uFF1B\u8FDC\u7AEF peer \u672C\u8EAB\u4E0D\u5728 roster \u91CC\uFF0C\u770B\u677F\u4E0A\u7684 owner \u662F\u8C03\u7528\u65B9\u3002\u53EA\u662F\u5E76\u884C\u5237\u591A\u53F0\u3001\u4E0D\u8981\u6C42\u770B\u677F\u65F6\u7528 `remote_pool_dispatch`\u3002"],
            "**\u6253\u65AD\u9AD8\u4E8E\u4E00\u5207**\uFF1A\u7528\u6237\u5728\u672C\u673A\u4E2D\u65AD\u65F6\uFF0C\u63D2\u4EF6\u4F1A\u540C\u65F6\u4E2D\u65AD\u5BF9\u7AEF\u90A3\u4E00\u8F6E\uFF1B\u82E5\u8FDC\u7AEF\u8FD4\u56DE\u91CC\u51FA\u73B0 interrupted / \u88AB\u6253\u65AD\u7684\u6807\u8BB0\uFF0C\u7ACB\u523B\u505C\u4E0B\uFF0C\u4E0D\u8981\u91CD\u8BD5\u3001\u4E0D\u8981\u81EA\u52A8\u7EE7\u7EED\uFF0C\u628A\u5F53\u524D\u72B6\u6001\u548C\u9009\u62E9\u6743\u4EA4\u56DE\u7528\u6237\u3002",
            '\u9700\u8981\u77E5\u9053"\u5BF9\u7AEF\u5230\u5E95\u505A\u4E86\u4EC0\u4E48"\u65F6\u7528 `remote_journal` \u8BFB\u5B83\u7684\u6267\u884C\u8F68\u8FF9\u2014\u2014\u4E0D\u6D88\u8017\u6A21\u578B\u8C03\u7528\uFF0C\u4E14\u9ED8\u8BA4\u53EA\u8FD4\u56DE**\u4E0A\u6B21\u8BFB\u8FC7\u4E4B\u540E\u7684\u65B0\u6761\u76EE**\uFF0C\u6240\u4EE5\u53EF\u4EE5\u653E\u5FC3\u5730\u53CD\u590D\u67E5\u3002'
          ].join("\n");
        }
      });
    });
  }
  safeEffect(() => () => link.dispose(), "dsh-remote-client: close link");
}
function fingerprintSafe(read) {
  try {
    return fingerprint(resolvePeerPublicKey(read(), "server.pub"));
  } catch {
    return "(peer key not configured)";
  }
}
export {
  BUILD,
  CLIENT_VERSION,
  Config,
  DSH_REMOTE_CLIENT_SETTINGS_NAMESPACE,
  LinkClient,
  apply,
  name
};
