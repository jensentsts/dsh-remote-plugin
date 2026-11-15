// src/mesh.ts
import { Service } from "@deepseek-ai/cordis";
import { isVolatile } from "@deepseek-ai/cosmokit";
import z from "@deepseek-ai/schemastery";
import { connect } from "node:net";

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
    const { connect: connect2 } = await import("node:net");
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
    const open2 = async () => {
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
      const socket2 = connect2({ host, port });
      this.connecting.add(socket2);
      socket2.once("close", () => {
        this.connecting.delete(socket2);
      });
      try {
        await new Promise((resolve2, reject) => {
          const clean = () => {
            clearTimeout(timer);
            socket2.off("connect", connected);
            socket2.off("error", failed);
            socket2.off("close", closed);
          };
          const connected = () => {
            clean();
            resolve2();
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
    let socket = await open2();
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
        socket = await open2();
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
      const failure2 = error instanceof HandshakeError ? error : new HandshakeError(`${this.label}: peer identity is no longer valid`);
      this.failSession(session, failure2);
      throw failure2;
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
      const failure2 = new PeerResponseError(String(reply.error ?? "peer reported failure"));
      if (typeof reply.code === "string") {
        failure2.peerCode = reply.code;
      }
      waiter.reject(failure2);
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

// src/relay-socket.ts
import { Duplex } from "node:stream";
var RELAY_CHUNK_BYTES = 48 * 1024;
var RELAY_RECEIVE_BYTES = 1024 * 1024;
function decodeRelayData(value) {
  if (typeof value !== "string" || value.length > 4 * Math.ceil(RELAY_CHUNK_BYTES / 3) || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) {
    throw new Error("invalid relay base64");
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.length > RELAY_CHUNK_BYTES || bytes.toString("base64") !== value) throw new Error("invalid relay base64");
  return bytes;
}
function failure(error) {
  return error instanceof Error ? error : new Error("relay request failed");
}
var RelaySocket = class extends Duplex {
  tunnelId;
  connecting = false;
  pending = false;
  remoteAddress = "relay";
  remoteFamily = "relay";
  localAddress = void 0;
  localPort = void 0;
  remotePort = void 0;
  bytesRead = 0;
  bytesWritten = 0;
  channel;
  maxReceiveBytes;
  cancellation = new AbortController();
  nextSend = 1;
  nextReceive = 1;
  peerClosed = false;
  timeoutMs = 0;
  timeoutTimer;
  referenced = true;
  constructor(tunnelId, channel, options = {}) {
    super({
      readableHighWaterMark: RELAY_CHUNK_BYTES,
      writableHighWaterMark: RELAY_CHUNK_BYTES,
      allowHalfOpen: false,
      autoDestroy: true
    });
    const limit = options.maxReceiveBytes ?? RELAY_RECEIVE_BYTES;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > RELAY_RECEIVE_BYTES) throw new Error("invalid relay receive limit");
    this.tunnelId = tunnelId;
    this.channel = channel;
    this.maxReceiveBytes = limit;
    this.on("error", () => {
    });
  }
  /** A narrow cast at the transport boundary; no native socket internals are used. */
  asSocket() {
    return this;
  }
  /** Admission is synchronous: a slow consumer can retain at most 1 MiB. */
  receive(seq, dataB64) {
    if (this.destroyed || this.peerClosed) return false;
    try {
      return this.receiveChunk(seq, decodeRelayData(dataB64));
    } catch (error) {
      this.destroy(failure(error));
      return false;
    }
  }
  /** Adopt an already canonical-decoded mesh race-buffer chunk without copying it. */
  receiveChunk(seq, bytes) {
    if (this.destroyed || this.peerClosed) return false;
    try {
      if (!Number.isSafeInteger(seq) || seq !== this.nextReceive || this.nextReceive > Number.MAX_SAFE_INTEGER) {
        throw new Error("invalid relay receive sequence");
      }
      if (!Buffer.isBuffer(bytes) || bytes.length > RELAY_CHUNK_BYTES) throw new Error("invalid relay chunk");
      if (this.readableLength + bytes.length > this.maxReceiveBytes) throw new Error("relay receive buffer exceeded");
      this.nextReceive += 1;
      this.bytesRead += bytes.length;
      this.activity();
      if (bytes.length !== 0) this.push(bytes);
      return true;
    } catch (error) {
      this.destroy(failure(error));
      return false;
    }
  }
  /** Remote/epoch closure must not echo another close or resurrect the channel. */
  remoteClosed(reason = "relay tunnel closed") {
    if (this.destroyed) return;
    this.peerClosed = true;
    this.push(null);
    this.destroy(new Error(reason));
  }
  _read() {
  }
  _write(chunk, encoding, callback) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    void (async () => {
      for (let offset = 0; offset < bytes.length; offset += RELAY_CHUNK_BYTES) {
        if (this.destroyed || this.peerClosed || this.cancellation.signal.aborted) throw new Error("relay tunnel closed during write");
        if (!Number.isSafeInteger(this.nextSend)) throw new Error("relay send sequence exhausted");
        const block = bytes.subarray(offset, offset + RELAY_CHUNK_BYTES);
        const seq = this.nextSend++;
        const reply = await this.untilClosed(this.channel.request("relay.write", {
          tunnelId: this.tunnelId,
          seq,
          dataB64: block.toString("base64")
        }));
        if (reply.written !== true) throw new Error("invalid relay write acknowledgement");
        this.bytesWritten += block.length;
        this.activity();
      }
    })().then(() => callback(), (error) => callback(failure(error)));
  }
  async untilClosed(work) {
    const signal = this.cancellation.signal;
    if (signal.aborted) {
      void work.catch(() => {
      });
      throw new Error("relay tunnel closed during write");
    }
    let abort;
    try {
      return await Promise.race([work, new Promise((_resolve, reject) => {
        abort = () => reject(new Error("relay tunnel closed during write"));
        signal.addEventListener("abort", abort, { once: true });
      })]);
    } finally {
      if (abort !== void 0) signal.removeEventListener("abort", abort);
    }
  }
  _final(callback) {
    callback();
    this.destroy();
  }
  _destroy(error, callback) {
    this.cancellation.abort();
    this.clearIdleTimer();
    if (!this.peerClosed) {
      this.peerClosed = true;
      try {
        void this.channel.request("relay.close", { tunnelId: this.tunnelId }).catch(() => {
        });
      } catch {
      }
    }
    callback(error);
  }
  /** Native Socket compatibility used by LinkClient, ByteReader and Session. */
  setNoDelay(_noDelay = true) {
    return this;
  }
  setKeepAlive(_enable = false, _initialDelay = 0) {
    return this;
  }
  setTimeout(timeout, callback) {
    if (!Number.isSafeInteger(timeout) || timeout < 0 || timeout > 2147483647) throw new RangeError("invalid socket timeout");
    if (callback !== void 0) this.once("timeout", callback);
    this.timeoutMs = timeout;
    this.activity();
    return this;
  }
  ref() {
    this.referenced = true;
    this.timeoutTimer?.ref?.();
    return this;
  }
  unref() {
    this.referenced = false;
    this.timeoutTimer?.unref?.();
    return this;
  }
  address() {
    return {};
  }
  resetAndDestroy() {
    this.destroy();
    return this;
  }
  destroySoon() {
    this.end();
  }
  get bufferSize() {
    return this.writableLength;
  }
  get readyState() {
    if (this.destroyed) return "closed";
    if (!this.readable) return "writeOnly";
    if (!this.writable) return "readOnly";
    return "open";
  }
  clearIdleTimer() {
    if (this.timeoutTimer !== void 0) clearTimeout(this.timeoutTimer);
    this.timeoutTimer = void 0;
  }
  activity() {
    this.clearIdleTimer();
    if (this.timeoutMs === 0 || this.destroyed) return;
    this.timeoutTimer = setTimeout(() => {
      this.timeoutTimer = void 0;
      this.emit("timeout");
    }, this.timeoutMs);
    if (!this.referenced) this.timeoutTimer.unref?.();
  }
};

// src/mesh.ts
var name = "dsh-remote-mesh";
var MeshConfigSchema = z.object({
  host: z.string().default(""),
  port: z.number().step(1).min(0).max(65535).default(0),
  privateKey: z.string().role("secret").default(""),
  privateKeyFile: z.string().default(dshHomePath("dsh-remote", "client.key")),
  autoGenerateKey: z.boolean().default(false),
  peerPublicKey: z.string().default(""),
  peerPublicKeyFile: z.string().default(dshHomePath("dsh-remote", "hub.pub")),
  timeoutMs: z.number().step(1).min(1).max(6e5).default(15e3),
  allowLegacyHandshake: z.boolean().default(false),
  maxSessionMs: z.number().step(1).min(100).max(36e5).default(36e5),
  acceptInbound: z.boolean().default(false),
  targetPort: z.number().step(1).min(1).max(65535).default(11325),
  autoReconnect: z.boolean().default(true),
  reconnectMinMs: z.number().step(1).min(100).max(6e4).default(1e3),
  reconnectMaxMs: z.number().step(1).min(100).max(6e4).default(3e4)
}).default({});
var Config = MeshConfigSchema.volatile();
var MAX_TUNNELS = 16;
var MAX_EARLY_FRAMES = 1024;
var TUNNEL_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
function nodeName(value) {
  return typeof value === "string" && /^[A-Za-z0-9._-]{2,128}$/u.test(value) && !["rmt", ".", "..", "__proto__", "constructor", "prototype"].includes(value.toLowerCase());
}
function errorOf(value) {
  return value instanceof Error ? value : new Error("mesh operation failed");
}
function configured(config) {
  return typeof config.host === "string" && config.host.trim() !== "" && (config.port ?? 0) > 0;
}
var MeshNode = class {
  read;
  log;
  dependencies;
  current;
  configId;
  invalidConfig = false;
  epoch;
  disposed = false;
  failures = 0;
  reconnectTimer;
  lastError;
  constructor(read, log = () => {
  }, dependencies = {}) {
    this.read = read;
    this.log = log;
    this.dependencies = dependencies;
    this.current = this.validate(read());
    this.configId = JSON.stringify(this.current);
    this.start();
  }
  validate(input) {
    const value = MeshConfigSchema(input);
    if ((value.reconnectMinMs ?? 1e3) > (value.reconnectMaxMs ?? 3e4)) throw new Error("mesh reconnect minimum exceeds maximum");
    if (value.relayTarget !== void 0 && value.relayTarget !== "") throw new Error("mesh hub cannot itself be a relay target");
    return value;
  }
  /** Committed settings changes synchronously invalidate every old key/channel. */
  refresh() {
    if (this.disposed) return;
    let value;
    try {
      value = this.validate(this.read());
    } catch (error) {
      this.invalidConfig = true;
      this.clearReconnect();
      if (this.epoch !== void 0) this.retire(this.epoch, errorOf(error), false);
      this.lastError = "invalid mesh configuration";
      return;
    }
    const identity = JSON.stringify(value);
    if (!this.invalidConfig && identity === this.configId) return;
    this.invalidConfig = false;
    this.configId = identity;
    this.current = value;
    this.failures = 0;
    this.lastError = void 0;
    this.clearReconnect();
    if (this.epoch !== void 0) this.retire(this.epoch, new Error("mesh configuration changed"), false);
    this.start();
  }
  start() {
    if (this.disposed || this.invalidConfig || !configured(this.current) || this.epoch !== void 0 || this.reconnectTimer !== void 0) return;
    void this.ensureRegistered().catch(() => {
    });
  }
  createEpoch() {
    if (this.disposed) throw new Error("mesh disposed");
    if (this.invalidConfig) throw new Error("invalid mesh configuration");
    const config = this.current;
    if (!configured(config)) throw new Error("mesh hub host and port are not configured");
    if (!config.peerPublicKey?.trim() && !config.peerPublicKeyFile?.trim()) throw new Error("mesh hub public-key pin is required");
    const link = this.dependencies.createChannel?.(config) ?? new LinkClient(() => config, (message) => this.log(message), "dsh-remote-mesh hub");
    const epoch = {
      link,
      config,
      abort: new AbortController(),
      tunnels: /* @__PURE__ */ new Map(),
      locals: /* @__PURE__ */ new Set(),
      incoming: /* @__PURE__ */ new Set(),
      early: /* @__PURE__ */ new Map(),
      earlyBytes: 0,
      earlyFrames: 0,
      pendingOpens: 0,
      retired: false,
      registered: false
    };
    this.epoch = epoch;
    link.onDisconnect((error) => {
      this.retire(epoch, error);
    });
    link.onEvent((frame) => {
      try {
        this.refresh();
        if (!epoch.retired && this.epoch === epoch) this.event(epoch, frame);
      } catch (error) {
        this.retire(epoch, errorOf(error));
      }
    });
    return epoch;
  }
  assertEpoch(epoch) {
    if (this.disposed || epoch.retired || this.epoch !== epoch || epoch.abort.signal.aborted) throw new Error("mesh hub connection closed");
  }
  async rpc(epoch, op, args = {}) {
    this.assertEpoch(epoch);
    if (epoch.registered && !epoch.link.connected) {
      this.retire(epoch, new Error("mesh hub disconnected"));
      throw new Error("mesh hub disconnected");
    }
    try {
      const work = epoch.link.request(op, args, epoch.config.timeoutMs ?? 15e3, { retries: 0 });
      const result = await raceAbort(work, epoch.abort.signal);
      this.assertEpoch(epoch);
      return result;
    } catch (error) {
      if (!epoch.retired && !epoch.link.connected) this.retire(epoch, errorOf(error));
      throw error;
    }
  }
  async ensureRegistered() {
    if (this.disposed) throw new Error("mesh disposed");
    this.clearReconnect();
    const epoch = this.epoch ?? this.createEpoch();
    if (epoch.registration === void 0) {
      epoch.registration = (async () => {
        try {
          const result = await this.rpc(epoch, "relay.register");
          if (!nodeName(result.nodeId)) throw new Error("invalid mesh registration response");
          this.assertEpoch(epoch);
          epoch.nodeId = result.nodeId;
          epoch.registered = true;
          this.failures = 0;
          this.lastError = void 0;
        } catch (error) {
          this.retire(epoch, errorOf(error));
          throw error;
        }
      })();
      void epoch.registration.catch(() => {
      });
    }
    await epoch.registration;
    this.assertEpoch(epoch);
    return epoch;
  }
  /** Return only transport bytes. The caller still authenticates its target pin. */
  async open(target) {
    this.refresh();
    if (!nodeName(target)) throw new Error("invalid mesh target identity");
    const epoch = await this.ensureRegistered();
    if (epoch.tunnels.size + epoch.pendingOpens >= MAX_TUNNELS) throw new Error("too many mesh tunnels");
    epoch.pendingOpens += 1;
    let socket;
    try {
      const result = await this.rpc(epoch, "relay.open", { target });
      this.assertEpoch(epoch);
      if (typeof result.tunnelId !== "string" || !TUNNEL_ID.test(result.tunnelId) || epoch.tunnels.has(result.tunnelId)) {
        this.retire(epoch, new Error("invalid mesh open response"));
        throw new Error("invalid mesh open response");
      }
      socket = this.attach(epoch, result.tunnelId);
      const early = epoch.early.get(result.tunnelId);
      if (early !== void 0) {
        epoch.early.delete(result.tunnelId);
        for (const chunk of early.chunks) {
          epoch.earlyBytes -= chunk.bytes.length;
          epoch.earlyFrames -= 1;
          socket.receiveChunk(chunk.seq, chunk.bytes);
        }
        if (early.closed !== void 0) socket.remoteClosed(early.closed);
      }
      if (socket.destroyed) throw new Error("mesh tunnel closed before open completed");
      return socket.asSocket();
    } catch (error) {
      socket?.destroy(errorOf(error));
      throw error;
    } finally {
      epoch.pendingOpens -= 1;
      if (epoch.pendingOpens === 0) {
        epoch.early.clear();
        epoch.earlyBytes = 0;
        epoch.earlyFrames = 0;
      }
    }
  }
  attach(epoch, tunnelId) {
    const socket = new RelaySocket(tunnelId, { request: (op, args) => this.rpc(epoch, op, args) });
    epoch.tunnels.set(tunnelId, socket);
    socket.once("close", () => {
      if (epoch.tunnels.get(tunnelId) === socket) epoch.tunnels.delete(tunnelId);
    });
    return socket;
  }
  event(epoch, frame) {
    const { kind, tunnelId } = frame;
    if (!["relay.offer", "relay.data", "relay.closed"].includes(String(kind)) || typeof tunnelId !== "string" || !TUNNEL_ID.test(tunnelId)) throw new Error("invalid mesh event");
    if (kind === "relay.offer") {
      if (!nodeName(frame.from) || epoch.tunnels.has(tunnelId) || epoch.incoming.has(tunnelId)) throw new Error("invalid mesh offer");
      if (epoch.config.acceptInbound !== true || epoch.tunnels.size + epoch.pendingOpens >= MAX_TUNNELS) {
        this.closeOffered(epoch, tunnelId);
        return;
      }
      epoch.incoming.add(tunnelId);
      const relay = this.attach(epoch, tunnelId);
      void this.accept(epoch, relay).catch(() => {
        relay.destroy(new Error("mesh local target unavailable"));
      }).finally(() => {
        epoch.incoming.delete(tunnelId);
      });
      return;
    }
    const socket = epoch.tunnels.get(tunnelId);
    if (socket !== void 0) {
      if (kind === "relay.data") socket.receive(frame.seq, frame.dataB64);
      else socket.remoteClosed("relay tunnel closed");
      return;
    }
    if (epoch.pendingOpens === 0) return;
    let early = epoch.early.get(tunnelId);
    if (early === void 0) {
      if (epoch.early.size >= MAX_TUNNELS) throw new Error("too many early mesh tunnels");
      early = { chunks: [], next: 1 };
      epoch.early.set(tunnelId, early);
    }
    if (kind === "relay.closed") {
      early.closed = "relay tunnel closed";
      return;
    }
    if (early.closed !== void 0 || !Number.isSafeInteger(frame.seq) || frame.seq !== early.next) throw new Error("invalid early mesh sequence");
    const bytes = decodeRelayData(frame.dataB64);
    if (epoch.earlyBytes + bytes.length > RELAY_RECEIVE_BYTES || epoch.earlyFrames >= MAX_EARLY_FRAMES) throw new Error("early mesh receive buffer exceeded");
    early.next += 1;
    early.chunks.push({ seq: frame.seq, bytes });
    epoch.earlyBytes += bytes.length;
    epoch.earlyFrames += 1;
  }
  closeOffered(epoch, tunnelId) {
    void this.rpc(epoch, "relay.close", { tunnelId }).catch(() => {
    });
  }
  async accept(epoch, relay) {
    await epoch.registration;
    this.assertEpoch(epoch);
    if (relay.destroyed) return;
    const local = this.dependencies.connectLocal?.(epoch.config.targetPort ?? 11325) ?? connect({ host: "127.0.0.1", port: epoch.config.targetPort ?? 11325 });
    epoch.locals.add(local);
    relay.once("close", () => {
      local.destroy();
    });
    local.on("error", () => {
      relay.destroy(new Error("mesh local target failed"));
    });
    local.once("close", () => {
      epoch.locals.delete(local);
      relay.destroy();
    });
    try {
      await this.waitLocal(epoch, local);
      this.assertEpoch(epoch);
      if (relay.destroyed) throw new Error("mesh offer closed");
      local.setNoDelay(true);
      local.setTimeout(0);
      relay.pipe(local);
      await this.rpc(epoch, "relay.accept", { tunnelId: relay.tunnelId });
      this.assertEpoch(epoch);
      if (relay.destroyed || local.destroyed) throw new Error("mesh offer closed");
      local.pipe(relay);
    } catch (error) {
      local.destroy();
      throw error;
    }
  }
  async waitLocal(epoch, socket) {
    await new Promise((resolve2, reject) => {
      let settled = false;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.off("connect", connected);
        socket.off("error", failed);
        socket.off("close", closed);
        epoch.abort.signal.removeEventListener("abort", closed);
        if (error === void 0) resolve2();
        else reject(error);
      };
      const connected = () => finish();
      const failed = () => finish(new Error("mesh local target connect failed"));
      const closed = () => finish(new Error("mesh local target closed"));
      const timer = setTimeout(() => {
        finish(new Error("mesh local target connect timed out"));
        socket.destroy();
      }, Math.min(epoch.config.timeoutMs ?? 15e3, 1e4));
      timer.unref?.();
      socket.once("connect", connected);
      socket.once("error", failed);
      socket.once("close", closed);
      epoch.abort.signal.addEventListener("abort", closed, { once: true });
      if (socket.destroyed || epoch.abort.signal.aborted) closed();
      else if (!socket.connecting) connected();
    });
  }
  retire(epoch, error, reconnect = true) {
    if (epoch.retired) return;
    epoch.retired = true;
    if (this.epoch === epoch) this.epoch = void 0;
    epoch.abort.abort();
    epoch.registered = false;
    epoch.early.clear();
    epoch.earlyBytes = 0;
    epoch.earlyFrames = 0;
    for (const socket of epoch.tunnels.values()) socket.remoteClosed("mesh hub disconnected");
    epoch.tunnels.clear();
    for (const socket of epoch.locals) socket.destroy();
    epoch.locals.clear();
    epoch.incoming.clear();
    epoch.link.dispose();
    this.lastError = error.message.slice(0, 240);
    if (reconnect) this.scheduleReconnect();
  }
  scheduleReconnect() {
    if (this.disposed || this.invalidConfig || this.current.autoReconnect === false || !configured(this.current) || this.reconnectTimer !== void 0) return;
    const min = this.current.reconnectMinMs ?? 1e3, max = this.current.reconnectMaxMs ?? 3e4;
    const ceiling = Math.min(max, min * 2 ** Math.min(this.failures++, 10));
    const random = this.dependencies.random?.() ?? Math.random();
    const jitter = Number.isFinite(random) ? Math.max(0, Math.min(1, random)) : 0.5;
    const delay = Math.max(min, Math.min(max, Math.floor(ceiling * (0.75 + jitter * 0.25))));
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = void 0;
      this.start();
    }, delay);
    this.reconnectTimer.unref?.();
  }
  clearReconnect() {
    if (this.reconnectTimer !== void 0) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = void 0;
  }
  /** No keys, pins, private config, or raw RPC payloads are exposed. */
  status() {
    this.refresh();
    const epoch = this.epoch;
    return {
      configured: !this.invalidConfig && configured(this.current),
      connected: epoch?.link.connected === true,
      registered: epoch?.registered === true,
      nodeId: epoch?.nodeId ?? null,
      tunnels: epoch?.tunnels.size ?? 0,
      pendingOpens: epoch?.pendingOpens ?? 0,
      inbound: epoch?.incoming.size ?? 0,
      reconnectScheduled: this.reconnectTimer !== void 0,
      disposed: this.disposed,
      ...this.lastError === void 0 ? {} : { error: this.lastError }
    };
  }
  /** Permanent: every timer, local dial, parked open and virtual stream is released. */
  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    this.clearReconnect();
    if (this.epoch !== void 0) this.retire(this.epoch, new Error("mesh disposed"), false);
  }
};
var MeshService = class extends Service {
  static Config = Config;
  node;
  constructor(ctx, config = {}) {
    super(ctx, "dshRemoteMesh");
    const read = () => isVolatile(config) ? config.get() : config;
    this.node = new MeshNode(read, (message) => ctx.logger.info(message));
    ctx.on("loader/volatile-update", () => {
      this.node.refresh();
    });
    ctx.effect(() => () => {
      this.dispose();
    }, "dsh-remote-mesh: close hub and tunnels");
  }
  open(target) {
    return this.node.open(target);
  }
  status() {
    return this.node.status();
  }
  dispose() {
    this.node.dispose();
  }
};
var mesh_default = MeshService;
export {
  Config,
  MeshConfigSchema,
  MeshNode,
  MeshService,
  mesh_default as default,
  name
};
