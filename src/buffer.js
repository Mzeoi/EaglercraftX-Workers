const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/**
 * Read a Minecraft VarInt from a Uint8Array at offset.
 * Returns { value, bytesRead } or null if buffer doesn't have enough bytes yet.
 */
export function readVarInt(buf, offset = 0, maxBytes = 5) {
  let numRead = 0;
  let result = 0;
  while (true) {
    if (offset + numRead >= buf.length) {
      return null; // need more bytes
    }
    const read = buf[offset + numRead];
    const value = read & 0x7f;
    result |= value << (7 * numRead);
    numRead++;
    if (numRead > maxBytes) {
      throw new Error('VarInt is too big');
    }
    if ((read & 0x80) === 0) {
      break;
    }
  }
  return { value: result, bytesRead: numRead };
}

/**
 * Encode an integer as a Minecraft VarInt Uint8Array.
 */
export function writeVarInt(value) {
  let v = value >>> 0;
  const out = [];
  do {
    let temp = v & 0x7f;
    v >>>= 7;
    if (v !== 0) {
      temp |= 0x80;
    }
    out.push(temp);
  } while (v !== 0);
  return new Uint8Array(out);
}

/**
 * Encode a Minecraft UTF-8 string (VarInt byte length + UTF-8 bytes).
 */
export function writeMCString(str) {
  const bytes = textEncoder.encode(str);
  const len = writeVarInt(bytes.length);
  return concatBytes(len, bytes);
}

/**
 * Read a Minecraft UTF-8 string (VarInt byte length + UTF-8 bytes).
 */
export function readMCString(buf, offset = 0, maxChars = 32767) {
  const lenInfo = readVarInt(buf, offset);
  if (!lenInfo) {
    throw new Error('Unexpected EOF reading MCString length');
  }
  const strLen = lenInfo.value;
  if (strLen < 0 || strLen > maxChars * 4) {
    throw new Error(`MCString length out of bounds: ${strLen}`);
  }
  const start = offset + lenInfo.bytesRead;
  const end = start + strLen;
  if (end > buf.length) {
    throw new Error('Unexpected EOF reading MCString body');
  }
  return {
    value: textDecoder.decode(buf.subarray(start, end)),
    bytesRead: lenInfo.bytesRead + strLen,
  };
}

export function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/**
 * Dynamic byte buffer builder for constructing binary packets.
 */
export class ByteWriter {
  constructor(initialCapacity = 128) {
    this.buf = new Uint8Array(initialCapacity);
    this.pos = 0;
  }

  ensure(extra) {
    if (this.pos + extra <= this.buf.length) return;
    let newLen = this.buf.length * 2;
    while (newLen < this.pos + extra) newLen *= 2;
    const next = new Uint8Array(newLen);
    next.set(this.buf.subarray(0, this.pos));
    this.buf = next;
  }

  writeByte(v) {
    this.ensure(1);
    this.buf[this.pos++] = v & 0xff;
  }

  writeBool(v) {
    this.writeByte(v ? 1 : 0);
  }

  writeShortBE(v) {
    this.ensure(2);
    this.buf[this.pos++] = (v >>> 8) & 0xff;
    this.buf[this.pos++] = v & 0xff;
  }

  writeIntBE(v) {
    this.ensure(4);
    this.buf[this.pos++] = (v >>> 24) & 0xff;
    this.buf[this.pos++] = (v >>> 16) & 0xff;
    this.buf[this.pos++] = (v >>> 8) & 0xff;
    this.buf[this.pos++] = v & 0xff;
  }

  writeBytes(arr) {
    this.ensure(arr.length);
    this.buf.set(arr, this.pos);
    this.pos += arr.length;
  }

  writeVarInt(v) {
    this.writeBytes(writeVarInt(v));
  }

  writeMCString(str) {
    this.writeBytes(writeMCString(str));
  }

  writeAsciiShortPrefixed(str, maxLen = 255) {
    const clipped = str.length > maxLen ? str.slice(0, maxLen) : str;
    const bytes = textEncoder.encode(clipped);
    this.writeByte(bytes.length & 0xff);
    this.writeBytes(bytes);
  }

  writeUtf8UShortPrefixed(str, maxLen = 65535) {
    let bytes = textEncoder.encode(str);
    if (bytes.length > maxLen) {
      bytes = bytes.subarray(0, maxLen);
    }
    this.writeShortBE(bytes.length);
    this.writeBytes(bytes);
  }

  toUint8Array() {
    return this.buf.slice(0, this.pos);
  }
}

/**
 * Cursor-based reader for parsing binary packets.
 */
export class ByteReader {
  constructor(buf) {
    this.buf = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    this.pos = 0;
  }

  get remaining() {
    return this.buf.length - this.pos;
  }

  require(n) {
    if (this.pos + n > this.buf.length) {
      throw new Error('IndexOutOfBoundsException');
    }
  }

  readUByte() {
    this.require(1);
    return this.buf[this.pos++];
  }

  readBool() {
    return this.readUByte() !== 0;
  }

  readUShortBE() {
    this.require(2);
    const v = (this.buf[this.pos] << 8) | this.buf[this.pos + 1];
    this.pos += 2;
    return v >>> 0;
  }

  readBytes(len) {
    this.require(len);
    const slice = this.buf.subarray(this.pos, this.pos + len);
    this.pos += len;
    return slice;
  }

  skip(len) {
    this.require(len);
    this.pos += len;
  }

  readAscii(len) {
    return textDecoder.decode(this.readBytes(len));
  }

  readVarInt(maxBytes = 5) {
    const res = readVarInt(this.buf, this.pos, maxBytes);
    if (!res) throw new Error('IndexOutOfBoundsException');
    this.pos += res.bytesRead;
    return res.value;
  }

  readMCString(maxChars = 32767) {
    const res = readMCString(this.buf, this.pos, maxChars);
    this.pos += res.bytesRead;
    return res.value;
  }
}

/**
 * Compute Java's UUID.nameUUIDFromBytes("OfflinePlayer:" + username) (UUID v3 / MD5).
 * Returns a 16-byte Uint8Array.
 */
export async function offlinePlayerUUIDBytes(username) {
  const input = textEncoder.encode('OfflinePlayer:' + username);
  let hash;
  try {
    const digest = await crypto.subtle.digest('MD5', input);
    hash = new Uint8Array(digest);
  } catch {
    hash = md5(input);
  }
  hash[6] = (hash[6] & 0x0f) | 0x30; // version 3
  hash[8] = (hash[8] & 0x3f) | 0x80; // IETF variant
  return hash;
}

/**
 * Zlib (RFC 1950) compression & decompression via Web Streams API.
 */
export async function zlibCompress(data) {
  const cs = new CompressionStream('deflate');
  const writer = cs.writable.getWriter();
  writer.write(data);
  writer.close();
  return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}

export async function zlibDecompress(data) {
  const ds = new DecompressionStream('deflate');
  const writer = ds.writable.getWriter();
  writer.write(data);
  writer.close();
  return new Uint8Array(await new Response(ds.readable).arrayBuffer());
}

/**
 * Minimal pure-JS MD5 fallback in case WebCrypto MD5 is unavailable in a test environment.
 */
function md5(bytes) {
  const r = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const k = new Uint32Array(64);
  for (let i = 0; i < 64; i++) {
    k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
  }
  const bitLen = bytes.length * 8;
  const padLen = ((bytes.length + 8) >> 6) * 64 + 64;
  const msg = new Uint8Array(padLen);
  msg.set(bytes);
  msg[bytes.length] = 0x80;
  const view = new DataView(msg.buffer);
  view.setUint32(padLen - 8, bitLen >>> 0, true);
  view.setUint32(padLen - 4, Math.floor(bitLen / 0x100000000), true);

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;

  for (let i = 0; i < padLen; i += 64) {
    const w = new Uint32Array(16);
    for (let j = 0; j < 16; j++) w[j] = view.getUint32(i + j * 4, true);
    let a = h0, b = h1, c = h2, d = h3;
    for (let j = 0; j < 64; j++) {
      let f, g;
      if (j < 16) {
        f = (b & c) | (~b & d);
        g = j;
      } else if (j < 32) {
        f = (d & b) | (~d & c);
        g = (5 * j + 1) % 16;
      } else if (j < 48) {
        f = b ^ c ^ d;
        g = (3 * j + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * j) % 16;
      }
      const temp = d;
      d = c;
      c = b;
      const sum = (a + f + k[j] + w[g]) >>> 0;
      b = (b + ((sum << r[j]) | (sum >>> (32 - r[j])))) >>> 0;
      a = temp;
    }
    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
  }
  const out = new Uint8Array(16);
  const ov = new DataView(out.buffer);
  ov.setUint32(0, h0, true);
  ov.setUint32(4, h1, true);
  ov.setUint32(8, h2, true);
  ov.setUint32(12, h3, true);
  return out;
}
