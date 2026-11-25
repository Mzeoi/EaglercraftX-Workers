// Pure-JS RSA PKCS#1 v1.5 encryption and AES-128/CFB8 stream cipher
// for Minecraft 1.20.5+ offline-mode encryption (shouldAuthenticate = false).

const SBOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// Precompute 32-bit AES T-tables for fast zero-allocation block encryption.
const TE0 = new Uint32Array(256);
const TE1 = new Uint32Array(256);
const TE2 = new Uint32Array(256);
const TE3 = new Uint32Array(256);

for (let i = 0; i < 256; i++) {
  const s = SBOX[i];
  const s2 = ((s << 1) ^ (s & 0x80 ? 0x1b : 0)) & 0xff;
  const s3 = s2 ^ s;
  const t0 = ((s2 << 24) | (s << 16) | (s << 8) | s3) >>> 0;
  TE0[i] = t0;
  TE1[i] = ((t0 >>> 8) | (t0 << 24)) >>> 0;
  TE2[i] = ((t0 >>> 16) | (t0 << 16)) >>> 0;
  TE3[i] = ((t0 >>> 24) | (t0 << 8)) >>> 0;
}

function expandAes128KeyWords(key) {
  if (key.length !== 16) throw new Error(`AES-128 key must be 16 bytes, got ${key.length}`);
  const rk = new Uint32Array(44);
  for (let i = 0; i < 4; i++) {
    const j = i * 4;
    rk[i] = ((key[j] << 24) | (key[j + 1] << 16) | (key[j + 2] << 8) | key[j + 3]) >>> 0;
  }
  for (let i = 4; i < 44; i++) {
    let temp = rk[i - 1];
    if (i % 4 === 0) {
      temp =
        ((SBOX[(temp >>> 16) & 0xff] << 24) |
          (SBOX[(temp >>> 8) & 0xff] << 16) |
          (SBOX[temp & 0xff] << 8) |
          SBOX[(temp >>> 24) & 0xff]) >>>
        0;
      temp ^= RCON[i / 4 - 1] << 24;
    }
    rk[i] = (rk[i - 4] ^ temp) >>> 0;
  }
  return rk;
}

/**
 * Stateful AES-128/CFB8 stream cipher (zero-allocation T-table implementation).
 */
export class Aes128Cfb8 {
  constructor(keyBytes) {
    this.rk = expandAes128KeyWords(keyBytes);
    this.iv0 = ((keyBytes[0] << 24) | (keyBytes[1] << 16) | (keyBytes[2] << 8) | keyBytes[3]) >>> 0;
    this.iv1 = ((keyBytes[4] << 24) | (keyBytes[5] << 16) | (keyBytes[6] << 8) | keyBytes[7]) >>> 0;
    this.iv2 = ((keyBytes[8] << 24) | (keyBytes[9] << 16) | (keyBytes[10] << 8) | keyBytes[11]) >>> 0;
    this.iv3 = ((keyBytes[12] << 24) | (keyBytes[13] << 16) | (keyBytes[14] << 8) | keyBytes[15]) >>> 0;
  }

  _nextKeystreamByte() {
    const rk = this.rk;
    let s0 = (this.iv0 ^ rk[0]) >>> 0;
    let s1 = (this.iv1 ^ rk[1]) >>> 0;
    let s2 = (this.iv2 ^ rk[2]) >>> 0;
    let s3 = (this.iv3 ^ rk[3]) >>> 0;

    let t0, t1, t2, t3;
    for (let r = 1; r <= 9; r++) {
      const k = r * 4;
      t0 = (TE0[s0 >>> 24] ^ TE1[(s1 >>> 16) & 0xff] ^ TE2[(s2 >>> 8) & 0xff] ^ TE3[s3 & 0xff] ^ rk[k]) >>> 0;
      t1 = (TE0[s1 >>> 24] ^ TE1[(s2 >>> 16) & 0xff] ^ TE2[(s3 >>> 8) & 0xff] ^ TE3[s0 & 0xff] ^ rk[k + 1]) >>> 0;
      t2 = (TE0[s2 >>> 24] ^ TE1[(s3 >>> 16) & 0xff] ^ TE2[(s0 >>> 8) & 0xff] ^ TE3[s1 & 0xff] ^ rk[k + 2]) >>> 0;
      t3 = (TE0[s3 >>> 24] ^ TE1[(s0 >>> 16) & 0xff] ^ TE2[(s1 >>> 8) & 0xff] ^ TE3[s2 & 0xff] ^ rk[k + 3]) >>> 0;
      s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    // Round 10 only needs the first byte (MSB of final state word 0)
    return SBOX[s0 >>> 24] ^ (rk[40] >>> 24);
  }

  encrypt(data) {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      const c = data[i] ^ this._nextKeystreamByte();
      out[i] = c;
      this.iv0 = ((this.iv0 << 8) | (this.iv1 >>> 24)) >>> 0;
      this.iv1 = ((this.iv1 << 8) | (this.iv2 >>> 24)) >>> 0;
      this.iv2 = ((this.iv2 << 8) | (this.iv3 >>> 24)) >>> 0;
      this.iv3 = ((this.iv3 << 8) | c) >>> 0;
    }
    return out;
  }

  decrypt(data) {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      const c = data[i];
      out[i] = c ^ this._nextKeystreamByte();
      this.iv0 = ((this.iv0 << 8) | (this.iv1 >>> 24)) >>> 0;
      this.iv1 = ((this.iv1 << 8) | (this.iv2 >>> 24)) >>> 0;
      this.iv2 = ((this.iv2 << 8) | (this.iv3 >>> 24)) >>> 0;
      this.iv3 = ((this.iv3 << 8) | c) >>> 0;
    }
    return out;
  }
}

// --- ASN.1 DER & RSA PKCS#1 v1.5 ---

function readAsn1Length(buf, offset) {
  const first = buf[offset];
  if ((first & 0x80) === 0) {
    return { length: first, nextOffset: offset + 1 };
  }
  const numBytes = first & 0x7f;
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | buf[offset + 1 + i];
  }
  return { length, nextOffset: offset + 1 + numBytes };
}

function readAsn1Tlv(buf, offset) {
  const tag = buf[offset];
  const { length, nextOffset } = readAsn1Length(buf, offset + 1);
  return {
    tag,
    value: buf.subarray(nextOffset, nextOffset + length),
    endOffset: nextOffset + length,
  };
}

function bytesToBigInt(bytes) {
  let res = 0n;
  for (let i = 0; i < bytes.length; i++) {
    res = (res << 8n) | BigInt(bytes[i]);
  }
  return res;
}

function bigIntToFixedBytes(n, len) {
  const out = new Uint8Array(len);
  let v = n;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function modPow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

/**
 * Parse X.509 SubjectPublicKeyInfo DER RSA public key.
 */
export function parseRsaSubjectPublicKeyInfo(derBytes) {
  const root = readAsn1Tlv(derBytes, 0);
  if (root.tag !== 0x30) throw new Error('Expected outer SEQUENCE in SPKI');
  const algId = readAsn1Tlv(root.value, 0);
  const bitString = readAsn1Tlv(root.value, algId.endOffset);
  if (bitString.tag !== 0x03) throw new Error('Expected BIT STRING in SPKI');
  // Skip unused-bits byte (0x00)
  const rsaSeq = readAsn1Tlv(bitString.value, 1);
  if (rsaSeq.tag !== 0x30) throw new Error('Expected RSA public key SEQUENCE');
  const modTlv = readAsn1Tlv(rsaSeq.value, 0);
  const expTlv = readAsn1Tlv(rsaSeq.value, modTlv.endOffset);
  if (modTlv.tag !== 0x02 || expTlv.tag !== 0x02) {
    throw new Error('Expected INTEGERs for RSA modulus/exponent');
  }

  // Strip leading 0x00 sign byte on positive DER INTEGER if present
  let nBytes = modTlv.value;
  if (nBytes.length > 1 && nBytes[0] === 0x00) {
    nBytes = nBytes.subarray(1);
  }
  return {
    keySizeBytes: nBytes.length,
    n: bytesToBigInt(nBytes),
    e: bytesToBigInt(expTlv.value),
  };
}

/**
 * Encrypt plaintext using RSAES-PKCS1-v1_5 with an X.509 SPKI public key.
 */
export function rsaPkcs1v15Encrypt(spkiDerBytes, plaintext) {
  const { keySizeBytes, n, e } = parseRsaSubjectPublicKeyInfo(spkiDerBytes);
  const psLen = keySizeBytes - 3 - plaintext.length;
  if (psLen < 8) {
    throw new Error('Plaintext too long for RSA key');
  }
  const em = new Uint8Array(keySizeBytes);
  em[0] = 0x00;
  em[1] = 0x02;
  // Non-zero random padding bytes
  let filled = 0;
  while (filled < psLen) {
    const rnd = new Uint8Array(psLen - filled);
    crypto.getRandomValues(rnd);
    for (let i = 0; i < rnd.length && filled < psLen; i++) {
      if (rnd[i] !== 0) {
        em[2 + filled++] = rnd[i];
      }
    }
  }
  em[2 + psLen] = 0x00;
  em.set(plaintext, 3 + psLen);

  const m = bytesToBigInt(em);
  const c = modPow(m, e, n);
  return bigIntToFixedBytes(c, keySizeBytes);
}
