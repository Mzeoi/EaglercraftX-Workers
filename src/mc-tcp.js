import { connect } from 'cloudflare:sockets';
import {
  concatBytes,
  readVarInt,
  writeVarInt,
  zlibCompress,
  zlibDecompress,
} from './buffer.js';
import { Aes128Cfb8 } from './crypto.js';

/**
 * Minecraft TCP connection wrapper handling VarInt length-prefixed framing
 * and optional Zlib compression (SetCompression 0x03).
 */
export class MinecraftTcpConnection {
  constructor(hostname, port, logger = null) {
    this.hostname = hostname;
    this.port = port;
    this.log = logger || (() => {});
    this.log(`[TCP] Connecting to ${hostname}:${port}...`);
    this.socket = connect({ hostname, port });
    this.reader = this.socket.readable.getReader();
    this.writer = this.socket.writable.getWriter();
    this.compressionThreshold = -1;
    this.txCipher = null;
    this.rxCipher = null;
    this.closed = false;
    this._recvBuf = new Uint8Array(65536);
    this._recvStart = 0;
    this._recvEnd = 0;
    this._writeQueue = Promise.resolve();
  }

  /**
   * Set compression threshold (from S03PacketSetCompression).
   * -1 disables compression; >= 0 enables zlib for packets >= threshold.
   */
  setCompressionThreshold(threshold) {
    this.log(`[TCP] SetCompression threshold=${threshold}`);
    this.compressionThreshold = threshold;
  }

  /**
   * Enable AES-128/CFB8 stream encryption on both TX and RX.
   */
  enableEncryption(sharedSecret) {
    this.log('[TCP] Enabling AES-128/CFB8 encryption');
    this.txCipher = new Aes128Cfb8(sharedSecret);
    this.rxCipher = new Aes128Cfb8(sharedSecret);
    if (this._recvEnd > this._recvStart) {
      const dec = this.rxCipher.decrypt(this._recvBuf.subarray(this._recvStart, this._recvEnd));
      this._recvBuf.set(dec, this._recvStart);
    }
  }

  /**
   * Send a single uncompressed Minecraft packet (VarInt packetId + payload).
   * Serialized via promise queue to preserve strict packet ordering.
   */
  sendPacket(packetBytes) {
    if (this.closed) return Promise.resolve();
    const task = this._writeQueue.then(async () => {
      if (this.closed) return;
      let frame;
      if (this.compressionThreshold >= 0) {
        if (packetBytes.length >= this.compressionThreshold) {
          const compressed = await zlibCompress(packetBytes);
          const dataLen = writeVarInt(packetBytes.length);
          const totalLen = writeVarInt(dataLen.length + compressed.length);
          frame = concatBytes(totalLen, dataLen, compressed);
        } else {
          const dataLen = new Uint8Array([0x00]);
          const totalLen = writeVarInt(1 + packetBytes.length);
          frame = concatBytes(totalLen, dataLen, packetBytes);
        }
      } else {
        const lenPrefix = writeVarInt(packetBytes.length);
        frame = concatBytes(lenPrefix, packetBytes);
      }
      const outFrame = this.txCipher ? this.txCipher.encrypt(frame) : frame;
      await this.writer.write(outFrame);
    });
    this._writeQueue = task.catch((err) => {
      this.log(`[TCP] Write error: ${err?.message || err}`);
    });
    return task;
  }

  /**
   * Read the next complete uncompressed Minecraft packet from the TCP stream.
   * Returns Uint8Array or null on EOF.
   */
  async readPacket() {
    while (true) {
      const frame = this._tryExtractFrame();
      if (frame !== null) {
        if (this.compressionThreshold >= 0) {
          const dataLenInfo = readVarInt(frame, 0);
          if (!dataLenInfo) {
            throw new Error('Malformed compressed packet: missing DataLength');
          }
          const dataLength = dataLenInfo.value;
          const payload = frame.subarray(dataLenInfo.bytesRead);
          if (dataLength === 0) {
            return payload;
          }
          return await zlibDecompress(payload);
        }
        return frame;
      }

      const { value, done } = await this.reader.read();
      if (done || !value) {
        this.log('[TCP] EOF from backend');
        return null;
      }
      const chunk = this.rxCipher ? this.rxCipher.decrypt(value) : value;
      this._appendChunk(chunk);
    }
  }

  _appendChunk(chunk) {
    const avail = this._recvEnd - this._recvStart;
    if (avail === 0) {
      this._recvStart = 0;
      this._recvEnd = 0;
    }
    if (this._recvEnd + chunk.length > this._recvBuf.length) {
      if (avail + chunk.length <= this._recvBuf.length) {
        this._recvBuf.copyWithin(0, this._recvStart, this._recvEnd);
        this._recvStart = 0;
        this._recvEnd = avail;
      } else {
        let newCap = this._recvBuf.length * 2;
        while (newCap < avail + chunk.length) newCap *= 2;
        const next = new Uint8Array(newCap);
        if (avail > 0) next.set(this._recvBuf.subarray(this._recvStart, this._recvEnd), 0);
        this._recvBuf = next;
        this._recvStart = 0;
        this._recvEnd = avail;
      }
    }
    this._recvBuf.set(chunk, this._recvEnd);
    this._recvEnd += chunk.length;
  }

  _tryExtractFrame() {
    const avail = this._recvEnd - this._recvStart;
    if (avail === 0) return null;
    const lenInfo = readVarInt(this._recvBuf, this._recvStart);
    if (!lenInfo) return null;
    const packetLen = lenInfo.value;
    if (packetLen < 0 || packetLen > 8 * 1024 * 1024) {
      throw new Error(`Minecraft packet length out of bounds: ${packetLen}`);
    }
    const totalNeeded = lenInfo.bytesRead + packetLen;
    if (avail < totalNeeded) {
      return null;
    }
    const frame = this._recvBuf.slice(this._recvStart + lenInfo.bytesRead, this._recvStart + totalNeeded);
    this._recvStart += totalNeeded;
    if (this._recvStart === this._recvEnd) {
      this._recvStart = 0;
      this._recvEnd = 0;
    }
    return frame;
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    this.log('[TCP] Closing socket');
    try {
      await this.reader.cancel();
    } catch {}
    try {
      await this.writer.close();
    } catch {}
    try {
      await this.socket.close();
    } catch {}
  }
}
