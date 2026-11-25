import {
  ByteReader,
  ByteWriter,
  offlinePlayerUUIDBytes,
} from './buffer.js';
import { MinecraftTcpConnection } from './mc-tcp.js';
import { queryMinecraftMotd } from './motd.js';
import { rsaPkcs1v15Encrypt } from './crypto.js';

const USERNAME_REGEX = /^[A-Za-z0-9_]{3,16}$/;

const PKT = {
  CLIENT_VERSION: 0x01,
  SERVER_VERSION: 0x02,
  VERSION_MISMATCH: 0x03,
  CLIENT_REQUEST_LOGIN: 0x04,
  SERVER_ALLOW_LOGIN: 0x05,
  SERVER_DENY_LOGIN: 0x06,
  CLIENT_PROFILE_DATA: 0x07,
  CLIENT_FINISH_LOGIN: 0x08,
  SERVER_FINISH_LOGIN: 0x09,
  SERVER_ERROR: 0xff,
};

const ERR = {
  UNKNOWN_PACKET: 0x01,
  INVALID_PACKET: 0x02,
  WRONG_PACKET: 0x03,
  CUSTOM_MESSAGE: 0x08,
};

const MAX_STALLED_PACKETS = 512;
const MAX_STALLED_BYTES = 256 * 1024;

function toHex(bytes, max = 96) {
  const slice = bytes.length > max ? bytes.subarray(0, max) : bytes;
  const hex = Array.from(slice, (b) => b.toString(16).padStart(2, '0')).join(' ');
  return bytes.length > max ? `${hex} ... (${bytes.length} bytes total)` : hex;
}

function bytesToUuidHex(bytes) {
  const h = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function playDisconnectId(mcProto) {
  if (mcProto <= 47) return 0x40;
  if (mcProto < 393) return 0x1a;
  if (mcProto <= 404) return 0x1b;
  if (mcProto <= 758) return 0x1a;
  if (mcProto <= 759) return 0x1d;
  if (mcProto <= 761) return 0x17;
  if (mcProto <= 765) return 0x1a;
  return 0x1d;
}

function pluginMessagePlayId(mcProto) {
  if (mcProto <= 47) return 0x3f;
  if (mcProto < 393) return 0x18;
  if (mcProto <= 404) return 0x19;
  if (mcProto <= 759) return 0x18;
  if (mcProto <= 761) return 0x15;
  if (mcProto <= 765) return 0x0a;
  return 0x18;
}

function configDisconnectId(mcProto) {
  if (mcProto >= 764 && mcProto <= 765) return 0x01;
  return 0x02;
}

function parseUuidStringToBytes(uuidStr) {
  const hex = uuidStr.replace(/-/g, '');
  if (hex.length !== 32) throw new Error(`Invalid UUID: ${uuidStr}`);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Handles a single Eaglercraft WebSocket session and translates it
 * into a Vanilla/Paper Minecraft TCP connection.
 */
export class EaglerBridgeSession {
  constructor(ws, config, sessionId = Math.random().toString(36).slice(2, 8)) {
    this.ws = ws;
    this.config = config;
    this.sessionId = sessionId;
    this.tcp = null;
    this.terminated = false;
    this.canSendV3Kick = false;

    this.eaglerProto = 0;
    this.mcProto = 47;
    this.username = '';
    this.authUsername = '';
    this.uuidBytes = new Uint8Array(16);

    // State machine: INIT -> VERSION_SENT -> BACKEND_LOGIN -> STALLING -> PLAY
    this.state = 'INIT';
    this.bufferedPackets = [];
    this.bufferedBytes = 0;
    this.playRxCount = 0;
    this.playTxCount = 0;
    this._wsQueue = Promise.resolve();

    this.log(`Session created -> target=${config.target.hostname}:${config.target.port} minMC=${config.minMcProtocol} maxMC=${config.maxMcProtocol}`);
  }

  log(msg) {
    if (this.config.verbose) {
      console.log(`[Eagler:${this.sessionId}] ${msg}`);
    }
  }

  sendWs(bytesOrText) {
    if (this.terminated) return;
    try {
      this.ws.send(bytesOrText);
    } catch (err) {
      this.log(`[WS<-] Send failed: ${err?.message || err}`);
    }
  }

  sendErrorAndClose(errorCode, message) {
    if (this.terminated) return;
    this.terminated = true;
    const msg = String(message || 'Disconnected');
    this.log(`[WS<-ERROR] code=0x${errorCode.toString(16)} eaglerProto=${this.eaglerProto} v3Kick=${this.canSendV3Kick} msg=${JSON.stringify(msg)}`);
    const w = new ByteWriter();
    w.writeByte(PKT.SERVER_ERROR);
    w.writeByte(errorCode);
    if (this.eaglerProto >= 3 && this.canSendV3Kick) {
      w.writeUtf8UShortPrefixed(msg, 65535);
    } else {
      const clipped = msg.length > 255 ? msg.slice(0, 255) : msg;
      const bytes = new TextEncoder().encode(clipped);
      const len = Math.min(bytes.length, 255);
      w.writeByte(len);
      w.writeBytes(bytes.subarray(0, len));
    }
    const out = w.toUint8Array();
    this.log(`[WS<-ERROR] raw hex=${toHex(out)}`);
    try {
      this.ws.send(out);
    } catch {}
    this.close('error_sent');
  }

  close(reason = 'normal') {
    if (this.terminated && !this.tcp) return;
    this.log(`Session closing (reason=${reason}, state=${this.state}, playRx=${this.playRxCount}, playTx=${this.playTxCount})`);
    this.terminated = true;
    this.bufferedPackets = [];
    this.bufferedBytes = 0;
    if (this.tcp) {
      const tcp = this.tcp;
      this.tcp = null;
      tcp.close();
    }
    try {
      this.ws.close();
    } catch {}
  }

  /**
   * Queue incoming WebSocket messages sequentially to avoid race conditions
   * during async handshake / UUID / TCP setup.
   */
  enqueueMessage(data) {
    this._wsQueue = this._wsQueue
      .then(() => this._handleMessage(data))
      .catch((err) => {
        this.log(`[WS->ERR] Unhandled exception in _handleMessage: ${err?.stack || err}`);
        if (!this.terminated) {
          this.sendErrorAndClose(ERR.CUSTOM_MESSAGE, `Proxy error: ${err.message}`);
        }
      });
  }

  async _handleMessage(data) {
    if (this.terminated) return;

    // Text frame: MOTD / Query
    if (typeof data === 'string') {
      this.log(`[WS->TEXT] state=${this.state} text=${JSON.stringify(data)}`);
      if (this.state !== 'INIT') {
        this.close('unexpected_text_frame');
        return;
      }
      const trimmed = data.trim();
      if (trimmed.length < 128 && trimmed.toLowerCase().startsWith('accept:')) {
        const acceptType = trimmed.slice(7).trim();
        if (acceptType.toLowerCase() === 'motd' || acceptType.toLowerCase().startsWith('motd.')) {
          const motdJson = await queryMinecraftMotd(this.config, acceptType, (m) => this.log(m));
          this.sendWs(motdJson);
          this.close('motd_done');
          return;
        }
      }
      this.close('unsupported_query');
      return;
    }

    const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data);
    if (bytes.length === 0) return;

    // Play state: forward raw Minecraft packet directly to TCP (length-prefixed + optional zlib)
    if (this.state === 'PLAY') {
      this.playTxCount++;
      if (this.playTxCount <= 10 || this.playTxCount % 100 === 0) {
        const r = new ByteReader(bytes);
        let pktIdStr = '?';
        try { pktIdStr = '0x' + r.readVarInt().toString(16); } catch {}
        this.log(`[PLAY WS->TCP #${this.playTxCount}] pktId=${pktIdStr} len=${bytes.length}`);
      }
      await this.tcp.sendPacket(bytes);
      return;
    }

    this.log(`[WS->BIN] state=${this.state} len=${bytes.length} hex=${toHex(bytes)}`);
    const reader = new ByteReader(bytes);

    if (this.state === 'INIT') {
      if (bytes.length <= 2) {
        this.log('[INIT] Packet too short, closing');
        this.close('short_init');
        return;
      }
      const b1 = reader.readUByte();
      const b2 = reader.readUByte();
      this.log(`[INIT] b1=0x${b1.toString(16)} b2=0x${b2.toString(16)}`);
      if (b1 === 1 && b2 === 2) {
        this._handleEaglerV2PlusInit(reader);
      } else if (b1 === 1 && b2 === 1) {
        this._handleEaglerV1Init(reader);
      } else {
        this.log(`[INIT] Unsupported protocol prefix b1=${b1} b2=${b2}`);
        this.close('unknown_init_prefix');
      }
      return;
    }

    if (this.state === 'VERSION_SENT') {
      const pktId = reader.readUByte();
      this.log(`[VERSION_SENT] pktId=0x${pktId.toString(16)}`);
      if (pktId === PKT.CLIENT_REQUEST_LOGIN) {
        await this._handleRequestLogin(reader, bytes);
      } else {
        this.sendErrorAndClose(ERR.WRONG_PACKET, 'Expected Request Login Packet');
      }
      return;
    }

    if (this.state === 'STALLING' || this.state === 'BACKEND_LOGIN') {
      const pktId = reader.readUByte();
      this.log(`[${this.state}] pktId=0x${pktId.toString(16)}`);
      if (pktId === PKT.CLIENT_PROFILE_DATA) {
        this._handleProfileData(reader);
      } else if (pktId === PKT.CLIENT_FINISH_LOGIN) {
        if (reader.remaining !== 0) {
          this.sendErrorAndClose(ERR.INVALID_PACKET, 'Invalid Finish Login Packet');
          return;
        }
        this._enterPlayState();
      } else {
        this.sendErrorAndClose(ERR.UNKNOWN_PACKET, `Unknown Packet #${pktId}`);
      }
    }
  }

  _handleEaglerV2PlusInit(reader) {
    let v2 = false, v3 = false, v4 = false, v5 = false;
    let maxAvailableMc = -1;
    const minAllowedMc = this.config.minMcProtocol;
    const maxAllowedMc = this.config.maxMcProtocol;

    try {
      const eaglerCount = reader.readUShortBE();
      if (eaglerCount === 0 || eaglerCount > 16) throw new Error('bad count');
      const eaglerVers = [];
      for (let i = 0; i < eaglerCount; i++) {
        const v = reader.readUShortBE();
        eaglerVers.push(v);
        if (v === 2) v2 = true;
        else if (v === 3) v3 = true;
        else if (v === 4) v4 = true;
        else if (v === 5) v5 = true;
      }

      const mcCount = reader.readUShortBE();
      if (mcCount === 0 || mcCount > 16) throw new Error('bad mc count');
      const mcVers = [];
      for (let i = 0; i < mcCount; i++) {
        const mc = reader.readUShortBE();
        mcVers.push(mc);
        if (mc >= minAllowedMc && mc <= maxAllowedMc && mc > maxAvailableMc) {
          maxAvailableMc = mc;
        }
      }

      let selectedEagler = -1;
      if (maxAvailableMc !== -1) {
        if (v5) selectedEagler = 5;
        else if (v4) selectedEagler = 4;
        else if (v3) selectedEagler = 3;
        else if (v2) selectedEagler = 2;
      }

      this.log(`[INIT V2+] clientEagler=${JSON.stringify(eaglerVers)} clientMC=${JSON.stringify(mcVers)} -> selectedEagler=${selectedEagler} selectedMC=${maxAvailableMc}`);

      if (selectedEagler === -1 || maxAvailableMc === -1) {
        const w = new ByteWriter();
        w.writeByte(PKT.VERSION_MISMATCH);
        w.writeShortBE(4);
        w.writeShortBE(2);
        w.writeShortBE(3);
        w.writeShortBE(4);
        w.writeShortBE(5);
        w.writeShortBE(2);
        w.writeShortBE(minAllowedMc);
        w.writeShortBE(maxAllowedMc);
        w.writeAsciiShortPrefixed('Unsupported Client Version');
        this.terminated = true;
        this.ws.send(w.toUint8Array());
        this.close('version_mismatch');
        return;
      }

      const brandLen = reader.readUByte();
      const brand = reader.readAscii(brandLen);
      const versLen = reader.readUByte();
      const version = reader.readAscii(versLen);
      const clientAuth = reader.readBool();
      const authUserLen = reader.readUByte();
      this.authUsername = authUserLen > 0 ? reader.readAscii(authUserLen) : '';
      this.log(`[INIT V2+] brand=${JSON.stringify(brand)} vers=${JSON.stringify(version)} clientAuth=${clientAuth} authUsername=${JSON.stringify(this.authUsername)} trailingBytes=${reader.remaining}`);

      this.eaglerProto = selectedEagler;
      this.mcProto = maxAvailableMc;
      this.canSendV3Kick = true;
      this.state = 'VERSION_SENT';

      const w = new ByteWriter();
      w.writeByte(PKT.SERVER_VERSION);
      w.writeShortBE(this.eaglerProto);
      w.writeShortBE(this.mcProto);
      w.writeAsciiShortPrefixed(this.config.serverBrand, 255);
      w.writeAsciiShortPrefixed(this.config.serverVersion, 255);
      w.writeByte(0); // authMethod = none
      w.writeShortBE(0); // saltingData len = 0
      if (this.eaglerProto >= 5) {
        w.writeBool(false); // nicknameSelection
      }
      const out = w.toUint8Array();
      this.log(`[WS<-SERVER_VERSION] len=${out.length} hex=${toHex(out)}`);
      this.sendWs(out);
    } catch (err) {
      this.log(`[INIT V2+] Parse error: ${err?.message || err}`);
      this.close('init_parse_error');
    }
  }

  _handleEaglerV1Init(reader) {
    try {
      const mcProto = reader.readUByte();
      const brandLen = reader.readUByte();
      const brand = reader.readAscii(brandLen);
      const versLen = reader.readUByte();
      const version = reader.readAscii(versLen);
      this.log(`[INIT V1] mcProto=${mcProto} brand=${JSON.stringify(brand)} vers=${JSON.stringify(version)}`);

      this.eaglerProto = 1;
      this.mcProto = mcProto;
      this.state = 'VERSION_SENT';

      const w = new ByteWriter();
      w.writeByte(PKT.SERVER_VERSION);
      w.writeByte(1);
      w.writeAsciiShortPrefixed(this.config.serverBrand, 255);
      w.writeAsciiShortPrefixed(this.config.serverVersion, 255);
      w.writeByte(0);
      w.writeShortBE(0);
      this.sendWs(w.toUint8Array());
    } catch (err) {
      this.log(`[INIT V1] Parse error: ${err?.message || err}`);
      this.close('init_v1_error');
    }
  }

  async _handleRequestLogin(reader, rawBytes) {
    let username;
    let requestedServer = '';
    try {
      const userLen = reader.readUByte();
      username = reader.readAscii(userLen);
      const reqSrvLen = reader.readUByte();
      requestedServer = reader.readAscii(reqSrvLen);
      const passLen = reader.readUByte();
      reader.skip(passLen);

      let enableCookie = false;
      let cookieLen = 0;
      if (this.eaglerProto >= 4) {
        enableCookie = reader.readBool();
        cookieLen = reader.readUByte();
        if (enableCookie) reader.skip(cookieLen);
      }

      let standardCaps = 0;
      let extCount = 0;
      if (this.eaglerProto >= 5) {
        standardCaps = reader.readVarInt();
        let capCount = 0;
        let tmp = standardCaps >>> 0;
        while (tmp) {
          capCount += tmp & 1;
          tmp >>>= 1;
        }
        for (let i = 0; i < capCount; i++) {
          reader.readVarInt();
        }
        extCount = reader.readUByte();
        for (let i = 0; i < extCount; i++) {
          reader.skip(16);
          reader.readVarInt();
        }
      }
      this.log(`[REQUEST_LOGIN] username=${JSON.stringify(username)} requestedServer=${JSON.stringify(requestedServer)} passLen=${passLen} cookie=${enableCookie}(${cookieLen}B) caps=0x${standardCaps.toString(16)} extCaps=${extCount} trailing=${reader.remaining}`);
    } catch (err) {
      this.log(`[REQUEST_LOGIN] Parse error: ${err?.message || err} rawHex=${toHex(rawBytes, 128)}`);
      this.sendErrorAndClose(ERR.INVALID_PACKET, 'Invalid Login Request');
      return;
    }

    if (!username && this.authUsername) {
      this.log(`[REQUEST_LOGIN] Empty username in 0x04, falling back to authUsername=${JSON.stringify(this.authUsername)}`);
      username = this.authUsername;
    }

    if (!USERNAME_REGEX.test(username)) {
      this.log(`[REQUEST_LOGIN] Rejected username=${JSON.stringify(username)} authUsername=${JSON.stringify(this.authUsername)}`);
      this.sendErrorAndClose(ERR.CUSTOM_MESSAGE, `Invalid Username: ${username || '(empty)'}`);
      return;
    }

    this.username = username;
    this.uuidBytes = await offlinePlayerUUIDBytes(username);
    this.state = 'BACKEND_LOGIN';
    this.log(`[BACKEND_LOGIN] Accepted username=${this.username} offlineUUID=${bytesToUuidHex(this.uuidBytes)}`);

    const { hostname, port } = this.config.target;
    this.tcp = new MinecraftTcpConnection(hostname, port, (m) => this.log(m));

    // Send Vanilla C00Handshake (nextState = 2: Login)
    const hs = new ByteWriter();
    hs.writeVarInt(0x00);
    hs.writeVarInt(this.mcProto);
    hs.writeMCString(hostname);
    hs.writeShortBE(port);
    hs.writeVarInt(2);
    await this.tcp.sendPacket(hs.toUint8Array());
    this.log(`[TCP<-C00Handshake] mcProto=${this.mcProto} host=${hostname}:${port} nextState=2`);

    // Send Vanilla C00PacketLoginStart
    const loginStart = new ByteWriter();
    loginStart.writeVarInt(0x00);
    loginStart.writeMCString(this.username);
    if (this.mcProto >= 759 && this.mcProto <= 760) {
      loginStart.writeBool(false); // hasPublicKey
    }
    if (this.mcProto >= 760) {
      loginStart.writeBytes(this.uuidBytes);
    }
    const loginBytes = loginStart.toUint8Array();
    await this.tcp.sendPacket(loginBytes);
    this.log(`[TCP<-LoginStart] username=${this.username} len=${loginBytes.length} hex=${toHex(loginBytes)}`);

    // Start background TCP read loop
    this._runTcpReadLoop();
  }

  _handleProfileData(reader) {
    try {
      if (this.eaglerProto >= 4) {
        const count = reader.readUByte();
        const types = [];
        for (let i = 0; i < count; i++) {
          const typeLen = reader.readUByte();
          const type = reader.readAscii(typeLen);
          const dataLen = reader.readUShortBE();
          reader.skip(dataLen);
          types.push(`${type}(${dataLen}B)`);
        }
        this.log(`[PROFILE_DATA] count=${count} items=${types.join(', ')}`);
      } else {
        const typeLen = reader.readUByte();
        const type = reader.readAscii(typeLen);
        const dataLen = reader.readUShortBE();
        reader.skip(dataLen);
        this.log(`[PROFILE_DATA] item=${type}(${dataLen}B)`);
      }
    } catch (err) {
      this.log(`[PROFILE_DATA] Parse error: ${err?.message || err}`);
      this.sendErrorAndClose(ERR.INVALID_PACKET, 'Invalid Profile Data');
    }
  }

  async _runTcpReadLoop() {
    try {
      while (!this.terminated) {
        const pkt = await this.tcp.readPacket();
        if (pkt === null) {
          this.close('tcp_eof');
          break;
        }
        if (this.terminated) break;

        if (this.state === 'PLAY') {
          this.playRxCount++;
          if (this.playRxCount <= 10 || this.playRxCount % 100 === 0) {
            const r = new ByteReader(pkt);
            let pktIdStr = '?';
            try { pktIdStr = '0x' + r.readVarInt().toString(16); } catch {}
            this.log(`[PLAY TCP->WS #${this.playRxCount}] pktId=${pktIdStr} len=${pkt.length}`);
          }
          this.sendWs(pkt);
          continue;
        }

        const reader = new ByteReader(pkt);
        const pktId = reader.readVarInt();
        this.log(`[TCP->${this.state}] pktId=0x${pktId.toString(16)} len=${pkt.length}`);

        if (this.state === 'BACKEND_LOGIN') {
          if (pktId === 0x00) {
            // S00PacketDisconnect
            const reason = reader.readMCString(32767);
            this.log(`[BACKEND_LOGIN] S00Disconnect reason=${reason}`);
            this.sendErrorAndClose(ERR.CUSTOM_MESSAGE, reason);
            break;
          } else if (pktId === 0x01) {
            // S01PacketEncryptionRequest
            let serverId = '';
            let pubKeyBytes = null;
            let verifyTokenBytes = null;
            let shouldAuthenticate = null;
            try {
              serverId = reader.readMCString(20);
              const pubKeyLen = reader.readVarInt();
              pubKeyBytes = reader.readBytes(pubKeyLen);
              const verifyTokenLen = reader.readVarInt();
              verifyTokenBytes = reader.readBytes(verifyTokenLen);
              if (this.mcProto >= 766 && reader.remaining >= 1) {
                shouldAuthenticate = reader.readBool();
              }
            } catch (e) {
              this.log(`[BACKEND_LOGIN] S01EncryptionRequest parse warning: ${e?.message || e}`);
            }
            this.log(
              `[BACKEND_LOGIN] S01EncryptionRequest serverId=${JSON.stringify(serverId)} pubKey=${pubKeyBytes ? pubKeyBytes.length : 0}B verifyToken=${verifyTokenBytes ? verifyTokenBytes.length : 0}B shouldAuthenticate=${shouldAuthenticate}`
            );

            if (
              this.config.compatMode &&
              shouldAuthenticate === false &&
              pubKeyBytes &&
              verifyTokenBytes
            ) {
              const sharedSecret = crypto.getRandomValues(new Uint8Array(16));
              const encSecret = rsaPkcs1v15Encrypt(pubKeyBytes, sharedSecret);
              const encToken = rsaPkcs1v15Encrypt(pubKeyBytes, verifyTokenBytes);

              const resp = new ByteWriter();
              resp.writeVarInt(0x01); // Serverbound EncryptionResponse
              resp.writeVarInt(encSecret.length);
              resp.writeBytes(encSecret);
              if (this.mcProto >= 759 && this.mcProto <= 760) {
                resp.writeBool(true); // hasVerifyToken
              }
              resp.writeVarInt(encToken.length);
              resp.writeBytes(encToken);

              await this.tcp.sendPacket(resp.toUint8Array());
              this.tcp.enableEncryption(sharedSecret);
              this.log('[BACKEND_LOGIN][COMPAT] Sent C01EncryptionResponse & enabled AES-128/CFB8 (shouldAuthenticate=false)');
            } else {
              this.sendErrorAndClose(ERR.CUSTOM_MESSAGE, 'Your client does not support online mode');
              break;
            }
          } else if (pktId === 0x03) {
            // S03PacketSetCompression
            const threshold = reader.readVarInt();
            this.tcp.setCompressionThreshold(threshold);
          } else if (pktId === 0x02) {
            // S02PacketLoginSuccess
            let acceptedUuidBytes;
            let acceptedUsername;
            if (this.mcProto >= 735) {
              acceptedUuidBytes = reader.readBytes(16);
              acceptedUsername = reader.readMCString(16);
            } else {
              const uuidStr = reader.readMCString(36);
              acceptedUuidBytes = parseUuidStringToBytes(uuidStr);
              acceptedUsername = reader.readMCString(16);
            }
            this.log(`[BACKEND_LOGIN] S02LoginSuccess username=${acceptedUsername} uuid=${bytesToUuidHex(acceptedUuidBytes)}`);

            // 1.20.2+ (764+): immediately send ServerboundLoginAcknowledged (0x03)
            if (this.mcProto >= 764) {
              const ack = new ByteWriter();
              ack.writeVarInt(0x03);
              await this.tcp.sendPacket(ack.toUint8Array());
              this.log('[TCP<-LoginAcknowledged] Sent 0x03 (mcProto >= 764)');
            }

            this.username = acceptedUsername;
            this.uuidBytes = acceptedUuidBytes;
            this.state = 'STALLING';
            this._sendAllowLogin();
          } else if (pktId === pluginMessagePlayId(this.mcProto)) {
            this._bufferStalledPacket(pkt);
          } else if (pktId === 0x04) {
            // S04LoginPluginRequest
            let msgId = null;
            let channel = '(unknown)';
            let payloadLen = 0;
            try {
              msgId = reader.readVarInt();
              channel = reader.readMCString(32767);
              payloadLen = reader.remaining;
            } catch (e) {
              this.log(`[BACKEND_LOGIN] S04LoginPluginRequest parse warning: ${e?.message || e}`);
            }

            if (this.config.compatMode && msgId !== null) {
              const resp = new ByteWriter();
              resp.writeVarInt(0x02); // Serverbound LoginPluginResponse
              resp.writeVarInt(msgId);
              resp.writeBool(false); // successful = false (unsupported channel)
              await this.tcp.sendPacket(resp.toUint8Array());
              this.log(
                `[BACKEND_LOGIN][COMPAT] S04LoginPluginRequest channel=${JSON.stringify(channel)} msgId=${msgId} payload=${payloadLen}B -> replied 0x02 (successful=false)`
              );
            } else {
              this.log(
                `[BACKEND_LOGIN] S04LoginPluginRequest channel=${JSON.stringify(channel)} msgId=${msgId} payload=${payloadLen}B -> unsupported by Eaglercraft`
              );
              this.sendErrorAndClose(
                ERR.CUSTOM_MESSAGE,
                'This server requires a login plugin handshake (proxy forwarding or mod support) that Eaglercraft clients cannot provide'
              );
              break;
            }
          } else if (pktId === 0x05 && this.config.compatMode && this.mcProto >= 766) {
            // S05CookieRequest (1.20.5+ / proto 766+)
            let key = '';
            try {
              key = reader.readMCString(32767);
              const resp = new ByteWriter();
              resp.writeVarInt(0x04); // Serverbound CookieResponse
              resp.writeMCString(key);
              resp.writeBool(false); // hasPayload = false
              await this.tcp.sendPacket(resp.toUint8Array());
              this.log(`[BACKEND_LOGIN][COMPAT] S05CookieRequest key=${JSON.stringify(key)} -> replied 0x04 (hasPayload=false)`);
            } catch (e) {
              this.log(`[BACKEND_LOGIN][COMPAT] S05CookieRequest parse warning: ${e?.message || e}`);
            }
          } else {
            this.log(`[BACKEND_LOGIN] Ignoring unknown login packet 0x${pktId.toString(16)}`);
          }
        } else if (this.state === 'STALLING') {
          const isPlayDisconnect = pktId === playDisconnectId(this.mcProto);
          const isConfigDisconnect = this.mcProto >= 764 && pktId === configDisconnectId(this.mcProto);
          if (isPlayDisconnect || isConfigDisconnect) {
            const reason = reader.readMCString(32767);
            this.log(`[STALLING] Disconnect packet reason=${reason}`);
            this.sendErrorAndClose(ERR.CUSTOM_MESSAGE, reason);
            break;
          }
          this._bufferStalledPacket(pkt);
        }
      }
    } catch (err) {
      this.log(`[TCP->ERR] ${err?.stack || err}`);
      if (!this.terminated) {
        this.sendErrorAndClose(ERR.CUSTOM_MESSAGE, `Backend connection error: ${err.message}`);
      }
    }
  }

  _sendAllowLogin() {
    const w = new ByteWriter();
    w.writeByte(PKT.SERVER_ALLOW_LOGIN);
    w.writeAsciiShortPrefixed(this.username, 16);
    w.writeBytes(this.uuidBytes);
    if (this.eaglerProto >= 5) {
      w.writeVarInt(0); // accepted standard capabilities mask
      w.writeByte(0);   // extended capabilities count
    }
    const out = w.toUint8Array();
    this.log(`[WS<-ALLOW_LOGIN] len=${out.length} hex=${toHex(out)}`);
    this.sendWs(out);
  }

  _bufferStalledPacket(pkt) {
    if (
      this.bufferedPackets.length >= MAX_STALLED_PACKETS ||
      this.bufferedBytes + pkt.length > MAX_STALLED_BYTES
    ) {
      this.sendErrorAndClose(
        ERR.CUSTOM_MESSAGE,
        'Login timed out (too much pending data while the client stalled)'
      );
      return;
    }
    this.bufferedBytes += pkt.length;
    this.bufferedPackets.push(pkt);
  }

  _enterPlayState() {
    const finish = new ByteWriter();
    finish.writeByte(PKT.SERVER_FINISH_LOGIN);
    this.sendWs(finish.toUint8Array());
    this.log(`[WS<-FINISH_LOGIN] Flushing ${this.bufferedPackets.length} buffered packets (${this.bufferedBytes} bytes) -> entering PLAY`);

    this.state = 'PLAY';
    for (const pkt of this.bufferedPackets) {
      this.sendWs(pkt);
    }
    this.bufferedPackets = [];
    this.bufferedBytes = 0;
  }
}
