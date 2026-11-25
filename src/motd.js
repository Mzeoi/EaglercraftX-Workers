import { ByteReader, ByteWriter } from './buffer.js';
import { MinecraftTcpConnection } from './mc-tcp.js';

/**
 * Flatten a Minecraft chat component (string or JSON object with text/extra)
 * into a legacy string preserving § formatting codes where possible.
 */
function flattenComponent(comp) {
  if (comp == null) return '';
  if (typeof comp === 'string') return comp;
  if (typeof comp !== 'object') return String(comp);

  let out = '';
  if (comp.color) {
    const colorMap = {
      black: '0', dark_blue: '1', dark_green: '2', dark_aqua: '3',
      dark_red: '4', dark_purple: '5', gold: '6', gray: '7',
      dark_gray: '8', blue: '9', green: 'a', aqua: 'b',
      red: 'c', light_purple: 'd', yellow: 'e', white: 'f',
    };
    if (colorMap[comp.color]) out += '§' + colorMap[comp.color];
  }
  if (comp.bold) out += '§l';
  if (comp.italic) out += '§o';
  if (comp.underlined) out += '§n';
  if (comp.strikethrough) out += '§m';
  if (comp.obfuscated) out += '§k';
  if (comp.text) out += comp.text;
  if (Array.isArray(comp.extra)) {
    for (const child of comp.extra) {
      out += flattenComponent(child);
    }
  }
  return out;
}

/**
 * Perform a Vanilla Minecraft Server List Ping (SLP) over TCP and convert
 * the response to Eaglercraft's MOTD JSON format.
 */
export async function queryMinecraftMotd(config, acceptHeader, log = () => {}) {
  const { hostname, port } = config.target;
  const acceptLower = acceptHeader.toLowerCase();
  const sub = acceptLower.startsWith('motd.') ? acceptLower.slice(5) : null;
  log(`[MOTD] Querying ${hostname}:${port} (accept=${acceptHeader})`);

  if (sub && sub.startsWith('cache.anim')) {
    return JSON.stringify({
      name: config.serverName,
      brand: config.serverBrand,
      vers: config.serverVersion,
      cracked: true,
      time: Date.now(),
      type: 'motd',
      data: { unsupported: true },
    });
  }

  let online = 0;
  let max = 20;
  let motdLines = [config.serverName, '§aPowered by Cloudflare Workers'];
  let players = [];

  const tcp = new MinecraftTcpConnection(hostname, port, log);
  try {
    const pingPromise = (async () => {
      const hs = new ByteWriter();
      hs.writeVarInt(0x00);
      hs.writeVarInt(47);
      hs.writeMCString(hostname);
      hs.writeShortBE(port);
      hs.writeVarInt(1);
      await tcp.sendPacket(hs.toUint8Array());

      const req = new ByteWriter();
      req.writeVarInt(0x00);
      await tcp.sendPacket(req.toUint8Array());

      const respBytes = await tcp.readPacket();
      if (!respBytes) {
        log('[MOTD] Backend closed without SLP response');
        return;
      }

      const reader = new ByteReader(respBytes);
      const pktId = reader.readVarInt();
      if (pktId !== 0x00) {
        log(`[MOTD] Unexpected SLP packetId=0x${pktId.toString(16)}`);
        return;
      }

      const jsonStr = reader.readMCString(32767);
      log(`[MOTD] Backend SLP JSON (${jsonStr.length} chars): ${jsonStr.slice(0, 300)}`);
      const status = JSON.parse(jsonStr);

      if (status.players) {
        if (typeof status.players.online === 'number') online = status.players.online;
        if (typeof status.players.max === 'number') max = status.players.max;
        if (Array.isArray(status.players.sample)) {
          players = status.players.sample
            .slice(0, 10)
            .map((p) => (p && p.name ? String(p.name) : ''))
            .filter(Boolean);
        }
      }
      if (status.description !== undefined) {
        const flat = flattenComponent(status.description);
        const lines = flat.split(/\r?\n/);
        motdLines = lines.slice(0, 2);
      }
    })();

    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('MOTD ping timeout (3s)')), 3000)
    );
    await Promise.race([pingPromise, timeoutPromise]);
  } catch (err) {
    log(`[MOTD] Backend SLP failed: ${err?.message || err}`);
    motdLines = [config.serverName, '§cBackend server unreachable'];
  } finally {
    await tcp.close();
  }

  const data = {
    cache: sub && sub.startsWith('cache') ? [] : false,
    motd: motdLines,
    icon: false,
    online,
    max,
    players,
  };
  if (sub && sub.startsWith('cache')) {
    data.ttl = 7200;
  }

  const out = JSON.stringify({
    name: config.serverName,
    brand: config.serverBrand,
    vers: config.serverVersion,
    plaf: 'cloudflare-workers',
    cracked: true,
    time: Date.now(),
    type: 'motd',
    data,
  });
  log(`[MOTD] Responding to client: ${out}`);
  return out;
}
