import { connect } from 'cloudflare:sockets';
import { resolveConfig } from './config.js';
import { EaglerBridgeSession } from './eagler-protocol.js';

/**
 * One Durable Object instance per client WebSocket connection.
 *
 * Why a Durable Object: a plain Worker invocation on the Free plan gets only
 * 10 ms of CPU for the whole lifetime of the WebSocket, which a Minecraft
 * session blows through within a second. In a Durable Object every incoming
 * WebSocket message resets the CPU budget (30 s), so a live game session
 * that keeps exchanging packets with the client stays alive.
 *
 * The outbound TCP socket (cloudflare:sockets) prevents hibernation anyway,
 * so we use the classic ws.accept() model instead of the hibernation API.
 */
export class EaglerSession {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(request) {
    if ((request.headers.get('Upgrade') || '').toLowerCase() !== 'websocket') {
      return new Response('Expected WebSocket upgrade', { status: 426 });
    }

    // The Worker forwards the original request untouched, so config
    // (access token, target, mode, compat) resolves exactly as before.
    const resolved = resolveConfig(request, this.env);
    const reqUrl = new URL(request.url);

    if (resolved.error) {
      console.warn(`[WS-REJECT] ${reqUrl.pathname} -> ${resolved.status} ${resolved.error}`);
      return new Response(resolved.error, { status: resolved.status });
    }

    const sessionId = Math.random().toString(36).slice(2, 8);
    if (resolved.verbose) {
      console.log(
        `[WS-ACCEPT:${sessionId}] path=${reqUrl.pathname} mode=${resolved.mode} target=${resolved.target.hostname}:${resolved.target.port} origin=${request.headers.get('Origin') || '-'}`
      );
    }

    const pair = new WebSocketPair();
    const clientWs = pair[0];
    const serverWs = pair[1];
    serverWs.accept();

    if (resolved.mode === 'raw') {
      handleRawWssToTcp(serverWs, resolved.target, resolved.verbose, sessionId);
    } else {
      handleEaglerWssToTcp(serverWs, resolved, sessionId);
    }

    return new Response(null, { status: 101, webSocket: clientWs });
  }
}

/**
 * EaglerXPaper-compatible mode:
 * Translates Eaglercraft WSS (MOTD + Handshake V1-V5 + Game Packets)
 * to Vanilla/Paper Minecraft TCP (with VarInt framing & Zlib compression).
 */
function handleEaglerWssToTcp(ws, config, sessionId) {
  const session = new EaglerBridgeSession(ws, config, sessionId);

  ws.addEventListener('message', (event) => {
    session.enqueueMessage(event.data);
  });

  ws.addEventListener('close', (ev) => {
    session.log(`[WS] Client closed (code=${ev?.code ?? '-'} reason=${ev?.reason ?? '-'})`);
    session.close('ws_close');
  });

  ws.addEventListener('error', (ev) => {
    session.log(`[WS] Client error: ${ev?.message || 'unknown'}`);
    session.close('ws_error');
  });
}

/**
 * Raw mode:
 * Transparently pipes binary WebSocket messages <-> raw TCP byte stream.
 */
function handleRawWssToTcp(ws, target, verbose, sessionId) {
  const log = (m) => { if (verbose) console.log(`[Raw:${sessionId}] ${m}`); };
  log(`Connecting TCP ${target.hostname}:${target.port}`);
  const socket = connect({ hostname: target.hostname, port: target.port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  let closed = false;

  const cleanup = (why) => {
    if (closed) return;
    closed = true;
    log(`Closing (${why})`);
    try { reader.cancel(); } catch {}
    try { writer.close(); } catch {}
    try { socket.close(); } catch {}
    try { ws.close(); } catch {}
  };

  ws.addEventListener('message', async (event) => {
    if (closed) return;
    try {
      const payload =
        typeof event.data === 'string'
          ? new TextEncoder().encode(event.data)
          : new Uint8Array(event.data);
      log(`WS->TCP ${payload.length} bytes`);
      await writer.write(payload);
    } catch (err) {
      cleanup(`write_err: ${err?.message}`);
    }
  });

  ws.addEventListener('close', () => cleanup('ws_close'));
  ws.addEventListener('error', () => cleanup('ws_error'));

  (async () => {
    try {
      while (!closed) {
        const { value, done } = await reader.read();
        if (done || !value) break;
        log(`TCP->WS ${value.length} bytes`);
        ws.send(value);
      }
    } catch (err) {
      log(`TCP read err: ${err?.message}`);
    }
    cleanup('tcp_eof');
  })();
}
