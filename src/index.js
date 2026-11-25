import { resolveConfig } from './config.js';

// The Durable Object class must be exported from the Worker entry module.
export { EaglerSession } from './session-do.js';

/**
 * Thin router. All the heavy lifting (Eagler handshake, TCP bridging,
 * zlib/AES) happens inside a per-connection Durable Object so the session
 * is not subject to the 10 ms Workers Free CPU limit.
 */
export default {
  async fetch(request, env) {
    const upgradeHeader = request.headers.get('Upgrade');
    const resolved = resolveConfig(request, env);
    const reqUrl = new URL(request.url);

    // Normal HTTP GET: return health/info response
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      if (resolved.error) {
        console.warn(`[HTTP] ${request.method} ${reqUrl.pathname} -> ${resolved.status} ${resolved.error}`);
        return Response.json(
          { ok: false, error: resolved.error },
          { status: resolved.status }
        );
      }
      if (resolved.verbose) {
        console.log(`[HTTP] ${request.method} ${reqUrl.pathname} -> 200 OK (mode=${resolved.mode}, target=${resolved.target.hostname}:${resolved.target.port})`);
      }
      return Response.json(
        {
          ok: true,
          service: 'eaglerx-cf-worker',
          runtime: 'durable-object',
          mode: resolved.mode,
          target: `${resolved.target.hostname}:${resolved.target.port}`,
          verbose: resolved.verbose,
          hint: 'Connect via WebSocket (wss://) using an Eaglercraft client or raw TCP tunnel.',
        },
        { status: 200 }
      );
    }

    // Reject bad token / disallowed target early, without spinning up a DO.
    if (resolved.error) {
      console.warn(`[WS-REJECT] ${reqUrl.pathname} -> ${resolved.status} ${resolved.error}`);
      return new Response(resolved.error, { status: resolved.status });
    }

    // One Durable Object per connection: each session gets its own
    // CPU budget and isolate, and sessions never block each other.
    const id = env.EAGLER_SESSION.newUniqueId();
    const stub = env.EAGLER_SESSION.get(id);
    return stub.fetch(request);
  },
};
