/**
 * Parse a target URL / host:port string into { hostname, port }.
 * Accepts:
 *   - "tcp://mc.example.com:25565"
 *   - "mc://mc.example.com:25565"
 *   - "mc.example.com:25565"
 *   - "mc.example.com" (defaults to 25565)
 *   - "[2001:db8::1]:25565"
 */
export function parseTargetUrl(raw) {
  if (!raw || typeof raw !== 'string') {
    throw new Error('Missing target URL');
  }
  let cleaned = raw.trim();
  // Strip optional scheme like tcp://, mc://, ws://, wss://, http://, https://
  cleaned = cleaned.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');
  // Strip trailing path/query if any
  const slashIdx = cleaned.indexOf('/');
  if (slashIdx !== -1) {
    cleaned = cleaned.slice(0, slashIdx);
  }
  if (!cleaned) {
    throw new Error('Empty target host');
  }

  let hostname;
  let port = 25565;

  if (cleaned.startsWith('[')) {
    const closeBracket = cleaned.indexOf(']');
    if (closeBracket === -1) {
      throw new Error(`Invalid IPv6 target: ${raw}`);
    }
    hostname = cleaned.slice(1, closeBracket);
    const rest = cleaned.slice(closeBracket + 1);
    if (rest.startsWith(':')) {
      port = parsePort(rest.slice(1), raw);
    }
  } else {
    const lastColon = cleaned.lastIndexOf(':');
    if (lastColon !== -1 && cleaned.indexOf(':') === lastColon) {
      hostname = cleaned.slice(0, lastColon);
      port = parsePort(cleaned.slice(lastColon + 1), raw);
    } else {
      hostname = cleaned;
    }
  }

  if (!hostname) {
    throw new Error(`Invalid target hostname: ${raw}`);
  }

  return { hostname, port };
}

function parsePort(portStr, raw) {
  const n = Number(portStr);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    throw new Error(`Invalid port in target "${raw}": ${portStr}`);
  }
  return n;
}

export function isTargetAllowed(target, allowedPatternsRaw) {
  if (!allowedPatternsRaw || !allowedPatternsRaw.trim()) {
    return true;
  }
  const patterns = allowedPatternsRaw
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (patterns.length === 0) return true;

  const hostLower = target.hostname.toLowerCase();
  const portStr = String(target.port);

  for (const pattern of patterns) {
    let pHost = pattern;
    let pPort = null;
    const colonIdx = pattern.lastIndexOf(':');
    if (colonIdx !== -1) {
      pHost = pattern.slice(0, colonIdx);
      pPort = pattern.slice(colonIdx + 1);
    }
    const portMatch = pPort === null || pPort === '*' || pPort === portStr;
    if (!portMatch) continue;

    if (pHost === '*' || pHost === hostLower) return true;
    if (pHost.startsWith('*.')) {
      const suffix = pHost.slice(1); // ".example.com"
      if (hostLower.endsWith(suffix) && hostLower.length > suffix.length) {
        return true;
      }
    }
  }
  return false;
}

export function resolveConfig(request, env) {
  const url = new URL(request.url);

  // Check optional access token
  const expectedToken = (env.ACCESS_TOKEN || '').trim();
  if (expectedToken) {
    const providedToken =
      url.searchParams.get('token') ||
      url.searchParams.get('key') ||
      request.headers.get('X-Access-Token') ||
      (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
    if (providedToken !== expectedToken) {
      return { error: 'Unauthorized: invalid or missing access token', status: 401 };
    }
  }

  const allowDynamic = String(env.ALLOW_DYNAMIC_TARGET || 'false').toLowerCase() === 'true';
  let rawTarget = (env.TARGET_URL || '').trim();
  if (!rawTarget && env.TARGET_HOST) {
    rawTarget = env.TARGET_PORT
      ? `${env.TARGET_HOST.trim()}:${env.TARGET_PORT.trim()}`
      : env.TARGET_HOST.trim();
  }

  // Optional dynamic target from query (?target=host:port) or path (/host:port)
  const queryTarget = url.searchParams.get('target') || url.searchParams.get('url');
  const pathTarget = url.pathname.length > 1 ? decodeURIComponent(url.pathname.slice(1)) : '';
  const requestedTarget = queryTarget || (pathTarget && !pathTarget.includes('/') ? pathTarget : '');

  if (requestedTarget) {
    if (!allowDynamic) {
      return { error: 'Dynamic target override is disabled on this worker', status: 403 };
    }
    rawTarget = requestedTarget;
  }

  let target;
  try {
    target = parseTargetUrl(rawTarget);
  } catch (err) {
    return { error: `Invalid target configuration: ${err.message}`, status: 400 };
  }

  if (requestedTarget && !isTargetAllowed(target, env.ALLOWED_TARGETS || '')) {
    return { error: `Target ${target.hostname}:${target.port} is not in ALLOWED_TARGETS`, status: 403 };
  }

  const modeParam = (url.searchParams.get('mode') || env.PROXY_MODE || 'eagler').toLowerCase();
  const mode = modeParam === 'raw' ? 'raw' : 'eagler';
  const compatParam = url.searchParams.get('compat');
  const compatMode =
    compatParam !== null
      ? compatParam.toLowerCase() === 'true'
      : String(env.COMPAT_MODE ?? 'false').toLowerCase() === 'true';

  return {
    target,
    mode,
    compatMode,
    verbose: String(env.VERBOSE ?? 'true').toLowerCase() === 'true',
    serverName: env.SERVER_NAME || 'EaglerX CF Worker',
    serverBrand: env.SERVER_BRAND || 'EaglerXCF',
    serverVersion: env.SERVER_VERSION || '1.1.1',
    minMcProtocol: Number(env.MIN_MC_PROTOCOL || 47),
    maxMcProtocol: Number(env.MAX_MC_PROTOCOL || 800),
  };
}
