// The MCP Security Checker's server-side checks: everything that needs the
// network. It walks what an MCP client does when it first meets a server,
// against the 2026-07-28 specification:
//
//   1. POST server/discover with no token (Streamable HTTP). Servers on an
//      older version don't know it, so they get initialize next.
//   2. Signed-in servers: read the 401 challenge, fetch protected resource
//      metadata (RFC 9728) and authorization server metadata (RFC 8414 or
//      OpenID Connect discovery), then confirm a fake token and an unsigned
//      token are both rejected.
//   3. Open servers: list the tools, check that a foreign Origin is refused and,
//      on older versions that still have sessions, check the session ID. The tools themselves are reviewed in the
//      visitor's browser and for the badge (review.ts, report.ts).
//   4. Servers that don't answer POST: look for the older HTTP+SSE transport.
//
// Checks are passive. Nothing is registered, no tool is ever called, and no
// credential of the visitor's is accepted or sent.

import { FetchError, safeRequest, type RequestFn, type SafeResponse } from './guard.ts';

export type Severity = 'high' | 'medium' | 'low' | 'note';

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  fix?: string;
  /** Link to the part of a specification that applies. */
  ref?: string;
}

export interface Step {
  label: string;
  method: string;
  url: string;
  status: number | null;
  ms: number;
  note?: string;
}

export interface CheckResult {
  target: string;
  checkedAt: string;
  reachable: boolean;
  auth: 'oauth' | 'open' | 'unknown';
  transport: 'streamable-http' | 'sse' | 'unknown';
  server?: { name?: string; version?: string; protocolVersion?: string };
  /** The authorization server's issuer, when one was found. */
  issuer?: string;
  /** Set when the check couldn't run far enough to judge the server. */
  inconclusive?: string;
  findings: Finding[];
  passed: string[];
  steps: Step[];
  /** Tools from tools/list, for open servers. */
  tools?: unknown[];
  toolsNote?: string;
}

export class InputError extends Error {}

const SPEC = 'https://modelcontextprotocol.io/specification/2026-07-28';
const REF = {
  auth: `${SPEC}/basic/authorization`,
  prmDiscovery: `${SPEC}/basic/authorization/authorization-server-discovery#protected-resource-metadata-discovery-requirements`,
  asDiscovery: `${SPEC}/basic/authorization/authorization-server-discovery#authorization-server-metadata-discovery`,
  registration: `${SPEC}/basic/authorization/client-registration`,
  pkce: `${SPEC}/basic/authorization/security-considerations#authorization-code-protection`,
  iss: `${SPEC}/basic/authorization#authorization-response-validation`,
  refresh: `${SPEC}/basic/authorization#refresh-tokens`,
  tokens: `${SPEC}/basic/authorization#token-handling`,
  scope: `${SPEC}/basic/authorization#scope-selection-strategy`,
  origin: `${SPEC}/basic/transports/streamable-http`,
  // Sessions ended with 2026-07-28, so this one stays on the last version that has them.
  sessions: 'https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#session-management',
  versions: `${SPEC}/basic/versioning#backward-compatibility-with-initialization-based-versions`,
  legacy: `${SPEC}/basic/transports/streamable-http#http+sse-transport-2024-11-05`,
  rfc9728: 'https://datatracker.ietf.org/doc/html/rfc9728',
  rfc8414: 'https://datatracker.ietf.org/doc/html/rfc8414#section-3.3',
  oauth21: 'https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13',
};

const CURRENT_VERSION = '2026-07-28';
/** The last version that starts with initialize. */
const INITIALIZE_VERSION = '2025-11-25';
const CLIENT_INFO = { name: 'nestedbit-mcp-security-checker', version: '1.0.0' };
const MAX_TOOLS = 300;

// ---------------------------------------------------------------------------
// Parsing helpers (exported for tests)

/** `allowHttp` is for checks run on the user's own machine, against a local or staging server. */
export function normalizeTarget(input: string, { allowHttp = false }: { allowHttp?: boolean } = {}): URL {
  const text = input.trim();
  if (!text) throw new InputError('Enter the address of an MCP server.');
  if (text.length > 2048) throw new InputError('That address is too long.');
  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`);
  } catch {
    throw new InputError('That isn’t a valid address.');
  }
  if (url.protocol === 'http:' && allowHttp) {
    url.hash = '';
    return url;
  }
  if (url.protocol === 'http:') {
    throw new InputError('MCP servers on the internet must use HTTPS. Enter an https:// address.');
  }
  if (url.protocol !== 'https:') throw new InputError(allowHttp ? 'Enter an http:// or https:// address.' : 'Enter an https:// address.');
  url.hash = '';
  return url;
}

export interface Challenge {
  scheme: string;
  params: Record<string, string>;
}

/** Parses WWW-Authenticate values into challenges (RFC 9110 section 11.6.1). */
export function parseWwwAuthenticate(values: string[]): Challenge[] {
  const challenges: Challenge[] = [];
  for (const value of values) {
    let current: Challenge | null = null;
    let i = 0;
    while (i < value.length) {
      while (i < value.length && /[\s,]/.test(value[i])) i++;
      const match = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+/.exec(value.slice(i));
      if (!match) {
        i++;
        continue;
      }
      const token = match[0];
      i += token.length;
      let j = i;
      while (value[j] === ' ') j++;
      if (value[j] === '=' && current && value[j + 1] !== '=') {
        j++;
        while (value[j] === ' ') j++;
        let param = '';
        if (value[j] === '"') {
          j++;
          while (j < value.length && value[j] !== '"') {
            if (value[j] === '\\') j++;
            param += value[j] ?? '';
            j++;
          }
          j++;
        } else {
          const bare = /^[^\s,]*/.exec(value.slice(j))![0];
          param = bare;
          j += bare.length;
        }
        current.params[token.toLowerCase()] = param;
        i = j;
      } else if (value[j] === '=' && current) {
        // token68 (e.g. a Basic credential echo); skip it.
        while (i < value.length && value[i] !== ',') i++;
      } else {
        current = { scheme: token, params: {} };
        challenges.push(current);
      }
    }
  }
  return challenges;
}

export interface SseEvent {
  event: string;
  data: string;
}

export function parseSse(body: string): SseEvent[] {
  const events: SseEvent[] = [];
  for (const block of body.split(/\r?\n\r?\n/)) {
    let event = 'message';
    const data: string[] = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith('event:')) event = line.slice(6).trim();
      else if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''));
    }
    if (data.length > 0) events.push({ event, data: data.join('\n') });
  }
  return events;
}

type JsonRpc = { id?: unknown; result?: Record<string, unknown>; error?: { code?: number; message?: string } };

/** Finds the JSON-RPC response with this id in a JSON or SSE body. */
export function readJsonRpc(res: SafeResponse, id: number): JsonRpc | null {
  const candidates: unknown[] = [];
  if ((res.headers['content-type'] ?? '').includes('text/event-stream')) {
    for (const e of parseSse(res.body)) {
      try {
        candidates.push(JSON.parse(e.data));
      } catch {
        // Not JSON; ignore.
      }
    }
  } else {
    try {
      const parsed = JSON.parse(res.body);
      candidates.push(...(Array.isArray(parsed) ? parsed : [parsed]));
    } catch {
      return null;
    }
  }
  const match = candidates.find((c) => c && typeof c === 'object' && (c as JsonRpc).id === id);
  return (match as JsonRpc) ?? null;
}

/** True once a complete SSE event carrying the response with this id has arrived. */
function sseHas(id: number) {
  return (body: string) => {
    const complete = /^[\s\S]*\r?\n\r?\n/.exec(body);
    if (!complete) return false;
    return parseSse(complete[0]).some((e) => {
      try {
        return (JSON.parse(e.data) as JsonRpc).id === id;
      } catch {
        return false;
      }
    });
  };
}

/** Lower-case scheme and host, no default port, fragment or trailing slash. */
export function canonical(url: string | URL): string {
  const u = new URL(url.toString());
  u.hash = '';
  const path = u.pathname.replace(/\/+$/, '');
  return `${u.protocol}//${u.host.toLowerCase()}${path}${u.search}`;
}

/** Whether a metadata resource identifies this endpoint, exactly or as a parent path on the same origin. */
export function resourceCovers(resource: string, target: URL): 'exact' | 'parent' | false {
  let r: URL;
  try {
    r = new URL(resource);
  } catch {
    return false;
  }
  if (canonical(r) === canonical(target)) return 'exact';
  if (r.origin !== target.origin || r.search) return false;
  const rp = r.pathname.replace(/\/+$/, '');
  const tp = target.pathname.replace(/\/+$/, '');
  return rp === '' || tp.startsWith(`${rp}/`) ? 'parent' : false;
}

export function prmCandidates(target: URL): URL[] {
  const path = target.pathname.replace(/\/+$/, '');
  const root = new URL('/.well-known/oauth-protected-resource', target.origin);
  return path ? [new URL(`/.well-known/oauth-protected-resource${path}`, target.origin), root] : [root];
}

export function asCandidates(issuer: URL): URL[] {
  const path = issuer.pathname.replace(/\/+$/, '');
  if (!path) {
    return [
      new URL('/.well-known/oauth-authorization-server', issuer.origin),
      new URL('/.well-known/openid-configuration', issuer.origin),
    ];
  }
  return [
    new URL(`/.well-known/oauth-authorization-server${path}`, issuer.origin),
    new URL(`/.well-known/openid-configuration${path}`, issuer.origin),
    new URL(`${path}/.well-known/openid-configuration`, issuer.origin),
  ];
}

function httpsUrl(value: unknown): URL | null {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url : null;
  } catch {
    return null;
  }
}

function list(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function mcpHeaders(extra: Record<string, string> = {}) {
  return { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...extra };
}

/** A request in the current protocol, which carries its version and client details every time. */
function modernRequest(
  id: number,
  method: string,
  version: string,
  params: Record<string, unknown> = {},
  headers: Record<string, string> = {},
) {
  return {
    method: 'POST' as const,
    headers: mcpHeaders({ 'mcp-protocol-version': version, 'mcp-method': method, ...headers }),
    body: JSON.stringify({
      jsonrpc: '2.0',
      id,
      method,
      params: {
        ...params,
        _meta: {
          'io.modelcontextprotocol/protocolVersion': version,
          'io.modelcontextprotocol/clientInfo': CLIENT_INFO,
          'io.modelcontextprotocol/clientCapabilities': {},
        },
      },
    }),
    until: sseHas(id),
  };
}

function initializeRequest(id: number, headers: Record<string, string> = {}) {
  return {
    method: 'POST' as const,
    headers: mcpHeaders(headers),
    body: JSON.stringify({
      jsonrpc: '2.0',
      id,
      method: 'initialize',
      params: { protocolVersion: INITIALIZE_VERSION, capabilities: {}, clientInfo: CLIENT_INFO },
    }),
    until: sseHas(id),
  };
}

/** The server/discover result in a response, or null when this isn't one. */
function readDiscovery(res: SafeResponse, id: number): Record<string, unknown> | null {
  if (res.status < 200 || res.status >= 300) return null;
  const result = readJsonRpc(res, id)?.result;
  return result && Array.isArray(result.supportedVersions) ? result : null;
}

/** An error only servers on the current protocol send: UnsupportedProtocolVersion, HeaderMismatch or MissingRequiredClientCapability. */
function readModernError(res: SafeResponse): { code: number; message: string; supported: string[] } | null {
  let error: { code?: unknown; message?: unknown; data?: { supported?: unknown } } | undefined;
  try {
    error = JSON.parse(res.body)?.error;
  } catch {
    return null;
  }
  if (typeof error?.code !== 'number' || ![-32022, -32020, -32021].includes(error.code)) return null;
  return {
    code: error.code,
    message: typeof error.message === 'string' ? error.message.slice(0, 200) : 'no message',
    supported: list(error.data?.supported),
  };
}

function unsignedToken(issuer: string | undefined, audience: string) {
  const now = Math.floor(Date.now() / 1000);
  const part = (obj: object) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  return `${part({ alg: 'none', typ: 'JWT' })}.${part({
    iss: issuer ?? 'https://nestedbit.com',
    sub: 'nestedbit-mcp-security-check',
    aud: audience,
    iat: now,
    exp: now + 300,
  })}.`;
}

// ---------------------------------------------------------------------------
// The check

export interface CheckOptions {
  request?: RequestFn;
  /** Epoch ms after which no new request starts. */
  deadline?: number;
  /** Accept an http:// target (local runs only; pair with a request function that allows it). */
  allowHttp?: boolean;
}

export async function checkServer(input: string, options: CheckOptions = {}): Promise<CheckResult> {
  const request = options.request ?? safeRequest;
  const deadline = options.deadline ?? Date.now() + 25_000;
  let target = normalizeTarget(input, { allowHttp: options.allowHttp });

  const result: CheckResult = {
    target: target.href,
    checkedAt: new Date().toISOString(),
    reachable: false,
    auth: 'unknown',
    transport: 'unknown',
    findings: [],
    passed: [],
    steps: [],
  };
  const add = (f: Finding) => result.findings.push(f);
  const pass = (text: string) => result.passed.push(text);

  type Outcome = { res: SafeResponse } | { error: FetchError };

  async function call(label: string, url: URL, opts: Parameters<RequestFn>[1] = {}): Promise<Outcome> {
    const method = opts.method ?? 'GET';
    const remaining = deadline - Date.now();
    if (remaining < 750) {
      const error = new FetchError('TIME', 'Skipped: the check ran out of time.');
      result.steps.push({ label, method, url: url.href, status: null, ms: 0, note: error.message });
      return { error };
    }
    try {
      const res = await request(url, { ...opts, timeoutMs: Math.min(opts.timeoutMs ?? 8000, remaining) });
      result.steps.push({ label, method, url: url.href, status: res.status, ms: res.ms });
      return { res };
    } catch (err) {
      const error = err instanceof FetchError ? err : new FetchError('NETWORK', 'The request failed.');
      result.steps.push({ label, method, url: url.href, status: null, ms: 0, note: error.message });
      return { error };
    }
  }

  /** GET a JSON object, following up to three redirects (each one checked like the first). */
  async function getJson(label: string, url: URL): Promise<{ doc: Record<string, unknown>; url: URL } | null> {
    let current = url;
    for (let hop = 0; hop <= 3; hop++) {
      const out = await call(hop ? `${label} (redirected)` : label, current, { headers: { accept: 'application/json' } });
      if ('error' in out) return null;
      const { res } = out;
      if (res.status >= 300 && res.status < 400 && res.headers.location) {
        const next = httpsUrl(new URL(res.headers.location, current).href);
        if (!next) return null;
        current = next;
        continue;
      }
      if (res.status !== 200) return null;
      try {
        const doc = JSON.parse(res.body);
        return doc && typeof doc === 'object' && !Array.isArray(doc) ? { doc, url: current } : null;
      } catch {
        return null;
      }
    }
    return null;
  }

  // The version every later request uses, and a request the sign-in gate covers.
  let version = CURRENT_VERSION;
  let gatedMethod = 'server/discover';

  // --- 1. Discover without a token -----------------------------------------------
  let opening: Outcome = await call('Discover the server, without a token', target, modernRequest(1, gatedMethod, version));

  // Follow up to two 307/308 redirects, which keep the POST.
  for (let hop = 0; hop < 2 && 'res' in opening; hop++) {
    const { res } = opening;
    if (![307, 308].includes(res.status) || !res.headers.location) break;
    const next = httpsUrl(new URL(res.headers.location, target).href);
    if (!next) break;
    add({
      id: 'redirect',
      severity: 'low',
      title: 'The address redirects',
      detail: `${target.href} redirects to ${next.href}. Some MCP clients don’t follow redirects, and tokens are issued for one exact address.`,
      fix: 'Publish the final address, and make the metadata’s resource match it.',
    });
    target = next;
    result.target = target.href;
    opening = await call('Discover the server, at the redirected address', target, modernRequest(1, gatedMethod, version));
  }

  if ('error' in opening && opening.error.code !== 'TIMEOUT') {
    const { error } = opening;
    if (error.code === 'BLOCKED' || error.code === 'NOT_HTTPS' || error.code === 'PORT' || error.code === 'CREDENTIALS') {
      throw new InputError(error.message);
    }
    if (error.code === 'TLS') {
      result.reachable = true;
      add({
        id: 'tls',
        severity: 'high',
        title: 'The HTTPS certificate isn’t valid',
        detail: `${error.message} Clients will refuse to connect, and anyone in between could read or change the traffic.`,
        fix: 'Serve a valid certificate for this host name, from a public certificate authority.',
        ref: REF.oauth21,
      });
      result.inconclusive = 'The connection failed on its certificate, so nothing else could be checked.';
      return result;
    }
    result.inconclusive = `${error.message} Check the address and try again.`;
    return result;
  }

  // A server on a newer version names what it speaks, and clients retry with one of those.
  let refused = 'res' in opening ? readModernError(opening.res) : null;
  const newer = refused?.code === -32022 ? refused.supported.filter((v) => v > version).sort().at(-1) : undefined;
  if (newer) {
    version = newer;
    opening = await call(`Discover the server, as version ${newer}`, target, modernRequest(1, gatedMethod, version));
    refused = 'res' in opening ? readModernError(opening.res) : null;
  }

  // An older server may stay silent on a method it doesn't know, so a timeout falls through too.
  const first = 'res' in opening ? opening.res : null;
  if (first) result.reachable = true;
  const discovery = first ? readDiscovery(first, 1) : null;

  if (first?.status === 401) {
    await checkSignedIn(first, false);
  } else if (discovery) {
    await checkOpen(first!, discovery, version);
  } else if (refused && (refused.code !== -32022 || newer)) {
    result.inconclusive = `The server speaks the current MCP version but refused the check’s request: ${refused.message}.`;
  } else {
    await checkOlderServer();
  }

  return result;

  // --- Servers on versions before 2026-07-28 ---------------------------------------
  async function checkOlderServer() {
    const init = await call('Initialize, as older MCP versions start', target, initializeRequest(1));
    if ('error' in init) {
      result.inconclusive = `${init.error.message} Check the address and try again.`;
      return;
    }
    result.reachable = true;
    const { res } = init;
    if (res.status === 401) {
      await checkSignedIn(res, false);
    } else if (res.status >= 200 && res.status < 300) {
      const message = readJsonRpc(res, 1);
      if (message?.result && typeof message.result === 'object') {
        await checkOpen(res, message.result, null);
      } else if (message?.error) {
        result.inconclusive = `The server answered initialize with an error: ${message.error.message ?? 'no message'}.`;
      } else {
        result.inconclusive = 'This address answered, but not with an MCP response. Check the path; many servers use /mcp.';
      }
    } else if ([400, 404, 405].includes(res.status)) {
      await checkLegacy(res.status);
    } else if (res.status === 403) {
      result.inconclusive =
        'The server refused the request (403 Forbidden) before any sign-in step. A firewall may be blocking automated checks.';
    } else if (res.status >= 300 && res.status < 400) {
      result.inconclusive = `The address redirects (${res.status}) in a way MCP clients can’t follow with a POST. Enter the final address instead.`;
    } else {
      result.inconclusive = `The server answered ${res.status}, so the check couldn’t continue.`;
    }
  }

  // --- Checks on any response ----------------------------------------------------
  function checkResponseHeaders(res: SafeResponse) {
    const hsts = res.headers['strict-transport-security'];
    if (hsts && /max-age=\s*"?(\d+)/i.test(hsts)) {
      pass('Sends Strict-Transport-Security, so browsers stay on HTTPS');
    } else {
      add({
        id: 'no-hsts',
        severity: 'low',
        title: 'No Strict-Transport-Security header',
        detail: 'Without HSTS, a browser-based client can be downgraded to plain HTTP on a hostile network.',
        fix: 'Send Strict-Transport-Security: max-age=31536000 on every HTTPS response.',
      });
    }
    if (res.headers['x-powered-by']) {
      add({
        id: 'powered-by',
        severity: 'note',
        title: 'The server names its framework',
        detail: `It sends X-Powered-By: ${res.headers['x-powered-by'].slice(0, 80)}, which tells attackers what to look up.`,
        fix: 'Remove the X-Powered-By header.',
      });
    }
  }

  // --- 2. Servers that require sign-in -------------------------------------------
  async function checkSignedIn(res: SafeResponse, legacy: boolean) {
    result.auth = 'oauth';
    if (!legacy) result.transport = 'streamable-http';
    checkResponseHeaders(res);
    pass('Requires sign-in: a request without a token gets 401 Unauthorized');

    const challenges = parseWwwAuthenticate(res.wwwAuthenticate);
    const bearer = challenges.find((c) => c.scheme.toLowerCase() === 'bearer');
    if (res.wwwAuthenticate.length === 0) {
      add({
        id: 'no-challenge',
        severity: 'medium',
        title: 'The 401 has no WWW-Authenticate header',
        detail: 'Clients read this header to learn how to sign in. Without it they have to guess the metadata address.',
        fix: 'Answer 401 with WWW-Authenticate: Bearer resource_metadata="https://…/.well-known/oauth-protected-resource".',
        ref: REF.prmDiscovery,
      });
    } else if (!bearer) {
      add({
        id: 'no-bearer',
        severity: 'medium',
        title: 'The 401 doesn’t offer Bearer tokens',
        detail: `The challenge offers ${challenges.map((c) => c.scheme).join(', ') || 'an unreadable scheme'}, but MCP clients sign in with OAuth Bearer tokens.`,
        fix: 'Answer 401 with a Bearer challenge that includes resource_metadata.',
        ref: REF.prmDiscovery,
      });
    }

    let metadataUrl: URL | null = null;
    if (bearer?.params.resource_metadata) {
      metadataUrl = httpsUrl(bearer.params.resource_metadata);
      if (metadataUrl) {
        pass('The 401 points clients to its metadata (resource_metadata)');
      } else {
        add({
          id: 'prm-url-invalid',
          severity: 'high',
          title: 'The metadata address in the 401 isn’t usable',
          detail: `resource_metadata is “${bearer.params.resource_metadata.slice(0, 120)}”, which isn’t an https:// URL.`,
          fix: 'Point resource_metadata at the full https:// URL of your protected resource metadata.',
          ref: REF.prmDiscovery,
        });
      }
    }
    if (bearer?.params.scope) {
      pass(`The 401 names the scopes it needs (${bearer.params.scope.slice(0, 80)})`);
    } else if (bearer) {
      add({
        id: 'no-challenge-scope',
        severity: 'note',
        title: 'The 401 doesn’t name the scopes it needs',
        detail: 'Without a scope in the challenge, clients request every scope in your metadata, which asks users for more than the first request needs.',
        fix: 'Add scope="…" to the Bearer challenge with the minimum scopes for the request.',
        ref: REF.scope,
      });
    }

    // Protected resource metadata (RFC 9728)
    let prm = metadataUrl ? await getJson('Protected resource metadata', metadataUrl) : null;
    if (!prm) {
      for (const candidate of prmCandidates(target)) {
        prm = await getJson('Protected resource metadata, well-known address', candidate);
        if (prm) break;
      }
      if (prm && metadataUrl) {
        add({
          id: 'prm-header-broken',
          severity: 'medium',
          title: 'The metadata address in the 401 doesn’t work',
          detail: `${metadataUrl.href} didn’t return metadata, though the well-known address did. Clients that follow the header stop there.`,
          fix: 'Fix resource_metadata so it points at the document clients can fetch.',
          ref: REF.prmDiscovery,
        });
      } else if (prm) {
        add({
          id: 'prm-not-in-header',
          severity: 'low',
          title: 'The 401 doesn’t say where the metadata is',
          detail: `Metadata was found at ${prm.url.href}, but only by probing well-known addresses.`,
          fix: 'Add resource_metadata="…" to the Bearer challenge so clients go straight to it.',
          ref: REF.prmDiscovery,
        });
      }
    }
    if (!prm) {
      add({
        id: 'no-prm',
        severity: 'high',
        title: 'No protected resource metadata',
        detail:
          'Neither the 401 nor the well-known addresses led to an OAuth protected resource metadata document. MCP servers must publish one (RFC 9728), and clients can’t find the sign-in server without it.',
        fix: 'Serve /.well-known/oauth-protected-resource with resource and authorization_servers, and point to it from the 401.',
        ref: REF.prmDiscovery,
      });
      if (!legacy) await probeTokens(undefined);
      return;
    }
    pass('Publishes protected resource metadata (RFC 9728)');

    const doc = prm.doc;
    const resource = typeof doc.resource === 'string' ? doc.resource : '';
    if (!resource) {
      add({
        id: 'prm-no-resource',
        severity: 'medium',
        title: 'The metadata doesn’t name the resource',
        detail: 'RFC 9728 requires a resource value, and clients use it as the audience they request tokens for.',
        fix: 'Set resource to this server’s canonical URL, such as https://mcp.example.com/mcp.',
        ref: REF.rfc9728,
      });
    } else {
      const covers = resourceCovers(resource, target);
      if (covers === 'exact') pass('The metadata’s resource matches this address exactly');
      else if (covers === 'parent') pass(`The metadata’s resource covers this address (${resource})`);
      else {
        add({
          id: 'prm-resource-mismatch',
          severity: 'high',
          title: 'The metadata names a different resource',
          detail: `The metadata says the resource is ${resource.slice(0, 160)}, but you checked ${target.href}. Clients that validate it, as RFC 9728 requires, refuse to continue, and tokens get issued for the wrong audience.`,
          fix: 'Set resource to the exact URL clients use for this server.',
          ref: REF.rfc9728,
        });
      }
    }
    if (list(doc.bearer_methods_supported).includes('query')) {
      add({
        id: 'token-in-query',
        severity: 'medium',
        title: 'Tokens are accepted in the URL',
        detail: 'bearer_methods_supported includes “query”. Tokens in URLs end up in logs, browser history and Referer headers, and MCP forbids them.',
        fix: 'Accept tokens only in the Authorization header.',
        ref: REF.tokens,
      });
    }
    if (!Array.isArray(doc.scopes_supported)) {
      add({
        id: 'prm-no-scopes',
        severity: 'note',
        title: 'The metadata lists no scopes',
        detail: 'Without scopes_supported, clients can’t request narrower access, so every token gets everything.',
        fix: 'List the minimum scopes in scopes_supported, and split read and write access.',
        ref: REF.scope,
      });
    }
    const challengeOffline = (bearer?.params.scope ?? '').split(/\s+/).includes('offline_access');
    const metadataOffline = list(doc.scopes_supported).includes('offline_access');
    if (challengeOffline || metadataOffline) {
      const where = [metadataOffline && 'the metadata’s scopes_supported', challengeOffline && 'the 401 challenge'].filter(Boolean);
      add({
        id: 'offline-access-scope',
        severity: 'low',
        title: 'offline_access is listed as a scope this server needs',
        detail: `It appears in ${where.join(' and ')}. offline_access is a request for a refresh token, made between the client and the authorization server, not a permission on this server. MCP servers shouldn’t list it, because it pushes clients to ask users for long-lived access they may not need.`,
        fix: 'Remove offline_access from scopes_supported and the 401 challenge. Clients add it themselves when the authorization server offers it.',
        ref: REF.refresh,
      });
    }

    // Authorization server metadata (RFC 8414 / OpenID Connect discovery)
    const servers = list(doc.authorization_servers);
    if (servers.length === 0) {
      add({
        id: 'prm-no-as',
        severity: 'high',
        title: 'The metadata names no authorization server',
        detail: 'MCP requires authorization_servers with at least one entry. Without it, clients don’t know where to sign in.',
        fix: 'Add authorization_servers: ["https://auth.example.com"] to the metadata.',
        ref: REF.prmDiscovery,
      });
      if (!legacy) await probeTokens(undefined);
      return;
    }
    const issuerUrl = httpsUrl(servers[0]);
    if (!issuerUrl) {
      add({
        id: 'as-not-https',
        severity: 'high',
        title: 'The authorization server isn’t on HTTPS',
        detail: `The metadata names ${servers[0].slice(0, 120)}. Every authorization server endpoint must use HTTPS.`,
        fix: 'Serve the authorization server over HTTPS and list its https:// issuer.',
        ref: REF.auth,
      });
      if (!legacy) await probeTokens(undefined);
      return;
    }
    result.issuer = issuerUrl.href;

    let as: { doc: Record<string, unknown>; url: URL } | null = null;
    for (const candidate of asCandidates(issuerUrl)) {
      as = await getJson('Authorization server metadata', candidate);
      if (as) break;
    }
    if (!as) {
      add({
        id: 'no-as-metadata',
        severity: 'high',
        title: 'No authorization server metadata',
        detail: `None of the discovery addresses for ${issuerUrl.href} returned metadata. MCP clients must find it through RFC 8414 or OpenID Connect discovery.`,
        fix: 'Serve /.well-known/oauth-authorization-server (or /.well-known/openid-configuration) for the issuer.',
        ref: REF.asDiscovery,
      });
    } else {
      pass(`Publishes authorization server metadata (${as.url.pathname.includes('openid') ? 'OpenID Connect' : 'RFC 8414'})`);
      checkAuthorizationServer(as.doc, issuerUrl);
    }

    if (!legacy) await probeTokens(issuerUrl.href);
  }

  function checkAuthorizationServer(doc: Record<string, unknown>, issuerUrl: URL) {
    const issuer = typeof doc.issuer === 'string' ? doc.issuer : '';
    if (!issuer) {
      add({
        id: 'as-no-issuer',
        severity: 'medium',
        title: 'The authorization server metadata has no issuer',
        detail: 'Clients compare issuer with the server they looked up, to defend against mix-up attacks.',
        fix: 'Set issuer to the authorization server’s exact URL.',
        ref: REF.rfc8414,
      });
    } else if (canonical(issuer) !== canonical(issuerUrl)) {
      add({
        id: 'as-issuer-mismatch',
        severity: 'medium',
        title: 'The issuer doesn’t match',
        detail: `The resource metadata names ${issuerUrl.href}, but the authorization server calls itself ${issuer.slice(0, 160)}. RFC 8414 requires these to be identical, and strict clients stop here.`,
        fix: 'Use the same issuer URL in both documents.',
        ref: REF.rfc8414,
      });
    } else {
      pass('The issuer matches the resource metadata');
    }

    for (const field of ['authorization_endpoint', 'token_endpoint'] as const) {
      if (typeof doc[field] !== 'string') {
        add({
          id: `as-no-${field}`,
          severity: 'high',
          title: `No ${field}`,
          detail: `The authorization server metadata has no ${field}, so clients can’t complete sign-in.`,
          fix: `Add ${field} to the metadata.`,
          ref: REF.asDiscovery,
        });
      } else if (!httpsUrl(doc[field])) {
        add({
          id: `as-${field}-not-https`,
          severity: 'high',
          title: `The ${field.replace('_', ' ')} isn’t on HTTPS`,
          detail: `${String(doc[field]).slice(0, 160)} would send codes or tokens unencrypted.`,
          fix: 'Serve every authorization server endpoint over HTTPS.',
          ref: REF.auth,
        });
      }
    }

    const pkce = doc.code_challenge_methods_supported;
    if (!Array.isArray(pkce)) {
      add({
        id: 'no-pkce',
        severity: 'high',
        title: 'PKCE support isn’t advertised',
        detail: 'The metadata has no code_challenge_methods_supported. MCP clients must refuse to continue without it, so sign-in fails in compliant clients.',
        fix: 'Support PKCE and add "code_challenge_methods_supported": ["S256"] to the metadata.',
        ref: REF.pkce,
      });
    } else if (!pkce.includes('S256')) {
      add({
        id: 'no-s256',
        severity: 'high',
        title: 'PKCE S256 isn’t supported',
        detail: `The metadata lists ${pkce.join(', ') || 'no methods'}. MCP clients must use S256.`,
        fix: 'Support the S256 code challenge method and list it in code_challenge_methods_supported.',
        ref: REF.pkce,
      });
    } else {
      pass('Supports PKCE with S256');
      if (pkce.includes('plain')) {
        add({
          id: 'pkce-plain',
          severity: 'low',
          title: 'PKCE “plain” is still allowed',
          detail: 'With plain, the verifier travels in the authorization request, so an intercepted request gives it away.',
          fix: 'Accept S256 only.',
          ref: REF.oauth21,
        });
      }
    }

    const grants = list(doc.grant_types_supported);
    const implicit =
      grants.includes('implicit') || list(doc.response_types_supported).some((t) => t.split(' ').includes('token'));
    const password = grants.includes('password');
    if (implicit || password) {
      const what = [implicit && 'the implicit flow', password && 'the password grant'].filter(Boolean);
      add({
        id: 'legacy-grants',
        severity: 'medium',
        title: 'Flows removed from OAuth 2.1 are still on',
        detail: `The metadata allows ${what.join(' and ')}. OAuth 2.1 removes ${what.length > 1 ? 'both' : 'it'}: implicit tokens leak through URLs, and password grants hand the client the user’s password.`,
        fix: 'Allow only the authorization code flow with PKCE, plus refresh tokens.',
        ref: REF.oauth21,
      });
    }

    if (doc.authorization_response_iss_parameter_supported === true) {
      pass('Advertises iss on authorization responses (RFC 9207), which lets clients catch mix-up attacks');
    } else {
      add({
        id: 'as-no-iss',
        severity: 'note',
        title: 'The authorization server doesn’t advertise iss',
        detail: 'Authorization servers should add iss to their authorization responses (RFC 9207) and say so in their metadata. Clients compare it with the server they chose, which catches a code sent by the wrong server. The specification expects to make this a requirement.',
        fix: 'Send iss on authorization responses, and set authorization_response_iss_parameter_supported to true.',
        ref: REF.iss,
      });
    }

    const cimd = doc.client_id_metadata_document_supported === true;
    const registration = doc.registration_endpoint;
    if (cimd) pass('Supports Client ID Metadata Documents, the registration method MCP now prefers');
    if (typeof registration === 'string') {
      if (!httpsUrl(registration)) {
        add({
          id: 'dcr-not-https',
          severity: 'high',
          title: 'The registration endpoint isn’t on HTTPS',
          detail: `${registration.slice(0, 160)} would return client credentials unencrypted.`,
          fix: 'Serve dynamic client registration over HTTPS.',
          ref: REF.auth,
        });
      } else {
        pass('Supports dynamic client registration (RFC 7591), which is deprecated but helps older clients');
      }
    }
    if (!cimd && typeof registration === 'string') {
      add({
        id: 'no-cimd',
        severity: 'note',
        title: 'No Client ID Metadata Documents',
        detail: 'The 2026-07-28 specification deprecates dynamic client registration in favour of Client ID Metadata Documents: clients identify themselves by an HTTPS URL instead of creating a new client each time.',
        fix: 'Add client_id_metadata_document_supported: true once your authorization server accepts URL client IDs.',
        ref: REF.registration,
      });
    }
    if (!cimd && typeof registration !== 'string') {
      add({
        id: 'no-registration',
        severity: 'medium',
        title: 'Clients can’t register themselves',
        detail: 'The metadata offers neither Client ID Metadata Documents nor dynamic client registration, so every user has to create an OAuth client by hand before connecting.',
        fix: 'Support Client ID Metadata Documents. Add dynamic client registration only if older clients need it.',
        ref: REF.registration,
      });
    }

    if (typeof doc.revocation_endpoint !== 'string') {
      add({
        id: 'no-revocation',
        severity: 'note',
        title: 'No token revocation endpoint',
        detail: 'Clients can’t revoke tokens when a user disconnects, so tokens stay valid until they expire.',
        fix: 'Add a revocation_endpoint (RFC 7009), and keep access tokens short-lived.',
        ref: REF.oauth21,
      });
    }
  }

  /** Confirms the server rejects a made-up token and an unsigned one. */
  async function probeTokens(issuer: string | undefined) {
    const probes = [
      { id: 'accepts-invalid-token', label: 'A request with a made-up token', token: 'nestedbit-mcp-check-not-a-real-token', what: 'a made-up token' },
      { id: 'accepts-unsigned-token', label: 'A request with an unsigned token', token: unsignedToken(issuer, target.href), what: 'an unsigned token (alg “none”)' },
    ];
    for (const probe of probes) {
      const authorization = { authorization: `Bearer ${probe.token}` };
      let out: Outcome = await call(probe.label, target, modernRequest(1, gatedMethod, version, {}, authorization));
      // A server on an older version refuses that request whatever the token, so ask its way too.
      if ('error' in out || (out.res.status !== 401 && !readJsonRpc(out.res, 1)?.result)) {
        out = await call(`${probe.label}, as older MCP versions start`, target, initializeRequest(1, authorization));
      }
      if ('error' in out) continue;
      const { res } = out;
      if (res.status === 401) {
        pass(`Rejects ${probe.what} with 401`);
      } else if (res.status >= 200 && res.status < 300 && readJsonRpc(res, 1)?.result) {
        add({
          id: probe.id,
          severity: 'high',
          title: `Accepts ${probe.what}`,
          detail: `The server answered a request carrying ${probe.what}. It checks that a token is present, not that it’s valid, so anyone can call it.`,
          fix: 'Validate every token: signature, issuer, expiry, and that its audience is this server.',
          ref: REF.tokens,
        });
      } else if (res.status >= 400 && res.status < 500 && !result.findings.some((f) => f.id === 'invalid-token-status')) {
        add({
          id: 'invalid-token-status',
          severity: 'low',
          title: `Answers ${probe.what} with ${res.status}, not 401`,
          detail: 'MCP servers must answer invalid or expired tokens with 401 and a WWW-Authenticate challenge, so clients know to sign in again.',
          fix: 'Return 401 with a Bearer challenge for any token that fails validation.',
          ref: REF.tokens,
        });
      }
    }
  }

  // --- 3. Servers open to anyone --------------------------------------------------
  /** modern is the version in use for a server/discover answer, and null for an initialize answer. */
  async function checkOpen(res: SafeResponse, init: Record<string, unknown>, modern: string | null) {
    result.transport = 'streamable-http';
    const meta = (init._meta ?? {}) as Record<string, unknown>;
    const info = ((modern ? meta['io.modelcontextprotocol/serverInfo'] : init.serverInfo) ?? {}) as { name?: unknown; version?: unknown };
    const negotiated = modern ?? (typeof init.protocolVersion === 'string' ? init.protocolVersion : INITIALIZE_VERSION);
    result.server = {
      name: typeof info.name === 'string' ? info.name.slice(0, 120) : undefined,
      version: typeof info.version === 'string' ? info.version.slice(0, 40) : undefined,
      protocolVersion: negotiated,
    };
    pass('Uses Streamable HTTP, the current MCP transport');
    if (modern) {
      pass(`Speaks the current MCP version (${modern}), which has no sessions to protect`);
    } else {
      add({
        id: 'legacy-protocol',
        severity: 'note',
        title: 'Speaks an older MCP version',
        detail: `It answered initialize as version ${negotiated.slice(0, 20)} but not server/discover, so it doesn’t speak ${CURRENT_VERSION}. Clients that know both versions can still connect, but the older one keeps sessions, which your server has to protect.`,
        fix: 'Update your MCP SDK. The current TypeScript SDK, Python SDK and FastMCP serve both versions.',
        ref: REF.versions,
      });
    }

    const session = modern ? undefined : res.headers['mcp-session-id'];
    if (session) {
      if (!/^[\x21-\x7e]+$/.test(session)) {
        add({
          id: 'session-chars',
          severity: 'low',
          title: 'The session ID has invalid characters',
          detail: 'Session IDs must contain only visible ASCII characters.',
          fix: 'Use a random UUID or a long random string.',
          ref: REF.sessions,
        });
      } else if (session.length < 16 || /^\d+$/.test(session)) {
        add({
          id: 'session-guessable',
          severity: 'medium',
          title: 'Session IDs look guessable',
          detail: `The session ID “${session.slice(0, 40)}” is short or numeric. Guessable session IDs let an attacker inject messages into someone else’s session.`,
          fix: 'Generate session IDs with a secure random source (a UUID v4 or 128 random bits), and never use them as authentication.',
          ref: REF.sessions,
        });
      } else {
        pass('Session IDs look random');
      }
    }

    const headers = (extra: Record<string, string> = {}) =>
      mcpHeaders({ 'mcp-protocol-version': negotiated, ...(session ? { 'mcp-session-id': session } : {}), ...extra });
    const listRequest = (id: number, params: Record<string, unknown>) =>
      modern
        ? modernRequest(id, 'tools/list', modern, params)
        : { method: 'POST' as const, headers: headers(), body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/list', params }), until: sseHas(id) };

    if (!modern) {
      await call('Initialized notification', target, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
      });
    }

    const capabilities = (init.capabilities ?? {}) as Record<string, unknown>;
    if (capabilities.tools) {
      const tools: unknown[] = [];
      let cursor: string | undefined;
      for (let page = 0; page < 3; page++) {
        const id = 2 + page;
        const out = await call(page ? `List tools, page ${page + 1}` : 'List tools', target, {
          ...listRequest(id, cursor ? { cursor } : {}),
          maxBytes: 1024 * 1024,
        });
        // Anyone may discover a server on the current version and still need a token for the rest.
        if (modern && page === 0 && 'res' in out && out.res.status === 401) {
          gatedMethod = 'tools/list';
          await checkSignedIn(out.res, false);
          return;
        }
        const message = 'res' in out ? readJsonRpc(out.res, id) : null;
        const pageTools = message?.result?.tools;
        if (!Array.isArray(pageTools)) {
          if (page === 0) result.toolsNote = 'The server didn’t return its tool list. Paste the output of tools/list below to review the tools.';
          break;
        }
        tools.push(...pageTools.slice(0, MAX_TOOLS - tools.length).map(trimTool));
        cursor = typeof message?.result?.nextCursor === 'string' ? message.result.nextCursor : undefined;
        if (!cursor || tools.length >= MAX_TOOLS) break;
      }
      if (!result.toolsNote) result.tools = tools;
    } else {
      result.tools = [];
      result.toolsNote = 'The server doesn’t offer any tools.';
    }

    result.auth = 'open';
    checkResponseHeaders(res);

    // Origin validation (DNS rebinding). Remote servers must check it too.
    const origin = { origin: 'https://evil.example' };
    const probe = await call('A request from a foreign web page', target, {
      ...(modern ? modernRequest(9, 'server/discover', modern, {}, origin) : initializeRequest(9, origin)),
      timeoutMs: 5000,
    });
    if ('res' in probe) {
      const { res: p } = probe;
      if (p.status === 403) {
        pass('Refuses requests from unknown web origins (403)');
      } else if (p.status >= 200 && p.status < 300) {
        add({
          id: 'no-origin-check',
          severity: 'low',
          title: 'Requests from any web page are accepted',
          detail: 'A request with Origin: https://evil.example was served. MCP servers must check the Origin header and answer unknown origins with 403; for servers people run on their own machines, this is what stops DNS rebinding attacks.',
          fix: 'Allow only the origins of web clients you support, and answer the rest with 403.',
          ref: REF.origin,
        });
        if (
          p.headers['access-control-allow-origin'] === 'https://evil.example' &&
          p.headers['access-control-allow-credentials'] === 'true'
        ) {
          add({
            id: 'cors-reflect',
            severity: 'medium',
            title: 'CORS trusts every origin, with credentials',
            detail: 'The server reflects any Origin in Access-Control-Allow-Origin and allows credentials, so any web page can read its responses with the visitor’s cookies.',
            fix: 'Return Access-Control-Allow-Origin only for an allowlist of origins.',
          });
        }
      }
      const extra = modern ? undefined : p.headers['mcp-session-id'];
      if (extra) await call('End the extra session', target, { method: 'DELETE', headers: mcpHeaders({ 'mcp-session-id': extra, 'mcp-protocol-version': negotiated }) });
    }

    if (session) await call('End the session', target, { method: 'DELETE', headers: headers() });
  }

  // --- 4. The older HTTP+SSE transport ---------------------------------------------
  async function checkLegacy(postStatus: number) {
    const out = await call('Look for the older HTTP+SSE transport', target, {
      method: 'GET',
      headers: { accept: 'text/event-stream' },
      timeoutMs: 5000,
      maxBytes: 16 * 1024,
      until: (body) => /event:\s*endpoint/.test(body),
    });
    if ('error' in out) {
      result.inconclusive = `POST returned ${postStatus} and GET failed, so this doesn’t look like an MCP endpoint. Check the path; many servers use /mcp.`;
      return;
    }
    const { res } = out;
    const legacyNote = {
      id: 'legacy-sse',
      severity: 'low' as const,
      title: 'Uses the deprecated HTTP+SSE transport',
      detail: 'This server speaks the 2024-11-05 HTTP+SSE transport, which the specification lists as deprecated. Streamable HTTP replaced it, and newer clients may drop support for it.',
      fix: 'Add a Streamable HTTP endpoint (one URL that accepts POST) and keep the old one only while clients migrate.',
      ref: REF.legacy,
    };
    if (res.status === 200 && /event:\s*endpoint/.test(res.body)) {
      result.transport = 'sse';
      result.auth = 'open';
      checkResponseHeaders(res);
      add(legacyNote);
      result.toolsNote =
        'This checker lists tools over Streamable HTTP only. Paste the output of tools/list below to review them.';
    } else if (res.status === 401) {
      result.transport = 'sse';
      add(legacyNote);
      await checkSignedIn(res, true);
    } else {
      result.inconclusive = `POST returned ${postStatus} and GET returned ${res.status}, so this doesn’t look like an MCP endpoint. Check the path; many servers use /mcp.`;
    }
  }
}

/** Keeps the fields the review uses, and bounds their size. */
function trimTool(tool: unknown): unknown {
  if (!tool || typeof tool !== 'object') return null;
  const t = tool as Record<string, unknown>;
  const schema = JSON.stringify(t.inputSchema ?? null);
  return {
    name: typeof t.name === 'string' ? t.name.slice(0, 200) : '',
    title: typeof t.title === 'string' ? t.title.slice(0, 200) : undefined,
    description: typeof t.description === 'string' ? t.description.slice(0, 8000) : undefined,
    inputSchema: schema.length <= 32_000 ? t.inputSchema : { type: 'object', truncated: true },
    annotations: trimAnnotations(t.annotations),
  };
}

const HINTS = ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'] as const;

function trimAnnotations(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const a = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of HINTS) if (typeof a[key] === 'boolean') out[key] = a[key];
  if (typeof a.title === 'string') out.title = a.title.slice(0, 200);
  return Object.keys(out).length > 0 ? out : undefined;
}
