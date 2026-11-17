// Outbound HTTPS for the checker, safe to point at a URL a stranger typed in.
//
// - HTTPS only, on 443 or 8443, with no credentials in the URL.
// - Every address a hostname resolves to is checked before connecting, and the
//   connection uses that checked address, so DNS rebinding can't swap in an
//   internal one. Private, loopback, link-local, metadata and other reserved
//   ranges are refused, for IPv4 and IPv6 (including mapped and NAT64 forms).
// - Redirects are never followed here; callers decide, and each hop comes back
//   through this function.
// - Each request has a time limit and a size cap, and sends only the headers the
//   caller passes. Nothing from the visitor (cookies, tokens) is ever forwarded.

import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';

export const USER_AGENT = 'NestedBit-MCP-Security-Checker/1.0 (+https://nestedbit.com/tools/mcp-security-checker)';

const ALLOWED_PORTS = new Set(['', '443', '8443']);

const BLOCKED_V4: [string, number][] = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

const BLOCKED_V6: [string, number][] = [
  ['::', 128],
  ['::1', 128],
  // IPv4-mapped addresses (::ffff:a.b.c.d) are checked against the IPv4 list by BlockList itself.
  ['64:ff9b::', 96], // NAT64
  ['64:ff9b:1::', 48],
  ['100::', 64], // discard
  ['2001::', 32], // Teredo
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4
  ['fc00::', 7], // unique local
  ['fe80::', 10], // link-local
  ['ff00::', 8], // multicast
];

const blockList = new net.BlockList();
for (const [address, prefix] of BLOCKED_V4) blockList.addSubnet(address, prefix, 'ipv4');
for (const [address, prefix] of BLOCKED_V6) blockList.addSubnet(address, prefix, 'ipv6');

const BLOCKED_NAMES = /(^|\.)(localhost|local|internal|intranet|lan|home|corp|svc|cluster\.local)$/i;

export function isBlockedAddress(address: string): boolean {
  const family = net.isIP(address);
  if (family === 0) return true;
  return blockList.check(address, family === 6 ? 'ipv6' : 'ipv4');
}

export class FetchError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/** Throws a FetchError with a message fit to show the visitor. */
export function assertSafeUrl(url: URL): void {
  if (url.protocol !== 'https:') throw new FetchError('NOT_HTTPS', 'Only https:// addresses can be checked.');
  if (url.username || url.password) throw new FetchError('CREDENTIALS', 'Remove the user name or password from the address.');
  if (!ALLOWED_PORTS.has(url.port)) throw new FetchError('PORT', 'Only the standard HTTPS ports (443 and 8443) can be checked.');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    if (isBlockedAddress(host)) throw new FetchError('BLOCKED', 'That address is private or reserved, so it can’t be checked.');
  } else if (!host.includes('.') || BLOCKED_NAMES.test(host)) {
    throw new FetchError('BLOCKED', 'That address is private or internal, so it can’t be checked.');
  }
}

type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void;

// Resolves like dns.lookup, but refuses if any resolved address is blocked.
function guardedLookup(hostname: string, options: dns.LookupOptions, callback: LookupCallback) {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err, []);
    const list = addresses as dns.LookupAddress[];
    if (list.length === 0 || list.some((a) => isBlockedAddress(a.address))) {
      const blocked = new Error('That address resolves to a private or reserved network.') as NodeJS.ErrnoException;
      blocked.code = 'BLOCKED';
      return callback(blocked, []);
    }
    if (options.all) callback(null, list);
    else callback(null, list[0].address, list[0].family);
  });
}

export interface SafeResponse {
  url: string;
  status: number;
  /** Lower-cased names; repeated headers joined with ", ". */
  headers: Record<string, string>;
  /** Every WWW-Authenticate value as sent, since joining them loses the boundaries. */
  wwwAuthenticate: string[];
  body: string;
  truncated: boolean;
  ms: number;
}

export interface SafeRequestOptions {
  method?: 'GET' | 'POST' | 'DELETE';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  maxBytes?: number;
  /** Stop reading once this returns true (for SSE streams that stay open). */
  until?: (body: string) => boolean;
}

export type RequestFn = (url: URL, options?: SafeRequestOptions) => Promise<SafeResponse>;

/** The hosted checker's request: only public https:// addresses, as above. */
export const safeRequest: RequestFn = (url, options = {}) => send(url, options, true);

/**
 * A request with none of the guards above: http:// and private, loopback and
 * internal addresses are allowed. Only for checks run on the user's own machine
 * (the @nestedbit/check CLI in packages/check), never for a URL a stranger typed in.
 */
export const localRequest: RequestFn = (url, options = {}) => send(url, options, false);

function send(url: URL, options: SafeRequestOptions, guarded: boolean): Promise<SafeResponse> {
  const { method = 'GET', headers = {}, body, timeoutMs = 8000, maxBytes = 256 * 1024, until } = options;
  return new Promise<SafeResponse>((resolve, reject) => {
    try {
      if (guarded) assertSafeUrl(url);
      else if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new FetchError('PROTOCOL', 'Only http:// and https:// addresses can be checked.');
    } catch (err) {
      reject(err);
      return;
    }
    const started = Date.now();
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const secure = url.protocol === 'https:';
    let settled = false;

    const req = (secure ? https : http).request(
      {
        protocol: url.protocol,
        hostname: host,
        port: url.port || (secure ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method,
        agent: false,
        ...(guarded && { lookup: guardedLookup as unknown as typeof dns.lookup }),
        ...(secure && { servername: net.isIP(host) ? undefined : host }),
        headers: {
          'user-agent': USER_AGENT,
          ...headers,
          ...(body !== undefined ? { 'content-length': Buffer.byteLength(body).toString() } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let truncated = false;

        const finish = () => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          const headerMap: Record<string, string> = {};
          const wwwAuthenticate: string[] = [];
          for (let i = 0; i < res.rawHeaders.length; i += 2) {
            const name = res.rawHeaders[i].toLowerCase();
            const value = res.rawHeaders[i + 1];
            if (name === 'www-authenticate') wwwAuthenticate.push(value);
            headerMap[name] = name in headerMap ? `${headerMap[name]}, ${value}` : value;
          }
          resolve({
            url: url.href,
            status: res.statusCode ?? 0,
            headers: headerMap,
            wwwAuthenticate,
            body: Buffer.concat(chunks).toString('utf8'),
            truncated,
            ms: Date.now() - started,
          });
          res.destroy();
        };

        res.on('data', (chunk: Buffer) => {
          if (settled) return;
          size += chunk.length;
          if (size > maxBytes) {
            chunks.push(chunk.subarray(0, chunk.length - (size - maxBytes)));
            truncated = true;
            finish();
            return;
          }
          chunks.push(chunk);
          if (until && until(Buffer.concat(chunks).toString('utf8'))) finish();
        });
        res.on('end', finish);
        res.on('error', (err) => fail(err));
      },
    );

    const fail = (err: Error & { code?: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req.destroy();
      reject(toFetchError(err));
    };

    const timer = setTimeout(() => fail(new FetchError('TIMEOUT', 'The server took too long to answer.')), timeoutMs);
    req.on('error', fail);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

const TLS_CODES = new Set([
  'CERT_HAS_EXPIRED',
  'CERT_NOT_YET_VALID',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_REVOKED',
]);

function toFetchError(err: Error & { code?: string }): FetchError {
  if (err instanceof FetchError) return err;
  const code = err.code ?? 'NETWORK';
  if (code === 'BLOCKED') return new FetchError('BLOCKED', err.message);
  if (TLS_CODES.has(code)) return new FetchError('TLS', `The HTTPS certificate isn’t valid (${code}).`);
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return new FetchError('DNS', 'That host name doesn’t resolve.');
  if (code === 'ECONNREFUSED') return new FetchError('REFUSED', 'The server refused the connection.');
  if (code === 'ECONNRESET' || code === 'EPIPE') return new FetchError('RESET', 'The server closed the connection.');
  return new FetchError(code, 'The server couldn’t be reached.');
}
