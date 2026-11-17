#!/usr/bin/env node

// src/bin/action.ts
import { appendFileSync } from "node:fs";

// src/mcp.ts
import { readFileSync as readFileSync2 } from "node:fs";
import path2 from "node:path";

// engine/guard.ts
import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import net from "node:net";
var USER_AGENT = "NestedBit-MCP-Security-Checker/1.0 (+https://nestedbit.com/tools/mcp-security-checker)";
var ALLOWED_PORTS = /* @__PURE__ */ new Set(["", "443", "8443"]);
var BLOCKED_V4 = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4]
];
var BLOCKED_V6 = [
  ["::", 128],
  ["::1", 128],
  // IPv4-mapped addresses (::ffff:a.b.c.d) are checked against the IPv4 list by BlockList itself.
  ["64:ff9b::", 96],
  // NAT64
  ["64:ff9b:1::", 48],
  ["100::", 64],
  // discard
  ["2001::", 32],
  // Teredo
  ["2001:db8::", 32],
  // documentation
  ["2002::", 16],
  // 6to4
  ["fc00::", 7],
  // unique local
  ["fe80::", 10],
  // link-local
  ["ff00::", 8]
  // multicast
];
var blockList = new net.BlockList();
for (const [address, prefix] of BLOCKED_V4) blockList.addSubnet(address, prefix, "ipv4");
for (const [address, prefix] of BLOCKED_V6) blockList.addSubnet(address, prefix, "ipv6");
var BLOCKED_NAMES = /(^|\.)(localhost|local|internal|intranet|lan|home|corp|svc|cluster\.local)$/i;
function isBlockedAddress(address) {
  const family = net.isIP(address);
  if (family === 0) return true;
  return blockList.check(address, family === 6 ? "ipv6" : "ipv4");
}
var FetchError = class extends Error {
  code;
  constructor(code, message) {
    super(message);
    this.code = code;
  }
};
function assertSafeUrl(url) {
  if (url.protocol !== "https:") throw new FetchError("NOT_HTTPS", "Only https:// addresses can be checked.");
  if (url.username || url.password) throw new FetchError("CREDENTIALS", "Remove the user name or password from the address.");
  if (!ALLOWED_PORTS.has(url.port)) throw new FetchError("PORT", "Only the standard HTTPS ports (443 and 8443) can be checked.");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host)) {
    if (isBlockedAddress(host)) throw new FetchError("BLOCKED", "That address is private or reserved, so it can\u2019t be checked.");
  } else if (!host.includes(".") || BLOCKED_NAMES.test(host)) {
    throw new FetchError("BLOCKED", "That address is private or internal, so it can\u2019t be checked.");
  }
}
function guardedLookup(hostname, options, callback) {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err, []);
    const list2 = addresses;
    if (list2.length === 0 || list2.some((a) => isBlockedAddress(a.address))) {
      const blocked = new Error("That address resolves to a private or reserved network.");
      blocked.code = "BLOCKED";
      return callback(blocked, []);
    }
    if (options.all) callback(null, list2);
    else callback(null, list2[0].address, list2[0].family);
  });
}
var safeRequest = (url, options = {}) => send(url, options, true);
var localRequest = (url, options = {}) => send(url, options, false);
function send(url, options, guarded) {
  const { method = "GET", headers = {}, body, timeoutMs = 8e3, maxBytes = 256 * 1024, until } = options;
  return new Promise((resolve, reject) => {
    try {
      if (guarded) assertSafeUrl(url);
      else if (url.protocol !== "https:" && url.protocol !== "http:") throw new FetchError("PROTOCOL", "Only http:// and https:// addresses can be checked.");
    } catch (err) {
      reject(err);
      return;
    }
    const started = Date.now();
    const host = url.hostname.replace(/^\[|\]$/g, "");
    const secure = url.protocol === "https:";
    let settled = false;
    const req = (secure ? https : http).request(
      {
        protocol: url.protocol,
        hostname: host,
        port: url.port || (secure ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method,
        agent: false,
        ...guarded && { lookup: guardedLookup },
        ...secure && { servername: net.isIP(host) ? void 0 : host },
        headers: {
          "user-agent": USER_AGENT,
          ...headers,
          ...body !== void 0 ? { "content-length": Buffer.byteLength(body).toString() } : {}
        }
      },
      (res) => {
        const chunks = [];
        let size = 0;
        let truncated = false;
        const finish = () => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          const headerMap = {};
          const wwwAuthenticate = [];
          for (let i = 0; i < res.rawHeaders.length; i += 2) {
            const name = res.rawHeaders[i].toLowerCase();
            const value = res.rawHeaders[i + 1];
            if (name === "www-authenticate") wwwAuthenticate.push(value);
            headerMap[name] = name in headerMap ? `${headerMap[name]}, ${value}` : value;
          }
          resolve({
            url: url.href,
            status: res.statusCode ?? 0,
            headers: headerMap,
            wwwAuthenticate,
            body: Buffer.concat(chunks).toString("utf8"),
            truncated,
            ms: Date.now() - started
          });
          res.destroy();
        };
        res.on("data", (chunk) => {
          if (settled) return;
          size += chunk.length;
          if (size > maxBytes) {
            chunks.push(chunk.subarray(0, chunk.length - (size - maxBytes)));
            truncated = true;
            finish();
            return;
          }
          chunks.push(chunk);
          if (until && until(Buffer.concat(chunks).toString("utf8"))) finish();
        });
        res.on("end", finish);
        res.on("error", (err) => fail(err));
      }
    );
    const fail = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req.destroy();
      reject(toFetchError(err));
    };
    const timer = setTimeout(() => fail(new FetchError("TIMEOUT", "The server took too long to answer.")), timeoutMs);
    req.on("error", fail);
    if (body !== void 0) req.write(body);
    req.end();
  });
}
var TLS_CODES = /* @__PURE__ */ new Set([
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "CERT_REVOKED"
]);
function toFetchError(err) {
  if (err instanceof FetchError) return err;
  const code = err.code ?? "NETWORK";
  if (code === "BLOCKED") return new FetchError("BLOCKED", err.message);
  if (TLS_CODES.has(code)) return new FetchError("TLS", `The HTTPS certificate isn\u2019t valid (${code}).`);
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return new FetchError("DNS", "That host name doesn\u2019t resolve.");
  if (code === "ECONNREFUSED") return new FetchError("REFUSED", "The server refused the connection.");
  if (code === "ECONNRESET" || code === "EPIPE") return new FetchError("RESET", "The server closed the connection.");
  return new FetchError(code, "The server couldn\u2019t be reached.");
}

// engine/check.ts
var InputError = class extends Error {
};
var SPEC = "https://modelcontextprotocol.io/specification/2026-07-28";
var REF = {
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
  sessions: "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#session-management",
  versions: `${SPEC}/basic/versioning#backward-compatibility-with-initialization-based-versions`,
  legacy: `${SPEC}/basic/transports/streamable-http#http+sse-transport-2024-11-05`,
  rfc9728: "https://datatracker.ietf.org/doc/html/rfc9728",
  rfc8414: "https://datatracker.ietf.org/doc/html/rfc8414#section-3.3",
  oauth21: "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13"
};
var CURRENT_VERSION = "2026-07-28";
var INITIALIZE_VERSION = "2025-11-25";
var CLIENT_INFO = { name: "nestedbit-mcp-security-checker", version: "1.0.0" };
var MAX_TOOLS = 300;
function normalizeTarget(input2, { allowHttp = false } = {}) {
  const text = input2.trim();
  if (!text) throw new InputError("Enter the address of an MCP server.");
  if (text.length > 2048) throw new InputError("That address is too long.");
  let url;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`);
  } catch {
    throw new InputError("That isn\u2019t a valid address.");
  }
  if (url.protocol === "http:" && allowHttp) {
    url.hash = "";
    return url;
  }
  if (url.protocol === "http:") {
    throw new InputError("MCP servers on the internet must use HTTPS. Enter an https:// address.");
  }
  if (url.protocol !== "https:") throw new InputError(allowHttp ? "Enter an http:// or https:// address." : "Enter an https:// address.");
  url.hash = "";
  return url;
}
function parseWwwAuthenticate(values) {
  const challenges = [];
  for (const value of values) {
    let current = null;
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
      while (value[j] === " ") j++;
      if (value[j] === "=" && current && value[j + 1] !== "=") {
        j++;
        while (value[j] === " ") j++;
        let param = "";
        if (value[j] === '"') {
          j++;
          while (j < value.length && value[j] !== '"') {
            if (value[j] === "\\") j++;
            param += value[j] ?? "";
            j++;
          }
          j++;
        } else {
          const bare = /^[^\s,]*/.exec(value.slice(j))[0];
          param = bare;
          j += bare.length;
        }
        current.params[token.toLowerCase()] = param;
        i = j;
      } else if (value[j] === "=" && current) {
        while (i < value.length && value[i] !== ",") i++;
      } else {
        current = { scheme: token, params: {} };
        challenges.push(current);
      }
    }
  }
  return challenges;
}
function parseSse(body) {
  const events = [];
  for (const block of body.split(/\r?\n\r?\n/)) {
    let event = "message";
    const data = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
    }
    if (data.length > 0) events.push({ event, data: data.join("\n") });
  }
  return events;
}
function readJsonRpc(res, id) {
  const candidates = [];
  if ((res.headers["content-type"] ?? "").includes("text/event-stream")) {
    for (const e of parseSse(res.body)) {
      try {
        candidates.push(JSON.parse(e.data));
      } catch {
      }
    }
  } else {
    try {
      const parsed = JSON.parse(res.body);
      candidates.push(...Array.isArray(parsed) ? parsed : [parsed]);
    } catch {
      return null;
    }
  }
  const match = candidates.find((c) => c && typeof c === "object" && c.id === id);
  return match ?? null;
}
function sseHas(id) {
  return (body) => {
    const complete = /^[\s\S]*\r?\n\r?\n/.exec(body);
    if (!complete) return false;
    return parseSse(complete[0]).some((e) => {
      try {
        return JSON.parse(e.data).id === id;
      } catch {
        return false;
      }
    });
  };
}
function canonical(url) {
  const u = new URL(url.toString());
  u.hash = "";
  const path3 = u.pathname.replace(/\/+$/, "");
  return `${u.protocol}//${u.host.toLowerCase()}${path3}${u.search}`;
}
function resourceCovers(resource, target) {
  let r;
  try {
    r = new URL(resource);
  } catch {
    return false;
  }
  if (canonical(r) === canonical(target)) return "exact";
  if (r.origin !== target.origin || r.search) return false;
  const rp = r.pathname.replace(/\/+$/, "");
  const tp = target.pathname.replace(/\/+$/, "");
  return rp === "" || tp.startsWith(`${rp}/`) ? "parent" : false;
}
function prmCandidates(target) {
  const path3 = target.pathname.replace(/\/+$/, "");
  const root = new URL("/.well-known/oauth-protected-resource", target.origin);
  return path3 ? [new URL(`/.well-known/oauth-protected-resource${path3}`, target.origin), root] : [root];
}
function asCandidates(issuer) {
  const path3 = issuer.pathname.replace(/\/+$/, "");
  if (!path3) {
    return [
      new URL("/.well-known/oauth-authorization-server", issuer.origin),
      new URL("/.well-known/openid-configuration", issuer.origin)
    ];
  }
  return [
    new URL(`/.well-known/oauth-authorization-server${path3}`, issuer.origin),
    new URL(`/.well-known/openid-configuration${path3}`, issuer.origin),
    new URL(`${path3}/.well-known/openid-configuration`, issuer.origin)
  ];
}
function httpsUrl(value) {
  if (typeof value !== "string") return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" ? url : null;
  } catch {
    return null;
  }
}
function list(value) {
  return Array.isArray(value) ? value.filter((v) => typeof v === "string") : [];
}
function mcpHeaders(extra = {}) {
  return { "content-type": "application/json", accept: "application/json, text/event-stream", ...extra };
}
function modernRequest(id, method, version, params = {}, headers = {}) {
  return {
    method: "POST",
    headers: mcpHeaders({ "mcp-protocol-version": version, "mcp-method": method, ...headers }),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method,
      params: {
        ...params,
        _meta: {
          "io.modelcontextprotocol/protocolVersion": version,
          "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
          "io.modelcontextprotocol/clientCapabilities": {}
        }
      }
    }),
    until: sseHas(id)
  };
}
function initializeRequest(id, headers = {}) {
  return {
    method: "POST",
    headers: mcpHeaders(headers),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "initialize",
      params: { protocolVersion: INITIALIZE_VERSION, capabilities: {}, clientInfo: CLIENT_INFO }
    }),
    until: sseHas(id)
  };
}
function readDiscovery(res, id) {
  if (res.status < 200 || res.status >= 300) return null;
  const result = readJsonRpc(res, id)?.result;
  return result && Array.isArray(result.supportedVersions) ? result : null;
}
function readModernError(res) {
  let error;
  try {
    error = JSON.parse(res.body)?.error;
  } catch {
    return null;
  }
  if (typeof error?.code !== "number" || ![-32022, -32020, -32021].includes(error.code)) return null;
  return {
    code: error.code,
    message: typeof error.message === "string" ? error.message.slice(0, 200) : "no message",
    supported: list(error.data?.supported)
  };
}
function unsignedToken(issuer, audience) {
  const now = Math.floor(Date.now() / 1e3);
  const part = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  return `${part({ alg: "none", typ: "JWT" })}.${part({
    iss: issuer ?? "https://nestedbit.com",
    sub: "nestedbit-mcp-security-check",
    aud: audience,
    iat: now,
    exp: now + 300
  })}.`;
}
async function checkServer(input2, options = {}) {
  const request = options.request ?? safeRequest;
  const deadline = options.deadline ?? Date.now() + 25e3;
  let target = normalizeTarget(input2, { allowHttp: options.allowHttp });
  const result = {
    target: target.href,
    checkedAt: (/* @__PURE__ */ new Date()).toISOString(),
    reachable: false,
    auth: "unknown",
    transport: "unknown",
    findings: [],
    passed: [],
    steps: []
  };
  const add = (f) => result.findings.push(f);
  const pass = (text) => result.passed.push(text);
  async function call(label, url, opts = {}) {
    const method = opts.method ?? "GET";
    const remaining = deadline - Date.now();
    if (remaining < 750) {
      const error = new FetchError("TIME", "Skipped: the check ran out of time.");
      result.steps.push({ label, method, url: url.href, status: null, ms: 0, note: error.message });
      return { error };
    }
    try {
      const res = await request(url, { ...opts, timeoutMs: Math.min(opts.timeoutMs ?? 8e3, remaining) });
      result.steps.push({ label, method, url: url.href, status: res.status, ms: res.ms });
      return { res };
    } catch (err) {
      const error = err instanceof FetchError ? err : new FetchError("NETWORK", "The request failed.");
      result.steps.push({ label, method, url: url.href, status: null, ms: 0, note: error.message });
      return { error };
    }
  }
  async function getJson(label, url) {
    let current = url;
    for (let hop = 0; hop <= 3; hop++) {
      const out = await call(hop ? `${label} (redirected)` : label, current, { headers: { accept: "application/json" } });
      if ("error" in out) return null;
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
        return doc && typeof doc === "object" && !Array.isArray(doc) ? { doc, url: current } : null;
      } catch {
        return null;
      }
    }
    return null;
  }
  let version = CURRENT_VERSION;
  let gatedMethod = "server/discover";
  let opening = await call("Discover the server, without a token", target, modernRequest(1, gatedMethod, version));
  for (let hop = 0; hop < 2 && "res" in opening; hop++) {
    const { res } = opening;
    if (![307, 308].includes(res.status) || !res.headers.location) break;
    const next = httpsUrl(new URL(res.headers.location, target).href);
    if (!next) break;
    add({
      id: "redirect",
      severity: "low",
      title: "The address redirects",
      detail: `${target.href} redirects to ${next.href}. Some MCP clients don\u2019t follow redirects, and tokens are issued for one exact address.`,
      fix: "Publish the final address, and make the metadata\u2019s resource match it."
    });
    target = next;
    result.target = target.href;
    opening = await call("Discover the server, at the redirected address", target, modernRequest(1, gatedMethod, version));
  }
  if ("error" in opening && opening.error.code !== "TIMEOUT") {
    const { error } = opening;
    if (error.code === "BLOCKED" || error.code === "NOT_HTTPS" || error.code === "PORT" || error.code === "CREDENTIALS") {
      throw new InputError(error.message);
    }
    if (error.code === "TLS") {
      result.reachable = true;
      add({
        id: "tls",
        severity: "high",
        title: "The HTTPS certificate isn\u2019t valid",
        detail: `${error.message} Clients will refuse to connect, and anyone in between could read or change the traffic.`,
        fix: "Serve a valid certificate for this host name, from a public certificate authority.",
        ref: REF.oauth21
      });
      result.inconclusive = "The connection failed on its certificate, so nothing else could be checked.";
      return result;
    }
    result.inconclusive = `${error.message} Check the address and try again.`;
    return result;
  }
  let refused = "res" in opening ? readModernError(opening.res) : null;
  const newer = refused?.code === -32022 ? refused.supported.filter((v) => v > version).sort().at(-1) : void 0;
  if (newer) {
    version = newer;
    opening = await call(`Discover the server, as version ${newer}`, target, modernRequest(1, gatedMethod, version));
    refused = "res" in opening ? readModernError(opening.res) : null;
  }
  const first = "res" in opening ? opening.res : null;
  if (first) result.reachable = true;
  const discovery = first ? readDiscovery(first, 1) : null;
  if (first?.status === 401) {
    await checkSignedIn(first, false);
  } else if (discovery) {
    await checkOpen(first, discovery, version);
  } else if (refused && (refused.code !== -32022 || newer)) {
    result.inconclusive = `The server speaks the current MCP version but refused the check\u2019s request: ${refused.message}.`;
  } else {
    await checkOlderServer();
  }
  return result;
  async function checkOlderServer() {
    const init = await call("Initialize, as older MCP versions start", target, initializeRequest(1));
    if ("error" in init) {
      result.inconclusive = `${init.error.message} Check the address and try again.`;
      return;
    }
    result.reachable = true;
    const { res } = init;
    if (res.status === 401) {
      await checkSignedIn(res, false);
    } else if (res.status >= 200 && res.status < 300) {
      const message = readJsonRpc(res, 1);
      if (message?.result && typeof message.result === "object") {
        await checkOpen(res, message.result, null);
      } else if (message?.error) {
        result.inconclusive = `The server answered initialize with an error: ${message.error.message ?? "no message"}.`;
      } else {
        result.inconclusive = "This address answered, but not with an MCP response. Check the path; many servers use /mcp.";
      }
    } else if ([400, 404, 405].includes(res.status)) {
      await checkLegacy(res.status);
    } else if (res.status === 403) {
      result.inconclusive = "The server refused the request (403 Forbidden) before any sign-in step. A firewall may be blocking automated checks.";
    } else if (res.status >= 300 && res.status < 400) {
      result.inconclusive = `The address redirects (${res.status}) in a way MCP clients can\u2019t follow with a POST. Enter the final address instead.`;
    } else {
      result.inconclusive = `The server answered ${res.status}, so the check couldn\u2019t continue.`;
    }
  }
  function checkResponseHeaders(res) {
    const hsts = res.headers["strict-transport-security"];
    if (hsts && /max-age=\s*"?(\d+)/i.test(hsts)) {
      pass("Sends Strict-Transport-Security, so browsers stay on HTTPS");
    } else {
      add({
        id: "no-hsts",
        severity: "low",
        title: "No Strict-Transport-Security header",
        detail: "Without HSTS, a browser-based client can be downgraded to plain HTTP on a hostile network.",
        fix: "Send Strict-Transport-Security: max-age=31536000 on every HTTPS response."
      });
    }
    if (res.headers["x-powered-by"]) {
      add({
        id: "powered-by",
        severity: "note",
        title: "The server names its framework",
        detail: `It sends X-Powered-By: ${res.headers["x-powered-by"].slice(0, 80)}, which tells attackers what to look up.`,
        fix: "Remove the X-Powered-By header."
      });
    }
  }
  async function checkSignedIn(res, legacy) {
    result.auth = "oauth";
    if (!legacy) result.transport = "streamable-http";
    checkResponseHeaders(res);
    pass("Requires sign-in: a request without a token gets 401 Unauthorized");
    const challenges = parseWwwAuthenticate(res.wwwAuthenticate);
    const bearer = challenges.find((c) => c.scheme.toLowerCase() === "bearer");
    if (res.wwwAuthenticate.length === 0) {
      add({
        id: "no-challenge",
        severity: "medium",
        title: "The 401 has no WWW-Authenticate header",
        detail: "Clients read this header to learn how to sign in. Without it they have to guess the metadata address.",
        fix: 'Answer 401 with WWW-Authenticate: Bearer resource_metadata="https://\u2026/.well-known/oauth-protected-resource".',
        ref: REF.prmDiscovery
      });
    } else if (!bearer) {
      add({
        id: "no-bearer",
        severity: "medium",
        title: "The 401 doesn\u2019t offer Bearer tokens",
        detail: `The challenge offers ${challenges.map((c) => c.scheme).join(", ") || "an unreadable scheme"}, but MCP clients sign in with OAuth Bearer tokens.`,
        fix: "Answer 401 with a Bearer challenge that includes resource_metadata.",
        ref: REF.prmDiscovery
      });
    }
    let metadataUrl = null;
    if (bearer?.params.resource_metadata) {
      metadataUrl = httpsUrl(bearer.params.resource_metadata);
      if (metadataUrl) {
        pass("The 401 points clients to its metadata (resource_metadata)");
      } else {
        add({
          id: "prm-url-invalid",
          severity: "high",
          title: "The metadata address in the 401 isn\u2019t usable",
          detail: `resource_metadata is \u201C${bearer.params.resource_metadata.slice(0, 120)}\u201D, which isn\u2019t an https:// URL.`,
          fix: "Point resource_metadata at the full https:// URL of your protected resource metadata.",
          ref: REF.prmDiscovery
        });
      }
    }
    if (bearer?.params.scope) {
      pass(`The 401 names the scopes it needs (${bearer.params.scope.slice(0, 80)})`);
    } else if (bearer) {
      add({
        id: "no-challenge-scope",
        severity: "note",
        title: "The 401 doesn\u2019t name the scopes it needs",
        detail: "Without a scope in the challenge, clients request every scope in your metadata, which asks users for more than the first request needs.",
        fix: 'Add scope="\u2026" to the Bearer challenge with the minimum scopes for the request.',
        ref: REF.scope
      });
    }
    let prm = metadataUrl ? await getJson("Protected resource metadata", metadataUrl) : null;
    if (!prm) {
      for (const candidate of prmCandidates(target)) {
        prm = await getJson("Protected resource metadata, well-known address", candidate);
        if (prm) break;
      }
      if (prm && metadataUrl) {
        add({
          id: "prm-header-broken",
          severity: "medium",
          title: "The metadata address in the 401 doesn\u2019t work",
          detail: `${metadataUrl.href} didn\u2019t return metadata, though the well-known address did. Clients that follow the header stop there.`,
          fix: "Fix resource_metadata so it points at the document clients can fetch.",
          ref: REF.prmDiscovery
        });
      } else if (prm) {
        add({
          id: "prm-not-in-header",
          severity: "low",
          title: "The 401 doesn\u2019t say where the metadata is",
          detail: `Metadata was found at ${prm.url.href}, but only by probing well-known addresses.`,
          fix: 'Add resource_metadata="\u2026" to the Bearer challenge so clients go straight to it.',
          ref: REF.prmDiscovery
        });
      }
    }
    if (!prm) {
      add({
        id: "no-prm",
        severity: "high",
        title: "No protected resource metadata",
        detail: "Neither the 401 nor the well-known addresses led to an OAuth protected resource metadata document. MCP servers must publish one (RFC 9728), and clients can\u2019t find the sign-in server without it.",
        fix: "Serve /.well-known/oauth-protected-resource with resource and authorization_servers, and point to it from the 401.",
        ref: REF.prmDiscovery
      });
      if (!legacy) await probeTokens(void 0);
      return;
    }
    pass("Publishes protected resource metadata (RFC 9728)");
    const doc = prm.doc;
    const resource = typeof doc.resource === "string" ? doc.resource : "";
    if (!resource) {
      add({
        id: "prm-no-resource",
        severity: "medium",
        title: "The metadata doesn\u2019t name the resource",
        detail: "RFC 9728 requires a resource value, and clients use it as the audience they request tokens for.",
        fix: "Set resource to this server\u2019s canonical URL, such as https://mcp.example.com/mcp.",
        ref: REF.rfc9728
      });
    } else {
      const covers2 = resourceCovers(resource, target);
      if (covers2 === "exact") pass("The metadata\u2019s resource matches this address exactly");
      else if (covers2 === "parent") pass(`The metadata\u2019s resource covers this address (${resource})`);
      else {
        add({
          id: "prm-resource-mismatch",
          severity: "high",
          title: "The metadata names a different resource",
          detail: `The metadata says the resource is ${resource.slice(0, 160)}, but you checked ${target.href}. Clients that validate it, as RFC 9728 requires, refuse to continue, and tokens get issued for the wrong audience.`,
          fix: "Set resource to the exact URL clients use for this server.",
          ref: REF.rfc9728
        });
      }
    }
    if (list(doc.bearer_methods_supported).includes("query")) {
      add({
        id: "token-in-query",
        severity: "medium",
        title: "Tokens are accepted in the URL",
        detail: "bearer_methods_supported includes \u201Cquery\u201D. Tokens in URLs end up in logs, browser history and Referer headers, and MCP forbids them.",
        fix: "Accept tokens only in the Authorization header.",
        ref: REF.tokens
      });
    }
    if (!Array.isArray(doc.scopes_supported)) {
      add({
        id: "prm-no-scopes",
        severity: "note",
        title: "The metadata lists no scopes",
        detail: "Without scopes_supported, clients can\u2019t request narrower access, so every token gets everything.",
        fix: "List the minimum scopes in scopes_supported, and split read and write access.",
        ref: REF.scope
      });
    }
    const challengeOffline = (bearer?.params.scope ?? "").split(/\s+/).includes("offline_access");
    const metadataOffline = list(doc.scopes_supported).includes("offline_access");
    if (challengeOffline || metadataOffline) {
      const where = [metadataOffline && "the metadata\u2019s scopes_supported", challengeOffline && "the 401 challenge"].filter(Boolean);
      add({
        id: "offline-access-scope",
        severity: "low",
        title: "offline_access is listed as a scope this server needs",
        detail: `It appears in ${where.join(" and ")}. offline_access is a request for a refresh token, made between the client and the authorization server, not a permission on this server. MCP servers shouldn\u2019t list it, because it pushes clients to ask users for long-lived access they may not need.`,
        fix: "Remove offline_access from scopes_supported and the 401 challenge. Clients add it themselves when the authorization server offers it.",
        ref: REF.refresh
      });
    }
    const servers = list(doc.authorization_servers);
    if (servers.length === 0) {
      add({
        id: "prm-no-as",
        severity: "high",
        title: "The metadata names no authorization server",
        detail: "MCP requires authorization_servers with at least one entry. Without it, clients don\u2019t know where to sign in.",
        fix: 'Add authorization_servers: ["https://auth.example.com"] to the metadata.',
        ref: REF.prmDiscovery
      });
      if (!legacy) await probeTokens(void 0);
      return;
    }
    const issuerUrl = httpsUrl(servers[0]);
    if (!issuerUrl) {
      add({
        id: "as-not-https",
        severity: "high",
        title: "The authorization server isn\u2019t on HTTPS",
        detail: `The metadata names ${servers[0].slice(0, 120)}. Every authorization server endpoint must use HTTPS.`,
        fix: "Serve the authorization server over HTTPS and list its https:// issuer.",
        ref: REF.auth
      });
      if (!legacy) await probeTokens(void 0);
      return;
    }
    result.issuer = issuerUrl.href;
    let as = null;
    for (const candidate of asCandidates(issuerUrl)) {
      as = await getJson("Authorization server metadata", candidate);
      if (as) break;
    }
    if (!as) {
      add({
        id: "no-as-metadata",
        severity: "high",
        title: "No authorization server metadata",
        detail: `None of the discovery addresses for ${issuerUrl.href} returned metadata. MCP clients must find it through RFC 8414 or OpenID Connect discovery.`,
        fix: "Serve /.well-known/oauth-authorization-server (or /.well-known/openid-configuration) for the issuer.",
        ref: REF.asDiscovery
      });
    } else {
      pass(`Publishes authorization server metadata (${as.url.pathname.includes("openid") ? "OpenID Connect" : "RFC 8414"})`);
      checkAuthorizationServer(as.doc, issuerUrl);
    }
    if (!legacy) await probeTokens(issuerUrl.href);
  }
  function checkAuthorizationServer(doc, issuerUrl) {
    const issuer = typeof doc.issuer === "string" ? doc.issuer : "";
    if (!issuer) {
      add({
        id: "as-no-issuer",
        severity: "medium",
        title: "The authorization server metadata has no issuer",
        detail: "Clients compare issuer with the server they looked up, to defend against mix-up attacks.",
        fix: "Set issuer to the authorization server\u2019s exact URL.",
        ref: REF.rfc8414
      });
    } else if (canonical(issuer) !== canonical(issuerUrl)) {
      add({
        id: "as-issuer-mismatch",
        severity: "medium",
        title: "The issuer doesn\u2019t match",
        detail: `The resource metadata names ${issuerUrl.href}, but the authorization server calls itself ${issuer.slice(0, 160)}. RFC 8414 requires these to be identical, and strict clients stop here.`,
        fix: "Use the same issuer URL in both documents.",
        ref: REF.rfc8414
      });
    } else {
      pass("The issuer matches the resource metadata");
    }
    for (const field of ["authorization_endpoint", "token_endpoint"]) {
      if (typeof doc[field] !== "string") {
        add({
          id: `as-no-${field}`,
          severity: "high",
          title: `No ${field}`,
          detail: `The authorization server metadata has no ${field}, so clients can\u2019t complete sign-in.`,
          fix: `Add ${field} to the metadata.`,
          ref: REF.asDiscovery
        });
      } else if (!httpsUrl(doc[field])) {
        add({
          id: `as-${field}-not-https`,
          severity: "high",
          title: `The ${field.replace("_", " ")} isn\u2019t on HTTPS`,
          detail: `${String(doc[field]).slice(0, 160)} would send codes or tokens unencrypted.`,
          fix: "Serve every authorization server endpoint over HTTPS.",
          ref: REF.auth
        });
      }
    }
    const pkce = doc.code_challenge_methods_supported;
    if (!Array.isArray(pkce)) {
      add({
        id: "no-pkce",
        severity: "high",
        title: "PKCE support isn\u2019t advertised",
        detail: "The metadata has no code_challenge_methods_supported. MCP clients must refuse to continue without it, so sign-in fails in compliant clients.",
        fix: 'Support PKCE and add "code_challenge_methods_supported": ["S256"] to the metadata.',
        ref: REF.pkce
      });
    } else if (!pkce.includes("S256")) {
      add({
        id: "no-s256",
        severity: "high",
        title: "PKCE S256 isn\u2019t supported",
        detail: `The metadata lists ${pkce.join(", ") || "no methods"}. MCP clients must use S256.`,
        fix: "Support the S256 code challenge method and list it in code_challenge_methods_supported.",
        ref: REF.pkce
      });
    } else {
      pass("Supports PKCE with S256");
      if (pkce.includes("plain")) {
        add({
          id: "pkce-plain",
          severity: "low",
          title: "PKCE \u201Cplain\u201D is still allowed",
          detail: "With plain, the verifier travels in the authorization request, so an intercepted request gives it away.",
          fix: "Accept S256 only.",
          ref: REF.oauth21
        });
      }
    }
    const grants = list(doc.grant_types_supported);
    const implicit = grants.includes("implicit") || list(doc.response_types_supported).some((t) => t.split(" ").includes("token"));
    const password = grants.includes("password");
    if (implicit || password) {
      const what = [implicit && "the implicit flow", password && "the password grant"].filter(Boolean);
      add({
        id: "legacy-grants",
        severity: "medium",
        title: "Flows removed from OAuth 2.1 are still on",
        detail: `The metadata allows ${what.join(" and ")}. OAuth 2.1 removes ${what.length > 1 ? "both" : "it"}: implicit tokens leak through URLs, and password grants hand the client the user\u2019s password.`,
        fix: "Allow only the authorization code flow with PKCE, plus refresh tokens.",
        ref: REF.oauth21
      });
    }
    if (doc.authorization_response_iss_parameter_supported === true) {
      pass("Advertises iss on authorization responses (RFC 9207), which lets clients catch mix-up attacks");
    } else {
      add({
        id: "as-no-iss",
        severity: "note",
        title: "The authorization server doesn\u2019t advertise iss",
        detail: "Authorization servers should add iss to their authorization responses (RFC 9207) and say so in their metadata. Clients compare it with the server they chose, which catches a code sent by the wrong server. The specification expects to make this a requirement.",
        fix: "Send iss on authorization responses, and set authorization_response_iss_parameter_supported to true.",
        ref: REF.iss
      });
    }
    const cimd = doc.client_id_metadata_document_supported === true;
    const registration = doc.registration_endpoint;
    if (cimd) pass("Supports Client ID Metadata Documents, the registration method MCP now prefers");
    if (typeof registration === "string") {
      if (!httpsUrl(registration)) {
        add({
          id: "dcr-not-https",
          severity: "high",
          title: "The registration endpoint isn\u2019t on HTTPS",
          detail: `${registration.slice(0, 160)} would return client credentials unencrypted.`,
          fix: "Serve dynamic client registration over HTTPS.",
          ref: REF.auth
        });
      } else {
        pass("Supports dynamic client registration (RFC 7591), which is deprecated but helps older clients");
      }
    }
    if (!cimd && typeof registration === "string") {
      add({
        id: "no-cimd",
        severity: "note",
        title: "No Client ID Metadata Documents",
        detail: "The 2026-07-28 specification deprecates dynamic client registration in favour of Client ID Metadata Documents: clients identify themselves by an HTTPS URL instead of creating a new client each time.",
        fix: "Add client_id_metadata_document_supported: true once your authorization server accepts URL client IDs.",
        ref: REF.registration
      });
    }
    if (!cimd && typeof registration !== "string") {
      add({
        id: "no-registration",
        severity: "medium",
        title: "Clients can\u2019t register themselves",
        detail: "The metadata offers neither Client ID Metadata Documents nor dynamic client registration, so every user has to create an OAuth client by hand before connecting.",
        fix: "Support Client ID Metadata Documents. Add dynamic client registration only if older clients need it.",
        ref: REF.registration
      });
    }
    if (typeof doc.revocation_endpoint !== "string") {
      add({
        id: "no-revocation",
        severity: "note",
        title: "No token revocation endpoint",
        detail: "Clients can\u2019t revoke tokens when a user disconnects, so tokens stay valid until they expire.",
        fix: "Add a revocation_endpoint (RFC 7009), and keep access tokens short-lived.",
        ref: REF.oauth21
      });
    }
  }
  async function probeTokens(issuer) {
    const probes = [
      { id: "accepts-invalid-token", label: "A request with a made-up token", token: "nestedbit-mcp-check-not-a-real-token", what: "a made-up token" },
      { id: "accepts-unsigned-token", label: "A request with an unsigned token", token: unsignedToken(issuer, target.href), what: "an unsigned token (alg \u201Cnone\u201D)" }
    ];
    for (const probe of probes) {
      const authorization = { authorization: `Bearer ${probe.token}` };
      let out = await call(probe.label, target, modernRequest(1, gatedMethod, version, {}, authorization));
      if ("error" in out || out.res.status !== 401 && !readJsonRpc(out.res, 1)?.result) {
        out = await call(`${probe.label}, as older MCP versions start`, target, initializeRequest(1, authorization));
      }
      if ("error" in out) continue;
      const { res } = out;
      if (res.status === 401) {
        pass(`Rejects ${probe.what} with 401`);
      } else if (res.status >= 200 && res.status < 300 && readJsonRpc(res, 1)?.result) {
        add({
          id: probe.id,
          severity: "high",
          title: `Accepts ${probe.what}`,
          detail: `The server answered a request carrying ${probe.what}. It checks that a token is present, not that it\u2019s valid, so anyone can call it.`,
          fix: "Validate every token: signature, issuer, expiry, and that its audience is this server.",
          ref: REF.tokens
        });
      } else if (res.status >= 400 && res.status < 500 && !result.findings.some((f) => f.id === "invalid-token-status")) {
        add({
          id: "invalid-token-status",
          severity: "low",
          title: `Answers ${probe.what} with ${res.status}, not 401`,
          detail: "MCP servers must answer invalid or expired tokens with 401 and a WWW-Authenticate challenge, so clients know to sign in again.",
          fix: "Return 401 with a Bearer challenge for any token that fails validation.",
          ref: REF.tokens
        });
      }
    }
  }
  async function checkOpen(res, init, modern) {
    result.transport = "streamable-http";
    const meta = init._meta ?? {};
    const info = (modern ? meta["io.modelcontextprotocol/serverInfo"] : init.serverInfo) ?? {};
    const negotiated = modern ?? (typeof init.protocolVersion === "string" ? init.protocolVersion : INITIALIZE_VERSION);
    result.server = {
      name: typeof info.name === "string" ? info.name.slice(0, 120) : void 0,
      version: typeof info.version === "string" ? info.version.slice(0, 40) : void 0,
      protocolVersion: negotiated
    };
    pass("Uses Streamable HTTP, the current MCP transport");
    if (modern) {
      pass(`Speaks the current MCP version (${modern}), which has no sessions to protect`);
    } else {
      add({
        id: "legacy-protocol",
        severity: "note",
        title: "Speaks an older MCP version",
        detail: `It answered initialize as version ${negotiated.slice(0, 20)} but not server/discover, so it doesn\u2019t speak ${CURRENT_VERSION}. Clients that know both versions can still connect, but the older one keeps sessions, which your server has to protect.`,
        fix: "Update your MCP SDK. The current TypeScript SDK, Python SDK and FastMCP serve both versions.",
        ref: REF.versions
      });
    }
    const session = modern ? void 0 : res.headers["mcp-session-id"];
    if (session) {
      if (!/^[\x21-\x7e]+$/.test(session)) {
        add({
          id: "session-chars",
          severity: "low",
          title: "The session ID has invalid characters",
          detail: "Session IDs must contain only visible ASCII characters.",
          fix: "Use a random UUID or a long random string.",
          ref: REF.sessions
        });
      } else if (session.length < 16 || /^\d+$/.test(session)) {
        add({
          id: "session-guessable",
          severity: "medium",
          title: "Session IDs look guessable",
          detail: `The session ID \u201C${session.slice(0, 40)}\u201D is short or numeric. Guessable session IDs let an attacker inject messages into someone else\u2019s session.`,
          fix: "Generate session IDs with a secure random source (a UUID v4 or 128 random bits), and never use them as authentication.",
          ref: REF.sessions
        });
      } else {
        pass("Session IDs look random");
      }
    }
    const headers = (extra = {}) => mcpHeaders({ "mcp-protocol-version": negotiated, ...session ? { "mcp-session-id": session } : {}, ...extra });
    const listRequest = (id, params) => modern ? modernRequest(id, "tools/list", modern, params) : { method: "POST", headers: headers(), body: JSON.stringify({ jsonrpc: "2.0", id, method: "tools/list", params }), until: sseHas(id) };
    if (!modern) {
      await call("Initialized notification", target, {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })
      });
    }
    const capabilities = init.capabilities ?? {};
    if (capabilities.tools) {
      const tools = [];
      let cursor;
      for (let page = 0; page < 3; page++) {
        const id = 2 + page;
        const out = await call(page ? `List tools, page ${page + 1}` : "List tools", target, {
          ...listRequest(id, cursor ? { cursor } : {}),
          maxBytes: 1024 * 1024
        });
        if (modern && page === 0 && "res" in out && out.res.status === 401) {
          gatedMethod = "tools/list";
          await checkSignedIn(out.res, false);
          return;
        }
        const message = "res" in out ? readJsonRpc(out.res, id) : null;
        const pageTools = message?.result?.tools;
        if (!Array.isArray(pageTools)) {
          if (page === 0) result.toolsNote = "The server didn\u2019t return its tool list. Paste the output of tools/list below to review the tools.";
          break;
        }
        tools.push(...pageTools.slice(0, MAX_TOOLS - tools.length).map(trimTool));
        cursor = typeof message?.result?.nextCursor === "string" ? message.result.nextCursor : void 0;
        if (!cursor || tools.length >= MAX_TOOLS) break;
      }
      if (!result.toolsNote) result.tools = tools;
    } else {
      result.tools = [];
      result.toolsNote = "The server doesn\u2019t offer any tools.";
    }
    result.auth = "open";
    checkResponseHeaders(res);
    const origin = { origin: "https://evil.example" };
    const probe = await call("A request from a foreign web page", target, {
      ...modern ? modernRequest(9, "server/discover", modern, {}, origin) : initializeRequest(9, origin),
      timeoutMs: 5e3
    });
    if ("res" in probe) {
      const { res: p } = probe;
      if (p.status === 403) {
        pass("Refuses requests from unknown web origins (403)");
      } else if (p.status >= 200 && p.status < 300) {
        add({
          id: "no-origin-check",
          severity: "low",
          title: "Requests from any web page are accepted",
          detail: "A request with Origin: https://evil.example was served. MCP servers must check the Origin header and answer unknown origins with 403; for servers people run on their own machines, this is what stops DNS rebinding attacks.",
          fix: "Allow only the origins of web clients you support, and answer the rest with 403.",
          ref: REF.origin
        });
        if (p.headers["access-control-allow-origin"] === "https://evil.example" && p.headers["access-control-allow-credentials"] === "true") {
          add({
            id: "cors-reflect",
            severity: "medium",
            title: "CORS trusts every origin, with credentials",
            detail: "The server reflects any Origin in Access-Control-Allow-Origin and allows credentials, so any web page can read its responses with the visitor\u2019s cookies.",
            fix: "Return Access-Control-Allow-Origin only for an allowlist of origins."
          });
        }
      }
      const extra = modern ? void 0 : p.headers["mcp-session-id"];
      if (extra) await call("End the extra session", target, { method: "DELETE", headers: mcpHeaders({ "mcp-session-id": extra, "mcp-protocol-version": negotiated }) });
    }
    if (session) await call("End the session", target, { method: "DELETE", headers: headers() });
  }
  async function checkLegacy(postStatus) {
    const out = await call("Look for the older HTTP+SSE transport", target, {
      method: "GET",
      headers: { accept: "text/event-stream" },
      timeoutMs: 5e3,
      maxBytes: 16 * 1024,
      until: (body) => /event:\s*endpoint/.test(body)
    });
    if ("error" in out) {
      result.inconclusive = `POST returned ${postStatus} and GET failed, so this doesn\u2019t look like an MCP endpoint. Check the path; many servers use /mcp.`;
      return;
    }
    const { res } = out;
    const legacyNote = {
      id: "legacy-sse",
      severity: "low",
      title: "Uses the deprecated HTTP+SSE transport",
      detail: "This server speaks the 2024-11-05 HTTP+SSE transport, which the specification lists as deprecated. Streamable HTTP replaced it, and newer clients may drop support for it.",
      fix: "Add a Streamable HTTP endpoint (one URL that accepts POST) and keep the old one only while clients migrate.",
      ref: REF.legacy
    };
    if (res.status === 200 && /event:\s*endpoint/.test(res.body)) {
      result.transport = "sse";
      result.auth = "open";
      checkResponseHeaders(res);
      add(legacyNote);
      result.toolsNote = "This checker lists tools over Streamable HTTP only. Paste the output of tools/list below to review them.";
    } else if (res.status === 401) {
      result.transport = "sse";
      add(legacyNote);
      await checkSignedIn(res, true);
    } else {
      result.inconclusive = `POST returned ${postStatus} and GET returned ${res.status}, so this doesn\u2019t look like an MCP endpoint. Check the path; many servers use /mcp.`;
    }
  }
}
function trimTool(tool) {
  if (!tool || typeof tool !== "object") return null;
  const t = tool;
  const schema = JSON.stringify(t.inputSchema ?? null);
  return {
    name: typeof t.name === "string" ? t.name.slice(0, 200) : "",
    title: typeof t.title === "string" ? t.title.slice(0, 200) : void 0,
    description: typeof t.description === "string" ? t.description.slice(0, 8e3) : void 0,
    inputSchema: schema.length <= 32e3 ? t.inputSchema : { type: "object", truncated: true },
    annotations: trimAnnotations(t.annotations)
  };
}
var HINTS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"];
function trimAnnotations(value) {
  if (!value || typeof value !== "object") return void 0;
  const a = value;
  const out = {};
  for (const key2 of HINTS) if (typeof a[key2] === "boolean") out[key2] = a[key2];
  if (typeof a.title === "string") out.title = a.title.slice(0, 200);
  return Object.keys(out).length > 0 ? out : void 0;
}

// engine/review.ts
var EXECUTE = /* @__PURE__ */ new Set(["exec", "execute", "shell", "bash", "sh", "cmd", "eval", "terminal", "spawn", "powershell", "sudo", "subprocess"]);
var RUNNABLE = /* @__PURE__ */ new Set(["code", "script", "command", "query", "sql", "python", "javascript", "js", "shell"]);
var DELETE = /* @__PURE__ */ new Set(["delete", "remove", "destroy", "drop", "purge", "erase", "wipe", "truncate", "revoke", "terminate", "kill", "rm", "unlink", "uninstall", "reset"]);
var WRITE = /* @__PURE__ */ new Set([
  "create",
  "add",
  "update",
  "edit",
  "set",
  "write",
  "put",
  "post",
  "send",
  "publish",
  "insert",
  "upsert",
  "patch",
  "modify",
  "move",
  "rename",
  "upload",
  "assign",
  "approve",
  "merge",
  "deploy",
  "transfer",
  "pay",
  "charge",
  "refund",
  "invite",
  "comment",
  "reply",
  "schedule",
  "book",
  "submit",
  "save",
  "push",
  "commit",
  "close",
  "enable",
  "disable",
  "start",
  "stop",
  "restart",
  "trigger",
  "import",
  "sync",
  "apply",
  "mark",
  "toggle",
  "cancel",
  "archive",
  "unarchive",
  "share",
  "grant",
  "register",
  "subscribe",
  "unsubscribe",
  "order",
  "buy",
  "purchase",
  "email",
  "message",
  "notify",
  "label",
  "tag",
  "attach",
  "copy",
  "clone",
  "invoke",
  "call",
  "mutate",
  "change",
  "replace",
  "append",
  "run",
  "install",
  "configure",
  "reopen",
  "lock",
  "unlock"
]);
var READ = /* @__PURE__ */ new Set([
  "get",
  "list",
  "read",
  "search",
  "find",
  "fetch",
  "query",
  "describe",
  "show",
  "view",
  "lookup",
  "retrieve",
  "count",
  "check",
  "status",
  "download",
  "export",
  "resolve",
  "browse",
  "explain",
  "summarize",
  "ask",
  "inspect",
  "analyze",
  "info",
  "preview",
  "validate",
  "compare",
  "diff",
  "history",
  "logs",
  "whoami",
  "me",
  "ping",
  "docs",
  "documentation"
]);
var URL_KEY = /^(url|uri|href|link|endpoint|webhook|callback|target|address|[a-z]+_?(url|uri))$/i;
var PATH_KEY = /^(path|file|filename|file_?path|dir|directory|folder|[a-z]+_?path)$/i;
var CODE_KEY = /^(sql|statement|command|cmd|script|code|shell|expression|eval|program)$/i;
var INSTRUCTION_TEXT = [
  /ignore (all |any )?(previous|prior|above|earlier) (instructions|messages|prompts)/i,
  /(do not|don['’]t|never) (tell|mention|inform|reveal|show|let)( this)?( to)? the user/i,
  /<\s{0,8}\/?\s{0,8}(important|system|instructions?|secret)\s{0,8}>/i,
  /without (asking|telling|informing) the user/i,
  /(you|the assistant|the model) must (always )?(first )?(read|send|include|pass|upload)/i
];
var SECRET_TEXT = /(~\/\.ssh|id_rsa|id_ed25519|\.env\b|\.aws\/credentials|\.npmrc|\.netrc|mcp\.json|private key|ssh key|api[_ -]?keys?|passwords?\b|access tokens?)/i;
var HIDDEN_CHARS = /[​-‏‪-‮⁠-⁤﻿]|[\u{E0000}-\u{E007F}]/u;
var VALID_NAME = /^[A-Za-z0-9_.-]{1,128}$/;
function nameWords(name) {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").split(/[^A-Za-z0-9]+/).filter(Boolean).map((w) => w.toLowerCase());
}
function schemaProperties(schema) {
  if (!schema || typeof schema !== "object") return {};
  const props = schema.properties;
  return props && typeof props === "object" ? props : {};
}
function isOpenString(prop) {
  const type = prop.type;
  const stringy = type === void 0 || type === "string" || Array.isArray(type) && type.includes("string");
  return stringy && prop.enum === void 0 && prop.const === void 0 && prop.pattern === void 0;
}
function kindFromWords(words) {
  const has = (set) => words.find((w) => set.has(w));
  const exec = has(EXECUTE) ?? (words.includes("run") && words.some((w) => RUNNABLE.has(w)) ? "run" : void 0);
  if (exec) return { kind: "execute", word: exec };
  if (words.includes("sql") && !words.some((w) => ["list", "describe", "schema", "schemas", "table", "tables"].includes(w))) {
    return { kind: "execute", word: "sql" };
  }
  const first = words[0];
  if (first && DELETE.has(first)) return { kind: "delete", word: first };
  if (first && WRITE.has(first)) return { kind: "write", word: first };
  if (first && READ.has(first)) return { kind: "read", word: first };
  const del = has(DELETE);
  if (del) return { kind: "delete", word: del };
  const write = has(WRITE);
  if (write) return { kind: "write", word: write };
  const read = has(READ);
  if (read) return { kind: "read", word: read };
  return null;
}
function kindFromDescription(description) {
  const start = description.trim().toLowerCase().slice(0, 60);
  if (/^(deletes?|removes?|destroys?|drops?|purges?|revokes?)\b/.test(start)) return "delete";
  if (/^(creates?|updates?|sends?|adds?|writes?|posts?|sets?|edits?|uploads?|publishes?|moves?|renames?|schedules?|modif(y|ies))\b/.test(start)) return "write";
  if (/^(retrieves?|gets?|lists?|returns?|fetch(es)?|search(es)?|reads?|finds?|looks? up|shows?|describes?|quer(y|ies)|provides?|answers?)\b/.test(start)) return "read";
  return null;
}
function scopePrefix(name, host) {
  const fromName = (name ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  if (fromName && fromName.length <= 24) return fromName;
  const labels = (host ?? "").toLowerCase().split(".").filter((l) => l && !["mcp", "www", "api", "app", "remote"].includes(l));
  return labels[0] ?? "mcp";
}
function verb(list2, one, many) {
  return list2.length === 1 ? one : many;
}
function names(list2) {
  const shown = list2.slice(0, 6).join(", ");
  return list2.length > 6 ? `${shown} and ${list2.length - 6} more` : shown;
}
function reviewTools(tools, prefix = "mcp") {
  const rows = [];
  const groups = {};
  const flag = (id, tool) => (groups[id] ??= []).push(tool);
  for (const tool of tools) {
    const name = tool.name;
    const hints = tool.annotations ?? {};
    const description = tool.description ?? "";
    const props = schemaProperties(tool.inputSchema);
    const keys = Object.keys(props);
    let match = kindFromWords(nameWords(name));
    const codeKey = keys.find((k) => CODE_KEY.test(k) && isOpenString(props[k]));
    if (codeKey && match?.kind !== "execute") match = { kind: "execute", word: `${codeKey} parameter` };
    let kind;
    let why;
    if (match) {
      kind = match.kind;
      why = match.word.includes("parameter") ? `Takes a ${match.word}` : `Name says \u201C${match.word}\u201D`;
    } else if (hints.readOnlyHint === true) {
      kind = "read";
      why = "Marked read-only";
    } else {
      const fromDescription = kindFromDescription(description);
      kind = fromDescription ?? "write";
      why = fromDescription ? "From its description" : "Unclear, so treated as a change";
    }
    if (match && hints.readOnlyHint === true && kind !== "read") flag("misleading-readonly", name);
    if (match && hints.destructiveHint === false && (kind === "delete" || kind === "execute")) flag("misleading-destructive", name);
    if (kind === "execute") flag("execute", name);
    if (kind === "delete") flag("delete", name);
    if (keys.some((k) => URL_KEY.test(k) && isOpenString(props[k]))) flag("url-param", name);
    if (keys.some((k) => PATH_KEY.test(k) && isOpenString(props[k]))) flag("path-param", name);
    const text = `${tool.title ?? ""}
${description}`;
    if (HIDDEN_CHARS.test(`${name}${text}`)) flag("hidden-chars", name);
    if (INSTRUCTION_TEXT.some((re) => re.test(text))) flag("injection-text", name);
    else if (SECRET_TEXT.test(text)) flag("secret-mention", name);
    if (description.length > 2e3) flag("long-description", name);
    if (!tool.annotations) flag("no-annotations", name);
    if (!tool.inputSchema || tool.inputSchema.type !== "object") flag("no-schema", name);
    if (!VALID_NAME.test(name)) flag("bad-name", name);
    const scope = { read: "read", write: "write", delete: "delete", execute: "admin" }[kind];
    rows.push({
      name,
      kind,
      scope: `${prefix}:${scope}`,
      confirm: kind === "read" ? "No" : kind === "write" ? "First use" : "Every call",
      why
    });
  }
  const findings = [];
  const g = (id) => groups[id] ?? [];
  if (g("hidden-chars").length) {
    findings.push({
      id: "hidden-chars",
      severity: "high",
      title: "Hidden characters in tool text",
      detail: `${names(g("hidden-chars"))}: zero-width or invisible tag characters hide text from people reviewing the tool, while the model still reads it.`,
      fix: "Strip invisible characters from names and descriptions, and find out how they got there."
    });
  }
  if (g("injection-text").length) {
    findings.push({
      id: "injection-text",
      severity: "high",
      title: "Descriptions give the AI instructions",
      detail: `${names(g("injection-text"))}: tool descriptions go straight into the model\u2019s context. Text that tells it to hide things from the user or ignore earlier instructions is how tool poisoning works, whoever added it.`,
      fix: "Describe what the tool does and what its inputs mean, nothing else."
    });
  }
  if (g("misleading-readonly").length) {
    findings.push({
      id: "misleading-readonly",
      severity: "high",
      title: "Marked read-only, but they change things",
      detail: `${names(g("misleading-readonly"))} ${verb(g("misleading-readonly"), "has", "have")} readOnlyHint: true, yet ${verb(g("misleading-readonly"), "its name says it changes", "their names say they change")} data. Clients may run read-only tools without asking the user.`,
      fix: "Set readOnlyHint: false on any tool that changes data, and destructiveHint: true on any that deletes."
    });
  }
  if (g("misleading-destructive").length) {
    findings.push({
      id: "misleading-destructive",
      severity: "high",
      title: "Marked safe, but they delete or run code",
      detail: `${names(g("misleading-destructive"))} ${verb(g("misleading-destructive"), "has", "have")} destructiveHint: false. Clients use that hint to decide whether to confirm with the user first.`,
      fix: "Set destructiveHint: true on any tool that deletes or runs code."
    });
  }
  if (g("execute").length) {
    findings.push({
      id: "execute",
      severity: "high",
      title: "Tools that run commands or code",
      detail: `${names(g("execute"))}. If the agent is tricked by text it reads, such as a web page, an email or a ticket, these tools run whatever it was told to. Treat them as administrator access.`,
      fix: "Run them in a sandbox without secrets or internal network access, allow only listed commands or read-only queries, ask the user before every call, and put them behind their own scope."
    });
  }
  if (g("delete").length) {
    findings.push({
      id: "delete",
      severity: "medium",
      title: "Tools that delete or revoke",
      detail: `${names(g("delete"))}. One mistaken or manipulated call removes data for good.`,
      fix: "Mark them destructiveHint: true, ask the user before every call, keep a way to undo (soft delete or a trash), and give them a separate scope."
    });
  }
  if (g("url-param").length) {
    findings.push({
      id: "url-param",
      severity: "medium",
      title: "Tools that fetch any URL",
      detail: `${names(g("url-param"))} ${verb(g("url-param"), "takes", "take")} a free-form URL. Without limits, the server can be made to call internal addresses or cloud metadata endpoints (server-side request forgery), from inside your network.`,
      fix: "Allow only the hosts the tool needs, resolve the name and refuse private and link-local addresses, and don\u2019t follow redirects to them."
    });
  }
  if (g("path-param").length) {
    findings.push({
      id: "path-param",
      severity: "medium",
      title: "Tools that take a file path",
      detail: `${names(g("path-param"))} ${verb(g("path-param"), "takes", "take")} a free-form path. Paths like ../../.ssh/id_rsa reach files outside the folder you meant to share.`,
      fix: "Resolve every path against one root folder, then refuse anything that ends up outside it, including through symbolic links."
    });
  }
  if (g("secret-mention").length) {
    findings.push({
      id: "secret-mention",
      severity: "medium",
      title: "Descriptions mention secrets or credential files",
      detail: `${names(g("secret-mention"))}: descriptions that talk about keys, passwords or files like ~/.ssh steer the model towards handling secrets.`,
      fix: "Keep secrets out of tool descriptions and tool inputs. Read credentials on the server, from its own configuration."
    });
  }
  if (g("no-annotations").length) {
    findings.push({
      id: "no-annotations",
      severity: "low",
      title: `${g("no-annotations").length} of ${tools.length} tools ${verb(g("no-annotations"), "has", "have")} no annotations`,
      detail: `${names(g("no-annotations"))}. Without hints, clients must treat every tool as one that can change and delete data, so users get asked about everything and stop reading the prompts.`,
      fix: "Add readOnlyHint, destructiveHint, idempotentHint and openWorldHint to each tool."
    });
  }
  if (g("no-schema").length) {
    findings.push({
      id: "no-schema",
      severity: "low",
      title: "Tools without an input schema",
      detail: `${names(g("no-schema"))}. Without a schema, nothing limits what the model sends.`,
      fix: "Give every tool an object inputSchema with types, required fields and limits, and validate inputs against it."
    });
  }
  if (tools.length > 40) {
    findings.push({
      id: "many-tools",
      severity: "note",
      title: `${tools.length} tools in one server`,
      detail: "Long tool lists fill the model\u2019s context and make it pick the wrong tool more often.",
      fix: "Split tools by job into separate servers, or expose fewer by default."
    });
  }
  if (g("long-description").length) {
    findings.push({
      id: "long-description",
      severity: "note",
      title: "Very long descriptions",
      detail: `${names(g("long-description"))} ${verb(g("long-description"), "has a description", "have descriptions")} over 2,000 characters, which few people read in full before approving a server.`,
      fix: "Keep descriptions short and move detail into documentation."
    });
  }
  if (g("bad-name").length) {
    findings.push({
      id: "bad-name",
      severity: "note",
      title: "Tool names with unusual characters",
      detail: `${names(g("bad-name"))}. Tool names should use only letters, digits, underscores, hyphens and dots.`,
      fix: "Rename them to plain names such as list_files."
    });
  }
  return { rows, findings };
}
function parseToolList(text) {
  let source = text.trim();
  if (!source) throw new Error("Paste the JSON your server returns for tools/list.");
  if (/^(event|data|id):/m.test(source) && !source.startsWith("{") && !source.startsWith("[")) {
    source = source.split(/\r?\n/).filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trim()).join("\n");
  }
  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new Error("That isn\u2019t valid JSON. Paste the whole response from tools/list.");
  }
  const candidates = Array.isArray(parsed) ? parsed : [parsed];
  let list2 = null;
  for (const c of candidates) {
    if (c && typeof c === "object") {
      const o = c;
      if (Array.isArray(o.tools)) list2 = o.tools;
      else if (Array.isArray(o.result?.tools)) list2 = o.result.tools;
    }
    if (list2) break;
  }
  if (!list2 && Array.isArray(parsed) && parsed.every((t) => t && typeof t === "object" && "name" in t)) list2 = parsed;
  if (!Array.isArray(list2)) throw new Error('No tools found. Paste the result of tools/list, which has a "tools" array.');
  const tools = list2.filter((t) => !!t && typeof t === "object" && typeof t.name === "string");
  if (tools.length === 0) throw new Error("The tools array is empty, or its tools have no names.");
  return tools.slice(0, 500);
}

// engine/report.ts
var ORDER = ["high", "medium", "low", "note"];
function usableTools(tools) {
  return (tools ?? []).filter((t) => !!t && typeof t.name === "string");
}
function reviewListedTools(tools, result) {
  if (tools.length === 0) return null;
  return reviewTools(tools, scopePrefix(result?.server?.name, result ? new URL(result.target).hostname : void 0));
}
function combineFindings(result, review) {
  const findings = [...result?.findings ?? []];
  if (result?.auth === "open") {
    const risky = review?.rows.filter((r) => r.kind !== "read") ?? [];
    const known = Boolean(review);
    findings.push({
      id: "open-access",
      severity: !known ? "medium" : risky.length > 0 ? "high" : "note",
      title: "Anyone can use this server without signing in",
      detail: !known ? "The server answered without asking for a token. That suits public, read-only data, but nothing else." : risky.length > 0 ? `It answered without a token, and ${risky.length} of its tools change data, delete it or run code (${risky.slice(0, 4).map((r) => r.name).join(", ")}${risky.length > 4 ? "\u2026" : ""}). Anyone who finds the address can call them.` : "It answered without a token. All its tools look read-only, which suits public data, as long as nothing it returns is private.",
      fix: risky.length > 0 || !known ? "Require OAuth sign-in (protected resource metadata, a 401 challenge and audience-checked tokens), or remove the tools that change data." : void 0,
      ref: "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization"
    });
  }
  findings.push(...review?.findings ?? []);
  return findings.sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
}

// src/rls.ts
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

// engine/shared/supabase-rls.ts
var RESERVED = new Set(
  `all analyse analyze and any array as asc asymmetric authorization binary both case cast check collate collation
  column concurrently constraint create cross current_catalog current_date current_role current_schema current_time
  current_timestamp current_user default deferrable desc distinct do else end except false fetch for foreign freeze
  from full grant group having ilike in initially inner intersect into is isnull join lateral leading left like limit
  localtime localtimestamp natural not notnull null offset on only or order outer overlaps placing primary references
  returning right select session_user similar some symmetric system_user table tablesample then to trailing true union
  unique user using variadic verbose when where window with`.split(/\s+/)
);
function identifier(name) {
  return /^[a-z_][a-z0-9_]*$/.test(name) && !RESERVED.has(name) ? name : `"${name.replace(/"/g, '""')}"`;
}
var comment = (text) => text.replace(/[\u0000-\u001f\u007f\u0085\u2028\u2029]+/g, " ").trim();
var utf8Length = (text) => new TextEncoder().encode(text).length;
function hash8(text) {
  let h = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}
function pgName(base, suffix = "") {
  if (utf8Length(base + suffix) <= 63) return base + suffix;
  const tag = `_${hash8(base)}`;
  let cut = base;
  while (cut.length > 0 && utf8Length(cut + tag + suffix) > 63) cut = cut.slice(0, -1);
  return cut + tag + suffix;
}

// engine/shared/supabase-lint.ts
var OP_CHARS = new Set("+-*/<>=~!@#%^&|`?");
var OP_SIGN_KEEPERS = new Set("~!@#%^&|`?");
function operatorAt(sql, i) {
  let end = i;
  while (end < sql.length && OP_CHARS.has(sql[end])) end += 1;
  let text = sql.slice(i, end);
  const cut = text.search(/--|\/\*/);
  if (cut > 0) text = text.slice(0, cut);
  if (text.length > 1 && /[+-]$/.test(text) && ![...text].some((c) => OP_SIGN_KEEPERS.has(c))) {
    text = text.replace(/[+-]+$/, "") || text[0];
  }
  return text;
}
var foldName = (text) => text.replace(/[A-Z]+/g, (c) => c.toLowerCase());
function tokenize(sql) {
  const out = [];
  let i = 0;
  let line = 1;
  const n = sql.length;
  let lineStart = true;
  let start = 0;
  const push = (kind, text, value, at) => out.push({ kind, text, value, line: at, offset: start });
  const count2 = (text) => {
    for (const ch of text) if (ch === "\n") line += 1;
  };
  while (i < n) {
    const ch = sql[i];
    if (ch === "\n") {
      line += 1;
      i += 1;
      lineStart = true;
      continue;
    }
    if (ch === " " || ch === "	" || ch === "\r" || ch === "\f") {
      i += 1;
      continue;
    }
    if (ch === "\\" && lineStart) {
      while (i < n && sql[i] !== "\n") i += 1;
      continue;
    }
    lineStart = false;
    if (ch === "-" && sql[i + 1] === "-") {
      while (i < n && sql[i] !== "\n") i += 1;
      continue;
    }
    if (ch === "/" && sql[i + 1] === "*") {
      let depth = 0;
      while (i < n) {
        if (sql[i] === "/" && sql[i + 1] === "*") {
          depth += 1;
          i += 2;
        } else if (sql[i] === "*" && sql[i + 1] === "/") {
          depth -= 1;
          i += 2;
          if (depth === 0) break;
        } else {
          if (sql[i] === "\n") line += 1;
          i += 1;
        }
      }
      continue;
    }
    start = i;
    const at = line;
    if ((ch === "E" || ch === "e") && sql[i + 1] === "'") {
      i += 2;
      let value = "";
      while (i < n) {
        if (sql[i] === "\\" && i + 1 < n) {
          value += sql[i + 1];
          i += 2;
        } else if (sql[i] === "'" && sql[i + 1] === "'") {
          value += "'";
          i += 2;
        } else if (sql[i] === "'") {
          i += 1;
          break;
        } else {
          value += sql[i];
          i += 1;
        }
      }
      const text2 = sql.slice(start, i);
      count2(text2);
      push("string", text2, value, at);
      continue;
    }
    if (ch === "'") {
      i += 1;
      let value = "";
      while (i < n) {
        if (sql[i] === "'" && sql[i + 1] === "'") {
          value += "'";
          i += 2;
        } else if (sql[i] === "'") {
          i += 1;
          break;
        } else {
          value += sql[i];
          i += 1;
        }
      }
      const text2 = sql.slice(start, i);
      count2(text2);
      push("string", text2, value, at);
      continue;
    }
    if (ch === "$") {
      const tag = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i, i + 64));
      if (tag) {
        const end = sql.indexOf(tag[0], i + tag[0].length);
        const stop = end === -1 ? n : end + tag[0].length;
        const text2 = sql.slice(i, stop);
        const value = sql.slice(i + tag[0].length, end === -1 ? n : end);
        i = stop;
        count2(text2);
        push("string", text2, value, at);
        continue;
      }
      const param = /^\$\d+/.exec(sql.slice(i, i + 12));
      if (param) {
        i += param[0].length;
        push("word", param[0], param[0], at);
        continue;
      }
    }
    if (ch === '"') {
      i += 1;
      let value = "";
      while (i < n) {
        if (sql[i] === '"' && sql[i + 1] === '"') {
          value += '"';
          i += 2;
        } else if (sql[i] === '"') {
          i += 1;
          break;
        } else {
          value += sql[i];
          i += 1;
        }
      }
      const text2 = sql.slice(start, i);
      count2(text2);
      push("ident", text2, value, at);
      continue;
    }
    if (/[A-Za-z_\u0080-￿]/.test(ch)) {
      while (i < n && /[A-Za-z0-9_$\u0080-￿]/.test(sql[i])) i += 1;
      const text2 = sql.slice(start, i);
      push("word", text2, foldName(text2), at);
      continue;
    }
    if (/[0-9]/.test(ch) || ch === "." && /[0-9]/.test(sql[i + 1] ?? "")) {
      while (i < n && /[0-9.eE]/.test(sql[i])) i += 1;
      const text2 = sql.slice(start, i);
      push("number", text2, text2, at);
      continue;
    }
    const text = ch === ":" && sql[i + 1] === ":" ? "::" : OP_CHARS.has(ch) ? operatorAt(sql, i) : ch;
    i += text.length;
    push("op", text, text, at);
  }
  return out;
}
function splitStatements(tokens) {
  const out = [];
  let current = [];
  let atomic = 0;
  let cases = 0;
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t.kind === "word") {
      if (t.value === "atomic" && tokens[i - 1]?.value === "begin") atomic += 1;
      else if (atomic > 0 && t.value === "case") cases += 1;
      else if (atomic > 0 && t.value === "end") {
        if (cases > 0) cases -= 1;
        else atomic -= 1;
      }
    }
    if (t.kind === "op" && t.value === ";" && atomic === 0) {
      if (current.length > 0) out.push({ tokens: current, line: current[0].line });
      current = [];
      continue;
    }
    current.push(t);
  }
  if (current.length > 0) out.push({ tokens: current, line: current[0].line });
  return out;
}
var isName = (t) => !!t && (t.kind === "word" || t.kind === "ident");
var isOp = (t, value) => !!t && t.kind === "op" && t.value === value;
var isWord = (t, ...values) => !!t && t.kind === "word" && values.includes(t.value);
function pairs(tokens) {
  const out = new Int32Array(tokens.length).fill(-1);
  const stack = [];
  for (let i = 0; i < tokens.length; i += 1) {
    if (isOp(tokens[i], "(")) stack.push(i);
    else if (isOp(tokens[i], ")") && stack.length > 0) {
      const open = stack.pop();
      out[open] = i;
      out[i] = open;
    }
  }
  return out;
}
function unwrap(tokens) {
  const match = pairs(tokens);
  let start = 0;
  let end = tokens.length - 1;
  while (end > start && isOp(tokens[start], "(") && match[start] === end) {
    start += 1;
    end -= 1;
  }
  return start === 0 ? tokens : tokens.slice(start, end + 1);
}
function splitTop(tokens, word) {
  const out = [];
  let depth = 0;
  let current = [];
  for (const t of tokens) {
    if (isOp(t, "(")) depth += 1;
    else if (isOp(t, ")")) depth -= 1;
    if (depth === 0 && isWord(t, word)) {
      out.push(current);
      current = [];
      continue;
    }
    current.push(t);
  }
  out.push(current);
  return out;
}
var SPACE_BEFORE_PAREN = /* @__PURE__ */ new Set([
  "in",
  "exists",
  "any",
  "all",
  "some",
  "and",
  "or",
  "not",
  "select",
  "where",
  "using",
  "check",
  "as",
  "on",
  "from",
  "values",
  "then",
  "else",
  "when",
  "is",
  "array",
  "with",
  "returning",
  "join",
  "case"
]);
function render(tokens) {
  let out = "";
  let prev;
  let before;
  for (const t of tokens) {
    if (prev) {
      const afterOperator = !before || before.kind === "op" && !isOp(before, ")") && !isOp(before, "]");
      const sign = (isOp(prev, "-") || isOp(prev, "+")) && t.kind === "number" && afterOperator;
      const tight = sign || isOp(prev, "(") || isOp(prev, ".") || isOp(prev, "::") || isOp(prev, "[") || isOp(t, ")") || isOp(t, ",") || isOp(t, ".") || isOp(t, "::") || isOp(t, "[") || isOp(t, "]") || isOp(t, "(") && isName(prev) && !(prev.kind === "word" && SPACE_BEFORE_PAREN.has(prev.value));
      if (!tight) out += " ";
    }
    out += t.text;
    before = prev;
    prev = t;
  }
  return out;
}
function canon(tokens) {
  let out = "";
  let prev;
  for (const t of tokens) {
    const wordy = t.kind === "word" || t.kind === "ident" || t.kind === "number";
    const prevWordy = prev && (prev.kind === "word" || prev.kind === "ident" || prev.kind === "number");
    if (wordy && (prevWordy || isOp(prev, ")"))) out += " ";
    else if (isOp(t, "(") && prev?.kind === "word" && SPACE_BEFORE_PAREN.has(prev.value)) out += " ";
    if (t.kind === "ident") out += /^[a-z_][a-z0-9_$]*$/.test(t.value) ? t.value : `"${t.value}"`;
    else if (t.kind === "string") out += `'${t.value.replace(/'/g, "''")}'`;
    else out += t.kind === "word" ? t.value : t.text;
    prev = t;
  }
  return out;
}
var SELECT_WRAP = /\(select (auth\.(?:uid|jwt|role|email)\(\)(?:->>?'[a-z_]+')*)(?: as \w+)?\)/g;
var PAREN_WRAP = /\((auth\.(?:uid|jwt|role|email)\(\)(?:->>?'[a-z_]+')*)\)/g;
var LITERAL_CAST = /('(?:[^']|'')*')::(?:text|name|varchar|character varying|"text")\b/g;
function core(tokens) {
  let text = canon(unwrap(tokens)).replace(LITERAL_CAST, "$1");
  for (let pass = 0; pass < 4; pass += 1) {
    const next = text.replace(SELECT_WRAP, "$1").replace(PAREN_WRAP, "$1");
    if (next === text) break;
    text = next;
  }
  return text;
}
var ALWAYS_TRUE = /* @__PURE__ */ new Set(["true", "1=1", "'t'", "'true'::boolean", "true::boolean"]);
var SIGNED_IN_ONLY = /* @__PURE__ */ new Set([
  "auth.uid() is not null",
  "auth.jwt() is not null",
  "auth.role()='authenticated'",
  "'authenticated'=auth.role()",
  "auth.jwt()->>'role'='authenticated'",
  "'authenticated'=auth.jwt()->>'role'",
  "auth.jwt()->>'sub' is not null",
  "not auth.uid() is null"
]);
function truthOf(tokens, depth = 0) {
  if (depth > 32) return "other";
  const t = unwrap(tokens);
  const ors = splitTop(t, "or");
  if (ors.length > 1) {
    const kinds = ors.map((part) => truthOf(part, depth + 1));
    return kinds.includes("true") ? "true" : kinds.includes("signed") ? "signed" : "other";
  }
  const ands = splitTop(t, "and");
  if (ands.length > 1) {
    const kinds = ands.map((part) => truthOf(part, depth + 1));
    return kinds.every((k) => k === "true") ? "true" : kinds.every((k) => k !== "other") ? "signed" : "other";
  }
  const text = core(t);
  return ALWAYS_TRUE.has(text) ? "true" : SIGNED_IN_ONLY.has(text) ? "signed" : "other";
}
var alwaysTrue = (expr) => !!expr && truthOf(expr.tokens) === "true";
var signedInOnly = (expr) => !!expr && truthOf(expr.tokens) === "signed";
function authCalls(tokens) {
  const out = [];
  const match = pairs(tokens);
  const selects = [];
  let openSelects = 0;
  const close = (open) => match[open] === -1 ? tokens.length - 1 : match[open];
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (isOp(t, "(")) {
      const isSelect = isWord(tokens[i + 1], "select");
      selects.push(isSelect);
      if (isSelect) openSelects += 1;
    } else if (isOp(t, ")") && selects.length > 0) {
      if (selects.pop()) openSelects -= 1;
    }
    let name;
    let open = -1;
    if (isName(t) && t.value === "auth" && isOp(tokens[i + 1], ".") && isName(tokens[i + 2]) && isOp(tokens[i + 3], "(")) {
      const fn = tokens[i + 2].value;
      if (["uid", "jwt", "role", "email"].includes(fn)) {
        name = `auth.${fn}`;
        open = i + 3;
      }
    } else if (isName(t) && t.value === "current_setting" && isOp(tokens[i + 1], "(") && !isOp(tokens[i - 1], ".")) {
      name = "current_setting";
      open = i + 1;
    } else if (isName(t) && t.value === "pg_catalog" && isOp(tokens[i + 1], ".") && tokens[i + 2]?.value === "current_setting" && isOp(tokens[i + 3], "(")) {
      name = "current_setting";
      open = i + 3;
    }
    if (!name) continue;
    const end = close(open);
    out.push({ name, start: i, end, wrapped: openSelects > 0 });
    i = end;
  }
  return out;
}
var added = (kind, text, line) => ({ kind, text, value: text, line });
function wrapCalls(tokens, calls) {
  const out = [];
  let at = 0;
  const copy = (from, to) => {
    for (let i = from; i < to; i += 1) out.push(tokens[i]);
  };
  for (const call of calls.filter((c) => !c.wrapped)) {
    const line = tokens[call.start].line;
    copy(at, call.start);
    out.push(added("op", "(", line), added("word", "select", line));
    copy(call.start, call.end + 1);
    out.push(added("op", ")", line));
    at = call.end + 1;
  }
  copy(at, tokens.length);
  return render(out);
}
var USER_METADATA = /(^|_)user_meta_?data$|raw_user_meta_data/;
var mentionsUserMetadata = (expr) => !!expr && expr.tokens.some((t) => USER_METADATA.test(t.value));
var FAILS_OPEN = /* @__PURE__ */ new Set(["coalesce", "nullif", "greatest", "least", "concat", "concat_ws", "case", "is", "not", "distinct"]);
function failsClosed(tokens, depth = 0) {
  if (depth > 32) return false;
  const t = unwrap(tokens);
  for (const word of ["or", "and"]) {
    const parts = splitTop(t, word);
    if (parts.length > 1) return parts.every((part) => failsClosed(part, depth + 1));
  }
  if (!t.some((x) => USER_METADATA.test(x.value))) return true;
  return !t.some((x) => x.kind === "word" && FAILS_OPEN.has(x.value) || isOp(x, "<>") || isOp(x, "!="));
}
function appMetadata(tokens) {
  if (!failsClosed(tokens)) return void 0;
  const out = [];
  for (const t of tokens) {
    if (!USER_METADATA.test(t.value)) out.push(t);
    else if (t.kind === "string" && t.value === "user_metadata") out.push({ ...t, text: "'app_metadata'", value: "app_metadata" });
    else if (isName(t) && t.value === "raw_user_meta_data") out.push({ ...t, kind: "word", text: "raw_app_meta_data", value: "raw_app_meta_data" });
    else return void 0;
  }
  return out;
}
function metadataKeys(tokens) {
  const out = /* @__PURE__ */ new Set();
  tokens.forEach((t, i) => {
    if (!USER_METADATA.test(t.value)) return;
    let k = skipCasts(tokens, i + 1);
    while (isOp(tokens[k], ")")) k = skipCasts(tokens, k + 1);
    if ((isOp(tokens[k], "->>") || isOp(tokens[k], "->")) && tokens[k + 1]?.kind === "string") out.add(tokens[k + 1].value);
  });
  return [...out];
}
function appMetadataNote(tokens) {
  const keys = metadataKeys(tokens).map((k) => `"${k}"`);
  const what = keys.length === 0 ? "the claim" : keys.length === 1 ? keys[0] : `${keys.slice(0, -1).join(", ")} and ${keys.at(-1)}`;
  return `Before you run this, set ${what} in each user\u2019s app_metadata from server code
(users can\u2019t change app_metadata). Until then, they lose access.`;
}
function fixText(tokens) {
  const safe = appMetadata(unwrap(tokens)) ?? unwrap(tokens);
  const calls = authCalls(safe);
  return calls.some((c) => !c.wrapped) ? wrapCalls(safe, calls) : render(safe);
}
var mentions = (expr, test) => !!expr && expr.tokens.some((t, i, all) => test(t, i, all));
var callsAuthRole = (expr) => mentions(expr, (t, i, all) => t.value === "auth" && all[i + 2]?.value === "role" && isOp(all[i + 3], "("));
var readsClaimsSetting = (expr) => mentions(expr, (t) => t.kind === "string" && /^request\.jwt\.claim/.test(t.value));
function bareCall(tokens, i, fn) {
  const named = isName(tokens[i]) && tokens[i].value === "auth" && isOp(tokens[i + 1], ".") && tokens[i + 2]?.value === fn;
  return named && isOp(tokens[i + 3], "(") && isOp(tokens[i + 4], ")") ? i + 5 : -1;
}
function uidSpan(tokens, i, match, depth = 0, who = "id") {
  const uid = bareCall(tokens, i, who === "id" ? "uid" : "email");
  if (uid !== -1) return uid;
  let jwt = bareCall(tokens, i, "jwt");
  if (jwt === -1 && isOp(tokens[i], "(") && match[i] !== -1 && depth < 3) {
    const close = match[i];
    const from = isWord(tokens[i + 1], "select") ? i + 2 : i + 1;
    const alias = (end) => isWord(tokens[end], "as") && isName(tokens[end + 1]) ? end + 2 : end;
    const inner = uidSpan(tokens, from, match, depth + 1, who);
    if (inner !== -1 && alias(inner) === close) return close + 1;
    const call = bareCall(tokens, from, "jwt");
    if (call !== -1 && alias(call) === close) jwt = close + 1;
  }
  if (jwt === -1) return -1;
  const sub = isOp(tokens[jwt], "->>") && tokens[jwt + 1]?.kind === "string" && tokens[jwt + 1].value === (who === "id" ? "sub" : "email");
  return sub ? skipCasts(tokens, jwt + 2) : -1;
}
function skipCasts(tokens, i) {
  while (isOp(tokens[i], "::") && isName(tokens[i + 1])) {
    i += 2;
    if (isOp(tokens[i], "[") && isOp(tokens[i + 1], "]")) i += 2;
  }
  return i;
}
var NOT_COLUMNS = /* @__PURE__ */ new Set(["null", "true", "false", "select", "and", "or", "not"]);
function ownerColumns(expr, who = "id") {
  if (!expr) return [];
  const tokens = expr.tokens;
  const match = pairs(tokens);
  const out = /* @__PURE__ */ new Set();
  for (let i = 0; i < tokens.length; i += 1) {
    const end = uidSpan(tokens, i, match, 0, who);
    if (end === -1) continue;
    const eq = skipCasts(tokens, end);
    if (isOp(tokens[eq], "=")) {
      let k = eq + 1;
      if (isName(tokens[k])) {
        while (isOp(tokens[k + 1], ".") && isName(tokens[k + 2])) k += 2;
        const after = tokens[skipCasts(tokens, k + 1)];
        const alone = !after || after.kind !== "op" || [")", ",", ";"].includes(after.value);
        if (alone && !NOT_COLUMNS.has(tokens[k].value)) out.add(tokens[k].value);
      }
    }
    if (isOp(tokens[i - 1], "=")) {
      let k = i - 2;
      while (k >= 2 && isName(tokens[k]) && isOp(tokens[k - 1], "::")) k -= 2;
      if (isOp(tokens[k], "]") && isOp(tokens[k - 1], "[") && isOp(tokens[k - 2], "::")) k -= 4;
      let first = k;
      while (isOp(tokens[first - 1], ".") && isName(tokens[first - 2])) first -= 2;
      const before = tokens[first - 1];
      const alone = !before || before.kind !== "op" || ["(", ","].includes(before.value);
      if (alone && isName(tokens[k]) && !isOp(tokens[k + 1], "(") && !NOT_COLUMNS.has(tokens[k].value)) out.add(tokens[k].value);
    }
    i = end - 1;
  }
  return [...out];
}
function nameAsToken(value, line) {
  const text = identifier(value);
  return { kind: text.startsWith('"') ? "ident" : "word", text, value, line };
}
function columnRefs(tokens, table, column) {
  const out = /* @__PURE__ */ new Set();
  const selects = [];
  let inSelect = 0;
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (isOp(t, "(")) {
      const select = isWord(tokens[i + 1], "select");
      selects.push(select);
      if (select) inSelect += 1;
    } else if (isOp(t, ")")) {
      if (selects.pop()) inSelect -= 1;
    } else if (isName(t) && t.value === column && !isOp(tokens[i + 1], "(") && !isOp(tokens[i + 1], ".") && !isOp(tokens[i - 1], "::")) {
      const qualified = isOp(tokens[i - 1], ".");
      if (qualified ? isName(tokens[i - 2]) && tokens[i - 2].value === table : inSelect === 0) out.add(i);
    }
  }
  return out;
}
function callsIn(tokens, depth = 0) {
  const out = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t.kind === "string" && depth < 3 && t.value.includes("(")) out.push(...callsIn(tokenize(t.value), depth + 1));
    if (!isName(t) || !isOp(tokens[i + 1], "(")) continue;
    const qualified = isOp(tokens[i - 1], ".") && isName(tokens[i - 2]);
    if (isWord(tokens[qualified ? i - 3 : i - 1], "references")) continue;
    out.push([qualified ? tokens[i - 2].value : void 0, t.value]);
  }
  return out;
}
var namesFunction = (call, fn) => call[1] === fn.name && (call[0] === void 0 || call[0] === fn.schema);
var COMMANDS = ["select", "insert", "update", "delete"];
var SYSTEM_SCHEMAS = /* @__PURE__ */ new Set([
  "_timescaledb_cache",
  "_timescaledb_catalog",
  "_timescaledb_config",
  "_timescaledb_internal",
  "auth",
  "cron",
  "extensions",
  "graphql",
  "graphql_public",
  "information_schema",
  "net",
  "pgmq",
  "pgroonga",
  "pgsodium",
  "pgsodium_masks",
  "pgtle",
  "pgbouncer",
  "pg_catalog",
  "realtime",
  "repack",
  "storage",
  "supabase_functions",
  "supabase_migrations",
  "tiger",
  "topology",
  "vault",
  "pg_toast",
  "_realtime",
  "_analytics",
  "supabase_realtime"
]);
var key = (schema, name) => `${schema}.${name}`;
var qualifiedName = (schema, name) => `${identifier(schema)}.${identifier(name)}`;
function emptyCatalog(source) {
  return { source, exposed: ["public"], relations: /* @__PURE__ */ new Map(), policies: [], functions: [], buckets: /* @__PURE__ */ new Map(), statements: 0, opaque: [] };
}
var Cursor = class {
  tokens;
  i;
  match;
  constructor(tokens) {
    this.tokens = tokens;
    this.i = 0;
    this.match = void 0;
  }
  peek(offset = 0) {
    return this.tokens[this.i + offset];
  }
  done() {
    return this.i >= this.tokens.length;
  }
  /** Consumes the words in order if they're all next. */
  accept(...words) {
    for (let k = 0; k < words.length; k += 1) if (!isWord(this.tokens[this.i + k], words[k])) return false;
    this.i += words.length;
    return true;
  }
  acceptOp(value) {
    if (isOp(this.peek(), value)) {
      this.i += 1;
      return true;
    }
    return false;
  }
  /** A name, possibly schema-qualified: [schema, name]. */
  name(defaultSchema = "public") {
    const first = this.peek();
    if (!isName(first)) return void 0;
    this.i += 1;
    if (isOp(this.peek(), ".") && isName(this.peek(1))) {
      const second = this.peek(1);
      this.i += 2;
      return [first.value, second.value];
    }
    return [defaultSchema, first.value];
  }
  /** The tokens inside the parentheses that start here, consuming them. */
  group() {
    if (!isOp(this.peek(), "(")) return void 0;
    this.match ??= pairs(this.tokens);
    const end = this.match[this.i] === -1 ? this.tokens.length : this.match[this.i];
    const inner = this.tokens.slice(this.i + 1, end);
    this.i = end + 1;
    return inner;
  }
  rest() {
    return this.tokens.slice(this.i);
  }
};
function commaSplit(tokens) {
  const out = [];
  let depth = 0;
  let current = [];
  for (const t of tokens) {
    if (isOp(t, "(") || isOp(t, "[")) depth += 1;
    if (isOp(t, ")") || isOp(t, "]")) depth -= 1;
    if (isOp(t, ",") && depth === 0) {
      out.push(current);
      current = [];
      continue;
    }
    current.push(t);
  }
  if (current.length > 0) out.push(current);
  return out;
}
var CONSTRAINT_WORDS = /* @__PURE__ */ new Set(["constraint", "primary", "unique", "check", "foreign", "exclude", "like"]);
var TABLE_CONSTRAINT_WORDS = ["primary", "unique", "check", "foreign", "exclude"];
var COLUMN_CONSTRAINT_WORDS = /* @__PURE__ */ new Set([
  "constraint",
  "not",
  "null",
  "default",
  "primary",
  "unique",
  "references",
  "check",
  "generated",
  "collate",
  "compression"
]);
var TRUE_WORDS = /* @__PURE__ */ new Set(["true", "on", "yes", "1"]);
function outside(tokens) {
  let depth = 0;
  return tokens.map((t) => {
    if (isOp(t, "(")) depth += 1;
    else if (isOp(t, ")")) depth -= 1;
    else return depth === 0;
    return false;
  });
}
function referenceTarget(tokens) {
  const c = new Cursor(tokens);
  const target = c.name();
  if (!target) return void 0;
  if (!isOp(c.peek(), "(")) return [target[0], target[1], "id"];
  const columns = (c.group() ?? []).filter(isName);
  return columns.length === 1 ? [target[0], target[1], columns[0].value] : void 0;
}
function referencesAuthUsers(tokens) {
  const target = referenceTarget(tokens);
  return !!target && target[0] === "auth" && target[1] === "users" && target[2] === "id";
}
var COLUMN_TYPE_ALIASES = {
  serial: "integer",
  serial4: "integer",
  bigserial: "bigint",
  serial8: "bigint",
  smallserial: "smallint",
  serial2: "smallint"
};
function columnType(tokens) {
  const match = pairs(tokens);
  const kept = [];
  for (let i = 0; i < tokens.length; i += 1) {
    if (isOp(tokens[i], "(") && match[i] !== -1) i = match[i];
    else kept.push(tokens[i]);
  }
  let type = canon(kept).replace(/"/g, "").replace(/^(pg_catalog|public)\./, "");
  const array = /(\[\])+$/.exec(type)?.[0] ?? "";
  if (array) type = type.slice(0, -array.length);
  if (type === "") return void 0;
  return (COLUMN_TYPE_ALIASES[type] ?? TYPE_ALIASES[type] ?? type) + array;
}
function privilegesFrom(tokens) {
  const commands = /* @__PURE__ */ new Set();
  let all = false;
  let execute = false;
  let usage = false;
  for (const part of commaSplit(tokens)) {
    const word = part[0]?.value;
    if (word === "all") {
      all = true;
      COMMANDS.forEach((c) => commands.add(c));
    } else if (word && COMMANDS.includes(word)) {
      commands.add(word);
    } else if (word === "execute") execute = true;
    else if (word === "usage") usage = true;
  }
  return { commands, all, execute, usage };
}
var EMBEDDED = /* @__PURE__ */ new Set(["create", "alter", "drop", "grant", "revoke"]);
function readSql(sql) {
  const catalog = emptyCatalog("sql");
  const statements = splitStatements(tokenize(sql));
  catalog.statements = statements.length;
  const exposed = /* @__PURE__ */ new Set(["public"]);
  const defaults = {
    tables: void 0,
    functionsGlobal: { public: true, anon: false, authenticated: false },
    functionsBySchema: /* @__PURE__ */ new Map([["public", { public: false, anon: true, authenticated: true }]])
  };
  const policies = /* @__PURE__ */ new Map();
  const functions = /* @__PURE__ */ new Map();
  const policyKey = (schema, table, name) => `${schema}.${table}\0${name}`;
  const functionKey = (f) => `${f.schema}.${f.name}(${f.args})`;
  const relation = (schema, name) => catalog.relations.get(key(schema, name));
  const ensureGrants = (rel) => {
    rel.grants ??= { anon: new Set(COMMANDS), authenticated: new Set(COMMANDS) };
    return rel.grants;
  };
  for (const statement of statements) handle(statement.tokens, statement.line, 0);
  catalog.exposed = [...exposed];
  catalog.policies = [...policies.values()];
  catalog.functions = [...functions.values()];
  for (const fn of catalog.functions) {
    fn.calledBy = catalog.functions.filter((g) => g !== fn && g.calls?.some((call) => namesFunction(call, fn))).map((g) => `${qualifiedName(g.schema, g.name)}(${g.args})`);
    fn.usedBy = [...catalog.relations.values()].filter((r) => r.calls?.some((call) => namesFunction(call, fn))).map((r) => qualifiedName(r.schema, r.name));
  }
  return catalog;
  function handle(tokens, line, depth) {
    const c = new Cursor(tokens);
    try {
      if (c.accept("do")) readDo(tokens, line, depth);
      else if (c.accept("create")) {
        c.accept("or", "replace");
        while (c.accept("temp") || c.accept("temporary") || c.accept("unlogged") || c.accept("global") || c.accept("local")) ;
        if (c.accept("table")) readCreateTable(c, line, "table");
        else if (c.accept("foreign", "table")) readCreateTable(c, line, "foreign");
        else if (c.accept("materialized", "view")) readCreateView(c, line, "matview");
        else if (c.accept("recursive", "view") || c.accept("view")) readCreateView(c, line, "view");
        else if (c.accept("policy")) readCreatePolicy(c, line);
        else if (c.accept("unique", "index") || c.accept("index")) readCreateIndex(c);
        else if (c.accept("function")) readCreateFunction(c, line);
      } else if (c.accept("alter", "table")) readAlterTable(c, line);
      else if (c.accept("alter", "view") || c.accept("alter", "materialized", "view")) readAlterView(c);
      else if (c.accept("alter", "policy")) readAlterPolicy(c);
      else if (c.accept("alter", "function")) readAlterFunction(c);
      else if (c.accept("alter", "publication")) readAlterPublication(c);
      else if (c.accept("alter", "default", "privileges")) readDefaultPrivileges(c);
      else if (c.accept("drop")) readDrop(c);
      else if (c.accept("grant")) readGrant(c, true);
      else if (c.accept("revoke")) readGrant(c, false);
      else if (c.accept("insert", "into")) readInsert(c);
    } catch {
    }
  }
  function readDo(tokens, line, depth) {
    const body = tokens.find((t) => t.kind === "string");
    if (!body || depth > 3) return;
    readBody(body.value, body.line, depth + 1);
  }
  function readBody(text, firstLine, depth) {
    const inner = tokenize(text);
    for (const t of inner) t.line += firstLine - 1;
    for (const statement of splitStatements(inner)) {
      const tokens = statement.tokens;
      for (let k = 0; k < tokens.length; k += 1) {
        const t = tokens[k];
        const starts = t.kind === "word" && EMBEDDED.has(t.value) && (k === 0 || isWord(tokens[k - 1], "begin", "then", "else", "loop"));
        if (starts) {
          handle(tokens.slice(k), t.line, depth);
          break;
        }
        if (isWord(t, "execute")) {
          const next = tokens[k + 1];
          if (next?.kind === "string") {
            readBody(next.value, next.line, depth + 1);
          } else if (isWord(next, "format") && isOp(tokens[k + 2], "(") && tokens[k + 3]?.kind === "string") {
            const dropAll = /^\s*drop\s+policy\s+(?:if\s+exists\s+)?%(?:\d+\$)?I\s+on\s+(.+?)\s*$/i.exec(tokens[k + 3].value);
            const target = dropAll ? dropTarget(dropAll[1].replace(/%%/g, "%")) : void 0;
            if (target) {
              const [schema, table] = target;
              for (const [id, p] of policies) {
                if ((schema === void 0 || p.schema === schema) && (table === void 0 || p.table === table)) policies.delete(id);
              }
              if (table === void 0) catalog.opaque.push(t.line);
            } else catalog.opaque.push(t.line);
          } else catalog.opaque.push(t.line);
          break;
        }
      }
    }
  }
  function addRelation(schema, name, kind, line, created = true) {
    const rel = {
      schema,
      name,
      kind,
      line,
      rls: false,
      rlsKnown: false,
      created,
      columns: [],
      types: /* @__PURE__ */ new Map(),
      notNull: /* @__PURE__ */ new Set(),
      userRefs: /* @__PURE__ */ new Set(),
      refs: /* @__PURE__ */ new Map(),
      indexed: /* @__PURE__ */ new Set(),
      securityInvoker: false,
      realtime: false,
      grants: defaults.tables ? { anon: new Set(defaults.tables.anon), authenticated: new Set(defaults.tables.authenticated) } : void 0
    };
    const existing = relation(schema, name);
    if (existing && (kind === existing.kind || !existing.created)) {
      existing.kind = kind;
      existing.created ||= created;
      return existing;
    }
    catalog.relations.set(key(schema, name), rel);
    return rel;
  }
  function readCreateTable(c, line, kind) {
    const ifNotExists = c.accept("if", "not", "exists");
    const name = c.name();
    if (!name) return;
    if (ifNotExists && relation(name[0], name[1])) return;
    const rel = addRelation(name[0], name[1], kind, line);
    if (c.accept("partition", "of")) return;
    const body = c.group();
    if (!body) return;
    for (const element of commaSplit(body)) {
      const first = element[0];
      if (!first) continue;
      if (first.kind === "word" && CONSTRAINT_WORDS.has(first.value)) {
        readConstraint(rel, element);
        continue;
      }
      if (!isName(first)) continue;
      readColumn(rel, element);
    }
  }
  function readColumn(rel, element) {
    const name = element[0].value;
    if (!rel.columns.includes(name)) rel.columns.push(name);
    let end = 1;
    while (end < element.length && !(element[end].kind === "word" && COLUMN_CONSTRAINT_WORDS.has(element[end].value))) end += 1;
    const type = columnType(element.slice(1, end));
    if (type) rel.types.set(name, type);
    const tail = element.slice(end);
    const top = outside(tail);
    const words = tail.filter((_, i) => top[i]);
    if (hasWords(words, "primary") || hasWords(words, "unique")) rel.indexed.add(name);
    const serial = /^(small|big)?serial[248]?$/.test(element[1]?.value ?? "");
    if (serial || hasWords(words, "not", "null") || hasWords(words, "primary", "key") || hasWords(words, "as", "identity")) {
      rel.notNull.add(name);
    }
    const calls = callsIn(tail);
    if (calls.length > 0) (rel.calls ??= []).push(...calls);
    const refs = tail.findIndex((t, i) => top[i] && isWord(t, "references"));
    const target = refs === -1 ? void 0 : referenceTarget(tail.slice(refs + 1));
    if (target) rel.refs.set(name, target);
    if (refs !== -1 && referencesAuthUsers(tail.slice(refs + 1))) rel.userRefs.add(name);
  }
  function readConstraint(rel, element) {
    const c = new Cursor(element);
    if (c.accept("constraint")) c.i += 1;
    if (isWord(c.peek(), "check")) {
      const calls = callsIn(c.rest());
      if (calls.length > 0) (rel.calls ??= []).push(...calls);
      return;
    }
    if (c.accept("primary", "key") || c.accept("unique")) {
      const primary = isWord(element[c.i - 1], "key");
      c.accept("nulls", "not", "distinct");
      const columns = (c.group() ?? []).filter((t, i, all) => isName(t) && (i === 0 || isOp(all[i - 1], ",")));
      if (columns[0]) rel.indexed.add(columns[0].value);
      if (primary) for (const t of columns) rel.notNull.add(t.value);
    } else if (c.accept("foreign", "key")) {
      const columns = (c.group() ?? []).filter(isName);
      if (columns.length !== 1 || !c.accept("references")) return;
      const target = referenceTarget(c.rest());
      if (target) rel.refs.set(columns[0].value, target);
      if (referencesAuthUsers(c.rest())) rel.userRefs.add(columns[0].value);
    }
  }
  function readCreateView(c, line, kind) {
    c.accept("if", "not", "exists");
    const name = c.name();
    if (!name) return;
    const rel = addRelation(name[0], name[1], kind, line);
    rel.kind = kind;
    rel.securityInvoker = false;
    if (isOp(c.peek(), "(")) c.group();
    if (c.accept("with")) {
      const options = c.group();
      if (options) applyViewOptions(rel, options, true);
    }
    while (!c.done() && !isWord(c.peek(), "as")) c.i += 1;
    c.accept("as");
    rel.query = c.rest();
  }
  function applyViewOptions(rel, options, set) {
    for (const option of commaSplit(options)) {
      if (option[0]?.value !== "security_invoker") continue;
      if (!set) rel.securityInvoker = false;
      else {
        const value = option[2] ?? option[1];
        rel.securityInvoker = option.length === 1 || value !== void 0 && TRUE_WORDS.has(value.value.toLowerCase());
      }
    }
  }
  function readAlterView(c) {
    c.accept("if", "exists");
    const name = c.name();
    if (!name) return;
    const rel = relation(name[0], name[1]);
    if (!rel) return;
    if (c.accept("set", "schema")) {
      const to = c.peek();
      if (isName(to)) moveRelation(rel, to.value, rel.name);
    } else if (c.accept("set")) {
      const options = c.group();
      if (options) applyViewOptions(rel, options, true);
    } else if (c.accept("reset")) {
      const options = c.group();
      if (options) applyViewOptions(rel, options, false);
    } else if (c.accept("rename", "to")) {
      const to = c.peek();
      if (isName(to)) moveRelation(rel, rel.schema, to.value);
    }
  }
  function moveRelation(rel, schema, name) {
    catalog.relations.delete(key(rel.schema, rel.name));
    for (const [id, p] of [...policies]) {
      if (p.schema !== rel.schema || p.table !== rel.name) continue;
      policies.delete(id);
      p.schema = schema;
      p.table = name;
      policies.set(policyKey(schema, name, p.name), p);
    }
    rel.schema = schema;
    rel.name = name;
    catalog.relations.set(key(schema, name), rel);
  }
  function renameColumn(rel, from, to) {
    const at = rel.columns.indexOf(from);
    if (at !== -1) rel.columns[at] = to;
    const type = rel.types.get(from);
    rel.types.delete(from);
    if (type) rel.types.set(to, type);
    for (const set of [rel.notNull, rel.userRefs, rel.indexed]) if (set.delete(from)) set.add(to);
    const target = rel.refs.get(from);
    rel.refs.delete(from);
    if (target) rel.refs.set(to, target);
    for (const p of policiesOf(rel)) {
      for (const expr of [p.using, p.check]) {
        if (!expr) continue;
        const refs = columnRefs(expr.tokens, rel.name, from);
        if (refs.size > 0) expr.tokens = expr.tokens.map((t, i) => refs.has(i) ? nameAsToken(to, t.line) : t);
      }
    }
  }
  function dropColumn(rel, column, cascade) {
    rel.columns = rel.columns.filter((c) => c !== column);
    rel.types.delete(column);
    for (const set of [rel.notNull, rel.userRefs, rel.indexed]) set.delete(column);
    rel.refs.delete(column);
    if (!cascade) return;
    for (const p of policiesOf(rel)) {
      const uses = [p.using, p.check].some((expr) => !!expr && columnRefs(expr.tokens, rel.name, column).size > 0);
      if (uses) policies.delete(policyKey(p.schema, p.table, p.name));
    }
  }
  function policiesOf(rel) {
    return [...policies.values()].filter((p) => p.schema === rel.schema && p.table === rel.name);
  }
  function readCreatePolicy(c, line) {
    const nameToken = c.peek();
    if (!isName(nameToken)) return;
    c.i += 1;
    if (!c.accept("on")) return;
    const table = c.name();
    if (!table) return;
    const policy = {
      schema: table[0],
      table: table[1],
      name: nameToken.value,
      permissive: true,
      command: "all",
      roles: ["public"],
      line
    };
    readPolicyClauses(c, policy);
    policies.delete(policyKey(policy.schema, policy.table, policy.name));
    policies.set(policyKey(policy.schema, policy.table, policy.name), policy);
  }
  function readPolicyClauses(c, policy) {
    while (!c.done()) {
      if (c.accept("as", "permissive")) policy.permissive = true;
      else if (c.accept("as", "restrictive")) policy.permissive = false;
      else if (c.accept("for")) {
        const command = c.peek()?.value;
        if (command && ["all", ...COMMANDS].includes(command)) policy.command = command;
        c.i += 1;
      } else if (c.accept("to")) {
        const roles = [];
        while (isName(c.peek())) {
          roles.push(c.peek().value);
          c.i += 1;
          if (!c.acceptOp(",")) break;
        }
        if (roles.length > 0) policy.roles = roles;
      } else if (c.accept("using")) {
        const inner = c.group();
        if (inner) policy.using = { tokens: inner };
      } else if (c.accept("with", "check")) {
        const inner = c.group();
        if (inner) policy.check = { tokens: inner };
      } else if (c.accept("rename", "to")) {
        const to = c.peek();
        if (isName(to)) policy.name = to.value;
        c.i += 1;
      } else c.i += 1;
    }
  }
  function readAlterPolicy(c) {
    const nameToken = c.peek();
    if (!isName(nameToken)) return;
    c.i += 1;
    if (!c.accept("on")) return;
    const table = c.name();
    if (!table) return;
    const policy = policies.get(policyKey(table[0], table[1], nameToken.value));
    if (!policy) return;
    readPolicyClauses(c, policy);
    if (policy.name !== nameToken.value) {
      policies.delete(policyKey(table[0], table[1], nameToken.value));
      policies.set(policyKey(policy.schema, policy.table, policy.name), policy);
    }
  }
  function readCreateIndex(c) {
    c.accept("concurrently");
    c.accept("if", "not", "exists");
    if (!isWord(c.peek(), "on")) c.i += 1;
    if (!c.accept("on")) return;
    c.accept("only");
    const table = c.name();
    if (!table) return;
    if (c.accept("using")) c.i += 1;
    const columns = c.group();
    const first = columns?.[0];
    const rel = relation(table[0], table[1]);
    if (rel && isName(first) && !isOp(columns?.[1], "(")) rel.indexed.add(first.value);
  }
  function readCreateFunction(c, line) {
    const name = c.name();
    if (!name) return;
    const args = c.group() ?? [];
    const rest = c.rest();
    const names2 = rest.filter(isName);
    const returns = names2.findIndex((t) => t.kind === "word" && t.value === "returns");
    const fn = {
      schema: name[0],
      name: name[1],
      args: argTypes(args),
      returnsTrigger: returns !== -1 && ["trigger", "event_trigger"].includes(names2[returns + 1]?.value ?? ""),
      securityDefiner: hasWords(rest, "security", "definer"),
      searchPathSet: rest.some((t, i) => isWord(t, "set") && rest[i + 1]?.value === "search_path"),
      anon: true,
      authenticated: true,
      line,
      acl: newFunctionAcl(name[0]),
      // The body, whether quoted or BEGIN ATOMIC.
      calls: callsIn(rest)
    };
    const existing = functions.get(functionKey(fn));
    if (existing?.acl) fn.acl = { ...existing.acl };
    fn.anon = fn.acl.public || fn.acl.anon;
    fn.authenticated = fn.acl.public || fn.acl.authenticated;
    functions.set(functionKey(fn), fn);
  }
  function readAlterFunction(c) {
    const name = c.name();
    if (!name) return;
    const args = isOp(c.peek(), "(") ? argTypes(c.group() ?? []) : void 0;
    const rest = c.rest();
    for (const fn of findFunctions(name[0], name[1], args)) {
      const moved = isWord(rest[0], "set") && isWord(rest[1], "schema") && isName(rest[2]);
      const renamed = isWord(rest[0], "rename") && isWord(rest[1], "to") && isName(rest[2]);
      if (moved || renamed) {
        functions.delete(functionKey(fn));
        if (moved) fn.schema = rest[2].value;
        else fn.name = rest[2].value;
        functions.set(functionKey(fn), fn);
        continue;
      }
      if (hasWords(rest, "security", "definer")) fn.securityDefiner = true;
      if (hasWords(rest, "security", "invoker")) fn.securityDefiner = false;
      if (rest.some((t, i) => isWord(t, "set") && rest[i + 1]?.value === "search_path")) fn.searchPathSet = true;
      if (rest.some((t, i) => isWord(t, "reset") && rest[i + 1]?.value === "search_path")) fn.searchPathSet = false;
    }
  }
  function findFunctions(schema, name, args) {
    if (args !== void 0) {
      const found = functions.get(functionKey({ schema, name, args }));
      return found ? [found] : [];
    }
    return [...functions.values()].filter((f) => f.schema === schema && f.name === name);
  }
  function readAlterTable(c, line) {
    c.accept("if", "exists");
    c.accept("only");
    const name = c.name();
    if (!name) return;
    const rel = relation(name[0], name[1]) ?? addRelation(name[0], name[1], "table", line, false);
    for (const action of commaSplit(c.rest())) {
      const a = new Cursor(action);
      if (a.accept("enable", "row", "level", "security")) {
        rel.rls = true;
        rel.rlsKnown = true;
      } else if (a.accept("disable", "row", "level", "security")) {
        rel.rls = false;
        rel.rlsKnown = true;
        rel.line = line;
      } else if (a.accept("add")) {
        const constraint = isWord(a.peek(), "constraint") ? a.peek(2) : a.peek();
        if (isWord(constraint, ...TABLE_CONSTRAINT_WORDS)) readConstraint(rel, a.rest());
        else {
          a.accept("column");
          a.accept("if", "not", "exists");
          const column = a.peek();
          if (isName(column) && !rel.columns.includes(column.value)) readColumn(rel, a.rest());
        }
      } else if (a.accept("alter")) {
        a.accept("column");
        const column = a.peek();
        if (!isName(column)) continue;
        a.i += 1;
        if (a.accept("set", "not", "null")) rel.notNull.add(column.value);
        else if (a.accept("set", "default")) {
          const calls = callsIn(a.rest());
          if (calls.length > 0) (rel.calls ??= []).push(...calls);
        } else if (a.accept("drop", "not", "null")) rel.notNull.delete(column.value);
        else if (a.accept("type") || a.accept("set", "data", "type")) {
          const rest = a.rest();
          const end = rest.findIndex((t) => isWord(t, "using", "collate"));
          const type = columnType(end === -1 ? rest : rest.slice(0, end));
          if (type) rel.types.set(column.value, type);
          else rel.types.delete(column.value);
        }
      } else if (a.accept("rename", "to")) {
        const to = a.peek();
        if (isName(to)) moveRelation(rel, rel.schema, to.value);
      } else if (a.accept("rename")) {
        if (a.accept("constraint")) continue;
        a.accept("column");
        const [from, to] = [a.peek(), a.peek(2)];
        if (isName(from) && isWord(a.peek(1), "to") && isName(to)) renameColumn(rel, from.value, to.value);
      } else if (a.accept("drop")) {
        if (a.accept("constraint")) continue;
        a.accept("column");
        a.accept("if", "exists");
        const column = a.peek();
        if (isName(column)) dropColumn(rel, column.value, hasWords(action, "cascade"));
      } else if (a.accept("set", "schema")) {
        const to = a.peek();
        if (isName(to)) moveRelation(rel, to.value, rel.name);
      }
    }
  }
  function readAlterPublication(c) {
    const name = c.peek()?.value;
    c.i += 1;
    if (name !== "supabase_realtime" || !c.accept("add", "table")) return;
    for (const part of commaSplit(c.rest())) {
      const p = new Cursor(part);
      p.accept("only");
      const table = p.name();
      const rel = table && relation(table[0], table[1]);
      if (rel) rel.realtime = true;
    }
  }
  function newFunctionAcl(schema) {
    const global = defaults.functionsGlobal;
    const local = defaults.functionsBySchema.get(schema);
    return {
      public: global.public || !!local?.public,
      anon: global.anon || !!local?.anon,
      authenticated: global.authenticated || !!local?.authenticated
    };
  }
  function readDefaultPrivileges(c) {
    const rest = c.rest();
    const at = rest.findIndex((t) => isWord(t, "grant", "revoke"));
    if (at === -1) return;
    const granting = rest[at].value === "grant";
    const inSchema = rest.findIndex((t, i) => isWord(t, "in") && isWord(rest[i + 1], "schema"));
    const schemas = inSchema === -1 ? void 0 : commaSplit(rest.slice(inSchema + 2, at)).map((p) => p[0]?.value);
    const on = rest.findIndex((t, i) => i > at && isWord(t, "on"));
    if (on === -1) return;
    const target = rest[on + 1]?.value;
    const privs = privilegesFrom(rest.slice(at + 1 + (isWord(rest[at + 1], "grant") ? 3 : 0), on));
    const roles = rolesAfter(rest, on + 2);
    if (target === "functions" || target === "routines") {
      if (!privs.execute && !privs.all) return;
      const apply = (acl, allowPublic) => {
        for (const role of ["public", "anon", "authenticated"]) {
          if (!roles.includes(role)) continue;
          if (role === "public" && !granting && !allowPublic) continue;
          acl[role] = granting;
        }
      };
      if (!schemas) apply(defaults.functionsGlobal, true);
      else {
        for (const schema of schemas) {
          if (!schema) continue;
          const acl = defaults.functionsBySchema.get(schema) ?? { public: false, anon: false, authenticated: false };
          apply(acl, false);
          defaults.functionsBySchema.set(schema, acl);
        }
      }
      return;
    }
    if (target !== "tables") return;
    if (schemas && !schemas.includes("public")) return;
    defaults.tables ??= { anon: new Set(COMMANDS), authenticated: new Set(COMMANDS) };
    for (const role of ["anon", "authenticated"]) {
      if (!roles.includes(role) && !roles.includes("public")) continue;
      for (const command of privs.commands) {
        if (granting) defaults.tables[role].add(command);
        else defaults.tables[role].delete(command);
      }
    }
  }
  function rolesAfter(tokens, from) {
    const out = [];
    for (let i = from; i < tokens.length; i += 1) {
      const t = tokens[i];
      if (isWord(t, "with", "granted", "cascade", "restrict")) break;
      if (isName(t) && !isWord(t, "to", "from", "group")) out.push(t.value);
    }
    return out;
  }
  function readGrant(c, granting) {
    c.accept("grant", "option", "for");
    const rest = c.rest();
    const on = rest.findIndex((t) => isWord(t, "on"));
    if (on === -1) return;
    const privs = privilegesFrom(rest.slice(0, on));
    const to = rest.findIndex((t, i) => i > on && isWord(t, granting ? "to" : "from"));
    if (to === -1) return;
    const roles = rolesAfter(rest, to + 1);
    const target = new Cursor(rest.slice(on + 1, to));
    if (target.accept("schema")) {
      if (!privs.usage && !privs.all) return;
      for (const part of commaSplit(target.rest())) {
        const schema = part[0]?.value;
        if (!schema || SYSTEM_SCHEMAS.has(schema)) continue;
        if (granting && (roles.includes("anon") || roles.includes("authenticated"))) exposed.add(schema);
      }
      return;
    }
    if (target.accept("function") || target.accept("routine")) {
      for (const part of splitFunctionList(target.rest())) {
        const p = new Cursor(part);
        const name = p.name();
        if (!name) continue;
        const args = isOp(p.peek(), "(") ? argTypes(p.group() ?? []) : void 0;
        for (const fn of findFunctions(name[0], name[1], args)) applyExecute(fn, roles, granting && (privs.execute || privs.all), granting);
      }
      return;
    }
    if (target.accept("all", "functions", "in", "schema") || target.accept("all", "routines", "in", "schema")) {
      const schemas = commaSplit(target.rest()).map((p) => p[0]?.value);
      for (const fn of functions.values()) if (schemas.includes(fn.schema)) applyExecute(fn, roles, granting, granting);
      return;
    }
    let tables = [];
    if (target.accept("all", "tables", "in", "schema")) {
      const schemas = commaSplit(target.rest()).map((p) => p[0]?.value);
      tables = [...catalog.relations.values()].filter((r) => schemas.includes(r.schema));
    } else {
      target.accept("table");
      for (const part of commaSplit(target.rest())) {
        const p = new Cursor(part);
        p.accept("only");
        const name = p.name();
        const rel = name && relation(name[0], name[1]);
        if (rel) tables.push(rel);
      }
    }
    for (const rel of tables) {
      const grants = ensureGrants(rel);
      for (const role of ["anon", "authenticated"]) {
        if (!roles.includes(role) && !roles.includes("public")) continue;
        if (!granting && !roles.includes(role)) continue;
        for (const command of privs.commands) {
          if (granting) grants[role].add(command);
          else grants[role].delete(command);
        }
      }
    }
  }
  function applyExecute(fn, roles, allow, granting) {
    const acl = fn.acl ??= { public: true, anon: true, authenticated: true };
    for (const role of ["public", "anon", "authenticated"]) {
      if (roles.includes(role)) acl[role] = granting ? allow || acl[role] : false;
    }
    fn.anon = acl.public || acl.anon;
    fn.authenticated = acl.public || acl.authenticated;
  }
  function readDrop(c) {
    if (c.accept("policy")) {
      c.accept("if", "exists");
      const name = c.peek();
      if (!isName(name)) return;
      c.i += 1;
      if (!c.accept("on")) return;
      const table = c.name();
      if (!table) return;
      policies.delete(policyKey(table[0], table[1], name.value));
      return;
    }
    if (c.accept("function")) {
      c.accept("if", "exists");
      for (const part of splitFunctionList(c.rest())) {
        const p = new Cursor(part);
        const name = p.name();
        if (!name) continue;
        const args = isOp(p.peek(), "(") ? argTypes(p.group() ?? []) : void 0;
        for (const fn of findFunctions(name[0], name[1], args)) functions.delete(functionKey(fn));
      }
      return;
    }
    if (c.accept("table") || c.accept("view") || c.accept("materialized", "view") || c.accept("foreign", "table")) {
      c.accept("if", "exists");
      const gone = [];
      for (const part of commaSplit(c.rest())) {
        const p = new Cursor(part);
        const name = p.name();
        if (!name) continue;
        dropRelation(name[0], name[1]);
        gone.push(key(name[0], name[1]));
      }
      if (!hasWords(c.rest(), "cascade")) return;
      for (let i = 0; i < gone.length; i += 1) {
        for (const rel of [...catalog.relations.values()]) {
          if (rel.kind !== "view" && rel.kind !== "matview" || !rel.query) continue;
          if (!viewReads(rel.query).tables.some(([schema, table]) => key(schema ?? "public", table) === gone[i])) continue;
          dropRelation(rel.schema, rel.name);
          gone.push(key(rel.schema, rel.name));
        }
      }
    }
  }
  function dropRelation(schema, name) {
    catalog.relations.delete(key(schema, name));
    for (const [id, x] of policies) if (x.schema === schema && x.table === name) policies.delete(id);
  }
  function readInsert(c) {
    const table = c.name();
    if (!table || table[0] !== "storage" || table[1] !== "buckets") return;
    const columns = (c.group() ?? []).filter(isName).map((t) => t.value);
    if (!c.accept("values")) return;
    while (isOp(c.peek(), "(")) {
      const row = commaSplit(c.group() ?? []);
      const value = (column) => row[columns.indexOf(column)]?.[0];
      const id = value("id") ?? value("name");
      if (id?.kind === "string") {
        const pub = value("public");
        catalog.buckets.set(id.value, { id: id.value, public: !!pub && (pub.value === "true" || pub.value === "t") });
      }
      if (!c.acceptOp(",")) break;
    }
  }
}
function hasWords(tokens, ...words) {
  return tokens.some((_, i) => words.every((w, k) => isWord(tokens[i + k], w)));
}
var MULTI_WORD_TYPE = /^(double precision|character varying|bit varying|national character|time with|time without|timestamp with|timestamp without|interval )/;
var TYPE_ALIASES = {
  int: "integer",
  int4: "integer",
  int8: "bigint",
  int2: "smallint",
  float8: "double precision",
  float4: "real",
  bool: "boolean",
  varchar: "character varying",
  char: "character",
  timestamptz: "timestamp with time zone",
  timestamp: "timestamp without time zone",
  timetz: "time with time zone",
  time: "time without time zone",
  decimal: "numeric"
};
var isArgMode = (t) => isWord(t, "in", "out", "inout", "variadic");
function argTypes(tokens) {
  return commaSplit(tokens).map((arg) => {
    let parts = arg;
    const cut = parts.findIndex((t) => isWord(t, "default") || isOp(t, "="));
    if (cut !== -1) parts = parts.slice(0, cut);
    const at = isArgMode(parts[0]) ? 0 : isName(parts[0]) && isArgMode(parts[1]) ? 1 : -1;
    let end = at;
    while (at !== -1 && isArgMode(parts[end])) end += 1;
    const mode = at === -1 ? "in" : parts.slice(at, end).map((t) => t.value).join(" ");
    if (mode === "out") return "";
    if (at !== -1) parts = [...parts.slice(0, at), ...parts.slice(end)];
    if (parts.length > 1 && isName(parts[0]) && isName(parts[1]) && !MULTI_WORD_TYPE.test(`${canon(parts).replace(/"/g, "")} `)) {
      parts = parts.slice(1);
    }
    const match = pairs(parts);
    const kept = [];
    for (let i = 0; i < parts.length; i += 1) {
      if (isOp(parts[i], "(") && match[i] !== -1) i = match[i];
      else kept.push(parts[i]);
    }
    let type = canon(kept).replace(/^(pg_catalog|public)\./, "");
    const array = type.endsWith("[]") ? "[]" : "";
    if (array) type = type.slice(0, -2);
    return (TYPE_ALIASES[type] ?? type) + array;
  }).filter((a) => a !== "").join(", ");
}
function splitFunctionList(tokens) {
  return commaSplit(tokens);
}
function dropTarget(text) {
  const parts = text.trim().split(".");
  if (parts.length > 2) return void 0;
  const filled = (part) => /^%(?:\d+\$)?-?[Is]$/.test(part.trim());
  const name = (part) => {
    const tokens = tokenize(part);
    return tokens.length === 1 && isName(tokens[0]) ? tokens[0].value : null;
  };
  const read = (part) => filled(part) ? void 0 : name(part);
  const table = read(parts.at(-1));
  const schema = parts.length === 2 ? read(parts[0]) : table === void 0 ? void 0 : "public";
  if (table === null || schema === null) return void 0;
  return [schema, table];
}
var KINDS = { r: "table", p: "table", v: "view", m: "matview", f: "foreign" };
var CMD = { ALL: "all", SELECT: "select", INSERT: "insert", UPDATE: "update", DELETE: "delete" };
function unwrapJson(text) {
  let value;
  const trimmed = text.trim();
  try {
    value = JSON.parse(trimmed);
  } catch {
    const start = trimmed.indexOf("{");
    const end = trimmed.lastIndexOf("}");
    if (start === -1 || end === -1) throw new Error("That isn\u2019t SQL or the JSON the query returns.");
    const body = trimmed.slice(start, end + 1);
    value = JSON.parse(body.includes('""') ? body.replace(/""/g, '"') : body);
  }
  for (let depth = 0; depth < 4; depth += 1) {
    if (typeof value === "string") value = JSON.parse(value);
    else if (Array.isArray(value)) value = value[0];
    else if (value && typeof value === "object" && !("relations" in value)) {
      const inner = value.supabase_rls_check;
      if (inner && typeof inner === "object") value = inner;
      else if (typeof inner === "string") value = JSON.parse(inner);
      else break;
    } else break;
  }
  if (!value || typeof value !== "object" || !Array.isArray(value.relations)) {
    throw new Error("This JSON isn\u2019t what the query returns. Copy the single value in the result, all of it.");
  }
  return value;
}
var strings = (v) => Array.isArray(v) ? v.map(String) : typeof v === "string" ? v.replace(/^\{|\}$/g, "").split(",").filter(Boolean) : [];
function columnTypes(v) {
  const out = /* @__PURE__ */ new Map();
  if (!v || typeof v !== "object" || Array.isArray(v)) return out;
  for (const [column, type] of Object.entries(v)) {
    if (typeof type !== "string") continue;
    const name = columnType(tokenize(type));
    if (name) out.set(column, name);
  }
  return out;
}
function foreignKeys(v) {
  const out = /* @__PURE__ */ new Map();
  if (!v || typeof v !== "object" || Array.isArray(v)) return out;
  for (const [column, target] of Object.entries(v)) {
    if (Array.isArray(target) && target.length === 3) out.set(column, target.map(String));
  }
  return out;
}
function readJson(text) {
  const data = unwrapJson(text);
  const catalog = emptyCatalog("json");
  catalog.exposed = String(data.exposed ?? "public").split(",").map((s) => s.trim().replace(/^"|"$/g, "")).filter(Boolean);
  const exprOf = (v) => typeof v === "string" && v.trim() !== "" ? { tokens: tokenize(v) } : void 0;
  for (const r of data.relations) {
    const kind = KINDS[String(r.kind)];
    if (!kind) continue;
    const options = strings(r.options).map((o) => o.toLowerCase());
    const rel = {
      schema: String(r.schema),
      name: String(r.name),
      kind,
      rls: r.rls === true,
      rlsKnown: true,
      created: true,
      columns: strings(r.columns),
      // Older copies of the query's result have no types: they stay unknown.
      types: columnTypes(r.column_types),
      notNull: new Set(strings(r.not_null)),
      userRefs: new Set(strings(r.user_refs)),
      refs: foreignKeys(r.refs),
      indexed: new Set(strings(r.indexed)),
      securityInvoker: options.some((o) => /^security_invoker=(1|true|yes|on)$/.test(o)),
      query: typeof r.definition === "string" ? tokenize(r.definition) : void 0,
      grants: {
        anon: new Set(strings(r.anon).map((s) => s.toLowerCase())),
        authenticated: new Set(strings(r.authenticated).map((s) => s.toLowerCase()))
      },
      realtime: r.realtime === true
    };
    catalog.relations.set(key(rel.schema, rel.name), rel);
  }
  for (const p of Array.isArray(data.policies) ? data.policies : []) {
    catalog.policies.push({
      schema: String(p.schema),
      table: String(p.table),
      name: String(p.name),
      permissive: String(p.permissive).toUpperCase() !== "RESTRICTIVE",
      command: CMD[String(p.cmd).toUpperCase()] ?? "all",
      roles: strings(p.roles),
      using: exprOf(p.qual),
      check: exprOf(p.with_check)
    });
  }
  for (const f of Array.isArray(data.functions) ? data.functions : []) {
    catalog.functions.push({
      schema: String(f.schema),
      name: String(f.name),
      args: String(f.args ?? ""),
      returnsTrigger: /^(event_)?trigger$/i.test(String(f.returns ?? "").trim()),
      securityDefiner: f.security_definer === true,
      searchPathSet: strings(f.config).some((c) => c.startsWith("search_path=")),
      anon: f.anon === true,
      authenticated: f.authenticated === true,
      // Older copies of the query's result don't say.
      calledBy: Array.isArray(f.called_by) ? strings(f.called_by) : void 0,
      usedBy: Array.isArray(f.used_by) ? strings(f.used_by) : void 0
    });
  }
  for (const b of Array.isArray(data.buckets) ? data.buckets : []) {
    catalog.buckets.set(String(b.id), { id: String(b.id), public: b.public === true });
  }
  catalog.statements = catalog.relations.size;
  return catalog;
}
var SENSITIVE = /* @__PURE__ */ new Set([
  "password",
  "passwd",
  "pwd",
  "passphrase",
  "secret",
  "secret_key",
  "private_key",
  "api_key",
  "apikey",
  "auth_key",
  "token",
  "jwt",
  "access_token",
  "refresh_token",
  "oauth_token",
  "session_token",
  "bearer_token",
  "auth_code",
  "session_id",
  "session_key",
  "session_secret",
  "recovery_code",
  "backup_code",
  "verification_code",
  "otp",
  "two_factor",
  "2fa_secret",
  "2fa_code",
  "ssn",
  "social_security",
  "social_security_number",
  "driver_license",
  "drivers_license",
  "license_number",
  "passport_number",
  "passport_id",
  "national_id",
  "tax_id",
  "credit_card",
  "card_number",
  "cvv",
  "cvc",
  "cvn",
  "bank_account",
  "account_number",
  "routing_number",
  "iban",
  "swift_code",
  "bic",
  "health_record",
  "medical_record",
  "patient_id",
  "insurance_number",
  "health_insurance",
  "medical_insurance",
  "treatment",
  "mac_address",
  "macaddr",
  "imei",
  "device_uuid",
  "pgp_key",
  "gpg_key",
  "ssh_key",
  "certificate",
  "license_key",
  "activation_key",
  "facial_recognition"
]);
var sensitiveColumns = (columns) => columns.filter((c) => SENSITIVE.has(c.toLowerCase().replace(/-/g, "_")));
var appliesTo = (policy, role) => policy.roles.includes("public") || policy.roles.includes(role);
var covers = (policy, command) => policy.command === "all" || policy.command === command;
function clauseFor(policy, command) {
  if (command === "insert") return policy.check ?? (policy.command === "all" ? policy.using : void 0);
  return policy.using;
}
var RANK = { none: 0, own: 1, some: 2, all: 3 };
function needsUser(tokens, depth = 0) {
  if (depth > 32) return false;
  const t = unwrap(tokens);
  const ors = splitTop(t, "or");
  if (ors.length > 1) return ors.every((part) => needsUser(part, depth + 1));
  const ands = splitTop(t, "and");
  if (ands.length > 1) return ands.some((part) => needsUser(part, depth + 1));
  return truthOf(t) === "signed" || ownerColumns({ tokens: t }).length > 0;
}
function classify(expr, role) {
  if (!expr) return "none";
  let best = "none";
  for (const branch of splitTop(unwrap(expr.tokens), "or")) {
    const truth = truthOf(branch);
    const reach = truth === "true" ? "all" : truth === "signed" ? role === "anon" ? "none" : "all" : needsUser(branch) ? role === "anon" ? "none" : "own" : "some";
    if (RANK[reach] > RANK[best]) best = reach;
  }
  return best;
}
function reachOf(rel, policies, command, role) {
  if (rel.grants && !rel.grants[role].has(command)) return "none";
  if (rel.kind === "view") return rel.securityInvoker ? "some" : command === "select" ? "all" : "some";
  if (rel.kind === "foreign") return "all";
  if (rel.kind !== "table") return command === "select" ? "all" : "none";
  if (!rel.rls) return "all";
  const applicable = policies.filter((p) => covers(p, command) && appliesTo(p, role));
  const permissive = applicable.filter((p) => p.permissive);
  if (permissive.length === 0) return "none";
  let best = "none";
  for (const p of permissive) {
    const reach = classify(clauseFor(p, command), role);
    if (RANK[reach] > RANK[best]) best = reach;
  }
  if (best === "all" && applicable.some((p) => !p.permissive && clauseFor(p, command))) best = "some";
  return best;
}
var VERB = { select: "read", insert: "add", update: "change", delete: "delete" };
var OWNER_NAMES = ["user_id", "userId", "owner_id", "ownerId", "created_by", "createdBy", "author_id", "authorId", "profile_id"];
var UID = "(select auth.uid())";
var SUB = "(select auth.jwt() ->> 'sub')";
var EMAIL = "(select auth.jwt() ->> 'email')";
function pointsAtUser(rel, column, relations) {
  if (rel.userRefs.has(column)) return true;
  const target = rel.refs.get(column);
  return !!target && !!relations?.get(key(target[0], target[1]))?.userRefs.has(target[2]);
}
function ownerOf(rel, policies, relations) {
  const columns = rel?.columns ?? [];
  const exists = (c) => columns.length === 0 || columns.includes(c);
  const byName = (list2) => OWNER_NAMES.filter((n) => list2.includes(n));
  const compared = (who2) => [...new Set(policies.flatMap((p) => [...ownerColumns(p.using, who2), ...ownerColumns(p.check, who2)]))].filter(exists);
  let pick = compared("id");
  const who = pick.length === 0 && compared("email").length > 0 ? "email" : "id";
  if (who === "email") pick = compared("email");
  let skipped;
  let suggest;
  if (pick.length === 0 && rel) {
    const refs = [...rel.userRefs];
    pick = refs.length > 1 && byName(refs).length === 1 ? byName(refs) : refs;
    if (pick.length === 0) {
      const named = byName(columns);
      pick = named.filter((c) => c !== "profile_id" || pointsAtUser(rel, c, relations)).slice(0, 1);
      const target = rel.refs.get("profile_id");
      if (pick.length === 0 && named.includes("profile_id")) {
        skipped = target ? `profile_id points at ${target[0]}.${target[1]}, not at a user id.` : "profile_id may hold a profile\u2019s id, not a user id.";
        const users = target ? [...relations?.get(key(target[0], target[1]))?.userRefs ?? []] : [];
        if (target && users.length === 1) {
          const profiles = qualifiedName(target[0], target[1]);
          suggest = {
            test: `profile_id in (select ${identifier(target[2])} from ${profiles} where ${identifier(users[0])} = ${UID})`,
            via: `${profiles}.${identifier(users[0])}`
          };
        }
      }
    }
    const userKeyed = ["profiles", "users", "accounts"].includes(rel.name) && columns.includes("id");
    if (pick.length === 0 && userKeyed && (rel.types.get("id") === "uuid" || rel.userRefs.has("id"))) pick = ["id"];
  }
  if (pick.length === 0) {
    if (skipped) return { reason: skipped, suggest };
    return columns.length === 0 ? { reason: "The checker can\u2019t see this table\u2019s columns." } : { reason: "No column says who owns each row.", none: true };
  }
  if (pick.length > 1) return { reason: `More than one column could hold the owner: ${pick.join(", ")}.` };
  const column = pick[0];
  const type = rel?.types.get(column);
  const nullable = !rel?.notNull.has(column);
  const textual = type === "text" || type === "character varying";
  if (who === "email") {
    if (type !== void 0 && !textual) return { reason: `${column} holds ${type} values, not emails.` };
    return { owner: { column: identifier(column), caller: EMAIL, nullable, who } };
  }
  const caller = type === void 0 || type === "uuid" ? UID : textual ? SUB : void 0;
  if (!caller) return { reason: `${column} holds ${type} values, not Supabase user ids.` };
  return { owner: { column: identifier(column), caller, nullable, who } };
}
var ACCESS_TABLE = /(^|_)(members?|memberships?|roles?|participants?|collaborators?|admins?|moderators?|permissions?)$/i;
var loose = (expr) => alwaysTrue(expr) || signedInOnly(expr);
function ownerFix(p, pick, taken) {
  const owner = pick.owner ?? { column: pick.none ? "user_id" : "<owner column>", caller: UID, nullable: !!pick.none, who: "id" };
  if (ACCESS_TABLE.test(p.table) && p.command !== "delete" && pick.owner) return accessTableFix(p, owner);
  const test = pick.suggest?.test ?? `${owner.caller} = ${owner.column}`;
  const insertClause = clauseFor(p, "insert");
  const anonInsert = (p.command === "insert" || p.command === "all") && appliesTo(p, "anon") && loose(insertClause) && classify(insertClause, "anon") !== "none";
  const insertTest = anonInsert && owner.nullable ? `${owner.column} is null or ${test}` : test;
  const tighten = (expr, t) => {
    if (!expr) return t;
    const tokens = unwrap(expr.tokens);
    if (splitTop(tokens, "or").length === 1) return t;
    return `(${fixText(tokens)}) and ${t === test ? t : `(${t})`}`;
  };
  const notes = [];
  const edit = policyEdit(p, "security");
  if (p.command === "insert") edit.check = tighten(p.check, insertTest);
  else if (p.command === "update") {
    if (loose(p.using)) edit.using = tighten(p.using, test);
    if (p.check ? loose(p.check) : edit.using !== void 0) edit.check = p.check ? tighten(p.check, test) : edit.using;
  } else if (p.command === "delete") edit.using = tighten(p.using, test);
  else if (p.command === "all") {
    const keep = (e) => e && fixText(e.tokens);
    const write = (e, t) => loose(e) ? tighten(e, t) : keep(e);
    const insert = write(p.check ?? p.using, insertTest);
    const update = write(p.using, test);
    const updateCheck = p.check ? write(p.check, test) : update;
    const remove = write(p.using, test);
    const free = (word) => {
      let name = pgName(p.name, ` (${word})`);
      for (let i = 2; taken.has(name); i += 1) name = pgName(p.name, ` (${word} ${i})`);
      return name;
    };
    const create = (name, command, using, check) => createPolicySql(p.schema, p.table, name, command, rolesFor(p.roles, using, check), using, check, name !== p.name);
    edit.replaceWith = [
      // The policy's own name now holds only the read rule. fixScript drops the old policy just before.
      create(p.name, "select", keep(p.using)),
      create(free("insert"), "insert", void 0, insert),
      create(free("update"), "update", update, updateCheck),
      create(free("delete"), "delete", remove)
    ].join("\n");
    notes.push("Split by command: reading keeps its rule, and adding, changing and deleting need the row to be the user\u2019s.");
    if ((mentionsUserMetadata(p.using) || mentionsUserMetadata(p.check)) && appMetadata(p.using?.tokens ?? []) && appMetadata(p.check?.tokens ?? [])) {
      notes.push(`It reads app_metadata instead of user_metadata. ${appMetadataNote([...p.using?.tokens ?? [], ...p.check?.tokens ?? []])}`);
    }
  }
  if (p.command !== "all") {
    const changes = (c) => c === "insert" ? edit.check !== void 0 && insertTest === test : c === "update" ? (edit.using ?? edit.check) !== void 0 : c === "delete" && edit.using !== void 0;
    const changed = COMMANDS.filter((c) => covers(p, c) && changes(c));
    const theirs = owner.who === "email" ? "their email" : "their user id";
    if (changed.length > 0) notes.push(`After this, users can only ${andList(changed.map((c) => VERB[c]))} rows where ${owner.column} is ${theirs}.`);
  }
  const formOnly = anonInsert && p.command === "insert";
  if (anonInsert && pick.owner && (owner.nullable || !formOnly)) {
    notes.push(owner.nullable ? `Signed-out visitors can still add rows, with ${owner.column} left empty.` : "Signed-out visitors can\u2019t add rows after this.");
  }
  if (notes.length > 0) edit.note = notes.join("\n");
  if (pick.owner && !(formOnly && !owner.nullable)) return policyFix([edit]);
  if (pick.owner) {
    const why2 = [
      `Signed-out visitors can add rows through this policy. After this fix they can\u2019t, because ${owner.column} can\u2019t be empty.`,
      "Run it only if they shouldn\u2019t add rows here."
    ];
    return { manual: true, fix: commentOut(`${commentLines(why2.join("\n"))}
${policySql(edit)}`) };
  }
  edit.note = void 0;
  const q = qualifiedName(p.schema, p.table);
  const why = [
    `The checker can\u2019t tie these rows to a user. ${pick.reason}`,
    ...formOnly ? ["If anyone may add rows here, as with a contact form or a waitlist,", "leave this policy as it is."] : [],
    ...pick.none ? anonInsert ? ["To give each row an owner, add a column for it, then tie the policy to it.", "Signed-out visitors can still add rows then, with user_id left empty:"] : ["To give each row an owner, add a column for it, then tie the policy to it:"] : pick.suggest ? [`If ${pick.suggest.via} holds each profile\u2019s user, this ties rows to it. Check that, then run:`] : ["Put the owner column in place of <owner column>, then run:"]
  ];
  const add = pick.none ? `alter table ${q} add column if not exists user_id uuid default auth.uid() references auth.users (id);
` : "";
  return { manual: true, fix: commentOut(`${commentLines(why.join("\n"))}
${add}${policySql(edit)}`) };
}
function accessTableFix(p, owner) {
  const why = [
    `Rows in ${qualifiedName(p.schema, p.table)} give people access, such as a place in a team or a role.`,
    `Requiring ${owner.column} to be the user\u2019s own isn\u2019t enough: anyone could still add`,
    "themselves, with any role, and nobody could add anyone else. Write a condition",
    "that checks the user may manage it, such as being an admin of the team, then run:"
  ];
  const edit = policyEdit(p, "security");
  if (p.command !== "insert") edit.using = "<your condition>";
  if (p.command !== "delete") edit.check = "<your condition>";
  return { manual: true, fix: commentOut(`${commentLines(why.join("\n"))}
${policySql(edit)}`) };
}
function rolesFor(roles, ...conditions) {
  const given = conditions.filter((c) => c !== void 0);
  const needsUser2 = given.length > 0 && given.every((c) => classify({ tokens: tokenize(c) }, "anon") === "none");
  return roles.length === 1 && roles[0] === "public" && needsUser2 ? ["authenticated"] : roles;
}
function createPolicySql(schema, table, name, command, roles, using, check, drop = true) {
  const target = `${identifier(name)} on ${qualifiedName(schema, table)}`;
  const lines = [
    drop ? `drop policy if exists ${target};` : "",
    `create policy ${target} for ${command}`,
    `  to ${roles.map(roleName).join(", ")}`,
    using !== void 0 ? `  using (${using})` : "",
    check !== void 0 ? `  with check (${check})` : ""
  ];
  return `${lines.filter(Boolean).join("\n")};`;
}
var orList = (items) => items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} or ${items.at(-1)}`;
var andList = (items) => items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;
function rlsOnFix(rel, policies, relations) {
  if (policies.length > 0) {
    const reached = (c) => policies.some((p) => p.permissive && covers(p, c) && !!clauseFor(p, c) && (appliesTo(p, "anon") || appliesTo(p, "authenticated")));
    const missing = COMMANDS.filter((c) => !reached(c)).map((c) => VERB[c]);
    const lines = ["Its policies take effect now. Any fixes they need are in this script too."];
    if (missing.length > 0) lines.push(`No policy lets the app ${orList(missing)} rows here, so it can\u2019t until you add one.`);
    return commentLines(lines.join("\n"));
  }
  const pick = ownerOf(rel, [], relations);
  if (pick.owner) {
    const test = `${pick.owner.caller} = ${pick.owner.column}`;
    const own = (c) => createPolicySql(rel.schema, rel.name, pgName(rel.name, `_${c}_own`), c, ["authenticated"], c === "insert" ? void 0 : test, c === "insert" || c === "update" ? test : void 0);
    return [
      "-- With RLS on, the app reaches only the rows a policy allows. These let each",
      "-- signed-in user read, add, change and delete their own rows. If other users",
      "-- should see these rows, change the select policy (Generate policies writes the full set).",
      ...COMMANDS.map(own)
    ].join("\n");
  }
  const example = createPolicySql(rel.schema, rel.name, pgName(rel.name, "_select"), "select", ["authenticated"], "true", void 0, false);
  return [
    "-- After this, the Data API returns no rows from it, and can\u2019t change it, until you",
    "-- add policies. That\u2019s right if only server code uses it.",
    `-- The checker can\u2019t add policies for each user\u2019s own rows. ${comment(pick.reason)}`,
    "-- Add one for each thing the app does. For example, so signed-in users can read",
    "-- every row:",
    commentOut(example)
  ].join("\n");
}
var policyEdit = (p, priority) => ({
  kind: "policy",
  schema: p.schema,
  table: p.table,
  name: p.name,
  priority
});
var roleName = (role) => role === "public" ? "public" : identifier(role);
var commentLines = (text) => text.split("\n").map((line) => `-- ${comment(line)}`.trimEnd()).join("\n");
var commentOut = (sql) => sql.split(/\r\n|\r|\n/).map((line) => line.trimStart().startsWith("--") ? line : `-- ${line}`.trimEnd()).join("\n");
function policySql(e) {
  const target = `${identifier(e.name)} on ${qualifiedName(e.schema, e.table)}`;
  const note = e.note ? `${commentLines(e.note)}
` : "";
  if (e.drop) return `${note}drop policy if exists ${target};`;
  if (e.replaceWith !== void 0) return `${note}drop policy if exists ${target};
${e.replaceWith}`;
  const parts = [
    e.roles ? `to ${e.roles.map(roleName).join(", ")}` : "",
    e.using !== void 0 ? `using (${e.using})` : "",
    e.check !== void 0 ? `with check (${e.check})` : ""
  ].filter(Boolean);
  if (parts.length === 0) return note.trimEnd();
  return `${note}alter policy ${target}
  ${parts.join("\n  ")};`;
}
var policyFix = (edits) => ({ fix: edits.map(policySql).join("\n"), edits });
function wrapAuthCalls(condition) {
  const tokens = tokenize(condition);
  const calls = authCalls(tokens);
  return calls.some((c) => !c.wrapped) ? wrapCalls(tokens, calls) : condition;
}
function mergePolicyEdits(edits) {
  const security = edits.filter((e) => e.priority === "security");
  const speed = edits.filter((e) => e.priority === "speed");
  const ranked = [...security, ...speed];
  const base = policyEdit(edits[0], security.length > 0 ? "security" : "speed");
  const notes = (list2) => [...new Set(list2.map((e) => e.note).filter((n) => !!n))].join("\n") || void 0;
  const drops = ranked.filter((e) => e.drop);
  if (drops.length > 0) return { ...base, drop: true, note: notes(drops) };
  const replacement = ranked.find((e) => e.replaceWith !== void 0);
  if (replacement) return { ...base, replaceWith: replacement.replaceWith, note: replacement.note };
  const wrap2 = speed.some((e) => e.using !== void 0 || e.check !== void 0);
  const clause = (pick) => {
    const all = [...new Set(security.map(pick).filter((c) => c !== void 0))];
    const rewrites = all.filter((c) => !all.some((other) => other.startsWith(`(${c}) and `)));
    if (rewrites.length === 0) return speed.map(pick).find((c) => c !== void 0);
    const text = rewrites.length === 1 ? rewrites[0] : rewrites.map((c) => `(${c})`).join(" and ");
    return wrap2 ? wrapAuthCalls(text) : text;
  };
  return {
    ...base,
    using: clause((e) => e.using),
    check: clause((e) => e.check),
    roles: (security.find((e) => e.roles) ?? speed.find((e) => e.roles))?.roles,
    note: notes(ranked)
  };
}
var literal2 = (text) => `'${text.replace(/'/g, "''")}'`;
var SEARCH_PATH = "public, extensions, pg_temp";
var SEARCH_PATH_NOTE = "Names in it without a schema still find public and extensions. Once every name in it\nhas its schema, such as public.profiles, search_path = '' is stricter.";
var HELPER_SCHEMAS = ["private", "app_private"];
var functionTarget = (e) => `${qualifiedName(e.schema, e.name)}(${e.args})`;
var argCount = (args) => args.trim() === "" ? 0 : commaSplit(tokenize(args)).length;
function argCountAt(tokens, open, match) {
  const close = match[open] === -1 ? tokens.length : match[open];
  return close === open + 1 ? 0 : commaSplit(tokens.slice(open + 1, close)).length;
}
function dollarTag(body) {
  let tag = "$fix$";
  for (let i = 2; body.includes(tag); i += 1) tag = `$fix${i}$`;
  return tag;
}
function functionSql(e, schema = true) {
  const target = functionTarget(e);
  const lines = e.note ? [commentLines(e.note)] : [];
  const searchPath = e.searchPath ? `alter function ${target} set search_path = ${e.searchPath};` : "";
  if (e.moveTo) {
    const body = [
      "begin",
      "  -- Skipped once it has moved, so the script can run again.",
      `  if to_regprocedure(${literal2(target)}) is not null then`,
      ...searchPath ? [`    ${searchPath}`] : [],
      `    alter function ${target} set schema ${identifier(e.moveTo)};`,
      "  end if;",
      "end"
    ].join("\n");
    const tag = dollarTag(body);
    if (schema) lines.push(`create schema if not exists ${identifier(e.moveTo)};`);
    lines.push(`do ${tag}
${body}
${tag};`);
  } else {
    if (searchPath) lines.push(searchPath);
    if (e.revokeFrom && e.revokeFrom.length > 0) lines.push(`revoke execute on function ${target} from ${e.revokeFrom.map(roleName).join(", ")};`);
  }
  if (e.optional) lines.push(commentOut(e.optional));
  return lines.join("\n");
}
var functionFix = (edits) => ({ fix: edits.map((e) => functionSql(e)).join("\n"), edits });
function mergeFunctionEdits(edits) {
  const { schema, name, args } = edits[0];
  const moveTo = edits.find((e) => e.moveTo)?.moveTo;
  const revokeFrom = [...new Set(edits.flatMap((e) => e.revokeFrom ?? []))];
  const notes = [...new Set(edits.map((e) => e.note).filter((n) => !!n))];
  return {
    kind: "function",
    schema,
    name,
    args,
    searchPath: edits.find((e) => e.searchPath)?.searchPath,
    moveTo,
    callArgs: edits.find((e) => e.moveTo)?.callArgs,
    revokeFrom: moveTo || revokeFrom.length === 0 ? void 0 : revokeFrom,
    optional: moveTo ? void 0 : edits.find((e) => e.optional)?.optional,
    note: notes.join("\n") || void 0
  };
}
function callAt(tokens, i, fn) {
  const t = tokens[i];
  if (!isName(t) || t.value !== fn.name || !isOp(tokens[i + 1], "(")) return false;
  if (!isOp(tokens[i - 1], ".")) return fn.schema === "public";
  return isName(tokens[i - 2]) && tokens[i - 2].value === fn.schema && !isOp(tokens[i - 3], ".");
}
function renameCalls(sql, moved, used) {
  if (moved.length === 0) return sql;
  const tokens = tokenize(sql);
  const match = pairs(tokens);
  let out = "";
  let at = 0;
  for (let i = 0; i < tokens.length; i += 1) {
    const fn = moved.find((m) => callAt(tokens, i, m) && (m.callArgs === void 0 || argCountAt(tokens, i + 1, match) === m.callArgs));
    if (!fn) continue;
    used?.add(fn);
    const start = (isOp(tokens[i - 1], ".") ? tokens[i - 2] : tokens[i]).offset;
    out += `${sql.slice(at, start)}${identifier(fn.moveTo)}.${identifier(fn.name)}`;
    at = tokens[i].offset + tokens[i].text.length;
  }
  return out + sql.slice(at);
}
var FROM_ENDS = /* @__PURE__ */ new Set([
  "where",
  "group",
  "order",
  "limit",
  "offset",
  "fetch",
  "having",
  "window",
  "join",
  "inner",
  "left",
  "right",
  "full",
  "cross",
  "natural",
  "on",
  "using",
  "union",
  "except",
  "intersect",
  "for",
  "tablesample",
  "lateral",
  "with",
  "returning"
]);
var NOT_CALLS = /* @__PURE__ */ new Set(["in", "exists", "any", "all", "some", "from", "join", "lateral", "as", "on", "and", "or", "not", "where", "when", "then", "else", "using", "array", "union", "except", "intersect"]);
function viewReads(tokens) {
  const match = pairs(tokens);
  const tables = [];
  let unknown = false;
  const named = new Set(tokens.filter((t, i) => isName(t) && isWord(tokens[i + 1], "as") && (isOp(tokens[i + 2], "(") || isWord(tokens[i + 2], "materialized", "not"))).map((t) => t.value));
  const readItems = (j) => {
    for (let guard = 0; guard < tokens.length && j < tokens.length; guard += 1) {
      while (isOp(tokens[j], "(") && !isWord(tokens[j + 1], "select", "with", "values")) j += 1;
      while (isWord(tokens[j], "only", "lateral")) j += 1;
      if (isOp(tokens[j], "(")) j = match[j] === -1 ? tokens.length : match[j] + 1;
      else if (isName(tokens[j]) && !(tokens[j].kind === "word" && FROM_ENDS.has(tokens[j].value))) {
        let schema;
        let table = tokens[j].value;
        if (isOp(tokens[j + 1], ".") && isName(tokens[j + 2])) {
          schema = table;
          table = tokens[j + 2].value;
          j += 2;
        }
        j += 1;
        if (isOp(tokens[j], "(")) {
          unknown = true;
          j = match[j] === -1 ? tokens.length : match[j] + 1;
        } else if (schema !== void 0 || !named.has(table)) tables.push([schema, table]);
      } else return;
      if (isWord(tokens[j], "as")) j += 1;
      if (isName(tokens[j]) && !(tokens[j].kind === "word" && FROM_ENDS.has(tokens[j].value))) {
        j += 1;
        if (isOp(tokens[j], "(")) j = match[j] === -1 ? tokens.length : match[j] + 1;
      }
      if (!isOp(tokens[j], ",")) return;
      j += 1;
    }
  };
  const calls = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (isOp(t, "(")) {
      const prev = tokens[i - 1];
      calls.push(isName(prev) && !(prev.kind === "word" && NOT_CALLS.has(prev.value)) && !isWord(tokens[i + 1], "select", "with", "values"));
    } else if (isOp(t, ")")) calls.pop();
    else if (isWord(t, "from", "join") && !calls.at(-1)) {
      if (isWord(t, "from") && isWord(tokens[i - 1], "distinct")) continue;
      readItems(i + 1);
    }
  }
  return { tables, unknown };
}
function storageScope(expr) {
  if (!expr) return void 0;
  let bucket;
  let signedIn = false;
  for (const part of splitTop(unwrap(expr.tokens), "and")) {
    const truth = truthOf(part);
    if (truth === "true") continue;
    if (truth === "signed") {
      signedIn = true;
      continue;
    }
    const test = /^bucket_id='((?:[^']|'')*)'$/.exec(core(part));
    if (!test || bucket !== void 0) return void 0;
    bucket = test[1].replace(/''/g, "'");
  }
  return { bucket, signedIn };
}
var MAX_INPUT = 5e6;
function lintSupabase(input2) {
  return lintCatalog(readSchema(input2));
}
function readSchema(input2) {
  const trimmed = input2.trim();
  if (trimmed === "") throw new Error("Paste SQL or the JSON the query returns.");
  if (trimmed.length > MAX_INPUT) {
    throw new Error(
      `That\u2019s ${trimmed.length.toLocaleString("en-US")} characters. Paste up to ${MAX_INPUT.toLocaleString("en-US")} at a time: split a big dump, or use the catalog query, which is much smaller.`
    );
  }
  const looksJson = /^[[{"]/.test(trimmed) || /"supabase_rls_check"/.test(trimmed.slice(0, 400));
  return looksJson ? readJson(trimmed) : readSql(trimmed);
}
function lintCatalog(catalog) {
  const findings = [];
  const exposed = (schema) => catalog.exposed.includes(schema) && !SYSTEM_SCHEMAS.has(schema);
  const policiesOn = (rel) => catalog.policies.filter((p) => p.schema === rel.schema && p.table === rel.name);
  const reachable = (rel) => !rel.grants || COMMANDS.some((c) => rel.grants.anon.has(c) || rel.grants.authenticated.has(c));
  const selectable = (rel) => !rel.grants || rel.grants.anon.has("select") || rel.grants.authenticated.has("select");
  const name = (schema, table) => qualifiedName(schema, table);
  const add = (f) => findings.push(f);
  const invokerBlocker = (view) => {
    if (!view.query) return "The checker can\u2019t see its query.";
    const reads = viewReads(view.query);
    if (reads.unknown) return "It reads something other than a table, such as a function, so the checker can\u2019t tell.";
    const roles = ["anon", "authenticated"].filter((r) => !view.grants || view.grants[r].has("select"));
    for (const [schema, table] of reads.tables) {
      const base = catalog.relations.get(key(schema ?? "public", table));
      const bq = name(schema ?? "public", table);
      if (!base) return `It reads ${bq}, which the checker can\u2019t see.`;
      if (!exposed(base.schema)) return `It reads ${bq}, in a schema the API doesn\u2019t serve.`;
      if (base.kind !== "table") return `It reads ${bq}, which isn\u2019t a table.`;
      if (!base.rls) return `It reads ${bq}, which has RLS off.`;
      for (const role of roles) {
        const who = role === "anon" ? "signed-out visitors" : "signed-in users";
        if (base.grants && !base.grants[role].has("select")) return `It reads ${bq}, and ${who} have no grant to read it.`;
        const policies = policiesOn(base).filter((p) => p.permissive && covers(p, "select") && appliesTo(p, role));
        if (policies.length === 0) return `It reads ${bq}, which has no select policy for ${who}.`;
        if (policies.every((p) => classify(p.using, role) === "none")) return `It reads ${bq}, whose select policies never let ${who} read it.`;
      }
    }
    return void 0;
  };
  const relations = [...catalog.relations.values()];
  const tables = [];
  for (const rel of relations) {
    if (!exposed(rel.schema)) continue;
    if (!rel.created && !rel.rlsKnown) continue;
    const q = name(rel.schema, rel.name);
    const policies = policiesOn(rel);
    const sensitive = sensitiveColumns(rel.columns);
    if (rel.kind === "table") {
      if (!rel.rls) {
        const open = reachable(rel);
        const lints = ["0013"];
        if (policies.length > 0) lints.push("0007");
        if (sensitive.length > 0) lints.push("0023");
        const parts = [
          open ? "Anyone with your project\u2019s public key can read, add, change and delete every row through the Data API. Row-level security is what stops them, and it\u2019s off." : "The API roles have no grants on it right now, so the Data API can\u2019t reach it. Turn RLS on anyway, so a later grant doesn\u2019t open it."
        ];
        if (sensitive.length > 0) parts.push(`It has columns that look sensitive: ${sensitive.join(", ")}.`);
        if (policies.length > 0) parts.push(`It has ${policies.length} ${policies.length === 1 ? "policy" : "policies"}, but policies do nothing until RLS is on.`);
        if (rel.realtime) parts.push("It\u2019s also published to Realtime, which sends its changes to subscribers.");
        if (open && !rel.grants && catalog.source === "sql") parts.push("This assumes Supabase\u2019s default grants, since the SQL doesn\u2019t set any.");
        add({
          id: "rls_disabled_in_public",
          severity: open ? "error" : "note",
          category: "security",
          lints,
          title: open ? `${q} is open to everyone${sensitive.length > 0 ? `, including ${sensitive.slice(0, 3).join(", ")}` : ""}` : `RLS is off on ${q}`,
          object: q,
          line: rel.line,
          detail: parts.join(" "),
          fix: `alter table ${q} enable row level security;
${rlsOnFix(rel, policies, catalog.relations)}`
        });
      } else if (policies.length === 0 && rel.created && catalog.opaque.length === 0) {
        add({
          id: "rls_enabled_no_policy",
          severity: "note",
          category: "security",
          lints: ["0008"],
          title: `Nobody can reach ${q} from the browser`,
          object: q,
          line: rel.line,
          detail: "RLS is on and there are no policies, so only server code using a secret key can use it. That\u2019s right for internal tables. If your app reads it from the browser, it gets no rows and no error."
        });
      }
    }
    if (rel.kind === "view") {
      const readsAuthUsers = !!rel.query && rel.query.some((t, i, all) => t.value === "auth" && isOp(all[i + 1], ".") && all[i + 2]?.value === "users");
      if (readsAuthUsers && reachable(rel)) {
        add({
          id: "auth_users_exposed",
          severity: "error",
          category: "security",
          lints: ["0002"],
          title: `${q} exposes auth.users`,
          object: q,
          line: rel.line,
          detail: "This view reads Supabase Auth\u2019s users table, with emails, phone numbers and sign-in details, and the Data API can serve it. A simple view like this takes inserts, updates and deletes too, which change auth.users. Keep it out of exposed schemas, or select only what the app needs from your own profiles table.",
          // PUBLIC too: a grant to it reaches anon and authenticated.
          fix: [
            "-- After this, the Data API stops serving it, so the app gets \u201Cpermission denied\u201D",
            "-- where it reads it. If the app needs some of these columns, keep them in your",
            "-- own profiles table and read that instead.",
            `revoke all on ${q} from public, anon, authenticated;`,
            `-- Or move it out of the API: create schema if not exists private; alter view ${q} set schema private;`
          ].join("\n")
        });
      } else if (!readsAuthUsers && !rel.securityInvoker && selectable(rel)) {
        const blocked = invokerBlocker(rel);
        const alter = `alter view ${q} set (security_invoker = true);`;
        const reads = rel.query ? viewReads(rel.query).tables.length > 0 : false;
        const finding = {
          id: "security_definer_view",
          severity: "error",
          category: "security",
          lints: ["0010"],
          title: `${q} skips the policies on the tables it reads`,
          object: q,
          line: rel.line,
          detail: "A view runs with its owner\u2019s rights unless it\u2019s created with security_invoker, and the owner is usually postgres, which isn\u2019t held back by RLS. So anyone who can read the view sees every row it selects."
        };
        if (!blocked) {
          add({ ...finding, fix: reads ? `-- From now on it shows each caller only the rows the policies on its tables let them read.
${alter}` : alter });
        } else {
          const why = [
            "With security_invoker on, the view runs with the caller\u2019s rights, so they need",
            "a grant and a select policy on each table it reads.",
            blocked,
            "Add those first, then run this. If the view shares only safe columns on purpose,",
            "you can keep it as it is."
          ];
          add({ ...finding, manual: true, fix: commentOut(`${commentLines(why.join("\n"))}
${alter}`) });
        }
      }
    }
    if (rel.kind === "matview" && selectable(rel)) {
      add({
        id: "materialized_view_in_api",
        severity: "warning",
        category: "security",
        lints: ["0016"],
        title: `${q} has no row-level security`,
        object: q,
        line: rel.line,
        detail: "Materialized views can\u2019t have RLS, so the Data API serves every row to anyone who can select it.",
        fix: [
          "-- After this, the Data API stops serving it, so the app gets an error where it",
          "-- reads it. If the app needs it, move it to a schema the API doesn\u2019t serve, and",
          "-- read it through a security definer function that returns only what each user",
          "-- may see.",
          `revoke select on ${q} from public, anon, authenticated;`
        ].join("\n")
      });
    }
    if (rel.kind === "foreign" && reachable(rel)) {
      const can = COMMANDS.filter((c) => !rel.grants || rel.grants.anon.has(c) || rel.grants.authenticated.has(c)).map((c) => VERB[c]);
      add({
        id: "foreign_table_in_api",
        severity: "warning",
        category: "security",
        lints: ["0017"],
        title: `${q} has no row-level security`,
        object: q,
        line: rel.line,
        detail: `Foreign tables ignore RLS, so the Data API lets anyone with a grant ${andList(can)} every row.`,
        fix: `-- After this, the Data API stops serving it.
revoke all on ${q} from public, anon, authenticated;`
      });
    }
    tables.push({
      schema: rel.schema,
      name: rel.name,
      kind: rel.kind,
      rls: rel.kind === "table" ? rel.rls : false,
      reachable: reachable(rel),
      grantsAssumed: !rel.grants,
      policies: policies.length,
      partial: !rel.created,
      access: Object.fromEntries(
        COMMANDS.map((c) => [c, { anon: reachOf(rel, policies, c, "anon"), authenticated: reachOf(rel, policies, c, "authenticated") }])
      )
    });
  }
  const byTable = /* @__PURE__ */ new Map();
  for (const p of catalog.policies) {
    const list2 = byTable.get(key(p.schema, p.table)) ?? [];
    list2.push(p);
    byTable.set(key(p.schema, p.table), list2);
  }
  for (const [tableKey, policies] of byTable) {
    const [schema, table] = [policies[0].schema, policies[0].table];
    const rel = catalog.relations.get(tableKey);
    const storage = schema === "storage" && table === "objects";
    if (!storage && !exposed(schema)) continue;
    const q = name(schema, table);
    const noRole = [];
    const owner = ownerOf(rel, policies, catalog.relations);
    const taken2 = new Set(policies.map((p) => p.name));
    for (const p of policies) {
      const pq = `${identifier(p.name)} on ${q}`;
      const commands = p.command === "all" ? COMMANDS : [p.command];
      const anon = appliesTo(p, "anon");
      const authed = appliesTo(p, "authenticated");
      const who = anon ? "Anyone, signed in or not," : "Every signed-in user";
      if (mentionsUserMetadata(p.using) || mentionsUserMetadata(p.check)) {
        const using = p.command !== "insert" && mentionsUserMetadata(p.using) ? p.using : void 0;
        const check = p.command !== "select" && p.command !== "delete" && mentionsUserMetadata(p.check) ? p.check : void 0;
        const swapped = (using || check) && [using, check].every((e) => !e || appMetadata(e.tokens));
        const finding = {
          id: "rls_references_user_metadata",
          severity: "error",
          category: "security",
          lints: ["0015"],
          title: `${identifier(p.name)} trusts user_metadata`,
          object: q,
          line: p.line,
          detail: "Users can change their own user_metadata from the browser with updateUser(), so a policy that reads a role or a team from it lets anyone give themselves access. Keep roles in app_metadata, which only server code can set, or in a table users can\u2019t write."
        };
        if (swapped) {
          const edit = { ...policyEdit(p, "security"), using: using && fixText(using.tokens), check: check && fixText(check.tokens) };
          const note = appMetadataNote([...using?.tokens ?? [], ...check?.tokens ?? []]);
          add({ ...finding, ...policyFix([{ ...edit, note }]) });
        } else {
          const clauses = [...using ? ["using (<your condition>)"] : [], ...check ? ["with check (<your condition>)"] : []];
          const opens = [using, check].some((e) => e && !failsClosed(e.tokens));
          add({
            ...finding,
            manual: true,
            fix: commentOut(
              [
                ...opens ? [
                  "-- It shuts people out when the claim says so. Read from app_metadata as it is, it",
                  "-- would let everyone in until server code sets the claim, so write it for that too."
                ] : [],
                "-- Write the condition with app_metadata, which only server code can set, for example:",
                "--   (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'",
                "-- Set that claim for each user first, or they lose access. Then run:",
                `alter policy ${pq}`,
                ...clauses.map((c) => `  ${c}`)
              ].join("\n") + ";"
            )
          });
        }
      }
      if (!storage && p.permissive && (anon || authed)) {
        const writes = commands.filter((c) => c !== "select");
        const openWrites = writes.filter((c) => alwaysTrue(clauseFor(p, c)) || c === "update" && !!p.using && alwaysTrue(p.check));
        if (openWrites.length > 0) {
          const destructive = openWrites.some((c) => c !== "insert");
          add({
            id: "rls_policy_always_true",
            severity: anon && destructive ? "error" : "warning",
            category: "security",
            lints: ["0024"],
            title: `${who} can ${openWrites.map((c) => VERB[c]).join(", ")} any row in ${q}`,
            object: q,
            line: p.line,
            detail: `${identifier(p.name)} lets ${openWrites.join(", ")} through with a condition that\u2019s always true${anon ? ", and it applies to signed-out visitors" : ""}. ${openWrites.includes("insert") ? "New rows can claim to belong to anyone. " : ""}Tie writes to the caller, such as (select auth.uid()) = user_id.`,
            ...ownerFix(p, owner, taken2)
          });
        } else {
          const signedIn = writes.filter((c) => signedInOnly(clauseFor(p, c)));
          if (signedIn.length > 0) {
            add({
              id: "signed_in_writes_any_row",
              severity: "warning",
              category: "security",
              lints: [],
              title: `Every signed-in user can ${signedIn.map((c) => VERB[c]).join(", ")} any row in ${q}`,
              object: q,
              line: p.line,
              detail: `${identifier(p.name)} only checks that someone is signed in. If anyone can sign up, that\u2019s anyone. Check that the row belongs to them, or to a team they\u2019re in.`,
              ...ownerFix(p, owner, taken2)
            });
          }
        }
        if (commands.includes("select") && alwaysTrue(p.using) && anon) {
          const sensitive = rel ? sensitiveColumns(rel.columns) : [];
          add({
            id: "public_read",
            severity: sensitive.length > 0 ? "warning" : "note",
            category: "security",
            lints: [],
            title: `Every row in ${q} is public`,
            object: q,
            line: p.line,
            detail: `${identifier(p.name)} lets anyone read all of it, signed in or not.${sensitive.length > 0 ? ` It has columns that look sensitive: ${sensitive.join(", ")}.` : ""} Fine for public content; move private rows or columns to another table.`
          });
        }
        if (p.roles.includes("anon") && !p.roles.includes("public") && writes.some((c) => !!clauseFor(p, c) && !alwaysTrue(clauseFor(p, c)))) {
          add({
            id: "anon_writes",
            severity: "note",
            category: "security",
            lints: [],
            title: `Signed-out visitors can ${writes.map((c) => VERB[c]).join(", ")} rows in ${q}`,
            object: q,
            line: p.line,
            detail: `${identifier(p.name)} is for the anon role. Right for things like a contact form; make sure the condition limits what a stranger can write.`
          });
        }
      }
      const needsUser2 = commands.every((c) => classify(clauseFor(p, c), "anon") === "none");
      if (p.permissive && !storage && p.roles.length === 1 && p.roles[0] === "public" && needsUser2) noRole.push(p);
      const usingCalls = authCalls(p.using?.tokens ?? []);
      const checkCalls = authCalls(p.check?.tokens ?? []);
      const calls = [...usingCalls, ...checkCalls];
      if (calls.some((call) => !call.wrapped)) {
        const wrapped = (expr, list2) => expr && list2.some((c) => !c.wrapped) ? wrapCalls(expr.tokens, list2) : void 0;
        add({
          id: "auth_rls_initplan",
          severity: "note",
          category: "performance",
          lints: ["0003"],
          title: `${identifier(p.name)} calls ${[...new Set(calls.filter((c) => !c.wrapped).map((c) => `${c.name}()`))].join(" and ")} once per row`,
          object: q,
          line: p.line,
          detail: "Postgres runs the function again for every row it checks. Wrapped in (select ...), it runs once per query, which is much faster on big tables. The result is the same.",
          ...policyFix([{ ...policyEdit(p, "speed"), using: wrapped(p.using, usingCalls), check: wrapped(p.check, checkCalls) }])
        });
      }
      if (callsAuthRole(p.using) || callsAuthRole(p.check) || readsClaimsSetting(p.using) || readsClaimsSetting(p.check)) {
        add({
          id: "legacy_auth_helpers",
          severity: "note",
          category: "security",
          lints: [],
          title: `${identifier(p.name)} uses an old way to read the user`,
          object: q,
          line: p.line,
          detail: "auth.role() and reading request.jwt.claims directly still work but are deprecated. Name the role with `to authenticated` or `to anon`, and read claims with auth.jwt()."
        });
      }
      if (p.command === "all" && !storage) {
        add({
          id: "for_all_policy",
          severity: "note",
          category: "security",
          lints: [],
          title: `${identifier(p.name)} covers every command`,
          object: q,
          line: p.line,
          detail: "A FOR ALL policy gives reads and writes the same rule, and with no WITH CHECK its USING also decides which new rows can be written. Separate select, insert, update and delete policies are easier to get right."
        });
      }
    }
    if (noRole.length > 0) {
      add({
        id: "policy_without_role",
        severity: "note",
        category: "performance",
        lints: [],
        title: `${noRole.length === 1 ? `${identifier(noRole[0].name)} applies` : `${noRole.length} policies on ${q} apply`} to every role`,
        object: q,
        line: noRole[0].line,
        detail: "With no TO clause a policy applies to every role, signed-out visitors included. Its condition needs a signed-in user, so it never lets them through, but Postgres still checks it on their queries. Add `to authenticated` to skip that.",
        ...policyFix(noRole.map((p) => ({ ...policyEdit(p, "speed"), roles: ["authenticated"] })))
      });
    }
    if (storage) {
      lintStorage(policies);
      continue;
    }
    const overlaps = [];
    for (const role of ["anon", "authenticated"]) {
      for (const command of COMMANDS) {
        const matching = policies.filter((p) => p.permissive && covers(p, command) && appliesTo(p, role));
        if (matching.length > 1) overlaps.push(`${command} for ${role}: ${matching.map((p) => identifier(p.name)).join(", ")}`);
      }
    }
    if (overlaps.length > 0) {
      add({
        id: "multiple_permissive_policies",
        severity: "note",
        category: "performance",
        lints: ["0006"],
        title: `${q} has overlapping policies`,
        object: q,
        line: policies[0].line,
        detail: `Postgres checks every permissive policy for each row, so these add up: ${overlaps.join("; ")}. Merge each group into one policy with OR.`
      });
    }
    for (const role of ["anon", "authenticated"]) {
      const canRead = policies.some((p) => p.permissive && covers(p, "select") && !!p.using && appliesTo(p, role));
      if (canRead) continue;
      const blind = ["update", "delete"].filter(
        (c) => policies.some((p) => p.permissive && p.command === c && !!p.using && (role === "anon" ? p.roles.includes("anon") : appliesTo(p, role)))
      );
      if (blind.length > 0) {
        add({
          id: "write_without_select",
          severity: "warning",
          category: "security",
          lints: [],
          title: `${role} can ${blind.map((c) => VERB[c]).join(" and ")} ${q} but not read it`,
          object: q,
          line: policies[0].line,
          detail: `Postgres only ${blind.join("s and ")}s rows the caller can select, so ${blind.join(" and ")} from the app changes nothing and reports no error. Add a select policy for ${role}.`
        });
      }
    }
    for (const command of COMMANDS) {
      const restrictive = policies.filter((p) => !p.permissive && covers(p, command));
      const permissive = policies.filter((p) => p.permissive && covers(p, command));
      if (restrictive.length > 0 && permissive.length === 0) {
        add({
          id: "restrictive_only",
          severity: "note",
          category: "security",
          lints: [],
          title: `${command} on ${q} has only restrictive policies`,
          object: q,
          line: restrictive[0].line,
          detail: "Restrictive policies can only narrow access that a permissive policy grants. With none, nothing passes."
        });
      }
    }
    if (rel && rel.kind === "table" && (catalog.source === "json" || rel.columns.length > 0)) {
      const missing = /* @__PURE__ */ new Set();
      for (const p of policies) {
        for (const column of [...ownerColumns(p.using), ...ownerColumns(p.check)]) {
          if (!rel.indexed.has(column) && (rel.columns.length === 0 || rel.columns.includes(column))) missing.add(column);
        }
      }
      for (const column of missing) {
        add({
          id: "policy_column_unindexed",
          severity: "note",
          category: "performance",
          lints: [],
          title: `${q}.${identifier(column)} has no index`,
          object: q,
          line: rel.line,
          detail: `Policies compare ${column} with the user\u2019s id on every query. Without an index, Postgres reads the whole table to do it.`,
          fix: `create index if not exists ${identifier(pgName(`${table}_${column}`, "_idx"))} on ${q} (${identifier(column)});`
        });
      }
    }
  }
  function lintStorage(policies) {
    for (const p of policies) {
      if (!p.permissive) continue;
      if (!appliesTo(p, "anon") && !appliesTo(p, "authenticated")) continue;
      const writesNew = p.command === "insert" || p.command === "update" || p.command === "all";
      const using = p.command === "insert" ? void 0 : storageScope(p.using);
      const check = writesNew ? storageScope(p.check ?? (p.command === "insert" ? void 0 : p.using)) : void 0;
      const commands = p.command === "all" ? COMMANDS : [p.command];
      const scopeOf = (c) => c === "insert" ? check : c === "update" ? using ?? check : using;
      const open = commands.filter((c) => scopeOf(c));
      if (open.length === 0) continue;
      const bucketId = using?.bucket ?? check?.bucket;
      const bucket = bucketId !== void 0 ? catalog.buckets.get(bucketId) : void 0;
      const where = bucketId !== void 0 ? `bucket ${bucketId}` : "every bucket";
      const anon = appliesTo(p, "anon") && open.some((c) => !scopeOf(c).signedIn);
      const who = anon ? "Anyone" : "Every signed-in user";
      const publicList = open.includes("select") && !!bucket?.public;
      const writes = open.filter((c) => c !== "select");
      const severity = writes.length > 0 ? anon ? "error" : "warning" : publicList || anon ? "warning" : "note";
      const single = {
        select: `list ${bucket?.public ? "" : "and download "}every file in`,
        insert: "upload to",
        update: "change any file in",
        delete: "delete any file in"
      };
      const verbs = { select: bucket?.public ? "list" : "read", insert: "upload", update: "change", delete: "delete" };
      const phrases = {
        select: `list ${bucket?.public ? "" : "and download "}every file`,
        insert: "upload files",
        update: "change any file",
        delete: "delete any file"
      };
      const scoped = (s) => `${s.bucket !== void 0 ? `bucket_id = ${literal2(s.bucket)} and ` : ""}owner_id = ${SUB}`;
      const edit = policyEdit(p, "security");
      if (using) edit.using = scoped(using);
      if (check) edit.check = scoped(check);
      const note = [];
      if (open.some((c) => c !== "insert")) {
        note.push(
          "Each user now reaches only the files they uploaded: Storage puts the uploader\u2019s",
          "id in owner_id. Files uploaded without a signed-in user have none, so users",
          "can\u2019t reach them after this."
        );
      }
      if (open.includes("insert") && anon) note.push("Signed-out visitors can\u2019t upload after this.");
      if (publicList) note.push("Public URLs still serve every file in a public bucket.");
      edit.note = note.join("\n");
      add({
        id: writes.length > 0 ? "storage_broad_write" : "storage_broad_select",
        severity,
        category: "security",
        lints: publicList ? ["0025"] : [],
        title: `${who} can ${open.length === 1 ? single[open[0]] : `${andList(open.map((c) => verbs[c]))} any file in`} ${where}`,
        object: "storage.objects",
        line: p.line,
        detail: `${identifier(p.name)} doesn\u2019t tie files to the user who uploaded them, so ${anon ? "anyone" : "any signed-in user"} can ${andList(open.map((c) => phrases[c]))}.${publicList ? " Public files are served by their URL anyway, so listing them all only shows more than you meant to share." : ""} Limit it to each user\u2019s own files.`,
        ...policyFix([edit])
      });
    }
  }
  const overloads = /* @__PURE__ */ new Map();
  for (const fn of catalog.functions) overloads.set(key(fn.schema, fn.name), [...overloads.get(key(fn.schema, fn.name)) ?? [], fn]);
  const calleesAt = (tokens, i, match) => {
    const t = tokens[i];
    if (!isName(t) || !isOp(tokens[i + 1], "(")) return [];
    let schema = "public";
    if (isOp(tokens[i - 1], ".")) {
      if (!isName(tokens[i - 2]) || isOp(tokens[i - 3], ".")) return [];
      schema = tokens[i - 2].value;
    }
    const list2 = overloads.get(key(schema, t.value)) ?? [];
    if (list2.length <= 1) return list2;
    const args = argCountAt(tokens, i + 1, match);
    const exact = list2.filter((f) => argCount(f.args) === args);
    return exact.length > 0 ? exact : list2.filter((f) => argCount(f.args) > args);
  };
  const policyCalls = /* @__PURE__ */ new Map();
  for (const p of catalog.policies) {
    for (const expr of [p.using, p.check]) {
      if (!expr) continue;
      const match = pairs(expr.tokens);
      for (let i = 0; i < expr.tokens.length; i += 1) {
        const callees = calleesAt(expr.tokens, i, match);
        for (const f of callees) policyCalls.set(f, [...policyCalls.get(f) ?? [], { args: argCountAt(expr.tokens, i + 1, match), callees }]);
      }
    }
  }
  const taken = new Set(catalog.functions.map((f) => `${f.schema}.${f.name}(${f.args})`));
  const hiddenFor = (fn, claim) => {
    const to = HELPER_SCHEMAS.find((s) => !catalog.exposed.includes(s) && !taken.has(`${s}.${fn.name}(${fn.args})`));
    if (to && claim) taken.add(`${to}.${fn.name}(${fn.args})`);
    return to;
  };
  const signatures = new Map(catalog.functions.map((f) => [`${name(f.schema, f.name)}(${f.args})`, f]));
  const indirectUses = (fn) => {
    const views = relations.filter((r) => r.kind === "view" && exposed(r.schema) && !!r.query && (!r.grants || r.grants.anon.has("select"))).filter((r) => callsIn(r.query).some((call) => namesFunction(call, fn))).map((r) => `the view ${name(r.schema, r.name)}`);
    const tables2 = (fn.usedBy ?? []).map((t) => `a column default or check on ${t}`);
    const bodies = (fn.calledBy ?? []).filter((sig) => !signatures.get(sig)?.securityDefiner).map((sig) => signatures.get(sig)?.returnsTrigger ? `the trigger function ${sig}` : sig);
    return [...views, ...tables2, ...bodies];
  };
  for (const fn of catalog.functions) {
    if (SYSTEM_SCHEMAS.has(fn.schema)) continue;
    const signature = `${name(fn.schema, fn.name)}(${fn.args})`;
    const callable = exposed(fn.schema) && !fn.returnsTrigger;
    const self = { kind: "function", schema: fn.schema, name: fn.name, args: fn.args };
    if (fn.securityDefiner && callable && (fn.anon || fn.authenticated)) {
      const calls = policyCalls.get(fn) ?? [];
      const helper = calls.length > 0;
      const endpoint = `/rest/v1/rpc/${fn.name}`;
      const rpc = `supabase.rpc('${fn.name}')`;
      const finding = {
        id: fn.anon ? "anon_security_definer_function_executable" : "authenticated_security_definer_function_executable",
        severity: fn.anon ? "warning" : "note",
        category: "security",
        lints: [fn.anon ? "0028" : "0029"],
        title: `${fn.anon ? "Anyone" : "Every signed-in user"} can call ${signature} with its owner\u2019s rights`,
        object: signature,
        line: fn.line,
        detail: `It\u2019s security definer and in an exposed schema, so ${fn.anon ? "anyone" : "any signed-in user"} can call it at ${endpoint}, and it runs as its owner, past RLS. ${helper ? "Policies call it, so taking execute away would make them fail. Move it to a schema the API doesn\u2019t serve instead." : "Revoking from public alone isn\u2019t enough on Supabase: anon and authenticated have their own grants."}`
      };
      if (helper) {
        const callArgs = (overloads.get(key(fn.schema, fn.name))?.length ?? 1) > 1 ? argCount(fn.args) : void 0;
        const callers = fn.calledBy ?? [];
        const unsure = calls.some((c) => c.callees.length > 1 || callArgs !== void 0 && c.args !== callArgs);
        const to = callers.length === 0 && !unsure ? hiddenFor(fn, true) : void 0;
        if (to) {
          const moved = `${identifier(to)}.${identifier(fn.name)}`;
          const first = HELPER_SCHEMAS[0];
          const note = [
            ...to === first || catalog.exposed.includes(first) ? [] : catalog.functions.some((f) => f.schema === first && f.name === fn.name && f.args === fn.args) ? [`${first} has a function ${fn.name}(${fn.args}) already, so this one goes to ${to}.`] : [`Another ${fn.name}(${fn.args}) moves to ${first} above, so this one goes to ${to}.`],
            "Policies call it, and they keep working after the move: Postgres keeps track",
            `of the function, not its name. The app can\u2019t call ${rpc} any more,`,
            `and SQL that names ${name(fn.schema, fn.name)} needs ${moved} now.`
          ];
          add({ ...finding, ...functionFix([{ ...self, moveTo: to, callArgs, note: note.join("\n") }]) });
        } else {
          const free = hiddenFor(fn, false);
          const into = free ? identifier(free) : "<schema>";
          const but = callers.length > 0 ? [
            `But ${andList(callers)} ${callers.length === 1 ? "calls" : "call"} it by name,`,
            `and would fail after the move. Run this together with new versions of ${callers.length === 1 ? "that function" : "them"}`,
            `that call ${into}.${identifier(fn.name)}:`
          ] : unsure ? ["But another function has the same name, and the checker can\u2019t tell which one", "each policy calls. Check that, then run:"] : [`But ${andList(HELPER_SCHEMAS)} each have a function ${fn.name}(${fn.args}) already.`, "Put another schema the API doesn\u2019t serve in place of <schema>, then run:"];
          const why = [
            "Policies call it, so taking execute away would make them fail. Moving it to a schema",
            "the API doesn\u2019t serve fixes it, and the policies keep working.",
            ...but
          ];
          const sql = `create schema if not exists ${into};
alter function ${signature} set schema ${into};`;
          add({ ...finding, manual: true, fix: commentOut(`${commentLines(why.join("\n"))}
${sql}`) });
        }
      } else if (fn.anon) {
        const uses = indirectUses(fn);
        const revoke = `revoke execute on function ${signature} from public, anon;`;
        if (uses.length > 0) {
          const why = [
            `It may run for signed-out visitors through ${andList(uses)} too.`,
            `Taking execute away from them would make ${uses.length === 1 ? "that" : "those"} fail. If they never reach it, run:`
          ];
          add({ ...finding, manual: true, fix: commentOut(`${commentLines(why.join("\n"))}
${revoke}`) });
        } else {
          const optional = fn.authenticated ? `-- If signed-in users shouldn\u2019t call it either, run this too:
revoke execute on function ${signature} from authenticated;` : void 0;
          const note = `After this, signed-out visitors get an error from ${rpc}
(${endpoint}). Skip it if the app calls it before sign-in.`;
          add({ ...finding, ...functionFix([{ ...self, revokeFrom: ["public", "anon"], optional, note }]) });
        }
      } else {
        const why = [
          `Signed-in users can call it with ${rpc}. If the app does that on purpose,`,
          "leave it, and check it only does what any user may do. Otherwise run this; the",
          "app then gets an error from that call:"
        ];
        add({ ...finding, manual: true, fix: commentOut(`${commentLines(why.join("\n"))}
revoke execute on function ${signature} from authenticated;`) });
      }
    }
    if (!fn.searchPathSet) {
      add({
        id: "function_search_path_mutable",
        severity: fn.securityDefiner ? "warning" : "note",
        category: "security",
        lints: ["0011"],
        title: `${signature} has no fixed search_path`,
        object: signature,
        line: fn.line,
        detail: fn.securityDefiner ? "A security definer function that looks names up through the caller\u2019s search_path can be tricked into running someone else\u2019s function or table with the owner\u2019s rights. Pin its search_path." : "Without a fixed search_path, the names inside resolve differently depending on who calls it. Pin it.",
        ...functionFix([{ ...self, searchPath: SEARCH_PATH, note: SEARCH_PATH_NOTE }])
      });
    }
  }
  if (catalog.opaque.length > 0) {
    add({
      id: "dynamic_sql",
      severity: "note",
      category: "security",
      lints: [],
      title: "Some SQL here is built at run time",
      object: catalog.opaque.length === 1 ? "a DO block" : `${catalog.opaque.length} DO blocks`,
      line: catalog.opaque[0],
      detail: "A DO block runs SQL it puts together itself, with execute, so the checker can\u2019t see the policies, grants or settings it makes. Tables it touches may have more or less access than shown. Run the catalog query on the live project for the real result."
    });
  }
  const order = { error: 0, warning: 1, note: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || (a.category === b.category ? 0 : a.category === "security" ? -1 : 1));
  shareFixes(findings);
  return {
    source: catalog.source,
    findings,
    tables: tables.sort((a, b) => key(a.schema, a.name).localeCompare(key(b.schema, b.name))),
    counts: {
      tables: relations.filter((r) => exposed(r.schema)).length,
      policies: catalog.policies.length,
      functions: catalog.functions.length,
      statements: catalog.statements
    }
  };
}
var editId = (e) => e.kind === "policy" ? `policy ${e.schema}.${e.table}\0${e.name}` : `function ${functionTarget(e)}`;
var titleLine = (f) => commentLines(`${f.category === "performance" ? "Speed: " : ""}${f.title}`);
function plan(findings) {
  const groups = /* @__PURE__ */ new Map();
  for (const f of findings) {
    if (f.manual || !f.edits) continue;
    const title = titleLine(f);
    for (const id of new Set(f.edits.map(editId))) {
      const group = groups.get(id) ?? { edits: [], titles: [], findings: 0 };
      group.edits.push(...f.edits.filter((e) => editId(e) === id));
      if (!group.titles.includes(title)) group.titles.push(title);
      group.findings += 1;
      groups.set(id, group);
    }
  }
  const blocks = /* @__PURE__ */ new Map();
  const moved = [];
  for (const [id, { edits, titles, findings: count2 }] of groups) {
    if (edits[0].kind === "function") {
      const merged2 = mergeFunctionEdits(edits);
      if (merged2.moveTo) moved.push(merged2);
      blocks.set(id, { edit: merged2, section: merged2.moveTo ? "helpers" : "functions", titles, findings: count2 });
      continue;
    }
    const merged = mergePolicyEdits(edits);
    const section = merged.priority === "speed" ? "speed" : merged.schema === "storage" ? "storage" : "policies";
    blocks.set(id, { edit: merged, section, titles, findings: count2 });
  }
  return { blocks, moved };
}
function blockSql(block, moved, schema, used) {
  return block.edit.kind === "function" ? functionSql(block.edit, schema) : renameCalls(policySql(block.edit), moved, used);
}
function shareFixes(findings) {
  const { blocks, moved } = plan(findings);
  for (const f of findings) {
    if (f.manual || !f.edits || f.edits.length === 0) continue;
    const ids = [...new Set(f.edits.map(editId))];
    const used = /* @__PURE__ */ new Set();
    const parts = [];
    for (const id of ids) {
      const block = blocks.get(id);
      const sql = blockSql(block, moved, true, used);
      if (sql === "") continue;
      const own = plan([{ ...f, edits: f.edits.filter((e) => editId(e) === id) }]).blocks.get(id);
      const shared = block.findings > 1 && blockSql(own, moved, true) !== sql;
      const what = block.edit.kind === "policy" ? "policy" : "function";
      parts.push(`${shared ? `-- The other fixes for this ${what} are in here too, so none undoes another.
` : ""}${sql}`);
    }
    const first = [...used].filter((m) => !ids.includes(editId(m))).map((m) => {
      const to = `${identifier(m.moveTo)}.${identifier(m.name)}`;
      return `-- It calls ${to}, so first it moves ${functionTarget(m)} there, as that function\u2019s own fix does.
${functionSql({ ...m, note: void 0 })}`;
    });
    f.fix = [...first, ...parts].join("\n");
  }
}

// src/rls.ts
var LEVEL = {
  error: "error",
  warning: "warning",
  note: "notice"
};
var InputError2 = class extends Error {
};
function collectFiles(inputs, cwd = process.cwd()) {
  const files = [];
  for (const input2 of inputs) {
    const full = path.resolve(cwd, input2);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      throw new InputError2(`Can\u2019t find ${input2}.`);
    }
    if (stat.isDirectory()) {
      const sql = readdirSync(full).filter((name) => name.toLowerCase().endsWith(".sql")).sort().map((name) => path.join(full, name));
      if (sql.length === 0) throw new InputError2(`${input2} has no .sql files.`);
      files.push(...sql);
    } else if (/\.(sql|json)$/i.test(full)) {
      files.push(full);
    } else {
      throw new InputError2(`${input2} isn\u2019t a .sql file, a .json catalog file or a folder of .sql files.`);
    }
  }
  return [...new Set(files)];
}
function joinSql(files) {
  const parts = [];
  const chunks = [];
  let line = 1;
  for (const { file, text } of files) {
    const body = text.endsWith("\n") ? text : `${text}
`;
    const lines = body.split("\n").length - 1;
    parts.push({ file, start: line, lines });
    chunks.push(body);
    line += lines;
  }
  return { sql: chunks.join(""), parts };
}
function locate(parts, line) {
  if (!line) return {};
  const part = parts.find((p) => line >= p.start && line < p.start + p.lines);
  return part ? { file: part.file, line: line - part.start + 1 } : {};
}
function toFindings(result, where) {
  return result.findings.map((f) => ({
    check: "rls",
    id: f.id,
    level: LEVEL[f.severity],
    title: f.title,
    detail: f.detail,
    ...f.fix && { fix: f.fix.trim() },
    ...f.object && { object: f.object },
    ...where(f.line)
  }));
}
var plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;
function shortPath(file, cwd) {
  const full = path.resolve(cwd, file);
  const rel = path.relative(cwd, full);
  return !rel ? path.basename(full) : rel.startsWith("..") || path.isAbsolute(rel) ? full : rel;
}
function checkRls(inputs, cwd = process.cwd()) {
  const files = collectFiles(inputs, cwd);
  const rel = (file) => shortPath(file, cwd);
  const read = (file) => {
    const text = readFileSync(file, "utf8");
    if (text.length > MAX_INPUT) throw new InputError2(`${rel(file)} is over ${MAX_INPUT / 1e6} MB.`);
    return text;
  };
  const reports = [];
  const sqlFiles = files.filter((f) => /\.sql$/i.test(f));
  if (sqlFiles.length > 0) {
    const { sql, parts } = joinSql(sqlFiles.map((file) => ({ file: rel(file), text: read(file) })));
    if (sql.length > MAX_INPUT) throw new InputError2(`The SQL files together are over ${MAX_INPUT / 1e6} MB.`);
    const result = lintSupabase(sql);
    reports.push({
      check: "rls",
      target: sqlFiles.length === 1 ? rel(sqlFiles[0]) : `${sqlFiles.length} SQL files`,
      findings: toFindings(result, (line) => locate(parts, line)),
      passed: [],
      note: `Read ${plural(result.counts.statements, "statement")}: ${plural(result.counts.tables, "table")}, ${plural(result.counts.policies, "policy", "policies")}, ${plural(result.counts.functions, "function")}. Where the SQL sets no grants, Supabase\u2019s defaults are assumed. These checks read settings, not your app\u2019s code.`
    });
  }
  for (const file of files.filter((f) => /\.json$/i.test(f))) {
    let result;
    try {
      result = lintSupabase(read(file));
    } catch (err) {
      throw new InputError2(`${rel(file)}: ${err.message}`);
    }
    reports.push({
      check: "rls",
      target: rel(file),
      findings: toFindings(result, () => ({ file: rel(file) })),
      passed: [],
      note: "Read from the catalog query: real grants, policies, functions and buckets."
    });
  }
  return reports;
}

// src/mcp.ts
var LEVEL2 = { high: "error", medium: "warning", low: "notice", note: "notice" };
function toFinding(f, extra = {}) {
  return {
    check: "mcp",
    id: f.id,
    level: LEVEL2[f.severity],
    title: f.title,
    detail: f.detail,
    ...f.fix && { fix: f.fix },
    ...f.ref && { ref: f.ref },
    ...extra
  };
}
async function checkMcpServer(url, options = {}) {
  let result;
  try {
    result = await checkServer(url, {
      request: options.request ?? localRequest,
      allowHttp: true,
      deadline: Date.now() + (options.timeoutMs ?? 25e3)
    });
  } catch (err) {
    if (err instanceof InputError) throw new InputError2(err.message);
    throw err;
  }
  const findings = combineFindings(result, reviewListedTools(usableTools(result.tools), result)).map(
    (f) => toFinding(f, { object: result.target })
  );
  const notes = [];
  if (new URL(result.target).protocol === "http:") {
    notes.push("Checked over plain HTTP, which is fine on your own machine; a server on the internet must use HTTPS.");
  }
  if (result.toolsNote) notes.push(result.toolsNote);
  if (result.inconclusive) {
    findings.unshift({
      check: "mcp",
      id: "inconclusive",
      level: "error",
      title: "Couldn\u2019t check this server",
      detail: result.inconclusive,
      object: result.target
    });
  }
  return {
    check: "mcp",
    target: result.target,
    findings,
    passed: result.passed,
    ...notes.length > 0 && { note: notes.join(" ") }
  };
}
function reviewToolsFile(file, cwd = process.cwd()) {
  const rel = shortPath(file, cwd);
  let text;
  try {
    text = readFileSync2(path2.resolve(cwd, file), "utf8");
  } catch {
    throw new InputError2(`Can\u2019t read ${file}.`);
  }
  let tools;
  try {
    tools = usableTools(parseToolList(text));
  } catch (err) {
    throw new InputError2(`${rel}: ${err.message}`);
  }
  if (tools.length === 0) throw new InputError2(`${rel} lists no tools.`);
  const review = reviewListedTools(tools, null);
  return {
    check: "mcp",
    target: rel,
    findings: combineFindings(null, review).map((f) => toFinding(f, { file: rel })),
    passed: [],
    note: `Reviewed ${tools.length} tool${tools.length === 1 ? "" : "s"} from tools/list: names, descriptions, input schemas and annotations, not what each tool\u2019s code does.`
  };
}

// src/findings.ts
var LEVELS = ["error", "warning", "notice"];
function fails(reports, failOn) {
  if (failOn === "never") return false;
  const threshold = LEVELS.indexOf(failOn);
  return reports.some((r) => r.findings.some((f) => LEVELS.indexOf(f.level) <= threshold));
}
function count(findings) {
  return Object.fromEntries(LEVELS.map((l) => [l, findings.filter((f) => f.level === l).length]));
}
var plural2 = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
function summary(findings) {
  const c = count(findings);
  if (findings.length === 0) return "no findings";
  return [plural2(c.error, "error"), plural2(c.warning, "warning"), plural2(c.notice, "notice")].join(", ");
}
var LABEL = { error: "ERROR", warning: "WARN ", notice: "NOTE " };
function formatText(reports, { color = false } = {}) {
  const paint = (code, text) => color ? `\x1B[${code}m${text}\x1B[0m` : text;
  const tone = { error: 31, warning: 33, notice: 36 };
  const out = [];
  for (const r of reports) {
    out.push(paint(1, `${r.check.toUpperCase()} \xB7 ${r.target}`) + ` \u2014 ${summary(r.findings)}`);
    if (r.note) out.push(`  ${r.note}`);
    for (const f of r.findings) {
      const where = f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : f.object;
      out.push("", `  ${paint(tone[f.level], LABEL[f.level])} ${f.title}${where ? `  ${paint(2, where)}` : ""}`);
      for (const line of wrap(f.detail, 88)) out.push(`        ${line}`);
      if (f.fix) {
        out.push(`        ${paint(2, "Fix:")}`);
        const lines = f.fix.includes("\n") ? f.fix.split("\n") : wrap(f.fix, 86);
        for (const line of lines) out.push(`          ${line}`);
      }
      if (f.ref) out.push(`        ${paint(2, f.ref)}`);
    }
    if (r.passed.length > 0) out.push("", `  ${paint(32, "Passed")}: ${r.passed.length} checks`);
    out.push("");
  }
  return out.join("\n");
}
function wrap(text, width) {
  const lines = [];
  for (const paragraph of text.split("\n")) {
    let line = "";
    for (const word of paragraph.split(/\s+/)) {
      if (line && line.length + 1 + word.length > width) {
        lines.push(line);
        line = word;
      } else {
        line = line ? `${line} ${word}` : word;
      }
    }
    lines.push(line);
  }
  return lines;
}
var escapeData = (s) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
var escapeProperty = (s) => escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
function formatGithub(reports) {
  const out = [];
  for (const r of reports) {
    for (const f of r.findings) {
      const props = [
        f.file && `file=${escapeProperty(f.file)}`,
        f.file && f.line && `line=${f.line}`,
        `title=${escapeProperty(`${r.check.toUpperCase()}: ${f.title}`)}`
      ].filter(Boolean);
      const where = !f.file && f.object ? `${f.object}
` : "";
      const message = `${where}${f.detail}${f.fix ? `

Fix:
${f.fix}` : ""}`;
      out.push(`::${f.level} ${props.join(",")}::${escapeData(message)}`);
    }
  }
  return out.join("\n");
}
function formatMarkdown(reports) {
  const cell = (s) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");
  const out = ["## NestedBit check", ""];
  for (const r of reports) {
    out.push(`### ${r.check.toUpperCase()}: ${cell(r.target)}`, "", `${summary(r.findings)}.`, "");
    if (r.note) out.push(`_${r.note}_`, "");
    if (r.findings.length > 0) {
      out.push("| Level | Finding | Where |", "|---|---|---|");
      for (const f of r.findings) {
        const where = f.file ? `\`${f.file}${f.line ? `:${f.line}` : ""}\`` : f.object ? `\`${f.object}\`` : "";
        out.push(`| ${f.level} | ${cell(f.title)} | ${cell(where)} |`);
      }
      out.push("");
    }
  }
  out.push("Checked with [@nestedbit/check](https://nestedbit.com/tools). The same checks run in your browser at nestedbit.com.");
  return out.join("\n");
}

// src/action.ts
var input = (env, name) => (env[`INPUT_${name.toUpperCase()}`] ?? "").trim();
var splitPaths = (value) => value.split(/\s+/).filter(Boolean);
async function runAction(io) {
  const { env } = io;
  const fail = (message) => {
    io.out(`::error title=NestedBit check::${escapeData(message)}
`);
    return 1;
  };
  const rls = splitPaths(input(env, "rls"));
  const mcp = input(env, "mcp");
  const tools = input(env, "tools");
  const failOn = input(env, "fail-on") || "error";
  if (![...LEVELS, "never"].includes(failOn)) {
    return fail(`fail-on must be one of ${[...LEVELS, "never"].join(", ")}, not \u201C${failOn}\u201D.`);
  }
  if (rls.length === 0 && !mcp && !tools) {
    return fail("Set at least one input: rls (migration folders or files), mcp (a server URL) or tools (a saved tools/list response).");
  }
  const reports = [];
  try {
    if (rls.length > 0) reports.push(...checkRls(rls, io.cwd));
    if (mcp) reports.push(await checkMcpServer(mcp));
    if (tools) reports.push(reviewToolsFile(tools, io.cwd));
  } catch (err) {
    return fail(err instanceof InputError2 ? err.message : `The check failed: ${err.message}`);
  }
  io.out(`::group::NestedBit check
${formatText(reports)}
::endgroup::
`);
  const annotations = formatGithub(reports);
  if (annotations) io.out(`${annotations}
`);
  const totals = count(reports.flatMap((r) => r.findings));
  if (env.GITHUB_STEP_SUMMARY) io.append(env.GITHUB_STEP_SUMMARY, `${formatMarkdown(reports)}
`);
  if (env.GITHUB_OUTPUT) {
    io.append(env.GITHUB_OUTPUT, `errors=${totals.error}
warnings=${totals.warning}
notices=${totals.notice}
`);
  }
  if (fails(reports, failOn)) {
    const at = LEVELS.slice(0, LEVELS.indexOf(failOn) + 1).reduce((n, l) => n + totals[l], 0);
    io.out(`${at} finding${at === 1 ? "" : "s"} at or above \u201C${failOn}\u201D. Set fail-on to change what fails this step.
`);
    return 1;
  }
  return 0;
}

// src/bin/action.ts
process.exitCode = await runAction({
  out: (t) => process.stdout.write(t),
  append: (file, text) => appendFileSync(file, text),
  env: process.env,
  cwd: process.cwd()
});
