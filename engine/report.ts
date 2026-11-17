// One verdict for a checked server, shared by the report in the visitor's
// browser and the badge on the checker, so the two can't disagree. Also the
// addresses of a shared report and its badge. Imported by the website, so it
// can't import anything that needs Node at runtime.

import { reviewTools, scopePrefix, type Tool, type ToolReview } from './review.ts';
import type { CheckResult, Finding, Severity } from './check.ts';

const ORDER: Severity[] = ['high', 'medium', 'low', 'note'];

export const TOOL_URL = 'https://nestedbit.com/tools/mcp-security-checker';
export const BADGE_URL = 'https://nestedbit.com/api/mcp-badge';

/** The usable entries of what a server listed. A hostile server can send anything. */
export function usableTools(tools: unknown[] | undefined): Tool[] {
  return (tools ?? []).filter((t): t is Tool => !!t && typeof (t as Tool).name === 'string');
}

export function reviewListedTools(tools: Tool[], result: CheckResult | null): ToolReview | null {
  if (tools.length === 0) return null;
  return reviewTools(tools, scopePrefix(result?.server?.name, result ? new URL(result.target).hostname : undefined));
}

/** Server findings plus the tool review, sorted, with the open-access finding judged by what the tools do. */
export function combineFindings(result: CheckResult | null, review: ToolReview | null): Finding[] {
  const findings: Finding[] = [...(result?.findings ?? [])];
  if (result?.auth === 'open') {
    const risky = review?.rows.filter((r) => r.kind !== 'read') ?? [];
    const known = Boolean(review);
    findings.push({
      id: 'open-access',
      severity: !known ? 'medium' : risky.length > 0 ? 'high' : 'note',
      title: 'Anyone can use this server without signing in',
      detail: !known
        ? 'The server answered without asking for a token. That suits public, read-only data, but nothing else.'
        : risky.length > 0
          ? `It answered without a token, and ${risky.length} of its tools change data, delete it or run code (${risky
              .slice(0, 4)
              .map((r) => r.name)
              .join(', ')}${risky.length > 4 ? '…' : ''}). Anyone who finds the address can call them.`
          : 'It answered without a token. All its tools look read-only, which suits public data, as long as nothing it returns is private.',
      fix:
        risky.length > 0 || !known
          ? 'Require OAuth sign-in (protected resource metadata, a 401 challenge and audience-checked tokens), or remove the tools that change data.'
          : undefined,
      ref: 'https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization',
    });
  }
  findings.push(...(review?.findings ?? []));
  return findings.sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
}

export function countFindings(findings: Finding[]) {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const f of findings) if (f.severity !== 'note') counts[f.severity]++;
  return counts;
}

export type BadgeState = 'clean' | 'minor' | 'fixes' | 'unknown';

/** What a badge may say. Clean and minor need a finished check that could tell how the server signs users in. */
export function badgeState(result: CheckResult): BadgeState {
  const counts = countFindings(combineFindings(result, reviewListedTools(usableTools(result.tools), result)));
  if (counts.high > 0 || counts.medium > 0) return 'fixes';
  if (!result.reachable || result.inconclusive || result.auth === 'unknown') return 'unknown';
  return counts.low > 0 ? 'minor' : 'clean';
}

// --- Sharing -------------------------------------------------------------------------

// The address goes in the fragment, which browsers never send to a server, so
// opening a report link leaves it out of hosting logs and referrers.
export function reportLink(target: string) {
  return `${TOOL_URL}#server=${encodeURIComponent(target)}`;
}

export function badgeLink(target: string) {
  return `${BADGE_URL}?url=${encodeURIComponent(target)}`;
}

/** The server address in a report link's fragment, or null. */
export function readReportHash(hash: string): string | null {
  const match = /^#server=(.+)$/.exec(hash);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return null;
  }
}

/** Query strings often carry API keys, so an address with one is never shared or badged. */
export function hasQuery(target: string) {
  return new URL(target).search !== '';
}

/** A path segment that looks like a key or token, as in hosted servers' personal addresses. */
export function looksSecret(target: string) {
  return new URL(target).pathname.split('/').some((segment) => {
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) return true;
    if (/^[0-9a-f]{24,}$/i.test(segment)) return true;
    if (segment.length < 20) return false;
    // Random text keeps switching between letters and digits; dated names don't.
    const switches = segment.replace(/[^A-Za-z0-9]/g, '').match(/[A-Za-z][0-9]|[0-9][A-Za-z]/g);
    return (switches?.length ?? 0) >= 4;
  });
}
