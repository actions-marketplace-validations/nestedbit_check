// `check mcp`: the MCP Security Checker from nestedbit.com/tools/mcp-security-checker,
// run from your own machine or CI runner. Unlike the hosted checker, it can reach
// http://localhost, private networks and staging servers behind a VPN, because the
// requests leave from wherever it runs. Nothing goes to nestedbit.com.
//
// `--tools <file>` reviews a saved tools/list response instead, offline: what each
// tool does, the scopes it should need and which ones should ask before running.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { checkServer, InputError as TargetError, type Finding as McpFinding, type CheckResult } from '../engine/check.ts';
import { localRequest, type RequestFn } from '../engine/guard.ts';
import { combineFindings, reviewListedTools, usableTools } from '../engine/report.ts';
import { parseToolList } from '../engine/review.ts';
import type { Finding, Level, Report } from './findings.ts';
import { InputError, shortPath } from './rls.ts';

const LEVEL: Record<McpFinding['severity'], Level> = { high: 'error', medium: 'warning', low: 'notice', note: 'notice' };

function toFinding(f: McpFinding, extra: Partial<Finding> = {}): Finding {
  return {
    check: 'mcp',
    id: f.id,
    level: LEVEL[f.severity],
    title: f.title,
    detail: f.detail,
    ...(f.fix && { fix: f.fix }),
    ...(f.ref && { ref: f.ref }),
    ...extra,
  };
}

export interface McpOptions {
  /** Injected in tests; defaults to a plain request that allows local addresses. */
  request?: RequestFn;
  timeoutMs?: number;
}

/** Checks a running MCP server, as the hosted checker does, from this machine. */
export async function checkMcpServer(url: string, options: McpOptions = {}): Promise<Report> {
  let result: CheckResult;
  try {
    result = await checkServer(url, {
      request: options.request ?? localRequest,
      allowHttp: true,
      deadline: Date.now() + (options.timeoutMs ?? 25_000),
    });
  } catch (err) {
    if (err instanceof TargetError) throw new InputError(err.message);
    throw err;
  }
  const findings = combineFindings(result, reviewListedTools(usableTools(result.tools), result)).map((f) =>
    toFinding(f, { object: result.target }),
  );
  const notes: string[] = [];
  if (new URL(result.target).protocol === 'http:') {
    notes.push('Checked over plain HTTP, which is fine on your own machine; a server on the internet must use HTTPS.');
  }
  if (result.toolsNote) notes.push(result.toolsNote);
  // A check that couldn't finish is a failure in CI: the server is down, or answers nothing like MCP.
  if (result.inconclusive) {
    findings.unshift({
      check: 'mcp',
      id: 'inconclusive',
      level: 'error',
      title: 'Couldn’t check this server',
      detail: result.inconclusive,
      object: result.target,
    });
  }
  return {
    check: 'mcp',
    target: result.target,
    findings,
    passed: result.passed,
    ...(notes.length > 0 && { note: notes.join(' ') }),
  };
}

/** Reviews a saved tools/list response (JSON, or the SSE text a server sends) without contacting anything. */
export function reviewToolsFile(file: string, cwd = process.cwd()): Report {
  const rel = shortPath(file, cwd);
  let text: string;
  try {
    text = readFileSync(path.resolve(cwd, file), 'utf8');
  } catch {
    throw new InputError(`Can’t read ${file}.`);
  }
  let tools;
  try {
    tools = usableTools(parseToolList(text));
  } catch (err) {
    throw new InputError(`${rel}: ${(err as Error).message}`);
  }
  if (tools.length === 0) throw new InputError(`${rel} lists no tools.`);
  const review = reviewListedTools(tools, null);
  return {
    check: 'mcp',
    target: rel,
    findings: combineFindings(null, review).map((f) => toFinding(f, { file: rel })),
    passed: [],
    note: `Reviewed ${tools.length} tool${tools.length === 1 ? '' : 's'} from tools/list: names, descriptions, input schemas and annotations, not what each tool’s code does.`,
  };
}
