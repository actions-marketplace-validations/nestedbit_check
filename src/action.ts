// The GitHub Action: runs the checks the step's inputs name, turns each finding into an
// annotation on the pull request, adds a table to the job's summary page and fails the
// step when anything is at or above fail-on.
//
//   - uses: nestedbit/check@v1
//     with:
//       rls: supabase/migrations

import { checkMcpServer, reviewToolsFile } from './mcp.ts';
import { checkRls, InputError } from './rls.ts';
import {
  count,
  escapeData,
  fails,
  formatGithub,
  formatMarkdown,
  formatText,
  LEVELS,
  type FailOn,
  type Report,
} from './findings.ts';

type Env = Record<string, string | undefined>;

/** An input as the runner passes it: INPUT_ and the name in capitals, hyphens kept. */
export const input = (env: Env, name: string) => (env[`INPUT_${name.toUpperCase()}`] ?? '').trim();

/** Paths one per line, or several on one line separated by spaces. */
export const splitPaths = (value: string) => value.split(/\s+/).filter(Boolean);

export interface ActionIo {
  out: (text: string) => void;
  /** Appends to a file the runner reads afterwards: the step summary and outputs. */
  append: (file: string, text: string) => void;
  env: Env;
  cwd: string;
}

/** Runs the Action and returns its exit code: 0 passed, 1 failed. */
export async function runAction(io: ActionIo): Promise<number> {
  const { env } = io;
  const fail = (message: string) => {
    io.out(`::error title=NestedBit check::${escapeData(message)}\n`);
    return 1;
  };

  const rls = splitPaths(input(env, 'rls'));
  const mcp = input(env, 'mcp');
  const tools = input(env, 'tools');
  const failOn = (input(env, 'fail-on') || 'error') as FailOn;
  if (![...LEVELS, 'never'].includes(failOn)) {
    return fail(`fail-on must be one of ${[...LEVELS, 'never'].join(', ')}, not “${failOn}”.`);
  }
  if (rls.length === 0 && !mcp && !tools) {
    return fail('Set at least one input: rls (migration folders or files), mcp (a server URL) or tools (a saved tools/list response).');
  }

  const reports: Report[] = [];
  try {
    if (rls.length > 0) reports.push(...checkRls(rls, io.cwd));
    if (mcp) reports.push(await checkMcpServer(mcp));
    if (tools) reports.push(reviewToolsFile(tools, io.cwd));
  } catch (err) {
    return fail(err instanceof InputError ? err.message : `The check failed: ${(err as Error).message}`);
  }

  io.out(`::group::NestedBit check\n${formatText(reports)}\n::endgroup::\n`);
  const annotations = formatGithub(reports);
  if (annotations) io.out(`${annotations}\n`);

  const totals = count(reports.flatMap((r) => r.findings));
  if (env.GITHUB_STEP_SUMMARY) io.append(env.GITHUB_STEP_SUMMARY, `${formatMarkdown(reports)}\n`);
  if (env.GITHUB_OUTPUT) {
    io.append(env.GITHUB_OUTPUT, `errors=${totals.error}\nwarnings=${totals.warning}\nnotices=${totals.notice}\n`);
  }

  if (fails(reports, failOn)) {
    const at = LEVELS.slice(0, LEVELS.indexOf(failOn as (typeof LEVELS)[number]) + 1).reduce((n, l) => n + totals[l], 0);
    io.out(`${at} finding${at === 1 ? '' : 's'} at or above “${failOn}”. Set fail-on to change what fails this step.\n`);
    return 1;
  }
  return 0;
}
