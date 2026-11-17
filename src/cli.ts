// nestedbit-check: NestedBit's free security checks, from a terminal or CI.
//
//   nestedbit-check rls supabase/migrations
//   nestedbit-check mcp http://localhost:3000/mcp
//   nestedbit-check mcp --tools tools-list.json
//
// Exit codes: 0 nothing at or above --fail-on, 1 findings at or above it,
// 2 bad arguments or input, 3 the check itself failed.

import { parseArgs } from 'node:util';
import { fails, formatGithub, formatJson, formatText, LEVELS, type FailOn, type Report } from './findings.ts';
import { checkRls, InputError } from './rls.ts';
import { checkMcpServer, reviewToolsFile } from './mcp.ts';

declare const __VERSION__: string | undefined;
export const VERSION = typeof __VERSION__ === 'string' ? __VERSION__ : 'dev';

export const HELP = `nestedbit-check ${VERSION}: NestedBit's free security checks, from a terminal or CI.

Usage
  nestedbit-check rls <path...>        Supabase row-level security, from migration SQL
                                       (a folder of .sql files, applied in name order)
                                       or the JSON the site's catalog query returns
  nestedbit-check mcp <url>            An MCP server's sign-in, discovery and tools,
                                       checked from this machine (localhost works)
  nestedbit-check mcp --tools <file>   A saved tools/list response, reviewed offline

Options
  --format text|json|github   Output (default: text). github prints annotations
                              for GitHub Actions.
  --fail-on error|warning|notice|never
                              Exit 1 when a finding is at or above this level
                              (default: error).
  -h, --help                  Show this help.
  -v, --version               Show the version.

Nothing is sent to NestedBit. The same checks run in your browser at
https://nestedbit.com/tools/supabase-rls-generator and
https://nestedbit.com/tools/mcp-security-checker.
`;

export interface Io {
  out: (text: string) => void;
  err: (text: string) => void;
  color: boolean;
  cwd: string;
}

const FORMATS = ['text', 'json', 'github'] as const;
type Format = (typeof FORMATS)[number];

export function render(reports: Report[], format: Format, color = false): string {
  if (format === 'json') return formatJson(reports);
  if (format === 'github') return formatGithub(reports);
  return formatText(reports, { color });
}

/** Runs the CLI and returns its exit code. */
export async function run(argv: string[], io: Io): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        format: { type: 'string', default: 'text' },
        'fail-on': { type: 'string', default: 'error' },
        tools: { type: 'string' },
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
      },
    });
  } catch (err) {
    io.err(`${(err as Error).message}\n\n${HELP}`);
    return 2;
  }
  const { values, positionals } = parsed;
  if (values.version) {
    io.out(`${VERSION}\n`);
    return 0;
  }
  const [command, ...rest] = positionals;
  if (values.help || !command) {
    (values.help ? io.out : io.err)(HELP);
    return values.help ? 0 : 2;
  }
  const format = values.format as Format;
  if (!FORMATS.includes(format)) {
    io.err(`--format must be one of ${FORMATS.join(', ')}.\n`);
    return 2;
  }
  const failOn = values['fail-on'] as FailOn;
  if (![...LEVELS, 'never'].includes(failOn)) {
    io.err(`--fail-on must be one of ${[...LEVELS, 'never'].join(', ')}.\n`);
    return 2;
  }

  let reports: Report[];
  try {
    if (command === 'rls') {
      if (rest.length === 0) throw new InputError('Give a folder of migrations or a .sql or .json file, such as supabase/migrations.');
      reports = checkRls(rest, io.cwd);
    } else if (command === 'mcp') {
      if (values.tools) {
        if (rest.length > 0) throw new InputError('Give either a server URL or --tools <file>, not both.');
        reports = [reviewToolsFile(values.tools, io.cwd)];
      } else {
        if (rest.length !== 1) throw new InputError('Give one MCP server URL, such as http://localhost:3000/mcp.');
        reports = [await checkMcpServer(rest[0])];
      }
    } else {
      throw new InputError(`Unknown command “${command}”. Use rls or mcp.`);
    }
  } catch (err) {
    if (err instanceof InputError) {
      io.err(`${err.message}\n`);
      return 2;
    }
    io.err(`The check failed: ${(err as Error).message}\n`);
    return 3;
  }

  const text = render(reports, format, io.color);
  if (text) io.out(`${text}\n`);
  return fails(reports, failOn) ? 1 : 0;
}
