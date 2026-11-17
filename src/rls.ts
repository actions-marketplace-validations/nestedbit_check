// `check rls`: the Supabase RLS checker from nestedbit.com/tools/supabase-rls-generator,
// on files in a repo. It reads migration SQL (a folder of .sql files, applied in
// name order like supabase/migrations) or the JSON the site's catalog query returns,
// and never connects to a database.
//
// SQL files are linted together, in order, so a table made in one migration and
// secured in a later one counts as secured. Each finding's line is mapped back to
// the file it came from.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { lintSupabase, MAX_INPUT, type LintResult } from '../engine/shared/supabase-lint.ts';
import type { Finding, Level, Report } from './findings.ts';

const LEVEL: Record<LintResult['findings'][number]['severity'], Level> = {
  error: 'error',
  warning: 'warning',
  note: 'notice',
};

export class InputError extends Error {}

/** The files to read: .sql and .json files as given, and a folder's .sql files in name order. */
export function collectFiles(inputs: string[], cwd = process.cwd()): string[] {
  const files: string[] = [];
  for (const input of inputs) {
    const full = path.resolve(cwd, input);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      throw new InputError(`Can’t find ${input}.`);
    }
    if (stat.isDirectory()) {
      const sql = readdirSync(full)
        .filter((name) => name.toLowerCase().endsWith('.sql'))
        .sort()
        .map((name) => path.join(full, name));
      if (sql.length === 0) throw new InputError(`${input} has no .sql files.`);
      files.push(...sql);
    } else if (/\.(sql|json)$/i.test(full)) {
      files.push(full);
    } else {
      throw new InputError(`${input} isn’t a .sql file, a .json catalog file or a folder of .sql files.`);
    }
  }
  return [...new Set(files)];
}

interface Part {
  file: string;
  /** Line in the joined SQL where this file starts (1-based). */
  start: number;
  lines: number;
}

/** Joins SQL files into one script and remembers where each starts, so lines map back. */
export function joinSql(files: { file: string; text: string }[]): { sql: string; parts: Part[] } {
  const parts: Part[] = [];
  const chunks: string[] = [];
  let line = 1;
  for (const { file, text } of files) {
    const body = text.endsWith('\n') ? text : `${text}\n`;
    const lines = body.split('\n').length - 1;
    parts.push({ file, start: line, lines });
    chunks.push(body);
    line += lines;
  }
  return { sql: chunks.join(''), parts };
}

export function locate(parts: Part[], line: number | undefined): { file?: string; line?: number } {
  if (!line) return {};
  const part = parts.find((p) => line >= p.start && line < p.start + p.lines);
  return part ? { file: part.file, line: line - part.start + 1 } : {};
}

function toFindings(result: LintResult, where: (line?: number) => { file?: string; line?: number }): Finding[] {
  return result.findings.map((f) => ({
    check: 'rls',
    id: f.id,
    level: LEVEL[f.severity],
    title: f.title,
    detail: f.detail,
    ...(f.fix && { fix: f.fix.trim() }),
    ...(f.object && { object: f.object }),
    ...where(f.line),
  }));
}

const plural = (n: number, word: string, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

/** A path relative to the working directory, as annotations need, or absolute when it's outside it. */
export function shortPath(file: string, cwd: string): string {
  const full = path.resolve(cwd, file);
  const rel = path.relative(cwd, full);
  return !rel ? path.basename(full) : rel.startsWith('..') || path.isAbsolute(rel) ? full : rel;
}

/** Lints the given paths and returns one report per input kind: the SQL together, each JSON file alone. */
export function checkRls(inputs: string[], cwd = process.cwd()): Report[] {
  const files = collectFiles(inputs, cwd);
  const rel = (file: string) => shortPath(file, cwd);
  const read = (file: string) => {
    const text = readFileSync(file, 'utf8');
    if (text.length > MAX_INPUT) throw new InputError(`${rel(file)} is over ${MAX_INPUT / 1_000_000} MB.`);
    return text;
  };

  const reports: Report[] = [];
  const sqlFiles = files.filter((f) => /\.sql$/i.test(f));
  if (sqlFiles.length > 0) {
    const { sql, parts } = joinSql(sqlFiles.map((file) => ({ file: rel(file), text: read(file) })));
    if (sql.length > MAX_INPUT) throw new InputError(`The SQL files together are over ${MAX_INPUT / 1_000_000} MB.`);
    const result = lintSupabase(sql);
    reports.push({
      check: 'rls',
      target: sqlFiles.length === 1 ? rel(sqlFiles[0]) : `${sqlFiles.length} SQL files`,
      findings: toFindings(result, (line) => locate(parts, line)),
      passed: [],
      note:
        `Read ${plural(result.counts.statements, 'statement')}: ${plural(result.counts.tables, 'table')}, ` +
        `${plural(result.counts.policies, 'policy', 'policies')}, ${plural(result.counts.functions, 'function')}. ` +
        'Where the SQL sets no grants, Supabase’s defaults are assumed. These checks read settings, not your app’s code.',
    });
  }
  for (const file of files.filter((f) => /\.json$/i.test(f))) {
    let result: LintResult;
    try {
      result = lintSupabase(read(file));
    } catch (err) {
      throw new InputError(`${rel(file)}: ${(err as Error).message}`);
    }
    reports.push({
      check: 'rls',
      target: rel(file),
      findings: toFindings(result, () => ({ file: rel(file) })),
      passed: [],
      note: 'Read from the catalog query: real grants, policies, functions and buckets.',
    });
  }
  return reports;
}
