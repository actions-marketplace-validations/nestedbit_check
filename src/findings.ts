// One shape for every check's findings, and the three ways to print them:
// text for a terminal, JSON for scripts, and GitHub workflow commands, which
// turn each finding into an annotation on the pull request's changed lines.

export type Level = 'error' | 'warning' | 'notice';

export interface Finding {
  /** Which check found it: rls, mcp. */
  check: string;
  /** The engine's own ID, stable across runs. */
  id: string;
  level: Level;
  title: string;
  detail: string;
  /** What to change: SQL, code or a setting. */
  fix?: string;
  /** What it's about: schema.table, a URL. */
  object?: string;
  /** Where it is, relative to the working directory, when it comes from a file. */
  file?: string;
  line?: number;
  /** The specification or doc that applies. */
  ref?: string;
}

export interface Report {
  check: string;
  /** What was checked: files or a URL. */
  target: string;
  findings: Finding[];
  /** Checks that passed, where the engine lists them. */
  passed: string[];
  /** A line on what the check could not see or do, when it matters. */
  note?: string;
}

export const LEVELS: Level[] = ['error', 'warning', 'notice'];

export type FailOn = Level | 'never';

/** True when any finding is at or above the level that fails the run. */
export function fails(reports: Report[], failOn: FailOn): boolean {
  if (failOn === 'never') return false;
  const threshold = LEVELS.indexOf(failOn);
  return reports.some((r) => r.findings.some((f) => LEVELS.indexOf(f.level) <= threshold));
}

export function count(findings: Finding[]) {
  return Object.fromEntries(LEVELS.map((l) => [l, findings.filter((f) => f.level === l).length])) as Record<Level, number>;
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

export function summary(findings: Finding[]): string {
  const c = count(findings);
  if (findings.length === 0) return 'no findings';
  return [plural(c.error, 'error'), plural(c.warning, 'warning'), plural(c.notice, 'notice')].join(', ');
}

// --- text ----------------------------------------------------------------------------

const LABEL: Record<Level, string> = { error: 'ERROR', warning: 'WARN ', notice: 'NOTE ' };

export function formatText(reports: Report[], { color = false }: { color?: boolean } = {}): string {
  const paint = (code: number, text: string) => (color ? `\u001b[${code}m${text}\u001b[0m` : text);
  const tone: Record<Level, number> = { error: 31, warning: 33, notice: 36 };
  const out: string[] = [];
  for (const r of reports) {
    out.push(paint(1, `${r.check.toUpperCase()} · ${r.target}`) + ` — ${summary(r.findings)}`);
    if (r.note) out.push(`  ${r.note}`);
    for (const f of r.findings) {
      const where = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : f.object;
      out.push('', `  ${paint(tone[f.level], LABEL[f.level])} ${f.title}${where ? `  ${paint(2, where)}` : ''}`);
      for (const line of wrap(f.detail, 88)) out.push(`        ${line}`);
      if (f.fix) {
        out.push(`        ${paint(2, 'Fix:')}`);
        // A one-line fix is advice, so it wraps; a longer one is SQL or code, kept as written.
        const lines = f.fix.includes('\n') ? f.fix.split('\n') : wrap(f.fix, 86);
        for (const line of lines) out.push(`          ${line}`);
      }
      if (f.ref) out.push(`        ${paint(2, f.ref)}`);
    }
    if (r.passed.length > 0) out.push('', `  ${paint(32, 'Passed')}: ${r.passed.length} checks`);
    out.push('');
  }
  return out.join('\n');
}

function wrap(text: string, width: number): string[] {
  const lines: string[] = [];
  for (const paragraph of text.split('\n')) {
    let line = '';
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

// --- JSON --------------------------------------------------------------------------------

export function formatJson(reports: Report[]): string {
  return JSON.stringify({ tool: '@nestedbit/check', reports }, null, 2);
}

// --- GitHub workflow commands --------------------------------------------------------------
// https://docs.github.com/actions/reference/workflows-and-actions/workflow-commands

/** Escapes a workflow command's message. */
export const escapeData = (s: string) => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');

/** Escapes a workflow command's property value. */
export const escapeProperty = (s: string) => escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');

export function formatGithub(reports: Report[]): string {
  const out: string[] = [];
  for (const r of reports) {
    for (const f of r.findings) {
      const props = [
        f.file && `file=${escapeProperty(f.file)}`,
        f.file && f.line && `line=${f.line}`,
        `title=${escapeProperty(`${r.check.toUpperCase()}: ${f.title}`)}`,
      ].filter(Boolean);
      const where = !f.file && f.object ? `${f.object}\n` : '';
      const message = `${where}${f.detail}${f.fix ? `\n\nFix:\n${f.fix}` : ''}`;
      out.push(`::${f.level} ${props.join(',')}::${escapeData(message)}`);
    }
  }
  return out.join('\n');
}

/** A Markdown summary for the job's summary page ($GITHUB_STEP_SUMMARY). */
export function formatMarkdown(reports: Report[]): string {
  const cell = (s: string) => s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
  const out = ['## NestedBit check', ''];
  for (const r of reports) {
    out.push(`### ${r.check.toUpperCase()}: ${cell(r.target)}`, '', `${summary(r.findings)}.`, '');
    if (r.note) out.push(`_${r.note}_`, '');
    if (r.findings.length > 0) {
      out.push('| Level | Finding | Where |', '|---|---|---|');
      for (const f of r.findings) {
        const where = f.file ? `\`${f.file}${f.line ? `:${f.line}` : ''}\`` : f.object ? `\`${f.object}\`` : '';
        out.push(`| ${f.level} | ${cell(f.title)} | ${cell(where)} |`);
      }
      out.push('');
    }
  }
  out.push('Checked with [@nestedbit/check](https://nestedbit.com/tools). The same checks run in your browser at nestedbit.com.');
  return out.join('\n');
}
