// The CLI and the GitHub Action: reading migrations across files, the three output
// formats, exit codes, and the MCP check against a real server on localhost.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { run, type Io } from '../src/cli.ts';
import { runAction } from '../src/action.ts';
import { escapeData, escapeProperty, fails, formatGithub, formatMarkdown, type Report } from '../src/findings.ts';
import { checkMcpServer, reviewToolsFile } from '../src/mcp.ts';
import { checkRls, collectFiles, InputError, joinSql, locate } from '../src/rls.ts';

const here = path.dirname(fileURLToPath(import.meta.url));
const cwd = path.join(here, 'fixtures');

function capture(): Io & { stdout: () => string; stderr: () => string } {
  let out = '';
  let err = '';
  return {
    out: (t) => (out += t),
    err: (t) => (err += t),
    color: false,
    cwd,
    stdout: () => out,
    stderr: () => err,
  };
}

// --- rls --------------------------------------------------------------------------

test('a folder is read as its .sql files in name order', () => {
  const files = collectFiles(['migrations'], cwd).map((f) => path.basename(f));
  assert.deepEqual(files, ['20260101000000_init.sql', '20260102000000_more.sql']);
  assert.throws(() => collectFiles(['missing'], cwd), InputError);
  assert.throws(() => collectFiles(['tools-list.txt'], cwd), InputError);
});

test('lines in joined SQL map back to their file', () => {
  const { sql, parts } = joinSql([
    { file: 'a.sql', text: 'one;\ntwo;' },
    { file: 'b.sql', text: 'three;\nfour;\nfive;\n' },
  ]);
  assert.equal(sql, 'one;\ntwo;\nthree;\nfour;\nfive;\n');
  assert.deepEqual(locate(parts, 2), { file: 'a.sql', line: 2 });
  assert.deepEqual(locate(parts, 3), { file: 'b.sql', line: 1 });
  assert.deepEqual(locate(parts, 5), { file: 'b.sql', line: 3 });
  assert.deepEqual(locate(parts, undefined), {});
});

test('a table secured in a later migration counts as secured', () => {
  const [report] = checkRls(['migrations'], cwd);
  const open = report.findings.filter((f) => f.id === 'rls_disabled_in_public');
  assert.deepEqual(
    open.map((f) => f.object),
    ['public.payments'],
  );
  assert.equal(open[0].level, 'error');
  assert.equal(open[0].file, path.join('migrations', '20260102000000_more.sql'));
  assert.equal(open[0].line, 5);
  assert.match(open[0].fix ?? '', /alter table public\.payments enable row level security;/);
  assert.match(report.note ?? '', /3 tables, 2 policies/);
});

test('clean migrations pass, and the CLI exits 0', async () => {
  const io = capture();
  assert.equal(await run(['rls', 'clean'], io), 0);
  assert.match(io.stdout(), /no findings/);
});

test('the CLI exits 1 on an error, unless --fail-on never', async () => {
  assert.equal(await run(['rls', 'migrations'], capture()), 1);
  assert.equal(await run(['rls', 'migrations', '--fail-on', 'never'], capture()), 0);
});

test('bad arguments exit 2 with a reason', async () => {
  for (const args of [[], ['rls'], ['rls', 'missing'], ['lint', 'x'], ['rls', 'clean', '--format', 'xml'], ['rls', 'clean', '--fail-on', 'high'], ['mcp'], ['mcp', 'a', 'b'], ['--nope']]) {
    const io = capture();
    assert.equal(await run(args, io), 2, args.join(' '));
    assert.ok(io.stderr().length > 0, args.join(' '));
  }
  const io = capture();
  assert.equal(await run(['--help'], io), 0);
  assert.match(io.stdout(), /nestedbit-check rls <path\.\.\.>/);
});

test('JSON output lists every finding with its place', async () => {
  const io = capture();
  await run(['rls', 'migrations', '--format', 'json'], io);
  const parsed = JSON.parse(io.stdout());
  assert.equal(parsed.tool, '@nestedbit/check');
  const finding = parsed.reports[0].findings.find((f: { id: string }) => f.id === 'rls_disabled_in_public');
  assert.equal(finding.line, 5);
});

// --- GitHub output ----------------------------------------------------------------------

test('workflow commands escape what would end or split them', () => {
  assert.equal(escapeData('50% done\r\nnext'), '50%25 done%0D%0Anext');
  assert.equal(escapeProperty('a:b,c'), 'a%3Ab%2Cc');
  const report: Report = {
    check: 'rls',
    target: 'x',
    passed: [],
    findings: [
      { check: 'rls', id: 'a', level: 'error', title: 'Open: a, b', detail: 'Line one\nline two', fix: 'do x;', file: 'db/1.sql', line: 3 },
      { check: 'mcp', id: 'b', level: 'notice', title: 'No file', detail: 'About a URL', object: 'http://localhost:3000/mcp' },
    ],
  };
  const [first, second] = formatGithub([report]).split('\n');
  assert.equal(first, '::error file=db/1.sql,line=3,title=RLS%3A Open%3A a%2C b::Line one%0Aline two%0A%0AFix:%0Ado x;');
  assert.equal(second, '::notice title=RLS%3A No file::http://localhost:3000/mcp%0AAbout a URL');
  assert.match(formatMarkdown([report]), /\| error \| Open: a, b \| `db\/1\.sql:3` \|/);
});

test('fail-on compares levels', () => {
  const at = (level: 'error' | 'warning' | 'notice'): Report[] => [
    { check: 'x', target: 'x', passed: [], findings: [{ check: 'x', id: 'x', level, title: 'x', detail: 'x' }] },
  ];
  assert.equal(fails(at('warning'), 'error'), false);
  assert.equal(fails(at('warning'), 'warning'), true);
  assert.equal(fails(at('error'), 'notice'), true);
  assert.equal(fails(at('error'), 'never'), false);
  assert.equal(fails([], 'notice'), false);
});

test('the Action annotates, summarises, sets outputs and fails the step', async () => {
  let out = '';
  const files: Record<string, string> = {};
  const code = await runAction({
    out: (t) => (out += t),
    append: (file, text) => (files[file] = (files[file] ?? '') + text),
    env: { INPUT_RLS: 'migrations\nclean', 'INPUT_FAIL-ON': 'error', GITHUB_STEP_SUMMARY: 'summary.md', GITHUB_OUTPUT: 'output.txt' },
    cwd,
  });
  assert.equal(code, 1);
  assert.match(out, /^::group::NestedBit check$/m);
  assert.match(out, /^::error file=migrations\/20260102000000_more\.sql,line=5,/m);
  assert.match(out, /1 finding at or above “error”/);
  assert.match(files['summary.md'], /## NestedBit check/);
  assert.equal(files['output.txt'], 'errors=1\nwarnings=0\nnotices=0\n');
});

test('the Action passes clean input and refuses a step with nothing to check', async () => {
  const quiet = { out: () => {}, append: () => {}, cwd };
  assert.equal(await runAction({ ...quiet, env: { INPUT_RLS: 'clean' } }), 0);
  assert.equal(await runAction({ ...quiet, env: { INPUT_RLS: 'migrations', 'INPUT_FAIL-ON': 'never' } }), 0);
  let out = '';
  assert.equal(await runAction({ ...quiet, out: (t) => (out += t), env: {} }), 1);
  assert.match(out, /^::error title=NestedBit check::Set at least one input/);
  assert.equal(await runAction({ ...quiet, env: { INPUT_RLS: 'clean', 'INPUT_FAIL-ON': 'loud' } }), 1);
});

// --- mcp --------------------------------------------------------------------------

test('a saved tools/list is reviewed offline', () => {
  const report = reviewToolsFile('tools-list.json', cwd);
  assert.equal(report.target, 'tools-list.json');
  const levels = Object.fromEntries(report.findings.map((f) => [f.title, f.level]));
  assert.equal(levels['Tools that run commands or code'], 'error');
  assert.equal(levels['Tools that delete or revoke'], 'warning');
  assert.ok(report.findings.every((f) => f.file === 'tools-list.json'));
  assert.throws(() => reviewToolsFile('migrations/20260101000000_init.sql', cwd), InputError);
});

/** A minimal open MCP server over plain HTTP, the kind a developer runs locally. */
async function localServer(): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      if (req.method !== 'POST') {
        res.writeHead(405).end();
        return;
      }
      const msg = JSON.parse(body || '{}');
      const reply = (result: unknown) => {
        res.writeHead(200, { 'content-type': 'application/json', 'mcp-session-id': '1' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result }));
      };
      if (msg.method === 'initialize') return reply({ protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'Local', version: '0.0.1' } });
      if (msg.method === 'tools/list') return reply({ tools: [{ name: 'run_shell', description: 'Run a shell command.', inputSchema: { type: 'object', properties: { command: { type: 'string' } } } }] });
      res.writeHead(202).end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

test('checks a server on localhost over plain HTTP', async () => {
  const server = await localServer();
  try {
    const report = await checkMcpServer(server.url, { timeoutMs: 10_000 });
    assert.equal(report.target, server.url);
    assert.match(report.note ?? '', /plain HTTP/);
    const ids = report.findings.map((f) => f.id);
    assert.ok(!ids.includes('inconclusive'), ids.join(', '));
    assert.ok(report.findings.some((f) => f.level === 'error' && /commands or code/.test(f.title)), ids.join(', '));
  } finally {
    await server.close();
  }
});

test('a server that is down fails the check', async () => {
  const server = await localServer();
  const url = server.url;
  await server.close();
  const report = await checkMcpServer(url, { timeoutMs: 5_000 });
  assert.equal(report.findings[0].id, 'inconclusive');
  assert.equal(report.findings[0].level, 'error');
});
