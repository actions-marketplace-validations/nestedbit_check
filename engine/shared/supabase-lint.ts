// Supabase RLS Checker: reads a project's schema, either as SQL (migrations,
// `supabase db dump`, pg_dump) or as the JSON the catalog query below returns,
// and reports what the Data API exposes. The checks follow Supabase's own
// database linter (splinter, github.com/supabase/splinter), plus mistakes it
// doesn't look for. Each finding comes with SQL that fixes it.
//
// Pure TypeScript with no DOM: nothing the visitor pastes leaves the browser.
// test/supabase-lint.test.ts covers it.

import { comment, identifier, pgName } from './supabase-rls.ts';
import type { Severity } from './access-model.ts';

// ---------------------------------------------------------------------------
// Tokens

type TokenKind = 'word' | 'ident' | 'string' | 'number' | 'op';

export interface Token {
  kind: TokenKind;
  /** As written. */
  text: string;
  /** Words lowercased, quoted identifiers and strings without their quotes. */
  value: string;
  line: number;
  /** Where it starts in the text it was read from; tokens a fix adds have none. */
  offset?: number;
}

/** Characters Postgres builds operators from, such as ->>, ~~* (ILIKE), ?| or =>. */
const OP_CHARS = new Set('+-*/<>=~!@#%^&|`?');
/** With one of these in it, an operator may end in + or -. */
const OP_SIGN_KEEPERS = new Set('~!@#%^&|`?');

/**
 * The operator that starts at i, read the way Postgres reads it: the longest
 * run of operator characters, cut where a comment starts, and without a
 * trailing + or - unless the run has one of ~!@#%^&|`? (so a=-1 is = then -1).
 */
function operatorAt(sql: string, i: number): string {
  let end = i;
  while (end < sql.length && OP_CHARS.has(sql[end])) end += 1;
  let text = sql.slice(i, end);
  const cut = text.search(/--|\/\*/);
  if (cut > 0) text = text.slice(0, cut);
  if (text.length > 1 && /[+-]$/.test(text) && ![...text].some((c) => OP_SIGN_KEEPERS.has(c))) {
    text = text.replace(/[+-]+$/, '') || text[0];
  }
  return text;
}

/** Postgres folds unquoted names to lower case, A to Z only: Übersicht keeps its Ü. */
const foldName = (text: string) => text.replace(/[A-Z]+/g, (c) => c.toLowerCase());

/** Splits SQL into tokens, skipping comments and psql meta-commands such as \restrict. */
export function tokenize(sql: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  let line = 1;
  const n = sql.length;
  let lineStart = true;
  let start = 0;
  const push = (kind: TokenKind, text: string, value: string, at: number) => out.push({ kind, text, value, line: at, offset: start });
  const count = (text: string) => {
    for (const ch of text) if (ch === '\n') line += 1;
  };

  while (i < n) {
    const ch = sql[i];
    if (ch === '\n') {
      line += 1;
      i += 1;
      lineStart = true;
      continue;
    }
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\f') {
      i += 1;
      continue;
    }
    // psql meta-commands (pg_dump 17.6+ writes \restrict and \unrestrict) run to the end of the line.
    if (ch === '\\' && lineStart) {
      while (i < n && sql[i] !== '\n') i += 1;
      continue;
    }
    lineStart = false;
    if (ch === '-' && sql[i + 1] === '-') {
      while (i < n && sql[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '/' && sql[i + 1] === '*') {
      let depth = 0;
      while (i < n) {
        if (sql[i] === '/' && sql[i + 1] === '*') {
          depth += 1;
          i += 2;
        } else if (sql[i] === '*' && sql[i + 1] === '/') {
          depth -= 1;
          i += 2;
          if (depth === 0) break;
        } else {
          if (sql[i] === '\n') line += 1;
          i += 1;
        }
      }
      continue;
    }
    start = i;
    const at = line;
    // E'...' strings take backslash escapes.
    if ((ch === 'E' || ch === 'e') && sql[i + 1] === "'") {
      i += 2;
      let value = '';
      while (i < n) {
        if (sql[i] === '\\' && i + 1 < n) {
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
      const text = sql.slice(start, i);
      count(text);
      push('string', text, value, at);
      continue;
    }
    if (ch === "'") {
      i += 1;
      let value = '';
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
      const text = sql.slice(start, i);
      count(text);
      push('string', text, value, at);
      continue;
    }
    if (ch === '$') {
      const tag = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i, i + 64));
      if (tag) {
        const end = sql.indexOf(tag[0], i + tag[0].length);
        const stop = end === -1 ? n : end + tag[0].length;
        const text = sql.slice(i, stop);
        const value = sql.slice(i + tag[0].length, end === -1 ? n : end);
        i = stop;
        count(text);
        push('string', text, value, at);
        continue;
      }
      // $1 parameters.
      const param = /^\$\d+/.exec(sql.slice(i, i + 12));
      if (param) {
        i += param[0].length;
        push('word', param[0], param[0], at);
        continue;
      }
    }
    if (ch === '"') {
      i += 1;
      let value = '';
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
      const text = sql.slice(start, i);
      count(text);
      push('ident', text, value, at);
      continue;
    }
    if (/[A-Za-z_\u0080-￿]/.test(ch)) {
      while (i < n && /[A-Za-z0-9_$\u0080-￿]/.test(sql[i])) i += 1;
      const text = sql.slice(start, i);
      push('word', text, foldName(text), at);
      continue;
    }
    if (/[0-9]/.test(ch) || (ch === '.' && /[0-9]/.test(sql[i + 1] ?? ''))) {
      while (i < n && /[0-9.eE]/.test(sql[i])) i += 1;
      const text = sql.slice(start, i);
      push('number', text, text, at);
      continue;
    }
    const text = ch === ':' && sql[i + 1] === ':' ? '::' : OP_CHARS.has(ch) ? operatorAt(sql, i) : ch;
    i += text.length;
    push('op', text, text, at);
  }
  return out;
}

export interface Statement {
  tokens: Token[];
  line: number;
}

/** Groups tokens into statements at each top-level semicolon, keeping BEGIN ATOMIC function bodies whole. */
export function splitStatements(tokens: Token[]): Statement[] {
  const out: Statement[] = [];
  let current: Token[] = [];
  let atomic = 0;
  let cases = 0;
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t.kind === 'word') {
      if (t.value === 'atomic' && tokens[i - 1]?.value === 'begin') atomic += 1;
      else if (atomic > 0 && t.value === 'case') cases += 1;
      else if (atomic > 0 && t.value === 'end') {
        if (cases > 0) cases -= 1;
        else atomic -= 1;
      }
    }
    if (t.kind === 'op' && t.value === ';' && atomic === 0) {
      if (current.length > 0) out.push({ tokens: current, line: current[0].line });
      current = [];
      continue;
    }
    current.push(t);
  }
  if (current.length > 0) out.push({ tokens: current, line: current[0].line });
  return out;
}

// ---------------------------------------------------------------------------
// Expressions

export interface Expr {
  tokens: Token[];
}

const isName = (t: Token | undefined): t is Token => !!t && (t.kind === 'word' || t.kind === 'ident');
const isOp = (t: Token | undefined, value: string) => !!t && t.kind === 'op' && t.value === value;
const isWord = (t: Token | undefined, ...values: string[]) => !!t && t.kind === 'word' && values.includes(t.value);

/**
 * For each parenthesis, the index of the one that matches it, or -1. One pass,
 * so deeply nested or unbalanced input stays linear.
 */
function pairs(tokens: Token[]): Int32Array {
  const out = new Int32Array(tokens.length).fill(-1);
  const stack: number[] = [];
  for (let i = 0; i < tokens.length; i += 1) {
    if (isOp(tokens[i], '(')) stack.push(i);
    else if (isOp(tokens[i], ')') && stack.length > 0) {
      const open = stack.pop()!;
      out[open] = i;
      out[i] = open;
    }
  }
  return out;
}

/** The tokens without parentheses wrapped around all of them. */
function unwrap(tokens: Token[]): Token[] {
  const match = pairs(tokens);
  let start = 0;
  let end = tokens.length - 1;
  while (end > start && isOp(tokens[start], '(') && match[start] === end) {
    start += 1;
    end -= 1;
  }
  return start === 0 ? tokens : tokens.slice(start, end + 1);
}

/** Splits at a keyword such as or/and where it isn't inside parentheses. */
function splitTop(tokens: Token[], word: string): Token[][] {
  const out: Token[][] = [];
  let depth = 0;
  let current: Token[] = [];
  for (const t of tokens) {
    if (isOp(t, '(')) depth += 1;
    else if (isOp(t, ')')) depth -= 1;
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

const SPACE_BEFORE_PAREN = new Set([
  'in', 'exists', 'any', 'all', 'some', 'and', 'or', 'not', 'select', 'where', 'using', 'check', 'as', 'on', 'from',
  'values', 'then', 'else', 'when', 'is', 'array', 'with', 'returning', 'join', 'case',
]);

/** Tokens as readable SQL, keeping each token as it was written. */
export function render(tokens: Token[]): string {
  let out = '';
  let prev: Token | undefined;
  let before: Token | undefined;
  for (const t of tokens) {
    if (prev) {
      // A sign after an operator or a parenthesis belongs to its number: score > -1.
      const afterOperator = !before || (before.kind === 'op' && !isOp(before, ')') && !isOp(before, ']'));
      const sign = (isOp(prev, '-') || isOp(prev, '+')) && t.kind === 'number' && afterOperator;
      const tight =
        sign ||
        isOp(prev, '(') ||
        isOp(prev, '.') ||
        isOp(prev, '::') ||
        isOp(prev, '[') ||
        isOp(t, ')') ||
        isOp(t, ',') ||
        isOp(t, '.') ||
        isOp(t, '::') ||
        isOp(t, '[') ||
        isOp(t, ']') ||
        (isOp(t, '(') && isName(prev) && !(prev.kind === 'word' && SPACE_BEFORE_PAREN.has(prev.value)));
      if (!tight) out += ' ';
    }
    out += t.text;
    before = prev;
    prev = t;
  }
  return out;
}

/** A compact form for matching: names lowercased and unquoted where that's the same name. */
function canon(tokens: Token[]): string {
  let out = '';
  let prev: Token | undefined;
  for (const t of tokens) {
    const wordy = t.kind === 'word' || t.kind === 'ident' || t.kind === 'number';
    const prevWordy = prev && (prev.kind === 'word' || prev.kind === 'ident' || prev.kind === 'number');
    // Words after a closing parenthesis keep a space too: "auth.uid() is not null".
    if (wordy && (prevWordy || isOp(prev, ')'))) out += ' ';
    else if (isOp(t, '(') && prev?.kind === 'word' && SPACE_BEFORE_PAREN.has(prev.value)) out += ' ';
    if (t.kind === 'ident') out += /^[a-z_][a-z0-9_$]*$/.test(t.value) ? t.value : `"${t.value}"`;
    else if (t.kind === 'string') out += `'${t.value.replace(/'/g, "''")}'`;
    else out += t.kind === 'word' ? t.value : t.text;
    prev = t;
  }
  return out;
}

// (select auth.jwt() ->> 'role') and (select auth.jwt()) ->> 'role' both read as auth.jwt()->>'role'.
const SELECT_WRAP = /\(select (auth\.(?:uid|jwt|role|email)\(\)(?:->>?'[a-z_]+')*)(?: as \w+)?\)/g;
const PAREN_WRAP = /\((auth\.(?:uid|jwt|role|email)\(\)(?:->>?'[a-z_]+')*)\)/g;
// Postgres writes literals back with their type, such as 'authenticated'::text, in pg_policies.
const LITERAL_CAST = /('(?:[^']|'')*')::(?:text|name|varchar|character varying|"text")\b/g;

/** canon() with (select auth.x() as alias) written as auth.x(), literal casts dropped and outer parentheses gone. */
function core(tokens: Token[]): string {
  let text = canon(unwrap(tokens)).replace(LITERAL_CAST, '$1');
  // Each pass unwraps one level; real policies need one or two.
  for (let pass = 0; pass < 4; pass += 1) {
    const next = text.replace(SELECT_WRAP, '$1').replace(PAREN_WRAP, '$1');
    if (next === text) break;
    text = next;
  }
  return text;
}

const ALWAYS_TRUE = new Set(['true', '1=1', "'t'", "'true'::boolean", 'true::boolean']);
const SIGNED_IN_ONLY = new Set([
  'auth.uid() is not null',
  'auth.jwt() is not null',
  "auth.role()='authenticated'",
  "'authenticated'=auth.role()",
  "auth.jwt()->>'role'='authenticated'",
  "'authenticated'=auth.jwt()->>'role'",
  "auth.jwt()->>'sub' is not null",
  'not auth.uid() is null',
]);

type Truth = 'true' | 'signed' | 'other';

/**
 * Whether a condition lets every row through ("true"), every signed-in user
 * ("signed"), or depends on the row. Top-level OR passes if any branch does;
 * AND only if every branch does. Nesting deeper than real policies go is "other".
 */
function truthOf(tokens: Token[], depth = 0): Truth {
  if (depth > 32) return 'other';
  const t = unwrap(tokens);
  const ors = splitTop(t, 'or');
  if (ors.length > 1) {
    const kinds = ors.map((part) => truthOf(part, depth + 1));
    return kinds.includes('true') ? 'true' : kinds.includes('signed') ? 'signed' : 'other';
  }
  const ands = splitTop(t, 'and');
  if (ands.length > 1) {
    const kinds = ands.map((part) => truthOf(part, depth + 1));
    return kinds.every((k) => k === 'true') ? 'true' : kinds.every((k) => k !== 'other') ? 'signed' : 'other';
  }
  const text = core(t);
  return ALWAYS_TRUE.has(text) ? 'true' : SIGNED_IN_ONLY.has(text) ? 'signed' : 'other';
}

/**
 * A missing clause isn't true: Postgres skips a permissive policy without the
 * clause a command needs, so it lets nothing through.
 */
const alwaysTrue = (expr: Expr | undefined) => !!expr && truthOf(expr.tokens) === 'true';
const signedInOnly = (expr: Expr | undefined) => !!expr && truthOf(expr.tokens) === 'signed';

interface Call {
  /** auth.uid, auth.jwt, auth.role, auth.email or current_setting. */
  name: string;
  start: number;
  /** Index of the closing parenthesis. */
  end: number;
  wrapped: boolean;
}

/** Calls to auth.<fn>() and current_setting(), and whether each sits inside (select ...). */
function authCalls(tokens: Token[]): Call[] {
  const out: Call[] = [];
  const match = pairs(tokens);
  // Open parentheses, and how many of them start a select, so "wrapped" is O(1).
  const selects: boolean[] = [];
  let openSelects = 0;
  const close = (open: number) => (match[open] === -1 ? tokens.length - 1 : match[open]);
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (isOp(t, '(')) {
      const isSelect = isWord(tokens[i + 1], 'select');
      selects.push(isSelect);
      if (isSelect) openSelects += 1;
    } else if (isOp(t, ')') && selects.length > 0) {
      if (selects.pop()) openSelects -= 1;
    }
    let name: string | undefined;
    let open = -1;
    if (isName(t) && t.value === 'auth' && isOp(tokens[i + 1], '.') && isName(tokens[i + 2]) && isOp(tokens[i + 3], '(')) {
      const fn = tokens[i + 2].value;
      if (['uid', 'jwt', 'role', 'email'].includes(fn)) {
        name = `auth.${fn}`;
        open = i + 3;
      }
    } else if (isName(t) && t.value === 'current_setting' && isOp(tokens[i + 1], '(') && !isOp(tokens[i - 1], '.')) {
      name = 'current_setting';
      open = i + 1;
    } else if (
      isName(t) && t.value === 'pg_catalog' && isOp(tokens[i + 1], '.') && tokens[i + 2]?.value === 'current_setting' && isOp(tokens[i + 3], '(')
    ) {
      name = 'current_setting';
      open = i + 3;
    }
    if (!name) continue;
    const end = close(open);
    out.push({ name, start: i, end, wrapped: openSelects > 0 });
    // Skip the call's arguments; the parentheses inside it are balanced or run to the end.
    i = end;
  }
  return out;
}

/** A token the fixes add, such as the ( and select around a call. */
const added = (kind: TokenKind, text: string, line: number): Token => ({ kind, text, value: text, line });

/**
 * The expression with each unwrapped auth call written as (select ...). Only
 * the call itself is wrapped, so it still runs once per query, and what's
 * around it stays as written: a function's own parentheses, the ->> after
 * auth.jwt(), and the ::text on a key.
 */
function wrapCalls(tokens: Token[], calls: Call[]): string {
  const out: Token[] = [];
  let at = 0;
  // One token at a time: spreading a long expression into push() overflows the stack.
  const copy = (from: number, to: number) => {
    for (let i = from; i < to; i += 1) out.push(tokens[i]);
  };
  for (const call of calls.filter((c) => !c.wrapped)) {
    const line = tokens[call.start].line;
    copy(at, call.start);
    out.push(added('op', '(', line), added('word', 'select', line));
    copy(call.start, call.end + 1);
    out.push(added('op', ')', line));
    at = call.end + 1;
  }
  copy(at, tokens.length);
  return render(out);
}

const USER_METADATA = /(^|_)user_meta_?data$|raw_user_meta_data/;

const mentionsUserMetadata = (expr: Expr | undefined) => !!expr && expr.tokens.some((t) => USER_METADATA.test(t.value));

// Around these, a claim that isn't there can still let someone through: not coalesce(x, false),
// x is null, x is distinct from 'guest' and coalesce(x, 'member') <> 'guest' all pass when x is missing.
const FAILS_OPEN = new Set(['coalesce', 'nullif', 'greatest', 'least', 'concat', 'concat_ws', 'case', 'is', 'not', 'distinct']);

/**
 * Whether each part of a condition that reads user_metadata lets nobody in
 * when the claim isn't there. A missing claim is null, and a test on null
 * fails, unless something around it, such as not, coalesce or is null, turns
 * that into a pass. AND and OR keep it: the other parts don't read the claim.
 */
function failsClosed(tokens: Token[], depth = 0): boolean {
  if (depth > 32) return false;
  const t = unwrap(tokens);
  for (const word of ['or', 'and']) {
    const parts = splitTop(t, word);
    if (parts.length > 1) return parts.every((part) => failsClosed(part, depth + 1));
  }
  if (!t.some((x) => USER_METADATA.test(x.value))) return true;
  return !t.some((x) => (x.kind === 'word' && FAILS_OPEN.has(x.value)) || isOp(x, '<>') || isOp(x, '!='));
}

/**
 * The condition reading app_metadata, which only server code can set, where
 * it reads user_metadata: the JWT's 'user_metadata' key, or auth.users's
 * raw_user_meta_data column. Undefined when it reads it some other way, such
 * as a column of the app's own, or when the swap could let more people in:
 * a claim nobody has set yet must keep them out.
 */
function appMetadata(tokens: Token[]): Token[] | undefined {
  if (!failsClosed(tokens)) return undefined;
  const out: Token[] = [];
  for (const t of tokens) {
    if (!USER_METADATA.test(t.value)) out.push(t);
    else if (t.kind === 'string' && t.value === 'user_metadata') out.push({ ...t, text: "'app_metadata'", value: 'app_metadata' });
    else if (isName(t) && t.value === 'raw_user_meta_data') out.push({ ...t, kind: 'word', text: 'raw_app_meta_data', value: 'raw_app_meta_data' });
    else return undefined;
  }
  return out;
}

/** The keys a condition reads from user_metadata, such as role in -> 'user_metadata' ->> 'role'. */
function metadataKeys(tokens: Token[]): string[] {
  const out = new Set<string>();
  tokens.forEach((t, i) => {
    if (!USER_METADATA.test(t.value)) return;
    let k = skipCasts(tokens, i + 1);
    while (isOp(tokens[k], ')')) k = skipCasts(tokens, k + 1);
    if ((isOp(tokens[k], '->>') || isOp(tokens[k], '->')) && tokens[k + 1]?.kind === 'string') out.add(tokens[k + 1].value);
  });
  return [...out];
}

/** What to do before a fix that reads app_metadata in place of user_metadata, naming the keys it reads. */
function appMetadataNote(tokens: Token[]): string {
  const keys = metadataKeys(tokens).map((k) => `"${k}"`);
  const what = keys.length === 0 ? 'the claim' : keys.length === 1 ? keys[0] : `${keys.slice(0, -1).join(', ')} and ${keys.at(-1)}`;
  return `Before you run this, set ${what} in each user’s app_metadata from server code\n(users can’t change app_metadata). Until then, they lose access.`;
}

/** A condition as a fix writes it: user_metadata read from app_metadata, and each auth call wrapped in (select ...). */
function fixText(tokens: Token[]): string {
  const safe = appMetadata(unwrap(tokens)) ?? unwrap(tokens);
  const calls = authCalls(safe);
  return calls.some((c) => !c.wrapped) ? wrapCalls(safe, calls) : render(safe);
}

const mentions = (expr: Expr | undefined, test: (t: Token, i: number, all: Token[]) => boolean) =>
  !!expr && expr.tokens.some((t, i, all) => test(t, i, all));

const callsAuthRole = (expr: Expr | undefined) =>
  mentions(expr, (t, i, all) => t.value === 'auth' && all[i + 2]?.value === 'role' && isOp(all[i + 3], '('));

const readsClaimsSetting = (expr: Expr | undefined) =>
  mentions(expr, (t) => t.kind === 'string' && /^request\.jwt\.claim/.test(t.value));

/** End (exclusive) of auth.<fn>() starting at i, or -1. */
function bareCall(tokens: Token[], i: number, fn: 'uid' | 'jwt' | 'email'): number {
  const named = isName(tokens[i]) && tokens[i].value === 'auth' && isOp(tokens[i + 1], '.') && tokens[i + 2]?.value === fn;
  return named && isOp(tokens[i + 3], '(') && isOp(tokens[i + 4], ')') ? i + 5 : -1;
}

/** What a policy compares a row with: the caller's user id, or their email. */
type Who = 'id' | 'email';

/**
 * End (exclusive) of the caller's user id starting at i, or -1: auth.uid() or
 * auth.jwt() ->> 'sub', bare, in parentheses, or wrapped in (select ...),
 * either the whole lookup or only the call, as in (select auth.jwt()) ->> 'sub'.
 * Also the way Postgres writes them back: ((select auth.jwt() as jwt) ->> 'sub'::text).
 * For their email: auth.email() or auth.jwt() ->> 'email', in the same forms.
 */
function uidSpan(tokens: Token[], i: number, match: Int32Array, depth = 0, who: Who = 'id'): number {
  const uid = bareCall(tokens, i, who === 'id' ? 'uid' : 'email');
  if (uid !== -1) return uid;
  let jwt = bareCall(tokens, i, 'jwt');
  if (jwt === -1 && isOp(tokens[i], '(') && match[i] !== -1 && depth < 3) {
    const close = match[i];
    const from = isWord(tokens[i + 1], 'select') ? i + 2 : i + 1;
    // (select auth.uid() as uid)
    const alias = (end: number) => (isWord(tokens[end], 'as') && isName(tokens[end + 1]) ? end + 2 : end);
    const inner = uidSpan(tokens, from, match, depth + 1, who);
    if (inner !== -1 && alias(inner) === close) return close + 1;
    const call = bareCall(tokens, from, 'jwt');
    if (call !== -1 && alias(call) === close) jwt = close + 1;
  }
  if (jwt === -1) return -1;
  const sub = isOp(tokens[jwt], '->>') && tokens[jwt + 1]?.kind === 'string' && tokens[jwt + 1].value === (who === 'id' ? 'sub' : 'email');
  return sub ? skipCasts(tokens, jwt + 2) : -1;
}

/** Past any casts such as ::text or ::uuid[] starting at i. */
function skipCasts(tokens: Token[], i: number): number {
  while (isOp(tokens[i], '::') && isName(tokens[i + 1])) {
    i += 2;
    if (isOp(tokens[i], '[') && isOp(tokens[i + 1], ']')) i += 2;
  }
  return i;
}

const NOT_COLUMNS = new Set(['null', 'true', 'false', 'select', 'and', 'or', 'not']);

/**
 * Columns compared with the caller's user id, such as user_id in auth.uid() =
 * user_id, or with their email. Linear in the tokens.
 */
function ownerColumns(expr: Expr | undefined, who: Who = 'id'): string[] {
  if (!expr) return [];
  const tokens = expr.tokens;
  const match = pairs(tokens);
  const out = new Set<string>();
  for (let i = 0; i < tokens.length; i += 1) {
    const end = uidSpan(tokens, i, match, 0, who);
    if (end === -1) continue;
    // auth.uid() = owner, but not auth.uid()::text = data ->> 'owner', which compares a value inside data.
    const eq = skipCasts(tokens, end);
    if (isOp(tokens[eq], '=')) {
      let k = eq + 1;
      if (isName(tokens[k])) {
        while (isOp(tokens[k + 1], '.') && isName(tokens[k + 2])) k += 2;
        const after = tokens[skipCasts(tokens, k + 1)];
        const alone = !after || after.kind !== 'op' || [')', ',', ';'].includes(after.value);
        if (alone && !NOT_COLUMNS.has(tokens[k].value)) out.add(tokens[k].value);
      }
    }
    // owner = auth.uid(), allowing owner::text, but not data -> owner = auth.uid()
    if (isOp(tokens[i - 1], '=')) {
      let k = i - 2;
      while (k >= 2 && isName(tokens[k]) && isOp(tokens[k - 1], '::')) k -= 2;
      if (isOp(tokens[k], ']') && isOp(tokens[k - 1], '[') && isOp(tokens[k - 2], '::')) k -= 4;
      let first = k;
      while (isOp(tokens[first - 1], '.') && isName(tokens[first - 2])) first -= 2;
      const before = tokens[first - 1];
      const alone = !before || before.kind !== 'op' || ['(', ','].includes(before.value);
      if (alone && isName(tokens[k]) && !isOp(tokens[k + 1], '(') && !NOT_COLUMNS.has(tokens[k].value)) out.add(tokens[k].value);
    }
    i = end - 1;
  }
  return [...out];
}

/** A name as a token, quoted when it has to be. */
function nameAsToken(value: string, line: number): Token {
  const text = identifier(value);
  return { kind: text.startsWith('"') ? 'ident' : 'word', text, value, line };
}

/**
 * Where a policy's condition names a column of its own table: bare and
 * outside subqueries, or after the table's name. A bare name inside a
 * subquery may be the other table's column, so it doesn't count.
 */
function columnRefs(tokens: Token[], table: string, column: string): Set<number> {
  const out = new Set<number>();
  const selects: boolean[] = [];
  let inSelect = 0;
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (isOp(t, '(')) {
      const select = isWord(tokens[i + 1], 'select');
      selects.push(select);
      if (select) inSelect += 1;
    } else if (isOp(t, ')')) {
      if (selects.pop()) inSelect -= 1;
    } else if (isName(t) && t.value === column && !isOp(tokens[i + 1], '(') && !isOp(tokens[i + 1], '.') && !isOp(tokens[i - 1], '::')) {
      const qualified = isOp(tokens[i - 1], '.');
      if (qualified ? isName(tokens[i - 2]) && tokens[i - 2].value === table : inSelect === 0) out.add(i);
    }
  }
  return out;
}

/**
 * The functions tokens call by name, as [schema, name], with no schema when a
 * call names none. Strings inside are read too, a few levels deep, since a
 * body may run SQL it holds in one.
 */
function callsIn(tokens: Token[], depth = 0): NamedCall[] {
  const out: NamedCall[] = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t.kind === 'string' && depth < 3 && t.value.includes('(')) out.push(...callsIn(tokenize(t.value), depth + 1));
    if (!isName(t) || !isOp(tokens[i + 1], '(')) continue;
    const qualified = isOp(tokens[i - 1], '.') && isName(tokens[i - 2]);
    // references public.profiles (id) names a table.
    if (isWord(tokens[qualified ? i - 3 : i - 1], 'references')) continue;
    out.push([qualified ? tokens[i - 2].value : undefined, t.value]);
  }
  return out;
}

/** Whether a call names the function: by its schema, or by its name alone. */
const namesFunction = (call: NamedCall, fn: { schema: string; name: string }) => call[1] === fn.name && (call[0] === undefined || call[0] === fn.schema);

// ---------------------------------------------------------------------------
// Catalog

export type Command = 'select' | 'insert' | 'update' | 'delete';
const COMMANDS: Command[] = ['select', 'insert', 'update', 'delete'];
type PolicyCommand = Command | 'all';
type Kind = 'table' | 'view' | 'matview' | 'foreign';

export interface Relation {
  schema: string;
  name: string;
  kind: Kind;
  line?: number;
  rls: boolean;
  /** True once some statement in the input decides RLS. */
  rlsKnown: boolean;
  /** False when the input only alters a table created somewhere else, such as an earlier migration. */
  created: boolean;
  columns: string[];
  /**
   * Column types the way Postgres names them, such as uuid, text or character
   * varying, without lengths. A column missing here has a type the input
   * doesn't say, such as catalog JSON from before the query read types.
   */
  types: Map<string, string>;
  /** Columns that can't be null, primary key columns included. */
  notNull: Set<string>;
  /** Columns with a foreign key to auth.users (id). */
  userRefs: Set<string>;
  /** Single-column foreign keys: column → [schema, table, column] it points at. */
  refs: Map<string, [string, string, string]>;
  /** For SQL input: functions its column defaults and checks call. */
  calls?: NamedCall[];
  /** First column of each index, primary key and unique constraint. */
  indexed: Set<string>;
  securityInvoker: boolean;
  /** For views: the query, to look for auth.users. */
  query?: Token[];
  /** Privileges anon and authenticated hold; undefined when the input never says (Supabase's defaults apply). */
  grants?: { anon: Set<Command>; authenticated: Set<Command> };
  realtime: boolean;
}

export interface Policy {
  schema: string;
  table: string;
  name: string;
  permissive: boolean;
  command: PolicyCommand;
  /** Role names as Postgres holds them (unquoted ones folded to lower case); ['public'] when the policy names none. */
  roles: string[];
  using?: Expr;
  check?: Expr;
  line?: number;
}

export interface Func {
  schema: string;
  name: string;
  args: string;
  returnsTrigger: boolean;
  securityDefiner: boolean;
  searchPathSet: boolean;
  /** Whether anon and authenticated can execute it. */
  anon: boolean;
  authenticated: boolean;
  line?: number;
  /** Execute grants as the input left them, for SQL input: PUBLIC, and direct grants. */
  acl?: { public: boolean; anon: boolean; authenticated: boolean };
  /**
   * Other functions whose bodies call it by name, as schema.name(args). A body
   * looks the name up each time it runs. Undefined when the input doesn't say.
   */
  calledBy?: string[];
  /** Tables whose column defaults or checks call it, as schema.table. */
  usedBy?: string[];
  /** For SQL input: what its body calls, as [schema, name], with no schema when the call names none. */
  calls?: NamedCall[];
}

/** A function a body, a default or a view calls: [schema, name], with no schema when the call names none. */
type NamedCall = [string | undefined, string];

export interface Bucket {
  id: string;
  public: boolean;
}

export interface Catalog {
  source: 'sql' | 'json';
  exposed: string[];
  relations: Map<string, Relation>;
  policies: Policy[];
  functions: Func[];
  buckets: Map<string, Bucket>;
  statements: number;
  /** Lines of DO blocks that run SQL built at run time, which this reader can't follow. */
  opaque: number[];
}

const SYSTEM_SCHEMAS = new Set([
  '_timescaledb_cache', '_timescaledb_catalog', '_timescaledb_config', '_timescaledb_internal', 'auth', 'cron',
  'extensions', 'graphql', 'graphql_public', 'information_schema', 'net', 'pgmq', 'pgroonga', 'pgsodium',
  'pgsodium_masks', 'pgtle', 'pgbouncer', 'pg_catalog', 'realtime', 'repack', 'storage', 'supabase_functions',
  'supabase_migrations', 'tiger', 'topology', 'vault', 'pg_toast', '_realtime', '_analytics', 'supabase_realtime',
]);

const key = (schema: string, name: string) => `${schema}.${name}`;

export const qualifiedName = (schema: string, name: string) => `${identifier(schema)}.${identifier(name)}`;

function emptyCatalog(source: Catalog['source']): Catalog {
  return { source, exposed: ['public'], relations: new Map(), policies: [], functions: [], buckets: new Map(), statements: 0, opaque: [] };
}

// ---------------------------------------------------------------------------
// Reading SQL

class Cursor {
  tokens: Token[];
  i: number;
  match: Int32Array | undefined;
  constructor(tokens: Token[]) {
    this.tokens = tokens;
    this.i = 0;
    this.match = undefined;
  }
  peek(offset = 0) {
    return this.tokens[this.i + offset];
  }
  done() {
    return this.i >= this.tokens.length;
  }
  /** Consumes the words in order if they're all next. */
  accept(...words: string[]) {
    for (let k = 0; k < words.length; k += 1) if (!isWord(this.tokens[this.i + k], words[k])) return false;
    this.i += words.length;
    return true;
  }
  acceptOp(value: string) {
    if (isOp(this.peek(), value)) {
      this.i += 1;
      return true;
    }
    return false;
  }
  /** A name, possibly schema-qualified: [schema, name]. */
  name(defaultSchema = 'public'): [string, string] | undefined {
    const first = this.peek();
    if (!isName(first)) return undefined;
    this.i += 1;
    if (isOp(this.peek(), '.') && isName(this.peek(1))) {
      const second = this.peek(1)!;
      this.i += 2;
      return [first.value, second.value];
    }
    return [defaultSchema, first.value];
  }
  /** The tokens inside the parentheses that start here, consuming them. */
  group(): Token[] | undefined {
    if (!isOp(this.peek(), '(')) return undefined;
    this.match ??= pairs(this.tokens);
    // An unclosed parenthesis runs to the end of the statement.
    const end = this.match[this.i] === -1 ? this.tokens.length : this.match[this.i];
    const inner = this.tokens.slice(this.i + 1, end);
    this.i = end + 1;
    return inner;
  }
  rest() {
    return this.tokens.slice(this.i);
  }
}

/** Splits tokens at top-level commas. */
function commaSplit(tokens: Token[]): Token[][] {
  const out: Token[][] = [];
  let depth = 0;
  let current: Token[] = [];
  for (const t of tokens) {
    if (isOp(t, '(') || isOp(t, '[')) depth += 1;
    if (isOp(t, ')') || isOp(t, ']')) depth -= 1;
    if (isOp(t, ',') && depth === 0) {
      out.push(current);
      current = [];
      continue;
    }
    current.push(t);
  }
  if (current.length > 0) out.push(current);
  return out;
}

const CONSTRAINT_WORDS = new Set(['constraint', 'primary', 'unique', 'check', 'foreign', 'exclude', 'like']);
const TABLE_CONSTRAINT_WORDS = ['primary', 'unique', 'check', 'foreign', 'exclude'];
/** Words that end a column's type and start its constraints. */
const COLUMN_CONSTRAINT_WORDS = new Set([
  'constraint', 'not', 'null', 'default', 'primary', 'unique', 'references', 'check', 'generated', 'collate', 'compression',
]);
const TRUE_WORDS = new Set(['true', 'on', 'yes', '1']);

/** Whether each token sits outside every parenthesis. */
function outside(tokens: Token[]): boolean[] {
  let depth = 0;
  return tokens.map((t) => {
    if (isOp(t, '(')) depth += 1;
    else if (isOp(t, ')')) depth -= 1;
    else return depth === 0;
    return false;
  });
}

/** After REFERENCES: the table and column it points at, taking id for a table named alone (its primary key, as a rule). */
function referenceTarget(tokens: Token[]): [string, string, string] | undefined {
  const c = new Cursor(tokens);
  const target = c.name();
  if (!target) return undefined;
  if (!isOp(c.peek(), '(')) return [target[0], target[1], 'id'];
  const columns = (c.group() ?? []).filter(isName);
  return columns.length === 1 ? [target[0], target[1], columns[0].value] : undefined;
}

/** After REFERENCES: whether it names auth.users, by its id or its primary key (which is id). */
function referencesAuthUsers(tokens: Token[]): boolean {
  const target = referenceTarget(tokens);
  return !!target && target[0] === 'auth' && target[1] === 'users' && target[2] === 'id';
}

// Serial types are integers with a default, and format_type() names them that way.
const COLUMN_TYPE_ALIASES: Record<string, string> = {
  serial: 'integer',
  serial4: 'integer',
  bigserial: 'bigint',
  serial8: 'bigint',
  smallserial: 'smallint',
  serial2: 'smallint',
};

/**
 * A column's type in one form for SQL and catalog JSON: "varchar(20)",
 * "character varying(20)" and "pg_catalog"."varchar" are all character varying.
 */
function columnType(tokens: Token[]): string | undefined {
  const match = pairs(tokens);
  const kept: Token[] = [];
  for (let i = 0; i < tokens.length; i += 1) {
    if (isOp(tokens[i], '(') && match[i] !== -1) i = match[i];
    else kept.push(tokens[i]);
  }
  let type = canon(kept).replace(/"/g, '').replace(/^(pg_catalog|public)\./, '');
  const array = /(\[\])+$/.exec(type)?.[0] ?? '';
  if (array) type = type.slice(0, -array.length);
  if (type === '') return undefined;
  return (COLUMN_TYPE_ALIASES[type] ?? TYPE_ALIASES[type] ?? type) + array;
}

function privilegesFrom(tokens: Token[]): { commands: Set<Command>; all: boolean; execute: boolean; usage: boolean } {
  const commands = new Set<Command>();
  let all = false;
  let execute = false;
  let usage = false;
  for (const part of commaSplit(tokens)) {
    const word = part[0]?.value;
    if (word === 'all') {
      all = true;
      COMMANDS.forEach((c) => commands.add(c));
    } else if (word && (COMMANDS as string[]).includes(word)) {
      // select (a, b) is a column grant: it still lets the role read those columns.
      commands.add(word as Command);
    } else if (word === 'execute') execute = true;
    else if (word === 'usage') usage = true;
  }
  return { commands, all, execute, usage };
}

type ExecuteAcl = { public: boolean; anon: boolean; authenticated: boolean };

interface Defaults {
  tables: { anon: Set<Command>; authenticated: Set<Command> } | undefined;
  /**
   * Execute on new functions. Postgres gives PUBLIC execute everywhere, and only
   * a default privilege without IN SCHEMA can take that away; one IN SCHEMA can
   * only add to it. Supabase grants anon and authenticated in schema public.
   */
  functionsGlobal: ExecuteAcl;
  functionsBySchema: Map<string, ExecuteAcl>;
}

/** Statements that can start inside a DO block's body. */
const EMBEDDED = new Set(['create', 'alter', 'drop', 'grant', 'revoke']);

function readSql(sql: string): Catalog {
  const catalog = emptyCatalog('sql');
  const statements = splitStatements(tokenize(sql));
  catalog.statements = statements.length;
  const exposed = new Set(['public']);
  const defaults: Defaults = {
    tables: undefined,
    functionsGlobal: { public: true, anon: false, authenticated: false },
    functionsBySchema: new Map([['public', { public: false, anon: true, authenticated: true }]]),
  };
  // Keyed stores, so long dumps stay fast; turned into lists at the end.
  const policies = new Map<string, Policy>();
  const functions = new Map<string, Func>();
  const policyKey = (schema: string, table: string, name: string) => `${schema}.${table}\u0000${name}`;
  const functionKey = (f: { schema: string; name: string; args: string }) => `${f.schema}.${f.name}(${f.args})`;

  const relation = (schema: string, name: string) => catalog.relations.get(key(schema, name));
  const ensureGrants = (rel: Relation) => {
    // The first grant or revoke in the input starts from Supabase's defaults, which give anon and authenticated everything.
    rel.grants ??= { anon: new Set(COMMANDS), authenticated: new Set(COMMANDS) };
    return rel.grants;
  };

  for (const statement of statements) handle(statement.tokens, statement.line, 0);
  catalog.exposed = [...exposed];
  catalog.policies = [...policies.values()];
  catalog.functions = [...functions.values()];
  // Who else calls each function, from the bodies, defaults and checks read above.
  for (const fn of catalog.functions) {
    fn.calledBy = catalog.functions
      .filter((g) => g !== fn && g.calls?.some((call) => namesFunction(call, fn)))
      .map((g) => `${qualifiedName(g.schema, g.name)}(${g.args})`);
    fn.usedBy = [...catalog.relations.values()]
      .filter((r) => r.calls?.some((call) => namesFunction(call, fn)))
      .map((r) => qualifiedName(r.schema, r.name));
  }
  return catalog;

  function handle(tokens: Token[], line: number, depth: number) {
    const c = new Cursor(tokens);
    try {
      if (c.accept('do')) readDo(tokens, line, depth);
      else if (c.accept('create')) {
        c.accept('or', 'replace');
        while (c.accept('temp') || c.accept('temporary') || c.accept('unlogged') || c.accept('global') || c.accept('local'));
        if (c.accept('table')) readCreateTable(c, line, 'table');
        else if (c.accept('foreign', 'table')) readCreateTable(c, line, 'foreign');
        else if (c.accept('materialized', 'view')) readCreateView(c, line, 'matview');
        else if (c.accept('recursive', 'view') || c.accept('view')) readCreateView(c, line, 'view');
        else if (c.accept('policy')) readCreatePolicy(c, line);
        else if (c.accept('unique', 'index') || c.accept('index')) readCreateIndex(c);
        else if (c.accept('function')) readCreateFunction(c, line);
      } else if (c.accept('alter', 'table')) readAlterTable(c, line);
      else if (c.accept('alter', 'view') || c.accept('alter', 'materialized', 'view')) readAlterView(c);
      else if (c.accept('alter', 'policy')) readAlterPolicy(c);
      else if (c.accept('alter', 'function')) readAlterFunction(c);
      else if (c.accept('alter', 'publication')) readAlterPublication(c);
      else if (c.accept('alter', 'default', 'privileges')) readDefaultPrivileges(c);
      else if (c.accept('drop')) readDrop(c);
      else if (c.accept('grant')) readGrant(c, true);
      else if (c.accept('revoke')) readGrant(c, false);
      else if (c.accept('insert', 'into')) readInsert(c);
    } catch {
      // A statement this reader doesn't follow is skipped; the rest still count.
    }
  }

  /**
   * A DO block's body: statements such as create policy inside if-not-exists
   * guards, and execute 'literal SQL', are read like the rest. SQL built at run
   * time can't be, except the common loop that drops every policy on a table.
   */
  function readDo(tokens: Token[], line: number, depth: number) {
    const body = tokens.find((t) => t.kind === 'string');
    if (!body || depth > 3) return;
    readBody(body.value, body.line, depth + 1);
  }

  function readBody(text: string, firstLine: number, depth: number) {
    const inner = tokenize(text);
    for (const t of inner) t.line += firstLine - 1;
    for (const statement of splitStatements(inner)) {
      const tokens = statement.tokens;
      for (let k = 0; k < tokens.length; k += 1) {
        const t = tokens[k];
        const starts =
          t.kind === 'word' && EMBEDDED.has(t.value) && (k === 0 || isWord(tokens[k - 1], 'begin', 'then', 'else', 'loop'));
        if (starts) {
          handle(tokens.slice(k), t.line, depth);
          break;
        }
        if (isWord(t, 'execute')) {
          const next = tokens[k + 1];
          if (next?.kind === 'string') {
            readBody(next.value, next.line, depth + 1);
          } else if (isWord(next, 'format') && isOp(tokens[k + 2], '(') && tokens[k + 3]?.kind === 'string') {
            const dropAll = /^\s*drop\s+policy\s+(?:if\s+exists\s+)?%(?:\d+\$)?I\s+on\s+(.+?)\s*$/i.exec(tokens[k + 3].value);
            const target = dropAll ? dropTarget(dropAll[1].replace(/%%/g, '%')) : undefined;
            if (target) {
              const [schema, table] = target;
              for (const [id, p] of policies) {
                if ((schema === undefined || p.schema === schema) && (table === undefined || p.table === table)) policies.delete(id);
              }
              // A loop over tables, such as one that resets every policy: which ones depends on the data.
              if (table === undefined) catalog.opaque.push(t.line);
            } else catalog.opaque.push(t.line);
          } else catalog.opaque.push(t.line);
          break;
        }
      }
    }
  }

  function addRelation(schema: string, name: string, kind: Kind, line: number, created = true): Relation {
    const rel: Relation = {
      schema,
      name,
      kind,
      line,
      rls: false,
      rlsKnown: false,
      created,
      columns: [],
      types: new Map(),
      notNull: new Set(),
      userRefs: new Set(),
      refs: new Map(),
      indexed: new Set(),
      securityInvoker: false,
      realtime: false,
      grants: defaults.tables
        ? { anon: new Set(defaults.tables.anon), authenticated: new Set(defaults.tables.authenticated) }
        : undefined,
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

  function readCreateTable(c: Cursor, line: number, kind: Kind) {
    const ifNotExists = c.accept('if', 'not', 'exists');
    const name = c.name();
    if (!name) return;
    // Postgres skips it when the name is taken: a later migration's columns and types don't count.
    if (ifNotExists && relation(name[0], name[1])) return;
    const rel = addRelation(name[0], name[1], kind, line);
    if (c.accept('partition', 'of')) return;
    const body = c.group();
    if (!body) return;
    for (const element of commaSplit(body)) {
      const first = element[0];
      if (!first) continue;
      if (first.kind === 'word' && CONSTRAINT_WORDS.has(first.value)) {
        readConstraint(rel, element);
        continue;
      }
      if (!isName(first)) continue;
      readColumn(rel, element);
    }
  }

  /** A column definition: name, type, then constraints such as not null or references auth.users. */
  function readColumn(rel: Relation, element: Token[]) {
    const name = element[0].value;
    if (!rel.columns.includes(name)) rel.columns.push(name);
    let end = 1;
    while (end < element.length && !(element[end].kind === 'word' && COLUMN_CONSTRAINT_WORDS.has(element[end].value))) end += 1;
    const type = columnType(element.slice(1, end));
    if (type) rel.types.set(name, type);
    // Constraints outside parentheses: check (x is not null) doesn't make the column not null.
    const tail = element.slice(end);
    const top = outside(tail);
    const words = tail.filter((_, i) => top[i]);
    if (hasWords(words, 'primary') || hasWords(words, 'unique')) rel.indexed.add(name);
    // Serial and identity columns are not null too.
    const serial = /^(small|big)?serial[248]?$/.test(element[1]?.value ?? '');
    if (serial || hasWords(words, 'not', 'null') || hasWords(words, 'primary', 'key') || hasWords(words, 'as', 'identity')) {
      rel.notNull.add(name);
    }
    const calls = callsIn(tail);
    if (calls.length > 0) (rel.calls ??= []).push(...calls);
    const refs = tail.findIndex((t, i) => top[i] && isWord(t, 'references'));
    const target = refs === -1 ? undefined : referenceTarget(tail.slice(refs + 1));
    if (target) rel.refs.set(name, target);
    if (refs !== -1 && referencesAuthUsers(tail.slice(refs + 1))) rel.userRefs.add(name);
  }

  /** A table constraint: primary key, unique or a foreign key to auth.users. */
  function readConstraint(rel: Relation, element: Token[]) {
    const c = new Cursor(element);
    if (c.accept('constraint')) c.i += 1;
    if (isWord(c.peek(), 'check')) {
      const calls = callsIn(c.rest());
      if (calls.length > 0) (rel.calls ??= []).push(...calls);
      return;
    }
    if (c.accept('primary', 'key') || c.accept('unique')) {
      const primary = isWord(element[c.i - 1], 'key');
      c.accept('nulls', 'not', 'distinct');
      const columns = (c.group() ?? []).filter((t, i, all) => isName(t) && (i === 0 || isOp(all[i - 1], ',')));
      if (columns[0]) rel.indexed.add(columns[0].value);
      if (primary) for (const t of columns) rel.notNull.add(t.value);
    } else if (c.accept('foreign', 'key')) {
      const columns = (c.group() ?? []).filter(isName);
      if (columns.length !== 1 || !c.accept('references')) return;
      const target = referenceTarget(c.rest());
      if (target) rel.refs.set(columns[0].value, target);
      if (referencesAuthUsers(c.rest())) rel.userRefs.add(columns[0].value);
    }
  }

  function readCreateView(c: Cursor, line: number, kind: Kind) {
    c.accept('if', 'not', 'exists');
    const name = c.name();
    if (!name) return;
    const rel = addRelation(name[0], name[1], kind, line);
    rel.kind = kind;
    // create or replace view sets the options afresh: without WITH, security_invoker is off again.
    rel.securityInvoker = false;
    if (isOp(c.peek(), '(')) c.group();
    if (c.accept('with')) {
      const options = c.group();
      if (options) applyViewOptions(rel, options, true);
    }
    while (!c.done() && !isWord(c.peek(), 'as')) c.i += 1;
    c.accept('as');
    rel.query = c.rest();
  }

  function applyViewOptions(rel: Relation, options: Token[], set: boolean) {
    for (const option of commaSplit(options)) {
      if (option[0]?.value !== 'security_invoker') continue;
      if (!set) rel.securityInvoker = false;
      else {
        const value = option[2] ?? option[1];
        rel.securityInvoker = option.length === 1 || (value !== undefined && TRUE_WORDS.has(value.value.toLowerCase()));
      }
    }
  }

  function readAlterView(c: Cursor) {
    c.accept('if', 'exists');
    const name = c.name();
    if (!name) return;
    const rel = relation(name[0], name[1]);
    if (!rel) return;
    if (c.accept('set', 'schema')) {
      const to = c.peek();
      if (isName(to)) moveRelation(rel, to.value, rel.name);
    } else if (c.accept('set')) {
      const options = c.group();
      if (options) applyViewOptions(rel, options, true);
    } else if (c.accept('reset')) {
      const options = c.group();
      if (options) applyViewOptions(rel, options, false);
    } else if (c.accept('rename', 'to')) {
      const to = c.peek();
      if (isName(to)) moveRelation(rel, rel.schema, to.value);
    }
  }

  /** A relation renamed or moved to another schema, with its policies. */
  function moveRelation(rel: Relation, schema: string, name: string) {
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

  /** A column renamed: its type, constraints and index go with it, and the table's policies use the new name, as in Postgres. */
  function renameColumn(rel: Relation, from: string, to: string) {
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
        if (refs.size > 0) expr.tokens = expr.tokens.map((t, i) => (refs.has(i) ? nameAsToken(to, t.line) : t));
      }
    }
  }

  /** A column dropped. With cascade, Postgres drops the policies that use it too. */
  function dropColumn(rel: Relation, column: string, cascade: boolean) {
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

  function policiesOf(rel: Relation) {
    return [...policies.values()].filter((p) => p.schema === rel.schema && p.table === rel.name);
  }

  function readCreatePolicy(c: Cursor, line: number) {
    const nameToken = c.peek();
    if (!isName(nameToken)) return;
    c.i += 1;
    if (!c.accept('on')) return;
    const table = c.name();
    if (!table) return;
    const policy: Policy = {
      schema: table[0],
      table: table[1],
      name: nameToken.value,
      permissive: true,
      command: 'all',
      roles: ['public'],
      line,
    };
    readPolicyClauses(c, policy);
    policies.delete(policyKey(policy.schema, policy.table, policy.name));
    policies.set(policyKey(policy.schema, policy.table, policy.name), policy);
  }

  function readPolicyClauses(c: Cursor, policy: Policy) {
    while (!c.done()) {
      if (c.accept('as', 'permissive')) policy.permissive = true;
      else if (c.accept('as', 'restrictive')) policy.permissive = false;
      else if (c.accept('for')) {
        const command = c.peek()?.value;
        if (command && ['all', ...COMMANDS].includes(command)) policy.command = command as PolicyCommand;
        c.i += 1;
      } else if (c.accept('to')) {
        const roles: string[] = [];
        while (isName(c.peek())) {
          // Unquoted names are folded already; a quoted one such as "Admin" keeps its case, as in Postgres.
          roles.push(c.peek()!.value);
          c.i += 1;
          if (!c.acceptOp(',')) break;
        }
        if (roles.length > 0) policy.roles = roles;
      } else if (c.accept('using')) {
        const inner = c.group();
        if (inner) policy.using = { tokens: inner };
      } else if (c.accept('with', 'check')) {
        const inner = c.group();
        if (inner) policy.check = { tokens: inner };
      } else if (c.accept('rename', 'to')) {
        const to = c.peek();
        if (isName(to)) policy.name = to.value;
        c.i += 1;
      } else c.i += 1;
    }
  }

  function readAlterPolicy(c: Cursor) {
    const nameToken = c.peek();
    if (!isName(nameToken)) return;
    c.i += 1;
    if (!c.accept('on')) return;
    const table = c.name();
    if (!table) return;
    const policy = policies.get(policyKey(table[0], table[1], nameToken.value));
    if (!policy) return;
    readPolicyClauses(c, policy);
    // A rename moves it to a new key.
    if (policy.name !== nameToken.value) {
      policies.delete(policyKey(table[0], table[1], nameToken.value));
      policies.set(policyKey(policy.schema, policy.table, policy.name), policy);
    }
  }

  function readCreateIndex(c: Cursor) {
    c.accept('concurrently');
    c.accept('if', 'not', 'exists');
    if (!isWord(c.peek(), 'on')) c.i += 1;
    if (!c.accept('on')) return;
    c.accept('only');
    const table = c.name();
    if (!table) return;
    if (c.accept('using')) c.i += 1;
    const columns = c.group();
    const first = columns?.[0];
    const rel = relation(table[0], table[1]);
    if (rel && isName(first) && !isOp(columns?.[1], '(')) rel.indexed.add(first.value);
  }

  function readCreateFunction(c: Cursor, line: number) {
    const name = c.name();
    if (!name) return;
    const args = c.group() ?? [];
    const rest = c.rest();
    const names = rest.filter(isName);
    const returns = names.findIndex((t) => t.kind === 'word' && t.value === 'returns');
    const fn: Func = {
      schema: name[0],
      name: name[1],
      args: argTypes(args),
      returnsTrigger: returns !== -1 && ['trigger', 'event_trigger'].includes(names[returns + 1]?.value ?? ''),
      securityDefiner: hasWords(rest, 'security', 'definer'),
      searchPathSet: rest.some((t, i) => isWord(t, 'set') && rest[i + 1]?.value === 'search_path'),
      anon: true,
      authenticated: true,
      line,
      acl: newFunctionAcl(name[0]),
      // The body, whether quoted or BEGIN ATOMIC.
      calls: callsIn(rest),
    };
    // create or replace keeps the existing function's grants.
    const existing = functions.get(functionKey(fn));
    if (existing?.acl) fn.acl = { ...existing.acl };
    fn.anon = fn.acl!.public || fn.acl!.anon;
    fn.authenticated = fn.acl!.public || fn.acl!.authenticated;
    functions.set(functionKey(fn), fn);
  }

  function readAlterFunction(c: Cursor) {
    const name = c.name();
    if (!name) return;
    const args = isOp(c.peek(), '(') ? argTypes(c.group() ?? []) : undefined;
    const rest = c.rest();
    for (const fn of findFunctions(name[0], name[1], args)) {
      const moved = isWord(rest[0], 'set') && isWord(rest[1], 'schema') && isName(rest[2]);
      const renamed = isWord(rest[0], 'rename') && isWord(rest[1], 'to') && isName(rest[2]);
      if (moved || renamed) {
        functions.delete(functionKey(fn));
        if (moved) fn.schema = rest[2].value;
        else fn.name = rest[2].value;
        functions.set(functionKey(fn), fn);
        continue;
      }
      if (hasWords(rest, 'security', 'definer')) fn.securityDefiner = true;
      if (hasWords(rest, 'security', 'invoker')) fn.securityDefiner = false;
      if (rest.some((t, i) => isWord(t, 'set') && rest[i + 1]?.value === 'search_path')) fn.searchPathSet = true;
      if (rest.some((t, i) => isWord(t, 'reset') && rest[i + 1]?.value === 'search_path')) fn.searchPathSet = false;
    }
  }

  function findFunctions(schema: string, name: string, args: string | undefined) {
    if (args !== undefined) {
      const found = functions.get(functionKey({ schema, name, args }));
      return found ? [found] : [];
    }
    return [...functions.values()].filter((f) => f.schema === schema && f.name === name);
  }

  function readAlterTable(c: Cursor, line: number) {
    c.accept('if', 'exists');
    c.accept('only');
    const name = c.name();
    if (!name) return;
    // A table from an earlier migration: what this statement changes still counts.
    const rel = relation(name[0], name[1]) ?? addRelation(name[0], name[1], 'table', line, false);
    for (const action of commaSplit(c.rest())) {
      const a = new Cursor(action);
      if (a.accept('enable', 'row', 'level', 'security')) {
        rel.rls = true;
        rel.rlsKnown = true;
      } else if (a.accept('disable', 'row', 'level', 'security')) {
        rel.rls = false;
        rel.rlsKnown = true;
        rel.line = line;
      } else if (a.accept('add')) {
        const constraint = isWord(a.peek(), 'constraint') ? a.peek(2) : a.peek();
        if (isWord(constraint, ...TABLE_CONSTRAINT_WORDS)) readConstraint(rel, a.rest());
        else {
          a.accept('column');
          a.accept('if', 'not', 'exists');
          // A column that's there already keeps its type: Postgres skips it, or stops with an error.
          const column = a.peek();
          if (isName(column) && !rel.columns.includes(column.value)) readColumn(rel, a.rest());
        }
      } else if (a.accept('alter')) {
        a.accept('column');
        const column = a.peek();
        if (!isName(column)) continue;
        a.i += 1;
        if (a.accept('set', 'not', 'null')) rel.notNull.add(column.value);
        else if (a.accept('set', 'default')) {
          const calls = callsIn(a.rest());
          if (calls.length > 0) (rel.calls ??= []).push(...calls);
        }
        else if (a.accept('drop', 'not', 'null')) rel.notNull.delete(column.value);
        else if (a.accept('type') || a.accept('set', 'data', 'type')) {
          const rest = a.rest();
          const end = rest.findIndex((t) => isWord(t, 'using', 'collate'));
          const type = columnType(end === -1 ? rest : rest.slice(0, end));
          if (type) rel.types.set(column.value, type);
          else rel.types.delete(column.value);
        }
      } else if (a.accept('rename', 'to')) {
        const to = a.peek();
        if (isName(to)) moveRelation(rel, rel.schema, to.value);
      } else if (a.accept('rename')) {
        // rename [column] a to b; a constraint's name doesn't matter here.
        if (a.accept('constraint')) continue;
        a.accept('column');
        const [from, to] = [a.peek(), a.peek(2)];
        if (isName(from) && isWord(a.peek(1), 'to') && isName(to)) renameColumn(rel, from.value, to.value);
      } else if (a.accept('drop')) {
        if (a.accept('constraint')) continue;
        a.accept('column');
        a.accept('if', 'exists');
        const column = a.peek();
        if (isName(column)) dropColumn(rel, column.value, hasWords(action, 'cascade'));
      } else if (a.accept('set', 'schema')) {
        const to = a.peek();
        if (isName(to)) moveRelation(rel, to.value, rel.name);
      }
    }
  }

  function readAlterPublication(c: Cursor) {
    const name = c.peek()?.value;
    c.i += 1;
    if (name !== 'supabase_realtime' || !c.accept('add', 'table')) return;
    for (const part of commaSplit(c.rest())) {
      const p = new Cursor(part);
      p.accept('only');
      const table = p.name();
      const rel = table && relation(table[0], table[1]);
      if (rel) rel.realtime = true;
    }
  }

  function newFunctionAcl(schema: string): ExecuteAcl {
    const global = defaults.functionsGlobal;
    const local = defaults.functionsBySchema.get(schema);
    return {
      public: global.public || !!local?.public,
      anon: global.anon || !!local?.anon,
      authenticated: global.authenticated || !!local?.authenticated,
    };
  }

  function readDefaultPrivileges(c: Cursor) {
    // alter default privileges [for role r] [in schema s] grant|revoke ... on tables|functions to|from roles
    const rest = c.rest();
    const at = rest.findIndex((t) => isWord(t, 'grant', 'revoke'));
    if (at === -1) return;
    const granting = rest[at].value === 'grant';
    const inSchema = rest.findIndex((t, i) => isWord(t, 'in') && isWord(rest[i + 1], 'schema'));
    const schemas = inSchema === -1 ? undefined : commaSplit(rest.slice(inSchema + 2, at)).map((p) => p[0]?.value);
    const on = rest.findIndex((t, i) => i > at && isWord(t, 'on'));
    if (on === -1) return;
    const target = rest[on + 1]?.value;
    const privs = privilegesFrom(rest.slice(at + 1 + (isWord(rest[at + 1], 'grant') ? 3 : 0), on));
    const roles = rolesAfter(rest, on + 2);

    if (target === 'functions' || target === 'routines') {
      if (!privs.execute && !privs.all) return;
      const apply = (acl: ExecuteAcl, allowPublic: boolean) => {
        for (const role of ['public', 'anon', 'authenticated'] as const) {
          if (!roles.includes(role)) continue;
          // IN SCHEMA can grant PUBLIC more, but can't take back what Postgres gives it everywhere.
          if (role === 'public' && !granting && !allowPublic) continue;
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

    if (target !== 'tables') return;
    if (schemas && !schemas.includes('public')) return;
    defaults.tables ??= { anon: new Set(COMMANDS), authenticated: new Set(COMMANDS) };
    for (const role of ['anon', 'authenticated'] as const) {
      if (!roles.includes(role) && !roles.includes('public')) continue;
      for (const command of privs.commands) {
        if (granting) defaults.tables[role].add(command);
        else defaults.tables[role].delete(command);
      }
    }
  }

  function rolesAfter(tokens: Token[], from: number): string[] {
    const out: string[] = [];
    for (let i = from; i < tokens.length; i += 1) {
      const t = tokens[i];
      if (isWord(t, 'with', 'granted', 'cascade', 'restrict')) break;
      if (isName(t) && !isWord(t, 'to', 'from', 'group')) out.push(t.value);
    }
    return out;
  }

  function readGrant(c: Cursor, granting: boolean) {
    c.accept('grant', 'option', 'for');
    const rest = c.rest();
    const on = rest.findIndex((t) => isWord(t, 'on'));
    if (on === -1) return; // role membership
    const privs = privilegesFrom(rest.slice(0, on));
    const to = rest.findIndex((t, i) => i > on && isWord(t, granting ? 'to' : 'from'));
    if (to === -1) return;
    const roles = rolesAfter(rest, to + 1);
    const target = new Cursor(rest.slice(on + 1, to));

    if (target.accept('schema')) {
      if (!privs.usage && !privs.all) return;
      for (const part of commaSplit(target.rest())) {
        const schema = part[0]?.value;
        if (!schema || SYSTEM_SCHEMAS.has(schema)) continue;
        if (granting && (roles.includes('anon') || roles.includes('authenticated'))) exposed.add(schema);
      }
      return;
    }
    if (target.accept('function') || target.accept('routine')) {
      for (const part of splitFunctionList(target.rest())) {
        const p = new Cursor(part);
        const name = p.name();
        if (!name) continue;
        const args = isOp(p.peek(), '(') ? argTypes(p.group() ?? []) : undefined;
        for (const fn of findFunctions(name[0], name[1], args)) applyExecute(fn, roles, granting && (privs.execute || privs.all), granting);
      }
      return;
    }
    if (target.accept('all', 'functions', 'in', 'schema') || target.accept('all', 'routines', 'in', 'schema')) {
      const schemas = commaSplit(target.rest()).map((p) => p[0]?.value);
      for (const fn of functions.values()) if (schemas.includes(fn.schema)) applyExecute(fn, roles, granting, granting);
      return;
    }
    let tables: Relation[] = [];
    if (target.accept('all', 'tables', 'in', 'schema')) {
      const schemas = commaSplit(target.rest()).map((p) => p[0]?.value);
      tables = [...catalog.relations.values()].filter((r) => schemas.includes(r.schema));
    } else {
      target.accept('table');
      for (const part of commaSplit(target.rest())) {
        const p = new Cursor(part);
        p.accept('only');
        const name = p.name();
        const rel = name && relation(name[0], name[1]);
        if (rel) tables.push(rel);
      }
    }
    for (const rel of tables) {
      const grants = ensureGrants(rel);
      for (const role of ['anon', 'authenticated'] as const) {
        if (!roles.includes(role) && !roles.includes('public')) continue;
        // Revoking from public leaves Supabase's direct grants to anon and authenticated in place.
        if (!granting && !roles.includes(role)) continue;
        for (const command of privs.commands) {
          if (granting) grants[role].add(command);
          else grants[role].delete(command);
        }
      }
    }
  }

  function applyExecute(fn: Func, roles: string[], allow: boolean, granting: boolean) {
    const acl = (fn.acl ??= { public: true, anon: true, authenticated: true });
    for (const role of ['public', 'anon', 'authenticated'] as const) {
      if (roles.includes(role)) acl[role] = granting ? allow || acl[role] : false;
    }
    fn.anon = acl.public || acl.anon;
    fn.authenticated = acl.public || acl.authenticated;
  }

  function readDrop(c: Cursor) {
    if (c.accept('policy')) {
      c.accept('if', 'exists');
      const name = c.peek();
      if (!isName(name)) return;
      c.i += 1;
      if (!c.accept('on')) return;
      const table = c.name();
      if (!table) return;
      policies.delete(policyKey(table[0], table[1], name.value));
      return;
    }
    if (c.accept('function')) {
      c.accept('if', 'exists');
      for (const part of splitFunctionList(c.rest())) {
        const p = new Cursor(part);
        const name = p.name();
        if (!name) continue;
        const args = isOp(p.peek(), '(') ? argTypes(p.group() ?? []) : undefined;
        for (const fn of findFunctions(name[0], name[1], args)) functions.delete(functionKey(fn));
      }
      return;
    }
    if (c.accept('table') || c.accept('view') || c.accept('materialized', 'view') || c.accept('foreign', 'table')) {
      c.accept('if', 'exists');
      const gone: string[] = [];
      for (const part of commaSplit(c.rest())) {
        const p = new Cursor(part);
        const name = p.name();
        if (!name) continue;
        dropRelation(name[0], name[1]);
        gone.push(key(name[0], name[1]));
      }
      // With cascade, Postgres drops the views that read it too, and the views on those.
      if (!hasWords(c.rest(), 'cascade')) return;
      for (let i = 0; i < gone.length; i += 1) {
        for (const rel of [...catalog.relations.values()]) {
          if ((rel.kind !== 'view' && rel.kind !== 'matview') || !rel.query) continue;
          if (!viewReads(rel.query).tables.some(([schema, table]) => key(schema ?? 'public', table) === gone[i])) continue;
          dropRelation(rel.schema, rel.name);
          gone.push(key(rel.schema, rel.name));
        }
      }
    }
  }

  function dropRelation(schema: string, name: string) {
    catalog.relations.delete(key(schema, name));
    for (const [id, x] of policies) if (x.schema === schema && x.table === name) policies.delete(id);
  }

  function readInsert(c: Cursor) {
    const table = c.name();
    if (!table || table[0] !== 'storage' || table[1] !== 'buckets') return;
    const columns = (c.group() ?? []).filter(isName).map((t) => t.value);
    if (!c.accept('values')) return;
    while (isOp(c.peek(), '(')) {
      const row = commaSplit(c.group() ?? []);
      const value = (column: string) => row[columns.indexOf(column)]?.[0];
      const id = value('id') ?? value('name');
      if (id?.kind === 'string') {
        const pub = value('public');
        catalog.buckets.set(id.value, { id: id.value, public: !!pub && (pub.value === 'true' || pub.value === 't') });
      }
      if (!c.acceptOp(',')) break;
    }
  }
}

function hasWords(tokens: Token[], ...words: string[]) {
  return tokens.some((_, i) => words.every((w, k) => isWord(tokens[i + k], w)));
}

// Types whose names are more than one word, so the first word isn't an argument name.
const MULTI_WORD_TYPE = /^(double precision|character varying|bit varying|national character|time with|time without|timestamp with|timestamp without|interval )/;

// Short names Postgres accepts, as oidvectortypes() writes them.
const TYPE_ALIASES: Record<string, string> = {
  int: 'integer',
  int4: 'integer',
  int8: 'bigint',
  int2: 'smallint',
  float8: 'double precision',
  float4: 'real',
  bool: 'boolean',
  varchar: 'character varying',
  char: 'character',
  timestamptz: 'timestamp with time zone',
  timestamp: 'timestamp without time zone',
  timetz: 'time with time zone',
  time: 'time without time zone',
  decimal: 'numeric',
};

const isArgMode = (t: Token | undefined) => isWord(t, 'in', 'out', 'inout', 'variadic');

/**
 * "(a uuid, out n int, b double precision default 1)" → "uuid, double
 * precision", the way Postgres names an overload: OUT arguments aren't part of
 * it. A quoted type such as "AppRole" stays quoted, or it would fold to approle.
 */
function argTypes(tokens: Token[]): string {
  return commaSplit(tokens)
    .map((arg) => {
      let parts = arg;
      const cut = parts.findIndex((t) => isWord(t, 'default') || isOp(t, '='));
      if (cut !== -1) parts = parts.slice(0, cut);
      // The mode comes first or after the name: out total int, total out int. IN OUT is INOUT.
      const at = isArgMode(parts[0]) ? 0 : isName(parts[0]) && isArgMode(parts[1]) ? 1 : -1;
      let end = at;
      while (at !== -1 && isArgMode(parts[end])) end += 1;
      const mode = at === -1 ? 'in' : parts.slice(at, end).map((t) => t.value).join(' ');
      if (mode === 'out') return '';
      if (at !== -1) parts = [...parts.slice(0, at), ...parts.slice(end)];
      // Two names in a row are a name and a type, unless they spell one type.
      if (parts.length > 1 && isName(parts[0]) && isName(parts[1]) && !MULTI_WORD_TYPE.test(`${canon(parts).replace(/"/g, '')} `)) {
        parts = parts.slice(1);
      }
      // Lengths and precisions, such as varchar(20), aren't part of the name.
      const match = pairs(parts);
      const kept: Token[] = [];
      for (let i = 0; i < parts.length; i += 1) {
        if (isOp(parts[i], '(') && match[i] !== -1) i = match[i];
        else kept.push(parts[i]);
      }
      let type = canon(kept).replace(/^(pg_catalog|public)\./, '');
      const array = type.endsWith('[]') ? '[]' : '';
      if (array) type = type.slice(0, -2);
      return (TYPE_ALIASES[type] ?? type) + array;
    })
    .filter((a) => a !== '')
    .join(', ');
}

function splitFunctionList(tokens: Token[]): Token[][] {
  return commaSplit(tokens);
}

/**
 * The schema and table a drop policy built with format() names, such as
 * public.%I: undefined for a part filled in at run time. A bare %I is a table
 * in any schema. Undefined when it isn't a plain name.
 */
function dropTarget(text: string): [string | undefined, string | undefined] | undefined {
  const parts = text.trim().split('.');
  if (parts.length > 2) return undefined;
  const filled = (part: string) => /^%(?:\d+\$)?-?[Is]$/.test(part.trim());
  const name = (part: string) => {
    const tokens = tokenize(part);
    return tokens.length === 1 && isName(tokens[0]) ? tokens[0].value : null;
  };
  const read = (part: string) => (filled(part) ? undefined : name(part));
  const table = read(parts.at(-1)!);
  const schema = parts.length === 2 ? read(parts[0]) : table === undefined ? undefined : 'public';
  if (table === null || schema === null) return undefined;
  return [schema, table];
}

// ---------------------------------------------------------------------------
// Reading the catalog query's JSON

/**
 * Run in the Supabase SQL Editor. It returns one JSON value describing tables,
 * views, policies, functions, grants and buckets: names and settings only, no rows.
 */
export const CATALOG_QUERY = `-- NestedBit Supabase RLS Checker: run this in the SQL Editor, then copy the
-- one value it returns. It reads settings (tables, policies, grants, functions),
-- never the rows in your tables.
with skip as (
  select unnest(array[
    '_timescaledb_cache', '_timescaledb_catalog', '_timescaledb_config', '_timescaledb_internal',
    'auth', 'cron', 'extensions', 'graphql', 'graphql_public', 'information_schema', 'net', 'pgmq',
    'pgroonga', 'pgsodium', 'pgsodium_masks', 'pgtle', 'pgbouncer', 'pg_catalog', 'pg_toast',
    'realtime', 'repack', 'storage', 'supabase_functions', 'supabase_migrations', 'tiger',
    'topology', 'vault'
  ]::name[]) as nspname
)
select json_build_object(
  'supabase_rls_check', 1,
  'exposed', coalesce(nullif(current_setting('pgrst.db_schemas', true), ''), 'public'),
  'relations', (
    select coalesce(json_agg(json_build_object(
      'schema', n.nspname,
      'name', c.relname,
      'kind', c.relkind,
      'rls', c.relrowsecurity,
      'options', c.reloptions,
      'columns', (
        select coalesce(json_agg(a.attname order by a.attnum), '[]'::json)
        from pg_attribute a
        where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
      ),
      'column_types', (
        select coalesce(json_object_agg(a.attname, format_type(a.atttypid, a.atttypmod)), '{}'::json)
        from pg_attribute a
        where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
      ),
      'not_null', (
        select coalesce(json_agg(a.attname order by a.attnum), '[]'::json)
        from pg_attribute a
        where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped and a.attnotnull
      ),
      'user_refs', (
        select coalesce(json_agg(distinct a.attname), '[]'::json)
        from pg_constraint k
        join pg_attribute a on a.attrelid = k.conrelid and a.attnum = k.conkey[1]
        join pg_attribute r on r.attrelid = k.confrelid and r.attnum = k.confkey[1]
        where k.conrelid = c.oid and k.contype = 'f' and cardinality(k.conkey) = 1
          and k.confrelid = to_regclass('auth.users') and r.attname = 'id'
      ),
      'refs', (
        select coalesce(json_object_agg(a.attname, json_build_array(rn.nspname, rc.relname, r.attname)), '{}'::json)
        from pg_constraint k
        join pg_attribute a on a.attrelid = k.conrelid and a.attnum = k.conkey[1]
        join pg_class rc on rc.oid = k.confrelid
        join pg_namespace rn on rn.oid = rc.relnamespace
        join pg_attribute r on r.attrelid = k.confrelid and r.attnum = k.confkey[1]
        where k.conrelid = c.oid and k.contype = 'f' and cardinality(k.conkey) = 1
      ),
      'indexed', (
        select coalesce(json_agg(distinct a.attname), '[]'::json)
        from pg_index x
        join pg_attribute a on a.attrelid = c.oid and a.attnum = x.indkey[0]
        where x.indrelid = c.oid
      ),
      'anon', array(
        select p from unnest(array['select', 'insert', 'update', 'delete']) p
        where has_table_privilege('anon', c.oid, p)
      ),
      'authenticated', array(
        select p from unnest(array['select', 'insert', 'update', 'delete']) p
        where has_table_privilege('authenticated', c.oid, p)
      ),
      'definition', case when c.relkind in ('v', 'm') then pg_get_viewdef(c.oid) end,
      'realtime', exists (
        select 1 from pg_publication_tables t
        where t.pubname = 'supabase_realtime' and t.schemaname = n.nspname and t.tablename = c.relname
      )
    ) order by n.nspname, c.relname), '[]'::json)
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where c.relkind in ('r', 'p', 'v', 'm', 'f')
      and n.nspname not in (select nspname from skip)
      and n.nspname not like 'pg_temp%'
      and not exists (select 1 from pg_depend d where d.objid = c.oid and d.deptype = 'e')
  ),
  'policies', (
    select coalesce(json_agg(json_build_object(
      'schema', p.schemaname, 'table', p.tablename, 'name', p.policyname,
      'permissive', p.permissive, 'roles', p.roles, 'cmd', p.cmd,
      'qual', p.qual, 'with_check', p.with_check
    ) order by p.schemaname, p.tablename, p.policyname), '[]'::json)
    from pg_policies p
    where p.schemaname not in (select nspname from skip) or (p.schemaname = 'storage' and p.tablename = 'objects')
  ),
  'functions', (
    select coalesce(json_agg(json_build_object(
      'schema', n.nspname,
      'name', f.proname,
      'args', oidvectortypes(f.proargtypes),
      'returns', pg_get_function_result(f.oid),
      'security_definer', f.prosecdef,
      'config', f.proconfig,
      'anon', has_function_privilege('anon', f.oid, 'execute'),
      'authenticated', has_function_privilege('authenticated', f.oid, 'execute'),
      'called_by', (
        select coalesce(json_agg(distinct format('%I.%I(%s)', gn.nspname, g.proname, oidvectortypes(g.proargtypes))), '[]'::json)
        from pg_proc g
        join pg_namespace gn on gn.oid = g.pronamespace
        where g.oid <> f.oid
          and gn.nspname not in (select nspname from skip)
          and strpos(lower(g.prosrc), lower(f.proname)) > 0
          and case when f.proname ~ '^[a-z_][a-z0-9_]*$'
            then g.prosrc ~* ('(^|[^a-z0-9_$])' || f.proname || '[[:space:]]*[(]')
            else true end
      ),
      'used_by', (
        select coalesce(json_agg(distinct format('%I.%I', dn.nspname, dc.relname)), '[]'::json)
        from pg_depend d
        left join pg_attrdef ad on d.classid = 'pg_attrdef'::regclass and ad.oid = d.objid
        left join pg_constraint ck on d.classid = 'pg_constraint'::regclass and ck.oid = d.objid
        join pg_class dc on dc.oid = coalesce(ad.adrelid, ck.conrelid)
        join pg_namespace dn on dn.oid = dc.relnamespace
        where d.refclassid = 'pg_proc'::regclass and d.refobjid = f.oid
      )
    ) order by n.nspname, f.proname), '[]'::json)
    from pg_proc f
    join pg_namespace n on n.oid = f.pronamespace
    where f.prokind = 'f'
      and n.nspname not in (select nspname from skip)
      and n.nspname not like 'pg_temp%'
      and not exists (select 1 from pg_depend d where d.objid = f.oid and d.deptype = 'e')
  ),
  'buckets', (
    select coalesce(json_agg(json_build_object('id', b.id, 'public', b.public)), '[]'::json)
    from storage.buckets b
  )
) as supabase_rls_check;
`;

const KINDS: Record<string, Kind> = { r: 'table', p: 'table', v: 'view', m: 'matview', f: 'foreign' };
const CMD: Record<string, PolicyCommand> = { ALL: 'all', SELECT: 'select', INSERT: 'insert', UPDATE: 'update', DELETE: 'delete' };

type Json = Record<string, unknown>;

/** Finds the catalog object in whatever the SQL Editor copied: the bare value, a JSON row, or a CSV cell. */
function unwrapJson(text: string): Json {
  let value: unknown;
  const trimmed = text.trim();
  try {
    value = JSON.parse(trimmed);
  } catch {
    // A CSV cell: quotes doubled, maybe with a header line.
    const start = trimmed.indexOf('{');
    const end = trimmed.lastIndexOf('}');
    if (start === -1 || end === -1) throw new Error('That isn’t SQL or the JSON the query returns.');
    const body = trimmed.slice(start, end + 1);
    value = JSON.parse(body.includes('""') ? body.replace(/""/g, '"') : body);
  }
  for (let depth = 0; depth < 4; depth += 1) {
    if (typeof value === 'string') value = JSON.parse(value);
    else if (Array.isArray(value)) value = value[0];
    else if (value && typeof value === 'object' && !('relations' in value)) {
      const inner = (value as Json).supabase_rls_check;
      if (inner && typeof inner === 'object') value = inner;
      else if (typeof inner === 'string') value = JSON.parse(inner);
      else break;
    } else break;
  }
  if (!value || typeof value !== 'object' || !Array.isArray((value as Json).relations)) {
    throw new Error('This JSON isn’t what the query returns. Copy the single value in the result, all of it.');
  }
  return value as Json;
}

const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.map(String) : typeof v === 'string' ? v.replace(/^\{|\}$/g, '').split(',').filter(Boolean) : [];

/** {"user_id": "uuid", "name": "character varying(20)"} as column → type, in columnType()'s form. */
function columnTypes(v: unknown): Map<string, string> {
  const out = new Map<string, string>();
  if (!v || typeof v !== 'object' || Array.isArray(v)) return out;
  for (const [column, type] of Object.entries(v as Json)) {
    if (typeof type !== 'string') continue;
    const name = columnType(tokenize(type));
    if (name) out.set(column, name);
  }
  return out;
}

/** {"profile_id": ["public", "profiles", "id"]} as column → what it points at. Older copies have none. */
function foreignKeys(v: unknown): Map<string, [string, string, string]> {
  const out = new Map<string, [string, string, string]>();
  if (!v || typeof v !== 'object' || Array.isArray(v)) return out;
  for (const [column, target] of Object.entries(v as Json)) {
    if (Array.isArray(target) && target.length === 3) out.set(column, target.map(String) as [string, string, string]);
  }
  return out;
}

function readJson(text: string): Catalog {
  const data = unwrapJson(text);
  const catalog = emptyCatalog('json');
  catalog.exposed = String(data.exposed ?? 'public')
    .split(',')
    .map((s) => s.trim().replace(/^"|"$/g, ''))
    .filter(Boolean);
  const exprOf = (v: unknown): Expr | undefined => (typeof v === 'string' && v.trim() !== '' ? { tokens: tokenize(v) } : undefined);

  for (const r of data.relations as Json[]) {
    const kind = KINDS[String(r.kind)];
    if (!kind) continue;
    const options = strings(r.options).map((o) => o.toLowerCase());
    const rel: Relation = {
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
      query: typeof r.definition === 'string' ? tokenize(r.definition) : undefined,
      grants: {
        anon: new Set(strings(r.anon).map((s) => s.toLowerCase()) as Command[]),
        authenticated: new Set(strings(r.authenticated).map((s) => s.toLowerCase()) as Command[]),
      },
      realtime: r.realtime === true,
    };
    catalog.relations.set(key(rel.schema, rel.name), rel);
  }
  for (const p of (Array.isArray(data.policies) ? data.policies : []) as Json[]) {
    catalog.policies.push({
      schema: String(p.schema),
      table: String(p.table),
      name: String(p.name),
      permissive: String(p.permissive).toUpperCase() !== 'RESTRICTIVE',
      command: CMD[String(p.cmd).toUpperCase()] ?? 'all',
      roles: strings(p.roles),
      using: exprOf(p.qual),
      check: exprOf(p.with_check),
    });
  }
  for (const f of (Array.isArray(data.functions) ? data.functions : []) as Json[]) {
    catalog.functions.push({
      schema: String(f.schema),
      name: String(f.name),
      args: String(f.args ?? ''),
      returnsTrigger: /^(event_)?trigger$/i.test(String(f.returns ?? '').trim()),
      securityDefiner: f.security_definer === true,
      searchPathSet: strings(f.config).some((c) => c.startsWith('search_path=')),
      anon: f.anon === true,
      authenticated: f.authenticated === true,
      // Older copies of the query's result don't say.
      calledBy: Array.isArray(f.called_by) ? strings(f.called_by) : undefined,
      usedBy: Array.isArray(f.used_by) ? strings(f.used_by) : undefined,
    });
  }
  for (const b of (Array.isArray(data.buckets) ? data.buckets : []) as Json[]) {
    catalog.buckets.set(String(b.id), { id: String(b.id), public: b.public === true });
  }
  catalog.statements = catalog.relations.size;
  return catalog;
}

// ---------------------------------------------------------------------------
// Findings

export interface Finding {
  id: string;
  severity: Severity;
  category: 'security' | 'performance';
  /** Supabase database linter numbers this matches, such as 0013. */
  lints: string[];
  title: string;
  /** schema.table, schema.function(args) or a bucket. */
  object: string;
  line?: number;
  detail: string;
  /**
   * What the finding shows as its fix: SQL that fixes it on its own, or, when
   * `manual`, a commented block to fill in. fixScript() builds its script from
   * `edits` when there are any, and from this otherwise.
   */
  fix?: string;
  /** The fix needs a decision from the user: fixScript() lists it, commented out, under NEEDS YOUR INPUT. */
  manual?: true;
  /** Changes fixScript() merges with other findings' changes to the same object. */
  edits?: Edit[];
}

/**
 * A change to one policy. fixScript() merges every finding's changes to the
 * same policy into one statement, so a later fix can't undo an earlier one.
 */
export interface PolicyEdit {
  kind: 'policy';
  schema: string;
  table: string;
  name: string;
  /** A security rewrite of a clause beats a speed rewrite of it. */
  priority: 'security' | 'speed';
  drop?: true;
  /** New USING and WITH CHECK conditions, without the parentheses around them. */
  using?: string;
  check?: string;
  /** New roles for TO. */
  roles?: string[];
  /** SQL that takes the policy's place, such as separate read and write policies. The old policy is dropped first. */
  replaceWith?: string;
  /** A plain comment shown above the SQL. */
  note?: string;
}

/**
 * A change to one function. fixScript() merges every finding's changes to the
 * same function into one block: its search_path first, then a move or a revoke.
 */
export interface FunctionEdit {
  kind: 'function';
  schema: string;
  name: string;
  /** Its argument types, as in its signature. */
  args: string;
  /** A fixed search_path, as it follows `set search_path =`. */
  searchPath?: string;
  /** A schema the API doesn't serve, to move it to. Policies that call it keep working. */
  moveTo?: string;
  /** When other functions share its name: how many arguments a call passes to run this one. */
  callArgs?: number;
  /** Roles that lose execute on it. */
  revokeFrom?: string[];
  /** SQL shown commented out after the fix, for the user to run if it fits their app. */
  optional?: string;
  /** A plain comment shown above the SQL. */
  note?: string;
}

export type Edit = PolicyEdit | FunctionEdit;

/** What one audience can reach with one command. */
export type Reach = 'none' | 'all' | 'own' | 'some';

export interface TableReport {
  schema: string;
  name: string;
  kind: Kind;
  rls: boolean;
  /** False when neither anon nor authenticated holds any privilege on it. */
  reachable: boolean;
  /** True when the input never said, and Supabase's default grants are assumed. */
  grantsAssumed: boolean;
  policies: number;
  /** Created somewhere else, such as an earlier migration: policies may exist that the input doesn't show. */
  partial: boolean;
  access: Record<Command, { anon: Reach; authenticated: Reach }>;
}

export interface LintResult {
  source: 'sql' | 'json';
  findings: Finding[];
  tables: TableReport[];
  counts: { tables: number; policies: number; functions: number; statements: number };
}

const SENSITIVE = new Set([
  'password', 'passwd', 'pwd', 'passphrase', 'secret', 'secret_key', 'private_key', 'api_key', 'apikey', 'auth_key',
  'token', 'jwt', 'access_token', 'refresh_token', 'oauth_token', 'session_token', 'bearer_token', 'auth_code',
  'session_id', 'session_key', 'session_secret', 'recovery_code', 'backup_code', 'verification_code', 'otp',
  'two_factor', '2fa_secret', '2fa_code', 'ssn', 'social_security', 'social_security_number', 'driver_license',
  'drivers_license', 'license_number', 'passport_number', 'passport_id', 'national_id', 'tax_id', 'credit_card',
  'card_number', 'cvv', 'cvc', 'cvn', 'bank_account', 'account_number', 'routing_number', 'iban', 'swift_code', 'bic',
  'health_record', 'medical_record', 'patient_id', 'insurance_number', 'health_insurance', 'medical_insurance',
  'treatment', 'mac_address', 'macaddr', 'imei', 'device_uuid', 'pgp_key', 'gpg_key', 'ssh_key', 'certificate',
  'license_key', 'activation_key', 'facial_recognition',
]);

export const sensitiveColumns = (columns: string[]) => columns.filter((c) => SENSITIVE.has(c.toLowerCase().replace(/-/g, '_')));

const appliesTo = (policy: Policy, role: 'anon' | 'authenticated') => policy.roles.includes('public') || policy.roles.includes(role);
const covers = (policy: Policy, command: Command) => policy.command === 'all' || policy.command === command;

/** The clause that decides which existing rows a command reaches, or which new rows it may write. */
function clauseFor(policy: Policy, command: Command): Expr | undefined {
  if (command === 'insert') return policy.check ?? (policy.command === 'all' ? policy.using : undefined);
  return policy.using;
}

const RANK: Record<Reach, number> = { none: 0, own: 1, some: 2, all: 3 };

/**
 * Whether a condition can only pass for a signed-in user: a sign-in check or
 * an ownership test that must hold, through AND, or in every OR branch.
 * auth.uid() is null for signed-out visitors, so an ownership test never
 * matches them. Nesting deeper than real policies go counts as no.
 */
function needsUser(tokens: Token[], depth = 0): boolean {
  if (depth > 32) return false;
  const t = unwrap(tokens);
  const ors = splitTop(t, 'or');
  if (ors.length > 1) return ors.every((part) => needsUser(part, depth + 1));
  const ands = splitTop(t, 'and');
  if (ands.length > 1) return ands.some((part) => needsUser(part, depth + 1));
  return truthOf(t) === 'signed' || ownerColumns({ tokens: t }).length > 0;
}

/** What a condition reaches for one role: the widest of its top-level OR branches. A missing one reaches nothing. */
function classify(expr: Expr | undefined, role: 'anon' | 'authenticated'): Reach {
  if (!expr) return 'none';
  let best: Reach = 'none';
  for (const branch of splitTop(unwrap(expr.tokens), 'or')) {
    const truth = truthOf(branch);
    const reach: Reach =
      truth === 'true'
        ? 'all'
        : truth === 'signed'
          ? role === 'anon' ? 'none' : 'all'
          : needsUser(branch)
            ? role === 'anon' ? 'none' : 'own'
            : 'some';
    if (RANK[reach] > RANK[best]) best = reach;
  }
  return best;
}

function reachOf(rel: Relation, policies: Policy[], command: Command, role: 'anon' | 'authenticated'): Reach {
  if (rel.grants && !rel.grants[role].has(command)) return 'none';
  if (rel.kind === 'view') return rel.securityInvoker ? 'some' : command === 'select' ? 'all' : 'some';
  // A foreign table ignores RLS for writes too; a materialized view can only be read.
  if (rel.kind === 'foreign') return 'all';
  if (rel.kind !== 'table') return command === 'select' ? 'all' : 'none';
  if (!rel.rls) return 'all';
  const applicable = policies.filter((p) => covers(p, command) && appliesTo(p, role));
  const permissive = applicable.filter((p) => p.permissive);
  if (permissive.length === 0) return 'none';
  let best: Reach = 'none';
  for (const p of permissive) {
    const reach = classify(clauseFor(p, command), role);
    if (RANK[reach] > RANK[best]) best = reach;
  }
  // A restrictive policy without the clause doesn't hold anything back.
  if (best === 'all' && applicable.some((p) => !p.permissive && clauseFor(p, command))) best = 'some';
  return best;
}

const VERB: Record<Command, string> = { select: 'read', insert: 'add', update: 'change', delete: 'delete' };

/** Column names that usually hold a row's owner, most likely first. */
const OWNER_NAMES = ['user_id', 'userId', 'owner_id', 'ownerId', 'created_by', 'createdBy', 'author_id', 'authorId', 'profile_id'];

/** How a fix ties a row to the signed-in user. */
interface Owner {
  /** The owner column, as SQL. */
  column: string;
  /** The user's id in the form the column holds it. */
  caller: string;
  /** Whether a row can be saved without an owner. */
  nullable: boolean;
  /** What the column holds of the user: their id, or their email. */
  who: Who;
}

/**
 * The owner column, or why the checker can't pick one. `none` when the table
 * has no column that could hold it at all, so the user would add one.
 */
type OwnerPick =
  | { owner: Owner; reason?: undefined; none?: undefined; suggest?: undefined }
  | { owner?: undefined; reason: string; none?: true; suggest?: { test: string; via: string } };

const UID = '(select auth.uid())';
// Supabase keeps the user's id in the JWT's sub too, as text: third-party sign-in such as Clerk only has that.
const SUB = "(select auth.jwt() ->> 'sub')";
const EMAIL = "(select auth.jwt() ->> 'email')";

/**
 * Whether a column points at a user id: a foreign key to auth.users, or to a
 * column that is one itself, such as profiles.id when it references auth.users.
 */
function pointsAtUser(rel: Relation, column: string, relations?: Map<string, Relation>): boolean {
  if (rel.userRefs.has(column)) return true;
  const target = rel.refs.get(column);
  return !!target && !!relations?.get(key(target[0], target[1]))?.userRefs.has(target[2]);
}

/**
 * The column that holds each row's owner. In order: the column the table's
 * policies already compare with the user's id, or with their email, a foreign
 * key to auth.users, a usual name, and id on a profiles, users or accounts
 * table. profile_id counts only when it points at a user id. Two candidates
 * at one step would be a guess, so then there's none. The column's type says
 * how to compare it: uuid with auth.uid(), text with the JWT's sub.
 */
function ownerOf(rel: Relation | undefined, policies: Policy[], relations?: Map<string, Relation>): OwnerPick {
  const columns = rel?.columns ?? [];
  const exists = (c: string) => columns.length === 0 || columns.includes(c);
  const byName = (list: string[]) => OWNER_NAMES.filter((n) => list.includes(n));
  const compared = (who: Who) => [...new Set(policies.flatMap((p) => [...ownerColumns(p.using, who), ...ownerColumns(p.check, who)]))].filter(exists);
  let pick = compared('id');
  // Policies that tie rows to the caller's email say the column holds emails.
  const who: Who = pick.length === 0 && compared('email').length > 0 ? 'email' : 'id';
  if (who === 'email') pick = compared('email');
  let skipped: string | undefined;
  let suggest: { test: string; via: string } | undefined;
  if (pick.length === 0 && rel) {
    const refs = [...rel.userRefs];
    pick = refs.length > 1 && byName(refs).length === 1 ? byName(refs) : refs;
    if (pick.length === 0) {
      // A profile_id may hold a profile's own id, which is never a user id.
      const named = byName(columns);
      pick = named.filter((c) => c !== 'profile_id' || pointsAtUser(rel, c, relations)).slice(0, 1);
      const target = rel.refs.get('profile_id');
      if (pick.length === 0 && named.includes('profile_id')) {
        skipped = target ? `profile_id points at ${target[0]}.${target[1]}, not at a user id.` : 'profile_id may hold a profile’s id, not a user id.';
        // A profiles table with one column for its user: the row is the user's when its profile is.
        const users = target ? [...(relations?.get(key(target[0], target[1]))?.userRefs ?? [])] : [];
        if (target && users.length === 1) {
          const profiles = qualifiedName(target[0], target[1]);
          suggest = {
            test: `profile_id in (select ${identifier(target[2])} from ${profiles} where ${identifier(users[0])} = ${UID})`,
            via: `${profiles}.${identifier(users[0])}`,
          };
        }
      }
    }
    const userKeyed = ['profiles', 'users', 'accounts'].includes(rel.name) && columns.includes('id');
    if (pick.length === 0 && userKeyed && (rel.types.get('id') === 'uuid' || rel.userRefs.has('id'))) pick = ['id'];
  }
  if (pick.length === 0) {
    if (skipped) return { reason: skipped, suggest };
    return columns.length === 0 ? { reason: 'The checker can’t see this table’s columns.' } : { reason: 'No column says who owns each row.', none: true };
  }
  if (pick.length > 1) return { reason: `More than one column could hold the owner: ${pick.join(', ')}.` };
  const column = pick[0];
  const type = rel?.types.get(column);
  const nullable = !rel?.notNull.has(column);
  const textual = type === 'text' || type === 'character varying';
  if (who === 'email') {
    if (type !== undefined && !textual) return { reason: `${column} holds ${type} values, not emails.` };
    return { owner: { column: identifier(column), caller: EMAIL, nullable, who } };
  }
  // An unknown type, from catalog JSON older than the types, is most likely uuid.
  const caller = type === undefined || type === 'uuid' ? UID : textual ? SUB : undefined;
  if (!caller) return { reason: `${column} holds ${type} values, not Supabase user ids.` };
  return { owner: { column: identifier(column), caller, nullable, who } };
}

/** Tables whose rows give people access, such as team members or user roles, by their name. */
const ACCESS_TABLE = /(^|_)(members?|memberships?|roles?|participants?|collaborators?|admins?|moderators?|permissions?)$/i;

/** A write clause that lets every row through, or every signed-in user. A missing one lets nothing through. */
const loose = (expr: Expr | undefined) => alwaysTrue(expr) || signedInOnly(expr);

/**
 * The fix that ties a policy's writes to each row's owner. Only clauses that
 * let any row through change: one that is only true or a sign-in check
 * becomes the owner test, and anything else keeps its condition with the
 * owner test added by AND. A FOR ALL policy is split, so reading keeps its
 * rule. With no owner column to use, the fix is a commented block to fill in.
 */
function ownerFix(p: Policy, pick: OwnerPick, taken: Set<string>): Pick<Finding, 'fix' | 'edits' | 'manual'> {
  // With no column at all, the fix to fill in adds one called user_id, which can be empty.
  const owner: Owner = pick.owner ?? { column: pick.none ? 'user_id' : '<owner column>', caller: UID, nullable: !!pick.none, who: 'id' };
  // Adding or changing a row in a members or roles table is how people get access: the row being theirs isn't enough.
  if (ACCESS_TABLE.test(p.table) && p.command !== 'delete' && pick.owner) return accessTableFix(p, owner);
  const test = pick.suggest?.test ?? `${owner.caller} = ${owner.column}`;
  const insertClause = clauseFor(p, 'insert');
  // Signed-out visitors can add rows now. If the owner column can be empty, they still can, as nobody.
  const anonInsert =
    (p.command === 'insert' || p.command === 'all') && appliesTo(p, 'anon') && loose(insertClause) && classify(insertClause, 'anon') !== 'none';
  const insertTest = anonInsert && owner.nullable ? `${owner.column} is null or ${test}` : test;
  const tighten = (expr: Expr | undefined, t: string) => {
    if (!expr) return t;
    const tokens = unwrap(expr.tokens);
    // Only true or a sign-in check: the owner test takes its place.
    if (splitTop(tokens, 'or').length === 1) return t;
    return `(${fixText(tokens)}) and ${t === test ? t : `(${t})`}`;
  };
  const notes: string[] = [];
  const edit = policyEdit(p, 'security');
  if (p.command === 'insert') edit.check = tighten(p.check, insertTest);
  else if (p.command === 'update') {
    if (loose(p.using)) edit.using = tighten(p.using, test);
    if (p.check ? loose(p.check) : edit.using !== undefined) edit.check = p.check ? tighten(p.check, test) : edit.using;
  } else if (p.command === 'delete') edit.using = tighten(p.using, test);
  else if (p.command === 'all') {
    // Postgres reads a missing WITH CHECK as the USING clause.
    const keep = (e: Expr | undefined) => e && fixText(e.tokens);
    const write = (e: Expr | undefined, t: string) => (loose(e) ? tighten(e, t) : keep(e));
    const insert = write(p.check ?? p.using, insertTest);
    const update = write(p.using, test);
    const updateCheck = p.check ? write(p.check, test) : update;
    const remove = write(p.using, test);
    const free = (word: string) => {
      let name = pgName(p.name, ` (${word})`);
      for (let i = 2; taken.has(name); i += 1) name = pgName(p.name, ` (${word} ${i})`);
      return name;
    };
    const create = (name: string, command: Command, using?: string, check?: string) =>
      createPolicySql(p.schema, p.table, name, command, rolesFor(p.roles, using, check), using, check, name !== p.name);
    edit.replaceWith = [
      // The policy's own name now holds only the read rule. fixScript drops the old policy just before.
      create(p.name, 'select', keep(p.using)),
      create(free('insert'), 'insert', undefined, insert),
      create(free('update'), 'update', update, updateCheck),
      create(free('delete'), 'delete', remove),
    ].join('\n');
    notes.push('Split by command: reading keeps its rule, and adding, changing and deleting need the row to be the user’s.');
    if ((mentionsUserMetadata(p.using) || mentionsUserMetadata(p.check)) && appMetadata(p.using?.tokens ?? []) && appMetadata(p.check?.tokens ?? [])) {
      notes.push(`It reads app_metadata instead of user_metadata. ${appMetadataNote([...(p.using?.tokens ?? []), ...(p.check?.tokens ?? [])])}`);
    }
  }
  if (p.command !== 'all') {
    // What changes for signed-in users, in plain words.
    const changes = (c: Command) =>
      c === 'insert' ? edit.check !== undefined && insertTest === test : c === 'update' ? (edit.using ?? edit.check) !== undefined : c === 'delete' && edit.using !== undefined;
    const changed = COMMANDS.filter((c) => covers(p, c) && changes(c));
    const theirs = owner.who === 'email' ? 'their email' : 'their user id';
    if (changed.length > 0) notes.push(`After this, users can only ${andList(changed.map((c) => VERB[c]))} rows where ${owner.column} is ${theirs}.`);
  }
  // An insert policy that lets signed-out visitors in, with an owner they can't leave empty, needs a decision.
  const formOnly = anonInsert && p.command === 'insert';
  if (anonInsert && pick.owner && (owner.nullable || !formOnly)) {
    notes.push(owner.nullable ? `Signed-out visitors can still add rows, with ${owner.column} left empty.` : 'Signed-out visitors can’t add rows after this.');
  }
  if (notes.length > 0) edit.note = notes.join('\n');
  if (pick.owner && !(formOnly && !owner.nullable)) return policyFix([edit]);
  if (pick.owner) {
    const why = [
      `Signed-out visitors can add rows through this policy. After this fix they can’t, because ${owner.column} can’t be empty.`,
      'Run it only if they shouldn’t add rows here.',
    ];
    return { manual: true, fix: commentOut(`${commentLines(why.join('\n'))}\n${policySql(edit)}`) };
  }
  // No owner to use: the notes above describe a fix that isn't there yet.
  edit.note = undefined;
  const q = qualifiedName(p.schema, p.table);
  const why = [
    `The checker can’t tie these rows to a user. ${pick.reason}`,
    ...(formOnly ? ['If anyone may add rows here, as with a contact form or a waitlist,', 'leave this policy as it is.'] : []),
    ...(pick.none
      ? anonInsert
        ? ['To give each row an owner, add a column for it, then tie the policy to it.', 'Signed-out visitors can still add rows then, with user_id left empty:']
        : ['To give each row an owner, add a column for it, then tie the policy to it:']
      : pick.suggest
        ? [`If ${pick.suggest.via} holds each profile’s user, this ties rows to it. Check that, then run:`]
        : ['Put the owner column in place of <owner column>, then run:']),
  ];
  const add = pick.none ? `alter table ${q} add column if not exists user_id uuid default auth.uid() references auth.users (id);\n` : '';
  return { manual: true, fix: commentOut(`${commentLines(why.join('\n'))}\n${add}${policySql(edit)}`) };
}

/**
 * For a table whose rows give people access, such as team members or user
 * roles: a commented block to fill in. Tying a new row to the user who adds
 * it would still let anyone add themselves, with any role, and stop them
 * adding anyone else.
 */
function accessTableFix(p: Policy, owner: Owner): Pick<Finding, 'fix' | 'manual'> {
  const why = [
    `Rows in ${qualifiedName(p.schema, p.table)} give people access, such as a place in a team or a role.`,
    `Requiring ${owner.column} to be the user’s own isn’t enough: anyone could still add`,
    'themselves, with any role, and nobody could add anyone else. Write a condition',
    'that checks the user may manage it, such as being an admin of the team, then run:',
  ];
  const edit = policyEdit(p, 'security');
  if (p.command !== 'insert') edit.using = '<your condition>';
  if (p.command !== 'delete') edit.check = '<your condition>';
  return { manual: true, fix: commentOut(`${commentLines(why.join('\n'))}\n${policySql(edit)}`) };
}

/** A policy's roles without public when its conditions never let signed-out visitors through anyway. */
function rolesFor(roles: string[], ...conditions: (string | undefined)[]): string[] {
  const given = conditions.filter((c): c is string => c !== undefined);
  const needsUser = given.length > 0 && given.every((c) => classify({ tokens: tokenize(c) }, 'anon') === 'none');
  return roles.length === 1 && roles[0] === 'public' && needsUser ? ['authenticated'] : roles;
}

/** CREATE POLICY as a fix writes it, after a drop so the script can run twice. */
function createPolicySql(
  schema: string,
  table: string,
  name: string,
  command: Command,
  roles: string[],
  using?: string,
  check?: string,
  drop = true,
): string {
  const target = `${identifier(name)} on ${qualifiedName(schema, table)}`;
  const lines = [
    drop ? `drop policy if exists ${target};` : '',
    `create policy ${target} for ${command}`,
    `  to ${roles.map(roleName).join(', ')}`,
    using !== undefined ? `  using (${using})` : '',
    check !== undefined ? `  with check (${check})` : '',
  ];
  return `${lines.filter(Boolean).join('\n')};`;
}

/** "a, b or c" */
const orList = (items: string[]) => (items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} or ${items.at(-1)}`);
/** "a, b and c" */
const andList = (items: string[]) => (items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`);

/**
 * What goes with turning RLS on. A table with policies: what they leave out.
 * Without: policies for each signed-in user's own rows when the owner column
 * is known, or else a plain warning and a commented example.
 */
function rlsOnFix(rel: Relation, policies: Policy[], relations?: Map<string, Relation>): string {
  if (policies.length > 0) {
    const reached = (c: Command) =>
      policies.some((p) => p.permissive && covers(p, c) && !!clauseFor(p, c) && (appliesTo(p, 'anon') || appliesTo(p, 'authenticated')));
    const missing = COMMANDS.filter((c) => !reached(c)).map((c) => VERB[c]);
    const lines = ['Its policies take effect now. Any fixes they need are in this script too.'];
    if (missing.length > 0) lines.push(`No policy lets the app ${orList(missing)} rows here, so it can’t until you add one.`);
    return commentLines(lines.join('\n'));
  }
  const pick = ownerOf(rel, [], relations);
  if (pick.owner) {
    const test = `${pick.owner.caller} = ${pick.owner.column}`;
    const own = (c: Command) =>
      createPolicySql(rel.schema, rel.name, pgName(rel.name, `_${c}_own`), c, ['authenticated'], c === 'insert' ? undefined : test, c === 'insert' || c === 'update' ? test : undefined);
    return [
      '-- With RLS on, the app reaches only the rows a policy allows. These let each',
      '-- signed-in user read, add, change and delete their own rows. If other users',
      '-- should see these rows, change the select policy (Generate policies writes the full set).',
      ...COMMANDS.map(own),
    ].join('\n');
  }
  const example = createPolicySql(rel.schema, rel.name, pgName(rel.name, '_select'), 'select', ['authenticated'], 'true', undefined, false);
  return [
    '-- After this, the Data API returns no rows from it, and can’t change it, until you',
    '-- add policies. That’s right if only server code uses it.',
    `-- The checker can’t add policies for each user’s own rows. ${comment(pick.reason)}`,
    '-- Add one for each thing the app does. For example, so signed-in users can read',
    '-- every row:',
    commentOut(example),
  ].join('\n');
}

// ---------------------------------------------------------------------------
// Policy edits

const policyEdit = (p: { schema: string; table: string; name: string }, priority: PolicyEdit['priority']): PolicyEdit => ({
  kind: 'policy',
  schema: p.schema,
  table: p.table,
  name: p.name,
  priority,
});

/** A role in TO: public is a keyword there, so it stays bare. */
const roleName = (role: string) => (role === 'public' ? 'public' : identifier(role));

/** Text as SQL comment lines, whatever it holds. */
const commentLines = (text: string) =>
  text
    .split('\n')
    .map((line) => `-- ${comment(line)}`.trimEnd())
    .join('\n');

/** SQL with every line that isn't a comment already turned into one. A carriage return ends a comment too. */
const commentOut = (sql: string) =>
  sql
    .split(/\r\n|\r|\n/)
    .map((line) => (line.trimStart().startsWith('--') ? line : `-- ${line}`.trimEnd()))
    .join('\n');

/** One policy change as SQL on its own. Safe to run twice: a drop says if exists. */
function policySql(e: PolicyEdit): string {
  const target = `${identifier(e.name)} on ${qualifiedName(e.schema, e.table)}`;
  const note = e.note ? `${commentLines(e.note)}\n` : '';
  if (e.drop) return `${note}drop policy if exists ${target};`;
  if (e.replaceWith !== undefined) return `${note}drop policy if exists ${target};\n${e.replaceWith}`;
  const parts = [
    e.roles ? `to ${e.roles.map(roleName).join(', ')}` : '',
    e.using !== undefined ? `using (${e.using})` : '',
    e.check !== undefined ? `with check (${e.check})` : '',
  ].filter(Boolean);
  if (parts.length === 0) return note.trimEnd();
  return `${note}alter policy ${target}\n  ${parts.join('\n  ')};`;
}

/** A finding's fix and edits, from its policy changes. */
const policyFix = (edits: PolicyEdit[]) => ({ fix: edits.map(policySql).join('\n'), edits });

/** A condition with each auth call that isn't wrapped yet written as (select ...). */
function wrapAuthCalls(condition: string): string {
  const tokens = tokenize(condition);
  const calls = authCalls(tokens);
  return calls.some((c) => !c.wrapped) ? wrapCalls(tokens, calls) : condition;
}

/**
 * Every change to one policy as one: a drop beats a replacement, which beats
 * an alter. In an alter, a security rewrite of a clause beats a speed rewrite,
 * and the speed fix's wrapping is applied to the clause that wins. Roles
 * changes join the same alter.
 */
function mergePolicyEdits(edits: PolicyEdit[]): PolicyEdit {
  const security = edits.filter((e) => e.priority === 'security');
  const speed = edits.filter((e) => e.priority === 'speed');
  const ranked = [...security, ...speed];
  const base = policyEdit(edits[0], security.length > 0 ? 'security' : 'speed');
  const notes = (list: PolicyEdit[]) => [...new Set(list.map((e) => e.note).filter((n): n is string => !!n))].join('\n') || undefined;

  const drops = ranked.filter((e) => e.drop);
  if (drops.length > 0) return { ...base, drop: true, note: notes(drops) };
  const replacement = ranked.find((e) => e.replaceWith !== undefined);
  if (replacement) return { ...base, replaceWith: replacement.replaceWith, note: replacement.note };

  const wrap = speed.some((e) => e.using !== undefined || e.check !== undefined);
  const clause = (pick: (e: PolicyEdit) => string | undefined): string | undefined => {
    const all = [...new Set(security.map(pick).filter((c): c is string => c !== undefined))];
    // A rewrite that another one already keeps, with more ANDed on (as the owner fix does), adds nothing.
    const rewrites = all.filter((c) => !all.some((other) => other.startsWith(`(${c}) and `)));
    if (rewrites.length === 0) return speed.map(pick).find((c) => c !== undefined);
    // Two security rewrites of one clause both hold: joined with AND, no more rows get through than with either.
    const text = rewrites.length === 1 ? rewrites[0] : rewrites.map((c) => `(${c})`).join(' and ');
    return wrap ? wrapAuthCalls(text) : text;
  };
  return {
    ...base,
    using: clause((e) => e.using),
    check: clause((e) => e.check),
    roles: (security.find((e) => e.roles) ?? speed.find((e) => e.roles))?.roles,
    note: notes(ranked),
  };
}

// ---------------------------------------------------------------------------
// Function edits

/** Text as an SQL string literal. */
const literal = (text: string) => `'${text.replace(/'/g, "''")}'`;

/** The search_path a fix pins: names without a schema still find what they found before, and pg_temp can't go first. */
const SEARCH_PATH = 'public, extensions, pg_temp';

const SEARCH_PATH_NOTE =
  'Names in it without a schema still find public and extensions. Once every name in it\nhas its schema, such as public.profiles, search_path = \'\' is stricter.';

/** Where helpers that policies call go: a schema the API doesn't serve. */
const HELPER_SCHEMAS = ['private', 'app_private'];

const functionTarget = (e: { schema: string; name: string; args: string }) => `${qualifiedName(e.schema, e.name)}(${e.args})`;

/** How many arguments a signature's type list has: "uuid, app_role" has two. */
const argCount = (args: string) => (args.trim() === '' ? 0 : commaSplit(tokenize(args)).length);

/** How many arguments the call whose ( is at tokens[open] passes. */
function argCountAt(tokens: Token[], open: number, match: Int32Array): number {
  const close = match[open] === -1 ? tokens.length : match[open];
  return close === open + 1 ? 0 : commaSplit(tokens.slice(open + 1, close)).length;
}

/** A dollar-quote tag that doesn't occur in the body. */
function dollarTag(body: string): string {
  let tag = '$fix$';
  for (let i = 2; body.includes(tag); i += 1) tag = `$fix${i}$`;
  return tag;
}

/**
 * One function change as SQL on its own. Safe to run twice: a move checks the
 * function is still where it was. `schema` false leaves out creating the
 * schema it moves to, for a script that does that once for every move.
 */
function functionSql(e: FunctionEdit, schema = true): string {
  const target = functionTarget(e);
  const lines = e.note ? [commentLines(e.note)] : [];
  const searchPath = e.searchPath ? `alter function ${target} set search_path = ${e.searchPath};` : '';
  if (e.moveTo) {
    const body = [
      'begin',
      '  -- Skipped once it has moved, so the script can run again.',
      `  if to_regprocedure(${literal(target)}) is not null then`,
      ...(searchPath ? [`    ${searchPath}`] : []),
      `    alter function ${target} set schema ${identifier(e.moveTo)};`,
      '  end if;',
      'end',
    ].join('\n');
    const tag = dollarTag(body);
    if (schema) lines.push(`create schema if not exists ${identifier(e.moveTo)};`);
    lines.push(`do ${tag}\n${body}\n${tag};`);
  } else {
    if (searchPath) lines.push(searchPath);
    if (e.revokeFrom && e.revokeFrom.length > 0) lines.push(`revoke execute on function ${target} from ${e.revokeFrom.map(roleName).join(', ')};`);
  }
  if (e.optional) lines.push(commentOut(e.optional));
  return lines.join('\n');
}

/** A finding's fix and edits, from its function changes. */
const functionFix = (edits: FunctionEdit[]) => ({ fix: edits.map((e) => functionSql(e)).join('\n'), edits });

/** Every change to one function as one: a move makes a revoke unneeded, since the API can't reach it there. */
function mergeFunctionEdits(edits: FunctionEdit[]): FunctionEdit {
  const { schema, name, args } = edits[0];
  const moveTo = edits.find((e) => e.moveTo)?.moveTo;
  const revokeFrom = [...new Set(edits.flatMap((e) => e.revokeFrom ?? []))];
  const notes = [...new Set(edits.map((e) => e.note).filter((n): n is string => !!n))];
  return {
    kind: 'function',
    schema,
    name,
    args,
    searchPath: edits.find((e) => e.searchPath)?.searchPath,
    moveTo,
    callArgs: edits.find((e) => e.moveTo)?.callArgs,
    revokeFrom: moveTo || revokeFrom.length === 0 ? undefined : revokeFrom,
    optional: moveTo ? undefined : edits.find((e) => e.optional)?.optional,
    note: notes.join('\n') || undefined,
  };
}

/** Whether tokens[i] names the function in a call: with its schema, or alone for one in public. */
function callAt(tokens: Token[], i: number, fn: { schema: string; name: string }): boolean {
  const t = tokens[i];
  if (!isName(t) || t.value !== fn.name || !isOp(tokens[i + 1], '(')) return false;
  if (!isOp(tokens[i - 1], '.')) return fn.schema === 'public';
  return isName(tokens[i - 2]) && tokens[i - 2].value === fn.schema && !isOp(tokens[i - 3], '.');
}


/**
 * SQL with each call to a function that moves written with its new schema,
 * as the script needs once the move has run. Everything else, comments and
 * strings included, stays exactly as it was.
 */
function renameCalls(sql: string, moved: FunctionEdit[], used?: Set<FunctionEdit>): string {
  if (moved.length === 0) return sql;
  const tokens = tokenize(sql);
  const match = pairs(tokens);
  let out = '';
  let at = 0;
  for (let i = 0; i < tokens.length; i += 1) {
    // Another function with the same name and a different number of arguments stays where it is.
    const fn = moved.find((m) => callAt(tokens, i, m) && (m.callArgs === undefined || argCountAt(tokens, i + 1, match) === m.callArgs));
    if (!fn) continue;
    used?.add(fn);
    const start = (isOp(tokens[i - 1], '.') ? tokens[i - 2] : tokens[i]).offset!;
    out += `${sql.slice(at, start)}${identifier(fn.moveTo!)}.${identifier(fn.name)}`;
    at = tokens[i].offset! + tokens[i].text.length;
  }
  return out + sql.slice(at);
}

// Words that end a FROM item, so they aren't read as its alias.
const FROM_ENDS = new Set([
  'where', 'group', 'order', 'limit', 'offset', 'fetch', 'having', 'window', 'join', 'inner', 'left', 'right', 'full',
  'cross', 'natural', 'on', 'using', 'union', 'except', 'intersect', 'for', 'tablesample', 'lateral', 'with', 'returning',
]);
// Words before a parenthesis that aren't function calls, so a FROM inside still counts.
const NOT_CALLS = new Set(['in', 'exists', 'any', 'all', 'some', 'from', 'join', 'lateral', 'as', 'on', 'and', 'or', 'not', 'where', 'when', 'then', 'else', 'using', 'array', 'union', 'except', 'intersect']);

/**
 * The tables a view's query reads, from each FROM and JOIN, as [schema, name]
 * with no schema when the query names none. `unknown` when something it reads
 * isn't a plain name, such as a function, so the list may be short.
 */
function viewReads(tokens: Token[]): { tables: [string | undefined, string][]; unknown: boolean } {
  const match = pairs(tokens);
  const tables: [string | undefined, string][] = [];
  let unknown = false;
  // Names WITH gives to its queries aren't tables.
  const named = new Set(tokens.filter((t, i) => isName(t) && isWord(tokens[i + 1], 'as') && (isOp(tokens[i + 2], '(') || isWord(tokens[i + 2], 'materialized', 'not'))).map((t) => t.value));

  // A comma-separated FROM list, starting at j.
  const readItems = (j: number) => {
    for (let guard = 0; guard < tokens.length && j < tokens.length; guard += 1) {
      // (a join b on ...): the names inside are read here and at each JOIN.
      while (isOp(tokens[j], '(') && !isWord(tokens[j + 1], 'select', 'with', 'values')) j += 1;
      while (isWord(tokens[j], 'only', 'lateral')) j += 1;
      if (isOp(tokens[j], '(')) j = match[j] === -1 ? tokens.length : match[j] + 1; // a subquery: its own FROMs are read where they are
      else if (isName(tokens[j]) && !(tokens[j].kind === 'word' && FROM_ENDS.has(tokens[j].value))) {
        let schema: string | undefined;
        let table = tokens[j].value;
        if (isOp(tokens[j + 1], '.') && isName(tokens[j + 2])) {
          schema = table;
          table = tokens[j + 2].value;
          j += 2;
        }
        j += 1;
        if (isOp(tokens[j], '(')) {
          unknown = true;
          j = match[j] === -1 ? tokens.length : match[j] + 1;
        } else if (schema !== undefined || !named.has(table)) tables.push([schema, table]);
      } else return;
      if (isWord(tokens[j], 'as')) j += 1;
      if (isName(tokens[j]) && !(tokens[j].kind === 'word' && FROM_ENDS.has(tokens[j].value))) {
        j += 1;
        if (isOp(tokens[j], '(')) j = match[j] === -1 ? tokens.length : match[j] + 1;
      }
      if (!isOp(tokens[j], ',')) return;
      j += 1;
    }
  };

  // What each open parenthesis is: a function call's arguments, where FROM means something else, or not.
  const calls: boolean[] = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (isOp(t, '(')) {
      const prev = tokens[i - 1];
      calls.push(isName(prev) && !(prev.kind === 'word' && NOT_CALLS.has(prev.value)) && !isWord(tokens[i + 1], 'select', 'with', 'values'));
    } else if (isOp(t, ')')) calls.pop();
    else if (isWord(t, 'from', 'join') && !calls.at(-1)) {
      // a is distinct from b
      if (isWord(t, 'from') && isWord(tokens[i - 1], 'distinct')) continue;
      readItems(i + 1);
    }
  }
  return { tables, unknown };
}

/**
 * When a Storage condition ties a file to nothing but its bucket, the bucket
 * and whether it also asks for a sign-in; otherwise undefined. Parts joined by
 * AND may each be the bucket test, always true, or a sign-in check.
 */
function storageScope(expr: Expr | undefined): { bucket?: string; signedIn: boolean } | undefined {
  // Without the clause, the policy lets nothing through.
  if (!expr) return undefined;
  let bucket: string | undefined;
  let signedIn = false;
  for (const part of splitTop(unwrap(expr.tokens), 'and')) {
    const truth = truthOf(part);
    if (truth === 'true') continue;
    if (truth === 'signed') {
      signedIn = true;
      continue;
    }
    const test = /^bucket_id='((?:[^']|'')*)'$/.exec(core(part));
    if (!test || bucket !== undefined) return undefined;
    bucket = test[1].replace(/''/g, "'");
  }
  return { bucket, signedIn };
}

/** The most text one check reads, so a huge paste can't freeze the page. */
export const MAX_INPUT = 5_000_000;

/** Checks a pasted schema: SQL, or the JSON CATALOG_QUERY returns. */
export function lintSupabase(input: string): LintResult {
  return lintCatalog(readSchema(input));
}

/** What a pasted schema holds, read from SQL or from the JSON CATALOG_QUERY returns. */
export function readSchema(input: string): Catalog {
  const trimmed = input.trim();
  if (trimmed === '') throw new Error('Paste SQL or the JSON the query returns.');
  if (trimmed.length > MAX_INPUT) {
    throw new Error(
      `That’s ${trimmed.length.toLocaleString('en-US')} characters. Paste up to ${MAX_INPUT.toLocaleString('en-US')} at a time: split a big dump, or use the catalog query, which is much smaller.`,
    );
  }
  const looksJson = /^[[{"]/.test(trimmed) || /"supabase_rls_check"/.test(trimmed.slice(0, 400));
  return looksJson ? readJson(trimmed) : readSql(trimmed);
}

export function lintCatalog(catalog: Catalog): LintResult {
  const findings: Finding[] = [];
  const exposed = (schema: string) => catalog.exposed.includes(schema) && !SYSTEM_SCHEMAS.has(schema);
  const policiesOn = (rel: { schema: string; name: string }) =>
    catalog.policies.filter((p) => p.schema === rel.schema && p.table === rel.name);
  const reachable = (rel: Relation) =>
    !rel.grants || COMMANDS.some((c) => rel.grants!.anon.has(c) || rel.grants!.authenticated.has(c));
  const selectable = (rel: Relation) => !rel.grants || rel.grants.anon.has('select') || rel.grants.authenticated.has('select');
  const name = (schema: string, table: string) => qualifiedName(schema, table);
  const add = (f: Finding) => findings.push(f);

  /**
   * Why a view would break with the caller's rights, or undefined when it
   * won't: each table it reads must be one the checker sees, in an exposed
   * schema, with RLS on, and a grant and a select policy for each API role
   * that reads the view.
   */
  const invokerBlocker = (view: Relation): string | undefined => {
    if (!view.query) return 'The checker can’t see its query.';
    const reads = viewReads(view.query);
    if (reads.unknown) return 'It reads something other than a table, such as a function, so the checker can’t tell.';
    const roles = (['anon', 'authenticated'] as const).filter((r) => !view.grants || view.grants[r].has('select'));
    for (const [schema, table] of reads.tables) {
      // A name without a schema was looked up in public, as the SQL Editor does.
      const base = catalog.relations.get(key(schema ?? 'public', table));
      const bq = name(schema ?? 'public', table);
      if (!base) return `It reads ${bq}, which the checker can’t see.`;
      if (!exposed(base.schema)) return `It reads ${bq}, in a schema the API doesn’t serve.`;
      if (base.kind !== 'table') return `It reads ${bq}, which isn’t a table.`;
      if (!base.rls) return `It reads ${bq}, which has RLS off.`;
      for (const role of roles) {
        const who = role === 'anon' ? 'signed-out visitors' : 'signed-in users';
        if (base.grants && !base.grants[role].has('select')) return `It reads ${bq}, and ${who} have no grant to read it.`;
        const policies = policiesOn(base).filter((p) => p.permissive && covers(p, 'select') && appliesTo(p, role));
        if (policies.length === 0) return `It reads ${bq}, which has no select policy for ${who}.`;
        // An own-rows policy applies to signed-out visitors too, but never lets them read a row.
        if (policies.every((p) => classify(p.using, role) === 'none')) return `It reads ${bq}, whose select policies never let ${who} read it.`;
      }
    }
    return undefined;
  };

  const relations = [...catalog.relations.values()];
  const tables: TableReport[] = [];

  for (const rel of relations) {
    if (!exposed(rel.schema)) continue;
    // Only altered here, without saying whether RLS is on: nothing to report.
    if (!rel.created && !rel.rlsKnown) continue;
    const q = name(rel.schema, rel.name);
    const policies = policiesOn(rel);
    const sensitive = sensitiveColumns(rel.columns);

    if (rel.kind === 'table') {
      if (!rel.rls) {
        const open = reachable(rel);
        const lints = ['0013'];
        if (policies.length > 0) lints.push('0007');
        if (sensitive.length > 0) lints.push('0023');
        const parts = [
          open
            ? 'Anyone with your project’s public key can read, add, change and delete every row through the Data API. Row-level security is what stops them, and it’s off.'
            : 'The API roles have no grants on it right now, so the Data API can’t reach it. Turn RLS on anyway, so a later grant doesn’t open it.',
        ];
        if (sensitive.length > 0) parts.push(`It has columns that look sensitive: ${sensitive.join(', ')}.`);
        if (policies.length > 0) parts.push(`It has ${policies.length} ${policies.length === 1 ? 'policy' : 'policies'}, but policies do nothing until RLS is on.`);
        if (rel.realtime) parts.push('It’s also published to Realtime, which sends its changes to subscribers.');
        if (open && !rel.grants && catalog.source === 'sql') parts.push('This assumes Supabase’s default grants, since the SQL doesn’t set any.');
        add({
          id: 'rls_disabled_in_public',
          severity: open ? 'error' : 'note',
          category: 'security',
          lints,
          title: open
            ? `${q} is open to everyone${sensitive.length > 0 ? `, including ${sensitive.slice(0, 3).join(', ')}` : ''}`
            : `RLS is off on ${q}`,
          object: q,
          line: rel.line,
          detail: parts.join(' '),
          fix: `alter table ${q} enable row level security;\n${rlsOnFix(rel, policies, catalog.relations)}`,
        });
      } else if (policies.length === 0 && rel.created && catalog.opaque.length === 0) {
        add({
          id: 'rls_enabled_no_policy',
          severity: 'note',
          category: 'security',
          lints: ['0008'],
          title: `Nobody can reach ${q} from the browser`,
          object: q,
          line: rel.line,
          detail:
            'RLS is on and there are no policies, so only server code using a secret key can use it. That’s right for internal tables. If your app reads it from the browser, it gets no rows and no error.',
        });
      }
    }

    if (rel.kind === 'view') {
      const readsAuthUsers = !!rel.query && rel.query.some((t, i, all) => t.value === 'auth' && isOp(all[i + 1], '.') && all[i + 2]?.value === 'users');
      if (readsAuthUsers && reachable(rel)) {
        add({
          id: 'auth_users_exposed',
          severity: 'error',
          category: 'security',
          lints: ['0002'],
          title: `${q} exposes auth.users`,
          object: q,
          line: rel.line,
          detail:
            'This view reads Supabase Auth’s users table, with emails, phone numbers and sign-in details, and the Data API can serve it. A simple view like this takes inserts, updates and deletes too, which change auth.users. Keep it out of exposed schemas, or select only what the app needs from your own profiles table.',
          // PUBLIC too: a grant to it reaches anon and authenticated.
          fix: [
            '-- After this, the Data API stops serving it, so the app gets “permission denied”',
            '-- where it reads it. If the app needs some of these columns, keep them in your',
            '-- own profiles table and read that instead.',
            `revoke all on ${q} from public, anon, authenticated;`,
            `-- Or move it out of the API: create schema if not exists private; alter view ${q} set schema private;`,
          ].join('\n'),
        });
      } else if (!readsAuthUsers && !rel.securityInvoker && selectable(rel)) {
        const blocked = invokerBlocker(rel);
        const alter = `alter view ${q} set (security_invoker = true);`;
        const reads = rel.query ? viewReads(rel.query).tables.length > 0 : false;
        const finding: Finding = {
          id: 'security_definer_view',
          severity: 'error',
          category: 'security',
          lints: ['0010'],
          title: `${q} skips the policies on the tables it reads`,
          object: q,
          line: rel.line,
          detail:
            'A view runs with its owner’s rights unless it’s created with security_invoker, and the owner is usually postgres, which isn’t held back by RLS. So anyone who can read the view sees every row it selects.',
        };
        if (!blocked) {
          add({ ...finding, fix: reads ? `-- From now on it shows each caller only the rows the policies on its tables let them read.\n${alter}` : alter });
        } else {
          const why = [
            'With security_invoker on, the view runs with the caller’s rights, so they need',
            'a grant and a select policy on each table it reads.',
            blocked,
            'Add those first, then run this. If the view shares only safe columns on purpose,',
            'you can keep it as it is.',
          ];
          add({ ...finding, manual: true, fix: commentOut(`${commentLines(why.join('\n'))}\n${alter}`) });
        }
      }
    }

    if (rel.kind === 'matview' && selectable(rel)) {
      add({
        id: 'materialized_view_in_api',
        severity: 'warning',
        category: 'security',
        lints: ['0016'],
        title: `${q} has no row-level security`,
        object: q,
        line: rel.line,
        detail: 'Materialized views can’t have RLS, so the Data API serves every row to anyone who can select it.',
        fix: [
          '-- After this, the Data API stops serving it, so the app gets an error where it',
          '-- reads it. If the app needs it, move it to a schema the API doesn’t serve, and',
          '-- read it through a security definer function that returns only what each user',
          '-- may see.',
          `revoke select on ${q} from public, anon, authenticated;`,
        ].join('\n'),
      });
    }

    if (rel.kind === 'foreign' && reachable(rel)) {
      const can = COMMANDS.filter((c) => !rel.grants || rel.grants.anon.has(c) || rel.grants.authenticated.has(c)).map((c) => VERB[c]);
      add({
        id: 'foreign_table_in_api',
        severity: 'warning',
        category: 'security',
        lints: ['0017'],
        title: `${q} has no row-level security`,
        object: q,
        line: rel.line,
        detail: `Foreign tables ignore RLS, so the Data API lets anyone with a grant ${andList(can)} every row.`,
        fix: `-- After this, the Data API stops serving it.\nrevoke all on ${q} from public, anon, authenticated;`,
      });
    }

    tables.push({
      schema: rel.schema,
      name: rel.name,
      kind: rel.kind,
      rls: rel.kind === 'table' ? rel.rls : false,
      reachable: reachable(rel),
      grantsAssumed: !rel.grants,
      policies: policies.length,
      partial: !rel.created,
      access: Object.fromEntries(
        COMMANDS.map((c) => [c, { anon: reachOf(rel, policies, c, 'anon'), authenticated: reachOf(rel, policies, c, 'authenticated') }]),
      ) as TableReport['access'],
    });
  }

  // Policies, table by table.
  const byTable = new Map<string, Policy[]>();
  for (const p of catalog.policies) {
    const list = byTable.get(key(p.schema, p.table)) ?? [];
    list.push(p);
    byTable.set(key(p.schema, p.table), list);
  }

  for (const [tableKey, policies] of byTable) {
    const [schema, table] = [policies[0].schema, policies[0].table];
    const rel = catalog.relations.get(tableKey);
    const storage = schema === 'storage' && table === 'objects';
    // Policies on a table with RLS off are checked too: turning RLS on, its fix, puts them to work.
    if (!storage && !exposed(schema)) continue;
    const q = name(schema, table);
    const noRole: Policy[] = [];
    const owner = ownerOf(rel, policies, catalog.relations);
    const taken = new Set(policies.map((p) => p.name));

    for (const p of policies) {
      const pq = `${identifier(p.name)} on ${q}`;
      const commands: Command[] = p.command === 'all' ? COMMANDS : [p.command];
      const anon = appliesTo(p, 'anon');
      const authed = appliesTo(p, 'authenticated');
      const who = anon ? 'Anyone, signed in or not,' : 'Every signed-in user';

      if (mentionsUserMetadata(p.using) || mentionsUserMetadata(p.check)) {
        // Only the clauses that read it, and only ones the command takes: INSERT has no USING.
        const using = p.command !== 'insert' && mentionsUserMetadata(p.using) ? p.using : undefined;
        const check = p.command !== 'select' && p.command !== 'delete' && mentionsUserMetadata(p.check) ? p.check : undefined;
        const swapped = (using || check) && [using, check].every((e) => !e || appMetadata(e.tokens));
        const finding: Finding = {
          id: 'rls_references_user_metadata',
          severity: 'error',
          category: 'security',
          lints: ['0015'],
          title: `${identifier(p.name)} trusts user_metadata`,
          object: q,
          line: p.line,
          detail:
            'Users can change their own user_metadata from the browser with updateUser(), so a policy that reads a role or a team from it lets anyone give themselves access. Keep roles in app_metadata, which only server code can set, or in a table users can’t write.',
        };
        if (swapped) {
          // The same claim from app_metadata. Until server code sets it, the policy lets nobody through.
          const edit = { ...policyEdit(p, 'security'), using: using && fixText(using.tokens), check: check && fixText(check.tokens) };
          const note = appMetadataNote([...(using?.tokens ?? []), ...(check?.tokens ?? [])]);
          add({ ...finding, ...policyFix([{ ...edit, note }]) });
        } else {
          const clauses = [...(using ? ['using (<your condition>)'] : []), ...(check ? ['with check (<your condition>)'] : [])];
          // A claim that shuts people out, such as banned: swapped as it is, a user without it gets in.
          const opens = [using, check].some((e) => e && !failsClosed(e.tokens));
          add({
            ...finding,
            manual: true,
            fix: commentOut(
              [
                ...(opens
                  ? [
                      '-- It shuts people out when the claim says so. Read from app_metadata as it is, it',
                      '-- would let everyone in until server code sets the claim, so write it for that too.',
                    ]
                  : []),
                '-- Write the condition with app_metadata, which only server code can set, for example:',
                "--   (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'",
                '-- Set that claim for each user first, or they lose access. Then run:',
                `alter policy ${pq}`,
                ...clauses.map((c) => `  ${c}`),
              ].join('\n') + ';',
            ),
          });
        }
      }

      if (!storage && p.permissive && (anon || authed)) {
        const writes = commands.filter((c) => c !== 'select');
        // An update with a USING that finds rows, and a WITH CHECK that lets them become anything.
        const openWrites = writes.filter((c) => alwaysTrue(clauseFor(p, c)) || (c === 'update' && !!p.using && alwaysTrue(p.check)));
        if (openWrites.length > 0) {
          const destructive = openWrites.some((c) => c !== 'insert');
          add({
            id: 'rls_policy_always_true',
            severity: anon && destructive ? 'error' : 'warning',
            category: 'security',
            lints: ['0024'],
            title: `${who} can ${openWrites.map((c) => VERB[c]).join(', ')} any row in ${q}`,
            object: q,
            line: p.line,
            detail: `${identifier(p.name)} lets ${openWrites.join(', ')} through with a condition that’s always true${anon ? ', and it applies to signed-out visitors' : ''}. ${
              openWrites.includes('insert') ? 'New rows can claim to belong to anyone. ' : ''
            }Tie writes to the caller, such as (select auth.uid()) = user_id.`,
            ...ownerFix(p, owner, taken),
          });
        } else {
          const signedIn = writes.filter((c) => signedInOnly(clauseFor(p, c)));
          if (signedIn.length > 0) {
            add({
              id: 'signed_in_writes_any_row',
              severity: 'warning',
              category: 'security',
              lints: [],
              title: `Every signed-in user can ${signedIn.map((c) => VERB[c]).join(', ')} any row in ${q}`,
              object: q,
              line: p.line,
              detail: `${identifier(p.name)} only checks that someone is signed in. If anyone can sign up, that’s anyone. Check that the row belongs to them, or to a team they’re in.`,
              ...ownerFix(p, owner, taken),
            });
          }
        }
        if (commands.includes('select') && alwaysTrue(p.using) && anon) {
          const sensitive = rel ? sensitiveColumns(rel.columns) : [];
          add({
            id: 'public_read',
            severity: sensitive.length > 0 ? 'warning' : 'note',
            category: 'security',
            lints: [],
            title: `Every row in ${q} is public`,
            object: q,
            line: p.line,
            detail: `${identifier(p.name)} lets anyone read all of it, signed in or not.${
              sensitive.length > 0 ? ` It has columns that look sensitive: ${sensitive.join(', ')}.` : ''
            } Fine for public content; move private rows or columns to another table.`,
          });
        }
        if (p.roles.includes('anon') && !p.roles.includes('public') && writes.some((c) => !!clauseFor(p, c) && !alwaysTrue(clauseFor(p, c)))) {
          add({
            id: 'anon_writes',
            severity: 'note',
            category: 'security',
            lints: [],
            title: `Signed-out visitors can ${writes.map((c) => VERB[c]).join(', ')} rows in ${q}`,
            object: q,
            line: p.line,
            detail: `${identifier(p.name)} is for the anon role. Right for things like a contact form; make sure the condition limits what a stranger can write.`,
          });
        }
      }

      // Narrowing a restrictive policy's roles would lift it for everyone left out, and a branch
      // without the user's id may serve signed-out visitors: only permissive policies that need a user.
      const needsUser = commands.every((c) => classify(clauseFor(p, c), 'anon') === 'none');
      if (p.permissive && !storage && p.roles.length === 1 && p.roles[0] === 'public' && needsUser) noRole.push(p);

      const usingCalls = authCalls(p.using?.tokens ?? []);
      const checkCalls = authCalls(p.check?.tokens ?? []);
      const calls = [...usingCalls, ...checkCalls];
      if (calls.some((call) => !call.wrapped)) {
        // Only the clauses with a call to wrap; the others stay as they are.
        const wrapped = (expr: Expr | undefined, list: Call[]) =>
          expr && list.some((c) => !c.wrapped) ? wrapCalls(expr.tokens, list) : undefined;
        add({
          id: 'auth_rls_initplan',
          severity: 'note',
          category: 'performance',
          lints: ['0003'],
          title: `${identifier(p.name)} calls ${[...new Set(calls.filter((c) => !c.wrapped).map((c) => `${c.name}()`))].join(' and ')} once per row`,
          object: q,
          line: p.line,
          detail:
            'Postgres runs the function again for every row it checks. Wrapped in (select ...), it runs once per query, which is much faster on big tables. The result is the same.',
          ...policyFix([{ ...policyEdit(p, 'speed'), using: wrapped(p.using, usingCalls), check: wrapped(p.check, checkCalls) }]),
        });
      }

      if (callsAuthRole(p.using) || callsAuthRole(p.check) || readsClaimsSetting(p.using) || readsClaimsSetting(p.check)) {
        add({
          id: 'legacy_auth_helpers',
          severity: 'note',
          category: 'security',
          lints: [],
          title: `${identifier(p.name)} uses an old way to read the user`,
          object: q,
          line: p.line,
          detail:
            'auth.role() and reading request.jwt.claims directly still work but are deprecated. Name the role with `to authenticated` or `to anon`, and read claims with auth.jwt().',
        });
      }

      if (p.command === 'all' && !storage) {
        add({
          id: 'for_all_policy',
          severity: 'note',
          category: 'security',
          lints: [],
          title: `${identifier(p.name)} covers every command`,
          object: q,
          line: p.line,
          detail:
            'A FOR ALL policy gives reads and writes the same rule, and with no WITH CHECK its USING also decides which new rows can be written. Separate select, insert, update and delete policies are easier to get right.',
        });
      }
    }

    if (noRole.length > 0) {
      add({
        id: 'policy_without_role',
        severity: 'note',
        category: 'performance',
        lints: [],
        title: `${noRole.length === 1 ? `${identifier(noRole[0].name)} applies` : `${noRole.length} policies on ${q} apply`} to every role`,
        object: q,
        line: noRole[0].line,
        detail:
          'With no TO clause a policy applies to every role, signed-out visitors included. Its condition needs a signed-in user, so it never lets them through, but Postgres still checks it on their queries. Add `to authenticated` to skip that.',
        ...policyFix(noRole.map((p) => ({ ...policyEdit(p, 'speed'), roles: ['authenticated'] }))),
      });
    }

    if (storage) {
      lintStorage(policies);
      continue;
    }

    // Several permissive policies for one role and command: Postgres runs them all.
    const overlaps: string[] = [];
    for (const role of ['anon', 'authenticated'] as const) {
      for (const command of COMMANDS) {
        const matching = policies.filter((p) => p.permissive && covers(p, command) && appliesTo(p, role));
        if (matching.length > 1) overlaps.push(`${command} for ${role}: ${matching.map((p) => identifier(p.name)).join(', ')}`);
      }
    }
    if (overlaps.length > 0) {
      add({
        id: 'multiple_permissive_policies',
        severity: 'note',
        category: 'performance',
        lints: ['0006'],
        title: `${q} has overlapping policies`,
        object: q,
        line: policies[0].line,
        detail: `Postgres checks every permissive policy for each row, so these add up: ${overlaps.join('; ')}. Merge each group into one policy with OR.`,
      });
    }

    // UPDATE and DELETE only reach rows the caller can SELECT.
    for (const role of ['anon', 'authenticated'] as const) {
      const canRead = policies.some((p) => p.permissive && covers(p, 'select') && !!p.using && appliesTo(p, role));
      if (canRead) continue;
      // Policies without a role count for authenticated; anon only when named.
      const blind = (['update', 'delete'] as const).filter((c) =>
        policies.some((p) => p.permissive && p.command === c && !!p.using && (role === 'anon' ? p.roles.includes('anon') : appliesTo(p, role))),
      );
      if (blind.length > 0) {
        add({
          id: 'write_without_select',
          severity: 'warning',
          category: 'security',
          lints: [],
          title: `${role} can ${blind.map((c) => VERB[c]).join(' and ')} ${q} but not read it`,
          object: q,
          line: policies[0].line,
          detail: `Postgres only ${blind.join('s and ')}s rows the caller can select, so ${blind.join(' and ')} from the app changes nothing and reports no error. Add a select policy for ${role}.`,
        });
      }
    }

    for (const command of COMMANDS) {
      const restrictive = policies.filter((p) => !p.permissive && covers(p, command));
      const permissive = policies.filter((p) => p.permissive && covers(p, command));
      if (restrictive.length > 0 && permissive.length === 0) {
        add({
          id: 'restrictive_only',
          severity: 'note',
          category: 'security',
          lints: [],
          title: `${command} on ${q} has only restrictive policies`,
          object: q,
          line: restrictive[0].line,
          detail: 'Restrictive policies can only narrow access that a permissive policy grants. With none, nothing passes.',
        });
      }
    }

    // Columns the policies compare with the user's id should be indexed.
    if (rel && rel.kind === 'table' && (catalog.source === 'json' || rel.columns.length > 0)) {
      const missing = new Set<string>();
      for (const p of policies) {
        for (const column of [...ownerColumns(p.using), ...ownerColumns(p.check)]) {
          if (!rel.indexed.has(column) && (rel.columns.length === 0 || rel.columns.includes(column))) missing.add(column);
        }
      }
      for (const column of missing) {
        add({
          id: 'policy_column_unindexed',
          severity: 'note',
          category: 'performance',
          lints: [],
          title: `${q}.${identifier(column)} has no index`,
          object: q,
          line: rel.line,
          detail: `Policies compare ${column} with the user’s id on every query. Without an index, Postgres reads the whole table to do it.`,
          fix: `create index if not exists ${identifier(pgName(`${table}_${column}`, '_idx'))} on ${q} (${identifier(column)});`,
        });
      }
    }
  }

  /**
   * Storage policies that tie files to nothing but their bucket. Every command
   * a policy covers is checked, and one finding lists them all. The fix keeps
   * the policy and limits it to the files each user uploaded, whatever the
   * folder layout: Storage puts the uploader's id in owner_id.
   */
  function lintStorage(policies: Policy[]) {
    for (const p of policies) {
      if (!p.permissive) continue;
      if (!appliesTo(p, 'anon') && !appliesTo(p, 'authenticated')) continue;
      // Postgres checks new rows of a FOR ALL or UPDATE policy without WITH CHECK against USING.
      const writesNew = p.command === 'insert' || p.command === 'update' || p.command === 'all';
      const using = p.command === 'insert' ? undefined : storageScope(p.using);
      const check = writesNew ? storageScope(p.check ?? (p.command === 'insert' ? undefined : p.using)) : undefined;
      const commands: Command[] = p.command === 'all' ? COMMANDS : [p.command];
      const scopeOf = (c: Command) => (c === 'insert' ? check : c === 'update' ? (using ?? check) : using);
      const open = commands.filter((c) => scopeOf(c));
      if (open.length === 0) continue;

      const bucketId = using?.bucket ?? check?.bucket;
      const bucket = bucketId !== undefined ? catalog.buckets.get(bucketId) : undefined;
      const where = bucketId !== undefined ? `bucket ${bucketId}` : 'every bucket';
      // A sign-in check in the condition shuts out signed-out visitors, whatever role it names.
      const anon = appliesTo(p, 'anon') && open.some((c) => !scopeOf(c)!.signedIn);
      const who = anon ? 'Anyone' : 'Every signed-in user';
      const publicList = open.includes('select') && !!bucket?.public;
      const writes = open.filter((c) => c !== 'select');
      const severity: Severity = writes.length > 0 ? (anon ? 'error' : 'warning') : publicList || anon ? 'warning' : 'note';
      const single: Record<Command, string> = {
        select: `list ${bucket?.public ? '' : 'and download '}every file in`,
        insert: 'upload to',
        update: 'change any file in',
        delete: 'delete any file in',
      };
      const verbs: Record<Command, string> = { select: bucket?.public ? 'list' : 'read', insert: 'upload', update: 'change', delete: 'delete' };
      const phrases: Record<Command, string> = {
        select: `list ${bucket?.public ? '' : 'and download '}every file`,
        insert: 'upload files',
        update: 'change any file',
        delete: 'delete any file',
      };

      const scoped = (s: { bucket?: string }) => `${s.bucket !== undefined ? `bucket_id = ${literal(s.bucket)} and ` : ''}owner_id = ${SUB}`;
      const edit = policyEdit(p, 'security');
      if (using) edit.using = scoped(using);
      if (check) edit.check = scoped(check);
      const note: string[] = [];
      if (open.some((c) => c !== 'insert')) {
        note.push(
          'Each user now reaches only the files they uploaded: Storage puts the uploader’s',
          'id in owner_id. Files uploaded without a signed-in user have none, so users',
          'can’t reach them after this.',
        );
      }
      if (open.includes('insert') && anon) note.push('Signed-out visitors can’t upload after this.');
      if (publicList) note.push('Public URLs still serve every file in a public bucket.');
      edit.note = note.join('\n');

      add({
        id: writes.length > 0 ? 'storage_broad_write' : 'storage_broad_select',
        severity,
        category: 'security',
        lints: publicList ? ['0025'] : [],
        title: `${who} can ${open.length === 1 ? single[open[0]] : `${andList(open.map((c) => verbs[c]))} any file in`} ${where}`,
        object: 'storage.objects',
        line: p.line,
        detail: `${identifier(p.name)} doesn’t tie files to the user who uploaded them, so ${anon ? 'anyone' : 'any signed-in user'} can ${andList(open.map((c) => phrases[c]))}.${
          publicList ? ' Public files are served by their URL anyway, so listing them all only shows more than you meant to share.' : ''
        } Limit it to each user’s own files.`,
        ...policyFix([edit]),
      });
    }
  }

  // Functions by schema and name: overloads share both, and a call's argument count picks one.
  const overloads = new Map<string, Func[]>();
  for (const fn of catalog.functions) overloads.set(key(fn.schema, fn.name), [...(overloads.get(key(fn.schema, fn.name)) ?? []), fn]);

  /** The functions a call starting at tokens[i] may run: by its schema (public when it names none), name and argument count. */
  const calleesAt = (tokens: Token[], i: number, match: Int32Array): Func[] => {
    const t = tokens[i];
    if (!isName(t) || !isOp(tokens[i + 1], '(')) return [];
    let schema = 'public';
    if (isOp(tokens[i - 1], '.')) {
      if (!isName(tokens[i - 2]) || isOp(tokens[i - 3], '.')) return [];
      schema = tokens[i - 2].value;
    }
    const list = overloads.get(key(schema, t.value)) ?? [];
    if (list.length <= 1) return list;
    const args = argCountAt(tokens, i + 1, match);
    const exact = list.filter((f) => argCount(f.args) === args);
    // Fewer arguments than each one takes: defaults fill the rest, in one the checker can't pick.
    return exact.length > 0 ? exact : list.filter((f) => argCount(f.args) > args);
  };

  // Each function's calls from policies: how many arguments each passes, and every function it may run.
  const policyCalls = new Map<Func, { args: number; callees: Func[] }[]>();
  for (const p of catalog.policies) {
    for (const expr of [p.using, p.check]) {
      if (!expr) continue;
      const match = pairs(expr.tokens);
      for (let i = 0; i < expr.tokens.length; i += 1) {
        const callees = calleesAt(expr.tokens, i, match);
        for (const f of callees) policyCalls.set(f, [...(policyCalls.get(f) ?? []), { args: argCountAt(expr.tokens, i + 1, match), callees }]);
      }
    }
  }

  // Where a helper that policies call moves: the first schema the API doesn't serve without a function of the same name and arguments.
  const taken = new Set(catalog.functions.map((f) => `${f.schema}.${f.name}(${f.args})`));
  const hiddenFor = (fn: Func, claim: boolean) => {
    const to = HELPER_SCHEMAS.find((s) => !catalog.exposed.includes(s) && !taken.has(`${s}.${fn.name}(${fn.args})`));
    if (to && claim) taken.add(`${to}.${fn.name}(${fn.args})`);
    return to;
  };

  // What signed-out visitors may run that calls a function without going through the API.
  // Postgres checks execute as them there too.
  const signatures = new Map(catalog.functions.map((f) => [`${name(f.schema, f.name)}(${f.args})`, f]));
  const indirectUses = (fn: Func): string[] => {
    const views = relations
      .filter((r) => r.kind === 'view' && exposed(r.schema) && !!r.query && (!r.grants || r.grants.anon.has('select')))
      .filter((r) => callsIn(r.query!).some((call) => namesFunction(call, fn)))
      .map((r) => `the view ${name(r.schema, r.name)}`);
    const tables = (fn.usedBy ?? []).map((t) => `a column default or check on ${t}`);
    // A security definer caller runs as its owner, who keeps execute.
    const bodies = (fn.calledBy ?? [])
      .filter((sig) => !signatures.get(sig)?.securityDefiner)
      .map((sig) => (signatures.get(sig)?.returnsTrigger ? `the trigger function ${sig}` : sig));
    return [...views, ...tables, ...bodies];
  };

  for (const fn of catalog.functions) {
    if (SYSTEM_SCHEMAS.has(fn.schema)) continue;
    const signature = `${name(fn.schema, fn.name)}(${fn.args})`;
    const callable = exposed(fn.schema) && !fn.returnsTrigger;
    const self = { kind: 'function' as const, schema: fn.schema, name: fn.name, args: fn.args };
    if (fn.securityDefiner && callable && (fn.anon || fn.authenticated)) {
      // Postgres checks execute as the user a policy runs for, so taking it away would make the policy fail.
      const calls = policyCalls.get(fn) ?? [];
      const helper = calls.length > 0;
      const endpoint = `/rest/v1/rpc/${fn.name}`;
      // How Supabase's client calls it.
      const rpc = `supabase.rpc('${fn.name}')`;
      const finding: Finding = {
        id: fn.anon ? 'anon_security_definer_function_executable' : 'authenticated_security_definer_function_executable',
        severity: fn.anon ? 'warning' : 'note',
        category: 'security',
        lints: [fn.anon ? '0028' : '0029'],
        title: `${fn.anon ? 'Anyone' : 'Every signed-in user'} can call ${signature} with its owner’s rights`,
        object: signature,
        line: fn.line,
        detail: `It’s security definer and in an exposed schema, so ${fn.anon ? 'anyone' : 'any signed-in user'} can call it at ${endpoint}, and it runs as its owner, past RLS. ${
          helper
            ? 'Policies call it, so taking execute away would make them fail. Move it to a schema the API doesn’t serve instead.'
            : 'Revoking from public alone isn’t enough on Supabase: anon and authenticated have their own grants.'
        }`,
      };
      if (helper) {
        // With other functions of the same name, only calls with its number of arguments run it.
        const callArgs = (overloads.get(key(fn.schema, fn.name))?.length ?? 1) > 1 ? argCount(fn.args) : undefined;
        // Bodies look it up by name each time they run, so they'd stop finding it.
        const callers = fn.calledBy ?? [];
        const unsure = calls.some((c) => c.callees.length > 1 || (callArgs !== undefined && c.args !== callArgs));
        const to = callers.length === 0 && !unsure ? hiddenFor(fn, true) : undefined;
        if (to) {
          const moved = `${identifier(to)}.${identifier(fn.name)}`;
          const first = HELPER_SCHEMAS[0];
          const note = [
            ...(to === first || catalog.exposed.includes(first)
              ? []
              : catalog.functions.some((f) => f.schema === first && f.name === fn.name && f.args === fn.args)
                ? [`${first} has a function ${fn.name}(${fn.args}) already, so this one goes to ${to}.`]
                : [`Another ${fn.name}(${fn.args}) moves to ${first} above, so this one goes to ${to}.`]),
            'Policies call it, and they keep working after the move: Postgres keeps track',
            `of the function, not its name. The app can’t call ${rpc} any more,`,
            `and SQL that names ${name(fn.schema, fn.name)} needs ${moved} now.`,
          ];
          add({ ...finding, ...functionFix([{ ...self, moveTo: to, callArgs, note: note.join('\n') }]) });
        } else {
          const free = hiddenFor(fn, false);
          const into = free ? identifier(free) : '<schema>';
          const but = callers.length > 0
            ? [
                `But ${andList(callers)} ${callers.length === 1 ? 'calls' : 'call'} it by name,`,
                `and would fail after the move. Run this together with new versions of ${callers.length === 1 ? 'that function' : 'them'}`,
                `that call ${into}.${identifier(fn.name)}:`,
              ]
            : unsure
              ? ['But another function has the same name, and the checker can’t tell which one', 'each policy calls. Check that, then run:']
              : [`But ${andList(HELPER_SCHEMAS)} each have a function ${fn.name}(${fn.args}) already.`, 'Put another schema the API doesn’t serve in place of <schema>, then run:'];
          const why = [
            'Policies call it, so taking execute away would make them fail. Moving it to a schema',
            'the API doesn’t serve fixes it, and the policies keep working.',
            ...but,
          ];
          const sql = `create schema if not exists ${into};\nalter function ${signature} set schema ${into};`;
          add({ ...finding, manual: true, fix: commentOut(`${commentLines(why.join('\n'))}\n${sql}`) });
        }
      } else if (fn.anon) {
        const uses = indirectUses(fn);
        const revoke = `revoke execute on function ${signature} from public, anon;`;
        if (uses.length > 0) {
          const why = [
            `It may run for signed-out visitors through ${andList(uses)} too.`,
            `Taking execute away from them would make ${uses.length === 1 ? 'that' : 'those'} fail. If they never reach it, run:`,
          ];
          add({ ...finding, manual: true, fix: commentOut(`${commentLines(why.join('\n'))}\n${revoke}`) });
        } else {
          const optional = fn.authenticated
            ? `-- If signed-in users shouldn’t call it either, run this too:\nrevoke execute on function ${signature} from authenticated;`
            : undefined;
          const note = `After this, signed-out visitors get an error from ${rpc}\n(${endpoint}). Skip it if the app calls it before sign-in.`;
          add({ ...finding, ...functionFix([{ ...self, revokeFrom: ['public', 'anon'], optional, note }]) });
        }
      } else {
        const why = [
          `Signed-in users can call it with ${rpc}. If the app does that on purpose,`,
          'leave it, and check it only does what any user may do. Otherwise run this; the',
          'app then gets an error from that call:',
        ];
        add({ ...finding, manual: true, fix: commentOut(`${commentLines(why.join('\n'))}\nrevoke execute on function ${signature} from authenticated;`) });
      }
    }
    if (!fn.searchPathSet) {
      add({
        id: 'function_search_path_mutable',
        severity: fn.securityDefiner ? 'warning' : 'note',
        category: 'security',
        lints: ['0011'],
        title: `${signature} has no fixed search_path`,
        object: signature,
        line: fn.line,
        detail: fn.securityDefiner
          ? 'A security definer function that looks names up through the caller’s search_path can be tricked into running someone else’s function or table with the owner’s rights. Pin its search_path.'
          : 'Without a fixed search_path, the names inside resolve differently depending on who calls it. Pin it.',
        ...functionFix([{ ...self, searchPath: SEARCH_PATH, note: SEARCH_PATH_NOTE }]),
      });
    }
  }

  if (catalog.opaque.length > 0) {
    add({
      id: 'dynamic_sql',
      severity: 'note',
      category: 'security',
      lints: [],
      title: 'Some SQL here is built at run time',
      object: catalog.opaque.length === 1 ? 'a DO block' : `${catalog.opaque.length} DO blocks`,
      line: catalog.opaque[0],
      detail:
        'A DO block runs SQL it puts together itself, with execute, so the checker can’t see the policies, grants or settings it makes. Tables it touches may have more or less access than shown. Run the catalog query on the live project for the real result.',
    });
  }

  const order: Record<Severity, number> = { error: 0, warning: 1, note: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || (a.category === b.category ? 0 : a.category === 'security' ? -1 : 1));
  // Each fix shown on its own is the script's final change to what it touches.
  shareFixes(findings);

  return {
    source: catalog.source,
    findings,
    tables: tables.sort((a, b) => key(a.schema, a.name).localeCompare(key(b.schema, b.name))),
    counts: {
      tables: relations.filter((r) => exposed(r.schema)).length,
      policies: catalog.policies.length,
      functions: catalog.functions.length,
      statements: catalog.statements,
    },
  };
}

type Section = 'helpers' | 'tables' | 'policies' | 'views' | 'functions' | 'storage' | 'speed';

/**
 * The script's parts, in the order they run. Helpers that policies call move
 * first, so every policy below can name them where they end up, and the
 * script still runs a second time.
 */
const SECTIONS: [Section, string][] = [
  ['helpers', 'Functions that policies call'],
  ['tables', 'Tables'],
  ['policies', 'Policies'],
  ['views', 'Views'],
  ['functions', 'Functions'],
  ['storage', 'Storage'],
  ['speed', 'Speed'],
];

/** Where a fix without edits goes. Others go by category: speed fixes last. */
const SECTION_OF: Record<string, Section> = {
  rls_disabled_in_public: 'tables',
  auth_users_exposed: 'views',
  security_definer_view: 'views',
  materialized_view_in_api: 'views',
  foreign_table_in_api: 'views',
  function_search_path_mutable: 'functions',
  anon_security_definer_function_executable: 'functions',
  authenticated_security_definer_function_executable: 'functions',
};

/** Which object an edit changes: one policy, or one function. */
const editId = (e: Edit) => (e.kind === 'policy' ? `policy ${e.schema}.${e.table}\u0000${e.name}` : `function ${functionTarget(e)}`);

/** A finding's title as a comment line in the script. */
const titleLine = (f: Finding) => commentLines(`${f.category === 'performance' ? 'Speed: ' : ''}${f.title}`);

/** Every finding's changes to one object, merged into the one change the script makes. */
interface Block {
  edit: Edit;
  section: Section;
  /** The titles of the findings that change it. */
  titles: string[];
  /** How many findings change it. */
  findings: number;
}

/**
 * Each object's merged change (see mergePolicyEdits and mergeFunctionEdits),
 * and the helpers that move, from the findings' edits. Fixes that need the
 * user's input aren't part of it.
 */
function plan(findings: Finding[]): { blocks: Map<string, Block>; moved: FunctionEdit[] } {
  const groups = new Map<string, { edits: Edit[]; titles: string[]; findings: number }>();
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
  const blocks = new Map<string, Block>();
  const moved: FunctionEdit[] = [];
  for (const [id, { edits, titles, findings: count }] of groups) {
    if (edits[0].kind === 'function') {
      const merged = mergeFunctionEdits(edits as FunctionEdit[]);
      if (merged.moveTo) moved.push(merged);
      blocks.set(id, { edit: merged, section: merged.moveTo ? 'helpers' : 'functions', titles, findings: count });
      continue;
    }
    const merged = mergePolicyEdits(edits as PolicyEdit[]);
    const section = merged.priority === 'speed' ? 'speed' : merged.schema === 'storage' ? 'storage' : 'policies';
    blocks.set(id, { edit: merged, section, titles, findings: count });
  }
  return { blocks, moved };
}

/** A block's SQL as it runs: a policy names each moved helper where it ends up. */
function blockSql(block: Block, moved: FunctionEdit[], schema: boolean, used?: Set<FunctionEdit>): string {
  return block.edit.kind === 'function' ? functionSql(block.edit, schema) : renameCalls(policySql(block.edit), moved, used);
}

/**
 * Each finding's fix as the script runs it: the one merged change to each
 * object it touches, other findings' changes included. Fixes copied one at a
 * time, in any order, then end where the script does, and none undoes
 * another. A policy that calls a helper that moves moves it first.
 */
function shareFixes(findings: Finding[]) {
  const { blocks, moved } = plan(findings);
  for (const f of findings) {
    if (f.manual || !f.edits || f.edits.length === 0) continue;
    const ids = [...new Set(f.edits.map(editId))];
    const used = new Set<FunctionEdit>();
    const parts: string[] = [];
    for (const id of ids) {
      const block = blocks.get(id)!;
      const sql = blockSql(block, moved, true, used);
      if (sql === '') continue;
      // Say so when other findings' changes make it differ from this finding's own.
      const own = plan([{ ...f, edits: f.edits.filter((e) => editId(e) === id) }]).blocks.get(id)!;
      const shared = block.findings > 1 && blockSql(own, moved, true) !== sql;
      const what = block.edit.kind === 'policy' ? 'policy' : 'function';
      parts.push(`${shared ? `-- The other fixes for this ${what} are in here too, so none undoes another.\n` : ''}${sql}`);
    }
    const first = [...used]
      .filter((m) => !ids.includes(editId(m)))
      .map((m) => {
        const to = `${identifier(m.moveTo!)}.${identifier(m.name)}`;
        return `-- It calls ${to}, so first it moves ${functionTarget(m)} there, as that function’s own fix does.\n${functionSql({ ...m, note: undefined })}`;
      });
    f.fix = [...first, ...parts].join('\n');
  }
}

/**
 * One script with every fix that can run as it is, then the ones that need
 * the user's input, commented out. Every finding's edits to one policy, or to
 * one function, become one block (see plan()), so no fix undoes another, and
 * the script is safe to run twice.
 */
export function fixScript(result: LintResult): string {
  const { blocks, moved } = plan(result.findings);
  const entries: { section: Section; text: string }[] = [];
  const manual: string[] = [];
  for (const f of result.findings) {
    if (f.manual) {
      if (f.fix) manual.push(`${titleLine(f)}\n${commentOut(f.fix)}`);
    } else if (!(f.edits && f.edits.length > 0) && f.fix) {
      const section = SECTION_OF[f.id] ?? (f.category === 'performance' ? 'speed' : 'policies');
      entries.push({ section, text: `${titleLine(f)}\n${f.fix}` });
    }
  }
  for (const block of blocks.values()) {
    const sql = blockSql(block, [], false);
    if (sql !== '') entries.push({ section: block.section, text: `${block.titles.join('\n')}\n${sql}` });
  }
  if (entries.length === 0 && manual.length === 0) return '';

  const out = [
    '-- Fixes from NestedBit’s Supabase RLS Checker. Read each one before running it,',
    '-- and try them on a test project first.',
  ];
  if (manual.length > 0) out.push('-- The ones that need a decision from you are at the end, commented out.');
  for (const [section, heading] of SECTIONS) {
    const here = entries.filter((e) => e.section === section);
    if (here.length === 0) continue;
    out.push('', `-- == ${heading} ==`);
    // Each schema the helpers move to is made once, before the first move.
    if (section === 'helpers') {
      out.push('', ...[...new Set(moved.map((m) => m.moveTo!))].map((to) => `create schema if not exists ${identifier(to)};`));
    }
    // Once a helper has moved, policies have to name it in its new schema.
    for (const e of here) out.push('', section === 'helpers' || section === 'functions' ? e.text : renameCalls(e.text, moved));
  }
  if (manual.length > 0) {
    out.push(
      '',
      '-- == NEEDS YOUR INPUT ==',
      '-- These don’t run as they are. Fill in each one, remove the -- in front of',
      '-- its SQL, and run it on its own.',
    );
    // They run after the script, so the SQL in them names moved helpers where they are then.
    const rename = (line: string) => line.replace(/^(\s*--\s?)(.*)$/, (_, mark: string, rest: string) => mark + renameCalls(rest, moved));
    for (const m of manual) out.push('', m.split('\n').map(rename).join('\n'));
  }
  return out.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// An example with the usual mistakes, for "Try a leaky example".

export const LEAKY_EXAMPLE = `-- A small app with the mistakes the checker looks for.
create table public.profiles (
  id uuid primary key references auth.users (id),
  username text,
  api_key text
);

create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id),
  title text not null,
  done boolean default false
);
alter table public.todos enable row level security;

create policy "Enable read access for all users" on public.todos
  for select using (true);

create policy "Users can update todos" on public.todos
  for update to authenticated using (auth.uid() is not null);

create policy "Users can insert their own todos" on public.todos
  for insert with check (auth.uid() = user_id);

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  team text,
  name text
);
alter table public.projects enable row level security;

create policy "Team members can manage projects" on public.projects
  for all to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'team') = team);

create view public.todo_counts as
  select user_id, count(*) from public.todos group by user_id;

create function public.make_admin(target uuid) returns void
  language sql security definer
  as $$ update public.profiles set username = 'admin' where id = target $$;

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
create policy "Avatar access" on storage.objects for select using (bucket_id = 'avatars');
`;
