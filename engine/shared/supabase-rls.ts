// Supabase row-level security from the access model: one role, resource and
// grant table, drawn as who may select, insert, update and delete on each table.
// Two extra audiences are built in, "Anyone" (the anon role, plus signed-in
// users) and "Signed-in user" (the authenticated role); any other role is held
// in a table the generated SQL creates, so users can't change it from a client.
//
// Pure TypeScript with no DOM, like access-model.ts. test/supabase-rls.test.ts
// runs the generated SQL on real Postgres.

import {
  SQL_COMMANDS,
  effectiveGrant,
  fromJson,
  getGrant,
  parseActions,
  prune,
  literal,
  newId,
  setGrant,
  snake,
  type AccessModel,
  type Check,
  type Scope,
} from './access-model.ts';
import { TEMPLATES } from './templates.ts';

export const COMMANDS = ['select', 'insert', 'update', 'delete'] as const;
export type Command = (typeof COMMANDS)[number];

export const ANYONE = 'anyone';
export const SIGNED_IN = 'signed_in';
export const ANYONE_NAME = 'Anyone';
export const SIGNED_IN_NAME = 'Signed-in user';

export const DEFAULT_OWNER = 'user_id';
export const DEFAULT_TENANT = 'organization_id';

export interface TableColumns {
  /** The column holding the owning user's id. */
  owner: string;
  /** The column holding the organization's id, for multi-tenant plans. */
  tenant: string;
}

export interface PlanOptions {
  /** Writes need a session that passed multi-factor sign-in (aal2), as restrictive policies. */
  mfaWrites: boolean;
  /** A Storage bucket where each signed-in user owns the folder named after their id. Blank for none. */
  storageBucket: string;
  /** Drop every other policy on the listed tables first, so the migration is the whole truth. */
  replaceExisting: boolean;
}

export const DEFAULT_OPTIONS: PlanOptions = { mfaWrites: false, storageBucket: '', replaceExisting: true };

export interface RlsPlan {
  /** Resources are tables, their actions are always COMMANDS. */
  model: AccessModel;
  /** Resource id → column names. A blank name means the default. */
  columns: Record<string, TableColumns>;
  /** Resource id → actions imported from a matrix that no SQL command matches. */
  apiOnly: Record<string, string[]>;
  /** Missing on plans saved before options existed. */
  options?: Partial<PlanOptions>;
}

/** A plan's options, with defaults for any it doesn't set. */
export const optionsOf = (plan: RlsPlan): PlanOptions => ({ ...DEFAULT_OPTIONS, ...plan.options });

const BUCKET = /^[a-z0-9][a-z0-9._-]{0,62}$/;

// Words Postgres won't take as a bare table or column name: PostgreSQL's
// "reserved" and "reserved (can be function or type)" keywords.
const RESERVED = new Set(
  `all analyse analyze and any array as asc asymmetric authorization binary both case cast check collate collation
  column concurrently constraint create cross current_catalog current_date current_role current_schema current_time
  current_timestamp current_user default deferrable desc distinct do else end except false fetch for foreign freeze
  from full grant group having ilike in initially inner intersect into is isnull join lateral leading left like limit
  localtime localtimestamp natural not notnull null offset on only or order outer overlaps placing primary references
  returning right select session_user similar some symmetric system_user table tablesample then to trailing true union
  unique user using variadic verbose when where window with`.split(/\s+/),
);

/** A name as SQL needs it: bare when that's safe, otherwise in double quotes. */
export function identifier(name: string): string {
  return /^[a-z_][a-z0-9_]*$/.test(name) && !RESERVED.has(name) ? name : `"${name.replace(/"/g, '""')}"`;
}

/** Text safe inside a -- comment: no line breaks or control characters that could end it. */
export const comment = (text: string) => text.replace(/[\u0000-\u001f\u007f\u0085\u2028\u2029]+/g, ' ').trim();

const utf8Length = (text: string) => new TextEncoder().encode(text).length;

/** FNV-1a, as 8 hex digits: short and stable, to keep long names apart. */
function hash8(text: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

/**
 * A Postgres name built from a base and a suffix that stays within Postgres's
 * 63-byte limit. Postgres would cut a longer name short, so names for the same
 * table could collide; here the base is shortened and tagged with its hash, and
 * the suffix is always kept.
 */
export function pgName(base: string, suffix = ''): string {
  if (utf8Length(base + suffix) <= 63) return base + suffix;
  const tag = `_${hash8(base)}`;
  let cut = base;
  while (cut.length > 0 && utf8Length(cut + tag + suffix) > 63) cut = cut.slice(0, -1);
  return cut + tag + suffix;
}

export const ownerColumn = (plan: RlsPlan, resourceId: string) =>
  snakeOr(plan.columns[resourceId]?.owner, DEFAULT_OWNER);

export const tenantColumn = (plan: RlsPlan, resourceId: string) =>
  snakeOr(plan.columns[resourceId]?.tenant, DEFAULT_TENANT);

function snakeOr(value: string | undefined, fallback: string): string {
  return value && value.trim() !== '' ? snake(value) : fallback;
}

const isBuiltIn = (roleId: string) => roleId === ANYONE || roleId === SIGNED_IN;

export const customRoles = (plan: RlsPlan) => plan.model.roles.filter((r) => !isBuiltIn(r.id));

const builtInRoles = () => [
  { id: ANYONE, name: ANYONE_NAME, inherits: [] },
  { id: SIGNED_IN, name: SIGNED_IN_NAME, inherits: [] },
];

// ---------------------------------------------------------------------------
// Plans: blank, from a spec, and from an RBAC matrix

/** A plan by name, as templates are written and as the JSON export saves it. */
export interface Spec {
  name: string;
  multiTenant: boolean;
  /** Custom roles; "Anyone" and "Signed-in user" are always there. */
  roles: string[];
  /** Table name → its columns and who may do what: "own:update" means own rows only. */
  tables: { name: string; owner?: string; tenant?: string; grants: Record<string, string[]>; apiOnly?: string[] }[];
  options?: Partial<PlanOptions>;
}

function fromSpec(spec: Spec): RlsPlan {
  const model: AccessModel = {
    name: spec.name,
    multiTenant: spec.multiTenant,
    roles: [...builtInRoles(), ...spec.roles.map((name) => ({ id: newId('role'), name, inherits: [] }))],
    resources: [],
    grants: {},
  };
  const plan: RlsPlan = { model, columns: {}, apiOnly: {}, options: { ...DEFAULT_OPTIONS, ...spec.options } };
  for (const table of spec.tables) {
    const id = newId('res');
    model.resources.push({ id, name: table.name, actions: [...COMMANDS] });
    plan.columns[id] = { owner: table.owner ?? DEFAULT_OWNER, tenant: table.tenant ?? DEFAULT_TENANT };
    if (table.apiOnly?.length) plan.apiOnly[id] = [...table.apiOnly];
    for (const [roleName, entries] of Object.entries(table.grants)) {
      const role = model.roles.find((r) => r.name === roleName);
      if (!role) continue;
      for (const entry of entries) {
        const scope: Scope = entry.startsWith('own:') ? 'own' : 'any';
        const command = entry.replace(/^own:/, '');
        if (!(COMMANDS as readonly string[]).includes(command)) continue;
        // Anyone has no user id, so it has no rows of its own.
        setGrant(model, role.id, id, command, role.id === ANYONE ? 'any' : scope);
      }
    }
  }
  return plan;
}

/** The plan by name, for saving and for the JSON export. */
export function planToSpec(plan: RlsPlan): Spec {
  const { model } = plan;
  return {
    name: model.name,
    multiTenant: model.multiTenant,
    roles: customRoles(plan).map((r) => r.name),
    tables: model.resources.map((resource) => {
      const grants: Record<string, string[]> = {};
      for (const role of model.roles) {
        const entries = COMMANDS.flatMap((c) => {
          const scope = getGrant(model, role.id, resource.id, c);
          return scope ? [scope === 'own' ? `own:${c}` : c] : [];
        });
        if (entries.length > 0) grants[role.name] = entries;
      }
      return {
        name: resource.name,
        owner: plan.columns[resource.id]?.owner || DEFAULT_OWNER,
        tenant: plan.columns[resource.id]?.tenant || DEFAULT_TENANT,
        grants,
        ...(plan.apiOnly[resource.id]?.length ? { apiOnly: plan.apiOnly[resource.id] } : {}),
      };
    }),
    options: optionsOf(plan),
  };
}

export const planToJson = (plan: RlsPlan) =>
  JSON.stringify({ tool: 'supabase-rls-generator', version: 1, ...planToSpec(plan) }, null, 2) + '\n';

/**
 * Reads this tool's JSON export, or an RBAC Matrix Builder JSON export. Throws
 * with a readable message if it can't.
 */
export function planFromJson(text: string): RlsPlan {
  const data = JSON.parse(text) as Record<string, unknown>;
  if (!isObject(data)) throw new Error('Expected a JSON object.');
  if (Array.isArray(data.resources)) {
    // Drop entries that aren't objects before the RBAC reader sees them.
    const clean = {
      ...data,
      roles: (Array.isArray(data.roles) ? data.roles : []).filter(isObject),
      resources: data.resources.filter(isObject),
      grants: (Array.isArray(data.grants) ? data.grants : []).filter(isObject),
    };
    return planFromModel(fromJson(JSON.stringify(clean)));
  }
  if (!Array.isArray(data.tables)) {
    throw new Error('Expected this tool’s JSON export (with "tables") or an RBAC Matrix Builder export (with "resources").');
  }
  const str = (v: unknown, fallback = '') => (typeof v === 'string' ? v : fallback);
  const roles = (Array.isArray(data.roles) ? data.roles : [])
    .map((r) => str(r).trim())
    .filter((r) => r !== '' && r !== ANYONE_NAME && r !== SIGNED_IN_NAME);
  const options = (data.options && typeof data.options === 'object' ? data.options : {}) as Record<string, unknown>;
  return fromSpec({
    name: str(data.name, 'Imported plan').slice(0, 120),
    multiTenant: data.multiTenant === true,
    roles: [...new Set(roles)],
    tables: (data.tables as unknown[]).filter(isObject).map((t) => {
      const grants: Record<string, string[]> = {};
      const raw = isObject(t.grants) ? t.grants : {};
      for (const [role, entries] of Object.entries(raw)) {
        if (Array.isArray(entries)) grants[role] = entries.map((e) => str(e).trim().toLowerCase());
      }
      return {
        name: str(t.name),
        owner: str(t.owner) || undefined,
        tenant: str(t.tenant) || undefined,
        grants,
        apiOnly: Array.isArray(t.apiOnly)
          ? (t.apiOnly as unknown[]).map((a) => snake(str(a))).filter((a) => a !== 'unnamed')
          : undefined,
      };
    }),
    options: {
      mfaWrites: options.mfaWrites === true,
      storageBucket: str(options.storageBucket),
      replaceExisting: options.replaceExisting !== false,
    },
  });
}

const OWN_ALL = ['own:select', 'own:insert', 'own:update', 'own:delete'];

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * An access model as the RBAC Matrix Builder saves it, checked field by field,
 * so a hand-edited or older save can't break the import. Throws with a readable
 * message when it isn't a model at all.
 */
export function readModel(source: unknown): AccessModel {
  if (!isObject(source) || !Array.isArray(source.roles) || !Array.isArray(source.resources)) {
    throw new Error('That isn’t a saved matrix: it needs roles and resources.');
  }
  const id = (v: unknown, prefix: string) => (typeof v === 'string' && v !== '' ? v : newId(prefix));
  const roles = source.roles.filter(isObject).map((r) => ({
    id: id(r.id, 'role'),
    name: typeof r.name === 'string' ? r.name : '',
    inherits: Array.isArray(r.inherits) ? r.inherits.filter((x): x is string => typeof x === 'string') : [],
  }));
  const resources = source.resources.filter(isObject).map((r) => ({
    id: id(r.id, 'res'),
    name: typeof r.name === 'string' ? r.name : '',
    actions: Array.isArray(r.actions) ? parseActions(r.actions.filter((a) => typeof a === 'string').join(',')) : [],
  }));
  const model: AccessModel = {
    name: typeof source.name === 'string' ? source.name : '',
    multiTenant: source.multiTenant === true,
    roles,
    resources,
    grants: {},
  };
  const grants = isObject(source.grants) ? source.grants : {};
  for (const [roleId, byResource] of Object.entries(grants)) {
    if (!isObject(byResource)) continue;
    for (const [resourceId, byAction] of Object.entries(byResource)) {
      if (!isObject(byAction)) continue;
      for (const [action, scope] of Object.entries(byAction)) {
        if (scope === 'any' || scope === 'own') setGrant(model, roleId, resourceId, action, scope);
      }
    }
  }
  prune(model);
  return model;
}

/** Turns any access model into a plan. Inherited permissions are written out, and each action becomes a SQL command. */
export function planFromModel(input: AccessModel | unknown): RlsPlan {
  const source = readModel(input);
  const roles = source.roles.map((r) => ({ id: newId('role'), name: r.name, inherits: [] }));
  const model: AccessModel = {
    name: source.name,
    multiTenant: source.multiTenant,
    roles: [...builtInRoles(), ...roles],
    resources: [],
    grants: {},
  };
  const plan: RlsPlan = { model, columns: {}, apiOnly: {}, options: { ...DEFAULT_OPTIONS } };
  for (const resource of source.resources) {
    const id = newId('res');
    model.resources.push({ id, name: snake(resource.name), actions: [...COMMANDS] });
    plan.columns[id] = { owner: DEFAULT_OWNER, tenant: DEFAULT_TENANT };
    for (const action of resource.actions) {
      const command = SQL_COMMANDS.find(([, pattern]) => pattern.test(action))?.[0];
      if (!command) {
        (plan.apiOnly[id] ??= []).push(action);
        continue;
      }
      source.roles.forEach((role, i) => {
        const grant = effectiveGrant(source, role.id, resource.id, action);
        if (!grant) return;
        // One command can come from several actions, such as update and edit: the widest wins.
        const current = getGrant(model, roles[i].id, id, command);
        if (current !== 'any') setGrant(model, roles[i].id, id, command, grant.scope);
      });
    }
  }
  return plan;
}

export interface PlanTemplate {
  id: string;
  name: string;
  build: () => RlsPlan;
}

export const PLAN_TEMPLATES: PlanTemplate[] = [
  {
    id: 'personal',
    name: 'Personal app: each user sees their own rows',
    build: () =>
      fromSpec({
        name: 'Personal app',
        multiTenant: false,
        roles: [],
        tables: [
          { name: 'profiles', owner: 'id', grants: { [SIGNED_IN_NAME]: ['own:select', 'own:insert', 'own:update'] } },
          { name: 'notes', grants: { [SIGNED_IN_NAME]: OWN_ALL } },
        ],
      }),
  },
  {
    id: 'public',
    name: 'Public content: anyone reads, authors write',
    build: () =>
      fromSpec({
        name: 'Public content',
        multiTenant: false,
        roles: ['Moderator'],
        tables: [
          {
            name: 'posts',
            owner: 'author_id',
            grants: {
              [ANYONE_NAME]: ['select'],
              [SIGNED_IN_NAME]: ['own:insert', 'own:update', 'own:delete'],
              Moderator: ['update', 'delete'],
            },
          },
          {
            name: 'comments',
            owner: 'author_id',
            grants: {
              [ANYONE_NAME]: ['select'],
              [SIGNED_IN_NAME]: ['own:insert', 'own:update', 'own:delete'],
              Moderator: ['delete'],
            },
          },
        ],
      }),
  },
  {
    id: 'team',
    name: 'Team SaaS: organizations with roles',
    build: () =>
      fromSpec({
        name: 'Team SaaS',
        multiTenant: true,
        roles: ['Admin', 'Member', 'Viewer'],
        tables: [
          {
            name: 'projects',
            owner: 'created_by',
            grants: {
              Admin: ['select', 'insert', 'update', 'delete'],
              Member: ['select', 'insert', 'own:update'],
              Viewer: ['select'],
            },
          },
          {
            name: 'documents',
            owner: 'created_by',
            grants: {
              Admin: ['select', 'insert', 'update', 'delete'],
              Member: ['select', 'insert', 'own:update', 'own:delete'],
              Viewer: ['select'],
            },
          },
        ],
      }),
  },
  {
    id: 'store',
    name: 'Store: staff roles and customers',
    build: () => planFromModel(TEMPLATES.find((t) => t.id === 'ecommerce')!.build()),
  },
];

// ---------------------------------------------------------------------------
// Checks

const MEMBERS_TABLE = 'organization_members';
const ROLES_TABLE = 'user_roles';

const WRITE_VERB: Record<Command, string> = { select: 'read', insert: 'add', update: 'change', delete: 'delete' };

export function checkPlan(plan: RlsPlan): Check[] {
  const out: Check[] = [];
  const { model } = plan;
  const roles = customRoles(plan);

  const seenTables = new Set<string>();
  for (const resource of model.resources) {
    const table = snake(resource.name);
    if (table === 'unnamed') {
      out.push({ severity: 'error', title: 'A table has no name', detail: 'Name every table: the SQL uses the names.' });
      continue;
    }
    if (seenTables.has(table)) {
      out.push({ severity: 'error', title: `Two tables are called ${table}`, detail: 'Rename or remove one.' });
    }
    for (const name of [table, ownerColumn(plan, resource.id), ...(model.multiTenant ? [tenantColumn(plan, resource.id)] : [])]) {
      if (name.length > 63) {
        out.push({
          severity: 'error',
          title: `${name.slice(0, 24)}… is too long`,
          detail: 'Postgres cuts table and column names at 63 characters, so the SQL wouldn’t find it. Shorten it.',
        });
      }
    }
    seenTables.add(table);
    if (roles.length > 0 && table === (model.multiTenant ? MEMBERS_TABLE : ROLES_TABLE)) {
      out.push({
        severity: 'error',
        title: `${table} is used for roles`,
        detail: 'This SQL creates that table to hold who has which role, with its own policy. Rename yours, or remove it here.',
      });
    }
  }

  const seenRoles = new Set<string>();
  for (const role of roles) {
    const key = snake(role.name);
    if (key === snake(ANYONE_NAME) || key === snake(SIGNED_IN_NAME)) {
      out.push({
        severity: 'error',
        title: `A role is called ${role.name.trim()}`,
        detail: `${ANYONE_NAME} and ${SIGNED_IN_NAME} are built in. Rename this role.`,
      });
    }
    if (key === 'unnamed') {
      out.push({ severity: 'error', title: 'A role has no name', detail: 'Name every role: the SQL uses the names.' });
    } else if (seenRoles.has(key)) {
      out.push({ severity: 'error', title: `Two roles are called ${key}`, detail: 'Rename or remove one.' });
    }
    seenRoles.add(key);
    const unused = model.resources.every((r) => COMMANDS.every((c) => !getGrant(model, role.id, r.id, c)));
    if (unused) {
      out.push({
        severity: 'warning',
        title: `${role.name || 'A role'} can’t do anything`,
        detail: 'Give it some access, or remove it.',
      });
    }
  }

  const allRoles = model.roles.filter((r) => model.resources.some((t) => COMMANDS.some((c) => getGrant(model, r.id, t.id, c))));

  for (const resource of model.resources) {
    const table = snake(resource.name);
    const scopeFor = (roleId: string, command: Command) => getGrant(model, roleId, resource.id, command);

    for (const command of ['insert', 'update', 'delete'] as const) {
      if (scopeFor(ANYONE, command)) {
        out.push({
          severity: 'error',
          title: `Anyone can ${WRITE_VERB[command]} rows in ${table}`,
          detail: 'No sign-in is needed, and the key your site ships to browsers is enough. Only keep this if it’s truly what you want.',
        });
      }
      if (scopeFor(SIGNED_IN, command) === 'any') {
        out.push({
          severity: 'warning',
          title: `Every signed-in user can ${WRITE_VERB[command]} any row in ${table}`,
          detail: 'If sign-up is open, that means anyone. You probably want Own, or a role.',
        });
      }
    }

    if (scopeFor(ANYONE, 'select')) {
      out.push({
        severity: 'note',
        title: `Every row in ${table} is public`,
        detail: 'Anyone can read all of it, including drafts or anything else private kept there. Move private rows or columns to another table.',
      });
    }
    if (model.multiTenant && scopeFor(SIGNED_IN, 'select') === 'any') {
      out.push({
        severity: 'warning',
        title: `Users in any organization can read all of ${table}`,
        detail: 'Signed-in user doesn’t stop at an organization’s edge. Use a role for data that belongs to one organization.',
      });
    }

    // Postgres finds no rows for an UPDATE or DELETE with a WHERE clause unless a SELECT policy lets the role see them.
    for (const role of allRoles) {
      for (const command of ['update', 'delete'] as const) {
        const canRead =
          scopeFor(role.id, 'select') ||
          scopeFor(ANYONE, 'select') ||
          (role.id !== ANYONE && scopeFor(SIGNED_IN, 'select'));
        if (scopeFor(role.id, command) && !canRead) {
          out.push({
            severity: 'warning',
            title: `${role.name} can ${WRITE_VERB[command]} ${table} but not read it`,
            detail: `Postgres only ${command}s rows the caller can select, so a filtered ${command} changes nothing and reports no error. Add select access.`,
          });
        }
      }
    }

    if (COMMANDS.every((c) => model.roles.every((r) => !scopeFor(r.id, c)))) {
      out.push({
        severity: 'note',
        title: `Nobody can reach ${table} from the browser`,
        detail: 'It gets no policies, so only server code with a secret key can use it. That’s right for internal tables.',
      });
    }
  }

  const options = optionsOf(plan);
  const bucket = options.storageBucket.trim();
  if (bucket !== '' && !BUCKET.test(bucket)) {
    out.push({
      severity: 'error',
      title: `“${bucket}” can’t be a bucket name`,
      detail: 'Use lowercase letters, numbers, dots, dashes and underscores, starting with a letter or number.',
    });
  }
  if (options.mfaWrites && model.resources.some((r) => (['insert', 'update', 'delete'] as const).some((c) => getGrant(model, ANYONE, r.id, c)))) {
    out.push({
      severity: 'note',
      title: 'Multi-factor sign-in can’t cover Anyone',
      detail: 'Signed-out visitors have no session to check, so writes open to Anyone stay open. Only signed-in writes need aal2.',
    });
  }

  if (model.resources.some((r) => model.roles.some((role) => getGrant(model, role.id, r.id, 'update')))) {
    out.push({
      severity: 'note',
      title: 'Policies pick rows, not columns',
      detail: 'Anyone allowed to update a row can change every column in it. If a table holds something like role, is_admin or plan, use a column grant or keep it in another table.',
    });
  }

  const order = ['error', 'warning', 'note'];
  return out.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
}


// ---------------------------------------------------------------------------
// SQL

const qualified = (table: string) => `public.${identifier(table)}`;

const sqlArray = (names: string[]) => `array[${names.map(literal).join(', ')}]`;

const UID = '(select auth.uid())';
const AAL2 = "(select auth.jwt() ->> 'aal') = 'aal2'";

type Policy = { to: string; condition: string };

/** Who a policy applies to, and its condition, or undefined when nobody has this command. */
function policyFor(plan: RlsPlan, resourceId: string, command: Command): Policy | undefined {
  const { model } = plan;
  const owner = `${UID} = ${identifier(ownerColumn(plan, resourceId))}`;
  const scope = (roleId: string) => getGrant(model, roleId, resourceId, command);

  if (scope(ANYONE)) return { to: 'anon, authenticated', condition: 'true' };

  const clauses: string[] = [];
  const signedIn = scope(SIGNED_IN);
  if (signedIn === 'any') return { to: 'authenticated', condition: 'true' };
  if (signedIn === 'own') clauses.push(owner);

  const named = (wanted: Scope) =>
    customRoles(plan)
      .filter((r) => scope(r.id) === wanted)
      .map((r) => snake(r.name));
  const roleCheck = (names: string[]) =>
    model.multiTenant
      ? `${identifier(tenantColumn(plan, resourceId))} in (select private.org_ids_with_role(${sqlArray(names)}))`
      : `(select private.has_role(${sqlArray(names)}))`;

  const any = named('any');
  const own = named('own');
  if (any.length > 0) clauses.push(roleCheck(any));
  if (own.length > 0) clauses.push(`(${roleCheck(own)} and ${owner})`);
  if (clauses.length === 0) return undefined;
  return {
    to: 'authenticated',
    condition: clauses.length === 1 ? clauses[0] : `\n    ${clauses.join('\n    or ')}\n  `,
  };
}

/** The USING and WITH CHECK clauses a command takes, for one condition. */
function clauses(command: Command, condition: string): string {
  const using = `using (${condition})`;
  const check = `with check (${condition})`;
  return command === 'insert' ? check : command === 'update' ? `${using}\n  ${check}` : using;
}

function policySql(table: string, command: Command, policy: Policy): string {
  const name = identifier(pgName(table, `_${command}`));
  const head = `create policy ${name} on ${qualified(table)} for ${command}\n  to ${policy.to}`;
  return `drop policy if exists ${name} on ${qualified(table)};\n${head}\n  ${clauses(command, policy.condition)};`;
}

/** A restrictive policy every signed-in write must also pass: a session that used multi-factor sign-in. */
function mfaSql(table: string, command: Command): string {
  const name = identifier(pgName(table, `_${command}_mfa`));
  return `drop policy if exists ${name} on ${qualified(table)};
create policy ${name} on ${qualified(table)} as restrictive for ${command}
  to authenticated
  ${clauses(command, AAL2)};`;
}

/** Drops every policy on a table, so the ones below are the only ones left. */
function dropAllSql(table: string): string {
  return `do $$
declare p record;
begin
  for p in select policyname from pg_policies where schemaname = 'public' and tablename = ${literal(table)} loop
    execute format('drop policy %I on ${qualified(table).replace(/%/g, '%%')}', p.policyname);
  end loop;
end $$;`;
}

function rolesTableSql(names: string[]): string {
  const roleList = names.map(literal).join(', ');
  return `-- Who holds which role. Nobody can change this from a browser, so nobody can promote
-- themselves. Add and change rows from server code using a secret key.
create schema if not exists private;
grant usage on schema private to authenticated;

create table if not exists public.${ROLES_TABLE} (
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null check (role in (${roleList})),
  primary key (user_id, role)
);
alter table public.${ROLES_TABLE} drop constraint if exists ${ROLES_TABLE}_role_check;
alter table public.${ROLES_TABLE} add constraint ${ROLES_TABLE}_role_check check (role in (${roleList}));
alter table public.${ROLES_TABLE} enable row level security;
revoke all on table public.${ROLES_TABLE} from anon, authenticated;
grant select on table public.${ROLES_TABLE} to authenticated;
grant select, insert, update, delete on table public.${ROLES_TABLE} to service_role;
drop policy if exists ${ROLES_TABLE}_select on public.${ROLES_TABLE};
create policy ${ROLES_TABLE}_select on public.${ROLES_TABLE} for select
  to authenticated
  using (${UID} = user_id);

-- Security definer, so a policy can look up roles without running the policies on
-- ${ROLES_TABLE} again. It lives outside public, where the API can't call it directly.
create or replace function private.has_role(wanted text[]) returns boolean
  language sql stable security definer set search_path = ''
  as $$
    select exists (
      select 1 from public.${ROLES_TABLE}
      where user_id = (select auth.uid()) and role = any (wanted)
    )
  $$;
revoke all on function private.has_role(text[]) from public, anon;
grant execute on function private.has_role(text[]) to authenticated;`;
}

function membersTableSql(names: string[]): string {
  const roleList = names.map(literal).join(', ');
  return `-- Who belongs to which organization, and with what role. Nobody can change this from a
-- browser, so nobody can add themselves to an organization or promote themselves. Add
-- and change rows from server code using a secret key. If admins manage members in your
-- app, send that through a server route that checks they're an admin.
-- organization_id is a uuid here: add a foreign key to your organizations table.
create schema if not exists private;
grant usage on schema private to authenticated;

create table if not exists public.${MEMBERS_TABLE} (
  organization_id uuid not null,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null check (role in (${roleList})),
  primary key (organization_id, user_id)
);
alter table public.${MEMBERS_TABLE} drop constraint if exists ${MEMBERS_TABLE}_role_check;
alter table public.${MEMBERS_TABLE} add constraint ${MEMBERS_TABLE}_role_check check (role in (${roleList}));
create index if not exists ${MEMBERS_TABLE}_user_id_idx on public.${MEMBERS_TABLE} (user_id);
alter table public.${MEMBERS_TABLE} enable row level security;
revoke all on table public.${MEMBERS_TABLE} from anon, authenticated;
grant select on table public.${MEMBERS_TABLE} to authenticated;
grant select, insert, update, delete on table public.${MEMBERS_TABLE} to service_role;
drop policy if exists ${MEMBERS_TABLE}_select on public.${MEMBERS_TABLE};
create policy ${MEMBERS_TABLE}_select on public.${MEMBERS_TABLE} for select
  to authenticated
  using (${UID} = user_id);

-- Security definer, so a policy can look up membership without running the policies on
-- ${MEMBERS_TABLE} again. It lives outside public, where the API can't call it directly.
create or replace function private.org_ids_with_role(wanted text[]) returns setof uuid
  language sql stable security definer set search_path = ''
  as $$
    select organization_id from public.${MEMBERS_TABLE}
    where user_id = (select auth.uid()) and role = any (wanted)
  $$;
revoke all on function private.org_ids_with_role(text[]) from public, anon;
grant execute on function private.org_ids_with_role(text[]) to authenticated;`;
}

/** Policies on storage.objects for a bucket where each user owns the folder named after their id. */
function storageSql(bucket: string, mfa: boolean): string {
  const folder = `bucket_id = ${literal(bucket)} and (storage.foldername(name))[1] = (select auth.jwt() ->> 'sub')`;
  const write = mfa ? `${folder}\n    and ${AAL2}` : folder;
  const out = [
    `-- Storage: each signed-in user reads and writes files under ${bucket}/<their user id>/,`,
    '-- and nobody else can see or list them. Upload with a path like `${user.id}/avatar.png`.',
    '-- Upserts need the select and update policies too. These policies cover this bucket only.',
    `insert into storage.buckets (id, name, public) values (${literal(bucket)}, ${literal(bucket)}, false)`,
    '  on conflict (id) do nothing;',
  ];
  for (const command of COMMANDS) {
    const name = identifier(pgName(bucket, `_own_${command}`));
    out.push(
      '',
      `drop policy if exists ${name} on storage.objects;`,
      `create policy ${name} on storage.objects for ${command}\n  to authenticated\n  ${clauses(command, command === 'select' ? folder : write)};`,
    );
  }
  return out.join('\n');
}

/**
 * The policy that one command on one table gets, exactly as the migration writes it, or
 * undefined when no role has that command. One policy covers every role for a command.
 */
export function cellPolicySql(plan: RlsPlan, resourceId: string, command: Command): string | undefined {
  const resource = plan.model.resources.find((r) => r.id === resourceId);
  const policy = resource ? policyFor(plan, resourceId, command) : undefined;
  return resource && policy ? policySql(snake(resource.name), command, policy) : undefined;
}

export const PLAN_FILENAME = 'supabase-rls.sql';
export const TEST_FILENAME = 'supabase-rls-test.sql';

/** A migration for the whole plan, safe to run more than once. */
export function toSupabaseSql(plan: RlsPlan): string {
  const { model } = plan;
  const options = optionsOf(plan);
  const roles = customRoles(plan).map((r) => snake(r.name));
  const out = [
    `-- ${comment(model.name) || 'Access plan'}: generated by NestedBit's Supabase RLS Generator`,
    '-- https://nestedbit.com/tools/supabase-rls-generator',
    '--',
    '-- Assumes these tables already exist. Run it as a migration or in the SQL Editor, on a',
    '-- test project first. It replaces what anon and authenticated could do on each table',
    '-- listed with exactly what the policies below need.',
    ...(options.replaceExisting
      ? ['-- It also drops every other policy on those tables, so these are the only ones left.']
      : []),
    '-- A column filled from a serial sequence also needs:',
    '--   grant usage on sequence <name> to authenticated;',
  ];

  const usage = ['authenticated', 'service_role'];
  if (model.resources.some((r) => COMMANDS.some((c) => getGrant(model, ANYONE, r.id, c)))) usage.unshift('anon');
  out.push('', '-- Tables are only reachable through the Data API with these grants.', `grant usage on schema public to ${usage.join(', ')};`);

  if (roles.length > 0) {
    out.push('', model.multiTenant ? membersTableSql(roles) : rolesTableSql(roles));
  }

  for (const resource of model.resources) {
    const table = snake(resource.name);
    const q = qualified(table);
    const policies = COMMANDS.map((command) => [command, policyFor(plan, resource.id, command)] as const).filter(
      (entry): entry is readonly [Command, Policy] => entry[1] !== undefined,
    );
    const forRole = (role: string) =>
      policies.filter(([, p]) => p.to.split(', ').includes(role)).map(([command]) => command);

    out.push('', `-- ${table}`, `alter table ${q} enable row level security;`);
    out.push(`revoke all on table ${q} from anon, authenticated;`);
    for (const role of ['anon', 'authenticated']) {
      const commands = forRole(role);
      if (commands.length > 0) out.push(`grant ${commands.join(', ')} on table ${q} to ${role};`);
    }
    out.push(`grant select, insert, update, delete on table ${q} to service_role;`);

    const needsOwner = model.roles.some((r) => COMMANDS.some((c) => getGrant(model, r.id, resource.id, c) === 'own'));
    const needsTenant =
      model.multiTenant && customRoles(plan).some((r) => COMMANDS.some((c) => getGrant(model, r.id, resource.id, c)));
    const indexed = new Set([...(needsOwner ? [ownerColumn(plan, resource.id)] : []), ...(needsTenant ? [tenantColumn(plan, resource.id)] : [])]);
    for (const column of indexed) {
      // id is normally the primary key, which already has an index.
      if (column !== 'id') out.push(`create index if not exists ${identifier(pgName(`${table}_${column}`, '_idx'))} on ${q} (${identifier(column)});`);
    }

    if (options.replaceExisting) out.push('', dropAllSql(table));

    if (policies.length === 0) {
      out.push('-- No policies: only server code using a secret key can reach this table.');
    } else {
      for (const [command, policy] of policies) out.push('', policySql(table, command, policy));
      if (options.mfaWrites) {
        for (const [command, policy] of policies) {
          if (command !== 'select' && policy.to.includes('authenticated')) out.push('', mfaSql(table, command));
        }
      }
      for (const command of COMMANDS) {
        if (!policies.some(([c]) => c === command)) out.push(`-- No ${command} policy, so ${command} is denied.`);
      }
    }
    const apiOnly = plan.apiOnly[resource.id];
    if (apiOnly?.length) {
      out.push(`-- ${comment(apiOnly.join(', '))}: no SQL command matches, so enforce ${apiOnly.length === 1 ? 'it' : 'them'} in your API.`);
    }
  }

  const bucket = options.storageBucket.trim();
  if (bucket !== '' && BUCKET.test(bucket)) out.push('', storageSql(bucket, options.mfaWrites));
  return out.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Trying it out

const TEST_USER = '00000000-0000-0000-0000-000000000001';
const TEST_ORG = '00000000-0000-0000-0000-0000000000aa';

/** Which rows one audience reaches with one command, in words. */
export function expectation(plan: RlsPlan, resourceId: string, roleId: string, command: Command): string | undefined {
  const { model } = plan;
  const owner = ownerColumn(plan, resourceId);
  const tenant = tenantColumn(plan, resourceId);
  const scopes = [getGrant(model, ANYONE, resourceId, command)];
  if (roleId !== ANYONE) scopes.push(getGrant(model, SIGNED_IN, resourceId, command));
  const custom = roleId !== ANYONE && roleId !== SIGNED_IN ? getGrant(model, roleId, resourceId, command) : undefined;
  if (scopes.includes('any')) return 'every row';
  const parts: string[] = [];
  if (scopes.includes('own')) parts.push(`rows where ${owner} is this user`);
  if (custom === 'any') parts.push(model.multiTenant ? `every row of this user's organization (${tenant})` : 'every row');
  if (custom === 'own') parts.push(model.multiTenant ? `this user's own rows in their organization` : `rows where ${owner} is this user`);
  if (parts.includes('every row')) return 'every row';
  return parts.length > 0 ? [...new Set(parts)].join(', plus ') : undefined;
}

/** SQL to run in the SQL Editor that shows what each audience can read, inside transactions that roll back. */
export function toTestSql(plan: RlsPlan): string {
  const { model } = plan;
  const out = [
    `-- ${comment(model.name) || 'Access plan'}: try the policies as each kind of user`,
    '-- Run one block at a time in the Supabase SQL Editor, on a test project, after the',
    '-- migration. Each block ends in rollback, so it changes nothing. Replace the ids with',
    '-- a real user id (Authentication > Users) and, for roles, a real organization id.',
  ];
  const audiences = [
    { id: ANYONE, label: 'a signed-out visitor (the anon role)', role: 'anon', claims: '{"role":"anon"}' },
    {
      id: SIGNED_IN,
      label: 'a signed-in user with no role',
      role: 'authenticated',
      claims: `{"sub":"${TEST_USER}","role":"authenticated"}`,
    },
    ...customRoles(plan).map((r) => ({
      id: r.id,
      label: `a user with the ${snake(r.name)} role`,
      role: 'authenticated',
      claims: `{"sub":"${TEST_USER}","role":"authenticated"}`,
      grant: model.multiTenant
        ? `insert into public.${MEMBERS_TABLE} (organization_id, user_id, role)\n  values (${literal(TEST_ORG)}, ${literal(TEST_USER)}, ${literal(snake(r.name))});`
        : `insert into public.${ROLES_TABLE} (user_id, role) values (${literal(TEST_USER)}, ${literal(snake(r.name))});`,
    })),
  ];

  for (const a of audiences) {
    out.push('', `-- As ${a.label}`, 'begin;');
    if ('grant' in a && a.grant) out.push(a.grant);
    out.push(`set local role ${a.role};`, `select set_config('request.jwt.claims', '${a.claims}', true);`);
    for (const resource of model.resources) {
      const table = snake(resource.name);
      const expect = expectation(plan, resource.id, a.id, 'select');
      const granted = policyFor(plan, resource.id, 'select')?.to.split(', ').includes(a.role);
      if (expect) out.push(`select * from ${qualified(table)}; -- expect: ${expect}`);
      else if (granted) out.push(`select count(*) from ${qualified(table)}; -- expect: 0, no policy lets them read it`);
      else out.push(`-- ${qualified(table)}: ${a.role} has no select grant, so a query here fails with "permission denied".`);
      const writes = (['insert', 'update', 'delete'] as const).map((c) => `${c} ${expectation(plan, resource.id, a.id, c) ?? 'nothing'}`);
      out.push(`--   and may ${writes.join('; ')}.`);
    }
    out.push('rollback;');
  }
  return out.join('\n') + '\n';
}
