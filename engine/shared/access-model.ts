// The access model behind NestedBit's permission tools: roles, resources,
// the actions on each resource, and which role may take which action, on any
// record or only its own. One model renders to a matrix, to policy code for
// Casbin, OPA (Rego), Cedar and Postgres row-level security, and is checked
// for the mistakes that make role systems hard to live with.
//
// Pure TypeScript with no DOM: the tools run it in the browser, the MCP server
// (mcp.ts) runs it on its host, and the later generators (Supabase, Kubernetes,
// Firestore) reuse it.

export type Scope = 'any' | 'own';

export interface Role {
  /** Stable internal key; exports use the name. */
  id: string;
  name: string;
  /** Ids of roles whose permissions this role also gets. */
  inherits: string[];
}

export interface Resource {
  id: string;
  name: string;
  actions: string[];
}

export interface AccessModel {
  name: string;
  roles: Role[];
  resources: Resource[];
  /** Direct grants: role id → resource id → action → scope. */
  grants: Record<string, Record<string, Record<string, Scope>>>;
  /** Records belong to a tenant (an organization), and roles apply within it. */
  multiTenant: boolean;
}

// ---------------------------------------------------------------------------
// Names and identifiers

/** "Store manager" → "store_manager". */
export function snake(name: string): string {
  return (
    name
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '') || 'unnamed'
  );
}

/** "purchase order" → "PurchaseOrder", for Cedar entity types. */
export function pascal(name: string): string {
  const id = snake(name)
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join('');
  return /^[A-Za-z]/.test(id) ? id : `T${id}`;
}

/** "read, update , delete" → ["read", "update", "delete"], deduplicated. */
export function parseActions(text: string): string[] {
  return [...new Set(text.split(',').map(snake).filter((a) => a !== 'unnamed'))];
}

let counter = 0;
export function newId(prefix: string): string {
  counter += 1;
  return `${prefix}${Date.now().toString(36)}${counter}`;
}

// ---------------------------------------------------------------------------
// Editing

export function getGrant(model: AccessModel, roleId: string, resourceId: string, action: string): Scope | undefined {
  return model.grants[roleId]?.[resourceId]?.[action];
}

/** Sets or clears one direct grant. Mutates the model. */
export function setGrant(
  model: AccessModel,
  roleId: string,
  resourceId: string,
  action: string,
  scope: Scope | undefined,
): void {
  const byResource = (model.grants[roleId] ??= {});
  const byAction = (byResource[resourceId] ??= {});
  if (scope) byAction[action] = scope;
  else delete byAction[action];
}

/** Drops grants for roles, resources or actions that no longer exist. Mutates the model. */
export function prune(model: AccessModel): void {
  const roleIds = new Set(model.roles.map((r) => r.id));
  for (const roleId of Object.keys(model.grants)) {
    if (!roleIds.has(roleId)) {
      delete model.grants[roleId];
      continue;
    }
    for (const resourceId of Object.keys(model.grants[roleId])) {
      const resource = model.resources.find((r) => r.id === resourceId);
      if (!resource) {
        delete model.grants[roleId][resourceId];
        continue;
      }
      for (const action of Object.keys(model.grants[roleId][resourceId])) {
        if (!resource.actions.includes(action)) delete model.grants[roleId][resourceId][action];
      }
    }
  }
  for (const role of model.roles) role.inherits = role.inherits.filter((id) => roleIds.has(id) && id !== role.id);
}

// ---------------------------------------------------------------------------
// Inheritance and effective permissions

/** Every role a role inherits from, directly or through others. Safe with cycles. */
export function ancestors(model: AccessModel, roleId: string): string[] {
  const seen = new Set<string>();
  const stack = [...(model.roles.find((r) => r.id === roleId)?.inherits ?? [])];
  while (stack.length > 0) {
    const id = stack.pop()!;
    if (seen.has(id) || id === roleId) continue;
    seen.add(id);
    stack.push(...(model.roles.find((r) => r.id === id)?.inherits ?? []));
  }
  return [...seen];
}

/** Roles that inherit from themselves, through any chain. */
export function cyclicRoles(model: AccessModel): Role[] {
  return model.roles.filter((role) => {
    const seen = new Set<string>();
    const stack = [...role.inherits];
    while (stack.length > 0) {
      const id = stack.pop()!;
      if (id === role.id) return true;
      if (seen.has(id)) continue;
      seen.add(id);
      stack.push(...(model.roles.find((r) => r.id === id)?.inherits ?? []));
    }
    return false;
  });
}

export interface EffectiveGrant {
  scope: Scope;
  /** The role the grant comes from: the role itself, or one it inherits. */
  from: string;
}

const wider = (a: Scope | undefined, b: Scope | undefined): Scope | undefined =>
  a === 'any' || b === 'any' ? 'any' : (a ?? b);

/** What a role can actually do on one action, including inherited grants. */
export function effectiveGrant(
  model: AccessModel,
  roleId: string,
  resourceId: string,
  action: string,
): EffectiveGrant | undefined {
  let best: EffectiveGrant | undefined;
  for (const id of [roleId, ...ancestors(model, roleId)]) {
    const scope = getGrant(model, id, resourceId, action);
    if (scope && wider(best?.scope, scope) !== best?.scope) best = { scope, from: id };
  }
  return best;
}

/** The grant a role inherits on one action, ignoring its own direct grant. */
export function inheritedGrant(
  model: AccessModel,
  roleId: string,
  resourceId: string,
  action: string,
): EffectiveGrant | undefined {
  let best: EffectiveGrant | undefined;
  for (const id of ancestors(model, roleId)) {
    const scope = getGrant(model, id, resourceId, action);
    if (scope && wider(best?.scope, scope) !== best?.scope) best = { scope, from: id };
  }
  return best;
}

export interface Permission {
  role: Role;
  resource: Resource;
  action: string;
  scope: Scope;
}

/** Every effective permission, inheritance expanded, in model order. */
export function permissions(model: AccessModel): Permission[] {
  const out: Permission[] = [];
  for (const role of model.roles) {
    for (const resource of model.resources) {
      for (const action of resource.actions) {
        const grant = effectiveGrant(model, role.id, resource.id, action);
        if (grant) out.push({ role, resource, action, scope: grant.scope });
      }
    }
  }
  return out;
}

function signature(model: AccessModel, roleId: string): string[] {
  const out: string[] = [];
  for (const resource of model.resources) {
    for (const action of resource.actions) {
      const grant = effectiveGrant(model, roleId, resource.id, action);
      if (grant) out.push(`${resource.id}:${action}:${grant.scope}`);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Checks

export type Severity = 'error' | 'warning' | 'note';

export interface Check {
  severity: Severity;
  title: string;
  detail: string;
}

const CREATE_ACTION = /^(create|submit|request|add|new|raise)/;
const APPROVE_ACTION = /^(approve|sign_off|authori[sz]e|accept)/;

export function check(model: AccessModel): Check[] {
  const out: Check[] = [];
  const name = (id: string) => model.roles.find((r) => r.id === id)?.name ?? id;

  for (const [kind, list] of [
    ['role', model.roles],
    ['resource', model.resources],
  ] as const) {
    const seen = new Map<string, string>();
    for (const item of list) {
      if (item.name.trim() === '') {
        out.push({ severity: 'error', title: `A ${kind} has no name`, detail: `Name every ${kind}; exports use the names.` });
        continue;
      }
      const key = snake(item.name);
      if (seen.has(key)) {
        out.push({
          severity: 'error',
          title: `Two ${kind}s share the name “${item.name}”`,
          detail: `“${seen.get(key)}” and “${item.name}” become the same identifier in code. Rename one.`,
        });
      } else seen.set(key, item.name);
    }
  }

  for (const resource of model.resources) {
    if (resource.actions.length === 0) {
      out.push({
        severity: 'error',
        title: `${resource.name || 'A resource'} has no actions`,
        detail: 'Add the actions people take on it, such as read, create, update and delete.',
      });
    }
  }

  const cyclic = cyclicRoles(model);
  if (cyclic.length > 0) {
    out.push({
      severity: 'error',
      title: 'Roles inherit from each other in a loop',
      detail: `${cyclic.map((r) => r.name).join(', ')} inherit from one another. Inheritance has to run one way, from broader roles to narrower ones.`,
    });
  }

  const signatures = new Map(model.roles.map((r) => [r.id, signature(model, r.id)]));

  for (const role of model.roles) {
    if (signatures.get(role.id)!.length === 0) {
      out.push({
        severity: 'warning',
        title: `${role.name} can’t do anything`,
        detail: 'A role with no permissions is usually unfinished or unused. Grant it something or remove it.',
      });
    }
  }

  // Identical and near-identical roles.
  const nearPairs: string[] = [];
  for (let i = 0; i < model.roles.length; i++) {
    for (let j = i + 1; j < model.roles.length; j++) {
      const a = model.roles[i];
      const b = model.roles[j];
      const sa = signatures.get(a.id)!;
      const sb = signatures.get(b.id)!;
      if (sa.length === 0 || sb.length === 0) continue;
      const setB = new Set(sb);
      const shared = sa.filter((s) => setB.has(s)).length;
      const diff = sa.length + sb.length - 2 * shared;
      if (diff === 0) {
        out.push({
          severity: 'warning',
          title: `${a.name} and ${b.name} are identical`,
          detail: 'They can do exactly the same things. Merge them, or give each the permissions that set it apart.',
        });
      } else if (diff === 1 && nearPairs.length < 3) {
        nearPairs.push(`${a.name} and ${b.name}`);
      }
    }
  }
  if (nearPairs.length > 0) {
    out.push({
      severity: 'note',
      title: 'Roles that differ by one permission',
      detail: `${nearPairs.join('; ')}. Roles this close often mean a condition, such as ownership or an amount limit, is being modelled as a separate role.`,
    });
  }

  // Actions nobody can take.
  const dead: string[] = [];
  for (const resource of model.resources) {
    for (const action of resource.actions) {
      if (!model.roles.some((r) => effectiveGrant(model, r.id, resource.id, action))) {
        dead.push(`${action} on ${resource.name}`);
      }
    }
  }
  if (dead.length > 0) {
    out.push({
      severity: 'warning',
      title: dead.length === 1 ? `Nobody can ${dead[0]}` : `${dead.length} actions nobody can take`,
      detail:
        dead.length === 1
          ? 'No role has this permission. Grant it to a role, or remove the action.'
          : `${dead.join(', ')}. Grant each to a role, or remove it.`,
    });
  }

  // Separation of duties: the same role can raise and approve.
  for (const role of model.roles) {
    for (const resource of model.resources) {
      const can = (pattern: RegExp) =>
        resource.actions.find((a) => pattern.test(a) && effectiveGrant(model, role.id, resource.id, a));
      const raise = can(CREATE_ACTION);
      const approve = can(APPROVE_ACTION);
      if (raise && approve) {
        out.push({
          severity: 'warning',
          title: `${role.name} can ${raise} and ${approve} ${resource.name}`,
          detail: 'One person could approve their own request. Stop approvers approving their own records in code, or split the duties across roles.',
        });
      }
    }
  }

  // A role that can do everything.
  const all = model.resources.reduce((n, r) => n + r.actions.length, 0);
  if (model.roles.length > 1 && all > 0) {
    for (const role of model.roles) {
      const sig = signatures.get(role.id)!;
      if (sig.length === all && sig.every((s) => s.endsWith(':any'))) {
        out.push({
          severity: 'note',
          title: `${role.name} can do everything`,
          detail: 'Keep the number of people with this role small, and log what they do.',
        });
      }
    }
  }

  // Direct grants that inheritance already covers.
  const redundant: string[] = [];
  for (const role of model.roles) {
    for (const resource of model.resources) {
      for (const action of resource.actions) {
        const direct = getGrant(model, role.id, resource.id, action);
        const inherited = inheritedGrant(model, role.id, resource.id, action);
        if (direct && inherited && wider(direct, inherited.scope) === inherited.scope) {
          redundant.push(`${role.name}: ${action} on ${resource.name} (from ${name(inherited.from)})`);
        }
      }
    }
  }
  if (redundant.length > 0) {
    out.push({
      severity: 'note',
      title: `${redundant.length} direct grant${redundant.length === 1 ? ' is' : 's are'} already inherited`,
      detail: `${redundant.slice(0, 4).join('; ')}${redundant.length > 4 ? '; and more' : ''}. Removing them keeps the model easier to change.`,
    });
  }

  if (model.roles.length > 8) {
    out.push({
      severity: 'note',
      title: `${model.roles.length} roles`,
      detail: 'Role counts tend to grow one exception at a time. Check whether some roles differ only by a condition, such as team, region or ownership, that a rule could express instead.',
    });
  }

  const order: Severity[] = ['error', 'warning', 'note'];
  return out.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
}

// ---------------------------------------------------------------------------
// Exports

const header = (model: AccessModel, comment: string) =>
  [
    `${comment} ${model.name || 'Access model'}: generated by NestedBit's RBAC Matrix Builder`,
    `${comment} https://nestedbit.com/tools/rbac-matrix-builder`,
  ].join('\n');

function csvCell(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

const SCOPE_LABEL: Record<Scope, string> = { any: 'Yes', own: 'Own only' };

/** One row per resource and action, one column per role. Opens in Excel and Sheets. */
export function toCsv(model: AccessModel): string {
  const rows = [['Resource', 'Action', ...model.roles.map((r) => r.name)]];
  for (const resource of model.resources) {
    for (const action of resource.actions) {
      rows.push([
        resource.name,
        action,
        ...model.roles.map((role) => {
          const grant = effectiveGrant(model, role.id, resource.id, action);
          return grant ? SCOPE_LABEL[grant.scope] : '';
        }),
      ]);
    }
  }
  return rows.map((row) => row.map(csvCell).join(',')).join('\n') + '\n';
}

export function toMarkdown(model: AccessModel): string {
  const esc = (s: string) => s.replace(/\|/g, '\\|');
  const lines = [
    `| Resource | Action | ${model.roles.map((r) => esc(r.name)).join(' | ')} |`,
    `| --- | --- | ${model.roles.map(() => ':---:').join(' | ')} |`,
  ];
  for (const resource of model.resources) {
    for (const action of resource.actions) {
      const cells = model.roles.map((role) => {
        const grant = effectiveGrant(model, role.id, resource.id, action);
        return grant ? (grant.scope === 'any' ? '✓' : 'Own') : '';
      });
      lines.push(`| ${esc(resource.name)} | ${action} | ${cells.join(' | ')} |`);
    }
  }
  return `${lines.join('\n')}\n\nOwn: only records the user owns.${model.multiTenant ? ' Every permission applies within the user’s own tenant.' : ''}\n`;
}

/** The model by name, with direct grants and inheritance, for saving or code. */
export function toJson(model: AccessModel): string {
  const roleName = (id: string) => model.roles.find((r) => r.id === id)?.name ?? id;
  const grants: { role: string; resource: string; action: string; scope: Scope }[] = [];
  for (const role of model.roles) {
    for (const resource of model.resources) {
      for (const action of resource.actions) {
        const scope = getGrant(model, role.id, resource.id, action);
        if (scope) grants.push({ role: role.name, resource: resource.name, action, scope });
      }
    }
  }
  return (
    JSON.stringify(
      {
        name: model.name,
        multiTenant: model.multiTenant,
        roles: model.roles.map((r) => ({ name: r.name, inherits: r.inherits.map(roleName) })),
        resources: model.resources.map((r) => ({ name: r.name, actions: r.actions })),
        grants,
      },
      null,
      2,
    ) + '\n'
  );
}

/** Reads a model written by toJson. Throws with a readable message if it can't. */
export function fromJson(text: string): AccessModel {
  const data = JSON.parse(text) as {
    name?: unknown;
    multiTenant?: unknown;
    roles?: { name?: unknown; inherits?: unknown }[];
    resources?: { name?: unknown; actions?: unknown }[];
    grants?: { role?: unknown; resource?: unknown; action?: unknown; scope?: unknown }[];
  };
  if (!Array.isArray(data.roles) || !Array.isArray(data.resources)) {
    throw new Error('Expected an object with "roles" and "resources" arrays, as the JSON export writes.');
  }
  const roles: Role[] = data.roles.map((r) => ({ id: newId('role'), name: String(r.name ?? ''), inherits: [] }));
  const byRoleName = new Map(roles.map((r) => [r.name, r.id]));
  data.roles.forEach((r, i) => {
    roles[i].inherits = (Array.isArray(r.inherits) ? r.inherits : [])
      .map((n) => byRoleName.get(String(n)))
      .filter((id): id is string => id !== undefined);
  });
  const resources: Resource[] = data.resources.map((r) => ({
    id: newId('res'),
    name: String(r.name ?? ''),
    actions: Array.isArray(r.actions) ? parseActions(r.actions.map(String).join(',')) : [],
  }));
  const byResourceName = new Map(resources.map((r) => [r.name, r.id]));
  const model: AccessModel = {
    name: typeof data.name === 'string' ? data.name : 'Imported model',
    multiTenant: data.multiTenant === true,
    roles,
    resources,
    grants: {},
  };
  for (const g of Array.isArray(data.grants) ? data.grants : []) {
    const roleId = byRoleName.get(String(g.role));
    const resourceId = byResourceName.get(String(g.resource));
    const scope = g.scope === 'own' ? 'own' : g.scope === 'any' ? 'any' : undefined;
    if (roleId && resourceId && scope) setGrant(model, roleId, resourceId, snake(String(g.action)), scope);
  }
  prune(model);
  return model;
}

/** Casbin model.conf: roles, optional tenants (domains) and ownership. */
export function toCasbinModel(model: AccessModel): string {
  const tenant = model.multiTenant;
  return `${header(model, '#')}
#
# Inherited permissions are written out in policy.csv, so roles need no
# hierarchy here. Assign users to roles in your app:
#   ${tenant ? 'g, alice, editor, acme' : 'g, alice, editor'}
# The last request value says whether the user owns the object ("true" or
# "false"); policies with the scope "own" need it to be "true":
#   ${tenant ? 'enforce("alice", "acme", "invoice", "update", "true")' : 'enforce("alice", "invoice", "update", "true")'}

[request_definition]
r = sub, ${tenant ? 'dom, ' : ''}obj, act, own

[policy_definition]
p = sub, obj, act, scope

[role_definition]
g = _, _${tenant ? ', _' : ''}

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub${tenant ? ', r.dom' : ''}) && r.obj == p.obj && r.act == p.act && (p.scope == "any" || r.own == "true")
`;
}

/** Casbin policy.csv, one line per effective permission. */
export function toCasbinPolicy(model: AccessModel): string {
  const lines = [header(model, '#'), ''];
  for (const p of permissions(model)) {
    lines.push(`p, ${snake(p.role.name)}, ${snake(p.resource.name)}, ${p.action}, ${p.scope}`);
  }
  return lines.join('\n') + '\n';
}

/** OPA policy in Rego v1 syntax. */
export function toRego(model: AccessModel): string {
  const table: Record<string, Record<string, Record<string, Scope>>> = {};
  for (const p of permissions(model)) {
    ((table[snake(p.role.name)] ??= {})[snake(p.resource.name)] ??= {})[p.action] = p.scope;
  }
  const tenantLine = model.multiTenant ? '\n\tinput.resource.tenant == input.user.tenant' : '';
  const grants = JSON.stringify(table, null, '\t');
  return `${header(model, '#')}
#
# Input:
#   {"user": {"id": "u1", "roles": ["editor"]${model.multiTenant ? ', "tenant": "acme"' : ''}},
#    "action": "update",
#    "resource": {"type": "invoice", "owner": "u1"${model.multiTenant ? ', "tenant": "acme"' : ''}}}

package rbac

import rego.v1

# role -> resource type -> action -> "any" or "own" (inherited permissions included)
grants := ${grants}

default allow := false

allow if {
	some role in input.user.roles
	grants[role][input.resource.type][input.action] == "any"${tenantLine}
}

allow if {
	some role in input.user.roles
	grants[role][input.resource.type][input.action] == "own"
	input.resource.owner == input.user.id${tenantLine}
}
`;
}

/** Cedar policies, one per role, resource and scope. */
export function toCedar(model: AccessModel): string {
  const groups = new Map<string, { role: string; type: string; scope: Scope; actions: string[] }>();
  for (const p of permissions(model)) {
    const key = `${p.role.id}|${p.resource.id}|${p.scope}`;
    const group = groups.get(key) ?? { role: snake(p.role.name), type: pascal(p.resource.name), scope: p.scope, actions: [] };
    group.actions.push(p.action);
    groups.set(key, group);
  }
  const blocks = [...groups.values()].map((g) => {
    const action =
      g.actions.length === 1
        ? `action == Action::"${g.actions[0]}"`
        : `action in [${g.actions.map((a) => `Action::"${a}"`).join(', ')}]`;
    const conditions = [
      ...(g.scope === 'own' ? ['resource.owner == principal'] : []),
      ...(model.multiTenant ? ['resource.tenant == principal.tenant'] : []),
    ];
    const when = conditions.length > 0 ? `\nwhen { ${conditions.join(' && ')} }` : '';
    return `permit (\n  principal in Role::"${g.role}",\n  ${action},\n  resource is ${g.type}\n)${when};`;
  });
  return `${header(model, '//')}
//
// Users are entities whose parents are their Role entities, for example
// User::"alice" in Role::"editor". Resources carry an "owner" attribute${model.multiTenant ? ', and\n// users and resources carry a "tenant" attribute' : ''}.

${blocks.join('\n\n')}
`;
}

export const SQL_COMMANDS: [string, RegExp][] = [
  ['select', /^(read|view|list|get|select|show|browse|search)$/],
  ['insert', /^(create|add|insert|new|upload)$/],
  ['update', /^(update|edit|write|modify|change|rename)$/],
  ['delete', /^(delete|remove|destroy|archive)$/],
];

/** "(a)" when short, else one clause per line, with the tenant check first. */
function sqlCondition(clauses: string[], tenant: boolean): string {
  if (!tenant && clauses.length === 1) return `(${clauses[0]})`;
  const roles = clauses.length === 1 ? clauses[0] : `(\n      ${clauses.join('\n      or ')}\n    )`;
  return tenant ? `(\n    tenant_id = app_tenant_id()\n    and ${roles}\n  )` : `(\n    ${clauses.join('\n    or ')}\n  )`;
}

const quote = (identifier: string) => `"${identifier.replace(/"/g, '""')}"`;
export const literal = (text: string) => `'${text.replace(/'/g, "''")}'`;

/** Postgres row-level security: one policy per table and command. */
export function toPostgresRls(model: AccessModel): string {
  const tenant = model.multiTenant;
  const out = [
    header(model, '--'),
    '--',
    '-- Assumes each table is named after its resource and has an owner_id',
    `-- column${tenant ? ' and a tenant_id column' : ''} (uuid). Your app sets the caller on each transaction:`,
    "--   set local app.user_id = '…';",
    "--   set local app.roles = 'editor,viewer';",
    ...(tenant ? ["--   set local app.tenant_id = '…';"] : []),
    '-- Change the helper functions if your app identifies users another way.',
    '',
    'create or replace function app_user_id() returns uuid',
    '  language sql stable',
    "  as $$ select nullif(current_setting('app.user_id', true), '')::uuid $$;",
    '',
    ...(tenant
      ? [
          'create or replace function app_tenant_id() returns uuid',
          '  language sql stable',
          "  as $$ select nullif(current_setting('app.tenant_id', true), '')::uuid $$;",
          '',
        ]
      : []),
    'create or replace function app_has_role(role_name text) returns boolean',
    '  language sql stable',
    "  as $$ select role_name = any (string_to_array(current_setting('app.roles', true), ',')) $$;",
  ];

  for (const resource of model.resources) {
    const table = snake(resource.name);
    out.push('', `-- ${resource.name}`, `alter table ${quote(table)} enable row level security;`);
    out.push(`alter table ${quote(table)} force row level security;`);

    const unmapped: string[] = [];
    const mapped = new Set<string>();
    const byCommand = new Map<string, string[]>();
    for (const action of resource.actions) {
      const command = SQL_COMMANDS.find(([, pattern]) => pattern.test(action))?.[0];
      if (!command) {
        unmapped.push(action);
        continue;
      }
      mapped.add(command);
      for (const role of model.roles) {
        const grant = effectiveGrant(model, role.id, resource.id, action);
        if (!grant) continue;
        const check = `app_has_role(${literal(snake(role.name))})`;
        const clause = grant.scope === 'own' ? `(${check} and owner_id = app_user_id())` : check;
        const list = byCommand.get(command) ?? [];
        if (!list.includes(clause)) list.push(clause);
        byCommand.set(command, list);
      }
    }

    for (const [command] of SQL_COMMANDS) {
      const clauses = byCommand.get(command);
      if (!clauses) {
        if (mapped.has(command)) out.push(`-- No role may ${command} ${table}, so there is no policy and it is denied.`);
        continue;
      }
      const condition = sqlCondition(clauses, tenant);
      const policy = quote(`${table}_${command}`);
      const using = `using ${condition}`;
      const withCheck = `with check ${condition}`;
      const body =
        command === 'insert' ? withCheck : command === 'update' ? `${using}\n  ${withCheck}` : using;
      out.push(`create policy ${policy} on ${quote(table)} for ${command}\n  ${body};`);
    }
    if (unmapped.length > 0) {
      out.push(`-- ${unmapped.join(', ')}: no SQL command matches, so enforce ${unmapped.length === 1 ? 'it' : 'them'} in your API.`);
    }
  }
  return out.join('\n') + '\n';
}

export interface ExportFormat {
  id: string;
  name: string;
  filename: string;
  mime: string;
  render: (model: AccessModel) => string;
}

export const EXPORTS: ExportFormat[] = [
  { id: 'csv', name: 'CSV', filename: 'rbac-matrix.csv', mime: 'text/csv', render: toCsv },
  { id: 'markdown', name: 'Markdown', filename: 'rbac-matrix.md', mime: 'text/markdown', render: toMarkdown },
  { id: 'json', name: 'JSON', filename: 'rbac-model.json', mime: 'application/json', render: toJson },
  { id: 'casbin-model', name: 'Casbin model', filename: 'model.conf', mime: 'text/plain', render: toCasbinModel },
  { id: 'casbin-policy', name: 'Casbin policy', filename: 'policy.csv', mime: 'text/csv', render: toCasbinPolicy },
  { id: 'rego', name: 'OPA Rego', filename: 'rbac.rego', mime: 'text/plain', render: toRego },
  { id: 'cedar', name: 'Cedar', filename: 'policies.cedar', mime: 'text/plain', render: toCedar },
  { id: 'postgres', name: 'Postgres RLS', filename: 'rls.sql', mime: 'application/sql', render: toPostgresRls },
];
