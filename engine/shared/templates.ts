// Starting points for the access model, one per industry NestedBit serves.
// Each is a plain description turned into a model by build(), so it reads
// like the matrix it produces.

import { newId, setGrant, type AccessModel, type Scope } from './access-model.ts';

interface Spec {
  name: string;
  multiTenant: boolean;
  /** Role name → names of roles it inherits from. */
  roles: [string, string[]][];
  /** Resource name → actions. */
  resources: [string, string[]][];
  /** Role name → resource name → actions it may take; "own:" marks own-records-only. */
  grants: Record<string, Record<string, string[]>>;
}

function build(spec: Spec): AccessModel {
  const roles = spec.roles.map(([name]) => ({ id: newId('role'), name, inherits: [] as string[] }));
  const roleId = (name: string) => roles.find((r) => r.name === name)!.id;
  spec.roles.forEach(([, parents], i) => (roles[i].inherits = parents.map(roleId)));
  const resources = spec.resources.map(([name, actions]) => ({ id: newId('res'), name, actions }));
  const model: AccessModel = { name: spec.name, multiTenant: spec.multiTenant, roles, resources, grants: {} };
  for (const [role, byResource] of Object.entries(spec.grants)) {
    for (const [resource, actions] of Object.entries(byResource)) {
      const resourceId = resources.find((r) => r.name === resource)!.id;
      for (const entry of actions) {
        const scope: Scope = entry.startsWith('own:') ? 'own' : 'any';
        setGrant(model, roleId(role), resourceId, entry.replace(/^own:/, ''), scope);
      }
    }
  }
  return model;
}

export interface Template {
  id: string;
  name: string;
  build: () => AccessModel;
}

export const TEMPLATES: Template[] = [
  {
    id: 'saas',
    name: 'SaaS product, with an AI assistant',
    build: () =>
      build({
        name: 'SaaS product',
        multiTenant: true,
        roles: [
          ['Owner', ['Admin']],
          ['Admin', ['Member']],
          ['Member', ['Viewer']],
          ['Viewer', []],
          ['Billing', []],
          ['AI assistant', []],
        ],
        resources: [
          ['Project', ['read', 'create', 'update', 'delete']],
          ['Document', ['read', 'create', 'update', 'delete', 'share']],
          ['Member', ['read', 'invite', 'remove', 'change_role']],
          ['Billing', ['read', 'update']],
        ],
        grants: {
          Owner: { Billing: ['read', 'update'] },
          Admin: {
            Project: ['update', 'delete'],
            Document: ['update', 'delete', 'share'],
            Member: ['read', 'invite', 'remove', 'change_role'],
          },
          Member: { Project: ['create'], Document: ['create', 'own:update', 'own:delete', 'own:share'] },
          Viewer: { Project: ['read'], Document: ['read'] },
          Billing: { Billing: ['read', 'update'], Member: ['read'] },
          'AI assistant': { Project: ['read'], Document: ['read', 'create', 'own:update'] },
        },
      }),
  },
  {
    id: 'ecommerce',
    name: 'E-commerce store',
    build: () =>
      build({
        name: 'E-commerce store',
        multiTenant: false,
        roles: [
          ['Admin', ['Store manager']],
          ['Store manager', ['Support agent']],
          ['Support agent', []],
          ['Warehouse', []],
          ['Customer', []],
        ],
        resources: [
          ['Product', ['read', 'create', 'update', 'delete']],
          ['Order', ['read', 'create', 'update', 'cancel', 'refund']],
          ['Customer', ['read', 'update', 'delete']],
          ['Discount', ['read', 'create', 'update', 'delete']],
        ],
        grants: {
          Admin: { Customer: ['delete'] },
          'Store manager': {
            Product: ['create', 'update', 'delete'],
            Order: ['refund'],
            Discount: ['read', 'create', 'update', 'delete'],
          },
          'Support agent': { Product: ['read'], Order: ['read', 'update', 'cancel'], Customer: ['read', 'update'] },
          Warehouse: { Product: ['read'], Order: ['read', 'update'] },
          Customer: {
            Product: ['read'],
            Order: ['own:read', 'own:create', 'own:cancel'],
            Customer: ['own:read', 'own:update'],
          },
        },
      }),
  },
  {
    id: 'finance',
    name: 'Finance: expenses and approvals',
    build: () =>
      build({
        name: 'Expenses and approvals',
        multiTenant: false,
        roles: [
          ['Admin', ['Finance', 'Manager']],
          ['Finance', []],
          ['Manager', ['Employee']],
          ['Employee', []],
          ['Auditor', []],
        ],
        resources: [
          ['Expense', ['read', 'create', 'update', 'submit', 'approve', 'pay']],
          ['Invoice', ['read', 'create', 'update', 'approve', 'pay']],
          ['Report', ['read', 'export']],
        ],
        grants: {
          Admin: { Invoice: ['approve'] },
          Finance: { Expense: ['read', 'pay'], Invoice: ['read', 'create', 'update', 'pay'], Report: ['read', 'export'] },
          Manager: { Expense: ['read', 'approve'], Report: ['read'] },
          Employee: { Expense: ['own:read', 'own:create', 'own:update', 'own:submit'] },
          Auditor: { Expense: ['read'], Invoice: ['read'], Report: ['read', 'export'] },
        },
      }),
  },
  {
    id: 'agency',
    name: 'Agency with client access',
    build: () =>
      build({
        name: 'Agency',
        multiTenant: false,
        roles: [
          ['Owner', ['Account manager']],
          ['Account manager', ['Contributor']],
          ['Contributor', []],
          ['Client', []],
        ],
        resources: [
          ['Client', ['read', 'create', 'update']],
          ['Project', ['read', 'create', 'update', 'delete']],
          ['Asset', ['read', 'upload', 'update', 'approve', 'delete']],
          ['Invoice', ['read', 'create', 'send']],
        ],
        grants: {
          Owner: { Project: ['delete'] },
          'Account manager': {
            Client: ['read', 'create', 'update'],
            Project: ['create', 'update'],
            Asset: ['update', 'approve', 'delete'],
            Invoice: ['read', 'create', 'send'],
          },
          Contributor: { Project: ['read'], Asset: ['read', 'upload', 'own:update'] },
          Client: { Project: ['own:read'], Asset: ['own:read', 'own:approve'], Invoice: ['own:read'] },
        },
      }),
  },
  {
    id: 'blank',
    name: 'Blank: two roles, one resource',
    build: () =>
      build({
        name: 'My app',
        multiTenant: false,
        roles: [
          ['Admin', ['Member']],
          ['Member', []],
        ],
        resources: [['Item', ['read', 'create', 'update', 'delete']]],
        grants: {
          Admin: { Item: ['update', 'delete'] },
          Member: { Item: ['read', 'create', 'own:update', 'own:delete'] },
        },
      }),
  },
];
