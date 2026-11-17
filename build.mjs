// Bundles the CLI and the GitHub Action into single files with no dependencies:
// dist/cli.js (the npm bin) and dist/action.js (what action.yml runs). The engines
// come from services/mcp-checker, the same code the site's tools run.

import { readFileSync } from 'node:fs';
import { build } from 'esbuild';

const { version } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

const shared = {
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  define: { __VERSION__: JSON.stringify(version) },
  legalComments: 'none',
  logLevel: 'info',
};

await build({
  ...shared,
  entryPoints: { cli: 'src/bin/cli.ts', action: 'src/bin/action.ts' },
  outdir: 'dist',
  banner: { js: '#!/usr/bin/env node' },
});
