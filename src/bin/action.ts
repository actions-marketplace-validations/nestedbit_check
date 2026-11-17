// The GitHub Action's entry point, bundled to dist/action.js. The logic is in ../action.ts.

import { appendFileSync } from 'node:fs';
import { runAction } from '../action.ts';

process.exitCode = await runAction({
  out: (t) => process.stdout.write(t),
  append: (file, text) => appendFileSync(file, text),
  env: process.env,
  cwd: process.cwd(),
});
