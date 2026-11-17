// The nestedbit-check command, bundled to dist/cli.js. The logic is in ../cli.ts.

import { run } from '../cli.ts';

process.exitCode = await run(process.argv.slice(2), {
  out: (t) => process.stdout.write(t),
  err: (t) => process.stderr.write(t),
  color: Boolean(process.stdout.isTTY) && !process.env.NO_COLOR,
  cwd: process.cwd(),
});
