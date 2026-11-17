# @nestedbit/check

NestedBit's free security checks, for your terminal and CI:

- **`rls`** lints Supabase migrations for row-level security gaps: tables anyone with your public key can read or change, policies that let any signed-in user write any row, `user_metadata` in policies, `security definer` views and functions, open storage buckets, and slow policies.
- **`mcp`** checks an MCP server's sign-in (OAuth discovery, PKCE, token checks), session handling and tools, or reviews a saved `tools/list` response for risky tools.

They're the same engines as the [Supabase RLS checker](https://nestedbit.com/tools/supabase-rls-generator) and [MCP Security Checker](https://nestedbit.com/tools/mcp-security-checker) on nestedbit.com. Everything runs where you run it. Nothing is sent to NestedBit, and `rls` never connects to a database: it reads your SQL files.

## Command line

Needs Node 22 or later.

```bash
npx @nestedbit/check rls supabase/migrations
```

```bash
npx @nestedbit/check mcp http://localhost:3000/mcp
```

```bash
npx @nestedbit/check mcp --tools tools-list.json
```

`rls` takes folders (their `.sql` files are read in name order, the way Supabase applies `supabase/migrations`) and `.sql` files. The SQL is read as one script, so a table created in one migration and secured in a later one counts as secured. Each finding points at the file and line it came from. It also takes the `.json` the catalog query on the RLS checker page returns, which has your project's real grants and policies.

`mcp` checks a running server from your machine, so `http://localhost`, private networks and staging behind a VPN all work (the hosted checker only reaches public HTTPS addresses). Plain HTTP is fine locally; the report notes it.

### Options

| Option | |
|---|---|
| `--format text\|json\|github` | `text` (default) for people, `json` for scripts, `github` for GitHub Actions annotations. |
| `--fail-on error\|warning\|notice\|never` | Exit 1 when any finding is at or above this level. Default `error`. |

Exit codes: `0` nothing at or above `--fail-on`, `1` findings at or above it (or an MCP server that couldn't be checked), `2` bad arguments or files, `3` the check itself failed.

## GitHub Action

Findings show as annotations on the pull request's lines, with a table on the job's summary page.

```yaml
name: Security checks
on: pull_request

jobs:
  rls:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: nestedbit/check@v1
        with:
          rls: supabase/migrations
```

To check an MCP server, start it in an earlier step and pass its address:

```yaml
      - run: npm ci && (npm start &) && npx wait-on http://localhost:3000/health
      - uses: nestedbit/check@v1
        with:
          mcp: http://localhost:3000/mcp
          fail-on: warning
```

| Input | |
|---|---|
| `rls` | Folders or `.sql`/`.json` files, one per line or separated by spaces. |
| `mcp` | A running MCP server's URL. |
| `tools` | A saved `tools/list` response to review. |
| `fail-on` | `error` (default), `warning`, `notice` or `never`. |

Outputs: `errors`, `warnings` and `notices`, the number of findings at each level.

## What it can't see

`rls` reads settings, not your app's code. Where your SQL sets no grants, it assumes Supabase's defaults. A clean result means the settings it can read look right, not that the app is secure. The `tools` review reads each tool's name, description, schema and annotations, not what its code does.

If you'd like a person to look, NestedBit does [security reviews](https://nestedbit.com/contact) of Supabase and MCP apps.

## Developing

- `src/cli.ts` and `src/action.ts`: the command and the Action. `src/bin/` holds their entry points.
- `src/rls.ts`, `src/mcp.ts`: run the engines and turn their results into findings.
- `src/findings.ts`: text, JSON, GitHub annotations and the summary table.
- `engine/`: the checks themselves, copied from the code behind nestedbit.com's tools so both give the same results.

```bash
npm install
npm test            # node --test, against fixtures and a local MCP server
npm run build       # esbuild → dist/cli.js and dist/action.js, no runtime dependencies
```

`dist/` is committed because the Action runs `dist/action.js` from a checkout. Found a false positive or a missed issue? [Open an issue](https://github.com/nestedbit/check/issues) with the SQL or the server's response.

## License

MIT
