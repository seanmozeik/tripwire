import { type Segment, hasBypass } from '../lib/bash';
import { type Decision, allow, deny, warn } from '../lib/decision';

// Opinionated tooling enforcement. Hard-deny on the package managers and
// Tools the user has explicitly replaced (npm/pip/patch-package); soft-warn
// Suggesting modern equivalents (find→fd, grep→rg).
//
// Hard-deny rationale (from the user's CLAUDE.md): TypeScript is bun-only,
// Python is uv-only. Slipping into npm or pip mid-session means the
// Agent forgot the toolchain and is about to install into the wrong
// Directory or make a lockfile bun can't read.

interface Policy {
  readonly rule: string;
  readonly action: 'deny' | 'warn';
  readonly message: string;
  readonly fires: (seg: Segment) => boolean;
}

const POLICIES: readonly Policy[] = [
  // ── HARD DENIES: wrong package manager ───────────────────────────────
  {
    rule: 'use-bun-not-npm',
    action: 'deny',
    message:
      'Use `bun` instead of `npm`. Translations: `npm install` → `bun install`, `npm install <pkg>` → `bun add <pkg>`, `npm install -D <pkg>` → `bun add -d <pkg>`, `npm run X` → `bun run X` (or `bun X` for bin scripts), `npm test` → `bun test`. If you genuinely need npm (publishing to a registry that requires it, working in a different repo), append ` # tripwire-allow: <reason>` to the command.',
    fires: (seg) => seg.head === 'npm',
  },
  {
    rule: 'use-bunx-not-npx',
    action: 'deny',
    message: 'Use `bunx` instead of `npx`. Same usage shape, faster, no implicit npm cache.',
    fires: (seg) => seg.head === 'npx',
  },
  {
    rule: 'use-bun-not-pnpm',
    action: 'deny',
    message: 'Use `bun` instead of `pnpm`. The user is bun-only across their repos.',
    fires: (seg) => seg.head === 'pnpm',
  },
  {
    rule: 'use-bun-not-yarn',
    action: 'deny',
    message: 'Use `bun` instead of `yarn`. The user is bun-only.',
    fires: (seg) => seg.head === 'yarn',
  },
  {
    rule: 'use-uv-not-pip',
    action: 'deny',
    message:
      'Use `uv` instead of `pip`. Translations: `pip install <pkg>` → `uv add <pkg>` (project dependency) or `uv pip install <pkg>` (env-only escape hatch). `pip freeze` → `uv pip freeze`. `pip list` → `uv pip list`. The user is uv-only across Python repos.',
    fires: (seg) => seg.head === 'pip' || seg.head === 'pip3',
  },
  {
    rule: 'use-uv-sync-not-venv',
    action: 'deny',
    message:
      '`python -m venv` creates a bare venv; use `uv sync` instead. uv sync creates the venv AND installs from pyproject.toml + uv.lock in one atomic step. To activate: `source .venv/bin/activate` after.',
    fires: (seg) =>
      (seg.head === 'python' || seg.head === 'python3') &&
      seg.tokens.includes('-m') &&
      seg.tokens.includes('venv'),
  },
  {
    rule: 'uv-sync-over-uv-venv',
    action: 'deny',
    message:
      'Use `uv sync` instead of `uv venv`. `uv venv` creates an empty venv that you then have to populate; `uv sync` creates the venv AND resolves+installs from pyproject.toml + uv.lock in one step. The only reason to use `uv venv` standalone is when there is no pyproject.toml — and in that case, `uv init` first.',
    fires: (seg) => seg.head === 'uv' && seg.tokens[1] === 'venv',
  },
  {
    rule: 'use-bun-patch-not-patch-package',
    action: 'deny',
    message:
      'Use `bun patch` instead of `patch-package`. Bun has built-in patch support that integrates with bun.lock; patch-package is npm-era and produces patches in a different format.',
    fires: (seg) => seg.head === 'patch-package',
  },

  // ── SOFT WARNS: modern equivalents the user has installed ────────────────
  {
    rule: 'consider-fd',
    action: 'warn',
    message:
      'Consider `fd` instead of `find`. Faster, simpler syntax, respects .gitignore by default. Examples: `find . -name "*.ts"` → `fd -e ts`, `find . -type f -name "X"` → `fd -t f X`, `find PATH ...` → `fd ... PATH`. The user has both installed; either works.',
    fires: (seg) => seg.head === 'find',
  },
  {
    rule: 'consider-rg',
    action: 'warn',
    message:
      'Consider `rg` (ripgrep) instead of `grep`. Faster; recurses by default; respects .gitignore by default (use `-u`/`-uu` to include ignored/hidden files); searches the CWD when no path is given. NOT a clean flag-for-flag swap; some flags differ or are unneeded. Carry over fine: `-i`, `-n`, `-v`, `-l`, `-c`. WATCH OUT: `-r` is NOT recursive in rg — it means `--replace` (rg already recurses), so `rg -rn "PATTERN" dir/` silently parses as `--replace=n` and rewrites every match to the literal "n" while exiting 0. Drop the `-r`: `grep -rn PATTERN .` → `rg -n PATTERN`. And `grep --include`/`--exclude` become `rg -g GLOB`/`-g !GLOB`.',
    fires: (seg) => seg.head === 'grep' || seg.head === 'egrep' || seg.head === 'fgrep',
  },
  {
    rule: 'consider-btop',
    action: 'warn',
    message: 'Consider `btop` instead of `top`. Better UI, more info, modern.',
    fires: (seg) => seg.head === 'top',
  },
  {
    rule: 'consider-dust',
    action: 'warn',
    message: 'Consider `dust` instead of `du -sh`. Sorted, colorful, faster.',
    fires: (seg) => seg.head === 'du',
  },
  {
    rule: 'consider-duf',
    action: 'warn',
    message: 'Consider `duf` instead of `df -h`. Better formatting, more readable.',
    fires: (seg) => seg.head === 'df',
  },
  {
    rule: 'consider-procs',
    action: 'warn',
    message: 'Consider `procs` instead of `ps aux`. Better filtering and output.',
    fires: (seg) => seg.head === 'ps',
  },
];

const bashToolPolicy = (segments: readonly Segment[], cmd: string): Decision => {
  if (hasBypass(cmd)) {
    return allow('bash-tool-policy');
  }
  for (const seg of segments) {
    for (const p of POLICIES) {
      if (p.fires(seg)) {
        return p.action === 'deny' ? deny(p.rule, p.message) : warn(p.rule, p.message);
      }
    }
  }
  return allow('bash-tool-policy');
};

export { bashToolPolicy };
