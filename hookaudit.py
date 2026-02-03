#!/usr/bin/env python3
"""hookaudit — Git Hook Security Auditor.

Scans git hook configurations for supply chain attack patterns.
Audits .pre-commit-config.yaml, .git/hooks/, husky, lint-staged,
and lefthook configs for malicious code, untrusted sources,
unpinned versions, and dangerous commands.

Zero dependencies. Python 3.9+.

Usage:
    hookaudit [PATH]              Scan project (default: current dir)
    hookaudit --json              JSON output
    hookaudit --check [GRADE]     CI mode (exit 1 if below grade)
    hookaudit --verbose           Show fix suggestions
    hookaudit --list-rules        List all rules
    hookaudit --severity LEVEL    Minimum severity to report
    hookaudit --ignore R1,R2      Skip specific rules
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


__version__ = "0.1.0"

# ── Severity ──────────────────────────────────────────────────────────────────

class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    _order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    @classmethod
    def weight(cls, s: str) -> int:
        return cls._order.get(s, 0)


# ── Finding ───────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: Optional[int] = None
    context: Optional[str] = None
    fix: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
        }
        if self.line is not None:
            d["line"] = self.line
        if self.context:
            d["context"] = self.context
        if self.fix:
            d["fix"] = self.fix
        return d


# ── Rules ─────────────────────────────────────────────────────────────────────

RULES: dict[str, dict] = {
    "HK001": {
        "name": "shell-injection",
        "severity": Severity.CRITICAL,
        "description": "Shell injection pattern in hook (curl|bash, eval, exec)",
    },
    "HK002": {
        "name": "reverse-shell",
        "severity": Severity.CRITICAL,
        "description": "Reverse shell or backdoor pattern detected",
    },
    "HK003": {
        "name": "data-exfiltration",
        "severity": Severity.CRITICAL,
        "description": "Data exfiltration pattern (POST with sensitive data)",
    },
    "HK004": {
        "name": "credential-access",
        "severity": Severity.CRITICAL,
        "description": "Hook accesses credential files (.ssh, .aws, .gnupg, keychain)",
    },
    "HK005": {
        "name": "unpinned-rev",
        "severity": Severity.HIGH,
        "description": "Hook repo uses tag/branch instead of pinned SHA commit",
    },
    "HK006": {
        "name": "untrusted-repo",
        "severity": Severity.HIGH,
        "description": "Hook from unverified/unknown repository source",
    },
    "HK007": {
        "name": "local-hook-danger",
        "severity": Severity.HIGH,
        "description": "Local hook definition contains dangerous commands",
    },
    "HK008": {
        "name": "hidden-payload",
        "severity": Severity.HIGH,
        "description": "Base64 decoding, obfuscated code, or hidden payload",
    },
    "HK009": {
        "name": "missing-rev",
        "severity": Severity.MEDIUM,
        "description": "Hook repo has no pinned version (uses latest)",
    },
    "HK010": {
        "name": "filesystem-escape",
        "severity": Severity.MEDIUM,
        "description": "Hook accesses files outside repository boundary",
    },
    "HK011": {
        "name": "sudo-usage",
        "severity": Severity.MEDIUM,
        "description": "Hook uses sudo or privilege escalation",
    },
    "HK012": {
        "name": "network-access",
        "severity": Severity.MEDIUM,
        "description": "Hook makes network requests (curl, wget, fetch)",
    },
    "HK013": {
        "name": "file-modification",
        "severity": Severity.MEDIUM,
        "description": "Hook modifies or deletes files in unexpected ways",
    },
    "HK014": {
        "name": "env-manipulation",
        "severity": Severity.MEDIUM,
        "description": "Hook manipulates environment variables or PATH",
    },
    "HK015": {
        "name": "hook-bypass",
        "severity": Severity.LOW,
        "description": "Hook can be bypassed (--no-verify, SKIP mentioned)",
    },
    "HK016": {
        "name": "excessive-hooks",
        "severity": Severity.LOW,
        "description": "Large number of hooks increases attack surface",
    },
    "HK017": {
        "name": "embedded-secret",
        "severity": Severity.HIGH,
        "description": "Hardcoded secret or API key in hook configuration",
    },
    "HK018": {
        "name": "dangerous-language",
        "severity": Severity.MEDIUM,
        "description": "Hook uses language with high exploitation risk for hooks",
    },
    "HK019": {
        "name": "git-hook-script",
        "severity": Severity.INFO,
        "description": "Custom git hook script found in .git/hooks/",
    },
    "HK020": {
        "name": "writable-hooks-dir",
        "severity": Severity.MEDIUM,
        "description": "Hooks directory is world-writable",
    },
}


# ── Trusted Sources ───────────────────────────────────────────────────────────

TRUSTED_ORGS = {
    "pre-commit",
    "pre-commit-hooks",
    "mirrors-",
    "psf",
    "python",
    "astral-sh",
    "PyCQA",
    "google",
    "jumanjihouse",
    "Lucas-C",
    "commitizen-tools",
    "compilerla",
    "adrienverge",
    "sqlfluff",
    "koalaman",
    "rhysd",
    "igorshubovych",
    "alessandrojcm",
    "gitleaks",
    "trufflesecurity",
    "zricethezav",
    "thoughtworks",
    "awslabs",
    "antonbabenko",
    "gruntwork-io",
    "bridgecrewio",
    "cisagov",
    "DavidAnson",
    "markdownlint",
    "hadolint",
    "shellcheck-py",
}

TRUSTED_DOMAINS = {
    "github.com",
    "gitlab.com",
}

# SHA pattern: 40 hex chars
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# ── Dangerous Patterns ────────────────────────────────────────────────────────

SHELL_INJECTION_PATTERNS = [
    (r"curl\s+.*\|\s*(ba)?sh", "curl piped to shell"),
    (r"wget\s+.*\|\s*(ba)?sh", "wget piped to shell"),
    (r"curl\s+.*\|\s*python", "curl piped to python"),
    (r"\beval\s*\(", "eval() call"),
    (r"\beval\s+[\"'\$]", "shell eval"),
    (r"\bexec\s*\(", "exec() call"),
    (r"\bexec\s+[\"'\$]", "shell exec"),
    (r"python\s+-c\s+['\"].*(?:import|exec|eval)", "python -c with code execution"),
    (r"node\s+-e\s+['\"].*(?:require|child_process|exec)", "node -e with code execution"),
    (r"ruby\s+-e\s+['\"].*(?:system|exec|`)", "ruby -e with code execution"),
    (r"perl\s+-e\s+['\"].*(?:system|exec|`)", "perl -e with code execution"),
    (r"\bsource\s+/dev/tcp/", "bash /dev/tcp source (network)"),
    (r">\s*/dev/tcp/", "bash /dev/tcp redirect"),
]

REVERSE_SHELL_PATTERNS = [
    (r"/dev/tcp/\d", "bash reverse shell via /dev/tcp"),
    (r"nc\s+(-e|-c)\s+", "netcat reverse shell"),
    (r"ncat\s+(-e|-c)\s+", "ncat reverse shell"),
    (r"mkfifo\s+.*\bsh\b", "named pipe shell redirect"),
    (r"socket\s*\.\s*socket.*connect", "Python socket connect"),
    (r"subprocess.*shell\s*=\s*True", "subprocess with shell=True"),
    (r"os\.system\s*\(", "os.system call"),
    (r"child_process.*exec", "Node child_process exec"),
    (r"socat\s+.*exec:", "socat exec"),
    (r"\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}", "hex-encoded shellcode"),
]

EXFILTRATION_PATTERNS = [
    (r"curl\s+.*(-d|--data)\s+.*(\$|`|\.env|\.ssh|\.aws|password|secret|token|key)", "curl POST with sensitive data"),
    (r"curl\s+.*(-X\s+POST|-X\s+PUT)\s+.*(\$|`)", "curl POST/PUT with variables"),
    (r"wget\s+.*--post-(data|file)", "wget POST data"),
    (r"cat\s+.*\|\s*curl", "file contents piped to curl"),
    (r"tar\s+.*\|\s*(curl|nc|ncat)", "archive piped to network tool"),
    (r"zip\s+.*\|\s*(curl|nc|ncat)", "compressed data to network"),
    (r"base64\s+.*\|\s*curl", "encoded data to curl"),
    (r"(\$HOME|~/)\.(ssh|aws|gnupg|config).*curl", "credential file to curl"),
]

CREDENTIAL_ACCESS_PATTERNS = [
    (r"(cat|head|tail|less|more|grep)\s+.*\.(ssh|aws|gnupg)/", "reading credential directory"),
    (r"(cat|head|tail)\s+.*/\.env\b", "reading .env file"),
    (r"(cat|head|tail)\s+.*/(credentials|token|secret|password|\.netrc)", "reading credentials file"),
    (r"\$HOME/\.(ssh|aws|gnupg|config/gcloud|azure|kube)", "accessing credential path"),
    (r"~/\.(ssh|aws|gnupg|config/gcloud|azure|kube)", "accessing credential path"),
    (r"security\s+find-(generic|internet)-password", "macOS keychain access"),
    (r"security\s+export\s", "macOS keychain export"),
    (r"/etc/(shadow|passwd|sudoers)", "system credential file access"),
    (r"git\s+config\s+.*credential", "git credential access"),
    (r"gh\s+auth\s+token", "GitHub CLI token access"),
    (r"npm\s+token", "npm token access"),
]

HIDDEN_PAYLOAD_PATTERNS = [
    (r"base64\s+(-d|--decode)", "base64 decode execution"),
    (r"echo\s+.*\|\s*base64\s+-d", "echo to base64 decode"),
    (r"(\\x[0-9a-f]{2}){4,}", "hex-encoded payload"),
    (r"(\\u[0-9a-f]{4}){4,}", "unicode-encoded payload"),
    (r"printf\s+.*\\x[0-9a-f]", "printf hex payload"),
    (r"xxd\s+-r", "xxd reverse hex dump"),
    (r"\$\(\s*echo\s+.*\|\s*rev\s*\)", "reversed string execution"),
    (r"String\.fromCharCode\s*\(", "JS string from char codes"),
]

SECRET_PATTERNS = [
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub personal access token"),
    (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth token"),
    (r"github_pat_[a-zA-Z0-9_]{22,}", "GitHub PAT (fine-grained)"),
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API key"),
    (r"sk-proj-[a-zA-Z0-9_-]+", "OpenAI project key"),
    (r"sk-ant-[a-zA-Z0-9_-]+", "Anthropic API key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"xoxb-[0-9]+-[a-zA-Z0-9]+", "Slack bot token"),
    (r"xoxp-[0-9]+-[a-zA-Z0-9]+", "Slack user token"),
    (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "SendGrid API key"),
    (r"sk_live_[a-zA-Z0-9]{24,}", "Stripe secret key"),
    (r"rk_live_[a-zA-Z0-9]{24,}", "Stripe restricted key"),
    (r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\sKEY-----", "Private key"),
    (r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.", "JWT token"),
]

FILESYSTEM_ESCAPE_PATTERNS = [
    (r"\.\./\.\.", "directory traversal (../..)"),
    (r"(?:^|\s)/(?:etc|var|tmp|usr|opt|root|home)\b", "absolute system path access"),
    (r"\$HOME(?!/\.|/\.local)", "HOME directory access"),
    (r"~/(?!\.|\.local)", "home directory access"),
    (r"(?:^|\s)/\s", "root directory reference"),
]

SUDO_PATTERNS = [
    (r"\bsudo\s+", "sudo usage"),
    (r"\bsu\s+-", "su switch user"),
    (r"\bdoas\s+", "doas usage"),
    (r"chmod\s+[0-7]*7[0-7]*\s+", "chmod world-writable"),
    (r"chmod\s+u\+s\s+", "setuid bit"),
    (r"chown\s+root", "chown to root"),
]

NETWORK_PATTERNS = [
    (r"\bcurl\s+", "curl request"),
    (r"\bwget\s+", "wget request"),
    (r"\bfetch\s*\(", "fetch() call"),
    (r"http\.request", "HTTP request"),
    (r"requests\.(get|post|put|patch|delete)", "Python requests call"),
    (r"urllib\.request", "Python urllib request"),
    (r"http\.client", "Python http.client"),
    (r"\bnc\s+", "netcat"),
    (r"\bnmap\s+", "nmap scan"),
    (r"socket\.\w+\(", "socket connection"),
]

FILE_MOD_PATTERNS = [
    (r"rm\s+-rf?\s+/", "recursive delete from root"),
    (r"rm\s+-rf?\s+\*", "recursive delete wildcard"),
    (r"rm\s+-rf?\s+\$", "recursive delete variable"),
    (r">\s*/dev/null\s*2>&1\s*&", "silenced background process"),
    (r"mktemp.*&&.*rm", "temp file race condition"),
    (r"truncate\s+-s\s*0", "file truncation"),
]

ENV_MANIPULATION_PATTERNS = [
    (r"export\s+PATH=", "PATH modification"),
    (r"export\s+LD_PRELOAD=", "LD_PRELOAD injection"),
    (r"export\s+LD_LIBRARY_PATH=", "LD_LIBRARY_PATH modification"),
    (r"export\s+PYTHONPATH=", "PYTHONPATH modification"),
    (r"export\s+NODE_PATH=", "NODE_PATH modification"),
    (r"export\s+GIT_.*=", "GIT environment modification"),
    (r"unset\s+(PATH|HOME|USER|SHELL)", "critical env var unset"),
]


# ── YAML Parser (minimal, for pre-commit config) ─────────────────────────────

def parse_yaml_simple(text: str) -> list[dict]:
    """Parse a .pre-commit-config.yaml file into a list of repo entries.
    
    This is a purpose-built parser for pre-commit config files, not a general
    YAML parser. It handles the specific structure: repos list with repo/rev/hooks.
    """
    repos = []
    current_repo: dict | None = None
    current_hook: dict | None = None
    in_repos = False
    in_hooks = False
    in_additional_deps = False
    in_args = False
    
    lines = text.split("\n")
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # Skip comments and empty lines
        if not stripped or stripped.startswith("#"):
            continue
        
        # Detect repos: section
        if stripped == "repos:" or stripped.startswith("repos:"):
            in_repos = True
            continue
        
        if not in_repos:
            continue
        
        # Detect new repo entry
        if stripped.startswith("- repo:"):
            if current_hook and current_repo:
                current_repo.setdefault("hooks", []).append(current_hook)
            if current_repo:
                repos.append(current_repo)
            repo_url = stripped[len("- repo:"):].strip().strip("'\"")
            current_repo = {"repo": repo_url, "hooks": [], "_line": i}
            current_hook = None
            in_hooks = False
            in_additional_deps = False
            in_args = False
            continue
        
        if current_repo is None:
            continue
        
        # Detect rev:
        if stripped.startswith("rev:") and not in_hooks:
            rev = stripped[len("rev:"):].strip().strip("'\"")
            current_repo["rev"] = rev
            continue
        
        # Detect hooks: section
        if stripped == "hooks:" or stripped.startswith("hooks:"):
            in_hooks = True
            in_additional_deps = False
            in_args = False
            continue
        
        if in_hooks:
            # New hook entry
            if stripped.startswith("- id:"):
                if current_hook:
                    current_repo["hooks"].append(current_hook)
                hook_id = stripped[len("- id:"):].strip().strip("'\"")
                current_hook = {"id": hook_id, "_line": i}
                in_additional_deps = False
                in_args = False
                continue
            
            if current_hook:
                # Hook properties
                if stripped.startswith("name:"):
                    current_hook["name"] = stripped[len("name:"):].strip().strip("'\"")
                elif stripped.startswith("entry:"):
                    current_hook["entry"] = stripped[len("entry:"):].strip().strip("'\"")
                elif stripped.startswith("language:"):
                    current_hook["language"] = stripped[len("language:"):].strip().strip("'\"")
                elif stripped.startswith("types:") or stripped.startswith("types_or:"):
                    pass  # Ignore types for security analysis
                elif stripped.startswith("stages:"):
                    stages_val = stripped.split(":", 1)[1].strip()
                    if stages_val.startswith("["):
                        stages = [s.strip().strip("'\"") for s in stages_val.strip("[]").split(",")]
                        current_hook["stages"] = stages
                elif stripped.startswith("args:"):
                    in_args = True
                    in_additional_deps = False
                    args_val = stripped.split(":", 1)[1].strip()
                    if args_val.startswith("["):
                        args = [s.strip().strip("'\"") for s in args_val.strip("[]").split(",")]
                        current_hook["args"] = args
                        in_args = False
                    else:
                        current_hook.setdefault("args", [])
                elif stripped.startswith("additional_dependencies:"):
                    in_additional_deps = True
                    in_args = False
                    current_hook.setdefault("additional_dependencies", [])
                elif stripped.startswith("- ") and in_additional_deps:
                    dep = stripped[2:].strip().strip("'\"")
                    current_hook.setdefault("additional_dependencies", []).append(dep)
                elif stripped.startswith("- ") and in_args:
                    arg = stripped[2:].strip().strip("'\"")
                    current_hook.setdefault("args", []).append(arg)
                elif stripped.startswith("files:"):
                    current_hook["files"] = stripped.split(":", 1)[1].strip().strip("'\"")
                elif stripped.startswith("exclude:"):
                    current_hook["exclude"] = stripped.split(":", 1)[1].strip().strip("'\"")
                elif stripped.startswith("always_run:"):
                    val = stripped.split(":", 1)[1].strip().lower()
                    current_hook["always_run"] = val in ("true", "yes")
                elif stripped.startswith("pass_filenames:"):
                    val = stripped.split(":", 1)[1].strip().lower()
                    current_hook["pass_filenames"] = val in ("true", "yes")
                elif stripped.startswith("require_serial:"):
                    val = stripped.split(":", 1)[1].strip().lower()
                    current_hook["require_serial"] = val in ("true", "yes")
                elif stripped.startswith("verbose:"):
                    val = stripped.split(":", 1)[1].strip().lower()
                    current_hook["verbose"] = val in ("true", "yes")
    
    # Flush last entries
    if current_hook and current_repo:
        current_repo["hooks"].append(current_hook)
    if current_repo:
        repos.append(current_repo)
    
    return repos


# ── Scanners ──────────────────────────────────────────────────────────────────

def scan_text_for_patterns(
    text: str,
    patterns: list[tuple[str, str]],
    rule_id: str,
    severity: str,
    file_path: str,
    prefix: str = "",
) -> list[Finding]:
    """Scan text lines for regex patterns."""
    findings = []
    seen = set()
    
    for i, line in enumerate(text.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for pattern, desc in patterns:
            if re.search(pattern, stripped, re.IGNORECASE):
                key = (rule_id, desc, file_path, i)
                if key not in seen:
                    seen.add(key)
                    msg = f"{prefix}{desc}" if prefix else desc
                    findings.append(Finding(
                        rule_id=rule_id,
                        severity=severity,
                        message=msg,
                        file=file_path,
                        line=i,
                        context=stripped[:120],
                    ))
    return findings


def scan_precommit_config(path: Path, ignored: set[str]) -> list[Finding]:
    """Scan .pre-commit-config.yaml for security issues."""
    findings = []
    
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return findings
    
    repos = parse_yaml_simple(text)
    rel_path = str(path)
    
    total_hooks = 0
    
    for repo_entry in repos:
        repo_url = repo_entry.get("repo", "")
        rev = repo_entry.get("rev", "")
        repo_line = repo_entry.get("_line", 0)
        hooks = repo_entry.get("hooks", [])
        total_hooks += len(hooks)
        
        # Skip meta/local repos for some checks
        is_local = repo_url in ("local", "meta")
        
        if not is_local:
            # HK009: Missing rev
            if "HK009" not in ignored and not rev:
                findings.append(Finding(
                    rule_id="HK009",
                    severity=Severity.MEDIUM,
                    message=f"No version pinned for repo: {repo_url}",
                    file=rel_path,
                    line=repo_line,
                    fix="Add 'rev:' with a specific tag or SHA commit hash",
                ))
            
            # HK005: Unpinned rev (not SHA)
            if "HK005" not in ignored and rev and not SHA_RE.match(rev):
                findings.append(Finding(
                    rule_id="HK005",
                    severity=Severity.HIGH,
                    message=f"Repo uses tag/branch '{rev}' instead of pinned SHA: {repo_url}",
                    file=rel_path,
                    line=repo_line,
                    context=f"rev: {rev}",
                    fix=f"Pin to a full SHA commit hash: `pre-commit autoupdate --freeze`",
                ))
            
            # HK006: Untrusted repo
            if "HK006" not in ignored:
                is_trusted = False
                for domain in TRUSTED_DOMAINS:
                    if domain in repo_url:
                        # Check org/owner
                        parts = repo_url.split("/")
                        for part in parts:
                            for org in TRUSTED_ORGS:
                                if org.startswith("mirrors-"):
                                    if part.startswith("mirrors-"):
                                        is_trusted = True
                                        break
                                elif part.lower() == org.lower():
                                    is_trusted = True
                                    break
                            if is_trusted:
                                break
                
                if not is_trusted and repo_url not in ("local", "meta"):
                    findings.append(Finding(
                        rule_id="HK006",
                        severity=Severity.HIGH,
                        message=f"Hook from unverified repository: {repo_url}",
                        file=rel_path,
                        line=repo_line,
                        fix="Verify the repository is maintained by a trusted organization. Consider forking to your org.",
                    ))
        
        # Scan hooks
        for hook in hooks:
            hook_id = hook.get("id", "unknown")
            hook_line = hook.get("_line", repo_line)
            entry = hook.get("entry", "")
            language = hook.get("language", "")
            
            # For local hooks, scan entry for dangerous patterns
            if is_local and entry:
                # HK007: Local hook with dangerous commands
                if "HK007" not in ignored:
                    for pattern, desc in SHELL_INJECTION_PATTERNS:
                        if re.search(pattern, entry, re.IGNORECASE):
                            findings.append(Finding(
                                rule_id="HK007",
                                severity=Severity.HIGH,
                                message=f"Local hook '{hook_id}' has dangerous entry: {desc}",
                                file=rel_path,
                                line=hook_line,
                                context=entry[:120],
                                fix="Review the hook entry command for safety",
                            ))
                            break
                
                # HK001: Shell injection in entry
                if "HK001" not in ignored:
                    for pattern, desc in SHELL_INJECTION_PATTERNS:
                        if re.search(pattern, entry, re.IGNORECASE):
                            findings.append(Finding(
                                rule_id="HK001",
                                severity=Severity.CRITICAL,
                                message=f"Shell injection in local hook '{hook_id}': {desc}",
                                file=rel_path,
                                line=hook_line,
                                context=entry[:120],
                            ))
                            break
                
                # HK004: Credential access in entry
                if "HK004" not in ignored:
                    for pattern, desc in CREDENTIAL_ACCESS_PATTERNS:
                        if re.search(pattern, entry, re.IGNORECASE):
                            findings.append(Finding(
                                rule_id="HK004",
                                severity=Severity.CRITICAL,
                                message=f"Hook '{hook_id}' accesses credentials: {desc}",
                                file=rel_path,
                                line=hook_line,
                                context=entry[:120],
                            ))
                            break
            
            # HK018: Dangerous language for hooks
            if "HK018" not in ignored and language in ("system", "script", "docker"):
                findings.append(Finding(
                    rule_id="HK018",
                    severity=Severity.MEDIUM,
                    message=f"Hook '{hook_id}' uses '{language}' language (high exploitation risk)",
                    file=rel_path,
                    line=hook_line,
                    fix=f"'{language}' hooks run arbitrary commands. Verify the source carefully.",
                ))
            
            # Scan args for dangerous patterns
            args = hook.get("args", [])
            args_text = " ".join(str(a) for a in args)
            if args_text:
                if "HK001" not in ignored:
                    for pattern, desc in SHELL_INJECTION_PATTERNS:
                        if re.search(pattern, args_text, re.IGNORECASE):
                            findings.append(Finding(
                                rule_id="HK001",
                                severity=Severity.CRITICAL,
                                message=f"Shell injection in hook '{hook_id}' args: {desc}",
                                file=rel_path,
                                line=hook_line,
                                context=args_text[:120],
                            ))
                            break
    
    # HK016: Excessive hooks
    if "HK016" not in ignored and total_hooks > 20:
        findings.append(Finding(
            rule_id="HK016",
            severity=Severity.LOW,
            message=f"Large number of hooks ({total_hooks}) increases attack surface",
            file=rel_path,
            fix="Review whether all hooks are necessary. Each hook is a potential supply chain vector.",
        ))
    
    # Scan full text for secrets
    if "HK017" not in ignored:
        findings.extend(scan_text_for_patterns(
            text, SECRET_PATTERNS, "HK017", Severity.HIGH,
            rel_path, prefix="Embedded secret in config: ",
        ))
    
    return findings


def scan_git_hooks_dir(hooks_dir: Path, ignored: set[str]) -> list[Finding]:
    """Scan .git/hooks/ directory for custom hook scripts."""
    findings = []
    
    if not hooks_dir.is_dir():
        return findings
    
    # HK020: Check directory permissions
    if "HK020" not in ignored:
        try:
            mode = hooks_dir.stat().st_mode
            if mode & stat.S_IWOTH:
                findings.append(Finding(
                    rule_id="HK020",
                    severity=Severity.MEDIUM,
                    message="Hooks directory is world-writable",
                    file=str(hooks_dir),
                    fix="chmod 755 .git/hooks/",
                ))
        except OSError:
            pass
    
    # Known git hook names
    hook_names = {
        "pre-commit", "prepare-commit-msg", "commit-msg", "post-commit",
        "pre-rebase", "post-rewrite", "post-checkout", "post-merge",
        "pre-push", "pre-receive", "update", "post-receive",
        "post-update", "push-to-checkout", "pre-auto-gc",
        "fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist",
        "p4-post-changelist", "p4-pre-submit", "sendemail-validate",
        "applypatch-msg", "pre-applypatch", "post-applypatch",
        "reference-transaction",
    }
    
    for item in sorted(hooks_dir.iterdir()):
        if not item.is_file():
            continue
        
        name = item.name
        
        # Skip .sample files
        if name.endswith(".sample"):
            continue
        
        rel_path = str(item)
        
        # HK019: Custom hook found
        if "HK019" not in ignored and name in hook_names:
            findings.append(Finding(
                rule_id="HK019",
                severity=Severity.INFO,
                message=f"Custom git hook script: {name}",
                file=rel_path,
            ))
        
        # Read and scan the script
        try:
            text = item.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            continue
        
        # HK001: Shell injection
        if "HK001" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, SHELL_INJECTION_PATTERNS, "HK001", Severity.CRITICAL,
                rel_path, prefix="Shell injection in hook: ",
            ))
        
        # HK002: Reverse shell
        if "HK002" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, REVERSE_SHELL_PATTERNS, "HK002", Severity.CRITICAL,
                rel_path, prefix="Reverse shell pattern: ",
            ))
        
        # HK003: Data exfiltration
        if "HK003" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, EXFILTRATION_PATTERNS, "HK003", Severity.CRITICAL,
                rel_path, prefix="Data exfiltration: ",
            ))
        
        # HK004: Credential access
        if "HK004" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, CREDENTIAL_ACCESS_PATTERNS, "HK004", Severity.CRITICAL,
                rel_path, prefix="Credential access: ",
            ))
        
        # HK008: Hidden payload
        if "HK008" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, HIDDEN_PAYLOAD_PATTERNS, "HK008", Severity.HIGH,
                rel_path, prefix="Hidden payload: ",
            ))
        
        # HK010: Filesystem escape
        if "HK010" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, FILESYSTEM_ESCAPE_PATTERNS, "HK010", Severity.MEDIUM,
                rel_path, prefix="Filesystem escape: ",
            ))
        
        # HK011: Sudo
        if "HK011" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, SUDO_PATTERNS, "HK011", Severity.MEDIUM,
                rel_path, prefix="Privilege escalation: ",
            ))
        
        # HK012: Network access
        if "HK012" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, NETWORK_PATTERNS, "HK012", Severity.MEDIUM,
                rel_path, prefix="Network access: ",
            ))
        
        # HK013: File modification
        if "HK013" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, FILE_MOD_PATTERNS, "HK013", Severity.MEDIUM,
                rel_path, prefix="Dangerous file operation: ",
            ))
        
        # HK014: Env manipulation
        if "HK014" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, ENV_MANIPULATION_PATTERNS, "HK014", Severity.MEDIUM,
                rel_path, prefix="Environment manipulation: ",
            ))
        
        # HK017: Secrets
        if "HK017" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, SECRET_PATTERNS, "HK017", Severity.HIGH,
                rel_path, prefix="Embedded secret: ",
            ))
    
    return findings


def scan_husky(project_dir: Path, ignored: set[str]) -> list[Finding]:
    """Scan Husky git hook configuration (.husky/ directory)."""
    findings = []
    
    husky_dir = project_dir / ".husky"
    if not husky_dir.is_dir():
        return findings
    
    hook_files = [
        "pre-commit", "commit-msg", "pre-push", "post-checkout",
        "post-commit", "post-merge", "pre-rebase",
    ]
    
    for name in hook_files:
        hook_file = husky_dir / name
        if not hook_file.is_file():
            continue
        
        rel_path = str(hook_file)
        
        try:
            text = hook_file.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            continue
        
        # HK019: Hook found
        if "HK019" not in ignored:
            findings.append(Finding(
                rule_id="HK019",
                severity=Severity.INFO,
                message=f"Husky hook script: {name}",
                file=rel_path,
            ))
        
        # Scan for all patterns
        if "HK001" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, SHELL_INJECTION_PATTERNS, "HK001", Severity.CRITICAL,
                rel_path, prefix="Shell injection in husky hook: ",
            ))
        if "HK002" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, REVERSE_SHELL_PATTERNS, "HK002", Severity.CRITICAL,
                rel_path, prefix="Reverse shell in husky hook: ",
            ))
        if "HK003" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, EXFILTRATION_PATTERNS, "HK003", Severity.CRITICAL,
                rel_path, prefix="Exfiltration in husky hook: ",
            ))
        if "HK004" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, CREDENTIAL_ACCESS_PATTERNS, "HK004", Severity.CRITICAL,
                rel_path, prefix="Credential access in husky hook: ",
            ))
        if "HK008" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, HIDDEN_PAYLOAD_PATTERNS, "HK008", Severity.HIGH,
                rel_path, prefix="Hidden payload in husky hook: ",
            ))
        if "HK011" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, SUDO_PATTERNS, "HK011", Severity.MEDIUM,
                rel_path, prefix="Privilege escalation in husky hook: ",
            ))
        if "HK012" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, NETWORK_PATTERNS, "HK012", Severity.MEDIUM,
                rel_path, prefix="Network access in husky hook: ",
            ))
        if "HK013" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, FILE_MOD_PATTERNS, "HK013", Severity.MEDIUM,
                rel_path, prefix="Dangerous file op in husky hook: ",
            ))
        if "HK014" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, ENV_MANIPULATION_PATTERNS, "HK014", Severity.MEDIUM,
                rel_path, prefix="Env manipulation in husky hook: ",
            ))
        if "HK017" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, SECRET_PATTERNS, "HK017", Severity.HIGH,
                rel_path, prefix="Embedded secret in husky hook: ",
            ))
    
    # Also check _/ directory (husky v9+)
    husky_internal = husky_dir / "_"
    if husky_internal.is_dir():
        for item in sorted(husky_internal.iterdir()):
            if not item.is_file():
                continue
            try:
                text = item.read_text(encoding="utf-8", errors="replace")
            except (OSError, PermissionError):
                continue
            rel_path = str(item)
            if "HK001" not in ignored:
                findings.extend(scan_text_for_patterns(
                    text, SHELL_INJECTION_PATTERNS, "HK001", Severity.CRITICAL,
                    rel_path, prefix="Shell injection in husky internal: ",
                ))
    
    return findings


def scan_lefthook(project_dir: Path, ignored: set[str]) -> list[Finding]:
    """Scan lefthook configuration (lefthook.yml / lefthook-local.yml)."""
    findings = []
    
    lefthook_files = ["lefthook.yml", "lefthook-local.yml", ".lefthook.yml"]
    
    for fname in lefthook_files:
        fpath = project_dir / fname
        if not fpath.is_file():
            continue
        
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            continue
        
        rel_path = str(fpath)
        
        # HK019: Lefthook config found
        if "HK019" not in ignored:
            findings.append(Finding(
                rule_id="HK019",
                severity=Severity.INFO,
                message=f"Lefthook configuration: {fname}",
                file=rel_path,
            ))
        
        # Scan for dangerous patterns in run: commands
        if "HK001" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, SHELL_INJECTION_PATTERNS, "HK001", Severity.CRITICAL,
                rel_path, prefix="Shell injection in lefthook: ",
            ))
        if "HK002" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, REVERSE_SHELL_PATTERNS, "HK002", Severity.CRITICAL,
                rel_path, prefix="Reverse shell in lefthook: ",
            ))
        if "HK003" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, EXFILTRATION_PATTERNS, "HK003", Severity.CRITICAL,
                rel_path, prefix="Exfiltration in lefthook: ",
            ))
        if "HK004" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, CREDENTIAL_ACCESS_PATTERNS, "HK004", Severity.CRITICAL,
                rel_path, prefix="Credential access in lefthook: ",
            ))
        if "HK008" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, HIDDEN_PAYLOAD_PATTERNS, "HK008", Severity.HIGH,
                rel_path, prefix="Hidden payload in lefthook: ",
            ))
        if "HK011" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, SUDO_PATTERNS, "HK011", Severity.MEDIUM,
                rel_path, prefix="Privilege escalation in lefthook: ",
            ))
        if "HK012" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, NETWORK_PATTERNS, "HK012", Severity.MEDIUM,
                rel_path, prefix="Network access in lefthook: ",
            ))
        if "HK017" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, SECRET_PATTERNS, "HK017", Severity.HIGH,
                rel_path, prefix="Embedded secret in lefthook: ",
            ))
    
    return findings


def scan_lint_staged(project_dir: Path, ignored: set[str]) -> list[Finding]:
    """Scan lint-staged configuration (package.json, .lintstagedrc*)."""
    findings = []
    
    # Check package.json for lint-staged config
    pkg_json = project_dir / "package.json"
    if pkg_json.is_file():
        try:
            text = pkg_json.read_text(encoding="utf-8", errors="replace")
            data = json.loads(text)
            lint_staged = data.get("lint-staged", {})
            if lint_staged:
                # Scan commands in lint-staged config
                for glob_pattern, commands in lint_staged.items():
                    if isinstance(commands, str):
                        commands = [commands]
                    if isinstance(commands, list):
                        for cmd in commands:
                            if not isinstance(cmd, str):
                                continue
                            # Check for dangerous commands
                            if "HK001" not in ignored:
                                for pattern, desc in SHELL_INJECTION_PATTERNS:
                                    if re.search(pattern, cmd, re.IGNORECASE):
                                        findings.append(Finding(
                                            rule_id="HK001",
                                            severity=Severity.CRITICAL,
                                            message=f"Shell injection in lint-staged ({glob_pattern}): {desc}",
                                            file=str(pkg_json),
                                            context=cmd[:120],
                                        ))
                                        break
                            if "HK004" not in ignored:
                                for pattern, desc in CREDENTIAL_ACCESS_PATTERNS:
                                    if re.search(pattern, cmd, re.IGNORECASE):
                                        findings.append(Finding(
                                            rule_id="HK004",
                                            severity=Severity.CRITICAL,
                                            message=f"Credential access in lint-staged ({glob_pattern}): {desc}",
                                            file=str(pkg_json),
                                            context=cmd[:120],
                                        ))
                                        break
        except (json.JSONDecodeError, OSError, PermissionError):
            pass
    
    # Check standalone lint-staged configs
    lint_staged_files = [
        ".lintstagedrc", ".lintstagedrc.json", ".lintstagedrc.yaml",
        ".lintstagedrc.yml", ".lintstagedrc.mjs", ".lintstagedrc.cjs",
        "lint-staged.config.js", "lint-staged.config.mjs", "lint-staged.config.cjs",
    ]
    
    for fname in lint_staged_files:
        fpath = project_dir / fname
        if not fpath.is_file():
            continue
        
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            continue
        
        rel_path = str(fpath)
        
        if "HK001" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, SHELL_INJECTION_PATTERNS, "HK001", Severity.CRITICAL,
                rel_path, prefix="Shell injection in lint-staged config: ",
            ))
        if "HK004" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, CREDENTIAL_ACCESS_PATTERNS, "HK004", Severity.CRITICAL,
                rel_path, prefix="Credential access in lint-staged config: ",
            ))
        if "HK017" not in ignored:
            findings.extend(scan_text_for_patterns(
                text, SECRET_PATTERNS, "HK017", Severity.HIGH,
                rel_path, prefix="Embedded secret in lint-staged config: ",
            ))
    
    return findings


def scan_overcommit(project_dir: Path, ignored: set[str]) -> list[Finding]:
    """Scan overcommit configuration (.overcommit.yml)."""
    findings = []
    
    overcommit = project_dir / ".overcommit.yml"
    if not overcommit.is_file():
        return findings
    
    try:
        text = overcommit.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return findings
    
    rel_path = str(overcommit)
    
    if "HK019" not in ignored:
        findings.append(Finding(
            rule_id="HK019",
            severity=Severity.INFO,
            message="Overcommit configuration found",
            file=rel_path,
        ))
    
    if "HK001" not in ignored:
        findings.extend(scan_text_for_patterns(
            text, SHELL_INJECTION_PATTERNS, "HK001", Severity.CRITICAL,
            rel_path, prefix="Shell injection in overcommit: ",
        ))
    if "HK004" not in ignored:
        findings.extend(scan_text_for_patterns(
            text, CREDENTIAL_ACCESS_PATTERNS, "HK004", Severity.CRITICAL,
            rel_path, prefix="Credential access in overcommit: ",
        ))
    if "HK017" not in ignored:
        findings.extend(scan_text_for_patterns(
            text, SECRET_PATTERNS, "HK017", Severity.HIGH,
            rel_path, prefix="Embedded secret in overcommit: ",
        ))
    
    return findings


# ── Grading ───────────────────────────────────────────────────────────────────

def calculate_grade(findings: list[Finding]) -> tuple[str, int]:
    """Calculate A-F grade from findings."""
    score = 100
    
    for f in findings:
        sev = f.severity
        if sev == Severity.CRITICAL:
            score -= 25
        elif sev == Severity.HIGH:
            score -= 15
        elif sev == Severity.MEDIUM:
            score -= 8
        elif sev == Severity.LOW:
            score -= 3
        # INFO doesn't affect score
    
    score = max(0, score)
    
    if score >= 97:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    
    return grade, score


# ── Output Formatters ─────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91m",  # Red
    Severity.HIGH: "\033[93m",      # Yellow
    Severity.MEDIUM: "\033[33m",    # Orange-ish
    Severity.LOW: "\033[36m",       # Cyan
    Severity.INFO: "\033[90m",      # Gray
}
RESET = "\033[0m"
BOLD = "\033[1m"

SEVERITY_SYMBOLS = {
    Severity.CRITICAL: "✖",
    Severity.HIGH: "✖",
    Severity.MEDIUM: "▲",
    Severity.LOW: "●",
    Severity.INFO: "ℹ",
}


def format_text(
    findings: list[Finding],
    grade: str,
    score: int,
    verbose: bool = False,
    use_color: bool = True,
) -> str:
    """Format findings as human-readable text."""
    lines = []
    
    # Header
    if use_color:
        lines.append(f"\n{BOLD}hookaudit{RESET} — Git Hook Security Auditor\n")
    else:
        lines.append("\nhookaudit — Git Hook Security Auditor\n")
    
    # Grade
    grade_color = ""
    if use_color:
        if score >= 90:
            grade_color = "\033[92m"  # Green
        elif score >= 70:
            grade_color = "\033[93m"  # Yellow
        elif score >= 50:
            grade_color = "\033[33m"  # Orange
        else:
            grade_color = "\033[91m"  # Red
    
    if use_color:
        lines.append(f"  Grade: {grade_color}{BOLD}{grade}{RESET} ({score}/100)")
    else:
        lines.append(f"  Grade: {grade} ({score}/100)")
    
    # Summary counts
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    
    summary_parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if sev in counts:
            if use_color:
                summary_parts.append(f"{SEVERITY_COLORS[sev]}{counts[sev]} {sev.lower()}{RESET}")
            else:
                summary_parts.append(f"{counts[sev]} {sev.lower()}")
    
    if summary_parts:
        lines.append(f"  Findings: {', '.join(summary_parts)}")
    else:
        lines.append("  Findings: none")
    
    lines.append("")
    
    # Findings
    if findings:
        # Group by file
        by_file: dict[str, list[Finding]] = {}
        for f in findings:
            by_file.setdefault(f.file, []).append(f)
        
        for file_path, file_findings in by_file.items():
            if use_color:
                lines.append(f"  {BOLD}{file_path}{RESET}")
            else:
                lines.append(f"  {file_path}")
            
            for f in sorted(file_findings, key=lambda x: Severity.weight(x.severity), reverse=True):
                sym = SEVERITY_SYMBOLS.get(f.severity, "●")
                if use_color:
                    color = SEVERITY_COLORS.get(f.severity, "")
                    line_info = f":{f.line}" if f.line else ""
                    lines.append(f"    {color}{sym}{RESET} [{f.rule_id}] {f.message}{line_info}")
                else:
                    line_info = f":{f.line}" if f.line else ""
                    lines.append(f"    {sym} [{f.rule_id}] {f.message}{line_info}")
                
                if f.context:
                    ctx = f.context
                    if len(ctx) > 80:
                        ctx = ctx[:77] + "..."
                    lines.append(f"      → {ctx}")
                
                if verbose and f.fix:
                    if use_color:
                        lines.append(f"      {BOLD}Fix:{RESET} {f.fix}")
                    else:
                        lines.append(f"      Fix: {f.fix}")
            
            lines.append("")
    else:
        lines.append("  ✓ No security issues found in git hooks\n")
    
    return "\n".join(lines)


def format_json(findings: list[Finding], grade: str, score: int) -> str:
    """Format findings as JSON."""
    data = {
        "tool": "hookaudit",
        "version": __version__,
        "grade": grade,
        "score": score,
        "total_findings": len(findings),
        "by_severity": {},
        "findings": [f.to_dict() for f in findings],
    }
    
    for f in findings:
        data["by_severity"][f.severity] = data["by_severity"].get(f.severity, 0) + 1
    
    return json.dumps(data, indent=2)


# ── Main ──────────────────────────────────────────────────────────────────────

def scan_project(project_dir: Path, ignored: set[str]) -> list[Finding]:
    """Run all scanners on a project directory."""
    findings = []
    
    # 1. .pre-commit-config.yaml
    precommit_config = project_dir / ".pre-commit-config.yaml"
    if precommit_config.is_file():
        findings.extend(scan_precommit_config(precommit_config, ignored))
    
    # Also check alternate name
    precommit_config_alt = project_dir / ".pre-commit-config.yml"
    if precommit_config_alt.is_file():
        findings.extend(scan_precommit_config(precommit_config_alt, ignored))
    
    # 2. .git/hooks/
    git_hooks = project_dir / ".git" / "hooks"
    if git_hooks.is_dir():
        findings.extend(scan_git_hooks_dir(git_hooks, ignored))
    
    # 3. Husky
    findings.extend(scan_husky(project_dir, ignored))
    
    # 4. Lefthook
    findings.extend(scan_lefthook(project_dir, ignored))
    
    # 5. lint-staged
    findings.extend(scan_lint_staged(project_dir, ignored))
    
    # 6. Overcommit
    findings.extend(scan_overcommit(project_dir, ignored))
    
    # 7. Check for core.hooksPath in git config
    git_config = project_dir / ".git" / "config"
    if git_config.is_file():
        try:
            text = git_config.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"hooksPath\s*=\s*(.+)", text)
            if match:
                hooks_path = match.group(1).strip()
                custom_hooks = Path(hooks_path)
                if not custom_hooks.is_absolute():
                    custom_hooks = project_dir / hooks_path
                if custom_hooks.is_dir() and custom_hooks != git_hooks:
                    findings.extend(scan_git_hooks_dir(custom_hooks, ignored))
                
                # Warn about custom hooks path
                if "HK010" not in ignored:
                    findings.append(Finding(
                        rule_id="HK010",
                        severity=Severity.MEDIUM,
                        message=f"Custom core.hooksPath configured: {hooks_path}",
                        file=str(git_config),
                        fix="Verify the custom hooks path is trusted and version-controlled",
                    ))
        except (OSError, PermissionError):
            pass
    
    return findings


def list_rules() -> str:
    """List all rules."""
    lines = ["\nhookaudit — Rule Reference\n"]
    for rule_id in sorted(RULES):
        r = RULES[rule_id]
        lines.append(f"  {rule_id}  [{r['severity']:8s}]  {r['name']}: {r['description']}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hookaudit",
        description="Git Hook Security Auditor — scan hook configs for supply chain risks",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Project directory to scan (default: current dir)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--check", nargs="?", const="B", metavar="GRADE",
                       help="CI mode: exit 1 if below grade (default: B)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show fix suggestions")
    parser.add_argument("--list-rules", action="store_true", help="List all rules")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                       help="Minimum severity to report")
    parser.add_argument("--ignore", help="Comma-separated rule IDs to skip")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument("--version", action="version", version=f"hookaudit {__version__}")
    
    args = parser.parse_args(argv)
    
    if args.list_rules:
        print(list_rules())
        return 0
    
    project_dir = Path(args.path).resolve()
    if not project_dir.is_dir():
        print(f"Error: {args.path} is not a directory", file=sys.stderr)
        return 2
    
    ignored = set()
    if args.ignore:
        ignored = {r.strip().upper() for r in args.ignore.split(",")}
    
    # Scan
    findings = scan_project(project_dir, ignored)
    
    # Filter by severity
    if args.severity:
        min_weight = Severity.weight(args.severity)
        findings = [f for f in findings if Severity.weight(f.severity) >= min_weight]
    
    # Sort by severity (critical first), then file, then line
    findings.sort(key=lambda f: (-Severity.weight(f.severity), f.file, f.line or 0))
    
    # Grade
    grade, score = calculate_grade(findings)
    
    # Output
    use_color = not args.no_color and sys.stdout.isatty() and not args.json
    
    if args.json:
        print(format_json(findings, grade, score))
    else:
        print(format_text(findings, grade, score, verbose=args.verbose, use_color=use_color))
    
    # CI mode
    if args.check:
        threshold = args.check.upper()
        grade_order = {"A+": 6, "A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
        if grade_order.get(grade, 0) < grade_order.get(threshold, 0):
            return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
