#!/usr/bin/env python3
"""hookaudit - Git Hook & Repository Config Security Auditor.

Scans git hooks, .gitattributes, .gitconfig, Husky configs, and other
hook frameworks for malicious or dangerous patterns. Detects reverse shells,
credential theft, data exfiltration, obfuscated payloads, and more.

Zero dependencies. Stdlib only. Python 3.8+.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

__version__ = "0.1.0"

# ── Severity ────────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> int:
        return {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 8,
            "LOW": 3,
            "INFO": 0,
        }[self.value]


# ── Finding ─────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    file: str
    line: int = 0
    evidence: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "file": self.file,
        }
        if self.line:
            d["line"] = self.line
        if self.evidence:
            d["evidence"] = self.evidence
        return d


# ── Rules ───────────────────────────────────────────────────────────

# HA001: Reverse shell patterns
REVERSE_SHELL_PATTERNS = [
    # Bash reverse shells
    re.compile(r'bash\s+-i\s+>&\s*/dev/tcp/', re.I),
    re.compile(r'bash\s+-i\s+>&\s*/dev/udp/', re.I),
    re.compile(r'/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+', re.I),
    # Netcat reverse shells
    re.compile(r'\bnc\b.*\s-e\s', re.I),
    re.compile(r'\bncat\b.*\s-e\s', re.I),
    re.compile(r'\bnetcat\b.*\s-e\s', re.I),
    re.compile(r'\bnc\b.*\s-c\s', re.I),
    # Python reverse shells
    re.compile(r'python[23]?\s+-c\s+["\'].*socket.*connect', re.I | re.S),
    re.compile(r'import\s+socket.*subprocess.*PIPE', re.I | re.S),
    # Perl reverse shells
    re.compile(r'perl\s+-e\s+["\'].*socket.*exec', re.I | re.S),
    # Ruby reverse shells
    re.compile(r'ruby\s+-rsocket\s+-e', re.I),
    # PHP reverse shells
    re.compile(r'php\s+-r\s+["\'].*fsockopen', re.I),
    # Socat
    re.compile(r'socat\b.*exec.*tcp', re.I),
    # Telnet piped
    re.compile(r'telnet\b.*\|\s*/bin/(ba)?sh', re.I),
    # mkfifo pipe reverse
    re.compile(r'mkfifo\b.*\bnc\b', re.I),
]

# HA002: Credential theft patterns
CREDENTIAL_THEFT_PATTERNS = [
    # SSH keys
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*~/\.ssh/', re.I), "SSH key access"),
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*/\.ssh/', re.I), "SSH key access"),
    # Git credentials
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*\.git-credentials', re.I), "git credential access"),
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*\.gitconfig', re.I), "global gitconfig access"),
    # AWS credentials
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*~/\.aws/', re.I), "AWS credential access"),
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*/\.aws/', re.I), "AWS credential access"),
    # GCP credentials
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*application_default_credentials', re.I), "GCP credential access"),
    # GPG keys
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*~/\.gnupg/', re.I), "GPG key access"),
    # Browser data
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*/Chrome/.*Login\s*Data', re.I), "browser credential access"),
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*/Firefox/.*logins\.json', re.I), "browser credential access"),
    # Keychains
    (re.compile(r'security\s+find-(generic|internet)-password', re.I), "macOS Keychain access"),
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*\.kube/config', re.I), "Kubernetes config access"),
    # npmrc / pypirc / docker
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*\.(npmrc|pypirc|docker/config\.json)', re.I), "package registry credential access"),
    # Generic password files
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*/(passwd|shadow)\b', re.I), "password file access"),
    # Env file exfil
    (re.compile(r'(cat|cp|tar|zip|curl|wget|scp)\b.*\.env\b', re.I), "env file access"),
]

# HA003: Data exfiltration
EXFIL_PATTERNS = [
    # curl/wget POST with data
    (re.compile(r'curl\b.*(-d|--data|--data-binary|--data-raw)\b', re.I), "HTTP POST data exfiltration"),
    (re.compile(r'curl\b.*-X\s*POST', re.I), "HTTP POST exfiltration"),
    (re.compile(r'wget\b.*--post-(data|file)', re.I), "HTTP POST data exfiltration"),
    # DNS exfiltration
    (re.compile(r'(dig|nslookup|host)\b.*\$\(', re.I), "DNS data exfiltration"),
    (re.compile(r'\$\(.*\)\.(.*\.)+\w{2,}', re.I), "DNS data exfiltration"),
    # Netcat data send
    (re.compile(r'\|\s*(nc|ncat|netcat)\b', re.I), "pipe to netcat"),
    # scp/rsync to remote
    (re.compile(r'scp\b.*[^@\s]+@[^:\s]+:', re.I), "SCP to remote host"),
    (re.compile(r'rsync\b.*[^@\s]+@[^:\s]+:', re.I), "rsync to remote host"),
]

# HA004: Download and execute
DOWNLOAD_EXEC_PATTERNS = [
    re.compile(r'curl\b.*\|\s*(ba)?sh\b', re.I),
    re.compile(r'wget\b.*\|\s*(ba)?sh\b', re.I),
    re.compile(r'curl\b.*-o\s+\S+.*&&.*chmod\s+\+x', re.I),
    re.compile(r'wget\b.*-O\s+\S+.*&&.*chmod\s+\+x', re.I),
    re.compile(r'curl\b.*\|\s*python', re.I),
    re.compile(r'wget\b.*\|\s*python', re.I),
    re.compile(r'curl\b.*\|\s*perl', re.I),
    re.compile(r'curl\b.*\|\s*ruby', re.I),
    # Downloading and sourcing
    re.compile(r'curl\b.*>\s*\S+\s*&&?\s*(\.|source)\s', re.I),
]

# HA005: Obfuscated code
OBFUSCATION_PATTERNS = [
    # Base64 decode and execute
    (re.compile(r'base64\s+(-d|--decode)\b.*\|\s*(ba)?sh', re.I), "base64 decode to shell"),
    (re.compile(r'base64\s+(-d|--decode)\b.*\|\s*(python|perl|ruby)', re.I), "base64 decode to interpreter"),
    (re.compile(r'echo\s+\S+\s*\|\s*base64\s+(-d|--decode)', re.I), "base64 payload decoding"),
    # Hex decode
    (re.compile(r'xxd\s+-r\b.*\|\s*(ba)?sh', re.I), "hex decode to shell"),
    (re.compile(r'printf\s+["\']\\x', re.I), "hex-encoded payload"),
    # eval with variable expansion
    (re.compile(r'\beval\s+"\$', re.I), "eval of variable (possible obfuscation)"),
    (re.compile(r'\beval\s+\$\(', re.I), "eval of command substitution"),
    # Python/Perl exec with decode
    (re.compile(r'exec\s*\(\s*(base64|codecs)\b', re.I), "exec with decode"),
    (re.compile(r'__import__\s*\(\s*["\']base64', re.I), "dynamic base64 import"),
    # Deliberate IFS manipulation
    (re.compile(r'IFS\s*=\s*[^$\s]', re.I), "IFS manipulation (obfuscation technique)"),
]

# HA006: Dangerous shell commands
DANGEROUS_CMD_PATTERNS = [
    (re.compile(r'\brm\s+(-rf|--recursive)\s+(/|~/|\$HOME|\${HOME})\s*$', re.M), "recursive delete of home/root"),
    (re.compile(r'\brm\s+(-rf|--recursive)\s+/\S*\s*$', re.M), "recursive delete of system path"),
    (re.compile(r'\bdd\b.*of=/dev/', re.I), "disk overwrite"),
    (re.compile(r'\bmkfs\b', re.I), "filesystem format"),
    (re.compile(r':\(\)\s*\{\s*:\|:&\s*\};\s*:', re.I), "fork bomb"),
    (re.compile(r'>\s*/dev/sd[a-z]', re.I), "direct disk write"),
]

# HA007: Privilege escalation
PRIV_ESC_PATTERNS = [
    (re.compile(r'\bsudo\b', re.I), "sudo usage in hook"),
    (re.compile(r'\bsu\s+-\b', re.I), "su usage in hook"),
    (re.compile(r'chmod\s+[0-7]*4[0-7]{2}\b', re.I), "setuid bit"),
    (re.compile(r'chmod\s+[0-7]*2[0-7]{2}\b', re.I), "setgid bit"),
    (re.compile(r'chmod\s+u\+s\b', re.I), "setuid bit"),
    (re.compile(r'chown\s+root\b', re.I), "changing ownership to root"),
]

# HA008: Environment variable exfiltration
ENV_EXFIL_PATTERNS = [
    (re.compile(r'\benv\b.*\|\s*(curl|wget|nc|ncat)', re.I), "env piped to network"),
    (re.compile(r'\bprintenv\b.*\|\s*(curl|wget|nc|ncat)', re.I), "env piped to network"),
    (re.compile(r'echo\s+\$\w+.*\|\s*(curl|wget|nc|ncat)', re.I), "env var piped to network"),
    (re.compile(r'(curl|wget)\b.*\$\w*(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL|AUTH)', re.I), "secret env var sent to network"),
    (re.compile(r'set\b.*\|\s*(curl|wget|nc|ncat)', re.I), "shell vars piped to network"),
]

# HA009: Background process spawning
BACKGROUND_PATTERNS = [
    (re.compile(r'\bnohup\b.*&', re.I), "nohup background process"),
    (re.compile(r'\bdisown\b', re.I), "disowned process"),
    (re.compile(r'\bsetsid\b', re.I), "new session process"),
    (re.compile(r'\bscreen\s+-dm\b', re.I), "detached screen session"),
    (re.compile(r'\btmux\b.*new-session\s+-d', re.I), "detached tmux session"),
    (re.compile(r'\bat\s+(now|midnight|\d)', re.I), "scheduled task creation"),
    (re.compile(r'crontab\b', re.I), "crontab modification"),
]

# HA010: Filesystem modification outside repo
FS_MOD_PATTERNS = [
    (re.compile(r'>\s*~/\.(bashrc|zshrc|profile|bash_profile|bash_login)', re.I), "shell profile modification"),
    (re.compile(r'>>\s*~/\.(bashrc|zshrc|profile|bash_profile|bash_login)', re.I), "shell profile append"),
    (re.compile(r'(cp|mv|tee|cat\s*>)\b.*/etc/', re.I), "system config modification"),
    (re.compile(r'(cp|mv|tee|cat\s*>)\b.*/usr/', re.I), "system binary modification"),
    (re.compile(r'mkdir\s+-p\s*~/\.local/bin.*&&.*cp\b', re.I), "binary installation to PATH"),
    (re.compile(r'(cp|install)\b.*\s+/usr/local/bin/', re.I), "binary installation to system PATH"),
]

# HA011: Crypto mining indicators
CRYPTO_MINING_PATTERNS = [
    (re.compile(r'(xmrig|minerd|cpuminer|cgminer|bfgminer|ethminer|nbminer)', re.I), "crypto miner binary"),
    (re.compile(r'stratum\+tcp://', re.I), "stratum mining pool"),
    (re.compile(r'(pool\.|mining\.|mine\.).*:\d{4,5}', re.I), "mining pool connection"),
    (re.compile(r'--algo\s+(cryptonight|randomx|ethash|kawpow)', re.I), "mining algorithm flag"),
    (re.compile(r'--donate-level', re.I), "mining donation setting"),
]

# ── Git Hook Names ──────────────────────────────────────────────────

KNOWN_HOOKS = {
    "applypatch-msg", "pre-applypatch", "post-applypatch",
    "pre-commit", "prepare-commit-msg", "commit-msg", "post-commit",
    "pre-rebase", "post-checkout", "post-merge", "pre-push",
    "pre-receive", "update", "post-receive", "post-update",
    "push-to-checkout", "pre-auto-gc", "post-rewrite",
    "sendemail-validate", "fsmonitor-watchman",
    "p4-changelist", "p4-prepare-changelist",
    "p4-post-changelist", "p4-pre-submit",
    "post-index-change", "reference-transaction",
}

# High-risk hooks (auto-triggered on common operations)
HIGH_RISK_HOOKS = {
    "post-checkout",   # Triggers on clone, checkout, switch
    "post-merge",      # Triggers on pull
    "pre-commit",      # Triggers on every commit
    "pre-push",        # Triggers on push
    "prepare-commit-msg",  # Triggers on every commit
    "post-rewrite",    # Triggers on rebase, amend
}

# ── Scanner ─────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    hooks_found: int = 0

    @property
    def risk_score(self) -> int:
        score = sum(f.severity.score for f in self.findings)
        return min(score, 100)

    @property
    def grade(self) -> str:
        s = self.risk_score
        if s == 0:
            return "A+"
        elif s <= 10:
            return "A"
        elif s <= 20:
            return "B"
        elif s <= 35:
            return "C"
        elif s <= 50:
            return "D"
        else:
            return "F"

    @property
    def risk_label(self) -> str:
        s = self.risk_score
        if s == 0:
            return "SAFE"
        elif s <= 20:
            return "LOW"
        elif s <= 50:
            return "MODERATE"
        elif s <= 75:
            return "HIGH"
        else:
            return "CRITICAL"


def _truncate(text: str, maxlen: int = 120) -> str:
    text = text.strip()
    if len(text) > maxlen:
        return text[:maxlen - 3] + "..."
    return text


def _scan_content(content: str, filepath: str, result: ScanResult) -> None:
    """Run all pattern-based rules against file content."""
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            continue

        # HA001: Reverse shells
        for pattern in REVERSE_SHELL_PATTERNS:
            if pattern.search(stripped):
                result.findings.append(Finding(
                    rule_id="HA001",
                    severity=Severity.CRITICAL,
                    message="Reverse shell pattern detected",
                    file=filepath,
                    line=line_num,
                    evidence=_truncate(stripped),
                ))
                break  # One finding per line per rule

        # HA002: Credential theft
        for pattern, desc in CREDENTIAL_THEFT_PATTERNS:
            if pattern.search(stripped):
                result.findings.append(Finding(
                    rule_id="HA002",
                    severity=Severity.CRITICAL,
                    message=f"Credential theft: {desc}",
                    file=filepath,
                    line=line_num,
                    evidence=_truncate(stripped),
                ))
                break

        # HA003: Data exfiltration
        for pattern, desc in EXFIL_PATTERNS:
            if pattern.search(stripped):
                result.findings.append(Finding(
                    rule_id="HA003",
                    severity=Severity.HIGH,
                    message=f"Data exfiltration: {desc}",
                    file=filepath,
                    line=line_num,
                    evidence=_truncate(stripped),
                ))
                break

        # HA004: Download and execute
        for pattern in DOWNLOAD_EXEC_PATTERNS:
            if pattern.search(stripped):
                result.findings.append(Finding(
                    rule_id="HA004",
                    severity=Severity.CRITICAL,
                    message="Download and execute pattern",
                    file=filepath,
                    line=line_num,
                    evidence=_truncate(stripped),
                ))
                break

        # HA005: Obfuscated code
        for pattern, desc in OBFUSCATION_PATTERNS:
            if pattern.search(stripped):
                result.findings.append(Finding(
                    rule_id="HA005",
                    severity=Severity.HIGH,
                    message=f"Obfuscated code: {desc}",
                    file=filepath,
                    line=line_num,
                    evidence=_truncate(stripped),
                ))
                break

        # HA006: Dangerous commands
        for pattern, desc in DANGEROUS_CMD_PATTERNS:
            if pattern.search(stripped):
                result.findings.append(Finding(
                    rule_id="HA006",
                    severity=Severity.CRITICAL,
                    message=f"Dangerous command: {desc}",
                    file=filepath,
                    line=line_num,
                    evidence=_truncate(stripped),
                ))
                break

        # HA007: Privilege escalation
        for pattern, desc in PRIV_ESC_PATTERNS:
            if pattern.search(stripped):
                result.findings.append(Finding(
                    rule_id="HA007",
                    severity=Severity.HIGH,
                    message=f"Privilege escalation: {desc}",
                    file=filepath,
                    line=line_num,
                    evidence=_truncate(stripped),
                ))
                break

        # HA008: Environment variable exfiltration
        for pattern, desc in ENV_EXFIL_PATTERNS:
            if pattern.search(stripped):
                result.findings.append(Finding(
                    rule_id="HA008",
                    severity=Severity.CRITICAL,
                    message=f"Environment exfiltration: {desc}",
                    file=filepath,
                    line=line_num,
                    evidence=_truncate(stripped),
                ))
                break

        # HA009: Background processes
        for pattern, desc in BACKGROUND_PATTERNS:
            if pattern.search(stripped):
                result.findings.append(Finding(
                    rule_id="HA009",
                    severity=Severity.MEDIUM,
                    message=f"Background process: {desc}",
                    file=filepath,
                    line=line_num,
                    evidence=_truncate(stripped),
                ))
                break

        # HA010: Filesystem modification
        for pattern, desc in FS_MOD_PATTERNS:
            if pattern.search(stripped):
                result.findings.append(Finding(
                    rule_id="HA010",
                    severity=Severity.HIGH,
                    message=f"Filesystem modification: {desc}",
                    file=filepath,
                    line=line_num,
                    evidence=_truncate(stripped),
                ))
                break

        # HA011: Crypto mining
        for pattern, desc in CRYPTO_MINING_PATTERNS:
            if pattern.search(stripped):
                result.findings.append(Finding(
                    rule_id="HA011",
                    severity=Severity.CRITICAL,
                    message=f"Crypto mining: {desc}",
                    file=filepath,
                    line=line_num,
                    evidence=_truncate(stripped),
                ))
                break

    # Multi-line patterns (need full content)
    # HA001 multi-line: reverse shell spanning lines
    for pattern in REVERSE_SHELL_PATTERNS:
        if pattern.search(content):
            # Check if we already caught it line by line
            if not any(f.rule_id == "HA001" and f.file == filepath for f in result.findings):
                result.findings.append(Finding(
                    rule_id="HA001",
                    severity=Severity.CRITICAL,
                    message="Reverse shell pattern detected (multi-line)",
                    file=filepath,
                    evidence=_truncate(pattern.pattern),
                ))


def _scan_gitattributes(path: Path, result: ScanResult) -> None:
    """HA012: Scan .gitattributes for dangerous filter drivers."""
    if not path.exists():
        return
    result.files_scanned += 1

    try:
        content = path.read_text(errors="replace")
    except (OSError, PermissionError):
        return

    filepath = str(path)
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Check for filter drivers
        filter_match = re.search(r'\bfilter\s*=\s*(\S+)', stripped)
        if filter_match:
            filter_name = filter_match.group(1)
            result.findings.append(Finding(
                rule_id="HA012",
                severity=Severity.HIGH,
                message=f"Git filter driver '{filter_name}' — executes code on checkout/add",
                file=filepath,
                line=line_num,
                evidence=_truncate(stripped),
            ))

        # Check for diff drivers
        diff_match = re.search(r'\bdiff\s*=\s*(\S+)', stripped)
        if diff_match:
            driver = diff_match.group(1)
            result.findings.append(Finding(
                rule_id="HA012",
                severity=Severity.MEDIUM,
                message=f"Custom diff driver '{driver}' — may execute code on diff",
                file=filepath,
                line=line_num,
                evidence=_truncate(stripped),
            ))

        # Check for merge drivers
        merge_match = re.search(r'\bmerge\s*=\s*(\S+)', stripped)
        if merge_match:
            driver = merge_match.group(1)
            result.findings.append(Finding(
                rule_id="HA012",
                severity=Severity.MEDIUM,
                message=f"Custom merge driver '{driver}' — may execute code on merge",
                file=filepath,
                line=line_num,
                evidence=_truncate(stripped),
            ))


def _scan_git_config(path: Path, result: ScanResult) -> None:
    """HA013: Scan .git/config or .gitconfig for dangerous settings."""
    if not path.exists():
        return
    result.files_scanned += 1

    try:
        content = path.read_text(errors="replace")
    except (OSError, PermissionError):
        return

    filepath = str(path)
    lines = content.split("\n")

    dangerous_keys = {
        "core.hookspath": (Severity.HIGH, "custom hooks path — hooks could come from anywhere"),
        "core.fsmonitor": (Severity.CRITICAL, "fsmonitor — executes command on every git operation"),
        "core.pager": (Severity.MEDIUM, "custom pager — could execute arbitrary code"),
        "core.editor": (Severity.LOW, "custom editor — could be malicious binary"),
        "core.sshcommand": (Severity.HIGH, "custom SSH command — could intercept credentials"),
        "credential.helper": (Severity.HIGH, "credential helper — could steal credentials"),
        "diff.*.textconv": (Severity.HIGH, "textconv — executes command on diff"),
        "merge.*.driver": (Severity.HIGH, "merge driver — executes command on merge"),
        "filter.*.clean": (Severity.HIGH, "filter clean — executes on git add"),
        "filter.*.smudge": (Severity.HIGH, "filter smudge — executes on git checkout"),
        "filter.*.process": (Severity.HIGH, "filter process — long-running filter command"),
    }

    current_section = ""
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue

        # Track sections
        section_match = re.match(r'\[(\S+?)(?:\s+"([^"]+)")?\]', stripped)
        if section_match:
            current_section = section_match.group(1).lower()
            if section_match.group(2):
                current_section += "." + section_match.group(2)
            continue

        # Check key=value pairs
        kv_match = re.match(r'\s*(\w+)\s*=\s*(.*)', stripped)
        if not kv_match:
            continue

        key = kv_match.group(1).lower()
        value = kv_match.group(2).strip()
        full_key = f"{current_section}.{key}"

        # Check exact matches
        for pattern, (severity, desc) in dangerous_keys.items():
            if "*" in pattern:
                # Wildcard match: filter.*.clean matches filter.lfs.clean
                parts = pattern.split("*")
                if full_key.startswith(parts[0].rstrip(".")) and full_key.endswith(parts[1].lstrip(".")):
                    result.findings.append(Finding(
                        rule_id="HA013",
                        severity=severity,
                        message=f"Dangerous git config: {desc}",
                        file=filepath,
                        line=line_num,
                        evidence=_truncate(f"{full_key} = {value}"),
                    ))
                    break
            elif full_key == pattern:
                result.findings.append(Finding(
                    rule_id="HA013",
                    severity=severity,
                    message=f"Dangerous git config: {desc}",
                    file=filepath,
                    line=line_num,
                    evidence=_truncate(f"{full_key} = {value}"),
                ))
                break

        # Check for URLs with embedded credentials
        if re.search(r'https?://[^@\s]+:[^@\s]+@', value):
            result.findings.append(Finding(
                rule_id="HA013",
                severity=Severity.HIGH,
                message="Embedded credentials in git config URL",
                file=filepath,
                line=line_num,
                evidence=_truncate(stripped),
            ))


def _scan_husky(repo_root: Path, result: ScanResult) -> None:
    """HA014: Scan Husky hook configurations."""
    husky_dir = repo_root / ".husky"
    if not husky_dir.is_dir():
        return

    for item in husky_dir.iterdir():
        if item.is_file() and item.name != "_" and not item.name.startswith("."):
            result.files_scanned += 1
            result.hooks_found += 1
            try:
                content = item.read_text(errors="replace")
            except (OSError, PermissionError):
                continue
            _scan_content(content, str(item), result)

    # Check .husky/_/husky.sh
    husky_sh = husky_dir / "_" / "husky.sh"
    if husky_sh.exists():
        result.files_scanned += 1
        try:
            content = husky_sh.read_text(errors="replace")
        except (OSError, PermissionError):
            return
        _scan_content(content, str(husky_sh), result)


def _scan_precommit_config(repo_root: Path, result: ScanResult) -> None:
    """HA015: Scan .pre-commit-config.yaml for suspicious repos."""
    config_path = repo_root / ".pre-commit-config.yaml"
    if not config_path.exists():
        return
    result.files_scanned += 1

    try:
        content = config_path.read_text(errors="replace")
    except (OSError, PermissionError):
        return

    filepath = str(config_path)
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()

        # Check for repos pointing to non-GitHub/non-trusted sources
        repo_match = re.search(r'repo:\s*(https?://\S+)', stripped)
        if repo_match:
            url = repo_match.group(1)
            # Flag non-standard hosts
            trusted_hosts = [
                "github.com", "gitlab.com", "bitbucket.org",
            ]
            is_trusted = any(host in url for host in trusted_hosts)
            if not is_trusted:
                result.findings.append(Finding(
                    rule_id="HA015",
                    severity=Severity.MEDIUM,
                    message=f"Pre-commit repo from untrusted host",
                    file=filepath,
                    line=line_num,
                    evidence=_truncate(url),
                ))

        # Check for local repos with suspicious paths
        local_match = re.search(r'repo:\s*(local|/)', stripped)
        if local_match:
            result.findings.append(Finding(
                rule_id="HA015",
                severity=Severity.LOW,
                message="Pre-commit config uses local repo — verify hook code",
                file=filepath,
                line=line_num,
                evidence=_truncate(stripped),
            ))

        # Check for entry commands that look dangerous
        entry_match = re.search(r'entry:\s*(.+)', stripped)
        if entry_match:
            entry_cmd = entry_match.group(1).strip()
            for pattern in DOWNLOAD_EXEC_PATTERNS:
                if pattern.search(entry_cmd):
                    result.findings.append(Finding(
                        rule_id="HA015",
                        severity=Severity.CRITICAL,
                        message="Pre-commit hook entry with download-and-execute",
                        file=filepath,
                        line=line_num,
                        evidence=_truncate(entry_cmd),
                    ))
                    break

            for pattern in REVERSE_SHELL_PATTERNS:
                if pattern.search(entry_cmd):
                    result.findings.append(Finding(
                        rule_id="HA015",
                        severity=Severity.CRITICAL,
                        message="Pre-commit hook entry with reverse shell",
                        file=filepath,
                        line=line_num,
                        evidence=_truncate(entry_cmd),
                    ))
                    break


def _scan_lefthook(repo_root: Path, result: ScanResult) -> None:
    """HA016: Scan lefthook configs for suspicious commands."""
    for name in ("lefthook.yml", ".lefthook.yml", "lefthook.yaml", ".lefthook.yaml"):
        config_path = repo_root / name
        if config_path.exists():
            result.files_scanned += 1
            try:
                content = config_path.read_text(errors="replace")
            except (OSError, PermissionError):
                continue

            filepath = str(config_path)
            lines = content.split("\n")

            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                # Check run commands
                run_match = re.search(r'run:\s*(.+)', stripped)
                if run_match:
                    cmd = run_match.group(1).strip()
                    # Apply all dangerous pattern checks to the command
                    _scan_content(cmd, filepath, result)
                    # Overwrite line numbers on any findings just added
                    for f in result.findings:
                        if f.file == filepath and f.line == 1:
                            f.line = line_num


def _scan_hook_scripts(repo_root: Path, result: ScanResult) -> None:
    """Scan .git/hooks/ and .githooks/ for malicious content."""

    hook_dirs = [
        repo_root / ".git" / "hooks",
        repo_root / ".githooks",
    ]

    # Also check if core.hooksPath is set to something custom
    git_config = repo_root / ".git" / "config"
    if git_config.exists():
        try:
            config_content = git_config.read_text(errors="replace")
            hooks_path_match = re.search(r'hookspath\s*=\s*(.+)', config_content, re.I)
            if hooks_path_match:
                custom_path = Path(hooks_path_match.group(1).strip())
                if not custom_path.is_absolute():
                    custom_path = repo_root / custom_path
                if custom_path.is_dir() and custom_path not in hook_dirs:
                    hook_dirs.append(custom_path)
        except (OSError, PermissionError):
            pass

    for hooks_dir in hook_dirs:
        if not hooks_dir.is_dir():
            continue

        for item in hooks_dir.iterdir():
            if not item.is_file():
                continue

            # Skip .sample files
            if item.suffix == ".sample":
                continue

            result.files_scanned += 1

            # Check if it's a known hook name
            hook_name = item.stem if item.suffix else item.name
            if hook_name in KNOWN_HOOKS:
                result.hooks_found += 1

                # HA017: Check if hook is in a high-risk category
                if hook_name in HIGH_RISK_HOOKS:
                    result.findings.append(Finding(
                        rule_id="HA017",
                        severity=Severity.INFO,
                        message=f"Auto-triggered hook: {hook_name} runs on common git operations",
                        file=str(item),
                    ))

            # Check executable bit
            try:
                mode = item.stat().st_mode
                if mode & stat.S_IXUSR:
                    pass  # Expected
                else:
                    result.findings.append(Finding(
                        rule_id="HA017",
                        severity=Severity.INFO,
                        message=f"Hook file is not executable (won't run)",
                        file=str(item),
                    ))
            except OSError:
                pass

            # Read and scan content
            try:
                content = item.read_text(errors="replace")
            except (OSError, PermissionError):
                continue

            _scan_content(content, str(item), result)

            # HA018: Check for binary content in hooks
            try:
                raw = item.read_bytes()
                if b"\x00" in raw[:512]:
                    result.findings.append(Finding(
                        rule_id="HA018",
                        severity=Severity.HIGH,
                        message="Binary content in hook file — could be compiled malware",
                        file=str(item),
                    ))
            except (OSError, PermissionError):
                pass


def scan_repo(repo_root: Path) -> ScanResult:
    """Scan a git repository for dangerous hooks and configs."""
    result = ScanResult()

    if not repo_root.is_dir():
        result.findings.append(Finding(
            rule_id="HA000",
            severity=Severity.INFO,
            message=f"Not a directory: {repo_root}",
            file=str(repo_root),
        ))
        return result

    # Scan hook scripts (.git/hooks, .githooks, custom hookspath)
    _scan_hook_scripts(repo_root, result)

    # Scan .gitattributes
    for ga in [repo_root / ".gitattributes"]:
        _scan_gitattributes(ga, result)
    # Also check subdirectory .gitattributes
    try:
        for ga in repo_root.rglob(".gitattributes"):
            if ".git" not in ga.parts:
                _scan_gitattributes(ga, result)
    except (OSError, PermissionError):
        pass

    # Scan git config
    _scan_git_config(repo_root / ".git" / "config", result)

    # Scan husky
    _scan_husky(repo_root, result)

    # Scan pre-commit config
    _scan_precommit_config(repo_root, result)

    # Scan lefthook
    _scan_lefthook(repo_root, result)

    return result


def scan_file(filepath: Path) -> ScanResult:
    """Scan a single file for dangerous patterns."""
    result = ScanResult()

    if not filepath.is_file():
        result.findings.append(Finding(
            rule_id="HA000",
            severity=Severity.INFO,
            message=f"Not a file: {filepath}",
            file=str(filepath),
        ))
        return result

    result.files_scanned = 1

    name = filepath.name
    if name == ".gitattributes":
        _scan_gitattributes(filepath, result)
    elif name in ("config", ".gitconfig"):
        _scan_git_config(filepath, result)
    elif name == ".pre-commit-config.yaml":
        _scan_precommit_config(filepath.parent, result)
    elif name in ("lefthook.yml", ".lefthook.yml", "lefthook.yaml", ".lefthook.yaml"):
        _scan_lefthook(filepath.parent, result)
    else:
        try:
            content = filepath.read_text(errors="replace")
        except (OSError, PermissionError):
            return result
        _scan_content(content, str(filepath), result)
        result.hooks_found = 1

    return result


# ── Output Formatting ───────────────────────────────────────────────

# ANSI colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"
MAGENTA = "\033[95m"

SEVERITY_COLORS = {
    Severity.CRITICAL: RED,
    Severity.HIGH: YELLOW,
    Severity.MEDIUM: MAGENTA,
    Severity.LOW: CYAN,
    Severity.INFO: GRAY,
}


def _supports_color() -> bool:
    if os.getenv("NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()


def format_text(result: ScanResult, verbose: bool = False, color: bool = True) -> str:
    """Format scan result as human-readable text."""
    use_color = color and _supports_color()

    def c(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if use_color else text

    lines: List[str] = []

    # Header
    grade = result.grade
    risk = result.risk_label
    score = result.risk_score

    grade_color = GREEN if grade.startswith("A") else (YELLOW if grade in ("B", "C") else RED)
    risk_color = GREEN if risk == "SAFE" else (YELLOW if risk in ("LOW", "MODERATE") else RED)

    lines.append(c(BOLD, "hookaudit") + f" — Git Hook Security Audit")
    lines.append("")
    lines.append(f"  Grade: {c(grade_color, c(BOLD, grade))}  Risk: {c(risk_color, risk)} ({score}/100)")
    lines.append(f"  Files scanned: {result.files_scanned}  Hooks found: {result.hooks_found}")
    lines.append(f"  Findings: {len(result.findings)}")
    lines.append("")

    if not result.findings:
        lines.append(c(GREEN, "  ✓ No security issues found"))
        return "\n".join(lines)

    # Group by severity
    by_severity: Dict[Severity, List[Finding]] = {}
    for f in result.findings:
        by_severity.setdefault(f.severity, []).append(f)

    for sev in Severity:
        findings = by_severity.get(sev, [])
        if not findings:
            continue
        if sev == Severity.INFO and not verbose:
            continue

        sev_color = SEVERITY_COLORS[sev]
        lines.append(c(sev_color, c(BOLD, f"  {sev.value} ({len(findings)})")))

        for f in findings:
            loc = f.file
            if f.line:
                loc += f":{f.line}"
            lines.append(f"    [{f.rule_id}] {f.message}")
            lines.append(f"      {c(GRAY, loc)}")
            if f.evidence:
                lines.append(f"      {c(GRAY, '→ ' + f.evidence)}")
            lines.append("")

    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    """Format scan result as JSON."""
    data = {
        "grade": result.grade,
        "risk": result.risk_label,
        "score": result.risk_score,
        "files_scanned": result.files_scanned,
        "hooks_found": result.hooks_found,
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(data, indent=2)


# ── Rule Reference ──────────────────────────────────────────────────

RULES = {
    "HA001": ("CRITICAL", "Reverse shell patterns (bash, netcat, python, perl, ruby, socat)"),
    "HA002": ("CRITICAL", "Credential theft (SSH keys, AWS/GCP creds, keychains, browser data)"),
    "HA003": ("HIGH", "Data exfiltration (HTTP POST, DNS, netcat pipe, scp/rsync)"),
    "HA004": ("CRITICAL", "Download and execute (curl|sh, wget|sh, download+chmod+x)"),
    "HA005": ("HIGH", "Obfuscated code (base64, hex, eval, IFS manipulation)"),
    "HA006": ("CRITICAL", "Dangerous commands (rm -rf /, fork bomb, disk overwrite)"),
    "HA007": ("HIGH", "Privilege escalation (sudo, su, setuid/setgid)"),
    "HA008": ("CRITICAL", "Environment variable exfiltration (env/secrets piped to network)"),
    "HA009": ("MEDIUM", "Background process spawning (nohup, crontab, at, screen/tmux)"),
    "HA010": ("HIGH", "Filesystem modification outside repo (shell profiles, /etc, /usr)"),
    "HA011": ("CRITICAL", "Crypto mining indicators (miners, stratum pools, mining algorithms)"),
    "HA012": ("HIGH", "Gitattributes filter/diff/merge drivers (arbitrary code execution)"),
    "HA013": ("HIGH", "Dangerous git config (fsmonitor, hooksPath, credential helper)"),
    "HA014": ("—", "Husky hook framework scanning"),
    "HA015": ("MEDIUM", "Pre-commit config suspicious repos or entries"),
    "HA016": ("—", "Lefthook config scanning"),
    "HA017": ("INFO", "Hook metadata (auto-triggered hooks, executable permissions)"),
    "HA018": ("HIGH", "Binary content in hook files"),
}


def format_rules() -> str:
    """List all rules."""
    lines = ["hookaudit rules:", ""]
    for rule_id, (severity, desc) in sorted(RULES.items()):
        lines.append(f"  {rule_id}  [{severity:>8s}]  {desc}")
    return "\n".join(lines)


# ── CLI ─────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="hookaudit",
        description="Git Hook & Repository Config Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  hookaudit                     Scan current repository
  hookaudit /path/to/repo       Scan specific repository
  hookaudit -f hook-script.sh   Scan a single file
  hookaudit --json              JSON output for CI
  hookaudit --rules             List all rules
""",
    )
    parser.add_argument("path", nargs="?", default=".",
                        help="Repository path or file to scan (default: .)")
    parser.add_argument("-f", "--file", action="store_true",
                        help="Scan a single file instead of a repository")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show INFO-level findings")
    parser.add_argument("--rules", action="store_true",
                        help="List all rules and exit")
    parser.add_argument("--ci", action="store_true",
                        help="CI mode: exit 1 if HIGH+ findings, exit 2 if CRITICAL")
    parser.add_argument("--version", action="version",
                        version=f"hookaudit {__version__}")

    args = parser.parse_args()

    if args.rules:
        print(format_rules())
        return 0

    target = Path(args.path).resolve()

    if args.file:
        result = scan_file(target)
    else:
        result = scan_repo(target)

    if args.json:
        print(format_json(result))
    else:
        print(format_text(result, verbose=args.verbose))

    if args.ci:
        has_critical = any(f.severity == Severity.CRITICAL for f in result.findings)
        has_high = any(f.severity == Severity.HIGH for f in result.findings)
        if has_critical:
            return 2
        if has_high:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
