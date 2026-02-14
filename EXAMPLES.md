# hookaudit Examples

Common use cases and examples for hookaudit.

## Quick Start

```bash
# Audit all Git hooks in current repo
hookaudit

# Audit specific hooks
hookaudit .git/hooks/pre-commit .git/hooks/pre-push

# JSON output for automation
hookaudit --json

# CI mode - exit 1 if any issues found
hookaudit --check
```

## Example Scenarios

### 1. Pre-commit Hook Validation

Check that pre-commit hooks are properly configured and don't have security issues:

```bash
hookaudit .git/hooks/pre-commit
```

Common issues detected:
- Missing shebang (#!/bin/bash)
- Executable bit not set (chmod +x)
- Hardcoded credentials in hooks
- Unsafe shell expansions
- Commands without error handling

### 2. CI/CD Integration

Add hookaudit to your CI pipeline to ensure Git hooks are safe:

```yaml
# .github/workflows/security.yml
name: Hook Security Audit

on: [push, pull_request]

jobs:
  audit-hooks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Audit Git hooks
        run: |
          python3 hookaudit.py --check
```

### 3. Team Hook Standards

Validate that all developers have the same secure hook configuration:

```bash
# In your project's setup script
if ! hookaudit --check .git/hooks/; then
    echo "Git hooks failed security audit"
    echo "Run: hookaudit .git/hooks/ --verbose"
    exit 1
fi
```

### 4. Custom Hook Development

Before committing a new hook, validate it first:

```bash
# Create new hook
cat > .git/hooks/pre-push << 'EOF'
#!/bin/bash
pytest tests/
EOF

# Validate it
hookaudit .git/hooks/pre-push

# If issues found, fix them before enabling
chmod +x .git/hooks/pre-push
```

## Common Issues and Fixes

### Missing Shebang

**Issue:**
```bash
# Hook file has no shebang
echo "pytest tests/" > .git/hooks/pre-commit
```

**Fix:**
```bash
#!/bin/bash
pytest tests/
```

### Executable Permission

**Issue:**
hookaudit reports "Not executable"

**Fix:**
```bash
chmod +x .git/hooks/pre-commit
```

### Hardcoded Secrets

**Issue:**
```bash
#!/bin/bash
API_KEY="sk-abc123..." npm run deploy
```

**Fix:**
```bash
#!/bin/bash
if [ -z "$API_KEY" ]; then
    echo "API_KEY not set"
    exit 1
fi
npm run deploy
```

### Unsafe Variable Expansion

**Issue:**
```bash
#!/bin/bash
rm -rf $PROJECT_DIR/*
```

**Fix:**
```bash
#!/bin/bash
set -euo pipefail
rm -rf "${PROJECT_DIR:?}/"*
```

## Output Formats

### Text Output (default)

```
hookaudit v1.0.0
Scanning: .git/hooks/

  .git/hooks/pre-commit
    ✓ Executable
    ✓ Shebang present
    ⚠️ Possible hardcoded secret on line 5
    ⚠️ Unsafe variable expansion on line 8

  .git/hooks/pre-push
    ✗ Not executable (chmod +x required)
    ✓ Shebang present

Summary: 2 hooks scanned, 3 warnings, 1 error
```

### JSON Output

```json
{
  "version": "1.0.0",
  "hooks_scanned": 2,
  "total_issues": 4,
  "hooks": [
    {
      "path": ".git/hooks/pre-commit",
      "executable": true,
      "has_shebang": true,
      "issues": [
        {
          "severity": "warning",
          "type": "hardcoded_secret",
          "line": 5,
          "message": "Possible hardcoded secret"
        }
      ]
    }
  ]
}
```

## Best Practices

1. **Always use shebangs**: Start hooks with `#!/bin/bash` or `#!/usr/bin/env python3`
2. **Set executable bit**: Run `chmod +x` on all hooks
3. **Use environment variables**: Never hardcode credentials
4. **Enable strict mode**: Add `set -euo pipefail` to bash hooks
5. **Quote variables**: Use `"${VAR}"` instead of `$VAR`
6. **Handle errors**: Check exit codes and fail fast
7. **Test hooks**: Run hookaudit before committing hooks
8. **Document behavior**: Add comments explaining what each hook does

## Integration with Git

### Share hooks with your team

```bash
# Store hooks in version control
mkdir -p scripts/git-hooks
cp .git/hooks/* scripts/git-hooks/

# Team members install them
cp scripts/git-hooks/* .git/hooks/
chmod +x .git/hooks/*

# Validate installation
hookaudit
```

### Automated hook setup

```bash
#!/bin/bash
# setup-hooks.sh

HOOKS_DIR=".git/hooks"
SOURCE_DIR="scripts/git-hooks"

for hook in "$SOURCE_DIR"/*; do
    hook_name=$(basename "$hook")
    cp "$hook" "$HOOKS_DIR/$hook_name"
    chmod +x "$HOOKS_DIR/$hook_name"
done

# Validate
hookaudit --check || {
    echo "Hook validation failed"
    exit 1
}

echo "Git hooks installed and validated"
```

## More Info

- [Git Hooks Documentation](https://git-scm.com/docs/githooks)
- [hookaudit on GitHub](https://github.com/kriskimmerle/hookaudit)
