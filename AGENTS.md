# Cortex Platform Content Repository

This repository contains the content (Integrations, Scripts, Playbooks, Reports, Modeling Rules, Parsing Rules) for the Cortex Platform (XSOAR, XSIAM, etc.).

This file provides guidance to agents when working with code in this repository.

## Codebase Introduction

This project uses `demisto-sdk` as the primary CLI for all development tasks.

- **Linting & Testing**: `demisto-sdk pre-commit -i <path>` (runs in Docker, replaces `lint`)
- **Formatting**: `demisto-sdk format -i <path>` (fixes style/lint issues)
- **Validation**: `demisto-sdk validate -i <path>`

## Commands

```bash
# Run lint, tests, and validation (single file/dir) - MUST run in Docker
demisto-sdk pre-commit -i Packs/MyPack/Integrations/MyInt/

# Format code (fixes many lint errors automatically)
demisto-sdk format -i Packs/MyPack/Integrations/MyInt/MyInt.py

# Validate content against XSOAR standards (also run by pre-commit)
demisto-sdk validate -i Packs/MyPack/Integrations/MyInt/

# Run pre-commit hooks on all files
demisto-sdk pre-commit -a
```

## Non-Obvious Project Rules

- **Runtime Injection**: `CommonServerPython` and `CommonServerUserPython` are injected at runtime. Always import them: `from CommonServerPython import *`.
- **Imports**: MUST import `demistomock as demisto` at the top of every integration/script.
- **Docker Dependency**: Dependencies are managed via Docker images defined in the `.yml` file, not local `pip`. You cannot `pip install` in the runtime environment.
- **Test Execution**: Standard `pytest` often fails due to missing runtime context. Use `demisto-sdk pre-commit` which sets up the correct Docker environment.
- **Error Handling**: Use `return_error("message")` for user-facing errors. Only raise exceptions for unexpected failures.
- **Outputs**: Use `return_outputs(readable_output, outputs, raw_response)` to return data. `outputs` dict keys should be CamelCase.
- **Logging**: Use `demisto.debug()` and `demisto.info()`. Avoid `print()`.

## Architecture Notes

- **Pack Structure**: `Packs/<PackName>/<Entity>/<EntityName>/`. Entities include `Integrations`, `Scripts`, `Playbooks`, `ModelingRules`, `ParsingRules`, `XDRCTemplates`, etc. Flat structures are forbidden.
- **Metadata**: Every pack requires `pack_metadata.json`. Every entity requires a YAML/JSON configuration file.
- **Versioning**: Changes require a new entry in `Packs/<PackName>/ReleaseNotes/<Version>.md`.
- **Isolation**: Integrations are stateless and run in isolated containers. No shared state between executions.
- **Source of Truth**: `xsoar.pan.dev` is the official documentation.

## Instructions

### Code Style

- **Variable Names**: Use descriptive, self-explanatory names.
- **Type Hints**: Always use type hints.  `mypy` is enforced.
- **Formatting**: 
    - `demisto-sdk format` is MANDATORY. It fixes YAML structure, JSON formatting, and Python style.
- **Parameters**: Use `demisto.params()` for configuration and `demisto.args()` for command arguments.
- **Function Size**: Keep functions small (~30 lines) and focused on a single responsibility.
- **Conditionals**: Use early returns (guard clauses) to avoid deep nesting.

### Workflow for complex tasks

1. **Explore**
   - Understand existing implementation and patterns.
   - Check `Templates/` for reference implementations.

2. **Plan**
   - List files to create/modify.
   - Identify necessary Docker image dependencies.
   - Plan for `pack_metadata.json` and `ReleaseNotes`.

3. **Implement**
   - Start with core logic in `.py` file.
   - Define commands/args in`.yml` file.

4. **Test**
   - Create `_test.py` file.
   - Use `demistomock` and `requests_mock`.
   - Run `demisto-sdk pre-commit -i <path>`.

5. **Self-review**
   - Check for hardcoded values.
   - Ensure `return_outputs` is used correctly.
   - Verify `dockerimage` in YAML matches requirements.

## Principles

- **Statelessness**: Integrations must be stateless.
- **Isolation**: Each execution is independent.
- **Security**: No hardcoded credentials. Use `demisto.params()`.
- **Clarity**: Human-readable outputs (`tableToMarkdown`) are as important as machine-readable context.
