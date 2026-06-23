# Plan-First Workflow

Use this workflow before making ANY changes to code or configuration.

---

## 1. Understand the Request

- [ ] Restate the goal in clear, specific terms
- [ ] Identify what type of change this is:
  - Integration code (Python .py files)?
  - Integration configuration (YAML files)?
  - Unit tests (test.py files)?
  - Playbooks, Scripts, or other content entities?
  - Documentation only?
- [ ] Check XSOAR validation impact:
  - Will this change require `demisto-sdk format`?
  - Will this change require `demisto-sdk validate`?
  - Does this affect pack dependencies or metadata?

---

## 2. Investigate Current State

**Read before deciding:**

- [ ] Read all files that will be affected
- [ ] Check git status and recent commits
- [ ] Review CLAUDE.md for safety constraints
- [ ] Review repository-wide AGENTS.md for XSOAR standards
- [ ] Identify existing patterns and conventions

**Critical checks for this project:**

- [ ] If touching .py files → read current code patterns, imports, type hints, CommandResults usage
- [ ] If touching .yml files → read current command definitions, parameters, outputs structure
- [ ] If touching _test.py files → understand test patterns, mock usage, test coverage expectations
- [ ] If touching pack_metadata.json → verify dependencies, version, supported modules
- [ ] If touching README.md → ensure accuracy with implemented commands and capabilities

---

## 3. Identify Knowledge Gaps

Tag each assumption with confidence level:

- **VERIFIED** - Confirmed by reading files, CLI documentation, or API docs
- **ASSUMED** - Logical inference but not confirmed
- **UNKNOWN** - Missing information, must ask

**Stop and ask if ANY of these are UNKNOWN:**

- Does this CLI command/API endpoint exist in the Prisma AIRs documentation?
- What is the exact API request/response format for this feature?
- **What are the EXACT field names in the SDK Zod schema for this resource?**
  - Have you read `./knowledge/prisma-airs-sdk-main/src/models/mgmt-{resource}.ts`?
  - Do you know the EXACT response field names (not guessed names)?
  - Example: Is it `customer_appId` or `customer_app_id`? (SDK says `customer_appId`)
- Will this change break backward compatibility with existing XSOAR playbooks?
- Does this follow XSOAR CommandResults patterns correctly?
- What are the XSOAR validation requirements for this change?
- Is this change tested with appropriate unit test coverage?

---

## 4. Design Solution

- [ ] List all files that will be modified
- [ ] Describe changes to each file specifically
- [ ] Identify risks and mitigations:
  - Breaking change risk? Document migration path for users
  - API change risk? Verify against latest SCM/Prisma AIRs API docs
  - Test coverage risk? Add appropriate unit tests
  - XSOAR validation risk? Run demisto-sdk validate before committing

**For Python integration file changes (PaloAltoNetworks_Prisma_AIRs.py):**

- [ ] Are you following existing code patterns and conventions?
- [ ] Are all functions using proper type hints (per AGENTS.md)?
- [ ] Are API calls correctly authenticated with Client ID/Secret?
- [ ] **CRITICAL: Have you validated ALL field names against the SDK Zod schema?**
  - [ ] Read the Zod schema in `./knowledge/prisma-airs-sdk-main/src/models/mgmt-{resource}.ts`
  - [ ] Reviewed the SDK client in `./knowledge/prisma-airs-sdk-main/src/management/{resource}.ts`
  - [ ] Checked endpoint path in `./knowledge/prisma-airs-sdk-main/src/constants.ts`
  - [ ] Using EXACT field names from schema (e.g., `profile_id` not `id`, `last_modified_ts` not `updated_at`)
  - [ ] Noted which fields are optional vs required in the schema
- [ ] Are errors handled gracefully with user-friendly messages?
- [ ] Is CommandResults used correctly (not demisto.results)?
- [ ] Are helper functions properly unit-tested?
- [ ] Does the CLI documentation in ./knowledge support this implementation?

**For YAML configuration changes (PaloAltoNetworks_Prisma_AIRs.yml):**

- [ ] Are command names following the pattern `<feature>-<action>-<object>`?
- [ ] Are all arguments properly defined with required/optional flags?
- [ ] **Are output context paths using EXACT field names from SDK Zod schema?**
  - [ ] Field names match schema exactly (e.g., `uuid` not `id` for DLP profiles)
  - [ ] No fields added that don't exist in schema (e.g., `created_at` if schema doesn't have it)
  - [ ] Data types match schema (String, Number, Boolean, Date)
- [ ] Are descriptions clear and user-friendly?
- [ ] Does the YAML validate with `demisto-sdk validate`?
- [ ] Are credentials parameters using the correct parameter types?

**For unit test changes (PaloAltoNetworks_Prisma_AIRs_test.py):**

- [ ] Are you mocking SCM API responses correctly?
- [ ] **Are mock responses using EXACT field names from SDK Zod schema?**
  - [ ] Mock data matches actual API response structure from schema
  - [ ] Field names are exact (e.g., `customer_appId` not `customer_app_id`)
  - [ ] Test assertions check correct field names (match schema, not guessed)
- [ ] Do tests cover both success and failure scenarios?
- [ ] Are test fixtures in test_data/ directory used appropriately?
- [ ] Do tests validate CommandResults output structure?
- [ ] Do all tests pass with pytest?

**For pack metadata changes (pack_metadata.json):**

- [ ] Is version number incremented appropriately (semantic versioning)?
- [ ] Are dependencies (CommonPlaybooks, CommonScripts) still correct?
- [ ] Are supportedModules (cloud_posture, xsiam, cloud) accurate?
- [ ] Is pack description and author information correct?

---

## 5. Present Plan for Approval

**Plan must include:**

1. **What**: Specific changes to specific files (with line numbers if available)
2. **Why**: Reason for the change (CLI conversion, bug fix, feature addition)
3. **CLI Reference**: Which CLI command/API this implements (with knowledge/ path)
4. **Risk**: What could go wrong (breaking changes, validation failures)
5. **Verification**: How to test/verify it works (unit tests, integration tests)
6. **Rollback**: How to undo if it breaks (git revert, version rollback)

**Wait for explicit approval before proceeding.**

If user says "go ahead" or "yes" or "approved" → move to implement workflow.

---

## Never Skip This Workflow For

- Changes to Python integration files (.py)
- Changes to YAML integration configuration (.yml)
- Changes to unit test files (_test.py)
- Adding/removing integration commands
- Changing command arguments or outputs structure
- Modifying authentication or API client code
- Adding new features from CLI tool
- Changes to pack dependencies or metadata
- Any change that affects backward compatibility
- Any change implementing new Prisma AIRs API endpoints
