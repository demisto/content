# Implementation Workflow

Use this workflow ONLY after plan approval. Never implement without an approved plan.

---

## 1. Pre-Flight Checks

- [ ] Plan was explicitly approved by user
- [ ] All UNKNOWN items were resolved
- [ ] All ASSUMED items were confirmed or documented
- [ ] CLI documentation reference is verified in ./knowledge
- [ ] Rollback plan is clear

**STOP if:**
- No plan was created
- Plan was not approved
- Any UNKNOWN items remain unresolved
- CLI/API documentation doesn't support the planned implementation

---

## 2. Execute Changes Exactly as Planned

- [ ] Follow the approved plan step-by-step
- [ ] Make ONLY the changes listed in the plan
- [ ] Do NOT add scope, features, or "improvements"
- [ ] Do NOT refactor unrelated code
- [ ] Reference plan in commit messages

**Safety checks during implementation:**

- [ ] If editing .py files → follow type hints, use CommandResults, handle errors gracefully
- [ ] If editing .yml files → verify YAML syntax, validate command structure
- [ ] If editing _test.py files → ensure tests cover both success and error cases
- [ ] If editing pack_metadata.json → verify version increment follows semantic versioning
- [ ] **CRITICAL: Validate ALL field names against SDK Zod schemas BEFORE implementation**
  - Read `./knowledge/prisma-airs-sdk-main/src/models/mgmt-{resource}.ts`
  - Check SDK client at `./knowledge/prisma-airs-sdk-main/src/management/{resource}.ts`
  - Use EXACT field names from schema - do NOT guess or assume
  - Common mistakes: `customer_app_id` vs `customer_appId`, `expires_at` vs `expiration`, `created_at` (doesn't exist in most schemas)
- [ ] Always reference CLI documentation in ./knowledge for API implementation accuracy

---

## 3. Local Verification (Required Before Commit)

**For Python integration changes (.py files):**

```bash
# Run demisto-sdk format (MANDATORY per AGENTS.md)
demisto-sdk format -i Integrations/PaloAltoNetworks_Prisma_AIRs/

# Run unit tests
cd Integrations/PaloAltoNetworks_Prisma_AIRs/
python -m pytest PaloAltoNetworks_Prisma_AIRs_test.py -v

# Run demisto-sdk validate
cd ../..
demisto-sdk validate -i Packs/PaloAltoNetworks_Prisma_AIRs/

# Check for linting issues
demisto-sdk lint -i Integrations/PaloAltoNetworks_Prisma_AIRs/
```

- [ ] demisto-sdk format completed successfully
- [ ] All unit tests pass
- [ ] demisto-sdk validate passes with no errors
- [ ] Linting passes or issues are justified

**For YAML configuration changes (.yml files):**

```bash
# Validate YAML syntax
demisto-sdk validate -i Integrations/PaloAltoNetworks_Prisma_AIRs/PaloAltoNetworks_Prisma_AIRs.yml

# Check command structure
grep -A 20 "script.commands:" Integrations/PaloAltoNetworks_Prisma_AIRs/PaloAltoNetworks_Prisma_AIRs.yml

# Verify outputs are defined
grep -A 10 "outputs:" Integrations/PaloAltoNetworks_Prisma_AIRs/PaloAltoNetworks_Prisma_AIRs.yml
```

- [ ] YAML syntax is valid
- [ ] Command definitions are complete
- [ ] Arguments and outputs are properly structured
- [ ] Validation passes

**For unit test changes (_test.py files):**

```bash
# Run specific test
python -m pytest PaloAltoNetworks_Prisma_AIRs_test.py::test_function_name -v

# Run all tests with coverage
python -m pytest PaloAltoNetworks_Prisma_AIRs_test.py --cov=PaloAltoNetworks_Prisma_AIRs -v

# Check test data fixtures
ls -la test_data/
```

- [ ] New tests pass
- [ ] Existing tests still pass
- [ ] Mocks are properly configured
- [ ] Test fixtures are appropriately used

**For documentation changes:**

- [ ] Markdown formatting is correct
- [ ] Command examples are accurate
- [ ] No broken links
- [ ] Information matches implementation

---

## 4. Commit Changes

- [ ] Stage ONLY the files in the approved plan
- [ ] Write clear commit message explaining WHY
- [ ] Do NOT commit unrelated changes
- [ ] Run demisto-sdk pre-commit hooks (per AGENTS.md)

**Commit message format:**

```
<type>: <concise description>

- Specific change 1
- Specific change 2
- CLI reference: ./knowledge/prisma-airs-cli-main/docs/cli/<command>.md

Related to: <Prisma AIRs feature/API endpoint>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

---

## 5. Pre-Push Safety Check

**IMPORTANT: This is XSOAR marketplace content - changes affect all customers**

Before `git push`:

- [ ] Confirm all unit tests pass
- [ ] Verify demisto-sdk validate passes
- [ ] Check commit is on the intended branch (NOT master/main directly)
- [ ] Backward compatibility verified (no breaking changes without migration path)
- [ ] User explicitly approved the changes

**Quality gates:**
- All unit tests must pass
- demisto-sdk validate must pass
- demisto-sdk format must have been run
- Type hints are present (per AGENTS.md)
- CommandResults pattern is used correctly

If this is a new feature:
- [ ] CLI documentation in ./knowledge supports this
- [ ] API endpoints are verified in Prisma AIRs docs
- [ ] **SDK Zod schema validation completed** (field names match exactly)
- [ ] SDK client implementation reviewed for endpoint paths and response structure
- [ ] Unit tests use correct field names from SDK schema (not guessed names)
- [ ] YAML outputs match SDK schema field names exactly
- [ ] README.md is updated with new commands

---

## 6. Post-Push Verification

**After pushing to branch:**

- [ ] GitHub CI workflow started (if configured)
- [ ] All validation checks pass
- [ ] Create pull request with clear description
- [ ] Reference CLI documentation in PR description
- [ ] Link to test results
- [ ] No validation errors

**Pull Request Checklist:**

- [ ] Title clearly describes the change
- [ ] Description explains WHY (not just what)
- [ ] References CLI command/API being implemented
- [ ] Lists test coverage
- [ ] Notes any breaking changes or migration requirements
- [ ] Release notes added to ReleaseNotes/ directory

**If validation fails:**

1. Check CI logs for specific errors
2. Fix issues locally
3. Re-run demisto-sdk validate
4. Do NOT push additional "fixes" without verifying locally first

---

## 7. Update Documentation

**If behavior changed:**

- [ ] Update README.md with new commands and examples
- [ ] Update command_examples.txt with usage examples
- [ ] Update CLAUDE.md if new patterns or constraints added
- [ ] Add release notes to ReleaseNotes/X_Y_Z.md
- [ ] Document any CLI-to-XSOAR mapping decisions

---

## Never Skip Verification For

- Python integration code changes (always run unit tests)
- YAML configuration changes (always run demisto-sdk validate)
- New command additions (always add unit tests)
- API authentication changes (critical for SCM connection)
- CommandResults structure changes (affects all playbooks)
- Any change that affects backward compatibility
