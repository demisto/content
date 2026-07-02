# Review Workflow

Use this workflow to review existing code, changes, or pull requests WITHOUT making modifications.

**READ-ONLY MODE: No edits, no implementations, only analysis and recommendations.**

---

## 1. Understand Review Scope

- [ ] What am I reviewing? (PR, commit, specific files, integration code)
- [ ] What is the review goal? (XSOAR compliance, quality, correctness, API accuracy)
- [ ] Is this a pre-commit review or post-implementation analysis?

---

## 2. XSOAR Standards & Compliance Review

**Critical compliance checks per AGENTS.md:**

### Python Integration Files (.py)

- [ ] Type hints are present on all functions (MANDATORY per AGENTS.md)
- [ ] `CommandResults` is used (NOT deprecated `demisto.results()`)
- [ ] Error handling is graceful with user-friendly messages
- [ ] API authentication uses Client ID/Secret from credentials parameter
- [ ] No hardcoded credentials or API keys
- [ ] Logging uses `demisto.debug()` appropriately
- [ ] Functions follow existing code patterns
- [ ] Helper functions are properly documented
- [ ] Code is formatted with `demisto-sdk format`

### YAML Configuration Files (.yml)

- [ ] Command names follow pattern: `<feature>-<action>-<object>`
- [ ] All arguments have clear descriptions
- [ ] Required vs optional arguments are correctly marked
- [ ] Outputs are structured with proper context paths
- [ ] Context output keys follow XSOAR naming conventions
- [ ] Credentials parameter uses correct type (authentication fields)
- [ ] Integration configuration parameters are well-documented
- [ ] No sensitive defaults in configuration

### Unit Test Files (_test.py)

- [ ] Tests use proper mocking for API responses
- [ ] Both success and failure scenarios are covered
- [ ] Test fixtures in test_data/ are appropriately used
- [ ] Tests validate CommandResults structure
- [ ] Mock objects match actual API response structure
- [ ] Edge cases are tested (empty responses, errors)
- [ ] All new commands have corresponding tests

### Pack Metadata (pack_metadata.json)

- [ ] Version follows semantic versioning
- [ ] Dependencies list is accurate and minimal
- [ ] Support level is correct (XSOAR official)
- [ ] Supported modules match pack capabilities
- [ ] Author and URL information is accurate
- [ ] Pack description is clear and marketing-appropriate

---

## 3. API & CLI Accuracy Review

**Verify implementation matches Prisma AIRs documentation:**

- [ ] API endpoints match those in ./knowledge/docs/Prisma_AIRs/
- [ ] Request/response formats match CLI tool in ./knowledge/prisma-airs-cli-main/
- [ ] Command parameters match CLI command options
- [ ] Output structure matches API response structure
- [ ] Authentication flow matches SCM Client ID/Secret pattern
- [ ] Error codes from API are handled appropriately
- [ ] Rate limiting is considered (if applicable)
- [ ] API versioning is documented

**CLI-to-XSOAR Conversion Quality:**

- [ ] CLI command maps logically to XSOAR command
- [ ] CLI flags/options map to XSOAR arguments
- [ ] CLI output format adapted appropriately for XSOAR context
- [ ] Batch operations handled correctly (CSV export, bulk scans)
- [ ] File upload/download operations work correctly

---

## 4. Code Quality Review

### Python Code Quality

- [ ] Functions have clear, descriptive names
- [ ] Code follows PEP 8 style guidelines
- [ ] Complex logic has explanatory comments
- [ ] No duplicate code (DRY principle)
- [ ] Error messages are actionable for users
- [ ] Constants are properly defined (not magic numbers/strings)
- [ ] API client code is reusable and maintainable

### YAML Quality

- [ ] YAML syntax is valid (validated with demisto-sdk)
- [ ] Indentation is consistent
- [ ] Descriptions are clear and user-friendly
- [ ] Examples are provided where helpful
- [ ] Default values are sensible
- [ ] Command outputs are well-structured

### Documentation

- [ ] README.md accurately describes all commands
- [ ] Command examples in command_examples.txt work correctly
- [ ] CLAUDE.md reflects current integration state
- [ ] No broken links or outdated references
- [ ] CLI-to-XSOAR mapping is documented
- [ ] API endpoints are referenced with knowledge/ paths

### Version Control

- [ ] Commit messages explain WHY (not just what)
- [ ] Changes are focused and atomic
- [ ] No unnecessary files committed
- [ ] Release notes added for user-facing changes

---

## 5. Best Practices Check

**XSOAR Integration Patterns:**

- [ ] CommandResults used consistently (not demisto.results)
- [ ] Context outputs follow XSOAR naming conventions (PascalCase)
- [ ] Readable outputs are formatted clearly for analysts
- [ ] Raw responses are included in context when useful
- [ ] Pagination is handled for large result sets
- [ ] Timeouts are set appropriately for API calls
- [ ] Retry logic for transient API errors

**Prisma AIRs Specific:**

- [ ] SCM authentication handled correctly (Client ID/Secret)
- [ ] Tenant Service Group ID parameter implemented
- [ ] Runtime scanning follows security profile patterns
- [ ] DLP filtering profiles correctly configured
- [ ] Red Team modes (static/dynamic/custom) implemented correctly
- [ ] Model security groups and rules properly structured
- [ ] Backup/restore functionality follows API patterns

**Error Handling:**

- [ ] API errors translated to user-friendly messages
- [ ] HTTP error codes handled appropriately
- [ ] Authentication failures provide clear guidance
- [ ] Network timeouts handled gracefully
- [ ] Invalid parameters caught before API call
- [ ] Error context includes helpful troubleshooting info

**Security:**

- [ ] No credentials hardcoded anywhere
- [ ] API keys loaded from integration configuration
- [ ] Sensitive data not logged in debug statements
- [ ] User input sanitized before API calls
- [ ] File uploads validated (if applicable)
- [ ] Output sanitized to prevent injection attacks

---

## 6. Risk Assessment

**Rate the risk level:**

- **LOW** - Documentation changes, new commands with tests, minor fixes
- **MEDIUM** - New features, command signature changes with backward compatibility
- **HIGH** - Breaking changes, authentication changes, API client modifications, pack dependency changes

**For HIGH-risk changes, verify:**

- [ ] Breaking changes documented with migration guide
- [ ] Backward compatibility maintained OR migration path clear
- [ ] All unit tests updated and passing
- [ ] Integration tests performed (if available)
- [ ] Impact on existing playbooks assessed
- [ ] Release notes explain the change clearly

---

## 7. Provide Review Findings

**Report structure:**

### Summary
- What was reviewed
- Overall assessment (approve / needs changes / critical issues)

### Critical Issues (Must Fix)
- List anything that could cause data loss, security breach, or production outage
- Each issue with: what's wrong, why it's dangerous, how to fix

### Recommendations (Should Fix)
- List improvements that enhance quality, safety, or maintainability
- Each with: current state, suggested improvement, benefit

### Observations (Nice to Have)
- Minor improvements or style suggestions
- Optional optimizations

### Questions
- Anything unclear or requiring clarification
- Assumptions that need verification

---

## 8. Stop - Do Not Implement

**This is a REVIEW workflow - READ-ONLY mode.**

- [ ] Do NOT edit files
- [ ] Do NOT implement suggestions
- [ ] Do NOT create commits
- [ ] Report findings and await user decision

If user wants changes implemented:

1. Present findings from this review
2. Get approval for specific changes
3. Switch to plan-first workflow
4. Create plan based on review findings
5. Get plan approval
6. Switch to implement workflow

---

## Use This Workflow For

- Pre-commit review of integration changes
- Pull request review for new commands
- XSOAR compliance validation
- CLI-to-XSOAR conversion accuracy check
- API implementation correctness review
- Unit test coverage assessment
- Backward compatibility analysis
- Security review of authentication code
- "What could go wrong?" analysis before risky changes
