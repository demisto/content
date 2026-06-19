# Review Workflow

Use this workflow to review existing code, changes, or pull requests WITHOUT making modifications.

**READ-ONLY MODE: No edits, no implementations, only analysis and recommendations.**

---

## 1. Understand Review Scope

- [ ] What am I reviewing? (PR, commit, specific files, entire codebase)
- [ ] What is the review goal? (safety, quality, correctness, best practices)
- [ ] Is this a pre-commit review or post-deployment analysis?

---

## 2. Safety & Security Review

**Critical safety checks for this project:**

### docker-compose.yaml

- [ ] `LITELLM_SALT_KEY` is loaded from `.env` (not hardcoded)
- [ ] `LITELLM_MASTER_KEY` is loaded from `.env` (not hardcoded)
- [ ] `DATABASE_URL` references correct database credentials
- [ ] Volume mount `postgres_data` with name `litellm_postgres_data` preserves data
- [ ] Volume marked as `external: true` (migrated from previous setup)
- [ ] Port mapping 8080:4000 is correct
- [ ] No secrets hardcoded in environment variables
- [ ] Service dependencies correct (litellm depends_on db)
- [ ] Health checks defined for litellm and db
- [ ] Container restart policies appropriate

### litellm_config.yaml

- [ ] All models reference `os.environ/` for API keys (not hardcoded)
- [ ] Guardrail configurations reference environment variables
- [ ] Model names are consistent and documented
- [ ] Tags are appropriate and meaningful
- [ ] RPM/TPM limits are reasonable
- [ ] `supports_function_calling` flags are correct for each model size
- [ ] Ollama models reference `os.environ/OLLAMA_API_BASE`
- [ ] Protected models have guardrails attached
- [ ] Guardrail mode (pre_call/post_call) is appropriate

### .env and .env.example

- [ ] `.env` is in `.gitignore` (never committed)
- [ ] `.env.example` has no real secrets (only placeholders)
- [ ] `LITELLM_SALT_KEY` is not changing (if .env exists)
- [ ] `LITELLM_MASTER_KEY` format is correct (starts with "sk-")
- [ ] `DATABASE_URL` components match `POSTGRES_*` variables
- [ ] All required variables are documented in `.env.example`
- [ ] Provider API keys (OpenAI, AWS, Prisma) are documented
- [ ] Ollama API base URL is documented

### .github/workflows/

- [ ] Deployment triggers are correct (main branch only)
- [ ] Target host label matches production (`gcp-docker-ai-vm`)
- [ ] `rsync --exclude` protects `.env`
- [ ] Deployment paths include litellm_config.yaml
- [ ] No credentials or secrets in workflow file
- [ ] `docker compose up -d --build --remove-orphans` is correct

### .gitignore

- [ ] `.env` is excluded (must never be committed)
- [ ] Docker volumes are excluded (if local)
- [ ] `.claude/` session/cache/tmp directories excluded
- [ ] No sensitive files are accidentally tracked

---

## 3. Deployment Impact Analysis

- [ ] Will these changes trigger auto-deployment?
  - Push to `main` branch?
  - Modifies: docker-compose.yaml, litellm_config.yaml, .github/workflows/, config/, src/?
- [ ] What is the production impact?
  - Container restart required?
  - Existing API keys affected?
  - Model availability changes?
  - Data migration needed?
- [ ] Is this change reversible?
- [ ] What is the rollback procedure?

---

## 4. Code Quality Review

### Configuration Files

- [ ] YAML syntax is valid
- [ ] Indentation is consistent
- [ ] Values are appropriate for production
- [ ] Comments explain non-obvious settings
- [ ] Model configurations follow established patterns
- [ ] Guardrail configurations are complete

### Documentation

- [ ] README.md is accurate and up-to-date
- [ ] CLAUDE.md reflects current architecture
- [ ] Examples in documentation actually work
- [ ] No broken links or outdated references
- [ ] Environment variables documented
- [ ] Model configurations documented

### Version Control

- [ ] Commit messages are clear and descriptive
- [ ] Changes are focused and coherent
- [ ] No unnecessary files committed
- [ ] Git history is clean (no sensitive data in history)

---

## 5. Best Practices Check

**Docker Compose:**

- [ ] Using specific image tags (not `latest`) OR `latest` is intentional for LiteLLM
- [ ] Environment variables properly documented
- [ ] Volume mounts preserve data correctly
- [ ] Named volumes used for persistence
- [ ] Network configuration is appropriate
- [ ] Health checks defined for critical services
- [ ] Service dependencies defined correctly

**LiteLLM Configuration:**

- [ ] Model naming is consistent and clear
- [ ] Guardrails attached to appropriate models
- [ ] Tags used for categorization (protected/unprotected)
- [ ] Rate limits (rpm/tpm) are reasonable
- [ ] API bases reference environment variables
- [ ] Function calling support matches model capabilities
- [ ] Callbacks configured (prometheus)

**CI/CD:**

- [ ] Deployment process is idempotent
- [ ] Rollback process exists and is documented
- [ ] Secrets managed securely (not in code)
- [ ] Deployment validation included
- [ ] Error handling is appropriate
- [ ] Protected files excluded from sync

**Security:**

- [ ] No secrets in version control
- [ ] Sensitive files properly ignored
- [ ] Environment variables loaded securely
- [ ] Encryption keys protected
- [ ] Provider API keys isolated in .env
- [ ] Guardrails configured for AI security

---

## 6. Risk Assessment

**Rate the risk level:**

- **LOW** - Documentation changes, non-functional updates
- **MEDIUM** - Model additions, guardrail configs, non-breaking features
- **HIGH** - Volume mounts, encryption keys, database changes, auto-deploy to production

**For HIGH-risk changes, verify:**

- [ ] Change was tested locally before merge
- [ ] Backup/rollback plan exists and is tested
- [ ] User is aware of production impact
- [ ] Monitoring plan exists for post-deployment

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

- Pre-commit review of changes
- Pull request review
- Post-deployment analysis
- Security audit of configuration
- "What could go wrong?" analysis before risky changes
- Understanding unfamiliar code before modifying it
- Model configuration validation
- Guardrail configuration review
