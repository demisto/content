# Plan-First Workflow

Use this workflow before making ANY changes to code or configuration.

---

## 1. Understand the Request

- [ ] Restate the goal in clear, specific terms
- [ ] Identify what type of change this is:
  - Configuration change (docker-compose.yaml, litellm_config.yaml, .env)?
  - CI/CD change (.github/workflows/)?
  - Documentation only?
- [ ] Check production impact:
  - Does this trigger auto-deploy to production?
  - Does this affect running LiteLLM proxy or stored API keys?
  - Does this change persistent data or volumes?

---

## 2. Investigate Current State

**Read before deciding:**

- [ ] Read all files that will be affected
- [ ] Check git status and recent commits
- [ ] Review CLAUDE.md for safety constraints
- [ ] Identify existing patterns and conventions

**Critical checks for this project:**

- [ ] If touching docker-compose.yaml → read current volume mounts, env vars, ports, services
- [ ] If touching litellm_config.yaml → read current model configurations, guardrails, settings
- [ ] If touching .env → verify LITELLM_SALT_KEY and LITELLM_MASTER_KEY are not changing
- [ ] If touching workflows → understand current deployment triggers
- [ ] If touching .gitignore → verify .env and volumes remain excluded

---

## 3. Identify Knowledge Gaps

Tag each assumption with confidence level:

- **VERIFIED** - Confirmed by reading files or documentation
- **ASSUMED** - Logical inference but not confirmed
- **UNKNOWN** - Missing information, must ask

**Stop and ask if ANY of these are UNKNOWN:**

- Will this change trigger auto-deployment?
- Will this affect existing LiteLLM users, API keys, or stored credentials?
- Will this affect model availability or guardrail behavior?
- Is this change reversible?
- What are the rollback steps?

---

## 4. Design Solution

- [ ] List all files that will be modified
- [ ] Describe changes to each file specifically
- [ ] Identify risks and mitigations:
  - Auto-deploy risk? Test locally first
  - Volume mount change? Verify data preservation
  - Env var change? Document impact
  - CI/CD change? Understand deployment implications
  - Model config change? Verify compatibility with existing integrations

**For docker-compose.yaml changes:**

- [ ] Will volume mounts preserve postgres_data (litellm_postgres_data)?
- [ ] Will environment variables break existing stored keys?
- [ ] Are port mappings still correct (8080:4000)?
- [ ] Is the LiteLLM/PostgreSQL/Prometheus version change intentional?
- [ ] Are service dependencies correct (litellm depends_on db)?

**For litellm_config.yaml changes:**

- [ ] Are model names changing (breaking existing integrations)?
- [ ] Are guardrails correctly configured with required env vars?
- [ ] Are tags, rpm, tpm limits appropriate?
- [ ] Is YAML syntax valid?
- [ ] Are Ollama models pointing to correct OLLAMA_API_BASE?

**For .env changes:**

- [ ] Is LITELLM_SALT_KEY remaining unchanged (critical)?
- [ ] Is LITELLM_MASTER_KEY remaining unchanged (unless password rotation)?
- [ ] Do DATABASE_URL components match POSTGRES_* variables?
- [ ] Are provider API keys valid?
- [ ] Are Prisma AIRS credentials correct?

**For .github/workflows changes:**

- [ ] Are deployment triggers correct (main branch only)?
- [ ] Is the target host label correct (gcp-docker-ai-vm)?
- [ ] Is .env excluded from sync?
- [ ] Are the correct paths triggering deployment?

---

## 5. Present Plan for Approval

**Plan must include:**

1. **What**: Specific changes to specific files
2. **Why**: Reason for the change
3. **Risk**: What could go wrong
4. **Verification**: How to test/verify it works
5. **Rollback**: How to undo if it breaks

**Wait for explicit approval before proceeding.**

If user says "go ahead" or "yes" or "approved" → move to implement workflow.

---

## Never Skip This Workflow For

- Changes to docker-compose.yaml
- Changes to litellm_config.yaml (model/guardrail configs)
- Changes to .github/workflows/
- Changes to environment variables
- Adding/removing models from configuration
- Changing guardrail settings
- Adding/removing files from .gitignore
- Upgrading LiteLLM, PostgreSQL, or Prometheus versions
- Modifying volume mounts or networking
- Any change that will auto-deploy to production
