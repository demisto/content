# Implementation Workflow

Use this workflow ONLY after plan approval. Never implement without an approved plan.

---

## 1. Pre-Flight Checks

- [ ] Plan was explicitly approved by user
- [ ] All UNKNOWN items were resolved
- [ ] All ASSUMED items were confirmed or documented
- [ ] Rollback plan is clear

**STOP if:**
- No plan was created
- Plan was not approved
- Any UNKNOWN items remain unresolved

---

## 2. Execute Changes Exactly as Planned

- [ ] Follow the approved plan step-by-step
- [ ] Make ONLY the changes listed in the plan
- [ ] Do NOT add scope, features, or "improvements"
- [ ] Do NOT refactor unrelated code
- [ ] Reference plan in commit messages

**Safety checks during implementation:**

- [ ] If editing docker-compose.yaml → verify syntax before saving
- [ ] If editing litellm_config.yaml → verify YAML syntax and model definitions
- [ ] If editing .env → confirm salt key and master key unchanged (or explicitly approved to change)
- [ ] If editing .github/workflows → verify deployment target and triggers
- [ ] Never commit .env file or database volumes

---

## 3. Local Verification (Required Before Commit)

**For docker-compose.yaml changes:**

```bash
# Validate syntax
docker compose config

# Test locally (if .env exists)
docker compose up -d
docker compose ps
docker compose logs -f litellm

# Verify LiteLLM accessible and healthy
curl http://localhost:8080/health/liveliness

# Check database
docker compose exec db pg_isready -U llmproxy -d litellm

# Stop test
docker compose down
```

- [ ] Syntax validation passed
- [ ] All containers start without errors
- [ ] Logs show no critical errors
- [ ] LiteLLM health check passes
- [ ] Database connection successful

**For litellm_config.yaml changes:**

```bash
# Start services
docker compose up -d

# Check LiteLLM loaded config correctly
docker compose logs litellm | grep -i "config"

# Verify models are available
curl http://localhost:8080/v1/models \
  -H "Authorization: Bearer ${LITELLM_MASTER_KEY}"

# Test a model endpoint
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer ${LITELLM_MASTER_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"model": "ollama_llama3", "messages": [{"role": "user", "content": "test"}]}'
```

- [ ] Config file loaded without errors
- [ ] All expected models appear in /v1/models
- [ ] Test request succeeds (or fails with expected error)
- [ ] Guardrails are active if configured

**For .github/workflows changes:**

- [ ] YAML syntax is valid
- [ ] Deployment triggers are correct
- [ ] Protected files (.env) are excluded from sync
- [ ] Target host label matches production runner

**For documentation changes:**

- [ ] Markdown formatting is correct
- [ ] No broken links
- [ ] Information is accurate and current

---

## 4. Commit Changes

- [ ] Stage ONLY the files in the approved plan
- [ ] Write clear commit message explaining WHY
- [ ] Do NOT commit unrelated changes
- [ ] Verify .env is not staged

**Commit message format:**

```
<type>: <concise description>

- Specific change 1
- Specific change 2

Related to: <context or issue if applicable>
```

Types: `feat`, `fix`, `docs`, `config`, `ci`, `refactor`

---

## 5. Pre-Push Safety Check

**CRITICAL: Pushing to main auto-deploys to production**

Before `git push`:

- [ ] Confirm changes were tested locally
- [ ] Verify commit is on the intended branch
- [ ] Check if this will trigger auto-deployment
- [ ] Rollback plan is documented and ready
- [ ] User explicitly approved pushing to production (if applicable)

**Auto-deploy triggers:**
- Push to `main` branch
- Changes to: docker-compose.yaml, litellm_config.yaml, .github/workflows/**, config/**, src/**

If auto-deploy will trigger:
- [ ] User is aware and approved
- [ ] Changes were tested locally
- [ ] Monitoring plan exists to verify deployment
- [ ] Rollback steps are documented

---

## 6. Post-Push Verification

**After pushing to main (triggers auto-deploy):**

- [ ] GitHub Actions workflow started successfully
- [ ] Workflow completed without errors
- [ ] Verify on production:
  - [ ] Containers running: `docker compose ps`
  - [ ] Health check passes: `curl http://<GCP_IP>:8080/health/liveliness`
  - [ ] Models available: `curl http://<GCP_IP>:8080/v1/models -H "Authorization: Bearer $MASTER_KEY"`
  - [ ] Database accessible: `docker compose exec db pg_isready`
- [ ] No rollback needed

**If deployment fails:**

1. Check GitHub Actions logs for errors
2. Follow rollback procedure in CLAUDE.md
3. Do NOT push additional "fixes" without new plan approval

---

## 7. Update Documentation

**If behavior changed:**

- [ ] Update README.md if user-facing behavior changed
- [ ] Update CLAUDE.md if new constraints or processes added
- [ ] Document any new assumptions or gotchas

---

## Never Skip Verification For

- docker-compose.yaml changes (always test locally first)
- litellm_config.yaml changes (always verify models load)
- .github/workflows changes (auto-deploy implications)
- Environment variable changes (salt key risk)
- Any change that will deploy to production
