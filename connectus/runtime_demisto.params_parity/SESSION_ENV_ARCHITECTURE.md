# Runtime Param-Parity — "Establish the Environment Once" Architecture (FINAL)

> **Status:** Design (architect), FINAL — grounded in an empirical idex experiment + user decisions. The environment is established **once, by a human, in a plain terminal**, before any migration begins. Autonomy relies on idex's **blanket execute auto-approve toggle** (empirically the only mechanism that works on this build) — **NOT** the per-command allowlist. The per-integration runtime **consumes** a prepared session, never improvises env, and **self-heals a dead port-forward** while hard-stopping only on true gcloud-auth expiry.

---

## 0. The real problem (not the symptoms)

Every blocker hit so far is the same class of defect: **the environment is assembled lazily, implicitly, and per-run, scattered across runtime code** — instead of established once, deterministically, before the pipeline starts.

| Symptom we patched | Real underlying cause |
|---|---|
| idex per-command approval prompts | We assumed the per-command **allowlist** gated execution (it does NOT — §1) |
| gcloud `Operation not permitted` on `credentials.db` | gcloud ran **by the agent in the idex sandbox** (read-only `~/.config`), config improvised mid-run |
| `copytree` symlink crash | That improvised config-copy lived in runtime capture code that shouldn't own env setup |
| GKE/VPN timeout, `gcloud auth login`, repo paths | Preconditions discovered only on failure, deep in the flow |
| port-forward churn | A long-lived resource (the kubectl tunnel) created/destroyed **per integration** |

**Root-cause fix:** one human-run setup establishes + verifies everything once; the agent never does *privileged* env work (only restarts the tunnel); autonomy comes from the blanket execute toggle.

---

## 1. EMPIRICAL FINDING — how idex auto-approval ACTUALLY works (decisive)

A 3-round experiment (4 distinct-prefix probe commands):

| Round | Config | Result |
|---|---|---|
| 1 | baseline | all 4 ran, **no prompts** |
| 2 | `alwaysAllowExecute` OFF, allowlist = `["echo IDEX_PROBE_A","ls content"]` | **all 4 ran, no prompts** — incl. `python3`/`git` NOT in the allowlist |
| 3 | `alwaysAllowExecute` ON, allowlist = `[]` empty | **all 4 ran, no prompts** |

**Conclusions:**
1. **`allowedCommands` does NOT gate execution on this build** (Round 2: non-allowlisted commands ran anyway).
2. **A blanket "auto-approve all execution" is the real mechanism** (Round 3: empty allowlist, still silent). This is `alwaysAllowExecute` / the master Auto-Approve→Execute toggle, and it works reliably.

**Design consequence:** rely ONLY on the **blanket execute toggle**. **Drop all reliance on `allowedCommands`** — no prefix entries, no no-`cd` requirement, no `&&`-chain concerns. Command shape is irrelevant to autonomy. The single host prerequisite for autonomy is: **Auto-Approve → Execute is ON.**

---

## 2. The decisive simplification — setup runs in the HUMAN's terminal

User-confirmed: **setup is a manual script the human runs in a normal terminal, ONCE, at batch start.** The agent prompts for it and waits for ACK.

Consequences:
- **`gcloud get-credentials` runs in the human terminal**, where `~/.config/gcloud` / `~/.kube/config` are **writable** → **DELETE the entire `.gcloud_tmp` writable-config copy** (`_gke_env()`, `copytree`, symlink handling, `CLOUDSDK_CONFIG`/`KUBECONFIG` redirect). That bug class only existed because gcloud ran under the agent sandbox.
- The agent **never** runs the privileged `get-credentials` (browser-auth-dependent). It MAY restart the **port-forward** (non-privileged tunnel, no `~/.config` write — see §6 Option C).

---

## 3. Precondition contract (single source of truth)

**ESTABLISH** = human setup creates it; **VERIFY** = setup checks and STOPS with an exact fix.

| # | Precondition | Kind | now → target |
|---|---|---|---|
| 1 | idex **blanket execute auto-approve** ON | VERIFY (host) | manual → setup prints reminder (can't set itself) |
| 2 | On `israel-gw` VPN (GKE reachable) | VERIFY | on-failure → setup probe |
| 3 | `gcloud auth login` done | VERIFY | on-failure → setup `gcloud config get-value account` |
| 4 | `gke-gcloud-auth-plugin` installed | VERIFY | implicit → setup check |
| 5 | GKE credentials (`get-credentials`) | **ESTABLISH** | per-run → human setup, once |
| 6 | kubectl **port-forward** to UCP shell pod | **ESTABLISH** | per-integration → human setup (session daemon); agent may revive |
| 7 | Root `.env` + required vars | VERIFY | preflight per run → setup, once |
| 8 | `CONNECTUS_REPO_DIR` → unified-connectors-content | VERIFY | preflight per run → setup; stored in descriptor |
| 9 | `CONNECTUS_BRANCH` personal namespaced | VERIFY | preflight per run → setup, once |
| 10 | param-parity probe in CommonServerPython | VERIFY | preflight per run → setup, once |
| 11 | gcloud/kubectl/git/demisto-sdk on PATH | VERIFY | preflight per run → setup, once |
| 12 | tenant id (one tenant/shell) | VERIFY | per run → setup; stored in descriptor |

---

## 4. Repo-path resolution (quick win, no new env var)

- **content repo:** already free via `env_loader.find_repo_root()` (`__file__`, cwd-independent). No new env var.
- **unified-connectors-content:** keep **`CONNECTUS_REPO_DIR` explicit** (other sibling repos may exist; auto-detect is wrong).
- **Quick win:** setup resolves both paths once and writes them into the **session descriptor**; per-run code reads them from there.

---

## 5. End-to-end flow (the user's spec, made precise)

**User:** *"continue migration of the next 20 integrations assigned to Joey."*

```
1. RESUME: skill enumerates Joey's in-progress/assigned integrations from the CSV,
   orders them (existing assignee-batch flow), and walks them one by one.

2. ONCE per batch — SESSION GATE (the only env human-gate):
   agent runs assert_session_live().
     - live  → proceed silently.
     - not live → PAUSE: "On the israel-gw VPN, run
         python3 content/connectus/runtime_demisto.params_parity/session_setup.py
       then reply 'ready'."  → human runs setup → ACKs → proceed.
   (Happens once for all 20, not per integration.)

3. PER INTEGRATION (unattended; blanket toggle approves every command):
   a. assert_session_live()  → cheap liveness; auto-revive a dead port-forward (§6);
      hard-stop only on gcloud-auth expiry.
   b. deploy ONCE per connector/integration/base-pack as needed (wrapper deploys
      before parity; port-forward reused, not recreated).
   c. runtime parity runs.
   d. MARKPASS POLICY (§7): auto-markpass on a CONFIDENT clean pass; ask for ACK
      ONLY on failure or low AI-confidence.
   e. recap + next integration.

4. ONCE at end — human runs session_teardown.py (kill tunnel, clear .session).
```

**Does idex prompt for lock/deploy/parity/release?** No — they're `subprocess` children inside the single `deploy_and_test.py` command; idex sees ONE command per integration, blanket-approved. No sub-prompts.

---

## 6. Resilience — expiry/death mid-batch (Option C: split recovery)

A long batch can outlive the session. Two things can die; they're handled differently.

### Idempotent, descriptor-tracked port-forward (never duplicate)
The descriptor stores the port-forward **PID + port**. Before starting/using a forward:
- **PID alive AND `port_is_live(port)`** → **REUSE it; do NOT start a second one.** (Answers "don't duplicate"; a blind 2nd forward on :8080 would `bind: address already in use` or create a confusing half-tunnel.)
- **PID dead OR port not live** → kill any stale PID, start a fresh forward, update the descriptor.
This makes `session_setup.py` safe to re-run (healthy = no-op; dead = clean re-establish).

### Option C — split recovery (user-chosen)
`assert_session_live()` classifies the failure:

| What died | How detected | Recovery |
|---|---|---|
| **Port-forward only** | `port_is_live(port)` false / PID dead, but gcloud auth OK | **Agent AUTO-REVIVES**: kill stale PID, restart `kubectl port-forward`, update descriptor, continue the batch. *No human, no prompt.* Safe because the tunnel restart does NOT write `~/.config` and the GKE creds were already human-established. |
| **gcloud auth expired** (refresh token dead / needs browser login) | `gcloud config get-value account` empty OR a `kubectl`/token call returns an auth error | **HARD-STOP + ask human**: "gcloud auth expired — run `gcloud auth login` and re-run `session_setup.py`, then reply 'ready'." Agent cannot do browser login. |

Note on tokens: `gke-gcloud-auth-plugin` auto-refreshes the short-lived **access token** from the stored refresh token on each kubectl call, so ordinary ~1h token expiry **self-heals**. The hard-stop is only for a dead **refresh token** (rare, long-running case).

`assert_session_live()` therefore returns one of: `LIVE` / `REVIVED` (auto, continue) / `AUTH_EXPIRED` (stop+ask) / `NOT_INITIALIZED` (stop+ask to run setup).

---

## 7. markpass / ACK policy (deterministic)

> **Default — to be confirmed by you (open decision #1).** The intent: auto-pass confident clean results; escalate failures or low confidence.

- **Auto-markpass (no prompt)** when ALL hold:
  - wrapper exit `0`, AND
  - results envelope `n_fail == 0`, AND
  - no `credentials` `VALUE_MISMATCH`, AND
  - no unexpected `OK_IGNORED` beyond the known hard-ignore set (`__params_parity_dump__`, `instance_name`, `ucp_credentials`).
- **PAUSE + present results + ask for ACK** when ANY:
  - exit `10` (real diff), or any non-zero exit, OR
  - the confidence conditions above aren't all met (e.g. a `credentials` mismatch — the known type-9 case — or unexpected ignored params).
- Setup/lock/deploy failures (exit `11/20/21/30`) → report the specific blocker, do not markpass (unchanged).

This is a deliberate **contract change** from today's "markpass is always run-through on exit 0" — captured for the skill update.

---

## 8. Component changes

### New: `session_env.py` (single env authority)
```
SESSION_DIR=<content-repo>/connectus/runtime_demisto.params_parity/.session
DESCRIPTOR_PATH=SESSION_DIR/parity_session.json

@dataclass SessionDescriptor:
    tenant_id, ucp_port, port_forward_pid, pod_name,
    content_repo, connectus_repo, created_ts, gcloud_account

write_descriptor / load_descriptor
port_is_live(port) -> bool                 # fast 1-shot TCP probe
gcloud_auth_ok() -> bool                   # account set + cheap kubectl token check
start_port_forward(desc) -> pid            # idempotent: reuse-if-live else (kill stale)+start
ensure_session() -> (status, descriptor)   # LIVE | REVIVED | AUTH_EXPIRED | NOT_INITIALIZED
assert_session_live() -> SessionDescriptor # wraps ensure_session; auto-revive on dead PF;
                                           # raise SessionNotReady(<fix msg>) on AUTH_EXPIRED/NOT_INITIALIZED
```
No `CLOUDSDK_CONFIG`, no copy, no `_gke_env`. The port-forward start/reuse logic (moved out of `ucp_capture`) lives here so BOTH the human setup and the agent auto-revive share ONE implementation.

### Refactor: `preflight_check.py` (VERIFY library)
Keep existing checks; add `_check_gcloud_authed()`, `_check_gke_reachable()` (israel-gw), `_check_auth_plugin()`. Read-only. `session_setup` calls `run_preflight()`.

### New: `session_setup.py` / `session_teardown.py` (human entrypoints)
Setup: VERIFY → `get-credentials` → `start_port_forward` (idempotent, detached `Popen(start_new_session=True)`) → write descriptor → health gate → print success + idex-toggle reminder. Teardown: kill PID, remove `.session/`.

### Refactor: `ucp_capture.py` (ASSUME, don't establish — major deletion)
Delete `start_port_forward`/`_cleanup_port_forward`/`stop_port_forward`/`_gke_env`/`.gcloud_tmp`/atexit/signal-reinstall. `capture_ucp_params`: `desc = assert_session_live()` (auto-revives PF if needed), use `desc.ucp_port`, talk `localhost:<port>`. AUTH_EXPIRED/NOT_INITIALIZED → exit 11 with the actionable human message.

### Refactor: `deploy_and_test.py` (consume session)
`run()` first step: `assert_session_live()` instead of per-integration `_run_preflight`. Lock/deploy/parity/release unchanged; `--skip-deploy` unchanged.

### Cleanup
`.gitignore`: add `.session/`; remove dead `.gcloud_tmp/` entry; delete leftover `.gcloud_tmp/` dir (currently still present in tabs).

---

## 9. State & lifecycle
```
.session/parity_session.json  (gitignored)
  { tenant_id, ucp_port, port_forward_pid, pod_name,
    content_repo, connectus_repo, created_ts, gcloud_account }
```
- Idempotent setup; per-run sub-second liveness; auto-revive dead tunnel; hard-stop on auth expiry; explicit teardown.

---

## 10. Autonomy layer — final
ONLY required idex setting: **blanket execute auto-approve** (`alwaysAllowExecute`), proven in §1. `allowedCommands` irrelevant (leave empty). The prior `settings.json` allowlist edits are harmless but not load-bearing. `session_setup.py`/`session_teardown.py` are human-run (gate never applies).

---

## 11. Migration plan (incremental, test-gated)
1. `session_env.py` — descriptor I/O, `port_is_live`, `gcloud_auth_ok`, idempotent `start_port_forward`, `ensure_session`/`assert_session_live`, `SessionNotReady`. Hermetic tests (mock subprocess/socket/fs).
2. Add 3 VERIFY checks to `preflight_check.py`. Tests.
3. `session_setup.py` + `session_teardown.py`. Mocked orchestration tests.
4. Gut `ucp_capture.py`; rewrite `ucp_capture_test.py` (retire start_port_forward tests; add assumes-session, auto-revive, raises-SessionNotReady).
5. `deploy_and_test.py` → `assert_session_live()`.
6. `.gitignore` + delete `.gcloud_tmp/`.
7. Skill update (`connectus-migration-SKILL.md`): batch Step 0 = ensure session (prompt human to run setup + ACK once); Step 13 = `deploy_and_test.py` per id with the §7 markpass policy; teardown at batch end; document the ONE host prereq (blanket toggle) + VPN/auth.
8. Live verify on AMPv2: human setup once → agent `deploy_and_test --skip-deploy` → zero prompts, reused port-forward, parity reaches a real result; then kill the tunnel and confirm auto-revive on the next integration.

> Transitional safety: in steps 4–5, if no descriptor exists, code MAY fall back to today's per-run behavior; drop the fallback once `session_setup` is the documented entry.

---

## 12. Why this is the root-cause fix
- **Autonomy on the mechanism that actually works** (blanket toggle, proven) — not the allowlist we mistakenly relied on.
- **Privileged env work leaves the agent** → gcloud-writability/symlink/`.gcloud_tmp` bug class **deleted, not patched**.
- **One authority + one human setup** → no per-run env improvisation; preconditions surface once.
- **Port-forward at session scope, idempotent, auto-revived** → no churn, no duplicates, survives a tunnel death; only true auth expiry needs a human.
- **Unattended by construction** → one approved command per integration covers lock→deploy→parity→release; confident passes auto-markpass; only failures/low-confidence/auth-expiry pause.

---

## 13. Open decisions for you
1. **Confirm the §7 markpass policy** exactly (the confidence conditions) — or simplify to "auto-pass on any exit 0, ask only on non-zero."
2. **Detached port-forward mechanism:** `Popen(start_new_session=True)` + PID in descriptor (recommended) vs launchd/systemd (skip).
3. **Revert the moot `settings.json` allowlist edits?** Harmless; recommend leave + document the blanket toggle is what matters.
