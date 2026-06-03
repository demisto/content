# Self-Executing Checkpoint Gates — Design Proposal

> **STATUS: proposal.** Make selected connectus workflow **checkpoints**
> self-executing: running `markpass` on such a checkpoint **runs the underlying
> command itself** (e.g. `demisto-sdk pre-commit`) and writes the `✅` marker
> **only if the command succeeds** — instead of trusting the agent to have run
> it. This mirrors the proven auth-parity gate inside `set-auth`
> ([`api.py:654-678`](workflow_state/api.py:654)): verify first, persist only on
> pass.
>
> Companion to [`release_notes_checkpoint_design.md`](release_notes_checkpoint_design.md)
> (which converts `Release Notes` to a *pure* checkpoint — the opposite case,
> where the check is already owned by `demisto-sdk validate`). This doc covers
> the checkpoints whose checks are run **by the workflow** going forward.

---

## 1. Goal

Today these checkpoints are **bookkeeping only** — the agent runs the command,
eyeballs the result, then `markpass`es. `markpass` writes `✅` with no
verification ([`cmd_markpass` cli.py:1198-1199](workflow_state/cli.py:1198)).

We want the **workflow** to run the command and gate the marker on it, for:

| Step | Command the gate runs | Status |
|---|---|---|
| `precommit/validate/unit tests passed` | `demisto-sdk pre-commit -i <integration dir>` (lint + unit tests + validate) | **ACTIVE (Phase 1)** |
| `param parity test passes` | `python3 connectus/check_command_params.py …` (param-parity analyzer) | **DEFERRED** — entrypoint/verdict contract unconfirmed (§6.3) |
| `run manifest make validate` | `make validate` on the generated manifest | **DEFERRED** — manifest path unresolved (§6.1) |

After this change, `markpass "<id>" "precommit/validate/unit tests passed"`
**executes `demisto-sdk pre-commit`** and refuses to mark the step passed unless
it exits 0. The agent no longer self-certifies this step.

> **Scope (current):** only the **`precommit`** gate is being implemented now —
> it has no blocking dependency and is what actually runs the unit tests via the
> workflow. The `param_parity` and `make_validate` gates are designed here but
> **deferred** until their open questions (§6.1, §6.3) are resolved. The gate
> mechanism is per-step and opt-in, so they can be wired in later with no
> rework.

`generated manifest`, `code reviewed`, `code merged` stay **pure** checkpoints
(no command to run, or inherently human) — they keep today's plain `markpass`.

---

## 2. Mechanism — reuse the auth-parity pattern exactly

The auth-parity gate already establishes every piece we need. We replicate its
structure for checkpoints:

| Concern | auth-parity (existing) | checkpoint gate (new) |
|---|---|---|
| Where the gate runs | `set_integration_auth` API ([`api.py:654`](workflow_state/api.py:654)) | `markpass_integration_step` API ([`api.py:468`](workflow_state/api.py:468)) |
| Runner | `_run_auth_parity_for_set_auth` ([`api.py:740`](workflow_state/api.py:740)) | new `_run_checkpoint_gate(...)` |
| Verdict | `_evaluate_parity_for_set_auth` → `{"allow", "reason"}` ([`api.py:828`](workflow_state/api.py:828)) | gate returns `{"allow", "reason", "exit_code", "stdout_tail", "stderr_tail"}` |
| Reject-before-persist | persist only after `gate["allow"]` ([`api.py:672`](workflow_state/api.py:672)) | persist (`apply_step_action`+`save_csv`) only after gate passes |
| Bypass | `CONNECTUS_SKIP_AUTH_PARITY=1` param-or-env ([`api.py:641-646`](workflow_state/api.py:641)) | `--no-gate` flag + `CONNECTUS_SKIP_CHECKPOINT_GATES=1` env |
| Dry-run | `--dry-run` → `dry_run_auth`, no write ([`cli.py:471-485`](workflow_state/cli.py:471)) | `--dry-run` → run gate, print verdict, no write |

**Ordering is the enforcement** (same as set-auth): the gate runs *before*
`apply_step_action`; on failure we `return`/`sys.exit` and the marker write never
happens. `apply_step_action` mutates the row but does not save
([`state_machine.py:226`](workflow_state/state_machine.py:226)); `save_csv` is
called by the handler afterward — so a gate inserted before it is naturally
transactional.

---

## 3. Config — declare the gate per step

### 3.1 New `Step` field

Add one optional field to the frozen `Step` dataclass
([`types.py:61`](workflow_state/types.py:61)), appended last to preserve the
positional signature:

```python
    gate: Optional[str] = None   # named checkpoint-gate key, or None for pure markpass
```

`gate` is a **named key into a gate registry** (mirroring how `json_schema` /
`cross_check` are named keys into validator registries — *not* a raw shell
string in the YAML). This keeps the command definitions in Python (where they
can resolve paths, build argv safely, set timeouts) and the YAML purely
declarative.

### 3.2 Gate registry (Python)

A small registry in a new `workflow_state/gates.py`, keyed by name, each value a
spec describing how to build + run the command:

```python
# gates.py — illustrative
@dataclass(frozen=True)
class GateSpec:
    name: str
    build_argv: Callable[[dict], list[str]]   # (files_info) -> argv
    cwd: Callable[[dict], str]                 # (files_info) -> working dir
    default_timeout: int

GATES: dict[str, GateSpec] = {
    "precommit": GateSpec(
        name="precommit",
        build_argv=lambda f: ["demisto-sdk", "pre-commit", "-i", f["directory"]],
        cwd=lambda f: BASE_DIR,
        default_timeout=1800,            # pre-commit pulls docker; generous
    ),
    "make_validate": GateSpec(
        name="make_validate",
        build_argv=lambda f: ["make", "validate"],
        cwd=lambda f: <manifest dir>,    # see §6 open question
        default_timeout=600,
    ),
    "param_parity": GateSpec(
        name="param_parity",
        build_argv=lambda f, iid: ["python3", "connectus/check_command_params.py", iid],
        cwd=lambda f: BASE_DIR,
        default_timeout=900,
    ),
}
```

The config loader validates `gate:` against `GATES.keys()` exactly like it
validates `json_schema` names ([`config_loader.py:439-447`](workflow_state/config_loader.py:439)),
appending an error for unknown keys.

### 3.3 YAML changes

```yaml
  - name: "run manifest make validate"
    kind: checkpoint
    gate: make_validate

  - name: "precommit/validate/unit tests passed"
    kind: checkpoint
    gate: precommit

  - name: "param parity test passes"
    kind: checkpoint
    gate: param_parity
```

Steps without a `gate:` key (`generated manifest`, `Release Notes`,
`code reviewed`, `code merged`) keep `gate=None` and behave exactly as today.

---

## 4. The runner — `_run_checkpoint_gate`

A generic subprocess runner modeled on `_run_auth_parity_for_set_auth`
([`api.py:740-825`](workflow_state/api.py:740)) but for plain shell commands
(no DockerConfig — `demisto-sdk pre-commit` manages its own docker):

```python
def _run_checkpoint_gate(integration_id: str, gate_name: str,
                         timeout: int | None) -> dict:
    spec = GATES.get(gate_name)
    if spec is None:
        return {"allow": False, "reason": f"unknown gate '{gate_name}'",
                "exit_code": None}

    files_info = get_integration_files(integration_id)   # api.py:236
    if "error" in files_info:
        return {"allow": False, "reason": files_info["error"],
                "exit_code": None}                        # infra → exit 3

    argv = spec.build_argv(files_info)
    cwd = spec.cwd(files_info)
    t = timeout or spec.default_timeout
    try:
        proc = subprocess.run(argv, cwd=cwd, capture_output=True,
                              text=True, timeout=t)
    except subprocess.TimeoutExpired:
        return {"allow": False, "reason": f"gate '{gate_name}' timed out after {t}s",
                "exit_code": None}
    return {
        "allow": proc.returncode == 0,
        "reason": ("passed" if proc.returncode == 0
                   else f"`{' '.join(argv)}` exited {proc.returncode}"),
        "exit_code": proc.returncode,
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-4000:],
    }
```

Directory resolution reuses `get_integration_files(...)["directory"]`
([`api.py:323`](workflow_state/api.py:323)) joined with `BASE_DIR`, identical to
the parity runner ([`api.py:765-766`](workflow_state/api.py:765)).

---

## 5. Wiring into `markpass`

> **Centralize in the API to avoid divergence.** Today the gate-relevant logic
> is duplicated across `cmd_markpass` ([`cli.py:1133`](workflow_state/cli.py:1133))
> and `markpass_integration_step` ([`api.py:436`](workflow_state/api.py:436)).
> Put the gate in the **API** (the way `set-auth` keeps the gate in
> `set_integration_auth`) and have the CLI handler call through it, so there is
> one enforcement path.

### 5.1 API — `markpass_integration_step`

Insert between the `flag_auto_na_target` loop and `apply_step_action`
([`api.py:467`](workflow_state/api.py:467), just before line 468):

```python
    # ----- Checkpoint gate --------------------------------------------------
    if target.gate and not skip_gate:
        verdict = _run_checkpoint_gate(integration_id, target.gate, gate_timeout)
        if not verdict["allow"]:
            return {
                "error": (f"'{step_name}' rejected — gate '{target.gate}' failed: "
                          f"{verdict['reason']}. Fix the underlying problem and "
                          f"re-run markpass, or bypass with --no-gate / "
                          f"CONNECTUS_SKIP_CHECKPOINT_GATES=1."),
                "gate": verdict,
            }
    # (fall through to apply_step_action + save_csv — unchanged, api.py:468-483)
```

`skip_gate` follows the param-or-env pattern from auth-parity
([`api.py:641-642`](workflow_state/api.py:641)):

```python
    if skip_gate is None:
        skip_gate = os.environ.get("CONNECTUS_SKIP_CHECKPOINT_GATES", "").strip() == "1"
```

Add `skip_gate: bool | None = None` and `gate_timeout: int | None = None`
params to `markpass_integration_step`.

### 5.2 CLI — `cmd_markpass`

- Parse flags up front with a new `_parse_markpass_flags(args)` helper modeled on
  `_parse_set_auth_flags` ([`cli.py:355-428`](workflow_state/cli.py:355)),
  returning `(remaining, dry_run, no_gate, timeout)`. Valued flags use the
  `--timeout=N` form only (reject the space form, same as set-auth).
- For `--dry-run`: call `_run_checkpoint_gate` directly, print the verdict +
  `stdout_tail`/`stderr_tail`, `sys.exit(0 if allow else 1)` — **never write the
  CSV** (mirrors [`cli.py:471-485`](workflow_state/cli.py:471)).
- Otherwise call `markpass_integration_step(name, step_name, skip_gate=no_gate,
  gate_timeout=timeout)` and translate an `{"error", "gate"}` envelope into a
  printed message + non-zero exit (print the `stderr_tail` so the operator sees
  why it failed).

The existing `flag_auto_na_target` short-circuit
([`cli.py:1178-1196`](workflow_state/cli.py:1178)) stays **above** the gate, so
an auto-N/A still wins without running a command.

### 5.3 Exit codes

Mirror the symmetric `set_auth_exit_code` / `dry_run_exit_code` pair
([`api.py:1129-1191`](workflow_state/api.py:1129)):
- `0` — passed (marked / would-mark).
- `1` — gate failed (command exited non-zero / timed out).
- `3` — infra error (files lookup failed, gate name unknown).

---

## 6. Open questions / things to nail down before coding

1. **`make validate` target directory.** The gate needs to know *where the
   generated manifest lives* to run `make validate` in it. The CSV doesn't
   currently record the manifest path. Options:
   - derive it from a known convention (manifest output dir per connector), or
   - add a tiny data column / lookup recording the manifest path at
     `generated manifest` time.
   **Needs the manifest-generation convention confirmed** before the
   `make_validate` gate is implementable. The `precommit` and `param_parity`
   gates have no such dependency (they key off the integration dir + id) and can
   ship first.
2. **Runtime cost & where it runs.** `demisto-sdk pre-commit` pulls docker and
   can take many minutes. Running it *inside* `markpass` means the CLI call
   blocks for that long. That's acceptable (the agent was running it anyway),
   but the default timeout must be generous (§3.2 uses 1800s) and the CLI should
   stream/echo progress, not look hung. Confirm the agent's tool-call timeout
   tolerates this, or require `--timeout=` tuning.
3. **`param parity test passes` invocation.** Confirm the exact
   `check_command_params.py` entrypoint/argv and success criteria (exit 0 vs.
   parsing a verdict). If it returns a structured verdict rather than a 0/1 exit
   code, the `param_parity` gate's `build_argv` + a small result-parser replaces
   the bare `returncode == 0` check.
4. **CI relationship.** CI already runs pre-commit on the PR
   (`pre-commit.yml`). The local gate is a *fast-feedback duplicate*, not a
   replacement. That's fine and intentional — keep both. No CI change needed.
5. **Schema bump?** Adding a `gate:` key and a `Step.gate` field is an
   **additive** config/schema change with a backward-compatible default
   (`None`), and writes no new cell values — so it does **not** require a
   `schema_version` bump (unlike the RN data→checkpoint migration, which does).
   Verify the config loader tolerates the new key on old configs (it should, via
   `item.get("gate")`).

---

## 7. Skill (`connectus-migration-SKILL.md`) updates

- Reframe the three gated checkpoints: the agent no longer "runs `demisto-sdk
  pre-commit` then marks it" — it just runs `markpass`, and **`markpass` runs
  the command**. Update the run-through policy note accordingly (these are still
  no-prompt operations).
- Document `--dry-run` (run the gate without committing) and the bypass
  (`--no-gate` / `CONNECTUS_SKIP_CHECKPOINT_GATES=1`) with a strong caveat that
  bypass is for exceptional cases and must be justified in commit notes (same
  framing as `CONNECTUS_SKIP_AUTH_PARITY`).
- Note that a failed gate prints the command's `stderr_tail` — the operator
  fixes the underlying problem and re-runs `markpass`, exactly like a failed
  parity gate.

---

## 8. Phasing recommendation

1. **Phase 1 — infra:** `Step.gate` field, config loader support, `gates.py`
   registry, `_run_checkpoint_gate`, API+CLI wiring, `--dry-run`/`--no-gate`,
   exit codes. Ship with the **`precommit`** gate wired to
   `precommit/validate/unit tests passed` (highest value, no path dependency).
2. **Phase 2 (DEFERRED) — `param_parity`** gate once the entrypoint/verdict
   contract (§6.3) is confirmed.
3. **Phase 3 (DEFERRED) — `make_validate`** gate once the manifest-path question
   (§6.1) is resolved.

Each phase is independently shippable because gates are per-step and opt-in via
the `gate:` key.
