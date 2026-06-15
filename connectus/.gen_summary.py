import json, glob, os, subprocess

CTX_DIR = "connectus/.idex_ctx_tmp"
IDS = ["CIRCL","CIRCL CVE Search","CloudConvert","Exabeam","Exabeam Data Lake",
       "ExabeamSecOpsPlatform","Core Lock","Demisto Lock","Unit 42 Intelligence",
       "Palo Alto Networks - Prisma SASE"]

AUTH_SUMMARY = {
    "CIRCL": "Plain (HTTP Basic via credentials widget)",
    "CIRCL CVE Search": "NoneRequired (public CVE API)",
    "CloudConvert": "APIKey (Bearer via credentials widget)",
    "Exabeam": "APIKey XOR Plain (api_token OR credentials/login)",
    "Exabeam Data Lake": "Plain (username/password login session)",
    "ExabeamSecOpsPlatform": "Passthrough (OAuth2 client_credentials)",
    "Core Lock": "NoneRequired (local lock utility, JS)",
    "Demisto Lock": "NoneRequired (local lock utility, JS)",
    "Unit 42 Intelligence": "NoneRequired (platform getLicenseID() Bearer)",
    "Palo Alto Networks - Prisma SASE": "Passthrough (OAuth2 client_credentials, tsg_id scope)",
}

NOTES = {
    "CIRCL": "No main(); bare top-level dispatch. All params module-level/auth-ignored; commands use args only.",
    "CIRCL CVE Search": "integration_reliability omitted (framework param). All commands args-only.",
    "CloudConvert": "Hidden legacy `apikey` (type 4) omitted everywhere (misclassification pattern #7).",
    "Exabeam": "XOR dual-auth (validate rejects both). Manual fetch-incidents params (static blind spot). UCP code fix applied (2 reads).",
    "Exabeam Data Lake": "cluster_name -> other_connection (required connection config).",
    "ExabeamSecOpsPlatform": "fetch-events/fetch-incidents manual params (static blind spot). UCP code fix applied (2 reads). Capabilities: Log Collection + Automation.",
    "Core Lock": "Non-Python (JS) -> analyzer skipped; manual per-command review. timeout/sync behavioral.",
    "Demisto Lock": "Non-Python (JS) -> analyzer skipped; manual per-command review. timeout/polling_interval/sync.",
    "Unit 42 Intelligence": "Pre-dispatch fan-out: create_relationships/create_threat_object_indicators added to ip/domain/url/file. getLicenseID() platform auth.",
    "Palo Alto Networks - Prisma SASE": "tsg_id placed inside Passthrough profile (OAuth scope), not other_connection. Per-command tsg_id is an arg override (disjointness).",
}

def status_icon(d):
    if d.get("all_complete"):
        return "✅ complete"
    # reached step 8 (manifest) but blocked by sandbox
    if d.get("current_step_index", 0) >= 8:
        return "⛔ blocked (steps 8-15: sandbox)"
    return "⏳ in-progress"

ctxs = {}
for i in IDS:
    fn = i.replace(" ", "_").replace("/", "_")
    with open(os.path.join(CTX_DIR, fn + ".json")) as f:
        ctxs[i] = json.load(f)

branch = subprocess.run(["git","rev-parse","--abbrev-ref","HEAD"],capture_output=True,text=True).stdout.strip()
utc = subprocess.run(["date","-u","+%Y-%m-%d %H:%M:%S UTC"],capture_output=True,text=True).stdout.strip()

out = []
A = out.append

A("# ConnectUs Migration — Batch 09 Summary\n")
A(f"- **Branch number:** 09")
A(f"- **Git branch name (intended):** `jl-connectus-migration-09`")
A(f"- **Git branch name (actual at write time):** `{branch}` (the harness reassigned the working branch mid-session; CSV state is branch-independent)")
A(f"- **Assignee:** jlevypaloalto")
A(f"- **Date/time (UTC):** {utc}")
A(f"- **Total integrations in this branch:** {len(IDS)}")
A("")
A("> All workflow state below is read back authoritatively via `workflow_state.py context \"<id>\"` (not reconstructed from memory).")
A("")

# Per-integration table
A("## Per-integration status\n")
A("| Integration ID | Connector ID | Auth type(s) classified | Furthest workflow step (name + #/15) | Status | Notes |")
A("|---|---|---|---|---|---|")
for i in IDS:
    d = ctxs[i]
    step = f"{d['current_step']} (#{d['current_step_index']}/{d['total_steps']})"
    A(f"| {i} | {d['connector_id']} | {AUTH_SUMMARY[i]} | {step} | {status_icon(d)} | {NOTES[i]} |")
A("")
A("> **Reached step #8 `generated manifest` = 7/15 steps complete (data columns 2–7 done).** "
  "Steps 8–15 are blocked: the agent sandbox denies access to the sibling `../unified-connectors-content/` repo that "
  "`manifest_generator.py` (step 8) and `demisto-sdk validate` (step 10) require.")
A("")

# Workflow-data written
A("## Workflow-data written (read back via `context`)\n")
COLS = ["Auth Details","Params to Commands","Params for test with default in code","Params to Capabilities","Release Notes"]
for i in IDS:
    d = ctxs[i]
    A(f"### {i}\n")
    dc = d.get("data_columns", {})
    for c in COLS:
        v = dc.get(c)
        if v is None:
            A(f"**{c}:** _(not set)_\n")
        else:
            A(f"**{c}:**")
            A("```json")
            A(json.dumps(v, indent=2, ensure_ascii=False))
            A("```")
            A("")
    A("")

print("\n".join(out))
