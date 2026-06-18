import json, sys, subprocess

ids = ["CIRCL", "CIRCL CVE Search", "CloudConvert", "Exabeam",
       "Exabeam Data Lake", "ExabeamSecOpsPlatform", "Core Lock",
       "Demisto Lock", "Unit 42 Intelligence",
       "Palo Alto Networks - Prisma SASE"]

PY = ".venv/bin/python"
for iid in ids:
    out = subprocess.run([PY, "connectus/workflow_state.py", "context", iid],
                         capture_output=True, text=True)
    try:
        d = json.loads(out.stdout)
    except Exception:
        print(f"{iid:42s} ERROR: {out.stdout[:80]} {out.stderr[:80]}")
        continue
    cid = d["connector_id"]
    si = d["current_step_index"]
    cs = d["current_step"]
    cf = d["connector_folder_path"]
    pcap = d["data_columns"].get("Params to Capabilities")
    auth = d["data_columns"].get("Auth Details")
    print(f"{iid:42s} conn={cid!r:30s} step#{si} {cs!r} cf={cf!r} pcap_set={pcap is not None} auth_set={auth is not None}")
