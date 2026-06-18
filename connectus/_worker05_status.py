import json
import subprocess
import sys

PY = ".venv/bin/python"
WS = "connectus/workflow_state.py"

IDS = [
    "BitSight Event Collector",
    "CapeSandbox",
    "Netmiko",
    "FireEye Central Management",
    "FireEyeHelix",
    "McAfeeNSMv2",
    "fireeye",
    "VMware",
    "VMware Carbon Black EDR v2",
    "VMware Workspace ONE UEM (AirWatch MDM)",
]


def has(dc, k):
    return "Y" if dc.get(k) else "-"


for ID in IDS:
    out = subprocess.run(
        [PY, WS, "context", ID], capture_output=True, text=True
    ).stdout
    try:
        d = json.loads(out)
    except Exception:
        print(f"{ID:44} | CONTEXT PARSE ERROR")
        continue
    dc = d.get("data_columns", {})
    name = d["integration_id"]
    line = (
        f"{name:44} | step#{d.get('current_step_index'):>2} "
        f"{(d.get('current_step') or '')[:30]:32} | "
        f"done {d.get('completed_steps')}/{d.get('total_steps')} | "
        f"auth={has(dc,'Auth Details')} "
        f"p2cmd={has(dc,'Params to Commands')} "
        f"p2cap={has(dc,'Params to Capabilities')} | "
        f"conn={d.get('connector_id')}"
    )
    print(line)
