#!/usr/bin/env python3
"""Audit: find params with a hidden: LIST that does NOT contain 'platform'
(per updated skill these must be carried through, not excluded).
Reports per-integration so we can see what my steps 4-7 wrongly dropped.
"""
import json
import subprocess
import sys

import yaml

ROOT = "/Users/yhayun/dev/demisto/content"

IDS = ["Akamai WAF","Akamai WAF SIEM","G Suite Security Alert Center","GCP-IAM",
"GSuiteAdmin","GSuiteAuditor","Gmail","Gmail Single User","Google Apigee",
"Google BigQuery","Google Cloud Compute","Google Cloud Functions",
"Google Cloud Storage","Google IP Ranges Feed","Google Key Management Service",
"Google Resource Manager","Google Safe Browsing v2","Google Vision AI",
"GoogleCalendar","GoogleCloudLogging","GoogleCloudTranslate","GoogleDocs",
"GoogleGemini","GoogleKubernetesEngine","GoogleMaps","GooglePubSub",
"GoogleSheets","google-vault","GuardiCore v2","Looker"]


def ws(*args):
    return subprocess.run(["python3", "connectus/workflow_state.py", *args],
                          cwd=ROOT, capture_output=True, text=True).stdout


def main():
    any_hit = False
    for iid in IDS:
        ctx = json.loads(ws("context", iid))
        yml = ctx["file_paths"]["yml"]
        d = yaml.safe_load(open(ROOT + "/" + yml))
        hits = []
        for c in d.get("configuration", []):
            h = c.get("hidden")
            # interested only in LIST hidden values that do NOT contain 'platform'
            if isinstance(h, list) and h and "platform" not in h:
                hits.append((c.get("name"), h, c.get("type"), c.get("required")))
        if hits:
            any_hit = True
            print("\n### %s" % iid)
            for n, h, t, r in hits:
                print("   %-26s hidden=%s type=%s required=%s" % (n, h, t, r))
    if not any_hit:
        print("No params with non-platform hidden lists found.")


if __name__ == "__main__":
    main()
