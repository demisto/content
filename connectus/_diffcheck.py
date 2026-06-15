#!/usr/bin/env python3
import subprocess, csv, io

ids = ["Akamai WAF","Akamai WAF SIEM","G Suite Security Alert Center","GCP-IAM","GSuiteAdmin","GSuiteAuditor","Gmail","Gmail Single User","Google Apigee","Google BigQuery","Google Cloud Compute","Google Cloud Functions","Google Cloud Storage","Google IP Ranges Feed","Google Key Management Service","Google Resource Manager","Google Safe Browsing v2","Google Vision AI","GoogleCalendar","GoogleCloudLogging","GoogleCloudTranslate","GoogleDocs","GoogleGemini","GoogleKubernetesEngine","GoogleMaps","GooglePubSub","GoogleSheets","google-vault","GuardiCore v2","Looker"]
idset = set(ids)

def load(text):
    r = csv.reader(io.StringIO(text))
    header = next(r)
    rows = {}
    for row in r:
        if row and row[0] in idset:
            rows[row[0]] = row
    return header, rows

head_text = subprocess.run(["git","show","HEAD:connectus/connectus-migration-pipeline.csv"],capture_output=True,text=True).stdout
work_text = open("connectus/connectus-migration-pipeline.csv").read()

h_head, head = load(head_text)
h_work, work = load(work_text)

print("HEADER identical:", h_head == h_work)
if h_head != h_work:
    print("  HEAD cols:", len(h_head), h_head)
    print("  WORK cols:", len(h_work), h_work)

diff_ids = []
for i in ids:
    if i not in head:
        diff_ids.append((i, "MISSING_IN_HEAD")); continue
    if i not in work:
        diff_ids.append((i, "MISSING_IN_WORK")); continue
    if head[i] != work[i]:
        cols = []
        for idx, (a, b) in enumerate(zip(head[i], work[i])):
            if a != b:
                cn = h_work[idx] if idx < len(h_work) else "col%d" % idx
                cols.append(cn)
        diff_ids.append((i, ",".join(cols) or "len-diff"))

print("\n%d of %d rows differ between WORKING and HEAD:\n" % (len(diff_ids), len(ids)))
for i, cols in diff_ids:
    print("  %s :: %s" % (i, cols))
