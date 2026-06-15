#!/usr/bin/env python3
import subprocess, csv, io, sys

target = sys.argv[1] if len(sys.argv) > 1 else "Akamai WAF"

def load(text):
    r = csv.reader(io.StringIO(text))
    header = next(r)
    rows = {row[0]: row for row in r if row}
    return header, rows

head_text = subprocess.run(["git","show","HEAD:connectus/connectus-migration-pipeline.csv"],capture_output=True,text=True).stdout
work_text = open("connectus/connectus-migration-pipeline.csv").read()
h, head = load(head_text)
_, work = load(work_text)

hr = head.get(target); wr = work.get(target)
if not hr or not wr:
    print("row missing"); sys.exit()

for idx, col in enumerate(h):
    a = hr[idx] if idx < len(hr) else ""
    b = wr[idx] if idx < len(wr) else ""
    if a != b:
        print("### COLUMN: %s" % col)
        print("  HEAD:    %s" % (a[:300] if a else "(empty)"))
        print("  WORKING: %s" % (b[:300] if b else "(empty)"))
        print()
