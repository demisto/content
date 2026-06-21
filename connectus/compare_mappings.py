import csv

target_integrations = [
    "FireEyeETP", "FireEye ETP Event Collector",
    "FireEyeHX v2", "FireEye HX Event Collector",
    "Prisma Access", "Prisma Access Egress IP feed", "Palo Alto Networks - Prisma SASE",
    "Unit 42 Feed", "Unit 42 Intelligence",
]

# Load newmappings (IntegrationID -> Connector, TPE)
new_map = {}
with open('/Users/juschwartz/dev/content/connectus/newmappings.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        iid = (row.get('IntegrationID') or '').strip()
        if iid:
            new_map[iid] = {
                'Connector': (row.get('Connector') or '').strip(),
                'TPE': (row.get('TPE') or '').strip(),
            }

# Load pipeline (Integration ID -> Connector ID, path)
pipe_map = {}
with open('/Users/juschwartz/dev/content/connectus/connectus-migration-pipeline.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        iid = (row.get('Integration ID') or '').strip()
        if iid:
            pipe_map[iid] = {
                'ConnectorID': (row.get('Connector ID') or '').strip(),
                'Path': (row.get('Integration File Path') or '').strip(),
                'ConnectorPath': (row.get('Connector Folder Path') or '').strip(),
            }

print(f"{'Integration':<40} {'Pack':<35} {'newmappings TPE':<25} {'newmappings Connector':<40} {'pipeline ConnectorID':<30}")
print("-" * 175)

# Group by pack
from collections import defaultdict
by_pack = defaultdict(list)

for iid in target_integrations:
    n = new_map.get(iid, {})
    p = pipe_map.get(iid, {})
    path = p.get('Path', '')
    # Pack is second segment
    pack = path.split('/')[1] if path.startswith('Packs/') else '?'
    by_pack[pack].append({
        'iid': iid,
        'tpe': n.get('TPE', ''),
        'nc': n.get('Connector', ''),
        'pc': p.get('ConnectorID', ''),
        'path': path,
    })

for pack, items in by_pack.items():
    print(f"\n### Pack: {pack}")
    print(f"{'Integration':<42} {'newmappings Connector':<42} {'newmappings TPE':<28} {'pipeline ConnectorID':<32}")
    for it in items:
        print(f"  {it['iid'][:40]:<40} {it['nc'][:40]:<42} {it['tpe'][:26]:<28} {it['pc'][:30]:<32}")
        print(f"    path: {it['path']}")
