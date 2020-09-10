import json
from Tests.Marketplace.upload_packs_private import print_packs_summary

with open('pack_list.json', 'w') as f:
    pack_list_json = json.load(f)

print_packs_summary(pack_list_json)
