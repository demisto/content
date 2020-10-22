import json

import demistomock as demisto  # noqa: F401
import yaml
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()
assets = incident[0].get('CustomFields', {}).get('assetstable', {})

if assets:
    if not isinstance(assets, dict):
        assets = json.loads(assets)

    if not isinstance(assets, list):
        assets = [assets]

    for asset in assets:
        if "interfaces" in asset:
            if isinstance(asset["interfaces"], str):
                asset["interfaces"] = json.loads(asset["interfaces"])
            asset["interfaces"] = yaml.dump(yaml.load(json.dumps(asset["interfaces"])))

    markdown = tableToMarkdown("Assets Table", assets)
    demisto.results([{'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdown}])
else:
    demisto.results('')
