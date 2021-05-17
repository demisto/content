import json

import demistomock as demisto  # noqa: F401
import yaml
from CommonServerPython import *  # noqa: F401


def main():
    try:
        incident = demisto.incident()
        assets = incident.get('CustomFields', {}).get('assettable', {})

        if not assets:
            return ''

        if not isinstance(assets, dict):
            assets = json.loads(assets)

        if not isinstance(assets, list):
            assets = [assets]

        for asset in assets:
            if "interfaces" in asset:
                if isinstance(asset["interfaces"], str):
                    asset["interfaces"] = json.loads(asset["interfaces"])
                # using yaml to prettify the output of the field
                asset["interfaces"] = yaml.dump(asset["interfaces"])

        markdown = tableToMarkdown("Asset Table", assets)
        return {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdown}

    except Exception as exp:
        return_error('could not parse QRadar assets', error=exp)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(main())
