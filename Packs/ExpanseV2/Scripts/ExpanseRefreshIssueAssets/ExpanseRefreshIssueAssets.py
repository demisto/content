import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import traceback
from typing import Dict, Any


''' COMMAND FUNCTION '''


def refresh_issue_assets_command(args: Dict[str, Any]) -> CommandResults:
    incident = demisto.incident()
    custom_fields = incident.get('CustomFields', {})
    assets = custom_fields.get('expanseasset', [])

    for asset in assets:
        asset_type = asset.get('assettype')
        asset_key = asset.get('assetkey')

        if asset_type == 'Domain':
            new_asset = demisto.executeCommand('expanse-get-domain', {"domain": asset_key})
        elif asset_type == 'IpRange':
            new_asset = demisto.executeCommand('expanse-get-iprange', {"id": asset_key, "include": "annotations"})
        elif asset_type == 'Certificate':
            new_asset = demisto.executeCommand('expanse-get-certificate', {"md5_hash": asset_key})
        else:
            # Unknown asset type, ignore.
            continue

        if isinstance(new_asset, list):
            for na in new_asset:
                if isinstance(na, dict) and 'Contents' in na:
                    contents = na.get('Contents')
                    break
        if not contents:
            continue

        if isinstance(contents, list):
            if len(contents) == 0:
                continue
            contents = contents[0]

        if not isinstance(contents, dict):
            continue

        if (annotations := contents.get('annotations', None)) and isinstance(annotations, dict):
            if (tags := annotations.get('tags', None)) and isinstance(tags, list) and len(tags) > 0:
                asset['tags'] = '\n'.join(t['name'] for t in tags if 'name' in t)

        if (ar := contents.get('attributionReasons', None)) and isinstance(ar, list) and len(ar) > 0:
            asset['attributionReasons'] = '\n'.join(a['reason'] for a in ar if 'reason' in a)

        asset['id'] = contents.get('id') or asset['id']

    demisto.executeCommand('setIncident', {
        "expanseasset": assets
    })

    return CommandResults(
        readable_output="OK"
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(refresh_issue_assets_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ExpanseRefreshIssueAsset. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
