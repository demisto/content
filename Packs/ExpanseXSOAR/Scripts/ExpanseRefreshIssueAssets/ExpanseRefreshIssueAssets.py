import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from typing import Dict, Any


''' COMMAND FUNCTION '''


def refresh_issue_assets_command(args: Dict[str, Any]) -> CommandResults:
    incident = demisto.incident()
    custom_fields = incident.get('CustomFields')
    assets = custom_fields.get('expanseasset')

    for asset in assets:
        asset_type = asset.get('assettype')
        asset_key = asset.get('assetkey')

        if asset_type == 'Domain':
            new_asset = demisto.executeCommand('expanse-get-domain', {"domain": asset_key})
        elif asset_type == 'IpRange':
            new_asset = demisto.executeCommand('expanse-get-iprange', {"id": asset_key})
        elif asset_type == 'Certificate':
            new_asset = demisto.executeCommand('expanse-get-certificate', {"pem_md5_hash": asset_key})
        else:
            # ???
            continue

        if isinstance(new_asset, list):
            if len(new_asset) == 0:
                continue
            new_asset = new_asset[0]

        contents = new_asset.get('Contents')

        if (annotations := contents.get('annotations', None)) and isinstance(annotations, dict):
            if (tags := annotations.get('tags', None)) and isinstance(tags, list) and len(tags) > 0:
                asset['tags'] = '\n'.join(t['name'] for t in tags if 'name' in t)

        if (ar := contents.get('attributionReasons', None)) and isinstance(ar, list) and len(ar) > 0:
            asset['attributionReasons'] = '\n'.join(a['reason'] for a in ar if 'reason' in a)

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
