import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' MAIN FUNCTION '''


def main():

    try:
        issue_id = demisto.executeCommand("Print", {"value": "${incident.cycognitoissueid}"})[0]["Contents"]
        asset_id = demisto.executeCommand("Print", {"value": "${incident.cycognitoaffectedasset}"})[0]["Contents"]

        issue_id = issue_id.replace('issue/', '')

        issue_end_point = f"https://platform.cycognito.com/issues/issue/{issue_id}/info"
        asset_end_point = f"https://platform.cycognito.com/assets/{asset_id}/info"

        html = f"<p style=text-align:left;>For more information on the Issue, <a href={issue_end_point}><i>click here</i></a></p>" \
            f"<p style=text-align:left;>For more information on the Affected Asset, <a href={asset_end_point}><i>click here</i></a></p>"

        demisto.results({
            'ContentsFormat': formats['html'],
            'Type': entryTypes['note'],
            'Contents': html
        })

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Could not find Deeplink:\n{e}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
