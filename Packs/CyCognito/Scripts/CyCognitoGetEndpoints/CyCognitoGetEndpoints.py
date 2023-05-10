import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' MAIN FUNCTION '''


def main():

    try:
        issue_id = demisto.incident().get('CustomFields', {}).get('cycognitoissueid')
        asset_id = demisto.incident().get('CustomFields', {}).get('cycognitoaffectedasset')

        issue_id = issue_id.replace('issue/', '')

        issue_end_point = f"https://platform.cycognito.com/issues/issue/{issue_id}/info"
        asset_end_point = f"https://platform.cycognito.com/assets/{asset_id}/info"

        html = "<p style=text-align:left;>For more information on the Issue, " \
               f"<a href={issue_end_point}><i>click here</i></a></p>" \
               "<p style=text-align:left;>For more information on the Affected Asset, " \
               f"<a href={asset_end_point}><i>click here</i></a></p>"

        demisto.results({
            'ContentsFormat': formats['html'],
            'Type': entryTypes['note'],
            'Contents': html
        })

    except Exception as e:
        return_error(f'Could not find Deeplink:\n{e}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
