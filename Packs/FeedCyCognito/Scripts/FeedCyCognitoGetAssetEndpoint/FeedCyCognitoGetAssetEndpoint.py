import demistomock as demisto  # noqa: F401
from CommonServerPython import *

import traceback

''' MAIN FUNCTION '''


def main():
    try:
        asset_id = demisto.args().get("indicator", {}).get("CustomFields", {}).get("feedcycognitoassetid")

        asset_end_point = f"https://platform.cycognito.com/assets/{asset_id}/info"

        html = f"<p style=text-align:left;>For more information on the Asset, <a href={asset_end_point}><i>click here</i></a></p>"

        demisto.results({
            "ContentsFormat": formats["html"],
            "Type": entryTypes["note"],
            "Contents": html
        })
    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute FeedCyCognitoGetAssetEndpoint. Error: {str(err)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
