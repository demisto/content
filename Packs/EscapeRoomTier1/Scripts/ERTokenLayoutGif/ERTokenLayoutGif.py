import traceback

import demistomock as demisto
from CommonServerPython import *


def set_indicator_hint(indicator_id):
    execute_command('setIndicator', {
        'id': indicator_id,
        'customFields': {
            'userpswdhint': ' ',
        },
    })

# MAIN FUNCTION #


def main():
    args = demisto.args()
    try:
        indicator_id = dict_safe_get(args, ['indicator', 'id'])
        set_indicator_hint(indicator_id)
        return_results(
            CommandResults(readable_output='![](https://raw.githubusercontent.com/demisto/content/'
                                           'EscapeRoomMaterials/Packs/EscapeRoomTier1/images/indicator_Jafar.gif)')
        )
    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ERTokenLayoutGif. Error: {str(exc)}')


# ENTRY POINT #

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
