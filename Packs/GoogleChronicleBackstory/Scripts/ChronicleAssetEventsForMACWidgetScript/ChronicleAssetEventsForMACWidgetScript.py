import demistomock as demisto
from CommonServerPython import *

import traceback
from typing import Any, Dict, Union


def set_arguments_for_widget_view(indicator_data: Dict[str, Any]) -> Union[Dict[str, str], str]:
    args = {}
    chronicleasset_mac = indicator_data.get('CustomFields', {}).get('chronicleassetmac', '')
    if chronicleasset_mac:
        args = {
            'asset_identifier': chronicleasset_mac,
            'asset_identifier_type': 'MAC Address',
            'preset_time_range': 'Last 30 days'
        }
    return args


def main() -> None:
    try:
        arguments = set_arguments_for_widget_view(demisto.args().get('indicator'))
        if not arguments:
            demisto.results('No MAC Address associated with the ChronicleAsset.')
        else:
            demisto.results(demisto.executeCommand('gcb-list-events', arguments))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Could not load widget:\n{e}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
