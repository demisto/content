import demistomock as demisto
from CommonServerPython import *

import traceback
from typing import Any, Dict, Union


def set_arguments_for_widget_view(indicator_data: Dict[str, Any]) -> Union[Dict[str, str], str]:
    args = {}
    chronicleasset_hostname = indicator_data.get('CustomFields', {}).get('chronicleassethostname', '')
    if chronicleasset_hostname:
        args = {
            'asset_identifier': chronicleasset_hostname,
            'asset_identifier_type': 'Host Name',
            'preset_time_range': 'Last 30 days'
        }
    return args


def main() -> None:
    try:
        arguments = set_arguments_for_widget_view(demisto.args().get('indicator'))
        if not arguments:
            demisto.results('No Hostname associated with the ChronicleAsset.')
        else:
            demisto.results(demisto.executeCommand('gcb-list-events', arguments))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Could not load widget:\n{e}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
