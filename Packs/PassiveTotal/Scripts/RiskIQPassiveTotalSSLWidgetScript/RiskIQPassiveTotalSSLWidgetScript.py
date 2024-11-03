from CommonServerPython import *

import traceback
from typing import Any


def set_arguments_for_widget_view(indicator_data: dict[str, Any]) -> dict[str, str]:
    """
        Prepare argument for commands or message to set custom layout of indicator
    """
    indicator_type = indicator_data.get('indicator_type', '').lower()
    arguments: dict[str, str] = {}
    if indicator_type == 'file sha-1':
        arguments = {
            'field': 'sha1',
            'query': indicator_data.get('value', '')
        }
    elif indicator_type == 'riskiqserialnumber':
        arguments = {
            'field': 'serialNumber',
            'query': indicator_data.get('value', '')
        }
    return arguments


def main() -> None:
    try:
        arguments = set_arguments_for_widget_view(demisto.args().get('indicator'))
        demisto.results(demisto.executeCommand('pt-ssl-cert-search', arguments))
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Could not load widget:\n{e}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
