from CommonServerPython import *

import traceback
from typing import Dict, Union, Any


def set_arguments_for_widget_view(indicator_data: Dict[str, Any]) -> Union[Dict[str, str], str]:
    """
        Prepare argument for commands or message to set custom layout of indicator
    """
    indicator_type = indicator_data.get('indicator_type', '').lower()
    if indicator_type == 'riskiqasset':
        riskiq_asset_type = indicator_data.get('CustomFields', {}).get('riskiqassettype', '')
        if riskiq_asset_type == '':
            return 'Please provide value in the "RiskIQAsset Type" field to fetch detailed information of the asset.'
        if riskiq_asset_type == 'Domain':
            return {
                'field': 'domain',
                'query': indicator_data.get('value', '')
            }
        elif riskiq_asset_type == 'Contact':
            return {
                'field': 'email',
                'query': indicator_data.get('value', '')
            }
        else:
            return 'No domain information were found for the given argument(s).'
    return {
        'field': indicator_type,
        'query': indicator_data.get('value', '')
    }


def main() -> None:
    try:
        arguments = set_arguments_for_widget_view(demisto.args().get('indicator'))
        if isinstance(arguments, str):
            demisto.results(arguments)
        else:
            demisto.results(demisto.executeCommand('pt-whois-search', arguments))
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Could not load widget:\n{e}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
