from CommonServerPython import *

import traceback
from typing import Dict, Union, Any


def set_arguments_for_widget_view(indicator_data: Dict[str, Any]) -> Union[Dict[str, str], str]:
    riskiq_asset_type = indicator_data.get('CustomFields', {}).get('riskiqassettype', '')
    if riskiq_asset_type:
        return {
            'name': indicator_data.get('value', ''),
            'type': riskiq_asset_type
        }
    else:
        return 'Please provide value in the "RiskIQAsset Type" field to fetch detailed information of the asset.'


def main() -> None:
    try:
        arguments = set_arguments_for_widget_view(demisto.args().get('indicator'))
        if isinstance(arguments, str):
            demisto.results(arguments)
        else:
            demisto.results(demisto.executeCommand('df-get-asset', arguments))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Could not load widget:\n{e}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
