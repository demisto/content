import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback


def health_check(health_dict, integration_name: str) -> bool:
    for _, integration in health_dict.items():
        if integration.get('brand') == integration_name:
            return False if integration.get('lastError') else True
    return False


def health_check_command(args: Dict[str, Any]) -> CommandResults:

    integration_name = args.get('integration_name', '')
    if not integration_name:
        raise ValueError('integration_name not specified')

    raw_result = demisto.executeCommand(
        "demisto-api-post",
        {
            "uri": "/settings/integration/search",
            "body": {
                "size": 10,
                "query": "name:" + integration_name
            },
        })
    health_dict = raw_result[0]["Contents"]["response"]["health"]

    is_health = health_check(health_dict, integration_name)

    return CommandResults(
        outputs_prefix='IntegrationHealth',
        outputs_key_field='',
        outputs={
            'isHealth': is_health,
            'healthDict': health_dict
        },
    )


def main():
    try:
        return_results(health_check_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute Script. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
