import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any, Tuple


def health_check(health_dict, integration_name: str) -> Tuple[bool, bool]:
    for _, integration in health_dict.items():
        if integration.get('brand') == integration_name:
            return (False, True) if integration.get('lastError') else (True, True)
    return True, False


def health_check_command(args: Dict[str, Any]) -> CommandResults:

    integration_name = args.get('integration_name', '')

    raw_result = demisto.executeCommand(
        "demisto-api-post",
        {
            "uri": "/settings/integration/search",
            "body": {
                "size": 10,
                "query": "name:" + integration_name
            },
        })
    if is_error(raw_result):
        return_error(get_error(raw_result))

    health_dict = raw_result[0]["Contents"]["response"]["health"]

    is_healthy, fetch_done = health_check(health_dict, integration_name)

    return CommandResults(
        outputs_prefix='IntegrationHealth',
        outputs_key_field='integrationName',
        outputs={
            'isHealthy': is_healthy,
            'fetchDone': fetch_done,
            'integrationName': integration_name
        },
    )


def main():
    try:
        return_results(health_check_command(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute Script. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
