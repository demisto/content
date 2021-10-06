import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Dict, Any, Tuple
import traceback


def instance_check(instances, integration_name: str) -> Tuple[bool, Any]:
    for instance_name, details in instances.items():
        if details.get('brand') == integration_name:
            return True, instance_name
    return False, None


def get_instance_name_command(args: Dict[str, Any]) -> CommandResults:
    integration_name = args.get('integration_name', '')

    instances = demisto.getModules()

    found, instance_name = instance_check(instances, integration_name)

    if not found:
        raise DemistoException(f'No instance for integration {integration_name}.')

    return CommandResults(
        outputs_prefix='Instances',
        outputs_key_field='',
        outputs={
            'integrationName': integration_name,
            'instanceName': instance_name
        },
    )


def main():
    try:
        return_results(get_instance_name_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute Script. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
