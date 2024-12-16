import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Any


def instance_check(instances, integration_name: str) -> list:
    instance_names = []
    for instance_name, details in instances.items():
        if details.get('brand') == integration_name:
            instance_names.append(instance_name)

    return instance_names


def get_instance_name_command(args: dict[str, Any]) -> CommandResults:
    integration_name = args.get('integration_name', '')

    instances = demisto.getModules()

    instance_names = instance_check(instances, integration_name)

    if not instance_names:
        raise DemistoException(f'No instance for integration {integration_name}.')

    if argToBoolean(args.get('return_all_instances', 'false')):
        return CommandResults(
            outputs_prefix='Instances',
            outputs_key_field='',
            outputs=[
                {
                    'integrationName': integration_name,
                    'instanceName': instance_name,
                } for instance_name in instance_names
            ],
        )

    return CommandResults(
        outputs_prefix='Instances',
        outputs_key_field='',
        outputs={
            'integrationName': integration_name,
            'instanceName': instance_names[0],
        },
    )


def main():
    try:
        return_results(get_instance_name_command(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute Script. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
