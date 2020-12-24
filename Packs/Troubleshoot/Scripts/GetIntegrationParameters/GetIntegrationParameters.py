from typing import Tuple

from CommonServerPython import *


def get_configurations_from_xsoar() -> dict:
    res = demisto.executeCommand('demisto-api-post', {
        'uri': 'settings/integration/search',
        'body': """{"size": 500}"""
    })
    if is_error(res):
        raise DemistoException(get_error(res))
    return res[0]['Contents']['response']


def get_conf(name: str) -> Tuple[dict, dict]:
    configurations = get_configurations_from_xsoar()
    instance_config = list(filter(lambda item: item['name'] == name, configurations['instances']))[0]
    brand = instance_config['brand']
    configuration = list(filter(lambda item: item['id'] == brand, configurations['configurations']))[0]

    return configuration, instance_config


def build_parameters(integration_config: dict, instance_config: dict) -> dict:
    """Gets configurations and building the parameters to context

    Args:
        integration_config: The integration's configuration
        instance_config: The instance's config

    Returns:
        A dictionary of parameters to check later.
    """
    if data := instance_config.get('data'):
        instance = {field['name']: field['value'] for field in data}
    else:
        instance = dict()
    instance['engine'] = instance_config['engine']
    try:
        del instance['credentials']
    except KeyError:
        pass
    integration_configuration = integration_config['integrationScript']
    integration_configuration['system'] = integration_config.get('system', True)
    integration_configuration['deprecated'] = integration_config.get('deprecated', False)
    # Remove heavy and/or sensitive information
    del integration_configuration['script']
    del integration_configuration['commands']
    instance.update(integration_configuration)
    if 'proxy' not in instance:  # Try to find any param named proxy
        for key in list(instance.keys()):
            if 'proxy' in key:
                instance['proxy'] = instance[key]
                break
        else:
            instance['proxy'] = None
            demisto.info('Could not find any key name proxy')

    if 'insecure' not in instance:  # Try to find any param named insecure
        instance['insecure'] = None
        demisto.info('Could not find any key name insecure')
    return instance


def main(instance_name: str):
    try:
        config, instance = get_conf(instance_name)
        parameters = build_parameters(config, instance)
        parameters['instance_name'] = instance_name
        human_readable = tableToMarkdown(f"Configured parameters for instance {instance_name}", parameters)
        return_outputs(
            human_readable,
            {'InstanceParameters(obj.instance_name === val.instance_name)': parameters},
            parameters
        )
    except Exception as exc:
        return_error(exc)


if __name__ in ("__main__", "builtin", "builtins"):
    main(demisto.args().get('instance_name'))
