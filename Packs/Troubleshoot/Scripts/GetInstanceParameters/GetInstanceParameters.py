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
    try:
        instance_config = list(filter(lambda item: item['name'] == name, configurations['instances']))[0]
    except IndexError as exc:
        raise DemistoException(f'Could not find the instance {name}') from exc
    brand = instance_config['brand']
    configuration = list(filter(lambda item: item['id'] == brand, configurations['configurations']))[0]

    return configuration, instance_config


def get_proxy_key(instance):
    proxy_key = None
    if 'proxy' in instance:
        proxy_key = 'proxy'
    for key in list(instance.keys()):  # Find proxy substring
        if 'proxy' in key:
            proxy_key = key
    return proxy_key


def get_proxy_key_value(instance) -> Tuple[Optional[str], Optional[bool]]:
    # Try to find any param named proxy
    if (proxy_key := get_proxy_key(instance)) is not None:
        return proxy_key, bool(instance[proxy_key])
    else:
        demisto.info('Could not find any key name proxy')
        return None, None


def get_insecure_key(instance: dict) -> Optional[str]:
    insecure_keys = ['insecure', 'unsecure']
    for key in insecure_keys:
        if key in instance:
            return key
    return None


def get_insecure_key_value(instance: dict) -> Tuple[Optional[str], Optional[bool]]:
    if (key := get_insecure_key(instance)) is not None:
        return key, bool(instance[key])
    else:
        demisto.info('Could not find any key name insecure')
        return None, None


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
    instance['proxy_key'], instance['proxy'] = get_proxy_key_value(instance)
    instance['insecure_key'], instance['insecure'] = get_insecure_key_value(instance)
    return instance


def main(instance_name: str):
    try:
        config, instance = get_conf(instance_name)
        parameters = build_parameters(config, instance)
        parameters['instance_name'] = instance_name
        human_readable = tableToMarkdown(f"Configured parameters for instance {instance_name}", parameters)
        parameters['RawInstance'] = instance
        return_outputs(
            human_readable,
            {
                'InstanceParameters(obj.instance_name === val.instance_name)': parameters
            },
            instance
        )
    except Exception as exc:
        return_error(exc)


if __name__ in ("__main__", "builtin", "builtins"):
    main(demisto.args().get('instance_name'))
