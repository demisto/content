import json
from functools import wraps
from typing import Callable

from demisto_sdk.commands.test_content.mock_server import MITMProxy


def run_with_proxy_configured(function: Callable) -> Callable:
    """
    This is a decorator for the 'instance_testing method`.
    This decorator configures the proxy in the server before the instance_testing execution and removes it afterwards.
    Args:
        function: Should be the instance_testing method.
    """

    @wraps(function)
    def decorated(build, *args, **kwargs):
        build.proxy.configure_proxy_in_demisto(proxy=build.servers[0].internal_ip + ':' + MITMProxy.PROXY_PORT,
                                               username=build.username, password=build.password,
                                               server=f'https://{build.servers[0].internal_ip}')
        result = function(build, *args, **kwargs)
        build.proxy.configure_proxy_in_demisto(proxy='',
                                               username=build.username, password=build.password,
                                               server=f'https://{build.servers[0].internal_ip}')
        return result

    return decorated


def get_integration_params(integration_secrets_path: str, instance_name: str):
    with open(integration_secrets_path) as file:
        try:
            integrations_instance_data = json.load(file).get("integrations") or []
        except ValueError as e:
            raise ValueError(f'Could not load {integration_secrets_path}, error: {e}')

    if not integrations_instance_data:
        raise RuntimeError(f'{integration_secrets_path} is empty')

    for integration_instance in integrations_instance_data:
        if integration_instance.get("instance_name") == instance_name or integration_instance.get("name") == instance_name:
            return integration_instance.get("params")

    raise ValueError(f'Could not find integration parameters for {instance_name}')
