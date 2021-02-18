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
                                               server=f'https://localhost:{build.servers[0].ssh_tunnel_port}')
        result = function(build, *args, **kwargs)
        build.proxy.configure_proxy_in_demisto(proxy='',
                                               username=build.username, password=build.password,
                                               server=f'https://localhost:{build.servers[0].ssh_tunnel_port}')
        return result

    return decorated
