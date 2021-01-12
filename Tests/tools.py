from functools import wraps
from typing import Callable


def run_with_proxy_configured(function: Callable) -> Callable:
    """
    This is a decorator for the 'instance_testing method`.
    This decorator configures the proxy in the server before the instance_testing execution and removes it afterwards.
    Args:
        function: Should be the instance_testing method.
    """

    @wraps(function)
    def decorated(build, *args, **kwargs):
        build.proxy.configure_proxy_in_demisto(proxy=build.proxy.ami.docker_ip + ':' + build.proxy.PROXY_PORT,
                                               username=build.username, password=build.password,
                                               server=build.servers[0].host)
        result = function(build, *args, **kwargs)
        build.proxy.configure_proxy_in_demisto(proxy='',
                                               username=build.username, password=build.password,
                                               server=build.servers[0].host)
        return result

    return decorated
