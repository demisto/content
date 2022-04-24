import socket

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

def ip_to_host(ip):
    try:
        host_info = socket.gethostbyaddr(ip)
    except Exception as e:
        return_error("Couln't get the ip host info. Error information: \"{0}\"".format(str(e)))

    if not host_info:
        return_error("Received an error while trying to get the host information")

    hostname = host_info[0]

    output = {
        "Hostname": str(hostname),
        "IP": ip
    }

    md = tableToMarkdown("IP to Host", [output])

    return CommandResults(
        outputs=output,
        outputs_prefix='Endpoint',
        outputs_key_field='Hostname',
        readable_output=md,
    )

def main():
    ip = demisto.args().get('ip')
    return_results(ip_to_host(ip))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()