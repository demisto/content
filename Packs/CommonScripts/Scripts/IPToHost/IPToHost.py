import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import socket


def ip_to_host(ip: str) -> CommandResults:
    host_info = socket.gethostbyaddr(ip)

    if not host_info:
        raise DemistoException('No results were found for the given value.')

    hostname = host_info[0]

    if str(hostname) == ip:
        return CommandResults(readable_output=f"The IP address {ip} has no associated hostname.")

    output = {
        'Hostname': str(hostname),
        'IP': ip
    }

    md = tableToMarkdown('IP to Host', [output])

    return CommandResults(
        outputs=output,
        outputs_prefix='Endpoint',
        outputs_key_field='Hostname',
        readable_output=md,
    )


def main():
    try:
        ip = demisto.args().get('ip')
        return_results(ip_to_host(ip))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Couldn\'t get the IP host info. Error information: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
