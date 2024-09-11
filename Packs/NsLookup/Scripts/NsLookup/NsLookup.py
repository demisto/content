import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any
import traceback
import socket
import re


def nslookup(domain):
    domain = re.sub(r'^https?://', '', domain)
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return "Could not resolve domain"


def main():
    domain = demisto.args().get('domain')

    ip = nslookup(domain)

    data = {'ip': ip, 'domain': domain}

    command_results = CommandResults(outputs_prefix='NsLookup',
                                     raw_response=data,
                                     outputs=data,
                                     readable_output=f'{domain} resolves to {ip}' if ip != 'Could not resolve domain' else ip
                                     )

    return_results(command_results)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
