import socket

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

HOSTS = demisto.args().get("hostname")
ips = []
if isinstance(HOSTS, list):
    for host in HOSTS:
        try:
            ip = socket.gethostbyname(host)
            ips.append(ip)
        except Exception as e:
            return_results("host name cannot be resolved" + str(e))
else:
    try:
        ip = socket.gethostbyname(HOSTS)
        ips.append(ip)
    except Exception as e:
        return_results("hostname cannot be resolved" + str(e))


return_results(ips)
if not ips:
    demisto.setContext("resolveip", ips)
    return_results(ips)
