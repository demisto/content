import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    data = demisto.executeCommand("panorama",
                                  {"cmd": "<show><config><running><xpath>devices/entry[@name='localhost.localdomain']/plugins/cloud_services/multi-tenant/tenants</xpath></running></config></show>",
                                   'type': 'op'}
                                  )[0]['Contents']['response']['result']['tenants']['entry']

    data = [{
        'Tenant Name': t['@name'],
        'Mobile Users': t.get('users', 'N/A'),
        'Remote Network': t.get('bandwidth', 'N/A')
    } for t in data]
    demisto.results({'total': len(data), 'data': data})


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
