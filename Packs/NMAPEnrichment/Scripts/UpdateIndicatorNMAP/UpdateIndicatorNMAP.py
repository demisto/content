from datetime import datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
nmap_data = args.get('nmap_data', None)
update_count = 0

if nmap_data:
    now = datetime.utcnow()
    scan = nmap_data.get('Scan', {})
    hosts = list()
    if type(scan) == list:
        for scan_item in scan:
            hosts += scan_item.get('Hosts', [])
    else:
        hosts += scan.get('Hosts', [])

    for host in hosts:
        indicator = demisto.executeCommand("findIndicators", {"query": f"value:{host['Address']}"})[0]['Contents']
        if not indicator:
            if is_ip_valid(host['Address']):
                indicator_type = "IP"
            elif is_ipv6_valid(host['Address']):
                indicator_type = "IPv6"
            else:
                indicator_type = "Host"
            new_indicator = demisto.executeCommand("createNewIndicator", {"value": host['Address'], "type": indicator_type})
            indicator_id = new_indicator[0]['Contents']['id']
        else:
            indicator_id = indicator[0].get('id')
        for service in host['Services']:
            service.update({"date": now.strftime("%Y-%m-%dT%H:%M:%SZ")})
        nmap_table = [{k.lower(): v for k, v in x.items()} for x in host['Services']]
        demisto.executeCommand("setIndicator", {"id": indicator_id,
                                                "nmapports": nmap_table, "hostname": host.get('Hostname', None)})
        update_count += 1
    demisto.results(f"Updated {update_count} indicator(s)")
else:
    demisto.results("No NMAP data to use")
