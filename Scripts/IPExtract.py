import re
import socket

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True

res = []
ips = []

data = demisto.args()['text']

for m in re.finditer(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', data, re.I):
    ip = m.group(0)
    if ip in ips:
        continue
    if not is_valid_ipv4_address(ip):
        continue
    ips.append(ip)

res.append('IPs found:\n' + '\n'.join(ips))
currIPs = demisto.get(demisto.context(), 'ips')
if currIPs and isinstance(currIPs, list):
    for i in ips:
        if i not in currIPs:
            currIPs.append(i)
else:
    currIPs = ips
demisto.setContext('ips', currIPs)
demisto.results(res)
