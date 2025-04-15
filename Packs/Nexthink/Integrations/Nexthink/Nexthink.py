import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
import json
import urllib.parse

import requests
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

entryList = []
deviceList = []
deviceEntry = {}

args = demisto.args()

device = args.get('hostname', None)

ip = args.get('ipaddress', None)

package = args.get('package', None)

SEARCH_DEVICE_USING_IP = f"(select (*) (from device (where device ( eq ip_addresses (ip_address '{ip}')))))"
SEARCH_DEVICE_USING_DEVICE = f"(select (*) (from device (where device ( eq name (string {device})))))"
SEARCH_COMPLIANCE_PACKAGE_DEVICE = """(select ((device (*)) (package (*))) (from (device package)
(with package (where package (eq name (pattern '*{}*')))
(where device (eq name (pattern '{}')))))
(limit 100))""".format(package, device)
TEST_MODULE = "(select (name) (from device ) (limit 1))"


def is_valid_hostname(hostname):
    if len(hostname) > 15:
        return False
    allowed = re.compile("(?!-)[A-Z\d-]{1,15}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname)


def nexthink_request(method, nxql):
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    base_url = params.get('url')
    port = params.get('port')
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    if proxy:
        proxies = handle_proxy()
    else:
        proxies = {
            "http": None,
            "https": None,
        }

    BASE_URL = f'https://{base_url}:{port}/2/query?platform=windows&format=json&query='
    NXQL = urllib.parse.quote(nxql)
    urlFragment = BASE_URL + NXQL

    try:
        if method == 'POST':
            response = requests.post(urlFragment, auth=(username, password), verify=verify_ssl, proxies=proxies)
        else:
            response = requests.get(urlFragment, auth=(username, password), verify=verify_ssl, proxies=proxies)

        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return str(response.status_code)
    except requests.Timeout:
        raise
    except requests.ConnectionError:
        raise


def nexthink_endpoint_details(device: None, ip: None):
    if not ip and not device:
        return_results('Please provide hostname or ipaddress argument')
        sys.exit(0)
    elif not device:
        if re.match(ipv4Regex, ip):
            data = nexthink_request('GET', SEARCH_DEVICE_USING_IP)
        else:
            return_results('Please enter valid ip address. (e.g. 192.168.1.100)')
            sys.exit(0)
    else:
        if is_valid_hostname(device):
            data = nexthink_request('GET', SEARCH_DEVICE_USING_DEVICE)
        else:
            return_results('Please enter valid hostname. (e.g. AMCE1234)')
            sys.exit(0)

    if len(data) > 0:
        deviceEntry['EndpointName'] = data[0]['name']
        deviceEntry['LastLoggedOnUser'] = data[0]['last_logged_on_user']
        deviceEntry['IPAddress'] = data[0]['ip_addresses'][0]
        deviceEntry['MACAddress'] = data[0]['mac_addresses'][0]
        deviceList.append(deviceEntry)

        dArgs = CommandResults(
            outputs_prefix="Nexthink.Endpoint",
            outputs_key_field="IPAddress",
            outputs=deviceList,
            readable_output=tableToMarkdown('Nexthink Endpoint Details: ', deviceList),
            raw_response=deviceList
        )

        return dArgs
    else:
        if not device:
            return f'No endpoint found with ip "{ip}"'
        else:
            return f'No endpoint found with hostname "{device}"'


def nexthink_installed_packages(device: None, package: None):
    data = nexthink_request('GET', SEARCH_COMPLIANCE_PACKAGE_DEVICE)

    if len(data) > 0:
        for t in data:
            entries = {}
            entries['PackageName'] = t['package/name']
            entries['PackagePublisher'] = t['package/publisher']
            entries['PackageVersion'] = t['package/version']
            entryList.append(entries)

        deviceEntry['DeviceName'] = data[0]['device/name']
        deviceEntry['LastLogged On User'] = data[0]['device/last_logged_on_user']
        deviceEntry['IPAddress'] = data[0]['device/ip_addresses'][0]
        deviceEntry['MACAddress'] = data[0]['device/mac_addresses'][0]
        deviceList.append(deviceEntry)
        hr = tableToMarkdown('Installed Packages: ', deviceList) + tableToMarkdown('Packages Details: ', entryList)

        dArgs = CommandResults(
            outputs_prefix="Nexthink.Package",
            outputs_key_field="IPAddress",
            outputs=deviceList,
            readable_output=hr,
            raw_response=deviceList
        )

        return dArgs
    else:
        return f'No package "{package}" found on endpoint {device}'


def nexthink_compliance_check(device: None, ip: None):
    data = ""
    if not device and not ip:
        return_results('Please provide hostname or ipaddress argument')
        sys.exit(0)
    elif not device:
        if re.match(ipv4Regex, ip):
            data = nexthink_request('GET', SEARCH_DEVICE_USING_IP)
        else:
            return_results('Please enter valid ip address. (e.g. 192.168.1.100)')
            sys.exit(0)
    else:
        if is_valid_hostname(device):
            data = nexthink_request('GET', SEARCH_DEVICE_USING_DEVICE)
        else:
            return_results('Please enter valid endpoint hostname. (e.g. AMCE1234)')

    if len(data) > 0:
        for t in data:
            entries = {}
            entries['DeviceAntivirus'] = t['antivirus_name']
            entries['DeviceAntivirus RTP'] = t['antivirus_rtp']
            entries['DeviceAntivirus Updated'] = t['antivirus_up_to_date']
            entries['DeviceAntispyware'] = t['antispyware_name']
            entries['DeviceAntispyware RTP'] = t['antispyware_rtp']
            entries['DeviceAntispyware Updated'] = t['antispyware_up_to_date']
            entryList.append(entries)

        deviceEntry['DeviceName'] = data[0]['name']
        deviceEntry['LastLoggedOnUser'] = data[0]['last_logged_on_user']
        deviceEntry['IPAddress'] = data[0]['ip_addresses'][0]
        deviceEntry['MACAddress'] = data[0]['mac_addresses'][0]
        deviceList.append(deviceEntry)

        hr = tableToMarkdown('Endpoint Details :', deviceList) + tableToMarkdown('Compliance Details: ', entryList)
        dArgs = CommandResults(
            outputs_prefix="Nexthink.Compliance",
            outputs_key_field="IPAddress",
            outputs=deviceList,
            readable_output=hr,
            raw_response=deviceList
        )

        return dArgs
    else:
        if not device:
            return f'No endpoint found with ip "{ip}"'
        else:
            return f'No endpoint found with hostname "{device}"'


def main():
    if demisto.command() == 'test-module':
        data = nexthink_request('GET', TEST_MODULE)
        if data:
            return_results("ok")
        else:
            return_results(data)
    elif demisto.command() == 'nt-endpoint-details':
        data = nexthink_endpoint_details(device, ip)
        return_results(data)
    elif demisto.command() == 'nt-compliance-check':
        data = nexthink_compliance_check(device, ip)
        return_results(data)
    elif demisto.command() == 'nt-installed-packages':
        data = nexthink_installed_packages(device, package)
        return_results(data)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
