import json
import urllib.parse

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

entryList = []
deviceList = []
deviceEntry = {}

args = demisto.args()

if 'hostname' in args:
    device = args['hostname']
else:
    device = None

if 'ipaddress' in args:
    ip = args['ipaddress']
else:
    ip = None

if 'package' in args:
    package = args['package']
else:
    package = None

SEARCH_DEVICE_USING_IP = "(select (*) (from device (where device ( eq ip_addresses (ip_address '{0}')))))".format(ip)
SEARCH_DEVICE_USING_DEVICE = "(select (*) (from device (where device ( eq name (string {0})))))".format(device)
SEARCH_COMPLIANCE_PACKAGE_DEVICE = """(select ((device (*)) (package (*))) (from (device package)
(with package (where package (eq name (pattern '*{0}*')))
(where device (eq name (pattern '{1}')))))
(limit 100))""".format(package, device)
TEST_MODULE = "(select (name) (from device ) (limit 1))"


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

    BASE_URL = 'https://{0}:{1}/2/query?platform=windows&format=json&query='.format(base_url, port)
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
    if not device:
        data = nexthink_request('GET', SEARCH_DEVICE_USING_IP)
    else:
        data = nexthink_request('GET', SEARCH_DEVICE_USING_DEVICE)
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
        return 'Endpoint Not Found'


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
        return 'Package Not Found'


def nexthink_compliance_check(device: None, ip: None):
    if not device:
        data = nexthink_request('GET', SEARCH_DEVICE_USING_IP)
    else:
        data = nexthink_request('GET', SEARCH_DEVICE_USING_DEVICE)

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
        return 'Endpoint Not Found'


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
