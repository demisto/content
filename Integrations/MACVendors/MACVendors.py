import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
INTEGRATION_NAME = "MAC Vendors"

'''API Client'''


class Client:

    def __init__(self, url, proxies):
        self.base_url = url
        self.proxies = proxies

    def query(self, address=None):
        LOG('running request with url=%s' % self.base_url)
        full_url = self.base_url + '/api/' + address
        res = requests.request(
            "GET",
            full_url,
            headers={'accept': "application/json"}
        )
        if res.status_code not in [200, 204]:
            raise ValueError("Error in API call to Service API %s. Reason: %s " % (res.status_code, res.text))
        try:
            return res.json()
        except Exception:
            raise ValueError("Failed to parse http response to JSON format. Original response body: \n %s" % res.text)


'''' Commands '''


def test_module(client):
    try:
        mac_address = '00:00:00'
        client.query(address=mac_address)
    except Exception as e:
        LOG(e)
        return_error(e)
    return 'ok'


def get_mac_vendor(client):
    args = demisto.args()
    mac_address = args.get('address')
    try:
        title = ("%s - Results for MAC Address Query" % INTEGRATION_NAME)
        raws = []
        macvendors_ec = []

        raw_response = client.query(address=mac_address)

        if raw_response:
            raws.append(raw_response)
            macvendors_ec.append({
                'Mac': mac_address,
                'Vendor': raw_response['result'].get('company'),
                'Type': raw_response['result'].get('type'),
                'Address': raw_response['result'].get('address')
            })

        if not raws:
            return ("%s - Could not find any results for given query" % INTEGRATION_NAME)

        context_entry = {
            "MACVendors": macvendors_ec
        }

        human_readable = tableToMarkdown(t=context_entry.get("MACVendors"), name=title)

        return [human_readable, context_entry, raws]

    except Exception as e:
        LOG(e)
        return_error(e)


def main():
    params = demisto.params()

    # Remove trailing slash to prevent wrong URL path to service
    url = params['url'][:-1] if (params['url'] and params['url'].endswith('/')) else params['url']
    # Remove proxy if not set to true in params
    proxies = handle_proxy()

    try:
        client = Client(url, proxies)
        commands = {
            'mac': get_mac_vendor,
            'test-module': test_module
        }

        command = demisto.command()
        LOG('Command being called is %s' % command)

        if command in commands:
            if command == 'test-module':
                return_outputs(test_module(client))

            else:
                outputs = commands[command](client)
                return_outputs(outputs[0], outputs[1], outputs[2])
        else:
            return_error("Command Not Found")

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()