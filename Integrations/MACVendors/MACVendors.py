import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
INTEGRATION_NAME = "MAC Vendors"

'''API Client'''


class Client(BaseClient):

    def __init__(self, url, verify: bool, proxy: bool):
        super().__init__(
            base_url=url,
            verify=verify,
            proxy=proxy,
            ok_codes=(200, 201, 204),
            headers={'accept': "application/json"}
        )

    def query(self, address):
        LOG(f"running request with url= {self._base_url}")
        suffix = address
        res = self._http_request(
            "GET",
            url_suffix=suffix,
            resp_type="text"
        )
        return res


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
    mac_address = args.get('macaddress')
    try:
        title = f"Results for MAC Address Query {INTEGRATION_NAME}"
        raws = []
        macvendors_ec = []

        raw_response = client.query(address=mac_address)

        if raw_response:
            raws.append(raw_response)
            macvendors_ec.append({
                'Vendor': raw_response
            })

        if not raws:
            return f'Could not find any results for given query {INTEGRATION_NAME}'

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

    try:
        client = Client(url, verify=params['verify'], proxy=params['proxy'])
        commands = {
            'MACAddress': get_mac_vendor,
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