from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


INTEGRATION_NAME = 'Nozomi Guardian'


'''API Client'''


class Client(BaseClient):

    def query(self, search_query):
        query = search_query
        LOG(f'running request with url= {self._base_url}')

        res = self._http_request(
            "GET",
            url_suffix='/api/open/query/do?query=' + query,
            resp_type="json"
        )
        return res


'''' Commands '''


def test_module(client):
    client.query('help')
    return 'ok'


def search_by_query(client, args):
    search_query = args.get('query')
    title = f'{INTEGRATION_NAME} - Results for the Search Query'
    raws = []
    nozomi_ec = []
    raw_response = client.query(search_query)['result']

    if raw_response:
        raws.append(raw_response)
        nozomi_ec.append(raws)

    if not raws:
        return_error(f'{INTEGRATION_NAME} - Could not find any results for given query')

    context_entry = {
        "NozomiGuardian": {"Queries": nozomi_ec}
    }

    human_readable = tableToMarkdown(t=context_entry['NozomiGuardian']['Queries'], name=title, headers='Query Results')
    return [human_readable, context_entry, raws]


def list_all_assets(client):
    search_query = "assets"
    title = f'{INTEGRATION_NAME} - Results for the Search Query'
    raws = []
    nozomi_ec = []
    raw_response = client.query(search_query)['result']

    if raw_response:
        for item in raw_response:
            raws.append(item)
            nozomi_ec.append({
                'Name': item['name'],
                'IP': item['ip'],
                'MAC': item['mac_address'],
                'Vendor': item['vendor'],
                'OS': item['os'],
                'CaptureDevice': item['capture_device']
            })

    if not raws:
        return f'{INTEGRATION_NAME} - Could not any nodes'

    context_entry = {
        "NozomiGuardian": {"Assets": nozomi_ec}
    }

    human_readable = tableToMarkdown(t=context_entry["NozomiGuardian"]['Assets'], name=title)
    return [human_readable, context_entry, raws]


def find_ip_by_mac(client, args):
    mac_address = args.get('mac')
    search_query = "assets | where mac_address match " + mac_address
    title = f'{INTEGRATION_NAME} - Results for the Search Query'
    raws = []
    nozomi_ec = []
    raw_response = client.query(search_query)['result']

    if raw_response:
        for item in raw_response:
            if 'ip' in item and item['ip'][0] is not None and len(item['ip'][0].split('.')) == 4:
                raws.append(item)
                nozomi_ec.append({
                    'IP': item['ip'],
                    'MAC': mac_address
                })

        if not raws:
            return f'{INTEGRATION_NAME} - Could not find any results for given query'

        context_entry = {
            "NozomiGuardian": {"Mappings": nozomi_ec}
        }

        human_readable = tableToMarkdown(t=context_entry['NozomiGuardian']['Mappings'], name=title)
        return [human_readable, context_entry, raws]

    return f'Could not find the mac address:{mac_address}'


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('credentials', {}).get('identifier', '')
    password = params.get('credentials', {}).get('password', '')
    base_url = params['url'][:-1] if (params['url'] and params['url'].endswith('/')) else params['url']
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy,
            ok_codes=(200, 201, 204),
            headers={'accept': "application/json"}
        )

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_outputs(result)

        elif demisto.command() == 'guardian-search':
            result = search_by_query(client, demisto.args())
            return_outputs(*result)

        elif demisto.command() == 'guardian-list-all-assets':
            result = list_all_assets(client)
            return_outputs(*result)

        elif demisto.command() == 'guardian-find-ip-by-mac':
            result = find_ip_by_mac(client, demisto.args())
            return_outputs(*result)

    except Exception as e:
        return_error(str(f'Failed to execute {demisto.command()} command. Error: {str(e)}'))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
