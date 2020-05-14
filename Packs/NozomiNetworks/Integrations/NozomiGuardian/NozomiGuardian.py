import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from base64 import b64encode
import urllib.parse
import urllib3


INTEGRATION_NAME = "Nozomi Guardian"

'''API Client'''


class Client:

    def __init__(self, url, proxies, username, password):
        self.base_url = url
        self.proxies = proxies
        self.username = username
        self.password = password

    def query(self, search_query):
        query = search_query
        LOG('running request with url=%s' % self.base_url)
        full_url = self.base_url + '/api/open/query/do?query=' + urllib.parse.quote(query.encode('utf8'))
        auth = (self.username + ':' + self.password).encode('utf-8')
        basic_auth = 'Basic ' + b64encode(auth).decode()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        res = requests.request(
            "GET",
            full_url,
            headers={
                'accept': "application/json",
                'Authorization': basic_auth
            },
            verify=False
        )
        if res.status_code not in [200, 204]:
            raise ValueError("Error in API call to Service API %s. Reason: %s " % (res.status_code,res.text))
        try:
            return res.json()
        except Exception:
            raise ValueError("Failed to parse http response to JSON format. Original response body: \n %s" % res.text)


'''' Commands '''


def test_module(client):
    try:
        client.query('help')
    except Exception as e:
        LOG(e)
        return_error(e)
    return 'ok'


def search_by_query(client):
    args = demisto.args()
    search_query = args.get('query')
    try:
        title = ("%s - Results for the Search Query" % INTEGRATION_NAME)
        raws = []
        nozomi_ec = []
        raw_response=client.query(search_query)['result']

        if raw_response:
            raws.append(raw_response)
            nozomi_ec.append({
                'QueryResults': raws
            })

        if not raws:
            return ("%s - Could not find any results for given query" % INTEGRATION_NAME)

        context_entry = {
            "Nozomi": nozomi_ec
         }

        human_readable = tableToMarkdown(t=context_entry.get("Nozomi"),name=title)

        return [human_readable,context_entry,raws]

    except Exception as e:
        LOG(e)
        return_error(e)


def list_all_nodes(client):
    args = demisto.args()
    search_query = "nodes"
    try:
        title = ("%s - Results for the Search Query" % INTEGRATION_NAME)
        raws = []
        nozomi_ec = []
        raw_response = client.query(search_query)['result']

        if raw_response:
            for item in raw_response:
                raws.append(raw_response)
                nozomi_ec.append({
                    'Host': item['appliance_host'],
                    'IP': item['ip'],
                    'MAC': item['mac_address'],
                    'Vendor': item['mac_vendor'],
                    'OS': item['os']
                })

        if not raws:
            return ("%s - Could not find any results for given query" % INTEGRATION_NAME)

        context_entry = {
            "Nozomi": nozomi_ec
         }

        human_readable = tableToMarkdown(t=context_entry.get("Nozomi"),name=title)

        return [human_readable,context_entry,raws]

    except Exception as e:
        LOG(e)
        return_error(e)


def find_ip_by_mac(client):
    args = demisto.args()
    mac_address=args.get('mac')
    search_query = "nodes | where mac_address match " + mac_address
    try:
        title = ("%s - Results for the Search Query" % INTEGRATION_NAME)
        raws = []
        nozomi_ec = []
        raw_response = client.query(search_query)['result']

        if raw_response:
            for item in raw_response:
                if 'ip' in item and item['ip'] is not None and len(item['ip'].split('.')) == 4:
                    raws.append(raw_response)
                    nozomi_ec.append({
                        'Mappings':
                            {
                                'IP': item['ip'],
                                'MAC': mac_address
                            }
                    })

        if not raws:
            return ("%s - Could not find any results for given query" % INTEGRATION_NAME)

        context_entry = {
            "Nozomi": nozomi_ec
         }

        human_readable = tableToMarkdown(t=context_entry.get("Nozomi"),name=title)

        return [human_readable,context_entry,raws]

    except Exception as e:
        LOG(e)
        return_error(e)


def main():
    params = demisto.params()

    username = params.get('credentials', {}).get('identifier', '')
    password = params.get('credentials', {}).get('password', '')


    # Remove trailing slash to prevent wrong URL path to service
    url = params['url'][:-1] if (params['url'] and params['url'].endswith('/')) else params['url']
    # Remove proxy if not set to true in params
    proxies = handle_proxy()

    try:
        client = Client(url, proxies,username,password)
        commands = {
            'guardian-search': search_by_query,
            'guardian-list-all-nodes': list_all_nodes,
            'guardian-find-ip-by-mac': find_ip_by_mac,
            'test-module': test_module
        }

        command = demisto.command()
        LOG('Command being called is %s' % command)

        if command in commands:
            if command == 'test-module':
                return_outputs(test_module(client))

            else:
                outputs=commands[command](client)
                return_outputs(outputs[0],outputs[1],outputs[2])
        else:
            return_error("Command Not Found")

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
