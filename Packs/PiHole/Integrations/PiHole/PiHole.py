import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client:
    def __init__(self, base_url, verify, proxies, auth):
        self.base_url = base_url
        self.verify = verify
        self.proxies = proxies
        self.auth = '&auth=' + auth

    def http_request(self, method, url_suffix):
        server = self.base_url + url_suffix + self.auth
        res = requests.request(
            method,
            server,
            verify=self.verify,
            proxies=self.proxies
        )
        try:
            return res.json()
        except ValueError:
            data = {'Info': res.text}
            return data


def results_return(command, thingtoreturn):
    finaldata = {'PiHole': {command: thingtoreturn}}
    return demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': thingtoreturn,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(command, thingtoreturn, removeNull=True),
        'EntryContext': finaldata
    })


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    result = client.http_request('GET', '')
    if result:
        return 'ok'
    else:
        return 'Test failed ' + result


def get_data(client, suffix, command):
    results_return(command, client.http_request('GET', suffix))


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    token = demisto.params().get('token')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/admin/api.php')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxies=proxy,
            auth=token)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'pihole-get-version':
            get_data(client, '?version', 'Version')
        elif demisto.command() == 'pihole-get-versions':
            get_data(client, '?versions', 'Versions')
        elif demisto.command() == 'pihole-get-type':
            get_data(client, '?type', 'Type')
        elif demisto.command() == 'pihole-get-summaryraw':
            get_data(client, '?summaryRaw', 'SummaryRaw')
        elif demisto.command() == 'pihole-get-overtimedata10mins':
            get_data(client, '?overTimeData10mins', 'OverTimeData10mins')
        elif demisto.command() == 'pihole-get-topitems':
            entries = int(demisto.args().get('entries'))
            get_data(client, '?topItems=' + str(entries), 'TopItems')
        elif demisto.command() == 'pihole-get-topclients':
            entries = int(demisto.args().get('entries'))
            get_data(client, '?topClients=' + str(entries), 'TopClients')
        elif demisto.command() == 'pihole-get-topclientsblocked':
            get_data(client, '?topClientsblocked', 'TopClientsBlocked')
        elif demisto.command() == 'pihole-get-forward-destinations':
            get_data(client, '?getForwardDestinations', 'ForwardDestinations')
        elif demisto.command() == 'pihole-get-query-types':
            get_data(client, '?getQueryTypes', 'QueryTypes')
        elif demisto.command() == 'pihole-get-all-queries':
            get_data(client, '?getAllQueries', 'AllQueries')
        elif demisto.command() == 'pihole-get-overTimeDataQueryTypes':
            get_data(client, '?overTimeDataQueryTypes', 'overTimeDataQueryTypes')
        elif demisto.command() == 'pihole-get-cache-info':
            get_data(client, '?getCacheInfo', 'CacheInfo')
        elif demisto.command() == 'pihole-get-client-names':
            get_data(client, '?getClientNames', 'ClientNames')
        elif demisto.command() == 'pihole-get-over-time-data-clients':
            get_data(client, '?overTimeDataClients', 'OverTimeDataClients')
        elif demisto.command() == 'pihole-get-recent-blocked':
            get_data(client, '?recentBlocked', 'RecentBlocked')
        elif demisto.command() == 'pihole-status':
            get_data(client, '?status', 'Status')
        elif demisto.command() == 'pihole-enable':
            get_data(client, '?enable', 'Enable')
        elif demisto.command() == 'pihole-disable':
            seconds = int(demisto.args().get('time'))
            if seconds == 0:
                get_data(client, '?disable', 'Disable')
            else:
                get_data(client, '?disable=' + str(seconds), 'DisabledFor' + str(seconds))
        elif demisto.command() == 'pihole-get-list':
            list = demisto.args().get('list')
            get_data(client, '?list=' + str(list), 'GetList')
        elif demisto.command() == 'pihole-list-management':
            domain = demisto.args().get('domain')
            action = demisto.args().get('action')
            list = demisto.args().get('list')
            get_data(client, '?list=' + str(list) + '&' + str(action) + '=' + str(domain), 'List')

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
