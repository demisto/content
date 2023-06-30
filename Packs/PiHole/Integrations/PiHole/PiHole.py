import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


def results_return(command, thingtoreturn):
    if command == 'RecentBlocked':
        results = CommandResults(
            outputs_prefix='PiHole.' + str(command),
            outputs_key_field='',
            outputs={'Data': thingtoreturn}
        )
    else:
        results = CommandResults(
            outputs_prefix='PiHole.' + str(command),
            outputs_key_field='',
            outputs=thingtoreturn
        )
    return_results(results)


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Returns:
        'ok' if test passed, anything else will fail the test.
    Test function gets the base url and if it responds the the test succeeds. No Auth needed.
    """
    result = client._http_request('GET', '')
    if result:
        return 'ok'
    else:
        return 'Test failed ' + str(result)


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    token = demisto.params().get('token')
    authtoken = '&auth=' + str(token)

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/admin/api.php')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = BaseClient(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'pihole-get-version':
            results_return('Version', client._http_request('GET', '?version' + str(authtoken)))
        elif demisto.command() == 'pihole-get-versions':
            results_return('Versions', client._http_request('GET', '?versions' + str(authtoken)))
        elif demisto.command() == 'pihole-get-type':
            results_return('Type', client._http_request('GET', '?type' + str(authtoken)))
        elif demisto.command() == 'pihole-get-summaryraw':
            results_return('SummaryRaw', client._http_request('GET', '?summaryRaw' + str(authtoken)))
        elif demisto.command() == 'pihole-get-overtimedata10mins':
            results_return('OverTimeData10mins', client._http_request('GET', '?overTimeData10mins' + str(authtoken)))
        elif demisto.command() == 'pihole-get-topitems':
            limit = int(demisto.args().get('limit'))
            results_return('TopItems', client._http_request('GET', '?topItems=' + str(limit) + str(authtoken)))
        elif demisto.command() == 'pihole-get-topclients':
            limit = int(demisto.args().get('limit'))
            results_return('TopClients', client._http_request('GET', '?topClients=' + str(limit) + str(authtoken)))
        elif demisto.command() == 'pihole-get-topclientsblocked':
            results_return('TopClientsBlocked', client._http_request('GET', '?topClientsblocked' + str(authtoken)))
        elif demisto.command() == 'pihole-get-forward-destinations':
            results_return('ForwardDestinations', client._http_request('GET', '?getForwardDestinations' + str(authtoken)))
        elif demisto.command() == 'pihole-get-query-types':
            results_return('QueryTypes', client._http_request('GET', '?getQueryTypes' + str(authtoken)))
        elif demisto.command() == 'pihole-get-all-queries':
            results_return('AllQueries', client._http_request('GET', '?getAllQueries' + str(authtoken)))
        elif demisto.command() == 'pihole-get-overTimeDataQueryTypes':
            results_return('OverTimeDataQueryTypes', client._http_request('GET', '?overTimeDataQueryTypes' + str(authtoken)))
        elif demisto.command() == 'pihole-get-cache-info':
            results_return('CacheInfo', client._http_request('GET', '?getCacheInfo' + str(authtoken)))
        elif demisto.command() == 'pihole-get-client-names':
            results_return('ClientNames', client._http_request('GET', '?getClientNames' + str(authtoken)))
        elif demisto.command() == 'pihole-get-over-time-data-clients':
            results_return('OverTimeDataClients', client._http_request('GET', '?overTimeDataClients' + str(authtoken)))
        elif demisto.command() == 'pihole-get-recent-blocked':
            results_return('RecentBlocked', client._http_request('GET', '?recentBlocked' + str(authtoken), resp_type='text'))
        elif demisto.command() == 'pihole-status':
            results_return('Status', client._http_request('GET', '?status' + str(authtoken)))
        elif demisto.command() == 'pihole-enable':
            results_return('Enable', client._http_request('GET', '?enable' + str(authtoken)))
        elif demisto.command() == 'pihole-disable':
            seconds = int(demisto.args().get('time'))
            if seconds == 0:
                results_return('Disable', client._http_request('GET', '?disable' + str(authtoken)))
            else:
                results_return('Disable', client._http_request('GET', '?disable=' + str(seconds) + str(authtoken)))
        elif demisto.command() == 'pihole-get-list':
            usedlist = demisto.args().get('list')
            results_return('Lists', client._http_request('GET', '?list=' + str(usedlist) + str(authtoken)))
        elif demisto.command() == 'pihole-list-management':
            domain = demisto.args().get('domain')
            action = demisto.args().get('action')
            usedlist = demisto.args().get('list')
            results_return('List', client._http_request('GET', '?list=' + str(usedlist)
                                                        + '&' + str(action) + '=' + str(domain) + str(authtoken)))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
