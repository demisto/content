import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

from datetime import datetime

import dateparser
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


def results_return(command, thingtoreturn):
    results = CommandResults(
        outputs_prefix='Graylog.' + str(command),
        outputs_key_field='',
        outputs=thingtoreturn
    )
    return_results(results)


def test_module(client):
    result = client._http_request('GET', 'cluster/')
    if result:
        return 'ok'
    else:
        return 'Test failed: ' + str(result)


def create_incident_from_log(log):
    occurred = log['timestamp']
    keys = log.keys()
    labels = []
    for key in keys:
        labels.append({'type': key, 'value': str(log[key])})
        formatted_description = 'Graylog Incident'
    return {
        'name': formatted_description,
        'labels': labels,
        'rawJSON': json.dumps(log),
        'occurred': occurred
    }


def form_incindents(logs):
    listofincidents = []
    for item in logs:
        listofincidents.append(create_incident_from_log(item['message']))
    return listofincidents


def fetch_incidents(client):
    timefrom = dateparser.parse(demisto.params().get('fetch_time')).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
    timefrom += 'Z'
    incidentquery = demisto.params().get('fetch_query')
    last_run = demisto.getLastRun()
    if last_run and 'start_time' in last_run:
        start_time = last_run.get('start_time')
    else:
        start_time = timefrom
    end_time = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
    end_time += 'Z'
    parameters = {'query': incidentquery,
                  'from': start_time,
                  'to': end_time}
    results = client._http_request('GET', '/search/universal/absolute', params=parameters)
    if 'total_results' in results and results['total_results'] > 0:
        demisto.setLastRun({'start_time': end_time})
        demisto.incidents(form_incindents(results['messages']))
    else:
        demisto.incidents([])


def main():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    headers = {'X-Requested-By': 'xsoar',
               'Accept': 'application/json'}

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        client = BaseClient(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents(client)
        elif demisto.command() == 'graylog-cluster-status':
            results_return('ClusterStatus', client._http_request('GET', 'cluster/'))
        elif demisto.command() == 'graylog-cluster-node-jvm':
            results_return('ClusterNodeJVM', client._http_request('GET', 'cluster/' + str(demisto.args().get('nodeId')) + '/jvm'))
        elif demisto.command() == 'graylog-cluster-inputstates':
            results_return('ClusterInputStates', client._http_request('GET', 'cluster/inputstates'))
        elif demisto.command() == 'graylog-cluster-processing-status':
            results_return('ClusterProcessingStatus', client._http_request('GET', '/cluster/processing/status'))
        elif demisto.command() == 'graylog-indexer-cluster-health':
            results_return('IndexerHealth', client._http_request('GET', '/system/indexer/cluster/health'))
        elif demisto.command() == 'graylog-search':
            parameters = {'query': demisto.args().get('query'),
                          'range': demisto.args().get('range'),
                          'limit': demisto.args().get('limit'),
                          'offset': demisto.args().get('offset'),
                          'filter': demisto.args().get('filter'),
                          'fields': demisto.args().get('fields'),
                          'sort': demisto.args().get('sort'),
                          'decorate': demisto.args().get('decorate')}
            results_return('Search', client._http_request('GET', '/search/universal/relative', params=parameters))
        elif demisto.command() == 'graylog-search-absolute':
            parameters = {'query': demisto.args().get('query'),
                          'from': demisto.args().get('from'),
                          'to': demisto.args().get('to'),
                          'limit': demisto.args().get('limit'),
                          'offset': demisto.args().get('offset'),
                          'filter': demisto.args().get('filter'),
                          'fields': demisto.args().get('fields'),
                          'sort': demisto.args().get('sort'),
                          'decorate': demisto.args().get('decorate')}
            results_return('SearchAbsolute', client._http_request('GET', '/search/universal/absolute', params=parameters))
        elif demisto.command() == 'graylog-events-search':
            jsonparameters = {'query': demisto.args().get('query'),
                              'filter': demisto.args().get('filter'),
                              'page': demisto.args().get('page'),
                              'sort_direction': demisto.args().get('sort_direction'),
                              'per_page': demisto.args().get('per_page'),
                              'timerange': {'type': 'relative', 'range': demisto.args().get('timerange')},
                              'sort_by': demisto.args().get('sort_by')}
            jsonparameters = remove_empty_elements(jsonparameters)
            results_return('EventsSearch', client._http_request('POST', '/events/search', json_data=jsonparameters))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
