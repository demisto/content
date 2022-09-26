from datetime import datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from sdcclient import SdMonitorClient, SdSecureClient


class Client(BaseClient):
    def query_sysdig(self, url_suffix):
        return self._http_request(
            method='GET',
            url_suffix=url_suffix
        )

# Convert from Unix time to ISO


def time_convert(dtString):
    try:
        dtConverted = datetime.fromtimestamp(int(str(dtString).split('.')[0])).isoformat()
    except Exception:
        dtConverted = datetime.fromtimestamp(int(str(int(dtString / 1000)).split('.')[0])).isoformat()
    return dtConverted

# Flatten json structures


def flatten_data(y):
    out = {}

    def flatten(x, name=''):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + '_')
        elif type(x) is list:
            i = 0
            for a in x:
                flatten(a, name + str(i) + '_')
                i += 1
        else:
            out[name[:-1]] = x
    flatten(y)
    return out


def get_alerts(monitor, url):
    sdclient = SdMonitorClient(token=monitor, sdc_url=url)
    ok, res = sdclient.get_alerts()
    if not ok:
        return res
    results = []
    for alert in res['alerts']:
        results.append(alert)
    readable_output = tableToMarkdown('Sysdig Alerts', results, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Sysdig.Alerts',
        outputs_key_field='Alerts',
        outputs=results,
        raw_response=res)


def get_metrics(monitor, url):
    sdclient = SdMonitorClient(token=monitor, sdc_url=url)
    ok, res = sdclient.get_metrics()
    if not ok:
        return res
    results = []
    for metric_id, metric in res.items():
        results.append(metric)
    readable_output = tableToMarkdown('Sysdig Metrics', results, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Sysdig.Metrics',
        outputs_key_field='Metrics',
        outputs=results,
        raw_response=res)


def get_events(args, monitor, url):
    sdclient = SdMonitorClient(token=monitor, sdc_url=url)
    eventNameInput = args['eventName']
    results = []
    if eventNameInput != 'All':
        ok, res = sdclient.get_events(limit=demisto.args()['limit'], name=eventNameInput)
    else:
        ok, res = sdclient.get_events(limit=demisto.args()['limit'])
    if not ok:
        return res
    for item in res['events']:
        createdOn = time_convert(item['createdOn'])
        eventDescription = item['description']
        eventId = item['id']
        eventName = item['name']
        eventScope = item['scope']
        eventSeverity = item['severity']
        eventSource = item['source']
        timestamp = time_convert(item['timestamp'])
        eventType = item['type']
        eventVersion = item['version']
        if eventNameInput != 'All' and eventNameInput != eventName:
            continue
        results.append({'CreatedOn': createdOn,
                        'EventDescription': eventDescription,
                        'EventId': eventId,
                        'EventName': eventName,
                        'EventScope': eventScope,
                        'EventSeverity': eventSeverity,
                        'EventSource': eventSource,
                        'Timestamp': timestamp,
                        'EventType': eventType,
                        'EventVersion': eventVersion
                        })
    readable_output = tableToMarkdown('Container Events', results, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Sysdig.Events',
        outputs_key_field='Events',
        outputs=results,
        raw_response=res)


def get_users(monitor, url):
    sdclient = SdMonitorClient(token=monitor, sdc_url=url)
    ok, res = sdclient.get_users()
    results = []
    if not ok:
        return res
    for user in res:
        dateActivated = time_convert(user['dateActivated']) if 'dateActivated' in user else 'NA'
        dateCreated = time_convert(user['dateCreated']) if 'dateCreated' in user else 'NA'
        lastSeen = time_convert(user['lastSeen']) if 'lastSeen' in user else 'NA'
        lastSeenOnSecure = time_convert(user['lastSeenOnSecure']) if 'lastSeenOnSecure' in user else 'NA'
        lastUpdated = time_convert(user['lastUpdated']) if 'lastUpdated' in user else 'NA'
        results.append({
            'FirstName': user['firstName'],
            'LastName': user['lastName'],
            'UserName': user['username'],
            'SystemRole': user['systemRole'],
            'DateActivated': dateActivated,
            'DateCreated': dateCreated,
            'LastSeen': lastSeen,
            'LastSeenOnSecure': lastSeenOnSecure,
            'LastUpdated': lastUpdated,
            'Products': user['products'],
            'TeamRoles': user['teamRoles'],
            'Timezone': user['timezone']
        })
    readable_output = tableToMarkdown('User Information', results, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Sysdig.UserInfo',
        outputs_key_field='UserInfo',
        outputs=results,
        raw_response=res)


def list_hosts(args, monitor, url):
    duration = int(args['duration'])
    count = int(args['count'])
    print_json = args['print_json']
    if print_json == 'yes':
        print_json is True
    else:
        print_json is False
    sdclient = SdMonitorClient(token=monitor, sdc_url=url)
    metrics = [
        {'id': 'host.hostName'},
        {'id': 'container.count', 'aggregations': {'time': 'avg', 'group': 'avg'}}
    ]
    results = []
    ok, res = sdclient.get_data(
        metrics,  # list of metrics
        -duration,  # start time: either a unix timestamp, or a difference from 'now'
        0,  # end time: either a unix timestamp, or a difference from 'now' (0 means you need 'last X seconds')
        duration,  # sampling time, ie. data granularity;
        # if equal to the time window span then the result will contain a single sample
        paging={
            'from': 0,
            'to': count - 1
        })
    if not ok:
        # data fetch failed
        return(res)

    # data fetched successfully
    if not print_json:
        return res
    else:
        data = res['data']
        for item in data:
            time = time_convert(item['t'])
            hostName = item['d'][0]
            count = item['d'][1]
            results.append({'DateAdded': time, 'Host': hostName, 'Count': count})
    readable_output = tableToMarkdown('Host Count', results, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Sysdig.HostCount',
        outputs_key_field='HostCount',
        outputs=results,
        raw_response=res)


def list_policies(secure, url):
    sdclient = SdSecureClient(token=secure, sdc_url=url)
    ok, res = sdclient.list_policies()
    results = []
    if not ok:
        return res
    for entry in res:
        description = entry['description']
        enabled = entry['enabled']
        name = entry['name']
        createdOn = time_convert(entry['createdOn'])
        modifiedOn = time_convert(entry['modifiedOn'])
        results.append({'Description': description, 'Enabled': enabled, 'Name': name,
                       'CreatedOn': createdOn, 'ModifiedOn': modifiedOn})
    readable_output = tableToMarkdown('Sysdig Policies', results, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Sysdig.Policies',
        outputs_key_field='Policies',
        outputs=results,
        raw_response=res)


def list_vulns(client: Client, args, url):
    workloadType = args['workloadType']
    csvOut = args['csv']
    limit = args['limit']
    results = []
    url_suffix = f'api/scanning/runtime/v2/workflows/kubernetes/results?cursor&filter&limit={str(limit)}&order=desc&sort=vulnsBySev'
    response = client.query_sysdig(url_suffix)
    data = response['data']
    for entry in data:
        entry['vulnsBySev'] = str(entry['vulnsBySev']).replace(',', ';')
        entry['runningVulnsBySev'] = str(entry['runningVulnsBySev']).replace(',', ';')
        row = flatten_data(entry)
        if workloadType != 'all' and workloadType != row['scope_kubernetes.workload.type']:
            continue
        results.append(row)

    if csvOut == 'yes':
        # Convert to csv
        header = ''
        row = ''
        outputContents = ''

        # Create csv header row
        for item in results[0].keys():
            header = header + item + ','
        # Remove trailing comma
        header = header[:-1] + '\n'

        outputContents = header
        for entry in results:
            for value in entry.values():
                row = row + str(value).replace(',', ';') + ','
            row = row[:-1]
            outputContents = outputContents + row + '\n'
            row = ''
        filename = 'container_vulnerabilities.csv'
        file_content = outputContents
        return_results(fileResult(filename, file_content))
    else:
        readable_output = tableToMarkdown('Vulnerabilities Found', results, removeNull=True)
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='Sysdig.ContainerVulns',
            outputs_key_field='ContainerVulns',
            outputs=results,
            raw_response=response)


def query_vulns_by_container(client: Client, args, url):
    imageId = args['resultId']
    limit = args['limit']
    results = []
    url_suffix = f'api/scanning/scanresults/v2/results/{imageId}/vulnPkgs?filter=&limit={str(limit)}&offset=0&order=asc&sort=vulnSeverity'
    response = client.query_sysdig(url_suffix)
    for item in response['data']:
        row = flatten_data(item)
        results.append(row)
    readable_output = tableToMarkdown('Vulnerabilities Found', results, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Sysdig.ContainerVulns',
        outputs_key_field='ContainerVulns',
        outputs=results,
        raw_response=response)


def main():
    url = demisto.params()['url'][:-1] if demisto.params()['url'].endswith('/') else demisto.params()['url']
    secure = demisto.params()['securekey']
    monitor = demisto.params()['monitorkey']
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        headers = {
            'Authorization': f'Bearer {secure}'
        }
        client = Client(
            base_url=url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            try:
                get_users(monitor, url)
                demisto.results('ok')
            except Exception as e:
                return_error(f'Error:\n{str(e)}')

        elif demisto.command() == 'sysdig-get-alerts':
            return_results(get_alerts(monitor, url))

        elif demisto.command() == 'sysdig-get-metrics':
            return_results(get_metrics(monitor, url))

        elif demisto.command() == 'sysdig-get-users':
            return_results(get_users(monitor, url))

        elif demisto.command() == 'sysdig-get-events':
            return_results(get_events(demisto.args(), monitor, url))

        elif demisto.command() == 'sysdig-list-policies':
            return_results(list_policies(secure, url))

        elif demisto.command() == 'sysdig-list-hosts':
            return_results(list_hosts(demisto.args(), monitor, url))

        elif demisto.command() == 'sysdig-list-vulnerabilities':
            return_results(list_vulns(client, demisto.args(), url))

        elif demisto.command() == 'sysdig-list-vulns-by-container':
            return_results(query_vulns_by_container(client, demisto.args(), url))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
