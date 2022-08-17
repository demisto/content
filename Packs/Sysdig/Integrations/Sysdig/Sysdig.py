import json
from datetime import datetime

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401
from sdcclient import SdMonitorClient, SdSecureClient

URL = demisto.params()['url']
SECUREKEY = demisto.params()['securekey']
MONITORKEY = demisto.params()['monitorkey']
USE_SSL = not demisto.params().get('insecure', False)

# Convert from Unix time to ISO


def time_convert(dtString):
    try:
        dtConverted = datetime.fromtimestamp(int(str(dtString).split('.')[0])).isoformat()
    except:
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


def get_alerts():
    sdclient = SdMonitorClient(token=MONITORKEY, sdc_url=URL)
    ok, res = sdclient.get_alerts()
    if not ok:
        return res
    results = []
    for alert in res['alerts']:
        results.append(alert)
    entry = {'Type': entryTypes['note'],
             'Contents': results,
             'ContentsFormat': formats['json'],
             'HumanReadable': tableToMarkdown('Sysdig Alerts', results, removeNull=True),
             'ReadableContentsFormat': formats['markdown'],
             'EntryContext': {'Alerts': results}
             }
    return entry


def get_metrics():
    sdclient = SdMonitorClient(token=MONITORKEY, sdc_url=URL)
    ok, res = sdclient.get_metrics()
    if not ok:
        return res
    results = []
    string = ''
    for metric_id, metric in res.items():
        results.append(metric)
        #string = string + 'Metric name: ' + metric_id + ', type: ' + metric['type'] + '\n'
    entry = {'Type': entryTypes['note'],
             'Contents': results,
             'ContentsFormat': formats['json'],
             'HumanReadable': tableToMarkdown('Sysdig Metrics', results, removeNull=True),
             'ReadableContentsFormat': formats['markdown'],
             'EntryContext': {'Metrics': results}
             }
    return entry


def get_events():
    sdclient = SdMonitorClient(token=MONITORKEY, sdc_url=URL)
    eventNameInput = demisto.args()['eventName']
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
    entry = {'Type': entryTypes['note'],
             'Contents': results,
             'ContentsFormat': formats['json'],
             'HumanReadable': tableToMarkdown('Container Events', results, removeNull=True),
             'ReadableContentsFormat': formats['markdown'],
             'EntryContext': {'Events': results}
             }
    return entry


def get_users():
    sdclient = SdMonitorClient(token=MONITORKEY, sdc_url=URL)
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
    entry = {'Type': entryTypes['note'],
             'Contents': results,
             'ContentsFormat': formats['json'],
             'HumanReadable': tableToMarkdown('User Information', results, removeNull=True),
             'ReadableContentsFormat': formats['markdown'],
             'EntryContext': {'UserInfo': results}
             }
    return entry


def list_hosts():
    args = demisto.args()
    duration = int(args['duration'])
    count = int(args['count'])
    print_json = args['print_json']
    if print_json == 'yes':
        print_json is True
    else:
        print_json is False
    sdclient = SdMonitorClient(token=MONITORKEY, sdc_url=URL)
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
    entry = {'Type': entryTypes['note'],
             'Contents': results,
             'ContentsFormat': formats['json'],
             'HumanReadable': tableToMarkdown('Host count', results, removeNull=True),
             'ReadableContentsFormat': formats['markdown'],
             'EntryContext': {'HostCount': results}
             }
    return entry


def list_policies():
    sdclient = SdSecureClient(token=SECUREKEY, sdc_url=URL)
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
    entry = {'Type': entryTypes['note'],
             'Contents': results,
             'ContentsFormat': formats['json'],
             'HumanReadable': tableToMarkdown('Sysdig Policies', results, removeNull=True),
             'ReadableContentsFormat': formats['markdown'],
             'EntryContext': {'Policies': results}
             }
    return entry


def list_vulns():
    workloadType = demisto.args()['workloadType']
    csvOut = demisto.args()['csv']
    results = []
    limit = demisto.args()['limit']
    url = URL + 'api/scanning/runtime/v2/workflows/kubernetes/results?cursor&filter&limit=' + \
        str(limit) + '&order=desc&sort=vulnsBySev'
    token = 'Bearer ' + SECUREKEY
    headers = {'Authorization': token}
    response = requests.get(url=url, headers=headers).json()
    data = response['data']
    for entry in data:
        entry['vulnsBySev'] = str(entry['vulnsBySev']).replace(',', ';')
        entry['runningVulnsBySev'] = str(entry['runningVulnsBySev']).replace(',', ';')
        row = flatten_data(entry)
        if workloadType != 'all' and workloadType != row['scope_kubernetes.workload.type']:
            continue
        results.append(row)
    entry = {'Type': entryTypes['note'],
             'Contents': results,
             'ContentsFormat': formats['json'],
             'HumanReadable': tableToMarkdown('Vulnerabilities Found', results, removeNull=True),
             'ReadableContentsFormat': formats['markdown'],
             'EntryContext': {'ContainerVulns': results}
             }
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
        return entry


def query_vulns_by_container():
    imageId = demisto.args()['resultId']
    limit = demisto.args()['limit']
    results = []
    url = URL + 'api/scanning/scanresults/v2/results/' + imageId + \
        '/vulnPkgs?filter=&limit=' + str(limit) + '&offset=0&order=asc&sort=vulnSeverity'
    token = 'Bearer ' + SECUREKEY
    headers = {'Authorization': token}
    response = requests.get(url=url, headers=headers).json()
    for item in response['data']:
        row = flatten_data(item)
        results.append(row)
    entry = {'Type': entryTypes['note'],
             'Contents': results,
             'ContentsFormat': formats['json'],
             'HumanReadable': tableToMarkdown('Vulnerabilities Found', results, removeNull=True),
             'ReadableContentsFormat': formats['markdown'],
             'EntryContext': {'ContainerVulns': results}
             }
    return entry


def test_module():
    try:
        sdclient = SdMonitorClient(token=MONITORKEY, sdc_url=URL)
        ok, res = sdclient.get_alerts()
        if ok is True:
            demisto.results('ok')
    except Exception as e:
        LOG(e)
        return_error(e.message)


try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'sysdig-get-alerts':
        demisto.results(get_alerts())
    elif demisto.command() == 'sysdig-get-metrics':
        demisto.results(get_metrics())
    elif demisto.command() == 'sysdig-get-users':
        demisto.results(get_users())
    elif demisto.command() == 'sysdig-get-events':
        demisto.results(get_events())
    elif demisto.command() == 'sysdig-list-policies':
        demisto.results(list_policies())
    elif demisto.command() == 'sysdig-list-hosts':
        demisto.results(list_hosts())
    elif demisto.command() == 'sysdig-list-vulnerabilities':
        demisto.results(list_vulns())
    elif demisto.command() == 'sysdig-list-vulns-by-container':
        demisto.results(query_vulns_by_container())
except Exception as e:
    return_error('Error has occurred in the Sysdig Integration: {error}\n {message}'.format(error=type(e), message=e.message))
