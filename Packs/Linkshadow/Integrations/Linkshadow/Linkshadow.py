import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import math
from datetime import datetime
import dateparser
import urllib3
import traceback
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
Linkshadow_SEVERITIES = 0

''' CLIENT CLASS '''


class Client(BaseClient):
    def fetch_anomaly(self, apiKey, api_username, plugin_id, action, time_frame):
        request_params = {}
        if apiKey:
            request_params['api_key'] = apiKey
        if api_username:
            request_params['api_username'] = api_username
        if plugin_id:
            request_params['plugin_id'] = plugin_id
        if action:
            request_params['action'] = action
        if time_frame:
            request_params['time_frame'] = int(time_frame)
        return self._http_request(
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            method='POST',
            url_suffix='/api/plugin/',
            data=request_params
        )


''' COMMAND FUNCTIONS '''


def test_module(client, apiKey, api_username, plugin_id, action, time_frame=1440):
    try:
        alerts = client.fetch_anomaly(apiKey=apiKey, api_username=api_username,
                                      plugin_id=plugin_id, action=action, time_frame=time_frame)
        if 'error' in str(alerts.get('message')) or 'success' in str(alerts.get('message')):
            return "ok"
        else:
            return alerts.get('message')
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            return e


def format_JSON_for_fetch_incidents(ls_anomaly):

    anomaly_info = {}
    anomaly = ls_anomaly
    anomaly_info['time_seen'] = anomaly['time_seen']if 'time_seen' in anomaly else 'no ls_anomaly time_seen'
    anomaly_info['category'] = anomaly['category']if 'category' in anomaly else 'no ls_anomaly category'
    anomaly_info['anomaly_type'] = anomaly['anomaly_type'] if 'anomaly_type' in anomaly else 'no ls_anomaly anomaly_type'
    anomaly_info['sip'] = anomaly['sip']if 'sip' in anomaly else 'no ls_anomaly sip'
    anomaly_info['anomaly_id'] = anomaly['anomaly_id']if 'anomaly_id' in anomaly else 'no ls_anomaly anomaly_id'
    anomaly_info['inserted_time'] = anomaly['inserted_time']if 'inserted_time' in anomaly else 'no ls_anomaly inserted_time'
    anomaly_info['smac'] = anomaly['smac']if 'smac' in anomaly else 'no ls_anomaly smac'
    anomaly_info['bandwidth'] = anomaly['bandwidth']if 'bandwidth' in anomaly else 'no ls_anomaly bandwidth'
    anomaly_info['score'] = anomaly['score']if 'score' in anomaly else 'no ls_anomaly score'
    anomaly_info['dport'] = anomaly['dport']if 'dport' in anomaly else 'no ls_anomaly dport'
    anomaly_info['dmac'] = anomaly['dmac']if 'dmac' in anomaly else 'no ls_anomaly dmac'
    anomaly_info['sport'] = anomaly['sport']if 'sport' in anomaly else 'no ls_anomaly sport'
    anomaly_info['dip'] = anomaly['dip']if 'dip' in anomaly else 'no ls_anomaly dip'
    anomaly_info['desc'] = anomaly['desc']if 'desc' in anomaly else 'no ls_anomaly desc'
    return anomaly_info


def fetch_incidents(client, max_alerts, last_run, first_fetch_time, apiKey, api_username, plugin_id, action):
    # handle first time fetch
    if not last_run.get('last_fetch'):
        last_fetch = dateparser.parse(first_fetch_time, settings={'TIMEZONE': 'UTC'})
    else:
        last_fetch = dateparser.parse(last_run.get('last_fetch'))
    latest_created_time = last_fetch
    assert latest_created_time is not None, f"could not parse {last_run.get('last_fetch')}"

    diff_timedelta = float(datetime.utcnow().strftime('%s')) - float(latest_created_time.strftime('%s'))
    time_frame = int(math.ceil(diff_timedelta / 60))
    incidents = []
    alerts = client.fetch_anomaly(apiKey=apiKey, api_username=api_username,
                                  plugin_id=plugin_id, action=action, time_frame=time_frame)
    for dic in alerts.get('data'):
        for key in dic.keys():
            if key == 'time_seen':
                incident_occurred_time = dic['time_seen']
                incident_created_time = dateparser.parse(str(int(dic['action_time']) * 1000), settings={'TIMEZONE': 'UTC'})
                if last_fetch:
                    assert incident_created_time is not None
                    if incident_created_time.strftime('%s') <= last_fetch.strftime('%s'):
                        continue
                incident_name = "Linkshadow-entityAnomaly"
                formatted_JSON = format_JSON_for_fetch_incidents(dic)

                incident = {
                    'name': incident_name,
                    'occurred': timestamp_to_datestring(incident_occurred_time),
                    'rawJSON': json.dumps(formatted_JSON),
                    'CustomFields': {  # Map specific XSOAR Custom Fields
                        'sip': formatted_JSON['sip'],
                        'sourceip': formatted_JSON['sip'],
                        'destinationip': formatted_JSON['dip'],
                        'sourceport': formatted_JSON['sport'],
                        'destinationport': formatted_JSON['dport'],
                        'macaddress': formatted_JSON['smac'],
                        'alertid': formatted_JSON['anomaly_id'],
                        'subcategory': formatted_JSON['category']
                    }
                }
                incidents.append(incident)
                # Update last run and add incident if the incident is newer than last fetch
                assert incident_created_time is not None
                if incident_created_time.strftime('%s') > latest_created_time.strftime('%s'):
                    latest_created_time = incident_created_time
                # print (max_alerts)
                if len(incidents) >= max_alerts:
                    break
    next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
    return next_run, incidents


def fetch_entity_anomalies(client, args, arg):
    apiKey = args.get('apiKey'),
    username = args.get('api_username')
    plugin_id = args.get('plugin_id')
    action = args.get('action')

    time_frame = arg_to_number(
        arg=arg.get('time_frame'),
        arg_name='time_frame',
        required=False
    )

    alerts = client.fetch_anomaly(
        apiKey=apiKey,
        api_username=username,
        plugin_id=plugin_id,
        action=action,
        time_frame=time_frame
    )

    return CommandResults(
        outputs_prefix='Linkshadow.data',
        outputs_key_field='GlobalID',
        outputs=alerts.get('data') or [{"message": "Linkshadow Anomaly already acknowledged!!"}]
    )


''' MAIN FUNCTION '''


def main():
    apiKey = demisto.params().get('apiKey')
    base_url = demisto.params().get('url')
    api_username = demisto.params().get('api_username')
    plugin_id = demisto.params().get("plugin_id")
    action = demisto.params().get("action")
    first_fetch = demisto.params().get('first_fetch', '1 days')
    proxy = demisto.params().get('proxy', False)
    demisto.debug('Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=base_url,
            verify=False,
            proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_module(client, apiKey, api_username, plugin_id, action)
            return_results(result)

        if demisto.command() == 'fetch-incidents':
            max_alerts = MAX_INCIDENTS_TO_FETCH
            next_run, incidents = fetch_incidents(
                client=client,
                max_alerts=max_alerts,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch,
                apiKey=apiKey,
                api_username=api_username,
                plugin_id=plugin_id,
                action=action
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'Linkshadow-fetch-entity-anomalies':
            return_results(fetch_entity_anomalies(client, demisto.params(), demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command', e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
