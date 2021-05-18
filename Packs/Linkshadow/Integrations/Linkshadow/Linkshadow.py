import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import requests
import dateparser
import traceback
import time
from datetime import datetime
import time

urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
Linkshadow_SEVERITIES = 0

''' CLIENT CLASS '''

class Client(BaseClient):
    def fetch_anomaly(self, apiKey, start_time, api_username, plugin_id, action, time_frame):
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
def test_module(client, first_fetch_time, apiKey, api_username, plugin_id, action, time_frame):
    try:
        alerts = client.fetch_anomaly(apiKey=apiKey, start_time=first_fetch_time, api_username=api_username,
                                plugin_id=plugin_id,action=action,time_frame=time_frame)
        if 'error' in str(alerts.get('message')) or 'success' in str(alerts.get('message')):
            return "ok"
        else:
            return alerts.get('message')
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            return e
    return 'ok'

def format_JSON_for_fetch_incidents(ls_anomaly):

    anomaly_info={}
    anomaly=ls_anomaly
    anomaly_info['time_seen']=anomaly['time_seen']if 'time_seen' in anomaly else 'no ls_anomaly time_seen'
    anomaly_info['category']=anomaly['category']if 'category' in anomaly else 'no ls_anomaly category'
    anomaly_info['anomaly_type']=anomaly['anomaly_type'] if 'anomaly_type' in anomaly else 'no ls_anomaly anomaly_type'
    anomaly_info['sip']=anomaly['sip']if 'sip' in anomaly else 'no ls_anomaly sip'
    # anomaly_info['GlobalID']=anomaly['GlobalID']if 'GlobalID' in anomaly else 'no ls_anomaly GlobalID'
    anomaly_info['anomaly_id']=anomaly['anomaly_id']if 'anomaly_id' in anomaly else 'no ls_anomaly anomaly_id'
    anomaly_info['inserted_time']=anomaly['inserted_time']if 'inserted_time' in anomaly else 'no ls_anomaly inserted_time'
    anomaly_info['smac']=anomaly['smac']if 'smac' in anomaly else 'no ls_anomaly smac'
    anomaly_info['bandwidth']=anomaly['bandwidth']if 'bandwidth' in anomaly else 'no ls_anomaly bandwidth'
    anomaly_info['score']=anomaly['score']if 'score' in anomaly else 'no ls_anomaly score'
    anomaly_info['dport']=anomaly['dport']if 'dport' in anomaly else 'no ls_anomaly dport'
    anomaly_info['dmac']=anomaly['dmac']if 'dmac' in anomaly else 'no ls_anomaly dmac'
    anomaly_info['sport']=anomaly['sport']if 'sport' in anomaly else 'no ls_anomaly sport'
    anomaly_info['dip']=anomaly['dip']if 'dip' in anomaly else 'no ls_anomaly dip'
    # anomaly_info['id']=anomaly['id']if 'id' in anomaly else 'no ls_anomaly id'
    anomaly_info['desc']=anomaly['desc']if 'desc' in anomaly else 'no ls_anomaly desc'

    # if 'data' in anomaly:
    #     data = anomaly['data']
    #     # data_info={}
    #     anomaly_info['linkflow_file_path'] = data['linkflow_file_path'] if 'linkflow_file_path' in data else 'no linkflow_file_path'
    #     anomaly_info['pcap_waiting'] = data['pcap_waiting'] if 'pcap_waiting' in data else 'no pcap_waiting'
    #     anomaly_info['log_source'] = data['log_source'] if 'log_source' in data else 'no log_source'
    #     anomaly_info['process_finder'] = data['process_finder'] if 'process_finder' in data else 'no process_finder'
    #     anomaly_info['end_time'] = data['end_time'] if 'end_time' in data else 'no end_time'
    #     anomaly_info['pcap'] = data['pcap'] if 'pcap' in data else 'no pcap'
    # anomaly_info['data'] = data_info


    return anomaly_info


def fetch_incidents(client, max_alerts, last_run, first_fetch_time, apiKey, api_username, plugin_id, action, time_frame):

    last_fetch = last_run.get('last_fetch', None)

    if last_fetch is None:
        last_fetch = first_fetch_time
    else:

        last_fetch = int(last_fetch)

    latest_created_time = int(last_fetch)
    incidents = []
    alerts = client.fetch_anomaly(apiKey=apiKey, start_time=first_fetch_time, api_username=api_username,
                                plugin_id=plugin_id,action=action,time_frame=time_frame)
    alert={}
    for alert in alerts:

        if  alert == 'data':
            for dic in  alerts['data']:
                for key in dic.keys():
                    if key=='time_seen':
                        incident_created_time =dic['time_seen']
                        if last_fetch:
                            if incident_created_time <= last_fetch:
                                continue
                        incident_name = "Linkshadow-entityAnomaly"
                        formatted_JSON = format_JSON_for_fetch_incidents(dic)

                        incident = {
                            'name': incident_name,
                            'occurred': timestamp_to_datestring(incident_created_time),
                            'rawJSON': json.dumps(formatted_JSON ),
                            'CustomFields': {  # Map specific XSOAR Custom Fields
                                'sip': formatted_JSON['sip'],
                                'sourceip':formatted_JSON['sip'],
                                'destinationip':formatted_JSON['dip'],
                                'sourceport':formatted_JSON['sport'],
                                'destinationport':formatted_JSON['dport'],
                                'macaddress':formatted_JSON['smac'],
                                'alertid':formatted_JSON['anomaly_id'],
                                'subcategory':formatted_JSON['category']
                            }
                        }

                        incidents.append(incident)

                        # Update last run and add incident if the incident is newer than last fetch
                        # if incident_created_time > latest_created_time:
                        #     latest_created_time = incident_created_time
                        # print (max_alerts)

                        if len(incidents) >= max_alerts:
                            break


    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents

def fetch_entity_anomalies(client,args):
    apiKey = args.get('apiKey'),
    username  = args.get('api_username')
    plugin_id = args.get('plugin_id')
    action = args.get('action')

    time_frame = arg_to_int(
        arg=args.get('time_frame'),
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
        outputs_prefix='Linkshadow.anomaly',
        outputs_key_field='demisto.args()',
        outputs=alerts
    )


def arg_to_int(arg, arg_name, required=False):

    if arg is None:
        if required is True:
            raise ValueError('Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError('Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError('Invalid number: "{arg_name}"')

def arg_to_timestamp(arg, arg_name, required = False) :

    if arg is None:
        if required is True:
            raise ValueError('Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():

        return int(arg)
    if isinstance(arg, str):

        date =datetime.utcnow()
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError('Invalid date: {arg_name}')

        return int(date.strftime('%s'))
    if isinstance(arg, (int, float)):

        return int(arg)
    raise ValueError('Invalid date: "{arg_name}"')

''' MAIN FUNCTION '''


def main():

    apiKey = demisto.params().get('apiKey')
    base_url = urljoin(demisto.params()['url'])
    api_username = demisto.params().get('api_username')
    plugin_id = demisto.params().get("plugin_id")
    action =demisto.params().get("action")
    time_frame = demisto.params().get("time_frame")
    verify_certificate = not demisto.params().get('insecure', False)

    first_fetch_time = arg_to_timestamp(
        arg=demisto.params().get('first_fetch', '1 days'),
        arg_name='First fetch time',
        required=True
    )

    proxy = demisto.params().get('proxy', False)

    demisto.debug('Command being called is {demisto.command()}')
    try:

        headers = {
            "apiKey" : apiKey,
            "api_username" :api_username,
            "plugin_id" : plugin_id,
            "action":action,
            "time_frame":time_frame

        }

        client = Client(
            base_url=base_url,
            verify=False,

            proxy=proxy)

        if demisto.command() == 'test-module':

            result = test_module(client, first_fetch_time, apiKey, api_username, plugin_id, action, time_frame)
            return_results(result)

        if demisto.command() == 'fetch-incidents':

            max_alerts=MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_alerts=max_alerts,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_time,
                apiKey = apiKey,
                api_username = api_username,
                plugin_id = plugin_id,
                action = action,
                time_frame = time_frame

            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

            # demisto.createIncidents(incidents)


        elif demisto.command() == 'Linkshadow_fetch_entity_anomalies':
            # print ("Linkshadow_fetch_entity_anomalies")
            return_results(fetch_entity_anomalies(client,demisto.args()))
    except:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error('Failed to execute {demisto.command()} command')

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
