import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import requests
import json
from datetime import datetime

# Possibly Needed
import urllib3
import urllib.parse
import base64

''' Global Params '''
base_url = "https://portal.auscert.org.au/api/"
incident_url = "msins/v1/search"
fetch_url = "msins/v1/get?msin_id="
indicator_url = "v1/malurl/"


def fetch_incidents(api_key: str) -> list:
    url = base_url + incident_url
    headers = {'API-Key': api_key}
    # Determine last run timestamp (if any)
    last_run = demisto.getLastRun()  # A dict - might be empty
    print_debug_msg(f'[1] {last_run=}')
    if not last_run:
        start_time = 3
        current_epoch_time = int(time.time())
        seconds_in_a_day = 60 * 60 * 24
        start_time_epoch = current_epoch_time - (start_time * seconds_in_a_day)
        print_debug_msg(f'[2] {start_time=}')
        print_debug_msg(f'[3] {start_time_epoch=}')
    else:
        start_time_epoch = last_run.get('last_fetch_time')
        print_debug_msg(f'[3] {start_time_epoch=}')
        # Need to convert the last fetch epoch timestamp into a "days ago" format as API only supports "days ago"
        current_time = int(time.time())
        current_epoch_time = int(time.time())
        time_diff_in_seconds = current_epoch_time - start_time_epoch
        start_time = time_diff_in_seconds // (60 * 60 * 24)
        if time_diff_in_seconds < (60 * 60 * 24):
            start_time = 1

    params = {
        "age_filter": start_time

    }

    request = requests.Request("GET", url, headers=headers, params=params)
    prepared_request = request.prepare()
    res = requests.get(url, headers=headers, params=params)
    current_time = int(time.time())
    events = []
    if res.status_code == 200:
        data = res.json()
        msins_data = data.pop('msins', [])
        for entry in msins_data:
            # epoch time stamp is entry['observed_epoch_time']
            if entry['observed_epoch_time'] > start_time_epoch:
                events.append(get_full_incident(entry['id'], api_key))
    else:
        print_debug_msg(f"Error: {res.status_code}, {res.text}")

    # events needs to now be formatted appropriate before being returned to XSOAR as an incident object
    incidents = []

    collect_incident_timestamps = set()

    for event in events:
        incident = {
            'name': f'AusCERT MSIN {event[0]["id"]}',        # name is required field, must be set
            'type': 'AusCERT MSIN',
            'occurred': convert_timestamp_to_iso8601(event[0]['observed_epoch_time']),  # must be string of a format ISO8601
            'rawJSON': json.dumps(event[0])
        }
        incidents.append(incident)
        collect_incident_timestamps.add(event[0]['observed_epoch_time'])

    # Record last incicent timestamp
    if incidents:
        latest_incident_time = max(collect_incident_timestamps)
        print_debug_msg("Latest incident time:")
        print_debug_msg(latest_incident_time)
    else:
        latest_incident_time = start_time_epoch

    demisto.setLastRun({
        'last_fetch_time': latest_incident_time,
    })

    demisto.incidents(incidents)
    return []


def get_full_incident(input_id: str, api_key: str) -> dict:
    # Now need to get the full incident information for each ID
    # GET https://portal.auscert.org.au/api/msins/v1/get?[ID]
    url = base_url + fetch_url + input_id
    headers = {'API-Key': api_key}
    request = requests.get(url, headers=headers)

    if request.status_code == 200:
        data = request.json()
        return (data)
    else:
        return (print_debug_msg(f"Error: {request.status_code}, {request.text}"))


def convert_timestamp_to_iso8601(time: str) -> str:
    dt_object = datetime.fromtimestamp(time)
    iso8601_format = dt_object.isoformat()
    xsoar_format = f'{iso8601_format}.000Z'
    return (xsoar_format)


def get_combined_feed(api_key: str, time_range: int) -> dict:
    url = "https://portal.auscert.org.au/api/v1/malurl/combo-" + time_range + "-stix/"
    headers = {'API-Key': api_key}

    request = requests.get(url, headers=headers)

    if request.status_code == 200:
        data = request.content.decode()
        return_results(CommandResults(
            outputs_prefix='auscertIndicators',
            readable_output='Indicators retrieved from Combined Threat Feed',
            outputs=data
        ))
    else:
        return (print_debug_msg(f"Error: {request.status_code}, {request.text}"))


def get_mal_feed(api_key: str, time_range: int) -> dict:
    url = "https://portal.auscert.org.au/api/v1/malurl/malware-" + time_range + "-stix/"
    headers = {'API-Key': api_key}

    request = requests.get(url, headers=headers)

    if request.status_code == 200:
        data = request.content.decode()
        return_results(CommandResults(
            outputs_prefix='auscertIndicators',
            readable_output='Indicators retrieved from Malware Threat Feed',
            outputs=data
        ))
    else:
        return (print_debug_msg(f"Error: {request.status_code}, {request.text}"))


def get_phish_feed(api_key: str, time_range: int) -> dict:
    url = "https://portal.auscert.org.au/api/v1/malurl/phishing-" + time_range + "-stix/"
    headers = {'API-Key': api_key}

    request = requests.get(url, headers=headers)

    if request.status_code == 200:
        data = request.content.decode()
        return_results(CommandResults(
            outputs_prefix='auscertIndicators',
            readable_output='Indicators retrieved from Phishing Threat Feed',
            outputs=data
        ))
    else:
        return (print_debug_msg(f"Error: {request.status_code}, {request.text}"))


def print_debug_msg(msg: str) -> str:
    """
    Prints a message to debug with PAN-DLP-Msg prefix.
    Args:
        msg (str): Message to be logged.

    """
    demisto.debug(f'PAN-Debug-Msg - {msg}')


def test(api_key) -> str:
    url = base_url + incident_url
    headers = {'API-Key': api_key}
    start_time = 3
    params = {
        "age_filter": start_time

    }
    request = requests.Request("GET", url, headers=headers, params=params)
    prepared_request = request.prepare()
    res = requests.get(url, headers=headers, params=params)

    if res.status_code == 200:
        return_results("ok")
    else:
        message = f"Integration test failed"
        raise DemistoException(message)


def main():
    try:
        demisto.info(f'Command is {demisto.command()}')
        api_key = demisto.params().get('API_Key')
        api_key = api_key['password']
        params = demisto.params()
        args = demisto.args()
        time_range = args.get('time_range')

        if demisto.command() == 'fetch-incidents':
            fetch_incidents(api_key)
        elif demisto.command() == "test-module":
            test(api_key)
        elif demisto.command() == "auscert_get_combined_feed":
            get_combined_feed(api_key, time_range)
        elif demisto.command() == "auscert_get_malware_feed":
            get_mal_feed(api_key, time_range)
        elif demisto.command() == "auscert_get_phishing_feed":
            get_phish_feed(api_key, time_range)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
