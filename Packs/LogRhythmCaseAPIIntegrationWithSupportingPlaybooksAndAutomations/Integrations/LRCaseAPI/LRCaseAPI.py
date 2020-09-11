import collections
import json
import ssl

import demistomock as demisto
# author: tsteckman
# interfaces with LR-CASE-API
import requests
from CommonServerPython import *  # noqa: F401
from requests.exceptions import HTTPError

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

BASE_URL = demisto.params().get('url')
API_KEY = demisto.params().get('apikey')
URI = "/lr-case-api/"
api_string = "Bearer " + API_KEY

# Begin fetcher code
DEFAULTS = {
    'fetch_time': '10 minutes'
}

FETCH_TIME = demisto.params().get('fetch_time').strip()
TIMESTAMP_FIELD = demisto.params().get('timestamp_field', 'dateCreated')


def lr_get_alarms_from_case(case_id):
    url = BASE_URL + "/lr-case-api/cases/{}/evidence?type=alarm".format(case_id)
    headers = {"Authorization": api_string}
    result = sendrequest(url, {}, headers)
    results = []
    for alarm in result:
        results.append(alarm['alarm']['alarmId'])
    return results


def sendrequest(url, gparams, hparam):
    response = requests.get(url, headers=hparam, params=gparams, verify=False)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 202:
        return response.content
    else:
        return_error(response.content)


def fetch_incidents():
    if FETCH_TIME:
        fetch_time = FETCH_TIME
    else:
        fetch_time = DEFAULTS['fetch_time']

    last_run = demisto.getLastRun()
    if 'time' not in last_run:
        lr_time, _ = parse_date_range(fetch_time, '%Y-%m-%dT%H:%M:%SZ')

    else:
        lr_time = last_run['time']

    url = BASE_URL + "/lr-case-api/cases/"
    headers = {"Authorization": api_string, 'createdAfter': lr_time}
    opencases = sendrequest(url, {}, headers)
    opencases.sort(key=lambda x: x["dateCreated"])
    incidents = []

    for result in opencases:
        labels = []
        for k, v in result.items():
            if isinstance(v, str):
                labels.append({
                    'type': k,
                    'value': v
                })

    for case in opencases:
        related_alarms = lr_get_alarms_from_case(case["id"])
        if related_alarms is not None:
            incident = {
                "name": case['name'],
                "occured": case['dateCreated'],
                "details": json.dumps(case),
                "rawJSON": json.dumps(case),
                "CustomFields": {
                    "lrcaseid": case['id'],
                    "lrcasenumber": str(case['number']),
                    "siemid": str(case['number']),
                    "linkedalarms": str(related_alarms)[1:-1]
                }
            }
        else:
            incident = {
                "name": case['name'],
                "occured": case['dateCreated'],
                "details": json.dumps(case),
                "rawJSON": json.dumps(case),
                "CustomFields": {
                    "lrcaseid": case['id'],
                    "lrcasenumber": str(case['number']),
                    "siemid": str(case['number']),
                }
            }
        incidents.append(incident)
        lr_time = case["dateCreated"]

    demisto.incidents(incidents)
    demisto.setLastRun({'time': lr_time})


if demisto.command() == 'fetch-incidents':
    url = BASE_URL + "/lr-case-api/cases/"
    fetch_incidents()

if demisto.command() == 'lr-get-case':
    caseid = demisto.args()["caseid"]
    url = BASE_URL + "/lr-case-api/cases/"
    headers = {"Authorization": api_string}
    data = {"externalId": caseid}
    result = sendrequest(url, data, headers)
    demisto.results({'ContentsFormat': formats['json'], 'Type': entryTypes['note'],
                     'Contents': result, 'EntryContext': {"LR-Case": result}})

if demisto.command() == 'lr-get-date':
    date = demisto.args()["date"]
    url = BASE_URL + "/lr-case-api/cases/"
    headers = {"Authorization": api_string, 'createdAfter': date}
    result = sendrequest(url, {}, headers)
    demisto.results({'ContentsFormat': formats['json'], 'Type': entryTypes['note'],
                     'Contents': result, 'EntryContext': {"date-Case": result}})

# end fether code


def test_connection():
    "confirms url and api key are good, returns 404 on success"
    full_uri = URI + 'cases/0'
    headers = {
        'Content-Type': 'text/json',
        'Authorization': api_string
    }
    r = requests.request(
        "GET",
        BASE_URL + full_uri,
        headers=headers,
        verify=False)
    return r.status_code


def create_case(inc_id, name, priority):
    "creates a case with the given attributes"
    full_uri = URI + 'cases/'
    summary = 'NTTS Incident ID: ' + inc_id + '.'
    data = {"externalId": inc_id, "name": name, "priority": priority, "summary": summary}
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': api_string}
    data = json.dumps(data)
    try:
        r = requests.request(
            "POST",
            BASE_URL + full_uri,
            headers=headers,
            data=data,
            verify=False)
        if r.status_code == 200 or r.status_code == 201:
            return r.content
        else:
            return_results(r.content)
            return_error("HTTP Status Code: " + str(r.status_code))
    except HTTPError as http_err:
        return_results(f'HTTP error occurred: {http_err}')
    except Exception as err:
        return_results(f'Other error occurred: {err}')


def add_alarms_to_case(case_id, alarms):
    "adds alarms to the specified LR case"
    full_uri = URI + 'cases/' + case_id + '/evidence/alarms/'
    alarms = alarms.split(',')
    alarm_ids = []
    for alarm in alarms:
        if len(alarm) == 6:
            alarm = alarm[1:-1]
        alarm = int(alarm)
        alarm_ids.append(alarm)
    data = {"alarmNumbers": alarm_ids}
    return_results(str(data))
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': api_string}
    data = json.dumps(data)
    try:
        r = requests.request(
            "POST",
            BASE_URL + full_uri,
            headers=headers,
            data=data,
            verify=False)
        if r.status_code == 200 or r.status_code == 201:
            return r.content
        else:
            return_results(r.content)
            return_error("HTTP Status Code: " + str(r.status_code))
    except HTTPError as http_err:
        return_results(f'HTTP error occurred: {http_err}')
    except Exception as err:
        return_results(f'Other error occurred: {err}')


def lr_update_case_summary(case_id, comment):
    full_uri = URI + 'cases/' + case_id + '/'
    data = {"summary": comment}
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': api_string}
    data = json.dumps(data)
    try:
        r = requests.request(
            "PUT",
            BASE_URL + full_uri,
            headers=headers,
            data=data,
            verify=False)
        if r.status_code == 200 or r.status_code == 201:
            return r.content
        else:
            return_results(r.content)
            return_error("HTTP Status Code: " + str(r.status_code))
    except HTTPError as http_err:
        return_results(f'HTTP error occurred: {http_err}')
    except Exception as err:
        return_results(f'Other error occurred: {err}')


def lr_update_case_status(case_id, status):
    full_uri = URI + 'cases/' + case_id + '/actions/changeStatus/'
    data = {"statusNumber": int(status)}
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': api_string}
    data = json.dumps(data)
    try:
        r = requests.request(
            "PUT",
            BASE_URL + full_uri,
            headers=headers,
            data=data,
            verify=False)
        if r.status_code == 200 or r.status_code == 201:
            return r.content
        else:
            return_results(r.content)
            return_error("HTTP Status Code: " + str(r.status_code))
    except HTTPError as http_err:
        return_results(f'HTTP error occurred: {http_err}')
    except Exception as err:
        return_results(f'Other error occurred: {err}')


def lr_add_case_note(case_id, note):
    full_uri = URI + 'cases/' + case_id + '/evidence/note/'
    data = {'text': note}
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': api_string}
    data = json.dumps(data)
    try:
        r = requests.request(
            "POST",
            BASE_URL + full_uri,
            headers=headers,
            data=data,
            verify=False)
        if r.status_code == 200 or r.status_code == 201:
            return r.content
        else:
            return_results(r.content)
            return_error("HTTP Status Code: " + str(r.status_code))
    except HTTPError as http_err:
        return_results(f'HTTP error occurred: {http_err}')
    except Exception as err:
        return_results(f'Other error occurred: {err}')


def drill_down_on(alarm_id):
    api_string = "Bearer " + API_KEY
    full_uri = "/lr-drilldown-cache-api/drilldown/" + alarm_id
    headers = {
        'Content-Type': 'text/json',
        'Authorization': api_string
    }
    try:
        r = requests.request(
            "GET",
            BASE_URL + full_uri,
            headers=headers,
            verify=False)
        if r.status_code == 200 or r.status_code == 202:
            return r.content
        else:
            return_error("HTTP Status Code: " + str(r.status_code))
    except HTTPError as http_err:
        return_results(f'HTTP error occurred: {http_err}')
    except Exception as err:
        return_results(f'Other error occurred: {err}')


if demisto.command() == 'test-module':
    result = test_connection()
    if result == 404:
        return_results('ok')
    else:
        return_results('Status code: ' + str(result))
if demisto.command() == 'lr-create-case':
    inc_id = demisto.args().get('inc_id')
    name = demisto.args().get('name')
    priority = int(demisto.args().get('priority'))
    result = create_case(inc_id, name, priority)
    result = json.loads(result)
    results = CommandResults(
        outputs_prefix='LogRhythm.Case',
        outputs_key_field='id',
        outputs=result
    )
    return_results(results)
    results = CommandResults(
        outputs_prefix='LogRhythm.Case',
        outputs_key_field='number',
        outputs=result
    )
    return_results(results)
if demisto.command() == 'lr-add-alarms-to-case':
    case_id = demisto.args().get('case_id')
    alarms = demisto.args().get('alarms')
    result = add_alarms_to_case(case_id, alarms)
    result = json.loads(result)
    demisto.results(
        {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'HumanReadable': tableToMarkdown('It is done.', result)
        }
    )
if demisto.command() == 'lr-update-case-summary':
    case_id = demisto.args().get('case_id')
    comment = demisto.args().get('comment')
    result = lr_update_case_summary(case_id, comment)
    result = json.loads(result)
    demisto.results(
        {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'HumanReadable': tableToMarkdown('Comment(s) added to Case.', result)
        }
    )
if demisto.command() == 'lr-add-case-note':
    case_id = demisto.args().get('case_id')
    note = demisto.args().get('note')
    result = lr_add_case_note(case_id, note)
    result = json.loads(result)
    demisto.results(
        {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'HumanReadable': tableToMarkdown('Comment(s) added to Case.', result)
        }
    )
if demisto.command() == 'lr-update-case-status':
    case_id = demisto.args().get('case_id')
    status = demisto.args().get('status')
    result = lr_update_case_status(case_id, status)
    result = json.loads(result)
    demisto.results(
        {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'HumanReadable': tableToMarkdown('Case status updated.', result)
        }
    )
if demisto.command() == 'lr-drilldown-on':
    alarm_id = demisto.args().get('id')
    result = drill_down_on(alarm_id)
    result = json.loads(result)
    result = result['Data']['DrillDownResults']
    demisto.results(
        {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'HumanReadable': tableToMarkdown('One who seeks shall also find...', result)
        }
    )
