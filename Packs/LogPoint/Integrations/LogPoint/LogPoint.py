import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''


import requests
import json
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

LPDATACONTEXT = 'Logpoint-SIEM'
DEFAULTCONTEXT = 'Account'
ALLOWEDDATA = '/getalloweddata'
SEARCHDATA = '/getsearchlogs'

'''new for 6.7 incidents api'''
INCIDENTS = '/incidents'
INCIDENTSTATES = '/incident_states'
SINGLEINCIDENT = '/get_data_from_incident'
ADDCOMMENTS = '/add_incident_comment'
ASSIGNINCIDENT = '/assign_incident'
RESOLVEINCIDENT = '/resolve_incident'
CLOSEINCIDENT = '/close_incident'
REOPENINCIDENT = '/reopen_incident'
USERSURL = '/get_users'
URLSIN67 = [INCIDENTS, INCIDENTSTATES, SINGLEINCIDENT, ADDCOMMENTS,
            ASSIGNINCIDENT, RESOLVEINCIDENT, CLOSEINCIDENT, REOPENINCIDENT, USERSURL]

METHOD = 'POST'
INCIDENTMETHOD = 'GET'

''' CLASS for Logpoint'''


class Client:
    def __init__(self, basedata, base_url, verify, proxies):
        self.basedata = basedata
        self.base_url = base_url
        self.verify = verify
        self.proxies = proxies

    def http_request(self, method, url_suffix, data=None):
        self.basedata.update(data)
        server = self.base_url + url_suffix
        res = requests.request(
            method,
            server,
            verify=self.verify,
            json=self.basedata if url_suffix in URLSIN67 else None,
            data=self.basedata if url_suffix not in URLSIN67 else None,
            proxies=self.proxies
        )
        if res.status_code != 200:
            raise ValueError(f'Error in API call to Logpoint {res.status_code}. Reason: {res.text}')
        try:
            return res.json()
        except Exception:
            raise ValueError(f"Failed to parse http response to JSON format. Original response body: \n{res.text}")


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client):
    """
        Performs basic get request to get user timezone as a test
        """
    response = client.http_request('POST', ALLOWEDDATA, {"type": "user_preference"})
    # test was successful
    if response['success']:
        return 'ok'
    else:
        return 'Failure'


def results_return(titletoreturn, thingtoreturn, datapointtoreturnat):
    finaldata = {}
    finaldata[datapointtoreturnat] = thingtoreturn
    return demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': thingtoreturn,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(titletoreturn, thingtoreturn, removeNull=True),
        'EntryContext': finaldata
    })


def results_return_account(titletoreturn, thingtoreturn, datapointtoreturnat):
    finaldata = {}
    datalist = []
    for item in thingtoreturn['users']:
        tempdata = {}
        tempdata['Type'] = 'Logpoint'
        tempdata['Groups'] = item['usergroups']
        tempdata['ID'] = item['id']
        tempdata['Name'] = item['name']
        datalist.append(tempdata)
    finaldata[datapointtoreturnat] = datalist
    return demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': finaldata,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(titletoreturn, finaldata, removeNull=True),
        'EntryContext': finaldata
    })


def get_and_return(method, client, incoming_data, command, titletoprint, url_suffix):
    response = client.http_request(method, url_suffix, incoming_data)
    if response['success']:
        if command == 'Get all users':
            results_return_account(titletoprint, response, DEFAULTCONTEXT)
        else:
            results_return(titletoprint, response, LPDATACONTEXT)
    else:
        return demisto.results("Error in command: " + command + " response from server was: " + str(response))


def get_user_timezone(client, args):
    title = 'User timezone details'
    command = 'Get User Timezone'
    data = {"type": "user_preference"}
    get_and_return(METHOD, client, data, command, title, ALLOWEDDATA)


def get_logpoints(client, args):
    title = 'Logpoints'
    command = 'Get Logpoints'
    data = {"type": "loginspects"}
    get_and_return(METHOD, client, data, command, title, ALLOWEDDATA)


def get_repos(client, args):
    title = 'Repos'
    command = 'Get Repos'
    data = {"type": "logpoint_repos"}
    get_and_return(METHOD, client, data, command, title, ALLOWEDDATA)


def get_devices(client, args):
    title = 'Devices'
    command = 'Get Devices'
    data = {"type": "devices"}
    get_and_return(METHOD, client, data, command, title, ALLOWEDDATA)


def get_livesearches(client, args):
    title = 'Live Searches'
    command = 'Get Live Searches'
    data = {"type": "livesearches"}
    get_and_return(METHOD, client, data, command, title, ALLOWEDDATA)


def get_livesearchresults(client, args):
    data = {}
    lifeid = args.get('life-id')
    command = 'Get Live Search results'
    title = 'Live Search results for ' + lifeid
    data_original = {"type": "livesearches", "search_id": lifeid, "waiter_id": "foobar", "seen_version": "1"}
    data["requestData"] = json.dumps(data_original)
    get_and_return(METHOD, client, data, command, title, SEARCHDATA)


def search_logs(client, args):
    data = {}
    command = 'Search'
    query = args.get('query')
    repo = args.get('repo')
    timeout = args.get('timeout')
    client_name = args.get('client_name')
    limit = args.get('limit')
    timerange = args.get('time-range')
    title = 'Search'
    data_original = {"timeout": timeout, "limit": limit, "query": query, "repos": [repo],
                     "client_name": client_name, "time_range": timerange}
    data["requestData"] = json.dumps(data_original)
    get_and_return(METHOD, client, data, command, title, SEARCHDATA)


def search_results(client, args):
    data = {}
    command = 'Search results'
    search_id = args.get('searchId')
    title = 'Search results'
    data_original = {"searchId": search_id, "waiter_id": 'foobar', "seen_version": '1'}
    data["requestData"] = json.dumps(data_original)
    get_and_return(METHOD, client, data, command, title, SEARCHDATA)


'''NEW STUFF FOR 6.7'''


def get_incidents(client, args):
    command = 'Get Incidents'
    timestampfrom = args.get('TimeStampFrom')
    timestampto = args.get('TimeStampTo')
    title = 'Get Incidents'
    data_original = {
        "requestData": {
            "version": '0.1',
            "ts_from": timestampfrom,
            "ts_to": timestampto
        }
    }
    get_and_return(INCIDENTMETHOD, client, data_original, command, title, INCIDENTS)


def get_incident_states(client, args):
    command = 'Get Incident States'
    timestampfrom = args.get('TimeStampFrom')
    timestampto = args.get('TimeStampTo')
    title = 'Get Incident States'
    data_original = {
        "requestData": {
            "version": '0.1',
            "ts_from": timestampfrom,
            "ts_to": timestampto
        }
    }
    get_and_return(INCIDENTMETHOD, client, data_original, command, title, INCIDENTSTATES)


def get_single_incident(client, args):
    command = 'Get Incident info'
    incident_obj_id = args.get('IncidentObjectID')
    incident_id = args.get('IncidentId')
    date = args.get('Date')
    title = 'Get Single Incident'
    data_original = {
        "requestData": {
            "incident_obj_id": incident_obj_id,
            "incident_id": incident_id,
            "date": date
        }
    }
    get_and_return(INCIDENTMETHOD, client, data_original, command, title, SINGLEINCIDENT)


def add_comments_to_incident(client, args):
    command = 'Adding comments to incident'
    incident_id = args.get('id')
    comment = args.get('comments')
    title = 'Adding comments to incident'
    data_original = {
        "requestData": {
            "version": '0.1',
            "states": [{"_id": incident_id, "comments": [comment]}]
        }
    }
    get_and_return(METHOD, client, data_original, command, title, ADDCOMMENTS)


def assign_incident(client, args):
    command = 'Assign Incident'
    incident_id = args.get('id')
    newassignee = args.get('new_assignee')
    title = 'New Assignee'
    data_original = {
        "requestData": {
            "version": '0.1',
            "incident_ids": [incident_id],
            "new_assignee": newassignee
        }
    }
    get_and_return(METHOD, client, data_original, command, title, ASSIGNINCIDENT)


def resolve_incident(client, args):
    command = 'Resolve Incident'
    incident_id = args.get('id')
    title = 'Resolve Incident'
    data_original = {
        "requestData": {
            "version": '0.1',
            "incident_ids": [incident_id],
        }
    }
    get_and_return(METHOD, client, data_original, command, title, RESOLVEINCIDENT)


def close_incident(client, args):
    command = 'Close Incident'
    incident_id = args.get('id')
    title = 'Close Incident'
    data_original = {
        "requestData": {
            "version": '0.1',
            "incident_ids": [incident_id],
        }
    }
    get_and_return(METHOD, client, data_original, command, title, CLOSEINCIDENT)


def reopen_incident(client, args):
    command = 'Reopen Incident'
    incident_id = args.get('id')
    title = 'Reopen Incident'
    data_original = {
        "requestData": {
            "version": '0.1',
            "incident_ids": [incident_id],
        }
    }
    get_and_return(METHOD, client, data_original, command, title, REOPENINCIDENT)


def get_users(client, args):
    command = 'Get all users'
    title = 'Users'
    data_original = {'a': 'a'}
    data_original = {}
    get_and_return(INCIDENTMETHOD, client, data_original, command, title, USERSURL)


def fetch_incidents(client):
    timefrom = demisto.params().get('queryStartTime')
    timestampfrom = int(datetime.strptime(timefrom, '%Y-%m-%dT%H:%M:%SZ').timestamp())
    timestampto = int(datetime.now().timestamp())
    lastrun = demisto.getLastRun()
    typeofincidents = demisto.params().get('incindenttypetoget')
    try:
        if lastrun['time']:
            data_original = {
                "requestData": {"version": '0.1', "ts_from": lastrun['time'], "ts_to": timestampto}
            }
            response = client.http_request(INCIDENTMETHOD, INCIDENTS, data_original)
            if response['success']:
                demisto.setLastRun({'time': timestampto})
                return form_incindents(response['incidents'], typeofincidents)
            else:
                return demisto.results("Error in fetching incidents. Error from server was: " + str(response))
    except Exception:
        data_original = {
            "requestData": {
                "version": '0.1',
                "ts_from": timestampfrom,
                "ts_to": timestampto
            }
        }
        response = client.http_request(INCIDENTMETHOD, INCIDENTS, data_original)
        if response['success']:
            demisto.setLastRun({'time': timestampto})
            return form_incindents(response['incidents'], typeofincidents)
        else:
            return demisto.results("Error in fetching incidents. Error from server was: " + str(response))


def create_incident_from_lpincident(lpincident):
    occured = datetime.fromtimestamp(lpincident['detection_timestamp']).strftime('%Y-%m-%dT%H:%M:%SZ')
    keys = lpincident.keys()
    labels = []
    for key in keys:
        labels.append({'type': key, 'value': str(lpincident[key])})
        formatted_description = re.sub(r'\s\n', ' ',
                                       lpincident['name']).replace('\n', ' ') if lpincident['name'] else ''
    return {
        'name': '{id} {description}'.format(id=lpincident['id'], description=formatted_description),
        'labels': labels,
        'rawJSON': json.dumps(lpincident),
        'occurred': occured
    }


def form_incindents(incidents, typetoget):
    returnableincidents = []
    for incident in incidents:
        if typetoget == 'all':
            returnableincidents.append(create_incident_from_lpincident(incident))
        elif typetoget == incident['status']:
            returnableincidents.append(create_incident_from_lpincident(incident))
    return returnableincidents


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    token = demisto.params().get('token')
    baseserver = demisto.params()['url'][:-1] \
        if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
    verify_certificate = not demisto.params().get('insecure', False)
    username = demisto.params().get('Username')
    basedata = {
        "username": username,
        "secret_key": token
    }
    proxies = handle_proxy()

    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        client = Client(basedata, baseserver, verify_certificate, proxies)
        commands = {
            'lp-get-user-timezone': get_user_timezone,
            'lp-get-logpoints': get_logpoints,
            'lp-get-repos': get_repos,
            'lp-get-devices': get_devices,
            'lp-get-livesearches': get_livesearches,
            'lp-get-livesearch-results': get_livesearchresults,
            'lp-search': search_logs,
            'lp-search-results': search_results,
            'lp-get-incidents': get_incidents,
            'lp-get-single-incident': get_single_incident,
            'lp-get-incident-states': get_incident_states,
            'lp-add-comment-to-incident': add_comments_to_incident,
            'lp-assign-incident': assign_incident,
            'lp-resolve-incident': resolve_incident,
            'lp-close-incident': close_incident,
            'lp-reopen-incident': reopen_incident,
            'lp-get-all-users': get_users
        }
        if command == 'test-module':
            results = test_module(client)
            return_outputs(results)
        elif demisto.command() == 'fetch-incidents':
            demisto.incidents(fetch_incidents(client))
        elif command in commands:
            commands[command](client, demisto.args())
    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
