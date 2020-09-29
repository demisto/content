import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]
# IMPORTS

from typing import Tuple, Dict, Any
import json
import requests
import dateparser
import zipfile
import io

# Disable insecure warnings

requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'
DEFAULT_HEADERS_POST_REQUEST = {'accept': 'application/json;charset=UTF-8',
                                'Content-Type': 'application/json;charset=UTF-8'}


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def get_deceptive_users(self, user_type):
        url_suffix = '/api/v1/deceptive-entities/users?deceptive_user_type={}'.format(user_type)
        return self._http_request("GET", url_suffix=url_suffix)

    def get_deceptive_serves(self, server_type):
        url_suffix = '/api/v1/deceptive-entities/servers?deceptive_server_type={}'.format(server_type)
        return self._http_request("GET", url_suffix=url_suffix)

    def add_deceptive_users(self, body):
        url_suffix = '/api/v1/deceptive-entities/users'
        return self._http_request('POST', url_suffix=url_suffix, data=json.dumps(body), ok_codes=(200,))

    def add_deceptive_servers(self, body):
        url_suffix = '/api/v1/deceptive-entities/servers'
        return self._http_request('POST', url_suffix=url_suffix, data=json.dumps(body), ok_codes=(200,))

    def assign_host_to_policy(self, policy_name, body):
        url_suffix = '/api/v1/policy/domain_hosts/assign?policy_name={}'.format(policy_name)
        return self._http_request('POST', url_suffix=url_suffix, data=json.dumps(body), ok_codes=(200,))

    def remove_host_from_policy(self, body):
        url_suffix = '/api/v1/policy/domain_hosts/remove_assignment'
        return self._http_request('POST', url_suffix=url_suffix, data=json.dumps(body), ok_codes=(200,))

    def get_forensics_timeline(self, incident_id, start_date, end_date):
        url_suffix = '/api/v1/forensics/timeline?incident_id={}'.format(incident_id)
        if end_date:
            url_suffix += "&end_date={}".format(end_date)
        if start_date:
            url_suffix += "&start_date={}".format(start_date)
        return self._http_request("GET", url_suffix=url_suffix, ok_codes=(200,))

    def get_asm_host_insight(self, hostname_or_ip):
        url_suffix = '/api/v1/attack-surface/machine-insights?hostNameOrIp={}'.format(hostname_or_ip)
        return self._http_request("GET", url_suffix=url_suffix)

    def get_asm_cj_insight(self):
        url_suffix = '/api/v1/crownjewels/insights'
        return self._http_request("GET", url_suffix=url_suffix)

    def run_forensics_on_demand(self, hostname_or_ip):
        url_suffix = '/api/v1/event/create-external-event?hostNameOrIp={}'.format(hostname_or_ip)
        return self._http_request("POST", url_suffix=url_suffix)

    def is_deceptive_user(self, username):
        url_suffix = '/api/v1/deceptive-entities/user?userName={}'.format(username)
        return self._http_request("GET", url_suffix=url_suffix, resp_type='text')

    def is_deceptive_server(self, hostname):
        url_suffix = '/api/v1/deceptive-entities/server?hostName={}'.format(hostname)
        return self._http_request("GET", url_suffix=url_suffix, resp_type='text')

    def delete_deceptive_users(self, deceptive_users):
        url_suffix = '/api/v1/deceptive-entities/users'
        url_suffix += "?deceptive_users=" + '&deceptive_users='.join(deceptive_users)
        return self._http_request("DELETE", url_suffix=url_suffix, resp_type='text')

    def delete_deceptive_servers(self, deceptive_servers):
        url_suffix = '/api/v1/deceptive-entities/servers'
        url_suffix += "?deceptive_hosts=" + '&deceptive_hosts='.join(deceptive_servers)
        return self._http_request("DELETE", url_suffix=url_suffix, resp_type='text')

    def get_incident(self, incident_id):
        url_suffix = '/api/v2/incidents/incident?incident_id={}'.format(incident_id)
        return self._http_request("GET", url_suffix=url_suffix)

    def get_event_incident_id(self, event_id):
        url_suffix = '/api/v1/incidents/id?event_id={}'.format(event_id)
        return self._http_request("GET", url_suffix=url_suffix, ok_codes=(200,))

    def list_all_incidents(self, has_forensics, host_names, limit, offset, start_date):
        url_suffix = '/api/v1/incidents?limit={}&offset={}'.format(limit, offset)
        if has_forensics is not None:
            url_suffix += "&has_forensics={}".format(has_forensics)
        if start_date:
            url_suffix += "&start_date={}".format(start_date)
        if host_names:
            url_suffix += "&host_names=" + '&host_names='.join(host_names)
        return self._http_request("GET", url_suffix=url_suffix)

    def test_configuration(self):
        url_suffix = '/api/v1/incidents?limit=10&offset=0'
        return self._http_request("GET", url_suffix=url_suffix, ok_codes=(200,))

    def get_incident_events(self, incident_id, limit, offset):
        url_suffix = '/api/v1/incidents/events?incident_id={}&limit={}&offset={}'.format(incident_id, limit, offset)
        return self._http_request("GET", url_suffix=url_suffix)

    def get_forensics_artifacts(self, event_id, artifact_type):
        url_suffix = '/api/v1/forensics/artifacts?event_id={}&artifacts_type={}'.format(event_id, artifact_type)
        return self._http_request("GET", url_suffix=url_suffix, resp_type="content")

    def get_forensics_analyzers(self, event_id):
        url_suffix = '/api/v1/forensics/analyzers?event_id={}'.format(event_id)
        return self._http_request("GET", url_suffix=url_suffix)

    def get_forensics_triggering_process_info(self, event_id):
        url_suffix = '/api/v1/forensics/triggering_process_info?event_id={}'.format(event_id)
        return self._http_request("GET", url_suffix=url_suffix, ok_codes=(200,))


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: Illusive Networks client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        client.test_configuration()
        return 'ok'
    except DemistoException as e:
        if "401" in e.args[0]:
            return "Test failed, potential reasons might be that the API KEY parameter is incorrect: {}".format(e.args[0])
        else:
            return "Test failed: {}".format(e.args[0])


def fetch_incidents(client, last_run, first_fetch_time, has_forensics):
    """
    This function will execute each interval (default is 1 minute).
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_run')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)

    latest_created_time = last_fetch
    incidents = []
    items = client.list_all_incidents(has_forensics, None, limit=10, offset=0, start_date=latest_created_time)
    for item in items:
        incident_created_time = item['incidentTimeUTC']
        incident_type = 'None'
        if len(item['incidentTypes']) > 0:
            incident_type = str(item['incidentTypes'][0])
        incident = {
            'name': "Illusive Attack Management detected an incident of type " + incident_type,
            'occurred': (dateparser.parse(incident_created_time)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(item)
        }
        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_run': latest_created_time}
    return next_run, incidents


def get_deceptive_users_command(client: Client, args: dict) -> Tuple:
    user_type = args.get("type", "ALL")
    try:
        result = client.get_deceptive_users(user_type)
    except DemistoException as e:
        if "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))

    readable_output = tableToMarkdown('Illusive Deceptive Users', result)
    outputs = {
        'Illusive.DeceptiveUser(val.userName == obj.userName)': result
    }
    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def get_deceptive_servers_command(client: Client, args: dict) -> Tuple:
    server_type = args.get("type", "ALL")
    try:
        result = client.get_deceptive_serves(server_type)
    except DemistoException as e:
        if "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))
    readable_output = tableToMarkdown('Illusive Deceptive Servers', result)
    outputs = {
        'Illusive.DeceptiveServer(val.host == obj.host)': result
    }
    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def add_deceptive_users_command(client: Client, args: dict) -> Tuple:
    user_name = args.get("username", None)
    domain_name = args.get("domain_name", None)
    password = args.get("password", None)
    policy_names = argToList(args.get('policy_names'))

    request_body = [
        {'domainName': domain_name, 'password': password, 'policyNames': policy_names, 'username': user_name}]
    try:
        client.add_deceptive_users(request_body)
    except DemistoException as e:
        if "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))

    result = {
        'userName': user_name,
        'domainName': domain_name,
        'policyNames': "All Policies" if policy_names == [] else policy_names,
        'password': password
    }
    readable_output = tableToMarkdown('Illusive Add Deceptive User Succeeded', result)
    outputs = {
        'Illusive.DeceptiveUser(val.userName == obj.userName)': result
    }
    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def add_deceptive_servers_command(client: Client, args: dict) -> Tuple:
    host_name = args.get("host", "")  # must be <host>.<domain>
    service_types = argToList(args.get("service_types"))
    policy_names = argToList(args.get('policy_names'), "All Policies")

    if len(host_name.split('.')) < 2:
        raise DemistoException("host name must have the following pattern: <host>.<domain>")

    request_body = [{'host': host_name, 'serviceTypes': service_types, 'policyNames': policy_names}]
    try:
        client.add_deceptive_servers(request_body)
    except DemistoException as e:
        if "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))

    result = {
        'host': host_name,
        'serviceTypes': service_types,
        'policyNames': "All Policies" if policy_names == [] else policy_names
    }
    readable_output = tableToMarkdown('Illusive Add Deceptive Server Succeeded', result)
    outputs = {
        'Illusive.DeceptiveServer(val.host == obj.host)': result
    }
    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def assign_host_to_policy_command(client: Client, args: dict) -> Tuple:
    policy_name = args.get("policy_name", None)
    host_names = argToList(args.get("hosts"))
    host_names = host_names[:1000]
    request_body = []
    for host_name in host_names:
        host_name_split = host_name.split('@')
        if len(host_name_split) != 2:
            raise Exception('bad hostname format: {}. Should be  <machineName>@<domainName> '.format(host_name))
        request_body.append({"machineName": host_name_split[0], "domainName": host_name_split[1]})
    try:
        client.assign_host_to_policy(policy_name, request_body)
    except DemistoException as e:
        if "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))
    result = []
    for host in host_names:
        result.append({
            'isAssigned': True,
            'hosts': host,
            'policy_name': policy_name
        })

    readable_output = tableToMarkdown('Illusive Assign Machines to Policy Succeeded', result)
    outputs = {
        'Illusive.DeceptionPolicy.isAssigned(val.hosts == obj.hosts)': result
    }
    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def remove_host_from_policy_command(client: Client, args: dict) -> Tuple:
    host_names = argToList(args.get("hosts"))
    host_names = host_names[:1000]
    request_body = []
    for host_name in host_names:
        host_name_split = host_name.split('@')
        if len(host_name_split) != 2:
            raise Exception('bad hostname format: {}. Should be  <machineName>@<domainName> '.format(host_name))
        request_body.append({"machineName": host_name_split[0], "domainName": host_name_split[1]})
    try:
        client.remove_host_from_policy(request_body)
    except DemistoException as e:
        if "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))

    result = []
    for host in host_names:
        result.append({
            'isAssigned': False,
            'hosts': host,
            'policy_name': ""})

    readable_output = tableToMarkdown('Illusive Remove Machines from All Policies Succeeded', result)
    outputs = {
        'Illusive.DeceptionPolicy.isAssigned(val.hosts == obj.hosts)': result
    }
    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def get_forensics_timeline_command(client: Client, args: dict) -> Tuple:
    incident_id = args.get("incident_id")
    start_date = args.get("start_date", None)
    end_date = args.get("end_date", None)
    if start_date:
        start_date, _ = parse_date_range(start_date, date_format=DATE_FORMAT, utc=True)
    if end_date:
        end_date, _ = parse_date_range(end_date, date_format=DATE_FORMAT, utc=True)

    try:
        result = client.get_forensics_timeline(incident_id, start_date, end_date)
        for evidence in result:
            evidence['date'] = evidence.get('details').get('date')
        readable_output = tableToMarkdown('Illusive Forensics Timeline', result)
        outputs = {
            'Illusive.Forensics(val.IncidentId == obj.IncidentId)': {
                'IncidentId': incident_id,
                'Status': 'Done',
                'Evidence': result
            }
        }
    except DemistoException as e:
        if "404" in e.args[0]:
            raise DemistoException("Incident id {} doesn't not exist".format(incident_id))
        elif "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        elif "202" in e.args[0]:
            readable_output = "Incident id {} hasn't been closed yet".format(incident_id)
            outputs = {
                'Illusive.Forensics(val.IncidentId == obj.IncidentId)': {
                    'IncidentId': incident_id,
                    'Status': 'InProgress',
                    'Evidence': []
                }
            }
            result = []
        else:
            raise DemistoException("{}".format(e.args[0]))

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def get_asm_host_insight_command(client: Client, args: dict) -> Tuple:
    hostname_or_ip = args.get("hostnameOrIp", None)
    try:
        result = client.get_asm_host_insight(hostname_or_ip)
    except DemistoException as e:
        if "404" in e.args[0]:
            result = []
        elif "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))
    readable_output = tableToMarkdown('Illusive ASM Host Insights', result)
    outputs = {
        'Illusive.AttackSurfaceInsightsHost(val.ipAddresses == obj.ipAddresses)': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def get_asm_cj_insight_command(client: Client, args: dict) -> Tuple:
    try:
        result = client.get_asm_cj_insight()
    except DemistoException as e:
        if "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))
    readable_output = tableToMarkdown('Illusive ASM Crown Jewels Insights', result)
    outputs = {
        'Illusive.AttackSurfaceInsightsCrownJewel(val.hostname == obj.hostname)': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def run_forensics_on_demand_command(client: Client, args: dict) -> Tuple:
    fqdn_or_ip = args.get("fqdn_or_ip", None)
    try:
        result = client.run_forensics_on_demand(fqdn_or_ip)
    except DemistoException as e:
        if "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))
    readable_output = tableToMarkdown('Illusive Run Forensics On Demand', result)
    outputs = {
        'Illusive.Event(val.eventId == obj.eventId)': result
    }
    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def is_deceptive_user_command(client: Client, args: dict) -> Tuple:
    username = args.get("username", None)
    is_deceptive_user = False
    is_deceptive_user = True if client.is_deceptive_user(username) else is_deceptive_user
    result = {
        'Username': username,
        'IsDeceptiveUser': is_deceptive_user
    }
    readable_output = tableToMarkdown('Illusive Is Deceptive', result)
    outputs = {
        'Illusive.IsDeceptive(val.Username == obj.Username)': result
    }
    return (
        readable_output,
        outputs,
        None  # raw response - the original response
    )


def is_deceptive_server_command(client: Client, args: dict) -> Tuple:
    hostname = args.get("hostname", None)
    is_deceptive_server = False
    is_deceptive_server = True if client.is_deceptive_server(hostname) else is_deceptive_server
    result = {
        'Hostname': hostname,
        'IsDeceptiveServer': is_deceptive_server
    }
    readable_output = tableToMarkdown('Illusive Is Deceptive', result)
    outputs = {
        'Illusive.IsDeceptive(val.Hostname == obj.Hostname)': result
    }
    return (
        readable_output,
        outputs,
        None  # raw response - the original response
    )


def delete_deceptive_users_command(client: Client, args: dict) -> Tuple:
    deceptive_users = argToList(args.get('deceptive_users'))
    try:
        client.delete_deceptive_users(deceptive_users)
    except DemistoException as e:
        if "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))
    if len(deceptive_users) > 1:
        a, b = "s", "were"
    else:
        a, b = "", "was"
    result = f' {"Deceptive User{} {} {} successfully Deleted".format(a, deceptive_users, b)}'
    readable_output = f'## {result}'

    outputs: Dict[str, Any] = {
    }
    return (
        readable_output,
        outputs,
        None  # raw response - the original response
    )


def delete_deceptive_servers_command(client: Client, args: dict) -> Tuple:
    deceptive_servers = argToList(args.get('deceptive_hosts'))
    try:
        client.delete_deceptive_servers(deceptive_servers)
    except DemistoException as e:
        if "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))

    if len(deceptive_servers) > 1:
        a, b = "s", "were"
    else:
        a, b = "", "was"
    result = f' {"Deceptive Server{} {} {} successfully Deleted".format(a, deceptive_servers, b)}'
    readable_output = f'## {result}'

    outputs: Dict[str, Any] = {
    }
    return (
        readable_output,
        outputs,
        None  # raw response - the original response
    )


def get_incidents_command(client: Client, args: dict) -> Tuple:
    incident_id = args.get("incident_id")
    has_forensics = args.get("has_forensics", None)
    host_names = argToList(args.get('host_names'))
    limit = args.get("limit", 10)
    offset = args.get("offset", 0)
    start_date = args.get("start_date", None)
    if start_date:
        start_date, _ = parse_date_range(start_date, date_format=DATE_FORMAT, utc=True)
    try:
        if incident_id:
            incident = client.get_incident(incident_id)
        else:
            limit = "100" if int(limit) > 100 else limit
            incident = client.list_all_incidents(has_forensics, host_names, limit, offset, start_date)
    except DemistoException as e:
        if "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))

    readable_output = tableToMarkdown('Illusive Incidents', incident)
    outputs = {
        'Illusive.Incident(val.incidentId == obj.incidentId)': incident
    }
    return (
        readable_output,
        outputs,
        incident  # raw response - the original response
    )


def get_event_incident_id_command(client: Client, args: dict) -> Tuple:
    event_id = int(args.get("event_id", None))
    status = "Done"
    try:
        incident = client.get_event_incident_id(event_id)
    except DemistoException as e:
        if "404" in e.args[0]:
            raise DemistoException("Event id {} doesn't not exist".format(event_id))
        elif "202" in e.args[0]:
            incident = "-"
            status = "InProgress"
        elif "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))
    result = [{
        'eventId': event_id,
        'incidentId': incident,
        'status': status
    }]
    outputs = {
        'Illusive.Event(val.eventId == obj.eventId)': result
    }
    readable_output = tableToMarkdown('Illusive Get Incident', result)

    return (
        readable_output,
        outputs,
        None  # raw response - the original response
    )


def get_incident_events_command(client: Client, args: dict) -> Tuple:
    incident_id = args.get("incident_id", 0)
    limit = args.get("limit", 100)
    limit = "1000" if int(limit) > 1000 else limit
    offset = args.get("offset", 0)
    try:
        events = client.get_incident_events(incident_id, limit, offset)
    except DemistoException as e:
        if "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))

    readable_output = tableToMarkdown('Illusive get incident\'s events', events, metadata="Number of events {}"
                                      .format(len(events)))

    outputs = {
        'Illusive.Incident(val.incidentId == obj.incidentId)': {
            'eventsNumber': len(events),
            'incidentId': int(incident_id),
            'Event': events
        }
    }
    return (
        readable_output,
        outputs,
        events  # raw response - the original response
    )


def get_forensics_analyzers_command(client: Client, args: dict) -> Tuple:
    event_id = args.get("event_id", 0)
    try:
        analyzers = client.get_forensics_analyzers(event_id)
        incident = client.get_event_incident_id(event_id)
    except DemistoException as e:
        if "404" in e.args[0]:
            raise DemistoException("Event id {} doesn't not exist".format(event_id))
        elif "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))

    outputs = {
        'Illusive.Event(val.eventId == obj.eventId)': {
            'eventId': int(event_id),
            'incidentId': int(incident),
            'ForensicsAnalyzers': analyzers
        }
    }

    readable_output = tableToMarkdown('Illusive Forensics Analyzers', analyzers)

    return (
        readable_output,
        outputs,
        incident  # raw response - the original response
    )


def get_forensics_triggering_process_info_command(client: Client, args: dict) -> Tuple:
    event_id = args.get("event_id")
    try:
        processes = client.get_forensics_triggering_process_info(event_id)
    except DemistoException as e:
        if "404" in e.args[0]:
            raise DemistoException("failed to get forensics for Event id {}".format(event_id))
        elif "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))

    readable_output = tableToMarkdown('Illusive Triggering Processes Info', processes.get('processes'))
    outputs = {
        'Illusive.Event(val.eventId == obj.eventId)': {
            'eventId': event_id,
            'ForensicsTriggeringProcess': processes.get('processes')
        }
    }

    return (
        readable_output,
        outputs,
        readable_output  # raw response - the original response
    )


def get_forensics_artifacts_command(client: Client, args: dict) -> Tuple:
    event_id = args.get("event_id")
    artifact_type = args.get("artifact_type", "DESKTOP_SCREENSHOT")
    try:
        client.get_event_incident_id(event_id)  # this request is for checking the event exists
        artifact = client.get_forensics_artifacts(event_id, artifact_type)
    except DemistoException as e:
        if "404" in e.args[0]:
            raise DemistoException("failed to get forensics for Event id {}".format(event_id))
        elif "429" in e.args[0]:
            raise DemistoException(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise DemistoException("{}".format(e.args[0]))

    if len(artifact) == 0:
        return [], []

    zip_file = zipfile.ZipFile(io.BytesIO(artifact))
    file_results = []
    file_names = []
    i = 0
    for info in zip_file.infolist():
        i = i + 1
        file_results.append(fileResult(
            filename=f'eventId_{event_id}_{artifact_type}_{i}.jpg',
            data=zip_file.read(info.filename),
            file_type=entryTypes["image"]
        ))
        file_names.append(f'eventId_{event_id}_{artifact_type}_{i}.jpg')
    return file_results, file_names


def link_forensics_artifacts_name_command(file_names, client: Client, args: dict) -> CommandResults:
    event_id = args.get("event_id", 0)

    if len(file_names) > 0:
        outputs = {
            'eventId': int(event_id),
            'Artifacts': file_names
        }

        return CommandResults(
            outputs_prefix='Illusive.Event',
            outputs_key_field='eventId',
            outputs=outputs
        )
    else:
        readable_output = f'### event id {event_id} has no artifacts'

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='Illusive.Event',
            outputs_key_field='eventId',
            outputs={'eventId': int(event_id)}
        )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API token
    api_token = demisto.params().get('api_token')
    has_forensics = demisto.params().get('has_forensics')
    has_forensics = None if has_forensics == "ALL" else has_forensics

    # get the service API url
    base_url = demisto.params()['url']

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '7 days').strip().lower()

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        headers = DEFAULT_HEADERS_POST_REQUEST
        headers["Authorization"] = api_token
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                has_forensics=has_forensics)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'illusive-get-forensics-timeline':
            return_outputs(*get_forensics_timeline_command(client, demisto.args()))

        elif demisto.command() == 'illusive-get-asm-host-insight':
            return_outputs(*get_asm_host_insight_command(client, demisto.args()))

        elif demisto.command() == 'illusive-get-asm-cj-insight':
            return_outputs(*get_asm_cj_insight_command(client, demisto.args()))

        elif demisto.command() == 'illusive-get-deceptive-users':
            return_outputs(*get_deceptive_users_command(client, demisto.args()))

        elif demisto.command() == 'illusive-get-deceptive-servers':
            return_outputs(*get_deceptive_servers_command(client, demisto.args()))

        elif demisto.command() == 'illusive-is-deceptive-user':
            return_outputs(*is_deceptive_user_command(client, demisto.args()))

        elif demisto.command() == 'illusive-is-deceptive-server':
            return_outputs(*is_deceptive_server_command(client, demisto.args()))

        elif demisto.command() == 'illusive-get-incidents':
            return_outputs(*get_incidents_command(client, demisto.args()))

        elif demisto.command() == 'illusive-get-event-incident-id':
            return_outputs(*get_event_incident_id_command(client, demisto.args()))

        elif demisto.command() == 'illusive-add-deceptive-users':
            return_outputs(*add_deceptive_users_command(client, demisto.args()))

        elif demisto.command() == 'illusive-add-deceptive-servers':
            return_outputs(*add_deceptive_servers_command(client, demisto.args()))

        elif demisto.command() == 'illusive-delete-deceptive-users':
            return_outputs(*delete_deceptive_users_command(client, demisto.args()))

        elif demisto.command() == 'illusive-delete-deceptive-servers':
            return_outputs(*delete_deceptive_servers_command(client, demisto.args()))

        elif demisto.command() == 'illusive-assign-host-to-policy':
            return_outputs(*assign_host_to_policy_command(client, demisto.args()))

        elif demisto.command() == 'illusive-remove-host-from-policy':
            return_outputs(*remove_host_from_policy_command(client, demisto.args()))

        elif demisto.command() == 'illusive-run-forensics-on-demand':
            return_outputs(*run_forensics_on_demand_command(client, demisto.args()))

        elif demisto.command() == 'illusive-get-forensics-artifacts':
            try:
                file_results, file_names = get_forensics_artifacts_command(client, demisto.args())
                return_results(file_results)
                return_results(link_forensics_artifacts_name_command(file_names, client, demisto.args()))
            except ValueError:
                return_results(link_forensics_artifacts_name_command([], client, demisto.args()))

        elif demisto.command() == 'illusive-get-forensics-triggering-process-info':
            return_outputs(*get_forensics_triggering_process_info_command(client, demisto.args()))

        elif demisto.command() == 'illusive-get-forensics-analyzers':
            return_outputs(*get_forensics_analyzers_command(client, demisto.args()))

        elif demisto.command() == 'illusive-get-incident-events':
            return_outputs(*get_incident_events_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
