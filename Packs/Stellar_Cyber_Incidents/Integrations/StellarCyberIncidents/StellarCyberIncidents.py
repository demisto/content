import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# pack version: 20240107.000


__version__ = '20240107.000'

__usage__ = '''
Script to be used on demisto to pull stellar incidents and associated security alert details

    version history
    - 20220719.001 :    initial build
    - 20231004.000 :    updated to version 4.3.6 stellar API and oauth
    - 20240107.000 :    updated to support updating incidents as well as mirror sync in

'''

import sys
import traceback
import requests
import json
import urllib3
import base64
import time
from datetime import datetime, timedelta
urllib3.disable_warnings()

''' CONSTANTS '''

STELLAR_IS_SAAS = True

_STELLAR_DP_ = None
_INCIDENT_API_PORT_ = None
_ALERT_API_USER_ = ""
_ALERT_API_TOKEN_ = ""
_MINUTES_AGO_ = None
_INCIDENTS_OR_CASES_ = ""
VALIDATE_CERT = False
_OAUTH_: Dict[str, Any] = {}
_TENANTID_ = None

''' CLIENT CLASS '''


class AccessToken:
    def __init__(self, token: str, expiration: int):
        self._expiration = expiration
        self._token = token

    def __str__(self):
        return self._token

    @property
    def expired(self) -> bool:
        return self._expiration < int(datetime.now().timestamp())


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, dp_host: str, username: str, password: str, verify: bool, proxy, tenantid, is_saas: bool):
        self.dp_host = dp_host
        super().__init__(base_url=f"https://{dp_host}", verify=verify, proxy=proxy)
        self._tenantid = tenantid
        self._is_saas = is_saas
        self._basic = base64.b64encode(bytes(username + ":" + password, "utf-8")).decode("utf-8")
        # self._auth = (username, password)
        self._token: AccessToken = AccessToken('', 0)

    def _get_auth_header(self):
        if self._is_saas:
            if self._token.expired:
                headers = {'Accept': 'application/json', 'Content-type': 'application/json'}
                headers['Authorization'] = f"Basic {self._basic}"
                token_url = f"https://{self.dp_host}/connect/api/v1/access_token"
                response = self._http_request(method='POST', full_url=token_url, headers=headers, auth=self._auth)
                current_token = response.get('access_token', '')
                current_exp = int(response.get('exp', 0))
                self._token = AccessToken(current_token, current_exp)
                header_string = f"Bearer {current_token}"
            else:
                header_string = f"Bearer {self._token}"
        else:
            header_string = f"Basic {self._auth}"

        return header_string

    def test_incidents(self):
        incident_url = f'https://{self.dp_host}/connect/api/data/aella-ser-*/_search?q=fidelity:<0'
        headers = {'Accept': 'application/json', 'Content-type': 'application/json'}
        headers['Authorization'] = self._get_auth_header()
        response = self._http_request(
            method='GET',
            full_url=incident_url,
            headers=headers
        )
        return True

    def get_new_incidents(self, last_run: int):
        if self._tenantid:
            incident_url = f"https://{self.dp_host}/connect/api/v1/incidents?tenantid={self._tenantid}&FROM~created_at={last_run}&sort=created_at&order=asc"
        else:
            incident_url = f"https://{self.dp_host}/connect/api/v1/incidents?FROM~created_at={last_run}&sort=created_at&order=asc"

        headers = {'Accept': 'application/json', 'Content-type': 'application/json'}
        headers['Authorization'] = self._get_auth_header()
        response = self._http_request(
            method='GET',
            full_url=incident_url,
            headers=headers
        )
        return response['data']['incidents']

    def get_updated_incidents(self, last_run: int):
        if self._tenantid:
            incident_url = f"https://{self.dp_host}/connect/api/v1/incidents?tenantid={self._tenantid}&FROM~modified_at={last_run}&sort=modified_at&order=asc"
        else:
            incident_url = f"https://{self.dp_host}/connect/api/v1/incidents?FROM~created_at={last_run}&sort=modified_at&order=asc"

        headers = {'Accept': 'application/json', 'Content-type': 'application/json'}
        headers['Authorization'] = self._get_auth_header()
        response = self._http_request(
            method='GET',
            full_url=incident_url,
            headers=headers
        )
        incident_ids = [i["ticket_id"] for i in response['data']['incidents']]
        return incident_ids

    def get_incident(self, ticket_id=int):
        incident_url = f"https://{self.dp_host}/connect/api/v1/incidents?ticket_id={ticket_id}"

        headers = {'Accept': 'application/json', 'Content-type': 'application/json'}
        headers['Authorization'] = self._get_auth_header()
        response = self._http_request(
            method='GET',
            full_url=incident_url,
            headers=headers
        )

        return response['data']['incidents'][0]

    def get_alert(self, alert_id: str):
        hit = {}
        alert_url = f"https://{self.dp_host}/connect/api/data/aella-ser*/_search?q=_id:{alert_id}"
        headers = {'Accept': 'application/json', 'Content-type': 'application/json'}
        headers['Authorization'] = self._get_auth_header()
        response = self._http_request(method='GET', full_url=alert_url, headers=headers)
        hits = response.get('hits', None).get('hits', None)
        timed_out = response.get('timed_out', False)
        if hits:
            hit = hits[0].get('_source', None)
            alert_index = hits[0].get('_index', '')
            hit = demisto_normalization(hit, alert_id, alert_index)

        return hit

    def update_incident(self, incident_id, incident_severity=None, incident_status=None, incident_assignee=None, incident_tags_add=[], incident_tags_remove=[]):
        update_data = {
            "priority": f"{incident_severity}",
            "status": f"{incident_status}",
            "assignee": f"{incident_assignee}",
            "tags": {
                "delete": incident_tags_remove,
                "add": incident_tags_add
            }
        }
        # if incident_severity:
        #     update_data["priority"] = f"{incident_severity}"
        # if incident_status:
        #     update_data["status"] = f"{incident_status}"
        # if incident_assignee:
        #     update_data["assignee"] = f"{incident_assignee}"

        incident_url = f'https://{self.dp_host}/connect/api/v1/incidents?id={incident_id}'
        headers = {'Accept': 'application/json', 'Content-type': 'application/json'}
        headers['Authorization'] = self._get_auth_header()

        response = self._http_request(method='POST', full_url=incident_url, headers=headers, json=update_data)


''' HELPER FUNCTIONS '''


def _get_auth_header(_OAUTH_={}):
    """
    Returns the authorization header string for making requests to the Stellar Cyber Incidents API.

    If the `STELLAR_IS_SAAS` flag is set to True, this function will attempt to retrieve an access token from the
    Stellar Cyber Incidents API using the provided `_ALERT_API_USER_` and `_ALERT_API_TOKEN_` credentials. If a valid
    access token is already stored in the `_OAUTH_` dictionary and has not yet expired, this function will return the
    authorization header string with the stored access token. Otherwise, this function will make a POST request to the
    Stellar Cyber Incidents API to retrieve a new access token and store it in the `_OAUTH_` dictionary.

    If the `STELLAR_IS_SAAS` flag is set to False, this function will return the authorization header string with the
    provided `_ALERT_API_USER_` and `_ALERT_API_TOKEN_` credentials in Basic authentication format.

    :param _OAUTH_: A dictionary containing the current access token and expiration time.
    :type _OAUTH_: dict
    :return: The authorization header string.
    :rtype: str
    """
    header_string = ''
    auth = base64.b64encode(bytes(_ALERT_API_USER_ + ":" + _ALERT_API_TOKEN_, "utf-8")).decode("utf-8")
    if STELLAR_IS_SAAS:
        ts = int(time.time())
        current_token = _OAUTH_.get('token', '')
        current_exp = int(_OAUTH_.get('exp', 0))
        if ts < current_exp and current_token:
            pass
        else:
            path = f'https://{_STELLAR_DP_}:{_INCIDENT_API_PORT_}/connect/api/v1/access_token'
            headers = {
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            return_code = None
            try:
                r = requests.post(headers=headers, url=path, verify=VALIDATE_CERT)
                return_code = r.status_code
                if 200 <= r.status_code <= 299:
                    rr = r.json()
                    current_token = rr.get('access_token', '')
                    current_exp = int(rr.get('exp', 0))
                    header_string = f"Bearer {current_token}"
                    _OAUTH_ = {"token": current_token, "expires": current_exp}

                else:
                    ret = r.text
                    raise Exception(f"{ret}")

            except Exception as e:
                demisto.error(f"Cannot perform POST request: [{return_code} {e}]")

    else:
        header_string = f"Basic {auth}"

    return header_string


def get_xsoar_severity(severity):
    sev_map = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }
    return sev_map[severity]

# def get_xsoar_severity(event_score):
#     """
#     Returns the severity level of an event based on its score.

#     Args:
#         event_score (int): The score of the event.

#     Returns:
#         int: The severity level of the event, ranging from 1 to 4.
#     """
#     ret = 1
#     if event_score <= 25:
#         ret = 1
#     elif 25 > event_score <= 50:
#         ret = 2
#     elif 50 > event_score <= 75:
#         ret = 3
#     else:
#         ret = 4
#     return ret


def demisto_normalization(alert, alert_id, alert_index):
    """
    Normalizes an alert from Stellar Cyber into a format that can be ingested by Demisto.

    Args:
        alert (dict): The alert from Stellar Cyber.
        alert_id (str): The ID of the alert.
        alert_index (str): The index of the alert.

    Returns:
        dict: The normalized alert in a format that can be ingested by Demisto.
    """
    ret_alert = {
        'alert_metadata': alert['xdr_event'],
        'alert_id': alert_id,
        'alert_index': alert_index,
        'tenant_id': alert['tenantid'],
        'tenant_name': alert['tenant_name'],
        'detected_field': alert.get('detected_field', ''),
        'detected_value': alert.get('detected_value', ''),
        'xdr_tactic_name': alert['xdr_event'].get('tactic', {}).get('name', ''),
        'xdr_tactic_id': alert['xdr_event'].get('tactic', {}).get('id', ''),
        'xdr_technique_name': alert['xdr_event'].get('technique', {}).get('name', ''),
        'xdr_technique_id': alert['xdr_event'].get('technique', {}).get('id', ''),
        'alert_url': f'https://{_STELLAR_DP_}/alerts/alert/{alert_index}/amsg/{alert_id}'
    }

    # workaround for some alerts (e.g.: uncommon process anomaly)
    if not ret_alert['detected_field']:
        ret_alert['detected_field'] = alert.get('detected_fields', '')
        ret_alert['detected_value'] = alert.get('detected_values', '')

    return ret_alert


''' COMMAND FUNCTIONS '''


def fetch_incidents(client: Client, last_run: dict, first_fetch_time: str):
    """
    Retrieves incidents from the Stellar Cyber platform and maps them to XSOAR incidents.

    Returns:
        List[dict]: A list of XSOAR incidents.
    """
    last_fetch = last_run.get('last_fetch')
    if not last_fetch:
        first_fetch = dateparser.parse(first_fetch_time)
        assert first_fetch is not None
        last_fetch = int(first_fetch.timestamp() * 1000)
    incidents = client.get_new_incidents(last_run=last_fetch)
    demisto_incidents = []

    number_of_incidents = len(incidents)
    demisto.info(f"Retrieved incidents: [{number_of_incidents}]")

    for incident in incidents:
        incident_id = incident['_id']
        cust_id = incident['cust_id']
        if _INCIDENTS_OR_CASES_ == 'Cases':
            incident['incident_url'] = f'https://{_STELLAR_DP_}/cases/case-detail/{incident_id}'
        else:
            incident['incident_url'] = f'https://{_STELLAR_DP_}/incidents/incident-detail/{incident_id}?cust_id={cust_id}&view=graph'
        incident_ticket_id = incident['ticket_id']
        # if len(incident['metadata']['name_auto']):
        #     incident_name = incident['metadata']['name_auto'][0]
        # else:
        #     incident_name = incident['name']
        incident_name = incident['name']
        incident_ts = incident['created_at']
        if last_fetch < incident_ts:
            last_fetch = incident_ts
        # incident_score = get_xsoar_severity(incident['priority'])
        event_ids = incident.get('event_ids', None)
        security_event_cnt = len(event_ids)
        demisto.info("Pulling security event info for incident: [{}] [ticket id: {}] [event_cnt: [{}]".format(incident_id,
                                                                                                              incident_ticket_id,
                                                                                                              security_event_cnt))
        incident['security_alerts'] = []
        for event in event_ids:
            incident['security_alerts'].append(client.get_alert(alert_id=event['_id']))

        demisto_incident = {
            'name': incident_name,
            'dbotMirrorId': str(incident['ticket_id']),
            'mirror_direction': 'In',
            'dbotMirrorDirection': 'In',
            'mirror_instance': demisto.integrationInstance(),
            'dbotMirrorInstance': demisto.integrationInstance(),
            # 'details': 'ipsum lorem',
            'occurred': timestamp_to_datestring(incident_ts),
            'rawJSON': json.dumps(incident),
            'type': 'Stellar Incident',  # Map to a specific XSOAR incident Type
            'severity': get_xsoar_severity(incident['priority']),
            'CustomFields': {  # Map specific XSOAR Custom Fields
                'stellarincidenturl': incident['incident_url'],
                'stellarincidentid': incident_id,
                'stellarincidentticketid': str(incident['ticket_id'])
            },
            'security_alerts': incident['security_alerts']
        }
        demisto_incidents.append(demisto_incident)

    demisto.setLastRun({'last_fetch': last_fetch})
    return demisto_incidents


def simple_query(client: Client, stellar_index, stellar_field, stellar_value):
    """
    Retrieves an alert from the Stellar Cyber platform by its ID.

    Args:
        stellar_index (str): The index to query
        stellar_field (str): The field to query
        stellar_value (str): The value to query

    Returns:
        list: A list of dictionaries with the results of the query. or None

    Raises:
        Exception: If there is an issue with retrieving the query results.
    """
    pass


def get_alert(client: Client, alert_id):
    """
    Retrieves an alert from the Stellar Cyber platform by its ID.

    Args:
        alert_id (str): The ID of the alert to retrieve.

    Returns:
        dict: A dictionary containing the details of the retrieved alert.

    Raises:
        Exception: If there is an issue with retrieving the alert.
    """
    demisto.info(f"Getting alert: {alert_id}")
    hit = client.get_alert(alert_id)
    return hit


def test_module(client: Client):
    try:
        if client.test_incidents():
            return 'ok'
        else:
            return 'failed'
    except Exception as e:
        return f'Test failed with the following error: {repr(e)}'


def test_connection():
    """
    Tests the connection and authentication to the Incident API.

    Returns:
        bool: True if the test was successful, False otherwise.
    """
    demisto.info("Testing connection and authentication to Incident API")
    # test auth but return empty set
    incident_url = f'https://{_STELLAR_DP_}:{_INCIDENT_API_PORT_}/connect/api/data/aella-ser-*/_search?q=fidelity:<0'
    headers = {'Accept': 'application/json', 'Content-type': 'application/json', "Stellar-Token": f"{_ALERT_API_TOKEN_}"}
    headers['Authorization'] = _get_auth_header(_OAUTH_)
    r_incidents = requests.get(incident_url, headers=headers, verify=VALIDATE_CERT)
    b_success = True

    if 200 <= r_incidents.status_code <= 299:
        demisto.info("Test API connection successful")
        b_success = True
    else:
        err_reason = r_incidents.text
        demisto.error(f"Test API connection failed: {err_reason}")

        b_success = False

    if b_success:
        demisto.results('ok')
    else:
        demisto.results('failed')

    return b_success


def close_incident(client: Client, incident_id, close_reason=''):
    """
    Closes a Stellar Cyber incident with the given incident ID and close reason.

    Args:
        incident_id (str): The ID of the incident to close.
        close_reason (str, optional): The reason for closing the incident. Defaults to ''.

    Raises:
        Exception: If there is a problem closing the incident.

    Returns:
        None
    """
    demisto.info(f"Closing stellar incident with id: [{incident_id}]")
    incident_url = f'https://{_STELLAR_DP_}:{_INCIDENT_API_PORT_}/connect/api/v1/incidents?id={incident_id}'
    headers = {'Accept': 'application/json', 'Content-type': 'application/json'}
    headers['Authorization'] = _get_auth_header(_OAUTH_)

    update_data = json.dumps({
        # "incident_id": "{}".format(incident_id),
        "status": "Resolved",
        # "resolution": "{}".format('this is the resolution'),
        "resolution": f"{close_reason}",
    })

    r_incidents = requests.post(incident_url, headers=headers, data=update_data)
    if 200 <= r_incidents.status_code <= 299:
        rr_incidents = r_incidents.text
        # print(json.dumps(rr_incidents, indent=4, sort_keys=False))
        demisto.info(f"Response from closing incident API call: [{rr_incidents}]")
        demisto.info(f"Successfully closed incident id with resolution: [{incident_id} / {close_reason}]")
    else:
        raise Exception(f"Problem closing incident: [{r_incidents.text}]")


def update_incident(client: Client, incident_id, incident_severity=None, incident_status=None, incident_assignee=None, incident_tags_add=[], incident_tags_remove=[]):
    """
    Updates a Stellar Cyber incident with the given incident ID and attributes to update.

    Args:
        incident_id (str): The ID of the incident to close.
        incident_severity(str): The severity to set on incident
        incident_status (str): The status to update on incident.
        incident_assignee (str): Email or username to assign to incident
        incident_tags_add (list): List of tags to add to incident
        incident_tags_remove (list): List of tags to remove from incident

    Raises:
        Exception: If there is a problem updating the incident.

    Returns:
        None
    """
    if not (incident_severity or incident_status or incident_assignee or len(incident_tags_add) or len(incident_tags_remove)):
        raise Exception(f"No values to update for stellar incident with id: [{incident_id}]")

    demisto.info(f"Updating stellar incident with id: [{incident_id}]")
    client.update_incident(incident_id, incident_severity, incident_status,
                           incident_assignee, incident_tags_add, incident_tags_remove)


def get_remote_data_command(client: Client, args):
    parsed_args = GetRemoteDataArgs(args)
    try:
        remote_incident_id = parsed_args.remote_incident_id
        incidents = client.get_incident(ticket_id=remote_incident_id)
        demisto_incidents = []

        number_of_incidents = len(incidents)
        demisto.info(f"Retrieved incidents: [{number_of_incidents}]")

        for incident in incidents:
            incident_id = incident['_id']
            cust_id = incident['cust_id']
            if _INCIDENTS_OR_CASES_ == 'Cases':
                incident['incident_url'] = f'https://{_STELLAR_DP_}/cases/case-detail/{incident_id}'
            else:
                incident['incident_url'] = f'https://{_STELLAR_DP_}/incidents/incident-detail/{incident_id}?cust_id={cust_id}&view=graph'
            incident_ticket_id = incident['ticket_id']
            # if len(incident['metadata']['name_auto']):
            #     incident_name = incident['metadata']['name_auto'][0]
            # else:
            #     incident_name = incident['name']
            incident_name = incident['name']
            # incident_score = get_xsoar_severity(incident['incident_score'])
            event_ids = incident.get('event_ids', None)
            security_event_cnt = len(event_ids)
            demisto.info("Pulling security event info for incident: [{}] [ticket id: {}] [event_cnt: [{}]".format(incident_id,
                                                                                                                  incident_ticket_id,
                                                                                                                  security_event_cnt))
            incident['security_alerts'] = []
            for event in event_ids:
                incident['security_alerts'].append(client.get_alert(alert_id=event['_id']))

            demisto_incident = {
                'name': incident_name,
                # 'details': incident['metadata']['description_auto'],
                'dbotMirrorId': str(incident['ticket_id']),
                'mirror_direction': 'In',
                'dbotMirrorDirection': 'In',
                'mirror_instance': demisto.integrationInstance(),
                'dbotMirrorInstance': demisto.integrationInstance(),
                # 'details': 'ipsum lorem',
                'rawJSON': json.dumps(incident),
                # 'type': 'Stellar Incident',  # Map to a specific XSOAR incident Type
                'severity': get_xsoar_severity(incident['priority']),
                'CustomFields': {  # Map specific XSOAR Custom Fields
                    'stellarincidenturl': incident['incident_url'],
                    'stellarincidentid': incident_id,
                    'stellarincidentticketid': str(incident['ticket_id'])
                },
                'security_alerts': incident['security_alerts']
            }
            demisto_incidents.append(demisto_incident)
        return GetRemoteDataResponse(demisto_incidents, [])
    except Exception as e:
        if "Rate limit exceeded" in str(e):
            return_error("API rate limit")


def get_modified_remote_data_command(client: Client, args):
    try:
        remote_args = GetModifiedRemoteDataArgs(args)
        last_update = remote_args.last_update
        last_update_utc = dateparser.parse(last_update, settings={'TIMEZONE': 'UTC'})
        assert last_update_utc is not None
        last_run_ts = int(last_update_utc.timestamp() * 1000)
        modified_incident_ids = client.get_updated_incidents(last_run=last_run_ts)

        set_last_mirror_run({"last_update": datetime.utcnow()})
        return GetModifiedRemoteDataResponse(modified_incident_ids)
    except Exception as e:
        return_error("skip update")


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    try:
        _STELLAR_DP_ = demisto.getParam('stellar_dp')
        _INCIDENT_API_PORT_ = demisto.getParam('incident_api_port')
        _ALERT_API_USER_ = demisto.getParam('credentials')['identifier']  # type: ignore
        _ALERT_API_TOKEN_ = demisto.getParam('credentials')['password']  # type: ignore
        _MINUTES_AGO_ = demisto.getParam('incidentFetchInterval')
        FIRST_FETCH = demisto.params().get('first_fetch', '3 days').strip()
        _INCIDENTS_OR_CASES_ = demisto.getParam('incidents_or_cases')
        VALIDATE_CERT = not demisto.params().get('insecure', True)
        PROXY = demisto.params().get('proxy', False)
        _OAUTH_ = {"token": '', "expires": 0}
        _TENANTID_ = demisto.params().get('tenantid', None)

        client = Client(dp_host=_STELLAR_DP_, username=_ALERT_API_USER_, password=_ALERT_API_TOKEN_,
                        verify=VALIDATE_CERT, proxy=PROXY, tenantid=_TENANTID_, is_saas=STELLAR_IS_SAAS)

        demisto.info(f'Command is {demisto.command()}')

        if demisto.command() == 'test-module':
            # test_connection()
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            incidents = fetch_incidents(client, last_run=demisto.getLastRun(), first_fetch_time=FIRST_FETCH)
            demisto.incidents(incidents)
        elif demisto.command() == 'stellar-get-event':
            return_results(get_alert(client, demisto.args()['alert_id']))
        elif demisto.command() == 'stellar-simple-query':
            return_results(simple_query(client, demisto.args()['stellar_index'],
                           demisto.args()['stellar_field'], demisto.args()['stellar_value']))
        elif demisto.command() == 'stellar-close-incident':
            incident_id = demisto.args().get('stellar_incident_id', False)
            close_reason = demisto.args().get('stellar_close_reason', '')
            close_incident(client, incident_id, close_reason)
            return_results("ok")
        elif demisto.command() == 'stellar-incident-update':
            incident_id = demisto.args().get('stellar_incident_id', False)
            incident_severity = demisto.args().get('incident_severity', None)
            incident_status = demisto.args().get('incident_status', None)
            incident_assignee = demisto.args().get('incident_assignee', None)
            incident_tags_add = demisto.args().get('incident_tags_add', [])
            incident_tags_remove = demisto.args().get('incident_tags_remove', [])
            update_incident(client, incident_id, incident_severity, incident_status,
                            incident_assignee, incident_tags_add, incident_tags_remove)
            return_results("ok")
        elif demisto.command() == 'get-modified-remote-data':
            return_results(get_modified_remote_data_command(client, demisto.args()))
        elif demisto.command() == 'get-remote-data':
            return_results(get_remote_data_command(client, demisto.args()))

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        demisto.results("failed")
        demisto.error(traceback.format_exc())  # print the traceback
        if exc_tb is not None and exc_tb.tb_lineno is not None:
            demisto.error(f"[line: {exc_tb.tb_lineno}] [{e}]")
        else:
            demisto.error(f"[{e}]")


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
