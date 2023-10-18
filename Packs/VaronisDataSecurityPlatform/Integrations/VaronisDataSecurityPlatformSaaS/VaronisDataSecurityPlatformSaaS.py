"""Varonis Data Security Platform integration
"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
import json
from typing import Dict, Any, List, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

MAX_USERS_TO_SEARCH = 5
NON_EXISTENT_SID = -1000
THREAT_MODEL_ENUM_ID = 5821
ALERT_STATUSES = {'new': 1, 'under investigation': 2, 'closed': 3, 'action required': 4, 'auto-resolved': 5}
ALERT_SEVERITIES = ['high', 'medium', 'low']
CLOSE_REASONS = {
    'none': 0,
    'resolved': 1,
    'misconfiguration': 2,
    'threat model disabled or deleted': 3,
    'account misclassification': 4,
    'legitimate activity': 5,
    'other': 6
}
DISPLAY_NAME_KEY = 'DisplayName'
SAM_ACCOUNT_NAME_KEY = 'SAMAccountName'
EMAIL_KEY = 'Email'


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def __init__(self, base_url, verify=True, proxy=False, ok_codes=tuple(), headers=None, auth=None):
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth)
        self._session.verify = verify
        if not verify and self._session.adapters['https://']:
            if hasattr(self._session.adapters['https://'], "context"):
                self._session.adapters['https://'].context.check_hostname = verify

        self.headers: Dict[str, Any] = {}
        self.headers["authorization"] = None
        self.headers["content-type"] = 'application/json'


    def varonis_authenticate(self, apiKey: str) -> Dict[str, Any]:
        headers = {
            'x-api-key': apiKey
        }
        response = self._http_request('POST', url_suffix='/api/authentication/api_keys/token', data='grant_type=varonis_custom', headers=headers)
        token = response['access_token']
        token_type = response['token_type']
        self._expires_in = response['expires_in']

        demisto.debug(f'Token expires in {self._expires_in}')

        self.headers["authorization"] = f'{token_type} {token}'
        return response


    def varonis_get_alerts(self, ruleIds: Optional[List[str]], alertIds: Optional[List[str]], start_time: Optional[datetime],
                           end_time: Optional[datetime], ingest_time_from: Optional[datetime],
                           ingest_time_to: Optional[datetime], device_names: Optional[List[str]], last_days: Optional[int],
                           sid_ids: Optional[List[int]], from_alert_id: Optional[int], alert_statuses: Optional[List[str]],
                           alert_severities: Optional[List[str]], aggregate: bool,
                           descending_order: bool) -> List[Dict[str, Any]]:
        """Get alerts

        :type ruleIds: ``Optional[List[str]]``
        :param ruleIds: List of threat models to filter by

        :type alertIds: ``Optional[List[str]]``
        :param alertIds: List of alertIds to filter by

        :type start_time: ``Optional[datetime]``
        :param start_time: Start time of the range of alerts

        :type end_time: ``Optional[datetime]``
        :param end_time: End time of the range of alerts

        :type ingest_time_from: ``Optional[datetime]``
        :param ingest_time_from: Start ingest time of the range of alerts

        :type ingest_time_to: ``Optional[datetime]``
        :param ingest_time_to: End ingest time of the range of alerts
        
        :type device_names: ``Optional[List[str]]``
        :param device_names: List of device names to filter by

        :type last_days: ``Optional[List[int]]``
        :param last_days: Number of days you want the search to go back to

        :type sid_ids: ``Optional[List[int]]``
        :param sid_ids: List of user ids

        :type from_alert_id: ``Optional[int]``
        :param from_alert_id: Alert id to fetch from

        :type alert_statuses: ``Optional[List[str]]``
        :param alert_statuses: List of alert statuses to filter by

        :type alert_severities: ``Optional[List[str]]``
        :param alert_severities: List of alert severities to filter by

        :type aggregate: ``bool``
        :param aggregate: Indicated whether agregate alert by alert id

        :type count: ``int``
        :param count: Alerts count

        :type descendingOrder: ``bool``
        :param descendingOrder: Indicates whether alerts should be ordered in newest to oldest order

        :return: Alerts
        :rtype: ``List[Dict[str, Any]]``
        """
        
        days_back = 7
        if start_time is None and end_time is None and last_days is None:
            last_days = days_back
        elif start_time is None and end_time is not None:
            start_time = datetime.now() - datetime.timedelta(days=days_back)
        elif end_time is None and start_time is not None:
            last_days = datetime.now()
        
        data = {
            'RuleIds': [],
            'AlertIds': [],
            'StartTime': None,
            'EndTime': None,
            'IngestTimeFrom': None,
            'IngestTimeTo': None,
            'DeviceNames': [],
            'LastDays': None,
            'SidIds': [],
            'Statuses': [],
            'Severities': [],
            'DescendingOrder': None
        }

        if ruleIds and len(ruleIds) > 0:
            data['RuleIds'] = ruleIds

        if alertIds and len(alertIds) > 0:
            data['AlertIds'] = alertIds

        if start_time:
            data['StartTime'] = start_time.isoformat()

        if end_time:
            data['EndTime'] = end_time.isoformat()

        if ingest_time_from:
            data['IngestTimeFrom'] = ingest_time_from.isoformat()

        if ingest_time_to:
            data['IngestTimeTo'] = ingest_time_to.isoformat()
            
        if device_names and len(device_names) > 0:
            data['DeviceNames'] = device_names

        if last_days:
            data['LastDays'] = last_days

        if sid_ids and len(sid_ids) > 0:
            data['SidIds'] = sid_ids

        if alert_statuses and len(alert_statuses) > 0:
            data['Statuses'] = alert_statuses
        
        if alert_severities and len(alert_severities) > 0:
            data['Severities'] = alert_severities
        
        if descending_order:
            data['DescendingOrder'] = descending_order
        
        # TODO: next parametes are not supported by API
        # if from_alert_id is not None:
        #     data['FromAlertSeqId'] = from_alert_id
        # data['Aggregate'] = aggregate
        
        dataJSON = json.dumps(data)
        return self._http_request(
            'POST',
            '/api/alert/search/alerts',
            data=dataJSON,
            headers=self.headers
        )


    def varonis_get_alerted_events(self, alertIds: List[str], start_time: Optional[datetime], end_time: Optional[datetime],
                                   descending_order: bool) -> List[Dict[str, Any]]:
        """Get alerted events

        :type alertIds: ``List[str]``
        :param alertIds: List of alert ids

        :type start_time: ``Optional[datetime]``
        :param start_time: Start time of the range of alerts

        :type end_time: ``Optional[datetime]``
        :param end_time: End time of the range of alerts

        :type count: ``int``
        :param count: Alerted events count

        :type descendingOrder: ``bool``
        :param descendingOrder: Indicates whether events should be ordered in newest to oldest order

        :return: Alerted events
        :rtype: ``List[Dict[str, Any]]``
        """
        
        data = {
            'AlertIds': [],
            'StartDate': None,
            'EndDate': None,
            'DescendingOrder': 'False'
        }

        if alertIds and len(alertIds) > 0:
            data['AlertIds'] = alertIds

        if start_time:
            data['StartDate'] = start_time.isoformat()

        if end_time:
            data['EndDate'] = end_time.isoformat()

        if descending_order:
            data['DescendingOrder'] = descending_order
        
        dataJSON = json.dumps(data)
        return self._http_request(
            'POST',
            '/api/alert/search/events',
            data=dataJSON,
            headers=self.headers
        )


    def varonis_get_users(self, search_string: str) -> List[Any]:
        """Search users by search string

        :type search_string: ``str``
        :param search_string: search string

        :return: The list of users
        :rtype: ``Dict[str, Any]``
        """
        request_params: Dict[str, Any] = {}
        request_params['columns'] = '[\'SamAccountName\',\'Email\',\'DomainName\',\'ObjName\']'
        request_params['searchString'] = search_string
        request_params['limit'] = 1000

        response = self._http_request(
            'GET',
            'api/userdata/users',
            params=request_params,
            headers=self.headers
        )
        return response['ResultSet']


    def varonis_get_enum(self, enum_id: int) -> List[Any]:
        """Gets an enum by enum_id. Usually needs for retrieving object required for a search

        :type enum_id: ``int``
        :param enum_id: Id of enum stored in database

        :return: The list of objects required for a search filter
        :rtype: ``List[Any]``
        """
        response = self._http_request('GET', f'/api/entitymodel/enum/{enum_id}', headers=self.headers)
        return response


    def varonis_update_alert_status(self, query: Dict[str, Any]) -> bool:
        """Update alert status

        :type query: ``Dict[str, Any]``
        :param query: Update request body

        :return: Result of execution
        :rtype: ``bool``

        """
        return self._http_request(
            'POST',
            '/api/alert/alert/SetStatusToAlerts',
            json_data=query,
            headers=self.headers)

    
    
''' HELPER FUNCTIONS '''

def convert_to_demisto_severity(severity: Optional[str]) -> int:
    """Maps Varonis severity to Cortex XSOAR severity

    Converts the Varonis alert severity level ('Low', 'Medium',
    'High') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the Varonis API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    if severity is None:
        return IncidentSeverity.LOW

    return {
        'Low': IncidentSeverity.LOW,
        'Medium': IncidentSeverity.MEDIUM,
        'High': IncidentSeverity.HIGH
    }[severity]


def get_included_severitires(severity: Optional[str]) -> List[str]:
    """ Return list of severities that is equal or higher then provided

    :type severity: ``Optional[str]``
    :param severity: Severity

    :return: List of severities
    :rtype: ``List[str]``
    """
    if not severity:
        return []

    severities = ALERT_SEVERITIES.copy()

    if severity.lower() == 'medium':
        severities.remove('low')

    if severity.lower() == 'high':
        severities.remove('low')
        severities.remove('medium')

    return severities


def validate_threat_models(client: Client, threat_models: List[str]):
    """ Validates if threat models exist in Varonis

    :type client: ``Client``
    :param client: Http client

    :type threat_models: ``Optional[List[str]]``
    :param threat_model: List of threat model names of alerts to fetch

    """

    rules_enum = client.varonis_get_enum(THREAT_MODEL_ENUM_ID)
    for threat_model in threat_models:
        rule = next((r for r in rules_enum if strEqual(r['ruleName'], threat_model)), None)

        if not rule:
            raise ValueError(f'There is no threat model with name {threat_model}.')


def try_convert(item, converter, error=None):
    """Try to convert item

    :type item: ``Any``
    :param item: An item to convert

    :type converter: ``Any``
    :param converter: Converter function

    :type error: ``Any``
    :param error: Error object that will be raised in case of error convertion

    :return: A converted item or None
    :rtype: ``Any``
    """
    if item:
        try:
            return converter(item)
        except Exception:
            if error:
                raise error
            raise
    return None


def strEqual(text1: str, text2: str) -> bool:
    if not text1 and not text2:
        return True
    if not text1 or not text2:
        return False

    return text1.casefold() == text2.casefold()


def enrich_with_url(output: Dict[str, Any], baseUrl: str, id: str) -> Dict[str, Any]:
    """Enriches result with alert url

    :type output: ``Dict[str, Any]``
    :param output: Output to enrich

    :type baseUrl: ``str``
    :param baseUrl: Varonis UI based url

    :type id: ``str``
    :param id: Alert it

    :return: Enriched output
    :rtype: ``Dict[str, Any]``
    """

    output['Url'] = urljoin(baseUrl, f'/#/app/analytics/entity/Alert/{id}')
    return output


def get_sids(client: Client, values: List[str], user_domain_name: Optional[str], key: str) -> List[int]:
    """Return list of user ids

    :type client: ``Client``
    :param client: Http client

    :type user_names: ``List[str]``
    :param user_names: A list of user names

    :type user_domain_name: ``str``
    :param user_domain_name: User domain name

    :return: List of user ids
    :rtype: ``List[int]``
    """
    sidIds: List[int] = []

    if not values:
        return sidIds

    for value in values:
        users = client.varonis_get_users(value)

        for user in users:
            if (strEqual(user[key], value)
                    and (not user_domain_name or strEqual(user['DomainName'], user_domain_name))):
                sidIds.append(user['Id'])

    if len(sidIds) == 0:
        sidIds.append(NON_EXISTENT_SID)

    return sidIds


def get_sids_by_user_name(client: Client, user_names: List[str], user_domain_name: str) -> List[int]:
    """Return list of user ids

    :type client: ``Client``
    :param client: Http client

    :type user_names: ``List[str]``
    :param user_names: A list of user names

    :type user_domain_name: ``str``
    :param user_domain_name: User domain name

    :return: List of user ids
    :rtype: ``List[int]``
    """
    return get_sids(client, user_names, user_domain_name, DISPLAY_NAME_KEY)


def get_sids_by_sam(client: Client, sam_account_names: List[str]) -> List[int]:
    """Return list of user ids

    :type client: ``Client``
    :param client: Http client

    :type sam_account_names: ``List[str]``
    :param sam_account_names: A list of sam account names

    :return: List of user ids
    :rtype: ``List[int]``
    """
    return get_sids(client, sam_account_names, None, SAM_ACCOUNT_NAME_KEY)


def get_sids_by_email(client: Client, emails: List[str]) -> List[int]:
    """Return list of user ids

    :type client: ``Client``
    :param client: Http client

    :type emails: ``List[str]``
    :param emails: A list of emails

    :return: List of user ids
    :rtype: ``List[int]``
    """
    return get_sids(client, emails, None, EMAIL_KEY)


def get_rule_ids(client: Client, values: List[str]) -> List[int]:
    """Return list of user ids

    :type client: ``Client``
    :param client: Http client

    :type threat_model_names: ``List[str]``
    :param threat_model_names: A list of threat_model_names

    :return: List of rule ids
    :rtype: ``List[int]``
    """
    ruleIds: List[int] = []

    if not values:
        return ruleIds

    rules = client.varonis_get_enum(THREAT_MODEL_ENUM_ID)
    for value in values:
        for rule in rules:
            if strEqual(rule['ruleName'], value):
                ruleIds.append(rule['ruleID'])
                # ruleIds.append(rule['templateID'])
                break

    if len(ruleIds) == 0:
        ruleIds.append(NON_EXISTENT_SID)

    return ruleIds


def varonis_update_alert(client: Client, close_reason_id: int, status_id: int, alert_ids: list) -> bool:
    """Update Varonis alert. It creates request and pass it to http client

    :type client: ``Client``
    :param client: Http client

    :type close_reason_id: ``int``
    :param close_reason_id: close reason enum id

    :type status_id: ``int``
    :param status_id: status id enum id

    :type alert_ids: ``list``
    :param alert_ids: list of alert id(s)

    :return: Result of execution
    :rtype: ``bool``

    """
    if len(alert_ids) == 0:
        raise ValueError('alert id(s) not specified')

    query: Dict[str, Any] = {
        'AlertGuids': alert_ids,
        'CloseReasonId': close_reason_id,
        'StatusId': status_id
    }

    return client.varonis_update_alert_status(query)


def convert_incident_alert_to_onprem_format(alert_saas_format):
    output = alert_saas_format

    # todo: fix when it will be converted to array
    output["Locations"] = []
    countries = [] if alert_saas_format.get("Country") is None else alert_saas_format.get("Country").split(',')
    states = [] if alert_saas_format.get("State") is None else alert_saas_format.get("State").split(',')
    blacklist_locations = [] if alert_saas_format.get("BlacklistLocation") is None else alert_saas_format.get("BlacklistLocation").split(',')
    abnormal_locations = [] if alert_saas_format.get("AbnormalLocation") is None else alert_saas_format.get("AbnormalLocation").split(',')
    for i in range(len(countries)):
        entry = {
            "Country": "" if len(countries) <= i else countries[i],
            "State": "" if len(states) <= i else states[i],
            "BlacklistLocation": "" if len(blacklist_locations) <= i else blacklist_locations[i],
            "AbnormalLocation": "" if len(abnormal_locations) <= i else abnormal_locations[i]
        }
        output["Locations"].append(entry)

    # todo: fix when it will be converted to array
    output["Sources"] = []
    platforms = [] if alert_saas_format.get("Platform") is None else alert_saas_format.get("Platform")
    file_server_or_Domain = [] if alert_saas_format.get("FileServerOrDomain") is None else alert_saas_format.get("FileServerOrDomain")
    for i in range(len(platforms)):
        entry = {
            "Platform": "" if len(platforms) <= i else platforms[i],
            "FileServerOrDomain": "" if len(file_server_or_Domain) <= i else file_server_or_Domain[i]
        }
        output["Sources"].append(entry)

    # todo: fix when it will be converted to array
    output["Devices"] = []
    device_names = [] if alert_saas_format.get("DeviceName") is None else alert_saas_format.get("DeviceName").split(',')
    assets = [] if alert_saas_format.get("Asset") is None else alert_saas_format.get("Asset")
    for i in range(len(device_names)):
        entry = {
            "Name": "" if len(device_names) <= i else device_names[i],
            "Asset": "" if len(assets) <= i else assets[i]
        }
        output["Devices"].append(entry)

    # todo: fix when it will be converted to array
    output["Users"] = []
    user_names = [] if alert_saas_format.get("UserName") is None else alert_saas_format["UserName"]
    sam_account_names = [] if alert_saas_format.get("SamAccountName") is None else alert_saas_format["SamAccountName"]
    privileged_account_types = [] if alert_saas_format.get("PrivilegedAccountType") is None else alert_saas_format["PrivilegedAccountType"]
    departments = [] if alert_saas_format.get("Department") is None else alert_saas_format["Department"].split(',')
    for i in range(len(user_names)):
        entry = {
            "Name": "" if len(user_names) <= i else user_names[i],
            "SamAccountName": "" if len(sam_account_names) <= i else sam_account_names[i],
            "PrivilegedAccountType": "" if len(privileged_account_types) <= i else privileged_account_types[i],
            "Department": "" if len(departments) <= i else departments[i]
        }
        output["Users"].append(entry)
        
    return output


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        client.varonis_get_enum(THREAT_MODEL_ENUM_ID)
        message = 'ok'
    except DemistoException as e:
        if 'Unauthorized' in str(e):
            message = 'Authorization Error: token is incorrect or expired.'
        else:
            raise e
    return message


def fetch_incidents_command(client: Client, last_run: Dict[str, datetime], first_fetch_time: Optional[datetime],
                            alert_status: Optional[str], threat_model: Optional[str], severity: Optional[str]
                            ) -> Tuple[Dict[str, Optional[datetime]], List[dict]]:
    """This function retrieves new alerts every interval (default is 1 minute).

    :type client: ``Client``
    :param client: Http client

    :type last_run: ``Dict[str, datetime]``
    :param last_run:
        A dict with a key containing the latest alert ingest time we got from last fetch

    :type first_fetch_time: ``Optional[datetime]``
    :param first_fetch_time:
        If last_run is None (first time we are fetching), it contains
        the datetime on when to start fetching incidents

    :type alert_status: ``Optional[str]``
    :param alert_status: status of the alert to search for. Options are 'New', 'Under investigation', 'Action Required', 'Auto-Resolved' or 'Closed' 

    :type threat_model: ``Optional[str]``
    :param threat_model: Comma-separated list of threat model names of alerts to fetch

    :type severity: ``Optional[str]``
    :param severity: severity of the alert to search for. Options are 'High', 'Medium' or 'Low'

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, Optional[int]]``): Contains last fetched id.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR
    :rtype: ``Tuple[Dict[str, int], List[dict]]``

    """

    threat_model_names = argToList(threat_model)
    if threat_model_names and len(threat_model_names) > 0:
        validate_threat_models(client, threat_model_names)

    incidents: List[Dict[str, Any]] = []
    
    last_fetched_ingest_time_str = last_run.get('last_fetched_ingest_time', first_fetch_time.isoformat())
    last_fetched_ingest_time = try_convert(
            last_fetched_ingest_time_str,
            lambda x: datetime.fromisoformat(x),
            ValueError(f'last_fetched_ingest_time should be in iso format, but it is {last_fetched_ingest_time_str}.')
        )
    ingest_time_to = datetime.now()

    demisto.debug(f'Fetching incidents. Last fetched ingest time: {last_fetched_ingest_time}')

    statuses = []
    if alert_status:
        statuses.append(alert_status)

    severities = get_included_severitires(severity)

    ruleIds = get_rule_ids(client, threat_model_names)

    alerts = client.varonis_get_alerts( ruleIds=ruleIds, alertIds=None, start_time=None, end_time=None,
                                        device_names=None, last_days=None, sid_ids=None, from_alert_id=None,
                                        ingest_time_from=last_fetched_ingest_time,
                                        ingest_time_to=ingest_time_to,
                                        alert_statuses=statuses, alert_severities=severities, aggregate=True,
                                        descending_order=True)

    demisto.debug(f'varonis_get_alerts returned: {len(alerts)} alerts')

    for alert in alerts:
        ingestTime_str = alert['IngestTime']
        ingestTime = try_convert(
            alert['IngestTime'],
            lambda x: datetime.fromisoformat(x),
            ValueError(f'IngestTime should be in iso format, but it is {ingestTime_str}.')
        )

        if not last_fetched_ingest_time or ingestTime > last_fetched_ingest_time:
            last_fetched_ingest_time = ingestTime + timedelta(minutes=1)
        guid = alert['ID']
        name = alert['Name']
        alert_time = alert['EventUTC']
        enrich_with_url(alert, client._base_url, guid)
        
        alert_converted = convert_incident_alert_to_onprem_format(alert)

        incident = {
            'name': f'Varonis alert {name}',
            'occurred': f'{alert_time}Z',
            'rawJSON': json.dumps(alert_converted),
            'type': 'Varonis DSP Incident',
            'severity': convert_to_demisto_severity(alert_converted['Severity']),
        }

        incidents.append(incident)
        demisto.debug(f'new incident: {json.dumps(alert, indent=4, sort_keys=True, default=str)}')

    next_run = {'last_fetched_ingest_time': last_fetched_ingest_time.isoformat()}

    return next_run, incidents


def varonis_get_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get alerts from Varonis DA

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['threat_model_name']`` List of requested threat models to retrieve
        ``args['ingest_time_from']`` Start ingest time of the range of alerts
        ``args['ingest_time_to']`` End ingest time of the range of alerts
        ``args['start_time']`` Start time of the range of alerts
        ``args['end_time']`` End time of the range of alerts
        ``args['alert_status']`` List of required alerts status
        ``args['alert_severity']`` List of alerts severity
        ``args['device_name']`` List of device names
        ``args['user_domain_name']`` User domain name
        ``args['user_name']`` List of user names
        ``args['sam_account_name']`` List of sam account names
        ``args['email']`` List of emails
        ``args['last_days']`` Number of days you want the search to go back to
        ``args['descending_order']`` Indicates whether alerts should be ordered in newest to oldest order

    :return:
        A ``CommandResults`` object

    :rtype: ``CommandResults``
    """
    threat_model_names = args.get('threat_model_name', None)
    alert_ids = args.get('alert_ids', None)
    start_time = args.get('start_time', None)
    end_time = args.get('end_time', None)
    ingest_time_from = args.get('ingest_time_from', None)
    ingest_time_to = args.get('ingest_time_to', None)
    alert_statuses = args.get('alert_status', None)
    alert_severities = args.get('alert_severity', None)
    device_names = args.get('device_name', None)
    user_domain_name = args.get('user_domain_name', None)
    user_names = args.get('user_name', None)
    sam_account_names = args.get('sam_account_name', None)
    emails = args.get('email', None)
    last_days = args.get('last_days', None)
    descending_order = args.get('descending_order', True)

    user_names = try_convert(user_names, lambda x: argToList(x))
    sam_account_names = try_convert(sam_account_names, lambda x: argToList(x))
    emails = try_convert(emails, lambda x: argToList(x))

    if last_days:
        last_days = try_convert(
            last_days,
            lambda x: int(x),
            ValueError(f'last_days should be integer, but it is {last_days}.')
        )

        if last_days <= 0:
            raise ValueError('last_days cannot be less then 1')

    if user_domain_name and (not user_names or len(user_names) == 0):
        raise ValueError('user_domain_name cannot be provided without user_name')

    if user_names and len(user_names) > MAX_USERS_TO_SEARCH:
        raise ValueError(f'cannot provide more then {MAX_USERS_TO_SEARCH} users')

    if sam_account_names and len(sam_account_names) > MAX_USERS_TO_SEARCH:
        raise ValueError(f'cannot provide more then {MAX_USERS_TO_SEARCH} sam account names')

    if emails and len(emails) > MAX_USERS_TO_SEARCH:
        raise ValueError(f'cannot provide more then {MAX_USERS_TO_SEARCH} emails')

    alert_severities = try_convert(alert_severities, lambda x: argToList(x))
    device_names = try_convert(device_names, lambda x: argToList(x))
    threat_model_names = try_convert(threat_model_names, lambda x: argToList(x))
    
    start_time = try_convert(
        start_time,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'start_time should be in iso format, but it is {start_time}.')
    )
    end_time = try_convert(
        end_time,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'end_time should be in iso format, but it is {start_time}.')
    )

    ingest_time_from = try_convert(
        ingest_time_from,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'ingest_time_from should be in iso format, but it is {ingest_time_from}.')
    )
    ingest_time_to = try_convert(
        ingest_time_to,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'ingest_time_to should be in iso format, but it is {ingest_time_to}.')
    )

    alert_statuses = try_convert(alert_statuses, lambda x: argToList(x))
    sid_ids = get_sids_by_email(client, emails) + get_sids_by_sam(client, sam_account_names) + \
        get_sids_by_user_name(client, user_names, user_domain_name)

    if alert_severities:
        for severity in alert_severities:
            if severity.lower() not in ALERT_SEVERITIES:
                raise ValueError(f'There is no severity {severity}.')

    if alert_statuses:
        for status in alert_statuses:
            if status.lower() not in ALERT_STATUSES.keys():
                raise ValueError(f'There is no status {status}.')
    
    ruleIds = get_rule_ids(client, threat_model_names)
    
    alerts = client.varonis_get_alerts(ruleIds, alert_ids, start_time, end_time, ingest_time_from, ingest_time_to, device_names,
                                       last_days, sid_ids, None, alert_statuses, alert_severities, False,
                                       descending_order)
    outputs = dict()
    outputs['Alert'] = alerts

    if outputs:
        for alert in alerts:
            enrich_with_url(alert, client._base_url, alert['ID'])

    readable_output = tableToMarkdown('Varonis Alerts', alerts, headers=[
                                      'Name', 'Severity', 'Time', 'Category', 'UserName', 'Status'])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Varonis',
        outputs_key_field='Varonis.Alert.ID',
        outputs=outputs
    )


def varonis_get_alerted_events_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get alerted events from Varonis DA

    :type client: ``Client``
    :param client: Http client 

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` List of alert ids
        ``args['start_time']`` Start time of the range of events
        ``args['end_time']`` End time of the range of events
        ``args['descending_order']`` Indicates whether events should be ordered in newest to oldest order

    :return:
        A ``CommandResults`` object

    :rtype: ``CommandResults``
    """
    alertIds = args.get('alert_id', None)
    start_time = args.get('start_time', None)
    end_time = args.get('end_time', None)
    descending_order = args.get('descending_order', True)

    alertIds = try_convert(alertIds, lambda x: argToList(x))
    start_time = try_convert(
        start_time,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'start_time should be in iso format, but it is {start_time}.')
    )
    end_time = try_convert(
        end_time,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'end_time should be in iso format, but it is {start_time}.')
    )
    
    events = client.varonis_get_alerted_events(alertIds=alertIds, start_time=start_time, end_time=end_time,
                                               descending_order=descending_order)
    outputs = dict()
    outputs['Event'] = events

    readable_output = tableToMarkdown('Varonis Alerted Events', events)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Varonis',
        outputs_key_field='Varonis.Event.ID',
        outputs=outputs
    )


def varonis_update_alert_status_command(client: Client, args: Dict[str, Any]) -> bool:
    """Update Varonis alert status command

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['status']`` Alert's new status
        ``args['alert_id']`` Array of alert ids to be updated

    :return: Result of execution
    :rtype: ``bool``

    """
    status = args.get('status', None)
    statuses = list(filter(lambda name: name != 'closed', ALERT_STATUSES.keys()))
    if status.lower() not in statuses:
        raise ValueError(f'status must be one of {statuses}.')

    status_id = ALERT_STATUSES[status.lower()]

    return varonis_update_alert(client, CLOSE_REASONS['none'], status_id, argToList(args.get('alert_id')))


def varonis_close_alert_command(client: Client, args: Dict[str, Any]) -> bool:
    """Close Varonis alert command

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['close_reason']`` Alert's close reason
        ``args['alert_id']`` Array of alert ids to be closed

    :return: Result of execution
    :rtype: ``bool``

    """
    close_reason = args.get('close_reason', None)
    close_reasons = list(filter(lambda name: not strEqual(name, 'none'), CLOSE_REASONS.keys()))
    if close_reason.lower() not in close_reasons:
        raise ValueError(f'close reason must be one of {close_reasons}')

    close_reason_id = CLOSE_REASONS[close_reason.lower()]

    return varonis_update_alert(client, close_reason_id, ALERT_STATUSES['closed'], argToList(args.get('alert_id')))


def is_xsoar_env() -> bool:
    return not not demisto.params().get('url')

'''' MAIN FUNCTION '''


def main() -> None:
    """Main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    if not is_xsoar_env():
        url = 'https://dev66f47.varonis-preprod.com'
        apiKey = 'vkey1_15536d2768e1493bac596dfe2b66e5c2_XNZhl8VzALAx2jSIEAM/I1gp4CnYJVOcvptxquXx0Hg='
        command = 'fetch-incidents'  # 'test-module'|
                                 # 'varonis-get-alerts'|
                                 # 'varonis-get-alerted-events'|
                                 # 'varonis-update-alert-status'|
                                 # 'varonis-close-alert'|
                                 # 'fetch-incidents'
        params = {
            'url': url,
            'apiKey': apiKey,
            'insecure': True,
            'proxy': False,
            'status': None,
            'threat_model': None,
            'severity': None,
            'max_fetch': None,
            'first_fetch': '1 week'
        }

        if command == 'test-module':
            pass
        elif command == 'varonis-get-alerts':
            args['threat_model_name'] = ["Deletion: Multiple directory service objects"]  # List of requested threat models
            args['ingest_time_from'] = None  # Start ingest time of the range of alerts
            args['ingest_time_to'] = None  # End ingest time of the range of alerts
            args['start_time'] = None  # Start time of the range of alerts
            args['end_time'] = None  # End time of the range of alerts
            args['alert_status'] = None  # List of required alerts status
            args['alert_severity'] = []  # List of alerts severity
            args['device_name'] = None  # List of device names
            args['user_domain_name'] = None  # User domain name
            args['user_name'] = None  # List of user names
            args['sam_account_name'] = None  # List of sam account names
            args['email'] = None  # List of emails
            args['last_days'] = None  # Number of days you want the search to go back to
            args['descending_order'] = None  # Indicates whether alerts should be ordered in newest to oldest order

        elif command == 'varonis-get-alerted-events':
            args['alert_id'] = None  # List of alert ids
            args['start_time'] = None  # Start time of the range of events
            args['end_time'] = None  # End time of the range of events
            args['descending_order'] = None  # Indicates whether events should be ordered in newest to oldest order

        elif command == 'varonis-update-alert-status':
            args['status'] = 'under investigation'  # Alert's new status
            args['alert_id'] = "2ca92ab1-b225-4eee-85ec-393875ed5389"  # Array of alert ids to be updated

        elif command == 'varonis-close-alert':
            args['close_reason'] = 'resolved'  # Alert's close reason
            args['alert_id'] = "2ca92ab1-b225-4eee-85ec-393875ed5389"  # Array of alert ids to be closed

        elif command == 'fetch-incidents':
            pass

    base_url = params['url']
    apiKey = params['apiKey']

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', True)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy
        )

        client.varonis_authenticate(apiKey)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module_command(client)
            return_results(result)

        elif command == 'varonis-get-alerts':
            return_results(varonis_get_alerts_command(client, args))

        elif command == 'varonis-get-alerted-events':
            return_results(varonis_get_alerted_events_command(client, args))

        elif command == 'varonis-update-alert-status':
            return_results(varonis_update_alert_status_command(client, args))

        elif command == 'varonis-close-alert':
            return_results(varonis_close_alert_command(client, args))

        elif command == 'fetch-incidents':
            alert_status = params.get('status', None)
            threat_model = params.get('threat_model', None)
            severity = params.get('severity', None)

            first_fetch_time = arg_to_datetime(
                arg=params.get('first_fetch', '1 week'),
                arg_name='First fetch time',
                required=True
            )

            next_run, incidents = fetch_incidents_command(  client=client, 
                                                            last_run=demisto.getLastRun(),
                                                            first_fetch_time=first_fetch_time,
                                                            alert_status=alert_status, 
                                                            threat_model=threat_model,
                                                            severity=severity)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')
                     
''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
