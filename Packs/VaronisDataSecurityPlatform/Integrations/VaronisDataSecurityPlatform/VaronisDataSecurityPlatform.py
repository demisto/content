import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Varonis Data Security Platform integration
"""

from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any, List, Tuple
from requests_ntlm import HttpNtlmAuth

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

MAX_USERS_TO_SEARCH = 5
NON_EXISTENT_SID = -1000
MAX_INCIDENTS_TO_FETCH = 50
THREAT_MODEL_ENUM_ID = 5821
ALERT_STATUSES = {'open': 1, 'under investigation': 2, 'closed': 3}
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

    def varonis_get_auth_url(self) -> str:
        """Get varonis authentication configuration

        :return: Authentication url
        :rtype: ``str``
        """
        response = self._http_request('GET', '/auth/configuration')

        demisto.debug(f'Auth configuration {response}')

        return response['authEndpoint']

    def varonis_authenticate(self, username: str, password: str, url: str) -> Dict[str, Any]:
        """Gets the authentication token using the '/auth/win' API endpoint and ntlm authentication

        :type username: ``str``
        :param username: User name with domain 'Domain\\UserMame'

        :type password: ``str``
        :param password: Password

        :type url: ``str``
        :param url: Auth url

        :return: Dict containing the authentication token, token type, expiration time (sec)
        :rtype: ``Dict[str, Any]``
        """
        ntlm = HttpNtlmAuth(username, password)
        response = self._http_request('POST', full_url=url, auth=ntlm, data='grant_type=client_credentials')
        token = response['access_token']
        token_type = response['token_type']
        self._expires_in = response['expires_in']

        demisto.debug(f'Token expires in {self._expires_in}')

        self._headers = {
            'Authorization': f'{token_type} {token}'
        }
        return response

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
            params=request_params
        )
        return response['ResultSet']

    def varonis_get_enum(self, enum_id: int) -> List[Any]:
        """Gets an enum by enum_id. Usually needs for retrieving object required for a search

        :type enum_id: ``int``
        :param enum_id: Id of enum stored in database

        :return: The list of objects required for a search filter
        :rtype: ``List[Any]``
        """
        response = self._http_request('GET', f'/api/entitymodel/enum/{enum_id}')
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
            json_data=query)

    def varonis_get_alerted_events(self, alerts: List[str], count: int, page: int,
                                   descending_order: bool) -> List[Dict[str, Any]]:
        """Get alerted events

        :type alerts: ``List[str]``
        :param alerts: List of alert ids

        :type count: ``int``
        :param count: Alerted events count

        :type page: ``int``
        :param page: Page number

        :type descendingOrder: ``bool``
        :param descendingOrder: Indicates whether events should be ordered in newest to oldest order

        :return: Alerted events
        :rtype: ``List[Dict[str, Any]]``
        """
        request_params: Dict[str, Any] = {}

        request_params['alertId'] = alerts
        request_params['maxResults'] = count
        request_params['offset'] = (page - 1) * count
        request_params['descendingOrder'] = descending_order

        return self._http_request(
            'GET',
            '/api/alert/alert/GetAlertedEvents',
            params=request_params
        )

    def varonis_get_alerts(self, threat_models: Optional[List[str]], start_time: Optional[datetime],
                           end_time: Optional[datetime], device_names: Optional[List[str]], last_days: Optional[int],
                           sid_ids: Optional[List[int]], from_alert_id: Optional[int], alert_statuses: Optional[List[str]],
                           alert_severities: Optional[List[str]], aggregate: bool, count: int,
                           page: int, descending_order: bool) -> List[Dict[str, Any]]:
        """Get alerts

        :type threat_models: ``Optional[List[str]]``
        :param threat_models: List of threat models to filter by

        :type start_time: ``Optional[datetime]``
        :param start_time: Start time of the range of alerts

        :type end_time: ``Optional[datetime]``
        :param end_time: End time of the range of alerts

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

        :type page: ``int``
        :param page: Page number

        :type descendingOrder: ``bool``
        :param descendingOrder: Indicates whether alerts should be ordered in newest to oldest order

        :return: Alerts
        :rtype: ``List[Dict[str, Any]]``
        """
        request_params: Dict[str, Any] = {}

        if threat_models and len(threat_models) > 0:
            request_params['ruleName'] = threat_models

        if start_time:
            request_params['startTime'] = start_time.isoformat()

        if end_time:
            request_params['endTime'] = end_time.isoformat()

        if device_names and len(device_names) > 0:
            request_params['deviceName'] = device_names

        if last_days:
            request_params['lastDays'] = last_days

        if sid_ids and len(sid_ids) > 0:
            request_params['sidId'] = sid_ids

        if from_alert_id is not None:
            request_params['fromAlertSeqId'] = from_alert_id

        if alert_statuses and len(alert_statuses) > 0:
            request_params['status'] = alert_statuses

        if alert_severities and len(alert_severities) > 0:
            request_params['severity'] = alert_severities

        request_params['descendingOrder'] = descending_order

        request_params['aggregate'] = aggregate
        request_params['offset'] = (page - 1) * count
        request_params['maxResult'] = count

        return self._http_request(
            'GET',
            '/api/alert/alert/GetAlerts',
            params=request_params
        )


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


def enrich_with_pagination(output: Dict[str, Any], page: int, page_size: int) -> Dict[str, Any]:
    """Enriches command output with pagination info

    :type output: ``Dict[str, Any]``
    :param output: Command output

    :type page: ``int``
    :param page: Page number

    :type page_size: ``int``
    :param page_size: Amount of elements on the page

    :return: Enriched command output
    :rtype: ``Dict[str, Any]``
    """
    output['Pagination'] = dict()
    output['Pagination']['Page'] = page
    output['Pagination']['PageSize'] = page_size
    return output


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
        'closeReasonId': close_reason_id,
        'statusId': status_id
    }

    return client.varonis_update_alert_status(query)


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
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


def fetch_incidents(client: Client, last_run: Dict[str, int], first_fetch_time: Optional[datetime], max_results: int,
                    alert_status: Optional[str], threat_model: Optional[str], severity: Optional[str]
                    ) -> Tuple[Dict[str, Optional[int]], List[dict]]:
    """This function retrieves new alerts every interval (default is 1 minute).

    :type client: ``Client``
    :param client: Http client

    :type last_run: ``Dict[str, int]``
    :param last_run:
        A dict with a key containing the latest alert id we got from last fetch

    :type first_fetch_time: ``Optional[datetime]``
    :param first_fetch_time:
        If last_run is None (first time we are fetching), it contains
        the datetime on when to start fetching incidents

    :type max_results: ``int``
    :param max_results: Maximum numbers of incidents per fetch

    :type alert_status: ``Optional[str]``
    :param alert_status: status of the alert to search for. Options are 'Open', 'Closed' or 'Under investigation'

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

    threat_models = argToList(threat_model)
    if threat_models and len(threat_models) > 0:
        validate_threat_models(client, threat_models)

    if max_results > MAX_INCIDENTS_TO_FETCH:
        raise ValueError(f'{max_results} is too big number to fetch. Max incidents to fetch is {MAX_INCIDENTS_TO_FETCH}')

    last_fetched_id = last_run.get('last_fetched_id', None)
    incidents: List[Dict[str, Any]] = []

    demisto.debug(f'Fetching incidents. Last fetched id: {last_fetched_id}')

    if last_fetched_id:
        first_fetch_time = None
    else:
        last_fetched_id = 0

    demisto.debug(f'Fetching incidents. Last fetched id: {last_fetched_id}')

    statuses = []
    if alert_status:
        statuses.append(alert_status)

    severities = get_included_severitires(severity)

    alerts = client.varonis_get_alerts(threat_models, first_fetch_time, None, None, None, None,
                                       last_fetched_id, statuses, severities, True, max_results, 1, True)

    for alert in alerts:
        id = alert['AlertSeqId']
        if not last_fetched_id or id > last_fetched_id:
            last_fetched_id = id
        guid = alert['ID']
        name = alert['Name']
        alert_time = alert['EventUTC']
        enrich_with_url(alert, client._base_url, guid)
        incident = {
            'name': f'Varonis alert {name}',
            'occurred': f'{alert_time}Z',
            'rawJSON': json.dumps(alert),
            'type': 'Varonis DSP Incident',
            'severity': convert_to_demisto_severity(alert['Severity']),
        }

        incidents.append(incident)

    next_run = {'last_fetched_id': last_fetched_id}

    return next_run, incidents


def varonis_get_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get alerts from Varonis DA

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['threat_model_name']`` List of requested threat models to retrieve
        ``args['page']`` Page number (default 1)
        ``args['max_results']`` The max number of alerts to retrieve (up to 50)
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
    max_results = args.get('max_results', None)
    start_time = args.get('start_time', None)
    end_time = args.get('end_time', None)
    alert_statuses = args.get('alert_status', None)
    alert_severities = args.get('alert_severity', None)
    device_names = args.get('device_name', None)
    page = args.get('page', '1')
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
    max_results = try_convert(
        max_results,
        lambda x: int(x),
        ValueError(f'max_results should be integer, but it is {max_results}.')
    )
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

    alert_statuses = try_convert(alert_statuses, lambda x: argToList(x))
    page = try_convert(
        page,
        lambda x: int(x),
        ValueError(f'page should be integer, but it is {page}.')
    )

    sid_ids = get_sids_by_email(client, emails) + get_sids_by_sam(client, sam_account_names) + \
        get_sids_by_user_name(client, user_names, user_domain_name)

    if alert_severities:
        for severity in alert_severities:
            if severity.lower() not in ALERT_SEVERITIES:
                raise ValueError(f'There is no severity {severity}.')

    if alert_statuses:
        for status in alert_statuses:
            if status.lower() not in ALERT_STATUSES.keys():
                raise ValueError(f'There is no status {severity}.')

    alerts = client.varonis_get_alerts(threat_model_names, start_time, end_time, device_names,
                                       last_days, sid_ids, None, alert_statuses, alert_severities, False, max_results,
                                       page, descending_order)
    outputs = dict()
    outputs['Alert'] = alerts

    page_size = len(alerts)
    if outputs:
        outputs = enrich_with_pagination(outputs, page, page_size)
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


def varonis_get_alerted_events_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get alerted events from Varonis DA

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` List of alert ids
        ``args['page']`` Page number (default 1)
        ``args['max_results']`` The max number of events to retrieve (up to 5k)
        ``args['descending_order']`` Indicates whether events should be ordered in newest to oldest order

    :return:
        A ``CommandResults`` object

    :rtype: ``CommandResults``
    """
    alerts = args.get('alert_id', None)
    page = args.get('page', '1')
    max_results = args.get('max_results', '100')
    descending_order = args.get('descending_order', True)

    alerts = try_convert(alerts, lambda x: argToList(x))
    max_results = try_convert(
        max_results,
        lambda x: int(x),
        ValueError(f'max_results should be integer, but it is {max_results}.')
    )
    page = try_convert(
        page,
        lambda x: int(x),
        ValueError(f'page should be integer, but it is {page}.')
    )

    events = client.varonis_get_alerted_events(alerts, max_results, page, descending_order)
    page_size = len(events)
    outputs = dict()
    outputs['Event'] = events

    if outputs:
        outputs = enrich_with_pagination(outputs, page, page_size)

    readable_output = tableToMarkdown('Varonis Alerted Events', events)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Varonis',
        outputs_key_field='Varonis.Event.ID',
        outputs=outputs
    )


''' MAIN FUNCTION '''


def main() -> None:
    """Main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')

    # get the service API url
    base_url = params['url']

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

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

        auth_url = client.varonis_get_auth_url()
        client.varonis_authenticate(username, password, auth_url)
        args = demisto.args()

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            alert_status = params.get('status', None)
            threat_model = params.get('threat_model', None)
            severity = params.get('severity', None)

            max_results = arg_to_number(
                arg=params.get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            first_fetch_time = arg_to_datetime(
                arg=params.get('first_fetch', '1 week'),
                arg_name='First fetch time',
                required=True
            )

            next_run, incidents = fetch_incidents(client=client, last_run=demisto.getLastRun(),
                                                  first_fetch_time=first_fetch_time,
                                                  alert_status=alert_status, threat_model=threat_model,
                                                  severity=severity,
                                                  max_results=max_results)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'varonis-get-alerts':
            return_results(varonis_get_alerts_command(client, args))

        elif demisto.command() == 'varonis-update-alert-status':
            return_results(varonis_update_alert_status_command(client, args))

        elif demisto.command() == 'varonis-close-alert':
            return_results(varonis_close_alert_command(client, args))

        elif demisto.command() == 'varonis-get-alerted-events':
            return_results(varonis_get_alerted_events_command(client, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
