"""Varonis Data Security Platform integration
"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
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
MAX_INCIDENTS_TO_FETCH = 100
SEARCH_RESULT_RETRIES = 10
BACKOFF_FACTOR = 5
THREAT_MODEL_ENUM_ID = 5821
ALERT_STATUSES = {'open': 1, 'under investigation': 2, 'closed': 3}
ALERT_SEVERITIES = {'high': 0, 'medium': 1, 'low': 2}
CLOSE_REASONS = {
    'none': 0,
    'resolved': 1,
    'misconfiguration': 2,
    'threat model disabled or deleted': 3,
    'account misclassification': 4,
    'legitimate activity': 5,
    'other': 6
}
STATUSES_TO_RETRY = [304, 405, 206]
ALERT_COLUMNS = [
    'Alert.ID',
    'Alert.Rule.Name',
    'Alert.Time',
    'Alert.Rule.Severity.Name',
    'Alert.Rule.Category.Name',
    'Alert.Location.CountryName',
    'Alert.Location.SubdivisionName',
    'Alert.Status.Name',
    'Alert.CloseReason.Name',
    'Alert.Location.BlacklistedLocation',
    'Alert.Location.AbnormalLocation',
    'Alert.EventsCount',
    'Alert.User.Name',
    'Alert.User.SamAccountName',
    'Alert.User.AccountType.Name',
    'Alert.User.Department',
    'Alert.Data.IsFlagged',
    'Alert.Data.IsSensitive',
    'Alert.Filer.Platform.Name',
    'Alert.Asset.Path',
    'Alert.Filer.Name',
    'Alert.Device.HostName',
    'Alert.Device.IsMaliciousExternalIP',
    'Alert.Device.ExternalIPThreatTypesName'
]

ALERT_OUTPUT = [
    'Alert.ID',
    'Alert.Name',
    'Alert.Time',
    'Alert.Severity',
    'Alert.Category',
    'Alert.Country',
    'Alert.State',
    'Alert.Status',
    'Alert.CloseReason',
    'Alert.BlacklistLocation',
    'Alert.AbnormalLocation',
    'Alert.NumOfAlertedEvents',
    'Alert.UserName',
    'Alert.By.SamAccountName',
    'Alert.By.PrivilegedAccountType',
    'Alert.By.Department',
    'Alert.On.ContainsFlaggedData',
    'Alert.On.ContainsSensitiveData',
    'Alert.On.Platform',
    'Alert.On.Asset',
    'Alert.On.FileServerOrDomain',
    'Alert.Device.Name',
    'Alert.Device.ContainMaliciousExternalIP',
    'Alert.Device.IPThreatTypes'
]

EVENT_COLUMNS = [
    'Event.ID',
    'Event.Type.Name',
    'Event.TimeUTC',
    'Event.Status.Name',
    'Event.Description',
    'Event.Location.CountryName',
    'Event.Location.SubdivisionName',
    'Event.Location.BlacklistedLocation',
    'Event.Operation.Name',
    'Event.EventBy.Name',
    'Event.EventBy.Type.Name',
    'Event.EventBy.AccountType.Name',
    'Event.EventBy.SamAccountName',
    'Event.EventBy.Domain.Name',
    'Event.EventBy.IsDisabled',
    'Event.EventBy.IsStale',
    'Event.EventBy.IsLockout',
    'Event.IP',
    'Event.Device.IsMaliciousExternalIP',
    'Event.Device.ExternalIPReputationName',
    'Event.Device.ExternalIPThreatTypesName',
    'Event.EventOnObjectName',
    'Event.EventOnResource.ObjectType.Name',
    'Event.EventOnResource.Folder.Filer.Platform.Name',
    'Event.EventOnResource.Folder.IsSensitive',
    'Event.EventOnResource.Folder.Filer.Name',
    'Event.EventOnUser.IsDisabled',
    'Event.EventOnUser.IsLockout',
    'Event.EventOnUser.SamAccountName',
    'Event.EventOnUser.AccountType.Name',
    'Event.Destination.IP',
    'Event.Destination.DeviceName'
]

EVENT_OUTPUT = [
    'Event.ID',
    'Event.Type',
    'Event.UTCTime',
    'Event.Status',
    'Event.Description',
    'Event.Country',
    'Event.State',
    'Event.Details.IsBlacklist',
    'Event.Details.Operation',
    'Event.ByUser.Name',
    'Event.ByUser.UserType',
    'Event.ByUser.UserAccountType',
    'Event.ByUser.SAMAccountName',
    'Event.ByUser.Domain',
    'Event.ByUser.DisabledAccount',
    'Event.ByUser.StaleAccount',
    'Event.ByUser.LockoutAccounts',
    'Event.SourceIP',
    'Event.IsMaliciousIP',
    'Event.IPReputation',
    'Event.IPThreatType',
    'Event.OnObject.Name',
    'Event.OnObject.ObjectType',
    'Event.OnObject.Platform',
    'Event.OnObject.IsSensitive',
    'Event.OnObject.FileServerOrDomain',
    'Event.OnObject.IsDisabledAccount',
    'Event.OnObject.IsLockOutAccount',
    'Event.OnObject.SAMAccountName',
    'Event.OnObject.UserAccountType',
    'Event.OnObject.DestinationIP',
    'Event.OnObject.DestinationDevice'
]


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

    def varonis_get_users_by_user_name(self, user_name: str) -> List[Any]:
        """Search users by user name

        :type user_name: ``str``
        :param user_name: user name to search by

        :return: The list of users
        :rtype: ``Dict[str, Any]``
        """
        return self.varonis_get_users(user_name, '[\'ObjName\']')

    def varonis_get_users_by_sam_account_name(self, sam_account_name: str) -> List[Any]:
        """Search users by sam account name

        :type sam_account_name: ``str``
        :param sam_account_name: sam account name to search by

        :return: The list of users
        :rtype: ``Dict[str, Any]``
        """
        return self.varonis_get_users(sam_account_name, '[\'SamAccountName\']')

    def varonis_get_users_by_email(self, email: str) -> List[Any]:
        """Search users by email

        :type email: ``str``
        :param email: email to search by

        :return: The list of users
        :rtype: ``Dict[str, Any]``
        """
        return self.varonis_get_users(email, '[\'Email\']')

    def varonis_get_users(self, search_string: str, columns: str) -> List[Any]:
        """Search users by search string

        :type search_string: ``str``
        :param search_string: search string

        :type columns: ``str``
        :param columns: columns to search by

        :return: The list of users
        :rtype: ``Dict[str, Any]``
        """
        request_params: Dict[str, Any] = {}
        request_params['columns'] = columns
        request_params['searchString'] = search_string
        request_params['limit'] = 1000

        return self._http_request(
            'GET',
            'api/userdata/users',
            params=request_params
        )['ResultSet']

    def varonis_get_enum(self, enum_id: int) -> List[Any]:
        """Gets an enum by enum_id. Usually needs for retrieving object required for a search

        :type enum_id: ``int``
        :param enum_id: Id of enum stored in database

        :return: The list of objects required for a search filter
        :rtype: ``List[Any]``
        """
        response = self._http_request('GET', f'/api/entitymodel/enum/{enum_id}')
        return response

    def varonis_execute_search(self, query: Dict[str, Any]) -> List[Any]:
        """Creates a search job on the server side. Retrieves the path to the results

        :type query: ``Dict[str, Any]``
        :param query: A collection of filters

        :return: a list of objects with the path to results and termination
        :rtype: ``List[Any]``
        """
        response = self._http_request('POST', '/api/search/v2/search', json_data=query)
        return response

    def varonis_get_search_result(
        self,
        search_location: str,
        url_query: str,
        retries=SEARCH_RESULT_RETRIES,
        backoff_factor=BACKOFF_FACTOR,
        status_list_to_retry=STATUSES_TO_RETRY
    ) -> Dict[str, Any]:
        """Get results generated by a search job. Location can be retrieved after the search job creation

        :type search_location: ``str``
        :param search_location: The location of the results generated by the search job

        :type url_query: ``str``
        :param url_query: Additional filter (e.g. a range of results)

        :type retries: ``int``
        :param retries: Amount of retries, needs for waiting while search job will be done

        :type backoff_factor: ``int``
        :param backoff_factor: Backoff factor

        :type status_list_to_retry: ``List[int]``
        :param status_list_to_retry: Http codes for retrying request

        :return: Search results
        :rtype: ``Dict[str, Any]``
        """
        response = self._http_request(
            'GET',
            f'/api/search/{search_location}?{url_query}',
            retries=retries,
            status_list_to_retry=status_list_to_retry,
            backoff_factor=backoff_factor)
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

    def varonis_get_xsoar_alerts(self, first_fetch_time: Optional[datetime], from_alert_id: Optional[int], max_results: int,
                                 alert_status: Optional[str], threat_models: Optional[List[str]], severity: Optional[str]
                                 ) -> List[Dict[str, Any]]:
        """Get alert ids to retrieve from search api.

        :type first_fetch_time: ``Optional[datetime]``
        :param first_fetch_time:
            If last_run is None (first time we are fetching), it contains
            the datetime on when to start fetching incidents

        :type from_alert_id: ``Optional[int]``
        :param from_alert_id:
            Alert id to fetch from

        :type max_results: ``int``
        :param max_results: Maximum numbers of incidents per fetch

        :type alert_status: ``Optional[str]``
        :param alert_status: status of the alert to search for. Options are 'Open', 'Closed' or 'Under investigation'

        :type threat_models: ``Optional[List[str]]``
        :param threat_model: List of threat model names of alerts to fetch

        :type severity: ``Optional[str]``
        :param severity: severity of the alert to search for. Options are 'High', 'Medium' or 'Low'

        :return: Alerts
        :rtype: ``List[Dict[str, Any]]``

        """
        request_params: Dict[str, Any] = {}

        if threat_models and len(threat_models) > 0:
            request_params['threatModels'] = threat_models

        if severity:
            request_params['severity'] = severity

        if alert_status:
            request_params['status'] = ALERT_STATUSES[alert_status.lower()]

        if from_alert_id:
            request_params['fromAlertId'] = from_alert_id
        elif first_fetch_time:
            request_params['fromDate'] = first_fetch_time.isoformat()

        request_params['bulkSize'] = max_results

        return self._http_request(
            'GET',
            '/api/alert/alert/GetXsoarAlerts',
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


class SearchQueryBuilder(object):
    """ Base search query builder
    """

    def __init__(
        self,
        select_columns: List[str],
        client: Client,
        entity_name: str,
        request_params: Any,
        alert_id_column_name: str
    ):
        """
        :type select_columns: ``List[str]``
        :param select_columns: Columns need to be retrieved

        :type client: ``Client``
        :param client: Http client
        """
        self._filters: List[Any] = []
        self._columns = select_columns
        self._client = client
        self._url_query = ''
        self._entity_name = entity_name
        self._request_params = request_params
        self._alert_id_column_name = alert_id_column_name
        self._ordering: List[Any] = []

    def create_alert_id_filter(self, alerts: List[str]):
        """Add alert id filter to the search query

        :type alerts: ``List[str]``
        :param alerts: A list of alert ids
        """
        filter_obj: Dict[str, Any] = {
            'path': self._alert_id_column_name,
            'operator': 'In',
            'values': []
        }

        if not alerts or not any(alerts):
            raise ValueError('The list of alerts can\'t be empty.')

        for alert_id in alerts:
            filter_obj['values'].append({self._alert_id_column_name: alert_id, 'displayValue': alert_id})

        self._filters.append(filter_obj)

    def create_ordering(self, order_column: str, sort_order: str):
        self._ordering.append({
            'path': order_column,
            "sortOrder": sort_order
        })

    def build(self) -> Dict[str, Any]:
        """Generate search query

        :return: The search query
        :rtype: ``Dict[str, Any]``
        """
        query: Dict[str, Any] = dict()
        query['rows'] = {
            'columns': self._columns,
            'ordering': self._ordering
        }
        query['query'] = {
            'entityName': self._entity_name,
            'filter': {'filterOperator': 0, 'filters': self._filters}
        }

        query['requestParams'] = self._request_params

        return query


class SearchAlertsQueryBuilder(SearchQueryBuilder):
    """ Builder class, needed for generation a search query for alerts
    """

    def __init__(self, client: Client):
        super().__init__(
            ALERT_COLUMNS,
            client,
            'Alert',
            {'searchSource': 1, 'searchSourceName': 'Alert'},
            'Alert.ID'
        )

    def create_threat_model_filter(self, threats: List[str]):
        """Add threat model filter to the search query

        :type threats: ``List[str]``
        :param threats: A list of threats
        """
        rule_enum = self._client.varonis_get_enum(THREAT_MODEL_ENUM_ID)
        filter_obj: Dict[str, Any] = {
            'path': 'Alert.Rule.ID',
            'operator': 'In',
            'values': []
        }

        for threat in threats:
            rule = next((x for x in rule_enum if strEqual(x['ruleName'], threat)), None)

            if not rule:
                raise ValueError(f'There is no threat model with name {threat}.')

            threat_object = {
                'Alert.Rule.ID': rule['ruleID'],
                'displayValue': rule['ruleName']
            }
            filter_obj['values'].append(threat_object)
        self._filters.append(filter_obj)

    def create_last_days_filter(self, last_days: int):
        """Add last days to the search query

        :type last_days: ``int``
        :param last_days: Number of days you want the search to go back to
        """
        filter_obj: Dict[str, Any] = {
            'path': 'Alert.Time',
            'operator': 'LastDays',
            'values': [{
                'Alert.Time': last_days,
                'displayValue': last_days
            }]
        }

        self._filters.append(filter_obj)

    def create_time_interval_filter(self, start: datetime, end: Optional[datetime]):
        """Add time interval to the search query

        :type start: ``datetime``
        :param start: Start time

        :type end: ``datetime``
        :param end: End time
        """
        if not end:
            future = datetime.now() + timedelta(days=7)
            if start > future:
                end = start + timedelta(days=7)
            else:
                end = future

        if start > end:
            raise ValueError(f'start_time should be greater or equal than end_time, {start} > {end}.')

        filter_obj: Dict[str, Any] = {
            'path': 'Alert.Time',
            'operator': 'Between',
            'values': [
                {
                    'Alert.Time': start.isoformat(),
                    'displayValue': start.isoformat(),
                    'Alert.Time0': end.isoformat()
                }
            ]
        }
        self._filters.append(filter_obj)

    def create_alert_severity_filter(self, severities: List[str]):
        """Add alert severities filter to the search query

        :type severities: ``List[str]``
        :param severities: A list of severities
        """
        severity_enum = ALERT_SEVERITIES
        filter_obj: Dict[str, Any] = {
            'path': 'Alert.Rule.Severity.ID',
            'operator': 'In',
            'values': []
        }

        for severity_name in severities:
            severity_id = severity_enum.get(severity_name.lower(), None)
            if severity_id is None:
                raise ValueError(f'There is no alert severity with name {severity_name}.')

            severity_object = {
                'Alert.Rule.Severity.ID': severity_id,
                'displayValue': severity_name
            }
            filter_obj['values'].append(severity_object)
        self._filters.append(filter_obj)

    def create_alert_device_name_filter(self, device_names: List[str]):
        """Add alert device names filter to the search query

        :type device_names: ``List[str]``
        :param device_names: A list of device names
        """

        filter_obj: Dict[str, Any] = {
            'path': 'Alert.Device.HostName',
            'operator': 'In',
            'values': []
        }

        for device_name in device_names:
            device_object = {
                'Alert.Device.HostName': device_name,
                'displayValue': device_name
            }
            filter_obj['values'].append(device_object)
        self._filters.append(filter_obj)

    def create_alert_user_name_filter(self, user_names: List[str], user_domain_name: str):
        """Add alert user names filter to the search query

        :type user_names: ``List[str]``
        :param user_names: A list of user names

        :type user_domain_name: ``str``
        :param user_domain_name: User domain name
        """
        sidIds: List[int] = []

        for user_name in user_names:
            users = self._client.varonis_get_users_by_user_name(user_name)

            for user in users:
                if (strEqual(user['DisplayName'], user_name)
                        and (not user_domain_name or strEqual(user['DomainName'], user_domain_name))):
                    sidIds.append(user['Id'])

        self.create_alert_sid_id_filter(sidIds)

    def create_alert_sam_account_name_filter(self, sam_account_names: List[str]):
        """Add alert sam account name filter to the search query

        :type sam_account_names: ``List[str]``
        :param sam_account_names: A list of sam account names
        """
        sidIds: List[int] = []

        for sam_account_name in sam_account_names:
            users = self._client.varonis_get_users_by_sam_account_name(sam_account_name)

            for user in users:
                if strEqual(user['SAMAccountName'], sam_account_name):
                    sidIds.append(user['Id'])

        self.create_alert_sid_id_filter(sidIds)

    def create_alert_email_filter(self, emails: List[str]):
        """Add alert email filter to the search query

        :type emails: ``List[str]``
        :param emails: A list of emails
        """
        sidIds: List[int] = []

        for email in emails:
            users = self._client.varonis_get_users_by_email(email)

            for user in users:
                if strEqual(user['Email'], email):
                    sidIds.append(user['Id'])

        self.create_alert_sid_id_filter(sidIds)

    def create_alert_sid_id_filter(self, sidIds: List[int]):
        """Add alert sid id filter to the search query

        :type sidIds: ``List[int]``
        :param sidIds: A list of sid ids
        """
        filter_obj: Dict[str, Any] = {
            'path': 'Alert.User.SidID',
            'operator': 'In',
            'values': []
        }

        if len(sidIds) == 0:
            sidIds.append(NON_EXISTENT_SID)

        for sidId in sidIds:
            user_object = {
                'Alert.User.SidID': sidId,
            }
            filter_obj['values'].append(user_object)

        self._filters.append(filter_obj)

    def create_alert_status_filter(self, statuses: List[str]):
        """Add alert statuses filter to the search query

        :type statuses: ``List[str]``
        :param statuses: A list of statuses
        """
        status_enum = ALERT_STATUSES
        filter_obj: Dict[str, Any] = {
            'path': 'Alert.Status.ID',
            'operator': 'In',
            'values': []
        }

        for status_name in statuses:
            status_id = status_enum.get(status_name.lower(), None)
            if not status_id:
                raise ValueError(f'There is no alert status with name {status_name}.')

            status_object = {
                'Alert.Status.ID': status_id,
                'displayValue': status_name
            }
            filter_obj['values'].append(status_object)
        self._filters.append(filter_obj)


class SearchEventQueryBuilder(SearchQueryBuilder):
    def __init__(self, client: Client):
        super().__init__(
            EVENT_COLUMNS,
            client,
            'Event',
            {"searchSource": 1, "searchSourceName": "Event"},
            'Event.Alert.ID'
        )


def get_query_range(count: int, page: int):
    """Generate query for range of the search results

    :type count: ``int``
    :param count: Max amount of the search results

    :type page: ``int``
    :param page: Current page, depends on count

    :return: A query range
    :rtype: ``str``
    """
    if page < 1:
        raise ValueError('page value can\'t be less than  1')

    if count < 1:
        raise ValueError('max results value can\'t be less than  1')

    return f'from={(page-1)*count + 1}&to={page*count}'


def get_search_result_path(search_response: List[Any]) -> str:
    """Extracts a search result path from a search job creation response

    :type search_response: ``List[Any]``
    :param search_response: A search job creation response

    :return: A path to the search results
    :rtype: ``str``
    """
    return next(x['location'] for x in search_response if strEqual(x['dataType'], 'rows'))


def create_output(columns: List[str], rows: List[List[Any]]) -> Dict[str, Any]:
    """Maps Varonis response to xsoar

    :type columns: ``List[str]``
    :param columns: Xsoar columns

    :type rows: ``List[List[Any]]``
    :param rows: Output values retrieved from Varonis

    :return: Tree like mapping
    :rtype: ``Dict[str, Any]``
    """
    outputs: Dict[str, List[Any]] = dict()
    for row in rows:
        out_obj: Dict[str, Any] = dict()
        for i in range(0, len(columns)):
            path = columns[i].split('.')
            if path[0] not in outputs:
                outputs[path[0]] = []
            temp_obj = out_obj
            part = None
            for p in range(1, len(path)):
                part = path[p]
                if p >= len(path) - 1:
                    break
                if part not in temp_obj:
                    temp_obj[part] = dict()
                temp_obj = temp_obj[part]

            if part is None:
                raise ValueError(f'{columns[i]}')
            temp_obj[part] = row[i]
        outputs[path[0]].append(out_obj)
    return outputs


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


def execute_search_query(client: Client, query: Any, data_range: str) -> Dict[str, Any]:
    """Execute search job and waiting for the results

    :type client: ``Client``
    :param client: Http client

    :type query: ``Any``
    :param query: Search query

    :type data_range: ``str``
    :param data_range: http url query for getting range of data

    :return: Search result
    :rtype: ``Dict[str, Any]``
    """
    response = client.varonis_execute_search(query)
    location = get_search_result_path(response)

    search_result = client.varonis_get_search_result(location, data_range, SEARCH_RESULT_RETRIES)
    return search_result


def varonis_get_alerts(
        client: Client,
        statuses: Optional[List[str]],
        threats: Optional[List[str]],
        start: Optional[datetime],
        end: Optional[datetime],
        count: int,
        page: int,
        alert_guids: Optional[List[str]],
        severities: Optional[List[str]],
        device_names: Optional[List[str]],
        user_domain_name: str,
        user_names: Optional[List[str]],
        sam_account_names: Optional[List[str]],
        emails: Optional[List[str]],
        last_days: Optional[int]
) -> Dict[str, Any]:
    """Searches and retrieves alerts

    :type client: ``Client``
    :param client: Http client

    :type statuses: ``Optional[List[str]]``
    :param statuses: A list of statuses

    :type threats: ``Optional[List[str]]``
    :param threats: A list of threats

    :type start: ``Optional[datetime]``
    :param start: Start time

    :type end: ``Optional[datetime]``
    :param end: End time

    :type count: ``int``
    :param count: Max amount of the search results

    :type page: ``int``
    :param page: Current page, depends on count

    :type alert_guids: ``Optional[List[str]]``
    :param alert_guids: List alert guids to search

    :type severities: ``Optional[List[str]]``
    :param severities: A list of severities

    :type device_names: ``Optional[List[str]]``
    :param device_names: A list of device names

    :type user_domain_name: ``str``
    :param user_domain_name: User domain name

    :type user_names: ``str``
    :param user_names: User names

    :type sam_account_names: ``str``
    :param sam_account_names: Sam account names

    :type emails: ``str``
    :param emails: List of emails

    :type last_days: ``Optional[int]``
    :param last_days: Number of days you want the search to go back to

    :return: Alerts
    :rtype: ``Dict[str, Any]``
    """
    builder = SearchAlertsQueryBuilder(client)

    if statuses and any(statuses):
        builder.create_alert_status_filter(statuses)
    if threats and any(threats):
        builder.create_threat_model_filter(threats)
    if start:
        builder.create_time_interval_filter(start, end)
    if alert_guids and len(alert_guids) > 0:
        builder.create_alert_id_filter(alert_guids)
    if severities and any(severities):
        builder.create_alert_severity_filter(severities)
    if device_names and any(device_names):
        builder.create_alert_device_name_filter(device_names)
    if user_names and any(user_names):
        builder.create_alert_user_name_filter(user_names, user_domain_name)
    if sam_account_names and any(sam_account_names):
        builder.create_alert_sam_account_name_filter(sam_account_names)
    if emails and any(emails):
        builder.create_alert_email_filter(emails)
    if last_days:
        builder.create_last_days_filter(last_days)
    builder.create_ordering('Alert.Time', 'Asc')

    query = builder.build()
    data_range = get_query_range(count, page)

    return execute_search_query(client, query, data_range)


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
    output['Url'] = urljoin(baseUrl, f'/#/app/analytics/entity/Alert/{id}')
    return output


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


def varonis_get_alerted_events(client: Client, alerts: List[str], count: int, page: int) -> Dict[str, Any]:
    """Searches and retrieves alerted events

    :type client: ``Client``
    :param client: Http client

    :type alerts: ``List[str]``
    :param alerts: A list of alert ids

    :type count: ``int``
    :param count: Max amount of the search results

    :type page: ``int``
    :param page: Current page, depends on count

    :return: Alerted events
    :rtype: ``Dict[str, Any]``
    """
    builder = SearchEventQueryBuilder(client)
    builder.create_alert_id_filter(alerts)
    builder.create_ordering('Event.TimeUTC', 'Asc')
    query = builder.build()
    data_range = get_query_range(count, page)

    return execute_search_query(client, query, data_range)


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

    alerts = client.varonis_get_xsoar_alerts(first_fetch_time=first_fetch_time, from_alert_id=last_fetched_id,
                                             max_results=max_results, alert_status=alert_status,
                                             threat_models=threat_models,
                                             severity=severity)

    for alert in alerts:
        id = alert['Id']
        if not last_fetched_id or id > last_fetched_id:
            last_fetched_id = id
        guid = alert['Guid']
        name = alert['Name']
        alert_time = alert['Time']
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

    result = varonis_get_alerts(client, alert_statuses, threat_model_names, start_time, end_time,
                                max_results, page, None, alert_severities, device_names, user_domain_name,
                                user_names, sam_account_names, emails, last_days)
    outputs = create_output(ALERT_OUTPUT, result['rows'])
    page_size = result['rowsCount']
    alerts = []
    if outputs:
        outputs = enrich_with_pagination(outputs, page, page_size)
        alerts = outputs['Alert']
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
        ``args['max_results']`` The max number of alerts to retrieve (up to 5k)

    :return:
        A ``CommandResults`` object

    :rtype: ``CommandResults``
    """
    alerts = args.get('alert_id', None)
    page = args.get('page', '1')
    max_results = args.get('max_results', '100')

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

    result = varonis_get_alerted_events(client, alerts, max_results, page)
    outputs = create_output(EVENT_OUTPUT, result['rows'])
    page_size = result['rowsCount']
    events = []
    if outputs:
        outputs = enrich_with_pagination(outputs, page, page_size)
        events = outputs['Event']

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
