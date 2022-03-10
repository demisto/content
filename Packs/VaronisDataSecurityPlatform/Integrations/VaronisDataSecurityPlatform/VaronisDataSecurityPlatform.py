"""Varonis Data Security Platform intehration
"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any, List
from requests_ntlm import HttpNtlmAuth

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

SEARCH_RESULT_RETRIES = 10
BACKOFF_FACTOR = 5
THREAT_MODEL_ENUM_ID = 5821
ALERT_STATUSES = {'Open': 1, 'Under Investigation': 2, 'Closed': 3}
CLOSE_REASONS = {
    'None': 0,
    'Resolved': 1,
    'Misconfiguration': 2,
    'Threat model disabled or deleted': 3,
    'Account misclassification': 4,
    'Legitimate activity': 5,
    'Other': 6
}
STATUSES_TO_RETRY = [304, 405]
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
    'Alert.User.IsFlagged',
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
    'Alert.By.PreivilegedAccountType',
    'Alert.By.HasFollowUpIndicators',
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
    'Event.ID',  # TODO need to clarify spec
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
    'Event.Device.ExternalIPReputationID',
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
    'Event.ID',  # TODO need to clarify spec
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
    'Event.ByUser.SAMAccountNamt',
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

    def varonis_authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """Gets the authentication token using the '/auth/win' API endpoint and ntlm authentication

        :type username: ``str``
        :param username: User name with domain 'Domain\\UserMame'

        :type password: ``str``
        :param password: Password

        :return: Dict containing the authentication token, token type, expiration time (sec) [TODO get sure that in sec]
        :rtype: ``Dict[str, Any]``
        """
        ntlm = HttpNtlmAuth(username, password)
        response = self._http_request('POST', '/auth/win', auth=ntlm, data='grant_type=client_credentials')
        token = response['access_token']
        token_type = response['token_type']
        self._expires_in = response['expires_in']
        self._headers = {
            'Authorization': f'{token_type} {token}'
        }
        return response

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


''' HELPER FUNCTIONS '''


class SearchQueryBuilder(object):
    """ Base search query builder
    """

    def __init__(
        self,
        select_columns: List[str],
        client: Client,
        entity_name: str,
        request_params: Any
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

    def build(self) -> Dict[str, Any]:
        """Generate search query

        :return: The search query
        :rtype: ``Dict[str, Any]``
        """
        query: Dict[str, Any] = dict()
        query['rows'] = {'columns': self._columns}
        query['query'] = {
            'entityName': self._entity_name,
            'requestParams': self._request_params,
            'filter': {'filterOperator': 0, 'filters': self._filters}
        }
        return query


class SearchAlertsQueryBuilder(SearchQueryBuilder):
    """ Builder class, needed for generation a search query for alerts
    """
    def __init__(self, client: Client):
        super().__init__(
            ALERT_COLUMNS,
            client,
            'Alert',
            {'searchSource': 1, 'searchSourceName': 'Alert'}  # TODO: find out where does this object come from
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
            rule = next((x for x in rule_enum if x['ruleName'] == threat), None)

            if not rule:
                raise ValueError(f'There is no threat model with name {threat}.')

            threat_object = {
                'Alert.Rule.ID': rule['ruleID'],
                'displayValue': rule['ruleName']
            }
            filter_obj['values'].append(threat_object)
        self._filters.append(filter_obj)

    def create_time_interval_filter(self, start: datetime, end: datetime):
        """Add time interval to the search query

        :type start: ``datetime``
        :param start: Start time

        :type end: ``datetime``
        :param end: End time
        """
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
            status_id = status_enum.get(status_name, None)
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
            {"searchSource": 1, "searchSourceName": "Event"}  # TODO: find out where does this object come from
        )

    def create_alert_id_filter(self, alerts: List[str]):
        """Add alert id filter to the search query

        :type alerts: ``List[str]``
        :param alerts: A list of alert ids
        """
        filter_obj: Dict[str, Any] = {
            'path': 'Event.Alert.ID',
            'operator': 'Equals',
            'values': []
        }

        if not alerts or not any(alerts):
            raise ValueError('The list of alerts can\'t be empty.')

        for alert_id in alerts:
            filter_obj['values'].append({'Event.Alert.ID': alert_id, 'displayValue': alert_id})

        self._filters.append(filter_obj)


def get_query_range(count: int, page: int):
    """Generate query for range of the search results

    :type count: ``int``
    :param count: Max amount of the search results

    :type page: ``int``
    :param page: Current page, depends on count

    :return: A query range
    :rtype: ``str``
    """
    if count:
        return f'from={(page-1)*count}&to={page*count-1}'
    return ''


def get_search_result_path(search_response: List[Any]) -> str:
    """Extracts a search result path from a search job creation response

    :type search_response: ``List[Any]``
    :param search_response: A search job creation response

    :return: A path to the search results
    :rtype: ``str``
    """
    return next(x['location'] for x in search_response if x['dataType'] == 'rows')


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
    statuses: List[str],
    threats: List[str],
    start: datetime,
    end: datetime,
    count: int,
    page: int
) -> Dict[str, Any]:
    """Searches and retrieves alerts

    :type client: ``Client``
    :param client: Http client

    :type statuses: ``List[str]``
    :param statuses: A list of statuses

    :type threats: ``List[str]``
    :param threats: A list of threats

    :type start: ``datetime``
    :param start: Start time

    :type end: ``datetime``
    :param end: End time

    :type count: ``int``
    :param count: Max amount of the search results

    :type page: ``int``
    :param page: Current page, depends on count

    :return: Alerts
    :rtype: ``Dict[str, Any]``
    """
    builder = SearchAlertsQueryBuilder(client)

    if statuses and any(statuses):
        builder.create_alert_status_filter(statuses)
    if threats and any(threats):
        builder.create_threat_model_filter(threats)
    if start and end:
        builder.create_time_interval_filter(start, end)

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
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


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
        ``args['Start_time']`` Start time of the range of alerts
        ``args['End_time']`` End time of the range of alerts
        ``args['Alert_Status']`` List of required alerts status

    :return:
        A ``CommandResults`` object

    :rtype: ``CommandResults``
    """
    threat_model_names = args.get('threat_model_name', None)
    max_results = args.get('max_results', None)
    start_time = args.get('Start_time', None)
    end_time = args.get('End_time', None)
    alert_statuses = args.get('Alert_Status', None)
    page = args.get('page', '1')

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

    result = varonis_get_alerts(client, alert_statuses, threat_model_names, start_time, end_time, max_results, page)
    outputs = create_output(ALERT_OUTPUT, result['rows'])
    page_size = result['rowsCount']
    outputs = enrich_with_pagination(outputs, page, page_size)
    return CommandResults(
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
        ``args['Status']`` Alert's new status
        ``args['Alert_id']`` Array of alert ids to be updated

    :return: Result of execution
    :rtype: ``bool``

    """
    status = args.get('Status', None)
    statuses = list(filter(lambda name: name != 'Closed', ALERT_STATUSES.keys()))
    if status not in statuses:
        raise ValueError(f'status must be one of {statuses}.')

    status_id = ALERT_STATUSES[status]

    return varonis_update_alert(client, CLOSE_REASONS['None'], status_id, argToList(args.get('Alert_id')))


def varonis_close_alert_command(client: Client, args: Dict[str, Any]) -> bool:
    """Close Varonis alert command

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['Close_Reason']`` Alert's close reason
        ``args['Alert_id']`` Array of alert ids to be closed

    :return: Result of execution
    :rtype: ``bool``

    """
    close_reason = args.get('Close_Reason', None)
    close_reasons = list(filter(lambda name: name != 'None', CLOSE_REASONS.keys()))
    if close_reason not in close_reasons:
        raise ValueError(f'close reason must be one of {close_reasons}')

    close_reason_id = CLOSE_REASONS[close_reason]

    return varonis_update_alert(client, close_reason_id, ALERT_STATUSES['Closed'], argToList(args.get('Alert_id')))


def varonis_get_alerted_events_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get alerted events from Varonis DA

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['Alert_id']`` List of alert ids
        ``args['page']`` Page number (default 1)
        ``args['max_results']`` The max number of alerts to retrieve (up to 5k)

    :return:
        A ``CommandResults`` object

    :rtype: ``CommandResults``
    """
    alerts = args.get('Alert_id', None)
    page = args.get('page', '1')
    max_results = args.get('max_results', None)

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
    outputs = enrich_with_pagination(outputs, page, page_size)
    return CommandResults(
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

    username = demisto.params().get('credentials', {}).get('identifier')
    password = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/DatAdvantage')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy
        )

        client.varonis_authenticate(username, password)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'varonis-get-alerts':
            return_results(varonis_get_alerts_command(client, demisto.args()))
        elif demisto.command() == 'varonis-update-alert-status':
            varonis_update_alert_status_command(client, demisto.args())
        elif demisto.command() == 'varonis-close-alert':
            varonis_close_alert_command(client, demisto.args())
        elif demisto.command() == 'varonis-get-alerted-events':
            return_results(varonis_get_alerted_events_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
