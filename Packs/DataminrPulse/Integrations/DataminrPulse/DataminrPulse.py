"""Dataminr Pulse Integration for Cortex XSOAR (aka Demisto)."""

from functools import reduce
from operator import concat
from typing import Optional, Callable, Tuple

import urllib3

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

# Base URL for the Dataminr Pulse API.
BASE_URL = 'https://gateway.dataminr.com'

ENDPOINTS = {
    # Authentication endpoint for the Dataminr Pulse API.
    'AUTH_ENDPOINT': '/auth/2/token',
    # Watchlists endpoint for the Dataminr Pulse API.
    'WATCHLISTS_ENDPOINT': '/account/2/get_lists',
    # Alerts endpoint for the Dataminr Pulse API.
    'ALERTS_ENDPOINT': '/api/3/alerts',
    # Related Alerts endpoint for the Dataminr Pulse API.
    'RELATED_ALERTS_ENDPOINT': 'alerts/2/get_related'
}

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

# Date format for displaying date in human-readable format in war room.
HR_DATE_FORMAT = '%d %b %Y, %I:%M %p UTC'

ALERT_VERSION = 14

OK_CODES = (200, 201, 401)
DEFAULT_NUMBER_OF_ALERTS_TO_RETRIEVE = 40
MAX_NUMBER_OF_ALERTS_TO_RETRIEVE = 3333
STATUS_LIST_TO_RETRY = (429, 500)
EARLY_EXPIRY_TIME = 30000  # in milliseconds

ERRORS = {
    'INVALID_JSON_OBJECT': 'Failed to parse json object from response: {}.',
    'UNAUTHORIZED_REQUEST': 'Unauthorized request: {}.',
    'GENERAL_AUTH_ERROR': 'Error occurred while creating an authorization token. '
                          'Please check the Client ID, Client Secret {}.',
    'NOT_MATCHED_WATCHLIST_NAMES': 'No matching watchlist data was found for the watchlist names configured in the '
                                   'instance.',
    'INVALID_MAX_NUM': ''.join(('{} is invalid value for num. Value of num should be between 0 to ',
                                str(MAX_NUMBER_OF_ALERTS_TO_RETRIEVE), '.')),
    'INVALID_MAX_FETCH': '{} is invalid value for max_fetch. Value of max_fetch should be greater than or equal to 0.',
    'AT_LEAST_ONE_REQUIRED': 'At least {} or {} is required.',
    'EITHER_ONE_REQUIRED': 'Either {} or {} is required.',
    'INVALID_REQUIRED_PARAMETER': '{} is a required field. Please provide correct input.'
}

ALERT_TYPE_TO_INCIDENT_SEVERITY = {
    "Alert": 1,
    "Urgent": 2,
    "Flash": 3
}

# Output prefix for the alerts.
OUTPUT_PREFIX_ALERTS = 'DataminrPulse.Alerts'
# Output prefix for the lists.
OUTPUT_PREFIX_WATCHLISTS = 'DataminrPulse.WatchLists'
# Output prefix for the cursor.
OUTPUT_PREFIX_CURSOR = 'DataminrPulse.Cursor'

''' CLIENT CLASS '''


class DataminrPulseClient(BaseClient):
    """DataminrPulseClient class to interact with the Dataminr Pulse API."""

    def __init__(self, client_id: str = '', client_secret: str = '', verify: bool = False, proxy: bool = False):
        """
        Constructor for the DataminrPulseClient class.

        :type client_id: ``str``
        :param client_id: Client ID to be used for authentication.

        :type client_secret: ``str``
        :param client_secret: Client Secret to be used for authentication.

        :type verify: ``bool``
        :param verify: Whether the request should verify the SSL certificate.

        :type proxy: ``bool``
        :param proxy: Whether to run the integration using the system proxy.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = BASE_URL
        super().__init__(base_url=self.base_url, verify=verify, proxy=proxy, headers={})

    def http_request(self, method, url_suffix, params=None, status_list_to_retry=STATUS_LIST_TO_RETRY,
                     backoff_factor=30, retries=3, internal_retries=3,
                     **kwargs) -> Optional[Dict]:
        """
        Method to override private _http_request of BaseClient to handle specific status code.

        :type method: ``str``
        :param method: The HTTP method, for example: GET, POST, and so on.

        :type url_suffix: ``str``
        :param url_suffix: The API endpoint.

        :type params: ``Dict``
        :param params: URL parameters to specify the query.

        :type status_list_to_retry: ``iterable``
        :param status_list_to_retry: A set of integer HTTP status codes that we should force a retry on.

        :type backoff_factor ``float``
        :param backoff_factor: A backoff factor to apply between attempts

        :type retries: ``int``
        :param retries: How many retries should be made in case of a failure.

        :type internal_retries: ``int``
        :param internal_retries: How many retries should be made in case of an auth failure.

        :return: Response Dict.
        :rtype: ``Optional[Dict]``
        """
        # Adds a valid authentication token to the headers.
        dma_token = self.get_dma_token(use_refresh_token=True)
        self._headers.update({'Authorization': f'Dmauth {dma_token}'})
        res = self._http_request(method=method, url_suffix=url_suffix, params=params,
                                 status_list_to_retry=status_list_to_retry, backoff_factor=backoff_factor,
                                 retries=retries, resp_type='response', ok_codes=OK_CODES, **kwargs)
        try:
            json_data = res.json()
        except ValueError as exception:
            raise DemistoException(ERRORS['INVALID_JSON_OBJECT'].format(res.content), exception)
        # If the success response is received, then return it.
        if res.status_code in [200, 201]:
            return json_data

        # If authentication failure happens.
        if res.status_code in [401]:
            if internal_retries > 0:
                dma_token = self.get_dma_token(use_refresh_token=False)
                self._headers.update({'Authorization': f'Dmauth {dma_token}'})
                internal_retries = internal_retries - 1
                return self.http_request(method=method, url_suffix=url_suffix, params=params,
                                         status_list_to_retry=status_list_to_retry, backoff_factor=backoff_factor,
                                         retries=retries, internal_retries=internal_retries)
            try:
                err_msg = ERRORS['UNAUTHORIZED_REQUEST'].format(str(res.json()))
            except ValueError:
                err_msg = ERRORS['UNAUTHORIZED_REQUEST'].format(str(res))
            raise DemistoException(err_msg)
        return None

    def update_refresh_token(self, refresh_token: str) -> Optional[str]:
        """
        Update a refresh token using the given client credentials and save it in the integration context.

        :type refresh_token: ``str``
        :param refresh_token: Refresh token.

        :return: DMA token if no error occurred.
        :rtype: ``str`` or ``None``
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        try:
            res = super()._http_request(method='POST', url_suffix=ENDPOINTS['AUTH_ENDPOINT'], resp_type='response',
                                        headers=headers, data=data, ok_codes=OK_CODES,
                                        status_list_to_retry=STATUS_LIST_TO_RETRY)
            try:
                res = res.json()
            except ValueError as exception:
                demisto.error(ERRORS['INVALID_JSON_OBJECT'].format(res.content), exception)
                return None
            if 'errors' in res:
                demisto.error(ERRORS['GENERAL_AUTH_ERROR'].format(str(res)))
                return None
            if res.get('refreshToken'):
                demisto.debug('Setting new refresh token in the integration context.')
                expiry_time = res.get('expire', 0) - EARLY_EXPIRY_TIME
                demisto.debug('Setting the expiry time of the authentication token to {}.'.format(
                    timestamp_to_datestring(expiry_time, is_utc=True)))
                dma_token: str = res.get('dmaToken')
                new_token = {
                    'dmaToken': dma_token,
                    'refreshToken': res.get('refreshToken'),
                    'expire': expiry_time
                }
                integration_context: Dict = get_integration_context()
                integration_context.update({'token': new_token})
                set_integration_context(integration_context)
                return dma_token
        except DemistoException as e:
            demisto.error(str(e.args[0]))
        return None

    def get_dma_token(self, use_refresh_token: bool = True) -> Optional[str]:
        """
        Get a DMA token that was previously created if it is still valid, else, generate a new authorization token from
        the client id, client secret and refresh token.

        :type use_refresh_token ``bool``
        :param use_refresh_token: Use refresh token to update DMA token if exists.

        :return: DMA token.
        :rtype: ``str``
        """
        integration_context: Dict = get_integration_context()
        previous_token: Dict = integration_context.get('token', {})

        # Check if there is existing valid authorization token.
        if previous_token.get('dmaToken') and use_refresh_token:
            if previous_token.get('expire') > datetime.now(timezone.utc).timestamp() * 1000:  # type: ignore
                demisto.debug('Got authentication token from the integration context.')
                return previous_token.get('dmaToken')  # type: ignore
            demisto.debug('Trying to re-generate a new authentication token using the refresh token stored in the '
                          'integration context.')
            dma_token: Optional[str] = self.update_refresh_token(previous_token.get('refreshToken'))  # type: ignore
            if dma_token:
                return dma_token  # if dma_token is found then return it.
                # else, continue on next block to generate new token

        demisto.debug('Trying to generate a new authentication token.')
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'api_key'
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        res = super()._http_request(method='POST', url_suffix=ENDPOINTS['AUTH_ENDPOINT'], resp_type='response',
                                    headers=headers, data=data, ok_codes=OK_CODES,
                                    status_list_to_retry=STATUS_LIST_TO_RETRY)
        try:
            res = res.json()
        except ValueError as exception:
            raise DemistoException(ERRORS['INVALID_JSON_OBJECT'].format(res.content),
                                   exception)
        if 'errors' in res:
            raise DemistoException(ERRORS['GENERAL_AUTH_ERROR'].format(str(res)))
        if res.get('dmaToken'):
            expiry_time = res.get('expire', 0) - EARLY_EXPIRY_TIME
            demisto.debug('Setting the expiry time of the authentication token to {}.'.format(
                timestamp_to_datestring(expiry_time, is_utc=True)))
            new_token = {
                'dmaToken': res.get('dmaToken'),
                'refreshToken': res.get('refreshToken'),
                'expire': expiry_time
            }
            integration_context.update({'token': new_token})
            set_integration_context(integration_context)
            return res.get('dmaToken')
        return None

    def get_watchlists(self) -> Optional[Dict]:
        """Retrieves the watchlists stored on the Dataminr platform.

        :return: A dictionary of Watchlists grouped by their types.
        :rtype: ``Optional[Dict]``
        """
        return self.http_request(method='GET', url_suffix=ENDPOINTS['WATCHLISTS_ENDPOINT'])

    def get_alerts(self, watchlist_ids: Optional[List], query: Optional[str], _from: Optional[str], to: Optional[str],
                   num: int = DEFAULT_NUMBER_OF_ALERTS_TO_RETRIEVE) -> Optional[Dict]:
        """
        Retrieves the alerts stored on the Dataminr platform.

        :type watchlist_ids ``Optional[List]``
        :param watchlist_ids: List of watchlist id.

        :type query ``Optional[str]``
        :param query: Terms to search within Dataminr Alerts.

        :type _from ``Optional[str]``
        :param _from: Provide cursor value to get alerts after that.

        :type to ``Optional[str]``
        :param to: Provide cursor value to get alerts before that.

        :type num ``int``
        :param num: Maximum number of alerts to return.

        :return: A dictionary of alerts.
        :rtype: ``Optional[Dict]``
        """
        params = {'num': num, 'alertversion': ALERT_VERSION, 'from': _from, 'to': to, 'query': query,
                  'application': 'palo_alto_cortex_xsoar', 'application_version': get_demisto_version_as_str(),
                  'integration_version': get_pack_version('Dataminr Pulse')}
        remove_nulls_from_dictionary(params)
        if watchlist_ids:
            params['lists'] = ','.join(map(str, watchlist_ids))  # type: ignore
        return self.http_request(method='GET', url_suffix=ENDPOINTS['ALERTS_ENDPOINT'], params=params)

    def get_related_alerts(self, alert_id: str, include_root: bool) -> Optional[List]:
        """
        Retrieve the related alerts for the given alert id from the Dataminr platform.

        :type alert_id ``Optional[str]``
        :param alert_id: Unique identifier of the Dataminr alert.

        :type include_root ``Optional[bool]``
        :param include_root: Whether to include the given alert in the response or not.

        :return: A List of dictionaries of related alerts.
        :rtype: ``Optional[List]``
        """
        params = {
            'alertversion': ALERT_VERSION,
            'id': alert_id,
            'includeRoot': include_root
        }
        return self.http_request(
            method='GET', url_suffix=ENDPOINTS['RELATED_ALERTS_ENDPOINT'], params=params)  # type: ignore


''' HELPER FUNCTIONS '''


def validate_params_for_alerts_get(watchlist_ids: Optional[List], watchlist_names: Optional[list], query: Optional[str],
                                   _from: Optional[str],
                                   to: Optional[str], num: int = DEFAULT_NUMBER_OF_ALERTS_TO_RETRIEVE,
                                   use_configured_watchlist_names: bool = True, is_fetch: bool = False):
    """
    To validate arguments for the alerts get.

    :type watchlist_ids ``Optional[List]``
    :param watchlist_ids: List of watchlist id.

    :type watchlist_names ``Optional[List]``
    :param watchlist_names: Watchlist names.

    :type query ``Optional[str]``
    :param query: Terms to search within Dataminr Alerts.

    :type _from ``Optional[str]``
    :param _from: Provide cursor value to get alerts after that.

    :type to ``Optional[str]``
    :param to: Provide cursor value to get alerts before that.

    :type num ``int``
    :param num: Maximum number of alerts to return.

    :type use_configured_watchlist_names ``bool``
    :param use_configured_watchlist_names: Use configured watchlist names.

    :type is_fetch ``bool``
    :param is_fetch: Function is called by fetch_incident method.
    """
    if is_fetch:
        if num < 0:
            raise ValueError(ERRORS['INVALID_MAX_FETCH'].format(num))
    elif MAX_NUMBER_OF_ALERTS_TO_RETRIEVE < num or num < 0:
        raise ValueError(ERRORS['INVALID_MAX_NUM'].format(num, MAX_NUMBER_OF_ALERTS_TO_RETRIEVE))
    if not watchlist_ids and not query:
        if use_configured_watchlist_names:
            if is_fetch or watchlist_names:
                raise ValueError(ERRORS['NOT_MATCHED_WATCHLIST_NAMES'])
            raise ValueError(
                ERRORS['AT_LEAST_ONE_REQUIRED'].format('query', 'watchlist_names configured in integration'))
        raise ValueError(
            ERRORS['AT_LEAST_ONE_REQUIRED'].format('query', 'watchlist_ids'))
    if _from and to:
        raise ValueError(ERRORS['EITHER_ONE_REQUIRED'].format('from', 'to'))


def validate_params_for_related_alerts_get_command(alert_id: Optional[str]) -> None:
    """
    To validate arguments for the related alerts get.

    :type alert_id ``Optional[str]``
    :param alert_id: Alert id.
    """
    if not alert_id:
        raise ValueError(ERRORS['INVALID_REQUIRED_PARAMETER'].format('alert_id'))


def trim_spaces_from_args(args: Dict) -> Dict:
    """Trim spaces from values of the args Dict.

    :type args: ``Dict``
    :param args: Dict to trim spaces from.

    :rtype: ``Dict``
    :return: Arguments after trim spaces.
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


def transform_watchlists_data(watchlists_data: Optional[Dict]) -> List:
    """
    Transform watchlist data from dictionary to single List.

    :type watchlists_data ``Dict``
    :param watchlists_data: Response to be converted in single list.

    :return: List of response.
    :rtype: ``List``
    """
    list_of_watchlists = watchlists_data.get('watchlists', {}).values()  # type: ignore
    # The returned object is a dictionary where the lists are grouped by their type.
    # So, modifying this object and creating a list of all list objects as the object itself contains
    # a property named "type" in it, which defines the type of the list.
    list_of_watchlists = list(list_of_watchlists)
    # The created list will be the list of lists. So, flattening the list is required.
    list_of_watchlists = reduce(concat, list_of_watchlists)
    return list_of_watchlists


def get_watchlist_ids(client: DataminrPulseClient, watchlist_names: Optional[List]) -> List:
    """
    Get watchlist IDs as per the given watchlist names using integration context and get_watchlists method from client.

    :type client ``DataminrPulseClient``
    :param client: DataminrPulseClient to get watchlists data.

    :type watchlist_names ``Optional[List]``
    :param watchlist_names: Watchlist names.

    :return: Watchlist IDs.
    :rtype: ``List``
    """
    watchlists_data: List = transform_watchlists_data(client.get_watchlists())
    filtered_watchlists_data: List = list(filter(
        lambda watchlist_data: watchlist_data.get('name') in watchlist_names,  # type: ignore
        watchlists_data)) if watchlist_names else watchlists_data
    if not filtered_watchlists_data:
        demisto.debug(
            'No matching watchlist data was found for the "{}" watchlist names configured in the instance.'.format(
                watchlist_names))
        return []
    watchlist_ids: List = [watchlist_data.get('id') for watchlist_data in filtered_watchlists_data]
    watchlist_ids: List = list(filter(None, watchlist_ids))
    return watchlist_ids


def prepare_hr_for_watchlists_get(watchlists: List) -> str:
    """
    Prepare human-readable string for war room entry.

    :type watchlists: ``List``
    :param watchlists: List of watchlists.

    :return: Human-readable output.
    :rtype: ``str``
    """
    # The title of the table.
    title = 'Watchlists'
    # Data dictionary for the table.
    hr_outputs = [
        {
            'Watchlist ID': wl.get('id', ''),
            'Watchlist Name': wl.get('name', ''),
            'Watchlist Type': wl.get('type', ''),
            'Watchlist Description': wl.get('description', ''),
            'Watchlist Color': wl.get('properties', {}).get('watchlistColor', '')
        } for wl in watchlists
    ]
    # Table headers.
    headers = ['Watchlist ID', 'Watchlist Name', 'Watchlist Type', 'Watchlist Description', 'Watchlist Color']
    return tableToMarkdown(title, hr_outputs, headers, removeNull=True)


def prepare_hr_for_alerts(alerts: List) -> str:
    """Prepare Human Readable output for alerts.

    :type alerts: ``List``
    :param alerts: Response from the API.

    :rtype: ``str``
    :return: Human readable output.
    """
    # The title of the table.
    title = 'Alerts'

    # This will store the data dictionaries for the table.
    hr_outputs = []

    for alert in alerts:
        # List of watchlist names matched in the alert.
        watchlist_names = [watchlist.get('name') for watchlist in alert.get('watchlistsMatchedByType', [])]

        hr_outputs.append({
            'Alert Type': alert.get('alertType', {}).get('name', ''),
            'Alert ID': alert.get('alertId', ''),
            'Caption': alert.get('caption', ''),
            'Alert URL': alert.get('expandAlertURL', ''),
            'Watchlist Name': ', '.join(watchlist_names),
            'Alert Time': timestamp_to_datestring(alert.get('eventTime', 0), HR_DATE_FORMAT, is_utc=True),
            'Alert Location': alert.get('eventLocation', {}).get('name'),
            'Post Link': alert.get('post', {}).get('link', ''),
            'Is source verified': alert.get('source', {}).get('verified', ''),
            'Publisher Category': alert.get('publisherCategory', {}).get('name', ''),
        })

    # Table headers.
    headers = ['Alert Type', 'Alert ID', 'Caption', 'Alert URL', 'Watchlist Name', 'Alert Time', 'Alert Location',
               'Post Link', 'Is source verified', 'Publisher Category']
    return tableToMarkdown(title, hr_outputs, headers, removeNull=True, url_keys=['Post Link', 'Alert URL'])


def prepare_hr_for_cursor(cursor: Dict) -> str:
    """Prepare Human Readable output for cursor.

    :type cursor: ``Dict``
    :param cursor: Contains from and to parameter.

    :rtype: ``str``
    :return: Human readable output.
    """
    # The title of the table.
    title = 'Cursor for pagination'

    # This will store the data dictionaries for the table.
    _from = cursor.get('from')
    if _from:
        _from = re.escape(_from)
    to = cursor.get('to')
    if to:
        to = re.escape(to)
    hr_outputs = [{'from': _from, 'to': to}]

    # Table headers.
    headers = ['from', 'to']
    return tableToMarkdown(title, hr_outputs, headers, removeNull=True)


''' COMMAND FUNCTIONS '''


def test_module(client: DataminrPulseClient) -> str:
    """Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    :type client: ``DataminrPulseClient``
    :param client: DataminrPulseClient to be used.

    :rtype: ``str``
    :return: 'ok' if test passed, anything else will fail the test.
    """
    # This  should validate all the inputs given in the integration configuration panel,
    # either manually or by using an API that uses them.
    params = demisto.params()
    is_fetch = params.get('isFetch', False)
    if is_fetch:
        fetch_incidents(client, {}, params, is_test=True)
    else:
        args = {'num': 0, 'watchlist_names': params.get('watchlist_names')}
        dataminrpulse_alerts_get(client, args)
    # Return OK, indicating the connection to the platform is successful.
    return 'ok'


def fetch_incidents(client: DataminrPulseClient, last_run: Dict[str, Any], params: Dict[str, Any],
                    is_test: bool = False) -> Tuple[Dict, List]:
    """Fetch issues list incidents.

    :type client: ``DataminrPulseClient``
    :param client: DataminrPulseClient to be used.

    :type last_run: ``Dict[str, Any]``
    :param last_run: last run object obtained from demisto.getLastRun().

    :type params: `Dict[str, Any]``
    :param params: Arguments to be used for fetch incident.

    :type is_test: ``bool``
    :param is_test: If test_module called fetch_incident.

    :rtype: ``Tuple[Dict, List]``
    :return: Tuple of last run object and list of fetched incidents.
    """
    num = arg_to_number(params.get('max_fetch', '40'), arg_name='Max Fetch')  # type: ignore
    _from = last_run.get('from')
    last_watchlist_names = last_run.get('last_watchlist_names')
    last_query = last_run.get('last_query')
    found_alert_ids = last_run.get('found_alert_ids', [])
    watchlist_names = argToList(params.get('watchlist_names'))
    query = params.get('query')
    alert_type: str = params.get('alert_type', 'All')

    watchlist_ids = get_watchlist_ids(client=client, watchlist_names=watchlist_names)
    if last_watchlist_names != watchlist_names or last_query != query:
        demisto.debug('Watchlist names or query changed in configuration, so fetching incident from start')
        _from = None

    if num > 200:  # type: ignore
        demisto.debug(
            'The value for the max_fetch parameter is {} which is greater than 200, so reducing it to 200.'.format(num))
        num = 200

    validate_params_for_alerts_get(watchlist_ids=watchlist_ids, watchlist_names=watchlist_names, query=query,
                                   _from=_from, to=None,
                                   num=num, use_configured_watchlist_names=True, is_fetch=True)  # type: ignore

    response = client.get_alerts(watchlist_ids=watchlist_ids, query=query, _from=_from, to=None,
                                 num=num)  # type: ignore

    alert_response = response.get('data', {}).get('alerts', [])  # type: ignore
    alert_valid_response = remove_empty_elements(alert_response)

    _from = response.get('data', {}).get('from', '')  # type: ignore
    to = response.get('data', {}).get('to', '')  # type: ignore
    cursor_response = {'from': _from, 'to': to}  # type: ignore
    cursor_valid_response = remove_empty_elements(cursor_response)

    if is_test:
        return {}, []

    next_run = last_run.copy()

    incidents = []

    for alert in alert_valid_response:
        parent_alert_id = alert.get('parentAlertId')
        if parent_alert_id:
            demisto.debug('Found alert with parent alert id, so skipping it. Alert ID: {}'.format(alert.get('alertId')))
            continue
        alert_type_name = alert.get('alertType', {}).get('name', '')
        if alert_type != 'All':
            if not alert_type_name or alert_type_name.lower() != alert_type.lower():
                continue
        alert_id = alert.get('alertId')
        if alert_id in found_alert_ids:
            demisto.debug('Found existing alert. Alert ID: {}'.format(alert_id))
            continue
        occurred_date = timestamp_to_datestring(alert.get('eventTime', 0), DATE_FORMAT, is_utc=True)  # type: ignore
        incidents.append({
            'name': alert.get('caption'),
            'occurred': occurred_date,  # type: ignore
            'rawJSON': json.dumps(alert),
            'severity': ALERT_TYPE_TO_INCIDENT_SEVERITY.get(alert_type_name, 0)})
        found_alert_ids.append(alert_id)

    next_run['found_alert_ids'] = found_alert_ids

    if alert_valid_response and cursor_valid_response:
        next_run['from'] = cursor_valid_response.get('to')
        next_run['last_watchlist_names'] = watchlist_names
        next_run['last_query'] = query

    return next_run, incidents


def dataminrpulse_watchlists_get_command(client: DataminrPulseClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve the Watchlist stored on the Dataminr platform.

    :type client: ``DataminrPulseClient``
    :param client: DataminrPulseClient to be used.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    # Retrieve the lists stored on the Dataminr platform.
    raw_lists_resp = client.get_watchlists()
    list_of_watchlists = transform_watchlists_data(raw_lists_resp)
    # Create a human-readable output for the war room entry.
    hr_output = prepare_hr_for_watchlists_get(list_of_watchlists)
    # Create and return a CommandResults object to return_results function.
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX_WATCHLISTS,
        outputs_key_field='id',
        outputs=list_of_watchlists,
        readable_output=hr_output,
        raw_response=raw_lists_resp
    )


def dataminrpulse_alerts_get(client: DataminrPulseClient, args: Dict[str, Any]) -> List[CommandResults]:
    """Retrieve the list of the alerts that meet the specified filter criteria.

    :type client: ``DataminrPulseClient``
    :param client: DataminrPulseClient to be used.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``List[CommandResults]``
    :return: Standard command results.
    """
    watchlist_names: List = argToList(args.get('watchlist_names', ''))
    watchlist_ids: List = argToList(args.get('watchlist_ids', ''))
    query: str = args.get('query', '')
    _from: str = args.get('from', '')
    to: str = args.get('to', '')
    num: int = arg_to_number(args.get('num', '40'), arg_name='num')  # type: ignore
    use_configured_watchlist_names: bool = argToBoolean(args.get('use_configured_watchlist_names', 'yes'))

    if use_configured_watchlist_names and not watchlist_ids:
        watchlist_ids = get_watchlist_ids(client, watchlist_names)

    validate_params_for_alerts_get(watchlist_ids=watchlist_ids, watchlist_names=watchlist_names, query=query,
                                   _from=_from, to=to, num=num,
                                   use_configured_watchlist_names=use_configured_watchlist_names)

    response = client.get_alerts(watchlist_ids, query, _from, to, num)
    alert_response = response.get('data', {}).get('alerts', [])  # type: ignore
    alert_valid_response = remove_empty_elements(alert_response)
    hr_output_for_alerts = prepare_hr_for_alerts(alert_valid_response)

    _from = response.get('data', {}).get('from', '')  # type: ignore
    to = response.get('data', {}).get('to', '')  # type: ignore
    cursor_response = {'from': _from, 'to': to}
    cursor_valid_response = remove_empty_elements(cursor_response)
    hr_output_for_cursor = prepare_hr_for_cursor(cursor_valid_response)

    alert_results = CommandResults(
        outputs_prefix=OUTPUT_PREFIX_ALERTS,
        outputs_key_field='alertId',
        outputs=alert_valid_response,
        readable_output=hr_output_for_alerts,
        raw_response=alert_response,
    )

    cursor_results = CommandResults(
        outputs_prefix=OUTPUT_PREFIX_CURSOR,
        outputs_key_field=['from', 'to'],
        outputs=cursor_valid_response,
        readable_output=hr_output_for_cursor,
        raw_response=cursor_response,
    )

    return [alert_results, cursor_results]


def dataminrpulse_related_alerts_get_command(client: DataminrPulseClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the related alerts for the given alert id from the Dataminr platform.

    :type client: ``DataminrPulseClient``
    :param client: DataminrPulseClient to be used.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    # Extract the arguments passed with the command.
    alert_id: Optional[str] = args.get('alert_id')
    include_root: bool = argToBoolean(args.get('include_root'))

    validate_params_for_related_alerts_get_command(alert_id=alert_id)

    # Retrieve the related alerts of the given alert ID.
    alerts = client.get_related_alerts(alert_id=alert_id, include_root=include_root)  # type: ignore

    validate_response = remove_empty_elements(alerts)

    # Create a human-readable output for the war room entry.
    hr_output = prepare_hr_for_alerts(validate_response)

    # Create and return a CommandResults object to return_results function.
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX_ALERTS,
        outputs_key_field='alertId',
        outputs=validate_response,
        readable_output=hr_output,
        raw_response=alerts
    )


""" MAIN FUNCTION """


def main():
    """Parse params and runs command functions."""
    # Retrieve the configuration parameters.
    params = demisto.params()

    # Credentials for connecting with the Dataminr Pulse API.
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')

    # Default configuration parameters for handling proxy and SSL Certificate validation.
    verify_certificate = not argToBoolean(params.get('insecure', False))
    proxy = argToBoolean(params.get('proxy', False))

    # Parameters for fetch incident mechanism
    watchlist_names = params.get('watchlist_names')

    # Retrieve the name of the command being called.
    command = demisto.command()
    demisto.debug(f'The command being called is {command}.')

    # A mapping of Demisto supported commands which require arguments with their respective command functions.
    demisto_commands: Dict[str, Callable] = {
        'dataminrpulse-alerts-get': dataminrpulse_alerts_get,
        'dataminrpulse-watchlists-get': dataminrpulse_watchlists_get_command,
        'dataminrpulse-related-alerts-get': dataminrpulse_related_alerts_get_command
    }

    try:
        # Create a Dataminr Pulse client object with the provided configuration parameters.
        client = DataminrPulseClient(
            client_id=client_id,
            client_secret=client_secret,
            proxy=proxy,
            verify=verify_certificate
        )

        # Execute the respective command function based on the command name got from the Demisto.
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, last_run, params)
            demisto.info(f'Fetched {len(incidents)} new incidents')
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)
        elif command in demisto_commands:
            args = demisto.args()
            if command == 'dataminrpulse-alerts-get':
                args.update({'watchlist_names': watchlist_names})
            remove_nulls_from_dictionary(trim_spaces_from_args(args))
            return_results(demisto_commands[command](client, args))
        else:
            raise NotImplementedError(f'The command {command} is not implemented.')

    # Log any exception raised and return error.
    except Exception as exception:
        demisto.error(traceback.format_exc())  # Print the traceback.
        return_error(f'Failed to execute {command} command.\nError:\n{str(exception)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
