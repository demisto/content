import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from typing import Any
import requests
import dateparser
import urllib3

# disable insecure warnings
urllib3.disable_warnings()


TOKEN_INPUT_IDENTIFIER = '__token'
DAYS_BACK_FOR_FIRST_QUERY_OF_INCIDENTS = 3
DATETIME_FORMAT_MILISECONDS = '%Y-%m-%dT%H:%M:%S.%f'
DEFAULT_LIMIT = 50
MAX_LENGTH_CONTEXT = 10000
DEFAULT_FETCH_TYPE = ["Exabeam Incident"]
MAX_LIMIT_FETCH_USERS = 200


class Client(BaseClient):
    """
    Client to use in the Exabeam integration. Overrides BaseClient
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool,
                 proxy: bool, headers, api_key: str = '', is_fetch: bool = None):
        self.validate_authentication_params(username=username, password=password, api_key=api_key, is_fetch=is_fetch)
        super().__init__(base_url=f'{base_url}', headers=headers, verify=verify, proxy=proxy)
        self.username = username
        self.password = password
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers = headers
        if not proxy:
            self.session.trust_env = False
        if self.is_token_auth():
            self.session.headers['ExaAuthToken'] = self.password or self.api_key
        else:
            self._login()

    def shutdown(self):
        if not self.is_token_auth():
            self._logout()
        super().__del__()

    def _login(self):
        """
        Login using the credentials and store the cookie
        """
        self._http_request('POST', full_url=f'{self._base_url}/api/auth/login', data={
            'username': self.username,
            'password': self.password
        })

    def _logout(self):
        """
        Logout from the session
        """
        try:
            self._http_request('GET', full_url=f'{self._base_url}/api/auth/logout')
        except Exception as err:
            demisto.debug(f'An error occurred during the logout.\n{str(err)}')

    def validate_authentication_params(self, username: str = None,
                                       password: str = None,
                                       api_key: str = None,
                                       is_fetch: bool = None):
        if username == TOKEN_INPUT_IDENTIFIER:
            if is_fetch:
                raise ValueError('In order to use the “Fetch Incident” functionality,'
                                 ' the username must be provided in the “Username” parameter.\n'
                                 ' Please see documentation `Authentication Methods`')
            if api_key:
                raise ValueError(f'When specifying {username=}, the API Token must be provieded using in the password field'
                                 ' please empty the other field')
            if not password:
                raise ValueError('Please insert API Token in the password field'
                                 ' or see documentation `Authentication Methods` for another authentication methods')
        elif not username:
            if not api_key:
                raise ValueError('If an API token is not provided, it is mandatory to insert username and password.')
            if is_fetch:
                raise ValueError('In order to use the “Fetch Incident” functionality,'
                                 ' the username must be provided in the “Username” parameter.\n'
                                 ' Please see documentation `Authentication Methods`')
        else:
            if not password and not api_key:
                raise ValueError('Please insert password or API token.')
            if password and api_key:
                raise ValueError('Please insert API token OR password and not both.')

    def is_token_auth(self) -> bool:

        if not self.username:
            return True
        if self.username == TOKEN_INPUT_IDENTIFIER:
            return True
        if self.api_key:
            return True
        return False

    def test_module_request(self):
        """
        Performs basic get request to check if the server is reachable.
        """
        self._http_request('GET', full_url=f'{self._base_url}/api/auth/check', resp_type='text')

    def get_notable_users_request(self, api_unit: str = None, num: str = None, limit: int = None) -> dict:
        """
        Args:
            api_unit:
            num: num of notable users
            limit: limit of notable users

        Returns:
            notable users
        """
        params = {
            'unit': api_unit,
            'num': num,
            'numberOfResults': limit
        }
        response = self._http_request('GET', url_suffix='/uba/api/users/notable', params=params)
        return response

    def get_user_info_request(self, username: str) -> dict:
        """
        Args:
            username: the username

        Returns:
            the user info
        """
        response = self._http_request('GET', url_suffix=f'/uba/api/user/{username}/info')
        return response

    def get_peer_groups_request(self) -> dict:
        """
        Returns:
            peer groups
        """
        response = self._http_request('GET', url_suffix='/uba/api/peerGroup')
        return response

    def get_user_labels_request(self) -> dict:
        """
        Returns:
            user labels
        """
        response = self._http_request('GET', url_suffix='/uba/api/userLabel')
        return response

    def user_sequence_request(self, username: str = None, parse_start_time=None, parse_end_time=None) -> dict:
        """
        Args:
            username:
            parse_start_time: start time
            parse_end_time: end time

        Returns:
            user sequence relevant to the time period
        """
        params = {
            'username': username,
            'startTime': parse_start_time,
            'endTime': parse_end_time
        }
        response = self._http_request('GET', url_suffix=f'/uba/api/user/{username}/sequences', params=params)
        return response

    def get_watchlist_request(self):
        """
        Returns:
            a watchlist
        """
        response = self._http_request('GET', url_suffix='/uba/api/watchlist')
        return response

    def delete_watchlist_request(self, watchlist_id: str = None):
        """
        Args:
            watchlist_id: watchlist id

        """
        self._http_request('DELETE', url_suffix=f'/uba/api/watchlist/{watchlist_id}/')

    def get_asset_data_request(self, asset_name: str = None) -> dict:
        """

        Args:
            asset_name: asset name

        Returns:
            asset data
        """
        response = self._http_request('GET', url_suffix=f'/uba/api/asset/{asset_name}/data')
        return response

    def get_session_info_request(self, session_id: str = None) -> dict:
        """

            Args:
                session_id: ID of the session to fetch data for

            Returns:
                (dict) The session information.
        """
        response = self._http_request('GET', url_suffix=f'/uba/api/session/{session_id}/info')
        return response

    def list_top_domains_request(self, sequence_id: str = None, sequence_type: str = None) -> dict:
        """

            Args:
                sequence_id: ID of the sequence to fetch top domains for
                sequence_type: type of the sequence to fetch top domains for

            Returns:
                (dict) The top domains of a sequence.
        """
        params = {
            'sequenceId': sequence_id,
            'sequenceType': sequence_type
        }
        response = self._http_request('GET', url_suffix='/uba/api/data_feed/topDomains', params=params)
        return response

    def list_triggered_rules_request(self, sequence_id: str = None, sequence_type: str = None) -> dict:
        """

            Args:
                sequence_id: ID of the sequence to fetch data for
                sequence_type: Type of the sequence to fetch data for

            Returns:
                (dict) The sequence's triggered rules data.
        """
        params = {
            'sequenceId': sequence_id,
            'sequenceType': sequence_type
        }
        response = self._http_request('GET', url_suffix='/uba/api/user/sequence/triggeredRules', params=params)
        return response

    def get_asset_info_request(self, asset_id: str = None, max_users_number: int = None) -> dict[str, Any]:
        """

            Args:
                asset_id: ID of the asset to fetch info for
                max_users_number: The maximal number of users

            Returns:
                (dict) The asset information.
        """
        params = {'maxNumberOfUsers': max_users_number}
        response = self._http_request('GET', url_suffix=f'/uba/api/asset/{asset_id}/info', params=params)
        return response

    def list_asset_next_events_request(self, asset_id: str = None,
                                       event_time: int = None,
                                       number_of_events: int = None,
                                       anomaly_only: str = None,
                                       event_categories: list = None,
                                       event_types: list = None,
                                       event_type_include: str = None,
                                       sequence_types: list = None) -> dict:
        """

            Args:
                asset_id: ID of the asset to fetch info for
                event_time: the event timestamp
                number_of_events: preferred number of events
                anomaly_only: return only anomaly
                event_categories: event categories
                event_types: event types
                event_type_include: whether or not to include event type
                sequence_types: sequence types

            Returns:
                (dict) The asset next events raw data.
        """
        params = {
            'assetId': asset_id,
            'eventTime': event_time,
            'preferredNumberOfEvents': number_of_events,
            'anomalyOnly': anomaly_only,
            'eventTypeInclude': event_type_include
        }

        array_type_params = {
            'eventTypes': event_types,
            'eventCategories': event_categories,
            'sequenceTypes': sequence_types
        }
        query_params_str = get_query_params_str(params, array_type_params)
        url_suffix = f'/uba/api/asset/timeline/events/next?{query_params_str}'

        response = self._http_request('GET', url_suffix=url_suffix, params=params)
        return response

    def list_security_alerts_request(self, asset_id: str = None, sort_by: str = None,
                                     sort_order: int = None, limit: int = None) -> dict:
        """
            Args:
                asset_id: ID of the asset to fetch info for
                sort_by: The attribute to sort results by
                sort_order: ascending (1) or descending (-1).
                limit: return only anomaly

            Returns:
                (dict) The asset's security alerts response.
        """
        params = {
            'sortBy': sort_by,
            'sortOrder': sort_order,
            'numberOfResults': limit
        }
        # note: "numberOfResults" is a required query parameter, no "offset" and no "startTime" parameters,
        # therefore it's impossible to implement a pagination here.

        url_suffix = f'/uba/api/asset/{asset_id}/securityAlerts'

        response = self._http_request('GET', url_suffix=url_suffix, params=params)
        return response

    def search_rules_request(self, keyword: str = None, filter_exp: str = None) -> list | dict:
        """
            Args:
                keyword: The search keyword
                filter_exp: The search filter expression

            Returns:
                (list) The search query response.
        """
        params = {
            'keyword': keyword,
            'filter': filter_exp
        }

        url_suffix = '/uba/api/rules/searchRules'

        response = self._http_request('GET', url_suffix=url_suffix, params=params)
        return response

    def get_rule_string_request(self, rule_id: str = None) -> str:
        """
            Args:
                rule_id: The rule ID.

            Returns:
                (str) The string response.
        """

        url_suffix = f'/uba/api/rules/{rule_id}/string'

        response = self._http_request('GET', url_suffix=url_suffix, resp_type='text')
        return response

    def fetch_rules_request(self, filter_by: str = None) -> list | dict:
        """
            Args:
                filter_by: rules to retrieve (default/custom/all).

            Returns:
                (list) The rules response.
        """

        params = {'filterBy': filter_by}
        url_suffix = '/uba/api/rules/fetchRules'

        response = self._http_request('GET', url_suffix=url_suffix, params=params)
        return response

    def get_model_definition_request(self, model_name: str = None) -> dict:
        """
            Args:
                model_name: The model name.

            Returns:
                (dict) The model definition.
        """

        params = {'modelName': model_name}
        url_suffix = '/uba/api/rules/modelDefinition'

        response = self._http_request('GET', url_suffix=url_suffix, params=params)
        return response

    def add_watchlist_items_from_csv_request(self, watchlist_id: str = None, watch_until_days: int = None,
                                             csv_file: str = None, category: str = None) -> dict:
        """
            Args:
                watchlist_id: ID of the watchlist to search assets for
                csv_file: The entry ID of the CSV file
                watch_until_days: Number of days until asset is automatically removed from the watchlist
                category: The items category

            Returns:
                (dict) The addFromCsv API response.
        """

        file_path = demisto.getFilePath(csv_file).get('path')

        if file_path:
            files = {'files': (os.path.basename(file_path), open(file_path, 'rb'), 'text/csv')}

            form_data = {
                'watchUntilDays': watch_until_days,
                'category': category
            }
            url_suffix = f'/uba/api/watchlist/{watchlist_id}/addFromCsv'

            response = self._http_request('PUT', url_suffix=url_suffix, data=form_data, files=files)
            return response
        else:
            raise ValueError('Invalid entry_id argument.')

    def add_watchlist_items_by_name_request(self, watchlist_id: str = None, watch_until_days: int = None,
                                            items: list = None, category: str = None) -> dict:
        """
            Args:
                watchlist_id: ID of the watchlist to search assets for
                items: A comma-separated list of the items to add.
                watch_until_days: Number of days until asset is automatically removed from the watchlist
                category: The items category

            Returns:
                (dict) The addFromCsv API response.
        """

        params = {
            'watchUntilDays': watch_until_days,
            'category': category
        }
        array_type_params = {'items[]': items}
        query_params_str = get_query_params_str(params, array_type_params)

        url_suffix = f'/uba/api/watchlist/{watchlist_id}/add?{query_params_str}'
        response = self._http_request('PUT', url_suffix=url_suffix)
        return response

    def search_asset_in_watchlist_request(self, keyword: str = None, watchlist_id: str = None, limit: int = None,
                                          is_exclusive: str = None, search_by_ip: str = None) -> dict:
        """
            Args:
                keyword: A keyword to search
                watchlist_id: ID of the watchlist to search assets for
                limit: Maximum number of results to retrieve
                is_exclusive: Whether or not the item is exclusive on watchlist
                search_by_ip: Whether or not to search the item by its IP

            Returns:
                (dict) The watchlist's assets search response.
        """

        params = {
            'watchlistId': watchlist_id,
            'keyword': keyword,
            'numberOfResults': limit,
            'isExclusive': is_exclusive,
            'searchByIp': search_by_ip
        }
        url_suffix = '/uba/api/watchlist/assets/search'

        response = self._http_request('GET', url_suffix=url_suffix, params=params)
        return response

    def remove_watchlist_items_request(self, watchlist_id: str = None, items: list = None,
                                       category: str = None) -> dict:
        """
            Args:
                watchlist_id: ID of the watchlist to remove an item from
                items: A comma-separated list of items to remove
                category: The item category

            Returns:
                (dict) The removal API response.
        """

        params = {
            'watchlistId': watchlist_id,
            'category': category
        }
        array_type_params = {'items[]': items}
        query_params_str = get_query_params_str(params, array_type_params)

        url_suffix = f'/uba/api/watchlist/{watchlist_id}/remove?{query_params_str}'
        response = self._http_request('PUT', url_suffix=url_suffix)
        return response

    def list_context_table_records_request(self, context_table_name: str = None,
                                           page_size: int = None, page_number: int = None) -> dict:
        """
            Args:
                context_table_name: The context table name.
                page_size: The page size.
                page_number: The page number (1-based).

            Returns:
                (dict) The context table records.
        """

        params = {
            'pageSize': page_size,
            'pageNumber': page_number
        }
        url_suffix = f'/api/setup/contextTables/{context_table_name}/records'

        response = self._http_request('GET', url_suffix=url_suffix, params=params)
        return response

    def update_session_id_of_context_table(self, context_table_name: str = None, session_id: str = None,
                                           replace: bool = False):
        """ Apply updates in context table.

            Args:
                context_table_name: The context table name.
                session_id: The ID of update session.
                replace: whether or not to replace the existing records.
        """
        try:
            url_suffix = f'/api/setup/contextTables/{context_table_name}/records'
            payload = {'sessionId': session_id, 'replace': replace}

            self._http_request('PUT', url_suffix=url_suffix, json_data=payload)
        except Exception:
            # the context table should be updated so we proceed and don't raise an exception.
            pass

    def add_context_table_records_request(self, context_table_name: str, records_list: list[str],
                                          key_only: bool, session_id: str = None) -> dict:
        """
            Args:
                context_table_name: The context table name.
                records_list: The records to add.
                key_only: True iff the context table type is key only.
                session_id: The ID of update session. If not specified, a new session is created.

            Returns:
                (dict) The context table records update response.
        """
        params = {'sessionId': session_id} if session_id else {}
        record_item_format = 'key' if key_only else 'key:value'
        payload = {
            'records': parse_context_table_records_list(records_list, fmt=record_item_format)
        }

        url_suffix = f'/api/setup/contextTables/{context_table_name}/changes/add'

        response = self._http_request('POST', url_suffix=url_suffix, params=params, json_data=payload)

        if not session_id and response.get('sessionId'):
            self.update_session_id_of_context_table(context_table_name, session_id=response.get('sessionId'))
        return response

    def update_context_table_records_request(self, context_table_name: str, records_list: list[str],
                                             key_only: bool, session_id: str = None) -> dict:
        """
            Args:
                context_table_name: The context table name.
                records_list: The records to update, in the following format: id:new_key(:new_vals).
                key_only: True iff the context table type is key only.
                session_id: The ID of update session. If not specified, a new session is created.

            Returns:
                (dict) The context table records update response.
        """

        params = {'sessionId': session_id} if session_id else {}

        record_item_format = 'id:key' if key_only else 'id:key:value'
        payload = {
            'records': parse_context_table_records_list(records_list, fmt=record_item_format)
        }

        url_suffix = f'/api/setup/contextTables/{context_table_name}/changes/update'

        response = self._http_request('POST', url_suffix=url_suffix, params=params, json_data=payload)

        if not session_id and response.get('sessionId'):
            self.update_session_id_of_context_table(context_table_name, session_id=response.get('sessionId'))

        return response

    def delete_context_table_records_request(self, context_table_name: str, records: list[str],
                                             session_id: str = None) -> dict:
        """
            Args:
                context_table_name: The context table name.
                records: The records to update, in the following format: id:new_key.
                session_id: The ID of update session. If not specified, a new session is created.

            Returns:
                (dict) The context table records update response.
        """

        params = {'sessionId': session_id} if session_id else {}
        payload = {
            'records': parse_context_table_records_list(records, fmt='id', is_delete=True)
        }
        url_suffix = f'/api/setup/contextTables/{context_table_name}/changes/delete'

        response = self._http_request('POST', url_suffix=url_suffix, params=params, json_data=payload)

        if not session_id and response.get('sessionId'):
            self.update_session_id_of_context_table(context_table_name, session_id=response.get('sessionId'))

        return response

    def add_context_table_records_from_csv_request(self, context_table_name: str = None,
                                                   csv_file: str = None, has_header: bool = False,
                                                   session_id: str = None, replace: bool = False) -> dict:
        """
            Args:
                context_table_name: The context table name.
                csv_file: The entry ID of the CSV file from which records will be added.
                has_header: Indicates whether the file has a header.
                session_id: The ID of update session. If not specified, a new session is created.
                replace: whether or not ro replace the existing records in the context table.

            Returns:
                (dict) The context table records update response.
        """
        file_path = demisto.getFilePath(csv_file).get('path')

        if file_path:
            url_suffix = f'/api/setup/contextTables/{context_table_name}/changes/addBulk'

            files = {'data': (os.path.basename(file_path), open(file_path, 'rb'), 'text/csv')}

            params: dict[str, Any] = {'hasHeader': has_header}
            if session_id:
                params['sessionId'] = session_id

            response = self._http_request('POST', url_suffix=url_suffix, params=params, files=files)

            if not session_id and response.get('sessionId'):
                self.update_session_id_of_context_table(context_table_name, session_id=response.get('sessionId'),
                                                        replace=replace)

            return response
        else:
            raise ValueError('Invalid entry_id argument.')

    def get_context_table_csv_request(self, context_table_name: str = None) -> tuple[str, str]:
        """
            Args:
                context_table_name: The context table name.

            Returns:
                (Tuple[str, str]) The file name and the response content.
        """

        url_suffix = f'/api/setup/contextTables/{context_table_name}/records/csv'

        headers = {'Accept': 'text/csv; charset=UTF-8'}
        response = self._http_request('GET', url_suffix=url_suffix, headers=headers, resp_type='response')
        # 'Content-Disposition' value is of the form: attachment; filename="filename.csv"
        # Since we don't have the file name anywhere else in the response object, we parse it from this entry.
        filename = response.headers.get('Content-Disposition', '').split('\"')[1]
        content = response.content

        return filename, content

    def get_notable_assets_request(self, api_unit: str = None, num: str = None, limit: int = None) -> dict:
        """
        Args:
            api_unit: The time duration unit.
            num: The num of time duration.
            limit: Results number.

        Returns:
            (dict) The notable assets response.
        """
        params = {
            'unit': api_unit,
            'num': num,
            'numberOfResults': limit
        }

        response = self._http_request('GET', url_suffix='uba/api/assets/notable', params=params)
        return response

    def get_notable_session_details_request(self, asset_id: str = None, sort_by: str = None,
                                            sort_order: int = None, limit: int = None) -> dict:
        """
        Args:
            asset_id: ID of the asset to fetch info for
            sort_by: The attribute to sort results by
            sort_order: ascending (1) or descending (-1).
            limit: return only anomaly

        Returns:
            (dict) The notable session details response.
        """
        params = {
            'sortBy': sort_by,
            'sortOrder': sort_order,
            'numberOfResults': limit
        }

        url_suffix = f'/uba/api/asset/{asset_id}/notableSessions'

        response = self._http_request('GET', url_suffix=url_suffix, params=params)
        return response

    def get_notable_sequence_details_request(self, asset_id: str = None, parse_start_time=None,
                                             parse_end_time=None):
        """
        Args:
            asset_id: ID of the asset to fetch info for
            parse_start_time: start time
            parse_end_time: end time

        Returns:
            notable sequence relevant to the time period
        """
        params = {
            'assetId': asset_id,
            'startTime': parse_start_time,
            'endTime': parse_end_time
        }
        response = self._http_request('GET', url_suffix=f'/uba/api/asset/{asset_id}/sequences', params=params)
        return response

    def get_notable_sequence_event_types_request(self, asset_sequence_id: str = None, search_str: str = None):
        """
        Args:
            asset_sequence_id: ID of the asset sequence to fetch info for
            search_str: string to search for inside display name

        Returns:
            (dict) The sequence event types response.
        """
        params = {
            'assetSequenceId': asset_sequence_id,
            'searchStr': search_str
        }
        response = self._http_request('GET', url_suffix=f'/uba/api/asset/sequence/{asset_sequence_id}/eventTypes',
                                      params=params)
        return response

    def get_list_incidents(self, query_params: dict):

        return self._http_request('GET', url_suffix='/ir/api/incident/list',
                                  params=query_params)

    def get_single_incident(self, incident_id: str, username: str = None):
        headers = self._headers | {'EXA_USERNAME': username or self.username}
        return self._http_request('GET', url_suffix=f'/ir/api/incident/{incident_id}',
                                  headers=headers)

    def get_incidents(self, query: dict[str, Any]):
        headers = self._headers
        if not self.password:
            headers = headers | {'EXA_USERNAME': self.username}
        return self._http_request(
            'POST',
            url_suffix='/ir/api/incidents/search',
            headers=headers,
            json_data=query,
        )


''' HELPER FUNCTIONS '''


def format_single_incident(incident: dict[str, Any]) -> dict[str, Any]:
    incident_fields = incident.get('fields', {})
    formatted_incident = {'incidentId': incident.get('incidentId'),
                          'name': incident.get('name'),
                          'fields': {
        'startedDate': convert_unix_to_date(incident_fields.get('startedDate')),
        'closedDate': convert_unix_to_date(incident_fields.get('closedDate')),
        'createdAt': convert_unix_to_date(incident_fields.get('createdAt')),
        'owner': incident_fields.get('owner'),
        'status': incident_fields.get('status'),
        'incidentType': incident_fields.get('incidentType'),
        'source': incident_fields.get('source'),
        'priority': incident_fields.get('priority'),
        'queue': incident_fields.get('queue'),
        'description': incident_fields.get('description')
    }}

    return formatted_incident


def get_query_params_str(params: dict, array_type_params: dict) -> str:
    """ Used for API queries that include array type parameters. Passing them in a dictionary won't work
        because their keys must be equal which is not possible in python dictionaries, thus we will
        eventually pass the parameters in the URL itself.

        Example: Because we can't pass {"a": "0", "a": "1"} as a dict to the params argument of the request function,
        we will pass the parameters as a part of the URL suffix: ?a=0&a=1.

            Args:
                params: string/integer parameters
                array_type_params: array type parameters

            Returns:
                (str) The query params string, which will be appended to the API request URL suffix.
            """
    query_params_str = '&'.join([f'{k}={v}' for k, v in params.items()])
    for array_type_param, values in array_type_params.items():
        curr_param_str = '&'.join([f'{array_type_param}={v}' for v in values])
        query_params_str += '&' + curr_param_str
    return query_params_str


def convert_unix_to_date(timestamp, sep='T'):
    """Convert unix timestamp to datetime in iso format.

    Args:
        timestamp: the date in unix to convert.
        sep: the separator between date and time, default is None.

    Returns:
        converted date.
    """
    if not timestamp:
        return None

    return datetime.fromtimestamp(int(timestamp) / 1000).isoformat(sep)


def convert_date_to_unix(date_string):
    """Convert date input to unix timestamp.

    Args:
        date_string: the date input string.

    Returns:
        (int) converted timestamp.
    """
    if not date_string:
        return None

    parsed_date = dateparser.parse(date_string)
    assert parsed_date is not None, f'could not parse {date_string}'
    return int(parsed_date.timestamp() * 1000)


def contents_user_info(user, user_info) -> dict:
    """create a content obj for the user

    Args:
        user: user object
        user_info: user info object

    Returns:
        A contents dict with the relevant user data
    """
    contents = {
        'Username': user.get('username'),
        'RiskScore': round(user_info.get('riskScore')) if 'riskScore' in user_info else None,
        'AverageRiskScore': user_info.get('averageRiskScore'),
        'LastSessionID': user_info.get('lastSessionId'),
        'FirstSeen': convert_unix_to_date(user_info.get('firstSeen')) if 'firstSeen' in user_info else None,
        'LastSeen': convert_unix_to_date(user_info.get('lastSeen')) if 'lastSeen' in user_info else None,
        'LastActivityType': user_info.get('lastActivityType'),
        'Label': user_info.get('labels'),
        'AccountNames': user.get('accountNames'),
        'PeerGroupFieldName': user.get('peerGroupFieldName'),
        'PeerGroupFieldValue': user.get('peerGroupFieldValue'),
        'PeerGroupDisplayName': user.get('peerGroupDisplayName'),
        'PeerGroupType': user.get('peerGroupType')
    }
    return contents


def contents_append_notable_user_info(contents, user, user_, user_info) -> list[Any]:
    """Appends a dictionary of data to the base list

    Args:
        contents: base list
        user: user object
        user_: user object
        user_info: user info object

    Returns:
        A contents list with the relevant notable user data
    """
    contents.append({
        'UserName': user_.get('username'),
        'RiskScore': round(user_info.get('riskScore')) if 'riskScore' in user_info else None,
        'FirstSeen': convert_unix_to_date(user_.get('firstSeen')) if 'firstSeen' in user_ else None,
        'LastSeen': convert_unix_to_date(user_.get('lastSeen')) if 'lastSeen' in user_ else None,
        'LastActivity': user_.get('lastActivityType'),
        'Labels': user_.get('labels'),
        'UserFullName': user.get('userFullName'),
        'Location': user_info.get('location'),
        'NotableSessionIds': user.get('notableSessionIds'),
        'NotableUser': True,
        'HighestRiskSession': user.get('highestRiskSession'),
        'EmployeeType': user_info.get('employeeType'),
        'Department': user_info.get('department'),
        'Title': user_info.get('title')
    })
    return contents


def contents_append_notable_assets_info(asset, asset_, highest_risk_sequence, latest_asset_comment) -> dict:
    """Appends a dictionary of data to the base list

    Args:
        asset: asset object
        asset_: asset object
        highest_risk_sequence: highest risk sequence object
        latest_asset_comment: latest asset comment object

    Returns:
        A contents list with the relevant notable user data
    """
    asset_info = {
        'highestRiskScore': asset.get('highestRiskScore'),
        'incidentIds': asset.get('incidentIds'),
        'zone': asset.get('zone'),

        'id': highest_risk_sequence.get('id'),
        'entityName': highest_risk_sequence.get('entityName'),
        'entityValue': highest_risk_sequence.get('entityValue'),
        'day': convert_unix_to_date(highest_risk_sequence.get('day')),
        'triggeredRuleCountOpt': highest_risk_sequence.get('triggeredRuleCountOpt'),
        'riskScoreOpt': highest_risk_sequence.get('riskScoreOpt'),

        'commentId': latest_asset_comment.get('commentId'),
        'commentType': latest_asset_comment.get('commentType'),
        'commentObjectId': latest_asset_comment.get('commentObjectId'),
        'text': latest_asset_comment.get('text'),
        'exaUser': latest_asset_comment.get('exaUser'),
        'exaUserFullname': latest_asset_comment.get('exaUserFullname'),
        'createTime': convert_unix_to_date(latest_asset_comment.get('createTime')),
        'updateTime': convert_unix_to_date(latest_asset_comment.get('updateTime')),
        'edited': latest_asset_comment.get('edited')
    }
    asset_info.update(contents_asset_data(asset_))
    return asset_info


def contents_append_notable_session_details(session) -> dict:
    """Appends a dictionary of data to the base list

    Args:
        session: session object

    Returns:
        A contents list with the relevant notable session details
    """
    content = {
        'SessionID': session.get('sessionId'),
        'InitialRiskScore': session.get('initialRiskScore'),
        'LoginHost': session.get('loginHost'),
        'Accounts': session.get('accounts'),
    }
    return content


def contents_append_notable_session_user_details(user_details, user_info) -> dict:
    """Appends a dictionary of filtered data to the base list for the context

    Args:
        user_details: user details object
        user_info: user info object

    Returns:
        A contents list with the relevant notable session details
    """
    content = {
        'UserName': user_details.get('username'),
        'RiskScore': round(user_details.get('riskScore')) if 'riskScore' in user_details else None,
        'AverageRiskScore': user_details.get('averageRiskScore'),
        'FirstSeen': convert_unix_to_date(user_details.get('firstSeen')) if 'firstSeen' in user_details else None,
        'LastSeen': convert_unix_to_date(user_details.get('lastSeen')) if 'lastSeen' in user_details else None,
        'lastActivityType': user_details.get('lastActivityType'),
        'Labels': user_details.get('labels'),
        'LastSessionID': user_details.get('lastSessionId'),
        'EmployeeType': user_info.get('employeeType'),
        'Department': user_info.get('department'),
        'Title': user_info.get('title'),
        'Location': user_info.get('location'),
        'Email': user_info.get('email'),
    }
    return content


def contents_append_notable_sequence_details(sequence, sequence_info) -> dict:
    """Appends a dictionary of filtered data to the base list for the context

    Args:
        sequence: sequence object
        sequence_info: sequence_info object

    Returns:
        A contents list with the relevant notable sequence details
    """
    content = {
        'sequenceId': sequence.get('sequenceId'),
        'isWhitelisted': sequence.get('isWhitelisted'),
        'areAllTriggeredRulesWhiteListed': sequence.get('areAllTriggeredRulesWhiteListed'),
        'hasBeenPartiallyWhiteListed': sequence.get('hasBeenPartiallyWhiteListed'),
        'riskScore': round(sequence_info.get('riskScore')) if 'riskScore' in sequence_info else None,
        'startTime': convert_unix_to_date(sequence_info.get('startTime')) if 'startTime' in sequence_info else None,
        'endTime': convert_unix_to_date(sequence_info.get('endTime')) if 'endTime' in sequence_info else None,
        'numOfReasons': sequence_info.get('numOfReasons'),
        'numOfEvents': sequence_info.get('numOfEvents'),
        'numOfUsers': sequence_info.get('numOfUsers'),
        'numOfSecurityEvents': sequence_info.get('numOfSecurityEvents'),
        'numOfZones': sequence_info.get('numOfZones'),
        'numOfAssets': sequence_info.get('numOfAssets'),
        'assetId': sequence_info.get('assetId'),
    }
    return content


def contents_append_notable_sequence_event_types(sequence, asset_sequence_id) -> dict:
    """Appends a dictionary of filtered data to the base list for the context

    Args:
        sequence: sequence object
        asset_sequence_id: asset sequence ID

    Returns:
        A contents list with the relevant notable sequence event types
    """
    content = {
        'eventType': sequence.get('eventType'),
        'displayName': sequence.get('displayName'),
        'count': sequence.get('count'),
        'sequenceId': asset_sequence_id
    }
    return content


def contents_asset_data(asset_data) -> dict:
    """create a content obj for the asset

    Args:
        asset_data: asset data
    Returns:
        A contents dict with the relevant asset data
    """
    contents = {
        'HostName': asset_data.get('hostName'),
        'IPAddress': asset_data.get('ipAddress'),
        'AssetType': asset_data.get('assetType'),
        'FirstSeen': convert_unix_to_date(asset_data.get('firstSeen')),
        'LastSeen': convert_unix_to_date(asset_data.get('lastSeen')),
        'Labels': asset_data.get('labels')
    }
    return contents


def get_rules_in_xsoar_format(rules_raw_data: list | dict, from_idx: int, to_idx: int) -> tuple[list[Any], str]:
    """ Converts rules raw data to XSOAR format.

    Args:
        rules_raw_data: rules raw data
        from_idx: from index (used for slicing)
        to_idx: to index (used for slicing)
    Returns:
        (tuple) Rules in XSOAR format and the human readable.
    """
    outputs = []

    for category in rules_raw_data:
        # raw data contains rules aggregated by categories - we flat them to a single rules array
        if len(category.get('rules', [])) > 0:
            rules = category.get('rules', [])
            for rule in rules:
                rule['categoryId'] = category.get('categoryId')
                rule['categoryDisplayName'] = category.get('categoryDisplayName')
                outputs.append(rule)

    res = outputs[from_idx:to_idx]

    return res, tableToMarkdown('Rule Search Results', res, removeNull=True, headerTransform=pascalToSpace)


def aggregated_events_to_xsoar_format(asset_id: str, events: list[Any]) -> tuple[list[Any], str]:
    """ Converts an asset aggregated events raw data to XSOAR format.

    Args:
        asset_id: The Asset ID
        events: events raw data
    Returns:
        (tuple) Events in XSOAR format and the human readable.
    """
    outputs = []
    aggregated_events_data = [{
        'start_time': convert_unix_to_date(event.get('ts'), sep=' '),
        'end_time': convert_unix_to_date(event.get('te'), sep=' '),
        'count': event.get('c'),
        'event_type': event.get('tp'),
        'events': event.get('es')
    } for event in events]

    human_readable = f'# Asset {asset_id} Next Events\n'

    for activity in aggregated_events_data:
        if isinstance(activity['count'], int) and activity['count'] > 0:
            activity_events = [event.get('fields') for event in activity['events']]
            for event in activity_events:
                event['time'] = convert_unix_to_date(event.get('time'))
                event['rawlog_time'] = convert_unix_to_date(event.get('rawlog_time'))

                # renaming attributes with unclear names
                if "getvalue('zone_info', src)" in event:
                    event['src_zone'] = event.pop("getvalue('zone_info', src)")
                elif "getvalue('zone_info', dest)" in event:
                    event['dest_zone'] = event.pop("getvalue('zone_info', dest)")

            title = f"{activity['count']} {activity['event_type']} event(s) " \
                    f"between {activity['start_time']} and {activity['end_time']}"
            human_readable += tableToMarkdown(title, activity_events, removeNull=True,
                                              headerTransform=underscoreToCamelCase) + '\n'
            outputs.extend(activity_events)

    return outputs, human_readable


def parse_context_table_records_list(records_list: list, fmt: str, is_delete: bool = False):
    """ Parses records list given as an argument in context tables management commands.

    Args:
        records_list: The list of records
        fmt: The format of each record, e.g. id:key:value
        is_delete: Whether or not it is a delete request
    Returns:
        (list) The records, in request payload format.
    """
    records = []
    for record_item in records_list:
        record_item = record_item.split(':')
        keys = fmt.split(':')
        if len(keys) != len(record_item):
            raise ValueError('records argument is malformed.')

        record = dict(zip(keys, record_item))
        if is_delete:
            record['key'] = ''
        if record.get('value'):
            record['value'] = record['value'].split(';')
        elif record.get('value') == '':
            record['value'] = []
        records.append(record)
    return records


def create_context_table_updates_outputs(name: str, raw_response: dict) -> tuple[Any, dict[str, Any]]:
    # flatten results
    outputs = [{
        'contextTableName': name,
        'sessionId': raw_response.get('sessionId'),
        'changeType': record.get('changeType'),
        'changeId': record.get('changeId'),
        'record': record.get('record')
    } for record in raw_response.get('recordChanges', [])]

    entry_context = {'Exabeam.ContextTableUpdate(val.changeId && val.changeId === obj.changeId)': outputs}

    metadata_str = ', '.join([f'{k}: {v}' for k, v in raw_response.get('metadata', {}).items()])
    human_readable = tableToMarkdown(f'Context Table {name} Update Details', outputs,
                                     headerTransform=pascalToSpace, removeNull=True, metadata=metadata_str)

    return human_readable, entry_context


def order_time_as_milisecound_for_fetch(start_time: str, end_time: str) -> tuple[str, str]:

    start = datetime.strptime(start_time, DATETIME_FORMAT_MILISECONDS)
    end = datetime.strptime(end_time, DATETIME_FORMAT_MILISECONDS)

    start_unix = convert_date_to_unix(start.strftime(DATETIME_FORMAT_MILISECONDS))
    end_unix = convert_date_to_unix(end.strftime(DATETIME_FORMAT_MILISECONDS))

    return str(start_unix), str(end_unix)


def convert_all_unix_keys_to_date(incident: dict) -> dict:
    keys = ['createdAt', 'startedDate', 'closedDate', 'updatedAt']
    if 'baseFields' in incident:
        for key in keys:
            if key in incident['baseFields']:
                incident['baseFields'][key] = convert_unix_to_date(incident['baseFields'][key]).split('.')[0] + 'Z'
    return incident


def convert_all_unix_keys_to_date_user(incident: dict) -> dict:
    keys = ['firstSeen', 'lastSeen', 'lastActivityTime', 'endTime', 'startTime']
    if 'user' in incident:
        for key in keys:
            if key in incident['user']:
                incident['user'][key] = convert_unix_to_date(incident['user'][key]).split('.')[0] + 'Z'
            if key in incident['highestRiskSession'] and incident['highestRiskSession'][key]:
                incident['highestRiskSession'][key] = convert_unix_to_date(
                    incident['highestRiskSession'][key]).split('.')[0] + 'Z'
    return incident


def build_incident_response_query_params(query: str | None,
                                         incident_type: str | None,
                                         priority: str | None,
                                         status: str | None,
                                         limit: int | None,
                                         page_size: int | None,
                                         page_number: int | None,
                                         ) -> dict:

    params: dict[str, Any] = {}
    if not query:
        q = ''
        if incident_type:
            q += f'incidentType:{incident_type} AND '
        if priority:
            q += f'priority:{priority} AND '
        if status:
            q += f'status:{status}'

        if q.strip().split(' ')[-1] == 'AND':
            q = q[:-(len(' AND '))]

        if q:
            params['query'] = q
    else:
        params['query'] = query

    if page_size and page_number:
        params['offset'] = page_size * page_number

    if limit:
        params['length'] = limit

    return params


''' COMMANDS '''


def test_module(client: Client, args: dict[str, str], params: dict[str, str]):
    """test function

    Args:
        client: Client

    Returns:
        ok if successful
    """
    client.test_module_request()

    is_fetch = argToBoolean(params.get("isFetch") or False)
    if is_fetch:
        fetch_type = params.get("fetch_type", DEFAULT_FETCH_TYPE)
        if "Exabeam Notable User" in fetch_type:

            fetch_interval = arg_to_number(params.get("notable_users_fetch_interval")) or 60
            if fetch_interval % 60 != 0:
                raise ValueError("The Notable Users Fetch Interval must be specified in whole hours")

            max_fetch_users = arg_to_number(params.get("max_fetch_users")) or DEFAULT_LIMIT
            if max_fetch_users <= 0 or max_fetch_users > MAX_LIMIT_FETCH_USERS:
                raise ValueError("The Max Users Per Fetch must be between 1 and 200")

            client.get_notable_users_request("h", "1", 1)

        if "Exabeam Incident" in fetch_type:
            client.get_incidents({})

    demisto.results('ok')


def get_notable_users(client: Client, args: dict) -> tuple[str, dict, dict]:
    """ Get notable users in a period of time

    Args:
        client: Client
        args: Dict

    """
    limit: int = args.get('limit', 10)
    time_period: str = args.get('time_period', '')
    time_ = time_period.split(' ')
    if not len(time_) == 2:
        raise Exception('Got invalid time period. Enter the time period number and unit. For example, 20 d.')
    num: str = time_[0]
    unit: str = time_[1]
    api_unit = unit[0]
    if api_unit == 'm':
        api_unit = api_unit.upper()

    if api_unit.lower() not in {'d', 'y', 'm', 'h'}:
        raise Exception('The time unit is incorrect - can be d, y, m or h.')

    contents: list = []
    headers = ['UserName', 'UserFullName', 'Title', 'Department', 'RiskScore', 'Labels', 'NotableSessionIds',
               'EmployeeType', 'FirstSeen', 'LastSeen', 'LastActivity', 'Location']
    raw_users = client.get_notable_users_request(api_unit, num, limit)
    users = raw_users.get('users', [])
    if not users:
        return 'No users were found in this period of time.', {}, {}

    for user in users:
        user_ = user.get('user', {})
        user_info = user_.get('info', {})
        contents = contents_append_notable_user_info(contents, user, user_, user_info)

    entry_context = {'Exabeam.User(val.UserName && val.UserName === obj.UserName)': contents}
    human_readable = tableToMarkdown('Exabeam Notable Users:', contents, headers=headers, removeNull=True)

    return human_readable, entry_context, raw_users


def get_user_info(client: Client, args: dict) -> tuple[str, dict, dict]:
    """Returns User info data for the given username
    Args:
        client: Client
        args: Dict

    """
    username: str = args.get('username', '')
    headers = ['Username', 'RiskScore', 'AverageRiskScore', 'LastSessionID', 'Labels', 'FirstSeen',
               'LastSeen', 'LastActivityType', 'AccountNames', 'PeerGroupFieldName', 'PeerGroupFieldValue',
               'PeerGroupDisplayName', 'PeerGroupType']
    user = client.get_user_info_request(username)
    user_info = user.get('userInfo', {})
    if not user_info:
        raise Exception('User has no info. Please check that the username and not the userFullName was inserted.')
    contents = contents_user_info(user, user_info)
    context = {'Exabeam.User(val.UserName && val.UserName === obj.UserName)': contents}

    if not user_info.get('firstSeen'):
        return f'The user {username} was not found', {}, {}

    human_readable = tableToMarkdown(f'User {username} information:', contents, headers, removeNull=True)
    return human_readable, context, user


def get_user_sessions(client: Client, args: dict) -> tuple[str, dict, dict]:
    """Returns sessions for the given username and time range

    Args:
        client: Client
        args: Dict

    """
    username = args.get('username')
    start_time = args.get('start_time', '30 days ago')
    end_time = args.get('end_time', '0 minutes ago')
    parse_start_time = convert_date_to_unix(start_time)
    parse_end_time = convert_date_to_unix(end_time)
    contents = []
    headers = ['SessionID', 'RiskScore', 'InitialRiskScore', 'StartTime', 'EndTime', 'LoginHost', 'Label']

    user = client.user_sequence_request(username, parse_start_time, parse_end_time)
    session = user.get('sessions')
    if not session:
        return f'The user {username} has no sessions in this time frame.', {}, {}

    for session_ in session:
        contents.append({
            'SessionID': session_.get('sessionId'),
            'StartTime': convert_unix_to_date(session_.get('startTime')),
            'EndTime': convert_unix_to_date(session_.get('endTime')),
            'InitialRiskScore': session_.get('initialRiskScore'),
            'RiskScore': round(session_.get('riskScore')),
            'LoginHost': session_.get('loginHost'),
            'Label': session_.get('label')
        })

    entry_context = {
        'Exabeam.User(val.SessionID && val.SessionID === obj.SessionID)': {
            'Username': username,
            'Session': contents
        }
    }
    human_readable = tableToMarkdown(f'User {username} sessions information:', contents, headers, removeNull=True)

    return human_readable, entry_context, user


def get_peer_groups(client: Client, *_) -> tuple[str, dict, dict]:
    """Returns all peer groups

    Args:
        client: Client

    """
    groups = client.get_peer_groups_request()
    contents = []
    for group in groups:
        contents.append({'Name': group})

    entry_context = {'Exabeam.PeerGroup(val.Name && val.Name === obj.Name)': contents}
    human_readable = tableToMarkdown('Exabeam Peer Groups:', contents)

    return human_readable, entry_context, groups


def get_user_labels(client: Client, *_) -> tuple[str, dict, dict]:
    """ Returns all user Labels

    Args:
        client: Client

    """
    labels = client.get_user_labels_request()
    contents = []
    for label in labels:
        contents.append({'Label': label})

    entry_context = {'Exabeam.UserLabel(val.Label && val.Label === obj.Label)': contents}
    human_readable = tableToMarkdown('Exabeam User Labels:', contents)

    return human_readable, entry_context, labels


def get_watchlist(client: Client, *_) -> tuple[str, dict, dict]:
    """  Returns all watchlist ids and titles.

    Args:
        client: Client

    """

    watchlist = client.get_watchlist_request()
    contents = []
    for list_ in watchlist:
        contents.append({
            'WatchlistID': list_.get('watchlistId'),
            'Title': list_.get('title'),
            'Category': list_.get('category')
        })

    entry_context = {'Exabeam.Watchlist(val.WatchlistID && val.WatchlistID === obj.WatchlistID)': contents}
    human_readable = tableToMarkdown('Exabeam Watchlists:', contents, headers=['WatchlistID', 'Title', 'Category'])

    return human_readable, entry_context, watchlist


def delete_watchlist(client: Client, args: dict) -> tuple[str, dict, dict]:
    """Delete a watchlist

    Args:
        client: Client
        args: Dict

    """

    watchlist_id = args.get('watchlist_id')
    client.delete_watchlist_request(watchlist_id)

    return f'The watchlist {watchlist_id} was deleted successfully.', {}, {}


def get_asset_data(client: Client, args: dict) -> tuple[Any, dict[str, dict[Any, Any]], Any | None]:
    """  Return asset data for given asset ID (hostname or IP address)

    Args:
        client: Client
        args: Dict

    """
    asset_name = args.get('asset_name')
    asset_raw_data = client.get_asset_data_request(asset_name)

    if not asset_raw_data or 'asset' not in asset_raw_data:
        raise Exception(f'The asset {asset_name} has no data. Please verify that the asset name is valid.')

    asset_data = asset_raw_data.get('asset')
    contents = contents_asset_data(asset_data)
    entry_context = {'Exabeam.Asset(val.IPAddress && val.IPAddress === obj.IPAddress)': contents}
    human_readable = tableToMarkdown('Exabeam Asset Data:', contents, removeNull=True)

    return human_readable, entry_context, asset_raw_data


def get_session_info_by_id(client: Client, args: dict) -> tuple[Any, dict[str, Any | None], dict[Any, Any]]:
    """  Return session information for a given session ID

    Args:
        client: Client
        args: Dict

    """
    session_id = args.get('session_id')
    session_info_raw_data = client.get_session_info_request(session_id)

    session_info = session_info_raw_data.get('sessionInfo')

    if session_info and isinstance(session_info, dict):
        session_info['startTime'] = convert_unix_to_date(session_info.get('startTime'))
        session_info['endTime'] = convert_unix_to_date(session_info.get('endTime'))

    entry_context = {'Exabeam.SessionInfo(val.sessionId && val.sessionId === obj.sessionId)': session_info}
    human_readable = tableToMarkdown(f'Session {session_id} Information', session_info,
                                     removeNull=True, headerTransform=pascalToSpace)

    return human_readable, entry_context, session_info_raw_data


def list_top_domains(client: Client, args: dict) -> tuple[Any, dict[str, dict[Any, Any]], Any | None]:
    """  Return session information for given session ID

    Args:
        client: Client
        args: Dict

    """
    sequence_id = args.get('sequence_id')
    sequence_type = args.get('sequence_type')
    top_domains_raw_data = client.list_top_domains_request(sequence_id, sequence_type)

    top_domains = top_domains_raw_data.get('topDomains', [])

    entry_context = {'Exabeam.DataFeed(val.sequenceId && val.sequenceId === obj.sequenceId)': top_domains_raw_data}
    human_readable = tableToMarkdown(f'Sequence {sequence_id} Top Domains', top_domains,
                                     removeNull=True, headerTransform=pascalToSpace)

    return human_readable, entry_context, top_domains_raw_data


def list_triggered_rules(client: Client, args: dict) -> tuple[Any, dict[str, Any | None], dict[Any, Any]]:
    """  Returns all triggered rules for a given sequence

    Args:
        client: Client
        args: Dict

    """
    sequence_id = args.get('sequence_id')
    sequence_type = args.get('sequence_type')
    triggered_rules_raw_data = client.list_triggered_rules_request(sequence_id, sequence_type)

    triggered_rules = triggered_rules_raw_data.get('triggeredRules', [])
    for triggered_rule in triggered_rules:
        triggered_rule['createdTime'] = convert_unix_to_date(triggered_rule.get('createdTime'))
        triggered_rule['triggeringTime'] = convert_unix_to_date(triggered_rule.get('triggeringTime'))

    entry_context = {'Exabeam.TriggeredRules(val._Id && val._Id === obj._Id)': triggered_rules}
    human_readable = tableToMarkdown(f'Sequence {sequence_id} Triggered Rules', triggered_rules,
                                     removeNull=True)

    return human_readable, entry_context, triggered_rules_raw_data


def get_asset_info(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, Any | None], dict[Any, Any]]:
    """  Returns asset info for given asset ID (hostname or IP address)

    Args:
        client: Client
        args: Dict

    """
    asset_id = args.get('asset_id')
    max_users_number = int(args['max_users_number'])
    asset_raw_data = client.get_asset_info_request(asset_id, max_users_number)

    asset_info = asset_raw_data.get('info', {})
    asset_info['assetId'] = asset_id
    asset_info['firstSeen'] = convert_unix_to_date(asset_info.get('firstSeen'))
    asset_info['lastSeen'] = convert_unix_to_date(asset_info.get('lastSeen'))
    entry_context = {'Exabeam.AssetInfo(val.assetId && val.assetId === obj.assetId)': asset_info}
    human_readable = tableToMarkdown(f'Asset {asset_id} Information', asset_info,
                                     removeNull=True, headerTransform=pascalToSpace)

    return human_readable, entry_context, asset_raw_data


def list_asset_next_events(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, list[Any]], dict[Any, Any]]:
    """  Returns next events for a given asset.

    Args:
        client: Client
        args: Dict

    """
    asset_id = args['asset_id']
    event_time = convert_date_to_unix(args['event_time'])
    number_of_events = int(args['number_of_events'])
    anomaly_only = args.get('anomaly_only')
    event_categories = argToList(args.get('event_categories'))
    event_types = argToList(args.get('event_types'))
    event_type_include = 'true' if args.get('event_types_operator') == 'include' else 'false'
    sequence_types = argToList(args.get('sequence_types'))

    events_raw_data = client.list_asset_next_events_request(asset_id,
                                                            event_time,
                                                            number_of_events,
                                                            anomaly_only,
                                                            event_categories,
                                                            event_types,
                                                            event_type_include,
                                                            sequence_types)

    aggregated_events = events_raw_data.get('aggregatedEvents', [])
    aggregated_events, human_readable = aggregated_events_to_xsoar_format(asset_id, aggregated_events)

    entry_context = {'Exabeam.AssetEvent(val.event_id && val.event_id === obj.event_id)': aggregated_events}

    return human_readable, entry_context, events_raw_data


def list_security_alerts_by_asset(client: Client,
                                  args: dict[str, str]) -> tuple[Any, dict[str, list[Any]], dict[Any, Any]]:
    """  Returns security alerts for a given asset.

    Args:
        client: Client
        args: Dict

    """
    asset_id = args.get('asset_id')
    sort_by = args.get('sort_by')
    sort_order = 1 if args.get('sort_order') == 'asc' else -1
    limit = int(args['limit'])

    security_alerts_raw_data = client.list_security_alerts_request(asset_id, sort_by, sort_order, limit)

    security_alerts = []
    for security_alert in security_alerts_raw_data.get('events', []):
        security_alert = security_alert.get('fields')
        security_alert['time'] = convert_unix_to_date(security_alert.get('time'))
        security_alert['rawlog_time'] = convert_unix_to_date(security_alert.get('rawlog_time'))
        security_alerts.append(security_alert)

    human_readable = tableToMarkdown(f'Asset {asset_id} Security Alerts', security_alerts,
                                     removeNull=True, headerTransform=underscoreToCamelCase)

    entry_context = {'Exabeam.AssetSecurityAlert': security_alerts}

    return human_readable, entry_context, security_alerts_raw_data


def search_rules(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, list[Any]], list | dict]:
    """  Searches for rules by a keyword.

    Args:
        client: Client
        args: Dict

    """
    keyword = args.get('keyword')
    filter_exp = args.get('filter')

    limit = int(args['limit'])
    page = int(args['page'])
    from_idx = page * limit
    to_idx = (page + 1) * limit

    rules_raw_data = client.search_rules_request(keyword, filter_exp)
    rules, human_readable = get_rules_in_xsoar_format(rules_raw_data, from_idx, to_idx)

    entry_context = {'Exabeam.Rule(val.ruleId && val.ruleId === obj.ruleId)': rules}

    return human_readable, entry_context, rules_raw_data


def get_rule_string(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, dict[str, Any | None]], str]:
    """  Gets a rule string by ID.

    Args:
        client: Client
        args: Dict

    """
    rule_id = args.get('rule_id')

    rule_string_raw_data = client.get_rule_string_request(rule_id)
    outputs = {}
    entry_context = {}
    if rule_string_raw_data:
        outputs = {'ruleId': rule_id, 'ruleString': rule_string_raw_data}
        entry_context = {'Exabeam.Rule(val.ruleId && val.ruleId === obj.ruleId)': outputs}
    human_readable = tableToMarkdown(f'Rule {rule_id} String', outputs, headerTransform=pascalToSpace)

    return human_readable, entry_context, rule_string_raw_data


def fetch_rules(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, Any], Any | None]:
    """  Gets all rules.

    Args:
        client: Client
        args: Dict

    """
    filter_by = args.get('filter_by')

    limit = int(args['limit'])
    page = int(args['page'])
    from_idx = page * limit
    to_idx = (page + 1) * limit

    rules_raw_data = client.fetch_rules_request(filter_by)
    rules, human_readable = get_rules_in_xsoar_format(rules_raw_data, from_idx, to_idx)
    entry_context = {'Exabeam.Rule(val.ruleId && val.ruleId === obj.ruleId)': rules}

    return human_readable, entry_context, rules_raw_data


def get_rules_model_definition(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, Any], Any | None]:
    """  Gets a rule model definition by name.

    Args:
        client: Client
        args: Dict

    """
    model_name = args.get('model_name')

    model = client.get_model_definition_request(model_name)
    entry_context = {'Exabeam.Model(val.name && val.name === obj.name)': model}
    human_readable = tableToMarkdown(f'Model {model_name} Definition', model,
                                     headerTransform=pascalToSpace, removeNull=True)

    return human_readable, entry_context, model


def add_watchlist_items(client: Client, args: dict[str, str]) -> tuple[str, Any | None, Any | None]:
    """  Add a watchlist items by names or from a CSV file.

    Args:
        client: Client
        args: Dict

    """
    watchlist_id = args.get('watchlist_id')
    csv_entry_id = args.get('csv_entry_id')
    items = argToList(args.get('items', ''))
    category = args.get('category')
    watch_until_days = int(args['watch_until_days'])

    if csv_entry_id and not items:
        raw_response = client.add_watchlist_items_from_csv_request(watchlist_id, watch_until_days,
                                                                   csv_entry_id, category)
        added_count = raw_response.get('addedCount')
    elif items and not csv_entry_id:
        raw_response = client.add_watchlist_items_by_name_request(watchlist_id, watch_until_days, items, category)
        added_count = raw_response.get('numberAdded')
    else:
        raise DemistoException('You must specify exactly one of the following arguments: items, csv_entry_id.')

    human_readable = f'Successfully added {added_count} items to watchlist {watchlist_id}.'

    return human_readable, None, raw_response


def search_asset_in_watchlist(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, Any], Any | None]:
    """  Gets the assets of a specified watchlist according to a keyword.

    Args:
        client: Client
        args: Dict

    """
    keyword = args.get('keyword')
    watchlist_id = args.get('watchlist_id')
    limit = int(args['limit'])
    is_exclusive = args.get('is_exclusive')
    search_by_ip = args.get('search_by_ip')

    assets_raw_data = client.search_asset_in_watchlist_request(keyword, watchlist_id, limit, is_exclusive, search_by_ip)
    assets = assets_raw_data.get('assets', [])
    for asset in assets:
        asset['firstSeen'] = convert_unix_to_date(asset.get('firstSeen'))
        asset['lastSeen'] = convert_unix_to_date(asset.get('lastSeen'))
    entry_context = {'Exabeam.AssetInfo((val.ipAddress && val.ipAddress === obj.ipAddress) ||'
                     '(val.hostName && val.hostName === obj.hostName))': assets}
    human_readable = tableToMarkdown(f'Watchlist {watchlist_id} Assets Search Results', assets,
                                     headerTransform=pascalToSpace, removeNull=True)

    return human_readable, entry_context, assets_raw_data


def remove_watchlist_items(client: Client, args: dict[str, str]) -> tuple[str, Any | None, Any | None]:
    """  Removes items from a watchlist.

    Args:
        client: Client
        args: Dict

    """
    watchlist_id = args.get('watchlist_id')
    items = argToList(args.get('items'))
    category = args.get('category')

    raw_response = client.remove_watchlist_items_request(watchlist_id, items, category)
    removed_count = raw_response.get('numberRemoved')

    human_readable = f'Successfully removed {removed_count} items from watchlist {watchlist_id}.'

    return human_readable, None, raw_response


def list_context_table_records(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, Any], Any | None]:
    """  Returns a list of a context table records.

    Args:
        client: Client
        args: Dict

    """
    context_table_name = args.get('context_table_name')
    page_size = int(args.get('limit', 50))
    page_number = int(args.get('offset', 1))

    records_raw_data = client.list_context_table_records_request(context_table_name, page_size, page_number)
    records = records_raw_data.get('records', [])

    entry_context = {
        'Exabeam.ContextTable(val.Name && val.Name === obj.Name)':
            {
                'Name': context_table_name,
                'Record': records
            }
    }
    human_readable = tableToMarkdown(f'Context Table `{context_table_name}` Records', records,
                                     headers=['id', 'position', 'sourceType', 'key', 'value'],
                                     headerTransform=pascalToSpace, removeNull=True)

    return human_readable, entry_context, records_raw_data


def add_context_table_records(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, Any], Any | None]:
    """  Adds records to a context table.

    Args:
        client: Client
        args: Dict

    """
    context_table_name = args['context_table_name']
    session_id = args.get('session_id')
    key_only = args.get('context_table_type') == 'key_only'
    records_list = argToList(args.get('records'))

    record_updates_raw_data = client.add_context_table_records_request(context_table_name, records_list,
                                                                       key_only, session_id)
    human_readable, entry_context = create_context_table_updates_outputs(context_table_name, record_updates_raw_data)
    return human_readable, entry_context, record_updates_raw_data


def update_context_table_records(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, Any], Any | None]:
    """  Updates records of a context table.

    Args:
        client: Client
        args: Dict

    """
    context_table_name = args['context_table_name']
    session_id = args.get('session_id')
    records = argToList(args.get('records'))
    key_only = args.get('context_table_type') == 'key_only'

    record_updates_raw_data = client.update_context_table_records_request(context_table_name, records,
                                                                          key_only, session_id)
    human_readable, entry_context = create_context_table_updates_outputs(context_table_name, record_updates_raw_data)
    return human_readable, entry_context, record_updates_raw_data


def delete_context_table_records(client: Client, args: dict) -> tuple[Any, dict[str, Any], Any | None]:
    """  Deletes records of a context table.

    Args:
        client: Client
        args: Dict

    """
    context_table_name = args['context_table_name']
    session_id = args.get('session_id')
    records = argToList(args.get('records'))

    records_raw_data = client.list_context_table_records_request(context_table_name, 10000, 1)
    all_records = records_raw_data.get('records', [])
    ids = [record['id'] for record in all_records if record['key'] in records]

    record_updates_raw_data = client.delete_context_table_records_request(context_table_name, ids, session_id)
    human_readable, entry_context = create_context_table_updates_outputs(context_table_name, record_updates_raw_data)
    return human_readable, entry_context, record_updates_raw_data


def add_context_table_records_from_csv(client: Client,
                                       args: dict[str, str]) -> tuple[Any, dict[str, Any], Any | None]:
    """  Bulk addition of a context table records from CSV file.

    Args:
        client: Client
        args: Dict

    """
    context_table_name = args['context_table_name']
    session_id = args.get('session_id')
    file_entry_id = args.get('file_entry_id')
    has_header = args.get('has_header') == 'true'
    replace = args.get('append_or_replace') == 'replace'

    record_updates_raw_data = client.add_context_table_records_from_csv_request(context_table_name, file_entry_id,
                                                                                has_header, session_id, replace)
    human_readable, entry_context = create_context_table_updates_outputs(context_table_name, record_updates_raw_data)
    return human_readable, entry_context, record_updates_raw_data


def get_context_table_csv(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, Any], Any | None]:
    """  Updates records of a context table.

    Args:
        client: Client
        args: Dict

    """
    context_table_name = args['context_table_name']

    filename, content = client.get_context_table_csv_request(context_table_name)

    demisto.results(fileResult(filename, content))
    return f'Successfully downloaded Context Table CSV file {context_table_name}.', {}, None


def get_notable_assets(client: Client, args: dict) -> tuple[Any, dict[str, Any], Any | None]:
    """  Updates records of a context table.

    Args:
        client: Client
        args: Dict

    """
    limit: int = args.get('limit', 10)
    time_period: str = args.get('time_period', '')
    time_ = time_period.split(' ')
    if not len(time_) == 2:
        raise Exception('Got invalid time period. Enter the time period number and unit.')
    num: str = time_[0]
    unit: str = time_[1]
    api_unit = unit[0]
    if api_unit == 'm':
        api_unit = api_unit.upper()

    if api_unit not in {'d', 'y', 'M', 'h'}:
        raise Exception('The time unit is incorrect - can be hours, days, months, years.')

    notable_assets_raw_data = client.get_notable_assets_request(api_unit, num, limit)
    notable_assets = notable_assets_raw_data.get('assets')

    if not notable_assets:
        return 'No users were found in this period of time.', {}, {}

    contents: list = []
    for asset in notable_assets:
        asset_ = asset.get('asset', {})
        highest_risk_sequence = asset.get('highestRiskSequence', {})
        latest_asset_comment = asset.get('latestAssetComment', {})
        contents.append(contents_append_notable_assets_info(asset, asset_, highest_risk_sequence, latest_asset_comment))

    entry_context = {'Exabeam.NotableAsset((val.ipAddress && val.ipAddress === obj.ipAddress) '
                     '|| (val.hostName && val.hostName === obj.hostName))': contents}
    human_readable = tableToMarkdown('Exabeam Notable Assets:', contents, removeNull=True)

    return human_readable, entry_context, notable_assets


def get_notable_session_details(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, Any], Any | None]:
    """  Updates records of a context table.

    Args:
        client: Client
        args: Dict

    """
    asset_id = args.get('asset_id')
    sort_by = args.get('sort_by')
    sort_order = 1 if args.get('sort_order') == 'asc' else -1
    limit = int(args['limit'])

    session_details_raw_data = client.get_notable_session_details_request(asset_id, sort_by, sort_order, limit)

    contents: list = []
    users: list = []
    executive_user_flags: list = []
    sessions = session_details_raw_data.get('sessions', {})
    for session in sessions:
        contents.append(contents_append_notable_session_details(session))

    users_response = session_details_raw_data.get('users', {})
    for _user_name, user_details in users_response.items():
        user_info = user_details.get('info', {})
        users.append(contents_append_notable_session_user_details(user_details, user_info))

    executive_user = session_details_raw_data.get('executiveUserFlags', {})
    for username, status in executive_user.items():
        executive_user_flags.append({
            username: status
        })

    contents_entry = {'sessions': contents, 'users': users, 'executiveUserFlags': executive_user_flags}
    entry_context = {'Exabeam.NotableSession(val.SessionID && val.SessionID === obj.SessionID)': contents_entry}
    if sessions:
        human_readable = tableToMarkdown('Notable Sessions details:', sessions, removeNull=True)
    else:
        human_readable = 'No results found.'

    return human_readable, entry_context, session_details_raw_data


def get_notable_sequence_details(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, Any], Any | None]:
    """  Updates records of a context table.

    Args:
        client: Client
        args: Dict

    """
    asset_id = args.get('asset_id')
    start_time = args.get('start_time', '30 days ago')
    end_time = args.get('end_time', '0 minutes ago')
    parse_start_time = convert_date_to_unix(start_time)
    parse_end_time = convert_date_to_unix(end_time)

    limit = int(args['limit'])
    page = int(args['page'])
    from_idx = page * limit
    to_idx = (page + 1) * limit

    sequence_details_raw_data = client.get_notable_sequence_details_request(asset_id, parse_start_time, parse_end_time)
    if not sequence_details_raw_data:
        return f'The Asset {asset_id} has no sequence details in this time frame.', {}, {}

    contents: list = []
    for sequence in sequence_details_raw_data:
        sequence_info = sequence.get('sequenceInfo')
        contents.append(contents_append_notable_sequence_details(sequence, sequence_info))

    contents = contents[from_idx:to_idx]

    entry_context = {'Exabeam.Sequence(val.sequenceId && val.sequenceId === obj.sequenceId)': contents}

    human_readable = tableToMarkdown('Notable sequence details:', contents, removeNull=True)

    return human_readable, entry_context, sequence_details_raw_data


def get_notable_sequence_event_types(client: Client, args: dict[str, str]) -> tuple[Any, dict[str, Any], Any | None]:
    """  Updates records of a context table.

    Args:
        client: Client
        args: Dict

    """
    asset_sequence_id = args.get('asset_sequence_id')
    search_str = args.get('search_str')

    limit = int(args['limit'])
    page = int(args['page'])
    from_idx = page * limit
    to_idx = (page + 1) * limit

    sequence_event_types_raw_data = client.get_notable_sequence_event_types_request(asset_sequence_id, search_str)

    if not sequence_event_types_raw_data:
        return f'The Asset {asset_sequence_id} has no sequence event types.', {}, {}

    contents: list = []
    for sequence in sequence_event_types_raw_data:
        contents.append(contents_append_notable_sequence_event_types(sequence, asset_sequence_id))

    contents = contents[from_idx:to_idx]

    entry_context = {'Exabeam.SequenceEventTypes(val.sequenceId && val.sequenceId === obj.sequenceId)': contents}

    human_readable = tableToMarkdown('Sequence event types:', contents, removeNull=True)

    return human_readable, entry_context, sequence_event_types_raw_data


def list_incidents(client: Client, args: dict[str, str]):
    incident_ids = argToList(args.get('incident_id'))
    query = args.get('query')
    incident_type = args.get('incident_type')
    priority = args.get('priority')
    status = args.get('status')
    limit = arg_to_number(args.get('limit', 50))
    page_size = arg_to_number(args.get('page_size', 25))
    page_number = arg_to_number(args.get('page_number', 0))
    username = args.get('username')

    if incident_ids and client.is_token_auth() and not username and not client.username:
        raise ValueError('The username argument is necessary be for this command if the instance configured by api key')

    incidents = []

    if incident_ids:
        for incident_id in incident_ids:
            raw_response = client.get_single_incident(incident_id, username)
            incidents.append(format_single_incident(raw_response))

    else:
        if any((query, incident_type, priority, status)):
            query_params = build_incident_response_query_params(query,
                                                                incident_type,
                                                                priority,
                                                                status,
                                                                limit,
                                                                page_size,
                                                                page_number,
                                                                )
            raw_response = client.get_list_incidents(query_params)
            for incident in raw_response['incidents']:
                incidents.append(format_single_incident(incident))
        else:
            return_error('One of the following params is a must: query, incident_type, priority, status')

    entry_context = {'Exabeam.Incident(val.incidentId && val.incidentId === obj.incidentId)': incidents}

    human_readable = tableToMarkdown('Incidents list:', incidents)

    return human_readable, entry_context, raw_response


def fetch_incidents(client: Client, args: dict[str, str]) -> tuple[list, dict]:
    incidents: list[dict] = []
    last_run: dict[str, Any] = demisto.getLastRun()
    demisto.debug(f"Last run before the fetch run: {last_run}")
    fetch_type = args.get("fetch_type", DEFAULT_FETCH_TYPE)

    if "Exabeam Notable User" in fetch_type:
        incidents, last_run = fetch_notable_users(client, args, last_run)
        demisto.debug(f'After fetch notable users, there are {len(incidents)} new incidents')

    if "Exabeam Incident" in fetch_type:
        exabeam_incidents, updated_last_run = fetch_exabeam_incidents(client, args, last_run)
        incidents.extend(exabeam_incidents)
        last_run.update(updated_last_run)

    demisto.debug(f"Last run after the fetch run: {last_run}")
    return incidents, last_run


def fetch_exabeam_incidents(client: Client, args: dict[str, str], last_run: dict[str, Any]) -> tuple[list, dict]:
    incidents: list[dict] = []
    look_back = arg_to_number(args.get('look_back')) or 1.

    start_time, end_time = get_fetch_run_time_range(
        last_run=last_run,
        first_fetch=args.get('first_fetch', '3 days'),
        look_back=look_back,
        date_format=DATETIME_FORMAT_MILISECONDS,
    )

    demisto.debug(f"fetching incidents between {start_time=} and {end_time=}")
    start_time_as_milisecound, end_time_as_milisecound = order_time_as_milisecound_for_fetch(start_time, end_time)

    demisto.debug(f'fetching incidents between {start_time_as_milisecound=}, {end_time_as_milisecound=} in milisecound')

    incident_type = argToList(args.get('incident_type'))
    priority = argToList(args.get('priority'))
    status = argToList(args.get('status'))
    limit = arg_to_number(args.get('max_fetch', 50))
    q = {
        "queryMap": {
            "status": status,
            "incidentType": incident_type,
            "priority": priority,
            "createdAt": [
                start_time_as_milisecound,
                end_time_as_milisecound
            ],
        },
        "sortBy": "createdAt",
        "sortOrder": "asc",
        "idOnly": False,
        "offset": 0,
        "length": last_run.get('limit') or limit
    }
    demisto.debug(f'The query incidentType: {incident_type}')
    demisto.debug(f'The query for fetch: {q}')

    resp = client.get_incidents(q)
    incidents_res: list[dict] = resp.get('incidents', [])
    demisto.debug(f'Got {len(incidents_res)} incidents from the API, before filtering')

    incidents_filtered = filter_incidents_by_duplicates_and_limit(
        incidents_res=incidents_res,
        last_run=last_run,
        fetch_limit=limit,
        id_field='incidentId'
    )
    demisto.debug(f'After filtering, there are {len(incidents_filtered)} incidents')

    for incident in incidents_filtered:
        incident['createdAt'] = datetime.fromtimestamp(
            incident.get('baseFields', {}).get('createdAt') / 1000.0).strftime(DATETIME_FORMAT_MILISECONDS)
        incident = convert_all_unix_keys_to_date(incident)
        incident['incident_type'] = 'Exabeam Incident'
        incidents.append({
            'Name': incident.get('name'),
            'occurred': incident.get('baseFields', {}).get('createdAt'),
            'rawJSON': json.dumps(incident)
        })

    last_run = update_last_run_object(
        last_run=last_run,
        incidents=incidents_filtered,
        fetch_limit=limit,
        start_fetch_time=start_time,
        end_fetch_time=end_time,
        look_back=look_back,
        created_time_field='createdAt',
        id_field='incidentId',
        date_format=DATETIME_FORMAT_MILISECONDS,
        increase_last_run_time=True
    )
    return incidents, last_run


def fetch_notable_users(client: Client, args: dict[str, str], last_run_obj: dict) -> tuple[list, dict]:
    current_time = datetime.now(timezone.utc)
    last_run_notable_users: str = last_run_obj.get("last_run_notable_users", "")
    demisto.debug(f"Last run notable users: {last_run_notable_users}, before fetch")

    if last_run_notable_users:
        last_run_time = datetime.fromisoformat(last_run_notable_users).astimezone(timezone.utc)
        difference = current_time - last_run_time
        difference_minutes = difference.total_seconds() / 60
        fetch_interval = arg_to_number(args.get("notable_users_fetch_interval")) or 60

       # Ensure fetch_interval is at least 60 and rounded to the nearest multiple of 60
        fetch_interval = max(60, round(fetch_interval / 60) * 60)

        demisto.debug(f"Difference of {difference_minutes} minutes between the current time and the last run notable users")
        if difference_minutes <= fetch_interval:  # Check if the time interval is past.
            return [], last_run_obj

        else:
            time_period = f"{int(fetch_interval/60)} hours"

    else:  # In the first run
        time_period = args.get("notable_users_first_fetch", "3 months")

    limit = arg_to_number(args.get("max_fetch_users")) or DEFAULT_LIMIT
    args_notable_users = {"limit": limit, "time_period": time_period}
    demisto.debug(f"Before the request args notable users, limit: {limit}, time period: {time_period}")
    _, _, res = get_notable_users(client, args_notable_users)
    users = res.get("users", [])
    demisto.debug(f"Got {len(users)} users from the API, before filtering")

    minimum_risks = arg_to_number(args.get("minimum_risk_score_to_fetch_users"))

    existing_usernames: list[str] = last_run_obj.get("usernames", [])

    demisto.debug(f"Existing {len(existing_usernames)} usernames in last run")
    new_risky_users = []
    new_usernames = []
    for user in users:
        user_details = user.get("user", {})
        username = user_details.get("username", "")
        risk_score = user_details.get("riskScore", -1)
        if risk_score >= minimum_risks and username not in existing_usernames:
            new_risky_users.append(user)
            new_usernames.append(username)

    demisto.debug(f"After filtering, there are {len(new_risky_users)} new risky users")

    combined_usernames = existing_usernames + new_usernames

    # Calculate the excess length, which is the amount by which the combined list exceeds the maximum allowed length
    excess_length = max(len(combined_usernames) - MAX_LENGTH_CONTEXT, 0)

    # Create the new list of usernames, trimming the excess from the existing ones
    usernames_to_last_run = existing_usernames[excess_length:] + new_usernames
    demisto.debug(f"{excess_length} usernames deleted from the lest run to avoid exceeding the maximum")

    last_run_obj["usernames"] = usernames_to_last_run
    demisto.debug(f"After the added lest run contain {len(usernames_to_last_run)} usernames")

    incidents: list[dict] = []
    for user_data in new_risky_users:
        user_data_fixed_time = convert_all_unix_keys_to_date_user(user_data)
        user_username = user_data.get("user", {}).get("username", "")
        user_data_fixed_time['incident_type'] = 'Exabeam Notable User'
        incidents.append(
            {
                "Name": user_username,
                "rawJSON": json.dumps(user_data_fixed_time),
            }
        )

    last_run_obj["last_run_notable_users"] = current_time.strftime(DATETIME_FORMAT_MILISECONDS)
    demisto.debug(f"Last run notable users after the fetch run: {last_run_notable_users}")
    return incidents, last_run_obj


def main():  # pragma: no cover
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    api_key = params.get('api_token', {}).get('password')
    base_url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    is_fetch = argToBoolean(params.get('isFetch') or False)
    headers = {'Accept': 'application/json', 'Csrf-Token': 'nocheck'}

    commands = {
        'get-notable-users': get_notable_users,
        'exabeam-get-notable-users': get_notable_users,
        'get-peer-groups': get_peer_groups,
        'exabeam-get-peer-groups': get_peer_groups,
        'get-user-info': get_user_info,
        'exabeam-get-user-info': get_user_info,
        'get-user-labels': get_user_labels,
        'exabeam-get-user-labels': get_user_labels,
        'get-user-sessions': get_user_sessions,
        'exabeam-get-user-sessions': get_user_sessions,
        'get-watchlists': get_watchlist,
        'exabeam-get-watchlists': get_watchlist,
        'exabeam-delete-watchlist': delete_watchlist,
        'exabeam-get-asset-data': get_asset_data,
        'exabeam-get-session-info-by-id': get_session_info_by_id,
        'exabeam-list-top-domains': list_top_domains,
        'exabeam-list-triggered-rules': list_triggered_rules,
        'exabeam-get-asset-info': get_asset_info,
        'exabeam-list-asset-timeline-next-events': list_asset_next_events,
        'exabeam-list-security-alerts-by-asset': list_security_alerts_by_asset,
        'exabeam-search-rules': search_rules,
        'exabeam-get-rule-string': get_rule_string,
        'exabeam-fetch-rules': fetch_rules,
        'exabeam-get-rules-model-definition': get_rules_model_definition,
        'exabeam-list-context-table-records': list_context_table_records,
        'exabeam-add-context-table-records': add_context_table_records,
        'exabeam-add-context-table-records-from-csv': add_context_table_records_from_csv,
        'exabeam-update-context-table-records': update_context_table_records,
        'exabeam-delete-context-table-records': delete_context_table_records,
        'exabeam-get-context-table-in-csv': get_context_table_csv,
        'exabeam-watchlist-add-items': add_watchlist_items,
        'exabeam-watchlist-asset-search': search_asset_in_watchlist,
        'exabeam-watchlist-remove-items': remove_watchlist_items,
        'exabeam-get-notable-assets': get_notable_assets,
        'exabeam-get-notable-sequence-details': get_notable_sequence_details,
        'exabeam-get-notable-session-details': get_notable_session_details,
        'exabeam-get-sequence-eventtypes': get_notable_sequence_event_types,
        'exabeam-list-incident': list_incidents,
    }
    client = None
    try:
        client = Client(base_url.rstrip('/'), verify=verify_certificate, username=username,
                        password=password, proxy=proxy, headers=headers, api_key=api_key, is_fetch=is_fetch)
        command = demisto.command()
        LOG(f'Command being called is {command}.')
        if command == 'fetch-incidents':
            incidents, next_run = fetch_incidents(client, params)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == 'test-module':
            test_module(client, args, params)
        elif command in commands:
            return_outputs(*commands[command](client, args))  # type: ignore
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except DemistoException as err:
        # some of the API error responses are not so clear, and the reason for the error is because of bad input.
        # we concat here a message to the output to make sure
        error_msg = str(err)
        if err.res is not None and err.res.status_code == 500:
            error_msg += '\nThe error might have occurred because of incorrect inputs. ' \
                         'Please make sure your arguments are set correctly.'
        return_error(error_msg)

    except Exception as err:
        return_error(str(err))

    finally:
        if client:
            client.shutdown()


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
