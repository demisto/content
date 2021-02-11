import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Tuple, Dict, List, Any, Optional
from copy import deepcopy
import requests

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


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


class Client(BaseClient):
    """
    Client to use in the Exabeam integration. Overrides BaseClient
    """
    def __init__(self, base_url: str, username: str, password: str, verify: bool,
                 proxy: bool, headers):
        super().__init__(base_url=f'{base_url}', headers=headers, verify=verify, proxy=proxy)
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers = headers
        if not proxy:
            self.session.trust_env = False

        self._login()

    def __del__(self):
        self._logout()

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
        self._http_request('GET', self._http_request('GET', f'{self._base_url}/api/auth/logout'))

    def test_module_request(self):
        """
        Performs basic get request to check if the server is reachable.
        """
        self._http_request('GET', '/uba/api/ping', resp_type='text')

    def get_notable_users_request(self, api_unit: str = None, num: str = None, limit: int = None) -> Dict:
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

    def get_user_info_request(self, username: str) -> Dict:
        """
        Args:
            username: the username

        Returns:
            the user info
        """
        response = self._http_request('GET', url_suffix=f'/uba/api/user/{username}/info')
        return response

    def get_peer_groups_request(self) -> Dict:
        """
        Returns:
            peer groups
        """
        response = self._http_request('GET', url_suffix='/uba/api/peerGroup')
        return response

    def get_user_labels_request(self) -> Dict:
        """
        Returns:
            user labels
        """
        response = self._http_request('GET', url_suffix='/uba/api/userLabel')
        return response

    def user_sequence_request(self, username: str = None, parse_start_time=None, parse_end_time=None) -> Dict:
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

    def get_asset_data_request(self, asset_name: str = None) -> Dict:
        """

        Args:
            asset_name: asset name

        Returns:
            asset data
        """
        response = self._http_request('GET', url_suffix=f'/uba/api/asset/{asset_name}/data')
        return response

    def get_session_info_request(self, session_id: str = None) -> Dict:
        """

            Args:
                session_id: ID of the session to fetch data for

            Returns:
                (dict) The session information.
        """
        response = self._http_request('GET', url_suffix=f'/uba/api/session/{session_id}/info')
        return response

    def list_top_domains(self, sequence_id: str = None, sequence_type: str = None) -> Dict:
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

    def list_triggered_rules_request(self, sequence_id: str = None, sequence_type: str = None) -> Dict:
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
        response = self._http_request('GET', url_suffix=f'/uba/api/user/sequence/triggeredRules', params=params)
        return response

    def get_asset_info_request(self, asset_id: str = None, max_users_number: int = None) -> Dict:
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

    def list_asset_next_events(self, asset_id: str = None,
                               event_time: int = None,
                               number_of_events: int = None,
                               anomaly_only: str = None,
                               event_categories: list = None,
                               event_types: list = None,
                               event_type_include: str = None,
                               sequence_types: list = None) -> Dict:
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

    def list_security_alerts(self, asset_id: str = None, sort_by: str = None,
                             sort_order: int = None, limit: int = None) -> Dict:
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

        url_suffix = f'/uba/api/asset/{asset_id}/securityAlerts'

        response = self._http_request('GET', url_suffix=url_suffix, params=params)
        return response

    def search_rules(self, keyword: str = None, filter_exp: str = None) -> Union[List, Dict]:
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

    def get_rule_string(self, rule_id: str = None) -> str:
        """
            Args:
                rule_id: The rule ID.

            Returns:
                (str) The string response.
        """

        url_suffix = f'/uba/api/rules/{rule_id}/string'

        response = self._http_request('GET', url_suffix=url_suffix, resp_type='text')
        return response

    def fetch_rules(self, filter_by: str = None) -> Union[List, Dict]:
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

    def get_model_definition(self, model_name: str = None) -> Dict:
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

    def add_watchlist_items_from_csv(self, watchlist_id: str = None, watch_until_days: int = None,
                                     csv_file: str = None, category: str = None) -> Dict:
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
            with open(file_path, 'rb') as _file:
                file = {'file': (file_path, _file.read())}

            form_data = {
                'watchUntilDays': watch_until_days,
                'category': category
            }
            url_suffix = f'/uba/api/watchlist/{watchlist_id}/addFromCsv'

            response = self._http_request('PUT', url_suffix=url_suffix, data=form_data, files=file)
            return response
        else:
            raise ValueError('Invalid entry_id argument.')

    def search_asset_in_watchlist(self, keyword: str = None, watchlist_id: str = None, limit: int = None,
                                  is_exclusive: str = None, search_by_ip: str = None) -> Dict:
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

    def remove_watchlist_item(self, watchlist_id: str = None, item: str = None, category: str = None) -> Dict:
        """
            Args:
                watchlist_id: ID of the watchlist to remove an item from
                item: An item to remove
                category: The item category

            Returns:
                (dict) The removal API response.
        """

        form_data = {
            'watchlistId': watchlist_id,
            'category': category,
            'items[]': item
        }
        url_suffix = f'/uba/api/watchlist/{watchlist_id}/remove'

        response = self._http_request('PUT', url_suffix=url_suffix, data=form_data)
        return response

    def list_context_table_records(self, context_table_name: str = None,
                                   page_size: int = None, page_number: int = None) -> Dict:
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

    def update_session_id_of_context_table(self, context_table_name: str = None, session_id: str = None) -> Dict:
        """
            Args:
                context_table_name: The context table name.
                session_id: The ID of update session.

            Returns:
                (dict) The context table session update response.
        """

        url_suffix = f'/api/setup/contextTables/{context_table_name}/records'
        payload = {'sessionId': session_id, 'replace': False}
        demisto.results(str(payload))

        response = self._http_request('PUT', url_suffix=url_suffix, json_data=payload)

        demisto.results(str(response))
        return response

    def add_context_table_records(self, context_table_name: str = None,
                                  records_list: List[str] = None,
                                  key_only: bool = False,
                                  session_id: str = None) -> Dict:
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

        try:
            records = []
            for record_item in records_list:
                record = record_item.split(':')
                records.append({
                    'key': record[0],
                    'value': [] if key_only else record[1].split(';')
                })
        except IndexError:
            raise ValueError('records argument is malformed.')
        payload = {'records': records}

        url_suffix = f'/api/setup/contextTables/{context_table_name}/changes/add'

        response = self._http_request('POST', url_suffix=url_suffix, params=params, json_data=payload)

        if not session_id and response.get('sessionId'):
            self.update_session_id_of_context_table(context_table_name, session_id=response.get('sessionId'))

        return response

    def update_context_table_records(self, context_table_name: str = None,
                                     records_list: List[str] = None,
                                     key_only: bool = False,
                                     session_id: str = None) -> Dict:
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

        try:
            records = []
            for record_item in records_list:
                record = record_item.split(':')
                records.append({
                    'id': record[0],
                    'key': record[1],
                    'value': [] if key_only else record[2].split(';')
                })
        except IndexError:
            raise ValueError('records argument is malformed.')
        payload = {'records': records}

        url_suffix = f'/api/setup/contextTables/{context_table_name}/changes/update'

        response = self._http_request('POST', url_suffix=url_suffix, params=params, data=payload)

        if not session_id and response.get('sessionId'):
            self.update_session_id_of_context_table(context_table_name, session_id=response.get('sessionId'))

        return response

    def delete_context_table_records(self, context_table_name: str = None,
                                     records: List[str] = None, session_id: str = None) -> Dict:
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
            'records': [
                {
                    'id': record.split(':')[0],
                    'key': ''
                }
                for record in records
            ]
        }
        url_suffix = f'/api/setup/contextTables/{context_table_name}/changes/delete'

        response = self._http_request('POST', url_suffix=url_suffix, params=params, data=payload)

        if not session_id and response.get('sessionId'):
            self.update_session_id_of_context_table(context_table_name, session_id=response.get('sessionId'))

        return response

    def addbulk_context_table_records(self, context_table_name: str = None, csv_file: str = None,
                                      session_id: str = None) -> Dict:
        """
            Args:
                context_table_name: The context table name.
                csv_file: The entry ID of the CSV file from which records will be added.
                session_id: The ID of update session. If not specified, a new session is created.

            Returns:
                (dict) The context table records update response.
        """

        params = {'sessionId': session_id} if session_id else {}

        file_path = demisto.getFilePath(csv_file).get('path')

        if file_path:
            with open(file_path, 'rb') as _file:
                file = {'file': (file_path, _file.read())}

            url_suffix = f'/api/setup/contextTables/{context_table_name}/changes/addBulk'

            response = self._http_request('POST', url_suffix=url_suffix, params=params, files=file)

            if not session_id and response.get('sessionId'):
                self.update_session_id_of_context_table(context_table_name, session_id=response.get('sessionId'))

            return response
        else:
            raise ValueError('Invalid entry_id argument.')

    def get_context_table_csv(self, context_table_name: str = None) -> Tuple[str, str]:
        """
            Args:
                context_table_name: The context table name.

            Returns:
                (Tuple[str, str]) The file name and the response content.
        """

        url_suffix = f'/api/setup/contextTables/{context_table_name}/records/csv'

        response = self._http_request('GET', url_suffix=url_suffix, resp_type='response')
        # 'Content-Disposition' value is of the form: attachment; filename="filename.csv"
        # Since we don't have the file name anywhere else in the response object, we parse it from this entry.
        filename = response.headers.get('Content-Disposition', str()).split('\"')[1]
        content = response.content

        return filename, content


def get_query_params_str(params: dict, array_type_params: dict) -> str:
    """ Used for API queries that include array type parameters. Passing them in a dictionary won't work
        because their keys must be equal which is not possible in python dictionaries, thus we will
        eventually pass the parameters in the URL itself.

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


def test_module(client: Client, *_):
    """test function

    Args:
        client:
        *_:

    Returns:
        ok if successful
    """
    client.test_module_request()
    demisto.results('ok')
    return '', None, None


def contents_append_notable_user_info(contents, user, user_, user_info) -> List[Any]:
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


def get_notable_users(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """ Get notable users in a period of time

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


def contents_user_info(user, user_info) -> Dict:
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


def get_user_info(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
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


def get_user_sessions(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Returns sessions for the given username and time range

    Args:
        client: Client
        args: Dict

    """
    username = args.get('username')
    start_time = args.get('start_time', datetime.now() - timedelta(days=30))
    end_time = args.get('end_time', datetime.now())
    parse_start_time = date_to_timestamp(start_time)
    parse_end_time = date_to_timestamp(end_time)
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


def get_peer_groups(client: Client, *_) -> Tuple[str, Dict, Dict]:
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


def get_user_labels(client: Client, *_) -> Tuple[str, Dict, Dict]:
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


def get_watchlist(client: Client, *_) -> Tuple[str, Dict, Dict]:
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


def delete_watchlist(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Delete a watchlist

    Args:
        client: Client
        args: Dict

    """

    watchlist_id = args.get('watchlist_id')
    client.delete_watchlist_request(watchlist_id)

    return f'The watchlist {watchlist_id} was deleted successfully.', {}, {}


def contents_asset_data(asset_data) -> Dict:
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


def get_asset_data(client: Client, args: Dict) -> Tuple[Any, Dict[str, Dict[Any, Any]], Optional[Any]]:
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


def get_session_info_by_id(client: Client, args: Dict) -> Tuple[Any, Dict[str, Dict[Any, Any]], Optional[Any]]:
    """  Return session information for a given session ID

    Args:
        client: Client
        args: Dict

    """
    session_id = args.get('session_id')
    session_info_raw_data = client.get_session_info_request(session_id)

    if not session_info_raw_data or 'sessionInfo' not in session_info_raw_data:
        raise Exception(f'The session with ID {session_id} has no information. '
                        f'Please verify that the session ID is valid.')

    session_info = session_info_raw_data.get('sessionInfo')

    entry_context = {'Exabeam.SessionInfo(val.sessionId && val.sessionId === obj.sessionId)': session_info}
    human_readable = tableToMarkdown(f'Session {session_id} Information', session_info,
                                     removeNull=True, headerTransform=pascalToSpace)

    return human_readable, entry_context, session_info_raw_data


def list_top_domains(client: Client, args: Dict) -> Tuple[Any, Dict[str, Dict[Any, Any]], Optional[Any]]:
    """  Return session information for given session ID

    Args:
        client: Client
        args: Dict

    """
    sequence_id = args.get('sequence_id')
    sequence_type = args.get('sequence_type')
    top_domains_raw_data = client.list_top_domains(sequence_id, sequence_type)

    top_domains = top_domains_raw_data.get('topDomains', [])

    entry_context = {'Exabeam.DataFeed(val.sequenceId && val.sequenceId === obj.sequenceId)': top_domains_raw_data}
    human_readable = tableToMarkdown(f'Sequence {sequence_id} Top Domains', top_domains,
                                     removeNull=True, headerTransform=pascalToSpace)

    return human_readable, entry_context, top_domains_raw_data


def list_triggered_rules(client: Client, args: Dict) -> Tuple[Any, Dict[str, Dict[Any, Any]], Optional[Any]]:
    """  Returns all triggered rules for a given sequence

    Args:
        client: Client
        args: Dict

    """
    sequence_id = args.get('sequence_id')
    sequence_type = args.get('sequence_type')
    triggered_rules_raw_data = client.list_triggered_rules_request(sequence_id, sequence_type)

    if not triggered_rules_raw_data or 'triggeredRules' not in triggered_rules_raw_data:
        raise Exception(f'The sequence has no triggered rules. '
                        f'Please verify that the sequence details are valid.')

    triggered_rules = triggered_rules_raw_data.get('triggeredRules')

    entry_context = {'Exabeam.TriggeredRules(val._Id && val._Id === obj._Id)': triggered_rules}
    human_readable = tableToMarkdown(f'Sequence {sequence_id} Triggered Rules', triggered_rules,
                                     removeNull=True, headerTransform=pascalToSpace)

    return human_readable, entry_context, triggered_rules_raw_data


def get_asset_info(client: Client, args: Dict) -> Tuple[Any, Dict[str, Dict[Any, Any]], Optional[Any]]:
    """  Returns asset info for given asset ID (hostname or IP address)

    Args:
        client: Client
        args: Dict

    """
    asset_id = args.get('asset_id')
    max_users_number = int(args.get('max_users_number'))
    asset_raw_data = client.get_asset_info_request(asset_id, max_users_number)

    asset_info = asset_raw_data.get('info')
    asset_info['assetId'] = asset_id
    entry_context = {'Exabeam.AssetInfo(val.assetId && val.assetId === obj.assetId)': asset_info}
    human_readable = tableToMarkdown(f'Asset {asset_id} Information', asset_info,
                                     removeNull=True, headerTransform=pascalToSpace)

    return human_readable, entry_context, asset_raw_data


def list_asset_next_events(client: Client, args: Dict) -> Tuple[Any, Dict[str, List[Any]], Optional[Any]]:
    """  Returns next events for a given asset.

    Args:
        client: Client
        args: Dict

    """
    asset_id = args.get('asset_id')
    event_time = int(args.get('event_time'))
    number_of_events = int(args.get('number_of_events'))
    anomaly_only = args.get('anomaly_only')
    event_categories = argToList(args.get('event_categories'))
    event_types = argToList(args.get('event_types'))
    event_type_include = 'true' if args.get('event_types_operator') == 'include' else 'false'
    sequence_types = argToList(args.get('sequence_types'))

    events_raw_data = client.list_asset_next_events(asset_id,
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


def aggregated_events_to_xsoar_format(asset_id: str = None, events: list = None) -> Tuple[list, str]:
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
            human_readable += tableToMarkdown(title, activity_events, removeNull=True) + '\n'
            outputs.extend(activity_events)

    return outputs, human_readable


def list_security_alerts_by_asset(client: Client, args: Dict) -> Tuple[Any, Dict[str, List[Any]], Optional[Any]]:
    """  Returns security alerts for a given asset.

    Args:
        client: Client
        args: Dict

    """
    asset_id = args.get('asset_id')
    sort_by = args.get('sort_by')
    sort_order = 1 if args.get('sort_order') == 'asc' else -1
    limit = int(args.get('limit'))

    security_alerts_raw_data = client.list_security_alerts(asset_id, sort_by, sort_order, limit)

    security_alerts = []
    for security_alert in security_alerts_raw_data.get('events', []):
        security_alert = security_alert.get('fields')
        security_alert['time'] = convert_unix_to_date(security_alert.get('time'))
        security_alert['rawlog_time'] = convert_unix_to_date(security_alert.get('rawlog_time'))
        security_alerts.append(security_alert)

    human_readable = tableToMarkdown(f'Asset {asset_id} Security Alerts', security_alerts,
                                     removeNull=True, headerTransform=pascalToSpace)

    entry_context = {'Exabeam.AssetSecurityAlert': security_alerts}

    return human_readable, entry_context, security_alerts_raw_data


def search_rules(client: Client, args: Dict) -> Tuple[Any, Dict[str, List[Any]], Optional[Any]]:
    """  Searches for rules by a keyword.

    Args:
        client: Client
        args: Dict

    """
    keyword = args.get('keyword')
    filter_exp = args.get('filter')

    limit = int(args.get('limit'))
    page = int(args.get('page'))
    from_idx = page * limit
    to_idx = (page + 1) * limit

    rules_raw_data = client.search_rules(keyword, filter_exp)
    rules, human_readable = get_rules_in_xsoar_format(rules_raw_data, from_idx, to_idx)

    entry_context = {'Exabeam.Rule(val.ruleId && val.ruleId === obj.ruleId)': rules}

    return human_readable, entry_context, rules_raw_data


def get_rules_in_xsoar_format(rules_raw_data: list, from_idx: int, to_idx: int) -> Tuple[List[Any], str]:
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


def get_rule_string(client: Client, args: Dict) -> Tuple[Any, Dict[str, Any], Optional[Any]]:
    """  Gets a rule string by ID.

    Args:
        client: Client
        args: Dict

    """
    rule_id = args.get('rule_id')

    rule_string_raw_data = client.get_rule_string(rule_id)
    outputs = {}
    entry_context = {}
    if rule_string_raw_data:
        outputs = {'ruleId': rule_id, 'ruleString': rule_string_raw_data}
        entry_context = {'Exabeam.Rule(val.ruleId && val.ruleId === obj.ruleId)': outputs}
    human_readable = tableToMarkdown(f'Rule {rule_id} String', outputs, headerTransform=pascalToSpace)

    return human_readable, entry_context, rule_string_raw_data


def fetch_rules(client: Client, args: Dict) -> Tuple[Any, Dict[str, Any], Optional[Any]]:
    """  Gets all rules.

    Args:
        client: Client
        args: Dict

    """
    filter_by = args.get('filter_by')

    limit = int(args.get('limit'))
    page = int(args.get('page'))
    from_idx = page * limit
    to_idx = (page + 1) * limit

    rules_raw_data = client.fetch_rules(filter_by)
    rules, human_readable = get_rules_in_xsoar_format(rules_raw_data, from_idx, to_idx)
    entry_context = {f'Exabeam.Rule(val.ruleId && val.ruleId === obj.ruleId)': rules}

    return human_readable, entry_context, rules_raw_data


def get_rules_model_definition(client: Client, args: Dict) -> Tuple[Any, Dict[str, Any], Optional[Any]]:
    """  Gets a rule model definition by name.

    Args:
        client: Client
        args: Dict

    """
    model_name = args.get('model_name')

    model = client.get_model_definition(model_name)
    entry_context = {'Exabeam.Model(val.name && val.name === obj.name)': model}
    human_readable = tableToMarkdown(f'Model {model_name} Definition', model,
                                     headerTransform=pascalToSpace, removeNull=True)

    return human_readable, entry_context, model


def add_watchlist_item_from_csv(client: Client, args: Dict) -> Tuple[str, Optional[Any], Optional[Any]]:
    """  Add a watchlist item from CSV file.

    Args:
        client: Client
        args: Dict

    """
    watchlist_id = args.get('watchlist_id')
    csv_entry_id = args.get('csv_entry_id')
    category = args.get('category')
    watch_until_days = int(args.get('watch_until_days'))

    raw_response = client.add_watchlist_items_from_csv(watchlist_id, watch_until_days, csv_entry_id, category)
    added_count = raw_response.get('addedCount')
    human_readable = f'Successfully added {added_count} items to watchlist {watchlist_id}.'

    return human_readable, None, raw_response


def search_asset_in_watchlist(client: Client, args: Dict) -> Tuple[Any, Dict[str, Any], Optional[Any]]:
    """  Gets the assets of a specified watchlist according to a keyword.

    Args:
        client: Client
        args: Dict

    """
    keyword = args.get('keyword')
    watchlist_id = args.get('watchlist_id')
    limit = int(args.get('limit'))
    is_exclusive = args.get('is_exclusive')
    search_by_ip = args.get('search_by_ip')

    assets_raw_data = client.search_asset_in_watchlist(keyword, watchlist_id, limit, is_exclusive, search_by_ip)
    assets = assets_raw_data.get('assets', [])
    entry_context = {'Exabeam.AssetInfo((val.ipAddress && val.ipAddress === obj.ipAddress) ||'
                     '(val.hostName && val.hostName === obj.hostName))': assets}
    human_readable = tableToMarkdown(f'Watchlist {watchlist_id} Assets Search Results', assets,
                                     headerTransform=pascalToSpace, removeNull=True)

    return human_readable, entry_context, assets_raw_data


def remove_watchlist_item(client: Client, args: Dict) -> Tuple[str, Optional[Any], Optional[Any]]:
    """  Removes items from a watchlist.

    Args:
        client: Client
        args: Dict

    """
    watchlist_id = args.get('watchlist_id')
    items = argToList(args.get('items'))
    category = args.get('category')

    for item in items:
        client.remove_watchlist_item(watchlist_id, item, category)

    human_readable = f'Successfully removed {len(items)} items from watchlist {watchlist_id}.'

    return human_readable, None, None


def list_context_table_records(client: Client, args: Dict) -> Tuple[Any, Dict[str, Any], Optional[Any]]:
    """  Returns a list of a context table records.

    Args:
        client: Client
        args: Dict

    """
    context_table_name = args.get('context_table_name')
    page_size = int(args.get('page_size'))
    page_number = int(args.get('page_number'))

    records_raw_data = client.list_context_table_records(context_table_name, page_size, page_number)
    records = records_raw_data.get('records', [])
    outputs = []
    for record in records:
        outputs.append({
            'key': record.get('key'),
            'id': record.get('id'),
            'value': record.get('value'),
            'position': record.get('position'),
            'sourceType': record.get('sourceType'),
            'contextTableName': context_table_name
        })

    entry_context = {'Exabeam.ContextTableRecord(val.contextTableName && val.contextTableName === obj.contextTableName'
                     '&& val.id && val.id === obj.id)': outputs}
    human_readable = tableToMarkdown(f'Context Table `{context_table_name}` Records', records,
                                     headerTransform=pascalToSpace, removeNull=True)

    return human_readable, entry_context, records_raw_data


def add_context_table_records(client: Client, args: Dict) -> Tuple[Any, Dict[str, Any], Optional[Any]]:
    """  Adds records to a context table.

    Args:
        client: Client
        args: Dict

    """
    context_table_name = args.get('context_table_name')
    session_id = args.get('session_id')
    key_only = True if args.get('context_table_type') == 'key_only' else False
    records_list = argToList(args.get('records'))

    record_updates_raw_data = client.add_context_table_records(context_table_name, records_list, key_only, session_id)
    outputs = {'Name': context_table_name, 'Details': record_updates_raw_data}
    entry_context = {'Exabeam.ContextTableAdd(val.Name && val.Name === obj.Name)': outputs}
    human_readable = tableToMarkdown(f'Context Table {context_table_name} Update Details', record_updates_raw_data,
                                     headerTransform=pascalToSpace, removeNull=True)

    return human_readable, entry_context, record_updates_raw_data


def update_context_table_records(client: Client, args: Dict) -> Tuple[Any, Dict[str, Any], Optional[Any]]:
    """  Updates records of a context table.

    Args:
        client: Client
        args: Dict

    """
    context_table_name = args.get('context_table_name')
    session_id = args.get('session_id')
    records = argToList(args.get('records'))
    key_only = True if args.get('context_table_type') == 'key_only' else False

    record_updates_raw_data = client.update_context_table_records(context_table_name, records, key_only, session_id)
    outputs = {'Name': context_table_name, 'Details': record_updates_raw_data}
    entry_context = {'Exabeam.ContextTableUpdate(val.Name && val.Name === obj.Name)': outputs}
    human_readable = tableToMarkdown(f'Context Table {context_table_name} Update Details', record_updates_raw_data,
                                     headerTransform=pascalToSpace, removeNull=True)

    return human_readable, entry_context, record_updates_raw_data


def delete_context_table_records(client: Client, args: Dict) -> Tuple[Any, Dict[str, Any], Optional[Any]]:
    """  Deletes records of a context table.

    Args:
        client: Client
        args: Dict

    """
    context_table_name = args.get('context_table_name')
    session_id = args.get('session_id')
    records = argToList(args.get('records'))

    record_updates_raw_data = client.delete_context_table_records(context_table_name, records, session_id)
    outputs = {'Name': context_table_name, 'Details': record_updates_raw_data}
    entry_context = {'Exabeam.ContextTableUpdate(val.Name && val.Name === obj.Name)': outputs}
    human_readable = tableToMarkdown(f'Context Table {context_table_name} Update Details', record_updates_raw_data,
                                     headerTransform=pascalToSpace, removeNull=True)

    return human_readable, entry_context, record_updates_raw_data


def addbulk_context_table_records(client: Client, args: Dict) -> Tuple[Any, Dict[str, Any], Optional[Any]]:
    """  Bulk addition of a context table records from CSV file.

    Args:
        client: Client
        args: Dict

    """
    context_table_name = args.get('context_table_name')
    session_id = args.get('session_id')
    file_entry_id = args.get('file_entry_id')

    record_updates_raw_data = client.addbulk_context_table_records(context_table_name, file_entry_id, session_id)
    outputs = {'Name': context_table_name, 'Details': record_updates_raw_data}
    entry_context = {'Exabeam.ContextTableUpdate(val.Name && val.Name === obj.Name)': outputs}
    human_readable = tableToMarkdown(f'Context Table {context_table_name} Update Details', record_updates_raw_data,
                                     headerTransform=pascalToSpace, removeNull=True)

    return human_readable, entry_context, record_updates_raw_data


def get_context_table_csv(client: Client, args: Dict) -> Tuple[Any, Dict[str, Any], Optional[Any]]:
    """  Updates records of a context table.

    Args:
        client: Client
        args: Dict

    """
    context_table_name = args.get('context_table_name')

    filename, content = client.get_context_table_csv(context_table_name)

    demisto.results(fileResult(filename, content))
    return f'Successfully downloaded Context Table CSV file {context_table_name}.', {}, None


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    base_url = demisto.params().get('url')
    verify_certificate = not demisto.params().get('insecure', False)
    headers = {'Accept': 'application/json'}
    proxy = demisto.params().get('proxy', False)

    commands = {
        'test-module': test_module,
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
        'exabeam-update-context-table-records': update_context_table_records,
        'exabeam-context-table-delete-records': delete_context_table_records,
        'exabeam-context-table-addbulk': addbulk_context_table_records,
        'exabeam-get-context-table-in-csv': get_context_table_csv,
        'exabeam-watchlist-add-from-csv': add_watchlist_item_from_csv,
        'exabeam-watchlist-asset-search': search_asset_in_watchlist,
        'exabeam-watchilst-remove-items': remove_watchlist_item
    }

    try:
        client = Client(base_url.rstrip('/'), verify=verify_certificate, username=username,
                        password=password, proxy=proxy, headers=headers)
        command = demisto.command()
        LOG(f'Command being called is {command}.')
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))  # type: ignore
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
