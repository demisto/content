from typing import Any, Dict, List, Optional, Tuple

import requests

import demistomock as demisto
from CommonServerPython import *

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


def convert_unix_to_date(timestamp):
    """Convert unix timestamp to datetime in iso format.

    Args:
        timestamp: the date in unix to convert.

    Returns:
        converted date.
    """
    return datetime.fromtimestamp(int(timestamp) / 1000).isoformat()


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

    def http_request(self, method: str, url_suffix: str = None, full_url: str = None, params: dict = None,
                     data: dict = None, resp_type: str = 'json'):
        """
        Generic request to Exabeam
        """
        full_url = full_url if full_url else f'{self._base_url}{url_suffix}'
        try:
            res = self.session.request(
                method,
                full_url,
                headers=self._headers,
                verify=self._verify,
                data=data,
                params=params
            )
            if not res.ok:
                raise ValueError(f'Error in API call to Exabeam {res.status_code}. Reason: {res.text}')

            try:
                if resp_type == 'json':
                    return res.json()
                return res.text
            except Exception:
                raise ValueError(
                    f'Failed to parse http response to JSON format. Original response body: \n{res.text}')

        except requests.exceptions.ConnectTimeout as exception:
            err_msg = 'Connection Timeout Error - potential reasons might be that the Server URL parameter' \
                      ' is incorrect or that the Server is not accessible from your host.'
            raise DemistoException(err_msg, exception)

        except requests.exceptions.SSLError as exception:
            err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                      ' the integration configuration.'
            raise DemistoException(err_msg, exception)

        except requests.exceptions.ProxyError as exception:
            err_msg = 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
                      ' selected, try clearing the checkbox.'
            raise DemistoException(err_msg, exception)

        except requests.exceptions.ConnectionError as exception:
            # Get originating Exception in Exception chain
            error_class = str(exception.__class__)
            err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'
            err_msg = f'\nError Type: {err_type}\nError Number: [{exception.errno}]\nMessage: {exception.strerror}\n ' \
                      f'Verify that the server URL parameter ' \
                      f'is correct and that you have access to the server from your host.'
            raise DemistoException(err_msg, exception)

        except Exception as exception:
            raise Exception(str(exception))

    def _login(self):
        """
        Login using the credentials and store the cookie
        """
        self.http_request('POST', full_url=f'{self._base_url}/api/auth/login', data={
            'username': self.username,
            'password': self.password
        })

    def _logout(self):
        """
        Logout from the session
        """
        try:
            self.http_request('GET', self.http_request('GET', f'{self._base_url}/api/auth/logout'))
        except Exception as err:
            demisto.debug(f'An error occurred during the logout.\n{str(err)}')

    def test_module_request(self):
        """
        Performs basic get request to check if the server is reachable.
        """
        self.http_request('GET', '/uba/api/ping', resp_type='text')

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
        response = self.http_request('GET', url_suffix='/uba/api/users/notable', params=params)
        return response

    def get_notable_assets_request(self, api_unit: str = None, num: str = None, limit: int = None) -> Dict:
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
        response = self.http_request('GET', url_suffix='/uba/api/assets/notable', params=params)
        return response

    def get_context_tables(self, tableNameLike: str = None, sortBy: str = None, order: str = None, pageSize: int = 10,
                           pageNumber: int = 1) -> Dict:
        """
        Args:
            tableNameLike: Context table name "like" pattern
            sortBy: Field name which used to sort context tables
            order: Ordering
            pageSize: Page size
            pageNumber: Page number (starts from 1)


        Returns:
            context table names
        """
        params = {
            'tableNameLike': tableNameLike,
            'sortBy': sortBy,
            'order': order,
            'pageSize': pageSize,
            'pageNumber': pageNumber,
        }
        response = self.http_request('GET', url_suffix='/api/setup/contextTables', params=params)
        return response

    def get_context_table_records(self, contextTableName: str, pageSize: int = 50, pageNumber: int = 1,
                                  sortBy: str = None, order: str = None, keyword: str = None) -> Dict:
        """
        Args:
            contextTableName: The table name to retrieve records from
            pageSize: Page size
            pageNumber: Page number (starts from 1)
            sortBy: Field name which used to sort context table records
            order: Ordering
            keyword: Keyword to match record keys

        Returns:
            records from contextTableName
        """
        params = {
            'contextTableName': contextTableName,
            'pageSize': pageSize,
            'pageNumber': pageNumber,
            'sortBy': sortBy,
            'order': order,
            'keyword': keyword
        }
        response = self.http_request('GET', url_suffix=f'/uba/api/setup/contextTables/{contextTableName}/records', params=params)
        return response

    def get_user_info_request(self, username: str) -> Dict:
        """
        Args:
            username: the username

        Returns:
            the user info
        """
        response = self.http_request('GET', url_suffix=f'/uba/api/user/{username}/info')
        return response

    def get_peer_groups_request(self) -> Dict:
        """
        Returns:
            peer groups
        """
        response = self.http_request('GET', url_suffix='/uba/api/peerGroup')
        return response

    def get_user_labels_request(self) -> Dict:
        """
        Returns:
            user labels
        """
        response = self.http_request('GET', url_suffix='/uba/api/userLabel')
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
        response = self.http_request('GET', url_suffix=f'/uba/api/user/{username}/sequences', params=params)
        return response

    def get_watchlist_request(self):
        """
        Returns:
            a watchlist
        """
        response = self.http_request('GET', url_suffix='/uba/api/watchlist')
        return response

    def delete_watchlist_request(self, watchlist_id: str = None):
        """
        Args:
            watchlist_id: watchlist id

        """
        self.http_request('DELETE', url_suffix=f'/uba/api/watchlist/{watchlist_id}/')

    def get_asset_data_request(self, asset_name: str = None) -> Dict:
        """

        Args:
            asset_name: asset name

        Returns:
            asset data
        """
        response = self.http_request('GET', url_suffix=f'/uba/api/asset/{asset_name}/data')
        return response

    def get_notable_session_details_request(self, sessionid: str = None) -> Dict:

        response = self.http_request('GET', url_suffix=f'/uba/api/session/{sessionid}/info')

        return response

    def get_notable_sequence_details_request(self, sequenceid: str = None) -> Dict:

        response = self.http_request('GET', url_suffix=f'/uba/api/asset/sequence/{sequenceid}/info')

        return response

    def get_sequence_eventtypes_request(self, sequenceid: str = None) -> Dict:

        response = self.http_request('GET', url_suffix=f'/uba/api/asset/sequence/{sequenceid}/eventTypes')

        return response

    def get_sequence_triggeredrules_request(self, sequenceid: str = None) -> Dict:

        response = self.http_request('GET', url_suffix=f'/uba/api/asset/sequence/{sequenceid}/triggeredRules')

        return response

    def get_sequence_securityalerts_request(self, sequenceid: str = None) -> Dict:

        response = self.http_request('GET', url_suffix=f'/uba/api/asset/sequence/{sequenceid}/securityAlerts')

        return response

    def get_asset_securityalerts_request(self, assetid: str = None, sortby: str = None, sortorder=0,
                                         maxresults=0) -> Dict:

        params = {
            'sortBy': sortby,
            'sortOrder': sortorder,
            'numberOfResults': maxresults
        }

        response = self.http_request('GET', url_suffix=f'/uba/api/asset/{assetid}/securityAlerts', params=params)

        return response

    def get_asset_header_data_request(self, assetid: str = None, maxusers=0) -> Dict:

        params = {
            'maxNumberOfUsers': maxusers
        }
        response = self.http_request('GET', url_suffix=f'/uba/api/asset/{assetid}/info', params=params)

        return response

    def get_watchlist_byID_request(self, watchlistid, maxresults, unit: str, num) -> Dict:

        params = {
            'numberOfResults': maxresults,
            'unit': unit,
            'num': num
        }

        response = self.http_request('GET', url_suffix=f'/uba/api/watchlist/assets/{watchlistid}/', params=params)

        return response

    def add_watchlist_item_request(self, watchlistid, items, watchuntil, category) -> Dict:

        params = {
            'items': items,
            'watchUntilDays': watchuntil,
            'category': category
        }

        response = self.http_request('PUT', url_suffix=f'/uba/api/watchlist/{watchlistid}/add', params=params)

        return response


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


def contents_append_notable_asset_info(contents, asset, asset_, ) -> List[Any]:
    """Appends a dictionary of data to the base list

    Args:
        contents: base list
        asset: asset object
        asset_: asset object

    Returns:
        A contents list with the relevant notable asset data
    """
    contents.append({
        'HostName': asset_.get('hostName'),
        'RiskScore': round(asset.get('highestRiskScore')) if 'highestRiskScore' in asset else None,
        'FirstSeen': convert_unix_to_date(asset_.get('firstSeen')) if 'firstSeen' in asset_ else None,
        'LastSeen': convert_unix_to_date(asset_.get('lastSeen')) if 'lastSeen' in asset_ else None,
        'Zone': asset.get('zone') if 'zone' in asset else None,
        'Notableasset': True,
        'HighestRiskSequence': asset.get('highestRiskSequence'),
        'AssetType': asset_.get('assetType')
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


def get_notable_assets(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
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
    headers = ['HostName', 'RiskScore',
               'AssetType', 'FirstSeen', 'LastSeen', 'Zone']
    raw_assets = client.get_notable_assets_request(api_unit, num, limit)

    assets = raw_assets.get('assets', [])
    if not assets:
        return 'No assets were found in this period of time.', {}, {}

    for asset in assets:
        asset_ = asset.get('asset', {})
        # asset_info = asset_.get('info', {})
        contents = contents_append_notable_asset_info(contents, asset, asset_)

    entry_context = {'Exabeam.Host(val.HostName && val.HostName === obj.HostName)': contents}
    human_readable = tableToMarkdown('Exabeam Notable Assets:', contents, headers=headers, removeNull=True)

    return human_readable, entry_context, raw_assets


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


def get_notable_session_details(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:

    sessionid = args.get('sessionid')

    session_details = client.get_notable_session_details_request(sessionid)

    if not session_details or 'sessionInfo' not in session_details:
        raise Exception(f'The session {sessionid} has no data. Please verify that the session is valid.')

    raw_data = session_details
    entry_context = {'Exabeam.Session(val.sessionId && val.sessionId === obj.sessionId)': session_details.get('sessionInfo')}
    human_readable = tableToMarkdown('Exabeam Session:', session_details.get('sessionInfo'), removeNull=True)
    return human_readable, entry_context, raw_data


def get_notable_sequence_details(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:

    sequenceid = args.get('sequenceid')

    sequence_details = client.get_notable_sequence_details_request(sequenceid)

    if not sequence_details or 'sequenceInfo' not in sequence_details:
        raise Exception(f'The sequence {sequenceid} has no data. Please verify that the session is valid.')

    raw_data = sequence_details
    entry_context = {
        'Exabeam.Sequence(val.sequenceId && val.sequenceId === obj.sequenceId)': sequence_details.get('sequenceInfo')}
    human_readable = tableToMarkdown('Exabeam Sequence:', sequence_details.get('sequenceInfo'), removeNull=True)
    return human_readable, entry_context, raw_data


def get_sequence_eventtypes(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:

    sequenceid = args.get('sequenceid')

    eventTypes = client.get_sequence_eventtypes_request(sequenceid)

    if not(type(eventTypes) is list) or len(eventTypes) == 0:
        raise Exception(f'The sequence {sequenceid} has no eventType data. Please verify that the session is valid.')

    raw_data = eventTypes

    entry_context = {'Exabeam.Sequence(val.sequenceId && val.sequenceId === obj.sequenceId)': {
        'sequenceId': sequenceid, 'eventTypes': eventTypes}}
    human_readable = tableToMarkdown('Exabeam eventTypes:', eventTypes, removeNull=True)
    return human_readable, entry_context, raw_data


def get_sequence_triggeredrules(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:

    sequenceid = args.get('sequenceid')

    triggeredRules = client.get_sequence_triggeredrules_request(sequenceid)

    if not triggeredRules:
        raise Exception(f'The sequence {sequenceid} has no triggeredRule data. Please verify that the session is valid.')

    raw_data = triggeredRules

    entry_context = {'Exabeam.Sequence(val.sequenceId && val.sequenceId === obj.sequenceId)': {
        'sequenceId': sequenceid, 'triggeredRules': triggeredRules}}
    human_readable = tableToMarkdown('Exabeam triggeredRules:', triggeredRules, removeNull=True)
    return human_readable, entry_context, raw_data


def get_sequence_securityalerts(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:

    sequenceid = args.get('sequenceid')

    securityAlerts = client.get_sequence_securityalerts_request(sequenceid)

    if not securityAlerts:
        raise Exception(f'The sequence {sequenceid} has no securityAlert data. Please verify that the session is valid.')

    raw_data = securityAlerts

    entry_context = {'Exabeam.Sequence(val.sequenceId && val.sequenceId === obj.sequenceId)': {
        'sequenceId': sequenceid, 'securityAlerts': securityAlerts}}
    human_readable = tableToMarkdown('Exabeam securityAlerts:', securityAlerts, removeNull=True)
    return human_readable, entry_context, raw_data


def get_asset_securityalerts(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:

    assetid = args.get('assetid')
    sortby = args.get('sortby')
    sortorder = args.get('sortorder')
    maxresults = args.get('maxresults')

    securityAlerts = client.get_asset_securityalerts_request(assetid, sortby, sortorder, maxresults)

    if not securityAlerts:
        raise Exception(f'The asset {assetid} has no securityAlert data. Please verify that the asset is valid.')

    raw_data = securityAlerts

    entry_context = {'Exabeam.Asset(val.assetId && val.assetId === obj.assetId)': {
        'assetId': assetid, 'securityAlerts': securityAlerts}}
    human_readable = tableToMarkdown('Exabeam securityAlerts:', securityAlerts, removeNull=True)
    return human_readable, entry_context, raw_data


def get_asset_header_data(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:

    assetid = args.get('assetid')
    maxusers = args.get('maxUsers')

    header_details = client.get_asset_header_data_request(assetid, maxusers)

    if not header_details:
        raise Exception(f'The asset {assetid} has no data. Please verify that the asset is valid.')

    raw_data = header_details
    entry_context = {'Exabeam.Asset(val.assetId && val.assetId === obj.assetId)': header_details}
    human_readable = tableToMarkdown('Exabeam Asset:', header_details, removeNull=True)
    return human_readable, entry_context, raw_data


def get_watchlist_byID(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:

    watchlistid = args.get('watchlistid')
    maxresults = args.get('maxresults')
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

    results = client.get_watchlist_byID_request(watchlistid, maxresults, api_unit, num)

    if not results:
        raise Exception(f'The watchlist {watchlistid} has no data. Please verify that the asset is valid.')

    raw_data = results
    entry_context = {'Exabeam.Watchlist(val.watchlistId && val.watchlistId === obj.watchlistId)': {
        'watchlistId': watchlistid, 'watchlist': results}}
    human_readable = tableToMarkdown('Exabeam Watchlist:', results, removeNull=True)
    return human_readable, entry_context, raw_data


def add_watchlist_item(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:

    watchlistid = args.get('watchlistid')
    items = args.get('items')
    watchuntil = args.get('watchUntiDays')
    category = args.get('category')

    results = client.add_watchlist_item_request(watchlistid, items, watchuntil, category)

    if not results:
        raise Exception(f'Failed to add items {items} to watchlist {watchlistid}')

    return "Added", {}, results


def fetch_incidents_command(client: Client, params: Dict, last_run: Dict):

    limit = params.get('maximum_fetch')
    time_period: str = params.get('fetch_time_period', '')
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

    # last_run = demisto.getLastRun()

    if last_run:
        # if 'last_id_timestamp' in last_run:
        #     last_id_timestamp = int(last_run.get('last_id_timestamp'))
        # if 'last_day_timestamp' in last_run:
        #     last_day_timestamp = int(last_run.get('last_day_timestamp'))
        api_unit = "d"
        num = "1"
    else:
        last_run = dict()
        # last_id_timestamp = 0
        # last_day_timestamp = 0

    previous_notable_users = last_run.get('previous_notable_users', '').split(',')
    current_notable_users = []

    previous_notable_assets = last_run.get('previous_notable_assets', '').split(',')
    current_notable_assets = []

    # Start with notable users then assets
    user_results = client.get_notable_users_request(api_unit, num, limit)
    asset_results = client.get_notable_assets_request(api_unit, num, limit)

    validatedUsers = list()
    validatedAssets = list()

    # user_timestamps = [last_id_timestamp]
    # asset_timestamps = [last_day_timestamp]

    users = user_results.get('users', [])
    assets = asset_results.get('assets', [])

    # if len(users) == 0:
    #    return
    incidents: List[Dict[str, Any]] = []

    for user in users:
        for sessionID in user.get('notableSessionIds', []):
            # session_id_time = int(sessionID.split("-")[1])#Assuming notable ID format remains
            # <username>-YYYYMMDDHHmmSS (guest-20200610154908)
            # if session_id_time > last_id_timestamp:
            if sessionID not in previous_notable_users:
                validatedUsers.append(user)

                user['type'] = 'user'  # Added to make mapping easier
                # user_timestamps.append(session_id_time)

                incidents.append({
                    "name": f"Exabeam Notable User - {user['notableSessionIds']}",
                    "rawJSON": json.dumps(user)
                })
            current_notable_users.append(sessionID)

    # user_timestamps = sorted(user_timestamps, reverse=True)
    # last_run['last_id_timestamp'] = str(user_timestamps[0])

    for asset in assets:
        # highest_risk_seq_day = int(asset['highestRiskSequence']['day'])
        # if highest_risk_seq_day > last_day_timestamp:
        if asset['highestRiskSequence']['id'] not in previous_notable_assets:
            validatedAssets.append(asset)
            asset['type'] = 'asset'  # Added to make mapping easier
            # asset_timestamps.append(highest_risk_seq_day)
            incidents.append({
                "name": f"Exabeam Notable Asset - {asset['asset']['hostName']}",
                "rawJSON": json.dumps(asset)
            })
        current_notable_assets.append(asset['highestRiskSequence']['id'])

    # asset_timsetamps = sorted(asset_timestamps,reverse=True)
    # last_run['last_day_timestamp'] = str(asset_timestamps[0])

    previous_assets = str(','.join(current_notable_assets))
    previous_users = str(','.join(current_notable_users))

    last_run['previous_notable_assets'] = previous_assets
    last_run['previous_notable_users'] = previous_users

    # demisto.setLastRun(last_run)

    # demisto.incidents(incidents)

    return incidents, last_run


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
        'exabeam-get-notable-assets': get_notable_assets,
        'exabeam-get-notable-session-details': get_notable_session_details,
        'exabeam-get-notable-sequence-details': get_notable_sequence_details,
        'exabeam-get-sequence-eventtypes': get_sequence_eventtypes,
        'exabeam-get-sequence-triggeredrules': get_sequence_triggeredrules,
        'exabeam-get-sequence-securityalerts': get_sequence_securityalerts,
        'exabeam-get-asset-header': get_asset_header_data,
        'exabeam-get-asset-securityalerts': get_asset_securityalerts,
        'exabeam-add-watchlist-item': add_watchlist_item,
        'exabeam-get-watchlist-byID': get_watchlist_byID
    }

    try:
        client = Client(base_url.rstrip('/'), verify=verify_certificate, username=username,
                        password=password, proxy=proxy, headers=headers)
        command = demisto.command()
        LOG(f'Command being called is {command}.')
        if command == 'fetch-incidents':
            incidents, next_run = fetch_incidents_command(client, demisto.params(), last_run=demisto.getLastRun())
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))  # type: ignore
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
