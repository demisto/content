import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import requests
from typing import Dict, Optional, MutableMapping

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' HELPERS '''


def convert_unix_to_date(d):
    """Convert unix timestamp to datetime in iso format"""
    return datetime.fromtimestamp(int(d) / 1000).isoformat()


class Client:
    def __init__(self, exabeam_url: str, username: str, password: str, verify: bool,
                 proxies: Optional[MutableMapping[str, str]], headers):
        self.server = exabeam_url.rstrip('/')
        self.base_url = f'{self.server}/uba/api/'
        self.username = username
        self.password = password
        self.verify = verify
        self.proxies = proxies
        self.headers = headers
        self.session = requests.Session()
        self.session.headers = headers
        self._login()

    def __del__(self):
        self._logout()

    def _http_request(self, method: str, suffix_url: str = None, params: dict = None, data: dict = None,
                      full_url: str = None, resp_type: str = 'json'):
        full_url = full_url if full_url else f'{self.base_url}{suffix_url}'
        try:
            res = self.session.request(
                method,
                full_url,
                verify=self.verify,
                data=data,
                proxies=self.proxies,
                params=params
            )
            if not res.ok:
                raise ValueError(f'Error in API call to Exabeam {res.status_code}. Reason: {res.text}')

            try:
                if resp_type == 'json':
                    return res.json()
                else:
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
            err_msg = '\nError Type: {}\nError Number: [{}]\nMessage: {}\n' \
                      'Verify that the server URL parameter' \
                      ' is correct and that you have access to the server from your host.' \
                .format(err_type, exception.errno, exception.strerror)
            raise DemistoException(err_msg, exception)

    def _login(self):
        """ Login using the credentials and store the cookie """
        self._http_request('POST', full_url=f'{self.server}/api/auth/login', data={
            'username': self.username,
            'password': self.password
        })

    def _logout(self):
        """ Logout from the session """
        self._http_request('GET', self._http_request('GET', f'{self.server}/api/auth/logout'))

    def test_module_request(self):
        """
        Performs basic get request to check if the server is reachable.
        """
        suffix_url = 'ping'
        return self._http_request('GET', suffix_url, resp_type='text')

    def get_notable_users_request(self, api_unit: str = None, num: str = None, limit: int = None):

        suffix_url = 'users/notable'

        params = {
            'unit': api_unit,
            'num': num,
            'numberOfResults': limit
        }
        response = self._http_request('GET', suffix_url, params)
        return response

    def get_user_info_request(self, username: str):

        suffix_url = f'user/{username}/info'
        response = self._http_request('GET', suffix_url)
        return response

    def get_watchlist_request(self):

        suffix_url = 'watchlist'
        response = self._http_request('GET', suffix_url)

        return response

    def get_peergroups_request(self):

        suffix_url = 'peerGroup'

        response = self._http_request('GET', suffix_url)
        return response

    def get_user_labels_request(self):

        suffix_url = 'userLabel'
        response = self._http_request('GET', suffix_url)

        return response

    def user_sequence_request(self, username: str = None, parse_start_time=None, parse_end_time=None):

        suffix_url = f'user/{username}/sequences'
        params = {
            'username': username,
            'startTime': parse_start_time,
            'endTime': parse_end_time
        }

        response = self._http_request('GET', suffix_url, params)
        return response


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client: Client, *_):

    client.test_module_request()
    demisto.results('ok')
    return '', None, None


def get_notable_users(client: Client, args: Dict):
    """ Get notable users in a period of time

    Args:
        client: Client
        args: Dict

    """
    limit: int = args.get('limit', 10)
    time_period: str = args.get('time_period', '')
    time_ = time_period.split(' ')
    if not len(time_) == 2:
        return_error('Got invalid time period. Enter the time period number and unit.')
    num: str = time_[0]
    unit: str = time_[1]
    api_unit = unit[0]
    if api_unit == 'm':
        api_unit = api_unit.upper()

    if api_unit not in {'d', 'y', 'M', 'h'}:
        return_error('The time unit is incorrect - can be hours, days, months, years')

    contents = []
    headers = ['UserFullName', 'UserName', 'Title', 'Department', 'RiskScore', 'Labels', 'NotableSessionIds',
               'EmployeeType', 'FirstSeen', 'LastSeen', 'LastActivity', 'Location']
    users = client.get_notable_users_request(api_unit, num, limit).get('users', [])
    if not users:
        return 'No users were found in this period of time.', {}, {}
    else:
        for user in users:
            user_ = user.get('user', {})
            user_info = user_.get('info', {})
            contents.append({
                'UserName': user_.get('username'),
                'RiskScore': round(user_.get('riskScore')),
                'FirstSeen': convert_unix_to_date(user_.get('firstSeen')),
                'LastSeen': convert_unix_to_date(user_.get('lastSeen')),
                'LastActivity': user_.get('lastActivityType'),
                'Labels': user_.get('labels'),
                'UserFullName': user.get('userFullName'),
                'Location': user_.get('info')['location'],
                'NotableSessionIds': user.get('notableSessionIds'),
                'NotableUser': True,
                'HighestRiskSession': user.get('highestRiskSession'),
                'EmployeeType': user_info.get('employeeType'),
                'Department': user_info.get('department'),
                'Title': user_info.get('title')
            })

        context = {
            'Exabeam.User(val.UserName && val.UserName === obj.UserName)': contents
        }

        human_readable = tableToMarkdown('Exabeam Notable Users', contents, headers, removeNull=True)
        return human_readable, context, users


def get_user_info(client: Client, args: Dict):
    """  Returns User info data for the given username
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
    contents = {
        'Username': user.get('username'),
        'RiskScore': round(user_info.get('riskScore')),
        'AverageRiskScore': user_info.get('averageRiskScore'),
        'LastSessionID': user_info.get('lastSessionId'),
        'FirstSeen': convert_unix_to_date(user_info.get('firstSeen')),
        'LastSeen': convert_unix_to_date(user_info.get('lastSeen')),
        'LastActivityType': user_info.get('lastActivityType'),
        'Label': user_info.get('labels'),
        'AccountNames': user.get('accountNames'),
        'PeerGroupFieldName': user.get('peerGroupFieldName'),
        'PeerGroupFieldValue': user.get('peerGroupFieldValue'),
        'PeerGroupDisplayName': user.get('peerGroupDisplayName'),
        'PeerGroupType': user.get('peerGroupType')
    }

    context = {
        'Exabeam.User(val.UserName && val.UserName === obj.UserName)': contents
    }

    if not user_info.get('firstSeen'):
        return f'The user {username} was not found', {}, {}
    else:
        human_readable = tableToMarkdown(f'User {username} information', contents, headers, removeNull=True)
        return human_readable, context, user


def get_user_sessions(client: Client, args: Dict):
    """ Returns sessions for the given username and time range

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

    context = {
        'Exabeam.User(val.SessionID && val.SessionID === obj.SessionID)': {
            'Username': username,
            'Session': contents
        }
    }

    if session:
        human_readable = tableToMarkdown(f'User {username} sessions information', contents, headers, removeNull=True)
        return human_readable, context, user
    else:
        return f'The user {username} was not found', {}, {}


def get_watchlist(client: Client, *_):
    """  Returns all watchlist ids and titles.

    Args:
        client: Client

    """

    watchlist = client.get_watchlist_request()
    contents = []
    headers = ['WatchlistID', 'Title', 'Category']
    for list_ in watchlist:
        contents.append({
            'WatchlistID': list_.get('watchlistId'),
            'Title': list_.get('title'),
            'Category': list_.get('category')
        })

    context = {
        'Exabeam.Watchlist(val.WatchlistID && val.WatchlistID === obj.WatchlistID)': contents
    }

    human_readable = tableToMarkdown('Exabeam Watchlists', contents, headers)
    return human_readable, context, watchlist


def get_peer_groups(client: Client, *_):
    """ Returns all peer groups

    Args:
        client: Client

    """
    groups = client.get_peergroups_request()
    contents = []
    for group in groups:
        contents.append({
            'Name': group
        })

    context = {
        'Exabeam.PeerGroup(val.Name && val.Name === obj.Name)': contents
    }

    human_readable = tableToMarkdown('Exabeam Peer Groups', contents)
    return human_readable, context, groups


def get_user_labels(client: Client, *_):
    """ Returns all user Labels

    Args:
        client: Client

    """
    labels = client.get_user_labels_request()
    contents = []
    for label in labels:
        contents.append({
            'Label': label
        })

    context = {
        'Exabeam.UserLabel(val.Label && val.Label === obj.Label)': contents
    }

    human_readable = tableToMarkdown('Exabeam User Labels', contents)
    return human_readable, context, labels


def main():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    server_url = demisto.params().get('url')
    verify_certificate = not demisto.params().get('insecure', False)
    headers = {
        'Accept': 'application/json'
    }
    proxies = handle_proxy()
    client = Client(server_url, verify=verify_certificate, username=username, password=password, proxies=proxies,
                    headers=headers)
    LOG(f'Command being called is demisto.command()')
    commands = {
        'test-module': test_module,
        'get-notable-users': get_notable_users,
        'get-watchlists': get_watchlist,
        'get-peer-groups': get_peer_groups,
        'get-user-info': get_user_info,
        'get-user-labels': get_user_labels,
        'get-user-sessions': get_user_sessions
    }
    try:
        command = demisto.command()
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))  # type: ignore

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
