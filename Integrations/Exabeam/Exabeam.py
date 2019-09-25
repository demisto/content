import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from typing import Dict

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' HELPERS '''


class DemistoException(Exception):
    pass


def convert_unix_to_date(d):
    """ Convert millise since epoch to date formatted MM/DD/YYYY HH:MI:SS """
    if d:
        dt = datetime.utcfromtimestamp(d / 1000)
        return dt.strftime('%m/%d/%Y %H:%M:%S')
    return 'N/A'


class Client:
    def __init__(self, exabeam_url, username, password, verify, proxies, headers):
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

    def _http_request(self, method, suffix_url, params=None, data=None, headers=None, full_url=None):
        full_url = full_url if full_url else self.base_url + suffix_url
        sessions_list = {
            'get': self.session.get,
            'post': self.session.post,
            'delete': self.session.delete,
            'put': self.session.put
        }
        session_call = sessions_list[method.lower()]
        try:
            res = session_call(
                full_url,
                verify=self.verify,
                data=data,
                proxies=self.proxies,
                params=params
            )
            if res.status_code not in {200}:
                raise ValueError(f'Error in API call to Exabeam {res.status_code}. Reason: {res.text}')

            try:
                return res
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
        self._http_request('POST', '', full_url=self.server + '/api/auth/login', data={
            'username': self.username,
            'password': self.password
        })

    def _logout(self):
        """ Logout from the session """
        self._http_request('GET', self.server + '/api/auth/logout', None)

    def test_module(self):
        """
        Performs basic get request to check if the server is reachable.
        """
        suffix_url = 'ping'
        self._http_request('GET', suffix_url)

    def get_notable_users_request(self, unit=None, num=None, limit=None):

        suffix_url = 'users/notable'

        params = {
            'unit': unit,
            'num': num,
            'numberOfResults': limit
        }

        response = self._http_request('GET', suffix_url, params)
        return response.json()

    def get_user_info_request(self, username):

        suffix_url = f'user/{username}/info'
        response = self._http_request('GET', suffix_url)

        return response.json()

    def create_watchlist_request(self, title=None, category=None, description=None, items=None):

        suffix_url = 'watchlist'

        params = {
            'title': title,
            'category': category,
            'description': description,
            'items': items
        }

        response = self._http_request('POST', suffix_url, params)
        return response.json()

    def get_watchlist_request(self):

        suffix_url = 'watchlist'
        response = self._http_request('GET', suffix_url)

        return response.json()

    def get_peergroups_request(self):

        suffix_url = 'peerGroup'

        response = self._http_request('GET', suffix_url)
        return response.json()

    def delete_watchlist_request(self, watchlist_id):

        suffix_url = f'watchlist/{watchlist_id}'

        response = self._http_request('DELETE', suffix_url)
        return response

    def add_user_request(self, user_id=None, watchlist_id=None):

        suffix_url = f'watchlist/user/{user_id}/add'

        params = {
            'itemId': user_id,
            'watchListId': watchlist_id
        }

        response = self._http_request('PUT', suffix_url, params)
        return response.json()

    def get_user_labels_request(self):

        suffix_url = 'userLabel'
        response = self._http_request('GET', suffix_url)

        return response.json()

    def get_users_request(self, user_label=None):

        suffix_url = 'userLabel/getUserIds'
        params = {
            'userLabels': user_label
        }

        response = self._http_request('GET', suffix_url, params)
        return response.json()

    def user_sequence_request(self, username=None, start_time=None, end_time=None):

        suffix_url = f'user/{username}/sequences'
        params = {
            'username': username,
            'startTime': start_time,
            'endTime': end_time
        }

        response = self._http_request('GET', suffix_url, params)
        return response.json()

    def get_asset_data_request(self, asset_id=None):

        suffix_url = f'asset/{asset_id}/data'
        response = self._http_request('GET', suffix_url)
        return response.json()


''' COMMANDS + REQUESTS FUNCTIONS '''


def get_notable_users(client: Client, args: Dict):
    """ Get notable users in a period of time

    Args:
        client: Client
        args: Dict

    """
    unit = args.get('time_duration_unit')
    num = args.get('time_duration_number')
    limit = args.get('limit')
    contents = []
    headers = ['UserFullName', 'UserName', 'Title', 'Department', 'RiskScore', 'Labels', 'NotableSessionIds',
               'EmployeeType', 'FirstSeen', 'LastSeen', 'LastActivity', 'Location']
    users = client.get_notable_users_request(unit, num, limit).get('users', [])
    if not users:
        return_outputs('No users were found in this period of time.', {})
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

        return_outputs(tableToMarkdown('Exabeam Notable Users', contents, headers, removeNull=True), context, users)


def get_user_info(client: Client, args: Dict):
    """  Returns User info data for the given username
    Args:
        client: Client
        args: Dict

    """
    username = args.get('username')
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
        return_outputs(f'The user {username} was not found', {})
    else:
        return_outputs(tableToMarkdown(f'User {username} information', contents, headers, removeNull=True), context, user)


def get_user_sessions(client: Client, args: Dict):
    """ Returns sessions for the given username and time range

    Args:
        client: Client
        args: Dict

    """
    username = args.get('username')
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    contents = []
    headers = ['SessionID', 'RiskScore', 'InitialRiskScore', 'StartTime', 'EndTime', 'LoginHost', 'Label']

    user = client.user_sequence_request(username, start_time, end_time)
    session = user.get('sessions')
    for session_ in session:
        contents.append({
            'SessionID': session_.get('sessionId'),
            'StartTime': convert_unix_to_date(session_.get('startTime')),
            'EndTime': convert_unix_to_date(session_.get('endTime')),
            'InitialRiskScore': session_.get('initialRiskScore'),
            'RiskScore': round(session_.get('riskScore')),
            'LoginHost': session_.get('loginHost'),
            'Label': session_.get('label'),
            })

    context = {
        'Exabeam.User': {
            'Username': username,
            'Session(val.SessionID && val.SessionID === obj.SessionID)': contents
        }
    }

    if session:
        return_outputs(tableToMarkdown(f'User {username} sessions information', contents, headers, removeNull=True),
                       context, user)
    else:
        return_outputs(f'The user {username} was not found', {})


def get_watchlist(client: Client):
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

    return_outputs(tableToMarkdown('Exabeam Watchlists', contents, headers), context, watchlist)


def get_peer_groups(client: Client):
    """ Returns all peer groups

    Args:
        client: Client

    """

    groups = client.get_peergroups_request()
    peer_group = ', '.join(groups)
    new_group = peer_group.split(',')
    contents = []
    for group in new_group:
        contents.append({
            'Name': group
        })

    context = {
        'Exabeam.PeerGroup(val.Name && val.Name === obj.Name)': contents
    }

    return_outputs(tableToMarkdown('Exabeam Peer Groups', contents), context, groups)


def get_user_labels(client: Client):
    """ Returns all user Labels

    Args:
        client: Client

    """

    labels = client.get_user_labels_request()
    user_labels = ', '.join(labels)
    new_group = user_labels.split(',')
    contents = []
    for label in new_group:
        contents.append({
            'Label': label
        })

    context = {
        'Exabeam.UserLabel(val.UserLabel && val.UserLabel === obj.UserLabel)': contents
    }

    return_outputs(tableToMarkdown('Exabeam User Labels', contents), context, labels)


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    server_url = demisto.params().get('url')
    verify_certificate = not demisto.params().get('insecure', False)
    headers = {
        'Accept': 'application/json'
    }
    proxies = handle_proxy()

    LOG('Command being called is %s' % (demisto.command()))

    try:
        client = Client(server_url, verify=verify_certificate, username=username, password=password, proxies=proxies,
                        headers=headers)
        if demisto.command() == 'test-module':
            client.test_module()
            demisto.results('ok')
        elif demisto.command() == 'get-notable-users':
            get_notable_users(client, demisto.args())
        elif demisto.command() == 'get-watchlists':
            get_watchlist(client)
        elif demisto.command() == 'get-peer-groups':
            get_peer_groups(client)
        elif demisto.command() == 'get-user-info':
            get_user_info(client, demisto.args())
        elif demisto.command() == 'get-user-labels':
            get_user_labels(client)
        elif demisto.command() == 'get-user-sessions':
            get_user_sessions(client, demisto.args())

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

