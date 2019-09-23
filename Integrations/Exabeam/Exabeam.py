import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from distutils.util import strtobool
from datetime import datetime
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

    def http_request(self, method, suffix_url, params=None, data=None, headers=None, full_url=None):
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
        self.http_request('POST', '', full_url=self.server + '/api/auth/login', data={
            'username': self.username,
            'password': self.password
        })

    def _logout(self):
        """ Logout from the session """
        self.http_request('GET', self.server + '/api/auth/logout', None)

    def test_module(self):
        """
        Performs basic get request to check if the server is reachable.
        """
        suffix_url = 'ping'
        self.http_request('GET', suffix_url)

    def get_notable_users_request(self, unit=None, num=None, limit=None):

        suffix_url = 'users/notable'

        params = {
            'unit': unit,
            'num': num,
            'numberOfResults': limit
        }

        response = self.http_request('GET', suffix_url, params)
        return response.json()

    def get_user_info_request(self, username):

        suffix_url = f'user/{username}/info'
        response = self.http_request('GET', suffix_url)

        return response.json()

    def create_watchlist_request(self, title=None, category=None, description=None, items=None):

        suffix_url = 'watchlist'

        params = {
            'title': title,
            'category': category,
            'description': description,
            'items': items
        }

        response = self.http_request('POST', suffix_url, params)
        return response.json()

    def get_watchlist_request(self):

        suffix_url = 'watchlist'
        response = self.http_request('GET', suffix_url)

        return response.json()

    def get_peergroups_request(self):

        suffix_url = 'peerGroup'

        response = self.http_request('GET', suffix_url)
        return response.json()

    def delete_watchlist_request(self, watchlist_id):

        suffix_url = f'watchlist/{watchlist_id}'

        response = self.http_request('DELETE', suffix_url)
        return response

    def add_user_request(self, user_id=None, watchlist_id=None):

        suffix_url = f'watchlist/user/{user_id}/add'

        params = {
            'itemId': user_id,
            'watchListId': watchlist_id
        }

        response = self.http_request('PUT', suffix_url, params)
        return response.json()

    def get_user_labels_request(self):

        suffix_url = 'userLabel'
        response = self.http_request('GET', suffix_url)

        return response.json()

    def get_users_request(self, user_label=None):

        suffix_url = 'userLabel/getUserIds'
        params = {
            'userLabels': user_label
        }

        response = self.http_request('GET', suffix_url, params)
        return response.json()

    def user_sequence_request(self, username=None, start_time=None, end_time=None):

        suffix_url = f'user/{username}/sequences'
        params = {
            'username': username,
            'startTime': start_time,
            'endTime': end_time
        }

        response = self.http_request('GET', suffix_url, params)
        return response.json()

    def get_asset_data_request(self, asset_id=None):

        suffix_url = f'asset/{asset_id}/data'
        response = self.http_request('GET', suffix_url)
        return response.json()


''' COMMANDS + REQUESTS FUNCTIONS '''


def get_notable_users(client, args):

    """
    Get notable users in a period of time
    """
    unit = args.get('time_duration_unit')
    num = args.get('time_duration_number')
    limit = args.get('limit')
    contents = []
    headers = ['UserFullName', 'UserName', 'RiskScore', 'AverageRiskScore', 'Labels', 'NotableSessionIds',
               'AccountsNumber', 'FirstSeen', 'LastSeen', 'LastActivityType', 'Executive', 'Location']
    users = client.get_notable_users_request(unit, num, limit).get('users', [])

    for user in users:
        user_ = user.get('user', {})
        contents.append({
            'UserName': user_.get('username'),
            'RiskScore': user_.get('riskScore'),
            'AverageRiskScore': user_.get('averageRiskScore'),
            'FirstSeen': convert_unix_to_date(user_.get('firstSeen')),
            'LastSeen': convert_unix_to_date(user_.get('lastSeen')),
            'LastActivityType': user_.get('lastActivityType'),
            'Labels': user_.get('labels'),
            'UserFullName': user.get('userFullName'),
            'AccountsNumber': user.get('numOfAccounts'),
            'Location': user_.get('info')['location'],
            'NotableSessionIds': user.get('notableSessionIds'),
            'Executive': user.get('isExecutive')
        })

    context = {
        'Exabeam.NotableUser(val.UserName && val.UserName === obj.UserName)': contents
    }

    return_outputs(tableToMarkdown('Exabeam Notable Users', contents, headers, removeNull=True), context, users)


def get_user_info(client, args):
    """
    Args:
        client: Client
        args: Dict

    Returns: User info data for the given username

    """
    username = args.get('username')
    headers = ['Username', 'RiskScore', 'AverageRiskScore', 'LastSessionID', 'Labels', 'FirstSeen',
               'LastSeen', 'LastActivityType', 'AccountNames', 'PeerGroupFieldName', 'PeerGroupFieldValue',
               'PeerGroupDisplayName', 'PeerGroupType']
    user = client.get_user_info_request(username)
    if user:
        user_info = user.get('userInfo', {})
        contents = {
            'Username': user.get('username'),
            'RiskScore': user_info.get('riskScore'),
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

    return_outputs(tableToMarkdown(f'User {username} information', contents, headers, removeNull=True), context, user)


def get_user_sequences(client: Client, args: Dict):
    """

    Args:
        client: Client
        args: Dict

    Returns: sessions for the given username and time range

    """
    username = args.get('username')
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    contents = []
    headers = ['SessionID', 'RiskScore', 'InitialRiskScore', 'StartTime', 'EndTime', 'LoginHost', 'Label']

    user = client.user_sequence_request(username, start_time, end_time)
    if user:
        session = user.get('sessions')
        for session_ in session:
            contents.append({
                'SessionID': session_.get('sessionId'),
                'StartTime': convert_unix_to_date(session_.get('startTime')),
                'EndTime': convert_unix_to_date(session_.get('endTime')),
                'InitialRiskScore': session_.get('initialRiskScore'),
                'RiskScore': session_.get('riskScore'),
                'LoginHost': session_.get('loginHost'),
                'Label': session_.get('label')
            })

    context = {
        'Exabeam.User(val.SessionID && val.SessionID === obj.SessionID)': contents
    }

    return_outputs(tableToMarkdown(f'User {username} sequence information', contents, headers, removeNull=True),
                   context, user)


def watchlist_add_user(client, args: Dict):
    """

    Args:
        client: Client
        args: Dict

    Add user to a watchlist

    """

    user_id = args.get('user_id')
    watchlist_id = args.get('watchlist_id')

    response = client.add_user_request(user_id, watchlist_id)
    if response:
        contents = {
            'UserID': response.get('item'),
            'WatchlistID': response.get('watchlistId')
        }
    context = {
        'Exabeam.Watchlist(val.WatchlistID && val.WatchlistID === obj.WatchlistID)': contents
    }

    return_outputs(tableToMarkdown('The user was added successfully to the watchlist', contents), context, response)


def get_watchlist(client: Client):
    """

    Args:
        client: Client

    Returns: All watchlist ids and titles.

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


def create_watchlist(client: Client, args: Dict):
    """

    Args:
        client: Client
        args: Dict

    Create new watchlist

    """
    title = args.get('title')
    category = args.get('category')
    description = args.get('description')
    items = argToList(args.get('items'))
    headers = ['WatchlistID', 'Title', 'Category']

    watchlist = client.create_watchlist_request(title, category, description, items)
    if watchlist:
        contents = {
            'WatchlistID': watchlist.get('watchlistId'),
            'Title': watchlist.get('title'),
            'Category': watchlist.get('category')
        }

    context = {
        'Exabeam.Watchlist(val.WatchlistID && val.WatchlistID === obj.WatchlistID)': contents
    }
    return_outputs(tableToMarkdown('New watchlist has been created', contents, headers), context, watchlist)


def delete_watchlist(client: Client, args: Dict):
    """

    Args:
        client: Client
        args: Dict

    Delete a watchlist

    """

    watchlist_id = args.get('watchlist_id')
    client.delete_watchlist_request(watchlist_id)

    demisto.results('The watchlist was deleted successfully')


def get_peer_groups(client: Client):
    """

    Args:
        client: Client

    Returns: All peer groups.

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
    """

    Args:
        client: Client

    Returns: All user Labels

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


def get_users(client: Client, args: Dict):
    """

    Args:
        client: Client
        args: Dict

    Returns: A list of user ids matching user labels.

    """

    user_label = args.get('user_label')

    users = client.get_users_request(user_label)
    print(users)
    users_ = ', '.join(users)
    data = users_.split(',')
    contents = []
    for user in data:
        contents.append({
            'UserID': user
        })

    context = {
        'Exabeam.User(val.UserID && val.UserID === obj.UserID)': contents
    }

    return_outputs(tableToMarkdown('Exabeam Users Ids', contents), context, users)


def get_asset_data(client: Client, args: Dict):
    """

    Args:
        client: Client
        args: Dict

    Returns: Asset data for given asset ID (hostname or IP address)

    """
    asset_id = args.get('asset_id')
    data = client.get_asset_data_request(asset_id)

    if data:
        asset = data.get('asset', {})
        contents = {
            'HostName': asset.get('hostName'),
            'IPAddress': asset.get('ipAddress'),
            'AssetType': asset.get('assetType'),
            'FirstSeen': convert_unix_to_date(asset.get('firstSeen')),
            'LastSeen': convert_unix_to_date(asset.get('lastSeen')),
            'Labels': data.get('labels')
        }

    context = {
        'Exabeam.Asset(val.IPAddress && val.IPAddress === obj.IPAddress)': contents
    }

    return_outputs(tableToMarkdown('Exabeam Asset Data', contents, removeNull=True), context, data)


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    server_url = demisto.params()['url'][:-1] \
        if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
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
        elif demisto.command() == 'create-watchlist':
            create_watchlist(client, demisto.args())
        elif demisto.command() == 'delete-watchlist':
            delete_watchlist(client, demisto.args())
        elif demisto.command() == 'get-user-info':
            get_user_info(client, demisto.args())
        elif demisto.command() == 'watchlist-add-user':
            watchlist_add_user(client, demisto.args())
        elif demisto.command() == 'get-user-labels':
            get_user_labels(client)
        elif demisto.command() == 'get-users':
            get_users(client, demisto.args())
        elif demisto.command() == 'get-asset-data':
            get_asset_data(client, demisto.args())
        elif demisto.command() == 'get-user-sequences':
            get_user_sequences(client, demisto.args())

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

