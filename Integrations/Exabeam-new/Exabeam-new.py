from typing import Dict

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from distutils.util import strtobool
from datetime import datetime

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' HELPERS '''


class DemistoException(Exception):
    pass


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
        self.login()

    def __del__(self):
        self.logout()

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

    def login(self):
        """ Login using the credentials and store the cookie """
        self.http_request('POST', '', full_url=self.server + '/api/auth/login', data={
            'username': self.username,
            'password': self.password
        })

    def logout(self):
        """ Logout from the session """
        self.http_request('GET', self.server + '/api/auth/logout', None)

    def test_module(self):
        """
        Performs basic get request to check if the server is reachable.
        """
        suffix_url = 'ping'
        self.http_request('GET', suffix_url)
        return True

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

        suffix_url = f'watchlist/{watchlist_id}/'

        response = self.http_request('DELETE', suffix_url)
        return response


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
    users = client.get_notable_users_request(unit, num, limit).get('users', {})

    for user in users:
        contents.append({
            'UserName': user.get('user').get('username'),
            'RiskScore': user.get('user').get('riskScore'),
            'AverageRiskScore': user.get('user').get('averageRiskScore'),
            'FirstSeen': user.get('user').get('firstSeen'),
            'LastSeen': user.get('user').get('lastSeen'),
            'LastActivityType': user.get('user').get('lastActivityType'),
            'Labels': user.get('user').get('labels'),
            'UserFullName': user.get('userFullName'),
            'AccountsNumber': user.get('numOfAccounts'),
            'Location': user.get('user').get('info')['location'],
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
        contents = {
            'Username': user.get('username'),
            'RiskScore': user.get('userInfo').get('riskScore'),
            'AverageRiskScore': user.get('userInfo').get('averageRiskScore'),
            'LastSessionID': user.get('userInfo').get('lastSessionId'),
            'FirstSeen': user.get('userinfo').get('firstSeen'),
            # 'LastSeen': user.get('userinfo').get('lastSeen'),
            # 'LastActivityType': user.get('userinfo').get('lastActivityType'),
            # 'Label': user.get('userinfo').get('labels'),
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


def get_watchlist(client):

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


def create_watchlist(client, args):
    """
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
    Delete a watchlist
    """

    watchlist_id = args.get('watchlist_id')
    client.delete_watchlist_request(watchlist_id)

    demisto.results('The watchlist was deleted successfully')


def get_peer_groups(client):

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


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # Remove trailing slash to prevent wrong URL path to service
    server_url = demisto.params()['url'][:-1] \
        if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
    verify_certificate = not demisto.params().get('insecure', False)
    headers = {
        'Accept': 'application/json'
    }

    # Remove proxy if not set to true in params
    proxies = handle_proxy()

    LOG('Command being called is %s' % (demisto.command()))

    try:
        client = Client(server_url, verify=verify_certificate, username=username, password=password, proxies=proxies, headers=headers)
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            client.test_module()
            demisto.results('ok')
        elif demisto.command() == 'get-notable-users':
            get_notable_users(client, demisto.args())
        elif demisto.command() == 'get-watchlist':
            get_watchlist(client)
        elif demisto.command() == 'get-peer-groups':
            get_peer_groups(client)
        elif demisto.command() == 'create-watchlist':
            create_watchlist(client, demisto.args())
        elif demisto.command() == 'delete-watchlist':
            delete_watchlist(client, demisto.args())
        elif demisto.command() == 'get-user-info':
            get_user_info(client, demisto.args())

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

