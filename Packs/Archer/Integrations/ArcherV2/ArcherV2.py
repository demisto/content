import demistomock as demisto
from CommonServerPython import *
import traceback
from CommonServerUserPython import *
from typing import Tuple, Dict, Any
''' IMPORTS '''


REQUEST_HEADERS = {'Accept': 'application/json,text/html,application/xhtml +xml,application/xml;q=0.9,*/*;q=0.8',
                   'Content-Type': 'application/json'}


class Client(BaseClient):
    def __init__(self, base_url, username, password, instance_name, domain, **kwargs):
        self.username = username
        self.password = password
        self.instance_name = instance_name
        self.domain = domain
        super(Client, self).__init__(base_url=base_url, headers=REQUEST_HEADERS, **kwargs)

    def do_request(self, method, url_suffix, data=None):
        if not REQUEST_HEADERS.get('Authorization'):
            self.update_session()
            res = self._http_request(method, url_suffix, headers=REQUEST_HEADERS, json_data=data,
                                 resp_type='response', ok_codes=[200, 401])

        if res.status_code == 401:
            self.update_session()
            res = self._http_request(method, url_suffix, headers=REQUEST_HEADERS, json_data=data,
                                     resp_type='response', ok_codes=[200, 401])
            return res

        return res.json()

    def update_session(self):
        body = {
            'InstanceName': self.instance_name,
            'Username': self.username,
            'UserDomain': self.domain,
            'Password': self.password
        }

        res = self._http_request('Post', 'core/security/login', json_data=body, ok_codes=[200])

        session = res.get('RequestedObject').get('SessionToken')
        REQUEST_HEADERS['Authorization'] = f'Archer session-id={session}'

    def login(self):
        return self.update_session()


def test_module(client: Client) -> str:
    return 'ok' if client.do_request('GET', 'core/system/application') else 'Connection failed.'


def search_applications_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    app_id = args.get('application-id', '')
    endpoint_url = 'core/system/application/'

    if app_id:
         endpoint_url = f'core/system/application/{app_id}'

    res = client.do_request('GET', endpoint_url)

    if isinstance(res, dict):
        res = [res]

    applications = []
    for app in res:
        if app.get('RequestedObject'):
            app_obj = app['RequestedObject']
            applications.append({'ID': app_obj.get('Id'),
                                 'Type': app_obj.get('Type'),
                                 'Name': app_obj.get('Name'),
                                 'Status': app_obj.get('Status'),
                                 'Guid': app_obj.get('Guid')})

    markdown = tableToMarkdown('Applications information', applications)
    context: dict = {
            f'Archer.Application(val.Id && val.Id == obj.Id)':
            applications
        }
    return markdown, context, res


def main():
    params = demisto.params()
    credentials = params.get('credentials')
    base_url = params.get('url').strip('/') + '/rsaarcher/api/'
    client = Client(base_url,
                    credentials.get('identifier'), credentials.get('password'),
                    params.get('instanceName'),
                    params.get('domain'),
                    verify=not params.get('insecure', False),
                    proxy=params.get('proxy', False))
    commands = {
        'archer-search-applications': search_applications_command,
    }

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'test-module':
            demisto.results(test_module(client))
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            return_error('Command not found.')
    except Exception as e:
        return_error(f'Unexpected error: {str(e)}, traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
