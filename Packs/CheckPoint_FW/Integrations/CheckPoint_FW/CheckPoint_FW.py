import json

import dateparser
import demistomock as demisto
import requests
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    """
    Client for CheckPoint RESTful API.
    Args:
          base_url (str): the URL of X-Force Exchange.
          server (str): the server
          port(str): the port
          api_key (str): the API key of X-Force Exchange.
          password (str): password for the API key (required for authentication).
          use_ssl (bool): specifies whether to verify the SSL certificate or not.
          use_proxy (bool): specifies if to use Demisto proxy settings.
    """

    def __init__(self, base_url: str, server: str, port: str, sid: str, use_ssl: bool, use_proxy: bool, **kwargs):
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy, **kwargs)
        self.server = server
        self.port = port
        self.headers = {'Content-Type': 'application/json',
                        'X-chkp-sid': sid}

    def logout(self):
        """logout from current session """
        return self._http_request(method='POST', url_suffix='logout', headers=self.headers,
                                  verify=False, json={})

    def checkpoint_delete_rule(self, identifier, layer):
        """
        Delete existing rule object using object name or uid.

        Args:
            identifier: uid, name or rule-number.
            layer: Layer that the rule belongs to identified by the name or UID.

        Returns:
            Operation status.
        """

        body = {'name': identifier,
                'layer': layer}
        response = self._http_request(method='POST', url_suffix='delete-access-rul', json_data=body).get('result')
        delete_object(response, 'rule')

    def checkpoint_update_rule(self, identifier: str, layer: str, action: str, enabled: bool, new_name: str,
                               new_position, ignore_warnings=False, ignore_errors=False):
        """
        Edit existing rule object using object name or uid.

        Args:
            identifier: uid, name or rule-number.
            layer (str): Layer that the rule belongs to identified by the name or UID.
            action (str): the action to set. available options:
                                "Accept", "Drop", "Ask", "Inform", "Reject", "User Auth", "Client Auth", "Apply Layer".
            enabled(bool): Enable/Disable the rule
            new_name(str): New name of the object.
            new_position(int or str): New position in the rulebase.
                                    value can be int- add rule at the specific position
                                    value can be str- add rule at the position. valid values: top, bottom.
            ignore_warnings(bool):Apply changes ignoring warnings.
            ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such a changes.
                                 If ignore-warnings flag was omitted - warnings will also be ignored.

        """

        body = {'name': identifier,
                'layer': layer,
                'action': action,
                'enabled': enabled,
                'new-name': new_name,
                'new-position': new_position,
                'ignore_warnings': ignore_warnings,
                'ignore_errors': ignore_errors
                }
        response = self._http_request(method='POST', url_suffix='set-access-rule', json_data=body).get('result')
        update_object(response, 'rule')

    def checkpoint_show_access_rulebase(self, identifier, limit: int = 50, offset: int = 0):
        """
        Show existing object using object name or uid.

        Args:
            identifier(str): uid or name.
            limit(int): The maximal number of returned results.
            offset(int): Number of the results to initially skip.
        """

        body = {'name': identifier,
                'limit': limit,
                'offset': offset}
        response = self._http_request(method='POST', url_suffix='show-access-rulebase', json_data=body)
        get_object(response, 'rule')

    def checkpoint_show_all_hosts(self, limit: int = 50, offset: int = 0, details_level: str = 'standard') -> dict:
        """
        Retrieve all host objects.

        Args:
            limit(int): The maximal number of returned results. default is 50.
            offset(int): Number of the results to initially skip. default is 0.
            details_level(str): level of details. default is standard.

        Returns:
        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs for other tasks in the
                 playbook
        raw_response (dict): Used for debugging/troubleshooting purposes - will be shown only if the command executed with
                      raw-response=true
        """

        dictionary = {'limit': limit, 'offset': offset, 'details-level': details_level}
        response = self._http_request(method='POST', url_suffix='show-hosts', headers=self.headers,
                                      resp_type='json', json_data=dictionary)
        show_all_objects(response, 'host')

    def checkpoint_show_host(self, identifier: str):
        """
        Show existing host object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        dictionary = {'name': identifier}
        response = self._http_request(method='POST', url_suffix='show-host', headers=self.headers,
                                      resp_type='json', json_data=dictionary)
        get_object(response, 'host')

    def checkpoint_add_host(self, name: str, ip: str):
        """
        Add host objects.

        Args:
            name(str): Object name. Must be unique in the domain.
            ip(str): IPv4 or IPv6 address..

        Returns:
            dict: the results to return into Demisto's context.
        """
        response = self._http_request(method='POST', url_suffix='add-host', headers=self.headers,
                                      json_data={"name": name, "ip-address": ip})
        add_object(response, 'add')

    def checkpoint_update_host(self, identifier, ip: str = None, new_name: str = None, comments: str = None,
                               ignore_warnings: bool = False, ignore_errors: bool = False) -> dict:
        """
        Edit existing host object using object name or uid.

        Args:
            identifier(str): uid or name.
            ip(str): IPv4 or IPv6 address.
            new_name(str): New name of the object.
            comments(str): Comments string.
            ignore_warnings(bool):Apply changes ignoring warnings.
            ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such a changes.
                                 If ignore-warnings flag was omitted - warnings will also be ignored.
        """
        body = {'name': identifier,
                'ip-address': ip,
                'new-name': new_name,
                'comments': comments,
                'ignore-warnings': ignore_warnings,
                'ignore-errors': ignore_errors
                }
        response = self._http_request(method='POST', url_suffix='set-host', headers=self.headers,
                                      json_data=body)
        update_object(response, 'add')

    def checkpoint_delete_host(self, identifier: str) -> dict:
        """
        Delete existing host object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        return self._http_request(method='POST', url_suffix='delete-host', headers=self.headers, verify=False,
                                  json_data={'name': identifier})


    def checkpoint_show_all_groups(self, limit: int = 50, offset: int = 0) -> dict:
        """
        Retrieve all group objects from checkpoint.

        Args:
            limit(int): The maximal number of returned results. default is 50.
            offset(int): Number of the results to initially skip. default is 0.

        Returns:
            dict: the results to return into Demisto's context.
        """
        response = self._http_request(method='POST', url_suffix='show-groups', headers=self.headers,
                                  verify=False, json_data={"limit": limit, "offset": offset})
        show_all_objects(response, 'group')

    def checkpoint_show_group(self, identifier):
        """
        Show existing group object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        response = self._http_request(method='POST', url_suffix='show-groups', json_data={'name': identifier})
        get_object(response, 'group')

    def checkpoint_add_group(self, name: str, ip: str) -> dict:
        """
        add group objects.

        Args:
            name(str): Object name. Must be unique in the domain.
            ip(str): IPv4 or IPv6 address..

        Returns:
            dict: the results to return into Demisto's context.
        """
        response = self._http_request(method='POST', url_suffix='add-group', headers=self.headers,
                                  verify=False, json_data={"name": name, "ip-address": ip})
        add_object(response, 'group')

    def checkpoint_update_group(self, identifier, ip: str = None, new_name: str = None, comments: str = None,
                                ignore_warnings: bool = False, ignore_errors: bool = False) -> dict:
        """
        Edit existing object using object name or uid.

        Args:
            identifier(str): uid or name.
            ip(str): IPv4 or IPv6 address.
            new_name(str): New name of the object.
            comments(str): Comments string.
            ignore_warnings(bool):Apply changes ignoring warnings.
            ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such a changes.
                                 If ignore-warnings flag was omitted - warnings will also be ignored.

        """
        body = {'name': identifier,
                'ip-address': ip,
                'new-name': new_name,
                'comments': comments,
                'ignore_warnings': ignore_warnings,
                'ignore_errors': ignore_errors}
        response = self._http_request(method='POST', url_suffix='set-group', headers=self.headers,
                                  verify=False, json_data=body)
        update_object(response, 'group')

    def checkpoint_delete_group(self, identifier: str) -> dict:
        """
        Delete existing group object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        response = self._http_request(method='POST', url_suffix='delete-group', headers=self.headers, verify=False,
                                  json_data={'name': identifier})
        delete_object(response, 'group')

    def checkpoint_show_all_address_ranges(self, limit: int = 50, offset: int = 0) -> dict:
        """
        Retrieve all address range objects from checkpoint.

        Args:
            limit(int): The maximal number of returned results. default is 50.
            offset(int): Number of the results to initially skip. default is 0.
        """
        response = self._http_request(method='POST', url_suffix='show-address-ranges', headers=self.headers,
                                  verify=False, json_data={"limit": limit, "offset": offset})
        show_all_objects(response, 'address range')

    def checkpoint_show_address_range(self, identifier):
        """
        Show existing address range object using object name or uid.

        Args:
            identifier(str): uid or name of the address range object.
        """
        response = self._http_request(method='POST', url_suffix='show-address-range', json_data={'name': identifier})
        get_object(response, 'address range')

    def checkpoint_add_address_range(self, name: str, first_ip: str, last_ip: str) -> dict:
        """
        add address_range objects.

        Args:
            name(str): Object name. Must be unique in the domain.
            first_ip(str): First IP address in the range. IPv4 or IPv6 address.
            last_ip(str): Last IP address in the range. IPv4 or IPv6 address.
        """
        body = {'name': name,
                'ip-address-first': first_ip,
                'ip-address-last': last_ip
                }
        response = self._http_request(method='POST', url_suffix='add-address-range', headers=self.headers,
                                  verify=False, json_data=body)
        add_object(response, 'address range')

    def checkpoint_update_address_range(self, identifier, first_ip: str = None, last_ip: str = None,
                                        new_name: str = None, comments: str = None, ignore_warnings: bool = False,
                                        ignore_errors: bool = False) -> dict:
        """
        Edit existing address_range object using object name or uid.

        Args:
            identifier(str): uid or name.
            first_ip(str): First IP address in the range. IPv4 or IPv6 address.
            last_ip(str): Last IP address in the range. IPv4 or IPv6 address.
            new_name(str): New name of the object.
            comments(str): Comments string.
            ignore_warnings(bool):Apply changes ignoring warnings.
            ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such a changes.
                                 If ignore-warnings flag was omitted - warnings will also be ignored.

        """
        body = {'name': identifier,
                'ip-address-first': first_ip,
                'ip-address-last': last_ip,
                'new-name': new_name,
                'comments': comments,
                'ignore_warnings': ignore_warnings,
                'ignore_errors': ignore_errors}

        response = self._http_request(method='POST', url_suffix='set-group', headers=self.headers,
                                  verify=False, json_data=body)
        update_object(response, 'address range')

    def checkpoint_delete_address_range(self, identifier: str) -> dict:
        """
        Delete existing address range object using object name or uid.

        Args:
            identifier(str): uid or name.
        Returns:
            Operation status.
        """
        response = self._http_request(method='POST', url_suffix='delete-address-range', headers=self.headers,
                                  verify=False, json_data={'name': identifier})
        delete_object(response, 'address range')

    def checkpoint_show_all_threat_indicators(self, limit: int = 50, offset: int = 0) -> dict:
        """
        Display a list of Threat-Indicators.

        Args:
            limit(int): The maximal number of returned results. default is 50.
            offset(int): Number of the results to initially skip. default is 0.

        Returns:
            dict: the results to return into Demisto's context.
        """
        response = self._http_request(method='POST', url_suffix='show-threat-indicators', headers=self.headers,
                                  verify=False, json_data={"limit": limit, "offset": offset})
        show_all_objects(response, 'threat indicator')

    def checkpoint_show_threat_indicator(self, identifier, details_level: str = 'standard'):
        """
        Show existing threat indicator using object name or uid.

        Args:
            identifier(str): uid or name.
            details_level(str): The level of detail for some of the fields in the response.
                                Valid values: uid, standard, full.
        """
        response = self._http_request(method='POST', url_suffix='show-threat-indicator',
                                  json_data={'name': identifier, 'details-level': details_level})

        get_object(response, 'threat indicator')

    def checkpoint_add_threat_indicator(self, name: str, ip: str) -> dict:
        """
        Create a new Threat-Indicator.

        Args:
            name(str): Object name. Must be unique in the domain.
            ip(str): IPv4 or IPv6 address..

        Returns:
            dict: the results to return into Demisto's context.
        """
        response = self._http_request(method='POST', url_suffix='add-threat-indicator', headers=self.headers,
                                  verify=False, json_data={"name": name, "ip-address": ip})
        add_object(response, 'threat indicator')

    def checkpoint_update_threat_indicator(self, identifier, ip: str = None, new_name: str = None,
                                           comments: str = None) -> dict:
        """
        Edit existing object using object name or uid.

        Args:
            identifier(str): uid or name.
            ip(str): IPv4 or IPv6 address.
            new_name(str): New name of the object.
            comments(str): Comments string.
        """
        body = {'name': identifier,
                'ip-address': ip,
                'new-name': new_name,
                'comments': comments
                }
        response = self._http_request(method='POST', url_suffix='set-threat-indicator', headers=self.headers,
                                  verify=False, json_data=body)
        update_object(response, 'threat indicator')

    def checkpoint_delete_threat_indicator(self, identifier: str) -> dict:
        """
        Delete existing group object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        response = self._http_request(method='POST', url_suffix='delete-threat-indicator', headers=self.headers,
                                  verify=False,
                                  json_data={'name': identifier})
        delete_object(response, 'threat indicator')

    def checkpoint_publih(self):
        """

        All the changes done by this user will be seen by all users only after publish is called.
        Args:
            uid(str): Session unique identifier.
        """
        return self._http_request(method='POST', url_suffix='publish', headers=self.headers,
                                  verify=False, json_data={})

    def list_incidents(self):
        """
        returns dummy incident data, just for the example.
        """
        return [
            {
                'incident_id': 1,
                'description': 'Hello incident 1',
                'created_time': datetime.utcnow().strftime(DATE_FORMAT)
            },
            {
                'incident_id': 2,
                'description': 'Hello incident 2',
                'created_time': datetime.utcnow().strftime(DATE_FORMAT)
            }
        ]


def login(username: str, password: str, base_url: str, verify_certificate: bool = False) -> str:
    """
    login to checkpoint admin account using username and password.
    """
    return requests.post(base_url + 'login', headers={'Content-Type': 'application/json'}, verify=verify_certificate,
                         json={'user': username, 'password': password}).json().get('sid')


def logout(base_url: str, sid: str) -> str:
    """
    logout checkpoint admin account.
    """
    return requests.post(base_url + 'logout', headers={'Content-Type': 'application/json', 'X-chkp-sid': sid},
                         verify=False, json={}).json()


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Args:
        client (Client): CheckPoint client.
    Returns:
        str: 'ok' if test passed, anything else will fail the test.
    """

    return 'ok' if client.show_all_hosts() else 'Connection failed.'


def checkpoint_api_command(client: Client, command: str):
    sshArgs = {
        'using': f'{client.server}:{client.port}',
        'cmd': command
    }
    sshArg = {'cmd': 'show host names ipv4'}
    return demisto.executeCommand('ssh', sshArg)


def say_hello_command(client, args):
    """
    Returns Hello {somename}

    Args:
        client (Client): HelloWorld client.
        args (dict): all command arguments.

    Returns:
        Hello {someone}

        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs for other tasks in the
                 playbook
        raw_response (dict): Used for debugging/troubleshooting purposes - will be shown only if the command executed with
                      raw-response=true
    """
    name = args.get('name')

    result = client.say_hello(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = f'## {result}'
    outputs = {
        'hello': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def show_all_objects(result: dict, endpoint: str):
    # result = client.search_ip(args.get('ip'))
    outputs = {f'Checkpoint.{endpoint}': {
        'from': result.get('from'),
        'to': result.get('to'),
        'total': result.get('total'),
        'object-name': result.get('objects')[0].get('name'),
        'object-uid': result.get('objects')[0].get('uid'),
        'object-type': result.get('objects')[0].get('type'),
    }
    }

    table_data = outputs[f'Checkpoint.{endpoint}']
    readable_output = tableToMarkdown(f'CheckPoint Data for List {endpoint}s:', table_data,
                                      removeNull=True)
    return_outputs(readable_output, outputs, result)


def get_object(result: dict, endpoint: str):
    outputs = {f'checkpoint.{endpoint}': {
        'name': result.get('name'),
        'uid': result.get('uid'),
        'type': result.get('type'),
        'domain-name': result.get('domain').get('name'),
        'domain-uid': result.get('domain').get('uid'),
        'domain-type': result.get('domain').get('type'),
        'ipv4-address': result.get('ipv4-address'),
        'ipv6-address': result.get('ipv4-address'),
        'read-only': result.get('read-only'),
        'MetaInfo-creation-time': result.get('meta-info').get('creation-time').get('posix'),
        'MetaInfo-creator': result.get('meta-info').get('creator'),
        'MetaInfo-last-modifier': result.get('meta-info').get('last-modifier')
    }
    }
    table_data = outputs[f'checkpoint.{endpoint}']
    readable_output = tableToMarkdown(f'CheckPoint Data for Getting {endpoint}:', table_data,
                                      removeNull=True)
    return_outputs(readable_output, outputs, result)


def add_object(result: dict, endpoint: str):
    outputs = {f'Checkpoint.{endpoint}': {
        'name': result.get('name'),
        'uid': result.get('uid'),
        'type': result.get('type'),
        'domain-name': result.get('domain').get('name'),
        'domain-uid': result.get('domain').get('uid'),
        'domain-type': result.get('domain').get('type'),
        'ipv4-address': result.get('ipv4-address'),
        'ipv6-address': result.get('ipv4-address'),
        'read-only': result.get('read-only'),
    }
    }
    table_data = outputs[f'Checkpoint.{endpoint}']
    readable_output = tableToMarkdown(f'CheckPoint Data for adding {endpoint}:', table_data,
                                      removeNull=True)
    return_outputs(readable_output, outputs, result)


def delete_object(result: dict, endpoint: str):
    outputs = {f'Checkpoint.{endpoint}': {
        'message': result.get('message'),
    }
    }
    table_data = outputs[f'Checkpoint.{endpoint}']
    readable_output = tableToMarkdown(f'CheckPoint Data for deleting {endpoint}:', table_data,
                                      removeNull=True)
    return_outputs(readable_output, outputs, result)


def update_object(result: dict, endpoint: str):
    outputs = {f'Checkpoint.{endpoint}': {
        'name': result.get('name'),
        'uid': result.get('uid'),
        'type': result.get('type'),
        'domain-name': result.get('domain').get('name'),
        'domain-uid': result.get('domain').get('uid'),
        'domain-type': result.get('domain').get('type'),
        'ipv4-address': result.get('ipv4-address'),
        'ipv6-address': result.get('ipv4-address'),
        'total-number': result.get('total-number'),
    }
    }
    table_data = outputs[f'Checkpoint.{endpoint}']
    readable_output = tableToMarkdown(f'CheckPoint Data for updating {endpoint}:', table_data,
                                      removeNull=True)
    return_outputs(readable_output, outputs, result)


def main():
    server = demisto.params()['server']
    port = demisto.params()['port']
    base_url = f'https://{server}:{port}/web_api/'

    username = demisto.params().get('username')
    password = demisto.params().get('passworda').get('password')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    sid = login(username, password, base_url, verify_certificate)
    LOG(f'Logged in successfully.') if sid else LOG(f'OOPS! Could not login with given credentials.')
    LOG(f'Command being called is {demisto.command()}')

    client = Client(
        base_url=base_url,
        server=server,
        port=port,
        sid=sid,
        use_ssl=verify_certificate,
        use_proxy=proxy)

    command = demisto.command()
    commands = {
        'checkpoint-host-list': client.checkpoint_show_all_hosts,
        'checkpoint-host-get': client.checkpoint_show_host,
        'checkpoint-host-add': client.checkpoint_add_host,
        'checkpoint-host-update': client.checkpoint_update_host,
        'checkpoint-host-delete': client.checkpoint_delete_host,

        'checkpoint-group-list': client.checkpoint_show_all_groups,
        'checkpoint-group-get': client.checkpoint_show_group,
        'checkpoint-group-add': client.checkpoint_add_group,
        'checkpoint-group-update': client.checkpoint_update_group,
        'checkpoint-group-delete': client.checkpoint_delete_group,

        'checkpoint-address-range-list': client.checkpoint_show_all_address_ranges,
        'checkpoint-address-range-get': client.checkpoint_show_address_range,
        'checkpoint-address-range-add': client.checkpoint_add_address_range,
        'checkpoint-address-range-update': client.checkpoint_update_address_range,
        'checkpoint-address-range-delete': client.checkpoint_delete_address_range,

        'checkpoint-threat-indicator-list': client.checkpoint_show_all_threat_indicators,
        'checkpoint-threat-indicator-get': client.checkpoint_show_threat_indicator,
        'checkpoint-threat-indicator-add': client.checkpoint_add_threat_indicator,
        'checkpoint-threat-indicator-update': client.checkpoint_update_threat_indicator,
        'checkpoint-threat-indicator-delete': client.checkpoint_delete_threat_indicator,
    }

    try:
        if demisto.command() == 'test-module':
            # result = test_module(client)
            demisto.results(test_module(client))

        elif demisto.command() == 'checkpoint-command':
            demisto.results(checkpoint_api_command(client, **demisto.args()))

        elif command in commands:
            commands[demisto.command()](**demisto.args())

        # client.checkpoint_publish()
        logout(base_url, sid)

    except Exception as e:
        logout(base_url, sid)
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
