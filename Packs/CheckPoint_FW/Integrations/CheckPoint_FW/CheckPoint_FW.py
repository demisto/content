import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
from collections import defaultdict
import requests

# import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
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

    def checkpoint_show_access_rule(self, identifier, limit: int, offset: int):
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
        response = self._http_request(method='POST', url_suffix='show-access-rulebase',
                                      headers=self.headers, json_data=body)

        response['objects'] = response.pop('objects-dictionary')
        print(response)
        show_all_objects(response, 'rule')

    def checkpoint_add_rule(self, layer: str, position, name: str = None):
        """
        Add rule objects.

        Args:
            layer(str): Layer that the rule belongs to identified by the name or UID..
            position(int or str): IPosition in the rulebase.
                                  int - add rule at a specific position
                                  str - add rule at the position. vaild value: top, bottom
            name(str): rule name

        """
        body = {"layer": layer, "position": position, 'name': name}
        response = self._http_request(method='POST', url_suffix='add-access-rule',
                                      headers=self.headers, json_data=body)
        print(response)
        add_object(response, 'access-rule')

    def checkpoint_update_rule(self, identifier: str, layer: str, ignore_warnings: bool, ignore_errors: bool,
                               enabled: bool, action: str = None, new_name: str = None, new_position=None):
        """
        Edit existing rule object using object name or uid.

        Args:
            identifier: uid, name or rule-number.
            layer (str): Layer that the rule belongs to identified by the name or UID.
            enabled(bool): Enable/Disable the rule
            action (str): the action to set. available options:
            ignore_warnings(bool):Apply changes ignoring warnings.
            ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such a changes.
                                 If ignore-warnings flag was omitted - warnings will also be ignored.
                                "Accept", "Drop", "Ask", "Inform", "Reject", "User Auth", "Client Auth", "Apply Layer".
            new_name(str): New name of the object.
            new_position(int or str): New position in the rulebase.
                                    value can be int- add rule at the specific position
                                    value can be str- add rule at the position. valid values: top, bottom.
        """

        body = {'name': identifier,
                'layer': layer,
                'action': action,
                'enabled': enabled,
                'new-name': new_name,
                'new-position': new_position,
                'ignore-warnings': ignore_warnings,
                'ignore-errors': ignore_errors
                }
        response = self._http_request(method='POST', url_suffix='set-access-rule',
                                      headers=self.headers, json_data=body)
        update_access_rule_object(response, 'rule')

    def checkpoint_delete_rule(self, identifier):
        """
        Delete existing rule object using object name or uid.

        Args:
            identifier: uid, name or rule-number.

        """
        response = self._http_request(method='POST', url_suffix='delete-access-rule', headers=self.headers,
                                      json_data={'name': identifier})
        delete_object(response, 'rule')

    def checkpoint_show_all_hosts(self, limit: int, offset: int):
        """
        Retrieve all host objects.

        Args:
            limit(int): The maximal number of returned results. default is 50.
            offset(int): Number of the results to initially skip. default is 0.

        """

        body = {'limit': limit, 'offset': offset}
        response = self._http_request(method='POST', url_suffix='show-hosts', headers=self.headers,
                                      resp_type='json', json_data=body)
        show_all_objects(response, 'host')

    def checkpoint_show_host(self, identifier: str):
        """
        Show existing host object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        dictionary = {'name': identifier}
        response = self._http_request(method='POST', url_suffix='show-host', headers=self.headers,
                                      json_data=dictionary)
        print(response)
        get_object(response, 'host')

    def checkpoint_add_host(self, name: str, ip: str):
        """
        Add host objects.

        Args:
            name(str): Object name. Must be unique in the domain.
            ip(str): IPv4 or IPv6 address..

        """
        response = self._http_request(method='POST', url_suffix='add-host', headers=self.headers,
                                      json_data={"name": name, "ip-address": ip})
        add_object(response, 'add')

    def checkpoint_update_host(self, identifier, ignore_warnings: bool, ignore_errors: bool,
                               ip: str = None, new_name: str = None, comments: str = None):
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

    def checkpoint_delete_host(self, identifier: str):
        """
        Delete existing host object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        response = self._http_request(method='POST', url_suffix='delete-host', headers=self.headers,
                                      json_data={'name': identifier})
        delete_object(response, 'host')

    def checkpoint_show_all_groups(self, limit: int, offset: int):
        """
        Retrieve all group objects from checkpoint.

        Args:
            limit(int): The maximal number of returned results. default is 50.
            offset(int): Number of the results to initially skip. default is 0.
        """
        response = self._http_request(method='POST', url_suffix='show-groups', headers=self.headers,
                                      json_data={"limit": limit, "offset": offset})
        show_all_objects(response, 'group')

    def checkpoint_show_group(self, identifier):
        """
        Show existing group object using object name or uid.

        """
        response = self._http_request(method='POST', url_suffix='show-group', headers=self.headers,
                                      json_data={'name': identifier})
        get_object(response, 'group')

    def checkpoint_add_group(self, name: str):
        """
        add group objects.

        Args:
            name(str): Object name. Must be unique in the domain.

        """
        response = self._http_request(method='POST', url_suffix='add-group', headers=self.headers,
                                      json_data={"name": name})
        add_object(response, 'group')

    def checkpoint_update_group(self, identifier, ignore_warnings: bool, ignore_errors: bool,
                                new_name: str = None, comments: str = None):
        """
        Edit existing object using object name or uid.

        Args:
            identifier(str): uid or name.
            ignore_warnings(bool):Apply changes ignoring warnings.
            ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such a changes.
                                 If ignore-warnings flag was omitted - warnings will also be ignored.
            new_name(str): New name of the object.
            comments(str): Comments string.
        """
        body = {'name': identifier,
                'new-name': new_name,
                'comments': comments,
                'ignore-warnings': ignore_warnings,
                'ignore-errors': ignore_errors}
        response = self._http_request(method='POST', url_suffix='set-group', headers=self.headers,
                                      json_data=body)
        update_object(response, 'group')

    def checkpoint_delete_group(self, identifier: str):
        """
        Delete existing group object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        response = self._http_request(method='POST', url_suffix='delete-group', headers=self.headers,
                                      json_data={'name': identifier})
        delete_object(response, 'group')

    def checkpoint_show_all_address_ranges(self, limit: int, offset: int):
        """
        Retrieve all address range objects from checkpoint.

        Args:
            limit(int): The maximal number of returned results. default is 50.
            offset(int): Number of the results to initially skip. default is 0.
        """
        response = self._http_request(method='POST', url_suffix='show-address-ranges', headers=self.headers,
                                      json_data={"limit": limit, "offset": offset})
        show_all_objects(response, 'address range')

    def checkpoint_show_address_range(self, identifier):
        """
        Show existing address range object using object name or uid.

        Args:
            identifier(str): uid or name of the address range object.
        """
        # TODO: Fix output
        response = self._http_request(method='POST', url_suffix='show-address-range', headers=self.headers,
                                      json_data={'name': identifier})
        get_object(response, 'address range')

    def checkpoint_add_address_range(self, name: str, ip_address_first: str, ip_address_last: str, set_if_exists: bool,
                                     ignore_warnings: bool, ignore_errors: bool):
        """
        add address_range objects.

        Args:
            name(str): Object name. Must be unique in the domain.
            ip_address_first(str): First IP address in the range. IPv4 or IPv6 address.
            ip_address_last(str): Last IP address in the range. IPv4 or IPv6 address.
            set_if_exists(bool): If another object with the same identifier already exists, it will be updated.
            ignore_warnings(bool): Apply changes ignoring warnings.
            ignore_errors(bool): Apply changes ignoring errors
        """

        body = {'name': name,
                'ip-address-first': ip_address_first,
                'ip-address-last': ip_address_last,
                'set-if-exists': set_if_exists,
                'ignore-warnings': ignore_warnings,
                'ignore-errors': ignore_errors
                }
        response = self._http_request(method='POST', url_suffix='add-address-range', headers=self.headers,
                                      json_data=body)
        add_object(response, 'address range')

    def checkpoint_update_address_range(self, identifier, ignore_warnings: bool, ignore_errors: bool,
                                        first_ip: str = None, last_ip: str = None, new_name: str = None,
                                        comments: str = None):
        """
        Edit existing address_range object using object name or uid.

        Args:
            identifier(str): uid or name.

            ignore_warnings(bool):Apply changes ignoring warnings.
            ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such a changes.
                                 If ignore-warnings flag was omitted - warnings will also be ignored.
            first_ip(str): First IP address in the range. IPv4 or IPv6 address.
            last_ip(str): Last IP address in the range. IPv4 or IPv6 address.
            new_name(str): New name of the object.
            comments(str): Comments string.
        """
        body = {'name': identifier,
                'ip-address-first': first_ip,
                'ip-address-last': last_ip,
                'new-name': new_name,
                'comments': comments,
                'ignore-warnings': ignore_warnings,
                'ignore-errors': ignore_errors}

        response = self._http_request(method='POST', url_suffix='set-group', headers=self.headers,
                                      json_data=body)
        update_object(response, 'address range')

    def checkpoint_delete_address_range(self, identifier: str):
        """
        Delete existing address range object using object name or uid.

        Args:
            identifier(str): uid or name.
        Returns:
            Operation status.
        """
        response = self._http_request(method='POST', url_suffix='delete-address-range', headers=self.headers,
                                      json_data={'name': identifier})
        delete_object(response, 'address range')

    def checkpoint_show_all_threat_indicators(self, limit: int, offset: int):
        """
        Display a list of Threat-Indicators.

        Args:
            limit(int): The maximal number of returned results. default is 50.
            offset(int): Number of the results to initially skip. default is 0.
        """
        response = self._http_request(method='POST', url_suffix='show-threat-indicators', headers=self.headers,
                                      json_data={"limit": limit, "offset": offset})
        response['objects'] = response.pop('indicators')
        show_all_objects(response, 'threat indicator')

    def checkpoint_get_threat_indicator(self, identifier):
        """
        Show existing threat indicator using object name or uid.

        Args:
            identifier(str): uid or name.

        """
        response = self._http_request(method='POST', url_suffix='show-threat-indicator', headers=self.headers,
                                      json_data={'name': identifier})

        get_object(response, 'threat indicator')

    def checkpoint_add_threat_indicator(self, name: str, observables: list):
        """
        Create a new Threat-Indicator.

        Args:
            name(str): Object name. Must be unique in the domain.
            observables(list): The indicator's observables.

        """
        print("AM I HERE?")
        return_outputs(self._http_request(method='POST', url_suffix='add-threat-indicator', headers=self.headers,
                                          json_data={"name": name, "observables": observables}))

    def checkpoint_update_threat_indicator(self, identifier, action: str = None, new_name: str = None,
                                           comments: str = None):
        """
        Edit existing object using object name or uid.

        Args:
            identifier(str): uid or name.
            action (str): the action to set. available options:
                                "Accept", "Drop", "Ask", "Inform", "Reject", "User Auth", "Client Auth", "Apply Layer".
            new_name(str): New name of the object.
            comments(str): Comments string.
        """
        body = {'name': identifier,
                'action': action,
                'new-name': new_name,
                'comments': comments
                }
        response = self._http_request(method='POST', url_suffix='set-threat-indicator', headers=self.headers,
                                      json_data=body)
        update_object(response, 'threat indicator')

    def checkpoint_delete_threat_indicator(self, identifier: str):
        """
        Delete existing group object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        response = self._http_request(method='POST', url_suffix='delete-threat-indicator', headers=self.headers,
                                      json_data={'name': identifier})
        delete_object(response, 'threat indicator')

    def checkpoint_show_application_site(self, limit: int, offset: int):
        """
        Show all application sites.

        Args:
            limit(int): The maximal number of returned results.
            offset(int): Number of the results to initially skip.
        """

        body = {'limit': limit,
                'offset': offset}
        response = self._http_request(method='POST', url_suffix='show-application-sites',
                                      headers=self.headers, json_data=body)
        show_all_objects(response, 'application-site')

    def checkpoint_add_application_site(self, name: str, primary_category: str,  identifier):
        """
        Add application site objects.

        Args:
            name(str): Object name. Must be unique in the domain.
            primary_category(str): Each application is assigned to one primary category
                                    based on its most defining aspect.
            identifier(str): can be:
                                   url-list(str): URLs that determine this particular application.
                                   application-signature(str): Application signature generated by Signature Tool.

        """
        body = {"name": name, "primary-category": primary_category, 'url-list': identifier}
        response = self._http_request(method='POST', url_suffix='add-application-site',
                                      headers=self.headers, json_data=body)
        print(response)
        application_site_object(response, 'application-site')

    def checkpoint_update_application_site(self, identifier: str, urls_defined_as_regular_expression: bool,
                                           description: str = None, new_name: str = None, primary_category: str = None,
                                           application_signature: str = None):
        """
        Edit existing application site object using object name or uid.

        Args:
            identifier: uid or name.
            urls_defined_as_regular_expression(bool): States whether the URL is defined as a Regular Expression or not.
            description(str): A description for the application.
            new_name(str): New name of the object.
            primary_category (str): Each application is assigned to one primary category based on its
                                    most defining aspect
            application_signature(str): Application signature generated by Signature Tool
        """

        body = {'name': identifier,
                'application-signature': application_signature,
                'description': description,
                'new-name': new_name,
                'primary-category': primary_category,
                'primary_category': primary_category,
                'urls-defined-as-regular-expression': urls_defined_as_regular_expression,
                }
        response = self._http_request(method='POST', url_suffix='set-application-site',
                                      headers=self.headers, json_data=body)
        add_object(response, 'application-site')

    def checkpoint_delete_application_site(self, identifier: str):
        """
        Delete existing application site object using object name or uid.

        Args:
            identifier(str): uid or name.

        """

        response = self._http_request(method='POST', url_suffix='delete-application-site',
                                      headers=self.headers, json_data={'name': identifier})
        delete_object(response, 'application-site')

    def checkpoint_publish(self):
        """

        All the changes done by this user will be seen by all users only after publish is called.
        Args:
            uid(str): Session unique identifier.
        """
        return self._http_request(method='POST', url_suffix='publish', headers=self.headers,
                                  json_data={})


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


def test_module(base_url: str, sid: str) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    """
    response = requests.post(base_url + 'show-api-versions',
                             headers={'Content-Type': 'application/json', 'X-chkp-sid': sid},
                             verify=False, json={}).json()
    return 'ok' if response else f'Connection failed.{response}'


def checkpoint_api_command(client: Client, command: str) -> dict:
    """
        Creating API command directly to the server using SSH.

    Args:
        client (Client): Client.
        command (str): Command that the user wish to execute.
    Returns:
        dict: raw response from CheckPoint.
    """

    sshArgs = {
        'using': f'{client.server}:{client.port}',
        'cmd': command
    }
    sshArg = {'cmd': 'show host names ipv4'}
    try:
        print(type(demisto))
        print(type(demisto.executeCommand('ssh')))
        print("TEST")
        return demisto.executeCommand('ssh', sshArg)
    except Exception as e:
        print("lo")
        print(e)


def show_all_objects(result: dict, endpoint: str):
    """
        Formats all objects info from CheckPoint into Demisto's outputs.

    Args:
        result (dict): the report from CheckPoint.
        endpoint (str): The endpoint that needs to be formatted.
    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from X-Force Exchange (used for debugging).
    """

    if not result.get('objects'):
        return_outputs('No data to show.', {}, result)
        return

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
    """
        Formats object info from CheckPoint into Demisto's outputs.

    Args:
        result (dict): the report from CheckPoint.
        endpoint (str): The endpoint that needs to be formatted.
    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from X-Force Exchange (used for debugging).
    """

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
    """
        Formats adding object result from CheckPoint into Demisto's outputs.

    Args:
        result (dict): the report from CheckPoint.
        endpoint (str): The endpoint that needs to be formatted.
    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from X-Force Exchange (used for debugging).
    """
    common_outputs = {
        'name': result.get('name'),
        'uid': result.get('uid'),
        'type': result.get('type'),
        'domain-name': result.get('domain').get('name'),
        'domain-uid': result.get('domain').get('uid'),
        'domain-type': result.get('domain').get('type'),
        'Meta-info: creation time': result.get('meta-info').get('creation-time').get('posix'),
        'Meta-info: creator': result.get('meta-info').get('creator'),
        'Meta info: last modifier': result.get('meta-info').get('last-modifier')
    }
    unique_outputs = {}
    if endpoint == 'application-site':
        unique_outputs = {
            'application-id': result.get('application-id'),
            'description': result.get('description'),
            'url-list': result.get('url-list'),
        }
    elif endpoint == 'access-rule':
        unique_outputs = {
            'layer': result.get('layer'),
            'enabled': result.get('enabled'),
        }
    elif endpoint == 'address range':
        unique_outputs = {
            'ipv4-address-first': result.get('ipv4-address-first'),
            'ipv4-address-last': result.get('ipv4-address-last'),
            'ipv6-address-first': result.get('ipv6-address-first'),
            'ipv6-address-last': result.get('ipv6-address-last'),
            'read-only': result.get('read-only')
        }
    elif endpoint == 'group':
        if result.get('groups'):
            unique_outputs = {
                'groups-name': result.get('groups')[0]
            }
    elif endpoint == 'host':
        unique_outputs = {
            'ipv4-address': result.get('ipv4-address'),
            'ipv6-address': result.get('ipv4-address'),
            'read-only': result.get('read-only')
        }
    common_outputs.update(unique_outputs)
    outputs = {f'Checkpoint.{endpoint}': common_outputs}

    table_data = outputs[f'Checkpoint.{endpoint}']
    readable_output = tableToMarkdown(f'CheckPoint data for adding {endpoint}:', table_data,
                                      removeNull=True)
    return_outputs(readable_output, outputs, result)


def delete_object(result: dict, endpoint: str):
    """
        Formats deleted object result from CheckPoint into Demisto's outputs.

    Args:
        result (dict): the report from CheckPoint.
        endpoint (str): The endpoint that needs to be formatted.
    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from X-Force Exchange (used for debugging).
    """

    outputs = {f'Checkpoint.{endpoint}': {
        'message': result.get('message'),
    }
    }
    table_data = outputs[f'Checkpoint.{endpoint}']
    readable_output = tableToMarkdown(f'CheckPoint Data for deleting {endpoint}:', table_data,
                                      removeNull=True)
    return_outputs(readable_output, outputs, result)


def update_object(result: dict, endpoint: str):
    """
        Formats updated object result from CheckPoint into Demisto's outputs.

    Args:
        result (dict): the report from CheckPoint.
        endpoint (str): The endpoint that needs to be formatted.
    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from X-Force Exchange (used for debugging).
    """
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


def add_access_rule_object(result: dict, endpoint: str):
    """
        Formats adding object result from CheckPoint into Demisto's outputs.

    Args:
        result (dict): the report from CheckPoint.
        endpoint (str): The endpoint that needs to be formatted.
    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from X-Force Exchange (used for debugging).
    """

    outputs = {f'Checkpoint.{endpoint}': {
        'name': result.get('name'),
        'uid': result.get('uid'),
        'type': result.get('type'),
        'domain-name': result.get('domain').get('name'),
        'domain-uid': result.get('domain').get('uid'),
        'domain-type': result.get('domain').get('type'),
        'enabled': result.get('enabled'),
        'layer': result.get('layer'),
    }
    }
    table_data = outputs[f'Checkpoint.{endpoint}']
    readable_output = tableToMarkdown(f'CheckPoint Data for adding {endpoint}:', table_data,
                                      removeNull=True)
    return_outputs(readable_output, outputs, result)


def update_access_rule_object(result: dict, endpoint: str):
    """
        Formats updated object result from CheckPoint into Demisto's outputs.

    Args:
        result (dict): the report from CheckPoint.
        endpoint (str): The endpoint that needs to be formatted.
    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from X-Force Exchange (used for debugging).
    """
    outputs = {f'Checkpoint.{endpoint}': {
        'name': result.get('name'),
        'uid': result.get('uid'),
        'type': result.get('type'),
        'action name': result.get('action').get('name'),
        'action uid': result.get('action').get('uid'),
        'action type': result.get('action').get('type'),
        'action domain name': result.get('action').get('domain').get('name'),
        'content direction': result.get('content-direction'),
        'domain name': result.get('domain').get('name'),
        'domain uid': result.get('domain').get('uid'),
        'domain type': result.get('domain').get('type'),
        'enabled': result.get('enabled'),
        'layer': result.get('layer'),
        'Meta-info: creation time': result.get('meta-info').get('creation-time').get('posix'),
        'Meta-info: creator': result.get('meta-info').get('creator'),
        'Meta info: last modifier': result.get('meta-info').get('last-modifier')
    }
    }
    table_data = outputs[f'Checkpoint.{endpoint}']
    readable_output = tableToMarkdown(f'CheckPoint Data for updating {endpoint}:', table_data,
                                      removeNull=True)
    return_outputs(readable_output, outputs, result)


def application_site_object(result: dict, endpoint: str):
    """
        Formats adding object result from CheckPoint into Demisto's outputs.

    Args:
        result (dict): the report from CheckPoint.
        endpoint (str): The endpoint that needs to be formatted.
    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from X-Force Exchange (used for debugging).
    """

    outputs = {f'Checkpoint.{endpoint}': {
        'name': result.get('name'),
        'uid': result.get('uid'),
        'type': result.get('type'),
        'application ID': result.get('application-id'),
        'description': result.get('description'),
        'domain-name': result.get('domain').get('name'),
        'domain-uid': result.get('domain').get('uid'),
        'domain-type': result.get('domain').get('type'),
        'url-list': result.get('url-list'),
    }
    }
    table_data = outputs[f'Checkpoint.{endpoint}']
    readable_output = tableToMarkdown(f'CheckPoint Data for adding {endpoint}:', table_data,
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
        'checkpoint-threat-indicator-get': client.checkpoint_get_threat_indicator,
        'checkpoint-threat-indicator-add': client.checkpoint_add_threat_indicator,
        'checkpoint-threat-indicator-update': client.checkpoint_update_threat_indicator,
        'checkpoint-threat-indicator-delete': client.checkpoint_delete_threat_indicator,

        'checkpoint-access-rule-list': client.checkpoint_show_access_rule,
        'checkpoint-access-rule-add': client.checkpoint_add_rule,
        'checkpoint-access-rule-update': client.checkpoint_update_rule,
        'checkpoint-access-rule-delete': client.checkpoint_delete_rule,

        'checkpoint-application-site-list': client.checkpoint_show_application_site,
        'checkpoint-application-site-add': client.checkpoint_add_application_site,
        'checkpoint-application-site-update': client.checkpoint_update_application_site,
        'checkpoint-application-site-delete': client.checkpoint_delete_application_site,
    }

    try:
        if demisto.command() == 'test-module':
            # result = test_module(client)
            demisto.results(test_module(base_url, sid))

        elif demisto.command() == 'checkpoint-command':
            demisto.results(checkpoint_api_command(client, **demisto.args()))

        elif command in commands:
            commands[demisto.command()](**demisto.args())

        Client.checkpoint_publish(client)
        print("logging out...", logout(base_url, sid))

    except Exception as e:
        print("logging out...", logout(base_url, sid))
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
