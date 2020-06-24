import requests
from typing import Tuple, Dict, Any

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client for CheckPoint RESTful API.
    Args:
          base_url (str): the URL of CheckPoint.
          sid (str): CheckPoint session ID of the current user session.
          use_ssl (bool): specifies whether to verify the SSL certificate or not.
          use_proxy (bool): specifies if to use Demisto proxy settings.
    """

    def __init__(self, base_url: str, sid: str, use_ssl: bool, use_proxy: bool, **kwargs):
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy, **kwargs)
        self.headers = {'Content-Type': 'application/json',
                        'X-chkp-sid': sid}
        self.verify = use_ssl

    def logout(self):
        """logout from current session """
        return self._http_request(method='POST', url_suffix='logout', headers=self.headers,
                                  json_data={})

    def checkpoint_show_access_rule_command(self, identifier: str, limit: int, offset: int):
        """
        Show existing access rule base objects using object name or uid.

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
        return format_list_objects(response, 'access-rule')

    def checkpoint_add_rule_command(self, layer: str, position, name: str = None):
        """
        Add access rule object.

        Args:
            layer(str): Layer that the rule belongs to identified by the name or UID.
            position(int or str): IPosition in the rulebase.
                                  int - add rule at a specific position
                                  str - add rule at the position. vaild value: top, bottom
            name(str): rule name

        """
        body = {"layer": layer, "position": position, 'name': name}
        response = self._http_request(method='POST', url_suffix='add-access-rule',
                                      headers=self.headers, json_data=body)
        return format_add_object(response, 'access-rule')

    def checkpoint_update_rule_command(self, identifier: str, layer: str, ignore_warnings: bool,
                                       ignore_errors: bool, enabled: bool, action: str = None,
                                       new_name: str = None, new_position=None):
        """
        Edit existing access rule object using object name or uid.

        Args:
            identifier (str): uid, name or rule-number.
            layer (str): Layer that the rule belongs to identified by the name or UID.
            ignore_warnings(bool):Apply changes ignoring warnings.
            ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such
                                 a changes. If ignore-warnings flag was omitted- warnings will also
                                 be ignored
            enabled(bool): Enable/Disable the rule
            action (str): the action to set. available options:
                                        "Accept", "Drop", "Ask", "Inform", "Reject", "User Auth",
                                        "Client Auth", "Apply Layer".
            new_name(str): New name of the object.
            new_position(int or str): New position in the rulebase. value can be int or str:
                                    int- add rule at the specific position
                                    str- add rule at the position. valid values: top, bottom.
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
        return format_update_object(response, 'access-rule')

    def checkpoint_delete_rule_command(self, identifier: str):
        """
        Delete existing rule object using object name or uid.

        Args:
            identifier(str): uid, name or rule-number.

        """
        response = self._http_request(method='POST', url_suffix='delete-access-rule',
                                      headers=self.headers,
                                      json_data={'name': identifier})
        return format_delete_object(response, 'access-rule')

    def checkpoint_list_hosts_command(self, limit: int, offset: int):
        """
        Retrieve all host objects.

        Args:
            limit(int): The maximal number of returned results. default is 50.
            offset(int): Number of the results to initially skip. default is 0.

        """

        response = self._http_request(method='POST', url_suffix='show-hosts',
                                      headers=self.headers, resp_type='json',
                                      json_data={'limit': limit, 'offset': offset})
        return format_list_objects(response, 'host')

    def checkpoint_get_host_command(self, identifier: str):
        """
        Show existing host object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        body = {'name': identifier}
        response = self._http_request(method='POST', url_suffix='show-host', headers=self.headers,
                                      json_data=body)
        return format_get_object(response, 'host')

    def checkpoint_add_host_command(self, name: str, ip_address: str, groups):
        """
        Add host objects.

        Args:
            name(str): Object name. Must be unique in the domain.
            ip_address(str): IPv4 or IPv6 address.
            groups(str or list): Collection of group identifiers.

        """
        response = self._http_request(method='POST', url_suffix='add-host', headers=self.headers,
                                      json_data={"name": name, "ip-address": ip_address,
                                                 'groups': groups})
        return format_add_object(response, 'host')

    def checkpoint_update_host_command(self, identifier: str, ignore_warnings: bool,
                                       ignore_errors: bool, ip_address: str = None,
                                       new_name: str = None, comments: str = None):
        """
        Edit existing host object using object name or uid.

        Args:
            identifier(str): uid or name.
            ip_address(str): IPv4 or IPv6 address.
            ignore_warnings(bool):Apply changes ignoring warnings.
            ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such
                                 a changes. If ignore-warnings flag was omitted- warnings will also
                                 be ignored
            new_name(str): New name of the object.
            comments(str): Comments string.

        """
        body = {'name': identifier,
                'ip-address': ip_address,
                'new-name': new_name,
                'comments': comments,
                'ignore-warnings': ignore_warnings,
                'ignore-errors': ignore_errors
                }
        response = self._http_request(method='POST', url_suffix='set-host', headers=self.headers,
                                      json_data=body)
        return format_update_object(response, 'host')

    def checkpoint_delete_host_command(self, identifier: str):
        """
        Delete existing host object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        response = self._http_request(method='POST', url_suffix='delete-host', headers=self.headers,
                                      json_data={'name': identifier})
        return format_delete_object(response, 'host')

    def checkpoint_list_groups_command(self, limit: int, offset: int):
        """
        Retrieve all group objects from checkpoint.

        Args:
            limit(int): The maximal number of returned results. default is 50.
            offset(int): Number of the results to initially skip. default is 0.
        """
        response = self._http_request(method='POST', url_suffix='show-groups', headers=self.headers,
                                      json_data={"limit": limit, "offset": offset})
        return format_list_objects(response, 'group')

    def checkpoint_get_group_command(self, identifier: str):
        """
        Show existing group object using object name or uid.

        Args:
            identifier(str): name or uid.
        """
        response = self._http_request(method='POST', url_suffix='show-group', headers=self.headers,
                                      json_data={'name': identifier})
        return format_get_object(response, 'group')

    def checkpoint_add_group_command(self, name: str):
        """
        add group objects.

        Args:
            name(str): Object name. Must be unique in the domain.

        """
        response = self._http_request(method='POST', url_suffix='add-group', headers=self.headers,
                                      json_data={"name": name})
        return format_add_object(response, 'group')

    def checkpoint_update_group_command(self, identifier: str, ignore_warnings: bool,
                                        ignore_errors: bool,
                                        new_name: str = None, comments: str = None):
        """
        Edit existing object using object name or uid.

        Args:
            identifier(str): uid or name.
            ignore_warnings(bool):Apply changes ignoring warnings.
            ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such
                                 a changes.
                                 If ignore-warnings flag was omitted- warnings will also be ignored
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
        return format_update_object(response, 'group')

    def checkpoint_delete_group_command(self, identifier: str):
        """
        Delete existing group object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        response = self._http_request(method='POST', url_suffix='delete-group',
                                      headers=self.headers,
                                      json_data={'name': identifier})
        return format_delete_object(response, 'group')

    def checkpoint_list_address_ranges_command(self, limit: int, offset: int):
        """
        Retrieve all address range objects from checkpoint.

        Args:
            limit(int): The maximal number of returned results. default is 50.
            offset(int): Number of the results to initially skip. default is 0.
        """
        response = self._http_request(method='POST', url_suffix='show-address-ranges',
                                      headers=self.headers,
                                      json_data={"limit": limit, "offset": offset})
        return format_list_objects(response, 'address-range')

    def checkpoint_get_address_range_command(self, identifier: str):
        """
        Show existing address range object using object name or uid.

        Args:
            identifier(str): uid or name of the address range object.
        """
        response = self._http_request(method='POST', url_suffix='show-address-range',
                                      headers=self.headers, json_data={'name': identifier})
        return format_get_object(response, 'address-range')

    def checkpoint_add_address_range_command(self, name: str, ip_address_first: str,
                                             ip_address_last: str, set_if_exists: bool,
                                             ignore_warnings: bool, ignore_errors: bool):
        """
        add address_range objects.

        Args:
            name(str): Object name. Must be unique in the domain.
            ip_address_first(str): First IP address in the range. IPv4 or IPv6 address.
            ip_address_last(str): Last IP address in the range. IPv4 or IPv6 address.
            set_if_exists(bool): If another object with the same identifier already exists,
                                 it will be updated.
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
        response = self._http_request(method='POST', url_suffix='add-address-range',
                                      headers=self.headers, json_data=body)
        return format_add_object(response, 'address-range')

    def checkpoint_update_address_range_command(self, identifier: str, ignore_warnings: bool,
                                                ignore_errors: bool, ip_address_first: str = None,
                                                ip_address_last: str = None, new_name: str = None,
                                                comments: str = None):
        """
        Edit existing address_range object using object name or uid.

        Args:
            identifier(str): uid or name.
            ignore_warnings(bool):Apply changes ignoring warnings.
            ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such
                                a changes.
                                 If ignore-warnings flag was omitted- warnings will also be ignored
            ip_address_first(str): First IP address in the range. IPv4 or IPv6 address.
            ip_address_last(str): Last IP address in the range. IPv4 or IPv6 address.
            new_name(str): New name of the object.
            comments(str): Comments string.
        """
        body = {'name': identifier,
                'ip-address-first': ip_address_first,
                'ip-address-last': ip_address_last,
                'new-name': new_name,
                'comments': comments,
                'ignore-warnings': ignore_warnings,
                'ignore-errors': ignore_errors}

        response = self._http_request(method='POST', url_suffix='set-address-range',
                                      headers=self.headers, json_data=body)
        return format_update_object(response, 'address-range')

    def checkpoint_delete_address_range_command(self, identifier: str):
        """
        Delete existing address range object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        response = self._http_request(method='POST', url_suffix='delete-address-range',
                                      headers=self.headers,
                                      json_data={'name': identifier})
        return format_delete_object(response, 'address-range')

    def checkpoint_list_threat_indicators_command(self, limit: int, offset: int):
        """
        Display a list of Threat-Indicators.

        Args:
            limit(int): The maximal number of returned results. default is 50.
            offset(int): Number of the results to initially skip. default is 0.
        """
        response = self._http_request(method='POST', url_suffix='show-threat-indicators',
                                      headers=self.headers,
                                      json_data={"limit": limit, "offset": offset})
        response['objects'] = response.pop('indicators')
        return format_list_objects(response, 'threat-indicator')

    def checkpoint_get_threat_indicator_command(self, identifier):
        """
        Show existing threat indicator using object name or uid.

        Args:
            identifier(str): uid or name.

        """
        response = self._http_request(method='POST', url_suffix='show-threat-indicator',
                                      headers=self.headers,
                                      json_data={'name': identifier})

        return format_get_object(response, 'threat-indicator')

    def checkpoint_add_threat_indicator_command(self, name: str, observables: list):
        """
        Create new Threat-Indicator.

        Args:
            name(str): Object name. Must be unique in the domain.
            observables(list): The indicator's observables.
        """
        response = self._http_request(method='POST', url_suffix='add-threat-indicator',
                                      headers=self.headers,
                                      json_data={"name": name, "observables": observables})
        return format_add_object(response, 'threat-indicator')

    def checkpoint_update_threat_indicator_command(self, identifier: str, action: str = None,
                                                   new_name: str = None, comments: str = None):
        """
        Edit existing object using object name or uid.

        Args:
            identifier(str): uid or name.
            action (str): the action to set. available options:
                                "Accept", "Drop", "Ask", "Inform", "Reject", "User Auth",
                                "Client Auth", "Apply Layer".
            new_name(str): New name of the object.
            comments(str): Comments string.
        """
        body = {'name': identifier,
                'action': action,
                'new-name': new_name,
                'comments': comments
                }
        response = self._http_request(method='POST', url_suffix='set-threat-indicator',
                                      headers=self.headers, json_data=body)
        return format_update_object(response, 'threat-indicator')

    def checkpoint_delete_threat_indicator_command(self, identifier: str):
        """
        Delete existing group object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        response = self._http_request(method='POST', url_suffix='delete-threat-indicator',
                                      headers=self.headers,
                                      json_data={'name': identifier})
        return format_delete_object(response, 'threat-indicator')

    def checkpoint_list_application_sites_command(self, limit: int, offset: int):
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
        return format_list_objects(response, 'application-site')

    def checkpoint_add_application_site_command(self, name: str, primary_category: str, identifier):
        """
        Add application site objects.

        Args:
            name(str): Object name. Must be unique in the domain.
            primary_category(str): Each application is assigned to one primary category
                                    based on its most defining aspect.
            identifier(str or list): can be-
                                   url-list(str or list): URLs that determine this particular
                                                          application
                                   application-signature(str): Application signature generated by
                                                                Signature Tool.
        """
        body = {"name": name, "primary-category": primary_category, 'url-list': identifier}
        response = self._http_request(method='POST', url_suffix='add-application-site',
                                      headers=self.headers, json_data=body)
        return format_add_object(response, 'application-site')

    def checkpoint_update_application_site_command(self, identifier: str,
                                                   urls_defined_as_regular_expression: bool,
                                                   url_list=None,
                                                   description: str = None, new_name: str = None,
                                                   primary_category: str = None,
                                                   application_signature: str = None):
        """
        Edit existing application site object using object name or uid.

        Args:
            identifier: uid or name.
            url_list(str or list): URLs that determine this particular application.
                                    can be a string of a URL or a list of URLs.
            urls_defined_as_regular_expression(bool): States whether the URL is defined as a
                                                      Regular Expression or not.
            description(str): A description for the application.
            new_name(str): New name of the object.
            primary_category (str): Each application is assigned to one primary category based on
                                    its most defining aspect
            application_signature(str): Application signature generated by Signature Tool
        """

        body = {'name': identifier,
                'description': description,
                'new-name': new_name,
                'primary-category': primary_category,
                'urls-defined-as-regular-expression': urls_defined_as_regular_expression,
                'application-signature': application_signature,
                'url-list': url_list,
                }

        response = self._http_request(method='POST', url_suffix='set-application-site',
                                      headers=self.headers, json_data=body)
        return format_update_object(response, 'application-site')

    def checkpoint_delete_application_site_command(self, identifier: str):
        """
        Delete existing application site object using object name or uid.

        Args:
            identifier(str): uid or name.
        """
        response = self._http_request(method='POST', url_suffix='delete-application-site',
                                      headers=self.headers, json_data={'name': identifier})
        return format_delete_object(response, 'application-site')

    def checkpoint_publish_command(self):
        """
        publish changes.
        All the changes done by this user will be seen by all users only after publish is called.
        """
        return self._http_request(method='POST', url_suffix='publish', headers=self.headers,
                                  json_data={})

    def install_policy_command(self, policy_package: str, targets, access: bool):
        """
        installing policy.

        Args:
            policy_package(str): The name of the Policy Package to be installed.
            targets(str or list):On what targets to execute this command. Targets may be identified
                                by their name, or object unique identifier.
            access(bool): Set to be true in order to install the Access Control policy.
                            By default, the value is true if Access Control policy is enabled
                            on the input policy package, otherwise false.
        """
        body = {
            'policy-package': policy_package,
            'targets': targets,
            'access': access
        }
        return self._http_request(method='POST', url_suffix='install-policy',
                                  headers=self.headers, json_data=body)

    def verify_policy_command(self, policy_package: str):
        """
        Verifies the policy of the selected package.

        Args:
            policy_package(str): The name of the Policy Package to be installed.
        """
        body = {'policy-package': policy_package, }
        return self._http_request(method='POST', url_suffix='verify-policy',
                                  headers=self.headers, json_data=body)


def login(base_url: str, username: str, password: str, verify_certificate: bool) -> str:
    """
    login to checkpoint admin account using username and password.
    """
    return requests.post(base_url + 'login', verify=verify_certificate,
                         headers={'Content-Type': 'application/json'},
                         json={'user': username, 'password': password}).json().get('sid')


def test_module(base_url: str, sid: str, verify_certificate) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    """
    response = requests.post(base_url + 'show-api-versions',
                             headers={'Content-Type': 'application/json', 'X-chkp-sid': sid},
                             verify=verify_certificate, json={})
    reason = ''
    if response.json().get('message') == 'Missing header: [X-chkp-sid]':
        reason = ' Wrong credentials.'
    return 'ok' if response else f'Connection failed.{reason}\nFull response:\n{response.json()}'


def format_list_objects(result: dict, endpoint: str) -> Tuple[str, dict, dict]:
    """
        Formats all objects info from CheckPoint into Demisto's outputs.

    Args:
        result (dict): the report from CheckPoint.
        endpoint (str): The endpoint that needs to be formatted.
    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from CheckPoint (used for debugging).
    """
    printable_result = []

    object_list = result.get('objects')
    if not object_list:
        return 'No data to show.', {}, result

    for element in object_list:
        current_object_data = {'name': element.get('name'),
                               'uid': element.get('uid')}
        if endpoint != 'access-rule':
            current_object_data['type'] = element.get('type')

        printable_result.append(current_object_data)

    outputs = {f'CheckPoint.{endpoint}(val.uid && val.uid == obj.uid)': printable_result}
    readable_output = tableToMarkdown(f'CheckPoint data for listing {endpoint}s:', printable_result,
                                      ['name', 'uid', 'type'], removeNull=True)
    return readable_output, outputs, result


def format_get_object(result: dict, endpoint: str) -> Tuple[str, dict, dict]:
    """
        Formats object info from CheckPoint into Demisto's outputs.

    Args:
        result (dict): the report from CheckPoint.
        endpoint (str): The endpoint that needs to be formatted.
    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from CheckPoint (used for debugging).
    """
    if not result:
        return 'No data to show.', {}, result

    outputs = {f'checkpoint.{endpoint}(val.uid && val.uid == obj.uid)': {
        'name': result.get('name'),
        'uid': result.get('uid'),
        'type': result.get('type'),
        'ipv4_address': result.get('ipv4-address'),
        'ipv6_address': result.get('ipv4-address'),
        'read_only': result.get('read-only'),
    }}

    if result.get('domain'):
        outputs.update({
            'domain-name': result.get('domain').get('name'),
            'domain-uid': result.get('domain').get('uid'),
            'domain-type': result.get('domain').get('type'),
        })
    if result.get('meta-info'):
        outputs.update({
            'creator': result.get('meta-info').get('creator'),
            'last_modifier': result.get('meta-info').get('last-modifier')
        })

    table_data = outputs[f'CheckPoint.{endpoint}(val.uid && val.uid == obj.uid)']
    readable_output = tableToMarkdown(f'CheckPoint Data for Getting {endpoint}:', table_data,
                                      removeNull=True)

    return readable_output, outputs, result


def format_add_object(result: dict, endpoint: str) -> Tuple[str, dict, dict]:
    """
        Formats adding object result from CheckPoint into Demisto's outputs.

    Args:
        result (dict): the report from CheckPoint.
        endpoint (str): The endpoint that needs to be formatted.
    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from CheckPoint (used for debugging).
    """
    if not result:
        return 'No data to show.', {}, result

    common_output = {
        'name': result.get('name'),
        'uid': result.get('uid'),
        'type': result.get('type'),
    }

    if result.get('domain'):
        common_output.update({
            'domain-name': result.get('domain').get('name'),
            'domain-uid': result.get('domain').get('uid'),
            'domain-type': result.get('domain').get('type'),
        })

    if result.get('meta-info'):
        common_output.update({
            'creator': result.get('meta-info').get('creator'),
            'last_modifier': result.get('meta-info').get('last-modifier'),
        })
    if result.get('groups'):
        group_list = []
        for group in result.get('groups'):
            group_list.append(group.get('name'))
        common_output['groups'] = group_list

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

    common_output.update(unique_outputs)

    outputs = {f'CheckPoint.{endpoint}(val.uid && val.uid == obj.uid)': common_output}
    readable_output = tableToMarkdown(f'CheckPoint data for adding {endpoint}:', common_output,
                                      removeNull=True)
    return readable_output, outputs, result


def format_update_object(result: dict, endpoint: str) -> Tuple[str, dict, dict]:
    """
        Formats updated object result from CheckPoint into Demisto's outputs.

    Args:
        result (dict): the report from CheckPoint.
        endpoint (str): The endpoint that needs to be formatted.

    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from CheckPoint (used for debugging).
    """
    if not result:
        return 'No data to show.', {}, result

    output = {
        'name': result.get('name'),
        'uid': result.get('uid'),
        'type': result.get('type'),
        'ipv4-address': result.get('ipv4-address'),
        'ipv6-address': result.get('ipv4-address'),
        'total-number': result.get('total-number'),
    }
    if result.get('domain'):
        output.update({
            'domain-name': result.get('domain').get('name'),
            'domain-uid': result.get('domain').get('uid'),
            'domain-type': result.get('domain').get('type'),
        })

    outputs = {f'CheckPoint.{endpoint}(val.uid && val.uid == obj.uid)': output}
    readable_output = tableToMarkdown(f'CheckPoint Data for updating {endpoint}:', output,
                                      removeNull=True)
    return readable_output, outputs, result


def format_delete_object(result: dict, endpoint: str) -> Tuple[str, dict, dict]:
    """
        Formats deleted object result from CheckPoint into Demisto's outputs.

    Args:
        result (dict): the report from CheckPoint.
        endpoint (str): The endpoint that needs to be formatted.
    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from CheckPoint (used for debugging).
    """
    if not result:
        return 'No data to show.', {}, result

    outputs = {f'CheckPoint.{endpoint}(val.uid && val.uid == obj.uid)': {
        'message': result.get('message'),
    }}
    table_data = outputs[f'CheckPoint.{endpoint}(val.uid && val.uid == obj.uid)']
    readable_output = tableToMarkdown(f'CheckPoint Data for deleting {endpoint}:', table_data,
                                      removeNull=True)
    return readable_output, outputs, result


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('username', {}).get('identifier')
    password = params.get('username', {}).get('password')

    server = params['server']
    port = params['port']
    base_url = f'https://{server}:{port}/web_api/'

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    sid = login(base_url, username, password, verify_certificate)
    demisto.info(f'Command being called is {demisto.command()}')

    client = Client(
        base_url=base_url,
        sid=sid,
        use_ssl=verify_certificate,
        use_proxy=proxy)

    command = demisto.command()
    commands = {
        'checkpoint-host-list': client.checkpoint_list_hosts_command,
        'checkpoint-host-get': client.checkpoint_get_host_command,
        'checkpoint-host-add': client.checkpoint_add_host_command,
        'checkpoint-host-update': client.checkpoint_update_host_command,
        'checkpoint-host-delete': client.checkpoint_delete_host_command,

        'checkpoint-group-list': client.checkpoint_list_groups_command,
        'checkpoint-group-get': client.checkpoint_get_group_command,
        'checkpoint-group-add': client.checkpoint_add_group_command,
        'checkpoint-group-update': client.checkpoint_update_group_command,
        'checkpoint-group-delete': client.checkpoint_delete_group_command,

        'checkpoint-address-range-list': client.checkpoint_list_address_ranges_command,
        'checkpoint-address-range-get': client.checkpoint_get_address_range_command,
        'checkpoint-address-range-add': client.checkpoint_add_address_range_command,
        'checkpoint-address-range-update': client.checkpoint_update_address_range_command,
        'checkpoint-address-range-delete': client.checkpoint_delete_address_range_command,

        'checkpoint-threat-indicator-list': client.checkpoint_list_threat_indicators_command,
        'checkpoint-threat-indicator-get': client.checkpoint_get_threat_indicator_command,
        'checkpoint-threat-indicator-add': client.checkpoint_add_threat_indicator_command,
        'checkpoint-threat-indicator-update': client.checkpoint_update_threat_indicator_command,
        'checkpoint-threat-indicator-delete': client.checkpoint_delete_threat_indicator_command,

        'checkpoint-access-rule-list': client.checkpoint_show_access_rule_command,
        'checkpoint-access-rule-add': client.checkpoint_add_rule_command,
        'checkpoint-access-rule-update': client.checkpoint_update_rule_command,
        'checkpoint-access-rule-delete': client.checkpoint_delete_rule_command,

        'checkpoint-application-site-list': client.checkpoint_list_application_sites_command,
        'checkpoint-application-site-add': client.checkpoint_add_application_site_command,
        'checkpoint-application-site-update': client.checkpoint_update_application_site_command,
        'checkpoint-application-site-delete': client.checkpoint_delete_application_site_command,
    }

    is_test_module_command = False
    try:
        if demisto.command() == 'test-module':
            is_test_module_command = True
            demisto.results(test_module(base_url, sid, verify_certificate))

        elif command == 'checkpoint-publish':
            return_outputs(client.checkpoint_publish_command())

        elif command == 'checkpoint-install-policy':
            return_outputs(client.install_policy_command(**demisto.args()))

        elif command == 'checkpoint-verify-policy':
            return_outputs(client.verify_policy_command(**demisto.args()))

        elif command in commands:
            readable_output, outputs, result = \
                (commands[demisto.command()](**demisto.args()))  # type: ignore
            return_outputs(readable_output, outputs, result)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')

    finally:
        if not is_test_module_command:
            demisto.debug("logging out...", client.logout())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
