import requests

import demistomock as demisto
from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
BASIC_FIELDS = ['name', 'id', 'type', 'protocol', 'method', 'actAsMethod', 'serverTechnologyName',
                'selfLink', 'queryStringLength', 'checkRequestLength', 'enforcementType',
                'ipAddress', 'ipMask', 'blockRequests', 'ignoreAnomalies', 'neverLogRequests',
                'neverLearnRequests', 'trustedByPolicyBuilder', 'includeSubdomains',
                'description', 'mandatoryBody', 'clickjackingProtection', 'attackSignaturesCheck',
                'metacharElementCheck', 'hasValidationFiles', 'followSchemaLinks', 'isBase64',
                'enableWSS', 'dataType', 'valueType', 'mandatory', 'isCookie', 'isHeader',
                'performStaging', 'active', 'allowed', 'isAllowed', 'createdBy', 'lastUpdateMicros']

BASIC_OBJECT_FIELDS = ['name', 'id', 'type', 'protocol', 'method', 'actAsMethod',
                       'serverTechnologyName', 'selfLink',
                       'queryStringLength', 'checkRequestLength', 'responseCheck', 'urlLength',
                       'checkUrlLength', 'postDataLength', 'enforcementType', 'isBase64',
                       'description', 'includeSubdomains', 'clickjackingProtection',
                       'ipAddress', 'ipMask', 'blockRequests', 'ignoreAnomalies',
                       'neverLogRequests', 'neverLearnRequests', 'trustedByPolicyBuilder',
                       'dataType', 'attackSignaturesCheck', 'metacharElementCheck',
                       'hasValidationFiles', 'followSchemaLinks', 'isBase64',
                       'enableWSS', 'valueType', 'mandatory', 'isCookie', 'isHeader',
                       'includeSubdomains', 'createdBy', 'performStaging', 'allowed', 'isAllowed',
                       'createdBy', 'lastUpdateMicros']


class Client(BaseClient):
    """
    Client for f5 RESTful API!.
    Args:
          base_url (str): f5 server url.
          token (str): f5 user token.
          use_ssl (bool): specifies whether to verify the SSL certificate or not.
          use_proxy (bool): specifies if to use Demisto proxy settings.
    """

    def __init__(self, base_url: str, token: str, use_ssl: bool, use_proxy: bool, **kwargs):
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy, **kwargs)
        self.headers = {'Content-Type': 'application/json',
                        'X-F5-Auth-Token': token}

    def get_id(self, md5: str, method_name: str, action: str, compare_value: str = 'name'):
        """
            Get the ID of a specific element (similar to getting the ID of the policy).

            Args:
                md5(str): MD5 hash of the policy the element is a member of.
                method_name (str): Name of the element the ID is from.
                action(str): endpoint where the element resides.
                compare_value(str): Dict field to compare values in (name, ipAddress etc).

            Returns:
                str: MD5 hash (can also be called ID) of the element.
        """
        url_suffix = 'asm/server-technologies' if action == 'server-technologies-general' \
            else f'asm/policies/{md5}/{action}'
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params={})
        index = -1
        for element in response.get('items'):
            if action == 'server-technologies':
                server_tech_reference = element.get('serverTechnologyReference')
                if server_tech_reference:
                    server_tech_name = server_tech_reference.get('serverTechnologyName')
                    if server_tech_name == method_name:
                        index = response.get('items').index(element)
            else:
                if element.get(compare_value) == method_name:
                    index = response.get('items').index(element)
        if index == -1:
            return method_name
        return (response.get('items')[index]).get('id')

    def get_policy_self_link(self, policy_md5):
        """
        Returns policy self link.

        Args:
            policy_md5 (str): MD5 hash of the policy.

        Returns:
            str: MD5 hash of the policy (can also be called the policy ID).
        """
        response = self._http_request(method='GET', url_suffix='asm/policies',
                                      headers=self.headers,
                                      params={'items': [{'name': policy_md5}]})
        return response.get('selfLink')

    def f5_get_policy_md5_command(self, policy_name: str):
        """
            Get the MD5 hash of a policy that can be accessed in the API.

            Args:
                policy_name (str): Name of the policy to get a hash for.

            Returns:
                str: MD5 hash of the policy (can also be called the policy ID).
        """
        response = self._http_request(method='GET', url_suffix='asm/policies',
                                      headers=self.headers, params={})
        index = -1
        for element in response.get('items'):
            if element.get('name') == policy_name:
                index = response.get('items').index(element)
        response = (response.get('items')[index].get('plainTextProfileReference').get('link'))
        if index < 0:
            md5_dict = {}
        else:
            md5 = response.partition('policies/')[2].partition('/')[0]
            md5_dict = {'md5': md5}
        return format_policy_md5(md5_dict)

    def f5_list_policies_command(self, self_link: str = "", kind: str = "", items=None):
        """
        Lists all policies in the current server.

        Args:
            self_link(str): A link to this resource.
            kind(str): A unique type identifier.
            items(list): items

        Returns:
            dict: response dictionary
        """
        if not items:
            items = []
        response = self._http_request(method='GET', url_suffix='asm/policies',
                                      headers=self.headers, params={"selfLink": self_link,
                                                                    "kind": kind, "items": items})
        return format_list_policies(response)

    def f5_create_policy_command(self, name: str, kind: str, enforcement_mode: str,
                                 protocol_independent: bool, parent: str = None,
                                 description: str = None):
        """
        Creates a new ASM policy.

        Args:
            name (str): Name of the new policy.
            kind(str): Parent / Child.
            enforcement_mode(str): Transparent / Blocking.
            protocol_independent(bool): Is the policy independent from protocols.
            parent(str): If child, specify the parent.
            description (str): Optional description.
        """
        body = {'name': name, 'description': description, 'enforcementMode': enforcement_mode,
                'protocolIndependent': protocol_independent}
        if kind == 'parent':
            body.update({'type': 'parent'})
        else:
            body.update({'parentPolicyName': parent})
        response = self._http_request(method='POST', url_suffix='asm/policies',
                                      headers=self.headers, json_data=body)
        return format_create_policy(response)

    def f5_apply_policy_command(self, policy_reference_link: str):
        """
        Apply a policy.

        Args:
            policy_reference_link(str): link to the policy the user wish to apply.
        """
        body = {'policyReference': {'link': policy_reference_link}}
        response = self._http_request(method='POST', url_suffix='asm/tasks/apply-policy',
                                      headers=self.headers, json_data=body)
        return format_apply_policy(response)

    def f5_export_policy_command(self, filename: str, minimal: bool,
                                 policy_reference_link: str):
        """
        Export a policy.

        Args:
            filename (str): name of the file to export to.
            policy_reference_link(str): link to policy user wishes to export
            minimal(bool):Indicates whether to export only custom settings.
        """
        body = {'filename': filename, 'minimal': minimal,
                'policyReference': {'link': policy_reference_link}}
        response = self._http_request(method='POST', url_suffix='asm/tasks/export-policy',
                                      headers=self.headers, json_data=body)
        return format_export_policy(response)

    def f5_delete_policy_command(self, policy_md5: str):
        """
        Delete a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
        """
        response = self._http_request(method='DELETE', url_suffix=f'asm/policies/{policy_md5}',
                                      headers=self.headers, json_data={})
        return format_delete_policy(response)

    def f5_list_policy_methods_command(self, policy_md5: str):
        """
        Get a list of all policy methods.

        Args:
            policy_md5 (str): MD5 hash of the policy.

        Returns:
            dict: the report from f5.
        """
        response = self._http_request(method='GET', headers=self.headers, json_data={},
                                      url_suffix=f'asm/policies/{policy_md5}/methods')
        return format_list_policy_functions(response, 'PolicyMethods')

    def f5_add_policy_method_command(self, policy_md5: str, new_method_name: str,
                                     act_as_method: str):
        """
        Add allowed method to a certain policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            new_method_name (str): Display name of the new method.
            act_as_method(str): functionality of the new method. default is GET.
        """
        body = {'name': new_method_name, 'actAsMethod': act_as_method.upper()}
        response = self._http_request(method='POST', headers=self.headers, json_data=body,
                                      url_suffix=f'asm/policies/{policy_md5}/methods')
        return format_policy_object(response, 'PolicyMethods')

    def f5_update_policy_method_command(self, policy_md5: str, method_name: str,
                                        act_as_method: str):
        """
        Update allowed method from a certain policy..

        Args:
            policy_md5 (str): MD5 hash of the policy.
            method_name (str): Display name of the method.
            act_as_method(str): functionality of the new method.
        """
        method_id = self.get_id(policy_md5, method_name, 'methods')
        body = {'name': method_name, 'actAsMethod': act_as_method.upper()}

        response = self._http_request(method='PATCH', headers=self.headers, json_data=body,
                                      url_suffix=f'asm/policies/{policy_md5}/methods/{method_id}')
        return format_policy_object(response, 'PolicyMethods')

    def f5_delete_policy_method_command(self, policy_md5: str, method_name: str):
        """
        Add allowed method to a certain policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            method_name (str): Display name of the method.
        """
        method_id = self.get_id(policy_md5, method_name, 'methods')
        response = self._http_request(method='DELETE', headers=self.headers, json_data={},
                                      url_suffix=f'asm/policies/{policy_md5}/methods/{method_id}')
        return format_policy_object(response, 'PolicyMethods')

    def f5_list_policy_file_types_command(self, policy_md5: str):
        """
        Lists the file types that are allowed or disallowed in the security policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
        """
        response = self._http_request(method='GET', headers=self.headers, json_data={},
                                      url_suffix=f'asm/policies/{policy_md5}/filetypes')
        return format_list_policy_functions(response, 'FileType')

    def f5_add_policy_file_type_command(self, policy_md5: str, new_file_type: str,
                                        query_string_length: int,
                                        check_post_data_length: bool, response_check: bool,
                                        check_request_length: bool, post_data_length: int,
                                        perform_staging: bool):
        """
        Add allowed file types to a certain policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            new_file_type(str): The new file type to add.
            query_string_length(int): Query string length. default is 100.
            check_post_data_length(bool): indicates if the user wishes check the length of
                                            data in post method. default is True.
            response_check(bool): Indicates if the user wishes to check the response.
            check_request_length(bool): Indicates if the user wishes to check the request length.
            post_data_length(int): post data length.
            perform_staging (bool): Indicates if the user wishes the new file type to be at staging.
        """
        body = {'name': new_file_type,
                'queryStringLength': query_string_length,
                'checkPostDataLength': check_post_data_length,
                'responseCheck': response_check,
                'checkRequestLength': check_request_length,
                'postDataLength': post_data_length,
                'performStaging': perform_staging}

        response = self._http_request(method='POST', headers=self.headers, json_data=body,
                                      url_suffix=f'asm/policies/{policy_md5}/filetypes')
        return format_policy_object(response, 'FileType')

    def f5_update_policy_file_type_command(self, policy_md5: str, file_type_name: str,
                                           query_string_length: int,
                                           check_post_data_length: bool, response_check: bool,
                                           check_request_length: bool, post_data_length: int,
                                           perform_staging: bool):
        """
        Update a given file type from a certain policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            file_type_name (str): The new file type to add.
            query_string_length(int): Query string length. default is 100.
            check_post_data_length(bool): indicates if the user wishes check the length of
                                            data in post method. default is True.
            response_check(bool): Indicates if the user wishes to check the response.
            check_request_length(bool): Indicates if the user wishes to check the request length.
            post_data_length(int): post data length.
            perform_staging (bool): Indicates if the user wishes the new file type to be at staging.
        """
        file_type_id = self.get_id(policy_md5, file_type_name, 'filetypes')
        body = {'name': file_type_name,
                'queryStringLength': query_string_length,
                'checkPostDataLength': check_post_data_length,
                'responseCheck': response_check,
                'checkRequestLength': check_request_length,
                'postDataLength': post_data_length,
                'performStaging': perform_staging}

        response = self._http_request(method='PATCH', headers=self.headers, json_data=body,
                                      url_suffix=f'asm/policies/{policy_md5}/filetypes/{file_type_id}')
        return format_policy_object(response, 'FileType')

    def f5_delete_policy_file_type_command(self, policy_md5: str, file_type_name: str):
        """
        Add allowed method to a certain policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            file_type_name (str): The new file type to delete.
        """
        file_type_id = self.get_id(policy_md5, file_type_name, 'filetypes')
        url_suffix = f'asm/policies/{policy_md5}/filetypes/{file_type_id}'
        response = self._http_request(method='DELETE', headers=self.headers, json_data={},
                                      url_suffix=url_suffix)
        return format_policy_object(response, 'FileType')

    def f5_list_policy_hostnames_command(self, policy_md5: str):
        """
            List all hostnames from a selected policy.

            Args:
                policy_md5 (str): MD5 hash of the policy.
        """
        response = self._http_request(method='GET', headers=self.headers, json_data={},
                                      url_suffix=f'asm/policies/{policy_md5}/host-names')
        return format_list_policy_functions(response, 'Hostname')

    def f5_add_policy_hostname_command(self, policy_md5: str, name: str,
                                       include_subdomains: bool):
        """
        Add a hostname to a selected policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of thr new host to add.
            include_subdomains (bool): Indicates whether or not to include subdomains.
        """
        data = {'name': name, 'includeSubdomains': include_subdomains}
        response = self._http_request(method='POST', headers=self.headers, json_data=data,
                                      url_suffix=f'asm/policies/{policy_md5}/host-names')
        return format_policy_object(response, 'Hostname')

    def f5_update_policy_hostname_command(self, policy_md5: str, name: str,
                                          include_subdomains: bool):
        """
        Update a hostname in a selected policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Host name to update.
            include_subdomains (bool): Indicates whether or not to include subdomains.
        """
        hostname_id = self.get_id(policy_md5, name, 'host-names')
        url_suffix = f'asm/policies/{policy_md5}/host-names/{hostname_id}'
        response = self._http_request(method='PATCH', headers=self.headers, url_suffix=url_suffix,
                                      json_data={'includeSubdomains': include_subdomains})
        return format_policy_object(response, 'Hostname')

    def f5_delete_policy_hostname_command(self, policy_md5: str, name: str):
        """
        Delete a hostname from a selected policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Host name to delete.
        """
        hostname_id = self.get_id(policy_md5, name, 'host-names')
        url_suffix = f'asm/policies/{policy_md5}/host-names/{hostname_id}'
        response = self._http_request(method='DELETE', headers=self.headers, url_suffix=url_suffix)
        return format_policy_object(response, 'Hostname')

    def f5_list_policy_blocking_settings_command(self, policy_md5: str, endpoint: str):
        """
        List a Blocking Settings element of a selected policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            endpoint (str): Sub-path of the wanted Blocking Settings endpoint.
        """
        response = self._http_request(method='GET', headers=self.headers,
                                      url_suffix=f'asm/policies/{policy_md5}/blocking-settings/{endpoint}')
        return format_policy_blocking_settings_list_command(response, endpoint)

    def f5_update_policy_blocking_setting_command(self, policy_md5: str, endpoint: str,
                                                  description: str, enabled: bool = None,
                                                  learn: bool = None, alarm: bool = None,
                                                  block: bool = None):
        """
        Update a specific Blocking Setting element of a certain policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            endpoint (str): Sub-path of the wanted Blocking Settings endpoint.
            description (str): Since there is no name, use description instead.
            enabled (bool): If possible, enable the element.
            learn (bool): If possible, have the element learn.
            alarm (bool): If possible, have the element alarm.
            block (bool): If possible, have the element block.
        """
        endpoint = 'blocking-settings/' + endpoint
        blocking_settings_id = self.get_id(policy_md5, action=endpoint, method_name=description,
                                           compare_value='description')
        json_body = {'enabled': enabled, 'learn': learn, 'alarm': alarm, 'block': block}
        json_body = {key: value for key, value in json_body.items() if value is not None}

        url_suffix = f'asm/policies/{policy_md5}/{endpoint}/{blocking_settings_id}'
        response = self._http_request(method='PATCH', url_suffix=url_suffix,
                                      headers=self.headers, json_data=json_body)
        return format_policy_blocking_settings_update_command(response, endpoint)

    def f5_list_policy_urls_command(self, policy_md5: str):
        """
        Get a list of all URLs of a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
        """
        response = self._http_request(method='GET', headers=self.headers, json_data={},
                                      url_suffix=f'asm/policies/{policy_md5}/urls')
        return format_list_policy_functions(response, 'Url')

    def f5_add_policy_url_command(self, policy_md5: str, name: str, protocol: str,
                                  url_type: str, is_allowed: bool, description: str = None,
                                  perform_staging: bool = None,
                                  clickjacking_protection: bool = None, method: str = None):
        """
        Create a new URL in a selected policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of the new URL.
            description (str): Optional descrption for the URL.
            method(str): Method to be used in the.
            protocol(str): HTTP or HTTPS
            url_type(str): Explicit or wildcard.
            is_allowed(bool): Whether or not the URL is allowed.
            clickjacking_protection(bool): Whether or not to enable clickjacking protection.
            perform_staging (bool): Whether or not to stage the URL.
        """
        json_body = {'name': name, 'protocol': protocol, 'description': description,
                     'method': method, 'type': url_type, 'isAllowed': is_allowed,
                     'clickjackingProtection': clickjacking_protection,
                     'performStaging': perform_staging}
        json_body = {key: value for key, value in json_body.items() if value is not None}

        response = self._http_request(method='POST', headers=self.headers, json_data=json_body,
                                      url_suffix=f'asm/policies/{policy_md5}/urls')
        return format_policy_object(response, 'Url')

    def f5_update_policy_url_command(self, policy_md5: str, name: str, perform_staging=None,
                                     description=None, mandatory_body=None,
                                     url_isreferrer=None):
        """
        Update an existing URL in a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of the URL to update.
            perform_staging (bool): Whether or not to stage the URL.
            description (str): Optional new description.
            mandatory_body(bool): Whether or not the body is mandatory
            url_isreferrer(bool): Whether or not the URL is a referrer.
        """
        url_id = self.get_id(policy_md5, name, 'urls')
        json_body = {'performStaging': perform_staging,
                     'description': description,
                     'mandatoryBody': mandatory_body,
                     'urlIsReferrer': url_isreferrer}

        json_body = {key: value for key, value in json_body.items() if value is not None}
        response = self._http_request(method='PATCH', headers=self.headers, json_data=json_body,
                                      url_suffix=f'asm/policies/{policy_md5}/urls/{url_id}')

        return format_policy_object(response, 'Url')

    def f5_delete_policy_url_command(self, policy_md5: str, name: str):
        """
        Delete an existing URL in a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of the URL to delete.
        """
        url_id = self.get_id(policy_md5, name, 'urls')
        response = self._http_request(method='DELETE', headers=self.headers, json_data={},
                                      url_suffix=f'asm/policies/{policy_md5}/urls/{url_id}')
        return format_policy_object(response, 'Url')

    def f5_list_policy_cookies_command(self, policy_md5: str):
        """
        Lists the file types that are allowed or disallowed in the security policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
        """
        response = self._http_request(method='GET', headers=self.headers, json_data={},
                                      url_suffix=f'asm/policies/{policy_md5}/cookies')
        return format_list_policy_functions(response, 'Cookies')

    def f5_add_policy_cookie_command(self, policy_md5: str, new_cookie_name: str,
                                     perform_staging: bool):
        """
        Add new cookie to a specific policy

        Args:
            policy_md5 (str): MD5 hash of the policy.
            new_cookie_name (str): The new cookie name to add.
            perform_staging (bool): Indicates if the user wishes the new file type to be at staging.
        """
        body = {'name': new_cookie_name, 'performStaging': perform_staging}
        response = self._http_request(method='POST', headers=self.headers, json_data=body,
                                      url_suffix=f'asm/policies/{policy_md5}/cookies')
        return format_policy_object(response, 'Cookies')

    def f5_update_policy_cookie_command(self, policy_md5: str, cookie_name: str,
                                        perform_staging: bool):
        """
        Update a given cookie from a certain policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            cookie_name (str): The cookie to update.
            perform_staging (bool): Indicates if the user wishes the new file type to be at staging.
        """
        file_type_id = self.get_id(policy_md5, cookie_name, 'cookies')
        body = {'name': cookie_name, 'performStaging': perform_staging}
        url_suffix = f'asm/policies/{policy_md5}/cookies/{file_type_id}'
        response = self._http_request(method='PATCH', headers=self.headers, json_data=body,
                                      url_suffix=url_suffix)
        return format_policy_object(response, 'Cookies')

    def f5_delete_policy_cookie_command(self, policy_md5: str, cookie_name: str):
        """
        Add allowed method to a certain policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            cookie_name (str): The cookie to delete.
        """

        file_type_id = self.get_id(policy_md5, cookie_name, 'cookies')
        url_suffix = f'asm/policies/{policy_md5}/cookies/{file_type_id}'
        response = self._http_request(method='DELETE', headers=self.headers, json_data={},
                                      url_suffix=url_suffix)
        return format_policy_object(response, 'Cookies')

    def f5_list_policy_whitelist_ips_command(self, policy_md5: str):
        """
        List all whitelisted IPs for a certain policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
        """

        response = self._http_request(method='GET', headers=self.headers, json_data={},
                                      url_suffix=f'asm/policies/{policy_md5}/whitelist-ips')
        return format_list_policy_functions(response, 'WhitelistIP')

    def f5_add_policy_whitelist_ip_command(self, policy_md5: str, ip_address: str,
                                           ip_mask=None, trusted_by_builder=None,
                                           ignore_brute_detection=None, description=None,
                                           block_requests=None, ignore_learning=None,
                                           never_log=None, ignore_intelligence=None):
        """
        Create a new whitelisted IP for a certain policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            ip_address(str): New IP address.
            ip_mask(str): Subnet mask for the new IP.
            trusted_by_builder(bool): Whether or not the IP is trusted by the policy builder.
            ignore_brute_detection(bool): Whether or not to ignore detections of brute force.
            description (str): Optional description for the new IP.
            block_requests(str): Method of blocking requests.
            ignore_learning(bool): Whether or not to ignore learning suggestions.
            never_log(bool): Whether or not to never log from the IP.
            ignore_intelligence(bool): Whether or not to ignore intelligence gathered on the IP.
        """

        json_body = {'ipAddress': ip_address,
                     'ipMask': ip_mask,
                     'ignoreIpReputation': ignore_intelligence,
                     'blockRequests': block_requests,
                     'ignoreAnomalies': ignore_brute_detection,
                     'description': description,
                     'neverLearnRequests': ignore_learning,
                     'neverLogRequests': never_log,
                     'trustedByPolicyBuilder': trusted_by_builder
                     }

        json_body = {key: value for key, value in json_body.items() if value is not None}

        response = self._http_request(method='POST', headers=self.headers,
                                      url_suffix=f'asm/policies/{policy_md5}/whitelist-ips',
                                      json_data=json_body)
        return format_policy_object(response, 'WhitelistIP')

    def f5_update_policy_whitelist_ip_command(self, policy_md5: str, ip_address: str,
                                              trusted_by_builder=None,
                                              ignore_brute_detection=None,
                                              description=None, block_requests=None,
                                              ignore_learning=None, never_log=None,
                                              ignore_intelligence=None):
        """
        Update an existing whitelisted IP for a certain policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            ip_address(str): IP address.
            trusted_by_builder(bool): Whether or not the IP is trusted by the policy builder.
            ignore_brute_detection(bool): Whether or not to ignore detections of brute force.
            description (str): Optional description for the new IP.
            block_requests(str): Method of blocking requests.
            ignore_learning(bool): Whether or not to ignore learning suggestions.
            never_log(bool): Whether or not to never log from the IP.
            ignore_intelligence(bool): Whether or not to ignore intelligence gathered on the IP.
        """
        ip_id = self.get_id(policy_md5, ip_address, 'whitelist-ips', compare_value='ipAddress')
        json_body = {'ignoreIpReputation': ignore_intelligence,
                     'blockRequests': block_requests,
                     'ignoreAnomalies': ignore_brute_detection,
                     'description': description,
                     'neverLearnRequests': ignore_learning,
                     'neverLogRequests': never_log,
                     'trustedByPolicyBuilder': trusted_by_builder}

        json_body = {key: value for key, value in json_body.items() if value is not None}
        response = self._http_request(method='PATCH', headers=self.headers,
                                      url_suffix=f'asm/policies/{policy_md5}/whitelist-ips/{ip_id}',
                                      json_data=json_body)

        return format_policy_object(response, 'WhitelistIP')

    def f5_delete_policy_whitelist_ip_command(self, policy_md5: str, ip_address: str):
        """
        Delete an existing whitelisted IP from a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            ip_address(str): IP address.
        """
        ip_id = self.get_id(policy_md5, ip_address, 'whitelist-ips', compare_value='ipAddress')
        response = self._http_request(method='DELETE', headers=self.headers, json_data={},
                                      url_suffix=f'asm/policies/{policy_md5}/whitelist-ips/{ip_id}')
        return format_policy_object(response, 'WhitelistIP')

    def f5_list_policy_signatures_command(self, policy_md5: str):
        """
        List all signatures for a certain policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
        """
        response = self._http_request(method='GET', headers=self.headers, json_data={},
                                      url_suffix=f'asm/policies/{policy_md5}/signatures')
        return format_list_policy_functions(response, 'Signatures')

    def f5_list_policy_parameters_command(self, policy_md5: str):
        """
        List all parameters for a certain policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
        """
        response = self._http_request(method='GET', headers=self.headers, json_data={},
                                      url_suffix=f'asm/policies/{policy_md5}/parameters')
        return format_list_policy_functions(response, "Parameter")

    def f5_add_policy_parameter_command(self, policy_md5: str, name: str, param_type=None,
                                        value_type=None, param_location=None,
                                        perform_staging=None, mandatory=None, allow_empty=None,
                                        allow_repeated=None, sensitive=None):
        """
            Add a new parameter to a policy

            Args:
            policy_md5 (str): MD5 hash of the policy.
            param_type(str): Type of parameter.
            name (str): Name of parameter.
            value_type(str): Type of value the parameter recieves.
            param_location (str): Where the parameter sits.
            perform_staging (bool): Whether or not to stage the parameter.
            mandatory (bool): Is the parameter mandatory.
            allow_empty (bool): Should the parameter allow empty values.
            allow_repeated (bool): Should the parameter allow repeated values.
            sensitive (bool): Should the parameter values be masked in logs.
        """
        json_body = {'name': name, 'type': param_type,
                     'valueType': value_type,
                     'parameterLocation': param_location, 'mandatory': mandatory,
                     'performStaging': perform_staging, 'sensitiveParameter': sensitive,
                     'allowEmptyValue': allow_empty,
                     'allowRepeatedParameterName': allow_repeated}
        json_body = {key: value for key, value in json_body.items() if value is not None}

        response = self._http_request(method='POST', headers=self.headers, json_data=json_body,
                                      url_suffix=f'asm/policies/{policy_md5}/parameters')
        return format_policy_object(response, "Parameter")

    def f5_update_policy_parameter_command(self, policy_md5: str, name: str,
                                           value_type: str = None, param_location: str = None,
                                           perform_staging: bool = None, mandatory: bool = None,
                                           allow_empty: bool = None, allow_repeated: bool = None,
                                           sensitive: bool = None):
        """
        Add an existing parameter to a policy

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of parameter.
            value_type(str): Type of value the parameter recieves.
            param_location(str): Where the parameter sits.
            perform_staging (bool): Whether or not to stage the parameter.
            mandatory(bool): Is the parameter mandatory.
            allow_empty(bool): Should the parameter allow empty values.
            allow_repeated(bool): Should the parameter allow repeated values.
            sensitive(bool): Should the parameter values be masked in logs.
        """
        parameter_id = self.get_id(policy_md5, name, 'parameters')
        json_body = {'name': name, 'valueType': value_type,
                     'parameterLocation': param_location, 'mandatory': mandatory,
                     'performStaging': perform_staging, 'sensitiveParameter': sensitive,
                     'allowEmptyValue': allow_empty,
                     'allowRepeatedParameterName': allow_repeated}
        json_body = {key: value for key, value in json_body.items() if value is not None}
        url_suffix = f'asm/policies/{policy_md5}/parameters/{parameter_id}'
        response = self._http_request(method='PATCH', headers=self.headers, json_data=json_body,
                                      url_suffix=url_suffix)
        return format_policy_object(response, "Parameter")

    def f5_delete_policy_parameter_command(self, policy_md5: str, name: str):
        """
        Delete an existing parameter from a policy

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of parameter.
        """

        parameter_id = self.get_id(policy_md5, name, 'parameters')

        url_suffix = f'asm/policies/{policy_md5}/parameters/{parameter_id}'
        response = self._http_request(method='DELETE', headers=self.headers, json_data={},
                                      url_suffix=url_suffix)
        return format_policy_object(response, "Parameter")

    def f5_list_policy_gwt_profiles_command(self, policy_md5: str):
        """
        List all GWT profiles from a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
        """
        response = self._http_request(method='GET', headers=self.headers, json_data={},
                                      url_suffix=f'asm/policies/{policy_md5}/gwt-profiles')
        return format_list_policy_functions(response, 'GWTProfile')

    def f5_add_policy_gwt_profile_command(self, policy_md5: str, name: str,
                                          maximum_value_len: str, maximum_total_len: str,
                                          description: str = None,
                                          tolerate_parsing_warnings: bool = None,
                                          check_signatures: bool = None,
                                          check_metachars: bool = None):
        """
        Add a new GWT profile to a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of the profile.
            description (str): Optional description for the profile.
            maximum_value_len(str): Maximum length to a value.
            maximum_total_len(str): Maximum total profile data length.
            tolerate_parsing_warnings(bool): Should the profile tolerate parsing warnings.
            check_signatures (bool): Should attack signatures be checked.
            check_metachars(bool): Should metachar elements be checked.
        """
        json_body = {'name': name,
                     'description': description,
                     'defenseAttributes':
                         {
                             'maximumValueLength': maximum_value_len,
                             'maximumTotalLengthOfGWTData': maximum_total_len,
                             'tolerateGWTParsingWarnings': tolerate_parsing_warnings == 'true'
                         },
                     'attackSignaturesCheck': check_signatures,
                     'metacharElementCheck': check_metachars}
        json_body = {key: value for key, value in json_body.items() if value is not None}

        response = self._http_request(method='POST', headers=self.headers,
                                      url_suffix=f'asm/policies/{policy_md5}/gwt-profiles',
                                      json_data=json_body)
        return format_policy_object(response, 'GWTProfile')

    def f5_update_policy_gwt_profile_command(self, policy_md5: str, name: str,
                                             maximum_value_len: str, maximum_total_len: str,
                                             description: str = None,
                                             tolerate_parsing_warnings: bool = None,
                                             check_signatures: bool = None,
                                             check_metachars: bool = None):
        """
        Update an existing GWT profile in a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of the profile.
            description (str): Optional description for the profile.
            maximum_value_len(str): Maximum length to a value.
            maximum_total_len(str): Maximum total profile data length.
            tolerate_parsing_warnings(bool): Should the profile tolerate parsing warnings.
            check_signatures (bool): Should attack signatures be checked.
            check_metachars(bool): Should metachar elements be checked.
        """
        profile_id = self.get_id(policy_md5, name, 'gwt-profiles')
        json_body = {'description': description,
                     'defenseAttributes':
                         {
                             'maximumValueLength': maximum_value_len,
                             'maximumTotalLengthOfGWTData': maximum_total_len,
                             'tolerateGWTParsingWarnings': tolerate_parsing_warnings == 'true'
                         },
                     'attackSignaturesCheck': check_signatures,
                     'metacharElementCheck': check_metachars}
        json_body = {key: value for key, value in json_body.items() if value is not None}
        url_suffix = f'asm/policies/{policy_md5}/gwt-profiles/{profile_id}'
        response = self._http_request(method='PATCH', headers=self.headers,
                                      url_suffix=url_suffix, json_data=json_body)
        return format_policy_object(response, 'GWTProfile')

    def f5_delete_policy_gwt_profile_command(self, policy_md5: str, name: str):
        """
        Delete an exisiting GWT profile from a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of the profile to remove.
        """
        profile_id = self.get_id(policy_md5, name, 'gwt-profiles')
        url_suffix = f'asm/policies/{policy_md5}/gwt-profiles/{profile_id}'
        response = self._http_request(method='DELETE', headers=self.headers,
                                      url_suffix=url_suffix)
        return format_policy_object(response, 'GWTProfile')

    def f5_list_policy_json_profiles_command(self, policy_md5: str):
        """
        List all JSON profiles in a policy

        Args:
            policy_md5 (str): MD5 hash of the policy.
        """
        response = self._http_request(method='GET', headers=self.headers,
                                      url_suffix=f'asm/policies/{policy_md5}/json-profiles')
        return format_list_policy_functions(response, 'JSONProfile')

    def f5_add_policy_json_profile_command(self, policy_md5: str, name: str,
                                           maximum_total_len: str, maximum_value_len: str,
                                           max_structure_depth: str, max_array_len: str,
                                           description: str = None,
                                           tolerate_parsing_warnings: bool = None,
                                           parse_parameters: bool = None,
                                           check_signatures: bool = None,
                                           check_metachars: bool = None):
        """
        Create a new JSON profile in a policy

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of JSON profile.
            description (str): Optional profile description.
            maximum_total_len(str): Maximum total length of JSON data.
            maximum_value_len(str): Maximum length for a single value.
            max_structure_depth(str): Maxmimum structure depth.
            max_array_len(str): Maximum JSON array length.
            tolerate_parsing_warnings(bool): Should the profile tolerate JSON parsing warnings.
            parse_parameters(bool): Should the profile handle JSON values as parameters.
            check_signatures (bool): Should the profile check for attack signatures.
            check_metachars(bool): Should the profile check for metachar elements.
        """
        json_body = {'name': name, 'description': description,
                     'defenseAttributes': {
                         'maximumValueLength': maximum_value_len,
                         'maximumTotalLengthOfJSONData': maximum_total_len,
                         'tolerateJSONParsingWarnings': tolerate_parsing_warnings == 'true',
                         'maximumArrayLength': max_array_len,
                         'maximumStructureDepth': max_structure_depth
                     },
                     'attackSignaturesCheck': check_signatures,
                     'metacharElementCheck': check_metachars,
                     'handleJsonValuesAsParameters': parse_parameters}
        json_body = {key: value for key, value in json_body.items() if value is not None}

        response = self._http_request(method='POST', headers=self.headers,
                                      url_suffix=f'asm/policies/{policy_md5}/json-profiles',
                                      json_data=json_body)
        return format_policy_object(response, 'JSONProfile')

    def f5_update_policy_json_profile_command(self, policy_md5: str, name: str,
                                              maximum_total_len: str, maximum_value_len: str,
                                              max_structure_depth: str, max_array_len: str,
                                              description: str = None,
                                              tolerate_parsing_warnings: bool = None,
                                              parse_parameters: bool = None,
                                              check_signatures: bool = None,
                                              check_metachars: bool = None):
        """
        Update an existing JSON profile in a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of JSON profile.
            description (str): Optional profile description.
            maximum_total_len(str): Maximum total length of JSON data.
            maximum_value_len(str): Maximum length for a single value.
            max_structure_depth(str): Maxmimum structure depth.
            max_array_len(str): Maximum JSON array length.
            tolerate_parsing_warnings(bool): Should the profile tolerate JSON parsing warnings.
            parse_parameters(bool): Should the profile handle JSON values as parameters.
            check_signatures (bool): Should the profile check for attack signatures.
            check_metachars(bool): Should the profile check for metachar elements.
        """
        profile_id = self.get_id(policy_md5, name, 'json-profiles')
        json_body = {'description': description,
                     'defenseAttributes':
                         {
                             'maximumValueLength': maximum_value_len,
                             'maximumTotalLengthOfJSONData': maximum_total_len,
                             'tolerateJSONParsingWarnings': tolerate_parsing_warnings == 'true',
                             'maximumArrayLength': max_array_len,
                             'maximumStructureDepth': max_structure_depth
                         },
                     'attackSignaturesCheck': check_signatures,
                     'metacharElementCheck': check_metachars,
                     'handleJsonValuesAsParameters': parse_parameters}
        json_body = {key: value for key, value in json_body.items() if value is not None}
        url_suffix = f'asm/policies/{policy_md5}/json-profiles/{profile_id}'
        response = self._http_request(method='PATCH', headers=self.headers,
                                      url_suffix=url_suffix, json_data=json_body)
        return format_policy_object(response, 'JSONProfile')

    def f5_delete_policy_json_profile_command(self, policy_md5: str, name: str):
        """
        Delete an existing JSON profile from a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of the profile to delete.
        """
        profile_id = self.get_id(policy_md5, name, 'json-profiles')
        url_suffix = f'asm/policies/{policy_md5}/json-profiles/{profile_id}'
        response = self._http_request(method='DELETE', headers=self.headers,
                                      url_suffix=url_suffix)
        return format_policy_object(response, 'JSONProfile')

    def f5_list_policy_xml_profiles_command(self, policy_md5: str):
        """
        List all existing XML profiles in a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
        """
        response = self._http_request(method='GET', headers=self.headers,
                                      url_suffix=f'asm/policies/{policy_md5}/xml-profiles')
        return format_list_policy_functions(response, 'XMLProfile')

    def f5_add_policy_xml_profile_command(self, policy_md5: str, name: str, description=None,
                                          check_signatures=None, check_metachar_elements=None,
                                          check_metachar_attributes=None, enable_wss=None,
                                          inspect_soap=None, follow_links=None,
                                          use_xml_response=None, allow_cdata=None,
                                          allow_dtds=None, allow_external_ref=None,
                                          allow_processing_instructions=None):
        """
        Add a new XML profile to a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of the profile.
            description (str): Optional description for the profile.
            check_signatures (bool): Whether or not to check for attack signatures.
            check_metachar_elements (bool): Whether or not to check for metachar elements.
            check_metachar_attributes (bool): Whether or not to check for metachar attributes.
            enable_wss (bool): Whether or not to enable web services securities.
            inspect_soap (bool): Whether or not to inspect SOAP attachments.
            follow_links (bool): Whether or not to follow schema links.
            use_xml_response(bool): Whether or not to use the XML response page.
            allow_cdata(bool): Whether or not to allow CDATA.
            allow_dtds(bool): Whether or not to allow DTDs.
            allow_external_ref(bool): Whether or not to allow external references.
            allow_processing_instructions(bool): Whether or not to allow processing instructions.
        """
        json_body = {'name': name, 'description': description,
                     'attackSignaturesCheck': check_signatures,
                     'metacharElementCheck': check_metachar_elements,
                     'metacharAttributeCheck': check_metachar_attributes,
                     'enableWss': enable_wss, 'inspectSoapAttachments': inspect_soap,
                     'followSchemaLinks': follow_links,
                     'useXmlResponsePage': use_xml_response,
                     'defenseAttributes':
                         {
                             'allowCDATA': allow_cdata == 'true',
                             'allowDTDs': allow_dtds == 'true',
                             'allowExternalReferences': allow_external_ref == 'true',
                             'allowProcessingInstructions':
                                 allow_processing_instructions == 'true'
                         }}
        json_body = {key: value for key, value in json_body.items() if value is not None}

        response = self._http_request(method='POST', headers=self.headers,
                                      url_suffix=f'asm/policies/{policy_md5}/xml-profiles',
                                      json_data=json_body)
        return format_policy_object(response, 'XMLProfile')

    def f5_update_policy_xml_profile_command(self, policy_md5: str, name: str,
                                             description=None,
                                             check_signatures=None, check_metachar_elements=None,
                                             check_metachar_attributes=None, enable_wss=None,
                                             inspect_soap=None, follow_links=None,
                                             use_xml_response=None, allow_cdata=None,
                                             allow_dtds=None, allow_external_ref=None,
                                             allow_processing_instructions=None):

        """
        Update an XML profile in a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of the profile.
            description (str): Optional description for the profile.
            check_signatures (bool): Whether or not to check for attack signatures.
            check_metachar_elements (bool): Whether or not to check for metachar elements.
            check_metachar_attributes (bool): Whether or not to check for metachar attributes.
            enable_wss (bool): Whether or not to enable web services securities.
            inspect_soap (bool): Whether or not to inspect SOAP attachments.
            follow_links (bool): Whether or not to follow schema links.
            use_xml_response (bool): Whether or not to use the XML response page.
            allow_cdata (bool): Whether or not to allow CDATA.
            allow_dtds (bool): Whether or not to allow DTDs.
            allow_external_ref (bool): Whether or not to allow external references.
            allow_processing_instructions (bool): Whether or not to allow processing instructions.
        """

        profile_id = self.get_id(policy_md5, name, 'xml-profiles')
        json_body_start = {'description': description,
                           'attackSignaturesCheck': check_signatures,
                           'metacharElementCheck': check_metachar_elements,
                           'metacharAttributeCheck': check_metachar_attributes,
                           'enableWss': enable_wss, 'inspectSoapAttachments': inspect_soap,
                           'followSchemaLinks': follow_links,
                           'useXmlResponsePage': use_xml_response,
                           'defenseAttributes':
                               {
                                   'allowCDATA': allow_cdata == 'true',
                                   'allowDTDs': allow_dtds == 'true',
                                   'allowExternalReferences': allow_external_ref == 'true',
                                   'allowProcessingInstructions':
                                       allow_processing_instructions == 'true'
                               }}
        json_body = {key: value for key, value in json_body_start.items() if value is not None}
        url_suffix = f'asm/policies/{policy_md5}/xml-profiles/{profile_id}'
        response = self._http_request(method='PATCH', headers=self.headers,
                                      url_suffix=url_suffix, json_data=json_body)
        return format_policy_object(response, 'XMLProfile')

    def f5_delete_policy_xml_profile_command(self, policy_md5: str, name: str):
        """
        Delete an existing XML profile from a policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            name (str): Name of the profile.
        """
        profile_id = self.get_id(policy_md5, name, 'xml-profiles')
        url_suffix = f'asm/policies/{policy_md5}/xml-profiles/{profile_id}'
        response = self._http_request(method='DELETE', headers=self.headers,
                                      url_suffix=url_suffix)
        return format_policy_object(response, 'XMLProfile')

    def f5_list_policy_server_technologies_command(self, policy_md5: str):
        """
            List all server technologies in a policy.

            Args:
                policy_md5 (str): MD5 hash of the policy.
        """
        url_suffix = f'asm/policies/{policy_md5}/server-technologies'
        response = self._http_request(method='GET', headers=self.headers,
                                      url_suffix=url_suffix)
        return format_list_policy_functions(response, 'ServerTechnology')

    def f5_add_policy_server_technology_command(self, policy_md5: str, name: str):
        """
            Add a server technology to a policy.

            Args:
                policy_md5 (str): MD5 hash of the policy.
                name (str): Name of the server technology.
        """
        url_suffix = f'asm/policies/{policy_md5}/server-technologies'
        technology_id = self.get_id(policy_md5, name, 'server-technologies-general',
                                    'serverTechnologyDisplayName')
        json_body = {'serverTechnologyReference': {'link': technology_id}}
        response = self._http_request(method='POST', headers=self.headers,
                                      url_suffix=url_suffix, json_data=json_body)
        return format_policy_object(response, 'ServerTechnology')

    def f5_delete_policy_server_technology_command(self, policy_md5: str, name: str):
        """
            Delete a server technology from a policy.

            Args:
                policy_md5 (str): MD5 hash of the policy.
                name (str): Name of the server technology.
        """
        technology_id = self.get_id(policy_md5, name, 'server-technologies',
                                    'serverTechnologyDisplayName')
        url_suffix = f'asm/policies/{policy_md5}/server-technologies/{technology_id}'
        response = self._http_request(method='DELETE', headers=self.headers,
                                      url_suffix=url_suffix, json_data={})
        return format_policy_object(response, 'ServerTechnology')


def test_module(server_address: str, username: str, password: str,
                verify_certificate: bool) -> str:
    """Returning 'ok' indicates that the integration works like it is supposed to."""
    response = requests.get(f'{server_address}sys/version', verify=verify_certificate,
                            auth=(username, password))
    if response.status_code == 200:
        return 'ok'
    if 400 <= response.status_code < 500:
        return f'Invalid credentials given.\nError: {response.status_code}: {response.text}'
    if response.status_code >= 500:
        return f'Invalid credentials given.\nError: {response.status_code}: {response.text}'
    return f'Error {response.status_code}: {response.text}'


def login(server_ip: str, username: str, password: str, verify_certificate: bool) -> str:
    """Log into the F5 instance in order to get a session token for further auth."""
    res = requests.post(f'https://{server_ip}/mgmt/shared/authn/login', verify=verify_certificate,
                        json={'username': username, 'password': password,
                              'loginProviderName': 'tmos'})
    return res.json().get('token').get('token')


def format_policy_md5(result: dict) -> CommandResults:
    """
    Formats f5 policy md5 to Demisto's outputs.

    Args:
        result (dict): the report from f5.
    """
    command_results = CommandResults(
        outputs_prefix='f5.Policy',
        outputs_key_field='(val.uid && val.uid == obj.uid)',
        outputs=result,
        raw_response=result
    )
    return command_results


def format_list_policies(result: dict) -> CommandResults:
    """
    Formats f5 policy list Demisto's outputs.

    Args:
        result (dict): the report from f5.
    """

    result = result.get('items')
    printable_result = []
    if result:
        for item in result:
            current_object_data = {
                'name': item.get('name'),
                'id': item.get('id'),
                'type': item.get('type'),
                'creatorName': item.get('creatorName'),
                'createdTime': item.get('createdDatetime'),
                'enforcementMode': item.get('enforcementMode'),
                'active': item.get('active'),
            }
            printable_result.append(current_object_data)

    readable_output = tableToMarkdown('f5 data for listing policies:', printable_result,
                                      ['name', 'id', 'type', 'enforcementMode',
                                       'creatorName', 'active', 'createdTime'],
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='f5.ListPolicies',
        outputs_key_field='(val.uid && val.uid == obj.uid)',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def format_create_policy(result) -> CommandResults:
    """
    Formats f5 policy create Demisto's outputs.

    Args:
        result (dict): the report from f5.
    """
    outputs = {
        'name': result.get('name'),
        'id': result.get('id'),
        'fullPath': result.get('fullPath'),
        'description': result.get('description'),
        'type': result.get('type'),
        'versionDatetime': result.get('versionDatetime'),
    }
    command_results = CommandResults(
        outputs_prefix='f5.CreatePolicy',
        outputs_key_field='(val.uid && val.uid == obj.uid)',
        outputs=outputs,
        raw_response=result
    )
    return command_results


def format_apply_policy(result) -> CommandResults:
    """
    Formats f5 policy apply Demisto's outputs.

    Args:
        result (dict): the report from f5.
    """
    outputs = {
        'policyReference': result.get('policyReference').get('link'),
        'status': result.get('status'),
        'id': result.get('id'),
        'startTime': result.get('startTime'),
        'kind': result.get('kind'),
    }
    command_results = CommandResults(
        outputs_prefix='f5.ApplyPolicy',
        outputs_key_field='(val.uid && val.uid == obj.uid)',
        outputs=outputs,
        raw_response=result
    )
    return command_results


def format_export_policy(result) -> CommandResults:
    """
    Formats f5 policy export Demisto's outputs.

    Args:
        result (dict): the report from f5.
    """
    outputs = {
        'status': result.get('status'),
        'id': result.get('id'),
        'startTime': result.get('startTime'),
        'kind': result.get('kind'),
        'format': result.get('format'),
        'filename': result.get('filename'),
    }
    policy_reference = result.get('policyReference')
    if policy_reference:
        outputs['policy-reference'] = policy_reference.get('link')

    readable_output = tableToMarkdown('f5 data for exporting policy:', outputs,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='f5.ExportPolicy',
        outputs_key_field='(val.uid && val.uid == obj.uid)',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )
    return command_results


def format_delete_policy(result) -> CommandResults:
    """
    Formats f5 delete policy to Demisto's outputs.

    Args:
        result (dict): the report from f5.
    """
    outputs = {
        'name': result.get('name'),
        'id': result.get('id'),
        'selfLink': result.get('selfLink'),
    }

    readable_output = tableToMarkdown('f5 data for deleting policy:', outputs,
                                      ['name', 'id', 'selfLink'], removeNull=True)

    command_results = CommandResults(
        outputs_prefix='f5.DeletePolicy',
        outputs_key_field='(val.uid && val.uid == obj.uid)',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )
    return command_results


def format_list_policy_functions(result: dict, context_path_endpoint: str) -> CommandResults:
    """
    Formats all f5 list functions to Demisto's outputs.

    Args:
        result(dict): The response from API.
        context_path_endpoint(str): The context path endpoint to format.
    """
    result = result.get('items')
    printable_result = []
    if result:
        for item in result:
            current_object_data = {}
            for endpoint in BASIC_FIELDS:
                if endpoint == 'lastUpdateMicros':
                    current_object_data[endpoint] = format_date(item.get(endpoint))
                else:
                    current_object_data[endpoint] = item.get(endpoint)
            server_tech_reference = item.get('serverTechnologyReference')
            if server_tech_reference:
                current_object_data['serverTechnologyName'] = server_tech_reference.get(
                    'serverTechnologyName')
            printable_result.append(current_object_data)

    readable_output = tableToMarkdown(f'f5 data for all {context_path_endpoint}:',
                                      printable_result, BASIC_FIELDS, removeNull=True)

    command_results = CommandResults(
        outputs_prefix=f'f5.{context_path_endpoint}',
        outputs_key_field='(val.uid && val.uid == obj.uid)',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def format_policy_object(result: dict, context_path_endpoint: str) -> CommandResults:
    """
    Formats all f5 add, update and remove functions to Demisto's outputs.

    Args:
        result(dict): The response from API.
        context_path_endpoint(str): The context path endpoint to format.
    """
    printable_result = {}
    for endpoint in BASIC_OBJECT_FIELDS:
        if endpoint == 'lastUpdateMicros':
            printable_result[endpoint] = format_date(result.get('lastUpdateMicros'))
        else:
            printable_result[endpoint] = result.get(endpoint)
    server_tech_reference = result.get('serverTechnologyReference')

    if server_tech_reference:
        printable_result['serverTechnologyName'] = server_tech_reference.get(
            'serverTechnologyName')

    readable_output = tableToMarkdown(f'f5 data for listing {context_path_endpoint}:',
                                      printable_result, BASIC_OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix=f'f5.{context_path_endpoint}',
        outputs_key_field='(val.uid && val.uid == obj.uid)',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def format_policy_blocking_settings_list_command(result: dict, endpoint: str) -> CommandResults:
    """
    Format Blocking Settings entries to Demisto's outputs.

    Args:
        result(dict): API response from F5.
        endpoint(str): One of: evasions, violations, web-services-securities, http-protocols.
    """
    result = result.get('items')
    printable_result = []
    references = {'evasions': 'evasionReference', 'violations': 'violationReference',
                  'web-services-securities': 'webServicesSecurityReference',
                  'http-protocols': 'httpProtocolReference'}

    if result:
        for item in result:
            current_object_data = {
                'description': item.get('description'),
                'learn': item.get('learn'),
                'alarm': item.get('alarm'),
                'block': item.get('block'),
                'id': item.get('id'),
                'kind': item.get('kind'),
                'enabled': item.get('enabled'),
                'selfLink': item.get('selfLink'),
                'section-reference': item.get('sectionReference').get('link') if item.get(
                    'sectionReference') else None,
                'lastUpdateMicros': format_date(item.get('lastUpdateMicros')),
            }
            reference_link = item.get(references.get(endpoint))

            if reference_link:
                current_object_data['reference'] = reference_link.get('link')
            printable_result.append(current_object_data)

    readable_output = tableToMarkdown(f'{endpoint.capitalize()} for selected policy',
                                      printable_result,
                                      headers=['id', 'description', 'enabled', 'learn', 'alarm',
                                               'block', 'kind', 'reference', 'selfLink',
                                               'section-reference', 'lastUpdateMicros'],
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix=f'f5.{endpoint}',
        outputs_key_field='(val.uid && val.uid == obj.uid)',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def format_policy_blocking_settings_update_command(result: dict, endpoint: str) -> CommandResults:
    """
        Format a single Blocking Setting element for demisto.

        Args:
            result(dict): API response from F5.
            endpoint(str): One of: evasions, violations, web-services-securities, http-protocols.
    """
    references = {'evasions': 'evasionReference', 'violations': 'violationReference',
                  'web-services-securities': 'webServicesSecurityReference',
                  'http-protocols': 'httpProtocolReference'}
    printable_result = {
        'description': result.get('description'),
        'learn': result.get('learn'),
        'alarm': result.get('alarm'),
        'block': result.get('block'),
        'id': result.get('id'),
        'kind': result.get('kind'),
        'enabled': result.get('enabled'),
        'selfLink': result.get('selfLink'),
        'lastUpdateMicros': format_date(result.get('lastUpdateMicros')),
    }
    section_reference = result.get('sectionReference')
    if section_reference:
        printable_result['section-reference'] = section_reference.get('link')

    reference_link = result.get(references.get(endpoint))
    if reference_link:
        printable_result['reference'] = reference_link.get('link')

    readable_output = tableToMarkdown(f'Modified {endpoint}', printable_result,
                                      headers=['id', 'description', 'enabled', 'learn', 'alarm',
                                               'block', 'kind', 'reference', 'selfLink',
                                               'section-reference', 'lastUpdateMicros'],
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix=f'f5.{endpoint}',
        outputs_key_field='(val.uid && val.uid == obj.uid)',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def format_date(date):
    """formats date according to Demisto date format"""
    date = int(date / 1000000)
    return time.strftime(DATE_FORMAT, time.localtime(date))


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')

    server_ip = params['url']
    base_url = f'https://{server_ip}/mgmt/tm/'

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    token = login(server_ip, username, password, verify_certificate)

    demisto.info(f'Command being called is {demisto.command()}')
    try:

        if demisto.command() == 'test-module':
            result = test_module(base_url, username, password, verify_certificate)
            return_results(result)

        client = Client(
            base_url=base_url,
            token=token,
            use_ssl=verify_certificate,
            use_proxy=proxy)
        command = demisto.command()
        commands = {
            'f5-asm-get-policy-md5': client.f5_get_policy_md5_command,
            'f5-asm-policy-list': client.f5_list_policies_command,
            'f5-asm-policy-create': client.f5_create_policy_command,
            'f5-asm-policy-apply': client.f5_apply_policy_command,
            'f5-asm-policy-export-file': client.f5_export_policy_command,
            'f5-asm-policy-delete': client.f5_delete_policy_command,

            'f5-asm-policy-methods-list': client.f5_list_policy_methods_command,
            'f5-asm-policy-methods-add': client.f5_add_policy_method_command,
            'f5-asm-policy-methods-update': client.f5_update_policy_method_command,
            'f5-asm-policy-methods-delete': client.f5_delete_policy_method_command,

            'f5-asm-policy-file-types-list': client.f5_list_policy_file_types_command,
            'f5-asm-policy-file-types-add': client.f5_add_policy_file_type_command,
            'f5-asm-policy-file-types-update': client.f5_update_policy_file_type_command,
            'f5-asm-policy-file-types-delete': client.f5_delete_policy_file_type_command,

            'f5-asm-policy-cookies-list': client.f5_list_policy_cookies_command,
            'f5-asm-policy-cookies-add': client.f5_add_policy_cookie_command,
            'f5-asm-policy-cookies-update': client.f5_update_policy_cookie_command,
            'f5-asm-policy-cookies-delete': client.f5_delete_policy_cookie_command,

            'f5-asm-policy-hostnames-list': client.f5_list_policy_hostnames_command,
            'f5-asm-policy-hostnames-add': client.f5_add_policy_hostname_command,
            'f5-asm-policy-hostnames-update': client.f5_update_policy_hostname_command,
            'f5-asm-policy-hostnames-delete': client.f5_delete_policy_hostname_command,

            'f5-asm-policy-blocking-settings-list':
                client.f5_list_policy_blocking_settings_command,
            'f5-asm-policy-blocking-settings-update':
                client.f5_update_policy_blocking_setting_command,

            'f5-asm-policy-urls-list': client.f5_list_policy_urls_command,
            'f5-asm-policy-urls-add': client.f5_add_policy_url_command,
            'f5-asm-policy-urls-update': client.f5_update_policy_url_command,
            'f5-asm-policy-urls-delete': client.f5_delete_policy_url_command,

            'f5-asm-policy-whitelist-ips-list': client.f5_list_policy_whitelist_ips_command,
            'f5-asm-policy-whitelist-ips-add': client.f5_add_policy_whitelist_ip_command,
            'f5-asm-policy-whitelist-ips-update': client.f5_update_policy_whitelist_ip_command,
            'f5-asm-policy-whitelist-ips-delete': client.f5_delete_policy_whitelist_ip_command,

            'f5-asm-policy-signatures-list': client.f5_list_policy_signatures_command,

            'f5-asm-policy-parameters-list': client.f5_list_policy_parameters_command,
            'f5-asm-policy-parameters-add': client.f5_add_policy_parameter_command,
            'f5-asm-policy-parameters-update': client.f5_update_policy_parameter_command,
            'f5-asm-policy-parameters-delete': client.f5_delete_policy_parameter_command,

            'f5-asm-policy-gwt-profiles-list': client.f5_list_policy_gwt_profiles_command,
            'f5-asm-policy-gwt-profiles-add': client.f5_add_policy_gwt_profile_command,
            'f5-asm-policy-gwt-profiles-update': client.f5_update_policy_gwt_profile_command,
            'f5-asm-policy-gwt-profiles-delete': client.f5_delete_policy_gwt_profile_command,

            'f5-asm-policy-json-profiles-list': client.f5_list_policy_json_profiles_command,
            'f5-asm-policy-json-profiles-add': client.f5_add_policy_json_profile_command,
            'f5-asm-policy-json-profiles-update': client.f5_update_policy_json_profile_command,
            'f5-asm-policy-json-profiles-delete': client.f5_delete_policy_json_profile_command,

            'f5-asm-policy-xml-profiles-list': client.f5_list_policy_xml_profiles_command,
            'f5-asm-policy-xml-profiles-add': client.f5_add_policy_xml_profile_command,
            'f5-asm-policy-xml-profiles-update': client.f5_update_policy_xml_profile_command,
            'f5-asm-policy-xml-profiles-delete': client.f5_delete_policy_xml_profile_command,

            'f5-asm-policy-server-technologies-list':
                client.f5_list_policy_server_technologies_command,
            'f5-asm-policy-server-technologies-add':
                client.f5_add_policy_server_technology_command,
            'f5-asm-policy-server-technologies-delete':
                client.f5_delete_policy_server_technology_command,
        }

        if command in commands:
            result = (commands[demisto.command()](**demisto.args()))  # type: ignore
            return_results(result)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
