from typing import Optional, List
import demistomock as demisto
from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
LIST_FIELDS = ['name', 'id', 'ipAddress', 'type', 'protocol', 'method', 'actAsMethod',
               'serverTechnologyName', 'checkRequestLength', 'enforcementType',
               'ipMask', 'blockRequests', 'ignoreAnomalies', 'neverLogRequests',
               'neverLearnRequests', 'trustedByPolicyBuilder', 'includeSubdomains',
               'description', 'mandatoryBody', 'clickjackingProtection', 'attackSignaturesCheck',
               'metacharElementCheck', 'hasValidationFiles', 'followSchemaLinks', 'isBase64',
               'enableWSS', 'dataType', 'valueType', 'mandatory', 'isCookie', 'isHeader',
               'performStaging', 'active', 'allowed', 'isAllowed', 'createdBy', 'lastUpdateMicros',
               'selfLink']

OBJECT_FIELDS = ['name', 'id', 'ipAddress', 'type', 'protocol', 'method', 'actAsMethod',
                 'serverTechnologyName',
                 'queryStringLength', 'checkRequestLength', 'responseCheck', 'urlLength',
                 'checkUrlLength', 'postDataLength', 'enforcementType', 'isBase64',
                 'description', 'includeSubdomains', 'clickjackingProtection',
                 'ipMask', 'blockRequests', 'ignoreAnomalies',
                 'neverLogRequests', 'neverLearnRequests', 'trustedByPolicyBuilder',
                 'dataType', 'attackSignaturesCheck', 'metacharElementCheck',
                 'hasValidationFiles', 'followSchemaLinks', 'isBase64',
                 'enableWSS', 'valueType', 'mandatory', 'isCookie', 'isHeader',
                 'includeSubdomains', 'createdBy', 'performStaging', 'allowed', 'isAllowed',
                 'createdBy', 'lastUpdateMicros', 'selfLink']

BLOCKING_SETTINGS_REFERENCE = {'evasions': 'evasionReference', 'violations': 'violationReference',
                               'web-services-securities': 'webServicesSecurityReference',
                               'http-protocols': 'httpProtocolReference'}


class Client(BaseClient):
    """
    Client for f5 RESTful API!.
    Args:
          base_url (str): f5 server url.
          token (str): f5 user token.
          use_ssl (bool): specifies whether to verify the SSL certificate or not.
          use_proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, token: str, use_ssl: bool, use_proxy: bool, **kwargs):
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy, **kwargs)
        self.headers = {'Content-Type': 'application/json',
                        'X-F5-Auth-Token': token}

    def get_id(self, md5: str, resource_name: str, action: str, compare_value: str):
        """
            Get the ID of a specific element (similar to getting the ID of the policy).

            Args:
                md5(str): MD5 hash of the policy the element is a member of.
                resource_name (str): Name of the element the ID is from.
                action(str): endpoint where the element resides.
                compare_value(str): Dict field to compare values in (name, ipAddress etc).

            Returns:
                str: MD5 hash (can also be called ID) of the element.
        """
        url_suffix = 'asm/server-technologies' if action == 'server-technologies-general' \
            else f'asm/policies/{md5}/{action}/'
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params={})
        index = -1
        for element in response.get('items'):
            if action == 'server-technologies':
                server_tech_reference = element.get('serverTechnologyReference')
                if server_tech_reference:
                    server_tech_name = server_tech_reference.get('serverTechnologyName')
                    if server_tech_name == resource_name:
                        index = response.get('items').index(element)
            else:
                if element.get(compare_value) == resource_name:
                    index = response.get('items').index(element)
        if index == -1:
            raise ValueError('Could not retrieve resource ID.')

        return (response.get('items')[index]).get('id')

    def set_id(self, md5: str, resource_id: str, resource_name: str,
               action: str, compare_value: str = 'name') -> str:
        """Helper function to get ID from user or from a resource name"""
        if resource_id != 'None':
            return resource_id
        elif resource_name != 'None':
            return self.get_id(md5, resource_name, action, compare_value)
        else:
            raise ValueError('Please fill resource name or resource id')

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

    def list_policy_blocking_settings(self, policy_md5: str, endpoint: str):
        url_suffix = f'asm/policies/{policy_md5}/blocking-settings/{endpoint}'
        return self._http_request(method='GET', url_suffix=url_suffix, headers=self.headers)

    def update_policy_blocking_setting(self, policy_md5: str, endpoint: str,
                                       description: str, enabled: Optional[bool],
                                       learn: Optional[bool], alarm: Optional[bool],
                                       block: Optional[bool]):
        object_id = self.get_id(policy_md5, action=f'blocking-settings/{endpoint}',
                                resource_name=description, compare_value='description')
        json_body = {'enabled': enabled, 'learn': learn, 'alarm': alarm, 'block': block}
        url_suffix = f'asm/policies/{policy_md5}/blocking-settings/{endpoint}/{object_id}'
        return self._http_request(method='PATCH', url_suffix=url_suffix,
                                  headers=self.headers, json_data=remove_empty_elements(json_body))

    def list_policies(self, self_link: str, kind: str, items):
        if not items:
            items = []
        return self._http_request(method='GET', url_suffix='asm/policies',
                                  headers=self.headers, params={"selfLink": self_link,
                                                                "kind": kind, "items": items})

    def create_policy(self, name: str, kind: str, enforcement_mode: str,
                      protocol_independent: bool, parent: Optional[str],
                      description: Optional[str], allow: Optional[bool], active: Optional[bool]):
        body = {'name': name,
                'description': description,
                'enforcementMode': enforcement_mode,
                'protocolIndependent': protocol_independent,
                'allow': allow,
                'active': active
                }
        if kind != 'child':
            body.update({'type': kind})
        else:
            body.update({'parentPolicyName': parent})
        return self._http_request(method='POST', url_suffix='asm/policies',
                                  headers=self.headers, json_data=remove_empty_elements(body))

    def apply_policy(self, policy_reference_link: str):
        body = {'policyReference': {'link': policy_reference_link}}
        return self._http_request(method='POST', url_suffix='asm/tasks/apply-policy',
                                  headers=self.headers, json_data=body)

    def export_policy(self, filename: str, minimal: bool, policy_reference_link: str):
        body = {'filename': filename, 'minimal': minimal,
                'policyReference': {'link': policy_reference_link}}
        return self._http_request(method='POST', url_suffix='asm/tasks/export-policy',
                                  headers=self.headers, json_data=body)

    def delete_policy(self, policy_md5: str):
        return self._http_request(method='DELETE', url_suffix=f'asm/policies/{policy_md5}',
                                  headers=self.headers, json_data={})

    def get_policy_md5(self):
        return self._http_request(method='GET', url_suffix='asm/policies',
                                  headers=self.headers, params={})

    def list_policy_methods(self, policy_md5: str):
        return self._http_request(method='GET', headers=self.headers, json_data={},
                                  url_suffix=f'asm/policies/{policy_md5}/methods')

    def add_policy_method(self, policy_md5: str, new_method_name: str,
                          act_as_method: str):
        body = {'name': new_method_name, 'actAsMethod': act_as_method.upper()}
        return self._http_request(method='POST', headers=self.headers, json_data=body,
                                  url_suffix=f'asm/policies/{policy_md5}/methods')

    def update_policy_method(self, policy_md5: str, method_id: str, method_name: str,
                             act_as_method: str):
        method_id = self.set_id(policy_md5, method_id, method_name, 'methods')
        body = {'name': method_name, 'actAsMethod': act_as_method.upper()}
        return self._http_request(method='PATCH', headers=self.headers, json_data=body,
                                  url_suffix=f'asm/policies/{policy_md5}/methods/{method_id}')

    def delete_policy_method(self, policy_md5: str, method_id: str, method_name: str):
        method_id = self.set_id(policy_md5, method_id, method_name, 'methods')
        return self._http_request(method='DELETE', headers=self.headers, json_data={},
                                  url_suffix=f'asm/policies/{policy_md5}/methods/{method_id}')

    def list_policy_file_types(self, policy_md5: str):
        return self._http_request(method='GET', headers=self.headers, json_data={},
                                  url_suffix=f'asm/policies/{policy_md5}/filetypes')

    def add_policy_file_type(self, policy_md5: str, new_file_type: str, query_string_length: int,
                             check_post_data_length: bool, response_check: bool,
                             check_request_length: bool, post_data_length: int,
                             perform_staging: bool):
        body = {'name': new_file_type,
                'queryStringLength': query_string_length,
                'checkPostDataLength': check_post_data_length,
                'responseCheck': response_check,
                'checkRequestLength': check_request_length,
                'postDataLength': post_data_length,
                'performStaging': perform_staging}

        return self._http_request(method='POST', headers=self.headers,
                                  json_data=remove_empty_elements(body),
                                  url_suffix=f'asm/policies/{policy_md5}/filetypes')

    def update_policy_file_type(self, policy_md5: str, file_type_id: str,
                                file_type_name: str, query_string_length: int,
                                check_post_data_length: bool, response_check: bool,
                                check_request_length: bool, post_data_length: int,
                                perform_staging: bool):
        file_type_id = self.set_id(policy_md5, file_type_id, file_type_name, 'filetypes')
        body = {'name': file_type_name,
                'queryStringLength': query_string_length,
                'checkPostDataLength': check_post_data_length,
                'responseCheck': response_check,
                'checkRequestLength': check_request_length,
                'postDataLength': post_data_length,
                'performStaging': perform_staging}
        return self._http_request(method='PATCH', headers=self.headers, json_data=body,
                                  url_suffix=f'asm/policies/{policy_md5}/filetypes/{file_type_id}')

    def delete_policy_file_type(self, policy_md5: str, file_type_id: str, file_type_name: str):
        file_type_id = self.set_id(policy_md5, file_type_id, file_type_name, 'filetypes')
        url_suffix = f'asm/policies/{policy_md5}/filetypes/{file_type_id}'
        return self._http_request(method='DELETE', headers=self.headers, json_data={},
                                  url_suffix=url_suffix)

    def list_policy_cookies(self, policy_md5: str):
        return self._http_request(method='GET', headers=self.headers, json_data={},
                                  url_suffix=f'asm/policies/{policy_md5}/cookies')

    def add_policy_cookie(self, policy_md5: str, new_cookie_name: str,
                          perform_staging: bool, parameter_type: str, enforcement_type: str,
                          attack_signatures_check: bool):
        body = {'name': new_cookie_name,
                'performStaging': perform_staging,
                'type': parameter_type,
                'enforcementType': enforcement_type,
                'attackSignaturesCheck': attack_signatures_check
                }
        return self._http_request(method='POST', headers=self.headers, json_data=body,
                                  url_suffix=f'asm/policies/{policy_md5}/cookies')

    def update_policy_cookie(self, policy_md5: str, cookie_id: str, cookie_name: str,
                             perform_staging: bool, parameter_type: str, enforcement_type: str,
                             attack_signatures_check: bool):
        file_type_id = self.set_id(policy_md5, cookie_id, cookie_name, 'cookies')
        body = {'name': cookie_name,
                'performStaging': perform_staging,
                'type': parameter_type,
                'enforcementType': enforcement_type,
                'attackSignaturesCheck': attack_signatures_check
                }
        return self._http_request(method='PATCH', headers=self.headers, json_data=body,
                                  url_suffix=f'asm/policies/{policy_md5}/cookies/{file_type_id}')

    def delete_policy_cookie(self, policy_md5: str, cookie_id: str, cookie_name: str):
        file_type_id = self.set_id(policy_md5, cookie_id, cookie_name, 'cookies')
        return self._http_request(method='DELETE', headers=self.headers, json_data={},
                                  url_suffix=f'asm/policies/{policy_md5}/cookies/{file_type_id}')

    def list_policy_hostnames(self, policy_md5: str):
        return self._http_request(method='GET', headers=self.headers, json_data={},
                                  url_suffix=f'asm/policies/{policy_md5}/host-names')

    def add_policy_hostname(self, policy_md5: str, name: str, include_subdomains: bool):
        data = {'name': name, 'includeSubdomains': include_subdomains}
        return self._http_request(method='POST', headers=self.headers, json_data=data,
                                  url_suffix=f'asm/policies/{policy_md5}/host-names')

    def update_policy_hostname(self, policy_md5: str, hostname_id: str, hostname_name: str,
                               include_subdomains: bool):
        hostname_id = self.set_id(policy_md5, hostname_id, hostname_name, 'host-names')
        url_suffix = f'asm/policies/{policy_md5}/host-names/{hostname_id}'
        return self._http_request(method='PATCH', headers=self.headers, url_suffix=url_suffix,
                                  json_data={'includeSubdomains': include_subdomains})

    def delete_policy_hostname(self, policy_md5: str, hostname_id: str, hostname_name: str):
        """
        Delete a hostname from a selected policy.

        Args:
            policy_md5 (str): MD5 hash of the policy.
            hostname_id (str): Host id to delete.
            hostname_name (str): Host name to delete.
        """
        hostname_id = self.set_id(policy_md5, hostname_id, hostname_name, 'host-names')
        url_suffix = f'asm/policies/{policy_md5}/host-names/{hostname_id}'
        return self._http_request(method='DELETE', headers=self.headers, url_suffix=url_suffix)

    def list_policy_urls(self, policy_md5: str):
        return self._http_request(method='GET', headers=self.headers, json_data={},
                                  url_suffix=f'asm/policies/{policy_md5}/urls')

    def add_policy_url(self, policy_md5: str, name: str, protocol: str, url_type: str,
                       is_allowed: bool, description: Optional[str],
                       perform_staging: Optional[bool], clickjacking_protection: Optional[bool],
                       method: Optional[str]):

        json_body = {'name': name, 'protocol': protocol, 'description': description,
                     'method': method, 'type': url_type, 'isAllowed': is_allowed,
                     'clickjackingProtection': clickjacking_protection,
                     'performStaging': perform_staging}

        return self._http_request(method='POST', headers=self.headers,
                                  json_data=remove_empty_elements(json_body),
                                  url_suffix=f'asm/policies/{policy_md5}/urls')

    def update_policy_url(self, policy_md5: str, url_id: str, url_name: str,
                          perform_staging, description, mandatory_body, url_isreferrer):
        url_id = self.set_id(policy_md5, url_id, url_name, 'urls')
        json_body = {'performStaging': perform_staging,
                     'description': description,
                     'mandatoryBody': mandatory_body,
                     'urlIsReferrer': url_isreferrer}

        return self._http_request(method='PATCH', headers=self.headers,
                                  url_suffix=f'asm/policies/{policy_md5}/urls/{url_id}',
                                  json_data=remove_empty_elements(json_body))

    def delete_policy_url(self, policy_md5: str, url_id: str, url_name: str):
        url_id = self.set_id(policy_md5, url_id, url_name, 'urls')
        return self._http_request(method='DELETE', headers=self.headers, json_data={},
                                  url_suffix=f'asm/policies/{policy_md5}/urls/{url_id}')

    def list_policy_whitelist_ips(self, policy_md5: str):
        return self._http_request(method='GET', headers=self.headers, json_data={},
                                  url_suffix=f'asm/policies/{policy_md5}/whitelist-ips')

    def add_policy_whitelist_ip(self, policy_md5: str, ip_address: str, ip_mask,
                                trusted_by_builder, ignore_brute_detection, description,
                                block_requests, ignore_learning, never_log, ignore_intelligence):
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
        return self._http_request(method='POST', headers=self.headers,
                                  url_suffix=f'asm/policies/{policy_md5}/whitelist-ips',
                                  json_data=remove_empty_elements(json_body))

    def update_policy_whitelist_ip(self, policy_md5: str, ip_id: str, ip_address: str,
                                   trusted_by_builder, ignore_brute_detection, description,
                                   block_requests, ignore_learning, never_log,
                                   ignore_intelligence):
        ip_id = self.set_id(policy_md5, ip_id, ip_address, 'whitelist-ips',
                            compare_value='ipAddress')

        json_body = {'ignoreIpReputation': ignore_intelligence,
                     'blockRequests': block_requests,
                     'ignoreAnomalies': ignore_brute_detection,
                     'description': description,
                     'neverLearnRequests': ignore_learning,
                     'neverLogRequests': never_log,
                     'trustedByPolicyBuilder': trusted_by_builder}
        return self._http_request(method='PATCH', headers=self.headers,
                                  url_suffix=f'asm/policies/{policy_md5}/whitelist-ips/{ip_id}',
                                  json_data=remove_empty_elements(json_body))

    def delete_policy_whitelist_ip(self, policy_md5: str, ip_id: str, ip_address: str):
        ip_id = self.set_id(policy_md5, ip_id, ip_address, 'whitelist-ips',
                            compare_value='ipAddress')
        return self._http_request(method='DELETE', headers=self.headers, json_data={},
                                  url_suffix=f'asm/policies/{policy_md5}/whitelist-ips/{ip_id}')

    def list_policy_signatures(self, policy_md5: str):
        return self._http_request(method='GET', headers=self.headers, json_data={},
                                  url_suffix=f'asm/policies/{policy_md5}/signatures')

    def list_policy_parameters(self, policy_md5: str):
        return self._http_request(method='GET', headers=self.headers, json_data={},
                                  url_suffix=f'asm/policies/{policy_md5}/parameters')

    def add_policy_parameter(self, policy_md5: str, name: str, param_type, value_type,
                             param_location, perform_staging, mandatory, allow_empty,
                             allow_repeated, sensitive):

        json_body = {'name': name, 'type': param_type,
                     'valueType': value_type,
                     'parameterLocation': param_location, 'mandatory': mandatory,
                     'performStaging': perform_staging, 'sensitiveParameter': sensitive,
                     'allowEmptyValue': allow_empty,
                     'allowRepeatedParameterName': allow_repeated}
        return self._http_request(method='POST', headers=self.headers,
                                  json_data=remove_empty_elements(json_body),
                                  url_suffix=f'asm/policies/{policy_md5}/parameters')

    def update_policy_parameter(self, policy_md5: str, parameter_id: str, parameter_name: str,
                                value_type: str, param_location: str, perform_staging: bool,
                                mandatory: bool, allow_empty: bool, allow_repeated: bool,
                                sensitive: bool):
        parameter_id = self.set_id(policy_md5, parameter_id, parameter_name, 'parameters')
        json_body = {'name': parameter_name, 'valueType': value_type,
                     'parameterLocation': param_location, 'mandatory': mandatory,
                     'performStaging': perform_staging, 'sensitiveParameter': sensitive,
                     'allowEmptyValue': allow_empty,
                     'allowRepeatedParameterName': allow_repeated}
        url_suffix = f'asm/policies/{policy_md5}/parameters/{parameter_id}'
        return self._http_request(method='PATCH', headers=self.headers, url_suffix=url_suffix,
                                  json_data=remove_empty_elements(json_body))

    def delete_policy_parameter(self, policy_md5: str, parameter_id: str, parameter_name: str):
        parameter_id = self.set_id(policy_md5, parameter_id, parameter_name, 'parameters')
        url_suffix = f'asm/policies/{policy_md5}/parameters/{parameter_id}'
        return self._http_request(method='DELETE', headers=self.headers, json_data={},
                                  url_suffix=url_suffix)

    def list_policy_gwt_profiles(self, policy_md5: str):
        return self._http_request(method='GET', headers=self.headers, json_data={},
                                  url_suffix=f'asm/policies/{policy_md5}/gwt-profiles')

    def add_policy_gwt_profile(self, policy_md5: str, name: str, maximum_value_len: str,
                               maximum_total_len: str, description: str,
                               tolerate_parsing_warnings: bool, check_signatures: bool,
                               check_metachars: bool):
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
        return self._http_request(method='POST', headers=self.headers,
                                  url_suffix=f'asm/policies/{policy_md5}/gwt-profiles',
                                  json_data=remove_empty_elements(json_body))

    def update_policy_gwt_profile(self, policy_md5: str, gwt_profile_id: str,
                                  gwt_profile_name: str, maximum_value_len: str,
                                  maximum_total_len: str, description: str,
                                  tolerate_parsing_warnings: bool, check_signatures: bool,
                                  check_metachars: bool):
        profile_id = self.set_id(policy_md5, gwt_profile_id, gwt_profile_name, 'gwt-profiles')

        json_body = {'description': description,
                     'defenseAttributes':
                         {
                             'maximumValueLength': maximum_value_len,
                             'maximumTotalLengthOfGWTData': maximum_total_len,
                             'tolerateGWTParsingWarnings': tolerate_parsing_warnings == 'true'
                         },
                     'attackSignaturesCheck': check_signatures,
                     'metacharElementCheck': check_metachars}
        url_suffix = f'asm/policies/{policy_md5}/gwt-profiles/{profile_id}'
        return self._http_request(method='PATCH', headers=self.headers, url_suffix=url_suffix,
                                  json_data=remove_empty_elements(json_body))

    def delete_policy_gwt_profile(self, policy_md5: str, gwt_profile_id: str,
                                  gwt_profile_name: str):
        profile_id = self.set_id(policy_md5, gwt_profile_id, gwt_profile_name, 'gwt-profiles')
        url_suffix = f'asm/policies/{policy_md5}/gwt-profiles/{profile_id}'
        return self._http_request(method='DELETE', headers=self.headers,
                                  url_suffix=url_suffix)

    def list_policy_json_profiles(self, policy_md5: str):
        return self._http_request(method='GET', headers=self.headers,
                                  url_suffix=f'asm/policies/{policy_md5}/json-profiles')

    def add_policy_json_profile(self, policy_md5: str, name: str, maximum_total_len: str,
                                maximum_value_len: str, max_structure_depth: str,
                                max_array_len: str, description: str,
                                tolerate_parsing_warnings: bool, parse_parameters: bool,
                                check_signatures: bool, check_metachars: bool):
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
        return self._http_request(method='POST', headers=self.headers,
                                  url_suffix=f'asm/policies/{policy_md5}/json-profiles',
                                  json_data=remove_empty_elements(json_body))

    def update_policy_json_profile(self, policy_md5: str, json_id: str, json_name: str,
                                   maximum_total_len: str,
                                   maximum_value_len: str, max_structure_depth: str,
                                   max_array_len: str, description: str,
                                   tolerate_parsing_warnings: bool, parse_parameters: bool,
                                   check_signatures: bool, check_metachars: bool):
        json_id = self.set_id(policy_md5, json_id, json_name, 'json-profiles')
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
        url_suffix = f'asm/policies/{policy_md5}/json-profiles/{json_id}'
        return self._http_request(method='PATCH', headers=self.headers, url_suffix=url_suffix,
                                  json_data=remove_empty_elements(json_body))

    def delete_policy_json_profile(self, policy_md5: str, json_id: str, json_name: str):
        json_id = self.set_id(policy_md5, json_id, json_name, 'json-profiles')
        url_suffix = f'asm/policies/{policy_md5}/json-profiles/{json_id}'
        return self._http_request(method='DELETE', headers=self.headers,
                                  url_suffix=url_suffix)

    def list_policy_xml_profiles(self, policy_md5: str):
        return self._http_request(method='GET', headers=self.headers,
                                  url_suffix=f'asm/policies/{policy_md5}/xml-profiles')

    def add_policy_xml_profile(self, policy_md5: str, name: str, description,
                               check_signatures, check_metachar_elements,
                               check_metachar_attributes, enable_wss, inspect_soap, follow_links,
                               use_xml_response, allow_cdata, allow_dtds, allow_external_ref,
                               allow_processing_instructions):
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
        return self._http_request(method='POST', headers=self.headers,
                                  url_suffix=f'asm/policies/{policy_md5}/xml-profiles',
                                  json_data=remove_empty_elements(json_body))

    def update_policy_xml_profile(self, policy_md5: str, xml_id: str, xml_name: str, description,
                                  check_signatures, check_metachar_elements,
                                  check_metachar_attributes, enable_wss, inspect_soap,
                                  follow_links, use_xml_response, allow_cdata, allow_dtds,
                                  allow_external_ref, allow_processing_instructions):
        xml_id = self.set_id(policy_md5, xml_id, xml_name, 'xml-profiles')
        json_body = {'description': description,
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
        url_suffix = f'asm/policies/{policy_md5}/xml-profiles/{xml_id}'
        return self._http_request(method='PATCH', headers=self.headers, url_suffix=url_suffix,
                                  json_data=remove_empty_elements(json_body))

    def delete_policy_xml_profile(self, policy_md5: str, xml_id: str, xml_name: str):
        xml_id = self.set_id(policy_md5, xml_id, xml_name, 'xml-profiles')
        url_suffix = f'asm/policies/{policy_md5}/xml-profiles/{xml_id}'
        return self._http_request(method='DELETE', headers=self.headers,
                                  url_suffix=url_suffix)

    def list_policy_server_technologies(self, policy_md5: str):
        url_suffix = f'asm/policies/{policy_md5}/server-technologies'
        return self._http_request(method='GET', headers=self.headers,
                                  url_suffix=url_suffix)

    def add_policy_server_technology(self, policy_md5: str, technology_id: str,
                                     technology_name: str):
        url_suffix = f'asm/policies/{policy_md5}/server-technologies'
        technology_id = self.set_id(policy_md5, technology_id, technology_name,
                                    'server-technologies-general',
                                    'serverTechnologyDisplayName')
        json_body = {'serverTechnologyReference': {'link': technology_id}}
        return self._http_request(method='POST', headers=self.headers,
                                  url_suffix=url_suffix, json_data=json_body)

    def delete_policy_server_technology(self, policy_md5: str, technology_id, technology_name):
        technology_id = self.set_id(policy_md5, technology_id, technology_name,
                                    'server-technologies',
                                    'serverTechnologyDisplayName')
        url_suffix = f'asm/policies/{policy_md5}/server-technologies/{technology_id}'
        return self._http_request(method='DELETE', headers=self.headers,
                                  url_suffix=url_suffix, json_data={})


def test_module(client: Client):
    """Returning 'ok' indicates the integration works like it is supposed to."""
    try:
        client.list_policies("", "", None)
    except DemistoException as exception:
        if 'Authorization Required' in str(exception) or 'Authentication failed' in str(exception):
            return f'Authorization Error: please check your credentials.\n\nError:\n{exception}'

        if 'HTTPSConnectionPool' in str(exception):
            return f'Connection Error: please check your server ip address.\n\nError: {exception}'

        return (f'Something went Wrong! Please check the credentials and IP address'
                f' you provided\n\nError: {exception}')
    return 'ok'


def login(server_ip: str, username: str, password: str, verify_certificate: bool) -> str:
    """Log into the F5 instance in order to get a session token for further auth."""
    response = requests.post(f'https://{server_ip}/mgmt/shared/authn/login',
                             verify=verify_certificate,
                             json={'username': username, 'password': password,
                                   'loginProviderName': 'tmos'}).json()
    token = dict_safe_get(response, ['token', 'token'], '', str)
    if not token:
        raise DemistoException(f'Authorization Error: please check your credentials. \n\nError:\n{response}')

    return token


def f5_get_policy_md5_command(client: Client, policy_name: str) -> CommandResults:
    """
    Formats f5 policy md5 to XSOAR outputs.

    Args:
        client (Client): f5 client.
        policy_name (str): policy name.
    """
    result = client.get_policy_md5()
    if result:
        result = result.get('items')
    readable_output = ''
    md5_dict = {}
    index = -1

    if result:
        for element in result:
            if element.get('name') == policy_name:
                index = result.index(element)

        response = (result[index].get('plainTextProfileReference').get('link'))
        if index >= 0:
            md5 = response.partition('policies/')[2].partition('/')[0]
            md5_dict = {'md5': md5}
            table_name = 'f5 policy md5:'
        else:
            table_name = f'No data for policy: {policy_name}'
        readable_output = tableToMarkdown(table_name, md5_dict)

    command_results = CommandResults(
        outputs_prefix='f5.Policy',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=md5_dict,
        raw_response=result
    )
    return command_results


def f5_list_policies_command(client: Client, self_link: str = "", kind: str = "",
                             items=None) -> CommandResults:
    """
    Lists all policies in the current server.

    Args:
        client(Client): CheckPoint client.
        self_link(str): A link to this resource.
        kind(str): A unique type identifier.
        items(list): items

    Returns:
        CommandResults: response
    """
    items = argToList(items)
    result = client.list_policies(self_link, kind, items)

    printable_result = []
    readable_output = 'No results'

    headers = ['name', 'id', 'type', 'enforcementMode', 'creatorName', 'active', 'createdTime',
               'selfLink']
    result = result.get('items')
    if result:
        for element in result:
            current_printable_result = {}
            for endpoint in headers:
                current_printable_result[endpoint] = element.get(endpoint)
            printable_result.append(current_printable_result)

        readable_output = tableToMarkdown('f5 data for listing policies:', printable_result,
                                          headers, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='f5.Policy',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_create_policy_command(client: Client, name: str, kind: str, enforcement_mode: str,
                             protocol_independent: bool, parent: str = None,
                             description: str = None, allow: bool = None,
                             active: bool = None) -> CommandResults:
    """
    Creates a new ASM policy.

    Args:
        client (Client): f5 client.
        name (str): Name of the new policy.
        kind(str): Parent / Child.
        enforcement_mode(str): Transparent / Blocking.
        protocol_independent(bool): Is the policy independent from protocols.
        parent(str): If child, specify the parent.
        description (str): Optional description.
        allow (bool): indicates if to allow the new policy.
        active (bool): indicates if to activate the new policy.
    """
    result = client.create_policy(name, kind, enforcement_mode, protocol_independent, parent,
                                  description, allow, active)
    headers = ['name', 'id', 'fullPath', 'type', 'description', 'versionDatetime', 'selfLink']
    outputs, headers = build_output(headers, result)
    readable_output = tableToMarkdown('f5 data for creating policy:', outputs, headers,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='f5.Policy',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )
    return command_results


def f5_apply_policy_command(client: Client, policy_reference_link: str) -> CommandResults:
    """
    Apply a policy.

    Args:
        client (Client): f5 client.
        policy_reference_link(str): link to the policy the user wish to apply.
    """
    result = client.apply_policy(policy_reference_link)
    headers = ['status', 'id', 'startTime', 'kind']
    outputs, headers = build_output(headers, result)
    readable_output = tableToMarkdown('f5 data for applying policy:', outputs, headers,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='f5.Policy',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )
    return command_results


def f5_export_policy_command(client: Client, filename: str, policy_reference_link: str,
                             minimal: bool) -> CommandResults:
    """
    Export a policy.

    Args:
        client (Client): f5 client.
        filename (str): name of the file to export to.
        policy_reference_link(str): link to policy user wishes to export
        minimal(bool):Indicates whether to export only custom settings.
    """
    result = client.export_policy(filename, minimal, policy_reference_link)
    headers = ['status', 'id', 'startTime', 'kind', 'format', 'filename']

    outputs, headers = build_output(headers, result)
    readable_output = tableToMarkdown('f5 data for exporting policy:', outputs, headers,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='f5.Policy',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )
    return command_results


def f5_delete_policy_command(client: Client, policy_md5: str) -> CommandResults:
    """
    Delete a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
    """
    result = client.delete_policy(policy_md5)
    headers = ['name', 'id', 'selfLink']

    outputs, headers = build_output(headers, result)
    readable_output = tableToMarkdown('f5 data for deleting policy:', outputs, headers,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='f5.Policy',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )
    return command_results


def f5_list_policy_methods_command(client: Client, policy_md5: str) -> CommandResults:
    """
    Get a list of all policy methods.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
    """
    result = client.list_policy_methods(policy_md5)

    table_name = 'f5 data for listing policy methods:'
    readable_output, printable_result = build_command_result(result, table_name)

    command_results = CommandResults(
        outputs_prefix='f5.PolicyMethods',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_add_policy_method_command(client: Client, policy_md5: str, new_method_name: str,
                                 act_as_method: str) -> CommandResults:
    """
    Add allowed method to a certain policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        new_method_name (str): Display name of the new method.
        act_as_method(str): functionality of the new method. default is GET.
    """
    result = client.add_policy_method(policy_md5, new_method_name, act_as_method)
    outputs, headers = build_output(OBJECT_FIELDS, result)

    readable_output = tableToMarkdown('f5 data for adding policy methods:', outputs, headers,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.PolicyMethods',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_update_policy_method_command(client: Client, policy_md5: str, method_id: str,
                                    method_name: str, act_as_method: str) -> CommandResults:
    """
    Update allowed method from a certain policy..

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        method_id (str): ID of the method.
        method_name (str): Display name of the method.
        act_as_method(str): functionality of the new method.
    """
    result = client.update_policy_method(policy_md5, method_id, method_name, act_as_method)
    outputs, headers = build_output(OBJECT_FIELDS, result)

    readable_output = tableToMarkdown('f5 data for updating policy methods:', outputs, headers,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.PolicyMethods',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_delete_policy_method_command(client: Client, policy_md5: str, method_id: str,
                                    method_name: str) -> CommandResults:
    """
    delete method from a certain policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        method_id (str): ID of the method.
        method_name (str): Display name of the method.
    """
    result = client.delete_policy_method(policy_md5, method_id, method_name)
    outputs, headers = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for deleting policy methods:', outputs, headers,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.PolicyMethods',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_list_policy_file_types_command(client: Client, policy_md5: str) -> CommandResults:
    """
    Get a list of all policy file types.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
    """
    result = client.list_policy_file_types(policy_md5)

    table_name = 'f5 data for listing policy file types:'
    readable_output, printable_result = build_command_result(result, table_name)

    command_results = CommandResults(
        outputs_prefix='f5.FileType',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_add_policy_file_type_command(client: Client, policy_md5: str, new_file_type: str,
                                    query_string_length: int,
                                    check_post_data_length: bool, response_check: bool,
                                    check_request_length: bool, post_data_length: int,
                                    perform_staging: bool) -> CommandResults:
    """
    Add allowed file types to a certain policy.

    Args:
        client (Client): f5 client.
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
    result = client.add_policy_file_type(policy_md5, new_file_type, query_string_length,
                                         check_post_data_length, response_check,
                                         check_request_length, post_data_length, perform_staging)
    outputs, headers = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for adding policy file types:', outputs, headers,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.FileType',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_update_policy_file_type_command(client: Client, policy_md5: str, file_type_id: str,
                                       file_type_name: str,
                                       query_string_length: int, check_post_data_length: bool,
                                       response_check: bool, check_request_length: bool,
                                       post_data_length: int,
                                       perform_staging: bool) -> CommandResults:
    """
    Update a given file type from a certain policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        file_type_id (str): ID of the file type.
        file_type_name (str): The new file type to add.
        query_string_length (int): Query string length. default is 100.
        check_post_data_length (bool): indicates if the user wishes check the length of
                                        data in post method. default is True.
        response_check (bool): Indicates if the user wishes to check the response.
        check_request_length (bool): Indicates if the user wishes to check the request length.
        post_data_length (int): post data length.
        perform_staging (bool): Indicates if the user wishes the new file type to be at staging.
    """
    result = client.update_policy_file_type(policy_md5, file_type_id, file_type_name,
                                            query_string_length, check_post_data_length,
                                            response_check, check_request_length, post_data_length,
                                            perform_staging)
    outputs, headers = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for updating policy methods:', outputs, headers,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.FileType',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_delete_policy_file_type_command(client: Client, policy_md5: str, file_type_id: str,
                                       file_type_name: str) -> CommandResults:
    """
    Delete file type from a certain policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        file_type_id (str): ID of the file type.
        file_type_name (str): The file type to delete.
    """
    result = client.delete_policy_file_type(policy_md5, file_type_id, file_type_name)

    outputs, headers = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for deleting policy file type:', outputs, headers,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.FileType',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_list_policy_cookies_command(client: Client, policy_md5: str) -> CommandResults:
    """
    Get a list of all policy cookies.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
    """
    result = client.list_policy_cookies(policy_md5)
    table_name = 'f5 data for listing policy cookies:'
    readable_output, printable_result = build_command_result(result, table_name)

    command_results = CommandResults(
        outputs_prefix='f5.Cookies',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_add_policy_cookie_command(client: Client, policy_md5: str, new_cookie_name: str,
                                 perform_staging: bool, parameter_type: str, enforcement_type: str,
                                 attack_signatures_check: bool) -> CommandResults:
    """
    Add new cookie to a specific policy

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        new_cookie_name (str): The new cookie name to add.
        perform_staging (bool): Indicates if the user wishes the new file type to be at staging.
        parameter_type (str): Type of the new parameter.
        enforcement_type (str): Enforcement type.
        attack_signatures_check (bool): Should attack signatures be checked. If enforcement type
         is set to 'enforce', this field will not get any value.
    """
    result = client.add_policy_cookie(policy_md5, new_cookie_name, perform_staging, parameter_type,
                                      enforcement_type, attack_signatures_check)
    outputs, headers = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown(f'f5 data for adding policy cookie: {new_cookie_name}',
                                      outputs, headers, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.Cookies',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_update_policy_cookie_command(client: Client, policy_md5: str, cookie_id: str,
                                    cookie_name: str,
                                    perform_staging: bool, parameter_type: str,
                                    enforcement_type: str,
                                    attack_signatures_check: bool) -> CommandResults:
    """
    Update a given cookie of a specific policy

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        cookie_id (str): ID of the cookie.
        cookie_name (str): The new cookie name to add.
        perform_staging (bool): Indicates if the user wishes the new file type to be at staging.
        parameter_type (str): Type of the new parameter.
        enforcement_type (str): Enforcement type.
        attack_signatures_check (bool): Should attack signatures be checked. If enforcement type
         is set to 'enforce', this field will not get any value.
    """
    result = client.update_policy_cookie(policy_md5, cookie_id, cookie_name, perform_staging,
                                         parameter_type, enforcement_type, attack_signatures_check)
    outputs, headers = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for updating cookie:',
                                      outputs, headers, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.Cookies',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_delete_policy_cookie_command(client: Client, policy_md5: str, cookie_id: str,
                                    cookie_name: str) -> CommandResults:
    """
    Delete cookie from a certain policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        cookie_id (str): ID of the cookie.
        cookie_name (str): The new cookie name to add.
    """
    result = client.delete_policy_cookie(policy_md5, cookie_id, cookie_name)
    outputs, headers = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for deleting cookie:', outputs, headers,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.Cookies',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_list_policy_hostnames_command(client: Client, policy_md5: str) -> CommandResults:
    """
    Get a list of all policy hostnames.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
    """
    result = client.list_policy_hostnames(policy_md5)

    table_name = 'f5 data for listing policy hostname:'
    readable_output, printable_result = build_command_result(result, table_name)

    command_results = CommandResults(
        outputs_prefix='f5.Hostname',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_add_policy_hostname_command(client: Client, policy_md5: str, name: str,
                                   include_subdomains: bool) -> CommandResults:
    """
    Add new hostname to a specific policy

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        name (str): Name of the new host to add.
        include_subdomains (bool): Indicates whether or not to include subdomains.
    """
    result = client.add_policy_hostname(policy_md5, name, include_subdomains)
    outputs, headers = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for adding policy hostname:', outputs, headers,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.Hostname',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_update_policy_hostname_command(client: Client, policy_md5: str, hostname_id: str,
                                      hostname_name: str,
                                      include_subdomains: bool) -> CommandResults:
    """
    Update a hostname in a selected policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        hostname_id (str): Host ID to update.
        hostname_name (str): Host name to update.
        include_subdomains (bool): Indicates whether or not to include subdomains.
    """
    result = client.update_policy_hostname(policy_md5, hostname_id, hostname_name,
                                           include_subdomains)
    outputs, headers = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for updating hostname:', outputs, headers,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.Hostname',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_delete_policy_hostname_command(client: Client, policy_md5: str,
                                      hostname_id, hostname_name: str) -> CommandResults:
    """
    Delete a hostname from a selected policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        hostname_id (str): ID of the hostname to delete.
        hostname_name (str): Host name to delete.
    """
    result = client.delete_policy_hostname(policy_md5, hostname_id, hostname_name)
    outputs, headers = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for deleting hostname:', outputs, headers,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.Hostname',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_list_policy_urls_command(client: Client, policy_md5: str) -> CommandResults:
    """
    Get a list of all policy urls.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
    """
    result = client.list_policy_urls(policy_md5)

    table_name = 'f5 data for listing policy url:'
    readable_output, printable_result = build_command_result(result, table_name)

    command_results = CommandResults(
        outputs_prefix='f5.Url',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_add_policy_url_command(client: Client, policy_md5: str, name: str, protocol: str,
                              url_type: str, is_allowed: bool, description: str = None,
                              perform_staging: bool = None, clickjacking_protection: bool = None,
                              method: str = None) -> CommandResults:
    """
    Create a new URL in a selected policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        name (str): Name of the new URL.
        protocol(str): HTTP or HTTPS
        url_type(str): Explicit or wildcard.
        is_allowed(bool): Whether or not the URL is allowed.
        description (str): Optional description for the URL.
        perform_staging (bool): Whether or not to stage the URL.
        clickjacking_protection(bool): Whether or not to enable clickjacking protection.
        method(str): Method to be used in the.
    """
    result = client.add_policy_url(policy_md5, name, protocol, url_type, is_allowed, description,
                                   perform_staging, clickjacking_protection, method)
    outputs, headers = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for adding policy url:', outputs, headers,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.Url',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_update_policy_url_command(client: Client, policy_md5: str, url_id: str, url_name: str,
                                 perform_staging=None, description=None, mandatory_body=None,
                                 url_isreferrer=None) -> CommandResults:
    """
    Update an existing URL in a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        url_id (str): ID of the URL to update.
        url_name (str): Name of the URL to update.
        perform_staging (bool): Whether or not to stage the URL.
        description (str): Optional new description.
        mandatory_body(bool): Whether or not the body is mandatory
        url_isreferrer(bool): Whether or not the URL is a referrer.
    """

    # first character in url name should be '/'.
    url_name = url_name if url_name[0] == '/' else '/' + url_name

    result = client.update_policy_url(policy_md5, url_id, url_name, perform_staging, description,
                                      mandatory_body, url_isreferrer)
    outputs, headers = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for updating url:', outputs, headers,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.Url',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_delete_policy_url_command(client: Client, policy_md5: str, url_id: str,
                                 url_name: str) -> CommandResults:
    """
    Delete an existing URL in a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        url_id (str): ID of the URL to delete.
        url_name (str): Name of the URL to delete.
    """

    # first character in url name should be '/'.
    url_name = url_name if url_name[0] == '/' else '/' + url_name

    result = client.delete_policy_url(policy_md5, url_id, url_name)

    outputs, headers = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for deleting url:', outputs, headers,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.Url',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=remove_empty_elements(outputs),
        raw_response=result
    )
    return command_results


def f5_list_policy_whitelist_ips_command(client: Client, policy_md5: str) -> CommandResults:
    """
    List all whitelisted IPs for a certain policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
    """
    result = client.list_policy_whitelist_ips(policy_md5)

    table_name = 'f5 list of all whitelist IPs:'
    readable_output, printable_result = build_command_result(result, table_name)

    command_results = CommandResults(
        outputs_prefix='f5.WhitelistIP',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_add_policy_whitelist_ip_command(client: Client, policy_md5: str, ip_address: str,
                                       ip_mask=None, trusted_by_builder=None,
                                       ignore_brute_detection=None, description=None,
                                       block_requests=None, ignore_learning=None,
                                       never_log=None, ignore_intelligence=None) -> CommandResults:
    """
    Create a new whitelisted IP for a certain policy.

    Args:
        client (Client): f5 client
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
    result = client.add_policy_whitelist_ip(policy_md5, ip_address, ip_mask, trusted_by_builder,
                                            ignore_brute_detection, description, block_requests,
                                            ignore_learning, never_log, ignore_intelligence)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for listing whitelist IP:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.WhitelistIP',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_update_policy_whitelist_ip_command(client: Client, policy_md5: str, ip_id: str,
                                          ip_address: str,
                                          trusted_by_builder=None, ignore_brute_detection=None,
                                          description=None, block_requests=None,
                                          ignore_learning=None, never_log=None,
                                          ignore_intelligence=None) -> CommandResults:
    """
    Update an existing whitelisted IP for a certain policy.

    Args:
        client (Client): f5 client
        policy_md5 (str): MD5 hash of the policy.
        ip_id (str): ID of the IP to update.
        ip_address(str): IP address.
        trusted_by_builder(bool): Whether or not the IP is trusted by the policy builder.
        ignore_brute_detection(bool): Whether or not to ignore detections of brute force.
        description (str): Optional description for the new IP.
        block_requests(str): Method of blocking requests.
        ignore_learning(bool): Whether or not to ignore learning suggestions.
        never_log(bool): Whether or not to never log from the IP.
        ignore_intelligence(bool): Whether or not to ignore intelligence gathered on the IP.
    """
    result = client.update_policy_whitelist_ip(policy_md5, ip_id, ip_address, trusted_by_builder,
                                               ignore_brute_detection, description, block_requests,
                                               ignore_learning, never_log, ignore_intelligence)

    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for listing whitelist IP:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.WhitelistIP',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_delete_policy_whitelist_ip_command(client, policy_md5: str, ip_id: str,
                                          ip_address: str) -> CommandResults:
    """
    Delete an existing whitelisted IP from a policy.

    Args:
        client (Client): f5 client
        policy_md5 (str): MD5 hash of the policy.
        ip_id (str): ID of the IP to update.
        ip_address(str): IP address.
    """
    result = client.delete_policy_whitelist_ip(policy_md5, ip_id, ip_address)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for listing whitelist IP:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.WhitelistIP',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_list_policy_signatures_command(client, policy_md5: str) -> CommandResults:
    """
    List all signatures for a certain policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
    """
    result = client.list_policy_signatures(policy_md5)

    table_name = 'f5 list of all signatures:'
    readable_output, printable_result = build_command_result(result, table_name)

    command_results = CommandResults(
        outputs_prefix='f5.Signatures',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_list_policy_parameters_command(client, policy_md5: str) -> CommandResults:
    """
    List all parameters for a given policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
    """
    result = client.list_policy_parameters(policy_md5)

    table_name = 'f5 list of all parameters:'
    readable_output, printable_result = build_command_result(result, table_name)

    command_results = CommandResults(
        outputs_prefix='f5.Parameter',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_add_policy_parameter_command(client, policy_md5: str, name: str, param_type=None,
                                    value_type=None, param_location=None,
                                    perform_staging=None, mandatory=None, allow_empty=None,
                                    allow_repeated=None, sensitive=None) -> CommandResults:
    """
    Add a new parameter to a policy

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        param_type(str): Type of parameter.
        name (str): Name of parameter.
        value_type(str): Type of value the parameter receives.
        param_location (str): Where the parameter sits.
        perform_staging (bool): Whether or not to stage the parameter.
        mandatory (bool): Is the parameter mandatory.
        allow_empty (bool): Should the parameter allow empty values.
        allow_repeated (bool): Should the parameter allow repeated values.
        sensitive (bool): Should the parameter values be masked in logs.
    """
    result = client.add_policy_parameter(policy_md5, name, param_type, value_type, param_location,
                                         perform_staging, mandatory, allow_empty, allow_repeated,
                                         sensitive)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for adding parameter:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.Parameter',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_update_policy_parameter_command(client, policy_md5: str, parameter_id: str,
                                       parameter_name: str,
                                       value_type: str = None, param_location: str = None,
                                       perform_staging: bool = None, mandatory: bool = None,
                                       allow_empty: bool = None, allow_repeated: bool = None,
                                       sensitive: bool = None) -> CommandResults:
    """
    Update an existing parameter to a policy

    Args:
        client (Client): f5 client
        policy_md5 (str): MD5 hash of the policy.
        parameter_id (str): ID of parameter.
        parameter_name (str): Display name of parameter.
        value_type(str): Type of value the parameter receives.
        param_location(str): Where the parameter sits.
        perform_staging (bool): Whether or not to stage the parameter.
        mandatory(bool): Is the parameter mandatory.
        allow_empty(bool): Should the parameter allow empty values.
        allow_repeated(bool): Should the parameter allow repeated values.
        sensitive(bool): Should the parameter values be masked in logs.
    """
    result = client.update_policy_parameter(policy_md5, parameter_id, parameter_name, value_type,
                                            param_location, perform_staging, mandatory,
                                            allow_empty, allow_repeated, sensitive)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for updating parameter:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.Parameter',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_delete_policy_parameter_command(client, policy_md5: str, parameter_id,
                                       parameter_name) -> CommandResults:
    """
    Delete an existing parameter from a policy

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        parameter_id (str): ID of parameter.
        parameter_name (str): Display name of parameter.
    """
    result = client.delete_policy_parameter(policy_md5, parameter_id, parameter_name)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for deleting parameter:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.Parameter',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_list_policy_gwt_profiles_command(client, policy_md5: str) -> CommandResults:
    """
    List all GWT profiles from a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
    """
    result = client.list_policy_gwt_profiles(policy_md5)

    table_name = 'f5 list of all GWT Profiles:'
    readable_output, printable_result = build_command_result(result, table_name)

    command_results = CommandResults(
        outputs_prefix='f5.GWTProfile',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_add_policy_gwt_profile_command(client, policy_md5: str, name: str,
                                      maximum_value_len: str, maximum_total_len: str,
                                      description: str = None,
                                      tolerate_parsing_warnings: bool = None,
                                      check_signatures: bool = None,
                                      check_metachars: bool = None) -> CommandResults:
    """
    Add a new GWT profile to a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        name (str): Name of the profile.
        description (str): Optional description for the profile.
        maximum_value_len (str): Maximum length to a value.
        maximum_total_len (str): Maximum total profile data length.
        tolerate_parsing_warnings (bool): Should the profile tolerate parsing warnings.
        check_signatures (bool): Should attack signatures be checked.
        check_metachars (bool): Should metachar elements be checked.
    """
    result = client.add_policy_gwt_profile(policy_md5, name, maximum_value_len, maximum_total_len,
                                           description, tolerate_parsing_warnings,
                                           check_signatures, check_metachars)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for adding GWT profile:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.GWTProfile',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_update_policy_gwt_profile_command(client, policy_md5: str, gwt_profile_id: str,
                                         gwt_profile_name: str,
                                         maximum_value_len: str, maximum_total_len: str,
                                         description: str = None,
                                         tolerate_parsing_warnings: bool = None,
                                         check_signatures: bool = None,
                                         check_metachars: bool = None) -> CommandResults:
    """
    Update an existing GWT profile in a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        gwt_profile_id (str): ID of the profile.
        gwt_profile_name (str): Name of the profile.
        description (str): Optional description for the profile.
        maximum_value_len(str): Maximum length to a value.
        maximum_total_len(str): Maximum total profile data length.
        tolerate_parsing_warnings(bool): Should the profile tolerate parsing warnings.
        check_signatures (bool): Should attack signatures be checked.
        check_metachars(bool): Should metachar elements be checked.
    """
    result = client.update_policy_gwt_profile(policy_md5, gwt_profile_id, gwt_profile_name,
                                              maximum_value_len, maximum_total_len,
                                              description, tolerate_parsing_warnings,
                                              check_signatures, check_metachars)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for updating GWT profile:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.GWTProfile',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_delete_policy_gwt_profile_command(client, policy_md5: str, gwt_profile_id: str,
                                         gwt_profile_name: str) -> CommandResults:
    """
    Delete an existing GWT profile from a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        gwt_profile_id (str): ID of the profile.
        gwt_profile_name (str): Name of the profile.
    """
    result = client.delete_policy_gwt_profile(policy_md5, gwt_profile_id, gwt_profile_name)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for deleting GWT profile:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.GWTProfile',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_list_policy_json_profiles_command(client, policy_md5: str) -> CommandResults:
    """
    List all JSON profiles in a policy

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
    """
    result = client.list_policy_json_profiles(policy_md5)

    table_name = 'f5 list of all JSON Profiles:'
    readable_output, printable_result = build_command_result(result, table_name)

    command_results = CommandResults(
        outputs_prefix='f5.JSONProfile',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_add_policy_json_profile_command(client, policy_md5: str, name: str, maximum_total_len: str,
                                       maximum_value_len: str, max_structure_depth: str,
                                       max_array_len: str, description: str = None,
                                       tolerate_parsing_warnings: bool = None,
                                       parse_parameters: bool = None, check_signatures: bool = None,
                                       check_metachars: bool = None) -> CommandResults:
    """
    Create a new JSON profile in a policy

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        name (str): Name of JSON profile.
        description (str): Optional profile description.
        maximum_total_len(str): Maximum total length of JSON data.
        maximum_value_len(str): Maximum length for a single value.
        max_structure_depth(str): Maximum structure depth.
        max_array_len(str): Maximum JSON array length.
        tolerate_parsing_warnings(bool): Should the profile tolerate JSON parsing warnings.
        parse_parameters(bool): Should the profile handle JSON values as parameters.
        check_signatures (bool): Should the profile check for attack signatures.
        check_metachars(bool): Should the profile check for metachar elements.
    """
    result = client.add_policy_json_profile(policy_md5, name, maximum_total_len, maximum_value_len,
                                            max_structure_depth, max_array_len, description,
                                            tolerate_parsing_warnings, parse_parameters,
                                            check_signatures, check_metachars)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for adding JSON profile:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.JSONProfile',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_update_policy_json_profile_command(client, policy_md5: str, json_id: str, json_name: str,
                                          maximum_total_len: str, maximum_value_len: str,
                                          max_structure_depth: str, max_array_len: str,
                                          description: str = None,
                                          tolerate_parsing_warnings: bool = None,
                                          parse_parameters: bool = None,
                                          check_signatures: bool = None,
                                          check_metachars: bool = None) -> CommandResults:
    """
    Update an existing JSON profile in a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        json_id (str): ID of JSON profile.
        json_name (str): Name of JSON profile.
        description (str): Optional profile description.
        maximum_total_len(str): Maximum total length of JSON data.
        maximum_value_len(str): Maximum length for a single value.
        max_structure_depth(str): Maximum structure depth.
        max_array_len(str): Maximum JSON array length.
        tolerate_parsing_warnings(bool): Should the profile tolerate JSON parsing warnings.
        parse_parameters(bool): Should the profile handle JSON values as parameters.
        check_signatures (bool): Should the profile check for attack signatures.
        check_metachars(bool): Should the profile check for metachar elements.
    """
    result = client.update_policy_json_profile(policy_md5, json_id, json_name, description,
                                               maximum_total_len, maximum_value_len,
                                               max_structure_depth, max_array_len,
                                               tolerate_parsing_warnings, parse_parameters,
                                               check_signatures, check_metachars)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for updating JSON profile:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.JSONProfile',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_delete_policy_json_profile_command(client, policy_md5: str, json_id: str,
                                          json_name: str) -> CommandResults:
    """
    Delete an existing JSON profile from a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        json_id (str): ID of JSON profile.
        json_name (str): Name of JSON profile.
    """
    result = client.delete_policy_json_profile(policy_md5, json_id, json_name)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for deleting JSON profile:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.JSONProfile',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_list_policy_xml_profiles_command(client, policy_md5: str) -> CommandResults:
    """
    List all existing XML profiles in a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
    """
    result = client.list_policy_xml_profiles(policy_md5)

    table_name = 'f5 list of all XML Profiles:'
    readable_output, printable_result = build_command_result(result, table_name)

    command_results = CommandResults(
        outputs_prefix='f5.XMLProfile',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_add_policy_xml_profile_command(client, policy_md5: str, name: str, description=None,
                                      check_signatures=None, check_metachar_elements=None,
                                      check_metachar_attributes=None, enable_wss=None,
                                      inspect_soap=None, follow_links=None,
                                      use_xml_response=None, allow_cdata=None,
                                      allow_dtds=None, allow_external_ref=None,
                                      allow_processing_instructions=None) -> CommandResults:
    """
    Add a new XML profile to a policy.

    Args:
        client (Client): f5 client.
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
    result = client.add_policy_xml_profile(policy_md5, name, description, check_signatures,
                                           check_metachar_elements, check_metachar_attributes,
                                           enable_wss, inspect_soap, follow_links,
                                           use_xml_response, allow_cdata, allow_dtds,
                                           allow_external_ref, allow_processing_instructions)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for adding XML profile:', printable_result,
                                      OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.XMLProfile',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_update_policy_xml_profile_command(client, policy_md5: str, xml_id: str, xml_name: str,
                                         description=None,
                                         check_signatures=None, check_metachar_elements=None,
                                         check_metachar_attributes=None, enable_wss=None,
                                         inspect_soap=None, follow_links=None,
                                         use_xml_response=None, allow_cdata=None,
                                         allow_dtds=None, allow_external_ref=None,
                                         allow_processing_instructions=None) -> CommandResults:
    """
    Update an XML profile in a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        xml_id (str): ID of the profile.
        xml_name (str): Name of the profile.
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
    result = client.update_policy_xml_profile(policy_md5, xml_id, xml_name, description,
                                              check_signatures, check_metachar_elements,
                                              check_metachar_attributes, enable_wss, inspect_soap,
                                              follow_links, use_xml_response, allow_cdata,
                                              allow_dtds, allow_external_ref,
                                              allow_processing_instructions)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for updating XML profile:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.XMLProfile',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_delete_policy_xml_profile_command(client, policy_md5: str, xml_id: str,
                                         xml_name: str) -> CommandResults:
    """
    Delete an existing XML profile from a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        xml_id (str): ID of the profile.
        xml_name (str): Name of the profile.
    """
    result = client.delete_policy_xml_profile(policy_md5, xml_id, xml_name)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for deleting XML profile:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.XMLProfile',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_list_policy_server_technologies_command(client, policy_md5: str) -> CommandResults:
    """
    List all server technologies in a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
    """
    result = client.list_policy_server_technologies(policy_md5)
    table_name = 'f5 list of all server technologies:'
    readable_output, printable_result = build_command_result(result, table_name)
    command_results = CommandResults(
        outputs_prefix='f5.ServerTechnology',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_add_policy_server_technology_command(client, policy_md5: str, technology_id: str,
                                            technology_name: str) -> CommandResults:
    """
    Add a server technology to a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        technology_id (str): ID of the server technology.
        technology_name (str): Name of the server technology.
    """
    result = client.add_policy_server_technology(policy_md5, technology_id, technology_name)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for adding server technology:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.ServerTechnology',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_delete_policy_server_technology_command(client, policy_md5: str, technology_id: str,
                                               technology_name: str) -> CommandResults:
    """
    Delete a server technology from a policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        technology_id (str): ID of the server technology.
        technology_name (str): Name of the server technology.
    """
    result = client.delete_policy_server_technology(policy_md5, technology_id, technology_name)
    printable_result, _ = build_output(OBJECT_FIELDS, result)
    readable_output = tableToMarkdown('f5 data for listing server technology:',
                                      printable_result, OBJECT_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.ServerTechnology',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_list_policy_blocking_settings_command(client: Client, policy_md5: str,
                                             endpoint: str) -> CommandResults:
    """
    List a Blocking Settings element of a selected policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        endpoint (str): Sub-path of the wanted Blocking Settings endpoint.
    """
    result = client.list_policy_blocking_settings(policy_md5, endpoint)
    result = result.get('items')
    printable_result = []

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
            reference_link = item.get(BLOCKING_SETTINGS_REFERENCE.get(endpoint))

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
        outputs_prefix='f5.BlockingSettings',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def f5_update_policy_blocking_settings_command(client: Client, policy_md5: str, endpoint: str,
                                               description: str, enabled: bool = None,
                                               learn: bool = None, alarm: bool = None,
                                               block: bool = None) -> CommandResults:
    """
    Update a specific Blocking Setting element of a certain policy.

    Args:
        client (Client): f5 client.
        policy_md5 (str): MD5 hash of the policy.
        endpoint (str): Sub-path of the wanted Blocking Settings endpoint.
        description (str): Since there is no name, use description instead.
        enabled (bool): If possible, enable the element.
        learn (bool): If possible, have the element learn.
        alarm (bool): If possible, have the element alarm.
        block (bool): If possible, have the element block.
    """
    result = client.update_policy_blocking_setting(policy_md5, endpoint, description, enabled,
                                                   learn, alarm, block)
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

    reference_link = result.get(BLOCKING_SETTINGS_REFERENCE.get(endpoint))
    if reference_link:
        printable_result['reference'] = reference_link.get('link')

    readable_output = tableToMarkdown(f'Modified {endpoint}', printable_result,
                                      headers=['id', 'description', 'enabled', 'learn', 'alarm',
                                               'block', 'kind', 'reference', 'selfLink',
                                               'section-reference', 'lastUpdateMicros'],
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='f5.BlockingSettings',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result
    )
    return command_results


def format_date(date):
    """formats date according to XSOAR date format"""
    date = int(date / 1000000)
    return time.strftime(DATE_FORMAT, time.localtime(date))


def build_output(headers: List[str], result: dict):
    """helper function. Builds the printable results."""
    printable_result = {}
    new_headers = headers

    for endpoint in new_headers:
        if endpoint == 'lastUpdateMicros':
            printable_result[endpoint] = format_date(result.get(endpoint))
        else:
            printable_result[endpoint] = result.get(endpoint)

    policy_reference = result.get('policyReference')
    if policy_reference:
        printable_result['policyReference'] = policy_reference.get('link')
        new_headers.insert(0, 'policyReference')

    server_tech_reference = result.get('serverTechnologyReference')
    if server_tech_reference:
        printable_result['serverTechnologyName'] = server_tech_reference.get(
            'serverTechnologyName')
        new_headers.insert(0, 'serverTechnologyName')
    return printable_result, list(dict.fromkeys(new_headers))


def build_list_output(printable_result: list, result: dict):
    headers = LIST_FIELDS
    for element in result:
        current_printable_result, headers = build_output(headers, element)
        printable_result.append(current_printable_result)
    return printable_result, headers


def build_command_result(result: dict, table_name: str):
    """Build readable_output and printable_result for list commands."""
    printable_result: List[dict] = []
    readable_output = 'No results'

    result = result.get('items')  # type: ignore
    if result:
        printable_result, headers = build_list_output(printable_result, result)
        readable_output = tableToMarkdown(table_name, printable_result, headers, removeNull=True)

    return readable_output, printable_result


def main():
    """ PARSE AND VALIDATE INTEGRATION PARAMS """
    params = demisto.params()
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')

    server_ip = params['url']
    base_url = f'https://{server_ip}/mgmt/tm/'

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    handle_proxy()

    token = login(server_ip, username, password, verify_certificate)

    demisto.info(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            token=token,
            use_ssl=verify_certificate,
            use_proxy=proxy,
        )

        command = demisto.command()
        if demisto.command() == 'test-module':
            return_results(test_module(client))

        elif command == 'f5-asm-get-policy-md5':
            return_results(f5_get_policy_md5_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-list':
            return_results(f5_list_policies_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-create':
            return_results(f5_create_policy_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-apply':
            return_results(f5_apply_policy_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-export-file':
            return_results(f5_export_policy_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-delete':
            return_results(f5_delete_policy_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-methods-list':
            return_results(f5_list_policy_methods_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-methods-add':
            return_results(f5_add_policy_method_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-methods-update':
            return_results(f5_update_policy_method_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-methods-delete':
            return_results(f5_delete_policy_method_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-file-types-list':
            return_results(f5_list_policy_file_types_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-file-types-add':
            return_results(f5_add_policy_file_type_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-file-types-update':
            return_results(f5_update_policy_file_type_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-file-types-delete':
            return_results(f5_delete_policy_file_type_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-cookies-list':
            return_results(f5_list_policy_cookies_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-cookies-add':
            return_results(f5_add_policy_cookie_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-cookies-update':
            return_results(f5_update_policy_cookie_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-cookies-delete':
            return_results(f5_delete_policy_cookie_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-hostnames-list':
            return_results(f5_list_policy_hostnames_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-hostnames-add':
            return_results(f5_add_policy_hostname_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-hostnames-update':
            return_results(f5_update_policy_hostname_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-hostnames-delete':
            return_results(f5_delete_policy_hostname_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-urls-list':
            return_results(f5_list_policy_urls_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-urls-add':
            return_results(f5_add_policy_url_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-urls-update':
            return_results(f5_update_policy_url_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-urls-delete':
            return_results(f5_delete_policy_url_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-whitelist-ips-list':
            return_results(f5_list_policy_whitelist_ips_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-whitelist-ips-add':
            return_results(f5_add_policy_whitelist_ip_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-whitelist-ips-update':
            return_results(f5_update_policy_whitelist_ip_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-whitelist-ips-delete':
            return_results(f5_delete_policy_whitelist_ip_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-signatures-list':
            return_results(f5_list_policy_signatures_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-parameters-list':
            return_results(f5_list_policy_parameters_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-parameters-add':
            return_results(f5_add_policy_parameter_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-parameters-update':
            return_results(f5_update_policy_parameter_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-parameters-delete':
            return_results(f5_delete_policy_parameter_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-gwt-profiles-list':
            return_results(f5_list_policy_gwt_profiles_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-gwt-profiles-add':
            return_results(f5_add_policy_gwt_profile_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-gwt-profiles-update':
            return_results(f5_update_policy_gwt_profile_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-gwt-profiles-delete':
            return_results(f5_delete_policy_gwt_profile_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-json-profiles-list':
            return_results(f5_list_policy_json_profiles_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-json-profiles-add':
            return_results(f5_add_policy_json_profile_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-json-profiles-update':
            return_results(f5_update_policy_json_profile_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-json-profiles-delete':
            return_results(f5_delete_policy_json_profile_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-xml-profiles-list':
            return_results(f5_list_policy_xml_profiles_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-xml-profiles-add':
            return_results(f5_add_policy_xml_profile_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-xml-profiles-update':
            return_results(f5_update_policy_xml_profile_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-xml-profiles-delete':
            return_results(f5_delete_policy_xml_profile_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-server-technologies-list':
            return_results(f5_list_policy_server_technologies_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-server-technologies-add':
            return_results(f5_add_policy_server_technology_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-server-technologies-delete':
            return_results(f5_delete_policy_server_technology_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-blocking-settings-list':
            return_results(f5_list_policy_blocking_settings_command(client, **demisto.args()))

        elif command == 'f5-asm-policy-blocking-settings-update':
            return_results(f5_update_policy_blocking_settings_command(client, **demisto.args()))

    except DemistoException as e:
        if 'Maximum number of login attempts exceeded' in str(e):
            return_error(f'Authorization Error: please check your credentials.\nError: {e}')
        elif 'HTTPSConnectionPool' in str(e):
            return_error(f'Connection Error: please check your server url address.\n\nError: {e}')
        elif 'already exists' in str(e):
            return_error(f'The object name already exists in your f5 server.\n\nError: {e}')
        else:
            raise

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. \n\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
