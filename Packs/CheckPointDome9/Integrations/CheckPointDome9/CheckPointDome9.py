import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any

TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


class Client(BaseClient):

    def __init__(self, base_url: str, key_id: str, key_secret: str, proxy: bool, verify: bool):
        self.base_url = base_url
        headers = {'Content-Type': 'application/json'}
        auth = (key_id, key_secret)
        super().__init__(base_url=base_url, auth=auth, verify=verify, headers=headers, proxy=proxy)

    def access_lease_list_request(self) -> dict[str, Any]:
        """ Get Access lease list.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        return self._http_request('GET', 'AccessLease')

    def access_lease_delete_request(self, lease_id: str) -> str:
        """ Delete an access lease by ID.

        Args:
            lease_id (str): The access lease ID.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        return self._http_request('DELETE', f'AccessLease/{lease_id}', resp_type='text')

    def access_lease_invitation_list_request(self, invitation_id: str = None) -> dict[str, Any]:
        """ Get Access lease invitation list.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        url_prefix = create_url_prefix(invitation_id)  # type: ignore[arg-type]

        response = self._http_request('GET', f'AccessLeaseInvitation{url_prefix}')

        return response

    def access_lease_invitation_delete_request(self, invitation_id: str) -> str:
        """ Delete an access lease invitation by ID.

        Args:
            invitation_id (str): The access lease invitation ID.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        return self._http_request('DELETE',
                                  f'AccessLeaseInvitation/{invitation_id}',
                                  resp_type='text')

    def findings_search_request(self,
                                max_fetch: int,
                                alert_severity: List[str] = None,
                                alert_region: List[str] = None,
                                alert_entity_type: List[str] = None,
                                alert_acknowledged: bool = None) -> dict[str, Any]:
        """ Search findings.
            Filter findings by account, region, VPC, IP, or instance name.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        fields = []
        for severity in (alert_severity or []):
            fields.append({"name": "severity", "value": severity})

        for region in (alert_region or []):
            fields.append({"name": "region", "value": region})

        for entity_type in (alert_entity_type or []):
            fields.append({"name": "entityTypeByEnvironmentType", "value": entity_type})

        if alert_acknowledged:
            fields.append({"name": "acknowledged", "value": alert_acknowledged})  # type: ignore[dict-item]

        data = {
            "pageSize": max_fetch,
            "sorting": {
                "fieldName": "createdTime",
                "direction": 1
            },
            "filter": {
                "fields": fields
            }
        }
        response = self._http_request('POST', 'Compliance/Finding/search', json_data=data)

        return response

    def ip_list_create_request(self,
                               name: str,
                               description: str,
                               items: List[dict[str, Any]] = None) -> dict[str, Any]:
        """ Create a new IP list.

        Args:
            name (str): The new IP list name.
            description (str): IP list description.
            items (list, optional): List of IP address and IP comment.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        items = items or ''
        data = {"description": description, "items": items, "name": name}
        return self._http_request('POST', 'IpList', json_data=data)

    def ip_list_update_request(self,
                               list_id: str,
                               description: str,
                               items: List[dict[str, Any]] = None) -> str:
        """ Update exist IP list.

        Args:
            list_id (str): The IP list ID.
            description (str): The new IP list description.
            items (list, optional): The new IP-list items (IP address and comment).

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        data = {"description": description, "items": items}
        response = self._http_request('PUT', f'IpList/{list_id}', json_data=data, resp_type='text')
        return response

    def ip_list_get_request(self, list_id: str) -> dict[str, Any]:
        """ Get an IP List by ID.

        Args:
            list_id (str): The IP-list ID to fetch.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """

        url_prefix = create_url_prefix(list_id)
        return self._http_request(method='GET', url_suffix=f'IpList{url_prefix}')

    def ip_list_delete_request(self, list_id: str) -> str:
        """ Delete an IP List by id.

        Args:
            list_id (str): The IP-list ID to delete.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """

        return self._http_request('DELETE', f'IpList/{list_id}', resp_type='text')

    def ip_list_metadata_list_request(self) -> dict[str, Any]:
        """ Get all IP addresses metadata.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        return self._http_request('GET', 'IpAddressMetadata')

    def ip_list_metadata_create_request(
        self,
        cidr: str,
        name: str,
        classification: str,
    ) -> dict[str, Any]:
        """ Add a new IP address metadata. An Ip Address metadata must contain CIDR, Name and Classification.
            Classification can be External or Unsafe or Dmz or InternalVpc or InternalDc or NoClassification.

        Args:
            cidr (str): The IP address CIDR.
            name (str): The IP address Name.
            classification (str): The IP address classification.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        data = {"cidr": cidr, "classification": classification, "name": name}

        response = self._http_request('POST', 'IpAddressMetadata', json_data=data)

        return response

    def ip_list_metadata_update_request(
        self,
        list_id: str,
        classification: str,
        name: str,
    ) -> dict[str, Any]:
        """ Update an existing IP address metadata.
            Classification can only be External or Unsafe or Dmz or InternalVpc or InternalDc or NoClassification.

        Args:
            list_id (str): The IP address internal ID.
            classification (str): The IP address classification.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        data = {"classification": classification, "id": list_id, "name": name}

        response = self._http_request('PUT', 'IpAddressMetadata', json_data=data)

        return response

    def ip_list_metadata_delete_request(
        self,
        account_id: str,
        address: str,
        mask: int,
    ) -> str:
        """ Delete an IP address metadata with a specific CIDR.

        Args:
            account_id (str): The account ID.
            address (str): The IP address to delete.
            mask (int): The subnet mask.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """

        params = {"accountId": account_id, "address": address, "mask": mask}
        response = self._http_request('DELETE',
                                      'IpAddressMetadata',
                                      params=params,
                                      resp_type='text')

        return response

    def compliance_remediation_get_request(self) -> dict[str, Any]:
        """ Get a list of remediation for the account.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """

        return self._http_request('GET', 'ComplianceRemediation')

    def compliance_remediation_create_request(self, ruleset_id: str, rule_logic_hash: str,
                                              comment: str, cloudbots: list) -> dict[str, Any]:
        """ Add a new remediation.

        Args:
            ruleset_id (str): Ruleset ID to apply remediation on.
            rule_logic_hash (str): Hash for the rule logic.
            comment (str): Comment text.
            cloudbots (list): Cloud bots execution expressions.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """

        data = {
            "rulesetId": ruleset_id,
            "ruleLogicHash": rule_logic_hash,
            "cloudBots": cloudbots,
            "comment": comment
        }
        return self._http_request('POST', 'ComplianceRemediation', json_data=data)

    def compliance_remediation_update_request(
        self,
        remediation_id: str,
        ruleset_id: str,
        rule_logic_hash: str,
        comment: str,
        cloudbots: list,
    ) -> dict[str, Any]:
        """ Update a remediation.

        Args:
            remediation_id (str): Remediation ID.
            ruleset_id (str): Ruleset ID.
            rule_logic_hash (str): Hash for the rule logic.
            comment (str): Comment text.
            cloudbots (list): Cloud bots execution expressions.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        data = {
            "cloudBots": cloudbots,
            "comment": comment,
            "id": remediation_id,
            "rulesetId": ruleset_id,
            "ruleLogicHash": rule_logic_hash
        }

        response = self._http_request('PUT', 'ComplianceRemediation', json_data=data)

        return response

    def compliance_remediation_delete_request(self, remediation_id: str) -> str:
        """ Delete a remediation by ID.

        Args:
            remediation_id (str): Remediation ID.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        return self._http_request('DELETE',
                                  f'ComplianceRemediation/{remediation_id}',
                                  resp_type='text')

    def compliance_ruleset_list_request(self) -> dict[str, Any]:
        """ Get all rulesets for the account.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        return self._http_request('GET', 'Compliance/Ruleset/view')

    def compliance_ruleset_rule_list_request(self, rule_id: int) -> dict[str, Any]:
        """ Get rule details (get rule logic hash).

        Args:
            rule_id (int): The Ruleset ID.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        return self._http_request('GET', f'Compliance/Ruleset/{rule_id}')

    def security_group_attach_request(
        self,
        instance_id: str,
        sg_id: str,
        nic_name: str,
    ) -> dict[str, Any]:
        """ Attach security Group to an AWS EC2 Instance.

        Args:
            instance_id (str): AWS Instance ID.
            sg_id (str): AWS security group ID.
            nic_name (str): The instance niCs name.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        data = {"groupid": sg_id, "nicname": nic_name}

        response = self._http_request('POST',
                                      f'cloudinstance/{instance_id}/sec-groups',
                                      json_data=data)

        return response

    def instance_list_request(self, instance_id: str) -> dict[str, Any]:
        """ Get an AWS EC2 Instances list.

        Args:
            instance_id (str): AWS Instance ID.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        url_prefix = create_url_prefix(instance_id)
        response = self._http_request('GET', f'cloudinstance{url_prefix}')

        return response

    def security_group_service_delete_request(self, sg_id: str, service_id: str) -> str:
        """ Delete security group service by ID.

        Args:
            sg_id (str): Security group ID.
            service_id (str): Service ID.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        response = self._http_request('DELETE',
                                      f'cloudsecuritygroup/{sg_id}/services/Inbound/{service_id}',
                                      resp_type='text')

        return response

    def security_group_tags_update_request(self, sg_id: str, key: str,
                                           value: str) -> dict[str, Any]:
        """ Create and Update a security group tag.

        Args:
            sg_id (str): Security group ID.
            key (str): The tag key to add.
            value (str): The tag value to add.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        data = {'tags': {key: value}}

        response = self._http_request('POST', f'cloudsecuritygroup/{sg_id}/tags', json_data=data)

        return response

    def security_group_service_create_request(
        self,
        sg_id: str,
        name: str,
        protocol_type: str,
        port: int,
        policy_type: str = None,
        open_for_all: bool = None,
        description: str = None,
        data_id: str = None,
        data_name: str = None,
        scope_type: str = None,
        is_valid: bool = None,
        inbound: bool = None,
        icmptype: str = None,
        icmpv6type: str = None,
    ) -> dict[str, Any]:
        """ Create new security group service.

        Args:
            sg_id (str): AWS Security group ID.
            name (str): Service name.
            protocol_type (str): The Service protocol type.
            port (int): The service port, indicates a port range.
            open_for_all (bool, optional): Indicates if the service is open to all ports. Defaults to None.
            description (str, optional): Service description. Defaults to None.
            data_id (str, optional): IP List ID to attach. Defaults to None.
            data_name (str, optional): IP List name to attach. Defaults to None.
            scope_type (str, optional): Scope type (CIDR / IPList) to attach. Defaults to None.
            is_valid (bool, optional): _description_. Defaults to None.
            inbound (bool, optional): _description_. Defaults to None.
            icmptype (str, optional):  ICMP type (when protocol is ICMP). Defaults to None.
            icmpv6type (str, optional): ICMP V6 type (when protocol is ICMPV6). Defaults to None.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        data = remove_empty_elements({
            "description":
            description,
            "icmpType":
            icmptype,
            "icmpv6Type":
            icmpv6type,
            "inbound":
            inbound,
            "name":
            name,
            "openForAll":
            open_for_all,
            "port":
            port,
            "protocolType":
            protocol_type,
            "scope": [{
                "data": {
                    "id": data_id,
                    "name": data_name
                },
                "isValid": is_valid,
                "type": scope_type
            }]
        })
        response = self._http_request('POST',
                                      f'cloudsecuritygroup/{sg_id}/services/{policy_type}',
                                      json_data=data)
        return response

    def security_group_service_update_request(
        self,
        sg_id: str,
        service_name: str,
        protocol_type: str,
        port: int,
        policy_type: str,
        open_for_all: bool = None,
        description: str = None,
        data_id: str = None,
        data_name: str = None,
        scope_type: str = None,
        is_valid: bool = None,
        inbound: bool = None,
        icmptype: str = None,
        icmpv6type: str = None,
    ) -> dict[str, Any]:
        """ Update security group service.

        Args:
            sg_id (str): AWS Security group ID.
            service_name (str): Service name.
            protocol_type (str): The Service protocol type.
            port (int): The service port, indicates a port range.
            open_for_all (bool, optional): Indicates if the service is open to all ports. Defaults to None.
            description (str, optional): Service description. Defaults to None.
            data_id (str, optional): IP List ID to attach. Defaults to None.
            data_name (str, optional): IP List name to attach. Defaults to None.
            scope_type (str, optional): Scope type (CIDR / IPList) to attach. Defaults to None.
            is_valid (bool, optional): _description_. Defaults to None.
            inbound (bool, optional): _description_. Defaults to None.
            icmptype (str, optional):  ICMP type (when protocol is ICMP). Defaults to None.
            icmpv6type (str, optional): ICMP V6 type (when protocol is ICMPV6). Defaults to None.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """

        data = remove_empty_elements({
            "description":
            description,
            "icmpType":
            icmptype,
            "icmpv6Type":
            icmpv6type,
            "inbound":
            inbound,
            "name":
            service_name,
            "openForAll":
            open_for_all,
            "port":
            port,
            "protocolType":
            protocol_type,
            "scope": [{
                "data": {
                    "id": data_id,
                    "name": data_name
                },
                "isValid": is_valid,
                "type": scope_type
            }]
        })

        response = self._http_request('PUT',
                                      f'cloudsecuritygroup/{sg_id}/services/{policy_type}',
                                      json_data=data)

        return response

    def security_group_instance_detach_request(
        self,
        instance_id: str,
        sg_id: str,
        nic_name: str,
    ) -> dict[str, Any]:
        """ Detach security Group from an AWS EC2 Instance.

        Args:
            instance_id (str): AWS Instance ID.
            sg_id (str): AWS security group ID.
            nic_name (str): The instance niCs name.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        data = {"groupid": sg_id, "nicname": nic_name}

        response = self._http_request('DELETE',
                                      f'cloudinstance/{instance_id}/sec-groups',
                                      json_data=data)

        return response

    def protection_mode_update_request(self, sg_id: str, protection_mode: str) -> dict[str, Any]:
        """ Change the protection mode for an AWS security group (FullManage or ReadOnly).

        Args:
            sg_id (str): The security group ID.
            protection_mode (str): The protection mode to update.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        data = {"protectionMode": protection_mode}

        response = self._http_request('POST',
                                      f'cloudsecuritygroup/{sg_id}/protection-mode',
                                      json_data=data)

        return response

    def cloud_accounts_list_request(self, account_id: str = None) -> dict[str, Any]:
        """ Get cloud accounts list.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        url_prefix = create_url_prefix(account_id)  # type: ignore[arg-type]
        response = self._http_request('GET', f'CloudAccounts{url_prefix}')

        return response

    def check_ip_list_security_group_attach_request(self, sg_id: str = None) -> dict[str, Any]:
        """ Get AWS cloud accounts for a specific security group and region and
            check if there is an IP-list that attach to a security group.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        url_prefix = create_url_prefix(sg_id)  # type: ignore[arg-type]
        response = self._http_request('GET', f'CloudSecurityGroup{url_prefix}')

        return response

    def security_group_list_request(self) -> dict[str, Any]:
        """ Get security group list.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        response = self._http_request('GET', 'AwsSecurityGroup')

        return response

    def global_search_get_request(self) -> dict[str, Any]:
        """ Get top results for each service.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        params = {"freeText": "String"}
        response = self._http_request('GET', 'GlobalSearch', params=params)

        return response

    def cloud_trail_get_request(self) -> dict[str, Any]:
        """ Get Cloud Trail events for a Dome9 user.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        response = self._http_request('GET', 'CloudTrail')

        return response

    def findings_bundle_get_request(self, bundle_id: str, rule_logic_hash: str) -> dict[str, Any]:
        """ Get the findings for a specific rule in a bundle, for all of the user's accounts.

        Args:
            bundle_id (str): The bundle ID.
            rule_logic_hash (str): MD5 hash of the rule GSL string.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        params = {"ruleLogicHash": rule_logic_hash, "pageSize": '100', "pageNumber": '1'}
        response = self._http_request('GET',
                                      f'Compliance/Finding/bundle/{bundle_id}',
                                      params=params)
        return response

    def finding_get_request(self, finding_id: str) -> dict[str, Any]:
        """ Get a findings by its ID.

        Args:
            finding_id (str): The findings ID.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        response = self._http_request('GET', f'Compliance/Finding/{finding_id}')
        return response

    def organizational_unit_view_get_request(self) -> dict[str, Any]:
        """ Get organizational unit view entities.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        response = self._http_request('GET', 'organizationalunit/view')
        return response

    def organizational_unit_flat_get_request(self) -> dict[str, Any]:
        """ Get all organizational units flat.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        response = self._http_request('GET', 'organizationalunit/GetFlatOrganizationalUnits')
        return response

    def organizational_unit_get_request(self, unit_id: str) -> dict[str, Any]:
        """ Get an organizational unit by its ID.

        Args:
            unit_id (str): The organizational unit ID.

        Returns:
            Dict[str, Any]: API response from Dome9.
        """
        url_prefix = create_url_prefix(unit_id)
        response = self._http_request('GET', f'OrganizationalUnit{url_prefix}')
        return response


def attach_comment_to_ip(ip_list: List[str],
                         comment_list: List[str],
                         description: str = None) -> List:
    """ Insure comment_list has the same length as ip_list
        and description or ip is specified.

    Args:
        ip_list (_type_): The IP list.
        comment_list (_type_): The comment list.
        description (_type_): List description.

    Raises:
        ValueError: Description or ip must be provided.

    Returns:
        List: Items List.
    """
    items = []

    if ip_list:
        while len(ip_list) > len(comment_list):
            comment_list.append('')

        for ip, comment in zip(ip_list, comment_list):
            items.append({'ip': ip, 'comment': comment})
    else:
        if not description:
            raise ValueError('description or ip must be provided.')
    return items


def validate_pagination_arguments(page: int = None, page_size: int = None, limit: int = None):
    """ Validate pagination arguments according to their default.

    Args:
        page (int, optional): Page number of paginated results.
        page_size (int, optional): Number of ip-list per page.
        limit (int, optional): The maximum number of records to retrieve.

    Raises:
        ValueError: Appropriate error message.
    """
    if page_size and (page_size < 1 or page_size > 50):
        raise ValueError('page size argument must be greater than 1 and smaller than 50.')

    if page and page < 1:
        raise ValueError('page argument must be greater than 0.')

    if limit and (limit < 1 or limit > 50):
        raise ValueError('limit argument must be greater than 1.')


def pagination(response: dict, args: dict[str, Any]) -> tuple:
    """ Executing Manual Pagination (using the page and page size arguments)
        or Automatic Pagination (display a number of total results).

    Args:
        response (dict): API response.
        page (int, optional): Page number of paginated results.
        page_size (int, optional): Number of ip-list per page.
        limit (int, optional): The maximum number of records to retrieve.

    Returns:
        dict: output and pagination message for Command Results.
    """
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))

    validate_pagination_arguments(page, page_size, limit)  # type: ignore[arg-type]

    output = response

    if page and page_size:
        if page_size < len(response):
            first_item = page_size * (page - 1)
            output = response[first_item:first_item + page_size]
        else:
            output = response[:page_size]
        pagination_message = f'Showing page {page}. \n Current page size: {page_size}'
    else:
        output = response[:limit]
        pagination_message = f'Showing {len(output)} rows out of {len(response)}.'

    return output, pagination_message


def arg_to_boolean(arg: str) -> Optional[bool]:
    """ Retrieve arg boolean value if it's not none.

    Args:
        arg (str): Boolean argument.

    Returns:
        Optional[bool]: The argument boolean value.
    """
    return argToBoolean(arg) if arg else None


def get_service_type_and_data(service: list) -> list:
    """ Get security group service type and data.

    Args:
        service (list): Inbound or Outbound service.

    Returns:
        str: service type and data.
    """
    service_type = service_data = service_scope = ''
    if service:
        service_scope = service[0]['scope']
        if service_scope:
            service_type = service_scope[0]['type']  # type: ignore[index]
            service_data = service_scope[0]['data']  # type: ignore[index]

    return service_type, service_data  # type: ignore[return-value]


def create_url_prefix(path_variable: str) -> str:
    """ Create url prefix for request.

    Args:
        path_variable (str): The path variable.

    Returns:
        str: URL prefix.
    """

    url_prefix = f'/{path_variable}' if path_variable else ''
    return url_prefix


def create_sg_list(fix_output: list) -> list:
    """ Create Security Group list according to a general template.

    Args:
        fix_output (list): Security group list to edit.

    Returns:
        list: A new Security Group list according to function format.
    """
    security_group_list = []
    for sg in fix_output:
        inbound_services = sg['services']['inbound']
        inbound_services_type, inbound_services_data = get_service_type_and_data(inbound_services)

        outbound_services = sg['services']['outbound']
        outbound_services_type, outbound_services_data = get_service_type_and_data(
            outbound_services)

        security_group_list.append({
            'cloud_account_id': sg['cloudAccountId'],
            'cloud_account_name': sg['cloudAccountName'],
            'region_id': sg['regionId'],
            'security_group_external_id': sg['externalId'],
            'security_group_id': sg['securityGroupId'],
            'security_group_name': sg['securityGroupName'],
            'isProtected': sg['isProtected'],
            'inbound_scope_type': inbound_services_type,
            'inbound_scope_data': inbound_services_data,
            'outbound_scope_type': outbound_services_type,
            'outbound_scope_data': outbound_services_data,
            'description': sg['description'],
            'vpc_id': sg['vpcId']
        })
    return security_group_list


def access_lease_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get a access lease list.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.access_lease_list_request()

    output = response['aws']
    fix_output, pagination_message = pagination(output, args)

    readable_output = tableToMarkdown(
        name='Access Lease:',
        metadata=pagination_message,
        t=fix_output,
        headers=['id', 'name', 'ip', 'user', 'region', 'length', 'created'],
        headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.AccessLease',
                                     outputs_key_field='id',
                                     outputs=output,
                                     raw_response=response)

    return command_results


def access_lease_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Delete access lease by ID.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    lease_id = args.get('lease_id')
    response = client.access_lease_delete_request(lease_id)  # type: ignore[arg-type]
    command_results = CommandResults(readable_output="Access Lease Deleted successfully",
                                     outputs_prefix='CheckPointDome9.AccessLease',
                                     outputs_key_field='',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def access_lease_invitation_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get a specific lease invitation.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    invitation_id = args.get('invitation_id')
    response = client.access_lease_invitation_list_request(invitation_id)  # type: ignore[arg-type]
    fix_output, pagination_message = pagination(response, args)

    readable_output = tableToMarkdown(
        name='Access Lease invitation',
        metadata=pagination_message,
        t=fix_output,
        headers=['id', 'issuerName', 'recipientName', 'length', 'created'],
        headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.AccessLease.Invitation',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def access_lease_invitation_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Delete a lease invitation.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    invitation_id = args.get('invitation_id')
    response = client.access_lease_invitation_delete_request(invitation_id)  # type: ignore[arg-type]
    command_results = CommandResults(readable_output="Access Lease Invitation Deleted successfully",
                                     outputs_prefix='CheckPointDome9.AccessLease.Invitation',
                                     outputs_key_field='',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def findings_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Search findings for the account.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    severity = argToList(args.get('severity'))
    acknowledged = arg_to_boolean(args.get('acknowledged'))  # type: ignore[arg-type]
    entity_type = argToList(args.get('entity_type'))
    region = argToList(args.get('region'))
    page_size = arg_to_number(args.get('limit'))

    response = client.findings_search_request(page_size, severity, region, entity_type,  # type: ignore[arg-type]
                                              acknowledged)  # type: ignore[arg-type]
    output = response['findings']

    fix_output, pagination_message = pagination(output, args)

    readable_output = tableToMarkdown(name='Findings:',
                                      metadata=pagination_message,
                                      t=fix_output,
                                      headers=[
                                          'id', 'alertType', 'severity', 'region', 'status',
                                          'action', 'cloudAccountId', 'description'
                                      ],
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.Finding',
                                     outputs_key_field='id',
                                     outputs=fix_output,
                                     raw_response=output)

    return command_results


def ip_list_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Create a new IP-list.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    name = args.get('name')
    description = args.get('description')
    ip_list = argToList(args.get('ip'))
    comment_list = argToList(args.get('comment'))

    # insure comment_list has the same length as ip_list
    items = attach_comment_to_ip(ip_list, comment_list, description)  # type: ignore[arg-type]

    response = client.ip_list_create_request(name, description, items)  # type: ignore[arg-type]
    command_results = CommandResults(readable_output="IP list created successfully",
                                     outputs_prefix='CheckPointDome9.IpList',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def ip_list_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Update IP list (description or items).

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    list_id = args.get('list_id')
    description = args.get('description')
    update_mode = args.get('update_mode', 'add_new_items')
    ip_list = argToList(args.get('ip'))
    comment_list = argToList(args.get('comment'))

    # insure comment_list has the same length as ip_list
    items = attach_comment_to_ip(ip_list, comment_list, description)  # type: ignore[arg-type]

    # This command replace items. To make the command update the list
    # we first get the old items
    if update_mode == 'add_new_items':
        old_items = client.ip_list_get_request(list_id=list_id)  # type: ignore[arg-type]
        items += old_items.get('items')  # type: ignore[arg-type]

    response = client.ip_list_update_request(list_id, description, items)  # type: ignore[arg-type]

    command_results = CommandResults(readable_output="IP list updated successfully",
                                     outputs_prefix='CheckPointDome9.IpList',
                                     outputs_key_field='',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def ip_list_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ List all IP Lists or Get individual by list ID.
    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    list_id = args.get('list_id')

    response = client.ip_list_get_request(list_id)  # type: ignore[arg-type]

    if isinstance(response, dict):
        response = [response]  # type: ignore

    ip_lists = []

    for ip_list in response:
        items = [item['ip'] for item in ip_list['items']]  # type: ignore[index]
        item = {
            'id': ip_list['id'],  # type: ignore[index]
            'items': items,
            'name': ip_list['name'],  # type: ignore[index]
            'description': ip_list['description']  # type: ignore[index]
        }

        ip_lists.append(item)

    readable_output = tableToMarkdown(name='IP list',
                                      t=ip_lists,
                                      headers=['id', 'name', 'items', 'description'],
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.IpList',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def ip_list_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Delete list by list ID.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    list_id = args.get('list_id')

    response = client.ip_list_delete_request(list_id)  # type: ignore[arg-type]
    command_results = CommandResults(readable_output="IP list deleted successfully",
                                     outputs_prefix='CheckPointDome9.IpList',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def ip_list_metadata_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get IP address metadata.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    output = client.ip_list_metadata_list_request()
    fix_output, pagination_message = pagination(output, args)

    readable_output = tableToMarkdown(name='IP List metadata',
                                      metadata=pagination_message,
                                      t=fix_output,
                                      headers=['id', 'name', 'cidr', 'classification'],
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.IpList.Metadata',
                                     outputs_key_field='id',
                                     outputs=output,
                                     raw_response=output)

    return command_results


def ip_list_metadata_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Add a new IP address metadata.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    cidr = args.get('cidr')
    name = args.get('name')
    classification = args.get('classification')

    response = client.ip_list_metadata_create_request(cidr, name, classification)  # type: ignore[arg-type]

    readable_output = tableToMarkdown(name='IP List metadata created successfully',
                                      t=response,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.IpList.Metadata',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def ip_list_metadata_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Update IP address metadata.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    list_metadata_id = args.get('list_metadata_id')
    classification = args.get('classification')
    name = args.get('name')

    response = client.ip_list_metadata_update_request(list_metadata_id, classification, name)  # type: ignore[arg-type]
    readable_output = tableToMarkdown(name='IP List metadata updated successfully',
                                      t=response,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.IpList.Metadata',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def ip_list_metadata_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Delete IP address metadata.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    account_id = args.get('account_id')
    address = args.get('address')
    mask = args.get('mask')

    response = client.ip_list_metadata_delete_request(account_id, address, mask)  # type: ignore[arg-type]
    command_results = CommandResults(readable_output="IP List metadata deleted successfully",
                                     outputs_prefix='CheckPointDome9.IpList.Metadata',
                                     outputs_key_field='',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def compliance_remediation_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get a list of remediations for the account.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.compliance_remediation_get_request()

    readable_output = tableToMarkdown(
        name='Compliance remediation:',
        t=response,
        headers=['id', 'ruleLogicHash', 'rulesetId', 'platform', 'comment', 'cloudBots'],
        headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.ComplianceRemediation',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def compliance_remediation_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Add a new remediation.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    ruleset_id = arg_to_number(args.get('ruleset_id'))
    rule_logic_hash = args.get('rule_logic_hash')
    comment = args.get('comment')
    cloudbots = argToList(args.get('cloudbots'))

    response = client.compliance_remediation_create_request(ruleset_id, rule_logic_hash, comment,  # type: ignore[arg-type]
                                                            cloudbots)

    readable_output = tableToMarkdown(
        name='Remediation created successfully',
        t=response,
        headers=['id', 'ruleLogicHash', 'rulesetId', 'platform', 'comment', 'cloudBots'],
        headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.ComplianceRemediation',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def compliance_remediation_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Update a remediation.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    remediation_id = args.get('remediation_id')
    ruleset_id = arg_to_number(args.get('ruleset_id'))
    comment = args.get('comment')
    cloudbots = argToList(args.get('cloudbots'))
    rule_logic_hash = args.get('rule_logic_hash')

    response = client.compliance_remediation_update_request(remediation_id, ruleset_id,  # type: ignore[arg-type]
                                                            rule_logic_hash, comment, cloudbots)  # type: ignore[arg-type]

    readable_output = tableToMarkdown(
        name='Remediation updated successfully',
        t=response,
        headers=['id', 'ruleLogicHash', 'rulesetId', 'platform', 'comment', 'cloudBots'],
        headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.ComplianceRemediation',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def compliance_remediation_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Delete a remediation.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    remediation_id = args.get('remediation_id')

    response = client.compliance_remediation_delete_request(remediation_id)  # type: ignore[arg-type]
    command_results = CommandResults(readable_output='Remediation deleted successfully',
                                     outputs_prefix='CheckPointDome9.ComplianceRemediation',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def compliance_ruleset_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get all rulesets for the account.
    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    response = client.compliance_ruleset_list_request()
    fix_output, pagination_message = pagination(response, args)

    readable_output = tableToMarkdown(name='Compliance Ruleset:',
                                      metadata=pagination_message,
                                      t=fix_output,
                                      headers=['accountId', 'id', 'name', 'description'],
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.ComplianceRuleset',
                                     outputs_key_field='id',
                                     outputs=fix_output,
                                     raw_response=response)

    return command_results


def compliance_ruleset_rule_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get all rulesets for the account (get rule logic hash for create remediation).

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    rule_id = args.get('rule_id')

    response = client.compliance_ruleset_rule_list_request(rule_id)  # type: ignore[arg-type]

    output = response['rules']

    fix_output, pagination_message = pagination(output, args)

    readable_output = tableToMarkdown(
        name='Compliance Ruleset Rules:',
        metadata=pagination_message,
        t=fix_output,
        headers=['name', 'severity', 'description', 'logic', 'logicHash'],
        headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.ComplianceRuleset.Rule',
                                     outputs_key_field='name',
                                     outputs=fix_output,
                                     raw_response=response)

    return command_results


def security_group_instance_attach_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Attach security Group to an AWS EC2 Instance.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    instance_id = args.get('instance_id')
    sg_id = args.get('sg_id')
    nic_name = args.get('nic_name')

    try:
        response = client.security_group_attach_request(instance_id, sg_id, nic_name)  # type: ignore[arg-type]
    except Exception:
        raise ValueError('Security group already attached')

    command_results = CommandResults(readable_output="Security group attach successfully",
                                     outputs_prefix='CheckPointDome9.Instance',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def security_group_service_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Delete a service from an AWS security group.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    sg_id = args.get('sg_id')
    service_id = args.get('service_id')

    response = client.security_group_service_delete_request(sg_id, service_id)  # type: ignore[arg-type]

    command_results = CommandResults(readable_output="Service deleted successfully",
                                     outputs_prefix='CheckPointDome9.SecurityGroup.Service',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def security_group_tags_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Update the list of tags for an AWS security group.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    sg_id = args.get('sg_id')
    key = args.get('key')
    value = args.get('value')

    response = client.security_group_tags_update_request(sg_id, key, value)  # type: ignore[arg-type]
    readable_output = tableToMarkdown(name='Tag updated successfully',
                                      t=response,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.SecurityGroup.Tag',
                                     outputs_key_field='key',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def security_group_service_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Create a new Service (rule) for the security group.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    sg_id = args.get('sg_id')  # mandatory
    name = args.get('name')  # mandatory
    protocol_type = args.get('protocol_type')  # mandatory
    port = arg_to_number(args.get('port'))  # mandatory
    policy_type = args.get('policy_type')
    open_for_all = arg_to_boolean(args.get('open_for_all'))  # type: ignore[arg-type]
    description = args.get('description')
    data_id = args.get('data_id')
    data_name = args.get('data_name')
    scope_type = args.get('type')
    is_valid = args.get('is_valid')
    inbound = arg_to_boolean(args.get('inbound'))  # type: ignore[arg-type]
    icmptype = args.get('icmptype')
    icmpv6type = args.get('icmpv6type')

    response = client.security_group_service_create_request(sg_id, name, protocol_type, port,  # type: ignore[arg-type]
                                                            policy_type, open_for_all, description,  # type: ignore[arg-type]
                                                            data_id, data_name, scope_type,  # type: ignore[arg-type]
                                                            is_valid, inbound, icmptype, icmpv6type)  # type: ignore[arg-type]
    sg_service = [{
        'id': response['id'],
        'name': response['name'],
        'protocol Type': response['protocolType'],
        'port': response['port'],
        'description': response['description'],
        'security Group ID': sg_id
    }]

    readable_output = tableToMarkdown(name='Security group service created successfully',
                                      t=sg_service,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.SecurityGroup.Service',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def security_group_service_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Update a service (rule) for an AWS security group. Can update only port and name.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    sg_id = args.get('sg_id')
    policy_type = args.get('policy_type')
    service_name = args.get('service_name')
    protocol_type = args.get('protocol_type')
    port = arg_to_number(args.get('port'))
    open_for_all = args.get('open_for_all')
    description = args.get('description')
    data_id = args.get('data_id')
    data_name = args.get('data_name')
    scope_type = args.get('scope_type')
    is_valid = args.get('is_valid')
    inbound = args.get('inbound')
    icmptype = args.get('icmptype')
    icmpv6type = args.get('icmpv6type')

    response = client.security_group_service_update_request(sg_id, service_name, protocol_type,  # type: ignore[arg-type]
                                                            port, policy_type, open_for_all,  # type: ignore[arg-type]
                                                            description, data_id, data_name,  # type: ignore[arg-type]
                                                            scope_type, is_valid, inbound, icmptype,  # type: ignore[arg-type]
                                                            icmpv6type)  # type: ignore[arg-type]

    sg_service = [{
        'id': response['id'],
        'name': response['name'],
        'protocol Type': response['protocolType'],
        'port': response['port'],
        'description': response['description'],
        'security Group ID': sg_id,
        # 'scopeType': response['scope'][0]['type'],
        #    'scopeData': f"{response['scope'][0]['data']['id']} - {response['scope'][0]['data']['name']}",
    }]
    readable_output = tableToMarkdown(name='Security group service updated successfully',
                                      t=sg_service,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.SecurityGroup.Service',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def security_group_instance_detach_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Detach security Group from an AWS EC2 Instance.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    instance_id = args.get('instance_id')
    sg_id = args.get('sg_id')
    nic_name = args.get('nic_name')

    try:
        response = client.security_group_instance_detach_request(instance_id, sg_id, nic_name)  # type: ignore[arg-type]
    except Exception:
        raise ValueError('Security group already detached')

    command_results = CommandResults(readable_output="Security group detach successfully",
                                     outputs_prefix='CheckPointDome9.Instance',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def security_group_protection_mode_update_command(client: Client,
                                                  args: dict[str, Any]) -> CommandResults:
    """ Change the protection mode for an AWS security group (FullManage or ReadOnly).

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    protection_mode = args.get('protection_mode')
    sg_id = args.get('sg_id')

    response = client.protection_mode_update_request(sg_id, protection_mode)  # type: ignore[arg-type]
    security_group_list = create_sg_list([response])

    readable_output = tableToMarkdown(name='protection mode updated for security group :',
                                      t=security_group_list,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.SecurityGroup',
                                     outputs_key_field='security_group_id',
                                     outputs=security_group_list,
                                     raw_response=response)

    return command_results


def cloud_accounts_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get cloud account list.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    account_id = args.get('account_id')
    response = client.cloud_accounts_list_request(account_id)  # type: ignore[arg-type]
    if account_id:
        fix_output, pagination_message = response, ""
    else:
        fix_output, pagination_message = pagination(response, args)

    readable_output = tableToMarkdown(
        name='Cloud accounts:',
        metadata=pagination_message,
        headers=['id', 'vendor', 'externalAccountNumber', 'creationDate', 'organizationalUnitName'],
        t=fix_output,
        headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.CloudAccount',
                                     outputs_key_field='cloud_account_id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def instance_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get AWS instances.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    instance_id = args.get('instance_id')
    response = client.instance_list_request(instance_id)  # type: ignore[arg-type]
    fix_output, pagination_message = pagination(response, args)

    instance_list = []

    for instance in fix_output:
        instance_list.append({
            'account ID': instance['accountId'],
            'instance_id': instance['externalId'],
            'nics name': instance['nics'][0]['name'],
            'instance type': instance['instanceType'],
            'region': instance['region'],
            'image': instance['image'],
            'cloud account ID': instance['cloudAccountId']
        })

    readable_output = tableToMarkdown(name='AWS instances',
                                      metadata=pagination_message,
                                      t=instance_list,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.Instance',
                                     outputs_key_field='instance_id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def check_ip_list_security_group_attach_command(client: Client, args: dict[str,
                                                                           Any]) -> CommandResults:
    """ Get AWS cloud accounts for a specific security group and region and check
        if there is an IP-list that attach to a security group.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    sg_id = args.get('sg_id')

    response = client.check_ip_list_security_group_attach_request(sg_id)  # type: ignore[arg-type]

    fix_output, pagination_message = pagination(response, args)

    security_group_list = create_sg_list(fix_output)

    readable_output = tableToMarkdown(name='Security Groups:',
                                      metadata=pagination_message,
                                      t=security_group_list,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.SecurityGroup',
                                     outputs_key_field='security_group_id',
                                     outputs=security_group_list,
                                     raw_response=response)

    return command_results


def security_group_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get all security group Entities.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.security_group_list_request()
    fix_output, pagination_message = pagination(response, args)

    security_group_list = []

    for sg in fix_output:
        security_group_list.append({
            'cloud_account_id': sg['cloudAccountId'],
            'region_id': sg['regionId'],
            'security_group_id': sg['externalId'],
            'security_group_name': sg['securityGroupName'],
            'vpc_id': sg['vpcId']
        })

    readable_output = tableToMarkdown(name='Security Groups:',
                                      metadata=pagination_message,
                                      t=security_group_list,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.SecurityGroup',
                                     outputs_key_field='security_group_id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def global_search_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get top results for each service.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.global_search_get_request()

    output = response['alerts']
    alerts = []
    for alert in output:
        alerts.append({
            'id': alert['id'],
            'createdTime': alert['createdTime'],
            'updatedTime': alert['updatedTime'],
            'cloudAccountId': alert['cloudAccountId'],
            'cloudAccountExternalId': alert['cloudAccountExternalId'],
            'bundleId': alert['bundleId'],
            'alertType': alert['alertType'],
            'severity': alert['severity'],
            'entityName': alert['entityName'],
            'ruleName': alert['ruleName'],
            'description': alert['description'],
            'remediation': alert['remediation'],
        })

    readable_output = tableToMarkdown(name='Global Search',
                                      t=alerts,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.GlobalSearch.Alert',
                                     outputs_key_field='id',
                                     outputs=alerts,
                                     raw_response=response)

    return command_results


def cloud_trail_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get CloudTrail events for a Dome9 user.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.cloud_trail_get_request()

    cloud_trail = response[0]  # type: ignore[index]
    cloud_trail_output = []
    cloud_trail_output.append({
        'name': cloud_trail['name'],
        'id': cloud_trail['id'],
        'region': cloud_trail['region'],
        'accountId': cloud_trail['accountId'],
        's3BucketName': cloud_trail['s3BucketName'],
    })

    readable_output = tableToMarkdown(name='Cloud Trail',
                                      t=cloud_trail_output,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.CloudTrail',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def findings_bundle_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get the findings for a specific rule in a bundle, for all of the user's accounts.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    bundle_id = arg_to_number(args.get('bundle_id'))
    rule_logic_hash = args.get('rule_logic_hash')

    response = client.findings_bundle_get_request(bundle_id, rule_logic_hash)  # type: ignore[arg-type]

    readable_output = tableToMarkdown(name='Findings Bundle',
                                      t=response,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.FindingBundle',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def organizational_unit_view_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get organizational unit view entities.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.organizational_unit_view_get_request()

    readable_output = tableToMarkdown(name='Organizational Unit View',
                                      t=response,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.OrganizationalUnitView',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def organizational_unit_flat_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get organizational unit view entities.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.organizational_unit_flat_get_request()
    fix_output, pagination_message = pagination(response, args)

    readable_output = tableToMarkdown(name='Organizational Unit Flat',
                                      metadata=pagination_message,
                                      t=fix_output,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.OrganizationalUnitFlat',
                                     outputs_key_field='id',
                                     outputs=fix_output,
                                     raw_response=response)

    return command_results


def organizational_unit_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get an organizational unit by its ID.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    unit_id = args.get('unit_id')
    response = client.organizational_unit_get_request(unit_id)  # type: ignore[arg-type]
    output = response[0]['item']  # type: ignore[index]

    organizational_unit_list = []

    organizational_unit_list.append({
        'accountId': output['accountId'],
        'id': output['id'],
        'name': output['name'],
        'created': output['created'],
        'updated': output['updated'],
        'isRoot': output['isRoot'],
        'awsCloudAcountsCount': output['awsCloudAcountsCount'],
    })

    readable_output = tableToMarkdown(name='Organizational Unit',
                                      t=organizational_unit_list,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.OrganizationalUnit',
                                     outputs_key_field='id',
                                     outputs=output,
                                     raw_response=response)

    return command_results


def finding_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get a findings by its ID.

    Args:
        client (Client): Dome9 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    finding_id = args.get('finding_id')
    response = client.finding_get_request(finding_id)  # type: ignore[arg-type]
    readable_output = tableToMarkdown(name='Findings:',
                                      t=response,
                                      headers=[
                                          'id', 'alertType', 'severity', 'region', 'status',
                                          'action', 'cloudAccountId', 'description'
                                      ],
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='CheckPointDome9.Finding',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def parse_incident(alert: dict) -> dict:
    """
    Parse alert to XSOAR Incident.

    Args:
        alert (dict): alert item.

    Returns:
        dict: XSOAR Incident.
    """
    alert_date = datetime.strptime(alert.get("createdTime"), TIME_FORMAT)  # type: ignore[arg-type]
    iso_time = FormatIso8601(alert_date) + 'Z'

    incident = {
        'name': "Dome9 Alert ID: " + alert.get('id'),  # type: ignore[arg-type,operator]
        'occurred': iso_time,
        'rawJSON': json.dumps(alert)
    }

    return incident


def fetch_incidents(client: Client, args: dict) -> None:
    """ This function retrieves new alerts every interval (default is 1 minute).
        This function has to implement the logic of making sure that incidents are
        fetched only onces and no incidents are missed. By default it's invoked by
        XSOAR every minute. It will use last_run to save the timestamp of the last
        alert it processed. If last_run is not provided, it should use the
        integration parameter first_fetch to determine when to start fetching
        the first time.

    Args:
        client (Client): The API client.
        args (dict): The args for fetch: alert types, alert severities, alert status,
                     max fetch and first fetch.
    """
    last_run = demisto.getLastRun()
    last_run_id = last_run.get('id')
    last_run_time = last_run.get('time')

    if not last_run:
        last_run_time = args.get('first_fetch', '3 Days')
        max_fetch = args.get('max_fetch')
    else:
        max_fetch = arg_to_number(args.get('max_fetch'))

    alert_severity = argToList(args.get('alert_severity'))
    alert_region = argToList(args.get('alert_region'))

    first_fetch = arg_to_datetime(arg=last_run_time, arg_name='First fetch time', required=True)

    first_fetch_timestamp = int(first_fetch.timestamp()) if first_fetch else None

    assert isinstance(first_fetch_timestamp, int)

    alert_list = client.findings_search_request(max_fetch, alert_severity, alert_region)  # type: ignore[arg-type]
    incidents = []

    # convert the last_run_time to dome9 time format
    last_run_datetime = dateparser.parse(last_run_time)
    last_run_str = last_run_datetime.strftime(TIME_FORMAT)  # type: ignore[union-attr]
    last_run_datetime = dateparser.parse(last_run_str)

    for alert in alert_list['findings']:
        alert_time = dateparser.parse(alert['createdTime'])
        if alert.get('id') != last_run_id and last_run_datetime < alert_time:  # type: ignore[return-value,operator]
            incidents.append(parse_incident(alert))

    demisto.incidents(incidents)

    if incidents:
        last_run_time = alert['createdTime']
        last_run_id = alert['id']
        demisto.setLastRun({'time': last_run_time, 'id': last_run_id})


def test_module(client: Client) -> None:
    try:
        client.access_lease_list_request()
    except DemistoException as e:
        if 'password' in str(e):
            return 'Authorization Error: make sure API key ID & secret are correctly set'  # type: ignore[return-value]
        else:
            raise e
    return 'ok'  # type: ignore[return-value]


def main() -> None:

    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()

    base_url = params.get('base_url')

    key_id = params.get('api_key_id')
    key_secret = params.get('api_key_secret')
    api_key_id_cred = params.get('api_key_id_cred', {}).get('password')
    api_key_secret_cred = params.get('api_key_secret_cred', {}).get('password')

    # get the api key and secret credentials
    key_id = api_key_id_cred or key_id
    key_secret = api_key_secret_cred or key_secret

    # validate the api key and secret credentials
    if not key_id:
        raise ValueError('Please provide a valid API key ID.')
    if not key_secret:
        raise ValueError('Please provide a valid API key secret.')

    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'dome9-access-lease-list': access_lease_list_command,
        'dome9-access-lease-delete': access_lease_delete_command,
        'dome9-access-lease-invitation-list': access_lease_invitation_list_command,
        'dome9-access-lease-invitation-delete': access_lease_invitation_delete_command,
        'dome9-findings-search': findings_search_command,
        'dome9-ip-list-create': ip_list_create_command,
        'dome9-ip-list-update': ip_list_update_command,
        'dome9-ip-list-get': ip_list_get_command,
        'dome9-ip-list-delete': ip_list_delete_command,
        'dome9-ip-list-metadata-list': ip_list_metadata_list_command,
        'dome9-ip-list-metadata-create': ip_list_metadata_create_command,
        'dome9-ip-list-metadata-update': ip_list_metadata_update_command,
        'dome9-ip-list-metadata-delete': ip_list_metadata_delete_command,
        'dome9-compliance-remediation-get': compliance_remediation_get_command,
        'dome9-compliance-remediation-create': compliance_remediation_create_command,
        'dome9-compliance-remediation-update': compliance_remediation_update_command,
        'dome9-compliance-remediation-delete': compliance_remediation_delete_command,
        'dome9-compliance-ruleset-list': compliance_ruleset_list_command,
        'dome9-compliance-ruleset-rule-list': compliance_ruleset_rule_list_command,
        'dome9-security-group-instance-attach': security_group_instance_attach_command,
        'dome9-security-group-service-delete': security_group_service_delete_command,
        'dome9-security-group-tags-update': security_group_tags_update_command,
        'dome9-security-group-service-create': security_group_service_create_command,
        'dome9-security-group-service-update': security_group_service_update_command,
        'dome9-security-group-instance-detach': security_group_instance_detach_command,
        'dome9-security-group-protection-mode-update':
        security_group_protection_mode_update_command,
        'dome9-cloud-accounts-list': cloud_accounts_list_command,
        'dome9-security-group-ip-list-details-get': check_ip_list_security_group_attach_command,
        'dome9-security-group-list': security_group_list_command,
        'dome9-instance-list': instance_list_command,
        'dome9-findings-get': finding_get_command,
        'dome9-organizational-unit-get': organizational_unit_get_command,
        'dome9-organizational-unit-flat-get': organizational_unit_flat_get_command,
        'dome9-organizational-unit-view-get': organizational_unit_view_get_command,
        'dome9-findings-bundle-get': findings_bundle_get_command,
        'dome9-cloud-trail-get': cloud_trail_get_command,
        'dome9-global-search-get': global_search_get_command
    }

    try:
        client: Client = Client(base_url, key_id, key_secret, proxy,  # type: ignore[arg-type]
                                verify_certificate)  # type: ignore

        if command == 'test-module':
            return_results(test_module(client))  # type: ignore[func-returns-value]
        if command == 'fetch-incidents':
            fetch_incidents(client, params)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'One or more of the specified fields are invalid. Please validate them. {e}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
