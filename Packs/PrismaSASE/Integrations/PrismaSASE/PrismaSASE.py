import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
SEARCH_LIMIT = 200
DEFAULT_LIMIT = 50
PA_OUTPUT_PREFIX = "PrismaSase."
CONFIG_URI_PREFIX = "/sse/config/v1/"


SECURITYRULE_FIELDS = {
    "action": "",
    "application": [],
    "category": [],
    "description": "",
    "destination": [],
    "destination_hip": [],
    "disabled": "",
    "from": [],
    "log_setting": "",
    "name": "",
    "negate_destination": "",
    "negate_source": "",
    "profile_setting": {},
    "service": [],
    "source": [],
    "source_hip": [],
    "source_user": [],
    "tag": [],
    "to": [],
}

ADDRESS_TYPES = ("ip_netmask", "ip_range", "ip_wildcard", "fqdn")


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls to the Saas Security platform, and does not contain any XSOAR logic.
    Handles the token retrieval.

    Args:
       base_url (str): Saas Security server url.
       client_id (str): client ID.
       client_secret (str): client secret.
       verify (bool): specifies whether to verify the SSL certificate or not.
       proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, client_id: str,
                 client_secret: str, oauth_url: str, tsg_id: str, verify: bool, proxy: bool, headers: dict, **kwargs):

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers, **kwargs)

        self.client_id = client_id
        self.client_secret = client_secret
        self.oauth_url = oauth_url
        self.tsg_id = tsg_id

    def http_request(self,
                     method: str,
                     url_suffix: str = '',
                     params: dict = None,
                     json_data: dict = None) -> dict:

        headers = self.access_token_to_headers()
        return self._http_request(method=method,
                                  url_suffix=url_suffix,
                                  params=params,
                                  json_data=json_data,
                                  headers=headers)

    @staticmethod
    def build_security_rule(args: Dict[str, Any]) -> dict:
        """Build a dictionary of security rule parameters to be used to create or edit a rule
        Args:
            args: demisto.args()
        Returns:
            Security rule dictionary
        """
        rule = {}
        keys = args.keys()
        for key in SECURITYRULE_FIELDS:
            if key in keys:
                field_value = args.get(key)
                if field_value:
                    if key == 'profile_setting':
                        val = argToList(field_value)
                        rule[key] = {'group': val}
                    if key == 'source_user':
                        val = argToList(field_value, ';')
                        rule[key] = val
                    elif isinstance(SECURITYRULE_FIELDS.get(key), str):
                        rule[key] = field_value  # type: ignore
                    elif isinstance(SECURITYRULE_FIELDS.get(key), list):
                        val = argToList(field_value)
                        rule[key] = val  # type: ignore

        return rule

    def create_security_rule(self, rule: dict, folder: str, position: str) -> dict:
        """Command to create new Prisma SASE security rule within the given Folder, Position, and Tenant/TSG
        Args:
            rule: Security rule dictionary
            folder: Prisma SASE Folder
            position: Prisma SASE rule position
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}security-rules'

        query_params = {
            'folder': encode_string_results(folder),
            'position': encode_string_results(position)
        }
        return self.http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=rule
        )

    def edit_security_rule(self, rule: dict, rule_id: str) -> dict:
        """Edit existing Prisma SASE security rule
        Args:
            rule: Security rule dictionary
            rule_id: identifier of rule to be edited
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}security-rules/{rule_id}'

        return self.http_request(
            method="PUT",
            url_suffix=uri,
            json_data=rule
        )

    def delete_security_rule(self, rule_id: str) -> dict:
        """Delete Prisma SASE security rule
        Args:
            rule_id: Identifier of the existing rule to be deleted
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}security-rules/{rule_id}'

        return self.http_request(
            method="DELETE",
            url_suffix=uri
        )

    def create_address_object(self, address: dict, folder: str) -> dict:
        """Create new Prisma SASE security rule within the given Folder, Position, and Tenant/TSG
        Args:
            address: address object dictionary
            folder: Prisma SASE Folder
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}addresses'
        query_params = {
            'folder': encode_string_results(folder)
        }

        return self.http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=address
        )

    def edit_address_object(self, address: dict, address_id: str) -> dict:
        """Edit existing address object
        Args:
            address: Address object dictionary
            address_id: Identifier of existing address to be edited
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}addresses/{address_id}'

        return self.http_request(
            method="PUT",
            url_suffix=uri,
            json_data=address
        )

    def delete_address_object(self, address_id: str) -> dict:
        """Delete existing address object
        Args:
            address_id: Identifier of existing address to be deleted
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}addresses/{address_id}'

        return self.http_request(
            method="DELETE",
            url_suffix=uri
        )

    def list_address_objects(self, query_params: dict) -> dict:
        """Return list of address objects from Prisma SASE
        Args:
            query_params: query parameters for the request
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}addresses'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )

    def list_security_rules(self, query_params: dict) -> dict:
        """Command to list security rules
        Args:
            query_params: query parameters for the request
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}security-rules'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )

    def query_agg_monitor_api(self, uri: str, query: dict) -> dict:
        """Query the Prisma SASE aggregate monitor API
        Args:
            uri: Query URI
            query: Query body represented as json
        Returns:
            Outputs.
        """
        query_params = {
            'agg_by': 'tenant'
        }

        if query is not None:
            return self.http_request(
                method="POST",
                url_suffix=uri,
                params=query_params,
                json_data=query
            )
        else:
            return self.http_request(
                method="GET",
                url_suffix=uri,
                params=query_params
            )

    def push_candidate_config(self, folders: str, description: str) -> dict:
        """Push candidate configuration
        Args:
            folders: Target Prisma SASE Folders for the configuration commit
            description: Description for the job
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}config-versions/candidate:push'
        body = {"folders": folders}
        if description:
            body['description'] = description

        return self.http_request(
            method="POST",
            url_suffix=uri,
            json_data=body
        )

    def get_config_job_by_id(self, job_id: str) -> dict:
        """List config jobs filtered by ID
        Args:
            job_id: ID of the config job
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}jobs/{job_id}'

        return self.http_request(
            method="GET",
            url_suffix=uri,
        )

    def list_config_jobs(self, query_params: dict) -> dict:
        """List config jobs
        Args:
            query_params: Address object dictionary
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}jobs'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
        )

    def get_address_by_id(self, query_params: dict, address_id: str) -> dict:
        """Get an existing address object
        Args:
            query_params: Address object dictionary
            address_id: Identifier of existing address to be edited
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}addresses/{address_id}'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )

    def get_security_rule_by_id(self, query_params: dict, rule_id: str) -> dict:
        """Get existing security rule
        Args:
            query_params: Address object dictionary
            rule_id: Identifier of existing address to be edited
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}security-rules/{rule_id}'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )

    def get_tag_by_id(self, query_params: dict, tag_id: str) -> dict:
        """Get a tag
        Args:
            query_params: Address object dictionary
            tag_id: Identifier of existing tag to be edited
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}tags/{tag_id}'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )

    def list_tags(self, query_params: dict) -> dict:
        """Command to list tags
        Args:
            query_params: query parameters for the request
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}tags'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )

    def update_tag(self, tag_id: str, tag: dict) -> dict:
        """Edit existing address object
        Args:
            tag: Tag dictionary
            tag_id: Identifier of existing address to be edited
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}tags/{tag_id}'

        return self.http_request(
            method="PUT",
            url_suffix=uri,
            json_data=tag
        )

    def delete_tag(self, tag_id: str) -> dict:
        """Delete Prisma SASE tag
        Args:
            tag_id: Identifier of the existing tag to be deleted
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}tags/{tag_id}'

        return self.http_request(
            method="DELETE",
            url_suffix=uri
        )

    def create_tag(self, query_params: dict, tag: dict) -> dict:
        """Create new Prisma SASE tag within the given Folder
        Args:
            tag: tag dictionary
            query_params: Prisma SASE Folder
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}tags'

        return self.http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=tag
        )

    def get_address_group_by_id(self, query_params: dict, group_id: str) -> dict:
        """Get a tag
        Args:
            query_params: Address object dictionary
            group_id: Identifier of existing tag to be edited
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}address-groups/{group_id}'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )

    def list_address_group(self, query_params: dict) -> dict:
        """Get all address groups
        Args:
            query_params: Address object dictionary
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}address-groups'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )

    def update_address_group(self, address_group: dict, group_id: str) -> dict:
        """Edit existing address group
        Args:
            address_group: Address object dictionary
            group_id: Identifier of existing address group to update
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}address-groups/{group_id}'

        return self.http_request(
            method="PUT",
            url_suffix=uri,
            json_data=address_group
        )

    def create_address_group(self, query_params: dict, address_group: dict) -> dict:
        """Create new Prisma SASE addres group
        Args:
            address_group: address group dictionary
            query_params: Prisma SASE Folder
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}address-groups'

        return self.http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=address_group
        )

    def delete_address_group(self, group_id: str) -> dict:
        """Delete Prisma SASE address group
        Args:
            group_id: Identifier of the existing address group to be deleted
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}address-groups/{group_id}'

        return self.http_request(
            method="DELETE",
            url_suffix=uri
        )

    def get_custom_url_category_by_id(self, query_params: dict, id: str) -> dict:
        """Get a tag
        Args:
            query_params: Address object dictionary
            id: Identifier of existing tag to be edited
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}url-categories/{id}'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )

    def list_custom_url_category(self, query_params: dict) -> dict:
        """Get all custom url category
        Args:
            query_params: Address object dictionary
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}url-categories'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )

    def update_custom_url_category(self, custom_url_category: dict, id: str) -> dict:
        """Updatr existing custom url category
        Args:
            custom_url_category: custom url category
            id: Identifier of existing address group to update
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}url-categories/{id}'

        return self.http_request(
            method="PUT",
            url_suffix=uri,
            json_data=custom_url_category
        )

    def create_custom_url_category(self, query_params: dict, custom_url_category: dict) -> dict:
        """Create new custom url category
        Args:
            custom_url_category: address group dictionary
            query_params: Prisma SASE Folder
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}url-categories'

        return self.http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=custom_url_category
        )

    def delete_custom_url_category(self, id: str) -> dict:
        """Delete custom url category
        Args:
            id: Identifier of the existing custom url category to be deleted
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}url-categories/{id}'

        return self.http_request(
            method="DELETE",
            url_suffix=uri
        )

    def get_access_token(self) -> str:
        """Get access token to use for API call.

        The SASE API is multi-tenant capable and the tenant structure is hierarchical.
        The TSG (tenant services group) is an identifier for a particular tenant.
        A single API service account can have access to the root tenant and any number of sub-tenants underneath.
        The scope / target of the API call is determined via the requested authorization token.

        If there is an existing access token, and it has not expired, set it as the access token for this request
        Else request a new access token for the provided TSG and store it in the integration context and add the TSG ID
        as a prefix.

        Returns:
            The access token
        """

        integration_context = get_integration_context()
        tsg_access_token = f'{self.tsg_id}.access_token'
        tsg_expiry_time = f'{self.tsg_id}.expiry_time'
        previous_token = integration_context.get(tsg_access_token)
        previous_token_expiry_time = integration_context.get(tsg_expiry_time)

        if previous_token and previous_token_expiry_time > date_to_timestamp(datetime.now()):
            return previous_token
        else:
            tsg = f'tsg_id:{self.tsg_id}'
            data = {
                'grant_type': 'client_credentials',
                'scope': tsg
            }
            try:
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                }

                res = self._http_request(method='POST',
                                         full_url=self.oauth_url,
                                         auth=(self.client_id, self.client_secret),
                                         resp_type='response',
                                         headers=headers,
                                         data=data)
                try:
                    res = res.json()
                except ValueError as exception:
                    raise DemistoException(f'Failed to parse json object from response: {res.text}.\n'
                                           f'Error: {exception}')

                if access_token := res.get('access_token'):
                    expiry_time = date_to_timestamp(datetime.now(), date_format=DATE_FORMAT)
                    expiry_time += res.get('expires_in', 0) - 10
                    new_token = {
                        tsg_access_token: access_token,
                        tsg_expiry_time: expiry_time
                    }
                    # store received token and expiration time in the integration context
                    set_integration_context(new_token)
                    return access_token

                else:
                    raise DemistoException('Error occurred while creating an access token. Access token field has not'
                                           ' found in the response data. Please check the instance configuration.\n')

            except Exception as e:
                raise DemistoException(f'Error occurred while creating an access token. Please check the instance'
                                       f' configuration.\n\n{e}')

    def access_token_to_headers(self) -> dict:
        access_token = self.get_access_token()

        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"
        return headers


"""HELPER FUNCTIONS"""


def modify_address(outputs: List[dict]) -> List[dict]:
    for output in outputs:
        for address_type in ADDRESS_TYPES:
            if address_type in output:
                output['type'] = address_type
                output['address_value'] = output[address_type]
                output.pop(address_type)
    return outputs


def modify_group_address(outputs: List[dict]) -> List[dict]:
    for output in outputs:
        if 'static' in output:
            output['addresses'] = output['static']
            output.pop('static')
        elif 'dynamic' in output:
            output['dynamic_filter'] = output['dynamic'].get('filter', '')
            output.pop('dynamic')
    return outputs


def update_new_rule(new_rule: dict, original_rule: dict, overwrite: bool) -> dict:

    if overwrite:
        # simply update the relevant keys with the new data
        original_rule.update(new_rule)
        return original_rule

    for key, value in new_rule.items():
        if isinstance(SECURITYRULE_FIELDS.get(key), list):
            # the 'any' value should be overwritten in all cases
            if 'any' in value or 'any' in original_rule.get(key, []):
                original_rule[key] = argToList(new_rule.get(key))
            else:
                original_rule.get(key, []).extend(argToList(new_rule.get(key, [])))
    return original_rule


"""COMMANDS"""


def test_module(client: Client) -> CommandResults:
    """Test command to determine if integration is working correctly.
    Args:
        client: Client object with request

    Returns:
        Outputs.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    """
    uri = f'{CONFIG_URI_PREFIX}config-versions?limit=1'

    client.http_request(method='GET', url_suffix=uri)
    return CommandResults(
        raw_response="ok"
    )


def create_security_rule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to create new Prisma Access security rule within the given Folder, Position, and Tenant/TSG
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    rule = client.build_security_rule(args)

    raw_response = client.create_security_rule(rule, args.get('folder'), args.get('position'))  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}SecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rule Created', outputs, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def create_address_object_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to create new Prisma Access address object
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    address_object = {
        args.get('type'): args.get('address_value'),
        'name': args.get('name')}

    if args.get('description'):
        address_object["description"] = args.get('description')

    if args.get('tag'):
        address_object['tag'] = args.get('tag')

    raw_response = client.create_address_object(address_object, args.get('folder'))  # type: ignore

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}Address',
        outputs_key_field='id',
        outputs=raw_response,
        readable_output=tableToMarkdown('Address Object Created', raw_response, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def edit_address_object_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to create new Prisma Access address object
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    query_params = {
        'folder': encode_string_results(args.get('folder'))
    }
    object_id = args.get('object_id')
    # first get the original address, so user won't need to send all data
    original_address = client.get_address_by_id(query_params, object_id)
    for address_type in ADDRESS_TYPES:
        # address object can have exactly one type. If the type is updated, need to delete the previous type
        if address_type in original_address:
            original_address.pop(address_type)
    original_address[args.get('type')] = args.get('address_value')

    if description := args.get('description'):
        original_address['description'] = description

    if tag := args.get('tag'):
        original_address['tag'] = tag

    raw_response = client.edit_address_object(original_address, object_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}Address',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Address Object Edited', outputs, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def delete_address_object_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to delete Prisma Access address object
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    raw_response = client.delete_address_object(args.get('id'))  # type: ignore

    return CommandResults(
        readable_output=f'Address object with id {raw_response.get("id", "")} '
                        f'and name {raw_response.get("name", "")} was deleted successfully',
        raw_response=raw_response
    )


def list_address_objects_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to get address objects for a given Prisma Access Folder / Position
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    query_params = {
        'folder': encode_string_results(args.get('folder'))
    }
    if object_id := args.get('object_id'):
        raw_response = client.get_address_by_id(query_params, object_id)
        outputs = [raw_response]
    else:
        page = arg_to_number(args.get('page')) or 1
        page_size = arg_to_number(args.get('page_size'))
        if page and page_size:
            query_params['offset'] = (page - 1) * page_size
            query_params['limit'] = page_size
        elif limit := arg_to_number(args.get('limit', DEFAULT_LIMIT)):
            query_params['limit'] = limit

        raw_response = client.list_address_objects(query_params)  # type: ignore

        outputs = raw_response.get('data')

    outputs = modify_address(outputs)

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}Address',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Address Objects', outputs,
                                        headers=['id', 'name', 'description', 'type', 'address_value', 'tag'],
                                        headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def delete_security_rule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to delete the specified security rule within the targeted Prisma Access tenant / TSG
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    rule_id = args.get('rule_id')

    raw_response = client.delete_security_rule(rule_id)  # type: ignore

    return CommandResults(
        readable_output=f'Security Rule object with id {raw_response.get("id", "")} '
                        f'and name {raw_response.get("name", "")} was deleted successfully',
        raw_response=raw_response
    )


def query_agg_monitor_api_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to query the SASE aggregate monitor API
    Args:
        client: Client object with request
        args: demisto.args()
            uri: Aggregate Monitor URI to query (for example: mt/monitor/v1/agg/threats)
            tsg_id: Tenant services group ID
            query_data: JSON structure query data

    Returns:
        Query Results
    """

    if query_data := args.get('query_data'):
        try:
            query = json.loads(query_data)  # type: ignore
        except ValueError as exception:
            raise DemistoException('Failed to parse query data.  Please check syntax.',
                                   exception)
    else:
        query = None

    raw_response = client.query_agg_monitor_api(args.get('uri'), query)  # type: ignore

    return CommandResults(
        readable_output=tableToMarkdown('Aggregate Monitor API Query Response', raw_response,
                                        headerTransform=string_to_table_header),
        raw_response=raw_response,
        outputs=raw_response,
        outputs_prefix='PrismaSase.AggregateQueryResponse'
    )


def edit_security_rule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to Update / Edit an existing Prisma Access security rule
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """
    rule = client.build_security_rule(args)
    rule_id = args.get('rule_id')
    overwrite = argToBoolean(args.get('overwrite'))
    query_params = {
        'folder': encode_string_results(args.get('folder'))
    }
    original_rule = client.get_security_rule_by_id(query_params, rule_id)
    updated_rule = update_new_rule(rule, original_rule, overwrite=overwrite)
    raw_response = client.edit_security_rule(updated_rule, rule_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}SecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rule Updated', outputs, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def push_candidate_config_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to Trigger a configuration push for the identified Folder/Devices
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """
    folders = argToList(args.get('folders'))  # type: ignore

    raw_response = client.push_candidate_config(folders, args.get('description'))  # type: ignore

    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}CandidateConfig',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Configuration Push Requested', outputs,
                                        headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def list_security_rules_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to Get all security rules for a given Prisma Access Folder / Position
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    query_params = {
        'folder': encode_string_results(args.get('folder')),
        'position': encode_string_results(args.get('position'))
    }

    if rule_id := args.get('rule_id') or '':
        raw_response = client.get_security_rule_by_id(query_params, rule_id)
        outputs = raw_response
    else:
        page = arg_to_number(args.get('page')) or 1
        page_size = arg_to_number(args.get('page_size'))
        if page and page_size:
            query_params['offset'] = (page - 1) * page_size
            query_params['limit'] = page_size
        elif limit := arg_to_number(args.get('limit', DEFAULT_LIMIT)):
            query_params['limit'] = limit

        raw_response = client.list_security_rules(query_params)  # type: ignore
        outputs = raw_response.get('data') or {}

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}SecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rules', outputs,
                                        headers=[
                                            'id', 'name', 'description', 'action', 'destination', 'folder', 'disabled'
                                        ],
                                        headerTransform=string_to_table_header,
                                        removeNull=True),
        raw_response=raw_response
    )


def list_config_jobs_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to list config jobs from Prisma Access
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """
    # TODO - add pagination

    query_params = {}
    if job_id := args.get('job_id'):
        raw_response = client.get_config_job_by_id(job_id)
    else:
        if limit := arg_to_number(args.get('limit', SEARCH_LIMIT)):
            query_params['limit'] = limit

        if offset := arg_to_number(args.get('offset', 0)):
            query_params['offset'] = offset

        raw_response = client.list_config_jobs(query_params)  # type: ignore

    outputs = raw_response.get('data')

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}ConfigJob',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Config Job',
                                        outputs,
                                        headers=['id', 'type_str', 'status_str', 'result_str', 'start_ts', 'end_ts'],
                                        headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def list_tags_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to list config jobs from Prisma Sase
        Args:
            client: Client object with request
            args: demisto.args()

        Returns:
            Outputs.
        """
    # TODO - add pagination

    query_params = {
        'folder': encode_string_results(args.get('folder'))
    }
    if tag_id := args.get('tag_id'):
        raw_response = client.get_tag_by_id(query_params, tag_id)
        outputs = raw_response
    else:
        if limit := arg_to_number(args.get('limit', SEARCH_LIMIT)):
            query_params['limit'] = limit

        if offset := arg_to_number(args.get('offset', 0)):
            query_params['offset'] = offset

        raw_response = client.list_tags(query_params)  # type: ignore
        outputs = raw_response.get('data')

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}Tag',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Tags',
                                        outputs,
                                        headers=['id', 'name', 'folder', 'color', 'comments'],
                                        headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def create_tag_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to create new Prisma Sase tag
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    tag = {
        'name': args.get('name')
    }

    if color := args.get('color'):
        tag['color'] = color

    if comments := args.get('comments'):
        tag['comments'] = comments

    raw_response = client.create_tag(tag, args.get('folder'))  # type: ignore

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}Tag',
        outputs_key_field='id',
        outputs=raw_response,
        readable_output=tableToMarkdown('Address Object Created', raw_response, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def update_tag_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to create new tag
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    query_params = {
        'folder': encode_string_results(args.get('folder'))
    }
    # first get the original tag, so user won't need to send all data
    original_tag = client.get_tag_by_id(query_params, args.get('tag_id'))
    print(original_tag)

    if color := args.get('color'):
        original_tag['color'] = color

    if comments := args.get('comments'):
        original_tag['comments'] = comments

    raw_response = client.update_tag(args.get('tag_id'), original_tag)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}Tag',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Tag Edited', outputs, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def delete_tag_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to delete the specified tag within the targeted Prisma Sase tenant / TSG
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    tag_id = args.get('tag_id')

    raw_response = client.delete_tag(tag_id)  # type: ignore

    return CommandResults(
        readable_output=f'Tag with id {raw_response.get("id", "")} '
                        f'and name {raw_response.get("name", "")} was deleted successfully',
        raw_response=raw_response
    )


def list_address_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to get address groups for a given Prisma Access Folder / Position
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    query_params = {
        'folder': encode_string_results(args.get('folder'))
    }
    if group_id := args.get('group_id'):
        raw_response = client.get_address_group_by_id(query_params, group_id)
        outputs = [raw_response]
    else:
        page = arg_to_number(args.get('page')) or 1
        page_size = arg_to_number(args.get('page_size'))
        if page and page_size:
            query_params['offset'] = (page - 1) * page_size
            query_params['limit'] = page_size
        elif limit := arg_to_number(args.get('limit', DEFAULT_LIMIT)):
            query_params['limit'] = limit

        raw_response = client.list_address_group(query_params)  # type: ignore

        outputs = raw_response.get('data')

    outputs = modify_group_address(outputs)

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}AddressGroup',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Address Groups', outputs,
                                        headers=['id', 'name', 'description', 'addresses', 'dynamic_filter'],
                                        headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def create_address_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to create new Prisma Access address group
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    address_group = {
        'name': args.get('name')}

    query_params = {
        'folder': encode_string_results(args.get('folder'))
    }

    if description := args.get('description'):
        address_group['description'] = description

    if group_type := args.get('type'):
        if group_type == 'static':
            if static_addresses := argToList(args.get('static_addresses')):
                address_group['static'] = static_addresses
        else:  # type == 'dynamic'
            if dynamic_filter := argToList(args.get('dynamic_filter')):
                address_group['dynamic'] = {'filter': dynamic_filter}

    raw_response = client.create_address_group(query_params, address_group)  # type: ignore

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}AddressGroup',
        outputs_key_field='id',
        outputs=raw_response,
        readable_output=tableToMarkdown('Address Group Created', raw_response, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def update_address_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to update new Prisma Access address group
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    query_params = {
        'folder': encode_string_results(args.get('folder'))
    }
    group_id = args.get('group_id')
    # first get the original address, so user won't need to send all data
    original_address_group = client.get_address_group_by_id(query_params, group_id)
    # TODO change overwrite

    if description := args.get('description'):
        original_address_group['description'] = description
    overwrite = args.get('overwrite')
    group_type = args.get('type')
    if not group_type:
        group_type = 'static' if 'static' in original_address_group else 'dynamic'

    if group_type == 'static':
        if static_addresses := argToList(args.get('static_addresses')):
            if static_addresses:
                original_address_group['static'] = static_addresses
                original_address_group.pop('dynamic')
    else:  # type == 'dynamic'
        if dynamic_filter := args.get('dynamic_filter'):
            if dynamic_filter:
                original_address_group['dynamic'] = {'filter': dynamic_filter}
                original_address_group.pop('static')

    raw_response = client.update_address_group(original_address_group, group_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}Address',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Address Group updated', outputs, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def delete_address_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to delete Prisma Access address group
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    raw_response = client.delete_address_group(args.get('group_id'))  # type: ignore

    return CommandResults(
        readable_output=f'Address group with id {raw_response.get("id", "")} '
                        f'and name {raw_response.get("name", "")} was deleted successfully',
        raw_response=raw_response
    )


def list_custom_url_category_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to get custom url categories
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    query_params = {
        'folder': encode_string_results(args.get('folder'))
    }
    if url_category_id := args.get('id'):
        raw_response = client.get_custom_url_category_by_id(query_params, url_category_id)
        outputs = [raw_response]
    else:
        page = arg_to_number(args.get('page')) or 1
        page_size = arg_to_number(args.get('page_size'))
        if page and page_size:
            query_params['offset'] = (page - 1) * page_size
            query_params['limit'] = page_size
        elif limit := arg_to_number(args.get('limit', DEFAULT_LIMIT)):
            query_params['limit'] = limit

        raw_response = client.list_custom_url_category(query_params)  # type: ignore

        outputs = raw_response.get('data')

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}CustomURLCategory',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Custom Url Categories', outputs,
                                        headers=['id', 'name', 'folder', 'type', 'match'],
                                        headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def create_custom_url_category_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to create new custom url category
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    custom_url_category = {
        'name': args.get('name'),
        'type': args.get('type')
    }

    query_params = {
        'folder': encode_string_results(args.get('folder'))
    }

    if description := args.get('description'):
        custom_url_category['description'] = description

    if value := argToList(args.get('value')):
        custom_url_category['list'] = value

    raw_response = client.create_custom_url_category(query_params, custom_url_category)  # type: ignore

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}CustomURLCategory',
        outputs_key_field='id',
        outputs=raw_response,
        readable_output=tableToMarkdown('Custom URrl Category Created', raw_response, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def update_custom_url_category_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to update custom url category
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    query_params = {
        'folder': encode_string_results(args.get('folder'))
    }
    url_category_id = args.get('id')
    # first get the original address, so user won't need to send all data
    original_custom_url_category = client.get_custom_url_category_by_id(query_params, url_category_id)
    # TODO change

    if description := args.get('description'):
        original_custom_url_category['description'] = description
    overwrite = args.get('overwrite')
    if category_type := args.get('type'):
        original_custom_url_category['type'] = category_type

    value = argToList(args.get('value'))
    if overwrite:
        original_custom_url_category['list'] = value
    else:
        original_custom_url_category.get('list', []).extend(value)

    raw_response = client.update_custom_url_category(original_address_group, url_category_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}CustomURLCategory',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Custom Url Category updated', outputs, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def delete_custom_url_category_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to delete Prisma custom url category
    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """

    raw_response = client.delete_custom_url_category(args.get('id'))  # type: ignore

    return CommandResults(
        readable_output=f'Custom Url Category with id {raw_response.get("id", "")} '
                        f'and name {raw_response.get("name", "")} was deleted successfully',
        raw_response=raw_response
    )




def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API url
    params = demisto.params()
    base_url = params.get('url').strip('/')
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    oauth_url = params.get('oauth_url')
    tsg_id = params.get('tsg_id')

    verify_certificate = not argToBoolean(params.get('insecure', False))
    proxy = argToBoolean(params.get('proxy', False))
    handle_proxy()

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    commands = {
        'test-module': test_module,
        'prisma-sase-security-rule-create': create_security_rule_command,
        'prisma-sase-security-rule-list': list_security_rules_command,
        'prisma-sase-security-rule-delete': delete_security_rule_command,
        'prisma-sase-security-rule-update': edit_security_rule_command,

        'prisma-sase-candidate-config-push': push_candidate_config_command,
        'prisma-sase-config-job-list': list_config_jobs_command,
        'prisma-sase-query-agg-monitor-api': query_agg_monitor_api_command,

        'prisma-sase-address-object-create': create_address_object_command,
        'prisma-sase-address-object-update': edit_address_object_command,
        'prisma-sase-address-object-delete': delete_address_object_command,
        'prisma-sase-address-object-list': list_address_objects_command,

        'prisma-sase-tag-list': list_tags_command,
        'prisma-sase-tag-create': create_tag_command,
        'prisma-sase-tag-update': update_tag_command,
        'prisma-sase-tag-delete': delete_tag_command,

        'prisma-sase-address-group-list': list_address_group_command,
        'prisma-sase-address-group-create': create_address_group_command,
        'prisma-sase-address-group-update': update_address_group_command,
        'prisma-sase-address-group-delete': delete_address_group_command,

        'prisma-sase-custom-url-category-list': list_custom_url_category_command,
        'prisma-sase-custom-url-category-create': create_custom_url_category_command,
        'prisma-sase-custom-url-category-update': update_custom_url_category_command,
        'prisma-sase-custom-url-category-delete': delete_custom_url_category_command,

    }
    client = Client(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        oauth_url=oauth_url,
        tsg_id=tsg_id,
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        proxy=proxy,
        ok_codes=(200, 201, 204))

    try:
        if command in commands:
            return_results(commands[command](client, demisto.args()))  # type: ignore
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
