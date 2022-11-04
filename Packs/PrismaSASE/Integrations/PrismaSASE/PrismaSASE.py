import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
SEARCH_LIMIT = 200
PA_OUTPUT_PREFIX = "PrismaAccess."
CONFIG_URI_PREFIX = "/sse/config/v1/"

SECURITYRULE_FIELDS = {
    "name": "",
    "action": "",
    "description": "",
    "log_setting": "",
    "application": [],
    "category": [],
    "destination": [],
    "destination_hip": [],
    "profile_setting": {},
    "service": [],
    "source": [],
    "source_hip": [],
    "source_user": [],
    "tag": [],
    "from": [],
    "to": [],
    "disabled": "",
    "negate_source": "",
    "negate_destination": ""
}


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
                 client_secret: str, oauth_url: str, verify: bool, proxy: bool, headers: dict, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret
        self.oauth_url = oauth_url

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers, **kwargs)

    @staticmethod
    def build_security_rule(args: Dict[str, Any]):
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
                if field_value != "" and field_value != "None":
                    if key == 'profile_setting':
                        val = argToList(field_value)
                        rule[key] = {'group': val}
                    elif isinstance(SECURITYRULE_FIELDS.get(key), str):
                        rule[key] = field_value   # type: ignore
                    elif isinstance(SECURITYRULE_FIELDS.get(key), list):
                        val = argToList(field_value)
                        rule[key] = val   # type: ignore
        return rule

    def create_security_rule(self, rule: dict, folder: str, position: str, tsg_id: str):
        """Command to create new Prisma Access security rule within the given Folder, Position, and Tenant/TSG
        Args:
            rule: Security rule dictionary
            folder: Prisma Access Folder
            position: Prisma access rule position
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}security-rules'
        access_token = self.get_access_token(tsg_id)

        query_params = {
            'folder': encode_string_results(folder),
            'position': encode_string_results(position)
        }

        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"

        return self._http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=rule,
            headers=headers
        )

    def edit_security_rule(self, rule: dict, ruleid: str, tsg_id: str):
        """Edit existing Prisma Access security rule
        Args:
            rule: Security rule dictionary
            folder: Prisma Access Folder
            postition: Prisma access rule position
            ruleid: identifier of rule to be edited
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}security-rules/{ruleid}'
        access_token = self.get_access_token(tsg_id)

        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"

        return self._http_request(
            method="PUT",
            url_suffix=uri,
            json_data=rule,
            headers=headers
        )

    def delete_security_rule(self, rule_id: str, tsg_id: str):
        """Delete Prisma Access security rule
        Args:
            rule_id: Identifier of the existing rule to be deleted
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'/sse/config/v1/security-rules/{rule_id}'
        access_token = self.get_access_token(tsg_id)
        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"

        return self._http_request(
            method="DELETE",
            url_suffix=uri,
            headers=headers
        )

    def create_address_object(self, address: dict, folder: str, tsg_id: str):
        """Create new Prisma Access security rule within the given Folder, Position, and Tenant/TSG
        Args:
            address: address object dictionary
            folder: Prisma Access Folder
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}addresses'
        access_token = self.get_access_token(tsg_id)

        query_params = {
            'folder': encode_string_results(folder)
        }

        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"

        return self._http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=address,
            headers=headers
        )

    def edit_address_object(self, address: dict, addressid: str, tsg_id: str):
        """Edit existing address object
        Args:
            address: Address object dictionary
            addressid: Identifier of existing address to be edited
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'/sse/config/v1/addresses/{addressid}'
        access_token = self.get_access_token(tsg_id)

        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"

        return self._http_request(
            method="PUT",
            url_suffix=uri,
            json_data=address,
            headers=headers
        )

    def delete_address_object(self, address_id: str, tsg_id: str):
        """Delete existing address object
        Args:
            addressid: Identifier of existing address to be deleted
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'/sse/config/v1/addresses/{address_id}'
        access_token = self.get_access_token(tsg_id)
        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"

        return self._http_request(
            method="DELETE",
            url_suffix=uri,
            headers=headers
        )

    def list_address_objects(self, query_params: dict, tsg_id: str):
        """Return list of address objects from Prisma Access
        Args:
            query_params: query paramters for the request
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}addresses'

        access_token = self.get_access_token(tsg_id)

        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"

        return self._http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            headers=headers
        )

    def list_security_rules(self, query_params: dict, tsg_id: str):
        """Command to list security rules
        Args:
            query_params: query paramters for the request
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}security-rules'

        access_token = self.get_access_token(tsg_id)

        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"

        return self._http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            headers=headers
        )

    def query_agg_monitor_api(self, tsg_id: str, uri: str, query: dict):
        """Query the Prisma SASE aggregate monitor API
        Args:
            uri: Query URI
            query: Query body represented as json
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        query_params = {
            'agg_by': "tenant"
        }

        access_token = self.get_access_token(tsg_id)

        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"

        if query is not None:
            return self._http_request(
                method="POST",
                url_suffix=uri,
                params=query_params,
                headers=headers,
                json_data=query
            )
        else:
            return self._http_request(
                method="GET",
                url_suffix=uri,
                params=query_params,
                headers=headers
            )

    def push_candidate_config(self, folders: str, description: str, tsg_id: str):
        """Push candidate configuration
        Args:
            folders: Target Prisma Access Folders for the configuration commit
            description: Description for the job
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}config-versions/candidate:push'

        access_token = self.get_access_token(tsg_id)

        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"

        body = {"folders": folders}

        if description:
            body['description'] = description

        return self._http_request(
            method="POST",
            url_suffix=uri,
            headers=headers,
            json_data=body
        )

    def get_config_jobs_by_id(self, tsg_id: str, job_id: str):
        """List config jobs filtered by ID
        Args:
            job_id: ID of the config job
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'/sse/config/v1/jobs/{job_id}'
        access_token = self.get_access_token(tsg_id)

        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"

        return self._http_request(
            method="GET",
            url_suffix=uri,
            headers=headers
        )

    def list_config_jobs(self, tsg_id: str, query_params: dict):
        """List config jobs
        Args:
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}jobs'
        access_token = self.get_access_token(tsg_id)
        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"
        return self._http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            headers=headers
        )

    def get_access_token(self, tsg_id: str):
        """Get access token to use for API call
        Args:
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.

        If there is an existing access token, and it has not expired, set it as the access token for this request
        Else request a new access token for the provided TSG and store it in the integration context and add the TSG ID
        as a prefix.
        """
        previous_token = get_integration_context()
        integration_context = get_integration_context()
        tsg_access_token = f'{tsg_id}.access_token'
        tsg_expiry_time = f'{tsg_id}.expiry_time'
        previous_token = integration_context.get(tsg_access_token)
        previous_token_expiry_time = integration_context.get(tsg_expiry_time)

        if previous_token and previous_token_expiry_time > date_to_timestamp(datetime.now()):
            return previous_token
        else:
            tsg = f'tsg_id:{tsg_id}'
            data = {
                'grant_type': "client_credentials",
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
                    raise DemistoException('Failed to parse json object from response: {}'.format(res.content),
                                           exception)

                if access_token := res.get('access_token'):
                    expiry_time = date_to_timestamp(datetime.now(), date_format='%Y-%m-%dT%H:%M:%S')
                    expiry_time += res.get('expires_in') * 1000 - 10
                    new_token = {
                        tsg_access_token: access_token,
                        tsg_expiry_time: expiry_time
                    }
                    # store received token and expiration time in the integration context
                    set_integration_context(new_token)
                    return access_token

                else:
                    raise DemistoException("Error occurred while creating an access token. Access token field has not"
                                           " found in the response data. Please check the instance configuration.\n")

            except Exception as e:
                raise DemistoException(f'Error occurred while creating an access token. Please check the instance'
                                       f' configuration.\n\n{e}')


def test_module(client: Client, default_tsg_id: str) -> CommandResults:
    """Test command to determine if integration is working correctly.
    Args:
        client: Client object with request
        default_tsg_id: Default Prisma SASE TSG configured for integration
    Returns:
        Outputs.

    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    """
    uri = f'{CONFIG_URI_PREFIX}config-versions?limit=1'

    access_token = client.get_access_token(default_tsg_id)
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {access_token}"
    }

    client._http_request(method='GET', url_suffix=uri, headers=headers)
    return CommandResults(
        raw_response="ok"
    )


def create_security_rule_command(client: Client, args: Dict[str, Any], default_tsg_id: str) -> CommandResults:
    """Command to create new Prisma Access security rule within the given Folder, Position, and Tenant/TSG
    Args:
        client: Client object with request
        args: demisto.args()
        default_tsg_id: Default Prisma SASE TSG configured for integration
    Returns:
        Outputs.
    """

    rule = client.build_security_rule(args)

    tsg_id = args.get('tsg_id') or default_tsg_id

    raw_response = client.create_security_rule(rule, args.get('folder'), args.get('position'), tsg_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}CreatedSecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rule Created', outputs),
        raw_response=raw_response
    )


def create_address_object_command(client: Client, args: Dict[str, Any], default_tsg_id: str) -> CommandResults:
    """Command to create new Prisma Access address object
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
        default_tsg_id: Default Prisma SASE TSG configured for integration
    Returns:
        Outputs.
    """

    address_object = {
        "ip_netmask": args.get('ip_netmask'),
        "name": args.get('name')}

    if args.get('description'):
        address_object["description"] = args.get('description')

    if args.get('tag'):
        address_object["tag"] = args.get('tag')

    tsg_id = args.get('tsg_id') or default_tsg_id

    raw_response = client.create_address_object(address_object, args.get('folder'), tsg_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}CreatedAddress',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Address Object Created', outputs),
        raw_response=raw_response
    )


def edit_address_object_command(client: Client, args: Dict[str, Any], default_tsg_id: str) -> CommandResults:
    """Command to create new Prisma Access address object
    Args:
        client: Client object with request
        args: demisto.args()
        default_tsg_id: Default Prisma SASE TSG configured for integration
    Returns:
        Outputs.
    """

    address_object = {
        "ip_netmask": args.get('ip_netmask'),
        "name": args.get('name')}

    if description := args.get('description'):
        address_object["description"] = description
    if tag := args.get('tag'):
        address_object["tag"] = tag

    tsg_id = args.get('tsg_id') or default_tsg_id

    raw_response = client.edit_address_object(address_object, args.get('id'), tsg_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}EditedAddress',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Address Object Edited', outputs),
        raw_response=raw_response
    )


def delete_address_object_command(client: Client, args: Dict[str, Any], default_tsg_id: str) -> CommandResults:
    """Command to delete Prisma Access address object
    Args:
        client: Client object with request
        args: demisto.args()
        default_tsg_id: Default Prisma SASE TSG configured for integration
    Returns:
        Outputs.
    """

    tsg_id = args.get('tsg_id') or default_tsg_id

    raw_response = client.delete_address_object(args.get('id'), tsg_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}DeletedAddress',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Address Object Deleted', outputs),
        raw_response=raw_response
    )


def list_address_objects_command(client: Client, args: Dict[str, Any], default_tsg_id: str) -> CommandResults:
    """Command to get address objects for a given Prisma Access Folder / Position
    Args:
        client: Client object with request
        args: demisto.args()
        default_tsg_id: Default Prisma SASE TSG configured for integration
    Returns:
        Outputs.
    """

    query_params = {
        'folder': encode_string_results(args.get('folder'))
    }

    tsg_id = args.get('tsg_id') or default_tsg_id

    if name := args.get('name'):
        query_params["name"] = encode_string_results(name)

    if limit := arg_to_number(args.get('limit', 10)):
        query_params["limit"] = limit
    if offset := arg_to_number(args.get('offset', 0)):
        query_params["offset"] = offset

    raw_response = client.list_address_objects(query_params, tsg_id)  # type: ignore

    outputs = raw_response.get('data')

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}FoundAddressObjects',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Address Objects', outputs, headers=[
                                        'name', 'description', 'ip_netmask', 'fqdn'], removeNull=True),
        raw_response=raw_response
    )


def delete_security_rule_command(client: Client, args: Dict[str, Any], default_tsg_id: str) -> CommandResults:
    """Command to delete the specified security rule within the targeted Prisma Access tenant / TSG
    Args:
        client: Client object with request
        args: demisto.args()
        default_tsg_id: Default Prisma SASE TSG configured for integration
    Returns:
        Outputs.
    """

    rule_id = args.get('rule_id')
    tsg_id = args.get('tsg_id') or default_tsg_id

    raw_response = client.delete_security_rule(rule_id, tsg_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}DeletedSecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rule Deleted', outputs),
        raw_response=raw_response
    )


def query_agg_monitor_api_command(client: Client, args: Dict[str, Any], default_tsg_id: str) -> CommandResults:
    """Command to query the SASE aggregate monitor API
    Args:
        client: Client object with request
        args: demisto.args()
            uri: Aggregate Monitor URI to query (for example: mt/monitor/v1/agg/threats)
            tsg_id: Tenant services group ID
            query_data: JSON structure query data
        default_tsg_id: Default Prisma SASE TSG configured for integration

    Returns:
        Query Results
    """

    tsg_id = args.get('tsg_id') or default_tsg_id

    if args.get('query_data'):
        query = json.loads(args.get('query_data'))  # type: ignore
    else:
        query = None

    raw_response = client.query_agg_monitor_api(tsg_id, args.get('uri'), query)  # type: ignore

    return CommandResults(
        readable_output=tableToMarkdown('Aggregate Monitor API Query Response', raw_response),
        raw_response=raw_response,
        outputs=raw_response,
        outputs_prefix='PrismaSASE.AggregateQueryResponse'
    )


def edit_security_rule_command(client: Client, args: Dict[str, Any], default_tsg_id: str) -> CommandResults:
    """Command to Update / Edit an existing Prisma Access security rule
    Args:
        client: Client object with request
        args: demisto.args()
        default_tsg_id: Default Prisma SASE TSG configured for integration
    Returns:
        Outputs.
    """
    rule = client.build_security_rule(args)

    tsg_id = args.get('tsg_id') or default_tsg_id

    raw_response = client.edit_security_rule(rule, args.get('id'), tsg_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}EditedSecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rule Updated', outputs),
        raw_response=raw_response
    )


def push_candidate_config_command(client: Client, args: Dict[str, Any], default_tsg_id: str) -> CommandResults:
    """Command to Trigger a configuration push for the identified Folder/Devices
    Args:
        client: Client object with request
        args: demisto.args()
        default_tsg_id: Default Prisma SASE TSG configured for integration
    Returns:
        Outputs.
    """
    folders = argToList(args.get('folders')) # type: ignore

    tsg_id = args.get('tsg_id') or default_tsg_id

    raw_response = client.push_candidate_config(folders, args.get('description'), tsg_id)  # type: ignore

    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}ConfigPush',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Configuration Push Requested', outputs),
        raw_response=raw_response
    )


def list_security_rules_command(client: Client, args: Dict[str, Any], default_tsg_id: str) -> CommandResults:
    """Command to Get all security rules for a given Prisma Access Folder / Position
    Args:
        client: Client object with request
        args: demisto.args()
        default_tsg_id: Default Prisma SASE TSG configured for integration
    Returns:
        Outputs.
    """
    query_params = {
        'folder': encode_string_results(args.get('folder')),
        'position': encode_string_results(args.get('position'))
    }

    tsg_id = args.get('tsg_id') or default_tsg_id

    if name := args.get('name'):
        query_params["name"] = encode_string_results(name)
    if limit := arg_to_number(args.get('limit', 10)):
        query_params["limit"] = limit
    if offset := arg_to_number(args.get('offset', 0)):
        query_params["offset"] = offset

    raw_response = client.list_security_rules(query_params, tsg_id)  # type: ignore

    outputs = raw_response.get('data')

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}FoundSecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rules', outputs, headers=[
                                        'id', 'name', 'description', 'action', 'destination', 'folder'],
                                        removeNull=True),
        raw_response=raw_response
    )


def get_security_rule_by_name_command(client: Client, args: Dict[str, Any], default_tsg_id: str) -> CommandResults:
    """Command to return single security rule from Prisma Access based on name
    Args:
        client: Client object with request
        args: demisto.args()
        default_tsg_id: Default Prisma SASE TSG configured for integration
    Returns:
        Outputs.
    """
    query_params = {
        'folder': encode_string_results(args.get('folder')),
        'position': encode_string_results(args.get('position')),
        "name": args.get('name'),
        "limit": 1,
        "offset": 0
    }

    tsg_id = args.get('tsg_id') or default_tsg_id

    raw_response = client.list_security_rules(query_params, tsg_id)  # type: ignore

    outputs = raw_response.get('data')

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}FoundSecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rules', outputs),
        raw_response=raw_response
    )


def get_config_jobs_by_id_command(client: Client, args: Dict[str, Any], default_tsg_id: str) -> CommandResults:
    """Command to list config jobs from Prisma Access filtered by command id
    Args:
        client: Client object with request
        args: demisto.args()
        default_tsg_id: Default Prisma SASE TSG configured for integration
    Returns:
        Outputs.
    """
    job_ids = argToList(args.get('id'))

    tsg_id = args.get('tsg_id') or default_tsg_id

    raw_responses = []

    for job_id in job_ids:

        raw_response = client.get_config_jobs_by_id(tsg_id, job_id).get('data')[0]
        raw_responses.append(raw_response)

    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}ConfigJob',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Config Jobs', outputs, headers=[
                                        'id', 'type_str', 'description', 'summary'], removeNull=True),
        raw_response=raw_response
    )


def list_config_jobs_command(client: Client, args: Dict[str, Any], default_tsg_id: str) -> CommandResults:
    """Command to list config jobs from Prisma Access
    Args:
        client: Client object with request
        args: demisto.args()
        default_tsg_id: Default Prisma SASE TSG configured for integration
    Returns:
        Outputs.
    """
    tsg_id = args.get('tsg_id') or default_tsg_id

    query_params = {}

    if limit := arg_to_number(args.get('limit', 200)):
        query_params["limit"] = limit

    if offset := arg_to_number(args.get('offset', 0)):
        query_params["offset"] = offset

    raw_response = client.list_config_jobs(tsg_id, query_params)  # type: ignore

    outputs = raw_response.get('data')

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}ConfigJob',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Config Job', outputs, headers=['id', 'type_str', 'description', 'summary']),
        raw_response=raw_response
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API url
    params = demisto.params()
    base_url = params.get('url').strip('/')
    verify_certificate = not argToBoolean(params.get('insecure', False))
    proxy = argToBoolean(params.get('proxy', False))
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    oauth_url = params.get('oauth_url')
    default_tsg_id = params.get('tsg_id')

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    commands = {
        'test-module': test_module,
        'prisma-access-create-security-rule': create_security_rule_command,
        'prisma-access-list-security-rules': list_security_rules_command,
        'prisma-access-push-candidate-config': push_candidate_config_command,
        'prisma-access-get-config-jobs-by-id': get_config_jobs_by_id_command,
        'prisma-access-list-config-jobs': list_config_jobs_command,
        'prisma-access-edit-security-rule': edit_security_rule_command,
        'prisma-access-get-security-rule-by-name': get_security_rule_by_name_command,
        'prisma-sase-query-agg-monitor-api': query_agg_monitor_api_command,
        'prisma-access-delete-security-rule': delete_security_rule_command,
        'prisma-access-create-address-object': create_address_object_command,
        'prisma-access-edit-address-object': edit_address_object_command,
        'prisma-access-delete-address-object': delete_address_object_command,
        'prisma-access-list-address-objects': list_address_objects_command
    }

    client = Client(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        oauth_url=oauth_url,
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        proxy=proxy,
        ok_codes=(200, 201, 204))

    try:
        if command in commands:
            return_results(commands[command](client, demisto.args(), default_tsg_id))  # type: ignore
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
