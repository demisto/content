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
DEFAULT_POLLING_INTERVAL = 30
DEFAULT_POLLING_TIMEOUT = 600
DEFAULT_POSITION = 'pre'
DEFAULT_FOLDER = 'Shared'
FREQUENCY_HOUR_REGEX = '[01][0-9]|2[0-3]'

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
       tsg_id: The default target Prisma SASE tenant ID
    """

    def __init__(self, base_url: str, client_id: str,
                 client_secret: str, tsg_id: str | None, verify: bool, proxy: bool, headers: dict, **kwargs):

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers, **kwargs)

        self.client_id = client_id
        self.client_secret = client_secret
        self.tsg_id = tsg_id

    def http_request(self,
                     method: str,
                     url_suffix: str = '',
                     params: dict = None,
                     json_data: dict = None,
                     tsg_id: str | None = None) -> dict:  # pragma: no cover

        headers = self.access_token_to_headers(tsg_id)
        return self._http_request(method=method,
                                  url_suffix=url_suffix,
                                  params=params,
                                  json_data=json_data,
                                  headers=headers)

    @staticmethod
    def build_security_rule(args: dict) -> dict:
        """Build a dictionary of security rule parameters to be used to create or update a rule
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
                    elif key == 'source_user':
                        val = argToList(field_value, ';')
                        rule[key] = val
                    elif isinstance(SECURITYRULE_FIELDS.get(key), str):
                        rule[key] = field_value  # type: ignore
                    elif isinstance(SECURITYRULE_FIELDS.get(key), list):
                        val = argToList(field_value)
                        rule[key] = val  # type: ignore

        return rule

    def create_security_rule(self, rule: dict, query_params: dict, tsg_id: str | None) -> dict:  # pragma: no cover
        """Creates new security rule
        Args:
            rule: Security rule dictionary
            query_params: folder and position params
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}security-rules'

        return self.http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=rule,
            tsg_id=tsg_id
        )

    def edit_security_rule(self, rule: dict, rule_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Update an existing security rule
        Args:
            rule: Security rule dictionary
            rule_id: identifier of rule to be updated
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}security-rules/{rule_id}'

        return self.http_request(
            method="PUT",
            url_suffix=uri,
            json_data=rule,
            tsg_id=tsg_id
        )

    def delete_security_rule(self, rule_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Delete en existing security rule
        Args:
            rule_id: Identifier of the rule to be deleted
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}security-rules/{rule_id}'

        return self.http_request(
            method="DELETE",
            url_suffix=uri,
            tsg_id=tsg_id
        )

    def create_address_object(self, address: dict, query_params: dict, tsg_id: str | None) -> dict:  # pragma: no cover
        """Create new address object
        Args:
            address: address object dictionary
            query_params: folder param
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}addresses'

        return self.http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=address,
            tsg_id=tsg_id
        )

    def edit_address_object(self, address: dict, address_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Update an existing address object
        Args:
            address: Address object dictionary
            address_id: Identifier of existing address to be updated
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}addresses/{address_id}'

        return self.http_request(
            method="PUT",
            url_suffix=uri,
            json_data=address,
            tsg_id=tsg_id
        )

    def delete_address_object(self, address_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Delete an existing address object
        Args:
            address_id: Identifier of existing address to be deleted
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}addresses/{address_id}'

        return self.http_request(
            method="DELETE",
            url_suffix=uri,
            tsg_id=tsg_id
        )

    def list_address_objects(self, query_params: dict, tsg_id: str | None) -> dict:  # pragma: no cover
        """List of address objects
        Args:
            query_params: folder param
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}addresses'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            tsg_id=tsg_id
        )

    def list_security_rules(self, query_params: dict, tsg_id: str | None) -> dict:  # pragma: no cover
        """List of security rules
        Args:
            query_params: folder param
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}security-rules'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            tsg_id=tsg_id
        )

    def push_candidate_config(self, folders: list, tsg_id: str | None, description: str | None = None) \
            -> dict:  # pragma: no cover
        """Push candidate configuration
        Args:
            folders: Target Prisma SASE Folders for the configuration commit
            description: Description for the job
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}config-versions/candidate:push'
        body: Dict[str, Any] = {'folders': folders}
        if description:
            body['description'] = description

        return self.http_request(
            method="POST",
            url_suffix=uri,
            json_data=body,
            tsg_id=tsg_id
        )

    def get_config_job_by_id(self, job_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Get a specific config job
        Args:
            job_id: ID of the config job
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}jobs/{job_id}'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            tsg_id=tsg_id
        )

    def list_config_jobs(self, tsg_id: str | None, query_params: dict | None = None) -> dict:  # pragma: no cover
        """List config jobs
        Args:
             query_params: limit and offset param
             tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}jobs'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            tsg_id=tsg_id,
            params=query_params
        )

    def get_address_by_id(self, query_params: dict, address_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Get an existing address object
        Args:
            query_params: folder param
            address_id: Identifier of existing address
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}addresses/{address_id}'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            tsg_id=tsg_id
        )

    def get_security_rule_by_id(self, query_params: dict, rule_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Get a specific security rule
        Args:
            query_params: folder and position params
            rule_id: Identifier of existing security rule
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}security-rules/{rule_id}'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            tsg_id=tsg_id
        )

    def get_tag_by_id(self, query_params: dict, tag_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Get a specific tag
        Args:
            query_params: folder param
            tag_id: Identifier of existing tag
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}tags/{tag_id}'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            tsg_id=tsg_id
        )

    def list_tags(self, query_params: dict, tsg_id: str | None) -> dict:  # pragma: no cover
        """List all tags
        Args:
            query_params: folder param
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}tags'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            tsg_id=tsg_id
        )

    def update_tag(self, tag_id: str, tag: dict, tsg_id: str | None) -> dict:  # pragma: no cover
        """Update an existing Tag
        Args:
            tag: Tag dictionary
            tag_id: Identifier of existing tag to be updated
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}tags/{tag_id}'

        return self.http_request(
            method="PUT",
            url_suffix=uri,
            json_data=tag,
            tsg_id=tsg_id
        )

    def delete_tag(self, tag_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Delete a tag
        Args:
            tag_id: Identifier of the existing tag to be deleted
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}tags/{tag_id}'

        return self.http_request(
            method="DELETE",
            url_suffix=uri,
            tsg_id=tsg_id
        )

    def create_tag(self, query_params: dict, tag: dict, tsg_id: str | None) -> dict:  # pragma: no cover
        """Create new tagr
        Args:
            tag: tag dictionary
            query_params: folder param
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}tags'

        return self.http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=tag,
            tsg_id=tsg_id
        )

    def get_address_group_by_id(self, query_params: dict, group_id: str, tsg_id: str | None) \
            -> dict:  # pragma: no cover
        """Get a specific address group
        Args:
            query_params: folder param
            group_id: Identifier of existing address group
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}address-groups/{group_id}'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            tsg_id=tsg_id
        )

    def list_address_group(self, query_params: dict, tsg_id: str | None) -> dict:  # pragma: no cover
        """List all address groups
        Args:
            query_params: folder param
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}address-groups'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            tsg_id=tsg_id
        )

    def update_address_group(self, address_group: dict, group_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Update an existing address group
        Args:
            address_group: Address object dictionary
            group_id: Identifier of existing address group to be updated
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}address-groups/{group_id}'

        return self.http_request(
            method="PUT",
            url_suffix=uri,
            json_data=address_group,
            tsg_id=tsg_id
        )

    def create_address_group(self, query_params: dict, address_group: dict, tsg_id: str | None) \
            -> dict:  # pragma: no cover
        """Create new address group
        Args:
            address_group: address group dictionary
            query_params: folder param
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}address-groups'

        return self.http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=address_group,
            tsg_id=tsg_id
        )

    def delete_address_group(self, group_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Delete an existing address group
        Args:
            group_id: Identifier of the existing address group to be deleted
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}address-groups/{group_id}'

        return self.http_request(
            method="DELETE",
            url_suffix=uri,
            tsg_id=tsg_id
        )

    def get_custom_url_category_by_id(self, query_params: dict, url_category_id: str, tsg_id: str | None) \
            -> dict:  # pragma: no cover
        """Get a specific custom URL category
        Args:
            query_params: folder param
            url_category_id: Identifier of existing url category
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}url-categories/{url_category_id}'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            tsg_id=tsg_id
        )

    def list_custom_url_category(self, query_params: dict, tsg_id: str | None) -> dict:  # pragma: no cover
        """List all custom url category
        Args:
            query_params: folder param
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}url-categories'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            tsg_id=tsg_id
        )

    def update_custom_url_category(self, custom_url_category: dict, url_category_id: str, tsg_id: str | None) \
            -> dict:  # pragma: no cover
        """Update an existing custom url category
        Args:
            custom_url_category: custom url category dictionary
            url_category_id: Identifier of existing address group to be updated
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}url-categories/{url_category_id}'

        return self.http_request(
            method="PUT",
            url_suffix=uri,
            json_data=custom_url_category,
            tsg_id=tsg_id
        )

    def create_custom_url_category(self, query_params: dict, custom_url_category: dict, tsg_id: str | None) \
            -> dict:  # pragma: no cover
        """Create new custom url category
        Args:
            custom_url_category: custom url category dictionary
            query_params: Prisma SASE Folder
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}url-categories'

        return self.http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=custom_url_category,
            tsg_id=tsg_id
        )

    def delete_custom_url_category(self, url_category_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Delete an existing custom url category
        Args:
            url_category_id: Identifier of the existing custom url category to be deleted
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}url-categories/{url_category_id}'

        return self.http_request(
            method="DELETE",
            url_suffix=uri,
            tsg_id=tsg_id
        )

    def get_external_dynamic_list_by_id(self, query_params: dict, external_dynamic_list_id: str, tsg_id: str | None) \
            -> dict:  # pragma: no cover
        """Get a specific external dynamic list
        Args:
            query_params: folder param
            external_dynamic_list_id: Identifier of existing external dynamic list
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}external-dynamic-lists/{external_dynamic_list_id}'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            tsg_id=tsg_id
        )

    def list_external_dynamic_list(self, query_params: dict, tsg_id: str | None) -> dict:  # pragma: no cover
        """List all external dynamic list
        Args:
            query_params: folder param
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}external-dynamic-lists'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            tsg_id=tsg_id
        )

    def update_external_dynamic_list(self, external_dynamic_list: dict, dynamic_list_id: str, tsg_id: str | None) \
            -> dict:  # pragma: no cover
        """Update an existing external dynamic list
        Args:
            external_dynamic_list: external dynamic list dictionary
            dynamic_list_id: Identifier of existing external dynamic list to be updated
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}external-dynamic-lists/{dynamic_list_id}'

        return self.http_request(
            method="PUT",
            url_suffix=uri,
            json_data=external_dynamic_list,
            tsg_id=tsg_id
        )

    def create_external_dynamic_list(self, query_params: dict, external_dynamic_list: dict, tsg_id: str | None) \
            -> dict:  # pragma: no cover
        """Create new external dynamic list
        Args:
            external_dynamic_list: external dynamic list dictionary
            query_params: folder param
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}external-dynamic-lists'

        return self.http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=external_dynamic_list,
            tsg_id=tsg_id
        )

    def delete_external_dynamic_list(self, dynamic_list_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Delete external dynamic list
        Args:
            dynamic_list_id: Identifier of the existing external dynamic list to be deleted
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}external-dynamic-lists/{dynamic_list_id}'

        return self.http_request(
            method="DELETE",
            url_suffix=uri,
            tsg_id=tsg_id
        )

    def list_url_access_profile(self, query_params: dict, tsg_id: str | None) -> dict:  # pragma: no cover
        """Get all url access profiles
        Args:
            query_params: folder param
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Outputs.
        """
        uri = f'{CONFIG_URI_PREFIX}url-access-profiles'

        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            tsg_id=tsg_id
        )

    def get_access_token(self, tsg_id: str | None) -> str:  # pragma: no cover
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
        tsg_access_token = f'{tsg_id}.access_token'
        tsg_expiry_time = f'{tsg_id}.expiry_time'
        previous_token = integration_context.get(tsg_access_token)
        previous_token_expiry_time = integration_context.get(tsg_expiry_time)

        if previous_token and previous_token_expiry_time > date_to_timestamp(datetime.now()):
            return previous_token
        else:
            tsg = f'tsg_id:{tsg_id}'
            data = {
                'grant_type': 'client_credentials',
                'scope': tsg
            }
            try:
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                }

                res = self._http_request(method='POST',
                                         full_url='https://auth.apps.paloaltonetworks.com/am/oauth2/access_token',
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

    def access_token_to_headers(self, tsg_id: str | None = None) -> dict:
        """Updates the headers with the access token
        Args:
            tsg_id: Target Prisma SASE tenant ID
        Returns:
            Headers
        """
        tsg_id = tsg_id if tsg_id else self.tsg_id
        access_token = self.get_access_token(tsg_id)

        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"
        return headers

    def quarantine_host(self, host_id: str, tsg_id: str | None) -> dict:  # pragma: no cover
        """Quarantine a given host
        Args:
            host_id: Host ID that needs to be added to quarantine List
            tsg_id: Target Prisma SASE tenant ID
        """
        uri = f'{CONFIG_URI_PREFIX}quarantined-devices'

        return self.http_request(
            method="POST",
            url_suffix=uri,
            json_data={'host_id': host_id},
            tsg_id=tsg_id
        )

    def get_cie_user(self, json_data: Dict[str, Any]) -> dict:  # pragma: no cover
        """
        Get CIE user
        Args:
            json_data: The JSON data to send in the request body.
        Returns:
            The response from the API.
        """
        url_suffix = 'cie/directory-sync/v1/cache-users'

        return self.http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=json_data,
        )


"""HELPER FUNCTIONS"""


def address_to_xsoar_format(outputs):
    """Modify an address object or list of address objects to XSOAR format
    Args:
        outputs: address objects
    """
    if isinstance(outputs, dict):
        outputs = [outputs]
    for output in outputs:
        for address_type in ADDRESS_TYPES:
            if address_type in output:
                output['type'] = address_type
                output['address_value'] = output[address_type]
                output.pop(address_type)


def address_group_to_xsoar_format(outputs):
    """Modify an address group or list of address groups to XSOAR format
    Args:
        outputs: address groups
    """
    if isinstance(outputs, dict):
        outputs = [outputs]
    for output in outputs:
        if 'static' in output:
            output['addresses'] = output['static']
            output.pop('static')
        elif 'dynamic' in output:
            output['dynamic_filter'] = output['dynamic'].get('filter', '')
            output.pop('dynamic')


def external_dynamic_list_to_xsoar_format(outputs):
    """Modify an external dynamic list or list of external dynamic lists to XSOAR format
    Args:
        outputs: external dynamic list
    Returns:
        Modified external dynamic list
    """
    if isinstance(outputs, dict):
        outputs = [outputs]
    for output in outputs:
        # For pre-defined list, also predefined values are returned, and their structure is different
        if output.get('snippet') == 'predefined':
            output['type'] = 'predefined'
            output['source'] = 'predefined'
            continue
        dynamic_list_type_object = output.get('type', {})
        try:
            # The object should contain exactly one key, and the key indicates the type of the dynamic list.
            dynamic_list_type = list(dynamic_list_type_object.keys())[0]
        except IndexError:
            raise DemistoException(f'Could not parse the type of the Dynamic list. '
                                   f'Type is missing. Dynamic list as returned by the API: {output}')
        output['description'] = dynamic_list_type_object.get(dynamic_list_type, {}).get('description')
        output['source'] = dynamic_list_type_object.get(dynamic_list_type, {}).get('url')
        output['frequency'] = next(iter(dynamic_list_type_object.get(dynamic_list_type, {}).get('recurring', {})), None)
        output['exception_list'] = dynamic_list_type_object.get(dynamic_list_type, {}).get('exception_list')
        output['type'] = dynamic_list_type


def get_address_group_type(original_address_group: dict) -> str:
    return 'static' if 'static' in original_address_group else 'dynamic'


def update_new_rule(new_rule: dict, original_rule: dict, overwrite: bool) -> dict:
    """Updates a security rule with the required data
    Args:
        new_rule: The new rule
        original_rule: The original rule
        overwrite: Rather to overwrite or append the updated values
    Returns:

    """
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
                original_rule.setdefault(key, []).extend(argToList(new_rule.get(key, [])))
        if isinstance(SECURITYRULE_FIELDS.get(key), str):
            original_rule[key] = new_rule.get(key)
    return original_rule


def get_url_according_to_type(args: dict) -> str:
    """Returns the url parameter according to the external dynamic list type.
    Args:
        args: Command args
    Returns:
        Url
    """
    dynamic_list_type = args.get('type')
    if dynamic_list_type in ('ip', 'domain', 'url'):
        url = args.get('source_url')
        if not url:
            raise DemistoException('Please provide the source_url argument when using IP, URL or Domain types')

    elif dynamic_list_type == 'predefined_url':
        url = args.get('predefined_url_list')
        if not url:
            raise DemistoException('Please provide the predefined_url_list argument when using predefined_url type')
    else:  # dynamic_list_type == 'predefined_ip':
        url = args.get('predefined_ip_list')
        if not url:
            raise DemistoException('Please provide the predefined_ip_list argument when using predefined_ip')
    return url


def validate_url_is_type_compatible(args: dict,
                                    type_changed: bool,
                                    original_dynamic_list_type: dict,
                                    original_dynamic_list_url: dict) -> str:
    """Validates that the update is valid and returns the correct URL
    Args:
        args: Command arguments
        original_dynamic_list_url: The original dynamic list url
        original_dynamic_list_type: The original dynamic list type
        type_changed: Rather the type has changed
    Returns:
        Url
    """
    dynamic_list_type = args.get('type') or original_dynamic_list_type
    if dynamic_list_type in ('ip', 'domain', 'url'):
        url = args.get('source_url', '')
        if not url and type_changed:
            raise DemistoException('Please provide the source_url argument when using IP, URL or Domain types')

    elif dynamic_list_type == 'predefined_url':
        url = args.get('predefined_url_list', '')
        if not url and type_changed:
            raise DemistoException('Please provide the predefined_url_list argument when using predefined_url type')
    else:  # dynamic_list_type == 'predefined_ip':
        url = args.get('predefined_ip_list', '')
        if not url and type_changed:
            raise DemistoException('Please provide the predefined_ip_list argument when using predefined_ip')
    url = url if url else original_dynamic_list_url
    return url


def build_recurring_according_to_params(args: dict) -> dict:
    """Returns a frequency object for the API according to the command arguments
    Args:
        args: Command arguments
    Returns:
        Frequency object
    """
    frequency = args.get('frequency') or 'five_minute'
    frequency_object: dict = {frequency: {}}
    if frequency in ('daily', 'weekly', 'monthly'):
        frequency_hour = args.get('frequency_hour')
        if not frequency_hour:
            raise DemistoException('Please provide the frequency_hour argument when using daily, '
                                   'weekly or monthly frequency')
        if not re.match(FREQUENCY_HOUR_REGEX, frequency_hour):
            raise DemistoException('frequency_hour argument should be 00,01,02...-23 only')
        frequency_object[frequency]['at'] = frequency_hour
        if frequency == 'weekly':
            day_of_week = args.get('day_of_week')
            if not day_of_week:
                raise DemistoException('Please provide the day_of_week argument when using weekly frequency')
            frequency_object[frequency]['day_of_week'] = day_of_week

        elif frequency == 'monthly':
            day_of_month = args.get('day_of_month')
            if not day_of_month:
                raise DemistoException('Please provide the day_of_month argument when using monthly frequency')
            day_of_month = arg_to_number(day_of_month) or 0
            if day_of_month < 1 or day_of_month > 31:
                raise DemistoException('day_of_month argument must be between 1 and 31')
            frequency_object[frequency]['day_of_month'] = str(day_of_month)

    return frequency_object


def validate_recurring_is_type_compatible(args: dict, original_frequency_obj: dict) -> dict:
    """Validates that the update is valid and returns the correct frequency object
    Args:
        args: Command arguments
        original_frequency_obj: The original frequency object
    Returns:
        Frequency object for the API
    """
    frequency = args.get('frequency')

    if len(list(original_frequency_obj.keys())) == 0 and not frequency:
        raise DemistoException('Could not find frequency for dynamic list type. Please check your configuration')
    original_frequency = list(original_frequency_obj.keys())[0]
    frequency = frequency if frequency else original_frequency
    frequency_object: dict = {frequency: {}}
    if frequency in ('daily', 'weekly', 'monthly'):
        frequency_hour = args.get('frequency_hour') or original_frequency_obj[original_frequency].get('frequency_hour')
        if not frequency_hour:
            raise DemistoException('Please provide the frequency_hour argument when using daily, '
                                   'weekly or monthly frequency')
        if not re.match(FREQUENCY_HOUR_REGEX, frequency_hour):
            raise DemistoException('frequency_hour argument should be 00,01,02...-23 only')
        frequency_object[frequency]['at'] = frequency_hour or original_frequency_obj[original_frequency].get('at')
        if frequency == 'weekly':
            day_of_week = args.get('day_of_week') or original_frequency_obj[original_frequency].get('day_of_week')
            if not day_of_week:
                raise DemistoException('Please provide the day_of_week argument when using weekly frequency')
            frequency_object[frequency]['day_of_week'] = day_of_week

        elif frequency == 'monthly':
            day_of_month = args.get('day_of_month') or original_frequency_obj[original_frequency].get('day_of_month')
            if not day_of_month:
                raise DemistoException('Please provide the day_of_month argument when using monthly frequency')
            day_of_month = arg_to_number(day_of_month) or 0
            if day_of_month < 1 or day_of_month > 31:
                raise DemistoException('day_of_month argument must be between 1 and 31')
            frequency_object[frequency]['day_of_month'] = str(day_of_month)

    return frequency_object if frequency_object else original_frequency_obj


def get_pagination_params(args: dict) -> dict:
    """Returns the pagination parameters
    Args:
        args: Command arguments
    Returns:
        Pagination params
    """
    pagination_params = {}
    page = arg_to_number(args.get('page')) or 1
    page_size = arg_to_number(args.get('page_size'))
    if page and page_size:
        pagination_params['offset'] = (page - 1) * page_size
        pagination_params['limit'] = page_size
    elif limit := arg_to_number(args.get('limit', DEFAULT_LIMIT)):
        pagination_params['limit'] = limit
    return pagination_params


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
    """
    Command to create new security rule
    """

    rule = client.build_security_rule(args)
    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER,
        'position': encode_string_results(args.get('position')) or DEFAULT_POSITION
    }
    tsg_id = args.get('tsg_id')
    demisto.debug(f'sending security rule to the API. Rule: {rule}')
    raw_response = client.create_security_rule(rule=rule, query_params=query_params, tsg_id=tsg_id)  # type: ignore
    outputs = raw_response
    outputs["position"] = query_params["position"]

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}SecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rule Created', outputs, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def create_address_object_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to create new address object
    Args:
        client: Client object with request
        args: demisto.args()
    Returns:
        Outputs.
    """

    address_object = {
        args.get('type'): args.get('address_value'),
        'name': args.get('name')}

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER
    }

    if args.get('description'):
        address_object['description'] = args.get('description')

    if args.get('tag'):
        address_object['tag'] = args.get('tag')

    demisto.debug(f'sending address_object to the API. address_object: {address_object}')
    raw_response = client.create_address_object(address=address_object,
                                                query_params=query_params,
                                                tsg_id=args.get('tsg_id'))  # type: ignore

    outputs = raw_response.copy()
    address_to_xsoar_format(outputs)

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}Address',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Address Object Created', outputs, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def edit_address_object_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to update address object
    """

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER
    }
    object_id = args.get('object_id', '')
    tsg_id = args.get('tsg_id')
    # first get the original address, so user won't need to send all data
    original_address = client.get_address_by_id(query_params=query_params, address_id=object_id, tsg_id=tsg_id)
    original_address_type = None
    if not args.get('type'):
        for address_type in ADDRESS_TYPES:
            if address_type in original_address:
                original_address_type = address_type
    else:
        original_address_type = args.get('type')

    original_address[original_address_type] = args.get('address_value')

    # in case the type has changed, we want to remove other types from the address object
    for address_type in ADDRESS_TYPES:
        if address_type in original_address and address_type != original_address_type:
            original_address.pop(address_type)

    if description := args.get('description'):
        original_address['description'] = description

    if tag := args.get('tag'):
        original_address['tag'] = tag

    demisto.debug(f'sending address_object to the API. address_object: {original_address}')

    raw_response = client.edit_address_object(address=original_address,
                                              address_id=object_id,
                                              tsg_id=tsg_id)  # type: ignore

    outputs = raw_response.copy()
    address_to_xsoar_format(outputs)

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}Address',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Address Object updated', outputs, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def delete_address_object_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to delete address object
    """
    tsg_id = args.get('tsg_id')
    address_id = args.get('object_id')
    demisto.debug(f'deleting address_object with id {address_id}')
    raw_response = client.delete_address_object(address_id=address_id, tsg_id=tsg_id)  # type: ignore

    return CommandResults(
        readable_output=f'Address object with id {raw_response.get("id", "")} '
                        f'and name {raw_response.get("name", "")} was deleted successfully',
        raw_response=raw_response
    )


def list_address_objects_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to get all address objects
    """

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER, 'name': args.get('name')
    }
    tsg_id = args.get('tsg_id')
    if object_id := args.get('object_id'):
        raw_response = client.get_address_by_id(query_params=query_params, address_id=object_id, tsg_id=tsg_id)
        outputs = raw_response.copy()
    else:
        query_params.update(get_pagination_params(args))

        raw_response = client.list_address_objects(query_params=query_params, tsg_id=tsg_id)  # type: ignore

        outputs = raw_response.copy()
        # A dict containing a list of results (data) is returned from the API.
        # When filtering by name the key 'data' does not exist in the response, therefore we return the entire response.
        outputs = outputs.get('data', outputs)

    address_to_xsoar_format(outputs)
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
    """
    Command to delete the specified security rule
    """

    rule_id = args.get('rule_id')
    tsg_id = args.get('tsg_id')

    demisto.debug(f'deleting security_rule with id {rule_id}')
    raw_response = client.delete_security_rule(rule_id=rule_id, tsg_id=tsg_id)  # type: ignore

    return CommandResults(
        readable_output=f'Security Rule object with id {raw_response.get("id", "")} '
                        f'and name {raw_response.get("name", "")} was deleted successfully',
        raw_response=raw_response
    )


def edit_security_rule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to update an existing security rule
    """
    rule = client.build_security_rule(args)
    rule_id = args.get('rule_id', '')
    tsg_id = args.get('tsg_id')
    overwrite = argToBoolean(args.get('overwrite'))
    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER,
        'position': encode_string_results(args.get('position')) or DEFAULT_POSITION
    }
    original_rule = client.get_security_rule_by_id(query_params=query_params, rule_id=rule_id, tsg_id=tsg_id)
    updated_rule = update_new_rule(rule, original_rule, overwrite=overwrite)
    demisto.debug(f'Sending security_rule to the API. Rule {updated_rule}')
    raw_response = client.edit_security_rule(rule=updated_rule, rule_id=rule_id, tsg_id=tsg_id)  # type: ignore
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

    """
    folders = argToList(args.get('folders'))  # type: ignore
    tsg_id = args.get('tsg_id')

    raw_response = client.push_candidate_config(folders, args.get('description', ''), tsg_id=tsg_id)  # type: ignore

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
    """
    Command to Get all security rules
    """

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER,
        'position': encode_string_results(args.get('position')) or DEFAULT_POSITION,
        'name': args.get('name')
    }
    tsg_id = args.get('tsg_id')

    if rule_id := args.get('rule_id'):
        raw_response = client.get_security_rule_by_id(query_params=query_params, rule_id=rule_id, tsg_id=tsg_id)
        outputs = raw_response
    else:
        query_params.update(get_pagination_params(args))

        raw_response = client.list_security_rules(query_params=query_params, tsg_id=tsg_id)  # type: ignore
        # A dict containing a list of results is returned by the API.
        # A single dict is returned when filtering the request by name.
        outputs = raw_response.get('data', raw_response)

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

    """

    query_params = {}
    tsg_id = args.get('tsg_id')
    if job_id := args.get('job_id'):
        raw_response = client.get_config_job_by_id(job_id=job_id, tsg_id=tsg_id)
    else:
        query_params.update(get_pagination_params(args))

        raw_response = client.list_config_jobs(tsg_id=tsg_id, query_params=query_params)  # type: ignore

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
    """
    Command to list all tags
    """

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER,
        'name': args.get('name'),
    }
    tsg_id = args.get('tsg_id')
    if tag_id := args.get('tag_id'):
        raw_response = client.get_tag_by_id(query_params=query_params, tag_id=tag_id, tsg_id=tsg_id)
        outputs = raw_response
    else:
        query_params.update(get_pagination_params(args))

        raw_response = client.list_tags(query_params=query_params, tsg_id=tsg_id)  # type: ignore
        # A dict containing a list of results is returned by the API.
        # A single dict is returned when filtering the request by name.
        outputs = raw_response.get('data', raw_response)

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
    """
    Command to create new tag
    """

    tag = {
        'name': args.get('name')
    }

    if color := args.get('color'):
        tag['color'] = color

    if comments := args.get('comments'):
        tag['comments'] = comments

    query_params = {
        'folder': args.get('folder') or DEFAULT_FOLDER
    }
    tsg_id = args.get('tsg_id')

    demisto.debug(f'Sending tag to the API. Tag: {tag}')

    raw_response = client.create_tag(query_params=query_params, tag=tag, tsg_id=tsg_id)  # type: ignore

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}Tag',
        outputs_key_field='id',
        outputs=raw_response,
        readable_output=tableToMarkdown('Address Object Created', raw_response, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def update_tag_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to update an existing tag
    """

    query_params = {
        'folder': encode_string_results(args.get('folder') or DEFAULT_FOLDER)
    }
    # first get the original tag, so user won't need to send all data
    tag_id = args.get('tag_id', '')
    tsg_id = args.get('tsg_id')
    original_tag = client.get_tag_by_id(query_params=query_params, tag_id=tag_id, tsg_id=tsg_id)

    if color := args.get('color'):
        original_tag['color'] = color

    if comments := args.get('comments'):
        original_tag['comments'] = comments

    demisto.debug(f'Sending tag to the API. Tag: {original_tag}')
    raw_response = client.update_tag(tag_id=tag_id, tag=original_tag, tsg_id=tsg_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}Tag',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Tag Edited', outputs, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def delete_tag_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to delete the specified tagG
    """

    tag_id = args.get('tag_id')
    tsg_id = args.get('tsg_id')

    demisto.debug(f'Deleting tag twith id {tag_id}')
    raw_response = client.delete_tag(tag_id=tag_id, tsg_id=tsg_id)  # type: ignore

    return CommandResults(
        readable_output=f'Tag with id {raw_response.get("id", "")} '
                        f'and name {raw_response.get("name", "")} was deleted successfully',
        raw_response=raw_response
    )


def list_address_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to get address groups
    """

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER,
        'name': args.get('name'),
    }
    tsg_id = args.get('tsg_id')
    if group_id := args.get('group_id'):
        raw_response = client.get_address_group_by_id(query_params=query_params, group_id=group_id, tsg_id=tsg_id)
        outputs = raw_response.copy()
    else:
        query_params.update(get_pagination_params(args))

        raw_response = client.list_address_group(query_params=query_params, tsg_id=tsg_id)  # type: ignore
        outputs = raw_response.copy()
        # A dict containing a list of results is returned by the API.
        # A single dict is returned when filtering the request by name.
        outputs = outputs.get('data', outputs)

    address_group_to_xsoar_format(outputs)

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
    """
    Command to create new address group
    """

    address_group = {
        'name': args.get('name')}

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER
    }
    tsg_id = args.get('tsg_id')

    if description := args.get('description'):
        address_group['description'] = description

    if group_type := args.get('type'):
        if group_type == 'static':
            if static_addresses := argToList(args.get('static_addresses')):
                address_group['static'] = static_addresses
        else:  # type == 'dynamic'
            if dynamic_filter := args.get('dynamic_filter'):
                address_group['dynamic'] = {'filter': dynamic_filter}
    demisto.debug(f'Sending address_group to the API. address_group: {address_group}')
    raw_response = client.create_address_group(query_params=query_params,
                                               address_group=address_group,
                                               tsg_id=tsg_id)  # type: ignore

    outputs = raw_response.copy()
    address_group_to_xsoar_format(outputs)

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}AddressGroup',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Address Group Created', outputs, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def update_address_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to update an existing address group
    """

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER
    }
    tsg_id = args.get('tsg_id')
    group_id = args.get('group_id', '')
    # first get the original address, so user won't need to send all data
    original_address_group = client.get_address_group_by_id(query_params=query_params, group_id=group_id, tsg_id=tsg_id)

    if description := args.get('description'):
        original_address_group['description'] = description
    overwrite = argToBoolean(args.get('overwrite'))
    group_type = args.get('type', '')
    if group_type and group_type != get_address_group_type(original_address_group):
        # we can not concatenate static value to dynamic
        demisto.info(f"setting overwrite parameter to True as the type of the address group has changed."
                     f"overwrite original value: {overwrite}")
        overwrite = True

    if not group_type:
        group_type = get_address_group_type(original_address_group)

    static_addresses = argToList(args.get('static_addresses'))
    dynamic_filter = args.get('dynamic_filter')
    if group_type == 'static' and (dynamic_filter and not static_addresses):
        raise DemistoException("Please provide the static_addresses argument with type static")
    if group_type == 'dynamic' and (not dynamic_filter and static_addresses):
        raise DemistoException("Please provide the dynamic_filter argument with type dynamic")
    if group_type == 'static':
        if overwrite:
            original_address_group['static'] = static_addresses
        else:
            original_address_group.setdefault('static', []).extend(static_addresses)
        original_address_group.pop('dynamic') if 'dynamic' in original_address_group else None

    else:  # type == 'dynamic'
        if not overwrite:
            dynamic_filter = original_address_group.get('dynamic', {}).get('filter', '') + ' ' + dynamic_filter

        original_address_group['dynamic'] = {'filter': dynamic_filter}

        original_address_group.pop('static') if 'static' in original_address_group else None

    demisto.debug(f'Sending address_group to the API. address_group: {original_address_group}')
    raw_response = client.update_address_group(address_group=original_address_group,
                                               group_id=group_id,
                                               tsg_id=tsg_id)  # type: ignore

    outputs = raw_response.copy()
    address_group_to_xsoar_format(outputs)

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}AddressGroup',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Address Group updated', outputs, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def delete_address_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to delete address group
    """
    group_id = args.get('group_id')
    tsg_id = args.get('tsg_id')

    demisto.debug(f'Deleting address group with id {group_id}')
    raw_response = client.delete_address_group(group_id=group_id, tsg_id=tsg_id)  # type: ignore

    return CommandResults(
        readable_output=f'Address group with id {raw_response.get("id", "")} '
                        f'and name {raw_response.get("name", "")} was deleted successfully',
        raw_response=raw_response
    )


def list_custom_url_category_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to get all custom url categories
    """

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER,
        'name': args.get('name'),
    }
    tsg_id = args.get('tsg_id')
    if url_category_id := args.get('id'):
        raw_response = client.get_custom_url_category_by_id(query_params=query_params,
                                                            url_category_id=url_category_id,
                                                            tsg_id=tsg_id)
        outputs = [raw_response]
    else:
        query_params.update(get_pagination_params(args))

        raw_response = client.list_custom_url_category(query_params=query_params, tsg_id=tsg_id)  # type: ignore
        # A dict containing a list of results is returned by the API.
        # A single dict is returned when filtering the request by name.
        outputs = raw_response.get('data', raw_response)

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}CustomURLCategory',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Custom Url Categories', outputs,
                                        headers=['id', 'name', 'folder', 'type', 'list'],
                                        headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def create_custom_url_category_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to create new custom url category
    """

    custom_url_category = {
        'name': args.get('name'),
        'type': args.get('type')
    }

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER
    }
    tsg_id = args.get('tsg_id')

    if description := args.get('description'):
        custom_url_category['description'] = description

    if value := argToList(args.get('value')):
        custom_url_category['list'] = value

    demisto.debug(f'Sending custom_url_category to the API. custom_url_category: {custom_url_category}')
    raw_response = client.create_custom_url_category(query_params=query_params,
                                                     custom_url_category=custom_url_category,
                                                     tsg_id=tsg_id)  # type: ignore

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}CustomURLCategory',
        outputs_key_field='id',
        outputs=raw_response,
        readable_output=tableToMarkdown('Custom URrl Category Created', raw_response,
                                        headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def update_custom_url_category_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to update an existing custom url category
    """

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER
    }
    tsg_id = args.get('tsg_id')
    url_category_id = args.get('id', '')
    # first get the original, so user won't need to send all data
    original_custom_url_category = client.get_custom_url_category_by_id(query_params=query_params,
                                                                        url_category_id=url_category_id,
                                                                        tsg_id=tsg_id)

    if description := args.get('description'):
        original_custom_url_category['description'] = description
    overwrite = argToBoolean(args.get('overwrite'))
    if category_type := args.get('type'):
        if category_type != original_custom_url_category['type']:
            demisto.info(f"setting overwrite parameter to True as the type of the URL category has changed."
                         f"overwrite original value: {overwrite}")
            overwrite = True
        original_custom_url_category['type'] = category_type

    if value := argToList(args.get('value')):
        if overwrite:
            original_custom_url_category['list'] = value
        else:
            original_custom_url_category.setdefault('list', []).extend(value)

    demisto.debug(f'Sending custom_url_category to the API. custom_url_category: {original_custom_url_category}')
    raw_response = client.update_custom_url_category(custom_url_category=original_custom_url_category,
                                                     url_category_id=url_category_id,
                                                     tsg_id=tsg_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}CustomURLCategory',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Custom Url Category updated', outputs, headerTransform=string_to_table_header),
        raw_response=raw_response
    )


def delete_custom_url_category_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to delete custom url category
    """
    url_category_id = args.get('id')
    tsg_id = args.get('tsg_id')

    demisto.debug(f'Deleting custom_url_category with id {url_category_id}')
    raw_response = client.delete_custom_url_category(url_category_id=url_category_id, tsg_id=tsg_id)  # type: ignore

    return CommandResults(
        readable_output=f'Custom Url Category with id {raw_response.get("id", "")} '
                        f'and name {raw_response.get("name", "")} was deleted successfully',
        raw_response=raw_response
    )


def list_external_dynamic_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to get all external dynamic lists
    """

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER,
        'name': args.get('name')
    }
    tsg_id = args.get('tsg_id')
    if external_dynamic_list_id := args.get('id'):
        raw_response = client.get_external_dynamic_list_by_id(query_params=query_params,
                                                              external_dynamic_list_id=external_dynamic_list_id,
                                                              tsg_id=tsg_id)
        outputs = raw_response.copy()
    else:
        query_params.update(get_pagination_params(args))

        raw_response = client.list_external_dynamic_list(query_params=query_params, tsg_id=tsg_id)  # type: ignore

        outputs = raw_response.copy()
        # A dict containing a list of results is returned by the API.
        # A single dict is returned when filtering the request by name.
        outputs = outputs.get('data', outputs)

    external_dynamic_list_to_xsoar_format(outputs)

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}ExternalDynamicList',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('External Dynamic Lists',
                                        outputs,
                                        headers=['id', 'name', 'type', 'folder', 'description', 'source', 'frequency'],
                                        headerTransform=string_to_table_header,
                                        is_auto_json_transform=True),
        raw_response=raw_response
    )


def create_external_dynamic_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to create new external dynamic list
    """

    dynamic_list_type = args.get('type', '')
    external_dynamic_list: dict = {
        'name': args.get('name'),
        'type': {dynamic_list_type: {}}
    }

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER
    }
    tsg_id = args.get('tsg_id')

    url = get_url_according_to_type(args)
    external_dynamic_list['type'][dynamic_list_type]['url'] = url

    if exception_list := argToList(args.get('exception_list')):
        external_dynamic_list['type'][dynamic_list_type]['exception_list'] = exception_list

    if description := args.get('description'):
        external_dynamic_list['type'][dynamic_list_type]['description'] = description

    if dynamic_list_type in ('ip', 'domain', 'url'):
        external_dynamic_list['type'][dynamic_list_type]['recurring'] = build_recurring_according_to_params(args)

    demisto.debug(f'Sending external_dynamic_list to the API. external_dynamic_list: {external_dynamic_list}')
    raw_response = client.create_external_dynamic_list(query_params=query_params,
                                                       external_dynamic_list=external_dynamic_list,
                                                       tsg_id=tsg_id)  # type: ignore

    outputs = raw_response.copy()
    external_dynamic_list_to_xsoar_format(outputs)

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}ExternalDynamicList',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('External Dynamic List Created',
                                        outputs,
                                        headers=['id', 'name', 'type', 'folder', 'description', 'source', 'frequency'],
                                        headerTransform=string_to_table_header,
                                        is_auto_json_transform=True),
        raw_response=raw_response
    )


def update_external_dynamic_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to update an existing external dynamic list
    """

    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER
    }
    tsg_id = args.get('tsg_id')
    dynamic_list_id = args.get('id', '')
    # first get the original, so user won't need to send all data
    original_dynamic_list = client.get_external_dynamic_list_by_id(query_params=query_params,
                                                                   external_dynamic_list_id=dynamic_list_id,
                                                                   tsg_id=tsg_id)

    overwrite = argToBoolean(args.get('overwrite'))
    original_dynamic_list_type_object = original_dynamic_list['type']
    try:
        original_dynamic_list_type = list(original_dynamic_list_type_object.keys())[0]
    except IndexError:
        raise DemistoException(f'Could not parse the type of the Dynamic list. '
                               f'Type is missing. Dynamic list as returned by the API: {original_dynamic_list}')
    original_dynamic_list_url = original_dynamic_list_type_object[original_dynamic_list_type]['url']
    original_frequency_object = original_dynamic_list_type_object[original_dynamic_list_type].get('recurring',
                                                                                                  {'recurring': {}})
    type_changed = False
    if (dynamic_list_type := args.get('type')) and original_dynamic_list_type != dynamic_list_type:
        # changing the key that indicates the type
        original_dynamic_list['type'][dynamic_list_type] = original_dynamic_list_type_object[
            original_dynamic_list_type]
        demisto.info(f"setting overwrite parameter to True as the type of the dynamic list has changed."
                     f"overwrite original value: {overwrite}")
        type_changed = True
        overwrite = True

    dynamic_list_type = dynamic_list_type if dynamic_list_type else original_dynamic_list_type
    if exception_list := argToList(args.get('exception_list')):
        if overwrite:
            original_dynamic_list['type'][dynamic_list_type]['exception_list'] = exception_list
        else:
            original_dynamic_list['type'][dynamic_list_type].setdefault('exception_list', []).extend(exception_list)

    if description := args.get('description'):
        original_dynamic_list['type'][dynamic_list_type]['description'] = description

    url = validate_url_is_type_compatible(args, type_changed, original_dynamic_list_type, original_dynamic_list_url)
    original_dynamic_list['type'][dynamic_list_type]['url'] = url

    if dynamic_list_type in ('ip', 'domain', 'url'):
        original_dynamic_list['type'][dynamic_list_type]['recurring'] = \
            validate_recurring_is_type_compatible(args, original_frequency_object)

    if type_changed:
        original_dynamic_list['type'].pop(original_dynamic_list_type)
        if not original_dynamic_list['type'][dynamic_list_type].get('recurring'):
            original_dynamic_list['type'][dynamic_list_type].pop('recurring')

    demisto.debug(f'Sending external_dynamic_list to the API. external_dynamic_list: {original_dynamic_list}')
    raw_response = client.update_external_dynamic_list(external_dynamic_list=original_dynamic_list,
                                                       dynamic_list_id=dynamic_list_id,
                                                       tsg_id=tsg_id)  # type: ignore
    outputs = raw_response.copy()
    external_dynamic_list_to_xsoar_format(outputs)

    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}ExternalDynamicList',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('External Dynamic List updated',
                                        outputs,
                                        headers=['id', 'name', 'type', 'folder', 'description', 'source', 'frequency'],
                                        headerTransform=string_to_table_header,
                                        is_auto_json_transform=True),
        raw_response=raw_response
    )


def delete_external_dynamic_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Command to delete external dynamic list

    """
    dynamic_list_id = args.get('id')
    tsg_id = args.get('tsg_id')

    demisto.debug(f'Deleting external_dynamic_list with id {dynamic_list_id}')
    raw_response = client.delete_external_dynamic_list(dynamic_list_id=dynamic_list_id, tsg_id=tsg_id)  # type: ignore

    return CommandResults(
        readable_output=f'External Dynamic List with id {raw_response.get("id", "")} '
                        f'and name {raw_response.get("name", "")} was deleted successfully',
        raw_response=raw_response
    )


def list_url_category_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command get all built-in url categories
    """
    query_params = {
        'folder': encode_string_results(args.get('folder')) or DEFAULT_FOLDER
    }
    tsg_id = args.get('tsg_id')
    raw_response = client.list_url_access_profile(query_params=query_params, tsg_id=tsg_id)  # type: ignore
    profiles = raw_response.get('data', [])

    categories: dict = {'alert': [], 'allow': [], 'block': [], 'continue': [], 'override': []}
    for profile in profiles:
        # we only want predefined profiles
        if profile.get('folder', '') == 'predefined':
            for category in categories:
                categories[category].extend(profile.get(category, []))
                categories[category].extend(profile.get('credential_enforcement', {}).get(category, []))
                # remove duplicates
                categories[category] = list(set(categories[category]))

    return CommandResults(
        readable_output=tableToMarkdown('URL categories', categories),
        raw_response=raw_response
    )


def quarantine_host_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command quarantine a given host
    """
    host_id = args.get('host_id', '')
    tsg_id = args.get('tsg_id')

    raw_response = client.quarantine_host(host_id=host_id, tsg_id=tsg_id)

    outputs = raw_response

    return CommandResults(
        readable_output=tableToMarkdown('Host Quarantined', outputs),
        raw_response=raw_response
    )


def get_cie_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command get cie user
    Args:
        client: Client
        args: Dict[str, Any]
    Returns:
        CommandResults
    """

    def prepare_args(args: Dict[str, Any]) -> Dict[str, Any]:
        """
            Prepare args for get_cie_user_command.
        Args:
            args: Dict[str, Any] - args to prepare
        Returns:
            Dict[str, Any] - The JSON data for the API call
        """
        operator_mapping = {"Equal": "equal", "Starts With": "startsWith", "Ends With": "endsWith",
                            "Contain": "contain", "Text Search": "textSearch"}

        missing_args = {"attributes_to_return": args.get('attributes_to_return'), "operator": args.get('operator'),
                        "attributes_to_filter_by": args.get('attributes_to_filter_by')}
        errors = [name for name, value in missing_args.items() if not value]
        if errors:
            raise ValueError(f"The following arguments are empty: {', '.join(errors)}")

        # Ensure "Unique Identifier" is always in the list for the deduplication process
        attributes_to_return = list(set(argToList(args.get("attributes_to_return", ""))) | {"Unique Identifier"})
        args["attributes_to_return"] = attributes_to_return

        return {
            "domain": args.get("domain"),
            "attrs": attributes_to_return,
            "name":
                {
                    "attrNameOR": argToList(args.get("attributes_to_filter_by", "")),
                    "attrValue": args.get("value_for_filter"),
                    "match": operator_mapping.get(args.get('operator', 'Equal'))
            },
            "useNormalizedAttrs": "True"
        }

    def parse_cie_response(raw_response: Dict[str, Any]) -> Dict[str, Any]:
        """
            Parse the raw response from the API call.
        Args:
            raw_response: dict - The raw response from the API call
        Returns:
            Dict[str, Any] - The parsed response
        """
        default_error_msg = "The get_cie_user_command failed. Please verify the arguments and try again."
        result_response = raw_response.get("result", {})
        if error := result_response.get("error"):
            raise ValueError(
                f"Error: {error.get('error-message', default_error_msg)}")
        parsed_raw_response = result_response.get("data", {}).get("domains", [])
        if parsed_raw_response and (objects := parsed_raw_response[0].get("objects", [])):
            return {key: objects[0].get(key) for key in args.get('attributes_to_return', [])}
        return {}

    payload = prepare_args(args)

    raw_response = client.get_cie_user(payload)

    outputs = parse_cie_response(raw_response)

    if outputs:
        return CommandResults(
            outputs_prefix=f'{PA_OUTPUT_PREFIX}CIE.User',
            outputs_key_field='unique_identifier',
            outputs={key.lower().replace(" ", "_").replace("-", "_"): value for key, value in outputs.items()},
            readable_output=tableToMarkdown('CIE User', outputs),
            raw_response=raw_response
        )
    return CommandResults(
        readable_output='No user found with the given arguments. Please verify the arguments and try again.',
        raw_response=raw_response
    )


def run_push_jobs_polling_command(client: Client, args: dict):
    """
    This function is generically handling the polling flow. In the polling flow, there is always an initial call that
    starts the uploading to the API (referred here as the 'upload' function) and another call that retrieves the status
    of that upload (referred here as the 'results' function).
    The run_polling_command function runs the 'upload' function and returns a ScheduledCommand object that schedules
    the next 'results' function, until the polling is complete.
    """
    polling_interval = args.get('interval_in_seconds') or DEFAULT_POLLING_INTERVAL
    polling_timeout = arg_to_number(args.get('polling_timeout_in_seconds')) or DEFAULT_POLLING_TIMEOUT
    tsg_id = args.get('tsg_id')
    if (folders := argToList(args.get('folders'))) and folders[0] != "done":
        # first call, folder in args. We make the first push
        res = client.push_candidate_config(folders=folders, tsg_id=tsg_id)
        # remove folders, not needed for the rest
        args['folders'] = ["done"]
        # The result from the push returns a job id
        job_id = res.get('job_id', '')
        args['job_id'] = job_id
        # The push job creates sub processes once done. at this point, the parent job hasn't finished.
        args['parent_finished'] = False
        return CommandResults(
            scheduled_command=ScheduledCommand(command='prisma-sase-candidate-config-push',
                                               args=args,
                                               next_run_in_seconds=polling_interval,
                                               timeout_in_seconds=polling_timeout),
            readable_output=f'Waiting for all data to push for job id {job_id}')

    job_id = args.get('job_id', '')
    outputs: dict = {'job_id': job_id, 'result': 'OK'}
    if not argToBoolean(args.get('parent_finished')):
        res = client.get_config_job_by_id(job_id=job_id, tsg_id=tsg_id).get('data', [{}])[0]
        if res.get('result_str') == 'PEND':
            demisto.debug(f'waiting for parent processes to finish, parent job_id {job_id}')
            return CommandResults(
                scheduled_command=ScheduledCommand(command='prisma-sase-candidate-config-push',
                                                   args=args,
                                                   next_run_in_seconds=polling_interval,
                                                   timeout_in_seconds=polling_timeout))

        # From testing (as this is not documented) the status returns only as OK if the job succeeded
        job_result = res.get('result_str')
        if job_result != 'OK':
            outputs['result'] = job_result
            outputs['details'] = res.get('details', '')
            return CommandResults(entry_type=EntryType.ERROR,
                                  outputs=outputs,
                                  outputs_prefix=f'{PA_OUTPUT_PREFIX}CandidateConfig',
                                  readable_output=f'Something went wrong while trying to push job id {job_id}. '
                                                  f'Result: {job_result}')

        # Parent is the first push. After finishing, sub processes created for each folder.
        args['parent_finished'] = True
    res = client.list_config_jobs(tsg_id=tsg_id).get('data', {})
    for job in res:
        # looking for all sub processes with parent id as the job id
        if job.get('parent_id') == job_id:
            demisto.debug(f'looking for child processes with parent_id {job}')
            if job.get('result_str') == 'PEND':
                return CommandResults(
                    scheduled_command=ScheduledCommand(command='prisma-sase-candidate-config-push',
                                                       args=args,
                                                       next_run_in_seconds=polling_interval,
                                                       timeout_in_seconds=polling_timeout))
            job_result = job.get('result_str')
            if job_result != 'OK':
                outputs['result'] = job_result
                outputs['details'] = job.get("summary")
                return CommandResults(entry_type=EntryType.ERROR,
                                      outputs=outputs,
                                      outputs_prefix=f'{PA_OUTPUT_PREFIX}CandidateConfig',
                                      readable_output=f'Something went wrong while trying to push sub process '
                                                      f'with id {job.get("id", "")}job id {job_id}. '
                                                      f'Result: {job_result}')
    return CommandResults(readable_output=f'Finished pushing job {job_id}',
                          outputs_prefix=f'{PA_OUTPUT_PREFIX}CandidateConfig',
                          outputs=outputs)


def main():  # pragma: no cover
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API url
    params = demisto.params()
    base_url = params.get('url').strip('/')
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    tsg_id = params.get('tsg_id')

    verify_certificate = not argToBoolean(params.get('insecure', False))
    proxy = argToBoolean(params.get('proxy', False))
    handle_proxy()

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    commands = {
        'prisma-sase-security-rule-create': create_security_rule_command,
        'prisma-sase-security-rule-list': list_security_rules_command,
        'prisma-sase-security-rule-delete': delete_security_rule_command,
        'prisma-sase-security-rule-update': edit_security_rule_command,

        'prisma-sase-candidate-config-push': run_push_jobs_polling_command,
        'prisma-sase-config-job-list': list_config_jobs_command,

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

        'prisma-sase-url-category-list': list_url_category_command,

        'prisma-sase-external-dynamic-list-list': list_external_dynamic_list_command,
        'prisma-sase-external-dynamic-list-create': create_external_dynamic_list_command,
        'prisma-sase-external-dynamic-list-update': update_external_dynamic_list_command,
        'prisma-sase-external-dynamic-list-delete': delete_custom_url_category_command,

        'prisma-sase-quarantine-host': quarantine_host_command,

        'prisma-sase-cie-user-get': get_cie_user_command,

    }
    client = Client(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        tsg_id=tsg_id,
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        proxy=proxy,
        ok_codes=(200, 201, 204))

    try:
        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, demisto.args()))  # type: ignore
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions
    except DemistoException as e:
        # special handling for 404 error, which is returned when the item is not found
        if e.res is not None and e.res.status_code == 404 and "Object Not Present" in e.message:
            return_results("The item you're searching for does not exist within the Prisma SASE API.")

        else:
            return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
