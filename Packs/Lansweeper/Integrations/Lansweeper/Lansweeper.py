import urllib3
from typing import Any, Callable
import traceback
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
demisto.debug('pack name = Lansweeper, pack version = 1.0.10')


# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

COMMON_GRAPHQL_ENDPOINT = "https://api.lansweeper.com/api/v2/graphql"

MESSAGES = {
    "AUTHENTICATION_ERROR": "Authentication error. Please provide valid 'Application Identity Code'.",
    "INTERNAL_SERVER_ERROR": "The server encountered an internal error for Lansweeper and was unable to complete your "
                             "request.",
    "REQUIRED_ARGUMENT": "Invalid argument value. '{}' is a required argument.",
    "INVALID_IP": "Provided IP Address(es) are invalid.",
    "INVALID_MAC": "Provided Mac Address(es) are invalid.",
    "INVALID_LIMIT": '{} is an invalid value for limit. Limit must be between 1 and 500.',
    "NO_AUTHORIZED_SITES_FOUND": "No authorized sites found for configured 'Application Identity Code'"
}
''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    """

    def http_request(self, full_url, method="POST", json_data=None,
                     params=None) -> Any:
        """
        Function to make http requests using inbuilt _http_request() method.
        Handles token expiration case and makes request using refreshed token.
        :param json_data: The data to send in a 'POST' request.
        :param method: http method to use
        :param full_url: the API endpoint
        :param params: parameters to send with request
        :return: response from the request
        """

        response = self._http_request(method=method, full_url=full_url, params=params, json_data=json_data,
                                      error_handler=self.exception_handler)

        errors = response.get('errors', [])
        if errors:
            extensions = errors[0].get('extensions', {})
            if extensions.get('exception', {}):
                err_msg = extensions.get('exception', {}).get('message', '')
            else:
                error_list = extensions.get('error', {}).get('extensions', {}).get('response', {}).get('body', {}).get(
                    'errors', [])
                err_msg = "\n".join(error.get('message', '') for error in error_list)
            raise DemistoException(err_msg)
        return response

    def site_list(self) -> Dict:
        """
        Returns response

        :return: API response
        :rtype: ``Dict``
        """
        query = """query {
                    authorizedSites {
                      sites {
                            id
                            name
                        }
                    }
                 }"""

        return self.http_request(full_url=COMMON_GRAPHQL_ENDPOINT, json_data={"query": query})

    def asset_list(self, query) -> Dict:
        """
        Returns response

        :return: API response
        :rtype: ``Dict``
        """
        params = {"query": query}

        return self.http_request(full_url=COMMON_GRAPHQL_ENDPOINT, json_data=params)

    @staticmethod
    def exception_handler(response: requests.models.Response):
        """
        Handle error in the response and display error message based on status code.

        :type response: ``requests.models.Response``
        :param response: response from API.

        :raises: raise DemistoException based on status code of response.
        """
        err_msg = ""
        if response.status_code == 400:
            err_msg = MESSAGES["AUTHENTICATION_ERROR"]
        elif response.status_code >= 500:
            err_msg = MESSAGES["INTERNAL_SERVER_ERROR"]

        raise DemistoException(err_msg)


''' HELPER FUNCTIONS '''


def prepare_hr_for_site(sites: List[Dict[str, Any]]) -> str:
    """
       Prepare human readable for list sites command.

       :type sites: ``List[Dict[str, Any]]``
       :param sites:The site data.

       :rtype: ``str``
       :return: Human readable.
    """
    hr_list = []
    for site in sites:
        hr_record = {
            'Site ID': site.get('id', ''),
            'Site Name': site.get('name', '')
        }

        hr_list.append(hr_record)

    return tableToMarkdown('Authorized Site(s)', hr_list, ['Site ID', 'Site Name'],
                           removeNull=True)


def prepare_query(site_id: str, condition: str) -> str:
    """
    Creates GraphQL query

    :type site_id: ``str``
    :param site_id: Site ID entered by user

    :type condition: ``str``
    :param condition: filter conditions

    :rtype: ``str``
    :return: GraphQL query
    """
    query = """query getAssetResources($pagination: AssetsPaginationInputValidated) {
                    site(id: "%s") {
                        assetResources (
                            assetPagination: $pagination,
                            fields: [
                                "assetBasicInfo.name",
                                "assetBasicInfo.domain",
                                "assetBasicInfo.userName",
                                "assetBasicInfo.userDomain",
                                "assetBasicInfo.fqdn",
                                "assetBasicInfo.description",
                                "assetBasicInfo.type",
                                "assetBasicInfo.mac",
                                "assetBasicInfo.ipAddress",
                                "assetBasicInfo.firstSeen"
                                "assetBasicInfo.lastSeen"
                                "assetCustom.model",
                                "assetCustom.serialNumber",
                                "assetCustom.manufacturer",
                                "assetCustom.sku",
                                "assetCustom.firmwareVersion",
                                "assetCustom.purchaseDate",
                                "assetCustom.warrantyDate",
                                "assetCustom.comment",
                                "assetCustom.location",
                                "assetCustom.department",
                                "assetCustom.contact",
                                "assetCustom.dnsName",
                                "assetCustom.stateName",
                                "operatingSystem.caption",
                                "operatingSystem.productType",
                                "url"
                            ],
                            filters: {
                                conjunction: OR,
                                conditions: [%s]
                            }
                        ) {
                            total
                            pagination {
                                limit
                                current
                                next
                                page
                            }
                            items
                        }
                    }
                }""" % (
        site_id,
        condition
    )

    return query


def prepare_hr_for_asset(assets: List[Dict[str, Any]]) -> str:
    """
    Prepare human readable for ls-ip-hunt command.

    :type assets: ``List[Dict[str, Any]]``
    :param assets:The asset data.

    :rtype: ``str``
    :return: Human readable.
    """
    hr_list = []

    for asset in assets:
        hr_record = {
            'Site Name': asset.get('siteName'),
            'Name': f"[{asset.get('assetBasicInfo', {}).get('name', '')}]({asset.get('url', '')})",
            'Domain': asset.get('assetBasicInfo', {}).get('domain', ''),
            'User Name': asset.get('assetBasicInfo', {}).get('userName', ''),
            'User Domain': asset.get('assetBasicInfo', {}).get('userDomain', ''),
            'FQDN': asset.get('assetBasicInfo', {}).get('fqdn', ''),
            'Description': asset.get('assetBasicInfo', {}).get('description', ''),
            'Type': asset.get('assetBasicInfo', {}).get('type', ''),
            'IP Address': asset.get('assetBasicInfo', {}).get('ipAddress', ''),
            'Mac Address': asset.get('assetBasicInfo', {}).get('mac', ''),
            'Model': asset.get('assetCustom', {}).get('model', ''),
            'Manufacturer': asset.get('assetCustom', {}).get('manufacturer', ''),
            'Serial Number': asset.get('assetCustom', {}).get('serialNumber', ''),
            'SKU': asset.get('assetCustom', {}).get('sku', ''),
            'First Seen': asset.get('assetBasicInfo', {}).get('firstSeen', ''),
            'Last Seen': asset.get('assetBasicInfo', {}).get('lastSeen', ''),

        }

        hr_list.append(hr_record)

    return tableToMarkdown('Asset(s)', hr_list,
                           ['Name', 'Domain', 'User Name', 'User Domain', 'FQDN', 'Description', 'Type',
                            'IP Address',
                            'Mac Address', 'Model', 'Manufacturer', 'Serial Number', 'SKU', 'Site Name', 'First Seen',
                            'Last Seen'],
                           removeNull=True)


def prepare_site_list(client: Client, args: Dict) -> List:
    """
    Prepare list of authorized sites

    :type client: ``Client``
    :param client:  Client object to be used.

    :type args: ``Dict``
    :param args: The command arguments provided by the user.

    :return: site list
    :rtype: ``List``
    """
    site_id = args.get('site_id')
    site_response = get_authorized_sites(client)
    if not (site_id or site_response):
        raise ValueError(MESSAGES["NO_AUTHORIZED_SITES_FOUND"])
    if site_id and site_response:
        for site in site_response:
            if site['id'] == site_id:
                return [site]
        site_list = [{'id': site_id}]
    elif site_id:
        site_list = [{'id': site_id}]
    else:
        site_list = site_response
    return site_list


def get_authorized_sites(client: Client) -> List:
    """
    Get the authorized sites from integration context if present else call the endpoint to retrieve authorized sites

    :type client: ``Client``
    :param client:  Client object to be used.

    :return: List of authorized sites
    :rtype: ``List``
    """
    site_response = get_integration_context()
    authorized_sites = site_response.get('authorized_sites')
    if authorized_sites:
        return authorized_sites

    response = client.site_list()
    site_response = get_integration_context()

    sites = {
        'authorized_sites': response.get('data', {}).get('authorizedSites', {}).get('sites', [])
    }
    site_response.update(sites)
    set_integration_context(site_response)
    return site_response['authorized_sites']


def creds_changed(context: dict, identity_code: str) -> bool:
    """
    Check whether the credentials were changed by the user.
    Args:
        context (dict): Integration context from Demisto.
        identity_code (str): Lansweeper application identity code.
    Returns:
        creds_changed (bool): True if credentials were changed, False otherwise.
    """
    return context.get("identity_code", "") != identity_code


def update_context(identity_code: str) -> None:
    """
    Invalidate the Demisto integration context and set new identity code.
    Args:
        identity_code (str): Lansweeper application identity code.
    """
    set_integration_context({"identity_code": identity_code})


''' COMMAND FUNCTIONS '''


def lansweeper_site_list_command(client: Client) -> CommandResults:
    """
    Retrieves the list of authorized sites
    :type client: ``Client``
    :param client: Client object to be used.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """

    response = client.site_list()
    records = response.get('data', {}).get('authorizedSites', {}).get('sites', [])
    context = remove_empty_elements(records)
    readable_hr = prepare_hr_for_site(records)
    return CommandResults(
        outputs_prefix="Lansweeper.Site",
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_hr,
        raw_response=response)


def lansweeper_ip_hunt_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Retrieves the list of assets
    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """

    total_records = []
    site_list = prepare_site_list(client, args)
    limit = arg_to_number(args.get('limit', 50))
    ip_list = argToList(args['ip'])

    if not ip_list:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format('ip'))

    if limit <= 0 or limit > 500:  # type:ignore
        raise ValueError(MESSAGES["INVALID_LIMIT"].format(limit))

    ip_condition = ""
    for ip in ip_list:
        if is_ip_valid(ip):
            ip_condition += ("""{operator: EQUAL,path: "assetBasicInfo.ipAddress",value: "%s"},""" % ip)
    if not ip_condition:
        raise ValueError(MESSAGES["INVALID_IP"])

    for site in site_list:
        query = prepare_query(site.get('id'), ip_condition[:-1])
        response = client.asset_list(query)
        records = response.get("data", {}).get("site", {}).get("assetResources", {}).get("items", [])
        for record in records:
            record['assetId'] = site.get('_id')
            record['siteId'] = site.get('id')
            record['siteName'] = site.get('name')
            total_records.append(remove_empty_elements(record))

    context = total_records[:limit]
    readable_hr = prepare_hr_for_asset(context)
    return CommandResults(
        outputs_prefix="Lansweeper.IP",
        outputs_key_field="assetId",
        outputs=context,
        readable_output=readable_hr,
        raw_response=response

    )


def lansweeper_mac_hunt_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Retrieves the list of assets
    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """
    total_records = []
    site_list = prepare_site_list(client, args)
    limit = arg_to_number(args.get('limit', 50))
    mac_list = argToList(args['mac_address'])

    if not mac_list:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format('mac_address'))

    if limit <= 0 or limit > 500:  # type:ignore
        raise ValueError(MESSAGES["INVALID_LIMIT"].format(limit))

    mac_condition = ""
    for mac in mac_list:
        if is_mac_address(mac):
            mac_condition += ("""{operator: EQUAL,path: "assetBasicInfo.mac",value: "%s"},""" % mac)
    if not mac_condition:
        raise ValueError(MESSAGES["INVALID_MAC"])

    for site in site_list:
        query = prepare_query(site.get('id'), mac_condition[:-1])
        response = client.asset_list(query)
        records = response.get("data", {}).get("site", {}).get("assetResources", {}).get("items", [])
        for record in records:
            record['assetId'] = site.get('_id')
            record['siteId'] = site.get('id')
            record['siteName'] = site.get('name')
            total_records.append(remove_empty_elements(record))

    context = total_records[:limit]
    readable_hr = prepare_hr_for_asset(context)
    return CommandResults(
        outputs_prefix="Lansweeper.Mac",
        outputs_key_field="assetId",
        outputs=context,
        readable_output=readable_hr,
        raw_response=response

    )


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        client: client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    client.site_list()
    return 'ok'


def main():
    """main function, parses params and runs command functions"""

    command = demisto.command()
    demisto.debug(f'[Lansweeper] Command being called is {command}')

    params = demisto.params()

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    identity_code = params.get("identity_code")
    if creds_changed(get_integration_context(), identity_code):
        update_context(identity_code)
    # Commands dictionary
    commands: Dict[str, Callable] = {
        'ls-ip-hunt': lansweeper_ip_hunt_command,
        'ls-mac-hunt': lansweeper_mac_hunt_command

    }

    try:
        headers: Dict = {
            "Authorization": f"Token {identity_code}"
        }

        client = Client(base_url=COMMON_GRAPHQL_ENDPOINT,
                        verify=verify_certificate,
                        proxy=proxy,
                        headers=headers
                        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'ls-site-list':
            return_results(lansweeper_site_list_command(client))

        elif command in commands:
            args = {key: value.strip() for key, value in demisto.args().items()}
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'Command {demisto.command()} is not implemented')
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
