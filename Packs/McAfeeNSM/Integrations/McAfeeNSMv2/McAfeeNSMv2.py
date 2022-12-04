
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any
import base64

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, url: str, auth: tuple, headers: Dict, proxy: bool = False, verify: bool = True):
        self.url = url
        self.headers = headers
        super().__init__(base_url=url, verify=verify, proxy=proxy, auth=auth, headers=headers)

    def get_session_request(self, encoded_str: str) -> Dict:
        """ Gets a session from the API.
            Args:
                encoded_str: str - The string that contains username:password in base64.
            Returns:
                A dictionary with the session details.
        """
        url_suffix = '/sdkapi/session'
        self.headers['NSM-SDK-API'] = encoded_str
        return self._http_request(method='GET', url_suffix=url_suffix)

    def list_domain_firewall_policy_request(self, encoded_str: str, domain_id: int) -> Dict:
        """ Gets the list of Firewall Policies defined in a particular domain.
            Args:
                encoded_str: str - The string that contains username:password in base64.
                domain_id: int - The id of the domain.
            Returns:
                A dictionary with the firewall policy list.
        """
        url_suffix = f'/sdkapi/domain/{domain_id}/firewallpolicy'
        self.headers['NSM-SDK-API'] = encoded_str
        return self._http_request(method='GET', url_suffix=url_suffix)

    def get_firewall_policy_request(self, encoded_str: str, policy_id) -> Dict:
        """ Gets the Firewall Policy details.
            Args:
                encoded_str: str - The string that contains username:password in base64.
                policy_id: int - The id of the policy.
            Returns:
                A dictionary with the policy details.
        """
        url_suffix = f'/sdkapi/firewallpolicy/{policy_id}'
        self.headers['NSM-SDK-API'] = encoded_str
        return self._http_request(method='GET', url_suffix=url_suffix)


''' HELPER FUNCTIONS '''


def encode_to_base64(str_to_convert: str) -> str:
    """ Converts a string to base64 string.
    Args:
        str_to_convert: str - The string that needs to be converted to base64.
    Returns:
        The converted string.
    """
    b = base64.b64encode(bytes(str_to_convert, 'utf-8'))  # bytes
    base64_str = b.decode('utf-8')  # convert bytes to string
    return base64_str


def get_session(client: Client, user_name_n_password_encoded: str) -> str:
    """ Gets the session string.
    Args:
        client: Client - A McAfeeNSM client.
        user_name_n_password_encoded: str - The username and password that needs to be converted to base64
            in order to get the session information.
    Returns:
        The converted string.
    """
    session = client.get_session_request(user_name_n_password_encoded)
    return encode_to_base64(f'{session.get("session")}:{session.get("userId")}')


def pagination(records_list: List, limit: int, page: int) -> List:
    """ Returns the wanted records.
    Args:
        records_list: List - The original list of objects.
        limit: str - The amount of records to be returned
        page: int - The page of the results (The results in page 1, 2 ...)
    Returns:
        The wanted records.
    """
    if page == 1:
        return records_list[:limit]
    else:
        min_size = (limit * (page - 1))  #TODO check if needed
        if min_size < len(records_list):
            results_list = records_list[min_size:]
            return results_list[:limit]
        else:
            return []


''' COMMAND FUNCTIONS '''


def test_module(client: Client, encoded_str: str) -> str:
    """ Test the connection to McAfee NSM.
    Args:
        client: Client - A McAfeeNSM client.
        encoded_str: str - The string that contains username:password in base64
    Returns:
        'ok' if the connection was successful, else throws exception.
    """
    try:
        client.get_session_request(encoded_str)
        return 'ok'
    except DemistoException as e:
        raise Exception(e.message)


def list_domain_firewall_policy_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Gets the list of Firewall Policies defined in a particular domain.
    Args:
        client: client - A McAfeeNSM client.
        args: Dict - The function arguments.
        session_str: str - The session string for authentication.
    Returns:
        A CommandResult object with the list of Firewall Policies defined in a particular domain.
    """
    domain_id = args.get('domain_id')
    limit = arg_to_number(args.get('limit', 50)) or 50
    page = arg_to_number(args.get('page', 1)) or 1

    response = client.list_domain_firewall_policy_request(session_str, domain_id)
    result = response.get('FirewallPoliciesForDomainResponseList', [])
    result = pagination(result, limit, page)
    human_readable = []
    for value in result:
        d = {'policyId': value.get('policyId'),
             'policyName': value.get('policyName'),
             'domainId': value.get('domainId'),
             'visibleToChild': value.get('visibleToChild'),
             'description': value.get('description'),
             'isEditable': value.get('isEditable'),
             'policyType': value.get('policyType'),
             'policyVersion': value.get('policyVersion'),
             'lastModUser': value.get('lastModUser')}
        human_readable.append(d)

    hr_title = 'Firewall Policies List'
    headers = ['policyId', 'policyName', 'domainId', 'visibleToChild', 'description', 'isEditable', 'policyType',
               'policyVersion', 'lastModUser']
    readable_output = tableToMarkdown(
        name=hr_title,
        t=human_readable,
        removeNull=True,
        headers=headers
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.Policy',
        outputs_key_field='policyId',
        outputs=result,
        raw_response=result
    )


def get_firewall_policy_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Gets the Firewall Policy details.
    Args:
        client: client - A McAfeeNSM client.
        args: Dict - The function arguments.
        session_str: str - The session string for authentication.
    Returns:
        A CommandResult object with the Firewall Policy details.
    """
    policy_id = args.get('policy_id')
    response = client.get_firewall_policy_request(session_str, policy_id)
    human_readable = {'FirewallPolicyId': response.get('FirewallPolicyId'),
                      'Name': response.get('Name'),
                      'Description': response.get('Description'),
                      'VisibleToChild': response.get('VisibleToChild'),
                      'IsEditable': response.get('IsEditable'),
                      'PolicyType': response.get('PolicyType'),
                      'PolicyVersion': response.get('PolicyVersion'),
                      'LastModifiedUser': response.get('LastModifiedUser'),
                      'LastModifiedTime': response.get('LastModifiedTime')}
    headers = ['PolicyId', 'Name', 'Description', 'VisibleToChild', 'IsEditable', 'PolicyType', 'PolicyVersion',
               'LastModifiedUser', 'LastModifiedTime']
    readable_output = tableToMarkdown(
        name=f'Firewall Policy {policy_id}',
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.Policy',
        outputs=response,
        raw_response=response,
        outputs_key_field='name'
    )


def create_firewall_policy_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Adds a new Firewall Policy and Access Rules.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
            session_str: str - The session string for authentication.
        Returns:
            A CommandResult object with a success message.
    """
    domain = args.get('domain')
    name = args.get('name')
    visible_to_child = args.get('visible_to_child')
    description = args.get('description')
    is_editable = args.get('is_editable')
    policy_type = args.get('policy_type')
    rule_description = args.get('rule_description')
    direction = args.get('direction')
    source_rule_object_id = args.get('source_rule_object_id')
    source_rule_name = args.get('source_rule_name')
    source_rule_object_type = args.get('source_rule_object_type')
    destination_rule_object_id = args.get('destination_rule_object_id')
    destination_rule_name = args.get('destination_rule_name')
    destination_rule_object_type = args.get('destination_rule_object_type')
    source_arr = [source_rule_object_id, source_rule_name, source_rule_object_type]
    destination_arr = [destination_rule_object_id, destination_rule_name, destination_rule_object_type]
    source_sum = sum(map(bool, source_arr))


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    url = demisto.params().get('url')
    user_name = demisto.params().get('credentials', {}).get('identifier', "")
    password = demisto.params().get('credentials', {}).get('password', "")
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    auth = (user_name, password)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        headers: Dict = {
            'Accept': 'application/vnd.nsm.v1.0+json',
            'Content-Type': 'application/json'
        }

        client = Client(url=url, auth=auth, headers=headers, proxy=proxy, verify=verify_certificate)
        user_name_n_password_encoded = encode_to_base64(f'{user_name}:{password}')
        session_str = ''
        if demisto.command() != 'test-module':
            session_str = get_session(client, user_name_n_password_encoded)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, user_name_n_password_encoded)
            return_results(result)
        elif demisto.command() == 'nsm-list-domain-firewall-policy':
            result = list_domain_firewall_policy_command(client, demisto.args(), session_str)
            return_results(result)
        elif demisto.command() == 'nsm-get-firewall-policy':
            results = get_firewall_policy_command(client, demisto.args(), session_str)
            return_results(results)
        elif demisto.command() == 'nsm-create-firewall-policy':
            results = create_firewall_policy_command(client, demisto.args(), session_str)
            return_results(results)
        else:
            raise NotImplementedError('This command is not implemented yet.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
