import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from smc import session
from smc.elements.network import IPList, DomainName, Host
from smc.policy.layer3 import FirewallTemplatePolicy, FirewallPolicy
from smc.api.exceptions import ElementNotFound
import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
DEFAULT_LIMIT = 50
''' CLIENT CLASS '''


class Client:
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """
    def __init__(self, url: str, api_key: str, verify: bool, proxy: bool, port: str):
        self.url = url + ':' + port
        self.api_key = api_key
        self.verify = verify  # How to use ssl?
        self.proxy = proxy

    def login(self):
        """Logs into a session of smc
        """
        session.login(url=self.url, api_key=self.api_key, verify=False, timeout=60)

    def logout(self):
        """logs out of a session in smc
        """
        session.logout()


def extract_host_address(host: Host):
    """extracting the ip address or the ipv6 address

    Args:
        host (Host): _description_

    Returns:
        _type_: _description_
    """
    address = ''
    try:
        address = host.address
    except AttributeError:
        pass

    ipv6_address = ''
    try:
        ipv6_address = host.ipv6_address
    except AttributeError:
        pass

    return address, ipv6_address


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    client.login()
    IPList.objects.limit(1)
    return 'ok'


def create_iplist_command(args: Dict[str, Any]) -> CommandResults:
    """Creating IP List with a list of addresses.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    name = args.get('name')
    addresses = argToList(args.get('addresses', []))
    comment = args.get('comment', '')

    ip_list = IPList.create(name=name, iplist=addresses, comment=comment)

    outputs = {'Name': ip_list.name,
               'Addresses': ip_list.iplist,
               'Comment': ip_list.comment,
               'Deleted': False}
    return CommandResults(
        outputs_prefix='ForcepointSMC.IPList',
        outputs=outputs,
        raw_response=outputs,
        readable_output=f'IP List {name} was created successfully.'
    )


def update_iplist_command(args: Dict[str, Any]) -> CommandResults:
    """Updating an IP List.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    name = args.get('name')
    addresses = argToList(args.get('addresses', []))
    comment = args.get('comment', '')
    is_overwrite = args.get('is_overwrite', False)

    if not list(IPList.objects.filter(name)):
        raise DemistoException(f'IP List {name} was not found.')

    ip_list = IPList.update_or_create(name=name, append_lists=not is_overwrite, iplist=addresses, comment=comment)

    outputs = {'Name': ip_list.name,
               'Addresses': ip_list.iplist,
               'Comment': ip_list.comment}

    return CommandResults(
        outputs_prefix='ForcepointSMC.IPList',
        outputs=outputs,
        raw_response=outputs,
        outputs_key_field='Name',
        readable_output=f'IP List {name} was updated successfully.'
    )


def list_iplist_command(args: Dict[str, Any]) -> CommandResults:
    """Lists the IP Lists in the system.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    name = args.get('name', '')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    all_results = argToBoolean(args.get('all_results', False))

    ip_lists = []
    if name:
        ip_lists = list(IPList.objects.filter(name))
    elif all_results:
        ip_lists = list(IPList.objects.all())
    else:
        ip_lists = list(IPList.objects.limit(limit))

    outputs = []
    for ip_list in ip_lists:
        outputs.append({'Name': ip_list.name,
                        'Addresses': ip_list.iplist,
                        'Comment': ip_list.comment})

    return CommandResults(
        outputs_prefix='ForcepointSMC.IPList',
        outputs=outputs,
        raw_response=outputs,
        outputs_key_field='Name',
        readable_output=tableToMarkdown(name='IP Lists:', t=outputs, removeNull=True),
    )


def delete_iplist_command(args: Dict[str, Any]) -> CommandResults:
    """Deleting IP List with a list of addresses.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    name = args.get('name')

    try:
        IPList(name).delete()

    except ElementNotFound:
        return CommandResults(readable_output=f'IP List {name} was not found.')

    outputs = {'Name': name,
               'Deleted': True}

    return CommandResults(
        outputs_prefix='ForcepointSMC.IPList',
        outputs_key_field='Name',
        outputs=outputs,
        readable_output=f'IP List {name} was deleted successfully.'
    )


def list_host_command(args: Dict[str, Any]) -> CommandResults:
    """Lists the Hosts in the system.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    name = args.get('name', '')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    all_results = argToBoolean(args.get('all_results', False))

    hosts = []
    if name:
        hosts = list(Host.objects.filter(name))
    elif all_results:
        hosts = list(Host.objects.all())
    else:
        hosts = list(Host.objects.limit(limit))

    outputs = []
    for host in hosts:
        address, ipv6_address = extract_host_address(host)
        outputs.append({'Name': host.name,
                        'Address': address,
                        'IPv6_address': ipv6_address,
                        'Secondary_address': host.secondary,
                        'Comment': host.comment})

    return CommandResults(
        outputs_prefix='ForcepointSMC.Host',
        outputs=outputs,
        raw_response=outputs,
        outputs_key_field='Name',
        readable_output=tableToMarkdown(name='Hosts:', t=outputs, removeNull=True),
    )


def create_host_command(args: Dict[str, Any]) -> CommandResults:
    """Creating a Host.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    name = args.get('name')
    address = args.get('address', '')
    ipv6_address = args.get('ipv6_address', '')
    secondary = args.get('secondary_address', '')
    comment = args.get('comment', '')

    Host.create(name=name, address=address, ipv6_address=ipv6_address, secondary=secondary, comment=comment)

    outputs = {'Name': name,
               'Address': address,
               'IPv6_address': ipv6_address,
               'Secondary_address': secondary,
               'Comment': comment}

    return CommandResults(
        outputs_prefix='ForcepointSMC.Host',
        outputs=outputs,
        raw_response=outputs,
        readable_output=f'Host {name} was created successfully.'
    )


def update_host_command(args: Dict[str, Any]) -> CommandResults:
    """Updating an Host.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    name = args.get('name')
    address = args.get('address', '')
    ipv6_address = args.get('ipv6_address', '')
    secondary = args.get('secondary_address', '')
    comment = args.get('comment', '')
    is_overwrite = args.get('is_overwrite', False)

    if not list(Host.objects.filter(name)):
        raise DemistoException(f'Host {name} was not found.')

    host = Host.update_or_create(name=name, address=address, ipv6_address=ipv6_address,
                                 secondary=secondary, comment=comment, append_lists=not is_overwrite)

    address, ipv6_address = extract_host_address(host)
    outputs = {'Name': host.name,
               'Address': address,
               'IPv6_address': ipv6_address,
               'Secondary_address': host.secondary,
               'Comment': host.comment}

    return CommandResults(
        outputs_prefix='ForcepointSMC.Host',
        outputs=outputs,
        raw_response=outputs,
        outputs_key_field='Name',
        readable_output=f'Host {name} was updated successfully.'
    )


def delete_host_command(args: Dict[str, Any]) -> CommandResults:
    """Deleting Host.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    name = args.get('name')

    try:
        Host(name).delete()

    except ElementNotFound:
        return CommandResults(readable_output=f'Host {name} was not found.')

    outputs = {'Name': name,
               'Deleted': True}

    return CommandResults(
        outputs_prefix='ForcepointSMC.Host',
        outputs_key_field='Name',
        outputs=outputs,
        readable_output=f'Host {name} was deleted successfully.'
    )


def create_domain_command(args: Dict[str, Any]) -> CommandResults:
    """Creating a Domain.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    name = args.get('name')
    comment = args.get('comment', '')

    DomainName.create(name=name, comment=comment)

    outputs = {'Name': name,
               'Comment': comment}

    return CommandResults(
        outputs_prefix='ForcepointSMC.Domain',
        outputs=outputs,
        raw_response=outputs,
        readable_output=f'Domain {name} was created successfully.'
    )


def list_domain_command(args: Dict[str, Any]) -> CommandResults:
    """Lists the Domains in the system.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    name = args.get('name', '')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    all_results = argToBoolean(args.get('all_results', False))

    domains = []
    if name:
        domains = list(DomainName.objects.filter(name))
    elif all_results:
        domains = list(DomainName.objects.all())
    else:
        domains = list(DomainName.objects.limit(limit))

    outputs = []
    for domain in domains:
        outputs.append({'Name': domain.name,
                        'Comment': domain.comment})

    return CommandResults(
        outputs_prefix='ForcepointSMC.Domain',
        outputs=outputs,
        raw_response=outputs,
        outputs_key_field='Name',
        readable_output=tableToMarkdown(name='Domains:', t=outputs, removeNull=True),
    )


def delete_domain_command(args: Dict[str, Any]) -> CommandResults:
    """Deleting domain.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    name = args.get('name')

    try:
        DomainName(name).delete()

    except ElementNotFound:
        return CommandResults(readable_output=f'Domain {name} was not found.')

    outputs = {'Name': name,
               'Deleted': True}

    return CommandResults(
        outputs_prefix='ForcepointSMC.Domain',
        outputs_key_field='Name',
        outputs=outputs,
        readable_output=f'Domain {name} was deleted successfully.'
    )


def list_policy_template_command(args: Dict[str, Any]) -> CommandResults:
    """Lists the policy templates in the system.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    all_results = argToBoolean(args.get('all_results', False))

    policy_templates = []
    if all_results:
        policy_templates = list(FirewallTemplatePolicy.objects.all())
    else:
        policy_templates = list(FirewallTemplatePolicy.objects.limit(limit))

    outputs = []
    for policy_template in policy_templates:
        outputs.append({'Name': policy_template.name,
                        'Comment': policy_template.comment})

    return CommandResults(
        outputs_prefix='ForcepointSMC.PolicyTemplate',
        outputs=outputs,
        raw_response=outputs,
        outputs_key_field='Name',
        readable_output=tableToMarkdown(name='Policy template:', t=outputs, removeNull=True),
    )


def list_firewall_policy_command(args: Dict[str, Any]) -> CommandResults:
    """Lists the policy templates in the system.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    all_results = argToBoolean(args.get('all_results', False))

    firewall_policies = []
    if all_results:
        firewall_policies = list(FirewallPolicy.objects.all())
    else:
        firewall_policies = list(FirewallPolicy.objects.limit(limit))

    outputs = []
    for firewall_policy in firewall_policies:
        outputs.append({'Name': firewall_policy.name,
                        'Comment': firewall_policy.comment})

    return CommandResults(
        outputs_prefix='ForcepointSMC.FirewallPolicy',
        outputs=outputs,
        raw_response=outputs,
        outputs_key_field='Name',
        readable_output=tableToMarkdown(name='Firewall policies:', t=outputs, removeNull=True),
    )


def create_firewall_policy_command(args: Dict[str, Any]) -> CommandResults:
    """Creating a Domain.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    name = args.get('name')
    template = args.get('template', '')

    firewall_policy = FirewallPolicy.create(name=name, template=template)

    outputs = {'Name': firewall_policy.name,
               'Comment': firewall_policy.comment}

    return CommandResults(
        outputs_prefix='ForcepointSMC.Domain',
        outputs=outputs,
        raw_response=outputs,
        readable_output=f'Firewall policy {name} was created successfully.'
    )


def delete_firewall_policy_command(args: Dict[str, Any]) -> CommandResults:
    """Deleting domain.

    Args:
        args (Dict[str, Any]): The command args.

    Returns:
        CommandResults
    """
    name = args.get('name')

    try:
        FirewallPolicy(name).delete()

    except ElementNotFound:
        return CommandResults(readable_output=f'Firewall policy {name} was not found.')

    outputs = {'Name': name,
               'Deleted': True}

    return CommandResults(
        outputs_prefix='ForcepointSMC.Policy',
        outputs_key_field='Name',
        outputs=outputs,
        readable_output=f'Firewall policy {name} was deleted successfully.'
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """
    params = demisto.params()
    url = params.get('url')
    api_key = params.get('credentials', {}).get('password')
    port = params.get('port')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()

    demisto.debug(f'Command being called is {command}')
    try:

        client = Client(
            url=url,
            api_key=api_key,
            verify=verify,
            proxy=proxy,
            port=port)

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        client.login()

        if command == 'forcepoint-smc-ip-list-create':
            return_results(create_iplist_command(demisto.args()))
        elif command == 'forcepoint-smc-ip-list-update':
            return_results(update_iplist_command(demisto.args()))
        elif command == 'forcepoint-smc-ip-list-list':
            return_results(list_iplist_command(demisto.args()))
        elif command == 'forcepoint-smc-ip-list-delete':
            return_results(delete_iplist_command(demisto.args()))
        elif command == 'forcepoint-smc-host-list':
            return_results(list_host_command(demisto.args()))
        elif command == 'forcepoint-smc-host-create':
            return_results(create_host_command(demisto.args()))
        elif command == 'forcepoint-smc-host-update':
            return_results(update_host_command(demisto.args()))
        elif command == 'forcepoint-smc-host-delete':
            return_results(delete_host_command(demisto.args()))
        elif command == 'forcepoint-smc-domain-create':
            return_results(create_domain_command(demisto.args()))
        elif command == 'forcepoint-smc-domain-list':
            return_results(list_domain_command(demisto.args()))
        elif command == 'forcepoint-smc-domain-delete':
            return_results(delete_domain_command(demisto.args()))
        elif command == 'forcepoint-smc-policy-template-list':
            return_results(list_policy_template_command(demisto.args()))
        elif command == 'forcepoint-smc-firewall-policy-create':
            return_results(create_firewall_policy_command(demisto.args()))
        elif command == 'forcepoint-smc-firewall-policy-delete':
            return_results(delete_firewall_policy_command(demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')
    finally:
        client.logout()


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
