from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''

import urllib3
from cymruwhois import Client  # Python interface to whois.cymru.com
import csv
from typing import Tuple

# Disable insecure warnings
urllib3.disable_warnings()

'''GLOBALS'''

HEADERS = ['ip', 'asn', 'owner', 'cc', 'prefix']
MAPPING = {'ip': 'IP', 'asn': 'ASN', 'owner': 'Organization', 'cc': 'Country', 'prefix': 'Range'}

''' CLIENT COMMANDS '''


def team_cymru_ip(client: Client, ip: str) -> Optional[Dict[str, Any]]:
    """Perform lookups by ip address and return ASN, Country Code, and Network Owner.

    :type client: ``Client``
    :param client: cymruwhois client to use
    :type ip: ``str``
    :param ip: string to add in the dummy dict that is returned

    :return: Dictionary contains the results of the lookup API call.
    :rtype: Dict[str, str]
    """
    raw_result = client.lookup(ip)
    return vars(raw_result) if raw_result else None


def team_cymru_bulk_whois(client: Client, bulk: List[str]) -> Optional[Dict[str, Any]]:
    """Perform lookups by bulk of ip addresses,
    returning a dictionary of ip -> record (ASN, Country Code, and Netblock Owner.)

    :type client: ``Client``
    :param client: cymruwhois client to use
    :type bulk: ``list``
    :param bulk: list of ip addresses

    :return: Dictionary contains the results of the lookupmany API call.
    :rtype: Dict[str, Dict[str, str]]
    """

    raw_result = client.lookupmany_dict(bulk)
    return {k: vars(raw_result[k]) for k in raw_result} if raw_result else None


''' HELPER FUNCTIONS '''


def parse_ip_result(ip: str, ip_data: dict[str, str]) -> CommandResults:
    """
    Arranges the IP's result from the API to the context format.
    :param ip: ip address
    :param ip_data: the ip given data (as returned from the API call)
    :return: commandResult of the given IP
    """
    asn = demisto.get(ip_data, 'asn')
    owner = demisto.get(ip_data, 'owner')
    country = demisto.get(ip_data, 'cc')
    prefix = demisto.get(ip_data, 'prefix')
    entry_context = {'Address': ip,
                     'ASN': asn,
                     'ASOwner': owner,
                     'Geo': {'Country': country},
                     'Registrar': {'Abuse': {'Network': prefix}}}
    indicator = Common.IP(
        ip=ip,
        asn=asn,
        as_owner=owner,
        geo_country=country,
        registrar_abuse_network=prefix,
        dbot_score=Common.DBotScore(indicator=ip,
                                    indicator_type=DBotScoreType.IP,
                                    score=Common.DBotScore.NONE))

    human_readable = tableToMarkdown(f'Team Cymru results for {ip}', ip_data, HEADERS,
                                     headerTransform=lambda header: MAPPING.get(header, header))
    outputs_key_field = 'ip'  # marks the ip address
    return CommandResults(
        readable_output=human_readable,
        raw_response=ip_data,
        outputs_prefix='TeamCymru.IP',
        outputs_key_field=outputs_key_field,
        indicator=indicator,
        outputs=entry_context
    )


def validate_ip_addresses(ips_list: list[str]) -> Tuple[list[str], list[str]]:
    """
    Given a list of IP addresses, returns the invalid and valid ips.
    :param ips_list: list of ip addresses
    :return: invalid_ip_addresses, valid_ip_addresses
    """
    invalid_ip_addresses = []
    valid_ip_addresses = []
    for ip in ips_list:
        ip = ip.strip().strip('\"')
        if ip:
            if is_ip_valid(ip):
                valid_ip_addresses.append(ip)
            else:
                invalid_ip_addresses.append(ip)
    return invalid_ip_addresses, valid_ip_addresses


def parse_file(file_path_res: dict[str, str], delimiter: str = ",") -> List[str]:
    """
    Parses the given file line by line to list.
    :param delimiter: delimiter by which the content of the list is seperated.
    :param file_path_res: Object contains file ID, path and name
    :return: bulk list of the elements in the file
    """
    bulk_list = []
    with open(file_path_res['path']) as file:
        reader = csv.reader(file, delimiter=delimiter, skipinitialspace=True)
        for row in reader:
            for col in row:
                bulk_list += col.split()
    return bulk_list


def parse_ips_list(client: Client, ips_list: list[str]) -> List[CommandResults]:
    """
    Creates a commandResults array based on a list of IP addresses,
    this by calling the relevant functions.
    :param client: client to use
    :param ips_list: list of IP addresses
    :return: CommandResults object
    """
    command_results: List[CommandResults] = []
    invalid_ips, valid_ips = validate_ip_addresses(ips_list)
    if invalid_ips:
        return_warning('The following IP Addresses were found invalid: {}'.format(', '.join(invalid_ips)),
                       exit=len(invalid_ips) == len(ips_list))

    results = team_cymru_bulk_whois(client, valid_ips)
    if results:
        for ip, ip_data in results.items():
            command_results.append(parse_ip_result(ip, ip_data))
    return command_results


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        result = team_cymru_ip(client, '8.8.8.8')
        if result and result.get('owner') == 'GOOGLE, US':
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def ip_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Returns the results of 'ip' command
    :type client: ``Client``
    :param Client: client to use

    :type args: ``Dict[str, Any]``
    :param args: All command arguments, the field 'ip'
    :return: CommandResults object containing the results of the lookup action as returned from the API
    and its readable output.
    """
    command_results: List[CommandResults] = []
    ip = argToList(args.get('ip'))
    if not ip:
        raise ValueError('IP not specified')
    if len(ip) > 1:
        return parse_ips_list(client, ip)
    if len(ip) == 1 and not is_ip_valid(ip[0]):
        raise ValueError(f"The given IP address: {ip[0]} is not valid")

    # Call the Client function and get the raw response
    result = team_cymru_ip(client, ip[0])
    if result:
        command_results.append(parse_ip_result(ip[0], result))
    return command_results


def cymru_bulk_whois_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Returns results of 'cymru-bulk-whois' command
    :type client: ``Client``
    :param Client: client to use

    :type args: ``Dict[str, Any]``
    :param args: All command arguments - 'entry_id', 'delimiter'
    :return: CommandResults object containing the results of the lookup action as returned from the API
    and its readable output.
    """

    if args.get('entry_id'):
        demisto.debug("Using the entry_id to find the file's path")
        file_path = demisto.getFilePath(args.get('entry_id'))
        if not file_path:
            raise ValueError('No file was found for given entry_id')
        ips_list = parse_file(file_path, args.get('delimiter', ','))
    else:
        raise ValueError('No entry_id specified.')

    return parse_ips_list(client, ips_list)


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    verify_certificate = not demisto.params().get('insecure', False)  # noqa: F841
    proxy = demisto.params().get('proxy', False)  # noqa: F841

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client()

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'ip':
            return_results(ip_command(client, demisto.args()))
        elif demisto.command() == 'cymru-bulk-whois':
            return_results(cymru_bulk_whois_command(client, demisto.args()))
        else:
            raise NotImplementedError(f"command {demisto.command()} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
