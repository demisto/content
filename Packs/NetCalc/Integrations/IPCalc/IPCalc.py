
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any
import ipcalc

''' COMMAND FUNCTIONS '''


def test_module() -> str:
    ipcalc.Network('192.168.10.10/32')
    return 'ok'


def return_subnet_addresses_command(args: Dict[str, Any]) -> CommandResults:

    subnet = args.get('subnet', None)

    if not subnet:
        raise ValueError('subnet not specified')

    addresses = []

    for x in ipcalc.Network(subnet):
        addresses.append(str(x))

    readable_output = tableToMarkdown(headers='IP Addresses:', t=addresses, name='List Addresses')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Address',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=addresses,
    )


def return_subnet_network_command(args: Dict[str, Any]) -> CommandResults:

    subnet = args.get('subnet', None)

    if not subnet:
        raise ValueError('subnet not specified')

    network = str(ipcalc.Network(subnet).guess_network())

    readable_output = tableToMarkdown(headers='Network:', t=network, name='Subnet Network')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Network',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=network,
    )


def return_subnet_first_address_command(args: Dict[str, Any]) -> CommandResults:

    subnet = args.get('subnet', None)

    if not subnet:
        raise ValueError('subnet not specified')

    first_address = str(ipcalc.Network(subnet).host_first())

    readable_output = tableToMarkdown(headers='Address:', t=first_address, name='First Address')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Address',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=first_address,
    )


def return_subnet_last_address_command(args: Dict[str, Any]) -> CommandResults:

    subnet = args.get('subnet', None)

    if not subnet:
        raise ValueError('subnet not specified')

    last_address = str(ipcalc.Network(subnet).host_last())

    readable_output = tableToMarkdown(headers='Address:', t=last_address, name='Last Address')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Address',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=last_address,
    )


def return_subnet_broadcast_address_command(args: Dict[str, Any]) -> CommandResults:

    subnet = args.get('subnet', None)

    if not subnet:
        raise ValueError('subnet not specified')

    broadcast_address = str(ipcalc.Network(subnet).broadcast())

    readable_output = tableToMarkdown(headers='Address:', t=broadcast_address, name='Broadcast Address')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Address',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=broadcast_address,
    )


def return_check_collision_command(args: Dict[str, Any]) -> CommandResults:

    subnet1 = args.get('subnet_one', None)
    subnet2 = args.get('subnet_two', None)

    if not subnet1 or not subnet2:
        raise ValueError('Collision subnets are not specified')

    collision_result = str(ipcalc.Network(subnet1).check_collision(subnet2))

    collision_object = {
        "subnet1": subnet1,
        "subnet2": subnet2,
        "collision": collision_result
    }

    readable_output = tableToMarkdown(t=collision_object, name='Collision Check')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Collision',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=collision_object,
    )


def return_subnet_info_command(args: Dict[str, Any]) -> CommandResults:

    subnet = args.get('subnet', None)

    if not subnet:
        raise ValueError('subnet not specified')

    subnet_info = str(ipcalc.Network(subnet).info())

    info_object = {
        "subnet": subnet,
        "allocation": subnet_info
    }

    readable_output = tableToMarkdown(t=info_object, name='Iana Allocation')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Allocation',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=info_object
    )


def return_subnet_binary_command(args: Dict[str, Any]) -> CommandResults:

    subnet = args.get('subnet', None)

    if not subnet:
        raise ValueError('subnet not specified')

    subnet_binary = str(ipcalc.Network(subnet).bin())

    binary_object = {
        "subnet": subnet,
        "binary": subnet_binary
    }

    readable_output = tableToMarkdown(t=binary_object, name='Subnet Binary')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Binary',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=binary_object
    )

''' MAIN FUNCTION '''


def main() -> None:

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        if demisto.command() == 'test-module':
            result = test_module()
            return_results(result)

        elif demisto.command() == 'ipcalc-return-subnet-iana-allocation':
            return_results(return_subnet_info_command(demisto.args()))

        elif demisto.command() == 'ipcalc-return-subnet-binary':
            return_results(return_subnet_binary_command(demisto.args()))

        elif demisto.command() == 'ipcalc-return-subnet-addresses':
            return_results(return_subnet_addresses_command(demisto.args()))

        elif demisto.command() == 'ipcalc-return-subnet-network':
            return_results(return_subnet_network_command(demisto.args()))

        elif demisto.command() == 'ipcalc-return-subnet-first-address':
            return_results(return_subnet_first_address_command(demisto.args()))

        elif demisto.command() == 'ipcalc-return-subnet-last-address':
            return_results(return_subnet_last_address_command(demisto.args()))

        elif demisto.command() == 'ipcalc-check-subnet-collision':
            return_results(return_check_collision_command(demisto.args()))


    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
