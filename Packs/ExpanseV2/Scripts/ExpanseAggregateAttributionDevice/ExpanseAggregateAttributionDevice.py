"""ExpanseAggregateAttributionDevice

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from typing import Dict, List, Any, Tuple
from ipaddress import IPv4Address, IPv4Network
import traceback


''' STANDALONE FUNCTION '''


def is_internal(net_list: List[IPv4Network], ip: IPv4Address) -> bool:
    if net_list is None or len(net_list) == 0:
        return ip.is_private

    result = next((inetwork for inetwork in net_list if ip in inetwork), None)
    return result is not None


def deconstruct_entry(entry: Dict[str, str],
                      serial_fields: List[str],
                      vsys_fields: List[str],
                      sightings_fields: List[str],
                      source_ip_fields: List[str]) -> Tuple[Optional[str],
                                                            Optional[str],
                                                            Optional[str],
                                                            Optional[int]]:
    serial = next((entry[field] for field in serial_fields if field in entry), None)
    vsys = next((entry[field] for field in vsys_fields if field in entry), None)
    sightings = next((int(entry[field]) for field in sightings_fields if field in entry), 1)
    source_ip = next((entry[field] for field in source_ip_fields if field in entry), None)

    return serial, vsys, source_ip, sightings


''' COMMAND FUNCTION '''


def aggregate_command(args: Dict[str, Any]) -> CommandResults:
    input_list = argToList(args.get('input', []))
    current_list = argToList(args.get('current', []))

    serial_fields = argToList(args.get('serial_fields', "serial_number,serial,log_source_id"))
    vsys_fields = argToList(args.get('vsys_fields', "vsys"))
    sightings_fields = argToList(args.get('sightings_fields', "count"))
    source_ip_fields = argToList(args.get('source_ip_fields', "src,src_ip"))

    internal_ip_networks = list(map(
        IPv4Network,
        argToList(args.get('internal_ip_networks', []))
    ))

    current_devices = {
        f"{d['serial']}::{d['vsys']}": d
        for d in current_list if d is not None
    }

    for entry in input_list:
        if not isinstance(entry, dict):
            continue

        serial, vsys, source_ip, sightings = deconstruct_entry(
            entry,
            serial_fields=serial_fields,
            vsys_fields=vsys_fields,
            sightings_fields=sightings_fields,
            source_ip_fields=source_ip_fields
        )

        if serial is None:
            continue
        if vsys is None:
            vsys = ""

        device_key = f"{serial}::{vsys}"
        current_state = current_devices.get(device_key, None)
        if current_state is None:
            current_state = {
                'serial': serial,
                'vsys': vsys,
                'sightings': 0,
                'exposing_service': False,
                'device-group': None,
                'expanse-tag': None,
            }
            current_devices[device_key] = current_state

        if current_state['exposing_service'] is False and source_ip is not None:
            current_state['exposing_service'] = not is_internal(
                internal_ip_networks,
                IPv4Address(source_ip)
            )

        if sightings is not None:
            current_state['sightings'] += sightings

    markdown = '## ExpanseAggregateAttributionDevice'
    outputs = list(current_devices.values())

    return CommandResults(
        readable_output=markdown,
        outputs=outputs if len(outputs) > 0 else None,
        outputs_prefix="Expanse.AttributionDevice",
        outputs_key_field=["serial", "vsys"]
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(aggregate_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ExpanseAggregateAttributionDevice. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
