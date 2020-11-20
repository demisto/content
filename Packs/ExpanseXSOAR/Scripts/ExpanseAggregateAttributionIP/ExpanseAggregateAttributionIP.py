"""ExpanseAggregateAttributionIP

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
                      source_ip_fields: List[str],
                      sightings_fields: List[str]) -> Tuple[Optional[str],
                                                            Optional[int]]:
    sightings = next((int(entry[field]) for field in sightings_fields if field in entry), 1)
    source_ip = next((entry[field] for field in source_ip_fields if field in entry), None)

    return source_ip, sightings


''' COMMAND FUNCTION '''


def aggregate_command(args: Dict[str, Any]) -> CommandResults:
    input_list = argToList(args.get('input', []))
    current_list = argToList(args.get('current', []))

    source_ip_fields = argToList(args.get('source_ip_fields', "src,src_ip"))
    sightings_fields = argToList(args.get('sightings_fields', "count"))

    internal_ip_networks = list(map(
        IPv4Network,
        argToList(args.get('internal_ip_networks', []))
    ))

    current_ips = {
        f"{d['ip']}": d
        for d in current_list if d is not None
    }

    for entry in input_list:
        if not isinstance(entry, dict):
            continue

        source_ip, sightings = deconstruct_entry(
            entry,
            source_ip_fields=source_ip_fields,
            sightings_fields=sightings_fields
        )

        if source_ip is None:
            continue

        current_state = current_ips.get(source_ip, None)
        if current_state is None:
            current_state = {
                'ip': source_ip,
                'sightings': 0,
                'internal': is_internal(internal_ip_networks, IPv4Address(source_ip))
            }
            current_ips[source_ip] = current_state

        if sightings is not None:
            current_state['sightings'] += sightings

    markdown = f'## ExpanseAggregateAttributionIP'
    outputs = list(current_ips.values())

    return CommandResults(
        readable_output=markdown,
        outputs=outputs if len(outputs) > 0 else None,
        outputs_prefix="Expanse.AttributionIP",
        outputs_key_field="ip"
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(aggregate_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ExpanseAggregateAttributionIP. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
