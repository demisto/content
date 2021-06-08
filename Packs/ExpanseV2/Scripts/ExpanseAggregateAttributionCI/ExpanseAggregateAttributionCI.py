"""ExpanseAggregateAttributionCI

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from typing import Dict, List, Any, Tuple, Optional
from ipaddress import IPv4Address, IPv4Network
import traceback


''' STANDALONE FUNCTION '''


def deconstruct_entry(ServiceNowCMDBContext: Dict[str, Any]) -> Tuple[Optional[str],
                                                            Optional[str],
                                                            Optional[str],
                                                            Optional[int],
                                                            Optional[int],
                                                            Optional[int]]:
    """
    deconstruct_entry
    Extracts device relevant fields from a log entry.

    :type ServiceNowCMDBContext: ``Dict[str, Any]``
    :param ServiceNowCMDBContext: ServiceNowCMDB.Record

    :return: Tuple where the first element is the name or None, the second element is the
        sys class name or None, the third element is the sys_id or None, the fourth element is the
        asset display value or None, the fifth element is the asset link or None, and the final element
        is the asset value or None.
    :rtype: ``Tuple[Optional[str], Optional[str], Optional[str], Optional[int], Optional[str], Optional[str]]``
    """
    name = ServiceNowCMDBContext.get("name")
    sys_class_name = ServiceNowCMDBContext.get("sys_class_name")
    sys_id = ServiceNowCMDBContext.get("sys_id")
    asset_display_value = ServiceNowCMDBContext.get("asset", {}).get("display_value")
    asset_link = ServiceNowCMDBContext.get("asset", {}).get("link")
    asset_value = ServiceNowCMDBContext.get("asset", {}).get("value")


    return name,\
           sys_class_name,\
           sys_id,\
           asset_display_value,\
           asset_link,\
           asset_value


''' COMMAND FUNCTION '''


def aggregate_command(args: Dict[str, Any]) -> CommandResults:
    input_list = argToList(args.get('input', []))
    current_list = argToList(args.get('current', []))

    current_sys_ids = {
        f"{c.get('sys_id', 'Unknown')}": c
        for c in current_list if c is not None
    }

    for entry in input_list:
        if not isinstance(entry, dict):
            continue

        name, sys_class_name, sys_id, asset_display_value, asset_link, asset_value = deconstruct_entry(entry)

        current_state = current_sys_ids.get(sys_id, None)
        if current_state is None:
            current_state = {
                'name': name,
                'sys_id': sys_id,
                'sys_class_name': sys_class_name,
                'asset_display_value': asset_display_value,
                'asset_link': asset_link,
                'asset_value': asset_value,
            }
            current_sys_ids[sys_id] = current_state

    markdown = '## ExpanseAggregateAttributionCI'
    outputs = list(current_sys_ids.values())

    return CommandResults(
        readable_output=markdown,
        outputs=outputs or None,
        outputs_prefix="Expanse.AttributionCI",
        outputs_key_field=["name", "sys_id", "sys_class_name"]
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(aggregate_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ExpanseAggregateAttributionCI. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
