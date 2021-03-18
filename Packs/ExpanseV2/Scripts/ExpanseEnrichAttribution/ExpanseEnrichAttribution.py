import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from typing import Dict, Any, List, Optional
import traceback


''' COMMAND FUNCTION '''


def enrich(current_list: List[Dict[str, Any]], enrich_list: List[Dict[str, Any]], enrich_key: str,
           enrich_fields: List[str], key_field: str, outputs_prefix: str) -> CommandResults:
    for enrich_entry in enrich_list:
        key = enrich_entry.get(enrich_key, None)
        if key is None:
            continue

        for current_entry in current_list:
            current_key = current_entry[key_field].lower()
            if isinstance(key, list):
                if next((k for k in key if k.lower() == current_key), None) is None:
                    continue
            else:
                if current_key != key.lower():
                    continue

            for enrich_field in enrich_fields:
                new_enrich_field = enrich_field
                if '=' in enrich_field:
                    enrich_field, new_enrich_field = enrich_field.split('=', 1)

                if enrich_field not in enrich_entry:
                    continue

                enrich_value = enrich_entry[enrich_field]
                if isinstance(enrich_value, list) and len(enrich_value) == 1:
                    enrich_value = enrich_value[0]

                current_entry[new_enrich_field] = enrich_value

    return CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field=key_field,
        outputs=current_list if len(current_list) > 0 else None,
        readable_output=""
    )


def enrich_command(args: Dict[str, Any]) -> CommandResults:
    type_: Optional[str]
    if (type_ := args.get("type")) is not None:
        type_ = type_.lower()

    current_list = argToList(args.get('current', []))
    enrich_list = argToList(args.get('enrich', []))
    enrich_key = args.get('enrich_key', "")
    enrich_fields = argToList(args.get('enrich_fields', []))

    if type_ == "ip":
        return enrich(
            current_list,
            enrich_list,
            enrich_key,
            enrich_fields,
            key_field="ip",
            outputs_prefix="Expanse.AttributionIP")
    elif type_ == "device":
        return enrich(
            current_list,
            enrich_list,
            enrich_key,
            enrich_fields,
            key_field="serial",
            outputs_prefix="Expanse.AttributionDevice")
    elif type_ == "user":
        return enrich(
            current_list,
            enrich_list,
            enrich_key,
            enrich_fields,
            key_field="username",
            outputs_prefix="Expanse.AttributionUser")

    raise ValueError("Invalid value for type argument")


''' MAIN FUNCTION '''


def main():
    try:
        enrich_result = enrich_command(demisto.args())
        return_results(enrich_result)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ExpanseEnrichAttribution. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
