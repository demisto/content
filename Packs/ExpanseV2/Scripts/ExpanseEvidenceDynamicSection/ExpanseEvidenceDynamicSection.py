import demistomock as demisto  # noqa
from CommonServerPython import *  # noqa

import json
import traceback
from json import JSONDecodeError
from typing import Dict, Any, Tuple, List, Optional


''' STANDALONE FUNCTION '''


def value_to_markdown(v: Any) -> Optional[str]:
    if v is None:
        return "*empty*"

    if isinstance(v, int) or isinstance(v, float) or isinstance(v, str):
        return f"{v}"

    if isinstance(v, list) and len(v) == 0:
        return "*empty list*"

    return None


def ds_to_field_list(name: str, d: Dict[str, Any], dict_stack: List[Tuple[str, Dict[str, Any]]]) -> List[str]:
    if isinstance(d, dict):
        fields = d.items()
    elif isinstance(d, list):
        if len(d) == 0:
            fields = []
        elif isinstance(d[0], dict) and 'name' in d[0] and len(d[0]) == 2:
            second_key = next((k for k in list(d[0].keys()) if k != 'name'))
            fields = [(e.pop('name'), e[second_key]) for e in d]
        else:
            fields = [(idx, v) for idx, v in enumerate(d)]

    else:
        return [
            f"### {name}",
            "*Unsupported data structure*"
        ]

    md_result = [
        f"### {name}",
        "|Field|Value|",
        "|---|---|"
    ]

    for field_name, value in fields:
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except JSONDecodeError:
                pass

        formatted_value = value_to_markdown(value)
        if formatted_value is None:
            subsect_name = f"{name} / {field_name}"
            dict_stack.insert(0, (
                subsect_name,
                value
            ))
            formatted_value = f"See below, *{subsect_name}*"

        md_result.append("|{}|{}|".format(
            field_name,
            formatted_value
        ))

    return md_result


def convert_to_markdown(evidence: Dict[str, Any]) -> str:
    md_result = []
    dict_stack: List[Tuple[str, Dict[str, Any]]] = [("Evidence", evidence)]

    while len(dict_stack) > 0:
        next_dict = dict_stack.pop()
        md_result.extend(ds_to_field_list(next_dict[0], next_dict[1], dict_stack))

    return '\n'.join(md_result)


''' COMMAND FUNCTION '''


def evidence_dynamic_section(args: Dict[str, Any]) -> CommandResults:
    incident = demisto.incident()
    custom_fields = incident.get('CustomFields', {})

    latest_evidence = custom_fields.get('expanselatestevidence', None)
    if latest_evidence is None:
        latest_evidence = "*No Latest Evidence*\n"
    else:
        latest_evidence = convert_to_markdown(json.loads(latest_evidence))

    return CommandResults(
        readable_output=latest_evidence
    )


''' MAIN FUNCTION '''


def main():
    try:
        result = evidence_dynamic_section(demisto.args())
        return_results(result)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ExpanseEvidenceDynamicSection. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
