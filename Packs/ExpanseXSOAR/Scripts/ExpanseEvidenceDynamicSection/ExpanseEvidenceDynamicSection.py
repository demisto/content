import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from json import JSONDecodeError


dict_stack = []


def valueToMarkdown(v):
    if v is None:
        return "*empty*"

    if isinstance(v, int) or isinstance(v, float) or isinstance(v, str):
        return f"{v}"

    if isinstance(v, list) and len(v) == 0:
        return "*empty list*"

    return None


def dsToFieldList(name, d):
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

        formatted_value = valueToMarkdown(value)
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


def convert_to_markdown(evidence):
    md_result = []
    dict_stack.append(("Evidence", evidence))

    while len(dict_stack) > 0:
        next_dict = dict_stack.pop()
        md_result.extend(dsToFieldList(next_dict[0], next_dict[1]))

    return '\n'.join(md_result)


try:
    incident = demisto.incidents()[0]
    custom_fields = incident.get('CustomFields')

    latest_evidence = custom_fields.get('expanselatestevidence', None)
    if latest_evidence is None:
        latest_evidence = "*No Latest Evidence*\n"
    else:
        latest_evidence = convert_to_markdown(json.loads(latest_evidence))

    return_outputs(readable_output=latest_evidence)

except Exception as e:
    return_error(f'Error in creating ExpanseEvidenceDynamicField: {str(e)}')
