import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


def main():
    args = demisto.args()

    value = args.get('value')
    if from_str_value := get_value_from_str(value):
        value = from_str_value

    title = args.get('title')
    headers = argToList(args.get('headers'))
    is_auto_json_transform = argToBoolean(args.get('is_auto_json_transform', False))
    json_transform_properties = args.get('json_transform_properties')
    json_transformers = {}
    if json_transform_properties:
        json_transform_properties = safe_load_json(json_transform_properties)
        for header_key, values in json_transform_properties.items():
            json_transformers[header_key] = JsonTransformer(**values)
    markdown = tableToMarkdown(title, value, headers=headers, json_transform_mapping=json_transformers,
                               is_auto_json_transform=is_auto_json_transform)
    return_results(markdown)


def get_value_from_str(value: Any):
    """
    Load Json from value in case of string value
    """
    str_value = None
    if isinstance(value, str):
        str_value = value

    # in case of str value when using this automation as transformer - the value will be in list as [str]
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], str):
        str_value = value[0]
    try:
        return json.loads(str_value) if str_value else None
    except json.JSONDecodeError:
        return str_value


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
