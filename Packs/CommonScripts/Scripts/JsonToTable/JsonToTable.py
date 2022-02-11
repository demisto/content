from CommonServerPython import *
import demistomock as demisto


def main():
    args = demisto.args()
    value = args.get('value')
    if isinstance(value, str):
        value = safe_load_json(value)
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


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
