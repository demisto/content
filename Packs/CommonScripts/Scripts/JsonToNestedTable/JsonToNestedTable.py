from CommonServerPython import *
import demistomock as demisto


def main():
    args = demisto.args()
    value = args.get('value')
    title = args.get('title')
    headers = argToList(args.get('headers'))
    is_auto_json_transform = args.get('is_auto_json_transform')
    json_transform_properties = args.get('json_transform_properties')
    json_transformer = None
    if json_transform_properties:
        json_transform_properties = json.loads(json_transform_properties)
        json_transformer = JsonTransformer(json_transform_properties)
    markdown = tableToMarkdown(title, value, headers=headers, json_transform=json_transformer,
                               is_auto_json_transform=is_auto_json_transform)

    return_results(markdown)

if __name__ in ['__builtin__', 'builtins']:
    main()
