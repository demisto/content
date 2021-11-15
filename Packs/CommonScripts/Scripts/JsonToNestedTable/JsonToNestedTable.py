from CommonServerPython import *
import demistomock as demisto


def main():
    args = demisto.args()
    value = args.get('value')
    title = args.get('title')
    headers = argToList(args.get('headers'))
    json_trasnfrom_properties = args.get('json_trasnfrom_properties')
    demisto.results(json_trasnfrom_properties)
    json_transform_args = json.loads(json_trasnfrom_properties)
    demisto.results(json_transform_args)
    markdown = tableToMarkdown(title, value, headers=headers)

    return_results(markdown)


if __name__ in ['__builtin__', 'builtins']:
    main()
