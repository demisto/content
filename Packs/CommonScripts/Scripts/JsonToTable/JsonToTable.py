from CommonServerPython import *
import demistomock as demisto


def main():
    args = demisto.args()
    value = args.get('value')
    title = args.get('title')
    headers = argToList(args.get('headers'))
    markdown = tableToMarkdown(title, value, headers=headers)

    return_results(markdown)


if __name__ in ['__builtin__', 'builtins']:
    main()
