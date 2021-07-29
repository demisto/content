from CommonServerPython import *
import demistomock as demisto


def main():
    args = demisto.args()
    value = args.get('value')
    title = args.get('title')
    markdown = tableToMarkdown(title, value)

    return_results(markdown)


if __name__ in ['__builtin__', 'builtins']:
    main()
