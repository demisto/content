import demistomock as demisto
from CommonServerPython import *
from markdownify import markdownify as md


def markdownify_command():
    args = demisto.args()
    html = args.get('html')
    markdown = md(html)
    result = {
            "Original": str(html),
            "Result": str(markdown)
        }
    outputs = {
        "Markdownify(val.Original == obj.Original)": result
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': result,
        'HumanReadable': markdown,
        'EntryContext': outputs
    })


def main():
    try:
        markdownify_command()
    except Exception as expt:
        return_error(f'Failed to execute Markdownify script. Error: {str(expt)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
