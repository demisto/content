import demistomock as demisto
from CommonServerPython import *
from markdownify import markdownify as md


def markdownify_command(args):
    html = args.get('html')
    markdown = md(html)
    outputs = {
        "Markdownify": {
            "Original": str(html),
            "Result": str(markdown)
        }
    }
    print(repr(markdown))

    return (
        markdown,
        outputs,
        markdown
    )


def main():
    try:
        return_outputs(*markdownify_command(demisto.args()))
    except Exception as expt:
        return_error(f'Failed to execute Markdownify script. Error: {str(expt)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
