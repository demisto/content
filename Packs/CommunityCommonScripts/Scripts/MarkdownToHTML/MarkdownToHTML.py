import demistomock as demisto  # noqa: F401
import markdown  # type: ignore
from bs4 import BeautifulSoup
from CommonServerPython import *  # noqa: F401

''' MAIN FUNCTION '''


def main():
    try:
        args = demisto.args()
        input_text = args["text"]
        input_only_md = argToBoolean(args.get("convertOnlyMarkdown", True))
        input_prettify = argToBoolean(args.get("prettifyHTML", False))

        data = markdown.markdown(input_text)  # converts markdown text to HTML
        if not input_only_md:
            # Add to the converted markdown the full HTML structure
            data = f"<!doctype html><html><head><meta charset=\"utf-8\"></head><body>{data}</body></html>"

        if input_prettify:
            # Format the resulted HTML to a unicode string, with a separate line for each tag and each string.
            soup = BeautifulSoup(data)
            data = soup.prettify()

        # Output the resulted HTML to the context
        res = CommandResults(
            outputs_prefix='MarkdownToHTML',
            outputs_key_field='',
            readable_output=data,
            outputs={'HTML': data})

        return_results(res)

    except Exception as ex:
        return_error(f'Failed to execute MarkdownToHTML. Error: {str(ex)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
