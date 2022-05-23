import traceback

import demistomock as demisto  # noqa: F401
import markdown  # type: ignore
from bs4 import BeautifulSoup
from CommonServerPython import *  # noqa: F401

''' MAIN FUNCTION '''


def main():
    try:
        args = demisto.args()
        input_text = args["text"]
        input_output_key = args.get("contextKey")  # maybe add a default value
        input_only_md = argToBoolean(args.get("convertOnlyMarkdown"))
        input_prettify = argToBoolean(args.get("prettifyHTML"))

        data = markdown.markdown(input_text)
        if not input_only_md:
            data = f"<!doctype html><html><head><meta charset=\"utf-8\"></head><body>{data}</body></html>"

        if input_prettify:
            soup = BeautifulSoup(data)
            data = soup.prettify()

        res = CommandResults(readable_output=data)
        if input_output_key:
            res = CommandResults(readable_output=data, outputs={input_output_key: data})
        return_results(res)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute MarkdownToHTML. Error: {str(ex)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
