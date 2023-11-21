import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re


def build_ews_query(demisto_args):
    # Regex for removing forward/replay prefixes
    p = re.compile('([\[\(] *)?(RE|FWD?) *([-:;)\]][ :;\])-]*|$)|\]+ *$', re.IGNORECASE)

    args = {}

    if demisto_args.get("from"):
        args["From"] = demisto_args.get("from")
    if demisto_args.get("subject"):
        args["Subject"] = demisto_args.get("subject")
    if demisto_args.get("attachmentName"):
        args["Attachment"] = demisto_args.get("attachmentName")
    if demisto_args.get("body"):
        args["Body"] = demisto_args.get("body")

    stripSubject = True if demisto_args.get("stripSubject").lower() == "true" else False
    escapeColons = True if demisto_args.get("escapeColons").lower() == "true" else False
    if stripSubject and args.get("Subject"):
        # Recursively remove the regex matches only from the beginning of the string
        match_string = args["Subject"]
        location_match = p.match(match_string)
        location = location_match.start() if location_match else -1

        while location == 0 and match_string:
            match_string = p.sub("", match_string, 1)
            location_match = p.match(match_string)
            location = location_match.start() if location_match else -1

        args["Subject"] = match_string

    if escapeColons:
        query = " AND ".join(r'{0}\\:"{1}"'.format(key, value) for (key, value) in args.items())

    else:
        query = " AND ".join('{0}:"{1}"'.format(key, value) for (key, value) in args.items())

    search_last_week = True if demisto_args.get("searchThisWeek").lower() == "true" else False
    if search_last_week:
        query = query + ' AND Received:"this week"'

    return CommandResults(
        content_format=formats["json"],
        raw_response={"EWS": {"Query": query or ' '}},
        entry_type=entryTypes["note"],
        readable_output=query or ' ',
        outputs={"EWS": {"Query": query or ' '}}
    )


def main():  # pragma: no cover
    args = demisto.args()
    try:
        return_results(build_ews_query(args))
    except Exception as e:
        err_msg = f'Encountered an error while running the script: [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
