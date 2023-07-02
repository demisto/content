import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()

    try:
        res = demisto.executeCommand("ConvertTableToHTML", {"table": args.get("table"), "title": args.get("title")})

        if is_error(res):
            raise DemistoException(f'Failed to create compliance report: {str(get_error(res))}')

        html = res[0]["EntryContext"]["HTMLTable"]

        body = f"""
        Hello,

        Please see below the details for the compliance report from Prisma Cloud Compute

        {html}

        - DBot
        """

        res = demisto.executeCommand("send-mail", {"to": args.get("to"), "subject": "IMPORTANT: Prisma Cloud "
                                                                                    "Compute Compliance", "body": body})

        if is_error(res):
            raise DemistoException(f'Failed to create compliance report: {str(get_error(res))}')

        demisto.results(res)
        return_results(CommandResults(
            readable_output=res[0]['Contents']
        ))

    except Exception as e:
        return_error(e)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
