import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json


def main():
    try:
        args = demisto.args()
        query = args["query"]
        res = demisto.executeCommand(
        "core-generic-api-call",
            {
                "path": "/xql/start_xql_query",
                "method": "POST",
                "data": json.dumps({"request_data":{"query": query}}),
            },
        )

        if is_error(res):
            return_error(res)

        else:
            context = res[0]["EntryContext"]
            data = context.get("data")
            data = json.loads(data)
            reply = data.get("reply")

            return_results(
                CommandResults(
                    outputs_prefix="Core.XQLQuery",
                    outputs={"queryId": reply},
                    readable_output=f"XQL query started successfully. Query ID: {reply}",
                )
            )
    except Exception as ex:
        return_error(f"Failed to execute StartXQLQuery. Error:\n{str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()