import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json


def main():
    try:
        args = demisto.args()
        res = demisto.executeCommand(
        "core-generic-api-call",
            {
                "path": "/get_data",
                "method": "POST",
                "data": json.dumps({
        "type": "grid",
        "table_name": "COVERAGE",
        "filter_data": {
    "sort": [],
    "filter": {},
    "free_text": "",
    "visible_columns": None,
    "locked": {},
    "paging": {
        "from": 0,
        "to": 100
    }
} ,
        "jsons": [],
        "onDemandFields": None,
    }),
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
                    outputs_prefix="Core.Coverage.Asset",
                    outputs=reply,
                    readable_output=f"Asset Coverage {reply}",
                )
            )
    except Exception as ex:
        return_error(f"Failed to execute StartXQLQuery. Error:\n{str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()