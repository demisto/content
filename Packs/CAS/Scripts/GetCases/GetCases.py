import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


def main():
    try:
        args = demisto.args()
        res = demisto.executeCommand(
        "core-generic-api-call",
            {
                "path": "/api/webapp/get_data",
                "method": "POST",
                "data": json.dumps({'type': 'grid', 'table_name': 'CASE_MANAGER_TABLE', 'filter_data': {'sort': [{'FIELD': 'LAST_UPDATE_TIME', 'ORDER': 'DESC'}], 'paging': {'from': 0, 'to': 100}, 'filter': {}}, 'jsons': [], 'onDemandFields': []})
            },
        )

        if is_error(res):
            return_error(res)

        else:
            context = res[0]["EntryContext"]
            data = context.get("data")
            data = json.loads(data)
            reply = data.get("reply")
            data = reply.get("DATA")

            return_results(
                CommandResults(
                    outputs_prefix="Core.Case",
                    outputs=data,
                    readable_output=f"Cases {data}",
                    raw_response=data,
                )
            )
    except Exception as ex:
        return_error(f"Failed to execute GetCases. Error:\n{str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
