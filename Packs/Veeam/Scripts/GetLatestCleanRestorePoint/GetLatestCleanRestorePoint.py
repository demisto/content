import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def find_latest_restore(data: list) -> dict:
    for item in data:
        malwareStatus = item.get("malwareStatus")

        if malwareStatus == "Clean":
            return item

    return {"id": "", "backupId": ""}


def main():
    try:
        args = demisto.args()
        data_arg = args.get("data", "")
        data: list[dict] = []

        if isinstance(data_arg, dict):
            data.append(data_arg)
        elif isinstance(data_arg, list):
            data.extend(data_arg)

        result: dict = find_latest_restore(data)

        command_results = CommandResults(outputs_prefix="Veeam.LatestCleanRestorePoint", outputs=result)
        return_results(command_results)

    except Exception as e:
        return_error(str(e))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
