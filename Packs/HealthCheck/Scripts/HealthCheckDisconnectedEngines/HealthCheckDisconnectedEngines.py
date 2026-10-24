import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


def get_engines() -> list[dict]:
    result = demisto.executeCommand("core-api-get", {"uri": "/xsoar/public/v1/engines/get"})

    if isError(result[0]):
        raise DemistoException(f"core-api-get failed: {get_error(result)}")

    response = result[0].get("Contents", {}).get("response", {})
    return response.get("engines") or []


def main():
    try:
        # 1. Fetch script arguments and evaluate 'RunInPlaybook'
        args = demisto.args()
        run_in_playbook = argToBoolean(args.get("RunInPlaybook", False))

        # 2. Collect core data
        engines = get_engines()
        disconnected = [e for e in engines if not e.get("connected", False)]

        # 3. Branching execution path
        if run_in_playbook:
            # Playbook Path: Save metrics and update the incident
            readable_output = f"Found {len(disconnected)} disconnected engines." if disconnected else "All engines are connected."

            # Map to your target incident field (verify the exact machine name in XSIAM)
            demisto.executeCommand("setIncident", {"healthcheckdisconnectedenginescount": len(disconnected)})

            return_results(CommandResults(readable_output=readable_output))

        else:
            # Widget Path: Generate JSON for the dashboard UI chart
            if not disconnected:
                chart_data = [{"name": "All Connected", "data": [0], "groups": []}]
            else:
                chart_data = [
                    {"name": e.get("name") or e.get("host") or "Unknown", "data": [1], "groups": []} for e in disconnected
                ]

            return_results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(chart_data)})

    except Exception as exc:
        return_error(f"DisconnectedEnginesWidget failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
