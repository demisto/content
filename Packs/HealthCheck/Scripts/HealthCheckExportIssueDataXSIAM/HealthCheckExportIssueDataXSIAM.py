import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from datetime import datetime, timedelta


def main():
    try:
        ctx = demisto.context()
        incident = demisto.incidents()[0]

        main = {"incident": incident, "ctx": ctx, "cases": {}}

        # Get case creation amounts
        # Calculate exact epoch timestamps (in milliseconds) as required by the XSIAM API
        now = datetime.utcnow()
        daily_ts = int((now - timedelta(days=1)).timestamp() * 1000)
        weekly_ts = int((now - timedelta(days=7)).timestamp() * 1000)
        monthly_ts = int((now - timedelta(days=30)).timestamp() * 1000)

        def build_api_args(timestamp):
            """Generates the correct XSIAM get_incidents REST API payload."""
            return {
                "uri": "/public_api/v1/incidents/get_incidents",
                "body": {
                    "request_data": {
                        "search_from": 0,
                        "search_to": 1,
                        "filters": [{"field": "creation_time", "operator": "gte", "value": timestamp}],
                    }
                },
            }

        # core-api-post interacts natively with XSIAM's REST API
        daily_res = demisto.executeCommand("core-api-post", build_api_args(daily_ts))
        weekly_res = demisto.executeCommand("core-api-post", build_api_args(weekly_ts))
        monthly_res = demisto.executeCommand("core-api-post", build_api_args(monthly_ts))

        def extract_count(res):
            """Safely extracts the 'total_count' property from the REST API reply."""
            if isinstance(res, list) and len(res) > 0:
                # Catch failures so the script doesn't crash
                if res[0].get("Type") == 4:
                    demisto.debug(f"API Error: {res[0].get('Contents')}")
                    return 0

                contents = res[0].get("Contents", {})
                if isinstance(contents, dict):
                    # core-api-post sometimes nests the JSON in a 'response' wrapper
                    payload = contents.get("response", contents)
                    reply = payload.get("reply", {})
                    if isinstance(reply, dict) and "total_count" in reply:
                        return reply.get("total_count", 0)
            return 0

        # Add metrics into main dict
        main["cases"] = {
            "daily": extract_count(daily_res),
            "weekly": extract_count(weekly_res),
            "monthly": extract_count(monthly_res),
        }

        variables = json.dumps(main).encode("utf-8")
        file_entry = fileResult(filename="HealthCheckDataExport.txt", data=variables)
        return_results(file_entry)

    except Exception as e:
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
