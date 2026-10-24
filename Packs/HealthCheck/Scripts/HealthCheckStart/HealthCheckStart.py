import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import time


def get_current_unix_ms() -> int:
    """Return the current time as a Unix timestamp in milliseconds."""
    return int(time.time() * 1000)


def get_issue_id_by_external_id(external_id: str) -> int | None:
    body = {
        "request_data": {
            "filters": [
                {
                    "field": "external_id",
                    "operator": "in",
                    "value": [external_id],
                }
            ]
        }
    }

    demisto.debug("get_issue_id_by_external_id: waiting 2 seconds for issue to be indexed")
    time.sleep(10)

    result = demisto.executeCommand(
        "core-api-post",
        {
            "uri": "/public_api/v1/issue/search",
            "body": body,
        },
    )
    if is_error(result):
        demisto.debug(f"get_issue_id_by_external_id error: {get_error(result)}")
        return None

    try:
        data = result[0]["Contents"]["response"]["reply"]["DATA"]
        if data:
            return data[0].get("id")
    except (KeyError, IndexError, TypeError) as e:
        demisto.debug(f"get_issue_id_by_external_id parse error: {e}")

    return None


def main() -> None:
    try:
        body = {
            "request_data": {
                "issue": {
                    "name": "System Diagnostics and Healthcheck Report",
                    "description": "Collecting local information to assest the system healthcheck",
                    "observation_time": get_current_unix_ms(),
                    "issue_domain": "Health",
                    "category": "Health Check Report",
                    "severity": "HIGH",
                }
            }
        }

        result = demisto.executeCommand(
            "core-api-post",
            {
                "uri": "/public_api/v1/issue",
                "body": json.dumps(body),
            },
        )

        if is_error(result):
            return_error(f"Failed to create issue: {get_error(result)}")
            return

        try:
            response = result[0]["Contents"]["response"]
            reply = response.get("reply", response)
        except (KeyError, IndexError, TypeError) as e:
            return_error(f"Unexpected response structure from /public_api/v1/issue: {e}")
            return

        external_id = reply.get("external_id") if isinstance(reply, dict) else None
        server_url = demisto.demistoUrls().get("server", "")

        if external_id:
            issue_id = get_issue_id_by_external_id(external_id)
            if issue_id:
                issue_url = f"{server_url}/issue-view/{issue_id}"
                message = f"HealthCheck issue created successfully &rarr; [Open Issue Here #{issue_id}]({issue_url})"
            else:
                message = "HealthCheck issue created."
        else:
            message = "HealthCheck issue created successfully."

        demisto.results(
            {
                "Type": entryTypes["note"],
                "ContentsFormat": formats["markdown"],
                "Contents": message,
            }
        )

    except Exception as e:
        return_error(f"HealthCheckStart failed: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
