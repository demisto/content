import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

RELATED_INC_COUNT_THRESHOLD = 500


def build_body(query: str = "") -> dict:
    """Build the request body used to search indicators."""
    return {
        "page": 0,
        "size": 10,
        "query": query,
        "sort": [{"field": "relatedIncCount", "asc": False}],
        "period": {"by": "day", "fromValue": 90},
    }


def main(args: dict) -> CommandResults:
    incident = demisto.incidents()[0]

    if is_demisto_version_ge("8.0.0"):
        # XSOAR 8 / XSIAM
        uri = "xsoar/public/v1/indicators/search"
        body = build_body()
    else:
        # XSOAR 6 — multi-tenant requires account-prefixed URI and query
        account_name = incident.get("account", "")
        uri = f"acc_{account_name}/indicators/search" if account_name else "indicators/search"
        body = build_body(f"account:{account_name}" if account_name else "")

    indicator_res = execute_command("core-api-post", {"uri": uri, "body": body})

    # `execute_command` returns a list in multi-tenant environments, a dict otherwise.
    if isinstance(indicator_res, list):
        indicator_res = indicator_res[0] if indicator_res else {}

    indicators = indicator_res.get("response", {}).get("iocObjects", [])

    res = []
    for indicator in indicators:
        if indicator.get("relatedIncCount", 0) > RELATED_INC_COUNT_THRESHOLD:
            res.append(
                {
                    "category": "Indicators",
                    "severity": "Low",
                    "description": f'The indicator: "{indicator["value"]}" was found {indicator["relatedIncCount"]} times',
                    "resolution": "You may consider adding it to the exclusion list",
                }
            )

    return CommandResults(
        readable_output="HealthCheckCommonIndicators Done",
        outputs_prefix="HealthCheck.ActionableItems",
        outputs=res,
    )


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    return_results(main(demisto.args()))
