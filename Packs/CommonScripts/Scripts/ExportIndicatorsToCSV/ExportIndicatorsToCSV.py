import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    indicator_query = demisto.args().get("query")
    seen_days_arg = demisto.args().get("seenDays", "7")
    try:
        indicator_seen_days = int(seen_days_arg)
    except (ValueError, TypeError):
        indicator_seen_days = 7  # default value

    columns_arg = demisto.args().get("columns")
    if columns_arg:
        indicator_columns = [x.strip() for x in columns_arg.split(",")]
    else:
        indicator_columns = [
            "id",
            "indicator_type",
            "value",
            "score",
            "timestamp",
            "relatedIncCount",
            "sourceBrands",
            "expirationStatus",
            "expiration",
            "modified",
        ]

    # body for the indicator request
    indicator_body = {
        "all": True,
        "filter": {
            "query": indicator_query,
            "sort": [{"field": "calculatedTime", "asc": False}],
            "period": {"by": "day", "fromValue": indicator_seen_days},
        },
        "columns": indicator_columns,
    }

    # Use internalHttpRequest to make the POST to create the indicators CSV file.
    post_response = demisto.internalHttpRequest(method="POST", uri="/indicators/batch/exportToCsv", body=indicator_body)

    # Log POST response headers to see Set-Cookie
    demisto.debug(f"POST Response Status: {post_response.get('statusCode')}")
    demisto.debug(f"POST Response Headers: {json.dumps(post_response.get('headers', {}), indent=2)}")

    # Extract and log cookies from Set-Cookie header
    set_cookie_headers = post_response.get("headers", {}).get("Set-Cookie", [])
    if set_cookie_headers:
        demisto.debug(f"Cookies received from POST: {set_cookie_headers}")
    else:
        demisto.debug("No Set-Cookie headers in POST response")

    # Check if the request was successful
    if post_response.get("statusCode") not in [200, 201]:
        return_error(
            f"Failed to initiate CSV export. Status: {post_response.get('statusCode')}, Body: {post_response.get('body')}"
        )

    # Parse the response to get the file ID
    try:
        file_id = json.loads(post_response.get("body", "{}"))
    except (json.JSONDecodeError, KeyError) as e:
        return_error(f"Failed to parse POST response: {e}")

    demisto.debug(f"File ID from POST response: {file_id}")

    # Use internalHttpRequest to download the file
    get_response = demisto.internalHttpRequest(method="GET", uri=f"/indicators/csv/{file_id}")

    # Log GET request/response to verify cookies are being sent
    demisto.debug(f"GET Response Status: {get_response.get('statusCode')}")
    demisto.debug(f"GET Response Headers: {json.dumps(get_response.get('headers', {}), indent=2)}")

    # Note: The Cookie header sent in the GET request is managed internally by demisto.internalHttpRequest
    # and may not be visible in the response object, but it's automatically included
    demisto.debug("Cookies are automatically managed by internalHttpRequest between requests in the same execution")

    # Check if the download was successful
    if get_response.get("statusCode") != 200:
        return_error(f"Failed to download CSV file. Status: {get_response.get('statusCode')}, Body: {get_response.get('body')}")

    # Get the file content
    file_content = get_response.get("body", "")

    # Return the file to the war room
    demisto.results(fileResult(file_id, file_content))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
