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

    # generate the file
    post_result = demisto.executeCommand("core-api-post", {"uri": "/indicators/batch/exportToCsv", "body": indicator_body})
    
    # Check if the command returned an error
    if not post_result or not isinstance(post_result, list) or not post_result[0]:
        return_error("Failed to execute core-api-post command. Result is empty or invalid.")
    
    first_result = post_result[0]
    
    # Check if the result is an error
    if is_error(first_result):
        return_error(f"Error in core-api-post: {get_error(first_result)}")
    
    # Extract the response
    if not isinstance(first_result, dict) or "Contents" not in first_result:
        return_error(f"Unexpected response format from core-api-post: {first_result}")
    
    contents = first_result.get("Contents")
    if not isinstance(contents, dict) or "response" not in contents:
        return_error(f"Unexpected Contents format from core-api-post: {contents}")
    
    res = contents["response"]

    # download the file and return to the war room
    get_result = demisto.executeCommand("core-api-get", {"uri": f"/indicators/csv/{res}"})
    
    # Check if the command returned an error
    if not get_result or not isinstance(get_result, list) or not get_result[0]:
        return_error("Failed to execute core-api-get command. Result is empty or invalid.")
    
    first_get_result = get_result[0]
    
    # Check if the result is an error
    if is_error(first_get_result):
        return_error(f"Error in core-api-get: {get_error(first_get_result)}")
    
    # Extract the file response
    if not isinstance(first_get_result, dict) or "Contents" not in first_get_result:
        return_error(f"Unexpected response format from core-api-get: {first_get_result}")
    
    get_contents = first_get_result.get("Contents")
    if not isinstance(get_contents, dict) or "response" not in get_contents:
        return_error(f"Unexpected Contents format from core-api-get: {get_contents}")
    
    file = get_contents["response"]
    demisto.results(fileResult(res, file))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
