import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def export_using_core_api(indicator_body: dict) -> tuple:
    """
    Export indicators using core-rest-api commands.
    This method works in most environments but may have issues in load-balanced setups.

    Args:
        indicator_body: The request body for the indicator export

    Returns:
        tuple: (file_id, file_content)
    """
    # Generate the file using core-api-post
    try:
        post_result = demisto.executeCommand("core-api-post", {"uri": "/indicators/batch/exportToCsv", "body": indicator_body})
        
        if not post_result or not isinstance(post_result, list) or len(post_result) == 0:
            return_error("Failed to initiate CSV export: Empty response from core-api-post")
        
        post_response = post_result[0]
        
        # Check for errors in the command response
        if is_error(post_response):
            error_message = get_error(post_response)
            return_error(f"Failed to initiate CSV export: {error_message}")
        
        # Extract the file ID from the response
        file_id = post_response.get("Contents", {}).get("response")
        
        if not file_id:
            return_error(f"Failed to get file ID from POST response. Response: {post_response}")
            
    except Exception as e:
        return_error(f"Failed to initiate CSV export: {str(e)}")

    # Download the file using core-api-get
    try:
        get_result = demisto.executeCommand("core-api-get", {"uri": f"/indicators/csv/{file_id}"})
        
        if not get_result or not isinstance(get_result, list) or len(get_result) == 0:
            return_error(f"Failed to download CSV file: Empty response from core-api-get for file ID: {file_id}")
        
        get_response = get_result[0]
        
        # Check for errors in the command response
        if is_error(get_response):
            error_message = get_error(get_response)
            return_error(f"Failed to download CSV file: {error_message}")
        
        # Extract the file content from the response
        file_content = get_response.get("Contents", {}).get("response")
        
        if file_content is None:
            return_error(f"Failed to get file content from GET response. Response: {get_response}")
            
    except Exception as e:
        return_error(f"Failed to download CSV file: {str(e)}")

    return file_id, file_content


def export_using_internal_http(indicator_body: dict) -> tuple:
    """
    Export indicators using internalHttpRequest.
    This method works better in load-balanced environments but has limited permissions.
    May fail when running from playbooks with permission errors.

    Args:
        indicator_body: The request body for the indicator export

    Returns:
        tuple: (file_id, file_content)
    """
    # Use internalHttpRequest to make the POST to create the indicators CSV file.
    post_response = demisto.internalHttpRequest(method="POST", uri="/indicators/batch/exportToCsv", body=indicator_body)

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

    # Use internalHttpRequest to download the file
    get_response = demisto.internalHttpRequest(method="GET", uri=f"/indicators/csv/{file_id}")

    # Check if the download was successful
    if get_response.get("statusCode") != 200:
        return_error(f"Failed to download CSV file. Status: {get_response.get('statusCode')}, Body: {get_response.get('body')}")

    # Get the file content
    file_content = get_response.get("body", "")
    return file_id, file_content


def main():
    indicator_query = demisto.args().get("query")
    seen_days = arg_to_number(demisto.args().get("seenDays", "7"))
    columns_arg = demisto.args().get("columns")
    use_internal_http = argToBoolean(demisto.args().get("use_internal_http_request", False))

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
            "period": {"by": "day", "fromValue": seen_days},
        },
        "columns": indicator_columns,
    }

    # Choose the export method based on the argument
    if use_internal_http:
        demisto.debug("ExportIndicatorsToCSV: Using internalHttpRequest method")
        file_id, file_content = export_using_internal_http(indicator_body)
    else:
        demisto.debug("ExportIndicatorsToCSV: Using core-rest-api method")
        file_id, file_content = export_using_core_api(indicator_body)

    demisto.results(fileResult(file_id, file_content))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
