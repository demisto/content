import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import time
import re

# Constants
MAX_RETRY_ITERATIONS = 10
# Maps each dashboard option (as passed via the argument) to the number of
# Custom XQL widgets it contains. Used to validate that all widgets have run.
DASHBOARD_WIDGET_COUNT: dict[str, int] = {
    "Ingestion/Integration": 10,
    "Issues/Cases": 3,
    "Agent and Asset": 7,
}
RETRY_INTERVAL_SECONDS = 10
QUERY_TEMPLATE = """dataset = xql_query_center_history
| filter xql_query_source = "dashboard"
| dedup xql_query_source_name
| filter xql_query contains "Healthcheck\""""


def extract_widget_name(source_name: str, widget_name_regex: str) -> str:
    """Extract widget name from source_name using regex."""
    # print(f">>> extract_widget_name: Extracting from: {source_name}")

    match = re.search(widget_name_regex, source_name)

    if match:
        widget_name = match.group(1)
        # print(f">>> extract_widget_name: Found widget name: {widget_name}")
        return widget_name

    # print(">>> extract_widget_name: No match found, using source_name as-is")
    return source_name


def execute_xql_query(query, max_polls=30):
    """Execute XQL query and wait for results."""
    # print(">>> Step 2: Executing XQL query")

    # Start query
    start_body = {
        "request_data": {
            "query": query,
            "timeframe": {"relativeTime": 3600000},  # 60 minutes
        }
    }

    result = demisto.executeCommand(
        "core-api-post",
        {"uri": "/public_api/v1/xql/start_xql_query", "body": json.dumps(start_body)},
    )

    if is_error(result):
        raise ValueError(f"Failed to start query: {get_error(result)}")

    execution_id = result[0]["Contents"]["response"]["reply"]
    # print(f">>> Query started: {execution_id}")

    # Poll for results
    poll_body = {
        "request_data": {
            "query_id": execution_id,
            "pending_flag": True,
            "limit": 1000,
            "format": "json",
        }
    }

    for _attempt in range(max_polls):
        # print(f">>> Polling attempt {attempt + 1}/{max_polls}")

        result = demisto.executeCommand(
            "core-api-post",
            {
                "uri": "/public_api/v1/xql/get_query_results",
                "body": json.dumps(poll_body),
            },
        )

        if is_error(result):
            raise ValueError(f"Failed to get results: {get_error(result)}")

        reply = result[0]["Contents"]["response"]["reply"]

        if reply["status"] == "SUCCESS":
            demisto.debug(">>> Query completed")
            return reply["results"]["data"]
        elif reply["status"] == "FAILED":
            raise ValueError("Query failed")

        time.sleep(3)  # pylint: disable=E9003

    raise TimeoutError("Query timeout")


def fetch_execution_results(execution_id):
    """Fetch results for a specific execution_id."""
    # print(f">>> Fetching results for: {execution_id}")

    poll_body = {
        "request_data": {
            "query_id": execution_id,
            "pending_flag": False,
            "limit": 10000,
            "format": "json",
        }
    }

    result = demisto.executeCommand(
        "core-api-post",
        {"uri": "/public_api/v1/xql/get_query_results", "body": json.dumps(poll_body)},
    )

    if is_error(result):
        # print(f">>> Error fetching {execution_id}")
        return []

    reply = result[0]["Contents"]["response"]["reply"]

    if reply["status"] == "SUCCESS":
        results = reply["results"]["data"]
        # print(f">>> Got {len(results)} results")
        return results

    # print(f">>> Status: {reply['status']}")
    return []


def create_html_file(markdown_content):
    """Convert markdown to HTML and create file in War Room."""
    # print(">>> create_html_file: Creating HTML file output")

    html_result = demisto.executeCommand("mdToHtml", {"text": markdown_content})

    if not is_error(html_result):
        html_content = html_result[0]["Contents"]

        # Create HTML file entry
        file_entry = fileResult(
            filename="HealthCheckCollect_Results.html",
            data=html_content,
            file_type=entryTypes["entryInfoFile"],
        )
        demisto.results(file_entry)
        # print(">>> create_html_file: HTML file created in War Room")
    else:
        demisto.debug(">>> create_html_file: Error creating HTML")


def query_center_history_with_retry(expected_results_count: int):
    """Query query center history with retry logic until expected results are found."""
    demisto.debug(f">>> query_center_history_with_retry: Expecting {expected_results_count} results")

    query = QUERY_TEMPLATE

    for iteration in range(1, MAX_RETRY_ITERATIONS + 1):
        # print(
        #     f">>> Iteration {iteration}/{MAX_RETRY_ITERATIONS}: Querying query center history"
        # )

        query_history_results = execute_xql_query(query)

        if not query_history_results:
            demisto.debug(f">>> Iteration {iteration}: No results found")
            if iteration < MAX_RETRY_ITERATIONS:
                # print(f">>> Waiting {RETRY_INTERVAL_SECONDS} seconds before retry...")
                time.sleep(RETRY_INTERVAL_SECONDS)  # pylint: disable=E9003
                continue
            else:
                demisto.debug(">>> Max iterations reached with no results")
                return []

        results_count = len(query_history_results)
        # print(
        #     f">>> Iteration {iteration}: Found {results_count} results (expected: {expected_results_count})"
        # )

        if results_count >= expected_results_count:
            demisto.debug(f">>> Validation SUCCESS: Got {results_count} results")
            return query_history_results
        else:
            demisto.debug(f">>> Validation FAILED: Missing {expected_results_count - results_count} results")
            if iteration < MAX_RETRY_ITERATIONS:
                # print(f">>> Waiting {RETRY_INTERVAL_SECONDS} seconds before retry...")
                time.sleep(RETRY_INTERVAL_SECONDS)  # pylint: disable=E9003
            else:
                demisto.debug(f">>> Max iterations reached - returning {results_count} results")
                return query_history_results

    return []


def main():
    """Main function."""
    try:
        # print(">>> ========== HealthCheckCollect Starting ==========")

        # Read dashboard_name argument, resolve expected widget count, and build regex
        dashboard_name = demisto.args().get("dashboard_name", "")
        if not dashboard_name:
            return_error("Missing required argument: dashboard_name")
            return
        expected_results_count = DASHBOARD_WIDGET_COUNT.get(dashboard_name)
        if expected_results_count is None:
            return_error(
                f"Unknown dashboard_name '{dashboard_name}'. " f"Valid options: {', '.join(DASHBOARD_WIDGET_COUNT.keys())}"
            )
            return
        widget_name_regex = rf"{re.escape(dashboard_name)} - (.*?) xql_\d+"

        # Step 1: Query query center history with validation and retry
        # print(">>> Step 1: Querying query center history with validation")
        query_history_results = query_center_history_with_retry(expected_results_count)

        if not query_history_results:
            demisto.debug(">>> No dashboard queries found")
            return_results(CommandResults(readable_output="No dashboard queries found in the last 60 minutes."))
            return

        # print(
        #     f">>> Step 3: Processing {len(query_history_results)} query history records"
        # )

        # Step 3: Fetch results for each execution_id
        results_dict = {}
        all_outputs = []
        markdown_parts = [f"## Query Results Summary\n\nProcessed {len(query_history_results)} dashboard queries:\n"]

        for record in query_history_results:
            execution_id = record.get("execution_id")
            source_name = record.get("xql_query_source_name")

            if not execution_id or not source_name:
                continue

            # Extract widget name from source_name
            widget_name = extract_widget_name(source_name, widget_name_regex)
            query_results = fetch_execution_results(execution_id)

            if query_results:
                results_dict[widget_name] = query_results

                # markdown_parts.append(f"\n### {widget_name}")
                markdown_parts.append(
                    tableToMarkdown(
                        f"{widget_name} ({len(query_results)} records)",
                        query_results,
                        headers=list(query_results[0].keys()) if query_results else [],
                    )
                )

                all_outputs.append(
                    CommandResults(
                        outputs_prefix=f"HealthCheck.CollectResults.{widget_name}",
                        outputs=query_results,
                    )
                )

        if not results_dict:
            demisto.debug(">>> No query results found")
            return_results(CommandResults(readable_output="No query results found."))
            return

        final_markdown = "\n".join(markdown_parts)

        # Create HTML file output
        create_html_file(final_markdown)

        # summary_output = CommandResults(
        #     readable_output=final_markdown,
        #     outputs_prefix="HealthCheck.CollectResults",
        #     outputs=results_dict,
        # )

        # all_outputs.insert(0, summary_output)

        # print(f">>> ========== Completed - {len(results_dict)} sources ==========")
        # return_results(all_outputs)
        return_results(all_outputs)

    except Exception as e:
        # print(f">>> ========== ERROR: {str(e)} ==========")
        return_error(f"Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
