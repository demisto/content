import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import time
import json
import pandas as pd
from datetime import UTC


def printDFtoMarkdown(result, title):
    dict_result = result.to_dict(orient="records")
    md = tableToMarkdown(title, dict_result)
    results = CommandResults(
        readable_output=md,
    )
    return_results(results)


def execute_xql_query(query, limit=1000, max_polls=30):
    # Execute XQL query and return results#

    # Step 1: Start query
    start_body = {
        "request_data": {
            "query": query,
            "timeframe": {"relativeTime": 86400000},  # 24 hours
        }
    }

    result = demisto.executeCommand(
        "core-api-post",
        {"uri": "/public_api/v1/xql/start_xql_query", "body": json.dumps(start_body)},
    )

    if is_error(result):
        raise ValueError(f"Failed to start query: {get_error(result)}")

    execution_id = result[0]["Contents"]["response"]["reply"]
    demisto.debug(f"Query started: {execution_id}")

    # Step 2: Poll for results
    poll_body = {
        "request_data": {
            "query_id": execution_id,
            "pending_flag": True,
            "limit": limit,
            "format": "json",
        }
    }

    for _attempt in range(max_polls):
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
            return reply["results"]["data"]
        elif reply["status"] == "FAILED":
            raise ValueError(f"Query failed: {reply.get('error')}")

        time.sleep(3)

    raise TimeoutError("Query timeout")


def query_inventory_by_os(df):
    """
    Query 1: Count endpoints grouped by platform, OS, and version.
    XQL: dataset = endpoints | comp count() as total by platform, operating_system, os_version | sort desc total

    Args:
        df (pd.DataFrame): DataFrame containing endpoint data

    Returns:
        pd.DataFrame: Results with columns [platform, operating_system, os_version, total]
    """
    # Group by platform, OS, version and count
    result = df.groupby(["platform", "operating_system", "os_version"]).size().reset_index(name="total")
    result = result.sort_values("total", ascending=False).reset_index(drop=True)

    return result


def query_content_autoupdate_disabled(df):
    """
    Query 2: Count endpoints with content auto-update disabled, grouped by prevention policy.
    XQL: dataset = endpoints | filter content_auto_update = ENUM.DISABLED | comp count() as total by assigned_prevention_policy

    Args:
        df (pd.DataFrame): DataFrame containing endpoint data

    Returns:
        pd.DataFrame: Results with columns [assigned_prevention_policy, total] or None if no matches
    """
    # Filter for disabled content auto-update
    df_filtered = df[df["content_auto_update"].isin(["DISABLED", "content_auto_update_0", 0])]

    if len(df_filtered) == 0:
        return_results("No endpoints found with content_auto_update = DISABLED")
        return None

    # Group by prevention policy and count
    result = df_filtered.groupby("assigned_prevention_policy").size().reset_index(name="total")
    result = result.sort_values("total", ascending=False).reset_index(drop=True)

    return result


def query_connection_lost_endpoints(df):
    """
    Query 4: Endpoints with status CONNECTION_LOST and daysNotSeen.

    XQL:
      dataset = endpoints
      | filter endpoint_status in (ENUM.CONNECTION_LOST)
      | alter daysNotSeen = timestamp_diff(current_time(), last_seen, "DAY")
      | fields endpoint_name as name, endpoint_type as type, daysNotSeen, last_seen

    Args:
        df (pd.DataFrame): Endpoint data with 'endpoint_status', 'last_seen',
                           'endpoint_name', 'endpoint_type'.

    Returns:
        pd.DataFrame: Columns [name, type, daysNotSeen, last_seen].
    """
    # Use timezone-aware UTC time
    current_time_utc = pd.to_datetime(datetime.now(UTC))

    # Filter only CONNECTION_LOST endpoints
    df_filtered = df[df["endpoint_status"] == "CONNECTION_LOST"]

    # Compute daysNotSeen from last_seen (ms since epoch)
    last_seen_dt = pd.to_datetime(df_filtered["last_seen"], unit="ms", utc=True)
    # days_not_seen = ((current_time_utc - last_seen_dt).dt.total_seconds() / (24 * 60 * 60)).round(0)
    days_not_seen = (current_time_utc - last_seen_dt).dt.days

    result = pd.DataFrame(
        {
            "name": df_filtered["endpoint_name"].values,
            "type": df_filtered["endpoint_type"].values,
            "daysNotSeen": days_not_seen.values,
            "last_seen": last_seen_dt.dt.strftime("%Y-%m-%d %H:%M:%S"),
        }
    ).sort_values("daysNotSeen", ascending=False, ignore_index=True)
    return result


from datetime import datetime


def query_disconnected_endpoints_by_type_optimized(df, days_threshold=20):
    current_time_utc = pd.to_datetime(datetime.now(UTC))

    # 1. Directly filter for relevant endpoint types and status first.
    # This reduces the size of the DataFrame for subsequent calculations.
    relevant_types = ["TYPE_WORKSTATION", "TYPE_SERVER"]
    df_filtered = df[(df["endpoint_status"] == "DISCONNECTED") & (df["endpoint_type"].isin(relevant_types))]

    # 2. Calculate 'daysNotSeen' only on the smaller, filtered DataFrame.
    # Using pd.to_datetime is more robust for timestamp calculations.
    last_seen_dt = pd.to_datetime(df_filtered["last_seen"], unit="ms", utc=True)
    days_not_seen = (current_time_utc - last_seen_dt).dt.days

    # 3. Create the final DataFrame in a single step and apply the final time filter.
    # This avoids creating multiple intermediate copies.
    result_df = pd.DataFrame(
        {
            "name": df_filtered["endpoint_name"],
            "type": df_filtered["endpoint_type"],
            "daysNotSeen": days_not_seen,
            "last_seen": last_seen_dt.dt.strftime("%Y-%m-%d %H:%M:%S"),
        }
    )

    final_df = result_df[result_df["daysNotSeen"] >= days_threshold].copy()

    # 4. Split the final DataFrame into two, once.
    workstations = final_df[final_df["type"] == "TYPE_WORKSTATION"].sort_values("daysNotSeen", ascending=False, ignore_index=True)
    servers = final_df[final_df["type"] == "TYPE_SERVER"].sort_values("daysNotSeen", ascending=False, ignore_index=True)

    return workstations, servers


"""Main execution."""

# Get query from args and limit
query = demisto.args().get("query", "dataset = endpoints | limit 100")

# Execute Main Endpoints dataset query

endpoints_data = execute_xql_query(query)

# Convert to DataFrame ONCE - fir all queries usage
df = pd.DataFrame(endpoints_data)
return_results(f"DataFrame created with {len(df)} rows and {len(df.columns)} columns\n")

# Execute Query 1: Inventory by OS
# Translate "XQL: dataset = endpoints | comp count() as total by platform, operating_system, os_version | sort desc total\n")
result_query_1 = query_inventory_by_os(df)
printDFtoMarkdown(result_query_1, "Count endpoints grouped by platform, OS, and version")
# return_results(result1.to_string(index=False))


# Execute Query 2: Content auto-update disabled

# Translate
# "XQL: dataset = endpoints | filter content_auto_update = ENUM.DISABLED | comp count() as total by assigned_prevention_policy\n"
result_query_2 = query_content_autoupdate_disabled(df)

if result_query_2 is not None:
    printDFtoMarkdown(
        result_query_2,
        "Count endpoints with content auto-update disabled, grouped by prevention policy",
    )
    # return_results(result_query_2.to_string(index=False))
    # return_results(
    #     f"Total endpoints with auto-update disabled: {result_query_2['total'].sum()}"
    # )


# execute query 3, 6:

workstations, servers = query_disconnected_endpoints_by_type_optimized(df, 20)
if workstations is not None:
    printDFtoMarkdown(workstations, "Disconnected Workstations:")
if servers is not None:
    printDFtoMarkdown(servers, "Disconnected Servers:")


# execute query 4

# Query 4: Connection lost endpoints
connection_lost = query_connection_lost_endpoints(df)
if connection_lost is not None:
    # return_results(connection_lost.to_string(index=False))
    printDFtoMarkdown(connection_lost, "Connection lost endpoints")
