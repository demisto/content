import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
from datetime import UTC, datetime
from typing import Any

import pandas as pd

PAGE_SIZE = 100
DISCONNECTED_DAYS_THRESHOLD = 20

# os_type field → get_versions OS family key
_OS_TYPE_TO_FAMILY: dict[str, str] = {
    "AGENT_OS_WINDOWS": "windows",
    "AGENT_OS_LINUX": "linux",
    "AGENT_OS_MAC": "macos",
}


def api_post(uri: str, body: dict) -> Any:
    """Call core-api-post and return the response payload, raising on error."""
    result = demisto.executeCommand(
        "core-api-post",
        {"uri": uri, "body": json.dumps(body)},
    )
    if is_error(result):
        raise ValueError(f"API call to {uri} failed: {get_error(result)}")
    return result[0]["Contents"]["response"]["reply"]


def fetch_supported_versions() -> dict[str, set[str]]:
    """Fetch supported agent versions per OS family from /public_api/v1/distributions/get_versions."""
    reply = api_post("/public_api/v1/distributions/get_versions", {})
    return {family: set(versions) for family, versions in reply.items() if isinstance(versions, list)}


def fetch_all_endpoints() -> list[dict]:
    """
    Fetch all endpoints via paginated POST /public_api/v1/endpoints/get_endpoint.
    Uses total_count from the first response to stop pagination precisely.
    """
    all_records: list[dict] = []
    search_from = 0
    total_count: int | None = None

    while True:
        body = {
            "request_data": {
                "search_from": search_from,
                "search_to": search_from + PAGE_SIZE,
                "filters": [],
            }
        }
        reply = api_post("/public_api/v1/endpoints/get_endpoint", body)
        page: list[dict] = reply.get("endpoints", [])

        if total_count is None:
            total_count = int(reply.get("total_count", 0))

        all_records.extend(page)

        if len(all_records) >= total_count:
            break

        search_from += PAGE_SIZE

    return all_records


def build_endpoints_dataframe(records: list[dict]) -> pd.DataFrame:
    """Convert endpoint records list into a pandas DataFrame."""
    return pd.DataFrame(records)


def print_df_to_markdown(df: pd.DataFrame, title: str) -> None:
    """Render a DataFrame as a markdown table in the war room."""
    return_results(CommandResults(readable_output=tableToMarkdown(title, df.to_dict(orient="records"))))


def query_agent_status_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    """Count endpoints grouped by endpoint_status, sorted descending."""
    result = df.groupby("endpoint_status").size().reset_index(name="total")
    return result.sort_values("total", ascending=False).reset_index(drop=True)


def query_agent_eol_versions(
    df: pd.DataFrame,
    supported_versions: dict[str, set[str]],
) -> pd.DataFrame:
    """
    List endpoints whose agent version is not in the supported versions list for their OS family.
    Uses os_type field to determine OS family. Unknown OS types are treated as supported.
    Returns columns: [endpoint_name, endpoint_version, operating_system, os_family].
    """
    _EMPTY = pd.DataFrame(columns=["endpoint_name", "endpoint_version", "operating_system", "os_family"])

    if not supported_versions:
        return _EMPTY

    os_families = df["os_type"].apply(lambda t: _OS_TYPE_TO_FAMILY.get(t or "", "unknown"))

    def _is_eol(idx: int) -> bool:
        family = os_families.iloc[idx]
        supported = supported_versions.get(family)
        return supported is not None and str(df["endpoint_version"].iloc[idx]) not in supported

    df_eol = df[[_is_eol(i) for i in range(len(df))]].copy()

    if df_eol.empty:
        return _EMPTY

    df_eol["os_family"] = os_families[df_eol.index].values
    cols = [c for c in ["endpoint_name", "endpoint_version", "operating_system", "os_family"] if c in df_eol.columns]
    return df_eol[cols].sort_values(["os_family", "endpoint_version"]).reset_index(drop=True)


def query_inventory_by_os(df: pd.DataFrame) -> pd.DataFrame:
    """Count endpoints grouped by platform, operating_system, os_version, sorted descending."""
    result = df.groupby(["platform", "operating_system", "os_version"]).size().reset_index(name="total")
    return result.sort_values("total", ascending=False).reset_index(drop=True)


def query_content_autoupdate_disabled(df: pd.DataFrame) -> pd.DataFrame | None:
    """Count endpoints with content auto-update disabled, grouped by prevention policy. Returns None if none found."""
    df_filtered = df[df["content_auto_update"].isin(["DISABLED", "content_auto_update_0", 0])]
    if df_filtered.empty:
        return None
    result = df_filtered.groupby("assigned_prevention_policy").size().reset_index(name="total")
    return result.sort_values("total", ascending=False).reset_index(drop=True)


def query_connection_lost_endpoints(df: pd.DataFrame) -> pd.DataFrame:
    """List CONNECTION_LOST endpoints with days since last seen."""
    df_filtered = df[df["endpoint_status"] == "CONNECTION_LOST"]
    if df_filtered.empty:
        return pd.DataFrame(columns=["name", "type", "daysNotSeen", "last_seen"])

    current_time_utc = pd.to_datetime(datetime.now(UTC))
    last_seen_dt = pd.to_datetime(df_filtered["last_seen"], unit="ms", utc=True)
    result = pd.DataFrame(
        {
            "name": df_filtered["endpoint_name"].values,
            "type": df_filtered["endpoint_type"].values,
            "daysNotSeen": (current_time_utc - last_seen_dt).dt.days.values,
            "last_seen": last_seen_dt.dt.strftime("%Y-%m-%d %H:%M:%S").values,
        }
    )
    return result.sort_values("daysNotSeen", ascending=False, ignore_index=True)


def query_disconnected_endpoints_by_type(
    df: pd.DataFrame,
    days_threshold: int = DISCONNECTED_DAYS_THRESHOLD,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    List DISCONNECTED workstations and servers not seen for >= days_threshold days.
    Returns (workstations_df, servers_df), each with columns [name, type, daysNotSeen, last_seen].
    """
    empty = pd.DataFrame(columns=["name", "type", "daysNotSeen", "last_seen"])
    df_filtered = df[(df["endpoint_status"] == "DISCONNECTED") & (df["endpoint_type"].isin(["TYPE_WORKSTATION", "TYPE_SERVER"]))]

    if df_filtered.empty:
        return empty, empty.copy()

    current_time_utc = pd.to_datetime(datetime.now(UTC))
    last_seen_dt = pd.to_datetime(df_filtered["last_seen"], unit="ms", utc=True)
    result_df = pd.DataFrame(
        {
            "name": df_filtered["endpoint_name"].values,
            "type": df_filtered["endpoint_type"].values,
            "daysNotSeen": (current_time_utc - last_seen_dt).dt.days.values,
            "last_seen": last_seen_dt.dt.strftime("%Y-%m-%d %H:%M:%S").values,
        }
    )

    final_df = result_df[result_df["daysNotSeen"] >= days_threshold].copy()
    workstations = final_df[final_df["type"] == "TYPE_WORKSTATION"].sort_values("daysNotSeen", ascending=False, ignore_index=True)
    servers = final_df[final_df["type"] == "TYPE_SERVER"].sort_values("daysNotSeen", ascending=False, ignore_index=True)
    return workstations, servers


def main() -> None:
    records = fetch_all_endpoints()

    if not records:
        return_warning("No endpoint records returned by the API.")
        return

    df = build_endpoints_dataframe(records)
    return_results(CommandResults(readable_output=f"**Endpoints loaded:** {len(df)}"))

    try:
        print_df_to_markdown(query_agent_status_breakdown(df), "Agent Status Breakdown")
    except Exception as exc:
        demisto.error(f"query_agent_status_breakdown failed: {exc}")

    try:
        supported_versions = fetch_supported_versions()
        eol_df = query_agent_eol_versions(df, supported_versions)
        if eol_df.empty:
            return_results(CommandResults(readable_output="**Agent EOL Versions:** All agents are on supported versions."))
        else:
            print_df_to_markdown(eol_df, f"Agent EOL Versions ({len(eol_df)} endpoints)")
    except Exception as exc:
        demisto.error(f"query_agent_eol_versions failed: {exc}")

    try:
        print_df_to_markdown(query_inventory_by_os(df), "Endpoint Inventory by OS")
    except Exception as exc:
        demisto.error(f"query_inventory_by_os failed: {exc}")

    try:
        autoupdate_df = query_content_autoupdate_disabled(df)
        if autoupdate_df is not None:
            print_df_to_markdown(autoupdate_df, "Content Auto-Update Disabled (by Prevention Policy)")
        else:
            return_results(CommandResults(readable_output="**Content Auto-Update Disabled:** None found."))
    except Exception as exc:
        demisto.error(f"query_content_autoupdate_disabled failed: {exc}")

    try:
        lost_df = query_connection_lost_endpoints(df)
        if lost_df.empty:
            return_results(CommandResults(readable_output="**Connection Lost Endpoints:** None found."))
        else:
            print_df_to_markdown(lost_df, f"Connection Lost Endpoints ({len(lost_df)})")
    except Exception as exc:
        demisto.error(f"query_connection_lost_endpoints failed: {exc}")

    try:
        workstations, servers = query_disconnected_endpoints_by_type(df, DISCONNECTED_DAYS_THRESHOLD)
        if workstations.empty:
            return_results(
                CommandResults(readable_output=f"**Disconnected Workstations:** None >{DISCONNECTED_DAYS_THRESHOLD} days.")
            )
        else:
            print_df_to_markdown(
                workstations,
                f"Disconnected Workstations >{DISCONNECTED_DAYS_THRESHOLD} days ({len(workstations)})",
            )

        if servers.empty:
            return_results(CommandResults(readable_output=f"**Disconnected Servers:** None >{DISCONNECTED_DAYS_THRESHOLD} days."))
        else:
            print_df_to_markdown(
                servers,
                f"Disconnected Servers >{DISCONNECTED_DAYS_THRESHOLD} days ({len(servers)})",
            )
    except Exception as exc:
        demisto.error(f"query_disconnected_endpoints_by_type failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
