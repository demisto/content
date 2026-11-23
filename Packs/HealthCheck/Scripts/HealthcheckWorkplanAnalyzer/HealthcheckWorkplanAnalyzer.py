"""
HealthcheckWorkplanAnalyzer
===========================

XSOAR / XSIAM automation script that analyzes the health of an incident's / issue's
workplan (invPlaybook) and produces a Markdown health report.

  * The workplan is fetched live via the Core REST API integration
    (`core-api-get`) using the provided Workplan ID (incident / issue ID).
  * The Markdown report is stored in the `healthcheckworkplanreport` field of the current
    incident / issue (via `setIncident`) and returned to the War Room (no context outputs).
  * Optionally, the report is attached as a .md file.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import re
import traceback
from collections import Counter
from collections.abc import Callable
from datetime import datetime
from typing import Any

# --- Defaults ---
DEFAULT_LARGE_IO_THRESHOLD_KB = 100
DEFAULT_SLOW_TASK_THRESHOLD_SECONDS = 15
DEFAULT_TOP_N = 5

# Core REST API command used to collect the workplan
CORE_API_GET_COMMAND = "core-api-get"

# Incident / issue field that stores the Markdown report
WORKPLAN_REPORT_FIELD = "healthcheckworkplanreport"

STRUCTURAL_TASK_TYPES = ("title", "start")
NOT_EXECUTED_STATE = "WillNotBeExecuted"
EMPTY_DATE_PREFIX = "0001-01-01"


# --- Markdown Helpers ---


def md_cell(value: Any) -> str:
    """Escapes pipe characters and newlines so they don't break Markdown tables."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def md_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    """Builds Markdown table lines from headers and rows."""
    lines = ["", "| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return lines


# --- Data Retrieval ---


def fetch_workplan(workplan_id: str) -> dict:
    """
    Fetches the workplan (invPlaybook) JSON for the given investigation ID
    using the Core REST API integration command `core-api-get`.

    Raises:
        DemistoException: If the workplan could not be retrieved.
    """
    uri = f"/inv-playbook/{workplan_id}"
    error_prefix = (
        f"Failed to retrieve workplan for ID '{workplan_id}' using '{CORE_API_GET_COMMAND}'. "
        "Make sure the Core REST API integration is configured and enabled."
    )

    res = demisto.executeCommand(CORE_API_GET_COMMAND, {"uri": uri})

    if not res:
        raise DemistoException(f"{error_prefix} Details: empty response.")
    if is_error(res):
        raise DemistoException(f"{error_prefix} Details: {get_error(res)}")

    contents = res[0].get("Contents")
    if isinstance(contents, str):
        try:
            contents = json.loads(contents)
        except json.JSONDecodeError:
            raise DemistoException(f"{error_prefix} Details: could not decode JSON response.")

    if not isinstance(contents, dict):
        raise DemistoException(f"{error_prefix} Details: unexpected response type {type(contents).__name__}.")

    # core-api-get wraps the API payload under the `response` key
    workplan = contents.get("response", contents)
    if not isinstance(workplan, dict) or not workplan:
        raise DemistoException(f"{error_prefix} Details: empty workplan returned.")

    demisto.debug(f"Fetched workplan {workplan_id} using {CORE_API_GET_COMMAND}")
    return workplan


def _get_root_tasks_map(workplan_json: dict) -> dict:
    """Returns the root tasks map, supporting both invPlaybook-wrapped and flat formats."""
    tasks_map = (workplan_json.get("invPlaybook") or {}).get("tasks") or {}
    if not tasks_map:
        tasks_map = workplan_json.get("tasks") or {}
    return tasks_map if isinstance(tasks_map, dict) else {}


def _get_sub_tasks_map(task: dict) -> dict:
    """Returns the nested tasks map of a subplaybook task (empty dict if none)."""
    sub_tasks = (task.get("subPlaybook") or {}).get("tasks") or {}
    return sub_tasks if isinstance(sub_tasks, dict) else {}


def _task_details(task: dict) -> dict:
    return task.get("task") or {}


def _task_type(task: dict) -> str | None:
    return _task_details(task).get("type")


def _task_name(task: dict, default: str = "Unnamed") -> str:
    return _task_details(task).get("name", default)


# --- Helper Functions ---


def get_all_tasks(workplan_json: dict) -> list[dict]:
    """Recursively traverses the workplan and nested subplaybooks and returns a flat list of tasks."""
    all_tasks: list[dict] = []
    tasks_to_process = list(_get_root_tasks_map(workplan_json).values())

    while tasks_to_process:
        task = tasks_to_process.pop()
        all_tasks.append(task)
        if _task_type(task) == "playbook":
            tasks_to_process.extend(_get_sub_tasks_map(task).values())

    return all_tasks


def iterate_tasks_with_context(workplan_json: dict) -> list[tuple[str, dict, dict, str]]:
    """
    Breadth-first traversal returning (task_id, task, sibling_tasks_map, playbook_context) tuples,
    where playbook_context is the name of the playbook containing the task.
    """
    results: list[tuple[str, dict, dict, str]] = []
    root_map = _get_root_tasks_map(workplan_json)
    if not root_map:
        return results

    queue: list[tuple[dict, str]] = [(root_map, "Main Playbook")]
    while queue:
        current_map, context = queue.pop(0)
        for task_id, task in current_map.items():
            results.append((task_id, task, current_map, context))
            if _task_type(task) == "playbook":
                sub_tasks = _get_sub_tasks_map(task)
                if sub_tasks:
                    queue.append((sub_tasks, _task_name(task, "Unknown Subplaybook")))
    return results


def _parse_iso_datetime(value: str) -> datetime:
    """
    Parses an ISO-8601 timestamp robustly. Handles a trailing 'Z' and
    fractional seconds longer than 6 digits (nanoseconds).
    """
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    match = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", value)
    if match:
        base, frac, tz = match.groups()
        if frac:
            frac = "." + frac[1:7].ljust(6, "0")
        value = f"{base}{frac or ''}{tz}"
    return datetime.fromisoformat(value)


def _calculate_task_duration(task: dict) -> float | None:
    """Calculates duration in seconds between startDate and completedDate, or None if unavailable."""
    start_str = task.get("startDate")
    end_str = task.get("completedDate")

    if not start_str or not end_str or start_str.startswith(EMPTY_DATE_PREFIX) or end_str.startswith(EMPTY_DATE_PREFIX):
        return None

    try:
        return (_parse_iso_datetime(end_str) - _parse_iso_datetime(start_str)).total_seconds()
    except Exception as e:
        demisto.debug(f"Error parsing dates for task {task.get('id')}: {e}")
        return None


def _classify_task_type(task: dict) -> str | None:
    """Returns a display category for a task, or None for structural tasks."""
    task_type = _task_type(task) or "unknown"
    if task_type in STRUCTURAL_TASK_TYPES:
        return None
    if task_type == "playbook":
        return "Subplaybook"
    if task_type == "condition":
        return "Condition"
    if task_type == "regular":
        return "Script" if _task_details(task).get("scriptId") else "Manual"
    return task_type.capitalize()


def get_structure_stats(workplan_json: dict) -> dict:
    """
    Analyzes the workplan structure: layers, total tasks, subplaybook usage (non-unique),
    task types (excluding structural) and execution status.
    """
    stats: dict[str, Any] = {
        "total_tasks": 0,
        "total_subplaybooks": 0,
        "layer_counts": {},
        "total_layers": 0,
        "task_types": Counter(),
        "unexecuted_tasks": 0,
    }

    initial_tasks_map = _get_root_tasks_map(workplan_json)
    if not initial_tasks_map:
        return stats

    layer_counter: Counter = Counter()
    max_depth = 0
    queue: list[tuple[list[dict], int]] = [(list(initial_tasks_map.values()), 0)]

    while queue:
        current_tasks, depth = queue.pop(0)
        if not current_tasks:
            continue

        max_depth = max(max_depth, depth)
        layer_counter[depth] += len(current_tasks)
        stats["total_tasks"] += len(current_tasks)

        for task in current_tasks:
            if task.get("state") == NOT_EXECUTED_STATE:
                stats["unexecuted_tasks"] += 1

            category = _classify_task_type(task)
            if category:
                stats["task_types"][category] += 1

            if _task_type(task) == "playbook":
                stats["total_subplaybooks"] += 1
                nested_map = _get_sub_tasks_map(task)
                if nested_map:
                    queue.append((list(nested_map.values()), depth + 1))

    stats["layer_counts"] = dict(sorted(layer_counter.items()))
    stats["total_layers"] = max_depth + 1
    return stats


# --- Check Functions ---


def _find_large_payloads(
    all_tasks: list[dict], limit_bytes: int, payload_getter: Callable[[dict], Any], label: str
) -> list[dict]:
    """Generic helper to find tasks whose payload (inputs/outputs) exceeds limit_bytes."""
    results = []
    for task in all_tasks:
        task_name = _task_name(task)
        task_id = task.get("id", "N/A")
        payload = payload_getter(task)
        if not payload:
            continue
        try:
            size_bytes = len(json.dumps(payload).encode("utf-8"))
        except Exception as e:
            demisto.debug(f"Could not check {label} size for task {task_id} ({task_name}): {e}")
            continue
        if size_bytes > limit_bytes:
            results.append({"id": task_id, "name": task_name, "size_kb": round(size_bytes / 1024, 2)})
    results.sort(key=lambda x: x["size_kb"], reverse=True)
    return results


def _get_task_inputs(task: dict) -> Any:
    if _task_type(task) == "playbook":
        return task.get("playbookInputs") or {}
    return task.get("scriptArguments") or {}


def find_large_inputs(all_tasks: list[dict], limit_bytes: int) -> list[dict]:
    """Finds tasks with inputs (scriptArguments / playbookInputs) larger than limit_bytes."""
    return _find_large_payloads(all_tasks, limit_bytes, _get_task_inputs, "input")


def find_large_outputs(all_tasks: list[dict], limit_bytes: int) -> list[dict]:
    """Finds tasks with outputs larger than limit_bytes."""
    return _find_large_payloads(all_tasks, limit_bytes, lambda t: t.get("outputs") or {}, "output")


def get_top_common_tasks(workplan_json: dict, top_n: int) -> list[dict]:
    """Finds the top N most common scripts used in regular tasks and the playbooks using them most."""
    script_stats: dict[str, dict[str, Any]] = {}
    for _, task, _, context in iterate_tasks_with_context(workplan_json):
        script_id = _task_details(task).get("scriptId")
        if _task_type(task) != "regular" or not script_id:
            continue
        entry = script_stats.setdefault(script_id, {"total": 0, "playbooks": Counter()})
        entry["total"] += 1
        entry["playbooks"][context] += 1

    sorted_scripts = sorted(script_stats.items(), key=lambda item: item[1]["total"], reverse=True)[:top_n]
    return [
        {
            "script_id": script_id,
            "count": data["total"],
            "unique_playbooks": len(data["playbooks"]),
            "top_playbooks": ", ".join(f"{name} ({count})" for name, count in data["playbooks"].most_common(5)),
        }
        for script_id, data in sorted_scripts
    ]


def _subplaybook_names(all_tasks: list[dict]) -> list[str]:
    return [_task_name(t) for t in all_tasks if _task_type(t) == "playbook"]


def get_top_common_subplaybooks(all_tasks: list[dict], top_n: int) -> list[tuple[str, int]]:
    """Finds the top N most common subplaybook tasks."""
    return Counter(_subplaybook_names(all_tasks)).most_common(top_n)


def get_total_unique_subplaybooks(all_tasks: list[dict]) -> int:
    """Counts the total number of unique subplaybooks referenced."""
    return len(set(_subplaybook_names(all_tasks)))


def get_loop_stats(all_tasks: list[dict]) -> list[dict]:
    """
    Gets subplaybooks configured to run in a loop.
    Supports the `loop` dict format and the `executionCount > 1` format.
    """
    loop_stats = []
    processed_task_ids = set()

    for task in all_tasks:
        task_id = task.get("id")
        task_type = task.get("type") or _task_type(task)
        if task_id in processed_task_ids or task_type != "playbook":
            continue

        loop_config = task.get("loop")
        execution_count = task.get("executionCount")
        is_looping = bool(loop_config) or (isinstance(execution_count, int) and execution_count > 1)
        if not is_looping:
            continue

        loop_max = loop_config.get("max", "N/A") if isinstance(loop_config, dict) and loop_config else execution_count
        loop_stats.append({"id": task_id, "name": _task_name(task), "loop_max": loop_max})
        processed_task_ids.add(task_id)

    return loop_stats


def get_slow_tasks(all_tasks: list[dict], threshold_seconds: float) -> list[dict]:
    """
    Finds script/regular tasks that took longer than threshold_seconds.
    Excludes subplaybooks, structural tasks, Sleep tasks and skipped tasks.
    """
    slow_tasks = []
    for task in all_tasks:
        if task.get("state") == NOT_EXECUTED_STATE:
            continue

        script_id = _task_details(task).get("scriptId") or "N/A"
        if script_id == "Sleep" or _task_type(task) in ("playbook", *STRUCTURAL_TASK_TYPES):
            continue

        duration = _calculate_task_duration(task)
        if duration is not None and duration > threshold_seconds:
            slow_tasks.append(
                {"id": task.get("id"), "name": _task_name(task), "scriptId": script_id, "duration": round(duration, 2)}
            )

    slow_tasks.sort(key=lambda x: float(x["duration"] or 0.0), reverse=True)
    return slow_tasks


def get_slowest_playbooks(all_tasks: list[dict], top_n: int) -> list[dict]:
    """Finds the top N slowest executing subplaybooks."""
    slow_playbooks = []
    for task in all_tasks:
        if task.get("state") == NOT_EXECUTED_STATE or _task_type(task) != "playbook":
            continue
        duration = _calculate_task_duration(task)
        if duration is not None:
            slow_playbooks.append({"id": task.get("id"), "name": _task_name(task), "duration": round(duration, 2)})

    slow_playbooks.sort(key=lambda x: float(x["duration"] or 0.0), reverse=True)
    return slow_playbooks[:top_n]


def _get_condition_targets(task: dict, sibling_map: dict) -> list[str]:
    """Returns the identifiers (script/playbook/name) of all tasks a condition branches to."""
    targets = []
    for target_ids in (task.get("nextTasks") or {}).values():
        for target_id in target_ids or []:
            target_task = sibling_map.get(target_id)
            if not target_task:
                continue
            details = _task_details(target_task)
            targets.append(details.get("scriptId") or details.get("playbookId") or details.get("name", "Unknown"))
    return targets


def check_conditional_tasks(workplan_json: dict) -> list[dict]:
    """
    Finds condition tasks with more than 5 branches where more than 50% of
    the branches lead to the same script/playbook/task.
    Each unique condition task definition (by UUID) is checked only once.
    """
    conditional_stats = []
    seen_uuids: set[str] = set()

    for task_id, task, sibling_map, context in iterate_tasks_with_context(workplan_json):
        if _task_type(task) != "condition":
            continue

        task_uuid = _task_details(task).get("id")
        if task_uuid in seen_uuids:
            continue
        if task_uuid:
            seen_uuids.add(task_uuid)

        targets = _get_condition_targets(task, sibling_map)
        if len(targets) <= 5:
            continue

        total_paths = len(targets)
        common_script, count = Counter(targets).most_common(1)[0]
        if count / total_paths > 0.5:
            conditional_stats.append(
                {
                    "id": task_id,
                    "name": _task_name(task, "Unnamed Condition"),
                    "context": context,
                    "common_script": common_script,
                    "count": count,
                    "total": total_paths,
                    "percent": round((count / total_paths) * 100, 1),
                }
            )

    return conditional_stats


# --- Analysis & Reporting ---


def build_structure_summary(structure_stats: dict, all_tasks: list[dict]) -> dict:
    total_tasks = structure_stats.get("total_tasks", 0)
    unexecuted = structure_stats.get("unexecuted_tasks", 0)
    return {
        "TotalTasks": total_tasks,
        "TotalSubplaybooks": structure_stats.get("total_subplaybooks", 0),
        "TotalUniqueSubplaybooks": get_total_unique_subplaybooks(all_tasks),
        "TotalLayers": structure_stats.get("total_layers", 0),
        "UnexecutedTasks": unexecuted,
        "UnexecutedPercent": round(unexecuted / total_tasks * 100, 1) if total_tasks else 0,
        "TaskTypes": dict(structure_stats.get("task_types", {})),
        "LayerCounts": {str(k): v for k, v in structure_stats.get("layer_counts", {}).items()},
    }


def analyze_workplan(workplan_data: dict, large_io_threshold_kb: float, slow_threshold_seconds: float, top_n: int) -> dict:
    """Runs all checks against the workplan and returns the results (also used as context output)."""
    limit_bytes = int(large_io_threshold_kb * 1024)
    all_tasks = get_all_tasks(workplan_data)
    structure_stats = get_structure_stats(workplan_data)

    return {
        "WorkplanID": workplan_data.get("id", "N/A"),
        "WorkplanName": workplan_data.get("name", "N/A"),
        "TotalTasksFlat": len(all_tasks),
        "Structure": build_structure_summary(structure_stats, all_tasks),
        "LargeInputs": find_large_inputs(all_tasks, limit_bytes),
        "LargeOutputs": find_large_outputs(all_tasks, limit_bytes),
        "CommonScripts": get_top_common_tasks(workplan_data, top_n),
        "CommonSubplaybooks": [{"name": name, "count": count} for name, count in get_top_common_subplaybooks(all_tasks, top_n)],
        "LoopingSubplaybooks": get_loop_stats(all_tasks),
        "SlowTasks": get_slow_tasks(all_tasks, slow_threshold_seconds),
        "SlowestSubplaybooks": get_slowest_playbooks(all_tasks, top_n),
        "ConditionalSkew": check_conditional_tasks(workplan_data),
        "Thresholds": {
            "LargeIOThresholdKB": large_io_threshold_kb,
            "SlowTaskThresholdSeconds": slow_threshold_seconds,
            "TopN": top_n,
        },
    }


def _section(title: str, headers: list[str], rows: list[list[Any]], empty_message: str) -> list[str]:
    """Builds a report section: a title followed by a table, or an empty-state message."""
    lines = [f"\n### {title}"]
    if rows:
        lines += md_table(headers, rows)
    else:
        lines.append(empty_message)
    return lines


def _structure_section(structure: dict) -> list[str]:
    total_tasks = structure["TotalTasks"]
    lines = [
        "\n### 0. Workplan Structure & Complexity",
        f"**Total Tasks (Recursive):** {total_tasks}  ",
        f"**Total Subplaybooks (All occurrences):** {structure['TotalSubplaybooks']}  ",
        f"**Total Unique Subplaybooks:** {structure['TotalUniqueSubplaybooks']}  ",
        f"**Total Depth/Layers:** {structure['TotalLayers']}  ",
        f"**Unexecuted Tasks:** {structure['UnexecutedTasks']} / {total_tasks} ({structure['UnexecutedPercent']:.1f}%)",
        "\n**Breakdown by Task Type (excluding Structural):**",
    ]
    type_rows = [
        [md_cell(t_type), count, f"{(count / total_tasks * 100) if total_tasks else 0:.1f}%"]
        for t_type, count in structure["TaskTypes"].items()
    ]
    lines += md_table(["Type", "Count", "% of Total"], type_rows)

    lines.append("\n**Tasks per Layer:**")
    layer_rows = [
        [f"{layer}{' (Main Playbook)' if str(layer) == '0' else ''}", count] for layer, count in structure["LayerCounts"].items()
    ]
    lines += md_table(["Layer (Depth)", "Task Count"], layer_rows)
    return lines


def _size_rows(items: list[dict]) -> list[list[Any]]:
    return [[md_cell(i["id"]), md_cell(i["name"]), f"{i['size_kb']:.2f}"] for i in items]


def generate_markdown_report(results: dict) -> str:
    """Builds the full Markdown health report from the analysis results."""
    io_kb = results["Thresholds"]["LargeIOThresholdKB"]
    slow_s = results["Thresholds"]["SlowTaskThresholdSeconds"]
    top_n = results["Thresholds"]["TopN"]

    lines = [
        f"## Workplan Health Report: {md_cell(results['WorkplanName'])} (ID: {md_cell(results['WorkplanID'])})",
        f"Total tasks processed (flat list): {results['TotalTasksFlat']}",
    ]

    if not results["TotalTasksFlat"]:
        lines.append("\nNo tasks found in workplan.")
        return "\n".join(lines)

    lines += _structure_section(results["Structure"])
    lines += _section(
        f"1. Tasks with Inputs > {io_kb}KB",
        ["Task ID", "Task Name", "Size (KB)"],
        _size_rows(results["LargeInputs"]),
        f"No tasks found with inputs > {io_kb}KB.",
    )
    lines += _section(
        f"2. Tasks with Outputs > {io_kb}KB",
        ["Task ID", "Task Name", "Size (KB)"],
        _size_rows(results["LargeOutputs"]),
        f"No tasks found with outputs > {io_kb}KB.",
    )
    lines += _section(
        f"3. Top {top_n} Most Common Scripts",
        ["Script ID", "Occurrences", "Unique Playbooks", "Top Playbooks (Count)"],
        [
            [md_cell(i["script_id"]), i["count"], i["unique_playbooks"], md_cell(i["top_playbooks"])]
            for i in results["CommonScripts"]
        ],
        "No script-based tasks found.",
    )
    lines += _section(
        f"4. Top {top_n} Most Common Subplaybook Tasks",
        ["Subplaybook Name", "Occurrences"],
        [[md_cell(i["name"]), i["count"]] for i in results["CommonSubplaybooks"]],
        "No subplaybook tasks found.",
    )
    lines += _section(
        "5. Subplaybook Loop Statistics",
        ["Task ID", "Subplaybook Name", "Max Iterations"],
        [[md_cell(i["id"]), md_cell(i["name"]), md_cell(i["loop_max"])] for i in results["LoopingSubplaybooks"]],
        "No subplaybooks were found configured to run in a loop.",
    )
    lines += _section(
        f"6. Slow Tasks (> {slow_s} seconds)",
        ["Task ID", "Task Name", "Script ID", "Duration (s)"],
        [[md_cell(i["id"]), md_cell(i["name"]), md_cell(i["scriptId"]), i["duration"]] for i in results["SlowTasks"]],
        "No slow tasks found.",
    )
    lines += _section(
        f"7. Top {top_n} Slowest Subplaybooks",
        ["Task ID", "Subplaybook Name", "Duration (s)"],
        [[md_cell(i["id"]), md_cell(i["name"]), i["duration"]] for i in results["SlowestSubplaybooks"]],
        "No subplaybooks with duration data found.",
    )
    lines += _section(
        "8. Conditional Task Analysis (Branches > 5, Same Script > 50%)",
        ["Subplaybook", "Condition Name", "Common Script", "Ratio"],
        [
            [
                md_cell(i["context"]),
                md_cell(i["name"]),
                md_cell(i["common_script"]),
                f"{i['count']}/{i['total']} ({i['percent']}%)",
            ]
            for i in results["ConditionalSkew"]
        ],
        "No conditional tasks found with heavily skewed branches.",
    )
    return "\n".join(lines)


def store_report_in_field(report_md: str) -> None:
    """Stores the Markdown report in the `healthcheckworkplanreport` field of the current incident / issue."""
    res = demisto.executeCommand("setIncident", {WORKPLAN_REPORT_FIELD: report_md})
    if is_error(res):
        raise DemistoException(f"Failed to set the '{WORKPLAN_REPORT_FIELD}' field. Details: {get_error(res)}")


# --- Entry Point ---


def _get_number_arg(args: dict, name: str, default: float, cast: Callable[[Any], Any] = float) -> Any:
    """Reads a numeric argument, falling back to the default on empty input."""
    value = args.get(name)
    if value in (None, ""):
        return default
    try:
        return cast(value)
    except (TypeError, ValueError):
        raise DemistoException(f"Argument '{name}' must be a number, got: {value}")


def resolve_workplan_id(args: dict) -> str:
    """Returns the workplan ID from the arguments, falling back to the current incident/issue ID."""
    workplan_id = str(args.get("workplan_id") or "").strip()
    if not workplan_id:
        workplan_id = str((demisto.incident() or {}).get("id") or "").strip()
    if not workplan_id:
        raise DemistoException("Argument 'workplan_id' is required.")
    return workplan_id


def workplan_analyzer_command(args: dict) -> list[Any]:
    workplan_id = resolve_workplan_id(args)
    large_io_threshold_kb = _get_number_arg(args, "large_io_threshold_kb", DEFAULT_LARGE_IO_THRESHOLD_KB, float)
    slow_threshold_seconds = _get_number_arg(args, "slow_task_threshold_seconds", DEFAULT_SLOW_TASK_THRESHOLD_SECONDS, float)
    top_n = _get_number_arg(args, "top_n", DEFAULT_TOP_N, int)
    attach_report = argToBoolean(args.get("attach_report", "false"))

    workplan_data = fetch_workplan(workplan_id)
    results = analyze_workplan(workplan_data, large_io_threshold_kb, slow_threshold_seconds, top_n)
    # Ensure the requested ID is in context even if the API omits it
    if results.get("WorkplanID") in (None, "", "N/A"):
        results["WorkplanID"] = workplan_id

    report_md = generate_markdown_report(results)
    store_report_in_field(report_md)

    entries: list[Any] = [CommandResults(readable_output=report_md, raw_response=results)]
    if attach_report:
        entries.append(fileResult(f"{workplan_id}-workplan-health.md", report_md, file_type=EntryType.FILE))
    return entries


def main() -> None:  # pragma: no cover
    try:
        return_results(workplan_analyzer_command(demisto.args()))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute HealthcheckWorkplanAnalyzer. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
