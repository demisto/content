import json

import demistomock as demisto
import pytest
from CommonServerPython import CommandResults, DemistoException

import HealthcheckWorkplanAnalyzer as analyzer


def _task(task_id, name, task_type="regular", script_id=None, **extra):
    details = {"id": f"uuid-{task_id}", "name": name, "type": task_type}
    if script_id:
        details["scriptId"] = script_id
    return {"id": task_id, "task": details, **extra}


def build_workplan():
    sub_tasks = {
        "s1": _task("s1", "Sub Script", script_id="Print"),
        "s2": _task(
            "s2",
            "Sub Slow",
            script_id="SlowScript",
            startDate="2024-01-01T00:00:00.123456789Z",
            completedDate="2024-01-01T00:00:30Z",
        ),
    }
    condition_targets = {f"t{i}": _task(f"t{i}", f"Target {i}", script_id="Print") for i in range(6)}
    root_tasks = {
        "0": _task("0", "Start", task_type="start"),
        "1": _task("1", "Print Task", script_id="Print", outputs={"big": "x" * 3000}),
        "2": _task("2", "Manual Task", state="WillNotBeExecuted"),
        "3": _task(
            "3",
            "My Sub",
            task_type="playbook",
            subPlaybook={"tasks": sub_tasks},
            loop={"max": 10},
            startDate="2024-01-01T00:00:00Z",
            completedDate="2024-01-01T00:01:00Z",
        ),
        "4": _task("4", "Branch", task_type="condition", nextTasks={"yes": list(condition_targets)}),
        **condition_targets,
    }
    return {"id": "123", "name": "Test Workplan", "invPlaybook": {"tasks": root_tasks}}


def test_get_all_tasks_includes_nested():
    tasks = analyzer.get_all_tasks(build_workplan())
    ids = {t["id"] for t in tasks}
    assert {"s1", "s2", "3", "t0"} <= ids
    assert len(tasks) == 13


def test_get_structure_stats():
    stats = analyzer.get_structure_stats(build_workplan())
    assert stats["total_tasks"] == 13
    assert stats["total_layers"] == 2
    assert stats["total_subplaybooks"] == 1
    assert stats["unexecuted_tasks"] == 1
    assert stats["layer_counts"] == {0: 11, 1: 2}
    assert stats["task_types"]["Script"] == 9
    assert stats["task_types"]["Manual"] == 1
    assert "Start" not in stats["task_types"]


def test_find_large_outputs():
    tasks = analyzer.get_all_tasks(build_workplan())
    result = analyzer.find_large_outputs(tasks, 1024)
    assert [r["id"] for r in result] == ["1"]
    assert analyzer.find_large_inputs(tasks, 1024) == []


def test_slow_tasks_and_playbooks():
    tasks = analyzer.get_all_tasks(build_workplan())
    slow = analyzer.get_slow_tasks(tasks, 15)
    assert len(slow) == 1
    assert slow[0]["scriptId"] == "SlowScript"
    assert slow[0]["duration"] == pytest.approx(29.88, abs=0.01)
    assert analyzer.get_slowest_playbooks(tasks, 5) == [{"id": "3", "name": "My Sub", "duration": 60.0}]


def test_loop_and_subplaybook_stats():
    tasks = analyzer.get_all_tasks(build_workplan())
    assert analyzer.get_loop_stats(tasks) == [{"id": "3", "name": "My Sub", "loop_max": 10}]
    assert analyzer.get_top_common_subplaybooks(tasks, 5) == [("My Sub", 1)]
    assert analyzer.get_total_unique_subplaybooks(tasks) == 1


def test_get_top_common_tasks():
    result = analyzer.get_top_common_tasks(build_workplan(), 1)
    assert result[0]["script_id"] == "Print"
    assert result[0]["count"] == 8
    assert result[0]["unique_playbooks"] == 2


def test_check_conditional_tasks():
    result = analyzer.check_conditional_tasks(build_workplan())
    assert len(result) == 1
    assert result[0]["common_script"] == "Print"
    assert result[0]["percent"] == 100.0


def test_generate_markdown_report_empty_workplan():
    results = analyzer.analyze_workplan({"id": "1", "name": "Empty"}, 100, 15, 5)
    report = analyzer.generate_markdown_report(results)
    assert "No tasks found in workplan." in report


def test_generate_markdown_report_sections():
    results = analyzer.analyze_workplan(build_workplan(), 1, 15, 5)
    report = analyzer.generate_markdown_report(results)
    for section in ("### 0.", "### 1.", "### 2.", "### 3.", "### 4.", "### 5.", "### 6.", "### 7.", "### 8."):
        assert section in report
    assert "| My Sub | 1 |" in report


def test_fetch_workplan_success(mocker):
    workplan = build_workplan()
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": {"response": workplan}}])
    assert analyzer.fetch_workplan("123") == workplan
    execute_mock.assert_called_once_with("core-api-get", {"uri": "/inv-playbook/123"})


def test_fetch_workplan_string_contents(mocker):
    workplan = build_workplan()
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": json.dumps({"response": workplan})}])
    assert analyzer.fetch_workplan("123")["id"] == "123"


def test_fetch_workplan_error(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 4, "Contents": "Not found"}])
    with pytest.raises(DemistoException, match="Failed to retrieve workplan"):
        analyzer.fetch_workplan("123")


def test_resolve_workplan_id_falls_back_to_current_incident(mocker):
    mocker.patch.object(demisto, "incident", return_value={"id": "42"})
    assert analyzer.resolve_workplan_id({}) == "42"
    assert analyzer.resolve_workplan_id({"workplan_id": " 7 "}) == "7"


def test_get_number_arg_invalid():
    with pytest.raises(DemistoException, match="must be a number"):
        analyzer._get_number_arg({"top_n": "abc"}, "top_n", 5, int)
    assert analyzer._get_number_arg({"top_n": ""}, "top_n", 5, int) == 5


def test_store_report_in_field(mocker):
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "done"}])
    analyzer.store_report_in_field("## Report")
    execute_mock.assert_called_once_with("setIncident", {"workplanreport": "## Report"})


def test_store_report_in_field_error(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 4, "Contents": "field not found"}])
    with pytest.raises(DemistoException, match="workplanreport"):
        analyzer.store_report_in_field("## Report")


def test_workplan_analyzer_command(mocker):
    mocker.patch.object(analyzer, "fetch_workplan", return_value=build_workplan())
    store_mock = mocker.patch.object(analyzer, "store_report_in_field")
    file_mock = mocker.patch.object(analyzer, "fileResult", return_value={"File": "report.md"})

    entries = analyzer.workplan_analyzer_command({"workplan_id": "123", "attach_report": "true"})

    store_mock.assert_called_once_with(entries[0].readable_output)

    assert isinstance(entries[0], CommandResults)
    assert entries[0].outputs is None
    assert entries[0].outputs_prefix is None
    assert entries[0].raw_response["WorkplanID"] == "123"
    assert "Workplan Health Report" in entries[0].readable_output
    assert entries[1] == {"File": "report.md"}
    assert file_mock.call_args[0][0] == "123-workplan-health.md"
