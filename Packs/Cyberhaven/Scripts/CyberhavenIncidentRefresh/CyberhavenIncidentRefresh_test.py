import json
from pathlib import Path

import pytest
import demistomock as demisto
from CommonServerPython import CommandResults

from CyberhavenIncidentRefresh import (
    handle_error,
    map_and_update_incident,
    remove_empty_elements_for_fetch,
    main,
)

EMPTY_INCIDENT_LIST_FIXTURE = Path(__file__).parents[2] / "Integrations" / "Cyberhaven" / "test_data" / "incident_list_empty.json"


class TestRemoveEmptyElementsForFetch:
    @pytest.mark.parametrize(
        "input_val, expected",
        [
            ({"a": 1, "b": None}, {"a": 1}),
            ({"a": 1, "b": {}}, {"a": 1}),
            ({"a": 1, "b": []}, {"a": 1}),
            ({"a": 1, "b": ""}, {"a": 1}),
            ({"a": {"x": 1, "y": None}, "b": None}, {"a": {"x": 1}}),
            ({"level1": {"level2": {"level3": None, "keep": "val"}}}, {"level1": {"level2": {"keep": "val"}}}),
            ([1, None, "", {}, [], 2], [1, 2]),
            ([{"a": 1, "b": None}, {"c": None}], [{"a": 1}]),
            ({}, {}),
            ([], []),
            (42, 42),
            ("hello", "hello"),
            (True, True),
        ],
    )
    def test_remove_empty_elements(self, input_val, expected):
        assert remove_empty_elements_for_fetch(input_val) == expected


class TestHandleError:
    def test_no_error_does_not_raise(self, mocker):
        mocker.patch("CyberhavenIncidentRefresh.isError", return_value=False)
        handle_error([{"Type": 1, "Contents": "ok"}])

    def test_error_calls_return_error(self, mocker):
        mocker.patch("CyberhavenIncidentRefresh.isError", return_value=True)
        mock_return_error = mocker.patch("CyberhavenIncidentRefresh.return_error", side_effect=SystemExit)
        with pytest.raises(SystemExit):
            handle_error([{"Type": 4, "Contents": "something went wrong"}])
        mock_return_error.assert_called_once_with("something went wrong")


class TestDemistoException:
    """Verify DemistoException raised for missing incident_id is caught and reported correctly."""

    @pytest.mark.parametrize(
        "args_val",
        [
            {},
            {"incident_id": ""},
            {"incident_id": None},
        ],
    )
    def test_exception_message_in_return_error(self, mocker, args_val):
        mocker.patch.object(demisto, "args", return_value=args_val)
        mocker.patch.object(demisto, "error")
        return_error_mock = mocker.patch("CyberhavenIncidentRefresh.return_error")

        main()

        error_msg = return_error_mock.call_args[0][0]
        assert "Failed to execute CyberhavenIncidentRefresh" in error_msg
        assert "'incident_id' is required" in error_msg

    def test_traceback_logged_on_demisto_exception(self, mocker):
        mocker.patch.object(demisto, "args", return_value={"incident_id": ""})
        error_mock = mocker.patch.object(demisto, "error")
        mocker.patch("CyberhavenIncidentRefresh.return_error")

        main()

        error_mock.assert_called_once()
        logged_traceback = error_mock.call_args[0][0]
        assert "Traceback" in logged_traceback
        assert "'incident_id' is required." in logged_traceback


class TestMapAndUpdateIncident:
    def test_returns_command_results(self, mocker):
        mocker.patch.object(demisto, "mapObject", return_value={"Field Name": "value"})
        mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1}])

        result = map_and_update_incident({"key": "val"}, "TestMapper", "TestType")

        assert isinstance(result, CommandResults)
        assert result.readable_output == "Incident has been synchronized successfully."

    def test_key_normalisation_lowercase_nospace(self, mocker):
        mocker.patch.object(demisto, "mapObject", return_value={"Field Name": "v", "UPPER KEY": "u"})
        exec_mock = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1}])

        map_and_update_incident({}, "Mapper", "Type")

        called_kwargs = exec_mock.call_args[0][1]
        assert "fieldname" in called_kwargs
        assert "upperkey" in called_kwargs

    def test_set_incident_called_with_mapped_data(self, mocker):
        mocker.patch.object(demisto, "mapObject", return_value={"severity": "high"})
        exec_mock = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1}])

        map_and_update_incident({"a": 1}, "Mapper", "Type")

        exec_mock.assert_called_once_with("setIncident", {"severity": "high"})

    def test_empty_mapped_data(self, mocker):
        mocker.patch.object(demisto, "mapObject", return_value={})
        exec_mock = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1}])

        result = map_and_update_incident({}, "Mapper", "Type")

        exec_mock.assert_called_once_with("setIncident", {})
        assert isinstance(result, CommandResults)


class TestMain:
    def _patch_common(self, mocker, incident_id="INC-001", command_result=None, resources=None):
        if command_result is None:
            resources = resources if resources is not None else [{"id": "INC-001", "severity": "high"}]
            command_result = [{"Type": 1, "Contents": {"resources": resources}}]

        mocker.patch.object(demisto, "args", return_value={"incident_id": incident_id})
        mocker.patch.object(demisto, "executeCommand", return_value=command_result)
        mocker.patch("CyberhavenIncidentRefresh.isError", return_value=False)
        mocker.patch.object(demisto, "mapObject", return_value={"severity": "high"})
        return command_result

    def test_successful_refresh(self, mocker):
        self._patch_common(mocker)
        return_results_mock = mocker.patch("CyberhavenIncidentRefresh.return_results")
        main()
        return_results_mock.assert_called_once()
        result = return_results_mock.call_args[0][0]
        assert isinstance(result, CommandResults)
        assert result.readable_output == "Incident has been synchronized successfully."

    @pytest.mark.parametrize(
        "args_val",
        [
            {},
            {"incident_id": ""},
            {"incident_id": None},
        ],
    )
    def test_missing_incident_id_raises_demisto_exception(self, mocker, args_val):
        mocker.patch.object(demisto, "args", return_value=args_val)
        mocker.patch.object(demisto, "error")
        return_error_mock = mocker.patch("CyberhavenIncidentRefresh.return_error", side_effect=SystemExit)
        with pytest.raises(SystemExit):
            main()
        call_msg = return_error_mock.call_args[0][0]
        assert "CyberhavenIncidentRefresh" in call_msg
        assert "incident_id" in call_msg

    @pytest.mark.parametrize(
        "contents",
        [
            {"resources": []},
            "error string",
        ],
    )
    def test_remote_incident_not_found_returns_error(self, mocker, contents):
        mocker.patch.object(demisto, "args", return_value={"incident_id": "INC-002"})
        mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": contents}])
        mocker.patch("CyberhavenIncidentRefresh.isError", return_value=False)
        map_mock = mocker.patch.object(demisto, "mapObject")
        return_error_mock = mocker.patch("CyberhavenIncidentRefresh.return_error", side_effect=SystemExit)

        with pytest.raises(SystemExit):
            main()

        map_mock.assert_not_called()
        assert "INC-002" in return_error_mock.call_args[0][0]

    def test_remote_incident_not_found_uses_empty_fixture(self, mocker):
        empty_response = json.loads(EMPTY_INCIDENT_LIST_FIXTURE.read_text(encoding="utf-8"))
        mocker.patch.object(demisto, "args", return_value={"incident_id": "INC-003"})
        mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": empty_response}])
        mocker.patch("CyberhavenIncidentRefresh.isError", return_value=False)
        map_mock = mocker.patch.object(demisto, "mapObject")
        return_error_mock = mocker.patch("CyberhavenIncidentRefresh.return_error", side_effect=SystemExit)

        with pytest.raises(SystemExit):
            main()

        map_mock.assert_not_called()
        assert "INC-003" in return_error_mock.call_args[0][0]

    def test_empty_command_result_calls_return_error(self, mocker):
        mocker.patch.object(demisto, "args", return_value={"incident_id": "INC-006"})
        mocker.patch.object(demisto, "executeCommand", return_value=[])
        return_error_mock = mocker.patch("CyberhavenIncidentRefresh.return_error", side_effect=SystemExit)

        with pytest.raises(SystemExit):
            main()

        return_error_mock.assert_called_once_with("No response received from cyberhaven-incident-list.")

    def test_command_error_stops_execution(self, mocker):
        mocker.patch.object(demisto, "args", return_value={"incident_id": "INC-004"})
        error_result = [{"Type": 4, "Contents": "API error occurred"}]
        mocker.patch.object(demisto, "executeCommand", return_value=error_result)
        mocker.patch("CyberhavenIncidentRefresh.isError", return_value=True)
        return_error_mock = mocker.patch("CyberhavenIncidentRefresh.return_error", side_effect=SystemExit)

        with pytest.raises(SystemExit):
            main()

        return_error_mock.assert_called_once_with("API error occurred")

    def test_uses_correct_mapper_and_type(self, mocker):
        self._patch_common(mocker)
        map_mock = mocker.patch.object(demisto, "mapObject", return_value={})
        mocker.patch("CyberhavenIncidentRefresh.return_results")

        main()

        map_mock.assert_called_once_with(
            {"id": "INC-001", "severity": "high"},
            "Cyberhaven - Incoming Mapper",
            "Cyberhaven Incident",
        )

    def test_incident_list_called_with_correct_args(self, mocker):
        self._patch_common(mocker)
        exec_mock = mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[{"Type": 1, "Contents": {"resources": [{"id": "INC-001"}]}}],
        )
        mocker.patch.object(demisto, "mapObject", return_value={})
        mocker.patch("CyberhavenIncidentRefresh.return_results")

        main()

        first_call = exec_mock.call_args_list[0]
        assert first_call[0][0] == "cyberhaven-incident-list"
        assert first_call[0][1] == {"incident_ids": "INC-001"}

    def test_unexpected_exception_calls_return_error(self, mocker):
        mocker.patch.object(demisto, "args", side_effect=RuntimeError("unexpected"))
        mocker.patch.object(demisto, "error")
        return_error_mock = mocker.patch("CyberhavenIncidentRefresh.return_error", side_effect=SystemExit)

        with pytest.raises(SystemExit):
            main()

        assert "CyberhavenIncidentRefresh" in return_error_mock.call_args[0][0]
        assert "unexpected" in return_error_mock.call_args[0][0]

    def test_resource_empty_elements_removed_before_mapping(self, mocker):
        resource = {"id": "INC-005", "empty_field": None, "data": "value"}
        mocker.patch.object(demisto, "args", return_value={"incident_id": "INC-005"})
        mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[{"Type": 1, "Contents": {"resources": [resource]}}],
        )
        mocker.patch("CyberhavenIncidentRefresh.isError", return_value=False)
        map_mock = mocker.patch.object(demisto, "mapObject", return_value={})
        mocker.patch("CyberhavenIncidentRefresh.return_results")

        main()

        passed_data = map_mock.call_args[0][0]
        assert "empty_field" not in passed_data
        assert passed_data.get("data") == "value"
