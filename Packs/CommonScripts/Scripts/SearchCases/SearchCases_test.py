import pytest
from datetime import datetime
import demistomock as demisto
from CommonServerPython import DemistoException
from SearchCases import prepare_start_end_time, main


def test_prepare_start_end_time_normal(monkeypatch):
    args = {"start_time": "2025-09-01T12:00:00", "end_time": "2025-09-02T13:00:00"}
    prepare_start_end_time(args)
    assert args["gte_creation_time"] == "2025-09-01T12:00:00"
    assert args["lte_creation_time"] == "2025-09-02T13:00:00"


def test_prepare_start_end_time_end_without_start():
    args = {"end_time": "2025-09-02T13:00:00"}
    with pytest.raises(DemistoException):
        prepare_start_end_time(args)


def test_prepare_start_end_time_only_start(monkeypatch):
    args = {"start_time": "2025-09-01T12:00:00"}
    monkeypatch.setattr("SearchCases.datetime", datetime)
    prepare_start_end_time(args)
    assert "gte_creation_time" in args
    assert "lte_creation_time" in args

def test_main_success(mocker):
    args = {"page_size": 50}
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch("SearchCases.prepare_start_end_time")
    mocker.patch("SearchCases.return_results")
    mocker.patch("SearchCases.CommandResults")
    mocker.patch.object(
        demisto, "executeCommand", return_value=[{"EntryContext": {"Core.Case": [{"case_id": "1"}]}, "HumanReadable": "hr"}]
    )
    mocker.patch("SearchCases.is_error", return_value=False)
    main()
    SearchCases.return_results.assert_called()


def test_main_error_handling(mocker):
    args = {"page_size": 50}
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch("SearchCases.prepare_start_end_time")
    mocker.patch.object(demisto, "executeCommand", return_value=[{"EntryContext": {}, "HumanReadable": "hr"}])
    mocker.patch("SearchCases.is_error", return_value=True)
    mocker.patch("SearchCases.get_error", return_value="bad error")
    mock_return_error = mocker.patch("SearchCases.return_error")
    main()
    assert mock_return_error.called
