import demistomock as demisto
import PanoraysCheckOlderDuplicate
from PanoraysCheckOlderDuplicate import check_older_duplicate


def test_check_older_duplicate_found(mocker):
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Type": 1, "Contents": {"data": [{"id": "100"}], "total": 0}}],
    )
    assert check_older_duplicate("FIND-1", "200") is True


def test_check_older_duplicate_not_found(mocker):
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Type": 1, "Contents": {"data": [], "total": 0}}],
    )
    assert check_older_duplicate("FIND-1", "200") is False


def test_check_older_duplicate_empty_result(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=None)
    assert check_older_duplicate("FIND-1", "200") is False


def test_main_success(mocker):
    mocker.patch.object(demisto, "args", return_value={"finding_id": "FIND-1", "incident_id": "200"})
    mocker.patch.object(PanoraysCheckOlderDuplicate, "check_older_duplicate", return_value=True)
    mock_results = mocker.patch.object(PanoraysCheckOlderDuplicate, "return_results")
    PanoraysCheckOlderDuplicate.main()
    assert mock_results.called


def test_main_failure(mocker):
    mocker.patch.object(demisto, "args", side_effect=Exception("boom"))
    mock_error = mocker.patch.object(PanoraysCheckOlderDuplicate, "return_error")
    PanoraysCheckOlderDuplicate.main()
    assert mock_error.called
