import pytest
import demistomock as demisto
from GetLatestCleanRestorePoint import find_latest_restore, main


@pytest.mark.parametrize(
    "data, expected",
    [
        (
            [{"id": "1", "backupId": "b1", "malwareStatus": "Clean"}],
            {"id": "1", "backupId": "b1", "malwareStatus": "Clean"},
        ),
        (
            [{"id": "1", "backupId": "b1", "malwareStatus": "Infected"}],
            {"id": "", "backupId": ""},
        ),
        (
            [],
            {"id": "", "backupId": ""},
        ),
        (
            [
                {"id": "1", "backupId": "b1", "malwareStatus": "Infected"},
                {"id": "2", "backupId": "b2", "malwareStatus": "Clean"},
                {"id": "3", "backupId": "b3", "malwareStatus": "Clean"},
            ],
            {"id": "2", "backupId": "b2", "malwareStatus": "Clean"},
        ),
        (
            [
                {"id": "1", "backupId": "b1", "malwareStatus": "Infected"},
                {"id": "2", "backupId": "b2", "malwareStatus": "Infected"},
            ],
            {"id": "", "backupId": ""},
        ),
    ],
)
def test_find_latest_restore(data, expected):
    assert find_latest_restore(data) == expected


@pytest.mark.parametrize(
    "args, expected_outputs",
    [
        (
            {"data": {"id": "1", "backupId": "b1", "malwareStatus": "Clean"}},
            {"id": "1", "backupId": "b1", "malwareStatus": "Clean"},
        ),
        (
            {
                "data": [
                    {"id": "1", "backupId": "b1", "malwareStatus": "Infected"},
                    {"id": "2", "backupId": "b2", "malwareStatus": "Clean"},
                ]
            },
            {"id": "2", "backupId": "b2", "malwareStatus": "Clean"},
        ),
        (
            {"data": [{"id": "1", "backupId": "b1", "malwareStatus": "Infected"}]},
            {"id": "", "backupId": ""},
        ),
    ],
)
def test_main(mocker, args, expected_outputs):
    mocker.patch.object(demisto, "args", return_value=args)
    mock_return_results = mocker.patch("GetLatestCleanRestorePoint.return_results")
    main()
    mock_return_results.assert_called_once()
    command_results = mock_return_results.call_args[0][0]
    assert command_results.outputs_prefix == "Veeam.LatestCleanRestorePoint"
    assert command_results.outputs == expected_outputs
