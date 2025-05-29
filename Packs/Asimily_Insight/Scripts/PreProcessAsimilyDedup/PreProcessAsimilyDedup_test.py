import demistomock as demisto  # noqa: F401
import pytest
from PreProcessAsimilyDedup import main


@pytest.mark.parametrize(
    "incident, existing_incidents, expected",
    [
        (
            # Case 1: missing type
            {"dbotMirrorId": "abc123"},
            [],
            True,
        ),
        (
            # Case 2: missing mirror id
            {"type": "Asimily Anomaly"},
            [],
            True,
        ),
        (
            # Case 3: unrelated incident type
            {"type": "Other Type", "dbotMirrorId": "abc123"},
            [],
            True,
        ),
        (
            # Case 4: valid type, no duplicates
            {"type": "Asimily Anomaly", "dbotMirrorId": "abc123"},
            [],
            True,
        ),
        (
            # Case 5: valid type, duplicate exists
            {"type": "Asimily Anomaly", "dbotMirrorId": "abc123"},
            [{"id": "123"}],
            False,
        ),
    ],
)
def test_main(mocker, incident, existing_incidents, expected):
    mocker.patch("demistomock.incidents", return_value=[incident])
    mocker.patch("demistomock.executeCommand", return_value=[{"Contents": {"data": existing_incidents}}])
    mock_results = mocker.patch("demistomock.results")

    main()

    mock_results.assert_called_once_with(expected)
