import pytest


@pytest.fixture(autouse=True)
def patch_missing_modules(mocker):
    # This must happen before any import that relies on CommonServerPython
    mocker.patch.dict("sys.modules", {"DemistoClassApiModule": mocker.MagicMock()})


@pytest.fixture
def mock_context_data():
    return {
        "AsimilyInsight": {
            "Asset": {
                "asimilydeviceid": "12345",
                "asimilydevicemacaddress": "00:11:22:33:44:55",
                "asimilydeviceipv4address": "192.168.1.1",
            }
        }
    }


def test_main(mocker, mock_context_data):
    # Delay all imports that depend on CommonServerPython until after patch
    from CommonServerPython import CommandResults
    from AsimilyExtraAssetContextData import main

    mocker.patch("demistomock.context", return_value=mock_context_data)
    mock_return = mocker.patch("AsimilyExtraAssetContextData.return_results")
    mock_table = mocker.patch("AsimilyExtraAssetContextData.tableToMarkdown", return_value="Mocked Markdown Table")

    main()

    mock_table.assert_called_once()
    mock_return.assert_called_once()

    result = mock_return.call_args[0][0]
    assert isinstance(result, CommandResults)
