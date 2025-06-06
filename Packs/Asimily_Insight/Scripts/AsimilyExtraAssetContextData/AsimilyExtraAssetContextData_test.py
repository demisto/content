import pytest
import demistomock as demisto  # noqa: F401
from AsimilyExtraAssetContextData import main


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
    mocker.patch("demistomock.context", return_value=mock_context_data)

    # Patch where they're used — in AsimilyExtraAssetContextData.py
    mock_return = mocker.patch("AsimilyExtraAssetContextData.return_results")
    mock_table = mocker.patch("AsimilyExtraAssetContextData.tableToMarkdown", return_value="Mocked Markdown Table")

    main()

    mock_table.assert_called_once()
    mock_return.assert_called_once()

    result = mock_return.call_args[0][0]
    assert result.readable_output == "Mocked Markdown Table"
    assert result.outputs_prefix == "AsimilyInsight.Asset"
    assert result.outputs_key_field == "asimilydeviceid"
