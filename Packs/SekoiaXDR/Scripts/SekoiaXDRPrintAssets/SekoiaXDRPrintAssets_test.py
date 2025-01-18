import demistomock as demisto
import SekoiaXDRPrintAssets


def test_assets_info(mocker):
    assets_ids = ["1", "2"]
    asset = {
        "name": "asset",
        "description": "description",
    }
    mocker.patch.object(
        demisto, "executeCommand", return_value=[{"Type": 3, "Contents": asset}]
    )
    assert len(SekoiaXDRPrintAssets.get_assets_info(assets_ids)) == 2


def test_assets_ids(mocker):
    alert_infos = {"assets": ["1", "2"]}
    assets_infos = [
        {"description": "alVEdEMFNEMcBTNodDPL", "name": "name1"},
        {"description": "alVEdEMFNEazedadazedL", "name": "name2"},
    ]
    mocker.patch.object(
        demisto, "executeCommand", return_value=[{"Type": 3, "Contents": alert_infos}]
    )
    mocker.patch.object(
        SekoiaXDRPrintAssets, "get_assets_info", return_value=assets_infos
    )
    assert "name1" in SekoiaXDRPrintAssets.get_assets_ids("1234")
    assert "name2" in SekoiaXDRPrintAssets.get_assets_ids("1234")
