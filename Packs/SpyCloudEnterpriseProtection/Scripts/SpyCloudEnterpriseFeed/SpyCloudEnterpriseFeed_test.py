import io
from json import loads
import SpyCloudEnterpriseFeed


def util_load_json(path):
    with io.open(path, mode="r") as f:
        return loads(f.read())


def test_create_custom_field():
    watchlist_data = util_load_json("test_data/watch_list.json")
    result = SpyCloudEnterpriseFeed.create_custom_field(watchlist_data)
    expected_output = util_load_json("test_data/expected_output.json")
    assert result == expected_output


def test_main(monkeypatch):
    def mock_args():
        return {
            "since": "-1days",
            "until": "now",
            "since_modification_date": "-1days",
            "until_modification_date": "now",
        }

    def mock_executeCommand(command, args):
        watchlist_data = util_load_json("test_data/watch_list.json")
        return [{"Contents": [watchlist_data]}]

    monkeypatch.setattr(SpyCloudEnterpriseFeed.demisto, "args", mock_args)
    monkeypatch.setattr(
        SpyCloudEnterpriseFeed.demisto, "executeCommand", mock_executeCommand
    )

    SpyCloudEnterpriseFeed.main()
