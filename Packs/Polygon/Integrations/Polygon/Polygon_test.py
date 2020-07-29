import json

from Polygon import demisto, Client, ANALGIN_UPLOAD, ATTACH, FILE_TYPE, \
    HASH_REPUTATION

with open("test_data/args.json", "r") as f:
    data = json.load(f)
    MOCKED_CLIENT_KWARGS = data["client_kwargs"]
    MOCKED_UPLOAD_FILE_ARGS = data["upload_file_args"]
    MOCKED_UPLOAD_URL_ARGS = data["upload_url_args"]
    MOCKED_ANALYSIS_INFO_ARGS = data["analysis_info_args"]
    MOCKED_FILE_ARGS = data["file_args"]

with open("test_data/get_report.json", "r") as f:
    MOCKED_REPORT = json.load(f)

with open("test_data/get_file_reputation.json", "r") as f:
    MOCKED_FILE_REPUTATION_DATA = json.load(f)

with open("test_data/upload.json", "r") as f:
    MOCKED_UPLOAD_DATA = json.load(f)

with open("test_data/get_analysis_info.json", "r") as f:
    MOCKED_ANALYSIS_INFO_DATA = json.load(f)

with open("test_data/results.json", "r") as f:
    data = json.load(f)
    MOCKED_UPLOAD_FILE_RESULTS = data["upload_file_results"]
    MOCKED_UPLOAD_URL_RESULTS = data["upload_url_results"]
    MOCKED_ANALYSIS_INFO_RESULTS = data["analysis_info_results"]
    MOCKED_SERIALIZED_REPORT = data["serialized_report"]
    MOCKED_MAIN_INDICATOR = data["main_indicator"]
    MOCKED_PACKAGES_INDICATORS = data["packages_indicators"]
    MOCKED_NETWORK_INDICATORS = data["network_indicators"]
    MOCKED_MONITOR_INDICATORS = data["monitor_indicators"]
    MOCKED_FILE_REPUTATION_RESULTS = data["file_reputation_results"]


class MockedClient(Client):
    def _http_request(self, method, url_suffix, params=None, data=None,
                      files=None, decode=True):
        if url_suffix == ANALGIN_UPLOAD:
            return MOCKED_UPLOAD_DATA
        elif url_suffix == ATTACH.format(1):
            return MOCKED_ANALYSIS_INFO_DATA
        elif url_suffix == HASH_REPUTATION.format("sha1",
                                                  MOCKED_FILE_ARGS["file"][0]):
            return MOCKED_FILE_REPUTATION_DATA
        return dict()

    def upload_file(self, file_name, file_path, password=""):
        return 100


def test_file_command(mocker):
    from Polygon import file_command
    mocked_client = MockedClient(**MOCKED_CLIENT_KWARGS)
    results = file_command(mocked_client, MOCKED_FILE_ARGS)
    assert MOCKED_FILE_REPUTATION_RESULTS == [r.to_context() for r in results]


def test_upload_file_command(mocker):
    from Polygon import upload_file_command
    mocked_client = MockedClient(**MOCKED_CLIENT_KWARGS)
    mocker.patch.object(demisto,
                        "getFilePath",
                        return_value={"name": "abc", "path": "abc"})
    results = upload_file_command(mocked_client, MOCKED_UPLOAD_FILE_ARGS)
    assert results.to_context() == MOCKED_UPLOAD_FILE_RESULTS


def test_upload_url_command(mocker):
    from Polygon import upload_url_command
    mocked_client = MockedClient(**MOCKED_CLIENT_KWARGS)
    results = upload_url_command(mocked_client, MOCKED_UPLOAD_URL_ARGS)
    assert results.to_context() == MOCKED_UPLOAD_URL_RESULTS


def test_analysis_info_command(mocker):
    from Polygon import analysis_info_command
    mocked_client = MockedClient(**MOCKED_CLIENT_KWARGS)
    results = analysis_info_command(mocked_client, MOCKED_ANALYSIS_INFO_ARGS)
    assert [r.to_context() for r in results] == MOCKED_ANALYSIS_INFO_RESULTS


def test_serialize_report_info(mocker):
    from Polygon import serialize_report_info
    results = serialize_report_info(MOCKED_REPORT, FILE_TYPE)
    assert results == MOCKED_SERIALIZED_REPORT


def test_get_main_indicator(mocker):
    from Polygon import get_main_indicator
    results = get_main_indicator(MOCKED_REPORT, FILE_TYPE)
    assert results.to_context() == MOCKED_MAIN_INDICATOR


def test_get_packages_indicators(mocker):
    from Polygon import get_packages_indicators
    results = get_packages_indicators(MOCKED_REPORT)
    assert MOCKED_PACKAGES_INDICATORS == [r.to_context() for r in results]


def test_get_network_indicators(mocker):
    from Polygon import get_network_indicators
    results = get_network_indicators(MOCKED_REPORT)
    assert MOCKED_NETWORK_INDICATORS == [r.to_context() for r in results]


def test_get_monitor_indicators(mocker):
    from Polygon import get_monitor_indicators
    results = get_monitor_indicators(MOCKED_REPORT)
    assert MOCKED_MONITOR_INDICATORS == [r.to_context() for r in results]
