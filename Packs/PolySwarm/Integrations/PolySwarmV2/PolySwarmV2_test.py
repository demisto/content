import os
import io

import demistomock as demisto
from CommonServerPython import EntryType

import PolySwarmV2
from PolySwarmV2 import PolyswarmConnector

import pytest
import vcr as libvcr

pytest_plugins = "test_data.vendored_pytest_vcr"

TEST_FOLDER = os.path.dirname(os.path.abspath(__file__))

TEST_SCAN_UUID = "95039375646493045"
TEST_SCAN_DOMAIN = "preesallmobilevalating23-gmail[.]com".replace("[.]", ".")
TEST_SCAN_IP = "205[.]210[.]31[.]208".replace("[.]", ".")
TEST_SCAN_URL = "http://preesallmobilevalating23-gmail[.]com".replace("[.]", ".")
TEST_HASH_FILE = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
TEST_ENTRY_ID = "XXXXX"

MOCK_API_URL = os.getenv("POLYSWARM_API_URI", "https://api.polyswarm.network/v3/")

POLYSWARM_URL_RESULTS_BASE = "https://polyswarm.network/scan/results/file"
POLYSWARM_URL_RESULTS = f"{POLYSWARM_URL_RESULTS_BASE}/{TEST_HASH_FILE}"
POLYSWARM_COMMUNITY = "default"

MOCK_PARAMS = {
    "api_key": os.getenv("POLYSWARM_API_KEY", "XXXXXXXXXXXXXXXXXXXXXXXXXX"),
    "base_url": MOCK_API_URL,
    "polyswarm_community": POLYSWARM_COMMUNITY,
}

MOCK_FILE_INFO = {"name": "MaliciousFile.exe", "path": "/path/MaliciousFile.exe"}


@pytest.fixture(autouse=True)
def patch_VCRHTTPResponse_version_string():
    # FROM: https://github.com/kevin1024/vcrpy/issues/888#issuecomment-2561302419
    # Can be removed after vcrpy gets updated
    from vcr.stubs import VCRHTTPResponse

    if not hasattr(VCRHTTPResponse, "version_string"):
        VCRHTTPResponse.version_string = None


@pytest.fixture(scope="module")
def vcr_config():
    redacted_data = [
        ("authorization", "XXXXXXXXXXXXXXXXXXXXXXXXXX"),
        ("X-Amz-Credential", "AKIADEADBEEFCREDENTIAL"),
        ("X-Amz-Signature", "2345678deadbeefdeadbeef2345678deadbeefdeadbeef2345678deadbeef"),
        ("X-Billing-ID", "876543218765"),
    ]

    def redact_response(response):
        for name, new_value in redacted_data:
            if name in response["headers"]:
                response["headers"][name] = new_value
        return response

    return {
        "serializer": "yaml",
        "cassette_library_dir": os.path.join(TEST_FOLDER, "test_data/fixtures/vcr/"),
        "path_transformer": libvcr.VCR.ensure_suffix(".tape"),
        "record_mode": libvcr.record_mode.RecordMode.ONCE,  # .ALL, # .NONE
        "filter_headers": redacted_data,
        "filter_post_data_parameters": redacted_data,
        "filter_query_parameters": redacted_data,
        "before_record_response": redact_response,
    }


@pytest.mark.vcr()
def test_file_scan(mocker):
    mocker.patch.object(demisto, "debug", return_value=None)
    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, "getFilePath", return_value=MOCK_FILE_INFO)
    mocker.patch.object(PolySwarmV2, "fileResult", return_value={"Type": EntryType.ENTRY_INFO_FILE})

    polyswarm = PolyswarmConnector()

    param = {"entryID": TEST_ENTRY_ID}

    def fake_open(*args, **kwargs):
        result = io.StringIO("X5O!P" r"%@AP[4\PZ" "X54(P^)7CC" ")7}$EICAR-STANDARD-ANTIVIRUS" "-TEST-FILE!$H+H*")
        result.seek(0)
        return result

    mocker.patch("builtins.open", fake_open)

    results = polyswarm.detonate_file(param["entryID"])
    results = results.to_context()

    assert results["Contents"]["Positives"] >= "10"
    assert results["Contents"]["Total"] >= "10"
    assert results["Contents"]["Scan_UUID"] == TEST_HASH_FILE
    assert results["Contents"]["Permalink"].startswith(POLYSWARM_URL_RESULTS)
    assert results["Contents"]["Artifact"] == TEST_HASH_FILE


@pytest.mark.vcr()
@pytest.mark.parametrize(
    "kind,scan_target,results_id",
    [
        pytest.param(
            "domain", TEST_SCAN_DOMAIN, "bd870bed700771f4fbe8992b5022fa655df743a397278c60cc40f4d25dac4052", id="domain"
        ),  # test Domain scan reputation
        pytest.param(
            "ip", TEST_SCAN_IP, "af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2", id="ip"
        ),  # test IP scan reputation
        pytest.param(
            "url", TEST_SCAN_URL, "dca3fb56531786e4141a7fdcdfaf0e74b64755b2514c2712881124e0449ba41d", id="url"
        ),  # test URL scan reputation
    ],
)
def test_reputation(mocker, kind, scan_target, results_id):
    mocker.patch.object(demisto, "debug", return_value=None)
    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)
    mocker.patch.object(PolySwarmV2, "fileResult", return_value={"Type": EntryType.ENTRY_INFO_FILE})

    polyswarm = PolyswarmConnector()

    param = {kind: [scan_target]}
    results = polyswarm.url_reputation(param, kind)
    results = results[0].to_context()
    assert results["Contents"]["Positives"] >= "1"
    assert results["Contents"]["Total"] >= "3"
    assert results["Contents"]["Scan_UUID"] == scan_target
    assert results["Contents"]["Permalink"].startswith(
        f"{POLYSWARM_URL_RESULTS_BASE}/{results_id}/"
    ), f'REALITY: {results["Contents"]["Permalink"]}'
    assert results["Contents"]["Artifact"] == scan_target


@pytest.mark.vcr()
def test_polyswarm_get_report(mocker):
    mocker.patch.object(demisto, "debug", return_value=None)
    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)
    mocker.patch.object(PolySwarmV2, "fileResult", return_value={"Type": EntryType.ENTRY_INFO_FILE})

    polyswarm = PolyswarmConnector()

    param = {"scan_uuid": TEST_HASH_FILE}

    results = polyswarm.get_report(param["scan_uuid"])
    results = results[0].to_context()

    assert int(results["Contents"]["Positives"]) >= 6
    assert int(results["Contents"]["Total"]) >= 11
    assert results["Contents"]["Scan_UUID"] == TEST_HASH_FILE
    assert results["Contents"]["Permalink"].startswith(POLYSWARM_URL_RESULTS), f'REALITY: {results["Contents"]["Permalink"]}'
    assert results["Contents"]["Artifact"] == TEST_HASH_FILE


@pytest.mark.vcr()
def test_file_rescan(mocker):
    mocker.patch.object(demisto, "debug", return_value=None)
    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)
    mocker.patch.object(PolySwarmV2, "fileResult", return_value={"Type": EntryType.ENTRY_INFO_FILE})

    polyswarm = PolyswarmConnector()

    param = {"hash": TEST_HASH_FILE}

    results = polyswarm.rescan_file(param["hash"])
    results = results[0].to_context()

    assert int(results["Contents"]["Positives"]) >= 1
    assert int(results["Contents"]["Total"]) >= 3
    assert results["Contents"]["Scan_UUID"] == TEST_HASH_FILE
    assert results["Contents"]["Permalink"].startswith(POLYSWARM_URL_RESULTS), f'REALITY: {results["Contents"]["Permalink"]}'
    assert results["Contents"]["Artifact"] == TEST_HASH_FILE


@pytest.mark.vcr()
def test_get_file(mocker):
    mocker.patch.object(demisto, "debug", return_value=None)
    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)

    polyswarm = PolyswarmConnector()

    param = {"hash": TEST_HASH_FILE}

    results = polyswarm.get_file(param["hash"])

    try:
        assert results["File"] == TEST_HASH_FILE
    finally:
        # Cannot mock fileResult as we are testing also its return value.
        # Instead, lets cleanup its leftovers
        os.unlink("1_" + results["FileID"])


@pytest.mark.vcr()
def test_file(mocker):
    mocker.patch.object(demisto, "debug", return_value=None)
    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)
    mocker.patch.object(PolySwarmV2, "fileResult", return_value={"Type": EntryType.ENTRY_INFO_FILE})

    polyswarm = PolyswarmConnector()

    param = {"hash": TEST_HASH_FILE}

    results = polyswarm.file_reputation(param["hash"])
    results = results[0].to_context()

    assert int(results["Contents"]["Positives"]) >= 6
    assert int(results["Contents"]["Total"]) >= 9
    assert results["Contents"]["Scan_UUID"] == TEST_HASH_FILE
    assert results["Contents"]["Permalink"].startswith(POLYSWARM_URL_RESULTS), f'REALITY: {results["Contents"]["Permalink"]}'
    assert results["Contents"]["Artifact"] == TEST_HASH_FILE
