from typing import Any
from CommonServerPython import CommandResults, DemistoException
import json
import pytest
import importlib

MD_Aether = importlib.import_module("MetaDefenderAether")


def util_load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return MD_Aether.Client(base_url="https://test.com", api_key="mockkey", proxy=False, verify=False)


APIKEY_VALIDATION_SUCCESS = {
    "accountId": "1234",
    "username": "Aniko",
    "email": "aniko@o.com",
}


@pytest.mark.parametrize("result, expected", [(APIKEY_VALIDATION_SUCCESS, "ok")])
def test_test_module_positive(mocker, client, result, expected):
    mocker.patch.object(client, "test_module", return_value=result)
    response = MD_Aether.test_module_command(client)
    assert response == expected


APIKEY_VALIDATION_FAILURE = {"detail": "Could not validate credentials"}


@pytest.mark.parametrize("result, expected", [(APIKEY_VALIDATION_FAILURE, DemistoException)])
def test_test_module_negative(mocker, client, result, expected):
    mocker.patch.object(client, "test_module", return_value=result)
    with pytest.raises(Exception) as e:
        MD_Aether.test_module_command(client)
    assert isinstance(e.value, expected)


def test_search_query_command_hash_badfile(mocker, client):
    raw_response = util_load_json("test_data/query_hash_badfile.json")

    mocker.patch.object(client, "get_search_query", return_value=raw_response)
    response = MD_Aether.search_query_command(client, {})
    assert response[0].outputs["file"]["sha256"] == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].outputs["verdict"] == "malicious"


def test_search_query_command_hash_cleanfile(mocker, client):
    raw_response = util_load_json("test_data/query_hash_cleanfile.json")

    mocker.patch.object(client, "get_search_query", return_value=raw_response)
    response = MD_Aether.search_query_command(client, {})

    assert response[0].outputs["file"]["sha256"] == "b280719e9f2dd010260e6a023e0d69c64fbee8b6cbb8669c722a1da8142d3325"
    assert response[0].outputs["verdict"] == "no_threat"


def test_search_query_command_url(mocker, client):
    raw_response = util_load_json("test_data/query_url_github.json")

    mocker.patch.object(client, "get_search_query", return_value=raw_response)
    response = MD_Aether.search_query_command(client, {})

    assert len(response) == 10

    assert response[0].outputs["file"]["sha256"] == "09a8b930c8b79e7c313e5e741e1d59c39ae91bc1f10cdefa68b47bf77519be57"
    assert response[0].outputs["verdict"] == "no_threat"
    assert response[1].outputs["file"]["sha256"] == "5adca05a86dbcaaa1049b14b364a9ddf305e2476064e2c0590e4ebb49696fa3b"
    assert response[4].outputs["verdict"] == "suspicious"


@pytest.mark.parametrize(
    "args, outputs",
    [
        ({"limit": "-1"}, DemistoException),
        ({"limit": "100"}, DemistoException),
        ({"limit": "a"}, Exception),
        ({"page": "-1"}, DemistoException),
        ({"page": "a"}, Exception),
        ({"page_size": "1"}, DemistoException),
        ({"page_size": "a"}, Exception),
    ],
)
def test_search_query_command_argument_check(mocker, client, args, outputs):
    mocker.patch.object(client, "get_search_query", return_value={})
    with pytest.raises(Exception) as e:
        MD_Aether.search_query_command(client, args)
    assert isinstance(e.value, outputs)


def test_scan_command_url_polling_waiting(requests_mock, mocker, client):
    from CommonServerPython import ScheduledCommand

    mocker.patch.object(client, "_http_request", return_value={"flow_id": "1234"})
    mocker.patch.object(ScheduledCommand, "raise_error_if_not_supported", return_value=None)
    mocker.patch("builtins.open", create=True)

    args = {
        "entry_id": "test_entry_id",
        "description": "test_file",
        "tags": "tag1",
        "password": "pass1234",
        "is_private": True,
    }

    response = MD_Aether.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'


def test_scan_command_url_polling(mocker, client):
    from CommonServerPython import ScheduledCommand

    args = {"url": "https://github.com/"}
    raw_response = util_load_json("test_data/scan_command_url_response.json")
    mocker.patch.object(client, "_http_request", return_value={"flow_id": "1234"})
    mocker.patch.object(ScheduledCommand, "raise_error_if_not_supported", return_value=None)

    response = MD_Aether.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'

    polling_args = {
        "flow_id": "1234",
        "hide_polling_output": True,
        "continue_to_poll": True,
        "url": "test.com",
    }
    mocker.patch.object(client, "get_scan_result", return_value=raw_response)
    response = MD_Aether.scan_command(client, polling_args)

    assert response[0].indicator.dbot_score.indicator == "09a8b930c8b79e7c313e5e741e1d59c39ae91bc1f10cdefa68b47bf77519be57"
    assert response[0].indicator.dbot_score.score == 1
    assert response[0].indicator.dbot_score.integration_name == "MetaDefender Aether"
    assert response[0].indicator.name == "https://github.com/"
    assert response[0].indicator.sha256 == "09a8b930c8b79e7c313e5e741e1d59c39ae91bc1f10cdefa68b47bf77519be57"
    assert response[0].outputs["finalVerdict"]["threatLevel"] == 0.25
    assert len(response[0].outputs["allTags"]) == 4
    assert response[0].outputs["overallState"] == "success_partial"
    assert response[0].outputs["taskReference"]["name"] == "transform-file"
    assert response[0].outputs["file"]["name"] == "https://github.com/"
    assert response[0].outputs["file"]["hash"] == "09a8b930c8b79e7c313e5e741e1d59c39ae91bc1f10cdefa68b47bf77519be57"
    assert response[0].outputs["file"]["type"] == "other"


def test_scan_command_file_polling(mocker, client):
    from CommonServerPython import ScheduledCommand

    args = {"entry_id": "test_entry_id"}
    raw_response = util_load_json("test_data/scan_command_zip_response.json")
    mocker.patch.object(client, "post_sample", return_value={"flow_id": "1234"})
    mocker.patch.object(ScheduledCommand, "raise_error_if_not_supported", return_value=None)

    response = MD_Aether.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'

    polling_args = {
        "flow_id": "1234",
        "hide_polling_output": True,
        "continue_to_poll": True,
        "url": "test.com",
    }
    mocker.patch.object(client, "_http_request", return_value=raw_response)
    response = MD_Aether.scan_command(client, polling_args)

    assert len(response) == 3

    assert response[0].indicator.dbot_score.indicator == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].indicator.dbot_score.score == 3
    assert response[0].indicator.dbot_score.integration_name == "MetaDefender Aether"
    assert response[0].indicator.name == "bad_file.exe"
    assert response[0].indicator.sha256 == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].outputs["finalVerdict"]["threatLevel"] == 1
    assert len(response[0].outputs["allTags"]) == 9
    assert response[0].outputs["overallState"] == "success_partial"
    assert response[0].outputs["taskReference"]["name"] == "transform-file"
    assert response[0].outputs["file"]["name"] == "bad_file.exe"
    assert response[0].outputs["file"]["hash"] == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].outputs["file"]["type"] == "pe"

    assert response[1].indicator.dbot_score.indicator == "ede5221225a03b12d11df11f4babf24e9c4a55e05aff27612813dd44876a71c2"
    assert response[1].indicator.dbot_score.score == 1
    assert response[1].indicator.dbot_score.integration_name == "MetaDefender Aether"
    assert response[1].indicator.name == "munkaltatoi.docx"
    assert response[1].indicator.sha256 == "ede5221225a03b12d11df11f4babf24e9c4a55e05aff27612813dd44876a71c2"
    assert response[1].outputs["finalVerdict"]["threatLevel"] == 0.25
    assert len(response[1].outputs["allTags"]) == 3
    assert response[1].outputs["overallState"] == "success"
    assert response[1].outputs["taskReference"]["name"] == "transform-file"
    assert response[1].outputs["file"]["name"] == "munkaltatoi.docx"
    assert response[1].outputs["file"]["hash"] == "ede5221225a03b12d11df11f4babf24e9c4a55e05aff27612813dd44876a71c2"
    assert response[1].outputs["file"]["type"] == "ms-office"

    assert response[2].indicator.dbot_score.indicator == "2ee79f9a52e660f2322985c72c9dffefdfb5a3c302576d61b4e629d049098cb5"
    assert response[2].indicator.dbot_score.score == 1
    assert response[2].indicator.dbot_score.integration_name == "MetaDefender Aether"
    assert response[2].indicator.name == "poorguy.png"
    assert response[2].indicator.sha256 == "2ee79f9a52e660f2322985c72c9dffefdfb5a3c302576d61b4e629d049098cb5"
    assert response[2].outputs["finalVerdict"]["threatLevel"] == 0.25
    assert len(response[2].outputs["allTags"]) == 2
    assert response[2].outputs["overallState"] == "success"
    assert response[2].outputs["taskReference"]["name"] == "transform-file"
    assert response[2].outputs["file"]["name"] == "poorguy.png"
    assert response[2].outputs["file"]["hash"] == "2ee79f9a52e660f2322985c72c9dffefdfb5a3c302576d61b4e629d049098cb5"
    assert response[2].outputs["file"]["type"] == "other"


def test_scan_command_file_invalid_password(mocker, client):
    from CommonServerPython import ScheduledCommand

    args = {"entry_id": "test_entry_id"}
    raw_response = util_load_json("test_data/scan_command_zip_invalid_pass.json")
    mocker.patch.object(client, "post_sample", return_value={"flow_id": "1234"})
    mocker.patch.object(ScheduledCommand, "raise_error_if_not_supported", return_value=None)

    response = MD_Aether.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'

    polling_args = {
        "flow_id": "1234",
        "hide_polling_output": True,
        "continue_to_poll": True,
        "url": "test.com",
    }
    mocker.patch.object(client, "get_scan_result", return_value=raw_response)

    with pytest.raises(Exception) as e:
        MD_Aether.scan_command(client, polling_args)
    assert isinstance(e.value, DemistoException)


def test_password_validator():
    raw_response = util_load_json("test_data/scan_command_zip_valid_pass.json")
    is_valid = MD_Aether.is_valid_pass(raw_response)
    assert is_valid


@pytest.mark.parametrize(
    "report, DBotScore",
    [
        (
            {
                "finalVerdict": {
                    "verdict": "UNDETERMINED",
                    "threatLevel": 0,
                }
            },
            0,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "TRUSTED",
                    "threatLevel": -1,
                }
            },
            1,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "NO_THREAT_DETECTED",
                    "threatLevel": 0.25,
                }
            },
            1,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "CONFIRMED_THREAT",
                    "threatLevel": 1.0,
                }
            },
            3,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "HIGH_RISK",
                    "threatLevel": 0.75,
                }
            },
            3,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "LOW_RISK",
                    "threatLevel": 0.5,
                }
            },
            2,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "SOME_FANCY",
                    "threatLevel": "not_a_number",
                }
            },
            0,
        ),
    ],
)
def test_build_one_reputation_result(report, DBotScore):
    reputation_result = MD_Aether.build_one_reputation_result(report)
    score = reputation_result.indicator.dbot_score.score
    assert score == DBotScore


def test_post_sample_url(mocker, client):
    """Test post_sample submits a URL and returns the API response."""
    mocker.patch.object(client, "_http_request", return_value={"flow_id": "url-1234"})
    result = client.post_sample({"url": "https://example.com", "description": "test", "tags": "t1"})
    assert result == {"flow_id": "url-1234"}
    client._http_request.assert_called_once_with(
        method="POST",
        url_suffix="/scan/url",
        ok_codes=(200,),
        data={"url": "https://example.com", "description": "test", "tags": "t1"},
    )


def test_post_sample_no_url_no_entry_raises(client):
    """Test post_sample raises when neither url nor entry_id is provided."""
    with pytest.raises(DemistoException, match="No file or URL was provided."):
        client.post_sample({})


def test_post_sample_file(mocker, client):
    """Test post_sample submits a file via entry_id."""
    import demistomock as demisto

    mocker.patch.object(demisto, "getFilePath", return_value={"path": "/tmp/test.txt", "name": "test.txt"})
    mock_open = mocker.mock_open(read_data=b"file-content")
    mocker.patch("builtins.open", mock_open)
    mocker.patch.object(client, "_http_request", return_value={"flow_id": "file-5678"})

    result = client.post_sample({"entry_id": "entry123", "password": "secret", "is_private": True})
    assert result == {"flow_id": "file-5678"}


def test_post_sample_file_not_found(mocker, client):
    """Test post_sample raises when entry_id file is not found."""
    import demistomock as demisto

    mocker.patch.object(demisto, "getFilePath", side_effect=Exception("File not found"))
    with pytest.raises(DemistoException, match="Failed to find file entry"):
        client.post_sample({"entry_id": "bad-entry"})


def test_search_query_command_empty_results(mocker, client):
    """Test search_query_command returns 'No Results' when no items are found."""
    mocker.patch.object(client, "get_search_query", return_value={"items": []})
    response = MD_Aether.search_query_command(client, {"query": "nonexistent"})
    assert response.readable_output == "No Results were found."


def test_search_query_command_with_page_and_page_size(mocker, client):
    """Test search_query_command with explicit page and page_size."""
    raw_response = util_load_json("test_data/query_hash_badfile.json")
    mocker.patch.object(client, "get_search_query", return_value=raw_response)

    response = MD_Aether.search_query_command(client, {"query": "test", "page": "1", "page_size": "10"})
    assert len(response) == 2
    client.get_search_query.assert_called_once_with("test", 1, 10)


def test_search_query_command_with_page_only(mocker, client):
    """Test search_query_command defaults page_size to 10 when only page is given."""
    raw_response = util_load_json("test_data/query_hash_cleanfile.json")
    mocker.patch.object(client, "get_search_query", return_value=raw_response)

    response = MD_Aether.search_query_command(client, {"query": "test", "page": "2"})
    assert len(response) == 1
    client.get_search_query.assert_called_once_with("test", 2, 10)


def test_search_query_command_with_page_size_only(mocker, client):
    """Test search_query_command defaults page to 1 when only page_size is given."""
    raw_response = util_load_json("test_data/query_hash_cleanfile.json")
    mocker.patch.object(client, "get_search_query", return_value=raw_response)

    response = MD_Aether.search_query_command(client, {"query": "test", "page_size": "5"})
    assert len(response) == 1
    client.get_search_query.assert_called_once_with("test", 1, 5)


def test_search_query_command_auto_pagination(mocker, client):
    """Test search_query_command paginates automatically and respects limit."""

    def _make_item(i: int) -> dict:
        sha = f"{i:064x}"
        return {"id": f"item-{i}", "file": {"name": f"file{i}.txt", "sha256": sha}, "verdict": "no_threat"}

    page1 = {"items": [_make_item(i) for i in range(5)]}
    page2 = {"items": [_make_item(i) for i in range(5, 8)]}

    mocker.patch.object(client, "get_search_query", side_effect=[page1, page2])
    response = MD_Aether.search_query_command(client, {"query": "test", "limit": "8"})
    assert len(response) == 8
    assert client.get_search_query.call_count == 2


def test_scan_command_timeout_argument(mocker, client):
    """Test scan_command passes custom timeout to the ScheduledCommand."""
    from CommonServerPython import ScheduledCommand
    import demistomock as demisto

    mocker.patch.object(demisto, "command", return_value="metadefender-aether-scan-url")
    mocker.patch.object(demisto, "args", return_value={"url": "https://example.com", "timeout": "120"})
    mocker.patch.object(client, "_http_request", return_value={"flow_id": "t-1234"})
    mocker.patch.object(ScheduledCommand, "raise_error_if_not_supported", return_value=None)

    # Re-apply the decorator with the patched demisto.args()
    reimported = importlib.reload(MD_Aether)
    new_client = reimported.Client(base_url="https://test.com", api_key="mockkey", proxy=False, verify=False)
    mocker.patch.object(new_client, "_http_request", return_value={"flow_id": "t-1234"})

    response = reimported.scan_command(new_client, {"url": "https://example.com", "timeout": "120"})
    assert response.scheduled_command._timeout == "120"


def test_scan_command_timeout_none_keeps_default(mocker, client):
    """Test scan_command uses default timeout (600) when not provided."""
    from CommonServerPython import ScheduledCommand
    import demistomock as demisto

    mocker.patch.object(demisto, "command", return_value="metadefender-aether-scan-url")
    mocker.patch.object(demisto, "args", return_value={"url": "https://example.com"})
    mocker.patch.object(ScheduledCommand, "raise_error_if_not_supported", return_value=None)

    reimported = importlib.reload(MD_Aether)
    new_client = reimported.Client(base_url="https://test.com", api_key="mockkey", proxy=False, verify=False)
    mocker.patch.object(new_client, "_http_request", return_value={"flow_id": "t-5678"})

    response = reimported.scan_command(new_client, {"url": "https://example.com"})
    assert response.scheduled_command._timeout == "600"


def test_polling_still_in_progress(mocker, client):
    """Test polling returns a scheduled result when scan is not finished."""
    from CommonServerPython import ScheduledCommand

    mocker.patch.object(ScheduledCommand, "raise_error_if_not_supported", return_value=None)
    in_progress_response = {
        "flow_id": "prog-1234",
        "allFinished": False,
        "reports": {},
    }
    mocker.patch.object(client, "get_scan_result", return_value=in_progress_response)

    response = MD_Aether.scan_command(client, {"flow_id": "prog-1234", "continue_to_poll": True})
    # The @polling_function decorator returns the partial_result (or default poll_message)
    # as a CommandResults, not a PollResult, when continue_to_poll=True.
    assert isinstance(response, CommandResults)
    assert response.readable_output is not None


def test_build_reputation_result_multiple_reports():
    """Test build_reputation_result handles multiple reports."""
    api_response = {
        "reports": {
            "report-1": {
                "finalVerdict": {"verdict": "NO_THREAT", "threatLevel": 0.25},
                "file": {"name": "file1.txt", "hash": "hash1", "type": "text"},
                "allTags": [],
                "subtaskReferences": [],
            },
            "report-2": {
                "finalVerdict": {"verdict": "CONFIRMED_THREAT", "threatLevel": 1.0},
                "file": {"name": "file2.exe", "hash": "hash2", "type": "pe"},
                "allTags": [],
                "subtaskReferences": [],
            },
        }
    }
    results = MD_Aether.build_reputation_result(api_response)
    assert len(results) == 2
    scores = {r.indicator.dbot_score.score for r in results}
    assert 1 in scores  # GOOD
    assert 3 in scores  # BAD


def test_build_search_query_result_empty():
    """Test build_search_query_result returns empty list for empty input."""
    results = MD_Aether.build_search_query_result([])
    assert results == []


def test_sample_submission(mocker, client):
    """Test sample_submission returns a PollResult with correct flow_id."""
    from CommonServerPython import ScheduledCommand

    mocker.patch.object(ScheduledCommand, "raise_error_if_not_supported", return_value=None)
    mocker.patch.object(client, "_http_request", return_value={"flow_id": "sub-9999"})

    result = MD_Aether.sample_submission(client, {"url": "https://example.com"})
    assert result.continue_to_poll is True
    assert result.args_for_next_run["flow_id"] == "sub-9999"
    assert 'Waiting for submission "sub-9999"' in result.partial_result.readable_output


def test_is_valid_pass_no_rejected_key():
    """Test is_valid_pass returns True when rejected_files key is absent."""
    assert MD_Aether.is_valid_pass({"flow_id": "123", "reports": {}}) is True


def test_is_valid_pass_invalid():
    """Test is_valid_pass returns False for INVALID_PASSWORD."""
    response = {"rejected_files": [{"rejected_reason": "INVALID_PASSWORD"}]}
    assert MD_Aether.is_valid_pass(response) is False


def test_is_valid_pass_other_reason():
    """Test is_valid_pass returns True for non-password rejection reasons."""
    response = {"rejected_files": [{"rejected_reason": "FILE_TOO_LARGE"}]}
    assert MD_Aether.is_valid_pass(response) is True


def test_main_test_module(mocker):
    """Test main() dispatches test-module command correctly."""
    import demistomock as demisto

    mocker.patch.object(demisto, "params", return_value={"url": "https://test.com", "api_key": {"password": "key123"}})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(MD_Aether, "test_module_command", return_value="ok")
    MD_Aether.main()
    MD_Aether.test_module_command.assert_called_once()


def test_main_unknown_command(mocker):
    """Test main() raises NotImplementedError for unknown commands."""
    import demistomock as demisto

    mocker.patch.object(demisto, "params", return_value={"url": "https://test.com", "api_key": {"password": "key123"}})
    mocker.patch.object(demisto, "command", return_value="unknown-command")
    mocker.patch.object(demisto, "args", return_value={})
    mock_return_error = mocker.patch("MetaDefenderAether.return_error")

    MD_Aether.main()
    assert mock_return_error.called
    assert "not implemented" in mock_return_error.call_args[0][0].lower()


def test_main_scan_url_command(mocker):
    """Test main() dispatches scan-url command correctly."""
    import demistomock as demisto

    mocker.patch.object(demisto, "params", return_value={"url": "https://test.com", "api_key": {"password": "key123"}})
    mocker.patch.object(demisto, "command", return_value="metadefender-aether-scan-url")
    mocker.patch.object(demisto, "args", return_value={"url": "https://example.com"})
    mock_scan = mocker.patch.object(MD_Aether, "scan_command", return_value="mock-result")
    mocker.patch.object(demisto, "results")

    MD_Aether.main()
    mock_scan.assert_called_once()
