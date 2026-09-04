import builtins
import gzip
import zlib
import pytest
from unittest.mock import MagicMock, patch

import CommonServerPython
for attr in dir(CommonServerPython):
    if not attr.startswith("__"):
        setattr(builtins, attr, getattr(CommonServerPython, attr))

from ImpervaIncapsulaEventCollector_v2 import (
    Client,
    extract_file_id,
    sanitize_cef_value,
    sanitize_cef_event,
    decompress_and_parse_cef,
    test_module as imperva_test_module,
    fetch_events,
    get_logs_index_command,
    get_events_command,
    LOG_PREFIX,
    VENDOR,
    PRODUCT,
)


def test_extract_file_id():
    """Test extract_file_id with valid and invalid filenames."""
    assert extract_file_id("798724459616_304511.log") == 304511
    assert extract_file_id("12345_1.log") == 1
    assert extract_file_id("invalid_name.log") is None
    assert extract_file_id("random_text") is None
    assert extract_file_id("") is None


def test_sanitize_cef_value():
    """Test CEF value sanitization for apostrophes, quotes, whitespace, and control chars."""
    # 1. Unescaped single quotes / apostrophes (the cicode bug)
    assert sanitize_cef_value("cicode", "Al 'Ayyat") == "Al Ayyat"
    assert sanitize_cef_value("cicode", "'Amran") == "Amran"
    assert sanitize_cef_value("cs1", "User's Browser") == "Users Browser"

    # 2. Multi-line characters replaced with spaces
    assert sanitize_cef_value("msg", "Line1\r\nLine2\nLine3") == "Line1  Line2 Line3"

    # 3. Doubled quotes in embedded JSON
    assert sanitize_cef_value("cs10", '""tag"": ""waf""') == '"tag": "waf"'

    # 4. Non-printable control characters removed
    assert sanitize_cef_value("raw", "Valid \x00\x07Text") == "Valid Text"

    # 5. Empty or None values
    assert sanitize_cef_value("empty", "") == ""
    assert sanitize_cef_value("none", None) == ""


def test_sanitize_cef_event():
    """Test CEF event sanitization across header and extension key-values."""
    raw_cef = (
        "CEF:0|Incapsula|SIEMintegration|1|1|Normal|0|"
        "request=https://example.com/login cicode=Al 'Ayyat src=192.168.1.100 act=ALLOW"
    )
    sanitized = sanitize_cef_event(raw_cef, file_name="12345_100.log")
    assert sanitized is not None
    assert "CEF:0|Incapsula|SIEMintegration|1|1|Normal|0|" in sanitized
    assert "cicode=Al Ayyat" in sanitized
    assert "src=192.168.1.100" in sanitized
    assert "act=ALLOW" in sanitized
    assert "logfilename=12345_100.log" in sanitized
    assert "eventhash=" in sanitized

    # Test raw event starting with 0|
    raw_no_cef = "0|Incapsula|SIEMintegration|1|1|Normal|0|src=10.0.0.1"
    sanitized_no_cef = sanitize_cef_event(raw_no_cef, file_name="test.log")
    assert sanitized_no_cef.startswith("CEF:0|Incapsula|SIEMintegration")

    # Test empty event returns None
    assert sanitize_cef_event("") is None
    assert sanitize_cef_event("   ") is None


def test_decompress_and_parse_cef():
    """Test decompression across GZIP, ZLIB, Deflate, and Plaintext payloads."""
    sample_cef = b"CEF:0|Incapsula|SIEMintegration|1|1|Normal|0|src=192.168.1.1 act=BLOCK\n"

    # 1. GZIP with |==| header marker
    gzipped_body = gzip.compress(sample_cef)
    payload_gzip = b"HEADER_INFO|==|" + gzipped_body
    events_gzip = decompress_and_parse_cef(payload_gzip, "test_gzip.log")
    assert len(events_gzip) == 1
    assert "src=192.168.1.1" in events_gzip[0]

    # 2. Standard ZLIB
    zlib_body = zlib.compress(sample_cef)
    events_zlib = decompress_and_parse_cef(zlib_body, "test_zlib.log")
    assert len(events_zlib) == 1
    assert "act=BLOCK" in events_zlib[0]

    # 3. Raw Deflate
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    deflate_body = compressor.compress(sample_cef) + compressor.flush()
    events_deflate = decompress_and_parse_cef(deflate_body, "test_deflate.log")
    assert len(events_deflate) == 1

    # 4. Plain text fallback
    events_plain = decompress_and_parse_cef(sample_cef, "test_plain.log")
    assert len(events_plain) == 1

    # 5. Invalid binary data raises ValueError
    with pytest.raises(ValueError):
        decompress_and_parse_cef(b"\x00\xff\xfe\x00\xaa\xbb\xcc\xdd", "corrupted.log")


def test_client_methods():
    """Test Client get_logs_index and get_log_file."""
    client = Client(base_url="https://logs.incapsula.com", api_id="test_id", api_key="test_key")

    with patch.object(client, "_http_request", return_value="12345_1.log\n12345_2.log\n") as mock_http:
        index = client.get_logs_index()
        assert index == ["12345_1.log", "12345_2.log"]
        mock_http.assert_called_once_with(
            method="GET",
            url_suffix="logs.index",
            resp_type="text",
            timeout=(10, 45),
            retries=3,
            backoff_factor=2,
            status_list_to_retry=[429, 500, 502, 503, 504]
        )

    with patch.object(client, "_http_request", return_value=b"compressed_data") as mock_http:
        content = client.get_log_file("12345_1.log")
        assert content == b"compressed_data"
        mock_http.assert_called_once_with(
            method="GET",
            url_suffix="12345_1.log",
            resp_type="content",
            timeout=(10, 90),
            retries=3,
            backoff_factor=2,
            status_list_to_retry=[429, 500, 502, 503, 504]
        )


def test_test_module_success():
    """Test test_module success case."""
    client = Client(base_url="https://logs.incapsula.com", api_id="test_id", api_key="test_key")
    with patch.object(client, "get_logs_index", return_value=["12345_1.log"]):
        assert imperva_test_module(client) == "ok"


def test_fetch_events():
    """Test fetch_events sorting, batching, and incremental state update."""
    client = Client(base_url="https://logs.incapsula.com", api_id="test_id", api_key="test_key")

    mock_index = ["12345_100.log", "12345_101.log", "12345_102.log", "12345_99.log"]
    sample_cef = b"CEF:0|Incapsula|SIEMintegration|1|1|Normal|0|src=1.1.1.1\n"
    gzipped_content = gzip.compress(sample_cef)

    with patch.object(client, "get_logs_index", return_value=mock_index), \
         patch.object(client, "get_log_file", return_value=gzipped_content):

        last_run = {"last_file_id": 99}
        next_run, events = fetch_events(
            client=client,
            last_run=last_run,
            max_logs=2,
            starting_file_id=0
        )

        assert len(events) == 2
        assert next_run["last_file_id"] == 101
        assert next_run["event_count"] == 2


def test_get_logs_index_command():
    """Test get_logs_index_command table formatting and outputs."""
    client = Client(base_url="https://logs.incapsula.com", api_id="test_id", api_key="test_key")
    with patch.object(client, "get_logs_index", return_value=["12345_1.log", "12345_2.log"]):
        res = get_logs_index_command(client, {"limit": "50"})
        assert res.outputs_prefix == "Imperva.LogIndex"
        assert res.outputs["total_files"] == 2
        assert "12345_1.log" in res.readable_output


def test_get_events_command():
    """Test get_events_command for preview and push modes."""
    client = Client(base_url="https://logs.incapsula.com", api_id="test_id", api_key="test_key")
    sample_cef = b"CEF:0|Incapsula|SIEMintegration|1|1|Normal|0|src=1.1.1.1\n"
    gzipped_content = gzip.compress(sample_cef)

    with patch.object(client, "get_logs_index", return_value=["12345_1.log"]), \
         patch.object(client, "get_log_file", return_value=gzipped_content), \
         patch.object(builtins, "send_events_to_xsiam") as mock_send:

        # 1. Preview mode (should_push_events=False)
        res_preview = get_events_command(client, {"limit": "1", "should_push_events": "false"})
        assert res_preview.outputs["total_events"] == 1
        assert "(preview only, not pushed)" in res_preview.readable_output
        mock_send.assert_not_called()

        # 2. Push mode (should_push_events=True)
        res_push = get_events_command(client, {"limit": "1", "should_push_events": "true"})
        assert res_push.outputs["total_events"] == 1
        assert "(pushed to dataset imperva_siemintegration_raw)" in res_push.readable_output
        mock_send.assert_called_once()
