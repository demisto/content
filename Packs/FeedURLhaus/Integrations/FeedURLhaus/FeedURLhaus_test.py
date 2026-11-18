from datetime import datetime, timedelta, UTC

import pytest
import requests

import demistomock as demisto
from CommonServerPython import DemistoException, FeedIndicatorType
from FeedURLhaus import DATE_FORMAT, LAST_RUN_KEY, build_feed_url, build_indicators, main, validate_fetch_interval

AUTH_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef"
FEED_URL = f"https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/online.csv"
ETAG = '"5f2a-63c1"'
LAST_MODIFIED = "Wed, 18 Nov 2026 09:08:22 GMT"
CACHING_HEADERS = {"ETag": ETAG, "Last-Modified": LAST_MODIFIED}
ONLINE_CSV = """################################################################
# abuse.ch URLhaus Database Dump (CSV - online URLs only)      #
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3700001","2026-10-28 10:00:00","http://malware.example.com/bins/x.sh","online","2026-10-28 10:05:00","malware_download","elf,mirai","https://urlhaus.abuse.ch/url/3700001/","anonymous"
"3700002","2026-10-28 11:00:00","http://malware.example.com/bins/y.sh","online","2026-10-28 11:05:00","malware_download","","https://urlhaus.abuse.ch/url/3700002/","anonymous"
"""


def mock_instance(mocker, command: str, fetch_interval: str | None = "60", insecure: bool = False, last_run: dict | None = None):
    params = {
        "credentials": {"password": AUTH_KEY},
        "feedFetchInterval": fetch_interval,
        "feedReliability": "B - Usually reliable",
        "feedTags": "urlhaus,feed",
        "tlp_color": "WHITE",
        "insecure": insecure,
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value=command)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run or {})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "createIndicators")
    return mocker.patch.object(demisto, "results")


def last_run_entry(last_updated: datetime) -> dict:
    return {LAST_RUN_KEY: {"etag": ETAG, "last_modified": LAST_MODIFIED, "last_updated": last_updated.strftime(DATE_FORMAT)}}


def test_build_feed_url():
    """
    Given: An abuse.ch Auth-Key.
    When: Building the feed URL.
    Then: The key is a path segment of the v2 online.csv export URL.
    """
    assert build_feed_url(AUTH_KEY) == FEED_URL


@pytest.mark.parametrize("fetch_interval", [None, "", "5", "60", 1440])
def test_validate_fetch_interval_valid(fetch_interval):
    """
    Given: A Feed Fetch Interval that is empty or at least 5 minutes.
    When: Validating the interval.
    Then: No error is raised.
    """
    validate_fetch_interval(fetch_interval)


@pytest.mark.parametrize("fetch_interval", ["0", "1", "4", 4])
def test_validate_fetch_interval_too_low(fetch_interval):
    """
    Given: A Feed Fetch Interval lower than 5 minutes.
    When: Validating the interval.
    Then: An error that names the 5-minute minimum is raised.
    """
    with pytest.raises(DemistoException, match="at least 5 minutes"):
        validate_fetch_interval(fetch_interval)


def test_build_indicators():
    """
    Given: The v2 online.csv export with its commented header.
    When: Building indicators.
    Then: Comment lines are skipped, the CSV columns are mapped to fields, empty columns are not mapped,
          and the instance tags, TLP and enrichment exclusion are applied.
    """
    params = {"feedTags": "urlhaus,feed", "tlp_color": "AMBER"}
    indicators = build_indicators(ONLINE_CSV.encode(), params, enrichment_excluded=True)

    assert [indicator["value"] for indicator in indicators] == [
        "http://malware.example.com/bins/x.sh",
        "http://malware.example.com/bins/y.sh",
    ]
    first = indicators[0]
    assert first["type"] == FeedIndicatorType.URL
    assert first["enrichmentExcluded"] is True
    assert first["rawJSON"]["id"] == "3700001"
    assert first["fields"] == {
        "Creation Date": "2026-10-28 10:00:00",
        "Value": "http://malware.example.com/bins/x.sh",
        "State": "online",
        "Tags": "elf,mirai",
        "Download URL": "https://urlhaus.abuse.ch/url/3700001/",
        "Reported By": "anonymous",
        "tags": ["urlhaus", "feed"],
        "trafficlightprotocol": "AMBER",
    }
    assert "Tags" not in indicators[1]["fields"]


def test_build_indicators_limit():
    """
    Given: An export with two rows.
    When: Building indicators with a limit of 1.
    Then: Only the first indicator is returned.
    """
    indicators = build_indicators(ONLINE_CSV.encode(), {}, enrichment_excluded=False, limit=1)

    assert len(indicators) == 1
    assert "enrichmentExcluded" not in indicators[0]


def test_test_module(mocker, requests_mock):
    """
    Given: A valid Auth-Key.
    When: Running test-module.
    Then: The export is reachable and "ok" is returned.
    """
    results = mock_instance(mocker, "test-module")
    requests_mock.get(FEED_URL, text=ONLINE_CSV)

    main()

    results.assert_called_once_with("ok")


def test_get_indicators(mocker, requests_mock):
    """
    Given: A lastRun with caching values.
    When: Running urlhaus-get-indicators.
    Then: The export is downloaded without conditional or Auth-Key headers, and the indicators are returned.
    """
    results = mock_instance(mocker, "urlhaus-get-indicators", last_run=last_run_entry(datetime.now(UTC)))
    requests_mock.get(FEED_URL, text=ONLINE_CSV)

    main()

    request_headers = requests_mock.last_request.headers
    assert not {"If-None-Match", "If-Modified-Since", "Auth-Key"} & set(request_headers)
    indicators = results.call_args[0][0]["Contents"]
    assert [indicator["value"] for indicator in indicators] == [
        "http://malware.example.com/bins/x.sh",
        "http://malware.example.com/bins/y.sh",
    ]


def test_fetch_indicators_first_fetch(mocker, requests_mock):
    """
    Given: No lastRun, and an export response with ETag and Last-Modified headers.
    When: Running fetch-indicators.
    Then: The indicators are created, and the lastRun is keyed by the export file name, without the Auth-Key.
    """
    mock_instance(mocker, "fetch-indicators")
    requests_mock.get(FEED_URL, text=ONLINE_CSV, headers=CACHING_HEADERS)

    main()

    assert "If-None-Match" not in requests_mock.last_request.headers
    indicators = demisto.createIndicators.call_args[0][0]
    assert len(indicators) == 2
    assert demisto.createIndicators.call_args[1] == {"noUpdate": False}
    last_run = demisto.setLastRun.call_args[0][0]
    assert list(last_run) == [LAST_RUN_KEY]
    assert last_run[LAST_RUN_KEY]["etag"] == ETAG
    assert last_run[LAST_RUN_KEY]["last_modified"] == LAST_MODIFIED
    assert AUTH_KEY not in str(last_run)


def test_fetch_indicators_not_modified(mocker, requests_mock):
    """
    Given: A recent lastRun with caching values.
    When: Running fetch-indicators, and the export did not change (304).
    Then: A conditional request is sent, createIndicators runs with noUpdate=True, and the lastRun is kept.
    """
    mock_instance(mocker, "fetch-indicators", last_run=last_run_entry(datetime.now(UTC)))
    requests_mock.get(FEED_URL, status_code=304)

    main()

    request_headers = requests_mock.last_request.headers
    assert request_headers["If-None-Match"] == ETAG
    assert request_headers["If-Modified-Since"] == LAST_MODIFIED
    demisto.createIndicators.assert_called_once_with([], noUpdate=True)
    demisto.setLastRun.assert_not_called()


def test_fetch_indicators_full_refresh(mocker, requests_mock):
    """
    Given: A lastRun that was last updated more than 12 hours ago.
    When: Running fetch-indicators.
    Then: The export is downloaded without conditional headers.
    """
    mock_instance(mocker, "fetch-indicators", last_run=last_run_entry(datetime.now(UTC) - timedelta(hours=13)))
    requests_mock.get(FEED_URL, text=ONLINE_CSV, headers=CACHING_HEADERS)

    main()

    assert not {"If-None-Match", "If-Modified-Since"} & set(requests_mock.last_request.headers)
    assert len(demisto.createIndicators.call_args[0][0]) == 2


def test_fetch_indicators_drops_url_keyed_last_run(mocker, requests_mock):
    """
    Given: A lastRun saved by an older version under the request URL, which contains the Auth-Key.
    When: Running fetch-indicators, and the response has no caching headers.
    Then: The lastRun is replaced with an empty one.
    """
    stale_last_run = {FEED_URL: {"etag": ETAG, "last_modified": LAST_MODIFIED, "last_updated": "2026-11-18T09:00:00Z"}}
    mock_instance(mocker, "fetch-indicators", last_run=stale_last_run)
    requests_mock.get(FEED_URL, text=ONLINE_CSV)

    main()

    assert "If-None-Match" not in requests_mock.last_request.headers
    demisto.setLastRun.assert_called_once_with({})


def test_fetch_indicators_batches(mocker, requests_mock):
    """
    Given: An export with two rows and a batch size of 1.
    When: Running fetch-indicators.
    Then: createIndicators is called once per batch.
    """
    mock_instance(mocker, "fetch-indicators")
    mocker.patch("FeedURLhaus.CREATE_INDICATORS_BATCH_SIZE", 1)
    requests_mock.get(FEED_URL, text=ONLINE_CSV)

    main()

    assert demisto.createIndicators.call_count == 2


@pytest.mark.parametrize("command", ["test-module", "fetch-indicators"])
def test_main_rejects_low_fetch_interval(mocker, requests_mock, command):
    """
    Given: A Feed Fetch Interval of 4 minutes.
    When: Running test-module or fetch-indicators.
    Then: The command fails with the minimum interval error and no request is sent.
    """
    mock_instance(mocker, command, fetch_interval="4")
    return_error = mocker.patch("FeedURLhaus.return_error")

    main()

    assert not requests_mock.called
    assert "at least 5 minutes" in return_error.call_args[0][0]


def test_main_does_not_validate_interval_for_get_indicators(mocker, requests_mock):
    """
    Given: A Feed Fetch Interval of 4 minutes.
    When: Running urlhaus-get-indicators manually.
    Then: The command runs.
    """
    results = mock_instance(mocker, "urlhaus-get-indicators", fetch_interval="4")
    requests_mock.get(FEED_URL, text=ONLINE_CSV)

    main()

    assert len(results.call_args[0][0]["Contents"]) == 2


def test_main_rejects_unknown_command(mocker, requests_mock):
    """
    Given: A command the integration does not implement.
    When: Running main.
    Then: The command fails with a not implemented error.
    """
    mock_instance(mocker, "unknown-command")
    return_error = mocker.patch("FeedURLhaus.return_error")

    main()

    assert not requests_mock.called
    assert "is not implemented" in return_error.call_args[0][0]


def test_main_masks_auth_key_in_errors(mocker, requests_mock):
    """
    Given: A request error whose text contains the feed URL (and so the Auth-Key).
    When: Running test-module.
    Then: The error entry does not contain the Auth-Key.
    """
    results = mock_instance(mocker, "test-module", insecure=True)
    requests_mock.get(FEED_URL, exc=requests.exceptions.SSLError(f"SSL error for url: {FEED_URL}"))

    with pytest.raises(SystemExit):
        main()

    error_contents = results.call_args[0][0]["Contents"]
    assert "SSL error for url" in error_contents
    assert AUTH_KEY not in error_contents


def test_main_masks_auth_key_in_http_errors(mocker, requests_mock):
    """
    Given: The export returns 401 for an invalid Auth-Key.
    When: Running test-module.
    Then: The error entry shows the abuse.ch message and does not contain the Auth-Key.
    """
    results = mock_instance(mocker, "test-module")
    requests_mock.get(FEED_URL, status_code=401, text='{"status":401,"message":"Invalid auth token"}')

    with pytest.raises(SystemExit):
        main()

    error_contents = results.call_args[0][0]["Contents"]
    assert "Invalid auth token" in error_contents
    assert AUTH_KEY not in error_contents
