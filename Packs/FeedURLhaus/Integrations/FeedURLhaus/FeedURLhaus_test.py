import pytest
import requests

import demistomock as demisto
from CommonServerPython import DemistoException, FeedIndicatorType
from FeedURLhaus import build_feed_params, build_feed_url, main, validate_fetch_interval

AUTH_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef"
FEED_URL = f"https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/online.csv"
ONLINE_CSV = """################################################################
# abuse.ch URLhaus Database Dump (CSV - online URLs only)      #
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3700001","2026-10-28 10:00:00","http://malware.example.com/bins/x.sh","online","2026-10-28 10:05:00","malware_download","elf,mirai","https://urlhaus.abuse.ch/url/3700001/","anonymous"
"""


def mock_instance(mocker, command: str, fetch_interval: str | None = "60", insecure: bool = False):
    params = {
        "credentials": {"password": AUTH_KEY},
        "feedFetchInterval": fetch_interval,
        "feedReliability": "B - Usually reliable",
        "insecure": insecure,
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value=command)
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    return mocker.patch.object(demisto, "results")


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


def test_build_feed_params():
    """
    Given: Instance params with the Auth Key and command args.
    When: Building the CSVFeedApiModule params.
    Then: The feed URL holds the key, no credentials are passed on (no auth header), and args override params.
    """
    params = {"credentials": {"password": AUTH_KEY}, "feedTags": "a", "proxy": None}
    feed_params = build_feed_params(params, {"limit": "10"}, AUTH_KEY)

    assert feed_params["url"] == [FEED_URL]
    assert list(feed_params["feed_url_to_config"]) == [FEED_URL]
    assert "credentials" not in feed_params
    assert "proxy" not in feed_params
    assert feed_params["limit"] == "10"
    assert feed_params["indicator_type"] == FeedIndicatorType.URL


def test_get_indicators_parses_online_csv(mocker, requests_mock):
    """
    Given: The v2 online.csv export with its commented header.
    When: Running urlhaus-get-indicators.
    Then: The URL indicator is mapped from the CSV columns, and the request carries no Auth-Key header.
    """
    results = mock_instance(mocker, "urlhaus-get-indicators")
    requests_mock.get(FEED_URL, text=ONLINE_CSV)

    main()

    indicators = results.call_args[0][0]["Contents"]
    assert len(indicators) == 1
    assert indicators[0]["value"] == "http://malware.example.com/bins/x.sh"
    assert indicators[0]["fields"]["State"] == "online"
    assert indicators[0]["fields"]["Download URL"] == "https://urlhaus.abuse.ch/url/3700001/"
    assert "Auth-Key" not in requests_mock.last_request.headers


@pytest.mark.parametrize("command", ["test-module", "fetch-indicators"])
def test_main_rejects_low_fetch_interval(mocker, command):
    """
    Given: A Feed Fetch Interval of 4 minutes.
    When: Running test-module or fetch-indicators.
    Then: The command fails with the minimum interval error and no request is sent.
    """
    mock_instance(mocker, command, fetch_interval="4")
    feed_main = mocker.patch("FeedURLhaus.feed_main")
    return_error = mocker.patch("FeedURLhaus.return_error")

    main()

    feed_main.assert_not_called()
    assert "at least 5 minutes" in return_error.call_args[0][0]


def test_main_does_not_validate_interval_for_get_indicators(mocker):
    """
    Given: A Feed Fetch Interval of 4 minutes.
    When: Running urlhaus-get-indicators manually.
    Then: The command runs.
    """
    mock_instance(mocker, "urlhaus-get-indicators", fetch_interval="4")
    feed_main = mocker.patch("FeedURLhaus.feed_main")

    main()

    feed_main.assert_called_once()


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


def test_main_rejects_unknown_command(mocker):
    """
    Given: A command the integration does not implement.
    When: Running main.
    Then: The command fails with a not implemented error.
    """
    mock_instance(mocker, "unknown-command")
    feed_main = mocker.patch("FeedURLhaus.feed_main")
    return_error = mocker.patch("FeedURLhaus.return_error")

    main()

    feed_main.assert_not_called()
    assert "is not implemented" in return_error.call_args[0][0]
