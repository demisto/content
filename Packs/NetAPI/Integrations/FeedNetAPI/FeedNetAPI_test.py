import httpx
import pytest
import respx
import FeedNetAPI
from FeedNetAPI import (
    LIST_DOMAINS,
    LIST_DOMAINS_NO_SINKHOLES,
    LIST_IPS,
    Client,
    content_lines,
    fetch_indicators_command,
    get_conditional_headers,
    get_indicators_command,
    get_list_name,
    iter_batches,
    iter_indicators,
    to_iso_date,
)
from CommonServerPython import *

PARAMS = {"feedTags": "netapi", "tlp_color": "WHITE"}


def load_lines(path: str) -> list[str]:
    with open(path, encoding="utf-8") as test_file:
        return test_file.read().splitlines()


def load_bytes(path: str) -> bytes:
    with open(path, "rb") as test_file:
        return test_file.read()


def make_client() -> Client:
    return Client(verify=True, proxy=False, timeout=10)


def mock_list(response: httpx.Response) -> respx.Route:
    """Mocks the NetAPI list endpoint (any query) with the given response."""
    return respx.route(method="GET", host="netapi.com", path="/api2/").mock(return_value=response)


@pytest.mark.parametrize(
    "params, expected",
    [
        ({}, LIST_DOMAINS),
        ({"list": LIST_DOMAINS_NO_SINKHOLES}, LIST_DOMAINS_NO_SINKHOLES),
        ({"list": LIST_IPS}, LIST_IPS),
    ],
)
def test_get_list_name(params, expected):
    """
    Given: the instance parameters.
    When: the list to fetch is chosen.
    Then: the configured list is returned, the compromised domains by default.
    """
    assert get_list_name(params) == expected


def test_get_list_name_unknown():
    """
    Given: an unknown list name.
    When: the list to fetch is chosen.
    Then: an error names the valid lists.
    """
    with pytest.raises(DemistoException, match="Unknown list"):
        get_list_name({"list": "Everything"})


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2019-12-18", "2019-12-18T00:00:00Z"),
        ("2026-11-20T05:51:56Z", "2026-11-20T05:51:56Z"),
        ("", None),
        (None, None),
        ("yesterday", None),
    ],
)
def test_to_iso_date(value, expected):
    """
    Given: a date as the lists carry it.
    When: it is converted for the indicator fields.
    Then: dates and date-times come back in ISO 8601 UTC, anything else is dropped.
    """
    assert to_iso_date(value) == expected


def test_iter_indicators_domains():
    """
    Given: the compromised domain list.
    When: it is parsed into indicators.
    Then: the header is skipped and every domain carries its threat type, evidence, dates, tags and TLP.
    """
    indicators = list(iter_indicators(load_lines("test_data/domains.csv"), LIST_DOMAINS, PARAMS, False))
    assert [indicator["value"] for indicator in indicators] == ["1gogetrichrightnow.com", "mosoli.com", "newnotify.online"]
    assert all(indicator["type"] == FeedIndicatorType.Domain for indicator in indicators)

    sinkholed = indicators[0]["fields"]
    assert sinkholed["threattypes"] == [{"threatcategory": "Malware"}]
    assert sinkholed["description"] == "NetAPI threat type: sinkhole-ns. Evidence: ns sc-a.sinkhole.shadowserver.org"
    assert sinkholed["firstseenbysource"] == "2019-12-18T00:00:00Z"
    assert sinkholed["lastseenbysource"] == "2026-11-23T00:00:00Z"
    assert sinkholed["tags"] == ["netapi"]
    assert sinkholed["trafficlightprotocol"] == "WHITE"
    assert indicators[0]["rawJSON"]["threat_type"] == "sinkhole-ns"

    assert indicators[1]["fields"]["threattypes"] == [{"threatcategory": "Phishing"}]

    cert_polska = indicators[2]["fields"]
    assert cert_polska["threattypes"] == [{"threatcategory": "Phishing"}]
    assert cert_polska["description"] == "NetAPI threat type: cert-polska."


def test_iter_indicators_ips():
    """
    Given: the honeypot attacker IP list.
    When: it is parsed into indicators.
    Then: every address carries its attack types, country, network and dates.
    """
    indicators = list(iter_indicators(load_lines("test_data/ips.csv"), LIST_IPS, PARAMS, True))
    assert [indicator["value"] for indicator in indicators] == ["1.0.168.9", "2.57.122.10"]
    assert all(indicator["type"] == FeedIndicatorType.IP for indicator in indicators)
    assert all(indicator["enrichmentExcluded"] for indicator in indicators)

    fields = indicators[1]["fields"]
    assert fields["threattypes"] == [{"threatcategory": "ssh-bruteforce"}, {"threatcategory": "env-file-hunting"}]
    assert fields["description"] == "Attack types seen by NetAPI honeypot sensors: ssh-bruteforce, env-file-hunting"
    assert fields["geocountry"] == "NL"
    assert fields["asn"] == "AS47890"
    assert fields["asowner"] == "UNMANAGED-DEDICATED-SERVERS"
    assert fields["firstseenbysource"] == "2026-11-01T10:00:00Z"


def test_iter_indicators_limit_and_empty_rows():
    """
    Given: a list with an empty row.
    When: it is parsed with a limit.
    Then: the empty row is skipped and no more than the limit is returned.
    """
    lines = load_lines("test_data/domains.csv")
    lines.insert(2, ",,,,")
    indicators = list(iter_indicators(lines, LIST_DOMAINS, PARAMS, False, limit=2))
    assert [indicator["value"] for indicator in indicators] == ["1gogetrichrightnow.com", "mosoli.com"]


def test_iter_indicators_unexpected_columns():
    """
    Given: a list whose columns are not the expected ones (for example the IP list read as domains).
    When: it is parsed.
    Then: an error is raised instead of creating wrong indicators.
    """
    with pytest.raises(DemistoException, match="Unexpected columns"):
        list(iter_indicators(load_lines("test_data/ips.csv"), LIST_DOMAINS, PARAMS, False))


def test_iter_indicators_empty_file():
    """
    Given: an empty response, without the header line.
    When: it is parsed.
    Then: an error is raised, so an empty answer is never taken for an empty list.
    """
    with pytest.raises(DemistoException, match="no header line"):
        list(iter_indicators([], LIST_DOMAINS, PARAMS, False))


def test_content_lines_bom_crlf_and_new_column():
    """
    Given: a list with a byte order mark, CRLF line ends, a column added at the end and a non-ASCII AS name.
    When: it is split into lines and parsed.
    Then: the header is recognized, the extra column is ignored and the AS name is kept intact.
    """
    content = (
        "\ufeffip,first_seen,last_seen,category,top_threat,threats,country,asn,as_name,sensors,score\r\n"
        "5.6.7.8,2026-11-20T05:51:56Z,2026-11-24T05:54:26Z,A,rdp-bruteforce,rdp-bruteforce,"
        'PL,5617,"Orange Polska \u0105\u017a",3,9\r\n'
    ).encode("utf-8")
    indicators = list(iter_indicators(content_lines(content), LIST_IPS, PARAMS, False))
    assert [indicator["value"] for indicator in indicators] == ["5.6.7.8"]
    assert indicators[0]["fields"]["asowner"] == "Orange Polska \u0105\u017a"


def test_iter_batches():
    """
    Given: an iterable of items.
    When: it is split into batches.
    Then: every batch has at most the batch size and nothing is lost.
    """
    assert list(iter_batches(iter(range(5)), 2)) == [[0, 1], [2, 3], [4]]
    assert list(iter_batches(iter([]), 2)) == []


def test_get_conditional_headers():
    """
    Given: the lastRun of a previous fetch.
    When: the conditional headers are built.
    Then: they are sent only for the same list and while no full refresh is due.
    """
    recent = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    last_run = {"list": LIST_DOMAINS, "etag": '"abc"', "last_modified": "Tue, 24 Nov 2026 06:30:47 GMT", "last_updated": recent}
    assert get_conditional_headers(last_run, LIST_DOMAINS) == {
        "If-None-Match": '"abc"',
        "If-Modified-Since": "Tue, 24 Nov 2026 06:30:47 GMT",
    }
    assert get_conditional_headers(last_run, LIST_IPS) == {}
    assert get_conditional_headers({**last_run, "last_updated": "2020-01-01T00:00:00Z"}, LIST_DOMAINS) == {}
    assert get_conditional_headers({}, LIST_DOMAINS) == {}


def test_fetch_indicators(mocker):
    """
    Given: a changed list.
    When: indicators are fetched.
    Then: they are created in batches, the right list is requested and the caching headers are saved afterwards.
    """
    mocker.patch.object(FeedNetAPI, "CREATE_INDICATORS_BATCH_SIZE", 2)
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    create_indicators = mocker.patch.object(demisto, "createIndicators")
    with respx.mock:
        route = mock_list(
            httpx.Response(
                200,
                content=load_bytes("test_data/domains.csv"),
                headers={"ETag": '"abc"', "Last-Modified": "Tue, 24 Nov 2026 06:30:47 GMT"},
            )
        )
        total = fetch_indicators_command(make_client(), LIST_DOMAINS_NO_SINKHOLES, PARAMS)
        request = route.calls.last.request
        assert dict(request.url.params) == {
            "method": "compromised",
            "dataset_type": "url",
            "format": "csv",
            "sinkholes": "0",
        }
        assert "If-None-Match" not in request.headers

    assert total == 3
    assert [len(call.args[0]) for call in create_indicators.call_args_list] == [2, 1]
    assert all(call.kwargs["noUpdate"] is False for call in create_indicators.call_args_list)
    saved = set_last_run.call_args.args[0]
    assert saved["list"] == LIST_DOMAINS_NO_SINKHOLES
    assert saved["etag"] == '"abc"'
    assert saved["last_modified"] == "Tue, 24 Nov 2026 06:30:47 GMT"


def test_fetch_indicators_not_modified(mocker):
    """
    Given: a list that has not changed since the last fetch (HTTP 304).
    When: indicators are fetched.
    Then: the conditional headers are sent, the 304 is accepted and the existing indicators are kept (noUpdate).
    """
    recent = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    mocker.patch.object(demisto, "getLastRun", return_value={"list": LIST_IPS, "etag": '"abc"', "last_updated": recent})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    create_indicators = mocker.patch.object(demisto, "createIndicators")
    with respx.mock:
        route = mock_list(httpx.Response(304))
        total = fetch_indicators_command(make_client(), LIST_IPS, PARAMS)
        assert route.calls.last.request.headers["If-None-Match"] == '"abc"'

    assert total == 0
    create_indicators.assert_called_once_with([], noUpdate=True)
    set_last_run.assert_not_called()


def test_fetch_indicators_empty_list(mocker):
    """
    Given: a list with a header and no rows.
    When: indicators are fetched.
    Then: an empty update is sent, so sudden death expires the indicators that left the list.
    """
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    create_indicators = mocker.patch.object(demisto, "createIndicators")
    with respx.mock:
        mock_list(httpx.Response(200, content=b"domain,threat_type,evidence,first_seen,last_seen\n"))
        assert fetch_indicators_command(make_client(), LIST_DOMAINS, PARAMS) == 0
    create_indicators.assert_called_once_with([], noUpdate=False)


def test_fetch_indicators_without_header(mocker):
    """
    Given: an HTTP 200 answer with an empty body.
    When: indicators are fetched.
    Then: the fetch fails without creating indicators or saving the lastRun, so nothing expires.
    """
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    create_indicators = mocker.patch.object(demisto, "createIndicators")
    with respx.mock:
        mock_list(httpx.Response(200, content=b""))
        with pytest.raises(DemistoException, match="no header line"):
            fetch_indicators_command(make_client(), LIST_DOMAINS, PARAMS)
    create_indicators.assert_not_called()
    set_last_run.assert_not_called()


def test_fetch_indicators_http_error(mocker):
    """
    Given: an HTTP 404 answer.
    When: indicators are fetched.
    Then: the fetch fails without creating indicators or saving the lastRun.
    """
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    create_indicators = mocker.patch.object(demisto, "createIndicators")
    with respx.mock:
        mock_list(httpx.Response(404, content=b"not found"))
        with pytest.raises(DemistoException):
            fetch_indicators_command(make_client(), LIST_DOMAINS, PARAMS)
    create_indicators.assert_not_called()
    set_last_run.assert_not_called()


def test_fetch_indicators_partial_content(mocker):
    """
    Given: an HTTP 206 answer, which the client accepts as a success.
    When: indicators are fetched.
    Then: the fetch fails without creating indicators or saving the lastRun, as only a 200 answer is a whole list.
    """
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    create_indicators = mocker.patch.object(demisto, "createIndicators")
    with respx.mock:
        mock_list(httpx.Response(206, content=load_bytes("test_data/domains.csv")))
        with pytest.raises(DemistoException, match="Unexpected HTTP status 206"):
            fetch_indicators_command(make_client(), LIST_DOMAINS, PARAMS)
    create_indicators.assert_not_called()
    set_last_run.assert_not_called()


def test_iter_indicators_extra_cells():
    """
    Given: a row with more cells than the header.
    When: the list is parsed.
    Then: the extra cells are left out of the raw JSON.
    """
    lines = ["domain,threat_type,evidence,first_seen,last_seen", "example.com,cert-polska,,2026-11-01,2026-11-24,extra,"]
    indicator = next(iter_indicators(lines, LIST_DOMAINS, PARAMS, False))
    assert None not in indicator["rawJSON"]
    assert indicator["rawJSON"]["domain"] == "example.com"


def test_get_indicators_command():
    """
    Given: the honeypot attacker IP list.
    When: netapi-get-indicators runs with a limit.
    Then: only that many indicators are returned.
    """
    with respx.mock:
        mock_list(httpx.Response(200, content=load_bytes("test_data/ips.csv")))
        result = get_indicators_command(make_client(), LIST_IPS, PARAMS, {"limit": "1"})
    assert [indicator["value"] for indicator in result.raw_response] == ["1.0.168.9"]
    assert "1.0.168.9" in result.readable_output


def test_get_indicators_command_large_limit():
    """
    Given: a limit above the number of rows of the list.
    When: netapi-get-indicators runs.
    Then: every row of the list is returned.
    """
    with respx.mock:
        mock_list(httpx.Response(200, content=load_bytes("test_data/domains.csv")))
        result = get_indicators_command(make_client(), LIST_DOMAINS, PARAMS, {"limit": "100000"})
    assert len(result.raw_response) == 3


def test_test_module():
    """
    Given: a reachable list with the expected columns.
    When: the instance is tested.
    Then: ok is returned.
    """
    with respx.mock:
        mock_list(httpx.Response(200, content=load_bytes("test_data/domains.csv")))
        assert FeedNetAPI.test_module(make_client(), LIST_DOMAINS, PARAMS) == "ok"
