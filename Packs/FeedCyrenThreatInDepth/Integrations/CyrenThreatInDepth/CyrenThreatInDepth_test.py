import pytest
import pathlib
import os

from CommonServerPython import (
    FeedIndicatorType, DemistoException, Common,
    set_integration_context, get_integration_context
)

from CyrenThreatInDepth import (
    Client, fetch_indicators_command, get_indicators_command,
    test_module_command as _test_module_command, BASE_URL,
    reset_offset_command, get_offset_command
)


pytestmark = pytest.mark.usefixtures("clean_integration_context")

API_TOKEN = "12345"
VERSION = "1.5.0"


def _load_file(file_name):
    full_path = os.path.join(pathlib.Path(__file__).parent.absolute(), "test_data", file_name)
    with open(full_path, "r") as f:
        return f.read()


@pytest.fixture(name="malware_files", scope="session")
def fixture_malware_files():
    return _load_file("malware_files.jsonl")


@pytest.fixture(name="malware_urls", scope="session")
def fixture_malware_urls():
    return _load_file("malware_urls.jsonl")


@pytest.fixture(name="phishing_urls", scope="session")
def fixture_phishing_urls():
    return _load_file("phishing_urls.jsonl")


@pytest.fixture(name="ip_reputation", scope="session")
def fixture_ip_reputation():
    return _load_file("ip_reputation.jsonl")


@pytest.fixture(name="response_429", scope="session")
def fixture_response_429():
    return _load_file("429.html")


@pytest.fixture(name="clean_integration_context", scope="function")
def fixture_clean_integration_context():
    set_integration_context({})
    yield
    set_integration_context({})


def _create_client(feed):
    return Client(feed_name=feed, api_token=API_TOKEN, base_url=BASE_URL, verify=False, proxy=False)


def _expected_headers():
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "Cyren-Client-Name": "Palo Alto Cortex XSOAR",
        "Cyren-Client-Version": VERSION,
    }


def _create_instance(requests_mock, feed, feed_data, offset_data, offset=0, count=2):
    expected_headers = _expected_headers()
    requests_mock.get(BASE_URL + "/data?format=jsonl&feedId={}_v2&offset={}&count={}".format(feed, offset, count),
                      text=feed_data, request_headers=expected_headers)
    requests_mock.get(BASE_URL + "/info?format=jsonl&feedId={}_v2".format(feed),
                      json=offset_data, request_headers=expected_headers)
    client = _create_client(feed)

    def fetch_command(initial_count=0, max_indicators=2, update_context=False):
        return fetch_indicators_command(client, initial_count, max_indicators, update_context)

    def get_command(max_indicators):
        args = dict(max_indicators=max_indicators)
        return get_indicators_command(client, args)

    return fetch_command, get_command


@pytest.mark.parametrize(
    "context_data, offsets, initial_count, max_indicators, expected_offset, expected_count", [
        # Given:
        #   - first run
        #   - no previous offset stored
        #   - an end offset of 10000

        # When:
        #   - running fetch-indicators with no initial import wanted and wanting 2

        # Then:
        #   - the API is asked for 2 from offset 10000
        (dict(), dict(startOffset=1, endOffset=10000), 0, 2, 10000, 2),
        # Given:
        #   - first run
        #   - no previous offset stored
        #   - an end offset of 10000

        # When:
        #   - running fetch-indicators with initial import of 1000 and wanting 2

        # Then:
        #   - the API is asked for 1002 from offset 9001
        (dict(), dict(startOffset=1, endOffset=10000), 1000, 2, 9001, 1002),
        # Given:
        #   - not the first run
        #   - previous offset of 9001
        #   - an end offset of 10000

        # When:
        #   - running fetch-indicators with no initial import wanted and wanting 2

        # Then:
        #   - the API is asked for 2 from offset 9001
        (dict(offset=9001), dict(startOffset=1, endOffset=10000), 0, 2, 9001, 2),
        # Given:
        #   - not the first run
        #   - previous offset of 9001
        #   - an end offset of 10000

        # When:
        #   - running fetch-indicators with initial import of 10000 and wanting 2

        # Then:
        #   - the API is asked for 2 from offset 9001
        (dict(offset=9001), dict(startOffset=1, endOffset=10000), 10000, 2, 9001, 2),
        # Given:
        #   - not the first run
        #   - previous offset of 9001
        #   - an end offset of 10000

        # When:
        #   - running fetch-indicators with no initial import wanted and wanting 2000

        # Then:
        #   - the API is asked for 2000 from offset 9001
        (dict(offset=9001), dict(startOffset=1, endOffset=10000), 0, 2000, 9001, 2000),
        # Given:
        #   - not the first run
        #   - previous offset of 9001
        #   - an end offset of 10000

        # When:
        #   - running fetch-indicators with initial import of 10000 and wanting 2000

        # Then:
        #   - the API is asked for 2000 from offset 9001
        (dict(offset=9001), dict(startOffset=1, endOffset=10000), 10000, 2000, 9001, 2000),
        # Given:
        #   - first run
        #   - no previous offset stored
        #   - an end offset of 10000

        # When:
        #   - running fetch-indicators with no initial import wanted and wanting 100001

        # Then:
        #   - the API is asked for a max of 100000 from offset 10000
        (dict(), dict(startOffset=1, endOffset=10000), 0, 100001, 10000, 100000),
        # Given:
        #   - not the first run
        #   - previous offset of 9001
        #   - an end offset of 10000

        # When:
        #   - running fetch-indicators with no initial import wanted and wanting 100001

        # Then:
        #   - the API is asked for a max of 100000 from offset 9001
        (dict(offset=9001), dict(startOffset=1, endOffset=10000), 0, 100001, 9001, 100000),
    ]
)
def test_fetch_indicators_offsets(requests_mock, ip_reputation, context_data, offsets,
                                  initial_count, max_indicators, expected_offset, expected_count):
    """
    Given:
        - the IP reputation feed

    When:
        - running fetch-indicators

    Then:
        - the new offset in the integration context is the max offset from the
          entries + 1
        - the number of imported indicators is the number of IP's in the feed

    """

    set_integration_context(context_data)
    fetch, _ = _create_instance(requests_mock, "ip_reputation", ip_reputation, offsets, expected_offset, expected_count)
    created = fetch(initial_count, max_indicators, True)

    assert len(created) == 8
    assert get_integration_context() == dict(offset=50007)


def test_fetch_indicators_parsing_errors(requests_mock, ip_reputation):
    """
    Given:
        - the IP reputation feed

    When:
        - running fetch-indicators
        - some non-JSON lines in the response

    Then:
        - still imported the number of good JSON lines in the response

    """

    ip_reputation_with_errors = f"\nbla\n{ip_reputation}\n\nno json, too\n"
    fetch, _ = _create_instance(requests_mock, "ip_reputation", ip_reputation_with_errors, dict(startOffset=0, endOffset=0))
    created = fetch()

    assert len(created) == 8


def test_fetch_indicators_rate_limiting(requests_mock, response_429):
    """
    Given:
        - the IP reputation feed

    When:
        - running fetch-indicators
        - a 429 Rate Limited response from the API

    Then:
        - a DemistoException is raised

    """

    requests_mock.get(BASE_URL + "/data?format=jsonl&feedId=ip_reputation_v2&offset=0&count=10",
                      request_headers=_expected_headers(),
                      text=response_429, status_code=429)
    requests_mock.get(BASE_URL + "/info?format=jsonl&feedId=ip_reputation_v2", json=dict(startOffset=0, endOffset=0),
                      request_headers=_expected_headers())
    client = _create_client("ip_reputation")

    with pytest.raises(DemistoException, match=f".*{response_429}.*"):
        fetch_indicators_command(client, 0, 10, False)


def test_fetch_indicators_output_ip_reputation(requests_mock, ip_reputation):
    """
    Given:
        - the IP reputation feed
        - no relationship information in the feed

    When:
        - running fetch-indicators

    Then:
        - the indicator type and value are being set
        - the DBot score is set to
          - BAD on spam category
          - SUSPICIOUS on malware, phishing category
          - NONE on feed removal and confirmed clean category
        - basic indicator fields are filled from the feed meta data
        - Cyren-specific indicator fields are filled

    """

    fetch, _ = _create_instance(requests_mock, "ip_reputation", ip_reputation, dict(startOffset=0, endOffset=0))
    created = fetch()

    assert len(created) == 8

    assert created[0]["fields"] == dict(updateddate="2020-10-29T05:15:29.062Z",
                                        indicatoridentification="45.193.212.54")
    assert created[0]["score"] == Common.DBotScore.SUSPICIOUS
    assert created[0]["rawJSON"]["tags"] == ["spam", "Botnet detection"]
    assert created[0]["rawJSON"]["source_tag"] == "primary"
    assert created[0]["type"] == FeedIndicatorType.IP
    assert created[0]["value"] == "45.193.212.54"

    assert created[1]["fields"] == dict(updateddate="2020-10-29T05:15:29.062Z",
                                        indicatoridentification="45.193.216.182")
    assert created[1]["score"] == Common.DBotScore.SUSPICIOUS
    assert created[1]["rawJSON"]["tags"] == ["malware", "Botnet detection"]
    assert created[1]["rawJSON"]["source_tag"] == "primary"
    assert created[1]["type"] == FeedIndicatorType.IP
    assert created[1]["value"] == "45.193.216.182"

    assert created[2]["fields"] == dict(updateddate="2020-10-29T05:15:29.062Z",
                                        published="2020-10-29T05:15:29.062Z",
                                        indicatoridentification="45.193.216.183")
    assert created[2]["score"] == Common.DBotScore.SUSPICIOUS
    assert created[2]["rawJSON"]["tags"] == ["phishing", "Botnet detection"]
    assert created[2]["rawJSON"]["source_tag"] == "primary"
    assert created[2]["type"] == FeedIndicatorType.IP
    assert created[2]["value"] == "45.193.216.183"

    assert created[3]["fields"] == dict(updateddate="2020-10-29T05:15:29.062Z",
                                        indicatoridentification="45.193.216.184")
    assert created[3]["score"] == Common.DBotScore.NONE
    assert created[3]["rawJSON"]["tags"] == ["spam", "Botnet detection"]
    assert created[3]["rawJSON"]["source_tag"] == "primary"
    assert created[3]["type"] == FeedIndicatorType.IP
    assert created[3]["value"] == "45.193.216.184"

    assert created[4]["fields"] == dict(updateddate="2020-10-29T05:15:29.062Z",
                                        indicatoridentification="45.193.216.185")
    assert created[4]["score"] == Common.DBotScore.NONE
    assert created[4]["rawJSON"]["tags"] == ["confirmed clean", "Botnet detection"]
    assert created[4]["rawJSON"]["source_tag"] == "primary"
    assert created[4]["type"] == FeedIndicatorType.IP
    assert created[4]["value"] == "45.193.216.185"

    assert created[5]["fields"] == dict(updateddate="2020-10-29T05:15:29.062Z",
                                        published="2020-10-29T05:15:29.062Z",
                                        indicatoridentification="45.193.212.55")
    assert created[5]["score"] == Common.DBotScore.SUSPICIOUS
    assert created[5]["rawJSON"]["tags"] == ["spam", "Botnet detection"]
    assert created[5]["rawJSON"]["source_tag"] == "primary"
    assert created[5]["type"] == FeedIndicatorType.IP
    assert created[5]["value"] == "45.193.212.55"

    assert created[6]["fields"] == dict(updateddate="2020-10-29T05:15:29.062Z",
                                        indicatoridentification="45.193.212.56")
    assert created[6]["score"] == Common.DBotScore.BAD
    assert created[6]["rawJSON"]["tags"] == ["spam", "Botnet detection"]
    assert created[6]["rawJSON"]["source_tag"] == "primary"
    assert created[6]["type"] == FeedIndicatorType.IP
    assert created[6]["value"] == "45.193.212.56"

    assert created[7]["fields"] == dict(updateddate="2020-10-29T05:15:29.062Z",
                                        published="2020-10-29T05:15:29.062Z",
                                        indicatoridentification="45.193.212.57")
    assert created[7]["score"] == Common.DBotScore.BAD
    assert created[7]["rawJSON"]["tags"] == ["spam", "Botnet detection"]
    assert created[7]["rawJSON"]["source_tag"] == "primary"
    assert created[7]["type"] == FeedIndicatorType.IP
    assert created[7]["value"] == "45.193.212.57"


def test_fetch_indicators_output_malware_files(requests_mock, malware_files):
    """
    Given:
        - the malware file feed
        - some relationship information in the feed

    When:
        - running fetch-indicators

    Then:
        - the indicator type and value are being set
        - the DBot score is set to
          - BAD on non confirmed-clean category
          - NONE on feed removal and confirmed clean category
        - basic indicator fields are filled from the feed meta data
        - Cyren-specific indicator fields are filled
        - feed related indicator field is filled with IP and SHA-256 relationships

    """

    fetch, _ = _create_instance(requests_mock, "malware_files", malware_files, dict(startOffset=0, endOffset=0))
    created = fetch()

    assert len(created) == 8

    assert created[0]["fields"] == dict(
        cyrenfeedrelationships=[dict(indicatortype="SHA-256",
                                     relationshiptype="downloaded from",
                                     value="0f6dbfb291ba1b84601b0372f70db3430df636c631d074c1c2463f9e5a033f21",
                                     description="downloaded from malware ip",
                                     timestamp="2020-10-28T14:42:14.000Z",
                                     entitycategory="malware")])
    assert created[0]["score"] == Common.DBotScore.NONE
    assert created[0]["rawJSON"]["source_tag"] == "related"
    assert created[0]["type"] == FeedIndicatorType.IP
    assert created[0]["value"] == "172.217.4.65"

    assert created[1]["fields"] == dict(updateddate="2020-10-28T14:45:24.921Z",
                                        published="2020-10-28T14:45:24.921Z",
                                        indicatoridentification=("0f6dbfb291ba1b84601b0372f70db"
                                                                 "3430df636c631d074c1c2463f9e5a033f21"),
                                        cyrenfeedrelationships=[
                                            dict(indicatortype="IP",
                                                 relationshiptype="downloaded from",
                                                 value="172.217.4.65",
                                                 description="downloaded from malware ip",
                                                 timestamp="2020-10-28T14:42:14.000Z",
                                                 entitycategory="malware")])
    assert created[1]["score"] == Common.DBotScore.BAD
    assert created[1]["rawJSON"]["tags"] == ["malware", "Malware detection", "js/clickjack.d"]
    assert created[1]["rawJSON"]["source_tag"] == "primary"
    assert created[1]["type"] == FeedIndicatorType.File
    assert created[1]["value"] == "0f6dbfb291ba1b84601b0372f70db3430df636c631d074c1c2463f9e5a033f21"

    assert created[2]["fields"] == dict(
        cyrenfeedrelationships=[dict(indicatortype="SHA-256",
                                     relationshiptype="downloaded from",
                                     value="243f68c5fffe1e868c012b7fcf20bd8c9025ec199b18d569a497a2e3f1aaca0a",
                                     description="downloaded from malware ip",
                                     timestamp="2020-10-28T11:50:21.000Z",
                                     entitycategory="malware")])
    assert created[2]["score"] == Common.DBotScore.NONE
    assert created[2]["rawJSON"]["source_tag"] == "related"
    assert created[2]["type"] == FeedIndicatorType.IP
    assert created[2]["value"] == "62.149.142.116"

    assert created[3]["fields"] == dict(updateddate="2020-10-28T14:45:24.921Z",
                                        published="2020-10-28T14:45:24.921Z",
                                        indicatoridentification=("243f68c5fffe1e868c012b7fcf20bd8"
                                                                 "c9025ec199b18d569a497a2e3f1aaca0a"),
                                        cyrenfeedrelationships=[
                                            dict(indicatortype="IP",
                                                 relationshiptype="downloaded from",
                                                 value="62.149.142.116",
                                                 description="downloaded from malware ip",
                                                 timestamp="2020-10-28T11:50:21.000Z",
                                                 entitycategory="malware")])
    assert created[3]["score"] == Common.DBotScore.BAD
    assert created[3]["rawJSON"]["tags"] == ["malware", "Malware detection", "js/coinhive.a!eldorado"]
    assert created[3]["rawJSON"]["source_tag"] == "primary"
    assert created[3]["type"] == FeedIndicatorType.File
    assert created[3]["value"] == "243f68c5fffe1e868c012b7fcf20bd8c9025ec199b18d569a497a2e3f1aaca0a"

    assert created[4]["fields"] == dict(
        cyrenfeedrelationships=[dict(indicatortype="SHA-256",
                                     relationshiptype="downloaded from",
                                     value="243f68c5fffe1e868c012b7fcf20bd8c9025ec199b18d569a497a2e3f1aaca0b",
                                     description="downloaded from malware ip",
                                     timestamp="2020-10-28T11:50:21.000Z",
                                     entitycategory="malware")])
    assert created[4]["score"] == Common.DBotScore.NONE
    assert created[4]["rawJSON"]["source_tag"] == "related"
    assert created[4]["type"] == FeedIndicatorType.IP
    assert created[4]["value"] == "62.149.142.116"

    assert created[5]["fields"] == dict(updateddate="2020-10-28T14:45:24.921Z",
                                        indicatoridentification=("243f68c5fffe1e868c012b7fcf20bd8c9"
                                                                 "025ec199b18d569a497a2e3f1aaca0b"),
                                        cyrenfeedrelationships=[
                                            dict(indicatortype="IP",
                                                 relationshiptype="downloaded from",
                                                 value="62.149.142.116",
                                                 description="downloaded from malware ip",
                                                 timestamp="2020-10-28T11:50:21.000Z",
                                                 entitycategory="malware")])
    assert created[5]["score"] == Common.DBotScore.NONE
    assert created[5]["rawJSON"]["tags"] == ["confirmed clean", "Malware detection", "js/coinhive.a!eldorado"]
    assert created[5]["rawJSON"]["source_tag"] == "primary"
    assert created[5]["type"] == FeedIndicatorType.File
    assert created[5]["value"] == "243f68c5fffe1e868c012b7fcf20bd8c9025ec199b18d569a497a2e3f1aaca0b"

    assert created[6]["fields"] == dict(
        cyrenfeedrelationships=[dict(indicatortype="SHA-256",
                                     relationshiptype="downloaded from",
                                     value="243f68c5fffe1e868c012b7fcf20bd8c9025ec199b18d569a497a2e3f1aaca0c",
                                     description="downloaded from malware ip",
                                     timestamp="2020-10-28T11:50:21.000Z",
                                     entitycategory="malware")])
    assert created[6]["score"] == Common.DBotScore.NONE
    assert created[6]["rawJSON"]["source_tag"] == "related"
    assert created[6]["type"] == FeedIndicatorType.IP
    assert created[6]["value"] == "62.149.142.116"

    assert created[7]["fields"] == dict(updateddate="2020-10-28T14:45:24.921Z",
                                        indicatoridentification=("243f68c5fffe1e868c012b7fcf20bd8c"
                                                                 "9025ec199b18d569a497a2e3f1aaca0c"),
                                        cyrenfeedrelationships=[
                                            dict(indicatortype="IP",
                                                 relationshiptype="downloaded from",
                                                 value="62.149.142.116",
                                                 description="downloaded from malware ip",
                                                 timestamp="2020-10-28T11:50:21.000Z",
                                                 entitycategory="malware")])
    assert created[7]["score"] == Common.DBotScore.NONE
    assert created[7]["rawJSON"]["tags"] == ["malware", "Malware detection", "js/coinhive.a!eldorado"]
    assert created[7]["rawJSON"]["source_tag"] == "primary"
    assert created[7]["type"] == FeedIndicatorType.File
    assert created[7]["value"] == "243f68c5fffe1e868c012b7fcf20bd8c9025ec199b18d569a497a2e3f1aaca0c"


def test_fetch_indicators_output_malware_urls(requests_mock, malware_urls):
    """
    Given:
        - the malware URL feed
        - some relationship information in the feed

    When:
        - running fetch-indicators

    Then:
        - the indicator type and value are being set
        - the DBot score is set to
          - BAD on non confirmed-clean category
          - NONE on feed removal and confirmed clean category
        - basic indicator fields are filled from the feed meta data
        - Cyren-specific indicator fields are filled
        - feed related indicator field is filled with IP and SHA-256 relationships

    """

    fetch, _ = _create_instance(requests_mock, "malware_urls", malware_urls, dict(startOffset=0, endOffset=0))
    created = fetch()

    assert len(created) == 8

    assert created[0]["fields"] == dict(
        cyrenfeedrelationships=[dict(indicatortype="URL",
                                     relationshiptype="resolves to",
                                     value="http://radiobarreradigitall.blogspot.com",
                                     description="resolves to malware ip",
                                     timestamp="2020-11-01T16:20:57.000Z",
                                     entitycategory="malware")])
    assert created[0]["score"] == Common.DBotScore.NONE
    assert created[0]["type"] == FeedIndicatorType.IP
    assert created[0]["value"] == "172.217.4.65"

    assert created[1]["fields"] == dict(
        cyrenfeedrelationships=[dict(indicatortype="URL",
                                     relationshiptype="serves",
                                     value="http://radiobarreradigitall.blogspot.com",
                                     description="serves malware file",
                                     timestamp="2020-11-01T16:11:54.000Z",
                                     entitycategory="malware")])
    assert created[1]["score"] == Common.DBotScore.BAD
    assert created[1]["rawJSON"]["source_tag"] == "related"
    assert created[1]["type"] == FeedIndicatorType.File
    assert created[1]["value"] == "a18c43948195abd429ba42ef66b26483a097d987e55289010bc8f935fc950515"

    assert created[2]["fields"] == dict(indicatoridentification="045541ea-fd19-5c08-bb60-437ce08cc08f",
                                        updateddate="2020-11-01T17:45:16.268Z",
                                        published="2020-11-01T17:45:16.268Z",
                                        cyrenfeedrelationships=[
                                            dict(indicatortype="IP",
                                                 relationshiptype="resolves to",
                                                 value="172.217.4.65",
                                                 description="resolves to malware ip",
                                                 timestamp="2020-11-01T16:20:57.000Z",
                                                 entitycategory="malware"),
                                            dict(indicatortype="SHA-256",
                                                 relationshiptype="serves",
                                                 value="a18c43948195abd429ba42ef66b26483a097d987e55289010bc8f935fc950515",
                                                 description="serves malware file",
                                                 timestamp="2020-11-01T16:11:54.000Z",
                                                 entitycategory="malware")])
    assert created[2]["score"] == Common.DBotScore.BAD
    assert created[2]["rawJSON"]["tags"] == ["malware", "Malware detection", "finance"]
    assert created[2]["rawJSON"]["source_tag"] == "primary"
    assert created[2]["type"] == FeedIndicatorType.URL
    assert created[2]["value"] == "http://radiobarreradigitall.blogspot.com"

    assert created[3]["fields"] == dict(
        cyrenfeedrelationships=[dict(indicatortype="URL",
                                     relationshiptype="resolves to",
                                     value=("https://wizkhalifanoticias.blogspot.com/"
                                            "2014/01/wiz-khalifa-adormece-durante.html"),
                                     description="resolves to malware ip",
                                     timestamp="2020-11-01T17:39:16.000Z",
                                     entitycategory="malware")])
    assert created[3]["score"] == Common.DBotScore.NONE
    assert created[3]["rawJSON"]["source_tag"] == "related"
    assert created[3]["type"] == FeedIndicatorType.IP
    assert created[3]["value"] == "172.217.4.193"

    assert created[4]["fields"] == dict(
        cyrenfeedrelationships=[dict(indicatortype="URL",
                                     relationshiptype="serves",
                                     value=("https://wizkhalifanoticias.blogspot.com/"
                                            "2014/01/wiz-khalifa-adormece-durante.html"),
                                     description="serves malware file",
                                     timestamp="2020-11-01T17:39:10.000Z",
                                     entitycategory="malware")])
    assert created[4]["score"] == Common.DBotScore.BAD
    assert created[4]["rawJSON"]["source_tag"] == "related"
    assert created[4]["type"] == FeedIndicatorType.File
    assert created[4]["value"] == "2bbeeaa4139b8e033fc1e114f55917e7180b305e75ac56701a0b6dcda4495494"

    assert created[5]["fields"] == dict(indicatoridentification="05040e64-a035-5014-8564-9c8faaf4da83",
                                        updateddate="2020-11-01T17:45:16.268Z",
                                        published="2020-11-01T17:45:16.268Z",
                                        cyrenfeedrelationships=[
                                            dict(indicatortype="IP",
                                                 relationshiptype="resolves to",
                                                 value="172.217.4.193",
                                                 description="resolves to malware ip",
                                                 timestamp="2020-11-01T17:39:16.000Z",
                                                 entitycategory="malware"),
                                            dict(indicatortype="SHA-256",
                                                 relationshiptype="serves",
                                                 value="2bbeeaa4139b8e033fc1e114f55917e7180b305e75ac56701a0b6dcda4495494",
                                                 description="serves malware file",
                                                 timestamp="2020-11-01T17:39:10.000Z",
                                                 entitycategory="malware")])
    assert created[5]["score"] == Common.DBotScore.BAD
    assert created[5]["rawJSON"]["tags"] == ["malware", "Malware detection"]
    assert created[5]["rawJSON"]["source_tag"] == "primary"
    assert created[5]["type"] == FeedIndicatorType.URL
    assert created[5]["value"] == "https://wizkhalifanoticias.blogspot.com/2014/01/wiz-khalifa-adormece-durante.html"

    assert created[6]["fields"] == dict(indicatoridentification="05040e64-a035-5014-8564-9c8faaf4da84",
                                        updateddate="2020-11-01T17:45:16.268Z")
    assert created[6]["score"] == Common.DBotScore.NONE
    assert created[6]["rawJSON"]["tags"] == ["confirmed clean", "Malware detection"]
    assert created[6]["rawJSON"]["source_tag"] == "primary"
    assert created[6]["type"] == FeedIndicatorType.URL
    assert created[6]["value"] == "https://wizkhalifanoticias.blogspot.com/2014/01/wiz-khalifa-adormece-durante-2.html"

    assert created[7]["fields"] == dict(updateddate="2020-11-01T17:45:16.268Z",
                                        indicatoridentification="05040e64-a035-5014-8564-9c8faaf4da85")
    assert created[7]["score"] == Common.DBotScore.NONE
    assert created[7]["rawJSON"]["tags"] == ["malware", "Malware detection"]
    assert created[7]["rawJSON"]["source_tag"] == "primary"
    assert created[7]["type"] == FeedIndicatorType.URL
    assert created[7]["value"] == "https://wizkhalifanoticias.blogspot.com/2014/01/wiz-khalifa-adormece-durante-3.html"


def test_fetch_indicators_output_phishing_urls(requests_mock, phishing_urls):
    """
    Given:
        - the phishing URL feed
        - some relationship information in the feed

    When:
        - running fetch-indicators

    Then:
        - the indicator type and value are being set
        - the DBot score is set to
          - BAD on non confirmed-clean category
          - NONE on feed removal and confirmed clean category
        - basic indicator fields are filled from the feed meta data
        - Cyren-specific indicator fields are filled
        - feed related indicator field is filled with IP and SHA-256 relationships

    """

    fetch, _ = _create_instance(requests_mock, "phishing_urls", phishing_urls, dict(startOffset=0, endOffset=0))
    created = fetch()

    assert len(created) == 8

    assert created[0]["fields"] == dict(
        cyrenfeedrelationships=[dict(indicatortype="URL",
                                     relationshiptype="resolves to",
                                     value="https://verify.paypalc.o.m.accoun.t-updates.info",
                                     description="resolves to phishing ip",
                                     timestamp="2020-11-01T17:01:45.000Z",
                                     entitycategory="phishing")])
    assert created[0]["score"] == Common.DBotScore.NONE
    assert created[0]["rawJSON"]["source_tag"] == "related"
    assert created[0]["type"] == FeedIndicatorType.IP
    assert created[0]["value"] == "195.201.98.73"

    assert created[1]["fields"] == dict(indicatoridentification="025859f4-4b07-58de-953b-0ed2bdc7ee0f",
                                        updateddate="2020-11-01T17:05:26.347Z",
                                        cyrenfeedrelationships=[
                                            dict(indicatortype="IP",
                                                 relationshiptype="resolves to",
                                                 value="195.201.98.73",
                                                 description="resolves to phishing ip",
                                                 timestamp="2020-11-01T17:01:45.000Z",
                                                 entitycategory="phishing")])
    assert created[1]["score"] == Common.DBotScore.BAD
    assert created[1]["rawJSON"]["tags"] == ["phishing", "URL Categorization", "Active URL inspection", "finance", "apple"]
    assert created[1]["rawJSON"]["source_tag"] == "primary"
    assert created[1]["type"] == FeedIndicatorType.URL
    assert created[1]["value"] == "https://verify.paypalc.o.m.accoun.t-updates.info"

    assert created[2]["fields"] == dict(
        cyrenfeedrelationships=[dict(indicatortype="URL",
                                     relationshiptype="resolves to",
                                     value="http://secureapplelock.servebeer.com/manage",
                                     description="resolves to phishing ip",
                                     timestamp="2020-11-01T17:03:40.000Z",
                                     entitycategory="phishing")])
    assert created[2]["score"] == Common.DBotScore.NONE
    assert created[2]["rawJSON"]["source_tag"] == "related"
    assert created[2]["type"] == FeedIndicatorType.IP
    assert created[2]["value"] == "192.163.194.76"

    assert created[3]["fields"] == dict(indicatoridentification="054f305a-f39c-51b7-b2c3-9f8c281ff1ea",
                                        updateddate="2020-11-01T17:05:26.347Z",
                                        published="2020-11-01T17:05:26.347Z",
                                        cyrenfeedrelationships=[
                                            dict(indicatortype="IP",
                                                 relationshiptype="resolves to",
                                                 value="192.163.194.76",
                                                 description="resolves to phishing ip",
                                                 timestamp="2020-11-01T17:03:40.000Z",
                                                 entitycategory="phishing")])
    assert created[3]["score"] == Common.DBotScore.BAD
    assert created[3]["rawJSON"]["tags"] == ["phishing", "Active URL inspection", "cloudapp"]
    assert created[3]["rawJSON"]["source_tag"] == "primary"
    assert created[3]["type"] == FeedIndicatorType.URL
    assert created[3]["value"] == "http://secureapplelock.servebeer.com/manage"

    assert created[4]["fields"] == dict(
        cyrenfeedrelationships=[dict(indicatortype="URL",
                                     relationshiptype="resolves to",
                                     value="http://secureapplelock.servebeer.com/manage-2",
                                     description="resolves to phishing ip",
                                     timestamp="2020-11-01T17:03:40.000Z",
                                     entitycategory="phishing")])
    assert created[4]["score"] == Common.DBotScore.NONE
    assert created[4]["rawJSON"]["source_tag"] == "related"
    assert created[4]["type"] == FeedIndicatorType.IP
    assert created[4]["value"] == "192.163.194.76"

    assert created[5]["fields"] == dict(indicatoridentification="054f305a-f39c-51b7-b2c3-9f8c281ff1eb",
                                        updateddate="2020-11-01T17:05:26.347Z",
                                        cyrenfeedrelationships=[
                                            dict(indicatortype="IP",
                                                 relationshiptype="resolves to",
                                                 value="192.163.194.76",
                                                 description="resolves to phishing ip",
                                                 timestamp="2020-11-01T17:03:40.000Z",
                                                 entitycategory="phishing")])
    assert created[5]["score"] == Common.DBotScore.NONE
    assert created[5]["rawJSON"]["tags"] == ["confirmed clean", "Active URL inspection", "cloudapp"]
    assert created[5]["rawJSON"]["source_tag"] == "primary"
    assert created[5]["type"] == FeedIndicatorType.URL
    assert created[5]["value"] == "http://secureapplelock.servebeer.com/manage-2"

    assert created[6]["fields"] == dict(
        cyrenfeedrelationships=[dict(indicatortype="URL",
                                     relationshiptype="resolves to",
                                     value="http://secureapplelock.servebeer.com/manage-3",
                                     description="resolves to phishing ip",
                                     timestamp="2020-11-01T17:03:40.000Z",
                                     entitycategory="phishing")])
    assert created[6]["score"] == Common.DBotScore.NONE
    assert created[6]["rawJSON"]["source_tag"] == "related"
    assert created[6]["type"] == FeedIndicatorType.IP
    assert created[6]["value"] == "192.163.194.76"

    assert created[7]["fields"] == dict(updateddate="2020-11-01T17:05:26.347Z",
                                        indicatoridentification="054f305a-f39c-51b7-b2c3-9f8c281ff1ec",
                                        cyrenfeedrelationships=[
                                            dict(indicatortype="IP",
                                                 relationshiptype="resolves to",
                                                 value="192.163.194.76",
                                                 description="resolves to phishing ip",
                                                 timestamp="2020-11-01T17:03:40.000Z",
                                                 entitycategory="phishing")])
    assert created[7]["score"] == Common.DBotScore.NONE
    assert created[7]["rawJSON"]["tags"] == ["phishing", "Active URL inspection", "cloudapp"]
    assert created[7]["rawJSON"]["source_tag"] == "primary"
    assert created[7]["type"] == FeedIndicatorType.URL
    assert created[7]["value"] == "http://secureapplelock.servebeer.com/manage-3"


@pytest.mark.parametrize(
    "context_data, offsets, max_indicators, expected_offset, expected_count", [
        # Given:
        #   - first run
        #   - no previous offset stored
        #   - an end offset of 1000

        # When:
        #   - running get-indicators with count 10

        # Then:
        #   - the API is asked for 10 from offset 991
        (dict(), dict(startOffset=1, endOffset=1000), 10, 991, 10),
        # Given:
        #   - not the first run
        #   - previous offset is 900
        #   - an end offset of 1000

        # When:
        #   - running get-indicators with count 20

        # Then:
        #   - the API is asked for 20 from offset 981
        (dict(offset=900), dict(startOffset=1, endOffset=1000), 20, 981, 20)
    ]
)
def test_get_indicators(requests_mock, phishing_urls, context_data, offsets,
                        max_indicators, expected_offset, expected_count):
    """
    Given:
        - the phishing URL feed

    When:
        - running get-indicators

    Then:
        - no adjustments made to the integration context
        - the number of indicators is taken from the response, meaning 4 entries

    """

    set_integration_context(context_data)
    _, get = _create_instance(requests_mock, "phishing_urls", phishing_urls, offsets, expected_offset, expected_count)
    result = get(max_indicators)

    assert len(result.raw_response) == 8
    assert get_integration_context() == context_data


def test_test_module_server_error(requests_mock):
    """
    Given:
        - the IP reputation feed

    When:
        - running test-module with a 500 Server Error

    Then:
        - it tells you the test failed

    """

    requests_mock.get(BASE_URL + "/data?format=jsonl&feedId=ip_reputation_v2&offset=0&count=10", status_code=500,
                      request_headers=_expected_headers())
    client = _create_client("ip_reputation")

    assert "Test failed because of: Error in API call [500] - None" in _test_module_command(client)


def test_test_module_invalid_token(requests_mock):
    """
    Given:
        - the IP reputation feed

    When:
        - running test-module with a 400 on an invalid claim

    Then:
        - it tells you the test failed

    """

    requests_mock.get(BASE_URL + "/data?format=jsonl&feedId=ip_reputation_v2&offset=0&count=10", status_code=400,
                      request_headers=_expected_headers(),
                      json=dict(statusCode=400,
                                error="unable to parse claims from token: ..."))
    client = _create_client("ip_reputation")

    assert "Test failed because of an invalid API token!" in _test_module_command(client)


def test_test_module_other_400(requests_mock):
    """
    Given:
        - the IP reputation feed

    When:
        - running test-module with an unknown 400

    Then:
        - it tells you the test failed

    """

    requests_mock.get(BASE_URL + "/data?format=jsonl&feedId=ip_reputation_v2&offset=0&count=10", status_code=400,
                      request_headers=_expected_headers())
    client = _create_client("ip_reputation")

    assert "Test failed because of: 400 Client Error:" in _test_module_command(client)


def test_test_module_404(requests_mock):
    """
    Given:
        - the IP reputation feed

    When:
        - running test-module with a 404

    Then:
        - it tells you the test failed

    """

    requests_mock.get(BASE_URL + "/data?format=jsonl&feedId=ip_reputation_v2&offset=0&count=10", status_code=404,
                      request_headers=_expected_headers())
    client = _create_client("ip_reputation")

    assert "Test failed because of an invalid API URL!" in _test_module_command(client)


def test_test_module_no_entries(requests_mock):
    """
    Given:
        - the IP reputation feed

    When:
        - running test-module with no entries being returned

    Then:
        - it tells you the test failed

    """

    requests_mock.get(BASE_URL + "/data?format=jsonl&feedId=ip_reputation_v2&offset=0&count=10", text="",
                      request_headers=_expected_headers())
    client = _create_client("ip_reputation")

    assert "Test failed because no indicators could be fetched!" in _test_module_command(client)


def test_test_module_ok(requests_mock, ip_reputation):
    """
    Given:
        - the IP reputation feed

    When:
        - running test-module with good result

    Then:
        - it tells you the test did not fail

    """

    requests_mock.get(BASE_URL + "/data?format=jsonl&feedId=ip_reputation_v2&offset=0&count=10", text=ip_reputation,
                      request_headers=_expected_headers())
    client = _create_client("ip_reputation")

    assert "ok" == _test_module_command(client)


@pytest.mark.parametrize("offset_data, context_data, offset, expected_text, expected_offset", [
    (
        dict(startOffset=1, endOffset=1000), dict(), None,
        (
            "Reset Cyren Threat InDepth ip_reputation feed client offset to 1000 "
            "(API provided max offset of 1000, was not set before)."
        ),
        1000
    ),
    (
        dict(startOffset=1, endOffset=1000), dict(), 900,
        (
            "Reset Cyren Threat InDepth ip_reputation feed client offset to 900 "
            "(API provided max offset of 1000, was not set before)."
        ),
        900
    ),
    (
        dict(startOffset=1, endOffset=1000), dict(), 1000,
        (
            "Reset Cyren Threat InDepth ip_reputation feed client offset to 1000 "
            "(API provided max offset of 1000, was not set before)."
        ),
        1000
    ),
    (
        dict(startOffset=1, endOffset=1000), dict(), 1001,
        (
            "Reset Cyren Threat InDepth ip_reputation feed client offset to 1000 "
            "(API provided max offset of 1000, was not set before)."
        ),
        1000
    ),
    (
        dict(startOffset=1, endOffset=1000), dict(offset=500), None,
        "Reset Cyren Threat InDepth ip_reputation feed client offset to 1000 (API provided max offset of 1000, was 500).",
        1000
    ),
    (
        dict(startOffset=1, endOffset=1000), dict(offset=500), 900,
        "Reset Cyren Threat InDepth ip_reputation feed client offset to 900 (API provided max offset of 1000, was 500).",
        900
    ),
    (
        dict(startOffset=1, endOffset=1000), dict(offset=500), 1000,
        "Reset Cyren Threat InDepth ip_reputation feed client offset to 1000 (API provided max offset of 1000, was 500).",
        1000
    ),
    (
        dict(startOffset=1, endOffset=1000), dict(offset=500), 1001,
        "Reset Cyren Threat InDepth ip_reputation feed client offset to 1000 (API provided max offset of 1000, was 500).",
        1000
    ),
])
def test_reset_offset_command(requests_mock, offset_data, context_data, offset, expected_text, expected_offset):
    """
    Given:
        - different stored offset configurations and desired offset parameters

    When:
        - running the reset offset command

    Then:
        - I am told what happened in a human-readable form
        - the new context has been stored in the integration context

    """

    set_integration_context(context_data)
    feed = "ip_reputation"
    requests_mock.get(BASE_URL + "/info?format=jsonl&feedId={}_v2".format(feed),
                      json=offset_data, request_headers=_expected_headers())
    client = _create_client(feed)

    args = dict()
    if offset is not None:
        args["offset"] = offset

    result = reset_offset_command(client, args)

    assert result.readable_output == expected_text
    assert get_integration_context() == dict(offset=expected_offset)


@pytest.mark.parametrize("offset_data, context_data, expected_text", [
    (
        dict(startOffset=1, endOffset=1000), dict(),
        (
            "Cyren Threat InDepth ip_reputation feed client offset has not been set yet "
            "(API provided max offset of 1000)."
        )
    ),
    (
        dict(startOffset=1, endOffset=1000), dict(offset=500),
        (
            "Cyren Threat InDepth ip_reputation feed client offset is 500 "
            "(API provided max offset of 1000)."
        )
    ),
])
def test_get_offset_command(requests_mock, offset_data, context_data, expected_text):
    """
    Given:
        - different stored offset configurations

    When:
        - running the get offset command

    Then:
        - I am told what the offset is

    """

    set_integration_context(context_data)
    feed = "ip_reputation"
    requests_mock.get(BASE_URL + "/info?format=jsonl&feedId={}_v2".format(feed),
                      json=offset_data, request_headers=_expected_headers())
    client = _create_client(feed)

    result = get_offset_command(client, dict())

    assert result.readable_output == expected_text
