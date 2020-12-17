import pytest
import pathlib
import os

from CommonServerPython import (
    FeedIndicatorType, DemistoException, Common
)
import demistomock as demisto

from CyrenThreatInDepth import (
    Client, fetch_indicators_command, get_indicators_command,
    test_module_command as _test_module_command
)


pytestmark = pytest.mark.usefixtures("clean_integration_context")


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
    demisto.setIntegrationContext({})
    yield
    demisto.setIntegrationContext({})


def _create_instance(requests_mock, feed, feed_data, offset_data, offset=0, count=2):
    base_url = "https://cyren.feed/"
    requests_mock.get(base_url + "data?format=jsonl&feedId={}&offset={}&count={}".format(feed, offset, count),
                      text=feed_data)
    requests_mock.get(base_url + "info?format=jsonl&feedId={}".format(feed), json=offset_data)
    client = Client(feed_name=feed, base_url=base_url, verify=False, proxy=False)

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

    demisto.setIntegrationContext(context_data)
    fetch, _ = _create_instance(requests_mock, "ip_reputation", ip_reputation, offsets, expected_offset, expected_count)
    created = fetch(initial_count, max_indicators, True)

    assert len(created) == 5
    assert demisto.getIntegrationContext() == dict(offset=50005)


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

    assert len(created) == 5


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

    base_url = "https://cyren.feed/"
    requests_mock.get(base_url + "data?format=jsonl&feedId=ip_reputation&offset=0&count=10",
                      text=response_429, status_code=429)
    requests_mock.get(base_url + "info?format=jsonl&feedId=ip_reputation", json=dict(startOffset=0, endOffset=0))
    client = Client(feed_name="ip_reputation", base_url=base_url, verify=False, proxy=False)

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

    assert len(created) == 5

    assert created[0]["fields"] == dict(firstseenbysource="2020-08-14T15:24:26.463Z",
                                        lastseenbysource="2020-10-29T05:07:34.017Z",
                                        updateddate="2020-10-29T05:15:29.062Z",
                                        indicatoridentification="45.193.212.54",
                                        tags=["spam", "Botnet detection"],
                                        geocountry="HK",
                                        port=[25],
                                        cyrendetectiondate="2020-08-14T15:24:26.463Z",
                                        cyrenfeedaction="update",
                                        cyrendetectioncategories=["spam"],
                                        cyrendetectionmethods=["Botnet detection"],
                                        cyrenobjecttype="ipv4",
                                        cyrenipclass="static",
                                        cyrenport=25,
                                        cyrenprotocol="smtp",
                                        cyrencountrycode="HK")
    assert created[0]["score"] == Common.DBotScore.BAD
    assert created[0]["type"] == FeedIndicatorType.IP
    assert created[0]["value"] == "45.193.212.54"

    assert created[1]["fields"] == dict(firstseenbysource="2020-08-14T15:24:26.463Z",
                                        lastseenbysource="2020-10-29T05:07:39.423Z",
                                        updateddate="2020-10-29T05:15:29.062Z",
                                        indicatoridentification="45.193.216.182",
                                        tags=["malware", "Botnet detection"],
                                        geocountry="HK",
                                        port=[25],
                                        cyrendetectiondate="2020-08-14T15:24:26.463Z",
                                        cyrenfeedaction="update",
                                        cyrendetectioncategories=["malware"],
                                        cyrendetectionmethods=["Botnet detection"],
                                        cyrenobjecttype="ipv4",
                                        cyrenipclass="static",
                                        cyrenport=25,
                                        cyrenprotocol="smtp",
                                        cyrencountrycode="HK")
    assert created[1]["score"] == Common.DBotScore.SUSPICIOUS
    assert created[1]["type"] == FeedIndicatorType.IP
    assert created[1]["value"] == "45.193.216.182"

    assert created[2]["fields"] == dict(firstseenbysource="2020-08-14T15:24:26.463Z",
                                        lastseenbysource="2020-10-29T05:07:39.423Z",
                                        creationdate="2020-10-29T05:15:29.062Z",
                                        published="2020-10-29T05:15:29.062Z",
                                        indicatoridentification="45.193.216.183",
                                        tags=["phishing", "Botnet detection"],
                                        geocountry="HK",
                                        port=[25],
                                        cyrendetectiondate="2020-08-14T15:24:26.463Z",
                                        cyrenfeedaction="add",
                                        cyrendetectioncategories=["phishing"],
                                        cyrendetectionmethods=["Botnet detection"],
                                        cyrenobjecttype="ipv4",
                                        cyrenipclass="static",
                                        cyrenport=25,
                                        cyrenprotocol="smtp",
                                        cyrencountrycode="HK")
    assert created[2]["score"] == Common.DBotScore.SUSPICIOUS
    assert created[2]["type"] == FeedIndicatorType.IP
    assert created[2]["value"] == "45.193.216.183"

    assert created[3]["fields"] == dict(firstseenbysource="2020-08-14T15:24:26.463Z",
                                        lastseenbysource="2020-10-29T05:07:39.423Z",
                                        indicatoridentification="45.193.216.184",
                                        tags=["spam", "Botnet detection"],
                                        geocountry="HK",
                                        port=[25],
                                        cyrendetectiondate="2020-08-14T15:24:26.463Z",
                                        cyrenfeedaction="remove",
                                        cyrendetectioncategories=["spam"],
                                        cyrendetectionmethods=["Botnet detection"],
                                        cyrenobjecttype="ipv4",
                                        cyrenipclass="static",
                                        cyrenport=25,
                                        cyrenprotocol="smtp",
                                        cyrencountrycode="HK")
    assert created[3]["score"] == Common.DBotScore.NONE
    assert created[3]["type"] == FeedIndicatorType.IP
    assert created[3]["value"] == "45.193.216.184"

    assert created[4]["fields"] == dict(firstseenbysource="2020-08-14T15:24:26.463Z",
                                        lastseenbysource="2020-10-29T05:07:39.423Z",
                                        updateddate="2020-10-29T05:15:29.062Z",
                                        indicatoridentification="45.193.216.185",
                                        tags=["confirmed clean", "Botnet detection"],
                                        geocountry="HK",
                                        port=[25],
                                        cyrendetectiondate="2020-08-14T15:24:26.463Z",
                                        cyrenfeedaction="update",
                                        cyrendetectioncategories=["confirmed clean"],
                                        cyrendetectionmethods=["Botnet detection"],
                                        cyrenobjecttype="ipv4",
                                        cyrenipclass="static",
                                        cyrenport=25,
                                        cyrenprotocol="smtp",
                                        cyrencountrycode="HK")
    assert created[4]["score"] == Common.DBotScore.NONE
    assert created[4]["type"] == FeedIndicatorType.IP
    assert created[4]["value"] == "45.193.216.185"


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

    assert len(created) == 4

    assert created[0]["fields"] == dict(firstseenbysource="2020-10-27T17:36:59.000Z",
                                        lastseenbysource="2020-10-28T14:44:00.413Z",
                                        creationdate="2020-10-28T14:45:24.921Z",
                                        published="2020-10-28T14:45:24.921Z",
                                        indicatoridentification=("0f6dbfb291ba1b84601b0372f70db"
                                                                 "3430df636c631d074c1c2463f9e5a033f21"),
                                        tags=["malware", "Malware detection", "js/clickjack.d"],
                                        cyrendetectiondate="2020-10-28T14:42:14.000Z",
                                        cyrenfeedaction="add",
                                        cyrendetectioncategories=["malware"],
                                        cyrendetectionmethods=["Malware detection"],
                                        malwarefamily="js/clickjack.d",
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="172.217.4.65",
                                                 description="downloaded from malware ip")])
    assert created[0]["score"] == Common.DBotScore.BAD
    assert created[0]["type"] == FeedIndicatorType.File
    assert created[0]["value"] == "0f6dbfb291ba1b84601b0372f70db3430df636c631d074c1c2463f9e5a033f21"

    assert created[1]["fields"] == dict(firstseenbysource="2020-10-28T11:40:19.000Z",
                                        lastseenbysource="2020-10-28T14:41:49.667Z",
                                        creationdate="2020-10-28T14:45:24.921Z",
                                        published="2020-10-28T14:45:24.921Z",
                                        indicatoridentification=("243f68c5fffe1e868c012b7fcf20bd8"
                                                                 "c9025ec199b18d569a497a2e3f1aaca0a"),
                                        tags=["malware", "Malware detection", "js/coinhive.a!eldorado"],
                                        cyrendetectiondate="2020-10-28T11:50:21.000Z",
                                        cyrenfeedaction="add",
                                        cyrendetectioncategories=["malware"],
                                        cyrendetectionmethods=["Malware detection"],
                                        malwarefamily="js/coinhive.a!eldorado",
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="62.149.142.116",
                                                 description="downloaded from malware ip")])
    assert created[1]["score"] == Common.DBotScore.BAD
    assert created[1]["type"] == FeedIndicatorType.File
    assert created[1]["value"] == "243f68c5fffe1e868c012b7fcf20bd8c9025ec199b18d569a497a2e3f1aaca0a"

    assert created[2]["fields"] == dict(firstseenbysource="2020-10-28T11:40:19.000Z",
                                        lastseenbysource="2020-10-28T14:41:49.667Z",
                                        updateddate="2020-10-28T14:45:24.921Z",
                                        indicatoridentification=("243f68c5fffe1e868c012b7fcf20bd8c9"
                                                                 "025ec199b18d569a497a2e3f1aaca0b"),
                                        tags=["confirmed clean", "Malware detection", "js/coinhive.a!eldorado"],
                                        cyrendetectiondate="2020-10-28T11:50:21.000Z",
                                        cyrenfeedaction="update",
                                        cyrendetectioncategories=["confirmed clean"],
                                        cyrendetectionmethods=["Malware detection"],
                                        malwarefamily="js/coinhive.a!eldorado",
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="62.149.142.116",
                                                 description="downloaded from malware ip")])
    assert created[2]["score"] == Common.DBotScore.NONE
    assert created[2]["type"] == FeedIndicatorType.File
    assert created[2]["value"] == "243f68c5fffe1e868c012b7fcf20bd8c9025ec199b18d569a497a2e3f1aaca0b"

    assert created[3]["fields"] == dict(firstseenbysource="2020-10-28T11:40:19.000Z",
                                        lastseenbysource="2020-10-28T14:41:49.667Z",
                                        indicatoridentification=("243f68c5fffe1e868c012b7fcf20bd8c"
                                                                 "9025ec199b18d569a497a2e3f1aaca0c"),
                                        tags=["malware", "Malware detection", "js/coinhive.a!eldorado"],
                                        cyrendetectiondate="2020-10-28T11:50:21.000Z",
                                        cyrenfeedaction="remove",
                                        cyrendetectioncategories=["malware"],
                                        cyrendetectionmethods=["Malware detection"],
                                        malwarefamily="js/coinhive.a!eldorado",
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="62.149.142.116",
                                                 description="downloaded from malware ip")])
    assert created[3]["score"] == Common.DBotScore.NONE
    assert created[3]["type"] == FeedIndicatorType.File
    assert created[3]["value"] == "243f68c5fffe1e868c012b7fcf20bd8c9025ec199b18d569a497a2e3f1aaca0c"


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

    assert len(created) == 6

    assert created[0]["fields"] == dict(
        feedrelatedindicators=[
            dict(type="Indicator", value="http://radiobarreradigitall.blogspot.com",
                 description="served by malware URL")
        ]
    )
    assert created[0]["score"] == Common.DBotScore.BAD
    assert created[0]["type"] == FeedIndicatorType.File
    assert created[0]["value"] == "a18c43948195abd429ba42ef66b26483a097d987e55289010bc8f935fc950515"

    assert created[1]["fields"] == dict(firstseenbysource="2020-11-01T16:11:54.000Z",
                                        lastseenbysource="2020-11-01T17:41:54.113Z",
                                        tags=["malware", "Malware detection", "finance"],
                                        indicatoridentification="045541ea-fd19-5c08-bb60-437ce08cc08f",
                                        creationdate="2020-11-01T17:45:16.268Z",
                                        published="2020-11-01T17:45:16.268Z",
                                        port=[80],
                                        cyrendetectiondate="2020-11-01T16:20:57.000Z",
                                        cyrendetectioncategories=["malware"],
                                        cyrendetectionmethods=["Malware detection"],
                                        cyrenfeedaction="add",
                                        cyrenindustries=["finance"],
                                        cyrenphishingbrands=[],
                                        cyrenport=80,
                                        cyrenprotocol="http",
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="172.217.4.65",
                                                 description="resolves to malware ip"),
                                            dict(type="Indicator",
                                                 value="a18c43948195abd429ba42ef66b26483a097d987e55289010bc8f935fc950515",
                                                 description="serves malware file")])
    assert created[1]["score"] == Common.DBotScore.BAD
    assert created[1]["type"] == FeedIndicatorType.URL
    assert created[1]["value"] == "http://radiobarreradigitall.blogspot.com"

    assert created[2]["fields"] == dict(
        feedrelatedindicators=[
            dict(type="Indicator", value="https://wizkhalifanoticias.blogspot.com/2014/01/wiz-khalifa-adormece-durante.html",
                 description="served by malware URL")
        ]
    )
    assert created[2]["score"] == Common.DBotScore.BAD
    assert created[2]["type"] == FeedIndicatorType.File
    assert created[2]["value"] == "2bbeeaa4139b8e033fc1e114f55917e7180b305e75ac56701a0b6dcda4495494"

    assert created[3]["fields"] == dict(firstseenbysource="2020-11-01T17:39:10.000Z",
                                        lastseenbysource="2020-11-01T17:40:25.020Z",
                                        tags=["malware", "Malware detection"],
                                        indicatoridentification="05040e64-a035-5014-8564-9c8faaf4da83",
                                        creationdate="2020-11-01T17:45:16.268Z",
                                        published="2020-11-01T17:45:16.268Z",
                                        port=[443],
                                        cyrendetectiondate="2020-11-01T17:39:16.000Z",
                                        cyrendetectioncategories=["malware"],
                                        cyrendetectionmethods=["Malware detection"],
                                        cyrenfeedaction="add",
                                        cyrenindustries=[],
                                        cyrenphishingbrands=[],
                                        cyrenport=443,
                                        cyrenprotocol="https",
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="172.217.4.193",
                                                 description="resolves to malware ip"),
                                            dict(type="Indicator",
                                                 value="2bbeeaa4139b8e033fc1e114f55917e7180b305e75ac56701a0b6dcda4495494",
                                                 description="serves malware file")])
    assert created[3]["score"] == Common.DBotScore.BAD
    assert created[3]["type"] == FeedIndicatorType.URL
    assert created[3]["value"] == "https://wizkhalifanoticias.blogspot.com/2014/01/wiz-khalifa-adormece-durante.html"

    assert created[4]["fields"] == dict(firstseenbysource="2020-11-01T17:39:10.000Z",
                                        lastseenbysource="2020-11-01T17:40:25.020Z",
                                        tags=["confirmed clean", "Malware detection"],
                                        indicatoridentification="05040e64-a035-5014-8564-9c8faaf4da84",
                                        updateddate="2020-11-01T17:45:16.268Z",
                                        port=[443],
                                        cyrendetectiondate="2020-11-01T17:39:16.000Z",
                                        cyrendetectioncategories=["confirmed clean"],
                                        cyrendetectionmethods=["Malware detection"],
                                        cyrenfeedaction="update",
                                        cyrenindustries=[],
                                        cyrenphishingbrands=[],
                                        cyrenport=443,
                                        cyrenprotocol="https",
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="172.217.4.193",
                                                 description="resolves to malware ip"),
                                            dict(type="Indicator",
                                                 value="2bbeeaa4139b8e033fc1e114f55917e7180b305e75ac56701a0b6dcda4495494",
                                                 description="serves malware file")])
    assert created[4]["score"] == Common.DBotScore.NONE
    assert created[4]["type"] == FeedIndicatorType.URL
    assert created[4]["value"] == "https://wizkhalifanoticias.blogspot.com/2014/01/wiz-khalifa-adormece-durante-2.html"

    assert created[5]["fields"] == dict(firstseenbysource="2020-11-01T17:39:10.000Z",
                                        lastseenbysource="2020-11-01T17:40:25.020Z",
                                        tags=["malware", "Malware detection"],
                                        indicatoridentification="05040e64-a035-5014-8564-9c8faaf4da85",
                                        port=[443],
                                        cyrendetectiondate="2020-11-01T17:39:16.000Z",
                                        cyrendetectioncategories=["malware"],
                                        cyrendetectionmethods=["Malware detection"],
                                        cyrenfeedaction="remove",
                                        cyrenindustries=[],
                                        cyrenphishingbrands=[],
                                        cyrenport=443,
                                        cyrenprotocol="https",
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="172.217.4.193",
                                                 description="resolves to malware ip"),
                                            dict(type="Indicator",
                                                 value="2bbeeaa4139b8e033fc1e114f55917e7180b305e75ac56701a0b6dcda4495494",
                                                 description="serves malware file")])
    assert created[5]["score"] == Common.DBotScore.NONE
    assert created[5]["type"] == FeedIndicatorType.URL
    assert created[5]["value"] == "https://wizkhalifanoticias.blogspot.com/2014/01/wiz-khalifa-adormece-durante-3.html"


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

    assert len(created) == 4

    assert created[0]["fields"] == dict(firstseenbysource="2020-10-31T00:41:08.000Z",
                                        lastseenbysource="2020-11-01T17:01:45.000Z",
                                        tags=["phishing", "URL Categorization", "Active URL inspection", "finance", "apple"],
                                        indicatoridentification="025859f4-4b07-58de-953b-0ed2bdc7ee0f",
                                        updateddate="2020-11-01T17:05:26.347Z",
                                        port=[443],
                                        cyrendetectiondate="2020-11-01T09:10:33.000Z",
                                        cyrendetectioncategories=["phishing"],
                                        cyrendetectionmethods=["URL Categorization", "Active URL inspection"],
                                        cyrenfeedaction="update",
                                        cyrenindustries=["finance"],
                                        cyrenphishingbrands=["apple"],
                                        cyrenport=443,
                                        cyrenprotocol="https",
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="195.201.98.73",
                                                 description="resolves to phishing ip")])
    assert created[0]["score"] == Common.DBotScore.BAD
    assert created[0]["type"] == FeedIndicatorType.URL
    assert created[0]["value"] == "https://verify.paypalc.o.m.accoun.t-updates.info"

    assert created[1]["fields"] == dict(firstseenbysource="2019-05-11T17:03:55.000Z",
                                        lastseenbysource="2020-11-01T17:03:40.000Z",
                                        tags=["phishing", "Active URL inspection", "cloudapp"],
                                        indicatoridentification="054f305a-f39c-51b7-b2c3-9f8c281ff1ea",
                                        creationdate="2020-11-01T17:05:26.347Z",
                                        published="2020-11-01T17:05:26.347Z",
                                        port=[80],
                                        cyrendetectiondate="2020-11-01T17:03:40.000Z",
                                        cyrendetectioncategories=["phishing"],
                                        cyrendetectionmethods=["Active URL inspection"],
                                        cyrenfeedaction="add",
                                        cyrenindustries=["cloudapp"],
                                        cyrenphishingbrands=[],
                                        cyrenport=80,
                                        cyrenprotocol="http",
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="192.163.194.76",
                                                 description="resolves to phishing ip")])
    assert created[1]["score"] == Common.DBotScore.BAD
    assert created[1]["type"] == FeedIndicatorType.URL
    assert created[1]["value"] == "http://secureapplelock.servebeer.com/manage"

    assert created[2]["fields"] == dict(firstseenbysource="2019-05-11T17:03:55.000Z",
                                        lastseenbysource="2020-11-01T17:03:40.000Z",
                                        tags=["confirmed clean", "Active URL inspection", "cloudapp"],
                                        indicatoridentification="054f305a-f39c-51b7-b2c3-9f8c281ff1eb",
                                        updateddate="2020-11-01T17:05:26.347Z",
                                        port=[80],
                                        cyrendetectiondate="2020-11-01T17:03:40.000Z",
                                        cyrendetectioncategories=["confirmed clean"],
                                        cyrendetectionmethods=["Active URL inspection"],
                                        cyrenfeedaction="update",
                                        cyrenindustries=["cloudapp"],
                                        cyrenphishingbrands=[],
                                        cyrenport=80,
                                        cyrenprotocol="http",
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="192.163.194.76",
                                                 description="resolves to phishing ip")])
    assert created[2]["score"] == Common.DBotScore.NONE
    assert created[2]["type"] == FeedIndicatorType.URL
    assert created[2]["value"] == "http://secureapplelock.servebeer.com/manage-2"

    assert created[3]["fields"] == dict(firstseenbysource="2019-05-11T17:03:55.000Z",
                                        lastseenbysource="2020-11-01T17:03:40.000Z",
                                        tags=["phishing", "Active URL inspection", "cloudapp"],
                                        indicatoridentification="054f305a-f39c-51b7-b2c3-9f8c281ff1ec",
                                        port=[80],
                                        cyrendetectiondate="2020-11-01T17:03:40.000Z",
                                        cyrendetectioncategories=["phishing"],
                                        cyrendetectionmethods=["Active URL inspection"],
                                        cyrenfeedaction="remove",
                                        cyrenindustries=["cloudapp"],
                                        cyrenphishingbrands=[],
                                        cyrenport=80,
                                        cyrenprotocol="http",
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="192.163.194.76",
                                                 description="resolves to phishing ip")])
    assert created[3]["score"] == Common.DBotScore.NONE
    assert created[3]["type"] == FeedIndicatorType.URL
    assert created[3]["value"] == "http://secureapplelock.servebeer.com/manage-3"


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

    demisto.setIntegrationContext(context_data)
    _, get = _create_instance(requests_mock, "phishing_urls", phishing_urls, offsets, expected_offset, expected_count)
    result = get(max_indicators)

    assert len(result.raw_response) == 4
    assert demisto.getIntegrationContext() == context_data


def test_test_module_server_error(requests_mock):
    """
    Given:
        - the IP reputation feed

    When:
        - running test-module with a 500 Server Error

    Then:
        - it tells you the test failed

    """

    base_url = "https://cyren.feed/"
    requests_mock.get(base_url + "data?format=jsonl&feedId=ip_reputation&offset=0&count=10", status_code=500)
    client = Client(feed_name="ip_reputation", base_url=base_url, verify=False, proxy=False)

    assert "Test failed because of: Error in API call [500] - None" in _test_module_command(client)


def test_test_module_no_entries(requests_mock):
    """
    Given:
        - the IP reputation feed

    When:
        - running test-module with no entries being returned

    Then:
        - it tells you the test failed

    """

    base_url = "https://cyren.feed/"
    requests_mock.get(base_url + "data?format=jsonl&feedId=ip_reputation&offset=0&count=10", text="")
    client = Client(feed_name="ip_reputation", base_url=base_url, verify=False, proxy=False)

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

    base_url = "https://cyren.feed/"
    requests_mock.get(base_url + "data?format=jsonl&feedId=ip_reputation&offset=0&count=10", text=ip_reputation)
    client = Client(feed_name="ip_reputation", base_url=base_url, verify=False, proxy=False)

    assert "ok" == _test_module_command(client)
