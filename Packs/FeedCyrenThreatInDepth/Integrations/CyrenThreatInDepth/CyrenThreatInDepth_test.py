import pytest
import pathlib
import os

from CommonServerPython import FeedIndicatorType, DemistoException
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
        # first run, no previous offset stored, don't want to have initial
        # import, trying to get 2 in total
        (dict(), dict(startOffset=1, endOffset=10000), 0, 2, 10000, 2),
        # first run, no previous offset stored, want 1000 as initial
        # import, trying to get 1002 in total
        (dict(), dict(startOffset=1, endOffset=10000), 1000, 2, 9001, 1002),
        # not the first run, next accepted offset is 9001, initial import
        # ignored, getting just the maximum of 2
        (dict(offset=9001), dict(startOffset=1, endOffset=10000), 0, 2, 9001, 2),
        (dict(offset=9001), dict(startOffset=1, endOffset=10000), 10000, 2, 9001, 2),
        # not the first run, next accepted offset is 9001, initial import
        # ignored, getting a maximum of 2000, even though more would be
        # available
        (dict(offset=9001), dict(startOffset=1, endOffset=10000), 0, 2000, 9001, 2000),
        (dict(offset=9001), dict(startOffset=1, endOffset=10000), 10000, 2000, 9001, 2000),
        # count is capped at 100000
        (dict(), dict(startOffset=1, endOffset=10000), 0, 100001, 10000, 100000),
        (dict(offset=9001), dict(startOffset=1, endOffset=10000), 0, 100001, 9001, 100000),
    ]
)
def test_fetch_indicators_offsets(requests_mock, ip_reputation, context_data, offsets,
                                  initial_count, max_indicators, expected_offset, expected_count):
    demisto.setIntegrationContext(context_data)
    fetch, _ = _create_instance(requests_mock, "ip_reputation", ip_reputation, offsets, expected_offset, expected_count)
    created = fetch(initial_count, max_indicators, True)

    assert len(created) == 5

    # regardless of the counts from the API, the next offset is determined by
    # the entries themselves
    assert demisto.getIntegrationContext() == dict(offset=50005)


def test_fetch_indicators_parsing_errors(requests_mock, ip_reputation):
    ip_reputation_with_errors = f"\nbla\n{ip_reputation}\n\nno json, too\n"
    fetch, _ = _create_instance(requests_mock, "ip_reputation", ip_reputation_with_errors, dict(startOffset=0, endOffset=0))
    created = fetch()

    assert len(created) == 5


def test_fetch_indicators_rate_limiting(requests_mock, response_429):
    base_url = "https://cyren.feed/"
    requests_mock.get(base_url + "data?format=jsonl&feedId=ip_reputation&offset=0&count=10",
                      text=response_429, status_code=429)
    requests_mock.get(base_url + "info?format=jsonl&feedId=ip_reputation", json=dict(startOffset=0, endOffset=0))
    client = Client(feed_name="ip_reputation", base_url=base_url, verify=False, proxy=False)

    with pytest.raises(DemistoException, match=f".*{response_429}.*"):
        fetch_indicators_command(client, 0, 10, False)


def test_fetch_indicators_output_ip_reputation(requests_mock, ip_reputation):
    fetch, _ = _create_instance(requests_mock, "ip_reputation", ip_reputation, dict(startOffset=0, endOffset=0))
    created = fetch()

    assert len(created) == 5

    assert created[0]["fields"] == dict(associations=["Botnet detection"],
                                        firstseenbysource="2020-08-14T15:24:26.463Z",
                                        lastseenbysource="2020-10-29T05:07:34.017Z",
                                        name="ip_reputation",
                                        tags=["spam"])
    assert created[0]["score"] == 3
    assert created[0]["type"] == FeedIndicatorType.IP
    assert created[0]["value"] == "45.193.212.54"

    assert created[1]["fields"] == dict(associations=["Botnet detection"],
                                        firstseenbysource="2020-08-14T15:24:26.463Z",
                                        lastseenbysource="2020-10-29T05:07:39.423Z",
                                        name="ip_reputation",
                                        tags=["malware"])
    assert created[1]["score"] == 2
    assert created[1]["type"] == FeedIndicatorType.IP
    assert created[1]["value"] == "45.193.216.182"

    assert created[2]["fields"] == dict(associations=["Botnet detection"],
                                        firstseenbysource="2020-08-14T15:24:26.463Z",
                                        lastseenbysource="2020-10-29T05:07:39.423Z",
                                        name="ip_reputation",
                                        tags=["phishing"])
    assert created[2]["score"] == 2
    assert created[2]["type"] == FeedIndicatorType.IP
    assert created[2]["value"] == "45.193.216.183"

    assert created[3]["fields"] == dict(associations=["Botnet detection"],
                                        firstseenbysource="2020-08-14T15:24:26.463Z",
                                        lastseenbysource="2020-10-29T05:07:39.423Z",
                                        name="ip_reputation",
                                        tags=["spam"])
    assert created[3]["score"] == 0
    assert created[3]["type"] == FeedIndicatorType.IP
    assert created[3]["value"] == "45.193.216.184"

    assert created[4]["fields"] == dict(associations=["Botnet detection"],
                                        firstseenbysource="2020-08-14T15:24:26.463Z",
                                        lastseenbysource="2020-10-29T05:07:39.423Z",
                                        name="ip_reputation",
                                        tags=["confirmed clean"])
    assert created[4]["score"] == 0
    assert created[4]["type"] == FeedIndicatorType.IP
    assert created[4]["value"] == "45.193.216.185"


def test_fetch_indicators_output_malware_files(requests_mock, malware_files):
    fetch, _ = _create_instance(requests_mock, "malware_files", malware_files, dict(startOffset=0, endOffset=0))
    created = fetch()

    assert len(created) == 4

    assert created[0]["fields"] == dict(associations=["Malware detection"],
                                        firstseenbysource="2020-10-27T17:36:59.000Z",
                                        lastseenbysource="2020-10-28T14:44:00.413Z",
                                        name="malware_files",
                                        tags=["malware"],
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="172.217.4.65",
                                                 description="downloaded from malware ip")])
    assert created[0]["score"] == 3
    assert created[0]["type"] == FeedIndicatorType.File
    assert created[0]["value"] == "0f6dbfb291ba1b84601b0372f70db3430df636c631d074c1c2463f9e5a033f21"

    assert created[1]["fields"] == dict(associations=["Malware detection"],
                                        firstseenbysource="2020-10-28T11:40:19.000Z",
                                        lastseenbysource="2020-10-28T14:41:49.667Z",
                                        name="malware_files",
                                        tags=["malware"],
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="62.149.142.116",
                                                 description="downloaded from malware ip")])
    assert created[1]["score"] == 3
    assert created[1]["type"] == FeedIndicatorType.File
    assert created[1]["value"] == "243f68c5fffe1e868c012b7fcf20bd8c9025ec199b18d569a497a2e3f1aaca0a"

    assert created[2]["fields"] == dict(associations=["Malware detection"],
                                        firstseenbysource="2020-10-28T11:40:19.000Z",
                                        lastseenbysource="2020-10-28T14:41:49.667Z",
                                        name="malware_files",
                                        tags=["confirmed clean"],
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="62.149.142.116",
                                                 description="downloaded from malware ip")])
    assert created[2]["score"] == 0
    assert created[2]["type"] == FeedIndicatorType.File
    assert created[2]["value"] == "243f68c5fffe1e868c012b7fcf20bd8c9025ec199b18d569a497a2e3f1aaca0b"

    assert created[3]["fields"] == dict(associations=["Malware detection"],
                                        firstseenbysource="2020-10-28T11:40:19.000Z",
                                        lastseenbysource="2020-10-28T14:41:49.667Z",
                                        name="malware_files",
                                        tags=["malware"],
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="62.149.142.116",
                                                 description="downloaded from malware ip")])
    assert created[3]["score"] == 0
    assert created[3]["type"] == FeedIndicatorType.File
    assert created[3]["value"] == "243f68c5fffe1e868c012b7fcf20bd8c9025ec199b18d569a497a2e3f1aaca0c"


def test_fetch_indicators_output_malware_urls(requests_mock, malware_urls):
    fetch, _ = _create_instance(requests_mock, "malware_urls", malware_urls, dict(startOffset=0, endOffset=0))
    created = fetch()

    assert len(created) == 4

    assert created[0]["fields"] == dict(associations=["Malware detection"],
                                        firstseenbysource="2020-11-01T16:11:54.000Z",
                                        lastseenbysource="2020-11-01T17:41:54.113Z",
                                        name="malware_urls",
                                        tags=["malware"],
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="172.217.4.65",
                                                 description="resolves to malware ip"),
                                            dict(type="Indicator",
                                                 value="a18c43948195abd429ba42ef66b26483a097d987e55289010bc8f935fc950515",
                                                 description="serves malware file")])
    assert created[0]["score"] == 3
    assert created[0]["type"] == FeedIndicatorType.URL
    assert created[0]["value"] == "http://radiobarreradigitall.blogspot.com"

    assert created[1]["fields"] == dict(associations=["Malware detection"],
                                        firstseenbysource="2020-11-01T17:39:10.000Z",
                                        lastseenbysource="2020-11-01T17:40:25.020Z",
                                        name="malware_urls",
                                        tags=["malware"],
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="172.217.4.193",
                                                 description="resolves to malware ip"),
                                            dict(type="Indicator",
                                                 value="2bbeeaa4139b8e033fc1e114f55917e7180b305e75ac56701a0b6dcda4495494",
                                                 description="serves malware file")])
    assert created[1]["score"] == 3
    assert created[1]["type"] == FeedIndicatorType.URL
    assert created[1]["value"] == "https://wizkhalifanoticias.blogspot.com/2014/01/wiz-khalifa-adormece-durante.html"

    assert created[2]["fields"] == dict(associations=["Malware detection"],
                                        firstseenbysource="2020-11-01T17:39:10.000Z",
                                        lastseenbysource="2020-11-01T17:40:25.020Z",
                                        name="malware_urls",
                                        tags=["confirmed clean"],
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="172.217.4.193",
                                                 description="resolves to malware ip"),
                                            dict(type="Indicator",
                                                 value="2bbeeaa4139b8e033fc1e114f55917e7180b305e75ac56701a0b6dcda4495494",
                                                 description="serves malware file")])
    assert created[2]["score"] == 0
    assert created[2]["type"] == FeedIndicatorType.URL
    assert created[2]["value"] == "https://wizkhalifanoticias.blogspot.com/2014/01/wiz-khalifa-adormece-durante-2.html"

    assert created[3]["fields"] == dict(associations=["Malware detection"],
                                        firstseenbysource="2020-11-01T17:39:10.000Z",
                                        lastseenbysource="2020-11-01T17:40:25.020Z",
                                        name="malware_urls",
                                        tags=["malware"],
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="172.217.4.193",
                                                 description="resolves to malware ip"),
                                            dict(type="Indicator",
                                                 value="2bbeeaa4139b8e033fc1e114f55917e7180b305e75ac56701a0b6dcda4495494",
                                                 description="serves malware file")])
    assert created[3]["score"] == 0
    assert created[3]["type"] == FeedIndicatorType.URL
    assert created[3]["value"] == "https://wizkhalifanoticias.blogspot.com/2014/01/wiz-khalifa-adormece-durante-3.html"


def test_fetch_indicators_output_phishing_urls(requests_mock, phishing_urls):
    fetch, _ = _create_instance(requests_mock, "phishing_urls", phishing_urls, dict(startOffset=0, endOffset=0))
    created = fetch()

    assert len(created) == 4

    assert created[0]["fields"] == dict(associations=["URL Categorization", "Active URL inspection"],
                                        firstseenbysource="2020-10-31T00:41:08.000Z",
                                        lastseenbysource="2020-11-01T17:01:45.000Z",
                                        name="phishing_urls",
                                        tags=["phishing"],
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="195.201.98.73",
                                                 description="resolves to phishing ip")])
    assert created[0]["score"] == 3
    assert created[0]["type"] == FeedIndicatorType.URL
    assert created[0]["value"] == "https://verify.paypalc.o.m.accoun.t-updates.info"

    assert created[1]["fields"] == dict(associations=["Active URL inspection"],
                                        firstseenbysource="2019-05-11T17:03:55.000Z",
                                        lastseenbysource="2020-11-01T17:03:40.000Z",
                                        name="phishing_urls",
                                        tags=["phishing"],
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="192.163.194.76",
                                                 description="resolves to phishing ip")])
    assert created[1]["score"] == 3
    assert created[1]["type"] == FeedIndicatorType.URL
    assert created[1]["value"] == "http://secureapplelock.servebeer.com/manage"

    assert created[2]["fields"] == dict(associations=["Active URL inspection"],
                                        firstseenbysource="2019-05-11T17:03:55.000Z",
                                        lastseenbysource="2020-11-01T17:03:40.000Z",
                                        name="phishing_urls",
                                        tags=["confirmed clean"],
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="192.163.194.76",
                                                 description="resolves to phishing ip")])
    assert created[2]["score"] == 0
    assert created[2]["type"] == FeedIndicatorType.URL
    assert created[2]["value"] == "http://secureapplelock.servebeer.com/manage-2"

    assert created[3]["fields"] == dict(associations=["Active URL inspection"],
                                        firstseenbysource="2019-05-11T17:03:55.000Z",
                                        lastseenbysource="2020-11-01T17:03:40.000Z",
                                        name="phishing_urls",
                                        tags=["phishing"],
                                        feedrelatedindicators=[
                                            dict(type="Indicator",
                                                 value="192.163.194.76",
                                                 description="resolves to phishing ip")])
    assert created[3]["score"] == 0
    assert created[3]["type"] == FeedIndicatorType.URL
    assert created[3]["value"] == "http://secureapplelock.servebeer.com/manage-3"


@pytest.mark.parametrize(
    "context_data, offsets, max_indicators, expected_offset, expected_count", [
        (dict(), dict(startOffset=1, endOffset=1000), 10, 991, 10),
        (dict(offset=900), dict(startOffset=1, endOffset=1000), 20, 981, 20)
    ]
)
def test_get_indicators(requests_mock, phishing_urls, context_data, offsets,
                        max_indicators, expected_offset, expected_count):
    demisto.setIntegrationContext(context_data)
    _, get = _create_instance(requests_mock, "phishing_urls", phishing_urls, offsets, expected_offset, expected_count)
    get(max_indicators)

    assert demisto.getIntegrationContext() == context_data


def test_test_module_server_error(requests_mock):
    base_url = "https://cyren.feed/"
    requests_mock.get(base_url + "data?format=jsonl&feedId=ip_reputation&offset=0&count=10", status_code=500)
    client = Client(feed_name="ip_reputation", base_url=base_url, verify=False, proxy=False)

    assert "Test failed because of: Error in API call [500] - None" in _test_module_command(client)


def test_test_module_no_entries(requests_mock):
    base_url = "https://cyren.feed/"
    requests_mock.get(base_url + "data?format=jsonl&feedId=ip_reputation&offset=0&count=10", text="")
    client = Client(feed_name="ip_reputation", base_url=base_url, verify=False, proxy=False)

    assert "Test failed because no indicators could be fetched!" in _test_module_command(client)


def test_test_module_ok(requests_mock, ip_reputation):
    base_url = "https://cyren.feed/"
    requests_mock.get(base_url + "data?format=jsonl&feedId=ip_reputation&offset=0&count=10", text=ip_reputation)
    client = Client(feed_name="ip_reputation", base_url=base_url, verify=False, proxy=False)

    assert "ok" == _test_module_command(client)
