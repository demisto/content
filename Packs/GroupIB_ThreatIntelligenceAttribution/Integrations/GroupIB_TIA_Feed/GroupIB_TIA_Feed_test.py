import ast
from types import SimpleNamespace
from unittest.mock import MagicMock
import pytest
import string
import hashlib
import re
import os
import time
from dataclasses import replace
from datetime import UTC, datetime
from json import load
from typing import Any
from GroupIB_TIA_Feed import (
    COLLECTIONS,
    Client,
    CollectionSpec,
    FetchIndicatorsCommand,
    GetIndicatorsCommand,
    IndicatorBuilder,
    Settings,
    main,
)
import GroupIB_TIA_Feed
from CommonServerPython import DemistoException
from ciaops import Parser, TICollections, TIRequestParams
from ciaops.exception import ConnectionException, NotFoundException

SERVER_ERROR = "HTTP 500: There are some troubles on server with your request."
SEQUENCE_LIST_DOWN = "Retries exhausted for https://api.example.com/api/v2/sequence_list: too many 502 error responses"
UPDATE_FEED_DOWN = "Retries exhausted for https://api.example.com/api/v2/malware/cnc/updated: too many 502 error responses"

COLLECTION_NAMES = [
    "compromised/account_group",
    "attacks/ddos",
    "attacks/deface",
    "attacks/phishing_kit",
    "attacks/phishing_group",
    "apt/threat",
    "hi/threat",
    "suspicious_ip/tor_node",
    "suspicious_ip/open_proxy",
    "suspicious_ip/socks_proxy",
    "suspicious_ip/vpn",
    "suspicious_ip/scanner",
    "malware/cnc",
    "osi/vulnerability",
    "osi/git_repository",
    "ioc/common",
    "ioc/primary",
    "compromised/spd",
    "hi/open_threats",
]

realpath = os.path.join(os.path.dirname(os.path.realpath(__file__)))

with open(f"{realpath}/test_data/main_collections_examples.json") as example:
    COLLECTIONS_RAW_JSON = load(example)


def _feed_client(**kwargs) -> Client:
    return Client(
        base_url="https://example.com", auth=("example@example.com", "token"), verify=kwargs.pop("verify", True), **kwargs
    )


def _build(collection: str, parsed: dict, settings: Settings | None = None) -> list[dict]:
    """The indicators of one parsed record."""
    return IndicatorBuilder(collection, settings or Settings()).build([parsed])


def _from_raw(collection: str, items: list[dict], settings: Settings | None = None) -> list[dict]:
    """The indicators of raw records, parsed by ciaops with the collection's parser mapping."""
    builder = IndicatorBuilder(collection, settings or Settings())
    return builder.build(builder.parse(Parser({"count": len(items), "items": items, "seqUpdate": 1}, [], [])))


def _fetch(
    client: Client,
    last_run: dict | None = None,
    first_fetch_time: str = "3 days",
    indicator_collections: list[str] | None = None,
    requests_count: int = 1,
    settings: Settings | None = None,
    limit: int | None = None,
    hunting_rules: bool = False,
) -> tuple[dict, list]:
    """One fetch-indicators run under the indicator settings of ``settings``: the next fetch state and the indicators
    to create."""
    run_settings = replace(
        settings or Settings(),
        collections=list(indicator_collections or []),
        first_fetch=first_fetch_time,
        requests_count=requests_count,
        limit=limit,  # type: ignore[arg-type]
        hunting_rules=hunting_rules,
    )
    return FetchIndicatorsCommand(client, run_settings).run(last_run)


def _get(client: Client, args: dict, params: dict | None = None, hunting_rules: bool = False) -> list:
    """The War Room entries of gibti-get-indicators under the instance settings ``params``."""
    settings = Settings.from_params({**(params or {}), "hunting_rules": hunting_rules})
    return GetIndicatorsCommand(client, settings.for_command()).run(args)


def _mock_update_feed(mocker, client: Client, **patch):
    """The client's update feed answered by ``patch`` (return_value or side_effect), read from the date when the
    collection has no cursor: start_cursor answers None, so sequence_list is not asked."""
    mocker.patch.object(client, "start_cursor", return_value=None)
    return mocker.patch.object(client, "update_feed", **patch)


def _failing_grant_list(mocker, client: Client):
    """Fails the test when the client sends any request, the grant list included."""
    return mocker.patch.object(client.poller, "send_request", side_effect=AssertionError("the client sent a request"))


@pytest.fixture(scope="function", params=COLLECTION_NAMES)
def session_fixture(request):
    """Each name of COLLECTION_NAMES with a new Client of the test URL and credentials."""
    return request.param, Client(
        base_url="https://example.com",
        auth=("example@example.com", "exampleAPI_TOKEN"),
        verify=True,
    )


def test_main_without_parameters_or_command_fails_through_return_error():
    with pytest.raises(SystemExit):
        main()


@pytest.mark.parametrize("collection", ["compromised/bank_card_group", "compromised/masked_card"])
def test_the_card_collections_are_not_feed_collections(collection):
    """Their cnc block is the shop that offers the card, not attacker infrastructure: the records carry no indicator."""
    assert collection not in COLLECTIONS
    with pytest.raises(DemistoException, match=f"The feed does not build indicators from {collection}"):
        _fetch(client=_feed_client(), last_run={}, indicator_collections=[collection])


# The observable types each sample page of test_data yields. Three samples yield none: the
# compromised/account_group events carry no C&C (the usual case), the hi/threat reports list no
# indicators and the osi/vulnerability records are advisories, not CVEs.
SAMPLE_OBSERVABLE_TYPES = {
    "compromised/account_group": set(),
    "attacks/ddos": {"URL", "Domain"},
    "attacks/deface": {"URL"},
    "attacks/phishing_kit": {"File"},
    "attacks/phishing_group": {"URL"},
    "apt/threat": {"IP", "Domain"},
    "hi/threat": set(),
    "suspicious_ip/tor_node": {"IP"},
    "suspicious_ip/open_proxy": {"IP"},
    "suspicious_ip/socks_proxy": {"IP"},
    "suspicious_ip/vpn": {"IP"},
    "suspicious_ip/scanner": {"IP"},
    "malware/cnc": {"IP", "Domain"},
    "osi/vulnerability": set(),
    "osi/git_repository": {"URL"},
    "ioc/common": {"File"},
    "ioc/primary": {"URL", "Domain", "IP", "File"},
    "compromised/spd": {"Cryptocurrency Address", "GIB Suspicious Payment Detail"},
    "hi/open_threats": {"IP", "Domain", "File", "CVE", "Cryptocurrency Address"},
}


def test_a_first_fetch_of_each_collection_yields_its_sample_observables(mocker, session_fixture):
    """Each sample page gives exactly SAMPLE_OBSERVABLE_TYPES, every observable with its gibid and collection."""
    collection_name, client = session_fixture
    if collection_name == "attacks/deface":
        first_fetch_time = "2024-10-01"
    else:
        first_fetch_time = "15 days"

    _mock_update_feed(
        mocker,
        client,
        return_value=[Parser(chunk=COLLECTIONS_RAW_JSON[collection_name], keys=[], iocs_keys=[])],
    )

    next_run, indicators = _fetch(
        client=client,
        last_run={},
        first_fetch_time=first_fetch_time,
        indicator_collections=[collection_name],
        requests_count=3,
    )

    assert "last_fetch" in next_run
    observables = [i for i in indicators if i["type"] not in ("Malware", "Threat Actor")]
    assert {i["type"] for i in observables} == SAMPLE_OBSERVABLE_TYPES[collection_name]
    assert all(i["fields"].get("gibid") and i["fields"]["gibcollection"] == collection_name for i in observables)


def test_the_instance_test_answers_ok_from_one_request_past_the_cache(mocker):
    client = Client(
        base_url="https://example.com",
        auth=("example@example.com", "exampleAPI_TOKEN"),
        verify=True,
    )
    cached = {"granted_collections_cache": {"fetched_at": time.time(), "items": [{"collection": "stale/cache"}]}}
    mocker.patch.object(GroupIB_TIA_Feed, "get_integration_context", return_value=cached)
    send = mocker.patch.object(
        client.poller, "send_request", return_value=[{"collection": "ioc/common"}, {"collection": "apt/threat"}]
    )
    written = mocker.patch.object(GroupIB_TIA_Feed, "set_integration_context")

    result = GroupIB_TIA_Feed.TestModuleCommand(client).run()

    assert result == "ok"
    # The instance test never answers from the cache: the credentials or the URL may have just changed.
    send.assert_called_once_with(endpoint="user/granted_collections", params={})
    written.assert_called_once()
    assert written.call_args.args[0]["granted_collections_cache"]["items"] == [
        {"collection": "ioc/common"},
        {"collection": "apt/threat"},
    ]


def test_the_instance_test_says_when_no_collection_is_available(mocker):
    client = Client(
        base_url="https://example.com",
        auth=("example@example.com", "exampleAPI_TOKEN"),
        verify=True,
    )
    mocker.patch.object(client.poller, "send_request", return_value=[])
    mocker.patch.object(GroupIB_TIA_Feed, "set_integration_context")

    result = GroupIB_TIA_Feed.TestModuleCommand(client).run()

    assert result == "No collections are available; ask Group-IB support to grant them."


def test_a_first_fetch_starts_from_the_first_fetch_date(mocker):
    last_run: dict[str, Any] = {}
    collection_name = "attacks/ddos"
    first_fetch_time = "2023-01-01"
    client = _feed_client()
    generator = _mock_update_feed(mocker, client, return_value=[])

    _fetch(client=client, last_run=last_run, first_fetch_time=first_fetch_time, indicator_collections=[collection_name])

    assert generator.call_args.kwargs["date_from"] == "2023-01-01"
    assert generator.call_args.kwargs["seq_update"] is None


def test_a_later_fetch_starts_from_the_stored_cursor(mocker):
    last_run = {"last_fetch": {"compromised/account_group": 12345}}
    collection_name = "compromised/account_group"
    first_fetch_time = "15 days"
    client = _feed_client()
    generator = _mock_update_feed(mocker, client, return_value=[])

    _fetch(client=client, last_run=last_run, first_fetch_time=first_fetch_time, indicator_collections=[collection_name])

    assert generator.call_args.kwargs["date_from"] is None
    assert generator.call_args.kwargs["seq_update"] == 12345


def test_an_invalid_first_fetch_is_refused():
    last_run: dict[str, Any] = {}
    collection_name = "compromised/account_group"
    first_fetch_time = "invalid-date-format"

    with pytest.raises(DemistoException, match="Invalid 'Indicator first fetch' value"):
        _fetch(
            client=_feed_client(), last_run=last_run, first_fetch_time=first_fetch_time, indicator_collections=[collection_name]
        )


def test_an_unknown_id_or_a_null_answer_is_a_readable_not_found_error(mocker):
    """A 404 from the API (ciaops NotFoundException) or a null answer becomes a readable error; an HTTP 500 and a retry
    failure whose URL holds "404" are raised as they are."""
    from unittest.mock import MagicMock

    client = MagicMock()
    client.record.side_effect = NotFoundException("HTTP 404: Not found. There is no such data on server.")
    with pytest.raises(DemistoException, match="No record with id 'deadbeef' was found in malware/cnc"):
        _get(client, {"collection": "malware/cnc", "id": "deadbeef", "limit": "5"})
    client.record.side_effect = None
    client.record.return_value = None
    with pytest.raises(DemistoException, match="No record with id 'deadbeef' was found in malware/cnc"):
        _get(client, {"collection": "malware/cnc", "id": "deadbeef", "limit": "5"})
    client.record.side_effect = ConnectionException(SERVER_ERROR)
    with pytest.raises(ConnectionException, match="HTTP 500"):
        _get(client, {"collection": "malware/cnc", "id": "deadbeef", "limit": "5"})
    # ciaops puts the URL, and so the id, in its retry messages: an id holding "404" is no 404
    retries = ConnectionException("Request to .../malware/cnc/a404b failed: Max retries exceeded")
    client.record.side_effect = retries
    with pytest.raises(ConnectionException, match="Max retries exceeded"):
        _get(client, {"collection": "malware/cnc", "id": "a404b", "limit": "5"})


def test_get_indicators_by_id_of_a_page_without_records_is_not_found():
    from unittest.mock import MagicMock

    client = MagicMock()
    client.record.return_value.parse_portion.return_value = []
    with pytest.raises(DemistoException, match="No record with id 'deadbeef' was found in malware/cnc"):
        _get(client, {"collection": "malware/cnc", "id": "deadbeef", "limit": "5"})


@pytest.mark.parametrize("collection", ["hi/threat", "apt/threat"])
def test_get_indicators_by_id_checks_a_refused_report_in_the_update_feed(collection):
    """Group-IB answers 403 for a report it has not published, and its update feed does not list it. A report's 403 is
    checked in that feed: a listed report gives its indicators, an unlisted one is not found, and a refusal there keeps
    the 403. A 403 in another collection is not checked there."""
    from unittest.mock import MagicMock

    refusal = ConnectionException("HTTP 403: Something is wrong with your account.")
    client = MagicMock()
    client.record.side_effect = refusal
    client.search.return_value = iter([])
    with pytest.raises(DemistoException, match=f"No record with id 'r1' was found in {collection}"):
        _get(client, {"collection": collection, "id": "r1", "limit": "5"})
    client.search.assert_called_once_with(collection, query="id:r1", limit=1)
    # the update feed lists it: its indicators are returned
    portion = MagicMock()
    portion.parse_portion.return_value = [{"id": "r1", "indicators_params_ipv4": [["203.0.113.1"]]}]
    client.search.return_value = iter([portion])
    results = _get(client, {"collection": collection, "id": "r1", "limit": "5"})
    assert "203.0.113.1" in results[0].readable_output

    # the update feed refuses too: the key cannot read the collection, the refusal stays
    def refused(*_args, **_kwargs):
        raise refusal
        yield  # pragma: no cover - makes this a generator like the one ciaops returns

    client.search.return_value = refused()
    with pytest.raises(ConnectionException, match="HTTP 403"):
        _get(client, {"collection": collection, "id": "r1", "limit": "5"})
    # a refusal in another collection is not retried
    client.search.reset_mock()
    with pytest.raises(ConnectionException, match="HTTP 403"):
        _get(client, {"collection": "malware/cnc", "id": "r1", "limit": "5"})
    client.search.assert_not_called()


def test_get_indicators_reads_the_feed_with_a_valid_limit_and_collection(mocker):
    limit = 25
    collection_name = "compromised/account_group"
    client = _feed_client()
    generator = _mock_update_feed(mocker, client, return_value=[])
    record = mocker.patch.object(client, "record")

    _get(client, {"limit": limit, "collection": collection_name})

    assert (generator.call_args.kwargs["collection_name"], generator.call_args.kwargs["limit"]) == (collection_name, 25)
    record.assert_not_called()


def test_get_indicators_refuses_a_limit_that_is_no_number():
    limit = "not-a-number"
    collection_name = "compromised/account_group"

    with pytest.raises(DemistoException, match="Limit should be a number"):
        _get(_feed_client(), {"limit": limit, "collection": collection_name})


def test_get_indicators_refuses_a_limit_below_one():
    limit = 0
    collection_name = "compromised/account_group"

    with pytest.raises(DemistoException, match="Limit should be greater than 0"):
        _get(_feed_client(), {"limit": limit, "collection": collection_name})


def test_get_indicators_refuses_a_limit_above_fifty():
    limit = 51
    collection_name = "compromised/account_group"

    with pytest.raises(DemistoException, match="Limit should be at most 50"):
        _get(_feed_client(), {"limit": limit, "collection": collection_name})


def test_get_indicators_refuses_an_unknown_collection():
    limit = 25
    collection_name = "invalid/collection"

    with pytest.raises(DemistoException, match="Unknown collection name"):
        _get(_feed_client(), {"limit": limit, "collection": collection_name})


def test_a_fetch_without_hunting_rules_never_reads_the_grant_list(mocker):
    collections = ["compromised/account_group", "attacks/ddos"]
    client = _feed_client()
    send = _failing_grant_list(mocker, client)
    _mock_update_feed(mocker, client, return_value=[])

    next_run, _ = _fetch(client=client, last_run={}, indicator_collections=collections)

    assert list(next_run["last_fetch"]) == collections
    send.assert_not_called()


def test_a_collection_the_feed_does_not_know_is_refused():
    with pytest.raises(DemistoException, match="unavailable/collection"):
        _fetch(client=_feed_client(), last_run={}, indicator_collections=["unavailable/collection"])


def test_a_fetch_of_no_collection_sends_no_request(mocker):
    client = _feed_client()
    send = _failing_grant_list(mocker, client)

    next_run, indicators = _fetch(client=client, last_run={}, indicator_collections=[])

    assert (next_run["last_fetch"], indicators) == ({}, [])
    send.assert_not_called()


def test_the_first_value_of_a_nested_list_is_its_first_non_empty_one():
    assert IndicatorBuilder._first_value([None, "", "valid"]) == "valid"
    assert IndicatorBuilder._first_value([[None, "nested"], "value"]) == "nested"
    assert IndicatorBuilder._first_value([None, "", []]) is None
    assert IndicatorBuilder._first_value("simple") == "simple"


def test_each_indicator_of_a_record_has_a_value_a_type_a_raw_json_and_fields():
    collection_name = "ioc/common"
    feed = {
        "id": "test-id-123",
        "url": "https://example.com/malicious",
        "domain": "malicious.example.com",
        "ip": "192.0.2.1",
        "dateFirstSeen": "2023-01-01T00:00:00Z",
        "dateLastSeen": "2023-01-02T00:00:00Z",
    }

    builder = IndicatorBuilder(collection_name, Settings(tlp_color="RED"))

    indicators = builder.build([feed])

    assert len(indicators) > 0
    assert all("value" in ind for ind in indicators)
    assert all("type" in ind for ind in indicators)
    assert all("rawJSON" in ind for ind in indicators)
    assert all("fields" in ind for ind in indicators)


def test_a_fetch_from_a_stored_cursor_stores_the_cursor_of_the_page(mocker, session_fixture):
    collection_name, client = session_fixture
    last_run = {"last_fetch": {collection_name: 12345}}
    first_fetch_time = "15 days"

    mock_parser = Parser(chunk=COLLECTIONS_RAW_JSON[collection_name], keys=[], iocs_keys=[])
    mock_parser.sequpdate = 67890
    _mock_update_feed(
        mocker,
        client,
        return_value=[mock_parser],
    )

    next_run, indicators = _fetch(
        client=client,
        last_run=last_run,
        first_fetch_time=first_fetch_time,
        indicator_collections=[collection_name],
        requests_count=1,
    )

    assert "last_fetch" in next_run
    assert collection_name in next_run["last_fetch"]
    assert next_run["last_fetch"][collection_name] == 67890


def _cnc_parser(seq: int) -> Parser:
    parser = Parser(chunk=COLLECTIONS_RAW_JSON["malware/cnc"], keys=[], iocs_keys=[])
    parser.sequpdate = seq
    return parser


def test_a_refused_collection_does_not_stop_the_feed(mocker):
    """A collection whose first read fails keeps its cursor, one that fails later stores the cursor of the pages read
    before; both are reported in the instance health, and the other collections are fetched. A run whose only collection
    fails raises that failure."""
    client = _feed_client()
    collections = ["osi/git_repository", "malware/cnc", "hi/threat"]

    def pages_then_refusal():
        yield _cnc_parser(300)
        raise ConnectionException(SERVER_ERROR)

    def generators(**kwargs):
        if kwargs["collection_name"] == "osi/git_repository":
            raise ConnectionException("Request to https://example.com failed: connection reset")
        if kwargs["collection_name"] == "hi/threat":
            return pages_then_refusal()
        return [_cnc_parser(200)]

    _mock_update_feed(mocker, client, side_effect=generators)
    health = mocker.patch.object(GroupIB_TIA_Feed.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "error")
    last_run = {"last_fetch": {"osi/git_repository": 100, "malware/cnc": 150, "hi/threat": 250}}
    next_run, indicators = _fetch(
        client=client,
        last_run=last_run,
        first_fetch_time="3 days",
        indicator_collections=collections,
        requests_count=3,
    )
    assert indicators
    assert next_run["last_fetch"] == {"osi/git_repository": 100, "malware/cnc": 200, "hi/threat": 300}
    [call] = health.call_args_list
    assert "osi/git_repository" in call.args[0]
    assert "hi/threat" in call.args[0]
    assert call.kwargs == {"is_error": True}
    # nothing fetched at all: the run fails
    _mock_update_feed(mocker, client, side_effect=ConnectionException("HTTP 403: Something is wrong with your account."))
    with pytest.raises(DemistoException, match="The fetch of malware/cnc failed: HTTP 403"):
        _fetch(
            client=client,
            last_run=last_run,
            first_fetch_time="3 days",
            indicator_collections=["malware/cnc"],
            requests_count=3,
        )


def test_a_fetch_of_several_collections_stores_a_cursor_for_each(mocker):
    client = Client(
        base_url="https://example.com",
        auth=("example@example.com", "exampleAPI_TOKEN"),
        verify=True,
    )

    collections = ["compromised/account_group", "attacks/ddos"]

    def create_mock_parser(collection_name):
        """The sample page of ``collection_name`` as one parsed portion at cursor 10000."""
        mock_parser = Parser(chunk=COLLECTIONS_RAW_JSON[collection_name], keys=[], iocs_keys=[])
        mock_parser.sequpdate = 10000
        return mock_parser

    def side_effect_func(**kwargs):
        """The update feed of ``collection_name``: its sample page."""
        collection_name = kwargs.get("collection_name")
        return [create_mock_parser(collection_name)]

    _mock_update_feed(
        mocker,
        client,
        side_effect=side_effect_func,
    )

    next_run, indicators = _fetch(
        client=client,
        last_run={},
        first_fetch_time="15 days",
        indicator_collections=collections,
        requests_count=1,
    )

    assert "last_fetch" in next_run
    assert len(next_run["last_fetch"]) == len(collections)


def test_get_indicators_without_an_id_reads_the_feed_and_answers_a_readable_table(mocker, session_fixture):
    collection_name, client = session_fixture
    args = {"collection": collection_name, "limit": 10}

    _mock_update_feed(
        mocker,
        client,
        return_value=[Parser(chunk=COLLECTIONS_RAW_JSON[collection_name], keys=[], iocs_keys=[])],
    )

    results = _get(client, args)

    assert isinstance(results, list)
    # Some sample pages hold no indicators: the structure is checked where results exist
    if len(results) > 0:
        assert all(hasattr(r, "readable_output") for r in results)


def test_the_client_hands_verify_to_the_ciaops_session_and_keeps_its_rate_limit():
    client = _feed_client(verify=False, rate_limit_delay=3.0)
    # The poller runs its own requests.Session; "Trust any certificate (not secure)" reaches it too.
    assert client.poller._session.verify is False
    assert client.rate_limit_delay == 3.0
    assert _feed_client().rate_limit_delay == Settings.DEFAULT_RATE_LIMIT_DELAY


def test_an_update_feed_read_passes_its_date_hunting_flag_limit_and_pacing_to_the_generator(mocker):
    client = _feed_client(rate_limit_delay=3.0)
    mocker.patch.object(client.poller, "get_seq_update_dict", return_value={})
    mocker.patch.object(client.poller, "create_update_generator", return_value=[])

    # attacks/phishing_kit takes the date as a filter: without a sequence_list cursor it is read from the date
    seq_update = client.start_cursor("attacks/phishing_kit", "2024-01-01", 1)
    assert seq_update is None
    client.update_feed(
        collection_name="attacks/phishing_kit", seq_update=seq_update, date_from="2024-01-01", apply_hunting_rules=True, limit=100
    )

    call_kwargs = client.poller.create_update_generator.call_args[1]
    request_params = call_kwargs["request_params"]
    assert isinstance(request_params, TIRequestParams)
    assert request_params.date_from == "2024-01-01"
    # TIRequestParams accepts only 0/1 for its binary filters.
    assert request_params.apply_hunting_rules == 1
    assert request_params.limit == 100
    assert call_kwargs["sequpdate"] is None
    assert call_kwargs["rate_limit_delay"] == 3.0


def test_an_update_feed_read_from_a_cursor_alone_sends_no_date_and_no_hunting_flag(mocker):
    client = _feed_client()
    mocker.patch.object(client.poller, "create_update_generator", return_value=[])

    client.update_feed(collection_name="attacks/deface", seq_update=555, apply_hunting_rules=None, limit=10)

    call_kwargs = client.poller.create_update_generator.call_args[1]
    assert call_kwargs["request_params"].apply_hunting_rules is None
    assert call_kwargs["request_params"].date_from is None
    assert call_kwargs["sequpdate"] == 555


def test_get_indicators_by_id_reads_the_record_by_its_id_without_ioc_keys_on_the_parser(mocker):
    """The by-id path asks search_feed_by_id for the record and answers with a list when the parser has no IOC keys."""
    client = _feed_client()
    parser = Parser(chunk=COLLECTIONS_RAW_JSON["malware/cnc"], keys=[], iocs_keys=[])
    mocker.patch.object(client.poller, "search_feed_by_id", return_value=parser)

    results = _get(client, {"id": "some-id", "collection": "malware/cnc", "limit": "10"})

    client.poller.search_feed_by_id.assert_called_once_with(collection_name="malware/cnc", feed_id="some-id")
    assert isinstance(results, list)


def test_git_repository_is_read_without_the_hunting_flag():
    """The hunting parameters are no-ops on osi/git_repository, which the server filters by the hunting
    rules anyway: they are not sent."""
    record = {"id": "a" * 40, "name": "example/config", "seqUpdate": 1_760_000_000_000_001, "files": []}
    feed = _UpdateFeed({"osi/git_repository": [record]}, start_cursors={"osi/git_repository": 1_760_000_000_000_000})
    for hunting_rules in (False, True):
        _fetch(
            client=feed.client(granted={"osi/git_repository"}),
            last_run={},
            first_fetch_time="3 days",
            indicator_collections=["osi/git_repository"],
            requests_count=1,
            hunting_rules=hunting_rules,
        )
    assert len(feed.sent_to("osi/git_repository/updated")) == 2
    assert [params.get("apply_hunting_rules") for _, params in feed.requests] == [None] * len(feed.requests)


@pytest.mark.parametrize(
    "params, expected",
    [
        ({}, Settings.DEFAULT_RATE_LIMIT_DELAY),
        ({"rate_limit_delay": ""}, Settings.DEFAULT_RATE_LIMIT_DELAY),
        ({"rate_limit_delay": "0"}, 0.0),
        ({"rate_limit_delay": "2.5"}, 2.5),
    ],
)
def test_the_rate_limit_delay_setting_reads_a_number_and_defaults_when_blank(params, expected):
    assert Settings.from_params(params).rate_limit_delay == expected


@pytest.mark.parametrize("value", ["abc", "-1"])
def test_a_rate_limit_delay_that_is_no_number_or_negative_is_refused(value):
    with pytest.raises(DemistoException):
        Settings.from_params({"rate_limit_delay": value})


def test_ioc_primary_network_record_yields_one_indicator_per_element_with_its_own_score():
    parsed = {
        "id": "r1",
        "record_type": "network",
        "url": ["http://a.test/", "http://b.test/"],
        "url_risk_score": [100, 40],
        "domain": ["a.test"],
        "domain_risk_score": [90],
        "ip": [],
        "ip_risk_score": [],
        "hash_md5": None,
        "hash_sha1": None,
        "hash_sha256": None,
        "file_risk_score": None,
        "date_first_seen": "2026-01-01",
        "date_last_seen": None,
        "malware_names": ["AgentOne"],
        "threat_names": ["ThreatFour"],
        "evaluation_tlp": "TLP:AMBER",
    }
    indicators = _build("ioc/primary", parsed, Settings(tlp_color="GREEN", tags=("feed",), use_tlp_from_source=True))
    by_value = {i["value"]: i for i in indicators}
    assert set(by_value) == {"http://a.test/", "http://b.test/", "a.test"}
    assert by_value["http://a.test/"]["fields"]["gibriskscore"] == 100
    assert by_value["http://a.test/"]["score"] == 3
    assert by_value["http://b.test/"]["fields"]["gibriskscore"] == 40
    # a risk score above 0, however low, is bad; 0 or none leaves it suspicious
    assert by_value["http://b.test/"]["score"] == 3
    assert by_value["a.test"]["type"] == "Domain"
    assert by_value["a.test"]["score"] == 3
    assert "AgentOne" in str(by_value["a.test"]["fields"]["gibmalwarename"])
    assert "ThreatFour" in str(by_value["a.test"]["fields"]["gibthreatname"])
    assert by_value["a.test"]["fields"]["trafficlightprotocol"] == "AMBER"
    assert "feed" in by_value["a.test"]["fields"]["tags"]


def test_ioc_primary_file_record_uses_sha256_and_keeps_every_hash():
    parsed = {
        "id": "r2",
        "record_type": "file",
        "url": [],
        "domain": [],
        "ip": [],
        "hash_md5": "a" * 32,
        "hash_sha1": "b" * 40,
        "hash_sha256": "c" * 64,
        "file_risk_score": 100,
    }
    indicators = _build("ioc/primary", parsed)
    assert [i["type"] for i in indicators] == ["File"]
    assert indicators[0]["value"] == "c" * 64
    assert indicators[0]["fields"]["md5"] == "a" * 32
    assert indicators[0]["fields"]["sha1"] == "b" * 40
    assert indicators[0]["score"] == 3
    only_md5 = dict(parsed, hash_sha1=None, hash_sha256=None)
    assert _build("ioc/primary", only_md5)[0]["value"] == "a" * 32


def test_ioc_primary_falls_back_to_amber_without_a_source_tlp():
    parsed = {"id": "r3", "record_type": "network", "url": [], "domain": ["x.test"], "domain_risk_score": [10], "ip": []}
    indicators = _build("ioc/primary", parsed, Settings(tlp_color="GREEN", use_tlp_from_source=True))
    assert indicators[0]["fields"]["trafficlightprotocol"] == "AMBER"


def test_spd_indicator_type_is_resolved_per_record():
    wallet = {
        "id": "w",
        "value": "bc1qexample",
        "spd_type": "Cryptocurrency Wallet",
        "service_type": "BTCLike",
        "illegal_score": 100,
        "spd_tags": ["Fraud Shop"],
        "country": [],
        "evaluation_tlp": "amber",
    }
    mobile = {
        "id": "m",
        "value": "+12025550100",
        "spd_type": "Mobile Number",
        "service_type": "ExampleWallet",
        "illegal_score": 60,
        "spd_tags": ["Casino"],
        "country": ["US"],
        "evaluation_tlp": "amber",
    }
    wallet_ind = _build("compromised/spd", wallet, Settings(tags=("feed",)))[0]
    mobile_ind = _build("compromised/spd", mobile)[0]
    assert wallet_ind["type"] == "Cryptocurrency Address"
    assert wallet_ind["score"] == 3
    assert wallet_ind["fields"]["gibspdtype"] == "Cryptocurrency Wallet"
    assert wallet_ind["fields"]["gibspdservicetype"] == "BTCLike"
    assert wallet_ind["fields"]["tags"] == ["feed", "compromised/spd", "Fraud Shop"]
    assert mobile_ind["type"] == "GIB Suspicious Payment Detail"
    assert mobile_ind["score"] == 2
    assert mobile_ind["fields"]["tags"] == ["compromised/spd", "Casino"]


def test_a_per_record_type_takes_the_first_value_of_a_list_and_needs_a_match_or_a_default(mocker):
    wallet = {"id": "w", "value": "bc1qexample", "spd_type": [None, "", "Cryptocurrency Wallet"], "illegal_score": 100}
    assert [i["type"] for i in _build("compromised/spd", wallet)] == ["Cryptocurrency Address"]
    spec = CollectionSpec(
        types={"value": {"field": "kind", "map": {"Wallet": "Cryptocurrency Address"}}}, indicator_fields={}, parser_mapping={}
    )
    mocker.patch.dict(COLLECTIONS, {"test/collection": spec})
    assert _build("test/collection", {"id": "x", "value": "bc1qexample", "kind": "Card"}) == []
    assert _build("test/collection", {"id": "x", "value": "bc1qexample", "kind": "Wallet"})[0]["type"] == "Cryptocurrency Address"
    assert IndicatorBuilder._resolve_type(42, {}) is None


@pytest.mark.parametrize("score", [150, -5, "n/a"])
def test_a_payment_detail_score_that_is_not_a_number_from_0_to_100_leaves_the_collection_verdict(score):
    mobile = {"id": "m", "value": "+12025550100", "spd_type": "Mobile Number", "illegal_score": score}
    [indicator] = _build("compromised/spd", mobile)
    assert indicator["score"] == COLLECTIONS["compromised/spd"].verdict == 2


def test_account_group_feed_never_emits_the_victim_ip():
    parsed = {
        "id": "acc",
        "event_url": ["http://cnc.test/gate"],
        "event_domain": ["cnc.test"],
        "service_url": "https://mail.example/",
        "malware_names": ["BankerOne"],
        "threat_actor_names": [],
        "evaluation_severity": "red",
    }
    indicators = _build("compromised/account_group", parsed)
    assert {i["type"] for i in indicators} == {"URL", "Domain"}
    # events.client.* is the infected device, the victim: the mapping reads its country code for the victim_countries
    # filter and nothing else, and no indicator field carries it.
    account_spec = COLLECTIONS["compromised/account_group"]
    client_paths = {path for path in account_spec.parser_mapping.values() if path.startswith("events.client")}
    assert client_paths == {"events.client.ipv4.countryCode"}
    assert all("event_country_code" not in fields for fields in account_spec.indicator_fields.values())
    cnc = next(i for i in indicators if i["value"] == "http://cnc.test/gate")
    assert "BankerOne" in str(cnc["fields"]["gibmalwarename"])
    assert cnc["fields"]["gibseverity"] == "red"


def test_threat_report_with_several_ips_yields_one_indicator_each():
    parsed = {
        "id": "t",
        "indicators_params_ipv4": ["203.0.113.1", "203.0.113.2"],
        "indicators_params_domain": [],
        "indicators_params_url": [],
        "indicators_params_hashes_md5": [],
        "threat_actor_name": "CrewThree",
        "evaluation_severity": "orange",
    }
    indicators = _build("hi/threat", parsed)
    assert sorted(i["value"] for i in indicators) == ["203.0.113.1", "203.0.113.2"]
    assert all(i["fields"]["gibthreatactorname"] == "CrewThree" for i in indicators)


def test_feed_tags_survive_across_portions():
    common = Settings(tlp_color="GREEN", tags=("feed",))
    parsed = {"id": "x", "ipv4_ip": "192.0.2.6", "source": "check.example.com", "evaluation_tlp": "green"}
    first = _build("suspicious_ip/tor_node", parsed, common)
    second = _build("suspicious_ip/tor_node", parsed, common)
    assert first[0]["fields"]["tags"] == ["feed", "suspicious_ip/tor_node"]
    assert second[0]["fields"]["tags"] == ["feed", "suspicious_ip/tor_node"]
    assert first[0]["fields"]["gibsource"] == "check.example.com"


def test_tor_indicator_takes_the_source_tlp():
    parsed = {"id": "x", "ipv4_ip": "192.0.2.6", "source": "check.example.com", "evaluation_tlp": "green"}
    ind = _build("suspicious_ip/tor_node", parsed, Settings(tlp_color="RED", use_tlp_from_source=True))[0]
    assert ind["fields"]["trafficlightprotocol"] == "GREEN"


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("TLP:AMBER", "AMBER"),
        ("tlp:red", "RED"),
        ("green", "GREEN"),
        ("amber+strict", "AMBER"),
        ("TLP:AMBER+STRICT", "AMBER"),
        ("clear", "WHITE"),
        ("TLP:CLEAR", "WHITE"),
        (None, None),
        ("", None),
        ("TLP: ", None),
    ],
)
def test_a_tlp_marking_is_read_in_any_spelling_and_a_blank_one_is_none(raw, expected):
    [indicator] = _build("suspicious_ip/tor_node", {"id": "x", "ipv4_ip": "192.0.2.6", "evaluation_tlp": raw})
    assert indicator["fields"]["trafficlightprotocol"] == expected


def test_an_unknown_tlp_fails_safe_to_red_and_is_logged(mocker):
    """The TLP set is open: an unseen value is the most restrictive color."""
    info = mocker.patch.object(GroupIB_TIA_Feed.demisto, "info")
    [indicator] = _build("suspicious_ip/tor_node", {"id": "x", "ipv4_ip": "192.0.2.6", "evaluation_tlp": "purple"})
    assert indicator["fields"]["trafficlightprotocol"] == "RED"
    assert "purple" in info.call_args.args[0]


def _restarted(last_run: dict, first_fetch: str, hunting_rules: bool = False) -> dict:
    """The state a fetch under these settings starts from."""
    settings = Settings(first_fetch=first_fetch, hunting_rules=hunting_rules)
    return FetchIndicatorsCommand(_feed_client(), settings)._restarted_if_changed(last_run)


def test_first_fetch_change_drops_feed_cursors():
    state = {
        "first_fetch_time": "3 days",
        "last_fetch": {"ioc/common": 5},
        "granted_collections_cache": {"fetched_at": 1, "items": []},
    }
    assert _restarted(state, "3 days") is state
    reset = _restarted(state, "30 days")
    assert reset["last_fetch"] == {}
    assert reset["granted_collections_cache"] == state["granted_collections_cache"]
    legacy = {"last_fetch": {"ioc/common": 5}}
    assert _restarted(legacy, "30 days") is legacy


def test_fetch_indicators_restarts_from_the_date_after_a_first_fetch_change(mocker):
    client = Client(
        base_url="https://example.com",
        auth=("example@example.com", "token"),
        verify=True,
    )
    generator = _mock_update_feed(mocker, client, return_value=[])
    next_run, _ = _fetch(
        client=client,
        last_run={"first_fetch_time": "3 days", "last_fetch": {"ioc/common": 777}},
        first_fetch_time="10 days",
        indicator_collections=["ioc/common"],
        requests_count=1,
    )
    assert generator.call_args.kwargs["seq_update"] is None
    assert generator.call_args.kwargs["date_from"]
    assert next_run["first_fetch_time"] == "10 days"
    next_run, _ = _fetch(
        client=client,
        last_run={"first_fetch_time": "10 days", "last_fetch": {"ioc/common": 777}},
        first_fetch_time="10 days",
        indicator_collections=["ioc/common"],
        requests_count=1,
    )
    assert generator.call_args.kwargs["seq_update"] == 777


def test_a_failed_grant_read_is_not_sent_again_within_one_command(mocker):
    client = Client(
        base_url="https://example.com",
        auth=("example@example.com", "token"),
        verify=True,
    )
    mocker.patch.object(GroupIB_TIA_Feed, "get_integration_context", return_value={})
    send = mocker.patch.object(client.poller, "send_request", side_effect=GroupIB_TIA_Feed.ConnectionException("HTTP 503"))
    for _ in range(3):
        with pytest.raises(GroupIB_TIA_Feed.ConnectionException, match="HTTP 503"):
            client.hunting_rules_collections()
    assert send.call_count == 1


def test_the_grant_list_is_read_once_and_cached_in_the_context_for_five_minutes(mocker):
    client = Client(
        base_url="https://example.com",
        auth=("example@example.com", "token"),
        verify=True,
    )
    context = {}
    mocker.patch.object(GroupIB_TIA_Feed, "get_integration_context", side_effect=lambda: dict(context))
    mocker.patch.object(GroupIB_TIA_Feed, "set_integration_context", side_effect=lambda value: context.update(value))
    send = mocker.patch.object(
        client.poller,
        "send_request",
        return_value=[
            {"collection": "ioc/common", "huntingRulesUsed": True},
            {"collection": "not/a-collection", "huntingRulesUsed": True},
        ],
    )
    assert client.hunting_rules_collections() == frozenset({"ioc/common"})
    assert send.call_count == 1
    assert context["granted_collections_cache"]["items"][0]["collection"] == "ioc/common"
    fresh = Client(
        base_url="https://example.com",
        auth=("example@example.com", "token"),
        verify=True,
    )
    send_fresh = mocker.patch.object(fresh.poller, "send_request")
    assert fresh.hunting_rules_collections() == frozenset({"ioc/common"})
    send_fresh.assert_not_called()
    context["granted_collections_cache"]["fetched_at"] = time.time() - 301
    stale = Client(
        base_url="https://example.com",
        auth=("example@example.com", "token"),
        verify=True,
    )
    send_stale = mocker.patch.object(stale.poller, "send_request", return_value=[])
    assert stale.hunting_rules_collections() == frozenset()
    assert send_stale.call_count == 1


def test_the_grant_list_is_read_once_per_command_and_a_malformed_cache_is_ignored(mocker):
    """A command asks for the grants once, whatever reads them; a cache entry without a time or a list is no cache."""
    malformed = {"granted_collections_cache": {"fetched_at": "yesterday", "items": [{"collection": "hi/threat"}]}}
    context = mocker.patch.object(GroupIB_TIA_Feed, "get_integration_context", return_value=malformed)
    mocker.patch.object(GroupIB_TIA_Feed, "set_integration_context")
    client = _feed_client()
    send = mocker.patch.object(
        client.poller, "send_request", return_value=[{"collection": "ioc/common", "huntingRulesUsed": True}]
    )
    assert client.hunting_rules_collections() == frozenset({"ioc/common"})
    reads = context.call_count
    assert client.hunting_rules_collections() == frozenset({"ioc/common"})
    send.assert_called_once()
    assert context.call_count == reads


@pytest.mark.parametrize(
    "collection, enabled, granted, expected",
    [
        ("osi/git_repository", True, {"osi/git_repository"}, None),  # filtered by the API, the flag a no-op
        ("hi/threat", False, {"hi/threat"}, None),  # setting off
        ("hi/threat", True, {"hi/threat"}, 1),  # supported + granted
        ("hi/threat", True, set(), None),  # supported, no grant
        ("ioc/primary", True, {"ioc/primary"}, None),  # API has no filter for it
        ("compromised/account_group", True, {"compromised/account_group"}, None),
        ("suspicious_ip/tor_node", True, {"suspicious_ip/tor_node"}, 1),
    ],
)
def test_the_hunting_rules_flag_follows_the_setting_the_grant_and_the_collection(mocker, collection, enabled, granted, expected):
    client = _feed_client()
    mocker.patch.object(client, "hunting_rules_collections", return_value=frozenset(granted))
    assert client.hunting_rules_flag(collection, enabled) == expected


def test_the_hunting_flag_of_each_collection_reaches_its_update_feed(mocker):
    client = _feed_client()
    mocker.patch.object(client, "hunting_rules_collections", return_value=frozenset({"hi/threat"}))
    generator = _mock_update_feed(mocker, client, return_value=[])
    next_run, _ = _fetch(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        indicator_collections=["hi/threat", "ioc/primary"],
        requests_count=1,
        hunting_rules=True,
    )
    flags = {c.kwargs["collection_name"]: c.kwargs["apply_hunting_rules"] for c in generator.call_args_list}
    assert flags == {"hi/threat": 1, "ioc/primary": None}
    assert next_run["hunting_rules"] is True


def test_toggling_hunting_rules_restarts_from_the_first_fetch_date(mocker):
    state = {"first_fetch_time": "3 days", "hunting_rules": False, "last_fetch": {"hi/threat": 5}}
    assert _restarted(state, "3 days", False) is state
    assert _restarted(state, "3 days", True)["last_fetch"] == {}
    # an upgraded instance has no hunting fingerprint yet and keeps its cursors
    legacy = {"first_fetch_time": "3 days", "last_fetch": {"hi/threat": 5}}
    assert _restarted(legacy, "3 days", True) is legacy


def test_get_indicators_command_honors_the_instance_hunting_setting(mocker):
    client = _feed_client()
    mocker.patch.object(client, "hunting_rules_collections", return_value=frozenset({"apt/threat"}))
    generator = _mock_update_feed(mocker, client, return_value=[])
    _get(client, {"collection": "apt/threat", "limit": "10"}, hunting_rules=True)
    assert generator.call_args.kwargs["apply_hunting_rules"] == 1
    _get(client, {"collection": "apt/threat", "limit": "10"})
    assert generator.call_args.kwargs["apply_hunting_rules"] is None


def test_ioc_common_file_record_yields_a_file_indicator_with_its_md5_sha1_and_sha256_and_drops_a_sha512():
    parsed = {
        "id": "f1",
        "url": None,
        "domain": None,
        "ip": None,
        "hash_list": ["a" * 40, "b" * 64, "c" * 32],
        "malware_names": ["BeaconOne"],
        "threat_names": ["ThreatThree"],
    }
    inds = _build("ioc/common", parsed)
    assert [i["type"] for i in inds] == ["File"]
    assert inds[0]["value"] == "b" * 64
    assert inds[0]["fields"]["md5"] == "c" * 32
    assert inds[0]["fields"]["sha1"] == "a" * 40
    assert "BeaconOne" in str(inds[0]["fields"]["gibmalwarename"])
    assert "ThreatThree" in str(inds[0]["fields"]["gibthreatname"])
    # a SHA-512 has no key of its own in the record: it is dropped, and the file is keyed by its next strongest hash
    [md5_keyed] = _build("ioc/common", {"id": "f2", "hash_list": ["d" * 128, "c" * 32]})
    assert (md5_keyed["type"], md5_keyed["value"], md5_keyed["fields"]["md5"]) == ("File", "c" * 32, "c" * 32)
    assert "d" * 128 not in str(md5_keyed)


def test_deface_and_phishing_group_feeds_emit_only_the_url():
    deface = _build(
        "attacks/deface",
        {"id": "d", "url": "http://victim.test/defaced", "target_domain": "victim.test", "target_ip_ip": "198.51.100.9"},
    )
    assert [(i["type"], i["value"]) for i in deface] == [("URL", "http://victim.test/defaced")]
    phishing = _build(
        "attacks/phishing_group",
        {"id": "p", "url": ["http://phish.test/login"], "phishing_domain_domain": "phish.test", "ipv4_ip": "198.51.100.10"},
    )
    # the domain and the hosting IP are often shared infrastructure: only the phishing URL
    assert [(i["type"], i["value"]) for i in phishing] == [("URL", "http://phish.test/login")]


@pytest.mark.parametrize(
    "name, message",
    [
        ("compromised/breached", "compromised/breacheddb is fetched as incidents"),
        ("attacks/phishing", "attacks/phishing_group"),
        ("compromised/imei", "has no replacement"),
        ("compromised/mule", "compromised/spd"),
    ],
)
def test_obsolete_collection_names_are_refused_naming_any_replacement(mocker, name, message):
    with pytest.raises(DemistoException, match=re.escape(message)):
        CollectionSpec.refuse_retired(name)
    client = _feed_client()
    grants = _failing_grant_list(mocker, client)
    with pytest.raises(DemistoException, match=re.escape(message)):
        _fetch(client=client, last_run={}, indicator_collections=[name])
    grants.assert_not_called()
    with pytest.raises(DemistoException, match=re.escape(message)):
        _get(client, {"limit": "10", "collection": name})
    grants.assert_not_called()


def _indicators(feed: dict) -> list:
    inds = IndicatorBuilder("malware/cnc", Settings(tlp_color="GREEN")).build([feed])
    return [(i["type"], i["value"]) for i in inds]


def test_ip_stored_under_domain_key_becomes_an_ip_indicator():
    assert _indicators({"id": "x", "domain": "203.0.113.45"}) == [("IP", "203.0.113.45")]


def test_a_domain_under_the_domain_key_stays_a_domain():
    assert ("Domain", "second-hand.example.com") in _indicators({"id": "x", "domain": "second-hand.example.com"})


def test_account_group_feed_never_emits_the_victim_service_url():
    parsed = {
        "id": "acc",
        "event_url": ["http://cnc.test/gate"],
        "event_domain": ["cnc.test"],
        "service_url": "https://mail.example/",
        "malware_names": ["BankerOne"],
        "threat_actor_names": ["CrewTwo"],
        "source_names": ["Botnet"],
        "evaluation_severity": "red",
    }
    indicators = _build("compromised/account_group", parsed, Settings(tags=("feed",)))
    assert "https://mail.example/" not in {i["value"] for i in indicators}
    assert "service_url" not in COLLECTIONS["compromised/account_group"].types
    cnc = next(i for i in indicators if i["value"] == "http://cnc.test/gate")
    assert cnc["fields"]["gibsource"] == "Botnet"
    assert cnc["fields"]["tags"] == ["feed", "compromised/account_group", "BankerOne", "CrewTwo"]
    assert cnc["fields"]["malwarefamily"] == ["BankerOne"]
    assert cnc["rawJSON"]["malwarefamily"] == ["BankerOne"]


def test_scanner_ip_gets_provider_sources_categories_and_the_country_code_fallback():
    parsed = {
        "id": "s",
        "ipv4_ip": "198.51.100.5",
        "ipv4_asn": "AS64501",
        "ipv4_country_name": "",
        "ipv4_country_code": "NL",
        "ipv4_provider": "Scan Hosting",
        "source_names": ["honeypot"],
        "categories": ["ssh", "rdp"],
        "date_first_seen": "2026-09-01T00:00:00+00:00",
        "evaluation_severity": "green",
    }
    ind = _build("suspicious_ip/scanner", parsed, Settings(tags=("feed",)))[0]
    assert ind["fields"]["geocountry"] == "NL"
    assert ind["fields"]["organization"] == "Scan Hosting"
    assert ind["fields"]["gibsource"] == "honeypot"
    assert ind["fields"]["gibseverity"] == "green"
    assert ind["fields"]["firstseenbysource"] == "2026-09-01T00:00:00+00:00"
    assert ind["fields"]["tags"] == ["feed", "suspicious_ip/scanner", "ssh", "rdp"]


def test_country_name_wins_over_the_code_when_present():
    parsed = {"id": "s", "ipv4_ip": "198.51.100.5", "ipv4_country_name": "Germany", "ipv4_country_code": "DE"}
    assert _build("suspicious_ip/scanner", parsed)[0]["fields"]["geocountry"] == "Germany"


def test_malware_cnc_ip_gets_provider_and_the_country_code_fallback():
    parsed = {
        "id": "c",
        "ipv4_ip": "192.0.2.9",
        "ipv4_country_code": "FR",
        "ipv4_provider": "CnC Hosting",
        "malware_list_names": ["LoaderOne"],
        "threat_actor_name": "Spider Crew",
    }
    ind = _build("malware/cnc", parsed)[0]
    assert ind["fields"]["geocountry"] == "FR"
    assert ind["fields"]["organization"] == "CnC Hosting"
    assert ind["fields"]["malwarefamily"] == ["LoaderOne"]
    assert ind["fields"]["tags"] == ["malware/cnc", "LoaderOne", "Spider Crew"]


def test_phishing_group_url_carries_brand_objective_and_actor():
    parsed = {
        "id": "p",
        "url": ["http://phish.test/login"],
        "phishing_domain_domain": "phish.test",
        "phishing_domain_registrar": "Example Registrar",
        "brand": "Example Bank",
        "objective": "Banking",
        "domain_expiration": "2027-01-01T00:00:00+00:00",
        "domain_registered": "2026-01-01T00:00:00+00:00",
        "date_detected": "2026-09-01T00:00:00+00:00",
        "threat_actor_name": "Phisher",
        "evaluation_severity": "orange",
    }
    [url] = _build("attacks/phishing_group", parsed)
    assert url["type"] == "URL"
    assert url["fields"]["gibphishingobjectives"] == "Banking"
    assert url["fields"]["firstseenbysource"] == "2026-09-01T00:00:00+00:00"
    assert url["fields"]["gibphishingbrand"] == "Example Bank"
    assert url["fields"]["gibthreatactorname"] == "Phisher"
    assert url["fields"]["tags"] == ["attacks/phishing_group", "Phisher", "Example Bank"]


def test_git_repository_and_deface_records_carry_dates_and_source():
    git = _build(
        "osi/git_repository",
        {
            "id": "g",
            "contributors_emails": ["dev@example.test"],
            "hash": ["a" * 40],
            "repository": "https://git.example.com/org/repo",
            "date_created": "2026-08-01T00:00:00+00:00",
            "date_detected": "2026-09-01T00:00:00+00:00",
        },
    )
    # one indicator per leak, the repository: revision hashes and committer e-mails do not become indicators
    [repository] = git
    assert (repository["type"], repository["value"]) == ("URL", "https://git.example.com/org/repo")
    assert repository["fields"]["firstseenbysource"] == "2026-08-01T00:00:00+00:00"
    assert repository["fields"]["lastseenbysource"] == "2026-09-01T00:00:00+00:00"
    assert repository["score"] == 2
    deface_record = {"id": "d", "url": "http://victim.test/x", "date": "2026-09-03T00:00:00+00:00", "source": "deface-archive"}
    deface = _build("attacks/deface", deface_record)[0]
    assert deface["fields"]["firstseenbysource"] == "2026-09-03T00:00:00+00:00"
    assert deface["fields"]["gibsource"] == "deface-archive"


def test_relationships_link_the_observable_to_malware_and_threat_actor_objects():
    parsed = {
        "id": "acc",
        "event_url": ["http://cnc.test/gate"],
        "event_domain": [],
        "malware_names": ["BankerOne", "LoaderOne"],
        "threat_actor_names": ["CrewTwo"],
    }
    ind = _build("compromised/account_group", parsed, Settings(create_relationships=True))[0]
    relationships = ind["relationships"]
    assert [(r["entityB"], r["entityBType"], r["name"], r["reverseName"]) for r in relationships] == [
        ("BankerOne", "Malware", "indicator-of", "indicated-by"),
        ("LoaderOne", "Malware", "indicator-of", "indicated-by"),
        ("CrewTwo", "Threat Actor", "related-to", "related-to"),
    ]
    assert all(r["entityA"] == "http://cnc.test/gate" and r["entityAType"] == "URL" for r in relationships)
    assert all(r["entityBFamily"] == "Indicator" and r["type"] == "IndicatorToIndicator" for r in relationships)
    # rawJSON stays a flat record for the classifier/mapper; the relationships ride on the indicator.
    assert "relationships" not in ind["rawJSON"]


def test_relationships_follow_the_setting_and_need_at_least_one_name():
    parsed = {"id": "acc", "event_url": ["http://cnc.test/gate"], "event_domain": [], "malware_names": ["BankerOne"]}
    assert "relationships" not in _build("compromised/account_group", parsed, Settings(create_relationships=False))[0]
    assert "relationships" not in _build("compromised/account_group", parsed)[0]
    bare = {"id": "acc", "event_url": ["http://cnc.test/gate"], "event_domain": []}
    assert "relationships" not in _build("compromised/account_group", bare, Settings(create_relationships=True))[0]


def test_ip_stored_under_the_domain_key_relates_as_an_ip():
    parsed = {"id": "x", "domain": "203.0.113.45", "malware_list_names": ["LoaderOne"]}
    ind = _build("malware/cnc", parsed, Settings(create_relationships=True))[0]
    assert ind["relationships"][0]["entityAType"] == "IP"


def test_tags_malware_family_and_relationships_stay_lists_and_other_lists_are_joined():
    ind = {
        "fields": {"tags": ["a", "b"], "malwarefamily": ["m"], "gibmalwarename": ["m", "n"]},
        "relationships": [{"fields": {"x": [1]}}],
    }
    out = IndicatorBuilder._flattened([ind])[0]
    assert out["fields"]["tags"] == ["a", "b"]
    assert out["fields"]["malwarefamily"] == ["m"]
    assert out["fields"]["gibmalwarename"] == "m, n"
    assert out["relationships"] == [{"fields": {"x": [1]}}]


def test_get_indicators_command_reads_the_relationship_setting_from_the_instance(mocker):
    params = {"url": "https://example.com", "credentials": {"identifier": "u", "password": "p"}, "create_relationships": False}
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "params", return_value=params)
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "command", return_value="gibti-get-indicators")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "args", return_value={"collection": "suspicious_ip/tor_node", "limit": "5"})
    seen: list[Settings] = []
    real = GroupIB_TIA_Feed.IndicatorBuilder

    class Spy(real):
        def __init__(self, collection_name, settings):
            seen.append(settings)
            super().__init__(collection_name, settings)

    mocker.patch.object(GroupIB_TIA_Feed, "IndicatorBuilder", Spy)
    portion = mocker.Mock()
    portion.parse_portion.return_value = [{"id": "x", "ipv4_ip": "192.0.2.6", "source": "s"}]
    mocker.patch.object(Client, "start_cursor", return_value=None)
    mocker.patch.object(Client, "update_feed", return_value=[portion])
    results = mocker.patch.object(GroupIB_TIA_Feed, "return_results")
    GroupIB_TIA_Feed.main()
    assert [settings.create_relationships for settings in seen] == [False]
    [[table]] = results.call_args.args
    assert "192.0.2.6" in table.readable_output


def test_feed_creates_the_malware_and_threat_actor_objects_once_per_portion():
    records = [
        {
            "id": "acc1",
            "event_url": ["http://cnc.test/gate"],
            "event_domain": [],
            "malware_names": ["BankerOne"],
            "threat_actor_names": ["CrewTwo"],
            "evaluation_tlp": "amber",
        },
        {"id": "acc2", "event_url": ["http://cnc2.test/gate"], "event_domain": [], "malware_names": ["BankerOne", "LoaderOne"]},
    ]
    indicators = IndicatorBuilder(
        "compromised/account_group",
        Settings(create_relationships=True, tags=("feed",), tlp_color="GREEN", use_tlp_from_source=True),
    ).build(records)
    objects = [(i["type"], i["value"]) for i in indicators if i["type"] in ("Malware", "Threat Actor")]
    assert objects == [("Malware", "BankerOne"), ("Threat Actor", "CrewTwo"), ("Malware", "LoaderOne")]
    banker = next(i for i in indicators if i["value"] == "BankerOne")
    assert banker["fields"] == {
        "gibcollection": "compromised/account_group",
        "tags": ["feed", "compromised/account_group"],
        "trafficlightprotocol": "AMBER",
    }
    assert banker["rawJSON"]["type"] == "Malware"
    assert "relationships" not in banker
    assert [i["type"] for i in indicators][:2] == ["URL", "Malware"]


def test_threat_actor_object_carries_the_id_and_apt_flag_when_the_record_names_one_actor():
    parsed = {
        "id": "c",
        "url": ["http://cnc.test/x"],
        "threat_actor_name": "Spider Crew",
        "threat_actor_id": "abc123",
        "threat_actor_is_apt": False,
        "malware_list_names": ["LoaderOne"],
    }
    indicators = _build("malware/cnc", parsed, Settings(create_relationships=True))
    actor = next(i for i in indicators if i["type"] == "Threat Actor")
    assert actor["value"] == "Spider Crew"
    assert actor["fields"]["gibthreatactorid"] == "abc123"
    assert actor["fields"]["gibthreatactorisapt"] is False
    assert actor["fields"]["tags"] == ["malware/cnc"]


def test_no_malware_or_actor_object_is_created_without_the_relationship_setting():
    parsed = {"id": "acc", "event_url": ["http://cnc.test/gate"], "event_domain": [], "malware_names": ["BankerOne"]}
    assert [i["type"] for i in _build("compromised/account_group", parsed)] == ["URL"]
    assert [i["type"] for i in _build("compromised/account_group", parsed, Settings(create_relationships=False))] == ["URL"]


@pytest.mark.parametrize(
    "collection, parsed, expected",
    [
        # a Tor exit node is "green" in Group-IB's evaluation: an anonymizer, not a benign IP
        ("suspicious_ip/tor_node", {"id": "t", "ipv4_ip": "203.0.113.54", "evaluation_severity": "green"}, 2),
        ("malware/cnc", {"id": "c", "url": "http://c2.test/gate"}, 3),
        ("apt/threat", {"id": "a", "indicators_params_ipv4": [["203.0.113.1"]], "evaluation_severity": "green"}, 3),
        ("ioc/common", {"id": "i", "domain": "bad.test"}, 3),
        ("attacks/phishing_group", {"id": "p", "url": ["http://phish.test/"], "evaluation_severity": "red"}, 2),
        ("osi/vulnerability", {"id": "CVE-2099-1", "cvss_score": 3.1}, 3),
        ("osi/vulnerability", {"id": "CVE-2099-2", "cvss_score": 5.0, "has_exploit": True}, 3),
        ("osi/vulnerability", {"id": "CVE-2099-3", "cvss_score": 9.8}, 3),
        ("osi/vulnerability", {"id": "CVE-2099-4", "epss_percentile": 0.97}, 3),
    ],
)
def test_every_feed_indicator_carries_its_collection_verdict(collection, parsed, expected):
    indicators = _build(collection, parsed)
    assert indicators
    assert {(i["score"], i["rawJSON"]["score"]) for i in indicators} == {(expected, expected)}


def test_threat_report_files_keep_their_own_name_and_hashes():
    # indicators.params.* yields one entry per element of the report's indicators array: a network
    # element has no hashes, a file element no IPs.
    parsed = {
        "id": "report-with-files",
        "indicators_params_ipv4": [["203.0.113.1", "203.0.113.2"], [], []],
        "indicators_params_domain": [None, None, None],
        "indicators_params_url": ["", None, None],
        "indicators_params_hashes_md5": [None, "a" * 32, "b" * 32],
        "indicators_params_name": [None, "loader.exe", "payload.dll"],
        "indicators_params_hashes_sha1": [None, "c" * 40, "d" * 40],
        "indicators_params_hashes_sha256": [None, "e" * 64, "f" * 64],
        "indicators_params_size": [None, 1024, 2048],
        "indicators_date_first_seen": ["2026-01-01", "2026-02-01", "2026-03-01"],
        "evaluation_severity": "red",
    }
    indicators = _build("apt/threat", parsed)
    files = [i for i in indicators if i["type"] == "File"]
    assert [
        (f["value"], f["fields"]["gibfilename"], f["fields"]["md5"], f["fields"]["sha1"], f["fields"]["size"]) for f in files
    ] == [
        ("e" * 64, "loader.exe", "a" * 32, "c" * 40, 1024),
        ("f" * 64, "payload.dll", "b" * 32, "d" * 40, 2048),
    ]
    assert [f["fields"]["firstseenbysource"] for f in files] == ["2026-02-01", "2026-03-01"]
    ips = [i for i in indicators if i["type"] == "IP"]
    assert [(i["value"], i["fields"]["firstseenbysource"]) for i in ips] == [
        ("203.0.113.1", "2026-01-01"),
        ("203.0.113.2", "2026-01-01"),
    ]


def test_threat_report_files_are_keyed_by_sha256_else_sha1_else_md5():
    # A report's file entry carries up to ten hash kinds, most of them empty: each file is keyed by
    # its SHA-256, else its SHA-1, else its MD5, else its SHA-512, so a file without an MD5 still becomes an indicator.
    parsed = {
        "id": "report-with-partial-hashes",
        "indicators_params_ipv4": [["203.0.113.1"], None, None, None],
        "indicators_params_hashes_md5": [None, "a" * 32, "", "b" * 32],
        "indicators_params_hashes_sha1": [None, "c" * 40, "d" * 40, ""],
        "indicators_params_hashes_sha256": [None, "e" * 64, "", ""],
        "indicators_params_name": [None, "full.exe", "sha1-only.dll", "md5-only.bin"],
    }
    for collection in ("apt/threat", "hi/threat"):
        files = [i for i in _build(collection, parsed) if i["type"] == "File"]
        assert [(f["value"], f["fields"]["gibfilename"]) for f in files] == [
            ("e" * 64, "full.exe"),
            ("d" * 40, "sha1-only.dll"),
            ("b" * 32, "md5-only.bin"),
        ]


def test_defanged_threat_report_urls_become_real_urls():
    parsed = {
        "id": "report-with-defanged-urls",
        "indicators_params_url": ["hxxps://files.example.com/lib/files/db/emp"],
        "indicators_params_domain": ["evil[.]example"],
    }
    indicators = _build("apt/threat", parsed)
    assert sorted((i["type"], i["value"], i["rawJSON"]["value"]) for i in indicators) == [
        ("Domain", "evil.example", "evil.example"),
        ("URL", "https://files.example.com/lib/files/db/emp", "https://files.example.com/lib/files/db/emp"),
    ]
    assert IndicatorBuilder._refang("https://fine.example/hxxp") == "https://fine.example/hxxp"
    assert IndicatorBuilder._refang(42) == 42


def test_feed_objects_carry_the_platform_object_verdict():
    parsed = {"id": "c", "url": "http://c2.test/gate", "malware_list_names": ["LoaderOne"], "threat_actor_name": ["CrewTwo"]}
    indicators = _build("malware/cnc", parsed, Settings(create_relationships=True))
    objects = {i["type"]: i for i in indicators if i["type"] in ("Malware", "Threat Actor")}
    assert set(objects) == {"Malware", "Threat Actor"}
    assert {(i["score"], i["rawJSON"]["score"]) for i in objects.values()} == {(3, 3)}


def test_template_values_are_not_feed_indicators():
    parsed = {
        "id": "t",
        "indicators_params_url": [
            "https://files.example/contents/{machineId}/Lic.txt",
            "https://drive.example/d/[generated id]/view",
            "hxxps://ok.example/x",
        ],
    }
    assert [i["value"] for i in _build("apt/threat", parsed)] == ["https://ok.example/x"]
    network = {
        "id": "3" * 40,
        "type": "network",
        "params": {"domain": "", "ipv4": [], "ipv6": ["{ipv6}", "2001:db8::77"], "ssl": [], "url": ""},
    }
    assert set(_by_key(_from_raw("hi/threat", [_report(indicators=[network])]))) == {("IPv6", "2001:db8::77")}


def test_get_indicators_by_id_reads_search_only_collections_through_the_update_feed():
    from unittest.mock import MagicMock

    client = MagicMock()
    portion = MagicMock()
    portion.parse_portion.return_value = [{"id": "p1", "url": ["http://phish.example/login"]}]
    client.search.return_value = iter([portion])
    results = _get(client, {"collection": "attacks/phishing_group", "id": "p1", "limit": "5"})
    client.search.assert_called_once_with("attacks/phishing_group", query="id:p1", limit=1)
    client.record.assert_not_called()
    assert "http://phish.example/login" in results[0].readable_output
    # a record without indicators says so instead of writing nothing
    portion.parse_portion.return_value = [{"id": "p1"}]
    client.search.return_value = iter([portion])
    [note] = _get(client, {"collection": "attacks/phishing_group", "id": "p1", "limit": "5"})
    assert "No indicators" in note.readable_output
    # an id the update feed does not have is an error, as for the other collections
    client.search.return_value = iter([])
    with pytest.raises(DemistoException, match="No record with id 'p1' was found in attacks/phishing_group"):
        _get(client, {"collection": "attacks/phishing_group", "id": "p1", "limit": "5"})


def test_the_affected_software_of_a_cve_is_a_table_in_gibsoftwaremixed():
    parsed = {
        "id": "CVE-2021-1",
        "cvss_score": 9.8,
        "software_mixed": {
            "names": ["example-lib", "example-framework"],
            "types": ["library", "framework"],
            "versions": ["2.0", None],
        },
    }
    [cve] = _build("osi/vulnerability", parsed)
    table = cve["fields"]["gibsoftwaremixed"]
    assert "| Software Name | Software Type | Software Version |" in table
    assert "| example-lib | library | 2.0 |" in table
    assert "| example-framework | framework |  |" in table
    [empty] = _build("osi/vulnerability", {"id": "CVE-2021-2", "software_mixed": {"names": [], "types": [], "versions": []}})
    assert "gibsoftwaremixed" not in empty["fields"]


def test_a_ddos_victim_gets_no_verdict_no_attacker_tags_and_no_relationships():
    parsed = {
        "id": "dd-1",
        "target_ipv4_ip": "192.0.2.15",
        "malware_name": "BotnetOne",
        "threat_actor_name": "Botmaster",
        "cnc_url": "http://c2.test/panel",
    }
    settings = replace(_filtered("attacks/ddos: kinds = URL, GIB Victim IP"), create_relationships=True)
    indicators = _build("attacks/ddos", parsed, settings)
    victim = next(i for i in indicators if i["type"] == "GIB Victim IP")
    assert victim["value"] == "192.0.2.15"
    assert victim["score"] == 0
    assert "relationships" not in victim
    assert victim["fields"]["gibmalwarename"] == "BotnetOne"
    assert "BotnetOne" not in victim["fields"].get("tags", [])
    assert "Botmaster" not in victim["fields"].get("tags", [])
    assert "malwarefamily" not in victim["fields"]
    # the C&C URL of the same record keeps its relationships; the objects behind them come from it alone
    c2 = next(i for i in indicators if i["type"] == "URL")
    assert len(c2["relationships"]) == 2
    assert sorted(i["type"] for i in indicators if i["type"] in ("Malware", "Threat Actor")) == ["Malware", "Threat Actor"]


def test_fetch_refuses_a_collection_the_feed_has_no_mapping_for(mocker):
    client = _feed_client()
    grants = _failing_grant_list(mocker, client)
    with pytest.raises(DemistoException, match="does not build indicators from osi/public_leak"):
        _fetch(client=client, last_run={}, indicator_collections=["osi/public_leak"])
    grants.assert_not_called()


def test_get_indicators_validates_the_limit_before_converting_it():
    client = _feed_client()
    with pytest.raises(DemistoException, match="Limit should be a number"):
        _get(client, {"collection": "ioc/common", "limit": "fifty"})


def test_get_indicators_stops_after_max_pages_of_records_without_indicators(mocker):
    from unittest.mock import MagicMock

    client = _feed_client()
    pages = []
    for number in range(GetIndicatorsCommand.MAX_PAGES + 3):
        page = MagicMock()
        page.parse_portion.return_value = [{"id": f"acc-{number}", "event_url": None, "event_domain": None}]
        pages.append(page)
    mocker.patch.object(client, "hunting_rules_collections", return_value=frozenset())
    _mock_update_feed(mocker, client, return_value=pages)
    _get(client, {"collection": "compromised/account_group", "limit": "10"})
    assert sum(page.parse_portion.call_count for page in pages) == GetIndicatorsCommand.MAX_PAGES


def test_get_indicators_counts_indicators_across_pages_up_to_the_limit(mocker):
    """`limit` is the number of indicators shown, not of War Room tables: the pages are read until it is
    reached and each page adds at most the rest."""
    from unittest.mock import MagicMock

    client = _feed_client()
    pages = []
    for number in range(3):
        page = MagicMock()
        page.parse_portion.return_value = [
            {"id": f"acc-{number}-{row}", "event_url": f"http://c2-{number}-{row}.test/", "event_domain": None}
            for row in range(4)
        ]
        pages.append(page)
    mocker.patch.object(client, "hunting_rules_collections", return_value=frozenset())
    _mock_update_feed(mocker, client, return_value=pages)
    results = _get(client, {"collection": "compromised/account_group", "limit": "10"})
    assert sum(page.parse_portion.call_count for page in pages) == 3
    [table] = results
    assert len(table.raw_response) == 10
    assert table.raw_response[0]["value"] == "http://c2-0-0.test/"


def test_get_indicators_by_id_shows_every_indicator_of_the_record(mocker):
    """A record looked up by id is shown whole, whatever the limit: a threat report may name more IOCs than `limit`."""
    from unittest.mock import MagicMock

    client = _feed_client()
    record = MagicMock()
    record.parse_portion.return_value = [
        {"id": "acc-1", "event_url": [f"http://c2-{number}.test/" for number in range(60)], "event_domain": None}
    ]
    mocker.patch.object(client.poller, "search_feed_by_id", return_value=record)
    [table] = _get(client, {"collection": "compromised/account_group", "id": "acc-1"})
    assert len(table.raw_response) == 60


def test_cursors_are_saved_only_after_the_indicators_were_created(mocker):
    params = {
        "url": "https://example.com",
        "credentials": {"identifier": "u", "password": "p"},
        "indicator_collections": ["ioc/common"],
    }
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "params", return_value=params)
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "command", return_value="fetch-indicators")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "args", return_value={})
    mocker.patch.object(GroupIB_TIA_Feed, "Client", autospec=True)
    mocker.patch.object(GroupIB_TIA_Feed, "get_integration_context", return_value={})
    mocker.patch.object(
        GroupIB_TIA_Feed.FetchIndicatorsCommand, "run", return_value=({"last_fetch": {"ioc/common": "9"}}, [{"value": "x"}])
    )
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "createIndicators", side_effect=RuntimeError("storage unavailable"))
    saved = mocker.patch.object(GroupIB_TIA_Feed, "set_integration_context")
    error = mocker.patch.object(GroupIB_TIA_Feed, "return_error")
    GroupIB_TIA_Feed.main()
    saved.assert_not_called()
    assert "storage unavailable" in error.call_args.args[0]


def test_a_fetch_creates_the_indicators_in_batches_then_merges_its_cursors_into_the_context(mocker):
    """The cursors are written after the last batch, next to what the context already holds (the grant cache)."""
    params = {
        "url": "https://example.com",
        "credentials": {"identifier": "u", "password": "p"},
        "indicator_collections": ["ioc/common"],
    }
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "params", return_value=params)
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "command", return_value="fetch-indicators")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "args", return_value={})
    cache = {"fetched_at": 1, "items": []}
    context = {"granted_collections_cache": cache, "last_fetch": {"ioc/common": "1"}}
    events: list = []
    mocker.patch.object(GroupIB_TIA_Feed, "get_integration_context", side_effect=lambda: dict(context))
    mocker.patch.object(GroupIB_TIA_Feed, "set_integration_context", side_effect=lambda value: events.append(("saved", value)))
    mocker.patch.object(
        GroupIB_TIA_Feed.demisto, "createIndicators", side_effect=lambda batch: events.append(("created", len(batch)))
    )
    next_run = {"last_fetch": {"ioc/common": "9"}, "first_fetch_time": "3 days", "hunting_rules": False}
    indicators = [{"value": f"192.0.2.{n % 250}", "n": n} for n in range(2001)]
    run = mocker.patch.object(GroupIB_TIA_Feed.FetchIndicatorsCommand, "run", return_value=(next_run, indicators))
    error = mocker.patch.object(GroupIB_TIA_Feed, "return_error")
    GroupIB_TIA_Feed.main()
    error.assert_not_called()
    run.assert_called_once_with(context)
    assert events == [("created", 2000), ("created", 1), ("saved", {"granted_collections_cache": cache, **next_run})]


def test_the_instance_test_through_main_answers_ok(mocker):
    params = {"url": "https://example.com", "credentials": {"identifier": "u", "password": "p"}}
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "params", return_value=params)
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "command", return_value="test-module")
    mocker.patch.object(GroupIB_TIA_Feed, "set_integration_context")
    send = mocker.patch.object(GroupIB_TIA_Feed.TIPoller, "send_request", return_value=[{"collection": "ioc/common"}])
    results = mocker.patch.object(GroupIB_TIA_Feed.demisto, "results")
    GroupIB_TIA_Feed.main()
    send.assert_called_once_with(endpoint="user/granted_collections", params={})
    results.assert_called_once_with("ok")


def test_an_ioc_primary_zero_risk_score_is_suspicious_and_an_osi_vulnerability_cve_is_bad():
    parsed = {
        "id": "r0",
        "record_type": "network",
        "url": ["http://z.test/"],
        "url_risk_score": [0],
        "domain": [],
        "ip": [],
        "hash_md5": None,
        "hash_sha1": None,
        "hash_sha256": None,
    }
    [zero] = _build("ioc/primary", parsed)
    assert zero["score"] == 2
    [cve] = _build("osi/vulnerability", {"id": "CVE-2021-3", "cvss_score": 2.0, "has_exploit": False})
    assert cve["score"] == 3


def test_an_unscored_ioc_primary_element_is_suspicious_and_one_scored_above_zero_bad():
    parsed = {
        "id": "r1",
        "record_type": "network",
        "url": ["http://scored.test/"],
        "url_risk_score": [50],
        "domain": ["unscored.test"],
        "ip": [],
        "hash_md5": None,
        "hash_sha1": None,
        "hash_sha256": None,
    }
    assert {i["value"]: i["score"] for i in _build("ioc/primary", parsed)} == {"http://scored.test/": 3, "unscored.test": 2}


def test_feed_pages_are_capped_per_collection(mocker):
    client = _feed_client()
    generator = mocker.patch.object(client.poller, "create_update_generator", return_value=iter([]))
    cap = GroupIB_TIA_Feed.TICollections.get_page_limit
    list(client.update_feed(collection_name="suspicious_ip/tor_node", seq_update=5, limit=100_000))
    assert (
        generator.call_args.kwargs["request_params"].limit
        == GroupIB_TIA_Feed.BoundaryPages.LARGEST_PAGES["suspicious_ip/tor_node"]
    )
    list(client.update_feed(collection_name="malware/cnc", seq_update=5, limit=10))
    assert generator.call_args.kwargs["request_params"].limit == 10
    client.search("osi/git_repository", query="x", limit=100_000)
    assert generator.call_args.kwargs["request_params"].limit == cap("osi/git_repository")
    client.update_feed(collection_name="compromised/account_group", seq_update=5)
    assert generator.call_args.kwargs["request_params"].limit == cap("compromised/account_group")


@pytest.mark.parametrize(
    "collection",
    [
        "ioc/primary",
        "ioc/common",
        "attacks/deface",
        "hi/threat",
        "apt/threat",
        "suspicious_ip/open_proxy",
        "suspicious_ip/socks_proxy",
        "suspicious_ip/vpn",
        "suspicious_ip/scanner",
        "osi/git_repository",
        "osi/vulnerability",
        "attacks/phishing_kit",
    ],
)
def test_the_feed_asks_no_collection_for_more_than_it_serves(collection):
    """A limit above the page size ciaops documents for the collection is cut to it, and to what the millisecond feeds
    serve; a collection ciaops gives no page size keeps the limit."""
    feed = _UpdateFeed()
    client = feed.client()
    _fetch(
        client=client,
        last_run={"last_fetch": {collection: 5}},
        first_fetch_time="3 days",
        indicator_collections=[collection],
        requests_count=1,
        limit=20000,
    )
    [request] = feed.sent_to(f"{collection}/updated")
    served = GroupIB_TIA_Feed.BoundaryPages.LARGEST_PAGES.get(collection)
    assert request["limit"] == (served or GroupIB_TIA_Feed.TICollections.get_page_limit(collection) or 20000)


@pytest.mark.parametrize("advisory", ["UNPATCHED_CVE_2099_0001.NASL", "RHSA-2099:1234", "MS:CVE-2099-0001"])
def test_the_feed_emits_no_cve_for_an_advisory_that_is_not_a_cve(advisory):
    assert _build("osi/vulnerability", {"id": advisory, "cvss_score": 9.8}) == []
    [cve] = _build("osi/vulnerability", {"id": "CVE-2099-12345", "cvss_score": 9.8})
    assert (cve["type"], cve["value"]) == ("CVE", "CVE-2099-12345")


def test_an_ipv6_scanner_becomes_an_ipv6_indicator():
    """A scanner record carries ipv4 or ipv6, never both: an IPv6 record is an IPv6 indicator, an IPv4 record an IP indicator."""
    parsed = {
        "id": "2001:db8::5",
        "ipv4_ip": None,
        "ipv6_ip": "2001:db8::5",
        "ipv6_country_code": "DE",
        "ipv6_provider": "Example Hosting",
        "categories": ["Scanner"],
    }
    [ind] = _build("suspicious_ip/scanner", parsed)
    assert (ind["type"], ind["value"]) == ("IPv6", "2001:db8::5")
    assert (ind["fields"]["geocountry"], ind["fields"]["organization"]) == ("DE", "Example Hosting")
    [ipv4] = _build("suspicious_ip/scanner", {"id": "198.51.100.5", "ipv4_ip": "198.51.100.5", "ipv6_ip": None})
    assert (ipv4["type"], ipv4["value"]) == ("IP", "198.51.100.5")


def test_an_open_proxy_is_last_seen_when_group_ib_last_saw_it():
    """dateDetected is when Group-IB first detected the proxy, dateLastSeen when it last saw it."""
    parsed = {
        "ipv4_ip": "198.51.100.7",
        "date_first_seen": "2026-01-01T00:00:00+00:00",
        "date_detected": "2026-01-01T00:00:00+00:00",
        "date_last_seen": "2026-03-01T00:00:00+00:00",
    }
    [ind] = _build("suspicious_ip/open_proxy", parsed)
    assert ind["fields"]["lastseenbysource"] == "2026-03-01T00:00:00+00:00"
    assert COLLECTIONS["suspicious_ip/open_proxy"].parser_mapping["date_last_seen"] == "dateLastSeen"


@pytest.mark.parametrize("flag", ["false_positive", "whitelist"])
def test_the_feed_drops_a_phishing_group_marked_false_positive_or_allow_listed(flag):
    parsed = {"id": "p", "url": ["http://phish.example/login"], flag: True}
    assert _build("attacks/phishing_group", parsed) == []
    [kept] = _build("attacks/phishing_group", {**parsed, flag: False})
    assert kept["value"] == "http://phish.example/login"


def test_the_feed_fetches_the_selected_collection(mocker):
    client = _feed_client()
    generator = _mock_update_feed(mocker, client, return_value=[])
    _fetch(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        indicator_collections=["malware/cnc"],
        requests_count=1,
    )
    assert generator.call_args.kwargs["collection_name"] == "malware/cnc"


def test_feed_requests_are_paced_above_one_second_by_default():
    assert Settings.DEFAULT_RATE_LIMIT_DELAY == 1.2
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "GroupIB_TIA_Feed.yml")) as yml_file:
        blocks = yml_file.read().split("\n- ")
    [block] = [block for block in blocks if "\n  name: rate_limit_delay\n" in block]
    assert '  defaultvalue: "1.2"' in block


class _MillisecondServer:
    """An update feed served by millisecond through the ciaops generator: a page starts after the cursor's millisecond
    and answers its last record's cursor; ``unit`` 1 compares the cursor whole, ``cap`` is the server's own page cap."""

    def __init__(self, records: list[dict], unit: int = 1000, cap: int | None = None):
        self.unit, self.cap = unit, cap
        self.records = sorted(records, key=lambda record: record["seqUpdate"] // unit)
        self.asked: list[Any] = []
        self.params: list[Any] = []

    def create_update_generator(self, collection_name, request_params, sequpdate=None, rate_limit_delay=None):
        self.asked.append(sequpdate)
        self.params.append(request_params)
        cursor = sequpdate
        size = min(request_params.limit, self.cap or request_params.limit)
        while True:
            start = -1 if cursor is None else int(cursor) // self.unit
            items = [record for record in self.records if record["seqUpdate"] // self.unit > start][:size]
            if not items:
                return
            cursor = items[-1]["seqUpdate"]
            ahead = [record for record in self.records if record["seqUpdate"] // self.unit > start]
            yield Parser({"count": len(ahead), "items": items, "seqUpdate": cursor}, None, None)


# An open_proxy id is the IP, listed again on the same or another port.
_REPEATED_ID_FIELDS = {"suspicious_ip/open_proxy": ("port",)}


class _UpdateFeed:
    """The ``{collection}/updated`` route and ``sequence_list`` behind the real ciaops generator: records above the
    cursor in cursor order, several per seqUpdate, each page answering its last record's cursor.

    ``start_cursors`` is what ``sequence_list`` answers per collection, an exception or a value; ``refused`` is what a
    collection's ``/updated`` route raises."""

    def __init__(
        self,
        records: dict[str, list[dict]] | None = None,
        start_cursors: dict[str, Any] | None = None,
        refused: dict[str, Exception] | None = None,
    ):
        self.records = {name: sorted(items, key=lambda item: item["seqUpdate"]) for name, items in (records or {}).items()}
        self.start_cursors = start_cursors or {}
        self.refused = refused or {}
        self.requests: list[tuple[str, dict]] = []

    def client(self, granted: frozenset[str] | set[str] = frozenset()) -> Client:
        client = Client(
            base_url="https://api.example.com",
            auth=("user@example.com", "token"),
            verify=True,
            rate_limit_delay=0,
        )
        client.poller.send_request = self.send_request  # type: ignore[method-assign]
        client.hunting_rules_collections = lambda: frozenset(granted)  # type: ignore[method-assign]
        return client

    def send_request(self, endpoint, params=None, **kwargs):
        sent = {key: value for key, value in (params or {}).items() if value is not None}
        self.requests.append((endpoint, sent))
        if endpoint == "sequence_list":
            answer = self.start_cursors.get(sent["collection"])
            if isinstance(answer, Exception):
                raise answer
            return {"list": {} if answer is None else {sent["collection"]: answer}}
        collection = endpoint.removesuffix("/updated")
        if collection in self.refused:
            raise self.refused[collection]
        cursor = int(sent.get("seqUpdate", 0))
        ahead = [item for item in self.records.get(collection, []) if item["seqUpdate"] > cursor]
        page = ahead[: int(sent.get("limit", 100))]
        return {
            "count": len(ahead),
            "items": [dict(item) for item in page],
            "seqUpdate": page[-1]["seqUpdate"] if page else cursor,
        }

    def sent_to(self, endpoint: str) -> list[dict]:
        return [params for name, params in self.requests if name == endpoint]


def _tied_feed_record(collection: str, n: int, seq: int) -> dict:
    """A record of ``collection`` in the shape the API serves."""
    record_id = f"{n:040x}"
    if collection == "compromised/spd":
        return {
            "id": record_id,
            "type": "IBAN",
            "serviceType": "Bank",
            "ownerName": None,
            "country": ["GB"],
            "value": {"value": f"GB00TEST{n:014d}", "email": None, "bankCard": None, "iban": None},
            "illegalScore": 100,
            "tags": [],
            "sources": [{"name": "shop.example.com", "type": "Underground Market"}],
            "events": [],
            "malware": [],
            "threatActor": [],
            "evaluation": {"admiraltyCode": "A2", "credibility": 80, "reliability": 100, "severity": "red", "tlp": "amber"},
            "createdAt": "2026-10-01T00:00:00.000Z",
            "firstSeenAt": "2026-10-01T00:00:00.000Z",
            "lastSeenAt": "2026-10-01T00:00:00.000Z",
            "seqUpdate": seq,
        }
    return {
        "id": record_id,
        "cnc": f"c2-{n}.example.com",
        "domain": f"c2-{n}.example.com",
        "url": "",
        "ipv4": [],
        "ipv6": [],
        "malwareList": [],
        "threatActor": [],
        "platform": "",
        "file": None,
        "dateDetected": "2026-10-01T00:00:00Z",
        "dateFirstSeen": "2026-10-01T00:00:00Z",
        "dateLastSeen": "2026-10-01T00:00:00Z",
        "seqUpdate": seq,
    }


@pytest.mark.parametrize(
    "collection",
    [
        "compromised/spd",
        "compromised/account_group",
        "osi/git_repository",
        "osi/vulnerability",
        "malware/cnc",
        "ioc/primary",
        "ioc/common",
    ],
)
@pytest.mark.parametrize("answer", [GroupIB_TIA_Feed.ConnectionException(SEQUENCE_LIST_DOWN), None, 0])
def test_a_first_fetch_without_a_start_cursor_waits_for_one(mocker, collection, answer):
    """These collections take no date as their start position: the collection is reported, stores no cursor and asks
    sequence_list again on the next run."""
    feed = _UpdateFeed(start_cursors={collection: answer, "attacks/ddos": 5})
    health = mocker.patch.object(GroupIB_TIA_Feed.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "error")
    fetch = {
        "client": feed.client(),
        "first_fetch_time": "3 days",
        "indicator_collections": [collection, "attacks/ddos"],
        "requests_count": 1,
    }
    next_run, _ = _fetch(last_run={}, **fetch)
    assert feed.sent_to(f"{collection}/updated") == []
    assert next_run["last_fetch"][collection] is None
    [call] = health.call_args_list
    assert collection in call.args[0]
    message = call.args[0]
    assert "the collection cannot start from a date" in message
    assert "so it waits for a sequence_list cursor" in message
    feed.start_cursors[collection] = 1_760_000_000_000_000
    _fetch(last_run=next_run, **fetch)
    [request] = feed.sent_to(f"{collection}/updated")
    assert request["seqUpdate"] == 1_760_000_000_000_000
    assert "df" not in request


@pytest.mark.parametrize(
    "collection, unit, below", [("ioc/primary", 1, 0), ("malware/cnc", 1, 1), ("suspicious_ip/tor_node", 1000, 1)]
)
def test_a_first_fetch_stores_the_cursor_of_its_pages_not_the_start_cursor(mocker, collection, unit, below):
    """sequence_list gives the start S and a page answers the cursor P above it: the next run starts at P, or just
    below it where records share cursors, not at S, which would read the page again."""
    mocker.patch.object(GroupIB_TIA_Feed.time, "sleep")
    start = 1_760_000_000_000_000
    last = start + 5 * unit
    records = [
        {"id": f"198.51.100.{n}", "ipv4": {"ip": f"198.51.100.{n}"}, "seqUpdate": seq}
        for n, seq in ((1, start + unit), (2, last))
    ]
    feed = _UpdateFeed({collection: records}, start_cursors={collection: start})
    next_run, _ = _fetch(
        client=feed.client(),
        last_run={},
        first_fetch_time="3 days",
        indicator_collections=[collection],
        requests_count=1,
    )
    [request] = feed.sent_to(f"{collection}/updated")
    assert request["seqUpdate"] == start
    stored = next_run["last_fetch"][collection]
    assert stored == last - below


def test_the_first_fetch_help_says_why_a_collection_waits_for_a_cursor():
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "GroupIB_TIA_Feed.yml")) as yml_file:
        blocks = yml_file.read().split("\n- ")
    [block] = [block for block in blocks if "\n  name: indicators_first_fetch\n" in block]
    assert "start from the date itself" in block
    assert "When no cursor is available for that date, any other collection is not read yet" in block
    assert "the cursor is requested again on the next fetch" in block
    assert "filter on dates" not in block


@pytest.mark.parametrize(
    "collection", ["ioc/primary", "osi/vulnerability", "malware/cnc", "suspicious_ip/tor_node", "attacks/ddos"]
)
def test_a_start_cursor_followed_by_no_page_is_stored(collection):
    """sequence_list gives the collection its start, and the first page is empty: the next run starts at
    that cursor instead of asking sequence_list again for a later one."""
    start = 1_760_000_000_000_000
    feed = _UpdateFeed(start_cursors={collection: start})
    fetch = {
        "client": feed.client(),
        "first_fetch_time": "3 days",
        "indicator_collections": [collection],
        "requests_count": 1,
    }
    next_run, indicators = _fetch(last_run={}, **fetch)
    assert indicators == []
    assert next_run["last_fetch"][collection] == start
    _fetch(last_run=next_run, **fetch)
    assert len(feed.sent_to("sequence_list")) == 1
    requests = feed.sent_to(f"{collection}/updated")
    assert [request["seqUpdate"] for request in requests] == [start, start]
    assert "df" not in requests[-1]


@pytest.mark.parametrize("refused", ["ioc/primary", "malware/cnc"])
def test_a_start_cursor_followed_by_a_refused_page_is_stored(mocker, refused):
    """sequence_list gives each collection its start and the first page of one is refused: that collection
    stores its start, and the other reads on past it."""
    start = 1_760_000_000_000_000
    common = {"id": "c" * 40, "ip": ["192.0.2.61"], "dateLastSeen": "2026-10-01T00:00:00Z", "seqUpdate": start + 10}
    feed = _UpdateFeed(
        {"ioc/common": [common]},
        start_cursors={refused: start, "ioc/common": start},
        refused={refused: GroupIB_TIA_Feed.ConnectionException(SERVER_ERROR)},
    )
    health = mocker.patch.object(GroupIB_TIA_Feed.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "error")
    next_run, indicators = _fetch(
        client=feed.client(),
        last_run={},
        first_fetch_time="3 days",
        indicator_collections=[refused, "ioc/common"],
        requests_count=1,
    )
    [request] = feed.sent_to(f"{refused}/updated")
    assert request["seqUpdate"] == start
    assert next_run["last_fetch"] == {refused: start, "ioc/common": start + 10}
    assert [indicator["value"] for indicator in indicators] == ["192.0.2.61"]
    [call] = health.call_args_list
    assert f"The fetch of {refused} failed: HTTP 500" in call.args[0]


def _cnc_body(cursor: int | None, *seqs: int) -> dict:
    """A page of records at ``seqs`` that answers ``cursor``; without one, a body that carries none."""
    if cursor is None:
        return {"message": "Sample"}
    items = [{"id": f"{seq:040x}", "cnc": "c2.example", "seqUpdate": seq} for seq in seqs]
    return {"count": len(items), "items": items, "seqUpdate": cursor}


@pytest.mark.parametrize(
    "bodies, stored, message",
    [
        ([_cnc_body(None)], 500, "The fetch of attacks/deface failed: HTTP 200 with a page that carries no seqUpdate"),
        ([_cnc_body(500, 600)], 500, "attacks/deface with a page whose seqUpdate does not advance"),
        ([_cnc_body(600, 600), _cnc_body(600, 700)], 600, "attacks/deface with a page whose seqUpdate does not advance"),
    ],
    ids=["missing", "repeated", "repeated on page 2"],
)
def test_a_page_whose_cursor_is_missing_or_does_not_advance_keeps_the_cursor_before_that_page(mocker, bodies, stored, message):
    """ciaops asks for the next page from whatever cursor a page answers; the walk stops there and keeps its cursor."""
    common = {"id": "c" * 40, "ip": ["192.0.2.61"], "dateLastSeen": "2026-10-01T00:00:00Z", "seqUpdate": 410}
    feed = _UpdateFeed({"ioc/common": [common]})
    served = feed.send_request
    answers = iter(bodies)

    def send_request(endpoint, params=None, **kwargs):
        if endpoint == "attacks/deface/updated":
            feed.requests.append((endpoint, dict(params or {})))
            return next(answers)
        return served(endpoint, params, **kwargs)

    client = feed.client()
    client.poller.send_request = send_request  # type: ignore[method-assign]
    health = mocker.patch.object(GroupIB_TIA_Feed.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "error")
    next_run, indicators = _fetch(
        client=client,
        last_run={"first_fetch_time": "3 days", "last_fetch": {"attacks/deface": 500, "ioc/common": 400}},
        indicator_collections=["attacks/deface", "ioc/common"],
        requests_count=3,
    )
    assert next_run["last_fetch"] == {"attacks/deface": stored, "ioc/common": 410}
    assert len(feed.sent_to("attacks/deface/updated")) == len(bodies)
    assert "192.0.2.61" in [indicator["value"] for indicator in indicators]
    assert message in health.call_args.args[0]


@pytest.mark.parametrize(
    "value, number",
    [(1_760_000_000_000_000, 1_760_000_000_000_000), (" 500 ", 500), (True, None), (None, None), ("next", None), (5.0, 5)],
)
def test_a_cursor_is_read_as_a_number_only_from_an_int_a_float_or_a_string_of_digits(value, number):
    assert GroupIB_TIA_Feed.seq_update_number(value) == number


def test_a_record_whose_type_is_no_string_does_not_fail_the_fetch(mocker):
    """A payment detail whose type is an object does not fail the fetch: both collections store their cursors."""
    odd = {**_tied_feed_record("compromised/spd", 1, 410), "type": {"name": "IBAN"}}
    common = {"id": "c" * 40, "ip": ["192.0.2.61"], "dateLastSeen": "2026-10-01T00:00:00Z", "seqUpdate": 420}
    feed = _UpdateFeed({"compromised/spd": [odd], "ioc/common": [common]})
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "error")
    next_run, indicators = _fetch(
        client=feed.client(),
        last_run={"first_fetch_time": "3 days", "last_fetch": {"compromised/spd": 400, "ioc/common": 400}},
        indicator_collections=["compromised/spd", "ioc/common"],
    )
    assert next_run["last_fetch"] == {"compromised/spd": 409, "ioc/common": 420}
    assert "192.0.2.61" in [indicator["value"] for indicator in indicators]


def test_open_proxies_whose_address_is_no_string_stay_records_of_their_own():
    proxies = [
        {"ipv4_ip": {"ip": "198.51.100.7"}, "port": "8080", "date_last_seen": "2026-03-01T00:00:00+00:00"},
        {"ipv4_ip": {"ip": "198.51.100.7"}, "port": "3128", "date_last_seen": "2026-03-02T00:00:00+00:00"},
    ]
    assert len(IndicatorBuilder("suspicious_ip/open_proxy", Settings())._merged_records(proxies)) == 2


def test_a_restart_after_a_first_fetch_change_whose_only_collection_lacks_a_start_cursor_fails_naming_sequence_list():
    feed = _UpdateFeed(start_cursors={"compromised/spd": GroupIB_TIA_Feed.ConnectionException(SEQUENCE_LIST_DOWN)})
    with pytest.raises(DemistoException, match="sequence_list"):
        _fetch(
            client=feed.client(),
            last_run={"first_fetch_time": "3 days", "last_fetch": {"compromised/spd": 777}},
            first_fetch_time="10 days",
            indicator_collections=["compromised/spd"],
            requests_count=1,
        )
    assert feed.sent_to("compromised/spd/updated") == []


def test_a_start_cursor_of_zero_is_reported_with_its_remedy(mocker):
    """sequence_list answers 0 for some collections at older dates; the health message names that answer
    and the setting that gives the collection a cursor."""
    feed = _UpdateFeed(start_cursors={"compromised/spd": 0, "attacks/ddos": 5})
    health = mocker.patch.object(GroupIB_TIA_Feed.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "error")
    next_run, _ = _fetch(
        client=feed.client(),
        last_run={},
        first_fetch_time="2026-03-01",
        indicator_collections=["compromised/spd", "attacks/ddos"],
        requests_count=1,
    )
    [call] = health.call_args_list
    assert "compromised/spd is not fetched yet: sequence_list answered 0 for 2026-03-01;" in call.args[0]
    assert "A later 'Indicator first fetch' date gives it a cursor" in call.args[0]
    assert "changing the setting restarts every selected collection from the new date" in call.args[0]
    assert feed.sent_to("compromised/spd/updated") == []
    assert next_run["last_fetch"]["compromised/spd"] is None


def test_get_indicators_reports_a_start_cursor_of_zero_with_its_remedy(mocker):
    feed = _UpdateFeed(start_cursors={"compromised/spd": 0})
    with pytest.raises(
        DemistoException,
        match="compromised/spd cannot be read yet: sequence_list answered 0 for 2026-03-01.*A later 'Indicator first fetch' date",
    ):
        _get(feed.client(), {"collection": "compromised/spd", "limit": "10"}, params={"indicators_first_fetch": "2026-03-01"})
    assert feed.sent_to("compromised/spd/updated") == []


@pytest.mark.parametrize("collection", ["attacks/ddos", "attacks/phishing_kit"])
def test_a_first_fetch_of_a_date_filtered_collection_starts_from_the_date(collection):
    """attacks/ddos and attacks/phishing_kit filter by df: without a sequence_list cursor they start from the first-fetch date."""
    feed = _UpdateFeed(start_cursors={collection: GroupIB_TIA_Feed.ConnectionException(SEQUENCE_LIST_DOWN)})
    _fetch(
        client=feed.client(),
        last_run={},
        first_fetch_time="2026-10-01",
        indicator_collections=[collection],
        requests_count=1,
    )
    [request] = feed.sent_to(f"{collection}/updated")
    assert request["df"] == "2026-10-01"
    assert "seqUpdate" not in request


def _ioc_primary(n: int, url: str | None) -> dict:
    """An ioc/primary network record in the shape the API serves."""
    return {
        "id": f"{n:040x}",
        "type": "network",
        "url": [{"url": url, "riskScore": 80}] if url else [],
        "domain": [],
        "ip": [],
        "evaluation": {"admiraltyCode": "B2", "credibility": 80, "reliability": 80, "TLP": "TLP:AMBER", "TTL": 365},
        "dateFirstSeen": "2026-10-01T00:00:00Z",
        "dateLastSeen": "2026-10-01T00:00:00Z",
        "malwareList": [],
        "threatList": [],
        "tags": [],
        "seqUpdate": 1_760_000_000_000_000 + n,
    }


def test_get_indicators_starts_where_a_first_fetch_would(mocker):
    """The command starts at the cursor of "Indicator first fetch" and shows each observable once."""
    urls = ["http://bad-1.example.com/a", "http://bad-2.example.com/b", None]
    urls += ["http://bad-1.example.com/a", "http://bad-3.example.com/c", "http://bad-4.example.com/d"]
    records = [_ioc_primary(n, url) for n, url in enumerate(urls, start=1)]
    feed = _UpdateFeed({"ioc/primary": records}, start_cursors={"ioc/primary": 1_760_000_000_000_000})
    [table] = _get(feed.client(), {"collection": "ioc/primary", "limit": "3"}, params={"indicators_first_fetch": "2026-10-01"})
    [sequence_list] = feed.sent_to("sequence_list")
    assert sequence_list["date"] == "2026-10-01"
    first = feed.sent_to("ioc/primary/updated")[0]
    assert first["seqUpdate"] == 1_760_000_000_000_000
    assert "df" not in first
    assert [indicator["value"] for indicator in table.raw_response] == [
        "http://bad-1.example.com/a",
        "http://bad-2.example.com/b",
        "http://bad-3.example.com/c",
    ]


def test_get_indicators_without_a_start_cursor_says_so(mocker):
    feed = _UpdateFeed(start_cursors={"compromised/spd": GroupIB_TIA_Feed.ConnectionException(SEQUENCE_LIST_DOWN)})
    with pytest.raises(DemistoException, match="sequence_list"):
        _get(feed.client(), {"collection": "compromised/spd", "limit": "10"}, params={})
    assert feed.sent_to("compromised/spd/updated") == []


def _by_key(indicators: list[dict]) -> dict:
    return {(i["type"], i["value"]): i for i in indicators}


def _objects(indicators: list[dict]) -> set:
    return {(i["type"], i["value"]) for i in indicators if i["type"] in ("Malware", "Threat Actor")}


def _report(**overrides) -> dict:
    record = {
        "id": "f" * 40,
        "threatActor": {"id": "a" * 40, "name": "CrewOne", "isAPT": False, "country": None},
        "malwareList": [],
        "evaluation": {
            "admiraltyCode": "B2",
            "credibility": 80,
            "reliability": 80,
            "tlp": "amber",
            "severity": "red",
            "ttl": None,
        },
        "indicators": [
            {
                "id": "1" * 40,
                "type": "network",
                "params": {"domain": "", "ipv4": ["192.0.2.10"], "ipv6": [], "ssl": [], "url": ""},
                "dateFirstSeen": "2026-09-01T00:00:00Z",
                "dateLastSeen": "2026-09-02T00:00:00Z",
            }
        ],
    }
    record.update(overrides)
    return record


def _cnc(**overrides) -> dict:
    record = {
        "id": "c" * 40,
        "cnc": "http://c2.example.com/gate.php",
        "domain": "c2.example.com",
        "url": "http://c2.example.com/gate.php",
        "ipv4": [],
        "ipv6": [],
        "file": [],
        "malwareList": [],
        "platform": "Windows",
        "threatActor": [],
        "dateDetected": "2026-08-20T11:03:52Z",
        "dateFirstSeen": "2026-08-18T00:00:00Z",
        "dateLastSeen": "2026-09-05T00:00:00Z",
        "seqUpdate": 1786415786354883,
    }
    record.update(overrides)
    return record


def _spd(type_: str, value: str, **overrides) -> dict:
    record = {
        "id": "5" * 40,
        "type": type_,
        "serviceType": "ExampleService",
        "ownerName": None,
        "country": ["GB"],
        "value": {"value": value, "email": None, "bankCard": None, "iban": None},
        "illegalScore": 100,
        "tags": ["Fraud Shop"],
        "sources": [{"name": "shop.example.com", "type": "Underground Market"}],
        "events": [],
        "malware": [],
        "threatActor": [],
        "evaluation": {
            "admiraltyCode": "A2",
            "credibility": 80,
            "reliability": 100,
            "severity": "red",
            "tlp": "amber",
            "ttl": 30,
        },
        "firstSeenAt": "2026-04-14T02:22:56.180Z",
        "lastSeenAt": "2026-04-14T02:22:56.180Z",
    }
    record.update(overrides)
    return record


@pytest.mark.parametrize("collection", ["hi/threat", "apt/threat"])
def test_a_report_relates_every_malware_family_it_names(collection):
    """malwareList[] is a list: every family is related and created."""
    record = _report(malwareList=[{"id": "m1", "name": "FamilyA"}, {"id": "m2", "name": "FamilyB"}])
    indicators = _from_raw(collection, [record], Settings(create_relationships=True))
    ip = _by_key(indicators)[("IP", "192.0.2.10")]
    assert ip["fields"]["gibmalwarename"] == "FamilyA, FamilyB"
    assert ip["fields"]["malwarefamily"] == ["FamilyA", "FamilyB"]
    assert [r["entityB"] for r in ip["relationships"]] == ["FamilyA", "FamilyB", "CrewOne"]
    assert _objects(indicators) == {("Malware", "FamilyA"), ("Malware", "FamilyB"), ("Threat Actor", "CrewOne")}


def test_a_cnc_relates_every_actor_and_an_actor_object_keeps_its_id_only_when_one_is_named():
    """threatActor[] and malwareList[] are arrays on malware/cnc."""
    record = _cnc(
        threatActor=[{"id": "t1", "name": "ActorOne", "isAPT": True}, {"id": "t2", "name": "ActorTwo", "isAPT": False}],
        malwareList=[{"id": "m1", "name": "FamilyA", "stixGuid": "g1"}, {"id": "m2", "name": "FamilyB", "stixGuid": "g2"}],
    )
    indicators = _from_raw("malware/cnc", [record], Settings(create_relationships=True))
    url = _by_key(indicators)[("URL", "http://c2.example.com/gate.php")]
    assert url["fields"]["gibthreatactorname"] == "ActorOne, ActorTwo"
    assert url["fields"]["gibthreatactorid"] == "t1, t2"
    # one APT flag cannot describe two actors
    assert "gibthreatactorisapt" not in url["fields"]
    assert url["fields"]["gibmalwarename"] == "FamilyA, FamilyB"
    assert [(r["entityBType"], r["entityB"]) for r in url["relationships"]] == [
        ("Malware", "FamilyA"),
        ("Malware", "FamilyB"),
        ("Threat Actor", "ActorOne"),
        ("Threat Actor", "ActorTwo"),
    ]
    actors = [i for i in indicators if i["type"] == "Threat Actor"]
    assert sorted(a["value"] for a in actors) == ["ActorOne", "ActorTwo"]
    assert all("gibthreatactorid" not in a["fields"] for a in actors)
    single = _cnc(threatActor=[{"id": "t1", "name": "ActorOne", "isAPT": True}])
    single_indicators = _from_raw("malware/cnc", [single], Settings(create_relationships=True))
    [actor] = [i for i in single_indicators if i["type"] == "Threat Actor"]
    assert actor["fields"]["gibthreatactorid"] == "t1"
    assert _by_key(single_indicators)[("URL", "http://c2.example.com/gate.php")]["fields"]["gibthreatactorisapt"] is True


def test_a_payment_detail_keeps_every_country():
    """country[] is a list of ISO codes."""
    [indicator] = _from_raw("compromised/spd", [_spd("IBAN", "GB00EXMP00000000000000", country=["GB", "DE"])])
    assert indicator["fields"]["gibspdcountry"] == "GB, DE"


def test_cnc_resolved_ips_keep_their_own_geo():
    """ipv4[] holds one object per resolved address, each with its own geo."""
    record = _cnc(
        ipv4=[
            {
                "ip": "203.0.113.1",
                "asn": "AS64496",
                "provider": "Alpha Hosting",
                "city": "Riga",
                "region": "Riga",
                "countryCode": "LV",
                "countryName": "Latvia",
            },
            {"ip": "203.0.113.2", "asn": "AS64511", "provider": "Beta Cloud", "city": None, "region": None, "countryCode": "DE"},
        ]
    )
    ips = {i["value"]: i["fields"] for i in _from_raw("malware/cnc", [record]) if i["type"] == "IP"}
    first, second = ips["203.0.113.1"], ips["203.0.113.2"]
    assert (first["asn"], first["organization"], first["geocountry"], first["geolocation"]) == (
        "AS64496",
        "Alpha Hosting",
        "Latvia",
        "Riga",
    )
    # the country code stands in for the missing name of this address, not the first address's name
    assert (second["asn"], second["organization"], second["geocountry"]) == ("AS64511", "Beta Cloud", "DE")
    assert "geolocation" not in second


def test_cnc_resolved_ipv6_addresses_are_ipv6_indicators_with_their_own_geo():
    """ipv6[] has the shape of ipv4[]: each resolved IPv6 address is an IPv6 indicator with its own geo,
    the verdict and the fields of the record's IPv4 addresses."""
    record = _cnc(
        ipv4=[{"ip": "203.0.113.1", "asn": "AS64496", "provider": "Alpha Hosting", "countryCode": "LV", "countryName": "Latvia"}],
        ipv6=[
            {
                "ip": "2001:db8::1",
                "asn": "AS64497",
                "provider": "Gamma Hosting",
                "city": "Tartu",
                "region": "Tartu",
                "countryCode": "EE",
                "countryName": "Estonia",
            },
            {"ip": "2001:db8::2", "asn": "AS64498", "provider": "Delta Cloud", "city": None, "region": None, "countryCode": "FI"},
        ],
        malwareList=[{"id": "m1", "name": "FamilyA"}],
        threatActor=[{"id": "t1", "name": "ActorOne", "isAPT": False}],
    )
    indicators = _by_key(_from_raw("malware/cnc", [record]))
    first, second = indicators[("IPv6", "2001:db8::1")], indicators[("IPv6", "2001:db8::2")]
    ipv4 = indicators[("IP", "203.0.113.1")]
    assert (first["fields"]["asn"], first["fields"]["organization"], first["fields"]["geocountry"]) == (
        "AS64497",
        "Gamma Hosting",
        "Estonia",
    )
    assert first["fields"]["geolocation"] == "Tartu"
    assert (second["fields"]["asn"], second["fields"]["organization"], second["fields"]["geocountry"]) == (
        "AS64498",
        "Delta Cloud",
        "FI",
    )
    assert "geolocation" not in second["fields"]
    for address in (first, second):
        assert address["score"] == ipv4["score"] == 3
        assert set(address["fields"]) - {"geolocation"} == set(ipv4["fields"]) - {"geolocation"}
        for field in ("gibid", "gibmalwarename", "gibthreatactorname", "firstseenbysource", "lastseenbysource", "tags"):
            assert address["fields"][field] == ipv4["fields"][field]


def _account(events: list[dict]) -> dict:
    return {
        "id": "a" * 40,
        "login": "user@example.com",
        "password": "example-password",
        "dateFirstSeen": "2026-09-20T00:00:00Z",
        "dateLastSeen": "2026-10-10T00:00:00Z",
        "service": {
            "domain": "mail.example.com",
            "ip": None,
            "url": "https://mail.example.com/login",
            "host": "mail.example.com",
        },
        "evaluation": {"admiraltyCode": "A2", "credibility": 80, "reliability": 100, "severity": "red", "tlp": "red", "ttl": 30},
        "events": events,
    }


def _event(cnc_url, cnc_domain, malware, actor, source, detected, cnc_ip=None) -> dict:
    return {
        "cnc": {
            "cnc": cnc_url or "",
            "domain": cnc_domain,
            "ipv4": {"ip": cnc_ip} if cnc_ip else None,
            "ipv6": None,
            "url": cnc_url,
        },
        "client": {"ipv4": {"ip": "192.0.2.77", "asn": "AS64500", "provider": "Example ISP"}, "ipv6": None},
        "source": {"id": "s1", "type": source, "idType": "bot"},
        "malware": {"id": "m", "name": malware},
        "threatActor": {"id": "t", "name": actor},
        "dateDetected": detected,
        "dateCompromised": detected,
    }


def test_an_account_cnc_takes_the_malware_actor_source_and_date_of_its_own_event():
    """malware, threatActor, source and dateDetected are per event."""
    record = _account(
        [
            _event(None, None, "FamilyA", "ActorOne", "TG Bot", "2026-09-20T00:00:00Z"),
            _event(
                "http://panel.example.com/gate.php",
                "panel.example.com",
                "FamilyB",
                "ActorTwo",
                "Botnet",
                "2026-10-10T00:00:00Z",
                cnc_ip="203.0.113.5",
            ),
        ]
    )
    indicators = _from_raw("compromised/account_group", [record], Settings(create_relationships=True))
    # The C&C IP is an indicator without the infected client's ASN and location.
    assert not {"asn", "geocountry", "organization"} & set(_by_key(indicators)[("IP", "203.0.113.5")]["fields"])
    for key in (("URL", "http://panel.example.com/gate.php"), ("Domain", "panel.example.com"), ("IP", "203.0.113.5")):
        indicator = _by_key(indicators)[key]
        fields = indicator["fields"]
        assert (fields["gibmalwarename"], fields["gibthreatactorname"], fields["gibsource"], fields["firstseenbysource"]) == (
            "FamilyB",
            "ActorTwo",
            "Botnet",
            "2026-10-10T00:00:00Z",
        )
        assert [r["entityB"] for r in indicator["relationships"]] == ["FamilyB", "ActorTwo"]
    assert _objects(indicators) == {("Malware", "FamilyB"), ("Threat Actor", "ActorTwo")}
    assert "192.0.2.77" not in {i["value"] for i in indicators}
    # an event without its own detection date takes the record's first-seen date
    undated = _account([_event("http://panel.example.com/gate.php", None, "FamilyB", "ActorTwo", "Botnet", None)])
    [url] = _from_raw("compromised/account_group", [undated])
    assert url["fields"]["firstseenbysource"] == "2026-09-20T00:00:00Z"


def _phishing_entry(url: str, objective, detected) -> dict:
    return {
        "id": url,
        "url": url,
        "title": "",
        "status": 7,
        "objective": objective,
        "source": ["urlscan"],
        "client": [],
        "domain": {"domain": "files.example.com"},
        "ip": {"ip": "198.51.100.10", "countryCode": "Default", "countryName": "Netherlands"},
        "date": {"added": detected, "blocked": None, "detected": detected},
        "phishingKit": [],
        "renderedUrls": [],
    }


def _phishing_group(brand: str = "Index of") -> dict:
    return {
        "id": "p" * 64,
        "domain": "files.example.com",
        "brand": brand,
        "objective": ["Index of", "Malware drop"],
        "phishing": [
            _phishing_entry("http://files.example.com/", ["Index of"], "2026-10-01T00:00:00+03:00"),
            _phishing_entry(
                "http://files.example.com/payload/invoice.zip", ["Malware drop", "Login harvest"], "2026-10-02T00:00:00Z"
            ),
            _phishing_entry("http://files.example.com/other", None, None),
        ],
        "ip": [{"ip": "198.51.100.10", "countryCode": "Default", "countryName": "Netherlands", "provider": "Example Hosting"}],
        "date": {
            "added": "0001-01-01T00:00:00+00:00",
            "detected": "0001-01-01T00:00:00+00:00",
            "updated": "2026-10-03T00:00:00Z",
            "blocked": None,
        },
        "threatActor": {"id": "", "name": "", "nameIndexed": "", "isAPT": False},
        "falsePositive": False,
        "whitelist": False,
        "evaluation": {"admiraltyCode": "C3", "credibility": 50, "reliability": 50, "severity": "red", "tlp": "amber", "ttl": 0},
    }


def test_a_phishing_url_takes_its_own_objective_and_detection_date():
    """Each phishing[] entry carries its own objective and detection date; the group's values stand in for an entry
    without them, and a year-1 date is no date."""
    urls = {i["value"]: i["fields"] for i in _from_raw("attacks/phishing_group", [_phishing_group()])}
    assert urls["http://files.example.com/"]["gibphishingobjectives"] == "Index of"
    assert urls["http://files.example.com/payload/invoice.zip"]["gibphishingobjectives"] == "Malware drop, Login harvest"
    assert urls["http://files.example.com/other"]["gibphishingobjectives"] == "Index of, Malware drop"
    assert urls["http://files.example.com/"]["firstseenbysource"] == "2026-10-01T00:00:00+03:00"
    assert urls["http://files.example.com/payload/invoice.zip"]["firstseenbysource"] == "2026-10-02T00:00:00Z"
    assert "firstseenbysource" not in urls["http://files.example.com/other"]
    assert all(fields["lastseenbysource"] == "2026-10-03T00:00:00Z" for fields in urls.values())


def test_a_year_one_date_never_reaches_a_date_field():
    """0001-01-01 is the API's zero-time placeholder."""
    record = {
        "id": "d" * 40,
        "cnc": {"url": "http://c2.example.com/panel", "domain": "c2.example.com", "ipv4": None},
        "target": {"ipv4": None},
        "dateBegin": "0001-01-01T00:00:00+00:00",
        "dateEnd": "2026-10-10T00:00:00Z",
    }
    for indicator in _from_raw("attacks/ddos", [record]):
        assert "firstseenbysource" not in indicator["fields"]
        assert indicator["fields"]["lastseenbysource"] == "2026-10-10T00:00:00Z"


def test_a_phishing_group_writes_no_empty_actor_and_no_brand_marker():
    """No empty actor is written, and the "Index of" and "Not specified" brand markers add no tag."""
    for marker in ("Index of", "Not specified"):
        for indicator in _from_raw("attacks/phishing_group", [_phishing_group(brand=marker)]):
            assert "gibthreatactorisapt" not in indicator["fields"]
            assert "gibphishingbrand" not in indicator["fields"]
            assert marker not in indicator["fields"]["tags"]
    [first, *_] = _from_raw("attacks/phishing_group", [_phishing_group(brand="Example Bank")])
    assert first["fields"]["gibphishingbrand"] == "Example Bank"
    assert "Example Bank" in first["fields"]["tags"]


@pytest.mark.parametrize(
    "value",
    [
        "upi://pay?pa=shop@examplebank&pn=Example Shop&cu=INR",
        "00020126360014BR.GOV.BCB.PIX0114+55000000000005204000053039865802BR5913Example Store6009Sao Paulo6304ABCD",
    ],
)
def test_a_qr_payment_string_with_a_space_is_a_payment_detail(value):
    """QR payment strings (PIX, UPI) carry payee names with spaces."""
    [indicator] = _from_raw("compromised/spd", [_spd("QR Payment String", value)])
    assert (indicator["type"], indicator["value"]) == ("GIB Suspicious Payment Detail", value)


def test_an_spd_email_is_keyed_on_its_lowercase_address():
    """value.value keeps the observed casing, value.email.value is lowercase."""
    record = _spd("Email", "Someone.Name@Example.com")
    record["value"]["email"] = {"value": "someone.name@example.com", "domain": "example.com"}
    [indicator] = _from_raw("compromised/spd", [record])
    assert indicator["value"] == "someone.name@example.com"


def _base58check(version: int, payload: bytes) -> str:
    """The base58check address of a version byte and a hash160 payload."""
    digits = "".join(c for c in string.digits + string.ascii_uppercase + string.ascii_lowercase if c not in "0OIl")
    raw = bytes([version]) + payload
    raw += hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    number, address = int.from_bytes(raw, "big"), ""
    while number:
        number, digit = divmod(number, 58)
        address = digits[digit] + address
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + address


# Base58check addresses of the patterned payloads 1..20 (pay-to-pubkey-hash) and 21..40 (pay-to-script-hash),
# and a bech32 one.
BTC_LEGACY = _base58check(0, bytes(range(1, 21)))
BTC_P2SH = _base58check(5, bytes(range(21, 41)))
BTC_BECH32 = "bc1qexample0wallet0address00000000000"


@pytest.mark.parametrize(
    "value, service_type, expected",
    [
        (BTC_LEGACY, "BTCLike", f"bitcoin:{BTC_LEGACY}"),
        (BTC_P2SH, "BTCLike", f"bitcoin:{BTC_P2SH}"),
        (BTC_BECH32, "BTCLike", f"bitcoin:{BTC_BECH32}"),
        # USDT on Omni is held at Bitcoin addresses: the shape decides, not the service type
        (BTC_P2SH, "USDT", f"bitcoin:{BTC_P2SH}"),
        (f"bitcoin:{BTC_LEGACY}", "BTCLike", f"bitcoin:{BTC_LEGACY}"),
        (f"BITCOIN:{BTC_LEGACY}", "BTCLike", f"bitcoin:{BTC_LEGACY}"),
        (f" {BTC_LEGACY} ", "BTCLike", f"bitcoin:{BTC_LEGACY}"),
        # a checksum that fails, a digit outside base58 or a number too large for 25 bytes is no Bitcoin address
        (BTC_LEGACY[:-1] + "a", "BTCLike", BTC_LEGACY[:-1] + "a"),
        (BTC_LEGACY[:-1] + "0", "BTCLike", BTC_LEGACY[:-1] + "0"),
        ("3" + "z" * 34, "BTCLike", "3" + "z" * 34),
        ("XexampleDashWalletAddress23456789A", "Dash", "XexampleDashWalletAddress23456789A"),
        ("TExampleTronWalletAddress23456789A", "TRC20", "TExampleTronWalletAddress23456789A"),
        ("0x" + "ab" * 20, "ERC20", "0x" + "ab" * 20),
    ],
)
def test_a_bitcoin_wallet_is_written_with_the_bitcoin_prefix(value, service_type, expected):
    """A Bitcoin address, a valid base58check one or a bc1 one, bare, prefixed or padded, is written bitcoin:<address>,
    as extraction writes a base58check wallet. A bare invalid address and other chains' addresses stay as they are."""
    [indicator] = _from_raw("compromised/spd", [_spd("Cryptocurrency Wallet", value, serviceType=service_type)])
    assert (indicator["type"], indicator["value"]) == ("Cryptocurrency Address", expected)
    assert indicator["rawJSON"]["value"] == expected


def test_only_a_crypto_wallet_takes_the_bitcoin_prefix():
    [indicator] = _from_raw("compromised/spd", [_spd("E-Wallet", BTC_LEGACY)])
    assert (indicator["type"], indicator["value"]) == ("GIB Suspicious Payment Detail", BTC_LEGACY)


def _kit(hash_: str, emails, first_seen: str) -> dict:
    return {
        "id": hash_,
        "hash": hash_,
        "seqUpdate": 1788219451511356,
        "dateDetected": first_seen,
        "dateFirstSeen": first_seen,
        "dateLastSeen": first_seen,
        "downloadedFrom": [{"date": first_seen, "url": "http://host.example.com/kit.zip", "domain": "host.example.com"}],
        "targetBrand": ["examplebrand"],
        "source": ["urlScanKit"],
        "path": f"https://tap.example.com/api/v2/malware/phishing_kit/{hash_}/file/{hash_}",
        "emails": emails,
        "telegramIds": [],
        "evaluation": {"admiraltyCode": "A1", "credibility": 90, "reliability": 90, "severity": "red", "tlp": "amber", "ttl": 30},
    }


def test_a_phishing_kit_emits_its_archive_hash_first():
    """The kit hash is the primary indicator; a kit without e-mails yields its hash alone."""
    recent = _kit("a" * 64, ["drop1@example.com"], "2026-09-01T10:12:00Z")
    older = _kit("b" * 64, None, "2018-03-09T22:19:59+00:00")
    indicators = _from_raw("attacks/phishing_kit", [recent, older])
    assert [(i["type"], i["value"], i["score"]) for i in indicators] == [
        ("File", "a" * 64, 2),
        ("Email", "drop1@example.com", 2),
        ("File", "b" * 64, 2),
    ]
    kit = indicators[0]["fields"]
    assert (kit["sha256"], kit["gibid"], kit["gibadmiraltycode"], kit["gibseverity"], kit["gibreliability"]) == (
        "a" * 64,
        "a" * 64,
        "A1",
        "red",
        90,
    )
    assert kit["firstseenbysource"] == "2026-09-01T10:12:00Z"


@pytest.mark.parametrize("collection", ["hi/threat", "apt/threat"])
def test_a_report_emits_ipv6_and_the_address_and_sender_of_an_email_message(collection):
    """params is {domain, ipv4[], ipv6[], ssl[], url} on network entries and {address, message, senderIp,
    serverIp} on email-message entries."""
    network = {
        "id": "1" * 40,
        "type": "network",
        "params": {"domain": "", "ipv4": [], "ipv6": ["2001:db8::10", "2001:db8[:][:]11"], "ssl": [], "url": ""},
        "dateFirstSeen": "2026-09-01T00:00:00Z",
        "dateLastSeen": "2026-09-02T00:00:00Z",
    }
    message = {
        "id": "2" * 40,
        "type": "email-message",
        "params": {"address": "phisher@example.com", "message": "", "senderIp": "198.51.100.5", "serverIp": "203.0.113.9"},
        "dateFirstSeen": "2026-09-03T00:00:00Z",
        "dateLastSeen": "2026-09-04T00:00:00Z",
    }
    other = {"id": "3" * 40, "type": "contact", "params": {"address": "someone@mail.example", "senderIp": "203.0.113.8"}}
    indicators = _by_key(_from_raw(collection, [_report(indicators=[network, message, other])]))
    assert set(indicators) == {
        ("IPv6", "2001:db8::10"),
        ("IPv6", "2001:db8::11"),
        ("Email", "phisher@example.com"),
        ("IP", "198.51.100.5"),
    }
    assert indicators[("IPv6", "2001:db8::10")]["fields"]["firstseenbysource"] == "2026-09-01T00:00:00Z"
    assert indicators[("Email", "phisher@example.com")]["fields"]["firstseenbysource"] == "2026-09-03T00:00:00Z"
    assert indicators[("IP", "198.51.100.5")]["fields"]["lastseenbysource"] == "2026-09-04T00:00:00Z"
    assert all(i["score"] == 3 and i["fields"]["gibthreatactorname"] == "CrewOne" for i in indicators.values())


def test_a_placeholder_or_blank_e_mail_is_no_indicator():
    """A kit or a report e-mail with braces or a blank stands for a value the record does not give; a payment
    string with blanks is a payment detail all the same."""
    kit = _kit("a" * 64, ["{operator_email}", "drop1 @example.com", "drop2@example.com"], "2026-09-01T10:12:00Z")
    assert [(i["type"], i["value"]) for i in _from_raw("attacks/phishing_kit", [kit]) if i["type"] == "Email"] == [
        ("Email", "drop2@example.com")
    ]
    message = {
        "id": "2" * 40,
        "type": "email-message",
        "params": {"address": "{{sender}}", "message": "", "senderIp": "198.51.100.5", "serverIp": ""},
    }
    assert set(_by_key(_from_raw("hi/threat", [_report(indicators=[message])]))) == {("IP", "198.51.100.5")}
    payment = "upi://pay?pa=shop@examplebank&pn=Example Shop&cu=INR"
    [indicator] = _from_raw("compromised/spd", [_spd("QR Payment String", payment)])
    assert (indicator["type"], indicator["value"]) == ("GIB Suspicious Payment Detail", payment)


@pytest.mark.parametrize("collection", ["hi/threat", "apt/threat"])
def test_a_report_file_with_only_a_sha512_is_kept(collection):
    """A report file entry with only a SHA-512 becomes a File indicator keyed by that hash, with its file name."""
    file_entry = {
        "id": "4" * 40,
        "type": "file",
        "params": {"hashes": {"md5": "", "sha1": "", "sha256": "", "sha512": "e" * 128}, "name": "only.bin", "size": 10},
        "dateFirstSeen": "2026-09-05T00:00:00Z",
    }
    [indicator] = _from_raw(collection, [_report(indicators=[file_entry])])
    assert (indicator["type"], indicator["value"]) == ("File", "e" * 128)
    assert (indicator["fields"]["sha512"], indicator["fields"]["gibfilename"]) == ("e" * 128, "only.bin")


@pytest.mark.parametrize(
    "common, expected",
    [
        (Settings(), "RED"),
        (Settings(use_tlp_from_source=False), "RED"),
        (Settings(tlp_color="GREEN"), "GREEN"),
        (Settings(tlp_color="GREEN", use_tlp_from_source=True), "RED"),
    ],
)
def test_an_indicator_keeps_its_record_tlp_unless_a_color_is_set_without_use_tlp_from_source(common, expected):
    """A TLP:RED report never becomes an indicator without TLP under the default settings: each record
    carries its own evaluation.tlp."""
    record = _report(evaluation={"admiraltyCode": "A1", "credibility": 90, "reliability": 90, "tlp": "red", "severity": "red"})
    [indicator] = _from_raw("hi/threat", [record], common)
    assert indicator["fields"]["trafficlightprotocol"] == expected


def test_an_unknown_tlp_is_logged_once_per_record(mocker):
    """The indicators of a report share its TLP: an unknown one is logged once per record, not once per indicator."""
    info = mocker.patch.object(GroupIB_TIA_Feed.demisto, "info")
    record = _report(evaluation={"tlp": "amber strict"})
    record["indicators"][0]["params"]["ipv4"] = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    indicators = _from_raw("hi/threat", [record])
    assert [i["fields"]["trafficlightprotocol"] for i in indicators] == ["RED", "RED", "RED"]
    assert [c.args[0] for c in info.call_args_list if "unknown TLP" in c.args[0]] == [
        "[IndicatorBuilder] unknown TLP 'amber strict': the indicator gets RED"
    ]


def test_a_defacer_handle_is_a_field_and_no_threat_actor():
    """threatActor.name is a pseudonymous grouping key, not an attribution."""
    record = {
        "id": "6" * 24,
        "url": "http://victim.example.com/index.html",
        "siteUrl": "http://victim.example.com/index.html",
        "targetDomain": "victim.example.com",
        "targetIp": {"ip": "198.51.100.20", "asn": "AS64500", "countryCode": "NL"},
        "threatActor": {"id": "h" * 40, "name": "handle-one", "isAPT": False, "country": None, "stixGuid": None},
        "date": "2026-10-01T00:00:00Z",
        "source": "aggregator.example.com",
        "evaluation": {
            "admiraltyCode": "B2",
            "credibility": 80,
            "reliability": 80,
            "severity": "green",
            "tlp": "amber",
            "ttl": 30,
        },
    }
    [indicator] = _from_raw("attacks/deface", [record], Settings(create_relationships=True, tags=("feed",)))
    assert (indicator["type"], indicator["value"]) == ("URL", "http://victim.example.com/index.html")
    assert (indicator["fields"]["gibthreatactorname"], indicator["fields"]["gibthreatactorid"]) == ("handle-one", "h" * 40)
    assert indicator["fields"]["tags"] == ["feed", "attacks/deface"]
    assert "relationships" not in indicator


def _listing(ip: str, port: int, anonymous: str, source: str, last_seen: str) -> dict:
    return {
        "id": ip,
        "seqUpdate": 1786415786354000,
        "dateFirstSeen": "2026-09-01T00:00:00Z",
        "dateLastSeen": last_seen,
        "dateDetected": "2026-09-01T00:00:00Z",
        "ipv4": {"ip": ip, "countryCode": "NL", "countryName": None, "region": None, "city": None, "asn": None, "provider": None},
        "port": port,
        "anonymous": anonymous,
        "type": "HTTP",
        "source": source,
        "sources": [source],
        "evaluation": {
            "admiraltyCode": "C3",
            "credibility": 50,
            "reliability": 50,
            "severity": "green",
            "tlp": "white",
            "ttl": 15,
        },
    }


def test_an_open_proxy_is_one_indicator_per_ip_with_its_latest_listing_and_every_port():
    """An address listed several times is one indicator with every port; the latest dateLastSeen gives its fields."""
    listings = [
        _listing("192.0.2.10", 8080, "1", "list-a.example.com", "2026-10-01T00:00:00Z"),
        _listing("192.0.2.10", 3128, "", "list-b.example.com", "2026-10-05T00:00:00Z"),
        _listing("192.0.2.11", 80, "1", "list-a.example.com", "2026-10-02T00:00:00Z"),
    ]
    for page in (listings, list(reversed(listings))):
        indicators = {i["value"]: i["fields"] for i in _from_raw("suspicious_ip/open_proxy", page)}
        assert set(indicators) == {"192.0.2.10", "192.0.2.11"}
        proxy = indicators["192.0.2.10"]
        assert (proxy["gibproxyport"], proxy["gibsource"], proxy["lastseenbysource"]) == (
            3128,
            "list-b.example.com",
            "2026-10-05T00:00:00Z",
        )
        assert proxy["gibproxyports"] == "3128, 8080"
        # the latest listing leaves anonymous empty: its empty value replaces the older listing's "1"
        assert proxy["gibproxyanonymous"] == ""
        assert (indicators["192.0.2.11"]["gibproxyport"], indicators["192.0.2.11"]["gibproxyanonymous"]) == (80, "1")


def test_a_socks_proxy_record_becomes_an_ip_with_its_country_code():
    record = {
        "id": "192.0.2.40",
        "seqUpdate": 17761987741592,
        "dateFirstSeen": "2026-04-13T00:00:00+00:00",
        "dateLastSeen": "2026-04-14T00:00:00+00:00",
        "dateDetected": "2026-04-13T00:00:00+00:00",
        "ipv4": {"ip": "192.0.2.40", "countryCode": "CN", "countryName": None, "region": None, "city": None, "asn": None},
        "evaluation": {
            "admiraltyCode": "A1",
            "credibility": 100,
            "reliability": 90,
            "tlp": "amber",
            "severity": "green",
            "ttl": 2,
        },
        "source": "proxy-harvester",
        "stixGuid": None,
        "bind": None,
        "portalLink": None,
    }
    [indicator] = _from_raw("suspicious_ip/socks_proxy", [record])
    fields = indicator["fields"]
    assert (indicator["type"], indicator["value"], indicator["score"]) == ("IP", "192.0.2.40", 2)
    assert (fields["geocountry"], fields["gibsource"], fields["gibadmiraltycode"], fields["trafficlightprotocol"]) == (
        "CN",
        "proxy-harvester",
        "A1",
        "AMBER",
    )
    assert fields["lastseenbysource"] == "2026-04-14T00:00:00+00:00"


def test_a_vpn_record_becomes_an_ip_tagged_with_its_products():
    record = {
        "id": "198.51.100.60",
        "seqUpdate": 17761987741593,
        "dateFirstSeen": "2026-09-01T00:00:00Z",
        "dateLastSeen": "2026-09-02T00:00:00Z",
        "ipv4": {"ip": "198.51.100.60", "asn": "AS64501", "countryCode": "SE", "countryName": None, "provider": None},
        "evaluation": {
            "admiraltyCode": "A2",
            "credibility": 80,
            "reliability": 90,
            "severity": "green",
            "tlp": "amber",
            "ttl": 2,
        },
        "source": "harvester-one",
        "sources": ["harvester-one", "harvester-two"],
        "names": ["Example VPN", "Example VPN Two"],
        "rules": ["VPN: Example VPN Two"],
        "types": ["commercial"],
    }
    [indicator] = _from_raw("suspicious_ip/vpn", [record], Settings(tags=("feed",)))
    fields = indicator["fields"]
    assert (indicator["type"], indicator["value"], indicator["score"]) == ("IP", "198.51.100.60", 2)
    assert (fields["asn"], fields["geocountry"], fields["gibsource"]) == ("AS64501", "SE", "harvester-one, harvester-two")
    assert fields["tags"] == ["feed", "suspicious_ip/vpn", "Example VPN", "Example VPN Two"]


def _vulnerability(**overrides) -> dict:
    record = {
        "id": "CVE-2099-10001",
        "type": "cve",
        "description": "An example flaw.",
        "datePublished": "2026-02-15T20:24:00+01:00",
        "dateModified": "2026-04-26T20:24:00+02:00",
        "cvss": {"score": 7.5, "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
        "mergedCvss": 9.8,
        "mergedCvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": {"epss": 0.20719, "percentile": 0.95595},
        "hasExploit": True,
        "softwareMixed": [{"softwareName": "Example Server", "softwareType": "software", "softwareVersion": "15.1.0"}],
        "evaluation": {
            "admiraltyCode": "A1",
            "credibility": 100,
            "reliability": 100,
            "tlp": "green",
            "severity": "red",
            "ttl": 30,
        },
    }
    record.update(overrides)
    return record


def test_a_cve_takes_the_merged_cvss_first_and_treats_a_zero_none_score_as_unknown():
    """mergedCvss is the score across CVSS versions; cvss.* is the legacy one."""
    [cve] = _from_raw("osi/vulnerability", [_vulnerability()])
    fields = cve["fields"]
    assert (cve["type"], cve["value"], cve["score"]) == ("CVE", "CVE-2099-10001", 3)
    assert (fields["cvss"], fields["gibcvssvector"], fields["gibmergedcvss"]) == (
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        9.8,
    )
    assert (fields["gibepsspercentile"], fields["gibhasexploit"], fields["published"]) == (
        0.95595,
        True,
        "2026-02-15T20:24:00+01:00",
    )
    assert "| Example Server | software | 15.1.0 |" in fields["gibsoftwaremixed"]
    [legacy] = _from_raw("osi/vulnerability", [_vulnerability(mergedCvss=None, mergedCvssVector=None)])
    assert (legacy["fields"]["cvss"], legacy["fields"]["gibcvssvector"]) == (7.5, "AV:N/AC:L/Au:N/C:P/I:P/A:P")
    [unknown] = _from_raw(
        "osi/vulnerability", [_vulnerability(cvss={"score": 0, "vector": "NONE"}, mergedCvss=0, mergedCvssVector=None)]
    )
    assert not {"cvss", "gibcvssvector", "gibmergedcvss"} & set(unknown["fields"])


def test_the_command_sets_the_tlp_as_fetch_does(mocker):
    portion = Parser({"count": 1, "items": [_spd("IBAN", "GB00EXMP00000000000000")], "seqUpdate": 1}, [], [])
    client = _feed_client()
    _mock_update_feed(mocker, client, side_effect=lambda **_kwargs: [portion])
    for params, expected in (
        ({}, "AMBER"),
        ({"tlp_color": "GREEN"}, "GREEN"),
        ({"tlp_color": "GREEN", "use_tlp_from_source": True}, "AMBER"),
    ):
        [table] = _get(client, {"collection": "compromised/spd", "limit": "5"}, params=params)
        assert table.raw_response[0]["trafficlightprotocol"] == expected


def test_the_command_table_of_a_cve_leaves_out_the_software_table(mocker):
    portion = Parser({"count": 1, "items": [_vulnerability()], "seqUpdate": 1}, [], [])
    client = _feed_client()
    _mock_update_feed(mocker, client, return_value=[portion])
    [table] = _get(client, {"collection": "osi/vulnerability", "limit": "5"})
    [row] = table.raw_response
    assert (row["type"], row["value"]) == ("CVE", "CVE-2099-10001")
    assert "gibsoftwaremixed" not in row
    assert "Example Server" not in table.readable_output


def _markdown_rows(markdown: str) -> list[dict]:
    lines = [line for line in markdown.splitlines() if line.startswith("|")]
    header = [cell.strip() for cell in lines[0].strip("|").split("|")]
    return [dict(zip(header, (cell.strip() for cell in line.strip("|").split("|")))) for line in lines[2:]]


@pytest.mark.parametrize("create_relationships", [False, True])
def test_the_command_table_shows_the_tlp(mocker, create_relationships):
    """The War Room table names the TLP of every indicator, the objects behind the relationships included."""
    record = _cnc(malwareList=[{"id": "m1", "name": "FamilyA"}])
    portion = Parser({"count": 1, "items": [record], "seqUpdate": 1}, [], [])
    client = _feed_client()
    _mock_update_feed(mocker, client, return_value=[portion])
    params = {"tlp_color": "GREEN", "create_relationships": create_relationships}
    tables = _get(client, {"collection": "malware/cnc", "limit": "10"}, params=params)
    rows = [row for table in tables for row in _markdown_rows(table.readable_output)]
    assert {row["type"] for row in rows} == ({"URL", "Domain", "Malware"} if create_relationships else {"URL", "Domain"})
    assert {row["trafficlightprotocol"] for row in rows} == {"GREEN"}


def test_a_tor_relay_takes_geo_and_as_from_its_consensus_entry():
    """A relay without ipv4.* geography takes its country and AS from nodes[].states[].data."""
    state = {
        "data": {
            "fingerprint": "F" * 40,
            "as": "AS64502",
            "asName": "Example Relay Hosting",
            "country": "de",
            "countryName": "Germany",
            "region": "Hesse",
        }
    }
    record = {
        "id": "192.0.2.50",
        "ipv4": {"ip": "192.0.2.50", "asn": None, "countryCode": None, "countryName": None, "region": None, "provider": None},
        "nodes": [{"createdAt": "2026-09-01T00:00:00", "states": [state]}],
        "source": "check.example.com",
        "dateFirstSeen": "2026-09-01T00:00:00Z",
        "dateLastSeen": "2026-09-02T00:00:00Z",
    }
    [indicator] = _from_raw("suspicious_ip/tor_node", [record])
    fields = indicator["fields"]
    assert (fields["asn"], fields["organization"], fields["geocountry"], fields["geolocation"]) == (
        "AS64502",
        "Example Relay Hosting",
        "Germany",
        "Hesse",
    )
    with_top_level = dict(record, ipv4={"ip": "192.0.2.50", "asn": "AS64503", "countryName": "France"})
    [top] = _from_raw("suspicious_ip/tor_node", [with_top_level])
    assert (top["fields"]["asn"], top["fields"]["geocountry"]) == ("AS64503", "France")


def test_a_tor_relay_takes_geo_and_as_from_its_newest_consensus_state():
    """A relay's consensus history accumulates states; the most recently seen one says where it is now,
    as in the incidents integration, whatever order nodes[] and states[] arrive in."""

    def state(seen: str, asn: str, name: str, country: str) -> dict:
        return {"data": {"as": asn, "asName": name, "countryName": country, "region": "", "dateLastSeen": seen}}

    record = {
        "id": "192.0.2.51",
        "ipv4": {"ip": "192.0.2.51", "asn": None, "countryCode": None, "countryName": None, "region": None},
        "nodes": [
            {"states": [state("2025-01-01T00:00:00+00:00", "AS64504", "Old Hosting", "Germany")]},
            {
                "states": [
                    state("2026-09-30T00:00:00+00:00", "AS64505", "Current Hosting", "France"),
                    state("2025-06-01T00:00:00+00:00", "AS64506", "Middle Hosting", "Spain"),
                ]
            },
        ],
        "source": "check.example.com",
        "dateFirstSeen": "2025-01-01T00:00:00Z",
        "dateLastSeen": "2026-09-30T00:00:00Z",
    }
    [indicator] = _from_raw("suspicious_ip/tor_node", [record])
    fields = indicator["fields"]
    assert (fields["asn"], fields["organization"], fields["geocountry"]) == ("AS64505", "Current Hosting", "France")


def test_a_cnc_types_an_ipv6_host_dedups_its_ip_and_dates_first_seen_by_detection_when_undated():
    """cnc is polymorphic: domain may hold an address."""
    v6 = _cnc(cnc="2001:db8::77", domain="2001:db8::77", url="")
    assert [(i["type"], i["value"]) for i in _from_raw("malware/cnc", [v6])] == [("IPv6", "2001:db8::77")]
    ip_host = _cnc(
        cnc="203.0.113.99",
        domain="203.0.113.99",
        url="",
        ipv4=[
            {
                "ip": "203.0.113.99",
                "asn": "AS64502",
                "provider": "Example Hosting",
                "countryCode": "US",
                "countryName": "United States",
            }
        ],
    )
    [ip] = _from_raw("malware/cnc", [ip_host])
    assert (ip["type"], ip["value"], ip["fields"]["asn"], ip["fields"]["geocountry"]) == (
        "IP",
        "203.0.113.99",
        "AS64502",
        "United States",
    )
    assert ip["fields"]["firstseenbysource"] == "2026-08-18T00:00:00Z"
    [undated] = _from_raw("malware/cnc", [_cnc(url="", dateFirstSeen=None)])
    assert undated["fields"]["firstseenbysource"] == "2026-08-20T11:03:52Z"
    dated = _by_key(_from_raw("malware/cnc", [_cnc()]))
    assert {key: indicator["fields"]["firstseenbysource"] for key, indicator in dated.items()} == {
        ("URL", "http://c2.example.com/gate.php"): "2026-08-18T00:00:00Z",
        ("Domain", "c2.example.com"): "2026-08-18T00:00:00Z",
    }


def test_scanner_categories_become_one_tag_per_category_whatever_the_case_or_separator():
    """categories[] arrives as Brute-Force and brute-force: case and separators do not split a category."""
    record = {
        "id": "198.51.100.5",
        "ipv4": {"ip": "198.51.100.5"},
        "categories": ["Brute-Force", "brute-force", "Exploit Probe", "exploit-probe", "Port Scan"],
    }
    [indicator] = _from_raw("suspicious_ip/scanner", [record])
    assert indicator["fields"]["tags"] == ["suspicious_ip/scanner", "brute-force", "exploit-probe", "port-scan"]


def test_a_list_field_never_carries_none_text():
    out = IndicatorBuilder._flattened([{"fields": {"gibsource": [None, "honeypot", ""]}}])[0]
    assert out["fields"]["gibsource"] == "honeypot"


def test_an_element_object_never_becomes_an_indicator_value():
    """An element that is an object is skipped and its siblings are kept."""
    record = {
        "id": "7" * 40,
        "ip": [{"ip": "192.0.2.30", "riskScore": 50}, "192.0.2.31"],
        "domain": None,
        "url": None,
        "hash": None,
    }
    assert [(i["type"], i["value"]) for i in _from_raw("ioc/common", [record])] == [("IP", "192.0.2.31")]


def _fetch_pages(mocker, pages: dict, collections: list[str], settings: Settings | None = None) -> list[dict]:
    client = _feed_client()
    _mock_update_feed(
        mocker,
        client,
        side_effect=lambda **kwargs: [Parser(pages[kwargs["collection_name"]], [], [])],
    )
    _, indicators = _fetch(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        indicator_collections=collections,
        requests_count=1,
        settings=settings,
    )
    return indicators


def test_one_value_from_several_collections_is_one_indicator_with_the_highest_verdict(mocker):
    """A value several collections report in one run is one indicator with the highest verdict, and the DDoS victim
    entry never replaces an IP."""
    address = "203.0.113.50"
    pages = {
        "malware/cnc": {"count": 1, "seqUpdate": 11, "items": [_cnc(domain=None, url=None, cnc=address, ipv4=[{"ip": address}])]},
        "suspicious_ip/scanner": {
            "count": 1,
            "seqUpdate": 12,
            "items": [{"id": address, "ipv4": {"ip": address}, "categories": ["Port Scan"], "evaluation": {"tlp": "white"}}],
        },
        "attacks/ddos": {"count": 1, "seqUpdate": 13, "items": [{"id": "d1", "target": {"ipv4": {"ip": address}}}]},
    }
    for order in (
        ["attacks/ddos", "suspicious_ip/scanner", "malware/cnc"],
        ["malware/cnc", "suspicious_ip/scanner", "attacks/ddos"],
    ):
        victims = _filtered("attacks/ddos: kinds = GIB Victim IP")
        [entry] = [i for i in _fetch_pages(mocker, pages, order, victims) if i["value"] == address]
        assert (entry["type"], entry["score"], entry["rawJSON"]["score"], entry["fields"]["gibcollection"]) == (
            "IP",
            3,
            3,
            "malware/cnc",
        )
        assert {"malware/cnc", "suspicious_ip/scanner", "port-scan"} <= set(entry["fields"]["tags"])


def test_an_object_takes_the_most_restrictive_tlp_of_the_records_naming_it(mocker):
    green = _report(id="g" * 40, malwareList=[{"name": "FamilyA"}], evaluation={"tlp": "green"})
    red = _report(id="r" * 40, malwareList=[{"name": "FamilyA"}], evaluation={"tlp": "red"})
    red["indicators"][0]["params"]["ipv4"] = ["192.0.2.11"]
    for records in ([green, red], [red, green]):
        [family] = [i for i in _from_raw("hi/threat", records, Settings(create_relationships=True)) if i["type"] == "Malware"]
        assert (family["fields"]["trafficlightprotocol"], family["rawJSON"]["trafficlightprotocol"]) == ("RED", "RED")
    pages = {
        "hi/threat": {"count": 1, "seqUpdate": 1, "items": [green]},
        "apt/threat": {"count": 1, "seqUpdate": 1, "items": [red]},
    }
    indicators = _fetch_pages(mocker, pages, ["hi/threat", "apt/threat"], Settings(create_relationships=True))
    [family] = [i for i in indicators if i["type"] == "Malware"]
    assert family["fields"]["trafficlightprotocol"] == "RED"


def test_on_an_equal_verdict_the_later_entry_of_a_value_wins():
    """A relay read again later in the run keeps its newer dates."""
    early = {"id": "192.0.2.60", "ipv4": {"ip": "192.0.2.60"}, "dateLastSeen": "2026-10-01T00:00:00Z", "source": "early"}
    late = dict(early, dateLastSeen="2026-10-05T00:00:00Z", source="late")
    [entry] = _from_raw("suspicious_ip/tor_node", [early, late])
    assert (entry["fields"]["lastseenbysource"], entry["fields"]["gibsource"]) == ("2026-10-05T00:00:00Z", "late")
    assert entry["rawJSON"]["lastseenbysource"] == "2026-10-05T00:00:00Z"


def test_one_ip_named_by_two_collections_relates_and_lists_the_families_and_actors_of_both(mocker):
    """The merged entry of a value keeps what every collection says of it: the relationships, and the
    malware and actor names in the Group-IB fields as in the multi-select."""
    address = "203.0.113.70"
    report = _report(malwareList=[{"id": "m1", "name": "FamilyA"}])
    report["indicators"][0]["params"]["ipv4"] = [address]
    cnc = _cnc(
        domain=None,
        url=None,
        cnc=address,
        ipv4=[{"ip": address}],
        malwareList=[{"id": "m2", "name": "FamilyB"}],
        threatActor=[{"id": "t2", "name": "ActorTwo", "isAPT": True}],
    )
    pages = {
        "hi/threat": {"count": 1, "seqUpdate": 21, "items": [report]},
        "malware/cnc": {"count": 1, "seqUpdate": 22, "items": [cnc]},
    }
    indicators = _fetch_pages(mocker, pages, ["hi/threat", "malware/cnc"], Settings(create_relationships=True))
    [entry] = [i for i in indicators if i["value"] == address]
    assert {(r["entityBType"], r["entityB"]) for r in entry["relationships"]} == {
        ("Malware", "FamilyA"),
        ("Malware", "FamilyB"),
        ("Threat Actor", "CrewOne"),
        ("Threat Actor", "ActorTwo"),
    }
    fields = entry["fields"]
    assert set(fields["malwarefamily"]) == {"FamilyA", "FamilyB"}
    assert fields["gibmalwarename"] == ", ".join(fields["malwarefamily"])
    assert set(fields["gibthreatactorname"].split(", ")) == {"CrewOne", "ActorTwo"}
    assert set(fields["gibthreatactorid"].split(", ")) == {"a" * 40, "t2"}
    assert "gibthreatactorisapt" not in fields
    assert entry["rawJSON"] == {"value": address, "type": "IP", **fields, "score": 3}


def test_one_ip_from_both_ioc_collections_lists_the_threats_of_both(mocker):
    """threatList[] attributes the record: the merged entry names the threats of both records in GIB
    Threat Name as in its tags."""
    address = "192.0.2.77"
    common = {
        "id": "8" * 40,
        "ip": [address],
        "dateLastSeen": "2026-10-01T00:00:00Z",
        "malwareList": [{"name": "FamilyA"}],
        "threatList": [{"name": "ThreatOne"}],
    }
    primary = {
        "id": "9" * 40,
        "type": "network",
        "ip": [{"ip": address, "riskScore": 90}],
        "domain": [],
        "url": [],
        "dateLastSeen": "2026-10-02T00:00:00Z",
        "malwareList": [{"name": "FamilyB", "aliases": None}],
        "threatList": [{"name": "ThreatTwo", "title": ""}],
        "evaluation": {"admiraltyCode": "C3", "credibility": 60, "reliability": 60, "TLP": "TLP:AMBER", "TTL": 365},
    }
    pages = {
        "ioc/common": {"count": 1, "seqUpdate": 31, "items": [common]},
        "ioc/primary": {"count": 1, "seqUpdate": 32, "items": [primary]},
    }
    for order in (["ioc/common", "ioc/primary"], ["ioc/primary", "ioc/common"]):
        [entry] = [i for i in _fetch_pages(mocker, pages, order) if i["value"] == address]
        fields = entry["fields"]
        assert set(fields["gibthreatname"].split(", ")) == {"ThreatOne", "ThreatTwo"}
        assert {"ThreatOne", "ThreatTwo"} <= set(fields["tags"])
        assert entry["rawJSON"]["gibthreatname"] == fields["gibthreatname"]


class _CollectionServer:
    """One _MillisecondServer per collection."""

    def __init__(self, servers: dict[str, _MillisecondServer]):
        self.servers = servers

    def create_update_generator(self, collection_name, request_params, sequpdate=None, rate_limit_delay=None):
        return self.servers[collection_name].create_update_generator(collection_name, request_params, sequpdate, rate_limit_delay)


@pytest.mark.parametrize("newer_first", [True, False])
@pytest.mark.parametrize("with_cnc", [False, True])
def test_an_open_proxy_listed_on_two_pages_keeps_its_latest_listing_and_every_port(mocker, newer_first, with_cnc):
    """Ids repeat between consecutive pages too; keep the latest dateLastSeen. A C&C entry of the same
    address keeps its verdict and collection."""
    mocker.patch.object(GroupIB_TIA_Feed.time, "sleep")
    newer = dict(_listing("192.0.2.90", 3128, "", "list-b.example.com", "2026-10-05T00:00:00Z"))
    older = dict(_listing("192.0.2.90", 8080, "1", "list-a.example.com", "2026-10-01T00:00:00Z"))
    first, last = (newer, older) if newer_first else (older, newer)
    first["seqUpdate"], last["seqUpdate"] = 11000, 13000
    other = dict(_listing("192.0.2.91", 80, "", "list-a.example.com", "2026-10-02T00:00:00Z"), seqUpdate=12000)
    servers = {"suspicious_ip/open_proxy": _MillisecondServer([first, other, last])}
    collections = ["suspicious_ip/open_proxy"]
    if with_cnc:
        servers["malware/cnc"] = _MillisecondServer([_cnc(domain=None, url=None, cnc="192.0.2.90", ipv4=[{"ip": "192.0.2.90"}])])
        collections = ["malware/cnc", "suspicious_ip/open_proxy"]
    client = _feed_client()
    client.poller = _CollectionServer(servers)
    _, indicators = _fetch(
        client=client,
        last_run={"last_fetch": {collection: 10999 for collection in collections}},
        first_fetch_time="3 days",
        indicator_collections=collections,
        requests_count=5,
        limit=2,
    )
    assert servers["suspicious_ip/open_proxy"].asked == [10999, 11999, 12999]
    [proxy] = [i for i in indicators if i["value"] == "192.0.2.90"]
    fields = proxy["fields"]
    assert (fields["gibproxyport"], fields["gibproxyanonymous"], fields["gibproxyports"]) == (3128, "", "3128, 8080")
    if with_cnc:
        assert (proxy["score"], fields["gibcollection"]) == (3, "malware/cnc")
    else:
        assert (fields["gibsource"], fields["lastseenbysource"]) == ("list-b.example.com", "2026-10-05T00:00:00Z")


def _command_entries(mocker, collection: str, pages: list[list[dict]], limit: str = "10") -> list[dict]:
    """The entries gibti-get-indicators shows for the pages of records the update feed serves in turn."""
    client = _feed_client()
    mocker.patch.object(client, "hunting_rules_collections", return_value=frozenset())
    portions = [Parser({"count": len(items), "items": items, "seqUpdate": n}, [], []) for n, items in enumerate(pages, start=1)]
    _mock_update_feed(mocker, client, return_value=portions)
    tables = _get(client, {"collection": collection, "limit": limit}, params={})
    return [entry for table in tables for entry in table.raw_response]


@pytest.mark.parametrize("one_page", [False, True])
def test_get_indicators_merges_a_value_a_later_page_names_again(mocker, one_page):
    """The entries of one value are merged whichever page holds them: the most restrictive TLP and every family."""
    address = "192.0.2.12"
    green = _report(id="g" * 40, malwareList=[{"name": "FamGreen"}], evaluation={"tlp": "green"})
    red = _report(id="r" * 40, malwareList=[{"name": "FamRed"}], evaluation={"tlp": "red"})
    for record in (green, red):
        record["indicators"][0]["params"]["ipv4"] = [address]
    entries = _command_entries(mocker, "hi/threat", [[green, red]] if one_page else [[green], [red]])
    [entry] = [entry for entry in entries if entry["value"] == address]
    assert entry["trafficlightprotocol"] == "RED"
    assert set(entry["gibmalwarename"].split(", ")) == {"FamGreen", "FamRed"}


@pytest.mark.parametrize("one_page", [False, True])
def test_get_indicators_shows_an_open_proxy_of_two_pages_with_its_latest_listing_and_every_port(mocker, one_page):
    older = _listing("192.0.2.93", 8080, "1", "list-a.example.com", "2026-10-01T00:00:00Z")
    newer = _listing("192.0.2.93", 3128, "", "list-b.example.com", "2026-10-05T00:00:00Z")
    entries = _command_entries(mocker, "suspicious_ip/open_proxy", [[older, newer]] if one_page else [[older], [newer]])
    [entry] = [entry for entry in entries if entry["value"] == "192.0.2.93"]
    assert (entry["gibproxyport"], entry["gibproxyports"], entry["gibproxyanonymous"]) == (3128, "3128, 8080", "")


def test_get_indicators_counts_each_value_once_against_the_limit(mocker):
    """A value named again does not count against the limit, and a value past the limit is not shown."""
    first = _listing("192.0.2.21", 80, "", "list-a.example.com", "2026-10-01T00:00:00Z")
    others = [_listing(ip, 80, "", "list-a.example.com", "2026-10-01T00:00:00Z") for ip in ("192.0.2.22", "192.0.2.23")]
    pages = [[first], [dict(first, port=8080), *others]]
    entries = _command_entries(mocker, "suspicious_ip/open_proxy", pages, limit="2")
    assert {entry["value"]: entry["gibproxyports"] for entry in entries} == {"192.0.2.21": "80, 8080", "192.0.2.22": "80"}


def test_get_indicators_reads_on_while_a_page_names_only_collected_values(mocker):
    """A page that names a collected value again brings the limit no closer: the next page is read."""
    first = _listing("192.0.2.41", 80, "", "list-a.example.com", "2026-10-01T00:00:00Z")
    other = _listing("192.0.2.42", 80, "", "list-a.example.com", "2026-10-01T00:00:00Z")
    parse = mocker.patch.object(Parser, "parse_portion", autospec=True, side_effect=Parser.parse_portion)
    entries = _command_entries(mocker, "suspicious_ip/open_proxy", [[first], [dict(first, port=8080)], [other]], limit="2")
    assert {entry["value"]: entry["gibproxyports"] for entry in entries} == {"192.0.2.41": "80, 8080", "192.0.2.42": "80"}
    assert parse.call_count == 3


def test_get_indicators_reads_no_page_after_the_one_that_reaches_the_limit(mocker):
    listings = [_listing(f"192.0.2.{n}", 80, "", "list-a.example.com", "2026-10-01T00:00:00Z") for n in (51, 52, 53, 54)]
    parse = mocker.patch.object(Parser, "parse_portion", autospec=True, side_effect=Parser.parse_portion)
    entries = _command_entries(mocker, "suspicious_ip/open_proxy", [listings[:2], listings[2:3], listings[3:]], limit="2")
    assert sorted(entry["value"] for entry in entries) == ["192.0.2.51", "192.0.2.52"]
    assert parse.call_count == 1


@pytest.mark.parametrize("proxy_first", [True, False])
def test_an_open_proxy_listing_and_a_scanner_entry_of_one_ip_merge_by_collection_order(mocker, proxy_first):
    """Two entries are compared by dateLastSeen only when both are open proxy listings. A scanner entry of the
    same address has the same verdict: the tags of both collections are kept, the collection read later wins the
    other fields both write, and the proxy fields stay."""
    address = "192.0.2.95"
    listing = dict(_listing(address, 3128, "", "list-b.example.com", "2026-10-05T00:00:00Z"), seqUpdate=41)
    scanner = {
        "id": address,
        "seqUpdate": 42,
        "dateFirstSeen": "2026-08-01T00:00:00Z",
        "dateLastSeen": "2026-09-01T00:00:00Z",
        "ipv4": {"ip": address, "countryCode": "NL", "countryName": None, "region": None, "city": None, "asn": None},
        "ipv6": None,
        "evaluation": {"admiraltyCode": "C3", "credibility": 50, "reliability": 50, "tlp": "white", "severity": "green"},
        "categories": ["Port Scan"],
        "sources": ["scanner-source.example.com"],
    }
    pages = {
        "suspicious_ip/open_proxy": {"count": 1, "seqUpdate": 41, "items": [listing]},
        "suspicious_ip/scanner": {"count": 1, "seqUpdate": 42, "items": [scanner]},
    }
    order = ["suspicious_ip/open_proxy", "suspicious_ip/scanner"]
    [entry] = [i for i in _fetch_pages(mocker, pages, order if proxy_first else order[::-1]) if i["value"] == address]
    fields = entry["fields"]
    winner = (
        ("suspicious_ip/scanner", "2026-09-01T00:00:00Z", "scanner-source.example.com")
        if proxy_first
        else ("suspicious_ip/open_proxy", "2026-10-05T00:00:00Z", "list-b.example.com")
    )
    assert (entry["score"], fields["gibcollection"], fields["lastseenbysource"], fields["gibsource"]) == (2, *winner)
    assert (fields["gibproxyport"], fields["gibproxyports"], fields["gibproxyanonymous"]) == (3128, "3128", "")
    assert {"suspicious_ip/open_proxy", "suspicious_ip/scanner", "port-scan"} <= set(fields["tags"])


# Observables a record holds under a key of each indicator type. An address under a domain key is emitted as
# an IP or IPv6 indicator and an IPv6 address under an IP key as an IPv6 one, so those keys hold both.
SAMPLE_OBSERVABLES = {
    "URL": ["https://example.com/path"],
    "Domain": ["example.com", "192.0.2.10", "2001:db8::10"],
    "IP": ["192.0.2.11", "2001:db8::11"],
    "IPv6": ["2001:db8::12"],
    "File": ["a" * 64],
    "Email": ["user@example.com"],
    "CVE": ["CVE-2099-0001"],
}


def _fields_the_feed_writes() -> dict[tuple[str, str], set[str]]:
    """(indicator type, field) -> the collections that write it. Each observable key of a collection gets a
    record of its own, in which every parser key holds a value and only that key holds observables."""
    written: dict[tuple[str, str], set[str]] = {}
    for collection, spec in COLLECTIONS.items():
        for key, type_spec in spec.types.items():
            # A type chosen per record is tried with every value of its map and with none.
            choices = [*type_spec["map"], None] if isinstance(type_spec, dict) else [None]
            for choice in choices:
                record: dict[str, Any] = {
                    name: dict.fromkeys(path, ["text"]) if isinstance(path, dict) else "text"
                    for name, path in spec.parser_mapping.items()
                }
                record.update(dict.fromkeys(spec.types))
                if isinstance(type_spec, dict):
                    record[type_spec["field"]] = choice
                indicator_type = IndicatorBuilder._resolve_type(type_spec, record)
                record[key] = SAMPLE_OBSERVABLES.get(str(indicator_type), [f"{indicator_type} value"])
                if key in spec.element_types:
                    record[spec.element_type_key] = [spec.element_types[key]] * len(record[key])
                builder = IndicatorBuilder(collection, Settings(create_relationships=True))
                for indicator in builder.build([record]):
                    for field in indicator["fields"]:
                        written.setdefault((indicator["type"], field), set()).add(collection)
    return written


def test_every_field_the_feed_writes_is_associated_with_the_indicator_type():
    """Every field the feed writes is a platform field or a pack field associated with the indicator type it is written to."""
    fields_dir = os.path.join(realpath, "..", "..", "IndicatorFields")
    fields = {}
    for name in sorted(os.listdir(fields_dir)):
        with open(os.path.join(fields_dir, name)) as handle:
            field = load(handle)
        fields[field["cliName"]] = field
    written = _fields_the_feed_writes()
    assert {"IP", "IPv6", "Email", "Cryptocurrency Address", "Malware", "Threat Actor"} <= {pair[0] for pair in written}

    def associated(field: str, indicator_type: str) -> bool:
        if field not in fields:
            return not field.startswith("gib")  # a platform field
        return fields[field].get("associatedToAll") is True or indicator_type in (fields[field].get("associatedTypes") or [])

    lost = sorted(
        (item_type, field, sorted(found)) for (item_type, field), found in written.items() if not associated(field, item_type)
    )
    assert lost == []


def test_a_start_cursor_of_one_is_the_collection_start_and_the_collection_waits(mocker):
    """seqUpdate 1 is the first update position: read from it, the feed would start at the collection's oldest
    record. The collection waits for a cursor of the date instead."""
    feed = _UpdateFeed(start_cursors={"ioc/primary": 1, "attacks/ddos": 5})
    health = mocker.patch.object(GroupIB_TIA_Feed.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "error")
    next_run, _ = _fetch(
        client=feed.client(),
        last_run={},
        first_fetch_time="2026-03-01",
        indicator_collections=["ioc/primary", "attacks/ddos"],
        requests_count=1,
    )
    [call] = health.call_args_list
    assert "ioc/primary is not fetched yet: sequence_list answered 1 for 2026-03-01, the start of the collection" in call.args[0]
    assert feed.sent_to("ioc/primary/updated") == []
    assert next_run["last_fetch"]["ioc/primary"] is None


def test_get_indicators_by_id_reads_every_listing_of_an_open_proxy():
    """One address can have several listings: the lookup by id asks for every listing of the address."""
    from unittest.mock import MagicMock

    client = MagicMock()
    client.search.return_value = iter([])
    with pytest.raises(DemistoException, match="No record with id '198.51.100.9'"):
        _get(client, {"collection": "suspicious_ip/open_proxy", "id": "198.51.100.9"})
    client.search.assert_called_once_with(
        "suspicious_ip/open_proxy",
        query="198.51.100.9",
        limit=GroupIB_TIA_Feed.TICollections.get_page_limit("suspicious_ip/open_proxy"),
    )
    assert GroupIB_TIA_Feed.TICollections.get_page_limit("suspicious_ip/open_proxy") > 1


def test_the_deprecated_gibtia_alias_runs_gibti_get_indicators_and_warns(mocker):
    """gibtia-get-indicators is the deprecated name of gibti-get-indicators: it runs the command, and the War
    Room says which name to use."""
    params = {"url": "https://example.com", "credentials": {"identifier": "u", "password": "p"}}
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "params", return_value=params)
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "command", return_value="gibtia-get-indicators")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "args", return_value={"collection": "malware/cnc", "id": "c" * 40})
    mocker.patch.object(Client, "record", return_value=Parser({"count": 1, "items": [_cnc()], "seqUpdate": 1}, [], []))
    warning = mocker.patch.object(GroupIB_TIA_Feed, "return_warning")
    results = mocker.patch.object(GroupIB_TIA_Feed, "return_results")
    error = mocker.patch.object(GroupIB_TIA_Feed, "return_error")
    GroupIB_TIA_Feed.main()
    error.assert_not_called()
    warning.assert_called_once_with(
        "Command 'gibtia-get-indicators' is deprecated. Use 'gibti-get-indicators' in your playbooks and scripts instead.",
        exit=False,
    )
    [tables] = results.call_args.args
    assert {table.raw_response[0]["type"] for table in tables} == {"URL", "Domain"}
    assert "http://c2.example.com/gate.php" in tables[0].readable_output


def test_a_blank_scanner_category_makes_no_tag():
    parsed = {"id": "s", "ipv4_ip": "198.51.100.6", "categories": ["Brute-Force", " ", ""]}
    [indicator] = _build("suspicious_ip/scanner", parsed)
    assert indicator["fields"]["tags"] == ["suspicious_ip/scanner", "brute-force"]


@pytest.mark.parametrize("first_fetch", ["", "   ", None])
def test_an_empty_first_fetch_starts_three_days_back(first_fetch):
    """An empty Indicator first fetch reads as 3 days, the default for fetch-indicators and gibti-get-indicators."""
    params = {"indicators_first_fetch": first_fetch}
    assert GroupIB_TIA_Feed.Settings.from_params(params).first_fetch == "3 days"


@pytest.mark.parametrize(
    "name, label", [("requests_count", "Number of requests per collection"), ("limit", "Limit (items per request)")]
)
def test_a_count_setting_that_is_not_a_whole_number_is_named(name, label):
    with pytest.raises(DemistoException, match=re.escape(f"Invalid '{label}' value: expected a whole number, got 'many'")):
        GroupIB_TIA_Feed.Settings.from_params({name: "many"})


@pytest.mark.parametrize(
    "name, label", [("requests_count", "Number of requests per collection"), ("limit", "Limit (items per request)")]
)
def test_a_negative_count_setting_is_refused(name, label):
    with pytest.raises(DemistoException, match=re.escape(f"'{label}' must be zero or positive.")):
        GroupIB_TIA_Feed.Settings.from_params({name: "-1"})


def test_a_refused_request_is_reported_without_a_traceback(mocker):
    """An API refusal is reported with its own message as the error, without a traceback."""
    params = {"url": "https://example.com", "credentials": {"identifier": "u", "password": "p"}}
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "params", return_value=params)
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "command", return_value="test-module")
    mocker.patch.object(GroupIB_TIA_Feed.TIPoller, "send_request", side_effect=ConnectionException("HTTP 401: Bad Credentials."))
    error = mocker.patch.object(GroupIB_TIA_Feed, "return_error")
    GroupIB_TIA_Feed.main()
    [message] = error.call_args.args
    assert message.endswith("Error: HTTP 401: Bad Credentials.")
    assert "Traceback" not in message


def test_a_cnc_named_by_two_events_carries_the_attribution_of_both():
    """The same C&C in two events of one record: its malware, actors and sources are those of every event naming
    it, and its detection date that of the first."""
    record = _account(
        [
            _event(
                "http://panel.example.com/gate.php", "panel.example.com", "FamilyA", "ActorOne", "TG Bot", "2026-09-20T00:00:00Z"
            ),
            _event(
                "http://panel.example.com/gate.php", "panel.example.com", "FamilyB", "ActorTwo", "Botnet", "2026-10-10T00:00:00Z"
            ),
        ]
    )
    indicators = _from_raw("compromised/account_group", [record], Settings(create_relationships=True))
    for key in (("URL", "http://panel.example.com/gate.php"), ("Domain", "panel.example.com")):
        indicator = _by_key(indicators)[key]
        fields = indicator["fields"]
        assert (fields["gibmalwarename"], fields["gibthreatactorname"], fields["gibsource"]) == (
            "FamilyA, FamilyB",
            "ActorOne, ActorTwo",
            "TG Bot, Botnet",
        )
        assert fields["firstseenbysource"] == "2026-09-20T00:00:00Z"
        assert sorted(r["entityB"] for r in indicator["relationships"]) == ["ActorOne", "ActorTwo", "FamilyA", "FamilyB"]
    assert _objects(indicators) == {
        ("Malware", "FamilyA"),
        ("Malware", "FamilyB"),
        ("Threat Actor", "ActorOne"),
        ("Threat Actor", "ActorTwo"),
    }


def _names_xsoar_lint_finds(code: str) -> set:
    """The names xsoar-lint (E9010) counts as implemented commands: dict keys and the constants an if compares with."""
    names = set()
    for node in ast.walk(ast.parse(code)):
        if isinstance(node, ast.Dict):
            names.update(key.value for key in node.keys if isinstance(key, ast.Constant))
        elif isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
            for compared in node.test.comparators:
                elements = compared.elts if isinstance(compared, ast.List | ast.Set | ast.Tuple) else [compared]
                names.update(element.value for element in elements if isinstance(element, ast.Constant))
    return names


def test_every_command_of_the_yml_is_named_where_xsoar_lint_looks():
    with open(f"{realpath}/GroupIB_TIA_Feed.yml") as yml_file:
        script = yml_file.read().split("\nscript:\n", 1)[1]
    declared = set(re.findall(r"^    name: (\S+)$", script, re.M))
    assert "gibti-get-indicators" in declared
    with open(f"{realpath}/GroupIB_TIA_Feed.py") as code_file:
        assert declared - _names_xsoar_lint_finds(code_file.read()) == set()


def _open_threats() -> list[dict]:
    return [dict(item) for item in COLLECTIONS_RAW_JSON["hi/open_threats"]["items"]]


def test_open_threat_posts_yield_their_extracted_observables_as_a_watchlist():
    entries = {
        (entry["type"], entry["value"]): entry
        for entry in _from_raw("hi/open_threats", _open_threats()[:1], Settings(create_relationships=True))
    }
    assert set(entries) == {
        ("IP", "198.51.100.7"),
        ("Domain", "c2.example"),
        ("File", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        ("File", "ffffffffffffffffffffffffffffffff"),
        ("CVE", "CVE-2099-0001"),
        ("Cryptocurrency Address", "bitcoin:16L5yRNPTuciSgXGHqYwn9N6NeoKqopAu"),
        ("Cryptocurrency Address", "0x0000000000000000000000000000000000000001"),
        ("Malware", "Sample Stealer"),
        ("Threat Actor", "Sample Group"),
    }
    ip = entries[("IP", "198.51.100.7")]
    assert ip["score"] == 2
    assert ip["fields"] == {
        "gibid": "0123456789abcdef0123456789abcdef01234590",
        "gibsource": "blog.example",
        "firstseenbysource": "2026-09-30T10:00:32+00:00",
        "lastseenbysource": "2026-10-01T00:00:31+00:00",
        "gibmalwarename": "Sample Stealer",
        "gibthreatactorname": "Sample Group",
        "gibthreatactorid": "0123456789abcdef0123456789abcdef01234580",
        "gibreliability": 50,
        "gibcredibility": 50,
        "gibadmiraltycode": "B3",
        "gibseverity": "orange",
        "trafficlightprotocol": "WHITE",
        "gibcollection": "hi/open_threats",
        "malwarefamily": ["Sample Stealer"],
        "tags": ["hi/open_threats", "Sample Stealer", "Sample Group", "ransomware", "banking"],
    }
    assert {relationship["entityB"] for relationship in ip["relationships"]} == {"Sample Stealer", "Sample Group"}
    file = entries[("File", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")]["fields"]
    assert (file["md5"], file["sha1"], file["gibfilename"], file["size"]) == (
        "dddddddddddddddddddddddddddddddd",
        "cccccccccccccccccccccccccccccccccccccccc",
        "dropper.exe",
        1024,
    )
    assert file["sha256"] == "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    # A standalone hash is a file known by that hash alone.
    assert entries[("File", "ffffffffffffffffffffffffffffffff")]["fields"]["md5"] == "ffffffffffffffffffffffffffffffff"
    assert "sha256" not in entries[("File", "ffffffffffffffffffffffffffffffff")]["fields"]
    social = _from_raw("hi/open_threats", _open_threats()[1:])
    assert [(entry["type"], entry["value"], entry["fields"]["gibseverity"]) for entry in social] == [
        ("Domain", "c2.example", "green")
    ]


def test_the_open_threat_filters_keep_the_selected_source_types_and_severities():
    posts = _open_threats()
    # The domain both posts name is one indicator; a post's e-mail address is none.
    assert len(_from_raw("hi/open_threats", posts)) == 7
    blogs = Settings.from_params({"open_threats_source_types": ["Blog"]})
    assert {entry["fields"]["gibsource"] for entry in _from_raw("hi/open_threats", posts, blogs)} == {"blog.example"}
    social = Settings.from_params({"open_threats_source_types": "social network"})
    assert {entry["fields"]["gibsource"] for entry in _from_raw("hi/open_threats", posts, social)} == {"social.example"}
    medium = Settings.from_params({"min_severity": "medium"})
    assert {entry["fields"]["gibseverity"] for entry in _from_raw("hi/open_threats", posts, medium)} == {"orange"}
    assert _from_raw("hi/open_threats", posts, Settings.from_params({"min_severity": "High"})) == []
    # The source types are the open threats' own, and a C&C record carries no severity.
    high = Settings.from_params({"min_severity": "High", "open_threats_source_types": ["Blog"]})
    cnc = COLLECTIONS_RAW_JSON["malware/cnc"]["items"][:1]
    assert len(_from_raw("malware/cnc", cnc, high)) == len(_from_raw("malware/cnc", cnc))
    with pytest.raises(DemistoException, match="'Open threat source types': source_types takes Blog, Social Network, got forum"):
        Settings.from_params({"open_threats_source_types": "Forum"})
    with pytest.raises(DemistoException, match="'Minimum severity': min_severity takes Low, Medium or High, got 'red'"):
        Settings.from_params({"min_severity": "red"})


def test_open_threats_are_selectable_and_the_filters_are_declared():
    with open(os.path.join(realpath, "GroupIB_TIA_Feed.yml")) as yml_file:
        yml = yml_file.read()
    [options] = [block for block in yml.split("\n- ") if "\n  name: indicator_collections\n" in block]
    assert "\n  - hi/open_threats\n" in options
    [command] = [block for block in yml.split("\n  - arguments:\n") if "\n    name: gibti-get-indicators\n" in block]
    assert "      - hi/open_threats\n" in command
    [sources] = [block for block in yml.split("\n- ") if "\n  name: open_threats_source_types\n" in block]
    assert "  - Blog\n  - Social Network\n" in sources
    assert "Works only for hi/open_threats" in sources
    [severity] = [block for block in yml.split("\n- ") if "\n  name: min_severity\n" in block]
    assert "  - Low\n  - Medium\n  - High\n" in severity
    assert "defaultvalue: Low" in severity
    [hunting] = [block for block in yml.split("\n- ") if "\n  name: hunting_rules\n" in block]
    assert "hi/open_threats" in hunting
    assert "hi/open_threats" in TICollections.APPLY_HUNTING_RULES


@pytest.mark.parametrize("collection", ["compromised/access", "compromised/messenger", "compromised/discord", "darkweb/forums"])
def test_the_feed_refuses_the_dark_web_collections_and_names_the_incidents_integration(collection):
    with pytest.raises(DemistoException, match=f"The feed does not build indicators from {collection}.*fetches it as incidents"):
        _fetch(_feed_client(), indicator_collections=[collection])


def test_two_collections_the_feed_does_not_read_are_named_in_one_message():
    with pytest.raises(
        DemistoException, match="from compromised/access, darkweb/forums; remove the collections .*fetches them as"
    ):
        _fetch(_feed_client(), indicator_collections=["compromised/access", "darkweb/forums"])


def test_a_failed_grants_read_fails_only_the_collection_that_needs_it(mocker):
    """With Hunting Rules on, a failed grants read is the refusal of the collection that asked for it; the others are fetched."""
    common = {"id": "c" * 40, "ip": ["192.0.2.61"], "dateLastSeen": "2026-10-01T00:00:00Z", "seqUpdate": 410}
    feed = _UpdateFeed({"ioc/common": [common]})
    client = feed.client()

    def grants_down():
        raise ConnectionException(
            "Retries exhausted for https://api.example.com/api/v2/user/granted_collections: too many 503 error responses"
        )

    client.hunting_rules_collections = grants_down  # type: ignore[method-assign]
    health = mocker.patch.object(GroupIB_TIA_Feed.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "error")
    last_run = {
        "last_fetch": {"osi/vulnerability": 500, "ioc/common": 400},
        "boundary_keys": {"osi/vulnerability": ["kept"]},
    }
    next_run, indicators = _fetch(
        client=client, last_run=last_run, indicator_collections=["osi/vulnerability", "ioc/common"], hunting_rules=True
    )
    assert "192.0.2.61" in [indicator["value"] for indicator in indicators]
    assert next_run["last_fetch"] == {"osi/vulnerability": 500, "ioc/common": 410}
    assert next_run["boundary_keys"]["osi/vulnerability"] == ["kept"]
    assert feed.sent_to("osi/vulnerability/updated") == []
    assert "The fetch of osi/vulnerability failed: Retries exhausted" in health.call_args.args[0]


FILTERS = GroupIB_TIA_Feed.FILTERS
FIXED_NOW = datetime(2026, 10, 10, tzinfo=UTC)
# One sample value per filter kind; an include or kinds filter with a closed set takes its first option instead.
SAMPLE_VALUES = {
    "include": "x",
    "exclude": "x",
    "contains": "x",
    "min": "5",
    "age": "30",
    "severity": "Medium",
    "flag": "true",
    "networks": "192.0.2.0/24",
    "score": "5",
}


def _filtered(lines: str = "", **params: Any) -> Settings:
    """The settings of an instance with the filters of ``params``, the lines of Collection filters and a clock at FIXED_NOW."""
    settings = Settings.from_params({**params, "collection_filters": lines})
    return replace(settings, record_filter=replace(settings.record_filter, clock=lambda: FIXED_NOW.timestamp()))


def _parsed_fixture(collection: str) -> list[dict]:
    items = COLLECTIONS_RAW_JSON[collection]["items"]
    builder = IndicatorBuilder(collection, Settings())
    return builder.parse(Parser({"count": len(items), "items": [dict(item) for item in items], "seqUpdate": 1}, [], []))


def test_every_feed_collection_has_filters_and_every_filter_reads_its_fixture():
    assert set(FILTERS) == set(COLLECTIONS)
    for collection, specs in FILTERS.items():
        assert (
            "kinds" in specs
            or collection in ("osi/vulnerability", "osi/git_repository")
            or collection.startswith("suspicious_ip/")
        ), collection
        if collection not in COLLECTIONS_RAW_JSON:
            continue
        records = _parsed_fixture(collection)
        for spec in specs.values():
            value = spec.options[0] if spec.options and spec.kind in ("include", "kinds") else SAMPLE_VALUES[spec.kind]
            settings = _filtered(f"{collection}: {spec.name} = {value}")
            assert settings.record_filter.rules[collection].keys() == {spec.name}
            for record in records:
                spec.read(record)
                assert settings.record_filter.accepts(collection, record) in (True, False)


@pytest.mark.parametrize(
    ("lines", "message"),
    [
        ("osi/vuln: types = cve", "Collection filters, line 1: unknown collection 'osi/vuln'. Collections: ioc/primary"),
        ("\nmalware/cnc: brands = x", "line 2: malware/cnc has no filter 'brands'; its filters: max_age_days, actors, malware"),
        ("ioc/primary: kinds = Email", "line 1: kinds takes URL, Domain, IP, File, IPv6, got email"),
        ("ioc/primary: min_risk_score = high", "line 1: min_risk_score takes a number, got 'high'"),
        ("*: min_severity = Critical", "line 1: min_severity takes Low, Medium or High, got 'Critical'"),
        (
            "suspicious_ip/*: excluded_networks = example",
            "line 1: excluded_networks takes addresses and CIDR networks, got 'example'",
        ),
        ("compromised/spd: types = loyalty", "line 1: types takes Cryptocurrency Wallet, .*, got loyalty"),
        ("ioc/primary kinds = IP", "line 1: expected 'collection: filter = value'"),
    ],
)
def test_a_collection_filters_line_the_feed_cannot_apply_is_refused_with_its_line(lines, message):
    with pytest.raises(DemistoException, match=message):
        Settings.from_params({"collection_filters": lines})


def test_collection_filters_lines_apply_over_the_settings_with_patterns_and_clearing():
    settings = _filtered(
        "suspicious_ip/*: max_age_days = 5\nsuspicious_ip/tor_node: max_age_days =\n# comment\nIOC/primary: Kinds = ip, domain",
        max_record_age_days="30",
    )
    rules = settings.record_filter.rules
    assert rules["suspicious_ip/vpn"] == {"max_age_days": 5}
    assert rules["suspicious_ip/tor_node"] == {}
    assert rules["malware/cnc"] == {"max_age_days": 30}
    assert rules["ioc/primary"] == {"max_age_days": 30, "kinds": {"ip", "domain"}}
    assert settings.record_filter.describe("ioc/primary") == "max_age_days=30; kinds=domain,ip"
    # A # inside a value is part of it: only a whole line is a comment.
    assert _filtered("ioc/primary: tags = #phishing").record_filter.rules["ioc/primary"]["tags"] == {"#phishing"}


def test_the_kinds_and_risk_score_filters_decide_per_observable():
    record = _ioc_primary(1, "https://bad.example/path")
    record["ip"] = [{"ip": "198.51.100.5", "riskScore": 30}]
    record["domain"] = [{"domain": "bad.example"}]

    def kinds(settings: Settings | None = None) -> set[tuple[str, str]]:
        return {(entry["type"], entry["value"]) for entry in _from_raw("ioc/primary", [record], settings)}

    assert kinds() == {("URL", "https://bad.example/path"), ("IP", "198.51.100.5"), ("Domain", "bad.example")}
    # The minimum applies to each observable's own score; an unscored one passes unless skip_unscored is true.
    assert kinds(_filtered(ioc_min_risk_score="50")) == {("URL", "https://bad.example/path"), ("Domain", "bad.example")}
    assert kinds(_filtered("ioc/primary: skip_unscored = true", ioc_min_risk_score="50")) == {("URL", "https://bad.example/path")}
    assert kinds(_filtered("ioc/primary: kinds = IP")) == {("IP", "198.51.100.5")}
    assert kinds(_filtered("ioc/primary: kinds = IP\nioc/primary: min_risk_score = 40")) == set()
    # A DDoS record's target, the attacked host, becomes a GIB Victim IP only when the kinds name that type.
    ddos = [dict(item) for item in COLLECTIONS_RAW_JSON["attacks/ddos"]["items"]]
    assert "GIB Victim IP" not in {entry["type"] for entry in _from_raw("attacks/ddos", ddos)}
    victims = _from_raw("attacks/ddos", ddos, _filtered("attacks/ddos: kinds = URL, Domain, IP, GIB Victim IP"))
    assert {"URL", "GIB Victim IP"} <= {entry["type"] for entry in victims}
    assert "GIB Victim IP" not in {
        entry["type"] for entry in _from_raw("attacks/ddos", ddos, _filtered("attacks/ddos: kinds = URL, Domain, IP"))
    }


def test_record_filters_drop_records_before_their_observables_become_indicators():
    # The fixture advisories carry wpvulndb ids; a CVE indicator needs a CVE id.
    items = [
        {**item, "id": f"CVE-2099-000{n}"} for n, item in enumerate(COLLECTIONS_RAW_JSON["osi/vulnerability"]["items"], start=1)
    ]
    unfiltered = _from_raw("osi/vulnerability", items)
    assert unfiltered
    assert _from_raw("osi/vulnerability", items, _filtered(vulnerability_types="cve, mscve")) == []
    assert _from_raw("osi/vulnerability", items, _filtered(vulnerability_excluded_types="wpvulndb")) == []
    assert len(_from_raw("osi/vulnerability", items, _filtered(vulnerability_types="WPVULNDB"))) == len(unfiltered)
    assert _from_raw("osi/vulnerability", items, _filtered(vulnerability_has_exploit=True)) == []
    # The age is the publication date, whatever the modification date.
    assert _from_raw("osi/vulnerability", items, _filtered(max_record_age_days="30")) == []
    recent = [{**item, "datePublished": "2026-10-01T00:00:00+00:00"} for item in items]
    assert len(_from_raw("osi/vulnerability", recent, _filtered(max_record_age_days="30"))) == len(unfiltered)
    # Whether a Tor relay is an exit comes from its newest consensus state; a VPN gateway's type from its types.
    tor = [dict(item) for item in COLLECTIONS_RAW_JSON["suspicious_ip/tor_node"]["items"][:1]]
    assert _from_raw("suspicious_ip/tor_node", tor, _filtered("suspicious_ip/tor_node: exit_only = true")) == []
    states = [
        {"data": {"dateLastSeen": "2025-01-01", "flags": ["Guard"], "country": "de", "as": "AS64501"}},
        {"data": {"dateLastSeen": "2026-01-01", "flags": ["Exit", "Fast"], "country": "fr", "as": "AS64502"}},
    ]
    exit_relay = [{**tor[0], "nodes": [{"states": states}]}]
    assert len(_from_raw("suspicious_ip/tor_node", exit_relay, _filtered("suspicious_ip/tor_node: exit_only = true"))) == 1
    assert _from_raw("suspicious_ip/tor_node", exit_relay, _filtered("suspicious_ip/tor_node: flags = Guard")) == []
    assert _from_raw("suspicious_ip/tor_node", exit_relay, _filtered("suspicious_ip/tor_node: countries = de")) == []
    assert len(_from_raw("suspicious_ip/tor_node", exit_relay, _filtered("suspicious_ip/tor_node: countries = FR"))) == 1
    vpn = [dict(item) for item in COLLECTIONS_RAW_JSON["suspicious_ip/vpn"]["items"]]
    assert _from_raw("suspicious_ip/vpn", vpn, _filtered("suspicious_ip/vpn: types = commercial")) == []
    assert len(_from_raw("suspicious_ip/vpn", vpn, _filtered("suspicious_ip/vpn: types = Self-Hosted"))) == len(
        _from_raw("suspicious_ip/vpn", vpn)
    )
    assert _from_raw("suspicious_ip/vpn", vpn, _filtered("suspicious_ip/vpn: excluded_networks = 0.0.0.0/0")) == []
    # An ASN matches with or without its AS prefix, in upper or lower case.
    every_gateway = len(_from_raw("suspicious_ip/vpn", vpn))
    assert (
        len(_from_raw("suspicious_ip/vpn", vpn, _filtered("suspicious_ip/vpn: asns = 64500, as64501, AS64502"))) == every_gateway
    )
    assert _from_raw("suspicious_ip/vpn", vpn, _filtered("suspicious_ip/vpn: asns = as64499")) == []
    assert _from_raw("suspicious_ip/vpn", vpn, _filtered("suspicious_ip/vpn: excluded_asns = AS64500, 64501, 64502")) == []


def test_a_cvss_score_of_0_without_a_vector_is_unknown_and_passes_min_cvss():
    vulnerability = _parsed_fixture("osi/vulnerability")[0]
    unscored = {**vulnerability, "merged_cvss_score": 0, "merged_cvss_vector": None, "cvss_score": 0, "cvss_vector": "NONE"}
    assert _filtered("osi/vulnerability: min_cvss = 7").record_filter.accepts("osi/vulnerability", unscored)
    zero = {**unscored, "merged_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}
    assert not _filtered("osi/vulnerability: min_cvss = 7").record_filter.accepts("osi/vulnerability", zero)


def test_a_vendor_product_pair_matches_only_a_row_of_the_cpe_table():
    rows = [("examplevendor", "alpha"), ("examplevendor", "beta"), ("samplecorp", "gamma")]
    record = _vulnerability(cpeTable=[{"vendor": vendor, "product": product, "type": "software"} for vendor, product in rows])
    [cve] = _from_raw("osi/vulnerability", [record], _filtered("osi/vulnerability: vendors = samplecorp:gamma"))
    assert cve["value"] == "CVE-2099-10001"
    assert _from_raw("osi/vulnerability", [record], _filtered("osi/vulnerability: vendors = samplecorp:beta")) == []


def test_kinds_can_keep_the_ipv6_indicators_of_an_ip_or_domain_field():
    record_filter = _filtered("ioc/primary: kinds = IPv6").record_filter
    assert record_filter.accepts_entry("ioc/primary", "IPv6", {})
    assert not record_filter.accepts_entry("ioc/primary", "IP", {})


def _observable_keys(collection: str) -> list[str]:
    spec = COLLECTIONS[collection]
    keys = [*spec.types]
    for extra in (*spec.value_preferred.values(), *spec.value_fallbacks.values()):
        keys.extend(extra)
    return keys


def test_the_filters_shared_with_the_incidents_integration_read_the_feed_records():
    def accepts(collection: str, record: dict, line: str) -> bool:
        return _filtered(line).record_filter.accepts(collection, record)

    account = {
        **_parsed_fixture("compromised/account_group")[0],
        "service_domain": "mail.victim.example",
        "login_domain": "corp.example",
        "event_country_code": ["NL", "DE"],
        "date_last_compromised": "2026-10-01T00:00:00+00:00",
        "date_last_seen": "2013-05-21T00:00:00+00:00",
    }
    assert accepts("compromised/account_group", account, "compromised/account_group: service_domains = victim.example")
    assert not accepts("compromised/account_group", account, "compromised/account_group: service_domains = other.example")
    assert accepts("compromised/account_group", account, "compromised/account_group: login_domains = corp.example")
    assert not accepts("compromised/account_group", account, "compromised/account_group: login_domains = other.example")
    assert accepts("compromised/account_group", account, "compromised/account_group: victim_countries = de")
    assert not accepts("compromised/account_group", account, "compromised/account_group: victim_countries = FR")
    # The age is the compromise date, as in the incidents integration, whatever the last sighting.
    assert accepts("compromised/account_group", account, "compromised/account_group: max_age_days = 30")
    stale = {**account, "date_last_compromised": "2020-01-01T00:00:00+00:00", "date_last_seen": "2026-10-09T00:00:00+00:00"}
    assert not accepts("compromised/account_group", stale, "compromised/account_group: max_age_days = 30")
    attacks = [dict(item) for item in COLLECTIONS_RAW_JSON["attacks/ddos"]["items"]]
    every_attack = len(_from_raw("attacks/ddos", attacks))
    assert len(_from_raw("attacks/ddos", attacks, _filtered("attacks/ddos: protocols = UDP"))) == every_attack
    assert _from_raw("attacks/ddos", attacks, _filtered("attacks/ddos: protocols = tcp")) == []
    defacements = [dict(item) for item in COLLECTIONS_RAW_JSON["attacks/deface"]["items"]]
    assert len(_from_raw("attacks/deface", defacements, _filtered("attacks/deface: target_domains = example.com"))) == 3
    assert len(_from_raw("attacks/deface", defacements, _filtered("attacks/deface: countries = de, ar"))) == 2
    assert _from_raw("attacks/deface", defacements, _filtered("attacks/deface: countries = FR")) == []
    groups = [dict(item) for item in COLLECTIONS_RAW_JSON["attacks/phishing_group"]["items"]]
    every_group = len(_from_raw("attacks/phishing_group", groups))
    assert (
        len(_from_raw("attacks/phishing_group", groups, _filtered("attacks/phishing_group: sources = Example-Search")))
        == every_group
    )
    assert _from_raw("attacks/phishing_group", groups, _filtered("attacks/phishing_group: sources = other")) == []
    reports = [
        {
            **item,
            "sectors": ["finance"],
            "regions": ["europe"],
            "countries": ["France"],
            "targetedCompany": ["Sample Bank plc"],
            "targetDomain": ["bank.example"],
        }
        for item in COLLECTIONS_RAW_JSON["apt/threat"]["items"]
    ]
    every_report = len(_from_raw("apt/threat", reports))
    assert every_report
    for line in ("sectors = Finance", "regions = france", "targeted_companies = bank", "target_domains = bank.example"):
        assert len(_from_raw("apt/threat", reports, _filtered(f"apt/threat: {line}"))) == every_report, line
    for line in ("sectors = energy", "regions = asia", "targeted_companies = insurance", "target_domains = other.example"):
        assert _from_raw("apt/threat", reports, _filtered(f"apt/threat: {line}")) == [], line
    report = _parsed_fixture("apt/threat")[0]
    silent_report = {**report, **dict.fromkeys(_observable_keys("apt/threat"), [])}
    assert accepts("apt/threat", {**report, "indicators_params_domain": ["evil.example"]}, "apt/threat: with_iocs_only = true")
    assert not accepts("apt/threat", silent_report, "apt/threat: with_iocs_only = true")
    # a file known by its SHA-1 alone is an indicator too
    sha1_only = {**silent_report, "indicators_params_hashes_sha1": ["a" * 40]}
    assert accepts("apt/threat", sha1_only, "apt/threat: with_iocs_only = true")
    # A report without a publication date is aged by its creation date.
    created = {**report, "date_published": None, "created_at": "2026-10-05T00:00:00+00:00"}
    assert accepts("apt/threat", created, "apt/threat: max_age_days = 30")
    assert not accepts("apt/threat", {**created, "created_at": "2020-01-01T00:00:00+00:00"}, "apt/threat: max_age_days = 30")
    matched_post, other_post = _parsed_fixture("hi/open_threats")
    assert accepts("hi/open_threats", matched_post, "hi/open_threats: matched_rules_only = true")
    assert not accepts("hi/open_threats", other_post, "hi/open_threats: matched_rules_only = true")
    silent_post = {**matched_post, **dict.fromkeys(_observable_keys("hi/open_threats"), [])}
    assert accepts("hi/open_threats", {**matched_post, "data_ip": ["192.0.2.7"]}, "hi/open_threats: with_iocs_only = true")
    assert not accepts("hi/open_threats", silent_post, "hi/open_threats: with_iocs_only = true")


def test_the_feed_asks_the_api_for_the_filtered_view_where_the_api_has_one(mocker):
    feed = _UpdateFeed(start_cursors={"compromised/spd": 7})
    _fetch(
        feed.client(),
        last_run={"last_fetch": {"osi/vulnerability": 5, "compromised/spd": 5}},
        indicator_collections=["osi/vulnerability", "compromised/spd"],
        settings=_filtered(vulnerability_types="mscve, cve", vulnerability_has_exploit=True, spd_types=["Bank Account Number"]),
    )
    [vulnerability] = feed.sent_to("osi/vulnerability/updated")
    assert vulnerability["q"] == 'type:"cve" OR type:"mscve"'
    assert vulnerability["apply_has_exploit"] == 1
    [spd] = feed.sent_to("compromised/spd/updated")
    assert spd["type"] == "Bank Account Number"
    assert "q" not in spd
    # Two payment detail types cannot be one request: the records are checked as they arrive.
    feed = _UpdateFeed()
    _fetch(
        feed.client(),
        last_run={"last_fetch": {"compromised/spd": 5}},
        indicator_collections=["compromised/spd"],
        settings=_filtered(spd_types=["IBAN", "Bank Card"]),
    )
    assert "type" not in feed.sent_to("compromised/spd/updated")[0]
    # gibti-get-indicators reads with the instance's filters too.
    feed = _UpdateFeed(start_cursors={"osi/vulnerability": 7})
    _get(feed.client(), {"collection": "osi/vulnerability"}, params={"vulnerability_excluded_types": "nessus"})
    assert feed.sent_to("osi/vulnerability/updated")[0]["q"] == '-type:"nessus"'


def test_the_feed_readme_and_yml_declare_every_filter_and_setting():
    with open(os.path.join(realpath, "README.md")) as readme_file:
        readme = readme_file.read()
    for collection, specs in FILTERS.items():
        section = readme[readme.index(f"##### `{collection}`\n") :]
        section = section[: section.find("\n##### ", 1) if "\n##### " in section[1:] else len(section)]
        for name in specs:
            assert f"| `{name}` |" in section, (collection, name)
    with open(os.path.join(realpath, "GroupIB_TIA_Feed.yml")) as yml_file:
        blocks = yml_file.read().split("\n- ")
    declared = {block.split("\n  name: ", 1)[1].split("\n", 1)[0] for block in blocks if "\n  name: " in block}
    assert {key for key, *_ in GroupIB_TIA_Feed.RecordFilter.SETTINGS} | {"collection_filters"} <= declared
    [filters] = [block for block in blocks if "\n  name: collection_filters\n" in block]
    assert "type: 12" in filters
    [score] = [block for block in blocks if "\n  name: ioc_min_risk_score\n" in block]
    assert "Works only for ioc/primary" in score


def test_a_feed_page_that_is_no_page_of_records_is_a_refused_read():
    first = SimpleNamespace(sequpdate=1)

    def pages():
        yield first
        raise AttributeError("'NoneType' object has no attribute 'get'")

    read = Client._pages(pages())
    assert next(read) is first
    with pytest.raises(ConnectionException, match="not a page of records"):
        next(read)


def test_the_feed_age_filter_reads_the_unknown_date_placeholder_as_no_date():
    report = {**_parsed_fixture("apt/threat")[0], "date_published": "0001-01-01T00:00:00Z", "created_at": None}
    assert _filtered("apt/threat: max_age_days = 30").record_filter.accepts("apt/threat", report)


def test_the_feed_age_filter_reads_the_vulnerability_placeholder_as_no_date():
    record = {**_parsed_fixture("osi/vulnerability")[0], "date_published": "1976-01-01T00:00:00+00:00"}
    assert _filtered("osi/vulnerability: max_age_days = 30").record_filter.accepts("osi/vulnerability", record)


def test_the_name_of_a_page_asset_is_no_e_mail_indicator():
    kit = _kit("a" * 64, ["logo@2x.png", "drop2@example.com"], "2026-09-01T10:12:00Z")
    assert [i["value"] for i in _from_raw("attacks/phishing_kit", [kit]) if i["type"] == "Email"] == ["drop2@example.com"]


def test_a_feed_vulnerability_type_is_quoted_in_the_query():
    params = _filtered('osi/vulnerability: types = a"b').record_filter.request_params("osi/vulnerability")
    assert params["query"] == 'type:"a\\"b"'
    params = _filtered('osi/vulnerability: excluded_types = a"b').record_filter.request_params("osi/vulnerability")
    assert params["query"] == '-type:"a\\"b"'


def test_every_page_generator_of_the_feed_takes_a_body_that_is_no_page_as_a_refused_read(mocker):
    client = _feed_client()

    def pages():
        raise AttributeError("'NoneType' object has no attribute 'get'")
        yield

    for read in (lambda: client.update_feed("malware/cnc"), lambda: client.search("attacks/phishing_group", "id:ab12")):
        mocker.patch.object(client.poller, "create_update_generator", return_value=pages())
        with pytest.raises(ConnectionException, match="not a page of records"):
            list(read())


def test_a_feed_by_id_answer_that_is_no_record_is_a_refused_read(mocker):
    client = _feed_client()
    mocker.patch.object(
        client.poller, "search_feed_by_id", side_effect=AttributeError("'NoneType' object has no attribute 'get'")
    )
    with pytest.raises(ConnectionException, match="not a page of records"):
        client.record("malware/cnc", "ab12")


def test_a_refusal_while_the_command_pages_is_one_message_naming_the_collection(mocker):
    client = _feed_client()

    def pages():
        raise ConnectionException(SERVER_ERROR)
        yield

    mocker.patch.object(client, "start_cursor", return_value=7)
    mocker.patch.object(client, "update_feed", return_value=pages())
    with pytest.raises(DemistoException, match="The read of malware/cnc failed: HTTP 500"):
        _get(client, {"limit": "10", "collection": "malware/cnc"})


def _position_runs(unit: int, sizes: tuple[int, ...] = (1, 3, 1, 7, 2, 4, 1, 5)) -> list[dict]:
    """Records in runs that share a position; inside a millisecond the served order runs against the cursor."""
    records = []
    for index, size in enumerate(sizes):
        for offset in range(size):
            spread = size - offset - 1 if unit > 1 else 0
            records.append({"id": f"{len(records):040x}", "seqUpdate": (5000 + index) * unit + spread})
    return records


def _walk(server: Any, collection: str, limit: int, cursor: Any, seen_keys: Any = ()) -> Any:
    params = GroupIB_TIA_Feed.TIRequestParams(limit=limit)
    return GroupIB_TIA_Feed.BoundaryPages(server, collection, params, cursor, seen_keys, 0)


def _delivered(pages: Any) -> list[str]:
    return [record["id"] for page in pages for record in page.raw_dict["items"]]


@pytest.mark.parametrize("limit", [1, 2, 3, 5, 100])
@pytest.mark.parametrize("collection", sorted(GroupIB_TIA_Feed.BoundaryPages.UNITS))
def test_a_walk_delivers_every_record_once_at_any_page_size(collection, limit):
    """A page edge cuts a run of records at one position; the walk reads the whole run, whatever the page size."""
    unit = GroupIB_TIA_Feed.BoundaryPages.UNITS[collection]
    records = _position_runs(unit)
    server = _MillisecondServer(records, unit=unit)
    assert sorted(_delivered(_walk(server, collection, limit, 4999 * unit))) == [record["id"] for record in records]


@pytest.mark.parametrize("collection", sorted(GroupIB_TIA_Feed.BoundaryPages.UNITS))
def test_one_generator_over_the_model_server_reads_fewer_records_than_it_holds(collection):
    """The control case of the walks above: without BoundaryPages, a page edge of the model cuts a run of records."""
    unit = GroupIB_TIA_Feed.BoundaryPages.UNITS[collection]
    records = _position_runs(unit)
    server = _MillisecondServer(records, unit=unit)
    pages = server.create_update_generator(collection, GroupIB_TIA_Feed.TIRequestParams(limit=3), 4999 * unit)
    assert len(_delivered(pages)) < len(records)


@pytest.mark.parametrize("limit", [1, 3, 100])
@pytest.mark.parametrize("collection", sorted(GroupIB_TIA_Feed.BoundaryPages.UNITS))
def test_fetch_runs_of_one_page_each_deliver_every_record_once(collection, limit):
    """The cursor and the digests a run stores let the next run read on with no record skipped or repeated."""
    unit = GroupIB_TIA_Feed.BoundaryPages.UNITS[collection]
    records = _position_runs(unit)
    server = _MillisecondServer(records, unit=unit)
    cursor, seen_keys, delivered = 4999 * unit, [], []
    for _ in range(len(records) + 2):
        walk = _walk(server, collection, limit, cursor, seen_keys)
        page = next(iter(walk), None)
        seen_keys = walk.seen_keys
        if page is None:
            break
        delivered.extend(_delivered([page]))
        cursor = page.sequpdate
    assert sorted(delivered) == [record["id"] for record in records]


def test_a_walk_keeps_two_listings_of_one_id_apart():
    """An open proxy address can have several listings under one id: a listing is told by its content."""
    records = [{"id": "192.0.2.5", "port": port, "seqUpdate": 7000 + port} for port in (80, 443, 8080)]
    server = _MillisecondServer(records)
    pages = list(_walk(server, "suspicious_ip/open_proxy", 2, 5999))
    assert sorted(record["port"] for page in pages for record in page.raw_dict["items"]) == [80, 443, 8080]


def test_a_page_of_one_position_is_read_again_larger():
    records = [{"id": f"{n:040x}", "seqUpdate": 7000} for n in range(5)]
    server = _MillisecondServer(records, unit=1)
    assert len(_delivered(_walk(server, "malware/cnc", 2, 6999))) == 5
    assert [params.limit for params in server.params] == [2, 4, 8]


def _wide_position(mocker: Any) -> Any:
    """suspicious_ip/tor_node with a largest page of 4 and a millisecond of 6 records, then one later record."""
    mocker.patch.dict(GroupIB_TIA_Feed.BoundaryPages.LARGEST_PAGES, {"suspicious_ip/tor_node": 4})
    wide = [{"id": f"{n:040x}", "seqUpdate": 7000 + n} for n in range(6)]
    return wide, _MillisecondServer(wide + [{"id": "f" * 40, "seqUpdate": 9000}])


def test_a_position_wider_than_the_largest_page_is_read_past_and_reported(mocker):
    wide, server = _wide_position(mocker)
    first = _walk(server, "suspicious_ip/tor_node", 2, 6999)
    assert _delivered(first) == [record["id"] for record in wide[:4]]
    assert first.stalls == []
    assert [params.limit for params in server.params] == [2, 4]
    second = _walk(server, "suspicious_ip/tor_node", 2, 6999, first.seen_keys)
    pages = list(second)
    assert _delivered(pages) == ["f" * 40]
    assert pages[0].sequpdate == 7003
    [stall] = second.stalls
    assert "suspicious_ip/tor_node" in stall
    assert "(7003)" in stall
    assert second.seen_keys == [second._digest(server.records[-1])]


def test_a_wide_position_with_nothing_behind_it_stores_no_digests(mocker):
    mocker.patch.dict(GroupIB_TIA_Feed.BoundaryPages.LARGEST_PAGES, {"suspicious_ip/tor_node": 4})
    server = _MillisecondServer([{"id": f"{n:040x}", "seqUpdate": 7000 + n} for n in range(6)])
    first = _walk(server, "suspicious_ip/tor_node", 4, 6999)
    list(first)
    second = _walk(server, "suspicious_ip/tor_node", 4, 6999, first.seen_keys)
    assert [page.sequpdate for page in second] == [7003]
    assert second.seen_keys == []


def test_a_walk_from_below_a_wide_position_reads_past_it_in_one_run(mocker):
    wide, server = _wide_position(mocker)
    walk = _walk(server, "suspicious_ip/tor_node", 4, 5999)
    assert _delivered(walk) == [record["id"] for record in wide[:4]] + ["f" * 40]
    assert len(walk.stalls) == 1


def test_a_short_page_of_one_position_with_more_ahead_is_read_past():
    """A page smaller than the limit whose count says more lies ahead must not hold the collection for good."""
    served = {"count": 5, "items": [{"id": "a", "seqUpdate": 7000}], "seqUpdate": 7000}
    server = MagicMock()
    server.create_update_generator.side_effect = [iter([GroupIB_TIA_Feed.Parser(served, None, None)]), iter([])]
    first = _walk(
        MagicMock(**{"create_update_generator.side_effect": lambda **_: iter([GroupIB_TIA_Feed.Parser(served, None, None)])}),
        "malware/cnc",
        100,
        6999,
    )
    list(first)
    walk = _walk(server, "malware/cnc", 100, 6999, first.seen_keys)
    assert [page.sequpdate for page in walk] == [7000]
    assert len(walk.stalls) == 1


def _larger_reads_fail(message: str) -> Any:
    """A server of one full position of two records whose larger pages raise ``message``."""
    body = {"count": 5, "items": [{"id": f"{n:040x}", "seqUpdate": 7000} for n in range(2)], "seqUpdate": 7000}

    def answers(**kwargs):
        if kwargs["sequpdate"] >= 7000:
            return iter([])
        if kwargs["request_params"].limit > 2:
            raise GroupIB_TIA_Feed.ConnectionException(message)
        return iter([GroupIB_TIA_Feed.Parser(body, None, None)])

    server = MagicMock()
    server.create_update_generator.side_effect = answers
    return server


@pytest.mark.parametrize(
    "message", ["HTTP 429: Maximum number of requests", "too many 503 error responses", "connection dropped"]
)
def test_a_larger_read_that_fails_for_now_holds_the_cursor(message):
    server = _larger_reads_fail(message)
    first = _walk(server, "malware/cnc", 2, 6999)
    assert len(_delivered(first)) == 2
    assert first.stalls == []
    second = _walk(server, "malware/cnc", 2, 6999, first.seen_keys)
    with pytest.raises(GroupIB_TIA_Feed.ConnectionException, match=message):
        list(second)
    assert second.stalls == []
    assert second.seen_keys == first.seen_keys


def test_a_failed_read_does_not_outlive_the_read_after_it():
    """The larger read fails once: the walk goes on, and the next read of the position ends it without a refusal."""
    server = _larger_reads_fail("connection dropped")
    answers = server.create_update_generator.side_effect
    calls = []

    def once(**kwargs):
        calls.append(kwargs["request_params"].limit)
        if kwargs["request_params"].limit > 2 and calls.count(kwargs["request_params"].limit) > 1:
            return iter([])
        return answers(**kwargs)

    server.create_update_generator.side_effect = once
    walk = _walk(server, "malware/cnc", 2, 5999)
    assert len(_delivered(walk)) == 2
    assert calls == [2, 4, 2, 4, 2]
    assert len(walk.stalls) == 1


def test_a_page_with_nothing_ahead_is_read_no_larger():
    body = {"count": 2, "items": [{"id": f"{n:040x}", "seqUpdate": 7000} for n in range(2)], "seqUpdate": 7000}
    server = MagicMock()
    server.create_update_generator.side_effect = lambda **_: iter([GroupIB_TIA_Feed.Parser(body, None, None)])
    assert len(_delivered(_walk(server, "malware/cnc", 2, 6999))) == 2
    assert server.create_update_generator.call_count == 1


def test_no_walk_asks_for_more_than_a_thousand_records_a_page():
    assert max(GroupIB_TIA_Feed.BoundaryPages.LARGEST_PAGES.values()) == 1000


@pytest.mark.parametrize(
    "message", ["HTTP 400: Bad Credentials or Wrong request.", "Unexpected HTTP status code: 413. Response: too large"]
)
def test_a_larger_page_the_server_refuses_ends_at_the_smaller_one(message):
    server = _larger_reads_fail(message)
    first = _walk(server, "malware/cnc", 2, 6999)
    assert len(_delivered(first)) == 2
    second = _walk(server, "malware/cnc", 2, 6999, first.seen_keys)
    assert [page.sequpdate for page in second] == [7000]
    assert len(second.stalls) == 1


def test_a_larger_read_that_answers_nothing_keeps_the_smaller_page():
    records = [{"id": f"{n:040x}", "seqUpdate": 7000} for n in range(2)]
    body = {"count": 5, "items": records, "seqUpdate": 7000}
    server = MagicMock()
    server.create_update_generator.side_effect = [iter([GroupIB_TIA_Feed.Parser(body, None, None)]), iter([])]
    assert len(_delivered(_walk(server, "malware/cnc", 2, 6999))) == 2


def test_a_first_read_that_fails_is_a_refusal():
    server = MagicMock()
    server.create_update_generator.side_effect = GroupIB_TIA_Feed.ConnectionException(UPDATE_FEED_DOWN)
    with pytest.raises(GroupIB_TIA_Feed.ConnectionException, match="too many 502 error responses"):
        list(_walk(server, "malware/cnc", 2, 6999))


def test_a_position_served_in_another_order_repeats_no_record(mocker):
    """Each read of a wide millisecond shows another part of it: every record comes once, then the walk moves on."""
    mocker.patch.dict(GroupIB_TIA_Feed.BoundaryPages.LARGEST_PAGES, {"suspicious_ip/tor_node": 4})
    records = [{"id": f"{n:040x}", "seqUpdate": 7000 + n} for n in range(6)]
    views = [records[:4], records[2:], records[:4]]
    server = MagicMock()
    answers = [
        iter([GroupIB_TIA_Feed.Parser({"count": 6, "items": view, "seqUpdate": view[-1]["seqUpdate"]}, None, None)])
        for view in views
    ]
    server.create_update_generator.side_effect = answers + [iter([])]
    cursor, seen_keys, delivered, stalls = 6999, [], [], []
    for _ in views:
        walk = _walk(server, "suspicious_ip/tor_node", 4, cursor, seen_keys)
        pages = list(walk)
        delivered.extend(_delivered(pages))
        stalls.extend(walk.stalls)
        cursor, seen_keys = pages[-1].sequpdate, walk.seen_keys
    assert sorted(delivered) == [record["id"] for record in records]
    assert len(stalls) == 1
    assert cursor == 7003


def test_a_walk_stores_the_digests_of_its_top_position_only():
    records = [{"id": "a" * 40, "seqUpdate": 7000}, {"id": "b" * 40, "seqUpdate": 8000}, {"id": "c" * 40, "seqUpdate": 8000}]
    walk = _walk(_MillisecondServer(records, unit=1), "malware/cnc", 100, 6999)
    list(walk)
    assert walk.seen_keys == sorted(walk._digest(record) for record in records[1:])


def test_a_page_below_the_cursor_is_refused_and_keeps_the_digests():
    body = {"count": 1, "items": [{"id": "a", "seqUpdate": 7000}], "seqUpdate": 7000}
    server = MagicMock()
    server.create_update_generator.side_effect = lambda **_: iter([GroupIB_TIA_Feed.Parser(body, None, None)])
    walk = _walk(server, "malware/cnc", 100, 9000, ["kept"])
    with pytest.raises(GroupIB_TIA_Feed.ConnectionException, match="below the cursor"):
        list(walk)
    assert walk.seen_keys == ["kept"]


def test_records_below_the_held_position_are_dropped():
    body = {"count": 2, "items": [{"id": "a", "seqUpdate": 7000}, {"id": "b", "seqUpdate": 9500}], "seqUpdate": 9500}
    server = MagicMock()
    server.create_update_generator.side_effect = [iter([GroupIB_TIA_Feed.Parser(body, None, None)]), iter([])]
    assert _delivered(_walk(server, "malware/cnc", 100, 8999)) == ["b"]


def test_a_cursor_inside_a_millisecond_is_not_moved_back():
    """A stored cursor from before the walk need not stand just below a millisecond."""
    body = {"count": 1, "items": [{"id": "a", "seqUpdate": 7600}], "seqUpdate": 7600}
    server = MagicMock()
    server.create_update_generator.side_effect = [iter([GroupIB_TIA_Feed.Parser(body, None, None)]), iter([])]
    assert [page.sequpdate for page in _walk(server, "suspicious_ip/tor_node", 100, 7500)] == [7500]


def test_a_stored_cursor_that_is_no_number_is_refused():
    with pytest.raises(GroupIB_TIA_Feed.ConnectionException, match="not a number"):
        _walk(MagicMock(), "malware/cnc", 100, "7000.0")


@pytest.mark.parametrize("limit", [-5, 0])
def test_a_limit_below_one_reads_the_largest_page(limit):
    server = _MillisecondServer(_position_runs(1), unit=1)
    params = GroupIB_TIA_Feed.TIRequestParams(limit=1)
    object.__setattr__(params, "limit", limit)
    list(GroupIB_TIA_Feed.BoundaryPages(server, "malware/cnc", params, 4999, (), 0))
    assert server.params[0].limit == GroupIB_TIA_Feed.BoundaryPages.LARGEST_PAGES["malware/cnc"]


def test_a_walk_ends_when_the_server_answers_the_same_page_whatever_the_cursor():
    page = {"count": 2, "items": [{"id": "a", "seqUpdate": 7000}, {"id": "b", "seqUpdate": 8000}], "seqUpdate": 8000}
    server = MagicMock()
    server.create_update_generator.side_effect = lambda **_: iter([GroupIB_TIA_Feed.Parser(page, None, None)])
    assert _delivered(_walk(server, "malware/cnc", 100, 6999)) == ["a", "b"]
    assert server.create_update_generator.call_count == 2


def test_a_walk_stops_on_a_page_that_holds_only_records_already_read():
    record = {"id": "a" * 40, "seqUpdate": 7000}
    server = _MillisecondServer([record], unit=1)
    walk = _walk(server, "malware/cnc", 100, 6999)
    assert len(list(walk)) == 1
    again = _walk(server, "malware/cnc", 100, 6999, walk.seen_keys)
    assert list(again) == []
    assert again.seen_keys == walk.seen_keys


def test_a_record_new_at_the_held_position_is_delivered():
    first = {"id": "a" * 40, "seqUpdate": 7000}
    server = _MillisecondServer([first], unit=1)
    walk = _walk(server, "malware/cnc", 100, 6999)
    list(walk)
    second = {"id": "b" * 40, "seqUpdate": 7000}
    again = _walk(_MillisecondServer([first, second], unit=1), "malware/cnc", 100, 6999, walk.seen_keys)
    [page] = list(again)
    assert _delivered([page]) == [second["id"]]
    assert page.sequpdate == 6999
    assert len(again.seen_keys) == 2


def test_only_the_first_request_of_a_walk_carries_the_date():
    server = _MillisecondServer(_position_runs(1), unit=1)
    params = GroupIB_TIA_Feed.TIRequestParams(limit=3, date_from="2026-01-01")
    list(GroupIB_TIA_Feed.BoundaryPages(server, "malware/cnc", params, None, (), 0))
    assert server.params[0].date_from == "2026-01-01"
    assert len(server.params) > 1
    assert all(sent.date_from is None for sent in server.params[1:])


def test_a_walk_asks_the_millisecond_feeds_for_no_more_than_they_serve():
    server = _MillisecondServer(_position_runs(1000))
    list(_walk(server, "suspicious_ip/scanner", 5000, 4999000))
    assert {params.limit for params in server.params} == {1000}


def test_a_walk_paces_its_requests_itself(mocker):
    wait = mocker.patch.object(GroupIB_TIA_Feed.RateLimiter, "wait")
    server = MagicMock(wraps=_MillisecondServer(_position_runs(1), unit=1))
    list(_walk(server, "malware/cnc", 3, 4999))
    assert wait.call_count == server.create_update_generator.call_count > 1
    assert {call.kwargs["rate_limit_delay"] for call in server.create_update_generator.call_args_list} == {0}


def test_a_page_without_records_is_refused_as_no_page():
    body = {"count": 1, "items": ["not a record"], "seqUpdate": 7000}
    server = MagicMock()
    server.create_update_generator.side_effect = lambda **_: iter([GroupIB_TIA_Feed.Parser(body, None, None)])
    with pytest.raises(GroupIB_TIA_Feed.ConnectionException, match="not a page of records"):
        list(_walk(server, "malware/cnc", 100, 6999))


def test_a_page_without_a_cursor_is_refused():
    body = {"count": 1, "items": [{"id": "a"}]}
    server = MagicMock()
    server.create_update_generator.side_effect = lambda **_: iter([GroupIB_TIA_Feed.Parser(body, None, None)])
    with pytest.raises(GroupIB_TIA_Feed.ConnectionException, match="carries no seqUpdate"):
        list(_walk(server, "malware/cnc", 100, 6999))


def test_a_record_without_a_cursor_takes_the_position_of_its_page():
    body = {"count": 1, "items": [{"id": "a"}], "seqUpdate": 7000}
    server = MagicMock()
    server.create_update_generator.side_effect = lambda **_: iter([GroupIB_TIA_Feed.Parser(body, None, None)])
    walk = _walk(server, "malware/cnc", 100, 6000)
    assert next(iter(walk)).sequpdate == 6999


def _boundary_fetch(feed: Any, last_run: dict, **settings: Any) -> tuple[dict, list]:
    return _fetch(
        client=feed.client(),
        last_run={"first_fetch_time": "3 days", **last_run},
        first_fetch_time="3 days",
        indicator_collections=["malware/cnc"],
        **settings,
    )


def test_the_fetch_stores_the_digests_with_the_cursor_and_repeats_no_indicator():
    feed = _UpdateFeed({"malware/cnc": [_tied_feed_record("malware/cnc", 1, 410), _tied_feed_record("malware/cnc", 2, 410)]})
    next_run, indicators = _boundary_fetch(feed, {"last_fetch": {"malware/cnc": 400}})
    assert next_run["last_fetch"]["malware/cnc"] == 409
    assert len(next_run["boundary_keys"]["malware/cnc"]) == 2
    assert indicators
    again, repeated = _boundary_fetch(feed, next_run)
    assert again["last_fetch"]["malware/cnc"] == 409
    assert again["boundary_keys"] == next_run["boundary_keys"]
    assert repeated == []


def test_a_record_new_at_the_stored_position_is_fetched_without_a_refusal(mocker):
    health = mocker.patch.object(GroupIB_TIA_Feed.demisto, "updateModuleHealth")
    feed = _UpdateFeed({"malware/cnc": [_tied_feed_record("malware/cnc", 1, 410)]})
    next_run, _ = _boundary_fetch(feed, {"last_fetch": {"malware/cnc": 400}})
    newcomer = _tied_feed_record("malware/cnc", 2, 410)
    feed.records["malware/cnc"].append(newcomer)
    again, indicators = _boundary_fetch(feed, next_run)
    assert indicators
    assert again["last_fetch"]["malware/cnc"] == 409
    assert len(again["boundary_keys"]["malware/cnc"]) == 2
    health.assert_not_called()


def test_a_changed_first_fetch_drops_the_stored_digests():
    record = _tied_feed_record("malware/cnc", 1, 410)
    feed = _UpdateFeed({"malware/cnc": [record]}, start_cursors={"malware/cnc": 409})
    stored = {"first_fetch_time": "7 days", "last_fetch": {"malware/cnc": 409}, "boundary_keys": {"malware/cnc": ["x"]}}
    next_run, indicators = _fetch(
        client=feed.client(), last_run=stored, first_fetch_time="3 days", indicator_collections=["malware/cnc"]
    )
    assert indicators
    assert "x" not in next_run["boundary_keys"]["malware/cnc"]


def test_a_refused_read_keeps_the_stored_cursor_and_digests(mocker):
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "error")
    feed = _UpdateFeed(
        {"ioc/common": [{"id": "c" * 40, "ip": ["192.0.2.61"], "dateLastSeen": "2026-10-01T00:00:00Z", "seqUpdate": 410}]},
        refused={"malware/cnc": ConnectionException(UPDATE_FEED_DOWN)},
    )
    last_run = {
        "first_fetch_time": "3 days",
        "last_fetch": {"malware/cnc": 409, "ioc/common": 400},
        "boundary_keys": {"malware/cnc": ["kept"]},
    }
    next_run, _ = _fetch(client=feed.client(), last_run=last_run, indicator_collections=["malware/cnc", "ioc/common"])
    assert next_run["last_fetch"]["malware/cnc"] == 409
    assert next_run["boundary_keys"]["malware/cnc"] == ["kept"]


def test_a_position_too_wide_to_read_goes_to_instance_health_and_the_fetch_moves_on(mocker):
    health = mocker.patch.object(GroupIB_TIA_Feed.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIB_TIA_Feed.demisto, "error")
    mocker.patch.dict(GroupIB_TIA_Feed.BoundaryPages.LARGEST_PAGES, {"malware/cnc": 2})
    records = [_tied_feed_record("malware/cnc", n, 410) for n in range(1, 4)]
    next_run, indicators = _boundary_fetch(
        _UpdateFeed({"malware/cnc": records}), {"last_fetch": {"malware/cnc": 400}}, limit=2, requests_count=3
    )
    assert next_run["last_fetch"]["malware/cnc"] == 410
    assert indicators
    assert "malware/cnc" in health.call_args.args[0]
    assert "cursor position" in health.call_args.args[0]


def test_a_search_stays_on_one_ciaops_generator(mocker):
    client = _feed_client()
    generator = mocker.patch.object(client.poller, "create_update_generator", return_value=iter([]))
    assert list(client.search("compromised/spd", query="x", limit=10)) == []
    generator.assert_called_once()


def test_only_the_collections_whose_records_share_cursor_positions_get_boundary_pages():
    client = _feed_client()
    assert isinstance(client.update_feed("malware/cnc", seq_update=5), GroupIB_TIA_Feed.BoundaryPages)
    assert not isinstance(client.update_feed("ioc/primary", seq_update=5), GroupIB_TIA_Feed.BoundaryPages)


@pytest.mark.parametrize(
    "value, placeholder",
    [
        ("0001-01-01T00:00:00Z", True),
        ("1976-01-01", True),
        ("12-05-2023", False),
        ("12-05-23", False),
        ("2023-12-05", False),
        ("none", False),
        (None, False),
    ],
)
def test_a_placeholder_date_is_told_from_a_day_first_date(value, placeholder):
    assert IndicatorBuilder._is_placeholder_date(value) is placeholder
