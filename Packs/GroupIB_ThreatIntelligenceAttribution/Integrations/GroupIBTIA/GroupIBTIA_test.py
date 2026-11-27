from unittest.mock import patch, MagicMock

import pytest
import string

from CommonServerPython import CommandResults, Common, EntryType, IncidentSeverity
from typing import Any, cast
from GroupIBTIA import (
    COLLECTIONS,
    DomainWhois,
    IPWhois,
    WhoisCommand,
    LOOKUP_COMMANDS,
    AvailableCollectionsCommand,
    CardDataMask,
    Client,
    CollectionSpec,
    FetchIncidentsCommand,
    IncidentBuilder,
    IndicatorBuilder,
    LookupCommand,
    Masking,
    PasswordMask,
    ReputationCommand,
    ScoringCommand,
    SearchCommand,
    Settings,
)
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings as urllib3_disable_warnings
from ciaops import Parser, TICollections, TIRequestParams
import ast
import dataclasses
import GroupIBTIA
import inspect
import threading
from json import load, loads
import json
from packaging.version import Version
import hashlib
import itertools
import os
from pathlib import Path
import random
import re
import requests
import time
from datetime import UTC, datetime
from types import SimpleNamespace
from CommonServerPython import DemistoException

realpath = os.path.join(os.path.dirname(os.path.realpath(__file__)))

with open(f"{realpath}/test_data/main_collections_examples.json") as example:
    COLLECTIONS_RAW_JSON = load(example)

with open(f"{realpath}/test_data/search_example.json") as example:
    SEARCH_RAW_JSON = load(example)

with open(f"{realpath}/test_data/available_collections_example.json") as example:
    AVAILABLE_COLLECTIONS_RAW_JSON = load(example)

urllib3_disable_warnings(InsecureRequestWarning)

# The parse keys and the observables of every collection the integration reads, from its catalog.
MAPPING = {name: spec.mapping for name, spec in COLLECTIONS.items() if spec.mapping}
INDICATORS_TYPES = {name: spec.indicator_types for name, spec in COLLECTIONS.items() if spec.indicator_types}
PORTAL_LINKS = TICollections.PORTAL_LINKS
DEFAULT_SOURCE_RELIABILITY = Settings.DEFAULT_SOURCE_RELIABILITY

COLLECTION_NAMES = [
    "compromised/account_group",
    "compromised/bank_card_group",
    "osi/git_repository",
    "osi/vulnerability",
    "attacks/ddos",
    "attacks/deface",
    "attacks/phishing_group",
    "attacks/phishing_kit",
    "suspicious_ip/tor_node",
    "suspicious_ip/open_proxy",
    "suspicious_ip/socks_proxy",
    "suspicious_ip/vpn",
    "suspicious_ip/scanner",
    "malware/cnc",
    "hi/threat",
    "hi/threat_actor",
    "apt/threat",
    "apt/threat_actor",
    "malware/malware",
    "osi/public_leak",
    "compromised/breacheddb",
    "compromised/access",
    "compromised/messenger",
    "compromised/discord",
    "darkweb/forums",
    "hi/open_threats",
]


@pytest.fixture(scope="function", params=COLLECTION_NAMES)
def session_fixture(request):
    """Each name of COLLECTION_NAMES with a Client of the test URL, credentials and headers; one client serves every
    collection."""
    return request.param, Client(
        base_url="https://example.com",
        auth=("example@example.com", "exampleAPI_TOKEN"),
        verify=True,
        headers={"Accept": "*/*"},
    )


@pytest.fixture(scope="function")
def single_session_fixture():
    """A Client of the test URL, credentials and headers, for tests that need no collection."""
    return Client(
        base_url="https://example.com",
        auth=("example@example.com", "exampleAPI_TOKEN"),
        verify=True,
        headers={"Accept": "*/*"},
    )


# The default settings, except that internal and reserved addresses are looked up:
# the test addresses are documentation ranges, which a default instance does not look up.
DEFAULT_SETTINGS = Settings.from_params({"lookup_internal_addresses": True})
NO_MASKS = Masking(PasswordMask(), CardDataMask())


# The client's own fork, before the fixture below replaces it.
REAL_FORK = Client.fork


@pytest.fixture(autouse=True)
def _one_client_for_every_thread(mocker):
    """Every thread uses the test's client."""
    mocker.patch.object(Client, "fork", lambda self: self)
    # A suspicious_ip listing is read by id; a test that lists none reads none.
    mocker.patch.object(ReputationCommand, "_listing", return_value=[])
    # A request no test answers fails at once instead of waiting on the network.
    mocker.patch.object(GroupIBTIA.TIPoller, "send_request", side_effect=RuntimeError("no network in tests"))


def settings_with(**overrides: Any) -> Settings:
    """The settings of a default instance, with ``overrides``."""
    return dataclasses.replace(DEFAULT_SETTINGS, **overrides)


def fetch_settings(
    incident_collections: Any,
    first_fetch_time: str = "3 days",
    max_requests: int = 3,
    hunting_rules: bool | int = False,
    combolist: bool = False,
    unique: bool = False,
    enable_probable_corporate_access: bool = False,
    skip_updated_incidents: bool = False,
    dedup_lookback_days: int = 365,
    pass_flagged_phishing_groups: bool = False,
    masking: Masking = NO_MASKS,
) -> Settings:
    """The settings of an instance that fetches ``incident_collections``."""
    return settings_with(
        incident_collections=incident_collections,
        first_fetch=first_fetch_time,
        max_requests=max_requests,
        hunting_rules=bool(hunting_rules),
        combolist=combolist,
        unique=unique,
        enable_probable_corporate_access=enable_probable_corporate_access,
        skip_updated_incidents=skip_updated_incidents,
        dedup_lookback_days=dedup_lookback_days,
        pass_flagged_phishing_groups=pass_flagged_phishing_groups,
        masking=masking,
    )


def fetch_incidents(
    client: Client,
    last_run: Any,
    incident_collections: Any,
    password_mask: PasswordMask | None = None,
    card_mask: CardDataMask | None = None,
    clock: Any = None,
    **settings: Any,
) -> tuple[dict, list]:
    """One fetch-incidents run of an instance with the given settings and masks."""
    masking = Masking(password_mask or PasswordMask(), card_mask or CardDataMask())
    return FetchIncidentsCommand(client, fetch_settings(incident_collections, masking=masking, **settings), clock).run(last_run)


def open_feed(client: Client, collection_name: str, hunting_rules: int | None = None, cursor: str | None = None, **settings: Any):
    """The pages and start cursor a fetch opens one collection with."""
    return FetchIncidentsCommand(client, fetch_settings([collection_name], **settings))._open_feed(
        collection_name=collection_name, cursor=cursor, hunting_rules=hunting_rules
    )


def seen_cache(clock: Any = None) -> FetchIncidentsCommand:
    """A fetch whose duplicate cache reads ``clock``."""
    return FetchIncidentsCommand(MagicMock(), DEFAULT_SETTINGS, clock)


def read_record(client: Client, collection_name: str, record_id: str, masker: Masking = NO_MASKS) -> dict | None:
    """The record a lookup reads for an id, None when the collection has none."""
    return LookupCommand(collection_name, client, settings_with(masking=masker))._record(collection_name, record_id)


def lookup(
    client: Client,
    collection_name: str,
    args: dict,
    masker: Masking = NO_MASKS,
    create_relationships: bool = True,
) -> list[CommandResults]:
    """The entries of a gibti-get-*-info command."""
    settings = settings_with(masking=masker, create_relationships=create_relationships)
    return LookupCommand(collection_name, client, settings).run(args)


def present_record(
    client: Client,
    collection_name: str,
    record_id: str,
    masker: Masking = NO_MASKS,
    create_relationships: bool = True,
):
    """What a lookup shows of the record of an id: the context record, its table, its nested tables, its indicators."""
    record_entry, *entries = lookup(client, collection_name, {"id": record_id}, masker, create_relationships)
    return SimpleNamespace(
        record=record_entry.outputs,
        readable_output=record_entry.readable_output,
        tables=[entry for entry in entries if entry.outputs is None],
        indicators=[entry for entry in entries if entry.outputs is not None],
    )


def threat_lookup(client: Client, base: str, args: dict) -> list[CommandResults]:
    """The entries of gibti-get-threat-info (``base`` "threat") or gibti-get-threat-actor-info."""
    return LookupCommand(base, client, settings_with(create_relationships=True)).run(args)


def reputation_settings(**overrides: Any) -> Settings:
    """The settings of a default instance whose reputation commands are enabled, with ``overrides``."""
    overrides.setdefault("enabled_reputation_commands", frozenset({"ip", "domain", "file", "url"}))
    return settings_with(**overrides)


def reputation(client: Client, kind: str, args: dict, override: str | None = None, **settings: Any) -> list[CommandResults]:
    """The results of the ip, domain, file or url command. ``override`` is the Source Reliability every result carries;
    None is "Ignore Source Reliability override" on, the reliability computed from the matched collections."""
    if override is None:
        settings.setdefault("use_computed_reliability", True)
    else:
        settings["source_reliability"] = override
    results = ReputationCommand(kind, client, reputation_settings(**settings)).run(args)
    assert isinstance(results, list)
    return results


def evidence(client: Client) -> ReputationCommand:
    """A reputation command, for what it reads of the collections."""
    return ReputationCommand("ip", client, reputation_settings())


def score_risk(client: Client, kind: str, args: dict) -> list[CommandResults]:
    """The results of gibti-ip-scoring (``kind`` "ip") or gibti-domain-scoring."""
    return ScoringCommand(kind, client, DEFAULT_SETTINGS).run(args)


def score_cves(client: Client, args: dict) -> list[CommandResults]:
    """The results of gibti-cve-scoring."""
    return ScoringCommand("cve", client, DEFAULT_SETTINGS).run(args)


def global_search(client: Any, args: dict) -> CommandResults:
    """The result of gibti-global-search."""
    return SearchCommand("global", client, DEFAULT_SETTINGS).run(args)


def local_search(client: Any, args: dict, masker: Masking = NO_MASKS) -> CommandResults:
    """The result of gibti-local-search."""
    return SearchCommand("local", client, settings_with(masking=masker)).run(args)


def run_main(mocker, params: dict, command: str, args: dict | None = None) -> dict[str, MagicMock]:
    """main() of an instance with ``params`` running ``command``; the mocks of return_results, return_error and return_warning."""
    mocker.patch.object(GroupIBTIA.demisto, "params", return_value=params)
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value=args or {})
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value=command)
    calls = {
        "results": mocker.patch.object(GroupIBTIA, "return_results"),
        "error": mocker.patch.object(GroupIBTIA, "return_error"),
        "warning": mocker.patch.object(GroupIBTIA, "return_warning"),
    }
    GroupIBTIA.main()
    return calls


MAIN_PARAMS = {"url": "https://example.com", "credentials": {"identifier": "u", "password": "p"}}


def test_a_fetch_of_no_collection_answers_a_list(mocker, session_fixture):
    collection_name, client = session_fixture
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=[COLLECTIONS_RAW_JSON[collection_name]])
    next_run, incidents = fetch_incidents(
        client=client, last_run={}, first_fetch_time="3 days", incident_collections=[], max_requests=3, hunting_rules=False
    )
    assert isinstance(incidents, list)


def test_a_masked_card_fetch_makes_one_incident_keyed_by_the_record_id_and_stores_the_cursor_as_text(
    mocker, single_session_fixture
):
    collection_name = "compromised/masked_card"
    client = single_session_fixture
    mock_portion = MagicMock()
    mock_portion.sequpdate = 1592219410029000
    mock_portion.portion_size = 1
    mock_portion.count = 1
    mock_portion.parse_portion.return_value = [
        {
            "id": "cccccccccccccccccccccccccccccccccccccccc",
            "name": "000000XXXXXXXXXX",
            "number": "000000XXXXXXXXXX",
            "issuer": None,
            "type": None,
            "payment_system": None,
            "validThru": "12/49",
            "address": None,
            "email": None,
            "owner_name": None,
            "phone": None,
            "dateDetected": "2020-05-22T17:04:25+00:00",
            "dateCompromised": "2020-05-15T09:17:45+00:00",
            "malware_name": "ExampleSniffer",
            "portalLink": "https://portal.example.com/cd/cards?id=cccccccccccccccccccccccccccccccccccccccc",
            "evaluation": {
                "admiraltyCode": "A2",
                "credibility": 80,
                "reliability": 90,
                "severity": "red",
                "tlp": "red",
            },
            "sourceType": "Card shop",
            "threat_actor_id": None,
            "threat_actor_name": None,
            "threat_actor_is_apt": None,
            "indicators": {
                "cnc_url": None,
                "cnc_domain": "cards-shop.example",
                "cnc_ipv4_ip": "198.51.100.11",
                "cnc_ipv4_asn": "AS64496",
                "cnc_ipv4_country_name": "United States",
                "cnc_ipv4_region": "North America",
            },
        }
    ]

    mocker.patch.object(
        client,
        "granted_collections",
        return_value=[{"collection": collection_name, "huntingRulesUsed": True}],
    )
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([mock_portion], None))

    next_run, incidents = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=[collection_name],
        max_requests=3,
        hunting_rules=0,
    )

    assert len(incidents) == 1
    assert incidents[0]["dbotMirrorId"] == "cccccccccccccccccccccccccccccccccccccccc"
    assert next_run["last_fetch"][collection_name] == "1592219410029000"


def test_main_reports_an_unknown_command_through_return_error():
    with (
        pytest.raises(SystemExit),
        patch.object(
            GroupIBTIA.demisto,
            "params",
            return_value={
                "credentials": {"identifier": "user@example.com", "password": "token"},
                "url": "https://example.com",
                "proxy": False,
                "insecure": False,
                "incident_collections": [],
                "first_fetch": "3 days",
                "max_fetch": 1,
                "limit": 10,
            },
        ),
        patch.object(GroupIBTIA.demisto, "args", return_value={}),
        patch.object(GroupIBTIA.demisto, "command", return_value="non-existent-command"),
        patch.object(GroupIBTIA, "Client", autospec=True),
        patch.object(GroupIBTIA, "return_error", side_effect=SystemExit(1)),
    ):
        GroupIBTIA.main()


def test_a_disabled_ip_command_answers_one_quiet_result_without_enrichment(mocker):
    mocker.patch.object(
        GroupIBTIA.demisto,
        "params",
        return_value={
            "credentials": {"identifier": "user@example.com", "password": "token"},
            "url": "https://example.com",
            "proxy": False,
            "insecure": False,
            # The setting is an allow-list: empty disables every reputation command.
            "enabled_reputation_commands": [],
            "incident_collections": [],
            "first_fetch": "3 days",
            "max_fetch": 1,
            "limit": 10,
        },
    )
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value={"ip": "198.51.100.88"})
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="ip")

    mocker.patch.object(GroupIBTIA, "Client", autospec=True)
    ip_impl = mocker.patch.object(GroupIBTIA.ReputationCommand, "_result", autospec=True)
    rr = mocker.patch.object(GroupIBTIA, "return_results", autospec=True)
    mocker.patch.object(GroupIBTIA, "return_error", side_effect=AssertionError("return_error is not called"))

    GroupIBTIA.main()

    assert ip_impl.call_count == 0
    assert rr.call_count == 1
    result_obj = rr.call_args[0][0]
    assert isinstance(result_obj, CommandResults)
    assert "is disabled" in (result_obj.readable_output or "").lower()


def test_reputation_commands_are_disabled_when_the_setting_is_missing(mocker):
    mocker.patch.object(
        GroupIBTIA.demisto,
        "params",
        return_value={
            "credentials": {"identifier": "user@example.com", "password": "token"},
            "url": "https://example.com",
            "proxy": False,
            "insecure": False,
            "incident_collections": [],
            "first_fetch": "3 days",
            "max_fetch": 1,
            "limit": 10,
        },
    )
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value={"ip": "198.51.100.88"})
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="ip")

    mocker.patch.object(GroupIBTIA, "Client", autospec=True)
    ip_impl = mocker.patch.object(GroupIBTIA.ReputationCommand, "_result", autospec=True)
    rr = mocker.patch.object(GroupIBTIA, "return_results", autospec=True)
    mocker.patch.object(GroupIBTIA, "return_error", side_effect=AssertionError("return_error is not called"))

    GroupIBTIA.main()

    assert ip_impl.call_count == 0
    assert rr.call_count == 1


def test_an_enabled_ip_command_runs_the_lookup(mocker):
    mocker.patch.object(
        GroupIBTIA.demisto,
        "params",
        return_value={
            "credentials": {"identifier": "user@example.com", "password": "token"},
            "url": "https://example.com",
            "proxy": False,
            "insecure": False,
            "enabled_reputation_commands": ["ip"],
            "incident_collections": [],
            "first_fetch": "3 days",
            "max_fetch": 1,
            "limit": 10,
        },
    )
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value={"ip": "198.51.100.88"})
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="ip")

    mocker.patch.object(GroupIBTIA, "Client", autospec=True)
    ip_impl = mocker.patch.object(
        GroupIBTIA.ReputationCommand,
        "run",
        autospec=True,
        return_value=CommandResults(readable_output="ok"),
    )
    rr = mocker.patch.object(GroupIBTIA, "return_results", autospec=True)
    mocker.patch.object(GroupIBTIA, "return_error", side_effect=AssertionError("return_error is not called"))

    GroupIBTIA.main()

    assert ip_impl.call_count == 1
    assert rr.call_count == 1


def test_the_global_search_writes_under_gibti_search_global_keyed_by_query(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client.poller, "global_search", return_value=SEARCH_RAW_JSON)
    test_query = {"query": "198.51.100.88"}
    result = global_search(client, test_query)

    assert result.outputs_prefix == "GIBTI.search.global"
    assert result.outputs_key_field == "query"


def test_the_available_collections_are_a_list_under_gibti_otherinfo(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client, "available_collections", return_value=frozenset(AVAILABLE_COLLECTIONS_RAW_JSON))
    result = AvailableCollectionsCommand(client).run()

    assert result.outputs_prefix == "GIBTI.OtherInfo"
    assert result.outputs_key_field == "collections"
    assert isinstance(result.outputs["collections"], list)


@pytest.fixture
def mock_client():
    """A client whose collection searches answer nothing."""
    client = MagicMock()
    client.search_collection.return_value = []
    return client


def test_a_local_search_without_results_answers_an_empty_table(mock_client):
    args = {"query": "test_query", "collection_name": "malware/cnc"}

    result = local_search(mock_client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "GIBTI.search.local"
    assert result.outputs_key_field == "id"
    assert result.outputs == []
    assert "Search results" in result.readable_output


def test_a_local_search_lists_one_entry_per_record_with_its_name(mock_client):
    mock_client.search_collection.return_value = [
        MagicMock(
            parse_portion=lambda keys, as_json: [
                {"id": "123", "name": "Test Result"},
                {"id": "456", "name": "Another Result"},
            ],
            raw_dict={"items": [{"id": "123", "seqUpdate": 11}, {"id": "456", "seqUpdate": 12}]},
        )
    ]

    args = {"query": "test_query", "collection_name": "malware/cnc"}

    result = local_search(mock_client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "GIBTI.search.local"
    assert result.outputs_key_field == "id"
    outputs = cast(list[dict[str, Any]], result.outputs)
    assert len(outputs) == 2
    assert outputs[0]["id"] == "123"
    assert outputs[0]["additional_info"] == "Name: Test Result"
    assert "Search results" in result.readable_output
    assert "Name: Test Result" in result.readable_output
    assert "Name: Another Result" in result.readable_output


def test_the_grid_rows_of_an_empty_block_are_one_empty_row():
    assert IncidentBuilder.rows({}) == [{}]


def test_grid_rows_are_one_per_list_element_with_scalars_repeated_and_empty_lists_as_none():
    input_dict: dict[str, Any] = {"a": [1, 2], "b": "x", "c": []}
    result = IncidentBuilder.rows(cast(Any, input_dict))
    assert len(result) == 2
    assert result[0] == {"a": 1, "b": "x", "c": None}
    assert result[1] == {"a": 2, "b": "x", "c": None}


def test_grid_keys_lose_their_underscores_and_case():
    data = [{"Test_Key": 1, "another_key": 2}]
    result = IncidentBuilder._lowercase_keys(data)
    assert result == [{"testkey": 1, "anotherkey": 2}]


def test_blank_values_of_a_block_become_none():
    data = {"a": "", "b": "value", "c": {"d": ""}}
    result = IncidentBuilder._blank_to_none(data)
    assert result == {"a": None, "b": "value", "c": {"d": None}}


def test_blank_values_of_a_list_become_none():
    data: list[Any] = ["", "x", [], [{}]]
    result = IncidentBuilder._blank_to_none(cast(Any, data))
    assert result == [None, "x", None, [{}]]


def test_an_empty_list_or_a_list_of_empty_lists_is_none():
    assert IncidentBuilder._blank_to_none(cast(Any, [])) is None
    assert IncidentBuilder._blank_to_none(cast(Any, [[]])) is None


def test_a_block_of_empty_lists_counts_as_empty():
    data = {"a": [], "b": {"c": []}}
    assert IncidentBuilder._all_lists_empty(data) is True


def test_a_block_with_a_filled_list_is_not_empty():
    data = {"a": [1], "b": {}}
    assert IncidentBuilder._all_lists_empty(data) is False


def test_a_search_date_is_written_as_the_update_feed_takes_it():
    assert SearchCommand._date("2020-01-01", "date") == "2020-01-01T00:00:00Z"


def test_a_search_date_with_an_offset_is_converted_to_utc(mocker):
    mocker.patch.object(GroupIBTIA, "dateparser_parse", side_effect=lambda value: datetime.fromisoformat(value))
    assert SearchCommand._date("2020-01-01T05:00:00+03:00", "date_from") == "2020-01-01T02:00:00Z"


def test_a_search_date_that_is_no_date_is_refused():
    with pytest.raises(Exception):
        SearchCommand._date("invalid", "date")


def test_grid_cells_join_their_lists_and_an_empty_list_is_none():
    data: list[dict[str, Any]] = [{"x": [1, 2], "y": "a"}, {"x": []}]
    result = IncidentBuilder._join_cells(cast(Any, data))
    assert result[0]["x"] == "1, 2"
    assert result[1]["x"] is None


def test_a_collection_name_that_is_not_retired_passes_validation():
    CollectionSpec.validate("valid_collection")


def _get_date_field_for_collection(collection_name: str) -> str:
    """The first of the collection's occurred_fields."""
    return CollectionSpec.of(collection_name).occurred_fields[0]


def test_a_fetch_opens_the_collection_once_with_combolist_and_unique(mocker, session_fixture):
    collection_name, client = session_fixture
    mock_portions = []
    mock_portion = MagicMock()
    mock_portion.sequpdate = 12345
    mock_portion.portion_size = 10
    mock_portion.count = 10
    # A record IncidentBuilder accepts: id, name, evaluation and the occurred-date field of the collection.
    date_field = _get_date_field_for_collection(collection_name)
    mock_incident_data = {
        "id": "test-id",
        "name": "test",
        "evaluation": {"severity": "green"},
    }
    mock_incident_data[date_field] = "2023-01-01T00:00:00+00:00"
    # A breached record carries its e-mail.
    if collection_name == "compromised/breacheddb":
        mock_incident_data["emails"] = ["test@example.com"]
    mock_portion.parse_portion.return_value = [mock_incident_data]
    mock_portions.append(mock_portion)

    mocker.patch.object(client, "available_collections", return_value=AVAILABLE_COLLECTIONS_RAW_JSON)
    mocker.patch.object(
        client,
        "granted_collections",
        return_value=[{"collection": collection_name, "huntingRulesUsed": True}],
    )
    opener = mocker.patch.object(
        GroupIBTIA.FetchIncidentsCommand, "_open_feed", autospec=True, return_value=(mock_portions, None)
    )

    next_run, incidents = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=[collection_name],
        max_requests=3,
        hunting_rules=0,
        combolist=True,
        unique=True,
        enable_probable_corporate_access=False,
    )

    opener.assert_called_once()
    settings = opener.call_args.args[0]._settings
    assert settings.combolist is True
    assert settings.unique is True
    assert isinstance(incidents, list)


def test_a_first_fetch_asks_sequence_list_once_for_the_collection(mocker, session_fixture):
    collection_name, client = session_fixture
    mock_portions = []
    mock_portion = MagicMock()
    mock_portion.sequpdate = 12345
    mock_portion.portion_size = 10
    mock_portion.count = 10
    date_field = _get_date_field_for_collection(collection_name)
    mock_incident_data = {
        "id": "test-id",
        "name": "test",
        "evaluation": {"severity": "green"},
    }
    mock_incident_data[date_field] = "2023-01-01T00:00:00+00:00"
    if collection_name == "compromised/breacheddb":
        mock_incident_data["emails"] = ["test@example.com"]
    mock_portion.parse_portion.return_value = [mock_incident_data]
    mock_portion.count = 1
    mock_portion.raw_dict = {"count": 1, "items": [{**mock_incident_data, "seqUpdate": 12345}], "seqUpdate": 12345}
    mock_portion.keys = mock_portion.iocs_keys = None
    mock_portions.append(mock_portion)

    resolved_sequpdate = 10000
    mocker.patch.object(
        client.poller,
        "get_seq_update_dict",
        return_value={collection_name: resolved_sequpdate},
    )
    mocker.patch.object(client, "available_collections", return_value=AVAILABLE_COLLECTIONS_RAW_JSON)
    mocker.patch.object(
        client,
        "granted_collections",
        return_value=[{"collection": collection_name, "huntingRulesUsed": True}],
    )
    mocker.patch.object(
        client.poller,
        "create_update_generator",
        return_value=mock_portions,
    )

    next_run, incidents = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="2023-01-01",
        incident_collections=[collection_name],
        max_requests=3,
        hunting_rules=0,
        combolist=False,
        unique=False,
        enable_probable_corporate_access=False,
    )

    client.poller.get_seq_update_dict.assert_called_once()
    assert isinstance(incidents, list)


def test_a_fetch_stores_the_cursor_of_the_page_it_read(mocker, session_fixture):
    collection_name, client = session_fixture
    mock_portions = []
    mock_portion = MagicMock()
    last_fetch_value = 10000
    sequpdate_value = 15000
    mock_portion.sequpdate = sequpdate_value
    mock_portion.portion_size = 10
    mock_portion.count = 10
    date_field = _get_date_field_for_collection(collection_name)
    mock_incident_data = {
        "id": "test-id",
        "name": "test",
        "evaluation": {"severity": "green"},
    }
    mock_incident_data[date_field] = "2023-01-01T00:00:00+00:00"
    if collection_name == "compromised/breacheddb":
        mock_incident_data["emails"] = ["test@example.com"]
    mock_portion.parse_portion.return_value = [mock_incident_data]
    mock_portions.append(mock_portion)

    mocker.patch.object(client, "available_collections", return_value=AVAILABLE_COLLECTIONS_RAW_JSON)
    mocker.patch.object(
        client,
        "granted_collections",
        return_value=[{"collection": collection_name, "huntingRulesUsed": True}],
    )
    mocker.patch.object(
        GroupIBTIA.FetchIncidentsCommand,
        "_open_feed",
        return_value=(mock_portions, last_fetch_value),
    )

    next_run, incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": {collection_name: last_fetch_value}},
        first_fetch_time="3 days",
        incident_collections=[collection_name],
        max_requests=3,
        hunting_rules=0,
        combolist=False,
        unique=False,
        enable_probable_corporate_access=False,
    )

    assert collection_name in next_run["last_fetch"]
    effective_last_fetch = next_run["last_fetch"][collection_name]
    assert int(str(effective_last_fetch)) == max(last_fetch_value, sequpdate_value)


def test_a_fetch_reads_max_requests_pages_and_makes_one_incident_per_record(mocker, session_fixture):
    """A fetch reads 'Number of requests per collection' pages (darkweb/forums one page) and keeps a cursor for the collection."""
    collection_name, client = session_fixture
    mock_portions = []
    date_field = _get_date_field_for_collection(collection_name)
    for i in range(5):
        mock_portion = MagicMock()
        mock_portion.sequpdate = 10000 + i * 1000
        mock_portion.portion_size = 10
        mock_portion.count = 10
        mock_incident_data = {
            "id": f"test-id-{i}",
            "name": f"test-{i}",
            "evaluation": {"severity": "green"},
        }
        mock_incident_data[date_field] = "2023-01-01T00:00:00+00:00"
        mock_portion.parse_portion.return_value = [mock_incident_data]
        mock_portions.append(mock_portion)

    mocker.patch.object(client, "available_collections", return_value=AVAILABLE_COLLECTIONS_RAW_JSON)
    mocker.patch.object(
        client,
        "granted_collections",
        return_value=[{"collection": collection_name, "huntingRulesUsed": True}],
    )
    mocker.patch.object(
        GroupIBTIA.FetchIncidentsCommand,
        "_open_feed",
        return_value=(mock_portions, None),
    )

    max_requests = 3
    next_run, incidents = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=[collection_name],
        max_requests=max_requests,
        hunting_rules=0,
        combolist=False,
        unique=False,
        enable_probable_corporate_access=False,
    )

    # A collection whose feed answers the lowest cursor of a page is read one page per run.
    expected = 1 if COLLECTIONS[collection_name].cursor_from_items else max_requests
    assert len(incidents) == expected
    assert collection_name in next_run["last_fetch"]


def test_the_feed_is_opened_with_combolist_and_unique_as_ones(mocker, single_session_fixture):
    client = single_session_fixture
    collection_name = "compromised/account_group"

    mock_portions = []
    mock_portion = MagicMock()
    mock_portion.sequpdate = 12346
    mock_portions.append(mock_portion)

    mocker.patch.object(
        client.poller,
        "get_seq_update_dict",
        return_value={collection_name: 12345},
    )
    mocker.patch.object(
        client.poller,
        "create_update_generator",
        return_value=mock_portions,
    )

    portions, last_fetch = open_feed(
        client,
        collection_name=collection_name,
        hunting_rules=0,
        enable_probable_corporate_access=False,
        unique=True,
        combolist=True,
        cursor=None,
        first_fetch_time="2023-01-01",
    )

    client.poller.create_update_generator.assert_called_once()
    call_kwargs = client.poller.create_update_generator.call_args[1]
    request_params = call_kwargs["request_params"]
    assert isinstance(request_params, TIRequestParams)
    assert request_params.combolist == 1
    assert request_params.unique == 1
    assert request_params.limit == client.limit
    assert call_kwargs["rate_limit_delay"] == client.rate_limit_delay
    assert list(portions) == mock_portions


def test_the_feed_is_opened_from_the_sequence_list_cursor_without_the_date(mocker, single_session_fixture):
    client = single_session_fixture
    collection_name = "compromised/account_group"
    resolved_sequpdate = 12345

    mock_portions = []
    mock_portion = MagicMock()
    mock_portions.append(mock_portion)

    mocker.patch.object(
        client.poller,
        "get_seq_update_dict",
        return_value={collection_name: resolved_sequpdate},
    )
    mocker.patch.object(
        client.poller,
        "create_update_generator",
        return_value=mock_portions,
    )

    portions, last_fetch = open_feed(
        client,
        collection_name=collection_name,
        hunting_rules=0,
        enable_probable_corporate_access=False,
        unique=False,
        combolist=False,
        cursor=None,
        first_fetch_time="2023-01-01",
    )

    client.poller.get_seq_update_dict.assert_called_once()
    call_kwargs = client.poller.create_update_generator.call_args[1]
    assert call_kwargs["sequpdate"] == resolved_sequpdate
    assert call_kwargs["request_params"].date_from is None


def test_a_date_filtered_collection_is_opened_from_the_date_without_a_cursor(mocker, single_session_fixture):
    """attacks/ddos filters by df: without a cursor the feed starts from the date."""
    client = single_session_fixture
    collection_name = "attacks/ddos"

    mock_portions = []
    mock_portion = MagicMock()
    mock_portions.append(mock_portion)

    mocker.patch.object(
        client.poller,
        "get_seq_update_dict",
        return_value={},
    )
    mocker.patch.object(
        client.poller,
        "create_update_generator",
        return_value=mock_portions,
    )

    portions, last_fetch = open_feed(
        client,
        collection_name=collection_name,
        hunting_rules=0,
        enable_probable_corporate_access=False,
        unique=False,
        combolist=False,
        cursor=None,
        first_fetch_time="2023-01-01",
    )

    client.poller.get_seq_update_dict.assert_called_once()
    call_kwargs = client.poller.create_update_generator.call_args[1]
    assert call_kwargs["request_params"].date_from == "2023-01-01"
    assert call_kwargs.get("sequpdate") is None


def test_breacheddb_is_opened_as_a_seq_update_collection_with_hunting_rules_always_on(mocker, single_session_fixture):
    """compromised/breacheddb is an ordinary seqUpdate collection on ciaops; only hunting rules are always on."""
    client = single_session_fixture
    collection_name = "compromised/breacheddb"
    mock_portions = [MagicMock(sequpdate=12346)]

    mocker.patch.object(client.poller, "get_seq_update_dict", return_value={collection_name: 12345})
    mocker.patch.object(client.poller, "create_update_generator", return_value=mock_portions)

    portions, last_fetch = open_feed(
        client,
        collection_name=collection_name,
        hunting_rules=FetchIncidentsCommand(client, fetch_settings([]))._hunting_rules(collection_name),
        enable_probable_corporate_access=False,
        unique=False,
        combolist=False,
        cursor=None,
        first_fetch_time="2023-01-01",
    )

    client.poller.create_update_generator.assert_called_once()
    call_kwargs = client.poller.create_update_generator.call_args[1]
    assert call_kwargs["collection_name"] == collection_name
    assert call_kwargs["request_params"].apply_hunting_rules == 1
    assert call_kwargs["sequpdate"] == 12345
    assert list(portions) == mock_portions
    assert last_fetch == 12345


def test_a_breached_fetch_makes_one_incident_and_stores_the_page_cursor_as_text(mocker, single_session_fixture):
    collection_name = "compromised/breacheddb"
    client = single_session_fixture
    mock_portion = MagicMock()
    mock_portion.sequpdate = 12345
    mock_portion.portion_size = 1
    mock_portion.count = 1
    mock_portion.parse_portion.return_value = [
        {
            "id": "breached-id",
            "name": ["Email collection"],
            "emails": ["user@example.com"],
            "uploadTime": "2024-10-01T01:45:13",
            "evaluation": {"severity": "green"},
        }
    ]

    mocker.patch.object(
        client,
        "granted_collections",
        return_value=[{"collection": collection_name, "huntingRulesUsed": True}],
    )
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([mock_portion], None))

    next_run, incidents = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=[collection_name],
        max_requests=3,
        hunting_rules=0,
    )

    assert len(incidents) == 1
    assert next_run["last_fetch"][collection_name] == "12345"


def test_a_breached_lookup_links_the_portal_by_id(mocker, single_session_fixture):
    """The API has no GET /compromised/breacheddb/{id}: the lookup sends neither that request nor an update feed search."""
    client = single_session_fixture
    mocker.patch.object(
        client.poller,
        "send_request",
        return_value={
            "id": ["breached-id"],
            "email": ["user@example.com"],
            "uploadTime": "2024-10-01T01:45:13",
            "evaluation": {"severity": "green"},
        },
    )
    collection_name = "compromised/breacheddb"
    search = mocker.patch.object(client, "search_collection")
    by_id = mocker.patch.object(client.poller, "search_feed_by_id")

    feed = present_record(client, collection_name, "breached-id").record

    assert feed["portalLink"] == f"{PORTAL_LINKS[collection_name]}breached-id"
    assert "user@example.com" not in feed["portalLink"]
    assert feed["id"] == "breached-id"
    search.assert_not_called()
    by_id.assert_not_called()


def test_a_lookup_keeps_nested_objects_in_the_context(mocker, single_session_fixture):
    """The playbook reads GIBTI.GIBCybercriminalThreatActorProfile.reports.id: nested objects go to the
    War Room as separate tables and stay in the context outputs."""
    client = single_session_fixture
    portion = MagicMock()
    portion.parse_portion.return_value = [
        {
            "id": "actor-1",
            "name": "examplefox",
            "reports": {"id": ["r-1", "r-2"], "name": ["Report 1", "Report 2"], "datePublished": ["2026-01-01", "2026-02-01"]},
            "evaluation": {"severity": "red"},
        }
    ]
    mocker.patch.object(client.poller, "search_feed_by_id", return_value=portion)
    view = present_record(client, "hi/threat_actor", "actor-1")
    assert view.record["reports"]["id"] == ["r-1", "r-2"]
    # one entry for the object, one row per report; the record's own table has no reports column
    [reports] = view.tables
    assert "Report 1" in reports.readable_output
    assert "Report 2" in reports.readable_output
    assert "reports" not in view.readable_output.split("\n")[1]


@pytest.mark.parametrize(
    "failure, hinted",
    [("HTTP 400: Bad Credentials or Wrong request.", True), ("HTTP 403: Something is wrong with your account.", False)],
)
def test_local_search_wraps_api_refusals_in_a_readable_error(mocker, single_session_fixture, failure, hinted):
    """An HTTP 400 to a search with a date window names the 30-day window of trial and POC accounts; an HTTP 403 does not."""
    from ciaops.exception import ConnectionException

    client = single_session_fixture

    def refused(*_args, **_kwargs):
        raise ConnectionException(failure)
        yield  # pragma: no cover - makes this a generator like the one ciaops returns

    mocker.patch.object(client, "search_collection", return_value=refused())
    with pytest.raises(DemistoException, match="The search in hi/threat failed") as error:
        local_search(client, {"collection_name": "hi/threat", "query": "ransomware", "date_from": "2026-01-01"})
    assert ("some collections serve only the last 30 days" in str(error.value)) is hinted


def test_a_breached_id_the_by_id_route_does_not_find_is_not_found(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client.poller, "send_request", side_effect=GroupIBTIA.NotFoundException("HTTP 404: Not found."))
    mocker.patch.object(client, "search_collection", return_value=iter([]))
    with pytest.raises(DemistoException, match="No record with id 'nope' was found in compromised/breacheddb"):
        present_record(client, "compromised/breacheddb", "nope")


def test_a_404_on_the_get_by_id_is_not_found(mocker, single_session_fixture):
    from ciaops.exception import NotFoundException

    client = single_session_fixture
    mocker.patch.object(
        client.poller,
        "search_feed_by_id",
        side_effect=NotFoundException("HTTP 404: Not found. There is no such data on server or you are using wrong endpoint."),
    )
    with pytest.raises(DemistoException, match="No record with id 'deadbeef' was found in malware/cnc"):
        present_record(client, "malware/cnc", "deadbeef")


def test_a_5xx_on_the_get_by_id_is_a_failed_lookup(mocker, single_session_fixture):
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=ConnectionException(SERVER_ERROR))
    with pytest.raises(DemistoException, match=r"The lookup of id 'x' in malware/cnc failed: HTTP 500"):
        present_record(client, "malware/cnc", "x")


ACCOUNT_REFUSAL = "HTTP 403: Something is wrong with your account."
SERVER_ERROR = "HTTP 500: There are some troubles on server with your request."
SEQUENCE_LIST_DOWN = "Retries exhausted for https://api.example.com/api/v2/sequence_list: too many 502 error responses"
UPDATE_FEED_DOWN = "Retries exhausted for https://api.example.com/api/v2/malware/cnc/updated: too many 502 error responses"


@pytest.mark.parametrize("collection", ["hi/threat_actor", "apt/threat_actor", "hi/threat", "apt/threat"])
@pytest.mark.parametrize("empty_feed", [[], [{}]], ids=["no portion", "empty portion"])
def test_a_refused_actor_or_report_the_update_feed_does_not_list_is_not_found(
    mocker, single_session_fixture, collection, empty_feed
):
    """Group-IB answers 403 for an actor profile or a report it has not published, and its update
    feed does not list it: the lookup says the id was not found instead of failing."""
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=ConnectionException(ACCOUNT_REFUSAL))
    portions = []
    for records in empty_feed:
        portion = MagicMock()
        portion.parse_portion.return_value = [records] if records else []
        portions.append(portion)
    search = mocker.patch.object(client, "search_collection", return_value=iter(portions))
    with pytest.raises(DemistoException, match=f"No record with id 'ab12' was found in {collection}"):
        lookup(client, collection, {"id": "ab12"})
    assert search.call_args.args == (collection,)
    assert search.call_args.kwargs["query"] == "id:ab12"


def test_a_refused_actor_the_update_feed_lists_is_read_from_it(mocker, single_session_fixture):
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=ConnectionException(ACCOUNT_REFUSAL))
    portion = MagicMock()
    portion.parse_portion.return_value = [{"id": "ab12", "name": "Crew One"}]
    search = mocker.patch.object(client, "search_collection", return_value=iter([portion]))
    feed = read_record(client, "hi/threat_actor", "ab12")
    assert feed["name"] == "Crew One"
    assert portion.parse_portion.call_args.kwargs["keys"] == MAPPING["hi/threat_actor"]
    assert search.call_args.kwargs == {"query": "id:ab12", "limit": 1}


def test_a_refusal_the_update_feed_repeats_stays_an_error(mocker, single_session_fixture):
    """A key without access to the collection is refused by the update feed too: that is an error
    of the instance, not a missing record."""
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=ConnectionException(ACCOUNT_REFUSAL))

    def refused(*_args, **_kwargs):
        raise ConnectionException(ACCOUNT_REFUSAL)
        yield  # pragma: no cover - makes this a generator like the one ciaops returns

    mocker.patch.object(client, "search_collection", return_value=refused())
    with pytest.raises(DemistoException, match=r"The lookup of id 'ab12' in apt/threat_actor failed: HTTP 403") as caught:
        read_record(client, "apt/threat_actor", "ab12")
    assert "No record with id" not in str(caught.value)


def test_only_a_403_on_an_actor_or_report_is_checked_against_the_update_feed(mocker, single_session_fixture):
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=ConnectionException(ACCOUNT_REFUSAL))
    search = mocker.patch.object(client, "search_collection")
    with pytest.raises(DemistoException, match=r"The lookup of id 'x' in malware/cnc failed: HTTP 403"):
        read_record(client, "malware/cnc", "x")
    # an actor lookup that fails for another reason is not a missing record either
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=ConnectionException(SERVER_ERROR))
    with pytest.raises(DemistoException, match=r"The lookup of id 'x' in hi/threat_actor failed: HTTP 500"):
        read_record(client, "hi/threat_actor", "x")
    search.assert_not_called()


def test_an_unpublished_actor_a_defacement_names_leaves_a_note_not_an_error(mocker, single_session_fixture):
    """The postprocessing playbook looks up the actors of a defacement; one Group-IB has not
    published is reported in the War Room and the playbook goes on."""
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=ConnectionException(ACCOUNT_REFUSAL))
    mocker.patch.object(client, "search_collection", side_effect=lambda *args, **kwargs: iter([]))
    [note] = threat_lookup(client, "threat_actor", {"id": "ab12", "isAPT": "false"})
    assert "Group-IB publishes no hi/threat_actor or apt/threat_actor record with id ab12" in note.readable_output
    assert note.raw_response["missing"] == ["ab12"]
    assert note.raw_response["refused"] == []
    assert note.outputs is None


def test_an_id_one_collection_does_not_publish_and_the_other_refuses_is_a_note(mocker, single_session_fixture):
    """A key without APT access: hi/threat_actor does not publish the actor, apt/threat_actor refuses
    (the GET and the update feed). The id is unpublished as far as the key can tell; the refusal is noted."""
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=ConnectionException(ACCOUNT_REFUSAL))

    def feed(collection, **_kwargs):
        if collection.startswith("apt/"):
            raise ConnectionException(ACCOUNT_REFUSAL)
        return iter([])

    mocker.patch.object(client, "search_collection", side_effect=feed)
    [note] = threat_lookup(client, "threat_actor", {"id": "ab12", "isAPT": "false"})
    assert note.raw_response["missing"] == ["ab12"]
    assert note.raw_response["refused"] == []
    assert note.raw_response["unread"] == [f"The lookup of id 'ab12' in apt/threat_actor failed: {ACCOUNT_REFUSAL}"]
    assert note.readable_output.startswith("Group-IB publishes no hi/threat_actor or apt/threat_actor record with id ab12.")
    # refused by both collections, the id stays an error of the instance
    mocker.patch.object(client, "search_collection", side_effect=ConnectionException(ACCOUNT_REFUSAL))
    with pytest.raises(DemistoException, match="The lookup of id 'ab12' in hi/threat_actor failed"):
        threat_lookup(client, "threat_actor", {"id": "ab12", "isAPT": "false"})


def test_a_record_the_update_feed_returns_for_another_id_is_not_this_one(mocker, single_session_fixture):
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=ConnectionException(ACCOUNT_REFUSAL))
    portion = MagicMock()
    portion.parse_portion.return_value = [{"id": "zz99", "name": "Another crew"}]
    mocker.patch.object(client, "search_collection", return_value=iter([portion]))
    with pytest.raises(DemistoException, match="No record with id 'ab12' was found in hi/threat_actor"):
        lookup(client, "hi/threat_actor", {"id": "ab12"})


@pytest.mark.parametrize(
    "record, expected", [({"id": ["a1", "ab12"]}, True), ({"id": "ab12"}, True), ({}, True), ({"id": "a1"}, False)]
)
def test_a_record_has_an_id_as_a_string_in_a_list_or_not_at_all(record, expected):
    assert LookupCommand._has_id(record, "ab12") is expected


def test_a_failed_request_whose_url_holds_404_is_not_a_missing_record(mocker, single_session_fixture):
    """ciaops puts the URL, and so the id, in its timeout and retry messages: an id that contains
    "404" does not turn such a failure into "not found"."""
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    failure = ConnectionException("Request to https://api.example.com/api/v2/malware/cnc/a404b failed: Max retries exceeded")
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=failure)
    with pytest.raises(DemistoException, match="The lookup of id 'a404b' in malware/cnc failed") as caught:
        read_record(client, "malware/cnc", "a404b")
    assert "No record with id" not in str(caught.value)


def test_main_reports_expected_failures_without_a_traceback(mocker):
    params = {"url": "https://example.com", "credentials": {"identifier": "u", "password": "p"}}
    mocker.patch.object(GroupIBTIA.demisto, "params", return_value=params)
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value={"id": "missing"})
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="gibti-get-malware-cnc-info")
    mocker.patch.object(GroupIBTIA, "Client", autospec=True)
    mocker.patch.object(
        GroupIBTIA.LookupCommand, "run", side_effect=DemistoException("No record with id 'missing' was found in malware/cnc.")
    )
    error = mocker.patch.object(GroupIBTIA, "return_error")
    GroupIBTIA.main()
    message = error.call_args.args[0]
    assert "No record with id 'missing' was found in malware/cnc." in message
    assert "Traceback" not in message


def test_an_incident_joins_a_list_source_type_without_repeats():
    record = {
        "id": "acc-1",
        "name": "login@example.com",
        "dateFirstSeen": "2026-08-28T04:30:22Z",
        "evaluation": {"severity": "green"},
        "source_type": ["Stealer logs cloud", "Stealer logs cloud", "Telegram"],
    }
    built = IncidentBuilder().build("compromised/account_group", record)
    assert json.loads(built["rawJSON"])["sourceType"] == "Stealer logs cloud, Telegram"


def test_a_breached_incident_links_the_portal_by_its_id():
    collection_name = "compromised/breacheddb"
    incident = {
        "id": "breached-id",
        "name": ["Email collection"],
        "emails": ["user@example.com"],
        "uploadTime": "2024-10-01T01:45:13",
        "evaluation": {"severity": "green"},
        "portalLink": "https://portal.example.com/cd/breached?id=breached-id",
    }

    built_incident = IncidentBuilder().build(collection_name, incident)
    raw_incident = loads(built_incident["rawJSON"])

    assert raw_incident["portalLink"] == f"{PORTAL_LINKS[collection_name]}breached-id"


# `dedup_lookback_days = N`: each id, the newest one too, stays in the duplicate cache for N days and then leaves it.


SECONDS_PER_DAY = 86_400


def test_the_dedup_lookback_is_kept_in_seconds():
    assert fetch_settings([], dedup_lookback_days=1).retention_seconds == SECONDS_PER_DAY
    assert fetch_settings([], dedup_lookback_days=365).retention_seconds == 365 * SECONDS_PER_DAY


def test_a_dedup_lookback_of_zero_is_zero_seconds():
    assert fetch_settings([], dedup_lookback_days=0).retention_seconds == 0


def test_a_lookback_of_zero_empties_the_duplicate_cache():
    cache = {"a": 1000.0, "b": 2000.0}
    pruned = seen_cache(clock=lambda: 10_000.0)._prune(cache, retention_seconds=0)
    assert pruned == {}


def test_pruning_with_a_negative_retention_empties_the_duplicate_cache():
    cache = {"a": 1000.0}
    pruned = seen_cache(clock=lambda: 10_000.0)._prune(cache, retention_seconds=-1)
    assert pruned == {}


def test_the_duplicate_cache_keeps_entries_within_the_lookback():
    now = 10_000.0
    cache = {
        "fresh": now - 100,
        "older": now - 500,
    }
    pruned = seen_cache(clock=lambda: now)._prune(cache, retention_seconds=1000)
    assert pruned == {"fresh": now - 100, "older": now - 500}


def test_the_duplicate_cache_drops_entries_older_than_the_lookback():
    now = 10_000.0
    cache = {
        "fresh": now - 100,
        "stale": now - 5000,
    }
    pruned = seen_cache(clock=lambda: now)._prune(cache, retention_seconds=1000)
    assert pruned == {"fresh": now - 100}


def test_an_entry_exactly_at_the_lookback_is_kept():
    now = 10_000.0
    cache = {"boundary": now - 1000}
    pruned = seen_cache(clock=lambda: now)._prune(cache, retention_seconds=1000)
    assert pruned == {"boundary": now - 1000}


def test_an_entry_a_millisecond_past_the_lookback_is_dropped():
    now = 10_000.0
    cache = {"just_past": now - 1000.001}
    pruned = seen_cache(clock=lambda: now)._prune(cache, retention_seconds=1000)
    assert pruned == {}


def test_an_entry_with_an_unreadable_or_negative_timestamp_is_dropped():
    now = 10_000.0
    cache = {
        "ok": now - 100,
        "string_ts": "not-a-number",  # type: ignore[dict-item]
        "none_ts": None,  # type: ignore[dict-item]
        "negative": -1,
    }
    pruned = seen_cache(clock=lambda: now)._prune(cache, retention_seconds=1000)  # type: ignore[arg-type]
    assert pruned == {"ok": now - 100}


def test_pruning_leaves_the_stored_cache_as_it_was():
    cache = {"a": 1.0, "b": 2.0}
    snapshot = dict(cache)
    seen_cache(clock=lambda: 1000.0)._prune(cache, retention_seconds=1)
    assert cache == snapshot


def test_the_newest_entry_is_dropped_too_when_older_than_the_lookback():
    now = 10_000.0
    cache = {
        "ancient_but_latest": now - 99_999_998,
        "ancient_too": now - 99_999_999,
    }
    pruned = seen_cache(clock=lambda: now)._prune(cache, retention_seconds=1000)
    assert pruned == {}


def test_adding_no_incident_leaves_the_duplicate_cache_as_it_was():
    state = {"found_incident_ids": {"existing": 1.0}}
    seen_cache()._remember(state, [], retention_seconds=365 * SECONDS_PER_DAY)
    assert state == {"found_incident_ids": {"existing": 1.0}}


def test_the_duplicate_cache_adds_the_fetched_ids_at_the_clock_time(mocker):
    fixed_now = 1_700_000_000.0

    state: dict = {}
    seen_cache(clock=lambda: fixed_now)._remember(
        state,
        [{"id": "alpha"}, {"id": "beta"}],
        retention_seconds=365 * SECONDS_PER_DAY,
    )
    assert state["found_incident_ids"] == {"alpha": fixed_now, "beta": fixed_now}


def test_the_duplicate_cache_stores_a_numeric_id_as_text(mocker):
    fixed_now = 1_700_000_000.0

    state: dict = {}
    seen_cache(clock=lambda: fixed_now)._remember(
        state,
        [{"id": 42}, {"id": "alpha"}],
        retention_seconds=365 * SECONDS_PER_DAY,
    )
    assert state["found_incident_ids"] == {"42": fixed_now, "alpha": fixed_now}


def test_an_incident_without_an_id_is_not_remembered(mocker):
    fixed_now = 1_700_000_000.0

    state: dict = {}
    seen_cache(clock=lambda: fixed_now)._remember(
        state,
        [{"id": None}, {"name": "no-id"}, {"id": "ok"}],
        retention_seconds=365 * SECONDS_PER_DAY,
    )
    assert state["found_incident_ids"] == {"ok": fixed_now}


def test_the_duplicate_cache_is_pruned_when_the_fetched_ids_are_added(mocker):
    fixed_now = 1_700_000_000.0

    state = {
        "found_incident_ids": {
            "stale": fixed_now - (366 * SECONDS_PER_DAY),
            "fresh": fixed_now - (10 * SECONDS_PER_DAY),
        }
    }
    seen_cache(clock=lambda: fixed_now)._remember(
        state,
        [{"id": "new"}],
        retention_seconds=365 * SECONDS_PER_DAY,
    )
    assert "stale" not in state["found_incident_ids"]
    assert "fresh" in state["found_incident_ids"]
    assert state["found_incident_ids"]["new"] == fixed_now


def test_a_duplicate_cache_stored_as_text_is_replaced_by_a_fresh_one(mocker):
    fixed_now = 1_700_000_000.0

    state: dict = {"found_incident_ids": "not-a-dict"}
    seen_cache(clock=lambda: fixed_now)._remember(
        state,
        [{"id": "alpha"}],
        retention_seconds=365 * SECONDS_PER_DAY,
    )
    assert state["found_incident_ids"] == {"alpha": fixed_now}


def test_an_id_added_exactly_lookback_days_ago_is_kept_and_a_second_earlier_is_dropped(mocker):
    fixed_now = 1_700_000_000.0

    n_days = 7
    retention_seconds = n_days * SECONDS_PER_DAY

    state = {
        "found_incident_ids": {
            "boundary": fixed_now - retention_seconds,
            "just_past": fixed_now - retention_seconds - 1,
        }
    }
    seen_cache(clock=lambda: fixed_now)._remember(
        state,
        [{"id": "today"}],
        retention_seconds=n_days * SECONDS_PER_DAY,
    )

    cache = state["found_incident_ids"]
    assert "boundary" in cache, "an id exactly N days old stays"
    assert "just_past" not in cache, "an id N days and 1 s old leaves"
    assert cache["today"] == fixed_now


def test_a_lookback_of_zero_drops_the_whole_cache_on_the_next_update(mocker):
    fixed_now = 1_700_000_000.0

    state = {"found_incident_ids": {"old": fixed_now - 10}}
    seen_cache(clock=lambda: fixed_now)._remember(
        state,
        [{"id": "incoming"}],
        retention_seconds=0 * SECONDS_PER_DAY,
    )
    assert state["found_incident_ids"] == {}


def _reputation_command(client):
    """The domain reputation command of a default instance whose reputation commands are enabled."""
    return ReputationCommand("domain", client, reputation_settings())


@pytest.mark.parametrize(
    "search_return",
    [None, "", [], {}, {"unexpected": 1}, [None, "text", {"apiPath": "x", "count": 1}, {"apiPath": "y", "count": 0}]],
)
def test_a_global_search_answer_of_any_shape_names_only_the_collections_with_hits(single_session_fixture, mocker, search_return):
    client = _reputation_client(mocker, single_session_fixture, {})
    mocker.patch.object(client.poller, "global_search", return_value=search_return)
    command = ReputationCommand("domain", client, reputation_settings(use_global_search=True))
    _data, _floors, mentions = command._lookup("domain", "example.com")
    assert mentions == (["x"] if isinstance(search_return, list) and len(search_return) == 4 else [])


def test_a_failed_global_search_is_recorded_and_decides_nothing(single_session_fixture, mocker):
    client = _reputation_client(mocker, single_session_fixture, {})
    mocker.patch.object(client.poller, "global_search", side_effect=RuntimeError("connection reset"))
    [result] = reputation(client, "domain", {"domain": "example.com"}, use_global_search=True)
    assert result.outputs["failedSources"] == ["collection search"]
    assert result.outputs["partial"] is False


def test_a_domain_lookup_without_records_reads_its_collections_and_the_risk_score(single_session_fixture, mocker):
    client = _reputation_client(mocker, single_session_fixture, {})
    data, floors, mentions = evidence(client)._lookup("domain", "example.com")
    assert data == {
        "attacks/deface": [],
        "apt/threat": [],
        "ioc/primary": [],
        "hi/open_threats": [],
        "scoring": {"score": None},
    }
    assert floors == {}
    assert mentions == []
    client.poller.global_search.assert_not_called()


def test_failed_collection_reads_leave_their_records_empty_and_are_each_recorded(single_session_fixture, mocker):
    """Every failed collection read leaves its records empty and is named among the failures; the risk score is still read."""
    client = _reputation_client(mocker, single_session_fixture, {}, {"example.com": 40})
    mocker.patch.object(GroupIBTIA.ReputationCommand, "_read", side_effect=RuntimeError("read failed"))
    command = evidence(client)
    data, _floors, _mentions = command._lookup("domain", "example.com")
    assert data == {
        "attacks/deface": [],
        "apt/threat": [],
        "ioc/primary": [],
        "hi/open_threats": [],
        "scoring": {"score": 40},
    }
    assert sorted(source for source, _exc in command._failures) == [
        "reading apt/threat",
        "reading attacks/deface",
        "reading hi/open_threats",
        "reading ioc/primary",
    ]


def test_a_failing_ip_enrichment_leaves_no_score_and_is_recorded(single_session_fixture, mocker):
    client = _reputation_client(mocker, single_session_fixture, {})
    mocker.patch.object(client.poller, "get_ip_scoring", side_effect=RuntimeError("scoring failed"))
    mocker.patch.object(client.poller, "graph_ip_search", side_effect=RuntimeError("whois failed"))
    command = evidence(client)
    data, _floors, _mentions = command._lookup("ip", "198.51.100.88")
    assert data["scoring"] == {"score": None}
    assert "graph_ip" not in data
    assert sorted((source, str(exc)) for source, exc in command._failures) == [
        ("ip WHOIS", "whois failed"),
        ("ip scoring", "scoring failed"),
    ]


def test_a_search_that_answers_none_reads_as_no_records(single_session_fixture, mocker):
    client = single_session_fixture
    mocker.patch.object(client, "search_collection", return_value=None)
    out = evidence(client)._read(path="ioc/primary", value="example.com")
    assert out == []


def test_a_page_that_parses_to_none_reads_as_no_records(single_session_fixture, mocker):
    client = single_session_fixture

    class _P:
        raw_dict = None

    mocker.patch.object(client, "search_collection", return_value=[None, _P()])
    out = evidence(client)._read(path="ioc/primary", value="example.com")
    assert out == []


def test_a_null_ip_scoring_answer_is_no_risk_score(single_session_fixture, mocker):
    client = _reputation_client(mocker, single_session_fixture, {})
    mocker.patch.object(client.poller, "get_ip_scoring", return_value=None)
    data, _floors, _mentions = evidence(client)._lookup("ip", "198.51.100.88")
    assert data["scoring"] == {"score": None}


def test_a_failed_ip_scoring_is_no_risk_score(single_session_fixture, mocker):
    client = _reputation_client(mocker, single_session_fixture, {})
    mocker.patch.object(client.poller, "get_ip_scoring", side_effect=RuntimeError("scoring failed"))
    data, _floors, _mentions = evidence(client)._lookup("ip", "198.51.100.88")
    assert data["scoring"] == {"score": None}


def test_a_null_global_search_answer_is_a_no_results_entry(single_session_fixture, mocker):
    client = single_session_fixture
    mocker.patch.object(client.poller, "global_search", return_value=None)
    result = global_search(client, {"query": "example.com"})
    assert isinstance(result, CommandResults)
    assert result.outputs == []
    assert "No results" in (result.readable_output or "")


def test_an_empty_global_search_answer_has_no_outputs(single_session_fixture, mocker):
    client = single_session_fixture
    mocker.patch.object(client.poller, "global_search", return_value=[])
    result = global_search(client, {"query": "example.com"})
    assert result.outputs == []


def test_the_global_search_keeps_only_entries_with_an_api_path(single_session_fixture, mocker):
    client = single_session_fixture
    # A known apiPath next to entries of other shapes.
    known_path = next(iter(MAPPING.keys()))
    raw = [None, "text", 42, {"apiPath": known_path, "count": 3, "link": "https://example.com/x"}]
    mocker.patch.object(client.poller, "global_search", return_value=raw)
    result = global_search(client, {"query": "example.com"})
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 1


def test_a_local_search_whose_feed_answers_none_has_no_outputs(mock_client):
    mock_client.search_collection.return_value = None
    result = local_search(mock_client, {"query": "q", "collection_name": "malware/cnc"})
    assert isinstance(result, CommandResults)
    assert result.outputs == []


def test_a_local_search_skips_a_page_that_is_none(mock_client):
    portion = MagicMock()
    portion.sequpdate = 1
    portion.parse_portion.return_value = None
    mock_client.search_collection.return_value = [None, portion]
    result = local_search(mock_client, {"query": "q", "collection_name": "malware/cnc"})
    assert result.outputs == []


def test_a_reputation_command_without_data_answers_dbotscore_none_and_says_so(single_session_fixture, mocker):
    client = _reputation_client(mocker, single_session_fixture, {})
    mocker.patch.object(client.poller, "get_domain_scoring", return_value={})
    [result] = reputation(client, "domain", {"domain": "example.com"})
    assert isinstance(result, CommandResults)
    assert "No Group-IB" in (result.readable_output or "")
    # DBotScore.NONE is the integer 0 in the public XSOAR API.
    assert result.raw_response["score"] == 0


def test_the_client_hands_verify_to_the_ciaops_session_and_keeps_its_rate_limit():
    client = Client(
        base_url="https://example.com",
        auth=("example@example.com", "exampleAPI_TOKEN"),
        verify=False,
        headers={"Accept": "*/*"},
        rate_limit_delay=2.5,
    )
    # The poller runs its own requests.Session; "Trust any certificate (not secure)" reaches it too.
    assert client.poller._session.verify is False
    assert client.rate_limit_delay == 2.5


def test_a_client_without_a_rate_limit_takes_the_integration_default(single_session_fixture):
    assert single_session_fixture.rate_limit_delay == GroupIBTIA.Settings.DEFAULT_RATE_LIMIT_DELAY


@pytest.mark.parametrize(
    "params, expected",
    [
        ({}, GroupIBTIA.Settings.DEFAULT_RATE_LIMIT_DELAY),
        ({"rate_limit_delay": ""}, GroupIBTIA.Settings.DEFAULT_RATE_LIMIT_DELAY),
        ({"rate_limit_delay": "0"}, 0.0),
        ({"rate_limit_delay": "2.5"}, 2.5),
    ],
)
def test_the_rate_limit_delay_setting_reads_a_number_and_defaults_when_blank(params, expected):
    assert Settings.from_params(params).rate_limit_delay == expected


@pytest.mark.parametrize("value", ["abc", "-1"])
def test_a_rate_limit_delay_that_is_no_number_or_negative_is_refused(value):
    with pytest.raises(GroupIBTIA.DemistoException):
        Settings.from_params({"rate_limit_delay": value})


def test_binary_filters_reach_ciaops_as_ints(mocker, single_session_fixture):
    """The binary filters go out as 0/1: a bool would be sent as True/False."""
    client = single_session_fixture
    mocker.patch.object(client.poller, "get_seq_update_dict", return_value={"compromised/account_group": 12345})
    mocker.patch.object(client.poller, "create_update_generator", return_value=[])

    open_feed(
        client,
        collection_name="compromised/account_group",
        hunting_rules=True,
        enable_probable_corporate_access=True,
        unique=False,
        combolist=True,
        cursor=None,
        first_fetch_time="2023-01-01",
    )

    request_params = client.poller.create_update_generator.call_args[1]["request_params"]
    assert (request_params.apply_hunting_rules, request_params.probable_corporate_access) == (1, 1)
    assert (request_params.unique, request_params.combolist) == (0, 1)
    binary = (
        request_params.apply_hunting_rules,
        request_params.probable_corporate_access,
        request_params.unique,
        request_params.combolist,
    )
    assert all(type(value) is int for value in binary)


def test_local_search_passes_query_limit_and_dates_to_the_collection_search(mock_client):
    mock_client.search_collection.return_value = []
    local_search(
        mock_client,
        {
            "query": "q",
            "collection_name": "malware/cnc",
            "page_size_limit": "5",
            "date_from": "2024-01-01",
        },
    )
    args, kwargs = mock_client.search_collection.call_args
    assert args == ("malware/cnc",)
    assert kwargs == {"query": "q", "limit": 5, "date_from": "2024-01-01T00:00:00Z", "date_to": None, "sequpdate": None}


def test_a_reputation_read_consumes_one_search_page(single_session_fixture, mocker):
    client = single_session_fixture
    first = MagicMock(raw_dict={"count": 2, "items": [{"id": "a"}]})
    second = MagicMock(raw_dict={"count": 2, "items": [{"id": "b"}]})
    search = mocker.patch.object(client, "search_collection", return_value=iter([first, second]))
    out = evidence(client)._read(path="ioc/primary", value="203.0.113.7")
    assert search.call_args.args == ("ioc/primary",)
    assert search.call_args.kwargs == {"query": "203.0.113.7", "limit": GroupIBTIA.ReputationCommand.SEARCH_PAGE_SIZE}
    assert out == [first.raw_dict]


def test_a_collection_search_passes_its_query_dates_cursor_and_rate_limit_to_the_update_generator(mocker, single_session_fixture):
    client = single_session_fixture
    generator = mocker.patch.object(client.poller, "create_update_generator", return_value=[])
    client.search_collection("hi/threat_actor", query="examplefox", limit=50, date_from="2024-01-01", sequpdate=7)
    kwargs = generator.call_args.kwargs
    params = kwargs["request_params"]
    assert kwargs["collection_name"] == "hi/threat_actor"
    assert kwargs["sequpdate"] == 7
    assert kwargs["rate_limit_delay"] == client.rate_limit_delay
    assert (params.query, params.limit, params.date_from, params.date_to) == ("examplefox", 50, "2024-01-01", None)


def test_the_ip_lookup_reads_the_risk_score_from_scoring_ip(single_session_fixture, mocker):
    client = _reputation_client(mocker, single_session_fixture, {})
    mocker.patch.object(
        client.poller, "get_ip_scoring", return_value={"items": {"198.51.100.88": {"ip": "198.51.100.88", "riskScore": 25}}}
    )
    data, _floors, _mentions = evidence(client)._lookup("ip", "198.51.100.88")
    assert data["scoring"] == {"score": 25}


def test_the_retired_breached_name_is_refused_naming_breacheddb():
    with pytest.raises(Exception, match="compromised/breacheddb"):
        CollectionSpec.validate("compromised/breached")
    assert GroupIBTIA.RETIRED_COLLECTIONS["compromised/breached"] == "compromised/breacheddb"
    assert "compromised/breacheddb" in MAPPING
    assert "compromised/breacheddb" in PORTAL_LINKS


def _granted(*names, hunting=()):
    return [{"collection": name, "huntingRulesUsed": name in hunting} for name in names]


def test_one_grant_request_answers_the_available_and_the_hunting_rules_collections(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(GroupIBTIA.demisto, "getIntegrationContext", return_value={})
    set_context = mocker.patch.object(GroupIBTIA.demisto, "setIntegrationContext")
    send = mocker.patch.object(
        client.poller,
        "send_request",
        return_value=_granted("ioc/common", "osi/git_repository", "example/unknown", hunting=("osi/git_repository",)),
    )
    assert client.available_collections() == frozenset({"ioc/common", "osi/git_repository"})
    assert client.hunting_rules_collections() == frozenset({"osi/git_repository"})
    assert send.call_count == 1
    assert set_context.call_args[0][0]["granted_collections_cache"]["items"][0]["collection"] == "ioc/common"


def test_a_failed_grant_read_is_not_sent_again_within_one_command(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(GroupIBTIA.demisto, "getIntegrationContext", return_value={})
    send = mocker.patch.object(client.poller, "send_request", side_effect=GroupIBTIA.ConnectionException("HTTP 503"))
    for _ in range(3):
        with pytest.raises(GroupIBTIA.ConnectionException, match="HTTP 503"):
            client.hunting_rules_collections()
    assert send.call_count == 1


def test_a_grant_list_cached_less_than_five_minutes_ago_is_not_read_again(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(
        GroupIBTIA.demisto,
        "getIntegrationContext",
        return_value={"granted_collections_cache": {"fetched_at": time.time(), "items": _granted("ioc/common")}},
    )
    send = mocker.patch.object(client.poller, "send_request")
    assert client.available_collections() == frozenset({"ioc/common"})
    send.assert_not_called()


def test_a_grant_list_cached_over_five_minutes_ago_is_read_again(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(
        GroupIBTIA.demisto,
        "getIntegrationContext",
        return_value={"granted_collections_cache": {"fetched_at": time.time() - 301, "items": _granted("ioc/common")}},
    )
    mocker.patch.object(GroupIBTIA.demisto, "setIntegrationContext")
    send = mocker.patch.object(client.poller, "send_request", return_value=_granted("apt/threat"))
    assert client.available_collections() == frozenset({"apt/threat"})
    assert send.call_count == 1


@pytest.mark.parametrize(
    "collection, enabled, granted, expected",
    [
        ("osi/public_leak", False, set(), 1),  # always filtered by the API
        ("osi/git_repository", True, {"osi/git_repository"}, None),  # filtered by the API, the flag a no-op
        ("hi/threat", False, {"hi/threat"}, None),  # setting off
        ("hi/threat", True, {"hi/threat"}, 1),  # supported + granted
        ("hi/threat", True, set(), None),  # supported, no grant -> unfiltered
        ("malware/cnc", True, {"malware/cnc"}, None),  # the API has no filter for it
        ("suspicious_ip/tor_node", True, {"suspicious_ip/tor_node"}, 1),
    ],
)
def test_the_hunting_rules_flag_follows_the_setting_the_grant_and_the_collection(
    mocker, single_session_fixture, collection, enabled, granted, expected
):
    client = single_session_fixture
    grants = mocker.patch.object(client, "hunting_rules_collections", return_value=frozenset(granted))
    assert FetchIncidentsCommand(client, fetch_settings([], hunting_rules=enabled))._hunting_rules(collection) == expected
    if not enabled or collection not in GroupIBTIA.TICollections.APPLY_HUNTING_RULES:
        grants.assert_not_called()


def test_fetch_passes_the_hunting_flag_per_collection(mocker, single_session_fixture):
    client = single_session_fixture
    granted = [{"collection": "hi/threat", "huntingRulesUsed": True}, {"collection": "malware/cnc", "huntingRulesUsed": True}]
    mocker.patch.object(client, "granted_collections", return_value=granted)
    generator = mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([], None))
    fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=["hi/threat", "malware/cnc"],
        max_requests=1,
        hunting_rules=True,
    )
    flags = {c.kwargs["collection_name"]: c.kwargs["hunting_rules"] for c in generator.call_args_list}
    assert flags == {"hi/threat": 1, "malware/cnc": None}


def test_first_fetch_change_drops_incident_cursors():
    state = {"first_fetch_time": "3 days", "last_fetch": {"ioc/common": "1"}, "found_incident_ids": {"a": 1.0}}
    assert FetchIncidentsCommand._drop_cursors_if_first_fetch_changed(state, "3 days") is state
    reset = FetchIncidentsCommand._drop_cursors_if_first_fetch_changed(state, "30 days")
    assert reset["last_fetch"] == {}
    assert reset["found_incident_ids"] == {"a": 1.0}
    legacy = {"last_fetch": {"ioc/common": "1"}}
    assert FetchIncidentsCommand._drop_cursors_if_first_fetch_changed(legacy, "30 days") is legacy


def test_fetch_incidents_records_the_first_fetch_fingerprint(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([], None))
    next_run, _ = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="7 days",
        incident_collections=[],
        max_requests=1,
        hunting_rules=0,
    )
    assert next_run["first_fetch_time"] == "7 days"


def _vulnerability(**overrides):
    record = {
        "id": "CVE-2099-0001",
        "title": "t",
        "description": "d",
        "cvss_score": 7.5,
        "cvss_vector": "AV:N",
        "merged_cvss": 7.5,
        "merged_cvss_vector": "AV:N",
        "epss": 0.1,
        "epss_percentile": 0.9,
        "has_exploit": True,
        "exploit_count": 2,
        "seen_in_the_wild": False,
        "severity": "orange",
        "tlp": "green",
        "date_published": "2024-01-01",
        "date_modified": "2024-02-01",
    }
    record.update(overrides)
    return record


def test_cve_scoring_scores_an_exploited_cve_as_bad(mocker, single_session_fixture):
    client = single_session_fixture
    portion = MagicMock()
    portion.parse_portion.return_value = [_vulnerability()]
    lookup = mocker.patch.object(client.poller, "search_feed_by_id", return_value=portion)
    results = score_cves(client, {"cve": "CVE-2099-0001"})
    assert lookup.call_args[0] == ("osi/vulnerability", "CVE-2099-0001")
    assert len(results) == 1
    outputs = results[0].outputs
    assert outputs["score"] == 3
    assert outputs["hasExploit"] is True
    assert outputs["tlp"] == "GREEN"
    assert outputs["cvssScore"] == 7.5
    assert results[0].outputs_prefix == "GIBTI.CVEScoring"
    assert results[0].indicator.dbot_score.score == 3
    assert results[0].indicator.cvss_vector == "AV:N"


@pytest.mark.parametrize("failure", [GroupIBTIA.NotFoundException("HTTP 404: Not found."), Exception("unexpected")])
def test_a_cve_scoring_whose_lookup_finds_nothing_or_fails_unexpectedly_reports_no_data(mocker, single_session_fixture, failure):
    client = single_session_fixture
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=failure)
    result = score_cves(client, {"cve": "CVE-1999-9999"})[0]
    assert result.outputs["found"] is False
    assert result.outputs["score"] == 0
    assert "No Group-IB Threat Intelligence data" in result.readable_output


@pytest.mark.parametrize(
    "failure, message",
    [
        (SERVER_ERROR, "The Group-IB scoring request for 'CVE-2099-0001' failed: HTTP 500. Run the command again later."),
        (ACCOUNT_REFUSAL, "The Group-IB scoring request for 'CVE-2099-0001' failed: HTTP 403. Check the instance credentials."),
    ],
)
def test_a_cve_scoring_whose_request_fails_names_the_status_and_the_next_step(mocker, single_session_fixture, failure, message):
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=ConnectionException(failure))
    with pytest.raises(DemistoException) as raised:
        score_cves(client, {"cve": "CVE-2099-0001"})
    assert str(raised.value) == message


def test_a_cve_scoring_without_a_cve_is_refused(single_session_fixture):
    with pytest.raises(DemistoException):
        score_cves(single_session_fixture, {})


@pytest.mark.parametrize(
    "fields, expected",
    [
        ({"has_exploit": True}, 3),
        ({"seen_in_the_wild": True}, 3),
        ({"epss": 0.6}, 3),
        ({"epss_percentile": 0.96}, 3),
        ({"cvss_score": 9.8}, 3),
        ({"severity": "red"}, 3),
        ({"cvss_score": 5.0}, 2),
        ({"epss_percentile": 0.85}, 2),
        ({"severity": "orange"}, 2),
        # A CVE Group-IB has a record of is never benign, whatever its CVSS.
        ({"cvss_score": 2.0}, 2),
        ({"cvss_score": 0, "merged_cvss": 0}, 2),
        ({"severity": "green"}, 2),
        ({}, 2),
    ],
)
def test_a_cve_is_bad_when_exploited_high_epss_critical_or_red_and_suspicious_otherwise(fields, expected):
    assert ScoringCommand._cve_verdict(fields) == expected


@pytest.mark.parametrize(
    "args, expected",
    [({"id": "x"}, "hi"), ({"id": "x", "isAPT": "true"}, "apt"), ({"id": "x", "isAPT": "false"}, "hi")],
)
def test_threat_commands_pick_the_collection_from_is_apt(mocker, single_session_fixture, args, expected):
    seen = []

    def results(command, collection_name, record_id):
        seen.append(collection_name)
        return []

    mocker.patch.object(GroupIBTIA.LookupCommand, "_results", results)
    threat_lookup(single_session_fixture, "threat", args)
    threat_lookup(single_session_fixture, "threat_actor", args)
    assert seen == [f"{expected}/threat", f"{expected}/threat_actor"]


def test_reputation_enrichment_collects_tags_malware_actors_and_tlp(single_session_fixture):
    data = {
        "ioc/primary": [
            ReputationCommand._with_tlp(
                {
                    "type": "network",
                    "ip": [{"ip": "203.0.113.9", "riskScore": 95}],
                    "malwareList": [{"name": "Sample Loader"}],
                    "threatList": [{"name": "Sample Campaign"}],
                    "threatActorList": [{"name": "Sample Actor"}],
                    "evaluation": {"TLP": "TLP:GREEN"},
                }
            )
        ],
        "apt/threat": [{"threat_actor_name": "Sample Report Actor"}],
        "attacks/deface": [{"threat_actor_name": "Sample Defacer", "tlp": "red"}],
        "scoring": {"score": 10},
        "whois": {},
    }
    tags, malware, actors, tlp = ReputationCommand._collect(data)
    # a defacement of the site adds its collection and TLP, never the defacer
    assert tags == [
        "ioc/primary",
        "Sample Campaign",
        "Sample Actor",
        "apt/threat",
        "Sample Report Actor",
        "attacks/deface",
    ]
    assert malware == ["Sample Loader"]
    assert actors == ["Sample Actor", "Sample Report Actor"]
    assert tlp == "RED"


def test_an_ioc_primary_record_without_a_tlp_gives_none_and_the_most_restrictive_marking_wins(single_session_fixture):
    assert ReputationCommand._collect({"ioc/primary": [{"type": "network"}]})[3] is None
    amber = ReputationCommand._with_tlp({"type": "network", "evaluation": {"TLP": "TLP:AMBER"}})
    assert ReputationCommand._collect({"ioc/primary": [amber], "apt/threat": [{"evaluation": {"tlp": "green"}}]})[3] == "AMBER"
    assert ReputationCommand._collect({"ioc/primary": []}) == ([], [], [], None)


def test_ioc_primary_actor_names_come_from_its_threat_actor_list(single_session_fixture):
    record = {"type": "network", "threatActorList": [{"name": "Sample Actor"}], "threatActor": {"name": "Sample Other"}}
    _tags, _malware, actors, _tlp = ReputationCommand._collect({"ioc/primary": [record]})
    assert actors == ["Sample Actor"]


def test_an_account_c2_gives_a_url_and_a_domain_and_the_url_carries_the_malware_as_suspicious():
    feed = {
        "evaluation": {"severity": "red"},
        "indicators": {
            "event_url": ["http://cnc.test/gate"],
            "event_domain": ["cnc.test"],
            "malware_names": ["BankerFive"],
            "threat_actor_names": [],
        },
    }
    results = IndicatorBuilder().items(feed, "compromised/account_group")
    kinds = {type(r.indicator).__name__ for r in results}
    assert kinds == {"URL", "Domain"}
    url = next(r.indicator for r in results if type(r.indicator).__name__ == "URL")
    assert url.malware_family == ["BankerFive"]
    assert "compromised/account_group" in url.tags
    assert "BankerFive" in url.tags
    # The record's red severity is the event's urgency, not the observable's verdict.
    assert url.dbot_score.score == 2


def test_threat_report_with_several_ips_yields_one_bad_indicator_each():
    feed = {
        "evaluation": {"severity": "orange"},
        "indicators": {"ipv4": ["203.0.113.1", "203.0.113.2"], "domain": [], "url": [], "hashes_md5": []},
    }
    results = IndicatorBuilder().items(feed, "hi/threat")
    assert sorted(r.indicator.ip for r in results) == ["203.0.113.1", "203.0.113.2"]
    assert all(r.indicator.dbot_score.score == 3 for r in results)


def test_an_spd_crypto_wallet_becomes_a_cryptocurrency_indicator_and_a_mobile_number_does_not():
    feed = {
        "evaluation": {"severity": "red"},
        "indicators": {
            "value_value": "bc1qexample",
            "type": "Cryptocurrency Wallet",
            "service_type": "BTCLike",
            "illegal_score": 100,
            "tlp": "amber",
            "malware_names": [],
            "threat_actor_names": [],
        },
    }
    indicator = IndicatorBuilder().items(feed, "compromised/spd")[0].indicator
    assert indicator.address == "bc1qexample"
    assert indicator.address_type == "bitcoin"
    assert indicator.dbot_score.score == 3
    feed["indicators"]["type"] = "Mobile Number"
    assert IndicatorBuilder().items(feed, "compromised/spd") == []


def test_vulnerability_indicator_carries_description_vector_cvss_score_and_tlp_and_is_bad():
    feed = {
        "evaluation": {"severity": "green"},
        "indicators": {
            "id": "CVE-2021-1",
            "cvss_score": 3.1,
            "cvss_vector": "AV:L",
            "description": "text",
            "has_exploit": False,
            "epss": 0.01,
            "severity": "green",
            "tlp": "green",
            "dateLastSeen": "2021-01-02",
            "datePublished": "2021-01-01",
        },
    }
    cve = IndicatorBuilder().items(feed, "osi/vulnerability")[0].indicator
    assert cve.description == "text"
    assert cve.cvss_vector == "AV:L"
    assert cve.cvss == 3.1
    assert cve.dbot_score.score == 3
    assert cve.traffic_light_protocol == "GREEN"


def test_an_observable_is_empty_only_when_it_has_attributes_and_all_are_empty_lists():
    assert IndicatorBuilder._carries_no_data({}) is False
    assert IndicatorBuilder._carries_no_data({"a": []}) is True
    assert IndicatorBuilder._carries_no_data({"a": [], "b": "x"}) is False


def test_reputation_enrichment_unwraps_the_api_envelope(single_session_fixture):
    record = {
        "type": "network",
        "malwareList": [{"name": "Sample Loader"}],
        "threatList": [{"name": "Sample Campaign"}],
        "evaluation": {"tlp": "amber"},
    }
    tags, malware, actors, tlp = ReputationCommand._collect({"ioc/primary": [{"count": 1, "items": [record]}]})
    assert tags == ["ioc/primary", "Sample Campaign"]
    assert malware == ["Sample Loader"]
    assert actors == []
    assert tlp == "AMBER"


def test_lookup_indicators_carry_the_record_tlp_and_malware_cnc_domain_is_emitted():
    feed = {
        "evaluation": {"severity": "red", "tlp": "amber"},
        "indicators": {
            "url": "",
            "domain": "cnc1.test",
            "ipv4_ip": [],
            "ipv4_asn": [],
            "country_name": [],
            "ipv4_region": [],
            "malware_names": ["BotnetTwo"],
            "threat_actor_names": [],
        },
    }
    results = IndicatorBuilder().items(feed, "malware/cnc")
    kinds = [type(r.indicator).__name__ for r in results]
    assert kinds == ["Domain"]
    domain = results[0].indicator
    assert domain.traffic_light_protocol == "AMBER"
    assert domain.malware_family == ["BotnetTwo"]
    assert domain.dbot_score.score == 3


def test_deface_and_phishing_lookups_emit_only_the_url():
    deface = {
        "evaluation": {"severity": "orange"},
        "indicators": {"url": "http://victim.test/x", "target_domain": "victim.test", "target_ip_ip": "198.51.100.9"},
    }
    assert [type(r.indicator).__name__ for r in IndicatorBuilder().items(deface, "attacks/deface")] == ["URL"]
    phishing = {
        "evaluation": {"severity": "red"},
        "indicators": {
            "url": ["http://phish.test/"],
            "phishing_domain_domain": "phish.test",
            "phishing_domain_registrar": "r",
            "ipv4_ip": "198.51.100.10",
            "ipv4_country_name": "X",
        },
    }
    phishing_results = IndicatorBuilder().items(phishing, "attacks/phishing_group")
    # the domain and the hosting IP are often shared infrastructure: only the phishing URL
    assert [type(r.indicator).__name__ for r in phishing_results] == ["URL"]
    assert set(MAPPING["attacks/phishing_group"]["indicators"]) == {"url", "brand", "objective", "threat_actor_names"}


def test_git_leaks_produce_no_indicators():
    # file revision hashes and committer e-mails are not indicators of an attack
    feed = {
        "evaluation": {"severity": "green", "tlp": "green"},
        "indicators": {"contributors_emails": ["dev@example.test"], "hash": ["a" * 40]},
    }
    assert IndicatorBuilder().items(feed, "osi/git_repository") == []
    assert "indicators" not in MAPPING["osi/git_repository"]


def test_the_incident_source_type_is_the_records_own_or_else_the_collection():
    tor = IncidentBuilder().build(
        "suspicious_ip/tor_node",
        {
            "id": "1",
            "name": "n",
            "dateFirstSeen": "2024-01-01T00:00:00+00:00",
            "dateLastSeen": "2024-01-02T00:00:00+00:00",
            "evaluation": {"severity": "green"},
        },
    )
    assert json.loads(tor["rawJSON"])["sourceType"] == "suspicious_ip/tor_node"
    card = IncidentBuilder().build(
        "compromised/bank_card_group",
        {
            "id": "1",
            "name": "n",
            "sourceType": "botnet",
            "dateFirstCompromised": "2024-01-01T00:00:00+00:00",
            "dateFirstSeen": "2024-01-01T00:00:00+00:00",
            "evaluation": {"severity": "red"},
        },
    )
    assert json.loads(card["rawJSON"])["sourceType"] == "botnet"


def test_main_hands_the_hunting_rules_setting_to_the_fetch(mocker):
    params = {
        "url": "https://example.com",
        "credentials": {"identifier": "u", "password": "p"},
        "hunting_rules": True,
        "incident_collections": ["hi/threat"],
        "first_fetch": "3 days",
    }
    context: dict = {}
    calls = {"send": 0}
    mocker.patch.object(GroupIBTIA.demisto, "params", return_value=params)
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="fetch-incidents")
    mocker.patch.object(GroupIBTIA.demisto, "getLastRun", return_value={})
    mocker.patch.object(GroupIBTIA.demisto, "getIntegrationContext", side_effect=lambda: dict(context))
    mocker.patch.object(GroupIBTIA.demisto, "setIntegrationContext", side_effect=lambda value: context.update(value))
    mocker.patch.object(GroupIBTIA.demisto, "incidents")
    mocker.patch.object(GroupIBTIA.demisto, "setLastRun")
    mocker.patch.object(GroupIBTIA, "return_error", side_effect=AssertionError("return_error is not called"))
    mocker.patch.object(
        GroupIBTIA.TIPoller,
        "send_request",
        side_effect=lambda *a, **k: (
            calls.__setitem__("send", calls["send"] + 1) or [{"collection": "hi/threat", "huntingRulesUsed": True}]
        ),
    )
    fetcher = mocker.patch.object(GroupIBTIA, "FetchIncidentsCommand")
    fetcher.return_value.run.return_value = ({}, [])

    GroupIBTIA.main()

    assert calls["send"] == 0  # the grant lookup lives inside FetchIncidentsCommand.run, mocked here
    assert fetcher.call_args.args[1].hunting_rules is True
    assert Settings.from_params(params).hunting_rules is True


def test_scoring_commands_report_request_failures_as_errors(mocker, single_session_fixture):
    """A misconfigured instance (wrong URL or key, HTTP 403) is reported as an error, not as "no risk score"."""
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    mocker.patch.object(
        client.poller, "get_ip_scoring", side_effect=ConnectionException("HTTP 403: Something is wrong with your account.")
    )
    with pytest.raises(DemistoException, match="scoring request for '192.0.2.14' failed"):
        score_risk(client, "ip", {"ip": "192.0.2.14"})
    mocker.patch.object(client.poller, "get_domain_scoring", side_effect=ConnectionException(SERVER_ERROR))
    # A failed request is that value's error; the other values of the list still answer.

    def score(domains: str | list[str]) -> dict:
        if "x.test" in ([domains] if isinstance(domains, str) else domains):
            raise ConnectionException(SERVER_ERROR)
        return {"items": {}}

    mocker.patch.object(client.poller, "get_domain_scoring", side_effect=score)
    failed, scored = score_risk(client, "domain", {"domain": "x.test, y.test"})
    assert failed.entry_type == EntryType.ERROR
    assert "scoring request for 'x.test' failed" in failed.readable_output
    assert scored.outputs["indicator"] == "y.test"
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=ConnectionException(ACCOUNT_REFUSAL))
    with pytest.raises(DemistoException, match="request for 'CVE-2099-0002' failed"):
        score_cves(client, {"cve": "CVE-2099-0002"})
    # a 404 or a null body still means "Group-IB has nothing about it"
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=GroupIBTIA.NotFoundException("HTTP 404: Not found."))
    results = score_cves(client, {"cve": "CVE-0000-0000"})
    assert results[0].outputs["score"] == 0
    mocker.patch.object(client.poller, "get_ip_scoring", return_value=None)
    assert score_risk(client, "ip", {"ip": "192.0.2.14"})[0].raw_response["riskScore"] is None


def test_ip_scoring_scores_every_ip_of_the_list(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(
        client.poller,
        "get_ip_scoring",
        side_effect=lambda ip: {"items": {ip: {"riskScore": {"192.0.2.14": 95, "192.0.2.78": 10}[ip]}}},
    )
    mocker.patch.object(client.poller, "graph_ip_search", return_value=None)
    results = score_risk(client, "ip", {"ip": "192.0.2.14, 192.0.2.78"})
    assert [(r.raw_response["indicator"], r.raw_response["score"]) for r in results] == [("192.0.2.14", 3), ("192.0.2.78", 1)]
    with pytest.raises(DemistoException):
        score_risk(client, "ip", {"ip": ""})


def test_incident_name_joins_list_values():
    assert IncidentBuilder._name("attacks/phishing_group", {"name": ["BrandA", "BrandB"]}) == "Phishing Group: BrandA, BrandB"


def test_by_id_lookup_does_not_mutate_the_module_mapping(mocker, single_session_fixture):
    client = single_session_fixture
    before = json.loads(json.dumps(MAPPING["compromised/breacheddb"]))
    body = {"id": ["x"], "email": ["a@example.com"], "addInfo": {"emailDomain": ["example.com"]}}
    mocker.patch.object(client.poller, "send_request", return_value=body)
    feed = read_record(client, "compromised/breacheddb", "x")
    assert MAPPING["compromised/breacheddb"] == before
    assert feed["emailDomains"] == ["example.com"]


def test_domain_scoring_scores_every_domain_of_the_list(mocker, single_session_fixture):
    client = single_session_fixture
    scores = {"evil.test": 90, "fine.test": 5}
    mocker.patch.object(client.poller, "get_domain_scoring", side_effect=lambda d: {"items": {d: {"riskScore": scores.get(d)}}})
    results = score_risk(client, "domain", {"domain": "evil.test, fine.test, unknown.test"})
    assert [(r.outputs["indicator"], r.outputs["score"], r.outputs["riskScore"]) for r in results] == [
        ("evil.test", 3, 90),
        ("fine.test", 1, 5),
        ("unknown.test", 0, None),
    ]
    assert results[0].outputs_prefix == "GIBTI.Scoring"
    # The reputation commands set the verdict; a scoring run leaves it alone.
    assert all(result.indicator is None for result in results)
    assert "no risk score" in results[2].readable_output


def test_an_ioc_primary_listing_raises_a_low_or_missing_risk_score_to_suspicious(single_session_fixture):
    """A listed IP or domain is Suspicious below a risk score of 80 or without one; unlisted and unscored it is Unknown."""
    listed = [{"type": "network", "domain": [{"domain": "sample.example", "riskScore": 90}]}]
    assert ReputationCommand._verdict("domain", {"scoring": {"score": 10}, "ioc/primary": listed}) == 2
    assert ReputationCommand._verdict("domain", {"scoring": {"score": None}, "ioc/primary": listed}) == 2
    assert ReputationCommand._verdict("domain", {"scoring": {"score": 90}, "ioc/primary": listed}) == 3
    unscored = [{"type": "network", "ip": [{"ip": "203.0.113.9"}]}]
    assert ReputationCommand._verdict("ip", {"scoring": {"score": None}, "ioc/primary": unscored}) == 2
    assert ReputationCommand._verdict("ip", {"scoring": {"score": None}}) == 0


def test_domain_reputation_fetches_the_risk_score(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client.poller, "global_search", return_value=[])
    scoring = mocker.patch.object(client.poller, "get_domain_scoring", return_value={"items": {"evil.test": {"riskScore": 95}}})
    [result] = reputation(client, "domain", {"domain": "evil.test"})
    assert scoring.call_count == 1
    assert result.raw_response["score"] == 3


def test_a_gibtia_alias_runs_and_warns_naming_its_gibti_command(mocker):
    params = {"url": "https://example.com", "credentials": {"identifier": "u", "password": "p"}}
    mocker.patch.object(GroupIBTIA.demisto, "params", return_value=params)
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value={})
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="gibtia-get-available-collections")
    mocker.patch.object(GroupIBTIA, "Client", autospec=True)
    mocker.patch.object(GroupIBTIA.AvailableCollectionsCommand, "run", return_value="ok")
    results = mocker.patch.object(GroupIBTIA, "return_results")
    warning = mocker.patch.object(GroupIBTIA, "return_warning")
    mocker.patch.object(GroupIBTIA, "return_error", side_effect=AssertionError("return_error is not called"))
    GroupIBTIA.main()
    assert results.call_count == 1
    assert warning.call_count == 1
    assert "gibti-get-available-collections" in warning.call_args.args[0]


def test_the_deprecated_mule_command_fails_naming_the_spd_command(mocker):
    params = {"url": "https://example.com", "credentials": {"identifier": "u", "password": "p"}}
    mocker.patch.object(GroupIBTIA.demisto, "params", return_value=params)
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value={"id": "x"})
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="gibti-get-compromised-mule-info")
    mocker.patch.object(GroupIBTIA, "Client", autospec=True)
    errors = mocker.patch.object(GroupIBTIA, "return_error")
    GroupIBTIA.main()
    assert errors.call_count == 1
    assert "gibti-get-compromised-spd-info" in errors.call_args.args[0]
    with pytest.raises(Exception, match="compromised/spd"):
        CollectionSpec.validate("compromised/mule")


@pytest.mark.parametrize("name", ["gibti-get-compromised-mule-info", "gibtia-get-compromised-mule-info"])
def test_the_released_mule_commands_stay_declared_as_deprecated(name):
    """A released command is never removed: a playbook that calls it gets the message naming the replacement."""
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        [block] = [block for block in yml_file.read().split("\n  - ") if f"\n    name: {name}\n" in block]
    assert "\n    deprecated: true" in block
    assert "gibti-get-compromised-spd-info" in block


def test_local_search_uses_the_collection_search_with_dates(mocker, single_session_fixture):
    client = single_session_fixture
    page = MagicMock()
    page.parse_portion.return_value = [{"id": "ta1", "name": "ExampleFox"}]
    page.raw_dict = {"items": [{"id": "ta1", "seqUpdate": 17870509246831}]}
    search = mocker.patch.object(client, "search_collection", return_value=[page])
    result = local_search(client, {"collection_name": "apt/threat_actor", "query": "examplefox", "date_from": "2024-01-01"})
    assert search.call_args.args == ("apt/threat_actor",)
    assert search.call_args.kwargs["query"] == "examplefox"
    assert search.call_args.kwargs["date_from"] == "2024-01-01T00:00:00Z"
    assert search.call_args.kwargs["sequpdate"] is None
    assert result.outputs == [{"id": "ta1", "additional_info": "Name: ExampleFox", "seqUpdate": 17870509246831}]


def test_global_search_lists_collections_the_pack_cannot_fetch(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(
        client.poller,
        "global_search",
        return_value=[
            {"apiPath": "apt/threat_actor", "label": "APT :: Actors", "count": 1, "link": "https://example.com/apt"},
            {"apiPath": "hi/analytic", "label": "Threats & Actors :: Analytics", "count": 40, "link": "https://example.com/an"},
        ],
    )
    result = global_search(client, {"query": "examplefox"})
    found = [(o["apiPath"], o["supportedByPack"]) for o in result.outputs]
    assert found == [("apt/threat_actor", True), ("hi/analytic", False)]


def _build(collection: str, record: dict) -> dict:
    parsed = Parser(chunk={"count": 1, "items": [record]}, keys=[], iocs_keys=[]).parse_portion(keys=MAPPING[collection])
    built = IncidentBuilder().build(collection, parsed[0])
    return json.loads(built["rawJSON"])


def _fixture(collection: str) -> dict:
    with open(f"{realpath}/test_data/main_collections_examples.json") as handle:
        return json.load(handle)[collection]["items"][0]


def test_actor_reports_table_dates_become_full_timestamps():
    """A date-only value in a grid date column becomes midnight UTC; a full timestamp stays as it is."""
    record = _fixture("hi/threat_actor")
    record["stat"] = {"reports": [{"id": "r-1", "name": "Report", "datePublished": "2026-08-28"}]}
    rows = _build("hi/threat_actor", record)["reports"]
    assert rows
    assert all(not IncidentBuilder.DATE_ONLY_RE.fullmatch(str(row.get("datepublished", ""))) for row in rows)
    rows = IncidentBuilder._full_dates(
        [{"datepublished": "2026-08-28", "name": "x", "count": 3}, {"datepublished": "2026-08-28T10:00:00Z"}]
    )
    assert rows == [{"datepublished": "2026-08-28T00:00:00Z", "name": "x", "count": 3}, {"datepublished": "2026-08-28T10:00:00Z"}]


def test_account_group_events_table_carries_country_name_and_source():
    record = _fixture("compromised/account_group")
    record["events"][0]["source"] = {"id": "https://messenger.example/c/1/2", "type": "Stealer logs cloud", "idType": None}
    rows = _build("compromised/account_group", record)["events_table"]
    assert rows[0]["countryname"] == record["events"][0]["client"]["ipv4"]["countryName"]
    assert rows[0]["sourcetype"] == "Stealer logs cloud"
    assert rows[0]["sourcelink"] == "https://messenger.example/c/1/2"
    assert rows[0]["ip"] == record["events"][0]["client"]["ipv4"]["ip"]  # the victim IP stays on the incident


def test_account_group_events_table_carries_host_information():
    record = _fixture("compromised/account_group")
    indexed = {
        "username": "example-user",
        "pcname": "DESKTOP-1",
        "os_raw": "Windows 11",
        "screen": "1920x1080",
        "locale": "English",
    }
    record["events"][0]["additionalData"] = {"raw": "...", "indexed": indexed}
    row = _build("compromised/account_group", record)["events_table"][0]
    assert (row["username"], row["pcname"], row["os"], row["screen"], row["locale"]) == (
        "example-user",
        "DESKTOP-1",
        "Windows 11",
        "1920x1080",
        "English",
    )


def test_ip_stored_under_domain_key_becomes_an_ip_indicator():
    record = _fixture("malware/cnc")
    record.update({"cnc": "http://203.0.113.95/x", "domain": "203.0.113.95", "url": "http://203.0.113.95/x", "ipv4": None})
    mapping = MAPPING["malware/cnc"]
    parsed = Parser(chunk={"count": 1, "items": [record]}, keys=[], iocs_keys=[]).parse_portion(keys=mapping)
    kinds = [type(r.indicator).__name__ for r in IndicatorBuilder().items(parsed[0], "malware/cnc")]
    assert "Domain" not in kinds
    assert kinds.count("IP") == 1


def test_card_group_maps_issuer_country_and_category_and_fills_cvv_from_events():
    record = _fixture("compromised/bank_card_group")
    record["cardInfo"]["category"] = "CREDIT"
    record["cardInfo"].pop("cvv", None)
    record["cardInfo"].pop("validThru", None)
    incident = _build("compromised/bank_card_group", record)
    assert incident["issuer_country_code"] == "US"
    assert incident["card_category"] == "CREDIT"
    event_card = record["events"][0]["cardInfo"]
    assert incident["cvv"] == event_card["cvv"]
    assert incident["validThru"] == event_card["validThru"]
    row = incident["compromised_events"][0]
    assert row["sourcetype"] == record["events"][0]["source"]["type"]
    assert row["sourcelink"] == record["events"][0]["source"]["id"]
    assert row["datedetected"]


def test_card_group_keeps_record_level_cvv_when_present():
    record = _fixture("compromised/bank_card_group")
    record["cardInfo"]["cvv"] = "999"
    assert _build("compromised/bank_card_group", record)["cvv"] == "999"


def test_a_breached_incident_has_a_details_table_and_a_text_id():
    record = _fixture("compromised/breacheddb")
    record["id"] = ["abc123"]
    record["addInfo"] = {
        "login": ["example_login"],
        "city": ["Exampleton"],
        "dob": ["1990-01-01"],
        "sex": [],
        "fileName": ["user.csv", "x.csv"],
    }
    incident = _build("compromised/breacheddb", record)
    assert incident["id"] == "abc123"
    assert incident["record_details"] == [
        {"key": "login", "value": "example_login"},
        {"key": "city", "value": "Exampleton"},
        {"key": "dob", "value": "1990-01-01"},
        {"key": "fileName", "value": "user.csv, x.csv"},
    ]


def test_breacheddb_actor_comes_from_the_authors_of_the_leak():
    record = _fixture("compromised/breacheddb")
    record["id"] = ["abc123"]
    record["authors"] = ["leak_publisher"]
    incident = _build("compromised/breacheddb", record)
    assert incident["threat_actor_name"] == "leak_publisher"
    assert "taName" not in MAPPING["compromised/breacheddb"].values()


def test_breacheddb_without_add_info_has_no_details_table():
    record = _fixture("compromised/breacheddb")
    record["addInfo"] = None
    assert _build("compromised/breacheddb", record)["record_details"] is None


def _fetched(mocker, client, collection: str, *items: dict, **masks: Any) -> list[dict]:
    """The incidents one fetch builds from raw API records of ``collection``, parsed by ciaops; ``masks`` are the
    password_mask and card_mask of the instance."""
    portion = Parser(chunk={"count": len(items), "items": list(items), "seqUpdate": 100}, keys=[], iocs_keys=[])
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": collection}])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([portion], None))
    _, incidents = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=[collection],
        max_requests=1,
        hunting_rules=0,
        **masks,
    )
    return incidents


def _breached_raw() -> dict:
    """A breached record as the API serves it: a list id, a null password and the leak's own columns in
    addInfo, each a list of values."""
    return {
        "id": ["b" * 40],
        "email": ["user@example.com"],
        "password": None,
        "leakName": "Example Leak",
        "authors": ["leak_publisher"],
        "addInfo": {
            "passwordFromAuthorizations0": ["Example-Secret-1"],
            "salt": ["a1b2c3"],
            "passportNumber": ["X1234567"],
            "phone": ["+1-555-0100"],
            "emailDomain": ["example.com"],
        },
        "uploadTime": "2026-10-02T01:15:00+03:00",
        "evaluation": {"admiraltyCode": "C3", "credibility": 60, "reliability": 60, "severity": "green", "tlp": "amber"},
    }


@pytest.mark.parametrize(
    "mode, credentials",
    [
        ("Off", {"passwordFromAuthorizations0": "Example-Secret-1", "salt": "a1b2c3"}),
        ("Partial", {"passwordFromAuthorizations0": "Example-****", "salt": "a1b****"}),
        ("Full", {}),
    ],
)
def test_breached_add_info_credentials_follow_the_password_mask(mocker, single_session_fixture, mode, credentials):
    client = single_session_fixture
    [incident] = _fetched(mocker, client, "compromised/breacheddb", _breached_raw(), password_mask=GroupIBTIA.PasswordMask(mode))
    raw = json.loads(incident["rawJSON"])
    details = {row["key"]: row["value"] for row in raw["record_details"]}
    assert {key: value for key, value in details.items() if key in ("passwordFromAuthorizations0", "salt")} == credentials
    assert (details["passportNumber"], details["phone"], details["emailDomain"]) == ("X1234567", "+1-555-0100", "example.com")
    assert raw["hasPassword"] is True
    assert raw["systemSeverity"] == 3
    assert ("Example-Secret-1" in incident["rawJSON"]) is (mode == "Off")


def test_breached_lookup_masks_the_add_info_credentials(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client.poller, "send_request", return_value=_breached_raw())
    feed = read_record(client, "compromised/breacheddb", "b" * 40, Masking(GroupIBTIA.PasswordMask("Full"), CardDataMask()))
    assert set(feed["record_details"]) == {"passportNumber", "phone", "emailDomain"}
    assert feed["hasPassword"] is True


def test_partial_mask_covers_numeric_and_nested_credential_columns():
    record = {"record_details": {"token": [12345678], "passwordHash": {"md5": "abcdef12"}, "city": ["Exampleton"]}}
    masked = GroupIBTIA.PasswordMask("Partial").apply("compromised/breacheddb", record)["record_details"]
    assert masked == {"token": ["1234****"], "passwordHash": {"md5": "abcd****"}, "city": ["Exampleton"]}


@pytest.mark.parametrize("mode", ["Off", "Partial", "Full"])
def test_a_breached_record_without_credentials_keeps_its_severity(mocker, single_session_fixture, mode):
    client = single_session_fixture
    record = _breached_raw()
    record["addInfo"] = {"emailDomain": ["example.com"], "passportNumber": ["X1234567"], "phone": ["+1-555-0100"]}
    [incident] = _fetched(mocker, client, "compromised/breacheddb", record, password_mask=GroupIBTIA.PasswordMask(mode))
    raw = json.loads(incident["rawJSON"])
    assert (raw["hasPassword"], raw["systemSeverity"]) == (False, 1)
    assert {row["key"]: row["value"] for row in raw["record_details"]} == {
        "emailDomain": "example.com",
        "passportNumber": "X1234567",
        "phone": "+1-555-0100",
    }


@pytest.mark.parametrize(
    "key",
    [
        "passengerName",
        "compassHeading",
        "hashtag",
        "PASSPORT_NO",
        "pass_port_no",
        "tmpassportnumber",
        "updateTimestampLong",
        "bypassFlag",
        "isPassive",
        "addressAlt",
        "passwordChangedAt",
        "password_updated_date",
        "tokenExpiry",
        "passwordExpired",
        "password_modified",
        "hashType",
        "hashAlgorithm",
        "hash_algo",
        "passwordFormat",
        "tokenKind",
        "passwordLength",
        "password_strength",
        "passwordPolicy",
        "tokenCount",
        "passwordRequired",
        "emailHash",
        "phoneHash",
        "email_md5",
        "phone_sha256",
    ],
)
def test_breached_columns_named_like_a_credential_but_not_one_are_kept(mocker, single_session_fixture, key):
    client = single_session_fixture
    record = _breached_raw()
    record["addInfo"] = {"emailDomain": ["example.com"], key: ["Sample Holder"]}
    [incident] = _fetched(mocker, client, "compromised/breacheddb", record, password_mask=GroupIBTIA.PasswordMask("Full"))
    raw = json.loads(incident["rawJSON"])
    assert (raw["hasPassword"], raw["systemSeverity"]) == (False, 1)
    assert {row["key"]: row["value"] for row in raw["record_details"]}[key] == "Sample Holder"


@pytest.mark.parametrize(
    "key",
    [
        "user_pass",
        "userPass",
        "PASSWORD",
        "userpassword",
        "passwd",
        "pwdHash",
        "hashedPassword",
        "accessToken",
        "salt",
        "hash",
        "userpass",
        "usersalt",
        "accesstoken",
        "authtoken",
        "passhash",
        "pwhash",
        "pw_hash",
        "pass_hash",
        "passwordHash",
        "hashedpass",
        "pw",
        "hashes",
        "md5",
        "SHA256",
        "md5_hash",
        "bcrypt",
        "password_hint",
    ],
)
def test_breached_credential_columns_are_recognized_by_their_words(mocker, single_session_fixture, key):
    client = single_session_fixture
    record = _breached_raw()
    record["addInfo"] = {"emailDomain": ["example.com"], key: ["Example-Secret-1"]}
    [incident] = _fetched(mocker, client, "compromised/breacheddb", record, password_mask=GroupIBTIA.PasswordMask("Partial"))
    raw = json.loads(incident["rawJSON"])
    assert (raw["hasPassword"], raw["systemSeverity"]) == (True, 3)
    assert {row["key"]: row["value"] for row in raw["record_details"]}[key] == "Example-****"


@pytest.mark.parametrize("value", [True, False, [False], [True, False], [], {}, [[], {}], {"set": False}, [None, ""]])
def test_a_breached_flag_or_an_empty_column_holds_no_credential(mocker, single_session_fixture, value):
    """A credential column holding only flags, placeholders (null, empty) or nothing exposes no credential: Full keeps
    the column, and the record keeps its severity."""
    record = {"record_details": {"passwordSet": value, "emailDomain": ["example.com"]}}
    assert GroupIBTIA.PasswordMask.credentials_in_details("compromised/breacheddb", record) == []
    masked = GroupIBTIA.PasswordMask("Full").apply("compromised/breacheddb", json.loads(json.dumps(record)))
    assert masked == record
    client = single_session_fixture
    raw_record = _breached_raw()
    raw_record["addInfo"] = {"emailDomain": ["example.com"], "passwordSet": value}
    [incident] = _fetched(mocker, client, "compromised/breacheddb", raw_record, password_mask=GroupIBTIA.PasswordMask("Full"))
    raw = json.loads(incident["rawJSON"])
    assert (raw["hasPassword"], raw["systemSeverity"]) == (False, 1)


def test_a_breached_credential_column_with_a_value_next_to_a_flag_is_one():
    record = {"record_details": {"passwordSet": [True, "Example-Secret-1"], "hash": {"value": "abcdef12", "cracked": False}}}
    assert GroupIBTIA.PasswordMask.credentials_in_details("compromised/breacheddb", record) == ["Example-Secret-1", "abcdef12"]
    assert GroupIBTIA.PasswordMask("Full").apply("compromised/breacheddb", record) == {"record_details": {}}


def test_mask_passwords_help_names_columns_as_the_code_reads_them():
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        blocks = yml_file.read().split("\n- ")
    [block] = [block for block in blocks if "\n  name: mask_passwords\n" in block]
    for key in ("user_pass", "usersalt", "accessToken", "apiKey", "sshKey", "passwordHash", "md5"):
        assert key in block
        assert GroupIBTIA.PasswordMask.is_credential_key(key)
    for key in ("emailHash", "passportNumber", "passwordChangedAt", "hashType", "passwordLength"):
        assert key in block
        assert not GroupIBTIA.PasswordMask.is_credential_key(key)
    assert "a credential column holding only a flag (true/false, 0/1), a placeholder (null, -) or nothing does not count" in block


HTML_DESCRIPTION = (
    "<h2>Summary</h2><p>Mail went to Sample Holder &lt;sample.holder@example.com&gt; and <b>Sample Owner</b> "
    "<sample.owner@example.com>.</p><figure><img src='https://portal.example.com/a.png'><figcaption>Internal"
    "</figcaption></figure><p>#include <stdio.h></p><ul><li>A &amp; B</li><li>C&nbsp;D</li></ul>end<br/>of report"
)
HTML_DESCRIPTION_TEXT = (
    "Summary\nMail went to Sample Holder <sample.holder@example.com> and Sample Owner <sample.owner@example.com>.\n"
    "#include <stdio.h>\nA & B\nC D\nend\nof report"
)


def test_report_descriptions_lose_their_markup_but_keep_text_shaped_like_a_tag():
    for collection in ("hi/threat", "apt/threat", "hi/threat_actor", "apt/threat_actor"):
        record = _fixture(collection)
        record["description"] = HTML_DESCRIPTION
        assert _build(collection, record)["description"] == HTML_DESCRIPTION_TEXT


@pytest.mark.parametrize("collection", ["hi/threat", "apt/threat", "hi/threat_actor", "apt/threat_actor", "malware/malware"])
def test_a_lookup_shows_a_description_as_its_incident_does(mocker, single_session_fixture, collection):
    record = _fixture(collection)
    record["description"] = HTML_DESCRIPTION
    [entry, *_] = _lookup_record(mocker, single_session_fixture, collection, [record])
    assert entry.outputs["description"] == HTML_DESCRIPTION_TEXT == _build(collection, record)["description"]
    assert entry.raw_response["description"] == HTML_DESCRIPTION_TEXT
    assert "<h2>" not in entry.readable_output
    assert "portal.example.com" not in entry.readable_output
    assert "A & B" in entry.readable_output


def test_escaped_markup_in_a_report_description_stays_as_text(mocker, single_session_fixture):
    """Entities are decoded once in the incident and the lookup: an escaped tag stays text, a double-escaped one stays escaped."""
    for collection in ("hi/threat", "apt/threat"):
        record = _fixture(collection)
        record["description"] = "<p>Use &lt;b&gt;x&lt;/b&gt; for bold, written &amp;lt;b&amp;gt;.</p>"
        expected = "Use <b>x</b> for bold, written &lt;b&gt;."
        assert _build(collection, record)["description"] == expected
        [entry, *_] = _lookup_record(mocker, single_session_fixture, collection, [record])
        assert entry.outputs["description"] == expected


def test_public_leak_data_is_kept_as_leaked():
    record = _fixture("osi/public_leak")
    record["data"] = "user: Sample Holder <sample.holder@example.com>\n#include <stdio.h>\n<p>x &amp; y</p>\nList<String> users"
    assert _build("osi/public_leak", record)["data"] == record["data"]


def test_vulnerability_description_is_stripped_only_when_it_holds_markup():
    record = _fixture("osi/vulnerability")
    record["description"] = "<p>Elevation of privilege in <b>Example</b> component.</p><p>Fixed in 2.1.</p>"
    assert _build("osi/vulnerability", record)["description"] == "Elevation of privilege in Example component.\nFixed in 2.1."
    record["description"] = "XSS through a crafted <script> element in the name parameter &amp; the title."
    assert _build("osi/vulnerability", record)["description"] == record["description"]
    record["description"] = "Overflow in <b>Example</b> &amp; <code>libexample</code>."
    assert _build("osi/vulnerability", record)["description"] == "Overflow in Example & libexample."
    record["description"] = "Stored XSS: the title accepts <script>alert(1)</script> unescaped."
    assert _build("osi/vulnerability", record)["description"] == record["description"]


@pytest.mark.parametrize("text", ["<" * 50_000, "<a " * 20_000, "<figure>" * 10_000 + "x"], ids=["brackets", "tags", "figures"])
def test_the_html_strip_is_linear_on_unclosed_tags(text):
    started = time.monotonic()
    IncidentBuilder._html_text(text)
    assert time.monotonic() - started < 1


def test_account_group_source_comes_from_its_events():
    record = _fixture("compromised/account_group")
    assert record["sourceType"] == []
    first, *_ = record["events"]
    record["events"] = [
        {**first, "source": {"id": "s-1", "type": "Stealer logs cloud", "idType": None}},
        {**first, "source": {"id": "s-2", "type": "TG Bot", "idType": None}},
        {**first, "source": {"id": "s-3", "type": "TG Bot", "idType": None}},
    ]
    assert _build("compromised/account_group", record)["sourceType"] == "Stealer logs cloud, TG Bot"


@pytest.mark.parametrize(
    "collection, dates, occurred",
    [
        (
            "attacks/ddos",
            {"dateBegin": "2026-10-01T10:00:00+00:00", "dateEnd": None, "dateReg": "2026-10-02T00:00:00+00:00"},
            "2026-10-01T10:00:00Z",
        ),
        ("attacks/ddos", {"dateBegin": None, "dateReg": "2026-10-02T00:00:00+00:00"}, "2026-10-02T00:00:00Z"),
        (
            "suspicious_ip/tor_node",
            {"dateFirstSeen": "2007-10-27T00:00:00Z", "dateLastSeen": "2026-10-10T08:00:00Z"},
            "2026-10-10T08:00:00Z",
        ),
        ("suspicious_ip/tor_node", {"dateFirstSeen": "2007-10-27T00:00:00Z", "dateLastSeen": None}, "2007-10-27T00:00:00Z"),
        (
            "suspicious_ip/open_proxy",
            {
                "dateFirstSeen": "2006-03-16T00:00:00Z",
                "dateLastSeen": "2026-10-11T00:00:00Z",
                "dateDetected": "2006-03-16T00:00:00Z",
            },
            "2026-10-11T00:00:00Z",
        ),
        (
            "malware/cnc",
            {"dateFirstSeen": None, "dateDetected": "2026-08-20T11:03:52Z", "dateLastSeen": "2026-09-05T00:00:00Z"},
            "2026-08-20T11:03:52Z",
        ),
        (
            "malware/cnc",
            {"dateFirstSeen": None, "dateDetected": None, "dateLastSeen": "2026-09-05T00:00:00Z"},
            "2026-09-05T00:00:00Z",
        ),
    ],
)
def test_occurred_time_falls_back_through_the_record_dates(mocker, single_session_fixture, collection, dates, occurred):
    record = {**_fixture(collection), **dates}
    [incident] = _fetched(mocker, single_session_fixture, collection, record)
    assert incident["occurred"] == occurred


@pytest.mark.parametrize("collection", ["malware/cnc", "attacks/ddos", "suspicious_ip/tor_node"])
def test_a_record_without_any_date_is_an_incident_without_an_occurred_time(mocker, single_session_fixture, collection):
    record = _fixture(collection)
    for field in ("dateBegin", "dateEnd", "dateReg", "dateFirstSeen", "dateLastSeen", "dateDetected"):
        if field in record:
            record[field] = None
    [incident] = _fetched(mocker, single_session_fixture, collection, record)
    assert "occurred" not in incident
    assert json.loads(incident["rawJSON"])["id"] == record["id"]


@pytest.mark.parametrize(
    "brand, name",
    [
        ("Index of", "Phishing Group: login.example.com"),
        ("Not specified", "Phishing Group: login.example.com"),
        ("login.example.com", "Phishing Group: login.example.com"),
        (None, "Phishing Group: login.example.com"),
        ("Example Bank", "Phishing Group: login.example.com (Example Bank)"),
        (["Example Bank", None], "Phishing Group: login.example.com (Example Bank)"),
    ],
)
def test_phishing_groups_are_named_after_their_domain_and_brand_unless_the_brand_is_a_placeholder_or_the_domain(brand, name):
    record = _fixture("attacks/phishing_group")
    record.update({"domain": "login.example.com", "brand": brand})
    record["domainInfo"]["domain"] = "login.example.com"
    assert _build("attacks/phishing_group", record)["name"] == name


def _git_raw(item_severity: str, *file_severities: str) -> dict:
    record = _fixture("osi/git_repository")
    template = record["files"][0]
    record["evaluation"]["severity"] = item_severity
    record["files"] = [
        {
            **template,
            "id": f"f-{index}",
            "name": f"config/{index}.env",
            "evaluation": {**template["evaluation"], "severity": severity},
            "revisions": [{"hash": f"h-{index}", "info": None}],
        }
        for index, severity in enumerate(file_severities)
    ]
    return record


@pytest.mark.parametrize(
    "item, files, severity",
    [
        ("green", ("gray", "red", "orange"), 3),
        ("green", ("gray", "orange"), 2),
        ("orange", ("yellow", "gray"), 2),
        ("green", ("gray",), 1),
        (None, ("yellow", "gray"), 1),
        ("gray", ("yellow",), 1),
        (None, ("gray",), 0),
    ],
)
def test_git_leak_severity_is_the_worst_of_the_repository_and_its_files(item, files, severity):
    incident = _build("osi/git_repository", _git_raw(item, *files))
    assert incident["systemSeverity"] == severity
    assert [row["severity"] for row in incident["files"]] == list(files)


def test_grid_joins_write_no_none_text_and_a_cell_of_empty_values_is_none():
    incident = _build("osi/git_repository", _git_raw("green", "red"))
    [row] = incident["files"]
    assert (row["hash"], row["authorname"], row["authoremail"]) == ("h-0", None, None)
    record = {
        "id": "s" * 40,
        "type": "Email",
        "value": {"value": "pay@example.com"},
        "serviceType": "Bank",
        "firstSeenAt": "2026-10-01T00:00:00Z",
        "evaluation": {"severity": "red", "tlp": "amber"},
        "events": [
            {"id": "e1", "malware": [{"id": "m1", "name": "ExampleBot"}], "threatActor": None, "source": {"type": "Gambling"}},
            {"id": "e2", "malware": [], "threatActor": [{"id": "t1", "name": None}], "source": {"type": "Gambling"}},
            {
                "id": "e3",
                "malware": [],
                "threatActor": [{"id": "t1", "name": None}, {"id": "t2", "name": "Example Actor"}],
                "source": {"type": "Gambling"},
            },
        ],
    }
    events = _build("compromised/spd", record)["events"]
    assert "None" not in json.dumps(events)
    assert (events[1]["threatactorid"], events[1]["threatactorname"]) == ("t1", None)
    assert (events[2]["threatactorid"], events[2]["threatactorname"]) == ("t1, t2", ", Example Actor")


def test_grid_joins_keep_each_value_in_its_position():
    record = _git_raw("green", "red")
    record["files"][0]["revisions"] = [
        {"hash": "h-1", "info": {"authorName": "Dev A", "authorEmail": "a@example.com", "dateCreated": "2026-01-01T00:00:00Z"}},
        {"hash": "h-2", "info": None},
        {"hash": "h-3", "info": {"authorName": "Dev C", "authorEmail": "c@example.com", "dateCreated": "2026-01-03T00:00:00Z"}},
    ]
    [row] = _build("osi/git_repository", record)["files"]
    assert (row["hash"], row["authorname"], row["authoremail"]) == (
        "h-1, h-2, h-3",
        "Dev A, , Dev C",
        "a@example.com, , c@example.com",
    )


def test_suspicious_ip_country_name_falls_back_to_the_country_code():
    for collection in ("suspicious_ip/open_proxy", "suspicious_ip/socks_proxy", "suspicious_ip/scanner", "suspicious_ip/vpn"):
        record = _fixture(collection)
        record["ipv4"].update({"countryCode": "US", "countryName": None})
        incident = _build(collection, record)
        assert (incident["countryCode"], incident["countryName"]) == ("US", "US")
    record = _fixture("suspicious_ip/vpn")
    record["ipv4"].update({"countryCode": "DE", "countryName": "Germany"})
    assert _build("suspicious_ip/vpn", record)["countryName"] == "Germany"


def _tor_state(as_: str, as_name: str, code: str, name: str, last_seen: str) -> dict:
    return {
        "data": {
            "fingerprint": "0" * 40,
            "as": as_,
            "asName": as_name,
            "country": code.lower(),
            "countryCode": code,
            "countryName": name,
            "dateLastSeen": last_seen,
            "flags": ["Exit", "Running"],
        },
        "md5": "1" * 32,
    }


def test_tor_geography_comes_from_the_newest_relay_state_when_the_address_has_none():
    record = {**_fixture("suspicious_ip/tor_node"), "id": "198.51.100.7"}
    record["ipv4"] = {"ip": "198.51.100.7", "asn": None, "countryCode": None, "countryName": None, "provider": None, "city": None}
    record["nodes"] = [
        {
            "dateUpdatedAt": "2026-10-10T10:00:00+00:00",
            "states": [
                _tor_state("AS64500", "Example Net A", "NL", "Netherlands", "2026-10-01T00:00:00+00:00"),
                _tor_state("AS64501", "Example Net B", "DE", "Germany", "2026-10-09T00:00:00+00:00"),
            ],
        },
        {
            "dateUpdatedAt": "2026-08-01T10:00:00+00:00",
            "states": [_tor_state("AS64502", "Example Net C", "FR", "France", "2026-07-30T00:00:00+00:00")],
        },
    ]
    incident = _build("suspicious_ip/tor_node", record)
    assert (incident["asn"], incident["provider"], incident["countryCode"], incident["countryName"]) == (
        "AS64501",
        "Example Net B",
        "DE",
        "Germany",
    )
    assert "nodes" not in incident
    record["ipv4"].update({"asn": "AS64510", "countryCode": "SE", "countryName": "Sweden", "provider": "Example Net S"})
    incident = _build("suspicious_ip/tor_node", record)
    assert (incident["asn"], incident["provider"], incident["countryCode"], incident["countryName"]) == (
        "AS64510",
        "Example Net S",
        "SE",
        "Sweden",
    )


def test_tor_country_code_comes_from_the_state_country_when_the_state_lacks_one():
    record = {**_fixture("suspicious_ip/tor_node"), "id": "198.51.100.7"}
    record["ipv4"] = {"ip": "198.51.100.7", "asn": None, "countryCode": None, "countryName": None, "provider": None}
    state = _tor_state("AS64501", "Example Net B", "DE", "Germany", "2026-10-09T00:00:00+00:00")
    del state["data"]["countryCode"], state["data"]["countryName"]
    record["nodes"] = [{"states": [state]}]
    incident = _build("suspicious_ip/tor_node", record)
    assert (incident["countryCode"], incident["countryName"]) == ("DE", "DE")


def test_tor_lookup_carries_the_relay_geography_without_the_node_list(mocker, single_session_fixture):
    record = {**_fixture("suspicious_ip/tor_node"), "id": "198.51.100.7"}
    record["ipv4"] = {"ip": "198.51.100.7", "asn": None, "countryCode": None, "countryName": None, "provider": None}
    record["nodes"] = [{"states": [_tor_state("AS64501", "Example Net B", "DE", "Germany", "2026-10-09T00:00:00+00:00")]}]
    portion = Parser(chunk={"count": 1, "items": [record], "seqUpdate": 1}, keys=[], iocs_keys=[])
    mocker.patch.object(single_session_fixture, "search_collection", return_value=[portion])
    feed = read_record(single_session_fixture, "suspicious_ip/tor_node", "198.51.100.7")
    assert (feed["asn"], feed["countryName"]) == ("AS64501", "Germany")
    assert "nodes" not in feed


def test_a_tor_relay_indicator_takes_the_as_and_country_of_its_lookup(mocker, single_session_fixture):
    """The IP indicator of a relay whose address block holds no AS or country carries the AS and the country of its newest
    consensus state, as the lookup's context and the feed do; an address block's own values come first."""
    record = {**_fixture("suspicious_ip/tor_node"), "id": "198.51.100.7"}
    record["ipv4"] = {"ip": "198.51.100.7", "asn": None, "countryCode": None, "countryName": None, "provider": None}
    state = _tor_state("AS64501", "Example Net B", "DE", "Germany", "2026-10-09T00:00:00+00:00")
    state["data"]["region"] = "Hesse"
    record["nodes"] = [{"states": [state]}]
    [ip] = _context_objects(_lookup_record(mocker, single_session_fixture, "suspicious_ip/tor_node", [record]), "IP")
    assert (ip["ASN"], ip["Organization"]["Name"], ip["Geo"]["Country"], ip["Geo"]["Description"]) == (
        "AS64501",
        "Example Net B",
        "Germany",
        "Hesse",
    )
    del state["data"]["countryName"]
    record["ipv4"].update({"asn": "AS64510", "provider": "Example Net S"})
    [ip] = _context_objects(_lookup_record(mocker, single_session_fixture, "suspicious_ip/tor_node", [record]), "IP")
    assert (ip["ASN"], ip["Organization"]["Name"], ip["Geo"]["Country"]) == ("AS64510", "Example Net S", "DE")


@pytest.mark.parametrize(
    "block, observables",
    [
        (
            {},
            {"asn": "AS64501", "provider": "Example Net B", "country_code": "DE", "country_name": "Germany", "region": "Hesse"},
        ),
        (
            {"countryCode": "SE", "countryName": "Sweden"},
            {"asn": "AS64501", "provider": "Example Net B", "country_code": "SE", "country_name": "Sweden", "region": None},
        ),
        (
            {"countryCode": "SE"},
            {"asn": "AS64501", "provider": "Example Net B", "country_code": "SE", "country_name": None, "region": None},
        ),
        (
            {"asn": "AS64510"},
            {"asn": "AS64510", "provider": None, "country_code": "DE", "country_name": "Germany", "region": "Hesse"},
        ),
    ],
)
def test_a_tor_relay_indicator_takes_a_group_from_the_state_only_where_its_block_has_none_of_it(block, observables):
    """The AS number goes with its name, and the country code with its name and region: the relay's IP
    indicator takes a group from the newest consensus state only when its address block holds none of it."""
    record = {**_fixture("suspicious_ip/tor_node"), "id": "198.51.100.7"}
    record["ipv4"] = {"ip": "198.51.100.7", **dict.fromkeys(("asn", "provider", "countryCode", "countryName", "region")), **block}
    state = _tor_state("AS64501", "Example Net B", "DE", "Germany", "2026-10-09T00:00:00+00:00")
    state["data"]["region"] = "Hesse"
    record["nodes"] = [{"states": [state]}]
    mapping = MAPPING["suspicious_ip/tor_node"]
    [parsed] = Parser(chunk={"count": 1, "items": [record]}, keys=[], iocs_keys=[]).parse_portion(keys=mapping)
    filled = IncidentBuilder.shape("suspicious_ip/tor_node", parsed)["indicators"]
    assert {key: filled.get(f"ipv4_{key}") for key in observables} == observables


def test_threat_reports_carry_no_is_tailored_flag():
    for collection in ("hi/threat", "apt/threat"):
        record = _fixture(collection)
        record["isTailored"] = False
        assert "isTailored" not in _build(collection, record)
        assert "isTailored" not in MAPPING[collection]


def test_nation_state_report_countries_are_one_text():
    record = _fixture("apt/threat")
    record["countries"] = ["US", "DE", None]
    assert _build("apt/threat", record)["countries"] == "US, DE"
    record = _fixture("hi/threat")
    record["countries"] = ["US", "DE"]
    assert _build("hi/threat", record)["countries"] == ["US", "DE"]


def test_grid_date_normalization_leaves_versions_alone():
    record = _fixture("osi/vulnerability")
    record["cpeTable"] = [{"vendor": "example", "product": "tool", "version": "2020-01-01", "type": "software", "update": ""}]
    record["affectedSoftware"] = [{"name": "tool", "operator": "lt", "version": "2021-03-04"}]
    incident = _build("osi/vulnerability", record)
    assert incident["cpeTable"][0]["version"] == "2020-01-01"
    assert incident["affectedSoftware"][0]["version"] == "2021-03-04"
    record = _fixture("hi/threat_actor")
    record["stat"]["reports"] = [{"id": "r-1", "name": {"en": "Report"}, "datePublished": "2026-08-28"}]
    assert _build("hi/threat_actor", record)["reports"][0]["datepublished"] == "2026-08-28T00:00:00Z"


MASKED_CARD_OWNER = {
    "name": "Sample Holder",
    "address": "1 Example Street",
    "birthday": "1990-01-01",
    "email": "sample.holder@example.com",
    "phone": "+1-555-0100",
    "city": "Exampleton",
    "zip": "00000",
    "passport": "X1234567",
    "taxNumber": "000-00-0000",
    "state": "CA",
    "countryCode": "US",
}


def _masked_card_raw() -> dict:
    """A masked card as the API serves it: the card masked at source, the owner not."""
    return {
        "id": "c" * 40,
        "baseName": "example-batch",
        "cardInfo": {
            "bin": ["601100"],
            "number": "601100XXXXXXXXXX",
            "cvv": None,
            "pin": None,
            "dump": None,
            "issuer": {"issuer": "EXAMPLE ISSUER", "countryCode": "US", "countryName": "United States"},
            "system": "DISCOVER",
            "category": "CREDIT",
            "type": "REWARDS",
            "validThru": "06/27",
            "validThruDate": "2027-06-30",
        },
        "client": None,
        "cnc": {
            "cnc": "shop.example.test",
            "domain": "shop.example.test",
            "ipv4": None,
            "ipv6": None,
            "url": "shop.example.test",
        },
        "dateDetected": "2026-04-14T00:15:25+00:00",
        "dateCompromised": "2025-12-29T00:00:00+00:00",
        "evaluation": {"admiraltyCode": "A2", "credibility": 80, "reliability": 90, "severity": "red", "tlp": "red", "ttl": 90},
        "isDump": False,
        "isExpired": False,
        "isMasked": False,
        "malware": {"name": "exampleshop", "id": "d" * 40, "stixGuid": None},
        "owner": dict(MASKED_CARD_OWNER),
        "price": {"currency": "USD", "value": 14.49},
        "sourceLink": "shop.example.test",
        "sourceType": "Card shop",
        "threatActor": None,
        "track": None,
    }


@pytest.mark.parametrize("enabled", [True, False])
def test_mask_card_data_masks_the_masked_card_owner_only_when_set(mocker, single_session_fixture, enabled):
    client = single_session_fixture
    [incident] = _fetched(
        mocker, client, "compromised/masked_card", _masked_card_raw(), card_mask=GroupIBTIA.CardDataMask(enabled)
    )
    raw = json.loads(incident["rawJSON"])
    owner = [
        raw[key]
        for key in (
            "owner_name",
            "address",
            "owner_birthday",
            "email",
            "phone",
            "owner_city",
            "owner_zip",
            "owner_passport",
            "owner_tax_number",
        )
    ]
    if enabled:
        assert owner == ["[redacted]"] * len(owner)
        assert "Sample Holder" not in incident["rawJSON"]
    else:
        assert owner == [MASKED_CARD_OWNER[key] for key in MASKED_CARD_OWNER if key not in ("state", "countryCode")]
    assert (raw["owner_state"], raw["owner_country_code"]) == ("CA", "US")


def test_masked_card_track_and_bin_list_only_their_values(mocker, single_session_fixture):
    record = _masked_card_raw()
    record["track"] = [None, 101]
    record["cardInfo"]["bin"] = ["601100", None]
    [incident] = _fetched(mocker, single_session_fixture, "compromised/masked_card", record)
    raw = json.loads(incident["rawJSON"])
    assert (raw["track"], raw["card_bin"]) == ("101", "601100")


def test_deface_keeps_its_own_portal_link():
    record = _fixture("attacks/deface")
    record["portalLink"] = f"https://portal.example.com/attacks/deface?searchValue=id:{record['id']}"
    assert _build("attacks/deface", record)["portalLink"] == record["portalLink"]
    record["portalLink"] = None
    assert _build("attacks/deface", record)["portalLink"] == f"{PORTAL_LINKS['attacks/deface']}{record['id']}"


def test_vulnerability_portal_link_quotes_an_id_with_a_colon():
    record = _fixture("osi/vulnerability")
    record["id"] = "WPVDB-ID:0001"
    assert _build("osi/vulnerability", record)["portalLink"] == f"{PORTAL_LINKS['osi/vulnerability']}id%3A%22WPVDB-ID%3A0001%22"
    record["id"] = "CVE-2099-0001"
    assert _build("osi/vulnerability", record)["portalLink"] == f"{PORTAL_LINKS['osi/vulnerability']}CVE-2099-0001"


def _searched(mocker, client, collection: str, *items: dict) -> list[tuple[Any, dict]]:
    """The additional info and the raw feed of each entry gibti-local-search shows for raw API records."""
    portion = Parser(chunk={"count": len(items), "items": list(items), "seqUpdate": 1}, keys=[], iocs_keys=[])
    mocker.patch.object(client, "search_collection", return_value=[portion])
    result = local_search(client, {"collection_name": collection, "query": "x", "include_raw_feed": "true"})
    return [(entry["additional_info"], json.loads(entry["raw_feed"])) for entry in result.outputs]


def test_local_search_builds_the_vulnerability_portal_link(mocker, single_session_fixture):
    advisory, cve = _fixture("osi/vulnerability"), _fixture("osi/vulnerability")
    advisory.update({"id": "RHSA-2099:0001", "portalLink": ""})
    cve.update({"id": "CVE-2099-0001", "portalLink": ""})
    links = [raw["portalLink"] for _, raw in _searched(mocker, single_session_fixture, "osi/vulnerability", advisory, cve)]
    assert links == [
        f"{PORTAL_LINKS['osi/vulnerability']}id%3A%22RHSA-2099%3A0001%22",
        f"{PORTAL_LINKS['osi/vulnerability']}CVE-2099-0001",
    ]


def test_local_search_shows_records_in_the_shape_of_their_incidents(mocker, single_session_fixture):
    group = _fixture("attacks/phishing_group")
    group.update({"domain": "login.example.com", "brand": "Index of"})
    [(info, _)] = _searched(mocker, single_session_fixture, "attacks/phishing_group", group)
    assert info == "Name: login.example.com"
    relay = {**_fixture("suspicious_ip/tor_node"), "id": "198.51.100.7"}
    relay["ipv4"] = {"ip": "198.51.100.7", "asn": None, "countryCode": None, "countryName": None, "provider": None}
    relay["nodes"] = [{"states": [_tor_state("AS64501", "Example Net B", "DE", "Germany", "2026-10-09T00:00:00+00:00")]}]
    [(_, raw)] = _searched(mocker, single_session_fixture, "suspicious_ip/tor_node", relay)
    assert "nodes" not in raw
    assert (raw["asn"], raw["provider"], raw["countryCode"], raw["countryName"]) == ("AS64501", "Example Net B", "DE", "Germany")


@pytest.mark.parametrize(
    "reports",
    [
        ["r-1", "r-2"],
        [
            {"id": "r-1", "name": {"en": "Report 1"}, "datePublished": "2026-01-01"},
            {"id": "r-2", "name": {"en": "Report 2"}, "datePublished": "2026-02-01"},
        ],
    ],
)
def test_actor_reports_are_read_as_objects_or_as_bare_ids(mocker, single_session_fixture, reports):
    for collection in ("hi/threat_actor", "apt/threat_actor"):
        record = _fixture(collection)
        record["stat"]["reports"] = reports
        names = [None, None] if isinstance(reports[0], str) else ["Report 1", "Report 2"]
        rows = _build(collection, record)["reports"]
        assert [(row["id"], row["name"]) for row in rows] == list(zip(["r-1", "r-2"], names))
        mocker.patch.object(
            single_session_fixture.poller,
            "search_feed_by_id",
            return_value=Parser(chunk=record, keys=[], iocs_keys=[]),
        )
        feed = read_record(single_session_fixture, collection, record["id"])
        assert (feed["reports"]["id"], feed["reports"]["name"]) == (["r-1", "r-2"], names)


def test_actor_profiles_carry_their_own_id_as_the_threat_actor_id():
    for collection in ("hi/threat_actor", "apt/threat_actor"):
        record = _fixture(collection)
        assert _build(collection, record)["threat_actor_id"] == record["id"]


def test_public_leak_without_matches_has_no_matches_table():
    record = _fixture("osi/public_leak")
    record["matches"] = {}
    assert _build("osi/public_leak", record)["matches"] is None


def test_ddos_without_a_target_address_is_named_after_its_domain_or_id():
    record = _fixture("attacks/ddos")
    record["target"]["ipv4"] = None
    record["target"]["domain"] = "victim.example.com"
    assert _build("attacks/ddos", record)["name"] == "Attacks DDoS: victim.example.com"
    record["target"] = None
    assert _build("attacks/ddos", record)["name"] == f"Attacks DDoS: {record['id']}"


def test_threat_reports_map_victims_sources_report_type_and_files():
    for collection in ("hi/threat", "apt/threat"):
        record = _fixture(collection)
        record.update(
            {
                "type": "threat",
                "sources": ["http://dls.example/post/1"],
                "targetedCompany": ["Example Wire Co"],
                "targetedPartnersAndClients": ["Sample Partner Ltd"],
                "targetDomain": ["victim-corp.example"],
                "countries": ["KR"],
                "files": [{"hash": "a" * 64, "mime": "image/png", "name": "shot.png", "size": 10}],
                "dateFirstSeen": "2026-03-23",
                "dateLastSeen": "2026-03-24",
            }
        )
        incident = _build(collection, record)
        assert incident["report_type"] == "threat"
        assert incident["sources"] == ["http://dls.example/post/1"]
        assert incident["targeted_companies"] == ["Example Wire Co"]
        assert incident["targeted_partners_and_clients"] == ["Sample Partner Ltd"]
        assert incident["target_domains"] == ["victim-corp.example"]
        assert incident["countries"] == (["KR"] if collection == "hi/threat" else "KR")
        assert incident["files"] == [{"hash": "a" * 64, "mime": "image/png", "name": "shot.png", "size": 10}]
        assert incident["dateFirstSeen"].startswith("2026-03-23"), collection
        assert incident["dateLastSeen"].startswith("2026-03-24"), collection


def test_threat_report_without_files_has_no_files_table():
    record = _fixture("hi/threat")
    record["files"] = []
    assert _build("hi/threat", record)["files"] is None


def _lookup(feed_indicators: dict, collection: str, severity: str = "red", **kwargs):
    feed = {"evaluation": {"severity": severity}, "indicators": feed_indicators}
    return IndicatorBuilder(**kwargs).items(feed, collection)


def _entries(result: CommandResults) -> list[tuple]:
    entries = [r.to_entry() for r in (result.relationships or [])]
    return [(r["entityA"], r["entityAType"], r["name"], r["entityB"], r["entityBType"]) for r in entries]


def test_cnc_ip_lookup_carries_provider_country_code_malware_and_actor():
    results = _lookup(
        {
            "ipv4_ip": "203.0.113.7",
            "ipv4_asn": "AS64500",
            "country_name": [],
            "ipv4_country_code": "DE",
            "ipv4_region": "Berlin",
            "ipv4_provider": "Example Hosting",
            "malware_names": "BankerOne",
            "threat_actor_names": "CrewOne",
        },
        "malware/cnc",
        create_relationships=True,
    )
    assert [type(r.indicator).__name__ for r in results] == ["IP"]
    ip = results[0].indicator
    assert (ip.ip, ip.asn, ip.geo_country, ip.geo_description, ip.organization_name) == (
        "203.0.113.7",
        "AS64500",
        "DE",
        "Berlin",
        "Example Hosting",
    )
    assert ip.malware_family == ["BankerOne"]
    assert ip.tags == ["malware/cnc", "BankerOne", "CrewOne"]
    assert ip.dbot_score.score == 3
    assert _entries(results[0]) == [
        ("203.0.113.7", "IP", "indicator-of", "BankerOne", "Malware"),
        ("203.0.113.7", "IP", "related-to", "CrewOne", "Threat Actor"),
    ]


def test_country_name_wins_over_the_code_and_event_lists_are_joined():
    ip = _lookup(
        {
            "ipv4_ip": ["198.51.100.5"],
            "ipv4_asn": ["AS64496", "AS64497"],
            "country_name": ["Germany"],
            "ipv4_country_code": ["DE"],
            "ipv4_provider": [],
            "malware_names": [],
            "threat_actor_names": [],
        },
        "malware/cnc",
    )[0].indicator
    assert ip.geo_country == "Germany"
    assert ip.asn == "AS64496, AS64497"
    assert ip.organization_name is None
    assert ip.malware_family is None
    assert ip.tags == ["malware/cnc"]


@pytest.mark.parametrize("collection", ["compromised/bank_card_group", "compromised/masked_card"])
def test_the_card_shop_is_never_an_indicator(collection):
    """The cnc block of the card feeds is the shop the card was offered in, not attacker
    infrastructure, and never an indicator."""
    assert collection not in INDICATORS_TYPES
    assert "indicators" not in MAPPING[collection]
    shop = {"cnc_url": "https://shop.example/", "cnc_domain": "shop.example", "cnc_ipv4_ip": "203.0.113.7"}
    assert _lookup(shop, collection) == []
    assert IncidentBuilder._related_indicators(collection, {"id": "c", "indicators": shop}) in ("", None, [])


def test_an_observable_with_empty_attribute_lists_only_is_still_dropped_but_record_fields_do_not_count():
    # Every per-observable attribute list is empty: nothing usable.
    assert IndicatorBuilder._carries_no_data({"asn": [], "geocountry": []}) is True
    # Record-level names do not decide whether an observable exists.
    assert IndicatorBuilder._carries_no_data({"malware_family": [], "threat_actor_names": []}) is False
    results = _lookup(
        {"ipv4": ["203.0.113.1"], "domain": [], "url": [], "hashes_md5": [], "malware_names": [], "threat_actor_names": []},
        "hi/threat",
    )
    assert [r.indicator.ip for r in results] == ["203.0.113.1"]


def test_phishing_group_lookup_carries_brand_and_actor():
    results = _lookup(
        {
            "url": ["http://phish.test/login"],
            "phishing_domain_domain": "phish.test",
            "phishing_domain_registrar": "Example Registrar",
            "domain_registered": "2026-01-01T00:00:00+00:00",
            "domain_expiration": "2027-01-01T00:00:00+00:00",
            "brand": "Example Bank",
            "objective": "Banking",
            "threat_actor_names": ["Phisher"],
        },
        "attacks/phishing_group",
        severity="orange",
        create_relationships=True,
    )
    by_type = {type(r.indicator).__name__: r for r in results}
    assert list(by_type) == ["URL"]
    assert by_type["URL"].indicator.tags == ["attacks/phishing_group", "Phisher", "Example Bank"]
    assert _entries(by_type["URL"]) == [("http://phish.test/login", "URL", "related-to", "Phisher", "Threat Actor")]
    assert "brand" in IndicatorBuilder.RECORD_LEVEL_FIELDS


def test_threat_report_observables_carry_the_report_malware_and_actor():
    results = _lookup(
        {
            "ipv4": ["203.0.113.1", "203.0.113.2"],
            "domain": ["cnc.test"],
            "url": [],
            "hashes_md5": ["c" * 32],
            "hashes_sha1": ["a" * 40],
            "hashes_sha256": ["b" * 64],
            "name": ["dropper.exe"],
            "size": [1024],
            "malware_names": ["LoaderOne"],
            "threat_actor_names": "ExampleGang",
        },
        "hi/threat",
        create_relationships=True,
    )
    indicators = [r.indicator for r in results]
    assert len(indicators) == 4
    assert all(i.malware_family == ["LoaderOne"] and i.tags == ["hi/threat", "LoaderOne", "ExampleGang"] for i in indicators)
    file_result = next(r for r in results if type(r.indicator).__name__ == "File")
    assert file_result.indicator.name == "dropper.exe"
    assert _entries(file_result) == [
        ("b" * 64, "File", "indicator-of", "LoaderOne", "Malware"),
        ("b" * 64, "File", "related-to", "ExampleGang", "Threat Actor"),
    ]


def test_lookup_relationships_follow_the_instance_setting(mocker, single_session_fixture):
    feed_indicators = {"event_url": ["http://cnc.test/gate"], "event_domain": [], "malware_names": ["BankerFive"]}
    assert _lookup(feed_indicators, "compromised/account_group")[0].relationships == []
    assert _lookup(feed_indicators, "compromised/account_group", create_relationships=True)[0].relationships
    # the lookup command takes the instance setting
    client = single_session_fixture
    record = {
        "id": "c" * 40,
        "cnc": "c2.example.com",
        "domain": "c2.example.com",
        "url": None,
        "ipv4": [],
        "malwareList": [{"name": "BankerFive"}],
    }
    related = _lookup_record(mocker, client, "malware/cnc", [record], create_relationships=True)
    assert [entry for entry in related if entry.relationships]
    unrelated = _lookup_record(mocker, client, "malware/cnc", [record], create_relationships=False)
    assert all(not entry.relationships for entry in unrelated)


def test_an_ip_stored_under_the_domain_key_relates_as_an_ip():
    results = _lookup(
        {"url": [], "domain": "203.0.113.45", "ipv4_ip": [], "malware_names": ["BotnetTwo"]},
        "malware/cnc",
        create_relationships=True,
    )
    assert _entries(results[0]) == [("203.0.113.45", "IP", "indicator-of", "BotnetTwo", "Malware")]


def test_reputation_run_relates_the_observable_to_malware_and_actors(single_session_fixture, mocker):
    client = single_session_fixture
    data = {
        "ioc/primary": [{"malwareList": [{"name": "LoaderOne"}], "threatList": [{"name": "ExampleGang"}]}],
        "apt/threat": [{"threat_actor_name": "ExampleActor", "tlp": "red"}],
        "scoring": {"score": 90},
    }
    mocker.patch.object(GroupIBTIA.ReputationCommand, "_lookup", return_value=(data, {}, []))
    mocker.patch.object(GroupIBTIA.ReputationCommand, "_verdict", return_value=3)
    mocker.patch.object(GroupIBTIA.ReputationCommand, "_reliability", return_value="A - Completely reliable")
    [result] = reputation(client, "domain", {"domain": "example.com"})
    assert _entries(result) == [
        ("example.com", "Domain", "indicator-of", "LoaderOne", "Malware"),
        ("example.com", "Domain", "related-to", "ExampleActor", "Threat Actor"),
    ]
    assert result.indicator.tags == ["ioc/primary", "ExampleGang", "apt/threat", "ExampleActor"]
    assert result.indicator.malware_family == ["LoaderOne"]
    assert result.raw_response["threatActors"] == ["ExampleActor"]
    assert reputation(client, "domain", {"domain": "example.com"}, create_relationships=False)[0].relationships is None


def test_main_runs_a_command_with_the_instance_settings(mocker):
    params = {
        "url": "https://example.com",
        "credentials": {"identifier": "u", "password": "p"},
        "create_relationships": False,
        "mask_passwords": "Partial",
        "mask_card_data": True,
        "reputation_floor_collections": "suspicious_ip/tor_node",
        "search_timeout": "5",
    }
    settings = Settings.from_params(params)
    captured = {
        "create_relationships": settings.create_relationships,
        "mask_passwords": settings.masking.password_mask.mode,
        "mask_card_data": settings.masking.card_mask.enabled,
        "floor": settings.floor_collections,
        "search_timeout": settings.search_timeout,
    }
    assert captured == {
        "create_relationships": False,
        "mask_passwords": "Partial",
        "mask_card_data": True,
        "floor": frozenset({"suspicious_ip/tor_node"}),
        "search_timeout": 5.0,
    }
    # main() runs the command with these settings
    search = mocker.patch.object(GroupIBTIA, "SearchCommand")
    run_main(mocker, params, "gibti-global-search")
    scope, _, passed = search.call_args.args
    assert scope == "global"
    assert dataclasses.replace(passed, masking=settings.masking) == settings
    assert (passed.masking.password_mask.mode, passed.masking.card_mask.enabled) == ("Partial", True)
    search.return_value.run.assert_called_once_with({})


def test_lookup_indicator_entries_are_extracted_and_skip_long_texts():
    record = {
        "evaluation": {"severity": "red"},
        "indicators": {
            "id": "CVE-2021-1",
            "cvss_score": 9.8,
            "description": "see https://vendor.example/advisory for details",
            "software_mixed": [{"softwareName": "x"}],
            "severity": "red",
        },
    }
    [entry] = IndicatorBuilder().results(record, "osi/vulnerability")
    assert entry.ignore_auto_extract is False
    assert "vendor.example" not in entry.readable_output
    assert "CVE-2021-1" in entry.readable_output
    [cve] = next(value for key, value in entry.to_context()["EntryContext"].items() if key.startswith("CVE"))
    assert cve["Description"] == "see https://vendor.example/advisory for details"


def test_scoring_results_are_extracted(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client.poller, "get_ip_scoring", return_value={"items": {"192.0.2.14": {"riskScore": 90}}})
    [result] = score_risk(client, "ip", {"ip": "192.0.2.14"})
    assert result.ignore_auto_extract is False


def test_an_incident_records_whether_hunting_rules_were_applied():
    record = {"id": "1", "name": "n", "dateFirstSeen": "2024-01-01T00:00:00+00:00", "evaluation": {"severity": "green"}}
    filtered = IncidentBuilder().build("suspicious_ip/tor_node", dict(record), hunting_rules_applied=True)
    unfiltered = IncidentBuilder().build("suspicious_ip/tor_node", dict(record), hunting_rules_applied=False)
    lookup = IncidentBuilder().build("suspicious_ip/tor_node", dict(record))
    assert json.loads(filtered["rawJSON"])["huntingRulesApplied"] is True
    assert json.loads(unfiltered["rawJSON"])["huntingRulesApplied"] is False
    assert json.loads(lookup["rawJSON"])["huntingRulesApplied"] is None


def test_fetch_stamps_incidents_with_the_hunting_rules_flag(mocker, single_session_fixture):
    client = single_session_fixture
    portion = MagicMock()
    portion.sequpdate = 1592219410029000
    portion.portion_size = 1
    portion.count = 1
    record = {
        "id": "203.0.113.170",
        "name": "203.0.113.170",
        "dateFirstSeen": "2024-01-01T00:00:00+00:00",
        "evaluation": {"severity": "green"},
    }
    portion.parse_portion.return_value = [record]
    mocker.patch.object(
        client,
        "granted_collections",
        return_value=[{"collection": "suspicious_ip/tor_node", "huntingRulesUsed": True}],
    )
    opener = mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([portion], None))
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_hunting_rules", return_value=1)
    _, incidents = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="7 days",
        incident_collections=["suspicious_ip/tor_node"],
        max_requests=1,
        hunting_rules=1,
    )
    assert incidents
    assert json.loads(incidents[0]["rawJSON"])["huntingRulesApplied"] is True
    assert opener.call_args.kwargs["hunting_rules"] == 1


def test_a_cybercriminal_threat_incident_carries_its_labels():
    with open(os.path.join(realpath, "test_data", "main_collections_examples.json")) as handle:
        record = json.load(handle)["hi/threat"]["items"][0]
    record["labels"] = ["Ransomware DLS"]
    parsed = Parser(chunk={"count": 1, "items": [record]}, keys=[], iocs_keys=[]).parse_portion(keys=MAPPING["hi/threat"])
    incident = json.loads(IncidentBuilder().build("hi/threat", parsed[0])["rawJSON"])
    assert incident["labels"] == ["Ransomware DLS"]


def _lookup_indicators(collection, feed):
    return [r.indicator for r in IndicatorBuilder("A - Completely reliable").items(feed, collection)]


def test_lookup_indicator_takes_the_collection_verdict():
    cnc = _lookup_indicators("malware/cnc", {"id": "x", "indicators": {"ipv4_ip": "203.0.113.5", "domain": "c2.example"}})
    assert cnc
    assert {i.dbot_score.score for i in cnc} == {GroupIBTIA.Common.DBotScore.BAD}
    deface = _lookup_indicators("attacks/deface", {"id": "x", "indicators": {"url": "http://defaced.example/x"}})
    assert deface
    assert deface[0].dbot_score.score == GroupIBTIA.Common.DBotScore.SUSPICIOUS


@pytest.mark.parametrize(
    "collection, indicators, expected",
    [
        # A Tor exit node is "green" in Group-IB's evaluation: an anonymizer, not a benign IP.
        ("suspicious_ip/tor_node", {"ipv4_ip": "203.0.113.54"}, 2),
        ("malware/cnc", {"ipv4_ip": "203.0.113.5"}, 3),
        ("apt/threat", {"ipv4": ["203.0.113.6"]}, 3),
        ("attacks/phishing_group", {"url": ["http://phish.test/"]}, 2),
    ],
)
def test_lookup_indicator_verdict_ignores_the_record_severity(collection, indicators, expected):
    feed = {"id": "x", "evaluation": {"severity": "green"}, "indicators": indicators}
    assert [i.dbot_score.score for i in _lookup_indicators(collection, feed)] == [expected]


@pytest.mark.parametrize("illegal_score, expected", [(95, 3), (80, 3), (79, 2), (0, 2), (None, 2)])
def test_payment_detail_verdict_follows_the_illegal_score(illegal_score, expected):
    indicators = {"value_value": "bc1qexample", "type": "Cryptocurrency Wallet", "illegal_score": illegal_score}
    feed = {"id": "x", "evaluation": {"severity": "green"}, "indicators": indicators}
    assert [i.dbot_score.score for i in _lookup_indicators("compromised/spd", feed)] == [expected]


@pytest.mark.parametrize(
    "risk_score, expected",
    [(None, 0), (-1, 0), (0, 1), (1, 1), (25, 1), (39, 1), (40, 2), (79, 2), (80, 3), (100, 3), (101, 0), ("85", 3)],
)
def test_risk_score_follows_the_group_ib_scale(risk_score, expected):
    assert IndicatorBuilder.risk_score_verdict(risk_score) == expected


@pytest.mark.parametrize("kind", ["ip", "domain"])
@pytest.mark.parametrize(
    ("risk_score", "verdict"), [(None, 0), (0, 1), (39, 1), (40, 2), (79, 2), (80, 3), (100, 3), (101, 0), (-1, 0)]
)
def test_an_unlisted_ip_or_domain_takes_its_verdict_from_the_risk_score(kind, risk_score, verdict):
    """Good from 0 to 39, Suspicious from 40, Bad from 80 to 100, else Unknown; mentions in other collections do not count."""
    mention = {"apt/threat": [{"id": "r"}], "hi/open_threats": [{"id": "p"}], "attacks/deface": [{"id": "d"}]}
    assert ReputationCommand._verdict(kind, {"scoring": {"score": risk_score}, **mention}) == verdict


@pytest.mark.parametrize("kind", ["ip", "domain"])
@pytest.mark.parametrize(("risk_score", "verdict"), [(None, 2), (0, 2), (39, 2), (40, 2), (79, 2), (80, 3), (100, 3)])
def test_an_ioc_primary_listing_keeps_an_ip_or_domain_at_least_suspicious(kind, risk_score, verdict):
    value = "sample.example" if kind == "domain" else "203.0.113.9"
    listed = [{"type": "network", kind: [{kind: value, "riskScore": 10}]}]
    assert ReputationCommand._verdict(kind, {"scoring": {"score": risk_score}, "ioc/primary": listed}) == verdict


@pytest.mark.parametrize(("kind", "value"), [("ip", "203.0.113.9"), ("domain", "sample.example")])
@pytest.mark.parametrize(("risk_score", "verdict"), [(0, 1), (39, 1), (40, 2), (79, 2), (80, 3), (100, 3)])
def test_the_verdict_of_an_unlisted_ip_or_domain_changes_at_risk_scores_40_and_80(
    mocker, single_session_fixture, kind, value, risk_score, verdict
):
    client = _reputation_client(mocker, single_session_fixture, {}, {value: risk_score})
    [result] = reputation(client, kind, {kind: value})
    assert (result.indicator.dbot_score.score, result.raw_response["riskScore"]) == (verdict, risk_score)


@pytest.mark.parametrize(("kind", "value"), [("ip", "203.0.113.9"), ("domain", "sample.example")])
def test_an_unlisted_ip_or_domain_without_a_risk_score_is_unknown(mocker, single_session_fixture, kind, value):
    client = _reputation_client(mocker, single_session_fixture, {"apt/threat": [{"id": "r"}]})
    [result] = reputation(client, kind, {kind: value})
    assert (result.indicator.dbot_score.score, result.raw_response["riskScore"]) == (0, None)


def _reputation_client(mocker, client, records: dict[str, list], scores: dict[str, int | None] | None = None):
    """A client whose collection reads and global search find ``records`` (collection -> records), with risk ``scores``."""
    mocker.patch.object(
        client.poller,
        "global_search",
        side_effect=lambda value: [{"apiPath": path, "count": len(items)} for path, items in records.items()],
    )
    mocker.patch.object(ReputationCommand, "_read", side_effect=lambda path, value, keys=None: records.get(path, []))
    mocker.patch.object(ReputationCommand, "_listing", side_effect=lambda path, value: records.get(path, []))
    scoring = {"items": {value: {"riskScore": score} for value, score in (scores or {}).items()}}
    mocker.patch.object(client.poller, "get_ip_scoring", return_value=scoring)
    mocker.patch.object(client.poller, "get_domain_scoring", return_value=scoring)
    mocker.patch.object(client.poller, "graph_ip_search", return_value=None)
    mocker.patch.object(client.poller, "graph_domain_search", return_value=None)
    return client


@pytest.mark.parametrize(
    ("element", "verdict"),
    [
        ({"ip": "203.0.113.9", "riskScore": 95}, 2),
        ({"ip": "203.0.113.9", "riskScore": 10}, 2),
        ({"ip": "203.0.113.9", "riskScore": 0}, 2),
        ({"ip": "203.0.113.9"}, 2),
        ({"ip": "203.0.113.10", "riskScore": 95}, 0),
    ],
)
def test_without_a_risk_score_an_ip_ioc_primary_lists_is_suspicious_whatever_its_element_score(
    mocker, single_session_fixture, element, verdict
):
    """Suspicious when ioc/primary lists the IP, Unknown when it lists another one."""
    client = _reputation_client(mocker, single_session_fixture, {"ioc/primary": [{"type": "network", "ip": [element]}]})
    [result] = reputation(client, "ip", {"ip": "203.0.113.9"})
    assert result.indicator.dbot_score.score == verdict
    assert result.raw_response["riskScore"] is None


@pytest.mark.parametrize(
    ("element", "verdict"),
    [
        ({"domain": "Sample.Example", "riskScore": 60}, 2),
        ({"domain": "sample.example", "riskScore": 0}, 2),
        ({"domain": "sample.example"}, 2),
        ({"domain": "other.example", "riskScore": 60}, 1),
    ],
)
def test_a_domain_with_a_zero_risk_score_is_suspicious_when_ioc_primary_lists_it_and_good_otherwise(
    mocker, single_session_fixture, element, verdict
):
    records = {"ioc/primary": [{"type": "network", "domain": [element]}]}
    client = _reputation_client(mocker, single_session_fixture, records, {"sample.example": 0})
    [result] = reputation(client, "domain", {"domain": "sample.example"})
    assert result.indicator.dbot_score.score == verdict


@pytest.mark.parametrize(("risk", "verdict"), [(0, 2), (10, 2), (39, 2), (40, 2), (79, 2), (80, 3), (100, 3)])
def test_an_ip_ioc_primary_lists_is_suspicious_below_a_risk_score_of_80_and_bad_from_it(
    mocker, single_session_fixture, risk, verdict
):
    records = {"ioc/primary": [{"type": "network", "ip": [{"ip": "203.0.113.9", "riskScore": 10}]}]}
    client = _reputation_client(mocker, single_session_fixture, records, {"203.0.113.9": risk})
    [result] = reputation(client, "ip", {"ip": "203.0.113.9"})
    assert (result.indicator.dbot_score.score, result.raw_response["riskScore"]) == (verdict, risk)


@pytest.mark.parametrize(
    ("records", "verdict"), [({"ioc/primary": [{"type": "network", "ip": [{"ip": "2001:db8::5"}]}]}, 2), ({}, 0)]
)
def test_an_ipv6_address_without_a_risk_score_is_suspicious_when_ioc_primary_lists_it_and_unknown_otherwise(
    mocker, single_session_fixture, records, verdict
):
    client = _reputation_client(mocker, single_session_fixture, records)
    [result] = reputation(client, "ip", {"ip": "2001:db8::5"})
    client.poller.get_ip_scoring.assert_not_called()
    assert (result.indicator.dbot_score.score, result.raw_response["riskScore"]) == (verdict, None)


def test_an_ioc_primary_decision_takes_the_tlp_malware_and_actors_of_its_record(mocker, single_session_fixture):
    record = {
        "type": "network",
        "ip": [{"ip": "203.0.113.9", "riskScore": 90}],
        "malwareList": [{"name": "Sample Loader"}],
        "threatActorList": [{"name": "Sample Actor"}],
        "evaluation": {"TLP": "TLP:AMBER"},
    }
    client = _reputation_client(mocker, single_session_fixture, {"ioc/primary": [record]})
    [result] = reputation(client, "ip", {"ip": "203.0.113.9"}, create_relationships=True)
    assert result.indicator.dbot_score.score == 2
    assert result.indicator.traffic_light_protocol == "AMBER"
    assert result.indicator.malware_family == ["Sample Loader"]
    assert result.raw_response["threatActors"] == ["Sample Actor"]
    assert _entries(result) == [
        ("203.0.113.9", "IP", "indicator-of", "Sample Loader", "Malware"),
        ("203.0.113.9", "IP", "related-to", "Sample Actor", "Threat Actor"),
    ]


def test_ip_reputation_answers_every_ip_of_the_list(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"198.51.100.27": 90, "203.0.113.54": 60})
    results = reputation(client, "ip", {"ip": "198.51.100.27,203.0.113.54"})
    assert [(r.indicator.ip, r.indicator.dbot_score.score) for r in results] == [("198.51.100.27", 3), ("203.0.113.54", 2)]
    asked = [c.kwargs["value"] for c in ReputationCommand._read.call_args_list if c.kwargs["path"] == "ioc/primary"]
    assert asked == ["198.51.100.27", "203.0.113.54"]
    client.poller.global_search.assert_not_called()


def _scoring(scores: dict[str, int]) -> Any:
    """A scoring answer for a value or a list of values, from ``scores``."""

    def answer(values: str | list[str]) -> dict:
        asked = [values] if isinstance(values, str) else values
        return {"items": {value: {"riskScore": scores[value]} for value in asked if value in scores}}

    return answer


def test_ip_reputation_asks_the_risk_scores_of_the_list_in_one_request(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {})
    scores = {"198.51.100.27": 90, "203.0.113.54": 60}
    client.poller.get_ip_scoring.side_effect = _scoring(scores)
    results = reputation(client, "ip", {"ip": "198.51.100.27,203.0.113.54,2001:db8::5,not-an-ip"})
    assert [r.raw_response["riskScore"] for r in results[:2]] == [90, 60]
    # IPv6 and a value that is no address are not scored
    assert [c.args[0] for c in client.poller.get_ip_scoring.call_args_list] == [["198.51.100.27", "203.0.113.54"]]


def test_domain_reputation_asks_one_value_on_its_own(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {})
    client.poller.get_domain_scoring.side_effect = _scoring({"example.com": 85})
    [result] = reputation(client, "domain", {"domain": "Example.COM."})
    assert result.raw_response["riskScore"] == 85
    assert [c.args[0] for c in client.poller.get_domain_scoring.call_args_list] == ["example.com"]


def test_reputation_asks_each_value_when_the_list_request_fails(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {})
    answer = _scoring({"sample-one.example": 85, "sample-two.example": 20})

    def scoring(values: str | list[str]) -> dict:
        if isinstance(values, list):
            raise RuntimeError("sample scoring failure")
        return answer(values)

    client.poller.get_domain_scoring.side_effect = scoring
    results = reputation(client, "domain", {"domain": "sample-one.example,sample-two.example"})
    assert [(r.raw_response["riskScore"], r.outputs["partial"]) for r in results] == [(85, False), (20, False)]
    asked = [c.args[0] for c in client.poller.get_domain_scoring.call_args_list]
    assert asked == [["sample-one.example", "sample-two.example"], "sample-one.example", "sample-two.example"]


@pytest.mark.parametrize("late", [False, True])
def test_a_list_scoring_request_that_fails_or_is_late_is_logged_as_such(mocker, single_session_fixture, late):
    client = _reputation_client(mocker, single_session_fixture, {})
    answer = _scoring({"198.51.100.27": 90, "203.0.113.54": 60})
    released = threading.Event()

    def scoring(values: str | list[str]) -> dict:
        if isinstance(values, list):
            if not late:
                raise RuntimeError("sample scoring failure")
            released.wait(5)
        return answer(values)

    client.poller.get_ip_scoring.side_effect = scoring
    debug = mocker.patch.object(GroupIBTIA.demisto, "debug")
    try:
        reputation(client, "ip", {"ip": "198.51.100.27,203.0.113.54"}, search_timeout=0.2)
    finally:
        released.set()
    logged = [str(call.args[0]) for call in debug.call_args_list if "values together" in str(call.args[0])]
    assert logged == [
        "[reputation] ip scoring of 2 values together was late"
        if late
        else "[reputation] ip scoring of 2 values together failed: sample scoring failure"
    ]


def test_reputation_asks_each_value_when_the_list_request_is_late(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {})
    answer = _scoring({"198.51.100.27": 90, "203.0.113.54": 60})
    released = threading.Event()

    def scoring(values: str | list[str]) -> dict:
        if isinstance(values, list):
            released.wait(5)
        return answer(values)

    client.poller.get_ip_scoring.side_effect = scoring
    try:
        results = reputation(client, "ip", {"ip": "198.51.100.27,203.0.113.54"}, search_timeout=0.2)
    finally:
        released.set()
    assert [r.raw_response["riskScore"] for r in results] == [90, 60]


def test_risk_scores_asks_at_most_one_hundred_values_a_request(mocker, single_session_fixture):
    client = single_session_fixture
    values = [f"sample-{index}.example" for index in range(150)]
    mocker.patch.object(client.poller, "get_domain_scoring", side_effect=_scoring({"sample-0.example": 40}))
    scores = client.risk_scores("domain", values)
    assert [len(c.args[0]) for c in client.poller.get_domain_scoring.call_args_list] == [100, 50]
    assert scores == {value: (40 if value == "sample-0.example" else None) for value in values}


def test_ip_scoring_asks_nothing_about_an_internal_address_unless_set(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client.poller, "get_ip_scoring", side_effect=_scoring({"10.0.0.1": 0}))
    [skipped] = ScoringCommand("ip", client, settings_with(lookup_internal_addresses=False)).run({"ip": "10.0.0.1"})
    assert "Group-IB was not asked about it" in skipped.readable_output
    client.poller.get_ip_scoring.assert_not_called()
    [asked] = ScoringCommand("ip", client, settings_with(lookup_internal_addresses=True)).run({"ip": "10.0.0.1"})
    assert asked.raw_response["riskScore"] == 0


def test_ip_scoring_asks_the_list_in_one_request_and_each_value_after_a_failure(mocker, single_session_fixture):
    client = single_session_fixture
    answer = _scoring({"198.51.100.27": 90, "203.0.113.54": 10})
    mocker.patch.object(client.poller, "get_ip_scoring", side_effect=answer)
    results = score_risk(client, "ip", {"ip": "198.51.100.27,203.0.113.54,2001:db8::5"})
    assert [r.raw_response["riskScore"] for r in results] == [90, 10, None]
    assert [c.args[0] for c in client.poller.get_ip_scoring.call_args_list] == [["198.51.100.27", "203.0.113.54"]]

    def failing(values: str | list[str]) -> dict:
        if isinstance(values, list):
            raise RuntimeError("sample scoring failure")
        return answer(values)

    client.poller.get_ip_scoring.side_effect = failing
    client.poller.get_ip_scoring.reset_mock()
    results = score_risk(client, "ip", {"ip": "198.51.100.27,203.0.113.54"})
    assert [r.raw_response["riskScore"] for r in results] == [90, 10]
    assert len(client.poller.get_ip_scoring.call_args_list) == 3


def test_ip_reputation_writes_an_ipv6_address_under_ipv6(mocker, single_session_fixture):
    """The lookups write an IPv6 address to IPv6 context; the reputation command writes it there too."""
    client = _reputation_client(mocker, single_session_fixture, {}, {"2001:db8::5": 90, "198.51.100.27": 90})
    roots = [
        {key.split("(", 1)[0] for key in result.to_context()["EntryContext"]}
        for result in reputation(client, "ip", {"ip": "2001:db8::5,198.51.100.27"})
    ]
    assert [root - {"DBotScore", "GIBTI.Reputation"} for root in roots] == [{"IPv6"}, {"IP"}]
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        blocks = yml_file.read().split("\n  - ")
    [block] = [block for block in blocks if block.startswith("name: ip\n")]
    assert "contextPath: IPv6.Address" in block


def test_a_low_risk_ip_gets_no_malware_or_actor_names_and_a_risky_ip_gets_those_of_every_record(mocker, single_session_fixture):
    records = {
        "ioc/primary": [
            {
                "type": "network",
                "ip": [{"ip": "203.0.113.9", "riskScore": 90}],
                "malwareList": [{"name": "Sample Stealer"}],
                "threatList": [{"name": "Sample Group campaign"}],
                "threatActorList": [{"name": "Sample Primary Group"}],
            }
        ],
        "apt/threat": [{"threatActor": {"name": "Sample Group"}, "malwareList": [{"name": "Sample Backdoor"}]}],
    }
    client = _reputation_client(mocker, single_session_fixture, records, {"198.51.100.88": 25})
    [result] = reputation(client, "ip", {"ip": "198.51.100.88"})
    assert result.indicator.dbot_score.score == 1
    # Below Suspicious only the collections are tags; their malware and actor names are not.
    assert (result.indicator.tags, result.indicator.malware_family) == (["apt/threat"], None)
    assert result.relationships is None
    assert "low risk (risk score 25)" in result.readable_output
    assert result.raw_response["collections"] == ["apt/threat"]
    # a risk score from 40 attaches the names of every matched record
    client = _reputation_client(mocker, single_session_fixture, records, {"203.0.113.9": 70})
    [result] = reputation(client, "ip", {"ip": "203.0.113.9"})
    assert result.indicator.dbot_score.score == 2
    assert result.indicator.malware_family == ["Sample Backdoor", "Sample Stealer"]
    assert {r.to_entry()["entityB"] for r in result.relationships} == {
        "Sample Backdoor",
        "Sample Stealer",
        "Sample Group",
        "Sample Primary Group",
    }


@pytest.mark.parametrize("risk", [None, 0, 25, 39])
def test_an_ip_that_ioc_primary_makes_suspicious_takes_the_names_of_the_ioc_primary_records_only(
    mocker, single_session_fixture, risk
):
    records = {
        "ioc/primary": [
            {
                "type": "network",
                "ip": [{"ip": "198.51.100.88", "riskScore": 90}],
                "malwareList": [{"name": "Sample Stealer"}],
                "threatActorList": [{"name": "Sample Primary Group"}],
            }
        ],
        "apt/threat": [{"threatActor": {"name": "Sample Group"}, "malwareList": [{"name": "Sample Backdoor"}]}],
    }
    client = _reputation_client(mocker, single_session_fixture, records, {"198.51.100.88": risk})
    [result] = reputation(client, "ip", {"ip": "198.51.100.88"}, create_relationships=True)
    assert result.indicator.dbot_score.score == 2
    assert result.indicator.malware_family == ["Sample Stealer"]
    assert result.indicator.tags == ["ioc/primary", "Sample Primary Group"]
    assert result.raw_response["threatActors"] == ["Sample Primary Group"]
    assert {r.to_entry()["entityB"] for r in result.relationships} == {"Sample Stealer", "Sample Primary Group"}
    assert result.raw_response["collections"] == ["apt/threat", "ioc/primary"]


def test_file_reputation_stores_every_hash_under_its_own_kind(mocker, single_session_fixture):
    sha256 = "abababababababababababababababababababababababababababababababab"
    sha1 = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
    md5 = "efefefefefefefefefefefefefefefef"
    record = {
        "type": "file",
        "hash": {"md5": md5, "sha1": sha1, "sha256": sha256},
        "riskScore": 100,
        "malwareList": [{"name": "Sample Loader"}],
    }
    records = {"ioc/primary": [{"count": 1, "items": [record]}]}
    client = _reputation_client(mocker, single_session_fixture, records)
    [result] = reputation(client, "file", {"file": sha256.upper()})
    file = result.indicator
    assert (file.md5, file.sha1, file.sha256) == (md5, sha1, sha256.upper())
    assert file.dbot_score.indicator == sha256.upper()
    assert file.dbot_score.score == 3
    [not_a_hash] = reputation(client, "file", {"file": "not-a-hash"})
    assert not_a_hash.indicator is None
    assert "not an MD5, SHA-1, SHA-256 or SHA-512 hash" in not_a_hash.readable_output


def _primary_file(sha256: str, md5: str, risk: int | None, first: str, last: str) -> dict:
    """An ioc/primary file record of the two hashes."""
    return {
        "type": "file",
        "hash": {"md5": md5, "sha1": None, "sha256": sha256, "other": []},
        "riskScore": risk,
        "evaluation": {"TLP": "TLP:AMBER"},
        "dateFirstSeen": first,
        "dateLastSeen": last,
    }


@pytest.mark.parametrize(("risk", "verdict"), [(100, 3), (80, 3), (79, 2), (1, 2), (0, 2), (None, 2)])
def test_file_reputation_takes_the_ioc_primary_risk_score(mocker, single_session_fixture, risk, verdict):
    """A hash only ioc/primary lists is Bad from a risk score of 80, else Suspicious, with both hashes and the record's TLP."""
    sha256, md5 = "ab" * 32, "ef" * 16
    records = {"ioc/primary": [_primary_file(sha256, md5, risk, "2026-04-09T00:00:00Z", "2026-04-10T00:00:00Z")]}
    client = _reputation_client(mocker, single_session_fixture, records)
    [result] = reputation(client, "file", {"file": sha256})
    assert result.indicator.dbot_score.score == verdict
    assert (result.indicator.md5, result.indicator.sha256) == (md5, sha256)
    assert result.raw_response["riskScore"] == risk
    assert result.indicator.traffic_light_protocol == "AMBER"


@pytest.mark.parametrize(
    ("records", "verdict"),
    [
        ({"ioc/common": [{"hash": ["EF" * 16, "ab" * 32]}]}, 3),
        (
            {
                "ioc/common": [{"hash": ["ef" * 16, "ab" * 32]}],
                "ioc/primary": [_primary_file("ab" * 32, "ef" * 16, 10, "2026-04-09T00:00:00Z", "2026-04-10T00:00:00Z")],
            },
            3,
        ),
        ({"ioc/common": [{"hash": ["cd" * 16, "cd" * 32]}]}, 0),
        ({}, 0),
    ],
)
def test_a_hash_ioc_common_lists_is_bad_whatever_ioc_primary_says(mocker, single_session_fixture, records, verdict):
    """ioc/common lists hashes Group-IB holds bad: a hash it lists is Bad, AMBER, and carries the record's other hashes."""
    client = _reputation_client(mocker, single_session_fixture, records)
    [result] = reputation(client, "file", {"file": "EF" * 16})
    assert result.indicator.dbot_score.score == verdict
    assert {c.kwargs["path"] for c in ReputationCommand._read.call_args_list} == {"ioc/common", "ioc/primary"}
    if verdict:
        assert result.indicator.sha256 == "ab" * 32
        assert result.indicator.traffic_light_protocol == "AMBER"
        assert "ioc/common" in result.indicator.tags
    else:
        assert result.indicator.tags is None


def test_file_reputation_takes_the_highest_ioc_primary_risk_score(mocker, single_session_fixture):
    sha256, md5 = "ab" * 32, "ef" * 16
    records = {
        "ioc/primary": [
            _primary_file(sha256, md5, 0, "2026-04-09T00:00:00Z", "2026-04-10T00:00:00Z"),
            _primary_file(sha256, md5, 90, "2026-04-09T00:00:00Z", "2026-04-10T00:00:00Z"),
        ]
    }
    client = _reputation_client(mocker, single_session_fixture, records)
    [result] = reputation(client, "file", {"file": sha256})
    assert (result.indicator.dbot_score.score, result.raw_response["riskScore"]) == (3, 90)


def test_file_reputation_skips_an_ioc_primary_record_of_another_hash(mocker, single_session_fixture):
    """A search hit of ioc/primary that does not list the hash asked about sets no verdict."""
    records = {"ioc/primary": [_primary_file("cd" * 32, "ef" * 16, 100, "2026-04-09T00:00:00Z", "2026-04-10T00:00:00Z")]}
    client = _reputation_client(mocker, single_session_fixture, records)
    [result] = reputation(client, "file", {"file": "ab" * 32})
    assert result.indicator.dbot_score.score == 0
    assert result.indicator.md5 is None


def test_reputation_sets_the_earliest_first_and_latest_last_sighting(mocker, single_session_fixture):
    sha256 = "ab" * 32
    records = {
        "ioc/primary": [
            _primary_file(sha256, "ef" * 16, 90, "2026-04-09T00:00:00Z", "2026-05-02T00:00:00Z"),
            _primary_file(sha256, "ef" * 16, 90, "2026-03-01T00:00:00Z", "2026-04-20T00:00:00Z"),
            {**_primary_file(sha256, "ef" * 16, 90, "", "2026-05-03T00:00:00Z"), "dateFirstSeen": None},
        ],
    }
    client = _reputation_client(mocker, single_session_fixture, records)
    [result] = reputation(client, "file", {"file": sha256})
    indicator = result.indicator
    assert (indicator.first_seen_by_source, indicator.last_seen_by_source) == ("2026-03-01T00:00:00Z", "2026-05-03T00:00:00Z")
    # without a dated record neither is set
    undated = {**_primary_file(sha256, "ef" * 16, 90, "", ""), "dateFirstSeen": None, "dateLastSeen": None}
    client = _reputation_client(mocker, single_session_fixture, {"ioc/primary": [undated]})
    [result] = reputation(client, "file", {"file": sha256})
    assert (result.indicator.first_seen_by_source, result.indicator.last_seen_by_source) == (None, None)


def test_reputation_writes_the_sightings_in_utc_whatever_the_offset_of_the_records(mocker, single_session_fixture):
    sha256 = "ab" * 32
    records = {
        "ioc/primary": [
            _primary_file(sha256, "ef" * 16, 90, "2026-03-01T02:00:00+03:00", "2026-04-01T00:00:00+00:00"),
            _primary_file(sha256, "ef" * 16, 90, "2026-03-01T00:00:00", "2026-04-01T01:00:00+03:00"),
        ]
    }
    client = _reputation_client(mocker, single_session_fixture, records)
    [result] = reputation(client, "file", {"file": sha256})
    # 02:00 at +03:00 is earlier than 00:00 UTC; 01:00 at +03:00 is earlier than 00:00 UTC
    assert (result.indicator.first_seen_by_source, result.indicator.last_seen_by_source) == (
        "2026-02-28T23:00:00Z",
        "2026-04-01T00:00:00Z",
    )


def test_collection_tags_below_suspicious_follow_the_setting(mocker, single_session_fixture):
    records = {"apt/threat": [{"indicators": [{"params": {"ipv4": "203.0.113.9"}}]}]}
    client = _reputation_client(mocker, single_session_fixture, records, {"203.0.113.9": 10})
    [on] = reputation(client, "ip", {"ip": "203.0.113.9"})
    [off] = reputation(client, "ip", {"ip": "203.0.113.9"}, collection_tags_always=False)
    assert on.indicator.dbot_score.score == off.indicator.dbot_score.score == 1
    assert (on.indicator.tags, off.indicator.tags) == (on.raw_response["collections"], None)
    assert on.indicator.tags
    assert Settings.from_params({}).collection_tags_always is True
    assert Settings.from_params({"collection_tags_always": False}).collection_tags_always is False


SAMPLE_REPORT = {
    "title": "Sample Campaign Report",
    "datePublished": "2026-03-02T00:00:00Z",
    "malwareList": [{"name": "SampleRat"}],
}
SAMPLE_POST = {
    "title": "1234567890",
    "link": "https://blog.example/posts/sample",
    "source": "blog.example",
    "createdAt": "2026-04-01T00:00:00Z",
}


def test_reputation_lists_the_titled_reports_and_the_posts_with_a_title_or_link_newest_first(mocker, single_session_fixture):
    untitled = [{"title": " ", "createdAt": "2026-05-01T00:00:00Z"}, {"title": "", "source": "blog.example"}]
    linked = {"link": "https://blog.example/posts/linked", "source": "blog.example", "createdAt": "2026-03-15T00:00:00Z"}
    records = {"apt/threat": [SAMPLE_REPORT, untitled[0]], "hi/open_threats": [SAMPLE_POST, untitled[1], linked]}
    client = _reputation_client(mocker, single_session_fixture, records, {"203.0.113.9": 70})
    [result] = reputation(client, "ip", {"ip": "203.0.113.9"})
    [context] = [v for k, v in result.indicator.to_context().items() if k.startswith("IP(")]
    assert context["Publications"] == [
        {
            "source": "blog.example",
            "title": "1234567890",
            "link": "https://blog.example/posts/sample",
            "timestamp": "2026-04-01T00:00:00Z",
        },
        {
            "source": "blog.example",
            "title": "https://blog.example/posts/linked",
            "link": "https://blog.example/posts/linked",
            "timestamp": "2026-03-15T00:00:00Z",
        },
        {
            "source": "Group-IB Threat Intelligence",
            "title": "Sample Campaign Report",
            "link": None,
            "timestamp": "2026-03-02T00:00:00Z",
        },
    ]


@pytest.mark.parametrize(
    ("scores", "primary"),
    [
        ({"203.0.113.9": 20}, []),
        # ioc/primary decides without a risk score; only its records give context
        ({}, [{"type": "network", "ip": [{"ip": "203.0.113.9", "riskScore": 90}], "dateLastSeen": "2026-04-01T00:00:00Z"}]),
    ],
)
def test_reputation_lists_no_publications_without_the_risk_score_deciding_suspicious(
    mocker, single_session_fixture, scores, primary
):
    records = {"apt/threat": [SAMPLE_REPORT], "hi/open_threats": [SAMPLE_POST], "ioc/primary": primary}
    client = _reputation_client(mocker, single_session_fixture, records, scores)
    [result] = reputation(client, "ip", {"ip": "203.0.113.9"})
    assert result.indicator.publications is None


def test_domain_reputation_reads_the_post_fields_and_the_ioc_primary_sightings(mocker, single_session_fixture):
    """A domain lookup keeps what the publications and sighting dates need from its parsed and raw records."""
    client = single_session_fixture
    pages = {
        "hi/open_threats": {**SAMPLE_POST, "data": {"domain": ["sample.example"]}},
        "ioc/primary": {
            "type": "network",
            "domain": [{"domain": "sample.example"}],
            "dateFirstSeen": "2026-01-05T00:00:00Z",
            "dateLastSeen": "2026-02-05T00:00:00Z",
        },
    }

    def search(path: str, query: str, limit: int) -> Any:
        record = pages.get(path)
        return iter([Parser(chunk={"count": 1, "items": [record]}, keys=[], iocs_keys=[])]) if record else iter([])

    mocker.patch.object(client, "search_collection", side_effect=search)
    mocker.patch.object(client.poller, "get_domain_scoring", return_value={"items": {"sample.example": {"riskScore": 70}}})
    mocker.patch.object(client.poller, "graph_domain_search", return_value=None)
    [result] = reputation(client, "domain", {"domain": "sample.example"})
    assert [(p.source, p.link) for p in result.indicator.publications] == [("blog.example", "https://blog.example/posts/sample")]
    assert result.indicator.first_seen_by_source == "2026-01-05T00:00:00Z"


def test_reputation_reports_the_records_and_sightings_of_each_collection(mocker, single_session_fixture):
    records = {
        "ioc/primary": [
            {
                "type": "network",
                "ip": [{"ip": "203.0.113.9"}],
                "dateFirstSeen": "2025-01-02T00:00:00Z",
                "dateLastSeen": "2025-06-01T00:00:00Z",
            },
            {
                "type": "network",
                "ip": [{"ip": "203.0.113.9"}],
                "dateFirstSeen": "2024-03-04T00:00:00Z",
                "dateLastSeen": "2025-02-01T00:00:00Z",
            },
        ],
        "suspicious_ip/tor_node": [
            {"id": "203.0.113.9", "dateFirstSeen": "2023-01-01T00:00:00Z", "dateLastSeen": "2023-02-01T00:00:00Z"}
        ],
        "apt/threat": [{"title": "Sample Campaign Report"}],
    }
    client = _reputation_client(mocker, single_session_fixture, records, {"203.0.113.9": 20})
    [result] = reputation(client, "ip", {"ip": "203.0.113.9"})
    assert sorted(result.outputs["sources"], key=lambda row: row["collection"]) == [
        {"collection": "apt/threat", "count": 1, "firstSeen": None, "lastSeen": None},
        {"collection": "ioc/primary", "count": 2, "firstSeen": "2024-03-04T00:00:00Z", "lastSeen": "2025-06-01T00:00:00Z"},
        {
            "collection": "suspicious_ip/tor_node",
            "count": 1,
            "firstSeen": "2023-01-01T00:00:00Z",
            "lastSeen": "2023-02-01T00:00:00Z",
        },
    ]
    assert "| suspicious_ip/tor_node | 1 | 2023-01-01T00:00:00Z | 2023-02-01T00:00:00Z |" in result.readable_output
    # a value no collection lists has no rows and no table
    client = _reputation_client(mocker, single_session_fixture, {}, {"203.0.113.9": 20})
    [result] = reputation(client, "ip", {"ip": "203.0.113.9"})
    assert (result.outputs["sources"], "Group-IB records" in result.readable_output) == ([], False)


def test_a_bad_value_names_its_risk_score_and_its_collections(mocker, single_session_fixture):
    records = {"apt/threat": [SAMPLE_REPORT]}
    client = _reputation_client(mocker, single_session_fixture, records, {"203.0.113.9": 90, "203.0.113.10": 90})
    named, alone = reputation(client, "ip", {"ip": "203.0.113.9"}) + reputation(
        _reputation_client(mocker, single_session_fixture, {}, {"203.0.113.10": 90}), "ip", {"ip": "203.0.113.10"}
    )
    assert named.indicator.dbot_score.malicious_description == "Group-IB risk score 90; listed in Group-IB apt/threat"
    assert alone.indicator.dbot_score.malicious_description == "Group-IB risk score 90"


def test_reputation_reliability_is_computed_only_with_the_override_ignored_and_a_match(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"198.51.100.1": 90})
    assert DEFAULT_SETTINGS.source_reliability == "C - Fairly reliable"
    # "Ignore Source Reliability override": nothing matched, so nothing was computed
    [result] = reputation(client, "ip", {"ip": "198.51.100.1"}, source_reliability="B - Usually reliable")
    assert result.indicator.dbot_score.reliability == "B - Usually reliable"
    # a computed reliability wins when the override is ignored
    records = {"ioc/primary": [{"type": "network", "ip": [{"ip": "198.51.100.2", "riskScore": 90}]}]}
    client = _reputation_client(mocker, single_session_fixture, records, {"198.51.100.2": 90})
    [result] = reputation(client, "ip", {"ip": "198.51.100.2"})
    assert result.indicator.dbot_score.reliability == "A - Completely reliable"
    # the instance override applies to every result
    [result] = reputation(client, "ip", {"ip": "198.51.100.2"}, "D - Not usually reliable")
    assert result.indicator.dbot_score.reliability == "D - Not usually reliable"


def test_threat_report_files_keep_their_own_name_and_hashes():
    # indicators.params.* yields one entry per element of the report's indicators array: a network
    # element has no hashes, a file element no IPs.
    indicators = {
        "ipv4": [["203.0.113.1", "203.0.113.2"], None, None],
        "domain": [None, None, None],
        "url": ["", None, None],
        "hashes_md5": [None, "a" * 32, "b" * 32],
        "name": [None, "loader.exe", "payload.dll"],
        "hashes_sha1": [None, "c" * 40, "d" * 40],
        "hashes_sha256": [None, "e" * 64, "f" * 64],
        "size": [None, 1024, 2048],
        "malware_names": ["Loader"],
        "threat_actor_names": ["Actor"],
    }
    results = _lookup(indicators, "apt/threat")
    files = [r.indicator for r in results if type(r.indicator).__name__ == "File"]
    assert [(f.md5, f.name, f.sha1, f.sha256, f.size) for f in files] == [
        ("a" * 32, "loader.exe", "c" * 40, "e" * 64, 1024),
        ("b" * 32, "payload.dll", "d" * 40, "f" * 64, 2048),
    ]
    ips = [r.indicator.ip for r in results if type(r.indicator).__name__ == "IP"]
    assert ips == ["203.0.113.1", "203.0.113.2"]


def test_threat_report_files_are_keyed_by_sha256_else_sha1_else_md5():
    # A report's file entry carries up to ten hash kinds, most of them empty: each file is keyed by
    # its SHA-256, else its SHA-1, else its MD5, else its SHA-512, and each of these four lands in its own attribute.
    indicators = {
        "ipv4": [["203.0.113.1"], None, None, None],
        "hashes_md5": [None, "a" * 32, "", "b" * 32],
        "hashes_sha1": [None, "c" * 40, "d" * 40, ""],
        "hashes_sha256": [None, "e" * 64, "", ""],
        "name": [None, "full.exe", "sha1-only.dll", "md5-only.bin"],
    }
    for collection in ("apt/threat", "hi/threat"):
        files = [r.indicator for r in _lookup(indicators, collection) if type(r.indicator).__name__ == "File"]
        assert [(f.dbot_score.indicator, f.md5, f.sha1, f.sha256, f.name) for f in files] == [
            ("e" * 64, "a" * 32, "c" * 40, "e" * 64, "full.exe"),
            ("d" * 40, None, "d" * 40, None, "sha1-only.dll"),
            ("b" * 32, "b" * 32, None, None, "md5-only.bin"),
        ]
        assert _related(collection, indicators) == "\n".join(["203.0.113.1", "e" * 64, "d" * 40, "b" * 32])


def test_lookup_tables_cut_long_cells_and_keep_the_context_whole(mocker, single_session_fixture):
    client = single_session_fixture
    description = "x" * 5000
    portion = MagicMock()
    portion.parse_portion.return_value = [
        {
            "id": "CVE-2099-1",
            "description": description,
            "cpeTable": {"product": [f"product-{i}" for i in range(250)], "vendor": [f"vendor-{i}" for i in range(250)]},
            "indicators": {"id": "CVE-2099-1", "description": description, "software_mixed": {"names": ["a"] * 3000}},
            "evaluation": {"severity": "red"},
        }
    ]
    mocker.patch.object(client.poller, "search_feed_by_id", return_value=portion)
    view = present_record(client, "osi/vulnerability", "CVE-2099-1")
    feed, readable_output = view.record, view.readable_output
    assert feed["description"] == description
    assert len(feed["cpeTable"]["product"]) == 250
    assert "the first 1000 of 5000 characters" in readable_output
    assert "software_mixed" not in readable_output
    assert len(readable_output) < 3000
    [cpe] = view.tables
    assert "first 200 of 250 rows" in cpe.readable_output
    assert "product-199" in cpe.readable_output
    assert "product-200" not in cpe.readable_output


def test_an_ungraded_cnc_incident_is_high_severity_a_graded_one_keeps_its_grade_and_an_ungraded_tor_node_is_unknown():
    record = {
        "id": "c2",
        "name": "http://c2.test/gate",
        "cnc": "http://c2.test/gate",
        "dateFirstSeen": "2026-01-01T00:00:00+00:00",
    }
    incident = IncidentBuilder().build("malware/cnc", dict(record))
    assert json.loads(incident["rawJSON"])["systemSeverity"] == 3
    graded = {**record, "evaluation": {"severity": "orange"}}
    incident = IncidentBuilder().build("malware/cnc", graded)
    assert json.loads(incident["rawJSON"])["systemSeverity"] == 2
    tor = {"id": "t", "name": "n", "dateFirstSeen": "2024-01-01T00:00:00+00:00"}
    incident = IncidentBuilder().build("suspicious_ip/tor_node", tor)
    assert json.loads(incident["rawJSON"])["systemSeverity"] == 0


@pytest.mark.parametrize(
    "defanged, refanged",
    [
        ("hxxps://staging.example/lib/files/db/emp", "https://staging.example/lib/files/db/emp"),
        ("hXXp://evil[.]example[:]8080/x", "http://evil.example:8080/x"),
        ("evil(.)example", "evil.example"),
        ("203.0.113[.]7", "203.0.113.7"),
        ("https://fine.example/hxxp", "https://fine.example/hxxp"),
        (None, None),
    ],
)
def test_refang_restores_defanged_observables(defanged, refanged):
    assert IndicatorBuilder.refang(defanged) == refanged


def test_threat_report_urls_are_refanged_for_lookups_and_incident_extraction():
    results = _lookup(
        {"url": ["hxxps://staging.example/lib/files/db/emp"], "ipv4": [], "domain": ["evil[.]example"]}, "apt/threat"
    )
    assert sorted(str(getattr(r.indicator, "url", None) or r.indicator.domain) for r in results) == [
        "evil.example",
        "https://staging.example/lib/files/db/emp",
    ]
    record = {
        "id": "t1",
        "name": "Actor",
        "createdAt": "2024-01-01T00:00:00+00:00",
        "indicators": {"url": ["hxxps://staging.example/lib/files/db/emp"], "hashes_md5": ["a" * 32]},
    }
    incident = IncidentBuilder().build("apt/threat", record)
    assert json.loads(incident["rawJSON"])["relatedIndicators"] == "https://staging.example/lib/files/db/emp\n" + "a" * 32


def _related(collection: str, indicators: dict) -> str | None:
    record = {"id": "r", "name": "n", "dateFirstSeen": "2024-01-01T00:00:00+00:00", "indicators": indicators}
    return IncidentBuilder._related_indicators(collection, record)


def test_incidents_extract_only_the_observables_the_lookups_build():
    # the victim's domain and IP of a defacement stay on the incident
    deface = {"url": "http://victim.example/x", "target_domain": "victim.example", "target_ip_ip": "198.51.100.9"}
    assert _related("attacks/deface", deface) == "http://victim.example/x"
    # the hosting provider ("Example.com, Inc." reads as a domain), geo and malware names are attributes
    cnc = {
        "url": ["http://c2.example/gate"],
        "domain": ["c2.example"],
        "ipv4_ip": ["203.0.113.8"],
        "ipv4_provider": ["Example.com, Inc."],
        "country_name": ["Germany"],
        "malware_names": ["BankerOne"],
    }
    assert _related("malware/cnc", cnc) == "http://c2.example/gate\nc2.example\n203.0.113.8"
    # the card shop of a card record is no indicator
    assert _related("compromised/bank_card_group", {"cnc_url": ["https://shop.example/"]}) is None
    # a CVE incident extracts the CVE, not the links of its description or its software list
    vulnerability = {
        "id": "CVE-2099-1",
        "description": "see https://vendor.example/advisory",
        "software_mixed": {"names": ["a.zip"]},
    }
    assert _related("osi/vulnerability", vulnerability) == "CVE-2099-1"
    # a report file is extracted once, by the hash the lookup keys it by; its name is not a domain
    report = {
        "hashes_md5": [None, "a" * 32],
        "hashes_sha1": [None, "b" * 40],
        "name": [None, "invoice.zip"],
        "ipv4": [["203.0.113.1"], None],
    }
    assert _related("hi/threat", report) == "203.0.113.1\n" + "b" * 40
    # a C&C IP given in the domain field is extracted once
    assert (
        _related("malware/cnc", {"domain": "203.0.113.7", "ipv4_ip": "203.0.113.7", "ipv4_provider": "Example"}) == "203.0.113.7"
    )
    assert _related("attacks/phishing_group", {"url": ["http://phish.example/login"], "brand": "Travel.example"}) == (
        "http://phish.example/login"
    )
    assert _related("osi/git_repository", {"hash": ["a" * 40]}) is None
    assert _related("osi/public_leak", {}) is None


def test_the_mapper_extracts_from_the_observable_list():
    mapper = json.load(open(f"{realpath}/../../Classifiers/classifier-Group-IB_Threat_Intelligence_mapper.json"))
    sources = {
        incident_type: rules["internalMapping"]["GIB Related Indicators Data"]
        for incident_type, rules in mapper["mapping"].items()
        if "GIB Related Indicators Data" in rules["internalMapping"]
    }
    legacy = {"GIB Compromised Account", "GIB Compromised Card"}
    assert {t: v for t, v in sources.items() if t not in legacy} == {
        t: {"simple": "relatedIndicators"} for t in sources if t not in legacy
    }
    assert "GIB Attacks Phishing Group" in sources
    assert "GIB OSI Vulnerability" in sources


EMAIL_TYPES = ("GIB Cybercriminal Threat", "GIB Nation-State Cybercriminals Threat", "GIB Attacks Phishing Kit")


@pytest.mark.parametrize("incident_type", EMAIL_TYPES)
def test_the_email_addresses_of_a_report_or_kit_are_extracted_as_email_only(incident_type):
    """Threat report and phishing kit incidents map their e-mail addresses to GIB Related Emails, which extracts Email only."""
    pack = Path(realpath).parent.parent
    mapper = json.load(open(pack / "Classifiers/classifier-Group-IB_Threat_Intelligence_mapper.json"))
    assert mapper["mapping"][incident_type]["internalMapping"]["GIB Related Emails"] == {"simple": "relatedEmails"}
    field = json.load(open(pack / "IncidentFields/incidentfield-GIB_Related_Emails.json"))
    assert (field["id"], field["cliName"]) == ("incident_gibrelatedemails", "gibrelatedemails")
    assert incident_type in field["associatedTypes"]
    file_name = incident_type.replace(" ", "_")
    extraction = json.load(open(pack / f"IncidentTypes/incidenttype-{file_name}.json"))["extractSettings"]
    assert extraction["fieldCliNameToExtractSettings"]["gibrelatedemails"] == {
        "extractAsIsIndicatorTypeId": "",
        "extractIndicatorTypesIDs": ["Email"],
        "isExtractingAllIndicatorTypes": False,
    }
    layout = (pack / f"Layouts/layoutscontainer-{file_name}_Layout.json").read_text()
    assert '"fieldId": "gibrelatedemails"' in layout


def test_threat_actor_lookup_reads_every_id_and_falls_back_to_the_other_collection(mocker, single_session_fixture):
    found = {("hi/threat_actor", "hi-actor"), ("apt/threat_actor", "apt-actor")}
    refused = {("hi/threat_actor", "locked-actor"), ("apt/threat_actor", "locked-actor")}
    calls = []

    def results(command, collection, record_id):
        calls.append((collection, record_id))
        if (collection, record_id) in refused:
            raise DemistoException(f"The lookup of id {record_id!r} in {collection} failed: HTTP 403")
        if (collection, record_id) not in found:
            return None
        return [CommandResults(readable_output=f"{collection} {record_id}")]

    mocker.patch.object(GroupIBTIA.LookupCommand, "_results", results)
    # three actor ids: a cybercriminal one, a nation-state one and a defacer neither actor collection publishes
    results = threat_lookup(single_session_fixture, "threat_actor", {"id": ["hi-actor", "apt-actor", "defacer"]})
    assert [r.readable_output for r in results[:2]] == ["hi/threat_actor hi-actor", "apt/threat_actor apt-actor"]
    assert "publishes no hi/threat_actor or apt/threat_actor record with id defacer" in results[2].readable_output
    assert calls == [
        ("hi/threat_actor", "hi-actor"),
        ("hi/threat_actor", "apt-actor"),
        ("apt/threat_actor", "apt-actor"),
        ("hi/threat_actor", "defacer"),
        ("apt/threat_actor", "defacer"),
    ]
    # isAPT picks the collection read first; a comma-separated string works as well
    calls.clear()
    threat_lookup(single_session_fixture, "threat_actor", {"id": "apt-actor, hi-actor", "isAPT": "true"})
    assert calls == [("apt/threat_actor", "apt-actor"), ("apt/threat_actor", "hi-actor"), ("hi/threat_actor", "hi-actor")]
    # a refusal is reported next to the records that were read, and is an error when nothing was read
    results = threat_lookup(single_session_fixture, "threat_actor", {"id": "hi-actor,locked-actor"})
    assert "HTTP 403" in results[-1].readable_output
    with pytest.raises(DemistoException, match="HTTP 403"):
        threat_lookup(single_session_fixture, "threat_actor", {"id": "locked-actor"})
    with pytest.raises(DemistoException, match="'id' is required"):
        threat_lookup(single_session_fixture, "threat", {"id": ""})


def test_a_floor_collection_keeps_a_low_risk_ip_suspicious_with_its_tag_only(mocker, single_session_fixture):
    records = {
        "suspicious_ip/tor_node": [{"id": "203.0.113.20", "dateLastSeen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}],
        "ioc/primary": [
            {"type": "network", "ip": [{"ip": "203.0.113.21", "riskScore": 90}], "malwareList": [{"name": "Sample Stealer"}]}
        ],
    }
    client = _reputation_client(mocker, single_session_fixture, records, {"203.0.113.20": 35})
    [result] = reputation(client, "ip", {"ip": "203.0.113.20"})
    assert result.indicator.dbot_score.score == 2
    assert result.indicator.tags == ["suspicious_ip/tor_node"]
    assert (result.indicator.malware_family, result.relationships) == (None, None)
    assert "listed in suspicious_ip/tor_node" in result.readable_output
    assert "No Group-IB collection" not in result.readable_output
    # The ioc/primary record lists another IP, so only the floor collection names it.
    assert result.raw_response["collections"] == ["suspicious_ip/tor_node"]
    # With only "none" selected, the risk score alone decides and the collection is not read.
    ReputationCommand._listing.reset_mock()
    [result] = reputation(client, "ip", {"ip": "203.0.113.20"}, floor_collections=frozenset())
    assert result.indicator.dbot_score.score == 1
    ReputationCommand._listing.assert_not_called()


@pytest.mark.parametrize(("risk", "verdict"), [(None, 0), (0, 1)])
def test_mentions_attach_nothing_below_40_and_an_ioc_primary_listing_attaches_only_its_own_names(
    mocker, single_session_fixture, risk, verdict
):
    mentions = {
        "apt/threat": [{"threatActor": {"name": "Sample Report Actor"}, "malwareList": [{"name": "Sample Report Malware"}]}],
        "hi/open_threats": [{"detected": "2026-04-01", "malwareList": [{"name": "Sample Post Malware"}]}],
        "attacks/deface": [{"date": "2026-04-01", "threat_actor_name": "Sample Defacer"}],
    }
    client = _reputation_client(mocker, single_session_fixture, mentions, {"example.com": risk})
    [result] = reputation(client, "domain", {"domain": "example.com"})
    assert result.indicator.dbot_score.score == verdict
    assert result.indicator.tags == result.raw_response["collections"]
    assert (result.indicator.malware_family, result.relationships) == (None, None)
    # an ioc/primary listing makes it Suspicious, and only its own names are attached
    primary = {
        "type": "network",
        "domain": [{"domain": "example.com", "riskScore": 80}],
        "malwareList": [{"name": "Sample Stealer"}],
        "threatActorList": [{"name": "Sample Actor"}],
    }
    client = _reputation_client(mocker, single_session_fixture, {**mentions, "ioc/primary": [primary]}, {"example.com": risk})
    [result] = reputation(client, "domain", {"domain": "example.com"})
    assert result.indicator.dbot_score.score == 2
    assert result.indicator.malware_family == ["Sample Stealer"]
    assert result.indicator.tags == ["ioc/primary", "Sample Actor"]
    assert result.raw_response["threatActors"] == ["Sample Actor"]


def test_an_open_threat_post_lends_its_actors_and_malware_when_the_risk_score_decides(mocker, single_session_fixture):
    post = {
        "detected": datetime.utcnow().strftime("%Y-%m-%d"),
        "threatActors": [{"id": "a1", "name": "Sample Group"}],
        "data": {"malware": [{"id": "m1", "name": "Sample Stealer"}]},
        "evaluation": {"tlp": "green"},
    }
    client = _reputation_client(mocker, single_session_fixture, {"hi/open_threats": [post]}, {"203.0.113.21": 90})
    [result] = reputation(client, "ip", {"ip": "203.0.113.21"})
    assert result.indicator.dbot_score.score == 3
    assert result.indicator.tags == ["hi/open_threats", "Sample Group"]
    assert result.indicator.malware_family == ["Sample Stealer"]
    assert result.indicator.traffic_light_protocol == "GREEN"


def test_a_slow_read_that_decides_nothing_leaves_the_verdict_and_is_named(mocker, single_session_fixture):
    records = {"apt/threat": [{"id": "r"}]}
    client = _reputation_client(mocker, single_session_fixture, records, {"203.0.113.30": 90})
    mocker.patch.object(
        ReputationCommand,
        "_read",
        side_effect=lambda path, value, keys=None: time.sleep(2) or [] if path == "apt/threat" else records.get(path, []),
    )
    started = time.monotonic()
    [result] = reputation(client, "ip", {"ip": "203.0.113.30"}, search_timeout=0.2)
    assert time.monotonic() - started < 1.5
    assert result.indicator.dbot_score.score == 3
    assert result.outputs["partial"] is False
    assert "reading apt/threat (no answer within the lookup timeout of 0.2 s)" in result.readable_output


@pytest.mark.parametrize("slow", [True, False])
def test_a_call_the_deadline_leaves_running_keeps_the_base_client_to_itself(mocker, single_session_fixture, slow):
    client = _reputation_client(mocker, single_session_fixture, {}, {"203.0.113.30": 90})
    fork = mocker.patch.object(Client, "fork", autospec=True, side_effect=lambda self: self)
    # The risk score is the last call of the lookup, so a late one leaves nothing else to run after the test.
    scoring = {"items": {"203.0.113.30": {"riskScore": 90}}}
    client.poller.get_ip_scoring.side_effect = lambda value: time.sleep(1) or scoring if slow else scoring
    reputation(client, "ip", {"ip": "203.0.113.30"}, search_timeout=0.2, parallel_requests=1, reputation_whois=False)
    # one worker uses the base client; only a call left running replaces it
    assert fork.call_count == (1 if slow else 0)


def test_a_value_no_request_answers_in_time_is_an_error_and_the_others_still_return(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"203.0.113.30": 20, "203.0.113.31": 20})
    slow = "203.0.113.30"
    mocker.patch.object(
        ReputationCommand, "_read", side_effect=lambda path, value, keys=None: time.sleep(1) or [] if value == slow else []
    )
    mocker.patch.object(ReputationCommand, "_risk_score", side_effect=lambda value: time.sleep(1) or 20 if value == slow else 20)
    mocker.patch.object(
        ReputationCommand, "_listing", side_effect=lambda path, value: time.sleep(1) or [] if value == slow else []
    )
    # A worker per call: a late call leaves no queued one to run after the test.
    late, answered = reputation(
        client, "ip", {"ip": f"{slow},203.0.113.31"}, search_timeout=0.2, reputation_whois=False, parallel_requests=12
    )
    assert late.entry_type == EntryType.ERROR
    assert "lookup of '203.0.113.30' failed: no answer within the lookup timeout of 0.2 s" in late.readable_output
    assert answered.indicator.dbot_score.score == 1


def test_a_slow_read_that_decides_the_verdict_sets_none_below_suspicious(mocker, single_session_fixture):
    """ioc/primary could make the IP Suspicious: a Good risk score alone sets nothing while it has not answered."""
    client = _reputation_client(mocker, single_session_fixture, {}, {"203.0.113.30": 20})
    mocker.patch.object(
        ReputationCommand,
        "_read",
        side_effect=lambda path, value, keys=None: time.sleep(2) or [] if path == "ioc/primary" else [],
    )
    [result] = reputation(client, "ip", {"ip": "203.0.113.30"}, search_timeout=0.2)
    assert result.indicator is None
    assert result.relationships is None
    assert result.outputs == {
        "indicator": "203.0.113.30",
        "type": "ip",
        "score": None,
        "riskScore": 20,
        "collections": [],
        "sources": [],
        "partial": True,
        "failedSources": ["reading ioc/primary"],
    }
    assert "incomplete: reading ioc/primary (no answer within the lookup timeout of 0.2 s). No verdict" in result.readable_output
    assert "raise the instance setting 'Lookup timeout (seconds)'" in result.readable_output
    assert "the indicator keeps the one it has" in result.readable_output


def test_a_failed_read_keeps_a_verdict_another_source_already_raised(mocker, single_session_fixture):
    records = {
        "ioc/primary": [{"type": "network", "ip": [{"ip": "203.0.113.30", "riskScore": 90}]}],
        "suspicious_ip/tor_node": [{"id": "203.0.113.30"}],
    }
    client = _reputation_client(mocker, single_session_fixture, records)

    mocker.patch.object(ReputationCommand, "_listing", side_effect=GroupIBTIA.ConnectionException(SERVER_ERROR))
    [result] = reputation(client, "ip", {"ip": "203.0.113.30"}, floor_collections=frozenset({"suspicious_ip/tor_node"}))
    assert result.indicator.dbot_score.score == 2
    assert result.outputs["partial"] is True
    assert result.outputs["failedSources"] == ["reading suspicious_ip/tor_node"]


def test_a_failed_read_of_a_collection_that_decides_nothing_keeps_the_verdict(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {"apt/threat": [{"id": "r"}]}, {"203.0.113.30": 20})
    down = GroupIBTIA.ConnectionException(SERVER_ERROR)

    def read(path: str, value: str, keys: Any = None) -> list:
        if path == "apt/threat":
            raise down
        return []

    mocker.patch.object(ReputationCommand, "_read", side_effect=read)
    [result] = reputation(client, "ip", {"ip": "203.0.113.30"})
    assert result.indicator.dbot_score.score == 1
    assert result.outputs["partial"] is False
    assert "Some Group-IB requests for" in result.readable_output


def test_one_failed_value_does_not_lose_the_others(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"198.51.100.27": 90})
    down = GroupIBTIA.ConnectionException(SERVER_ERROR)

    def failing(value: str, answer: Any) -> Any:
        if value == "203.0.113.54":
            raise down
        return answer

    mocker.patch.object(ReputationCommand, "_read", side_effect=lambda path, value, keys=None: failing(value, []))
    mocker.patch.object(ReputationCommand, "_listing", side_effect=lambda path, value: failing(value, []))
    mocker.patch.object(client.poller, "graph_ip_search", side_effect=lambda value: failing(value, None))
    mocker.patch.object(
        client.poller, "get_ip_scoring", side_effect=lambda value: failing(value, {"items": {value: {"riskScore": 90}}})
    )
    failed, scored = reputation(client, "ip", {"ip": "203.0.113.54,198.51.100.27"})
    assert failed.entry_type == EntryType.ERROR
    assert "The Group-IB ip lookup of '203.0.113.54' failed" in failed.readable_output
    assert scored.indicator.dbot_score.score == 3


def test_a_refused_key_fails_the_whole_command(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {})
    refused = GroupIBTIA.ConnectionException("HTTP 401: Bad Credentials.")
    mocker.patch.object(ReputationCommand, "_read", side_effect=refused)
    with pytest.raises(GroupIBTIA.CredentialsRefused, match="Check the instance credentials"):
        reputation(client, "ip", {"ip": "198.51.100.27,203.0.113.54"})
    mocker.patch.object(client.poller, "get_ip_scoring", side_effect=GroupIBTIA.ConnectionException(ACCOUNT_REFUSAL))
    with pytest.raises(GroupIBTIA.CredentialsRefused):
        score_risk(client, "ip", {"ip": "198.51.100.27,203.0.113.54"})


@pytest.mark.parametrize(
    "value, reason",
    [
        ("10.0.0.1", "private, shared or reserved"),
        ("127.0.0.1", "private, shared or reserved"),
        ("fe80::1", "private, shared or reserved"),
        ("203.0.113.5", "private, shared or reserved"),
        ("not-an-ip", "is not an IP address"),
        ("198.51.100.1/24", "is not an IP address"),
    ],
)
def test_an_internal_or_malformed_address_is_not_looked_up(mocker, single_session_fixture, value, reason):
    client = _reputation_client(mocker, single_session_fixture, {})
    [result] = reputation(client, "ip", {"ip": value}, lookup_internal_addresses=False)
    assert reason in result.readable_output
    assert result.indicator is None
    client.poller.global_search.assert_not_called()
    client.poller.get_ip_scoring.assert_not_called()


def test_an_internal_address_is_looked_up_when_the_setting_is_on(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"10.0.0.1": 90})
    [result] = reputation(client, "ip", {"ip": "10.0.0.1"}, lookup_internal_addresses=True)
    assert result.indicator.dbot_score.score == 3


def test_an_instance_without_the_setting_does_not_look_up_internal_addresses():
    """An instance without a value for the setting does not look up internal addresses; true turns it on."""
    assert Settings.from_params({}).lookup_internal_addresses is False
    assert Settings.from_params({"lookup_internal_addresses": True}).lookup_internal_addresses is True


def test_an_ipv6_address_is_not_sent_to_ip_scoring_and_relates_as_ipv6(mocker, single_session_fixture):
    primary = {"type": "network", "ip": [{"ip": "2001:db8::5", "riskScore": 90}], "malwareList": [{"name": "Sample Loader"}]}
    client = _reputation_client(mocker, single_session_fixture, {"ioc/primary": [primary]})
    [result] = reputation(client, "ip", {"ip": "2001:db8::5"})
    client.poller.get_ip_scoring.assert_not_called()
    assert result.indicator.dbot_score.score == 2
    assert _entries(result) == [("2001:db8::5", "IPv6", "indicator-of", "Sample Loader", "Malware")]


@pytest.mark.parametrize(
    "kind, typed, asked",
    [
        ("domain", "Evil[.]Example.", "evil.example"),
        ("domain", " evil.example ", "evil.example"),
        ("ip", "203.0.113[.]9", "203.0.113.9"),
    ],
)
def test_a_defanged_or_padded_value_is_asked_about_as_its_plain_form(mocker, single_session_fixture, kind, typed, asked):
    client = _reputation_client(mocker, single_session_fixture, {}, {asked: 90})
    [result] = reputation(client, kind, {kind: typed})
    assert {c.kwargs["value"] for c in ReputationCommand._read.call_args_list} == {asked}
    assert result.outputs["indicator"] == asked


def test_a_bad_verdict_says_why_in_its_malicious_description(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"198.51.100.27": 90})
    [result] = reputation(client, "ip", {"ip": "198.51.100.27"})
    assert result.indicator.dbot_score.malicious_description == "Group-IB risk score 90"
    records = {"ioc/primary": [{"type": "network", "ip": [{"ip": "198.51.100.28", "riskScore": 10}]}]}
    client = _reputation_client(mocker, single_session_fixture, records, {"198.51.100.28": 80})
    [result] = reputation(client, "ip", {"ip": "198.51.100.28"})
    assert result.indicator.dbot_score.malicious_description == "Group-IB risk score 80; listed in Group-IB ioc/primary"
    client = _reputation_client(mocker, single_session_fixture, {"ioc/common": [{"hash": ["ef" * 16]}]})
    [result] = reputation(client, "file", {"file": "ef" * 16})
    assert result.indicator.dbot_score.malicious_description == "Listed in Group-IB ioc/common"
    # a Suspicious verdict has no malicious description
    client = _reputation_client(mocker, single_session_fixture, records)
    [result] = reputation(client, "ip", {"ip": "198.51.100.28"})
    assert (result.indicator.dbot_score.score, result.indicator.dbot_score.malicious_description) == (2, None)


def test_a_lookup_writes_one_entry_per_indicator_type():
    feed = {
        "evaluation": {"severity": "red"},
        "indicators": {
            "ipv4": [["203.0.113.1", "203.0.113.2", "203.0.113.3"], None, None],
            "hashes_sha256": [None, "e" * 64, "f" * 64],
            "name": [None, "a.exe", "b.dll"],
            "malware_names": ["Loader"],
        },
    }
    ips, files = IndicatorBuilder(create_relationships=True).results(feed, "apt/threat")
    # xsoar-lint refuses the `indicators` key (E9007) and `indicator` takes one indicator:
    # the entry carries the indicators' context itself
    assert not ips.indicators
    assert not ips.indicator
    ip_context = ips.to_context()["EntryContext"]
    dbot = next(value for key, value in ip_context.items() if key.startswith("DBotScore"))
    assert sorted(score["Indicator"] for score in dbot) == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
    assert len(next(value for key, value in files.to_context()["EntryContext"].items() if key.startswith("File"))) == 2
    assert all(value in ips.readable_output for value in ("203.0.113.1", "203.0.113.2", "203.0.113.3"))
    assert "a.exe" in files.readable_output
    assert "b.dll" in files.readable_output
    assert len(ips.relationships) == 3


def test_template_values_are_not_indicators():
    indicators = {
        "url": [
            "https://files.example/contents/{machineId}/Lic.txt",
            "https://drive.example/d/[generated id]/view",
            "hxxps://ok.example/x",
        ],
        "domain": ["evil[.]example"],
    }
    values = [value for _, value, _ in IndicatorBuilder.observables("apt/threat", indicators)]
    assert values == ["evil.example", "https://ok.example/x"]
    # square brackets alone are real URLs: an IPv6 host, a PHP array parameter
    real = {"url": ["http://[2001:db8::1]/gate", "https://evil.example/p.php?id[]=1"]}
    assert [value for _, value, _ in IndicatorBuilder.observables("apt/threat", real)] == real["url"]


def _lookup_record(
    mocker, client, collection: str, records: list[dict], create_relationships: bool = True
) -> list[CommandResults]:
    """The entries of the lookup command for raw records shaped as the API serves them, served by the collection's route."""
    mocker.patch.object(client.poller, "search_feed_by_id", return_value=Parser({"count": 1, "items": records[:1]}, [], []))
    mocker.patch.object(
        client, "search_collection", return_value=iter([Parser({"count": len(records), "items": records}, [], [])])
    )
    return lookup(client, collection, {"id": records[0]["id"]}, create_relationships=create_relationships)


def _context_objects(results: list[CommandResults], path: str) -> list[dict]:
    """The context objects the entries write under ``path`` (``IP``, ``IPv6``, ``DBotScore``...)."""
    found: list[dict] = []
    for result in results:
        for key, value in (result.outputs or {}).items() if isinstance(result.outputs, dict) else []:
            if str(key).split("(", 1)[0] == path:
                found.extend(value if isinstance(value, list) else [value])
    return found


def _related_values(collection: str, record: dict) -> set[str]:
    return set((_build(collection, record).get("relatedIndicators") or "").splitlines())


def _scanner_v6() -> dict:
    """A suspicious_ip/scanner record of an IPv6 scanner: ipv4 is null and the id is the address."""
    return {
        "id": "2001:db8::5",
        "seqUpdate": 1760000000000000,
        "dateFirstSeen": "2026-10-10T08:00:00Z",
        "dateLastSeen": "2026-10-14T08:00:00Z",
        "ipv4": None,
        "ipv6": {
            "ip": "2001:db8::5",
            "countryCode": "CA",
            "countryName": None,
            "region": None,
            "city": None,
            "asn": None,
            "provider": None,
        },
        "evaluation": {
            "admiraltyCode": "C3",
            "credibility": 50,
            "reliability": 50,
            "severity": "green",
            "tlp": "white",
            "ttl": 15,
        },
        "categories": ["Port Scan"],
        "sources": ["ExampleSource"],
        "bind": None,
        "portalLink": None,
    }


def test_an_ipv6_scanner_is_an_ipv6_indicator_with_its_country(mocker, single_session_fixture):
    record = _scanner_v6()
    incident = _build("suspicious_ip/scanner", record)
    assert incident["relatedIndicators"] == "2001:db8::5"
    assert (incident["countryCode"], incident["countryName"]) == ("CA", "CA")
    results = _lookup_record(mocker, single_session_fixture, "suspicious_ip/scanner", [record])
    [lookup] = [r.outputs for r in results if r.outputs_prefix == "GIBTI.SuspiciousIPScanner"]
    assert (lookup["countryCode"], lookup["countryName"]) == ("CA", "CA")
    named = _scanner_v6()
    named["ipv6"]["countryName"] = "Canada"
    assert _build("suspicious_ip/scanner", named)["countryName"] == "Canada"
    [ipv6] = _context_objects(results, "IPv6")
    assert (ipv6["Address"], ipv6["Geo"]["Country"], ipv6["TrafficLightProtocol"]) == ("2001:db8::5", "CA", "WHITE")
    assert _context_objects(results, "IP") == []
    [score] = _context_objects(results, "DBotScore")
    assert (score["Indicator"], score["Type"], score["Score"]) == ("2001:db8::5", "ip", 2)


def _report(**overrides) -> dict:
    """A threat report whose indicators[] holds a network, an email-message and an account entry."""
    record = {
        "id": "4b" * 20,
        "title": "Example campaign",
        "createdAt": "2026-09-01T00:00:00Z",
        "threatActor": {"id": "a1" * 20, "name": "ExampleCrew", "isAPT": False, "country": None},
        "malwareList": [{"id": "b2" * 20, "name": "ExampleLoader"}],
        "evaluation": {"admiraltyCode": "B2", "credibility": 80, "reliability": 80, "severity": "red", "tlp": "amber"},
        "indicators": [
            {"type": "network", "params": {"domain": "", "ipv4": [], "ipv6": ["2001:db8::20"], "ssl": [], "url": ""}},
            {
                "type": "email-message",
                "params": {"address": "lure@example.com", "message": "", "senderIp": "198.51.100.5", "serverIp": "198.51.100.6"},
            },
            {"type": "account", "params": {"address": "someone@mail.example"}},
        ],
    }
    record.update(overrides)
    return record


@pytest.mark.parametrize("collection", ["hi/threat", "apt/threat"])
def test_report_ipv6_and_email_message_entries_are_indicators(mocker, single_session_fixture, collection):
    """An email-message entry gives its address and senderIp, not its serverIp (side unknown); an account entry's
    address gives none."""
    record = _report()
    assert _related_values(collection, record) == {"2001:db8::20", "198.51.100.5"}
    assert _build(collection, record)["relatedEmails"] == "lure@example.com"
    client = single_session_fixture
    results = _lookup_record(mocker, client, collection, [record])
    assert [obj["Address"] for obj in _context_objects(results, "IPv6")] == ["2001:db8::20"]
    assert [obj["Address"] for obj in _context_objects(results, "IP")] == ["198.51.100.5"]
    assert [obj["Email"]["Address"] for obj in _context_objects(results, "Account")] == ["lure@example.com"]
    assert {score["Indicator"]: score["Score"] for score in _context_objects(results, "DBotScore")} == {
        "2001:db8::20": 3,
        "198.51.100.5": 3,
        "lure@example.com": 3,
    }
    ipv6_entry = next(r for r in results if _context_objects([r], "IPv6"))
    assert _entries(ipv6_entry) == [
        ("2001:db8::20", "IPv6", "indicator-of", "ExampleLoader", "Malware"),
        ("2001:db8::20", "IPv6", "related-to", "ExampleCrew", "Threat Actor"),
    ]


@pytest.mark.parametrize("collection", ["hi/threat", "apt/threat"])
def test_a_report_file_with_only_a_sha512_is_a_file_indicator(collection):
    """A file is keyed by its SHA-256, SHA-1 or MD5, in that order, and by its SHA-512 only when it has no other."""
    sha512, sha256, sha1, md5 = "d" * 128, "e" * 64, "9" * 40, "c" * 32
    files = [
        {"type": "file", "params": {"hashes": {"md5": "", "sha1": "", "sha256": "", "sha512": sha512}, "name": "a.bin"}},
        {"type": "file", "params": {"hashes": {"md5": "", "sha1": "", "sha256": sha256, "sha512": "f" * 128}, "name": "b.bin"}},
        {"type": "file", "params": {"hashes": {"md5": md5, "sha1": "", "sha256": "", "sha512": "a" * 128}, "name": "c.bin"}},
        {"type": "file", "params": {"hashes": {"md5": "", "sha1": sha1, "sha256": "", "sha512": "b" * 128}, "name": "d.bin"}},
    ]
    record = _report(indicators=files)
    assert _related_values(collection, record) == {sha512, sha256, md5, sha1}
    built = _build(collection, record)
    by_value = {item.row["value"]: item.indicator for item in IndicatorBuilder().items(built, collection)}
    assert (by_value[sha512].sha512, by_value[sha512].sha256, by_value[sha512].name) == (sha512, None, "a.bin")
    assert (by_value[sha256].sha256, by_value[sha256].sha512) == (sha256, "f" * 128)
    assert (by_value[md5].md5, by_value[md5].sha512, by_value[md5].name) == (md5, "a" * 128, "c.bin")
    assert (by_value[sha1].sha1, by_value[sha1].sha512, by_value[sha1].name) == (sha1, "b" * 128, "d.bin")


def _cnc_v6() -> dict:
    """A malware/cnc record whose C&C is a bare IPv6 address, with the address in ipv6[]."""
    return {
        "id": "c3" * 20,
        "cnc": "2001:db8::77",
        "domain": None,
        "url": None,
        "ipv4": [],
        "ipv6": [
            {
                "ip": "2001:db8::77",
                "asn": "AS64500",
                "provider": "Example Hosting",
                "city": None,
                "region": None,
                "countryCode": "NL",
                "countryName": "Netherlands",
            }
        ],
        "file": [],
        "malwareList": [{"id": "d4" * 20, "name": "ExampleRAT", "stixGuid": None}],
        "platform": None,
        "threatActor": [],
        "dateDetected": "2026-10-01T00:00:00Z",
        "dateFirstSeen": "2026-10-01T00:00:00Z",
        "dateLastSeen": "2026-10-05T00:00:00Z",
        "seqUpdate": 1760000000000001,
    }


def test_a_cnc_ipv6_address_is_an_ipv6_indicator(mocker, single_session_fixture):
    record = _cnc_v6()
    assert _related_values("malware/cnc", record) == {"2001:db8::77"}
    results = _lookup_record(mocker, single_session_fixture, "malware/cnc", [record])
    [ipv6] = _context_objects(results, "IPv6")
    assert (ipv6["Address"], ipv6["ASN"], ipv6["Geo"]["Country"], ipv6["MalwareFamily"]) == (
        "2001:db8::77",
        "AS64500",
        "Netherlands",
        ["ExampleRAT"],
    )
    assert ReputationCommand._host_of("2001:db8::77") == "2001:db8::77"
    # a C&C address given in the domain field too: an IPv6 there is no Domain
    record = {**_cnc_v6(), "domain": "2001:db8::77"}
    assert [
        (kind, value)
        for kind, value, _ in IndicatorBuilder.observables("malware/cnc", _build("malware/cnc", record)["indicators"])
    ] == [
        ("IPv6", "2001:db8::77"),
        ("IPv6", "2001:db8::77"),
    ]


def _kit(**overrides) -> dict:
    """An attacks/phishing_kit record without e-mails: the hash, the SHA-256 of the kit archive and its primary
    indicator, and the dates."""
    record = {
        "id": "ab" * 32,
        "hash": "ab" * 32,
        "dateDetected": "2026-09-01T10:12:00Z",
        "dateFirstSeen": "2026-09-01T10:12:00Z",
        "dateLastSeen": "2026-09-04T22:41:00Z",
        "source": ["exampleScanner"],
        "emails": [],
        "downloadedFrom": [],
        "evaluation": {"admiraltyCode": "A1", "credibility": 90, "reliability": 90, "severity": "red", "tlp": "amber", "ttl": 30},
    }
    record.update(overrides)
    return record


def test_a_phishing_kit_hash_is_a_file_indicator_and_its_emails_keep_their_verdict(mocker, single_session_fixture):
    assert _related_values("attacks/phishing_kit", _kit()) == {"ab" * 32}
    record = _kit(emails=["drop@example.com"])
    built = _build("attacks/phishing_kit", record)
    assert (built["relatedIndicators"], built["relatedEmails"]) == ("ab" * 32, "drop@example.com")
    results = _lookup_record(mocker, single_session_fixture, "attacks/phishing_kit", [record])
    [file] = _context_objects(results, "File")
    assert (file["SHA256"], file["TrafficLightProtocol"]) == ("ab" * 32, "AMBER")
    assert {score["Indicator"]: score["Score"] for score in _context_objects(results, "DBotScore")} == {
        "ab" * 32: 2,
        "drop@example.com": 2,
    }


def test_the_kit_lookup_declares_the_email_context_it_writes(mocker, single_session_fixture):
    """Common.EMAIL writes an e-mail address to Account.Email.Address, the output the command declares."""
    results = _lookup_record(mocker, single_session_fixture, "attacks/phishing_kit", [_kit(emails=["drop@example.com"])])
    assert [account["Email"]["Address"] for account in _context_objects(results, "Account")] == ["drop@example.com"]
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        blocks = yml_file.read().split("\n  - ")
    [block] = [block for block in blocks if "\n    name: gibti-get-phishing-kit-info\n" in block]
    declared = re.findall(r"contextPath: (\S+)", block)
    assert "Account.Email.Address" in declared
    assert not [path for path in declared if path.startswith("Email.")]


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


# Invented base58check addresses (version 0 / 5 and made-up hash160 bytes), so the checksum Cortex XSOAR
# verifies holds.
BTC_LEGACY = _base58check(0, bytes(range(1, 21)))
BTC_P2SH = _base58check(5, bytes(range(21, 41)))
BTC_BECH32 = "bc1qexampleexampleexampleexample0000000"
ETH_WALLET = "0x" + "5a" * 20


def _platform_extracts(text: str | None) -> list[str]:
    """What Cortex XSOAR extracts from a text as Cryptocurrency Address: the type's regex, then CryptoCurrenciesFormat,
    which answers bitcoin:<address> for a base58check address and blanks any other."""
    digits = "".join(c for c in string.digits + string.ascii_uppercase + string.ascii_lowercase if c not in "0OIl")
    found = []
    for address in re.findall(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", text or ""):
        number = 0
        for char in address:
            number = number * 58 + digits.index(char)
        try:
            raw = number.to_bytes(25, "big")
        except OverflowError:
            continue
        if raw[-4:] == hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4]:
            found.append(f"bitcoin:{address}")
    return found


def _wallet(address: str, service_type: str) -> dict:
    """A compromised/spd record of a crypto wallet."""
    return {
        "id": hashlib.sha1(address.encode()).hexdigest(),
        "type": "Cryptocurrency Wallet",
        "serviceType": service_type,
        "ownerName": None,
        "country": [],
        "value": {"value": address, "email": None, "bankCard": None, "iban": None},
        "illegalScore": 100,
        "tags": [],
        "sources": [{"name": "shop.example", "type": "Underground Market"}],
        "events": [],
        "malware": [],
        "threatActor": [],
        "firstSeenAt": "2026-10-01T00:00:00Z",
        "lastSeenAt": "2026-10-02T00:00:00Z",
        "createdAt": "2026-10-01T00:00:00Z",
        "evaluation": {"admiraltyCode": "A2", "credibility": 80, "reliability": 80, "severity": "red", "tlp": "green", "ttl": 30},
    }


@pytest.mark.parametrize(
    "address, service_type",
    [
        (BTC_LEGACY, "BTCLike"),
        (BTC_P2SH, "BTCLike"),
        (f"bitcoin:{BTC_LEGACY}", "BTCLike"),
        (f"BITCOIN:{BTC_LEGACY}", "BTCLike"),
        (BTC_P2SH, "USDT"),
    ],
)
def test_a_bitcoin_wallet_is_one_indicator_whether_extracted_or_enriched(mocker, single_session_fixture, address, service_type):
    """Extraction and the lookup name a Bitcoin address as the same bitcoin:<address>, whatever coin the record's
    serviceType names (USDT on Omni lives at Bitcoin addresses)."""
    record = _wallet(address, service_type)
    related = _build("compromised/spd", record)["relatedIndicators"]
    wallet = address.rpartition(":")[2]
    results = _lookup_record(mocker, single_session_fixture, "compromised/spd", [record])
    [crypto] = _context_objects(results, "Cryptocurrency")
    [score] = _context_objects(results, "DBotScore")
    assert _platform_extracts(related) == [crypto["Address"]] == [score["Indicator"]] == [f"bitcoin:{wallet}"]
    assert crypto["AddressType"] == "bitcoin"


@pytest.mark.parametrize(
    "address, service_type, value, address_type",
    [
        (ETH_WALLET, "ETHLike", ETH_WALLET, "ethereum"),
        ("TQ" + "x" * 32, "TRXLike", "TQ" + "x" * 32, "tron"),
        (BTC_BECH32, "BTCLike", f"bitcoin:{BTC_BECH32}", "bitcoin"),
        ("16L5yRNPTuciSgXGHqYwn9N6NeoKqopAv", "BTCLike", "16L5yRNPTuciSgXGHqYwn9N6NeoKqopAv", "bitcoin"),
        ("33cWaRif1jWtZ8nLPVxgPUVG8fKA6grfEY", "BTCLike", "33cWaRif1jWtZ8nLPVxgPUVG8fKA6grfEY", "bitcoin"),
    ],
)
def test_a_wallet_that_extraction_cannot_keep_is_left_to_the_enrichment(
    mocker, single_session_fixture, address, service_type, value, address_type
):
    """A wallet that extraction would blank is no line of GIB Related Indicators Data, and the lookup the enrichment reads
    creates it; a bech32 address is listed and created as bitcoin:<address> but never extracted."""
    record = _wallet(address, service_type)
    related = _build("compromised/spd", record)["relatedIndicators"]
    assert _platform_extracts(related) == []
    assert related == (value if value.startswith("bitcoin:") else None)
    results = _lookup_record(mocker, single_session_fixture, "compromised/spd", [record])
    [crypto] = _context_objects(results, "Cryptocurrency")
    assert (crypto["Address"], crypto["AddressType"]) == (value, address_type)


@pytest.mark.parametrize(
    "payment_string",
    [
        "upi://pay?pa=shop@examplebank&pn=Example Shop&cu=INR",
        "00020126330014EXAMPLE.PIX.TS0111123456789015204000053039865802BR5913Example Store6012Example City6304ABCD",
    ],
    ids=["UPI", "PIX"],
)
def test_the_template_filter_leaves_payment_strings_alone(mocker, payment_string):
    """A QR payment string holds the payee name with its blanks; only a URL, domain, IP or e-mail address with a
    blank or a brace is a report's placeholder."""
    record = _wallet(payment_string, "PIX")
    record["type"] = "QR Payment String"
    spd_types = INDICATORS_TYPES["compromised/spd"]["types"]["value_value"]
    mocker.patch.dict(spd_types["map"], {"QR Payment String": "GIB Suspicious Payment Detail"})
    built = _build("compromised/spd", record)
    assert [value for _, value, _ in IndicatorBuilder.observables("compromised/spd", built["indicators"])] == [payment_string]
    assert built["relatedIndicators"] == payment_string
    report = {"url": ["https://files.example/contents/{machineId}/x", "https://example.com/a b"], "domain": ["evil .example"]}
    assert list(IndicatorBuilder.observables("apt/threat", report)) == []


@pytest.mark.parametrize("placeholder", ["{email}", "drop {at} example.com", "sample user@example.com", "{user}@example.com"])
def test_an_email_with_a_blank_or_a_brace_is_a_placeholder(placeholder):
    """An e-mail address holds no blank and no brace: such a value is a template, not an indicator."""
    kit = {"emails": ["drop@example.com", placeholder], "hash": None}
    assert [value for _, value, _ in IndicatorBuilder.observables("attacks/phishing_kit", kit)] == ["drop@example.com"]
    report = {"email_address": [placeholder], "email_sender_ip": [None], "element_type": ["email-message"]}
    assert list(IndicatorBuilder.observables("apt/threat", report)) == []


def test_an_account_c2_carries_only_the_malware_and_actor_of_its_own_event():
    """Attribution is per event: each C&C carries the malware and actor of the event that names it."""

    def event(source: str, malware: str, actor: str | None, cnc: dict | None) -> dict:
        return {
            "id": f"e-{malware}",
            "source": {"id": "s", "type": source, "idType": "x"},
            "malware": {"id": f"m-{malware}", "name": malware},
            "threatActor": {"id": f"t-{actor}", "name": actor} if actor else None,
            "cnc": cnc or {"cnc": "", "domain": None, "ipv4": None, "ipv6": None, "url": None},
            "client": {
                "ipv4": {"ip": "203.0.113.200", "asn": "AS64511", "provider": "Example ISP", "countryName": "Exampleland"},
                "ipv6": None,
            },
            "dateDetected": "2026-09-20T00:00:00Z",
        }

    record = {
        "id": "f5" * 20,
        "login": "user@example.com",
        "password": "secret",
        "events": [
            event("Stealer logs cloud", "ExampleStealer", None, None),
            event(
                "Botnet",
                "ExampleLoader",
                "ActorZ",
                {
                    "cnc": "http://panel.example/gate.php",
                    "domain": "panel.example",
                    "url": "http://panel.example/gate.php",
                    "ipv4": {"ip": "203.0.113.5"},
                    "ipv6": None,
                },
            ),
            event("TG Bot", "ExampleBot", None, {"cnc": "", "domain": "198.51.100.99", "url": None, "ipv4": None, "ipv6": None}),
        ],
        "sourceType": [],
        "dateFirstSeen": "2026-09-22T01:30:00+03:00",
        "evaluation": {"severity": "red", "tlp": "red"},
    }
    built = _build("compromised/account_group", record)
    results = IndicatorBuilder(create_relationships=True).items(built, "compromised/account_group")
    by_value = {item.row["value"]: item for item in results}
    # The C&C IP is an indicator; the infected client's address (203.0.113.200) is the victim's.
    assert set(by_value) == {"http://panel.example/gate.php", "panel.example", "203.0.113.5", "198.51.100.99"}
    assert (by_value["203.0.113.5"].indicator.asn, by_value["203.0.113.5"].indicator.geo_country) == (None, None)
    for value in ("http://panel.example/gate.php", "panel.example", "203.0.113.5"):
        assert by_value[value].indicator.tags == ["compromised/account_group", "ExampleLoader", "ActorZ"]
        assert [(r.to_entry()["name"], r.to_entry()["entityB"]) for r in by_value[value].relationships] == [
            ("indicator-of", "ExampleLoader"),
            ("related-to", "ActorZ"),
        ]
    assert by_value["198.51.100.99"].indicator.tags == ["compromised/account_group", "ExampleBot"]
    assert by_value["198.51.100.99"].indicator.malware_family == ["ExampleBot"]


def _phishing_group(**overrides) -> dict:
    """An attacks/phishing_group record."""
    record = {
        "id": "c1" * 32,
        "brand": "Example Bank",
        "objective": ["Login harvest"],
        "falsePositive": False,
        "whitelist": False,
        "phishing": [{"url": "https://login.example.com/secure/index.php", "phishingKit": None}],
        "domainInfo": {"domain": "login.example.com"},
        "ip": [{"ip": "203.0.113.70", "countryCode": "US", "countryName": "United States", "provider": "Example Cloud"}],
        "threatActor": None,
        "date": {"detected": "2026-10-01T00:00:00Z", "updated": "2026-10-02T00:00:00Z"},
        "evaluation": {"admiraltyCode": "A2", "credibility": 80, "reliability": 80, "severity": "red", "tlp": "amber"},
    }
    record.update(overrides)
    return record


@pytest.mark.parametrize("flag", ["falsePositive", "whitelist"])
def test_a_flagged_phishing_group_lookup_names_the_flag_and_builds_no_indicator(mocker, single_session_fixture, flag):
    results = _lookup_record(mocker, single_session_fixture, "attacks/phishing_group", [_phishing_group(**{flag: True})])
    assert _context_objects(results, "DBotScore") == []
    assert _context_objects(results, "URL") == []
    record_entry = results[0]
    assert record_entry.outputs[flag] is True
    assert f"Group-IB flags this record as {flag}" in record_entry.readable_output
    unflagged = _lookup_record(mocker, single_session_fixture, "attacks/phishing_group", [_phishing_group()])
    assert [obj["Data"] for obj in _context_objects(unflagged, "URL")] == ["https://login.example.com/secure/index.php"]
    assert "flags this record" not in unflagged[0].readable_output
    # an incident built from a flagged record gives extraction nothing either
    assert _build("attacks/phishing_group", _phishing_group(**{flag: True}))["relatedIndicators"] is None
    assert (
        _build("attacks/phishing_group", _phishing_group())["relatedIndicators"] == "https://login.example.com/secure/index.php"
    )


@pytest.mark.parametrize("marker", ["Index of", "Not specified", "INDEX OF"])
def test_a_phishing_brand_marker_is_no_tag(mocker, single_session_fixture, marker):
    """The brand values "Index of" (a directory listing) and "Not specified" name no brand."""
    results = _lookup_record(mocker, single_session_fixture, "attacks/phishing_group", [_phishing_group(brand=marker)])
    [url] = _context_objects(results, "URL")
    assert url["Tags"] == ["attacks/phishing_group"]
    results = _lookup_record(mocker, single_session_fixture, "attacks/phishing_group", [_phishing_group()])
    assert _context_objects(results, "URL")[0]["Tags"] == ["attacks/phishing_group", "Example Bank"]


def _deface(target: str, ip: str, defacer: str, **overrides) -> dict:
    """An attacks/deface record: the defaced site is the victim."""
    record = {
        "id": hashlib.sha1(f"{target}{defacer}".encode()).hexdigest(),
        "url": f"http://{target}/index.html",
        "siteUrl": f"http://{target}/index.html",
        "targetDomain": target,
        "targetIp": {"ip": ip, "asn": "AS64500", "countryCode": "DE", "countryName": "Germany", "region": "Europe"},
        "threatActor": {"id": "e7" * 20, "name": defacer, "isAPT": False},
        "contacts": [],
        "date": "2026-10-10T08:15:00Z",
        "source": "mirror.example",
        "evaluation": {"admiraltyCode": "B2", "credibility": 80, "reliability": 80, "severity": "orange", "tlp": "amber"},
    }
    record.update(overrides)
    return record


def _search_client(mocker, client, records: dict[str, list[dict]], scores: dict[str, int]):
    """A client whose search reports ``records`` (collection -> raw records) and serves them, parsed as the
    reputation commands parse them."""
    mocker.patch.object(
        client.poller,
        "global_search",
        side_effect=lambda value: [{"apiPath": path, "count": len(items)} for path, items in records.items()],
    )
    mocker.patch.object(
        client,
        "search_collection",
        side_effect=lambda path, query, limit=None: iter(
            [Parser({"count": len(records.get(path, [])), "items": records.get(path, [])}, [], [])]
        ),
    )
    scoring = {"items": {value: {"riskScore": score} for value, score in scores.items()}}
    mocker.patch.object(client.poller, "get_ip_scoring", return_value=scoring)
    mocker.patch.object(client.poller, "get_domain_scoring", return_value=scoring)
    mocker.patch.object(client.poller, "graph_ip_search", return_value=None)
    mocker.patch.object(client.poller, "graph_domain_search", return_value=None)
    return client


@pytest.mark.parametrize(
    "kind, value",
    [("domain", "victim.example"), ("ip", "198.51.100.7")],
)
def test_a_defacement_tags_its_own_site_with_the_collection_only(mocker, single_session_fixture, kind, value):
    """Only the defacement of the site itself counts, not one that names the value elsewhere; the defacer attacked
    the site, so neither its name nor a relationship goes to the site."""
    own = _deface("victim.example", "198.51.100.7", "defacer-one")
    mention = _deface(
        "other.example", "203.0.113.90", "defacer-two", contacts=["https://victim.example/", "mailto:x@198.51.100.7"]
    )
    client = _search_client(mocker, single_session_fixture, {"attacks/deface": [own, mention]}, {value: 55})
    [result] = reputation(client, kind, {kind: value})
    assert result.indicator.dbot_score.score == 2
    assert result.indicator.tags == ["attacks/deface"]
    assert result.relationships is None
    assert result.raw_response["threatActors"] == []
    assert result.raw_response["tlp"] == "AMBER"
    # a defacement of another site that only mentions the value adds nothing
    client = _search_client(mocker, single_session_fixture, {"attacks/deface": [mention]}, {value: 55})
    [result] = reputation(client, kind, {kind: value})
    assert result.indicator.tags is None
    assert result.raw_response["tlp"] is None


def test_an_actor_profile_naming_the_value_is_not_read_by_the_reputation_commands(mocker, single_session_fixture):
    """An APT actor's stat.targetDomain is a domain it attacks; that domain's reputation takes no tag and no reliability
    from the profile."""
    profile = {"id": "f8" * 20, "name": "ExampleAPT", "stat": {"targetDomain": ["victim.example"]}}
    client = _search_client(mocker, single_session_fixture, {"apt/threat_actor": [profile]}, {"victim.example": 55})
    [result] = reputation(client, "domain", {"domain": "victim.example"})
    assert "apt/threat_actor" not in [call.args[0] for call in client.search_collection.call_args_list]
    assert result.indicator.tags is None
    assert result.indicator.dbot_score.reliability == DEFAULT_SOURCE_RELIABILITY
    assert "domain" not in GroupIBTIA.COLLECTIONS["apt/threat_actor"].reputation_kinds
    assert GroupIBTIA.COLLECTIONS["apt/threat_actor"].reputation_reliability is None


def _days_ago(days: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days * 86400))


@pytest.mark.parametrize(
    "collection, age_days, setting, floored",
    [
        ("suspicious_ip/tor_node", 400, None, True),
        ("suspicious_ip/open_proxy", 400, None, True),
        ("suspicious_ip/socks_proxy", 400, None, True),
        ("suspicious_ip/vpn", 400, None, True),
        ("suspicious_ip/scanner", 400, None, True),
        ("suspicious_ip/tor_node", 20, 30, True),
        ("suspicious_ip/scanner", 14, 7, False),
        ("suspicious_ip/vpn", 3, 2, False),
        ("suspicious_ip/open_proxy", 1, 2, True),
        ("suspicious_ip/socks_proxy", 400, 0, True),
    ],
)
def test_a_listing_keeps_the_floor_at_any_age_unless_the_recency_setting_sets_a_window(
    mocker, single_session_fixture, collection, age_days, setting, floored
):
    """A listing of any age keeps the floor; a recency setting counts one seen within that many days, and 0 one of any age."""
    assert GroupIBTIA.COLLECTIONS[collection].floor_max_age_days is None
    record = {"id": "203.0.113.20", "ipv4": {"ip": "203.0.113.20"}, "dateLastSeen": _days_ago(age_days)}
    client = _reputation_client(mocker, single_session_fixture, {collection: [record]}, {"203.0.113.20": 20})
    [result] = reputation(client, "ip", {"ip": "203.0.113.20"}, floor_max_age_days=setting)
    assert result.indicator.dbot_score.score == (2 if floored else 1)
    # A stale listing is no tag either.
    assert result.indicator.tags == ([collection] if floored else None)


def test_an_unscored_ip_with_a_stale_listing_is_suspicious_by_default_and_unknown_outside_a_set_window(
    mocker, single_session_fixture
):
    record = {"id": "203.0.113.20", "dateLastSeen": _days_ago(30)}
    client = _reputation_client(mocker, single_session_fixture, {"suspicious_ip/tor_node": [record]})
    assert reputation(client, "ip", {"ip": "203.0.113.20"})[0].indicator.dbot_score.score == 2
    [result] = reputation(client, "ip", {"ip": "203.0.113.20"}, floor_max_age_days=7)
    assert result.indicator.dbot_score.score == 0


def test_a_listing_without_a_last_sighting_keeps_the_floor_only_without_a_recency_window(mocker, single_session_fixture):
    client = _reputation_client(
        mocker, single_session_fixture, {"suspicious_ip/tor_node": [{"id": "203.0.113.20"}]}, {"203.0.113.20": 20}
    )
    assert reputation(client, "ip", {"ip": "203.0.113.20"})[0].indicator.dbot_score.score == 2
    assert reputation(client, "ip", {"ip": "203.0.113.20"}, floor_max_age_days=30)[0].indicator.dbot_score.score == 1


@pytest.mark.parametrize(
    ("kind", "value", "record"),
    [
        ("ip", "203.0.113.20", {"cnc": "203.0.113.20", "domain": None, "ipv4": [{"ip": "203.0.113.20"}]}),
        ("domain", "c2.example", {"cnc": "c2.example", "domain": "c2.example", "url": None}),
    ],
)
def test_an_instance_whose_floor_setting_still_selects_malware_cnc_gets_no_floor_from_it(
    mocker, single_session_fixture, kind, value, record
):
    floors = Settings.from_params({"reputation_floor_collections": "suspicious_ip/tor_node,malware/cnc"}).floor_collections
    client = _reputation_client(mocker, single_session_fixture, {"malware/cnc": [record]}, {value: 20})
    [result] = reputation(client, kind, {kind: value}, floor_collections=floors)
    assert result.indicator.dbot_score.score == 1
    assert result.indicator.tags is None
    assert "malware/cnc" not in [c.kwargs["path"] for c in ReputationCommand._read.call_args_list]
    assert "malware/cnc" not in [c.args[0] for c in ReputationCommand._listing.call_args_list]


def test_the_floor_carries_the_most_restrictive_tlp_of_its_listings(mocker, single_session_fixture):
    """A floored verdict, and one the risk score raised, carry the most restrictive TLP of the IP's listings."""
    records = {
        "suspicious_ip/scanner": [{"id": "203.0.113.20", "dateLastSeen": _days_ago(1), "evaluation": {"tlp": "white"}}],
        "suspicious_ip/socks_proxy": [{"id": "203.0.113.20", "dateLastSeen": _days_ago(1), "evaluation": {"tlp": "amber"}}],
    }
    client = _reputation_client(mocker, single_session_fixture, records, {"203.0.113.20": 20})
    [result] = reputation(client, "ip", {"ip": "203.0.113.20"})
    assert result.indicator.dbot_score.score == 2
    assert result.indicator.traffic_light_protocol == "AMBER"
    assert result.raw_response["tlp"] == "AMBER"
    # a verdict the risk score raised carries the TLP of the listings whose tags it carries
    client = _reputation_client(mocker, single_session_fixture, records, {"203.0.113.20": 60})
    [result] = reputation(client, "ip", {"ip": "203.0.113.20"})
    assert (result.indicator.tags, result.raw_response["tlp"]) == (
        ["suspicious_ip/scanner", "suspicious_ip/socks_proxy"],
        "AMBER",
    )


@pytest.mark.parametrize("raw, expected", [(None, None), ("", None), ("0", 0), (" 7 ", 7), (30, 30)])
def test_the_floor_max_age_setting_takes_a_whole_number_and_blank_is_none(raw, expected):
    assert Settings.from_params({"reputation_floor_max_age_days": raw}).floor_max_age_days == expected


@pytest.mark.parametrize("raw", ["-1", "two", "1.5"])
def test_floor_max_age_setting_refuses_invalid_values(raw):
    with pytest.raises(DemistoException, match="Suspicious IP listing recency"):
        Settings.from_params({"reputation_floor_max_age_days": raw})


def test_main_reads_the_floor_max_age_setting(mocker):
    params = {"credentials": {"identifier": "u", "password": "p"}, "url": "https://example.com/api/v2/"}
    params["reputation_floor_max_age_days"] = "9"
    assert Settings.from_params(params).floor_max_age_days == 9
    command = mocker.patch.object(GroupIBTIA, "ReputationCommand")
    run_main(mocker, {**params, "enabled_reputation_commands": ["ip"]}, "ip", {"ip": "198.51.100.1"})
    assert command.call_args.args[2].floor_max_age_days == 9
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        assert "\n  name: reputation_floor_max_age_days\n" in yml_file.read()


def _proxy(port: int, last_seen: str, **overrides) -> dict:
    """An open proxy listing: the IP repeats on another port as another record."""
    record = {
        "id": "192.0.2.10",
        "ipv4": {"ip": "192.0.2.10", "countryCode": "NL", "countryName": None, "asn": None, "provider": None},
        "port": port,
        "type": "HTTP",
        "source": "list-a.example.com",
        "sources": ["list-a.example.com"],
        "dateFirstSeen": "2026-10-10T08:00:00Z",
        "dateLastSeen": last_seen,
        "dateDetected": "2026-10-10T08:00:00Z",
        "evaluation": {"admiraltyCode": "C3", "credibility": 50, "reliability": 50, "severity": "green", "tlp": "white"},
    }
    record.update(overrides)
    return record


def test_an_open_proxy_lookup_returns_every_listing_of_the_address(mocker, single_session_fixture):
    listings = [
        _proxy(8080, "2026-10-14T08:00:00Z"),
        _proxy(3128, "2026-10-13T08:00:00Z", type="Socks4"),
        _proxy(8080, "2026-10-14T08:00:00Z"),
        _proxy(1080, "2026-10-12T08:00:00Z", id="192.0.2.11", ipv4={"ip": "192.0.2.11"}),
    ]
    client = single_session_fixture
    results = _lookup_record(mocker, client, "suspicious_ip/open_proxy", listings)
    assert client.search_collection.call_args.kwargs == {"query": "192.0.2.10", "limit": 1000}
    records = [r for r in results if r.outputs_prefix == "GIBTI.SuspiciousIPOpenProxy"]
    assert [(r.outputs["id"], r.outputs["port"], r.outputs["type"]) for r in records] == [
        ("192.0.2.10", 8080, "HTTP"),
        ("192.0.2.10", 3128, "Socks4"),
    ]
    assert [r.outputs["countryName"] for r in records] == ["NL", "NL"]
    assert [obj["Address"] for obj in _context_objects(results, "IP")] == ["192.0.2.10"]
    with pytest.raises(DemistoException, match="No record with id '192.0.2.99'"):
        lookup(client, "suspicious_ip/open_proxy", {"id": "192.0.2.99"})


def test_each_open_proxy_listing_has_its_own_context_key_port_0_included(mocker, single_session_fixture):
    """The context merges an entry into the object whose key fields are truthy and equal; a port of 0 is
    falsy there, so the key is one text of the address and the port."""
    listings = [_proxy(0, "2026-10-14T08:00:00Z"), _proxy(8080, "2026-10-13T08:00:00Z")]
    results = _lookup_record(mocker, single_session_fixture, "suspicious_ip/open_proxy", listings)
    records = [r for r in results if r.outputs_prefix == "GIBTI.SuspiciousIPOpenProxy"]
    assert [(r.outputs["listing"], r.outputs["port"]) for r in records] == [("192.0.2.10:0", 0), ("192.0.2.10:8080", 8080)]
    assert {key for r in records for key in r.to_context()["EntryContext"]} == {
        "GIBTI.SuspiciousIPOpenProxy(val.listing && val.listing == obj.listing)"
    }
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        blocks = yml_file.read().split("\n  - ")
    for command in ("gibti-get-suspicious-ip-open-proxy-info", "gibtia-get-suspicious-ip-open-proxy-info"):
        [block] = [block for block in blocks if f"\n    name: {command}\n" in block]
        assert "contextPath: GIBTI.SuspiciousIPOpenProxy.listing" in block


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("clear", "WHITE"),
        ("TLP:CLEAR", "WHITE"),
        ("amber+strict", "AMBER"),
        ("TLP:AMBER+STRICT", "AMBER"),
        ("green", "GREEN"),
        ("purple", "RED"),
        ("", None),
        (None, None),
    ],
)
def test_a_tlp_2_marking_maps_to_its_level_and_an_unknown_one_to_red(raw, expected):
    assert IndicatorBuilder.tlp(raw) == expected


@pytest.mark.parametrize("tlp, expected", [("clear", "WHITE"), ("amber+strict", "AMBER"), ("restricted", "RED")])
def test_a_lookup_indicator_takes_a_tlp_2_marking(mocker, single_session_fixture, tlp, expected):
    """Group-IB's TLP is an open set; an unknown marking is handled as RED."""
    record = _report(evaluation={"severity": "red", "tlp": tlp})
    results = _lookup_record(mocker, single_session_fixture, "hi/threat", [record])
    assert {obj["TrafficLightProtocol"] for obj in _context_objects(results, "IP")} == {expected}


def _cve(**overrides) -> dict:
    """An osi/vulnerability record whose legacy cvss is CVSS v2 and whose mergedCvss is the cross-version score."""
    record = {
        "id": "CVE-2099-10001",
        "type": "cve",
        "description": "Example Server allows remote code execution.",
        "datePublished": "2026-02-15T20:24:00+01:00",
        "dateModified": "2026-04-26T20:24:00+02:00",
        "cvss": {"score": 7.5, "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
        "mergedCvss": 9.8,
        "mergedCvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": {"epss": 0.01, "percentile": 0.2},
        "hasExploit": False,
        "exploitCount": 0,
        "seenInTheWild": False,
        "evaluation": {"admiraltyCode": "A1", "credibility": 100, "reliability": 100, "severity": "orange", "tlp": "green"},
    }
    record.update(overrides)
    return record


def test_cvss_is_read_from_merged_cvss_first(mocker, single_session_fixture):
    client = single_session_fixture
    results = _lookup_record(mocker, client, "osi/vulnerability", [_cve()])
    [cve] = _context_objects(results, "CVE")
    assert cve["CVSS"] == {"Score": 9.8, "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    [scored] = score_cves(client, {"cve": "CVE-2099-10001"})
    assert (scored.outputs["cvssScore"], scored.outputs["cvssVector"]) == (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    # no exploit, a low EPSS and an orange record: the CVSS of 9.8 alone makes it Bad
    assert scored.outputs["score"] == 3
    # a record without the merged score keeps the legacy one and its vector
    mocker.patch.object(
        client.poller,
        "search_feed_by_id",
        return_value=Parser({"count": 1, "items": [_cve(mergedCvss=None, mergedCvssVector=None)]}, [], []),
    )
    [scored] = score_cves(client, {"cve": "CVE-2099-10001"})
    assert (scored.outputs["cvssScore"], scored.outputs["cvssVector"], scored.outputs["score"]) == (
        7.5,
        "AV:N/AC:L/Au:N/C:P/I:P/A:P",
        2,
    )


def test_a_defacement_lookup_keeps_its_url_indicator_out_of_extraction(mocker, single_session_fixture):
    """Extraction from the entry would add the victim site's host as a Domain: the entry is not extracted, and
    the URL stays an indicator object with its verdict."""
    client = single_session_fixture
    results = _lookup_record(mocker, client, "attacks/deface", [_deface("victim.example", "198.51.100.7", "defacer-one")])
    [entry] = [r for r in results if _context_objects([r], "URL")]
    assert entry.ignore_auto_extract is True
    assert entry.to_context()["IgnoreAutoExtract"] is True
    assert [obj["Data"] for obj in _context_objects([entry], "URL")] == ["http://victim.example/index.html"]
    assert [(s["Indicator"], s["Score"]) for s in _context_objects([entry], "DBotScore")] == [
        ("http://victim.example/index.html", 2)
    ]
    # the other collections' indicator entries stay extractable
    other = _lookup_record(mocker, client, "malware/cnc", [_cnc_v6()])
    assert all(r.ignore_auto_extract is False for r in other if _context_objects([r], "DBotScore"))


def test_malware_incidents_carry_their_actors_as_text_and_the_threat_level_as_severity():
    record = {
        "id": "m1",
        "name": "StealerOne",
        "updatedAt": "2026-01-01T00:00:00+00:00",
        "threatLevel": "High",
        "taList": {"id": ["a1", "a2"], "name": ["Crew One", "Crew Two"]},
    }
    raw = json.loads(IncidentBuilder().build("malware/malware", dict(record))["rawJSON"])
    assert (raw["threat_actor_name"], raw["threat_actor_id"], raw["systemSeverity"]) == ("Crew One, Crew Two", "a1, a2", 3)
    for level, severity in (("Medium", 2), ("Low", 1), ("", 0), (None, 0)):
        incident = IncidentBuilder().build("malware/malware", {**record, "threatLevel": level})
        assert json.loads(incident["rawJSON"])["systemSeverity"] == severity
    with open(f"{realpath}/../../Classifiers/classifier-Group-IB_Threat_Intelligence_mapper.json") as mapper_file:
        rules = json.load(mapper_file)["mapping"]["GIB Malware"]["internalMapping"]
    assert rules["GIB Threat Actor Name"] == {"simple": "threat_actor_name"}
    assert rules["GIB Threat Actor ID"] == {"simple": "threat_actor_id"}
    assert rules["severity"] == {"simple": "systemSeverity"}


def test_cpe_rows_carry_the_update_and_drop_empty_columns(mocker, single_session_fixture):
    client = single_session_fixture
    portion = MagicMock()
    portion.parse_portion.return_value = [
        {
            "id": "CVE-2099-10002",
            "cpeTable": {
                "product": ["examplelib", "examplelib"],
                "version": ["2.0", "2.0"],
                "update": ["beta1", "rc1"],
                "string": ["", ""],
                "string23": ["", None],
            },
            "evaluation": {"severity": "red"},
        }
    ]
    mocker.patch.object(client.poller, "search_feed_by_id", return_value=portion)
    view = present_record(client, "osi/vulnerability", "CVE-2099-10002")
    feed, [cpe] = view.record, view.tables
    assert "beta1" in cpe.readable_output
    assert "rc1" in cpe.readable_output
    assert feed["cpeTable"]["update"] == ["beta1", "rc1"]
    assert "string" not in feed["cpeTable"]
    assert "string23" not in feed["cpeTable"]
    assert MAPPING["osi/vulnerability"]["cpeTable"]["update"] == "cpeTable.update"
    with open(f"{realpath}/../../IncidentFields/incidentfield-GIB_CPE_Table.json") as field_file:
        assert "update" in [column["key"] for column in json.load(field_file)["columns"]]


@pytest.mark.parametrize(
    "raw, expected",
    [
        (None, DEFAULT_SETTINGS.floor_collections),
        ("", DEFAULT_SETTINGS.floor_collections),
        ("none", frozenset()),
        ("suspicious_ip/tor_node,malware/cnc", frozenset({"suspicious_ip/tor_node", "malware/cnc"})),
        (["suspicious_ip/vpn"], frozenset({"suspicious_ip/vpn"})),
    ],
)
def test_the_floor_collections_setting_takes_a_list_or_a_comma_separated_text(raw, expected):
    params = {} if raw is None else {"reputation_floor_collections": raw}
    assert Settings.from_params(params).floor_collections == expected


def test_no_incident_type_runs_the_postprocessing_playbook_automatically():
    """The playbook is every type's default and starts by hand, or with Run playbook automatically."""
    types_dir = f"{realpath}/../../IncidentTypes"
    types = [json.load(open(os.path.join(types_dir, name))) for name in sorted(os.listdir(types_dir))]
    assert types
    assert {t["name"]: t["autorun"] for t in types if t["autorun"] is not False} == {}
    assert {t["playbookId"] for t in types} == {"Incident Postprocessing - Group-IB Threat Intelligence & Attribution"}


def test_floor_default_is_every_suspicious_ip_collection_in_the_code_and_the_yml():
    expected = frozenset(
        {
            "suspicious_ip/tor_node",
            "suspicious_ip/open_proxy",
            "suspicious_ip/socks_proxy",
            "suspicious_ip/vpn",
            "suspicious_ip/scanner",
        }
    )
    assert expected == DEFAULT_SETTINGS.floor_collections
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        blocks = yml_file.read().split("\n- ")
    [block] = [block for block in blocks if "\n  name: reputation_floor_collections\n" in block]
    [default] = [line.split(":", 1)[1].strip() for line in block.splitlines() if line.startswith("  defaultvalue:")]
    assert frozenset(default.split(",")) == expected
    options = block.split("\n  options:\n", 1)[1]
    assert frozenset(line.strip()[2:] for line in options.splitlines() if line.startswith("  - ")) == expected | {"none"}


# The last sighting of a suspicious_ip/* listing seen today.
SEEN_TODAY = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@pytest.mark.parametrize(
    "kind, value, collection, record, floored",
    [
        (
            "ip",
            "203.0.113.20",
            "suspicious_ip/open_proxy",
            {"id": "203.0.113.20", "ipv4": {"ip": "203.0.113.20"}, "dateLastSeen": SEEN_TODAY},
            True,
        ),
        (
            "ip",
            "2001:db8::5",
            "suspicious_ip/scanner",
            {"ipv4": None, "ipv6": {"ip": "2001:db8::5"}, "dateLastSeen": SEEN_TODAY},
            True,
        ),
        (
            "ip",
            "2001:db8::5",
            "suspicious_ip/scanner",
            {"ipv4": None, "ipv6": {"ip": "2001:DB8:0:0::5"}, "dateLastSeen": SEEN_TODAY},
            True,
        ),
        # a record of another address: another proxy returned when an IP is read by id, and a VPN gateway for
        # a domain, which is never looked up in suspicious_ip/*
        (
            "ip",
            "203.0.113.20",
            "suspicious_ip/socks_proxy",
            {"id": "203.0.113.21", "ipv4": {"ip": "203.0.113.21"}, "dateLastSeen": SEEN_TODAY},
            False,
        ),
        (
            "domain",
            "c2.example",
            "suspicious_ip/vpn",
            {"id": "203.0.113.40", "ipv4": {"ip": "203.0.113.40"}, "dateLastSeen": SEEN_TODAY},
            False,
        ),
    ],
)
def test_a_floor_collection_counts_only_when_it_lists_the_observable_itself(
    mocker, single_session_fixture, kind, value, collection, record, floored
):
    """The floor counts only the IP's own record, in any IPv6 notation; a domain is not looked up in suspicious_ip/*."""
    client = _reputation_client(mocker, single_session_fixture, {collection: [record]}, {value: 20})
    [result] = reputation(client, kind, {kind: value}, floor_collections=DEFAULT_SETTINGS.floor_collections)
    assert result.indicator.dbot_score.score == (2 if floored else 1)
    assert (f"is listed in {collection}" in result.readable_output) is floored
    # A domain is never looked up in a suspicious_ip/* collection.
    asked_at_all = kind == "ip"
    assert result.raw_response["collections"] == ([collection] if asked_at_all else [])
    assert result.indicator.tags == ([collection] if floored else None)
    if not asked_at_all:
        return
    listings = [tuple(c.args) for c in ReputationCommand._listing.call_args_list]
    [(_path, asked)] = [call for call in listings if call[0] == collection]
    assert asked == value


def test_the_floor_reads_only_the_selected_collections(mocker, single_session_fixture):
    records = {"suspicious_ip/tor_node": [{"id": "203.0.113.20"}], "attacks/ddos": [{"id": "203.0.113.20"}]}
    client = _reputation_client(mocker, single_session_fixture, records, {"203.0.113.20": 20})
    reputation(client, "ip", {"ip": "203.0.113.20"}, floor_collections=frozenset({"suspicious_ip/tor_node"}))
    assert [c.args[0] for c in ReputationCommand._listing.call_args_list] == ["suspicious_ip/tor_node"]
    assert "attacks/ddos" not in [c.kwargs["path"] for c in ReputationCommand._read.call_args_list]


def test_a_domain_is_never_looked_up_in_a_suspicious_ip_collection(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"example.com": 20})
    reputation(client, "domain", {"domain": "example.com"})
    ReputationCommand._listing.assert_not_called()


def test_the_search_timeout_setting_takes_zero_or_positive_seconds():
    def search_timeout(params):
        return Settings.from_params(params).search_timeout

    assert search_timeout({}) == GroupIBTIA.Settings.DEFAULT_SEARCH_TIMEOUT
    assert search_timeout({"search_timeout": ""}) == GroupIBTIA.Settings.DEFAULT_SEARCH_TIMEOUT
    assert search_timeout({"search_timeout": " 5 "}) == 5.0
    assert search_timeout({"search_timeout": "0"}) == 0.0
    with pytest.raises(DemistoException, match="must be zero or positive"):
        search_timeout({"search_timeout": "-1"})
    with pytest.raises(DemistoException, match="expected a number of seconds"):
        search_timeout({"search_timeout": "soon"})


class _FakeServer:
    """demisto.internalHttpRequest over a fixed set of answers: (method, uri) -> (status, body)."""

    def __init__(self, answers: dict[tuple[str, str], tuple[int, Any]]):
        self.answers = answers
        self.calls: list[tuple[str, str, Any]] = []

    def __call__(self, method, uri, body=None):
        self.calls.append((method, uri, json.loads(body) if body else None))
        status, payload = self.answers.get((method, uri), (404, "not found"))
        return {"statusCode": status, "body": json.dumps(payload) if not isinstance(payload, str) else payload}


def _shipped_rules():
    return [
        {
            "id": "gib_rule_all_types",
            "name": "GIB Rule All Types",
            "action": "script",
            "scriptName": "GIBTIIncidentUpdateAllTypes",
            "scriptID": "",
            "version": 1,
        },
        {
            "id": "gib_rule",
            "name": "GIB Rule",
            "action": "script",
            "scriptName": "GIBTIIncidentUpdate",
            "scriptID": "GIBTIIncidentUpdate",
            "version": 1,
        },
        {"id": "other", "name": "Someone else's rule", "action": "script", "scriptName": "Other", "scriptID": "", "version": 1},
    ]


def test_testing_the_instance_fills_the_script_of_the_shipped_rules():
    server = _FakeServer(
        {
            ("GET", "/preprocess/rules"): (200, _shipped_rules()),
            ("POST", "/automation/search"): (
                200,
                {"scripts": [{"id": "GIBTIIncidentUpdateAllTypes", "name": "GIBTIIncidentUpdateAllTypes"}]},
            ),
            ("POST", "/preprocess/rule"): (200, {}),
        }
    )
    assert GroupIBTIA.PreProcessRuleScripts(server).fill() == ["GIB Rule All Types"]
    [save] = [call for call in server.calls if call[:2] == ("POST", "/preprocess/rule")]
    assert save[2]["scriptID"] == "GIBTIIncidentUpdateAllTypes"
    assert save[2]["id"] == "gib_rule_all_types"
    assert ("POST", "/automation/search", {"page": 0, "size": 1, "query": 'id:"GIBTIIncidentUpdateAllTypes"'}) in server.calls


@pytest.mark.parametrize(
    "answers",
    [
        {},  # the pre-processing rules route answers 404
        {("GET", "/preprocess/rules"): (200, _shipped_rules())},  # the script is not installed
        {
            ("GET", "/preprocess/rules"): (200, _shipped_rules()),
            ("POST", "/automation/search"): (200, {"scripts": [{"id": "GIBTIIncidentUpdateAllTypes"}]}),
            ("POST", "/preprocess/rule"): (403, "forbidden"),
        },
    ],
)
def test_a_rule_that_cannot_be_filled_is_left_alone(answers, mocker):
    mocker.patch.object(GroupIBTIA.demisto, "error")
    server = _FakeServer(answers)
    assert GroupIBTIA.PreProcessRuleScripts(server).fill() == []
    saves = [call for call in server.calls if call[:2] == ("POST", "/preprocess/rule")]
    # a rule is saved only with the id of a script the platform has
    assert all(call[2]["scriptID"] == "GIBTIIncidentUpdateAllTypes" for call in saves)
    if ("POST", "/automation/search") not in answers:
        assert saves == []


def test_a_rule_left_without_its_script_is_logged_as_an_error(mocker):
    error = mocker.patch.object(GroupIBTIA.demisto, "error")
    refused = _FakeServer(
        {
            ("GET", "/preprocess/rules"): (200, _shipped_rules()),
            ("POST", "/automation/search"): (200, {"scripts": [{"id": "GIBTIIncidentUpdateAllTypes"}]}),
            ("POST", "/preprocess/rule"): (403, "forbidden"),
        }
    )
    assert GroupIBTIA.PreProcessRuleScripts(refused).fill() == []
    [message] = [call.args[0] for call in error.call_args_list]
    assert "'GIB Rule All Types'" in message
    assert "select GIBTIIncidentUpdateAllTypes in the rule" in message
    error.reset_mock()
    not_installed = _FakeServer({("GET", "/preprocess/rules"): (200, _shipped_rules())})
    assert GroupIBTIA.PreProcessRuleScripts(not_installed).fill() == []
    [message] = [call.args[0] for call in error.call_args_list]
    assert "GIBTIIncidentUpdateAllTypes is not installed" in message


def test_a_rules_route_that_answers_404_logs_nothing(mocker):
    error = mocker.patch.object(GroupIBTIA.demisto, "error")
    assert GroupIBTIA.PreProcessRuleScripts(_FakeServer({})).fill() == []
    error.assert_not_called()


def test_the_instance_test_passes_whatever_the_rules_do(mocker, single_session_fixture):
    granted = mocker.patch.object(single_session_fixture, "granted_collections", return_value=[{"collection": "ioc/common"}])
    mocker.patch.object(single_session_fixture, "available_collections", return_value=frozenset({"ioc/common"}))
    fill = mocker.patch.object(GroupIBTIA.PreProcessRuleScripts, "fill", side_effect=RuntimeError("connection reset"))
    error = mocker.patch.object(GroupIBTIA.demisto, "error")
    assert GroupIBTIA.TestModuleCommand(single_session_fixture).run() == "ok"
    granted.assert_called_once_with(refresh=True)
    assert fill.call_count == 1
    error.assert_called_once_with("[pre-processing rules] not checked: connection reset")


@pytest.mark.parametrize(
    "mode, password, expected",
    [
        ("Off", "P@ssw0rd123", "P@ssw0rd123"),
        ("Partial", "P@ssw0rd123", "P@ssw****"),
        ("Partial", "x", "****"),
        ("Partial", "", ""),
    ],
)
def test_the_partial_password_mask_keeps_the_first_half_and_off_keeps_the_password(mode, password, expected):
    record = {"id": "a", "password": password}
    assert GroupIBTIA.PasswordMask(mode).apply("compromised/account_group", record)["password"] == expected


def test_full_password_masking_drops_the_password_field_of_account_and_breached_records_only():
    mask = GroupIBTIA.PasswordMask("Full")
    assert mask.apply("compromised/account_group", {"id": "a", "password": "secret"}) == {"id": "a"}
    assert mask.apply("compromised/breacheddb", {"id": "b", "passwords": ["secret"]}) == {"id": "b"}
    leak = {"id": "c", "password": "kept"}
    assert mask.apply("osi/public_leak", dict(leak)) == leak


def test_the_password_mask_setting_is_read_in_any_case_and_validated():
    assert GroupIBTIA.PasswordMask.from_params({}).mode == "Off"
    assert GroupIBTIA.PasswordMask.from_params({"mask_passwords": ""}).mode == "Off"
    assert GroupIBTIA.PasswordMask.from_params({"mask_passwords": "partial"}).mode == "Partial"
    with pytest.raises(DemistoException, match="Mask passwords"):
        GroupIBTIA.PasswordMask.from_params({"mask_passwords": "Half"})


def _account_record() -> dict:
    return {
        "id": "acc-1",
        "name": "user@example.com",
        "login": "user@example.com",
        "password": "P@ssw0rd123",
        "dateFirstSeen": "2026-01-01T00:00:00+00:00",
        "dateLastSeen": "2026-01-02T00:00:00+00:00",
        "evaluation": {"severity": "red", "tlp": "amber"},
        "indicators": {"event_url": None, "event_domain": None},
    }


def test_fetched_account_incidents_carry_the_masked_password(mocker, single_session_fixture):
    client = single_session_fixture
    portion = MagicMock()
    portion.sequpdate = 1592219410029000
    portion.portion_size = 1
    portion.count = 1
    portion.parse_portion.return_value = [_account_record()]
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "compromised/account_group"}])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([portion], None))
    _, incidents = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=["compromised/account_group"],
        max_requests=1,
        hunting_rules=0,
        password_mask=GroupIBTIA.PasswordMask("Partial"),
    )
    [incident] = incidents
    raw = json.loads(incident["rawJSON"])
    assert raw["password"] == "P@ssw****"
    assert "P@ssw0rd123" not in incident["rawJSON"]


def test_account_lookup_and_local_search_mask_the_password(mocker, single_session_fixture):
    client = single_session_fixture
    masker = Masking(GroupIBTIA.PasswordMask("Full"), CardDataMask())
    portion = MagicMock()
    portion.parse_portion.return_value = [_account_record()]
    mocker.patch.object(client.poller, "search_feed_by_id", return_value=portion)
    feed = read_record(client, "compromised/account_group", "acc-1", masker)
    assert "password" not in feed
    search_portion = MagicMock()
    search_portion.parse_portion.return_value = [_account_record()]
    search_portion.raw_dict = {"items": [{"seqUpdate": 1}]}
    mocker.patch.object(client, "search_collection", return_value=[search_portion])
    result = local_search(
        client, {"query": "user@example.com", "collection_name": "compromised/account_group", "include_raw_feed": "true"}, masker
    )
    assert "P@ssw0rd123" not in json.dumps(result.outputs)
    assert "P@ssw0rd123" not in result.readable_output


@pytest.mark.parametrize(
    "mode, passwords, expected",
    [
        ("Off", ["P@ssw0rd123", "abcd"], ["P@ssw0rd123", "abcd"]),
        ("Partial", ["P@ssw0rd123", "abcd"], ["P@ssw****", "ab****"]),
        ("Partial", None, None),
    ],
)
def test_password_mask_covers_the_passwords_of_breached_records(mode, passwords, expected):
    record = {"id": ["b-1"], "passwords": passwords, "emails": ["user@example.com"]}
    assert GroupIBTIA.PasswordMask(mode).apply("compromised/breacheddb", record)["passwords"] == expected
    full = GroupIBTIA.PasswordMask("Full").apply("compromised/breacheddb", dict(record))
    assert "passwords" not in full
    assert full["emails"] == ["user@example.com"]


TEST_PAN = "4111111111111111"


def _card_record() -> dict:
    return {
        "id": "card-1",
        "name": TEST_PAN,
        "number": TEST_PAN,
        "cvv": "015",
        "validThru": "12/30",
        "issuer": "Example Bank",
        "compromised_events": {
            "cvv": ["015", None],
            "valid_thru": ["12/30", "12/30"],
            "victim_name": ["Sample Holder", None],
            "victim_phone": ["+15550100", ""],
            "cnc": ["shop.example", None],
        },
        "evaluation": {"severity": "red", "tlp": "red"},
        "dateFirstSeen": "2026-01-01T00:00:00+00:00",
        "dateLastSeen": "2026-01-02T00:00:00+00:00",
        "indicators": {},
    }


def test_card_mask_keeps_the_first_six_and_last_four_digits_drops_the_cvv_and_redacts_the_cardholder():
    masked = GroupIBTIA.CardDataMask(True).apply("compromised/bank_card_group", _card_record())
    assert masked["name"] == masked["number"] == "411111XXXXXX1111"
    assert masked["cvv"] is None
    assert masked["compromised_events"]["cvv"] == [None, None]
    assert masked["compromised_events"]["victim_name"] == ["[redacted]", None]
    assert masked["compromised_events"]["victim_phone"] == ["[redacted]", ""]
    # what identifies the card for the analyst stays
    assert (masked["validThru"], masked["issuer"]) == ("12/30", "Example Bank")
    assert masked["compromised_events"]["cnc"] == ["shop.example", None]
    assert TEST_PAN not in json.dumps(masked)
    assert "015" not in json.dumps(masked)


@pytest.mark.parametrize(
    "number, expected",
    [("4111111111111111", "411111XXXXXX1111"), ("5500000000000004001", "550000XXXXXXXXX4001"), ("1234567", "XXX4567"), ("", "")],
)
def test_card_numbers_of_any_length_are_masked(number, expected):
    assert GroupIBTIA.CardDataMask.mask_number(number) == expected


def test_card_mask_off_changes_nothing_and_a_masked_card_number_is_left_as_served():
    assert GroupIBTIA.CardDataMask(False).apply("compromised/bank_card_group", _card_record()) == _card_record()
    record = {"name": TEST_PAN, "number": TEST_PAN}
    assert GroupIBTIA.CardDataMask(True).apply("compromised/masked_card", dict(record)) == record


def test_the_card_mask_setting_is_off_unless_set():
    assert GroupIBTIA.CardDataMask.from_params({}).enabled is False
    assert GroupIBTIA.CardDataMask.from_params({"mask_card_data": "true"}).enabled is True
    assert GroupIBTIA.CardDataMask.from_params({"mask_card_data": False}).enabled is False


def test_fetched_card_incidents_lookups_and_local_search_carry_the_masked_card(mocker, single_session_fixture):
    client = single_session_fixture
    masker = Masking(PasswordMask(), GroupIBTIA.CardDataMask(True))
    portion = MagicMock()
    portion.sequpdate = 1592219410029000
    portion.portion_size = 1
    portion.count = 1
    portion.parse_portion.return_value = [_card_record()]
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "compromised/bank_card_group"}])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([portion], None))
    _, incidents = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=["compromised/bank_card_group"],
        max_requests=1,
        hunting_rules=0,
        card_mask=masker.card_mask,
    )
    [incident] = incidents
    assert "411111XXXXXX1111" in incident["name"]
    assert TEST_PAN not in json.dumps(incident)
    assert '"015"' not in incident["rawJSON"]
    lookup = MagicMock()
    lookup.parse_portion.return_value = [_card_record()]
    mocker.patch.object(client.poller, "search_feed_by_id", return_value=lookup)
    feed = read_record(client, "compromised/bank_card_group", "card-1", masker)
    assert feed["number"] == "411111XXXXXX1111"
    search_portion = MagicMock()
    search_portion.parse_portion.return_value = [_card_record()]
    search_portion.raw_dict = {"items": [{"seqUpdate": 1}]}
    mocker.patch.object(client, "search_collection", return_value=[search_portion])
    result = local_search(
        client, {"query": "411111", "collection_name": "compromised/bank_card_group", "include_raw_feed": "true"}, masker
    )
    assert TEST_PAN not in json.dumps(result.outputs)
    assert TEST_PAN not in result.readable_output


def test_breached_lookup_masks_the_passwords(mocker, single_session_fixture):
    client = single_session_fixture
    body = {"id": ["b-1"], "password": ["P@ssw0rd123"], "email": ["user@example.com"]}
    mocker.patch.object(client.poller, "send_request", return_value=body)
    feed = read_record(client, "compromised/breacheddb", "b-1", Masking(GroupIBTIA.PasswordMask("Partial"), CardDataMask()))
    assert feed["passwords"] == ["P@ssw****"]


def test_a_breached_lookup_escapes_a_slash_in_the_id_of_the_by_id_route(mocker, single_session_fixture):
    """An id with a slash stays one path segment of compromised/breached/{id}."""
    client = single_session_fixture
    body = {"id": ["ab/12"], "email": ["user@example.com"], "password": [], "leakName": "Example leak", "evaluation": None}
    send = mocker.patch.object(client.poller, "send_request", return_value=body)
    search = mocker.patch.object(client, "search_collection")
    feed = read_record(client, "compromised/breacheddb", "ab/12")
    assert send.call_args.kwargs["endpoint"] == "compromised/breached/ab%2F12"
    assert (feed["id"], feed["leakName"], feed["emails"]) == ("ab/12", "Example leak", ["user@example.com"])
    search.assert_not_called()


@pytest.mark.parametrize("record_id", [".", ".."])
def test_a_dot_id_is_refused_before_the_by_id_route_is_requested(mocker, record_id):
    """A bare dot segment would resolve to another endpoint; the lookup fails on the argument with a plain message."""
    send = mocker.patch.object(GroupIBTIA.TIPoller, "send_request")
    params = {"url": "https://example.com", "credentials": {"identifier": "u", "password": "p"}}
    mocker.patch.object(GroupIBTIA.demisto, "params", return_value=params)
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="gibti-get-compromised-breached-info")
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value={"id": record_id})
    error = mocker.patch.object(GroupIBTIA, "return_error")
    GroupIBTIA.main()
    send.assert_not_called()
    [message] = error.call_args.args
    assert f"Invalid id {record_id!r}: a bare dot segment" in message
    assert "Traceback" not in message


@pytest.mark.parametrize(
    "answer, not_found, message",
    [
        (GroupIBTIA.NotFoundException("HTTP 404: Not found."), True, "No record with id 'b-1' was"),
        ({"id": ["another"], "leakName": "Other leak"}, True, "No record with id 'b-1' was"),
        (None, True, "No record with id 'b-1' was"),
        (
            GroupIBTIA.ConnectionException("Request to https://example.com failed: connection reset"),
            False,
            r"did not answer the lookup of id 'b-1' .*try again later",
        ),
        (
            GroupIBTIA.ConnectionException("Request to https://example.com timed out after 120s"),
            False,
            "try again later",
        ),
        (GroupIBTIA.ConnectionException("Retries exhausted for https://example.com"), False, "try again later"),
        (GroupIBTIA.ConnectionException(SERVER_ERROR), False, "try again later"),
        (GroupIBTIA.ConnectionException("HTTP 429: Maximum number of requests"), False, "try again later"),
        (GroupIBTIA.ConnectionException("HTTP 403: Something is wrong with your account."), False, "refused"),
    ],
    ids=["404", "another record", "empty", "cut", "timeout", "5xx after retries", "5xx", "429", "refused"],
)
def test_breached_lookup_reads_the_by_id_route_only(mocker, single_session_fixture, answer, not_found, message):
    """A breached record is looked up by its by-id route only: a missing record is not found, an HTTP 403 is reported as
    refused, any other failure asks to try again later, and no failure reads as a credentials error."""
    client = single_session_fixture
    if isinstance(answer, Exception):
        mocker.patch.object(client.poller, "send_request", side_effect=answer)
    else:
        mocker.patch.object(client.poller, "send_request", return_value=answer)
    search = mocker.patch.object(client, "search_collection")
    with pytest.raises(DemistoException, match=message) as raised:
        lookup(client, "compromised/breacheddb", {"id": "b-1"})
    search.assert_not_called()
    assert "Bad Credentials" not in str(raised.value)
    assert ("No record with id" in str(raised.value)) == not_found


def test_a_breached_record_with_a_list_of_ids_is_cached_under_its_joined_id(mocker, single_session_fixture):
    client = single_session_fixture
    record = {
        "id": ["abc123", "def456"],
        "name": ["Email collection"],
        "emails": ["user@example.com"],
        "uploadTime": "2024-10-01T01:45:13",
        "evaluation": {"severity": "green"},
    }
    portion = MagicMock()
    portion.sequpdate = 12345
    portion.portion_size = 2
    portion.count = 2
    portion.parse_portion.return_value = [dict(record)]
    mocker.patch.object(
        client,
        "granted_collections",
        return_value=[{"collection": "compromised/breacheddb", "huntingRulesUsed": True}],
    )
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([portion], None))
    fetch = {
        "client": client,
        "first_fetch_time": "3 days",
        "incident_collections": ["compromised/breacheddb"],
        "max_requests": 1,
        "hunting_rules": 0,
        "skip_updated_incidents": True,
        "dedup_lookback_days": 30,
    }
    next_run, incidents = fetch_incidents(last_run={}, **fetch)
    [incident] = incidents
    assert json.loads(incident["rawJSON"])["id"] == "abc123, def456"
    assert "compromised/breacheddb|abc123, def456||2024-10-01T01:45:13" in next_run[GroupIBTIA.FetchIncidentsCommand.SEEN_IDS_KEY]
    # the same record again: known by its joined id, dropped
    portion.parse_portion.return_value = [dict(record)]
    _, again = fetch_incidents(last_run=next_run, **fetch)
    assert again == []


def test_one_breached_credential_in_two_leaks_makes_two_incidents(mocker, single_session_fixture):
    """A breached record's id names the credential, not the exposure: the same id comes back with every
    leak it appears in, so the duplicate cache keys on the id, the leak and the upload time."""
    client = single_session_fixture
    first = {
        "id": ["cred-1"],
        "name": ["cred-1"],
        "leakName": "Leak A",
        "uploadTime": "2026-01-01T00:00:00",
        "evaluation": {"severity": "green"},
    }
    second = {**first, "leakName": "Leak B"}
    portion = MagicMock()
    portion.sequpdate = 12345
    portion.portion_size = 2
    portion.count = 2
    portion.parse_portion.return_value = [dict(first), dict(second)]
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "compromised/breacheddb"}])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", side_effect=lambda **kwargs: ([portion], None))
    fetch = {
        "client": client,
        "first_fetch_time": "3 days",
        "incident_collections": ["compromised/breacheddb"],
        "max_requests": 1,
        "hunting_rules": 0,
        "skip_updated_incidents": True,
        "dedup_lookback_days": 30,
    }
    next_run, incidents = fetch_incidents(last_run={}, **fetch)
    assert [json.loads(incident["rawJSON"])["leakName"] for incident in incidents] == ["Leak A", "Leak B"]
    assert all(GroupIBTIA.FetchIncidentsCommand.DEDUP_ID_KEY not in incident["rawJSON"] for incident in incidents)
    # the same two records re-sent unchanged are dropped; a new upload of one of them is not
    portion.parse_portion.return_value = [dict(first), dict(second), {**first, "uploadTime": "2026-02-01T00:00:00"}]
    _, again = fetch_incidents(last_run=next_run, **fetch)
    assert [json.loads(incident["rawJSON"])["uploadTime"] for incident in again] == ["2026-02-01T00:00:00"]


@pytest.mark.parametrize("mode", ["Off", "Partial", "Full"])
def test_a_breached_record_with_a_password_is_a_high_severity_incident(mocker, single_session_fixture, mode):
    """A breached record that holds a password is a high-severity incident, whatever the masking leaves of it."""
    client = single_session_fixture

    def record(id_: str, passwords: Any) -> dict:
        return {
            "id": [id_],
            "name": [id_],
            "passwords": passwords,
            "uploadTime": "2026-01-01T00:00:00",
            "evaluation": {"severity": "green"},
        }

    with_password, without, empty = record("with", ["P@ssw0rd123"]), record("without", None), record("empty", [""])
    portion = MagicMock()
    portion.sequpdate = 12345
    portion.portion_size = 3
    portion.count = 3
    portion.parse_portion.return_value = [with_password, without, empty]
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "compromised/breacheddb"}])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([portion], None))
    _, incidents = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=["compromised/breacheddb"],
        max_requests=1,
        hunting_rules=0,
        password_mask=GroupIBTIA.PasswordMask(mode),
    )
    raw = [json.loads(incident["rawJSON"]) for incident in incidents]
    assert [(r["id"], r["systemSeverity"]) for r in raw] == [("with", 3), ("without", 1), ("empty", 1)]
    assert [r["hasPassword"] for r in raw] == [True, False, False]
    assert "P@ssw0rd123" not in incidents[0]["rawJSON"] or mode == "Off"


def test_the_duplicate_key_names_the_collection_and_the_record():
    assert FetchIncidentsCommand._dedup_id("malware/cnc", {"id": "x-1", "leakName": "ignored"}) == "malware/cnc|x-1"
    assert (
        FetchIncidentsCommand._dedup_id("compromised/breacheddb", {"id": "b-1", "uploadTime": "t"})
        == "compromised/breacheddb|b-1||t"
    )
    assert (
        FetchIncidentsCommand._dedup_id("suspicious_ip/open_proxy", {"id": "198.51.100.10", "port": 0})
        == "suspicious_ip/open_proxy|198.51.100.10|0"
    )


SUSPICIOUS_ADDRESS = "198.51.100.10"
RAW_SCANNER = {
    "id": SUSPICIOUS_ADDRESS,
    "ipv4": {"ip": SUSPICIOUS_ADDRESS, "asn": "AS64500", "countryCode": "US", "countryName": None},
    "ipv6": None,
    "categories": ["Web scanning"],
    "sources": ["example-honeypot"],
    "dateFirstSeen": "2026-10-01T00:00:00Z",
    "dateLastSeen": "2026-10-10T00:00:00Z",
    "evaluation": {"admiraltyCode": "C3", "credibility": 50, "reliability": 50, "severity": "green", "tlp": "white", "ttl": 15},
}
RAW_TOR_NODE = {k: v for k, v in RAW_SCANNER.items() if k not in ("ipv6", "categories")}
RAW_VPN = {
    "id": SUSPICIOUS_ADDRESS,
    "ipv4": {"ip": SUSPICIOUS_ADDRESS, "asn": "AS64500", "countryCode": "US", "countryName": None, "provider": None},
    "names": ["Example VPN"],
    "types": ["commercial"],
    "source": "example-harvester",
    "sources": ["example-harvester"],
    "dateFirstSeen": "2026-10-01T00:00:00Z",
    "dateLastSeen": "2026-10-10T00:00:00Z",
    "evaluation": {"admiraltyCode": "A2", "credibility": 80, "reliability": 90, "severity": "green", "tlp": "amber", "ttl": 2},
}
RAW_OPEN_PROXY = {
    "id": SUSPICIOUS_ADDRESS,
    "ipv4": {"ip": SUSPICIOUS_ADDRESS, "countryCode": "US", "countryName": None, "asn": None, "provider": None},
    "port": 8080,
    "type": "http",
    "anonymous": "elite",
    "source": "example-list",
    "sources": ["example-list"],
    "dateFirstSeen": "2026-10-01T00:00:00Z",
    "dateLastSeen": "2026-10-10T00:00:00Z",
    "dateDetected": "2026-10-01T00:00:00Z",
    "evaluation": {"admiraltyCode": "C3", "credibility": 50, "reliability": 50, "severity": "green", "tlp": "white", "ttl": 15},
}
CNC_ID = "c2" * 20
RAW_CNC = {
    "id": CNC_ID,
    "cnc": "c2.example.com",
    "domain": "c2.example.com",
    "url": None,
    "ipv4": [{"ip": "203.0.113.7"}],
    "malwareList": [{"id": "m-1", "name": "ExampleBot"}],
    "dateFirstSeen": "2026-10-01T00:00:00+00:00",
    "dateDetected": "2026-10-01T00:00:00+00:00",
    "dateLastSeen": "2026-10-09T00:00:00+00:00",
    "evaluation": {"severity": "red", "tlp": "amber"},
}
PHISHING_GROUP_ID = "fe" * 32
RAW_PHISHING_GROUP = {
    "id": PHISHING_GROUP_ID,
    "domain": "login.example.test",
    "domainInfo": {"domain": "login.example.test", "domainPuny": "login.example.test", "registrar": None},
    "brand": "Example Bank",
    "objective": ["Login harvest"],
    "phishing": [{"url": "https://login.example.test/signin", "ip": {"ip": "192.0.2.44"}}],
    "ip": [{"ip": "192.0.2.44", "countryCode": "Default", "countryName": "Exampleland", "provider": "Example Hosting"}],
    "date": {
        "added": "2026-10-01T00:00:00+00:00",
        "detected": "2026-10-01T00:00:00+00:00",
        "updated": "2026-10-02T00:00:00+00:00",
    },
    "falsePositive": False,
    "whitelist": False,
    "evaluation": {"admiraltyCode": "C3", "credibility": 50, "reliability": 50, "severity": "red", "tlp": "amber", "ttl": 0},
}


def _fetch_raw_pages(
    mocker, client, pages: dict[str, list[dict]], last_run: dict, skip_updated_incidents: bool = True, **settings: Any
):
    """One fetch-incidents run over raw records, one page per collection, parsed by ciaops."""
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": c} for c in pages])
    mocker.patch.object(
        GroupIBTIA.FetchIncidentsCommand,
        "_open_feed",
        side_effect=lambda collection_name, **kwargs: (
            [Parser({"count": len(pages[collection_name]), "items": pages[collection_name], "seqUpdate": 300}, [], [])],
            None,
        ),
    )
    return fetch_incidents(
        client=client,
        last_run=last_run,
        first_fetch_time="3 days",
        incident_collections=list(pages),
        max_requests=1,
        hunting_rules=0,
        skip_updated_incidents=skip_updated_incidents,
        dedup_lookback_days=30,
        **settings,
    )


def test_one_address_in_two_suspicious_ip_collections_makes_two_incidents(mocker, single_session_fixture):
    """The address is the record id of every suspicious_ip/* collection: the scanner incident of an
    address does not hide its open-proxy listing."""
    client = single_session_fixture
    first_run, scanner = _fetch_raw_pages(mocker, client, {"suspicious_ip/scanner": [RAW_SCANNER]}, {})
    _, proxy = _fetch_raw_pages(mocker, client, {"suspicious_ip/open_proxy": [RAW_OPEN_PROXY]}, first_run)
    assert [incident["name"] for incident in scanner + proxy] == [
        "Suspicious IP Scanner: 198.51.100.10",
        "Suspicious IP Open Proxy: 198.51.100.10:8080",
    ]


def test_each_port_of_an_open_proxy_is_its_own_incident(mocker, single_session_fixture):
    """An open proxy address can have several listings, each with its port, and the record key is (id, port)."""
    client = single_session_fixture
    first_run, first = _fetch_raw_pages(mocker, client, {"suspicious_ip/open_proxy": [RAW_OPEN_PROXY]}, {})
    other_ports = [{**RAW_OPEN_PROXY, "port": 3128}, {**RAW_OPEN_PROXY, "port": 0}, RAW_OPEN_PROXY]
    _, second = _fetch_raw_pages(mocker, client, {"suspicious_ip/open_proxy": other_ports}, first_run)
    assert [incident["name"] for incident in first + second] == [
        "Suspicious IP Open Proxy: 198.51.100.10:8080",
        "Suspicious IP Open Proxy: 198.51.100.10:3128",
        "Suspicious IP Open Proxy: 198.51.100.10:0",
    ]
    assert [json.loads(incident["rawJSON"])["port"] for incident in second] == [3128, 0]


@pytest.mark.parametrize("embedded, fingerprint", [(True, {}), (False, {}), (True, {"first_fetch_time": "3 days"})])
def test_a_cache_of_bare_record_ids_still_hides_the_records_it_names(mocker, single_session_fixture, embedded, fingerprint):
    """A cache of bare ids still hides the records of a collection keyed by id alone; a bare address takes the key of
    the one suspicious_ip/* collection the previous run read."""
    added = time.time() - 3600
    cursors = {"malware/cnc": "100", "suspicious_ip/tor_node": "100"}
    legacy = {
        **({"last_fetch": cursors} if embedded else cursors),
        **fingerprint,
        GroupIBTIA.FetchIncidentsCommand.SEEN_IDS_KEY: {CNC_ID: added, SUSPICIOUS_ADDRESS: added},
    }
    pages = {"malware/cnc": [RAW_CNC], "suspicious_ip/tor_node": [RAW_TOR_NODE], "suspicious_ip/vpn": [RAW_VPN]}
    next_run, incidents = _fetch_raw_pages(mocker, single_session_fixture, pages, legacy)
    assert [incident["name"] for incident in incidents] == [f"Suspicious IP VPN: {SUSPICIOUS_ADDRESS}"]
    assert next_run[GroupIBTIA.FetchIncidentsCommand.SEEN_IDS_KEY] == {
        CNC_ID: added,
        f"suspicious_ip/tor_node|{SUSPICIOUS_ADDRESS}": added,
        f"suspicious_ip/vpn|{SUSPICIOUS_ADDRESS}": pytest.approx(time.time(), abs=60),
    }


@pytest.mark.parametrize(
    "previous, pages",
    [
        (
            ["suspicious_ip/tor_node", "suspicious_ip/scanner"],
            {"suspicious_ip/tor_node": [RAW_TOR_NODE], "suspicious_ip/scanner": [RAW_SCANNER]},
        ),
        (["suspicious_ip/open_proxy"], {"suspicious_ip/open_proxy": [RAW_OPEN_PROXY]}),
    ],
)
@pytest.mark.parametrize("fingerprint", [{}, {"first_fetch_time": "3 days"}])
def test_a_bare_address_that_names_no_single_record_hides_nothing(mocker, single_session_fixture, previous, pages, fingerprint):
    """A bare address the previous run could have cached from several suspicious_ip/* collections, or from
    any port of an open proxy, would hide records it never named: it is dropped and each record comes back once."""
    added = time.time() - 3600
    legacy = {
        "last_fetch": dict.fromkeys(previous, "100"),
        **fingerprint,
        GroupIBTIA.FetchIncidentsCommand.SEEN_IDS_KEY: {SUSPICIOUS_ADDRESS: added},
    }
    next_run, incidents = _fetch_raw_pages(mocker, single_session_fixture, pages, legacy)
    assert [json.loads(incident["rawJSON"])["gibType"] for incident in incidents] == list(pages)
    assert set(next_run[GroupIBTIA.FetchIncidentsCommand.SEEN_IDS_KEY]) == {
        FetchIncidentsCommand._dedup_id(collection, record) for collection, records in pages.items() for record in records
    }


def test_a_record_that_fails_to_build_is_not_remembered_as_seen(mocker, single_session_fixture):
    """A record skipped because it could not be built made no incident: the next version of it the API
    serves still gets one, while the record built next to it is remembered."""
    client = single_session_fixture
    mocker.patch.object(GroupIBTIA.demisto, "error")
    build = GroupIBTIA.IncidentBuilder.build
    unbuildable = {CNC_ID}

    def build_or_fail(builder, collection_name, record, hunting_rules_applied=None):
        if record.get("id") in unbuildable:
            raise DemistoException(f"record {record['id']} cannot be built")
        return build(builder, collection_name, record, hunting_rules_applied)

    mocker.patch.object(GroupIBTIA.IncidentBuilder, "build", build_or_fail)
    other = {**RAW_CNC, "id": "f" * 40, "cnc": "c3.example.com", "domain": "c3.example.com"}
    first_run, first = _fetch_raw_pages(mocker, client, {"malware/cnc": [RAW_CNC, other]}, {})
    assert [json.loads(incident["rawJSON"])["id"] for incident in first] == [other["id"]]
    assert list(first_run[GroupIBTIA.FetchIncidentsCommand.SEEN_IDS_KEY]) == [f"malware/cnc|{other['id']}"]
    unbuildable.clear()
    _, second = _fetch_raw_pages(mocker, client, {"malware/cnc": [RAW_CNC, other]}, first_run)
    assert [json.loads(incident["rawJSON"])["id"] for incident in second] == [CNC_ID]


def test_a_record_without_any_date_is_remembered_as_seen(mocker, single_session_fixture):
    """A record without any date makes an incident without an occurred time, so the cache holds it like any
    other built record and the next run skips it."""
    dateless = {**RAW_CNC, "dateFirstSeen": None, "dateDetected": None, "dateLastSeen": None}
    first_run, first = _fetch_raw_pages(mocker, single_session_fixture, {"malware/cnc": [dateless]}, {})
    assert [("occurred" in incident, json.loads(incident["rawJSON"])["id"]) for incident in first] == [(False, CNC_ID)]
    assert list(first_run[GroupIBTIA.FetchIncidentsCommand.SEEN_IDS_KEY]) == [f"malware/cnc|{CNC_ID}"]
    _, second = _fetch_raw_pages(mocker, single_session_fixture, {"malware/cnc": [dateless]}, first_run)
    assert second == []


def test_a_cache_entry_past_the_lookback_hides_nothing(mocker, single_session_fixture):
    """The cache is pruned before the first page is filtered: an entry older than 'Deduplication lookback (days)'
    hides no record on the run that finds it expired, and leaves the cache on that run whatever is built."""
    expired = time.time() - 31 * 86_400
    other = f"malware/cnc|{'f' * 40}"
    last_run = {GroupIBTIA.FetchIncidentsCommand.SEEN_IDS_KEY: {f"malware/cnc|{CNC_ID}": expired, other: expired}}
    next_run, incidents = _fetch_raw_pages(mocker, single_session_fixture, {"malware/cnc": [RAW_CNC]}, last_run)
    assert [json.loads(incident["rawJSON"])["id"] for incident in incidents] == [CNC_ID]
    assert next_run[GroupIBTIA.FetchIncidentsCommand.SEEN_IDS_KEY] == {
        f"malware/cnc|{CNC_ID}": pytest.approx(time.time(), abs=60)
    }
    next_run, incidents = _fetch_raw_pages(mocker, single_session_fixture, {"malware/cnc": []}, last_run)
    assert (incidents, next_run[GroupIBTIA.FetchIncidentsCommand.SEEN_IDS_KEY]) == ([], {})


@pytest.mark.parametrize("flag", ["falsePositive", "whitelist"])
def test_a_flagged_phishing_group_reaches_the_pre_processing_rule_only_when_the_setting_says_so(
    mocker, single_session_fixture, flag
):
    """With "Pass flagged phishing groups to the pre-processing rule" on, a flagged group goes to GIB Rule All Types
    (with deduplication on, only a group that already has an incident); off, it is dropped at fetch."""
    client = single_session_fixture
    first_run, first = _fetch_raw_pages(mocker, client, {"attacks/phishing_group": [RAW_PHISHING_GROUP]}, {})
    assert len(first) == 1
    flagged = [{**RAW_PHISHING_GROUP, flag: True}, {**RAW_PHISHING_GROUP, "id": "f" * 64, flag: True}]

    def handed_on(pages: list[dict], last_run: dict = first_run, **settings: Any) -> list[str]:
        _, incidents = _fetch_raw_pages(mocker, client, {"attacks/phishing_group": pages}, last_run, **settings)
        return [json.loads(incident["rawJSON"])["id"] for incident in incidents]

    assert handed_on(flagged, pass_flagged_phishing_groups=True) == [PHISHING_GROUP_ID]
    assert handed_on(flagged, {}, pass_flagged_phishing_groups=True) == []
    assert handed_on(flagged, pass_flagged_phishing_groups=True, skip_updated_incidents=False) == [PHISHING_GROUP_ID, "f" * 64]
    assert handed_on(flagged, pass_flagged_phishing_groups=False) == []
    assert handed_on(flagged, pass_flagged_phishing_groups=False, skip_updated_incidents=False) == []
    assert handed_on(flagged) == []
    assert handed_on([RAW_PHISHING_GROUP], pass_flagged_phishing_groups=True) == []


@pytest.mark.parametrize("value, expected", [(None, False), ("", False), (True, True), ("false", False), ("true", True)])
def test_main_reads_the_flagged_phishing_group_setting(mocker, value, expected):
    """Off unless set: a flagged group handed on opens an incident wherever GIB Rule All Types does not run."""
    params = {
        "url": "https://example.com",
        "credentials": {"identifier": "u", "password": "p"},
        "incident_collections": ["attacks/phishing_group"],
        "first_fetch": "3 days",
    }
    if value is not None:
        params["pass_flagged_phishing_groups"] = value
    mocker.patch.object(GroupIBTIA.demisto, "params", return_value=params)
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="fetch-incidents")
    mocker.patch.object(GroupIBTIA.demisto, "getLastRun", return_value={})
    mocker.patch.object(GroupIBTIA.demisto, "incidents")
    mocker.patch.object(GroupIBTIA.demisto, "setLastRun")
    mocker.patch.object(GroupIBTIA, "return_error", side_effect=AssertionError("return_error is not called"))
    fetcher = mocker.patch.object(GroupIBTIA, "FetchIncidentsCommand")
    fetcher.return_value.run.return_value = ({}, [])
    GroupIBTIA.main()
    assert fetcher.call_args.args[1].pass_flagged_phishing_groups is expected
    assert Settings.from_params(params).pass_flagged_phishing_groups is expected
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        blocks = yml_file.read().split("\n- ")
    [block] = [block for block in blocks if "\n  name: pass_flagged_phishing_groups\n" in block]
    assert '  defaultvalue: "false"' in block


def _cnc_page(seq: int, record_id: str) -> MagicMock:
    page = MagicMock()
    page.sequpdate = seq
    page.portion_size = 1
    page.count = 1
    page.parse_portion.return_value = [
        {"id": record_id, "name": record_id, "cnc": "c2.example", "dateFirstSeen": "2026-01-01T00:00:00+00:00"}
    ]
    return page


def test_a_refused_collection_does_not_stop_the_others(mocker, single_session_fixture):
    """A collection whose read fails keeps its cursor and is reported in the instance health; the other
    collections are fetched and their cursors move on."""
    client = single_session_fixture
    collections = ["osi/public_leak", "malware/cnc"]
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": c} for c in collections])

    def generator(collection_name, **kwargs):
        if collection_name == "osi/public_leak":
            raise GroupIBTIA.ConnectionException("Request to https://example.com failed: connection reset")
        return [_cnc_page(200, "cnc-1")], None

    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", side_effect=generator)
    health = mocker.patch.object(GroupIBTIA.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIBTIA.demisto, "error")
    last_run = {"last_fetch": {"osi/public_leak": "100", "malware/cnc": "150"}}
    next_run, incidents = fetch_incidents(
        client=client,
        last_run=last_run,
        first_fetch_time="3 days",
        incident_collections=collections,
        max_requests=1,
        hunting_rules=0,
    )
    assert [json.loads(i["rawJSON"])["id"] for i in incidents] == ["cnc-1"]
    assert next_run["last_fetch"] == {"osi/public_leak": "100", "malware/cnc": "200"}
    [call] = health.call_args_list
    assert "osi/public_leak" in call.args[0]
    assert call.kwargs == {"is_error": True}


def test_a_page_refused_mid_fetch_keeps_the_pages_before_it(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "malware/cnc"}])

    def pages():
        yield _cnc_page(200, "cnc-1")
        raise GroupIBTIA.ConnectionException(SERVER_ERROR)

    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=(pages(), 150))
    mocker.patch.object(GroupIBTIA.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIBTIA.demisto, "error")
    next_run, incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": {"malware/cnc": "150"}},
        first_fetch_time="3 days",
        incident_collections=["malware/cnc"],
        max_requests=3,
        hunting_rules=0,
    )
    assert [json.loads(i["rawJSON"])["id"] for i in incidents] == ["cnc-1"]
    assert next_run["last_fetch"]["malware/cnc"] == "200"


def test_a_fetch_every_collection_of_which_was_refused_fails(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "malware/cnc"}])
    mocker.patch.object(
        GroupIBTIA.FetchIncidentsCommand, "_open_feed", side_effect=GroupIBTIA.ConnectionException(ACCOUNT_REFUSAL)
    )
    mocker.patch.object(GroupIBTIA.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIBTIA.demisto, "error")
    with pytest.raises(DemistoException, match="The fetch of malware/cnc failed: HTTP 403"):
        fetch_incidents(
            client=client,
            last_run={},
            first_fetch_time="3 days",
            incident_collections=["malware/cnc"],
            max_requests=1,
            hunting_rules=0,
        )


def test_the_duplicate_cache_is_dropped_when_the_built_in_deduplication_is_off(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "malware/cnc"}])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([], None))
    next_run, _ = fetch_incidents(
        client=client,
        last_run={GroupIBTIA.FetchIncidentsCommand.SEEN_IDS_KEY: {"old": 1}},
        first_fetch_time="3 days",
        incident_collections=["malware/cnc"],
        max_requests=1,
        hunting_rules=0,
        skip_updated_incidents=False,
    )
    assert next_run[GroupIBTIA.FetchIncidentsCommand.SEEN_IDS_KEY] == {}


def test_a_reputation_read_keeps_every_record_of_a_dated_page(mocker, single_session_fixture):
    client = single_session_fixture
    page = MagicMock()
    page.parse_portion.return_value = [{"id": "a", "dateLastSeen": "2026-01-01"}, {"id": "b", "dateLastSeen": "2026-02-01"}]
    mocker.patch.object(client, "search_collection", return_value=iter([page]))
    out = evidence(client)._read(path="ioc/primary", value="example.com", keys={"dateLastSeen": "dateLastSeen"})
    assert [record["id"] for record in out] == ["a", "b"]


def test_phishing_group_tables_become_grid_rows_and_the_countries_one_string():
    record = {
        "id": "p1",
        "name": "phish.test",
        "detected": "2026-01-01T00:00:00+00:00",
        "evaluation": {"severity": "red"},
        "phishing_ip": {
            "ip": ["198.51.100.1", "198.51.100.2"],
            "countryCode": ["UA", "US"],
            "countryName": ["Ukraine", "United States"],
            "provider": ["Hoster A", "Hoster B"],
        },
        "phishing_kit_table": {"name": ["kit-1"], "email": ["drop@example.com"]},
        "indicators": {"url": ["http://phish.test/login"]},
    }
    raw = json.loads(IncidentBuilder().build("attacks/phishing_group", record)["rawJSON"])
    assert raw["phishing_ip"] == [
        {"ip": "198.51.100.1", "countrycode": "UA", "countryname": "Ukraine", "provider": "Hoster A"},
        {"ip": "198.51.100.2", "countrycode": "US", "countryname": "United States", "provider": "Hoster B"},
    ]
    assert raw["phishing_kit_table"] == [{"name": "kit-1", "email": "drop@example.com"}]
    assert raw["countryName"] == "Ukraine, United States"


def test_cve_indicators_take_modified_from_date_modified():
    assert MAPPING["osi/vulnerability"]["indicators"]["dateModified"] == "dateModified"
    assert INDICATORS_TYPES["osi/vulnerability"]["add_fields_types"]["id"]["dateModified"] == "cvemodified"
    feed = {
        "evaluation": {"severity": "red"},
        "indicators": {"id": "CVE-2021-1", "dateModified": "2024-01-02T00:00:00+00:00", "description": "d", "cvss_score": 9.8},
    }
    [entry] = IndicatorBuilder(create_relationships=False).results(feed, "osi/vulnerability")
    [cve] = next(value for key, value in entry.to_context()["EntryContext"].items() if key.startswith("CVE"))
    assert cve["Modified"] == "2024-01-02T00:00:00+00:00"


def test_a_record_that_cannot_be_built_is_skipped_and_logged(mocker, single_session_fixture):
    client = single_session_fixture
    good = _account_record()
    bad = {key: value for key, value in _account_record().items() if key != "name"}
    bad["id"] = "acc-2"
    portion = MagicMock()
    portion.sequpdate = 1
    portion.portion_size = 2
    portion.count = 2
    portion.parse_portion.return_value = [bad, good]
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "compromised/account_group"}])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([portion], None))
    error = mocker.patch.object(GroupIBTIA.demisto, "error")
    _, incidents = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=["compromised/account_group"],
        max_requests=1,
        hunting_rules=0,
    )
    assert [json.loads(incident["rawJSON"])["id"] for incident in incidents] == ["acc-1"]
    [message] = [call.args[0] for call in error.call_args_list]
    assert "'acc-2' skipped" in message
    assert "P@ssw0rd123" not in message


def test_a_page_without_ids_counts_as_a_request_and_moves_the_cursor(mocker, single_session_fixture):
    """A page whose records carry no id counts against 'Number of requests per collection' and moves the cursor past
    it, so it is not read again on the next run."""
    client = single_session_fixture
    empty = MagicMock()
    empty.sequpdate = 7
    empty.portion_size = 1
    empty.count = 1
    empty.parse_portion.return_value = [{key: value for key, value in _account_record().items() if key != "id"}]
    full = MagicMock()
    full.sequpdate = 8
    full.portion_size = 1
    full.count = 1
    full.parse_portion.return_value = [_account_record()]
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "compromised/account_group"}])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([empty, full], None))
    next_run, incidents = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=["compromised/account_group"],
        max_requests=1,
        hunting_rules=0,
    )
    assert incidents == []
    assert full.parse_portion.call_count == 0
    assert next_run["last_fetch"]["compromised/account_group"] == "7"


def test_date_conversion_touches_bare_calendar_dates_only():
    assert IncidentBuilder._date_conversion("2026-01-02") == "2026-01-02T00:00:00"
    assert IncidentBuilder._date_conversion("2026-01-02T03:04:05+00:00") is None
    assert IncidentBuilder._date_conversion("") is None
    assert IncidentBuilder._date_conversion(None) is None


def test_a_free_text_id_lookup_returns_the_record_with_that_id_only(mocker, single_session_fixture):
    client = single_session_fixture
    assert GroupIBTIA.COLLECTIONS["suspicious_ip/tor_node"].lookup_route == "text query"
    page = MagicMock()
    page.parse_portion.return_value = [
        {"id": "198.51.100.1", "name": "198.51.100.1"},
        {"id": "198.51.100.9", "name": "198.51.100.9"},
    ]
    mocker.patch.object(client, "search_collection", return_value=[page])
    assert read_record(client, "suspicious_ip/tor_node", "198.51.100.9")["id"] == "198.51.100.9"
    with pytest.raises(DemistoException, match="No record with id '198.51.100.7' was found in suspicious_ip/tor_node"):
        lookup(client, "suspicious_ip/tor_node", {"id": "198.51.100.7"})


def test_a_blank_source_reliability_is_none():
    assert Settings._source_reliability("   ") is None
    assert Settings._source_reliability(None) is None


def test_main_reports_a_refused_group_ib_request_without_a_traceback(mocker):
    from ciaops.exception import ConnectionException

    params = {"url": "https://example.com", "credentials": {"identifier": "u", "password": "p"}}
    mocker.patch.object(GroupIBTIA.demisto, "params", return_value=params)
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value={})
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="gibti-get-available-collections")
    mocker.patch.object(GroupIBTIA, "Client", autospec=True)
    mocker.patch.object(GroupIBTIA.AvailableCollectionsCommand, "run", side_effect=ConnectionException(ACCOUNT_REFUSAL))
    error = mocker.patch.object(GroupIBTIA, "return_error")
    GroupIBTIA.main()
    message = error.call_args.args[0]
    assert ACCOUNT_REFUSAL in message
    assert "Traceback" not in message


def test_a_failed_grants_read_fails_only_the_collection_that_needs_it(mocker, single_session_fixture):
    """With Hunting Rules on, a failed grants read is the refusal of the collection that asked for it; the others are fetched."""
    client = single_session_fixture
    client.rate_limit_delay = 0
    feed = _UpdateFeed({"malware/cnc": [_tied_record("malware/cnc", 1, 410)]})
    mocker.patch.object(client.poller, "send_request", side_effect=feed.send_request)
    mocker.patch.object(
        client,
        "granted_collections",
        side_effect=GroupIBTIA.ConnectionException(
            "Retries exhausted for https://api.example.com/api/v2/user/granted_collections: too many 503 error responses"
        ),
    )
    health = mocker.patch.object(GroupIBTIA.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIBTIA.demisto, "error")
    next_run, incidents = fetch_incidents(
        client=client,
        last_run={
            "last_fetch": {"malware/cnc": "400", "suspicious_ip/scanner": "500"},
            "boundary_keys": {"suspicious_ip/scanner": ["kept"]},
        },
        first_fetch_time="3 days",
        incident_collections=["malware/cnc", "suspicious_ip/scanner"],
        max_requests=1,
        hunting_rules=True,
    )
    assert [json.loads(incident["rawJSON"])["id"] for incident in incidents] == [f"{1:040x}"]
    assert next_run["last_fetch"]["malware/cnc"] != "400"
    assert next_run["last_fetch"]["suspicious_ip/scanner"] == "500"
    assert next_run["boundary_keys"]["suspicious_ip/scanner"] == ["kept"]
    assert feed.sent_to("suspicious_ip/scanner/updated") == []
    [call] = health.call_args_list
    assert "The fetch of suspicious_ip/scanner failed: Retries exhausted" in call.args[0]


def test_main_names_an_unknown_command(mocker):
    params = {"url": "https://example.com", "credentials": {"identifier": "u", "password": "p"}}
    mocker.patch.object(GroupIBTIA.demisto, "params", return_value=params)
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value={})
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="gibti-no-such-command")
    mocker.patch.object(GroupIBTIA, "Client", autospec=True)
    error = mocker.patch.object(GroupIBTIA, "return_error")
    GroupIBTIA.main()
    assert "Command gibti-no-such-command is not implemented" in error.call_args.args[0]


@pytest.mark.parametrize("collection", ["suspicious_ip/vpn", "suspicious_ip/scanner"])
def test_suspicious_ip_incidents_are_named_after_the_ip(collection):
    record = {
        "id": "0123abcd",
        "name": "198.51.100.3",
        "dateFirstSeen": "2026-01-01T00:00:00+00:00",
        "evaluation": {"severity": "green"},
        "indicators": {},
    }
    assert MAPPING[collection]["name"] == "ipv4.ip"
    built = IncidentBuilder().build(collection, record)
    assert "198.51.100.3" in built["name"]
    assert "0123abcd" not in built["name"]


def test_a_lookup_without_an_id_says_so(single_session_fixture):
    with pytest.raises(DemistoException, match="Argument 'id' is required."):
        lookup(single_session_fixture, "suspicious_ip/vpn", {})


def test_a_fetch_the_api_refuses_is_one_message_with_the_window_hint(mocker, single_session_fixture):
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "compromised/breacheddb"}])

    def refused():
        raise ConnectionException("HTTP 400: Bad Credentials or Wrong request.")
        yield  # pragma: no cover

    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=(refused(), None))
    with pytest.raises(DemistoException, match="shorten the window") as caught:
        fetch_incidents(
            client=client,
            last_run={},
            first_fetch_time="60 days",
            incident_collections=["compromised/breacheddb"],
            max_requests=1,
            hunting_rules=0,
        )
    assert "HTTP 400" in str(caught.value)


def test_a_block_of_nulls_is_no_grid_table():
    record = {
        "id": "p2",
        "name": "phish.test",
        "detected": "2026-01-01T00:00:00+00:00",
        "evaluation": {"severity": "red"},
        "phishing_ip": {"ip": ["198.51.100.1"], "countryCode": [None], "countryName": ["Germany"], "provider": [None]},
        "phishing_kit_table": {"name": [None, [], []], "email": [None, [], {}]},
        "indicators": {"url": ["http://phish.test/login"]},
    }
    raw = json.loads(IncidentBuilder().build("attacks/phishing_group", record)["rawJSON"])
    assert raw["phishing_kit_table"] is None
    assert IncidentBuilder._is_blank([[], [None], {"a": ""}])
    assert not IncidentBuilder._is_blank([[], "x"])
    assert raw["phishing_ip"] == [{"ip": "198.51.100.1", "countrycode": None, "countryname": "Germany", "provider": None}]


def test_a_low_cvss_cve_is_a_bad_lookup_indicator_and_suspicious_in_cve_scoring():
    feed = {"evaluation": {"severity": "green"}, "indicators": {"id": "CVE-2021-2", "description": "d", "cvss_score": 3.1}}
    [entry] = IndicatorBuilder(create_relationships=False).results(feed, "osi/vulnerability")
    [dbot] = next(value for key, value in entry.to_context()["EntryContext"].items() if key.startswith("DBotScore"))
    assert dbot["Score"] == 3
    # the graded rules stay with gibti-cve-scoring
    assert ScoringCommand._cve_verdict({"cvss_score": 3.1}) == 2


def test_local_search_refuses_a_collection_the_pack_has_no_mapping_for(mocker, single_session_fixture):
    """The API grants more collections than the pack reads; one without a mapping is refused before
    any request instead of failing inside the parser."""
    client = single_session_fixture
    search = mocker.patch.object(client, "search_collection")
    with pytest.raises(DemistoException, match="hi/unsupported_collection collection is not supported by gibti-local-search"):
        local_search(client, {"query": "StealerThree", "collection_name": "hi/unsupported_collection"})
    search.assert_not_called()


def test_every_local_search_collection_of_the_yml_has_a_mapping():
    """Every collection gibti-local-search offers is one the pack can parse."""
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        commands = yml_file.read().split("\n  - arguments:\n")
    [command] = [command for command in commands if "\n    name: gibti-local-search\n" in command]
    [argument] = [argument for argument in command.split("\n    - ") if "\n      name: collection_name\n" in argument]
    predefined = argument.split("predefined:\n", 1)[1].splitlines()
    collections = [line[len("      - ") :] for line in itertools.takewhile(lambda line: line.startswith("      - "), predefined)]
    assert len(collections) == 28
    assert set(collections) <= set(MAPPING)


@pytest.mark.parametrize("collection", sorted(GroupIBTIA.TICollections.INFO))
def test_the_page_size_is_the_limit_up_to_the_ciaops_page_limit(collection):
    """The page size ciaops documents for a collection caps the limit and stands in for a missing one."""
    cap = GroupIBTIA.TICollections.get_page_limit(collection)
    assert Client.page_size(collection, None) == cap
    assert Client.page_size(collection, 1) == 1
    assert Client.page_size(collection, 100_000) == (cap if cap is not None else 100_000)


def test_fetch_and_search_send_the_capped_page_size(mocker, single_session_fixture):
    client = single_session_fixture
    client.limit = 100_000
    generator = mocker.patch.object(client.poller, "create_update_generator", return_value=iter([]))
    mocker.patch.object(client.poller, "get_seq_update_dict", return_value={"osi/public_leak": 5})
    pages, _ = open_feed(
        client,
        collection_name="osi/public_leak",
        hunting_rules=None,
        enable_probable_corporate_access=False,
        unique=False,
        combolist=False,
        cursor="5",
        first_fetch_time="3 days",
    )
    list(pages)
    assert generator.call_args.kwargs["request_params"].limit == GroupIBTIA.TICollections.get_page_limit("osi/public_leak")
    client.search_collection("malware/malware", query="x", limit=100_000)
    assert generator.call_args.kwargs["request_params"].limit == GroupIBTIA.TICollections.get_page_limit("malware/malware")


@pytest.mark.parametrize(
    "collection, hunting_rules, expected",
    [
        ("compromised/account_group", 0, True),
        ("compromised/spd", 0, True),
        ("compromised/breacheddb", 0, True),
        ("attacks/ddos", 0, True),
        ("malware/cnc", 0, False),
        ("attacks/deface", 1, False),
    ],
)
def test_server_scoped_collections_are_marked_as_fetched_with_hunting_rules(
    mocker, single_session_fixture, collection, hunting_rules, expected
):
    """compromised/*, darkweb/forums, the leak feeds and attacks/ddos are filtered by the customer's hunting rules on every
    request the integration sends."""
    client = single_session_fixture
    page = MagicMock()
    page.sequpdate = 200
    page.portion_size = 1
    page.count = 1
    page.parse_portion.return_value = [{"id": "r-1", "name": "r-1"}]
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": collection}])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([page], None))
    built = mocker.patch.object(GroupIBTIA.IncidentBuilder, "build")
    fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=[collection],
        max_requests=1,
        hunting_rules=hunting_rules,
    )
    assert built.call_args.kwargs["hunting_rules_applied"] is expected


@pytest.mark.parametrize(
    "advisory", ["UNPATCHED_CVE_2099_0001.NASL", "RHSA-2099:1234", "MS:CVE-2099-0001", "WPVDB-ID:abc", "CVE-2026"]
)
def test_an_advisory_that_is_not_a_cve_is_no_cve_indicator(advisory):
    """osi/vulnerability carries Nessus, Red Hat, Microsoft and WordPress advisories under their own ids;
    only a CVE id is a CVE."""
    assert _lookup({"id": advisory, "cvss_score": 9.8}, "osi/vulnerability") == []
    assert _related("osi/vulnerability", {"id": advisory}) is None
    [cve] = _lookup({"id": "CVE-2099-12345", "cvss_score": 9.8}, "osi/vulnerability")
    assert cve.indicator.id == "CVE-2099-12345"


def test_an_occurred_time_with_an_offset_is_converted_to_utc(mocker):
    """dateparser keeps the offset of the string; the incident's occurred time is UTC."""
    mocker.patch.object(GroupIBTIA, "dateparser_parse", side_effect=lambda date_string: datetime.fromisoformat(date_string))
    fields = GroupIBTIA.COLLECTIONS["attacks/phishing_group"].occurred_fields
    first = fields[0]
    assert (
        IncidentBuilder._occurred("attacks/phishing_group", {"id": "p", first: "2026-01-01T12:00:00+03:00"})
        == "2026-01-01T09:00:00Z"
    )


def test_the_year_one_placeholder_is_no_occurred_time(mocker):
    """An unknown date arrives as 0001-01-01; the next date field decides."""
    mocker.patch.object(GroupIBTIA, "dateparser_parse", side_effect=lambda date_string: datetime.fromisoformat(date_string))
    fields = GroupIBTIA.COLLECTIONS["attacks/phishing_group"].occurred_fields
    assert fields == ("detected", "updated")
    record = {"id": "p", fields[0]: "0001-01-01T00:00:00+00:00", fields[1]: "2026-02-01T00:00:00+00:00"}
    assert IncidentBuilder._occurred("attacks/phishing_group", record) == "2026-02-01T00:00:00Z"


def test_an_ipv6_scanner_incident_is_named_after_its_address():
    """ipv4 is null on the IPv6 scanner records, whose id is their address."""
    assert (
        IncidentBuilder._name("suspicious_ip/scanner", {"id": "2001:db8::5", "name": None})
        == "Suspicious IP Scanner: 2001:db8::5"
    )


def test_the_instance_test_checks_the_credentials_not_the_cache(mocker, single_session_fixture):
    """The grant list is cached for five minutes; Test asks the API again, since the key or the URL may have changed."""
    client = single_session_fixture
    mocker.patch.object(GroupIBTIA.Client, "_cached_grants", return_value=[{"collection": "malware/cnc"}])
    mocker.patch.object(GroupIBTIA.PreProcessRuleScripts, "fill", return_value=[])
    send = mocker.patch.object(
        client.poller, "send_request", side_effect=GroupIBTIA.ConnectionException("HTTP 401: Bad Credentials.")
    )
    with pytest.raises(GroupIBTIA.ConnectionException, match="HTTP 401"):
        GroupIBTIA.TestModuleCommand(client).run()
    send.side_effect = None
    send.return_value = [{"collection": "malware/cnc"}]
    assert GroupIBTIA.TestModuleCommand(client).run() == "ok"
    send.return_value = []
    assert GroupIBTIA.TestModuleCommand(client).run() == "No collections are available; ask Group-IB support to grant them."


def test_only_an_ioc_record_of_the_value_itself_decides_the_verdict(mocker, single_session_fixture):
    """A search hit of ioc/primary that only mentions the value (a URL on the domain, a file record) decides nothing."""
    mentions = {
        "ioc/primary": [
            {
                "type": "network",
                "domain": [{"domain": "evil.example", "riskScore": 90}],
                "url": [{"url": "https://code-host.example/evil/payload", "riskScore": 90}],
            },
            {
                "type": "file",
                "hash": {"md5": "a" * 32, "sha1": None, "sha256": None},
                "riskScore": 100,
                "malwareList": [{"name": "Sample Stealer"}],
            },
        ]
    }
    client = _reputation_client(mocker, single_session_fixture, mentions, {"code-host.example": 0})
    [result] = reputation(client, "domain", {"domain": "code-host.example"})
    assert result.indicator.dbot_score.score == 1
    assert result.indicator.malware_family is None
    assert result.raw_response["collections"] == []
    listed = {"ioc/primary": [*mentions["ioc/primary"], {"type": "network", "domain": [{"domain": "Code-Host.example"}]}]}
    client = _reputation_client(mocker, single_session_fixture, listed, {"code-host.example": 0})
    [result] = reputation(client, "domain", {"domain": "code-host.example"})
    assert result.indicator.dbot_score.score == 2
    shaped = {"ioc/primary": [{"type": "network", "ip": [{"ip": "203.0.113.5", "riskScore": 90}]}]}
    client = _reputation_client(mocker, single_session_fixture, shaped, {"203.0.113.5": 0})
    [result] = reputation(client, "ip", {"ip": "203.0.113.5"})
    assert result.indicator.dbot_score.score == 2
    # a file is matched by its hash, in either case
    client = _reputation_client(mocker, single_session_fixture, mentions)
    [result] = reputation(client, "file", {"file": "A" * 32})
    assert result.indicator.dbot_score.score == 3
    [result] = reputation(client, "file", {"file": "b" * 32})
    assert result.indicator.dbot_score.score == 0


def test_local_search_reads_no_more_pages_than_asked(mocker, single_session_fixture):
    """Without a cursor the update feed walks the whole collection: the command stops at requests_limit
    instead of reading every page first."""
    client = single_session_fixture
    pulled = []

    def pages():
        for index in range(1, 50):
            page = MagicMock()
            page.parse_portion.return_value = [{"id": f"r{index}", "name": f"r{index}"}]
            page.raw_dict = {"items": [{"seqUpdate": index}]}
            pulled.append(index)
            yield page

    mocker.patch.object(client, "search_collection", return_value=pages())
    result = local_search(client, {"collection_name": "malware/cnc", "query": "x", "requests_limit": "2"})
    assert [entry["id"] for entry in result.outputs] == ["r1", "r2"]
    assert pulled == [1, 2]


def test_local_search_refuses_an_end_date_without_a_start(single_session_fixture):
    """date_to without date_from is refused: the end of a date window is sent only with its start."""
    with pytest.raises(DemistoException, match="date_to needs date_from"):
        local_search(single_session_fixture, {"collection_name": "malware/cnc", "query": "x", "date_to": "2026-01-01"})


@pytest.mark.parametrize("flag", ["falsePositive", "whitelist"])
def test_a_phishing_group_marked_false_positive_or_allow_listed_is_no_incident(mocker, single_session_fixture, flag):
    """With the default settings, a phishing group Group-IB flags as a false positive or allow-listed is dropped at fetch."""
    client = single_session_fixture
    page = MagicMock()
    page.sequpdate = 200
    page.portion_size = 2
    page.count = 2
    record = {"id": "p", "name": "Brand", "detected": "2026-01-01T00:00:00+00:00", "falsePositive": False, "whitelist": False}
    page.parse_portion.return_value = [{**record, "id": "kept"}, {**record, "id": "dropped", flag: True}]
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "attacks/phishing_group"}])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([page], None))
    next_run, incidents = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=["attacks/phishing_group"],
        max_requests=1,
        hunting_rules=0,
    )
    assert [json.loads(i["rawJSON"])["id"] for i in incidents] == ["kept"]
    assert next_run["last_fetch"]["attacks/phishing_group"] == "200"
    assert MAPPING["attacks/phishing_group"][flag] == flag


def test_a_collection_missing_from_the_grant_list_is_fetched_anyway(mocker, single_session_fixture):
    """Feed access is not gated on the grant list; the request for the collection itself decides."""
    client = single_session_fixture
    mocker.patch.object(client, "granted_collections", return_value=[])
    generator = mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([], None))
    fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=["malware/cnc"],
        max_requests=1,
        hunting_rules=0,
    )
    assert generator.call_args.kwargs["collection_name"] == "malware/cnc"


def test_scoring_sends_each_route_only_what_it_scores(mocker, single_session_fixture):
    """scoring/ip scores IPv4 addresses and scoring/domain scores domains: each route is sent only the values it scores."""
    client = single_session_fixture
    ip_scoring = mocker.patch.object(client.poller, "get_ip_scoring", return_value={"items": {"198.51.100.5": {"riskScore": 90}}})
    domain_scoring = mocker.patch.object(client.poller, "get_domain_scoring", return_value={"items": {}})
    results = score_risk(client, "ip", {"ip": "example.com,198.51.100.5,2001:db8::1,192.0.2.0/24"})
    assert [call.args[0] for call in ip_scoring.call_args_list] == ["198.51.100.5"]
    assert results[1].outputs["riskScore"] == 90
    for skipped in (results[0], results[2], results[3]):
        assert "Group-IB scores IPv4 addresses only" in skipped.readable_output
        assert skipped.indicator is None
    results = score_risk(client, "domain", {"domain": "198.51.100.5"})
    domain_scoring.assert_not_called()
    assert "is an IP address" in results[0].readable_output


def test_requests_are_paced_above_one_second_by_default():
    """Group-IB allows one request per second per route; the default pause stays above it."""
    assert GroupIBTIA.Settings.DEFAULT_RATE_LIMIT_DELAY == 1.2
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        blocks = yml_file.read().split("\n- ")
    [block] = [block for block in blocks if "\n  name: rate_limit_delay\n" in block]
    assert '  defaultvalue: "1.2"' in block


# An open_proxy id is the IP, listed again on the same or another port.
_REPEATED_ID_FIELDS = {"suspicious_ip/open_proxy": ("port",)}


class _UpdateFeed:
    """The ``{collection}/updated`` route and ``sequence_list`` behind the real ciaops generator: records above the
    cursor in cursor order, several per seqUpdate, each page answering its last record's cursor."""

    def __init__(self, records: dict[str, list[dict]] | None = None, start_cursors: dict[str, Any] | None = None):
        self.records = {name: sorted(items, key=lambda item: item["seqUpdate"]) for name, items in (records or {}).items()}
        self.start_cursors = start_cursors or {}
        self.requests: list[tuple[str, dict]] = []

    def send_request(self, endpoint, params=None, **kwargs):
        sent = {key: value for key, value in (params or {}).items() if value is not None}
        self.requests.append((endpoint, sent))
        if endpoint == "sequence_list":
            answer = self.start_cursors.get(sent["collection"])
            if isinstance(answer, Exception):
                raise answer
            return {"list": {} if answer is None else {sent["collection"]: answer}}
        collection = endpoint.removesuffix("/updated")
        cursor = int(sent.get("seqUpdate", 0))
        ahead = [item for item in self.records.get(collection, []) if item["seqUpdate"] > cursor]
        page = ahead[: int(sent.get("limit", 100))]
        return {
            "count": len(ahead),
            "items": json.loads(json.dumps(page)),
            "seqUpdate": page[-1]["seqUpdate"] if page else cursor,
        }

    def sent_to(self, endpoint: str) -> list[dict]:
        return [params for name, params in self.requests if name == endpoint]


_EVALUATION = {"admiraltyCode": "A2", "credibility": 80, "reliability": 100, "severity": "red", "tlp": "amber", "ttl": 30}


def _tied_record(collection: str, n: int, seq: int) -> dict:
    """A record of ``collection`` shaped as the API serves it."""
    record_id = f"{n:040x}"
    if collection == "osi/public_leak":
        return {
            "id": record_id,
            "hash": f"{n + 500:040x}",
            "seqUpdate": seq,
            "created": "2026-10-01T09:00:00+03:00",
            "updated": "2026-10-01T09:00:00+03:00",
            "language": "text",
            "size": 21,
            "data": "db_password=example\r\n",
            "evaluation": {**_EVALUATION, "admiraltyCode": "C3", "credibility": 50, "reliability": 50},
            "bind": [{"id": "rule-1", "type": "domain", "key": "example.com", "ruleValue": "example.com"}],
            "linkList": [
                {
                    "link": f"https://paste.example/raw/{n}",
                    "source": "paste.example",
                    "title": "dump",
                    "author": "",
                    "hash": f"{n + 500:040x}",
                    "dateDetected": "2026-10-01T09:00:00+03:00",
                    "datePublished": "2026-10-01T08:00:00+03:00",
                }
            ],
            "matches": {},
        }
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
            "evaluation": _EVALUATION,
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
        "suspicious_ip/open_proxy",
        "suspicious_ip/socks_proxy",
        "suspicious_ip/vpn",
        "suspicious_ip/scanner",
        "attacks/deface",
        "hi/threat",
        "apt/threat",
        "osi/git_repository",
        "osi/vulnerability",
        "attacks/phishing_kit",
    ],
)
def test_the_fetch_asks_no_collection_for_more_than_it_serves(mocker, single_session_fixture, collection):
    """A limit above the page size ciaops documents for the collection is cut to it, and to what the millisecond feeds
    serve."""
    client = single_session_fixture
    client.limit, client.rate_limit_delay = 20000, 0
    feed = _UpdateFeed()
    mocker.patch.object(client.poller, "send_request", side_effect=feed.send_request)
    mocker.patch.object(client, "granted_collections", return_value=[])
    fetch_incidents(
        client=client,
        last_run={"last_fetch": {collection: "5"}},
        first_fetch_time="3 days",
        incident_collections=[collection],
        max_requests=1,
        hunting_rules=0,
    )
    [request] = feed.sent_to(f"{collection}/updated")
    served = GroupIBTIA.BoundaryPages.LARGEST_PAGES.get(collection)
    assert request["limit"] == (served or GroupIBTIA.TICollections.get_page_limit(collection))


@pytest.mark.parametrize(
    "collection", ["compromised/spd", "compromised/breacheddb", "osi/git_repository", "osi/vulnerability", "malware/cnc"]
)
@pytest.mark.parametrize("answer", [GroupIBTIA.ConnectionException(SEQUENCE_LIST_DOWN), None, 0])
def test_a_first_fetch_without_a_start_cursor_waits_for_one(mocker, single_session_fixture, collection, answer):
    """These collections take no date as their start position: the collection is reported, stores no cursor and asks
    sequence_list again on the next run."""
    client = single_session_fixture
    client.rate_limit_delay = 0
    feed = _UpdateFeed(start_cursors={collection: answer, "attacks/ddos": 5})
    mocker.patch.object(client.poller, "send_request", side_effect=feed.send_request)
    mocker.patch.object(client, "granted_collections", return_value=[])
    health = mocker.patch.object(GroupIBTIA.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIBTIA.demisto, "error")
    fetch = {
        "client": client,
        "first_fetch_time": "3 days",
        "incident_collections": [collection, "attacks/ddos"],
        "max_requests": 1,
        "hunting_rules": 0,
    }
    next_run, _ = fetch_incidents(last_run={}, **fetch)
    assert feed.sent_to(f"{collection}/updated") == []
    assert next_run["last_fetch"][collection] is None
    [call] = health.call_args_list
    assert collection in call.args[0]
    assert "cannot start from a date" in call.args[0]
    assert "waits for a sequence_list cursor" in call.args[0]
    feed.start_cursors[collection] = 1_760_000_000_000_000
    fetch_incidents(last_run=next_run, **fetch)
    [request] = feed.sent_to(f"{collection}/updated")
    assert request["seqUpdate"] == 1_760_000_000_000_000
    assert "df" not in request


def test_a_first_fetch_change_whose_only_collection_lacks_a_start_cursor_fails_naming_sequence_list(
    mocker, single_session_fixture
):
    """The restart after a changed "Incidents first fetch" asks sequence_list the same way."""
    client = single_session_fixture
    feed = _UpdateFeed(start_cursors={"compromised/spd": GroupIBTIA.ConnectionException(SEQUENCE_LIST_DOWN)})
    mocker.patch.object(client.poller, "send_request", side_effect=feed.send_request)
    mocker.patch.object(client, "granted_collections", return_value=[])
    with pytest.raises(DemistoException, match="sequence_list"):
        fetch_incidents(
            client=client,
            last_run={"first_fetch_time": "3 days", "last_fetch": {"compromised/spd": "777"}},
            first_fetch_time="10 days",
            incident_collections=["compromised/spd"],
            max_requests=1,
            hunting_rules=0,
        )
    assert feed.sent_to("compromised/spd/updated") == []


def test_a_start_cursor_of_zero_is_reported_with_its_remedy(mocker, single_session_fixture):
    """sequence_list answers 0 for some collections at older dates; the health
    message names that answer and the setting that gives the collection a cursor."""
    client = single_session_fixture
    client.rate_limit_delay = 0
    feed = _UpdateFeed(start_cursors={"compromised/spd": 0, "attacks/ddos": 5})
    mocker.patch.object(client.poller, "send_request", side_effect=feed.send_request)
    mocker.patch.object(client, "granted_collections", return_value=[])
    health = mocker.patch.object(GroupIBTIA.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIBTIA.demisto, "error")
    next_run, _ = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="2026-03-01",
        incident_collections=["compromised/spd", "attacks/ddos"],
        max_requests=1,
        hunting_rules=0,
    )
    [call] = health.call_args_list
    assert "compromised/spd is not fetched yet: sequence_list answered 0 for 2026-03-01;" in call.args[0]
    assert "A later 'Incidents first fetch' date gives it a cursor" in call.args[0]
    assert "changing the setting restarts every selected collection from the new date" in call.args[0]
    assert feed.sent_to("compromised/spd/updated") == []
    assert next_run["last_fetch"]["compromised/spd"] is None


def test_first_fetch_help_states_that_a_change_restarts_every_collection():
    """The help that offers a later date as the remedy for a 0 answer also states what changing it costs."""
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        blocks = yml_file.read().split("\n- ")
    [block] = [block for block in blocks if "\n  name: first_fetch\n" in block]
    assert "Changing this value after the first run restarts every selected collection from the new date" in block


def test_first_fetch_help_says_why_a_collection_waits_for_a_cursor():
    """The first-fetch help names the collections that start from the date and says the others wait for a cursor,
    asked again on the next fetch."""
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        blocks = yml_file.read().split("\n- ")
    [block] = [block for block in blocks if "\n  name: first_fetch\n" in block]
    assert "attacks/ddos and attacks/phishing_kit start from the date itself" in block
    assert "Any other collection without a cursor for that date is not read yet" in block
    assert "the cursor is requested again on the next fetch" in block


@pytest.mark.parametrize("collection", ["attacks/ddos", "attacks/phishing_kit"])
def test_a_first_fetch_of_a_date_filtered_collection_starts_from_the_date(mocker, single_session_fixture, collection):
    """attacks/ddos and attacks/phishing_kit filter by df: without a sequence_list cursor they start from the first-fetch date."""
    client = single_session_fixture
    client.rate_limit_delay = 0
    feed = _UpdateFeed(start_cursors={collection: GroupIBTIA.ConnectionException(SEQUENCE_LIST_DOWN)})
    mocker.patch.object(client.poller, "send_request", side_effect=feed.send_request)
    mocker.patch.object(client, "granted_collections", return_value=[])
    next_run, _ = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="2026-10-01",
        incident_collections=[collection],
        max_requests=1,
        hunting_rules=0,
    )
    [request] = feed.sent_to(f"{collection}/updated")
    assert request["df"] == "2026-10-01"
    assert "seqUpdate" not in request


def test_git_repository_is_fetched_without_the_hunting_flag(mocker, single_session_fixture):
    """The hunting parameters are no-ops on osi/git_repository and are not sent; the feed is filtered by
    the hunting rules on the server, so its incidents say so."""
    client = single_session_fixture
    client.rate_limit_delay = 0
    record = {
        "id": "a" * 40,
        "name": "example/config",
        "seqUpdate": 1_760_000_000_000_001,
        "dateDetected": "2026-10-01T00:00:00+00:00",
        "evaluation": {**_EVALUATION, "severity": "green"},
        "files": [],
        "contributors": [],
    }
    feed = _UpdateFeed({"osi/git_repository": [record]}, start_cursors={"osi/git_repository": 1_760_000_000_000_000})
    mocker.patch.object(client.poller, "send_request", side_effect=feed.send_request)
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "osi/git_repository"}])
    built = mocker.patch.object(GroupIBTIA.IncidentBuilder, "build", autospec=True, side_effect=GroupIBTIA.IncidentBuilder.build)
    for hunting_rules in (0, 1):
        fetch_incidents(
            client=client,
            last_run={},
            first_fetch_time="3 days",
            incident_collections=["osi/git_repository"],
            max_requests=1,
            hunting_rules=hunting_rules,
        )
    assert [params.get("apply_hunting_rules") for _, params in feed.requests] == [None] * len(feed.requests)
    assert built.call_count == 2
    assert {call.kwargs["hunting_rules_applied"] for call in built.call_args_list} == {True}


PACK_DIR = Path(realpath).parents[1]
# Platform incident fields the mapper fills: the incident's name (its title, in no layout section), its
# severity, and the Common Types Description and Phone Number.
PLATFORM_INCIDENT_FIELDS = {"name": None, "severity": "severity", "Description": "description", "Phone Number": "phonenumber"}
# Fields every incident has, which a widget may query or group by.
PLATFORM_QUERY_FIELDS = frozenset({"type", "severity", "status"})


def _pack_items(folder: str) -> list[dict]:
    directory = PACK_DIR / folder
    items = []
    for name in sorted(os.listdir(directory)):
        with open(directory / name) as handle:
            items.append(json.load(handle))
    return items


def _classifier() -> dict:
    with open(PACK_DIR / "Classifiers" / "classifier-Group-IB_Threat_Intelligence_classifier.json") as handle:
        return json.load(handle)["keyTypeMap"]


def _mapper() -> dict:
    with open(PACK_DIR / "Classifiers" / "classifier-Group-IB_Threat_Intelligence_mapper.json") as handle:
        return {incident_type: rules["internalMapping"] for incident_type, rules in json.load(handle)["mapping"].items()}


def _layout_of(incident_type: str) -> dict:
    [layout_id] = [item["layout"] for item in _pack_items("IncidentTypes") if item["name"] == incident_type]
    [layout] = [item for item in _pack_items("Layouts") if item["id"] == layout_id]
    return layout


def _shown_cli_names(node: Any) -> set[str]:
    """The fields a layout shows, by CLI name: a field id is the CLI name, with or without incident_."""
    names: set[str] = set()
    if isinstance(node, dict):
        if "fieldId" in node:
            names.add(node["fieldId"].removeprefix("incident_"))
        for value in node.values():
            names |= _shown_cli_names(value)
    elif isinstance(node, list):
        for value in node:
            names |= _shown_cli_names(value)
    return names


def _associated(field: dict, item_type: str) -> bool:
    return field.get("associatedToAll") is True or item_type in (field.get("associatedTypes") or [])


def _mapped_value(incident: dict, rule: dict) -> Any:
    """What a mapper rule reads from the incident: its dotted path, or a complex rule's root and accessor."""
    path = rule.get("simple") or ".".join(filter(None, (rule["complex"].get("root"), rule["complex"].get("accessor"))))
    value: Any = incident
    for part in path.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


@pytest.mark.parametrize("collection", sorted(MAPPING))
def test_every_field_the_mapper_fills_is_on_the_layout_and_associated_with_the_incident_type(collection):
    """Every field the mapper fills, except the incident name, is on the incident type's layout and, when it is a pack
    field, associated with the type."""
    incident_type = _classifier()[collection]
    fields = {field["name"]: field for field in _pack_items("IncidentFields")}
    shown = _shown_cli_names(_layout_of(incident_type))
    off_layout, unassociated = [], []
    for name in _mapper()[incident_type]:
        if name in fields:
            cli_name = fields[name]["cliName"]
            if not _associated(fields[name], incident_type):
                unassociated.append(name)
        else:
            assert name in PLATFORM_INCIDENT_FIELDS
            cli_name = PLATFORM_INCIDENT_FIELDS[name]
        if cli_name is not None and cli_name not in shown:
            off_layout.append(name)
    assert (off_layout, unassociated) == ([], [])


@pytest.mark.parametrize("collection", sorted(MAPPING))
def test_every_pack_field_a_layout_shows_is_one_the_mapper_fills_for_the_incident_type(collection):
    """A field the mapper does not fill for the type stands empty on its layout."""
    incident_type = _classifier()[collection]
    cli_names = {field["name"]: field["cliName"] for field in _pack_items("IncidentFields")}
    filled = {cli_names[name] for name in _mapper()[incident_type] if name in cli_names}
    shown = _shown_cli_names(_layout_of(incident_type))
    assert sorted(name for name in shown if name in cli_names.values() and name not in filled) == []


@pytest.mark.parametrize("collection", sorted(MAPPING))
def test_every_mapper_rule_reads_a_key_the_incident_carries(collection):
    """A rule whose key no incident carries fills nothing; the keys are those of the collection's mapping and
    the ones the incident builder adds."""
    record = Parser(chunk={"count": 1, "items": [{"id": "a" * 40}]}, keys=[], iocs_keys=[]).parse_portion(
        keys=MAPPING[collection]
    )[0]
    built = IncidentBuilder().build(collection, record)
    keys = set(MAPPING[collection]) | set(json.loads(built["rawJSON"]))
    rules = _mapper()[_classifier()[collection]]
    roots = {name: (rule.get("simple") or rule["complex"]["root"]).split(".")[0] for name, rule in rules.items()}
    assert {name: root for name, root in roots.items() if root not in keys} == {}


@pytest.mark.parametrize("collection", sorted(c for c in MAPPING if COLLECTIONS_RAW_JSON.get(c, {}).get("items")))
def test_a_number_or_boolean_field_is_given_a_number_or_a_boolean(collection):
    """A digit string such as the CVV "015" is no number: its leading zero is part of it."""
    fields = {field["name"]: field for field in _pack_items("IncidentFields")}
    rules = _mapper()[_classifier()[collection]]
    wrong = []
    for record in COLLECTIONS_RAW_JSON[collection]["items"]:
        incident = _build(collection, record)
        for name, rule in rules.items():
            value = _mapped_value(incident, rule)
            kind = fields.get(name, {}).get("type")
            if value is None or kind not in ("number", "boolean"):
                continue
            if kind == "boolean":
                fits = isinstance(value, bool)
            else:
                fits = isinstance(value, int | float) and not isinstance(value, bool)
            if not fits:
                wrong.append((name, value))
    assert wrong == []


def test_every_column_a_grid_row_carries_is_a_column_of_its_grid_field():
    """Every key a grid row carries is a column of its grid field, a git repository file's own severity among them."""
    fields = {field["name"]: field for field in _pack_items("IncidentFields")}
    mapper = _mapper()
    missing = {}
    for collection, tables in ((name, spec.grid_tables) for name, spec in COLLECTIONS.items() if spec.grid_tables):
        rules = mapper[_classifier()[collection]]
        for table in tables:
            keys = MAPPING[collection].get(table)
            if not isinstance(keys, dict):
                continue  # rows built by a transform of their own
            for name, rule in rules.items():
                if rule.get("simple") == table:
                    columns = {column["key"] for column in fields[name]["columns"]}
                    lost = sorted({key.replace("_", "").lower() for key in keys} - columns)
                    if lost:
                        missing[name] = lost
    assert missing == {}


@pytest.mark.parametrize("collection", ["hi/threat_actor", "apt/threat_actor"])
def test_an_actor_profile_fills_gib_threat_actor_id_with_its_own_id(collection):
    """The postprocessing playbook looks the actor up by GIB Threat Actor ID."""
    record = _fixture(collection)
    incident = _build(collection, record)
    rules = _mapper()[_classifier()[collection]]
    assert rules["GIB Threat Actor ID"] == {"simple": "threat_actor_id"}
    assert _mapped_value(incident, rules["GIB Threat Actor ID"]) == record["id"]


def test_the_flags_of_a_phishing_group_fill_the_fields_the_pre_processing_scripts_read():
    """GIBTIIncidentUpdate, GIBTIIncidentUpdateAllTypes and GIBTIIncidentUpdateIncludingClosed copy the flags
    of a re-sent group to the incidents they update through gibfalsepositive and giballowlisted."""
    incident = _build("attacks/phishing_group", {**_fixture("attacks/phishing_group"), "falsePositive": True, "whitelist": False})
    fields = {field["name"]: field for field in _pack_items("IncidentFields")}
    filled = {
        fields[name]["cliName"]: (fields[name]["type"], _mapped_value(incident, rule))
        for name, rule in _mapper()["GIB Attacks Phishing Group"].items()
        if rule.get("simple") in ("falsePositive", "whitelist")
    }
    assert filled == {"gibfalsepositive": ("boolean", True), "giballowlisted": ("boolean", False)}


def test_gib_collection_is_associated_with_every_indicator_type_a_lookup_returns():
    """GIBTIEnrichIncidentIndicators creates every indicator of a lookup with GIB Collection. An IPv6 address
    under an IP key is an IPv6 indicator, and a wallet a Cryptocurrency Address."""
    names = {"Cryptocurrency": "Cryptocurrency Address"}
    types = {"IPv6"}
    for mapping in INDICATORS_TYPES.values():
        for spec in mapping["types"].values():
            types |= {names.get(value, value) for value in (spec["map"].values() if isinstance(spec, dict) else [spec])}
    [field] = [item for item in _pack_items("IndicatorFields") if item["cliName"] == "gibcollection"]
    assert sorted(item_type for item_type in types if not _associated(field, item_type)) == []


def test_every_widget_a_dashboard_shows_is_the_widget_of_the_pack():
    widgets = {widget["id"]: widget for widget in _pack_items("Widgets")}
    shown = [(dashboard["name"], entry["widget"]) for dashboard in _pack_items("Dashboards") for entry in dashboard["layout"]]
    assert shown
    assert [(name, widget["id"]) for name, widget in shown if widget != widgets.get(widget["id"])] == []


def test_every_field_a_widget_counts_by_is_searchable_and_filled_for_a_type_it_counts():
    """A widget counts what its incident query finds: a field that is not searchable, or that the mapper never
    fills for the types the widget names, makes it count nothing."""
    fields = {field["cliName"]: field for field in _pack_items("IncidentFields")}
    cli_names = {field["name"]: field["cliName"] for field in fields.values()}
    filled = {incident_type: {cli_names.get(name) for name in rules} for incident_type, rules in _mapper().items()}
    empty = []
    for widget in _pack_items("Widgets"):
        params = widget.get("params") or {}
        queries = f"{widget['query']} {params.get('query') or ''}"
        names = set(re.findall(r"(?<![\w.])-?([a-z][a-z0-9]*):", queries)) | set(params.get("groupBy") or [])
        types = set(re.findall(r'(?<!-)type:"([^"]+)"', queries))
        for name in sorted(names - PLATFORM_QUERY_FIELDS):
            field = fields.get(name)
            if field is None or field.get("unsearchable") or not any(name in filled.get(item, set()) for item in types):
                empty.append((widget["name"], name))
    assert empty == []


def test_every_field_the_gibti_scripts_query_is_searchable():
    """The pre-processing scripts find incidents by getIncidents queries: a field that is not searchable matches
    nothing, so every incoming duplicate is created."""
    fields = {field["cliName"]: field for field in _pack_items("IncidentFields")}
    queried = set()
    scripts = PACK_DIR / "Scripts"
    for name in sorted(os.listdir(scripts)):
        if name.startswith("GIBTI"):
            with open(scripts / name / f"{name}.py") as handle:
                queried |= set(re.findall(r"[\"'](gib[a-z0-9]*):", handle.read()))
    assert {"gibid", "gibleakname", "gibproxyport"} <= queried
    assert sorted(name for name in queried if fields[name].get("unsearchable") is not False) == []


def test_the_tailored_threats_widget_counts_the_reports_fetched_with_hunting_rules():
    """A report matched by the organization's hunting rules counts as tailored."""
    [widget] = [item for item in _pack_items("Widgets") if item["id"] == "gib-ti-tailored-threats"]
    for query in (widget["query"], widget["params"]["query"]):
        assert "gibfetchedwithhuntingrules:true" in query
        assert "gibistailored" not in query


def test_the_suspicious_ip_widgets_count_every_suspicious_ip_type_by_country_code_and_asn():
    """Group-IB sends a country code without a name on open proxy, SOCKS, VPN and scanner IPs, and the incident then shows
    the code as the name: grouped by name, one country would count twice."""
    suspicious = {incident_type for collection, incident_type in _classifier().items() if collection.startswith("suspicious_ip/")}
    widgets = {widget["id"]: widget for widget in _pack_items("Widgets")}
    for widget_id, field in (("gib-ti-suspicious-ips-by-country", "gibcountrycode"), ("gib-ti-suspicious-ips-by-asn", "gibasn")):
        widget = widgets[widget_id]
        for query in (widget["query"], widget["params"]["query"]):
            assert set(re.findall(r'type:"([^"]+)"', query)) == suspicious
            assert f"{field}:*" in query
        assert widget["params"]["groupBy"] == [field]


def test_a_start_cursor_of_one_is_the_collection_start_and_the_collection_waits(mocker, single_session_fixture):
    """seqUpdate 1 is the first update position: the collection waits for a cursor of the date rather than
    being read from its oldest record."""
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    mocker.patch.object(client.poller, "get_seq_update_dict", return_value={"compromised/account_group": 1})
    generator = mocker.patch.object(client.poller, "create_update_generator")
    with pytest.raises(ConnectionException, match="answered 1 for 2023-01-01, the start of the collection"):
        open_feed(
            client,
            collection_name="compromised/account_group",
            hunting_rules=0,
            enable_probable_corporate_access=False,
            unique=False,
            combolist=False,
            cursor=None,
            first_fetch_time="2023-01-01",
        )
    generator.assert_not_called()


def test_a_defacement_lookup_relates_and_tags_no_threat_actor(mocker, single_session_fixture):
    """The defacer handle groups defacements and is no attribution, as in the feed and the reputation commands."""
    client = single_session_fixture
    results = _lookup_record(mocker, client, "attacks/deface", [_deface("victim.example", "198.51.100.7", "defacer-one")])
    assert all(not r.relationships for r in results)
    urls = _context_objects(results, "URL")
    assert urls
    assert all("defacer-one" not in (url.get("Tags") or []) for url in urls)


def test_a_timeout_whose_url_holds_400_gets_no_refusal_hint(mocker, single_session_fixture):
    """The cursor in a timed-out request's URL can hold the digits 400; only an HTTP 400 answer is a refusal."""
    from ciaops.exception import ConnectionException

    client = single_session_fixture
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "osi/public_leak"}])

    def timed_out():
        raise ConnectionException(
            "Request to https://api.example.com/api/v2/osi/public_leak/updated failed: "
            "HTTPSConnectionPool(host='api.example.com', port=443): Max retries exceeded with url: "
            "/api/v2/osi/public_leak/updated?seqUpdate=1787184001234567&limit=20 (Caused by ReadTimeoutError)"
        )
        yield  # pragma: no cover

    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=(timed_out(), None))
    with pytest.raises(DemistoException) as caught:
        fetch_incidents(
            client=client,
            last_run={},
            first_fetch_time="3 days",
            incident_collections=["osi/public_leak"],
            max_requests=1,
            hunting_rules=0,
        )
    assert "shorten the window" not in str(caught.value)


def test_main_reports_an_error_raised_while_the_settings_are_read(mocker):
    """An instance whose proxy setting is no boolean fails while its settings are read: the failure is reported
    through return_error, naming the incident collections of the fetch and no endpoint, and nothing escapes main()."""
    calls = run_main(mocker, {**MAIN_PARAMS, "proxy": "maybe", "incident_collections": ["malware/cnc"]}, "fetch-incidents")
    message = calls["error"].call_args.args[0]
    assert message.startswith(
        "Failed to execute fetch-incidents command.\nIncident collections: ['malware/cnc'].\nCommand endpoint: None.\nError: "
    )
    assert "valid boolean-like value" in message


def test_the_available_collections_are_sorted(mocker):
    """The granted collections are answered in one order whatever order the API lists them in."""
    names = sorted(GroupIBTIA.TICollections.INFO)
    mocker.patch.object(GroupIBTIA.demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(GroupIBTIA.demisto, "setIntegrationContext")
    mocker.patch.object(GroupIBTIA.TIPoller, "send_request", return_value=[{"collection": name} for name in reversed(names)])
    calls = run_main(mocker, MAIN_PARAMS, "gibti-get-available-collections")
    [result] = calls["results"].call_args.args
    assert result.outputs["collections"] == names
    assert result.raw_response == names
    calls["error"].assert_not_called()


@pytest.mark.parametrize(
    "command, command_class",
    [
        ("gibti-get-available-collections", "AvailableCollectionsCommand"),
        ("gibti-global-search", "SearchCommand"),
        ("gibti-local-search", "SearchCommand"),
        ("gibti-ip-scoring", "ScoringCommand"),
        ("gibti-domain-scoring", "ScoringCommand"),
        ("gibti-cve-scoring", "ScoringCommand"),
        ("gibti-get-threat-info", "LookupCommand"),
        ("gibti-get-threat-actor-info", "LookupCommand"),
        ("gibtia-get-threat-actor-info", "LookupCommand"),
        ("ip", "ReputationCommand"),
        ("domain", "ReputationCommand"),
        ("file", "ReputationCommand"),
        *[(command, "LookupCommand") for command in LOOKUP_COMMANDS],
    ],
)
def test_main_runs_the_command_object_of_each_command(mocker, command, command_class):
    """Each command listed runs its command object with the arguments of the call, and its result goes to the War Room."""
    run = mocker.patch.object(getattr(GroupIBTIA, command_class), "run", return_value=["result"])
    params = {**MAIN_PARAMS, "enabled_reputation_commands": ["ip", "domain", "file"]}
    calls = run_main(mocker, params, command, {"id": "x"})
    run.assert_called_once_with({"id": "x"})
    calls["results"].assert_called_once_with(["result"])
    calls["error"].assert_not_called()


def test_every_command_of_the_yml_has_a_handler(mocker):
    """The commands the YAML declares are the ones main() answers: a handler, a legacy name or a deprecated name without one."""
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        script = yml_file.read().split("\nscript:\n", 1)[1]
    declared = {command or reputation for command, reputation in re.findall(r"^    name: (\S+)$|^  - name: (\S+)$", script, re.M)}
    handlers: dict = {}

    def dispatch_table(message, *args, **kwargs):
        # main's table of command name -> callable, read from its frame when it reports a command it does not know.
        frame = inspect.currentframe()
        while frame is not None and frame.f_code is not GroupIBTIA.main.__code__:
            frame = frame.f_back
        assert frame is not None
        handlers.update(frame.f_locals["commands"])

    mocker.patch.object(GroupIBTIA.demisto, "params", return_value=MAIN_PARAMS)
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value={})
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="gibti-no-such-command")
    error = mocker.patch.object(GroupIBTIA, "return_error", side_effect=dispatch_table)
    GroupIBTIA.main()
    assert "Command gibti-no-such-command is not implemented" in error.call_args.args[0]
    handled = set(handlers) | set(GroupIBTIA.LEGACY_ALIASES) | set(GroupIBTIA.REMOVED_COMMANDS)
    assert declared == handled - {"test-module", "fetch-incidents"}


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
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        script = yml_file.read().split("\nscript:\n", 1)[1]
    declared = {command or reputation for command, reputation in re.findall(r"^    name: (\S+)$|^  - name: (\S+)$", script, re.M)}
    with open(f"{realpath}/GroupIBTIA.py") as code_file:
        assert declared - _names_xsoar_lint_finds(code_file.read()) == set()


def test_main_names_the_collection_of_a_failed_lookup_and_no_incident_collection(mocker):
    mocker.patch.object(
        GroupIBTIA.LookupCommand, "run", side_effect=DemistoException("No record with id 'x' was found in malware/cnc.")
    )
    calls = run_main(mocker, {**MAIN_PARAMS, "incident_collections": ["malware/cnc"]}, "gibti-get-malware-cnc-info", {"id": "x"})
    assert calls["error"].call_args.args[0] == (
        "Failed to execute gibti-get-malware-cnc-info command.\nIncident collections: None.\n"
        "Command endpoint: malware/cnc.\nError: No record with id 'x' was found in malware/cnc."
    )


def test_main_names_the_incident_collections_of_a_failed_fetch(mocker):
    mocker.patch.object(GroupIBTIA.demisto, "getLastRun", return_value={})
    failure = DemistoException("The fetch of malware/cnc failed: HTTP 403.")
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "run", side_effect=failure)
    calls = run_main(mocker, {**MAIN_PARAMS, "incident_collections": ["malware/cnc"]}, "fetch-incidents")
    assert calls["error"].call_args.args[0] == (
        "Failed to execute fetch-incidents command.\nIncident collections: ['malware/cnc'].\n"
        "Command endpoint: None.\nError: The fetch of malware/cnc failed: HTTP 403."
    )


def test_main_names_no_incident_collection_for_a_deprecated_command(mocker):
    """A deprecated command without a handler fails before a handler is chosen, and its error names no incident collection."""
    calls = run_main(mocker, {**MAIN_PARAMS, "incident_collections": ["malware/cnc"]}, "gibtia-get-compromised-mule-info")
    assert calls["error"].call_args.args[0] == (
        "Failed to execute gibtia-get-compromised-mule-info command.\nIncident collections: None.\n"
        "Command endpoint: None.\nError: Command gibtia-get-compromised-mule-info is no longer available. "
        "Use gibti-get-compromised-spd-info instead."
    )


def test_main_fetch_stores_the_next_run_and_creates_the_incidents(mocker):
    mocker.patch.object(GroupIBTIA.demisto, "getLastRun", return_value={"last_fetch": {"malware/cnc": "5"}})
    set_last_run = mocker.patch.object(GroupIBTIA.demisto, "setLastRun")
    incidents = mocker.patch.object(GroupIBTIA.demisto, "incidents")
    run = mocker.patch.object(
        GroupIBTIA.FetchIncidentsCommand, "run", return_value=({"last_fetch": {"malware/cnc": "7"}}, [{"name": "n"}])
    )
    calls = run_main(mocker, {**MAIN_PARAMS, "incident_collections": ["malware/cnc"]}, "fetch-incidents")
    run.assert_called_once_with({"last_fetch": {"malware/cnc": "5"}})
    set_last_run.assert_called_once_with({"last_fetch": {"malware/cnc": "7"}})
    incidents.assert_called_once_with([{"name": "n"}])
    calls["error"].assert_not_called()


def test_main_test_module_answers_through_demisto_results(mocker):
    mocker.patch.object(GroupIBTIA.TestModuleCommand, "run", return_value="ok")
    results = mocker.patch.object(GroupIBTIA.demisto, "results")
    calls = run_main(mocker, MAIN_PARAMS, "test-module")
    results.assert_called_once_with("ok")
    calls["error"].assert_not_called()


@pytest.mark.parametrize(
    "params, field, expected",
    [
        ({}, "hunting_rules", False),
        ({"hunting_rules": True}, "hunting_rules", True),
        ({"combolist": True, "unique": True}, "combolist", True),
        ({"enable_probable_corporate_access": True}, "enable_probable_corporate_access", True),
        ({"proxy": True}, "proxy", True),
        ({"insecure": True}, "verify", False),
        ({}, "verify", True),
        ({"limit": "20"}, "limit", 20),
        ({}, "limit", 100),
        ({"max_fetch": "5"}, "max_requests", 5),
        ({}, "max_requests", 3),
        ({"first_fetch": " 7 days "}, "first_fetch", "7 days"),
        ({"incident_collections": ["malware/cnc"]}, "incident_collections", ["malware/cnc"]),
        ({"integration_reliability": "A - Completely reliable"}, "source_reliability", "A - Completely reliable"),
        ({"integration_reliability": "a - typed by hand"}, "source_reliability", "C - Fairly reliable"),
        ({"disable_integration_reliability_override": True}, "reputation_reliability", None),
        ({}, "reputation_reliability", "C - Fairly reliable"),
        (
            {"enabled_reputation_commands": "IP, Domain, url, hash"},
            "enabled_reputation_commands",
            frozenset({"ip", "domain", "url"}),
        ),
        ({}, "enabled_reputation_commands", frozenset()),
        ({"dedup_lookback_days": " 30 "}, "dedup_lookback_days", 30),
        ({"dedup_lookback_days": 7}, "dedup_lookback_days", 7),
        ({}, "dedup_lookback_days", 365),
        ({"skip_updated_incidents": "true"}, "skip_updated_incidents", True),
    ],
)
def test_settings_read_the_instance_parameters(params, field, expected):
    assert getattr(Settings.from_params(params), field) == expected


@pytest.mark.parametrize(
    "params, error",
    [
        (
            {"dedup_lookback_days": True},
            "Invalid 'Deduplication lookback (days)' value: expected a whole number of days, got True.",
        ),
        (
            {"dedup_lookback_days": 7.5},
            "Invalid 'Deduplication lookback (days)' value: expected a whole number of days, got 7.5.",
        ),
        (
            {"dedup_lookback_days": "x"},
            "Invalid 'Deduplication lookback (days)' value: expected a whole number of days, got 'x'.",
        ),
        ({"rate_limit_delay": "-1", "search_timeout": "x"}, "'Delay between API requests (seconds)' must be zero or positive."),
    ],
)
def test_settings_name_the_first_invalid_parameter(params, error):
    with pytest.raises(DemistoException) as raised:
        Settings.from_params(params)
    assert str(raised.value) == error


def test_a_negative_dedup_lookback_fails_the_fetch_only():
    settings = Settings.from_params({"dedup_lookback_days": "-1", "skip_updated_incidents": True})
    assert settings.dedup_lookback_days == -1
    with pytest.raises(DemistoException, match="'Deduplication lookback \\(days\\)' must be zero or positive."):
        settings.dedup_enabled()


def test_an_invalid_first_fetch_fails_the_fetch_only_when_a_collection_has_no_cursor(mocker, single_session_fixture):
    """The first-fetch date is parsed when a collection needs it."""
    client = single_session_fixture
    mocker.patch.object(client.poller, "create_update_generator", return_value=[])
    open_feed(client, "malware/cnc", cursor="5", first_fetch_time="not a date")
    with pytest.raises(DemistoException, match="Invalid 'Incidents first fetch' value"):
        open_feed(client, "malware/cnc", cursor=None, first_fetch_time="not a date")


def test_the_duplicate_cache_and_the_granted_collections_cache_read_an_injected_clock(mocker):
    seen = seen_cache(clock=lambda: 1_000.0)
    state: dict = {"found_incident_ids": {"old": 1.0}}
    seen._remember(state, [{GroupIBTIA.FetchIncidentsCommand.DEDUP_ID_KEY: "malware/cnc|a"}], retention_seconds=500)
    assert state["found_incident_ids"] == {"malware/cnc|a": 1_000.0}
    context: dict = {}
    mocker.patch.object(GroupIBTIA.demisto, "getIntegrationContext", side_effect=lambda: dict(context))
    mocker.patch.object(GroupIBTIA.demisto, "setIntegrationContext", side_effect=context.update)
    Client(base_url="https://example.com", auth=("u", "p"), clock=lambda: 1_000.0)._cache_grants([{"collection": "ioc/common"}])
    assert context["granted_collections_cache"]["fetched_at"] == 1_000.0
    assert Client(base_url="https://example.com", auth=("u", "p"), clock=lambda: 1_300.0)._cached_grants() == [
        {"collection": "ioc/common"}
    ]
    assert Client(base_url="https://example.com", auth=("u", "p"), clock=lambda: 1_301.0)._cached_grants() is None


def test_the_shared_tables_are_not_changed_by_incidents_and_lookups():
    """MAPPING and INDICATORS_TYPES share their evaluation, suspicious_ip and threat report blocks between
    collections: building incidents and lookup indicators from every fixture leaves them as they are."""
    before = json.dumps([MAPPING, INDICATORS_TYPES], sort_keys=True)
    for collection, page in COLLECTIONS_RAW_JSON.items():
        for record in page["items"]:
            built = _build(collection, json.loads(json.dumps(record)))
            IndicatorBuilder(DEFAULT_SOURCE_RELIABILITY, True).results(built, collection)
    assert json.dumps([MAPPING, INDICATORS_TYPES], sort_keys=True) == before
    assert MAPPING["suspicious_ip/vpn"]["indicators"] is MAPPING["suspicious_ip/tor_node"]["indicators"]
    assert INDICATORS_TYPES["hi/threat"] is INDICATORS_TYPES["apt/threat"]


def test_settings_left_empty_or_null_take_their_defaults():
    params = {
        "credentials": None,
        "incident_collections": None,
        "first_fetch": None,
        "max_fetch": None,
        "limit": "",
        "skip_updated_incidents": None,
        "create_relationships": None,
        "disable_integration_reliability_override": None,
    }
    settings = GroupIBTIA.Settings.from_params(params)
    assert (settings.username, settings.password, settings.limit) == (None, None, 100)
    assert (settings.incident_collections, settings.first_fetch, settings.max_requests) == ([], "3 days", 3)
    assert settings.skip_updated_incidents is False
    assert (settings.create_relationships, settings.use_computed_reliability) == (True, False)


@pytest.mark.parametrize(
    "name, label", [("max_fetch", "Number of requests per collection"), ("limit", "Limit (items per request)")]
)
def test_a_count_setting_that_is_not_a_whole_number_is_named(name, label):
    with pytest.raises(DemistoException, match=re.escape(f"Invalid '{label}' value: expected a whole number, got 'many'")):
        GroupIBTIA.Settings.from_params({name: "many"})


@pytest.mark.parametrize("name", ["bp/phishing", "bp/phishing_kit", "compromised/imei"])
def test_a_removed_collection_is_refused(name):
    with pytest.raises(DemistoException, match=f"Collection {name} is obsolete and has no replacement"):
        CollectionSpec.validate(name)


def test_local_search_reads_whole_number_arguments(mock_client):
    """requests_limit, page_size_limit and seq_update take a whole number; blank is none."""
    args = {"query": "q", "collection_name": "malware/cnc"}
    local_search(mock_client, {**args, "requests_limit": 3, "page_size_limit": " ", "seq_update": 7})
    assert mock_client.search_collection.call_args.kwargs == {
        "query": "q",
        "limit": None,
        "date_from": None,
        "date_to": None,
        "sequpdate": 7,
    }
    with pytest.raises(DemistoException, match="Invalid 'requests_limit' value: expected a whole number, got 'two'"):
        local_search(mock_client, {**args, "requests_limit": "two"})
    with pytest.raises(DemistoException, match="Invalid 'requests_limit' value: expected a whole number, got \\["):
        local_search(mock_client, {**args, "requests_limit": [1]})


@pytest.mark.parametrize(
    "value, expected", [(7, 7), (7.9, 7), (" 12 ", 12), ("abc", None), (True, None), (None, None), ([5], None)]
)
def test_a_stored_or_served_cursor_is_a_whole_number(value, expected):
    assert GroupIBTIA.seq_update_number(value) == expected


def test_the_fetch_log_summarizes_a_state_of_any_shape():
    assert FetchIncidentsCommand._summary(None) == {"last_fetch": {}, "seen_incident_ids_cache_size": 0}
    state = {"last_fetch": "x", "found_incident_ids": {"a": 1.0, "b": 2.0}}
    assert FetchIncidentsCommand._summary(state) == {"last_fetch": {}, "seen_incident_ids_cache_size": 2}


def test_a_lookup_timeout_of_zero_waits_for_every_request(mocker, single_session_fixture):
    records = {"ioc/primary": [{"type": "network", "ip": [{"ip": "203.0.113.30", "riskScore": 90}]}]}
    client = _reputation_client(mocker, single_session_fixture, records)
    mocker.patch.object(
        ReputationCommand, "_read", side_effect=lambda path, value, keys=None: time.sleep(0.3) or records.get(path, [])
    )
    [result] = reputation(client, "ip", {"ip": "203.0.113.30"}, search_timeout=0)
    assert result.outputs["partial"] is False
    assert result.indicator.dbot_score.score == 2


def test_a_failed_domain_scoring_is_no_risk_score(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {})
    mocker.patch.object(client.poller, "get_domain_scoring", side_effect=GroupIBTIA.ConnectionException(SERVER_ERROR))
    data, _floors, _mentions = evidence(client)._lookup("domain", "example.com")
    assert data["scoring"] == {"score": None}


def test_a_malformed_granted_collections_cache_is_no_cache(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(
        GroupIBTIA.demisto,
        "getIntegrationContext",
        return_value={"granted_collections_cache": {"fetched_at": time.time(), "items": "not a list"}},
    )
    mocker.patch.object(GroupIBTIA.demisto, "setIntegrationContext")
    send = mocker.patch.object(client.poller, "send_request", return_value=[{"collection": "ioc/common"}])
    assert client.available_collections() == frozenset({"ioc/common"})
    assert send.call_count == 1


def test_a_platform_answer_that_is_no_json_is_an_empty_one():
    server = _FakeServer({("GET", "/preprocess/rules"): (200, "<html>maintenance</html>")})
    assert GroupIBTIA.PreProcessRuleScripts(server).fill() == []
    assert server.calls == [("GET", "/preprocess/rules", None)]


def test_the_instance_test_logs_the_rules_it_filled(mocker, single_session_fixture):
    mocker.patch.object(single_session_fixture, "granted_collections", return_value=[{"collection": "ioc/common"}])
    mocker.patch.object(single_session_fixture, "available_collections", return_value=frozenset({"ioc/common"}))
    mocker.patch.object(GroupIBTIA.PreProcessRuleScripts, "fill", return_value=["GIB Rule All Types"])
    info = mocker.patch.object(GroupIBTIA.demisto, "info")
    assert GroupIBTIA.TestModuleCommand(single_session_fixture).run() == "ok"
    info.assert_called_once_with("[pre-processing rules] script id filled in: GIB Rule All Types")


def test_the_computed_reliability_is_the_most_trusted_of_the_matched_collections(mocker, single_session_fixture):
    """With "Ignore Source Reliability override" on, the most trusted matched collection gives the reliability:
    apt/threat's A over hi/open_threats' B."""
    records = {"hi/open_threats": [{"id": "t-1"}], "apt/threat": [{"id": "r-1"}]}
    client = _reputation_client(mocker, single_session_fixture, records, {"example.com": 90})
    [result] = reputation(client, "domain", {"domain": "example.com"})
    assert result.indicator.dbot_score.reliability == "A - Completely reliable"
    client = _reputation_client(mocker, single_session_fixture, {"hi/open_threats": [{"id": "t-1"}]}, {"example.com": 90})
    [result] = reputation(client, "domain", {"domain": "example.com"})
    assert result.indicator.dbot_score.reliability == "B - Usually reliable"


DARKWEB_COLLECTIONS = ("compromised/access", "compromised/messenger", "compromised/discord", "darkweb/forums")
POST_COLLECTIONS = ("compromised/messenger", "compromised/discord", "darkweb/forums")
DARKWEB_AND_OPEN_THREAT_COLLECTIONS = (*DARKWEB_COLLECTIONS, "hi/open_threats")
PARTIAL_POST_MASK = Masking(PasswordMask(), CardDataMask(), GroupIBTIA.PostTextMask("Partial"))
FULL_POST_MASK = Masking(PasswordMask(), CardDataMask(), GroupIBTIA.PostTextMask("Full"))


def _fixtures(collection: str) -> list[dict]:
    return json.loads(json.dumps(COLLECTIONS_RAW_JSON[collection]["items"]))


def _parsed(collection: str, index: int = 0) -> dict:
    """A raw fixture parsed with the collection's mapping, as a fetch or a lookup reads it."""
    return Parser(chunk={"count": 1, "items": [_fixtures(collection)[index]]}, keys=[], iocs_keys=[]).parse_portion(
        keys=MAPPING[collection]
    )[0]


def _incident(collection: str, index: int = 0) -> dict:
    return IncidentBuilder().build(collection, _parsed(collection, index))


def test_compromised_access_incident_names_the_host_and_the_stealer_and_turns_nothing_into_an_indicator():
    """The target is the customer's own host and the shop is the marketplace, not attacker infrastructure."""
    record = _fixtures("compromised/access")[0]
    incident = _incident("compromised/access")
    built = json.loads(incident["rawJSON"])
    assert incident["name"] == "Compromised Access: mail.victim.example (Sample Stealer)"
    assert incident["occurred"] == "2026-10-02T08:00:00Z"
    assert built["systemSeverity"] == IncidentSeverity.HIGH
    assert built["sourceType"] == "Example Market"
    assert built["target"]["host"] == "mail.victim.example"
    assert built["target"]["os"] == "Windows 10 Pro x64"
    assert built["shop"] == {
        "domain": "market.example",
        "url": "https://market.example:443",
        "ip": "198.51.100.7",
        "port": 443,
        "protocol": "https",
        "asn": "AS64496",
        "provider": "Example Hosting",
        "countryCode": "US",
        "region": "Example Region",
        "city": None,
    }
    assert built["archiveFiles"] == "Cookies\nAutofill\nChrome\nDocuments/report.docx"
    assert built["portalLink"] == f"https://tap.group-ib.com/cd/shops?id={record['id']}"
    assert built["relatedIndicators"] is None
    assert IndicatorBuilder().items(_parsed("compromised/access"), "compromised/access") == []
    second = json.loads(_incident("compromised/access", 1)["rawJSON"])
    assert second["name"] == "Compromised Access: vpn.victim.example (Sample Logger)"
    assert second["archiveFiles"] == ""


def test_telegram_incident_is_named_after_the_channel_and_dated_by_the_post():
    first = json.loads(_incident("compromised/messenger")["rawJSON"])
    assert first["name"] == "Darkweb Telegram: Sample Market"
    assert first["systemSeverity"] == IncidentSeverity.HIGH
    assert first["sourceType"] == "compromised/messenger"
    assert first["author"] == {
        "id": "5005",
        "handle": "sample_seller",
        "firstName": "Sample",
        "lastName": "Seller",
        "type": "user",
        "name": "Sample Seller",
    }
    assert first["channel"]["title"] == "Sample Market"
    assert first["channel"]["subscribers"] == 50
    # An empty attachment block and an empty deletion date are no attachment and no deletion.
    assert first["attachment"] is None
    assert first["deletedDate"] is None
    assert first["edits"] == [
        {"datedetected": "2026-10-01T10:05:00", "text": "logs for sale, card 4111111111111111", "translation": None}
    ]
    assert first["portalLink"] == "https://tap.group-ib.com/ta/im?chatId=4242&msg=0123456789abcdef0123456789abcdef01234570"
    assert first["relatedIndicators"] is None
    second_incident = _incident("compromised/messenger", 1)
    second = json.loads(second_incident["rawJSON"])
    assert second_incident["occurred"] == "2018-05-05T10:00:00Z"
    assert second["deletedDate"] == "2026-10-02T17:35:05"
    assert second["attachment"] == {"name": "logs.zip", "type": "document", "size": 2048}
    assert second["reply"]["text"] == "logs for sale, card 4111 1111 1111 1111 cvv 123"
    assert second["author"]["name"] is None
    assert second["edits"] is None


def test_discord_incident_is_named_after_the_server_and_the_channel():
    first = json.loads(_incident("compromised/discord")["rawJSON"])
    assert first["name"] == "Darkweb Discord: Sample Server / market"
    assert first["author"]["handle"] == "sample_seller#0001"
    assert first["channel"]["server"] == "Sample Server"
    assert first["channel"]["messages"] == 10
    assert first["attachment"] is None
    assert first["edits"] is None
    assert first["deletedDate"] is None
    assert first["portalLink"] == "https://tap.group-ib.com/ta/im?collection=discord&chatId=ch-1&msg=1290000000000000001"
    second = json.loads(_incident("compromised/discord", 1)["rawJSON"])
    # A discriminator of 0 is Discord's "none".
    assert second["author"]["handle"] == "sample_buyer"
    assert second["edits"] == [
        {
            "date": "2026-10-01T12:31:00Z",
            "datedetected": "2026-10-01T12:32:00Z",
            "text": "price? card 5555444433331111",
            "translation": None,
        }
    ]
    assert second["reply"]["text"] == "selling access now, pm me"
    assert second["reply"]["authorName"] == "sample_seller"
    assert second["attachment"] == {"name": "dump.txt", "type": "text/plain", "size": 512}


def test_forum_incident_is_named_after_the_thread_and_keeps_the_board_path_and_the_categories():
    first_incident = _incident("darkweb/forums")
    first = json.loads(first_incident["rawJSON"])
    assert first_incident["name"] == "Darkweb Forum: VPN access for sale"
    assert first_incident["occurred"] == "2026-10-01T09:00:00Z"
    assert first["forum"] == "forum.example"
    assert first["forumSection"] == "Market / Access"
    assert first["categories"] == ["Access", "Sale", "Sample Company"]
    assert first["languages"] == "English"
    assert first["author"] == {"handle": "sample_broker"}
    assert first["portalLink"] == "https://tap.group-ib.com/ta/darkweb?id=0123456789abcdef0123456789abcdef"
    assert first["imageText"] is None
    assert first["relatedIndicators"] is None
    second = json.loads(_incident("darkweb/forums", 1)["rawJSON"])
    assert second["languages"] == "English, Russian"
    assert second["categories"] == []
    assert second["imageText"] == "4111111111111111 09/27 CVV 123 APPROVED"


def test_open_threat_incident_is_named_after_the_author_and_the_title_or_the_text():
    blog_incident = _incident("hi/open_threats")
    blog = json.loads(blog_incident["rawJSON"])
    assert blog_incident["name"] == "Open Threat: example_research: Sample stealer campaign targets banks"
    assert blog_incident["occurred"] == "2026-10-01T00:00:31Z"
    assert blog["systemSeverity"] == IncidentSeverity.MEDIUM
    assert blog["sourceType"] == "Blog"
    assert blog["sourceName"] == "blog.example"
    # The HTML of a blog record's text is reduced to its text.
    assert blog["text"] == "Sample Group spreads Sample Stealer through fake installers."
    assert blog["threat_actor_name"] == "Sample Group"
    assert blog["malware_name"] == "Sample Stealer"
    assert blog["tags"] == "ransomware, banking"
    assert blog["cveIds"] == "CVE-2099-0001"
    assert blog["huntingRuleIds"] == "100001"
    assert blog["companyTags"] == "Sample Company"
    assert blog["countryName"] == "United States"
    assert blog["relatedIndicators"].splitlines() == [
        "198.51.100.7",
        "c2.example",
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "ffffffffffffffffffffffffffffffff",
        "CVE-2099-0001",
        "bitcoin:16L5yRNPTuciSgXGHqYwn9N6NeoKqopAu",
    ]
    # The post's e-mail address stays on the record and becomes no indicator.
    assert "contact@c2.example" in json.dumps(blog["indicators"])
    social_incident = _incident("hi/open_threats", 1)
    social = json.loads(social_incident["rawJSON"])
    # A social post is titled by its id: the start of its text names the incident instead.
    assert (
        social_incident["name"]
        == "Open Threat: example_research: #SampleStealer seen again http://c2.example/gate #cybersecurity"
    )
    assert social["systemSeverity"] == IncidentSeverity.LOW
    assert social["sourceType"] == "Social Network"
    assert social["relatedIndicators"] == "c2.example"


def test_an_untitled_open_threat_post_is_cut_to_the_title_length():
    record = _parsed("hi/open_threats", 1)
    record["title"] = "12345"
    record["text"] = "word " * 40
    record["author"]["handle"] = None
    record["sourceName"] = None
    built = IncidentBuilder().build("hi/open_threats", record)
    assert built["name"] == "Open Threat: " + ("word " * 16).rstrip() + "..."


def test_open_threat_indicators_cover_every_extraction_but_the_email_and_the_ip_gets_the_suspicious_verdict():
    items = {
        (item.observable_type, item.row["value"]): item
        for item in IndicatorBuilder("B - Usually reliable", True).items(_parsed("hi/open_threats"), "hi/open_threats")
    }
    assert set(items) == {
        ("IP", "198.51.100.7"),
        ("Domain", "c2.example"),
        ("File", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        ("File", "ffffffffffffffffffffffffffffffff"),
        ("CVE", "CVE-2099-0001"),
        ("Cryptocurrency", "bitcoin:16L5yRNPTuciSgXGHqYwn9N6NeoKqopAu"),
        ("Cryptocurrency", "0x0000000000000000000000000000000000000001"),
    }
    ip = items[("IP", "198.51.100.7")].indicator
    assert ip.dbot_score.score == Common.DBotScore.SUSPICIOUS
    assert ip.dbot_score.reliability == "B - Usually reliable"
    assert ip.tags == ["hi/open_threats", "Sample Stealer", "Sample Group"]
    assert ip.traffic_light_protocol == "WHITE"
    assert {relationship.to_context()["EntityB"] for relationship in items[("IP", "198.51.100.7")].relationships} == {
        "Sample Stealer",
        "Sample Group",
    }
    file = items[("File", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")].indicator
    assert (file.md5, file.sha1, file.name, file.size) == (
        "dddddddddddddddddddddddddddddddd",
        "cccccccccccccccccccccccccccccccccccccccc",
        "dropper.exe",
        1024,
    )
    assert items[("File", "ffffffffffffffffffffffffffffffff")].indicator.md5 == "ffffffffffffffffffffffffffffffff"
    assert items[("Cryptocurrency", "0x0000000000000000000000000000000000000001")].indicator.address_type == "ethereum"
    assert items[("Cryptocurrency", "bitcoin:16L5yRNPTuciSgXGHqYwn9N6NeoKqopAu")].indicator.address_type == "bitcoin"


@pytest.mark.parametrize("collection", DARKWEB_COLLECTIONS)
def test_dark_web_records_yield_no_indicators(collection):
    """A post is free text that can quote anything; a listing names the customer's host and the shop."""
    for index in range(len(_fixtures(collection))):
        assert IndicatorBuilder().items(_parsed(collection, index), collection) == []
        assert json.loads(_incident(collection, index)["rawJSON"])["relatedIndicators"] is None


def test_post_text_mask_partial_cuts_card_numbers_and_clears_cvv_codes_in_every_copy_of_the_text():
    mask = GroupIBTIA.PostTextMask("Partial")
    telegram = mask.apply("compromised/messenger", _parsed("compromised/messenger", 1))
    assert telegram["text"] == "who sells access to victim.example"
    assert telegram["reply"]["text"] == "logs for sale, card ************1111 cvv: ***"
    assert telegram["highlight"] == "who sells access to <em>victim.example</em>"
    assert mask.apply("compromised/messenger", _parsed("compromised/messenger"))["edits"]["text"] == [
        "logs for sale, card ************1111"
    ]
    discord = mask.apply("compromised/discord", _parsed("compromised/discord", 1))
    assert discord["text"] == "price? card ************1111 exp 06/27 CVV: ***"
    assert discord["edits"]["text"] == ["price? card ************1111"]
    forum = mask.apply("darkweb/forums", _parsed("darkweb/forums", 1))
    assert forum["imageText"] == "************1111 09/27 CVV: *** APPROVED"
    assert forum["clearText"] == "checker output attached"
    assert forum["author"] == {"handle": "sample_checker"}


@pytest.mark.parametrize(
    "text, masked",
    [
        ("4111111111111111 09/27 CVV 123 APPROVED", "************1111 09/27 CVV: *** APPROVED"),
        ("card 4111 1111 1111 1111 cvv: 123", "card ************1111 cvv: ***"),
        ("4111-1111-1111-1111|09|23|123", "************1111|09|23|***"),
        ("378282246310005 amex", "***********0005 amex"),
        ("cvc 1234 only", "cvc: *** only"),
        # A longer run of digits and a phone number are no card numbers.
        ("id 12345678901234567890 ok", "id 12345678901234567890 ok"),
        ("call +1 555 0100 ext 12", "call +1 555 0100 ext 12"),
    ],
)
def test_post_text_mask_recognizes_card_numbers_and_cvv_codes(text, masked):
    assert GroupIBTIA.PostTextMask.mask_text(text) == masked


def test_post_text_mask_full_withholds_the_text_and_keeps_the_metadata():
    record = GroupIBTIA.PostTextMask("Full").apply("compromised/messenger", _parsed("compromised/messenger", 1))
    assert record["text"] == record["reply"]["text"] == record["highlight"] == "[withheld]"
    assert record["reply"]["translation"] == ""
    assert record["channel"]["title"] == "Sample Market"
    assert record["attachment"]["name"] == "logs.zip"
    assert record["deletedDate"] == "2026-10-02T17:35:05"


def test_post_text_mask_leaves_other_collections_and_the_off_mode_alone():
    record = _parsed("compromised/account_group")
    assert GroupIBTIA.PostTextMask("Full").apply("compromised/account_group", record) is record
    post = _parsed("darkweb/forums", 1)
    assert GroupIBTIA.PostTextMask().apply("darkweb/forums", post) is post


def test_the_post_text_mask_reaches_incidents_lookups_and_the_local_search(mocker, single_session_fixture):
    client = single_session_fixture
    page = Parser({"count": 1, "items": _fixtures("compromised/discord")[1:], "seqUpdate": 1786482042688602}, [], [])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([page], None))
    settings = fetch_settings(["compromised/discord"], masking=PARTIAL_POST_MASK)
    _, [incident] = FetchIncidentsCommand(client, settings).run({})
    assert json.loads(incident["rawJSON"])["text"] == "price? card ************1111 exp 06/27 CVV: ***"
    mocker.patch.object(client, "search_collection", return_value=iter([page]))
    [entry, *_] = LookupCommand("compromised/discord", client, settings_with(masking=FULL_POST_MASK)).run(
        {"id": "1290000000000000002"}
    )
    assert entry.outputs["text"] == "[withheld]"
    assert entry.outputs["channel"]["server"] == "Sample Server"
    assert "5555" not in entry.readable_output
    mocker.patch.object(client, "search_collection", return_value=iter([page]))
    result = local_search(client, {"collection_name": "compromised/discord", "include_raw_feed": "true"}, PARTIAL_POST_MASK)
    assert "************1111" in result.outputs[0]["raw_feed"]
    assert "5555 4444" not in result.outputs[0]["raw_feed"]


def test_the_post_text_mask_setting_is_read_in_any_case_and_validated():
    assert Settings.from_params({**MAIN_PARAMS, "mask_post_text": "full"}).masking.post_mask.mode == "Full"
    assert Settings.from_params(MAIN_PARAMS).masking.post_mask.mode == "Off"
    with pytest.raises(DemistoException, match="'Mask dark web post text' must be one of Off, Partial, Full, got 'Half'"):
        Settings.from_params({**MAIN_PARAMS, "mask_post_text": "Half"})


NOW = datetime(2026, 10, 10, tzinfo=UTC)


def test_the_record_age_filter_skips_old_records_by_their_collections_date_and_keeps_undated_ones():
    record_filter = GroupIBTIA.RecordFilter.from_params({"max_record_age_days": "30"})
    assert record_filter.accepts("compromised/messenger", _parsed("compromised/messenger"), NOW)
    assert not record_filter.accepts("compromised/messenger", _parsed("compromised/messenger", 1), NOW)
    assert not record_filter.accepts("darkweb/forums", _parsed("darkweb/forums", 1), NOW)
    undated = {**_parsed("compromised/discord"), "postDate": None}
    assert record_filter.accepts("compromised/discord", undated, NOW)
    # Every collection is held to its own date: a public post to its creation, a vulnerability to its publication,
    # whatever its modification date.
    old_post = {**_parsed("hi/open_threats"), "createdAt": "2000-01-01T00:00:00Z", "dateDetected": "2000-01-02T00:00:00Z"}
    assert not record_filter.accepts("hi/open_threats", old_post, NOW)
    # A threat report is aged by its publication date, which the parser reads for hi/threat as for apt/threat.
    assert _parsed("hi/threat").get("datePublished")
    report = {**_parsed("hi/threat"), "datePublished": "2026-10-01", "createdAt": "2000-01-01T00:00:00Z"}
    assert record_filter.accepts("hi/threat", report, NOW)
    recent = {**_parsed("osi/vulnerability"), "datePublished": "2026-10-01T00:00:00Z", "dateModified": "2000-01-01T00:00:00Z"}
    assert record_filter.accepts("osi/vulnerability", recent, NOW)
    updated = {**recent, "datePublished": "2000-01-01T00:00:00Z", "dateModified": "2026-10-09T00:00:00Z"}
    assert not record_filter.accepts("osi/vulnerability", updated, NOW)
    # 0 or empty keeps every record.
    assert GroupIBTIA.RecordFilter.from_params({"max_record_age_days": "0"}).accepts(
        "darkweb/forums", _parsed("darkweb/forums", 1), NOW
    )
    assert GroupIBTIA.RecordFilter.from_params({}).accepts("darkweb/forums", _parsed("darkweb/forums", 1), NOW)


def test_the_forum_category_filters_match_any_category_whatever_its_case():
    categorized, uncategorized = _parsed("darkweb/forums"), _parsed("darkweb/forums", 1)
    fetch = GroupIBTIA.RecordFilter.from_params({"darkweb_forum_categories": "access, Database"})
    assert fetch.accepts("darkweb/forums", categorized, NOW)
    assert not fetch.accepts("darkweb/forums", uncategorized, NOW)
    skip = GroupIBTIA.RecordFilter.from_params({"darkweb_forum_excluded_categories": "SALE"})
    assert not skip.accepts("darkweb/forums", categorized, NOW)
    assert skip.accepts("darkweb/forums", uncategorized, NOW)
    both = GroupIBTIA.RecordFilter.from_params(
        {"darkweb_forum_categories": "access", "darkweb_forum_excluded_categories": "sale"}
    )
    assert not both.accepts("darkweb/forums", categorized, NOW)
    # Categories are a forum thing: a Telegram post is never held to them.
    assert fetch.accepts("compromised/messenger", _parsed("compromised/messenger"), NOW)


def test_the_open_threat_source_types_and_the_minimum_severity_select_posts():
    blog, social = _parsed("hi/open_threats"), _parsed("hi/open_threats", 1)
    blogs = GroupIBTIA.RecordFilter.from_params({"open_threats_source_types": ["Blog"]})
    assert blogs.accepts("hi/open_threats", blog, NOW)
    assert not blogs.accepts("hi/open_threats", social, NOW)
    posts = GroupIBTIA.RecordFilter.from_params({"open_threats_source_types": "social network"})
    assert not posts.accepts("hi/open_threats", blog, NOW)
    assert posts.accepts("hi/open_threats", social, NOW)
    medium = GroupIBTIA.RecordFilter.from_params({"min_severity": "Medium"})
    assert medium.accepts("hi/open_threats", blog, NOW)
    assert not medium.accepts("hi/open_threats", social, NOW)
    high = GroupIBTIA.RecordFilter.from_params({"min_severity": "high"})
    assert not high.accepts("hi/open_threats", blog, NOW)
    # An unrated post counts as Low.
    assert medium.accepts("hi/open_threats", {**blog, "evaluation": {}}, NOW) is False
    assert GroupIBTIA.RecordFilter.from_params({"min_severity": "Low"}).accepts(
        "hi/open_threats", {**blog, "evaluation": {}}, NOW
    )
    # The minimum severity holds every collection whose records carry a rating; a collection without ratings passes.
    access = _parsed("compromised/access")
    assert high.accepts("compromised/access", access, NOW)
    assert not medium.accepts("compromised/access", {**access, "evaluation": {"severity": "green"}}, NOW)
    assert high.accepts("malware/cnc", _parsed("malware/cnc"), NOW)
    assert high.accepts("compromised/messenger", _parsed("compromised/messenger"), NOW)
    # For a malware profile it is the threat level.
    assert medium.accepts("malware/malware", {**_parsed("malware/malware"), "threatLevel": "High"}, NOW)
    assert not medium.accepts("malware/malware", {**_parsed("malware/malware"), "threatLevel": "low"}, NOW)


def test_the_record_filter_settings_are_validated():
    with pytest.raises(DemistoException, match="'Open threat source types': source_types takes Blog, Social Network, got forum"):
        GroupIBTIA.RecordFilter.from_params({"open_threats_source_types": "Blog, Forum"})
    with pytest.raises(DemistoException, match="'Minimum severity': min_severity takes Low, Medium or High, got 'red'"):
        GroupIBTIA.RecordFilter.from_params({"min_severity": "red"})
    with pytest.raises(DemistoException, match="'Skip records older than \\(days\\)': max_age_days must be zero or positive"):
        GroupIBTIA.RecordFilter.from_params({"max_record_age_days": "-1"})
    with pytest.raises(
        DemistoException, match="'Skip records older than \\(days\\)': max_age_days takes a whole number of days, got 'month'"
    ):
        GroupIBTIA.RecordFilter.from_params({"max_record_age_days": "month"})
    with pytest.raises(
        DemistoException, match="'Payment detail types to fetch': types takes Cryptocurrency Wallet, .*, got loyalty card"
    ):
        GroupIBTIA.RecordFilter.from_params({"spd_types": ["IBAN", "Loyalty Card"]})
    with pytest.raises(
        DemistoException, match="'Breached records to fetch': records takes all, password, credentials, got 'Some'"
    ):
        GroupIBTIA.RecordFilter.from_params({"breacheddb_records": "Some"})
    rules = Settings.from_params({**MAIN_PARAMS, "darkweb_forum_categories": " Access ,,sale"}).record_filter.rules
    assert rules == {"darkweb/forums": {"categories": {"access", "sale"}}}


def test_the_fetch_applies_the_record_filters_and_moves_the_cursor_past_the_skipped_records(mocker, single_session_fixture):
    client = single_session_fixture
    page = Parser({"count": 2, "items": _fixtures("compromised/messenger"), "seqUpdate": 1786482042688510}, [], [])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([page], None))
    debug = mocker.patch.object(GroupIBTIA.demisto, "debug")
    settings = settings_with(
        incident_collections=["compromised/messenger"],
        record_filter=GroupIBTIA.RecordFilter.from_params({"max_record_age_days": "30"}),
    )
    next_run, incidents = FetchIncidentsCommand(client, settings, clock=lambda: NOW.timestamp()).run({})
    assert [incident["name"] for incident in incidents] == ["Darkweb Telegram: Sample Market"]
    assert next_run["last_fetch"]["compromised/messenger"] == "1786482042688510"
    assert "[fetch-incidents] compromised/messenger: 1 record(s) skipped by the instance filters" in [
        call.args[0] for call in debug.call_args_list
    ]


class _ForumFeed(_UpdateFeed):
    """The forums route: records strictly above the cursor, each page answering its lowest record cursor."""

    def send_request(self, endpoint, params=None, **kwargs):
        body = super().send_request(endpoint, params, **kwargs)
        if endpoint == "darkweb/forums/updated" and body["items"]:
            body["seqUpdate"] = min(item["seqUpdate"] for item in body["items"])
        return body


def _forum_posts(*cursors: int) -> list[dict]:
    posts = _fixtures("darkweb/forums")
    return [{**posts[0], "id": f"{index:040x}", "seqUpdate": cursor} for index, cursor in enumerate(cursors)]


def _forum_client(mocker: Any, client: Client, feed: _UpdateFeed) -> Client:
    client.rate_limit_delay = 0
    mocker.patch.object(client.poller, "send_request", side_effect=feed.send_request)
    mocker.patch.object(client, "granted_collections", return_value=[])
    return client


def test_a_forum_fetch_stands_below_the_highest_record_cursor_and_reads_one_page_per_run(mocker, single_session_fixture):
    """The forums feed answers the lowest cursor of a page: a fetch that stored it would read the page again."""
    feed = _ForumFeed({"darkweb/forums": _forum_posts(1779670773451213, 1779670773451299, 1779670773451400)})
    client = _forum_client(mocker, single_session_fixture, feed)
    client.limit = 2
    next_run, incidents = fetch_incidents(
        client, {"last_fetch": {"darkweb/forums": "1779670773451000"}}, ["darkweb/forums"], max_requests=3
    )
    assert len(incidents) == 2
    assert len(feed.sent_to("darkweb/forums/updated")) == 1
    assert next_run["last_fetch"]["darkweb/forums"] == "1779670773451298"
    assert len(next_run["boundary_keys"]["darkweb/forums"]) == 1


@pytest.mark.parametrize("limit", [1, 2, 3, 100])
def test_forum_posts_that_share_a_cursor_are_fetched_once_over_several_runs(mocker, single_session_fixture, limit):
    posts = _forum_posts(100, 200, 200, 200, 300, 400, 400, 500)
    client = _forum_client(mocker, single_session_fixture, _ForumFeed({"darkweb/forums": posts}))
    client.limit = limit
    last_run: dict = {"last_fetch": {"darkweb/forums": "50"}}
    ids = []
    for _ in range(len(posts) + 2):
        last_run, incidents = fetch_incidents(client, last_run, ["darkweb/forums"], max_requests=3)
        ids.extend(json.loads(incident["rawJSON"])["id"] for incident in incidents)
    assert sorted(ids) == [post["id"] for post in posts]


def test_a_caught_up_forum_fetch_keeps_its_cursor_and_repeats_no_post(mocker, single_session_fixture):
    client = _forum_client(mocker, single_session_fixture, _ForumFeed({"darkweb/forums": _forum_posts(100, 200)}))
    last_run, incidents = fetch_incidents(client, {"last_fetch": {"darkweb/forums": "50"}}, ["darkweb/forums"], max_requests=3)
    assert len(incidents) == 2
    again, repeated = fetch_incidents(client, last_run, ["darkweb/forums"], max_requests=3)
    assert repeated == []
    assert again["last_fetch"]["darkweb/forums"] == last_run["last_fetch"]["darkweb/forums"] == "199"


def test_a_forum_page_without_record_cursors_takes_the_position_it_answers():
    body = {"count": 1, "items": [{"id": "x"}], "seqUpdate": 7000}
    server = MagicMock()
    server.create_update_generator.side_effect = lambda **_: iter([Parser(body, [], [])])
    walk = GroupIBTIA.BoundaryPages(server, "darkweb/forums", GroupIBTIA.TIRequestParams(limit=10), 6000, (), 0)
    assert next(iter(walk)).sequpdate == 6999


def test_the_dark_web_collections_count_as_filtered_by_hunting_rules_and_open_threats_take_the_flag(
    mocker, single_session_fixture
):
    client = single_session_fixture
    mocker.patch.object(client, "hunting_rules_collections", return_value=frozenset({"hi/open_threats", "compromised/messenger"}))
    fetch = FetchIncidentsCommand(client, fetch_settings(list(DARKWEB_AND_OPEN_THREAT_COLLECTIONS), hunting_rules=True))
    assert fetch._hunting_rules("hi/open_threats") == 1
    assert fetch._hunting_rules("compromised/access") is None
    assert fetch._hunting_rules("compromised/discord") is None
    assert (
        FetchIncidentsCommand(client, fetch_settings(list(DARKWEB_AND_OPEN_THREAT_COLLECTIONS)))._hunting_rules("hi/open_threats")
        is None
    )
    for collection in DARKWEB_COLLECTIONS:
        assert COLLECTIONS[collection].server_scoped
    assert not COLLECTIONS["hi/open_threats"].server_scoped


@pytest.mark.parametrize("collection", DARKWEB_AND_OPEN_THREAT_COLLECTIONS)
def test_the_lookups_of_the_dark_web_and_open_threat_collections_read_the_record_by_its_id(
    mocker, single_session_fixture, collection
):
    client = single_session_fixture
    records = _fixtures(collection)
    search = mocker.patch.object(client, "search_collection", return_value=iter([Parser({"count": 2, "items": records}, [], [])]))
    [entry, *rest] = lookup(client, collection, {"id": records[1]["id"]})
    assert search.call_args.kwargs["query"] == f"id:{records[1]['id']}"
    assert entry.outputs_prefix == COLLECTIONS[collection].context_prefix
    assert entry.outputs["id"] == records[1]["id"]
    assert entry.outputs["portalLink"].startswith("https://tap.group-ib.com/")
    indicators = [result for result in rest if result.outputs is not None]
    assert bool(indicators) == (collection == "hi/open_threats")
    with pytest.raises(DemistoException, match=f"No record with id 'missing' was found in {collection}"):
        mocker.patch.object(client, "search_collection", return_value=iter([Parser({"count": 0, "items": []}, [], [])]))
        lookup(client, collection, {"id": "missing"})


def test_the_open_threat_lookup_returns_an_entry_for_each_indicator_type(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(
        client, "search_collection", return_value=iter([Parser({"count": 1, "items": _fixtures("hi/open_threats")[:1]}, [], [])])
    )
    view = present_record(client, "hi/open_threats", _fixtures("hi/open_threats")[0]["id"])
    assert view.record["text"] == "Sample Group spreads Sample Stealer through fake installers."
    assert {result.readable_output.split("\n", 1)[0] for result in view.indicators} == {
        "### IP indicators",
        "### Domain indicators",
        "### File indicators",
        "### CVE indicators",
        "### Cryptocurrency indicators",
    }
    assert "c2.example" in str(_context_objects(view.indicators, "Domain"))


def test_every_dark_web_and_open_threat_collection_is_selectable_searchable_and_has_a_lookup_command():
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        yml = yml_file.read()
    [options] = [block for block in yml.split("\n- ") if "\n  name: incident_collections\n" in block]
    commands = yml.split("\n  - arguments:\n")
    [local_search_command] = [command for command in commands if "\n    name: gibti-local-search\n" in command]
    listed = [line.strip() for line in options.split("options:\n", 1)[1].splitlines()]
    for collection in DARKWEB_AND_OPEN_THREAT_COLLECTIONS:
        assert f"- {collection}" in listed
        assert f"      - {collection}\n" in local_search_command
        [command_name] = [name for name, target in LOOKUP_COMMANDS.items() if target == collection]
        assert f"\n    name: {command_name}\n" in yml
        assert COLLECTIONS[collection].mapping
        assert COLLECTIONS[collection].lookup_route == "id query"
    assert set(LOOKUP_COMMANDS) >= {
        "gibti-get-compromised-access-info",
        "gibti-get-darkweb-telegram-info",
        "gibti-get-darkweb-discord-info",
        "gibti-get-darkweb-forum-info",
        "gibti-get-open-threat-info",
    }


def test_the_dark_web_and_open_threat_lookups_declare_the_outputs_they_write():
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        commands = yml_file.read().split("\n  - arguments:\n")
    for collection in DARKWEB_AND_OPEN_THREAT_COLLECTIONS:
        [command_name] = [name for name, target in LOOKUP_COMMANDS.items() if target == collection]
        [command] = [command for command in commands if f"\n    name: {command_name}\n" in command]
        declared = set(re.findall(r"contextPath: (\S+)", command))
        prefix = COLLECTIONS[collection].context_prefix
        written = set()
        for index in range(len(_fixtures(collection))):
            record = IncidentBuilder.portal_link(collection, IncidentBuilder.shape(collection, _parsed(collection, index)))
            for key, value in record.items():
                if key == "indicators" or value is None:
                    continue
                if isinstance(value, dict):
                    written |= {f"{prefix}.{key}.{column}" for column in value}
                else:
                    written.add(f"{prefix}.{key}")
        assert written - declared == set(), collection


def _full_indicator_record(collection: str) -> dict:
    """A record whose indicator block holds a value for every key the collection maps to an indicator."""
    values = {
        "ipv4": "198.51.100.7",
        "ip": "198.51.100.7",
        "cnc_ipv4_ip": "198.51.100.7",
        "ipv4_ip": "198.51.100.7",
        "event_ipv4": "198.51.100.7",
        "email_sender_ip": "198.51.100.7",
        "ipv6": "2001:db8::7",
        "ipv6_ip": "2001:db8::7",
        "domain": "sample.example",
        "cnc_domain": "sample.example",
        "event_domain": "sample.example",
        "url": "http://sample.example/a",
        "cnc_url": "http://sample.example/a",
        "event_url": "http://sample.example/a",
        "hashes_sha256": "a" * 64,
        "file_sha256": "a" * 64,
        "hash": "a" * 64,
        "hashes_sha1": "b" * 40,
        "file_sha1": "b" * 40,
        "hashes_md5": "c" * 32,
        "file_md5": "c" * 32,
        "hashes_sha512": "d" * 128,
        "file_sha512": "d" * 128,
        "email_address": "drop@example.com",
        "emails": "drop@example.com",
        "cve": "CVE-2021-44228",
        "id": "CVE-2021-44228",
        "wallet": BTC_LEGACY,
        "value_value": BTC_LEGACY,
        "tlp": "amber",
        "type": "Cryptocurrency Wallet",
        "illegal_score": 90,
        "size": 10,
        "merged_cvss": 9.1,
        "cvss_score": 7.5,
    }
    types = GroupIBTIA.CollectionSpec.of(collection).indicator_types
    block = {}
    for key in types["types"]:
        block[key] = values.get(key, "sample")
        for source in types.get("add_fields_types", {}).get(key, {}):
            block.setdefault(source, values.get(source, f"sample {source}"))
    return {"id": "rec-1", "name": "Sample", "indicators": block, "evaluation": {"tlp": "amber", "severity": "red"}}


def _context_paths(indicator) -> set[str]:
    """The context paths an indicator writes, without the DT selectors."""
    paths: set[str] = set()

    def walk(value, prefix):
        if isinstance(value, dict):
            for key, inner in value.items():
                walk(inner, f"{prefix}.{key}")
        elif isinstance(value, list):
            for inner in value:
                walk(inner, prefix)
        else:
            paths.add(prefix)

    for path, value in indicator.to_context().items():
        walk(value, path.split("(")[0])
    return paths


def test_every_lookup_declares_the_indicator_outputs_it_writes():
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        commands = yml_file.read().split("\n  - arguments:\n")
    checked = 0
    for command_name, collection in LOOKUP_COMMANDS.items():
        if not GroupIBTIA.CollectionSpec.of(collection).indicator_types.get("types"):
            continue
        written: set[str] = set()
        for item in IndicatorBuilder("C - Fairly reliable").items(_full_indicator_record(collection), collection):
            written |= _context_paths(item.indicator)
        for name in (command_name, command_name.replace("gibti-", "gibtia-", 1)):
            blocks = [block for block in commands if f"\n    name: {name}\n" in block]
            if not blocks:
                continue
            declared = set(re.findall(r"contextPath: (\S+)", blocks[0]))
            assert written - declared == set(), name
            checked += 1
    assert checked >= 20


def test_a_forum_post_gets_no_deleted_date_key():
    assert "deletedDate" not in IncidentBuilder.shape("darkweb/forums", _parsed("darkweb/forums", 1))
    assert "deletedDate" in IncidentBuilder.shape("compromised/messenger", _parsed("compromised/messenger"))


def test_the_dark_web_and_open_threat_incident_types_extract_indicators_from_open_threats_only():
    """A post can quote the victim's own e-mail addresses and hosts, and a shop listing names the victim's host:
    nothing is extracted from either."""
    types = {item["name"]: item for item in _pack_items("IncidentTypes")}
    for name in ("GIB Compromised Access", "GIB Darkweb Telegram", "GIB Darkweb Discord", "GIB Darkweb Forum"):
        assert types[name]["extractSettings"] == {"fieldCliNameToExtractSettings": {}, "mode": "Specific"}
    assert types["GIB Open Threat"]["extractSettings"]["fieldCliNameToExtractSettings"] == {
        "gibrelatedindicatorsdata": {
            "extractAsIsIndicatorTypeId": "",
            "extractIndicatorTypesIDs": [],
            "isExtractingAllIndicatorTypes": True,
        }
    }


def test_the_dark_web_and_open_threat_settings_name_the_collections_the_modes_the_options_and_the_default():
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        blocks = yml_file.read().split("\n- ")
    [mask] = [block for block in blocks if "\n  name: mask_post_text\n" in block]
    for text in (
        "compromised/messenger",
        "compromised/discord",
        "darkweb/forums",
        "GIB Post Text",
        "  - 'Off'",
        "  - Partial",
        "  - Full",
        "last four digits",
    ):
        assert text in mask
    [age] = [block for block in blocks if "\n  name: max_record_age_days\n" in block]
    assert "post date of a dark web post" in age
    [categories] = [block for block in blocks if "\n  name: darkweb_forum_categories\n" in block]
    assert "Works only for darkweb/forums" in categories
    assert "monitoring label" in categories
    [sources] = [block for block in blocks if "\n  name: open_threats_source_types\n" in block]
    assert "  - Blog\n  - Social Network\n" in sources
    [severity] = [block for block in blocks if "\n  name: min_severity\n" in block]
    assert "  - Low\n  - Medium\n  - High\n" in severity
    assert "defaultvalue: Low" in severity
    [hunting] = [block for block in blocks if "\n  name: hunting_rules\n" in block]
    assert "hi/open_threats" in hunting
    assert "darkweb/forums" in hunting


FILTERS = GroupIBTIA.FILTERS
# One sample value per filter kind; an include filter with a closed set takes its first option instead,
# and a query filter with fields takes a query on one of its fields.
SAMPLE_VALUES = {
    "include": "x",
    "exclude": "x",
    "contains": "x",
    "min": "5",
    "max": "5",
    "age": "30",
    "severity": "Medium",
    "flag": "true",
    "choice": "credentials",
    "networks": "192.0.2.0/24",
    "query": "word",
}


def _rules(lines: str, **params: Any) -> GroupIBTIA.RecordFilter:
    return GroupIBTIA.RecordFilter.from_params({**params, "collection_filters": lines})


def test_a_report_whose_only_observable_is_a_sha512_or_a_sender_ip_carries_indicators():
    silent = {**_parsed("apt/threat"), "indicators": {}}
    rules = _rules("apt/threat: with_iocs_only = true")
    assert not rules.accepts("apt/threat", silent, NOW)
    for key in ("hashes_sha512", "email_sender_ip"):
        assert rules.accepts("apt/threat", {**silent, "indicators": {key: ["value"]}}, NOW), key


def test_every_collection_the_fetch_reads_has_filters_and_every_filter_reads_its_fixture():
    assert set(FILTERS) == {name for name, spec in COLLECTIONS.items() if spec.mapping}
    for collection, specs in FILTERS.items():
        assert "max_age_days" in specs or collection == "malware/malware", collection
        if collection not in COLLECTIONS_RAW_JSON:
            continue
        records = [_parsed(collection, index) for index in range(len(_fixtures(collection)))]
        for spec in specs.values():
            value = spec.options[0] if spec.options and spec.kind == "include" else SAMPLE_VALUES[spec.kind]
            value = 'forum:"x"' if spec.kind == "query" and spec.options else value
            record_filter = _rules(f"{collection}: {spec.name} = {value}")
            assert record_filter.rules[collection].keys() == {spec.name}
            for record in records:
                spec.read(record)
                assert record_filter.accepts(collection, record, NOW) in (True, False)


def test_collection_filters_lines_are_parsed_over_the_settings_with_patterns_comments_and_clearing():
    record_filter = _rules(
        "# everything of the last month, the compromised collections of the last week, forum posts of any age\n"
        "*: max_age_days = 30\n"
        "# every compromised collection\n"
        "compromised/*: max_age_days = 7\n"
        "darkweb/forums: max_age_days =\n"
        "suspicious_ip/*: excluded_countries = US, de\n"
        "OSI/vulnerability: Min_CVSS = 7.5\n",
        max_record_age_days="365",
    )
    assert record_filter.rules["osi/vulnerability"] == {"max_age_days": 30, "min_cvss": 7.5}
    assert record_filter.rules["compromised/access"] == {"max_age_days": 7}
    assert "max_age_days" not in record_filter.rules["darkweb/forums"]
    assert record_filter.rules["suspicious_ip/vpn"]["excluded_countries"] == {"us", "de"}
    assert record_filter.rules.get("malware/malware", {}) == {}
    assert record_filter.describe("suspicious_ip/vpn") == "max_age_days=30; excluded_countries=de,us"
    assert _rules("").rules == {}
    assert _rules("osi/vulnerability: types = cve").rules == {"osi/vulnerability": {"types": {"cve"}}}
    # A # inside a value is part of it: only a whole line is a comment.
    assert _rules('darkweb/forums: query = message:"#sale"').rules == {"darkweb/forums": {"query": 'message:"#sale"'}}


@pytest.mark.parametrize(
    ("lines", "message"),
    [
        (
            "osi/vuln: types = cve",
            "Collection filters, line 1: unknown collection 'osi/vuln'. Collections: compromised/account_group",
        ),
        (
            "# the first line\nosi/vulnerability: typo = cve",
            "line 2: osi/vulnerability has no filter 'typo'; its filters: min_severity, max_age_days, types",
        ),
        ("suspicious_ip/*: brands = x", "line 1: suspicious_ip/\\* has no filter 'brands'; its filters: see the README"),
        ("osi/vulnerability types = cve", "line 1: expected 'collection: filter = value', got 'osi/vulnerability types = cve'"),
        ("osi/vulnerability: min_cvss = high", "line 1: min_cvss takes a number, got 'high'"),
        ("osi/vulnerability: min_cvss = -1", "line 1: min_cvss must be zero or positive"),
        ("*: min_severity = critical", "line 1: min_severity takes Low, Medium or High, got 'critical'"),
        ("osi/vulnerability: has_exploit = maybe", "line 1: has_exploit takes true or false, got 'maybe'"),
        (
            "malware/cnc: excluded_networks = 192.0.2.0/24, example",
            "line 1: excluded_networks takes addresses and CIDR networks, got 'example'",
        ),
        ("compromised/breacheddb: records = some", "line 1: records takes all, password, credentials, got 'some'"),
        ("compromised/spd: types = loyalty", "line 1: types takes Cryptocurrency Wallet, Bank Account Number, .*, got loyalty"),
        (
            'darkweb/forums: query = categories:"Access"',
            "line 1: query does not take the query field 'categories' here; use id, forum, nickname",
        ),
        (
            "hi/threat_actor: query = name:Sample",
            "line 1: query does not take the query field 'name' here; it takes a bare value",
        ),
    ],
)
def test_a_collection_filters_line_that_the_integration_cannot_apply_is_refused_with_its_line(lines, message):
    with pytest.raises(DemistoException, match=message):
        _rules(lines)
    # The instance settings carry the filters: a bad line fails every command.
    with pytest.raises(DemistoException, match=message):
        Settings.from_params({**MAIN_PARAMS, "collection_filters": lines})


def test_the_filter_kinds_decide_as_the_readme_says():
    vulnerability = {
        **_parsed("osi/vulnerability"),
        "type": "cve",
        "mergedCvss": 7.2,
        "epssPercentile": 0.95,
        "hasExploit": False,
    }
    # include: a record needs one of the values; without the value it is skipped.
    assert _rules("osi/vulnerability: types = CVE, mscve").accepts("osi/vulnerability", vulnerability, NOW)
    assert not _rules("osi/vulnerability: types = nessus").accepts("osi/vulnerability", vulnerability, NOW)
    assert not _rules("osi/vulnerability: types = cve").accepts("osi/vulnerability", {**vulnerability, "type": None}, NOW)
    # exclude: a record with one of the values is skipped; without the value it passes.
    assert not _rules("osi/vulnerability: excluded_types = CVE").accepts("osi/vulnerability", vulnerability, NOW)
    assert _rules("osi/vulnerability: excluded_types = nessus").accepts("osi/vulnerability", {**vulnerability, "type": None}, NOW)
    # min and max: a record without the number passes.
    assert _rules("osi/vulnerability: min_cvss = 7").accepts("osi/vulnerability", vulnerability, NOW)
    assert not _rules("osi/vulnerability: min_cvss = 7.5").accepts("osi/vulnerability", vulnerability, NOW)
    assert _rules("osi/vulnerability: min_cvss = 9").accepts(
        "osi/vulnerability", {**vulnerability, "mergedCvss": None, "cvss": {}}, NOW
    )
    # a CVSS score of 0 without a vector is unknown, so the record passes too; with a vector it is a real 0
    assert _rules("osi/vulnerability: min_cvss = 9").accepts(
        "osi/vulnerability", {**vulnerability, "mergedCvss": 0, "cvss": {"score": 0, "vector": "NONE"}}, NOW
    )
    assert not _rules("osi/vulnerability: min_cvss = 9").accepts(
        "osi/vulnerability",
        {**vulnerability, "mergedCvss": 0, "mergedCvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "cvss": {}},
        NOW,
    )
    assert _rules("osi/vulnerability: min_epss_percentile = 90").accepts("osi/vulnerability", vulnerability, NOW)
    assert not _rules("osi/vulnerability: min_epss_percentile = 96").accepts("osi/vulnerability", vulnerability, NOW)
    # flag: true keeps the records the condition holds for; false is no filter.
    assert not _rules("osi/vulnerability: has_exploit = true").accepts("osi/vulnerability", vulnerability, NOW)
    assert _rules("osi/vulnerability: has_exploit = yes").accepts("osi/vulnerability", {**vulnerability, "hasExploit": True}, NOW)
    assert _rules("osi/vulnerability: has_exploit = false").rules == {}
    # contains: a record passes when one of its texts holds one of the values.
    report = {**_parsed("hi/threat"), "targeted_companies": ["Sample Bank plc", "Other"]}
    assert _rules("hi/threat: targeted_companies = bank").accepts("hi/threat", report, NOW)
    assert not _rules("hi/threat: targeted_companies = insurance").accepts("hi/threat", report, NOW)
    # choice: breached records with a password or a credential column.
    breach = {**_parsed("compromised/breacheddb"), "hasPassword": True}
    assert _rules("compromised/breacheddb: records = credentials").accepts("compromised/breacheddb", breach, NOW)
    assert not _rules("compromised/breacheddb: records = password").accepts(
        "compromised/breacheddb", {**breach, "hasPassword": False}, NOW
    )
    assert _rules("compromised/breacheddb: records = all").rules == {}
    # networks: an address inside a listed network is skipped; a text that is no address passes.
    listing = _parsed("suspicious_ip/socks_proxy")
    assert not _rules(f"suspicious_ip/socks_proxy: excluded_networks = {listing['name']}/24").accepts(
        "suspicious_ip/socks_proxy", listing, NOW
    )
    assert _rules("suspicious_ip/socks_proxy: excluded_networks = 203.0.113.0/24").accepts(
        "suspicious_ip/socks_proxy", listing, NOW
    )
    assert _rules("suspicious_ip/socks_proxy: excluded_networks = 203.0.113.0/24").accepts(
        "suspicious_ip/socks_proxy", {**listing, "name": "host"}, NOW
    )
    # A domain filter matches the domain and its subdomains.
    account = {**_parsed("compromised/account_group"), "service": {"domain": "mail.victim.example"}}
    assert _rules("compromised/account_group: service_domains = victim.example").accepts(
        "compromised/account_group", account, NOW
    )
    assert not _rules("compromised/account_group: service_domains = notvictim.example").accepts(
        "compromised/account_group", account, NOW
    )
    # query: sent to the API, never applied to a record.
    assert _rules('darkweb/forums: query = forum:"x.example"').accepts("darkweb/forums", _parsed("darkweb/forums"), NOW)


def test_the_payment_detail_filters_read_the_country():
    detail = {"id": "spd-1", "type": "IBAN", "country": "US"}
    assert _rules("compromised/spd: countries = us").accepts("compromised/spd", detail, NOW)
    assert not _rules("compromised/spd: countries = DE").accepts("compromised/spd", detail, NOW)
    assert MAPPING["compromised/spd"]["country"] == "country"


def test_the_listing_filters_read_the_shapes_of_each_suspicious_ip_collection_and_the_cnc_platform():
    scanner = {**_parsed("suspicious_ip/scanner"), "categories": ["Brute-Force", "Web Spam"]}
    assert _rules("suspicious_ip/scanner: categories = brute force").accepts("suspicious_ip/scanner", scanner, NOW)
    assert not _rules("suspicious_ip/scanner: excluded_categories = web_spam").accepts("suspicious_ip/scanner", scanner, NOW)
    proxy = {**_parsed("suspicious_ip/open_proxy"), "type": "SOCKS4, SOCKS5", "sources": ["a", "b"], "port": 1080}
    assert _rules("suspicious_ip/open_proxy: types = socks5").accepts("suspicious_ip/open_proxy", proxy, NOW)
    assert not _rules("suspicious_ip/open_proxy: types = http").accepts("suspicious_ip/open_proxy", proxy, NOW)
    assert _rules("suspicious_ip/open_proxy: ports = 1080, 8080").accepts("suspicious_ip/open_proxy", proxy, NOW)
    assert not _rules("suspicious_ip/open_proxy: min_sources = 3").accepts("suspicious_ip/open_proxy", proxy, NOW)
    assert _rules("suspicious_ip/open_proxy: min_sources = 2").accepts("suspicious_ip/open_proxy", proxy, NOW)
    # An ASN matches with or without its AS prefix, in upper or lower case.
    relay = {**_parsed("suspicious_ip/socks_proxy"), "asn": "AS64501"}
    assert _rules("suspicious_ip/socks_proxy: asns = 64501").accepts("suspicious_ip/socks_proxy", relay, NOW)
    assert _rules("suspicious_ip/socks_proxy: asns = as64501, AS64502").accepts("suspicious_ip/socks_proxy", relay, NOW)
    assert not _rules("suspicious_ip/socks_proxy: excluded_asns = 64501").accepts("suspicious_ip/socks_proxy", relay, NOW)
    assert _rules("suspicious_ip/socks_proxy: excluded_asns = 64502").accepts("suspicious_ip/socks_proxy", relay, NOW)
    vpn = {**_parsed("suspicious_ip/vpn"), "types": ["self-hosted"], "names": ["Sample VPN"], "asn": "AS64500"}
    assert _rules("suspicious_ip/vpn: types = Self-Hosted").accepts("suspicious_ip/vpn", vpn, NOW)
    assert not _rules("suspicious_ip/vpn: excluded_names = sample vpn").accepts("suspicious_ip/vpn", vpn, NOW)
    assert _rules("suspicious_ip/vpn: asns = AS64500").accepts("suspicious_ip/vpn", vpn, NOW)
    assert not _rules("suspicious_ip/vpn: excluded_asns = as64500").accepts("suspicious_ip/vpn", vpn, NOW)
    # A Tor relay's flags, and its country and AS when it has none of its own, come from its newest consensus state.
    states = [{"data": {"dateLastSeen": "2026-01-01", "flags": ["Guard", "Exit"], "country": "de", "as": "AS64501"}}]
    relay = {**_parsed("suspicious_ip/tor_node"), "countryCode": None, "asn": None, "nodes": [{"states": states}]}
    assert _rules("suspicious_ip/tor_node: exit_only = true").accepts("suspicious_ip/tor_node", relay, NOW)
    assert _rules("suspicious_ip/tor_node: flags = exit").accepts("suspicious_ip/tor_node", relay, NOW)
    assert _rules("suspicious_ip/tor_node: countries = DE").accepts("suspicious_ip/tor_node", relay, NOW)
    assert _rules("suspicious_ip/tor_node: asns = 64501").accepts("suspicious_ip/tor_node", relay, NOW)
    assert _rules("suspicious_ip/tor_node: asns = AS64501").accepts("suspicious_ip/tor_node", relay, NOW)
    bad_exit = {**relay, "nodes": [{"states": [{"data": {**states[0]["data"], "flags": ["Exit", "BadExit"]}}]}]}
    assert not _rules("suspicious_ip/tor_node: exit_only = true").accepts("suspicious_ip/tor_node", bad_exit, NOW)
    assert not _rules("suspicious_ip/tor_node: exit_only = true").accepts("suspicious_ip/tor_node", {**relay, "nodes": []}, NOW)
    # The filter reads the platform value "Winsows" as Windows.
    cnc = {**_parsed("malware/cnc"), "platform": "Winsows"}
    assert _rules("malware/cnc: platforms = windows").accepts("malware/cnc", cnc, NOW)


def test_the_settings_compile_into_rules_for_every_collection_that_has_the_filter():
    record_filter = GroupIBTIA.RecordFilter.from_params(
        {
            "min_severity": "Medium",
            "max_record_age_days": "10",
            "vulnerability_types": "CVE, MSCVE",
            "vulnerability_excluded_types": "nessus",
            "vulnerability_has_exploit": True,
            "breacheddb_records": "With a password or a credential column",
            "spd_types": ["IBAN", "Bank Card"],
            "darkweb_forum_excluded_categories": "Sale",
        }
    )
    assert {name for name, rules in record_filter.rules.items() if "min_severity" in rules} == {
        name for name, specs in FILTERS.items() if "min_severity" in specs
    }
    assert "min_severity" not in record_filter.rules.get("compromised/messenger", {})
    assert record_filter.rules["osi/vulnerability"] == {
        "min_severity": 2,
        "max_age_days": 10,
        "types": {"cve", "mscve"},
        "excluded_types": {"nessus"},
        "has_exploit": True,
    }
    assert record_filter.rules["compromised/breacheddb"]["records"] == "credentials"
    assert record_filter.rules["compromised/spd"]["types"] == {"iban", "bank card"}
    assert record_filter.rules["darkweb/forums"] == {"max_age_days": 10, "excluded_categories": {"sale"}}
    # Low and an empty value set no rule; a checkbox that is off sets none.
    assert (
        GroupIBTIA.RecordFilter.from_params(
            {"min_severity": "Low", "max_record_age_days": "", "vulnerability_has_exploit": False}
        ).rules
        == {}
    )


@pytest.mark.parametrize(
    ("collection", "params", "expected", "absent"),
    [
        (
            "osi/vulnerability",
            {"vulnerability_types": "mscve, cve", "vulnerability_has_exploit": True},
            {"q": 'type:"cve" OR type:"mscve"', "apply_has_exploit": 1},
            ("unique", "combolist", "probable_corporate_access"),
        ),
        ("osi/vulnerability", {"vulnerability_excluded_types": "nessus"}, {"q": '-type:"nessus"'}, ("apply_has_exploit",)),
        ("osi/vulnerability", {"vulnerability_excluded_types": "nessus, redhat"}, {}, ("q",)),
        ("compromised/breacheddb", {"breacheddb_records": "With a password"}, {"has_password": 1}, ()),
        ("compromised/breacheddb", {"breacheddb_records": "With a password or a credential column"}, {}, ("has_password",)),
        ("compromised/spd", {"spd_types": ["Bank Account Number"]}, {"type": "Bank Account Number"}, ()),
        ("compromised/spd", {"spd_types": ["IBAN", "Bank Card"]}, {}, ("type",)),
        (
            "darkweb/forums",
            {"collection_filters": 'darkweb/forums: query = nickname:"sample_seller"'},
            {"q": 'nickname:"sample_seller"'},
            (),
        ),
        ("hi/threat_actor", {"collection_filters": "hi/threat_actor: query = Sample Crew"}, {"q": "Sample Crew"}, ()),
        (
            "compromised/account_group",
            {"collection_filters": "*: min_severity = High"},
            {"unique": 0, "combolist": 0, "probable_corporate_access": 0},
            ("q",),
        ),
    ],
)
def test_the_fetch_asks_the_api_for_the_filtered_view_where_the_api_has_one(
    mocker, single_session_fixture, collection, params, expected, absent
):
    client = single_session_fixture
    client.limit, client.rate_limit_delay = 100, 0
    feed = _UpdateFeed()
    mocker.patch.object(client.poller, "send_request", side_effect=feed.send_request)
    mocker.patch.object(client, "granted_collections", return_value=[])
    settings = settings_with(incident_collections=[collection], record_filter=GroupIBTIA.RecordFilter.from_params(params))
    FetchIncidentsCommand(client, settings).run({"last_fetch": {collection: "5"}})
    [request] = feed.sent_to(f"{collection}/updated")
    assert {key: request[key] for key in expected} == expected
    assert not set(absent) & set(request)


def test_the_fetch_skips_the_records_the_filters_drop_and_logs_how_many(mocker, single_session_fixture):
    client = single_session_fixture
    items = _fixtures("osi/vulnerability")
    items[0]["type"], items[1]["type"], items[2]["type"] = "cve", "nessus", "mscve"
    page = Parser({"count": 3, "items": items, "seqUpdate": 1786482042688510}, [], [])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([page], None))
    debug = mocker.patch.object(GroupIBTIA.demisto, "debug")
    settings = settings_with(
        incident_collections=["osi/vulnerability"],
        record_filter=GroupIBTIA.RecordFilter.from_params({"vulnerability_excluded_types": "nessus"}),
    )
    next_run, incidents = FetchIncidentsCommand(client, settings, clock=lambda: NOW.timestamp()).run({})
    assert len(incidents) == 2
    assert next_run["last_fetch"]["osi/vulnerability"] == "1786482042688510"
    messages = [call.args[0] for call in debug.call_args_list]
    assert "[fetch-incidents] osi/vulnerability: 1 record(s) skipped by the instance filters" in messages


def test_the_malware_path_of_a_stealer_event_reaches_the_events_table_and_the_lookup_context():
    incident = json.loads(_incident("compromised/account_group")["rawJSON"])
    [event] = [row for row in incident["events_table"] if row.get("malwarepath")]
    assert event["malwarepath"] == "C:\\Users\\sample.user\\AppData\\Local\\Temp\\sample.exe"
    assert event["pcname"] == "DESKTOP-SAMPLE1"
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        yml = yml_file.read()
    assert yml.count("contextPath: GIBTI.CompromisedAccountGroup.events_table.malwarePath") == 2
    grid = os.path.join(realpath, "..", "..", "IncidentFields", "incidentfield-GIB_Compromised_Events_Information_Table.json")
    with open(grid) as handle:
        columns = {column["key"] for column in json.load(handle)["columns"]}
    assert "malwarepath" in columns


def test_a_tor_relay_incident_carries_the_newest_consensus_state_and_the_mapper_maps_the_tor_fields_and_vpn_types():
    states = [
        {"data": {"dateLastSeen": "2025-01-01", "flags": ["Guard"], "country": "de", "as": "AS64501"}},
        {"data": {"dateLastSeen": "2026-01-01", "flags": ["Exit", "Fast"], "country": "fr", "as": "AS64502"}},
    ]
    relay = {**_parsed("suspicious_ip/tor_node"), "nodes": [{"states": states}]}
    built = json.loads(IncidentBuilder().build("suspicious_ip/tor_node", relay)["rawJSON"])
    assert built["torFlags"] == ["Exit", "Fast"]
    assert built["torExit"] is True
    assert built["countryCode"] == "FR"
    bare = json.loads(
        IncidentBuilder().build("suspicious_ip/tor_node", {**_parsed("suspicious_ip/tor_node"), "nodes": []})["rawJSON"]
    )
    assert bare["torFlags"] is None
    assert bare["torExit"] is False
    mapper_path = os.path.join(realpath, "..", "..", "Classifiers", "classifier-Group-IB_Threat_Intelligence_mapper.json")
    with open(mapper_path) as handle:
        mapper = json.load(handle)["mapping"]
    for field_name, mapped in (("GIB Tor Flags", "torFlags"), ("GIB Tor Exit", "torExit"), ("GIB VPN Types", "types")):
        incident_type = "GIB Suspicious IP VPN" if mapped == "types" else "GIB Suspicious IP TOR Node"
        assert mapper[incident_type]["internalMapping"][field_name] == {"simple": mapped}


def test_the_readme_and_the_yml_declare_every_filter_and_setting():
    with open(f"{realpath}/README.md") as readme_file:
        readme = readme_file.read()
    for collection, specs in FILTERS.items():
        section = readme[readme.index(f"##### `{collection}`\n") :]
        section = section[: section.find("\n##### ", 1) if "\n##### " in section[1:] else len(section)]
        for name in specs:
            assert f"| `{name}` |" in section, (collection, name)
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        blocks = yml_file.read().split("\n- ")
    declared = {block.split("\n  name: ", 1)[1].split("\n", 1)[0] for block in blocks if "\n  name: " in block}
    assert {key for key, *_ in GroupIBTIA.RecordFilter.SETTINGS} | {"collection_filters"} <= declared
    [filters] = [block for block in blocks if "\n  name: collection_filters\n" in block]
    assert "type: 12" in filters
    assert "osi/vulnerability: min_cvss = 7" in filters
    [types] = [block for block in blocks if "\n  name: spd_types\n" in block]
    assert all(f"  - {option}\n" in types for option in GroupIBTIA.SPD_TYPES)
    [records] = [block for block in blocks if "\n  name: breacheddb_records\n" in block]
    assert "  - With a password or a credential column\n" in records
    assert "defaultvalue: All" in records


PHISHING_URL = "http://example.com/accounts-platform-a/c2?sort=expensive&page=1&size=30"


def _url_client(mocker, client, records: dict[str, list]):
    """A client whose collection searches answer ``records`` (collection -> records) and record the queries sent."""
    queries: dict[str, str] = {}

    def read(path, value, keys=None):
        queries[path] = value
        return records.get(path, [])

    mocker.patch.object(ReputationCommand, "_read", side_effect=read)
    mocker.patch.object(client.poller, "global_search", side_effect=AssertionError("a URL is no global search term"))
    client.url_queries = queries  # type: ignore[attr-defined]
    return client


def _url(client, value: str, **settings: Any) -> CommandResults:
    [result] = reputation(client, "url", {"url": value}, **settings)
    return result


def test_url_reputation_reads_only_ioc_primary_and_keeps_the_records_of_the_url_itself(mocker, single_session_fixture):
    records = {
        "ioc/primary": [
            {
                "count": 2,
                "items": [
                    {
                        "url": [{"url": "http://evil.example/login", "riskScore": 85}],
                        "malwareList": [{"name": "StealerOne"}],
                        "evaluation": {"TLP": "TLP:AMBER"},
                    },
                    {"url": [{"url": "http://evil.example/login/longer", "riskScore": 99}], "malwareList": [{"name": "Other"}]},
                ],
            }
        ],
        "malware/cnc": [{"cnc": "http://evil.example/login/", "url": "http://evil.example/login/", "domain": "evil.example"}],
    }
    client = _url_client(mocker, single_session_fixture, records)
    result = _url(client, "hxxp://evil[.]example/login/", override="C - Fairly reliable")
    assert client.url_queries == {"ioc/primary": '"http://evil.example/login/"'}
    assert result.indicator.url == "http://evil.example/login/"
    assert result.indicator.dbot_score.score == 3
    assert result.indicator.dbot_score.indicator_type == "url"
    # The record of the longer URL (risk score 99, malware family Other) belongs to another indicator.
    assert result.raw_response["collections"] == ["ioc/primary"]
    assert result.raw_response["riskScore"] == 85
    assert result.indicator.malware_family == ["StealerOne"]
    assert result.indicator.traffic_light_protocol == "AMBER"
    assert result.indicator.tags == ["ioc/primary"]
    assert "Group-IB reputation for" in result.readable_output


@pytest.mark.parametrize(
    ("records", "score", "tags", "reliability"),
    [
        ({"ioc/primary": [{"url": [{"url": "http://c2.example/gate.php"}]}]}, 2, ["ioc/primary"], "A - Completely reliable"),
        (
            {"ioc/primary": [{"url": [{"url": "http://c2.example/gate.php", "riskScore": 0}]}]},
            2,
            ["ioc/primary"],
            "A - Completely reliable",
        ),
        (
            {"ioc/primary": [{"url": [{"url": "http://c2.example/gate.php", "riskScore": 12}]}]},
            2,
            ["ioc/primary"],
            "A - Completely reliable",
        ),
        (
            {"ioc/primary": [{"url": [{"url": "http://c2.example/gate.php", "riskScore": 79}]}]},
            2,
            ["ioc/primary"],
            "A - Completely reliable",
        ),
        (
            {"ioc/primary": [{"url": [{"url": "http://c2.example/gate.php", "riskScore": 80}]}]},
            3,
            ["ioc/primary"],
            "A - Completely reliable",
        ),
        (
            {"ioc/primary": [{"url": [{"url": "http://c2.example/gate.php", "riskScore": 100}]}]},
            3,
            ["ioc/primary"],
            "A - Completely reliable",
        ),
        (
            {"ioc/primary": [{"url": [{"url": "http://c2.example/other", "riskScore": 100}]}]},
            0,
            None,
            "C - Fairly reliable",
        ),
        ({}, 0, None, "C - Fairly reliable"),
    ],
)
def test_url_reputation_is_bad_from_an_ioc_primary_risk_score_of_80_suspicious_below_it_or_without_one_and_unknown_with_no_record(
    mocker, single_session_fixture, records, score, tags, reliability
):
    client = _url_client(mocker, single_session_fixture, records)
    result = _url(client, "http://c2.example/gate.php")
    assert result.indicator.dbot_score.score == score
    assert result.indicator.tags == tags
    assert result.indicator.dbot_score.reliability == reliability
    if score == 0:
        assert "No Group-IB Threat Intelligence data was found" in result.readable_output


@pytest.mark.parametrize(
    "records",
    [
        {
            "malware/cnc": [
                {
                    "cnc": "http://c2.example/gate.php",
                    "url": "http://c2.example/gate.php",
                    "threatActor": [{"name": "Sample Crew"}],
                    "malwareList": [{"name": "Sample Loader"}],
                }
            ]
        },
        {
            "attacks/phishing_group": [
                {
                    "brand": "Sample Brand",
                    "phishing": [{"url": "http://c2.example/gate.php"}],
                    "threatActor": {"name": "Sample Kit Seller"},
                    "evaluation": {"tlp": "amber"},
                }
            ]
        },
    ],
)
def test_a_url_only_malware_cnc_or_attacks_phishing_group_lists_is_unknown_and_neither_is_read(
    mocker, single_session_fixture, records
):
    client = _url_client(mocker, single_session_fixture, records)
    result = _url(client, "http://c2.example/gate.php")
    assert client.url_queries == {"ioc/primary": '"http://c2.example/gate.php"'}
    assert result.indicator.dbot_score.score == 0
    assert (result.indicator.tags, result.indicator.malware_family, result.relationships) == (None, None, None)


def test_url_reputation_refuses_a_value_that_is_no_url_and_a_disabled_url_command(mocker, single_session_fixture):
    client = _url_client(mocker, single_session_fixture, {})
    result = _url(client, "evil.example/login")
    assert result.indicator is None
    assert "is not a URL" in result.readable_output
    assert client.url_queries == {}
    disabled = ReputationCommand("url", client, reputation_settings(enabled_reputation_commands=frozenset({"ip"}))).run(
        {"url": "http://evil.example/"}
    )
    assert isinstance(disabled, CommandResults)
    assert "the 'url' reputation command is disabled" in disabled.readable_output


def test_url_reputation_is_declared_and_routed(mocker):
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        yml = yml_file.read()
    [block] = [block for block in yml.split("\n  - ") if block.startswith("name: url\n")]
    for path in ("URL.Data", "URL.Tags", "URL.MalwareFamily", "URL.TrafficLightProtocol", "DBotScore.Score"):
        assert f"contextPath: {path}\n" in block
    [options] = [block for block in yml.split("\n- ") if "\n  name: enabled_reputation_commands\n" in block]
    assert options.endswith("  - file\n  - url")
    with open(f"{realpath}/README.md") as readme_file:
        readme = readme_file.read()
    assert "### url\n" in readme
    assert "#### `url` score rules" in readme
    with open(f"{realpath}/command_examples.txt") as examples:
        assert "!url url=" in examples.read()
    assert "url" in Settings.REPUTATION_COMMANDS
    run = mocker.patch.object(
        GroupIBTIA.ReputationCommand, "run", autospec=True, return_value=CommandResults(readable_output="ok")
    )
    run_main(mocker, {**MAIN_PARAMS, "enabled_reputation_commands": ["url"]}, "url", {"url": "http://evil.example/"})
    assert run.call_args.args[0].kind == "url"


# The generic sub-playbooks of the Cortex XSOAR content the pack's playbooks call.
STANDARD_SUB_PLAYBOOKS = {
    "Account Enrichment - Generic v2.1",
    "Block Account - Generic v2",
    "Block Domain - Generic v2",
    "Block Indicators - Generic v3",
    "Block URL - Generic v2",
    "CVE Enrichment - Generic v2",
    "Cloud Credentials Rotation - Generic",
    "Containment Plan - Clear User Sessions",
    "Eradication Plan - Reset Password",
    "GenericPolling",
    "Get User Devices by Username - Generic",
    "Isolate Endpoint - Generic V2",
    "SIEM - Search for Failed logins",
    "Search And Delete Emails - Generic v2",
    "Search Endpoint by CVE - Generic",
    "Threat Hunting - Generic",
    "Ticket Management - Generic",
}


def _pack_playbooks() -> dict[str, dict]:
    """The pack's playbooks parsed; skipped where PyYAML is not installed."""
    yaml = pytest.importorskip("yaml")
    folder = os.path.join(realpath, "..", "..", "Playbooks")
    playbooks = {}
    for name in sorted(os.listdir(folder)):
        if name.endswith(".yml"):
            with open(os.path.join(folder, name)) as handle:
                playbooks[name] = yaml.safe_load(handle)
    return playbooks


def test_every_pack_playbook_links_its_tasks_and_calls_what_the_pack_or_the_platform_provides():
    playbooks = _pack_playbooks()
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        commands = set(re.findall(r"^(?:  - |    )name: (\S+)$", yml_file.read(), re.MULTILINE)) | {
            "closeInvestigation",
            "send-mail",
        }
    scripts = set(os.listdir(os.path.join(realpath, "..", "..", "Scripts")))
    assert len(playbooks) == 7
    for name, playbook in playbooks.items():
        tasks = playbook["tasks"]
        assert playbook["id"] == playbook["name"]
        assert playbook["starttaskid"] in tasks
        assert tasks[playbook["starttaskid"]]["type"] == "start"
        inputs = {item["key"] for item in playbook["inputs"]}
        reachable, stack = set(), [playbook["starttaskid"]]
        while stack:
            key = stack.pop()
            if key in reachable:
                continue
            reachable.add(key)
            for targets in tasks[key].get("nexttasks", {}).values():
                for target in targets:
                    assert target in tasks, (name, key, target)
                    stack.append(target)
        assert reachable == set(tasks), (name, set(tasks) - reachable)
        for key, task in tasks.items():
            assert task["id"] == key, (name, key)
            assert task["taskid"] == task["task"]["id"], (name, key)
            kind = task["type"]
            if kind == "playbook":
                assert task["task"]["playbookName"] in STANDARD_SUB_PLAYBOOKS, (name, task["task"]["playbookName"])
            elif kind == "regular" and task["task"].get("iscommand"):
                assert task["task"]["script"].split("|||")[-1] in commands, (name, task["task"]["script"])
            elif kind == "regular" and task["task"].get("scriptName"):
                assert task["task"]["scriptName"] in scripts, (name, task["task"]["scriptName"])
            elif kind == "condition" and task.get("conditions"):
                assert {item["label"] for item in task["conditions"]} == set(task["nexttasks"]) - {"#default#"}, (name, key)
            for match in re.findall(r"inputs\.([A-Za-z]+)", json.dumps(task)):
                assert match in inputs, (name, key, match)


def test_the_response_playbooks_read_fields_the_pack_defines_and_name_their_sub_playbooks_and_inputs_in_the_readme():
    fields_dir = os.path.join(realpath, "..", "..", "IncidentFields")
    cli_names = set()
    for file_name in os.listdir(fields_dir):
        with open(os.path.join(fields_dir, file_name)) as handle:
            cli_names.add(json.load(handle)["cliName"])
    cli_names |= {"id", "name", "type", "sourceInstance", "severity"}
    for name, playbook in _pack_playbooks().items():
        if not name.startswith("Group-IB_TI_-_") or "Create_Threat_Intel_Report" in name:
            continue
        text = json.dumps(playbook)
        accessors = re.findall(r'"root": "incident", "accessor": "([A-Za-z.]+)"', text)
        for field in set(re.findall(r"incident\.([A-Za-z]+)", text)) | set(accessors):
            assert field.split(".")[0] in cli_names, (name, field)
        with open(os.path.join(realpath, "..", "..", "Playbooks", name.replace(".yml", "_README.md"))) as handle:
            readme = handle.read()
        sub_playbooks = {task["task"]["playbookName"] for task in playbook["tasks"].values() if task["type"] == "playbook"}
        for sub_playbook in sub_playbooks:
            assert f"* {sub_playbook}\n" in readme, (name, sub_playbook)
        for item in playbook["inputs"]:
            assert f"| {item['key']} |" in readme, (name, item["key"])


def _failing_url_client(mocker, client, failures: dict[str, Exception]):
    """A client whose URL source reads raise ``failures`` (collection -> exception) and answer nothing otherwise."""

    def read(path, value, keys=None):
        if path in failures:
            raise failures[path]
        return []

    mocker.patch.object(ReputationCommand, "_read", side_effect=read)
    return client


def test_a_url_lookup_whose_key_is_refused_fails_instead_of_reading_as_no_data(mocker, single_session_fixture):
    refused = GroupIBTIA.ConnectionException("HTTP 401: Bad Credentials.")
    client = _failing_url_client(mocker, single_session_fixture, {"ioc/primary": refused})
    with pytest.raises(DemistoException, match="refused the url lookup of 'http://evil.example/x': HTTP 401"):
        _url(client, "http://evil.example/x")


def test_a_url_lookup_whose_ioc_primary_read_fails_is_an_error(mocker, single_session_fixture):
    client = _failing_url_client(mocker, single_session_fixture, {"ioc/primary": GroupIBTIA.ConnectionException(SERVER_ERROR)})
    failed = _url(client, "http://evil.example/x")
    assert failed.entry_type == EntryType.ERROR
    assert "The Group-IB url lookup of" in failed.readable_output


def test_an_ip_lookup_whose_key_is_refused_fails(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"198.51.100.27": 90})
    mocker.patch.object(ReputationCommand, "_read", side_effect=GroupIBTIA.ConnectionException("HTTP 401: Bad Credentials."))
    with pytest.raises(DemistoException, match="refused the ip lookup of '198.51.100.27'"):
        reputation(client, "ip", {"ip": "198.51.100.27"})


def test_a_domain_lookup_no_request_answers_fails(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {})
    down = GroupIBTIA.ConnectionException(SERVER_ERROR)
    mocker.patch.object(ReputationCommand, "_read", side_effect=down)
    mocker.patch.object(client.poller, "get_domain_scoring", side_effect=down)
    mocker.patch.object(client.poller, "graph_domain_search", side_effect=down)
    [failed] = reputation(client, "domain", {"domain": "example.com"})
    assert failed.entry_type == EntryType.ERROR
    assert "The Group-IB domain lookup of 'example.com' failed" in failed.readable_output


def test_the_url_query_is_refanged_without_user_info_and_the_host_ignores_case_the_path_does_not(mocker, single_session_fixture):
    records = {"ioc/primary": [{"url": [{"url": "http://evil.example/AbC"}]}]}
    client = _url_client(mocker, single_session_fixture, records)
    result = _url(client, "hxxp://user:secret@EVIL[.]example/AbC")
    assert client.url_queries["ioc/primary"] == '"http://EVIL.example/AbC"'
    assert "secret" not in json.dumps(client.url_queries)
    assert result.indicator.dbot_score.score == 2
    other_path = _url(_url_client(mocker, single_session_fixture, records), "http://evil.example/abc")
    assert other_path.indicator.dbot_score.score == 0


@pytest.mark.parametrize(
    "text, masked",
    [
        ("amex 3782 822463 10005", "amex ***********0005"),
        ("diners 3056 930902 5904", "diners **********5904"),
        ("dotted 4000.0000.0000.0002", "dotted ************0002"),
        ("spaced 4000  0000  0000  0002", "spaced ************0002"),
    ],
)
def test_the_partial_post_mask_cuts_every_common_card_layout(text, masked):
    assert GroupIBTIA.PostTextMask.mask_text(text) == masked


def test_a_highlight_split_by_field_is_masked_like_the_text():
    post = {**_parsed("compromised/messenger"), "highlight": {"message": ["card 4000 0000 0000 0002"]}}
    partial = GroupIBTIA.PostTextMask("Partial").apply("compromised/messenger", post)
    assert partial["highlight"] == {"message": ["card ************0002"]}
    full = GroupIBTIA.PostTextMask("Full").apply("compromised/messenger", post)
    assert full["highlight"] == {"message": ["[withheld]"]}


def test_the_age_filter_reads_the_unknown_date_placeholder_as_no_date():
    record_filter = GroupIBTIA.RecordFilter.from_params({"max_record_age_days": "30"})
    record = {**_parsed("compromised/breacheddb"), "leakPublished": "0001-01-01T00:00:00Z", "uploadTime": None}
    assert record_filter.accepts("compromised/breacheddb", record, NOW)


def test_local_search_reads_one_page_of_a_collection_paged_by_its_items(mocker, single_session_fixture):
    client = single_session_fixture
    pulled = []

    def pages():
        for index in range(1, 5):
            page = MagicMock()
            page.parse_portion.return_value = [{"id": f"p{index}", "title": f"p{index}"}]
            page.raw_dict = {"items": [{"seqUpdate": index}]}
            pulled.append(index)
            yield page

    mocker.patch.object(client, "search_collection", return_value=pages())
    result = local_search(client, {"collection_name": "darkweb/forums", "query": "x", "requests_limit": "5"})
    assert [entry["id"] for entry in result.outputs] == ["p1"]
    assert pulled == [1]


def test_a_forum_fetch_refused_with_http_500_names_the_query_filter_and_no_other_fetch_does(single_session_fixture):
    settings = dataclasses.replace(
        fetch_settings(["darkweb/forums"]),
        record_filter=GroupIBTIA.RecordFilter.from_params({"collection_filters": 'darkweb/forums: query = forum:"x'}),
    )
    command = FetchIncidentsCommand(single_session_fixture, settings)
    message = command._refusal("darkweb/forums", GroupIBTIA.ConnectionException(SERVER_ERROR))
    assert "check its query in 'Collection filters'" in message
    plain = FetchIncidentsCommand(single_session_fixture, fetch_settings(["darkweb/forums"]))
    assert "Collection filters" not in plain._refusal("darkweb/forums", GroupIBTIA.ConnectionException(SERVER_ERROR))
    actors = dataclasses.replace(
        fetch_settings(["hi/threat_actor"]),
        record_filter=GroupIBTIA.RecordFilter.from_params({"collection_filters": "hi/threat_actor: query = Sample Crew"}),
    )
    message = FetchIncidentsCommand(single_session_fixture, actors)._refusal(
        "hi/threat_actor", GroupIBTIA.ConnectionException(SERVER_ERROR)
    )
    assert "Collection filters" not in message


def test_a_page_that_is_no_page_of_records_is_refused_and_the_pages_before_it_are_kept(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "malware/cnc"}])

    def pages():
        yield _cnc_page(200, "cnc-1")
        raise AttributeError("'NoneType' object has no attribute 'get'")

    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=(pages(), 150))
    health = mocker.patch.object(GroupIBTIA.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIBTIA.demisto, "error")
    next_run, incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": {"malware/cnc": "150"}},
        first_fetch_time="3 days",
        incident_collections=["malware/cnc"],
        max_requests=3,
        hunting_rules=0,
    )
    assert [json.loads(i["rawJSON"])["id"] for i in incidents] == ["cnc-1"]
    assert next_run["last_fetch"]["malware/cnc"] == "200"
    assert "not a page of records" in health.call_args.args[0]


@pytest.mark.parametrize(
    "cursors, message",
    [
        ([200, 200], "malware/cnc with a page whose seqUpdate does not advance"),
        ([200, 180], "malware/cnc with a page whose seqUpdate does not advance"),
        ([200, None], "The fetch of malware/cnc failed: HTTP 200 with a page that carries no seqUpdate"),
    ],
    ids=["repeated", "lower", "missing"],
)
def test_a_page_whose_cursor_does_not_advance_ends_the_walk_and_is_reported(mocker, single_session_fixture, cursors, message):
    client = single_session_fixture
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "malware/cnc"}])
    pages = [_cnc_page(seq, f"cnc-{n}") for n, seq in enumerate(cursors, start=1)]
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=(GroupIBTIA.Client._pages(iter(pages)), 150))
    health = mocker.patch.object(GroupIBTIA.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIBTIA.demisto, "error")
    next_run, incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": {"malware/cnc": "150"}},
        first_fetch_time="3 days",
        incident_collections=["malware/cnc"],
        max_requests=3,
        hunting_rules=0,
    )
    assert [json.loads(i["rawJSON"])["id"] for i in incidents] == ["cnc-1"]
    assert next_run["last_fetch"]["malware/cnc"] == "200"
    assert message in health.call_args.args[0]


def test_a_first_page_at_the_stored_cursor_fails_a_fetch_of_that_collection_alone(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "malware/cnc"}])
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=(iter([_cnc_page(150, "cnc-1")]), 150))
    mocker.patch.object(GroupIBTIA.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIBTIA.demisto, "error")
    with pytest.raises(DemistoException, match="malware/cnc with a page whose seqUpdate does not advance"):
        fetch_incidents(
            client=client,
            last_run={"last_fetch": {"malware/cnc": "150"}},
            first_fetch_time="3 days",
            incident_collections=["malware/cnc"],
            max_requests=3,
            hunting_rules=0,
        )


def test_a_forum_page_below_the_stored_cursor_is_refused(mocker, single_session_fixture):
    client = single_session_fixture
    client.rate_limit_delay = 0
    body = {"count": 1, "items": [{"id": "post-1", "seqUpdate": 150}], "seqUpdate": 150}
    mocker.patch.object(client.poller, "send_request", return_value=body)
    mocker.patch.object(client, "granted_collections", return_value=[])
    with pytest.raises(GroupIBTIA.DemistoException, match="below the cursor"):
        fetch_incidents(client, {"last_fetch": {"darkweb/forums": "150"}}, ["darkweb/forums"], max_requests=3)


def test_a_hunting_rules_change_drops_incident_cursors():
    state = {"hunting_rules": False, "last_fetch": {"hi/threat": "1"}, "found_incident_ids": {"a": 1.0}}
    assert FetchIncidentsCommand._drop_cursors_if_hunting_rules_changed(state, False) is state
    reset = FetchIncidentsCommand._drop_cursors_if_hunting_rules_changed(state, True)
    assert reset["last_fetch"] == {}
    assert reset["found_incident_ids"] == {"a": 1.0}
    # An instance upgraded from a version without the fingerprint keeps its cursors.
    legacy = {"last_fetch": {"hi/threat": "1"}}
    assert FetchIncidentsCommand._drop_cursors_if_hunting_rules_changed(legacy, True) is legacy


def test_the_phishing_takedown_blocks_the_domain_only_when_asked_and_reads_the_group_after_polling():
    playbook = _pack_playbooks()["Group-IB_TI_-_Phishing_Takedown.yml"]
    tasks = playbook["tasks"]
    defaults = {item["key"]: item["value"].get("simple") for item in playbook["inputs"]}
    assert defaults["BlockDomain"] == "False"
    [domain_block] = [key for key, task in tasks.items() if task["task"].get("playbookName") == "Block Domain - Generic v2"]
    [gate] = [key for key, task in tasks.items() if domain_block in task.get("nexttasks", {}).get("yes", [])]
    assert "inputs.BlockDomain" in json.dumps(tasks[gate]["conditions"])
    assert domain_block not in tasks[gate]["nexttasks"]["#default#"]
    # GenericPolling keeps its reads in its own context: the group is read again before its blocked date is checked.
    [polling] = [key for key, task in tasks.items() if task["task"].get("playbookName") == "GenericPolling"]
    [read] = tasks[polling]["nexttasks"]["#none#"]
    assert tasks[read]["task"]["script"].endswith("gibti-get-phishing-group-info")
    assert "GIBTI.PhishingGroup.blocked" in json.dumps(tasks[tasks[read]["nexttasks"]["#none#"][0]]["conditions"])


def test_a_lookup_page_that_is_no_page_of_records_is_a_refused_read(mocker, single_session_fixture):
    client = single_session_fixture

    def pages():
        raise AttributeError("'NoneType' object has no attribute 'get'")
        yield

    mocker.patch.object(client.poller, "create_update_generator", return_value=pages())
    with pytest.raises(GroupIBTIA.ConnectionException, match="not a page of records"):
        list(client.search_collection("hi/threat_actor", query="id:ab12", limit=1))


def test_a_url_with_a_bracket_in_its_host_is_looked_up_without_a_traceback(mocker, single_session_fixture):
    records = {"ioc/primary": [{"url": [{"url": "http://evil.example[/]login"}, {"url": "http://evil.example/x"}]}]}
    client = _url_client(mocker, single_session_fixture, records)
    result = _url(client, "hxxps://evil[.]example[/]login")
    assert client.url_queries["ioc/primary"] == '"https://evil.example[/]login"'
    assert result.indicator.dbot_score.score == 0
    # A record URL with a stray bracket next to the match does not stop the comparison.
    assert _url(_url_client(mocker, single_session_fixture, records), "http://evil.example/x").indicator.dbot_score.score == 2


def test_a_failed_read_that_decides_the_verdict_sets_no_verdict_and_is_named(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"198.51.100.27": 20})
    retried = GroupIBTIA.ConnectionException(
        "Retries exhausted for https://example.com/api/v2/ioc/primary/updated: Max retries exceeded "
        "(Caused by ResponseError('too many 503 error responses'))"
    )
    mocker.patch.object(
        ReputationCommand,
        "_read",
        side_effect=lambda path, value, keys=None: (_ for _ in ()).throw(retried) if path == "ioc/primary" else [],
    )
    [result] = reputation(client, "ip", {"ip": "198.51.100.27"})
    assert result.indicator is None
    assert result.outputs["partial"] is True
    assert "reading ioc/primary (HTTP 503)" in result.readable_output


SAMPLE_IP_PRIMARY = {"type": "network", "ip": [{"ip": "198.51.100.27", "riskScore": 10}], "evaluation": {"TLP": "TLP:GREEN"}}


def _failing_read(failing: str, records: dict[str, list]) -> Any:
    """A _read that fails with an HTTP 500 on one collection and returns ``records`` for the others."""
    error = GroupIBTIA.ConnectionException(SERVER_ERROR)

    def read(path: str, value: str, keys: Any = None) -> list:
        if path == failing:
            raise error
        return records.get(path, [])

    return read


@pytest.mark.parametrize(
    ("scores", "failing", "records", "verdict"),
    [
        # the risk score could have made it Bad: the Suspicious the ioc/primary listing gives is not set
        ({}, "scoring", {"ioc/primary": [SAMPLE_IP_PRIMARY]}, None),
        # ioc/primary could only have made it Suspicious: a Suspicious risk score stands
        ({"198.51.100.27": 50}, "ioc/primary", {}, 2),
        # and a Bad one too
        ({"198.51.100.27": 90}, "ioc/primary", {}, 3),
    ],
)
def test_a_verdict_stands_only_when_no_missing_answer_could_raise_it(
    mocker, single_session_fixture, scores, failing, records, verdict
):
    client = _reputation_client(mocker, single_session_fixture, records, scores)
    if failing == "scoring":
        client.poller.get_ip_scoring.side_effect = GroupIBTIA.ConnectionException(SERVER_ERROR)
    mocker.patch.object(ReputationCommand, "_read", side_effect=_failing_read(failing, records))
    [result] = reputation(client, "ip", {"ip": "198.51.100.27"})
    assert result.outputs["partial"] is True
    assert result.outputs["score"] == verdict
    assert (result.indicator is None) is (verdict is None)


@pytest.mark.parametrize(
    ("failing", "records", "verdict"),
    [
        # ioc/common could have made the hash Bad: the Suspicious of ioc/primary is not set
        ("ioc/common", ("ioc/primary",), None),
        # ioc/primary could have made it Bad from 80, and ioc/common does not list the hash: nothing is set
        ("ioc/primary", (), None),
        # ioc/common already made it Bad
        ("ioc/primary", ("ioc/common",), 3),
    ],
)
def test_a_file_verdict_below_bad_is_not_set_while_a_source_that_could_make_it_bad_is_missing(
    mocker, single_session_fixture, failing, records, verdict
):
    sha256 = "ab" * 32
    data = {
        "ioc/primary": [_primary_file(sha256, "ef" * 16, 50, "2026-04-09T00:00:00Z", "2026-04-10T00:00:00Z")],
        "ioc/common": [{"hash": [sha256]}],
    }
    chosen = {path: data[path] for path in records}
    client = _reputation_client(mocker, single_session_fixture, chosen)
    mocker.patch.object(ReputationCommand, "_read", side_effect=_failing_read(failing, chosen))
    [result] = reputation(client, "file", {"file": sha256})
    assert result.outputs["partial"] is True
    assert result.outputs["score"] == verdict


def test_an_ipv6_address_in_another_notation_matches_its_ioc_primary_element(mocker, single_session_fixture):
    records = {"ioc/primary": [{"type": "network", "ip": [{"ip": "2001:db8::1"}]}]}
    client = _reputation_client(mocker, single_session_fixture, records)
    [result] = reputation(client, "ip", {"ip": "2001:DB8:0::1"})
    assert result.indicator.dbot_score.score == 2


def test_a_file_lookup_whose_requests_all_fail_is_an_error(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {})
    mocker.patch.object(ReputationCommand, "_read", side_effect=GroupIBTIA.ConnectionException(SERVER_ERROR))
    [failed] = reputation(client, "file", {"file": "a" * 32})
    assert failed.entry_type == EntryType.ERROR


@pytest.mark.parametrize(
    "text, masked",
    [
        ("tab 4000\t0000\t0000\t0002", "tab ************0002"),
        ("dashed 4000 - 0000 - 0000 - 0002", "dashed ************0002"),
        ("slashed 4000/0000/0000/0002", "slashed ************0002"),
        ("underscored 4000_0000_0000_0002", "underscored ************0002"),
        ("halves 40000000 00000002", "halves ************0002"),
    ],
)
def test_the_partial_post_mask_cuts_a_card_number_split_by_tabs_dashes_slashes_underscores_or_in_halves(text, masked):
    assert GroupIBTIA.PostTextMask.mask_text(text) == masked


def test_a_forum_fetch_refused_after_retries_on_http_500_names_the_query_filter(single_session_fixture):
    settings = dataclasses.replace(
        fetch_settings(["darkweb/forums"]),
        record_filter=GroupIBTIA.RecordFilter.from_params({"collection_filters": 'darkweb/forums: query = forum:"x'}),
    )
    retried = GroupIBTIA.ConnectionException(
        "Retries exhausted for https://example.com/api/v2/darkweb/forums/updated: Max retries exceeded "
        "(Caused by ResponseError('too many 500 error responses'))"
    )
    message = FetchIncidentsCommand(single_session_fixture, settings)._refusal("darkweb/forums", retried)
    assert "check its query in 'Collection filters'" in message


def _search_page(seq: Any, record_id: str) -> MagicMock:
    page = MagicMock()
    page.sequpdate = seq
    page.parse_portion.return_value = [{"id": record_id, "cnc": "c2.example"}]
    page.raw_dict = {"items": [{"id": record_id, "seqUpdate": seq}]}
    return page


def test_a_search_ends_at_a_page_whose_cursor_does_not_advance(mocker, single_session_fixture):
    client = single_session_fixture
    pages = [_search_page(0, "first"), _search_page(0, "first"), _search_page(0, "first")]
    mocker.patch.object(client.poller, "create_update_generator", return_value=iter(pages))
    result = local_search(client, {"collection_name": "malware/cnc", "query": "c2.example", "requests_limit": "3"})
    assert [entry["id"] for entry in result.outputs] == ["first"]


def test_a_search_whose_page_carries_no_cursor_fails_naming_the_collection(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client.poller, "create_update_generator", return_value=iter([_search_page(None, "x")]))
    with pytest.raises(DemistoException, match="The search in malware/cnc failed .*a page that carries no seqUpdate"):
        local_search(client, {"collection_name": "malware/cnc", "query": "c2.example", "requests_limit": "3"})


def test_a_search_from_a_cursor_that_answers_it_back_returns_nothing(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client.poller, "create_update_generator", return_value=iter([_search_page(200, "repeated")]))
    result = local_search(client, {"collection_name": "malware/cnc", "query": "c2.example", "seq_update": "200"})
    assert result.outputs == []


def test_a_forum_search_from_the_highest_record_cursor_returns_the_posts_above_it(mocker, single_session_fixture):
    """A forum page answers its lowest record cursor; the records above the cursor asked from are new."""
    client = single_session_fixture
    page = _search_page(200, "post-1")
    page.raw_dict = {"items": [{"id": "post-1", "seqUpdate": 201}]}
    mocker.patch.object(client.poller, "create_update_generator", return_value=iter([page]))
    result = local_search(client, {"collection_name": "darkweb/forums", "query": "x", "seq_update": "200"})
    assert [entry["id"] for entry in result.outputs] == ["post-1"]


def test_a_fetch_after_hunting_rules_was_turned_on_starts_every_collection_without_its_cursor(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "malware/cnc"}])
    opened = mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=([], None))
    common = {"client": client, "first_fetch_time": "3 days", "incident_collections": ["malware/cnc"], "max_requests": 1}
    next_run, _ = fetch_incidents(last_run={"last_fetch": {"malware/cnc": "150"}}, hunting_rules=False, **common)
    assert next_run["hunting_rules"] is False
    assert opened.call_args.kwargs["cursor"] == "150"
    fetch_incidents(last_run={**next_run, "last_fetch": {"malware/cnc": "150"}}, hunting_rules=True, **common)
    assert opened.call_args.kwargs["cursor"] is None


def test_a_by_id_answer_that_is_no_record_is_a_failed_lookup(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(
        client.poller, "search_feed_by_id", side_effect=AttributeError("'NoneType' object has no attribute 'get'")
    )
    with pytest.raises(DemistoException, match="The lookup of id 'ab12' in malware/cnc failed: HTTP 200 with a body"):
        present_record(client, "malware/cnc", "ab12")


@pytest.mark.parametrize(
    "text, masked",
    [
        ("comma 4000,0000,0000,0002", "comma ************0002"),
        ("colon 4000:0000:0000:0002", "colon ************0002"),
        ("pipe 4000|0000|0000|0002", "pipe ************0002"),
        ("hidden 4000\u200b0000\u200b0000\u200b0002", "hidden ************0002"),
        ("six-ten 400000 0000000002", "six-ten ************0002"),
        ("five-five-six 40000 00000 000002", "five-five-six ************0002"),
        ("year after 4000 0000 0000 0002, 2025", "year after ************0002, 2025"),
        ("dates 20240101-20241231", "dates 20240101-20241231"),
        ("ids 12345678/87654321", "ids 12345678/87654321"),
        ("ports 8080\n8443\n9000\n9443", "ports 8080\n8443\n9000\n9443"),
        ("longer 4000 0000 0000 0002 1008", "longer ************0002 1008"),
    ],
)
def test_the_partial_post_mask_cuts_a_grouped_number_only_when_its_check_digit_is_valid(text, masked):
    assert GroupIBTIA.PostTextMask.mask_text(text) == masked


def test_the_partial_post_mask_reads_a_long_line_of_digit_groups_in_linear_time():
    line = "4111 " + " ".join(f"{n % 1000:03d}" for n in range(1500))
    started = time.perf_counter()
    GroupIBTIA.PostTextMask.mask_text(line)
    assert time.perf_counter() - started < 2


@pytest.mark.parametrize(
    "separator",
    ["\u2013", "\u2014", "\u2212", "\u2009", "\u202f", "\u2007", "\u3000", "*", "\u2022", " * "],
    ids=["en dash", "em dash", "minus", "thin", "narrow", "figure", "ideographic", "asterisk", "bullet", "spaced asterisk"],
)
def test_the_partial_post_mask_reads_any_separator_on_one_line(separator):
    card = separator.join(["4000", "0000", "0000", "0002"])
    assert GroupIBTIA.PostTextMask.mask_text(f"card {card} ok") == "card ************0002 ok"
    other = separator.join(["4000", "0000", "0000", "0003"])
    assert GroupIBTIA.PostTextMask.mask_text(f"card {other} ok") == f"card {other} ok"


def test_the_partial_post_mask_reads_a_number_whose_first_group_has_three_digits_on_one_line():
    assert GroupIBTIA.PostTextMask.mask_text("card 400 000 000 000 0002") == "card ************0002"
    assert GroupIBTIA.PostTextMask.mask_text("card 400\u2028000 000 000 0002") == "card 400\u2028000 000 000 0002"


@pytest.mark.parametrize("prefix", ["101. ", "#123 ", "order #12345 (", "2024. ", "item 777) "])
def test_a_number_before_a_grouped_card_never_leaves_its_middle_digits(prefix):
    masked = GroupIBTIA.PostTextMask.mask_text(f"{prefix}4000 0000 0000 0002 ok")
    assert "0000" not in masked
    assert masked.endswith("0002 ok")


def test_no_number_before_a_grouped_card_leaves_its_middle_digits():
    rng = random.Random(5)
    for _ in range(300):
        prefix = "".join(rng.choice("123456789") for _ in range(rng.randint(3, 5)))
        separator = rng.choice([". ", " ", " #", ") ", ", ", "-"])
        masked = GroupIBTIA.PostTextMask.mask_text(f"see {prefix}{separator}4000 0000 0000 0002 ok")
        assert "0000" not in masked, (prefix, separator)
        assert masked.endswith("0002 ok"), (prefix, separator)


def test_an_ipv4_address_is_never_read_as_card_digits():
    # 113, 151 and the first groups of the card pass the check digit together.
    mask = GroupIBTIA.PostTextMask.mask_text
    assert mask("host 203.0.113.151 4000 0000 0000 0002") == "host 203.0.113.151 ************0002"
    assert mask("host 203.0.113.151:4000 0000 0000 0002") == "host 203.0.113.151:************0002"
    assert mask("host 203.0.113.151:3389 ok") == "host 203.0.113.151:3389 ok"


def test_a_dotted_run_of_more_than_four_numbers_is_no_address():
    mask = GroupIBTIA.PostTextMask.mask_text
    assert "151" not in mask("v7.203.0.113.151 4000 0000 0000 0002")
    assert "151" not in mask("v203.0.113.151.4000.0000.0000.0002")


def test_a_card_after_an_address_and_a_colon_keeps_only_its_last_four_digits():
    rng = random.Random(13)
    for _ in range(300):
        separator = rng.choice([" ", "-", ".", "  ", "\t", " - "])
        port = rng.choice(["", "22 ", "443 ", "3389 ", "8080 ", "12345 ", "65535 "])
        text = f"host 203.0.113.{rng.randint(1, 254)}:{port}{separator.join(['4000', '0000', '0000', '0002'])} ok"
        masked = GroupIBTIA.PostTextMask.mask_text(text)
        assert "0000" not in masked, text
        assert masked.endswith("0002 ok"), text


@pytest.mark.parametrize(
    "text, masked",
    [
        ("<em>4000</em> 0000 0000 0002", "<em>************0002"),
        ("<b>400000</b>0000000002", "<b>************0002"),
        ("4000 0000 <mark>0000</mark> 0002", "************0002"),
        ('4000 <span class="hl">0000</span> 0000 0002', "************0002"),
        ('4000 <span data-n="1">0000</span> 0000 0002', "************0002"),
        ("4000 <0000> 0000 0002", "************0002"),
        ("4000 <b\n>0000 0000 0002", "4000 <b\n>0000 0000 0002"),
    ],
    ids=[
        "first group",
        "bin",
        "inside",
        "with attributes",
        "digits in the tag",
        "digits in brackets are no tag",
        "a tag across lines joins nothing",
    ],
)
def test_the_partial_post_mask_reads_a_markup_tag_between_digit_groups_as_a_separator(text, masked):
    assert GroupIBTIA.PostTextMask.mask_text(text) == masked


def test_a_highlight_that_marks_part_of_a_card_number_is_masked_like_the_text():
    post = {**_parsed("compromised/messenger"), "highlight": {"message": ["card <em>4000</em> 0000 0000 0002"]}}
    partial = GroupIBTIA.PostTextMask("Partial").apply("compromised/messenger", post)
    assert partial["highlight"] == {"message": ["card <em>************0002"]}


SECRET = "Sample-Secret-9"


@pytest.mark.parametrize(
    "key",
    [
        "userPw",
        "user_pw",
        "pw1",
        "hashed_pw",
        "psw",
        "pswd",
        "plain",
        "plaintext",
        "cleartext",
        "cracked",
        "secret",
        "userSecret",
        "credentials",
        "nthash",
        "nt_hash",
        "lmhash",
        "sha",
        "ssha",
        "crypt",
        "md5crypt",
        "hashed",
        "digest",
        "senha",
        "contrasena",
        "parol",
        "haslo",
        "sifre",
        "mdp",
        "kennwort",
        "clave",
        "wachtwoord",
    ],
)
def test_a_leak_column_named_by_any_password_word_is_a_credential(key):
    assert GroupIBTIA.PasswordMask.is_credential_key(key)


@pytest.mark.parametrize("key", ["contrase\u00f1a", "has\u0142o", "\u015fifre"])
def test_a_leak_column_spelled_with_accents_is_read_as_its_plain_spelling(key):
    assert GroupIBTIA.PasswordMask.is_credential_key(key)


@pytest.mark.parametrize(
    "key",
    [
        "passport",
        "passportNumber",
        "emailHash",
        "hashType",
        "passwordChangedAt",
        "plainAddress",
        "secretQuestion",
        "shadow",
        "encrypted",
        "messageDigest",
        "compass",
    ],
)
def test_a_leak_column_that_only_resembles_a_password_word_is_not_a_credential(key):
    assert not GroupIBTIA.PasswordMask.is_credential_key(key)


@pytest.mark.parametrize("mode", ["Partial", "Full"])
@pytest.mark.parametrize(
    "details",
    [
        {"userPw": [SECRET]},
        {"account": {"password": SECRET}},
        {"accounts": [{"pass": SECRET}]},
        {"line": [f"user@example.com:{SECRET}"]},
        {"note": f"login user password={SECRET}"},
    ],
    ids=["column name", "nested column", "nested in a list", "e-mail:password line", "password= phrase"],
)
def test_no_breached_password_shows_under_the_mask_and_each_marks_the_record_as_holding_a_credential(mode, details):
    record = {"id": "b" * 40, "passwords": [], "record_details": dict(details)}
    masking = GroupIBTIA.Masking(GroupIBTIA.PasswordMask(mode), GroupIBTIA.CardDataMask())
    masked = masking.apply("compromised/breacheddb", record)
    assert SECRET not in json.dumps(masked)
    assert masked["hasPassword"] is True


def test_the_password_of_a_service_url_is_masked():
    record = {"id": "a" * 40, "password": SECRET, "service": {"url": f"https://user:{SECRET}@example.com/login"}}
    masked = GroupIBTIA.PasswordMask("Partial").apply("compromised/account_group", record)
    assert masked["service"]["url"] == "https://user:Sample-****@example.com/login"
    full = GroupIBTIA.PasswordMask("Full").apply("compromised/account_group", {**record, "service": dict(record["service"])})
    assert SECRET not in json.dumps(full)


def test_the_values_and_text_of_a_public_leak_are_masked_and_their_count_kept():
    def leak():
        return {
            "id": "c" * 40,
            "data": f"dump\nuser@example.com:{SECRET}\napi_key={SECRET}",
            "matches": {
                "commonKeywords": {"password": [SECRET, SECRET]},
                "email": {"email:pass": [f"user@example.com:{SECRET}"]},
            },
        }

    partial = GroupIBTIA.PasswordMask("Partial").apply("osi/public_leak", leak())
    assert SECRET not in json.dumps(partial)
    assert partial["matches"]["commonKeywords"]["password"] == ["Sample-****", "Sample-****"]
    assert partial["data"] == "dump\nuser@example.com:Sample-****\napi_key=Sample-****"
    full = GroupIBTIA.PasswordMask("Full").apply("osi/public_leak", leak())
    assert full["matches"]["commonKeywords"]["password"] == ["[withheld]", "[withheld]"]
    assert full["data"] == "[withheld]"


@pytest.mark.parametrize("matches", [{"commonKeywords": {"password": [SECRET]}}, [SECRET]], ids=["object", "list"])
def test_a_secret_of_a_public_leak_is_masked_in_every_form_its_raw_text_quotes(matches):
    data = "\n".join(
        [
            f"DB_PASSWORD={SECRET}",
            f'{{"password": "{SECRET}"}}',
            f"'password' => '{SECRET}'",
            f"<password>{SECRET}</password>",
            f"sampleuser:{SECRET}",
            f"aws_secret_access_key = {SECRET}",
            f"Authorization: Bearer {SECRET}",
        ]
    )
    masked = GroupIBTIA.PasswordMask("Partial").apply("osi/public_leak", {"id": "c" * 40, "data": data, "matches": matches})
    assert SECRET not in json.dumps(masked)


@pytest.mark.parametrize(
    "text",
    [
        f"DB_PASSWORD={SECRET}",
        f'"password": "{SECRET}"',
        f"'password' => '{SECRET}'",
        f"<password>{SECRET}</password>",
        f"Authorization: Bearer {SECRET}",
        f"aws_secret_access_key = {SECRET}",
        f"access_token={SECRET}",
        f"client_secret: {SECRET}",
    ],
)
def test_a_secret_quoted_by_its_key_is_masked_in_any_text(text):
    assert SECRET not in GroupIBTIA.PasswordMask("Partial").mask_inline(text)


@pytest.mark.parametrize(
    "text",
    [
        "a@example.com;b@example.com",
        "a@example.com|Sample User|1990",
        "a@example.com:8080",
        "password:\nnext line",
        "This course gives basic understanding of security",
        "Basic knowledge required, bearer instruments explained",
        "git@git.example.com:example/repo.git",
        "scp file user@example.com:/tmp/upload",
        "Contact admin@example.com:2026-10-01T12:00:00Z",
        "https://example.com:8080/a",
        "http://203.0.113.5:80/x:y",
        "see https://example.com/a for more",
        "passport: X1234567",
        '"hashType": "md5"',
        "MD5: 0123456789abcdef0123456789abcdef",
        "pass.example.com:8443",
        "What to do with the leaked cloud credentials: Ask (an analyst decides)",
        "Passwords: 12000, Cookies: 50000",
        "Credentials: 500 lines",
        "Secrets: 12 found",
        "Tokens: 3 left",
        "max_tokens: 1024",
        "Authorization: required for this endpoint",
        "Authorization: none",
        "http://[2001:db8::1]:8080",
        "http://[2001:db8:0:0:0:0:0:1]",
        "https://example.com/api?ts=2026-11-03T10:30:45Z",
        "https://password.example.com:443/reset",
        "--password-file /etc/sample/pass.txt",
        "--token-ttl 3600",
        "Passover: April 2026",
        "Selling logs. Passwords: 2.5k, Autofills: 900",
        "OLDPWD=/home/sample",
        "PWD=/home/sample/work",
        "usage: tool --password PASSWORD",
        "<PasswordBox>Enter here</PasswordBox>",
        '{"salt_rounds": 10}',
        '{"tokenizer": "bert"}',
        'user.setPasswordVisible("true")',
        "https://www.example.com/feed/update/urn:li:activity:7123456789012345678",
        "take the Basic Life-Support course",
        "https://example.com/page#:~:text=reset:more",
        '{"authorization":{"type":"bearer"}}',
        '{"hasPassword": true}',
        '{"passthrough": true}',
        '<a data-key="password">Forgot your password?</a>',
    ],
)
def test_a_pair_or_phrase_that_holds_no_secret_is_left_alone(text):
    assert GroupIBTIA.PasswordMask.inline_secrets(text) == []
    assert GroupIBTIA.PasswordMask("Partial").mask_inline(text) == text


def test_a_breached_record_whose_columns_only_resemble_a_pair_is_not_marked_as_holding_a_credential():
    record = {"id": "b" * 40, "passwords": [], "record_details": {"emails": "a@example.com;b@example.com"}}
    masking = GroupIBTIA.Masking(GroupIBTIA.PasswordMask("Off"), GroupIBTIA.CardDataMask())
    assert masking.apply("compromised/breacheddb", record)["hasPassword"] is False


@pytest.mark.parametrize(
    "key", ["api_key", "apiKey", "apikey", "secret_key", "secretKey", "private_key", "auth_key", "access_key"]
)
def test_a_column_named_for_a_secret_key_is_a_credential(key):
    assert GroupIBTIA.PasswordMask.is_credential_key(key)


@pytest.mark.parametrize("key", ["publicKey", "primaryKey", "foreignKey", "key"])
def test_a_column_named_for_another_key_is_not_a_credential(key):
    assert not GroupIBTIA.PasswordMask.is_credential_key(key)


def test_a_card_in_a_post_shows_its_last_four_digits_under_the_partial_post_text_and_password_masks():
    post = {"id": "d" * 40, "text": "user@example.com|4000000000000002|12/25|123"}
    masking = GroupIBTIA.Masking(
        GroupIBTIA.PasswordMask("Partial"), GroupIBTIA.CardDataMask(), GroupIBTIA.PostTextMask("Partial")
    )
    masked = masking.apply("compromised/messenger", post)["text"]
    assert "************0002" in masked
    assert "40000000" not in masked


def test_a_card_number_quoted_as_a_password_in_a_post_shows_no_leading_digits():
    post = {"id": "d" * 40, "text": "user@example.com:4000000000000002 fresh"}
    masking = GroupIBTIA.Masking(
        GroupIBTIA.PasswordMask("Partial"), GroupIBTIA.CardDataMask(), GroupIBTIA.PostTextMask("Partial")
    )
    masked = masking.apply("compromised/messenger", post)["text"]
    assert masked.startswith("user@example.com:****")
    assert "4000" not in masked


def test_a_short_value_a_public_leak_detector_extracted_is_masked():
    leak = {"id": "c" * 40, "data": "dump", "matches": ["Pw1x"]}
    assert GroupIBTIA.PasswordMask("Partial").apply("osi/public_leak", leak)["matches"] == ["Pw****"]


def test_an_attacker_url_in_the_indicators_block_keeps_its_credentials():
    url = "ftp://drop:Exfil-Secret@c2.test/up"
    record = {"id": "a" * 40, "password": SECRET, "indicators": {"cnc_url": [url]}}
    masked = GroupIBTIA.PasswordMask("Full").apply("compromised/account_group", record)
    assert masked["indicators"] == {"cnc_url": [url]}


def test_a_credential_quoted_in_a_dark_web_post_is_masked_with_the_password_mask():
    post = {"id": "d" * 40, "text": f"fresh logs user@example.com:{SECRET} and pass: {SECRET}"}
    masked = GroupIBTIA.PasswordMask("Partial").apply("compromised/messenger", dict(post))
    assert masked["text"] == "fresh logs user@example.com:Sample-**** and pass: Sample-****"
    assert GroupIBTIA.PasswordMask("Off").apply("compromised/messenger", dict(post)) == post


LEAK_FORMATS = [
    '{"dbPassword": "%s"}',
    '"clientSecret": "%s"',
    '"accessToken": "%s"',
    "refreshToken=%s",
    "PGPASSWORD=%s",
    "DBPASS=%s",
    "APP_PROD_EU_DB_MAIN_PASSWORD=%s",
    "AUTH_KEY=%s",
    '"SecretAccessKey": "%s"',
    "--password=%s",
    "spring.datasource.password=%s",
    "define('DB_PASSWORD', '%s');",
    'ds.setPassword("%s");',
    '<add key="DbPassword" value="%s"/>',
    '<property name="password" value="%s"/>',
    '<entry key="password">%s</entry>',
    "<dbPassword>%s</dbPassword>",
    "<password><![CDATA[%s]]></password>",
    "<password> %s </password>",
    "https://login.example.com/:sampleuser:%s",
    "https://login.example.com:sampleuser:%s",
    "android://AbCdEf==@com.example.app/:sampleuser:%s",
    "https://login.example.com|sampleuser|%s",
    "a@example.com:Other-Secret-1,b@example.com:%s",
    "redis://:%s@cache.example.com:6379/0",
    "https://api.example.com/v1/items?token=%s&page=2",
    "Authorization: Token %s",
    "-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----",
    "\u041b\u043e\u0433\u0438\u043d: sampleuser \u041f\u0430\u0440\u043e\u043b\u044c: %s",
    "contrase\u00f1a: %s",
    "mot de passe: %s",
    "l\u00f6senord: %s",
    "\u5bc6\u7801: %s",
    "--password %s",
    "Cookie: sessionid=%s",
    "Cookie: session_id=%s",
    "password=Qz7m&%s",
    "password=Qz7m)%s",
    "password=Qz7m|%s",
    "Bearer abcdefghijklmnopqrstuv%s",
    "password:\u00a0%s",
    '"user@example.com":"%s"',
    "sampleuser:$6$%s",
]


@pytest.mark.parametrize("mode", ["Partial", "Full"])
@pytest.mark.parametrize("text", LEAK_FORMATS)
def test_a_secret_written_in_a_common_leak_format_is_masked(mode, text):
    masked = GroupIBTIA.PasswordMask(mode).mask_inline(text % SECRET)
    assert "Sample-S" not in masked


def test_a_short_number_after_a_dotted_key_and_an_equals_sign_is_a_secret_not_a_port():
    assert GroupIBTIA.PasswordMask("Partial").mask_inline("spring.datasource.password=48213") == (
        "spring.datasource.password=48****"
    )
    assert GroupIBTIA.PasswordMask("Partial").mask_inline("pass.example.com:8443") == "pass.example.com:8443"


@pytest.mark.parametrize(
    "text, kept",
    [
        ("https://example.com/login?user=sampleuser&password=%s&remember=true", "&remember=true"),
        ('{"combo":"user@example.com:%s","source":"cloud"}', '","source":"cloud"}'),
        ("token=%s)&next=/home", ")&next=/home"),
        ("postgres://sampleuser:%s@db.example.com:5432/app", "@db.example.com:5432/app"),
    ],
)
def test_a_masked_secret_ends_where_the_secret_ends(text, kept):
    masked = GroupIBTIA.PasswordMask("Partial").mask_inline(text % SECRET)
    assert "Sample-****" in masked
    assert masked.endswith(kept)


def test_each_part_of_a_quoted_secret_with_spaces_shows_at_most_its_first_half():
    masked = GroupIBTIA.PasswordMask("Partial").mask_inline('{"password": "Sample Secret Nine"}')
    assert masked == '{"password": "Sam**** Sec**** Ni****"}'


def test_a_credential_column_holding_several_secrets_shows_at_most_the_first_half_of_each():
    record = {"id": "b" * 40, "passwords": [], "record_details": {"passwords": f"{SECRET};Other-Secret-2"}}
    masked = GroupIBTIA.PasswordMask("Partial").apply("compromised/breacheddb", record)
    assert masked["record_details"]["passwords"] == "Sample-****;Other-S****"


@pytest.mark.parametrize("mode", ["Partial", "Full"])
def test_every_copy_of_a_secret_a_post_quotes_is_masked(mode):
    post = {"id": "d" * 40, "text": f"logs user@example.com:{SECRET} and the same {SECRET} for ftp"}
    assert SECRET not in GroupIBTIA.PasswordMask(mode).apply("compromised/messenger", post)["text"]


@pytest.mark.parametrize("mode", ["Partial", "Full"])
@pytest.mark.parametrize(
    "raw", ["sampleuser:Pw1x5Z", "sampleuser/Pw1x5Z", "my pass is Pw1x5Z.", "Pw1x5Z@", '{\\"pwd\\":\\"Pw1x5Z\\"}']
)
def test_every_copy_of_a_breached_password_is_masked(mode, raw):
    record = {"id": "b" * 40, "passwords": ["Pw1x5Z"], "record_details": {"raw": raw}}
    assert "Pw1x5Z" not in json.dumps(GroupIBTIA.PasswordMask(mode).apply("compromised/breacheddb", record))


def test_a_four_character_password_is_masked_in_a_sentence_but_not_in_a_date():
    record = {"id": "a" * 40, "password": "2013", "dateFirstSeen": "2013-05-21T00:00:00+00:00", "note": "the password 2013 again"}
    masked = GroupIBTIA.PasswordMask("Partial").apply("compromised/account_group", record)
    assert (masked["dateFirstSeen"], masked["note"]) == ("2013-05-21T00:00:00+00:00", "the password 20**** again")


def test_a_password_of_symbols_alone_is_masked_where_a_text_repeats_it():
    record = {"id": "a" * 40, "password": "!@#$%^&*", "note": "the pw was !@#$%^&* indeed"}
    assert "!@#$%^&*" not in GroupIBTIA.PasswordMask("Partial").apply("compromised/account_group", record)["note"]


@pytest.mark.parametrize("mode", ["Partial", "Full"])
@pytest.mark.parametrize(
    "text, secret",
    [
        ("SECRET=changeme", "changeme"),
        ("secret:changeme", "changeme"),
        ('"secret": "changeme"', "changeme"),
        ("<secret>changeme</secret>", "changeme"),
        ("mdp: azerty", "azerty"),
        ("token: Abcdefghij", "Abcdefghij"),
        ("Clave: Amor", "Amor"),
    ],
)
def test_a_secret_of_letters_alone_is_masked_after_its_key(mode, text, secret):
    assert secret not in GroupIBTIA.PasswordMask(mode).mask_inline(text)


@pytest.mark.parametrize("secret", ["Sample&Secret9", "ab12,cd1234xyz", "Sample'Secret9", "Sample<Secret9"])
def test_a_pair_password_with_a_symbol_is_masked_to_its_end(secret):
    leak = {"id": "c" * 40, "data": "dump", "matches": {"email": {"email:pass": [f"user@example.com:{secret}"]}}}
    partial = GroupIBTIA.PasswordMask("Partial").apply("osi/public_leak", json.loads(json.dumps(leak)))
    assert secret[len(secret) // 2 :] not in json.dumps(partial)
    full = GroupIBTIA.PasswordMask("Full").apply("osi/public_leak", leak)
    assert full["matches"]["email"]["email:pass"] == ["user@example.com:[withheld]"]


def test_both_hashes_of_an_ntlm_dump_line_are_masked():
    lm, nt = "00112233445566778899aabbccddeeff", "ffeeddccbbaa99887766554433221100"
    masked = GroupIBTIA.PasswordMask("Partial").mask_inline(f"sampleuser:1001:{lm}:{nt}:::")
    assert lm[16:] not in masked
    assert nt[16:] not in masked


def test_a_password_of_separators_alone_shows_its_first_half():
    assert GroupIBTIA.PasswordMask._partial(";;;;;;;;") == ";;;;****"


@pytest.mark.parametrize("text", ["ab:" * 350000, 'key="a">x ' * 100000, "PATH=" + "/usr/bin:" * 110000])
def test_a_long_line_of_keys_masks_in_linear_time(text):
    started = time.perf_counter()
    GroupIBTIA.PasswordMask("Partial").apply("darkweb/forums", {"id": "d" * 40, "text": text})
    assert time.perf_counter() - started < 5


def test_a_known_secret_inside_a_longer_word_is_left_alone():
    record = {"id": "b" * 40, "passwords": ["Pw-1x5"], "record_details": {"note": "Pw-1x5yz and Pw-1x5"}}
    masked = GroupIBTIA.PasswordMask("Partial").apply("compromised/breacheddb", record)
    assert masked["record_details"]["note"] == "Pw-1x5yz and Pw-****"


def test_an_extracted_pair_shows_its_address_and_the_first_half_of_its_password():
    leak = {"id": "c" * 40, "data": "dump", "matches": {"email": {"email:pass": [f"user@example.com:{SECRET}"]}}}
    masked = GroupIBTIA.PasswordMask("Partial").apply("osi/public_leak", leak)
    assert masked["matches"]["email"]["email:pass"] == ["user@example.com:Sample-****"]


def test_a_password_shorter_than_four_characters_is_not_looked_for_in_the_texts():
    record = {"id": "b" * 40, "passwords": ["abc"], "record_details": {"note": "abc and more"}}
    assert GroupIBTIA.PasswordMask("Partial").apply("compromised/breacheddb", record)["record_details"]["note"] == "abc and more"


def test_a_short_value_a_text_quotes_is_not_looked_for_elsewhere():
    post = {"id": "d" * 40, "text": "pass: 2024 posted in 2024"}
    assert GroupIBTIA.PasswordMask("Partial").apply("compromised/messenger", post)["text"] == "pass: 20**** posted in 2024"


def test_a_login_and_password_value_a_detector_extracted_is_masked_in_the_raw_text():
    leak = {"id": "c" * 40, "data": f"x sampleuser:{SECRET} y", "matches": {"email": {"login:pass": [f"sampleuser:{SECRET}"]}}}
    assert SECRET not in json.dumps(GroupIBTIA.PasswordMask("Partial").apply("osi/public_leak", leak))


def test_a_detector_value_that_is_a_key_word_leaves_the_secret_after_that_word_masked():
    leak = {"id": "c" * 40, "data": f"password: {SECRET}", "matches": {"commonKeywords": {"password": ["password"]}}}
    assert SECRET not in json.dumps(GroupIBTIA.PasswordMask("Partial").apply("osi/public_leak", leak))


@pytest.mark.parametrize(
    "key",
    [
        "dbPassword",
        "pasword",
        "paswd",
        "p4ssword",
        "l\u00f6senord",
        "heslo",
        "\u043f\u0430\u0440\u043e\u043b\u044c",
        "\u5bc6\u7801",
        "sshKey",
        "encryption_key",
        "masterKey",
        "sessionKey",
        "session_id",
        "sessionId",
        "ASP.NET_SessionId",
    ],
)
def test_a_column_named_by_a_prefixed_misspelled_or_foreign_password_word_a_secret_key_or_a_session_id_is_a_credential(key):
    assert GroupIBTIA.PasswordMask.is_credential_key(key)


@pytest.mark.parametrize(
    "key",
    ["pwdLastSet", "passwordLastSet", "lastPasswordChange", "passwordReset", "token_id", "api_key_id"]
    + ["passage", "passion", "trespass", "parole_officer"],
)
def test_a_column_that_dates_or_identifies_a_credential_or_only_resembles_one_is_not_a_credential(key):
    assert not GroupIBTIA.PasswordMask.is_credential_key(key)


@pytest.mark.parametrize("value", ["0", "1", "false", "NULL", "-", "n/a", ["none", "true"]])
def test_a_credential_column_holding_a_flag_or_a_placeholder_holds_no_credential(value):
    record = {"id": "b" * 40, "passwords": [], "record_details": {"has_password": value}}
    masking = GroupIBTIA.Masking(GroupIBTIA.PasswordMask("Full"), GroupIBTIA.CardDataMask())
    masked = masking.apply("compromised/breacheddb", record)
    assert (masked["hasPassword"], masked["record_details"]) == (False, {"has_password": value})


@pytest.mark.parametrize(
    "secret",
    [
        "0123456789abcdef0123456789abcdef:fedcba9876543210fedcba9876543210",
        "ghp_SampleSecretValue0123456789",
        # Joined at run time so that no secret scanner reads the sample as a live token.
        "-".join(("xoxb", "0123456789", "SampleSecretValue")),
        "sk_live_Sample-Secret-Value",
    ],
)
def test_a_secret_known_by_its_shape_is_masked_without_a_key(secret):
    text = f"sampleuser:1001:{secret}:::" if ":" in secret else f"found {secret} in the repository"
    masked = GroupIBTIA.PasswordMask("Partial").mask_inline(text)
    assert secret not in masked
    assert secret[len(secret) // 2 :] not in masked


def test_the_password_mask_reads_a_long_line_of_addresses_in_linear_time():
    text = ";".join(f"user{index}@example.com" for index in range(50000))
    started = time.perf_counter()
    GroupIBTIA.PasswordMask("Partial").mask_inline(text)
    assert time.perf_counter() - started < 2


@pytest.mark.parametrize("mode", ["Partial", "Full"])
def test_a_public_leak_with_many_extracted_pairs_masks_in_linear_time(mode):
    pairs = [f"user{index}@example.com:Sample-Secret-{index}" for index in range(10000)]
    leak = {"id": "c" * 40, "data": "\n".join(pairs), "matches": {"email": {"email:pass": pairs}}}
    assert "Sample-Secret-9999" not in json.dumps(GroupIBTIA.PasswordMask(mode).apply("osi/public_leak", leak))

    def seconds(count: int) -> float:
        """The CPU time of the best of three runs over ``count`` pairs, which a busy machine affects least."""
        part = pairs[:count]
        sized = {"id": "c" * 40, "data": "\n".join(part), "matches": {"email": {"email:pass": part}}}
        best = float("inf")
        for _ in range(3):
            started = time.process_time()
            GroupIBTIA.PasswordMask(mode).apply("osi/public_leak", sized)
            best = min(best, time.process_time() - started)
        return best

    # Eight times the pairs take about eight times as long; a quadratic mask would take sixty-four.
    assert seconds(8000) < 24 * seconds(1000)


def test_the_cnc_of_an_account_shows_one_value_in_its_events_and_its_indicators():
    url = "ftp://drop:Exfil-Secret@c2.test/up"
    record = {"id": "a" * 40, "password": SECRET, "events_table": {"cnc": [url]}, "indicators": {"cnc_url": [url]}}
    masked = GroupIBTIA.PasswordMask("Full").apply("compromised/account_group", record)
    assert (masked["events_table"]["cnc"], masked["indicators"]["cnc_url"]) == ([url], [url])


@pytest.mark.parametrize(
    "matches, rows",
    [
        ({"commonKeywords": None}, None),
        ({"commonKeywords": {"password": None}}, None),
        ({"email": ["a@example.com"]}, None),
        ({"commonKeywords": {"password": "Pw****"}}, [{"type": "commonKeywords", "subtype": "password", "value": "Pw****"}]),
    ],
)
def test_irregular_public_leak_matches_give_the_rows_they_hold(matches, rows):
    assert GroupIBTIA.IncidentBuilder._matches_rows(matches) == rows


PACK = Path(realpath).parent.parent


def test_no_incident_field_names_an_incident_type_no_pack_item_defines():
    types = {json.loads(path.read_text())["name"] for path in (PACK / "IncidentTypes").glob("*.json")}
    unknown = {}
    for path in (PACK / "IncidentFields").glob("*.json"):
        field = json.loads(path.read_text())
        names = set(field.get("associatedTypes") or []) | set(field.get("systemAssociatedTypes") or [])
        if names - types:
            unknown[field["name"]] = sorted(names - types)
    assert unknown == {}


def test_no_playbook_calls_a_pack_script_newer_than_itself():
    yaml = pytest.importorskip("yaml")
    scripts = {}
    for path in (PACK / "Scripts").glob("*/*.yml"):
        script = yaml.safe_load(path.read_text())
        scripts[script["name"]] = script["fromversion"]
    newer = []
    for path in (PACK / "Playbooks").glob("*.yml"):
        playbook = yaml.safe_load(path.read_text())
        for task in (playbook.get("tasks") or {}).values():
            if task.get("skipunavailable"):
                continue
            name = (task.get("task") or {}).get("scriptName") or (task.get("task") or {}).get("script")
            if name in scripts and Version(scripts[name]) > Version(playbook["fromversion"]):
                newer.append((playbook["name"], name))
    assert newer == []


def test_each_script_readme_names_the_version_its_yml_declares():
    yaml = pytest.importorskip("yaml")
    for path in (PACK / "Scripts").glob("*/*.yml"):
        script = yaml.safe_load(path.read_text())
        readme = (path.parent / "README.md").read_text()
        assert f"| Cortex XSOAR Version | {script['fromversion']} |" in readme, path.parent.name


def test_every_argument_made_required_since_3_x_is_named_in_the_breaking_notes():
    yaml = pytest.importorskip("yaml")
    notes = json.loads((PACK / "ReleaseNotes/4_0_0.json").read_text())["breakingChangesNotes"]
    [line] = [line for line in notes.split("\n") if line.endswith("are required.")]
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        commands = {command["name"]: command for command in yaml.safe_load(yml_file)["script"]["commands"]}
    for command, argument in (
        ("gibti-get-suspicious-ip-vpn-info", "id"),
        ("gibti-get-suspicious-ip-scanner-info", "id"),
        ("gibti-get-malware-malware-info", "id"),
        ("ip", "ip"),
        ("domain", "domain"),
        ("file", "file"),
    ):
        [declared] = [item for item in commands[command]["arguments"] if item["name"] == argument]
        assert declared.get("required") is True
        assert f"***{command}***" in line
        assert f"*{argument}*" in line


def test_no_two_sections_of_a_layout_tab_share_a_cell():
    for path in (PACK / "Layouts").glob("*.json"):
        for tab in (json.loads(path.read_text()).get("detailsV2") or {}).get("tabs") or []:
            cells: dict = {}
            for section in tab.get("sections") or []:
                if any(section.get(key) is None for key in "xywh"):
                    continue
                for x in range(section["x"], section["x"] + section["w"]):
                    for y in range(section["y"], section["y"] + section["h"]):
                        assert (x, y) not in cells, (path.name, tab.get("name"), section.get("name"), cells.get((x, y)))
                        cells[(x, y)] = section.get("name")


def test_the_spd_lookup_declares_every_output_it_writes():
    with open(f"{realpath}/GroupIBTIA.yml") as yml_file:
        commands = yml_file.read().split("\n  - arguments:\n")
    [command] = [command for command in commands if "\n    name: gibti-get-compromised-spd-info\n" in command]
    declared = set(re.findall(r"contextPath: (\S+)", command))
    chunk = {"count": 1, "items": [_wallet(BTC_LEGACY, "BTCLike")]}
    parsed = Parser(chunk=chunk, keys=[], iocs_keys=[]).parse_portion(keys=MAPPING["compromised/spd"])[0]
    record = IncidentBuilder.portal_link("compromised/spd", IncidentBuilder.shape("compromised/spd", parsed))
    prefix = COLLECTIONS["compromised/spd"].context_prefix
    written = set()
    for key, value in record.items():
        if key == "indicators" or value is None:
            continue
        written |= {f"{prefix}.{key}.{column}" for column in value} if isinstance(value, dict) else {f"{prefix}.{key}"}
    assert f"{prefix}.source_type" in written
    assert written - declared == set()


def test_every_e_mail_address_of_a_kit_is_listed_once_in_gib_related_emails():
    built = _build("attacks/phishing_kit", _kit(emails=["drop@example.com", "second@example.com", "drop@example.com"]))
    assert built["relatedEmails"] == "drop@example.com\nsecond@example.com"


@pytest.mark.parametrize("placeholder", ["0001-01-01T00:00:00Z", "1976-01-01T00:00:00+00:00"])
def test_the_age_filter_and_the_occurred_time_read_a_placeholder_as_no_date_and_the_incident_blanks_it(placeholder):
    record_filter = GroupIBTIA.RecordFilter.from_params({"max_record_age_days": "30"})
    record = {**_parsed("osi/vulnerability"), "datePublished": placeholder}
    assert record_filter.accepts("osi/vulnerability", record, NOW)
    assert IncidentBuilder._occurred("osi/vulnerability", {"id": "p", "datePublished": placeholder}) is None
    built = IncidentBuilder().build("osi/vulnerability", {**_parsed("osi/vulnerability"), "datePublished": placeholder})
    assert json.loads(built["rawJSON"])["datePublished"] is None


def _playbook_condition(name: str, task_name: str, label: str = "yes") -> list:
    yaml = pytest.importorskip("yaml")
    playbook = yaml.safe_load((PACK / f"Playbooks/{name}.yml").read_text())
    [task] = [task for task in playbook["tasks"].values() if task["task"]["name"] == task_name]
    [condition] = [item["condition"] for item in task["conditions"] if item["label"] == label]
    return condition


@pytest.mark.parametrize(
    "name, task_name, label, shape",
    [
        ("Group-IB_TI_-_Compromised_Account_Response", "Is the login one of yours?", "yes", [2]),
        ("Group-IB_TI_-_Compromised_Account_Response", "Is the compromised device named?", "ticket", [1, 1]),
        ("Group-IB_TI_-_Leaked_Credentials_and_Secrets", "Are the e-mail domains yours?", "yes", [2]),
        ("Group-IB_TI_-_Leaked_Credentials_and_Secrets", "Notify the committers?", "yes", [1, 1]),
        ("Group-IB_TI_-_Malware_C2_Response", "Did a host talk to the C&C?", "yes", [9]),
        ("Group-IB_TI_-_Vulnerability_Triage", "Does a host carry the CVE?", "yes", [3]),
        ("Group-IB_TI_-_Vulnerability_Triage", "Exploitable or likely exploited?", "yes", [4]),
    ],
)
def test_a_playbook_condition_lists_alternatives_inside_a_group_and_requirements_as_groups(name, task_name, label, shape):
    assert [len(group) for group in _playbook_condition(name, task_name, label)] == shape


def test_only_gibti_commands_are_bound_to_an_instance():
    """A playbook task bound to an instance runs a gibti-* command."""
    yaml = pytest.importorskip("yaml")
    for path in (PACK / "Playbooks").glob("*.yml"):
        for task in yaml.safe_load(path.read_text())["tasks"].values():
            if "using" in (task.get("scriptarguments") or {}):
                assert task["task"].get("script", "").startswith("|||gibti-"), (path.name, task["task"].get("script"))


def test_vulnerability_triage_opens_no_ticket_unless_asked():
    yaml = pytest.importorskip("yaml")
    playbook = yaml.safe_load((PACK / "Playbooks/Group-IB_TI_-_Vulnerability_Triage.yml").read_text())
    [ticket] = [item for item in playbook["inputs"] if item["key"] == "CreateTicket"]
    assert ticket["value"]["simple"] == "False"


@pytest.mark.parametrize("mode", ["Partial", "Full"])
def test_a_login_or_domain_that_equals_the_password_keeps_naming_the_account(mode):
    record = {
        "id": "a" * 40,
        "name": "sampleuser",
        "login": "sampleuser",
        "password": "sampleuser",
        "parsedLogin": {"domain": "sampleuser", "ip": None},
        "service": {"domain": "sampleuser", "url": None, "ip": None},
        "note": "the password sampleuser again",
    }
    masked = GroupIBTIA.PasswordMask(mode).apply("compromised/account_group", record)
    assert (masked["name"], masked["login"], masked["parsedLogin"]["domain"], masked["service"]["domain"]) == ("sampleuser",) * 4
    assert "sampleuser" not in masked["note"]
    assert masked.get("password") != "sampleuser"


@pytest.mark.parametrize("mode", ["Partial", "Full"])
@pytest.mark.parametrize(
    "fields",
    [
        {"login": "sampleuser:Sample7Secret"},
        {"name": "sampleuser:Sample7Secret"},
        {"service": {"url": "https://portal.example.com/reset/Sample7Secret?u=sample&p=Sample7Secret"}},
    ],
)
def test_a_password_inside_a_login_pair_or_a_url_of_an_identity_field_is_masked(mode, fields):
    record = {"id": "a" * 40, "password": "Sample7Secret", **fields}
    assert "Sample7Secret" not in json.dumps(GroupIBTIA.PasswordMask(mode).apply("compromised/account_group", record))


def test_an_address_or_domain_holding_the_password_keeps_naming_the_breached_account():
    record = {
        "id": "b" * 40,
        "passwords": ["sampleuser"],
        "emails": ["sampleuser@example.com"],
        "emailDomains": ["sampleuser.example.com"],
    }
    masked = GroupIBTIA.PasswordMask("Partial").apply("compromised/breacheddb", record)
    assert (masked["emails"], masked["emailDomains"]) == (["sampleuser@example.com"], ["sampleuser.example.com"])


def test_a_run_of_asterisks_masks_in_linear_time():
    started = time.perf_counter()
    GroupIBTIA.PostTextMask.mask_text("*" * 200000)
    assert time.perf_counter() - started < 2


def test_the_name_topic_and_url_of_a_forum_post_follow_the_post_mask_and_a_messenger_name_stays():
    card = "4000000000000002"
    post = {
        "id": "d" * 40,
        "text": "x",
        "name": f"dump {card}",
        "topic": f"dump {card}",
        "url": f"https://forum.example.com/t/{card}",
    }
    partial = GroupIBTIA.PostTextMask("Partial").apply("darkweb/forums", dict(post))
    assert (partial["name"], partial["topic"]) == ("dump ************0002",) * 2
    assert partial["url"] == "https://forum.example.com/t/************0002"
    full = GroupIBTIA.PostTextMask("Full").apply("darkweb/forums", dict(post))
    assert ("name" not in full, full["topic"]) == (True, "[withheld]")
    assert full["url"] == "https://forum.example.com/t/************0002"
    named = IncidentBuilder().build("darkweb/forums", {**full, "forum": "forum.example"})
    assert named["name"].endswith("forum.example")
    for url in ("https://forum.example.com/viewforum.php?cid=1234&t=5", "https://forum.example.com/threads/1712345678901"):
        assert GroupIBTIA.PostTextMask("Partial").apply("darkweb/forums", {"id": "d" * 40, "url": url})["url"] == url
    other = {"id": "d" * 40, "text": "x", "name": f"channel {card}"}
    assert GroupIBTIA.PostTextMask("Full").apply("compromised/messenger", dict(other))["name"] == other["name"]


@pytest.mark.parametrize(
    "text, masked",
    [
        ("4000000000000002|12|29|123", "************0002|12|29|***"),
        ("4000000000000002|12/29|123", "************0002|12/29|***"),
        ("4000000000000002|1229|1234", "************0002|1229|***"),
        ("4000000000000002 12 2029 123", "************0002 12 2029 ***"),
        ("4000000000000002|12|29", "************0002|12|29"),
        ("4000000000000002 and 123", "************0002 and 123"),
        ("4000000000000002|2912|123", "************0002|2912|***"),
        ("4000000000000002|2029|12|123", "************0002|2029|12|***"),
        ("4000000000000002 | 12 / 29 | 123", "************0002 | 12 / 29 | ***"),
        ("4000000000000002=12/29=123", "************0002=12/29=***"),
        ("4000000000000002 12.29 123", "************0002 12.29 ***"),
        ("400000******0002|12|29|123", "400000******0002|12|29|***"),
        ("4000000000000002 12/25 500$ fresh", "************0002 12/25 500$ fresh"),
        ("4000000000000002 12/25 1000 USD", "************0002 12/25 1000 USD"),
        ("4000000000000002 12/29 123.45", "************0002 12/29 123.45"),
    ],
)
def test_the_partial_post_mask_clears_a_cvv_after_the_expiry_and_keeps_an_amount_or_a_number_without_an_expiry(text, masked):
    assert GroupIBTIA.PostTextMask.mask_text(text) == masked


def test_a_vulnerability_type_is_quoted_in_the_query():
    record_filter = GroupIBTIA.RecordFilter.from_params({"vulnerability_types": 'a"b'})
    assert record_filter.request_params("osi/vulnerability")["query"] == 'type:"a\\"b"'
    assert (
        GroupIBTIA.RecordFilter.from_params({"vulnerability_types": "a\\b"}).request_params("osi/vulnerability")["query"]
        == 'type:"a\\\\b"'
    )
    excluded = GroupIBTIA.RecordFilter.from_params({"vulnerability_excluded_types": 'a"b'})
    assert excluded.request_params("osi/vulnerability")["query"] == '-type:"a\\"b"'


def test_local_search_sends_no_date_window_next_to_a_cursor(mock_client):
    mock_client.search_collection.return_value = []
    local_search(
        mock_client,
        {"query": "q", "collection_name": "malware/cnc", "date_from": "2024-01-01", "date_to": "2024-02-01", "seq_update": "12"},
    )
    _, kwargs = mock_client.search_collection.call_args
    assert (kwargs["date_from"], kwargs["date_to"], kwargs["sequpdate"]) == (None, None, 12)


def test_an_empty_local_search_with_a_query_points_to_the_global_search(mock_client):
    mock_client.search_collection.return_value = []
    result = local_search(mock_client, {"query": "q", "collection_name": "apt/threat_actor"})
    assert "gibti-global-search counts a wider index" in result.readable_output
    assert "wider index" not in local_search(mock_client, {"collection_name": "apt/threat_actor"}).readable_output


def test_a_local_search_with_results_adds_no_note(mock_client):
    page = MagicMock(raw_dict={"count": 1, "items": [{"id": "a"}]})
    page.parse_portion.return_value = [{"id": "a"}]
    mock_client.search_collection.return_value = [page]
    assert "wider index" not in local_search(mock_client, {"query": "q", "collection_name": "malware/cnc"}).readable_output


@pytest.mark.parametrize("text", ["Bearer xKpQmNvRtLs", "Bearer my-secret-token", "Basic c2FtcGxlOnBhc3M="])
def test_a_token_after_bearer_or_basic_is_masked(text):
    assert GroupIBTIA.PasswordMask("Partial").mask_inline(text) != text


def test_the_name_of_a_page_asset_is_no_e_mail_address():
    built = _build("attacks/phishing_kit", _kit(emails=["logo@2x.png", "drop@example.com"]))
    assert built["relatedEmails"] == "drop@example.com"


def test_the_feed_reputation_help_holds_the_phrase_validation_asks_for():
    text = (Path(realpath).parent / "GroupIB_TIA_Feed/GroupIB_TIA_Feed.yml").read_text()
    assert "Indicators from this integration instance will be marked with this reputation" in text


def test_the_lookups_that_need_an_id_declare_it_required():
    yaml = pytest.importorskip("yaml")
    commands = {command["name"]: command for command in yaml.safe_load(open(f"{realpath}/GroupIBTIA.yml"))["script"]["commands"]}
    for name in ("gibti-get-suspicious-ip-vpn-info", "gibti-get-suspicious-ip-scanner-info", "gibti-get-malware-malware-info"):
        [argument] = [argument for argument in commands[name]["arguments"] if argument["name"] == "id"]
        assert argument.get("required") is True, name


def test_the_pack_metadata_names_github_logins_and_an_optional_cryptocurrency_dependency():
    meta = json.loads((PACK / "pack_metadata.json").read_text())
    assert meta["githubUser"]
    assert all(" " not in user for user in meta["githubUser"])
    assert meta["dependencies"]["Cryptocurrency"]["mandatory"] is False


def test_an_spd_incident_names_the_types_of_its_sources_in_gib_source():
    assert _build("compromised/spd", _wallet(BTC_LEGACY, "BTCLike"))["sourceType"] == "Underground Market"
    mapper = json.loads((PACK / "Classifiers/classifier-Group-IB_Threat_Intelligence_mapper.json").read_text())
    assert mapper["mapping"]["GIB SPD"]["internalMapping"]["GIB Source"] == {"simple": "sourceType"}


def test_an_incidents_fetch_builds_the_other_records_when_a_record_type_is_no_string(mocker, single_session_fixture):
    """When one record's type is an object, the other records of the page become incidents and the cursor passes the page."""
    client = single_session_fixture
    mocker.patch.object(client, "granted_collections", return_value=[{"collection": "compromised/spd"}])
    good = _wallet(BTC_LEGACY, "BTCLike")
    odd = {**_wallet(BTC_P2SH, "BTCLike"), "type": {"name": "IBAN"}}
    page = MagicMock()
    page.sequpdate = 200
    page.portion_size = 2
    page.count = 2
    page.parse_portion.return_value = [odd, good]
    mocker.patch.object(GroupIBTIA.FetchIncidentsCommand, "_open_feed", return_value=(iter([page]), 150))
    mocker.patch.object(GroupIBTIA.demisto, "error")
    next_run, incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": {"compromised/spd": "150"}},
        first_fetch_time="3 days",
        incident_collections=["compromised/spd"],
        max_requests=1,
        hunting_rules=0,
    )
    assert good["id"] in [json.loads(incident["rawJSON"])["id"] for incident in incidents]
    assert next_run["last_fetch"]["compromised/spd"] == "200"


@pytest.mark.parametrize(
    "text, masked",
    [
        ("x 4000 0000 0000 0002 0000 1011 0011 y", "x ************************0011 y"),
        ("x 014 037 0679 061959 042 y", "x ***************9042 y"),
    ],
    ids=["one starts in the last group of the other", "a later one ends first"],
)
def test_numbers_that_share_a_digit_group_are_cut_as_one(text, masked):
    assert GroupIBTIA.PostTextMask.mask_text(text) == masked


def test_the_failures_of_one_value_are_not_named_on_the_next(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"198.51.100.27": 50, "203.0.113.54": 50})

    def read(path: str, value: str, keys: Any = None) -> list:
        if value == "198.51.100.27" and path == "apt/threat":
            raise GroupIBTIA.ConnectionException(ACCOUNT_REFUSAL)
        return []

    mocker.patch.object(ReputationCommand, "_read", side_effect=read)
    first, second = reputation(client, "ip", {"ip": "198.51.100.27,203.0.113.54"})
    assert "reading apt/threat (HTTP 403)" in first.readable_output
    assert "Some Group-IB requests for" not in second.readable_output


@pytest.mark.parametrize(
    "error, label",
    [
        (ACCOUNT_REFUSAL, "HTTP 403"),
        ("Retries exhausted for https://example.com/x: (Caused by ResponseError('too many 503 error responses'))", "HTTP 503"),
        (GroupIBTIA.Client.NOT_A_PAGE, "a body that is not a page of records"),
        (GroupIBTIA.Client.NO_CURSOR, "a page that carries no seqUpdate"),
        ("Request to https://example.com/x timed out after 120s: read timed out", "timeout"),
        ("Request to https://example.com/x failed: SSLError(certificate verify failed)", "TLS failure"),
        ("JSON decode error for https://example.com/x: Expecting value", "not JSON"),
        ("Request to https://example.com/x failed: [Errno 111] Connection refused", "connection failure"),
        ("something else", "ConnectionException"),
    ],
)
def test_a_failed_request_is_labeled_by_its_kind_never_with_its_text(error, label):
    assert ReputationCommand._failure_label(GroupIBTIA.ConnectionException(error)) == label


@pytest.mark.parametrize(
    "cause, label",
    [
        (requests.exceptions.ConnectTimeout("connect timeout"), "timeout"),
        (requests.exceptions.SSLError("certificate verify failed"), "TLS failure"),
        (requests.exceptions.JSONDecodeError("Expecting value", "", 0), "not JSON"),
        (requests.exceptions.ConnectionError("Connection reset by peer"), "connection failure"),
    ],
    ids=["timeout", "TLS", "not JSON", "connection"],
)
def test_a_failed_request_is_labeled_by_the_error_ciaops_chains_never_by_the_looked_up_url(cause, label):
    text = "Request to https://example.com/x?q=https%3A%2F%2FSSL.example%2Ftimed-out failed: lost"
    try:
        raise GroupIBTIA.ConnectionException(text) from cause
    except GroupIBTIA.ConnectionException as exc:
        assert ReputationCommand._failure_label(exc) == label
    unchained = GroupIBTIA.ConnectionException("Request to https://example.com/x?q=SSL failed: [Errno 111] Connection refused")
    assert ReputationCommand._failure_label(unchained) == "connection failure"


def test_the_fallback_url_comparison_ignores_case_and_the_fallback_query_drops_user_info(mocker, single_session_fixture):
    records = {"ioc/primary": [{"url": [{"url": "http://evil.example[/]x"}]}]}
    client = _url_client(mocker, single_session_fixture, records)
    result = _url(client, "http://user:secret@EVIL.example[/]x")
    assert "secret" not in json.dumps(client.url_queries)
    assert result.indicator.dbot_score.score == 2


class _MillisecondServer:
    """An update feed served by millisecond through the ciaops generator: a page starts after the cursor's millisecond
    and answers its last record's cursor; ``unit`` 1 compares the cursor whole."""

    def __init__(self, records: list[dict], unit: int = 1000):
        self.unit = unit
        self.records = sorted(records, key=lambda record: record["seqUpdate"] // unit)
        self.asked: list[Any] = []
        self.params: list[Any] = []

    def create_update_generator(self, collection_name, request_params, sequpdate=None, rate_limit_delay=None):
        self.asked.append(sequpdate)
        self.params.append(request_params)
        cursor = sequpdate
        while True:
            start = -1 if cursor is None else int(cursor) // self.unit
            items = [record for record in self.records if record["seqUpdate"] // self.unit > start][: request_params.limit]
            if not items:
                return
            cursor = items[-1]["seqUpdate"]
            ahead = [record for record in self.records if record["seqUpdate"] // self.unit > start]
            yield GroupIBTIA.Parser({"count": len(ahead), "items": items, "seqUpdate": cursor}, None, None)


def _position_runs(unit: int, sizes: tuple[int, ...] = (1, 3, 1, 7, 2, 4, 1, 5)) -> list[dict]:
    """Records in runs that share a position; inside a millisecond the served order runs against the cursor."""
    records = []
    for index, size in enumerate(sizes):
        for offset in range(size):
            spread = size - offset - 1 if unit > 1 else 0
            records.append({"id": f"{len(records):040x}", "seqUpdate": (5000 + index) * unit + spread})
    return records


def _walk(server: Any, collection: str, limit: int, cursor: Any, seen_keys: Any = ()) -> Any:
    params = GroupIBTIA.TIRequestParams(limit=limit)
    return GroupIBTIA.BoundaryPages(server, collection, params, cursor, seen_keys, 0)


def _delivered(pages: Any) -> list[str]:
    return [record["id"] for page in pages for record in page.raw_dict["items"]]


@pytest.mark.parametrize("limit", [1, 2, 3, 5, 100])
@pytest.mark.parametrize("collection", sorted(GroupIBTIA.BoundaryPages.UNITS))
def test_a_walk_delivers_every_record_once_at_any_page_size(collection, limit):
    """A page edge cuts a run of records at one position; the walk reads the whole run, whatever the page size."""
    unit = GroupIBTIA.BoundaryPages.UNITS[collection]
    records = _position_runs(unit)
    server = _MillisecondServer(records, unit=unit)
    assert sorted(_delivered(_walk(server, collection, limit, 4999 * unit))) == [record["id"] for record in records]


@pytest.mark.parametrize("collection", sorted(GroupIBTIA.BoundaryPages.UNITS))
def test_one_generator_over_the_model_server_reads_fewer_records_than_it_holds(collection):
    """The control case of the walks above: without BoundaryPages, a page edge of the model cuts a run of records."""
    unit = GroupIBTIA.BoundaryPages.UNITS[collection]
    records = _position_runs(unit)
    server = _MillisecondServer(records, unit=unit)
    pages = server.create_update_generator(collection, GroupIBTIA.TIRequestParams(limit=3), 4999 * unit)
    assert len(_delivered(pages)) < len(records)


@pytest.mark.parametrize("limit", [1, 3, 100])
@pytest.mark.parametrize("collection", sorted(GroupIBTIA.BoundaryPages.UNITS))
def test_fetch_runs_of_one_page_each_deliver_every_record_once(collection, limit):
    """The cursor and the digests a run stores let the next run read on with no record skipped or repeated."""
    unit = GroupIBTIA.BoundaryPages.UNITS[collection]
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
    mocker.patch.dict(GroupIBTIA.BoundaryPages.LARGEST_PAGES, {"suspicious_ip/tor_node": 4})
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
    mocker.patch.dict(GroupIBTIA.BoundaryPages.LARGEST_PAGES, {"suspicious_ip/tor_node": 4})
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
    server.create_update_generator.side_effect = [iter([GroupIBTIA.Parser(served, None, None)]), iter([])]
    first = _walk(
        MagicMock(**{"create_update_generator.side_effect": lambda **_: iter([GroupIBTIA.Parser(served, None, None)])}),
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
            raise GroupIBTIA.ConnectionException(message)
        return iter([GroupIBTIA.Parser(body, None, None)])

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
    with pytest.raises(GroupIBTIA.ConnectionException, match=message):
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
    server.create_update_generator.side_effect = lambda **_: iter([GroupIBTIA.Parser(body, None, None)])
    assert len(_delivered(_walk(server, "malware/cnc", 2, 6999))) == 2
    assert server.create_update_generator.call_count == 1


def test_no_walk_asks_for_more_than_a_thousand_records_a_page():
    assert max(GroupIBTIA.BoundaryPages.LARGEST_PAGES.values()) == 1000


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
    server.create_update_generator.side_effect = [iter([GroupIBTIA.Parser(body, None, None)]), iter([])]
    assert len(_delivered(_walk(server, "malware/cnc", 2, 6999))) == 2


def test_a_first_read_that_fails_is_a_refusal():
    server = MagicMock()
    server.create_update_generator.side_effect = GroupIBTIA.ConnectionException(UPDATE_FEED_DOWN)
    with pytest.raises(GroupIBTIA.ConnectionException, match="too many 502 error responses"):
        list(_walk(server, "malware/cnc", 2, 6999))


def test_a_position_served_in_another_order_repeats_no_record(mocker):
    """Each read of a wide millisecond shows another part of it: every record comes once, then the walk moves on."""
    mocker.patch.dict(GroupIBTIA.BoundaryPages.LARGEST_PAGES, {"suspicious_ip/tor_node": 4})
    records = [{"id": f"{n:040x}", "seqUpdate": 7000 + n} for n in range(6)]
    views = [records[:4], records[2:], records[:4]]
    server = MagicMock()
    answers = [
        iter([GroupIBTIA.Parser({"count": 6, "items": view, "seqUpdate": view[-1]["seqUpdate"]}, None, None)]) for view in views
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
    server.create_update_generator.side_effect = lambda **_: iter([GroupIBTIA.Parser(body, None, None)])
    walk = _walk(server, "malware/cnc", 100, 9000, ["kept"])
    with pytest.raises(GroupIBTIA.ConnectionException, match="below the cursor"):
        list(walk)
    assert walk.seen_keys == ["kept"]


def test_records_below_the_held_position_are_dropped():
    body = {"count": 2, "items": [{"id": "a", "seqUpdate": 7000}, {"id": "b", "seqUpdate": 9500}], "seqUpdate": 9500}
    server = MagicMock()
    server.create_update_generator.side_effect = [iter([GroupIBTIA.Parser(body, None, None)]), iter([])]
    assert _delivered(_walk(server, "malware/cnc", 100, 8999)) == ["b"]


def test_a_cursor_inside_a_millisecond_is_not_moved_back():
    """A stored cursor from before the walk need not stand just below a millisecond."""
    body = {"count": 1, "items": [{"id": "a", "seqUpdate": 7600}], "seqUpdate": 7600}
    server = MagicMock()
    server.create_update_generator.side_effect = [iter([GroupIBTIA.Parser(body, None, None)]), iter([])]
    assert [page.sequpdate for page in _walk(server, "suspicious_ip/tor_node", 100, 7500)] == [7500]


def test_a_stored_cursor_that_is_no_number_is_refused():
    with pytest.raises(GroupIBTIA.ConnectionException, match="not a number"):
        _walk(MagicMock(), "malware/cnc", 100, "7000.0")


@pytest.mark.parametrize("limit", [-5, 0])
def test_a_limit_below_one_reads_the_largest_page(limit):
    server = _MillisecondServer(_position_runs(1), unit=1)
    params = GroupIBTIA.TIRequestParams(limit=1)
    object.__setattr__(params, "limit", limit)
    list(GroupIBTIA.BoundaryPages(server, "malware/cnc", params, 4999, (), 0))
    assert server.params[0].limit == GroupIBTIA.BoundaryPages.LARGEST_PAGES["malware/cnc"]


def test_a_walk_ends_when_the_server_answers_the_same_page_whatever_the_cursor():
    page = {"count": 2, "items": [{"id": "a", "seqUpdate": 7000}, {"id": "b", "seqUpdate": 8000}], "seqUpdate": 8000}
    server = MagicMock()
    server.create_update_generator.side_effect = lambda **_: iter([GroupIBTIA.Parser(page, None, None)])
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
    params = GroupIBTIA.TIRequestParams(limit=3, date_from="2026-01-01")
    list(GroupIBTIA.BoundaryPages(server, "malware/cnc", params, None, (), 0))
    assert server.params[0].date_from == "2026-01-01"
    assert len(server.params) > 1
    assert all(sent.date_from is None for sent in server.params[1:])


def test_a_walk_asks_the_millisecond_feeds_for_no_more_than_they_serve():
    server = _MillisecondServer(_position_runs(1000))
    list(_walk(server, "suspicious_ip/scanner", 5000, 4999000))
    assert {params.limit for params in server.params} == {1000}


def test_a_walk_paces_its_requests_itself(mocker):
    wait = mocker.patch.object(GroupIBTIA.RateLimiter, "wait")
    server = MagicMock(wraps=_MillisecondServer(_position_runs(1), unit=1))
    list(_walk(server, "malware/cnc", 3, 4999))
    assert wait.call_count == server.create_update_generator.call_count > 1
    assert {call.kwargs["rate_limit_delay"] for call in server.create_update_generator.call_args_list} == {0}


def test_a_page_without_records_is_refused_as_no_page():
    body = {"count": 1, "items": ["not a record"], "seqUpdate": 7000}
    server = MagicMock()
    server.create_update_generator.side_effect = lambda **_: iter([GroupIBTIA.Parser(body, None, None)])
    with pytest.raises(GroupIBTIA.ConnectionException, match="not a page of records"):
        list(_walk(server, "malware/cnc", 100, 6999))


def test_a_page_without_a_cursor_is_refused():
    body = {"count": 1, "items": [{"id": "a"}]}
    server = MagicMock()
    server.create_update_generator.side_effect = lambda **_: iter([GroupIBTIA.Parser(body, None, None)])
    with pytest.raises(GroupIBTIA.ConnectionException, match="carries no seqUpdate"):
        list(_walk(server, "malware/cnc", 100, 6999))


def test_a_record_without_a_cursor_takes_the_position_of_its_page():
    body = {"count": 1, "items": [{"id": "a"}], "seqUpdate": 7000}
    server = MagicMock()
    server.create_update_generator.side_effect = lambda **_: iter([GroupIBTIA.Parser(body, None, None)])
    walk = _walk(server, "malware/cnc", 100, 6000)
    assert next(iter(walk)).sequpdate == 6999


def _boundary_fetch(client: Any, last_run: dict, **settings: Any) -> tuple[dict, list]:
    return fetch_incidents(
        client=client,
        last_run={"first_fetch_time": "3 days", **last_run},
        first_fetch_time="3 days",
        incident_collections=["malware/cnc"],
        hunting_rules=0,
        **settings,
    )


def _boundary_client(mocker: Any, client: Client, feed: _UpdateFeed) -> Client:
    client.rate_limit_delay = 0
    mocker.patch.object(client.poller, "send_request", side_effect=feed.send_request)
    mocker.patch.object(client, "granted_collections", return_value=[])
    return client


def test_the_fetch_stores_the_digests_with_the_cursor_and_repeats_no_incident(mocker, single_session_fixture):
    records = [_tied_record("malware/cnc", 1, 410), _tied_record("malware/cnc", 2, 410)]
    client = _boundary_client(mocker, single_session_fixture, _UpdateFeed({"malware/cnc": records}))
    next_run, incidents = _boundary_fetch(client, {"last_fetch": {"malware/cnc": "400"}})
    assert next_run["last_fetch"]["malware/cnc"] == "409"
    assert len(next_run["boundary_keys"]["malware/cnc"]) == 2
    assert len(incidents) == 2
    again, repeated = _boundary_fetch(client, next_run)
    assert again["last_fetch"]["malware/cnc"] == "409"
    assert again["boundary_keys"] == next_run["boundary_keys"]
    assert repeated == []


def test_a_record_new_at_the_stored_position_is_fetched_without_a_refusal(mocker, single_session_fixture):
    health = mocker.patch.object(GroupIBTIA.demisto, "updateModuleHealth")
    feed = _UpdateFeed({"malware/cnc": [_tied_record("malware/cnc", 1, 410)]})
    client = _boundary_client(mocker, single_session_fixture, feed)
    next_run, _ = _boundary_fetch(client, {"last_fetch": {"malware/cnc": "400"}})
    feed.records["malware/cnc"].append(_tied_record("malware/cnc", 2, 410))
    again, incidents = _boundary_fetch(client, next_run)
    assert len(incidents) == 1
    assert again["last_fetch"]["malware/cnc"] == "409"
    assert len(again["boundary_keys"]["malware/cnc"]) == 2
    health.assert_not_called()


def test_a_page_edge_loses_no_incident_over_several_runs(mocker, single_session_fixture):
    records = [_tied_record("malware/cnc", n, 410 + n // 3) for n in range(1, 11)]
    client = _boundary_client(mocker, single_session_fixture, _UpdateFeed({"malware/cnc": records}))
    client.limit = 2
    last_run: dict = {"last_fetch": {"malware/cnc": "400"}}
    names = []
    for _ in range(12):
        last_run, incidents = _boundary_fetch(client, last_run, max_requests=1)
        names.extend(incident["name"] for incident in incidents)
    assert len(names) == len(records)
    assert len(set(names)) == len(records)


def test_a_changed_first_fetch_drops_the_stored_digests(mocker, single_session_fixture):
    feed = _UpdateFeed({"malware/cnc": [_tied_record("malware/cnc", 1, 410)]}, start_cursors={"malware/cnc": 409})
    client = _boundary_client(mocker, single_session_fixture, feed)
    stored = {"first_fetch_time": "7 days", "last_fetch": {"malware/cnc": "409"}, "boundary_keys": {"malware/cnc": ["x"]}}
    next_run, incidents = fetch_incidents(
        client=client, last_run=stored, first_fetch_time="3 days", incident_collections=["malware/cnc"], hunting_rules=0
    )
    assert incidents
    assert "x" not in next_run["boundary_keys"]["malware/cnc"]


def test_a_refused_read_keeps_the_stored_cursor_and_digests(mocker, single_session_fixture):
    mocker.patch.object(GroupIBTIA.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIBTIA.demisto, "error")
    client = single_session_fixture
    client.rate_limit_delay = 0
    mocker.patch.object(client.poller, "send_request", side_effect=GroupIBTIA.ConnectionException(UPDATE_FEED_DOWN))
    mocker.patch.object(client, "granted_collections", return_value=[])
    last_run = {
        "first_fetch_time": "3 days",
        "last_fetch": {"malware/cnc": "409", "osi/git_repository": "400"},
        "boundary_keys": {"malware/cnc": ["kept"]},
    }
    with pytest.raises(GroupIBTIA.DemistoException):
        fetch_incidents(
            client=client,
            last_run=last_run,
            first_fetch_time="3 days",
            incident_collections=["malware/cnc", "osi/git_repository"],
            hunting_rules=0,
        )
    command = FetchIncidentsCommand(client, fetch_settings(["malware/cnc"]))
    cursor, refusal = command._fetch("malware/cnc", dict(last_run), [], False)
    assert cursor == "409"
    assert "too many 502 error responses" in (refusal or "")
    assert command._boundary_keys["malware/cnc"] == ["kept"]


def test_a_position_too_wide_to_read_goes_to_instance_health_and_the_fetch_moves_on(mocker, single_session_fixture):
    health = mocker.patch.object(GroupIBTIA.demisto, "updateModuleHealth")
    mocker.patch.object(GroupIBTIA.demisto, "error")
    mocker.patch.dict(GroupIBTIA.BoundaryPages.LARGEST_PAGES, {"malware/cnc": 2})
    records = [_tied_record("malware/cnc", n, 410) for n in range(1, 4)]
    client = _boundary_client(mocker, single_session_fixture, _UpdateFeed({"malware/cnc": records}))
    client.limit = 2
    next_run, incidents = _boundary_fetch(client, {"last_fetch": {"malware/cnc": "400"}})
    assert next_run["last_fetch"]["malware/cnc"] == "410"
    assert incidents
    assert "malware/cnc" in health.call_args.args[0]
    assert "cursor position" in health.call_args.args[0]


def test_a_search_stays_on_one_ciaops_generator(mocker, single_session_fixture):
    client = single_session_fixture
    generator = mocker.patch.object(client.poller, "create_update_generator", return_value=iter([]))
    assert list(client.search_collection("compromised/spd", query="x", limit=10)) == []
    generator.assert_called_once()


def test_only_the_collections_whose_records_share_cursor_positions_get_boundary_pages(single_session_fixture):
    client = single_session_fixture
    params = GroupIBTIA.TIRequestParams(limit=10)
    assert isinstance(client.update_feed("malware/cnc", params, 5), GroupIBTIA.BoundaryPages)
    assert not isinstance(client.update_feed("ioc/primary", params, 5), GroupIBTIA.BoundaryPages)


CARD = "4111111111111111"


def test_a_change_of_a_text_leaves_its_ipv4_addresses_alone():
    assert GroupIBTIA.PostTextMask._outside_addresses("a 198.51.100.7 b", str.upper) == "A 198.51.100.7 B"


def test_a_url_is_read_around_its_ipv4_addresses(mocker):
    mocker.patch.object(GroupIBTIA.PostTextMask, "_outside_addresses", return_value="around")
    assert GroupIBTIA.PostTextMask.masked_url("https://198.51.100.7/") == "around"


def test_an_incident_of_a_cve_with_a_placeholder_date_keeps_it_out_of_its_raw_json(mocker, single_session_fixture):
    client = single_session_fixture
    client.rate_limit_delay = 0
    record = _cve(datePublished="1976-01-01T00:00:00+00:00", seqUpdate=410)
    mocker.patch.object(client.poller, "send_request", side_effect=_UpdateFeed({"osi/vulnerability": [record]}).send_request)
    mocker.patch.object(client, "granted_collections", return_value=[])
    _, [incident] = fetch_incidents(
        client=client,
        last_run={"last_fetch": {"osi/vulnerability": "400"}},
        first_fetch_time="3 days",
        incident_collections=["osi/vulnerability"],
        hunting_rules=0,
    )
    assert "1976-01-01" not in incident["rawJSON"]


@pytest.mark.parametrize("mode", ["Partial", "Full"])
@pytest.mark.parametrize(
    "url, shown",
    [
        (f"https://f.example/t/{CARD}", "https://f.example/t/************1111"),
        (f"https://f.example/t/{CARD}-12-25-123", "https://f.example/t/************1111-12-25-***"),
        (f"https://f.example/t/123-{CARD}", "https://f.example/t/123-************1111"),
        ("https://f.example/t?c=4111+1111+1111+1111", "https://f.example/t?c=************1111"),
        ("https://f.example/t?c=4111%201111%201111%201111", "https://f.example/t?c=************1111"),
        ("https://f.example/t?c=4111-1111-1111-1111", "https://f.example/t?c=************1111"),
        ("https://f.example/t/4111_1111_1111_1111", "https://f.example/t/************1111"),
        (f"https://f.example/t/{CARD}%7C12%7C25%7C123", "https://f.example/t/************1111%7C12%7C25%7C***"),
        (f"https://f.example/t/{CARD}|12|25|123", "https://f.example/t/************1111|12|25|***"),
        (f"https://f.example/t?c={CARD}&cvv=123", "https://f.example/t?c=************1111&cvv=***"),
        ("https://f.example/t?cvc2=1234", "https://f.example/t?cvc2=***"),
        (f"https://f.example/t?q=card%20{CARD}", "https://f.example/t?q=card%20************1111"),
        (f"https://f.example/t/%21{CARD}", "https://f.example/t/%21************1111"),
        (f"https://f.example/t/%26{CARD}", "https://f.example/t/%26************1111"),
        ("https://f.example/t?q=x%204111%201111%201111%201111", "https://f.example/t?q=x%20************1111"),
        ("https://f.example/t/4111/1111/1111/1111", "https://f.example/t/************1111"),
        ("https://f.example/t?c=4111:1111:1111:1111", "https://f.example/t?c=************1111"),
        ("https://f.example/t?c=4111%2B1111%2B1111%2B1111", "https://f.example/t?c=************1111"),
        ("https://f.example/t?c=4111++1111++1111++1111", "https://f.example/t?c=************1111"),
        ("https://f.example/t?c=4111%20-%201111%20-%201111%20-%201111", "https://f.example/t?c=************1111"),
        (f"https://f.example/t/*{CARD}", "https://f.example/t/*************1111"),
        ("https://f.example/t?a=100%20x-4111-1111-1111-1111", "https://f.example/t?a=100%20x-************1111"),
        (f"https://f.example/t/{CARD}|123|12|25", "https://f.example/t/************1111|***|12|25"),
        (f"https://f.example/t/{CARD}-exp-12-25-123", "https://f.example/t/************1111-exp-12-25-***"),
        ("https://f.example/t?card[cvv]=123", "https://f.example/t?card[cvv]=***"),
        ("https://f.example/t?cvv_code=123", "https://f.example/t?cvv_code=***"),
        (f"https://f.example/t/{CARD}-123-12-25", "https://f.example/t/************1111-***-12-25"),
        (f"https://f.example/t/{CARD}-1234-12-25", "https://f.example/t/************1111-***-12-25"),
        (f"https://f.example/t/{CARD}%7C123%7C12%7C25", "https://f.example/t/************1111%7C***%7C12%7C25"),
        (f"https://f.example/t/{CARD}|123|12|2025", "https://f.example/t/************1111|***|12|2025"),
        (f"https://f.example/t/{CARD}%3A12%3A25%3A123", "https://f.example/t/************1111%3A12%3A25%3A***"),
        ("https://f.example/t?cvv%3D123", "https://f.example/t?cvv%3D***"),
        ("https://f.example/t?card_cvv=123", "https://f.example/t?card_cvv=***"),
        ("https://f.example/t?cardCvv=123", "https://f.example/t?cardCvv=***"),
        ("https://f.example/t?cvv:123", "https://f.example/t?cvv:***"),
        ("https://f.example/t?cvv%20=%20123", "https://f.example/t?cvv%20=%20***"),
        (f"https://f.example/t?c={CARD}=25121011234567", "https://f.example/t?c=************1111=***"),
        (
            f"https://f.example/t/B{CARD}%5ESAMPLE%2FNAME%5E25121011234",
            "https://f.example/t/B************1111%5ESAMPLE%2FNAME%5E***",
        ),
    ],
)
def test_a_forum_url_loses_its_card_numbers_cvv_codes_and_stripe_data(mode, url, shown):
    masked = GroupIBTIA.PostTextMask(mode).apply("darkweb/forums", {"id": "a", "url": url})
    assert masked["url"] == shown


@pytest.mark.parametrize(
    "url",
    [
        "https://f.example/status/1793145148216929281",
        "https://f.example/t/2023-12-05-1234",
        "https://f.example/t?cid=1234",
        "https://f.example/t/192.0.2.15/page-100",
        "https://f.example/thread/12345678/page-2",
        "https://f.example/t?c=123%20456",
        "https://f.example/forums/free-cc-cvv.1234/",
        "https://f.example/threads/cvv.123/",
        "https://[2001:db8::1]:8080/page",
        "https://f.example:8443/t",
        "https://f.example/t/2023/12/05/page-100",
    ],
)
def test_a_forum_url_keeps_its_ids_dates_addresses_and_ports(url):
    assert GroupIBTIA.PostTextMask("Partial").apply("darkweb/forums", {"id": "a", "url": url})["url"] == url


@pytest.mark.parametrize(
    "text, shown",
    [
        (f"{CARD}|123|12|25", "************1111|***|12|25"),
        (f"{CARD}|123|12|2025", "************1111|***|12|2025"),
        (f"{CARD}|2025|12|123", "************1111|2025|12|***"),
        (f"{CARD}-12-25-123", "************1111-12-25-***"),
        (f"{CARD}=25121011234567", "************1111=***"),
        (f"B{CARD}^SAMPLE/NAME^25121011234", "B************1111^SAMPLE/NAME^***"),
        (f"{CARD} 12/25 500$", "************1111 12/25 500$"),
        (f"{CARD} 12/25 500 $", "************1111 12/25 500 $"),
        (f"{CARD} 12/25 500 usd", "************1111 12/25 500 usd"),
        (f"{CARD} 12/25 500 BTC", "************1111 12/25 500 BTC"),
        (f"{CARD} 12-05-2023", "************1111 12-05-2023"),
        (f"{CARD}, 2023-12-05 10:00", "************1111, 2023-12-05 10:00"),
        (f"{CARD} 12/25 2023-12-05", "************1111 12/25 2023-12-05"),
        (f"{CARD}|1234|12|25", "************1111|***|12|25"),
        (f"{CARD}|123|1225", "************1111|***|1225"),
        (f"{CARD}|123|122025", "************1111|***|122025"),
        (f"{CARD}|123|2025|12", "************1111|***|2025|12"),
        (f"{CARD}|123|25|12", "************1111|***|25|12"),
        (f"{CARD} 123 12/25", "************1111 *** 12/25"),
        (f"{CARD}	123	12	25", "************1111	***	12	25"),
        (f"{CARD} 123 12 2025", "************1111 *** 12 2025"),
        (f"{CARD}|SAMPLE NAME|12|25|123", "************1111|SAMPLE NAME|12|25|***"),
        (f"{CARD}|12|25|SAMPLE NAME|123", "************1111|12|25|SAMPLE NAME|***"),
        (f"{CARD}.123.12.25", "************1111.***.12.25"),
        (f"{CARD}.12.25.123", "************1111.12.25.***"),
    ],
)
def test_a_dump_line_after_its_card_number_loses_only_its_cvv_or_stripe_data(text, shown):
    assert GroupIBTIA.PostTextMask.mask_text(text) == shown


@pytest.mark.parametrize("login", ["sample user1", "sample!user1", "+1 (555) 010-0123", "name(1)", "CORP\\sampleuser1"])
def test_a_login_of_any_shape_equal_to_the_password_stays(login):
    record = {"id": "a" * 40, "login": login, "password": login}
    masked = GroupIBTIA.PasswordMask("Partial").apply("compromised/account_group", record)
    assert masked["login"] == login
    assert masked["password"] != login


def test_a_domain_that_is_the_password_is_masked():
    record = {"id": "a" * 40, "login": "Sample-Secret-1\\user", "password": "Sample-Secret-1"}
    assert "Sample-Secret-1" not in GroupIBTIA.PasswordMask("Partial").apply("compromised/account_group", record)["login"]


def test_a_domain_login_whose_user_is_the_password_stays():
    record = {"id": "a" * 40, "login": "CORP\\sampleuser1", "password": "sampleuser1"}
    assert GroupIBTIA.PasswordMask("Partial").apply("compromised/account_group", record)["login"] == "CORP\\sampleuser1"


@pytest.mark.parametrize(
    "login",
    [
        "sample Sample-Secret-1",
        "Sample-Secret-1 extra",
        "sample\tSample-Secret-1",
        "user@example.com Sample-Secret-1",
        "password Sample-Secret-1",
        "user(Sample-Secret-1)",
        "user~Sample-Secret-1",
        "user\nSample-Secret-1",
    ],
)
def test_a_login_with_the_password_beside_it_is_masked(login):
    record = {"id": "a" * 40, "login": login, "password": "Sample-Secret-1"}
    assert "Sample-Secret-1" not in GroupIBTIA.PasswordMask("Partial").apply("compromised/account_group", record)["login"]


@pytest.mark.parametrize(
    "login",
    ["user:Sample-Secret-1", "https://user:Sample-Secret-1@example.com/", "user;Sample-Secret-1", "user|Sample-Secret-1"],
)
def test_a_login_holding_a_credential_is_still_masked(login):
    record = {"id": "a" * 40, "login": login, "password": "Sample-Secret-1"}
    assert "Sample-Secret-1" not in GroupIBTIA.PasswordMask("Partial").apply("compromised/account_group", record)["login"]


def test_cve_scoring_reads_a_placeholder_date_as_no_date(mocker, single_session_fixture):
    portion = MagicMock()
    portion.parse_portion.return_value = [
        _vulnerability(date_published="1976-01-01T00:00:00+00:00", date_modified="0001-01-01T00:00:00Z")
    ]
    mocker.patch.object(single_session_fixture.poller, "search_feed_by_id", return_value=portion)
    [result] = score_cves(single_session_fixture, {"cve": "CVE-2099-0001"})
    assert (result.outputs["datePublished"], result.outputs["dateModified"]) == (None, None)
    assert (result.indicator.published, result.indicator.modified) == (None, None)


def test_a_cve_lookup_shows_no_placeholder_date(mocker, single_session_fixture):
    record = _cve(datePublished="1976-01-01T00:00:00+00:00", dateModified="0001-01-01T00:00:00Z")
    record["indicators"] = {"datePublished": "1976-01-01T00:00:00+00:00", "dateModified": "2024-01-02T00:00:00+00:00"}
    results = _lookup_record(mocker, single_session_fixture, "osi/vulnerability", [record])
    shown = json.dumps([result.to_context() for result in results])
    assert "1976-01-01" not in shown
    assert "0001-01-01" not in shown


def test_an_incident_keeps_no_placeholder_date_in_its_indicators_block():
    record = {"indicators": {"datePublished": "1976-01-01T00:00:00+00:00", "dateModified": "2024-01-02T00:00:00+00:00"}}
    assert IncidentBuilder.blank_placeholder_dates(record)["indicators"] == {
        "datePublished": None,
        "dateModified": "2024-01-02T00:00:00+00:00",
    }


def test_a_cve_indicator_takes_no_placeholder_date():
    feed = {
        "evaluation": {"severity": "red"},
        "indicators": {
            "id": "CVE-2021-1",
            "datePublished": "1976-01-01T00:00:00+00:00",
            "dateModified": "2024-01-02T00:00:00+00:00",
            "description": "d",
            "cvss_score": 9.8,
        },
    }
    [entry] = IndicatorBuilder(create_relationships=False).results(feed, "osi/vulnerability")
    [cve] = next(value for key, value in entry.to_context()["EntryContext"].items() if key.startswith("CVE"))
    assert not cve.get("Published")
    assert cve["Modified"] == "2024-01-02T00:00:00+00:00"


@pytest.mark.parametrize(
    "value, known",
    [
        ("1976-01-01T00:00:00+00:00", None),
        ("0001-01-01", None),
        ("2024-03-01T00:00:00+00:00", "2024-03-01T00:00:00+00:00"),
        ("12-05-2023", "12-05-2023"),
        ("12-05-23", "12-05-23"),
        (None, None),
    ],
)
def test_a_placeholder_date_reads_as_no_date(value, known):
    assert GroupIBTIA.known_date(value) == known


@pytest.mark.parametrize("gap", [" ", "\t", "\n"])
def test_a_cvv_label_followed_by_a_long_gap_masks_in_linear_time(gap):
    started = time.perf_counter()
    assert GroupIBTIA.PostTextMask.mask_text("cvv" + gap * 100000) == "cvv" + gap * 100000
    assert time.perf_counter() - started < 2


@pytest.mark.parametrize("label", ["cvv 123", "CVV: 123", "cvc = 123", "CVV2:123", "cid 1234", "cvv :  123"])
def test_a_labeled_cvv_is_cleared_after_any_gap(label):
    assert "*" in GroupIBTIA.PostTextMask.mask_text(label)
    assert not re.search(r"\d{3}", GroupIBTIA.PostTextMask.mask_text(label).replace("CVV2", "").replace("cvv2", ""))


def test_the_requests_of_one_lookup_run_in_parallel(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"198.51.100.27": 90})
    mocker.patch.object(ReputationCommand, "_read", side_effect=lambda path, value, keys=None: time.sleep(0.4) or [])
    started = time.monotonic()
    reputation(client, "ip", {"ip": "198.51.100.27"}, parallel_requests=12)
    parallel = time.monotonic() - started
    started = time.monotonic()
    reputation(client, "ip", {"ip": "198.51.100.27"}, parallel_requests=1)
    sequential = time.monotonic() - started
    # Four collection reads of 0.4 s each; the floor listings answer at once.
    assert parallel < 1.0
    assert sequential >= 1.6


def test_a_fork_has_a_poller_of_its_own_with_the_instance_settings(single_session_fixture):
    client = single_session_fixture
    twin = REAL_FORK(client)
    assert twin.poller is not client.poller
    assert twin.poller._session is not client.poller._session
    assert twin.poller._session.verify == client.poller._session.verify
    assert twin.poller._session.auth == client.poller._session.auth
    assert twin.poller._session.headers.get("User-Agent") == client.poller._session.headers.get("User-Agent")
    assert twin.rate_limit_delay == client.rate_limit_delay


@pytest.mark.parametrize(
    "answer, expected",
    [
        (
            GroupIBTIA.ConnectionException(
                "HTTP 400: Bad Credentials or Wrong request. The issue can be related to the wrong searchable tag for entity. "
                "Server said: item with id 203.0.113.9 not found: not valid"
            ),
            [],
        ),
        (
            GroupIBTIA.NotFoundException("HTTP 404: Not found. There is no such data on server or you are using wrong endpoint."),
            [],
        ),
    ],
)
def test_an_address_a_suspicious_ip_collection_does_not_list_is_no_listing(mocker, single_session_fixture, answer, expected):
    mocker.stopall()
    client = single_session_fixture
    mocker.patch.object(client, "record_by_id", side_effect=answer)
    assert evidence(client)._listing("suspicious_ip/tor_node", "203.0.113.9") == expected


@pytest.mark.parametrize(
    "answer",
    [
        GroupIBTIA.ConnectionException(
            "HTTP 400: Bad Credentials or Wrong request. The issue can be related to the wrong searchable tag for entity."
        ),
        GroupIBTIA.ConnectionException(SERVER_ERROR),
    ],
)
def test_any_other_failed_listing_read_is_a_failure(mocker, single_session_fixture, answer):
    mocker.stopall()
    client = single_session_fixture
    mocker.patch.object(client, "record_by_id", side_effect=answer)
    with pytest.raises(GroupIBTIA.ConnectionException):
        evidence(client)._listing("suspicious_ip/tor_node", "203.0.113.9")


def test_a_listing_is_the_record_the_collection_answers_by_id(mocker, single_session_fixture):
    mocker.stopall()
    client = single_session_fixture
    record = {"id": "203.0.113.9", "dateLastSeen": "2026-11-01T00:00:00+00:00"}
    mocker.patch.object(client, "record_by_id", return_value=Parser(record, [], []))
    assert evidence(client)._listing("suspicious_ip/tor_node", "203.0.113.9") == [record]


def test_the_lookup_settings_default_to_four_requests_at_once_and_no_global_search():
    settings = Settings.from_params({})
    assert (settings.parallel_requests, settings.use_global_search) == (4, False)


def test_parallel_requests_per_lookup_refuses_zero():
    with pytest.raises(DemistoException, match="Parallel requests per lookup must be 1 or more"):
        Settings.from_params({"parallel_requests": "0"})


def test_the_global_search_adds_the_collections_that_mention_the_value(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"198.51.100.27": 20})
    mocker.patch.object(client.poller, "global_search", return_value=[{"apiPath": "compromised/messenger", "count": 3}])
    [result] = reputation(client, "ip", {"ip": "198.51.100.27"}, use_global_search=True)
    assert result.outputs["collections"] == ["compromised/messenger"]
    [result] = reputation(client, "ip", {"ip": "198.51.100.27"})
    assert result.outputs["collections"] == []


def test_a_call_that_ends_with_a_base_exception_raises_it(single_session_fixture):
    class Stop(BaseException):
        pass

    def stop() -> None:
        raise Stop

    with pytest.raises(Stop):
        GroupIBTIA.ParallelCalls(single_session_fixture, 2, 5, threading.local()).run({"a": stop, "b": lambda: 1})


def test_an_empty_page_does_not_name_its_collection(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"198.51.100.27": 20})
    mocker.patch.object(ReputationCommand, "_read", side_effect=lambda path, value, keys=None: [{"count": 0, "items": []}, {}])
    [result] = reputation(client, "ip", {"ip": "198.51.100.27"})
    assert result.outputs["collections"] == []
    assert "No Group-IB collection lists" in result.readable_output


def _whois_object(kind: str, **fields: Any) -> dict:
    return {
        "type": kind,
        "values": {},
        "parsed": [
            {"field": name.replace("_", "-"), "value": value if isinstance(value, list) else [value]}
            for name, value in fields.items()
        ],
    }


def _ip_graph(*snapshots: tuple[str, list[dict]], provider: str = "ripe") -> dict:
    return {
        "id": "x",
        "start": "198.51.100.0",
        "end": "198.51.100.255",
        "provider": provider,
        "whoisSummary": {"isp": "RPKI ROA for 198.51.100.0/24 / AS64496", "phone": "+000000000"},
        "whoisHistory": [{"first_seen": seen, "last_seen": seen, "data": data} for seen, data in snapshots],
    }


SAMPLE_IP_SNAPSHOT = [
    _whois_object("inetnum", inetnum=[], netname="SAMPLE-NET", cidr="198.51.100.0/24", status="ASSIGNED PA", country="NL"),
    _whois_object("organisation", **{"org_name": "Sample Hosting B.V.", "country": "nl", "phone": "+1-555-0150"}),
    _whois_object("role", role=[], **{"abuse_mailbox": "abuse@example.net", "phone": ["+1-555-0199", "+000000000"]}),
    _whois_object("route", route=[], descr="RPKI ROA for 198.51.100.0/24 / AS64496", origin="AS64496"),
    _whois_object("route", route=[], descr="Sample Transit", origin="AS64496"),
    _whois_object("route", route=[], origin="64497"),
]


def test_an_ip_record_takes_each_field_from_its_registry_object():
    record = IPWhois.parse("198.51.100.27", _ip_graph(("2026-11-01", SAMPLE_IP_SNAPSHOT)))
    assert record.to_context() == {
        "ip": "198.51.100.27",
        "rangeStart": "198.51.100.0",
        "rangeEnd": "198.51.100.255",
        "cidr": "198.51.100.0/24",
        "registry": "RIPE",
        "netname": "SAMPLE-NET",
        "organization": "Sample Hosting B.V.",
        "country": "NL",
        "asn": "AS64496",
        "abuseEmails": ["abuse@example.net"],
        "abusePhones": ["+1-555-0199"],
        "status": "ASSIGNED PA",
        "firstSeen": "2026-11-01",
        "lastSeen": "2026-11-01",
    }


def test_an_ip_record_takes_a_field_the_newest_snapshot_lacks_from_an_older_one():
    routes_only = [_whois_object("route", route=[], origin="AS64498")]
    record = IPWhois.parse("198.51.100.27", _ip_graph(("2026-11-08", routes_only), ("2026-10-01", SAMPLE_IP_SNAPSHOT)))
    assert (record.asn, record.organization, record.cidr, record.last_seen) == (
        "AS64498",
        "Sample Hosting B.V.",
        "198.51.100.0/24",
        "2026-11-08",
    )


def test_an_ip_record_finds_the_abuse_contact_among_unlabeled_contacts():
    """ARIN contacts carry no role: only an e-mail address with abuse in it names the abuse contact; aut-num names the AS."""
    contacts = [
        _whois_object("inetnum", inetnum=[], **{"org_name": "Sample Networks LLC"}, netname="SAMPLE-ARIN"),
        _whois_object("contact", contact=[], phone="+1-555-0100", **{"e_mail": "noc@example.com"}),
        _whois_object("contact", contact=[], phone="+1-555-0199", **{"e_mail": "network-abuse@example.com"}),
        _whois_object("aut-num", **{"aut_num": "AS64496", "as_name": "SAMPLE-AS"}),
    ]
    record = IPWhois.parse("198.51.100.27", _ip_graph(("2026-11-01", contacts), provider="arin"))
    assert (record.organization, record.abuse_emails, record.abuse_phones) == (
        "Sample Networks LLC",
        ("network-abuse@example.com",),
        ("+1-555-0199",),
    )
    assert (record.asn, record.as_owner) == ("AS64496", "SAMPLE-AS")


def test_an_ip_record_reads_no_owner_of_the_as_without_an_aut_num_object():
    record = IPWhois.parse("198.51.100.27", _ip_graph(("2026-11-01", SAMPLE_IP_SNAPSHOT)))
    assert record.as_owner is None


def test_an_ip_record_lists_the_snapshots_before_the_newest_up_to_the_limit():
    body = _ip_graph(*[(f"2026-0{month}-01", SAMPLE_IP_SNAPSHOT) for month in range(1, 6)])
    record = IPWhois.parse("198.51.100.27", body, history_limit=2)
    assert record.last_seen == "2026-05-01"
    assert [item["lastSeen"] for item in record.history] == ["2026-04-01", "2026-03-01"]
    assert record.history[0] == {
        "firstSeen": "2026-04-01",
        "lastSeen": "2026-04-01",
        "organization": "Sample Hosting B.V.",
        "netname": "SAMPLE-NET",
        "asn": "AS64496",
        "cidr": "198.51.100.0/24",
    }


def test_an_ip_record_of_no_answer_has_the_address_only():
    assert IPWhois.parse("198.51.100.27", None).to_context() == {"ip": "198.51.100.27"}


SAMPLE_REGISTRY_TEXT = "\r\n".join(
    [
        "Domain Name: SAMPLE-SHOP.EXAMPLE",
        "   Registrar WHOIS Server: whois.registrar.example",
        "   Updated Date: 2026-01-02T03:04:05Z",
        "   Creation Date: 2015-06-07T08:09:10Z",
        "   Registry Expiry Date: 2027-06-07T08:09:10Z",
        "   Registrar: Sample Registrar LLC",
        "   Registrar IANA ID: 9999",
        ">>> Last update of whois database: 2026-11-09T00:00:00Z <<<",
    ]
)
SAMPLE_REGISTRAR_TEXT = "\n".join(
    [
        "Domain Name: sample-shop.example",
        "Registrar Abuse Contact Email: abuse@registrar.example",
        "Registrar Abuse Contact Phone: +1.5550100",
        "Registrant Name: Sample Owner",
        "Registrant Organization: REDACTED FOR PRIVACY",
        "Registrant Email: owner@example.com",
        "Registrant Country: US",
    ]
)


def _domain_graph(name: str = "sample-shop.example", **extra: Any) -> dict:
    return {
        "name": name,
        "zone": "example",
        "is_sld": True,
        "whois": [
            {
                "level": 1,
                "checked_at": "2026-11-09 10:00:00",
                "response": SAMPLE_REGISTRY_TEXT,
                "parsed": [
                    {"field": "Registrar", "value": ["sample registrar llc"]},
                    {
                        "field": "Status",
                        "value": ["clientTransferProhibited https://registry.example/epp#clienttransferprohibited", "ok,"],
                    },
                    {"field": "NameServers", "value": ["NS1.EXAMPLE.NET.", "ns2.example.net"]},
                    {"field": "CreationDate", "value": []},
                ],
            },
            {"level": 2, "checked_at": "2026-11-09 10:00:01", "response": SAMPLE_REGISTRAR_TEXT, "parsed": []},
        ],
        "whois_history": [
            {
                "first_seen": "2020-01-01",
                "last_seen": "2024-01-01",
                "parsed": [{"field": "Registrar", "value": ["Older Registrar"]}],
            },
            {
                "first_seen": "2024-01-02",
                "last_seen": "2026-11-09",
                "parsed": [{"field": "Registrar", "value": ["Sample Registrar LLC"]}],
            },
        ],
        **extra,
    }


def test_a_domain_record_takes_a_missing_field_from_the_newest_record_that_has_it(mocker):
    mocker.patch.object(
        GroupIBTIA, "dateparser_parse", side_effect=lambda text: datetime.fromisoformat(text.replace("Z", "+00:00"))
    )
    snapshot = [
        {"field": "registrar", "value": ["SAMPLE-REG"]},
        {"field": "org", "value": ["Sample Org"]},
        {"field": "name_servers", "value": ["ns1.sample.example", "ns2.sample.example"]},
        {"field": "creation_date", "value": ["2001-02-03T04:05:06Z"]},
        {"field": "status", "value": ["REGISTERED, DELEGATED"]},
    ]
    body = {
        "name": "sample.test",
        "zone": "test",
        "is_sld": True,
        "whois": [{"level": 1, "checked_at": "2026-11-09 10:00:00", "response": "% for details.", "parsed": []}],
        "whois_history": [
            {"first_seen": "2026-11-09", "last_seen": "2026-11-09", "parsed": []},
            {"first_seen": "2022-01-01", "last_seen": "2022-01-01", "parsed": snapshot},
            {"first_seen": "2020-01-01", "last_seen": "2020-01-01", "parsed": [{"field": "registrar", "value": ["OLDER-REG"]}]},
        ],
    }
    record = DomainWhois.parse("sample.test", body, history_limit=1).to_context()
    assert (record["registrar"], record["registrantOrganization"]) == ("SAMPLE-REG", "Sample Org")
    assert record["nameServers"] == ["ns1.sample.example", "ns2.sample.example"]
    assert record["creationDate"] == "2001-02-03T04:05:06Z"
    assert record["statuses"] == ["registered", "delegated"]
    # the earlier records list their name servers from the same snake_case field
    assert record["history"] == [
        {
            "firstSeen": "2022-01-01",
            "lastSeen": "2022-01-01",
            "registrar": "SAMPLE-REG",
            "nameServers": ["ns1.sample.example", "ns2.sample.example"],
        }
    ]


def test_a_domain_record_leaves_out_a_date_that_is_no_date(mocker):
    mocker.patch.object(GroupIBTIA, "dateparser_parse", return_value=None)
    registry = SAMPLE_REGISTRY_TEXT.replace("2015-06-07T08:09:10Z", "before Aug-1996")
    graph = _domain_graph()
    graph["whois"][0]["response"] = registry
    record = DomainWhois.parse("sample-shop.example", graph, history_limit=1).to_context(personal_data=True)
    assert "creationDate" not in record


def test_a_domain_record_reads_the_registry_and_registrar_answers(mocker):
    mocker.patch.object(
        GroupIBTIA, "dateparser_parse", side_effect=lambda text: datetime.fromisoformat(text.replace("Z", "+00:00"))
    )
    record = DomainWhois.parse("sample-shop.example", _domain_graph(), history_limit=1)
    assert record.to_context() == {
        "domain": "sample-shop.example",
        "zone": "example",
        "registeredDomain": True,
        "registrar": "Sample Registrar LLC",
        "registrarIanaId": "9999",
        "registrarAbuseEmail": "abuse@registrar.example",
        "registrarAbusePhone": "+1.5550100",
        "whoisServer": "whois.registrar.example",
        "registrantCountry": "US",
        "registrantName": "Sample Owner",
        "registrantEmail": "owner@example.com",
        "statuses": ["clienttransferprohibited", "ok"],
        "creationDate": "2015-06-07T08:09:10Z",
        "updatedDate": "2026-01-02T03:04:05Z",
        "expirationDate": "2027-06-07T08:09:10Z",
        "nameServers": ["ns1.example.net", "ns2.example.net"],
        "checkedAt": "2026-11-09 10:00:01",
        # the newest snapshot is the current registration; history starts with the one before
        "history": [{"firstSeen": "2020-01-01", "lastSeen": "2024-01-01", "registrar": "Older Registrar"}],
    }
    without = record.to_context(personal_data=False)
    assert "registrantName" not in without
    assert "registrantEmail" not in without


def test_a_country_code_registry_text_gives_its_dates(mocker):
    mocker.patch.object(
        GroupIBTIA, "dateparser_parse", side_effect=lambda text: datetime.fromisoformat(text.replace("Z", "+00:00"))
    )
    text = "created:       2001-02-03T04:05:06Z\npaid-till:     2030-02-03T04:05:06Z\nregistrar:     SAMPLE-REG\n"
    body = {"name": "sample.example", "zone": "example", "is_sld": True, "whois": [{"level": 1, "response": text}]}
    record = DomainWhois.parse("sample.example", body)
    assert (record.registrar, record.creation_date, record.expiration_date) == (
        "SAMPLE-REG",
        "2001-02-03T04:05:06Z",
        "2030-02-03T04:05:06Z",
    )


def _whois(client: Client, kind: str, args: dict, **settings: Any) -> list[CommandResults]:
    return WhoisCommand(kind, client, settings_with(**settings)).run(args)


def test_the_ip_whois_command_writes_the_record_and_sets_no_verdict(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client.poller, "graph_ip_search", return_value=_ip_graph(("2026-11-01", SAMPLE_IP_SNAPSHOT)))
    [result] = _whois(client, "ip", {"ip": "198.51.100[.]27"})
    assert result.outputs_prefix == "GIBTI.IPWhois"
    assert result.outputs["organization"] == "Sample Hosting B.V."
    assert result.indicator is None
    assert "Sample Hosting B.V." in result.readable_output
    client.poller.graph_ip_search.assert_called_once_with("198.51.100.27")


@pytest.mark.parametrize(
    "value, note",
    [("10.0.0.1", "private, shared or reserved"), ("not-an-ip", "is not an IP address")],
)
def test_the_ip_whois_command_does_not_ask_about_an_internal_or_malformed_address(mocker, single_session_fixture, value, note):
    client = single_session_fixture
    mocker.patch.object(client.poller, "graph_ip_search")
    [result] = _whois(client, "ip", {"ip": value}, lookup_internal_addresses=False)
    assert note in result.readable_output
    client.poller.graph_ip_search.assert_not_called()


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {},
        GroupIBTIA.NotFoundException("HTTP 404: Not found. There is no such data on server or you are using wrong endpoint."),
    ],
)
def test_a_whois_without_a_record_says_so(mocker, single_session_fixture, answer):
    client = single_session_fixture
    mocker.patch.object(
        client.poller, "graph_domain_search", side_effect=answer if isinstance(answer, Exception) else None, return_value=answer
    )
    [result] = _whois(client, "domain", {"domain": "unregistered.example"})
    assert result.readable_output == "Group-IB has no WHOIS record for `unregistered.example`."
    assert result.outputs is None


def _domain_indicator_context(**dates) -> dict:
    score = Common.DBotScore(
        indicator="sample.test", indicator_type=GroupIBTIA.DBotScoreType.DOMAIN, integration_name="Group-IB", score=0
    )
    return GroupIBTIA.DomainIndicator(domain="sample.test", dbot_score=score, **dates).to_context()[Common.Domain.CONTEXT_PATH]


def test_only_the_domain_creation_and_updated_dates_take_the_day_first_safe_form():
    context = _domain_indicator_context(
        creation_date="2001-02-03T04:05:06Z", updated_date="2026-08-12T01:53:35Z", expiration_date="2027-03-08T05:00:00Z"
    )
    assert context["CreationDate"] == "03 Feb 2001 04:05:06 UTC"
    assert context["UpdatedDate"] == "12 Aug 2026 01:53:35 UTC"
    assert context["ExpirationDate"] == "2027-03-08T05:00:00Z"
    assert context["WHOIS"]["CreationDate"] == "2001-02-03T04:05:06Z"
    assert context["WHOIS"]["UpdatedDate"] == "2026-08-12T01:53:35Z"
    assert "CreationDate" not in _domain_indicator_context(expiration_date="2027-03-08T05:00:00Z")


def test_the_day_first_safe_date_reads_the_same_under_every_dateutil_setting():
    dateutil_parser = pytest.importorskip("dateutil.parser")
    for iso, safe in (("2001-02-03T04:05:06Z", "03 Feb 2001 04:05:06 UTC"), ("2026-12-01T00:00:00Z", "01 Dec 2026 00:00:00 UTC")):
        assert GroupIBTIA.day_first_safe_date(iso) == safe
        expected = datetime.strptime(iso, GroupIBTIA.DATE_FORMAT)
        for dayfirst in (False, True):
            for yearfirst in (False, True):
                parsed = dateutil_parser.parse(safe, dayfirst=dayfirst, yearfirst=yearfirst, fuzzy=True)
                assert parsed.replace(tzinfo=None) == expected
    # a day-first parse of the ISO form swaps its day and month
    assert dateutil_parser.parse("2001-02-03T04:05:06Z", dayfirst=True).month == 3


def test_a_failed_whois_request_is_the_error_of_its_value_and_a_refused_key_fails_the_command(mocker, single_session_fixture):
    client = single_session_fixture

    def graph(value: str) -> dict:
        if value == "198.51.100.1":
            raise GroupIBTIA.ConnectionException(SERVER_ERROR)
        return _ip_graph(("2026-11-01", SAMPLE_IP_SNAPSHOT))

    mocker.patch.object(client.poller, "graph_ip_search", side_effect=graph)
    failed, found = _whois(client, "ip", {"ip": "198.51.100.1,198.51.100.2"})
    assert failed.entry_type == EntryType.ERROR
    assert "WHOIS request for '198.51.100.1' failed" in failed.readable_output
    assert found.outputs["ip"] == "198.51.100.2"
    mocker.patch.object(
        client.poller, "graph_ip_search", side_effect=GroupIBTIA.ConnectionException("HTTP 401: Bad Credentials.")
    )
    with pytest.raises(GroupIBTIA.CredentialsRefused):
        _whois(client, "ip", {"ip": "198.51.100.1"})


def test_the_domain_whois_command_answers_a_subdomain_with_its_registered_domain(mocker, single_session_fixture):
    client = single_session_fixture
    subdomain = {"name": "www.sample-shop.example", "zone": "example", "is_sld": False, "whois": []}
    mocker.patch.object(
        client.poller,
        "graph_domain_search",
        side_effect=lambda value: subdomain if value == "www.sample-shop.example" else _domain_graph(),
    )
    [result] = _whois(client, "domain", {"domain": "WWW.Sample-Shop.Example."})
    assert [call.args[0] for call in client.poller.graph_domain_search.call_args_list] == [
        "www.sample-shop.example",
        "sample-shop.example",
    ]
    assert "this is the WHOIS record of `sample-shop.example`" in result.readable_output
    assert result.outputs["registrar"] == "Sample Registrar LLC"


def test_the_domain_whois_command_asks_about_an_internationalized_domain_in_ascii(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client.poller, "graph_domain_search", return_value=_domain_graph())
    unicode_name = "xn--caf-dma.example".encode("ascii").decode("idna")
    _whois(client, "domain", {"domain": unicode_name})
    client.poller.graph_domain_search.assert_called_once_with("xn--caf-dma.example")


def test_domain_reputation_reads_the_whois_of_a_subdomain_and_an_internationalized_domain(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"www.sample-shop.example": 20, "xn--caf-dma.example": 20})
    subdomain = {"name": "www.sample-shop.example", "zone": "example", "is_sld": False, "whois": []}
    mocker.patch.object(
        client.poller,
        "graph_domain_search",
        side_effect=lambda value: subdomain if value == "www.sample-shop.example" else _domain_graph(),
    )
    unicode_name = "xn--caf-dma.example".encode("ascii").decode("idna")
    sub_result, idn_result = reputation(client, "domain", {"domain": f"www.sample-shop.example,{unicode_name}"})
    assert sub_result.indicator.registrar_name == "Sample Registrar LLC"
    assert idn_result.indicator.registrar_name == "Sample Registrar LLC"
    asked = [call.args[0] for call in client.poller.graph_domain_search.call_args_list]
    assert asked == ["www.sample-shop.example", "sample-shop.example", "xn--caf-dma.example"]


def test_a_whois_failure_names_the_kind_of_failure_without_the_url(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(
        client.poller,
        "graph_ip_search",
        side_effect=GroupIBTIA.ConnectionException(
            "Request to https://sample.example/api/v2/utils/graph/ip?ip=198.51.100.1 timed out after 120s: Read timed out."
        ),
    )
    [failed] = _whois(client, "ip", {"ip": "198.51.100.1"})
    assert "WHOIS request for '198.51.100.1' failed: timeout." in failed.readable_output
    assert "sample.example" not in failed.readable_output
    mocker.patch.object(
        client.poller, "graph_ip_search", side_effect=GroupIBTIA.ConnectionException("HTTP 401: Bad Credentials.")
    )
    with pytest.raises(GroupIBTIA.CredentialsRefused, match="HTTP 401. Check the instance credentials."):
        _whois(client, "ip", {"ip": "198.51.100.1"})


@pytest.mark.parametrize("limit", ["0", "-1"])
def test_the_domain_whois_command_refuses_a_history_limit_below_one(single_session_fixture, limit):
    with pytest.raises(DemistoException, match="history_limit must be 1 or more"):
        _whois(single_session_fixture, "domain", {"domain": "sample-shop.example", "history": "true", "history_limit": limit})


def test_a_whois_body_skips_the_parts_of_another_shape_and_reads_the_rest():
    ip_body = {"start": "198.51.100.0", "whoisHistory": [{"first_seen": "2026-11-01", "data": 5}]}
    assert IPWhois.parse("198.51.100.27", ip_body).to_context()["rangeStart"] == "198.51.100.0"
    domain_body = {"whois": [{"level": "registry", "response": "Registrar: Sample Registrar LLC"}]}
    assert DomainWhois.parse("sample-shop.example", domain_body).to_context()["registrar"] == "Sample Registrar LLC"


@pytest.mark.parametrize("personal", [True, False])
def test_domain_reputation_writes_whois_where_the_domain_indicator_type_maps_it(mocker, single_session_fixture, personal):
    client = _reputation_client(mocker, single_session_fixture, {}, {"sample-shop.example": 20})
    graph = _domain_graph()
    graph["whois"][1]["response"] = SAMPLE_REGISTRAR_TEXT.replace("REDACTED FOR PRIVACY", "Sample Shop Inc.")
    mocker.patch.object(client.poller, "graph_domain_search", return_value=graph)
    [result] = reputation(client, "domain", {"domain": "sample-shop.example"}, whois_personal_data=personal)
    context = result.indicator.to_context()[Common.Domain.CONTEXT_PATH]
    assert context["Whois"] == {"Registrar": {"Name": "Sample Registrar LLC", "AbuseEmail": "abuse@registrar.example"}}
    assert context["Admin"] == {"Organization": "Sample Shop Inc."}
    lower_case = {key: item for key, item in context["Registrant"].items() if key.islower()}
    # the lower-case keys stay out of WHOIS.Registrant, and no registrant key is written empty
    assert not any(key.islower() for key in context["WHOIS"]["Registrant"])
    assert all(context["Registrant"].values())
    assert "Phone" not in context["Registrant"]
    expected = {"country": "US"}
    if personal:
        expected |= {"name": "Sample Owner", "email": "owner@example.com"}
    assert lower_case == expected


def test_the_domain_whois_command_drops_personal_data_when_set(mocker, single_session_fixture):
    client = single_session_fixture
    mocker.patch.object(client.poller, "graph_domain_search", return_value=_domain_graph())
    [shown] = _whois(client, "domain", {"domain": "sample-shop.example"})
    [dropped] = _whois(client, "domain", {"domain": "sample-shop.example"}, whois_personal_data=False)
    assert shown.outputs["registrantEmail"] == "owner@example.com"
    assert "registrantEmail" not in dropped.outputs
    assert "registrantName" not in dropped.outputs


def test_the_whois_settings_default_to_whois_in_reputation_and_personal_data_shown():
    settings = Settings.from_params({})
    assert (settings.reputation_whois, settings.whois_personal_data) == (True, True)
    assert Settings.from_params({"whois_personal_data": "Drop", "reputation_whois": False}).whois_personal_data is False


def test_ip_reputation_writes_the_whois_record_to_the_indicator_without_a_geo_country(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"198.51.100.27": 20})
    mocker.patch.object(client.poller, "graph_ip_search", return_value=_ip_graph(("2026-11-01", SAMPLE_IP_SNAPSHOT)))
    [result] = reputation(client, "ip", {"ip": "198.51.100.27"})
    context = result.indicator.to_context()["IP(val.Address && val.Address == obj.Address)"]
    assert context["ASN"] == "AS64496"
    assert context["Organization"] == {"Name": "Sample Hosting B.V."}
    assert context["Registrar"] == {"Abuse": {"Email": "abuse@example.net", "Phone": "+1-555-0199"}}
    assert "ASOwner" not in context
    assert "Geo" not in context
    assert "Description" not in context


def test_ip_reputation_asks_no_whois_when_the_setting_is_off(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"198.51.100.27": 20})
    reputation(client, "ip", {"ip": "198.51.100.27"}, reputation_whois=False)
    client.poller.graph_ip_search.assert_not_called()


def test_domain_reputation_writes_the_whois_record_to_the_indicator(mocker, single_session_fixture):
    client = _reputation_client(mocker, single_session_fixture, {}, {"sample-shop.example": 20})
    mocker.patch.object(client.poller, "graph_domain_search", return_value=_domain_graph())
    [result] = reputation(client, "domain", {"domain": "sample-shop.example"})
    context = result.indicator.to_context()["Domain(val.Name && val.Name == obj.Name)"]
    assert context["Registrar"] == {
        "Name": "Sample Registrar LLC",
        "AbuseEmail": "abuse@registrar.example",
        "AbusePhone": "+1.5550100",
    }
    assert context["NameServers"] == ["ns1.example.net", "ns2.example.net"]
    assert result.outputs["partial"] is False
