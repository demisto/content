import json

import pytest
from CognyteLuminarV3 import (
    Client,
    PaginationExpiredError,
    build_relationships_dummy_indicator,
    cognyte_luminar_get_indicators,
    cognyte_luminar_get_leaked_records,
    get_extension_fields,
    get_indicator_type_and_value,
    index_objects,
    module_test,
    normalize_taxii_timestamp,
    parse_stix_pattern,
    reset_last_run,
    stix_objects_to_indicators,
)

BASE_URL = "https://luminar.example.com"
ACCOUNT_ID = "test-realm"
EXT_ID = "extension-definition--ddd2bf71-3c91-5f4d-8251-10cd685737c3"


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


IOCS_RESPONSE = load_json("test_data/iocs_response.json")
LEAKED_RESPONSE = load_json("test_data/leaked_records_response.json")

client = Client(
    base_url=BASE_URL,
    account_id=ACCOUNT_ID,
    client_id="client-id",
    client_secret="client-secret",
    verify=False,
    proxy=False,
    tags=["tag1"],
    tlp_color="RED",
)


def mock_token(requests_mock):
    requests_mock.post(
        f"{BASE_URL}/externalApi/v2/realm/{ACCOUNT_ID}/token",
        json={"access_token": "tok123", "expires_in": 3600, "token_type": "Bearer"},
    )


def test_fetch_access_token(requests_mock):
    mock_token(requests_mock)
    assert client.fetch_access_token() == "tok123"
    # second call uses the cache - no new HTTP request
    assert client.fetch_access_token() == "tok123"


def test_parse_stix_pattern():
    assert parse_stix_pattern("[ipv4-addr:value = '8.8.8.8']") == [("ipv4-addr", "value", "8.8.8.8")]
    assert parse_stix_pattern("[url:value = 'https://[2a02:4780::1]/x']") == [("url", "value", "https://[2a02:4780::1]/x")]
    assert parse_stix_pattern("[file:hashes.MD5 = 'aaaa']") == [("file", "hashes.MD5", "aaaa")]
    assert parse_stix_pattern("[file:hashes.'SHA-256' = 'bbbb']") == [("file", "hashes.'SHA-256", "bbbb")]
    assert parse_stix_pattern("[ipv4-addr:value = '1.1.1.1' OR ipv4-addr:value = '2.2.2.2']")[0] == (
        "ipv4-addr",
        "value",
        "1.1.1.1",
    )
    assert parse_stix_pattern("") == []


def test_get_indicator_type_and_value():
    assert get_indicator_type_and_value({"type": "indicator", "pattern": "[ipv4-addr:value = '8.8.8.8']"}) == (
        "IP",
        "8.8.8.8",
        None,
    )
    assert get_indicator_type_and_value({"type": "indicator", "pattern": "[ipv4-addr:value = '8.8.0.0/16']"}) == (
        "CIDR",
        "8.8.0.0/16",
        None,
    )
    assert get_indicator_type_and_value({"type": "indicator", "pattern": "[file:hashes.MD5 = 'aaaa']"}) == ("File", "aaaa", "md5")
    assert get_indicator_type_and_value({"type": "ipv4-addr", "value": "1.2.3.4"}) == ("IP", "1.2.3.4", None)
    assert get_indicator_type_and_value({"type": "ipv6-addr", "value": "::1"}) == ("IPv6", "::1", None)


def test_get_extension_fields():
    obj = {
        "extensions": {
            EXT_ID: {
                "extension_type": "property-extension",
                "luminar_tenant_id": "tid",
                "score": 52,
                "asn": 16276,
            }
        }
    }
    ext = get_extension_fields(obj)
    assert ext == {"score": 52, "asn": 16276}


def test_stix_objects_to_indicators_iocs():
    indicators, rels = stix_objects_to_indicators(IOCS_RESPONSE["objects"], ["tag1"], "RED")
    types = {i["type"] for i in indicators}
    assert "IP" in types or "URL" in types
    assert "Malware" in types
    assert "Threat Actor" in types
    assert rels
    ip_indicator = next(i for i in indicators if i["type"] in ("IP", "URL"))
    assert ip_indicator["fields"]["stixid"].startswith("indicator--")
    assert ip_indicator["fields"]["trafficlightprotocol"] == "RED"
    assert "tag1" in ip_indicator["fields"]["tags"]


def test_stix_objects_to_indicators_leaked_records():
    indicators, rels = stix_objects_to_indicators(LEAKED_RESPONSE["objects"], [], None)
    accounts = [i for i in indicators if i["type"] == "Account"]
    assert accounts
    account = accounts[0]
    assert account["fields"]["accounttype"] == "LEAKED CREDENTIAL"
    assert any(t.startswith("Incident: ") for t in account["fields"]["tags"])
    assert account["fields"].get("luminarleakedcredential") is not None
    # related incident data is saved on the account's fields (old integration approach)
    assert account["fields"].get("luminarincidentname")
    assert account["fields"].get("luminarincidentdescription")
    # incidents become 'Luminar Incident' indicators so accounts/malware/IP
    # can be linked to the leak bundle
    incident_indicators = [i for i in indicators if i["rawJSON"].get("type") == "incident"]
    assert incident_indicators
    assert all(i["type"] == "Luminar Incident" for i in incident_indicators)
    # the standalone ipv4-addr SCO becomes an IP indicator
    assert any(i["type"] == "IP" for i in indicators)


def test_build_relationships_dummy_indicator():
    objects = IOCS_RESPONSE["objects"]
    light_map, _, rel_records = index_objects(objects)
    dummy = build_relationships_dummy_indicator(rel_records, light_map)
    assert dummy["value"] == "$$DummyIndicator$$"
    assert dummy["relationships"]
    rel = dummy["relationships"][0]
    assert rel["entityA"]
    assert rel["entityB"]


def test_module(requests_mock):
    mock_token(requests_mock)
    requests_mock.get(
        f"{BASE_URL}/externalApi/taxii/collections/",
        json={
            "collections": [
                {"id": "1", "title": "IOCs", "alias": "iocs"},
                {"id": "2", "title": "Leaked Records", "alias": "leakedrecords"},
            ]
        },
    )
    assert module_test(client) == "ok"


def test_module_missing_collection(requests_mock):
    mock_token(requests_mock)
    requests_mock.get(
        f"{BASE_URL}/externalApi/taxii/collections/",
        json={"collections": [{"id": "1", "title": "IOCs"}]},
    )
    with pytest.raises(Exception):
        module_test(client)


def test_get_objects_pagination(requests_mock):
    mock_token(requests_mock)
    requests_mock.get(
        f"{BASE_URL}/externalApi/taxii/collections/",
        json={"collections": [{"id": "coll1", "title": "IOCs"}]},
    )
    objects_url = f"{BASE_URL}/externalApi/taxii/collections/coll1/objects/"
    requests_mock.get(
        objects_url,
        [
            {
                "json": {"objects": [{"id": "a", "type": "identity"}], "more": True, "next": "tok"},
                "headers": {"X-TAXII-Date-Added-Last": "2026-01-01T00:00:00.000000Z"},
            },
            {
                "json": {"objects": [{"id": "b", "type": "identity"}], "more": False},
                "headers": {"X-TAXII-Date-Added-Last": "2026-01-02T00:00:00.000000Z"},
            },
        ],
    )
    pages = list(client.iter_collection_objects("coll1", added_after="2025-01-01T00:00:00.000000Z"))
    assert len(pages) == 2
    assert pages[1][1] == "2026-01-02T00:00:00.000000Z"


def test_get_objects_410_restart(requests_mock):
    mock_token(requests_mock)
    objects_url = f"{BASE_URL}/externalApi/taxii/collections/coll1/objects/"
    requests_mock.get(
        objects_url,
        [
            {"status_code": 410, "json": {"error": "Expired pagination token"}},
            {"json": {"objects": [], "more": False}, "headers": {}},
        ],
    )
    pages = list(client.iter_collection_objects("coll1"))
    assert pages[0][0] == []


def test_get_indicators_command(mocker):
    mocker.patch.object(
        client, "iter_collection_objects", return_value=iter([(IOCS_RESPONSE["objects"], "2026-01-01T00:00:00.000000Z")])
    )
    mocker.patch.object(client, "resolve_collection_id", return_value="coll1")
    response = cognyte_luminar_get_indicators(client, {"limit": 50})
    assert response.outputs_prefix == "LuminarV3.Indicators"
    assert response.outputs


def test_get_leaked_records_command(mocker):
    mocker.patch.object(
        client,
        "iter_collection_objects",
        return_value=iter([(LEAKED_RESPONSE["objects"], "2026-01-01T00:00:00.000000Z")]),
    )
    mocker.patch.object(client, "resolve_collection_id", return_value="coll1")
    response = cognyte_luminar_get_leaked_records(client, {"limit": 50})
    assert response.outputs_prefix == "LuminarV3.LeakedCredentials"
    assert response.outputs


def test_reset_last_run(mocker):
    mocker.patch("CognyteLuminarV3.demisto.setIntegrationContext")
    response = reset_last_run()
    assert response.readable_output == "Fetch history deleted successfully"


def test_normalize_taxii_timestamp():
    assert normalize_taxii_timestamp("2026-08-11T00:43:16.307Z") == "2026-08-11T00:43:16.307000Z"
    assert normalize_taxii_timestamp("2026-08-11") == "2026-08-11T00:00:00.000000Z"


def test_get_indicators_command_from_date(mocker):
    iter_mock = mocker.patch.object(client, "iter_collection_objects", return_value=iter([(IOCS_RESPONSE["objects"], None)]))
    mocker.patch.object(client, "resolve_collection_id", return_value="coll1")
    cognyte_luminar_get_indicators(client, {"limit": 50, "from_date": "2026-08-11T00:43:16.307Z"})
    assert iter_mock.call_args[0][1] == "2026-08-11T00:43:16.307000Z"


def test_get_leaked_records_command_from_date(mocker):
    iter_mock = mocker.patch.object(client, "iter_collection_objects", return_value=iter([(LEAKED_RESPONSE["objects"], None)]))
    mocker.patch.object(client, "resolve_collection_id", return_value="coll1")
    cognyte_luminar_get_leaked_records(client, {"limit": 50, "from_date": "2026-08-11"})
    assert iter_mock.call_args[0][1] == "2026-08-11T00:00:00.000000Z"


def test_pagination_expired_error():
    assert issubclass(PaginationExpiredError, Exception)
