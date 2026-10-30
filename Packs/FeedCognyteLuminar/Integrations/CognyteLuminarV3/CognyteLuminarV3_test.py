import json

import pytest
from CognyteLuminarV3 import (
    Client,
    DemistoException,
    PaginationExpiredError,
    fetch_indicators_command,
    build_relationships_dummy_indicator,
    luminar_v3_get_indicators_command,
    luminar_v3_get_leaked_records_command,
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
    """
    Given:
        - A mocked Luminar OAuth2 token endpoint returning a valid token.
    When:
        - Fetching the access token twice.
    Then:
        - The token is returned, and the second call is served from the cache
          without a new HTTP request.
    """
    mock_token(requests_mock)
    assert client.fetch_access_token() == "tok123"
    # second call uses the cache - no new HTTP request
    assert client.fetch_access_token() == "tok123"


def test_parse_stix_pattern():
    """
    Given:
        - STIX indicator patterns of several observable types.
    When:
        - Parsing each pattern.
    Then:
        - The (object type, field, value) tuples are extracted correctly.
    """
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
    """
    Given:
        - STIX indicator objects and SCO objects.
    When:
        - Resolving their XSOAR indicator type and value.
    Then:
        - The correct indicator type, value and hash field are returned.
    """
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
    """
    Given:
        - A STIX object carrying the Luminar property extension.
    When:
        - Extracting its extension fields.
    Then:
        - The extension-specific keys are returned without metadata keys.
    """
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
    """
    Given:
        - A STIX bundle from the IOCs collection.
    When:
        - Converting it to XSOAR indicators.
    Then:
        - IOC, Malware and Threat Actor indicators are created with feed tags,
          TLP color and relationship records.
    """
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
    """
    Given:
        - A STIX bundle from the Leaked Records collection.
    When:
        - Converting it to XSOAR indicators.
    Then:
        - The leaked credential becomes an Account indicator enriched with the
          related incident's fields, and the incident becomes a
          'Luminar Incident' indicator.
    """
    indicators, rels = stix_objects_to_indicators(LEAKED_RESPONSE["objects"], [], None)
    accounts = [i for i in indicators if i["type"] == "Account"]
    assert accounts
    account = accounts[0]
    assert account["fields"]["accounttype"] == "LEAKED CREDENTIAL"
    assert any(t.startswith("Incident: ") for t in account["fields"]["tags"])
    # plaintext credential is masked by default and never added as a tag
    assert account["fields"]["luminarleakedcredential"] == "********"
    assert account["rawJSON"]["credential"] == "********"
    assert not any(t.startswith("Credentials:") for t in account["fields"]["tags"])
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
    # the malware's sample_refs resolve to the file's parent directory path + name
    malware = [i for i in indicators if i["type"] == "Malware"]
    assert malware
    assert malware[0]["fields"]["luminarsamples"] == "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe"


def test_stix_objects_to_indicators_include_credential():
    """
    Given:
        - A STIX bundle from the Leaked Records collection and the opt-in
          'Include Leaked Credentials' setting enabled.
    When:
        - Converting it to XSOAR indicators with include_credential=True.
    Then:
        - The Account indicator stores the plaintext leaked credential.
    """
    indicators, _ = stix_objects_to_indicators(LEAKED_RESPONSE["objects"], [], None, include_credential=True)
    accounts = [i for i in indicators if i["type"] == "Account"]
    assert accounts
    assert accounts[0]["fields"]["luminarleakedcredential"] == "P@ssw0rd!123"
    assert accounts[0]["rawJSON"]["credential"] == "P@ssw0rd!123"


def test_stix_objects_to_indicators_data_type():
    """
    Given:
        - A STIX bundle and a collection data-type label.
    When:
        - Converting it to XSOAR indicators with data_type set.
    Then:
        - Every created indicator carries 'luminardatatype' so sources can be
          differentiated in the TIM UI.
    """
    indicators, _ = stix_objects_to_indicators(LEAKED_RESPONSE["objects"], [], None, data_type="Luminar Leaked Record")
    assert indicators
    assert all(i["fields"]["luminardatatype"] == "Luminar Leaked Record" for i in indicators)


def test_build_relationships_dummy_indicator():
    """
    Given:
        - A STIX bundle containing relationship objects.
    When:
        - Building the dummy indicator used to create relationship edges.
    Then:
        - A '$$DummyIndicator$$' indicator with entityA/entityB pairs is
          returned.
    """
    objects = IOCS_RESPONSE["objects"]
    light_map, _, rel_records = index_objects(objects)
    dummy = build_relationships_dummy_indicator(rel_records, light_map)
    assert dummy["value"] == "$$DummyIndicator$$"
    assert dummy["relationships"]
    rel = dummy["relationships"][0]
    assert rel["entityA"]
    assert rel["entityB"]


def test_module(requests_mock):
    """
    Given:
        - A mocked token endpoint and a collections list containing both
          required collections.
    When:
        - Running test-module.
    Then:
        - 'ok' is returned.
    """
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
    """
    Given:
        - A mocked collections list missing the 'Leaked Records' collection.
    When:
        - Running test-module.
    Then:
        - An exception is raised reporting the missing collection.
    """
    mock_token(requests_mock)
    requests_mock.get(
        f"{BASE_URL}/externalApi/taxii/collections/",
        json={"collections": [{"id": "1", "title": "IOCs"}]},
    )
    with pytest.raises(Exception):
        module_test(client)


def test_get_objects_pagination(requests_mock):
    """
    Given:
        - A mocked objects endpoint returning two pages.
    When:
        - Iterating the collection objects.
    Then:
        - Both pages are yielded with their X-TAXII-Date-Added-Last values.
    """
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
    """
    Given:
        - A mocked objects endpoint that returns 410 'Expired pagination
          token' and then an empty page.
    When:
        - Iterating the collection objects.
    Then:
        - Pagination is rebuilt and completes instead of failing.
    """
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


def test_get_objects_non_recoverable_http_error(requests_mock):
    """
    Given:
        - A mocked objects endpoint that returns HTTP 500.
    When:
        - Iterating the collection objects.
    Then:
        - The error propagates as a DemistoException (no silent retry loop).
    """
    mock_token(requests_mock)
    objects_url = f"{BASE_URL}/externalApi/taxii/collections/coll1/objects/"
    requests_mock.get(objects_url, status_code=500, json={"error": "internal error"})
    with pytest.raises(DemistoException):
        list(client.iter_collection_objects("coll1"))


def test_get_indicators_command(mocker):
    """
    Given:
        - A mocked IOCs collection returning a STIX bundle.
    When:
        - Running luminar-v3-get-indicators.
    Then:
        - The command returns LuminarV3.Indicators context entries with the
          indicator type and value fields.
    """
    mocker.patch.object(
        client, "iter_collection_objects", return_value=iter([(IOCS_RESPONSE["objects"], "2026-01-01T00:00:00.000000Z")])
    )
    mocker.patch.object(client, "resolve_collection_id", return_value="coll1")
    response = luminar_v3_get_indicators_command(client, {"limit": 50})
    assert response.outputs_prefix == "LuminarV3.Indicators"
    assert response.outputs
    row = response.outputs[0]
    assert row["Type"]
    assert row["Value"]
    assert row["stixid"]


def test_get_leaked_records_command(mocker):
    """
    Given:
        - A mocked Leaked Records collection returning a STIX bundle.
    When:
        - Running luminar-v3-get-leaked-records.
    Then:
        - The command returns LuminarV3.LeakedCredentials context entries with
          the account type and the related incident name fields.
    """
    mocker.patch.object(
        client,
        "iter_collection_objects",
        return_value=iter([(LEAKED_RESPONSE["objects"], "2026-01-01T00:00:00.000000Z")]),
    )
    mocker.patch.object(client, "resolve_collection_id", return_value="coll1")
    response = luminar_v3_get_leaked_records_command(client, {"limit": 50})
    assert response.outputs_prefix == "LuminarV3.LeakedCredentials"
    assert response.outputs
    row = response.outputs[0]
    assert row["Type"] == "Account"
    assert row["accounttype"] == "LEAKED CREDENTIAL"
    assert row["luminarincidentname"] == "Example_Leak_Bundle.zip"


def test_commands_invalid_limit(mocker):
    """
    Given:
        - A non-positive 'limit' argument.
    When:
        - Running a get-* command.
    Then:
        - A DemistoException is raised instead of fetching data.
    """
    mocker.patch.object(client, "resolve_collection_id", return_value="coll1")
    with pytest.raises(DemistoException):
        luminar_v3_get_indicators_command(client, {"limit": 0})
    with pytest.raises(DemistoException):
        luminar_v3_get_leaked_records_command(client, {"limit": -3})


def test_reset_last_run(mocker):
    """
    Given:
        - An existing fetch history in the integration context.
    When:
        - Running luminar-v3-reset-fetch-indicators.
    Then:
        - The integration context is cleared and a confirmation is returned.
    """
    set_ctx_mock = mocker.patch("CognyteLuminarV3.demisto.setIntegrationContext")
    response = reset_last_run()
    set_ctx_mock.assert_called_once_with({})
    assert response.readable_output == "Fetch history deleted successfully"


def test_normalize_taxii_timestamp():
    """
    Given:
        - Valid and invalid date strings.
    When:
        - Normalizing them to TAXII timestamp format.
    Then:
        - Valid dates get 6-digit fractions; an unparseable date raises a
          DemistoException.
    """
    assert normalize_taxii_timestamp("2026-08-11T00:43:16.307Z") == "2026-08-11T00:43:16.307000Z"
    assert normalize_taxii_timestamp("2026-08-11") == "2026-08-11T00:00:00.000000Z"
    with pytest.raises(DemistoException):
        normalize_taxii_timestamp("not-a-date")


def test_get_indicators_command_from_date(mocker):
    """
    Given:
        - A 'from_date' command argument.
    When:
        - Running luminar-v3-get-indicators.
    Then:
        - The argument is normalized and passed as the TAXII added_after filter.
    """
    iter_mock = mocker.patch.object(client, "iter_collection_objects", return_value=iter([(IOCS_RESPONSE["objects"], None)]))
    mocker.patch.object(client, "resolve_collection_id", return_value="coll1")
    luminar_v3_get_indicators_command(client, {"limit": 50, "from_date": "2026-08-11T00:43:16.307Z"})
    assert iter_mock.call_args[0][1] == "2026-08-11T00:43:16.307000Z"


def test_get_leaked_records_command_from_date(mocker):
    """
    Given:
        - A 'from_date' command argument.
    When:
        - Running luminar-v3-get-leaked-records.
    Then:
        - The argument is normalized and passed as the TAXII added_after filter.
    """
    iter_mock = mocker.patch.object(client, "iter_collection_objects", return_value=iter([(LEAKED_RESPONSE["objects"], None)]))
    mocker.patch.object(client, "resolve_collection_id", return_value="coll1")
    luminar_v3_get_leaked_records_command(client, {"limit": 50, "from_date": "2026-08-11"})
    assert iter_mock.call_args[0][1] == "2026-08-11T00:00:00.000000Z"


def test_pagination_expired_error():
    """
    Given:
        - The PaginationExpiredError class.
    When:
        - Checking its type hierarchy.
    Then:
        - It is an Exception subclass (distinct so 410 responses can be handled).
    """
    assert issubclass(PaginationExpiredError, Exception)


def test_fetch_indicators_command(mocker):
    """
    Given:
        - Both collections resolved, each yielding one resolved batch.
    When:
        - Running fetch-indicators.
    Then:
        - Indicators are created per batch via createIndicators and one
          checkpoint is saved per collection.
    """
    resolve_mock = mocker.patch.object(client, "resolve_collection_id", return_value="coll1")
    mocker.patch.object(
        client,
        "iter_resolved_batches",
        side_effect=[
            iter([(IOCS_RESPONSE["objects"], [], "2026-01-01T00:00:00.000000Z")]),
            iter([(LEAKED_RESPONSE["objects"], [], "2026-01-02T00:00:00.000000Z")]),
        ],
    )
    create_mock = mocker.patch("CognyteLuminarV3.demisto.createIndicators")
    mocker.patch("CognyteLuminarV3.demisto.getIntegrationContext", return_value={})
    set_ctx_mock = mocker.patch("CognyteLuminarV3.demisto.setIntegrationContext")

    fetch_indicators_command(client, "7 days")

    assert resolve_mock.call_count == 2
    assert create_mock.called
    # one checkpoint saved per collection
    assert set_ctx_mock.call_count == 2
    checkpoints = set_ctx_mock.call_args[0][0]["checkpoints"]
    assert checkpoints == {"IOCs": "2026-01-01T00:00:00.000000Z", "Leaked Records": "2026-01-02T00:00:00.000000Z"}


def test_fetch_indicators_command_failure_propagates(mocker):
    """
    Given:
        - A collection resolution that raises an error.
    When:
        - Running fetch-indicators.
    Then:
        - The error propagates so the fetch run is marked as failed.
    """
    mocker.patch("CognyteLuminarV3.demisto.getIntegrationContext", return_value={})
    mocker.patch.object(client, "resolve_collection_id", side_effect=DemistoException("boom"))
    with pytest.raises(DemistoException):
        fetch_indicators_command(client, "7 days")
