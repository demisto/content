import base64
import copy
import io
import json
import os
import zipfile
from datetime import datetime, UTC

import CertificateManagerSaaS
import demistomock as demisto
import pytest
from freezegun import freeze_time
from nacl.public import PrivateKey, SealedBox

from CertificateManagerSaaS import (
    DemistoException,
    build_keystore_request_body,
    certificate_keystore_download_command,
    keystore_base_name,
    keystore_passphrase,
    unpack_pem_keystore,
    GraphQLEnum,
    IncidentSeverity,
    Client,
    Common,
    GraphQLQueryError,
    build_revocation_failed_incident,
    resolve_reported_key_compromise_score,
    revocation_verdict,
    certificate_readable_row,
    application_list_command,
    build_certificate_request_body,
    build_search_predicate,
    build_search_query,
    certificate_command,
    certificate_download_command,
    certificate_get_command,
    certificate_list_expiring_command,
    certificate_request_command,
    certificate_request_status_command,
    certificate_revoke_command,
    certificate_search_command,
    certificate_to_context,
    cloud_installation_context,
    collect_certificates,
    collection_nodes,
    connection_address,
    safe_connection_details,
    days_until_expiry,
    expiry_thresholds,
    installation_locations,
    extract_list,
    extract_subject_alternative_names,
    fetch_incidents,
    first_common_name,
    machine_get_command,
    machine_list_command,
    normalize_fingerprint,
    normalize_host,
    normalize_sha1_fingerprint,
    partition_fingerprints,
    PACK_VERSION,
    public_key_context,
    test_module as run_test_module,
    threshold_alignment_message,
    threshold_severity,
    to_graphql_literal,
)

BASE_URL = "https://api.venafi.cloud"
GRAPHQL_URL = f"{BASE_URL}/graphql"
USER_ACCOUNTS_URL = f"{BASE_URL}/v1/useraccounts"
MACHINES_URL = f"{BASE_URL}/v1/machines"
APPLICATIONS_URL = f"{BASE_URL}/outagedetection/v1/applications"
CERTIFICATE_REQUESTS_URL = f"{BASE_URL}/outagedetection/v1/certificaterequests"

API_KEY = "dummy-api-key"
RELIABILITY = "C - Fairly reliable"
KNOWN_FINGERPRINT = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
FROZEN_NOW = "2026-09-23T00:00:00Z"
REQUEST_ID = "7d3f1a20-2222-11ef-9a11-0242ac120002"
CERTIFICATE_ID = "4a2b7c10-3333-11ef-9a11-0242ac120002"
CONTENTS_URL = f"{BASE_URL}/outagedetection/v1/certificates/{CERTIFICATE_ID}/contents"
MINIMAL_REQUEST_ARGS = {"application_id": "app-1", "certificate_issuing_template_id": "tmpl-1"}


def util_load_json(name: str) -> dict:
    path = os.path.join(os.path.dirname(__file__), "test_data", name)
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, api_key=API_KEY, verify=False, proxy=False)


""" PURE HELPERS """


@pytest.mark.parametrize(
    "case, raw, expected",
    [
        ("accepts bare hex", "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"),
        ("strips colons", "A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:12:34:56:78", KNOWN_FINGERPRINT),
        ("strips whitespace and dashes", " A1B2-C3D4 E5F60718293A4B5C6D7E8F9012345678 ", KNOWN_FINGERPRINT),
    ],
)
def test_normalize_fingerprint(case: str, raw: str, expected: str):
    # arrange / act
    result = normalize_fingerprint(raw)

    # assert
    assert result == expected, case


@pytest.mark.parametrize(
    "case, raw",
    [
        ("rejects non-hexadecimal characters", "not-a-fingerprint"),
        ("rejects an unknown digest length", "A1B2C3"),
        ("rejects an empty value", ""),
    ],
)
def test_normalize_fingerprint_rejects_malformed_input(case: str, raw: str):
    # arrange / act / assert
    with pytest.raises(ValueError):
        normalize_fingerprint(raw)


def test_partition_fingerprints_separates_malformed_from_valid():
    # arrange
    raw_values = [KNOWN_FINGERPRINT.lower(), "oops", KNOWN_FINGERPRINT]

    # act
    valid, rejected = partition_fingerprints(raw_values)

    # assert
    assert valid == [KNOWN_FINGERPRINT], "deduplicates after normalization"
    assert [entry["Fingerprint"] for entry in rejected] == ["oops"]


@pytest.mark.parametrize(
    "case, value, expected",
    [
        ("renders bare keys and quoted strings", {"eq": "AB"}, '{eq: "AB"}'),
        ("renders nested filters", {"and": {"fingerprint": {"in": ["A", "B"]}}}, '{and: {fingerprint: {in: ["A", "B"]}}}'),
        ("renders booleans unquoted", {"isCA": True}, "{isCA: true}"),
        ("renders null", {"x": None}, "{x: null}"),
        ("escapes quotes inside strings", {"eq": 'a"b'}, '{eq: "a\\"b"}'),
        ("renders enum values bare", {"eq": GraphQLEnum("FAILED")}, "{eq: FAILED}"),
    ],
)
def test_to_graphql_literal(case: str, value: object, expected: str):
    # arrange / act
    result = to_graphql_literal(value)

    # assert
    assert result == expected, case


@pytest.mark.parametrize(
    "case, container, expected",
    [
        ("returns nodes when present", {"totalCount": 1, "nodes": [{"id": "a"}]}, [{"id": "a"}]),
        ("returns empty list when totalCount is positive but nodes is null", {"totalCount": 9, "nodes": None}, []),
        ("returns empty list when the container itself is null", None, []),
    ],
)
def test_collection_nodes(case: str, container: dict | None, expected: list):
    # arrange / act
    result = collection_nodes(container)

    # assert
    assert result == expected, case


@pytest.mark.parametrize(
    "case, holder, expected",
    [
        ("returns the first entry of the array", {"commonName": ["a.example.com", "b.example.com"]}, "a.example.com"),
        ("tolerates a plain string", {"commonName": "a.example.com"}, "a.example.com"),
        ("returns None for an empty array", {"commonName": []}, None),
        ("returns None for a missing holder", None, None),
    ],
)
def test_first_common_name(case: str, holder: dict | None, expected: str | None):
    # arrange / act
    result = first_common_name(holder)

    # assert
    assert result == expected, case


@pytest.mark.parametrize(
    "case, raw_host, expected",
    [
        ("lowercases an FQDN", "F5-LTM-01.Example.COM", "f5-ltm-01.example.com"),
        ("strips scheme, user, port and path", "https://admin@F5-LTM-01.Example.COM:8443/mgmt/", "f5-ltm-01.example.com"),
        ("keeps a bare IPv4", "203.0.113.10", "203.0.113.10"),
        ("returns None for an empty value", "  ", None),
        ("returns None when the field is absent", None, None),
    ],
)
def test_normalize_host(case: str, raw_host: str | None, expected: str | None):
    # arrange / act
    result = normalize_host(raw_host)

    # assert
    assert result == expected, case


def test_safe_connection_details_drops_everything_not_allow_listed():
    # arrange
    raw = {
        "host": "f5.example.com",
        "password": "should-never-appear",
        "credentialId": "c0ffee00-0000-0000-0000-000000000000",
        "protocolSsh": {"hostnameOrAddress": "203.0.113.10", "port": 22, "sshPassword": {"credentialType": "local"}},
        "protocolSecrets": {"token": "should-never-appear"},
    }

    # act
    result = safe_connection_details(raw)

    # assert
    assert result == {"host": "f5.example.com", "protocolSsh": {"hostnameOrAddress": "203.0.113.10", "port": 22}}


@pytest.mark.parametrize(
    "case, connection_details, expected",
    [
        ("reads a top-level host", {"host": "f5.example.com", "port": 443}, ("f5.example.com", 443)),
        ("reads a top-level hostnameOrAddress", {"hostnameOrAddress": "10.0.0.5"}, ("10.0.0.5", None)),
        (
            "reads a host nested under a protocol block",
            {
                "protocol": "ssh2",
                "protocolSsh": {"hostnameOrAddress": "203.0.113.10", "port": 22, "sshPassword": {"credentialType": "local"}},
            },
            ("203.0.113.10", 22),
        ),
        ("returns no host for a cloud connector", {"keyVaultName": "prod-vault", "tenantId": "t"}, (None, None)),
    ],
)
def test_connection_address(case: str, connection_details: dict, expected: tuple):
    # arrange / act
    result = connection_address(connection_details)

    # assert
    assert result == expected, case


@freeze_time(FROZEN_NOW)
@pytest.mark.parametrize(
    "case, validity_to, expected",
    [
        ("counts whole days remaining", "2026-10-03T00:00:00Z", 10),
        ("goes negative once expired", "2026-09-13T00:00:00Z", -10),
        ("returns None for a missing timestamp", None, None),
    ],
)
def test_days_until_expiry(case: str, validity_to: str | None, expected: int | None):
    # arrange / act
    result = days_until_expiry(validity_to)

    # assert
    assert result == expected, case


@pytest.mark.parametrize(
    "case, info, expected_algorithm, expected_extra",
    [
        ("maps an RSA key", {"__typename": "RSAKeyInfo", "strength": 2048}, "RSA", {"Length": 2048}),
        ("maps an EC key", {"__typename": "ECKeyInfo", "curve": "P-384"}, "EC", {"Curve": "P-384"}),
        ("falls back to unknown", {"__typename": "GenericKeyInfo"}, "Unknown Algorithm", {}),
        ("tolerates a missing block", None, "Unknown Algorithm", {}),
    ],
)
def test_public_key_context(case: str, info: dict | None, expected_algorithm: str, expected_extra: dict):
    # arrange / act
    result = public_key_context(info)

    # assert
    assert result["Algorithm"] == expected_algorithm, case
    assert {key: result.get(key) for key in expected_extra} == expected_extra, case


def test_extract_subject_alternative_names_flattens_the_union():
    # arrange
    certificate = util_load_json("search_certificates_page.json")["data"]["searchCertificates"]["nodes"][0]

    # act
    result = extract_subject_alternative_names(certificate)

    # assert
    assert result == ["shop.example.com", "www.shop.example.com", "203.0.113.10"]


@pytest.mark.parametrize(
    "case, payload, expected_length",
    [
        ("unwraps the documented key", {"machines": [{"id": "a"}]}, 1),
        ("accepts a bare list", [{"id": "a"}, {"id": "b"}], 2),
        ("returns empty for an unexpected shape", {"unexpected": 1}, 0),
        ("returns empty for None", None, 0),
    ],
)
def test_extract_list(case: str, payload: object, expected_length: int):
    # arrange / act
    result = extract_list(payload, "machines")

    # assert
    assert len(result) == expected_length, case


@freeze_time(FROZEN_NOW)
def test_certificate_to_context_maps_the_documented_field_shapes():
    # arrange
    certificate = util_load_json("search_certificates_page.json")["data"]["searchCertificates"]["nodes"][0]

    # act
    context = certificate_to_context(certificate, "CertificateManagerSaaS")

    # assert
    assert context["SourceBrand"] == "CertificateManagerSaaS"
    assert context["CommonName"] == "shop.example.com", "commonName is an array upstream"
    assert context["ValidityPeriodSeconds"] == 23932800, "period is seconds, not days"
    assert context["DaysUntilExpiry"] == 12
    assert context["PublicKey"] == {"Algorithm": "RSA", "Length": 2048}
    assert context["Installations"] == [
        {
            "ID": "inst-0001",
            "Status": "INSTALLED",
            "MachineID": "mach-0001",
            "MachineName": "F5 v17",
            "PluginName": "F5 BIG-IP LTM (VSatellite)",
        }
    ]
    assert "IsPublic" not in context, "a null isPublic is omitted rather than rendered as false"
    assert context["InstallationLocations"] == ["F5 v17 (F5 BIG-IP LTM (VSatellite))"]
    assert "CloudInstallations" not in context, "a null cloudInstallations block is omitted"


@pytest.mark.parametrize(
    "case, metadata_type, expected_type",
    [
        ("maps aws metadata to acm", "AWSCertificateMetadata", "AWS Certificate Manager"),
        ("maps azure metadata to key vault", "AzureCertificateMetadata", "Azure Key Vault"),
        ("maps gcp metadata to google certificate manager", "GCPCertificateMetadata", "Google Certificate Manager"),
        ("maps akamai metadata to the cdn", "AkamaiCertificateMetadata", "Akamai CDN"),
        ("omits the type for an unknown metadata variant", "FutureCertificateMetadata", None),
    ],
)
def test_cloud_installation_context(case: str, metadata_type: str, expected_type: str | None):
    # arrange
    node = {
        "id": "mi-0001",
        "cloudKeystoreId": "ks-0001",
        "cloudKeystoreName": "prod-vault",
        "cloudProviderName": "Corp cloud",
        "status": "INSTALLED",
        "metadata": {"__typename": metadata_type},
    }

    # act
    context = cloud_installation_context(node)

    # assert
    assert context.get("KeystoreType") == expected_type, case
    assert context["KeystoreName"] == "prod-vault", case


@pytest.mark.parametrize(
    "case, installations, cloud_installations, expected",
    [
        (
            "combines machine label and plugin",
            [{"MachineName": "F5 prod", "PluginName": "F5 BIG-IP LTM"}],
            [],
            ["F5 prod (F5 BIG-IP LTM)"],
        ),
        (
            "names a machine-based cloud store by its plugin",
            [{"PluginName": "Azure Private Key Vault"}],
            [],
            ["Azure Private Key Vault"],
        ),
        (
            "names a cloud keystore by type and name",
            [],
            [{"KeystoreType": "AWS Certificate Manager", "KeystoreName": "prod-acm"}],
            ["AWS Certificate Manager: prod-acm"],
        ),
        ("falls back to the keystore name without a type", [], [{"KeystoreName": "prod-acm"}], ["prod-acm"]),
        ("drops duplicates and empty entries", [{"MachineName": "a"}, {"MachineName": "a"}, {}], [{}], ["a"]),
    ],
)
def test_installation_locations(case: str, installations: list, cloud_installations: list, expected: list):
    # arrange / act
    result = installation_locations(installations, cloud_installations)

    # assert
    assert result == expected, case


""" TEST MODULE """


def test_test_module_returns_ok_when_both_surfaces_answer(client: Client, requests_mock):
    # arrange
    requests_mock.get(USER_ACCOUNTS_URL, json=util_load_json("useraccounts.json"))
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    result = run_test_module(client)

    # assert
    assert result == "ok"


def test_test_module_explains_a_rejected_api_key(client: Client, requests_mock):
    # arrange
    requests_mock.get(USER_ACCOUNTS_URL, status_code=401, json={"message": "Invalid API key"})

    # act / assert
    with pytest.raises(Exception, match="Authentication failed"):
        run_test_module(client)


def test_test_module_distinguishes_a_forbidden_graphql_root_field(client: Client, requests_mock):
    # arrange
    requests_mock.get(USER_ACCOUNTS_URL, json=util_load_json("useraccounts.json"))
    requests_mock.post(GRAPHQL_URL, status_code=403, text="")

    # act / assert
    with pytest.raises(Exception, match="not allow-listed"):
        run_test_module(client)


def test_client_never_puts_the_api_key_in_the_request_body(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    client.search_certificates(first=1)

    # assert
    assert requests_mock.last_request.headers["tppl-api-key"] == API_KEY, "the key travels only in the custom header"
    assert API_KEY not in requests_mock.last_request.text


def test_client_identifies_itself_with_the_pack_version(client: Client, requests_mock):
    # arrange
    metadata_path = os.path.join(os.path.dirname(__file__), "..", "..", "pack_metadata.json")
    with open(metadata_path, encoding="utf-8") as handle:
        pack_version = json.load(handle)["currentVersion"]
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    client.search_certificates(first=1)

    # assert
    assert requests_mock.last_request.headers["User-Agent"] == f"CortexXSOAR-CertificateManagerSaaS/{pack_version}"
    assert pack_version == PACK_VERSION, "the User-Agent version must track pack_metadata.json"


""" REPUTATION """


@freeze_time(FROZEN_NOW)
def test_certificate_command_returns_an_indicator_for_a_known_fingerprint(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    results = certificate_command(client, {"certificate": KNOWN_FINGERPRINT}, RELIABILITY)

    # assert
    assert len(results) == 1
    indicator = results[0].indicator.to_context()
    dbot_score = indicator[Common.DBotScore.CONTEXT_PATH]
    assert dbot_score["Indicator"] == KNOWN_FINGERPRINT
    assert dbot_score["Type"] == "certificate"
    assert dbot_score["Reliability"] == RELIABILITY
    assert dbot_score["Score"] == 0, "presence in an inventory is not a reputation verdict"
    assert results[0].outputs["CommonName"] == "shop.example.com"
    assert "Verdict" in results[0].readable_output, "the analyst sees the verdict in the War Room"
    assert "Verdict" not in results[0].outputs, "the verdict lives in DBotScore, not in our context"


def test_certificate_command_emits_no_score_for_a_fingerprint_the_tenant_does_not_know(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_empty.json"))
    unknown = "F" * 64

    # act
    results = certificate_command(client, {"certificate": unknown}, RELIABILITY)

    # assert
    assert len(results) == 1
    assert results[0].indicator is None, "an unresolvable lookup must not be scored"
    assert results[0].outputs == [
        {"Fingerprint": unknown, "Reason": "No certificate with this fingerprint was returned by the tenant."}
    ]


def test_certificate_command_reports_malformed_input_separately_from_a_miss(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    results = certificate_command(client, {"certificate": f"{KNOWN_FINGERPRINT},zzz"}, RELIABILITY)

    # assert
    assert len(results) == 2
    unresolved = results[-1].outputs
    assert unresolved[0]["Fingerprint"] == "zzz"
    assert "hexadecimal" in unresolved[0]["Reason"]


def test_certificate_command_requires_at_least_one_value(client: Client):
    # arrange / act / assert
    with pytest.raises(ValueError, match="required"):
        certificate_command(client, {"certificate": ""}, RELIABILITY)


def test_certificate_command_batches_lookups_at_the_page_cap(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_empty.json"))
    fingerprints = [f"{index:040X}" for index in range(1, 151)]

    # act
    certificate_command(client, {"certificate": ",".join(fingerprints)}, RELIABILITY)

    # assert
    assert requests_mock.call_count == 2, "150 fingerprints cost two calls, not 150"


""" SEARCH """


@freeze_time(FROZEN_NOW)
def test_certificate_search_returns_every_certificate_when_no_criteria_are_given(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    result = certificate_search_command(client, {})

    # assert
    assert [certificate["Fingerprint"] for certificate in result.outputs] == [
        KNOWN_FINGERPRINT,
        "BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE",
    ]


def test_certificate_search_returns_empty_list_when_no_certificates_match(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    result = certificate_search_command(client, {"common_name": "nothing-matches-this"})

    # assert
    assert result.outputs is None
    assert "No entries" in result.readable_output


def test_certificate_search_filters_a_fingerprint_server_side(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    certificate_search_command(client, {"fingerprint": KNOWN_FINGERPRINT.lower()})

    # assert
    sent_query = requests_mock.last_request.json()["query"]
    assert f'filterOn: {{and: {{fingerprint: {{eq: "{KNOWN_FINGERPRINT}"}}}}}}' in sent_query


def test_certificate_search_matches_a_subject_alternative_name(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    result = certificate_search_command(client, {"common_name": "WWW.SHOP"})

    # assert
    assert [certificate["Fingerprint"] for certificate in result.outputs] == [KNOWN_FINGERPRINT]


def test_certificate_search_raises_when_the_gateway_answers_200_with_errors(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, status_code=200, json=util_load_json("search_certificates_errors.json"))

    # act / assert
    with pytest.raises(GraphQLQueryError, match="Subgraph errors redacted"):
        certificate_search_command(client, {})


def test_certificate_search_tolerates_a_positive_total_count_with_null_nodes(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_null_nodes.json"))

    # act
    result = certificate_search_command(client, {})

    # assert
    assert result.outputs is None


def test_collect_certificates_follows_the_cursor_until_the_last_page(client: Client, requests_mock):
    # arrange
    first_page = copy.deepcopy(util_load_json("search_certificates_page.json"))
    first_page["data"]["searchCertificates"]["pageInfo"] = {"hasNextPage": True, "endCursor": "cursor-1"}
    requests_mock.post(GRAPHQL_URL, [{"json": first_page}, {"json": util_load_json("search_certificates_page.json")}])

    # act
    certificates, more_available = collect_certificates(client, limit=10)

    # assert
    assert len(certificates) == 4
    assert more_available is False
    assert requests_mock.request_history[1].json()["variables"]["after"] == "cursor-1"


def test_collect_certificates_reports_truncation_at_the_limit(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    certificates, more_available = collect_certificates(client, limit=1)

    # assert
    assert len(certificates) == 1
    assert more_available is True


def test_build_search_predicate_returns_none_without_criteria():
    # arrange / act
    predicate = build_search_predicate()

    # assert
    assert predicate is None


@freeze_time(FROZEN_NOW)
@pytest.mark.parametrize(
    "case, fixture, run",
    [
        ("search", "search_certificates_page.json", lambda client: certificate_search_command(client, {}).outputs),
        (
            "get",
            "search_certificates_page.json",
            lambda client: [certificate_get_command(client, {"fingerprint": KNOWN_FINGERPRINT}).outputs],
        ),
        (
            "list expiring",
            "search_certificates_expiry_mix.json",
            lambda client: certificate_list_expiring_command(client, {}).outputs,
        ),
        (
            "revoke",
            "revoke_certificate.json",
            lambda client: [certificate_revoke_command(client, {"fingerprint": KNOWN_FINGERPRINT}).outputs],
        ),
        (
            "reputation",
            "search_certificates_page.json",
            lambda client: [certificate_command(client, {"certificate": KNOWN_FINGERPRINT}, RELIABILITY)[0].outputs],
        ),
        (
            "fetch raw json",
            "fetch_certificates_page.json",
            lambda client: [json.loads(incident["rawJSON"]) for incident in fetch_incidents(client, {}, {})[0]],
        ),
    ],
)
def test_certificate_outputs_carry_the_cm_saas_source_brand(case: str, fixture: str, run, client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json(fixture))

    # act
    outputs = run(client)

    # assert
    assert outputs, case
    assert [output["SourceBrand"] for output in outputs] == ["CertificateManagerSaaS"] * len(outputs), case
    assert all(output.get("Fingerprint") for output in outputs), case


""" GET """


@freeze_time(FROZEN_NOW)
def test_certificate_get_returns_the_single_matching_certificate(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    result = certificate_get_command(client, {"fingerprint": KNOWN_FINGERPRINT})

    # assert
    assert result.outputs["Fingerprint"] == KNOWN_FINGERPRINT
    assert result.outputs["Installations"][0]["MachineID"] == "mach-0001"


def test_certificate_get_explains_an_empty_result(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_empty.json"))

    # act
    result = certificate_get_command(client, {"fingerprint": "A" * 64})

    # assert
    assert "cannot distinguish" in result.readable_output
    assert result.outputs is None


@freeze_time(FROZEN_NOW)
def test_certificate_get_adds_the_device_host_when_machine_details_are_requested(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))
    requests_mock.get(f"{MACHINES_URL}/mach-0001", json=util_load_json("machine_detail_appliance.json"))

    # act
    result = certificate_get_command(client, {"fingerprint": KNOWN_FINGERPRINT, "include_machine_details": "true"})

    # assert
    assert result.outputs["Installations"][0]["Host"] == "f5-ltm-01.example.com"


@freeze_time(FROZEN_NOW)
def test_certificate_get_leaves_the_host_absent_for_a_cloud_machine(client: Client, requests_mock):
    # arrange
    page = copy.deepcopy(util_load_json("search_certificates_page.json"))
    page["data"]["searchCertificates"]["nodes"][0]["machineInstallations"]["nodes"][0]["machine"]["id"] = "mach-0002"
    requests_mock.post(GRAPHQL_URL, json=page)
    requests_mock.get(f"{MACHINES_URL}/mach-0002", json=util_load_json("machine_detail_cloud.json"))

    # act
    result = certificate_get_command(client, {"fingerprint": KNOWN_FINGERPRINT, "include_machine_details": "true"})

    # assert
    assert "Host" not in result.outputs["Installations"][0], "no host is a normal outcome for cloud connectors"


""" EXPIRING """


@freeze_time(FROZEN_NOW)
def test_certificate_list_expiring_filters_the_window_server_side_and_sorts_soonest_first(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_expiry_mix.json"))

    # act
    result = certificate_list_expiring_command(client, {"days": "30"})

    # assert
    sent_query = requests_mock.last_request.json()["query"]
    assert 'validityTo: {between: {gte: "2026-09-23T00:00:00Z", lte: "2026-10-23T00:00:00Z"}}' in sent_query
    assert "isCurrent: {eq: true}" in sent_query
    assert "status: {eq: ACTIVE}" in sent_query
    assert [certificate["ID"] for certificate in result.outputs] == ["cert-expired", "cert-soon", "cert-far"]


@freeze_time(FROZEN_NOW)
def test_certificate_list_expiring_moves_the_lower_bound_back_to_include_expired_certificates(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_expiry_mix.json"))

    # act
    certificate_list_expiring_command(client, {"days": "30", "include_expired": "true"})

    # assert
    sent_query = requests_mock.last_request.json()["query"]
    assert 'validityTo: {between: {gte: "2025-09-23T00:00:00Z", lte: "2026-10-23T00:00:00Z"}}' in sent_query


@freeze_time(FROZEN_NOW)
def test_certificate_list_expiring_notes_truncation(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_expiry_mix.json"))

    # act
    result = certificate_list_expiring_command(client, {"days": "3650", "limit": "1"})

    # assert
    assert "truncated" in result.readable_output


""" APPLICATIONS AND MACHINES """


def test_application_list_returns_the_applications(client: Client, requests_mock):
    # arrange
    requests_mock.get(APPLICATIONS_URL, json=util_load_json("applications_list.json"))

    # act
    result = application_list_command(client, {})

    # assert
    assert [application["Name"] for application in result.outputs] == ["Storefront", "Internal APIs"]


def test_application_list_surfaces_an_unavailable_endpoint(client: Client, requests_mock):
    # arrange
    requests_mock.get(APPLICATIONS_URL, status_code=404, text="")

    # act / assert
    with pytest.raises(Exception, match="not available on this tenant"):
        application_list_command(client, {})


def test_machine_list_honours_the_limit(client: Client, requests_mock):
    # arrange
    requests_mock.get(MACHINES_URL, json=util_load_json("machines_list.json"))

    # act
    result = machine_list_command(client, {"limit": "1"})

    # assert
    assert [machine["ID"] for machine in result.outputs] == ["mach-0001"]


def test_machine_get_normalizes_the_device_host(client: Client, requests_mock):
    # arrange
    requests_mock.get(f"{MACHINES_URL}/mach-0001", json=util_load_json("machine_detail_appliance.json"))

    # act
    result = machine_get_command(client, {"machine_identifier": "mach-0001"})

    # assert
    assert result.outputs["Host"] == "f5-ltm-01.example.com"
    assert result.outputs["ConnectionDetails"]["host"] == "https://admin@F5-LTM-01.Example.COM:8443/mgmt/"


def test_machine_get_raw_response_carries_only_allow_listed_connection_details(client: Client, requests_mock):
    # arrange
    machine = util_load_json("machine_detail_appliance.json")
    machine["connectionDetails"]["password"] = "not-a-real-secret"
    requests_mock.get(f"{MACHINES_URL}/mach-0001", json=machine)

    # act
    result = machine_get_command(client, {"machine_identifier": "mach-0001"})

    # assert
    assert "not-a-real-secret" not in json.dumps(result.raw_response)
    assert "not-a-real-secret" not in json.dumps(result.outputs)
    assert result.raw_response["ConnectionDetails"]["host"] == "https://admin@F5-LTM-01.Example.COM:8443/mgmt/"


def test_machine_get_omits_the_host_for_a_cloud_machine(client: Client, requests_mock):
    # arrange
    requests_mock.get(f"{MACHINES_URL}/mach-0002", json=util_load_json("machine_detail_cloud.json"))

    # act
    result = machine_get_command(client, {"machine_identifier": "mach-0002"})

    # assert
    assert "Host" not in result.outputs
    assert result.outputs["ConnectionDetails"]["keyVaultName"] == "prod-kv"


def test_days_until_expiry_accepts_an_injected_reference_time():
    # arrange
    now = datetime(2026, 9, 23, tzinfo=UTC)

    # act
    result = days_until_expiry("2026-10-23T00:00:00Z", now=now)

    # assert
    assert result == 30


""" REVOKE """


@pytest.mark.parametrize(
    "case, raw, expected",
    [
        ("accepts a sha-1 digest", KNOWN_FINGERPRINT.lower(), KNOWN_FINGERPRINT),
        ("strips separators", "A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:12:34:56:78", KNOWN_FINGERPRINT),
    ],
)
def test_normalize_sha1_fingerprint(case: str, raw: str, expected: str):
    # arrange / act
    result = normalize_sha1_fingerprint(raw)

    # assert
    assert result == expected, case


def test_normalize_sha1_fingerprint_rejects_a_digest_of_another_length():
    # arrange / act / assert
    with pytest.raises(ValueError, match="SHA-1"):
        normalize_sha1_fingerprint("A" * 64)


@freeze_time(FROZEN_NOW)
def test_certificate_revoke_sends_the_mutation_and_returns_the_revocation(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("revoke_certificate.json"))

    # act
    result = certificate_revoke_command(
        client, {"fingerprint": KNOWN_FINGERPRINT.lower(), "reason": "key_compromise", "comment": "case 4210"}
    )

    # assert
    sent = requests_mock.last_request.json()
    assert "revokeCertificate(fingerprint: $fingerprint" in sent["query"], "revocation is a mutation, not a REST call"
    assert sent["variables"] == {
        "fingerprint": KNOWN_FINGERPRINT,
        "revocationReason": "KEY_COMPROMISE",
        "revocationComment": "case 4210",
    }
    assert result.outputs["Revocation"] == {
        "Status": "SUBMITTED",
        "Reason": "KEY_COMPROMISE",
        "Comment": "Revoked by Cortex (case 4210).",
    }


def test_certificate_revoke_defaults_to_an_unspecified_reason(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("revoke_certificate.json"))

    # act
    certificate_revoke_command(client, {"fingerprint": KNOWN_FINGERPRINT})

    # assert
    assert requests_mock.last_request.json()["variables"]["revocationReason"] == "UNSPECIFIED"


def test_certificate_revoke_rejects_a_reason_the_api_does_not_accept(client: Client):
    # arrange / act / assert
    with pytest.raises(ValueError, match="CA_COMPROMISE"):
        certificate_revoke_command(client, {"fingerprint": KNOWN_FINGERPRINT, "reason": "CA_COMPROMISE"})


def test_certificate_revoke_fails_loudly_when_nothing_matched(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json={"data": {"revokeCertificate": None}})

    # act / assert
    with pytest.raises(Exception, match="nothing was revoked"):
        certificate_revoke_command(client, {"fingerprint": KNOWN_FINGERPRINT})


@pytest.mark.parametrize(
    "case, error, expected_text",
    [
        ("carries the CA's reason", {"message": "Already revoked, serial number 84B1"}, "Already revoked, serial number 84B1"),
        ("says when the CA gave none", None, "the CA gave no reason"),
    ],
)
def test_certificate_revoke_fails_when_the_ca_refuses(case, error, expected_text, client: Client, requests_mock):
    # arrange: a CA refusal is a normal response with status FAILED, not an error
    revoked = {"fingerprint": KNOWN_FINGERPRINT, "revocation": {"status": "FAILED", "reason": "KEY_COMPROMISE", "error": error}}
    requests_mock.post(GRAPHQL_URL, json={"data": {"revokeCertificate": revoked}})

    # act / assert
    with pytest.raises(Exception, match=f"The CA did not revoke certificate {KNOWN_FINGERPRINT}: {expected_text}"):
        certificate_revoke_command(client, {"fingerprint": KNOWN_FINGERPRINT, "reason": "KEY_COMPROMISE"})


""" CERTIFICATE REQUESTS """


def test_build_certificate_request_body_asks_the_service_to_generate_the_key_pair():
    # arrange
    args = MINIMAL_REQUEST_ARGS | {"common_name": "new.example.com", "sans": "a.example.com,b.example.com", "key_type": "rsa"}

    # act
    body = build_certificate_request_body(args)

    # assert
    assert body["isVaaSGenerated"] is True
    assert body["csrAttributes"]["commonName"] == "new.example.com"
    assert body["csrAttributes"]["subjectAlternativeNamesByType"] == {"dnsNames": ["a.example.com", "b.example.com"]}
    assert body["csrAttributes"]["keyTypeParameters"] == {"keyType": "RSA"}


def test_build_certificate_request_body_passes_a_supplied_csr_through():
    # arrange
    args = MINIMAL_REQUEST_ARGS | {"certificate_signing_request": "-----BEGIN CERTIFICATE REQUEST-----"}

    # act
    body = build_certificate_request_body(args)

    # assert
    assert body["isVaaSGenerated"] is False
    assert "csrAttributes" not in body, "a supplied CSR and generated CSR attributes are mutually exclusive"


def test_build_certificate_request_body_normalizes_a_renewal_fingerprint():
    # arrange
    renewal = {"common_name": "new.example.com", "existing_certificate_fingerprint": KNOWN_FINGERPRINT.lower()}
    args = MINIMAL_REQUEST_ARGS | renewal

    # act
    body = build_certificate_request_body(args)

    # assert
    assert body["existingCertificateFingerprint"] == KNOWN_FINGERPRINT


@pytest.mark.parametrize("renewal_key", ["existing_certificate_id", "existing_certificate_fingerprint"])
def test_build_certificate_request_body_clones_the_subject_on_a_key_generating_renewal(renewal_key):
    # arrange
    args = MINIMAL_REQUEST_ARGS | {
        "common_name": "new.example.com",
        "organization": "Example Org",
        "sans": "a.example.com,192.0.2.1",
        "key_type": "rsa",
        renewal_key: KNOWN_FINGERPRINT,
    }

    # act
    body = build_certificate_request_body(args)

    # assert
    assert body["renewType"] == "CLONED_CSR_WITH_NEW_PRIVATE_KEY", "otherwise fields left out of csrAttributes are dropped"
    assert body["csrAttributes"] == {"commonName": "new.example.com", "keyTypeParameters": {"keyType": "RSA"}}, (
        "the service copies the old subject and SANs; sending SANs could turn an IP SAN into a DNS name"
    )


def test_build_certificate_request_body_sends_no_renew_type_for_a_new_certificate_or_a_csr():
    # arrange
    new_certificate = MINIMAL_REQUEST_ARGS | {"common_name": "new.example.com"}
    csr_renewal = MINIMAL_REQUEST_ARGS | {
        "certificate_signing_request": "-----BEGIN CERTIFICATE REQUEST-----",
        "existing_certificate_fingerprint": KNOWN_FINGERPRINT,
    }

    # act / assert
    assert "renewType" not in build_certificate_request_body(new_certificate)
    assert "renewType" not in build_certificate_request_body(csr_renewal), "a CSR renewal carries its own subject"


@pytest.mark.parametrize(
    "case, args, expected_message",
    [
        ("requires a subject or a csr", MINIMAL_REQUEST_ARGS, "common_name"),
        (
            "rejects two ways of naming the certificate to renew",
            MINIMAL_REQUEST_ARGS | {"common_name": "a", "existing_certificate_id": "x", "existing_certificate_fingerprint": "y"},
            "mutually exclusive",
        ),
    ],
)
def test_build_certificate_request_body_rejects_incoherent_arguments(case: str, args: dict, expected_message: str):
    # arrange / act / assert
    with pytest.raises(ValueError, match=expected_message):
        build_certificate_request_body(args)


def test_certificate_request_returns_the_created_request(client: Client, requests_mock):
    # arrange
    requests_mock.post(CERTIFICATE_REQUESTS_URL, json=util_load_json("certificate_request_created.json"))

    # act
    result = certificate_request_command(client, MINIMAL_REQUEST_ARGS | {"common_name": "new.example.com"})

    # assert
    assert result.outputs[0]["ID"] == REQUEST_ID
    assert result.outputs[0]["Status"] == "REQUESTED"
    assert requests_mock.last_request.json()["applicationId"] == "app-1"


def test_certificate_request_fails_when_the_api_creates_nothing(client: Client, requests_mock):
    # arrange
    requests_mock.post(CERTIFICATE_REQUESTS_URL, json={"certificateRequests": []})

    # act / assert
    with pytest.raises(Exception, match="returned no certificate request"):
        certificate_request_command(client, MINIMAL_REQUEST_ARGS | {"common_name": "new.example.com"})


def test_certificate_request_status_returns_the_issued_certificate_ids(client: Client, requests_mock):
    # arrange
    requests_mock.get(f"{CERTIFICATE_REQUESTS_URL}/{REQUEST_ID}", json=util_load_json("certificate_request_status.json"))

    # act
    result = certificate_request_status_command(client, {"request_id": REQUEST_ID})

    # assert
    assert result.outputs["Status"] == "ISSUED"
    assert result.outputs["CertificateIDs"] == [CERTIFICATE_ID]


def test_certificate_request_status_surfaces_the_failure_reason(client: Client, requests_mock):
    # arrange
    failed = util_load_json("certificate_request_status.json") | {
        "status": "FAILED",
        "errorInformation": {"code": 1006, "message": "The issuing template rejected the subject."},
    }
    requests_mock.get(f"{CERTIFICATE_REQUESTS_URL}/{REQUEST_ID}", json=failed)

    # act
    result = certificate_request_status_command(client, {"request_id": REQUEST_ID})

    # assert
    assert result.outputs["ErrorCode"] == 1006
    assert result.outputs["ErrorMessage"] == "The issuing template rejected the subject."


""" DOWNLOAD """


def test_certificate_download_returns_a_file_and_the_pem_in_context(client: Client, requests_mock, monkeypatch, tmp_path):
    # arrange
    monkeypatch.chdir(tmp_path)
    requests_mock.get(CONTENTS_URL, text="-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")

    # act
    results = certificate_download_command(client, {"certificate_id": CERTIFICATE_ID, "chain_order": "EE_FIRST"})

    # assert
    assert results[0]["File"] == f"{CERTIFICATE_ID}.pem"
    assert results[1].outputs["Contents"].startswith("-----BEGIN CERTIFICATE-----")
    assert requests_mock.last_request.qs == {"format": ["pem"], "chainorder": ["ee_first"]}
    assert requests_mock.last_request.headers["Accept"] == "text/plain"


def test_certificate_download_returns_der_as_a_file_only(client: Client, requests_mock, monkeypatch, tmp_path):
    # arrange
    monkeypatch.chdir(tmp_path)
    requests_mock.get(CONTENTS_URL, content=b"\x30\x82\x01\x0a")

    # act
    results = certificate_download_command(client, {"certificate_id": CERTIFICATE_ID, "format": "der"})

    # assert
    assert len(results) == 1, "a binary payload has no useful context representation"
    assert results[0]["File"] == f"{CERTIFICATE_ID}.der"
    assert requests_mock.last_request.headers["Accept"] == "application/octet-stream"


def test_certificate_download_rejects_an_unsupported_format(client: Client):
    # arrange / act / assert
    with pytest.raises(ValueError, match="PKCS12"):
        certificate_download_command(client, {"certificate_id": CERTIFICATE_ID, "format": "pkcs12"})


""" KEYSTORE DOWNLOAD """

CERTIFICATE_URL = f"{BASE_URL}/outagedetection/v1/certificates/{CERTIFICATE_ID}"
KEYSTORE_URL = f"{CERTIFICATE_URL}/keystore"
DEK_HASH = "dek-hash-0001"
EDGE_KEY_URL = f"{BASE_URL}/v1/edgeencryptionkeys/{DEK_HASH}"
PASSPHRASE = "Aa1!dummy-passphrase"
KEYSTORE_CN = "shop.example.com"
ENCRYPTED_KEY = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHz\n-----END ENCRYPTED PRIVATE KEY-----\n"
LEAF = b"-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
ROOT = b"-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n"


@pytest.fixture
def edge_private_key() -> PrivateKey:
    return PrivateKey.generate()


def edge_key_response(private_key: PrivateKey, algorithm: str = "ED25519") -> dict:
    return {"key": base64.b64encode(bytes(private_key.public_key)).decode(), "keyAlgorithm": algorithm}


def pem_keystore_zip() -> bytes:
    """A PEM keystore shaped like the live one: the key, each certificate, and the chain in both orders."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(f"{KEYSTORE_CN}.key", ENCRYPTED_KEY)
        archive.writestr(f"{KEYSTORE_CN}.crt", LEAF)
        archive.writestr("Example Root CA.crt", ROOT)
        archive.writestr(f"{KEYSTORE_CN}_root-first.pem", ROOT + LEAF)
        archive.writestr(f"{KEYSTORE_CN}_root-last.pem", LEAF + ROOT)
    return buffer.getvalue()


def mock_keystore_api(requests_mock, private_key: PrivateKey, keystore: bytes, certificate: dict | None = None):
    certificate = {"id": CERTIFICATE_ID, "subjectCN": [KEYSTORE_CN], "dekHash": DEK_HASH} if certificate is None else certificate
    requests_mock.get(CERTIFICATE_URL, json=certificate)
    requests_mock.get(EDGE_KEY_URL, json=edge_key_response(private_key))
    return requests_mock.post(KEYSTORE_URL, status_code=201, content=keystore)


def written_file(tmp_path, entry: dict) -> bytes:
    """Read back what fileResult wrote for a war-room file entry."""
    return (tmp_path / f"{demisto.investigation()['id']}_{entry['FileID']}").read_bytes()


@pytest.mark.parametrize(
    "case, export_format, expected_keystore_passphrase",
    [
        ("leaves the zip without a passphrase for PEM", "PEM", ""),
        ("protects the p12 file with the passphrase too", "PKCS12", "sealed"),
    ],
)
def test_build_keystore_request_body(case: str, export_format: str, expected_keystore_passphrase: str):
    # arrange / act
    body = build_keystore_request_body(export_format, "sealed")

    # assert
    assert body == {
        "exportFormat": export_format,
        "encryptedPrivateKeyPassphrase": "sealed",
        "encryptedKeystorePassphrase": expected_keystore_passphrase,
        "certificateLabel": "",
    }, case


def test_certificate_keystore_download_returns_the_pem_key_and_chain_as_files(
    client: Client, requests_mock, monkeypatch, tmp_path, edge_private_key: PrivateKey
):
    # arrange
    monkeypatch.chdir(tmp_path)  # fileResult writes into the working directory
    keystore_mock = mock_keystore_api(requests_mock, edge_private_key, pem_keystore_zip())

    # act
    key_entry, chain_entry, result = certificate_keystore_download_command(
        client, {"certificate_id": CERTIFICATE_ID, "passphrase": PASSPHRASE}
    )

    # assert
    assert (key_entry["File"], chain_entry["File"]) == (f"{KEYSTORE_CN}.key", f"{KEYSTORE_CN}.pem")
    assert written_file(tmp_path, key_entry) == ENCRYPTED_KEY
    assert written_file(tmp_path, chain_entry) == LEAF + ROOT, "the chain is leaf first"
    assert result.outputs == {
        "CertificateID": CERTIFICATE_ID,
        "Format": "PEM",
        "PrivateKeyFileName": f"{KEYSTORE_CN}.key",
        "ChainFileName": f"{KEYSTORE_CN}.pem",
    }
    assert result.outputs_prefix == "CertManagerSaaS.Keystore"
    assert "PRIVATE KEY" not in json.dumps(result.to_context()), "no key material in the context, raw response or table"
    request = keystore_mock.last_request
    assert request.headers["Accept"] == "*/*", "with application/octet-stream every error is an empty 400"
    body = request.json()
    assert (body["exportFormat"], body["encryptedKeystorePassphrase"], body["certificateLabel"]) == ("PEM", "", "")
    assert SealedBox(edge_private_key).decrypt(base64.b64decode(body["encryptedPrivateKeyPassphrase"])) == PASSPHRASE.encode()
    assert PASSPHRASE not in request.text, "the passphrase never travels in clear"


def test_certificate_keystore_download_returns_pkcs12_as_one_file(
    client: Client, requests_mock, monkeypatch, tmp_path, edge_private_key: PrivateKey
):
    # arrange
    monkeypatch.chdir(tmp_path)
    p12 = b"\x30\x82\x0a\x1b-raw-pkcs12"
    keystore_mock = mock_keystore_api(requests_mock, edge_private_key, p12)

    # act
    results = certificate_keystore_download_command(
        client, {"certificate_id": CERTIFICATE_ID, "passphrase": PASSPHRASE, "format": "pkcs12"}
    )

    # assert
    assert len(results) == 2
    assert results[0]["File"] == f"{KEYSTORE_CN}.p12"
    assert written_file(tmp_path, results[0]) == p12, "the p12 is returned as is, not unzipped"
    assert results[1].outputs == {"CertificateID": CERTIFICATE_ID, "Format": "PKCS12", "KeystoreFileName": f"{KEYSTORE_CN}.p12"}
    body = keystore_mock.last_request.json()
    assert body["exportFormat"] == "PKCS12"
    assert SealedBox(edge_private_key).decrypt(base64.b64decode(body["encryptedKeystorePassphrase"])) == PASSPHRASE.encode()


@pytest.mark.parametrize(
    "case, certificate, edge_key, keystore, expected_message",
    [
        (
            "explains a key the VSatellite did not generate",
            {"id": CERTIFICATE_ID, "subjectCN": [KEYSTORE_CN]},
            None,
            None,
            "Only private keys that a VSatellite generated",
        ),
        (
            "explains a VSatellite key that no longer exists",
            None,
            {"status_code": 404, "json": {"errors": [{"code": 404, "message": "Not found"}]}},
            None,
            "no longer exists",
        ),
        (
            "rejects a VSatellite key type it cannot seal for",
            None,
            {"json": {"key": "AAAA", "keyAlgorithm": "VSAT_HPKE"}},
            None,
            "type VSAT_HPKE. Downloading it is not supported yet",
        ),
        (
            "explains a CA that returned no chain",
            None,
            None,
            {"status_code": 400, "json": {"errors": [{"code": 20602, "message": "Issuer certificates not available"}]}},
            "didn't provide the issuer certificates",
        ),
        (
            "quotes any other API error",
            None,
            None,
            {"status_code": 400, "json": {"errors": [{"code": 1006, "message": "request object parsing failed"}]}},
            r"failed \(HTTP 400\): request object parsing failed",
        ),
        (
            "keeps the product's 401 message",
            None,
            None,
            {"status_code": 401, "json": {"errors": [{"code": 10501, "message": "Unauthorized"}]}},
            "The API key was rejected",
        ),
    ],
)
def test_certificate_keystore_download_errors(
    case: str,
    certificate: dict | None,
    edge_key: dict | None,
    keystore: dict | None,
    expected_message: str,
    client: Client,
    requests_mock,
    edge_private_key: PrivateKey,
):
    # arrange
    mock_keystore_api(requests_mock, edge_private_key, b"", certificate)
    if edge_key:
        requests_mock.get(EDGE_KEY_URL, **edge_key)
    if keystore:
        requests_mock.post(KEYSTORE_URL, **keystore)

    # act / assert
    with pytest.raises(DemistoException, match=expected_message):
        certificate_keystore_download_command(client, {"certificate_id": CERTIFICATE_ID, "passphrase": PASSPHRASE})


@pytest.mark.parametrize(
    "case, args, default_passphrase, expected_passphrase, expected_note",
    [
        ("uses the instance setting when no argument is given", {}, "setting-passphrase", "setting-passphrase", "setting"),
        (
            "uses the instance setting for an empty argument",
            {"passphrase": ""},
            "setting-passphrase",
            "setting-passphrase",
            "setting",
        ),
        (
            "prefers the argument over the instance setting",
            {"passphrase": PASSPHRASE},
            "setting-passphrase",
            PASSPHRASE,
            "you supplied",
        ),
    ],
)
def test_certificate_keystore_download_passphrase_source(
    case: str,
    args: dict,
    default_passphrase: str,
    expected_passphrase: str,
    expected_note: str,
    client: Client,
    requests_mock,
    monkeypatch,
    tmp_path,
    edge_private_key: PrivateKey,
):
    # arrange
    monkeypatch.chdir(tmp_path)  # fileResult writes into the working directory
    keystore_mock = mock_keystore_api(requests_mock, edge_private_key, pem_keystore_zip())

    # act
    results = certificate_keystore_download_command(client, {"certificate_id": CERTIFICATE_ID} | args, default_passphrase)

    # assert
    sealed = base64.b64decode(keystore_mock.last_request.json()["encryptedPrivateKeyPassphrase"])
    assert SealedBox(edge_private_key).decrypt(sealed) == expected_passphrase.encode(), case
    assert expected_note in results[-1].readable_output, "the note names the passphrase that opens the file"


@pytest.mark.parametrize(
    "case, params, expected",
    [
        ("reads the password of the credential", {"keystore_passphrase": {"identifier": "", "password": "p"}}, "p"),
        ("is empty when the setting is empty", {"keystore_passphrase": {"identifier": "", "password": ""}}, ""),
        ("is empty when the setting is missing", {}, ""),
    ],
)
def test_keystore_passphrase(case: str, params: dict, expected: str):
    # arrange / act / assert
    assert keystore_passphrase(params) == expected, case


@pytest.mark.parametrize(
    "case, args, expected_message",
    [
        ("rejects a format the API does not offer", {"passphrase": PASSPHRASE, "format": "JKS"}, "PEM, PKCS12"),
        ("requires a passphrase from the argument or the setting", {"passphrase": ""}, "set the instance's Keystore passphrase"),
    ],
)
def test_certificate_keystore_download_rejects_bad_arguments(case: str, args: dict, expected_message: str, client: Client):
    # arrange / act / assert: nothing is sent, so no request is mocked
    with pytest.raises(ValueError, match=expected_message):
        certificate_keystore_download_command(client, {"certificate_id": CERTIFICATE_ID} | args)


@pytest.mark.parametrize(
    "case, certificate, expected",
    [
        ("uses the first common name", {"subjectCN": [KEYSTORE_CN, "other.example.com"]}, KEYSTORE_CN),
        ("makes a wildcard safe for a file name", {"subjectCN": ["*.example.com"]}, "_.example.com"),
        ("falls back to the certificate id", {}, CERTIFICATE_ID),
    ],
)
def test_keystore_base_name(case: str, certificate: dict, expected: str):
    # arrange / act / assert
    assert keystore_base_name(certificate, CERTIFICATE_ID) == expected, case


@pytest.mark.parametrize(
    "case, content, expected_message",
    [
        ("rejects a body that is not a zip", b"not a zip", "not a zip archive"),
        ("rejects a zip without the chain", None, "no private key or no chain file"),
    ],
)
def test_unpack_pem_keystore_rejects_an_unexpected_body(case: str, content: bytes | None, expected_message: str):
    # arrange
    if content is None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(f"{KEYSTORE_CN}.key", ENCRYPTED_KEY)
        content = buffer.getvalue()

    # act / assert
    with pytest.raises(DemistoException, match=expected_message):
        unpack_pem_keystore(content)


def test_main_dispatches_the_keystore_download(requests_mock, monkeypatch, tmp_path, edge_private_key: PrivateKey):
    # arrange
    monkeypatch.chdir(tmp_path)
    mock_keystore_api(requests_mock, edge_private_key, pem_keystore_zip())
    returned: list = []
    monkeypatch.setattr(demisto, "params", lambda: {"url": BASE_URL, "credentials": {"password": API_KEY}})
    monkeypatch.setattr(demisto, "args", lambda: {"certificate_id": CERTIFICATE_ID, "passphrase": PASSPHRASE})
    monkeypatch.setattr(demisto, "command", lambda: "cmsaas-certificate-keystore-download")
    monkeypatch.setattr(CertificateManagerSaaS, "return_results", returned.append)
    monkeypatch.setattr(CertificateManagerSaaS, "return_error", pytest.fail)

    # act
    CertificateManagerSaaS.main()

    # assert
    assert [entry["File"] for entry in returned[0][:2]] == [f"{KEYSTORE_CN}.key", f"{KEYSTORE_CN}.pem"]


""" EXPIRY THRESHOLDS """


@pytest.mark.parametrize(
    "case, payload, expected_fragment",
    [
        ("reports an aligned tenant", {"getCertExpActiveThresholds": {"thresholds": [7, 30, 90]}}, "covers the severity ladder"),
        ("reports a misaligned tenant", {"getCertExpActiveThresholds": {"thresholds": [14]}}, "does not include [7, 30]"),
        ("reports a tenant with no thresholds", {"getCertExpActiveThresholds": {"thresholds": []}}, "no certificate-expiry"),
    ],
)
def test_threshold_alignment_message(case: str, payload: dict, expected_fragment: str, client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json={"data": payload})

    # act
    message = threshold_alignment_message(client)

    # assert
    assert expected_fragment in message, case


def test_threshold_alignment_message_tolerates_a_root_field_that_is_not_allow_listed(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, status_code=403, text="")

    # act
    message = threshold_alignment_message(client)

    # assert
    assert message.startswith("Could not read"), "a diagnostic must never fail the connection test"


""" FETCH INCIDENTS """


@pytest.mark.parametrize(
    "case, threshold_days, expected",
    [
        ("critical at the seven day threshold", 7, IncidentSeverity.CRITICAL),
        ("critical below the seven day threshold", 3, IncidentSeverity.CRITICAL),
        ("high at the thirty day threshold", 30, IncidentSeverity.HIGH),
        ("high between the two thresholds", 14, IncidentSeverity.HIGH),
        ("medium beyond the thirty day threshold", 45, IncidentSeverity.MEDIUM),
    ],
)
def test_threshold_severity(case: str, threshold_days: int, expected: float):
    # arrange / act
    result = threshold_severity(threshold_days)

    # assert
    assert result == expected, case
    assert result >= IncidentSeverity.MEDIUM, "low creates neither a case nor a grouping"


@pytest.mark.parametrize(
    "case, window_days, expected",
    [
        ("the ladder for the default window", 30, [7, 30]),
        ("a wider window adds its own rung", 45, [7, 30, 45]),
        ("a narrower window clamps the thirty day rung to itself", 14, [7, 14]),
        ("a window inside the critical rung leaves one rung", 5, [5]),
    ],
)
def test_expiry_thresholds(case: str, window_days: int, expected: list[int]):
    # arrange / act
    result = expiry_thresholds(window_days)

    # assert
    assert result == expected, case


@freeze_time(FROZEN_NOW)
def test_fetch_incidents_creates_one_incident_per_threshold_crossing(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))

    # act
    incidents, last_run = fetch_incidents(client, {}, {})

    # assert
    assert [incident["name"].split(": ")[-1] for incident in incidents] == [
        "high.example.com",
        "crit.example.com",
        "late.example.com",
    ], "oldest threshold crossing first"
    assert [incident["occurred"] for incident in incidents] == [
        "2026-09-15T00:00:00Z",
        "2026-09-20T00:00:00Z",
        "2026-09-22T06:00:00Z",
    ], "occurred is when the certificate crossed the threshold, not when we noticed"
    assert [incident["severity"] for incident in incidents] == [
        IncidentSeverity.HIGH,
        IncidentSeverity.CRITICAL,
        IncidentSeverity.HIGH,
    ]
    assert [json.loads(incident["rawJSON"])["CrossedThresholdDays"] for incident in incidents] == [30, 7, 30]
    assert {incident["type"] for incident in incidents} == {"CertManagerSaaS Certificate Expiry"}
    assert {json.loads(incident["rawJSON"])["IssueType"] for incident in incidents} == {"CertManagerSaaS Certificate Expiry"}, (
        "the Common pack classifier types the issue from this key; XSIAM ignores the incident's type"
    )
    assert last_run["time"] == "2026-09-22T06:00:00Z"
    assert set(last_run["found_incident_ids"]) == {f"{'B' * 40}:30", f"{'A' * 40}:7", f"{'C' * 40}:30"}


@freeze_time(FROZEN_NOW)
def test_fetch_incidents_raises_only_the_critical_crossing_for_a_backlog_certificate(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))

    # act
    incidents, _ = fetch_incidents(client, {}, {})

    # assert
    backlog = [incident for incident in incidents if json.loads(incident["rawJSON"])["Fingerprint"] == "A" * 40]
    assert len(backlog) == 1, "the thirty day crossing is already stale once the seven day one has happened"
    assert backlog[0]["severity"] == IncidentSeverity.CRITICAL
    assert backlog[0]["dedup_id"] == f"{'A' * 40}:7"


def test_fetch_incidents_raises_a_new_incident_for_each_threshold_crossed_across_fetches(client: Client, requests_mock):
    # arrange
    page = util_load_json("fetch_certificates_page.json")
    page["data"]["searchCertificates"]["nodes"] = [
        {**page["data"]["searchCertificates"]["nodes"][1], "validity": {"to": "2026-10-20T00:00:00Z"}}
    ]
    requests_mock.post(GRAPHQL_URL, json=page)

    # act
    with freeze_time("2026-09-21T00:00:00Z"):
        first, last_run = fetch_incidents(client, {}, {})
    with freeze_time("2026-10-14T00:00:00Z"):
        second, _ = fetch_incidents(client, {}, last_run)

    # assert
    assert [incident["severity"] for incident in first] == [IncidentSeverity.HIGH]
    assert [incident["severity"] for incident in second] == [IncidentSeverity.CRITICAL]
    assert [incident["occurred"] for incident in first + second] == ["2026-09-20T00:00:00Z", "2026-10-13T00:00:00Z"]


@freeze_time(FROZEN_NOW)
def test_fetch_incidents_does_not_duplicate_on_re_fetch(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))
    _, last_run = fetch_incidents(client, {}, {})

    # act
    incidents, _ = fetch_incidents(client, {}, last_run)

    # assert
    assert incidents == [], "every crossing inside the look back is already recorded"


@freeze_time(FROZEN_NOW)
def test_fetch_incidents_drops_a_certificate_without_a_usable_expiry_date(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))

    # act
    incidents, _ = fetch_incidents(client, {}, {})

    # assert
    assert "D" * 40 not in {json.loads(incident["rawJSON"])["Fingerprint"] for incident in incidents}


@freeze_time(FROZEN_NOW)
def test_fetch_incidents_uses_the_server_side_expiry_filter(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))

    # act
    fetch_incidents(client, {"fetch_expiry_days": "45"}, {})

    # assert
    sent_query = requests_mock.request_history[0].json()["query"]
    assert 'validityTo: {between: {gte: "2026-09-23T00:00:00Z", lte: "2026-11-07T00:00:00Z"}}' in sent_query
    # Only the current, active version: a renewed (replaced) or retired certificate must not raise expiry issues.
    assert "isCurrent: {eq: true}" in sent_query
    assert "status: {eq: ACTIVE}" in sent_query, "an enum filter value must be bare, not quoted"


@freeze_time(FROZEN_NOW)
def test_fetch_incidents_does_not_recreate_an_incident_it_already_created(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))
    last_run = {"time": "2026-08-01T00:00:00Z", "found_incident_ids": {f"{'A' * 40}:7": 1758326400000}}

    # act
    incidents, _ = fetch_incidents(client, {"look_back": "0"}, last_run)

    # assert
    assert [json.loads(incident["rawJSON"])["Fingerprint"] for incident in incidents] == ["B" * 40, "C" * 40]


@freeze_time(FROZEN_NOW)
@pytest.mark.parametrize(
    "case, look_back, expected",
    [
        ("skips a crossing that predates the last run", "0", []),
        ("recovers it once a look back is configured", "1440", ["late.example.com"]),
    ],
)
def test_fetch_incidents_look_back_recovers_a_late_threshold_crossing(
    case: str, look_back: str, expected: list[str], client: Client, requests_mock
):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))
    last_run = {"time": "2026-09-22T12:00:00Z"}

    # act
    incidents, _ = fetch_incidents(client, {"look_back": look_back}, last_run)

    # assert
    assert [incident["name"].split(": ")[-1] for incident in incidents] == expected, case


@freeze_time(FROZEN_NOW)
def test_fetch_incidents_honours_the_maximum_per_fetch(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))

    # act
    incidents, last_run = fetch_incidents(client, {"max_fetch": "1"}, {})

    # assert
    assert len(incidents) == 1
    assert last_run["time"] == "2026-09-15T00:00:00Z", "the next run resumes at the oldest crossing not yet consumed"


@freeze_time(FROZEN_NOW)
def test_fetch_incidents_uses_the_incident_type_selected_on_the_instance(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))

    # act
    incidents, _ = fetch_incidents(client, {"incidentType": "Custom Expiry"}, {})

    # assert
    assert {incident["type"] for incident in incidents} == {"Custom Expiry"}


def failed_revocations_page(*revocations: tuple[str, str]) -> dict:
    """A search page of certificates with FAILED revocations, one per (fingerprint, reason)."""
    nodes = [
        {
            "fingerprint": fingerprint,
            "subject": {"commonName": [f"{fingerprint[:4].lower()}.example.com"]},
            "revocation": {"status": "FAILED", "reason": reason, "error": {"message": "CA refused the request"}},
        }
        for fingerprint, reason in revocations
    ]
    return {"data": {"searchCertificates": {"pageInfo": {"hasNextPage": False}, "nodes": nodes}}}


def route_fetch_queries(requests_mock, failed_page: dict) -> None:
    """Answer the expiry query with the fetch fixture and the FAILED-revocation query with `failed_page`."""
    expiry_page = util_load_json("fetch_certificates_page.json")

    def answer(request, context):
        return failed_page if "revocationStatus" in request.json()["query"] else expiry_page

    requests_mock.post(GRAPHQL_URL, json=answer)


@freeze_time(FROZEN_NOW)
def test_fetch_incidents_raises_a_high_issue_for_a_failed_key_compromise_revocation(client: Client, requests_mock):
    # arrange
    route_fetch_queries(requests_mock, failed_revocations_page(("D" * 40, "KEY_COMPROMISE"), ("E" * 40, "SUPERSEDED")))

    # act
    incidents, last_run = fetch_incidents(client, {}, {})

    # assert
    failures = [incident for incident in incidents if incident["type"] == "CertManagerSaaS Revocation Failed"]
    assert [incident["name"] for incident in failures] == ["Key-compromise revocation failed: dddd.example.com"]
    assert failures[0]["severity"] == IncidentSeverity.HIGH
    assert json.loads(failures[0]["rawJSON"])["IssueType"] == "CertManagerSaaS Revocation Failed"
    assert "CA refused the request" in failures[0]["details"], "the analyst sees why the CA refused"
    assert "revocationStatus: {eq: FAILED}" in requests_mock.last_request.json()["query"], "an enum value must not be quoted"
    assert last_run["raised_revocation_failures"] == ["D" * 40], "only key-compromise failures are tracked"


@freeze_time(FROZEN_NOW)
@pytest.mark.parametrize(
    "case, raised_before, expected",
    [
        ("does not raise the same failure twice", ["D" * 40], []),
        ("raises again after the certificate left the failed state", [], ["D" * 40]),
    ],
)
def test_fetch_incidents_deduplicates_failed_revocations_by_state(case, raised_before, expected, client: Client, requests_mock):
    # arrange
    route_fetch_queries(requests_mock, failed_revocations_page(("D" * 40, "KEY_COMPROMISE")))

    # act
    incidents, _ = fetch_incidents(client, {}, {"raised_revocation_failures": raised_before})

    # assert
    raised = [json.loads(i["rawJSON"])["Fingerprint"] for i in incidents if i["type"] == "CertManagerSaaS Revocation Failed"]
    assert raised == expected, case


@freeze_time(FROZEN_NOW)
@pytest.mark.parametrize(
    "case, params, expected_issue_type",
    [
        ("defaults to the pack's expiry type", {}, "CertManagerSaaS Certificate Expiry"),
        ("carries a custom type chosen on the instance", {"incidentType": "Custom Expiry"}, "Custom Expiry"),
    ],
)
def test_fetch_incidents_writes_the_issue_type_for_the_classifier(
    case, params, expected_issue_type, client: Client, requests_mock
):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))

    # act
    incidents, _ = fetch_incidents(client, params, {})

    # assert
    assert {json.loads(incident["rawJSON"])["IssueType"] for incident in incidents} == {expected_issue_type}, case


def test_build_revocation_failed_incident_without_a_ca_error():
    # arrange
    certificate = {"fingerprint": "D" * 40, "revocation": {"status": "FAILED", "reason": "KEY_COMPROMISE"}}

    # act
    incident = build_revocation_failed_incident(certificate, "CertificateManagerSaaS", now=datetime(2026, 9, 28, tzinfo=UTC))

    # assert
    assert "the CA gave no reason" in incident["details"]
    assert incident["occurred"] == "2026-09-28T00:00:00Z"
    assert incident["dedup_id"] == f"{'D' * 40}:revocation-failed"


KC = "KEY_COMPROMISE"
SUSPICIOUS = Common.DBotScore.SUSPICIOUS
BAD = Common.DBotScore.BAD


@pytest.mark.parametrize(
    "case, revocation, global_revocation, reported_score, expected_score",
    [
        ("scores nothing without a revocation", None, None, SUSPICIOUS, Common.DBotScore.NONE),
        ("never scores good when the CA says not revoked", None, {"status": "NOT_REVOKED"}, SUSPICIOUS, Common.DBotScore.NONE),
        (
            "key compromise confirmed by the CA list is malicious",
            {"status": "SUBMITTED", "reason": KC},
            {"status": "REVOKED"},
            SUSPICIOUS,
            BAD,
        ),
        (
            "key compromise submitted to a private CA is malicious",
            {"status": "SUBMITTED", "reason": KC},
            {"status": "UNKNOWN"},
            SUSPICIOUS,
            BAD,
        ),
        (
            "key compromise submitted without a CA list result is malicious",
            {"status": "SUBMITTED", "reason": KC},
            None,
            SUSPICIOUS,
            BAD,
        ),
        (
            "key compromise revoked outside CM SaaS is malicious",
            None,
            {"status": "REVOKED", "reason": "KEY_COMPROMISED"},
            SUSPICIOUS,
            BAD,
        ),
        (
            "failed key compromise is suspicious",
            {"status": "FAILED", "reason": KC},
            {"status": "UNKNOWN"},
            SUSPICIOUS,
            SUSPICIOUS,
        ),
        (
            "key compromise waiting for approval is suspicious",
            {"status": "PENDING_APPROVAL", "reason": KC},
            None,
            SUSPICIOUS,
            SUSPICIOUS,
        ),
        (
            "key compromise waiting for final approval is suspicious",
            {"status": "PENDING_FINAL_APPROVAL", "reason": KC},
            None,
            SUSPICIOUS,
            SUSPICIOUS,
        ),
        (
            "submitted key compromise the CA list shows not revoked is suspicious",
            {"status": "SUBMITTED", "reason": KC},
            {"status": "NOT_REVOKED"},
            SUSPICIOUS,
            SUSPICIOUS,
        ),
        ("the setting raises reported key compromise to malicious", {"status": "FAILED", "reason": KC}, None, BAD, BAD),
        ("the setting does not touch other reasons", {"status": "SUBMITTED", "reason": "SUPERSEDED"}, None, BAD, SUSPICIOUS),
        (
            "revoked for another reason is suspicious",
            {"status": "SUBMITTED", "reason": "SUPERSEDED"},
            {"status": "UNKNOWN"},
            SUSPICIOUS,
            SUSPICIOUS,
        ),
        (
            "revoked outside CM SaaS for another reason is suspicious",
            None,
            {"status": "REVOKED", "reason": "SUPERSEDED"},
            SUSPICIOUS,
            SUSPICIOUS,
        ),
        (
            "failed revocation for another reason scores nothing",
            {"status": "FAILED", "reason": "SUPERSEDED"},
            None,
            SUSPICIOUS,
            Common.DBotScore.NONE,
        ),
        (
            "rejected key compromise approval scores nothing",
            {"status": "REJECTED_APPROVAL", "reason": KC},
            None,
            BAD,
            Common.DBotScore.NONE,
        ),
        (
            "rejected key compromise but revoked for another reason is suspicious",
            {"status": "REJECTED_APPROVAL", "reason": KC},
            {"status": "REVOKED", "reason": "SUPERSEDED"},
            BAD,
            SUSPICIOUS,
        ),
    ],
)
def test_revocation_verdict(case, revocation, global_revocation, reported_score, expected_score):
    # arrange
    certificate = {"fingerprint": "A" * 40, "revocation": revocation, "globalRevocation": global_revocation}

    # act
    score, description = revocation_verdict(certificate, "Certificate Manager SaaS", reported_score)

    # assert
    assert score == expected_score, case
    assert (description is not None) == (expected_score == BAD), "a malicious description goes with a BAD score only"


@pytest.mark.parametrize(
    "case, revocation, global_revocation, expected_text",
    [
        (
            "names the confirmation date",
            {"status": "SUBMITTED", "reason": KC},
            {"status": "REVOKED", "revokedTime": "2026-09-01T00:00:00Z"},
            "2026-09-01T00:00:00Z",
        ),
        (
            "explains an unverifiable submission",
            {"status": "SUBMITTED", "reason": KC},
            {"status": "UNKNOWN"},
            "cannot be checked",
        ),
        ("carries the revocation comment", {"status": "SUBMITTED", "reason": KC, "comment": "case 4412"}, None, "case 4412"),
    ],
)
def test_revocation_verdict_description(case, revocation, global_revocation, expected_text):
    # arrange
    certificate = {"fingerprint": "A" * 40, "revocation": revocation, "globalRevocation": global_revocation}

    # act
    _, description = revocation_verdict(certificate, "Certificate Manager SaaS")

    # assert
    assert expected_text in description, case


@pytest.mark.parametrize(
    "case, revocation, global_revocation, expected_revocation, expected_verdict",
    [
        (
            "shows a malicious key compromise",
            {"status": "SUBMITTED", "reason": KC},
            {"status": "UNKNOWN"},
            "SUBMITTED (KEY_COMPROMISE)",
            "Malicious",
        ),
        (
            "shows a suspicious revocation",
            {"status": "SUBMITTED", "reason": "SUPERSEDED"},
            None,
            "SUBMITTED (SUPERSEDED)",
            "Suspicious",
        ),
        ("shows an unscored certificate as unknown", None, None, None, "Unknown"),
    ],
)
def test_certificate_readable_row(case, revocation, global_revocation, expected_revocation, expected_verdict):
    # arrange
    certificate = {"fingerprint": "A" * 40, "revocation": revocation, "globalRevocation": global_revocation}
    context = certificate_to_context(certificate, "CertificateManagerSaaS")

    # act
    row = certificate_readable_row(certificate, context, SUSPICIOUS)

    # assert
    assert row.get("Revocation") == expected_revocation, case
    assert row["Verdict"] == expected_verdict, case


def test_build_search_query_requests_the_revocation_blocks_the_verdict_needs():
    # arrange / act
    query = build_search_query({"and": {"fingerprint": {"in": ["A" * 40]}}})

    # assert
    assert "revocation { status reason comment error { message } }" in query
    assert "globalRevocation { status reason revokedTime }" in query, "the CA list result decides confirmed revocation"


@pytest.mark.parametrize(
    "case, params, expected",
    [
        ("defaults to suspicious", {}, SUSPICIOUS),
        ("reads malicious", {"reported_key_compromise_score": "Malicious"}, BAD),
    ],
)
def test_resolve_reported_key_compromise_score(case, params, expected):
    # act / assert
    assert resolve_reported_key_compromise_score(params) == expected, case


def test_resolve_reported_key_compromise_score_rejects_unknown_values():
    # act / assert
    with pytest.raises(DemistoException, match="Suspicious or Malicious"):
        resolve_reported_key_compromise_score({"reported_key_compromise_score": "Good"})
