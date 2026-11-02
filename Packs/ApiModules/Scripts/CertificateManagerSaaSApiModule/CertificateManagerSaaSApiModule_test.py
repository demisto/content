"""Unit tests for CertificateManagerSaaSApiModule.

These cover the module on its own: the client base, its authentication hook and the product
profile, the pure helpers, scoring, certificate request bodies and the fetch. The integrations'
own suites exercise the shared commands end to end through their clients.
"""

import base64
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import demistomock as demisto
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hpke, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from freezegun import freeze_time
from nacl.public import PrivateKey, SealedBox

from CommonServerPython import Common, DemistoException, IncidentSeverity

from CertificateManagerSaaSApiModule import (
    MAX_HOST_LOOKUPS,
    READ_RETRIES,
    RETRY_STATUSES,
    CertificateManagerClient,
    GraphQLEnum,
    GraphQLQueryError,
    ProductProfile,
    seal_passphrase,
    build_certificate_request_body,
    build_revocation_failed_incident,
    build_search_query,
    build_expiry_incident,
    certificate_command,
    certificate_readable_output,
    certificate_readable_row,
    certificate_revoke_command,
    certificate_search_command,
    certificate_to_context,
    cloud_installation_context,
    collection_nodes,
    connection_address,
    days_until_expiry,
    edge_encryption_key,
    enrich_installations_with_hosts,
    expiry_thresholds,
    extract_list,
    extract_subject_alternative_names,
    fetch_incidents,
    hpke_seal,
    first_common_name,
    installation_locations,
    normalize_fingerprint,
    normalize_host,
    normalize_sha1_fingerprint,
    partition_fingerprints,
    public_key_context,
    resolve_reported_key_compromise_score,
    revocation_failed_incidents,
    revocation_verdict,
    safe_connection_details,
    threshold_severity,
    to_graphql_literal,
    updated_expiry_state,
)

BASE_URL = "https://api.example.test"
GRAPHQL_URL = f"{BASE_URL}/graphql"
KEYSTORE_URL = f"{BASE_URL}/outagedetection/v1/certificates/cert-1/keystore"
PRODUCT = ProductProfile(
    name="Example Product",
    brand="ExampleProduct",
    user_agent="unit-test-agent",
    http_error_messages={401: "Example credential rejected."},
)
EMPTY_SEARCH = {"data": {"searchCertificates": {"totalCount": 0, "pageInfo": {"hasNextPage": False}, "nodes": []}}}
KNOWN_FINGERPRINT = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
FROZEN_NOW = "2026-09-23T00:00:00Z"
NOW = datetime(2026, 9, 23, tzinfo=UTC)
MINIMAL_REQUEST_ARGS = {"application_id": "app-1", "certificate_issuing_template_id": "tmpl-1"}
EXPIRY_TYPE = "CertManagerSaaS Certificate Expiry"


def util_load_json(name: str) -> dict:
    path = os.path.join(os.path.dirname(__file__), "test_data", name)
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


class BearerClient(CertificateManagerClient):
    """A client that authenticates per request, the way a token-based integration does."""

    def _http_request(self, *args: Any, **kwargs: Any) -> Any:
        kwargs["headers"] = {**(kwargs.get("headers") or self._headers or {}), "Authorization": "Bearer dummy-token"}
        return super()._http_request(*args, **kwargs)


@pytest.fixture
def client() -> CertificateManagerClient:
    return CertificateManagerClient(base_url=BASE_URL, product=PRODUCT, verify=False, proxy=False)


def test_client_sends_static_credential_headers_and_the_product_user_agent(requests_mock):
    # arrange
    client = CertificateManagerClient(
        base_url=BASE_URL, product=PRODUCT, verify=False, proxy=False, headers={"x-api-key": "dummy-key"}
    )
    requests_mock.post(GRAPHQL_URL, json=EMPTY_SEARCH)

    # act
    client.search_certificates(first=1)

    # assert
    headers = requests_mock.last_request.headers
    assert headers["x-api-key"] == "dummy-key"
    assert headers["User-Agent"] == PRODUCT.user_agent
    assert headers["Accept"] == "application/json"


def test_client_lets_a_subclass_attach_per_request_authentication(requests_mock):
    # arrange
    client = BearerClient(base_url=BASE_URL, product=PRODUCT, verify=False, proxy=False)
    requests_mock.post(GRAPHQL_URL, json=EMPTY_SEARCH)

    # act
    result = certificate_search_command(client, {})

    # assert
    assert requests_mock.last_request.headers["Authorization"] == "Bearer dummy-token"
    assert requests_mock.last_request.headers["User-Agent"] == PRODUCT.user_agent
    assert result.outputs is None
    assert "Example Product certificates" in result.readable_output


def test_client_names_the_product_when_graphql_returns_errors(client: CertificateManagerClient, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json={"errors": [{"message": "Validation error"}], "data": None})

    # act / assert
    with pytest.raises(GraphQLQueryError, match="The Example Product GraphQL gateway returned errors: Validation error"):
        client.search_certificates(first=1)


@pytest.mark.parametrize(
    "case, status_code, expected_message",
    [
        ("uses the product message for a known status", 401, "Example credential rejected."),
        ("falls back to the shared 404 message", 404, "not available on this tenant"),
        ("names the product for any other status", 500, "Request to Example Product failed with HTTP 500"),
    ],
)
def test_client_raise_http_error(
    case: str, status_code: int, expected_message: str, client: CertificateManagerClient, requests_mock
):
    # arrange
    requests_mock.post(GRAPHQL_URL, status_code=status_code, text="boom")

    # act / assert
    with pytest.raises(Exception, match=expected_message):
        client.search_certificates(first=1)


def test_revocation_verdict_attributes_the_description_to_the_vendor():
    # arrange
    certificate = {"fingerprint": "A" * 40, "revocation": {"status": "SUBMITTED", "reason": "KEY_COMPROMISE"}}

    # act
    _, description = revocation_verdict(certificate, "Example Product")

    # assert
    assert "submitted to the CA through Example Product" in description


def test_certificate_to_context_maps_both_revocation_blocks():
    # arrange
    certificate = {
        "fingerprint": "A" * 40,
        "revocation": {"status": "FAILED", "reason": "KEY_COMPROMISE", "error": {"message": "CA refused"}},
        "globalRevocation": {"status": "REVOKED", "reason": "KEY_COMPROMISED", "revokedTime": "2026-09-01T00:00:00Z"},
    }

    # act
    context = certificate_to_context(certificate, PRODUCT.brand)

    # assert
    assert context["Revocation"] == {"Status": "FAILED", "Reason": "KEY_COMPROMISE", "Error": "CA refused"}
    assert context["GlobalRevocation"] == {
        "Status": "REVOKED",
        "Reason": "KEY_COMPROMISED",
        "RevokedTime": "2026-09-01T00:00:00Z",
    }


@pytest.mark.parametrize(
    "case, certificate, expected",
    [
        ("maps the owning tsg", {"fingerprint": "A" * 40, "workspaceId": "1000000001"}, "1000000001"),
        ("omits a null tsg, as on cm saas", {"fingerprint": "A" * 40, "workspaceId": None}, None),
    ],
)
def test_certificate_to_context_tsg_id(case: str, certificate: dict, expected: str | None):
    # arrange / act
    context = certificate_to_context(certificate, PRODUCT.brand)

    # assert
    assert context.get("TSGID") == expected, case


def test_certificate_to_context_stamps_the_source_brand():
    # arrange
    certificate = {"fingerprint": "A" * 40}

    # act
    context = certificate_to_context(certificate, "SomeBrand")

    # assert
    assert context["SourceBrand"] == "SomeBrand"


def test_certificate_search_stamps_the_product_brand(requests_mock):
    # arrange
    client = BearerClient(base_url=BASE_URL, product=PRODUCT, verify=False, proxy=False)
    page = {"data": {"searchCertificates": {"pageInfo": {"hasNextPage": False}, "nodes": [{"fingerprint": "A" * 40}]}}}
    requests_mock.post(GRAPHQL_URL, json=page)

    # act
    result = certificate_search_command(client, {})

    # assert
    assert [output["SourceBrand"] for output in result.outputs] == ["ExampleProduct"]


def test_build_expiry_incident_puts_the_source_brand_and_fingerprint_in_raw_json():
    # arrange
    certificate = {"fingerprint": "A" * 40, "validity": {"to": "2026-10-01T00:00:00Z"}}

    # act
    incident = build_expiry_incident(certificate, 7, "Some Type", "ExampleProduct")

    # assert
    raw = json.loads(incident["rawJSON"])
    assert raw["SourceBrand"] == "ExampleProduct"
    assert raw["Fingerprint"] == "A" * 40


def test_build_expiry_incident_describes_the_crossing():
    # arrange
    certificate = {
        "fingerprint": "A" * 40,
        "subject": {"commonName": ["shop.example.com"]},
        "issuer": {"commonName": ["Example CA"]},
        "validity": {"to": "2026-10-01T00:00:00Z"},
    }

    # act
    incident = build_expiry_incident(certificate, 30, "Some Type", "ExampleProduct", now=datetime(2026, 9, 1, tzinfo=UTC))

    # assert
    assert incident["details"] == (
        f"Certificate shop.example.com (fingerprint {'A' * 40}), issued by Example CA, expires on "
        "2026-10-01T00:00:00Z - 30 day(s) left. It crossed the 30-day expiry threshold."
    ), "XSIAM shows details as the issue description"


def test_build_search_query_requests_the_owner_without_the_deprecated_field():
    # arrange / act
    query = build_search_query()

    # assert
    assert "workspaceId" in query
    assert "tsgId" not in query, "GraphQL tsgId is deprecated for workspaceId"


def test_certificate_readable_output_renders_installations_as_their_own_tables():
    # arrange
    context = {
        "Fingerprint": "A" * 40,
        "Installations": [
            {"MachineName": "Panorama 01", "Host": "panorama01.example.com", "PluginName": "Panorama", "Status": "VALIDATED"}
        ],
        "CloudInstallations": [
            {"KeystoreName": "prod-vault", "KeystoreType": "AZURE", "ProviderName": "Azure", "Status": "INSTALLED"}
        ],
    }

    # act
    readable = certificate_readable_output("Certificate A", context)

    # assert
    assert "{'" not in readable, "no raw Python dict in a table cell"
    assert "Machine installations" in readable
    assert "| Panorama 01 | panorama01.example.com | Panorama | VALIDATED |" in readable
    assert "| prod-vault | AZURE | Azure | INSTALLED |" in readable


@pytest.mark.parametrize(
    "case, instance, expected",
    [
        ("stamps the instance that ran the command", "ngts-workspace-a", "ngts-workspace-a"),
        ("omits it outside an integration instance", "", None),
    ],
)
def test_certificate_to_context_source_instance(case: str, instance: str, expected: str | None, mocker):
    # arrange
    mocker.patch.object(demisto, "integrationInstance", return_value=instance)

    # act
    context = certificate_to_context({"fingerprint": "A" * 40}, PRODUCT.brand)

    # assert
    assert context.get("SourceInstance") == expected, case


@pytest.mark.parametrize(
    "case, response, expected_message",
    [
        (
            "names the product when the CA returned no chain",
            {"status_code": 400, "json": {"errors": [{"code": 20602, "message": "Issuer certificates not available"}]}},
            "Example Product can't build the keystore",
        ),
        (
            "quotes every API message",
            {"status_code": 400, "json": {"errors": [{"code": 1, "message": "first"}, {"code": 2, "message": "second"}]}},
            r"\(HTTP 400\): first; second",
        ),
        (
            "uses the product message for a known status",
            {"status_code": 401, "json": {"errors": [{"message": "Unauthorized"}]}},
            "Example credential rejected.",
        ),
        ("falls back to the shared translation without an errors array", {"status_code": 500, "text": "boom"}, "HTTP 500: boom"),
    ],
)
def test_client_raise_keystore_error(
    case: str, response: dict, expected_message: str, client: CertificateManagerClient, requests_mock
):
    # arrange
    requests_mock.post(KEYSTORE_URL, **response)

    # act / assert
    with pytest.raises(Exception, match=expected_message):
        client.export_keystore("cert-1", {"exportFormat": "PEM"})


def test_seal_passphrase_round_trip():
    # arrange
    private_key = PrivateKey.generate()
    edge_key = {"keyAlgorithm": "ED25519", "key": base64.b64encode(bytes(private_key.public_key)).decode()}

    # act
    sealed = seal_passphrase("dummy-passphrase", edge_key)

    # assert
    assert SealedBox(private_key).decrypt(base64.b64decode(sealed)) == b"dummy-passphrase"


def p384_key_pair() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    private_key = ec.generate_private_key(ec.SECP384R1())
    public = private_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return private_key, public


HPKE_SUITE = hpke.Suite(hpke.KEM.P384, hpke.KDF.HKDF_SHA512, hpke.AEAD.AES_256_GCM)


def test_hpke_seal_matches_an_independent_hpke_implementation():
    # arrange
    private_key, public = p384_key_pair()

    # act
    sealed = hpke_seal(public, info=b"company-1", aad=b"", plaintext=b"dummy-passphrase")

    # assert
    # cryptography's HPKE takes no associated data, so it can check the key exchange and key schedule only with an empty one.
    assert HPKE_SUITE.decrypt(sealed, private_key, info=b"company-1") == b"dummy-passphrase"
    assert len(sealed) == 97 + len(b"dummy-passphrase") + 16, "enc, then the ciphertext and its tag"


def test_hpke_seal_binds_the_associated_data():
    # arrange
    private_key, public = p384_key_pair()

    # act
    sealed = hpke_seal(public, info=b"company-1", aad=b"company-1", plaintext=b"dummy-passphrase")

    # assert
    with pytest.raises(InvalidTag):
        HPKE_SUITE.decrypt(sealed, private_key, info=b"company-1")


def test_seal_passphrase_uses_hpke_with_the_company_id_for_a_vsat_hpke_key(mocker):
    # arrange
    _, public = p384_key_pair()
    edge_key = {"keyAlgorithm": "VSAT_HPKE", "key": base64.b64encode(public).decode(), "companyId": "company-1"}
    seal = mocker.patch("CertificateManagerSaaSApiModule.hpke_seal", return_value=b"sealed")

    # act
    sealed = seal_passphrase("dummy-passphrase", edge_key)

    # assert
    seal.assert_called_once_with(public, info=b"company-1", aad=b"company-1", plaintext=b"dummy-passphrase")
    assert sealed == base64.b64encode(b"sealed").decode()


@pytest.mark.parametrize(
    "case, algorithm, supported",
    [
        ("accepts an ED25519 key", "ED25519", True),
        ("accepts the VSAT_HPKE key of a current VSatellite", "VSAT_HPKE", True),
        ("rejects another key type", "RSA", False),
    ],
)
def test_edge_encryption_key(case: str, algorithm: str, supported: bool, client: CertificateManagerClient, mocker):
    # arrange
    mocker.patch.object(client, "get_edge_encryption_key", return_value={"keyAlgorithm": algorithm, "key": "a2V5"})

    # act / assert
    if supported:
        assert edge_encryption_key(client, "cert-1", "dek-1")["keyAlgorithm"] == algorithm, case
    else:
        with pytest.raises(DemistoException, match="only ED25519 and VSAT_HPKE keys are"):
            edge_encryption_key(client, "cert-1", "dek-1")


def test_graphql_read_asks_for_retries_on_throttling_and_server_errors(client: CertificateManagerClient, mocker):
    # arrange
    http_request = mocker.patch.object(client, "_http_request", return_value={"data": {"searchCertificates": {}}})

    # act
    client.search_certificates(first=1)

    # assert
    assert http_request.call_args.kwargs["retries"] == READ_RETRIES
    assert http_request.call_args.kwargs["status_list_to_retry"] == RETRY_STATUSES


def test_revoke_is_never_retried_even_after_a_retrying_read(client: CertificateManagerClient, mocker):
    # arrange
    http_request = mocker.patch.object(client, "_http_request", return_value={"data": {"revokeCertificate": None}})
    reset = mocker.patch.object(client, "_implement_retry")
    client.search_certificates(first=1)

    # act
    client.revoke_certificate("A" * 40, "KEY_COMPROMISE", None)

    # assert
    reset.assert_called_once_with(retries=0)
    assert http_request.call_args.kwargs["retries"] == 0
    assert http_request.call_args.kwargs["status_list_to_retry"] is None


def test_certificate_command_scores_zero_for_a_valid_fingerprint_the_tenant_does_not_return(
    client: CertificateManagerClient, requests_mock
):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=EMPTY_SEARCH)

    # act
    results = certificate_command(client, {"certificate": f"{'B' * 40},not-a-fingerprint"}, "A - Completely reliable")

    # assert
    indicator = results[0].indicator
    assert indicator.dbot_score.score == Common.DBotScore.NONE
    assert indicator.dbot_score.integration_name == PRODUCT.name, "same vendor as a certificate that was found"
    assert indicator.sha1 == "b" * 40
    assert [entry["Fingerprint"] for entry in results[-1].outputs] == ["not-a-fingerprint", "B" * 40]
    assert all(result.indicator is None for result in results[1:]), "a value that isn't a fingerprint gets no score"


def test_enrich_installations_with_hosts_skips_a_machine_it_cannot_read(client: CertificateManagerClient, mocker):
    # arrange
    machines = {"m-ok": {"connectionDetails": {"hostnameOrAddress": "lb01.example.com"}}}

    def get_machine(machine_id: str) -> dict:
        if machine_id not in machines:
            raise DemistoException("Not found (HTTP 404).")
        return machines[machine_id]

    mocker.patch.object(client, "get_machine", side_effect=get_machine)

    # act
    enriched = enrich_installations_with_hosts(client, [{"MachineID": "m-gone"}, {"MachineID": "m-ok"}])

    # assert
    assert enriched == [{"MachineID": "m-gone"}, {"MachineID": "m-ok", "Host": "lb01.example.com"}]


def test_enrich_installations_with_hosts_caps_the_machine_lookups(client: CertificateManagerClient, mocker):
    # arrange
    get_machine = mocker.patch.object(client, "get_machine", return_value={"connectionDetails": {}})
    installations = [{"MachineID": f"m-{index}"} for index in range(MAX_HOST_LOOKUPS + 5)]

    # act
    enriched = enrich_installations_with_hosts(client, installations)

    # assert
    assert get_machine.call_count == MAX_HOST_LOOKUPS
    assert len(enriched) == len(installations), "installations past the cap stay, without a host"


@pytest.mark.parametrize(
    "case, status",
    [
        ("names a revocation waiting for approval", "PENDING_APPROVAL"),
        ("names a submitted revocation", "SUBMITTED"),
    ],
)
def test_certificate_revoke_title_shows_the_revocation_status(
    case: str, status: str, client: CertificateManagerClient, requests_mock
):
    # arrange
    certificate = {"fingerprint": KNOWN_FINGERPRINT, "revocation": {"status": status, "reason": "KEY_COMPROMISE"}}
    requests_mock.post(GRAPHQL_URL, json={"data": {"revokeCertificate": certificate}})

    # act
    result = certificate_revoke_command(client, {"fingerprint": KNOWN_FINGERPRINT, "reason": "KEY_COMPROMISE"})

    # assert
    assert result.readable_output.startswith(f"### Revocation of certificate {KNOWN_FINGERPRINT}: {status}"), case


def test_certificate_search_filters_the_expiry_server_side(client: CertificateManagerClient, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=EMPTY_SEARCH)

    # act
    certificate_search_command(client, {"expires_in_days": "30"})

    # assert
    sent_query = requests_mock.last_request.json()["query"]
    assert "filterOn: {and: [{validityTo: {between: {lte: " in sent_query
    assert "gte" not in sent_query, "already expired certificates still match, as before"


def failed_revocation_node(fingerprint: str) -> dict[str, Any]:
    return {"fingerprint": fingerprint, "revocation": {"status": "FAILED", "reason": "KEY_COMPROMISE"}}


def test_revocation_failed_incidents_stay_within_the_budget(client: CertificateManagerClient, requests_mock):
    # arrange
    nodes = [failed_revocation_node(fingerprint) for fingerprint in ("A" * 40, "B" * 40, "C" * 40)]
    requests_mock.post(GRAPHQL_URL, json={"data": {"searchCertificates": {"pageInfo": {"hasNextPage": False}, "nodes": nodes}}})

    # act
    incidents, raised = revocation_failed_incidents(client, raised_before=["A" * 40], budget=1)

    # assert
    assert [incident["dedup_id"] for incident in incidents] == [f"{'B' * 40}:revocation-failed"]
    assert raised == ["A" * 40, "B" * 40], "C waits for the next fetch, so it is not marked as raised"


def test_revocation_failed_incidents_keep_the_previous_state_when_the_query_fails(
    client: CertificateManagerClient, requests_mock
):
    # arrange
    requests_mock.post(GRAPHQL_URL, status_code=400, text="bad request")

    # act
    incidents, raised = revocation_failed_incidents(client, raised_before=["A" * 40], budget=10)

    # assert
    assert incidents == []
    assert raised == ["A" * 40]


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


""" SHA-1 FINGERPRINTS """


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


def expiry_page(*nodes: dict) -> dict:
    return {"data": {"searchCertificates": {"pageInfo": {"hasNextPage": False}, "nodes": list(nodes)}}}


def expiring_certificate(fingerprint: str, expires: datetime) -> dict:
    return {
        "fingerprint": fingerprint,
        "subject": {"commonName": [f"{fingerprint[:4].lower()}.example.com"]},
        "validity": {"to": expires.strftime("%Y-%m-%dT%H:%M:%SZ")},
    }


def raised_fingerprints(incidents: list[dict]) -> list[str]:
    return [json.loads(incident["rawJSON"])["Fingerprint"] for incident in incidents]


def test_fetch_incidents_raises_the_most_severe_threshold_each_certificate_has_crossed(
    client: CertificateManagerClient, requests_mock
):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))

    # act
    incidents, next_run = fetch_incidents(client, {}, {}, now=NOW)

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
    ], "crit.example.com is past both thresholds, so only the Critical one is raised"
    assert [json.loads(incident["rawJSON"])["CrossedThresholdDays"] for incident in incidents] == [30, 7, 30]
    assert {incident["type"] for incident in incidents} == {EXPIRY_TYPE}
    assert {json.loads(incident["rawJSON"])["IssueType"] for incident in incidents} == {EXPIRY_TYPE}, (
        "the Common pack classifier types the issue from this key; XSIAM ignores the incident's type"
    )
    assert next_run["raised_expiry_thresholds"] == {"B" * 40: 30, "A" * 40: 7, "C" * 40: 30}


@pytest.mark.parametrize(
    "case, days_left, expected_threshold",
    [
        ("first seen with 5 days left, it still gets the Critical incident", 5, 7),
        ("first seen with 20 days left, it gets the High incident at once", 20, 30),
    ],
)
def test_fetch_incidents_raises_a_certificate_first_seen_inside_the_window(
    case: str, days_left: int, expected_threshold: int, client: CertificateManagerClient, requests_mock
):
    # arrange
    certificate = expiring_certificate("E" * 40, NOW + timedelta(days=days_left))
    requests_mock.post(GRAPHQL_URL, json=expiry_page(certificate))

    # act
    incidents, _ = fetch_incidents(client, {}, {}, now=NOW)

    # assert
    assert [json.loads(incident["rawJSON"])["CrossedThresholdDays"] for incident in incidents] == [expected_threshold], case


def test_fetch_incidents_does_not_raise_a_threshold_again(client: CertificateManagerClient, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))
    _, next_run = fetch_incidents(client, {}, {}, now=NOW)

    # act
    incidents, _ = fetch_incidents(client, {}, next_run, now=NOW + timedelta(days=3))

    # assert
    assert incidents == [], "the state never expires while the certificate stays in the window"


def test_fetch_incidents_raises_the_next_threshold_when_it_is_crossed(client: CertificateManagerClient, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=expiry_page(expiring_certificate("B" * 40, datetime(2026, 10, 15, tzinfo=UTC))))
    first, next_run = fetch_incidents(client, {}, {}, now=NOW)

    # act
    second, _ = fetch_incidents(client, {}, next_run, now=datetime(2026, 10, 10, tzinfo=UTC))

    # assert
    assert [incident["severity"] for incident in first + second] == [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]
    assert second[0]["occurred"] == "2026-10-08T00:00:00Z"


def test_fetch_incidents_defers_incidents_past_the_maximum_to_the_next_fetch(client: CertificateManagerClient, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))

    # act
    first, next_run = fetch_incidents(client, {"max_fetch": "1"}, {}, now=NOW)
    second, _ = fetch_incidents(client, {"max_fetch": "1"}, next_run, now=NOW)

    # assert
    assert raised_fingerprints(first) == ["B" * 40], "the oldest crossing comes first"
    assert next_run["raised_expiry_thresholds"] == {"B" * 40: 30}, "a deferred certificate is not marked as raised"
    assert raised_fingerprints(second) == ["A" * 40]


def test_fetch_incidents_drops_a_certificate_without_a_usable_expiry_date(client: CertificateManagerClient, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))

    # act
    incidents, next_run = fetch_incidents(client, {}, {}, now=NOW)

    # assert
    assert "D" * 40 not in raised_fingerprints(incidents)
    assert "D" * 40 not in next_run["raised_expiry_thresholds"]


def test_fetch_incidents_uses_the_server_side_expiry_filter(client: CertificateManagerClient, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))

    # act
    fetch_incidents(client, {"fetch_expiry_days": "45"}, {}, now=NOW)

    # assert
    sent_query = requests_mock.request_history[0].json()["query"]
    assert 'validityTo: {between: {gte: "2026-09-23T00:00:00Z", lte: "2026-11-07T00:00:00Z"}}' in sent_query
    # Only the current, active version: a renewed (replaced) or retired certificate must not raise expiry issues.
    assert "isCurrent: {eq: true}" in sent_query
    assert "status: {eq: ACTIVE}" in sent_query, "an enum filter value must be bare, not quoted"


@pytest.mark.parametrize(
    "case, truncated, expected",
    [
        ("forgets a certificate that left the window", False, {"A" * 40: 7, "B" * 40: 30}),
        ("keeps it when the page walk was cut short", True, {"A" * 40: 7, "B" * 40: 30, "F" * 40: 7}),
    ],
)
def test_updated_expiry_state(case: str, truncated: bool, expected: dict):
    # arrange
    raised = {"A" * 40: 7, "F" * 40: 7}
    certificates = [{"fingerprint": "A" * 40}, {"fingerprint": "B" * 40}]
    incidents = [{"dedup_id": f"{'B' * 40}:30"}]

    # act
    state = updated_expiry_state(raised, certificates, incidents, truncated)

    # assert
    assert state == expected, case


def test_fetch_incidents_raises_a_high_issue_for_a_failed_key_compromise_revocation(
    client: CertificateManagerClient, requests_mock
):
    # arrange
    route_fetch_queries(requests_mock, failed_revocations_page(("D" * 40, "KEY_COMPROMISE"), ("E" * 40, "SUPERSEDED")))

    # act
    incidents, last_run = fetch_incidents(client, {}, {}, now=NOW)

    # assert
    failures = [incident for incident in incidents if incident["type"] == "CertManagerSaaS Revocation Failed"]
    assert [incident["name"] for incident in failures] == ["Key-compromise revocation failed: dddd.example.com"]
    assert failures[0]["severity"] == IncidentSeverity.HIGH
    assert json.loads(failures[0]["rawJSON"])["IssueType"] == "CertManagerSaaS Revocation Failed"
    assert "CA refused the request" in failures[0]["details"], "the analyst sees why the CA refused"
    assert "revocationStatus: {eq: FAILED}" in requests_mock.last_request.json()["query"], "an enum value must not be quoted"
    assert last_run["raised_revocation_failures"] == ["D" * 40], "only key-compromise failures are tracked"


@pytest.mark.parametrize(
    "case, raised_before, expected",
    [
        ("does not raise the same failure twice", ["D" * 40], []),
        ("raises again after the certificate left the failed state", [], ["D" * 40]),
    ],
)
def test_fetch_incidents_deduplicates_failed_revocations_by_state(
    case, raised_before, expected, client: CertificateManagerClient, requests_mock
):
    # arrange
    route_fetch_queries(requests_mock, failed_revocations_page(("D" * 40, "KEY_COMPROMISE")))

    # act
    incidents, _ = fetch_incidents(client, {}, {"raised_revocation_failures": raised_before}, now=NOW)

    # assert
    failures = [incident for incident in incidents if incident["type"] == "CertManagerSaaS Revocation Failed"]
    assert raised_fingerprints(failures) == expected, case


def test_fetch_incidents_leaves_failed_revocations_beyond_the_maximum_for_the_next_fetch(
    client: CertificateManagerClient, requests_mock
):
    # arrange
    route_fetch_queries(requests_mock, failed_revocations_page(("D" * 40, "KEY_COMPROMISE")))

    # act
    incidents, next_run = fetch_incidents(client, {"max_fetch": "3"}, {}, now=NOW)

    # assert
    assert len(incidents) == 3, "the three expiry incidents use the whole budget"
    assert next_run["raised_revocation_failures"] == []


@pytest.mark.parametrize(
    "case, params, expected_issue_type",
    [
        ("defaults to the pack's expiry type", {}, EXPIRY_TYPE),
        ("carries a custom type chosen on the instance", {"incidentType": "Custom Expiry"}, "Custom Expiry"),
    ],
)
def test_fetch_incidents_writes_the_issue_type_for_the_classifier(
    case, params, expected_issue_type, client: CertificateManagerClient, requests_mock
):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("fetch_certificates_page.json"))

    # act
    incidents, _ = fetch_incidents(client, params, {}, now=NOW)

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


""" REVOCATION VERDICT """


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
