"""Unit tests for CertificateManagerSaaSApiModule.

The integrations' own suites exercise the shared commands end to end; these cover the seam the
module exposes to them - the client base, its authentication hook and the product profile.
"""

import base64
import json
from typing import Any

import demistomock as demisto
import pytest
from nacl.public import PrivateKey, SealedBox

from CertificateManagerSaaSApiModule import (
    CertificateManagerClient,
    GraphQLQueryError,
    ProductProfile,
    seal_passphrase,
    build_search_query,
    build_expiry_incident,
    certificate_readable_output,
    certificate_search_command,
    certificate_to_context,
    revocation_verdict,
)

BASE_URL = "https://api.example.test"
GRAPHQL_URL = f"{BASE_URL}/graphql"
PRODUCT = ProductProfile(
    name="Example Product",
    brand="ExampleProduct",
    user_agent="unit-test-agent",
    http_error_messages={401: "Example credential rejected."},
)
EMPTY_SEARCH = {"data": {"searchCertificates": {"totalCount": 0, "pageInfo": {"hasNextPage": False}, "nodes": []}}}


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
    incident = build_expiry_incident(certificate, 30, "Some Type", "ExampleProduct")

    # assert
    assert "shop.example.com" in incident["details"], "XSIAM shows details as the issue description"
    assert "Example CA" in incident["details"]
    assert "30-day expiry threshold" in incident["details"]


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
def test_certificate_to_context_source_instance(case: str, instance: str, expected: str | None, monkeypatch):
    # arrange
    monkeypatch.setattr(demisto, "integrationInstance", lambda: instance)

    # act
    context = certificate_to_context({"fingerprint": "A" * 40}, PRODUCT.brand)

    # assert
    assert context.get("SourceInstance") == expected, case


KEYSTORE_URL = f"{BASE_URL}/outagedetection/v1/certificates/cert-1/keystore"


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

    # act
    sealed = seal_passphrase("dummy-passphrase", base64.b64encode(bytes(private_key.public_key)).decode())

    # assert
    assert SealedBox(private_key).decrypt(base64.b64decode(sealed)) == b"dummy-passphrase"
