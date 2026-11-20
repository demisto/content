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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from nacl.public import PrivateKey, SealedBox

from CertificateManagerSaaS import (
    DemistoException,
    build_keystore_request_body,
    certificate_keystore_download_command,
    keystore_base_name,
    keystore_passphrase,
    unpack_pem_keystore,
    Client,
    Common,
    GraphQLQueryError,
    application_list_command,
    build_search_predicate,
    certificate_command,
    certificate_download_command,
    certificate_get_command,
    certificate_list_expiring_command,
    certificate_request_command,
    certificate_request_status_command,
    certificate_revoke_command,
    certificate_search_command,
    collect_certificates,
    days_until_expiry,
    fetch_incidents,
    machine_get_command,
    machine_list_command,
    PACK_VERSION,
    test_module as run_test_module,
    threshold_alignment_message,
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


def test_certificate_command_scores_zero_for_a_fingerprint_the_tenant_does_not_know(client: Client, requests_mock):
    # arrange
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_empty.json"))
    unknown = "F" * 64

    # act
    results = certificate_command(client, {"certificate": unknown}, RELIABILITY)

    # assert
    assert len(results) == 2
    indicator = results[0].indicator
    assert indicator.dbot_score.score == Common.DBotScore.NONE
    assert indicator.dbot_score.integration_name == "Certificate Manager SaaS"
    assert indicator.sha256 == unknown.lower()
    assert results[1].outputs == [
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
    assert f'filterOn: {{and: [{{fingerprint: {{eq: "{KNOWN_FINGERPRINT}"}}}}]}}' in sent_query


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


def test_certificate_keystore_download_seals_for_the_hpke_key_of_a_current_vsatellite(
    client: Client, requests_mock, monkeypatch, tmp_path, edge_private_key: PrivateKey
):
    # arrange
    monkeypatch.chdir(tmp_path)  # fileResult writes into the working directory
    keystore_mock = mock_keystore_api(requests_mock, edge_private_key, pem_keystore_zip())
    p384 = ec.generate_private_key(ec.SECP384R1()).public_key()
    point = p384.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    hpke_key = {"key": base64.b64encode(point).decode(), "keyAlgorithm": "VSAT_HPKE", "companyId": "company-1"}
    requests_mock.get(EDGE_KEY_URL, json=hpke_key)

    # act
    key_entry, _, _ = certificate_keystore_download_command(client, {"certificate_id": CERTIFICATE_ID, "passphrase": PASSPHRASE})

    # assert
    assert written_file(tmp_path, key_entry) == ENCRYPTED_KEY
    sealed = base64.b64decode(keystore_mock.last_request.json()["encryptedPrivateKeyPassphrase"])
    assert len(sealed) == 97 + len(PASSPHRASE) + 16, "the HPKE encapsulated key, then the ciphertext and its tag"
    assert PASSPHRASE not in keystore_mock.last_request.text, "the passphrase never travels in clear"


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
            {"json": {"key": "AAAA", "keyAlgorithm": "RSA"}},
            None,
            "type RSA. Downloading it is not supported yet",
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
