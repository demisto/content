import base64
import copy
import json
import os
from datetime import datetime
from urllib.parse import parse_qs

import demistomock as demisto
import NextGenTrustSecurity
import pytest
from freezegun import freeze_time
from nacl.public import PrivateKey, SealedBox

from NextGenTrustSecurity import (
    DEFAULT_BASE_URL,
    DEFAULT_TOKEN_URL,
    PACK_VERSION,
    TOKEN_CACHE_CONTEXT_KEY,
    Client,
    OAuthSettings,
    build_client,
    certificate_command,
    certificate_download_command,
    certificate_keystore_download_command,
    certificate_get_command,
    certificate_list_expiring_command,
    certificate_request_command,
    certificate_request_status_command,
    certificate_revoke_command,
    certificate_search_command,
    fetch_incidents,
    machine_get_command,
    machine_list_command,
    test_module as run_test_module,
    threshold_alignment_message,
    thresholds_from_configuration,
    token_cache_key,
    web_filter_message,
    error_message,
)

BASE_URL = "https://api.ngts.example.test/ngts"
TOKEN_URL = "https://auth.ngts.example.test/auth/v1/oauth2/access_token"
GRAPHQL_URL = f"{BASE_URL}/graphql"
THRESHOLDS_URL = f"{BASE_URL}/outagedetection/v1/inventorymonitoringconfig/CERTIFICATE_EXPIRATION"
USER_ACCOUNTS_URL = f"{BASE_URL}/v1/useraccounts"
CLIENT_ID = "svc@1000000001.iam.panserviceaccount.com"
CLIENT_SECRET = "dummy-client-secret"
TSG_ID = "1000000001"
FINGERPRINT = "C1D2E3F405162738495A6B7C8D9EAFB0C1D2E3F4"
RELIABILITY = "C - Fairly reliable"
BRAND = "NextGenTrustSecurity"
FROZEN_NOW = "2026-09-24T00:00:00Z"
CERTIFICATE_ID = "5c1e8a40-b79e-11f1-aaca-000000000001"
CONTENTS_URL = f"{BASE_URL}/outagedetection/v1/certificates/{CERTIFICATE_ID}/contents"
CERTIFICATE_REQUESTS_URL = f"{BASE_URL}/outagedetection/v1/certificaterequests"
REQUEST_ID = "7d3f1a20-2222-11ef-9a11-0242ac120002"
MACHINES_URL = f"{BASE_URL}/v1/machines"
MACHINE_ID = "mach-0001"
PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


def util_load_json(name: str) -> dict:
    path = os.path.join(os.path.dirname(__file__), "test_data", name)
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def token_response(access_token: str, expires_in: int = 899) -> dict:
    return {"access_token": access_token, "token_type": "Bearer", "scope": f"tsg_id:{TSG_ID}", "expires_in": expires_in}


def oauth(client_id: str = CLIENT_ID, client_secret: str = CLIENT_SECRET, token_url: str = TOKEN_URL) -> OAuthSettings:
    return OAuthSettings(token_url=token_url, client_id=client_id, client_secret=client_secret, tsg_id=TSG_ID)


def seed_cached_token(access_token: str, valid_until: float = 4_102_444_800.0) -> None:
    """Put a still-valid token for the default configuration into the integration context."""
    entry = {"cache_key": token_cache_key(oauth(), BASE_URL), "access_token": access_token, "valid_until": valid_until}
    demisto.setIntegrationContext({TOKEN_CACHE_CONTEXT_KEY: entry})


def search_node() -> dict:
    return copy.deepcopy(util_load_json("search_certificates_page.json")["data"]["searchCertificates"]["nodes"][0])


@pytest.fixture(autouse=True)
def integration_context():
    # demistomock keeps the integration context in a module global; start and end every test empty.
    demisto.setIntegrationContext({})
    yield
    demisto.setIntegrationContext({})


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, oauth=oauth(), verify=False, proxy=False)


""" TOKEN """


def test_client_requests_a_token_with_basic_auth_and_the_tsg_scope(client: Client, requests_mock):
    # arrange
    token_mock = requests_mock.post(TOKEN_URL, json=util_load_json("token.json"))
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    client.search_certificates(first=1)

    # assert
    token_request = token_mock.last_request
    assert token_request.headers["Authorization"].startswith("Basic ")
    assert token_request.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert parse_qs(token_request.text) == {"grant_type": ["client_credentials"], "scope": [f"tsg_id:{TSG_ID}"]}
    assert requests_mock.last_request.headers["Authorization"] == "Bearer dummy-access-token-1"


def test_client_reuses_the_cached_token_across_requests_and_instances(client: Client, requests_mock):
    # arrange
    token_mock = requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))
    second_client = Client(base_url=BASE_URL, oauth=oauth(), verify=False, proxy=False)

    # act
    client.search_certificates(first=1)
    client.search_certificates(first=1)
    second_client.search_certificates(first=1)

    # assert
    assert token_mock.call_count == 1, "the token must come from the integration context after the first request"
    assert requests_mock.last_request.headers["Authorization"] == "Bearer token-a"


def test_client_refreshes_the_token_a_minute_before_it_expires(client: Client, requests_mock):
    # arrange
    token_mock = requests_mock.post(TOKEN_URL, [{"json": token_response("token-a")}, {"json": token_response("token-b")}])
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    with freeze_time("2026-09-24T10:00:00Z") as frozen:
        client.search_certificates(first=1)
        frozen.tick(899 - 61)
        client.search_certificates(first=1)
        still_cached_calls = token_mock.call_count
        frozen.tick(2)
        client.search_certificates(first=1)

    # assert
    assert still_cached_calls == 1, "a token with more than the margin left is reused"
    assert token_mock.call_count == 2, "a token inside the last minute of its life is replaced"
    assert requests_mock.last_request.headers["Authorization"] == "Bearer token-b"


def test_client_ignores_a_token_cached_for_another_service_account(requests_mock):
    # arrange
    token_mock = requests_mock.post(TOKEN_URL, [{"json": token_response("token-a")}, {"json": token_response("token-b")}])
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))
    Client(base_url=BASE_URL, oauth=oauth("first@example"), verify=False, proxy=False).search_certificates(first=1)

    # act
    Client(base_url=BASE_URL, oauth=oauth("second@example"), verify=False, proxy=False).search_certificates(first=1)

    # assert
    assert token_mock.call_count == 2
    assert requests_mock.last_request.headers["Authorization"] == "Bearer token-b"


def test_client_keeps_other_integration_context_keys(client: Client, requests_mock):
    # arrange
    demisto.setIntegrationContext({"unrelated": "value"})
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    client.search_certificates(first=1)

    # assert
    context = demisto.getIntegrationContext()
    assert context["unrelated"] == "value"
    assert context[TOKEN_CACHE_CONTEXT_KEY]["access_token"] == "token-a"


def test_client_retries_once_with_a_fresh_token_after_a_401(client: Client, requests_mock):
    # arrange
    seed_cached_token("stale")
    token_mock = requests_mock.post(TOKEN_URL, json=token_response("fresh"))
    search_mock = requests_mock.post(
        GRAPHQL_URL, [{"status_code": 401, "json": {}}, {"json": util_load_json("search_certificates_page.json")}]
    )

    # act
    page = client.search_certificates(first=1)

    # assert
    assert page["totalCount"] == 1
    assert token_mock.call_count == 1
    assert [request.headers["Authorization"] for request in search_mock.request_history] == ["Bearer stale", "Bearer fresh"]
    assert demisto.getIntegrationContext()[TOKEN_CACHE_CONTEXT_KEY]["access_token"] == "fresh"


def test_client_reports_a_second_401_without_retrying_again(client: Client, requests_mock):
    # arrange
    seed_cached_token("stale")
    token_mock = requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    search_mock = requests_mock.post(GRAPHQL_URL, status_code=401, json={})

    # act / assert
    with pytest.raises(Exception, match="rejected a freshly issued access token"):
        client.search_certificates(first=1)
    assert search_mock.call_count == 2
    assert token_mock.call_count == 1


def test_client_does_not_retry_a_401_on_a_token_it_just_minted(client: Client, requests_mock):
    # arrange
    token_mock = requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    search_mock = requests_mock.post(GRAPHQL_URL, status_code=401, json={})

    # act / assert
    with pytest.raises(Exception, match="rejected a freshly issued access token"):
        client.search_certificates(first=1)
    assert search_mock.call_count == 1, "a brand-new token being rejected is a real rejection, not staleness"
    assert token_mock.call_count == 1


def test_client_retries_a_401_on_a_token_it_minted_earlier_in_the_run(client: Client, requests_mock):
    # arrange
    token_mock = requests_mock.post(TOKEN_URL, [{"json": token_response("token-a")}, {"json": token_response("token-b")}])
    search_mock = requests_mock.post(
        GRAPHQL_URL,
        [
            {"json": util_load_json("search_certificates_page.json")},
            {"status_code": 401, "json": {}},
            {"json": util_load_json("search_certificates_page.json")},
        ],
    )

    # act
    with freeze_time(FROZEN_NOW) as frozen:
        client.search_certificates(first=1)
        frozen.tick(120)
        client.search_certificates(first=1)

    # assert
    assert token_mock.call_count == 2
    assert [request.headers["Authorization"] for request in search_mock.request_history] == [
        "Bearer token-a",
        "Bearer token-a",
        "Bearer token-b",
    ]


def test_client_touches_the_integration_context_once_per_run(client: Client, requests_mock, monkeypatch):
    # arrange
    reads: list[int] = []
    writes: list[dict] = []
    real_get = NextGenTrustSecurity.get_integration_context
    real_set = NextGenTrustSecurity.set_integration_context
    monkeypatch.setattr(NextGenTrustSecurity, "get_integration_context", lambda *a, **k: reads.append(1) or real_get(*a, **k))
    monkeypatch.setattr(
        NextGenTrustSecurity,
        "set_integration_context",
        lambda context, *a, **k: writes.append(context) or real_set(context, *a, **k),
    )
    token_mock = requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    for _ in range(3):
        client.search_certificates(first=1)

    # assert
    assert token_mock.call_count == 1
    assert len(reads) == 1, "the context is read on first need only"
    assert len(writes) == 1, "the context is written only when a token is minted"


def test_client_does_not_write_the_context_when_the_cached_token_is_used(client: Client, requests_mock, monkeypatch):
    # arrange
    seed_cached_token("cached")
    writes: list[dict] = []
    monkeypatch.setattr(NextGenTrustSecurity, "set_integration_context", lambda context, *a, **k: writes.append(context))
    token_mock = requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    client.search_certificates(first=1)
    client.search_certificates(first=1)

    # assert
    assert not token_mock.called
    assert writes == []
    assert requests_mock.last_request.headers["Authorization"] == "Bearer cached"


@freeze_time(FROZEN_NOW)
def test_client_caches_a_token_without_expires_in_for_a_conservative_lifetime(client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json={"access_token": "token-a", "token_type": "Bearer"})
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    client.search_certificates(first=1)

    # assert
    entry = demisto.getIntegrationContext()[TOKEN_CACHE_CONTEXT_KEY]
    now = datetime.fromisoformat(FROZEN_NOW).timestamp()
    assert entry["valid_until"] == now + 600 - 60


@pytest.mark.parametrize(
    "case, second_oauth, second_server_url",
    [
        ("a rotated client secret", {"client_secret": "another-dummy-secret"}, BASE_URL),
        ("another token url", {"token_url": "https://auth.other.example.test/token"}, BASE_URL),
        ("another server url", {}, "https://api.other.example.test/ngts"),
    ],
)
def test_client_misses_the_cache_when_the_configuration_changes(
    case: str, second_oauth: dict, second_server_url: str, requests_mock
):
    # arrange
    token_urls = {TOKEN_URL, second_oauth.get("token_url", TOKEN_URL)}
    token_mocks = [
        requests_mock.post(url, [{"json": token_response("token-a")}, {"json": token_response("token-b")}]) for url in token_urls
    ]
    for server_url in {BASE_URL, second_server_url}:
        requests_mock.post(f"{server_url}/graphql", json=util_load_json("search_certificates_page.json"))
    Client(base_url=BASE_URL, oauth=oauth(), verify=False, proxy=False).search_certificates(first=1)

    # act
    Client(base_url=second_server_url, oauth=oauth(**second_oauth), verify=False, proxy=False).search_certificates(first=1)

    # assert
    assert sum(mock.call_count for mock in token_mocks) == 2, case


def test_token_cache_key_never_contains_the_client_secret(client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    client.search_certificates(first=1)

    # assert
    cache_key = demisto.getIntegrationContext()[TOKEN_CACHE_CONTEXT_KEY]["cache_key"]
    assert CLIENT_SECRET not in cache_key
    assert cache_key.startswith(f"{CLIENT_ID}:{TSG_ID}:")


@pytest.mark.parametrize(
    "case, token_mock_kwargs, expected_message",
    [
        (
            "explains rejected client credentials",
            {"status_code": 401, "json": {"error": "invalid_client"}},
            "rejected the client",
        ),
        ("rejects a response without a token", {"json": {"token_type": "Bearer"}}, "without an access token"),
    ],
)
def test_client_token_failures(case: str, token_mock_kwargs: dict, expected_message: str, client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, **token_mock_kwargs)
    graphql_mock = requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act / assert
    with pytest.raises(Exception, match=expected_message):
        client.search_certificates(first=1)
    assert not graphql_mock.called, case


def test_oauth_settings_keep_the_client_secret_out_of_repr():
    # arrange / act
    text = repr(oauth())

    # assert
    assert CLIENT_SECRET not in text
    assert CLIENT_ID in text


""" REQUESTS """


def test_client_identifies_itself_and_sends_no_api_key_header(client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    client.search_certificates(first=1)

    # assert
    headers = requests_mock.last_request.headers
    assert headers["User-Agent"] == f"CortexXSOAR-NextGenTrustSecurity/{PACK_VERSION}"
    assert "tppl-api-key" not in headers
    assert requests_mock.request_history[0].headers["User-Agent"] == headers["User-Agent"], "the token call identifies too"


def test_client_explains_a_403_as_a_missing_permission(client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    requests_mock.post(GRAPHQL_URL, status_code=403, json={"_errors": [{"code": "AUTHZ_DENIED"}]})

    # act / assert
    with pytest.raises(Exception, match="role does not permit this operation"):
        client.search_certificates(first=1)


@pytest.mark.parametrize(
    "case, headers",
    [
        ("recognises the html page", {"Content-Type": "text/html"}),
        ("recognises the gateway header alone", {"x-request-flow-error": "DEF_403"}),
    ],
)
def test_client_explains_a_web_filter_403(case: str, headers: dict, client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    requests_mock.post(GRAPHQL_URL, status_code=403, text="403 Forbidden", headers=headers)

    # act / assert
    with pytest.raises(NextGenTrustSecurity.WebFilterBlockedError, match="security filter blocked it"):
        client.revoke_certificate("A" * 40, "KEY_COMPROMISE", "Revoked in Cortex case 123")


@pytest.mark.parametrize(
    "case, args, expected",
    [
        (
            "quotes the revocation comment",
            {"fingerprint": "A" * 40, "comment": "Revoked in Cortex case 123"},
            'because of the text in "comment" ("Revoked in Cortex case 123")',
        ),
        (
            "quotes every free-text argument supplied",
            {"common_name": "shop.example.com", "sans": "a.example.com", "organization": ""},
            '"common_name" ("shop.example.com"), "sans" ("a.example.com")',
        ),
        ("falls back when no free text was supplied", {"fingerprint": "A" * 40}, "looked like an attack"),
    ],
)
def test_web_filter_message(case: str, args: dict, expected: str):
    # act
    message = web_filter_message(args)

    # assert
    assert expected in message, case
    assert "Strata Cloud Manager gateway's security filter" in message
    assert "not a permission problem" in message


@pytest.mark.parametrize(
    "case, command, error, expected, unexpected",
    [
        (
            "explains a web-filter block",
            "ngts-certificate-revoke",
            NextGenTrustSecurity.WebFilterBlockedError("x"),
            "security filter",
            None,
        ),
        (
            "adds the approval-rule hint to a redacted revoke error",
            "ngts-certificate-revoke",
            Exception("The Next-Gen Trust Security GraphQL gateway returned errors: Subgraph errors redacted"),
            "nothing was changed",
            None,
        ),
        (
            "points the redacted revoke error to the help section",
            "ngts-certificate-revoke",
            Exception("Subgraph errors redacted"),
            'See "Revocation approval rules" in the integration help',
            None,
        ),
        (
            "keeps other commands' redacted errors as they are",
            "ngts-certificate-search",
            Exception("Subgraph errors redacted"),
            "Subgraph errors redacted",
            "approval rule",
        ),
        ("passes any other error through", "ngts-certificate-revoke", Exception("boom"), "boom", "approval rule"),
    ],
)
def test_error_message(case: str, command: str, error: Exception, expected: str, unexpected: str | None):
    # act
    message = error_message(command, {}, error)

    # assert
    assert expected in message, case
    if unexpected:
        assert unexpected not in message, case


""" TEST MODULE """


def test_test_module_runs_a_one_certificate_search_instead_of_useraccounts(client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    graphql_mock = requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))
    requests_mock.get(THRESHOLDS_URL, json=util_load_json("expiry_thresholds.json"))
    user_accounts_mock = requests_mock.get(USER_ACCOUNTS_URL, status_code=403, json={})

    # act
    result = run_test_module(client)

    # assert
    assert result == "ok"
    assert graphql_mock.last_request.json()["variables"]["first"] == 1
    assert not user_accounts_mock.called, "/v1/useraccounts is 403 on NGTS"


def test_test_module_passes_when_the_thresholds_are_forbidden(client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))
    requests_mock.get(THRESHOLDS_URL, status_code=403, json={})

    # act
    result = run_test_module(client)

    # assert
    assert result == "ok", "the thresholds are a diagnostic and must not fail the connection test"


def test_test_module_mints_a_fresh_token_instead_of_trusting_the_cache(client: Client, requests_mock):
    # arrange
    seed_cached_token("cached")
    token_mock = requests_mock.post(TOKEN_URL, json=token_response("fresh"))
    graphql_mock = requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))
    requests_mock.get(THRESHOLDS_URL, json=util_load_json("expiry_thresholds.json"))

    # act
    result = run_test_module(client)

    # assert
    assert result == "ok"
    assert token_mock.call_count == 1
    assert graphql_mock.last_request.headers["Authorization"] == "Bearer fresh"
    assert demisto.getIntegrationContext()[TOKEN_CACHE_CONTEXT_KEY]["access_token"] == "fresh"


""" THRESHOLDS """


def test_get_expiry_thresholds_reads_the_rest_configuration(client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    graphql_mock = requests_mock.post(GRAPHQL_URL, status_code=403, json={})
    requests_mock.get(THRESHOLDS_URL, json=util_load_json("expiry_thresholds.json"))

    # act
    thresholds = client.get_expiry_thresholds()
    message = threshold_alignment_message(client)

    # assert
    assert thresholds == [7, 30, 60]
    assert "covers the severity ladder" in message
    assert not graphql_mock.called, "getCertExpActiveThresholds is 403 on NGTS"


@pytest.mark.parametrize(
    "case, response, expected",
    [
        ("reads the thresholds", {"configuration": {"thresholds": [14, 30]}}, [14, 30]),
        ("tolerates a missing configuration", {"id": "x"}, []),
        ("tolerates null thresholds", {"configuration": {"thresholds": None}}, []),
        ("tolerates an empty response", None, []),
    ],
)
def test_thresholds_from_configuration(case: str, response: dict | None, expected: list):
    # arrange / act
    result = thresholds_from_configuration(response)

    # assert
    assert result == expected, case


""" COMMANDS """


def test_certificate_search_maps_the_tsg_id_into_the_shared_context(client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    graphql_mock = requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    result = certificate_search_command(client, {"limit": "5"})

    # assert
    assert result.outputs_prefix == "CertManagerSaaS.Certificate"
    assert result.outputs[0]["TSGID"] == TSG_ID
    assert "Next-Gen Trust Security certificates" in result.readable_output
    assert "workspaceId" in graphql_mock.last_request.json()["query"]


def test_certificate_command_attributes_the_verdict_to_ngts(client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    results = certificate_command(client, {"certificate": FINGERPRINT}, RELIABILITY)

    # assert
    dbot_score = results[0].indicator.dbot_score
    assert dbot_score.integration_name == "Next-Gen Trust Security"
    assert dbot_score.score == 3, "a submitted KEY_COMPROMISE revocation with no CA list result is malicious"
    assert "through Next-Gen Trust Security" in dbot_score.malicious_description
    assert "case 42" in dbot_score.malicious_description


@freeze_time(FROZEN_NOW)
@pytest.mark.parametrize(
    "case, graphql_response, run",
    [
        ("search", "search", lambda client: certificate_search_command(client, {}).outputs),
        ("get", "search", lambda client: [certificate_get_command(client, {"fingerprint": FINGERPRINT}).outputs]),
        ("list expiring", "search", lambda client: certificate_list_expiring_command(client, {"days": "30"}).outputs),
        ("revoke", "revoke", lambda client: [certificate_revoke_command(client, {"fingerprint": FINGERPRINT}).outputs]),
        (
            "reputation",
            "search",
            lambda client: [certificate_command(client, {"certificate": FINGERPRINT}, RELIABILITY)[0].outputs],
        ),
    ],
)
def test_certificate_outputs_carry_the_ngts_source_brand(case: str, graphql_response: str, run, client: Client, requests_mock):
    # arrange
    responses = {
        "search": util_load_json("search_certificates_page.json"),
        "revoke": {"data": {"revokeCertificate": search_node()}},
    }
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    requests_mock.post(GRAPHQL_URL, json=responses[graphql_response])

    # act
    outputs = run(client)

    # assert
    assert outputs, case
    assert [output["SourceBrand"] for output in outputs] == [BRAND] * len(outputs), case
    assert requests_mock.last_request.headers["Authorization"] == "Bearer token-a", case


def test_certificate_revoke_sends_the_mutation_with_the_bearer_token(client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    graphql_mock = requests_mock.post(GRAPHQL_URL, json={"data": {"revokeCertificate": search_node()}})

    # act
    result = certificate_revoke_command(client, {"fingerprint": FINGERPRINT, "reason": "superseded", "comment": "rotated"})

    # assert
    sent = graphql_mock.last_request.json()
    assert "revokeCertificate(fingerprint: $fingerprint" in sent["query"]
    assert sent["variables"] == {"fingerprint": FINGERPRINT, "revocationReason": "SUPERSEDED", "revocationComment": "rotated"}
    assert graphql_mock.last_request.headers["Authorization"] == "Bearer token-a"
    assert result.outputs["Fingerprint"] == FINGERPRINT


def test_certificate_request_and_status_go_through_the_bearer_client(client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    create_mock = requests_mock.post(
        CERTIFICATE_REQUESTS_URL, json={"certificateRequests": [{"id": REQUEST_ID, "status": "REQUESTED"}]}
    )
    status_mock = requests_mock.get(
        f"{CERTIFICATE_REQUESTS_URL}/{REQUEST_ID}",
        json={"id": REQUEST_ID, "status": "ISSUED", "certificateIds": [CERTIFICATE_ID]},
    )

    # act
    created = certificate_request_command(client, {"certificate_issuing_template_id": "tmpl-1", "common_name": "a.example"})
    status = certificate_request_status_command(client, {"request_id": REQUEST_ID})

    # assert
    assert created.outputs[0]["ID"] == REQUEST_ID
    assert create_mock.last_request.json()["isVaaSGenerated"] is True
    assert create_mock.last_request.headers["Authorization"] == "Bearer token-a"
    assert status.outputs["CertificateIDs"] == [CERTIFICATE_ID]
    assert status_mock.last_request.headers["Authorization"] == "Bearer token-a"


def test_machine_list_and_get_go_through_the_bearer_client(client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    list_mock = requests_mock.get(MACHINES_URL, json={"machines": [{"id": MACHINE_ID, "machineName": "F5 v17"}]})
    get_mock = requests_mock.get(
        f"{MACHINES_URL}/{MACHINE_ID}",
        json={"id": MACHINE_ID, "machineName": "F5 v17", "connectionDetails": {"host": "https://F5.example.test:8443/mgmt"}},
    )

    # act
    listed = machine_list_command(client, {})
    machine = machine_get_command(client, {"machine_identifier": MACHINE_ID})

    # assert
    assert [entry["ID"] for entry in listed.outputs] == [MACHINE_ID]
    assert machine.outputs["Host"] == "f5.example.test"
    assert list_mock.last_request.headers["Authorization"] == "Bearer token-a"
    assert get_mock.last_request.headers["Authorization"] == "Bearer token-a"


def test_certificate_download_keeps_the_accept_header_and_the_raw_content(client: Client, requests_mock, monkeypatch, tmp_path):
    # arrange
    monkeypatch.chdir(tmp_path)  # fileResult writes into the working directory
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    contents_mock = requests_mock.get(CONTENTS_URL, text=PEM)

    # act
    results = certificate_download_command(client, {"certificate_id": CERTIFICATE_ID})

    # assert
    request = contents_mock.last_request
    assert request.headers["Accept"] == "text/plain"
    assert request.headers["Authorization"] == "Bearer token-a"
    assert request.qs == {"format": ["pem"]}
    assert results[0]["File"] == f"{CERTIFICATE_ID}.pem"
    assert results[1].outputs["Contents"] == PEM


def test_certificate_download_keeps_the_accept_header_and_the_raw_content_on_the_401_retry(client: Client, requests_mock):
    # arrange
    seed_cached_token("stale")
    requests_mock.post(TOKEN_URL, json=token_response("fresh"))
    der = b"\x30\x82\x01\x0a"
    contents_mock = requests_mock.get(CONTENTS_URL, [{"status_code": 401, "json": {}}, {"content": der}])

    # act
    contents = client.download_certificate(CERTIFICATE_ID, "DER", {})

    # assert
    assert contents == der, "resp_type=content must survive the retry"
    assert [request.headers["Accept"] for request in contents_mock.request_history] == ["application/octet-stream"] * 2
    assert [request.headers["Authorization"] for request in contents_mock.request_history] == ["Bearer stale", "Bearer fresh"]


CERTIFICATE_URL = f"{BASE_URL}/outagedetection/v1/certificates/{CERTIFICATE_ID}"
KEYSTORE_URL = f"{CERTIFICATE_URL}/keystore"
DEK_HASH = "dek-hash-0001"
EDGE_KEY_URL = f"{BASE_URL}/v1/edgeencryptionkeys/{DEK_HASH}"
PASSPHRASE = "Aa1!dummy-passphrase"
P12 = b"\x30\x82\x0a\x1b-raw-pkcs12"


def mock_keystore_api(requests_mock, private_key: PrivateKey, keystore_responses: list[dict]):
    requests_mock.get(CERTIFICATE_URL, json={"id": CERTIFICATE_ID, "subjectCN": ["vsat.example.test"], "dekHash": DEK_HASH})
    requests_mock.get(
        EDGE_KEY_URL, json={"key": base64.b64encode(bytes(private_key.public_key)).decode(), "keyAlgorithm": "ED25519"}
    )
    return requests_mock.post(KEYSTORE_URL, keystore_responses)


def test_certificate_keystore_download_goes_through_the_bearer_client(client: Client, requests_mock, monkeypatch, tmp_path):
    # arrange
    monkeypatch.chdir(tmp_path)  # fileResult writes into the working directory
    private_key = PrivateKey.generate()
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    keystore_mock = mock_keystore_api(requests_mock, private_key, [{"status_code": 201, "content": P12}])

    # act
    results = certificate_keystore_download_command(
        client, {"certificate_id": CERTIFICATE_ID, "passphrase": PASSPHRASE, "format": "PKCS12"}
    )

    # assert
    ngts_requests = [request for request in requests_mock.request_history if request.url.startswith(BASE_URL)]
    assert [request.headers["Authorization"] for request in ngts_requests] == ["Bearer token-a"] * 3
    assert keystore_mock.last_request.headers["Accept"] == "*/*"
    sealed = keystore_mock.last_request.json()["encryptedPrivateKeyPassphrase"]
    assert SealedBox(private_key).decrypt(base64.b64decode(sealed)) == PASSPHRASE.encode()
    assert results[0]["File"] == "vsat.example.test.p12"
    assert results[1].outputs == {
        "CertificateID": CERTIFICATE_ID,
        "Format": "PKCS12",
        "KeystoreFileName": "vsat.example.test.p12",
    }


def test_certificate_keystore_download_keeps_the_accept_header_and_the_binary_body_on_the_401_retry(
    client: Client, requests_mock
):
    # arrange
    seed_cached_token("stale")
    requests_mock.post(TOKEN_URL, json=token_response("fresh"))
    keystore_mock = requests_mock.post(KEYSTORE_URL, [{"status_code": 401, "json": {}}, {"status_code": 201, "content": P12}])

    # act
    contents = client.export_keystore(CERTIFICATE_ID, {"exportFormat": "PKCS12"})

    # assert
    assert contents == P12, "resp_type=content must survive the retry"
    assert [request.headers["Accept"] for request in keystore_mock.request_history] == ["*/*"] * 2
    assert [request.headers["Authorization"] for request in keystore_mock.request_history] == ["Bearer stale", "Bearer fresh"]


def test_certificate_keystore_download_explains_a_web_filter_403(client: Client, requests_mock):
    # arrange
    private_key = PrivateKey.generate()
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    blocked = {"status_code": 403, "headers": {"x-request-flow-error": "DEF_403"}, "text": "<html>blocked</html>"}
    mock_keystore_api(requests_mock, private_key, [blocked])

    # act / assert
    with pytest.raises(Exception, match="security filter"):
        certificate_keystore_download_command(client, {"certificate_id": CERTIFICATE_ID, "passphrase": PASSPHRASE})


def test_main_dispatches_the_keystore_download(requests_mock, monkeypatch, tmp_path):
    # arrange
    monkeypatch.chdir(tmp_path)
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    mock_keystore_api(requests_mock, PrivateKey.generate(), [{"status_code": 201, "content": P12}])
    params = {"url": BASE_URL, "token_url": TOKEN_URL, "credentials": {"identifier": CLIENT_ID, "password": CLIENT_SECRET}}
    returned: list = []
    monkeypatch.setattr(demisto, "params", lambda: params | {"tsg_id": TSG_ID})
    monkeypatch.setattr(demisto, "args", lambda: {"certificate_id": CERTIFICATE_ID, "passphrase": PASSPHRASE, "format": "PKCS12"})
    monkeypatch.setattr(demisto, "command", lambda: "ngts-certificate-keystore-download")
    monkeypatch.setattr(NextGenTrustSecurity, "return_results", returned.append)
    monkeypatch.setattr(NextGenTrustSecurity, "return_error", pytest.fail)

    # act
    NextGenTrustSecurity.main()

    # assert
    assert returned[0][0]["File"] == "vsat.example.test.p12"
    assert returned[0][1].outputs_prefix == "CertManagerSaaS.Keystore"


@freeze_time(FROZEN_NOW)
def test_fetch_incidents_stamps_the_source_brand_and_fingerprint_into_raw_json(client: Client, requests_mock):
    # arrange
    requests_mock.post(TOKEN_URL, json=token_response("token-a"))
    graphql_mock = requests_mock.post(GRAPHQL_URL, json=util_load_json("search_certificates_page.json"))

    # act
    incidents, last_run = fetch_incidents(client, {}, {})

    # assert
    assert len(incidents) == 1
    raw = json.loads(incidents[0]["rawJSON"])
    assert raw["SourceBrand"] == BRAND
    assert raw["Fingerprint"] == FINGERPRINT
    assert raw["CrossedThresholdDays"] == 30
    assert set(last_run["found_incident_ids"]) == {f"{FINGERPRINT}:30"}
    assert graphql_mock.last_request.headers["Authorization"] == "Bearer token-a"


""" PARAMETERS """


def test_build_client_uses_the_production_defaults():
    # arrange
    params = {"credentials": {"identifier": CLIENT_ID, "password": CLIENT_SECRET}, "tsg_id": f" {TSG_ID} "}

    # act
    client = build_client(params)

    # assert
    assert client._base_url == DEFAULT_BASE_URL
    assert client._oauth.token_url == DEFAULT_TOKEN_URL
    assert client._oauth.tsg_id == TSG_ID


def test_build_client_honours_configured_urls():
    # arrange
    params = {
        "url": f"{BASE_URL}/",
        "token_url": TOKEN_URL,
        "credentials": {"identifier": CLIENT_ID, "password": CLIENT_SECRET},
        "tsg_id": TSG_ID,
    }

    # act
    client = build_client(params)

    # assert
    assert client._base_url == BASE_URL
    assert client._oauth.token_url == TOKEN_URL


@pytest.mark.parametrize(
    "case, params",
    [
        ("requires the client id", {"credentials": {"password": CLIENT_SECRET}, "tsg_id": TSG_ID}),
        ("requires the client secret", {"credentials": {"identifier": CLIENT_ID}, "tsg_id": TSG_ID}),
        ("requires the tsg id", {"credentials": {"identifier": CLIENT_ID, "password": CLIENT_SECRET}, "tsg_id": " "}),
    ],
)
def test_build_client_rejects_incomplete_parameters(case: str, params: dict):
    # arrange / act / assert
    with pytest.raises(Exception, match="are all required"):
        build_client(params)
