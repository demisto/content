"""Unit tests for the Tenzai integration (first-party v1 API)."""

import demistomock as demisto
import pytest
from CommonServerPython import DemistoException

from Tenzai import (
    Client,
    DEFAULT_HTTP_TIMEOUT,
    TEST_ENDPOINT,
    _client_from_params,
    _finding_cve,
    _match_lead_to_alert,
    _render_lead_rationale_markdown,
    _validated_from_status,
    create_scan_command,
    get_scan_command,
    get_scan_result_command,
    uuid_to_base62,
)
from Tenzai import test_module as run_test_module

# Polling requires a platform version that supports ScheduledCommand; mock it for status tests.
SUPPORTED_VERSION = {"version": "6.10.0", "buildNumber": "12345"}

BASE_URL = "https://api.tenzai.test"

# Real UUIDs so uuid_to_base62 (which validates hex) accepts them in referenceUrl tests.
APP_UUID = "0053254e-423e-4ac4-88f0-f0d22b92281d"
SCAN_UUID = "11111111-2222-4333-8444-555555555555"


def build_client() -> Client:
    return Client(
        base_url=BASE_URL,
        verify=False,
        headers={"Authorization": "Bearer test-key"},
        proxy=False,
    )


# ---------------------------------------------------------------------------
# base62 port
# ---------------------------------------------------------------------------


def test_uuid_to_base62_known_vector():
    """The port matches the platform/UI vector."""
    assert uuid_to_base62(APP_UUID) == "00bzrAULhh4ZlgSZbYKf3V"


# ---------------------------------------------------------------------------
# test-module
# ---------------------------------------------------------------------------


def test_test_module_ok(requests_mock):
    """A 2xx from the applications endpoint => 'ok'."""
    requests_mock.get(f"{BASE_URL}{TEST_ENDPOINT}", json={"items": [], "total": 0})
    assert run_test_module(build_client()) == "ok"


def test_test_module_probes_applications_with_size_one(requests_mock):
    """test-module hits GET /v1/applications?size=1."""
    mock = requests_mock.get(f"{BASE_URL}{TEST_ENDPOINT}", json={"items": []})
    run_test_module(build_client())
    assert mock.last_request.qs["size"] == ["1"]


def test_test_module_auth_error(requests_mock):
    """A 401 is translated into a readable authorization message, not a raw stacktrace."""
    requests_mock.get(f"{BASE_URL}{TEST_ENDPOINT}", status_code=401, json={"error": "Unauthorized"})
    result = run_test_module(build_client())
    assert "Authorization Error" in result
    assert "API Key" in result


def test_test_module_forbidden_is_auth_error(requests_mock):
    """A 403 is also treated as an authorization error."""
    requests_mock.get(f"{BASE_URL}{TEST_ENDPOINT}", status_code=403, json={"error": "Forbidden"})
    assert "Authorization Error" in run_test_module(build_client())


def test_test_module_other_error_raises(requests_mock):
    """A non-auth failure (e.g. 500) propagates as a DemistoException."""
    requests_mock.get(f"{BASE_URL}{TEST_ENDPOINT}", status_code=500, json={"error": "boom"})
    with pytest.raises(DemistoException):
        run_test_module(build_client())


def test_client_sends_bearer_auth_header(requests_mock):
    """The configured API key is sent as a Bearer token on requests."""
    mock = requests_mock.get(f"{BASE_URL}{TEST_ENDPOINT}", json={"items": []})
    build_client().test_connection()
    assert mock.last_request.headers["Authorization"] == "Bearer test-key"


# ---------------------------------------------------------------------------
# client construction: bounded HTTP timeout (ENG-5184)
# ---------------------------------------------------------------------------


def test_client_from_params_uses_bounded_default_timeout():
    """With no timeout param, the client uses the bounded default (not BaseClient's 60s).

    The bound must stay well under the poll automation's execution timeout so a
    stalled host fails fast enough for the graceful retry path to run.
    """
    client = _client_from_params({"url": BASE_URL, "credentials": {"password": "k"}})
    assert client.timeout == DEFAULT_HTTP_TIMEOUT
    assert DEFAULT_HTTP_TIMEOUT < 60  # tighter than BaseClient's default


def test_client_from_params_reads_timeout_param():
    """An explicit timeout param overrides the default."""
    client = _client_from_params({"url": BASE_URL, "credentials": {"password": "k"}, "timeout": "12"})
    assert client.timeout == 12


def test_client_from_params_blank_timeout_falls_back_to_default():
    """A blank/invalid timeout param falls back to the bounded default rather than 0/None."""
    client = _client_from_params({"url": BASE_URL, "credentials": {"password": "k"}, "timeout": ""})
    assert client.timeout == DEFAULT_HTTP_TIMEOUT


# ---------------------------------------------------------------------------
# tenzai-create-scan: find-or-create + scan-create
# ---------------------------------------------------------------------------


def _mock_app_list(requests_mock, items):
    return requests_mock.get(f"{BASE_URL}/v1/applications", json={"items": items, "total": len(items)})


def test_create_scan_finds_existing_app_exact_name(requests_mock):
    """An existing app with an EXACT (case-insensitive) name is reused; no POST /v1/applications."""
    _mock_app_list(
        requests_mock,
        [
            # contains-match noise the API filter would also return
            {"id": "other", "name": "vpn.acme.com.evil"},
            {"id": APP_UUID, "name": "VPN.ACME.COM"},  # exact, different case
        ],
    )
    create_mock = requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": "should-not-be-used"})
    scan_mock = requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    result = create_scan_command(
        build_client(),
        {"target": "vpn.acme.com", "exposure_name": "Insecure OpenSSH", "port": "22", "protocol": "tcp"},
    )

    assert not create_mock.called  # reused, did not create
    assert scan_mock.called
    assert result.outputs["id"] == SCAN_UUID
    assert result.outputs["applicationId"] == APP_UUID
    assert result.outputs["status"] == "Pending"


def test_create_scan_includes_live_log_reference_url(requests_mock, mocker):
    """create-scan emits a live Agent-log referenceUrl (base62 ids, /log tab) when frontend_url is set (ENG-5200)."""
    mocker.patch.object(demisto, "params", return_value={"frontend_url": "https://app.tenzai.io"})
    _mock_app_list(requests_mock, [{"id": APP_UUID, "name": "vpn.acme.com"}])
    requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    result = create_scan_command(
        build_client(),
        {"target": "vpn.acme.com", "exposure_name": "Insecure OpenSSH", "port": "22", "protocol": "tcp"},
    )

    assert result.outputs["referenceUrl"] == (
        f"https://app.tenzai.io/apps/{uuid_to_base62(APP_UUID)}/tests/{uuid_to_base62(SCAN_UUID)}/log"
    )


def test_derive_app_url_maps_known_host_shapes():
    """The app URL is inferable from the API URL on every Tenzai env shape (ENG-6970)."""
    from Tenzai import _derive_app_url

    # Leading api. label -> app.
    assert _derive_app_url("https://api.tenzai.io") == "https://app.tenzai.io"
    assert _derive_app_url("https://api.dev.tenzai.io") == "https://app.dev.tenzai.io"
    # A shard label sits first with the api label second -> drop the api label.
    assert _derive_app_url("https://eu.api.tenzai.io") == "https://eu.tenzai.io"
    # Scheme and explicit port are preserved.
    assert _derive_app_url("https://api.tenzai.io:8443") == "https://app.tenzai.io:8443"
    # Unrecognised shapes return None — a wrong link is worse than no link.
    assert _derive_app_url("https://other.tenzai.io") is None
    assert _derive_app_url("https://tenzai.io") is None
    assert _derive_app_url("") is None


def test_create_scan_derives_reference_url_from_api_url(requests_mock, mocker):
    """With no frontend_url, the app URL is derived from the API URL so the link still renders."""
    mocker.patch.object(demisto, "params", return_value={"url": "https://eu.api.tenzai.io"})
    _mock_app_list(requests_mock, [{"id": APP_UUID, "name": "vpn.acme.com"}])
    requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    result = create_scan_command(build_client(), {"target": "vpn.acme.com", "exposure_name": "x"})

    assert result.outputs["referenceUrl"] == (
        f"https://eu.tenzai.io/apps/{uuid_to_base62(APP_UUID)}/tests/{uuid_to_base62(SCAN_UUID)}/log"
    )


def test_create_scan_explicit_frontend_url_overrides_derivation(requests_mock, mocker):
    """An explicitly configured frontend_url wins over the derived one."""
    mocker.patch.object(
        demisto,
        "params",
        return_value={"url": "https://eu.api.tenzai.io", "frontend_url": "https://custom.tenzai.io"},
    )
    _mock_app_list(requests_mock, [{"id": APP_UUID, "name": "vpn.acme.com"}])
    requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    result = create_scan_command(build_client(), {"target": "vpn.acme.com", "exposure_name": "x"})

    assert result.outputs["referenceUrl"].startswith("https://custom.tenzai.io/apps/")


def test_create_scan_appends_analyst_guidelines(requests_mock):
    """Analyst guidelines are appended as their own section; focus + scope lock survive (ENG-6970)."""
    _mock_app_list(requests_mock, [{"id": APP_UUID, "name": "vpn.acme.com"}])
    scan_mock = requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    create_scan_command(
        build_client(),
        {
            "target": "vpn.acme.com",
            "exposure_name": "Insecure OpenSSH",
            "guidelines": "Credentials are admin/admin. Do not brute force.",
        },
    )

    guidelines = scan_mock.last_request.json()["guidelines"]
    assert "Analyst guidelines:" in guidelines
    assert "Credentials are admin/admin. Do not brute force." in guidelines
    # The synthesized focus and the single-target scope lock are never dropped.
    assert "Validate the externally-reported exposure: Insecure OpenSSH." in guidelines
    assert "do not pivot to other hosts" in guidelines


def test_create_scan_omits_reference_url_without_frontend_url(requests_mock):
    """Neither frontend_url nor a derivable API URL => no referenceUrl on the create output."""
    _mock_app_list(requests_mock, [{"id": APP_UUID, "name": "vpn.acme.com"}])
    requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    result = create_scan_command(
        build_client(),
        {"target": "vpn.acme.com", "exposure_name": "Insecure OpenSSH", "port": "22", "protocol": "tcp"},
    )

    assert "referenceUrl" not in result.outputs


def test_create_scan_creates_app_on_miss(requests_mock):
    """No exact-name match => POST /v1/applications, then scan-create under the new app."""
    _mock_app_list(requests_mock, [{"id": "noise", "name": "sub.vpn.acme.com"}])  # contains, not exact
    create_mock = requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": APP_UUID, "name": "vpn.acme.com"})
    requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "INITIALIZING"}},
    )

    result = create_scan_command(
        build_client(),
        {
            "target": "vpn.acme.com",
            "exposure_name": "Insecure OpenSSH",
            "supporting_data": "CVE-2024-1234; OpenSSH 7.4",
            "port": "22",
            "protocol": "tcp",
            "service_classification": "SshServer",
            "asm_service_id": "svc-1",
            "alert_internal_id": "alert-9",
            "issue_description": "Cortex flagged a weak SSH config.",
        },
    )

    body = create_mock.last_request.json()
    assert body["name"] == "vpn.acme.com"
    assert body["applicationType"] == "NETWORK_SERVICE"  # derived from tcp + port
    assert body["targets"] == [{"url": "tcp://vpn.acme.com:22"}]
    # Guidelines fold in exposure, supporting data, classification, issue description, and correlation.
    guidelines = body["guidelines"]
    assert "Insecure OpenSSH" in guidelines["focusArea"]
    assert "CVE-2024-1234" in guidelines["focusArea"]
    assert "SshServer" in guidelines["focusArea"]
    assert "Cortex flagged a weak SSH config." in guidelines["focusArea"]
    assert "do not pivot" in guidelines["outOfScope"].lower()
    assert "asm_service_id=svc-1" in guidelines["additional"]
    assert "alert_internal_id=alert-9" in guidelines["additional"]
    # Initializing maps to Pending.
    assert result.outputs["status"] == "Pending"


def test_create_scan_http_server_on_nonstandard_port_is_web_app(requests_mock):
    """ENG-7120: an HTTP server reported on a non-web port (no http scheme, port not
    in _WEB_PORTS) must classify as WEB_APP via the product signal in the exposure
    name / description — not NETWORK_SERVICE — and scan over https://host:port."""
    _mock_app_list(requests_mock, [])
    create_mock = requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": APP_UUID, "name": "198.51.100.5"})
    requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "INITIALIZING"}},
    )

    create_scan_command(
        build_client(),
        {
            "target": "198.51.100.5",
            "port": "15580",
            "exposure_name": "CVE-2021-40438 vulnerability at HTTP Server at 198.51.100.5:15580",
            "issue_description": (
                "Service HTTP Server at 198.51.100.5:15580 on version(s) "
                "['ApacheWebServer 2.4.41', 'OpenSSL 1.1.1d', 'PHP 7.2.28']."
            ),
        },
    )

    body = create_mock.last_request.json()
    assert body["applicationType"] == "WEB_APP"
    assert body["targets"] == [{"url": "https://198.51.100.5:15580"}]


def test_create_scan_matches_concatenated_apachewebserver_token(requests_mock):
    """ENG-7120: the product form must match the concatenated 'ApacheWebServer'
    token (a plain \\bapache\\b would not, since it's inside one word) even when
    that is the ONLY web signal present."""
    _mock_app_list(requests_mock, [])
    create_mock = requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": APP_UUID, "name": "1.2.3.4"})
    requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    create_scan_command(
        build_client(),
        {
            "target": "1.2.3.4",
            "port": "15580",
            "exposure_name": "CVE-2021-40438 at 1.2.3.4:15580",
            "issue_description": "Detected banner: ApacheWebServer 2.4.41 with mod_proxy enabled.",
        },
    )

    body = create_mock.last_request.json()
    assert body["applicationType"] == "WEB_APP"
    assert body["targets"] == [{"url": "https://1.2.3.4:15580"}]


def test_create_scan_unrelated_https_url_stays_network_service(requests_mock):
    """ENG-7120 guardrail: a non-HTTP exposure whose description merely quotes an
    https:// reference URL (no web-server product) must NOT be misclassified as
    WEB_APP — it stays NETWORK_SERVICE. Scheme is read from the target, not text."""
    _mock_app_list(requests_mock, [])
    create_mock = requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": APP_UUID, "name": "10.0.0.5"})
    requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    create_scan_command(
        build_client(),
        {
            "target": "10.0.0.5",
            "port": "1723",
            "protocol": "tcp",
            "exposure_name": "PPTP Server at 10.0.0.5:1723",
            "issue_description": "Legacy PPTP VPN endpoint. See https://nvd.nist.gov/vuln/detail/CVE-2012-3268 for details.",
        },
    )

    body = create_mock.last_request.json()
    assert body["applicationType"] == "NETWORK_SERVICE"
    assert body["targets"] == [{"url": "tcp://10.0.0.5:1723"}]


def test_create_scan_l4_proxy_mention_stays_network_service(requests_mock):
    """ENG-7120 guardrail: HAProxy/Envoy front raw TCP as well as HTTP, so naming one
    in a genuine TCP exposure must NOT force WEB_APP — the classifier only trusts
    products that imply an HTTP surface."""
    _mock_app_list(requests_mock, [])
    create_mock = requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": APP_UUID, "name": "10.0.0.9"})
    requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    create_scan_command(
        build_client(),
        {
            "target": "10.0.0.9",
            "port": "5432",
            "protocol": "tcp",
            "exposure_name": "Exposed PostgreSQL at 10.0.0.9:5432",
            "issue_description": "Postgres reachable through an Envoy / HAProxy TCP passthrough.",
        },
    )

    body = create_mock.last_request.json()
    assert body["applicationType"] == "NETWORK_SERVICE"
    assert body["targets"] == [{"url": "tcp://10.0.0.9:5432"}]


def test_create_scan_translates_invalid_application_type_422(requests_mock):
    """ENG-7120: a backend that rejects the app type (pre-Host/Network-Service) gets a
    clear, actionable error — not the raw pydantic 422, and no silent WEB_APP retry."""
    _mock_app_list(requests_mock, [])
    requests_mock.post(
        f"{BASE_URL}/v1/applications",
        status_code=422,
        json={
            "detail": [
                {"type": "value_error", "loc": ["body"], "msg": "Value error, 'NETWORK_SERVICE' is not a valid ApplicationType"}
            ]
        },
    )

    with pytest.raises(DemistoException) as exc:
        create_scan_command(
            build_client(),
            {"target": "10.0.0.5", "port": "1723", "protocol": "tcp", "exposure_name": "PPTP Server"},
        )
    msg = str(exc.value)
    assert "NETWORK_SERVICE" in msg
    assert "does not support" in msg
    assert "Upgrade the Tenzai API instance" in msg


def test_create_scan_race_reuses_winner_on_422(requests_mock):
    """A 422 name-exists on create triggers a re-GET that reuses the concurrently-created app."""
    # First list call (miss) then, after the 422, a second list call that now returns the winner.
    requests_mock.get(
        f"{BASE_URL}/v1/applications",
        [
            {"json": {"items": [], "total": 0}},
            {"json": {"items": [{"id": APP_UUID, "name": "vpn.acme.com"}], "total": 1}},
        ],
    )
    requests_mock.post(
        f"{BASE_URL}/v1/applications",
        status_code=422,
        json={"detail": [{"loc": ["body", "name"], "msg": "An application with this name already exists."}]},
    )
    scan_mock = requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    result = create_scan_command(
        build_client(), {"target": "vpn.acme.com", "exposure_name": "SSH", "port": "22", "protocol": "tcp"}
    )
    assert scan_mock.called
    assert result.outputs["applicationId"] == APP_UUID


def test_create_scan_web_app_target_and_body(requests_mock):
    """A WEB_APP target builds https://host and posts an EXTERNAL_LEAD / MANUAL scan."""
    _mock_app_list(requests_mock, [])
    requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": APP_UUID, "name": "app.tenzai.io"})
    scan_mock = requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    create_scan_command(
        build_client(),
        {"target": "https://app.tenzai.io", "exposure_name": "Exposed admin panel", "alert_internal_id": "532303"},
    )

    body = scan_mock.last_request.json()
    # Targets are owned by the application; the test-create body must NOT send them
    # (the API 422s "Test targets are managed by the application and cannot be overridden").
    assert "targets" not in body
    assert body["trigger"] == "MANUAL"
    assert body["name"] == "Exposed admin panel"
    # EXTERNAL_LEAD profile carries the exposure reference; no CVE => MISCONFIGURATION.
    # category is emitted UPPER-case to satisfy the API enum ('CVE'/'MISCONFIGURATION').
    # Assert the EXACT minimal shape so a regression in the optional-field filter
    # (leaking null/empty ruleId/severity/cwe/port/… that the strict schema 422s on)
    # is caught here rather than at runtime.
    assert body["profileConfig"] == {
        "profile": "EXTERNAL_LEAD",
        "alertId": "532303",
        "title": "Exposed admin panel",
        "category": "MISCONFIGURATION",
        "target": "https://app.tenzai.io",
    }


def test_create_scan_external_lead_cve_category_and_fields(requests_mock):
    """A supplied cve_id drives category=cve and rides on the profile with the optional fields."""
    _mock_app_list(requests_mock, [])
    requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": APP_UUID, "name": "10.0.0.5"})
    scan_mock = requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    create_scan_command(
        build_client(),
        {
            "target": "10.0.0.5",
            "port": "22",
            "exposure_name": "CVE-2018-15473 on SSH",
            "alert_internal_id": "532282",
            "cve_id": "CVE-2018-15473",
            "severity": "High",
            "cwe": "CWE-200",
            "rule_id": "asm-ssh-userenum",
            "issue_description": "OpenSSH user enumeration",
            "supporting_data": "Inferred CVEs: CVE-2018-15473",
        },
    )

    profile = scan_mock.last_request.json()["profileConfig"]
    assert profile["category"] == "CVE"
    assert profile["cveId"] == "CVE-2018-15473"
    assert profile["severity"] == "High"
    assert profile["cwe"] == "CWE-200"
    assert profile["ruleId"] == "asm-ssh-userenum"
    assert profile["port"] == 22
    assert profile["description"] == "OpenSSH user enumeration"
    assert profile["supportingEvidence"] == "Inferred CVEs: CVE-2018-15473"


def test_create_scan_explicit_category_overrides_inference(requests_mock):
    """An explicit category wins even when a cve_id is present."""
    _mock_app_list(requests_mock, [])
    requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": APP_UUID, "name": "10.0.0.5"})
    scan_mock = requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    create_scan_command(
        build_client(),
        {"target": "10.0.0.5", "exposure_name": "x", "cve_id": "CVE-2020-1", "category": "misconfiguration"},
    )

    profile = scan_mock.last_request.json()["profileConfig"]
    assert profile["category"] == "MISCONFIGURATION"
    assert "cveId" not in profile  # cveId only rides along when category resolves to cve


def test_create_scan_cve_category_without_cve_id_downgrades(requests_mock):
    """An explicit category=cve with no cve_id degrades to misconfiguration — a CVE lead
    with no identifier is not a coherent objective, so it becomes a direct probe."""
    _mock_app_list(requests_mock, [])
    requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": APP_UUID, "name": "10.0.0.5"})
    scan_mock = requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    create_scan_command(build_client(), {"target": "10.0.0.5", "exposure_name": "x", "category": "cve"})

    profile = scan_mock.last_request.json()["profileConfig"]
    assert profile["category"] == "MISCONFIGURATION"
    assert "cveId" not in profile


def test_create_scan_drops_out_of_range_port(requests_mock):
    """An out-of-range port is omitted from the profile (the schema constrains 0..65535),
    so it does not 422 the scan-create."""
    _mock_app_list(requests_mock, [])
    requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": APP_UUID, "name": "10.0.0.5"})
    scan_mock = requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    create_scan_command(
        build_client(),
        {"target": "10.0.0.5", "exposure_name": "x", "port": "99999", "application_type": "NETWORK_SERVICE"},
    )

    assert "port" not in scan_mock.last_request.json()["profileConfig"]


def test_create_scan_alert_id_falls_back_to_service_id(requests_mock):
    """With no alert_internal_id, alertId prefers the ASM service id over the exposure name."""
    _mock_app_list(requests_mock, [])
    requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": APP_UUID, "name": "10.0.0.5"})
    scan_mock = requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    create_scan_command(
        build_client(),
        {"target": "10.0.0.5", "exposure_name": "Exposed thing", "asm_service_id": "svc-77"},
    )

    assert scan_mock.last_request.json()["profileConfig"]["alertId"] == "svc-77"


def test_create_scan_derives_web_app_from_port_80(requests_mock):
    """Port 80 with no explicit type derives WEB_APP with an http:// target."""
    _mock_app_list(requests_mock, [])
    app_create = requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": APP_UUID, "name": "1.2.3.4"})
    scan_mock = requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    create_scan_command(build_client(), {"target": "1.2.3.4", "exposure_name": "HTTP server", "port": "80"})

    assert app_create.last_request.json()["applicationType"] == "WEB_APP"
    # The derived target rides on the application (targets are app-owned), not the test body.
    assert app_create.last_request.json()["targets"] == [{"url": "http://1.2.3.4:80"}]
    assert "targets" not in scan_mock.last_request.json()


def test_create_scan_bare_host_is_network_host(requests_mock):
    """A bare host with no port/service signal derives NETWORK_HOST with a bare-host target."""
    _mock_app_list(requests_mock, [])
    app_create = requests_mock.post(f"{BASE_URL}/v1/applications", json={"id": APP_UUID, "name": "host.acme.com"})
    scan_mock = requests_mock.post(
        f"{BASE_URL}/v1/applications/{APP_UUID}/tests",
        json={"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "PENDING"}},
    )

    create_scan_command(build_client(), {"target": "host.acme.com", "exposure_name": "Exposed host"})

    assert app_create.last_request.json()["applicationType"] == "NETWORK_HOST"
    # The derived target rides on the application (targets are app-owned), not the test body.
    assert app_create.last_request.json()["targets"] == [{"url": "host.acme.com"}]
    assert "targets" not in scan_mock.last_request.json()


# ---------------------------------------------------------------------------
# tenzai-get-scan (polling)
# ---------------------------------------------------------------------------


def test_get_scan_still_running(requests_mock, mocker):
    """INPROGRESS maps to Running and keeps polling (no final outputs, partial result)."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    requests_mock.get(f"{BASE_URL}/v1/tests/{SCAN_UUID}", json={"id": SCAN_UUID, "status": {"type": "INPROGRESS"}})
    result = get_scan_command({"id": SCAN_UUID}, build_client())
    assert result.outputs is None
    assert result.scheduled_command is not None


def test_get_scan_pending_keeps_polling(requests_mock, mocker):
    """PENDING maps to Pending and keeps polling."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    requests_mock.get(f"{BASE_URL}/v1/tests/{SCAN_UUID}", json={"id": SCAN_UUID, "status": {"type": "PENDING"}})
    result = get_scan_command({"id": SCAN_UUID}, build_client())
    assert result.scheduled_command is not None


def test_get_scan_complete(requests_mock, mocker):
    """SUCCESS maps to Complete and resolves polling with final status outputs."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    requests_mock.get(f"{BASE_URL}/v1/tests/{SCAN_UUID}", json={"id": SCAN_UUID, "status": {"type": "SUCCESS"}})
    result = get_scan_command({"id": SCAN_UUID}, build_client())
    assert result.outputs == {"id": SCAN_UUID, "status": "Complete"}
    assert result.outputs_prefix == "Tenzai.Scan"
    assert result.scheduled_command is None


def test_get_scan_error_terminal(requests_mock, mocker):
    """TERMINATED maps to Error and resolves polling."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    requests_mock.get(f"{BASE_URL}/v1/tests/{SCAN_UUID}", json={"id": SCAN_UUID, "status": {"type": "TERMINATED"}})
    result = get_scan_command({"id": SCAN_UUID}, build_client())
    assert result.outputs == {"id": SCAN_UUID, "status": "Error"}
    assert result.scheduled_command is None


# ---------------------------------------------------------------------------
# tenzai-get-scan-result
# ---------------------------------------------------------------------------


def _validated_finding() -> dict:
    return {
        "id": "f1",
        "name": "PPTP cleartext auth",
        "severity": "high",
        "impact": "Credentials are exposed in cleartext.",
        "description": "The service negotiates MS-CHAPv2 over an unencrypted channel.",
        "prerequisites": ["Network path to the host"],
        "steps": ["1. Connect to 1.2.3.4:1723", "Capture the auth handshake"],
        "reproduction": {
            "parameters": [
                {"name": "target_host", "defaultValue": "1.2.3.4", "sensitive": False},
                {"name": "api_key", "defaultValue": "[REDACTED]", "sensitive": True},
            ],
            "scripts": [{"language": "PYTHON", "script": "print('exploit')"}],
        },
        "remediation": {
            "items": [
                {"title": "Disable PPTP", "description": "Turn off the PPTP endpoint."},
                {"title": "Use IPsec", "description": "Migrate remote access to IPsec/IKEv2."},
            ],
            "codingAgentPrompt": "Disable PPTP and enforce IPsec.",
        },
    }


def _mock_result(requests_mock, scan, findings, leads=None):
    requests_mock.get(f"{BASE_URL}/v1/tests/{SCAN_UUID}", json=scan)
    requests_mock.get(f"{BASE_URL}/v1/tests/{SCAN_UUID}/findings", json={"items": findings, "total": len(findings)})
    leads = leads or []
    requests_mock.get(f"{BASE_URL}/v1/tests/{SCAN_UUID}/leads", json={"items": leads, "total": len(leads)})


def _by_prefix(results, prefix):
    """Return the outputs of the CommandResults in the returned list matching a prefix, or None."""
    for cr in results:
        if cr.outputs_prefix == prefix:
            return cr.outputs
    return None


def test_get_scan_result_validated_true(requests_mock, mocker):
    """SUCCESS + >=1 finding => validated True, with impact-first evidence + reproduction + guidance."""
    mocker.patch.object(demisto, "params", return_value={"frontend_url": "https://app.tenzai.io"})
    scan = {"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "SUCCESS"}, "acuCount": 12.5, "duration": 252}
    # validated is now lead-scoped: a MATERIALIZED matched lead yields True. The sole lead is used
    # because no correlation keys are passed (nothing to disambiguate).
    _mock_result(requests_mock, scan, [_validated_finding()], leads=[_cve_lead(status="MATERIALIZED")])

    results = get_scan_result_command(build_client(), {"id": SCAN_UUID})
    out = _by_prefix(results, "Tenzai.Scan")

    assert out["id"] == SCAN_UUID
    assert out["applicationId"] == APP_UUID
    assert out["status"] == "Complete"
    assert out["validated"] is True
    assert out["correlationState"] == "resolved"  # a lead matched this alert (drives the write-back readiness gate)
    assert out["creditUsage"] == 12.5
    assert out["duration"] == 252

    # Evidence is impact-first.
    assert out["evidence"].startswith("## Confirmed findings")
    impact_pos = out["evidence"].index("**Impact:**")
    desc_pos = out["evidence"].index("negotiates MS-CHAPv2")
    assert impact_pos < desc_pos

    # Reproduction: prerequisites (bullets) + steps (ordered, re-numbered) + fenced script.
    repro = out["reproduction"]
    assert "**Prerequisites:**" in repro
    assert "- Network path to the host" in repro
    assert "**Steps:**" in repro
    assert "1. Connect to 1.2.3.4:1723" in repro  # leading "1. " stripped then re-numbered
    assert "2. Capture the auth handshake" in repro
    assert "```python" in repro
    assert "print('exploit')" in repro
    assert "`api_key` = `[REDACTED]`" in repro  # sensitive default already redacted upstream

    # Guidance: remediation items in order + coding-agent prompt.
    guidance = out["guidance"]
    assert "**Disable PPTP**" in guidance
    assert "**Use IPsec**" in guidance
    assert "**Coding-agent prompt:**" in guidance
    assert "enforce IPsec" in guidance

    # referenceUrl is base62-encoded app/scan ids.
    assert out["referenceUrl"] == (
        f"https://app.tenzai.io/apps/{uuid_to_base62(APP_UUID)}/tests/{uuid_to_base62(SCAN_UUID)}/findings"
    )

    # Findings land under the sibling Tenzai.Finding root (NOT nested in the scan).
    assert "Finding" not in out  # not nested under Tenzai.Scan
    findings = _by_prefix(results, "Tenzai.Finding")
    assert len(findings) == 1
    row = findings[0]
    assert row["title"] == "PPTP cleartext auth"
    assert row["severity"] == "HIGH"
    assert row["details"].startswith("**Impact:**")
    detail = row["detail"]
    assert detail.startswith("**Impact:**")
    assert "## Reproduction" in detail
    assert "## Fix Guidance" in detail


def test_get_scan_result_not_validated_no_findings(requests_mock, mocker):
    """An INVALIDATED matched lead => validated False, no findings, status-aware evidence."""
    mocker.patch.object(demisto, "params", return_value={"frontend_url": "https://app.tenzai.io"})
    scan = {"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "SUCCESS"}, "acuCount": 3.0}
    _mock_result(requests_mock, scan, [], leads=[_cve_lead(status="INVALIDATED")])

    results = get_scan_result_command(build_client(), {"id": SCAN_UUID})
    out = _by_prefix(results, "Tenzai.Scan")
    assert out["validated"] is False
    assert out["evidence"] == "No exploitable findings were confirmed for this exposure."
    assert "reproduction" not in out  # None stripped
    assert "guidance" not in out
    assert "duration" not in out  # scan reported no duration => None stripped from outputs
    # No findings => no Tenzai.Finding result at all.
    assert _by_prefix(results, "Tenzai.Finding") is None


def test_get_scan_result_no_matched_lead_is_inconclusive(requests_mock, mocker):
    """No lead correlates (empty leads page) => validated is None (no verdict), not False."""
    mocker.patch.object(demisto, "params", return_value={})
    scan = {"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "INPROGRESS"}}
    _mock_result(requests_mock, scan, [])

    results = get_scan_result_command(build_client(), {"id": SCAN_UUID})
    out = _by_prefix(results, "Tenzai.Scan")
    assert out["validated"] is None
    # Empty leads page = not populated yet → pending (transient), NOT a definitive unmatched:
    # the gate keeps polling rather than writing a partial verdict.
    assert out["correlationState"] == "pending"
    # Status-aware evidence when the verdict isn't final yet.
    assert "not produced a confirmed verdict" in out["evidence"]


def test_get_scan_result_unmatched_when_no_lead_correlates(requests_mock, mocker):
    """Leads present but none correlate to the supplied key => correlationState 'unmatched' (final):
    the write-back gate writes the inconclusive verdict at once, not 'pending' which would keep polling."""
    mocker.patch.object(demisto, "params", return_value={})
    scan = {"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "SUCCESS"}, "acuCount": 1.0}
    _mock_result(requests_mock, scan, [], leads=[_cve_lead(status="INVALIDATED")])

    # Supply a CVE the sole lead does not carry -> no unique match, sole-lead fallback suppressed.
    results = get_scan_result_command(build_client(), {"id": SCAN_UUID, "cve": "CVE-2099-0001"})
    out = _by_prefix(results, "Tenzai.Scan")
    assert out["validated"] is None
    assert out["correlationState"] == "unmatched"


def test_get_scan_result_no_frontend_url_omits_reference_url(requests_mock, mocker):
    """Without frontend_url configured, referenceUrl is omitted (not built)."""
    mocker.patch.object(demisto, "params", return_value={})
    scan = {"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "SUCCESS"}, "acuCount": 1.0}
    _mock_result(requests_mock, scan, [_validated_finding()], leads=[_cve_lead(status="MATERIALIZED")])

    results = get_scan_result_command(build_client(), {"id": SCAN_UUID})
    out = _by_prefix(results, "Tenzai.Scan")
    assert "referenceUrl" not in out
    assert out["validated"] is True


# ---------------------------------------------------------------------------
# CVE lead rationale (ENG-4910)
# ---------------------------------------------------------------------------


def _cve_lead(**overrides) -> dict:
    """A terminal CVE external lead (origin=external, cve set) as the leads API serializes it."""
    lead = {
        "id": "11111111-1111-4111-8111-111111111111",
        "origin": "external",
        "title": "CVE-2018-15473 OpenSSH Username Enumeration at 203.0.113.7:22",
        "hypothesis": "CVE-2018-15473 affects OpenSSH through 7.7; the server may leak valid usernames.",
        "closedReason": "CONFIRMED FALSE POSITIVE - not exploitable; uniform USERAUTH_FAILURE; RHEL backported patches.",
        "status": "INVALIDATED",
        "cve": "CVE-2018-15473",
        "cwe": "CWE-203",
    }
    lead.update(overrides)
    return lead


def test_get_scan_result_extracts_timeline(requests_mock, mocker):
    """The exposure Timeline (from the lead's statusHistory) and status are surfaced."""
    mocker.patch.object(demisto, "params", return_value={"frontend_url": "https://app.tenzai.io"})
    scan = {"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "SUCCESS"}, "acuCount": 3.0}
    lead = _cve_lead(
        status="BLOCKED",
        statusHistory=[
            {"status": "OPEN", "timestamp": "2026-08-16T14:53:46.192631Z"},
            {"status": "BLOCKED", "timestamp": "2026-08-16T15:01:10.297360Z"},
        ],
    )
    _mock_result(requests_mock, scan, [], leads=[lead])

    out = _by_prefix(get_scan_result_command(build_client(), {"id": SCAN_UUID}), "Tenzai.Scan")
    assert out["exposureStatus"] == "BLOCKED"
    assert out["timeline"] == [
        {"status": "OPEN", "time": "08-16 14:53:46"},
        {"status": "BLOCKED", "time": "08-16 15:01:10"},
    ]
    # startedAt is the OPEN entry's FULL ISO (not the lossy grid form) — feeds the panel "Started at".
    assert out["startedAt"] == "2026-08-16T14:53:46.192631Z"


def test_lead_started_at_selects_earliest_open_by_parsed_time():
    """_lead_started_at returns the EARLIEST OPEN entry's full ISO, chosen by parsed timestamp
    (not API/list order). A non-OPEN status is never treated as the start; no OPEN => None."""
    from Tenzai import _lead_started_at

    # Earliest OPEN wins even when a later OPEN appears first in the list (parsed, not lexical/order).
    assert (
        _lead_started_at(
            {
                "statusHistory": [
                    {"status": "OPEN", "timestamp": "2026-08-16T15:10:00Z"},
                    {"status": "IN_PROGRESS", "timestamp": "2026-08-16T14:00:00Z"},
                    {"status": "OPEN", "timestamp": "2026-08-16T14:53:46.192631Z"},
                ]
            }
        )
        == "2026-08-16T14:53:46.192631Z"
    )
    # No OPEN entry => None (an arbitrary non-OPEN status is never the assessment start).
    assert (
        _lead_started_at(
            {
                "statusHistory": [
                    {"status": "BLOCKED", "timestamp": "2026-08-16T15:01:10Z"},
                    {"status": "IN_PROGRESS", "timestamp": "2026-08-16T14:59:00Z"},
                ]
            }
        )
        is None
    )
    # An OPEN entry with no/blank timestamp is skipped; no usable OPEN => None.
    assert _lead_started_at({"statusHistory": [{"status": "OPEN"}]}) is None
    assert _lead_started_at({}) is None


def test_match_lead_by_alert_id_is_strongest_key():
    """alertId selects the lead even when a sibling shares the CVE."""
    leads = [
        {"id": "a", "alertId": "600052", "cve": "CVE-2023-44487"},
        {"id": "b", "alertId": "600099", "cve": "CVE-2024-23897"},
    ]
    assert _match_lead_to_alert(leads, "600052", "CVE-2023-44487", None)["id"] == "a"


def test_match_lead_cve_alone_only_when_unique():
    """CVE alone matches a sole CVE lead, but is rejected (None) when two leads share the CVE."""
    unique = [{"id": "a", "cve": "CVE-2023-44487"}, {"id": "b", "cve": "CVE-2024-23897"}]
    assert _match_lead_to_alert(unique, None, "CVE-2023-44487", None)["id"] == "a"

    # Two leads with the same CVE => ambiguous => no borrowed verdict.
    ambiguous = [
        {"id": "a", "cve": "CVE-2024-23897", "status": "INVALIDATED"},
        {"id": "b", "cve": "CVE-2024-23897", "status": "MATERIALIZED"},
    ]
    assert _match_lead_to_alert(ambiguous, None, "CVE-2024-23897", None) is None


def test_match_lead_cve_plus_rule_id_disambiguates_siblings():
    """cve + ruleId resolves same-CVE siblings that CVE alone cannot."""
    leads = [
        {"id": "a", "cve": "CVE-2024-23897", "ruleId": "rule-1"},
        {"id": "b", "cve": "CVE-2024-23897", "ruleId": "rule-2"},
    ]
    assert _match_lead_to_alert(leads, None, "CVE-2024-23897", "rule-2")["id"] == "b"


def test_match_lead_sole_lead_only_without_keys():
    """A sole lead is a safe fallback ONLY when no correlation keys were supplied.

    With keys that fail to resolve, matching returns None rather than borrowing the lone lead —
    the bug this ticket fixes (a 44487 alert must never inherit a sibling 24897 verdict).
    """
    lone = [{"id": "only", "cve": "CVE-2024-23897"}]
    assert _match_lead_to_alert(lone, None, None, None)["id"] == "only"
    # A supplied alertId that does not match the lone lead => miss, not fallback.
    assert _match_lead_to_alert(lone, "600052", None, None) is None
    # A supplied CVE that does not match => miss, not fallback.
    assert _match_lead_to_alert(lone, None, "CVE-2023-44487", None) is None
    assert _match_lead_to_alert([], "600052", "CVE-2023-44487", None) is None


def test_validated_from_status_tri_state():
    """MATERIALIZED->True, INVALIDATED->False, everything else (incl. BLOCKED)->None."""
    assert _validated_from_status("MATERIALIZED") is True
    assert _validated_from_status("materialized") is True
    assert _validated_from_status("INVALIDATED") is False
    assert _validated_from_status("BLOCKED") is None
    assert _validated_from_status("OPEN") is None
    assert _validated_from_status(None) is None
    assert _validated_from_status("") is None


def test_finding_cve_parses_structured_then_name():
    """CVE is read from a structured field first, else parsed from the finding name (display only)."""
    assert _finding_cve({"cve": "cve-2024-23897"}) == "CVE-2024-23897"
    assert _finding_cve({"name": "CVE-2024-23897: Unauthenticated Arbitrary File Read"}) == "CVE-2024-23897"
    assert _finding_cve({"name": "Some misconfiguration finding"}) is None


def test_get_scan_result_tags_cross_cve_finding_as_discovered(requests_mock, mocker):
    """A finding whose CVE differs from the matched exposure's CVE is attributed ``discovered``;
    the matching one is ``own``. The verdict + narrative scope to the matched lead, not the sibling."""
    mocker.patch.object(demisto, "params", return_value={"frontend_url": "https://app.tenzai.io"})
    scan = {"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "SUCCESS"}, "acuCount": 3.0}
    lead = _cve_lead(cve="CVE-2023-44487", status="INVALIDATED", alertId="600052")
    findings = [
        {"name": "CVE-2023-44487: HTTP/2 Rapid Reset", "severity": "HIGH", "impact": "Own-exposure impact."},
        {"name": "CVE-2024-23897: Unauthenticated Arbitrary File Read", "severity": "HIGH", "impact": "Jenkins CLI read."},
    ]
    _mock_result(requests_mock, scan, findings, leads=[lead])

    results = get_scan_result_command(build_client(), {"id": SCAN_UUID, "alert_id": "600052"})
    scan_out = _by_prefix(results, "Tenzai.Scan")
    assert scan_out["validated"] is False  # matched lead is INVALIDATED, not the sibling's verdict
    assert scan_out["cwe"] == "CWE-203"  # from the matched 44487 lead, not the 24897 finding
    # Scan-level narrative is scoped to OWN findings only — the sibling Jenkins impact never leaks in.
    assert "Jenkins CLI read." not in scan_out["evidence"]
    assert "Own-exposure impact." in scan_out["evidence"]

    rows = _by_prefix(results, "Tenzai.Finding")
    by_cve = {r["cve"]: r for r in rows}
    assert by_cve["CVE-2023-44487"]["attribution"] == "own"
    assert by_cve["CVE-2024-23897"]["attribution"] == "discovered"


def test_get_scan_result_unmatched_lead_marks_findings_unattributed(requests_mock, mocker):
    """When correlation keys are supplied but no lead matches, findings are ``unattributed`` (not own)
    and the verdict is inconclusive — so uncorrelated findings are never counted as the alert's own."""
    mocker.patch.object(demisto, "params", return_value={"frontend_url": "https://app.tenzai.io"})
    scan = {"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "SUCCESS"}, "acuCount": 3.0}
    # Two same-CVE leads => cve alone is ambiguous; a non-matching alert_id => no correlation at all.
    leads = [_cve_lead(cve="CVE-2024-23897", alertId="111"), _cve_lead(cve="CVE-2024-23897", alertId="222")]
    findings = [{"name": "CVE-2024-23897: Arbitrary File Read", "severity": "HIGH", "impact": "x"}]
    _mock_result(requests_mock, scan, findings, leads=leads)

    results = get_scan_result_command(build_client(), {"id": SCAN_UUID, "alert_id": "999", "cve": "CVE-2024-23897"})
    scan_out = _by_prefix(results, "Tenzai.Scan")
    assert scan_out["validated"] is None  # no matched lead => no verdict
    assert "cwe" not in scan_out  # no lead => no classification borrowed
    # Uncorrelated findings do not populate the alert's own narrative.
    assert scan_out["evidence"] == "No exploitable findings were confirmed for this exposure."
    rows = _by_prefix(results, "Tenzai.Finding")
    assert rows[0]["attribution"] == "unattributed"


def test_render_lead_rationale_cve_only():
    """A CVE lead renders Description + Conclusion; a misconfiguration (no cve) renders nothing."""
    md = _render_lead_rationale_markdown(_cve_lead())
    assert md is not None
    assert "## Description" in md
    assert "affects OpenSSH" in md
    assert "## Conclusion" in md
    assert "CONFIRMED FALSE POSITIVE" in md
    # Misconfiguration lead (no cve) => no rationale block.
    assert _render_lead_rationale_markdown(_cve_lead(cve=None)) is None
    assert _render_lead_rationale_markdown(None) is None
    # Open lead with no conclusion yet => Description only.
    open_md = _render_lead_rationale_markdown(_cve_lead(closedReason=None))
    assert "## Description" in open_md
    assert "## Conclusion" not in open_md


def test_get_scan_result_cve_lead_rationale(requests_mock, mocker):
    """A CVE external lead surfaces its Description + Conclusion as leadRationale."""
    mocker.patch.object(demisto, "params", return_value={"frontend_url": "https://app.tenzai.io"})
    scan = {"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "SUCCESS"}, "acuCount": 3.0}
    _mock_result(requests_mock, scan, [], leads=[_cve_lead()])

    out = _by_prefix(get_scan_result_command(build_client(), {"id": SCAN_UUID}), "Tenzai.Scan")
    assert out["validated"] is False
    assert out["leadRationale"].startswith("## Description")
    assert "CONFIRMED FALSE POSITIVE" in out["leadRationale"]


def test_get_scan_result_misconfiguration_lead_no_rationale(requests_mock, mocker):
    """A non-CVE (misconfiguration) external lead produces no leadRationale."""
    mocker.patch.object(demisto, "params", return_value={})
    scan = {"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "SUCCESS"}, "acuCount": 3.0}
    _mock_result(requests_mock, scan, [], leads=[_cve_lead(cve=None, cwe="CWE-16")])

    out = _by_prefix(get_scan_result_command(build_client(), {"id": SCAN_UUID}), "Tenzai.Scan")
    assert "leadRationale" not in out  # None stripped


def test_get_scan_result_leads_fetch_failure_is_non_fatal(requests_mock, mocker):
    """A failing leads fetch degrades to no lead (no rationale, inconclusive verdict), never raising.

    Without the lead the verdict cannot be scoped, so ``validated`` is None (inconclusive) rather
    than a fabricated boolean — but the command still returns cleanly with the scan-level fields.
    """
    mocker.patch.object(demisto, "params", return_value={})
    scan = {"id": SCAN_UUID, "applicationId": APP_UUID, "status": {"type": "SUCCESS"}, "acuCount": 3.0}
    requests_mock.get(f"{BASE_URL}/v1/tests/{SCAN_UUID}", json=scan)
    requests_mock.get(f"{BASE_URL}/v1/tests/{SCAN_UUID}/findings", json={"items": [], "total": 0})
    requests_mock.get(f"{BASE_URL}/v1/tests/{SCAN_UUID}/leads", status_code=500, json={"detail": "boom"})

    out = _by_prefix(get_scan_result_command(build_client(), {"id": SCAN_UUID}), "Tenzai.Scan")
    assert out["validated"] is None  # no lead => inconclusive, but the command did not break
    assert out["creditUsage"] == 3.0
    assert "leadRationale" not in out
