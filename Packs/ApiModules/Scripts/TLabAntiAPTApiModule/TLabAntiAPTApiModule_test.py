"""Tests for the shared tLab Anti-APT client and helpers.

The cases here encode the behaviours that are easy to get wrong against the
real API and that fail silently rather than loudly.
"""

import time

import pytest
from CommonServerPython import DemistoException

from TLabAntiAPTApiModule import (
    ACTIONABLE_VERDICTS,
    AUTH_INTERNAL,
    AUTH_SIGN_IN,
    AUTH_SOURCE_KEY,
    AUTH_TLAB_ACCOUNT,
    jwt_expiry,
    stored_file_verdict,
    default_auth_url,
    COMPLETENESS_COMPLETE,
    COMPLETENESS_EMPTY,
    COMPLETENESS_PARTIAL,
    DEFAULT_SEVERITY_MAP,
    NON_ERROR_REJECTIONS,
    REJECTION_MESSAGES,
    REPORT_TYPE_DROPPED,
    REPORT_TYPE_MAIN,
    SOURCE_TYPE_DISPLAY,
    SOURCE_TYPE_NAME,
    SubmitSettings,
    TLabClient,
    TLabRejection,
    VERDICT_CLEAN,
    VERDICT_MALWARE,
    VERDICT_OK,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    VERDICT_WHITELIST,
    canonical_verdict,
    describe_rejection,
    epoch_to_datetime,
    epoch_to_iso,
    is_terminal,
    normalize_verdict,
    score_to_verdict,
    score_value,
    select_main_report,
    validate_sort,
    verdict_to_dbot_score,
    verdict_to_severity,
)

BASE = "https://tlab.example.com"


def make_client(auth_mode=AUTH_SOURCE_KEY, secret="key", username="", auth_url=""):
    return TLabClient(
        base_url=BASE,
        auth_mode=auth_mode,
        credentials={"identifier": username, "password": secret},
        client_name="xsoar",
        verify=False,
        auth_url=auth_url,
    )


# ---------------------------------------------------------------- verdicts


def test_normalize_verdict_accepts_both_vocabularies():
    # The server returns MALICIOUS on one field and MALWARE on another for the
    # very same sample.
    assert normalize_verdict("MALICIOUS") == normalize_verdict("MALWARE") == VERDICT_MALWARE
    # CLEAN and OK must stay distinct: ScoreLevel separates score == 0 from 0 < score < 50.
    assert normalize_verdict("CLEAN") != normalize_verdict("OK")
    assert normalize_verdict("whitelisted") == VERDICT_WHITELIST
    assert normalize_verdict(" suspicious ") == VERDICT_SUSPICIOUS
    assert normalize_verdict("nonsense") == ""
    assert normalize_verdict(None) == ""


@pytest.mark.parametrize(
    "score,present,expected",
    [
        (0, False, ""),
        (-1.0, True, ""),  # the API's sentinel for "no score"
        (-0.5, True, ""),
        (0, True, VERDICT_CLEAN),
        (0.1, True, VERDICT_OK),
        (49.9, True, VERDICT_OK),
        (50, True, VERDICT_SUSPICIOUS),
        (85, True, VERDICT_SUSPICIOUS),
        (85.1, True, VERDICT_MALWARE),
        (100, True, VERDICT_MALWARE),
    ],
)
def test_score_to_verdict_boundaries(score, present, expected):
    assert score_to_verdict(score, present) == expected


def test_score_value_handles_the_minus_one_sentinel():
    # sampleScore defaults to -1.0 rather than null, and sampleScoreExists is
    # the real presence flag. Reading -1 as a score would call an unfinished
    # analysis clean.
    assert score_value({"sampleScore": -1.0, "sampleScoreExists": True}) == (0.0, False)
    assert score_value({"sampleScore": 50, "sampleScoreExists": False}) == (0.0, False)
    assert score_value({}) == (0.0, False)
    assert score_value({"sampleScore": 0, "sampleScoreExists": True}) == (0.0, True)
    assert score_value({"sampleScore": 72.5}) == (72.5, True)


def test_file_verdict_code_two_is_never_treated_as_ordinal():
    # FileVerdict skips 2 (MALWARE is 3) while ScoreLevel uses 2 for MALICIOUS.
    # Mapping by number would silently swap meanings, so only names are mapped.
    assert normalize_verdict(2) == ""
    assert normalize_verdict("2") == ""


def test_whitelist_beats_everything():
    for report in (
        {"whitelisted": True, "sampleScore": 99, "sampleScoreExists": True, "sampleReportCompleteness": COMPLETENESS_COMPLETE},
        {
            "file": {"fileVerdict": "WHITELIST"},
            "sampleScore": 99,
            "sampleScoreExists": True,
            "sampleReportCompleteness": COMPLETENESS_COMPLETE,
        },
        {"verdict": "WHITELIST", "sampleScore": 99, "sampleScoreExists": True, "sampleReportCompleteness": COMPLETENESS_COMPLETE},
        {"whitelisted": True, "file": {"fileVerdict": "MALWARE"}},
    ):
        assert canonical_verdict(report) == VERDICT_WHITELIST


def test_score_recomputed_only_when_complete():
    report = {
        "file": {"fileVerdict": "OK"},
        "sampleScore": 95,
        "sampleScoreExists": True,
        "sampleReportCompleteness": COMPLETENESS_COMPLETE,
    }
    assert canonical_verdict(report) == VERDICT_MALWARE

    # Before COMPLETE the stored verdict is trusted rather than recomputed.
    report["sampleReportCompleteness"] = COMPLETENESS_PARTIAL
    assert canonical_verdict(report) == VERDICT_OK


def test_early_verdict_requires_stat_and_av():
    report = {
        "file": {"fileVerdict": "UNKNOWN"},
        "verdict": "UNKNOWN",
        "sampleScore": 90,
        "sampleScoreExists": True,
        "sampleReportCompleteness": COMPLETENESS_PARTIAL,
        "completedAnalyzes": ["STAT_ANALYSIS"],
    }
    assert canonical_verdict(report, early_verdict=True) == VERDICT_UNKNOWN

    report["completedAnalyzes"] = ["STAT_ANALYSIS", "AV_ANALYSIS"]
    assert canonical_verdict(report, early_verdict=True) == VERDICT_MALWARE


def test_canonical_verdict_prefers_file_verdict_then_score_level():
    assert canonical_verdict({"file": {"fileVerdict": "MALWARE"}, "verdict": "OK"}) == VERDICT_MALWARE
    assert canonical_verdict({"verdict": "MALICIOUS"}) == VERDICT_MALWARE
    assert canonical_verdict({}) == VERDICT_UNKNOWN


def test_custom_score_thresholds_are_honoured():
    report = {"sampleScore": 40, "sampleScoreExists": True, "sampleReportCompleteness": COMPLETENESS_COMPLETE}
    assert canonical_verdict(report) == VERDICT_OK
    assert canonical_verdict(report, suspicious_from=30, malicious_from=60) == VERDICT_SUSPICIOUS


@pytest.mark.parametrize(
    "completeness,verdict,expected",
    [
        (COMPLETENESS_COMPLETE, VERDICT_UNKNOWN, True),
        (COMPLETENESS_COMPLETE, VERDICT_MALWARE, True),
        (COMPLETENESS_PARTIAL, VERDICT_MALWARE, True),
        (COMPLETENESS_PARTIAL, VERDICT_WHITELIST, True),
        (COMPLETENESS_PARTIAL, VERDICT_UNKNOWN, False),
        (COMPLETENESS_EMPTY, VERDICT_MALWARE, False),
        ("", VERDICT_MALWARE, False),
    ],
)
def test_is_terminal(completeness, verdict, expected):
    assert is_terminal(completeness, verdict) is expected


def test_unknown_is_not_actionable():
    # UNKNOWN means "keep polling"; treating it as actionable would end
    # polling on every fresh submission.
    assert VERDICT_UNKNOWN not in ACTIONABLE_VERDICTS


@pytest.mark.parametrize(
    "verdict,expected",
    [
        (VERDICT_MALWARE, 3),
        (VERDICT_SUSPICIOUS, 2),
        (VERDICT_OK, 1),
        (VERDICT_CLEAN, 1),
        (VERDICT_WHITELIST, 1),
        (VERDICT_UNKNOWN, 0),
    ],
)
def test_verdict_to_dbot_score(verdict, expected):
    assert verdict_to_dbot_score(verdict) == expected


def test_unknown_can_be_reported_as_benign_when_configured():
    assert verdict_to_dbot_score(VERDICT_UNKNOWN) == 0
    assert verdict_to_dbot_score(VERDICT_UNKNOWN, unknown_is_benign=True) == 1


@pytest.mark.parametrize(
    "verdict,score,present,escalate,expected",
    [
        (VERDICT_MALWARE, 90, True, 0, 3),
        (VERDICT_SUSPICIOUS, 60, True, 0, 2),
        (VERDICT_WHITELIST, 0, True, 0, 0.5),
        (VERDICT_MALWARE, 96, True, 95, 4),  # escalated
        (VERDICT_MALWARE, 94, True, 95, 3),  # below the threshold
        (VERDICT_MALWARE, 0, False, 95, 3),  # escalation needs a score
        (VERDICT_SUSPICIOUS, 99, True, 95, 2),  # escalation is malware-only
        ("BOGUS", 0, False, 0, 1),  # unmapped falls back to Low
    ],
)
def test_verdict_to_severity(verdict, score, present, escalate, expected):
    assert verdict_to_severity(verdict, score, present, DEFAULT_SEVERITY_MAP, escalate) == expected


def test_informational_severity_survives_as_float():
    # 0.5 is Informational on the XSOAR scale; an int anywhere in the path
    # would silently drop it to 0.
    assert verdict_to_severity(VERDICT_WHITELIST) == 0.5


# ------------------------------------------------------------------- dates


@pytest.mark.parametrize(
    "value,expected_iso",
    [
        (1774512000000, "2026-03-26T08:00:00Z"),  # milliseconds
        (1774512000, "2026-03-26T08:00:00Z"),  # seconds, promoted
        ("2026-03-26T08:00:00Z", "2026-03-26T08:00:00Z"),
        (None, None),
        (0, None),
        ("", None),
    ],
)
def test_epoch_parsing_accepts_three_formats(value, expected_iso):
    # tlab-server has no spring.jackson config, so java.util.Date serializes as
    # epoch millis by Jackson default. A Spring Boot upgrade would flip that to
    # ISO strings, so all three shapes are accepted.
    assert epoch_to_iso(value) == expected_iso


def test_epoch_to_datetime_returns_utc():
    parsed = epoch_to_datetime(1774512000000)
    assert parsed is not None
    assert parsed.tzinfo is not None
    assert parsed.year == 2026


# -------------------------------------------------------------- rejections


def test_rejection_table_covers_every_documented_code():
    expected = {
        "common.whitelisted",
        "common.already_analyzed",
        "common.limit_reached",
        "common.invalid_file_size",
        "common.invalid_file_name",
        "common.file_type_no_allowed",
        "common.general_io_error",
        "common.unknown",
        "common.no_such_report",
        "common.mainFileContentMissing",
        "common.extraFileContentMissing",
        "url.invalid",
        "url.protocol_not_allowed",
        "url.download_error",
        "url.download_timeout",
        "archive.password_required",
        "archive.decryption_not_supported",
        "archive.unknown_error",
        "activation.invalidLicense",
    }
    assert expected.issubset(set(REJECTION_MESSAGES))


def test_unknown_rejection_code_is_echoed_not_swallowed():
    text = describe_rejection("some.new.code", "extra detail")
    assert "some.new.code" in text
    assert "extra detail" in text


def test_whitelisted_and_already_analyzed_are_outcomes_not_failures():
    # Both mean "there is a result", so commands return it instead of raising.
    assert {"common.whitelisted", "common.already_analyzed"} == NON_ERROR_REJECTIONS


def test_rejection_exception_keeps_the_raw_code():
    exc = TLabRejection("url.invalid", "bad scheme")
    assert exc.code == "url.invalid"
    assert "URL is not valid" in str(exc)


# ------------------------------------------------------------------ sorting


def test_create_time_sort_is_rejected_before_the_request_leaves():
    # The server does not reject it — it silently reorders by update_time DESC.
    with pytest.raises(Exception) as err:
        validate_sort("createTime,asc")
    assert "createTime" in str(err.value)


@pytest.mark.parametrize("sort", ["", "sampleReportId,asc", "updateTime,desc", "reportTime,asc", "sampleScore,desc", "size,asc"])
def test_valid_sort_keys_pass(sort):
    validate_sort(sort)


# ------------------------------------------------------- main report choice


def test_select_main_report_prefers_explicit_main_type():
    reports = [
        {"sampleReportId": 2, "sampleReportType": REPORT_TYPE_DROPPED, "parentReportId": 1},
        {"sampleReportId": 1, "sampleReportType": REPORT_TYPE_MAIN},
    ]
    assert select_main_report(reports)["sampleReportId"] == 1


def test_select_main_report_falls_back_to_root_then_score():
    reports = [
        {"sampleReportId": 5, "parentReportId": 4, "sampleScore": 90},
        {"sampleReportId": 4, "sampleScore": 10},
    ]
    assert select_main_report(reports)["sampleReportId"] == 4

    # No roots at all: highest score wins, ties broken by lowest id.
    reports = [
        {"sampleReportId": 7, "parentReportId": 1, "sampleScore": 10},
        {"sampleReportId": 6, "parentReportId": 1, "sampleScore": 90},
    ]
    assert select_main_report(reports)["sampleReportId"] == 6
    assert select_main_report([]) is None


# ------------------------------------------------------------------ submit


def test_submit_form_repeats_analysis_types_and_brackets_properties():
    settings = SubmitSettings(
        analysis_types=["STAT_ANALYSIS", "DYN_ANALYSIS"],
        properties={"xsoar_incident_id": "42", "xsoar_instance": "inst"},
        tags=["xsoar", "phishing"],
        source_uid="lic-1",
    )
    form = settings.to_form()
    assert [v for k, v in form if k == "analysisTypes"] == ["STAT_ANALYSIS", "DYN_ANALYSIS"]
    assert ("properties[xsoar_incident_id]", "42") in form
    assert ("properties[xsoar_instance]", "inst") in form
    # Tags are indexed form keys, not a repeated flat key.
    assert ("tags[0].name", "xsoar") in form
    assert ("tags[1].name", "phishing") in form
    # The source type travels by enum NAME; the display code is a different string.
    assert ("source.sourceType", SOURCE_TYPE_NAME) in form
    assert SOURCE_TYPE_NAME != SOURCE_TYPE_DISPLAY


def test_submit_settings_validate_client_side():
    with pytest.raises(Exception, match="3600"):
        SubmitSettings(research_time=99999)
    with pytest.raises(Exception, match="positive"):
        SubmitSettings(research_time=0)
    with pytest.raises(Exception, match="50 characters"):
        SubmitSettings(env_preset="x" * 51)
    with pytest.raises(Exception, match="200 characters"):
        SubmitSettings(command_line_args="x" * 201)
    with pytest.raises(Exception, match="at least one|At least one"):
        SubmitSettings(analysis_types=[])
    with pytest.raises(Exception, match="2 and 150"):
        SubmitSettings(tags=["x"])


def test_submit_form_booleans_are_lowercase_strings():
    form = dict(SubmitSettings(enable_network=True, extract_archive=False).to_form())
    assert form["dynAnalysisSettings.enableNetwork"] == "true"
    assert form["extractArchive"] == "false"


# ------------------------------------------------------------------- auth


def test_auth_header_per_mode(requests_mock):
    requests_mock.get(f"{BASE}/auth/test", json={"userLogin": "svc", "userRole": "admin"})

    make_client(AUTH_SOURCE_KEY, secret="abc").whoami()
    assert requests_mock.last_request.headers["Authorization"] == "Bearer abc"

    make_client(AUTH_INTERNAL, secret="abc").whoami()
    assert requests_mock.last_request.headers["Authorization"] == "Internal abc"


def test_sign_in_token_has_no_scheme_prefix(requests_mock, mocker):
    # The legacy branch on the server looks the raw value up in the token table,
    # so prefixing it with Bearer would break authentication.
    mocker.patch("TLabAntiAPTApiModule.demisto.getIntegrationContext", return_value={})
    mocker.patch("TLabAntiAPTApiModule.demisto.setIntegrationContext")
    requests_mock.post(
        f"{BASE}/auth/sign_in",
        json={"successful": True, "token": {"tokenValue": "opaque-token", "expirationTime": 9999999999000}},
    )
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    make_client(AUTH_SIGN_IN, secret="pw", username="user").whoami()
    assert requests_mock.last_request.headers["Authorization"] == "opaque-token"


def test_sign_in_token_is_cached(requests_mock, mocker):
    context = {}
    mocker.patch("TLabAntiAPTApiModule.demisto.getIntegrationContext", side_effect=lambda: context)
    mocker.patch(
        "TLabAntiAPTApiModule.demisto.setIntegrationContext",
        side_effect=lambda value: context.update(value),
    )
    sign_in = requests_mock.post(
        f"{BASE}/auth/sign_in",
        json={"successful": True, "token": {"tokenValue": "tok", "expirationTime": 9999999999000}},
    )
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    client = make_client(AUTH_SIGN_IN, secret="pw", username="user")
    client.whoami()
    client.whoami()
    assert sign_in.call_count == 1


def test_sign_in_failure_is_reported_clearly(requests_mock, mocker):
    mocker.patch("TLabAntiAPTApiModule.demisto.getIntegrationContext", return_value={})
    requests_mock.post(f"{BASE}/auth/sign_in", json={"successful": False})
    with pytest.raises(Exception, match="username and password"):
        make_client(AUTH_SIGN_IN, secret="pw", username="user").whoami()


def test_client_header_uses_type_semicolon_name(requests_mock):
    # ClientExtractor splits on the first ';' and requires the type to be one of
    # web|mail|endpoint, otherwise the whole header is discarded silently.
    requests_mock.get(f"{BASE}/auth/test", json={})
    make_client().whoami()
    assert requests_mock.last_request.headers["X-Client"] == "endpoint;xsoar"


def test_401_message_explains_the_internal_token_restriction(requests_mock):
    requests_mock.get(f"{BASE}/auth/test", status_code=401, text="nope")
    with pytest.raises(Exception, match="127.0.0.1"):
        make_client(AUTH_INTERNAL).whoami()


def test_403_message_explains_the_role_restriction(requests_mock):
    # Internal tokens authenticate but GET /sample_reports has no branch for
    # the external_service role, so a correct token still gets 403.
    requests_mock.get(f"{BASE}/sample_reports", status_code=403, text="Forbidden")
    with pytest.raises(Exception, match="external_service"):
        make_client().list_sample_reports()


# ------------------------------------------------------------------ paging


def test_list_sample_reports_sends_repeated_array_filters(requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json={"content": [], "last": True})
    make_client().list_sample_reports(
        min_report_id=412840,
        completeness=["COMPLETE", "PARTIALLY_COMPLETE"],
        file_verdicts=["MALWARE", "SUSPICIOUS"],
        root_only=True,
    )
    query = requests_mock.last_request.qs
    assert query["minreportid"] == ["412840"]
    assert sorted(query["completeness"]) == ["complete", "partially_complete"]
    assert sorted(query["fileverdict"]) == ["malware", "suspicious"]
    assert query["rootonly"] == ["true"]
    assert query["sort"] == ["samplereportid,asc"]


def test_iter_sample_reports_stops_on_short_page(requests_mock):
    requests_mock.get(
        f"{BASE}/sample_reports",
        [
            {"json": {"content": [{"sampleReportId": i} for i in range(3)], "last": False}},
            {"json": {"content": [{"sampleReportId": 99}], "last": False}},
        ],
    )
    rows = list(make_client().iter_sample_reports(page_size=3, max_pages=10))
    assert [r["sampleReportId"] for r in rows] == [0, 1, 2, 99]


def test_iter_sample_reports_respects_max_pages(requests_mock):
    requests_mock.get(
        f"{BASE}/sample_reports",
        json={"content": [{"sampleReportId": 1}, {"sampleReportId": 2}], "last": False},
    )
    rows = list(make_client().iter_sample_reports(page_size=2, max_pages=3))
    assert len(rows) == 6


# ----------------------------------------------------------- public routes


def test_request_status_sends_no_authorization_header(requests_mock):
    # /public/** is in the server's unauthenticated path list.
    requests_mock.get(f"{BASE}/public/request_status/abc", json={"analysisRequestStatus": "ACCEPTED"})
    make_client().request_status("abc")
    assert "Authorization" not in requests_mock.last_request.headers


def test_request_status_early_verdict_flag(requests_mock):
    requests_mock.get(f"{BASE}/public/request_status/abc", json={})
    make_client().request_status("abc", early_verdict=True)
    assert requests_mock.last_request.qs["earlyverdict"] == ["true"]


def test_request_status_batch_posts_a_bare_array(requests_mock):
    requests_mock.post(f"{BASE}/public/request_status/batch", json=[])
    make_client().request_status_batch(["a", "b"])
    assert requests_mock.last_request.json() == ["a", "b"]


# --------------------------------------------------------------- artifacts


def test_download_sends_an_explicit_accept_header(requests_mock):
    # DynReportsController maps two handlers to {id}/pcap that differ only by
    # produces, so '*/*' resolves in a Spring-version-dependent way.
    requests_mock.get(f"{BASE}/dyn_reports/5/pcap", content=b"pcapdata")
    data = make_client().download("/dyn_reports/5/pcap", "application/octet-stream", max_bytes=1024)
    assert data == b"pcapdata"
    assert requests_mock.last_request.headers["Accept"] == "application/octet-stream"


def test_download_aborts_when_the_artifact_exceeds_the_limit(requests_mock):
    requests_mock.get(f"{BASE}/dyn_reports/5/memory_dump", content=b"x" * 5000)
    with pytest.raises(Exception, match="exceeds the configured limit"):
        make_client().download("/dyn_reports/5/memory_dump", "application/octet-stream", max_bytes=1000)


def test_download_without_a_limit_returns_everything(requests_mock):
    requests_mock.get(f"{BASE}/x", content=b"y" * 5000)
    assert len(make_client().download("/x", "application/json", max_bytes=0)) == 5000


# ------------------------------------------------------- tlab-auth account

AUTH = "https://tlab.example.com:8002/api"  # derived from BASE: the omni-center portal


def jwt(exp: float) -> str:
    """Unsigned JWT with an exp claim — the client never verifies signatures."""
    import base64
    import json as _json

    def b64(obj):
        return base64.urlsafe_b64encode(_json.dumps(obj).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'HS256'})}.{b64({'exp': exp, 'sub': 'svc'})}.sig"


@pytest.fixture
def context(mocker):
    store = {}
    mocker.patch("TLabAntiAPTApiModule.demisto.getIntegrationContext", side_effect=lambda: dict(store))
    mocker.patch("TLabAntiAPTApiModule.demisto.setIntegrationContext", side_effect=lambda value: store.update(value))
    return store


def test_default_auth_url_uses_the_omni_portal_over_tls():
    # Encrypted, and not https://<host>/api, which on a sandbox host is tlab-server.
    assert default_auth_url("https://10.0.0.5/api") == "https://10.0.0.5:8002/api"
    assert default_auth_url("http://tlab.example.com:8080") == "https://tlab.example.com:8002/api"
    assert default_auth_url("") == ""


def test_auth_url_answered_by_tlab_server_is_named(requests_mock, context):
    # Exactly what a sandbox host returns for /api/auth/login: Spring's error
    # shape from tlab-server, not tlab-auth.
    requests_mock.post(
        f"{AUTH}/auth/login",
        status_code=401,
        json={
            "timestamp": 1,
            "status": 401,
            "error": "Unauthorized",
            "message": "Authentication Failed: No authorizationHeader data",
            "path": "//auth/login",
        },
    )
    with pytest.raises(DemistoException, match="answered by tlab-server, not tlab-auth"):
        make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc").whoami()


def test_jwt_expiry_reads_exp_and_tolerates_garbage():
    assert jwt_expiry(jwt(1_900_000_000)) == 1_900_000_000
    assert jwt_expiry("not-a-jwt") is None


def test_tlab_account_logs_in_and_sends_bearer(requests_mock, context):
    access = jwt(time.time() + 3600)
    login = requests_mock.post(f"{AUTH}/auth/login", json={"access": access, "refresh": "r1"})
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc").whoami()

    assert login.last_request.json() == {"login": "svc", "password": "pw"}
    assert requests_mock.last_request.headers["Authorization"] == f"Bearer {access}"


def test_tlab_account_honours_explicit_auth_url(requests_mock, context):
    login = requests_mock.post("http://10.0.0.5:8033/api/auth/login", json={"access": jwt(time.time() + 3600)})
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc", auth_url="http://10.0.0.5:8033/api/").whoami()

    assert login.call_count == 1


def test_tlab_account_session_is_cached(requests_mock, context):
    login = requests_mock.post(f"{AUTH}/auth/login", json={"access": jwt(time.time() + 3600), "refresh": "r1"})
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    client = make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc")
    client.whoami()
    client.whoami()
    # A new client (the next command run) reuses the integration context too.
    make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc").whoami()

    assert login.call_count == 1


def test_tlab_account_refreshes_before_expiry(requests_mock, context):
    login = requests_mock.post(f"{AUTH}/auth/login", json={"access": jwt(time.time() + 30), "refresh": "r1"})
    fresh = jwt(time.time() + 3600)
    refresh = requests_mock.post(f"{AUTH}/auth/refresh", json={"access": fresh, "refresh": "r2"})
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    client = make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc")
    client.whoami()  # logs in; the token is already inside the refresh margin
    client.whoami()  # must refresh, not log in again

    assert login.call_count == 1
    assert refresh.call_count == 1
    assert refresh.last_request.json() == {"refresh_token": "r1"}
    assert requests_mock.last_request.headers["Authorization"] == f"Bearer {fresh}"


def test_tlab_account_falls_back_to_login_when_refresh_fails(requests_mock, context):
    login = requests_mock.post(
        f"{AUTH}/auth/login",
        [{"json": {"access": jwt(time.time() + 30), "refresh": "r1"}}, {"json": {"access": jwt(time.time() + 3600)}}],
    )
    requests_mock.post(f"{AUTH}/auth/refresh", status_code=401, json={"message": "refresh token expired"})
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    client = make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc")
    client.whoami()
    client.whoami()

    assert login.call_count == 2


def test_tlab_account_retries_once_on_sandbox_401(requests_mock, context):
    requests_mock.post(f"{AUTH}/auth/login", json={"access": jwt(time.time() + 3600), "refresh": "r1"})
    refresh = requests_mock.post(f"{AUTH}/auth/refresh", json={"access": jwt(time.time() + 3600), "refresh": "r2"})
    sandbox = requests_mock.get(f"{BASE}/auth/test", [{"status_code": 401, "text": "revoked"}, {"json": {"userRole": "admin"}}])

    assert make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc").whoami() == {"userRole": "admin"}
    assert refresh.call_count == 1
    assert sandbox.call_count == 2


def test_tlab_account_does_not_loop_on_persistent_401(requests_mock, context):
    requests_mock.post(f"{AUTH}/auth/login", json={"access": jwt(time.time() + 3600), "refresh": "r1"})
    requests_mock.post(f"{AUTH}/auth/refresh", json={"access": jwt(time.time() + 3600), "refresh": "r2"})
    sandbox = requests_mock.get(f"{BASE}/auth/test", status_code=401, text="nope")

    with pytest.raises(DemistoException, match="401"):
        make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc").whoami()
    assert sandbox.call_count == 2


def test_tlab_account_wrong_password_is_tried_once(requests_mock, context):
    # A second attempt with the same wrong password would count twice towards
    # the account lockout in tlab-auth.
    login = requests_mock.post(f"{AUTH}/auth/login", status_code=401, json={"message": "invalid login or password"})

    with pytest.raises(Exception, match="invalid login or password"):
        make_client(AUTH_TLAB_ACCOUNT, secret="bad", username="svc").whoami()
    assert login.call_count == 1


def test_tlab_account_relogs_when_the_account_changes(requests_mock, context):
    login = requests_mock.post(f"{AUTH}/auth/login", json={"access": jwt(time.time() + 3600), "refresh": "r1"})
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc").whoami()
    make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="other").whoami()

    assert login.call_count == 2


def test_tlab_account_without_any_host_explains_itself(context):
    client = TLabClient(base_url="", auth_mode=AUTH_TLAB_ACCOUNT, credentials={"identifier": "svc", "password": "pw"})
    with pytest.raises(Exception, match="Auth server URL"):
        client.whoami()


def test_stored_file_verdict_hides_the_unset_default():
    # Written only by the manual /files/{sha256|id}/verdict routes; UNKNOWN
    # means nobody set it.
    assert stored_file_verdict("UNKNOWN") is None
    assert stored_file_verdict(None) is None
    assert stored_file_verdict("") is None
    assert stored_file_verdict("whitelist") == "WHITELIST"
    assert stored_file_verdict("MALWARE") == "MALWARE"
