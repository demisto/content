import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest
from AWSSNSListener import (
    Response,  # re-exported via `from fastapi import ... Response`
    SNSCertificateManager,
    handle_notification,
    is_valid_integration_credentials,
    status,  # re-exported via `from fastapi import ... status`
)
from CommonServerPython import DemistoException

VALID_PAYLOAD = {
    "Type": "Notification",
    "MessageId": "uuid",
    "TopicArn": "topicarn",
    "Subject": "NotificationSubject",
    "Message": "NotificationMessage",
    "Timestamp": "2024-02-13T18:03:27.239Z",
    "SignatureVersion": "1",
    "Signature": "sign",
    "SigningCertURL": "https://sns.example.amazonaws.com",
}


@pytest.fixture
def mock_params(mocker):
    return mocker.patch("AWSSNSListener.PARAMS", new={"credentials": {"identifier": "foo", "password": "bar"}}, autospec=False)


def test_handle_notification_valid():
    """
    Given a valid SNS notification message
    When handle_notification is called with the message and raw json
    Then should parse to a valid incident
    """
    raw_json = {}
    expected_notification = {
        "name": "NotificationSubject",
        "labels": [],
        "rawJSON": raw_json,
        "occurred": "2024-02-13T18:03:27.239Z",
        "details": "ExternalID:uuid TopicArn:topicarn Message:NotificationMessage",
        "type": "AWS-SNS Notification",
    }

    actual_incident = handle_notification(VALID_PAYLOAD, raw_json)

    assert actual_incident == expected_notification


@patch("AWSSNSListener.X509")
@patch("M2Crypto.EVP.PKey")
def test_is_valid_sns_message(mock_PKey, mock_x509, requests_mock):
    """
    Given a valid SNS payload whose SigningCertURL serves a (mocked) certificate
    When SNSCertificateManager.is_valid_sns_message() is called
    Then the signature verification path returns True.
    """
    sNSCertificateManager = SNSCertificateManager()
    requests_mock.get(VALID_PAYLOAD["SigningCertURL"], text="-----BEGIN CERT-----\n-----END CERT-----")
    mock_PKey.verify_final.return_value = 1
    mock_x509.get_pubkey.return_value = mock_PKey
    mock_x509.load_cert_string.return_value = mock_x509
    mock_x509.get_subject.return_value = MagicMock(CN="sns.amazonaws.com")
    assert sNSCertificateManager.is_valid_sns_message(VALID_PAYLOAD)


@patch("AWSSNSListener.X509")
@patch("M2Crypto.EVP.PKey")
def test_not_valid_sns_message(mock_PKey, mock_x509, requests_mock, capfd):
    """
    Given a valid SNS payload whose signature fails verification
    When SNSCertificateManager.is_valid_sns_message() is called
    Then the method returns False.
    """
    sNSCertificateManager = SNSCertificateManager()
    requests_mock.get(VALID_PAYLOAD["SigningCertURL"], text="-----BEGIN CERT-----\n-----END CERT-----")
    mock_PKey.verify_final.return_value = 2
    mock_x509.get_pubkey.return_value = mock_PKey
    mock_x509.load_cert_string.return_value = mock_x509
    mock_x509.get_subject.return_value = MagicMock(CN="sns.amazonaws.com")
    with capfd.disabled():
        assert sNSCertificateManager.is_valid_sns_message(VALID_PAYLOAD) is False


@patch("fastapi.security.http.HTTPBasicCredentials")
def test_valid_credentials(mock_httpBasicCredentials, mock_params):
    """
    Given valid credentials, request headers and token
    When is_valid_integration_credentials is called
    Then it should return True, header_name
    """
    mock_httpBasicCredentials.username = "foo"
    mock_httpBasicCredentials.password = "bar"
    request_headers = {}
    token = "sometoken"
    result, header_name = is_valid_integration_credentials(mock_httpBasicCredentials, request_headers, token)
    assert result is True
    assert header_name is None


@patch("fastapi.security.http.HTTPBasicCredentials")
def test_invalid_credentials(mock_httpBasicCredentials, mock_params):
    """
    Given invalid credentials, request headers and token
    When is_valid_integration_credentials is called
    Then it should return True, header_name
    """
    mock_httpBasicCredentials.username = "foot"
    mock_httpBasicCredentials.password = "bark"
    request_headers = {}
    token = "sometoken"
    result, header_name = is_valid_integration_credentials(mock_httpBasicCredentials, request_headers, token)
    assert result is False


class TestValidateSnsUrl:
    """Tests for URL format validation in _validate_sns_url."""

    def test_valid_aws_sns_url_accepted(self):
        """Test that a valid AWS SNS URL passes validation."""
        from AWSSNSListener import _validate_sns_url

        _validate_sns_url("https://sns.us-east-1.amazonaws.com/cert.pem", "SigningCertURL")

    def test_valid_aws_china_url_accepted(self):
        """Test that a valid AWS China region URL passes validation."""
        from AWSSNSListener import _validate_sns_url

        _validate_sns_url("https://sns.cn-north-1.amazonaws.com.cn/cert.pem", "SigningCertURL")

    def test_non_https_url_rejected(self):
        """Test that a non-HTTPS URL is rejected."""
        from AWSSNSListener import _validate_sns_url

        with pytest.raises(DemistoException, match="must use HTTPS"):
            _validate_sns_url("http://sns.us-east-1.amazonaws.com/cert.pem", "SigningCertURL")

    def test_non_aws_host_rejected(self):
        """Test that a non-AWS host is rejected."""
        from AWSSNSListener import _validate_sns_url

        with pytest.raises(DemistoException, match="not an AWS SNS endpoint"):
            _validate_sns_url("https://attacker.example.com/cert.pem", "SigningCertURL")

    def test_aws_like_subdomain_rejected(self):
        """Test that a URL with an AWS-like subdomain on a different host is rejected."""
        from AWSSNSListener import _validate_sns_url

        with pytest.raises(DemistoException, match="not an AWS SNS endpoint"):
            _validate_sns_url("https://sns.us-east-1.amazonaws.com.evil.com/cert.pem", "SigningCertURL")


# ---------------------------------------------------------------------------
# Helpers / fixtures for the new (concurrent) and old (sequential) flow tests
# ---------------------------------------------------------------------------


def _make_payload(**overrides):
    """Return a fresh copy of VALID_PAYLOAD with optional field overrides."""
    payload = dict(VALID_PAYLOAD)
    payload.update(overrides)
    return payload


def _make_prep(payload=None, type_="Notification", params=None, req_id="testreq"):
    """Build the `prep` dict that `_process_request_blocking` expects.

    Mirrors the contract produced by `_prepare_request`.
    """
    pl = payload if payload is not None else _make_payload()
    return {
        "payload": pl,
        "raw_json": json.dumps(pl),
        "type": type_,
        "params": params or {},
        "req_id": req_id,
    }


@pytest.fixture
def reset_inflight():
    """Force the module-level in-flight gauges back to zero between tests."""
    import AWSSNSListener as mod

    with mod._inflight_lock:
        mod._inflight = 0
        mod._inflight_peak = 0
    yield
    with mod._inflight_lock:
        mod._inflight = 0
        mod._inflight_peak = 0


@pytest.fixture
def stub_install_sample_executor(mocker):
    """Replace `_install_sample_executor` with a synchronous stub.

    Lets us assert `store_samples` was called without spinning a real thread.
    """
    import AWSSNSListener as mod

    class _Sync:
        def submit(self, fn):
            fn()
            return MagicMock()

    mocker.patch.object(mod, "_install_sample_executor", return_value=_Sync())
    # Reset the pending counter so each test starts from a clean slate.
    with mod._sample_pending_lock:
        mod._sample_pending = 0
    yield
    with mod._sample_pending_lock:
        mod._sample_pending = 0


# ---------------------------------------------------------------------------
# Processing-mode resolution
# ---------------------------------------------------------------------------


class TestResolveProcessingMode:
    """Covers the routing key that selects the OLD vs NEW SNS pipeline."""

    def test_default_is_sequential(self, mocker):
        """
        Given no `processing_mode` is configured in integration params
        When _resolve_processing_mode is called
        Then it returns "sequential" (the legacy/old flow is the safe default)
        """
        from AWSSNSListener import _resolve_processing_mode

        mocker.patch("AWSSNSListener.demisto.params", return_value={})
        assert _resolve_processing_mode() == "sequential"

    def test_concurrent_selected_when_configured(self):
        """
        Given params explicitly set `processing_mode=concurrent`
        When _resolve_processing_mode is called with those params
        Then it returns "concurrent" (the new thread-pool flow is selected)
        """
        from AWSSNSListener import _resolve_processing_mode

        assert _resolve_processing_mode({"processing_mode": "concurrent"}) == "concurrent"

    def test_unknown_value_falls_back_to_sequential(self):
        """
        Given params contain a garbage `processing_mode` value
        When _resolve_processing_mode is called
        Then it falls back to "sequential" instead of crashing the integration
        """
        from AWSSNSListener import _resolve_processing_mode

        assert _resolve_processing_mode({"processing_mode": "asyncio-magic"}) == "sequential"


# ---------------------------------------------------------------------------
# `_process_request_blocking` — the core pipeline used by BOTH flows
# ---------------------------------------------------------------------------


class TestProcessRequestBlocking:
    """`_process_request_blocking` body runs identically in old and new flow."""

    def test_notification_creates_incident(self, mocker, reset_inflight):
        """
        Given a valid SNS Notification whose signature verifies
        When _process_request_blocking runs the pipeline
        Then demisto.createIncidents is invoked once and its result is returned
        """
        import AWSSNSListener as mod

        mocker.patch.object(mod.sns_cert_manager, "is_valid_sns_message", return_value=True)
        create = mocker.patch.object(mod.demisto, "createIncidents", return_value=[{"id": "1"}])

        result = mod._process_request_blocking(_make_prep())

        create.assert_called_once()
        assert result == [{"id": "1"}]

    def test_notification_invalid_signature_returns_401(self, mocker, reset_inflight):
        """
        Given an SNS Notification whose signature fails verification
        When _process_request_blocking runs the pipeline
        Then it returns a 401 Response and no incident is created
        """
        import AWSSNSListener as mod

        mocker.patch.object(mod.sns_cert_manager, "is_valid_sns_message", return_value=False)
        create = mocker.patch.object(mod.demisto, "createIncidents")

        result = mod._process_request_blocking(_make_prep())

        assert isinstance(result, Response)
        assert result.status_code == status.HTTP_401_UNAUTHORIZED
        create.assert_not_called()

    def test_notification_create_failure_returns_503(self, mocker, reset_inflight):
        """
        Given demisto.createIncidents returns empty (server-side failure)
        When _process_request_blocking runs the pipeline
        Then it returns a 503 Response so SNS retries (not a silent 200)
        """
        import AWSSNSListener as mod

        mocker.patch.object(mod.sns_cert_manager, "is_valid_sns_message", return_value=True)
        mocker.patch.object(mod.demisto, "createIncidents", return_value=None)
        # Mock `demisto.error` so the failure log doesn't hit stdout (conftest's
        # check_std_out_err would otherwise fail the test) — and so we can assert
        # the failure was actually logged.
        err = mocker.patch.object(mod.demisto, "error")

        result = mod._process_request_blocking(_make_prep())

        assert isinstance(result, Response)
        assert result.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        err.assert_called_once()

    def test_notification_triggers_store_samples_when_enabled(self, mocker, reset_inflight, stub_install_sample_executor):
        """
        Given params include `store_samples=True` and the executor is stubbed
        When _process_request_blocking processes a valid Notification
        Then store_samples is invoked via the (stubbed) background writer
        """
        import AWSSNSListener as mod

        mocker.patch.object(mod.sns_cert_manager, "is_valid_sns_message", return_value=True)
        mocker.patch.object(mod.demisto, "createIncidents", return_value=[{"id": "1"}])
        store_spy = mocker.patch.object(mod, "store_samples")

        mod._process_request_blocking(_make_prep(params={"store_samples": True}))

        store_spy.assert_called_once()

    def test_notification_skips_store_samples_when_disabled(self, mocker, reset_inflight, stub_install_sample_executor):
        """
        Given params do NOT include the `store_samples` flag
        When _process_request_blocking processes a valid Notification
        Then store_samples is never invoked (no wasted writes to integration context)
        """
        import AWSSNSListener as mod

        mocker.patch.object(mod.sns_cert_manager, "is_valid_sns_message", return_value=True)
        mocker.patch.object(mod.demisto, "createIncidents", return_value=[{"id": "1"}])
        store_spy = mocker.patch.object(mod, "store_samples")

        mod._process_request_blocking(_make_prep(params={}))

        store_spy.assert_not_called()

    def test_subscription_confirmation_success(self, mocker, reset_inflight):
        """
        Given a valid SubscriptionConfirmation payload and a 200 from SubscribeURL
        When _process_request_blocking runs the pipeline
        Then it returns a Response carrying the upstream status code (200)
        """
        import AWSSNSListener as mod

        mocker.patch.object(mod.sns_cert_manager, "is_valid_sns_message", return_value=True)
        upstream = MagicMock(status_code=200)
        mocker.patch.object(mod, "handle_subscription_confirmation", return_value=upstream)

        payload = _make_payload(Type="SubscriptionConfirmation", SubscribeURL="https://sns.example.amazonaws.com")
        result = mod._process_request_blocking(_make_prep(payload=payload, type_="SubscriptionConfirmation"))

        assert isinstance(result, Response)
        assert result.status_code == 200

    def test_subscription_confirmation_upstream_failure_returns_503(self, mocker, reset_inflight):
        """
        Given a SubscriptionConfirmation whose SubscribeURL fetch raises an error
        When _process_request_blocking runs the pipeline
        Then it returns 503 so SNS retries (instead of a fake 200 that breaks the topic)
            and the failure is logged via demisto.error
        """
        import AWSSNSListener as mod

        mocker.patch.object(mod.sns_cert_manager, "is_valid_sns_message", return_value=True)
        mocker.patch.object(mod, "handle_subscription_confirmation", side_effect=RuntimeError("network"))
        err = mocker.patch.object(mod.demisto, "error")

        payload = _make_payload(Type="SubscriptionConfirmation", SubscribeURL="https://sns.example.amazonaws.com")
        result = mod._process_request_blocking(_make_prep(payload=payload, type_="SubscriptionConfirmation"))

        assert isinstance(result, Response)
        assert result.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        err.assert_called_once()

    def test_unsubscribe_confirmation_returns_message(self, mocker, reset_inflight):
        """
        Given a valid UnsubscribeConfirmation payload
        When _process_request_blocking runs the pipeline
        Then it returns a short text acknowledgement containing the upstream Message
        """
        import AWSSNSListener as mod

        mocker.patch.object(mod.sns_cert_manager, "is_valid_sns_message", return_value=True)

        payload = _make_payload(Type="UnsubscribeConfirmation", Message="goodbye")
        result = mod._process_request_blocking(_make_prep(payload=payload, type_="UnsubscribeConfirmation"))

        assert isinstance(result, str)
        assert "goodbye" in result

    def test_unknown_type_returns_400(self, mocker, reset_inflight):
        """
        Given an SNS payload with an unsupported `Type` value
        When _process_request_blocking runs the pipeline
        Then it returns 400 Bad Request (client error — don't make SNS retry forever)
            and the unknown-type failure is logged via demisto.error
        """
        import AWSSNSListener as mod

        mocker.patch.object(mod.sns_cert_manager, "is_valid_sns_message", return_value=True)
        err = mocker.patch.object(mod.demisto, "error")
        payload = _make_payload(Type="WeirdType")

        result = mod._process_request_blocking(_make_prep(payload=payload, type_="WeirdType"))

        assert isinstance(result, Response)
        assert result.status_code == status.HTTP_400_BAD_REQUEST
        err.assert_called_once()

    def test_inflight_counters_increment_and_decrement(self, mocker, reset_inflight):
        """
        Given a request entering the pipeline
        When _process_request_blocking runs and then exits
        Then _inflight is 1 during processing, peak is recorded, and current returns to 0
        """
        import AWSSNSListener as mod

        observed = {}

        def _check_inflight(_payload):
            with mod._inflight_lock:
                observed["during"] = mod._inflight
            return True

        mocker.patch.object(mod.sns_cert_manager, "is_valid_sns_message", side_effect=_check_inflight)
        mocker.patch.object(mod.demisto, "createIncidents", return_value=[{"id": "1"}])

        mod._process_request_blocking(_make_prep())

        with mod._inflight_lock:
            after = mod._inflight
            peak = mod._inflight_peak
        assert observed["during"] == 1
        assert after == 0
        assert peak >= 1

    def test_raw_json_built_in_worker_when_missing(self, mocker, reset_inflight):
        """
        Given a `prep` dict with no pre-built `raw_json` (the concurrent-mode shape)
        When _process_request_blocking runs the pipeline
        Then the worker builds raw_json from payload and propagates it into the incident
            (proves json.dumps stays off the event loop in concurrent mode)
        """
        import AWSSNSListener as mod

        mocker.patch.object(mod.sns_cert_manager, "is_valid_sns_message", return_value=True)
        captured = {}

        def _capture(incidents):
            captured["incident"] = incidents[0]
            return [{"id": "1"}]

        mocker.patch.object(mod.demisto, "createIncidents", side_effect=_capture)

        payload = _make_payload()
        prep = _make_prep(payload=payload)
        prep.pop("raw_json")
        mod._process_request_blocking(prep)

        # raw_json was constructed by the worker and propagated into the incident.
        assert captured["incident"]["rawJSON"] == json.dumps(payload)


# ---------------------------------------------------------------------------
# `handle_post` — proves OLD and NEW flow dispatch correctly
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine to completion in a fresh event loop.

    Lets us call `async def` functions (like `handle_post`) from synchronous
    pytest tests without pulling in `pytest-asyncio`.
    """
    return asyncio.run(coro)


class TestHandlePostDispatch:
    """The router decides between inline (old) and threadpool (new) execution."""

    def test_old_flow_runs_inline_in_sequential_mode(self, mocker, reset_inflight):
        """
        Given _prepare_request yields a prep dict with `processing_mode=sequential`
        When handle_post dispatches the request
        Then _process_request_blocking is called inline (no asyncio.to_thread hop)
        """
        import AWSSNSListener as mod

        mocker.patch.object(
            mod,
            "_prepare_request",
            return_value={"payload": {}, "type": "Notification", "params": {"processing_mode": "sequential"}, "req_id": "r1"},
        )
        blocking = mocker.patch.object(mod, "_process_request_blocking", return_value="OLD")
        to_thread = mocker.patch.object(mod.asyncio, "to_thread")

        result = _run(mod.handle_post(MagicMock(), MagicMock(), MagicMock()))

        assert result == "OLD"
        blocking.assert_called_once()
        to_thread.assert_not_called()

    def test_new_flow_dispatches_to_thread_in_concurrent_mode(self, mocker, reset_inflight):
        """
        Given _prepare_request yields a prep dict with `processing_mode=concurrent`
        When handle_post dispatches the request
        Then the worker is invoked through asyncio.to_thread (heavy work off the event loop)
        """
        import AWSSNSListener as mod

        mocker.patch.object(
            mod,
            "_prepare_request",
            return_value={"payload": {}, "type": "Notification", "params": {"processing_mode": "concurrent"}, "req_id": "r2"},
        )
        mocker.patch.object(mod, "_install_default_executor")
        blocking = mocker.patch.object(mod, "_process_request_blocking", return_value="NEW")

        async def _fake_to_thread(fn, prep):
            # Mirror the real call path: invoke synchronously and return.
            return fn(prep)

        mocker.patch.object(mod.asyncio, "to_thread", side_effect=_fake_to_thread)

        result = _run(mod.handle_post(MagicMock(), MagicMock(), MagicMock()))

        assert result == "NEW"
        blocking.assert_called_once()

    def test_handle_post_returns_prepare_response_immediately(self, mocker, reset_inflight):
        """
        Given _prepare_request returns a Response (e.g. 401 auth failure)
        When handle_post dispatches the request
        Then that Response is returned as-is and the pipeline is never invoked
        """
        import AWSSNSListener as mod

        early = Response(status_code=status.HTTP_401_UNAUTHORIZED, content="nope")
        mocker.patch.object(mod, "_prepare_request", return_value=early)
        blocking = mocker.patch.object(mod, "_process_request_blocking")

        result = _run(mod.handle_post(MagicMock(), MagicMock(), MagicMock()))

        assert result is early
        blocking.assert_not_called()


# ---------------------------------------------------------------------------
# Sample-writer back-pressure (`_submit_store_samples`)
# ---------------------------------------------------------------------------


class TestSubmitStoreSamples:
    """The background writer must not block callers and must drop when full."""

    def test_submits_to_executor(self, mocker, stub_install_sample_executor):
        """
        Given the background executor is stubbed to run synchronously
        When _submit_store_samples is called with an incident
        Then store_samples is invoked once with that incident
        """
        import AWSSNSListener as mod

        store = mocker.patch.object(mod, "store_samples")
        mod._submit_store_samples({"name": "x"}, "req-1")
        store.assert_called_once_with({"name": "x"})

    def test_drops_when_backlog_full(self, mocker):
        """
        Given the pending-writes gauge is already at _SAMPLE_PENDING_MAX (back-pressure)
        When _submit_store_samples is called
        Then the submission is dropped, store_samples is never invoked,
            and the drop is logged via demisto.error
        """
        import AWSSNSListener as mod

        store = mocker.patch.object(mod, "store_samples")
        err = mocker.patch.object(mod.demisto, "error")
        # Saturate the gauge so the next submit hits the drop path.
        with mod._sample_pending_lock:
            mod._sample_pending = mod._SAMPLE_PENDING_MAX

        try:
            mod._submit_store_samples({"name": "x"}, "req-drop")
            store.assert_not_called()
            err.assert_called_once()
        finally:
            with mod._sample_pending_lock:
                mod._sample_pending = 0

    def test_swallows_executor_runtime_error(self, mocker):
        """
        Given the executor is shut down and its submit() raises RuntimeError
        When _submit_store_samples is called
        Then the exception is swallowed, the pending gauge is rolled back to 0,
            and the failure is logged via demisto.error
        """
        import AWSSNSListener as mod

        broken = MagicMock()
        broken.submit.side_effect = RuntimeError("shutdown")
        mocker.patch.object(mod, "_install_sample_executor", return_value=broken)
        err = mocker.patch.object(mod.demisto, "error")

        with mod._sample_pending_lock:
            mod._sample_pending = 0
        mod._submit_store_samples({"name": "x"}, "req-shutdown")
        # Gauge must be rolled back so future submits aren't permanently blocked.
        with mod._sample_pending_lock:
            assert mod._sample_pending == 0
        err.assert_called_once()


# ---------------------------------------------------------------------------
# In-flight gauge helpers
# ---------------------------------------------------------------------------


class TestInflightGauges:
    """`_inflight_enter` / `_inflight_exit` track concurrent processing."""

    def test_enter_increments_and_tracks_peak(self, reset_inflight):
        """
        Given the in-flight gauges start at zero
        When _inflight_enter() is called twice
        Then current goes 1 then 2, and peak is updated to at least 2
        """
        import AWSSNSListener as mod

        cur1, peak1 = mod._inflight_enter()
        cur2, peak2 = mod._inflight_enter()
        assert cur1 == 1
        assert cur2 == 2
        assert peak2 >= 2

    def test_exit_decrements(self, reset_inflight):
        """
        Given two prior _inflight_enter() calls
        When _inflight_exit() is called once
        Then the returned current value is the post-decrement count (1)
        """
        import AWSSNSListener as mod

        mod._inflight_enter()
        mod._inflight_enter()
        remaining = mod._inflight_exit()
        assert remaining == 1


# ---------------------------------------------------------------------------
# Thread-local client (one AWS_SNS_CLIENT per worker thread)
# ---------------------------------------------------------------------------


class TestThreadLocalClient:
    """`_get_thread_local_client` returns one shared client per thread."""

    def test_same_thread_returns_same_instance(self, mocker):
        """
        Given thread-local client state is reset
        When _get_thread_local_client() is called twice on the same thread
        Then both calls return the SAME client instance (caching avoids new boto sessions)
        """
        import AWSSNSListener as mod

        # Reset any pre-existing client on this thread.
        if hasattr(mod._thread_local, "client"):
            del mod._thread_local.client
        mocker.patch.object(mod, "AWS_SNS_CLIENT", return_value=MagicMock(name="client"))
        c1 = mod._get_thread_local_client()
        c2 = mod._get_thread_local_client()
        assert c1 is c2

    def test_different_threads_get_different_clients(self, mocker):
        """
        Given thread-local client state is reset and one client is obtained on the main thread
        When a worker thread calls _get_thread_local_client()
        Then the worker thread receives a different client instance (per-thread isolation)
        """
        import threading
        import AWSSNSListener as mod

        if hasattr(mod._thread_local, "client"):
            del mod._thread_local.client
        mocker.patch.object(mod, "AWS_SNS_CLIENT", side_effect=lambda: MagicMock(name="client"))
        main_client = mod._get_thread_local_client()

        other = {}

        def _worker():
            other["client"] = mod._get_thread_local_client()

        t = threading.Thread(target=_worker)
        t.start()
        t.join()
        assert other["client"] is not main_client


# ---------------------------------------------------------------------------
# `handle_notification` edge case — missing Subject
# ---------------------------------------------------------------------------


def test_handle_notification_missing_subject_uses_fallback():
    """
    Given an SNS Notification payload with no `Subject` field (Subject is optional in AWS SNS)
    When handle_notification builds the incident
    Then the incident `name` falls back to "AWS-SNS Notification <MessageId>" instead of crashing
    """
    payload = _make_payload()
    payload.pop("Subject")
    payload["MessageId"] = "abc-123"

    incident = handle_notification(payload, raw_json={})

    assert incident["name"] == "AWS-SNS Notification abc-123"


# ---------------------------------------------------------------------------
# Certificate cache eviction semantics
# ---------------------------------------------------------------------------


class TestCertCacheEviction:
    """`_evict_if_url_matches` must only evict the URL it was told about."""

    def test_evict_matching_url(self):
        """
        Given a cache populated with URL A
        When _evict_if_url_matches is called with URL A
        Then the cache is cleared
        """
        mgr = SNSCertificateManager()
        mgr._commit_cache("URL", "testtest")
        mgr._evict_if_url_matches("URL")
        assert mgr._cached is None
        assert mgr.cached_cert_text is None

    def test_evict_non_matching_url_keeps_cache(self):
        """
        Given a cache populated with URL A
        When _evict_if_url_matches is called with a different URL B
        Then the cache for URL A is preserved (a transient B failure must not poison A)
        """
        mgr = SNSCertificateManager()
        mgr._commit_cache("https://URL/A.pem", "testtest")
        mgr._evict_if_url_matches("https://URL/B.pem")
        assert mgr._cached == ("https://URL/A.pem", "testtest")

    @patch("AWSSNSListener.X509")
    def test_cache_hit_skips_fetch(self, mock_x509, requests_mock):
        """
        Given the cert cache is pre-populated for SigningCertURL
            and a stub HTTP endpoint that would return 500 if hit
        When _load_cached_cert_text is called
        Then the cached PEM is returned and no HTTP fetch happens
        """
        mgr = SNSCertificateManager()
        mgr._commit_cache(VALID_PAYLOAD["SigningCertURL"], "testtest")
        # Set up the mock so a real fetch would FAIL the test (registers a 500).
        requests_mock.get(VALID_PAYLOAD["SigningCertURL"], status_code=500)

        result = mgr._load_cached_cert_text(VALID_PAYLOAD)

        assert result == "testtest"

    @patch("AWSSNSListener.X509")
    def test_non_aws_subject_cn_rejected(self, mock_x509, requests_mock, mocker):
        """
        Given a fetched cert whose subject CN is not under amazonaws.com
        When _load_cached_cert_text validates the cert
        Then None is returned, the bogus cert is NOT committed to the cache,
            and the rejection is logged via demisto.error
        """
        import AWSSNSListener as mod

        mgr = SNSCertificateManager()
        requests_mock.get(VALID_PAYLOAD["SigningCertURL"], text="-----BEGIN CERT-----\n-----END CERT-----")
        mock_x509.load_cert_string.return_value = mock_x509
        mock_x509.get_subject.return_value = MagicMock(CN="attacker.example.com")
        err = mocker.patch.object(mod.demisto, "error")

        result = mgr._load_cached_cert_text(VALID_PAYLOAD)

        assert result is None
        # And the bogus cert must NOT be committed to cache.
        assert mgr._cached is None
        err.assert_called_once()
