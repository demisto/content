"""Hermetic unit tests for the post-create UCP instance verification helpers.

These cover the defensive "did the instance ACTUALLY get created?" probe added
to diagnose/guard the observed case where ``POST /instances`` returns 201 but
the instance does not actually exist (it never showed up in the UI).

Everything is hermetic: ``requests`` is monkeypatched so NO network is hit, and
the orchestration function is tested by monkeypatching the lower-level helpers
(``get_ucp_instance`` / ``list_ucp_instances``) so the routing logic is isolated.

Tested units:
  * get_ucp_instance — single-instance GET (best-effort, never raises).
  * list_ucp_instances — list fallback (bare list or wrapped, never raises).
  * verify_ucp_instance_created — orchestration over the above, returning a
    clear {"exists", "instance_id", "status", "via"} dict.
"""
from __future__ import annotations

import ucp_capture


# ---------------------------------------------------------------------------
# Fake requests response + a scriptable requests.get replacement
# ---------------------------------------------------------------------------

class _FakeResp:
    """Minimal stand-in for a ``requests.Response``."""

    def __init__(self, status_code=200, json_data=None, text="", raise_on_json=False):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self._raise_on_json = raise_on_json

    def json(self):
        if self._raise_on_json:
            raise ValueError("not json")
        return self._json_data


class _Recorder:
    """Records the URLs requested and returns scripted responses by URL match.

    ``responses`` maps a substring-of-URL → either a _FakeResp or an Exception
    instance (which is raised to simulate a transport error).
    """

    def __init__(self, responses):
        self.responses = responses
        self.calls: list[str] = []

    def __call__(self, url, headers=None, **kwargs):
        self.calls.append(url)
        for needle, resp in self.responses.items():
            if needle in url:
                if isinstance(resp, Exception):
                    raise resp
                return resp
        raise AssertionError(f"unexpected URL requested: {url}")


# ===========================================================================
# get_ucp_instance
# ===========================================================================

def test_get_ucp_instance_200_returns_body(monkeypatch):
    body = {"id": "abc", "name": "n", "status": "ENABLED"}
    rec = _Recorder({"/instances/abc": _FakeResp(200, json_data=body)})
    monkeypatch.setattr(ucp_capture.requests, "get", rec)

    out = ucp_capture.get_ucp_instance("abc", "tenant-1", port=8080)

    assert out == body
    assert rec.calls == ["http://localhost:8080/api/v1/instances/abc"]


def test_get_ucp_instance_404_returns_none(monkeypatch):
    rec = _Recorder({"/instances/abc": _FakeResp(404, text="not found")})
    monkeypatch.setattr(ucp_capture.requests, "get", rec)

    out = ucp_capture.get_ucp_instance("abc", "tenant-1")

    assert out is None


def test_get_ucp_instance_transport_error_returns_none(monkeypatch):
    rec = _Recorder({"/instances/abc": ConnectionError("boom")})
    monkeypatch.setattr(ucp_capture.requests, "get", rec)

    # Must NOT raise — best-effort helper.
    out = ucp_capture.get_ucp_instance("abc", "tenant-1")

    assert out is None


def test_get_ucp_instance_200_unparseable_returns_none(monkeypatch):
    rec = _Recorder({"/instances/abc": _FakeResp(200, raise_on_json=True)})
    monkeypatch.setattr(ucp_capture.requests, "get", rec)

    out = ucp_capture.get_ucp_instance("abc", "tenant-1")

    assert out is None


# ===========================================================================
# list_ucp_instances
# ===========================================================================

def test_list_ucp_instances_bare_list(monkeypatch):
    data = [{"id": "a"}, {"id": "b"}]
    rec = _Recorder({"/instances": _FakeResp(200, json_data=data)})
    monkeypatch.setattr(ucp_capture.requests, "get", rec)

    out = ucp_capture.list_ucp_instances("tenant-1", port=9000)

    assert out == data
    assert rec.calls == ["http://localhost:9000/api/v1/instances"]


def test_list_ucp_instances_wrapped_instances_key(monkeypatch):
    data = {"instances": [{"id": "a"}], "page": 1}
    rec = _Recorder({"/instances": _FakeResp(200, json_data=data)})
    monkeypatch.setattr(ucp_capture.requests, "get", rec)

    out = ucp_capture.list_ucp_instances("tenant-1")

    assert out == [{"id": "a"}]


def test_list_ucp_instances_wrapped_data_key(monkeypatch):
    data = {"data": [{"id": "z"}]}
    rec = _Recorder({"/instances": _FakeResp(200, json_data=data)})
    monkeypatch.setattr(ucp_capture.requests, "get", rec)

    out = ucp_capture.list_ucp_instances("tenant-1")

    assert out == [{"id": "z"}]


def test_list_ucp_instances_non_200_returns_none(monkeypatch):
    rec = _Recorder({"/instances": _FakeResp(500, text="boom")})
    monkeypatch.setattr(ucp_capture.requests, "get", rec)

    out = ucp_capture.list_ucp_instances("tenant-1")

    assert out is None


def test_list_ucp_instances_transport_error_returns_none(monkeypatch):
    rec = _Recorder({"/instances": ConnectionError("down")})
    monkeypatch.setattr(ucp_capture.requests, "get", rec)

    out = ucp_capture.list_ucp_instances("tenant-1")

    assert out is None


def test_list_ucp_instances_unexpected_shape_returns_none(monkeypatch):
    # A dict with no list-valued known key → None.
    rec = _Recorder({"/instances": _FakeResp(200, json_data={"foo": "bar"})})
    monkeypatch.setattr(ucp_capture.requests, "get", rec)

    out = ucp_capture.list_ucp_instances("tenant-1")

    assert out is None


# ===========================================================================
# verify_ucp_instance_created — orchestration (monkeypatch the helpers)
# ===========================================================================

def test_verify_via_get_id_success(monkeypatch):
    """POST-response id is directly retrievable → exists True, via 'get-id'."""
    monkeypatch.setattr(
        ucp_capture, "get_ucp_instance",
        lambda cid, tenant, port=8080: {"id": cid, "status": "ENABLED"} if cid == "post-id" else None,
    )
    monkeypatch.setattr(ucp_capture, "list_ucp_instances", lambda *a, **k: None)

    out = ucp_capture.verify_ucp_instance_created(
        creation_view_id="creation-id",
        post_response={"id": "post-id", "status": "PENDING"},
        tenant_id="t",
    )

    assert out["exists"] is True
    assert out["instance_id"] == "post-id"
    assert out["status"] == "ENABLED"
    assert out["via"] == "get-id"


def test_verify_falls_back_to_creation_id(monkeypatch):
    """POST id 404s, creation-view id is retrievable → via 'get-creation-id'."""
    monkeypatch.setattr(
        ucp_capture, "get_ucp_instance",
        lambda cid, tenant, port=8080: {"id": cid, "status": "ENABLED"} if cid == "creation-id" else None,
    )
    monkeypatch.setattr(ucp_capture, "list_ucp_instances", lambda *a, **k: None)

    out = ucp_capture.verify_ucp_instance_created(
        creation_view_id="creation-id",
        post_response={"id": "post-id", "status": "PENDING"},
        tenant_id="t",
    )

    assert out["exists"] is True
    assert out["instance_id"] == "creation-id"
    assert out["via"] == "get-creation-id"


def test_verify_falls_back_to_list(monkeypatch):
    """Both single GETs fail; list route contains the id → via 'list'."""
    monkeypatch.setattr(ucp_capture, "get_ucp_instance", lambda *a, **k: None)
    monkeypatch.setattr(
        ucp_capture, "list_ucp_instances",
        lambda *a, **k: [{"id": "other"}, {"id": "post-id", "status": "ACTIVE"}],
    )

    out = ucp_capture.verify_ucp_instance_created(
        creation_view_id="creation-id",
        post_response={"id": "post-id", "status": "PENDING"},
        tenant_id="t",
    )

    assert out["exists"] is True
    assert out["instance_id"] == "post-id"
    assert out["status"] == "ACTIVE"
    assert out["via"] == "list"


def test_verify_list_matches_creation_id(monkeypatch):
    """List route only has the creation-view id (post id differs and is absent)."""
    monkeypatch.setattr(ucp_capture, "get_ucp_instance", lambda *a, **k: None)
    monkeypatch.setattr(
        ucp_capture, "list_ucp_instances",
        lambda *a, **k: [{"id": "creation-id", "status": "ACTIVE"}],
    )

    out = ucp_capture.verify_ucp_instance_created(
        creation_view_id="creation-id",
        post_response={"id": "post-id", "status": "PENDING"},
        tenant_id="t",
    )

    assert out["exists"] is True
    assert out["instance_id"] == "creation-id"
    assert out["via"] == "list"


def test_verify_everything_fails(monkeypatch):
    """No GET and no list match → exists False, instance_id = post id, via None."""
    monkeypatch.setattr(ucp_capture, "get_ucp_instance", lambda *a, **k: None)
    monkeypatch.setattr(ucp_capture, "list_ucp_instances", lambda *a, **k: None)

    out = ucp_capture.verify_ucp_instance_created(
        creation_view_id="creation-id",
        post_response={"id": "post-id", "status": "PENDING"},
        tenant_id="t",
    )

    assert out["exists"] is False
    assert out["instance_id"] == "post-id"
    assert out["status"] == "PENDING"
    assert out["via"] is None


def test_verify_everything_fails_no_post_id(monkeypatch):
    """When the POST response has no id, fall back to the creation-view id."""
    monkeypatch.setattr(ucp_capture, "get_ucp_instance", lambda *a, **k: None)
    monkeypatch.setattr(ucp_capture, "list_ucp_instances", lambda *a, **k: None)

    out = ucp_capture.verify_ucp_instance_created(
        creation_view_id="creation-id",
        post_response={},
        tenant_id="t",
    )

    assert out["exists"] is False
    assert out["instance_id"] == "creation-id"
    assert out["via"] is None


def test_verify_post_id_differs_still_resolves(monkeypatch):
    """The whole point: post_id != creation_view_id. Verify it still resolves to
    the POST id when that's the one that actually exists."""
    seen = {}

    def fake_get(cid, tenant, port=8080):
        seen[cid] = True
        return {"id": cid, "status": "ENABLED"} if cid == "REAL-post-id" else None

    monkeypatch.setattr(ucp_capture, "get_ucp_instance", fake_get)
    monkeypatch.setattr(ucp_capture, "list_ucp_instances", lambda *a, **k: None)

    out = ucp_capture.verify_ucp_instance_created(
        creation_view_id="PREALLOC-creation-id",
        post_response={"id": "REAL-post-id", "status": "PENDING"},
        tenant_id="t",
    )

    assert out["exists"] is True
    assert out["instance_id"] == "REAL-post-id"
    assert out["via"] == "get-id"
    # The POST id was tried first (before the creation id).
    assert "REAL-post-id" in seen


def test_verify_handles_none_post_response(monkeypatch):
    """A None post_response must not raise (defensive)."""
    monkeypatch.setattr(ucp_capture, "get_ucp_instance", lambda *a, **k: None)
    monkeypatch.setattr(ucp_capture, "list_ucp_instances", lambda *a, **k: None)

    out = ucp_capture.verify_ucp_instance_created(
        creation_view_id="creation-id",
        post_response=None,
        tenant_id="t",
    )

    assert out["exists"] is False
    assert out["instance_id"] == "creation-id"
    assert out["via"] is None
