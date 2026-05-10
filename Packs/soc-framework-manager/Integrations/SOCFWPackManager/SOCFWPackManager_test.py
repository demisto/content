"""
SOCFWPackManager_test.py

Unit tests for the SOCFWPackManager integration.
Run:
    pytest Packs/soc-framework-manager/Integrations/SOCFWPackManager/SOCFWPackManager_test.py -v
"""

import importlib
import json
import os
import shutil
import sys
import tempfile
import types
import zipfile

import pytest


MODULE_NAME = "SOCFWPackManager"


# ---------------------------------------------------------------------------
# CommonServerPython stub
# ---------------------------------------------------------------------------


def _make_common_server_python_stub(captured_results, captured_errors):
    """Build a minimal CommonServerPython module rich enough that the
    integration's ``from CommonServerPython import *`` resolves every name
    the integration references at import time.

    Attributes on this module are pulled into the integration namespace by
    the wildcard import — that's how ``BaseClient`` becomes available inside
    SOCFWPackManager.py during test load.
    """

    common = types.ModuleType("CommonServerPython")

    class _StubBaseClient:
        """Minimal BaseClient compatible with the integration's usage.

        ``_http_request`` is monkeypatched per test. ``stream`` is honored so
        callers can pass it without exploding.
        """

        def __init__(self, base_url, verify=True, proxy=False, headers=None, **kwargs):
            self._base_url = base_url
            self._verify = verify
            self._proxy = proxy
            self._headers = headers or {}

        def _http_request(self, method, url_suffix="", full_url=None, **kwargs):
            raise NotImplementedError(
                "Test must replace _http_request on the client instance."
            )

    class _StubDemistoException(Exception):
        pass

    def _arg_to_boolean(value):
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        if isinstance(value, str):
            return value.strip().lower() in ("true", "yes", "1", "y", "on")
        return bool(value)

    def _return_results(value):
        captured_results.append(value)

    def _return_error(message):
        captured_errors.append(message)
        raise RuntimeError(message)

    def _command_results(**kw):
        return kw

    common.BaseClient = _StubBaseClient
    common.DemistoException = _StubDemistoException
    common.argToBoolean = _arg_to_boolean
    common.return_results = _return_results
    common.return_error = _return_error
    common.CommandResults = _command_results

    return common


def load_integration(params=None, args=None):
    """(Re)load the integration module under a fresh stub harness."""
    dm = types.SimpleNamespace()
    dm._params = params or {}
    dm._args = args or {}
    dm._results = []
    dm._errors = []

    dm.params = lambda: dm._params
    dm.args = lambda: dm._args
    dm.command = lambda: dm._args.get("__command__", "socfw-install-pack")
    dm.debug = lambda x: None
    dm.error = lambda x: None

    sys.modules["demistomock"] = dm
    sys.modules["CommonServerPython"] = _make_common_server_python_stub(
        dm._results, dm._errors
    )

    if MODULE_NAME in sys.modules:
        del sys.modules[MODULE_NAME]

    module = importlib.import_module(MODULE_NAME)
    return module, dm


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _StreamingResponse:
    """Mock matching the ``iter_content``/``headers`` surface used by
    ``ContentClient.stream_download_zip``."""

    def __init__(self, content: bytes, status_code: int = 200, headers=None):
        self._content = content
        self.status_code = status_code
        self.headers = headers or {}

    def iter_content(self, chunk_size=1):
        idx = 0
        while idx < len(self._content):
            yield self._content[idx : idx + chunk_size]
            idx += chunk_size


def _make_client(mod, *, verify=True, proxy=False):
    """Build a ContentClient with neutral creds for tests."""
    return mod.ContentClient(
        base_url="https://tenant.xdr.us.paloaltonetworks.com",
        api_id="3",
        api_key="my-key",
        verify=verify,
        proxy=proxy,
    )


def _make_test_zip(tmp_dir, nested=True):
    zip_path = os.path.join(tmp_dir, "TestPack.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        if nested:
            zf.writestr(
                "TestPack/pack_metadata.json",
                json.dumps({"name": "TestPack", "currentVersion": "1.0.0"}),
            )
            zf.writestr("TestPack/README.md", "# Test")
            zf.writestr("TestPack/CorrelationRules/rule.yml", "id: test-rule\n")
        else:
            zf.writestr(
                "pack_metadata.json",
                json.dumps({"name": "TestPack", "currentVersion": "1.0.0"}),
            )
    return zip_path


# ---------------------------------------------------------------------------
# ContentClient._set_sdk_env (covers the prior _set_sdk_env tests)
# ---------------------------------------------------------------------------


def test_set_sdk_env_uses_api_prefix():
    mod, _ = load_integration()
    client = mod.ContentClient(
        base_url="https://tenant.xdr.us.paloaltonetworks.com",
        api_id="3",
        api_key="my-key",
        verify=True,
        proxy=False,
    )
    client._set_sdk_env()
    assert (
        os.environ["DEMISTO_BASE_URL"]
        == "https://api-tenant.xdr.us.paloaltonetworks.com"
    )
    assert os.environ["DEMISTO_API_KEY"] == "my-key"
    assert os.environ["XSIAM_AUTH_ID"] == "3"


def test_set_sdk_env_preserves_existing_api_prefix():
    mod, _ = load_integration()
    client = mod.ContentClient(
        base_url="https://api-tenant.xdr.us.paloaltonetworks.com",
        api_id="5",
        api_key="k",
        verify=True,
        proxy=False,
    )
    client._set_sdk_env()
    assert (
        os.environ["DEMISTO_BASE_URL"]
        == "https://api-tenant.xdr.us.paloaltonetworks.com"
    )


# ---------------------------------------------------------------------------
# _prepare_pack_dir / _safe_extract_zip / _safe_flatten_one_level
# (covers the prior unzip_and_flatten tests)
# ---------------------------------------------------------------------------


def test_unzip_and_flatten_nested_zip():
    mod, _ = load_integration()
    tmp = tempfile.mkdtemp()
    orig = os.getcwd()
    try:
        os.chdir(tmp)
        pack_path = mod._prepare_pack_dir(_make_test_zip(tmp), "TestPack.zip")
        assert os.path.isdir(pack_path)
        assert os.path.exists(os.path.join(pack_path, "pack_metadata.json"))
        assert os.path.exists(os.path.join(pack_path, "CorrelationRules", "rule.yml"))
        assert not os.path.isdir(os.path.join(pack_path, "TestPack"))
    finally:
        os.chdir(orig)
        shutil.rmtree(tmp, ignore_errors=True)


def test_unzip_and_flatten_creates_landing_page_stub():
    mod, _ = load_integration()
    tmp = tempfile.mkdtemp()
    orig = os.getcwd()
    try:
        os.chdir(tmp)
        mod._prepare_pack_dir(_make_test_zip(tmp), "TestPack.zip")
        lp = os.path.join(tmp, "Tests", "Marketplace", "landingPage_sections.json")
        assert os.path.exists(lp)
        assert json.load(open(lp)) == {"sections": []}
    finally:
        os.chdir(orig)
        shutil.rmtree(tmp, ignore_errors=True)


def test_unzip_and_flatten_rejects_non_zip():
    mod, _ = load_integration()
    tmp = tempfile.mkdtemp()
    try:
        bad = os.path.join(tmp, "bad.zip")
        with open(bad, "w") as f:
            f.write("not a zip")
        with pytest.raises(Exception, match="not a valid zip"):
            mod._prepare_pack_dir(bad, "bad.zip")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_unzip_and_flatten_rejects_missing_pack_metadata():
    mod, _ = load_integration()
    tmp = tempfile.mkdtemp()
    orig = os.getcwd()
    try:
        os.chdir(tmp)
        zip_path = os.path.join(tmp, "bad.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("some_file.yml", "content")
        with pytest.raises(Exception, match="missing pack_metadata.json"):
            mod._prepare_pack_dir(zip_path, "bad.zip")
    finally:
        os.chdir(orig)
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# ContentClient.stream_download_zip (covers the prior _stream_download tests)
# ---------------------------------------------------------------------------


def test_stream_download_writes_full_payload(tmp_path):
    mod, _ = load_integration()
    payload = b"abc" * 100

    client = _make_client(mod)
    client._http_request = lambda **kw: _StreamingResponse(
        payload, headers={"Content-Length": str(len(payload))}
    )

    dest = str(tmp_path / "out.zip")
    client.stream_download_zip("https://example.com/pack.zip", dest)
    assert open(dest, "rb").read() == payload


def test_stream_download_rejects_oversized_content_length(tmp_path):
    mod, _ = load_integration()
    too_big = mod.MAX_DOWNLOAD_BYTES + 1

    client = _make_client(mod)
    client._http_request = lambda **kw: _StreamingResponse(
        b"x", headers={"Content-Length": str(too_big)}
    )

    dest = str(tmp_path / "out.zip")
    with pytest.raises(Exception, match="exceeds size limit"):
        client.stream_download_zip("https://example.com/pack.zip", dest)


def test_stream_download_rejects_oversized_streamed_body(tmp_path):
    """Server lies (or omits) Content-Length — guard during write must trip."""
    mod, _ = load_integration()
    mod.MAX_DOWNLOAD_BYTES = 1024
    mod.DOWNLOAD_CHUNK_BYTES = 256

    client = _make_client(mod)
    client._http_request = lambda **kw: _StreamingResponse(b"x" * 4096, headers={})

    dest = str(tmp_path / "out.zip")
    with pytest.raises(Exception, match="exceeds size limit during download"):
        client.stream_download_zip("https://example.com/pack.zip", dest)
    assert not os.path.exists(dest)


def test_stream_download_propagates_http_error(tmp_path):
    """BaseClient surfaces non-OK HTTP. We simulate that by raising."""
    mod, _ = load_integration()

    client = _make_client(mod)

    def fake_http_request(**kw):
        raise mod.DemistoException("Download failed HTTP 404")

    client._http_request = fake_http_request

    dest = str(tmp_path / "out.zip")
    with pytest.raises(Exception, match="Download failed HTTP 404"):
        client.stream_download_zip("https://example.com/missing.zip", dest)


def test_stream_download_threads_verify_flag(tmp_path):
    """verify is a ContentClient-level concern, plumbed into BaseClient.

    With verify=False the client records the flag at construction and any
    requests it issues use that setting. Our stub records what BaseClient
    was given so we can assert it.
    """
    mod, _ = load_integration()

    insecure_client = _make_client(mod, verify=False)
    assert insecure_client._verify is False

    secure_client = _make_client(mod, verify=True)
    assert secure_client._verify is True

    # And confirm stream=True is forwarded to the HTTP layer on download.
    seen = {}

    def capture(**kw):
        seen.update(kw)
        return _StreamingResponse(b"abc")

    secure_client._http_request = capture
    secure_client.stream_download_zip(
        "https://example.com/pack.zip", str(tmp_path / "out.zip")
    )
    assert seen.get("stream") is True


# ---------------------------------------------------------------------------
# install_pack_command (covers the prior command_install_pack tests)
# ---------------------------------------------------------------------------


def test_command_install_pack_calls_download_and_sdk(tmp_path):
    mod, dm = load_integration()

    # Build a real valid zip
    zip_path = str(tmp_path / "Pack-v1.0.0.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "Pack-v1.0.0/pack_metadata.json",
            json.dumps({"name": "Pack", "currentVersion": "1.0.0"}),
        )
    zip_bytes = open(zip_path, "rb").read()

    client = _make_client(mod, verify=True)
    client._http_request = lambda **kw: _StreamingResponse(
        zip_bytes, headers={"Content-Length": str(len(zip_bytes))}
    )

    sdk_calls = []

    def fake_upload(pack_path):
        sdk_calls.append({"pack_path": pack_path, "verify": client._verify})
        return {"success": True}

    client.upload_pack_as_system_content = fake_upload

    orig = os.getcwd()
    try:
        os.chdir(str(tmp_path))
        result = mod.install_pack_command(
            client,
            args={
                "url": "https://github.com/example/releases/download/Pack-v1.0.0/Pack-v1.0.0.zip",
                "filename": "Pack-v1.0.0.zip",
            },
        )
    finally:
        os.chdir(orig)

    assert sdk_calls, "upload_pack_as_system_content should be called"
    assert "Pack-v1.0.0" in sdk_calls[0]["pack_path"]
    assert sdk_calls[0]["verify"] is True
    # CommandResults stub returns kwargs; outputs include the filename.
    assert result.get("outputs", {}).get("filename") == "Pack-v1.0.0.zip"


def test_command_install_pack_threads_insecure_param(tmp_path):
    mod, _ = load_integration()

    zip_path = str(tmp_path / "Pack-v1.0.0.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "Pack-v1.0.0/pack_metadata.json",
            json.dumps({"name": "Pack", "currentVersion": "1.0.0"}),
        )
    zip_bytes = open(zip_path, "rb").read()

    # Insecure instance — verify=False is what the integration's main()
    # would build from params={"insecure": True}.
    client = _make_client(mod, verify=False)
    client._http_request = lambda **kw: _StreamingResponse(
        zip_bytes, headers={"Content-Length": str(len(zip_bytes))}
    )

    sdk_calls = []

    def fake_upload(pack_path):
        sdk_calls.append({"verify": client._verify})
        return {"success": True}

    client.upload_pack_as_system_content = fake_upload

    orig = os.getcwd()
    try:
        os.chdir(str(tmp_path))
        mod.install_pack_command(
            client,
            args={
                "url": "https://github.com/example/releases/download/Pack-v1.0.0/Pack-v1.0.0.zip",
            },
        )
    finally:
        os.chdir(orig)

    # verify=False propagates from ContentClient construction to the upload.
    assert client._verify is False
    assert sdk_calls[0]["verify"] is False


def test_command_install_pack_404_raises():
    mod, _ = load_integration()
    client = _make_client(mod)

    def fake_http_request(**kw):
        raise mod.DemistoException("Download failed HTTP 404")

    client._http_request = fake_http_request

    with pytest.raises(Exception, match="Download failed HTTP 404"):
        mod.install_pack_command(
            client,
            args={"url": "https://github.com/example/does-not-exist.zip"},
        )


def test_command_install_pack_derives_filename_from_url(monkeypatch):
    mod, _ = load_integration()
    client = _make_client(mod)
    client._http_request = lambda **kw: _StreamingResponse(b"fake")

    derived = []

    def capture(zip_path, filename):
        derived.append(filename)
        raise RuntimeError("stop_here")

    monkeypatch.setattr(mod, "_prepare_pack_dir", capture)

    with pytest.raises(RuntimeError, match="stop_here"):
        mod.install_pack_command(
            client,
            args={
                "url": "https://github.com/org/repo/releases/download/Pack-v2.0.0/Pack-v2.0.0.zip"
            },
        )

    assert derived == ["Pack-v2.0.0.zip"]


def test_command_install_pack_appends_zip_if_missing(monkeypatch):
    mod, _ = load_integration()
    client = _make_client(mod)
    client._http_request = lambda **kw: _StreamingResponse(b"fake")

    derived = []

    def capture(zip_path, filename):
        derived.append(filename)
        raise RuntimeError("stop")

    monkeypatch.setattr(mod, "_prepare_pack_dir", capture)

    with pytest.raises(Exception):
        mod.install_pack_command(
            client,
            args={"url": "https://example.com/Pack-v1.0.0", "filename": "Pack-v1.0.0"},
        )

    assert derived
    assert derived[0].endswith(".zip")
