"""
SOCFWPackManager_integration_test.py

Unit tests for the SOCFWPackManager integration.
Run:
    pytest Packs/soc-framework-manager/Integrations/SOCFWPackManager/SOCFWPackManager_integration_test.py -v
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


MODULE_NAME = "SOCFWPackManager_integration"


def load_integration(params=None, args=None):
    dm = types.SimpleNamespace()
    dm._params  = params or {}
    dm._args    = args   or {}
    dm._results = []

    dm.params  = lambda: dm._params
    dm.args    = lambda: dm._args
    dm.command = lambda: dm._args.get("__command__", "socfw-install-pack")
    dm.debug   = lambda x: None
    dm.error   = lambda x: None

    def return_results(value):
        dm._results.append(value)

    def return_error(message):
        raise RuntimeError(message)

    sys.modules["demistomock"] = dm

    common = types.ModuleType("CommonServerPython")
    common.return_results = return_results
    common.return_error   = return_error
    common.CommandResults = lambda **kw: kw
    sys.modules["CommonServerPython"] = common

    if MODULE_NAME in sys.modules:
        del sys.modules[MODULE_NAME]

    module = importlib.import_module(MODULE_NAME)

    # Inject names that the module resolves from CommonServerPython at import time.
    # importlib-loaded modules lose these bindings when sys.modules is swapped,
    # so we inject them directly into the module namespace.
    import requests as _requests
    module.requests        = _requests
    module.return_results  = return_results
    module.return_error    = return_error
    module.CommandResults  = lambda **kw: kw
    module.tempfile        = __import__("tempfile")

    return module, dm


# ── _set_sdk_env ──────────────────────────────────────────────────────────────

def test_set_sdk_env_uses_api_prefix():
    mod, _ = load_integration()
    mod._set_sdk_env("https://tenant.xdr.us.paloaltonetworks.com", "my-key", "3")
    assert os.environ["DEMISTO_BASE_URL"] == "https://api-tenant.xdr.us.paloaltonetworks.com"
    assert os.environ["DEMISTO_API_KEY"]  == "my-key"
    assert os.environ["XSIAM_AUTH_ID"]    == "3"


def test_set_sdk_env_preserves_existing_api_prefix():
    mod, _ = load_integration()
    mod._set_sdk_env("https://api-tenant.xdr.us.paloaltonetworks.com", "k", "5")
    assert os.environ["DEMISTO_BASE_URL"] == "https://api-tenant.xdr.us.paloaltonetworks.com"


# ── unzip_and_flatten ─────────────────────────────────────────────────────────

def _make_test_zip(tmp_dir, nested=True):
    zip_path = os.path.join(tmp_dir, "TestPack.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        if nested:
            zf.writestr("TestPack/pack_metadata.json",
                        json.dumps({"name": "TestPack", "currentVersion": "1.0.0"}))
            zf.writestr("TestPack/README.md", "# Test")
            zf.writestr("TestPack/CorrelationRules/rule.yml", "id: test-rule\n")
        else:
            zf.writestr("pack_metadata.json",
                        json.dumps({"name": "TestPack", "currentVersion": "1.0.0"}))
    return zip_path


def test_unzip_and_flatten_nested_zip():
    mod, _ = load_integration()
    tmp = tempfile.mkdtemp()
    orig = os.getcwd()
    try:
        os.chdir(tmp)
        pack_path = mod.unzip_and_flatten(_make_test_zip(tmp), "TestPack.zip")
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
        mod.unzip_and_flatten(_make_test_zip(tmp), "TestPack.zip")
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
            mod.unzip_and_flatten(bad, "bad.zip")
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
            mod.unzip_and_flatten(zip_path, "bad.zip")
    finally:
        os.chdir(orig)
        shutil.rmtree(tmp, ignore_errors=True)


# ── command_install_pack ──────────────────────────────────────────────────────

def test_command_install_pack_calls_download_and_sdk(tmp_path):
    mod, dm = load_integration()

    # Build a real valid zip
    zip_path = str(tmp_path / "Pack-v1.0.0.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("Pack-v1.0.0/pack_metadata.json",
                    json.dumps({"name": "Pack", "currentVersion": "1.0.0"}))
    with open(zip_path, "rb") as f:
        zip_bytes = f.read()

    mock_resp = types.SimpleNamespace(status_code=200, content=zip_bytes)
    mod.requests = types.SimpleNamespace(get=lambda url, **kw: mock_resp)

    sdk_calls = []
    mod.post_system_content_bundle = lambda base_url, api_key, api_id, pack_path: (
        sdk_calls.append(pack_path) or {"success": True}
    )

    orig = os.getcwd()
    try:
        os.chdir(str(tmp_path))
        mod.command_install_pack(
            params={"url": "https://tenant.xdr.us.paloaltonetworks.com",
                    "credentials": {"identifier": "3", "password": "my-key"}},
            args={"url": "https://github.com/example/releases/download/Pack-v1.0.0/Pack-v1.0.0.zip",
                  "filename": "Pack-v1.0.0.zip"},
        )
    finally:
        os.chdir(orig)

    assert sdk_calls, "post_system_content_bundle should be called"
    assert any("Pack-v1.0.0" in str(r) for r in dm._results)


def test_command_install_pack_404_raises():
    mod, _ = load_integration()
    mod.requests = types.SimpleNamespace(
        get=lambda url, **kw: types.SimpleNamespace(status_code=404, content=b"")
    )
    with pytest.raises(Exception, match="Download failed HTTP 404"):
        mod.command_install_pack(
            params={"url": "https://tenant.xdr.us.paloaltonetworks.com",
                    "credentials": {"identifier": "3", "password": "my-key"}},
            args={"url": "https://github.com/example/does-not-exist.zip"},
        )


def test_command_install_pack_derives_filename_from_url():
    mod, _ = load_integration()

    derived = []

    def capture(zip_path, filename):
        derived.append(filename)
        raise RuntimeError("stop_here")

    mod.unzip_and_flatten = capture
    mod.requests = types.SimpleNamespace(
        get=lambda url, **kw: types.SimpleNamespace(status_code=200, content=b"fake")
    )

    with pytest.raises(RuntimeError, match="stop_here"):
        mod.command_install_pack(
            params={"url": "https://t.xdr.us.paloaltonetworks.com",
                    "credentials": {"identifier": "1", "password": "k"}},
            args={"url": "https://github.com/org/repo/releases/download/Pack-v2.0.0/Pack-v2.0.0.zip"},
        )

    assert derived == ["Pack-v2.0.0.zip"]


def test_command_install_pack_appends_zip_if_missing():
    mod, _ = load_integration()

    derived = []

    def capture(zip_path, filename):
        derived.append(filename)
        raise RuntimeError("stop")

    mod.unzip_and_flatten = capture
    mod.requests = types.SimpleNamespace(
        get=lambda url, **kw: types.SimpleNamespace(status_code=200, content=b"fake")
    )

    with pytest.raises(Exception):
        mod.command_install_pack(
            params={"url": "https://t.xdr.us.paloaltonetworks.com",
                    "credentials": {"identifier": "1", "password": "k"}},
            args={"url": "https://example.com/Pack-v1.0.0",
                  "filename": "Pack-v1.0.0"},
        )

    assert derived and derived[0].endswith(".zip")
