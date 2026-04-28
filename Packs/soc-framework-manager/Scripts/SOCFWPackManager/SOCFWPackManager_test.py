"""
Unit tests for the SOCFWPackManager script.

Follows the pattern from SOCCommandWrapper_test.py.
Run: pytest Packs/soc-framework-manager/Scripts/SOCFWPackManager_test.py
"""

import importlib
import json
import sys
import types

import pytest

SCRIPT_MODULE_NAME = "SOCFWPackManager"


def load_script():
    """Import SOCFWPackManager with mocked XSOAR runtime."""
    demisto_mock = types.SimpleNamespace()
    demisto_mock._args    = {}
    demisto_mock._results = []
    demisto_mock._commands = []
    demisto_mock._command_responses = {}
    demisto_mock._context = {}

    def _execute_command(command, args):
        demisto_mock._commands.append((command, args))
        response = demisto_mock._command_responses.get(command)
        if callable(response):
            return response(args)
        return response if response is not None else []

    demisto_mock.args             = lambda: demisto_mock._args
    demisto_mock.results          = lambda x: demisto_mock._results.append(x)
    demisto_mock.executeCommand   = _execute_command
    demisto_mock.debug            = lambda x: None
    demisto_mock.info             = lambda x: None
    demisto_mock.context          = lambda: demisto_mock._context

    sys.modules["demistomock"] = demisto_mock

    common = types.ModuleType("CommonServerPython")
    common.return_results = lambda x: demisto_mock._results.append(x)
    common.return_error   = lambda x: (_ for _ in ()).throw(RuntimeError(x))
    sys.modules["CommonServerPython"] = common

    if SCRIPT_MODULE_NAME in sys.modules:
        del sys.modules[SCRIPT_MODULE_NAME]

    module = importlib.import_module(SCRIPT_MODULE_NAME)

    # Inject demisto into the module namespace.
    # Scripts use demisto as a module-level global; importlib loses
    # the binding when sys.modules["demistomock"] is swapped between tests.
    module.demisto        = demisto_mock
    module.return_results = lambda x: demisto_mock._results.append(x)
    module.return_error   = lambda msg: (_ for _ in ()).throw(RuntimeError(msg))

    return module, demisto_mock


# ── Utility helpers ───────────────────────────────────────────────────────────

def test_arg_to_bool_true_variants():
    script, _ = load_script()
    for v in ("true", "True", "1", "yes", "y", "on", True):
        assert script.arg_to_bool(v) is True


def test_arg_to_bool_false_variants():
    script, _ = load_script()
    for v in ("false", "False", "0", "no", "n", "off", False):
        assert script.arg_to_bool(v) is False


def test_arg_to_bool_none_returns_default():
    script, _ = load_script()
    assert script.arg_to_bool(None, True) is True
    assert script.arg_to_bool(None, False) is False


def test_to_int_valid():
    script, _ = load_script()
    assert script.to_int("42", 0) == 42


def test_to_int_invalid_returns_default():
    script, _ = load_script()
    assert script.to_int("bad", 99) == 99


def test_guess_pack_id_from_label_strips_version():
    script, _ = load_script()
    assert script._guess_pack_id_from_label("soc-optimization-unified-v3.4.0.zip") == "soc-optimization-unified"
    assert script._guess_pack_id_from_label("SocFrameworkTrendMicroVisionOne-v1.0.30.zip") == "SocFrameworkTrendMicroVisionOne"
    assert script._guess_pack_id_from_label("soc-optimization-unified") == "soc-optimization-unified"


def test_is_timeout_error_detects_common_patterns():
    script, _ = load_script()
    assert script.is_timeout_error("read timed out") is True
    assert script.is_timeout_error("context deadline exceeded") is True
    assert script.is_timeout_error("awaiting headers") is True
    assert script.is_timeout_error("connection refused") is False


# ── Catalog helpers ───────────────────────────────────────────────────────────

def test_find_pack_in_catalog_found():
    script, _ = load_script()
    catalog = {"packs": [
        {"id": "soc-optimization-unified", "version": "3.6.3"},
        {"id": "SocFrameworkTrendMicroVisionOne", "version": "1.0.30"},
    ]}
    result = script.find_pack_in_catalog(catalog, "soc-optimization-unified")
    assert result["version"] == "3.6.3"


def test_find_pack_in_catalog_not_found():
    script, _ = load_script()
    catalog = {"packs": [{"id": "pack-a", "version": "1.0.0"}]}
    assert script.find_pack_in_catalog(catalog, "pack-z") is None


def test_find_pack_in_catalog_empty():
    script, _ = load_script()
    assert script.find_pack_in_catalog({}, "anything") is None


# ── xsoar_config helpers ──────────────────────────────────────────────────────

def test_extract_custom_packs_from_xsoar_cfg():
    script, _ = load_script()
    cfg = {"custom_packs": [
        {"id": "my-pack.zip", "url": "https://example.com/my-pack-v1.0.0.zip", "system": "true"},
    ]}
    result = script._extract_custom_packs_from_xsoar_cfg(cfg)
    assert len(result) == 1
    assert result[0]["url"] == "https://example.com/my-pack-v1.0.0.zip"
    assert result[0]["system"] == "true"


def test_extract_custom_packs_from_xsoar_cfg_empty():
    script, _ = load_script()
    assert script._extract_custom_packs_from_xsoar_cfg({}) == []
    assert script._extract_custom_packs_from_xsoar_cfg({"custom_packs": []}) == []


def test_has_config_docs_pre_true():
    script, _ = load_script()
    cfg = {"pre_config_docs": [{"name": "README", "url": "https://example.com/README.md"}]}
    assert script.has_config_docs(cfg, "pre") is True


def test_has_config_docs_post_false_when_empty():
    script, _ = load_script()
    assert script.has_config_docs({}, "post") is False
    assert script.has_config_docs({"post_config_docs": []}, "post") is False


# ── action=list ───────────────────────────────────────────────────────────────

def test_do_list_renders_table(mocker):
    script, demisto = load_script()
    catalog = {"packs": [
        {"id": "soc-optimization-unified", "display_name": "SOC Framework Unified",
         "version": "3.6.3", "visible": True, "path": "Packs/soc-optimization-unified"},
        {"id": "SocFrameworkTrendMicroVisionOne", "display_name": "SOC Trend Micro",
         "version": "1.0.30", "visible": True, "path": "Packs/SocFrameworkTrendMicroVisionOne"},
    ]}
    mocker.patch.object(script, "fetch_pack_catalog", return_value=catalog)

    script.do_list({"limit": "50", "offset": "0", "sort_by": "id", "sort_dir": "asc",
                    "fields": "id,display_name,version,visible,path", "show_total": "True"})

    output = " ".join(str(r) for r in demisto._results)
    assert "soc-optimization-unified" in output
    assert "SocFrameworkTrendMicroVisionOne" in output
    assert "showing: 1-2 of 2" in output


def test_do_list_filter(mocker):
    script, demisto = load_script()
    catalog = {"packs": [
        {"id": "soc-optimization-unified", "display_name": "SOC Framework Unified",
         "version": "3.6.3", "visible": True, "path": "Packs/soc-optimization-unified"},
        {"id": "SocFrameworkTrendMicroVisionOne", "display_name": "Trend Micro",
         "version": "1.0.30", "visible": True, "path": "Packs/SocFrameworkTrendMicroVisionOne"},
    ]}
    mocker.patch.object(script, "fetch_pack_catalog", return_value=catalog)

    script.do_list({"filter": "trend", "limit": "50", "offset": "0",
                    "sort_by": "id", "fields": "id,version"})

    output = " ".join(str(r) for r in demisto._results)
    assert "SocFrameworkTrendMicroVisionOne" in output
    assert "showing: 1-1 of 1" in output


# ── action=sync-tags ──────────────────────────────────────────────────────────

def test_compute_hash_is_stable():
    script, _ = load_script()
    rows = [{"ScriptID": "cs-falcon-contain-host", "Tag": "isolate", "Time": "5"}]
    h1 = script._compute_hash(rows)
    h2 = script._compute_hash(rows)
    assert h1 == h2
    assert len(h1) == 32  # MD5 hex


def test_compute_hash_differs_on_change():
    script, _ = load_script()
    rows_a = [{"ScriptID": "cs-falcon-contain-host", "Tag": "isolate", "Time": "5"}]
    rows_b = [{"ScriptID": "cs-falcon-contain-host", "Tag": "isolate", "Time": "10"}]
    assert script._compute_hash(rows_a) != script._compute_hash(rows_b)


def test_do_sync_tags_up_to_date(mocker):
    script, demisto = load_script()

    rows = [{"ScriptID": "test", "Tag": "t", "Time": "1"}]
    current_hash = script._compute_hash(rows)

    mocker.patch.object(script, "http_get_json", return_value=rows)
    mocker.patch.object(script, "_normalize_lookup_rows", return_value=rows)
    mocker.patch.object(script, "_remove_omitted_fields", return_value=rows)
    mocker.patch.object(script, "_get_current_meta",
                        return_value={"hash": current_hash, "version": current_hash[:8],
                                      "updated_at": "2026-01-01T00:00:00Z"})

    script.do_sync_tags({"force": "False"})

    results_flat = " ".join(json.dumps(r) if not isinstance(r, str) else r
                            for r in demisto._results)
    assert "up_to_date" in results_flat


def test_do_sync_tags_updates_when_hash_differs(mocker):
    script, demisto = load_script()

    rows = [{"ScriptID": "new-script", "Tag": "t", "Time": "2"}]
    mocker.patch.object(script, "http_get_json", return_value=rows)
    mocker.patch.object(script, "_normalize_lookup_rows", return_value=rows)
    mocker.patch.object(script, "_remove_omitted_fields", return_value=rows)
    mocker.patch.object(script, "_get_current_meta",
                        return_value={"hash": "old_hash_abc", "version": "old_hash",
                                      "updated_at": "2025-01-01T00:00:00Z"})
    mock_upload = mocker.patch.object(script, "_xql_lookup_add_data_list")
    mock_set    = mocker.patch.object(script, "_set_current_meta")

    script.do_sync_tags({"force": "False"})

    mock_upload.assert_called_once()
    mock_set.assert_called_once()
    upload_rows = mock_upload.call_args[1]["rows"] if mock_upload.call_args[1] \
        else mock_upload.call_args[0][1]
    assert upload_rows == rows  # only data rows, no meta row in dataset


def test_do_sync_tags_force_updates_even_when_equal(mocker):
    script, demisto = load_script()

    rows = [{"ScriptID": "s", "Tag": "t", "Time": "1"}]
    current_hash = script._compute_hash(rows)

    mocker.patch.object(script, "http_get_json", return_value=rows)
    mocker.patch.object(script, "_normalize_lookup_rows", return_value=rows)
    mocker.patch.object(script, "_remove_omitted_fields", return_value=rows)
    mocker.patch.object(script, "_get_current_meta",
                        return_value={"hash": current_hash, "version": current_hash[:8],
                                      "updated_at": "2026-01-01T00:00:00Z"})
    mock_upload = mocker.patch.object(script, "_xql_lookup_add_data_list")
    mocker.patch.object(script, "_set_current_meta")

    script.do_sync_tags({"force": "True"})

    mock_upload.assert_called_once()


def test_do_sync_tags_no_rows_raises(mocker):
    script, _ = load_script()
    mocker.patch.object(script, "http_get_json", return_value=[])
    mocker.patch.object(script, "_normalize_lookup_rows", return_value=[])
    mocker.patch.object(script, "_remove_omitted_fields", return_value=[])

    with pytest.raises(Exception, match="0 usable rows"):
        script.do_sync_tags({})


# ── action=configure ──────────────────────────────────────────────────────────

def test_do_configure_missing_pack_id_raises():
    script, _ = load_script()
    with pytest.raises(Exception, match="pack_id is required"):
        script.do_configure({})


def test_do_configure_calls_all_sections(mocker):
    script, _ = load_script()

    xsoar_cfg = {
        "integration_instances": [{"name": "inst1", "brand": "BrandA", "data": []}],
        "jobs": [],
        "lookup_datasets": [],
    }
    mock_catalog = {"packs": [{"id": "my-pack", "version": "1.0.0",
                                "xsoar_config": "https://example.com/xsoar_config.json"}]}
    mocker.patch.object(script, "fetch_pack_catalog", return_value=mock_catalog)
    mocker.patch.object(script, "fetch_xsoar_config",  return_value=xsoar_cfg)
    mocker.patch.object(script, "fetch_installed_marketplace_pack_ids", return_value=[])
    mock_integ   = mocker.patch.object(script, "configure_integrations_from_xsoar_config")
    mock_jobs    = mocker.patch.object(script, "configure_jobs_from_xsoar_config")
    mock_lookups = mocker.patch.object(script, "configure_lookups_from_xsoar_config")
    mocker.patch.object(script, "print_config_docs")

    script.do_configure({"pack_id": "my-pack"})

    mock_integ.assert_called_once()
    mock_jobs.assert_called_once()
    mock_lookups.assert_called_once()


def test_do_configure_respects_flags(mocker):
    script, _ = load_script()

    xsoar_cfg = {"integration_instances": [], "jobs": [], "lookup_datasets": []}
    mocker.patch.object(script, "fetch_pack_catalog",
                        return_value={"packs": [{"id": "p", "version": "1.0.0"}]})
    mocker.patch.object(script, "fetch_xsoar_config", return_value=xsoar_cfg)
    mocker.patch.object(script, "fetch_installed_marketplace_pack_ids", return_value=[])
    mock_integ   = mocker.patch.object(script, "configure_integrations_from_xsoar_config")
    mock_jobs    = mocker.patch.object(script, "configure_jobs_from_xsoar_config")
    mock_lookups = mocker.patch.object(script, "configure_lookups_from_xsoar_config")
    mocker.patch.object(script, "print_config_docs")

    script.do_configure({
        "pack_id": "p",
        "configure_integrations": "False",
        "configure_jobs": "False",
        "configure_lookups": "True",
    })

    mock_integ.assert_not_called()
    mock_jobs.assert_not_called()
    mock_lookups.assert_called_once()


# ── action dispatch (main) ────────────────────────────────────────────────────

def test_main_unsupported_action_raises():
    script, demisto = load_script()
    demisto._args = {"action": "explode"}
    with pytest.raises(Exception, match="Unsupported action"):
        script.main()


def test_main_list_calls_do_list(mocker):
    script, demisto = load_script()
    demisto._args = {"action": "list"}
    mock_list = mocker.patch.object(script, "do_list")
    script.main()
    mock_list.assert_called_once()


def test_main_configure_calls_do_configure(mocker):
    script, demisto = load_script()
    demisto._args = {"action": "configure", "pack_id": "soc-optimization-unified"}
    mock_cfg = mocker.patch.object(script, "do_configure")
    script.main()
    mock_cfg.assert_called_once()


def test_main_sync_tags_calls_do_sync_tags(mocker):
    script, demisto = load_script()
    demisto._args = {"action": "sync-tags"}
    mock_sync = mocker.patch.object(script, "do_sync_tags")
    script.main()
    mock_sync.assert_called_once()


def test_main_apply_requires_pack_id():
    script, demisto = load_script()
    demisto._args = {"action": "apply"}
    with pytest.raises(Exception, match="pack_id is required"):
        script.main()


def test_main_apply_pre_config_gate_stops_when_docs_present(mocker):
    script, demisto = load_script()
    demisto._args = {
        "action": "apply",
        "pack_id": "SocFrameworkTrendMicroVisionOne",
        "pre_config_gate": "True",
        "pre_config_done": "False",
    }
    manifest = {
        "marketplace_packs": [],
        "custom_zip_urls": [],
        "xsoar_config_url": "https://example.com/xsoar_config.json",
        "pack_version": "1.0.30",
    }
    xsoar_cfg = {
        "pre_config_docs": [{"name": "README", "url": "https://example.com/README.md"}],
        "integration_instances": [],
        "jobs": [],
        "lookup_datasets": [],
    }
    mocker.patch.object(script, "resolve_manifest", return_value=manifest)
    mocker.patch.object(script, "fetch_xsoar_config", return_value=xsoar_cfg)
    mocker.patch.object(script, "print_config_docs")

    script.main()

    results_flat = json.dumps(demisto._results)
    assert "stopped_after_pre_docs" in results_flat or "pre_config" in results_flat
