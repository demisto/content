"""
Unit tests for the SOCFWPackManager script.

Follows the pattern from SOCCommandWrapper_test.py.
Run: pytest Packs/SocFrameworkManager/Scripts/SOCFWPackManager_test.py
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
    demisto_mock._args = {}
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

    demisto_mock.args = lambda: demisto_mock._args
    demisto_mock.results = lambda x: demisto_mock._results.append(x)
    demisto_mock.executeCommand = _execute_command
    demisto_mock.debug = lambda x: None
    demisto_mock.info = lambda x: None
    demisto_mock.context = lambda: demisto_mock._context
    demisto_mock._modules = {}
    demisto_mock.getModules = lambda: demisto_mock._modules

    sys.modules["demistomock"] = demisto_mock

    common = types.ModuleType("CommonServerPython")
    common.return_results = lambda x: demisto_mock._results.append(x)
    common.return_error = lambda x: (_ for _ in ()).throw(RuntimeError(x))
    common.argToList = lambda v: (
        v if isinstance(v, list) else [x.strip() for x in str(v).split(",") if x.strip()] if v not in (None, "") else []
    )

    class _CommandResults:
        def __init__(self, outputs_prefix=None, outputs_key_field=None, outputs=None, readable_output=None):
            self.outputs_prefix = outputs_prefix
            self.outputs_key_field = outputs_key_field
            self.outputs = outputs
            self.readable_output = readable_output

    common.CommandResults = _CommandResults
    sys.modules["CommonServerPython"] = common

    if SCRIPT_MODULE_NAME in sys.modules:
        del sys.modules[SCRIPT_MODULE_NAME]

    module = importlib.import_module(SCRIPT_MODULE_NAME)

    # Inject demisto into the module namespace.
    # Scripts use demisto as a module-level global; importlib loses
    # the binding when sys.modules["demistomock"] is swapped between tests.
    module.demisto = demisto_mock
    module.return_results = lambda x: demisto_mock._results.append(x)
    module.return_error = lambda msg: (_ for _ in ()).throw(RuntimeError(msg))

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
    catalog = {
        "packs": [
            {"id": "soc-optimization-unified", "version": "3.6.3"},
            {"id": "SocFrameworkTrendMicroVisionOne", "version": "1.0.30"},
        ]
    }
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
    cfg = {
        "custom_packs": [
            {"id": "my-pack.zip", "url": "https://example.com/my-pack-v1.0.0.zip", "system": "true"},
        ]
    }
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
    catalog = {
        "packs": [
            {
                "id": "soc-optimization-unified",
                "display_name": "SOC Framework Unified",
                "version": "3.6.3",
                "visible": True,
                "path": "Packs/soc-optimization-unified",
            },
            {
                "id": "SocFrameworkTrendMicroVisionOne",
                "display_name": "SOC Trend Micro",
                "version": "1.0.30",
                "visible": True,
                "path": "Packs/SocFrameworkTrendMicroVisionOne",
            },
        ]
    }
    mocker.patch.object(script, "fetch_pack_catalog", return_value=catalog)

    script.do_list(
        {
            "limit": "50",
            "offset": "0",
            "sort_by": "id",
            "sort_dir": "asc",
            "fields": "id,display_name,version,visible,path",
            "show_total": "True",
        }
    )

    output = " ".join(str(r) for r in demisto._results)
    assert "soc-optimization-unified" in output
    assert "SocFrameworkTrendMicroVisionOne" in output
    assert "2 pack(s)" in output


def test_do_list_filter(mocker):
    script, demisto = load_script()
    catalog = {
        "packs": [
            {
                "id": "soc-optimization-unified",
                "display_name": "SOC Framework Unified",
                "version": "3.6.3",
                "visible": True,
                "path": "Packs/soc-optimization-unified",
            },
            {
                "id": "SocFrameworkTrendMicroVisionOne",
                "display_name": "Trend Micro",
                "version": "1.0.30",
                "visible": True,
                "path": "Packs/SocFrameworkTrendMicroVisionOne",
            },
        ]
    }
    mocker.patch.object(script, "fetch_pack_catalog", return_value=catalog)

    script.do_list({"filter": "trend", "limit": "50", "offset": "0", "sort_by": "id", "fields": "id,version"})

    output = " ".join(str(r) for r in demisto._results)
    assert "SocFrameworkTrendMicroVisionOne" in output
    assert "1 pack(s)" in output


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
    mocker.patch.object(
        script,
        "_get_current_meta",
        return_value={"hash": current_hash, "version": current_hash[:8], "updated_at": "2026-01-01T00:00:00Z"},
    )

    script.do_sync_tags({"force": "False"})

    results_flat = " ".join(json.dumps(r) if not isinstance(r, str) else r for r in demisto._results)
    assert "up_to_date" in results_flat


def test_do_sync_tags_updates_when_hash_differs(mocker):
    script, demisto = load_script()

    rows = [{"ScriptID": "new-script", "Tag": "t", "Time": "2"}]
    mocker.patch.object(script, "http_get_json", return_value=rows)
    mocker.patch.object(script, "_normalize_lookup_rows", return_value=rows)
    mocker.patch.object(script, "_remove_omitted_fields", return_value=rows)
    mocker.patch.object(
        script,
        "_get_current_meta",
        return_value={"hash": "old_hash_abc", "version": "old_hash", "updated_at": "2025-01-01T00:00:00Z"},
    )
    mock_upload = mocker.patch.object(script, "_xql_lookup_add_data_list")
    mock_set = mocker.patch.object(script, "_set_current_meta")

    script.do_sync_tags({"force": "False"})

    mock_upload.assert_called_once()
    mock_set.assert_called_once()
    upload_rows = mock_upload.call_args[1]["rows"] if mock_upload.call_args[1] else mock_upload.call_args[0][1]
    assert upload_rows == rows  # only data rows, no meta row in dataset


def test_do_sync_tags_force_updates_even_when_equal(mocker):
    script, demisto = load_script()

    rows = [{"ScriptID": "s", "Tag": "t", "Time": "1"}]
    current_hash = script._compute_hash(rows)

    mocker.patch.object(script, "http_get_json", return_value=rows)
    mocker.patch.object(script, "_normalize_lookup_rows", return_value=rows)
    mocker.patch.object(script, "_remove_omitted_fields", return_value=rows)
    mocker.patch.object(
        script,
        "_get_current_meta",
        return_value={"hash": current_hash, "version": current_hash[:8], "updated_at": "2026-01-01T00:00:00Z"},
    )
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
    mock_catalog = {"packs": [{"id": "my-pack", "version": "1.0.0", "xsoar_config": "https://example.com/xsoar_config.json"}]}
    mocker.patch.object(script, "fetch_pack_catalog", return_value=mock_catalog)
    mocker.patch.object(script, "fetch_xsoar_config", return_value=xsoar_cfg)
    mocker.patch.object(script, "fetch_installed_marketplace_pack_ids", return_value=[])
    mock_integ = mocker.patch.object(script, "configure_integrations_from_xsoar_config")
    mock_jobs = mocker.patch.object(script, "configure_jobs_from_xsoar_config")
    mock_lookups = mocker.patch.object(script, "configure_lookups_from_xsoar_config")
    mocker.patch.object(script, "print_config_docs")

    script.do_configure({"pack_id": "my-pack"})

    mock_integ.assert_called_once()
    mock_jobs.assert_called_once()
    mock_lookups.assert_called_once()


def test_do_configure_respects_flags(mocker):
    script, _ = load_script()

    xsoar_cfg = {"integration_instances": [], "jobs": [], "lookup_datasets": []}
    mocker.patch.object(script, "fetch_pack_catalog", return_value={"packs": [{"id": "p", "version": "1.0.0"}]})
    mocker.patch.object(script, "fetch_xsoar_config", return_value=xsoar_cfg)
    mocker.patch.object(script, "fetch_installed_marketplace_pack_ids", return_value=[])
    mock_integ = mocker.patch.object(script, "configure_integrations_from_xsoar_config")
    mock_jobs = mocker.patch.object(script, "configure_jobs_from_xsoar_config")
    mock_lookups = mocker.patch.object(script, "configure_lookups_from_xsoar_config")
    mocker.patch.object(script, "print_config_docs")

    script.do_configure(
        {
            "pack_id": "p",
            "configure_integrations": "False",
            "configure_jobs": "False",
            "configure_lookups": "True",
        }
    )

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


# ── Marketplace install ───────────────────────────────────────────────────────


def test_ver_key_orders_versions():
    script, _ = load_script()
    assert script._ver_key("1.2.3") == (1, 2, 3)
    assert script._ver_key("1.22.28") > script._ver_key("1.9.99")
    assert script._ver_key("") == (0, 0, 0)
    assert script._ver_key(None) == (0, 0, 0)
    assert script._ver_key("2.0") == (2, 0, 0)


def test_fetch_installed_packs_parses_version_and_update_flag():
    script, demisto_mock = load_script()
    demisto_mock._command_responses["core-api-get"] = [
        {
            "Type": 1,
            "Contents": {
                "response": [
                    {"id": "Base", "currentVersion": "1.42.2", "updateAvailable": True},
                    {"id": "Whois", "currentVersion": "1.5.42", "updateAvailable": False},
                    {"currentVersion": "9.9.9"},
                ]
            },
        }
    ]
    out = script.fetch_installed_packs("")
    assert out["Base"] == {"version": "1.42.2", "update_available": True}
    assert out["Whois"] == {"version": "1.5.42", "update_available": False}
    assert len(out) == 2


def test_fetch_installed_packs_returns_empty_on_error():
    script, demisto_mock = load_script()

    def boom(args):
        raise RuntimeError("500")

    demisto_mock._command_responses["core-api-get"] = boom
    assert script.fetch_installed_packs("") == {}


def test_fetch_mandatory_dependencies_filters_optional():
    script, _ = load_script()
    payload = {
        "response": {
            "packs": [
                {
                    "id": "CommonScripts",
                    "extras": {
                        "pack": {
                            "dependencies": {
                                "Base": {"mandatory": True, "minVersion": "1.42.1"},
                                "Core": {"mandatory": True, "minVersion": "3.5.65"},
                                "Optional": {"mandatory": False, "minVersion": "1.0.0"},
                            }
                        }
                    },
                }
            ]
        }
    }
    script.core_api_post = lambda path, body, using="": payload
    out = script.fetch_mandatory_dependencies([{"id": "CommonScripts", "version": "1.0.0"}], "")
    assert out == {"CommonScripts": {"Base": "1.42.1", "Core": "3.5.65"}}


def test_resolve_install_closure_expands_transitive_dependencies():
    script, _ = load_script()
    graph = {
        "CommonScripts": {"Base": "1.42.1", "DemistoRESTAPI": "1.4.5"},
        "Base": {"Core": "3.5.65"},
        "Core": {"CommonPlaybooks": "2.8.0"},
        "CommonPlaybooks": {"rasterize": "2.1.30"},
    }

    def fake_deps(packs, using):
        return {p["id"]: graph.get(p["id"], {}) for p in packs}

    script.fetch_mandatory_dependencies = fake_deps
    closure = script.resolve_install_closure([{"id": "CommonScripts", "version": "1.22.28"}], "", {})

    assert set(closure) == {
        "CommonScripts",
        "Base",
        "DemistoRESTAPI",
        "Core",
        "CommonPlaybooks",
        "rasterize",
    }
    assert closure["CommonScripts"] == "1.22.28"
    assert closure["Core"] == "3.5.65"


def test_resolve_install_closure_prefers_installed_version_for_latest():
    script, _ = load_script()
    script.fetch_mandatory_dependencies = lambda packs, using: {}

    def should_not_be_called(pack_id, using):
        raise AssertionError("marketplace lookup should be skipped when the pack is installed")

    script.resolve_latest_version = should_not_be_called
    installed = {"Whois": {"version": "1.5.42", "update_available": True}}
    closure = script.resolve_install_closure([{"id": "Whois", "version": "latest"}], "", installed)
    assert closure == {"Whois": "1.5.42"}


def test_resolve_install_closure_resolves_latest_when_not_installed():
    script, _ = load_script()
    script.fetch_mandatory_dependencies = lambda packs, using: {}
    script.resolve_latest_version = lambda pack_id, using: "9.9.9"
    closure = script.resolve_install_closure([{"id": "Whois", "version": "latest"}], "", {})
    assert closure == {"Whois": "9.9.9"}


def test_resolve_install_closure_upgrades_dependency_below_min_version():
    script, _ = load_script()
    script.fetch_mandatory_dependencies = lambda packs, using: (
        {"A": {"Base": "2.0.0"}} if packs and packs[0]["id"] == "A" else {}
    )
    installed = {"Base": {"version": "1.0.0", "update_available": True}}
    closure = script.resolve_install_closure([{"id": "A", "version": "1.0.0"}], "", installed)
    assert closure["Base"] == "2.0.0"


def test_install_marketplace_packs_sends_full_closure_in_object_body():
    script, demisto_mock = load_script()
    script.fetch_installed_packs = lambda using: {}
    script.resolve_install_closure = lambda seeds, using, installed, upgrade=False: {
        "CommonScripts": "1.22.28",
        "Base": "1.42.2",
    }
    demisto_mock._command_responses["core-api-post"] = [{"Type": 1, "Contents": {"response": []}}]

    result = script.install_marketplace_packs([{"id": "CommonScripts", "version": "latest"}], "", 0, 0, debug=False)

    posts = [c for c in demisto_mock._commands if c[0] == "core-api-post"]
    assert len(posts) == 1
    args = posts[0][1]
    assert args["uri"] == "/contentpacks/marketplace/install"
    body = json.loads(args["body"])
    # Object wrapper, and the dependency has to ride along with the requested pack.
    assert sorted(body["packs"], key=lambda p: p["id"]) == [
        {"id": "Base", "version": "1.42.2"},
        {"id": "CommonScripts", "version": "1.22.28"},
    ]
    assert result["installed"] == {"CommonScripts": "1.22.28", "Base": "1.42.2"}


def test_install_marketplace_packs_skips_when_already_satisfied():
    script, demisto_mock = load_script()
    script.fetch_installed_packs = lambda using: {"CommonScripts": {"version": "1.22.28", "update_available": False}}
    script.resolve_install_closure = lambda seeds, using, installed, upgrade=False: {"CommonScripts": "1.22.28"}

    result = script.install_marketplace_packs([{"id": "CommonScripts", "version": "latest"}], "", 0, 0, debug=False)

    assert [c for c in demisto_mock._commands if c[0] == "core-api-post"] == []
    assert result["installed"] == {}
    assert result["already_present"] == {"CommonScripts": "1.22.28"}


def test_install_marketplace_packs_emits_legacy_context_on_success():
    script, demisto_mock = load_script()
    script.fetch_installed_packs = lambda using: {}
    script.resolve_install_closure = lambda seeds, using, installed, upgrade=False: {
        "CommonScripts": "1.22.28",
        "Base": "1.42.2",
    }
    demisto_mock._command_responses["core-api-post"] = [{"Type": 1, "Contents": {"response": []}}]

    script.install_marketplace_packs([{"id": "CommonScripts", "version": "latest"}], "", 0, 0, debug=False)

    ctx = [r for r in demisto_mock._results if getattr(r, "outputs_prefix", None) == "ConfigurationSetup.MarketplacePacks"]
    assert len(ctx) == 1
    assert ctx[0].outputs_key_field == "packid"
    rows = {r["packid"]: r["installationstatus"] for r in ctx[0].outputs}
    assert rows["CommonScripts"] == "Success."
    assert rows["Base"] == "Installed as requirement."


def test_install_marketplace_packs_emits_legacy_context_on_failure():
    script, demisto_mock = load_script()
    script.fetch_installed_packs = lambda using: {}
    script.resolve_install_closure = lambda seeds, using, installed, upgrade=False: {"CommonScripts": "1.22.28"}

    def boom(args):
        raise RuntimeError("dependency missing")

    demisto_mock._command_responses["core-api-post"] = boom

    with pytest.raises(Exception):
        script.install_marketplace_packs([{"id": "CommonScripts", "version": "latest"}], "", 0, 0, debug=False)

    ctx = [r for r in demisto_mock._results if getattr(r, "outputs_prefix", None) == "ConfigurationSetup.MarketplacePacks"]
    assert ctx
    assert ctx[-1].outputs[0]["installationstatus"] == "Failed to install."


def test_marketplace_context_rows_match_legacy_shape():
    script, _ = load_script()
    rows = script._marketplace_context_rows({"A", "B", "C"}, {"A": "1.0.0", "D": "2.0.0"}, {"B": "3.0.0"}, {"C": "4.0.0"})
    by_id = {r["packid"]: r for r in rows}
    assert set(by_id["A"]) == {"packid", "packversion", "installationstatus"}
    assert by_id["A"]["installationstatus"] == "Success."
    assert by_id["D"]["installationstatus"] == "Installed as requirement."
    assert by_id["B"]["installationstatus"] == "Already Installed on the machine."
    assert by_id["C"]["installationstatus"] == "Failed to install."
    assert by_id["A"]["packversion"] == "1.0.0"


# ── list: drift + category grouping ───────────────────────────────────────────


def _list_catalog():
    return {
        "packs": [
            {"id": "soc-a", "display_name": "A", "category": "Endpoint", "version": "1.0.5", "visible": True},
            {"id": "soc-b", "display_name": "B", "category": "Endpoint", "version": "2.0.0", "visible": True},
            {"id": "soc-c", "display_name": "C", "category": "Identity", "version": "1.0.0", "visible": True},
        ]
    }


def test_do_list_reports_install_status_per_pack(mocker):
    script, demisto_mock = load_script()
    mocker.patch.object(script, "fetch_pack_catalog", return_value=_list_catalog())
    mocker.patch.object(
        script,
        "fetch_installed_packs",
        return_value={
            "soc-a": {"version": "1.0.4", "update_available": True},
            "soc-b": {"version": "2.0.0", "update_available": False},
        },
    )

    script.do_list({})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    assert "update available" in out
    assert "up to date" in out
    assert "not installed" in out
    assert "1.0.4" in out


def test_do_list_groups_by_category_and_drops_visible_and_path(mocker):
    script, demisto_mock = load_script()
    mocker.patch.object(script, "fetch_pack_catalog", return_value=_list_catalog())
    mocker.patch.object(script, "fetch_installed_packs", return_value={"soc-a": {"version": "1.0.5"}})

    script.do_list({})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    assert "**Endpoint**" in out
    assert "**Identity**" in out
    # visible/path are not rendered; "visible_only" in the summary line is fine.
    assert "| visible" not in out
    assert "Packs/soc-a" not in out


def test_do_list_defaults_to_list_not_table(mocker):
    script, demisto_mock = load_script()
    mocker.patch.object(script, "fetch_pack_catalog", return_value=_list_catalog())
    mocker.patch.object(script, "fetch_installed_packs", return_value={"soc-a": {"version": "1.0.4"}})

    script.do_list({})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    # A markdown table gets transposed when a category has a single pack.
    assert "| --- |" not in out
    assert "\nsoc-a — " in out
    assert "1.0.4 → 1.0.5 · update available" in out


def test_do_list_table_format_still_available(mocker):
    script, demisto_mock = load_script()
    mocker.patch.object(script, "fetch_pack_catalog", return_value=_list_catalog())
    mocker.patch.object(script, "fetch_installed_packs", return_value={"soc-a": {"version": "1.0.5"}})

    script.do_list({"output_format": "table"})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    assert "| --- |" in out
    assert "| installed" in out


def test_do_list_line_wording_per_status(mocker):
    script, demisto_mock = load_script()
    mocker.patch.object(script, "fetch_pack_catalog", return_value=_list_catalog())
    mocker.patch.object(
        script,
        "fetch_installed_packs",
        return_value={"soc-a": {"version": "1.0.5"}, "soc-b": {"version": "9.9.9"}},
    )

    script.do_list({})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    assert "1.0.5 · up to date" in out
    assert "ahead of catalog (2.0.0)" in out
    assert "not installed · 1.0.0 available" in out


def test_do_list_flat_when_grouping_disabled(mocker):
    script, demisto_mock = load_script()
    mocker.patch.object(script, "fetch_pack_catalog", return_value=_list_catalog())
    mocker.patch.object(script, "fetch_installed_packs", return_value={})

    script.do_list({"group_by_category": "false"})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    assert "**Endpoint**" not in out
    assert "soc-a" in out


def test_do_list_marks_status_unknown_when_installed_lookup_fails(mocker):
    script, demisto_mock = load_script()
    mocker.patch.object(script, "fetch_pack_catalog", return_value=_list_catalog())
    mocker.patch.object(script, "fetch_installed_packs", return_value={})

    script.do_list({})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    assert "unknown" in out
    assert "not installed" not in out


def test_do_list_flags_pack_ahead_of_catalog(mocker):
    script, demisto_mock = load_script()
    mocker.patch.object(script, "fetch_pack_catalog", return_value=_list_catalog())
    mocker.patch.object(script, "fetch_installed_packs", return_value={"soc-a": {"version": "9.9.9"}})

    script.do_list({})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    assert "ahead of catalog" in out


def test_pack_docs_url_uses_docs_path_basename():
    script, _ = load_script()
    url = script._pack_docs_url(
        {"id": "soc-wiz-cloud", "docs_path": "docs/soc-wiz-cloud"},
        "https://palo-cortex.github.io/secops-framework",
    )
    assert url == "https://palo-cortex.github.io/secops-framework/soc-wiz-cloud/overview/"


def test_pack_docs_url_is_absolute_and_tolerates_trailing_slash():
    script, _ = load_script()
    url = script._pack_docs_url(
        {"id": "soc-a", "docs_path": "docs/soc-a/"},
        "https://example.com/site/",
    )
    assert url.startswith("https://")
    assert url == "https://example.com/site/soc-a/overview/"


def test_pack_docs_url_falls_back_to_pack_id():
    script, _ = load_script()
    url = script._pack_docs_url({"id": "soc-b"}, "https://example.com")
    assert url == "https://example.com/soc-b/overview/"


def test_pack_docs_url_empty_when_base_disabled():
    script, _ = load_script()
    assert script._pack_docs_url({"id": "soc-b", "docs_path": "docs/soc-b"}, "") == ""


def test_do_list_links_pack_id_to_docs(mocker):
    script, demisto_mock = load_script()
    mocker.patch.object(script, "fetch_pack_catalog", return_value=_list_catalog())
    mocker.patch.object(script, "fetch_installed_packs", return_value={"soc-a": {"version": "1.0.5"}})

    script.do_list({})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    assert "\nsoc-a — " in out
    assert "[docs](https://palo-cortex.github.io/secops-framework/soc-a/overview/)" in out
    # Never emit a relative href -- XSIAM resolves it against the tenant host.
    assert "](/" not in out


def test_do_list_omits_link_when_docs_base_url_blank(mocker):
    script, demisto_mock = load_script()
    mocker.patch.object(script, "fetch_pack_catalog", return_value=_list_catalog())
    mocker.patch.object(script, "fetch_installed_packs", return_value={})

    script.do_list({"docs_base_url": ""})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    assert "soc-a" in out
    assert "](http" not in out


def test_pack_docs_url_prefers_explicit_absolute_docs_field():
    script, _ = load_script()
    url = script._pack_docs_url(
        {"id": "soc-a", "docs_path": "docs/soc-a", "docs": "https://example.com/custom/page/"},
        "https://palo-cortex.github.io/secops-framework",
    )
    assert url == "https://example.com/custom/page/"


def test_pack_docs_url_treats_relative_docs_field_as_a_path():
    script, _ = load_script()
    url = script._pack_docs_url(
        {"id": "soc-a", "docs": "docs/soc-a"},
        "https://example.com",
    )
    assert url == "https://example.com/soc-a/overview/"


def test_do_list_leaves_pack_id_unlinked_for_copy_paste(mocker):
    script, demisto_mock = load_script()
    mocker.patch.object(script, "fetch_pack_catalog", return_value=_list_catalog())
    mocker.patch.object(script, "fetch_installed_packs", return_value={"soc-a": {"version": "1.0.4"}})

    script.do_list({})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    # The id has to be plain text so it can be pasted into pack_id=.
    assert "\nsoc-a — " in out
    assert "[soc-a](" not in out
    assert "[docs](https://palo-cortex.github.io/secops-framework/soc-a/overview/)" in out


def test_do_list_table_puts_docs_in_its_own_column(mocker):
    script, demisto_mock = load_script()
    mocker.patch.object(script, "fetch_pack_catalog", return_value=_list_catalog())
    mocker.patch.object(script, "fetch_installed_packs", return_value={"soc-a": {"version": "1.0.5"}})

    script.do_list({"output_format": "table"})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    assert "| docs |" in out
    assert "[soc-a](" not in out
    assert "[docs](" in out


def test_do_list_headings_are_not_absorbed_into_a_markdown_list(mocker):
    script, demisto_mock = load_script()
    mocker.patch.object(script, "fetch_pack_catalog", return_value=_list_catalog())
    mocker.patch.object(script, "fetch_installed_packs", return_value={"soc-a": {"version": "1.0.4"}})

    script.do_list({})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    # A bold heading directly after a list item becomes a lazy continuation of
    # that list, which indents every heading after the first.
    assert "\n- " not in out
    for line in out.splitlines():
        if line.startswith("**") and line.endswith("**"):
            continue
        assert not line.lstrip().startswith("- ")


# ── diagnose + loud degradation ───────────────────────────────────────────────


def test_dependency_lookup_failure_raises_typed_error():
    script, demisto_mock = load_script()

    def boom(args):
        raise RuntimeError("404 route not found")

    demisto_mock._command_responses["core-api-post"] = boom
    with pytest.raises(script.DependencyLookupError):
        script.fetch_mandatory_dependencies([{"id": "CommonScripts", "version": "1.0.0"}], "")

    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))
    assert "Dependency lookup failed" in out
    assert "404 route not found" in out
    assert "not the install endpoint" in out


def test_install_does_not_attempt_when_dependencies_unresolvable():
    script, demisto_mock = load_script()
    script.fetch_installed_packs = lambda using: {}

    def raise_lookup(seeds, using, installed, upgrade=False):
        raise script.DependencyLookupError("dependency endpoint returned 500")

    script.resolve_install_closure = raise_lookup

    with pytest.raises(Exception) as exc:
        script.install_marketplace_packs([{"id": "CommonScripts", "version": "latest"}], "", 0, 0, debug=False)

    assert "was not attempted" in str(exc.value)
    assert "dependency endpoint returned 500" in str(exc.value)
    # Nothing should have been sent to the install endpoint.
    assert [c for c in demisto_mock._commands if c[0] == "core-api-post"] == []


def test_installed_packs_failure_is_announced():
    script, demisto_mock = load_script()

    def boom(args):
        raise RuntimeError("500 internal")

    demisto_mock._command_responses["core-api-get"] = boom
    assert script.fetch_installed_packs("") == {}

    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))
    assert "Could not read installed packs" in out
    assert "500 internal" in out


def test_diagnose_reports_pass_and_fail_per_endpoint():
    script, demisto_mock = load_script()
    script.fetch_installed_packs = lambda using: {}

    def get_ok(args):
        uri = args.get("uri", "")
        if uri.endswith("/metadata/installed"):
            return [{"Type": 1, "Contents": {"response": [{"id": "Whois", "currentVersion": "1.5.42"}]}}]
        raise RuntimeError("boom on marketplace metadata")

    def post_fail(args):
        raise RuntimeError("dependency endpoint unavailable")

    demisto_mock._command_responses["core-api-get"] = get_ok
    demisto_mock._command_responses["core-api-post"] = post_fail

    script.do_diagnose({})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    assert "installed packs" in out
    assert "pass" in out
    assert "FAIL" in out
    assert "dependency endpoint unavailable" in out


def test_diagnose_all_pass_verdict():
    script, demisto_mock = load_script()
    demisto_mock._modules = {"Core REST API_instance_1": {"brand": "Core REST API", "state": "active"}}

    def get_ok(args):
        uri = args.get("uri", "")
        if uri.endswith("/metadata/installed"):
            return [{"Type": 1, "Contents": {"response": [{"id": "Whois", "currentVersion": "1.5.42"}]}}]
        return [{"Type": 1, "Contents": {"response": {"currentVersion": "1.5.43"}}}]

    def post_ok(args):
        return [
            {
                "Type": 1,
                "Contents": {
                    "response": {
                        "packs": [
                            {
                                "id": "Whois",
                                "extras": {"pack": {"dependencies": {"Base": {"mandatory": True, "minVersion": "1.0.0"}}}},
                            }
                        ]
                    }
                },
            }
        ]

    demisto_mock._command_responses["core-api-get"] = get_ok
    demisto_mock._command_responses["core-api-post"] = post_ok

    script.do_diagnose({})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    assert "All checks passed" in out
    assert "FAIL" not in out


def test_find_core_rest_api_instances_matches_known_brands():
    script, demisto_mock = load_script()
    demisto_mock._modules = {
        "Core REST API_instance_1": {"brand": "Core REST API", "state": "active"},
        "SOCFWPackManager_instance_1": {"brand": "SOCFWPackManager", "state": "active"},
        "Something": {"brand": "Whois", "state": "active"},
    }
    found = script.find_core_rest_api_instances()
    assert [f["name"] for f in found] == ["Core REST API_instance_1"]


def test_find_core_rest_api_instances_empty_when_absent():
    script, demisto_mock = load_script()
    demisto_mock._modules = {"SOCFWPackManager_instance_1": {"brand": "SOCFWPackManager", "state": "active"}}
    assert script.find_core_rest_api_instances() == []


def test_diagnose_names_missing_core_rest_api_instance_first():
    script, demisto_mock = load_script()
    demisto_mock._modules = {}

    def boom(args):
        raise RuntimeError("connection refused")

    demisto_mock._command_responses["core-api-get"] = boom
    demisto_mock._command_responses["core-api-post"] = boom

    script.do_diagnose({})
    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))

    # The missing instance is the real cause; it must be named rather than
    # leaving three opaque transport errors to interpret.
    assert "Core REST API instance" in out
    assert "none configured" in out
    assert out.index("Core REST API instance") < out.index("installed packs")


def test_dependency_failure_hint_names_missing_instance():
    script, demisto_mock = load_script()
    demisto_mock._modules = {}

    def boom(args):
        raise RuntimeError("500")

    demisto_mock._command_responses["core-api-post"] = boom
    with pytest.raises(script.DependencyLookupError):
        script.fetch_mandatory_dependencies([{"id": "CommonScripts", "version": "1.0.0"}], "")

    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))
    assert "No Core REST API instance is configured" in out


def test_dependency_failure_hint_when_instance_present():
    script, demisto_mock = load_script()
    demisto_mock._modules = {"Core REST API_instance_1": {"brand": "Core REST API", "state": "active"}}

    def boom(args):
        raise RuntimeError("404")

    demisto_mock._command_responses["core-api-post"] = boom
    with pytest.raises(script.DependencyLookupError):
        script.fetch_mandatory_dependencies([{"id": "CommonScripts", "version": "1.0.0"}], "")

    out = "\n".join(str(r.get("Contents", "")) for r in demisto_mock._results if isinstance(r, dict))
    assert "route or payload problem" in out


# ── upgrade_marketplace ───────────────────────────────────────────────────────


def test_closure_default_keeps_installed_version_and_skips_lookup():
    script, _ = load_script()
    script.fetch_mandatory_dependencies = lambda packs, using: {}

    def should_not_run(pack_id, using):
        raise AssertionError("marketplace lookup must be skipped when not upgrading")

    script.resolve_latest_version = should_not_run
    installed = {"CommonScripts": {"version": "1.22.28", "update_available": True}}
    closure = script.resolve_install_closure([{"id": "CommonScripts", "version": "latest"}], "", installed)
    assert closure == {"CommonScripts": "1.22.28"}


def test_closure_upgrade_resolves_newest_published_version():
    script, _ = load_script()
    script.fetch_mandatory_dependencies = lambda packs, using: {}
    script.resolve_latest_version = lambda pack_id, using: "1.22.39"
    installed = {"CommonScripts": {"version": "1.22.28", "update_available": True}}
    closure = script.resolve_install_closure([{"id": "CommonScripts", "version": "latest"}], "", installed, upgrade=True)
    assert closure == {"CommonScripts": "1.22.39"}


def test_closure_upgrade_skips_lookup_when_no_update_available():
    script, _ = load_script()
    script.fetch_mandatory_dependencies = lambda packs, using: {}

    def should_not_run(pack_id, using):
        raise AssertionError("no update available, so the large lookup is wasted")

    script.resolve_latest_version = should_not_run
    installed = {"Whois": {"version": "1.5.43", "update_available": False}}
    closure = script.resolve_install_closure([{"id": "Whois", "version": "latest"}], "", installed, upgrade=True)
    assert closure == {"Whois": "1.5.43"}


def test_closure_upgrade_does_not_force_upgrade_dependencies():
    script, _ = load_script()
    script.resolve_latest_version = lambda pack_id, using: "2.0.0"
    script.fetch_mandatory_dependencies = lambda packs, using: (
        {"A": {"Base": "1.0.0"}} if packs and packs[0]["id"] == "A" else {}
    )
    installed = {
        "A": {"version": "1.0.0", "update_available": True},
        "Base": {"version": "1.42.2", "update_available": True},
    }
    closure = script.resolve_install_closure([{"id": "A", "version": "latest"}], "", installed, upgrade=True)
    assert closure["A"] == "2.0.0"
    # Dependency already satisfies minVersion, so it stays put.
    assert closure["Base"] == "1.42.2"


def test_install_marketplace_packs_upgrade_produces_pending_install():
    script, demisto_mock = load_script()
    script.fetch_installed_packs = lambda using: {"CommonScripts": {"version": "1.22.28", "update_available": True}}
    script.fetch_mandatory_dependencies = lambda packs, using: {}
    script.resolve_latest_version = lambda pack_id, using: "1.22.39"
    demisto_mock._command_responses["core-api-post"] = [{"Type": 1, "Contents": {"response": []}}]

    result = script.install_marketplace_packs([{"id": "CommonScripts", "version": "latest"}], "", 0, 0, debug=False, upgrade=True)

    posts = [c for c in demisto_mock._commands if c[0] == "core-api-post"]
    assert len(posts) == 1
    body = json.loads(posts[0][1]["body"])
    assert body["packs"] == [{"id": "CommonScripts", "version": "1.22.39"}]
    assert result["installed"] == {"CommonScripts": "1.22.39"}


def test_closure_takes_highest_minversion_across_requirers():
    """Regression: Base and CommonScripts want Core >= 3.5.75 while
    CommonPlaybooks only wants 3.5.73. Taking the first value seen resolved
    Core to 3.5.73 and the platform rejected the whole install with
    'Mismatching dependency contentpack with ID Core'.
    """
    script, _ = load_script()
    graph = {
        "Base": {"Core": "3.5.75"},
        "CommonPlaybooks": {"Core": "3.5.73"},
        "CommonScripts": {"Core": "3.5.75"},
        "Core": {},
    }

    def fake_deps(packs, using):
        return {p["id"]: graph.get(p["id"], {}) for p in packs}

    script.fetch_mandatory_dependencies = fake_deps
    closure = script.resolve_install_closure(
        [
            {"id": "CommonPlaybooks", "version": "2.8.5"},
            {"id": "Base", "version": "1.42.13"},
            {"id": "CommonScripts", "version": "1.22.39"},
        ],
        "",
        {},
    )
    assert closure["Core"] == "3.5.75"


def test_closure_highest_minversion_regardless_of_requirer_order():
    script, _ = load_script()
    graph = {"A": {"Dep": "1.0.0"}, "B": {"Dep": "5.0.0"}, "Dep": {}}

    def fake_deps(packs, using):
        return {p["id"]: graph.get(p["id"], {}) for p in packs}

    script.fetch_mandatory_dependencies = fake_deps
    for seeds in (
        [{"id": "A", "version": "1.0.0"}, {"id": "B", "version": "1.0.0"}],
        [{"id": "B", "version": "1.0.0"}, {"id": "A", "version": "1.0.0"}],
    ):
        closure = script.resolve_install_closure(seeds, "", {})
        assert closure["Dep"] == "5.0.0", f"order-dependent result for {seeds}"


def test_closure_keeps_installed_version_when_it_exceeds_all_minimums():
    script, _ = load_script()
    graph = {"A": {"Dep": "1.0.0"}, "B": {"Dep": "2.0.0"}, "Dep": {}}
    script.fetch_mandatory_dependencies = lambda packs, using: {p["id"]: graph.get(p["id"], {}) for p in packs}
    installed = {"Dep": {"version": "9.9.9", "update_available": False}}
    closure = script.resolve_install_closure([{"id": "A", "version": "1.0.0"}, {"id": "B", "version": "1.0.0"}], "", installed)
    assert closure["Dep"] == "9.9.9"


def test_closure_raising_a_dependency_pulls_its_own_new_dependencies():
    script, _ = load_script()
    graph = {
        "A": {"Mid": "2.0.0"},
        # Mid only gains this dependency at 2.0.0.
        "Mid": {"Deep": "1.0.0"},
        "Deep": {},
    }
    script.fetch_mandatory_dependencies = lambda packs, using: {p["id"]: graph.get(p["id"], {}) for p in packs}
    closure = script.resolve_install_closure([{"id": "A", "version": "1.0.0"}], "", {})
    assert closure["Mid"] == "2.0.0"
    assert closure["Deep"] == "1.0.0"


def test_install_sends_ignore_warnings():
    """Regression: without ignoreWarnings a pre-existing incident field makes
    the platform reject the entire install ("Field with name 'Email
    Classification' already exists"), which is guaranteed on any tenant that
    already has content.
    """
    script, demisto_mock = load_script()
    script.fetch_installed_packs = lambda using: {}
    script.resolve_install_closure = lambda seeds, using, installed, upgrade=False: {"CommonScripts": "1.22.39"}
    demisto_mock._command_responses["core-api-post"] = [{"Type": 1, "Contents": {"response": []}}]

    script.install_marketplace_packs([{"id": "CommonScripts", "version": "latest"}], "", 0, 0, debug=False)

    posts = [c for c in demisto_mock._commands if c[0] == "core-api-post"]
    body = json.loads(posts[0][1]["body"])
    assert body["ignoreWarnings"] is True
    assert body["packs"] == [{"id": "CommonScripts", "version": "1.22.39"}]


# ── pack id / directory naming ─────────────────────────────────────────────────


def test_guess_pack_id_strips_version_and_prerelease_suffix():
    script, _ = load_script()
    cases = {
        "soc-optimization-unified.zip": "soc-optimization-unified",
        "soc-optimization-unified-v3.11.2.zip": "soc-optimization-unified",
        "soc-optimization-unified-v3.11.2": "soc-optimization-unified",
        "soc-optimization-unified-v3.11.1-pr1008.zip": "soc-optimization-unified",
        "soc-common-playbooks-unified": "soc-common-playbooks-unified",
        "SocFrameworkAbnormalSecurity-v1.0.4.zip": "SocFrameworkAbnormalSecurity",
        "": "",
    }
    for given, expected in cases.items():
        assert script._guess_pack_id_from_label(given) == expected, given


def test_guess_pack_id_leaves_embedded_dash_v_alone():
    """A naive split on "-v" truncated any pack whose own name contains it."""
    script, _ = load_script()
    assert script._guess_pack_id_from_label("soc-vendor-thing.zip") == "soc-vendor-thing"
    assert script._guess_pack_id_from_label("soc-vendor-thing-v1.2.3.zip") == "soc-vendor-thing"


# ---------------------------
# catalog URL resolution
# ---------------------------


def test_resolve_catalog_url_explicit_arg_wins():
    script, demisto_mock = load_script()
    demisto_mock._command_responses["socfw-get-catalog-url"] = [
        {"Type": 1, "Contents": {"catalog_url": "https://instance.example/catalog.json"}}
    ]

    assert script.resolve_catalog_url("https://explicit.example/catalog.json") == "https://explicit.example/catalog.json"
    # The instance is not consulted when an explicit value is supplied.
    assert not [c for c in demisto_mock._commands if c[0] == "socfw-get-catalog-url"]


def test_resolve_catalog_url_uses_instance_value():
    script, demisto_mock = load_script()
    demisto_mock._command_responses["socfw-get-catalog-url"] = [
        {"Type": 1, "Contents": {"catalog_url": "https://instance.example/catalog.json"}}
    ]

    assert script.resolve_catalog_url("") == "https://instance.example/catalog.json"


def test_resolve_catalog_url_falls_back_when_command_missing():
    script, _ = load_script()
    # No response registered: the command does not exist on this tenant.
    assert script.resolve_catalog_url("") == script.DEFAULT_CATALOG_URL


def test_resolve_catalog_url_falls_back_on_error_entry():
    script, demisto_mock = load_script()
    demisto_mock._command_responses["socfw-get-catalog-url"] = [{"Type": 4, "Contents": "Unsupported command (23)"}]

    assert script.resolve_catalog_url("") == script.DEFAULT_CATALOG_URL
