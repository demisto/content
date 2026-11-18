"""Unit tests for the deterministic Marketplace assessment logic."""

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest


SCRIPT = Path(__file__).with_name("TypeSafeJevMarketplaceAssessment.py")
common_server = sys.modules.setdefault("CommonServerPython", types.ModuleType("CommonServerPython"))
common_server.is_error = lambda entry: entry.get("Type") == 4
common_server.argToBoolean = lambda value: value if isinstance(value, bool) else str(value).lower() == "true"
SPEC = importlib.util.spec_from_file_location("marketplace_assessment", SCRIPT)
marketplace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(marketplace)


def test_version_comparison_handles_release_and_prerelease_ordering():
    assert marketplace.compare_versions("1.2.3", "1.2.4") == -1
    assert marketplace.compare_versions("1.2.3", "1.2.3") == 0
    assert marketplace.compare_versions("1.2.3", "1.2.3-beta.1") == 1
    assert marketplace.compare_versions("1.2.3-beta.2", "1.2.3-beta.10") == -1
    with pytest.raises(ValueError, match="Unsupported version"):
        marketplace.version("latest")


def test_inventory_maps_enabled_instances_and_reports_unknown_brands():
    result = marketplace.inventory(
        {
            "configurations": [
                {"id": "definition-1", "name": "Example", "display": "Example Integration", "packID": "ExamplePack"}
            ],
            "instances": [
                {"id": "enabled", "name": "Enabled", "brand": "definition-1", "enabled": True},
                {"id": "disabled", "name": "Disabled", "brand": "definition-1", "enabled": False},
                {"id": "unknown", "name": "Unknown", "brand": "missing", "enabled": "true"},
            ],
        }
    )
    assert result["components"] == [
        {
            "kind": "integration",
            "id": "enabled",
            "name": "Enabled",
            "brand": "definition-1",
            "display": "Example Integration",
            "pack_id": "ExamplePack",
            "enabled": True,
        }
    ]
    assert result["unmapped"] == ["Unknown"]


@pytest.mark.parametrize(
    ("breaking_notes", "expected"),
    [
        ("The Example integration is removed.", "affected"),
        ("The Example integration is removed when using legacy mode.", "unresolved"),
    ],
)
def test_breaking_changes_require_observed_component_and_unconditional_evidence(breaking_notes, expected):
    pack = {"id": "ExamplePack", "name": "Example", "installed_version": "1.0.0", "target_version": "2.0.0"}
    release = {"version": "2.0.0", "notes": "Release notes", "breaking": True, "breaking_notes": breaking_notes}
    component = {
        "id": "instance-1",
        "pack_id": "ExamplePack",
        "brand": "Example",
        "display": "Example Integration",
        "enabled": True,
    }
    result = marketplace.determine(pack, release, [component])
    assert result["status"] == expected


def test_choice_validation_rejects_malformed_distributions():
    options = ["affected", "nonbreaking", "unaffected", "unknown"]
    valid = {
        "type": "choice",
        "choice": "affected",
        "confidence": 0.85,
        "probabilities": {"affected": 0.9, "nonbreaking": 0.04, "unaffected": 0.03, "unknown": 0.03},
    }
    assert marketplace.validate_choice(valid, options)["probability"] == 0.9
    invalid_sum = dict(valid, probabilities={"affected": 0.7, "nonbreaking": 0.3, "unaffected": 0.3, "unknown": 0.1})
    assert marketplace.validate_choice(invalid_sum, options) is None
    wrong_winner = dict(valid, probabilities={"affected": 0.1, "nonbreaking": 0.7, "unaffected": 0.1, "unknown": 0.1})
    assert marketplace.validate_choice(wrong_winner, options) is None
    assert marketplace.validate_choice(dict(valid, confidence=1.1), options) is None


def test_analysis_rejects_unknown_questions_and_binds_selected_component():
    component = {"id": "instance-1", "pack_id": "ExamplePack", "enabled": True}
    plan = {"model_alias": "jev-1.13.0", "items": [{"id": "release_0", "key": "pack:2.0.0", "candidates": [component]}]}
    response = {
        "model": "jev-1.13.0",
        "answers": {
            "release_0": {
                "type": "choice",
                "choice": "affected",
                "confidence": 0.9,
                "probabilities": {"affected": 0.9, "nonbreaking": 0.04, "unaffected": 0.03, "unknown": 0.03},
            },
            "release_0_component": {
                "type": "choice",
                "choice": "component_0",
                "confidence": 0.9,
                "probabilities": {"none": 0.02, "unobserved": 0.03, "component_0": 0.95},
            },
        },
    }
    decision = marketplace.normalize_analysis(plan, response)[0]
    assert decision["key"] == "pack:2.0.0"
    assert decision["status"] == "affected"
    assert decision["component_ids"] == ["instance-1"]
    response["answers"]["unexpected"] = response["answers"]["release_0"]
    with pytest.raises(ValueError, match="outside this review plan"):
        marketplace.normalize_analysis(plan, response)


def test_dependency_groups_keep_cycles_together_and_order_dependencies_first():
    candidates = [
        {"id": "A", "version": "2.0.0", "dependencies": {"B": {"mandatory": True, "minVersion": "1.0.0"}}},
        {"id": "B", "version": "2.0.0", "dependencies": {"A": {"mandatory": True, "minVersion": "1.0.0"}}},
        {"id": "C", "version": "1.0.0", "dependencies": {}},
        {"id": "D", "version": "1.0.0", "dependencies": {"C": {"mandatory": True, "minVersion": "1.0.0"}}},
    ]
    groups = marketplace.dependency_groups(candidates, {})
    normalized = [sorted(item["id"] for item in group) for group in groups]
    assert ["A", "B"] in normalized
    assert normalized.index(["C"]) < normalized.index(["D"])


def test_install_dry_run_never_calls_installer(monkeypatch):
    timestamp = marketplace.now_iso()
    snapshot = {
        "core_instance": "Core",
        "collected_at": timestamp,
        "packs": [
            {
                "id": "ExamplePack",
                "name": "Example",
                "installed_version": "1.0.0",
                "target_version": "2.0.0",
                "update_available": True,
                "releases": [{"version": "2.0.0"}],
                "dependencies": {},
            }
        ],
    }
    report = {
        "core_instance": "Core",
        "assessed_at": timestamp,
        "analysis_provider": "TypeSafe Jev",
        "ai_decision_count": 1,
        "expected_ai_decision_count": 1,
        "findings": [
            {"pack_id": "ExamplePack", "release_version": "2.0.0", "status": "not_flagged", "release_notes": "Routine fix"}
        ],
    }
    monkeypatch.setattr(marketplace, "_command", lambda *_args, **_kwargs: pytest.fail("Installer called during dry run"))
    monkeypatch.setattr(marketplace, "core", lambda *_args, **_kwargs: [{"id": "ExamplePack", "currentVersion": "1.0.0"}])
    result = marketplace.install_updates(snapshot, report, "Core", True)
    assert result["installed"] == []
    assert result["held"][0]["reason"].startswith("Dry run:")


def test_dependency_expansion_includes_recursive_exact_release_evidence(monkeypatch):
    snapshot = {
        "packs": [
            {
                "id": "Parent",
                "installed_version": "1.0.0",
                "target_version": "1.0.0",
                "update_available": False,
                "dependencies": {"DepA": {"mandatory": True, "minVersion": "1.5.0"}},
            }
        ],
        "installed_versions": {"Parent": "1.0.0"},
    }

    def fake_core(method, uri, _instance, body=None):
        if method == "get" and uri.startswith("/contentpacks/installed/"):
            raise RuntimeError("404 not found")
        if method == "get" and uri.endswith("/DepA"):
            return {
                "id": "DepA",
                "name": "Dependency A",
                "currentVersion": "2.0.0",
                "changelog": {"1.5.0": {"releaseNotes": "A release", "breakingChanges": False}},
                "dependencies": {},
            }
        if method == "get" and uri.endswith("/DepB"):
            return {
                "id": "DepB",
                "name": "Dependency B",
                "currentVersion": "1.0.0",
                "changelog": {"1.0.0": {"releaseNotes": "B release", "breakingChanges": False}},
                "dependencies": {},
            }
        if method == "post" and uri == "/contentpacks/marketplace/search/dependencies":
            requested = body
            rows = []
            for pack in requested:
                dependencies = {"DepB": {"mandatory": True, "minVersion": "1.0.0"}} if pack["id"] == "DepA" else {}
                rows.append(
                    {"extras": {"pack": {"id": pack["id"], "currentVersion": pack["version"], "dependencies": dependencies}}}
                )
            return {"packs": rows}
        raise AssertionError((method, uri, body))

    monkeypatch.setattr(marketplace, "core", fake_core)
    marketplace.expand_dependencies(snapshot, "Core")
    by_id = {pack["id"]: pack for pack in snapshot["packs"]}
    assert by_id["DepA"]["target_version"] == "1.5.0"
    assert by_id["DepA"]["required_by"] == ["Parent"]
    assert by_id["DepB"]["target_version"] == "1.0.0"
    assert by_id["DepB"]["required_by"] == ["DepA"]
    assert snapshot["dependency_packs"] == 2


def test_install_uses_content_pack_installer_and_verifies_exact_target(monkeypatch):
    timestamp = marketplace.now_iso()
    snapshot = {
        "core_instance": "Core",
        "collected_at": timestamp,
        "installed_versions": {"ExamplePack": "1.0.0"},
        "packs": [
            {
                "id": "ExamplePack",
                "name": "Example",
                "installed_version": "1.0.0",
                "target_version": "2.0.0",
                "update_available": True,
                "releases": [{"version": "2.0.0"}],
                "dependencies": {},
            }
        ],
    }
    report = {
        "core_instance": "Core",
        "assessed_at": timestamp,
        "analysis_provider": "TypeSafe Jev",
        "ai_decision_count": 1,
        "expected_ai_decision_count": 1,
        "findings": [
            {"pack_id": "ExamplePack", "release_version": "2.0.0", "status": "not_flagged", "release_notes": "Routine fix"}
        ],
    }
    calls = []
    reads = iter([[{"id": "ExamplePack", "currentVersion": "1.0.0"}], [{"id": "ExamplePack", "currentVersion": "2.0.0"}]])
    monkeypatch.setattr(marketplace, "core", lambda *_args, **_kwargs: next(reads))
    monkeypatch.setattr(marketplace, "_command", lambda name, args: calls.append((name, args)) or [{"Type": 1, "Contents": "ok"}])
    result = marketplace.install_updates(snapshot, report, "Core", False)
    assert result["installed"] == [
        {"pack_id": "ExamplePack", "previous_version": "1.0.0", "version": "2.0.0", "dependency_install": False}
    ]
    assert calls[0][0] == "ContentPackInstaller"
    assert calls[0][1]["install_dependencies"] == "false"


def test_stale_evidence_is_rejected_before_install():
    snapshot = {"core_instance": "Core", "collected_at": "2020-01-01T00:00:00+00:00", "packs": []}
    report = {
        "core_instance": "Core",
        "assessed_at": marketplace.now_iso(),
        "analysis_provider": "TypeSafe Jev",
        "ai_decision_count": 0,
        "expected_ai_decision_count": 0,
        "findings": [],
    }
    with pytest.raises(ValueError, match="Evidence expired"):
        marketplace.install_updates(snapshot, report, "Core", False)


def test_review_dry_run_does_not_resolve_stale_issue(monkeypatch):
    state = {
        "name": "review-ledger",
        "exists": True,
        "data": {
            "review:OldPack:1.0.0": {
                "status": "open",
                "pack_id": "OldPack",
                "target_version": "1.0.0",
                "external_id": "external-1",
            }
        },
    }
    snapshot = {
        "core_instance": "Core",
        "packs": [{"id": "OldPack", "installed_version": "1.0.0", "target_version": "1.0.0"}],
        "installed_versions": {"OldPack": "1.0.0"},
    }
    report = {"core_instance": "Core", "findings": []}
    installation = {"held": [], "failed": [], "installed": [], "already_current": []}
    monkeypatch.setattr(marketplace, "_ledger", lambda *_args: state)
    monkeypatch.setattr(
        marketplace, "_find_issue_by_external_id", lambda *_args: {"id": "issue-1", "external_id": "external-1", "status": "New"}
    )
    monkeypatch.setattr(marketplace, "_resolve_review_issue", lambda *_args: pytest.fail("Issue resolved during dry run"))
    result = marketplace.review_held(snapshot, report, installation, "Core", True)
    assert result["resolved_stale"] == 0
    assert result["stale"][0]["action"] == "would_resolve"


def test_review_closes_stale_tracked_issue_after_target_installs(monkeypatch):
    state = {
        "name": "review-ledger",
        "exists": True,
        "data": {
            "review:OldPack:1.0.0": {
                "status": "open",
                "pack_id": "OldPack",
                "target_version": "1.0.0",
                "external_id": "external-1",
            }
        },
    }
    snapshot = {
        "core_instance": "Core",
        "packs": [{"id": "OldPack", "installed_version": "1.0.0", "target_version": "1.0.0"}],
        "installed_versions": {"OldPack": "1.0.0"},
    }
    report = {"core_instance": "Core", "findings": []}
    installation = {"held": [], "failed": [], "installed": [], "already_current": []}
    saved = []
    monkeypatch.setattr(marketplace, "_ledger", lambda *_args: state)
    monkeypatch.setattr(
        marketplace, "_find_issue_by_external_id", lambda *_args: {"id": "issue-1", "external_id": "external-1", "status": "New"}
    )
    monkeypatch.setattr(marketplace, "_resolve_review_issue", lambda *_args: True)
    monkeypatch.setattr(marketplace, "_save_ledger", lambda ledger, *_args: saved.append(ledger["data"].copy()))
    result = marketplace.review_held(snapshot, report, installation, "Core", False)
    assert result["resolved_stale"] == 1
    assert state["data"]["review:OldPack:1.0.0"]["status"] == "resolved"
    assert saved


def _snapshot(packs=None, components=None):
    return {
        "core_instance": "Core",
        "collected_at": marketplace.now_iso(),
        "packs": packs or [],
        "components": components or [],
        "coverage": {"complete": True},
    }


def _pack(releases=None):
    return {
        "id": "ExamplePack",
        "name": "Example Pack",
        "installed_version": "1.0.0",
        "target_version": "2.0.0",
        "update_available": True,
        "releases": releases or [],
    }


def test_parse_and_freshness_reject_invalid_and_expired_evidence():
    assert marketplace.parse('[{"value": 1}]') == [{"value": 1}]
    assert marketplace.parse(["not-json"]) == "not-json"
    assert marketplace.parse({"value": 1}) == {"value": 1}
    with pytest.raises(ValueError, match="missing or invalid"):
        marketplace.ensure_fresh("not-a-time")
    with pytest.raises(ValueError, match="expired"):
        marketplace.ensure_fresh("2000-01-01T00:00:00+00:00")
    with pytest.raises(ValueError, match="expired"):
        marketplace.ensure_fresh("2999-01-01T00:00:00+00:00")


def test_breaking_notice_and_component_matching_are_conservative():
    assert marketplace.normalize_breaking("True") is True
    assert marketplace.normalize_breaking("false") is False
    assert marketplace.normalize_breaking("unknown") is None
    assert marketplace.notice("The API is deprecated and requires manual migration")
    assert not marketplace.mentions("NotExampleConnector", "Example")
    assert marketplace.mentions("Example Connector removed", "Example")

    pack = _pack()
    component = {"id": "instance-1", "pack_id": pack["id"], "brand": "Example", "display": "Example Connector", "enabled": True}
    release = {"version": "2.0.0", "breaking": True, "breaking_notes": "The Example integration was removed."}
    result = marketplace.determine(pack, release, [component])
    assert result["status"] == "affected"
    assert result["affected_components"] == [component]
    assert marketplace.determine(pack, {"version": "2.0.0", "breaking": "yes"}, [])["status"] == "unresolved"
    assert marketplace.determine(pack, {"version": "2.0.0", "breaking": False, "notes": "Deprecated."}, [])["status"] == "notice"
    assert (
        marketplace.determine(pack, {"version": "2.0.0", "breaking": False, "notes": "Routine maintenance."}, [])["status"]
        == "not_flagged"
    )


def test_inventory_rejects_unknown_schema_and_maps_definition_aliases():
    with pytest.raises(ValueError, match="schema"):
        marketplace.inventory({"instances": []})
    result = marketplace.inventory(
        {
            "configurations": [{"name": "Example", "display": "Example display", "packID": "ExamplePack"}],
            "instances": [{"id": "i1", "brand": "Example", "enabled": "true"}],
        }
    )
    assert result["components"][0]["pack_id"] == "ExamplePack"


def test_assessment_reports_metadata_gaps_and_all_status_counts():
    snapshot = _snapshot(
        [
            _pack(
                [
                    {"version": "2.0.0", "breaking": False, "notes": "Routine maintenance."},
                    {"version": "2.1.0", "breaking": False, "notes": "Deprecated API."},
                ]
            ),
            {"id": "Missing", "collection_issue": "Marketplace lookup failed", "releases": []},
        ],
        components=[{"id": "i1", "pack_id": "Unknown", "enabled": True}],
    )
    report = marketplace.assess(snapshot, "Core")
    assert report["counts"] == {"affected": 0, "unresolved": 1, "notice": 1, "not_flagged": 1}
    assert report["health"] == "incomplete"
    with pytest.raises(ValueError, match="different tenant"):
        marketplace.assess(snapshot, "OtherCore")


def test_prepare_ai_builds_evidence_bound_questions_and_empty_plan():
    component = {"id": "instance-1", "pack_id": "ExamplePack", "enabled": True}
    snapshot = _snapshot([_pack([{"version": "2.0.0", "breaking": True, "breaking_notes": "Removed API."}])], [component])
    plan = marketplace.prepare_ai(snapshot, "Core", "jev-1.13.0")
    assert plan["Required"] is True
    assert plan["items"][0]["candidates"] == [component]
    assert json.loads(plan["QuestionsJSON"])["release_0_component"]["criteria"]["component_0"]
    empty = marketplace.prepare_ai(_snapshot(), "Core", "")
    assert empty["Required"] is False
    assert empty["BatchJSON"] == []
    with pytest.raises(ValueError, match="different tenant"):
        marketplace.prepare_ai(snapshot, "OtherCore", "jev-1.13.0")


def _answer(choice, labels):
    return {
        "type": "choice",
        "choice": choice,
        "confidence": 0.95,
        "probabilities": {label: (0.95 if label == choice else 0.05 / (len(labels) - 1)) for label in labels},
    }


def test_normalize_and_apply_ai_validate_evidence_and_impact_paths():
    component = {"id": "instance-1", "pack_id": "ExamplePack", "enabled": True}
    snapshot = _snapshot([_pack([{"version": "2.0.0", "breaking": True, "breaking_notes": "Removed API."}])], [component])
    plan = marketplace.prepare_ai(snapshot, "Core", "jev-1.13.0")
    response = {
        "model": plan["model_alias"],
        "answers": {
            "release_0": _answer("affected", list(marketplace.IMPACT_OPTIONS)),
            "release_0_component": _answer("component_0", ["none", "unobserved", "component_0"]),
        },
    }
    decisions = marketplace.normalize_analysis(plan, {"Contents": json.dumps(response)})
    assert decisions[0]["component_ids"] == ["instance-1"]
    report = marketplace.apply_ai(plan, response, "Core")
    assert report["findings"][0]["status"] == "affected"
    assert report["analysis_provider"] == "TypeSafe Jev"
    for bad in ({"model": "wrong", "answers": {}}, {"model": plan["model_alias"], "answers": {"other": {}}}):
        with pytest.raises(ValueError):
            marketplace.normalize_analysis(plan, bad)
    with pytest.raises(ValueError, match="another integration"):
        marketplace.apply_ai(plan, response, "OtherCore")


def test_review_payload_includes_decision_evidence_and_deduplication_key():
    pack = _pack([{"version": "2.0.0", "breaking": True, "breaking_notes": "Removed API."}])
    finding = {
        "release_version": "2.0.0",
        "status": "affected",
        "reason": "Validate migration",
        "analysis": {"status": "affected", "confidence": 0.9, "probability": 0.95},
    }
    payload = marketplace._review_payload(pack, {"target_version": "2.0.0"}, [finding])
    assert payload["key"] == "review:ExamplePack:2.0.0"
    assert "Jev=affected" in payload["description"]
    assert "Release notes" in payload["description"]


def test_pack_detail_filters_releases_by_installed_and_requested_target(monkeypatch):
    responses = [
        [{"id": "ExamplePack", "currentVersion": "1.0.0"}],
        {
            "id": "ExamplePack",
            "name": "Example Pack",
            "currentVersion": "3.0.0",
            "changelog": {
                "1.0.0": {},
                "2.0.0": {"breakingChanges": True, "releaseNotes": "Changes"},
                "3.0.0": {"releaseNotes": "Latest"},
            },
            "dependencies": {"CommonScripts": {"mandatory": True, "minVersion": "1.0.0"}},
        },
    ]
    monkeypatch.setattr(marketplace, "core", lambda *_args, **_kwargs: responses.pop(0))
    result = marketplace.pack_detail("ExamplePack", "2.0.0", "Core")
    assert result["installed_version"] == "1.0.0"
    assert [release["version"] for release in result["releases"]] == ["2.0.0"]
    assert result["dependencies"][0]["mandatory"] is True


def test_collect_builds_release_inventory_and_rejects_mismatched_sources(monkeypatch):
    responses = {
        "/contentpacks/installed-expired": [
            {
                "id": "ExamplePack",
                "name": "Example Pack",
                "changelog": {
                    "1.0.0": {},
                    "2.0.0": {
                        "releaseNotes": "Changed",
                        "breakingChanges": "true",
                        "breakingChangesNotes": "Migration required",
                    },
                },
                "dependencies": {},
            }
        ],
        "/contentpacks/metadata/installed": [{"id": "ExamplePack", "currentVersion": "1.0.0", "updateAvailable": True}],
        "/settings/integration/search": {"configurations": [], "instances": []},
    }
    monkeypatch.setattr(marketplace, "core", lambda _method, uri, *_args: responses[uri])
    monkeypatch.setattr(marketplace, "expand_dependencies", lambda *_args: None)
    result = marketplace.collect("Core")
    assert result["packs"][0]["target_version"] == "2.0.0"
    assert result["packs"][0]["releases"][0]["breaking"] is True
    responses["/contentpacks/metadata/installed"] = []
    with pytest.raises(RuntimeError, match="inconsistent"):
        marketplace.collect("Core")


def test_publish_dry_run_creation_and_existing_deduplication(monkeypatch):
    report = {
        "core_instance": "Core",
        "health": "completed",
        "counts": {"affected": 1},
        "findings": [{"key": "ExamplePack:2.0.0", "status": "affected", "pack_name": "Example", "release_version": "2.0.0"}],
    }
    assert marketplace.publish(report, "Core", True)["would_create"] == 1
    with pytest.raises(ValueError, match="different integration"):
        marketplace.publish(report, "OtherCore", True)

    state = {"data": {}}
    monkeypatch.setattr(marketplace, "_ledger", lambda *_args: state)
    saved = []
    monkeypatch.setattr(marketplace, "_save_ledger", lambda *_args: saved.append(True))
    monkeypatch.setattr(marketplace, "_create_issue", lambda *_args: {"external_id": "external-1"})
    created = marketplace.publish(report, "Core", False)
    assert created["created"] == 1
    assert state["data"]["ExamplePack:2.0.0"]["external_id"] == "external-1"
    existing = marketplace.publish(report, "Core", False)
    assert existing["existing"] == 1
    assert saved


def test_review_held_dry_run_and_creation_are_deduplicated(monkeypatch):
    snapshot = _snapshot([_pack([{"version": "2.0.0", "notes": "Changes"}])])
    report = {"core_instance": "Core", "findings": [{"pack_id": "ExamplePack", "release_version": "2.0.0"}]}
    installation = {"held": [{"pack_id": "ExamplePack", "target_version": "2.0.0", "reason": "Uncertain"}], "failed": []}
    state = {"data": {}}
    monkeypatch.setattr(marketplace, "_ledger", lambda *_args: state)
    monkeypatch.setattr(marketplace, "_save_ledger", lambda *_args: None)
    dry = marketplace.review_held(snapshot, report, installation, "Core", True)
    assert dry["would_create"] == 1
    monkeypatch.setattr(marketplace, "_create_issue", lambda *_args: {"external_id": "review-1", "issue_id": "42"})
    created = marketplace.review_held(snapshot, report, installation, "Core", False)
    assert created["created"] == 1
    assert state["data"]["review:ExamplePack:2.0.0"]["status"] == "open"
    monkeypatch.setattr(
        marketplace, "_find_issue_by_external_id", lambda *_args: {"id": "42", "external_id": "review-1", "status": "New"}
    )
    existing = marketplace.review_held(snapshot, report, installation, "Core", False)
    assert existing["existing"] == 1


def test_command_and_core_wrappers_validate_cortex_responses(monkeypatch):
    monkeypatch.setattr(
        marketplace,
        "demisto",
        types.SimpleNamespace(executeCommand=lambda *_args: [{"Type": 1, "Contents": '{"response":{"ok":true}}'}]),
        raising=False,
    )
    assert marketplace.core("get", "/example", "Core") == {"ok": True}
    monkeypatch.setattr(marketplace.demisto, "executeCommand", lambda *_args: [{"Type": 4, "Contents": "bad"}])
    with pytest.raises(RuntimeError, match="bad"):
        marketplace._command("test", {})
    monkeypatch.setattr(marketplace.demisto, "executeCommand", lambda *_args: [])
    with pytest.raises(RuntimeError, match="no response"):
        marketplace._command("empty", {})
    monkeypatch.setattr(marketplace.demisto, "executeCommand", lambda *_args: [{"Type": 1, "Contents": "not-json"}])
    with pytest.raises(RuntimeError, match="expected API response"):
        marketplace.core("get", "/empty", "Core")


def test_main_parses_dry_run_with_arg_to_boolean(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        marketplace,
        "install_updates",
        lambda snapshot, assessment, instance, dry_run: captured.update(dry_run=dry_run) or {"ok": True},
    )
    monkeypatch.setattr(marketplace, "CommandResults", lambda **kwargs: kwargs, raising=False)
    monkeypatch.setattr(marketplace, "return_results", lambda _result: None, raising=False)
    monkeypatch.setattr(marketplace, "demisto", types.SimpleNamespace(setContext=lambda *_args: None), raising=False)

    marketplace.main({"action": "install", "core_instance": "Core", "dry_run": "false"})

    assert captured["dry_run"] is False


def test_dependency_metadata_helpers_validate_exact_versions(monkeypatch):
    monkeypatch.setattr(marketplace, "core", lambda *_args: {"id": "Dep", "currentVersion": "2.0.0"})
    assert marketplace._installed_detail("Dep", "Core")["currentVersion"] == "2.0.0"
    monkeypatch.setattr(marketplace, "core", lambda *_args: {"not": "a pack"})
    with pytest.raises(ValueError, match="Unrecognized"):
        marketplace._installed_detail("Dep", "Core")
    monkeypatch.setattr(
        marketplace,
        "core",
        lambda *_args: {"packs": [{"extras": {"pack": {"id": "Dep", "currentVersion": "2.0.0", "dependencies": {}}}}]},
    )
    found = marketplace._exact_dependency_metadata([{"id": "Dep", "version": "2.0.0"}], "Core")
    assert found["Dep"]["currentVersion"] == "2.0.0"
    with pytest.raises(ValueError, match="target mismatch"):
        marketplace._exact_dependency_metadata([{"id": "Dep", "version": "3.0.0"}], "Core")


def test_installer_holds_incompatible_dependency_and_changed_state(monkeypatch):
    timestamp = marketplace.now_iso()
    snapshot = {
        "core_instance": "Core",
        "collected_at": timestamp,
        "packs": [
            {
                "id": "Parent",
                "installed_version": "1.0.0",
                "target_version": "2.0.0",
                "update_available": True,
                "releases": [{"version": "2.0.0"}],
                "dependencies": {"Dependency": {"mandatory": True, "minVersion": "2.0.0"}},
            },
            {
                "id": "Dependency",
                "installed_version": "1.0.0",
                "target_version": "2.0.0",
                "update_available": True,
                "releases": [{"version": "2.0.0"}],
                "dependencies": {},
            },
        ],
    }
    report = {
        "core_instance": "Core",
        "assessed_at": timestamp,
        "analysis_provider": "TypeSafe Jev",
        "ai_decision_count": 2,
        "expected_ai_decision_count": 2,
        "findings": [
            {"pack_id": "Parent", "status": "not_flagged", "release_notes": "Routine"},
            {"pack_id": "Dependency", "status": "affected", "release_notes": "Breaking"},
        ],
    }
    monkeypatch.setattr(
        marketplace,
        "core",
        lambda *_args: [
            {"id": "Parent", "currentVersion": "1.0.0"},
            {"id": "Dependency", "currentVersion": "1.0.0"},
        ],
    )
    result = marketplace.install_updates(snapshot, report, "Core", True)
    assert any(item["pack_id"] == "Parent" and "dependency" in item["reason"].lower() for item in result["held"])
    assert any(item["pack_id"] == "Dependency" for item in result["held"])


def test_ledger_helpers_read_write_and_validate_persisted_state(monkeypatch):
    monkeypatch.setattr(marketplace, "core", lambda *_args: [])
    missing = marketplace._ledger("state", "Core")
    assert missing == {"name": "state", "data": {}, "exists": False}
    responses = iter([[{"name": "state", "data": '{"a":1}'}], [{"name": "state", "data": '{"a":1}'}]])
    monkeypatch.setattr(marketplace, "core", lambda *_args: next(responses))
    monkeypatch.setattr(marketplace, "_command", lambda *_args: [{"Type": 1}])
    saved = {"name": "state", "data": {"a": 1}, "exists": False}
    marketplace._save_ledger(saved, "Core")
    assert saved["exists"] is True


def test_close_review_requires_matching_installed_target(monkeypatch):
    monkeypatch.setattr(marketplace, "core", lambda *_args: [{"id": "ExamplePack", "currentVersion": "1.0.0"}])
    with pytest.raises(ValueError, match="exact target version"):
        marketplace.close_review({"pack": "ExamplePack", "target_version": "2.0.0"}, "Core")
    with pytest.raises(ValueError, match="requires pack"):
        marketplace.close_review({"pack": "", "target_version": "2.0.0"}, "Core")


def test_review_issue_helpers_resolve_and_reconcile(monkeypatch):
    assert marketplace._issue_is_open({"status": "New"})
    assert not marketplace._issue_is_open({"status.progress": "Resolved"})
    assert marketplace._resolve_review_issue({}, "reason", "Core") is False
    assert marketplace._resolve_review_issue({"id": "1", "status": "Resolved"}, "reason", "Core") is True
    calls = []
    monkeypatch.setattr(marketplace, "core", lambda *_args: calls.append(True) or {})
    monkeypatch.setattr(
        marketplace,
        "_find_issue_by_external_id",
        lambda *_args: {"id": "1", "external_id": "ext", "status": "Resolved"},
    )
    assert marketplace._resolve_review_issue({"id": "1", "external_id": "ext", "status": "New"}, "done", "Core")
    assert calls
