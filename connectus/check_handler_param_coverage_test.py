"""Unit tests for ``check_handler_param_coverage``.

The tests build minimal connector layouts under ``tmp_path`` so each scenario
(hidden exclusion, serializer translation, view-group filtering, auth-profile
inclusion, capability filtering) is isolated. A couple of tests also exercise
the real Salesforce fixture under
``runtime_demisto.params_parity/test_data`` to lock in end-to-end behavior.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

import check_handler_param_coverage as mod

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------
HANDLER_REL = Path("components") / "handlers" / "xsoar-test"


def _write_yaml(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        yaml.safe_dump(doc, fh)


def _build_connector(
    tmp_path: Path,
    *,
    handler: dict,
    capabilities: dict | None = None,
    configurations: dict | None = None,
    connection: dict | None = None,
    serializer: dict | None = None,
) -> tuple[Path, Path]:
    """Create a connector layout. Returns (connector_root, handler_dir)."""
    connector_root = tmp_path / "myconnector"
    handler_dir = connector_root / HANDLER_REL
    _write_yaml(handler_dir / mod.HANDLER_FILE, handler)
    if capabilities is not None:
        _write_yaml(connector_root / mod.CAPABILITIES_FILE, capabilities)
    if configurations is not None:
        _write_yaml(connector_root / mod.CONFIGURATIONS_FILE, configurations)
    if connection is not None:
        _write_yaml(connector_root / mod.CONNECTION_FILE, connection)
    if serializer is not None:
        _write_yaml(handler_dir / mod.SERIALIZER_GLOB, serializer)
    return connector_root, handler_dir


def _write_integration_yml(tmp_path: Path, configuration: list[dict]) -> Path:
    path = tmp_path / "integration.yml"
    _write_yaml(path, {"name": "Test", "configuration": configuration})
    return path


# ---------------------------------------------------------------------------
# _is_hidden / collect_yml_params
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "param,expected",
    [
        ({"name": "a"}, False),
        ({"name": "a", "hidden": False}, False),
        ({"name": "a", "hidden": []}, False),
        ({"name": "a", "hidden": True}, True),
        ({"name": "a", "hidden": "platform"}, True),
        ({"name": "a", "hidden": ["platform"]}, True),
        ({"name": "a", "hidden": ["marketplacev2", "platform"]}, True),
    ],
)
def test_is_hidden(param: dict, expected: bool) -> None:
    assert mod._is_hidden(param) is expected


def test_collect_yml_params_excludes_hidden() -> None:
    cfg = [
        {"name": "visible1"},
        {"name": "visible2", "hidden": False},
        {"name": "hidden_bool", "hidden": True},
        {"name": "hidden_platform", "hidden": "platform"},
        {"name": "hidden_list", "hidden": ["platform"]},
        {"no_name": "ignored"},
    ]
    assert mod.collect_yml_params({"configuration": cfg}) == {"visible1", "visible2"}


# ---------------------------------------------------------------------------
# parse_handler
# ---------------------------------------------------------------------------
def test_parse_handler_extracts_view_group_caps_and_profiles() -> None:
    handler = {
        "id": "xsoar-test",
        "capabilities": [
            {
                "id": "automation",
                "auth_options": [
                    {"id": "oauth2.test"},
                    {"id": "apikey.test"},
                ],
            },
            {"id": "fetch-issues", "auth_options": [{"id": "oauth2.test"}]},
        ],
    }
    view_group, cap_ids, profile_ids = mod.parse_handler(handler)
    assert view_group == "xsoar-test"
    assert cap_ids == {"automation", "fetch-issues"}
    assert profile_ids == {"oauth2.test", "apikey.test"}


# ---------------------------------------------------------------------------
# serializer + resolver
# ---------------------------------------------------------------------------
def test_load_serializer_mappings_and_resolve(tmp_path: Path) -> None:
    handler = {"id": "xsoar-test", "capabilities": []}
    _, handler_dir = _build_connector(
        tmp_path,
        handler=handler,
        serializer={"field_mappings": [{"id": "domain", "field_name": "url"}]},
    )
    mappings = mod.load_serializer_mappings(handler_dir)
    assert mappings == {"domain": "url"}
    assert mod.resolve_param_name("domain", mappings) == "url"
    assert mod.resolve_param_name("other", mappings) == "other"


# ---------------------------------------------------------------------------
# connector-root resolution
# ---------------------------------------------------------------------------
def test_resolve_connector_root(tmp_path: Path) -> None:
    _, handler_dir = _build_connector(tmp_path, handler={"id": "xsoar-test"})
    assert mod.resolve_connector_root(handler_dir) == (tmp_path / "myconnector").resolve()


def test_resolve_connector_root_bad_layout(tmp_path: Path) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    with pytest.raises(mod.CoverageError):
        mod.resolve_connector_root(flat)


# ---------------------------------------------------------------------------
# capability-config collector
# ---------------------------------------------------------------------------
def test_capability_config_filters_by_handler_capability_ids() -> None:
    configurations = {
        "configurations": [
            {
                "id": "automation",
                "configurations": [{"fields": [{"id": "create_user"}]}],
            },
            {
                "id": "other-cap",
                "configurations": [{"fields": [{"id": "should_not_appear"}]}],
            },
        ]
    }
    ids = mod.collect_capability_config_field_ids({}, configurations, {"automation"})
    assert ids == ["create_user"]


def test_capability_config_flattens_nested_checkbox_group() -> None:
    """A checkbox_group wrapper is not a param; its nested leaves are."""
    configurations = {
        "configurations": [
            {
                "id": "automation",
                "configurations": [
                    {
                        "fields": [
                            {
                                "id": "user_operations",
                                "field_type": "checkbox_group",
                                "fields": [
                                    {"id": "create_user_enabled"},
                                    {"id": "update_user_enabled"},
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    }
    ids = mod.collect_capability_config_field_ids({}, configurations, {"automation"})
    assert set(ids) == {"create_user_enabled", "update_user_enabled"}
    # The wrapper container id is NOT treated as a param.
    assert "user_operations" not in ids


def test_capability_config_includes_sub_capabilities() -> None:
    capabilities = {
        "capabilities": [
            {
                "id": "posture",
                "configurations": [{"fields": [{"id": "parent_field"}]}],
                "sub_capabilities": [
                    {
                        "id": "posture-remediation",
                        "configurations": [{"fields": [{"id": "sub_field"}]}],
                    }
                ],
            }
        ]
    }
    ids = mod.collect_capability_config_field_ids(
        capabilities, {}, {"posture-remediation"}
    )
    assert "sub_field" in ids


# ---------------------------------------------------------------------------
# general-configurations collector (view_group filtering)
# ---------------------------------------------------------------------------
def test_general_config_view_group_filtering() -> None:
    doc = {
        "general_configurations": {
            "configurations": [
                {"view_group": "xsoar-test", "fields": [{"id": "mine"}]},
                {"view_group": "other-handler", "fields": [{"id": "theirs"}]},
                {"fields": [{"id": "shared"}]},  # no view_group → shared
            ]
        }
    }
    ids = mod.collect_general_config_field_ids([doc], {"xsoar-test"})
    assert set(ids) == {"mine", "shared"}
    assert "theirs" not in ids


def test_general_config_flattens_nested_checkbox_group() -> None:
    """A general-config checkbox_group wrapper is flattened to its leaves."""
    doc = {
        "general_configurations": {
            "configurations": [
                {
                    "fields": [
                        {
                            "id": "user_operations",
                            "field_type": "checkbox_group",
                            "fields": [
                                {"id": "create_user_enabled"},
                                {"id": "disable_user_enabled"},
                            ],
                        }
                    ]
                }
            ]
        }
    }
    ids = mod.collect_general_config_field_ids([doc], {"xsoar-test"})
    assert set(ids) == {"create_user_enabled", "disable_user_enabled"}
    assert "user_operations" not in ids


# ---------------------------------------------------------------------------
# handler view-group resolver
# ---------------------------------------------------------------------------
def test_resolve_handler_view_groups_from_configurations() -> None:
    """View groups come from the per-capability config entries, not the id."""
    configurations = {
        "configurations": [
            {"id": "automation-and-remediation_psps", "view_group": "psps"},
            {"id": "unrelated_cap", "view_group": "other"},
        ]
    }
    capabilities: dict = {"capabilities": []}
    view_groups = mod.resolve_handler_view_groups(
        configurations, capabilities, {"automation-and-remediation_psps"}
    )
    assert view_groups == {"psps"}


def test_resolve_handler_view_groups_from_inline_capabilities() -> None:
    """Inline view_group on a capability / sub-capability is also collected."""
    configurations: dict = {"configurations": []}
    capabilities = {
        "capabilities": [
            {
                "id": "automation",
                "view_group": "vg-top",
                "sub_capabilities": [
                    {"id": "automation_sub", "view_group": "vg-sub"},
                ],
            }
        ]
    }
    view_groups = mod.resolve_handler_view_groups(
        configurations, capabilities, {"automation_sub"}
    )
    assert view_groups == {"vg-sub"}


def test_resolve_handler_view_groups_empty_when_no_match() -> None:
    configurations = {
        "configurations": [{"id": "some_cap", "view_group": "psps"}]
    }
    view_groups = mod.resolve_handler_view_groups(
        configurations, {"capabilities": []}, {"different_cap"}
    )
    assert view_groups == set()


# ---------------------------------------------------------------------------
# auth-profile collector
# ---------------------------------------------------------------------------
def test_auth_profile_collector_filters_by_referenced_ids() -> None:
    connection = {
        "profiles": [
            {
                "id": "oauth2.test",
                "configurations": [{"fields": [{"id": "client_key"}, {"id": "client_secret"}]}],
            },
            {
                "id": "unused.test",
                "configurations": [{"fields": [{"id": "unused_field"}]}],
            },
        ]
    }
    ids = mod.collect_auth_profile_field_ids(connection, {"oauth2.test"})
    assert set(ids) == {"client_key", "client_secret"}
    assert "unused_field" not in ids


# ---------------------------------------------------------------------------
# End-to-end check_coverage (tmp fixtures)
# ---------------------------------------------------------------------------
def _full_connector(tmp_path: Path):
    handler = {
        "id": "xsoar-test",
        "capabilities": [
            {"id": "automation", "auth_options": [{"id": "oauth2.test"}]},
        ],
    }
    capabilities = {"capabilities": [{"id": "automation"}]}
    configurations = {
        "configurations": [
            {
                "id": "automation",
                "configurations": [{"fields": [{"id": "create_user"}]}],
            }
        ],
        "general_configurations": {
            "configurations": [
                {"view_group": "xsoar-test", "fields": [{"id": "log_level"}]},
            ]
        },
    }
    connection = {
        "general_configurations": {
            "configurations": [
                {"view_group": "xsoar-test", "fields": [{"id": "domain"}]},
            ]
        },
        "profiles": [
            {
                "id": "oauth2.test",
                "configurations": [{"fields": [{"id": "client_key"}]}],
            }
        ],
    }
    serializer = {"field_mappings": [{"id": "domain", "field_name": "url"}]}
    return _build_connector(
        tmp_path,
        handler=handler,
        capabilities=capabilities,
        configurations=configurations,
        connection=connection,
        serializer=serializer,
    )


def test_check_coverage_pass(tmp_path: Path) -> None:
    _, handler_dir = _full_connector(tmp_path)
    # All YML params map into the connector set: create_user, log_level,
    # url (serializer-translated from domain), client_key.
    yml = _write_integration_yml(
        tmp_path,
        [
            {"name": "create_user"},
            {"name": "log_level"},
            {"name": "url"},
            {"name": "client_key"},
            {"name": "secret_hidden", "hidden": True},  # excluded
        ],
    )
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is True
    assert missing == set()


def test_check_coverage_general_config_view_group_differs_from_handler_id(
    tmp_path: Path,
) -> None:
    """General-config params pinned to the sub-capability's view group are
    covered even when the handler id differs from the view group.

    Mirrors the real ``psps`` connector: the handler id is ``xsoar-psps`` but
    the per-capability config entry (and its general-config group) is pinned to
    the ``psps`` view group. The view group must be derived from the config
    entry, not the handler id, or ``integrationLogLevel`` is missed.
    """
    handler = {
        "id": "xsoar-psps",
        "capabilities": [{"id": "automation-and-remediation_psps"}],
    }
    capabilities = {
        "capabilities": [
            {
                "id": "automation-and-remediation",
                "sub_capabilities": [{"id": "automation-and-remediation_psps"}],
            }
        ]
    }
    configurations = {
        "configurations": [
            {
                "id": "automation-and-remediation_psps",
                "view_group": "psps",
                "configurations": [{"fields": [{"id": "defaultIgnore"}]}],
            }
        ],
        "general_configurations": {
            "configurations": [
                {"view_group": "psps", "fields": [{"id": "integrationLogLevel"}]},
            ]
        },
    }
    _, handler_dir = _build_connector(
        tmp_path,
        handler=handler,
        capabilities=capabilities,
        configurations=configurations,
    )
    yml = _write_integration_yml(
        tmp_path,
        [{"name": "defaultIgnore"}, {"name": "integrationLogLevel"}],
    )
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is True
    assert missing == set()


def test_check_coverage_fail_lists_missing(tmp_path: Path) -> None:
    _, handler_dir = _full_connector(tmp_path)
    yml = _write_integration_yml(
        tmp_path,
        [
            {"name": "create_user"},
            {"name": "not_in_connector"},
            {"name": "also_missing"},
        ],
    )
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is False
    assert missing == {"not_in_connector", "also_missing"}


def test_check_coverage_serializer_translation_required(tmp_path: Path) -> None:
    """``domain`` connector id must be compared as the original ``url``."""
    _, handler_dir = _full_connector(tmp_path)
    # YML uses original name `url`; without serializer translation it'd be
    # reported missing.
    yml = _write_integration_yml(tmp_path, [{"name": "url"}])
    passed, _ = mod.check_coverage(handler_dir, yml)
    assert passed is True

    # The raw connector id `domain` is NOT a YML param name → reported missing.
    yml2 = _write_integration_yml(tmp_path, [{"name": "domain"}])
    passed2, missing2 = mod.check_coverage(handler_dir, yml2)
    assert passed2 is False
    assert missing2 == {"domain"}


def test_check_coverage_bad_handler_path(tmp_path: Path) -> None:
    yml = _write_integration_yml(tmp_path, [{"name": "a"}])
    with pytest.raises(mod.CoverageError):
        mod.check_coverage(tmp_path / "nope", yml)


# ---------------------------------------------------------------------------
# handler.yaml path input (file path accepted, dir back-compat)
# ---------------------------------------------------------------------------
def test_check_coverage_accepts_handler_yaml_file_path(tmp_path: Path) -> None:
    """check_coverage accepts the path to handler.yaml directly."""
    _, handler_dir = _full_connector(tmp_path)
    yml = _write_integration_yml(tmp_path, [{"name": "create_user"}])
    handler_yaml_path = handler_dir / mod.HANDLER_FILE
    passed, missing = mod.check_coverage(handler_yaml_path, yml)
    assert passed is True
    assert missing == set()


def test_check_coverage_still_accepts_handler_dir(tmp_path: Path) -> None:
    """Back-compat: the handler directory is still accepted."""
    _, handler_dir = _full_connector(tmp_path)
    yml = _write_integration_yml(tmp_path, [{"name": "create_user"}])
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is True
    assert missing == set()


# ---------------------------------------------------------------------------
# computed_fields.output collection
# ---------------------------------------------------------------------------
def test_load_serializer_computed_output_ids(tmp_path: Path) -> None:
    handler = {"id": "xsoar-test", "capabilities": []}
    _, handler_dir = _build_connector(
        tmp_path,
        handler=handler,
        serializer={
            "computed_fields": [
                {"output": [{"id": "fetch_event"}, {"id": "another_output"}]},
                {"output": [{"id": "third_output"}]},
            ]
        },
    )
    ids = mod.load_serializer_computed_output_ids(handler_dir)
    assert set(ids) == {"fetch_event", "another_output", "third_output"}


def test_check_coverage_computed_output_counts_as_param(tmp_path: Path) -> None:
    """A computed_fields output id covers the matching integration param."""
    handler = {"id": "xsoar-test", "capabilities": []}
    _, handler_dir = _build_connector(
        tmp_path,
        handler=handler,
        serializer={
            "computed_fields": [{"output": [{"id": "synthetic_param"}]}],
        },
    )
    yml = _write_integration_yml(tmp_path, [{"name": "synthetic_param"}])
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is True
    assert missing == set()


def test_check_coverage_computed_output_resolved_via_field_mappings(
    tmp_path: Path,
) -> None:
    """A computed output id is resolved through serializer field_mappings."""
    handler = {"id": "xsoar-test", "capabilities": []}
    _, handler_dir = _build_connector(
        tmp_path,
        handler=handler,
        serializer={
            "field_mappings": [{"id": "synthetic", "field_name": "original_name"}],
            "computed_fields": [{"output": [{"id": "synthetic"}]}],
        },
    )
    yml = _write_integration_yml(tmp_path, [{"name": "original_name"}])
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is True
    assert missing == set()


# ---------------------------------------------------------------------------
# Platform "alert" renames: incidentType / incidentFetchInterval
# ---------------------------------------------------------------------------
def _alert_connector(tmp_path: Path, *, alert_field_id: str):
    """Build a connector whose automation cap exposes a single alert field."""
    handler = {
        "id": "xsoar-test",
        "capabilities": [{"id": "automation"}],
    }
    configurations = {
        "configurations": [
            {
                "id": "automation",
                "configurations": [{"fields": [{"id": alert_field_id}]}],
            }
        ]
    }
    return _build_connector(
        tmp_path,
        handler=handler,
        capabilities={"capabilities": [{"id": "automation"}]},
        configurations=configurations,
    )


def test_incident_type_covered_by_bare_alert_type(tmp_path: Path) -> None:
    _, handler_dir = _alert_connector(tmp_path, alert_field_id="alertType")
    yml = _write_integration_yml(tmp_path, [{"name": "incidentType"}])
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is True
    assert missing == set()


def test_incident_type_covered_by_prefixed_alert_type(tmp_path: Path) -> None:
    _, handler_dir = _alert_connector(
        tmp_path, alert_field_id="fetch-issues_xsoar_alertType"
    )
    yml = _write_integration_yml(tmp_path, [{"name": "incidentType"}])
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is True
    assert missing == set()


def test_incident_type_missing_when_no_alert_type(tmp_path: Path) -> None:
    _, handler_dir = _alert_connector(tmp_path, alert_field_id="unrelated_field")
    yml = _write_integration_yml(tmp_path, [{"name": "incidentType"}])
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is False
    assert missing == {"incidentType"}


def test_incident_fetch_interval_covered_by_bare_alert_fetch_interval(
    tmp_path: Path,
) -> None:
    _, handler_dir = _alert_connector(tmp_path, alert_field_id="alertFetchInterval")
    yml = _write_integration_yml(tmp_path, [{"name": "incidentFetchInterval"}])
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is True
    assert missing == set()


def test_incident_fetch_interval_covered_by_prefixed_field(tmp_path: Path) -> None:
    _, handler_dir = _alert_connector(
        tmp_path, alert_field_id="fetch-issues_xsoar_alertFetchInterval"
    )
    yml = _write_integration_yml(tmp_path, [{"name": "incidentFetchInterval"}])
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is True
    assert missing == set()


def test_incident_fetch_interval_missing_when_no_alert_field(tmp_path: Path) -> None:
    _, handler_dir = _alert_connector(tmp_path, alert_field_id="unrelated_field")
    yml = _write_integration_yml(tmp_path, [{"name": "incidentFetchInterval"}])
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is False
    assert missing == {"incidentFetchInterval"}


# ---------------------------------------------------------------------------
# Real Salesforce fixture (integration test)
# ---------------------------------------------------------------------------
SALESFORCE_HANDLER = (
    Path(__file__).parent
    / "runtime_demisto.params_parity"
    / "test_data"
    / "connectors"
    / "salesforce"
    / "components"
    / "handlers"
    / "xsoar_sf"
)


@pytest.mark.skipif(
    not SALESFORCE_HANDLER.is_dir(), reason="salesforce fixture not present"
)
def test_salesforce_fixture_collects_expected_params(tmp_path: Path) -> None:
    connector_root = mod.resolve_connector_root(SALESFORCE_HANDLER)
    capabilities_doc = mod.load_yaml(connector_root / mod.CAPABILITIES_FILE)
    configurations_doc = mod.load_yaml(connector_root / mod.CONFIGURATIONS_FILE)
    connection_doc = mod.load_yaml(connector_root / mod.CONNECTION_FILE)
    handler_yaml = mod.load_yaml(SALESFORCE_HANDLER / mod.HANDLER_FILE)

    params = mod.collect_connector_params(
        SALESFORCE_HANDLER,
        capabilities_doc,
        configurations_doc,
        connection_doc,
        handler_yaml,
    )
    # automation-and-remediation capability fields.
    assert "create_user_enabled" in params
    # serializer translates connector `domain` → `InstanceURL`.
    assert "InstanceURL" in params
    # auth-profile field from the referenced oauth2 profile.
    assert "client_key" in params


# ---------------------------------------------------------------------------
# type:9 credentials params
# ---------------------------------------------------------------------------
def test_collect_type9_params_maps_name_to_hiddenusername() -> None:
    cfg = [
        {"name": "creds", "type": mod.YML_TYPE_CREDENTIALS},
        {"name": "apikey_creds", "type": mod.YML_TYPE_CREDENTIALS, "hiddenusername": True},
        {"name": "plain", "type": 0},  # not credentials
        {"name": "enc", "type": 4},  # encrypted, not credentials
        {"name": "hidden_creds", "type": mod.YML_TYPE_CREDENTIALS, "hidden": True},
    ]
    result = mod.collect_type9_params({"configuration": cfg})
    assert result == {"creds": False, "apikey_creds": True}


def test_collect_type9_params_excludes_hidden() -> None:
    cfg = [
        {"name": "h1", "type": mod.YML_TYPE_CREDENTIALS, "hidden": True},
        {"name": "h2", "type": mod.YML_TYPE_CREDENTIALS, "hidden": "platform"},
        {"name": "h3", "type": mod.YML_TYPE_CREDENTIALS, "hidden": ["platform"]},
        {"name": "visible", "type": mod.YML_TYPE_CREDENTIALS},
    ]
    assert mod.collect_type9_params({"configuration": cfg}) == {"visible": False}


@pytest.mark.parametrize(
    "leaf_id,raw_ids,expected",
    [
        ("creds_password", ["creds_password"], True),  # exact
        ("creds_password", ["fetch-issues_int_creds_password"], True),  # prefixed
        ("creds_password", ["other"], False),  # absent
        ("name_password", ["xname_password"], False),  # partial-token guard
    ],
)
def test_raw_id_matches_leaf(leaf_id, raw_ids, expected) -> None:
    assert mod._raw_id_matches_leaf(leaf_id, raw_ids) is expected


def test_type9_default_requires_both_leaves() -> None:
    type9 = {"creds": False}
    # Both halves present → covered.
    assert mod._type9_leaf_covered(
        {"creds"}, ["creds_username", "creds_password"], set(), type9
    ) == set()
    # Only password half → NOT covered for a default credentials param.
    assert mod._type9_leaf_covered(
        {"creds"}, ["creds_password"], set(), type9
    ) == {"creds"}
    # Only username half → NOT covered.
    assert mod._type9_leaf_covered(
        {"creds"}, ["creds_username"], set(), type9
    ) == {"creds"}


def test_type9_hiddenusername_password_only() -> None:
    type9 = {"apikey_creds": True}
    # Bare name (the password-only field id) → covered.
    assert mod._type9_leaf_covered(
        {"apikey_creds"}, ["apikey_creds"], set(), type9
    ) == set()
    # <name>_password also covers it.
    assert mod._type9_leaf_covered(
        {"apikey_creds"}, ["apikey_creds_password"], set(), type9
    ) == set()
    # No leaf at all → still missing.
    assert mod._type9_leaf_covered(
        {"apikey_creds"}, ["unrelated"], set(), type9
    ) == {"apikey_creds"}


def test_type9_serializer_bridged_is_noop() -> None:
    """When the serializer already maps a connector field back to the bare
    name, the param is in connector_params and stays covered."""
    type9 = {"creds": False}
    assert mod._type9_leaf_covered(
        {"creds"}, [], {"creds"}, type9
    ) == set()


def test_type9_prefixed_leaves_covered() -> None:
    type9 = {"creds": False}
    raw = [
        "fetch-issues_int_creds_username",
        "fetch-issues_int_creds_password",
    ]
    assert mod._type9_leaf_covered({"creds"}, raw, set(), type9) == set()


def _type9_connector(tmp_path: Path, *, fields: list[dict]):
    handler = {
        "id": "xsoar-test",
        "capabilities": [{"id": "automation"}],
    }
    capabilities = {"capabilities": [{"id": "automation"}]}
    configurations = {
        "configurations": [
            {"id": "automation", "configurations": [{"fields": fields}]}
        ]
    }
    return _build_connector(
        tmp_path,
        handler=handler,
        capabilities=capabilities,
        configurations=configurations,
    )


def test_check_coverage_type9_both_leaves_pass(tmp_path: Path) -> None:
    _, handler_dir = _type9_connector(
        tmp_path, fields=[{"id": "creds_username"}, {"id": "creds_password"}]
    )
    yml = _write_integration_yml(
        tmp_path, [{"name": "creds", "type": mod.YML_TYPE_CREDENTIALS}]
    )
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is True
    assert missing == set()


def test_check_coverage_type9_password_only_default_fails(tmp_path: Path) -> None:
    """A default credentials param needs BOTH halves; password-only fails."""
    _, handler_dir = _type9_connector(tmp_path, fields=[{"id": "creds_password"}])
    yml = _write_integration_yml(
        tmp_path, [{"name": "creds", "type": mod.YML_TYPE_CREDENTIALS}]
    )
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is False
    assert missing == {"creds"}


def test_check_coverage_type9_hiddenusername_bare_pass(tmp_path: Path) -> None:
    _, handler_dir = _type9_connector(tmp_path, fields=[{"id": "apikey_creds"}])
    yml = _write_integration_yml(
        tmp_path,
        [{"name": "apikey_creds", "type": mod.YML_TYPE_CREDENTIALS, "hiddenusername": True}],
    )
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is True
    assert missing == set()


def test_check_coverage_type9_uncovered_fails(tmp_path: Path) -> None:
    """A credentials param whose leaves are absent is reported missing."""
    _, handler_dir = _type9_connector(tmp_path, fields=[{"id": "unrelated"}])
    yml = _write_integration_yml(
        tmp_path, [{"name": "creds", "type": mod.YML_TYPE_CREDENTIALS}]
    )
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is False
    assert missing == {"creds"}
