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
    _, handler_dir = _alert_connector(tmp_path, alert_field_id="incidentType")
    yml = _write_integration_yml(tmp_path, [{"name": "incidentType"}])
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is True
    assert missing == set()


def test_incident_type_covered_by_prefixed_alert_type(tmp_path: Path) -> None:
    _, handler_dir = _alert_connector(
        tmp_path, alert_field_id="fetch-issues_xsoar_incidentType"
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
    _, handler_dir = _alert_connector(tmp_path, alert_field_id="incidentFetchInterval")
    yml = _write_integration_yml(tmp_path, [{"name": "incidentFetchInterval"}])
    passed, missing = mod.check_coverage(handler_dir, yml)
    assert passed is True
    assert missing == set()


def test_incident_fetch_interval_covered_by_prefixed_field(tmp_path: Path) -> None:
    _, handler_dir = _alert_connector(
        tmp_path, alert_field_id="fetch-issues_xsoar_incidentFetchInterval"
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


# ===========================================================================
# Interpolation-published params (the new "what the handler should receive"
# source). A connection profile's `metadata.xsoar.interpolation_mapping` is a
# CSV of `FIELD_ID:dotted.dest` pairs. At runtime the platform places each
# credential under `params[dotted.dest]`, so the integration sees the dotted
# path. The TOP-LEVEL TOKEN of the dotted destination IS the integration-side
# param name (matches the YML `name:` of a type:9 credentials widget, or a
# plain `name:` for a simple param). These tokens MUST contribute to the
# expected-param set, and MUST NOT pass through serializer.field_mappings
# (interpolation already does the renaming).
#
# Reference: connectus/interpolated-param-schemas-and-fix.md:13-181.
# ===========================================================================
def _interp_profile(
    profile_id: str,
    *,
    interpolation_mapping: str | None = None,
    fields: list[dict] | None = None,
    extra_metadata: dict | None = None,
) -> dict:
    """Build a connection profile dict with optional interpolation_mapping.

    ``interpolation_mapping`` is the raw CSV string the platform stores under
    ``metadata.xsoar.interpolation_mapping``. ``fields`` populates a single
    ``configurations[].fields`` group. ``extra_metadata`` is merged INTO
    ``metadata`` (NOT into ``metadata.xsoar``), useful for negative-case
    fixtures that need to populate other metadata branches.
    """
    metadata: dict = {}
    if interpolation_mapping is not None:
        metadata["xsoar"] = {
            "interpolated": True,
            "interpolation_mapping": interpolation_mapping,
        }
    if extra_metadata:
        # Shallow merge — caller's extra keys live alongside xsoar.
        for key, value in extra_metadata.items():
            metadata[key] = value
    profile: dict = {"id": profile_id}
    if metadata:
        profile["metadata"] = metadata
    if fields is not None:
        profile["configurations"] = [{"fields": fields}]
    return profile


class TestCollectInterpolationPublished:
    """Cycle 1 RED: 10 unit tests for the not-yet-implemented helper
    ``collect_interpolation_published_params(connection_doc, auth_profile_ids)``.

    Contract:
      * Walks every ``profiles[]`` whose ``id`` is in ``auth_profile_ids``.
      * Reads ``profile.metadata.xsoar.interpolation_mapping`` (CSV string).
      * For each ``FIELD_ID:dotted.dest`` entry, yields the substring of
        ``dotted.dest`` before the first ``.`` (the top-level token that
        becomes a key in ``demisto.params()``).
      * Returns a deduped, order-stable list (or set — implementation TBD;
        tests assert on set form via ``set(...)``).
      * Missing metadata, malformed entries, and unreferenced profiles are
        handled gracefully without raising.
    """

    def test__single_entry__yields_top_token(self) -> None:
        connection = {
            "profiles": [
                _interp_profile(
                    "passthrough.x",
                    interpolation_mapping="api_key:credentials.password",
                )
            ]
        }
        result = mod.collect_interpolation_published_params(
            connection, {"passthrough.x"}
        )
        assert set(result) == {"credentials"}

    def test__multiple_entries__dedup_by_top_token(self) -> None:
        connection = {
            "profiles": [
                _interp_profile(
                    "passthrough.x",
                    interpolation_mapping=(
                        "u:credentials.identifier,p:credentials.password"
                    ),
                )
            ]
        }
        result = mod.collect_interpolation_published_params(
            connection, {"passthrough.x"}
        )
        assert set(result) == {"credentials"}

    def test__deep_path__only_top_token(self) -> None:
        connection = {
            "profiles": [
                _interp_profile(
                    "passthrough.x",
                    interpolation_mapping="k:creds.auth.identifier",
                )
            ]
        }
        result = mod.collect_interpolation_published_params(
            connection, {"passthrough.x"}
        )
        assert set(result) == {"creds"}

    def test__no_dot__entire_rhs_is_the_token(self) -> None:
        connection = {
            "profiles": [
                _interp_profile(
                    "passthrough.x", interpolation_mapping="api_key:apikey"
                )
            ]
        }
        result = mod.collect_interpolation_published_params(
            connection, {"passthrough.x"}
        )
        assert set(result) == {"apikey"}

    def test__profile_not_referenced_by_handler__skipped(self) -> None:
        connection = {
            "profiles": [
                _interp_profile(
                    "passthrough.referenced",
                    interpolation_mapping="api_key:credentials.password",
                ),
                _interp_profile(
                    "passthrough.unused",
                    interpolation_mapping="api_key:should_not_appear",
                ),
            ]
        }
        result = mod.collect_interpolation_published_params(
            connection, {"passthrough.referenced"}
        )
        assert set(result) == {"credentials"}

    def test__missing_metadata__returns_empty(self) -> None:
        # Profile is referenced but carries no metadata.xsoar.interpolation_mapping.
        connection = {
            "profiles": [
                {"id": "passthrough.x", "configurations": [{"fields": []}]}
            ]
        }
        result = mod.collect_interpolation_published_params(
            connection, {"passthrough.x"}
        )
        assert set(result) == set()

    def test__malformed_entry_missing_colon__skipped_without_error(self) -> None:
        # `bad_entry_no_colon` has no `:`; the good entry should still produce
        # its top token. The helper must NOT raise.
        connection = {
            "profiles": [
                _interp_profile(
                    "passthrough.x",
                    interpolation_mapping=(
                        "bad_entry_no_colon,api_key:credentials.password"
                    ),
                )
            ]
        }
        result = mod.collect_interpolation_published_params(
            connection, {"passthrough.x"}
        )
        assert set(result) == {"credentials"}

    def test__whitespace_around_entries__trimmed(self) -> None:
        connection = {
            "profiles": [
                _interp_profile(
                    "passthrough.x",
                    interpolation_mapping=(
                        "  u : credentials.identifier , p : credentials.password "
                    ),
                )
            ]
        }
        result = mod.collect_interpolation_published_params(
            connection, {"passthrough.x"}
        )
        assert set(result) == {"credentials"}

    def test__empty_string__returns_empty(self) -> None:
        connection = {
            "profiles": [
                _interp_profile("passthrough.x", interpolation_mapping="")
            ]
        }
        result = mod.collect_interpolation_published_params(
            connection, {"passthrough.x"}
        )
        assert set(result) == set()

    def test__multiple_profiles__union_of_top_tokens(self) -> None:
        connection = {
            "profiles": [
                _interp_profile(
                    "passthrough.a",
                    interpolation_mapping="u:credentials.identifier",
                ),
                _interp_profile(
                    "passthrough.b",
                    interpolation_mapping="api_key:apikey",
                ),
                _interp_profile(
                    "passthrough.c",  # NOT in auth_profile_ids → excluded.
                    interpolation_mapping="k:should_not_appear",
                ),
            ]
        }
        result = mod.collect_interpolation_published_params(
            connection, {"passthrough.a", "passthrough.b"}
        )
        assert set(result) == {"credentials", "apikey"}


# ===========================================================================
# HashiCorp Vault — golden / regression test.
#
# Pin the real ``Packs/HashiCorp-Vault/Integrations/HashiCorpVault/
# HashiCorpVault.yml`` non-hidden parameter list against a synthetic-but-
# representative connector fixture that exercises every coverage path the
# unified-connectors platform supports:
#
#   * Capability-config fields (plain config params via the ``automation``
#     capability).
#   * Auth-profile fields with ``metadata.event.publish: true`` (the
#     namespace + connect-section fields that ride the lifecycle event into
#     ``demisto.params()``).
#   * Interpolation-published params (``credentials.identifier`` /
#     ``credentials.password`` produced from a ``plain.*`` profile, so the
#     compound ``type:9 credentials`` widget is covered via the
#     ``interpolation_mapping`` top-token rule).
#   * ``type:9`` leaf coverage for the password-only ``credentials_token``
#     widget (``hiddenusername: true``): an ``api_key.*`` profile whose
#     password field uses the bare ``credentials_token`` id satisfies the
#     ``_type9_leaf_covered`` rule.
#
# The first test asserts FULL coverage with no missing params. The second
# test removes a single field from the fixture and asserts the framework
# correctly reports the gap (proves the test discriminates — a vacuous PASS
# is impossible).
#
# When real connector migration lands in ``unified-connectors-content/
# connectors/hashicorp-vault/``, this fixture can be replaced with a
# filesystem-based golden test (TestGoldenHashicorpVault) reading the real
# manifests, but the YML side of the assertion stays identical.
# ===========================================================================
HASHICORP_VAULT_YML = (
    Path(__file__).resolve().parents[1]
    / "Packs"
    / "HashiCorp-Vault"
    / "Integrations"
    / "HashiCorpVault"
    / "HashiCorpVault.yml"
)

# The set of non-hidden YML params the HashiCorp Vault integration declares
# today. Pinned here so a future YML edit (add/remove a non-hidden param)
# trips the test and forces an explicit decision.
HASHICORP_VAULT_EXPECTED_NON_HIDDEN_PARAMS = {
    "server",
    "use_approle",
    "credentials",        # type:9 compound, both halves visible
    "cache_token",
    "credentials_token",  # type:9 password-only (hiddenusername: true)
    "namespace",
    "unsecure",
    "proxy",
    "isFetchCredentials",
    "engines",
    "concat_username_to_cred_name",
}


def _make_field(
    field_id: str,
    *,
    auth_parameter: str | None = None,
    event_publish: bool = False,
) -> dict:
    """Build a connection profile field, optionally with auth/event metadata."""
    field: dict = {"id": field_id, "field_type": "input"}
    metadata: dict = {}
    if auth_parameter is not None:
        metadata["auth"] = {"parameter": auth_parameter}
    if event_publish:
        metadata["event"] = {"publish": True}
    if metadata:
        field["metadata"] = metadata
    return field


def _build_hashicorp_vault_connector(
    tmp_path: Path,
    *,
    omit_config_field_id: str | None = None,
    omit_profile_field_id: str | None = None,
) -> tuple[Path, Path]:
    """Build a synthetic HashiCorp Vault connector that covers every
    non-hidden integration YML param.

    Two optional knobs let the discrimination test exercise gap reporting:

    * ``omit_config_field_id`` — drop one capability-config field id from the
      connector before writing it. Use to prove a gap in
      capability/general-config space surfaces as a missing param.
    * ``omit_profile_field_id`` — drop one connection-profile field id.
      Same purpose, profile-side.
    """
    handler = {
        "id": "xsoar-hashicorp-vault",
        "capabilities": [
            {
                "id": "automation",
                "auth_options": [
                    {"id": "plain.hashicorp_vault"},
                    {"id": "api_key.hashicorp_vault_token"},
                ],
            },
            {
                "id": "collect-credentials",
                "auth_options": [
                    {"id": "plain.hashicorp_vault"},
                    {"id": "api_key.hashicorp_vault_token"},
                ],
            },
        ],
    }
    capabilities = {
        "capabilities": [
            {"id": "automation"},
            {"id": "collect-credentials"},
        ]
    }

    # Capability-config fields — plain config params declared on the
    # respective capabilities. Each id matches its YML param name 1:1, so
    # no serializer mapping is required.
    automation_fields = [
        {"id": "server"},
        {"id": "use_approle"},
        {"id": "cache_token"},
        {"id": "namespace"},
        {"id": "unsecure"},
        {"id": "proxy"},
    ]
    collect_fields = [
        {"id": "isFetchCredentials"},
        {"id": "engines"},
        {"id": "concat_username_to_cred_name"},
    ]
    if omit_config_field_id is not None:
        automation_fields = [
            f for f in automation_fields if f["id"] != omit_config_field_id
        ]
        collect_fields = [
            f for f in collect_fields if f["id"] != omit_config_field_id
        ]
    configurations = {
        "configurations": [
            {
                "id": "automation",
                "view_group": "xsoar-hashicorp-vault",
                "configurations": [{"fields": automation_fields}],
            },
            {
                "id": "collect-credentials",
                "view_group": "xsoar-hashicorp-vault",
                "configurations": [{"fields": collect_fields}],
            },
        ]
    }

    # Plain profile — username/password interpolated back into the integration
    # YML's compound ``credentials`` (type:9) widget. The
    # ``interpolation_mapping`` RHS top-token ``credentials`` covers it
    # without going through ``serializer.field_mappings``.
    plain_profile = _interp_profile(
        "plain.hashicorp_vault",
        interpolation_mapping=(
            "username:credentials.identifier,password:credentials.password"
        ),
        fields=[
            _make_field("username", auth_parameter="username"),
            _make_field("password", auth_parameter="password"),
        ],
    )

    # API-key profile — bare ``credentials_token`` field covers the
    # password-only ``type:9`` widget via the ``_type9_leaf_covered`` rule
    # (``hiddenusername: true`` → emit bare ``<name>`` or ``<name>_password``).
    api_key_fields = [_make_field("credentials_token", auth_parameter="token")]
    if omit_profile_field_id is not None:
        api_key_fields = [
            f for f in api_key_fields if f["id"] != omit_profile_field_id
        ]
    api_key_profile = {
        "id": "api_key.hashicorp_vault_token",
        "configurations": [{"fields": api_key_fields}],
    }

    connection = {"profiles": [plain_profile, api_key_profile]}
    return _build_connector(
        tmp_path,
        handler=handler,
        capabilities=capabilities,
        configurations=configurations,
        connection=connection,
    )


@pytest.mark.skipif(
    not HASHICORP_VAULT_YML.is_file(),
    reason="HashiCorp Vault integration YML not present",
)
class TestHashiCorpVault:
    """Golden coverage test for the HashiCorp Vault integration.

    Fails loudly when the connector fixture stops covering every non-hidden
    YML param — the exact gate the unified-connectors migration must pass.
    """

    def test__yml_non_hidden_param_set_matches_pinned_snapshot(self) -> None:
        """Sanity-check the YML hasn't drifted from the pinned snapshot.

        If this fails, the YML added or removed a non-hidden param; update
        ``HASHICORP_VAULT_EXPECTED_NON_HIDDEN_PARAMS`` AND extend / shrink
        the connector fixture in the same edit.
        """
        yml = mod.load_yaml(HASHICORP_VAULT_YML)
        assert (
            mod.collect_yml_params(yml)
            == HASHICORP_VAULT_EXPECTED_NON_HIDDEN_PARAMS
        )

    def test__full_connector_fixture_covers_every_non_hidden_yml_param(
        self, tmp_path: Path
    ) -> None:
        """STRICT: every non-hidden YML param must be covered. No exceptions.

        This is the gate. If the framework fails to recognise an interpolated
        ``credentials`` compound, a published config field, or a ``type:9``
        leaf, ``missing`` is non-empty and the test fails with the exact list
        of uncovered params.
        """
        _, handler_dir = _build_hashicorp_vault_connector(tmp_path)
        passed, missing = mod.check_coverage(handler_dir, HASHICORP_VAULT_YML)
        assert missing == set(), (
            f"HashiCorp Vault connector fixture failed to cover: {sorted(missing)}"
        )
        assert passed is True

    def test__omitting_a_config_field_surfaces_as_missing(
        self, tmp_path: Path
    ) -> None:
        """Discrimination test: prove a vacuous PASS is impossible.

        Drop ``namespace`` from the connector fixture and assert that the
        framework reports it as missing. If this test passes (i.e. ``missing``
        contains ``namespace``), the strict coverage test above is meaningful.
        """
        _, handler_dir = _build_hashicorp_vault_connector(
            tmp_path, omit_config_field_id="namespace"
        )
        passed, missing = mod.check_coverage(handler_dir, HASHICORP_VAULT_YML)
        assert passed is False
        assert "namespace" in missing

    def test__omitting_the_token_field_surfaces_credentials_token_as_missing(
        self, tmp_path: Path
    ) -> None:
        """Discrimination test for the ``type:9`` leaf rule.

        Drop the bare ``credentials_token`` field from the api_key profile.
        With no surviving leaf, the password-only widget can no longer be
        covered, and ``credentials_token`` must show up in ``missing``.
        """
        _, handler_dir = _build_hashicorp_vault_connector(
            tmp_path, omit_profile_field_id="credentials_token"
        )
        passed, missing = mod.check_coverage(handler_dir, HASHICORP_VAULT_YML)
        assert passed is False
        assert "credentials_token" in missing
