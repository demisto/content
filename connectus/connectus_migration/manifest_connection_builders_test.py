"""Unit tests for ``connection_builder`` (connection.yaml builders).

Covers the design in ``plans/connection-auth-types-design.md``:
Part A (auth_types -> profiles), Part B (proxy/insecure), Part C (engine
3-field + Appendix G/H carve-outs + triggers), Part D (view_groups +
general_configurations for the rest of other_connection), and the top-level
``build_connection_yaml`` assembly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import manifest_generator as cb


# ---------------------------------------------------------------------------
# Part A — profile id + field id + role mapping
# ---------------------------------------------------------------------------
def test_derive_profile_id_basic():
    entry = {"type": "Passthrough", "name": "passthrough"}
    assert cb.derive_profile_id(entry, "Microsoft Graph") == "passthrough.microsoft_graph"


def test_derive_profile_id_api_key_and_plain():
    assert cb.derive_profile_id({"type": "APIKey", "name": "k"}, "Okta") == "api_key.okta"
    assert cb.derive_profile_id({"type": "Plain", "name": "c"}, "EWS v2") == "plain.ews_v2"


def test_derive_profile_id_unknown_type_raises():
    with pytest.raises(ValueError):
        cb.derive_profile_id({"type": "OAuth2ClientCreds", "name": "x"}, "Foo")


def test_derive_profile_id_short_purpose_padded():
    pid = cb.derive_profile_id({"type": "APIKey", "name": "k"}, "AB")
    # purpose must be >= 3 word chars after the dot
    assert pid.startswith("api_key.")
    assert len(pid.split(".", 1)[1]) >= 3


def test_derive_profile_id_same_type_collision_guard():
    seen: set[str] = set()
    a = cb.derive_profile_id({"type": "Plain", "name": "first"}, "Foo", seen)
    b = cb.derive_profile_id({"type": "Plain", "name": "second"}, "Foo", seen)
    assert a == "plain.foo"
    assert b == "plain.foo_second"
    assert a != b


def test_connection_field_id_from_map_key_type9_both_leaves():
    keys = {"creds_certificate.identifier", "creds_certificate.password"}
    assert (
        cb._connection_field_id_from_map_key("creds_certificate.identifier", keys)
        == "creds_certificate_username"
    )
    assert (
        cb._connection_field_id_from_map_key("creds_certificate.password", keys)
        == "creds_certificate_password"
    )


def test_connection_field_id_from_map_key_hiddenusername_password_bare():
    keys = {"creds_enc_key.password"}  # no .identifier sibling
    assert (
        cb._connection_field_id_from_map_key("creds_enc_key.password", keys)
        == "creds_enc_key"
    )


def test_connection_field_id_from_map_key_flat():
    assert cb._connection_field_id_from_map_key("api_key", {"api_key"}) == "api_key"


def test_auth_parameter_for_role_apikey_remap():
    assert cb._auth_parameter_for_role("api_key", "key") == "api_key"


def test_auth_parameter_for_role_plain_passthrough_verbatim():
    assert cb._auth_parameter_for_role("plain", "username") == "username"
    assert cb._auth_parameter_for_role("plain", "password") == "password"
    assert cb._auth_parameter_for_role("passthrough", "client_secret") == "client_secret"


def test_build_connection_profile_apikey_shape():
    entry = {"type": "APIKey", "name": "api_key", "xsoar_param_map": {"api_key": "key"}}
    prof = cb.build_connection_profile(entry, "Okta", connector_title="Okta")
    assert prof["id"] == "api_key.okta"
    assert prof["type"] == "api_key"
    assert prof["title"] == "API Key"
    field = prof["configurations"][0]["fields"][0]
    assert field["id"] == "api_key"
    assert field["metadata"]["auth"]["parameter"] == "api_key"
    assert field["options"]["mask"] is True


def test_build_connection_profile_plain_username_unmasked():
    entry = {
        "type": "Plain",
        "name": "credentials",
        "xsoar_param_map": {
            "credentials.identifier": "username",
            "credentials.password": "password",
        },
    }
    prof = cb.build_connection_profile(entry, "Foo", connector_title="Foo")
    fields = {f["metadata"]["auth"]["parameter"]: f for f in prof["configurations"][0]["fields"]}
    assert fields["username"]["options"]["mask"] is False
    assert fields["password"]["options"]["mask"] is True
    assert fields["username"]["id"] == "credentials_username"
    assert fields["password"]["id"] == "credentials_password"


def test_build_connection_profile_passthrough_title_and_freeform_roles():
    entry = {
        "type": "Passthrough",
        "name": "bag",
        "interpolated": True,
        "xsoar_param_map": {
            "creds_auth_id.password": "creds_auth_id",
            "managed_identities_client_id.password": "managed_identities_client_id",
        },
    }
    prof = cb.build_connection_profile(entry, "Microsoft Graph", connector_title="Microsoft Graph")
    assert prof["type"] == "passthrough"
    assert prof["title"] == "Microsoft Graph Credentials"
    params = {f["metadata"]["auth"]["parameter"] for f in prof["configurations"][0]["fields"]}
    assert params == {"creds_auth_id", "managed_identities_client_id"}


def test_build_connection_profile_title_enrichment_from_yml():
    entry = {"type": "APIKey", "name": "k", "xsoar_param_map": {"credentials.password": "key"}}
    yml = {"credentials": {"displaypassword": "API Token", "display": "Creds"}}
    prof = cb.build_connection_profile(entry, "Foo", yml_params_by_name=yml)
    field = prof["configurations"][0]["fields"][0]
    # hiddenusername case -> bare id "credentials"; title from displaypassword
    assert field["id"] == "credentials"
    assert field["title"] == "API Token"


# ---------------------------------------------------------------------------
# Part B — proxy / insecure detection + shapes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "pid,expected",
    [
        ("proxy", "proxy"),
        ("use_proxy", "proxy"),
        ("useProxy", "proxy"),
        ("insecure", "insecure"),
        ("unsecure", "insecure"),
        ("verify_certificate", "insecure"),
        ("verify", "insecure"),
        ("secure", "insecure"),
        ("trust_any_certificate", None),  # `trust` removed (B-D5)
        ("url", None),
        ("host", None),
        ("port", None),
    ],
)
def test_classify_connection_param(pid, expected):
    assert cb.classify_connection_param(pid) == expected


def test_build_proxy_field_shape():
    f = cb.build_proxy_field("proxy")
    assert f["id"] == "proxy"
    assert f["field_type"] == "switch"
    assert f["options"]["default_value"] is False
    assert f["options"]["mask"] is False
    assert f["metadata"]["event"]["publish"] is True
    assert f["metadata"]["xsoar"]["config_type"] == "backend"


def test_build_insecure_field_default_false_always():
    # even if yml shipped a true default, we force false (B-D6)
    yml = {"insecure": {"display": "Trust any cert", "defaultvalue": "true"}}
    f = cb.build_insecure_field("insecure", yml)
    assert f["options"]["default_value"] is False
    assert f["title"] == "Trust any cert"


# ---------------------------------------------------------------------------
# Part C — engine carve-outs + field shapes + triggers
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "integration_id,expected",
    [
        ("Microsoft Graph", "full"),
        ("EDL", "excluded"),
        ("edl", "excluded"),
        ("AWS", "excluded"),
        ("slack", "single"),
        ("SLACK", "single"),
        ("duo", "single"),
    ],
)
def test_engine_exclusion_class(integration_id, expected):
    assert cb.engine_exclusion_class(integration_id) == expected


def test_build_engine_mode_field_full_vs_single():
    full = cb.build_engine_mode_field("engine_mode", single_engine=False)
    single = cb.build_engine_mode_field("engine_mode", single_engine=True)
    full_keys = [v["key"] for v in full["options"]["values"]]
    single_keys = [v["key"] for v in single["options"]["values"]]
    assert full_keys == ["no_engine", "engine", "engine_group"]
    assert single_keys == ["no_engine", "engine"]
    assert full["options"]["default_value"] == "no_engine"
    # uses {key,label} (D-D4)
    assert "label" in full["options"]["values"][0]


def test_build_engine_field_dynamic_values():
    f = cb.build_engine_field("engine", "EWSO365")
    dv = f["metadata"]["dynamic_values"]
    assert dv["provider"] == "xsoar"
    assert dv["params"]["integrationID"] == "EWSO365"
    assert dv["params"]["dynamicField"] == "engine"
    assert f["metadata"]["event"]["publish"] is True


def test_build_engine_group_field_dynamic_field():
    f = cb.build_engine_group_field("engine_group", "EWSO365")
    assert f["metadata"]["dynamic_values"]["params"]["dynamicField"] == "engine-group"


def test_build_engine_triggers_both():
    trig = cb.build_engine_triggers(
        mode_id="engine_mode", engine_id="engine", engine_group_id="engine_group"
    )
    assert len(trig) == 2
    assert trig[0]["conditions"]["id"] == "engine_mode"
    assert trig[0]["conditions"]["operator"] == "neq"
    assert trig[0]["effects"][0]["id"] == "engine"
    assert trig[0]["effects"][0]["action"]["hidden"] is True
    assert trig[1]["effects"][0]["id"] == "engine_group"


def test_build_engine_triggers_single_omits_group():
    trig = cb.build_engine_triggers(
        mode_id="engine_mode", engine_id="engine", engine_group_id=None
    )
    assert len(trig) == 1
    assert trig[0]["effects"][0]["id"] == "engine"


# ---------------------------------------------------------------------------
# Part C/B — attach_per_profile_connection_fields
# ---------------------------------------------------------------------------
def _one_profile() -> list[dict]:
    return [{"id": "passthrough.foo", "type": "passthrough", "configurations": [{"fields": []}]}]


def test_attach_full_emits_proxy_insecure_engine():
    profiles = _one_profile()
    trig = cb.attach_per_profile_connection_fields(
        profiles, "Foo", ["host", "proxy", "insecure"]
    )
    ids = [f["id"] for f in profiles[0]["configurations"][0]["fields"]]
    assert ids == ["proxy", "insecure", "engine_mode", "engine", "engine_group"]
    assert len(trig) == 2


def test_attach_appendix_g_skips_proxy_and_engine_keeps_insecure():
    profiles = [{"id": "passthrough.edl", "configurations": [{"fields": []}]}]
    trig = cb.attach_per_profile_connection_fields(
        profiles, "EDL", ["proxy", "insecure"]
    )
    ids = [f["id"] for f in profiles[0]["configurations"][0]["fields"]]
    assert ids == ["insecure"]  # no proxy, no engine
    assert trig == []


def test_attach_appendix_h_single_engine_no_group():
    profiles = [{"id": "plain.slack", "configurations": [{"fields": []}]}]
    trig = cb.attach_per_profile_connection_fields(
        profiles, "slack", ["proxy", "insecure"]
    )
    ids = [f["id"] for f in profiles[0]["configurations"][0]["fields"]]
    assert "engine_mode" in ids
    assert "engine" in ids
    assert "engine_group" not in ids
    # single-engine: engine_mode 2-option
    mode = next(f for f in profiles[0]["configurations"][0]["fields"] if f["id"] == "engine_mode")
    assert [v["key"] for v in mode["options"]["values"]] == ["no_engine", "engine"]
    assert len(trig) == 1


def test_attach_multi_profile_dedup_and_serializer_bridge():
    profiles = [
        {"id": "plain.foo", "configurations": [{"fields": []}]},
        {"id": "api_key.foo", "configurations": [{"fields": []}]},
    ]
    bridges: list[tuple[str, str, str]] = []

    def bridge(handler_dir: Path, new_id: str, original_id: str) -> None:
        bridges.append((str(handler_dir), new_id, original_id))

    cb.attach_per_profile_connection_fields(
        profiles,
        "Foo",
        ["proxy", "insecure"],
        handler_dir=Path("/tmp/h"),
        serializer_bridge=bridge,
    )
    first_ids = [f["id"] for f in profiles[0]["configurations"][0]["fields"]]
    second_ids = [f["id"] for f in profiles[1]["configurations"][0]["fields"]]
    # first profile keeps bare ids
    assert "proxy" in first_ids and "engine" in first_ids
    # second profile gets prefixed ids
    assert "foo_proxy" in second_ids and "foo_engine" in second_ids
    # serializer bridges map prefixed -> XSOAR name (engine_group -> engineGroup)
    bridged = {(b[1], b[2]) for b in bridges}
    assert ("foo_proxy", "proxy") in bridged
    assert ("foo_engine", "engine") in bridged
    assert ("foo_engine_group", "engineGroup") in bridged


# ---------------------------------------------------------------------------
# Part D — view_groups + general_configurations
# ---------------------------------------------------------------------------
def test_build_view_groups_registry():
    reg = cb.build_view_groups_registry([("EWS O365", "EWS O365")])
    assert reg == [
        {
            "id": "ews-o365",
            "label": "EWS O365",
            "help_text": "Connection settings for the EWS O365 integration.",
        }
    ]


def test_build_general_configurations_rest_only():
    yml = {
        "host": {"name": "host", "type": 0, "display": "Host URL"},
        "proxy": {"name": "proxy", "type": 8},
    }

    def mapper(p: dict) -> list[dict]:
        return [{"id": p["name"], "field_type": "input", "options": {}}]

    block = cb.build_connection_general_configurations(
        "EWSO365", ["host", "proxy"], yml, mapper
    )
    assert block["view_group"] == "ewso365"
    # proxy is per-profile, excluded here; only host remains, id-prefixed
    ids = [f["id"] for f in block["fields"]]
    assert ids == ["ewso365_host"]
    assert block["fields"][0]["options"]["mask"] is False


def test_build_general_configurations_none_when_empty():
    def mapper(p: dict) -> list[dict]:
        return [{"id": p["name"], "field_type": "input", "options": {}}]

    block = cb.build_connection_general_configurations(
        "Foo", ["proxy", "insecure"], {}, mapper
    )
    assert block is None


# ---------------------------------------------------------------------------
# Top-level build_connection_yaml
# ---------------------------------------------------------------------------
def test_build_connection_yaml_empty_auth_raises():
    with pytest.raises(ValueError):
        cb.build_connection_yaml({"auth_types": [], "other_connection": []}, "Foo")


def test_build_connection_yaml_microsoft_graph_end_to_end():
    auth = {
        "auth_types": [
            {
                "type": "Passthrough",
                "name": "passthrough",
                "interpolated": True,
                "xsoar_param_map": {
                    "auth_code.password": "auth_code",
                    "creds_certificate.identifier": "creds_certificate_identifier",
                    "creds_certificate.password": "creds_certificate",
                    "creds_enc_key.password": "creds_enc_key",
                },
            }
        ],
        "other_connection": ["host", "insecure", "proxy"],
    }

    def mapper(p: dict) -> list[dict]:
        return [{"id": p["name"], "field_type": "input", "options": {}}]

    conn, triggers = cb.build_connection_yaml(
        auth,
        "Microsoft Graph",
        connector_title="Microsoft Graph",
        yml_params_by_name={"host": {"name": "host", "type": 0, "display": "Host URL"}},
        field_mapper=mapper,
    )
    assert conn["profiles"][0]["id"] == "passthrough.microsoft_graph"
    # host went to general_configurations (the rest of other_connection)
    gc = conn["general_configurations"]["configurations"][0]
    assert gc["view_group"] == "microsoft-graph"
    assert [f["id"] for f in gc["fields"]] == ["microsoftgraph_host"]
    # proxy/insecure/engine are per-profile
    prof_ids = [f["id"] for f in conn["profiles"][0]["configurations"][0]["fields"]]
    assert "proxy" in prof_ids and "insecure" in prof_ids and "engine_mode" in prof_ids
    assert len(triggers) == 2
