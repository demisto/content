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
    # Profile title now derives from the auth-type object's ``name`` (Issue #4).
    assert prof["title"] == entry["name"]
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
    # Profile title now derives from the auth-type object's ``name`` (Issue #4).
    assert prof["title"] == "bag"
    params = {f["metadata"]["auth"]["parameter"] for f in prof["configurations"][0]["fields"]}
    assert params == {"creds_auth_id", "managed_identities_client_id"}


def test_build_connection_profile_title_enrichment_from_yml():
    entry = {"type": "APIKey", "name": "k", "xsoar_param_map": {"credentials.password": "key"}}
    # ``credentials`` must be an explicit type-9 (Credentials) widget for the
    # dotted ``.password`` leaf to be honored as a hiddenusername password leaf
    # (title from ``displaypassword``). Only type 9 may nest; a non-type-9 (or
    # untyped) dotted leaf is now FLATTENED + warned, in which case the title
    # would come from the param's own ``display`` instead. (Updated for the
    # type-9-only-nesting fix.)
    yml = {
        "credentials": {
            "type": 9,
            "displaypassword": "API Token",
            "display": "Creds",
        }
    }
    prof = cb.build_connection_profile(entry, "Foo", yml_params_by_name=yml)
    field = prof["configurations"][0]["fields"][0]
    # hiddenusername case -> bare id "credentials"; title from displaypassword
    assert field["id"] == "credentials"
    assert field["title"] == "API Token"


# ---------------------------------------------------------------------------
# Part A — type-9-only nesting + flat-secret masking (FLATTEN + WARN bug fix)
# Only XSOAR type 9 (Credentials) may ever nest into _username/_password.
# Every other param type must stay FLAT; a flat credential masks robustly even
# when the originating YML param type can't be resolved.
# ---------------------------------------------------------------------------
def test_build_connection_profile_apikey_flat_secret_masks_without_yml():
    # Regression guard for the masking bug: a flat secret keyed in an auth
    # profile's xsoar_param_map masks True even when yml_params_by_name is not
    # supplied (origin type unresolvable). Mirrors apikey_shape but isolates the
    # masking contract.
    entry = {"type": "APIKey", "name": "api_key", "xsoar_param_map": {"api_key": "key"}}
    prof = cb.build_connection_profile(entry, "Okta", connector_title="Okta")
    field = prof["configurations"][0]["fields"][0]
    assert field["id"] == "api_key"  # bare flat id, never split
    assert field["options"]["mask"] is True


def test_build_connection_profile_flat_type14_single_masked_field():
    # A flat type-14 (cert/encrypted) param keyed directly in xsoar_param_map
    # stays FLAT: one field with a bare id (no _username/_password split), masked
    # True, and a flat interpolation entry (no dot).
    entry = {
        "type": "APIKey",
        "name": "cert",
        "xsoar_param_map": {"client_cert": "key"},
    }
    yml = {"client_cert": {"name": "client_cert", "type": 14, "display": "Client Cert"}}
    prof = cb.build_connection_profile(
        entry, "Foo", connector_title="Foo", yml_params_by_name=yml
    )
    fields = prof["configurations"][0]["fields"]
    assert len(fields) == 1
    field = fields[0]
    assert field["id"] == "client_cert"  # bare, NOT client_cert_username/_password
    assert field["options"]["mask"] is True
    # Flat interpolation entry — no dot in the xsoar_path.
    assert (
        prof["metadata"]["xsoar"]["interpolation_mapping"] == "api_key:client_cert"
    )


def test_build_connection_profile_dotted_non_type9_flattens_and_warns(caplog):
    # A dotted .identifier/.password pair whose originating YML param is NOT
    # type 9 (here type 14) must be FLATTENED back to a single flat field +
    # flat interpolation entry, and emit a warning naming the param + its type.
    import logging

    entry = {
        "type": "APIKey",
        "name": "cert",
        # Buggy upstream shape: a non-type-9 param dotted as if it were creds.
        "xsoar_param_map": {
            "client_cert.identifier": "username",
            "client_cert.password": "key",
        },
    }
    yml = {"client_cert": {"name": "client_cert", "type": 14, "display": "Client Cert"}}
    with caplog.at_level(logging.WARNING):
        prof = cb.build_connection_profile(
            entry, "Foo", connector_title="Foo", yml_params_by_name=yml
        )
    fields = prof["configurations"][0]["fields"]
    # Flattened to a SINGLE flat field with the bare param id (no _username /
    # _password split).
    assert [f["id"] for f in fields] == ["client_cert"]
    assert fields[0]["options"]["mask"] is True
    # Interpolation collapses to a single FLAT entry (bare param name on both
    # sides — no dotted leaf path).
    assert prof["metadata"]["xsoar"]["interpolation_mapping"] == "api_key:client_cert"
    # A warning was emitted naming the param, its type, and the flatten action.
    warning_text = " ".join(r.getMessage() for r in caplog.records)
    assert "client_cert" in warning_text
    assert "14" in warning_text
    assert "flatten" in warning_text.lower()


def test_build_connection_profile_dotted_type9_still_nests():
    # Regression guard: a genuine type-9 Credentials param keyed with dotted
    # leaves STILL nests into _username/_password fields + dotted interpolation
    # entries. (The flatten-on-non-type-9 fix must not touch type 9.)
    entry = {
        "type": "Plain",
        "name": "creds",
        "xsoar_param_map": {
            "creds.identifier": "username",
            "creds.password": "password",
        },
    }
    yml = {"creds": {"name": "creds", "type": 9, "display": "Creds"}}
    prof = cb.build_connection_profile(
        entry, "Foo", connector_title="Foo", yml_params_by_name=yml
    )
    fields = {f["id"]: f for f in prof["configurations"][0]["fields"]}
    assert set(fields) == {"creds_username", "creds_password"}
    assert fields["creds_username"]["options"]["mask"] is False
    assert fields["creds_password"]["options"]["mask"] is True
    # Dotted interpolation entries are preserved for the credentials leaves.
    assert prof["metadata"]["xsoar"]["interpolation_mapping"] == (
        "username:creds.identifier,password:creds.password"
    )


# ---------------------------------------------------------------------------
# Part A (vault_mappings) — passthrough profiles with type-9 (dotted) creds
# emit a profile-level ``vault_mappings`` array. Non-passthrough / non-type-9
# profiles must NOT emit the key.
# ---------------------------------------------------------------------------
def test_build_connection_profile_passthrough_vault_mappings_user_password():
    # A type-9 Credentials param with both an .identifier and a .password leaf
    # collapses into ONE vault_mappings entry mapping user->identifier-role and
    # password->password-role.
    entry = {
        "type": "Passthrough",
        "name": "creds",
        "xsoar_param_map": {
            "credentials.identifier": "username",
            "credentials.password": "password",
        },
    }
    prof = cb.build_connection_profile(entry, "Foo", connector_title="Foo")
    assert prof["vault_mappings"] == [
        {"id": "credentials", "map": {"user": "username", "password": "password"}}
    ]


def test_build_connection_profile_passthrough_vault_mappings_password_only():
    # A hiddenusername-style type-9 param (only a .password leaf) yields a
    # single entry with just ``password``.
    entry = {
        "type": "Passthrough",
        "name": "extra",
        "xsoar_param_map": {
            "additional_password.password": "additional_password",
        },
    }
    prof = cb.build_connection_profile(entry, "Foo", connector_title="Foo")
    assert prof["vault_mappings"] == [
        {"id": "additional_password", "map": {"password": "additional_password"}}
    ]


def test_build_connection_profile_passthrough_vault_mappings_insertion_order():
    # vault_mappings entries follow the FIRST-APPEARANCE order of each param in
    # the raw xsoar_param_map (insertion order), NOT sorted order. Here the raw
    # order puts ``credentials`` first then ``additional_password``.
    entry = {
        "type": "Passthrough",
        "name": "ssh",
        "xsoar_param_map": {
            "credentials.identifier": "username",
            "credentials.password": "password",
            "additional_password.password": "additional_password",
        },
    }
    prof = cb.build_connection_profile(entry, "Foo", connector_title="Foo")
    assert prof["vault_mappings"] == [
        {"id": "credentials", "map": {"user": "username", "password": "password"}},
        {"id": "additional_password", "map": {"password": "additional_password"}},
    ]


def test_build_connection_profile_plain_omits_vault_mappings():
    # The SAME type-9 map on a PLAIN profile must NOT emit vault_mappings.
    entry = {
        "type": "Plain",
        "name": "credentials",
        "xsoar_param_map": {
            "credentials.identifier": "username",
            "credentials.password": "password",
        },
    }
    prof = cb.build_connection_profile(entry, "Foo", connector_title="Foo")
    assert "vault_mappings" not in prof


def test_build_connection_profile_api_key_omits_vault_mappings():
    # api_key profiles (flat secret, no dotted type-9 cred) never emit the key.
    entry = {
        "type": "APIKey",
        "name": "api_key",
        "xsoar_param_map": {"api_key": "key"},
    }
    prof = cb.build_connection_profile(entry, "Okta", connector_title="Okta")
    assert "vault_mappings" not in prof


def test_build_connection_profile_passthrough_flat_only_omits_vault_mappings():
    # A passthrough profile with ONLY flat (non-dotted) keys has no type-9 creds
    # and must omit vault_mappings entirely (not emit an empty list).
    entry = {
        "type": "Passthrough",
        "name": "bag",
        "xsoar_param_map": {
            "creds_auth_id": "creds_auth_id",
            "managed_identities_client_id": "managed_identities_client_id",
        },
    }
    prof = cb.build_connection_profile(entry, "Foo", connector_title="Foo")
    assert "vault_mappings" not in prof


def test_build_connection_profile_vault_mappings_placement_after_description():
    # vault_mappings must sit AFTER description and BEFORE metadata in key order.
    entry = {
        "type": "Passthrough",
        "name": "creds",
        "xsoar_param_map": {
            "credentials.identifier": "username",
            "credentials.password": "password",
        },
    }
    prof = cb.build_connection_profile(entry, "Foo", connector_title="Foo")
    keys = list(prof.keys())
    assert keys.index("description") < keys.index("vault_mappings")
    assert keys.index("vault_mappings") < keys.index("metadata")


# ---------------------------------------------------------------------------
# Part A (interpolation) — build_interpolation_mapping pure helper
# ---------------------------------------------------------------------------
def _parse_param_map_like_runtime(param_map: str) -> list[tuple[str, str]]:
    """Re-implement CommonServerPython._parse_param_map grammar (split on ',',
    then first ':') so tests can round-trip the emitted string back to
    (role, xsoar_path) pairs without importing the runtime module."""
    pairs: list[tuple[str, str]] = []
    for raw in param_map.split(","):
        entry = raw.strip()
        if not entry or ":" not in entry:
            continue
        left, right = entry.split(":", 1)
        left, right = left.strip(), right.strip()
        if not left or not right:
            continue
        pairs.append((left, right))
    return pairs


def test_build_interpolation_mapping_apikey_flat_remaps_role_on_left():
    # APIKey role "key" must remap to auth_parameter "api_key" on the LEFT.
    assert (
        cb.build_interpolation_mapping("api_key", {"api_key": "key"})
        == "api_key:api_key"
    )


def test_build_interpolation_mapping_apikey_dotted_leaf():
    assert (
        cb.build_interpolation_mapping("api_key", {"credentials.password": "key"})
        == "api_key:credentials.password"
    )


def test_build_interpolation_mapping_plain_both_leaves_sorted():
    # Sorted by xsoar_path: credentials.identifier < credentials.password.
    assert cb.build_interpolation_mapping(
        "plain",
        {
            "credentials.identifier": "username",
            "credentials.password": "password",
        },
    ) == "username:credentials.identifier,password:credentials.password"


def test_build_interpolation_mapping_plain_two_flat_params_sorted_by_key():
    # Sorted by xsoar_path: server_password < server_user.
    assert cb.build_interpolation_mapping(
        "plain",
        {"server_user": "username", "server_password": "password"},
    ) == "password:server_password,username:server_user"


def test_build_interpolation_mapping_passthrough_multi_secret_verbatim_roles():
    assert cb.build_interpolation_mapping(
        "passthrough",
        {
            "credentials_auth_id.password": "client_id",
            "credentials_enc_key.password": "client_secret",
        },
    ) == (
        "client_id:credentials_auth_id.password,"
        "client_secret:credentials_enc_key.password"
    )


def test_build_interpolation_mapping_passthrough_secrets_bag():
    # Sorted by xsoar_path: credentials.password < hunting_credentials.password.
    assert cb.build_interpolation_mapping(
        "passthrough",
        {
            "credentials.password": "primary_api_key",
            "hunting_credentials.password": "hunting_api_key",
        },
    ) == (
        "primary_api_key:credentials.password,"
        "hunting_api_key:hunting_credentials.password"
    )


def test_build_interpolation_mapping_round_trips_through_runtime_grammar():
    # Cross-check: feed the emitted string through the same grammar the runtime
    # _parse_param_map uses and assert it reconstructs role -> xsoar_path.
    xsoar_param_map = {
        "credentials_auth_id.password": "client_id",
        "credentials_enc_key.password": "client_secret",
    }
    emitted = cb.build_interpolation_mapping("passthrough", xsoar_param_map)
    parsed = _parse_param_map_like_runtime(emitted)
    # role -> xsoar_path reconstruction equals the inverted input map.
    reconstructed = {role: path for role, path in parsed}
    assert reconstructed == {
        "client_id": "credentials_auth_id.password",
        "client_secret": "credentials_enc_key.password",
    }
    # And the LEFT-side roles are exactly the post-remap auth_parameters.
    assert [role for role, _ in parsed] == ["client_id", "client_secret"]


# ---------------------------------------------------------------------------
# Part A (interpolation) — build_connection_profile emits metadata.xsoar
# ---------------------------------------------------------------------------
def test_build_connection_profile_apikey_emits_interpolation_metadata():
    entry = {
        "type": "APIKey",
        "name": "api_key",
        "interpolated": False,
        "xsoar_param_map": {"api_key": "key"},
    }
    prof = cb.build_connection_profile(entry, "Okta", connector_title="Okta")
    assert prof["metadata"]["xsoar"]["interpolation_mapping"] == "api_key:api_key"
    # Regression: existing field shape unchanged.
    field = prof["configurations"][0]["fields"][0]
    assert field["id"] == "api_key"
    assert field["metadata"]["auth"]["parameter"] == "api_key"


def test_build_connection_profile_plain_mapping_matches_field_roles():
    entry = {
        "type": "Plain",
        "name": "credentials",
        "interpolated": True,
        "xsoar_param_map": {
            "credentials.identifier": "username",
            "credentials.password": "password",
        },
    }
    prof = cb.build_connection_profile(entry, "Foo", connector_title="Foo")
    mapping = prof["metadata"]["xsoar"]["interpolation_mapping"]
    left_roles = {entry.split(":", 1)[0] for entry in mapping.split(",")}
    field_params = {
        f["metadata"]["auth"]["parameter"]
        for f in prof["configurations"][0]["fields"]
    }
    assert left_roles == field_params == {"username", "password"}


def test_build_connection_profile_passthrough_interpolated_true():
    entry = {
        "type": "Passthrough",
        "name": "bag",
        "interpolated": False,
        "xsoar_param_map": {
            "credentials_auth_id.password": "client_id",
            "credentials_enc_key.password": "client_secret",
        },
    }
    prof = cb.build_connection_profile(entry, "Microsoft Graph")
    assert prof["metadata"]["xsoar"]["interpolation_mapping"] == (
        "client_id:credentials_auth_id.password,"
        "client_secret:credentials_enc_key.password"
    )


def test_build_connection_profile_interpolated_always_true():
    # ALWAYS-INTERPOLATE gate (Plan B INV-5): interpolated is hard-forced True
    # on every profile, regardless of what the entry carries.
    entry_default = {
        "type": "APIKey",
        "name": "api_key",
        "xsoar_param_map": {"api_key": "key"},
    }
    prof_default = cb.build_connection_profile(entry_default, "Okta")
    assert prof_default["metadata"]["xsoar"]["interpolated"] is True
    # Even an entry that explicitly says interpolated False still emits True.
    entry_false = {**entry_default, "interpolated": False}
    prof_false = cb.build_connection_profile(entry_false, "Okta")
    assert prof_false["metadata"]["xsoar"]["interpolated"] is True


def test_build_connection_profile_metadata_precedes_configurations():
    entry = {
        "type": "APIKey",
        "name": "api_key",
        "interpolated": True,
        "xsoar_param_map": {"api_key": "key"},
    }
    prof = cb.build_connection_profile(entry, "Okta")
    keys = list(prof.keys())
    assert keys.index("metadata") < keys.index("configurations")


# ---------------------------------------------------------------------------
# Part A (interpolation) — Plan B hard gate (_validate_interpolation_invariants)
# See interpolated-param-schemas-and-fix.md §6.6.
# ---------------------------------------------------------------------------
def _profile_with_field(
    *,
    profile_type: str,
    auth_parameter: str | None,
    mapping: str,
    interpolated: bool = True,
):
    """Hand-build a minimal profile dict for direct validator tests.

    Lets the tests construct profiles that ``build_connection_profile`` would
    never produce (e.g. a mapping role with no matching field), exercising the
    gate's must-raise paths directly.
    """
    field_metadata: dict = {}
    if auth_parameter is not None:
        field_metadata = {"auth": {"parameter": auth_parameter}}
    return {
        "id": f"{profile_type}.test",
        "type": profile_type,
        "metadata": {
            "xsoar": {
                "interpolated": interpolated,
                "interpolation_mapping": mapping,
            }
        },
        "configurations": [{"fields": [{"id": "f", "metadata": field_metadata}]}],
    }


# --- Positive: every built profile passes the gate (one per type) ---
@pytest.mark.parametrize(
    "entry",
    [
        {"type": "APIKey", "name": "k", "xsoar_param_map": {"api_key": "key"}},
        {
            "type": "Plain",
            "name": "c",
            "xsoar_param_map": {
                "credentials.identifier": "username",
                "credentials.password": "password",
            },
        },
        {
            "type": "Passthrough",
            "name": "bag",
            "xsoar_param_map": {
                "credentials_auth_id.password": "client_id",
                "credentials_enc_key.password": "client_secret",
            },
        },
    ],
)
def test_validate_invariants_built_profiles_pass(entry):
    # build_connection_profile already runs the gate; no raise == pass.
    prof = cb.build_connection_profile(entry, "Acme", connector_title="Acme")
    # And re-validating is idempotent.
    cb._validate_interpolation_invariants(prof, "Acme")


# --- INV-1 / INV-2: role with no matching field auth.parameter ---
def test_validate_inv1_role_without_matching_field_raises():
    prof = _profile_with_field(
        profile_type="plain",
        auth_parameter="username",
        # 'password' has no matching field auth.parameter.
        mapping="username:credentials.identifier,password:credentials.password",
    )
    with pytest.raises(cb.InterpolationSchemaError, match="INV-1/INV-2"):
        cb._validate_interpolation_invariants(prof, "Acme")


def test_validate_inv2_non_auth_field_mapped_raises():
    # A none_* config field has NO auth.parameter -> field_parameters empty,
    # so the mapped role 'server_url' cannot match.
    prof = _profile_with_field(
        profile_type="plain",
        auth_parameter=None,
        mapping="server_url:none_server_url",
    )
    with pytest.raises(cb.InterpolationSchemaError, match="INV-1/INV-2"):
        cb._validate_interpolation_invariants(prof, "MxToolbox")


# --- INV-3: api_key LEFT must be 'api_key', not raw 'key' ---
def test_validate_inv3_apikey_raw_key_left_raises():
    prof = _profile_with_field(
        profile_type="api_key",
        auth_parameter="key",
        mapping="key:api_key.password",
    )
    with pytest.raises(cb.InterpolationSchemaError, match="INV-3"):
        cb._validate_interpolation_invariants(prof, "Acme")


# --- INV-4: no reserved delimiters in role/path (grammar has no escaping) ---
def test_build_interpolation_mapping_inv4_comma_in_path_raises():
    # A ',' in the xsoar_path would corrupt the comma-joined mapping string;
    # caught at emission time in build_interpolation_mapping.
    with pytest.raises(cb.InterpolationSchemaError, match="INV-4"):
        cb.build_interpolation_mapping("passthrough", {"creds.a,b": "client_id"})


def test_build_interpolation_mapping_inv4_colon_in_role_raises():
    # A ':' in the role would corrupt the first-':' split; caught at emission.
    with pytest.raises(cb.InterpolationSchemaError, match="INV-4"):
        cb.build_interpolation_mapping("passthrough", {"creds.a": "client:id"})


# --- INV-5: interpolated must be True on every profile ---
def test_validate_inv5_interpolated_not_true_raises():
    prof = _profile_with_field(
        profile_type="api_key",
        auth_parameter="api_key",
        mapping="api_key:api_key",
        interpolated=False,
    )
    with pytest.raises(cb.InterpolationSchemaError, match="INV-5"):
        cb._validate_interpolation_invariants(prof, "Acme")


# --- Round-trip parse guard: emitted mapping round-trips role -> xsoar_path ---
@pytest.mark.parametrize(
    "profile_type,xsoar_param_map",
    [
        ("api_key", {"api_key": "key"}),
        (
            "plain",
            {
                "credentials.identifier": "username",
                "credentials.password": "password",
            },
        ),
        (
            "passthrough",
            {
                "credentials_auth_id.password": "client_id",
                "credentials_enc_key.password": "client_secret",
            },
        ),
    ],
)
def test_emitted_mapping_round_trips_to_auth_parameter_pairs(
    profile_type, xsoar_param_map
):
    mapping = cb.build_interpolation_mapping(profile_type, xsoar_param_map)
    # Re-implement the runtime _parse_param_map grammar inline (first-':' split).
    parsed = []
    for entry in mapping.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        left, _, right = entry.partition(":")
        parsed.append((left.strip(), right.strip()))
    # Each parsed pair must be (post-remap auth_parameter, xsoar_path).
    expected = {
        (
            cb._auth_parameter_for_role(profile_type, role),
            xsoar_path,
        )
        for xsoar_path, role in xsoar_param_map.items()
    }
    assert set(parsed) == expected


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
    # switch -> checkbox (Issue #6)
    assert f["field_type"] == "checkbox"
    assert f["options"]["default_value"] is False
    assert f["options"]["mask"] is False
    assert f["metadata"]["event"]["publish"] is True
    # proxy/insecure are NOT backend-managed (Issue #5) — no xsoar metadata.
    assert "xsoar" not in f["metadata"]
    # proxy ships visible-but-locked (read_only:true), unlocked by the engine
    # trigger (Issue #7) — NOT hidden.
    assert f["options"]["create_modifiers"]["read_only"] is True
    assert f["options"]["create_modifiers"]["hidden"] is False
    assert f["options"]["edit_modifiers"]["read_only"] is True


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
    # "host" (rest of other_connection) is now emitted FIRST, per-profile,
    # before proxy/insecure/engine.
    assert ids == [
        "host",
        "proxy",
        "insecure",
        "engine_mode",
        "engine",
        "engine_group",
    ]
    # 2 engine-hide triggers + 1 merged proxy-unlock trigger (proxy unlocked
    # via read_only:false when engine OR engine_group is_not_empty — Issue #7).
    assert len(trig) == 3
    proxy_unlock = [
        t
        for t in trig
        if t["effects"][0]["action"] == {"read_only": False}
        and t["effects"][0]["id"] == "proxy"
    ]
    assert proxy_unlock == [
        {
            "conditions": {
                "operator": "OR",
                "children": [
                    {
                        "id": "engine",
                        "behavior": "value",
                        "operator": "is_not_empty",
                    },
                    {
                        "id": "engine_group",
                        "behavior": "value",
                        "operator": "is_not_empty",
                    },
                ],
            },
            "effects": [{"id": "proxy", "action": {"read_only": False}}],
        },
    ]


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
    # single-engine: 1 engine-hide trigger + 1 proxy-unlock trigger (engine
    # is_not_empty → proxy read_only:false). No engine_group → single condition
    # (no OR group needed). (Issue #7)
    assert len(trig) == 2
    proxy_unlock = [
        t
        for t in trig
        if t["effects"][0]["action"] == {"read_only": False}
        and t["effects"][0]["id"] == "proxy"
    ]
    assert proxy_unlock == [
        {
            "conditions": {
                "id": "engine",
                "behavior": "value",
                "operator": "is_not_empty",
            },
            "effects": [{"id": "proxy", "action": {"read_only": False}}],
        },
    ]


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


def test_rest_fields_duplicated_per_profile_with_serializer_bridge():
    # The rest of other_connection (host) is duplicated into EVERY profile:
    # profile 1 keeps the bare id; profile 2+ get a prefixed id + a serializer
    # bridge back to the original XSOAR param name (same model as proxy).
    profiles = [
        {"id": "plain.foo", "configurations": [{"fields": []}]},
        {"id": "api_key.foo", "configurations": [{"fields": []}]},
    ]
    bridges: list[tuple[str, str, str]] = []

    def bridge(handler_dir: Path, new_id: str, original_id: str) -> None:
        bridges.append((str(handler_dir), new_id, original_id))

    def mapper(p: dict) -> list[dict]:
        return [{"id": p["name"], "field_type": "input", "options": {}}]

    cb.attach_per_profile_connection_fields(
        profiles,
        "Foo",
        ["host"],
        yml_params_by_name={"host": {"name": "host", "type": 0}},
        handler_dir=Path("/tmp/h"),
        serializer_bridge=bridge,
        field_mapper=mapper,
    )
    first_ids = [f["id"] for f in profiles[0]["configurations"][0]["fields"]]
    second_ids = [f["id"] for f in profiles[1]["configurations"][0]["fields"]]
    assert "host" in first_ids
    assert "foo_host" in second_ids
    bridged = {(b[1], b[2]) for b in bridges}
    assert ("foo_host", "host") in bridged


# ---------------------------------------------------------------------------
# Part D — view_groups
# ---------------------------------------------------------------------------
def test_build_view_groups_registry():
    reg = cb.build_view_groups_registry([("EWS O365", "EWS O365")])
    assert reg == [
        {
            "id": "ews-o365",
            "label": "EWS O365",
            "help_text": "Connection settings for EWS O365.",
        }
    ]


def test_rest_fields_emitted_per_profile_single_profile():
    # Rest of other_connection (host) is emitted INSIDE the auth profile
    # (not in general_configurations). One profile -> bare id, no bridge.
    profiles = [{"id": "passthrough.foo", "configurations": [{"fields": []}]}]

    def mapper(p: dict) -> list[dict]:
        return [{"id": p["name"], "field_type": "input", "options": {}}]

    cb.attach_per_profile_connection_fields(
        profiles,
        "Foo",
        ["host", "proxy", "insecure"],
        yml_params_by_name={"host": {"name": "host", "type": 0}},
        field_mapper=mapper,
    )
    ids = [f["id"] for f in profiles[0]["configurations"][0]["fields"]]
    assert ids[0] == "host"
    assert "proxy" in ids and "insecure" in ids
    host_field = profiles[0]["configurations"][0]["fields"][0]
    assert host_field["metadata"]["event"]["publish"] is True
    assert host_field["options"]["mask"] is False


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
    # connection.yaml has NO general_configurations — every non-auth field is
    # per-profile now.
    assert "general_configurations" not in conn
    # host (rest of other_connection) + proxy/insecure/engine all live inside
    # the profile, AFTER the auth credential fields. host precedes proxy.
    prof_ids = [f["id"] for f in conn["profiles"][0]["configurations"][0]["fields"]]
    assert "host" in prof_ids
    assert "proxy" in prof_ids and "insecure" in prof_ids and "engine_mode" in prof_ids
    assert prof_ids.index("host") < prof_ids.index("proxy")
    # 2 engine-hide triggers (engine, engine_group) + 1 merged proxy-unlock
    # trigger (proxy unlocked via read_only:false when engine OR engine_group
    # is_not_empty — Issue #7).
    assert len(triggers) == 3
    proxy_unlock = [
        t
        for t in triggers
        if t["effects"][0]["action"] == {"read_only": False}
        and t["effects"][0]["id"] == "proxy"
    ]
    assert len(proxy_unlock) == 1
    assert proxy_unlock[0]["conditions"]["operator"] == "OR"
    assert [
        c["id"] for c in proxy_unlock[0]["conditions"]["children"]
    ] == ["engine", "engine_group"]
