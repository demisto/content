"""TDD tests for the non-type-9 nesting patch (``flatten_non_type9_nesting``).

These tests use synthetic ``connection.yaml`` fixtures written to a temp dir and
an INJECTED ``{param_name: type}`` map (the production type resolver, which reads
the pipeline CSV + source YMLs, is mocked out so the unit tests never touch the
real repo). They pin the patch's behaviour to mirror the generator's
``_flatten_non_type9_param_map`` semantics exactly:

* type-14 (and any non-type-9) nested leaves are FLATTENED;
* type-9 nested leaves are LEFT UNCHANGED;
* a mixed manifest flattens only the non-type-9 params;
* the patch is idempotent (second run is a no-op);
* an unresolved-type param is SKIPPED (not flattened) and reported;
* a flat/clean manifest is untouched.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

# Make the sibling patch module importable regardless of invocation dir.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import flatten_non_type9_nesting as patch  # noqa: E402


# --------------------------------------------------------------------------- #
# Fixtures helpers
# --------------------------------------------------------------------------- #
def _write_connection(tmp_path: Path, connector: str, body: str) -> Path:
    """Write a connection.yaml under ``connectors/<connector>/`` and return it."""
    conn_dir = tmp_path / "connectors" / connector
    conn_dir.mkdir(parents=True, exist_ok=True)
    conn_path = conn_dir / "connection.yaml"
    conn_path.write_text(textwrap.dedent(body).lstrip("\n"))
    return conn_path


# A nested type-14 manifest: param ``certbundle`` was wrongly nested into a
# ``.password`` leaf. Field id is the bare ``certbundle`` (no ``.identifier``
# sibling, per the generator's ``_connection_field_id_from_map_key``).
NESTED_TYPE14 = """
    metadata:
      title: Connection
    profiles:
    - id: api_key.acme
      type: api_key
      view_group: acme
      title: API
      metadata:
        xsoar:
          interpolated: true
          interpolation_mapping: api_key:certbundle.password
      configurations:
      - fields:
        - id: certbundle
          title: Certificate
          field_type: input
          metadata:
            auth:
              parameter: api_key
          options:
            mask: true
            create_modifiers:
              required: true
              hidden: false
"""

# A nested type-9 manifest: param ``credentials`` legitimately splits into
# ``.identifier`` (username) + ``.password`` leaves -> two fields.
NESTED_TYPE9 = """
    metadata:
      title: Connection
    profiles:
    - id: plain.acme
      type: plain
      view_group: acme
      title: Basic
      metadata:
        xsoar:
          interpolated: true
          interpolation_mapping: username:credentials.identifier,password:credentials.password
      configurations:
      - fields:
        - id: credentials_username
          title: Username
          field_type: input
          metadata:
            auth:
              parameter: username
          options:
            mask: false
            create_modifiers:
              required: true
              hidden: false
      - fields:
        - id: credentials_password
          title: Password
          field_type: input
          metadata:
            auth:
              parameter: password
          options:
            mask: true
            create_modifiers:
              required: true
              hidden: false
"""

# Mixed: a type-9 ``credentials`` pair (keep) + a type-14 ``certbundle`` leaf
# (flatten) in the SAME profile.
MIXED = """
    metadata:
      title: Connection
    profiles:
    - id: plain.acme
      type: plain
      view_group: acme
      title: Basic
      metadata:
        xsoar:
          interpolated: true
          interpolation_mapping: username:credentials.identifier,password:credentials.password,api_key:certbundle.password
      configurations:
      - fields:
        - id: credentials_username
          title: Username
          field_type: input
          metadata:
            auth:
              parameter: username
          options:
            mask: false
            create_modifiers:
              required: true
              hidden: false
      - fields:
        - id: credentials_password
          title: Password
          field_type: input
          metadata:
            auth:
              parameter: password
          options:
            mask: true
            create_modifiers:
              required: true
              hidden: false
      - fields:
        - id: certbundle
          title: Certificate
          field_type: input
          metadata:
            auth:
              parameter: api_key
          options:
            mask: true
            create_modifiers:
              required: true
              hidden: false
"""

# A clean, fully-flat manifest (nothing to do).
CLEAN_FLAT = """
    metadata:
      title: Connection
    profiles:
    - id: api_key.acme
      type: api_key
      view_group: acme
      title: API
      metadata:
        xsoar:
          interpolated: true
          interpolation_mapping: api_key:api_key,tsg_id:tsg_id
      configurations:
      - fields:
        - id: api_key
          title: API Key
          field_type: input
          metadata:
            auth:
              parameter: api_key
          options:
            mask: true
            create_modifiers:
              required: true
              hidden: false
      - fields:
        - id: tsg_id
          title: TSG ID
          field_type: input
          metadata:
            auth:
              parameter: tsg_id
          options:
            mask: false
            create_modifiers:
              required: false
              hidden: false
"""

# Nested .identifier + .password pair for a NON-type-9 param: both leaves must
# collapse onto a single flat field; the .password (secret) leaf wins the role.
NESTED_NON9_PAIR = """
    metadata:
      title: Connection
    profiles:
    - id: plain.acme
      type: plain
      view_group: acme
      title: Basic
      metadata:
        xsoar:
          interpolated: true
          interpolation_mapping: username:weird.identifier,password:weird.password
      configurations:
      - fields:
        - id: weird_username
          title: Username
          field_type: input
          metadata:
            auth:
              parameter: username
          options:
            mask: false
            create_modifiers:
              required: true
              hidden: false
      - fields:
        - id: weird_password
          title: Password
          field_type: input
          metadata:
            auth:
              parameter: password
          options:
            mask: true
            create_modifiers:
              required: true
              hidden: false
"""


def _mapping_of(profile: dict) -> str:
    return profile["metadata"]["xsoar"]["interpolation_mapping"]


def _field_ids(profile: dict) -> list[str]:
    ids: list[str] = []
    for cfg in profile.get("configurations", []) or []:
        for f in cfg.get("fields", []) or []:
            ids.append(f.get("id"))
    return ids


def _field_by_id(profile: dict, fid: str) -> dict | None:
    for cfg in profile.get("configurations", []) or []:
        for f in cfg.get("fields", []) or []:
            if f.get("id") == fid:
                return f
    return None


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_type14_nested_manifest_is_flattened(tmp_path: Path) -> None:
    conn = _write_connection(tmp_path, "acme", NESTED_TYPE14)
    type_lookup = lambda _conn: {"certbundle": 14}

    result = patch.patch_file(conn, type_lookup, dry_run=False)

    assert result.modified is True
    assert "certbundle" in result.flattened_params

    doc = patch.load_yaml(conn)
    prof = doc["profiles"][0]
    # interpolation_mapping: dotted leaf collapsed to the bare param name.
    assert _mapping_of(prof) == "api_key:certbundle"
    # Field id stays the bare ``certbundle`` (it already was), mask preserved.
    assert _field_ids(prof) == ["certbundle"]
    fld = _field_by_id(prof, "certbundle")
    assert fld["metadata"]["auth"]["parameter"] == "api_key"
    assert fld["options"]["mask"] is True


def test_type9_nested_manifest_unchanged(tmp_path: Path) -> None:
    conn = _write_connection(tmp_path, "acme", NESTED_TYPE9)
    before = conn.read_text()
    type_lookup = lambda _conn: {"credentials": 9}

    result = patch.patch_file(conn, type_lookup, dry_run=False)

    assert result.modified is False
    assert result.flattened_params == []
    # Byte-for-byte unchanged on disk.
    assert conn.read_text() == before
    doc = patch.load_yaml(conn)
    prof = doc["profiles"][0]
    assert _mapping_of(prof) == (
        "username:credentials.identifier,password:credentials.password"
    )
    assert _field_ids(prof) == ["credentials_username", "credentials_password"]


def test_mixed_manifest_flattens_only_non_type9(tmp_path: Path) -> None:
    conn = _write_connection(tmp_path, "acme", MIXED)
    type_lookup = lambda _conn: {"credentials": 9, "certbundle": 14}

    result = patch.patch_file(conn, type_lookup, dry_run=False)

    assert result.modified is True
    assert result.flattened_params == ["certbundle"]

    doc = patch.load_yaml(conn)
    prof = doc["profiles"][0]
    # type-9 credentials nesting preserved; certbundle flattened.
    assert _mapping_of(prof) == (
        "username:credentials.identifier,password:credentials.password,"
        "api_key:certbundle"
    )
    ids = _field_ids(prof)
    assert "credentials_username" in ids
    assert "credentials_password" in ids
    assert "certbundle" in ids
    # certbundle stays a masked secret.
    assert _field_by_id(prof, "certbundle")["options"]["mask"] is True


def test_non_type9_identifier_password_pair_collapses_secret_wins(
    tmp_path: Path,
) -> None:
    conn = _write_connection(tmp_path, "acme", NESTED_NON9_PAIR)
    type_lookup = lambda _conn: {"weird": 4}

    result = patch.patch_file(conn, type_lookup, dry_run=False)

    assert result.modified is True
    assert result.flattened_params == ["weird"]
    doc = patch.load_yaml(conn)
    prof = doc["profiles"][0]
    # Both leaves collapse to ONE flat ``weird`` entry; the .password (secret)
    # leaf wins, so the surviving auth role is ``password`` and it stays masked.
    assert _mapping_of(prof) == "password:weird"
    assert _field_ids(prof) == ["weird"]
    fld = _field_by_id(prof, "weird")
    assert fld["metadata"]["auth"]["parameter"] == "password"
    assert fld["options"]["mask"] is True


def test_idempotent_second_run_is_noop(tmp_path: Path) -> None:
    conn = _write_connection(tmp_path, "acme", NESTED_TYPE14)
    type_lookup = lambda _conn: {"certbundle": 14}

    first = patch.patch_file(conn, type_lookup, dry_run=False)
    assert first.modified is True
    after_first = conn.read_text()

    second = patch.patch_file(conn, type_lookup, dry_run=False)
    assert second.modified is False
    assert second.flattened_params == []
    # No further byte changes.
    assert conn.read_text() == after_first


def test_unresolved_type_is_skipped_and_reported(tmp_path: Path) -> None:
    conn = _write_connection(tmp_path, "acme", NESTED_TYPE14)
    before = conn.read_text()
    # Type lookup cannot resolve ``certbundle`` -> empty map.
    type_lookup = lambda _conn: {}

    result = patch.patch_file(conn, type_lookup, dry_run=False)

    assert result.modified is False
    assert result.flattened_params == []
    assert "certbundle" in result.unresolved_params
    # Left untouched on disk (we never flatten what we can't positively resolve).
    assert conn.read_text() == before


def test_clean_flat_manifest_untouched(tmp_path: Path) -> None:
    conn = _write_connection(tmp_path, "acme", CLEAN_FLAT)
    before = conn.read_text()
    type_lookup = lambda _conn: {"api_key": 4, "tsg_id": 0}

    result = patch.patch_file(conn, type_lookup, dry_run=False)

    assert result.modified is False
    assert result.flattened_params == []
    assert result.unresolved_params == []
    assert conn.read_text() == before


def test_dry_run_does_not_write(tmp_path: Path) -> None:
    conn = _write_connection(tmp_path, "acme", NESTED_TYPE14)
    before = conn.read_text()
    type_lookup = lambda _conn: {"certbundle": 14}

    result = patch.patch_file(conn, type_lookup, dry_run=True)

    # Reports the change it WOULD make, but does not write.
    assert result.modified is True
    assert result.flattened_params == ["certbundle"]
    assert conn.read_text() == before


def test_per_profile_lookup_scopes_types_to_owning_profile(tmp_path: Path) -> None:
    """A 2-arg ``(path, profile)`` resolver scopes types PER PROFILE.

    This guards the real-world AWS collision: the same param name (``creds``)
    is type 9 in one profile's source integration but type 14 in another's.
    Only the type-14 profile must flatten; the type-9 profile stays nested.
    """
    body = """
        metadata:
          title: Connection
        profiles:
        - id: api_key.nine
          type: api_key
          view_group: nine
          metadata:
            xsoar:
              interpolated: true
              interpolation_mapping: api_key:creds.password
          configurations:
          - fields:
            - id: creds
              title: Creds
              field_type: input
              metadata:
                auth:
                  parameter: api_key
              options:
                mask: true
        - id: api_key.fourteen
          type: api_key
          view_group: fourteen
          metadata:
            xsoar:
              interpolated: true
              interpolation_mapping: api_key:creds.password
          configurations:
          - fields:
            - id: creds
              title: Creds
              field_type: input
              metadata:
                auth:
                  parameter: api_key
              options:
                mask: true
    """
    conn = _write_connection(tmp_path, "shared", body)

    # Resolver keyed on the profile id: type 9 for the first, type 14 for the
    # second — exactly the per-integration scoping the production resolver does.
    def type_lookup(_path: Path, profile: dict) -> dict:
        if profile.get("id") == "api_key.nine":
            return {"creds": 9}
        return {"creds": 14}

    result = patch.patch_file(conn, type_lookup, dry_run=False)

    assert result.modified is True
    assert result.flattened_params == ["creds"]  # only the type-14 profile

    doc = patch.load_yaml(conn)
    nine, fourteen = doc["profiles"]
    # Type-9 profile untouched (still nested .password leaf).
    assert _mapping_of(nine) == "api_key:creds.password"
    # Type-14 profile flattened to a bare param.
    assert _mapping_of(fourteen) == "api_key:creds"


def test_scan_tree_finds_all_connection_files(tmp_path: Path) -> None:
    connectors = tmp_path / "connectors"
    _write_connection(tmp_path, "acme", NESTED_TYPE14)
    _write_connection(tmp_path, "beta", NESTED_TYPE9)
    found = patch.find_connection_files(connectors)
    names = sorted(p.parent.name for p in found)
    assert names == ["acme", "beta"]
