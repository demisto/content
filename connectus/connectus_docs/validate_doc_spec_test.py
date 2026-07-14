"""Unit tests for validate_doc_spec (§9 rules).

Builds a synthetic ConnectorBundle directly (no disk) so the validator's
cross-checks have a known truth source. Run from the package directory::

    cd content/connectus/connectus_docs && python3 -m pytest validate_doc_spec_test.py
"""

from __future__ import annotations

import copy
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from gatherers import (  # noqa: E402
    ConnectorBundle,
    MemberBundle,
    ProfileSource,
    ViewGroupFlag,
)
from resolvers import ConnectorPaths, ViewGroup  # noqa: E402
from validate_doc_spec import validate  # noqa: E402


# --------------------------------------------------------------------------- #
# Synthetic truth source + a valid spec
# --------------------------------------------------------------------------- #
def _bundle() -> ConnectorBundle:
    paths = ConnectorPaths(
        slug="acme",
        folder=None,  # type: ignore[arg-type]
        connector_yaml=None,
        capabilities_yaml=None,
        connection_yaml=None,
        configurations_yaml=None,
        summary_yaml=None,
    )
    member = MemberBundle(
        integration_id="Acme One",
        expected_view_group_id="acme-one",
        commonfields_id="Acme One",
        commonfields_name="Acme One",
        description_md=(
            "Acme overview.\n\n"
            "Generate an API key in the [Acme console](https://acme.example.com)."
        ),
        description_md_len=90,
        description_sections=[],
        profiles=[
            # On-disk profile copy is CLEAN by default so the §9.11c audit (which
            # now inspects the EFFECTIVE final on-disk state) does not trip the
            # base bundle. Audit tests that need jargon override these explicitly.
            ProfileSource(
                id="plain.acme",
                type="plain",
                view_group="acme-one",
                view_group_label="Acme One",
                title="API Key",
                description="Authenticate using an API key from the Acme console.",
                integration_id="Acme One",
                commonfields_name="Acme One",
            ),
            ProfileSource(
                id="api_key.acme",
                type="api_key",
                view_group="acme-one",
                view_group_label="Acme One",
                title=None,
                description=None,
                integration_id="Acme One",
                commonfields_name="Acme One",
            ),
        ],
    )
    # help_text "placeholder" is non-boilerplate (does not match a template nor
    # the label) so the base bundle passes the §9.13 audit.
    vg = ViewGroup(id="acme-one", label="Acme One", help_text="placeholder")
    flag = ViewGroupFlag(
        view_group_id="acme-one",
        label="Acme One",
        expected_id="acme-one",
        expected_label="Acme One",
        id_ok=True,
        label_ok=True,
    )
    return ConnectorBundle(
        slug="acme",
        paths=paths,
        view_groups=[vg],
        members=[member],
        view_group_flags=[flag],
    )


def _valid_spec() -> dict:
    return {
        "connector_slug": "acme",
        "connector_id": "Acme",
        "members": [
            {
                "integration_id": "Acme One",
                "view_group_id": "acme-one",
                "commonfields_name": "Acme One",
                "description_md_len": 90,
            }
        ],
        "connector": {"description": "Acme connector for security operations."},
        "capabilities": {
            "items": [
                {
                    "id": "automation-and-remediation",
                    "description": "Run automated actions and remediation commands against the connected service.",
                }
            ]
        },
        "connection": {
            "view_groups": [
                {
                    "id": "acme-one",
                    "label": "Acme One",
                    "help_text": "Generate an API key in the [Acme console](https://acme.example.com).",
                }
            ]
        },
        "configurations": {"view_groups": []},
        "summary": {"metadata": {"next_steps": None}},
    }


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #
def test_valid_spec_passes():
    report = validate(_valid_spec(), "acme", bundle=_bundle())
    assert report.ok, report.errors
    # The valid spec preserves the source link -> no link warning.
    assert not any("§9.10" in w for w in report.warnings)


# --------------------------------------------------------------------------- #
# §9.5 flags
# --------------------------------------------------------------------------- #
def test_flag_sentinel_fails():
    spec = _valid_spec()
    spec["connector"]["description"] = "__FLAG__: no usable source"
    report = validate(spec, "acme", bundle=_bundle())
    assert not report.ok
    assert any("§9.5" in e for e in report.errors)


# --------------------------------------------------------------------------- #
# §9.2 connector description
# --------------------------------------------------------------------------- #
def test_short_connector_description_fails():
    spec = _valid_spec()
    spec["connector"]["description"] = "short"
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.2" in e for e in report.errors)


def test_long_connector_description_warns():
    spec = _valid_spec()
    spec["connector"]["description"] = "a valid long description line\n" * 6
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok
    assert any("§9.2" in w for w in report.warnings)


# --------------------------------------------------------------------------- #
# §9.3 capabilities
# --------------------------------------------------------------------------- #
def test_unknown_capability_id_fails():
    spec = _valid_spec()
    spec["capabilities"]["items"][0]["id"] = "not-a-real-capability"
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.3" in e for e in report.errors)


def test_capability_description_drift_warns():
    spec = _valid_spec()
    spec["capabilities"]["items"][0]["description"] = "Custom reworded description."
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok
    assert any("§9.3" in w for w in report.warnings)


# --------------------------------------------------------------------------- #
# §9.4 connection coverage
# --------------------------------------------------------------------------- #
def test_member_without_connection_help_text_passes():
    # §9.4 RELAXED: connection help_text is OPTIONAL; a member view_group with no
    # help_text key no longer errors (the former count==0 branch was removed).
    spec = _valid_spec()
    spec["connection"]["view_groups"] = [{"id": "acme-one", "label": "Acme One"}]
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok, report.errors
    assert not any("§9.4" in e and "missing" in e for e in report.errors)


def test_duplicate_connection_help_fails():
    spec = _valid_spec()
    spec["connection"]["view_groups"].append(
        copy.deepcopy(spec["connection"]["view_groups"][0])
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.4" in e for e in report.errors)


def test_unknown_connection_view_group_fails():
    spec = _valid_spec()
    spec["connection"]["view_groups"][0]["id"] = "ghost-vg"
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.4" in e for e in report.errors)


def test_optional_config_help_absent_is_ok():
    spec = _valid_spec()
    spec["configurations"]["view_groups"] = []
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok


# --------------------------------------------------------------------------- #
# §9.6 summary
# --------------------------------------------------------------------------- #
def test_empty_next_steps_string_fails():
    spec = _valid_spec()
    spec["summary"]["metadata"]["next_steps"] = "   "
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.6" in e for e in report.errors)


def test_next_steps_string_ok():
    spec = _valid_spec()
    spec["summary"]["metadata"]["next_steps"] = "Enable fetching in the instance."
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok


# --------------------------------------------------------------------------- #
# §9.7 no-commands
# --------------------------------------------------------------------------- #
def test_command_content_in_help_fails():
    spec = _valid_spec()
    spec["connection"]["view_groups"][0]["help_text"] += "\n## Commands\n### acme-do\nx"
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.7" in e for e in report.errors)


# --------------------------------------------------------------------------- #
# §9.9 view_group correctness
# --------------------------------------------------------------------------- #
def test_label_mismatch_in_bundle_fails():
    bundle = _bundle()
    bundle.view_group_flags[0] = ViewGroupFlag(
        view_group_id="acme-one",
        label="Wrong Label",
        expected_id="acme-one",
        expected_label="Acme One",
        id_ok=True,
        label_ok=False,
    )
    report = validate(_valid_spec(), "acme", bundle=bundle)
    assert any("§9.9" in e for e in report.errors)


def test_spec_label_drift_fails():
    spec = _valid_spec()
    spec["connection"]["view_groups"][0]["label"] = "Drifted Label"
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.9" in e for e in report.errors)


# --------------------------------------------------------------------------- #
# §9.10 link preservation
# --------------------------------------------------------------------------- #
def test_dropped_source_link_in_authored_help_text_fails():
    # §9.10 (hardened): when the doc-spec AUTHORS help_text but drops a source
    # link, that is a fidelity loss -> HARD error (was a soft warn).
    spec = _valid_spec()
    spec["connection"]["view_groups"][0]["help_text"] = "No link here at all."
    report = validate(spec, "acme", bundle=_bundle())
    assert not report.ok
    assert any("§9.10" in e for e in report.errors)


def test_dropped_source_link_when_help_text_omitted_only_warns():
    # When help_text is OMITTED (on-disk value left untouched), §9.10 stays soft.
    spec = _valid_spec()
    spec["connection"]["view_groups"][0] = {"id": "acme-one", "label": "Acme One"}
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.10" in w for w in report.warnings)
    assert not any("§9.10" in e for e in report.errors)


# --------------------------------------------------------------------------- #
# §9.8 length governor
# --------------------------------------------------------------------------- #
def test_overlong_help_text_warns():
    spec = _valid_spec()
    spec["connection"]["view_groups"][0]["help_text"] = (
        "Generate an API key in the [Acme console](https://acme.example.com). "
        + ("padding " * 200)
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok
    assert any("§9.8" in w for w in report.warnings)


# --------------------------------------------------------------------------- #
# slug mismatch
# --------------------------------------------------------------------------- #
def test_slug_mismatch_fails():
    report = validate(_valid_spec(), "different-slug", bundle=_bundle())
    assert any("connector_slug" in e for e in report.errors)


# --------------------------------------------------------------------------- #
# §9.11 profile title/description checks
# --------------------------------------------------------------------------- #
def _spec_with_profiles(profiles):
    spec = _valid_spec()
    spec["connection"]["profiles"] = profiles
    return spec


def test_profiles_unknown_id_hard_fails():
    spec = _spec_with_profiles([{"id": "ghost.profile", "title": "Token"}])
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.11" in e and "not found" in e for e in report.errors)


def test_profiles_missing_both_fields_hard_fails():
    spec = _spec_with_profiles([{"id": "plain.acme"}])
    report = validate(spec, "acme", bundle=_bundle())
    assert any(
        "§9.11" in e and "at least one" in e for e in report.errors
    )


def test_profiles_jargon_passthrough_in_description_hard_fails():
    spec = _spec_with_profiles(
        [{"id": "plain.acme", "description": "A passthrough auth profile."}]
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.11" in e and "passthrough" in e for e in report.errors)


def test_profiles_jargon_raw_type_value_hard_fails():
    # api_key.acme has type "api_key" -> using "api_key" in title is banned.
    spec = _spec_with_profiles(
        [{"id": "api_key.acme", "title": "api_key credentials"}]
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.11" in e and "api_key" in e for e in report.errors)


def test_profiles_jargon_whole_word_case_insensitive():
    # "Passthrough"/"PLAIN" trip (case-insensitive); "explained" (substring
    # "plain") does NOT.
    spec_hit = _spec_with_profiles(
        [{"id": "plain.acme", "title": "Passthrough", "description": "PLAIN auth."}]
    )
    report_hit = validate(spec_hit, "acme", bundle=_bundle())
    assert any("§9.11" in e and "passthrough" in e for e in report_hit.errors)
    assert any("§9.11" in e and "plain" in e for e in report_hit.errors)

    spec_clean = _spec_with_profiles(
        [{"id": "plain.acme", "description": "Everything is explained clearly."}]
    )
    report_clean = validate(spec_clean, "acme", bundle=_bundle())
    assert not any("§9.11" in e for e in report_clean.errors)


def test_profiles_command_content_hard_fails():
    spec = _spec_with_profiles(
        [{"id": "plain.acme", "description": "Run it.\n## Commands\n### acme-do\nx"}]
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert any(
        "§9.11" in e and "command content" in e for e in report.errors
    )


def test_profiles_title_over_60_soft_warns():
    spec = _spec_with_profiles(
        [{"id": "plain.acme", "title": "T" * 61}]
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok  # soft warning only
    assert any("§9.11" in w and "title" in w for w in report.warnings)


def test_profiles_description_over_200_soft_warns():
    spec = _spec_with_profiles(
        [{"id": "plain.acme", "description": "D" * 201}]
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok  # soft warning only
    assert any("§9.11" in w and "description" in w for w in report.warnings)


def test_profiles_clean_rewrite_passes():
    spec = _spec_with_profiles(
        [
            {
                "id": "plain.acme",
                "title": "API Token",
                "description": "Authenticate using an API token from the Acme console.",
            }
        ]
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok, report.errors
    assert not any("§9.11" in w for w in report.warnings)


def test_profiles_empty_or_absent_passes():
    # Absent key.
    report_absent = validate(_valid_spec(), "acme", bundle=_bundle())
    assert not any("§9.11" in e for e in report_absent.errors)
    # Empty array.
    report_empty = validate(
        _spec_with_profiles([]), "acme", bundle=_bundle()
    )
    assert not any("§9.11" in e for e in report_empty.errors)


def test_profiles_description_null_passes_at_least_one_rule():
    spec = _spec_with_profiles([{"id": "plain.acme", "description": None}])
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok, report.errors
    assert not any("§9.11" in e for e in report.errors)
    assert not any("§9.11" in w for w in report.warnings)


def test_profiles_id_only_no_keys_hard_fails():
    spec = _spec_with_profiles([{"id": "plain.acme"}])
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.11" in e and "at least one" in e for e in report.errors)


def test_profiles_no_redundancy_hard_fail():
    spec = _spec_with_profiles(
        [{"id": "plain.acme", "title": "API Key", "description": "API Key"}]
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok, report.errors
    assert not any("§9.11" in e for e in report.errors)


# --------------------------------------------------------------------------- #
# §9.13 help_text boilerplate rejection (§8.3b)
# --------------------------------------------------------------------------- #
def _spec_with_conn_help(help_text):
    """Set the single connection view_group's help_text (string or None)."""
    spec = _valid_spec()
    spec["connection"]["view_groups"][0]["help_text"] = help_text
    return spec


def test_boilerplate_equals_label_hard_fails():
    # label is "Acme One"; normalized help_text equals it.
    spec = _spec_with_conn_help("Acme One")
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.13" in e and "restates" in e for e in report.errors)


def test_boilerplate_template_configuration_settings_for_x_hard_fails():
    spec = _spec_with_conn_help("Configuration settings for Acme One.")
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.13" in e and "template" in e for e in report.errors)


def test_boilerplate_template_settings_for_x_hard_fails():
    spec = _spec_with_conn_help("Settings for Acme One")
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.13" in e and "template" in e for e in report.errors)


def test_boilerplate_template_x_settings_hard_fails():
    spec = _spec_with_conn_help("Acme One settings")
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.13" in e and "template" in e for e in report.errors)


def test_boilerplate_template_connection_settings_for_x_hard_fails():
    spec = _spec_with_conn_help("Connection settings for Acme")
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.13" in e and "template" in e for e in report.errors)


def test_boilerplate_normalization_trailing_period_case_spaces():
    spec = _spec_with_conn_help("  CONFIGURATION  Settings  For  X .  ")
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.13" in e and "template" in e for e in report.errors)


def test_substantive_help_text_passes():
    spec = _spec_with_conn_help(
        "Generate an API key in the [Acme console](https://acme.example.com) "
        "and paste it into the settings field below."
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert not any("§9.13" in e for e in report.errors)


def test_help_text_null_passes_validator():
    spec = _spec_with_conn_help(None)
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok, report.errors
    assert not any("§9.13" in e for e in report.errors)


def test_connection_view_group_unknown_member_still_fails():
    spec = _valid_spec()
    spec["connection"]["view_groups"][0]["id"] = "ghost-vg"
    report = validate(spec, "acme", bundle=_bundle())
    assert any("§9.4" in e for e in report.errors)


# --------------------------------------------------------------------------- #
# §9.11c / §9.13 AUDIT of the FINAL on-disk state (P1)
#
# These audits inspect the connector's POST-APPLY effective state — the on-disk
# value OVERRIDDEN by any doc-spec authoring — INDEPENDENT of what the doc-spec
# touched. Migration-leftover jargon/boilerplate the author never addressed now
# HARD-fails.
# --------------------------------------------------------------------------- #
def _bundle_with_jargon_profile():
    """Base bundle but the on-disk plain.acme profile leaks (plain) jargon."""
    bundle = _bundle()
    member = bundle.members[0]
    member.profiles[0] = ProfileSource(
        id="plain.acme",
        type="plain",
        view_group="acme-one",
        view_group_label="Acme One",
        title="API Key",
        description="Authentication profile for Acme (plain).",
        integration_id="Acme One",
        commonfields_name="Acme One",
    )
    return bundle


def _bundle_with_config_help(help_text):
    """Base bundle with a configurations view_group carrying ``help_text``."""
    bundle = _bundle()
    bundle.config_view_groups = [
        ViewGroup(id="acme-one", label="Acme One", help_text=help_text)
    ]
    return bundle


def test_audit_on_disk_profile_jargon_hard_fails_when_unauthored():
    # On-disk profile leaks "(plain)"; the doc-spec does NOT address profiles.
    spec = _valid_spec()
    report = validate(spec, "acme", bundle=_bundle_with_jargon_profile())
    assert not report.ok
    assert any("§9.11c audit" in e and "plain.acme" in e for e in report.errors)


def test_audit_profile_jargon_passes_when_authored_clean():
    # On-disk leaks "(plain)" but the doc-spec rewrites it to clean copy.
    spec = _spec_with_profiles(
        [
            {
                "id": "plain.acme",
                "description": "Authenticate using an API token from the Acme console.",
            }
        ]
    )
    report = validate(spec, "acme", bundle=_bundle_with_jargon_profile())
    assert report.ok, report.errors
    assert not any("§9.11c audit" in e for e in report.errors)


def test_audit_profile_jargon_passes_when_on_disk_clean_and_unauthored():
    # On-disk profile copy is already clean; doc-spec does not address it.
    spec = _valid_spec()
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok, report.errors
    assert not any("§9.11c audit" in e for e in report.errors)


def test_profile_jargon_audit_passes_when_description_effectively_none():
    # On-disk leaks "(plain)" but the doc-spec NULLS the description -> effective
    # None -> §9.11c on-disk jargon audit PASSES (removal is a complete fix).
    spec = _spec_with_profiles([{"id": "plain.acme", "description": None}])
    report = validate(spec, "acme", bundle=_bundle_with_jargon_profile())
    assert report.ok, report.errors
    assert not any("§9.11c audit" in e for e in report.errors)


def test_profile_jargon_audit_passes_when_description_absent_on_disk():
    # api_key.acme has description None on disk and the doc-spec does not address
    # it -> effective None -> the audit's isinstance(str) guard skips it (PASS).
    spec = _valid_spec()
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok, report.errors
    assert not any(
        "§9.11c audit" in e and "api_key.acme" in e for e in report.errors
    )


def test_audit_on_disk_config_boilerplate_hard_fails_when_unauthored():
    # On-disk config view_group help_text is migration boilerplate; the doc-spec
    # omits the configurations view_group entirely (effective = on-disk value).
    spec = _valid_spec()
    bundle = _bundle_with_config_help("Configurations settings for Acme One.")
    report = validate(spec, "acme", bundle=bundle)
    assert not report.ok
    assert any(
        "§9.13 audit" in e and "configurations" in e and "acme-one" in e
        for e in report.errors
    )


def test_audit_config_boilerplate_passes_when_nulled():
    # Doc-spec sets the config view_group help_text to null -> effective None.
    spec = _valid_spec()
    spec["configurations"]["view_groups"] = [{"id": "acme-one", "label": "Acme One", "help_text": None}]
    bundle = _bundle_with_config_help("Configurations settings for Acme One.")
    report = validate(spec, "acme", bundle=bundle)
    assert report.ok, report.errors
    assert not any("§9.13 audit" in e for e in report.errors)


def test_audit_config_boilerplate_passes_when_replaced():
    # Doc-spec overwrites the boilerplate with substantive help_text.
    spec = _valid_spec()
    spec["configurations"]["view_groups"] = [
        {
            "id": "acme-one",
            "label": "Acme One",
            "help_text": "Set the maximum number of events to fetch per cycle and the first fetch window.",
        }
    ]
    bundle = _bundle_with_config_help("Configurations settings for Acme One.")
    report = validate(spec, "acme", bundle=bundle)
    assert report.ok, report.errors
    assert not any("§9.13 audit" in e for e in report.errors)


def test_audit_connection_boilerplate_hard_fails_when_unauthored():
    # On-disk CONNECTION view_group help_text is boilerplate; doc-spec omits the
    # view_group (effective = on-disk boilerplate value).
    spec = _valid_spec()
    spec["connection"]["view_groups"] = []  # author addresses nothing
    bundle = _bundle()
    bundle.view_groups = [
        ViewGroup(id="acme-one", label="Acme One", help_text="Connection settings for Acme One.")
    ]
    report = validate(spec, "acme", bundle=bundle)
    assert not report.ok
    assert any(
        "§9.13 audit" in e and "connection" in e and "acme-one" in e
        for e in report.errors
    )


def test_audit_uses_effective_value_doc_spec_overrides_on_disk():
    # Explicit precedence: on-disk help_text is CLEAN, but the doc-spec OVERWRITES
    # it with boilerplate -> the audit must fail on the EFFECTIVE (authored) value.
    spec = _valid_spec()
    spec["connection"]["view_groups"][0]["help_text"] = "Acme One settings"
    bundle = _bundle()  # on-disk help_text "placeholder" (clean)
    report = validate(spec, "acme", bundle=bundle)
    assert not report.ok
    # Either the authored-content check (§9.13 boilerplate) or the audit fires;
    # the effective-value audit must independently catch it.
    assert any("§9.13" in e and "acme-one" in e for e in report.errors)


# --------------------------------------------------------------------------- #
# §9.14 stray escaped bang (the literal two chars backslash + bang)
# --------------------------------------------------------------------------- #
def test_escaped_bang_in_help_text_fails():
    spec = _valid_spec()
    # The Python literal "\\!" is the two characters: backslash, bang.
    spec["connection"]["view_groups"][0]["help_text"] = (
        "Run the ***\\!acme-auth-start*** command."
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert not report.ok
    assert any("§9.14" in e for e in report.errors)


def test_escaped_bang_in_connector_description_fails():
    spec = _valid_spec()
    spec["connector"]["description"] = "Acme connector. Run \\!acme-auth-test to verify."
    report = validate(spec, "acme", bundle=_bundle())
    assert not report.ok
    assert any("§9.14" in e for e in report.errors)


def test_escaped_bang_in_profile_fields_fails():
    spec = _valid_spec()
    spec["connection"]["profiles"] = [
        {"id": "plain.acme", "description": "Use \\!acme-auth-start to begin."}
    ]
    report = validate(spec, "acme", bundle=_bundle())
    assert not report.ok
    assert any("§9.14" in e and "plain.acme" in e for e in report.errors)


def test_unescaped_bang_command_passes():
    # The legitimate form "!cmd" (bang, no backslash) must NOT trip §9.14.
    spec = _valid_spec()
    spec["connection"]["view_groups"][0]["help_text"] = (
        "Generate an API key in the [Acme console](https://acme.example.com). "
        "Then run ***!acme-auth-start*** and ***!acme-auth-complete***."
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok, report.errors
    assert not any("§9.14" in e for e in report.errors)


# --------------------------------------------------------------------------- #
# §9.15 command-token preservation
# --------------------------------------------------------------------------- #
def _bundle_with_source(src: str) -> "ConnectorBundle":
    b = _bundle()
    b.members[0].description_md = src
    b.members[0].description_md_len = len(src)
    return b


def test_dropped_source_command_in_authored_help_text_fails():
    src = (
        "Generate an API key in the [Acme console](https://acme.example.com).\n"
        "Run the ***!acme-auth-start*** command, then ***!acme-auth-complete***."
    )
    spec = _valid_spec()
    # Authored help_text keeps the link but GENERICIZES the commands.
    spec["connection"]["view_groups"][0]["help_text"] = (
        "Generate an API key in the [Acme console](https://acme.example.com). "
        "Run the authentication start command, then the complete command."
    )
    report = validate(spec, "acme", bundle=_bundle_with_source(src))
    assert not report.ok
    assert any("§9.15" in e and "acme-auth-start" in e for e in report.errors)
    assert any("§9.15" in e and "acme-auth-complete" in e for e in report.errors)


def test_preserved_source_command_passes():
    src = (
        "Generate an API key in the [Acme console](https://acme.example.com).\n"
        "Run the ***!acme-auth-start*** command."
    )
    spec = _valid_spec()
    spec["connection"]["view_groups"][0]["help_text"] = (
        "Generate an API key in the [Acme console](https://acme.example.com). "
        "Run the ***!acme-auth-start*** command."
    )
    report = validate(spec, "acme", bundle=_bundle_with_source(src))
    assert report.ok, report.errors
    assert not any("§9.15" in e for e in report.errors)


# --------------------------------------------------------------------------- #
# Cortex XSOAR is LEFT AS-IS (the §9.16 rename gate was intentionally removed)
# --------------------------------------------------------------------------- #
def test_cortex_xsoar_is_not_flagged():
    # 'Cortex XSOAR' must NOT be flagged anymore — the rename logic was removed.
    spec = _valid_spec()
    spec["connection"]["view_groups"][0]["help_text"] = (
        "Configure the app in Cortex XSOAR. "
        "Generate an API key in the [Acme console](https://acme.example.com)."
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok, report.errors
    assert not any("§9.16" in e for e in report.errors)


# --------------------------------------------------------------------------- #
# §9.17 incident -> issue terminology
# --------------------------------------------------------------------------- #
def test_incident_word_in_help_text_fails():
    spec = _valid_spec()
    spec["connection"]["view_groups"][0]["help_text"] = (
        "Configure fetch incidents. "
        "Generate an API key in the [Acme console](https://acme.example.com)."
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert not report.ok
    assert any("§9.17" in e for e in report.errors)


def test_incident_word_in_connector_description_fails():
    spec = _valid_spec()
    spec["connector"]["description"] = "Acme fetches incidents from the service."
    report = validate(spec, "acme", bundle=_bundle())
    assert not report.ok
    assert any("§9.17" in e for e in report.errors)


def test_incident_word_in_profile_description_fails():
    spec = _valid_spec()
    spec["connection"]["profiles"] = [
        {"id": "plain.acme", "description": "Used to fetch incidents."}
    ]
    report = validate(spec, "acme", bundle=_bundle())
    assert not report.ok
    assert any("§9.17" in e and "plain.acme" in e for e in report.errors)


def test_issue_word_passes():
    spec = _valid_spec()
    spec["connection"]["view_groups"][0]["help_text"] = (
        "Configure fetch issues. "
        "Generate an API key in the [Acme console](https://acme.example.com)."
    )
    report = validate(spec, "acme", bundle=_bundle())
    assert report.ok, report.errors
    assert not any("§9.17" in e for e in report.errors)
