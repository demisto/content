import json

import pytest

import BlockDomain
from BlockDomain import (
    OBJECT_NAME_PREFIX,
    MAX_OBJECT_NAME_LENGTH,
    RESULT_FAILED,
    RESULT_SUCCESS,
    STATUS_DONE,
    STATUS_FAILED,
    PanOs,
    build_final_command_results,
    build_verbose_human_readable,
    derive_object_name,
    is_valid_fqdn,
    is_wildcard,
    normalize_tags,
    pan_os_push_status,
    run_execute_command,
    validate_domains,
)


def ok_entry(entry_context=None, contents="ok", instance=None, brand="Panorama"):
    """Build a minimal successful execute_command entry.

    When ``instance`` is provided, includes a ``Metadata`` block matching what the platform
    actually returns (``Metadata.instance`` / ``Metadata.brand``) so tests can assert that the
    aggregate script correctly captures the serving-instance name from response entries.
    """
    entry: dict = {"Type": 1, "Contents": contents, "HumanReadable": "", "EntryContext": entry_context or {}}
    if instance is not None:
        entry["Metadata"] = {"instance": instance, "brand": brand}
    return entry


def err_entry(contents="error"):
    """Build a minimal error execute_command entry (Type 4 == entryTypes['error'])."""
    return {"Type": 4, "Contents": contents, "HumanReadable": "", "EntryContext": {}}


def test_run_execute_command_returns_entries(monkeypatch):
    """
    Given:
       - executeCommand returns a non-empty list of entries.
    When:
       - Calling run_execute_command.
    Then:
       - The entries are returned unchanged.
    """
    entries = [ok_entry()]
    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", lambda *a, **k: entries)

    assert run_execute_command("pan-os-get-address", {"name": "x"}) == entries


@pytest.mark.parametrize("empty_response", [[], None])
def test_run_execute_command_raises_on_empty_response(monkeypatch, empty_response):
    """
    Given:
       - executeCommand returns an empty response (empty list or None).
    When:
       - Calling run_execute_command.
    Then:
       - A DemistoException is raised instead of letting downstream res[0] indexing crash.
    """
    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", lambda *a, **k: empty_response)

    with pytest.raises(BlockDomain.DemistoException, match="returned an empty response"):
        run_execute_command("pan-os-get-address", {"name": "x"})


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("*.evil.com", True),
        ("evil.*.com", True),
        ("evil.example.com", False),
        ("sub.domain.co.uk", False),
    ],
)
def test_is_wildcard(domain, expected):
    """
    Given:
       - A domain string that may or may not contain a wildcard character.
    When:
       - Calling is_wildcard to detect wildcard patterns.
    Then:
       - Returns True for domains containing '*', False otherwise.
    """
    assert is_wildcard(domain) is expected


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("evil.example.com", True),
        ("sub.domain.co.uk", True),
        ("a.b", True),
        ("no-dot", False),
        ("*.evil.com", False),
        ("-leading.example.com", False),
        ("trailing-.example.com", False),
        ("space in.example.com", False),
        ("", False),
    ],
)
def test_is_valid_fqdn(domain, expected):
    """
    Given:
       - A domain string that may or may not be a syntactically valid FQDN.
    When:
       - Calling is_valid_fqdn to validate the domain.
    Then:
       - Returns True for well-formed FQDNs (has dot, valid labels, no wildcard/illegal chars),
         and False for anything else including empty strings and wildcards.
    """
    assert is_valid_fqdn(domain) is expected


def test_derive_object_name_is_deterministic():
    """
    Given:
       - The same FQDN passed to derive_object_name twice.
    When:
       - Comparing the two returned object names.
    Then:
       - Both invocations return the exact same string (deterministic mapping).
    """
    assert derive_object_name("evil.example.com") == derive_object_name("evil.example.com")


def test_derive_object_name_illegal_chars():
    """
    Given:
       - A domain containing an underscore, which is not a legal PAN-OS object-name character.
    When:
       - Calling derive_object_name.
    Then:
       - Underscores are normalized to hyphens so the resulting name is accepted by PAN-OS.
    """
    assert derive_object_name("bad_domain.example.com") == "Cortex-bad-domain.example.com"


def test_derive_object_name_overflow_truncates_and_hashes():
    """
    Given:
       - A domain long enough that the naive prefixed name would exceed the PAN-OS
         MAX_OBJECT_NAME_LENGTH limit.
    When:
       - Calling derive_object_name.
    Then:
       - The returned name fits within MAX_OBJECT_NAME_LENGTH, still starts with the
         "Cortex-" prefix, and remains deterministic across calls.
    """
    long_domain = ("a" * 80) + ".example.com"
    name = derive_object_name(long_domain)
    assert len(name) <= MAX_OBJECT_NAME_LENGTH
    assert name.startswith(OBJECT_NAME_PREFIX)


def test_derive_object_name_overflow_distinct_domains_are_unique():
    """
    Given:
       - Two DIFFERENT over-length domains.
    When:
       - Deriving each object name (both take the truncate+hash overflow path).
    Then:
       - The two names are different, proving the hash suffix disambiguates over-length names
         (the digest is a function of the full domain, not the truncated body).
    """
    name_a = derive_object_name(("a" * 80) + ".example.com")
    name_b = derive_object_name(("b" * 80) + ".example.com")
    assert name_a != name_b


def test_derive_object_name_overflow_same_prefix_different_tail_are_unique():
    """
    Given:
       - Two over-length domains that share an identical long leading segment (so their
         truncated bodies are the same) but differ only in a tail beyond the truncation point.
    When:
       - Deriving each object name.
    Then:
       - The names are STILL unique - the digest is computed over the full original domain, so
         differences past the truncation boundary are preserved in the hash suffix. This is the
         key anti-collision guarantee for the prefix-hash naming scheme.
    """
    shared_head = "a" * 80
    name_a = derive_object_name(f"{shared_head}.first-tail.example.com")
    name_b = derive_object_name(f"{shared_head}.second-tail.example.com")
    assert name_a != name_b
    # Both are truncated to the same length budget, so equal length; only the digest differs.
    assert len(name_a) == len(name_b)


def test_validate_domains_splits_valid_and_failed():
    """
    Given:
       - A mixed list of domains containing valid FQDNs, a wildcard, and an invalid FQDN.
    When:
       - Calling validate_domains to partition the input.
    Then:
       - Valid FQDNs are returned in the first list; the wildcard and invalid entries are
         returned as failed rows with STATUS_FAILED / RESULT_FAILED and appropriate messages.
    """
    valid, failed = validate_domains(["evil.example.com", "*.evil.com", "no-dot", "phish.attacker.net"])

    assert valid == ["evil.example.com", "phish.attacker.net"]
    assert len(failed) == 2

    wildcard_row = next(row for row in failed if row["Domain"] == "*.evil.com")
    assert wildcard_row["Status"] == STATUS_FAILED
    assert wildcard_row["Result"] == RESULT_FAILED
    assert "Wildcard" in wildcard_row["Message"]
    # No brand/rule applies to a validation-failed row - these must be real null, not "".
    assert wildcard_row["Brand"] is None
    assert wildcard_row["RuleName"] is None

    invalid_row = next(row for row in failed if row["Domain"] == "no-dot")
    assert invalid_row["Status"] == STATUS_FAILED
    assert invalid_row["Result"] == RESULT_FAILED
    assert "Invalid FQDN" in invalid_row["Message"]


def _pan_os(domains):
    return PanOs(
        {
            "domain_list": domains,
            "rule_name": "Cortex - Block Domain",
            "address_group": "Blocked Domains - Cortex",
            "tag": "cortex-blocked-domains",
            "log_forwarding_name": "",
            "auto_commit": True,
        }
    )


def _mock_execute(monkeypatch, responses_by_command):
    """Patch BlockDomain.demisto.executeCommand to answer per command name (order-independent).

    ``responses_by_command`` maps a command name to the entry list it should return. Probe commands
    (pan-os-get-address / -list-address-groups / -list-rules) supply the tenant state; write commands
    default to a bare success entry when not specified. ``pan-os-create-tag`` is always auto-answered.

    Args:
        monkeypatch: The pytest monkeypatch fixture.
        responses_by_command (dict): Mapping of command name -> entry list to return.
    Returns:
        The ``calls`` list of (command_name, args) tuples recorded during the run.
    """
    calls: list = []

    def _dispatch(command_name, args=None, *a, **k):
        calls.append((command_name, args or {}))
        if command_name == "pan-os-create-tag":
            return [ok_entry()]
        return responses_by_command.get(command_name, [ok_entry()])

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _dispatch)
    return calls


def test_process_domains_create_everything(monkeypatch):
    """
    Given:
       - A tenant where neither the address group nor the security rule exist yet, and the
         address object for the domain also does not exist.
    When:
       - Calling process_domains for a single domain.
    Then:
       - The address is created first, then the group is seeded with that object, then the
         rule is created against the now-existing group, then the rule is moved to the top.
         The resulting row is Done / Success / Created and carries the expected rule name.
    """
    _mock_execute(
        monkeypatch,
        {
            "pan-os-get-address": [err_entry("not found")],
            "pan-os-list-address-groups": [ok_entry({"Panorama.AddressGroups": []})],
            "pan-os-list-rules": [ok_entry({"Panorama.SecurityRule": []})],
        },
    )
    pan = _pan_os(["evil.example.com"])
    rows = pan.process_domains()
    assert len(rows) == 1
    assert rows[0]["Status"] == STATUS_DONE
    assert rows[0]["Result"] == RESULT_SUCCESS
    assert rows[0]["RuleName"] == "Cortex - Block Domain"
    # Action is no longer surfaced; change-detection is tracked internally to gate the commit.
    assert pan._address_made_changes is True
    assert "Action" not in rows[0]


def test_ensure_tag_creates_tag_up_front(monkeypatch):
    """
    Given:
       - A PanOs flow configured with a tag.
    When:
       - Calling ensure_tag.
    Then:
       - pan-os-create-tag is invoked exactly once with the configured tag name, so the tag exists
         before any group/rule references it (independent of whether an address object is created).
    """
    calls: list = []

    def _capture(name, args):
        calls.append((name, args))
        return [ok_entry()]

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _capture)

    _pan_os(["evil.example.com"]).ensure_tag()

    assert calls == [("pan-os-create-tag", {"name": "cortex-blocked-domains"})]


def test_ensure_tag_tolerates_already_exists_error(monkeypatch):
    """
    Given:
       - pan-os-create-tag returns an error (the tag already exists on the device).
    When:
       - Calling ensure_tag.
    Then:
       - ensure_tag does NOT raise - an already-existing tag is an expected, benign outcome.
    """

    def _err(name, args):
        return [err_entry("tag already exists")]

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _err)

    # Must not raise.
    _pan_os(["evil.example.com"]).ensure_tag()


def test_ensure_tag_noop_when_no_tag(monkeypatch):
    """
    Given:
       - A PanOs flow with an empty tag.
    When:
       - Calling ensure_tag.
    Then:
       - No pan-os-create-tag call is made (nothing to create).
    """
    calls: list = []

    def _capture(name, args):
        calls.append(name)
        return [ok_entry()]

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _capture)

    pan = _pan_os(["evil.example.com"])
    pan.tag = ""
    pan.ensure_tag()

    assert calls == []


# ---- tag helpers (pure) ------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        (None, []),
        ("", []),
        ("solo", ["solo"]),
        (["a", "b"], ["a", "b"]),
        (["a", "", None, "b"], ["a", "b"]),
    ],
)
def test_normalize_tags(raw, expected):
    """
    Given:
       - A raw PAN-OS 'Tags' value that may be None, an empty string, a single string, or a list
         possibly containing falsy entries.
    When:
       - Calling normalize_tags.
    Then:
       - It flattens the value into a clean list of tag-name strings, dropping falsy entries.
    """
    assert normalize_tags(raw) == expected


@pytest.mark.parametrize(
    "existing, expected",
    [
        ([], ["cortex-blocked-domains"]),
        (["other"], ["other", "cortex-blocked-domains"]),
        (["cortex-blocked-domains"], None),
        (["other", "cortex-blocked-domains"], None),
    ],
)
def test_merged_tags_if_missing(existing, expected):
    """
    Given:
       - An entity's current tag list and a PanOs flow configured with 'cortex-blocked-domains'.
    When:
       - Calling merged_tags_if_missing.
    Then:
       - Returns the de-duplicated union (existing + configured tag) when the tag is absent, and
         None (no edit needed) when the tag is already present. The existing tag is never duplicated.
    """
    assert _pan_os(["evil.example.com"]).merged_tags_if_missing(existing) == expected


def test_start_flow_skips_commit_when_all_actions_unchanged(monkeypatch):
    """
    Given:
       - A tenant already fully configured for the requested domain (group exists, rule exists,
         address object already a member) so every row is Unchanged.
    When:
       - Calling start_flow.
    Then:
       - pan_os_commit is never invoked; start_flow returns the Unchanged rows directly
         (skipping the multi-minute commit + push polling cycle on Panorama).
    """
    calls: list = []

    def _capture(name, args):
        calls.append((name, args))
        seq = {
            "pan-os-list-address-groups": [
                ok_entry(
                    {
                        "Panorama.AddressGroups": [
                            {
                                "Name": "Blocked Domains - Cortex",
                                "Type": "static",
                                "Addresses": ["Cortex-evil.example.com"],
                                "Tags": ["cortex-blocked-domains"],
                            }
                        ]
                    }
                )
            ],
            "pan-os-list-rules": [
                ok_entry(
                    {
                        "Panorama.SecurityRule": [
                            {
                                "Name": "Cortex - Block Domain",
                                "Destination": ["Blocked Domains - Cortex"],
                                "Tags": ["cortex-blocked-domains"],
                            }
                        ]
                    }
                )
            ],
            "pan-os-get-address": [
                ok_entry({"Panorama.Addresses": {"Name": "Cortex-evil.example.com", "Tags": ["cortex-blocked-domains"]}})
            ],
            "pan-os-move-rule": [ok_entry()],
        }
        return seq.get(name, [ok_entry()])

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _capture)
    monkeypatch.setattr(
        BlockDomain, "pan_os_commit", lambda *a, **k: pytest.fail("pan_os_commit must not be called when all rows are Unchanged")
    )
    monkeypatch.setattr(BlockDomain.demisto, "setContext", lambda *a, **k: None)

    result = _pan_os(["evil.example.com"]).start_flow()

    assert isinstance(result, list)
    assert len(result) == 1
    assert "Action" not in result[0]
    assert "pan-os-commit" not in [c[0] for c in calls]


def test_start_flow_commits_when_at_least_one_row_modified(monkeypatch):
    """
    Given:
       - A tenant where the group and rule already exist but the address object for the
         requested domain is missing, so at least one row will end up Created.
    When:
       - Calling start_flow.
    Then:
       - pan_os_commit is invoked (candidate config was modified and must be pushed).
    """
    commit_called: list = []

    def _fake_commit(args, responses):
        commit_called.append(True)
        return BlockDomain.CommandResults(readable_output="fake commit ok")

    def _capture(name, args):
        seq = {
            "pan-os-list-address-groups": [
                ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": []}]})
            ],
            "pan-os-list-rules": [
                ok_entry(
                    {"Panorama.SecurityRule": [{"Name": "Cortex - Block Domain", "Destination": ["Blocked Domains - Cortex"]}]}
                )
            ],
            "pan-os-get-address": [err_entry("not found")],
            "pan-os-create-address": [ok_entry()],
            "pan-os-edit-address-group": [ok_entry()],
            "pan-os-move-rule": [ok_entry()],
        }
        return seq.get(name, [ok_entry()])

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _capture)
    monkeypatch.setattr(BlockDomain.demisto, "setContext", lambda *a, **k: None)
    monkeypatch.setattr(BlockDomain, "pan_os_commit", _fake_commit)
    monkeypatch.setattr(BlockDomain.demisto, "context", lambda: {"block_domain_rows": "[]"})

    _pan_os(["evil.example.com"]).start_flow()

    assert commit_called, "pan_os_commit must be called when at least one row is Created/Modified"


def test_process_domains_rule_created_when_object_unchanged_sets_rule_changed(monkeypatch):
    """
    Given:
       - The address object and group already exist and the object is already a member (so the
         per-domain Action is Unchanged), but the requested rule_name does NOT exist yet, so a
         new rule must be created.
    When:
       - Calling process_domains.
    Then:
       - The row Action is Unchanged (object/membership did not change), but the instance's
         _rule_changed flag is set True because pan-os-create-rule ran. This is what lets
         start_flow still commit a rule-only change.
    """
    obj = "Cortex-evil.example.com"

    def _capture(name, args):
        seq = {
            # Group exists, already contains the object, and already carries the tag -> Unchanged.
            "pan-os-list-address-groups": [
                ok_entry(
                    {
                        "Panorama.AddressGroups": [
                            {
                                "Name": "Blocked Domains - Cortex",
                                "Type": "static",
                                "Addresses": [obj],
                                "Tags": ["cortex-blocked-domains"],
                            }
                        ]
                    }
                )
            ],
            # No rule with the requested name exists -> ensure_rule will create it.
            "pan-os-list-rules": [ok_entry({"Panorama.SecurityRule": []})],
            # Object exists and already carries the tag -> no object tag edit.
            "pan-os-get-address": [ok_entry({"Panorama.Addresses": [{"Name": obj, "Tags": ["cortex-blocked-domains"]}]})],
            "pan-os-create-rule": [ok_entry()],
            "pan-os-move-rule": [ok_entry()],
        }
        return seq.get(name, [ok_entry()])

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _capture)

    pan_os = _pan_os(["evil.example.com"])
    rows = pan_os.process_domains()

    # Object + membership did not change (so _made_changes stays False), but the rule was created,
    # so _rule_changed is True - that alone must still trigger a commit in start_flow.
    assert "Action" not in rows[0]
    assert pan_os._address_made_changes is False
    assert pan_os._rule_changed is True


def test_start_flow_commits_when_only_the_rule_changed(monkeypatch):
    """
    Given:
       - Every address object is already present and a member (all rows Unchanged), but a new
         rule had to be created this run (rule-only change).
    When:
       - Calling start_flow.
    Then:
       - pan_os_commit is still invoked, so the newly created rule is actually committed/pushed
         instead of silently sitting in the candidate config.
    """
    obj = "Cortex-evil.example.com"
    commit_called: list = []

    def _fake_commit(args, responses):
        commit_called.append(True)
        return BlockDomain.CommandResults(readable_output="fake commit ok")

    def _capture(name, args):
        seq = {
            "pan-os-list-address-groups": [
                ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": [obj]}]})
            ],
            "pan-os-list-rules": [ok_entry({"Panorama.SecurityRule": []})],
            "pan-os-get-address": [ok_entry({"Panorama.Addresses": [{"Name": obj}]})],
            "pan-os-create-rule": [ok_entry()],
            "pan-os-move-rule": [ok_entry()],
        }
        return seq.get(name, [ok_entry()])

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _capture)
    monkeypatch.setattr(BlockDomain.demisto, "setContext", lambda *a, **k: None)
    monkeypatch.setattr(BlockDomain, "pan_os_commit", _fake_commit)
    monkeypatch.setattr(BlockDomain.demisto, "context", lambda: {"block_domain_rows": "[]"})

    _pan_os(["evil.example.com"]).start_flow()

    assert commit_called, "pan_os_commit must be called when only the rule changed (all objects Unchanged)"


def test_process_domains_missing_group_created_lazily_with_first_object(monkeypatch):
    """
    Given:
       - A tenant with neither group nor rule pre-configured, and no address object for the
         requested domain. PAN-OS refuses to create a static group with no members, and
         refuses to create a rule whose destination does not resolve to an existing object.
    When:
       - Calling process_domains for a single domain.
    Then:
       - The address is created first; then the group is created lazily seeded with that
         first object (never as an empty static group); then the rule is created against the
         now-existing group. No edit-address-group call is emitted for the seed domain.
    """
    calls: list = []

    def _capture(name, args):
        calls.append((name, args))
        seq = {
            "pan-os-list-address-groups": [ok_entry({"Panorama.AddressGroups": []})],
            "pan-os-list-rules": [ok_entry({"Panorama.SecurityRule": []})],
            "pan-os-create-rule": [ok_entry()],
            "pan-os-move-rule": [ok_entry()],
            "pan-os-get-address": [err_entry("not found")],
            "pan-os-create-address": [ok_entry()],
            "pan-os-create-address-group": [ok_entry()],
        }
        return seq.get(name, [ok_entry()])

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _capture)

    _pan_os(["evil.example.com"]).process_domains()

    names = [c[0] for c in calls]
    assert names.index("pan-os-create-address") < names.index("pan-os-create-address-group")
    assert names.index("pan-os-create-address-group") < names.index("pan-os-create-rule")
    group_create_args = next(args for name, args in calls if name == "pan-os-create-address-group")
    assert group_create_args["type"] == "static"
    # The group is created once with the full member list (all objects created first).
    assert group_create_args["addresses"] == ["Cortex-evil.example.com"]
    rule_create_args = next(args for name, args in calls if name == "pan-os-create-rule")
    assert rule_create_args["destination"] == "Blocked Domains - Cortex"
    assert "pan-os-edit-address-group" not in names


def test_process_domains_multi_domain_creates_all_objects_before_group(monkeypatch):
    """
    Given:
       - A tenant with no group, no rule, and neither address object existing, for TWO domains.
    When:
       - Calling process_domains for both domains.
    Then:
       - Both address objects are created BEFORE the single group-create, and the group is created
         once with the full member list (this is the ordering that avoids the reference error).
    """
    calls = _mock_execute(
        monkeypatch,
        {
            "pan-os-get-address": [err_entry("not found")],
            "pan-os-list-address-groups": [ok_entry({"Panorama.AddressGroups": []})],
            "pan-os-list-rules": [ok_entry({"Panorama.SecurityRule": []})],
        },
    )
    _pan_os(["evil.example.com", "phish.attacker.net"]).process_domains()

    names = [name for name, _ in calls]
    create_addresses = [i for i, name in enumerate(names) if name == "pan-os-create-address"]
    group_create_index = names.index("pan-os-create-address-group")
    # Both objects are created before the single group-create.
    assert len(create_addresses) == 2
    assert max(create_addresses) < group_create_index
    assert names.count("pan-os-create-address-group") == 1
    group_args = next(args for name, args in calls if name == "pan-os-create-address-group")
    assert group_args["addresses"] == ["Cortex-evil.example.com", "Cortex-phish.attacker.net"]


def test_process_domains_all_unchanged(monkeypatch):
    """
    Given:
       - A tenant where the group, rule, and address object all already exist and the
         address object is already a member of the group.
    When:
       - Calling process_domains.
    Then:
       - The resulting row is Done / Unchanged (no create/modify happened).
    """
    obj = "Cortex-evil.example.com"
    calls = _mock_execute(
        monkeypatch,
        {
            "pan-os-get-address": [ok_entry({"Panorama.Addresses": [{"Name": obj, "Tags": ["cortex-blocked-domains"]}]})],
            "pan-os-list-address-groups": [
                ok_entry(
                    {
                        "Panorama.AddressGroups": [
                            {
                                "Name": "Blocked Domains - Cortex",
                                "Type": "static",
                                "Addresses": [obj],
                                "Tags": ["cortex-blocked-domains"],
                            }
                        ]
                    }
                )
            ],
            "pan-os-list-rules": [
                ok_entry(
                    {
                        "Panorama.SecurityRule": [
                            {
                                "Name": "Cortex - Block Domain",
                                "Destination": ["Blocked Domains - Cortex"],
                                "Tags": ["cortex-blocked-domains"],
                            }
                        ]
                    }
                )
            ],
        },
    )
    pan = _pan_os(["evil.example.com"])
    rows = pan.process_domains()
    assert rows[0]["Status"] == STATUS_DONE
    # Everything already in place (incl. the tag) -> no change -> commit will be skipped.
    assert pan._address_made_changes is False
    assert pan._rule_changed is False
    assert "Action" not in rows[0]
    # A pre-existing, unchanged rule must NOT be moved (no needless candidate-config churn).
    assert not any(name == "pan-os-move-rule" for name, _ in calls)


def test_process_domains_modified_when_added_to_existing_group(monkeypatch):
    """
    Given:
       - A tenant where the group and rule already exist but the group has no members yet
         and the address object for the requested domain does not exist.
    When:
       - Calling process_domains.
    Then:
       - The address is created and added to the existing group; the resulting row is
         Done / Created (most-significant action of the create-address step).
    """
    _mock_execute(
        monkeypatch,
        {
            "pan-os-get-address": [err_entry("not found")],
            "pan-os-list-address-groups": [
                ok_entry(
                    {
                        "Panorama.AddressGroups": [
                            {
                                "Name": "Blocked Domains - Cortex",
                                "Type": "static",
                                "Addresses": [],
                                "Tags": ["cortex-blocked-domains"],
                            }
                        ]
                    }
                )
            ],
            "pan-os-list-rules": [
                ok_entry(
                    {
                        "Panorama.SecurityRule": [
                            {
                                "Name": "Cortex - Block Domain",
                                "Destination": ["Blocked Domains - Cortex"],
                                "Tags": ["cortex-blocked-domains"],
                            }
                        ]
                    }
                )
            ],
        },
    )
    pan = _pan_os(["evil.example.com"])
    rows = pan.process_domains()
    assert rows[0]["Status"] == STATUS_DONE
    # A new object was created and added to the group -> a change occurred -> commit will run.
    assert pan._address_made_changes is True
    assert "Action" not in rows[0]


def test_process_domains_existing_rule_missing_group_is_edited(monkeypatch):
    """
    Given:
       - A tenant where the rule exists but its destination does not yet reference our
         address group; the group and the address object already exist.
    When:
       - Calling process_domains.
    Then:
       - The rule is edited to include the group in its destination; the resulting row is
         Done / Unchanged because the address object and its group membership were unchanged
         (rule-level fix is a group-scope, not per-domain, mutation).
    """
    obj = "Cortex-evil.example.com"
    _mock_execute(
        monkeypatch,
        {
            "pan-os-get-address": [ok_entry({"Panorama.Addresses": [{"Name": obj, "Tags": ["cortex-blocked-domains"]}]})],
            "pan-os-list-address-groups": [
                ok_entry(
                    {
                        "Panorama.AddressGroups": [
                            {
                                "Name": "Blocked Domains - Cortex",
                                "Type": "static",
                                "Addresses": [obj],
                                "Tags": ["cortex-blocked-domains"],
                            }
                        ]
                    }
                )
            ],
            "pan-os-list-rules": [
                ok_entry(
                    {
                        "Panorama.SecurityRule": [
                            {
                                "Name": "Cortex - Block Domain",
                                "Destination": ["something-else"],
                                "Tags": ["cortex-blocked-domains"],
                            }
                        ]
                    }
                )
            ],
        },
    )
    pan = _pan_os(["evil.example.com"])
    rows = pan.process_domains()
    assert rows[0]["Status"] == STATUS_DONE
    # Object + membership unchanged, but the rule was edited to add the group -> _rule_changed.
    assert pan._address_made_changes is False
    assert pan._rule_changed is True
    assert "Action" not in rows[0]


def _tag_capture(monkeypatch):
    """Patch executeCommand with a dict-based capture that tolerates call ordering.

    Returns the ``calls`` list of (command_name, args) tuples. Read/probe commands return
    fixtures that model an already-existing object/group/rule WITHOUT the configured tag, so the
    merge/edit paths are exercised. Every other command returns a bare success entry.
    """
    obj = "Cortex-evil.example.com"
    calls: list = []
    fixtures = {
        "pan-os-list-address-groups": [
            ok_entry(
                {
                    "Panorama.AddressGroups": [
                        {"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": [obj], "Tags": ["other"]}
                    ]
                }
            )
        ],
        "pan-os-list-rules": [
            ok_entry(
                {
                    "Panorama.SecurityRule": [
                        {"Name": "Cortex - Block Domain", "Destination": ["Blocked Domains - Cortex"], "Tags": ["other"]}
                    ]
                }
            )
        ],
        "pan-os-get-address": [ok_entry({"Panorama.Addresses": [{"Name": obj, "Tags": ["other"]}]})],
    }

    def _capture(name, args):
        calls.append((name, args))
        return fixtures.get(name, [ok_entry()])

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _capture)
    return calls


def test_process_domains_merges_tag_on_existing_object_group_and_rule(monkeypatch):
    """
    Given:
       - A tenant where the address object, address group, and rule all already exist, each
         carrying a different pre-existing tag ('other') but NOT the configured tag.
    When:
       - Calling process_domains with tag='cortex-blocked-domains'.
    Then:
       - The configured tag is merged (never replacing) onto all three entities:
         * pan-os-edit-address with element_to_change=tag and the merged list ['other', tag]
         * pan-os-edit-address-group with tags=['other', tag]
         * pan-os-edit-rule with element_to_change=tag, behaviour=add, element_value=tag
    """
    calls = _tag_capture(monkeypatch)
    pan = _pan_os(["evil.example.com"])
    rows = pan.process_domains()

    assert rows[0]["Status"] == STATUS_DONE

    edit_address = [args for name, args in calls if name == "pan-os-edit-address"]
    assert edit_address == [
        {
            "name": "Cortex-evil.example.com",
            "element_to_change": "tag",
            "element_value": ["other", "cortex-blocked-domains"],
        }
    ]

    # The group edit carries element_to_add (required by the static-group guard) together with the
    # merged tags in one call. The object is already a member, so the full list is re-added (no-op).
    edit_group = [args for name, args in calls if name == "pan-os-edit-address-group" and "tags" in args]
    assert edit_group == [
        {
            "name": "Blocked Domains - Cortex",
            "type": "static",
            "element_to_add": ["Cortex-evil.example.com"],
            "tags": ["other", "cortex-blocked-domains"],
        }
    ]

    edit_rule_tag = [args for name, args in calls if name == "pan-os-edit-rule" and args.get("element_to_change") == "tag"]
    assert edit_rule_tag == [
        {
            "rulename": "Cortex - Block Domain",
            "element_to_change": "tag",
            "element_value": "cortex-blocked-domains",
            "behaviour": "add",
            "pre_post": "pre-rulebase",
        }
    ]


def test_process_domains_does_not_re_tag_when_tag_already_present(monkeypatch):
    """
    Given:
       - The demo scenario: an existing FQDN, an existing group, and an existing rule that ALL
         already carry the configured tag; the user re-runs the command.
    When:
       - Calling process_domains with the same tag.
    Then:
       - No tag edit is issued on the object, group, or rule (the tag is never duplicated), and
         nothing changes so the commit is skipped.
    """
    obj = "Cortex-evil.example.com"
    tag = "cortex-blocked-domains"
    calls: list = []
    fixtures = {
        "pan-os-list-address-groups": [
            ok_entry(
                {
                    "Panorama.AddressGroups": [
                        {"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": [obj], "Tags": [tag]}
                    ]
                }
            )
        ],
        "pan-os-list-rules": [
            ok_entry(
                {
                    "Panorama.SecurityRule": [
                        {"Name": "Cortex - Block Domain", "Destination": ["Blocked Domains - Cortex"], "Tags": [tag]}
                    ]
                }
            )
        ],
        "pan-os-get-address": [ok_entry({"Panorama.Addresses": [{"Name": obj, "Tags": [tag]}]})],
    }

    def _capture(name, args):
        calls.append((name, args))
        return fixtures.get(name, [ok_entry()])

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _capture)

    pan = _pan_os(["evil.example.com"])
    pan.process_domains()

    assert [args for name, args in calls if name == "pan-os-edit-address"] == []
    assert [args for name, args in calls if name == "pan-os-edit-address-group" and "tags" in args] == []
    assert [args for name, args in calls if name == "pan-os-edit-rule" and args.get("element_to_change") == "tag"] == []
    assert pan._address_made_changes is False
    assert pan._rule_changed is False


def test_process_domains_new_rule_name_does_not_re_tag_existing_object_and_group(monkeypatch):
    """
    Given:
       - An existing FQDN and existing group that ALREADY carry the configured tag, but a brand-new
         rule name that does not exist yet (the "just add a rule" case).
    When:
       - Calling process_domains.
    Then:
       - The object and group are NOT re-tagged (no duplication); only the new rule is created
         (which carries the tag at creation time via its own create args).
    """
    obj = "Cortex-evil.example.com"
    tag = "cortex-blocked-domains"
    calls: list = []
    fixtures = {
        "pan-os-list-address-groups": [
            ok_entry(
                {
                    "Panorama.AddressGroups": [
                        {"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": [obj], "Tags": [tag]}
                    ]
                }
            )
        ],
        # Rule does not exist yet -> it will be created (with the tag in its create args).
        "pan-os-list-rules": [ok_entry({"Panorama.SecurityRule": []})],
        "pan-os-get-address": [ok_entry({"Panorama.Addresses": [{"Name": obj, "Tags": [tag]}]})],
    }

    def _capture(name, args):
        calls.append((name, args))
        return fixtures.get(name, [ok_entry()])

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _capture)

    pan = _pan_os(["evil.example.com"])
    pan.process_domains()

    # Object and group already carry the tag -> no re-tag edits.
    assert [args for name, args in calls if name == "pan-os-edit-address"] == []
    assert [args for name, args in calls if name == "pan-os-edit-address-group" and "tags" in args] == []
    # The new rule is created and carries the tag at creation.
    create_rule = [args for name, args in calls if name == "pan-os-create-rule"]
    assert len(create_rule) == 1
    assert create_rule[0]["tags"] == tag
    assert pan._rule_changed is True


def _pan_os_with_log_forwarding(domains, profile):
    """Build a PanOs flow configured with a log-forwarding profile name (rule-only)."""
    pan = _pan_os(domains)
    pan.log_forwarding_name = profile
    return pan


def _lf_capture(monkeypatch, existing_profile):
    """Patch executeCommand modelling an existing object/group/rule (everything already in place).

    The existing rule carries ``existing_profile`` as its LogForwardingProfile. Returns the
    ``calls`` list of (command_name, args) tuples. Tags are pre-present so no tag edits fire.
    """
    obj = "Cortex-evil.example.com"
    tag = "cortex-blocked-domains"
    calls: list = []
    fixtures = {
        "pan-os-list-address-groups": [
            ok_entry(
                {
                    "Panorama.AddressGroups": [
                        {"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": [obj], "Tags": [tag]}
                    ]
                }
            )
        ],
        "pan-os-list-rules": [
            ok_entry(
                {
                    "Panorama.SecurityRule": [
                        {
                            "Name": "Cortex - Block Domain",
                            "Destination": ["Blocked Domains - Cortex"],
                            "Tags": [tag],
                            "LogForwardingProfile": existing_profile,
                        }
                    ]
                }
            )
        ],
        "pan-os-get-address": [ok_entry({"Panorama.Addresses": [{"Name": obj, "Tags": [tag]}]})],
    }

    def _capture(name, args):
        calls.append((name, args))
        return fixtures.get(name, [ok_entry()])

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _capture)
    return calls


def test_process_domains_sets_log_forwarding_on_existing_rule_when_absent(monkeypatch):
    """
    Given:
       - An existing rule with NO log-forwarding profile, and a flow configured with one.
    When:
       - Calling process_domains.
    Then:
       - pan-os-edit-rule is issued with element_to_change=log-forwarding and the configured
         profile, and _rule_changed is set.
    """
    calls = _lf_capture(monkeypatch, existing_profile="")
    pan = _pan_os_with_log_forwarding(["evil.example.com"], "cortex-lfp")
    pan.process_domains()

    edit_lf = [args for name, args in calls if name == "pan-os-edit-rule" and args.get("element_to_change") == "log-forwarding"]
    assert edit_lf == [
        {
            "rulename": "Cortex - Block Domain",
            "element_to_change": "log-forwarding",
            "element_value": "cortex-lfp",
            "pre_post": "pre-rulebase",
        }
    ]
    assert pan._rule_changed is True


def test_process_domains_sets_log_forwarding_on_existing_rule_when_different(monkeypatch):
    """
    Given:
       - An existing rule whose log-forwarding profile differs from the configured one.
    When:
       - Calling process_domains.
    Then:
       - pan-os-edit-rule replaces it with the configured profile (single-value, no dedup concept).
    """
    calls = _lf_capture(monkeypatch, existing_profile="old-lfp")
    pan = _pan_os_with_log_forwarding(["evil.example.com"], "cortex-lfp")
    pan.process_domains()

    edit_lf = [args for name, args in calls if name == "pan-os-edit-rule" and args.get("element_to_change") == "log-forwarding"]
    assert len(edit_lf) == 1
    assert edit_lf[0]["element_value"] == "cortex-lfp"
    assert pan._rule_changed is True


def test_process_domains_does_not_set_log_forwarding_when_already_matches(monkeypatch):
    """
    Given:
       - An existing rule that ALREADY carries the configured log-forwarding profile.
    When:
       - Calling process_domains.
    Then:
       - No log-forwarding edit is issued (no unnecessary edit), and since nothing else changed
         the rule is left untouched.
    """
    calls = _lf_capture(monkeypatch, existing_profile="cortex-lfp")
    pan = _pan_os_with_log_forwarding(["evil.example.com"], "cortex-lfp")
    pan.process_domains()

    edit_lf = [args for name, args in calls if name == "pan-os-edit-rule" and args.get("element_to_change") == "log-forwarding"]
    assert edit_lf == []
    assert pan._rule_changed is False


def test_process_domains_dynamic_group_is_failed(monkeypatch):
    """
    Given:
       - A tenant where the target group already exists but as a *dynamic* address group
         (which cannot accept manually added static members).
    When:
       - Calling process_domains.
    Then:
       - The domain could not be blocked, so the row is marked Failed / Failed and the message
         explains the group is dynamic.
    """
    _mock_execute(
        monkeypatch,
        {
            "pan-os-get-address": [err_entry("not found")],
            "pan-os-list-address-groups": [
                ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "dynamic", "Match": "x"}]})
            ],
        },
    )
    # Capture the abort log so it does not leak to stdout (conftest fails on any stdout).
    errors: list = []
    monkeypatch.setattr(BlockDomain.demisto, "error", lambda msg: errors.append(msg))

    rows = _pan_os(["evil.example.com"]).process_domains()
    assert rows[0]["Status"] == STATUS_FAILED
    assert rows[0]["Result"] == RESULT_FAILED
    assert "dynamic" in rows[0]["Message"]
    # The aborted domains are logged for troubleshooting.
    assert any("evil.example.com" in msg for msg in errors)


def test_process_domains_moves_rule_to_top_when_rule_created(monkeypatch):
    """
    Given:
       - A tenant where neither the rule nor the address object exist yet, so the rule is created.
    When:
       - Calling process_domains.
    Then:
       - pan-os-move-rule is issued to enforce top placement for the newly created rule.
    """
    calls = _mock_execute(
        monkeypatch,
        {
            "pan-os-get-address": [err_entry("not found")],
            "pan-os-list-address-groups": [
                ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": []}]})
            ],
            "pan-os-list-rules": [ok_entry({"Panorama.SecurityRule": []})],
        },
    )
    pan = _pan_os(["evil.example.com"])
    pan.process_domains()
    assert pan._rule_changed is True
    assert any(name == "pan-os-move-rule" for name, _ in calls)


def test_process_domains_failure_marks_row_failed(monkeypatch):
    """
    Given:
       - A tenant where the group and rule do not exist yet, and the pan-os-create-address
         command fails (e.g. permission denied) before the group and rule are touched.
    When:
       - Calling process_domains.
    Then:
       - The resulting row is Failed / Failed and the error message from PAN-OS is surfaced,
         and the full traceback is logged via demisto.error.
    """
    _mock_execute(
        monkeypatch,
        {
            "pan-os-get-address": [err_entry("not found")],
            "pan-os-create-address": [err_entry("permission denied")],
            "pan-os-list-address-groups": [ok_entry({"Panorama.AddressGroups": []})],
            "pan-os-list-rules": [ok_entry({"Panorama.SecurityRule": []})],
        },
    )
    # Capture the traceback log so it does not leak to stdout (conftest fails on any stdout).
    errors: list = []
    monkeypatch.setattr(BlockDomain.demisto, "error", lambda msg: errors.append(msg))

    rows = _pan_os(["evil.example.com"]).process_domains()
    assert rows[0]["Status"] == STATUS_FAILED
    assert rows[0]["Result"] == RESULT_FAILED
    assert "permission denied" in rows[0]["Message"]
    assert any("process_domains failed" in msg for msg in errors)


def test_build_verbose_human_readable_joins_with_blank_lines():
    """
    Given:
       - A list of response entries where some carry a HumanReadable string and some do not.
    When:
       - Calling build_verbose_human_readable.
    Then:
       - Entries without HumanReadable are skipped; the rest are joined with a blank line
         separator, prefixed by a leading blank line so the block detaches from the summary
         table above it.
    """
    responses = [
        [ok_entry(contents="c1")],
        [{"Type": 1, "Contents": "c2", "HumanReadable": "HR-two", "EntryContext": {}}],
        [{"Type": 1, "Contents": "c3", "HumanReadable": "HR-three", "EntryContext": {}}],
    ]
    verbose_hr = build_verbose_human_readable(responses)
    assert verbose_hr == "\n\nHR-two\n\nHR-three"


def test_build_verbose_human_readable_empty_when_no_hr():
    """
    Given:
       - A response list where no entry has a HumanReadable string, or an empty list.
    When:
       - Calling build_verbose_human_readable.
    Then:
       - Returns an empty string (nothing to append to the summary table).
    """
    assert build_verbose_human_readable([[ok_entry(contents="c1")]]) == ""
    assert build_verbose_human_readable([]) == ""


def test_build_final_command_results_non_verbose_is_table_only():
    """
    Given:
       - A rows list and a set of responses that include HumanReadable content, with
         verbose=False.
    When:
       - Calling build_final_command_results.
    Then:
       - The returned CommandResults uses the BlockDomain context prefix, exposes the
         rows unchanged as outputs, renders the summary table containing the domain, and does
         NOT append any of the per-command verbose HR blocks.
    """
    rows = [
        {
            "Domain": "a.com",
            "Brand": "Panorama",
            "Status": STATUS_DONE,
            "Result": RESULT_SUCCESS,
            "RuleName": "Cortex - Block Domain",
            "Message": "ok",
        }
    ]
    responses = [[{"Type": 1, "Contents": "c", "HumanReadable": "HR", "EntryContext": {}}]]

    result = build_final_command_results(rows, verbose=False, responses=responses)
    assert result.outputs_prefix == "BlockDomain"
    assert result.outputs == rows
    assert "a.com" in result.readable_output
    assert "HR" not in result.readable_output


def test_build_final_command_results_verbose_appends_command_hr():
    """
    Given:
       - A rows list and responses with a HumanReadable block, with verbose=True.
    When:
       - Calling build_final_command_results.
    Then:
       - The returned CommandResults exposes the rows as outputs, renders the summary table
         containing the domain, and appends the per-command HR block at the end of the
         readable_output (so users can see exactly what each downstream call produced).
    """
    rows = [
        {
            "Domain": "a.com",
            "Brand": "Panorama",
            "Status": STATUS_DONE,
            "Result": RESULT_SUCCESS,
            "RuleName": "Cortex - Block Domain",
            "Message": "ok",
        }
    ]
    responses = [[{"Type": 1, "Contents": "c", "HumanReadable": "HR-one", "EntryContext": {}}]]

    result = build_final_command_results(rows, verbose=True, responses=responses)
    assert result.outputs == rows
    assert "a.com" in result.readable_output
    assert result.readable_output.endswith("HR-one")


def test_build_final_command_results_all_failed_is_error_entry():
    """
    Given:
       - A rows list where every row has Result == Failed.
    When:
       - Calling build_final_command_results.
    Then:
       - The returned CommandResults is marked as an ERROR entry, still exposes the rows as
         outputs, and its readable_output carries the "All runs failed" header so the war room
         and any downstream playbook can branch on the failure.
    """
    rows = [
        {
            "Domain": "a.com",
            "Brand": "Panorama",
            "Status": STATUS_FAILED,
            "Result": RESULT_FAILED,
            "RuleName": "",
            "Message": "boom",
        },
        {
            "Domain": "b.com",
            "Brand": "Panorama",
            "Status": STATUS_FAILED,
            "Result": RESULT_FAILED,
            "RuleName": "",
            "Message": "boom",
        },
    ]

    result = build_final_command_results(rows, verbose=False, responses=[])
    assert result.entry_type == BlockDomain.EntryType.ERROR
    assert result.outputs == rows
    assert "All runs failed" in result.readable_output


def test_build_final_command_results_partial_failure_is_not_error_entry():
    """
    Given:
       - A rows list with at least one successful row alongside a failed row.
    When:
       - Calling build_final_command_results.
    Then:
       - The returned CommandResults is NOT an ERROR entry (entry_type is unset / not ERROR),
         so a partial success is still reported as a normal result.
    """
    rows = [
        {
            "Domain": "a.com",
            "Brand": "Panorama",
            "Status": STATUS_DONE,
            "Result": RESULT_SUCCESS,
            "RuleName": "Cortex - Block Domain",
            "Message": "ok",
        },
        {
            "Domain": "b.com",
            "Brand": "Panorama",
            "Status": STATUS_FAILED,
            "Result": RESULT_FAILED,
            "RuleName": "",
            "Message": "boom",
        },
    ]

    result = build_final_command_results(rows, verbose=False, responses=[])
    assert result.entry_type != BlockDomain.EntryType.ERROR
    assert "All runs failed" not in result.readable_output


def test_build_final_command_results_empty_rows_is_not_error_entry():
    """
    Given:
       - An empty rows list (e.g. no domains reached a vendor).
    When:
       - Calling build_final_command_results.
    Then:
       - The run is NOT reported as an error (an empty run is not an all-failed run).
    """
    result = build_final_command_results([], verbose=False, responses=[])
    assert result.entry_type != BlockDomain.EntryType.ERROR
    assert "All runs failed" not in result.readable_output


def test_pan_os_push_status_error_contents_is_terminal_failure(monkeypatch):
    """
    Given:
       - pan-os-push-status returns an error entry whose Contents is a plain string
         (PAN-OS surfaces errors as a bare string instead of the nested status dict).
    When:
       - Calling pan_os_push_status.
    Then:
       - The function does NOT crash with 'str object has no attribute get'; it stops polling
         (no ScheduledCommand attached) and reports a Failure status for the job.
    """
    monkeypatch.setattr(
        BlockDomain.demisto,
        "executeCommand",
        lambda *a, **k: [err_entry("Failed to execute pan-os-push-status. Error: job not found")],
    )

    # The @polling_function decorator unwraps the PollResult and returns its CommandResults response
    # at runtime, though the declared return type is still PollResult (hence the type: ignore below).
    result = pan_os_push_status({"push_job_id": "123"}, [])

    assert not BlockDomain.is_polling_in_progress(result)
    assert result.outputs == {"JobID": "123", "Status": "Failure"}  # type: ignore[attr-defined]


def test_pan_os_push_status_fin_stops_polling(monkeypatch):
    """
    Given:
       - pan-os-push-status returns a well-formed nested dict whose job status is 'FIN'.
    When:
       - Calling pan_os_push_status.
    Then:
       - Polling stops (no ScheduledCommand attached) and the reported job status is 'FIN'.
    """
    fin_entry = {
        "Type": 1,
        "Contents": {"response": {"result": {"job": {"status": "FIN"}}}},
        "HumanReadable": "",
        "EntryContext": {},
    }
    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", lambda *a, **k: [fin_entry])

    result = pan_os_push_status({"push_job_id": "456"}, [])

    assert not BlockDomain.is_polling_in_progress(result)
    assert result.outputs == {"Status": "FIN", "JobID": "456"}  # type: ignore[attr-defined]


def _install_fake_context(monkeypatch):
    """Back demisto.context()/setContext() with an in-memory dict, mirroring platform behavior.

    Returns the backing store so tests can inspect exactly what was serialized to context.
    """
    store: dict = {}
    monkeypatch.setattr(BlockDomain.demisto, "context", lambda: dict(store))
    monkeypatch.setattr(BlockDomain.demisto, "setContext", lambda key, value: store.__setitem__(key, value))
    return store


def test_save_and_restore_responses_json_round_trip(monkeypatch):
    """
    Given:
       - A PanOs instance whose accumulated responses contain the realistic PAN-OS entry shape
         (nested Contents dict, Metadata, None HumanReadable) written to context as JSON.
    When:
       - Calling save_responses on one polling cycle and restore_responses on the next.
    Then:
       - The context value is valid JSON (not a Python repr), and the responses survive the
         json.dumps -> json.loads round-trip byte-for-byte equal to the reduced form.
    """
    store = _install_fake_context(monkeypatch)

    pan_os = _pan_os(["evil.example.com"])
    pan_os.responses = [
        [
            {
                "Type": 1,
                "Contents": {"response": {"result": {"job": {"status": "FIN", "id": "42"}}}},
                "HumanReadable": None,
                "Metadata": {"instance": "Panorama_QA", "brand": "Panorama"},
                "EntryContext": {"dropped": "not serialized"},
            }
        ]
    ]
    expected_reduced = pan_os.reduce_responses()

    pan_os.save_responses()

    # Stored value must be real JSON that json.loads can parse (would fail on a Python repr).
    stored = store["panorama_responses"]
    assert json.loads(stored) == expected_reduced

    # A fresh instance restoring from the same context recovers the reduced responses exactly.
    fresh = _pan_os(["evil.example.com"])
    fresh.restore_responses()
    assert fresh.responses == expected_reduced


def test_finish_reads_rows_and_responses_as_json_then_clears_context(monkeypatch):
    """
    Given:
       - Context holds block_domain_rows and panorama_responses that were written as JSON by a
         previous polling cycle.
    When:
       - Calling finish().
    Then:
       - The rows are parsed back from JSON and returned; the accumulated responses are restored
         onto the instance for verbose output; and all polling context keys are cleared.
    """
    store = _install_fake_context(monkeypatch)

    rows = [
        {
            "Domain": "evil.example.com",
            "Brand": "Panorama",
            "Status": STATUS_DONE,
            "Result": RESULT_SUCCESS,
            "RuleName": "Cortex - Block Domain",
            "Message": "ok",
        }
    ]
    responses = [[{"HumanReadable": "HR", "Contents": "ok", "Type": 1, "Metadata": None}]]
    store["block_domain_rows"] = json.dumps(rows)
    store["panorama_responses"] = json.dumps(responses)
    store["commit_job_id"] = "999"

    pan_os = _pan_os(["evil.example.com"])
    result = pan_os.finish()

    assert result == rows
    assert pan_os.responses == responses
    # All polling context keys are cleared on finish.
    assert store["commit_job_id"] == ""
    assert store["push_job_id"] == ""
    assert store["panorama_responses"] == ""
    assert store["block_domain_rows"] == ""


def test_finish_tolerates_corrupt_context_data(monkeypatch):
    """
    Given:
       - Context holds a non-JSON (corrupt) block_domain_rows value.
    When:
       - Calling finish().
    Then:
       - finish() does not raise; it degrades to an empty list and still clears context.
    """
    store = _install_fake_context(monkeypatch)
    store["block_domain_rows"] = "{not valid json"
    store["panorama_responses"] = "also not json"

    pan_os = _pan_os(["evil.example.com"])
    result = pan_os.finish()

    assert result == []
    assert store["block_domain_rows"] == ""
