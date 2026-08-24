import json

import pytest

import BlockDomain
from BlockDomain import (
    ACTION_CREATED,
    ACTION_MODIFIED,
    ACTION_UNCHANGED,
    OBJECT_NAME_PREFIX,
    MAX_OBJECT_NAME_LENGTH,
    RESULT_FAILED,
    RESULT_SUCCESS,
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_SKIPPED,
    PanOs,
    build_final_command_results,
    build_verbose_human_readable,
    derive_object_name,
    is_valid_fqdn,
    is_wildcard,
    most_significant_action,
    pan_os_push_status,
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


def test_derive_object_name_simple():
    """
    Given:
       - A short, standard FQDN.
    When:
       - Calling derive_object_name to compute the PAN-OS address-object name.
    Then:
       - Returns the domain prefixed with "Cortex-".
    """
    assert derive_object_name("evil.example.com") == "Cortex-evil.example.com"


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


def test_derive_object_name_sanitises_illegal_chars():
    """
    Given:
       - A domain containing an underscore, which is not a legal PAN-OS object-name character.
    When:
       - Calling derive_object_name.
    Then:
       - Underscores are normalised to hyphens so the resulting name is accepted by PAN-OS.
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
    assert name == derive_object_name(long_domain)


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
    assert wildcard_row["Action"] == ACTION_UNCHANGED
    assert "Wildcard" in wildcard_row["Message"]

    invalid_row = next(row for row in failed if row["Domain"] == "no-dot")
    assert invalid_row["Status"] == STATUS_FAILED
    assert invalid_row["Result"] == RESULT_FAILED
    assert "Invalid FQDN" in invalid_row["Message"]


def test_validate_domains_all_valid():
    """
    Given:
       - A list of domains that are all syntactically valid FQDNs.
    When:
       - Calling validate_domains.
    Then:
       - All entries end up in the valid list and no failed rows are produced.
    """
    valid, skipped = validate_domains(["a.com", "b.org"])
    assert valid == ["a.com", "b.org"]
    assert skipped == []


@pytest.mark.parametrize(
    "actions, expected",
    [
        ([], ACTION_UNCHANGED),
        ([ACTION_UNCHANGED, ACTION_UNCHANGED], ACTION_UNCHANGED),
        ([ACTION_UNCHANGED, ACTION_MODIFIED], ACTION_MODIFIED),
        ([ACTION_MODIFIED, ACTION_CREATED], ACTION_CREATED),
        ([ACTION_CREATED, ACTION_UNCHANGED], ACTION_CREATED),
    ],
)
def test_most_significant_action(actions, expected):
    """
    Given:
       - A list of per-step actions (Unchanged / Modified / Created).
    When:
       - Calling most_significant_action to summarise the whole flow into a single action.
    Then:
       - Returns Created > Modified > Unchanged in priority; empty list yields Unchanged.
    """
    assert most_significant_action(actions) == expected


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


def _mock_execute(monkeypatch, side_effect):
    """Patch BlockDomain.demisto.executeCommand to yield the given responses in order."""
    responses = iter(side_effect)
    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", lambda *a, **k: next(responses))


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
        [
            [ok_entry({"Panorama.AddressGroups": []})],
            [ok_entry({"Panorama.SecurityRule": []})],
            [err_entry("not found")],
            [ok_entry()],
            [ok_entry()],
            [ok_entry()],
            [ok_entry()],
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert len(rows) == 1
    assert rows[0]["Status"] == STATUS_DONE
    assert rows[0]["Result"] == RESULT_SUCCESS
    assert rows[0]["Action"] == ACTION_CREATED
    assert rows[0]["RuleName"] == "Cortex - Block Domain"


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
                            {"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": ["Cortex-evil.example.com"]}
                        ]
                    }
                )
            ],
            "pan-os-list-rules": [
                ok_entry(
                    {"Panorama.SecurityRule": [{"Name": "Cortex - Block Domain", "Destination": ["Blocked Domains - Cortex"]}]}
                )
            ],
            "pan-os-get-address": [ok_entry({"Panorama.Addresses": {"Name": "Cortex-evil.example.com"}})],
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
    assert result[0]["Action"] == ACTION_UNCHANGED
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
        BlockDomain.POLLING = False
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


def test_process_domains_captures_instance_name_from_response_metadata(monkeypatch):
    """
    Given:
       - A stream of PAN-OS responses where the first entry carries Metadata.instance
         (the platform stamps this on every execute_command result).
    When:
       - Calling process_domains.
    Then:
       - The class captures the serving-instance name on the first successful response and
         propagates it into every resulting row's Instance field.
    """
    _mock_execute(
        monkeypatch,
        [
            [ok_entry({"Panorama.AddressGroups": []}, instance="Panorama_QA")],
            [ok_entry({"Panorama.SecurityRule": []})],
            [err_entry("not found")],
            [ok_entry()],
            [ok_entry()],
            [ok_entry()],
            [ok_entry()],
        ],
    )
    pan_os = _pan_os(["evil.example.com"])
    rows = pan_os.process_domains()
    assert pan_os.instance_name == "Panorama_QA"
    assert len(rows) == 1
    assert rows[0]["Instance"] == "Panorama_QA"


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
    assert group_create_args["addresses"] == "Cortex-evil.example.com"
    rule_create_args = next(args for name, args in calls if name == "pan-os-create-rule")
    assert rule_create_args["destination"] == "Blocked Domains - Cortex"
    assert "pan-os-edit-address-group" not in names


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
    _mock_execute(
        monkeypatch,
        [
            [ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": [obj]}]})],
            [
                ok_entry(
                    {"Panorama.SecurityRule": [{"Name": "Cortex - Block Domain", "Destination": ["Blocked Domains - Cortex"]}]}
                )
            ],
            [ok_entry()],
            [ok_entry({"Panorama.Addresses": [{"Name": obj}]})],
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert rows[0]["Status"] == STATUS_DONE
    assert rows[0]["Action"] == ACTION_UNCHANGED


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
        [
            [ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": []}]})],
            [
                ok_entry(
                    {"Panorama.SecurityRule": [{"Name": "Cortex - Block Domain", "Destination": ["Blocked Domains - Cortex"]}]}
                )
            ],
            [ok_entry()],
            [err_entry("not found")],
            [ok_entry()],
            [ok_entry()],
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert rows[0]["Status"] == STATUS_DONE
    assert rows[0]["Action"] == ACTION_CREATED


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
        [
            [ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": [obj]}]})],
            [ok_entry({"Panorama.SecurityRule": [{"Name": "Cortex - Block Domain", "Destination": ["something-else"]}]})],
            [ok_entry()],
            [ok_entry()],
            [ok_entry({"Panorama.Addresses": [{"Name": obj}]})],
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert rows[0]["Status"] == STATUS_DONE
    assert rows[0]["Action"] == ACTION_UNCHANGED


def test_process_domains_dynamic_group_is_skipped(monkeypatch):
    """
    Given:
       - A tenant where the target group already exists but as a *dynamic* address group
         (which cannot accept manually added static members).
    When:
       - Calling process_domains.
    Then:
       - The row is marked Skipped / Success and the message explains the group is dynamic.
    """
    _mock_execute(
        monkeypatch,
        [
            [ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "dynamic", "Match": "x"}]})],
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert rows[0]["Status"] == STATUS_SKIPPED
    assert rows[0]["Result"] == RESULT_SUCCESS
    assert "dynamic" in rows[0]["Message"]


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
        [
            [ok_entry({"Panorama.AddressGroups": []})],
            [ok_entry({"Panorama.SecurityRule": []})],
            [err_entry("not found")],
            [err_entry("permission denied")],
        ],
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
            "Instance": "",
            "Status": STATUS_DONE,
            "Result": RESULT_SUCCESS,
            "Action": ACTION_CREATED,
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
            "Instance": "",
            "Status": STATUS_DONE,
            "Result": RESULT_SUCCESS,
            "Action": ACTION_CREATED,
            "RuleName": "Cortex - Block Domain",
            "Message": "ok",
        }
    ]
    responses = [[{"Type": 1, "Contents": "c", "HumanReadable": "HR-one", "EntryContext": {}}]]

    result = build_final_command_results(rows, verbose=True, responses=responses)
    assert result.outputs == rows
    assert "a.com" in result.readable_output
    assert result.readable_output.endswith("HR-one")


def test_pan_os_push_status_error_contents_is_terminal_failure(monkeypatch):
    """
    Given:
       - pan-os-push-status returns an error entry whose Contents is a plain string
         (PAN-OS surfaces errors as a bare string instead of the nested status dict).
    When:
       - Calling pan_os_push_status.
    Then:
       - The function does NOT crash with 'str object has no attribute get'; it stops polling
         (POLLING flipped to False) and reports a Failure status for the job.
    """
    monkeypatch.setattr(
        BlockDomain.demisto,
        "executeCommand",
        lambda *a, **k: [err_entry("Failed to execute pan-os-push-status. Error: job not found")],
    )

    # The @polling_function decorator unwraps the PollResult and returns its CommandResults response
    # at runtime, though the declared return type is still PollResult (hence the type: ignore below).
    result = pan_os_push_status({"push_job_id": "123"}, [])

    assert BlockDomain.POLLING is False
    assert result.outputs == {"JobID": "123", "Status": "Failure"}  # type: ignore[attr-defined]


def test_pan_os_push_status_fin_stops_polling(monkeypatch):
    """
    Given:
       - pan-os-push-status returns a well-formed nested dict whose job status is 'FIN'.
    When:
       - Calling pan_os_push_status.
    Then:
       - Polling stops (POLLING flipped to False) and the reported job status is 'FIN'.
    """
    fin_entry = {
        "Type": 1,
        "Contents": {"response": {"result": {"job": {"status": "FIN"}}}},
        "HumanReadable": "",
        "EntryContext": {},
    }
    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", lambda *a, **k: [fin_entry])

    result = pan_os_push_status({"push_job_id": "456"}, [])

    assert BlockDomain.POLLING is False
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
            "Instance": "Panorama_QA",
            "Status": STATUS_DONE,
            "Result": RESULT_SUCCESS,
            "Action": ACTION_CREATED,
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
