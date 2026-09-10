import json
import os

import pytest

import demistomock as demisto
from BlockUrl import BlockUrlError, PanOs

TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data")


def util_load_json(path):
    with open(os.path.join(TEST_DATA_DIR, path), encoding="utf-8") as f:
        return json.loads(f.read())


RESPONSES = util_load_json("pan_os_responses.json")


def build_pan_os(**overrides) -> PanOs:
    """Build a PanOs instance with the script defaults, overridden as the test needs."""
    args = {
        "url_entries": [{"URL": "http://new.example.com", "SubmittedURL": "new.example.com"}],
        "rule_name": "Cortex - Block URLs",
        "url_category": "Blocked URLs - Cortex",
        "url_filtering_profile": "Cortex - Block URL profile",
        "log_forwarding_name": "",
        "tag": "cortex-blocked-urls",
        "auto_commit": True,
        "verbose": False,
        "incident_id": "1",
    }
    args.update(overrides)
    pan_os = PanOs(args)
    pan_os.is_panorama = overrides.pop("is_panorama", True)
    pan_os.device_group = overrides.pop("device_group", "Test-Device-Group")
    return pan_os


def executed_commands(mock) -> list[tuple[str, dict]]:
    """The (command name, args) pairs that were executed, in order."""
    return [(call.args[0], call.args[1]) for call in mock.call_args_list]


def successful_flow_responses() -> list:
    """The responses of a full start_pan_os_flow run on a Panorama holding none of the objects yet."""
    return [
        RESPONSES["system_info_panorama"],
        RESPONSES["object_not_found"],
        RESPONSES["category_created"],
        RESPONSES["object_not_found"],
        RESPONSES["url_filter_created"],
        RESPONSES["tag_created"],
        RESPONSES["list_rules_empty"],
        RESPONSES["rule_created"],
        RESPONSES["profile_applied"],
        RESPONSES["rule_moved"],
    ]


""" URL NORMALIZATION """


@pytest.mark.parametrize(
    "raw_url, expected",
    [
        ("http://example.com", "example.com"),
        ("https://example.com", "example.com"),
        ("HTTPS://Example.COM", "example.com"),
        ("example.com/", "example.com"),
        ("https://example.com/", "example.com"),
        ("UPPER.example.com/Some/Path", "upper.example.com/Some/Path"),
        ("  example.com  ", "example.com"),
        ("example.com/some/path", "example.com/some/path"),
        ("a" * 240 + ".example.com", "a" * 240 + ".example.com"),
    ],
)
def test_normalize_url_accepts(raw_url, expected):
    """
    Given:
       - A URL with a scheme, a trailing slash, mixed case or surrounding whitespace.
    When:
       - Normalizing it before submitting it to PAN-OS.
    Then:
       - The scheme and the trailing slash are stripped, the host is lowercased, the path keeps its
         case, and no rejection message is returned.
    """
    from BlockUrl import normalize_url

    submitted_url, rejection_message = normalize_url(raw_url)
    assert submitted_url == expected
    assert rejection_message == ""


@pytest.mark.parametrize(
    "raw_url, expected_message_part",
    [
        ("", "empty"),
        ("   ", "empty"),
        ("*.example.com", "Wildcards are not supported"),
        ("https://*.example.com", "Wildcards are not supported"),
        ("a" * 256 + ".example.com", "exceeds 255 chars"),
        ("example.com,other.example.com", "comma"),
        ("example .com", "whitespace"),
        ("ftp://example.com", "scheme is not supported"),
    ],
)
def test_normalize_url_rejects(raw_url, expected_message_part):
    """
    Given:
       - A URL that PAN-OS would store verbatim and then silently fail to match.
    When:
       - Normalizing it before submitting it to PAN-OS.
    Then:
       - The URL is rejected with an explanatory message, and the submitted URL stays empty.
    """
    from BlockUrl import normalize_url

    submitted_url, rejection_message = normalize_url(raw_url)
    assert submitted_url == ""
    assert expected_message_part in rejection_message


def test_normalize_url_length_measured_after_scheme_strip():
    """
    Given:
       - A URL that exceeds 255 characters only while it still carries its scheme.
    When:
       - Normalizing it.
    Then:
       - It is accepted, since PAN-OS enforces the limit on the stored, scheme-less value.
    """
    from BlockUrl import normalize_url

    raw_url = "https://" + "a" * 250 + ".com"
    submitted_url, rejection_message = normalize_url(raw_url)
    assert rejection_message == ""
    assert len(submitted_url) == 254


def test_partition_urls_mixed():
    """
    Given:
       - A mix of valid URLs and URLs that must never reach a brand.
    When:
       - Partitioning the requested URL list.
    Then:
       - The valid URLs are accepted with their normalized form, the invalid ones are returned as
         failures with an empty SubmittedURL, and the input order is preserved.
    """
    from BlockUrl import partition_urls

    accepted, rejected = partition_urls(["https://good.example.com", "*.bad.example.com", "second.example.com"])

    assert accepted == [
        {"URL": "https://good.example.com", "SubmittedURL": "good.example.com"},
        {"URL": "second.example.com", "SubmittedURL": "second.example.com"},
    ]
    assert len(rejected) == 1
    assert rejected[0]["URL"] == "*.bad.example.com"
    assert rejected[0]["SubmittedURL"] == ""
    assert rejected[0]["Result"] == "Failed"


""" #TEXT NORMALIZATION """


@pytest.mark.parametrize(
    "value, expected",
    [
        ("URL List", "URL List"),
        ({"#text": "URL List", "@dirtyId": "1074", "@admin": "test-admin"}, "URL List"),
        (None, ""),
        ({}, ""),
    ],
)
def test_text_normalizer(value, expected):
    """
    Given:
       - A PAN-OS field that is a plain string when committed and a '#text' dict when dirty.
    When:
       - Normalizing it before a comparison.
    Then:
       - The plain string value is returned for both shapes.
    """
    from BlockUrl import _text

    assert _text(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (["a.example.com", "b.example.com"], ["a.example.com", "b.example.com"]),
        ([{"#text": "a.example.com", "@dirtyId": "1"}], ["a.example.com"]),
        ("single.example.com", ["single.example.com"]),
        ({"#text": "single.example.com", "@dirtyId": "1"}, ["single.example.com"]),
        (None, []),
    ],
)
def test_text_list_normalizer(value, expected):
    """
    Given:
       - A PAN-OS Sites field holding zero, one or many members, committed or dirty.
    When:
       - Normalizing it into a list of plain strings.
    Then:
       - Every shape yields the same flat list of strings.
    """
    from BlockUrl import _text_list

    assert _text_list(value) == expected


""" CUSTOM URL CATEGORY """


def test_get_custom_url_category_missing(mocker):
    """
    Given:
       - A custom URL category that does not exist on PAN-OS.
    When:
       - Reading it before deciding whether to create or edit it.
    Then:
       - The 'Object not present' error is treated as missing rather than as a failure.
    """
    mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["object_not_found"])

    assert build_pan_os().get_custom_url_category() == {}


def test_get_custom_url_category_real_error_raises(mocker):
    """
    Given:
       - A custom URL category read that fails for a reason other than the object being absent.
    When:
       - Reading it.
    Then:
       - The failure is surfaced instead of being mistaken for a missing object.
    """
    error_response = [{"Type": 4, "Contents": "Request Failed.\nInvalid credentials.", "EntryContext": {}}]
    mocker.patch.object(demisto, "executeCommand", return_value=error_response)

    with pytest.raises(BlockUrlError, match="Invalid credentials"):
        build_pan_os().get_custom_url_category()


def test_ensure_url_category_creates_when_missing(mocker):
    """
    Given:
       - No existing custom URL category.
    When:
       - Ensuring the category holds the requested URLs.
    Then:
       - The category is created as a 'URL List' with the requested sites.
    """
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["category_created"])

    already_present = build_pan_os().ensure_url_category({}, ["new.example.com"])

    assert already_present == []
    command_name, command_args = executed_commands(execute_mock)[0]
    assert command_name == "pan-os-create-custom-url-category"
    assert command_args["type"] == "URL List"
    assert command_args["sites"] == ["new.example.com"]


@pytest.mark.parametrize("fixture_name", ["category_committed", "category_dirty"])
def test_ensure_url_category_appends_missing_sites_only(mocker, fixture_name):
    """
    Given:
       - An existing 'URL List' category, in both the committed and the dirty response shapes.
    When:
       - Ensuring it holds a mix of URLs it already has and URLs it does not.
    Then:
       - Only the missing URLs are appended, and the URLs already present are reported back.
    """
    existing = RESPONSES[fixture_name][0]["EntryContext"]["Panorama.CustomURLCategory(val.Name == obj.Name)"]
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["category_edited"])

    already_present = build_pan_os().ensure_url_category(existing, ["already.example.com", "new.example.com"])

    assert already_present == ["already.example.com"]
    command_name, command_args = executed_commands(execute_mock)[0]
    assert command_name == "pan-os-edit-custom-url-category"
    assert command_args["action"] == "add"
    assert command_args["sites"] == ["new.example.com"]


@pytest.mark.parametrize("fixture_name", ["category_committed", "category_dirty"])
def test_ensure_url_category_skips_when_all_present(mocker, fixture_name):
    """
    Given:
       - An existing category that already holds every requested URL, committed or dirty.
    When:
       - Ensuring it holds those URLs.
    Then:
       - No write command is issued, which also avoids the dirty-object edit failure.
    """
    existing = RESPONSES[fixture_name][0]["EntryContext"]["Panorama.CustomURLCategory(val.Name == obj.Name)"]
    execute_mock = mocker.patch.object(demisto, "executeCommand")

    already_present = build_pan_os().ensure_url_category(existing, ["already.example.com", "second.example.com"])

    assert already_present == ["already.example.com", "second.example.com"]
    execute_mock.assert_not_called()


def test_ensure_url_category_aborts_on_foreign_type(mocker):
    """
    Given:
       - An existing category of type 'Category Match', which PAN-OS would silently convert into a
         'URL List' and corrupt if it were edited.
    When:
       - Ensuring it holds the requested URLs.
    Then:
       - The flow aborts with a clear message and no write command is issued.
    """
    existing = RESPONSES["category_foreign_type"][0]["EntryContext"]["Panorama.CustomURLCategory(val.Name == obj.Name)"]
    execute_mock = mocker.patch.object(demisto, "executeCommand")

    with pytest.raises(BlockUrlError, match="Won't modify a user-managed category"):
        build_pan_os().ensure_url_category(existing, ["new.example.com"])

    execute_mock.assert_not_called()


def test_ensure_url_category_dirty_object_error_is_actionable(mocker):
    """
    Given:
       - A category edit that PAN-OS rejects because the object has uncommitted changes.
    When:
       - Appending the missing URLs.
    Then:
       - The raw integration error is replaced with an actionable "commit and re-run" message.
    """
    existing = RESPONSES["category_committed"][0]["EntryContext"]["Panorama.CustomURLCategory(val.Name == obj.Name)"]
    mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["dirty_object_error"])

    with pytest.raises(BlockUrlError, match="Commit the pending changes on PAN-OS and re-run"):
        build_pan_os().ensure_url_category(existing, ["new.example.com"])


""" URL FILTERING PROFILE """


def test_ensure_url_filtering_profile_creates_when_missing(mocker):
    """
    Given:
       - No existing URL filtering profile.
    When:
       - Ensuring the profile blocks the custom URL category.
    Then:
       - The profile is created with action=block for that category.
    """
    execute_mock = mocker.patch.object(
        demisto, "executeCommand", side_effect=[RESPONSES["object_not_found"], RESPONSES["url_filter_created"]]
    )

    build_pan_os().ensure_url_filtering_profile()

    commands = executed_commands(execute_mock)
    assert [name for name, _ in commands] == ["pan-os-get-url-filter", "pan-os-create-url-filter"]
    assert commands[1][1]["action"] == "block"
    assert commands[1][1]["url_category"] == "Blocked URLs - Cortex"


def test_ensure_url_filtering_profile_edits_existing(mocker):
    """
    Given:
       - An existing profile that does not block the category yet, in the dirty response shape.
    When:
       - Ensuring the profile blocks the category.
    Then:
       - The category is added to the block list of the existing profile.
    """
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[RESPONSES["url_filter_dirty_other_category"], RESPONSES["url_filter_edited"]],
    )

    build_pan_os().ensure_url_filtering_profile()

    commands = executed_commands(execute_mock)
    assert [name for name, _ in commands] == ["pan-os-get-url-filter", "pan-os-edit-url-filter"]
    assert commands[1][1]["element_to_change"] == "block_categories"
    assert commands[1][1]["add_remove_element"] == "add"


def test_ensure_url_filtering_profile_skips_when_category_attached(mocker):
    """
    Given:
       - An existing profile that already blocks the category.
    When:
       - Ensuring the profile blocks the category.
    Then:
       - No edit command is issued, which also avoids the dirty-object edit failure.
    """
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["url_filter_committed"])

    build_pan_os().ensure_url_filtering_profile()

    assert [name for name, _ in executed_commands(execute_mock)] == ["pan-os-get-url-filter"]


""" TAG AND SECURITY RULE """


def test_ensure_tag_created_before_rule(mocker):
    """
    Given:
       - A full PAN-OS configuration flow that creates a security rule referencing a tag.
    When:
       - Running start_pan_os_flow, which is where the real step ordering is decided.
    Then:
       - The tag is created before the rule, since PAN-OS rejects a rule that references an unknown
         tag with "tag '<name>' is not a valid reference".
    """
    execute_mock = mocker.patch.object(demisto, "executeCommand", side_effect=successful_flow_responses())

    build_pan_os().start_pan_os_flow()

    command_names = [name for name, _ in executed_commands(execute_mock)]
    assert command_names.index("pan-os-create-tag") < command_names.index("pan-os-create-rule")


def test_start_pan_os_flow_step_order(mocker):
    """
    Given:
       - A PAN-OS instance with none of the objects the script manages.
    When:
       - Running the configuration part of the flow.
    Then:
       - The steps run in the only order PAN-OS accepts: the topology is detected first, the category
         is created before the profile that blocks it, and the tag exists before the rule that
         references it.
    """
    execute_mock = mocker.patch.object(demisto, "executeCommand", side_effect=successful_flow_responses())

    build_pan_os().start_pan_os_flow()

    assert [name for name, _ in executed_commands(execute_mock)] == [
        "pan-os",
        "pan-os-get-custom-url-category",
        "pan-os-create-custom-url-category",
        "pan-os-get-url-filter",
        "pan-os-create-url-filter",
        "pan-os-create-tag",
        "pan-os-list-rules",
        "pan-os-create-rule",
        "pan-os-apply-security-profile",
        "pan-os-move-rule",
    ]


def test_start_pan_os_flow_reports_failure_reason(mocker):
    """
    Given:
       - A flow that writes the category and the profile and then fails on the security rule.
    When:
       - The BlockUrlError aborts the flow before the commit.
    Then:
       - The PAN-OS failure reason is captured on the failure message. No rollback is done.
    """
    mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            RESPONSES["system_info_panorama"],
            RESPONSES["object_not_found"],
            RESPONSES["category_created"],
            RESPONSES["object_not_found"],
            RESPONSES["url_filter_created"],
            RESPONSES["tag_created"],
            [{"Type": 4, "Contents": "rulebase is locked", "EntryContext": {}}],
        ],
    )
    mocker.patch.object(demisto, "setContext")
    pan_os = build_pan_os()

    pan_os.start_pan_os_flow()

    assert "rulebase is locked" in pan_os.failure_message


def test_ensure_tag_failure_does_not_abort(mocker):
    """
    Given:
       - A tag creation that fails.
    When:
       - Running the tag step.
    Then:
       - The failure is tolerated rather than aborting the whole flow.
    """
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 4, "Contents": "tag error", "EntryContext": {}}])

    build_pan_os().ensure_tag()


def test_ensure_security_rule_creates_and_moves_to_top(mocker):
    """
    Given:
       - A rulebase that does not contain the rule yet.
    When:
       - Ensuring the security rule exists.
    Then:
       - The rule is created with action=allow so the URL filtering profile can inspect the traffic,
         the profile is applied, and the rule is moved to the top of the rulebase.
    """
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            RESPONSES["list_rules_empty"],
            RESPONSES["rule_created"],
            RESPONSES["profile_applied"],
            RESPONSES["rule_moved"],
        ],
    )

    build_pan_os().ensure_security_rule()

    commands = executed_commands(execute_mock)
    assert [name for name, _ in commands] == [
        "pan-os-list-rules",
        "pan-os-create-rule",
        "pan-os-apply-security-profile",
        "pan-os-move-rule",
    ]
    assert commands[1][1]["action"] == "allow"
    assert commands[1][1]["tags"] == "cortex-blocked-urls"
    assert commands[3][1]["where"] == "top"


def test_ensure_security_rule_reuses_existing_and_still_moves(mocker):
    """
    Given:
       - A rulebase that already contains the rule.
    When:
       - Ensuring the security rule exists.
    Then:
       - The rule is not recreated, the tag edit is still issued, and the profile is applied again
         and the rule is moved back to the top, since precedence must be re-asserted on every run.
    """
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            RESPONSES["list_rules_with_rule"],
            RESPONSES["rule_tag_added"],
            RESPONSES["profile_applied"],
            RESPONSES["rule_moved"],
        ],
    )

    build_pan_os().ensure_security_rule()

    assert [name for name, _ in executed_commands(execute_mock)] == [
        "pan-os-list-rules",
        "pan-os-edit-rule",
        "pan-os-apply-security-profile",
        "pan-os-move-rule",
    ]


def test_ensure_security_rule_adds_missing_tag_to_existing_rule(mocker):
    """
    Given:
       - A rulebase that already contains the rule, but the rule does not carry the configured tag
         (for example the tag argument was changed between runs).
    When:
       - Ensuring the security rule exists.
    Then:
       - The configured tag is added to the existing rule with behaviour=add, so its existing tags
         are preserved, before the profile is re-applied and the rule is moved to the top.
    """
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            RESPONSES["list_rules_with_rule"],
            RESPONSES["rule_tag_added"],
            RESPONSES["profile_applied"],
            RESPONSES["rule_moved"],
        ],
    )

    build_pan_os().ensure_security_rule()

    commands = executed_commands(execute_mock)
    assert [name for name, _ in commands] == [
        "pan-os-list-rules",
        "pan-os-edit-rule",
        "pan-os-apply-security-profile",
        "pan-os-move-rule",
    ]
    edit_args = commands[1][1]
    assert edit_args["element_to_change"] == "tag"
    assert edit_args["element_value"] == "cortex-blocked-urls"
    assert edit_args["behaviour"] == "add"


def test_ensure_security_rule_adds_tag_even_when_tag_present(mocker):
    """
    Given:
       - A rulebase that already contains the rule, already carrying the configured tag in the
         fetched context.
    When:
       - Ensuring the security rule exists.
    Then:
       - The add-tag edit is still issued unconditionally (with behaviour=add and the pre_post scope
         on Panorama), because the fetched tag list can be stale and behaviour=add is idempotent on
         the device.
    """
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            RESPONSES["list_rules_with_rule_tagged"],
            RESPONSES["rule_tag_added"],
            RESPONSES["profile_applied"],
            RESPONSES["rule_moved"],
        ],
    )

    build_pan_os().ensure_security_rule()

    commands = executed_commands(execute_mock)
    assert [name for name, _ in commands] == [
        "pan-os-list-rules",
        "pan-os-edit-rule",
        "pan-os-apply-security-profile",
        "pan-os-move-rule",
    ]
    edit_args = commands[1][1]
    assert edit_args["element_to_change"] == "tag"
    assert edit_args["element_value"] == "cortex-blocked-urls"
    assert edit_args["behaviour"] == "add"
    assert "pre_post" in edit_args


def test_rule_commands_omit_pre_post_on_firewall(mocker):
    """
    Given:
       - A plain firewall, where pre_post is not a valid argument.
    When:
       - Ensuring the security rule exists.
    Then:
       - None of the rule commands carry pre_post.
    """
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            RESPONSES["list_rules_empty"],
            RESPONSES["rule_created"],
            RESPONSES["profile_applied"],
            RESPONSES["rule_moved"],
        ],
    )
    pan_os = build_pan_os()
    pan_os.is_panorama = False

    pan_os.ensure_security_rule()

    assert all("pre_post" not in command_args for _, command_args in executed_commands(execute_mock))


def test_log_forwarding_only_when_non_empty(mocker):
    """
    Given:
       - No log forwarding profile name.
    When:
       - Creating the security rule.
    Then:
       - The log_forwarding argument is omitted entirely.
    """
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["rule_created"])

    build_pan_os(log_forwarding_name="").create_security_rule()

    assert "log_forwarding" not in executed_commands(execute_mock)[0][1]


""" TOPOLOGY """


@pytest.mark.parametrize("fixture_name, expected_is_panorama", [("system_info_panorama", True), ("system_info_firewall", False)])
def test_detect_topology(mocker, fixture_name, expected_is_panorama):
    """
    Given:
       - A PAN-OS instance that is either a Panorama or a plain firewall.
    When:
       - Detecting the topology through the system info op command.
    Then:
       - The Panorama-only behaviour is enabled only for a Panorama.
    """
    mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES[fixture_name])
    pan_os = build_pan_os()

    pan_os.detect_topology()

    assert pan_os.is_panorama is expected_is_panorama


""" COMMIT AND PUSH ARGUMENTS """


def test_build_commit_args_panorama():
    """
    Given:
       - A Panorama instance with a device group.
    When:
       - Building the commit arguments.
    Then:
       - The commit is scoped as narrowly as PAN-OS allows: by device group, excluding the shared
         objects and the device and network configuration.
    """
    from BlockUrl import build_commit_args

    commit_args = build_commit_args(
        {
            "url_entries": [{"URL": "a", "SubmittedURL": "a"}, {"URL": "b", "SubmittedURL": "b"}],
            "device_group": "Test-Device-Group",
            "is_panorama": True,
            "incident_id": "1",
        }
    )

    assert commit_args == {
        "polling": True,
        "description": "Block URL - 2 URL(s) - 1",
        "exclude_device_network_configuration": True,
        "device-group": "Test-Device-Group",
        "exclude_shared_objects": True,
    }


def test_build_commit_args_firewall_drops_device_group():
    """
    Given:
       - A plain firewall, which has no device group and whose objects may live in shared.
    When:
       - Building the commit arguments.
    Then:
       - Both device-group and exclude_shared_objects are dropped.
    """
    from BlockUrl import build_commit_args

    commit_args = build_commit_args({"url_entries": [], "is_panorama": False, "incident_id": "1"})

    assert "device-group" not in commit_args
    assert "exclude_shared_objects" not in commit_args


""" POLLING """


def test_pan_os_commit_starts_polling(mocker):
    """
    Given:
       - Pending changes on PAN-OS.
    When:
       - Committing them.
    Then:
       - Polling starts and the commit job ID is stored for the next round.
    """
    import BlockUrl
    from BlockUrl import pan_os_commit

    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["commit_started"])
    set_context_mock = mocker.patch.object(demisto, "setContext")

    pan_os_commit({"url_entries": [], "is_panorama": True, "device_group": "Test-Device-Group"}, [])

    assert BlockUrl.POLLING is True
    set_context_mock.assert_any_call("commit_job_id", "56795")
    assert executed_commands(execute_mock)[0][0] == "pan-os-commit"


def test_pan_os_commit_nothing_to_commit(mocker):
    """
    Given:
       - No pending changes on PAN-OS.
    When:
       - Committing.
    Then:
       - Polling does not start, since there is no job to wait for.
    """
    import BlockUrl
    from BlockUrl import pan_os_commit

    mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["commit_nothing_to_commit"])
    mocker.patch.object(demisto, "setContext")

    pan_os_commit({"url_entries": [], "is_panorama": True}, [])

    assert BlockUrl.POLLING is False


def test_pan_os_commit_status_still_running(mocker):
    """
    Given:
       - A commit job that has not finished.
    When:
       - Checking its status.
    Then:
       - Polling continues.
    """
    import BlockUrl
    from BlockUrl import pan_os_commit_status

    mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["commit_status_pending"])

    pan_os_commit_status({"commit_job_id": "56795"}, [])

    assert BlockUrl.POLLING is True


def test_pan_os_commit_status_warnings_are_not_failure(mocker):
    """
    Given:
       - A commit job that finished successfully but reported warnings, which the lab does on every
         single commit.
    When:
       - Checking its status.
    Then:
       - Polling stops and the result is reported as a success, not as a failure.
    """
    import BlockUrl
    from BlockUrl import pan_os_commit_status

    mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["commit_status_done_with_warnings"])

    result = pan_os_commit_status({"commit_job_id": "56795"}, [])

    assert BlockUrl.POLLING is False
    assert result.outputs["Status"] == "Success"


def test_pan_os_push_to_device_starts_polling(mocker):
    """
    Given:
       - Committed changes that must be pushed to the device group.
    When:
       - Pushing them.
    Then:
       - Polling starts, the push job ID is stored, and the push is scoped to the device group.
    """
    import BlockUrl
    from BlockUrl import pan_os_push_to_device

    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["push_started"])
    set_context_mock = mocker.patch.object(demisto, "setContext")

    pan_os_push_to_device({"device_group": "Test-Device-Group", "incident_id": "1"}, [])

    assert BlockUrl.POLLING is True
    set_context_mock.assert_any_call("push_job_id", "56957")
    assert executed_commands(execute_mock)[0][1]["device-group"] == "Test-Device-Group"


def test_pan_os_push_status_pending_then_completed(mocker):
    """
    Given:
       - A push job that is still settling, and then a push job that completed with warnings.
    When:
       - Checking the push status, which is read from the context because the human readable output
         is nearly empty mid-flight.
    Then:
       - Polling continues while pending and stops once the status is Completed, with the warnings
         treated as a success.
    """
    import BlockUrl
    from BlockUrl import pan_os_push_status

    mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["push_status_pending"])
    pan_os_push_status({"push_job_id": "56957"}, [])
    assert BlockUrl.POLLING is True

    mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["push_status_completed_with_warnings"])
    completed_result = pan_os_push_status({"push_job_id": "56957"}, [])
    assert BlockUrl.POLLING is False
    assert completed_result.outputs["Status"] == "Completed"


""" JOB FAILURE """


def test_pan_os_commit_status_failed_job_is_a_failure(mocker):
    """
    Given:
       - A commit job that PAN-OS finished with a result other than OK. The command entry itself is a
         type-1 success, so the is_error sweep cannot detect it.
    When:
       - Checking the commit status.
    Then:
       - Polling stops, the status is reported as a Failure, and the PAN-OS reason is published for
         the flow so the push is skipped rather than pushing a config that failed validation.
    """
    import BlockUrl
    from BlockUrl import pan_os_commit_status

    BlockUrl.JOB_FAILURE_MESSAGE = ""
    mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["commit_status_failed"])

    result = pan_os_commit_status({"commit_job_id": "56795"}, [])

    assert BlockUrl.POLLING is False
    assert result.outputs["Status"] == "Failure"
    assert "commit job 56795 failed" in BlockUrl.JOB_FAILURE_MESSAGE
    assert "url-filtering profile is invalid" in BlockUrl.JOB_FAILURE_MESSAGE
    BlockUrl.JOB_FAILURE_MESSAGE = ""


def test_failed_commit_skips_the_push_and_reports_failed(mocker):
    """
    Given:
       - A polling round that resumes on a commit job which PAN-OS finished with a failure.
    When:
       - Running the PAN-OS state machine.
    Then:
       - No push command is issued, and every URL is reported as Failed carrying the PAN-OS reason,
         rather than "URL was blocked successfully."
    """
    import BlockUrl
    from BlockUrl import PanOs

    BlockUrl.JOB_FAILURE_MESSAGE = ""
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["commit_status_failed"])
    mocker.patch.object(demisto, "context", return_value={"commit_job_id": "56795"})
    mocker.patch.object(demisto, "setContext")
    pan_os = PanOs(build_pan_os().args | {"commit_job_id": "56795", "polling": True})

    results = pan_os.manage_pan_os_flow()

    executed = [name for name, _ in executed_commands(execute_mock)]
    assert "pan-os-push-to-device-group" not in executed
    assert results[0].outputs[0]["Result"] == "Failed"
    assert "commit job 56795 failed" in results[0].outputs[0]["Message"]
    BlockUrl.JOB_FAILURE_MESSAGE = ""


def test_pan_os_push_status_empty_status_keeps_polling(mocker):
    """
    Given:
       - A push status response that carries no Panorama.Push context at all, which the findings doc
         records as normal while the job is still settling.
    When:
       - Checking the push status.
    Then:
       - Polling continues rather than stopping and reporting a full success. The polling decorator
         timeout is the safety net for a status that never resolves.
    """
    import BlockUrl
    from BlockUrl import pan_os_push_status

    BlockUrl.JOB_FAILURE_MESSAGE = ""
    mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["push_status_empty"])

    pan_os_push_status({"push_job_id": "56957"}, [])

    assert BlockUrl.POLLING is True
    assert BlockUrl.JOB_FAILURE_MESSAGE == ""


def test_pan_os_push_status_failed_job_is_a_failure(mocker):
    """
    Given:
       - A push job that PAN-OS reports with an explicit failure status.
    When:
       - Checking the push status.
    Then:
       - Polling stops immediately instead of running to the timeout, and the failure is published
         for the flow to report it.
    """
    import BlockUrl
    from BlockUrl import pan_os_push_status

    BlockUrl.JOB_FAILURE_MESSAGE = ""
    mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["push_status_failed"])

    result = pan_os_push_status({"push_job_id": "56957"}, [])

    assert BlockUrl.POLLING is False
    assert result.outputs["Status"] == "FAIL"
    assert "push job 56957 failed" in BlockUrl.JOB_FAILURE_MESSAGE
    assert "commit failed on the managed firewall" in BlockUrl.JOB_FAILURE_MESSAGE
    BlockUrl.JOB_FAILURE_MESSAGE = ""


def test_pan_os_commit_status_error_entry_is_a_clean_failure(mocker):
    """
    Given:
       - A resume on a stale/invalid commit job where pan-os-commit-status returns an error entry
         (Type 4) whose Contents is a plain string ("Invalid Job ID error: job X not found"),
         followed by a Type 16 file entry, exactly as the live crash showed.
    When:
       - Checking the commit status.
    Then:
       - The function does not raise 'str' object has no attribute 'get', polling stops, the status is
         reported as a Failure, and the PAN-OS reason is published so the push is skipped.
    """
    import BlockUrl
    from BlockUrl import pan_os_commit_status

    BlockUrl.JOB_FAILURE_MESSAGE = ""
    mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["commit_status_job_not_found"])

    result = pan_os_commit_status({"commit_job_id": "57069"}, [])

    assert BlockUrl.POLLING is False
    assert result.outputs["Status"] == "Failure"
    assert "job 57069 not found" in BlockUrl.JOB_FAILURE_MESSAGE
    BlockUrl.JOB_FAILURE_MESSAGE = ""


def test_pan_os_push_status_error_entry_is_a_clean_failure(mocker):
    """
    Given:
       - A push status response that is an error entry (Type 4) with a plain string Contents, the same
         shape as the commit-status crash.
    When:
       - Checking the push status.
    Then:
       - The function does not raise, polling stops, the status is reported as a Failure, and the
         PAN-OS reason is published for the flow to report it.
    """
    import BlockUrl
    from BlockUrl import pan_os_push_status

    BlockUrl.JOB_FAILURE_MESSAGE = ""
    mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["push_status_job_not_found"])

    result = pan_os_push_status({"push_job_id": "57069"}, [])

    assert BlockUrl.POLLING is False
    assert result.outputs["Status"] == "Failure"
    assert "job 57069 not found" in BlockUrl.JOB_FAILURE_MESSAGE
    BlockUrl.JOB_FAILURE_MESSAGE = ""


def test_commit_status_error_entry_skips_push_and_reports_failed(mocker):
    """
    Given:
       - A polling round that resumes on a commit job whose status command returns an error entry with
         a string Contents (the "job not found" live crash shape).
    When:
       - Running the PAN-OS state machine.
    Then:
       - No push command is issued, the flow does not crash, and every URL is reported as Failed
         carrying the PAN-OS reason.
    """
    import BlockUrl
    from BlockUrl import PanOs

    BlockUrl.JOB_FAILURE_MESSAGE = ""
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=RESPONSES["commit_status_job_not_found"])
    mocker.patch.object(demisto, "context", return_value={})
    mocker.patch.object(demisto, "setContext")
    pan_os = PanOs(build_pan_os().args | {"commit_job_id": "57069", "polling": True})

    results = pan_os.manage_pan_os_flow()

    executed = [name for name, _ in executed_commands(execute_mock)]
    assert "pan-os-push-to-device-group" not in executed
    assert results[0].outputs[0]["Result"] == "Failed"
    assert "job 57069 not found" in results[0].outputs[0]["Message"]
    BlockUrl.JOB_FAILURE_MESSAGE = ""


def test_stale_commit_job_id_in_context_does_not_hijack_fresh_run(mocker):
    """
    Given:
       - A brand-new (non-polling) invocation with no commit_job_id in args, but a completed previous
         run left commit_job_id='57069' in the incident context.
    When:
       - Running the PAN-OS state machine.
    Then:
       - The stale context id is ignored (not read as a resume), so pan-os-commit-status is not called
         with the stale id and the fresh configuration flow runs instead.
    """
    from BlockUrl import PanOs

    # The fresh flow runs the full config sequence and then a commit. Ending on "nothing to commit"
    # keeps the flow from polling and exercises the whole path without a push.
    flow_responses = successful_flow_responses() + [RESPONSES["commit_nothing_to_commit"]]
    execute_mock = mocker.patch.object(demisto, "executeCommand", side_effect=flow_responses)
    mocker.patch.object(demisto, "context", return_value={"commit_job_id": "57069"})
    set_context_mock = mocker.patch.object(demisto, "setContext")
    pan_os = PanOs(build_pan_os().args | {"commit_job_id": None, "polling": True})

    pan_os.manage_pan_os_flow()

    executed = [name for name, _ in executed_commands(execute_mock)]
    assert "pan-os-commit-status" not in executed
    assert "pan-os" in executed
    # The stale context id was scrubbed rather than trusted.
    set_context_mock.assert_any_call("commit_job_id", "")


def test_adopt_job_failure_clears_the_global():
    """
    Given:
       - A job failure published by one of the polling functions.
    When:
       - The flow adopts it.
    Then:
       - It becomes the failure message of this run and the global is cleared, so it cannot leak into
         an unrelated later run in the same process.
    """
    import BlockUrl

    BlockUrl.JOB_FAILURE_MESSAGE = "the commit failed"
    pan_os = build_pan_os()

    assert pan_os.adopt_job_failure() is True
    assert pan_os.failure_message == "the commit failed"
    assert BlockUrl.JOB_FAILURE_MESSAGE == ""
    assert pan_os.adopt_job_failure() is False


""" BRAND RESUME """


def test_update_brands_to_run_removes_executed_brands(mocker):
    """
    Given:
       - A polling round that resumes after another brand already finished.
    When:
       - Computing the brands that still need to run.
    Then:
       - The brands that already executed are not run again.
    """
    from BlockUrl import update_brands_to_run

    mocker.patch.object(demisto, "context", return_value={"executed_brands": "['Panorama']"})

    executed_brands, brands_to_run = update_brands_to_run(["Panorama"])

    assert executed_brands == ["Panorama"]
    assert brands_to_run == set()


def test_update_brands_to_run_without_panorama(mocker):
    """
    Given:
       - A run that does not involve the polling brand.
    When:
       - Computing the brands that still need to run.
    Then:
       - The resume logic is skipped entirely.
    """
    from BlockUrl import update_brands_to_run

    executed_brands, brands_to_run = update_brands_to_run(["SomeOtherBrand"])

    assert executed_brands == []
    assert brands_to_run == {"SomeOtherBrand"}


""" OUTPUT """


def test_create_final_context_success_skipped_and_failed():
    """
    Given:
       - One URL that was newly blocked and one that the category already held.
    When:
       - Building the final context.
    Then:
       - Each URL gets its own record, with the full output schema and the right per-URL result.
    """
    from BlockUrl import create_final_context

    url_entries = [
        {"URL": "https://new.example.com", "SubmittedURL": "new.example.com"},
        {"URL": "already.example.com", "SubmittedURL": "already.example.com"},
    ]
    details = {
        "rule_name": "Cortex - Block URLs",
        "url_category": "Blocked URLs - Cortex",
        "job_id": "56795",
        "already_present": ["already.example.com"],
        "failure_message": "",
    }

    context = create_final_context("Panorama", url_entries, details)

    assert context[0] == {
        "URL": "https://new.example.com",
        "SubmittedURL": "new.example.com",
        "Brand": "Panorama",
        "Result": "Success",
        "Message": "URL was blocked successfully.",
        "RuleName": "Cortex - Block URLs",
        "URLCategory": "Blocked URLs - Cortex",
        "JobID": "56795",
    }
    assert context[1]["Result"] == "Skipped"
    assert context[1]["Message"] == "URL already present in the category."


def test_create_final_context_failure():
    """
    Given:
       - A flow that failed.
    When:
       - Building the final context.
    Then:
       - Every URL is reported as failed, carrying the failure message.
    """
    from BlockUrl import create_final_context

    context = create_final_context(
        "Panorama",
        [{"URL": "new.example.com", "SubmittedURL": "new.example.com"}],
        {"failure_message": "Won't modify a user-managed category", "already_present": []},
    )

    assert context[0]["Result"] == "Failed"
    assert context[0]["Message"] == "Won't modify a user-managed category"


def test_create_rejected_results_uses_none_for_absent_fields():
    """
    Given:
       - URLs that were rejected before any brand was contacted.
    When:
       - Building their results.
    Then:
       - They are reported as failures, and every field with no meaningful value is None (real JSON
         null) rather than an empty string, per the output contract.
    """
    from BlockUrl import create_rejected_results

    results = create_rejected_results(
        [{"URL": "*.bad.example.com", "SubmittedURL": "", "Result": "Failed", "Message": "Wildcards are not supported."}]
    )

    assert results.outputs_prefix == "BlockURLResults"
    assert results.outputs[0]["Result"] == "Failed"
    for field in ("SubmittedURL", "Brand", "RuleName", "URLCategory", "JobID"):
        assert results.outputs[0][field] is None
    assert "" not in results.outputs[0].values()


def test_create_final_context_uses_none_never_empty_string():
    """
    Given:
       - A flow whose details carry no rule name, category or job id (all absent).
    When:
       - Building the final context.
    Then:
       - Every absent field is None (real JSON null), and no field is ever an empty string.
    """
    from BlockUrl import create_final_context

    context = create_final_context(
        "",
        [{"URL": "", "SubmittedURL": ""}],
        {"rule_name": "", "url_category": "", "job_id": "", "already_present": [], "failure_message": ""},
    )

    row = context[0]
    for field in ("URL", "SubmittedURL", "Brand", "RuleName", "URLCategory", "JobID"):
        assert row[field] is None
    assert "" not in row.values()


def test_profile_failure_aborts_before_rule_is_created(mocker):
    """
    Given:
       - A flow where the URL filtering profile creation fails.
    When:
       - Running start_pan_os_flow.
    Then:
       - The flow aborts before any rule command runs, so the security rule is never created without
         a working profile attached.
    """
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            RESPONSES["system_info_panorama"],
            RESPONSES["object_not_found"],
            RESPONSES["category_created"],
            RESPONSES["object_not_found"],
            [{"Type": 4, "Contents": "profile creation failed", "EntryContext": {}}],
        ],
    )
    mocker.patch.object(demisto, "setContext")
    pan_os = build_pan_os()

    pan_os.start_pan_os_flow()

    command_names = [name for name, _ in executed_commands(execute_mock)]
    assert "pan-os-create-rule" not in command_names
    assert "pan-os-list-rules" not in command_names
    assert "profile creation failed" in pan_os.failure_message


def test_profile_edit_failure_aborts_before_rule_is_created(mocker):
    """
    Given:
       - A flow where the profile exists but attaching the category to it fails.
    When:
       - Running start_pan_os_flow.
    Then:
       - The flow aborts before any rule command runs.
    """
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            RESPONSES["system_info_panorama"],
            RESPONSES["object_not_found"],
            RESPONSES["category_created"],
            RESPONSES["url_filter_dirty_other_category"],
            [{"Type": 4, "Contents": "profile edit failed", "EntryContext": {}}],
        ],
    )
    mocker.patch.object(demisto, "setContext")
    pan_os = build_pan_os()

    pan_os.start_pan_os_flow()

    command_names = [name for name, _ in executed_commands(execute_mock)]
    assert "pan-os-create-rule" not in command_names
    assert "pan-os-list-rules" not in command_names
    assert "profile edit failed" in pan_os.failure_message


def test_prepare_context_and_hr_verbose_adds_per_command_entries():
    """
    Given:
       - A flow whose commands each produced a human readable entry.
    When:
       - Building the results with verbose enabled and disabled.
    Then:
       - Verbose returns an entry per command plus the summary, and non-verbose returns only the
         summary.
    """
    from BlockUrl import prepare_context_and_hr_multiple_executions

    responses = [RESPONSES["rule_moved"], RESPONSES["profile_applied"]]
    url_entries = [{"URL": "new.example.com", "SubmittedURL": "new.example.com"}]
    details = {"brand": "Panorama", "rule_name": "Cortex - Block URLs", "already_present": [], "failure_message": ""}

    verbose_results = prepare_context_and_hr_multiple_executions(responses, True, url_entries, details)
    quiet_results = prepare_context_and_hr_multiple_executions(responses, False, url_entries, details)

    assert len(verbose_results) == 3
    assert len(quiet_results) == 1
    assert quiet_results[0].outputs_prefix == "BlockURLResults"


def test_prepare_context_and_hr_reports_command_errors():
    """
    Given:
       - A flow in which one of the commands returned an error entry.
    When:
       - Building the results.
    Then:
       - The URLs are reported as failed and the error message reaches the output.
    """
    from BlockUrl import prepare_context_and_hr_multiple_executions

    results = prepare_context_and_hr_multiple_executions(
        [RESPONSES["dirty_object_error"]],
        False,
        [{"URL": "new.example.com", "SubmittedURL": "new.example.com"}],
        {"brand": "Panorama", "already_present": [], "failure_message": ""},
    )

    assert results[0].outputs[0]["Result"] == "Failed"
    assert "Please commit the instance" in results[0].outputs[0]["Message"]
