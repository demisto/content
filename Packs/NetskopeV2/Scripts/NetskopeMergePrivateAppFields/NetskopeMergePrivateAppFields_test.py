import demistomock as demisto
from NetskopeMergePrivateAppFields import (
    get_current_app,
    main,
    merge_hosts,
    merge_protocols,
    merge_tags,
    remove_hosts,
    remove_ports,
    remove_tag_names,
)


def test_merge_hosts_appends_new_host():
    """
    Given:
        - An existing comma-separated host list and a new host to add.
    When:
        - Running merge_hosts.
    Then:
        - The new host is appended without disturbing the existing ones.
    """
    assert merge_hosts("webserver.local,192.168.0.1", ["10.0.0.5"]) == "webserver.local,192.168.0.1,10.0.0.5"


def test_merge_hosts_deduplicates_case_insensitively():
    """
    Given:
        - A host to add that already exists, differing only in case.
    When:
        - Running merge_hosts.
    Then:
        - No duplicate is added.
    """
    assert merge_hosts("Webserver.local", ["webserver.local"]) == "Webserver.local"


def test_remove_hosts_removes_matching_entry():
    """
    Given:
        - An existing host list and a host to remove.
    When:
        - Running remove_hosts.
    Then:
        - Only the matching entry is removed, the rest are kept.
    """
    assert remove_hosts("webserver.local,192.168.0.1,10.0.0.5", ["192.168.0.1"]) == "webserver.local,10.0.0.5"


def test_merge_protocols_normalizes_read_shape_to_write_shape():
    """
    Given:
        - Current protocols in the read shape returned by netskopev2-list-private-apps (extra
          fields, "transport" instead of "type"), plus a new port to add.
    When:
        - Running merge_protocols.
    Then:
        - Existing entries are normalized to the write shape ({type, port}) and the new port is
          appended.
    """
    current = [{"id": 1, "service_id": 1, "port": "22", "transport": "tcp", "created_at": "x", "updated_at": "x"}]
    merged = merge_protocols(current, ["443"], "tcp")
    assert merged == [{"type": "tcp", "port": "22"}, {"type": "tcp", "port": "443"}]


def test_remove_ports_drops_matching_port_and_normalizes_rest():
    """
    Given:
        - Current protocols in the read shape, with one port to remove.
    When:
        - Running remove_ports.
    Then:
        - The matching port is dropped and the remaining entries are normalized to the write shape.
    """
    current = [
        {"port": "22", "transport": "tcp", "id": 1},
        {"port": "443", "transport": "tcp", "id": 2},
    ]
    remaining = remove_ports(current, ["443"])
    assert remaining == [{"type": "tcp", "port": "22"}]


def test_merge_tags_appends_new_tag():
    """
    Given:
        - Current tags in the read shape (tag_id + tag_name) and a new tag to add.
    When:
        - Running merge_tags.
    Then:
        - The existing tag names are kept and the new tag is appended.
    """
    current_tags = [{"tag_id": 1, "tag_name": "foo"}]
    assert merge_tags(current_tags, ["test"]) == ["foo", "test"]


def test_remove_tag_names_drops_matching_tag():
    """
    Given:
        - A list of tag name strings and one to remove.
    When:
        - Running remove_tag_names.
    Then:
        - Only the matching tag is removed.
    """
    assert remove_tag_names(["foo", "bar"], ["foo"]) == ["bar"]


def test_get_current_app_reads_entry_context_not_contents(mocker):
    """
    Given:
        - netskopev2-list-private-apps returns an entry where Contents reflects raw_response,
          with the structured list under EntryContext instead.
    When:
        - Running get_current_app with a matching app_id.
    Then:
        - The matching app dict is returned.
    """
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Type": 1,
                "Contents": {"data": {"private_apps": [{"app_id": 4458}]}},
                "EntryContext": {"Netskope.PrivateApp": [{"app_id": 4458, "host": "webserver.local"}]},
            }
        ],
    )
    app = get_current_app("4458")
    assert app == {"app_id": 4458, "host": "webserver.local"}


def test_main_passes_through_direct_values_when_nothing_to_add_or_remove(mocker):
    """
    Given:
        - No hosts_to_add/ports_to_add/hosts_to_remove/ports_to_remove/tags_to_add/tags_to_remove.
    When:
        - Running main.
    Then:
        - The direct-replace host/protocols_json/tags values pass through unchanged, and no
          lookup (executeCommand) happens.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "app_id": "4458",
            "host": "10.0.0.6",
            "protocols_json": '[{"type": "tcp", "port": "443"}]',
            "tags": "existing",
        },
    )
    execute_mock = mocker.patch.object(demisto, "executeCommand")
    results_mock = mocker.patch.object(demisto, "results")

    main()

    execute_mock.assert_not_called()
    outputs = results_mock.call_args[0][0]["EntryContext"]["MergedPrivateAppFields"]
    assert outputs["host"] == "10.0.0.6"
    assert outputs["protocols_json"] == '[{"type": "tcp", "port": "443"}]'
    assert outputs["tags"] == "existing"


def test_main_merges_hosts_ports_and_tags(mocker):
    """
    Given:
        - hosts_to_add, ports_to_add, and tags_to_add are provided for an existing app.
    When:
        - Running main.
    Then:
        - The current host/protocols/tags are fetched and merged with the new values.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "app_id": "4458",
            "hosts_to_add": "10.0.0.5",
            "ports_to_add": "8080",
            "tags_to_add": "test",
            "protocol_type": "tcp",
        },
    )
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Type": 1,
                "Contents": {},
                "EntryContext": {
                    "Netskope.PrivateApp": [
                        {
                            "app_id": 4458,
                            "host": "webserver.local",
                            "protocols": [{"port": "22", "transport": "tcp"}],
                            "tags": [{"tag_id": 1, "tag_name": "foo"}],
                        }
                    ]
                },
            }
        ],
    )
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["MergedPrivateAppFields"]
    assert outputs["host"] == "webserver.local,10.0.0.5"
    assert outputs["protocols_json"] == '[{"type": "tcp", "port": "22"}, {"type": "tcp", "port": "8080"}]'
    assert outputs["tags"] == "foo,test"
