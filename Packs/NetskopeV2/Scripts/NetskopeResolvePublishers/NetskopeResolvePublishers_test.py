import demistomock as demisto
from NetskopeResolvePublishers import get_all_publishers, main, resolve_publishers


def test_resolve_publishers_single_match():
    """
    Given:
        - A publisher name that matches exactly one publisher.
    When:
        - Running resolve_publishers.
    Then:
        - The publisher is resolved, with publisher_id coerced to a string, and no errors.
    """
    all_publishers = [{"publisher_id": 10, "publisher_name": "AWS-NPA"}]
    resolved, errors = resolve_publishers(["AWS-NPA"], all_publishers)
    assert resolved == [{"publisher_id": "10", "publisher_name": "AWS-NPA"}]
    assert errors == []


def test_resolve_publishers_case_insensitive():
    """
    Given:
        - A requested name that differs in case from the stored publisher_name.
    When:
        - Running resolve_publishers.
    Then:
        - The publisher is still resolved.
    """
    all_publishers = [{"publisher_id": 10, "publisher_name": "AWS-NPA"}]
    resolved, errors = resolve_publishers(["aws-npa"], all_publishers)
    assert resolved == [{"publisher_id": "10", "publisher_name": "AWS-NPA"}]
    assert errors == []


def test_resolve_publishers_no_match():
    """
    Given:
        - A requested name with no matching publisher.
    When:
        - Running resolve_publishers.
    Then:
        - An error is returned and nothing is resolved.
    """
    resolved, errors = resolve_publishers(["nonexistent"], [{"publisher_id": 10, "publisher_name": "AWS-NPA"}])
    assert resolved == []
    assert len(errors) == 1
    assert "No publisher found" in errors[0]


def test_resolve_publishers_ambiguous_match():
    """
    Given:
        - Two publishers sharing the same name.
    When:
        - Running resolve_publishers.
    Then:
        - An error listing both IDs is returned instead of resolving either.
    """
    all_publishers = [{"publisher_id": 10, "publisher_name": "dup"}, {"publisher_id": 11, "publisher_name": "dup"}]
    resolved, errors = resolve_publishers(["dup"], all_publishers)
    assert resolved == []
    assert "Multiple publishers named" in errors[0]


def test_get_all_publishers_reads_entry_context_not_contents(mocker):
    """
    Given:
        - netskopev2-list-publishers returns an entry where Contents reflects raw_response
          (not outputs), with the structured list under EntryContext instead.
    When:
        - Running get_all_publishers.
    Then:
        - The publishers are read from EntryContext, keyed by a prefix match on "Netskope.Publisher",
          and the fields-filtering param is passed to keep the response small.
    """
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Type": 1,
                "Contents": {"data": {"publishers": [{"publisher_id": 10}]}},
                "EntryContext": {"Netskope.Publisher": [{"publisher_id": 10, "publisher_name": "AWS-NPA"}]},
            }
        ],
    )
    publishers = get_all_publishers()
    assert publishers == [{"publisher_id": 10, "publisher_name": "AWS-NPA"}]
    execute_mock.assert_called_once_with("netskopev2-list-publishers", {"fields": "publisher_id,publisher_name"})


def test_main_empty_publisher_names_does_not_call_executeCommand(mocker):
    """
    Given:
        - publisher_names is empty.
    When:
        - Running main.
    Then:
        - No lookup happens (executeCommand not called) and a clean error is set instead of
          relying on platform-level required-argument enforcement.
    """
    mocker.patch.object(demisto, "args", return_value={"publisher_names": ""})
    execute_mock = mocker.patch.object(demisto, "executeCommand")
    results_mock = mocker.patch.object(demisto, "results")

    main()

    execute_mock.assert_not_called()
    outputs = results_mock.call_args[0][0]["EntryContext"]["ResolvedPublishers"]
    assert outputs["publishers_json"] == ""
    assert "must not be empty" in outputs["error"]


def test_main_resolves_publisher_names(mocker):
    """
    Given:
        - publisher_names matches a single existing publisher.
    When:
        - Running main.
    Then:
        - publishers_json contains the resolved {publisher_id, publisher_name} with no error.
    """
    mocker.patch.object(demisto, "args", return_value={"publisher_names": "AWS-NPA"})
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Type": 1,
                "Contents": {},
                "EntryContext": {"Netskope.Publisher": [{"publisher_id": 10, "publisher_name": "AWS-NPA"}]},
            }
        ],
    )
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["ResolvedPublishers"]
    assert outputs["publishers_json"] == '[{"publisher_id": "10", "publisher_name": "AWS-NPA"}]'
    assert outputs["error"] == ""
