import demistomock as demisto
from NetskopeResolvePrivateAppId import find_by_name, get_all_apps, main, strip_brackets


def test_strip_brackets_removes_wrapping():
    """
    Given:
        - A name wrapped in brackets, as returned by netskopev2-list-private-apps.
    When:
        - Running strip_brackets.
    Then:
        - The brackets are removed.
    """
    assert strip_brackets("[test server]") == "test server"


def test_strip_brackets_leaves_unwrapped_name_untouched():
    """
    Given:
        - A name without brackets.
    When:
        - Running strip_brackets.
    Then:
        - The name is returned unchanged.
    """
    assert strip_brackets("test server") == "test server"


def test_find_by_name_matches_bracket_wrapped_app_name():
    """
    Given:
        - A list of apps where app_name is bracket-wrapped (the list-response shape).
    When:
        - Running find_by_name with the unwrapped name.
    Then:
        - The matching app is found.
    """
    apps = [{"app_id": 1, "app_name": "[test server]"}, {"app_id": 2, "app_name": "[other server]"}]
    matches = find_by_name(apps, "test server")
    assert len(matches) == 1
    assert matches[0]["app_id"] == 1


def test_find_by_name_no_match():
    """
    Given:
        - A list of apps, none matching the requested name.
    When:
        - Running find_by_name.
    Then:
        - No matches are returned.
    """
    apps = [{"app_id": 1, "app_name": "[test server]"}]
    assert find_by_name(apps, "nonexistent") == []


def test_find_by_name_multiple_matches():
    """
    Given:
        - Two apps sharing the same name.
    When:
        - Running find_by_name.
    Then:
        - Both are returned as matches.
    """
    apps = [{"app_id": 1, "app_name": "[dup]"}, {"app_id": 2, "app_name": "[dup]"}]
    assert len(find_by_name(apps, "dup")) == 2


def test_get_all_apps_reads_entry_context_not_contents(mocker):
    """
    Given:
        - netskopev2-list-private-apps returns an entry where Contents reflects raw_response
          (not outputs), with the structured list under EntryContext instead.
    When:
        - Running get_all_apps.
    Then:
        - The apps are read from EntryContext, keyed by a prefix match on "Netskope.PrivateApp".
    """
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Type": 1,
                "Contents": {"data": {"private_apps": [{"app_id": 1}]}},
                "EntryContext": {
                    "Netskope.PrivateApp(val.app_id && val.app_id == obj.app_id)": [
                        {"app_id": 1, "app_name": "[a]"}
                    ]
                },
            }
        ],
    )
    apps = get_all_apps()
    assert apps == [{"app_id": 1, "app_name": "[a]"}]


def test_main_uses_app_id_directly_without_lookup(mocker):
    """
    Given:
        - app_id is provided.
    When:
        - Running main.
    Then:
        - The provided app_id is used directly and no lookup (executeCommand) happens.
    """
    mocker.patch.object(demisto, "args", return_value={"app_id": "4458", "app_name": ""})
    execute_mock = mocker.patch.object(demisto, "executeCommand")
    results_mock = mocker.patch.object(demisto, "results")

    main()

    execute_mock.assert_not_called()
    outputs = results_mock.call_args[0][0]["EntryContext"]["ResolvedAppId"]
    assert outputs["app_id"] == "4458"
    assert outputs["resolved_by"] == "app_id"
    assert outputs["error"] == ""


def test_main_resolves_app_name(mocker):
    """
    Given:
        - app_name is provided, app_id is not, and exactly one app matches that name.
    When:
        - Running main.
    Then:
        - The resolved app_id is returned with resolved_by="app_name" and no error.
    """
    mocker.patch.object(demisto, "args", return_value={"app_id": "", "app_name": "test server"})
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Type": 1,
                "Contents": {},
                "EntryContext": {"Netskope.PrivateApp": [{"app_id": 4458, "app_name": "[test server]"}]},
            }
        ],
    )
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["ResolvedAppId"]
    assert outputs["app_id"] == "4458"
    assert outputs["resolved_by"] == "app_name"
    assert outputs["error"] == ""


def test_main_app_name_not_found(mocker):
    """
    Given:
        - app_name is provided but no app matches it.
    When:
        - Running main.
    Then:
        - app_id is empty and error explains no match was found.
    """
    mocker.patch.object(demisto, "args", return_value={"app_id": "", "app_name": "nonexistent"})
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": {}, "EntryContext": {}}])
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["ResolvedAppId"]
    assert outputs["app_id"] == ""
    assert "No private app found" in outputs["error"]


def test_main_neither_app_id_nor_app_name_provided(mocker):
    """
    Given:
        - Neither app_id nor app_name is provided.
    When:
        - Running main.
    Then:
        - An error explains that one of them must be provided.
    """
    mocker.patch.object(demisto, "args", return_value={"app_id": "", "app_name": ""})
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["ResolvedAppId"]
    assert outputs["resolved_by"] == "none"
    assert "must be provided" in outputs["error"]
