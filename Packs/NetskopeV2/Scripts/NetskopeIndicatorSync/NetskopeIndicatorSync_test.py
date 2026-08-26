import demistomock as demisto
from NetskopeIndicatorSync import build_query, chunk_list, find_new_values, format_value, main


def test_format_value_cidr_gets_prefix():
    """
    Given:
        - A CIDR indicator value.
    When:
        - Running format_value.
    Then:
        - The value is prefixed with "CIDR:", matching Netskope's Definition field syntax.
    """
    assert format_value("CIDR", "10.0.0.0/24") == "CIDR:10.0.0.0/24"


def test_format_value_non_cidr_unchanged():
    """
    Given:
        - A non-CIDR indicator value (e.g. Domain).
    When:
        - Running format_value.
    Then:
        - The value is returned unchanged.
    """
    assert format_value("Domain", "evil.com") == "evil.com"


def test_chunk_list_splits_into_fixed_size_batches():
    """
    Given:
        - A list of 5 items and a chunk size of 2.
    When:
        - Running chunk_list.
    Then:
        - The list is split into batches of at most 2, preserving order.
    """
    assert chunk_list([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]


def test_build_query_includes_tags_and_skip_tags():
    """
    Given:
        - Indicator types, tags, and skip_tags.
    When:
        - Running build_query.
    Then:
        - The query string includes a type filter, a tags filter, and a negated skip_tags filter.
    """
    query = build_query(["Domain", "URL"], ["netskope-block"], ["ignore"])
    assert query == "type:(Domain URL) and tags:(netskope-block) and -tags:(ignore)"


def test_build_query_without_tags():
    """
    Given:
        - Only indicator types, no tags or skip_tags.
    When:
        - Running build_query.
    Then:
        - The query string only contains the type filter.
    """
    assert build_query(["Domain"], [], []) == "type:(Domain)"


def test_find_new_values_skips_existing_and_no_value(mocker):
    """
    Given:
        - Search results containing one indicator already in `existing`, one with no value, and
          one genuinely new indicator.
    When:
        - Running find_new_values.
    Then:
        - Only the new indicator is returned, and stats reflect the skips.
    """
    mocker.patch.object(
        demisto,
        "searchIndicators",
        return_value={
            "iocs": [
                {"value": "already-blocked.com", "indicator_type": "Domain"},
                {"value": None, "indicator_type": "Domain"},
                {"value": "new.com", "indicator_type": "Domain"},
            ]
        },
    )
    new_values, chunks, stats = find_new_values(["Domain"], [], [], {"already-blocked.com"}, 500, 10)
    assert new_values == ["new.com"]
    assert chunks == [["new.com"]]
    assert stats["total_found"] == 3
    assert stats["skipped_existing"] == 1
    assert stats["skipped_no_value"] == 1
    assert stats["new_count"] == 1


def test_find_new_values_handles_none_iocs(mocker):
    """
    Given:
        - demisto.searchIndicators returns {"iocs": None} (present key, None value) when nothing
          matches.
    When:
        - Running find_new_values.
    Then:
        - No exception is raised and zero new values are found.
    """
    mocker.patch.object(demisto, "searchIndicators", return_value={"iocs": None})
    new_values, chunks, stats = find_new_values(["Domain"], [], [], set(), 500, 10)
    assert new_values == []
    assert stats["total_found"] == 0


def test_main_without_profile_id_only_prepares_values(mocker):
    """
    Given:
        - No profile_id is provided.
    When:
        - Running main.
    Then:
        - New values are found and returned, but no append/deploy commands are executed.
    """
    mocker.patch.object(demisto, "args", return_value={"indicator_types": "Domain"})
    mocker.patch.object(demisto, "searchIndicators", return_value={"iocs": [{"value": "new.com", "indicator_type": "Domain"}]})
    execute_mock = mocker.patch.object(demisto, "executeCommand")
    results_mock = mocker.patch.object(demisto, "results")

    main()

    execute_mock.assert_not_called()
    outputs = results_mock.call_args[0][0]["EntryContext"]["NetskopeSync"]
    assert outputs["all_new_values"] == ["new.com"]
    assert outputs["added_count"] == 0
    assert outputs["deployed"] is False


def test_main_with_profile_id_appends_and_deploys(mocker):
    """
    Given:
        - A profile_id is provided and new values are found.
    When:
        - Running main.
    Then:
        - The new values are appended via netskopev2-update-destination-profile-values and the
          profile is deployed via netskopev2-deploy-destination-profiles.
    """
    mocker.patch.object(demisto, "args", return_value={"indicator_types": "Domain", "profile_id": "5"})
    mocker.patch.object(demisto, "searchIndicators", return_value={"iocs": [{"value": "new.com", "indicator_type": "Domain"}]})
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "ok"}])
    results_mock = mocker.patch.object(demisto, "results")

    main()

    called_commands = [call.args[0] for call in execute_mock.call_args_list]
    assert "netskopev2-update-destination-profile-values" in called_commands
    assert "netskopev2-deploy-destination-profiles" in called_commands
    outputs = results_mock.call_args[0][0]["EntryContext"]["NetskopeSync"]
    assert outputs["added_count"] == 1
    assert outputs["deployed"] is True


def test_main_rejects_invalid_indicator_type(mocker):
    """
    Given:
        - An indicator_types value that isn't one of Domain/URL/IP/CIDR.
    When:
        - Running main.
    Then:
        - A DemistoException is raised before any search happens.
    """
    import pytest
    from CommonServerPython import DemistoException

    mocker.patch.object(demisto, "args", return_value={"indicator_types": "Email"})
    with pytest.raises(DemistoException, match="indicator_types must be one of"):
        main()
