from TaegisXDRCaseStatusOpenOptions import OPEN_STATUSES, TAEGIS_STATUSES_ALL, main


def test_open_statuses_excludes_closed():
    assert all(not s.startswith("CLOSED_") for s in OPEN_STATUSES)


def test_open_statuses_is_subset_of_all_statuses():
    assert set(OPEN_STATUSES).issubset(set(TAEGIS_STATUSES_ALL))
    assert "ACTIVE" in OPEN_STATUSES
    assert "AWAITING_ACTION" in OPEN_STATUSES
    assert "OPEN" in OPEN_STATUSES
    assert "SUSPENDED" in OPEN_STATUSES


def test_main_returns_placeholder_and_open_statuses(mocker):
    return_results_mock = mocker.patch("TaegisXDRCaseStatusOpenOptions.return_results")

    main()

    result = return_results_mock.call_args[0][0]
    assert result["hidden"] is False
    assert result["options"][0] == "Select Status"
    assert all(not s.startswith("CLOSED_") for s in result["options"][1:])
    assert set(result["options"][1:]) == set(OPEN_STATUSES)
