import demistomock as demisto
from SekoiaXDRPrintCase import get_case_info, create_case_object, main  # type: ignore


def test_create_case_object():
    cases = [
        {
            "title": "title1",
            "description": "description1",
            "short_id": "11",
            "status": "status1",
            "priority": "priority1",
            "alerts": [{"short_id": "1"}, {"short_id": "2"}, {"short_id": "3"}],
        },
        {
            "title": "title2",
            "description": "description2",
            "short_id": "22",
            "status": "status2",
            "priority": "priority2",
            "alerts": [{"short_id": "4"}, {"short_id": "5"}, {"short_id": "6"}],
        },
    ]
    expected = [
        {
            "title": "title1",
            "description": "description1",
            "status": "Status1",
            "priority": "Priority1",
            "related alerts": "1, 2, 3",
        },
        {
            "title": "title2",
            "description": "description2",
            "status": "Status2",
            "priority": "Priority2",
            "related alerts": "4, 5, 6",
        },
    ]
    assert create_case_object(cases) == expected


def test_get_case_info(mocker):
    cases_output = [
        {
            "title": "title1",
            "description": "description1",
            "short_id": "11",
            "status": "status1",
            "priority": "priority1",
            "alerts": [{"short_id": "1"}, {"short_id": "2"}, {"short_id": "3"}],
        },
        {
            "title": "title2",
            "description": "description2",
            "short_id": "22",
            "status": "status2",
            "priority": "priority2",
            "alerts": [{"short_id": "4"}, {"short_id": "5"}, {"short_id": "6"}],
        },
    ]
    mocker.patch.object(
        demisto, "executeCommand", return_value=[{"Type": 3, "Contents": cases_output}]
    )
    assert "title1" in get_case_info("1")
    assert "title2" in get_case_info("1")
    assert "1, 2, 3" in get_case_info("1")


def test_main(mocker):
    mocker.patch.object(
        demisto, "incident", return_value={"CustomFields": {"caseid": "1"}}
    )
    mocker.patch(
        "SekoiaXDRPrintCase.get_case_info",
        return_value="### Case Info:\n\
        |title|description|status|priority|related alerts|\n\
        |---|---|---|---|---|\n\
        | title1 | description1 | Status1 | Priority1 | 1, 2, 3 |\n",
    )
    mocker.patch.object(demisto, "results")

    main()
    assert (
        demisto.results.call_args[0][0]["HumanReadable"]
        == "### Case Info:\n\
        |title|description|status|priority|related alerts|\n\
        |---|---|---|---|---|\n\
        | title1 | description1 | Status1 | Priority1 | 1, 2, 3 |\n"
    )
