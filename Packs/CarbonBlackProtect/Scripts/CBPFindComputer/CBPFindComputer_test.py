import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_cbp_find_computer(mocker):
    from CBPFindComputer import cbp_find_computer

    args = {"limit": 2}
    computer = [
        {"Type": 3, "Contents": {"getTicketResponse": {"some_info": {"info": "test"}}}},
        {
            "Type": 3,
        },
    ]
    mocker.patch.object(demisto, "executeCommand", return_value=computer)
    mocker.patch.object(demisto, "results")
    cbp_find_computer(args)
    res = demisto.results
    content = res.call_args[0][0]
    expected_res = [
        {"Type": 1, "ContentsFormat": "table", "Contents": {"getTicketResponse": {"some_info": {"info": "test"}}}},
        {"Type": 1, "ContentsFormat": "text", "Contents": "No matches."},
    ]
    assert expected_res == content
