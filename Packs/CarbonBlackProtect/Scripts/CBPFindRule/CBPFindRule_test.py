import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_cbp_find_rule(mocker):
    from CBPFindRule import cbp_find_rule

    args = {"hash": "some_hash"}
    rule = [{"Type": 3, "Contents": [{"hash": "some_hash", "fileState": 1}]}]
    mocker.patch.object(demisto, "executeCommand", return_value=rule)
    mocker.patch.object(demisto, "results")
    cbp_find_rule(args)
    res = demisto.results
    content = res.call_args[0][0]
    expected_res = [
        {"Type": 1, "ContentsFormat": "markdown", "Contents": "Hash some_hash is in state **Unapproved**\n"},
        {"Type": 1, "ContentsFormat": "table", "Contents": [{"hash": "some_hash", "fileState": 1}]},
    ]
    assert expected_res == content
