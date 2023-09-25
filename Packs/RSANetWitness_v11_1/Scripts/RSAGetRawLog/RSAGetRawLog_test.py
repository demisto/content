import demistomock as demisto  # noqa: F401
import pytest
import RSAGetRawLog
from RSAGetRawLog import is_json, merge_dict, create_id_set, get_raw_log, get_metas_log, main


def test_is_json():
    assert is_json('{"test": "test"}') == {"test": "test"}


def test_merge_dict():
    assert merge_dict({"a": "a"}, {"b": "b"}) == {"a": "a", "b": "b"}


def test_create_id_set():
    assert create_id_set([{"id": 1}, {"id": 2}, {"id": 3}]) == [1, 2, 3]


def test_get_raw_log(mocker):
    mocker.patch.object(RSAGetRawLog, "isCommandAvailable", return_value=True)
    mocker.patch.object(demisto, 'executeCommand',
                        return_value=[{'Contents': {"logs": ["log1", "log2"]}}])

    assert get_raw_log("0", "1.2.3.4", "1234") == ["log1", "log2"]


def test_get_metas_log(mocker):
    mocker.patch.object(RSAGetRawLog, "isCommandAvailable", return_value=True)
    mocker.patch.object(demisto, 'executeCommand',
                        return_value=[{'Contents': {}, "EntryContext": {"NetWitness.Events": "Test Value"}}])

    assert get_metas_log("0", "1.2.3.4", "1234") == "Test Value"


@pytest.mark.parametrize(
    "alerts_incident, expected_results",
    [
        (
            {
                "CustomFields":
                    {
                        "rsaalerts": [],
                        "rsarawlogslist": [],
                        "rsametasevents": []
                    }
            },
            "No alert/event was found in this incident."
        ),
        (
            {
                "CustomFields":
                    {
                        "rsaalerts": [{"id": 1}, {"id": 2}, {"id": 3}],
                        "rsarawlogslist": [{"id": 1}, {"id": 2}, {"id": 3}],
                        "rsametasevents": []
                    }
            },
            "Nothing has changed !"
        ),
        (
            {
                "CustomFields":
                    {
                        "rsaalerts": [
                            {
                                "id": 1,
                                "title": "title",
                                "created": "2023-08-29T11:46:22.529Z",
                                "events": [{"eventSource": "1.2.3.4:56005", "eventSourceId": "157970808811"}]
                            }],
                        "rsarawlogslist": [{"id": 2}, {"id": 3}],
                        "rsametasevents": []
                    }
            },
            "1 raw log inserts !"
        ),
    ],
)
def test_main(
    mocker, alerts_incident, expected_results
):
    mocker_result = mocker.patch.object(demisto, 'results')
    mocker.patch.object(RSAGetRawLog, "get_raw_log", return_value=[{"log": "value"}])
    mocker.patch.object(RSAGetRawLog, "get_metas_log", return_value=[{"metas": "value"}])
    mocker.patch("RSAGetRawLog.demisto.incident", return_value=alerts_incident)

    main()
    result_content = mocker_result.call_args.args[0].get('HumanReadable')
    assert result_content == expected_results
