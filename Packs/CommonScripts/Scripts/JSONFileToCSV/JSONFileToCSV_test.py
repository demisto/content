import os
import demistomock as demisto

from CommonServerPython import entryTypes


TEST_DATA_DIR = "test_data"


def getFilePath_mock(entry_id):
    raise Exception("getFilePath_" + entry_id)


def test_json_to_csv():
    from JSONFileToCSV import json_to_csv
    data = [
        {"a": 1, "b": 2, "c": 3},
        {"a": 11, "b": 12, "c": 13},
        {"a": 21, "b": 22, "c": 23},
    ]
    expected1 = "\r\n".join(["a,b,c", "1,2,3", "11,12,13", "21,22,23"])
    expected2 = "\r\n".join(["a|b|c", "1|2|3", "11|12|13", "21|22|23"])
    result1 = json_to_csv(data, ",")
    result2 = json_to_csv(data, "|")

    assert result1 == expected1
    assert result2 == expected2


def test_main(mocker):
    from JSONFileToCSV import main

    json_path = os.path.join(TEST_DATA_DIR, "sanity.json")

    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "getFilePath", return_value={"path": json_path})
    mocker.patch.object(demisto, "uniqueFile", return_value="out.csv")
    mocker.patch.object(demisto, "investigation", return_value={"id": os.path.join(TEST_DATA_DIR, "sanity")})
    main("mock", "sanity_out.csv", ",")
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]["Type"] == entryTypes["file"]
    assert results[0]["File"] == "sanity_out.csv"
    assert results[0]["FileID"] == "out.csv"

    mocker.patch.object(demisto, "getFilePath", side_effect=getFilePath_mock)
    return_error_mock = mocker.patch("JSONFileToCSV.return_error")
    try:
        main("mock", "sanity_out.csv", ",")
    except:  # noqa: E722
        pass
    assert return_error_mock.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = return_error_mock.call_args[0]
    assert len(results) == 1
    assert results[0] == "Failed to get the file path for entry: mock the error message was getFilePath_mock"
