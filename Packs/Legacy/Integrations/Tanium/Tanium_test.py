import demistomock as demisto
from CommonServerPython import *

CSV_STRING_1 = "header1,header2,header3\r\ncol1,col2,col3\r\ncol1,col2,col3"
CSV_STRING_2 = "header1,header2,header3\r\ncol1,\"col2_1\r\ncol2_2\",col3\r\ncol1,col2,col3"
CSV_STRING_3 = "header1,header2,header3"

RESULT_DICT_1 = [
    {
        "header1": "col1",
        "header2": "col2",
        "header3": "col3"
    },
    {
        "header1": "col1",
        "header2": "col2",
        "header3": "col3"
    }
]

RESULT_DICT_2 = [
    {
        "header1": "col1",
        "header2": "col2_1 col2_2",
        "header3": "col3"
    },
    {
        "header1": "col1",
        "header2": "col2",
        "header3": "col3"
    }
]


def test_csvstr_to_list_1(mocker):
    from Tanium import csvstr_to_list
    mocker.patch.object(demisto, 'params', return_value={
        "proxy": True,
        "credentials": {
            "identifier": "iiii",
            "password": "iiii"
        },
        "host": "iii",
        "port": "443"
    })
    result = csvstr_to_list(CSV_STRING_1)
    assert result == RESULT_DICT_1


def test_csvstr_to_list_2(mocker):
    from Tanium import csvstr_to_list
    mocker.patch.object(demisto, 'params', return_value={
        "proxy": True,
        "credentials": {
            "identifier": "iiii",
            "password": "iiii"
        },
        "host": "iii",
        "port": "443"
    })
    result = csvstr_to_list(CSV_STRING_2)
    assert result == RESULT_DICT_2


def test_csvstr_to_list_3(mocker):
    from Tanium import csvstr_to_list
    mocker.patch.object(demisto, 'params', return_value={
        "proxy": True,
        "credentials": {
            "identifier": "iiii",
            "password": "iiii"
        },
        "host": "iii",
        "port": "443"
    })
    result = csvstr_to_list(CSV_STRING_3)
    assert result == []
