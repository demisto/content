
CSV_STRING_1 = "header1,header2,header3\r\n" \
               "col1,col2,col3\r\n" \
               "col1,col2,col3"

CSV_STRING_2 = "header1,header2,header3\r\n" \
               "col1,\"col2_1\r\ncol2_2\",col3\r\n" \
               "col1,col2,col3"

CSV_STRING_3 = "header1,header2,header3"

CSV_STRING_4 = "header1,header2,header3\r\n" \
               "col1,\"col2_1\r\ncol2_2\r\ncol2_3\",col3\r\n" \
               "col1,col2,col3"

CSV_STRING_5 = "header1,header2,header3\r\n" \
               "\r\ncol1,\"col2_1\r\ncol2_2\r\ncol2_3\",col3\r\n" \
               "col1,col2,col3"

CSV_STRING_6 = "header1,header2,header3\r\n" \
               "\r\ncol1,\"col2_1\r\ncol2_2\r\n\r\ncol2_3\",col3\r\n" \
               "col1,col2,col3"

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

RESULT_DICT_4 = [
    {
        "header1": "col1",
        "header2": "col2_1 col2_2 col2_3",
        "header3": "col3"
    },
    {
        "header1": "col1",
        "header2": "col2",
        "header3": "col3"
    }
]


def test_csvstr_to_list_1():
    from Tanium import csvstr_to_list
    result = csvstr_to_list(CSV_STRING_1)
    assert result == RESULT_DICT_1


def test_csvstr_to_list_2():
    from Tanium import csvstr_to_list
    result = csvstr_to_list(CSV_STRING_2)
    assert result == RESULT_DICT_2


def test_csvstr_to_list_3():
    from Tanium import csvstr_to_list
    result = csvstr_to_list(CSV_STRING_3)
    assert result == []


def test_csvstr_to_list_4():
    from Tanium import csvstr_to_list
    result = csvstr_to_list(CSV_STRING_4)
    assert result == RESULT_DICT_4


def test_csvstr_to_list_5():
    from Tanium import csvstr_to_list
    result = csvstr_to_list(CSV_STRING_5)
    assert result == RESULT_DICT_4


def test_csvstr_to_list_6():
    from Tanium import csvstr_to_list
    result = csvstr_to_list(CSV_STRING_6)
    assert result == RESULT_DICT_4
