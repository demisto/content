
CSV_STRING_1 = "header1,header2,header3\r\n" \
               "col1,col2,col3\r\n" \
               "col1,col2,col3"

CSV_STRING_2 = "header1,header2,header3\r\n" \
               "col1,\"col2_1\r\ncol2_2\",col3\r\n" \
               "col1,col2,col3"

CSV_STRING_3 = "header1,header2,header3"

CSV_STRING_4 = "header1,header2,header3\r\n" \
               "col1,\"col2_1\r\n" \
               "col2_2\r\n" \
               "col2_3\",col3\r\n" \
               "col1,col2,col3"

CSV_STRING_5 = "header1,header2,header3\r\n" \
               "\r\n" \
               "col1,\"col2_1\r\n" \
               "col2_2\r\n" \
               "col2_3\",col3\r\n" \
               "col1,col2,col3"

CSV_STRING_6 = "header1,header2,header3\r\n" \
               "\r\n" \
               "col1,\"col2_1\r\n" \
               "col2_2\r\n" \
               "\r\n" \
               "col2_3\",col3\r\n" \
               "col1,col2,col3"

CSV_STRING_7 = "col_1,col_2,col_3,col_4,col_5,col_6,col_7,col_8,col_9,col_10,col_11,col_12\r\n" \
               "data_1,data_2,data_3,data_4,\"data_5_1\r\n" \
               "data_5_2\",data_6,data_7,data_8,data_9,data_10,data_11,\"data_12_1\r\n" \
               "data_12_2\r\n" \
               "data_12_3\""

CSV_STRING_8 = "col\r\n\"data1\r\ndata2\r\ndata3\""

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
        "header2": "col2_1\ncol2_2",
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
        "header2": "col2_1\ncol2_2\ncol2_3",
        "header3": "col3"
    },
    {
        "header1": "col1",
        "header2": "col2",
        "header3": "col3"
    }
]

RESULT_DICT_6 = [
    {
        "header1": "col1",
        "header2": "col2_1\ncol2_2\n\ncol2_3",
        "header3": "col3"
    },
    {
        "header1": "col1",
        "header2": "col2",
        "header3": "col3"
    }
]


RESULT_DICT_7 = [
    {
        "col_1": "data_1",
        "col_2": "data_2",
        "col_3": "data_3",
        "col_4": "data_4",
        "col_5": "data_5_1\ndata_5_2",
        "col_6": "data_6",
        "col_7": "data_7",
        "col_8": "data_8",
        "col_9": "data_9",
        "col_10": "data_10",
        "col_11": "data_11",
        "col_12": "data_12_1\ndata_12_2\ndata_12_3"
    }
]

CONTEXT_RESULT_DICT_2 = [
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

CONTEXT_RESULT_DICT_4 = [
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

CONTEXT_RESULT_DICT_7 = [
    {
        "col_1": "data_1",
        "col_2": "data_2",
        "col_3": "data_3",
        "col_4": "data_4",
        "col_5": "data_5_1 data_5_2",
        "col_6": "data_6",
        "col_7": "data_7",
        "col_8": "data_8",
        "col_9": "data_9",
        "col_10": "data_10",
        "col_11": "data_11",
        "col_12": "data_12_1 data_12_2 data_12_3"
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
    assert result == RESULT_DICT_6


def test_csvstr_to_list_7():
    from Tanium import csvstr_to_list
    res = csvstr_to_list(CSV_STRING_7)
    assert res == RESULT_DICT_7


def test_format_context():
    from Tanium import format_context
    res = format_context(RESULT_DICT_2)
    assert res == CONTEXT_RESULT_DICT_2

    res = format_context(RESULT_DICT_4)
    assert res == CONTEXT_RESULT_DICT_4

    res = format_context(RESULT_DICT_7)
    assert res == CONTEXT_RESULT_DICT_7
