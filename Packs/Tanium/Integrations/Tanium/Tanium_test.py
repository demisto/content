
RAW_JSON_RESPONSE_1 = [
    {
        "row0": [
            {
                "column.display_name": "header1",
                "column.result_type": "DataSize",
                "column.values": [
                    "col1"
                ],
                "column.what_hash": 0
            },
            {
                "column.display_name": "header2",
                "column.result_type": "NumericDecimal",
                "column.values": [
                    "col2"
                ],
                "column.what_hash": 0
            },
            {
                "column.display_name": "header3",
                "column.result_type": "NumericDecimal",
                "column.values": [
                    "col3"
                ],
                "column.what_hash": 0
            }
        ]
    },
    {
        "row1": [
            {
                "column.display_name": "header1",
                "column.result_type": "DataSize",
                "column.values": [
                    "col1"
                ],
                "column.what_hash": 0
            },
            {
                "column.display_name": "header2",
                "column.result_type": "NumericDecimal",
                "column.values": [
                    "col2"
                ],
                "column.what_hash": 0
            },
            {
                "column.display_name": "header3",
                "column.result_type": "NumericDecimal",
                "column.values": [
                    "col3"
                ],
                "column.what_hash": 0
            }
        ]
    }
]

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


def test_raw_response_to_json_1():
    from Tanium import raw_response_to_json
    res = raw_response_to_json(RAW_JSON_RESPONSE_1)
    assert res == RESULT_DICT_1


def test_format_context():
    from Tanium import format_context
    res = format_context(RESULT_DICT_2)
    assert res == CONTEXT_RESULT_DICT_2

    res = format_context(RESULT_DICT_4)
    assert res == CONTEXT_RESULT_DICT_4

    res = format_context(RESULT_DICT_7)
    assert res == CONTEXT_RESULT_DICT_7
