
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

RAW_JSON_RESPONSE_2 = [
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
                    "col2_1",
                    "col2_2"
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

RAW_JSON_RESPONSE_3 = [
    {
        "row0": [
            {
                "column.display_name": "header1",
                "column.result_type": "DataSize",
                "column.values": [
                    None
                ],
                "column.what_hash": 0
            },
            {
                "column.display_name": "header2",
                "column.result_type": "NumericDecimal",
                "column.values": [
                    "data_2",
                ],
                "column.what_hash": 0
            },
            {
                "column.display_name": "header3",
                "column.result_type": "NumericDecimal",
                "column.values": [
                    "data_3"
                ],
                "column.what_hash": 0
            },
            {
                "column.display_name": "header4",
                "column.result_type": "NumericDecimal",
                "column.values": [
                    "data_4"
                ],
                "column.what_hash": 0
            },
            {
                "column.display_name": "header5",
                "column.result_type": "NumericDecimal",
                "column.values": [
                    "data_5_1",
                    "data_5_2"
                ],
                "column.what_hash": 0
            },
            {
                "column.display_name": "header6",
                "column.result_type": "NumericDecimal",
                "column.values": [
                    "data_6"
                ],
                "column.what_hash": 0
            },
            {
                "column.display_name": "header7",
                "column.result_type": "NumericDecimal",
                "column.values": [
                    "data_7"
                ],
                "column.what_hash": 0
            },
            {
                "column.display_name": "header8",
                "column.result_type": "NumericDecimal",
                "column.values": [
                    "data_8_1",
                    "data_8_2",
                    "data_8_3"
                ],
                "column.what_hash": 0
            },
        ]
    },
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

RESULT_DICT_3 = [
    {
        "header1": None,
        "header2": "data_2",
        "header3": "data_3",
        "header4": "data_4",
        "header5": "data_5_1\ndata_5_2",
        "header6": "data_6",
        "header7": "data_7",
        "header8": "data_8_1\ndata_8_2\ndata_8_3"
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

CONTEXT_RESULT_DICT_2 = [
    {
        "header1": "col1",
        "header2": ["col2_1", "col2_2"],
        "header3": "col3"
    },
    {
        "header1": "col1",
        "header2": "col2",
        "header3": "col3"
    }
]

CONTEXT_RESULT_DICT_3 = [
    {
        "header1": None,
        "header2": "data_2",
        "header3": "data_3",
        "header4": "data_4",
        "header5": ["data_5_1", "data_5_2"],
        "header6": "data_6",
        "header7": "data_7",
        "header8": ["data_8_1", "data_8_2", "data_8_3"]
    }
]

CONTEXT_RESULT_DICT_4 = [
    {
        "header1": "col1",
        "header2": ["col2_1", "col2_2", "col2_3"],
        "header3": "col3"
    },
    {
        "header1": "col1",
        "header2": "col2",
        "header3": "col3"
    }
]


def test_raw_response_to_json_1():
    from Tanium import raw_response_to_json
    res = raw_response_to_json(RAW_JSON_RESPONSE_1)
    assert res == RESULT_DICT_1


def test_raw_response_to_json_2():
    from Tanium import raw_response_to_json
    res = raw_response_to_json(RAW_JSON_RESPONSE_2)
    assert res == RESULT_DICT_2


def test_raw_response_to_json_3():
    from Tanium import raw_response_to_json
    res = raw_response_to_json(RAW_JSON_RESPONSE_3)
    assert res == RESULT_DICT_3


def test_format_context():
    from Tanium import format_context
    res = format_context(RESULT_DICT_2)
    assert res == CONTEXT_RESULT_DICT_2

    res = format_context(RESULT_DICT_3)
    assert res == CONTEXT_RESULT_DICT_3

    res = format_context(RESULT_DICT_4)
    assert res == CONTEXT_RESULT_DICT_4
