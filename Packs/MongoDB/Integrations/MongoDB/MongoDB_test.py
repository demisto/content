import pytest
from MongoDB import convert_id_to_object_id, convert_object_id_to_str, convert_str_to_datetime
from bson.objectid import ObjectId
from datetime import datetime

id_to_obj_inputs = [
    (
        [{"_id": "5e4412f230c5b8f63a7356ba"}],
        [{"_id": ObjectId("5e4412f230c5b8f63a7356ba")}],
    ),
    (
        {"_id": "5e4412f230c5b8f63a7356ba"},
        {"_id": ObjectId("5e4412f230c5b8f63a7356ba")},
    ),
    ({}, {}),
    ({"id": 1}, {"id": 1}),
]

entry_input_lst = [{"testing": 123, "time": "ISODate('2020-06-12T08:23:07.000Z')"},
                   pytest.param({"testing": 123, "time": "ISODate('2018-06-12T08:23:07.000')"}, marks=pytest.mark.xfail)]


@pytest.mark.parametrize("func_input, expected", id_to_obj_inputs)
def test_convert_id_to_object_id(func_input, expected):
    assert expected == convert_id_to_object_id(func_input)


object_to_id = [
    ([ObjectId("5e4412f230c5b8f63a7356ba")], ["5e4412f230c5b8f63a7356ba"]),
    (
        [ObjectId("5e4412f230c5b8f63a7356ba"), ObjectId("5e4412f230c5b8f63a7356ba")],
        ["5e4412f230c5b8f63a7356ba", "5e4412f230c5b8f63a7356ba"],
    ),
]


@pytest.mark.parametrize("func_input, expected", object_to_id)
def test_convert_object_id_to_str(func_input, expected):
    assert expected == convert_object_id_to_str(func_input)


@pytest.mark.parametrize("func_input", entry_input_lst)
def test_convert_str_to_datetime(func_input):
    res = convert_str_to_datetime(func_input)
    assert type(res['time']) is datetime


@pytest.mark.parametrize("func_input", entry_input_lst)
def test_convert_datetime_to_str(func_input):
    res = convert_str_to_datetime(func_input)
    assert type(res['time']) is datetime
