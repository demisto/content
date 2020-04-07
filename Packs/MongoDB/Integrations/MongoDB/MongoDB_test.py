import pytest
from MongoDB import convert_id_to_object_id, convert_object_id_to_str
from bson.objectid import ObjectId

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
