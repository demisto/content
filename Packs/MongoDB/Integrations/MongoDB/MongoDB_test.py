from datetime import datetime

import pytest
from bson.objectid import ObjectId

from MongoDB import convert_id_to_object_id, convert_object_id_to_str, convert_str_to_datetime, Client, search_query

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


def test_normalize_id():
    res = Client.normalize_id({'_id': ObjectId('5e4412f230c5b8f63a7356ba')})
    assert '5e4412f230c5b8f63a7356ba' == res['_id']


class TestConvertStrToDatetime:
    dict_inputs = [
        {"testing": 123, "time": "ISODate('2020-06-12T08:23:07.000Z')"},
        pytest.param(
            {"testing": 123, "time": "ISODate('2018-06-12T08:23:07.000')"},
            marks=pytest.mark.xfail)
    ]

    @pytest.mark.parametrize("func_input", dict_inputs)
    def test_convert_str_to_datetime(self, func_input):
        res = convert_str_to_datetime(func_input)
        assert isinstance(res['time'], datetime)

    def test_convert_str_to_datetime_no_datetime_obj(self):
        inputs = {1: 2}
        res = convert_str_to_datetime(inputs)
        assert isinstance(res[1], int)

    def test_nested_dict(self):
        """
        Given:
        A nested dict with a timestamp

        When:
        Running a query or insert

        Then:
        Validating all keys in the dict are there and the timestamp is valid

        """
        func_input = {"k": {"$gte": "ISODate('2020-06-12T08:23:07.000Z')"}}
        res = convert_str_to_datetime(func_input)
        assert isinstance(res["k"]["$gte"], datetime)


class TestDatetimeToStr:
    datetime_obj = datetime.strptime('2020-05-19T09:05:28.000Z', '%Y-%m-%dT%H:%M:%S.000Z')
    datetime_str = '2020-05-19T09:05:28.000Z'

    def test_datetime_to_str_dict(self):
        """
        Given:
            dict containing datetime object

        When:
            converting datetimes to strs

        Then:
            validate the value is a string.
        """
        raw = Client.datetime_to_str({'time': self.datetime_obj})
        assert self.datetime_str == raw['time']

    def test_datetime_to_str_list(self):
        """
        Given:
            list containing datetime object

        When:
            converting datetimes to strs

        Then:
            validate the value is a string.
        """
        raw = Client.datetime_to_str([self.datetime_obj])
        assert [self.datetime_str] == raw

    def test_datetime_to_str_str(self):
        """
        Given:
            datetime object

        When:
            converting datetimes to strs

        Then:
            validate the value is a string.
        """
        raw = Client.datetime_to_str(self.datetime_obj)
        assert self.datetime_str == raw

    def test_datetime_to_str_dict_no_datetime(self):
        """
        Given:
            dict containing 5 (int)

        When:
            converting datetimes to strs

        Then:
            validate the value returned is 5
        """
        raw = Client.datetime_to_str({'time': 5})
        assert 5 == raw['time']

    def test_datetime_to_str_list_no_datetime(self):
        """
        Given:
            list containing an int (5) object

        When:
            converting datetimes to strs

        Then:
            validate the value returned is 5.
        """
        raw = Client.datetime_to_str([5])
        assert [5] == raw

    def test_datetime_to_str_str_no_datetime(self):
        """
        Given:
            'str'

        When:
            converting datetimes to strs

        Then:
            validate the value returned is 'str'.
        """
        raw = Client.datetime_to_str('str')
        assert 'str' == raw


class MockedQuery:
    class Limit:
        @staticmethod
        def limit(number):
            return [{'time': TestDatetimeToStr.datetime_obj, '_id': ObjectId('5e4412f230c5b8f63a7356ba')}]

    @classmethod
    def find(cls, query):
        return cls.Limit


def test_query(mocker):
    """
    Given:
        Object with datetime and object id in it

    When:
        Quering object

    Then:
        validate all objects returned are strs.
    """
    client = Client(['aaaaa'], 'a', 'b', 'd')
    mocker.patch.object(Client, 'get_collection', return_value=MockedQuery)
    readable_outputs, outputs, raw_response = search_query(client, 'a', '{}', '50')
    time = raw_response[0]['time']
    _id = raw_response[0]['_id']
    assert isinstance(_id, str)
    assert isinstance(time, str)
