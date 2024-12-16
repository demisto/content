import copy
from datetime import datetime

import pytest
from bson.objectid import ObjectId

from MongoDB import convert_id_to_object_id, convert_object_id_to_str, convert_str_to_datetime, Client, search_query, \
    format_sort, pipeline_query_command, parse_and_validate_bulk_update_arguments, bulk_update_command, update_entry_command
from CommonServerPython import DemistoException

id_to_obj_inputs = [
    (
        [{"_id": "5e4412f230c5b8f63a7356ba"}],
        [{"_id": ObjectId("5e4412f230c5b8f63a7356ba")}],
    ),
    (
        {"_id": "5e4412f230c5b8f63a7356ba"},
        {"_id": ObjectId("5e4412f230c5b8f63a7356ba")},
    ),
    (
        {"_id": {"$gte": "5e4412f230c5b8f63a7356ba"}},
        {"_id": {"$gte": ObjectId("5e4412f230c5b8f63a7356ba")}},
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
    assert res['_id'] == '5e4412f230c5b8f63a7356ba'


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
        assert raw['time'] == 5

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
        assert raw == 'str'


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


class TestFormatSort:
    def test_format_sort_correctly(self):
        """
        Given:
            a sort string in the correct format
        Then:
            Format the string in the correct format to be used in `pymongo.sort()`
        """
        assert format_sort("field1:asc,field2:desc") == [('field1', 1), ('field2', -1)]
        assert format_sort("field1:asc") == [('field1', 1)]

    def test_format_sort_raises_error(self):
        """
            Given:
            a sort string in the wrong format
        Then:
            raise a ValueError
        """
        with pytest.raises(ValueError):
            format_sort("Wrong:Type")
        with pytest.raises(ValueError):
            format_sort("WrongType")


def test_pipeline_query_command(mocker):
    """
        Given:
            collection - where to search.
            pipeline - json pipeline query

        When:
            calling `pipeline_query_command`

        Then:
            validate the readable output and context
        """
    client = Client(['aaaaa'], 'a', 'b', 'd')
    return_value = [
        {'title': 'test_title', 'color': 'red', 'year': '2019', '_id': '6034a5a62f605638740dba55'},
        {'title': 'test_title', 'color': 'yellow', 'year': '2020', '_id': '6034a5c52f605638740dba57'}
    ]
    mocker.patch.object(client, 'pipeline_query', return_value=return_value)
    readable_outputs, outputs, raw_response = pipeline_query_command(
        client=client,
        collection='test_collection',
        pipeline="[{\"$match\": {\"title\": \"test_title\"}}]"
    )

    expected_context = []
    for item in copy.deepcopy(raw_response):
        item.update({'collection': 'test_collection'})
        expected_context.append(item)

    assert 'Total of 2 entries were found in MongoDB collection' in readable_outputs
    assert outputs.get('MongoDB.Entry(val._id === obj._id && obj.collection === val.collection)') == expected_context


class MockResponse:
    """Mock response for TestUpdateQueryCommands and TestBulkUpdateQueryCommands classes.
    represents a partial SDK response of the update_entry and bulk_update_entries functions.
    """

    def __init__(self, acknowledged, modified_count, upserted_count, upserted_id=False):
        self.acknowledged = acknowledged
        self.modified_count = modified_count
        self.upserted_count = upserted_count
        self.upserted_id = upserted_id


class TestUpdateQueryCommands:
    """Class for update_query_command UTs."""
    client = Client(['aaaaa'], 'a', 'b', 'd')
    case_upsert_with_no_matching_entry = (
        "{\"Name\": \"dummy\"}", "{\"$set\":{\"test\":0}}", True, True, MockResponse(True, 0, 0, 1),
        'A new entry was inserted to the collection.')
    case_upsert_with_one_matching_entry = (
        "{\"Name\": \"dummy\"}", "{\"$set\":{\"test\":0}}", True, True, MockResponse(True, 1, 0, 0),
        'MongoDB: Total of 1 entries has been modified.')
    case_upsert_with_many_matching_entry = (
        "{\"Name\": \"dummy\"}", "{\"$set\":{\"test\":0}}", False, True, MockResponse(True, 5, 0, 0),
        'MongoDB: Total of 5 entries has been modified.')
    case_upsert_with_matching_entry_no_modifications = (
        "{\"Name\": \"dummy\"}", "{\"$set\":{\"test\":0}}", True, True, MockResponse(True, 0, 0, 0),
        'MongoDB: Total of 0 entries has been modified.')
    case_upsert_with_many_matching_entries_update_only_one = (
        "{\"Name\": \"dummy\"}", "{\"$set\":{\"test\":0}}", True, True, MockResponse(True, 1, 0, 0),
        'MongoDB: Total of 1 entries has been modified.')
    case_no_upsert_with_no_matching_entry = (
        "{\"Name\": \"dummy\"}", "{\"$set\":{\"test\":0}}", True, False, MockResponse(True, 0, 0, 0),
        'MongoDB: Total of 0 entries has been modified.')

    update_query_cases = [case_upsert_with_no_matching_entry, case_upsert_with_one_matching_entry,
                          case_upsert_with_many_matching_entry, case_upsert_with_matching_entry_no_modifications,
                          case_upsert_with_many_matching_entries_update_only_one, case_no_upsert_with_no_matching_entry]

    @pytest.mark.parametrize('filter, update, update_one, upsert, response, expected', update_query_cases)
    def test_update_entry_command(self, mocker, filter, update, update_one, upsert, response, expected, client=client):
        """
        Given:
            valid arguments

        When:
            running mongodb-update command in XSOAR

        Then:
            the expected human readable is returned
        """
        mocker.patch.object(client, 'update_entry', return_value=response)
        return_value = update_entry_command(client, "test_collection", filter=filter,
                                            update=update, update_one=update_one, upsert=upsert)
        assert return_value[0] == expected

    case_invalid_filter_argument = ("\"Name\": \"dummy\"}", "{\"$set\":{\"test\":0}}", MockResponse(
        True, 0, 0, 0), 'The `filter` argument is not a valid json. Valid input example: `{"key": "value"}`')
    case_invalid_update_argument = ("{\"Name\": \"dummy\"}", "\"$set\":{\"test\":0}}", MockResponse(
        True, 0, 0, 0), 'The `update` argument is not a valid json. Valid input example: `{"$set": {"key": "value"}`')
    case_invalid_response = (
        "{\"Name\": \"dummy\"}", "{\"$set\":{\"test\":0}}", None, 'Error occurred when trying to enter update entries.')

    invalid_cases = [case_invalid_filter_argument, case_invalid_update_argument, case_invalid_response]

    @pytest.mark.parametrize('filter, update, response, expected', invalid_cases)
    def test_update_entry_command_fail(self, mocker, filter, update, response, expected, client=client):
        """
        Given:
            invalid arguments

        When:
            running mongodb-update command in XSOAR

        Then:
            the expected error message is raised
        """
        mocker.patch.object(client, 'update_entry', return_value=response)
        try:
            update_entry_command(client, "test_collection", filter=filter, update=update)
        except DemistoException as e:
            assert str(e) == expected


class TestBulkUpdateQueryCommands:
    """ Class for bulk_update_query_command UTs. """
    client = Client(['aaaaa'], 'a', 'b', 'd')
    # valid command arguments
    case_single_update_args = ("[{\"Name\": \"dummy\"}]", "[{\"$set\":{\"test\":0}}]",
                               ([{"Name": "dummy"}], [{"$set": {"test": 0}}]))
    case_simple_bulk_update_args = ("[{\"Name\": \"dummy1\"},{\"Name\": \"dummy2\"}]",
                                    "[{\"$set\":{\"test\":1}},{\"$set\":{\"test\":2}}]",
                                    ([{"Name": "dummy1"},
                                      {"Name": "dummy2"}],
                                        [{"$set": {"test": 1}},
                                         {"$set": {"test": 2}}]))
    case_bulk_update_complex_filter = (
        "[{\"$and\": [{\"value\":0,\"another_value\":1}],\"Name\":\"dummy1\",\
            \"less_than\": {\"$lt\":3000}},{\"Name\":\"dummy2\"}]",
        "[{\"$set\":{\"test\":1}},{\"$set\":{\"test\":2}}]",
        ([{"$and": [{"value": 0, "another_value": 1}],
           "less_than": {"$lt": 3000},
           "Name": "dummy1"},
          {"Name": "dummy2"}],
         [{"$set": {"test": 1}},
          {"$set": {"test": 2}}]))
    case_bulk_update_complex_update = (
        "[{\"Name\":\"dummy1\"},{\"Name\":\"dummy2\"}]",
        "[{\"$set\":{\"test\":1,\"value\":2,\"another_value\":{\"sub_value\": 4}}},{\"$set\":{\"test\":2}}]",
        ([{"Name": "dummy1"},
          {"Name": "dummy2"}],
         [{"$set": {"test": 1, "value": 2, "another_value": {"sub_value": 4}}},
          {"$set": {"test": 2}}]))
    case_bulk_update_context_args = ([{"Name": "dummy1"}, {"Name": "dummy2"}],
                                     [{"$set": {"test": 1}}, {"$set": {"test": 2}}],
                                     ([{"Name": "dummy1"},
                                      {"Name": "dummy2"}],
                                      [{"$set": {"test": 1}},
                                         {"$set": {"test": 2}}]))

    # invalid command arguments
    case_missing_brackets = ("{\"Name\": \"dummy1\"},{\"Name\": \"dummy2\"}]",
                             "[{\"$set\":{\"test\":1}},{\"$set\":{\"test\":2}}]",
                             'The `filter` argument must be a json array.')
    case_not_matching_number_of_filters_and_updates = (
        "[{\"Name\": \"dummy1\"},{\"Name\": \"dummy2\"}]", "[{\"$set\":{\"test\":1}}]",
        'The `filter` and `update` arguments must contain the same number of elements.')
    case_invalid_json = ("{\"Name\": \"dummy1\"},{\"Name\": \"dummy2\"]",
                         "[{\"$set\":{\"test\":1}},{\"$set\":{\"test\":2}}]",
                         'The `filter` argument contains an invalid json.')

    @pytest.mark.parametrize('filter, update, expected_output', [
        case_single_update_args,
        case_simple_bulk_update_args,
        case_bulk_update_complex_filter,
        case_bulk_update_complex_update,
        case_bulk_update_context_args
    ])
    def test_parse_and_validate_bulk_update_arguments(self, filter, update, expected_output):
        """
        Given:
            valid arguments for bulk update command

        When:
            running mongodb-bulk-update command in XSOAR

        Then:
            parse_and_validate_bulk_update_arguments will parse validate the filter and update arguments
        """
        filter_list, update_list = parse_and_validate_bulk_update_arguments(filter, update)
        assert filter_list == expected_output[0]
        assert update_list == expected_output[1]

    @pytest.mark.parametrize('filter, update, error_message', [
        case_missing_brackets,
        case_not_matching_number_of_filters_and_updates,
        case_invalid_json
    ])
    def test_parse_and_validate_bulk_update_arguments_fail(self, filter, update, error_message):
        """
        Given:
            invalid arguments for bulk update command

        When:
            running mongodb-bulk-update command in XSOAR

        Then:
            parse_and_validate_bulk_update_arguments will raise an error
        """
        with pytest.raises(DemistoException) as e:
            parse_and_validate_bulk_update_arguments(filter, update)
            assert error_message in str(e.value)

    def test_bulk_update_command(
            self, mocker, client=client, case_simple_bulk_update_args=case_simple_bulk_update_args):
        """
        Given:
            valid arguments for bulk update command

        When:
            running mongodb-bulk-update command in XSOAR

        Then:
            the expected human readable is returned
        """
        response = MockResponse(acknowledged=True, modified_count=1, upserted_count=1)
        mocker.patch.object(client, 'bulk_update_entries', return_value=response)
        return_value = bulk_update_command(
            client, "test_collection", filter=case_simple_bulk_update_args[0],
            update=case_simple_bulk_update_args[1])
        excepted_output = 'MongoDB: Total of 1 entries has been modified.\
            \nMongoDB: Total of 1 entries has been inserted.'
        # 'replace' method is used due to inconsistent spaces in the output
        assert return_value[0].replace(' ', '') == excepted_output.replace(' ', '')
