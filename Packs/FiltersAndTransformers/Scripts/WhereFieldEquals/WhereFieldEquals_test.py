import unittest
from WhereFieldEquals import where_field_equals


class WhereFieldEquals(unittest.TestCase):
    @staticmethod
    def test_where_field_equals_hebrew():
        """
        Given: list of dictionaries containing hebrew characters
        When: Finding fields that contain the given value under the given key.
        Then: Return properly formatted tuple containing a human readable representation
        and a dictionary containing the correct context.
        """
        args = {
            "value":
            '[{ "name": "מה זה", "type": "IP" }, {  "name": "myFile.txt", "type": '
            '"File"  }, { "name": "172.0.0.2", "type": "IP" }, "somestring"]',
            "field":
            "type",
            "equalTo":
            "IP",
            "getField":
            "name"
        }
        expected_result = '["מה זה","172.0.0.2"]'
        received_result = where_field_equals(args)

        assert expected_result == received_result

    @staticmethod
    def test_where_field_equals_latin_i():
        """
        Given: list of dictionaries containing the latin ł characters
        When: Finding fields that contain the given value under the given key.
        Then: Return properly formatted tuple containing a human readable representation
        and a dictionary containing the correct context.
        """
        args = {
            "value":
            '[{ "name": "łłłłł", "type": "IP" }, {  "name": "myFile.txt", "type": '
            '"File"  }, { "name": "172.0.0.2", "type": "IP" }]',
            "field":
            "type",
            "equalTo":
            "IP",
            "getField":
            "name"
        }
        expected_result = '["łłłłł","172.0.0.2"]'
        received_result = where_field_equals(args)
        assert expected_result == received_result

    @staticmethod
    def test_where_field_equals_missing_get_field():
        """
        Given: list of dictionaries while missing the getField argument.
        When: Finding fields that contain the given value under the given key.
        Then: Return properly formatted tuple containing a human readable representation
        and a dictionary containing the correct context.
        """
        args = {
            "value": '[{ "name": "Testing", "text": "Hello", "type": "IP" }, '
                     '{ "name": "myFile.txt", "type": "IP" }, '
                     '{ "name": "172.0.0.2", "text": "World", "type": "IP" }]',
            "field": "type",
            "equalTo": "IP",
            "getField": "text",
        }
        expected_result = '["Hello","World"]'

        received_result = where_field_equals(args)
        assert expected_result == received_result

    @staticmethod
    def test_where_field_equals_json_value():
        """
        Given: list of dictionaries while missing the getField argument.
        When: Finding fields that contain the given value under the given key.
        Then: Return properly formatted tuple containing a human readable representation
        and a dictionary containing the correct context.
        """
        args = {
            "value": [
                {"name": "Testing", "text": "Hello", "type": "IP"},
                {"name": "myFile.txt", "type": "IP"},
                {"name": "172.0.0.2", "text": "World", "type": "IP"},
            ],
            "field": "type",
            "equalTo": "IP",
            "getField": "text",
        }
        expected_result = '["Hello","World"]'

        received_result = where_field_equals(args)
        assert expected_result == received_result

    @staticmethod
    def test_where_field_equals__no_stringify():
        """
        Given: list of dictionaries.
        When: disabling the stringify option.
        Then: Return a list of relevant field values.
        """
        args = {
            "value": [
                {
                    "NetworkType": "Internal",
                    "Address": "test1@demisto.com",
                },
                {
                    "NetworkType": "Internal",
                    "Address": "test2@demisto.com",
                },
                {
                    "NetworkType": "External",
                    "Address": "test3@demisto.com",
                },
                {
                    "NetworkType": "Internal",
                    "Address": "test4@demisto.com",
                }
            ],
            "field": "NetworkType",
            "equalTo": "Internal",
            "getField": "Address",
            "stringify": "false",
        }
        expected_result = ["test1@demisto.com", "test2@demisto.com", "test4@demisto.com"]

        received_result = where_field_equals(args)
        assert expected_result == received_result

    @staticmethod
    def test_where_field_equals_malformed():
        """
        Given: list of dictionaries where some keys are not present in all dictionaries.
        When: Finding fields that contain the given value under the given key.
        Then: Return properly formatted tuple containing a human readable representation
        and a dictionary containing the correct context.
        """
        args = {
            "value":
            '[{ "name": "מה זה", "type": "IP" }, {  "name": "myFile.txt", "type": '
            '"File"  }, { "name": "172.0.0.2", "type_1": "IP" }]',
            "field":
            "type",
            "equalTo":
            "IP",
            "getField":
            "name"
        }
        expected_result = "מה זה"
        received_result = where_field_equals(args)
        assert expected_result == received_result
