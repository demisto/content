import unittest
from WhereFieldEquals import where_field_equals


class WhereFieldEquals(unittest.TestCase):
    def test_where_field_equals_hebrew(self):
        """
        Given: list of dictionaries containing hebrew characters
        When: Finding fields that contain the given value under the given key.
        Then: Return properly formatted tuple containing a human readable representation
        and a dictionary containing the correct context.
        """
        args = {
            "value":
            '[{ "name": "מה זה", "type": "IP" }, {  "name": "myFile.txt", "type": '
            '"File"  }, { "name": "172.0.0.2", "type": "IP" }]',
            "field":
            "type",
            "equalTo":
            "IP",
            "getField":
            "name"
        }
        expected_result = '["מה זה","172.0.0.2"]'
        recieved_result = where_field_equals(args)

        assert expected_result == recieved_result

    def test_where_field_equals_latin_i(self):
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
        recieved_result = where_field_equals(args)
        assert expected_result == recieved_result

    def test_where_field_equals_missing_get_field(self):
        """
        Given: list of dictionaries while missing the getField argument.
        When: Finding fields that contain the given value under the given key.
        Then: Return properly formatted tuple containing a human readable representation
        and a dictionary containing the correct context.
        """
        args = {
            "value":
            '[{ "name": "Testing", "type": "IP" }, {  "name": "myFile.txt", "type": '
            '"File"  }, { "name": "172.0.0.2", "type": "IP" }]',
            "field":
            "type",
            "equalTo":
            "IP"
        }
        expected_result = '[{"name":"Testing","type":"IP"},{"name":"172.0.0.2","type":"IP"}]'

        recieved_result = where_field_equals(args)
        assert expected_result == recieved_result

    def test_where_field_equals_malformed(self):
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
        recieved_result = where_field_equals(args)
        assert expected_result == recieved_result
