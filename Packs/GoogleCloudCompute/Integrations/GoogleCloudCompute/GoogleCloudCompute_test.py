import pytest
from GoogleCloudCompute import parse_resource_ids, parse_firewall_rule, \
    parse_metadata_items, parse_labels


class TestHelperFunctions:
    def test_parse_resource_ids(self):
        """
        Given:
            - resource ids with 2 items and spaces between them
        When:
            - calling function parse_resource_ids
        Then:
            - The function should return a list of items with no spaces
        :return:
        """
        resource_ids = 'test, test 1'
        expected = ['test', 'test1']
        actual = parse_resource_ids(resource_ids)
        assert actual == expected

    def test_parse_firewall_rule__invalid(self):
        """
        Given:
            - invalid firewall rule
        When:
            - calling function parse_firewall_rule
        Then:
            - The function should raise a value error
        """
        invalid_firewall_rule = 'name=abc,ports=1234'
        with pytest.raises(ValueError):
            parse_firewall_rule(invalid_firewall_rule)

        invalid_firewall_rule = 'ipprotocol=abc,name=1234'
        with pytest.raises(ValueError):
            parse_firewall_rule(invalid_firewall_rule)

        invalid_firewall_rule = ''
        with pytest.raises(ValueError):
            parse_firewall_rule(invalid_firewall_rule)

    def test_parse_firewall_rule__valid(self):
        """
        Given:
            - multiple valid firewall rules
        When:
            - calling function parse_firewall_rule
        Then:
            - The function should return a list with firewall rules
        """
        expected = [{'IPProtocol': 'abc', 'ports': ['123']}, {'IPProtocol': 'a', 'ports': ['1']}]
        actual = parse_firewall_rule('ipprotocol=abc,ports=123;ipprotocol=a,ports=1')
        assert actual == expected

    def test_parse_metadata_items__invalid(self):
        """
        Given:
            - invalid metadata item
        When:
            - calling function parse_metadata_items
        Then:
            - The function should raise a value error
        """
        invalid_metadata_item = 'name=abc,value=1234'
        with pytest.raises(ValueError):
            parse_metadata_items(invalid_metadata_item)

        invalid_metadata_item = 'key=abc,name=1234'
        with pytest.raises(ValueError):
            parse_metadata_items(invalid_metadata_item)

        invalid_metadata_item = ''
        with pytest.raises(ValueError):
            parse_metadata_items(invalid_metadata_item)

    def test_parse_metadata_items__valid(self):
        """
        Given:
            - multiple valid metadata items
        When:
            - calling function parse_metadata_items
        Then:
            - The function should return a list with metadata items
        """
        expected = [{'key': 'abc', 'value': '123'}, {'key': 'a', 'value': '1'}]
        actual = parse_metadata_items('key=abc,value=123;key=a,value=1')
        assert actual == expected

    def test_parse_labels__invalid(self):
        """
        Given:
            - invalid labels
        When:
            - calling function parse_metadata_items
        Then:
            - The function should raise a value error
        """
        invalid_label_str = 'name=abc,value=1234'
        with pytest.raises(ValueError):
            parse_labels(invalid_label_str)

        invalid_label_str = 'key=abc,name=1234'
        with pytest.raises(ValueError):
            parse_labels(invalid_label_str)

        invalid_label_str = ''
        with pytest.raises(ValueError):
            parse_labels(invalid_label_str)

    def test_parse_labels__valid(self):
        """
        Given:
            - multiple valid labels
        When:
            - calling function parse_labels
        Then:
            - The function should return a list with lower cased labels
        """
        expected = {'a': 'test', 'abc': '123'}
        actual = parse_labels('key=ABC,value=123;key=a,value=TEST')
        assert actual == expected
