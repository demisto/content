import re
import pytest

from MatchRegexV2 import parse_regex_flags, main


class TestParseRegexFlags:
    @staticmethod
    def test__sanity():
        flags, multiple_matches = parse_regex_flags()
        assert re.I in flags
        assert re.M in flags
        assert multiple_matches

    @staticmethod
    def test__custom_flags():
        flags, multiple_matches = parse_regex_flags('gi')
        assert re.I in flags
        assert re.M not in flags
        assert multiple_matches

    @staticmethod
    def test__custom_flags_without_multiple_match():
        flags, multiple_matches = parse_regex_flags('i')
        assert re.I in flags
        assert re.M not in flags
        assert not multiple_matches

    @staticmethod
    def test__invalid_flags():
        with pytest.raises(ValueError):
            parse_regex_flags('gimh')


class TestMain:
    @staticmethod
    def test__sanity():
        args = {
            'data': 'hello world\nthis is a regex test named "sanity". please consider test named "sanity2".',
            'regex': 'test.*"(.*?)"',
        }
        results = main(args)
        assert not results.outputs
        assert 'test named "sanity"' in results.raw_response
        assert 'test named "sanity2"' in results.raw_response

    @staticmethod
    def test__with_unicode():
        args = {
            'data': 'hello world\nthis is a regex test named "sanity". please consider test named "שלום".',
            'regex': 'test.*"(.*?)"',
        }
        results = main(args)
        assert not results.outputs
        assert 'test named "sanity"' in results.raw_response
        assert 'test named "שלום"' in results.raw_response

    @staticmethod
    def test__multiple_with_group():
        args = {
            'data': 'hello world\nthis is a regex test named "sanity".\nplease consider test named "sanity2".\n',
            'regex': 'test.*"(.*?)".$',
            'group': '1',
        }
        results = main(args)
        assert not results.outputs
        assert 'sanity' in results.raw_response
        assert 'sanity2' in results.raw_response

    @staticmethod
    def test__single_with_group():
        args = {
            'data': 'hello world\nthis is a regex test named "sanity".\nplease consider test named "sanity2".\n',
            'regex': 'test.*"(.*?)".$',
            'group': '1',
            'flags': 'im',
        }
        results = main(args)
        assert not results.outputs
        assert 'sanity' in results.raw_response
        assert 'sanity2' not in results.raw_response

    @staticmethod
    def test__with_high_group():
        args = {
            'data': 'hello world\nthis is a regex test named "sanity". please consider test named "sanity2".',
            'regex': 'test.*"(.*?)"',
            'group': '5',
        }
        results = main(args)
        assert not results.outputs
        assert 'test named "sanity"' in results.raw_response
        assert 'test named "sanity2"' in results.raw_response

    @staticmethod
    def test__with_invalid_group():
        args = {
            'data': 'hello world\nthis is a regex test named "sanity". please consider test named "sanity2".',
            'regex': 'test.*"(.*?)"',
            'group': 'not a number',
        }
        with pytest.raises(ValueError):
            main(args)
