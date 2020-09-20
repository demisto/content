import re
import pytest

import demistomock as demisto
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
    def test__sanity(mocker):
        args = {
            'data': 'hello world\nthis is a regex test named "sanity". please consider test named "sanity2".',
            'regex': 'test.*"(.*?)"',
        }
        mocker.patch.object(demisto, 'executeCommand')
        results = main(args)
        assert not results.outputs
        assert 'test named "sanity"' in results.raw_response
        assert 'test named "sanity2"' in results.raw_response

    @staticmethod
    def test__with_unicode(mocker):
        args = {
            'data': 'hello world\nthis is a regex test named "sanity". please consider test named "שלום".',
            'regex': 'test.*"(.*?)"',
        }
        mocker.patch.object(demisto, 'executeCommand')
        results = main(args)
        assert not results.outputs
        assert 'test named "sanity"' in results.raw_response
        assert 'test named "שלום"' in results.raw_response

    @staticmethod
    def test__multiple_with_group(mocker):
        args = {
            'data': 'hello world\nthis is a regex test named "sanity".\nplease consider test named "sanity2".\n',
            'regex': 'test.*"(.*?)".$',
            'group': '1',
        }
        mocker.patch.object(demisto, 'executeCommand')
        results = main(args)
        assert not results.outputs
        assert 'sanity' in results.raw_response
        assert 'sanity2' in results.raw_response

    @staticmethod
    def test__single_with_group(mocker):
        args = {
            'data': 'hello world\nthis is a regex test named "sanity".\nplease consider test named "sanity2".\n',
            'regex': 'test.*"(.*?)".$',
            'group': '1',
            'flags': 'im',
        }
        mocker.patch.object(demisto, 'executeCommand')
        results = main(args)
        assert not results.outputs
        assert 'sanity' in results.raw_response
        assert 'sanity2' not in results.raw_response

    @staticmethod
    def test__with_high_group(mocker):
        args = {
            'data': 'hello world\nthis is a regex test named "sanity". please consider test named "sanity2".',
            'regex': 'test.*"(.*?)"',
            'group': '5',
        }
        mocker.patch.object(demisto, 'executeCommand')
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
