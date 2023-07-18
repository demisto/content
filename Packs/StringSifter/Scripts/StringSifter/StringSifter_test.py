import json
from StringSifter import *
import pytest


def open_file(path):
    with open(path) as file:
        return file.read()


def open_json(path):
    with open(path) as json_file:
        return json.load(json_file)


@pytest.mark.parametrize('args, result', [({'limit': '50'}, ['rank_strings', '--scores', '--limit', '50']),
                                          ({}, ['rank_strings', '--scores'])])
def test_create_rank_strings_args(args, result):
    """
    Given:
        - args from to generate the rank string cli command
    When:
        - preparing the list of the rank string command
    Then:
        - Return the command list with the competible arguments
    """
    assert result == create_rank_strings_args(args)


def test_stringsifter_entryID(mocker):
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'test_data/test_words.txt', 'name': 'name'})
    cr = stringsifter({'entryID': '123'})
    assert cr.readable_output == open_file('test_data/stringsifter_result.md')
    assert cr.outputs == open_json('test_data/words_rating.json')


def test_main_with_flags(mocker):
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'test_data/test_words.txt', 'name': 'name'})
    cr = stringsifter({'limit': '20', 'min_score': '6.34', 'entryID': '123'})
    assert cr.readable_output == open_file('test_data/stringsifter_results_with_filters.md')
    assert cr.outputs == open_json('test_data/words_rating_with_filter.json')


def test_text_as_string(mocker):
    with open('test_data/temp_out.txt') as f:
        string_output = f.read()
        cr = stringsifter({'string_text': string_output, 'file_name': 'test_file', 'limit': '5'})
        assert cr.readable_output == open_file('test_data/redable_output_string_text.md')
        assert cr.outputs == open_json('test_data/string_text_outputs.json')


@pytest.mark.xfail(raiseExceptions=ValueError)
def test_entered_entry_id_and_string_text(mocker):
    stringsifter({'string_text': '123', 'entryID': '123'})
