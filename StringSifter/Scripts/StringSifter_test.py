import json
import io
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


def test_main(mocker):
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'test_data/test_words.txt'})
    cr = main()
    assert cr.readable_output == open_file('test_data/stringsifter_result.md')
    assert cr.outputs == open_json('test_data/words_rating.json')


def test_main_with_flags(mocker):
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'test_data/test_words.txt'})
    mocker.patch.object(demisto, 'args', return_value={'limit': '20', 'min_score': '6.34'})
    cr = main()
    assert cr.readable_output == open_file('test_data/stringsifter_results_with_filters.md')
    assert cr.outputs == open_json('test_data/words_rating_with_filter.json')
