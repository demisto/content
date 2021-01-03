import pytest
import Intel471Actors as feed

# import demistomock as demisto

BUILD_PARAM_DICT_DATA = [
    (
        {'credentials': {'identifier': 'username', 'password': 'apikey'}, 'insecure': True,
         'fetch_time': '10 minutes', 'proxy': False},  # input
        'https://api.intel471.com/v1/actors?actor=*'  # expected

    ),
    (
        {'credentials': {'identifier': 'username', 'password': 'apikey'}, 'insecure': True,
         'fetch_time': '10 minutes', 'proxy': False, 'actor': 'search_word'},  # input
        'https://api.intel471.com/v1/actors?actor=search_word'  # expected

    ),

]


@pytest.mark.parametrize("input,expected_results", BUILD_PARAM_DICT_DATA)
def test_build_url(mocker, input, expected_results):
    """
    Given:
        - set of parameters from demisto.

    When:
        - create an instance and on every run.

    Then:
        - Returns a string describing url with relevant params only.

    """
    params_dict = feed._create_url(**input)
    assert params_dict == expected_results
