import json
import pytest
import io
from CommonServerPython import Common
from typing import *


def util_load_json(path: str) -> Any:
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def mock_client():
    from JoeSecurityV2 import Client
    client = Client(base_url='https://test.com', apikey="mockkey")
    return client


def mock_gen():
    for i in range(0, 100):
        yield i


PAGINATION_SUCCESS = [
    ({'limit': '0'}, []),
    ({'limit': '1'}, [0]),
    ({'limit': '50'}, [i for i in range(0, 50)]),
    ({}, [i for i in range(0, 50)]),
    ({'page': '1', 'page_size': '1'}, [0]),
    ({'page': '1', 'page_size': '5'}, [0, 1, 2, 3, 4]),
    ({'page': '11', 'page_size': '10'}, []),
    ({'page': '10', 'page_size': '10'}, [i for i in range(90, 100)])
]


@pytest.mark.parametrize('args,excepted', PAGINATION_SUCCESS)
def test_pagination_success(args, excepted):
    """
    Given:
        - An pagination arguments such as limit, page and page size.
    When:
        - Pagination method has been called.
    Then:
        - Ensure that the right page were returned.
    """
    from JoeSecurityV2 import pagination

    pages = mock_gen()
    result = pagination(args, pages)
    assert result == excepted


PAGINATION_FAILURE = [
    ({'limit': '-1'}, "one of the arguments are not having a valid value"),
    ({'page': '1'}, "one of the page or page_size arguments are missing"),
    ({'page_size': '1'}, "one of the page or page_size arguments are missing"),
    ({'page': '-1', 'page_size': '1'}, "one of the arguments are not having a valid value"),
]


@pytest.mark.parametrize('args,excepted', PAGINATION_FAILURE)
def test_pagination_failure(args, excepted):
    """
    Given:
        - An invalid pagination arguments values.
    When:
        - Pagination method has been called.
    Then:
        - Ensure that the right error message raised.
    """
    from JoeSecurityV2 import pagination

    pages = mock_gen()

    with pytest.raises(Exception) as e:
        pagination(args, pages)
    assert e.value.args[0] == excepted


@pytest.mark.parametrize('result,excepted', [({'online': True}, 'online'), ({'online': False}, 'offline')])
def test_is_online(mocker, result, excepted):
    """
    Given:
        - An app client object.
    When:
        - Is online method has been called.
    Then:
        - Ensure the human-readable correspond to the expcted server status.
    """
    from JoeSecurityV2 import is_online

    client = mock_client()
    mocker.patch.object(client, 'server_online', return_value=result)
    response = is_online(client)
    assert response.readable_output == f'Joe server is {excepted}'


def test_list_analysis(mocker):
    """
    Given:
        - An app client object.
    When:
        - list analysis method has been called.
    Then:
        - Ensure the corresponded indicator were created with the right DBscore and verify the outputs as expected.
    """
    from JoeSecurityV2 import list_analysis

    result = util_load_json('test_data/analysis_info_list.json')
    excepted = util_load_json('test_data/analysis.json')

    client = mock_client()
    mocker.patch.object(client, 'analysis_list_paged', return_value=[])
    mocker.patch.object(client, 'analysis_info', return_value={})
    mocker.patch.object(client, 'analysis_info_list', return_value=result)

    response = list_analysis(client, {})
    for index, indicator in enumerate(response.indicators):
        assert indicator.dbot_score.indicator == excepted.get('DBotScore')[index].get('Indicator')
        assert indicator.dbot_score.score == excepted.get('DBotScore')[index].get('Score')
        if isinstance(indicator, Common.File):
            assert indicator.sha1 == excepted.get('File')[index].get('SHA1')
        else:
            assert indicator.url == excepted.get('URL').get('Data')
    assert response.outputs == excepted.get('Joe').get('Analysis')
