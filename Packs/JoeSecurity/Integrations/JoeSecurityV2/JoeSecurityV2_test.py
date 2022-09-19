import json
import pytest
import io
from CommonServerPython import Common, DemistoException
from typing import *


def util_load_json(path: str) -> Any:
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    from JoeSecurityV2 import Client
    return Client(base_url='https://test.com', apikey="mockkey")


def mock_gen():
    for i in range(0, 100):
        yield i


PAGINATION_SUCCESS = [({'limit': '0'}, []), ({'limit': '1'}, [0]), ({'limit': '50'}, [i for i in range(0, 50)]),
                      ({}, [i for i in range(0, 50)]), ({'page': '1', 'page_size': '1'}, [0]),
                      ({'page': '1', 'page_size': '5'}, [0, 1, 2, 3, 4]), ({'page': '11', 'page_size': '10'}, []),
                      ({'page': '10', 'page_size': '10'}, [i for i in range(90, 100)])]


@pytest.mark.parametrize('args,excepted', PAGINATION_SUCCESS)
def test_paginate_success(args, excepted):
    """
    Given:
        - An paginate arguments such as limit, page and page size.
    When:
        - Paginate method was called.
    Then:
        - Ensure that the right page were returned.
    """
    from JoeSecurityV2 import paginate

    pages = mock_gen()
    result = paginate(args, pages)
    assert result == excepted


PAGINATION_FAILURE = [({'limit': '-1'}, ValueError), ({'page': '1'}, DemistoException),
                      ({'page_size': '1'}, DemistoException), ({'page': '-1', 'page_size': '1'}, ValueError), ]


@pytest.mark.parametrize('args,excepted', PAGINATION_FAILURE)
def test_paginate_failure(args, excepted):
    """
    Given:
        - An invalid paginate arguments values.
    When:
        - Pagination method was called.
    Then:
        - Ensure that the right error message raised.
    """
    from JoeSecurityV2 import paginate

    pages = mock_gen()

    with pytest.raises(Exception) as e:
        paginate(args, pages)
    assert isinstance(e.value, excepted)


@pytest.mark.parametrize('result,excepted', [({'online': True}, 'online'), ({'online': False}, 'offline')])
def test_is_online_command(mocker, client, result, excepted):
    """
    Given:
        - A Joe sever status (online/offline).
    When:
        - joe-is-online command was called.
    Then:
        - Ensure the human-readable corresponding to the expcted server status.
    """
    from JoeSecurityV2 import is_online_command

    mocker.patch.object(client, 'server_online', return_value=result)
    response = is_online_command(client)
    assert response.readable_output == f'Joe server is {excepted}'


def test_list_analysis_command(mocker, client):
    """
    Given:
        - A list of Joe analysis.
    When:
        - joe-list-analysis command was called.
    Then:
        - Ensure the corresponding indicator were created with the right DBscore and verify the outputs as expected.
    """
    from JoeSecurityV2 import list_analysis_command

    result = util_load_json('test_data/list_analysis_raw_response.json')
    excepted = util_load_json('test_data/list_analysis_expected_output.json')

    mocker.patch.object(client, 'analysis_list_paged', return_value=[])
    mocker.patch.object(client, 'analysis_info', return_value={})
    mocker.patch.object(client, 'analysis_info_list', return_value=result)

    response = list_analysis_command(client, {})
    for index, command_res in enumerate(response[:-1]):
        assert command_res.indicator.dbot_score.indicator == excepted.get('DBotScore')[index].get('Indicator')
        assert command_res.indicator.dbot_score.score == excepted.get('DBotScore')[index].get('Score')
        if isinstance(command_res.indicator, Common.File):
            assert command_res.indicator.sha1 == excepted.get('File')[index].get('SHA1')
        else:
            assert command_res.indicator.url == excepted.get('URL').get('Data')
    assert response[-1].outputs == excepted.get('Joe').get('Analysis')


@pytest.mark.parametrize('web_id,file_type', [('1', 'html'), ('2', 'json'), ('3', 'pcap')])
def test_download_report_command(mocker, client, web_id, file_type):
    """
    Given:
        - An app client object, web id and file type.
    When:
        - joe-download-report command was called.
    Then:
        - Ensure the corresponding infoFile has been created.
    """
    from JoeSecurityV2 import download_report_command

    mocker.patch.object(client, 'analysis_download', return_value=('test_report', 'html_test_report'))
    response = download_report_command(client, {'webid': web_id, 'type': file_type})
    assert response.get('File') == f'{web_id}_report.{file_type}'


def test_download_sample_command(mocker, client):
    """
    Given:
        - An app client object and web id.
    When:
        - joe-download-sample command was called.
    Then:
        - Ensure the corresponding File has been created.
    """
    from JoeSecurityV2 import download_sample_command

    mocker.patch.object(client, 'analysis_download', return_value=('test_sample', 'test_sample'))

    for web_id in range(0, 3):
        response = download_sample_command(client, {'webid': web_id})
        assert response.get('File') == f'{web_id}.dontrun'


def test_search_command(mocker, client):
    """
    Given:
        - A query.
    When:
        - joe-search command was called
    Then:
        - Ensure the corresponding readable output is returned.
    """
    from JoeSecurityV2 import search_command

    mocker.patch.object(client, 'analysis_search', return_value=[])
    response = search_command(client, {'query': 'test.com'})
    assert not response.outputs


def test_file_command(mocker, client):
    """
    Given:
        - An app client object and files for reputation command.
    When:
        - The file reputation command was called.
    Then:
        - Ensure the corresponding indicator were created with the right DBscore and duplicates were removed.
    """
    from JoeSecurityV2 import file_command

    result = util_load_json('test_data/list_analysis_raw_response.json')[:-1]
    excepted = util_load_json('test_data/list_analysis_expected_output.json')

    mocker.patch.object(client, 'analysis_search', return_value=result)

    response = file_command(client, {'file': '1.pdf,test_2.jbs,test_3.jbs'})
    for index, command_res in enumerate(response):
        assert command_res.indicator.dbot_score.indicator == excepted.get('DBotScore')[index].get('Indicator')
        assert command_res.indicator.dbot_score.score == excepted.get('DBotScore')[index].get('Score')
        if isinstance(command_res.indicator, Common.File):
            assert command_res.indicator.sha1 == excepted.get('File')[index].get('SHA1')


def test_url_command(mocker, client):
    """
    Given:
        - An app client object and urls for reputation command.
    When:
        - The url reputation command was called.
    Then:
        - Ensure the corresponding indicator were created with the right DBscore and duplicates were removed.
    """
    from JoeSecurityV2 import url_command

    result = util_load_json('test_data/list_analysis_raw_response.json')[-1]
    excepted = util_load_json('test_data/list_analysis_expected_output.json')

    mocker.patch.object(client, 'analysis_search', return_value=[result])
    command_res = url_command(client, {'url': 'test_url'})[0]

    assert command_res.indicator.dbot_score.indicator == excepted.get('DBotScore')[-1].get('Indicator')
    assert command_res.indicator.dbot_score.score == excepted.get('DBotScore')[-1].get('Score')
    assert command_res.indicator.url == excepted.get('URL').get('Data')
