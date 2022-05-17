import json
import io

import pytest

from Arkime import Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_file_list_command():
    pass
    # client = Client(server_url='url', verify=False, proxy=False, headers={}, auth={})
    # args = {}
    # response = file_list_command(client, args)
    #
    # mock_response = util_load_json('test_data/connection_list.json')
    #
    # assert response.outputs == mock_response


def test_connection_list_command():
    client = Client(server_url='https://www.example.com', verify=False, proxy=False, headers={}, auth={})


page_size_in_range = (50, 50)
page_size_above_range = (150, 100)
page_size_below_range = (-1, 1)

page_size_validness_input = [page_size_in_range, page_size_above_range, page_size_below_range]


@pytest.mark.parametrize('page_size, page_size_expected', page_size_validness_input)
def test_page_size_validness(page_size: int, page_size_expected: int):
    from Arkime import page_size_validness
    assert page_size_validness(page_size) == page_size_expected
