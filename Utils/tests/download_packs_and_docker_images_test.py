from unittest.mock import patch

from ..download_packs_and_docker_images import create_content_item_id_set, get_docker_images_with_tag, get_pack_names

MOCK_ID_SET = {
    'integrations':
        [{'mock_integration': {'name': 'mock_integration',
                               'file_path': 'Packs/mock_pack',
                               'source': ['code.pan.run', 'xsoar', 'content'],
                               'fromversion': '5.0.0',
                               'pack': 'mock_pack',
                               'docker_image': 'demisto/python3:3.9.8.24399'}
          },
         {'mock_integration_2': {'name': 'mock_integration_2',
                                 'file_path': 'Packs/mock_pack_2/',
                                 'source': ['code.pan.run', 'xsoar', 'content'],
                                 'fromversion': '5.0.0',
                                 'pack': 'mock_pack2',
                                 'tests': ['No tests']}}
         ],
    'scripts': [{'mock_script': {'name': 'mock_script',
                                 'file_path': 'Packs/mock_pack',
                                 'source': ['code.pan.run', 'xsoar', 'content'],
                                 'fromversion': '5.0.0',
                                 'pack': 'mock_pack',
                                 'docker_image': 'demisto/python:2.7.18.20958'}},
                {'mock_script_2': {'name': 'mock_script_2',
                                   'file_path': 'Packs/mock_script_2',
                                   'source': ['code.pan.run', 'xsoar', 'content'],
                                   'fromversion': '5.0.0',
                                   'pack': 'mock_pack_2',
                                   'docker_image': 'demisto/python:2.7.18.20958'}}
                ],
    "Packs": {'mock_pack': {'name': 'mock pack',
                            'current_version': '1.0.3',
                            'source': ['code.pan.run', 'xsoar', 'content'],
                            'ContentItems': {'integrations': ['mock_integration'], 'scripts': ['mock_script']}},
              'mock_pack_2': {'name': 'mock pack 2',
                              'current_version': '1.0.3',
                              'source': ['code.pan.run', 'xsoar', 'content'],
                              'ContentItems': {'integrations': ['mock_integration_2'], 'scripts': ['mock_script_2']}}
              }
}


def test_create_content_item_id_set():
    """ Test create_content_item_id_set with a valid item

    Given:
        - mock_id_set_item with 2 integrations
    When:
        - Calling create_content_item_id_set
    Then:
        - Return the same item list as a dict
    """
    expected_output = {'mock_integration': {'name': 'mock_integration', 'file_path': 'Packs/mock_pack',
                                            'source': ['code.pan.run', 'xsoar', 'content'], 'fromversion': '5.0.0',
                                            'pack': 'mock_pack', 'docker_image': 'demisto/python3:3.9.8.24399'},
                       'mock_integration_2': {'name': 'mock_integration_2', 'file_path': 'Packs/mock_pack_2/',
                                              'source': ['code.pan.run', 'xsoar', 'content'], 'fromversion': '5.0.0',
                                              'pack': 'mock_pack2', 'tests': ['No tests']}}
    assert create_content_item_id_set(MOCK_ID_SET['integrations']) == expected_output  # type: ignore


def test_create_content_item_id_set_empty():
    """ Test create_content_item_id_set with an empty item

    Given:
        - mock_id_set_item with 0 integrations
    When:
        - calling create_content_item_id_set
    Then:
        - return an empty dict
    """
    mock_id_set_item: list = []
    assert create_content_item_id_set(mock_id_set_item) == {}


@patch('builtins.print')
def test_get_docker_images_with_tag(mock_print):
    """ Test get_docker_images_with_tag given valid duplicate entries

    Given:
        - packs with 3 images, 2 are duplicates
    When:
        - calling actual_docker_images with said packs
    Then:
        - assert prints contain the image
        - return 2 expected docker images with tag
    """
    expected_docker_images = {'demisto/python3:3.9.8.24399', 'demisto/python:2.7.18.20958'}
    actual_docker_images = get_docker_images_with_tag({'d_mock': 'mock_pack', 'd_mock_2': 'mock_pack_2'}, MOCK_ID_SET)
    mock_print.assert_called_with('\t\tdemisto/python:2.7.18.20958 - used by mock_script_2')
    assert actual_docker_images == expected_docker_images


@patch('builtins.print')
def test_get_docker_images_with_tag_invalid(mock_print):
    """ Test get_docker_images_with_tag given invalid pack

    Given:
        - invalid pack name
    When:
        - calling actual_docker_images with said pack
    Then:
        - assert print warns pack wasn't found
        - return empty set
    """
    expected_docker_image: set = set()
    actual_docker_images = get_docker_images_with_tag({'d_no_pack': 'no_pack'}, MOCK_ID_SET)
    mock_print.assert_called_with('\tPack d_no_pack was not found in id_set.json.')
    assert actual_docker_images == expected_docker_image


@patch('builtins.print')
def test_get_pack_names(mock_print):
    """ Test that given display names for packs returns valid pack names

    Given:
        - 2 packs: mock_pack and mock_pack_2
        - non-existent pack: invalid_pack
    When:
        - calling get_pack_name
    Then:
        - a message that invalid pack isn't found
        - get result for 2 packs
    """
    pack_display_name, pack_display_name_2, invalid_pack = 'mock pack', 'mock pack 2', 'invalid pack'
    pack_name, pack_name_2 = 'mock_pack', 'mock_pack_2'
    expected = {pack_display_name: pack_name, pack_display_name_2: pack_name_2}
    res = get_pack_names([pack_display_name, pack_display_name_2, invalid_pack], MOCK_ID_SET)
    assert res == expected
    mock_print.assert_called_with("Couldn't find pack invalid pack. Skipping pack.")
