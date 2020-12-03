import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_file_share_link_object():
    from Packs.Box.Integrations.BoxV2.BoxV2 import FileShareLink
    testing_args = {}
    testing_args.update({'access': 'some_access'})
    testing_args.update({'password': 'some_pass'})
    testing_args.update({'file_id': None})
    file_share_link_object = FileShareLink(args=testing_args)
    assert file_share_link_object.password == 'some_pass'
    assert file_share_link_object.access == 'some_access'
    assert file_share_link_object.file_id is None
    assert file_share_link_object.permissions == {'can_download': False}

    prepared_request = file_share_link_object.prepare_request_object()

    expected_request_object = {
        'access': 'some_access',
        'password': 'some_pass',
        'permissions': {
            'can_download': False}
    }

    assert prepared_request == expected_request_object


def test_folder_share_link_object():
    from Packs.Box.Integrations.BoxV2.BoxV2 import FolderShareLink
    testing_args = {}
    testing_args.update({'access': 'some_access'})
    testing_args.update({'password': 'some_pass'})
    testing_args.update({'folder_id': None})
    folder_share_link_object = FolderShareLink(args=testing_args)
    assert folder_share_link_object.password == 'some_pass'
    assert folder_share_link_object.access == 'some_access'
    assert folder_share_link_object.folder_id is None
    assert folder_share_link_object.permissions == {'can_download': False}

    prepared_request = folder_share_link_object.prepare_request_object()

    expected_request_object = {
        'access': 'some_access',
        'password': 'some_pass',
        'permissions': {
            'can_download': False}
    }

    assert prepared_request == expected_request_object


def test_query_handler_object():
    from Packs.Box.Integrations.BoxV2.BoxV2 import QueryHandler
    testing_args = {}
    testing_args.update({'': ''})


def test_find_file_folder_by_share_link(requests_mock):
    """
    Tests the box-find-file-by-share-link function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import Client, find_file_folder_by_share_link_command

    mock_response = util_load_json('/Users/ashamah/PycharmProjects/content_2/Packs/Box/Integrations/BoxV2/test_data/find_file_folder_by_share_link.json')
    requests_mock.get(
        'https://api.box.com/2.0/shared_items/',
        json=mock_response)

    client = Client(
        base_url='https://api.box.com/2.0',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'shared_link': 'https://app.box.com/s/testing',
        'password': 'some_pass',
        'as_user': '1234567'
    }

    response = find_file_folder_by_share_link_command(client, args)

    assert response.outputs_prefix == 'Box.FileShareLink'
    assert response.outputs_key_field == 'shared_link'
    assert response.outputs == mock_response


def test_create_update_file_share_link(requests_mock):
    """
    Tests the box-find-file-by-share-link function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import Client, create_update_file_share_link_command

    mock_response = util_load_json('/Users/ashamah/PycharmProjects/content_2/Packs/Box/Integrations/BoxV2/test_data/create_update_file_share_link.json')
    requests_mock.put(
        'https://api.box.com/2.0/files/742246263170/?fields=shared_link',
        json=mock_response)

    client = Client(
        base_url='https://api.box.com/2.0',
        verify=False,
        headers={
            'Authentication': 'Bearer JWT_TOKEN'
        }
    )

    args = {
        'file_id': '742246263170',
        'password': 'some_pass',
        'access': 'open',
        'as_user': '1234567'
    }

    response = create_update_file_share_link_command(client, args)

    assert response.outputs_prefix == 'Box.FileShareLink'
    assert response.outputs_key_field == 'shared_link'
    assert response.outputs == mock_response


def test_remove_file_share_link_command(requests_mock):
    """
    Tests the box-find-file-by-share-link function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import Client, remove_file_share_link_command

    mock_response = util_load_json('/Users/ashamah/PycharmProjects/content_2/Packs/Box/Integrations/BoxV2/test_data/create_update_file_share_link.json')
    requests_mock.put(
        'https://api.box.com/2.0/files/742246263170/?fields=shared_link',
        json=mock_response)

    client = Client(
        base_url='https://api.box.com/2.0',
        verify=False,
        headers={
            'Authentication': 'Bearer JWT_TOKEN'
        }
    )

    args = {
        'file_id': '742246263170',
        'password': 'some_pass',
        'access': 'open',
        'as_user': '1234567'
    }

    response = remove_file_share_link_command(client, args)

    assert response.outputs_prefix == 'Box.FileShareLink'
    assert response.outputs_key_field == 'shared_link'
    assert response.outputs == mock_response
    assert response.readable_output == 'File Share Link for the file_id 742246263170 was removed.'
