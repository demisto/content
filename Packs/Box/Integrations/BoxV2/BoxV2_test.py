import json
import io
from unittest import mock

import demistomock as demisto
from BoxV2 import Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


class TestBox:
    def __init__(self, mocker):
        test_params = {
            'client_id': '',
            'client_secret': '',
            'pub_key_id': '',
            'private_key': '',
            'passphrase': '',
            'enterprise_id': ''
        }
        testing_auth_header = {'Authorization': f'Bearer JWT_TOKEN'}
        mocker.patch.object(Client, '_request_token', return_value=testing_auth_header)

        self.client = Client(
            base_url='https://api.box.com/2.0',
            verify=False,
            proxy=False,
            auth_params=test_params
        )


def test_find_file_folder_by_share_link(requests_mock, mocker):
    """
    Tests the box-find-file-by-share-link function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import find_file_folder_by_share_link_command

    mock_response = util_load_json(
        'test_data/find_file_folder_by_share_link.json')
    requests_mock.get(
        'https://api.box.com/2.0/shared_items/',
        json=mock_response)

    args = {
        'shared_link': 'https://app.box.com/s/testing',
        'password': 'some_pass',
        'as_user': '1234567'
    }
    client = TestBox(mocker).client
    response = find_file_folder_by_share_link_command(client, args)

    assert requests_mock.request_history[0].headers.get(
        'Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].headers.get(
        'BoxApi') == "shared_link=https://app.box.com/s/testing&shared_link_password=some_pass"
    assert response.outputs_prefix == 'Box.FileShareLink'
    assert response.outputs_key_field == 'shared_link'
    assert response.outputs == mock_response


def test_file_share_link_object():
    from BoxV2 import FileShareLink
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
    from BoxV2 import FolderShareLink
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


def test_create_update_file_share_link(requests_mock, mocker):
    """
    Tests the box-find-file-by-share-link function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import create_update_file_share_link_command

    mock_response = util_load_json('test_data/create_update_file_share_link.json')
    requests_mock.put(
        'https://api.box.com/2.0/files/742246263170/?fields=shared_link',
        json=mock_response)

    client = TestBox(mocker).client

    args = {
        'file_id': '742246263170',
        'password': 'some_pass',
        'access': 'open',
        'as_user': '1234567'
    }

    response = create_update_file_share_link_command(client, args)

    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].json().get('shared_link').get('password') == 'some_pass'
    assert response.outputs_prefix == 'Box.FileShareLink'
    assert response.outputs_key_field == 'shared_link'
    assert response.outputs == mock_response


def test_remove_file_share_link_command(requests_mock, mocker):
    """
    Tests the box-find-file-by-share-link function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import remove_file_share_link_command

    mock_response = util_load_json('test_data/create_update_file_share_link.json')
    requests_mock.put(
        'https://api.box.com/2.0/files/742246263170/?fields=shared_link',
        json=mock_response)

    client = TestBox(mocker).client

    args = {
        'file_id': '742246263170',
        'password': 'some_pass',
        'access': 'open',
        'as_user': '1234567'
    }

    response = remove_file_share_link_command(client, args)

    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].json().get('shared_link') is None
    assert response.outputs_prefix == 'Box.FileShareLink'
    assert response.outputs_key_field == 'shared_link'
    assert response.outputs == mock_response
    assert response.readable_output == 'File Share Link for the file_id 742246263170 was removed.'


def test_get_shared_link_for_file_command(requests_mock, mocker):
    """
    Tests the box-get-shared-link-for-file function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import get_shared_link_for_file_command

    mock_response = util_load_json('test_data/create_update_file_share_link.json')
    requests_mock.get(
        'https://api.box.com/2.0/files/742246263170/',
        json=mock_response)

    client = TestBox(mocker).client

    args = {
        'file_id': '742246263170',
        'as_user': '1234567'
    }

    response = get_shared_link_for_file_command(client, args)

    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].qs.get('fields') == ['shared_link']
    assert response.outputs_prefix == 'Box.FileShareLink'
    assert response.outputs_key_field == 'shared_link'
    assert response.outputs == mock_response


def test_create_update_folder_share_link_command(requests_mock, mocker):
    """
    Tests the box-get-shared-link-for-file function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import Client, create_update_folder_share_link_command

    mock_response = util_load_json('test_data/create_update_file_share_link.json')
    requests_mock.put(
        'https://api.box.com/2.0/folders/742246263170/',
        json=mock_response)

    client = TestBox(mocker).client

    args = {
        'access': 'open',
        'password': 'testpass',
        'unshared_at': '3 days',
        'can_download': 'False',
        'folder_id': '742246263170',
        'as_user': '1234567'
    }

    response = create_update_folder_share_link_command(client, args)

    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].json().get('shared_link').get('access') == 'open'
    assert response.outputs_prefix == 'Box.FolderShareLink'
    assert response.outputs_key_field == 'shared_link'
    assert response.outputs == mock_response


def test_remove_folder_share_link_command(requests_mock, mocker):
    """
    Tests the box-get-shared-link-for-file function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import remove_folder_share_link_command

    mock_response = util_load_json('test_data/create_update_file_share_link.json')
    requests_mock.put(
        'https://api.box.com/2.0/folders/742246263170/',
        json=mock_response)

    client = TestBox(mocker).client

    args = {
        'folder_id': '742246263170',
        'as_user': '1234567'
    }

    response = remove_folder_share_link_command(client, args)

    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].json().get('shared_link') is None
    assert response.outputs_prefix == 'Box.FolderShareLink'
    assert response.outputs_key_field == 'shared_link'
    assert response.outputs == mock_response


def test_get_folder_command(requests_mock, mocker):
    """
    Tests the box-get-shared-link-for-file function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import get_folder_command

    mock_response = util_load_json('test_data/get_folder.json')
    requests_mock.get(
        'https://api.box.com/2.0/folders/0/',
        json=mock_response)

    client = TestBox(mocker).client

    args = {
        'folder_id': '0',
        'as_user': '1234567'
    }

    response = get_folder_command(client, args)

    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].url == 'https://api.box.com/2.0/folders/0/'
    assert response.outputs_prefix == 'Box.Folder'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response


def test_list_folder_items_command(requests_mock, mocker):
    """
    Tests the box-get-shared-link-for-file function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import list_folder_items_command

    mock_response = util_load_json('test_data/get_folder.json')
    requests_mock.get(
        'https://api.box.com/2.0/folders/0/',
        json=mock_response)

    client = TestBox(mocker).client

    args = {
        'folder_id': '0',
        'as_user': '1234567',
        'limit': '100',
        'offset': '0',
        'sort': 'asc'
    }

    response = list_folder_items_command(client, args)

    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].qs.get('sort') == ['asc']
    assert response.outputs_prefix == 'Box.Folder'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response


def test_folder_create_command(requests_mock, mocker):
    """
    Tests the box-get-shared-link-for-file function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import folder_create_command

    mock_response = util_load_json('test_data/get_folder.json')
    requests_mock.post(
        'https://api.box.com/2.0/folders/',
        json=mock_response)

    client = TestBox(mocker).client

    args = {
        'parent_id': '0',
        'as_user': '1234567',
        'name': 'Testing Folder'
    }

    response = folder_create_command(client, args)

    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].json().get('name') == 'Testing Folder'
    assert response.outputs_prefix == 'Box.Folder'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response


def test_file_delete_command(requests_mock, mocker):
    """
    Tests the box-get-shared-link-for-file function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import file_delete_command

    successful_file_deletion_status_code = 204
    requests_mock.delete(
        'https://api.box.com/2.0/files/12345',
        status_code=successful_file_deletion_status_code)

    client = TestBox(mocker).client

    args = {
        'as_user': '1234567',
        'file_id': '12345'
    }

    response = file_delete_command(client, args)
    expected_response = 'The file 12345 was successfully deleted.'

    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].method == 'DELETE'
    assert response.readable_output == expected_response


def test_list_users_command(requests_mock, mocker):
    """
    Tests the box-get-shared-link-for-file function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import list_users_command

    mock_response = util_load_json('test_data/get_folder.json')
    requests_mock.get(
        'https://api.box.com/2.0/users/',
        json=mock_response)

    client = TestBox(mocker).client

    args = {
        'fields': 'name',
        'filter_term': 'test_user',
        'limit': '100',
        'offset': '0'
    }

    response = list_users_command(client, args)

    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].qs.get('filter_term') == ['test_user']

    assert response.outputs_prefix == 'Box.Users'
    assert response.outputs_key_field == 'entries'
    assert response.outputs == mock_response


def test_upload_file_command(requests_mock, mocker):
    """
    Tests the box-get-shared-link-for-file function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from BoxV2 import upload_file_command
    from unittest import mock

    # First need to mock the getFilePath object so we can replace with a test file.
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './test_data/test_image.jpg'})

    mock_obj = mock.Mock()
    mock_obj.st_size = 10500000
    mocker.patch('os.stat', return_value=mock_obj)

    # The size of the file we are testing is 298,306 bytes for testing purposes, we will use 70,000
    # byte chunks. This should result in a total of 5 chunked upload requests.
    session_request_response = {
        'id': 'test_session_id',
        'part_size': 70000
    }

    # Each chunk response is expected to include an upload summary which is then included when
    # committing the file. We will assert that these values match the commit request.
    part_data = {
        'part': {
            'some_info': 'some-result'
        }
    }

    # The response given when a session is committed.
    session_commit_response = {
        'entities': {
            'name': 'some_file',
            'file_type': 'jpg'
        }
    }

    # Mock for the request to open an upload session.
    requests_mock.post(
        'https://upload.box.com/api/2.0/files/upload_sessions',
        json=session_request_response
    )
    requests_mock.put(
         'https://upload.box.com/api/2.0/files/upload_sessions/test_session_id',
         json=part_data
    )
    requests_mock.post(
        'https://upload.box.com/api/2.0/files/upload_sessions/test_session_id/commit',
        json=session_commit_response
    )

    client = TestBox(mocker).client

    args = {
        'entry_id': '123@123',
        'file_name': 'test_user.png',
        'folder_id': '100',
        'as_user': '0'
    }

    response = upload_file_command(client, args)

    # Validate request to open a session
    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].text == '{"file_name": "test_user.png", "file_size": 10500000, "folder_id": "100"}'

    # Validate first PUT request
    assert requests_mock.request_history[1].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[1].headers.get('Content-Range') == "bytes 0-69999/10500000"
    assert requests_mock.request_history[1].headers.get('Digest') == "SHA=X1QbZ9o+V8TFMLKQ6LBmYEiBdD8="

    # Validate second PUT request
    assert requests_mock.request_history[2].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[2].headers.get('Content-Range') == "bytes 70000-139999/10500000"
    assert requests_mock.request_history[2].headers.get('Digest') == "SHA=XkaxVkVB+djbRD6KHylwQCQOAZY="

    # Skipping the remaining PUT requests

    # Validate request made to commit the file
    assert requests_mock.request_history[6].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[6].headers.get('Digest') == "SHA=O/ybJoSaHW2S0x4O/1p3QTcz3E4="
    assert len(requests_mock.request_history[6].json().get('parts')) == 5

    # Assert number of requests was 7. Where 5 were chunked upload, 1 session, and 1 commit request.
    assert len(requests_mock.request_history) == 7

    assert response.outputs_prefix == 'Box.File'
    assert response.outputs_key_field == 'entries'
    assert response.outputs == session_commit_response


def test_get_current_user_command(requests_mock, mocker):
    from BoxV2 import get_current_user_command

    mock_response = util_load_json('test_data/get_current_user.json')

    client = TestBox(mocker).client

    args = {
        'as_user': 'sample_current_user'
    }

    requests_mock.get(
        'https://api.box.com/2.0/users/me/',
        json=mock_response
    )

    response = get_current_user_command(client, args)

    assert requests_mock.request_history[0].headers.get('As-User') == "sample_current_user"
    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"

    assert response.outputs_prefix == 'Box.User'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response


def test_create_user_command(requests_mock, mocker):
    from BoxV2 import create_user_command

    mock_response = util_load_json('test_data/create_user.json')

    client = TestBox(mocker).client

    args = {
        'as_user': 'sample_current_user',
        'login': 'dbot@paloaltonetworks.com',
        'name': 'D Bot',
        'role': 'user',
        'language': 'en',
        'is_sync_enabled': 'true',
        'job_title': 'CEO',
        'phone': '4808675309',
        'address': '3000 Tannery Way, Santa Clara, CA 95054',
        'space_amount': '11345156112',
        'tracking_codes': 'key=tracking_code_key,value=tracking_code_value;key=test1,value=test2',
        'can_see_managed_users': 'true',
        'timezone': 'US/Western',
        'is_exempt_from_device_limits': 'true',
        'is_exempt_from_login_verification': 'true',
        'is_external_collab_restricted': 'true',
        'is_platform_access_only': 'true',
        'status': 'active'
    }

    requests_mock.post(
        'https://api.box.com/2.0/users/',
        json=mock_response
    )

    response = create_user_command(client, args)

    assert requests_mock.request_history[0].headers.get('As-User') == "sample_current_user"
    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].json().get('name') == 'D Bot'
    assert requests_mock.request_history[0].json().get('tracking_codes') == [
        {'tracking_code_key': 'tracking_code_value'},
        {'test1': 'test2'}
    ]
    assert requests_mock.request_history[0].json().get('login') == 'dbot@paloaltonetworks.com'

    assert response.outputs_prefix == 'Box.User'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response


def test_update_user_command(requests_mock, mocker):
    from BoxV2 import update_user_command

    mock_response = util_load_json('test_data/create_user.json')

    client = TestBox(mocker).client

    args = {
        'as_user': 'sample_current_user',
        'login': 'dbot@paloaltonetworks.com',
        'name': 'D Bot',
        'role': 'user',
        'language': 'en',
        'is_sync_enabled': 'true',
        'job_title': 'CEO',
        'phone': '4808675309',
        'address': '3000 Tannery Way, Santa Clara, CA 95054',
        'space_amount': '11345156112',
        'tracking_codes': 'key=tracking_code_key,value=tracking_code_value;key=test1,value=test2',
        'can_see_managed_users': 'true',
        'timezone': 'US/Western',
        'is_exempt_from_device_limits': 'true',
        'is_exempt_from_login_verification': 'true',
        'is_external_collab_restricted': 'true',
        'is_platform_access_only': 'true',
        'status': 'active',
        'user_id': '12345'
    }

    requests_mock.put(
        'https://api.box.com/2.0/users/12345/',
        json=mock_response
    )

    response = update_user_command(client, args)

    assert requests_mock.request_history[0].headers.get('As-User') == "sample_current_user"
    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].json().get('name') == 'D Bot'
    assert requests_mock.request_history[0].json().get('tracking_codes') == [
        {'tracking_code_key': 'tracking_code_value'},
        {'test1': 'test2'}
    ]
    assert requests_mock.request_history[0].json().get('login') == 'dbot@paloaltonetworks.com'

    assert response.outputs_prefix == 'Box.User'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response


def test_delete_user_command(requests_mock, mocker):
    from BoxV2 import delete_user_command

    client = TestBox(mocker).client

    args = {
        'as_user': 'sample_current_user',
        'user_id': '12345',
        'force': 'true'
    }

    requests_mock.delete(
        'https://api.box.com/2.0/users/12345/',
        status_code=204
    )

    response = delete_user_command(client, args)

    assert requests_mock.request_history[0].headers.get('As-User') == "sample_current_user"
    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].qs.get('force') == ['true']

    assert response.readable_output == 'The user 12345 was successfully deleted.'
