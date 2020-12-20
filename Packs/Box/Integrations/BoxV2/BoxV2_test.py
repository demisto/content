import json
import io

import demistomock as demisto
from BoxV2 import Client


def util_load_json(path):
    """
    Simple test utility to open the recorded JSON files.

    :param path: str - Path to the JSON file
    :return: dict - A dict representation of the JSON
    """
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


class TestBox:
    """
    Test class to handle the client.
    """
    def __init__(self, mocker):
        test_params = {'credentials_json': str('{"boxAppSettings": {"clientID": '
                                               '"1234", '
                                               '"clientSecret": '
                                               '"1234", "appAuth": {'
                                               '"publicKeyID": "1234", "privateKey": '
                                               '"-----BEGIN ENCRYPTED PRIVATE KEY----------END '
                                               'ENCRYPTED PRIVATE KEY-----", "passphrase": '
                                               '"1234"}}, '
                                               '"enterpriseID": "1234"}')}
        testing_auth_header = {'Authorization': 'Bearer JWT_TOKEN'}
        mocker.patch.object(Client, '_request_token', return_value=testing_auth_header)

        self.client = Client(
            base_url='https://api.box.com/2.0',
            verify=False,
            proxy=False,
            auth_params=test_params
        )


def test_find_file_folder_by_share_link(requests_mock, mocker):
    """
    Tests the box-find-file-folder-by-share-link function and command.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    Verifies:
      - The Authorization header is correct
      - BoxApi header matches the expected query.

    Given: A valid shared_link and password
    When: Executing the box-find-file-folder-by-share-link command
    Then: Return the result where the outputs match the mocked response.

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
    assert response.outputs_prefix == 'Box.ShareLink'
    assert response.outputs_key_field == 'shared_link'
    assert response.outputs == mock_response


def test_file_share_link_object():
    """
    Tests the creation of a file_share_link object. Since the function which uses this is a CRUD
    function, this test simply asserts that arguments given to it will return the correct request
    object
    """
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
    """
    Tests the creation of a folder_share_link object. Since the function which uses this is a CRUD
    function, this test simply asserts that arguments given to it will return the correct request
    object
    """
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
    Tests the box-create-file-share-link function and command.

    Configures requests_mock instance to generate the appropriate
    files API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    Verifies:
      - The Authorization header is correct
      - Shared link request sends the correct password
      - Outputs match the expected result.

    Given: A valid file_id and password
    When: Executing the box-create-file-share-link command
    Then: Return the result where the outputs match the mocked response.

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
    assert response.outputs_prefix == 'Box.ShareLink'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response


def test_remove_file_share_link_command(requests_mock, mocker):
    """
    Tests the box-remove-file-share-link function and command.

    Configures requests_mock instance to generate the appropriate
    files API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    Verifies:
      - The Authorization header is correct
      - Shared link request sends the correct password
      - Outputs match the expected result.
      - Readable output matches the correct result for deletion.

    Given: A valid file_id and password
    When: Executing the box-remove-file-share-link command
    Then: Return the result where the outputs match the mocked response.

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
    assert response.outputs_prefix == 'Box.ShareLink'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response
    assert response.readable_output == 'File Share Link for the file_id 742246263170 was removed.'


def test_get_shared_link_for_file_command(requests_mock, mocker):
    """
    Tests the box-get-shared-link-by-file function and command.

    Configures requests_mock instance to generate the appropriate
    files API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    Verifies:
      - The Authorization header is correct
      - Query string sends the share_link as a field.
      - Outputs match the expected result.

    Given: A valid file_id.
    When: Executing the box-get-shared-link-by-file command.
    Then: Return the result where the outputs match the mocked response.

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
    assert response.outputs_prefix == 'Box.ShareLink'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response


def test_create_update_folder_share_link_command(requests_mock, mocker):
    """
    Tests the box-create/update-folder-share-link function and command.

    Configures requests_mock instance to generate the appropriate
    folders API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    Verifies:
      - The Authorization header is correct
      - The access field is requested as True.
      - Outputs match the expected result.

    Given: A valid folder_id, password, and unshared_at time.
    When: Executing the  box-create/update-folder-share-link command.
    Then: Return the result where the outputs match the mocked response.

    """
    from BoxV2 import create_update_folder_share_link_command

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
    assert response.outputs_prefix == 'Box.ShareLink'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response


def test_remove_folder_share_link_command(requests_mock, mocker):
    """
    Tests the box-remove-folder-share-link function and command.

    Configures requests_mock instance to generate the appropriate
    folders API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    Verifies:
      - The Authorization header is correct
      - The shared_link argument is requested as None.
      - Outputs match the expected result.

    Given: A valid folder_id.
    When: Executing the box-remove-folder-share-link command.
    Then: Return the result where the outputs match the mocked response.

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
    assert response.outputs_prefix == 'Box.ShareLink'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response


def test_get_folder_command(requests_mock, mocker):
    """
    Tests the box-get-folder function and command.

    Configures requests_mock instance to generate the appropriate
    folders API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    Verifies:
      - The Authorization header is correct
      - The correct URL is called with the folder ID.
      - Outputs match the expected result.

    Given: A valid folder_id.
    When: Executing the box-get-folder command.
    Then: Return the result where the outputs match the mocked response.

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
    Tests the box-list-folder-items function and command.

    Configures requests_mock instance to generate the appropriate
    folders API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    Verifies:
      - The Authorization header is correct
      - The query string is sent with the sort parameter as asc.
      - Outputs match the expected result.

    Given: A valid folder_id.
    When: Executing the box-list-folder-items command.
    Then: Return the result where the outputs match the mocked response.

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
    Tests the box-create-folder function and command.

    Configures requests_mock instance to generate the appropriate
    folders API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    Verifies:
      - The Authorization header is correct
      - The folder name is requested as Testing Folder.
      - Outputs match the expected result.

    Given: A valid parent_id and name.
    When: Executing the box-create-folder command.
    Then: Return the result where the outputs match the mocked response.

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
    Tests the box-file-delete function and command.

    Configures requests_mock instance to generate the appropriate
    files API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    Verifies:
      - The Authorization header is correct
      - The request method is DELETE.
      - Outputs match the expected result.

    Given: A valid file_id.
    When: Executing the box-file-delete command.
    Then: Return the result where the outputs match the mocked response.

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
    Tests the box-list-users function and command.

    Configures requests_mock instance to generate the appropriate
    users API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    Verifies:
      - The Authorization header is correct
      - The query string contains the filter term test_user.
      - Outputs match the expected result.

    Given: A valid filter_term and fields to search in.
    When: Executing the box-list-users command.
    Then: Return the result where the outputs match the mocked response.

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
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response.get('entries')


def test_upload_file_command(requests_mock, mocker):
    """
    Tests the box-upload function and command.

    Configures multiple requests_mock instances to generate the appropriate
    file API responses which are loaded from local JSON files. Checks
    the output of the command function with the expected output.
    Verifies:
     - The correct number of chunks were created and uploaded.
     - Content-Range and Digest headers are correct.
     - The commit request contains the proper amount of parts.

    Given: A file entry ID, file name and destination folder.
    When: Executing the box-upload-file command.
    Then: Return the result where the outputs match the mocked response.

    """
    from BoxV2 import upload_file_command
    from unittest import mock

    # First need to mock the getFilePath object so we can replace with a test file.
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './test_data/test_image.jpg'})

    mock_obj = mock.Mock()
    mock_obj.st_size = 105000000
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
            'file_type': 'jpg',
            'id': 123
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
    assert requests_mock.request_history[0].text == '{"file_name": "test_user.png", "file_size": 105000000, "folder_id": "100"}'

    # Validate first PUT request
    assert requests_mock.request_history[1].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[1].headers.get('Content-Range') == "bytes 0-69999/105000000"
    assert requests_mock.request_history[1].headers.get('Digest') == "SHA=X1QbZ9o+V8TFMLKQ6LBmYEiBdD8="

    # Validate second PUT request
    assert requests_mock.request_history[2].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[2].headers.get('Content-Range') == "bytes 70000-139999/105000000"
    assert requests_mock.request_history[2].headers.get('Digest') == "SHA=XkaxVkVB+djbRD6KHylwQCQOAZY="

    # Skipping the remaining PUT requests

    # Validate request made to commit the file
    assert requests_mock.request_history[6].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[6].headers.get('Digest') == "SHA=O/ybJoSaHW2S0x4O/1p3QTcz3E4="
    assert len(requests_mock.request_history[6].json().get('parts')) == 5

    # Assert number of requests was 7. Where 5 were chunked upload, 1 session, and 1 commit request.
    assert len(requests_mock.request_history) == 7

    assert response.outputs_prefix == 'Box.File'
    assert response.outputs_key_field == 'id'
    assert response.outputs == session_commit_response.get('entities')


def test_get_current_user_command(requests_mock, mocker):
    """
    Tests the box-get-current-user function and command.

    Configures a requests_mock instance to generate the appropriate
    user API response which is loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    Verifies:
     - The As-User header is correct
     - Outputs match the expected format

    Given: A valid user id.
    When: Executing the box-get-current-user command.
    Then: Return the result where the outputs match the mocked response.

    """
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
    """
     Tests the box-create-user function and command.

     Configures a requests_mock instance to generate the appropriate
     user API response which is loaded from a local JSON file. Checks
     the output of the command function with the expected output.
     Verifies:
      - The As-User header is correct
      - Outputs match the expected format
      - Expected user id is sent in the request.
      - Tracking code parameter is formatted correctly.

     Given: Arguments defining a new user's properties.
     When: Executing the box-create-user command.
     Then: Return the result where the outputs match the mocked response.

     """
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
        'tracking_codes': 'tracking_code_key:tracking_code_value,test1:test2',
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
    """
     Tests the box-update-user function and command.

     Configures a requests_mock instance to generate the appropriate
     user API response which is loaded from a local JSON file. Checks
     the output of the command function with the expected output.
     Verifies:
      - The As-User header is correct
      - Outputs match the expected format
      - Expected user id is sent in the request.
      - Expected user's name is correct.
      - Tracking code parameter is formatted correctly.

     Given: Arguments defining a new user's properties.
     When: Executing the box-update-user command.
     Then: Return the result where the outputs match the mocked response.

     """
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
        'tracking_codes': 'tracking_code_key:tracking_code_value,test1:test2',
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
    """
     Tests the box-delete-user function and command.

     Configures a requests_mock instance to generate the appropriate
     user API response which is loaded from a local JSON file. Checks
     the output of the command function with the expected output.
     Verifies:
      - The As-User header is correct
      - Outputs match the expected format
      - Force parameter is True
      - Readable output matches the expected result.

     Given: A valid user ID to delete and the force argument.
     When: Executing the box-delete-user command.
     Then: Return the result where the outputs match the mocked response.

     """
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


def test_fetch_incidents(requests_mock, mocker):
    """
     Tests the fetch-incidents function and command.

     Configures a requests_mock instance to generate the appropriate
     events API response which is loaded from a local JSON file. Checks
     the output of the command function with the expected output.
     Verifies:
      - The As-User header is correct
      - Outputs match the expected format
      - Stream_type parameter is correct.
      - Created after time is formatted correctly.
      - Readable output matches the expected result.
      - New last run time is newer than old last run time.

     Given: A valid last run object and time in the past.
     When: Executing the fetch-incidents command.
     Then: Return a tuple of the last run object and an array of incidents.

     """
    from BoxV2 import fetch_incidents

    client = TestBox(mocker).client

    as_user = 'sample_current_user'
    max_results = 10
    last_run = {'time': '2015-10-21T04:29-8:00'}
    first_fetch_time = 1607935741

    mock_response = util_load_json('test_data/events.json')
    expected_fetch_results = util_load_json('test_data/fetch_expected_response.json')

    requests_mock.get(
        'https://api.box.com/2.0/events/',
        json=mock_response
    )

    response = fetch_incidents(client, max_results, last_run, first_fetch_time, as_user)

    assert requests_mock.request_history[0].headers.get('As-User') == "sample_current_user"
    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].qs.get('stream_type') == ['admin_logs']
    assert requests_mock.request_history[0].qs.get('created_after') == ['2015-10-21t04:29-8:00']

    assert response[0] > '2015-10-21T04:29-8:00'
    assert response[1] == expected_fetch_results


def test_list_user_events_command(requests_mock, mocker):
    """
     Tests the box-list-user-events function and command.

     Configures a requests_mock instance to generate the appropriate
     user API response which is loaded from a local JSON file. Checks
     the output of the command function with the expected output.
     Verifies:
      - The As-User header is correct
      - stream_type is all
      - Length of returned events are greater than 0.

     Given: A valid user ID to delete and the force argument.
     When: Executing the box-list-user-events command.
     Then: Return the result where the outputs match the mocked response.

     """
    from BoxV2 import list_user_events_command

    client = TestBox(mocker).client

    args = {
        'as_user': 'sample_current_user',
        'stream_type': 'all'
    }
    mock_response = util_load_json('test_data/events.json')
    requests_mock.get(
        'https://api.box.com/2.0/events/',
        json=mock_response
    )

    response = list_user_events_command(client, args)

    assert requests_mock.request_history[0].headers.get('As-User') == "sample_current_user"
    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].qs.get('stream_type') == ['all']

    assert len(response.outputs) > 0


def test_list_enterprise_events_command(requests_mock, mocker):
    """
     Tests the box-list-enterprise-events function and command.

     Configures a requests_mock instance to generate the appropriate
     user API response which is loaded from a local JSON file. Checks
     the output of the command function with the expected output.
     Verifies:
      - The As-User header is correct
      - Created after time is more than 3 days from the time test was written.
      - Length of returned events are greater than 0.

     Given: A valid user ID to delete and the force argument.
     When: Executing the box-list-enterprise-events command.
     Then: Return the result where the outputs match the mocked response.

     """
    from BoxV2 import list_enterprise_events_command

    client = TestBox(mocker).client

    args = {
        'as_user': 'sample_current_user',
        'stream_type': 'all',
        'created_after': '3 days'
    }
    mock_response = util_load_json('test_data/events.json')
    requests_mock.get(
        'https://api.box.com/2.0/events/',
        json=mock_response
    )

    response = list_enterprise_events_command(client, args)

    assert requests_mock.request_history[0].headers.get('As-User') == "sample_current_user"
    assert requests_mock.request_history[0].headers.get('Authorization') == "Bearer JWT_TOKEN"
    assert requests_mock.request_history[0].qs.get('created_after')[0] > '2020-12-12t09:51:28'

    assert len(response.outputs) > 0
