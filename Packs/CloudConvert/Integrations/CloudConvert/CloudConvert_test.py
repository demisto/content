from CloudConvert import upload_command, Client, convert_command, check_status_command, download_command, modify_results_dict
from CommonServerPython import remove_empty_elements, tableToMarkdown, string_to_table_header
import demistomock as demisto
import json
import io
import pytest


MOCK_API_KEY = "a1b2c3d4e5"
MOCK_URL = 'https://www.thisisamockurl.com'
MOCK_ENTRY_ID = '@123'


def create_client():
    headers = {
        'Authorization': f'Bearer {MOCK_API_KEY}'
    }
    return Client(headers=headers)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_upload_valid_url(mocker):
    """

    Given:
        - Valid url of a file, str
    When:
        - When the user uploads a file for later conversion via url
    Then:
        - Returns the response data

    """
    client = create_client()
    mocker.patch.object(client, 'upload_url', return_value=util_load_json('./test_data/upload_url_response.json'))
    results = upload_command(client, {'url': MOCK_URL})
    raw_response = util_load_json('./test_data/upload_url_response.json')
    raw_response['data']['operation'] = 'upload/url'
    readable_output = tableToMarkdown('Upload Results', remove_empty_elements(raw_response.get('data')),
                                      headers=('id', 'operation', 'created_at', 'status'),
                                      headerTransform=string_to_table_header,
                                      )

    assert results.outputs == remove_empty_elements(raw_response.get('data'))
    assert results.readable_output == readable_output


def test_upload_invalid_url(mocker):
    """

    Given:
        - Invalid url of a file, str
    When:
        - When the user uploads a file for later conversion via url
    Then:
        - Returns the response message of invalid input

    """
    client = create_client()
    mocker.patch.object(client, 'upload_url', return_value=util_load_json('./test_data/upload_url_bad_url_response.json'))
    with pytest.raises(ValueError) as e:
        upload_command(client, {'url': MOCK_URL})
        if not e:
            assert False


def test_upload_valid_entry(mocker):
    """

    Given:
        - Valid entry id of a file, str
    When:
        - When the user uploads a file for later conversion via entry
    Then:
        - Returns the response data

    """

    client = create_client()
    mocker.patch.object(client, 'upload_entry_id',
                        return_value=util_load_json('./test_data/upload_entry_response.json'))
    results = upload_command(client, {'entry_id': MOCK_ENTRY_ID})
    raw_response = util_load_json('./test_data/upload_entry_response.json')
    raw_response['data']['operation'] = 'upload/entry'
    readable_output = tableToMarkdown('Upload Results',
                                      remove_empty_elements(raw_response.get('data')),
                                      headers=('id', 'operation', 'created_at', 'status'),
                                      headerTransform=string_to_table_header,
                                      )

    assert results.outputs == remove_empty_elements(raw_response.get('data'))
    assert results.readable_output == readable_output


def test_upload_invalid_entry(mocker):
    """

    Given:
        - Invalid entry id of a file, str
    When:
        - When the user uploads a file for later conversion via entry
    Then:
        - Returns the response message of invalid input

    """

    client = create_client()
    mocker.patch.object(demisto, 'getFilePath', return_value=None)
    with pytest.raises(ValueError) as e:
        upload_command(client, {'entry_id': MOCK_ENTRY_ID})
        if not e:
            assert False


def test_convert_valid_format_and_id(mocker):
    """

    Given:
        - Valid destination format for given file
    When:
        - When the user converts a file that was priorly uploaded
    Then:
        - Returns the response data

    """
    client = create_client()
    mocker.patch.object(client, 'convert', return_value=util_load_json(
        'test_data/convert_valid_format_and_id_response.json'))
    results = convert_command(client, {
        'task_id': 'id',
        'output_format': 'pdf'
    })
    readable_output = tableToMarkdown('Convert Results',
                                      remove_empty_elements(util_load_json('test_data/convert_val'
                                                                           'id_format_and_id_response.'
                                                                           'json').get('data')),
                                      headers=('id', 'operation', 'created_at', 'status', 'depends_on_task_ids'),
                                      headerTransform=string_to_table_header)
    assert results.outputs == remove_empty_elements(util_load_json('test_data/convert_valid_format_and_id_response.json'
                                                                   ).get('data'))
    assert results.readable_output == readable_output


def test_convert_invalid_format_or_id(mocker):
    """

    Given:
        - Inalid destination format for given file
    When:
        - When the user converts a file that was priorly uploaded
    Then:
        - Returns the response message of invalid input

    """
    client = create_client()
    mocker.patch.object(client, 'convert', return_value=util_load_json('test_data/convert_invalid_format_or_id'
                                                                       '_response.json'))
    with pytest.raises(ValueError) as e:
        convert_command(client, {
            'task_id': 'ff',
            'output_format': 'ff'
        })
        if not e:
            assert False


def test_check_status_invalid_id(mocker):
    """

    Given:
        - Inalid task id for given file
    When:
        - When the user checks the status of a task that was priorly done
    Then:
        - Returns the response message of invalid input

    """
    client = create_client()
    mocker.patch.object(client, 'check_status', return_value=util_load_json('test_data/'
                                                                            'check_status_bad_id_response.json'))
    with pytest.raises(ValueError) as e:
        check_status_command(client, {
            'task_id': 'ff'
        })
        if not e:
            assert False


@pytest.mark.parametrize('create_war_room_entry', [True, False])
def test_check_status_valid_id_non_download(mocker, create_war_room_entry):
    """

    Given:
        - A valid task id, of a non-download operation
    When:
        - When the user checks the status of a task that was priorly done, and it is not download.
        the purpose here is to make sure that the extra argument, 'create_war_room_entry', only makes a difference
         when the id is of an actual download operation.
    Then:
        - Returns the response

    """
    client = create_client()
    mocker.patch.object(client, 'check_status', return_value=util_load_json(
        'test_data/check_status_non_download_response.json'))
    results = check_status_command(client, {
        'task_id': 'id',
        'create_war_room_entry': create_war_room_entry
    })
    raw_response_data = util_load_json('test_data/check_status_non_download_response.json').get('data')
    modify_results_dict(raw_response_data)
    readable_output = tableToMarkdown('Check Status Results',
                                      remove_empty_elements(raw_response_data),
                                      headers=('id', 'operation', 'created_at', 'status', 'depends_on_task_ids',
                                               'file_name', 'url'),
                                      headerTransform=string_to_table_header)
    modify_results_dict(raw_response_data)
    assert results.outputs == remove_empty_elements(raw_response_data)
    assert results.readable_output == readable_output


@pytest.mark.parametrize('create_war_room_entry', [True, False])
def test_check_status_valid_id_download(mocker, create_war_room_entry):
    """

    Given:
        - A valid task id, of an download operation
    When:
        - When the user checks the status of a task that was priorly done, and it is an download operation.

    Then:
        - When checking on a download operation and the argument 'create_war_room_entry' is set to True, the output is a
        warroom entry. if set to False, then a regular response is retrieved.

    """
    import CloudConvert
    client = create_client()
    mocker.patch.object(client, 'check_status', return_value=util_load_json(
        'test_data/check_status_download_response.json'))
    mocker.patch.object(client, 'get_file_from_url', return_value='')
    file_name = util_load_json('test_data/check_status_download_response.json').get('data'). \
        get('result').get('files')[0].get('filename')
    mocker.patch.object(CloudConvert, 'fileResult', return_value={'File': file_name})
    results = check_status_command(client, {
        'task_id': 'id',
        'create_war_room_entry': create_war_room_entry
    })
    raw_response_data = util_load_json('test_data/check_status_download_response.json').get('data')
    modify_results_dict(raw_response_data)
    if create_war_room_entry:
        raw_response_data['operation'] = 'download/entry'
        assert results.get('File') == file_name

    else:
        raw_response_data['operation'] = 'download/url'
        assert results.outputs == remove_empty_elements(raw_response_data)
        readable_output = tableToMarkdown('Check Status Results',
                                          remove_empty_elements(raw_response_data),
                                          headers=('id', 'operation', 'created_at', 'status', 'depends_on_task_ids',
                                                   'file_name', 'url'),
                                          headerTransform=string_to_table_header)
        assert results.readable_output == readable_output


@pytest.mark.parametrize('download_as', ['war_room_entry', 'url'])
def test_download_invalid_id(mocker, download_as):
    """

    Given:
        - Invalid task id for given file
    When:
        - When the user wants to download a file that was priorly uploaded
    Then:
        - Returns the response message of invalid input

    """
    client = create_client()
    mocker.patch.object(client, 'download_url', return_value=util_load_json('test_data/download_invalid_id_response.json'))
    with pytest.raises(ValueError) as e:
        download_command(client, {
            'task_id': 'id',
            'download_as': download_as
        })
        if not e:
            assert False


@pytest.mark.parametrize('download_as', ['war_room_entry', 'url'])
def test_download_valid_id(mocker, download_as):
    """

    Given:
        - Valid task id for given file
    When:
        - When the user wants to download a file that was priorly uploaded
    Then:
        - Returns the response message of invalid input

    """
    client = create_client()
    mocker.patch.object(client, 'download_url', return_value=util_load_json('test_data/download_valid_id_response.json'))

    results = download_command(client, {
        'task_id': 'id',
        'download_as': download_as
    })
    raw_response = util_load_json('test_data/download_valid_id_response.json')
    if download_as == 'url':
        raw_response['data']['operation'] = 'download/url'
        readable_output = tableToMarkdown('Download Results',
                                          remove_empty_elements(raw_response.get('data')),
                                          headers=('id', 'operation', 'created_at', 'status', 'depends_on_task_ids'),
                                          headerTransform=string_to_table_header,
                                          )
        assert results.outputs == remove_empty_elements(raw_response.get('data'))
        assert results.readable_output == readable_output

    else:
        raw_response['data']['operation'] = 'download/entry'
        assert results.outputs == remove_empty_elements(raw_response.get('data'))
