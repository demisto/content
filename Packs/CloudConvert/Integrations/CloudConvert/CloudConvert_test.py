from CloudConvert import import_command, Client, convert_command, check_status_command, export_command
import CommonServerPython
import json
import io
import pytest

MOCK_API_KEY = "a1b2c3d4e5"
MOCK_URL = 'https://www.thisisamockurl.com'


def create_client():
    headers = {
        'Authorization': f'Bearer {MOCK_API_KEY}'
    }
    return Client(headers=headers)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_import_valid_url(mocker):
    """

    Given:
        - Valid url of a file, str
    When:
        - When the user uploads a file for later conversion via url
    Then:
        - Returns the response data

    """
    client = create_client()
    mocker.patch.object(client, 'import_url', return_value=util_load_json('./test_data/import_url_response.json'))
    results = import_command(client, {'url': MOCK_URL})
    assert results.outputs == util_load_json('./test_data/import_url_response.json').get('data')


def test_import_invalid_url(mocker):
    """

    Given:
        - Invalid url of a file, str
    When:
        - When the user uploads a file for later conversion via url
    Then:
        - Returns the response data

    """
    client = create_client()
    mocker.patch.object(client, 'import_url', return_value=util_load_json('./test_data/import_url_bad_url_response.json'))
    with pytest.raises(ValueError) as e:
        import_command(client, {'url': MOCK_URL})
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
    assert results.outputs == util_load_json('test_data/convert_valid_format_and_id_response.json').get('data')


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
    mocker.patch.object(client, 'convert', return_value=util_load_json('test_data/convert_invalid_format_or_id_response.json'))
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
    mocker.patch.object(client, 'check_status', return_value=util_load_json('test_data/check_status_bad_id_response.json'))
    with pytest.raises(ValueError) as e:
        check_status_command(client, {
            'task_id': 'ff'
        })
        if not e:
            assert False


@pytest.mark.parametrize('entry_id', [True, False])
def test_check_status_valid_id_non_export(mocker, entry_id):
    """

    Given:
        - A valid task id, of a non-export operation
    When:
        - When the user checks the status of a task that was priorly done, and it is not export.
        the purpose here is to make sure that the extra argument, 'is_entry', only makes a difference when the id is of
        an actual export operation.
    Then:
        - Returns the response

    """
    client = create_client()
    mocker.patch.object(client, 'check_status', return_value=util_load_json(
        'test_data/check_status_non_export_response.json'))

    results = check_status_command(client, {
        'task_id': 'id',
        'entry_id': entry_id
    })
    assert results.outputs == util_load_json('test_data/check_status_non_export_response.json').get('data')


@pytest.mark.parametrize('entry_id', [True, False])
def test_check_status_valid_id_export(mocker, entry_id):
    """

    Given:
        - A valid task id, of an export operation
    When:
        - When the user checks the status of a task that was priorly done, and it is an export operation.

    Then:
        - When checking on a export operation and the argument 'is_entry' is set to True, the output is a
        warroom entry. if set to False, then a regular response is retrieved.

    """
    import CloudConvert
    client = create_client()
    mocker.patch.object(client, 'check_status', return_value=util_load_json(
        'test_data/check_status_export_response.json'))
    mocker.patch.object(client, 'get_file_from_url', return_value='')
    file_name = util_load_json('test_data/check_status_export_response.json').get('data'). \
        get('result').get('files')[0].get('filename')
    mocker.patch.object(CloudConvert, 'fileResult', return_value={'File': file_name})
    results = check_status_command(client, {
        'task_id': 'id',
        'is_entry': entry_id
    })
    if entry_id:
        assert results.get('File') == file_name

    else:
        assert results.outputs == util_load_json('test_data/check_status_export_response.json').get('data')


@pytest.mark.parametrize('export_as', ['war_room_entry', 'url'])
def test_export_invalid_id(mocker, export_as):
    """

    Given:
        - Invalid task id for given file
    When:
        - When the user wants to export a file that was priorly uploaded
    Then:
        - Returns the response message of invalid input

    """
    client = create_client()
    mocker.patch.object(client, 'export_url', return_value=util_load_json('test_data/export_invalid_id_response.json'))
    with pytest.raises(ValueError) as e:
        export_command(client, {
            'task_id': 'id',
            'export_as': export_as
        })
        if not e:
            assert False


@pytest.mark.parametrize('export_as', ['war_room_entry', 'url'])
def test_export_valid_id(mocker, export_as):
    """

    Given:
        - Valid task id for given file
    When:
        - When the user wants to export a file that was priorly uploaded
    Then:
        - Returns the response message of invalid input

    """
    client = create_client()
    mocker.patch.object(client, 'export_url', return_value=util_load_json('test_data/export_valid_id_response.json'))

    results = export_command(client, {
        'task_id': 'id',
        'export_as': export_as
    })
    if export_as == 'url':
        assert results.outputs == util_load_json('test_data/export_valid_id_response.json').get('data')
    else:
        request_results = util_load_json('test_data/export_valid_id_response.json')
        request_results['data']['operation'] = 'export/entry'
        assert results.outputs == request_results.get('data')
