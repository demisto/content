import uuid
from http import HTTPStatus

from intezer_sdk import consts
from intezer_sdk.api import IntezerApi

from Packs.Intezer.Integrations.IntezerV2.IntezerV2 import analyze_by_hash_command

fake_api_key = str(uuid.uuid4())
intezer_api = IntezerApi(consts.API_VERSION, fake_api_key, consts.BASE_URL)

full_url = f'{consts.BASE_URL}{consts.API_VERSION}'


def _setup_access_token(requests_mock):
    requests_mock.post(f'{full_url}/get-access-token', json=dict(result='access-token'))


# region intezer-analyze-by-hash
def test_analyze_by_hash_command_success(requests_mock):
    # Arrange
    analysis_id = 'analysis-id'

    _setup_access_token(requests_mock)
    requests_mock.post(
        f'{full_url}/analyze-by-hash',
        status_code=HTTPStatus.CREATED,
        json=dict(result_url=f'/analyses/{analysis_id}')
    )

    args = dict(file_hash='123test')

    # Act
    command_results = analyze_by_hash_command(intezer_api, args)

    # Assert
    assert command_results.outputs['ID'] == analysis_id


def test_analyze_by_hash_command_missing_hash(requests_mock):
    # Arrange

    _setup_access_token(requests_mock)
    requests_mock.post(
        f'{full_url}/analyze-by-hash',
        status_code=HTTPStatus.NOT_FOUND
    )

    file_hash = '123test'
    args = dict(file_hash=file_hash)

    # Act
    command_results = analyze_by_hash_command(intezer_api, args)

    # Assert
    assert command_results.readable_output == f'The Hash {file_hash} was not found on Intezer genome database'


def test_analyze_by_hash_command_already_running(requests_mock):
    # Arrange
    _setup_access_token(requests_mock)
    requests_mock.post(
        f'{full_url}/analyze-by-hash',
        status_code=HTTPStatus.CONFLICT
    )

    file_hash = '123test'
    args = dict(file_hash=file_hash)

    # Act
    command_results = analyze_by_hash_command(intezer_api, args)

    # Assert
    assert command_results.readable_output == 'Analysis is still in progress'

# endregion
