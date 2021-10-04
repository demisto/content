import tempfile
import uuid
from http import HTTPStatus

from CommonServerPython import outputPaths
from IntezerV2 import analyze_by_hash_command
from IntezerV2 import analyze_by_uploaded_file_command
from IntezerV2 import check_analysis_status_and_get_results_command
from IntezerV2 import get_analysis_code_reuse_command
from IntezerV2 import get_analysis_metadata_command
from IntezerV2 import get_analysis_sub_analyses_command
from IntezerV2 import get_family_info_command
from IntezerV2 import get_latest_result_command
from intezer_sdk import consts
from intezer_sdk.api import IntezerApi

fake_api_key = str(uuid.uuid4())
intezer_api = IntezerApi(consts.API_VERSION, fake_api_key, consts.BASE_URL)

full_url = f'{consts.BASE_URL}{consts.API_VERSION}'


def _setup_access_token(requests_mock):
    requests_mock.post(f'{full_url}/get-access-token', json=dict(result='access-token'))


# region analyze_by_hash_command
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

# region get_latest_result_command

def test_get_latest_result_command_success(requests_mock):
    # Arrange
    sha256 = 'sha256'
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/files/{sha256}',
        json={
            'result': {
                'analysis_id': analysis_id,
                'sub_verdict': 'trusted',
                'sha256': sha256,
                'verdict': 'trusted',
                'analysis_url': 'bla'
            }
        }
    )

    args = dict(file_hash=sha256)

    # Act
    command_results = get_latest_result_command(intezer_api, args)

    # Assert
    assert len(command_results.outputs) == 3
    assert command_results.outputs[outputPaths['dbotscore']]['Indicator'] == sha256


def test_get_latest_result_command_file_missing(requests_mock):
    # Arrange
    sha256 = 'sha256'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/files/{sha256}',
        status_code=HTTPStatus.NOT_FOUND
    )

    args = dict(file_hash=sha256)

    # Act
    command_results = get_latest_result_command(intezer_api, args)

    # Assert
    assert command_results.readable_output == f'The Hash {sha256} was not found on Intezer genome database'


# endregion

# region analyze_by_uploaded_file_command

def test_analyze_by_uploaded_file_command_success(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis-id'

    _setup_access_token(requests_mock)
    requests_mock.post(
        f'{full_url}/analyze',
        status_code=HTTPStatus.CREATED,
        json=dict(result_url=f'/analyses/{analysis_id}')
    )

    args = dict(file_entry_id='123@123')

    # Act
    with tempfile.NamedTemporaryFile() as file:
        file_path_patch = mocker.patch('demistomock.getFilePath')
        file_path_patch.return_value = dict(path=file.name)
        command_results = analyze_by_uploaded_file_command(intezer_api, args)

    # Assert
    assert command_results.outputs['ID'] == analysis_id


def test_analyze_by_uploaded_file_command_analysis_already_running(requests_mock, mocker):
    # Arrange

    _setup_access_token(requests_mock)
    requests_mock.post(
        f'{full_url}/analyze',
        status_code=HTTPStatus.CONFLICT
    )

    args = dict(file_entry_id='123@123')

    # Act
    with tempfile.NamedTemporaryFile() as file:
        file_path_patch = mocker.patch('demistomock.getFilePath')
        file_path_patch.return_value = dict(path=file.name)
        command_results = analyze_by_uploaded_file_command(intezer_api, args)

    # Assert
    assert command_results.readable_output == 'Analysis is still in progress'


# endregion

# region check_analysis_status_and_get_results_command

def test_check_analysis_status_and_get_results_command_single_success(requests_mock):
    # Arrange
    sha256 = 'sha256'
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
                'sub_verdict': 'trusted',
                'sha256': sha256,
                'verdict': 'trusted',
                'analysis_url': 'bla'
            },
            'status': 'succeeded'
        }
    )

    args = dict(analysis_id=analysis_id)

    # Act
    command_results_list = check_analysis_status_and_get_results_command(intezer_api, args)

    # Assert
    assert len(command_results_list) == 1

    first_result = command_results_list[0]
    assert first_result.outputs[outputPaths['dbotscore']]['Indicator'] == sha256


def test_check_analysis_status_and_get_results_command_single_success_endpoint(requests_mock):
    # Arrange
    sha256 = 'sha256'
    analysis_id = 'analysis_id'
    computer_name = 'kfir-pc'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/endpoint-analyses/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
                'sub_verdict': 'trusted',
                'sha256': sha256,
                'verdict': 'trusted',
                'analysis_url': 'bla',
                'computer_name': computer_name,
                'scan_start_time': 'now'
            }
        }
    )

    args = dict(analysis_id=analysis_id, analysis_type='Endpoint')

    # Act
    command_results_list = check_analysis_status_and_get_results_command(intezer_api, args)

    # Assert
    assert len(command_results_list) == 1

    first_result = command_results_list[0]
    assert first_result.outputs[outputPaths['dbotscore']]['Indicator'] == computer_name
    assert first_result.outputs['Intezer.Analysis(val.ID && val.ID == obj.ID)']['ID'] == analysis_id


def test_check_analysis_status_and_get_results_command_multiple_analyses(requests_mock):
    # Arrange
    sha256_1 = 'sha256'
    analysis_id_1 = 'analysis_id'

    sha256_2 = 'sha256foo'
    analysis_id_2 = 'analysis_id-2'

    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id_1}',
        json={
            'result': {
                'analysis_id': analysis_id_1,
                'sub_verdict': 'trusted',
                'sha256': sha256_1,
                'verdict': 'trusted',
                'analysis_url': 'bla'
            },
            'status': 'succeeded'
        }
    )
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id_2}',
        json={
            'result': {
                'analysis_id': analysis_id_2,
                'sub_verdict': 'trusted',
                'sha256': sha256_2,
                'verdict': 'trusted',
                'analysis_url': 'bla'
            },
            'status': 'succeeded'
        }
    )

    args = dict(analysis_id=f'{analysis_id_1},{analysis_id_2}')

    # Act
    command_results_list = check_analysis_status_and_get_results_command(intezer_api, args)

    # Assert
    assert len(command_results_list) == 2

    first_result = command_results_list[0]
    assert first_result.outputs[outputPaths['dbotscore']]['Indicator'] == sha256_1

    second_result = command_results_list[1]
    assert second_result.outputs[outputPaths['dbotscore']]['Indicator'] == sha256_2


def test_check_analysis_status_and_get_results_command_multiple_analyses_one_fails(requests_mock):
    # Arrange
    sha256_1 = 'sha256'
    analysis_id_1 = 'analysis_id'

    analysis_id_2 = 'analysis_id-2'

    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id_1}',
        json={
            'result': {
                'analysis_id': analysis_id_1,
                'sub_verdict': 'trusted',
                'sha256': sha256_1,
                'verdict': 'trusted',
                'analysis_url': 'bla'
            },
            'status': 'succeeded'
        }
    )
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id_2}',
        status_code=HTTPStatus.NOT_FOUND,
    )

    args = dict(analysis_id=f'{analysis_id_1},{analysis_id_2}')

    # Act
    command_results_list = check_analysis_status_and_get_results_command(intezer_api, args)

    # Assert
    assert len(command_results_list) == 2

    first_result = command_results_list[0]
    assert first_result.outputs[outputPaths['dbotscore']]['Indicator'] == sha256_1

    second_result = command_results_list[1]
    assert second_result.readable_output == f'The Analysis {analysis_id_2} was not found on Intezer Analyze'


# endregion

# region get_analysis_sub_analyses_command

def test_get_analysis_sub_analyses_command_success(requests_mock):
    # Arrange
    sha256 = 'sha256'
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
                'sub_verdict': 'trusted',
                'sha256': sha256,
                'verdict': 'trusted',
                'analysis_url': 'bla'
            },
            'status': 'succeeded'
        }
    )
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses',
        json={
            'sub_analyses': [
                {
                    'sub_analysis_id': '123123',
                    'source': 'dynamic',
                    'sha256': 'sha256',
                }
            ]
        }
    )

    args = dict(analysis_id=analysis_id)

    # Act
    command_results = get_analysis_sub_analyses_command(intezer_api, args)

    # Assert
    assert len(command_results.outputs['SubAnalysesIDs']) == 1


def test_get_analysis_sub_analyses_command_analysis_doesnt_exist(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}',
        status_code=HTTPStatus.NOT_FOUND
    )

    args = dict(analysis_id=analysis_id)

    # Act
    command_results = get_analysis_sub_analyses_command(intezer_api, args)

    # Assert
    assert command_results.readable_output == f'The Analysis {analysis_id} was not found on Intezer Analyze'


# endregion

# region get_analysis_code_reuse_command

def test_get_analysis_code_reuse_command_success_root(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses/root/code-reuse',
        json={
            'families': [
                {
                    'family_id': '123',
                    'family_name': 'Name',
                    'reused_gene_count': 123
                }
            ],
            'unique_gene_count': 0
        }
    )

    args = dict(analysis_id=analysis_id)

    # Act
    command_results = get_analysis_code_reuse_command(intezer_api, args)

    # Assert
    outputs = command_results.outputs['Intezer.Analysis(obj.ID == val.ID)']
    assert outputs['ID'] == analysis_id
    assert len(outputs['CodeReuseFamilies']) == 1
    assert 'CodeReuse' in outputs


def test_get_analysis_code_reuse_command_success(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    sub_analysis_id = 'sub_analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses/{sub_analysis_id}/code-reuse',
        json={
            'families': [
                {
                    'family_id': '123',
                    'family_name': 'Name',
                    'reused_gene_count': 123
                }
            ],
            'unique_gene_count': 0
        }
    )

    args = dict(analysis_id=analysis_id, sub_analysis_id=sub_analysis_id)

    # Act
    command_results = get_analysis_code_reuse_command(intezer_api, args)

    # Assert
    outputs = command_results.outputs['Intezer.Analysis(obj.RootAnalysis == val.ID).SubAnalyses(obj.ID == val.ID)']
    assert outputs['ID'] == sub_analysis_id
    assert outputs['RootAnalysis'] == analysis_id
    assert len(outputs['CodeReuseFamilies']) == 1
    assert 'CodeReuse' in outputs


def test_get_analysis_code_reuse_command_analysis_doesnt_exist(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    sub_analysis_id = 'sub_analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses/{sub_analysis_id}/code-reuse',
        status_code=HTTPStatus.NOT_FOUND
    )

    args = dict(analysis_id=analysis_id, sub_analysis_id=sub_analysis_id)

    # Act
    command_results = get_analysis_code_reuse_command(intezer_api, args)

    # Assert
    assert command_results.readable_output == f'The Analysis {analysis_id} was not found on Intezer Analyze'


def test_get_analysis_code_reuse_command_no_code_reuse(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    sub_analysis_id = 'sub_analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses/{sub_analysis_id}/code-reuse',
        status_code=HTTPStatus.CONFLICT
    )

    args = dict(analysis_id=analysis_id, sub_analysis_id=sub_analysis_id)

    # Act
    command_results = get_analysis_code_reuse_command(intezer_api, args)

    # Assert
    assert command_results.readable_output == 'No code reuse for this analysis'


# endregion

# region get_analysis_metadata_command

def test_get_analysis_metadata_command_success_root(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses/root/metadata',
        json={
            'sha256': 'sha256',
            'product_name': 'something'
        }
    )

    args = dict(analysis_id=analysis_id)

    # Act
    command_results = get_analysis_metadata_command(intezer_api, args)

    # Assert
    outputs = command_results.outputs['Intezer.Analysis(obj.ID == val.ID)']
    assert outputs['ID'] == analysis_id
    assert 'Metadata' in outputs


def test_get_analysis_metadata_command_success(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    sub_analysis_id = 'sub_analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses/{sub_analysis_id}/metadata',
        json={
            'sha256': 'sha256',
            'product_name': 'something'
        }
    )

    args = dict(analysis_id=analysis_id, sub_analysis_id=sub_analysis_id)

    # Act
    command_results = get_analysis_metadata_command(intezer_api, args)

    # Assert
    outputs = command_results.outputs['Intezer.Analysis(obj.RootAnalysis == val.ID).SubAnalyses(obj.ID == val.ID)']
    assert outputs['ID'] == sub_analysis_id
    assert outputs['RootAnalysis'] == analysis_id
    assert 'Metadata' in outputs


def test_get_analysis_metadata_command_analysis_doesnt_exist(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    sub_analysis_id = 'sub_analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses/{sub_analysis_id}/metadata',
        status_code=HTTPStatus.NOT_FOUND
    )

    args = dict(analysis_id=analysis_id, sub_analysis_id=sub_analysis_id)

    # Act
    command_results = get_analysis_metadata_command(intezer_api, args)

    # Assert
    assert command_results.readable_output == f'The Analysis {analysis_id} was not found on Intezer Analyze'


# endregion

# region get_family_info_command

def test_get_family_info_command_success(requests_mock):
    # Arrange
    family_id = 'family_id'
    family_name = 'Kfir'
    family_type = 'Malicious'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/families/{family_id}/info',
        json={
            'result': {
                'family_name': family_name,
                'family_type': family_type
            }
        }
    )

    args = dict(family_id=family_id)

    # Act
    command_results = get_family_info_command(intezer_api, args)

    # Assert
    assert command_results.outputs['Name'] == family_name
    assert command_results.outputs['Type'] == family_type


def test_get_family_info_command_analysis_doesnt_exist(requests_mock):
    # Arrange
    family_id = 'family_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/families/{family_id}/info',
        status_code=HTTPStatus.NOT_FOUND
    )

    args = dict(family_id=family_id)

    # Act
    command_results = get_family_info_command(intezer_api, args)

    # Assert
    assert command_results.readable_output == f'The Family {family_id} was not found on Intezer Analyze'

# endregion
