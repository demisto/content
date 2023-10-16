import tempfile
import uuid
from http import HTTPStatus
from unittest.mock import patch

import intezer_sdk.errors
import pytest
from intezer_sdk.alerts import Alert
from intezer_sdk.analysis import FileAnalysis
from intezer_sdk.analysis import UrlAnalysis
from intezer_sdk.consts import AlertStatusCode

from CommonServerPython import *

from IntezerV2 import analyze_by_hash_command
from IntezerV2 import analyze_by_uploaded_file_command
from IntezerV2 import analyze_url_command
from IntezerV2 import check_analysis_status_and_get_results_command
from IntezerV2 import get_analysis_code_reuse_command
from IntezerV2 import get_analysis_iocs_command
from IntezerV2 import get_analysis_metadata_command
from IntezerV2 import get_analysis_sub_analyses_command
from IntezerV2 import get_family_info_command
from IntezerV2 import get_latest_result_command
from IntezerV2 import get_file_analysis_result_command
from IntezerV2 import get_endpoint_analysis_result_command
from IntezerV2 import get_url_analysis_result_command
from IntezerV2 import check_is_available
from IntezerV2 import submit_alert_command
from IntezerV2 import submit_suspected_phishing_email_command
from IntezerV2 import get_alert_result_command
from IntezerV2 import enrich_dbot_and_display_alert_results
from intezer_sdk import consts
from intezer_sdk.api import IntezerApi

fake_api_key = str(uuid.uuid4())
intezer_api = IntezerApi(consts.API_VERSION, fake_api_key, consts.BASE_URL)

full_url = f'{consts.BASE_URL}{consts.API_VERSION}'


def _setup_access_token(requests_mock):
    requests_mock.post(f'{full_url}/get-access-token', json={"result": 'access-token'})


# region analyze_by_hash_command
def test_analyze_by_hash_command_success(requests_mock):
    # Arrange
    analysis_id = 'analysis-id'

    _setup_access_token(requests_mock)
    requests_mock.post(
        f'{full_url}/analyze-by-hash',
        status_code=HTTPStatus.CREATED,
        json={"result_url": f'/analyses/{analysis_id}'}
    )

    args = {"file_hash": '123test'}

    # Act
    command_results = analyze_by_hash_command(args, intezer_api)

    # Assert
    assert command_results.outputs['ID'] == analysis_id


def test_analyze_by_hash_command_success_polling_true(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis-id'

    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.post(
        f'{full_url}/analyze-by-hash',
        status_code=HTTPStatus.CREATED,
        json={"result_url": f'/analyses/{analysis_id}'}
    )

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
            },
            'status': 'in_progress'
        }
    )

    args = {"file_hash": '123test', "wait_for_result": True}

    # Act
    command_results = analyze_by_hash_command(args, intezer_api)

    # Assert
    assert command_results.readable_output == 'Fetching Intezer analysis. Please wait...'


def test_analyze_by_hash_command_missing_hash(requests_mock):
    # Arrange

    _setup_access_token(requests_mock)
    requests_mock.post(
        f'{full_url}/analyze-by-hash',
        status_code=HTTPStatus.NOT_FOUND
    )

    file_hash = '123test'
    args = {"file_hash": file_hash}

    # Act
    command_results = analyze_by_hash_command(args, intezer_api)

    # Assert
    assert command_results.readable_output == f'The Hash {file_hash} was not found on Intezer genome database'


def test_analyze_by_hash_command_already_running(requests_mock):
    # Arrange
    _setup_access_token(requests_mock)
    requests_mock.post(
        f'{full_url}/analyze-by-hash',
        json={},
        status_code=HTTPStatus.CONFLICT
    )

    file_hash = '123test'
    args = {"file_hash": file_hash}

    # Act
    command_results = analyze_by_hash_command(args, intezer_api)

    # Assert
    assert command_results.readable_output == 'Analysis is still in progress'


# endregion

# region get_latest_result_command

def test_get_latest_result_command_success(requests_mock):
    # Arrange
    sha256 = 'sha256'
    md5 = 'md5'
    sha1 = 'sha1'
    analysis_id = 'analysis_id'
    root_sub_analysis = 'root_analysis_id'
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

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses',
        json={'sub_analyses': [{
            'sha256': sha256,
            'source': 'root',
            'sub_analysis_id': root_sub_analysis
        }]
        }
    )

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses/{root_sub_analysis}/metadata',
        json={
            'file_type': 'non executable',
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
            'size_in_bytes': 838,
            'ssdeep': '12:dfhfgjh:sdfghfgjfgh'
        }
    )

    args = {"file_hash": sha256}

    # Act
    command_results = get_latest_result_command(args, intezer_api)

    # Assert
    indicators = [dbotscore['Indicator'] for dbotscore in command_results.outputs[outputPaths['dbotscore']]]

    assert len(command_results.outputs) == 3
    assert all(indicator in indicators for indicator in [sha256, md5, sha1])


def test_get_latest_result_command_file_missing(requests_mock):
    # Arrange
    sha256 = 'sha256'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/files/{sha256}',
        status_code=HTTPStatus.NOT_FOUND
    )

    args = {"file_hash": sha256}

    # Act
    command_results = get_latest_result_command(args, intezer_api)

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
        json={"result_url": f'/analyses/{analysis_id}'}
    )

    args = {"file_entry_id": '123@123'}

    # Act
    with tempfile.NamedTemporaryFile() as file:
        file_path_patch = mocker.patch('demistomock.getFilePath')
        file_path_patch.return_value = {"path": file.name, "name": file.name}
        command_results = analyze_by_uploaded_file_command(args, intezer_api)

    # Assert
    assert command_results.outputs['ID'] == analysis_id
    assert command_results.scheduled_command is None
    assert command_results.outputs == {'ID': analysis_id, 'Status': 'Created', 'Type': 'File'}


def test_analyze_by_uploaded_file_command_polling_true(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis-id'

    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.post(
        f'{full_url}/analyze',
        status_code=HTTPStatus.CREATED,
        json={"result_url": f'/analyses/{analysis_id}'}
    )

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
            },
            'status': 'in_progress'
        }
    )

    args = {"file_entry_id": '123@123', "wait_for_result": True}

    # Act
    with tempfile.NamedTemporaryFile() as file:
        file_path_patch = mocker.patch('demistomock.getFilePath')
        file_path_patch.return_value = {"path": file.name, "name": file.name}
        command_results = analyze_by_uploaded_file_command(args, intezer_api)

    # Assert
    assert command_results.readable_output == 'Fetching Intezer analysis. Please wait...'
    assert command_results.outputs is None


def test_analyze_by_uploaded_file_command_analysis_already_running(requests_mock, mocker):
    # Arrange

    _setup_access_token(requests_mock)
    requests_mock.post(
        f'{full_url}/analyze',
        json={},
        status_code=HTTPStatus.CONFLICT
    )

    args = {"file_entry_id": '123@123'}

    # Act
    with tempfile.NamedTemporaryFile() as file:
        file_path_patch = mocker.patch('demistomock.getFilePath')
        file_path_patch.return_value = {"path": file.name, "name": file.name}
        command_results = analyze_by_uploaded_file_command(args, intezer_api)

    # Assert
    assert command_results.readable_output == 'Analysis is still in progress'


# endregion

# region check_analysis_status_and_get_results_command

def test_check_analysis_status_and_get_results_command_single_success(requests_mock):
    # Arrange
    sha256 = 'sha256'
    md5 = 'md5'
    sha1 = 'sha1'
    analysis_id = 'analysis_id'
    root_sub_analysis = 'root_sub_analysis'
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
        json={'sub_analyses': [{
            'sha256': sha256,
            'source': 'root',
            'sub_analysis_id': root_sub_analysis
        }]
        }
    )

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses/{root_sub_analysis}/metadata',
        json={
            'file_type': 'non executable',
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
            'size_in_bytes': 838,
            'ssdeep': '12:dfhfgjh:sdfghfgjfgh'
        }
    )

    args = {"analysis_id": analysis_id}

    # Act
    command_results_list = check_analysis_status_and_get_results_command(args, intezer_api)

    # Assert
    assert len(command_results_list) == 1

    indicators = [dbotscore['Indicator'] for dbotscore in command_results_list[0].outputs[outputPaths['dbotscore']]]
    assert all(indicator in indicators for indicator in [sha256, md5, sha1])


def test_check_analysis_status_and_get_results_url_command_single_success(requests_mock):
    # Arrange
    url = 'https://intezer.com'
    scanned_url = 'https://intezer.com/r'
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    file_analysis_id = '8db9a401-a142-41be-9a31-8e5f3642db62'
    file_root_analysis_id = 'root_analysis_id'
    sha256 = 'sha256'
    md5 = 'md5'
    sha1 = 'sha1'
    requests_mock.get(
        f'{full_url}/url/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
                'summary': {
                    'title': 'malicious',
                    'verdict_name': 'malicious',
                    'verdict_type': 'malicious'
                },
                'indicators': [
                    {
                        'classification': 'informative',
                        'text': 'URL is accessible'
                    },
                    {
                        'classification': 'informative',
                        'text': 'Assigned IPv4 domain'
                    },
                    {
                        'classification': 'informative',
                        'text': 'Vaild IPv4 domain'
                    },
                    {
                        'classification': 'suspicious',
                        'text': 'suspicious'
                    },
                    {
                        'classification': 'malicious',
                        'text': 'malicious'
                    }
                ],
                'redirect_chain': [
                    {
                        'response_status': 301,
                        'url': 'https://foo.com/'
                    },
                    {
                        'response_status': 200,
                        'url': 'http://www.foo.com/'
                    }
                ],
                'scanned_url': scanned_url,
                'submitted_url': url,
                'downloaded_file': {
                    'analysis_id': file_analysis_id,
                    'analysis_summary': {
                        'verdict_description':
                            "This file contains code from malicious s"
                            "oftware, therefore it's very likely that it's malicious.",
                        'verdict_name': 'malicious',
                        'verdict_title': 'Malicious',
                        'verdict_type': 'malicious'
                    },
                    'sha256': '4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7'
                },
                'analysis_url': 'bla'
            },
            'status': 'succeeded'
        }
    )

    requests_mock.get(
        f'{full_url}/analyses/{file_analysis_id}',
        json={
            'result': {
                'analysis_id': file_analysis_id,
                'sub_verdict': 'malicious',
                'sha256': 'a' * 64,
                'verdict': 'malicious',
                'analysis_url': 'bla'
            },
            'status': 'succeeded'
        })

    requests_mock.get(
        f'{full_url}/analyses/{file_analysis_id}/sub-analyses',
        json={'sub_analyses': [{
            'sha256': sha256,
            'source': 'root',
            'sub_analysis_id': file_root_analysis_id
        }]
        }
    )

    requests_mock.get(
        f'{full_url}/analyses/{file_analysis_id}/sub-analyses/{file_root_analysis_id}/metadata',
        json={
            'file_type': 'non executable',
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
            'size_in_bytes': 838,
            'ssdeep': '12:dfhfgjh:sdfghfgjfgh'
        }
    )

    args = {"analysis_id": analysis_id, "analysis_type": 'Url'}

    # Act
    command_results_list = check_analysis_status_and_get_results_command(args, intezer_api)

    # Assert
    assert len(command_results_list) == 1
    assert len(command_results_list[0].outputs[outputPaths['dbotscore']]) == 5

    first_result = command_results_list[0]
    indicators = [dbotscore['Indicator'] for dbotscore in first_result.outputs[outputPaths['dbotscore']]]
    assert all(indicator in indicators for indicator in [sha256, md5, sha1, url, scanned_url])
    assert all(dbot['Score'] == 3 for dbot in first_result.outputs[outputPaths['dbotscore']])


def test_check_analysis_status_and_get_results_command_single_success_endpoint(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    computer_name = 'kfir-pc'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/endpoint-analyses/{analysis_id}',
        json={
            'status': 'succeeded',
            'result': {
                'analysis_id': analysis_id,
                'sub_verdict': 'trusted',
                'verdict': 'trusted',
                'analysis_url': 'bla',
                'computer_name': computer_name,
                'scan_start_time': 'Wed, 19 Jun 2022 07:48:12 GMT'
            }
        }
    )

    args = {"analysis_id": analysis_id, "analysis_type": 'Endpoint'}

    # Act
    command_results_list = check_analysis_status_and_get_results_command(args, intezer_api)

    # Assert
    assert len(command_results_list) == 1

    first_result = command_results_list[0]
    assert first_result.outputs[outputPaths['dbotscore']]['Indicator'] == computer_name
    assert first_result.outputs['Intezer.Analysis(val.ID && val.ID == obj.ID)']['ID'] == analysis_id


def test_get_endpoint_analysis_missing(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/endpoint-analyses/{analysis_id}',
        status_code=HTTPStatus.NOT_FOUND
    )

    args = {"analysis_id": analysis_id, "analysis_type": 'Endpoint'}

    # Act
    command_results = check_analysis_status_and_get_results_command(args, intezer_api)

    # Assert
    assert command_results[0].readable_output == f'Could not find the endpoint analysis \'{analysis_id}\''


def test_check_analysis_status_and_get_results_command_multiple_analyses(requests_mock):
    # Arrange
    sha256_1 = 'sha256'
    sha1_1 = 'sha1'
    md5_1 = 'md5'
    analysis_id_1 = 'analysis_id'
    root_analysis_id_1 = 'root_analysis_id'

    sha256_2 = 'sha256-2'
    sha1_2 = 'sha1-2'
    md5_2 = 'md5-2'
    analysis_id_2 = 'analysis_id-2'
    root_analysis_id_2 = 'root_analysis_id_2'

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
        f'{full_url}/analyses/{analysis_id_1}/sub-analyses',
        json={'sub_analyses': [{
            'sha256': sha256_1,
            'source': 'root',
            'sub_analysis_id': root_analysis_id_1
        }]
        }
    )

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id_1}/sub-analyses/{root_analysis_id_1}/metadata',
        json={
            'file_type': 'non executable',
            'md5': md5_1,
            'sha1': sha1_1,
            'sha256': sha256_1,
            'size_in_bytes': 838,
            'ssdeep': '12:dfhfgjh:sdfghfgjfgh'
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

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id_2}/sub-analyses',
        json={'sub_analyses': [{
            'sha256': sha256_2,
            'source': 'root',
            'sub_analysis_id': root_analysis_id_2
        }]
        }
    )

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id_2}/sub-analyses/{root_analysis_id_2}/metadata',
        json={
            'file_type': 'non executable',
            'md5': md5_2,
            'sha1': sha1_2,
            'sha256': sha256_2,
            'size_in_bytes': 838,
            'ssdeep': '12:dfhfgjh:sdfghfgjfgh'
        }
    )

    args = {"analysis_id": f'{analysis_id_1},{analysis_id_2}'}

    # Act
    command_results_list = check_analysis_status_and_get_results_command(args, intezer_api)

    # Assert
    assert len(command_results_list) == 2

    first_result = command_results_list[0]
    indicators = [dbotscore['Indicator'] for dbotscore in first_result.outputs[outputPaths['dbotscore']]]
    assert all(indicator in indicators for indicator in [sha256_1, md5_1, sha1_1])

    second_result = command_results_list[1]
    indicators = [dbotscore['Indicator'] for dbotscore in second_result.outputs[outputPaths['dbotscore']]]
    assert all(indicator in indicators for indicator in [sha256_2, md5_2, sha1_2])


def test_check_analysis_status_and_get_results_command_multiple_analyses_one_fails(requests_mock):
    # Arrange
    sha256_1 = 'sha256'
    md5_1 = 'md5'
    sha1_1 = 'sha1'
    analysis_id_1 = 'analysis_id'
    root_analysis_id_1 = 'root_analysis_id'

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
        f'{full_url}/analyses/{analysis_id_1}/sub-analyses',
        json={'sub_analyses': [{
            'sha256': sha256_1,
            'source': 'root',
            'sub_analysis_id': root_analysis_id_1
        }]
        }
    )

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id_1}/sub-analyses/{root_analysis_id_1}/metadata',
        json={
            'file_type': 'non executable',
            'md5': md5_1,
            'sha1': sha1_1,
            'sha256': sha256_1,
            'size_in_bytes': 838,
            'ssdeep': '12:dfhfgjh:sdfghfgjfgh'
        }
    )

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id_2}',
        status_code=HTTPStatus.NOT_FOUND,
    )

    args = {"analysis_id": f'{analysis_id_1},{analysis_id_2}'}

    # Act
    command_results_list = check_analysis_status_and_get_results_command(args, intezer_api)

    # Assert
    assert len(command_results_list) == 2

    first_result = command_results_list[0]
    indicators = [dbotscore['Indicator'] for dbotscore in first_result.outputs[outputPaths['dbotscore']]]
    assert all(indicator in indicators for indicator in [sha256_1, md5_1, sha1_1])

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

    args = {"analysis_id": analysis_id}

    # Act
    command_results = get_analysis_sub_analyses_command(args, intezer_api)

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

    args = {"analysis_id": analysis_id}

    # Act
    command_results = get_analysis_sub_analyses_command(args, intezer_api)

    # Assert
    assert command_results.readable_output == f'The Analysis {analysis_id} was not found on Intezer Analyze'


# endregion

# region get_file_analysis_result_command
def test_get_file_analysis_result_command_success(requests_mock, mocker):
    # Arrange
    sha256 = 'sha256'
    md5 = 'md5'
    sha1 = 'sha1'
    analysis_id = 'analysis_id'
    root_sub_analysis = 'root_sub_analysis'
    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

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
        json={'sub_analyses': [{
            'sha256': sha256,
            'source': 'root',
            'sub_analysis_id': root_sub_analysis
        }]
        }
    )

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses/{root_sub_analysis}/metadata',
        json={
            'file_type': 'non executable',
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
            'size_in_bytes': 838,
            'ssdeep': '12:dfhfgjh:sdfghfgjfgh'
        }
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act
    command_result = get_file_analysis_result_command(args, intezer_api)

    # Assert
    indicators = [dbotscore['Indicator'] for dbotscore in command_result.outputs[outputPaths['dbotscore']]]
    assert all(indicator in indicators for indicator in [sha256, md5, sha1])


def test_get_url_analysis_still_running_polling(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/url/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
            },
            'status': 'in_progress'
        }
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act
    command_result = get_url_analysis_result_command(args, intezer_api)

    # Assert
    assert command_result.scheduled_command._args['analysis_id'] == analysis_id
    assert command_result.scheduled_command._args['hide_polling_output']
    assert command_result.scheduled_command._args['wait_for_result']


def test_get_url_analysis_result_command_analysis_failed(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'

    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)
    requests_mock.get(
        f'{full_url}/url/{analysis_id}',
        status_code=HTTPStatus.NOT_FOUND,
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act
    command_result = get_url_analysis_result_command(args, intezer_api)

    # Assert
    assert command_result.readable_output == f'The Analysis {analysis_id} was not found on Intezer Analyze'


# endregion

# region get_endpoint_analysis_result_command
def test_get_endpoint_analysis_still_running_polling(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/endpoint-analyses/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
            },
            'status': 'in_progress'
        }
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act
    command_result = get_endpoint_analysis_result_command(args, intezer_api)

    # Assert
    assert command_result.scheduled_command._args['analysis_id'] == analysis_id
    assert command_result.scheduled_command._args['hide_polling_output']
    assert command_result.scheduled_command._args['wait_for_result']


def test_get_endpoint_analysis_queued_polling(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/endpoint-analyses/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
            },
            'status': 'queued'
        }
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act
    command_result = get_endpoint_analysis_result_command(args, intezer_api)

    # Assert
    assert command_result.scheduled_command._args['analysis_id'] == analysis_id
    assert command_result.scheduled_command._args['hide_polling_output']
    assert command_result.scheduled_command._args['wait_for_result']


def test_get_endpoint_analysis_polling_false(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/endpoint-analyses/{analysis_id}',
        status_code=HTTPStatus.CONFLICT
    )

    args = {"analysis_id": analysis_id, "wait_for_result": False}

    # Act
    command_result = get_endpoint_analysis_result_command(args, intezer_api)

    # Assert
    assert command_result.scheduled_command is None
    assert command_result.outputs == {'ID': analysis_id, 'Status': 'InProgress', 'Type': 'Endpoint'}


def test_get_endpoint_analysis_result_command_analysis_missing(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/endpoint-analyses/{analysis_id}',
        status_code=HTTPStatus.NOT_FOUND
    )

    # Act
    args = {"analysis_id": analysis_id, "wait_for_result": True}
    command_result = get_endpoint_analysis_result_command(args, intezer_api)

    # Assert
    assert command_result.readable_output == f'Could not find the endpoint analysis \'{analysis_id}\''


def test_get_endpoint_analysis_result_command_polling_true(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'

    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/endpoint-analyses/{analysis_id}',
        status_code=HTTPStatus.CONFLICT,
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act
    command_result = get_endpoint_analysis_result_command(args, intezer_api)

    # Assert
    assert command_result.scheduled_command._args['analysis_id'] == analysis_id
    assert command_result.scheduled_command._args['hide_polling_output']


def test_get_endpoint_analysis_result_success(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'
    computer_name = 'matan-pc'
    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/endpoint-analyses/{analysis_id}',
        json={
            'status': 'succeeded',
            'result': {
                'analysis_id': analysis_id,
                'sub_verdict': 'trusted',
                'verdict': 'trusted',
                'analysis_url': 'bla',
                'computer_name': computer_name,
                'scan_start_time': 'Wed, 19 Jun 2022 07:48:12 GMT'
            }
        }
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act
    command_results = get_endpoint_analysis_result_command(args, intezer_api)

    # Assert
    assert command_results.outputs[outputPaths['dbotscore']]['Indicator'] == computer_name
    assert command_results.outputs['Intezer.Analysis(val.ID && val.ID == obj.ID)']['ID'] == analysis_id


def test_get_endpoint_analysis_result_http_error(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/endpoint-analyses/{analysis_id}',
        status_code=HTTPStatus.BAD_REQUEST
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act + Assert
    with pytest.raises(Exception):
        get_endpoint_analysis_result_command(args, intezer_api)


# endregion

# region get_url_analysis_result_command
def test_get_url_analysis_result_command_success(requests_mock, mocker):
    # Arrange
    sha256 = 'sha256'
    url = 'https://foo.com'
    scanned_url = 'https://foo.com'
    file_analysis_id = 'file_analysis_id'
    md5 = 'md5'
    sha1 = 'sha1'
    analysis_id = 'analysis_id'
    file_root_analysis_id = 'file_root_analysis_id'

    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/url/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
                'summary': {
                    'title': 'malicious',
                    'verdict_name': 'malicious',
                    'verdict_type': 'malicious'
                },
                'indicators': [
                    {
                        'classification': 'informative',
                        'text': 'URL is accessible'
                    },
                    {
                        'classification': 'informative',
                        'text': 'Assigned IPv4 domain'
                    },
                    {
                        'classification': 'informative',
                        'text': 'Vaild IPv4 domain'
                    },
                    {
                        'classification': 'suspicious',
                        'text': 'suspicious'
                    },
                    {
                        'classification': 'malicious',
                        'text': 'malicious'
                    }
                ],
                'redirect_chain': [
                    {
                        'response_status': 301,
                        'url': 'https://foo.com/'
                    },
                    {
                        'response_status': 200,
                        'url': 'http://www.foo.com/'
                    }
                ],
                'scanned_url': scanned_url,
                'submitted_url': url,
                'downloaded_file': {
                    'analysis_id': file_analysis_id,
                    'analysis_summary': {
                        'verdict_description':
                            "This file contains code from malicious s"
                            "oftware, therefore it's very likely that it's malicious.",
                        'verdict_name': 'malicious',
                        'verdict_title': 'Malicious',
                        'verdict_type': 'malicious'
                    },
                    'sha256': '4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7'
                },
                'analysis_url': 'bla'
            },
            'status': 'succeeded'
        }
    )

    requests_mock.get(
        f'{full_url}/analyses/{file_analysis_id}',
        json={
            'result': {
                'analysis_id': file_analysis_id,
                'sub_verdict': 'malicious',
                'sha256': 'a' * 64,
                'verdict': 'malicious',
                'analysis_url': 'bla'
            },
            'status': 'succeeded'
        })

    requests_mock.get(
        f'{full_url}/analyses/{file_analysis_id}/sub-analyses',
        json={'sub_analyses': [{
            'sha256': sha256,
            'source': 'root',
            'sub_analysis_id': file_root_analysis_id
        }]
        }
    )

    requests_mock.get(
        f'{full_url}/analyses/{file_analysis_id}/sub-analyses/{file_root_analysis_id}/metadata',
        json={
            'file_type': 'non executable',
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
            'size_in_bytes': 838,
            'ssdeep': '12:dfhfgjh:sdfghfgjfgh'
        }
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act
    command_result = get_url_analysis_result_command(args, intezer_api)

    # Assert
    assert len(command_result.outputs[outputPaths['dbotscore']]) == 4

    indicators = [dbotscore['Indicator'] for dbotscore in command_result.outputs[outputPaths['dbotscore']]]
    assert all(indicator in indicators for indicator in [sha256, md5, sha1, url, scanned_url])
    assert all(dbot['Score'] == 3 for dbot in command_result.outputs[outputPaths['dbotscore']])


def test_get_url_analysis_result_command_failed(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'

    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/url/{analysis_id}',
        status_code=HTTPStatus.NOT_FOUND,
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act
    command_result = get_url_analysis_result_command(args, intezer_api)

    # Assert
    assert command_result.readable_output == f'The Analysis {analysis_id} was not found on Intezer Analyze'


def test_get_url_analysis_result_command_polling(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'

    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/url/{analysis_id}',
        status_code=HTTPStatus.CONFLICT,
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act
    command_result = get_url_analysis_result_command(args, intezer_api)

    # Assert
    assert command_result.scheduled_command._args['analysis_id'] == analysis_id
    assert command_result.scheduled_command._args['hide_polling_output']


def test_get_file_analysis_polling_false(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}',
        status_code=HTTPStatus.CONFLICT
    )

    args = {"analysis_id": analysis_id, "wait_for_result": False}

    # Act
    command_result = get_file_analysis_result_command(args, intezer_api)

    # Assert
    assert command_result.scheduled_command is None
    assert command_result.outputs == {'ID': analysis_id, 'Status': 'InProgress', 'Type': 'File'}


def test_get_file_analysis_result_command_analysis_failed(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'

    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}',
        status_code=HTTPStatus.NOT_FOUND,
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act
    command_result = get_file_analysis_result_command(args, intezer_api)

    # Assert
    assert command_result.readable_output == f'The Analysis {analysis_id} was not found on Intezer Analyze'


def test_get_file_analysis_result_http_error(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}',
        status_code=HTTPStatus.BAD_REQUEST
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act + Assert
    with pytest.raises(Exception):
        get_file_analysis_result_command(args, intezer_api)


def test_get_file_analysis_still_running_polling(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
            },
            'status': 'in_progress'
        }
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act
    command_result = get_file_analysis_result_command(args, intezer_api)

    # Assert
    assert command_result.scheduled_command._args['analysis_id'] == analysis_id
    assert command_result.scheduled_command._args['hide_polling_output']
    assert command_result.scheduled_command._args['wait_for_result']


def test_get_file_analysis_result_command_polling(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis_id'

    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}',
        status_code=HTTPStatus.CONFLICT,
    )

    args = {"analysis_id": analysis_id, "wait_for_result": True}

    # Act
    command_result = get_file_analysis_result_command(args, intezer_api)

    # Assert
    assert command_result.scheduled_command._args['analysis_id'] == analysis_id
    assert command_result.scheduled_command._args['hide_polling_output']


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

    args = {"analysis_id": analysis_id}

    # Act
    command_results = get_analysis_code_reuse_command(args, intezer_api)

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

    args = {"analysis_id": analysis_id, "sub_analysis_id": sub_analysis_id}

    # Act
    command_results = get_analysis_code_reuse_command(args, intezer_api)

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

    args = {"analysis_id": analysis_id, "sub_analysis_id": sub_analysis_id}

    # Act
    command_results = get_analysis_code_reuse_command(args, intezer_api)

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

    args = {"analysis_id": analysis_id, "sub_analysis_id": sub_analysis_id}

    # Act
    command_results = get_analysis_code_reuse_command(args, intezer_api)

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

    args = {"analysis_id": analysis_id}

    # Act
    command_results = get_analysis_metadata_command(args, intezer_api)

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

    args = {"analysis_id": analysis_id, "sub_analysis_id": sub_analysis_id}

    # Act
    command_results = get_analysis_metadata_command(args, intezer_api)

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

    args = {"analysis_id": analysis_id, "sub_analysis_id": sub_analysis_id}

    # Act
    command_results = get_analysis_metadata_command(args, intezer_api)

    # Assert
    assert command_results.readable_output == f'The Analysis {analysis_id} was not found on Intezer Analyze'


# endregion

# region get_analysis_iocs_command

def test_get_analysis_iocs_command_success(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
                'sub_verdict': 'trusted',
                'sha256': 'sha256',
                'verdict': 'trusted',
                'analysis_url': 'bla'
            },
            'status': 'succeeded'
        }
    )
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/iocs',
        json={
            'result': {
                'files': [
                    {
                        'path': 'test_file_1.csv',
                        'sha256': 'eeb1199f7db006e4d20086171cc312cf5bdf53682cc37997223ad0c15a27dc88',
                        'verdict': 'malicious',
                        'family': 'Turla',
                        'type': 'Main file',
                    }
                ],
                'network': [
                    {
                        'ioc': '1.1.1.1',
                        'source': [
                            'Network communication'
                        ],
                        'type': 'ip'
                    },
                    {
                        'ioc': 'raw.exampledomain.com',
                        'source': [
                            'Network communication'
                        ],
                        'type': 'domain'
                    }
                ]
            }
        }
    )

    args = {"analysis_id": analysis_id}

    # Act
    command_results = get_analysis_iocs_command(args, intezer_api)

    # Assert
    outputs = command_results.outputs['Intezer.Analysis(obj.ID == val.ID)']
    assert outputs.get('ID') == analysis_id
    assert 'IOCs' in outputs


def test_get_analysis_iocs_command_no_iocs(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
                'sub_verdict': 'trusted',
                'sha256': 'sha256',
                'verdict': 'trusted',
                'analysis_url': 'bla'
            },
            'status': 'succeeded'
        }
    )
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/iocs',
        status_code=HTTPStatus.NOT_FOUND
    )

    args = {"analysis_id": analysis_id}

    # Act
    command_results = get_analysis_iocs_command(args, intezer_api)

    # Assert
    outputs = command_results.outputs['Intezer.Analysis(obj.ID == val.ID)']
    assert outputs.get('ID') == analysis_id
    assert command_results.readable_output == 'No IOCs found'
    assert 'IOCs' in outputs
    assert outputs['IOCs'] is None


def test_get_analysis_iocs_command_analysis_doesnt_exist(requests_mock):
    # Arrange
    analysis_id = 'analysis_id'
    _setup_access_token(requests_mock)
    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}',
        status_code=HTTPStatus.NOT_FOUND
    )

    args = {"analysis_id": analysis_id}

    # Act
    command_results = get_analysis_iocs_command(args, intezer_api)

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

    args = {"family_id": family_id}

    # Act
    command_results = get_family_info_command(args, intezer_api)

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

    args = {"family_id": family_id}

    # Act
    command_results = get_family_info_command(args, intezer_api)

    # Assert
    assert command_results.readable_output == f'The Family {family_id} was not found on Intezer Analyze'


# endregion

# region check_is_available
def test_check_is_available_success(requests_mock):
    requests_mock.get(
        f'{full_url}/is-available',
        json={'ok': 'ok'},
    )

    requests_mock.post(
        f'{full_url}/get-access-token',
        json={'result': 'some_token'},
    )

    response = check_is_available({}, intezer_api)
    assert response == 'ok'


def test_check_is_available_http_error(requests_mock):
    requests_mock.get(
        f'{full_url}/is-available',
        status_code=HTTPStatus.BAD_REQUEST
    )

    requests_mock.post(
        f'{full_url}/get-access-token',
        json={'result': 'some_token'},
    )

    response = check_is_available({}, intezer_api)
    assert 'Error occurred when reaching Intezer Analyze. Please check Analyze Base URL.' in response


# endregion

# region analyze_url_command
def test_analyze_url_command_success(requests_mock):
    # Arrange
    analysis_id = 'analysis-id'

    _setup_access_token(requests_mock)
    requests_mock.post(
        f'{full_url}/url',
        status_code=HTTPStatus.CREATED,
        json={"result_url": f'/url/{analysis_id}'}
    )

    args = {"url": 'https://intezer.com'}

    # Act
    command_results = analyze_url_command(args, intezer_api)

    # Assert
    assert command_results.outputs['ID'] == analysis_id


def test_analyze_url_command_success_polling_true(requests_mock, mocker):
    # Arrange
    analysis_id = 'analysis-id'

    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.post(
        f'{full_url}/url',
        status_code=HTTPStatus.CREATED,
        json={"result_url": f'/url/{analysis_id}'}
    )

    requests_mock.get(
        f'{full_url}/url/{analysis_id}',
        json={
            'result': {
                'analysis_id': analysis_id,
            },
            'status': 'in_progress'
        }
    )

    args = {"url": 'https://intezer.com', "wait_for_result": True}

    # Act
    command_results = analyze_url_command(args, intezer_api)

    # Assert
    assert command_results.readable_output == 'Fetching Intezer analysis. Please wait...'


def test_analyze_url_command_missing_url(requests_mock):
    # Arrange

    _setup_access_token(requests_mock)
    requests_mock.post(
        f'{full_url}/url',
        status_code=HTTPStatus.BAD_REQUEST,
        json={"error": 'Bad url'}
    )

    url = '123test'
    args = {"url": url, "analysis_type": 'Url'}

    # Act
    command_results = analyze_url_command(args, intezer_api)

    # Assert
    assert command_results.readable_output == ('The Url 123test was not found on Intezer. '
                                               'Error Server returned bad request error: Bad url. Error:Bad url')


def test_analyze_url_command_url_not_found(requests_mock):
    # Arrange
    _setup_access_token(requests_mock)
    requests_mock.post(
        f'{full_url}/url',
        status_code=HTTPStatus.BAD_REQUEST,
        json={"error": 'Bad url'}
    )

    args = {"analysis_type": 'Url'}

    # Act
    with pytest.raises(ValueError):
        analyze_url_command(args, intezer_api)


# endregion

# region submit_alert_command

def test_submit_alert_command_success(requests_mock):
    # Arrange
    _setup_access_token(requests_mock)
    alert_id = '112233'
    requests_mock.post(
        f'{full_url}/alerts/ingest',
        status_code=HTTPStatus.OK,
        json={"alert_id": alert_id, "result": True}
    )

    mapping = {'test': 'mapping'}

    args = {"raw_alert": {'id': 123}, "mapping": json.dumps(mapping), "source": 'cs'}

    # Act
    command_results = submit_alert_command(args, intezer_api)

    # Assert
    assert command_results.outputs['ID'] == alert_id
    assert command_results.outputs['Status'] == 'Created'
    assert command_results.readable_output == f'Alert created successfully: {alert_id}'


def test_submit_alert_command_invalid_mapping_file(requests_mock):
    # Arrange
    _setup_access_token(requests_mock)
    alert_id = '112233'
    requests_mock.post(
        f'{full_url}/alerts/ingest',
        status_code=HTTPStatus.BAD_REQUEST,
        json={"alert_id": alert_id, "result": True}
    )

    mapping = {'test': 'mapping'}

    args = {"raw_alert": {'id': 123}, "mapping": json.dumps(mapping), "source": 'cs'}

    # Act + Assert
    with pytest.raises(intezer_sdk.errors.InvalidAlertMappingError):
        submit_alert_command(args, intezer_api)


# endregion

# region submit_suspected_phishing_email_command

def test_submit_suspected_phishing_email_command_success(requests_mock, mocker):
    # Arrange
    _setup_access_token(requests_mock)
    alert_id = '112233'
    requests_mock.post(
        f'{full_url}/alerts/ingest/binary',
        status_code=HTTPStatus.OK,
        json={"alert_id": alert_id, "result": True}
    )

    args = {"email_file_entry_id": '123@123'}

    # Act
    with tempfile.NamedTemporaryFile() as file:
        file.write(b'123')
        file.seek(0)
        file_path_patch = mocker.patch('demistomock.getFilePath')
        file_path_patch.return_value = {"path": file.name, "name": file.name}
        command_results = submit_suspected_phishing_email_command(args, intezer_api)

    # Assert
    assert command_results.outputs['ID'] == alert_id
    assert command_results.outputs['Status'] == 'Created'
    assert command_results.readable_output == f'Suspected email was sent successfully, alert_id: {alert_id}'


# endregion


# region get_alert_response_command

def test_get_alert_response_command_alert_not_found(requests_mock, mocker):
    # Arrange
    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/alerts/get-by-id',
        status_code=HTTPStatus.NOT_FOUND,
        json={"alert_id": '123'}
    )

    args = {"alert_id": '123', "wait_for_result": True}

    # Act
    command_result = get_alert_result_command(args, intezer_api)

    # Assert
    command_result.readable_output = 'Could not find alert with the alert_id of 123'


def test_get_alert_response_command_alert_in_progress(requests_mock, mocker):
    # Arrange
    _setup_access_token(requests_mock)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    requests_mock.get(
        f'{full_url}/alerts/get-by-id',
        status_code=HTTPStatus.OK,
        json={"result": {'123': '123'}, "status": 'in_progress'}
    )

    args = {"alert_id": '123', "wait_for_result": True}

    # Act
    command_result = get_alert_result_command(args, intezer_api)

    # Assert
    assert command_result.readable_output == 'Fetching Intezer alert. Please wait...'


def test_get_alert_response_command_alert_success(requests_mock, mocker):
    # Arrange
    _setup_access_token(requests_mock)

    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)
    mocker.patch('IntezerV2.enrich_dbot_and_display_alert_results', return_value=CommandResults(readable_output='test'))

    requests_mock.get(
        f'{full_url}/alerts/get-by-id',
        status_code=HTTPStatus.OK,
        json={"result": {'123': '123'}, "status": 'succeeded'}
    )

    args = {"alert_id": '123', "wait_for_result": True}

    # Act
    command_result = get_alert_result_command(args, intezer_api)

    # Assert
    assert command_result.readable_output == 'test'


def test_enrich_dbot_and_display_alert_results_no_scans(requests_mock, mocker):
    # Arrange
    _setup_access_token(requests_mock)
    alert_id = '123'
    alert = Alert(alert_id, api=intezer_api)
    alert.scans = []
    alert.status = AlertStatusCode.FINISHED
    alert.intezer_alert_url = 'some_url'
    alert.family_name = None
    mocker.patch.object(Alert, 'result', return_value={'scans': [],
                                                       'triage_result': {'alert_verdict_display': 'dangerous',
                                                                         'risk_category_display': 'malicious'}})

    # Act
    with patch('IntezerV2.return_results') as results_mock:
        enrich_dbot_and_display_alert_results(alert, intezer_api)

    # Assert
    assert results_mock.call_count == 1


def test_enrich_dbot_and_display_alert_results_artifact_analyses(requests_mock, mocker):
    # Arrange
    _setup_access_token(requests_mock)
    alert_id = '123'
    alert = Alert(alert_id, api=intezer_api)
    alert.scans = []
    alert.status = AlertStatusCode.FINISHED
    alert.intezer_alert_url = 'some_url'
    alert.family_name = None
    malicious_ip = 'some_ip'
    mocker.patch.object(Alert, 'result', return_value={'scans': [{'artifact_analysis': {'artifact_type': 'ip',
                                                                                        'artifact_value': malicious_ip,
                                                                                        'family_name': 'Vobfus',
                                                                                        'verdict': 'malicious'},
                                                                  'collection_status': 'collected', 'scan_type': 'artifact'}],
                                                       'triage_result': {'alert_verdict_display': 'dangerous',
                                                                         'risk_category_display': 'malicious'}})

    # Act
    with patch('IntezerV2.return_results') as results_mock:
        enrich_dbot_and_display_alert_results(alert, intezer_api)

    # Assert
    first_result: CommandResults = results_mock.call_args.args[0][0]
    assert len(results_mock.call_args.args[0]) == 2
    assert first_result.indicator.dbot_score.indicator_type == 'ip'
    assert first_result.indicator.dbot_score.indicator == malicious_ip
    assert first_result.indicator.dbot_score.score == Common.DBotScore.BAD


def test_enrich_dbot_and_display_alert_results_file_analysis(requests_mock, mocker):
    # Arrange
    _setup_access_token(requests_mock)
    alert_id = '123'
    alert = Alert(alert_id, api=intezer_api)
    alert.status = AlertStatusCode.FINISHED
    alert.intezer_alert_url = 'some_url'
    alert.family_name = None

    analysis_id = '123'
    root_sub_analysis = '456'
    analysis = FileAnalysis(api=intezer_api)
    analysis.analysis_id = analysis_id
    analysis.analysis_type = 'file'
    sha256 = 'a' * 64
    md5 = 'b' * 32
    sha1 = 'c' * 40
    analysis._report = {'analysis_id': analysis_id, 'analysis_time': 'Mon, 24 Jul 2023 15:45:58 GMT',
                        'analysis_url': f'https://analyze.intezer.com/analyses/{analysis_id}',
                        'file_name': 'body-html.html', 'is_private': True,
                        'sha256': sha256,
                        'sub_verdict': 'inconclusive', 'verdict': 'unknown'}

    alert.scans = [analysis]

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses',
        json={'sub_analyses': [{
            'sha256': sha256,
            'source': 'root',
            'sub_analysis_id': root_sub_analysis
        }]
        }
    )

    requests_mock.get(
        f'{full_url}/analyses/{analysis_id}/sub-analyses/{root_sub_analysis}/metadata',
        json={
            'file_type': 'non executable',
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
            'size_in_bytes': 838,
            'ssdeep': '12:dfhfgjh:sdfghfgjfgh'
        }
    )

    mocker.patch.object(Alert, 'result', return_value={'scans': [{'scan_type': 'file', 'file_analysis': analysis.result()}],
                                                       'triage_result': {'alert_verdict_display': 'dangerous',
                                                                         'risk_category_display': 'malicious'}})

    # Act
    with patch('IntezerV2.return_results') as results_mock:
        enrich_dbot_and_display_alert_results(alert, intezer_api)

    # Assert
    first_result: CommandResults = results_mock.call_args.args[0][0]
    assert len(results_mock.call_args.args[0]) == 2
    assert first_result.indicator.dbot_score.indicator_type == 'file'
    assert first_result.indicator.dbot_score.indicator == sha256
    assert first_result.indicator.dbot_score.score == Common.DBotScore.NONE
    assert first_result.indicator.md5 == md5
    assert first_result.indicator.sha1 == sha1
    assert first_result.indicator.sha256 == sha256


def test_enrich_dbot_and_display_alert_results_url_analysis(requests_mock, mocker):
    # Arrange
    _setup_access_token(requests_mock)
    alert_id = '123'
    alert = Alert(alert_id, api=intezer_api)
    alert.status = AlertStatusCode.FINISHED
    alert.intezer_alert_url = 'some_url'
    alert.family_name = None

    analysis_id = '123'
    analysis = UrlAnalysis(api=intezer_api)
    analysis.analysis_id = analysis_id
    url = 'https://www.google.com'
    analysis._report = {'analysis_id': analysis_id, 'analysis_time': 'Mon, 24 Jul 2023 15:45:58 GMT',
                        'analysis_url': f'https://analyze.intezer.com/analyses/{analysis_id}',
                        'scanned_url': url, 'submitted_url': url,
                        'summary': {'verdict_type': 'malicious'}}

    alert.scans = [analysis]

    mocker.patch.object(Alert, 'result', return_value={'scans': [{'scan_type': 'file', 'file_analysis': analysis.result()}],
                                                       'triage_result': {'alert_verdict_display': 'dangerous',
                                                                         'risk_category_display': 'malicious'}})

    # Act
    with patch('IntezerV2.return_results') as results_mock:
        enrich_dbot_and_display_alert_results(alert, intezer_api)

    # Assert
    first_result: CommandResults = results_mock.call_args.args[0][0]
    assert len(results_mock.call_args.args[0]) == 2
    assert first_result.indicator.dbot_score.indicator_type == 'url'
    assert first_result.indicator.dbot_score.indicator == url
    assert first_result.indicator.dbot_score.score == Common.DBotScore.BAD
