"""
Unit testing for Check Point Threat Emulation (SandBlast)
commands: query, upload, download and quota.
"""
import json
import io
import os
from unittest import mock
import pytest
from CommonServerPython import *
from CheckPointSandBlast import Client,\
    file_command, query_command, quota_command, upload_command, download_command, get_dbotscore


HOST = 'https://te.checkpoint.com'
BASE_URL = f'{HOST}/tecloud/api/v1/file'
BOUNDARY = 'wL36Yn8afVp8Ag7AmP8qZ0SA4n1v9T'
QUERY_PATH = '/query'
QUOTA_PATH = '/quota'
UPLOAD_PATH = '/upload'
DOWNLOAD_PATH = '/download'
API_KEY = 'API_Key'
QUERY_OUTPUTS_PREFIX = 'SandBlast.Query'
QUOTA_OUTPUTS_PREFIX = 'SandBlast.Quota'
UPLOAD_OUTPUTS_PREFIX = 'SandBlast.Upload'
DOWNLOAD_OUTPUTS_PREFIX = 'SandBlast.Download'
FILE_ENTRY = {
    'name': 'upload_file.txt',
    'path': 'test_data/upload_file.txt'
}


def load_mock_response(file_name: str) -> str | io.TextIOWrapper:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    path = os.path.join('test_data', file_name)

    with io.open(path, mode='r', encoding='utf-8') as mock_file:
        if os.path.splitext(file_name)[1] == '.json':
            return json.loads(mock_file.read())

        return mock_file


@pytest.fixture(autouse=True)
def mock_client() -> Client:
    """
    Establish a connection to the client with a URL and API key.

    Returns:
        Client: Connection to client.
    """
    return Client(
        host=HOST,
        api_key=API_KEY,
        reliability='C - Fairly reliable'
    )


def test_file_command(requests_mock, mock_client):
    """
    Scenario:
    -   Use generic file command to find out if a file hash is malicious.
    Given:
    -    The user has filled in the required arguments.
    When:
    -    file is called.
    Then:
    -   Ensure that the score in dbotscore is correct.
    """
    mock_response = load_mock_response('query_response.json')
    requests_mock.post(
        f'{BASE_URL}{QUERY_PATH}',
        json=mock_response
    )

    args = {
        'file': 'da855ff838250f45d528a5a05692f14e',
    }
    command_results = file_command(mock_client, args)

    assert command_results[0].indicator.dbot_score.score == 3


def test_query_command(requests_mock, mock_client):
    """
    Scenario:
    -   Query a file in the ThreatCloud.
    Given:
    -    The user has filled in the required arguments.
    When:
    -    sandblast-query is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure outputs_key_field is correct.
    -   Ensure outputs_key_field is correct.
    -   Ensure outputs has correct te name.
    -   Ensure outputs has correct av name.
    -   Ensure outputs has correct extraction name.
    """
    mock_response = load_mock_response('query_response.json')
    requests_mock.post(
        f'{BASE_URL}{QUERY_PATH}',
        json=mock_response
    )

    args = {
        'file_name': 'MyFile.docx.pdf',
        'file_hash': 'da855ff838250f45d528a5a05692f14e',
        'features': ['All'],
        'reports': ['xml', 'summary'],
        'method': 'pdf',
    }
    response = query_command(mock_client, args)

    assert response.outputs_prefix == QUERY_OUTPUTS_PREFIX
    assert ['MD5', 'SHA1', 'SHA256'] == response.outputs_key_field
    assert 'ThreatEmulation' in response.outputs
    assert 'AntiVirus' in response.outputs
    assert 'ThreatExtraction' in response.outputs


def test_quota_command(requests_mock, mock_client):
    """
    Scenario:
    -   Check an API key's quota.
    When:
    -    sandblast-quota is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure outputs_key_field is correct.
    -   Ensure outputs_key_field is correct.
    -   Ensure outputs has correct quota_id name.
    """
    mock_response = load_mock_response('quota_response.json')
    requests_mock.post(
        f'{BASE_URL}{QUOTA_PATH}',
        json=mock_response
    )

    args = {}
    response = quota_command(mock_client, args)

    assert response.outputs_prefix == 'SandBlast.Quota'
    assert response.outputs_key_field == 'QuotaId'
    assert 'QuotaId' in response.outputs


@mock.patch('CheckPointSandBlast.demisto.getFilePath', lambda x: FILE_ENTRY)
def test_upload_command(requests_mock, mock_client):
    """
    Scenario:
    -   Upload a file to the ThreatCloud to go through a virtual SandBox.
    Given:
    -    The user has filled in the required arguments.
    When:
    -    sandblast-upload is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure outputs_key_field is correct.
    -   Ensure outputs_key_field is correct.
    -   Ensure outputs has correct te name.
    -   Ensure outputs has correct av name.
    -   Ensure outputs has correct extraction name.
    """
    mock_response = load_mock_response('upload_response.json')
    requests_mock.post(
        f'{BASE_URL}{UPLOAD_PATH}',
        json=mock_response,
    )

    args = {
        'file_id': 'file_id',
        'features': ['All'],
        'reports': ['xml', 'summary'],
        'method': 'pdf',
    }
    response = upload_command(mock_client, args)

    assert response.outputs_prefix == 'SandBlast.Upload'
    assert response.outputs_key_field == ['MD5', 'SHA1', 'SHA256']
    assert 'ThreatEmulation' in response.outputs
    assert 'AntiVirus' in response.outputs
    assert 'ThreatExtraction' in response.outputs


def test_download_command(requests_mock, mock_client):
    """
    Scenario:
    -   Download a file from the ThreatCloud.
    Given:
    -    The user has filled in the required arguments.
    When:
    -    sandblast-download is called.
    Then:
    -   Ensure Contents is correct.
    -   Ensure ContentsFormat is correct.
    -   Ensure Type is correct.
    -   Ensure FileID is correct.
    -   Ensure file name is correct.
    """
    mock_response = load_mock_response('upload_file.txt')
    requests_mock.get(
        f'{BASE_URL}{DOWNLOAD_PATH}',
        body=mock_response
    )

    args = {
        'file_id': 'file_id'
    }
    response = download_command(mock_client, args)

    assert 'Contents' in response
    assert 'ContentsFormat' in response
    assert 'Type' in response
    assert 'FileID' in response


def test_dbot_score():
    """
    Given:
    - Response.
    When:
    - get_dbotscore is called.
    Then:
    -   Ensure the right dbot score is returned.
    """
    response = {"response": {"av": {"malware_info": {"confidence": 0, "severity": 0}},
                             "features": ["te", "av", "extraction"],
                             "te": {"combined_verdict": "Benign", "confidence": 0, "severity": 0}}}
    assert get_dbotscore(response) == Common.DBotScore.GOOD
