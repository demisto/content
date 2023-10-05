import json

import dateparser
import pytest
from freezegun import freeze_time

import demistomock as demisto

deployed_image_1 = {'Secrets': None, '_id': 'sha256:4c', 'agentless': True, 'allCompliance': {}, 'appEmbedded': False,
                    'binaries': None,
                    'cloudMetadata': {'accountID': 'aa', 'image': 'amazon',
                                      'labels': [{'key': 'aws:name', 'sourceName': 'i-0', 'sourceType': 'aws',
                                                  'timestamp': '2023-09-14T19:01:52.874Z',
                                                  'value': 'name'}],
                                      'provider': 'aws', 'region': 'us-east', 'resourceID': 'i-0', 'type': 't3'},
                    'clusters': ['cluster1'], 'collections': ['All', 'Access Group', 'access-all'],
                    'complianceDistribution': {'critical': 0, 'high': 1, 'low': 0, 'medium': 0, 'total': 1},
                    'complianceIssues': None, 'complianceIssuesCount': 1, 'complianceRiskScore': 10000,
                    'creationTime': '2015-10-19T09:17:01.62Z', 'distro': 'Linux 8', 'err': '',
                    'files': None, 'firewallProtection': {'enabled': False, 'outOfBandMode': '', 'supported': False},
                    'firstScanTime': '2023-09-14T19:09:45.811Z', 'foundSecrets': None, 'history': None, 'hostname': '',
                    'hosts': {
                        'ip-1.us-east.compute.internal-i-0': {'accountID': '49',
                                                              'agentless': True,
                                                              'agentlessScanID': 486,
                                                              'cluster': 'cluster1',
                                                              'modified': '2023-10-03T00:35:57.271Z',
                                                              'namespaces': ['default']},
                        'ip-2.us-east.compute.internal-i-5': {'accountID': '44',
                                                              'agentless': True,
                                                              'agentlessScanID': 486,
                                                              'cluster': 'cluster1',
                                                              'modified': '2023-10-03T00:35:57.189Z',
                                                              'namespaces': ['default']},
                        'ip-3.us-east.compute.internal-i-6': {'accountID': '45',
                                                              'agentless': True,
                                                              'agentlessScanID': 486,
                                                              'cluster': 'cluster1',
                                                              'modified': '2023-10-03T00:35:57.266Z',
                                                              'namespaces': ['default']},
                        'ip-4.us-east.compute.internal-i-9': {'accountID': '47',
                                                              'agentless': True,
                                                              'agentlessScanID': 486,
                                                              'cluster': 'cluster1',
                                                              'modified': '2023-10-03T00:35:57.26Z',
                                                              'namespaces': ['default']}},
                    'id': 'sha256:4cv',
                    'image': {'created': '2015-10-19T09:17:01.62Z', 'entrypoint': ['ee4']},
                    'installedProducts': {'agentless': True, 'docker': 'a1', 'hasPackageManager': True,
                                          'osDistro': 'Linux 8'},
                    'instances': [{'host': 'ip-1.us-east.compute.internal-i-2',
                                   'image': 'registry.io/a-example:latest', 'modified': '2023-10-03T00:35:57.271Z',
                                   'registry': 'registry.io', 'repo': 'a-example', 'tag': 'latest'}], 'isARM64': False,
                    'malwareAnalyzedTime': '0001-01-01T00:00:00Z',
                    'missingDistroVulnCoverage': True, 'namespaces': ['default'], 'osDistro': 'd',
                    'osDistroRelease': 'j', 'osDistroVersion': '', 'packageCorrelationDone': False,
                    'packageManager': False, 'packages': None, 'pushTime': '0001-01-01T00:00:00Z', 'redHatNonRPMImage': False,
                    'repoDigests': [
                        'registry.io/a-example@sha256:5'],
                    'repoTag': {'registry': 'registry.io', 'repo': 'a-example', 'tag': 'latest'},
                    'riskFactors': {'Attack complexity: low': {}, 'Attack vector: network': {}, 'Critical severity': {},
                                    'DoS - High': {}, 'DoS - Low': {}, 'Exploit exists - POC': {}, 'Has fix': {},
                                    'High severity': {}, 'Medium severity': {}, 'Remote execution': {}},
                    'scanBuildDate': '20230914', 'scanID': 486, 'scanTime': '2023-10-03T00:35:57.271Z',
                    'scanVersion': '31.01.131', 'secretScanMetrics': {}, 'startupBinaries': None,
                    'tags': [{'registry': 'registry.io', 'repo': 'a-example', 'tag': 'latest'}],
                    'topLayer': 'sha256:5',
                    'trustStatus': 'trusted', 'type': 'image', 'vulnerabilities': None, 'vulnerabilitiesCount': 126,
                    'vulnerabilityDistribution': {'critical': 60, 'high': 53, 'low': 0, 'medium': 13, 'total': 126},
                    'vulnerabilityRiskScore': 60531300, 'wildFireUsage': None}

deployed_image_2 = {'repoTag': {'registry': '', 'repo': 'b-example', 'tag': 'latest'}, 'id': 'sha256:6', }

passed_ci_scan_image_1 = {"_id": "sha256:8",
                          "complianceDistribution": {"critical": 0, "high": 4, "low": 0, "medium": 1, "total": 5},
                          "complianceIssuesCount": 5, "creationTime": "2023-09-29T13:17:31.797Z",
                          "distro": "Ubuntu", "hostname": "ab",
                          "image": {"created": "2023-09-29T13:17:31.797Z", "entrypoint": ["python3"]},
                          "instances": [{"image": "pythonserver.io/pythonserver:67"}],
                          "labels": ["image.version:22.04", "name:ubuntu"],
                          "repoTag": {"registry": "pythonserver.io", "repo": "pythonserver", "tag": "67"}, "scanID": 0,
                          "scanTime": "2023-09-29T13:18:39.093Z", "scanVersion": "31.01.131",
                          "tags": [{"registry": "pythonserver.io", "repo": "pythonserver", "tag": "67"}],
                          "type": "ciImage", "vulnerabilitiesCount": 80,
                          "vulnerabilityDistribution": {"critical": 1, "high": 4, "low": 34, "medium": 41, "total": 80}}

passed_ci_scan_image_2 = {"_id": "sha256:7", "repoTag": {"registry": "pythonserver.io", "repo": "pythonserver", "tag": "67"}}


def execute_command(name, args=None):
    if name == 'getList' and args and 'listName' in args and args['listName'] == 'existingList':
        return [{'Contents': json.dumps({'b-example:*': '2023-10-03T15:34:52Z'}), 'Type': 'LIST'}]
    if name in ['setList', 'createList']:
        return None
    return None


def test_update_local_trusted_images(mocker):
    """
    Given:
        - Inputs including list name, time frame, and sample images
    When:
        - Calling the script with the inputs
    Then:
        - The script executes as expected and the readable output matches the expected value
    """
    from PrismaCloudLocalTrustedImagesListUpdate import update_local_trusted_images

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    list_name = 'existingList'
    time_frame = '1 day'
    args = {'list_name': list_name, 'time_frame': time_frame,
            'deployed_image': [deployed_image_1, deployed_image_2],
            'passed_ci_scan_image': [passed_ci_scan_image_1, passed_ci_scan_image_2]}
    response = update_local_trusted_images(args)
    assert response.readable_output == 'List existingList Updated Successfully.'


@pytest.mark.parametrize('given_input, expected', [
    (None, []),
    ('{"str": "value"}', [{'str': 'value'}]),
    ({"dict": "value"}, [{'dict': 'value'}]),
    ([{"list": "value"}], [{"list": "value"}])
])
def test_get_list_from_args(given_input, expected):
    """
    Given:
        - Various input arguments for the script
    When:
        - Calling the script with the different input arguments
    Then:
        - Returns the expected output of type list
    """
    from PrismaCloudLocalTrustedImagesListUpdate import get_list_from_args

    assert get_list_from_args(given_input) == expected


@pytest.mark.parametrize('list_name,get_list_response,expected_exists,expected_list', [
    ('test_list', {'Type': 1, 'Contents': '{"key": "value"}'}, True, {"key": "value"}),
    ('bad_list', {'Type': 4, 'Contents': 'Item not found'}, False, {}),
])
def test_get_list_if_exist(mocker, list_name, get_list_response, expected_exists, expected_list):
    """
    Given:
        - A list name input parameter
    When:
        - Calling getList with the list name
    Then:
        - Returns the expected output of whether the list exists and its content
    """
    from PrismaCloudLocalTrustedImagesListUpdate import get_list_if_exist

    mocker.patch('PrismaCloudLocalTrustedImagesListUpdate.demisto.executeCommand', return_value=[get_list_response])

    exists, list_ = get_list_if_exist(list_name)

    assert exists == expected_exists
    assert list_ == expected_list


@freeze_time('2022-02-22T00:00:00')
@pytest.mark.parametrize('current_dict, deployed_images, passed_ci_scan_images, expected', [
    ({},
     [{'repoTag': {'registry': 'r1', 'repo': 'img1'}}],
     [{'repoTag': {'registry': 'r2', 'repo': 'img2'}}],
     {'r1/img1:*': '2022-02-22T00:00:00Z', 'r2/img2:*': '2022-02-22T00:00:00Z'}),
    ({'r1/img1:*': '2022-02-21T00:00:00Z'},
     [],
     [{'repoTag': {'registry': 'r1', 'repo': 'img1'}}],
     {'r1/img1:*': '2022-02-22T00:00:00Z'}),
])
def test_update_dict_from_images(current_dict, deployed_images, passed_ci_scan_images, expected):
    """
    Given:
        - Input parameters for current dictionary, deployed images list, and CI scan images list
    When:
        - Calling the script with the input parameters
    Then:
        - The updated dictionary returned contains the expected entries
    """
    from PrismaCloudLocalTrustedImagesListUpdate import update_dict_from_images

    result = update_dict_from_images(current_dict, deployed_images, passed_ci_scan_images)
    assert result == expected


@freeze_time('2022-01-04T00:00:00')
@pytest.mark.parametrize('current_dict, time_frame, expected', [
    (
        {
            'image1': '2022-01-01T00:00:00',
            'image2': '2022-01-02T00:00:00',
            'image3': '2022-01-03T00:00:00'
        },
        '2022-01-02T00:00:00',
        {
            'image2': '2022-01-02T00:00:00',
            'image3': '2022-01-03T00:00:00'
        }
    ),
    (
        {
            'image1': '2022-01-03T00:00:00',
        },
        '1 hour',
        {}
    )
])
def test_remove_expired_images(current_dict, time_frame, expected):
    """
    Given:
        - A dictionary containing image entries with timestamps and a time frame for expiration
    When:
        - Calling the script with a time frame
    Then:
        - The function returns a dictionary containing only unexpired images
    """
    from PrismaCloudLocalTrustedImagesListUpdate import remove_expired_images

    result = remove_expired_images(current_dict, dateparser.parse(time_frame))
    assert result == expected


@pytest.mark.parametrize('list_name, list_data, is_list_exist', [
    ('test', {'image': 'img1'}, True),
    ('test', {'image': 'img2'}, False)
])
def test_create_update_list(mocker, list_name, list_data, is_list_exist):
    """
    Given:
        - A list name from script parameters
    When:
        - Calling create_update_list with the inputs
    Then:
        - The result matches expected strings based on the input existance of the list
    """
    from PrismaCloudLocalTrustedImagesListUpdate import create_update_list

    mocker.patch.object(demisto, 'executeCommand', return_value=[])

    result = create_update_list(list_name, list_data, is_list_exist)

    if is_list_exist:
        assert result == 'List test Updated Successfully.'
    else:
        assert result == 'List test Created Successfully.'
