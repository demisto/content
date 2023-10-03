import json

from PrismaCloudLocalTrustedImagesListUpdate import update_local_trusted_images
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
    if name == 'setList' or name == 'createList':
        return None
    else:
        raise ValueError('Unimplemented command called: {}'.format(name))


def test_update_local_trusted_images(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    list_name = 'existingList'
    time_frame = '1 day'
    args = {'list_name': list_name, 'time_frame': time_frame,
            'deployed_image': [deployed_image_1, deployed_image_2],
            'passed_ci_scan_image': [passed_ci_scan_image_1, passed_ci_scan_image_2]}
    response = update_local_trusted_images(args)
    assert response.readable_output == 'List existingList Updated Successfully.'

