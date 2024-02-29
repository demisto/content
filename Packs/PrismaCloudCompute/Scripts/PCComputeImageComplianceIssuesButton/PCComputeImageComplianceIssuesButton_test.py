from PCComputeImageComplianceIssuesButton import run_prisma_cloud_compute_images_scan_list, main
import pytest
import json
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import the script you want to test

TEST_CASES = [
    ({'id': 'sha256:e1e5f27107c905ac998cd8107b0513f65a64d49a1b04c974e6a19d27f73e0c82', 'compliance_ids': '6112'}, [
        {'ComplianceID': '6112', 'Cause': 'The directory /tmp should be mounted. File: /proc/mounts',
         'Severity': 'high', 'Title': '(CIS_Linux_2.0.0 - 1.1.2) Ensure /tmp is configured',
         'Description':
             'The /tmp directory is a world-writable directory used for temporary storage by all users\nand some applications.'}
    ]),
    ({'id': 'sha256:e1e5f27107c905ac998cd8107b0513f65a64d49a1b04c974e6a19d27f73e0c82', 'compliance_ids': '6112,6116,6117'}, [
        {'ComplianceID': '6112', 'Cause': 'The directory /tmp should be mounted. File: /proc/mounts',
         'Severity': 'high', 'Title': '(CIS_Linux_2.0.0 - 1.1.2) Ensure /tmp is configured',
         'Description':
             'The /tmp directory is a world-writable directory used for temporary storage by all users\nand some applications.'},
        {'ComplianceID': '6116', 'Cause': 'The directory /var should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.6) Ensure separate partition exists for /var',
         'Description': 'Description for compliance ID 6116'},
        {'ComplianceID': '6117', 'Cause': 'The directory /var/tmp should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.7) Ensure separate partition exists for /var/tmp',
         'Description':
             'Description for compliance ID 6117'}
    ]),
    ({'id': 'sha256:e1e5f27107c905ac998cd8107b0513f65a64d49a1b04c974e6a19d27f73e0c82', 'compliance_ids': ''}, [
        {'ComplianceID': '6112', 'Cause': 'The directory /tmp should be mounted. File: /proc/mounts',
         'Severity': 'high', 'Title': '(CIS_Linux_2.0.0 - 1.1.2) Ensure /tmp is configured',
         'Description':
             'The /tmp directory is a world-writable directory used for temporary storage by all users\nand some applications.'},
        {'ComplianceID': '6116', 'Cause': 'The directory /var should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.6) Ensure separate partition exists for /var',
         'Description': 'Description for compliance ID 6116'},
        {'ComplianceID': '6117', 'Cause': 'The directory /var/tmp should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.7) Ensure separate partition exists for /var/tmp',
         'Description': 'Description for compliance ID 6117'},
        {'ComplianceID': '61115', 'Cause': 'The directory /var/log should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.11) Ensure separate partition exists for /var/log',
         'Description': 'Description for compliance ID 61115'},
        {'ComplianceID': '61116', 'Cause': 'The directory /var/log/audit should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.12) Ensure separate partition exists for /var/log/audit',
         'Description': 'Description for compliance ID 61116'},
        {'ComplianceID': '602214', 'Cause': 'The service systemd-timesyncd.service should be enabled',
         'Severity': 'low', 'Title': '(CIS_Linux_2.0.0 - 2.2.1.4) Ensure systemd-timesyncd is configured',
         'Description': 'Description for compliance ID 602214'}
    ])
]

RETURN_ERROR_TARGET = 'PCComputeImageComplianceIssuesButton.return_error'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


compliance_issues = util_load_json('test_data/compliance_issues.json')


@pytest.mark.parametrize('args, expected', TEST_CASES)
def test_run_prisma_cloud_compute_images_scan_list(mocker, args, expected):
    # Mock the executeCommand function
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Type': EntryType.NOTE,
                                                                  'Contents': [{'complianceIssues': compliance_issues}]
                                                                  }])

    # Run the function
    mocker.patch.object(demisto, 'results')
    run_prisma_cloud_compute_images_scan_list(args.get('id'), args.get('compliance_ids'))

    # Check the results
    results = demisto.results.call_args[0][0]
    assert results.get('Tags') == ['ComplianceIssuesResults']

    outputs = results['EntryContext']
    assert outputs.get('PrismaCloudCompute.PCC_ImageComplianceIssues', []).get('compliance_issues') == expected

    readable_output = results['HumanReadable']
    assert f'Compliance Issues of image {args.get("id")}' in readable_output


def test_main_function_with_error(mocker):
    # Mock the necessary components
    mocker.patch.object(demisto, 'getArg', side_effect='invalid_image_id')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    main()
    err_msg = return_error_mock.call_args_list[0][0][0]
    assert 'Invalid image_id. It should be in the format \'sha256:{64 characters}\'.' in err_msg
