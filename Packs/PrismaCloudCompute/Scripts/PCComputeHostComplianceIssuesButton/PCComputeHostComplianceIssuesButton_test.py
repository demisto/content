from PCComputeHostComplianceIssuesButton import run_prisma_cloud_compute_hosts_scan_list
import pytest
import json
import io
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import the script you want to test

TEST_CASES = [
    ({'hostname': 'example-host', 'ComplianceIDs': '6112'}, [
        {'Compliance ID': '6112', 'Cause': 'The directory /tmp should be mounted. File: /proc/mounts',
         'Severity': 'high', 'Title': '(CIS_Linux_2.0.0 - 1.1.2) Ensure /tmp is configured',
         'Description':
             'The /tmp directory is a world-writable directory used for temporary storage by all users\nand some applications.'}
    ]),
    ({'hostname': 'example-host', 'ComplianceIDs': '6112,6116,6117'}, [
        {'Compliance ID': '6112', 'Cause': 'The directory /tmp should be mounted. File: /proc/mounts',
         'Severity': 'high', 'Title': '(CIS_Linux_2.0.0 - 1.1.2) Ensure /tmp is configured',
         'Description':
             'The /tmp directory is a world-writable directory used for temporary storage by all users\nand some applications.'},
        {'Compliance ID': '6116', 'Cause': 'The directory /var should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.6) Ensure separate partition exists for /var',
         'Description': 'Description for compliance ID 6116'},
        {'Compliance ID': '6117', 'Cause': 'The directory /var/tmp should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.7) Ensure separate partition exists for /var/tmp',
         'Description':
             'Description for compliance ID 6117'}
    ]),
    ({'hostname': 'example-host', 'ComplianceIDs': ''}, [
        {'Compliance ID': '6112', 'Cause': 'The directory /tmp should be mounted. File: /proc/mounts',
         'Severity': 'high', 'Title': '(CIS_Linux_2.0.0 - 1.1.2) Ensure /tmp is configured',
         'Description':
             'The /tmp directory is a world-writable directory used for temporary storage by all users\nand some applications.'},
        {'Compliance ID': '6116', 'Cause': 'The directory /var should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.6) Ensure separate partition exists for /var',
         'Description': 'Description for compliance ID 6116'},
        {'Compliance ID': '6117', 'Cause': 'The directory /var/tmp should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.7) Ensure separate partition exists for /var/tmp',
         'Description': 'Description for compliance ID 6117'},
        {'Compliance ID': '61115', 'Cause': 'The directory /var/log should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.11) Ensure separate partition exists for /var/log',
         'Description': 'Description for compliance ID 61115'},
        {'Compliance ID': '61116', 'Cause': 'The directory /var/log/audit should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.12) Ensure separate partition exists for /var/log/audit',
         'Description': 'Description for compliance ID 61116'},
        {'Compliance ID': '602214', 'Cause': 'The service systemd-timesyncd.service should be enabled',
         'Severity': 'low', 'Title': '(CIS_Linux_2.0.0 - 2.2.1.4) Ensure systemd-timesyncd is configured',
         'Description': 'Description for compliance ID 602214'}
    ])
]



def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


compliance_issues = util_load_json('test_data/host_compliance_issues.json')


@pytest.mark.parametrize('args, expected', TEST_CASES)
def test_run_prisma_cloud_compute_hosts_scan_list(mocker, args, expected):
    # Mock the executeCommand function
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Type': EntryType.NOTE,
                                                                  'Contents': [{'complianceIssues': compliance_issues}]
                                                                  }])

    # Run the function
    mocker.patch.object(demisto, 'results')
    run_prisma_cloud_compute_hosts_scan_list(args.get('hostname'), args.get('ComplianceIDs'))

    # Check the results
    results = demisto.results.call_args[0][0]
    # results = demisto.results.mock_calls[00].args[0]
    assert results.get('Tags') == ['ComplianceIssuesResults']

    outputs = results['EntryContext']
    assert outputs.get('PrismaCloudCompute.PCC_HostComplianceIssues', []).get('compliance_issues') == expected

    readable_output = results['HumanReadable']
    assert f'Compliance Issues of host {args.get("hostname")}' in readable_output

# Add more tests as needed
