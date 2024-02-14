from PCComputeHostComplianceIssuesButton import run_prisma_cloud_compute_hosts_scan_list
import pytest
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import the script you want to test

TEST_CASES = [
    ({'hostname': 'example-host', 'ComplianceIDs': '6112'}, [
        {'Compliance ID': '6112', 'Cause': 'The directory /tmp should be mounted. File: /proc/mounts',
         'Severity': 'high', 'Title': '(CIS_Linux_2.0.0 - 1.1.2) Ensure /tmp is configured'}
    ]),
    ({'hostname': 'example-host', 'ComplianceIDs': '6112,6116,6117'}, [
        {'Compliance ID': '6112', 'Cause': 'The directory /tmp should be mounted. File: /proc/mounts',
         'Severity': 'high', 'Title': '(CIS_Linux_2.0.0 - 1.1.2) Ensure /tmp is configured'},
        {'Compliance ID': '6116', 'Cause': 'The directory /var should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.6) Ensure separate partition exists for /var'},
        {'Compliance ID': '6117', 'Cause': 'The directory /var/tmp should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.7) Ensure separate partition exists for /var/tmp'}
    ]),
    ({'hostname': 'example-host', 'ComplianceIDs': ''}, [
        {'Compliance ID': '6112', 'Cause': 'The directory /tmp should be mounted. File: /proc/mounts',
         'Severity': 'high', 'Title': '(CIS_Linux_2.0.0 - 1.1.2) Ensure /tmp is configured'},
        {'Compliance ID': '6116', 'Cause': 'The directory /var should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.6) Ensure separate partition exists for /var'},
        {'Compliance ID': '6117', 'Cause': 'The directory /var/tmp should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.7) Ensure separate partition exists for /var/tmp'},
        {'Compliance ID': '61115', 'Cause': 'The directory /var/log should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.11) Ensure separate partition exists for /var/log'},
        {'Compliance ID': '61116', 'Cause': 'The directory /var/log/audit should be mounted. File: /proc/mounts',
         'Severity': 'medium', 'Title': '(CIS_Linux_2.0.0 - 1.1.12) Ensure separate partition exists for /var/log/audit'},
        {'Compliance ID': '602214', 'Cause': 'The service systemd-timesyncd.service should be enabled',
         'Severity': 'low', 'Title': '(CIS_Linux_2.0.0 - 2.2.1.4) Ensure systemd-timesyncd is configured'}
    ])
]


@pytest.mark.parametrize('args, expected', TEST_CASES)
def test_run_prisma_cloud_compute_hosts_scan_list(mocker, args, expected):
    # Mock the executeCommand function
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Type': EntryType.NOTE,
                                                                  'Contents': [{'complianceIssues': [
                                                                      {"text": "", "id": 6112, "severity": "high", "cvss": 0, "status": "",
                                                                       "cause": "The directory /tmp should be mounted. File: /proc/mounts",
                                                                       "description": "The /tmp directory is a world-writable directory used for temporary storage by all users\nand some "
                                                                       "applications.",
                                                                       "title": "(CIS_Linux_2.0.0 - 1.1.2) Ensure /tmp is configured",
                                                                       "vecStr": "", "exploit": "", "riskFactors": None, "link": "", "type": "linux", "packageName": "",
                                                                       "packageVersion": "", "layerTime": 0, "templates": None, "twistlock": False, "cri": False,
                                                                       "published": 0, "fixDate": 0, "discovered": "0001-01-01T00:00:00Z", "functionLayer": "",
                                                                       "wildfireMalware": {}, "secret": {}},
                                                                      {"text": "", "id": 6116, "severity": "medium", "cvss": 0, "status": "",
                                                                       "cause": "The directory /var should be mounted. File: /proc/mounts",
                                                                       "description": "Description for compliance ID 6116",
                                                                       "title": "(CIS_Linux_2.0.0 - 1.1.6) Ensure separate partition exists for /var",
                                                                       "vecStr": "", "exploit": "", "riskFactors": None, "link": "", "type": "linux", "packageName": "",
                                                                       "packageVersion": "", "layerTime": 0, "templates": None, "twistlock": False, "cri": False,
                                                                       "published": 0, "fixDate": 0, "discovered": "0001-01-01T00:00:00Z", "functionLayer": "",
                                                                       "wildfireMalware": {}, "secret": {}},
                                                                      {"text": "", "id": 6117, "severity": "medium", "cvss": 0, "status": "",
                                                                       "cause": "The directory /var/tmp should be mounted. File: /proc/mounts",
                                                                       "description": "Description for compliance ID 6117",
                                                                       "title": "(CIS_Linux_2.0.0 - 1.1.7) Ensure separate partition exists for /var/tmp",
                                                                       "vecStr": "", "exploit": "", "riskFactors": None, "link": "", "type": "linux", "packageName": "",
                                                                       "packageVersion": "", "layerTime": 0, "templates": None, "twistlock": False, "cri": False,
                                                                       "published": 0, "fixDate": 0, "discovered": "0001-01-01T00:00:00Z", "functionLayer": "",
                                                                       "wildfireMalware": {}, "secret": {}},
                                                                      {"text": "", "id": 61115, "severity": "medium", "cvss": 0, "status": "",
                                                                       "cause": "The directory /var/log should be mounted. File: /proc/mounts",
                                                                       "description": "Description for compliance ID 61115",
                                                                       "title": "(CIS_Linux_2.0.0 - 1.1.11) Ensure separate partition exists for /var/log",
                                                                       "vecStr": "", "exploit": "", "riskFactors": None, "link": "", "type": "linux", "packageName": "",
                                                                       "packageVersion": "", "layerTime": 0, "templates": None, "twistlock": False, "cri": False,
                                                                       "published": 0, "fixDate": 0, "discovered": "0001-01-01T00:00:00Z", "functionLayer": "",
                                                                       "wildfireMalware": {}, "secret": {}},
                                                                      {"text": "", "id": 61116, "severity": "medium", "cvss": 0, "status": "",
                                                                       "cause": "The directory /var/log/audit should be mounted. File: /proc/mounts",
                                                                       "description": "Description for compliance ID 61116",
                                                                       "title": "(CIS_Linux_2.0.0 - 1.1.12) Ensure separate partition exists for /var/log/audit",
                                                                       "vecStr": "", "exploit": "", "riskFactors": None, "link": "", "type": "linux", "packageName": "",
                                                                       "packageVersion": "", "layerTime": 0, "templates": None, "twistlock": False, "cri": False,
                                                                       "published": 0, "fixDate": 0, "discovered": "0001-01-01T00:00:00Z", "functionLayer": "",
                                                                       "wildfireMalware": {}, "secret": {}},
                                                                      {"text": "", "id": 602214, "severity": "low", "cvss": 0, "status": "",
                                                                       "cause": "The service systemd-timesyncd.service should be enabled",
                                                                       "description": "Description for compliance ID 602214",
                                                                       "title": "(CIS_Linux_2.0.0 - 2.2.1.4) Ensure systemd-timesyncd is configured",
                                                                       "vecStr": "", "exploit": "", "riskFactors": None, "link": "", "type": "linux", "packageName": "",
                                                                       "packageVersion": "", "layerTime": 0, "templates": None,
                                                                       "twistlock": False, "cri": False,
                                                                       "published": 0, "fixDate": 0, "discovered": "0001-01-01T00:00:00Z", "functionLayer": "",
                                                                       "wildfireMalware": {}, "secret": {}},
                                                                  ]}]
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
