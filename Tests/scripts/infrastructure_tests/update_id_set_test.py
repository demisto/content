import unittest
import pytest
from Tests.scripts.update_id_set import has_duplicate, get_integration_data, get_script_data, get_playbook_data, \
    validate_playbook_dependencies

MOCKED_DATA = [
    (
        [
            {
                "BluecatAddressManager": {
                    "name": "BluecatAddressManager",
                    "file_path": "Integrations/BluecatAddressManager/BluecatAddressManager.yml",
                    "fromversion": "5.0.0"
                }
            },
            {
                "BluecatAddressManager": {
                    "name": "BluecatAddressManager",
                    "file_path": "Integrations/BluecatAddressManager/BluecatAddressManager.yml",
                    "fromversion": "5.0.0"
                }
            }
        ], 'BluecatAddressManager', True
    ),
    (
        [
            {
                "BluecatAddressManager": {
                    "name": "BluecatAddressManager",
                    "file_path": "Integrations/BluecatAddressManager/BluecatAddressManager.yml",
                    "fromversion": "5.0.0"
                }
            },
            {
                "BluecatAddressManager": {
                    "name": "BluecatAddressManager",
                    "file_path": "Integrations/BluecatAddressManager/BluecatAddressManager.yml",
                    "fromversion": "3.1.0",
                    "toversion": "4.0.0"
                }
            }
        ], 'BluecatAddressManager', False
    ),
    (
        [
            {
                'Test3': {
                    'name': 'Test3',
                    'file_path': 'A',
                    'fromversion': '3.0.0',
                    'toversion': '3.6.0',
                }
            },
            {
                'Test3': {
                    'name': 'Test3',
                    'file_path': 'B',
                    'fromversion': '3.5.0',
                    'toversion': '4.5.0',
                }
            },
            {
                'Test3': {
                    'name': 'Test3',
                    'file_path': 'C',
                    'fromversion': '3.5.2',
                    'toversion': '3.5.4',
                }
            },
            {
                'Test3': {
                    'name': 'Test3',
                    'file_path': 'D',
                    'fromversion': '4.5.0',
                },
            },
        ], 'Test3', True
    ),
]


@pytest.mark.parametrize('id_set, id_to_check, result', MOCKED_DATA)
def test_had_duplicates(id_set, id_to_check, result):
    assert result == has_duplicate(id_set, id_to_check)


INTEGRATION_DATA = {
    "Cortex XDR - IR": {
        "name": "Cortex XDR - IR",
        "file_path": "Packs/CortexXDR/Integrations/PaloAltoNetworks_XDR/PaloAltoNetworks_XDR.yml",
        "fromversion": "4.1.0",
        "commands": [
            "xdr-get-incidents",
            "xdr-get-incident-extra-data",
            "xdr-update-incident"
        ]
    }
}

SCRIPT_DATA = {
    "EntryWidgetNumberHostsXDR": {
        "name": "EntryWidgetNumberHostsXDR",
        "file_path": "Packs/CortexXDR/Scripts/EntryWidgetNumberHostsXDR/EntryWidgetNumberHostsXDR.yml",
        "fromversion": "5.0.0",
        "tests": [
            "No test - no need to test widget"
        ]
    }
}

PLAYBOOK_DATA = {
    "name": "Cortex XDR Incident Handling",
    "file_path": "Packs/CortexXDR/Playbooks/Cortex_XDR_Incident_Handling.yml",
    "fromversion": "4.5.0",
    "implementing_scripts": [
        "XDRSyncScript",
        "StopScheduledTask",
    ],
    "implementing_playbooks": [
        "Calculate Severity - Standard",
        "Palo Alto Networks - Malware Remediation",
    ],
    "command_to_integration": {
        "xdr-update-incident": "",
        "autofocus-sample-analysis": ""
    },
    "tests": [
        "No Test"
    ]
}
PLAYBOOK_DATA_TEST = PLAYBOOK_DATA.copy()
PLAYBOOK_DATA_TEST["implementing_playbooks"] = ["Calculate Severity - Standard"]
PLAYBOOK_DATA_TEST["name"] = "Calculate Severity - Standard Test"

PLAYBOOK_DATA2 = PLAYBOOK_DATA.copy()
PLAYBOOK_DATA2["implementing_playbooks"] = ["Cortex XDR Incident Handling"]
PLAYBOOK_DATA2["name"] = "Calculate Severity - Standard"

PLAYBOOK_DATA3 = PLAYBOOK_DATA.copy()
PLAYBOOK_DATA3["implementing_playbooks"] = ["Cortex XDR Incident Handling"]
PLAYBOOK_DATA3["name"] = "Palo Alto Networks - Malware Remediation"


class TestIntegration(unittest.TestCase):
    def test_get_integration_data(self):
        """
        Test for getting all the integration data
        """
        file_path = 'Packs/CortexXDR/Integrations/PaloAltoNetworks_XDR/PaloAltoNetworks_XDR.yml'
        data = get_integration_data(file_path)
        self.assertDictEqual(data, INTEGRATION_DATA)

    def test_get_script_data(self):
        """
        Test for getting the script data
        """
        file_path = 'Packs/CortexXDR/Scripts/EntryWidgetNumberHostsXDR/EntryWidgetNumberHostsXDR.yml'
        data = get_script_data(file_path)
        self.assertDictEqual(data, SCRIPT_DATA)

    def test_get_playbook_data(self):
        """
        Test for getting the playbook data
        """
        file_path = 'Packs/CortexXDR/Playbooks/Cortex_XDR_Incident_Handling.yml'
        data = get_playbook_data(file_path)['Cortex XDR Incident Handling']
        self.assertEqual(data['name'], PLAYBOOK_DATA['name'])
        self.assertEqual(data['file_path'], PLAYBOOK_DATA['file_path'])
        self.assertEqual(data['fromversion'], PLAYBOOK_DATA['fromversion'])
        self.assertListEqual(data['tests'], PLAYBOOK_DATA['tests'])
        self.assertSetEqual(set(data['implementing_playbooks']), set(PLAYBOOK_DATA['implementing_playbooks']))
        self.assertListEqual(data['tests'], PLAYBOOK_DATA['tests'])
        self.assertDictEqual(data['command_to_integration'], PLAYBOOK_DATA['command_to_integration'])


class TestValidatePlaybook(object):
    playbook_deps = [
        # One playbook path, all depends on each other
        {"playbooks": [{"str0": PLAYBOOK_DATA}, {"str1": PLAYBOOK_DATA2}, {"str2": PLAYBOOK_DATA3}]},
        # Empty case
        {},
        # Two paths, depends on each other
        {"TestPlaybooks": [{"str": PLAYBOOK_DATA_TEST}],
         "playbooks": [{"str": PLAYBOOK_DATA2}, {"str1": PLAYBOOK_DATA3}, {"str2": PLAYBOOK_DATA}]},
    ]

    @pytest.mark.parametrize('input_data', playbook_deps)
    def test_validate_playbook_deps(self, input_data):
        validate_playbook_dependencies(input_data)

    playbook_deps_invalid = [
        # One dependency, no other playbook
        {"playbooks": [{"str": PLAYBOOK_DATA}]},
        # Two different paths playbooks, missing dependency
        {"playbooks": [{"str": PLAYBOOK_DATA}], "TestPlaybooks": [{"str": PLAYBOOK_DATA2}]},
        # Missing playbook
        {"TestPlaybooks": [{"PLAYBOOK_DATA_TEST": PLAYBOOK_DATA_TEST}]}

    ]

    @pytest.mark.parametrize('input_data', playbook_deps_invalid)
    def test_invalid_playbook_deps(self, input_data):
        with pytest.raises(SystemExit):
            validate_playbook_dependencies(input_data)


if __name__ == '__main__':
    unittest.main()
