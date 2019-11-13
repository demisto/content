
import pytest
import unittest
from Tests.scripts.update_id_set import has_duplicate, get_integration_data, get_script_data, get_playbook_data

mocked_data = [
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
        ], 'BluecatAddressManager', True),
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
        ], 'BluecatAddressManager', False)

]


@pytest.mark.parametrize('id_set, id_to_check, acceptable', mocked_data)
def test_had_duplicates(id_set, id_to_check, acceptable):
    assert acceptable == has_duplicate(id_set, id_to_check)


integration_data = {
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

integration_data_local = {
        "Cortex XDR - IR": {
            "name": "Cortex XDR - IR",
            "file_path": "~/dev/demisto/content/Packs/CortexXDR/Integrations/"
                         "PaloAltoNetworks_XDR/PaloAltoNetworks_XDR.yml",
            "fromversion": "4.1.0",
            "commands": [
                "xdr-get-incidents",
                "xdr-get-incident-extra-data",
                "xdr-update-incident"
            ]
        }
}

script_data = {
    "EntryWidgetNumberHostsXDR": {
        "name": "EntryWidgetNumberHostsXDR",
        "file_path": "Packs/CortexXDR/Scripts/EntryWidgetNumberHostsXDR/EntryWidgetNumberHostsXDR.yml",
        "fromversion": "5.0.0",
        "tests": [
            "No test - no need to test widget"
        ]
    }
}

script_data_local = {
    "EntryWidgetNumberHostsXDR": {
        "name": "EntryWidgetNumberHostsXDR",
        "file_path": "~/dev/demisto/content/Packs/CortexXDR/Scripts/EntryWidgetNumberHostsXDR/"
                     "EntryWidgetNumberHostsXDR.yml",
        "fromversion": "5.0.0",
        "tests": [
            "No test - no need to test widget"
        ]
    }
}


playbook_data = {
    "Cortex XDR Incident Handling": {
        "name": "Cortex XDR Incident Handling",
        "file_path": "Packs/CortexXDR/Playbooks/Cortex_XDR_Incident_Handling.yml",
        "fromversion": "4.5.0",
        "implementing_scripts": [
            "XDRSyncScript",
            "StopScheduledTask"
        ],
        "implementing_playbooks": [
            "Palo Alto Networks - Malware Remediation",
            "Calculate Severity - Standard"
        ],
        "command_to_integration": {
            "xdr-update-incident": "",
            "autofocus-sample-analysis": ""
        },
        "tests": [
            "No Test"
        ]
    }
}

playbook_data_local = {
    "Cortex XDR Incident Handling": {
        "name": "Cortex XDR Incident Handling",
        "file_path": "~/dev/demisto/content/Packs/CortexXDR/Playbooks/Cortex_XDR_Incident_Handling.yml",
        "fromversion": "4.5.0",
        "implementing_scripts": [
            "XDRSyncScript",
            "StopScheduledTask"
        ],
        "implementing_playbooks": [
            "Palo Alto Networks - Malware Remediation",
            "Calculate Severity - Standard"
        ],
        "command_to_integration": {
            "xdr-update-incident": "",
            "autofocus-sample-analysis": ""
        },
        "tests": [
            "No Test"
        ]
    }
}


class TestIntegration(unittest.TestCase):
    def test_get_integration_data(self, is_circle=False):
        """
        Test for getting all the integration data
        """
        file_path = '~/dev/demisto/content/Packs/CortexXDR/Integrations/PaloAltoNetworks_XDR/PaloAltoNetworks_XDR.yml'
        data = get_integration_data(file_path)
        self.assertDictEqual(data, integration_data_local)

        if is_circle:
            file_path = 'Packs/CortexXDR/Integrations/PaloAltoNetworks_XDR/PaloAltoNetworks_XDR.yml'
            data = get_integration_data(file_path)
            self.assertDictEqual(data, integration_data)

    def test_get_script_data(self, is_circle=False):
        """
        Test for getting the script data
        """
        file_path = '~/dev/demisto/content/Packs/CortexXDR/Scripts/EntryWidgetNumberHostsXDR/' \
                    'EntryWidgetNumberHostsXDR.yml'
        data = get_script_data(file_path)
        self.assertDictEqual(data, script_data_local)

        if is_circle:
            file_path = 'Packs/CortexXDR/Scripts/EntryWidgetNumberHostsXDR/' \
                    'EntryWidgetNumberHostsXDR.yml'
            data = get_script_data(file_path)
            self.assertDictEqual(data, script_data)

    def test_get_playbook_data(self, is_circle=False):
        """
        Test for getting the paybook data
        """
        file_path = '~/dev/demisto/content/Packs/CortexXDR/Playbooks/Cortex_XDR_Incident_Handling.yml'
        data = get_playbook_data(file_path)
        self.assertDictEqual(data, playbook_data_local)

        if is_circle:
            file_path = 'Packs/CortexXDR/Playbooks/Cortex_XDR_Incident_Handling.yml'
            data = get_playbook_data(file_path)
            self.assertDictEqual(data, playbook_data)


if __name__ == '__main__':
    unittest.main()
