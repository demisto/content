
import pytest
import unittest
from Tests.scripts.update_id_set import has_duplicate, get_integration_data, get_script_data

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
            "file_path": "Integrations/PaloAltoNetworks_XDR/PaloAltoNetworks_XDR.yml",
            "fromversion": "4.1.0",
            "commands": [
                "xdr-get-incidents",
                "xdr-get-incident-extra-data",
                "xdr-update-incident"
            ]
        }
    }

script_data = {
    "AnalyzeMemImage": {
        "name": "AnalyzeMemImage",
        "file_path": "Scripts/script-AnalyzeMemImage.yml"
    }
}


class TestIntegration(unittest.TestCase):
    def test_get_integration_data(self):
        """
        Test for getting all the integration data
        """
        file_path = 'Integrations/PaloAltoNetworks_XDR/PaloAltoNetworks_XDR.yml'
        data = get_integration_data(file_path)
        self.assertDictEqual(data, integration_data)

    def test_get_script_data(self):
        """
        Test for getting the script data
        """
        file_path = 'Scripts/script-AnalyzeMemImage.yml'
        data = get_script_data(file_path)
        self.assertDictEqual(data, script_data)


if __name__ == '__main__':
    unittest.main()

