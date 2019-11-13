import pytest

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


integration_data = "{'Cortex XDR - IR': OrderedDict([('name', 'Cortex XDR - IR')"


def test_get_integration_data():
    file_path = '~/dev/demisto/content/Integrations/PaloAltoNetworks_XDR/PaloAltoNetworks_XDR.yml'
    data = get_integration_data(file_path)

    assert integration_data in str(data)


script_data = "{'AnalyzeMemImage': OrderedDict([('name', 'AnalyzeMemImage')"


def test_get_script_data():
    file_path = '~/dev/demisto/content/Scripts/script-AnalyzeMemImage.yml'
    data = get_script_data(file_path)

    assert script_data in str(data)

