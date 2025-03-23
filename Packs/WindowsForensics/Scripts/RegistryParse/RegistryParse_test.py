import json
import RegistryParse as reg_parse


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_get_sub_keys():
    key = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
    folder_output_key = "Sid"
    mock_reg = util_load_json("./test_data/mock_reg_users.json")
    expected = util_load_json("./test_data/mock_reg_users_result.json")
    actual = reg_parse.get_sub_keys(mock_reg, key, folder_output_key)
    for actual_items in actual:
        for actual_item in actual_items:
            assert actual_item in expected[0] or actual_item in expected[1]


def test_parse_reg_values():
    expected = "C:\\Windows\\ServiceProfiles\\LocalService"
    hex_value = "hex(2):43,00,3a,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,\
00,73,00,5c,00,53,00,65,00,72,00,76,00,69,00,63,00,65,00,50,00,72,00,6f,00,\
66,00,69,00,6c,00,65,00,73,00,5c,00,4c,00,6f,00,63,00,61,00,6c,00,53,00,65,\
00,72,00,76,00,69,00,63,00,65,00,00,00"
    actual = reg_parse.parse_reg_value(hex_value)
    assert actual == expected


def test_get_reg_results():
    """
    Given
       - registry keys with mocked "evil" data (which could be case-insensitive as well)

    When
       - parsing registry results

    Then
      - make sure the result is parsed correctly.

    """
    from RegistryParse import get_reg_results

    reg = {
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run": {
            '"Cyvera"': '"test.exe"',
            '"EvilKey"': '"test2.exe"',
        }
    }

    records, type_records = get_reg_results(
        reg=reg, type_to_keys={"MachineStartup": ["HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]}
    )

    assert records == [
        {
            "Type": "MachineStartup",
            "RegistryPath": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "RegistryKey": "Cyvera",
            "RegistryValue": "test.exe",
        },
        {
            "Type": "MachineStartup",
            "RegistryPath": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "RegistryKey": "EvilKey",
            "RegistryValue": "test2.exe",
        },
    ]

    assert type_records == {"MachineStartup": [{"Cyvera": "test.exe", "EvilKey": "test2.exe"}]}
