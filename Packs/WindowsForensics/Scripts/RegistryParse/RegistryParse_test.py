import json
import RegistryParse as reg_parse


def util_load_json(path):
    with open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_sub_keys():
    key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList'
    folder_output_key = 'Sid'
    mock_reg = util_load_json('./test_data/mock_reg_users.json')
    expected = util_load_json('./test_data/mock_reg_users_result.json')
    actual = reg_parse.get_sub_keys(mock_reg, key, folder_output_key)
    for actual_items in actual:
        for actual_item in actual_items:
            assert actual_item in expected[0] or actual_item in expected[1]


def test_parse_reg_values():
    expected = 'C:\\Windows\\ServiceProfiles\\LocalService'
    hex_value = 'hex(2):43,00,3a,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,\
00,73,00,5c,00,53,00,65,00,72,00,76,00,69,00,63,00,65,00,50,00,72,00,6f,00,\
66,00,69,00,6c,00,65,00,73,00,5c,00,4c,00,6f,00,63,00,61,00,6c,00,53,00,65,\
00,72,00,76,00,69,00,63,00,65,00,00,00'
    actual = reg_parse.parse_reg_value(hex_value)
    assert actual == expected
