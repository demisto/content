"""OPNSense Integration for Cortex XSOAR - Unit Tests file"""

import json
import io
import ast


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_mock(path):
    with open(path, 'r') as f:
        data = f.read()
    return ast.literal_eval(data)


MOCK_PARAMETERS = {
    'base_url': 'https://opnsense.mockserver.com/api',
    'auth': (
        'NTVjNzhjNGE0MzkzMzUzMzJjNjY4ZDA2NjQzYTkwY2Q3ZDIyODExMzAzOWEzZmNmODNhMTU3ZmFkMDBmNGY5Mg',
        'NzYyMDgzYThlYjU1OTZlMGY5ZTdmY2MwMDk1NDI2MTMyMGMxZDZlNzhlOWZjMzIyNzQ0NmJjYmEzZWQ0MDUyYQ'
    ),
    'verify_cert': False,
    'proxy': False,
    'timeout': 60
}


def test_opnsense_alias_apply(requests_mock):
    from OPNSense import Client, alias_apply_command
    mock_response = {'status': 'ok'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/alias/reconfigure/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = alias_apply_command(client)
    assert response.outputs_prefix == 'OPNSense.Alias'
    assert response.outputs == '{"status": "ok"}'


def test_opnsense_alias_list(requests_mock):
    from OPNSense import Client, alias_list_command
    mock_response = ["alias1", "alias2", "alias3"]
    requests_mock.get("https://opnsense.mockserver.com/api/firewall/alias_util/aliases/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = alias_list_command(client)
    assert response.outputs_prefix == 'OPNSense.Alias'
    assert response.outputs == '["alias1", "alias2", "alias3"]'


def test_opnsense_alias_add(requests_mock):
    from OPNSense import Client, alias_add_command
    mock_args = {'name': 'NewAlias', 'type': 'host', 'content': '1.2.3.4', 'description': 'MyNewAlias'}
    mock_response = {'result': 'saved', 'uuid': '8abfa542-4031-4e63-9ccd-34ffd31886d4'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/alias/addItem/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = alias_add_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Alias'
    assert response[0].outputs == {'result': 'saved', 'uuid': '8abfa542-4031-4e63-9ccd-34ffd31886d4'}


def test_opnsense_alias_mod(requests_mock):
    from OPNSense import Client, alias_mod_command
    mock_args = {'uuid': '8abfa542-4031-4e63-9ccd-34ffd31886d4', 'description': 'MyRenamedAlias',
                 'content': '1.2.3.4', 'name': 'RenamedAlias'}
    mock_response = util_load_json('test_data/opnsense_alias_mod.json')
    requests_mock.get("https://opnsense.mockserver.com/api/firewall/alias/getItem/8abfa542-4031-4e63-9ccd-34ffd31886d4/",
                      json=mock_response)
    mock_response2 = {'result': 'saved'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/alias/setItem/8abfa542-4031-4e63-9ccd-34ffd31886d4/",
                       json=mock_response2)
    client = Client(MOCK_PARAMETERS)
    response = alias_mod_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Alias'
    assert response[0].outputs == {'result': 'saved'}


def test_opnsense_alias_mod_additem(requests_mock):
    from OPNSense import Client, alias_mod_additem_command
    mock_args = {'name': 'NewAlias', 'entry': '1.2.3.4'}
    mock_response = {'status': 'done'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/alias_util/add/NewAlias/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = alias_mod_additem_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Alias'
    assert response[0].outputs == {'status': 'done'}


def test_opnsense_alias_mod_delitem(requests_mock):
    from OPNSense import Client, alias_mod_delitem_command
    mock_args = {'name': 'NewAlias', 'entry': '1.2.3.4'}
    mock_response = {'status': 'done'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/alias_util/delete/NewAlias/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = alias_mod_delitem_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Alias'
    assert response[0].outputs == {'status': 'done'}


def test_opnsense_alias_del(requests_mock):
    from OPNSense import Client, alias_del_command
    mock_args = {'uuid': '8abfa542-4031-4e63-9ccd-34ffd31886d4'}
    mock_response = {'result': 'deleted'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/alias/delItem/8abfa542-4031-4e63-9ccd-34ffd31886d4/",
                       json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = alias_del_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Alias'
    assert response[0].outputs == {'result': 'deleted'}


def test_opnsense_alias_get(requests_mock):
    from OPNSense import Client, alias_get_command
    mock_args = {'uuid': '8abfa542-4031-4e63-9ccd-34ffd31886d4'}
    mock_response = util_load_json('test_data/opnsense_alias_get.json')
    requests_mock.get("https://opnsense.mockserver.com/api/firewall/alias/getItem/8abfa542-4031-4e63-9ccd-34ffd31886d4/",
                      json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = alias_get_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Alias'
    assert response[0].outputs == {'enabled': '1', 'name': 'NewAlias', 'type': 'host', 'proto': '', 'interface': '',
                                   'counters': '', 'updatefreq': '', 'content': '1.2.3.4', 'description': 'MyNewAlias'}


def test_opnsense_alias_getuuid(requests_mock):
    from OPNSense import Client, alias_getuuid_command
    mock_args = {'name': 'NewAlias'}
    mock_response = {'uuid': '8abfa542-4031-4e63-9ccd-34ffd31886d4'}
    requests_mock.get("https://opnsense.mockserver.com/api/firewall/alias/getAliasUUID/NewAlias/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = alias_getuuid_command(client, mock_args)
    assert response.outputs_prefix == 'OPNSense.Alias'
    assert response.outputs == '"8abfa542-4031-4e63-9ccd-34ffd31886d4"'


def test_opnsense_interfaces_list(requests_mock):
    from OPNSense import Client, interfaces_list_command
    mock_response = {"int1": "name1", "int2": "name2", "int3": "name3"}
    requests_mock.get("https://opnsense.mockserver.com/api/diagnostics/interface/getInterfaceNames/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = interfaces_list_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Interfaces'
    assert response[0].outputs == {"int1": "name1", "int2": "name2", "int3": "name3"}


def test_opnsense_logs_search(requests_mock):
    from OPNSense import Client, logs_search_command
    mock_args = {'limit': 5}
    mock_response = util_load_mock('test_data/opnsense_logs_search.mock')
    requests_mock.get("https://opnsense.mockserver.com/api/diagnostics/firewall/log/?limit=5", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = logs_search_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Logs'
    assert response[0].outputs == util_load_mock('test_data/opnsense_logs_search.res.mock')


def test_opnsense_states_search(requests_mock):
    from OPNSense import Client, states_search_command
    mock_args = {'limit': 5}
    mock_response = util_load_mock('test_data/opnsense_states_search.mock')
    requests_mock.post("https://opnsense.mockserver.com/api/diagnostics/firewall/queryStates/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = states_search_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.States'
    assert response[0].outputs == util_load_mock('test_data/opnsense_states_search.res.mock')


def test_opnsense_states_del(requests_mock):
    from OPNSense import Client, state_del_command
    mock_args = {'state_id': '0006466200000003/ef725303'}
    mock_response = {'result': 'killed 1 states\n\n\n'}
    requests_mock.post("https://opnsense.mockserver.com/api/diagnostics/firewall/delState/0006466200000003/ef725303",
                       json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = state_del_command(client, mock_args)
    assert response == {'result': 'killed 1 states\n\n\n'}


def test_opnsense_category_list(requests_mock):
    from OPNSense import Client, category_list_command
    mock_response = {'rows': [{'uuid': 'cef2c7d7-68d8-41aa-b6b8-1cac38554d58', 'name': 'Categ1', 'auto': '1', 'color': ''},
                              {'uuid': '5c30d496-72e6-40ee-aef3-9f27300733f6', 'name': 'Categ2', 'auto': '1', 'color': ''},
                              {'uuid': 'a5c385cb-2328-486e-b200-482efebf8248', 'name': 'Categ3', 'auto': '1', 'color': ''}]}
    requests_mock.get("https://opnsense.mockserver.com/api/firewall/category/searchItem/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = category_list_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Category'
    assert response[0].outputs == [{'uuid': 'cef2c7d7-68d8-41aa-b6b8-1cac38554d58', 'name': 'Categ1', 'auto': '1', 'color': ''},
                                   {'uuid': '5c30d496-72e6-40ee-aef3-9f27300733f6', 'name': 'Categ2', 'auto': '1', 'color': ''},
                                   {'uuid': 'a5c385cb-2328-486e-b200-482efebf8248', 'name': 'Categ3', 'auto': '1', 'color': ''}]


def test_opnsense_category_add(requests_mock):
    from OPNSense import Client, category_add_command
    mock_args = {'name': 'NewCategory', 'auto': '0', 'color': ''}
    mock_response = {'result': 'saved', 'uuid': 'e291bafc-0696-457b-aa97-6377af4a818a'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/category/addItem/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = category_add_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Category'
    assert response[0].outputs == {'result': 'saved', 'uuid': 'e291bafc-0696-457b-aa97-6377af4a818a'}


def test_opnsense_category_del(requests_mock):
    from OPNSense import Client, category_del_command
    mock_args = {'uuid': 'e291bafc-0696-457b-aa97-6377af4a818a'}
    mock_response = {'result': 'deleted'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/category/delItem/e291bafc-0696-457b-aa97-6377af4a818a/",
                       json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = category_del_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Category'
    assert response[0].outputs == {'result': 'deleted'}


def test_opnsense_category_get(requests_mock):
    from OPNSense import Client, category_get_command
    mock_args = {'uuid': 'e291bafc-0696-457b-aa97-6377af4a818a'}
    mock_response = {'category': {'name': 'NewCategory', 'auto': '0', 'color': ''}}
    requests_mock.get("https://opnsense.mockserver.com/api/firewall/category/getItem/e291bafc-0696-457b-aa97-6377af4a818a/",
                      json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = category_get_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Category'
    assert response[0].outputs == {'name': 'NewCategory', 'auto': '0', 'color': ''}


def test_opnsense_category_mod(requests_mock):
    from OPNSense import Client, category_mod_command
    mock_args = {'uuid': '8abfa542-4031-4e63-9ccd-34ffd31886d4', 'name': 'RenamedCategory', 'auto': '0', 'color': ''}
    mock_response = {'category': {'name': 'NewCategory', 'auto': '0', 'color': ''}}
    requests_mock.get("https://opnsense.mockserver.com/api/firewall/category/getItem/8abfa542-4031-4e63-9ccd-34ffd31886d4/",
                      json=mock_response)
    mock_response2 = {'result': 'saved'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/category/setItem/8abfa542-4031-4e63-9ccd-34ffd31886d4/",
                       json=mock_response2)
    client = Client(MOCK_PARAMETERS)
    response = category_mod_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Category'
    assert response[0].outputs == {'result': 'saved'}


def test_opnsense_fw_rule_list(requests_mock):
    from OPNSense import Client, fw_rule_list_command
    mock_response = {'rows': [{'uuid': '443ebf6b-e4d5-4317-84ad-dca961b4821d', 'enabled': '1',
                               'sequence': '1', 'description': 'Rule1'},
                              {'uuid': '443ebf6b-e4d5-4317-84ad-dca961b4821d', 'enabled': '1',
                               'sequence': '1', 'description': 'Rule2'}],
                     'rowCount': 1, 'total': 1, 'current': 1}
    requests_mock.get("https://opnsense.mockserver.com/api/firewall/filter/searchRule/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = fw_rule_list_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Rule'
    assert response[0].outputs == [{'uuid': '443ebf6b-e4d5-4317-84ad-dca961b4821d', 'enabled': '1',
                                    'sequence': '1', 'description': 'Rule1'},
                                   {'uuid': '443ebf6b-e4d5-4317-84ad-dca961b4821d', 'enabled': '1',
                                    'sequence': '1', 'description': 'Rule2'}]


def test_opnsense_fw_rule_get(requests_mock):
    from OPNSense import Client, fw_rule_get_command
    mock_args = {'uuid': 'e37b5bb2-b96f-455a-a2cb-5542103e5ac2'}
    mock_response = util_load_json('test_data/opnsense_rule_get.json')
    requests_mock.get("https://opnsense.mockserver.com/api/firewall/filter/getRule/e37b5bb2-b96f-455a-a2cb-5542103e5ac2/",
                      json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = fw_rule_get_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Rule'
    assert response[0].outputs == util_load_mock('test_data/opnsense_fw_rule_get.res.mock')


def test_opnsense_fw_rule_del(requests_mock):
    from OPNSense import Client, fw_rule_del_command
    mock_args = {'uuid': 'e37b5bb2-b96f-455a-a2cb-5542103e5ac2'}
    mock_response = {'result': 'deleted'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/filter/delRule/e37b5bb2-b96f-455a-a2cb-5542103e5ac2/",
                       json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = fw_rule_del_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Rule'
    assert response[0].outputs == {'result': 'deleted'}


def test_opnsense_fw_rule_add(requests_mock):
    from OPNSense import Client, fw_rule_add_command
    mock_args = {'description': 'MyNew Rule', 'source_net': '192.168.10.0/24', 'dest_net': '192.168.20.0/24',
                 'protocol': 'TCP', 'interface': 'opt1'}
    mock_response = {'result': 'saved', 'uuid': 'e37b5bb2-b96f-455a-a2cb-5542103e5ac2'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/filter/addRule/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = fw_rule_add_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Rule'
    assert response[0].outputs == {'result': 'saved', 'uuid': 'e37b5bb2-b96f-455a-a2cb-5542103e5ac2'}


def test_opnsense_fw_rule_mod(requests_mock):
    from OPNSense import Client, fw_rule_mod_command
    mock_args = {'uuid': 'e37b5bb2-b96f-455a-a2cb-5542103e5ac2', 'description': 'My renamed Rule'}
    mock_response = util_load_json('test_data/opnsense_rule_mod.json')
    requests_mock.get("https://opnsense.mockserver.com/api/firewall/filter/getRule/e37b5bb2-b96f-455a-a2cb-5542103e5ac2/",
                      json=mock_response)
    mock_response2 = {'result': 'saved'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/filter/setRule/e37b5bb2-b96f-455a-a2cb-5542103e5ac2/",
                       json=mock_response2)
    client = Client(MOCK_PARAMETERS)
    response = fw_rule_mod_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Rule'
    assert response[0].outputs == {'result': 'saved'}


def test_opnsense_fw_rule_apply(requests_mock):
    from OPNSense import Client, fw_rule_apply_command
    mock_args = {'rollback_revision': None}
    mock_response = {'status': 'ok'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/filter/apply/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = fw_rule_apply_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Rule'
    assert response[0].outputs == {'status': 'ok'}


def test_opnsense_fw_rule_savepoint(requests_mock):
    from OPNSense import Client, fw_rule_savepoint_command
    mock_response = {'status': 'ok', 'retention': 100, 'revision': '1648740593.4431'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/filter/savepoint/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = fw_rule_savepoint_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Rule'
    assert response[0].outputs == {'status': 'ok', 'retention': 100, 'revision': '1648740593.4431'}


def test_opnsense_fw_rule_revert(requests_mock):
    from OPNSense import Client, fw_rule_revert_command
    mock_args = {'rollback_revision': '1648740593.4431'}
    mock_response = {'status': 'ok'}
    requests_mock.post("https://opnsense.mockserver.com/api/firewall/filter/revert/1648740593.4431/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = fw_rule_revert_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Rule'
    assert response[0].outputs == {'status': 'ok'}


def test_opnsense_device_reboot(requests_mock):
    from OPNSense import Client, device_reboot_command
    mock_response = {'status': 'ok'}
    requests_mock.get("https://opnsense.mockserver.com/api/core/system/reboot/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = device_reboot_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Device'
    assert response[0].outputs == {'status': 'ok'}


def test_opnsense_firmware_info(requests_mock):
    from OPNSense import Client, firmware_info_command
    mock_response = util_load_json('test_data/opnsense_firmware_info.json')
    requests_mock.get("https://opnsense.mockserver.com/api/core/firmware/info/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = firmware_info_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Firmware'
    assert response[0].outputs == util_load_json('test_data/opnsense_firmware_info.json')


def test_opnsense_firmware_status(requests_mock):
    from OPNSense import Client, firmware_status_command
    mock_response = util_load_mock('test_data/opnsense_firmware_status.mock')
    requests_mock.get("https://opnsense.mockserver.com/api/core/firmware/status/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = firmware_status_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Firmware'
    assert response[0].outputs['product_id'] == 'opnsense'


def test_opnsense_firmware_upgradestatus(requests_mock):
    from OPNSense import Client, firmware_upgradestatus_command
    mock_response = util_load_mock('test_data/opnsense_firmware_upgradestatus.mock')
    requests_mock.get("https://opnsense.mockserver.com/api/core/firmware/upgradestatus/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = firmware_upgradestatus_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Firmware'
    assert response[0].outputs['status'] == 'done'


def test_opnsense_firmware_update(requests_mock):
    from OPNSense import Client, firmware_update_command
    mock_response = {'status': 'ok', 'msg_uuid': 'f6dbee27-431f-4574-a017-6823e1a9b631'}
    requests_mock.post("https://opnsense.mockserver.com/api/core/firmware/update", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = firmware_update_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Firmware'
    assert response[0].outputs == {'status': 'ok', 'msg_uuid': 'f6dbee27-431f-4574-a017-6823e1a9b631'}


def test_opnsense_firmware_upgrade(requests_mock):
    from OPNSense import Client, firmware_upgrade_command
    mock_response = {'status': 'ok', 'msg_uuid': 'a55216fb-0877-4c15-ab77-8afb78f4841b'}
    requests_mock.post("https://opnsense.mockserver.com/api/core/firmware/upgrade", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = firmware_upgrade_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Firmware'
    assert response[0].outputs == {'status': 'ok', 'msg_uuid': 'a55216fb-0877-4c15-ab77-8afb78f4841b'}
