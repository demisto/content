"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_mock(path):
    with open(path, 'r') as f:
        return f.readlines()

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
    mock_response = [{'rulenr': '60', 'subrulenr': '', 'anchorname': '', 'rid': 'fae559338f65e11c53669fc3642c93c2', 'interface': 'vmx3', 'reason': 'match', 'action': 'pass', 'dir': 'out', 'ipversion': '4', 'tos': '0x0', 'ecn': '', 'ttl': '63', 'id': '42039', 'offset': '0', 'ipflags': 'DF', 'protonum': '6', 'protoname': 'tcp', 'length': '60', 'src': '1.2.3.4', 'dst': '5.6.7.8', 'srcport': '33158', 'dstport': '10050', 'datalen': '0', 'tcpflags': 'S', 'seq': '4032345221', 'ack': '', 'urp': '64240', 'tcpopts': '', '__timestamp__': '2022-03-28T10:08:50', '__host__': 'myhost.mydomain.com', '__digest__': 'd452650dc383adcb11b493eeb3f98274', '__spec__': ['rulenr', 'subrulenr', 'anchorname', 'rid', 'interface', 'reason', 'action', 'dir', 'ipversion', 'tos', 'ecn', 'ttl', 'id', 'offset', 'ipflags', 'protonum', 'protoname', 'length', 'src', 'dst', 'srcport', 'dstport', 'datalen', 'tcpflags', 'seq', 'ack', 'urp', 'tcpopts'], 'label': 'let out anything from firewall host itself'}, {'rulenr': '60', 'subrulenr': '', 'anchorname': '', 'rid': 'fae559338f65e11c53669fc3642c93c2', 'interface': 'vmx3', 'reason': 'match', 'action': 'pass', 'dir': 'out', 'ipversion': '4', 'tos': '0x0', 'ecn': '', 'ttl': '63', 'id': '28371', 'offset': '0', 'ipflags': 'DF', 'protonum': '6', 'protoname': 'tcp', 'length': '60', 'src': '1.2.3.4', 'dst': '6.7.8.9', 'srcport': '57340', 'dstport': '10050', 'datalen': '0', 'tcpflags': 'S', 'seq': '453090896', 'ack': '', 'urp': '64240', 'tcpopts': '', '__timestamp__': '2022-03-28T10:08:50', '__host__': 'myhost.mydomain.com', '__digest__': '39aac9c9fc8cb9e049b34a14c61cca42', '__spec__': ['rulenr', 'subrulenr', 'anchorname', 'rid', 'interface', 'reason', 'action', 'dir', 'ipversion', 'tos', 'ecn', 'ttl', 'id', 'offset', 'ipflags', 'protonum', 'protoname', 'length', 'src', 'dst', 'srcport', 'dstport', 'datalen', 'tcpflags', 'seq', 'ack', 'urp', 'tcpopts'], 'label': 'let out anything from firewall host itself'}, {'rulenr': '60', 'subrulenr': '', 'anchorname': '', 'rid': 'fae559338f65e11c53669fc3642c93c2', 'interface': 'vmx3', 'reason': 'match', 'action': 'pass', 'dir': 'out', 'ipversion': '4', 'tos': '0x0', 'ecn': '', 'ttl': '63', 'id': '26473', 'offset': '0', 'ipflags': 'DF', 'protonum': '17', 'protoname': 'udp', 'length': '69', 'src': '1.2.3.4', 'dst': '6.7.8.9', 'srcport': '56006', 'dstport': '53', 'datalen': '49', '__timestamp__': '2022-03-28T10:08:50', '__host__': 'myhost.mydomain.com', '__digest__': '890d05592a8e676d4ec163e79cbbc6e2', '__spec__': ['rulenr', 'subrulenr', 'anchorname', 'rid', 'interface', 'reason', 'action', 'dir', 'ipversion', 'tos', 'ecn', 'ttl', 'id', 'offset', 'ipflags', 'protonum', 'protoname', 'length', 'src', 'dst', 'srcport', 'dstport', 'datalen'], 'label': 'let out anything from firewall host itself'}, {'rulenr': '76', 'subrulenr': '', 'anchorname': '', 'rid': 'db5898c5f347c8eecae25ede28e6eed1', 'interface': 'vmx5', 'reason': 'match', 'action': 'pass', 'dir': 'in', 'ipversion': '4', 'tos': '0x0', 'ecn': '', 'ttl': '64', 'id': '26473', 'offset': '0', 'ipflags': 'DF', 'protonum': '17', 'protoname': 'udp', 'length': '69', 'src': '1.2.3.4', 'dst': '6.7.8.9', 'srcport': '56006', 'dstport': '53', 'datalen': '49', '__timestamp__': '2022-03-28T10:08:50', '__host__': 'myhost.mydomain.com', '__digest__': '56a109033b48e844c323d973cc66ed94', '__spec__': ['rulenr', 'subrulenr', 'anchorname', 'rid', 'interface', 'reason', 'action', 'dir', 'ipversion', 'tos', 'ecn', 'ttl', 'id', 'offset', 'ipflags', 'protonum', 'protoname', 'length', 'src', 'dst', 'srcport', 'dstport', 'datalen'], 'label': 'Allow all hosts to reach internal DNS resolver'}, {'rulenr': '60', 'subrulenr': '', 'anchorname': '', 'rid': 'fae559338f65e11c53669fc3642c93c2', 'interface': 'vmx5', 'reason': 'match', 'action': 'pass', 'dir': 'out', 'ipversion': '4', 'tos': '0x0', 'ecn': '', 'ttl': '63', 'id': '60770', 'offset': '0', 'ipflags': 'DF', 'protonum': '6', 'protoname': 'tcp', 'length': '60', 'src': '172.16.0.1', 'dst': '1.2.3.4', 'srcport': '38076', 'dstport': '10051', 'datalen': '0', 'tcpflags': 'S', 'seq': '2403980021', 'ack': '', 'urp': '29200', 'tcpopts': '', '__timestamp__': '2022-03-28T10:08:50', '__host__': 'myhost.mydomain.com', '__digest__': 'b66a13918b2c2cf7a7549c249e2f1682', '__spec__': ['rulenr', 'subrulenr', 'anchorname', 'rid', 'interface', 'reason', 'action', 'dir', 'ipversion', 'tos', 'ecn', 'ttl', 'id', 'offset', 'ipflags', 'protonum', 'protoname', 'length', 'src', 'dst', 'srcport', 'dstport', 'datalen', 'tcpflags', 'seq', 'ack', 'urp', 'tcpopts'], 'label': 'let out anything from firewall host itself'}]
    #mock_response = util_load_mock('test_data/opnsense_logs_search.mock')
    requests_mock.get("https://opnsense.mockserver.com/api/diagnostics/firewall/log/?limit=5", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = logs_search_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.Logs'
    assert response[0].outputs == [{'interface': 'vmx3', 'action': 'pass', 'protoname': 'tcp', 'src': '1.2.3.4', 'dst': '5.6.7.8', 'srcport': '33158', 'dstport': '10050', '__timestamp__': '2022-03-28T10:08:50', 'label': 'let out anything from firewall host itself'}, {'interface': 'vmx3', 'action': 'pass', 'protoname': 'tcp', 'src': '1.2.3.4', 'dst': '6.7.8.9', 'srcport': '57340', 'dstport': '10050', '__timestamp__': '2022-03-28T10:08:50', 'label': 'let out anything from firewall host itself'}, {'interface': 'vmx3', 'action': 'pass', 'protoname': 'udp', 'src': '1.2.3.4', 'dst': '6.7.8.9', 'srcport': '56006', 'dstport': '53', '__timestamp__': '2022-03-28T10:08:50', 'label': 'let out anything from firewall host itself'}, {'interface': 'vmx5', 'action': 'pass', 'protoname': 'udp', 'src': '1.2.3.4', 'dst': '6.7.8.9', 'srcport': '56006', 'dstport': '53', '__timestamp__': '2022-03-28T10:08:50', 'label': 'Allow all hosts to reach internal DNS resolver'}, {'interface': 'vmx5', 'action': 'pass', 'protoname': 'tcp', 'src': '172.16.0.1', 'dst': '1.2.3.4', 'srcport': '38076', 'dstport': '10051', '__timestamp__': '2022-03-28T10:08:50', 'label': 'let out anything from firewall host itself'}]


def test_opnsense_states_search(requests_mock):
    from OPNSense import Client, states_search_command
    mock_args = {'limit': 5}
    mock_response = {'rows': [{'label': '2bddaa30de8995a0bb24da55edbca7f2', 'descr': 'testing query', 'nat_addr': None, 'nat_port': None, 'iface': 'all', 'proto': 'tcp', 'ipproto': 'ipv4', 'direction': 'in', 'dst_addr': '9.8.7.6', 'dst_port': '443', 'src_addr': '1.2.3.5', 'src_port': '44878', 'state': 'ESTABLISHED:ESTABLISHED', 'age': '00:38:29', 'expires': '23:59:51', 'pkts': [2564, 2351], 'bytes': [1349458, 1309707], 'rule': '126', 'id': '0006466200000003/ef725303', 'interface': 'all'}, {'label': '6523ac6b61c83be8af3e7b0710cb5685', 'descr': 'ma plus belle rule', 'nat_addr': '10.0.30.1', 'nat_port': '44878', 'iface': 'all', 'proto': 'tcp', 'ipproto': 'ipv4', 'direction': 'out', 'dst_addr': '12.5.6.4', 'dst_port': '443', 'src_addr': '6.7.8.9', 'src_port': '33278', 'state': 'ESTABLISHED:ESTABLISHED', 'age': '00:38:29', 'expires': '23:59:51', 'pkts': [2564, 2351], 'bytes': [1349458, 1309707], 'rule': '63', 'id': '0106466200000003/ef725303', 'interface': 'all'}, {'label': '0b9caaabaeea5dbeac41ab1c3141c09a', 'descr': 'Allow any output without filtering for Albea scanning', 'nat_addr': None, 'nat_port': None, 'iface': 'all', 'proto': 'tcp', 'ipproto': 'ipv4', 'direction': 'in', 'dst_addr': '1.2.3.4', 'dst_port': '443', 'src_addr': '1.2.3.4', 'src_port': '33144', 'state': 'ESTABLISHED:ESTABLISHED', 'age': '00:29:24', 'expires': '23:55:46', 'pkts': [1582, 1519], 'bytes': [903958, 887372], 'rule': '129', 'id': '2c0a466200000003/ef725303', 'interface': 'all'}, {'label': '6523ac6b61c83be8af3e7b0710cb5685', 'descr': 'ma plus belle rule', 'nat_addr': '10.0.10.1', 'nat_port': '33144', 'iface': 'all', 'proto': 'tcp', 'ipproto': 'ipv4', 'direction': 'out', 'dst_addr': '4.5.6.7', 'dst_port': '443', 'src_addr': '5.6.7.8', 'src_port': '18472', 'state': 'ESTABLISHED:ESTABLISHED', 'age': '00:29:24', 'expires': '23:55:46', 'pkts': [1582, 1519], 'bytes': [903958, 887372], 'rule': '63', 'id': '2d0a466200000003/ef725303', 'interface': 'all'}, {'label': 'c40f27236a328bb02bf42effd30b2600', 'descr': 'Allow https access from XSOAR', 'nat_addr': None, 'nat_port': None, 'iface': 'all', 'proto': 'tcp', 'ipproto': 'ipv4', 'direction': 'in', 'dst_addr': '1.2.3.4', 'dst_port': '3128', 'src_addr': '1.2.3.4', 'src_port': '44886', 'state': 'FIN_WAIT_2:ESTABLISHED', 'age': '00:19:51', 'expires': '00:05:15', 'pkts': [13, 12], 'bytes': [1715, 6861], 'rule': '70', 'id': '230f466200000003/ef725303', 'interface': 'all'}], 'rowCount': 955, 'total': 955, 'current': 1}
    requests_mock.post("https://opnsense.mockserver.com/api/diagnostics/firewall/queryStates/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = states_search_command(client, mock_args)
    assert response[0].outputs_prefix == 'OPNSense.States'
    assert response[0].outputs == [{'label': '2bddaa30de8995a0bb24da55edbca7f2', 'descr': 'testing query', 'nat_addr': None, 'nat_port': None, 'iface': 'all', 'proto': 'tcp', 'ipproto': 'ipv4', 'direction': 'in', 'dst_addr': '9.8.7.6', 'dst_port': '443', 'src_addr': '1.2.3.5', 'src_port': '44878', 'state': 'ESTABLISHED:ESTABLISHED', 'age': '00:38:29', 'expires': '23:59:51', 'pkts': [2564, 2351], 'bytes': [1349458, 1309707], 'rule': '126', 'id': '0006466200000003/ef725303', 'interface': 'all'}, {'label': '6523ac6b61c83be8af3e7b0710cb5685', 'descr': 'ma plus belle rule', 'nat_addr': '10.0.30.1', 'nat_port': '44878', 'iface': 'all', 'proto': 'tcp', 'ipproto': 'ipv4', 'direction': 'out', 'dst_addr': '12.5.6.4', 'dst_port': '443', 'src_addr': '6.7.8.9', 'src_port': '33278', 'state': 'ESTABLISHED:ESTABLISHED', 'age': '00:38:29', 'expires': '23:59:51', 'pkts': [2564, 2351], 'bytes': [1349458, 1309707], 'rule': '63', 'id': '0106466200000003/ef725303', 'interface': 'all'}, {'label': '0b9caaabaeea5dbeac41ab1c3141c09a', 'descr': 'Allow any output without filtering for Albea scanning', 'nat_addr': None, 'nat_port': None, 'iface': 'all', 'proto': 'tcp', 'ipproto': 'ipv4', 'direction': 'in', 'dst_addr': '1.2.3.4', 'dst_port': '443', 'src_addr': '1.2.3.4', 'src_port': '33144', 'state': 'ESTABLISHED:ESTABLISHED', 'age': '00:29:24', 'expires': '23:55:46', 'pkts': [1582, 1519], 'bytes': [903958, 887372], 'rule': '129', 'id': '2c0a466200000003/ef725303', 'interface': 'all'}, {'label': '6523ac6b61c83be8af3e7b0710cb5685', 'descr': 'ma plus belle rule', 'nat_addr': '10.0.10.1', 'nat_port': '33144', 'iface': 'all', 'proto': 'tcp', 'ipproto': 'ipv4', 'direction': 'out', 'dst_addr': '4.5.6.7', 'dst_port': '443', 'src_addr': '5.6.7.8', 'src_port': '18472', 'state': 'ESTABLISHED:ESTABLISHED', 'age': '00:29:24', 'expires': '23:55:46', 'pkts': [1582, 1519], 'bytes': [903958, 887372], 'rule': '63', 'id': '2d0a466200000003/ef725303', 'interface': 'all'}, {'label': 'c40f27236a328bb02bf42effd30b2600', 'descr': 'Allow https access from XSOAR', 'nat_addr': None, 'nat_port': None, 'iface': 'all', 'proto': 'tcp', 'ipproto': 'ipv4', 'direction': 'in', 'dst_addr': '1.2.3.4', 'dst_port': '3128', 'src_addr': '1.2.3.4', 'src_port': '44886', 'state': 'FIN_WAIT_2:ESTABLISHED', 'age': '00:19:51', 'expires': '00:05:15', 'pkts': [13, 12], 'bytes': [1715, 6861], 'rule': '70', 'id': '230f466200000003/ef725303', 'interface': 'all'}]


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
    assert response[0].outputs == {'enabled': '1', 'sequence': '1', 'action': 'pass', 'quick': '1', 'interface': 'opt1', 'direction': 'in', 'ipprotocol': 'inet', 'protocol': 'any', 'source_net': '1.2.3.4', 'source_not': '0', 'source_port': '', 'destination_net': '5.6.7.8', 'destination_not': '0', 'destination_port': '', 'gateway': '', 'log': '0', 'description': 'NewRule'}


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
    mock_response = {'product': {'product_abi': '22.1', 'product_arch': 'amd64', 'product_check': None, 'product_copyright_owner': 'Deciso B.V.', 'product_copyright_url': 'https://www.deciso.com/', 'product_copyright_years': '2014-2022', 'product_crypto': 'OpenSSL', 'product_email': 'project@opnsense.org', 'product_flavour': 'OpenSSL', 'product_hash': '1aa77c16b', 'product_id': 'opnsense', 'product_latest': '22.1.4_1', 'product_mirror': 'https://pkg.opnsense.org/FreeBSD:13:amd64/22.1', 'product_name': 'OPNsense', 'product_nickname': 'Observant Owl', 'product_repos': 'OPNsense', 'product_series': '22.1', 'product_time': 'Thu Mar 31 17:44:06 CEST 2022', 'product_version': '22.1.4_1', 'product_website': 'https://opnsense.org/'}, 'status_msg': 'Firmware status requires to check for update first to provide more information.', 'status': 'none'}
    requests_mock.get("https://opnsense.mockserver.com/api/core/firmware/status/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = firmware_status_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Firmware'
    assert response[0].outputs['product_id'] == 'opnsense'


def test_opnsense_firmware_upgradestatus(requests_mock):
    from OPNSense import Client, firmware_upgradestatus_command
    mock_response = {'status': 'done', 'log': '***GOT REQUEST TO UPDATE***\nCurrently running OPNsense 22.1.4_1 (amd64/OpenSSL) at Fri Apr  1 10:30:54 CEST 2022\nUpdating OPNsense repository catalogue...\nOPNsense repository is up to date.\nAll repositories are up to date.\nUpdating OPNsense repository catalogue...\nOPNsense repository is up to date.\nAll repositories are up to date.\nChecking for upgrades (0 candidates): . done\nProcessing candidates (0 candidates): . done\nChecking integrity... done (0 conflicting)\nYour packages are up to date.\nChecking integrity... done (0 conflicting)\nNothing to do.\nChecking all packages: .......... done\nNothing to do.\nNothing to do.\nStarting web GUI...done.\nGenerating RRD graphs...done.\n***DONE***'}
    requests_mock.get("https://opnsense.mockserver.com/api/core/firmware/upgradestatus/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = firmware_upgradestatus_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Firmware'
    assert response[0].outputs['status'] == 'done'


def test_opnsense_firmware_update(requests_mock):
    from OPNSense import Client, firmware_update_command
    mock_response = {'status': 'ok', 'msg_uuid': 'f6dbee27-431f-4574-a017-6823e1a9b631'}
    requests_mock.post("https://opnsense.mockserver.com/api/core/firmware/update/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = firmware_update_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Firmware'
    assert response[0].outputs == {'status': 'ok', 'msg_uuid': 'f6dbee27-431f-4574-a017-6823e1a9b631'}


def test_opnsense_firmware_upgrade(requests_mock):
    from OPNSense import Client, firmware_upgrade_command
    mock_response = {'status': 'ok', 'msg_uuid': 'a55216fb-0877-4c15-ab77-8afb78f4841b'}
    requests_mock.post("https://opnsense.mockserver.com/api/core/firmware/upgrade/", json=mock_response)
    client = Client(MOCK_PARAMETERS)
    response = firmware_upgrade_command(client)
    assert response[0].outputs_prefix == 'OPNSense.Firmware'
    assert response[0].outputs == {'status': 'ok', 'msg_uuid': 'a55216fb-0877-4c15-ab77-8afb78f4841b'}
