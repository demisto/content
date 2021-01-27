import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_checkpoint_list_hosts_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_list_hosts_command
    mock_response = util_load_json('test_data/list_host_response.json')
    mocked_client = mocker.Mock()
    mocked_client.list_hosts.return_value = mock_response

    result = checkpoint_list_hosts_command(mocked_client, 50, 0).outputs
    assert result[0].get('name') == 'list 1'
    assert result[0].get('uid') == '123'
    assert result[0].get('type') == 'host'
    assert len(result[0]) == 10


def test_checkpoint_get_host_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_get_host_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/get_host_response.json')
    mocked_client.get_host.return_value = mock_response
    result = checkpoint_get_host_command(mocked_client, 'host 1').outputs
    assert result.get('name') == 'host 1'
    assert result.get('uid') == '1234'
    assert result.get('type') == 'host'
    assert len(result) == 7


def test_checkpoint_add_host_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_add_host_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/add_host_response.json')
    mocked_client.add_host.return_value = mock_response
    result = checkpoint_add_host_command(mocked_client, 'host 1', '1.2.3.4').outputs
    assert result.get('name') == 'add host'
    assert result.get('uid') == '123'
    assert result.get('type') == 'host'
    assert len(result) == 12


def test_checkpoint_update_host_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_update_host_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/update_host_response.json')
    mocked_client.update_host.return_value = mock_response
    result = checkpoint_update_host_command(mocked_client, 'host 1', False, False).outputs
    assert result.get('name') == 'update host'
    assert result.get('uid') == '123'
    assert result.get('type') == 'host'
    assert len(result) == 11


def test_checkpoint_delete_host_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_delete_host_command
    mocked_client = mocker.Mock()
    mocked_client.delete_host.return_value = util_load_json('test_data/delete_object.json')
    result = checkpoint_delete_host_command(mocked_client, 'host 1').outputs
    assert result.get('message') == 'OK'
    assert mocked_client.delete_host.call_args[0][0] == 'host 1'


def test_checkpoint_list_groups_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_list_groups_command
    mock_response = util_load_json('test_data/list_groups.json')
    mocked_client = mocker.Mock()
    mocked_client.list_groups.return_value = mock_response
    result = checkpoint_list_groups_command(mocked_client, 2, 0).outputs
    assert result[0].get('name') == 'group1'
    assert result[0].get('uid') == '123'
    assert result[0].get('type') == 'group'
    assert len(result[0]) == 4


def test_checkpoint_get_group_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_get_group_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/get_group.json')
    mocked_client.get_group.return_value = mock_response
    result = checkpoint_get_group_command(mocked_client, 'group_test').outputs
    assert result.get('name') == 'group_test'


def test_checkpoint_add_group_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_add_group_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/add_group.json')
    mocked_client.add_group.return_value = mock_response
    result = checkpoint_add_group_command(mocked_client, 'groupi').outputs
    assert result.get('name') == 'groupi'
    assert result.get('uid') == '1234'
    assert result.get('type') == 'group'
    assert len(result) == 12


def test_checkpoint_update_group_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_update_group_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/update_group.json')
    mocked_client.update_group.return_value = mock_response
    result = checkpoint_update_group_command(mocked_client, 'groupi', False, False).outputs
    assert result.get('name') == 'group_test'
    assert result.get('uid') == '1234'
    assert result.get('type') == 'group'
    assert len(result) == 9


def test_checkpoint_delete_group_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_delete_group_command
    mocked_client = mocker.Mock()
    mocked_client.delete_group.return_value = util_load_json('test_data/delete_object.json')
    result = checkpoint_delete_group_command(mocked_client, 'group').outputs
    assert result.get('message') == 'OK'


def test_checkpoint_list_application_site_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_list_application_site_command
    mock_response = util_load_json('test_data/list_application_site.json')
    mocked_client = mocker.Mock()
    mocked_client.list_application_site.return_value = mock_response
    result = checkpoint_list_application_site_command(mocked_client, 2, 0).outputs
    assert result[0].get('name') == 'application site 1'
    assert result[0].get('uid') == '1234'
    assert result[0].get('type') == 'application-site'
    assert len(result[0]) == 3


def test_checkpoint_add_application_site_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_add_application_site_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/add_application_site.json')
    mocked_client.add_application_site.return_value = mock_response
    result = checkpoint_add_application_site_command(mocked_client, 'application1',
                                                     'Test Category', 'qmasters.co').outputs
    assert result.get('name') == 'application1'
    assert result.get('uid') == '1234'
    assert result.get('url-list') == ['qmasters.co']
    assert result.get('type') == 'application-site'
    assert len(result) == 12


def test_checkpoint_update_application_site_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_update_application_site_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/update_application_site.json')
    mocked_client.update_application_site.return_value = mock_response
    result = checkpoint_update_application_site_command(mocked_client, 'app1', False).outputs
    assert result.get('name') == 'application1'
    assert result.get('uid') == '1234'
    assert result.get('url-list') == ['paloaltonetworks.com']
    assert result.get('type') == 'application-site'
    assert len(result) == 11


def test_checkpoint_delete_application_site_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_delete_application_site_command
    mocked_client = mocker.Mock()
    mocked_client.delete_application_site.return_value = util_load_json('test_data/delete_object.json')
    result = checkpoint_delete_application_site_command(mocked_client, 'application1').outputs
    assert result.get('message') == 'OK'


def test_checkpoint_list_address_range_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_list_address_range_command
    mock_response = util_load_json('test_data/list_address_range.json')
    mocked_client = mocker.Mock()
    mocked_client.list_address_ranges.return_value = mock_response
    result = checkpoint_list_address_range_command(mocked_client, 2, 0).outputs
    assert result[0].get('name') == 'address_range_test_1'
    assert result[0].get('uid') == '1234'
    assert result[0].get('type') == 'address-range'
    assert len(result[0]) == 3


def test_checkpoint_get_address_range_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_get_address_range_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/get_address_range.json')
    mocked_client.get_address_range.return_value = mock_response
    result = checkpoint_get_address_range_command(mocked_client, 'address_range_1').outputs
    assert result.get('name') == 'address_range_1'


def test_checkpoint_add_address_range_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_add_address_range_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/add_address_range.json')
    mocked_client.add_address_range.return_value = mock_response
    result = checkpoint_add_address_range_command(mocked_client, 'address_range_1',
                                                  '255.255.255.32', '255.255.255.64', False,
                                                  False, False).outputs
    assert result.get('name') == 'address_range_1'
    assert result.get('uid') == '1234'
    assert result.get('type') == 'address-range'
    assert len(result) == 13


def test_checkpoint_update_address_range_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_update_address_range_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/update_address_range.json')
    mocked_client.update_address_range.return_value = mock_response
    result = checkpoint_update_address_range_command(mocked_client, 'address_range_1',
                                                     False, False).outputs
    assert result.get('name') == 'address_range_1'
    assert result.get('uid') == '1234'
    assert result.get('type') == 'address-range'
    assert len(result) == 11


def test_checkpoint_delete_address_range_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_delete_address_range_command
    mocked_client = mocker.Mock()
    mocked_client.delete_address_range.return_value = util_load_json('test_data/delete_object.json')
    result = checkpoint_delete_address_range_command(mocked_client, 'address_range_1').outputs
    assert result.get('message') == 'OK'


def test_checkpoint_list_threat_indicator_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_list_threat_indicator_command
    mock_response = util_load_json('test_data/list_threat_indicator.json')
    mocked_client = mocker.Mock()
    mocked_client.list_threat_indicators.return_value = mock_response
    result = checkpoint_list_threat_indicator_command(mocked_client, 5, 0).outputs
    assert result[2].get('name') == 'threat_indicator_3'
    assert result[2].get('uid') == '9101'
    assert result[2].get('type') == 'threat-indicator'
    assert len(result[2]) == 3


def test_checkpoint_get_threat_indicator_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_get_threat_indicator_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/get_threat_indicator.json')
    mocked_client.get_threat_indicator.return_value = mock_response
    result = checkpoint_get_threat_indicator_command(mocked_client, 'threat_indicator_1').outputs
    assert result.get('name') == 'threat_indicator_1'


def test_checkpoint_add_threat_indicator_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_add_threat_indicator_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/add_threat_indicator.json')
    mocked_client.add_threat_indicator.return_value = mock_response
    result = checkpoint_add_threat_indicator_command(mocked_client, 'threat_indicator_1',
                                                     []).outputs
    assert result.get('task-id') == '123456789'


def test_checkpoint_update_threat_indicator_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_update_threat_indicator_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/update_threat_indicator.json')
    mocked_client.update_threat_indicator.return_value = mock_response
    result = checkpoint_update_threat_indicator_command(mocked_client, 'address_range_1').outputs
    assert result.get('name') == 'threat_indicator_1'
    assert result.get('uid') == '1234'
    assert result.get('type') == 'threat-indicator'
    assert len(result) == 11


def test_checkpoint_delete_threat_indicator_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_delete_threat_indicator_command
    mocked_client = mocker.Mock()
    mocked_client.delete_threat_indicator.return_value = util_load_json('test_data/delete_object.json')
    result = checkpoint_delete_threat_indicator_command(mocked_client, 'threat_indicator_1').outputs
    assert result.get('message') == 'OK'


def test_checkpoint_list_access_rule_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_list_access_rule_command
    mock_response = util_load_json('test_data/list_access_rule.json')
    mocked_client = mocker.Mock()
    mocked_client.list_access_rule.return_value = mock_response
    result = checkpoint_list_access_rule_command(mocked_client, 'Networks', 1, 0).outputs
    assert result[0].get('name') == 'access_rule_1'
    assert result[0].get('uid') == '1234'
    assert result[0].get('type') == 'access-rule'
    assert len(result[0]) == 3


def test_checkpoint_add_access_rule_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_add_access_rule_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/add_access_rule.json')
    mocked_client.add_rule.return_value = mock_response
    result = checkpoint_add_access_rule_command(mocked_client, 'access_rule_1',
                                                'Network', 'top').outputs
    assert result.get('uid') == '1234'
    assert result.get('type') == 'access-rule'
    assert len(result) == 10


def test_checkpoint_update_access_rule_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_update_access_rule_command
    mocked_client = mocker.Mock()
    mock_response = util_load_json('test_data/update_access_rule.json')
    mocked_client.update_rule.return_value = mock_response
    result = checkpoint_update_access_rule_command(mocked_client, 'access_rule_1', 'Network',
                                                   False, False, False).outputs
    assert result.get('name') == 'access_rule_1'
    assert result.get('uid') == '1234'
    assert result.get('type') == 'access-rule'
    assert len(result) == 13


def test_checkpoint_delete_access_rule_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_delete_access_rule_command
    mocked_client = mocker.Mock()
    mocked_client.delete_rule.return_value = util_load_json('test_data/delete_object.json')
    result = checkpoint_delete_access_rule_command(mocked_client, 'access_rule_1', 'Network').outputs
    assert result.get('message') == 'OK'


def test_publish_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_publish_command
    mocked_client = mocker.Mock()
    mocked_client.publish.return_value = util_load_json('test_data/publish.json')
    result = checkpoint_publish_command(mocked_client).outputs
    assert result.get('task-id') == "01234567"


def test_show_task_command(mocker):
    from CheckPointFirewall_v2 import checkpoint_show_task_command
    mocked_client = mocker.Mock()
    mocked_client.show_task.return_value = util_load_json('test_data/show_task.json')
    result = checkpoint_show_task_command(mocked_client, '01234567').outputs
    assert result[0].get('task-id') == "01234567"
    assert result[0].get("task-name") == "Publish operation"
    assert result[0].get("status") == "succeeded"
    assert result[0].get("progress-percentage") == 100
