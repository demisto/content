import json
import io

MOCK_EMPTY_RESPONSE = {"kind": "tm:asm:policies:host-names:host-namecollectionstate",
                       "selfLink": "https://localhost/mgmt/tm/asm/policies/0000/host-names",
                       "totalItems": 0,
                       "items": []
                       }


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_f5_get_md5_command(mocker):
    from F5_ASM import f5_get_policy_md5_command
    mocked_client = mocker.Mock()
    mocked_client.get_policy_md5.return_value = util_load_json('test_data/get_md5.json')
    result = f5_get_policy_md5_command(mocked_client, 'Test_Policy').outputs
    assert result.get('md5') == 'md5-4321'


def test_f5_create_policy_command(mocker):
    from F5_ASM import f5_create_policy_command
    mocked_client = mocker.Mock()
    mocked_client.create_policy.return_value = util_load_json('test_data/create_policy.json')
    result = f5_create_policy_command(mocked_client, 'New_Policy', 'parent', 'transparent', False).outputs
    assert result.get('name') == 'New_Policy'
    assert result.get('id') == '0000'
    assert result.get('description') == 'This is a description!'


def test_f5_apply_policy_command(mocker):
    from F5_ASM import f5_apply_policy_command
    mocked_client = mocker.Mock()
    mocked_client.apply_policy.return_value = util_load_json('test_data/apply_policy.json')
    result = f5_apply_policy_command(mocked_client, 'https://New_Policy.com').outputs
    assert result.get('status') == 'NEW'
    assert result.get('id') == '0000'


def test_f5_export_policy_command(mocker):
    from F5_ASM import f5_export_policy_command
    mocked_client = mocker.Mock()
    mocked_client.export_policy.return_value = util_load_json('test_data/export_policy.json')
    result = f5_export_policy_command(mocked_client, 'exported_file.xml', 'https://New_Policy.com', False).outputs
    assert result.get('status') == 'NEW'
    assert result.get('id') == '0000'


def test_f5_delete_policy_command(mocker):
    from F5_ASM import f5_delete_policy_command
    mocked_client = mocker.Mock()
    mocked_client.delete_policy.return_value = util_load_json('test_data/delete_policy.json')
    result = f5_delete_policy_command(mocked_client, 'policy_md5').outputs
    assert result.get('name') == 'New_Policy'
    assert result.get('id') == '0000'


def test_f5_list_policies_command(mocker):
    from F5_ASM import f5_list_policies_command
    mocked_client = mocker.Mock()
    mocked_client.list_policies.return_value = MOCK_EMPTY_RESPONSE
    assert f5_list_policies_command(mocked_client).outputs == []

    mocked_client.list_policies.return_value = util_load_json('test_data/list_policies.json')
    result = f5_list_policies_command(mocked_client).outputs
    assert result[0].get('name') == 'Test_Policy'
    assert result[0].get('id') == '1234'
    assert result[1].get('name') == 'Common_copy_2'
    assert result[1].get('id') == '9876'


def test_f5_list_policy_methods_command(mocker):
    from F5_ASM import f5_list_policy_methods_command
    mocked_client = mocker.Mock()
    mocked_client.list_policy_methods.return_value = util_load_json('test_data/list_methods.json')
    result = f5_list_policy_methods_command(mocked_client, '0000').outputs
    assert result[0].get('name') == 'posty'


def test_f5_add_policy_methods_command(mocker):
    from F5_ASM import f5_add_policy_method_command
    mocked_client = mocker.Mock()
    mocked_client.add_policy_method.return_value = util_load_json('test_data/add_methods.json')
    result = f5_add_policy_method_command(mocked_client, '0000', 'posty', 'POST').outputs
    assert result.get('name') == 'posty'
    assert result.get('id') == 'md5-1234'
    assert result.get('actAsMethod') == 'POST'


def test_f5_update_policy_methods_command(mocker):
    from F5_ASM import f5_update_policy_method_command
    mocked_client = mocker.Mock()
    mocked_client.update_policy_method.return_value =\
        util_load_json('test_data/update_methods.json')
    result = f5_update_policy_method_command(mocked_client, '0000', 'id123', 'posty', 'GET').outputs
    assert result.get('name') == 'posty'
    assert result.get('id') == 'md5-1234'
    assert result.get('actAsMethod') == 'GET'


def test_f5_delete_policy_methods_command(mocker):
    from F5_ASM import f5_delete_policy_method_command
    mocked_client = mocker.Mock()
    mocked_client.delete_policy_method.return_value =\
        util_load_json('test_data/delete_methods.json')
    result = f5_delete_policy_method_command(mocked_client, '0000', 'id123', 'posty').outputs
    assert result.get('name') == 'posty'
    assert result.get('id') == 'md5-1234'
    assert result.get('actAsMethod') == 'GET'


def test_f5_list_policy_file_types_command(mocker):
    from F5_ASM import f5_list_policy_file_types_command
    mocked_client = mocker.Mock()
    mocked_client.list_policy_file_types.return_value = util_load_json('test_data/list_file_types.json')
    result = f5_list_policy_file_types_command(mocked_client, '0000').outputs
    assert result[0].get('name') == 'csv'


def test_f5_add_policy_file_types_command(mocker):
    from F5_ASM import f5_add_policy_file_type_command
    mocked_client = mocker.Mock()
    mocked_client.add_policy_file_type.return_value =\
        util_load_json('test_data/add_file_type.json')
    result = f5_add_policy_file_type_command(mocked_client, '0000', 'cs', 100, True, True,
                                             True, 100, True).outputs
    assert result.get('name') == 'cs'
    assert result.get('id') == 'md5-1234'


def test_f5_update_policy_file_types_command(mocker):
    from F5_ASM import f5_update_policy_file_type_command
    mocked_client = mocker.Mock()
    mocked_client.update_policy_file_type.return_value = util_load_json('test_data/update_file_type.json')
    result = f5_update_policy_file_type_command(mocked_client, '0000', 'id123', 'cs', 100, True, True,
                                                True, 100, True).outputs
    assert result.get('name') == 'cs'
    assert result.get('id') == 'md5-1234'


def test_f5_delete_policy_file_types_command(mocker):
    from F5_ASM import f5_delete_policy_file_type_command
    mocked_client = mocker.Mock()
    mocked_client.delete_policy_file_type.return_value = util_load_json('test_data/delete_file_type.json')
    result = f5_delete_policy_file_type_command(mocked_client, '0000', 'id123', 'cs').outputs
    assert result.get('name') == 'cs'
    assert result.get('id') == 'md5-1234'


def test_f5_list_policy_cookies_command(mocker):
    from F5_ASM import f5_list_policy_cookies_command
    mocked_client = mocker.Mock()
    mocked_client.list_policy_cookies.return_value = util_load_json('test_data/list_cookies.json')
    result = f5_list_policy_cookies_command(mocked_client, '0000').outputs
    assert result[0].get('name') == 'yummy'
    assert result[0].get('id') == 'cookie-md5'
    assert result[1].get('name') == 'cookie'
    assert result[1].get('id') == 'cookie-md5-2'


def test_f5_add_policy_cookie_command(mocker):
    from F5_ASM import f5_add_policy_cookie_command
    mocked_client = mocker.Mock()
    mocked_client.add_policy_cookie.return_value = util_load_json('test_data/add_cookie.json')
    result = f5_add_policy_cookie_command(mocked_client, '0000', 'new_cookie', True, 'wildcard', 'allow', True).outputs
    assert result.get('name') == 'new_cookie'
    assert result.get('id') == 'cookie-md5'


def test_f5_update_policy_cookie_command(mocker):
    from F5_ASM import f5_update_policy_cookie_command
    mocked_client = mocker.Mock()
    mocked_client.update_policy_cookie.return_value = util_load_json('test_data/update_cookie.json')
    result = f5_update_policy_cookie_command(mocked_client, '0000', 'id123', 'new_cookie', True, 'wildcard',
                                             'allow', True).outputs
    assert result.get('name') == 'new_cookie'
    assert result.get('id') == 'cookie-md5'


def test_f5_delete_policy_cookie_command(mocker):
    from F5_ASM import f5_delete_policy_cookie_command
    mocked_client = mocker.Mock()
    mocked_client.delete_policy_cookie.return_value = util_load_json('test_data/delete_cookie.json')
    result = f5_delete_policy_cookie_command(mocked_client, '0000', 'id123', 'new_cookie').outputs
    assert result.get('name') == 'new_cookie'
    assert result.get('id') == 'cookie-md5'


def test_f5_list_policy_hostname_command(mocker):
    from F5_ASM import f5_list_policy_hostnames_command
    mocked_client = mocker.Mock()
    mocked_client.list_policy_hostnames.return_value = util_load_json('test_data/list_hostname.json')
    result = f5_list_policy_hostnames_command(mocked_client, '0000').outputs
    assert result[0].get('name') == 'example.com'
    assert result[0].get('id') == 'hostname-md5-1'
    assert result[1].get('name') == 'qmasters.co.il'
    assert result[1].get('id') == 'hostname-md5-2'


def test_f5_add_policy_hostname_command(mocker):
    from F5_ASM import f5_add_policy_hostname_command
    mocked_client = mocker.Mock()
    mocked_client.add_policy_hostname.return_value = util_load_json('test_data/add_hostname.json')
    result = f5_add_policy_hostname_command(mocked_client, '0000', 'example.co.il', True).outputs
    assert result.get('name') == 'example.co.il'
    assert result.get('id') == 'hostname-md5'


def test_f5_update_policy_hostname_command(mocker):
    from F5_ASM import f5_update_policy_hostname_command
    mocked_client = mocker.Mock()
    mocked_client.update_policy_hostname.return_value = util_load_json('test_data/update_hostname.json')
    result = f5_update_policy_hostname_command(mocked_client, '0000', 'id123', 'example.co.il', True).outputs
    assert result.get('name') == 'example.co.il'
    assert result.get('id') == 'hostname-md5'


def test_f5_delete_policy_hostname_command(mocker):
    from F5_ASM import f5_delete_policy_hostname_command
    mocked_client = mocker.Mock()
    mocked_client.delete_policy_hostname.return_value = util_load_json('test_data/delete_hostname.json')
    result = f5_delete_policy_hostname_command(mocked_client, '0000', 'id123', 'example.co.il').outputs
    assert result.get('name') == 'example.co.il'
    assert result.get('id') == 'hostname-md5'


def test_f5_list_policy_urls_command(mocker):
    from F5_ASM import f5_list_policy_urls_command
    mocked_client = mocker.Mock()
    mocked_client.list_policy_urls.return_value = util_load_json('test_data/list_urls.json')
    result = f5_list_policy_urls_command(mocked_client, '0000').outputs
    assert result[0].get('name') == '/http_example_1'
    assert result[0].get('id') == 'url-md5-1'
    assert result[1].get('name') == '/http_example_2'
    assert result[1].get('id') == 'url-md5-2'


def test_f5_add_policy_url_command(mocker):
    from F5_ASM import f5_add_policy_url_command
    mocked_client = mocker.Mock()
    mocked_client.add_policy_url.return_value = util_load_json('test_data/add_url.json')
    result = f5_add_policy_url_command(mocked_client, '0000', 'new_url', 'http', 'Explicit', True).outputs
    assert result.get('name') == '/new_url'
    assert result.get('id') == 'url-md5'


def test_f5_update_policy_url_command(mocker):
    from F5_ASM import f5_update_policy_url_command
    mocked_client = mocker.Mock()
    mocked_client.update_policy_url.return_value = util_load_json('test_data/update_url.json')
    result = f5_update_policy_url_command(mocked_client, '0000', 'id123', 'new_url', True).outputs
    assert result.get('name') == '/new_url'
    assert result.get('id') == 'url-md5'


def test_f5_delete_policy_url_command(mocker):
    from F5_ASM import f5_delete_policy_url_command
    mocked_client = mocker.Mock()
    mocked_client.delete_policy_url.return_value = util_load_json('test_data/delete_url.json')
    result = f5_delete_policy_url_command(mocked_client, '0000', 'id123', 'new_url').outputs
    assert result.get('name') == '/new_url'
    assert result.get('id') == 'url-md5'


def test_f5_list_policy_gwt_profiles_command(mocker):
    from F5_ASM import f5_list_policy_gwt_profiles_command
    mocked_client = mocker.Mock()
    mocked_client.list_policy_gwt_profiles.return_value = MOCK_EMPTY_RESPONSE
    result = f5_list_policy_gwt_profiles_command(mocked_client, 'unimportant').to_context()
    result = result.get('HumanReadable')
    assert 'No results' in result

    # adding fields to BASIC_FIELDS after previus test emptied this list.
    LIST_FIELDS = ['name', 'id', 'selfLink', 'lastUpdateMicros', 'type', 'protocol', 'method']  # noqa: F841

    mocked_client.list_policy_gwt_profiles.return_value = util_load_json('test_data/list_GWT.json')
    result = f5_list_policy_gwt_profiles_command(mocked_client, 'unimportant').outputs
    assert result[0].get('name') == 'test-GWT'
    assert result[0].get('id') == 'GWT-md5'


def test_f5_add_policy_gwt_profile_command(mocker):
    from F5_ASM import f5_add_policy_gwt_profile_command
    mocked_client = mocker.Mock()
    mocked_client.add_policy_gwt_profile.return_value = util_load_json('test_data/CUD_GWT.json')
    result = f5_add_policy_gwt_profile_command(mocked_client, '0000', 'GWT_test', '100', '100').outputs
    assert result.get('name') == 'GWT_test'
    assert result.get('id') == 'GWT-md5'


def test_f5_update_policy_gwt_profile_command(mocker):
    from F5_ASM import f5_update_policy_gwt_profile_command
    mocked_client = mocker.Mock()
    mocked_client.update_policy_gwt_profile.return_value = util_load_json('test_data/CUD_GWT.json')
    result = f5_update_policy_gwt_profile_command(mocked_client, '0000', 'id123', 'GWT_test', '100', '100').outputs
    assert result.get('name') == 'GWT_test'
    assert result.get('id') == 'GWT-md5'


def test_f5_delete_policy_gwt_profile_command(mocker):
    from F5_ASM import f5_delete_policy_gwt_profile_command
    mocked_client = mocker.Mock()
    mocked_client.delete_policy_gwt_profile.return_value = util_load_json('test_data/CUD_GWT.json')
    result = f5_delete_policy_gwt_profile_command(mocked_client, '0000', 'id123', 'GWT_test').outputs
    assert result.get('name') == 'GWT_test'
    assert result.get('id') == 'GWT-md5'


def test_f5_list_policy_parameters_command(mocker):
    from F5_ASM import f5_list_policy_parameters_command
    mocked_client = mocker.Mock()
    mocked_client.list_policy_parameters.return_value = MOCK_EMPTY_RESPONSE
    result = f5_list_policy_parameters_command(mocked_client, 'unimportant').to_context()
    result = result.get('HumanReadable')
    assert 'No results' in result

    mocked_client.list_policy_parameters.return_value = util_load_json('test_data/list_parameters.json')
    result = f5_list_policy_parameters_command(mocked_client, 'unimportant').outputs
    assert result[0].get('name') == 'param-1'
    assert result[0].get('id') == 'parameter-md5-1'
    assert result[1].get('name') == 'param-2'
    assert result[1].get('id') == 'parameter-md5-2'


def test_f5_add_policy_parameter_command(mocker):
    from F5_ASM import f5_add_policy_parameter_command
    mocked_client = mocker.Mock()
    mocked_client.add_policy_parameter.return_value = util_load_json('test_data/CUD_parameters.json')
    result = f5_add_policy_parameter_command(mocked_client, '0000', 'param-1').outputs
    assert result.get('name') == 'param-1'
    assert result.get('id') == 'parameter-md5'


def test_f5_update_policy_parameter_command(mocker):
    from F5_ASM import f5_update_policy_parameter_command
    mocked_client = mocker.Mock()
    mocked_client.update_policy_parameter.return_value = util_load_json('test_data/CUD_parameters.json')
    result = f5_update_policy_parameter_command(mocked_client, '0000', 'id123', 'param-1').outputs
    assert result.get('name') == 'param-1'
    assert result.get('id') == 'parameter-md5'


def test_f5_delete_policy_parameter_command(mocker):
    from F5_ASM import f5_delete_policy_parameter_command
    mocked_client = mocker.Mock()
    mocked_client.delete_policy_parameter.return_value = util_load_json('test_data/CUD_parameters.json')
    result = f5_delete_policy_parameter_command(mocked_client, '0000', 'id123', 'param-1').outputs
    assert result.get('name') == 'param-1'
    assert result.get('id') == 'parameter-md5'


def test_f5_list_policy_json_profiles_command(mocker):
    from F5_ASM import f5_list_policy_json_profiles_command
    mocked_client = mocker.Mock()
    mocked_client.list_policy_json_profiles.return_value = MOCK_EMPTY_RESPONSE
    result = f5_list_policy_json_profiles_command(mocked_client, 'unimportant').to_context()
    result = result.get('HumanReadable')
    assert 'No results' in result

    mocked_client.list_policy_json_profiles.return_value = util_load_json('test_data/list_json_profiles.json')
    result = f5_list_policy_json_profiles_command(mocked_client, '0000').outputs
    assert result[0].get('name') == 'json-profile-1'
    assert result[0].get('id') == 'json-profile-md5-1'
    assert result[1].get('name') == 'Default'
    assert result[1].get('id') == 'json-profile-md5-2'


def test_f5_add_policy_json_profile_command(mocker):
    from F5_ASM import f5_add_policy_json_profile_command
    mocked_client = mocker.Mock()
    mocked_client.add_policy_json_profile.return_value = util_load_json('test_data/CUD_json_profile.json')
    result = f5_add_policy_json_profile_command(mocked_client, '0000', 'param-1', '100', '100', '100',
                                                '100').outputs
    assert result.get('name') == 'json-profile'
    assert result.get('id') == 'json-profile-md5'


def test_f5_update_policy_json_profile_command(mocker):
    from F5_ASM import f5_update_policy_json_profile_command
    mocked_client = mocker.Mock()
    mocked_client.update_policy_json_profile.return_value = util_load_json('test_data/CUD_json_profile.json')
    result = f5_update_policy_json_profile_command(mocked_client, '0000', 'id123', 'param-1', '100', '100',
                                                   '100', '100').outputs
    assert result.get('name') == 'json-profile'
    assert result.get('id') == 'json-profile-md5'


def test_f5_delete_policy_json_profile_command(mocker):
    from F5_ASM import f5_delete_policy_json_profile_command
    mocked_client = mocker.Mock()
    mocked_client.delete_policy_json_profile.return_value = util_load_json('test_data/CUD_json_profile.json')
    result = f5_delete_policy_json_profile_command(mocked_client, '0000', 'id123', 'param-1').outputs
    assert result.get('name') == 'json-profile'
    assert result.get('id') == 'json-profile-md5'


def test_f5_list_policy_xml_profiles_command(mocker):
    from F5_ASM import f5_list_policy_xml_profiles_command
    mocked_client = mocker.Mock()
    mocked_client.list_policy_xml_profiles.return_value = MOCK_EMPTY_RESPONSE
    result = f5_list_policy_xml_profiles_command(mocked_client, '0000').to_context()
    result = result.get('HumanReadable')
    assert 'No results' in result

    mocked_client.list_policy_xml_profiles.return_value = util_load_json('test_data/list_xml_profile.json')
    result = f5_list_policy_xml_profiles_command(mocked_client, '0000').outputs
    assert result[0].get('name') == 'Default'
    assert result[0].get('id') == 'xml-profile-md5'


def test_f5_add_policy_xml_profile_command(mocker):
    from F5_ASM import f5_add_policy_xml_profile_command
    mocked_client = mocker.Mock()
    mocked_client.add_policy_xml_profile.return_value = util_load_json('test_data/CUD_xml_profile.json')
    result = f5_add_policy_xml_profile_command(mocked_client, '0000', 'param-1', '100').outputs
    assert result.get('name') == 'new_xml_profile'
    assert result.get('id') == 'xml-profile-md5'


def test_f5_update_policy_xml_profile_command(mocker):
    from F5_ASM import f5_update_policy_xml_profile_command
    mocked_client = mocker.Mock()
    mocked_client.update_policy_xml_profile.return_value = util_load_json('test_data/CUD_xml_profile.json')
    result = f5_update_policy_xml_profile_command(mocked_client, '0000', 'param-1', '100').outputs
    assert result.get('name') == 'new_xml_profile'
    assert result.get('id') == 'xml-profile-md5'


def test_f5_delete_policy_xml_profile_command(mocker):
    from F5_ASM import f5_delete_policy_xml_profile_command
    mocked_client = mocker.Mock()
    mocked_client.delete_policy_xml_profile.return_value = util_load_json('test_data/CUD_xml_profile.json')
    result = f5_delete_policy_xml_profile_command(mocked_client, '0000', 'id123', '8.8.8.8').outputs
    assert result.get('name') == 'new_xml_profile'
    assert result.get('id') == 'xml-profile-md5'


def test_f5_list_policy_signatures_command(mocker):
    from F5_ASM import f5_list_policy_signatures_command
    mocked_client = mocker.Mock()
    mocked_client.list_policy_signatures.return_value = MOCK_EMPTY_RESPONSE
    result = f5_list_policy_signatures_command(mocked_client, 'unimportant').to_context()
    result = result.get('HumanReadable')
    assert 'No results' in result


def test_f5_list_policy_server_technologies_command(mocker):
    from F5_ASM import f5_list_policy_server_technologies_command
    # adding fields to BASIC_FIELDS after previus test emptied this list.
    LIST_FIELDS = ['name', 'id', 'selfLink', 'lastUpdateMicros', 'type', 'protocol', 'method']  # noqa: F841
    mocked_client = mocker.Mock()
    mocked_client.list_policy_server_technologies.return_value =\
        util_load_json('test_data/list_server_technologies.json')
    result = f5_list_policy_server_technologies_command(mocked_client, '0000').outputs
    assert result[0].get('id') == 'server-technology-md5-1'
    assert result[1].get('id') == 'server-technology-md5-2'


def test_f5_add_policy_server_technologies_command(mocker):
    from F5_ASM import f5_add_policy_server_technology_command
    mocked_client = mocker.Mock()
    mocked_client.add_policy_server_technology.return_value =\
        util_load_json('test_data/add_delete_server_technology.json')
    result = f5_add_policy_server_technology_command(mocked_client, 'id123', '0000', 'ASP').outputs
    assert result.get('id') == 'server-technology-md5'


def test_f5_delete_policy_server_technologies_command(mocker):
    from F5_ASM import f5_delete_policy_server_technology_command
    mocked_client = mocker.Mock()
    mocked_client.delete_policy_server_technology.return_value = util_load_json('test_data/add_delete_server_technology.json')
    result = f5_delete_policy_server_technology_command(mocked_client, 'id123', '0000', 'ASP').outputs
    assert result.get('id') == 'server-technology-md5'


def test_f5_list_policy_whitelist_ips_command(mocker):
    from F5_ASM import f5_list_policy_whitelist_ips_command
    # adding fields to BASIC_FIELDS after previus test emptied this list.
    LIST_FIELDS = ['name', 'id', 'selfLink', 'lastUpdateMicros', 'type', 'protocol', 'method']  # noqa: F841
    mocked_client = mocker.Mock()
    mocked_client.list_policy_whitelist_ips.return_value = util_load_json('test_data/list_whitelist.json')
    result = f5_list_policy_whitelist_ips_command(mocked_client, '0000').outputs
    assert result[0].get('id') == 'whitelist-md5-1'
    assert result[1].get('id') == 'whitelist-md5-2'


def test_f5_add_policy_whitelist_ip_command(mocker):
    from F5_ASM import f5_add_policy_whitelist_ip_command
    mocked_client = mocker.Mock()
    mocked_client.add_policy_whitelist_ip.return_value = util_load_json('test_data/CUD_whitelist.json')
    result = f5_add_policy_whitelist_ip_command(mocked_client, '0000', '8.8.8.8').outputs
    assert result.get('id') == 'whitelist-md5'


def test_f5_update_policy_whitelist_ip_command(mocker):
    from F5_ASM import f5_update_policy_whitelist_ip_command
    mocked_client = mocker.Mock()
    mocked_client.update_policy_whitelist_ip.return_value = util_load_json('test_data/CUD_whitelist.json')
    result = f5_update_policy_whitelist_ip_command(mocked_client, '0000', 'id123', '8.8.8.8').outputs
    assert result.get('id') == 'whitelist-md5'


def test_f5_delete_policy_whitelist_ip_command(mocker):
    from F5_ASM import f5_delete_policy_whitelist_ip_command
    mocked_client = mocker.Mock()
    mocked_client.delete_policy_whitelist_ip.return_value = util_load_json('test_data/CUD_whitelist.json')
    result = f5_delete_policy_whitelist_ip_command(mocked_client, '0000', 'id123', '8.8.8.8').outputs
    assert result.get('id') == 'whitelist-md5'
