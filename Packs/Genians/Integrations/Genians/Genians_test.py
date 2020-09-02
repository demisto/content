import demistomock as demisto
import pytest


integration_params = {
    # (e.g. 192.168.100.2)
    'server_ip': 'Genian NAC Server IP Address',

    # (e.g. 98e7ab23-5078-49ff-bd8e-153a90f3f328)
    'apikey': 'Genian NAC API KEY',

    'tag_name': 'THREAT',
}

mock_demisto_args = {
    'ip': '172.29.62.3'
}


@pytest.fixture(autouse=True)
def init_tests(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)


def run_command_test(command_func, args, response, result, mocker):
    response_vlaue = response
    mocker.patch('Genians.http_request', return_value=response_vlaue)

    if command_func.__name__ == 'get_ip_nodeid':
        res = command_func(args)
    else:
        res = command_func()

    assert result == res


def test_get_ip_nodeid(mocker):
    '''Genians-Genian-NAC-get-ip-nodeid'''
    from Genians import get_ip_nodeid

    run_command_test(command_func=get_ip_nodeid,
                     args=mock_demisto_args['ip'],
                     response=response_data_1,
                     result=result_data_1,
                     mocker=mocker)


def test_get_tag_list(mocker):
    '''Genians-Genian-NAC-get-tag-list'''
    from Genians import get_tag_list

    run_command_test(command_func=get_tag_list,
                     args='',
                     response=response_data_2,
                     result=result_data_2,
                     mocker=mocker)


def test_list_tag_data_string(mocker):
    '''Genians-Genian-NAC-list-tag-data-string'''
    from Genians import list_tag_data_string

    result = list_tag_data_string(integration_params['tag_name'])

    assert result == result_data_3


response_data_1 = [{
    "nl_nodeid": "66af6c34-4871-103a-8002-2cf05d0cf498-c9cd139d",
    "nl_ipstr": mock_demisto_args['ip'],
    "nl_mac": "2C:F0:5D:0C:F4:98",
    "nl_sensornid": "455eba44-4871-103a-8001-08002746dd06-326ef817",
    "nl_genidev": 20
}]

response_data_2 = {
    "result": [
        {
            "NP_NAME": integration_params['tag_name'],
            "NP_PERIOD": "0h",
            "NP_STATIC": 0,
            "NP_PERIODEXPIRE": "0h",
            "NP_PERIODTYPE": 0,
            "NP_COLOR": "ff0000",
            "NP_DESC": "Anomaly",
            "NP_IDX": 3
        }
    ],
    "total": 1,
    "pageSize": 30,
    "page": 1
}

result_data_1 = [{
    "nl_nodeid": "66af6c34-4871-103a-8002-2cf05d0cf498-c9cd139d",
    "nl_ipstr": "172.29.62.3",
    "nl_mac": "2C:F0:5D:0C:F4:98",
    "nl_sensornid": "455eba44-4871-103a-8001-08002746dd06-326ef817",
    "nl_genidev": 20
}]

result_data_2 = {
    "result": [
        {
            "NP_NAME": 'THREAT',
            "NP_PERIOD": "0h",
            "NP_STATIC": 0,
            "NP_PERIODEXPIRE": "0h",
            "NP_PERIODTYPE": 0,
            "NP_COLOR": "ff0000",
            "NP_DESC": "Anomaly",
            "NP_IDX": 3
        }
    ],
    "total": 1,
    "pageSize": 30,
    "page": 1
}

result_data_3 = [{
    "id": "",
    "name": integration_params['tag_name'],
    "description": "",
    "startDate": "",
    "expireDate": "",
    "periodType": "",
    "expiryPeriod": ""
}]
