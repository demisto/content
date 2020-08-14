import demistomock as demisto
import pytest


integration_params = {
    # (e.g. 192.168.100.2)
    'server_ip': 'Genian NAC Server IP Address',
    
    # (e.g. 98e7ab23-5078-49ff-bd8e-153a90f3f328)
    'apikey': 'Genian NAC API KEY',
    
    # (e.g. THREAT)
    'tag_name': 'Genian NAC Tag Name',
    
    'insecure': True
}

mock_demisto_args = {
    # (e.g. 192.168.100.100)
    'ip': 'IP address for assign or unassign tags'
}


@pytest.fixture(autouse=True)
def init_tests(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)


def test_get_ip_nodeid(mocker):
    '''Genians-Genian-NAC-get-ip-nodeid'''
    from Genians import get_ip_nodeid

    res = get_ip_nodeid(mock_demisto_args['ip'])

    result_1 = res[0]['nl_nodeid']
    result_2 = res[0]['nl_ipstr']

    assert result_1 != None
    assert result_2 == mock_demisto_args['ip']


def test_get_tag_list(mocker):
    '''Genians-Genian-NAC-get-tag-list'''
    from Genians import get_tag_list

    res = get_tag_list()

    result_1 = res['result']
    result_2 = res['result'][0]['NP_NAME']

    assert result_1 != []
    assert result_2 == integration_params['tag_name']
