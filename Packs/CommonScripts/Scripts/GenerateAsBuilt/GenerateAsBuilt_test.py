from GenerateAsBuilt import TableData, SortedTableData
import pytest
import demistomock as demisto

def test_as_html():
    test_data = [{
        "name": "test",
        "blah": "test2"
    }]
    o = TableData(test_data, "Test table")
    r = o.as_html(["name", "blah"])
    assert "<th>name</th>" in r
    assert "<td>test</td>" in r


def test_sort_table():
    test_data = [
        {
            "name": "btest",
            "blah": "test2"
        },
        {
            "name": "Ctest",
            "blah": "test2"
        },
        {
            "name": "atest",
            "blah": "test2"
        }
    ]
    o = SortedTableData(test_data, "Test table", "name")
    assert o.data[0].get("name") == "atest"
    assert o.data[1].get("name") == "btest"


def test_post_api_request(mocker):
    """
    Given:
    
    When:
    
    Then:
    """
    from GenerateAsBuilt import post_api_request, DEMISTO_INCIDENTS_PATH
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'response': 'ok'}}])
    assert post_api_request(DEMISTO_INCIDENTS_PATH, {}) == 'ok'


@pytest.mark.parametrize('res, expected',
                         [([{'Contents': {'response': ['ok']}}],
                           ['ok']),
                          ([{'Contents': {'response': None}}],
                           None)])
def test_get_api_request(mocker, res, expected):
    from GenerateAsBuilt import get_api_request, DEMISTO_INCIDENTS_PATH
    mocker.patch.object(demisto, 'executeCommand', return_value=res)
    assert get_api_request(DEMISTO_INCIDENTS_PATH,) == expected


def test_get_all_incidents(mocker):
    import GenerateAsBuilt
    from GenerateAsBuilt import get_all_incidents
    mocker.patch.object(GenerateAsBuilt, 'post_api_request', return_value={'data': 'ok'})
    assert get_all_incidents() == 'ok'


def test_get_open_incidents(mocker):
    import GenerateAsBuilt
    from GenerateAsBuilt import get_open_incidents, SingleFieldData
    mocker.patch.object(GenerateAsBuilt, 'post_api_request', return_value={'total': 1000})
    expected = SingleFieldData(f"Open Incidents {7} days", 1000)
    res = get_open_incidents()
    assert res.name == expected.name
    assert res.data == expected.data


def test_get_closed_incidents(mocker):
    import GenerateAsBuilt
    from GenerateAsBuilt import get_closed_incidents, SingleFieldData
    mocker.patch.object(GenerateAsBuilt, 'post_api_request', return_value={'total': 1000})
    expected = SingleFieldData(f"Closed Incidents {7} days", 1000)
    res = get_closed_incidents()
    assert res.name == expected.name
    assert res.data == expected.data


def test_get_enabled_integrations(mocker):
    import GenerateAsBuilt
    from GenerateAsBuilt import get_enabled_integrations, SortedTableData
    mocker.patch.object(GenerateAsBuilt, 'post_api_request', return_value={
                        'instances': [{'enabled': True, 'name': 'test'}]})
    expected = SortedTableData([{'enabled': True, 'name': 'test'}], "Enabled Instances", "name")
    res = get_enabled_integrations(1)
    assert res.name == expected.name
    assert res.data == expected.data


@pytest.mark.parametrize('get_api_request_returned_value', [None, [{'enabled': True, 'name': 'test'}]])
def test_get_installed_packs(mocker, get_api_request_returned_value):
    import GenerateAsBuilt
    from GenerateAsBuilt import get_installed_packs, SortedTableData, NoneTableData
    mocker.patch.object(GenerateAsBuilt, 'get_api_request', return_value=get_api_request_returned_value)
    
    res = get_installed_packs()
    if res:
        expected = SortedTableData([{'enabled': True, 'name': 'test'}], "Installed Content Packs", "name")
        assert res.name == expected.name
        assert res.data == expected.data
    else:
        assert isinstance(res, NoneTableData)
        

def test_get_custom_playbooks(mocker):
    import GenerateAsBuilt
    from GenerateAsBuilt import get_custom_playbooks, SortedTableData
    mocker.patch.object(GenerateAsBuilt, 'post_api_request', return_value={
                        'playbooks': [{'name': 'test'}]})
    expected = SortedTableData([{'name': 'test', 'TotalTasks': 0}], "Custom Playbooks", "name")
    res = get_custom_playbooks()
    assert res.name == expected.name
    assert res.data == expected.data