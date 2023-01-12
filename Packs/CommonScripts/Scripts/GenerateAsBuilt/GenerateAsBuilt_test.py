from GenerateAsBuilt import TableData, SortedTableData
import pytest
import demistomock as demisto


def test_as_html():
    """
    Given:
        - a list of dicts
    When:
        - calling as_html
    Then:
        - validate the html is as expected
    """
    test_data = [{
        "name": "test",
        "blah": "test2"
    }]
    o = TableData(test_data, "Test table")
    r = o.as_html(["name", "blah"])
    assert "<th>name</th>" in r
    assert "<td>test</td>" in r


def test_sort_table():
    """
    Given:
        - a list of dicts
    When:
        - calling sort_table
    Then:
        - validate the list is sorted by the given key
    """
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
        - valid api path and body arguments
    When:
        - calling post_api_request
    Then:
        - validate the response is as expected
    """
    from GenerateAsBuilt import post_api_request
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'response': 'ok'}}])
    assert post_api_request("/incidents/search", {}) == 'ok'


@pytest.mark.parametrize('res, expected',
                         [([{'Contents': {'response': ['ok']}}],
                           ['ok']),
                          ([{'Contents': {'response': None}}],
                           None)])
def test_get_api_request(mocker, res, expected):
    """
    Given:
        - valid api path
    When:
        - calling get_api_request
    Then:
        - validate the response is as expected
    """
    from GenerateAsBuilt import get_api_request
    mocker.patch.object(demisto, 'executeCommand', return_value=res)
    assert get_api_request("/incidents/search") == expected


def test_get_all_incidents(mocker):
    """
    Given:
        - available incidents
    When:
        - calling get_all_incidents
    Then:
        - all available incidents are returned
    """
    import GenerateAsBuilt
    from GenerateAsBuilt import get_all_incidents
    mocker.patch.object(GenerateAsBuilt, 'post_api_request', return_value={'data': 'ok'})
    assert get_all_incidents() == 'ok'


def test_get_open_incidents(mocker):
    """
    Given:
        - open incidents
    When:
        - calling get_open_incidents
    Then:
        - all open incidents are returned
    """
    import GenerateAsBuilt
    from GenerateAsBuilt import get_open_incidents, SingleFieldData
    mocker.patch.object(GenerateAsBuilt, 'post_api_request', return_value={'total': 1000})
    expected = SingleFieldData(f"Open Incidents {7} days", 1000)
    res = get_open_incidents()
    assert res.name == expected.name
    assert res.data == expected.data


def test_get_closed_incidents(mocker):
    """
    Given:
        - closed incidents
    When:
        - calling get_closed_incidents
    Then:
        - all closed incidents are returned
    """
    import GenerateAsBuilt
    from GenerateAsBuilt import get_closed_incidents, SingleFieldData
    mocker.patch.object(GenerateAsBuilt, 'post_api_request', return_value={'total': 1000})
    expected = SingleFieldData(f"Closed Incidents {7} days", 1000)
    res = get_closed_incidents()
    assert res.name == expected.name
    assert res.data == expected.data


def test_get_enabled_integrations(mocker):
    """
    Given:
        - enabled integrations
    When:
        - calling get_enabled_integrations
    Then:
        - all enabled integrations are returned
    """
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
    """
    Given:
        - installed packs
    When:
        - calling get_installed_packs
    Then:
        - all installed packs are returned
    """
    import GenerateAsBuilt
    from GenerateAsBuilt import get_installed_packs, SortedTableData
    mocker.patch.object(GenerateAsBuilt, 'get_api_request', return_value=get_api_request_returned_value)

    result = get_installed_packs()
    if result:
        expected = SortedTableData([{'enabled': True, 'name': 'test'}], "Installed Content Packs", "name")
        assert result.name == expected.name
        assert result.data == expected.data


def test_get_custom_playbooks(mocker):
    """
    Given:
        - custom playbooks
    When:
        - calling get_custom_playbooks
    Then:
        - all custom playbooks are returned
    """
    import GenerateAsBuilt
    from GenerateAsBuilt import get_custom_playbooks, SortedTableData
    mocker.patch.object(GenerateAsBuilt, 'post_api_request', return_value={
                        'playbooks': [{'name': 'test'}]})
    expected = SortedTableData([{'name': 'test', 'TotalTasks': 0}], "Custom Playbooks", "name")
    res = get_custom_playbooks()
    assert res.name == expected.name
    assert res.data == expected.data


def test_get_custom_reports(mocker):
    """
    Given:
        - custom reports
    When:
        - calling get_custom_reports
    Then:
        - all custom reports are returned
    """
    import GenerateAsBuilt
    from GenerateAsBuilt import get_custom_reports, TableData
    mocker.patch.object(GenerateAsBuilt, 'get_api_request', return_value=[{'name': 'test'}])
    expected = TableData([{'name': 'test'}], 'Custom Reports')
    res = get_custom_reports()
    assert res.name == expected.name
    assert res.data == expected.data


def test_get_custom_dashboards(mocker):
    """
    Given:
        - custom dashboards
    When:
        - calling get_custom_dashboards
    Then:
        - all custom dashboards are returned
    """
    import GenerateAsBuilt
    from GenerateAsBuilt import get_custom_dashboards, TableData
    mocker.patch.object(GenerateAsBuilt, 'get_api_request', return_value={'dashboard': {'name': 'test'}})
    expected = TableData([{'name': 'test'}], 'Custom dashboards')
    res = get_custom_dashboards()
    assert res.name == expected.name
    assert res.data == expected.data


def test_get_all_playbooks(mocker):
    """
    Given:
        - available playbooks
    When:
        - calling get_all_playbooks
    Then:
        - all available playbooks are returned
    """
    import GenerateAsBuilt
    from GenerateAsBuilt import get_all_playbooks, TableData
    mocker.patch.object(GenerateAsBuilt, 'post_api_request', return_value={'playbooks': [{'name': 'test'}]})
    expected = TableData([{'name': 'test', 'TotalTasks': 0}], 'All Playbooks')
    res = get_all_playbooks()
    assert res.name == expected.name
    assert res.data == expected.data


def test_get_playbook_stats(mocker):
    """
    Given:
        - available playbooks
    When:
        - calling get_playbook_stats
    Then:
        - all available playbooks stats are returned
    """
    import GenerateAsBuilt
    from GenerateAsBuilt import get_playbook_stats, TableData
    mocker.patch.object(GenerateAsBuilt, 'get_all_incidents', return_value=[
                        {'name': 'test', 'TotalTasks': 0, 'playbookId': '000001'}])

    expected = TableData([{'playbook': '000001', 'incidents': 1}], "Playbook Stats")
    res = get_playbook_stats(SortedTableData([{'name': 'test', 'TotalTasks': 0}], "Custom Playbooks", "name"))

    assert res.name == expected.name
    assert res.data == expected.data


def test_get_playbook_dependencies(mocker):
    """
    Given:
        - available playbooks
    When:
        - calling get_playbook_dependencies
    Then:
        - all available playbooks dependencies are returned
    """
    import GenerateAsBuilt
    from GenerateAsBuilt import get_playbook_dependencies, TableData
    mocker.patch.object(GenerateAsBuilt, 'get_all_playbooks', return_value=TableData(
        [{'name': 'test', 'TotalTasks': 0, 'id': '000001'}], 'All Playbooks'))
    mocker.patch.object(GenerateAsBuilt, 'post_api_request', return_value={'existing': {
                        'playbook': {'000001': [{'ok': 'ok', 'type': 'type', 'name': 'name'}]}}})

    res = get_playbook_dependencies('test')
    assert res.get('type').name == 'types'
    assert res.get('type').data == [{'type': 'type', 'name': 'name', 'pack': 'Custom'}]


def test_get_custom_automations(mocker):
    """
    Given:
        - custom automations
    When:
        - calling get_custom_automations
    Then:
        - all custom automations are returned
    """
    import GenerateAsBuilt
    from GenerateAsBuilt import get_custom_automations, TableData
    mocker.patch.object(GenerateAsBuilt, 'post_api_request', return_value={'scripts': [{'name': 'test'}]})
    expected = TableData([{'name': 'test'}], 'Custom Automations')
    res = get_custom_automations()
    assert res.name == expected.name
    assert res.data == expected.data


def test_get_system_config(mocker):
    """
    Given:
        - system configuration settings
    When:
        - calling get_system_config
    Then:
        - all system configurations are returned
    """
    import GenerateAsBuilt
    from GenerateAsBuilt import get_system_config, TableData
    mocker.patch.object(GenerateAsBuilt, 'get_api_request', return_value={'config': [{'name': 'test'}]})
    expected = TableData([{'name': 'test'}], 'System Configuration')
    res = get_system_config()
    assert res.name == expected.name
