inputs_and_outputs = [
    {
        'args': [{'name': 'text', 'size': 10.44}],
        'id': '9',
        'name': 'Extract indicators from incident'
    },
    {
        'id': '198',
        'name': 'Malware Investigation',
        'outputs': [{'name': 'IP', 'size': 159.692}],
        'subplaybook': 'Malware Investigation'
    },
    {
        'args': [{'name': 'text', 'size': 11.44}],
        'id': '10',
        'name': 'Extract indicators from incident again'
    },
    {
        'id': '200',
        'name': 'Malware Investigation 2',
        'outputs': [{'name': 'IP', 'size': 200.692}],
    }
]


largest_input = {
    'IncidentID': '[1](https://test-address:8443/#/incident/1)',
    'TaskID': '[10](https://test-address:8443/#/WorkPlan/1/10)',
    'TaskName': 'Extract indicators from incident again',
    'Name': 'text',
    'Size(MB)': 11.44,
    'InputOrOutput': 'Input'
}

largest_output = {
    'IncidentID': '[1](https://test-address:8443/#/incident/1)',
    'TaskID': '[200](https://test-address:8443/#/WorkPlan/1/200)',
    'TaskName': 'Malware Investigation 2',
    'Name': 'IP',
    'Size(MB)': 200.692,
    'InputOrOutput': 'Output'
}


def test_get_largest_inputs_and_outputs():
    """
    Given:
        a list of inputs and outputs
    When:
        Running get_largest_inputs_and_outputs.
    Then:
        the result a list with only the larges input and output
    """
    from GetLargestInputsAndOuputsInIncidents import get_largest_inputs_and_outputs
    res = []
    get_largest_inputs_and_outputs(inputs_and_outputs, res, '1')
    assert len(res) == 2
    assert largest_input in res
    assert largest_output in res


def test_get_largest_inputs_and_outputs__on_fail():
    """
    Given:
        a failure message from getInvPlaybookMetaData command
    When:
        Running get_largest_inputs_and_outputs.
    Then:
        the result is an empty list
    """
    from GetLargestInputsAndOuputsInIncidents import get_largest_inputs_and_outputs
    res = []
    get_largest_inputs_and_outputs('No data', res, '1')
    assert len(res) == 0
