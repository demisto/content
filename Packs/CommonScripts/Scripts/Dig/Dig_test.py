''' STANDALONE FUNCTION UNIT TESTS'''


def test_regex_result():
    """
    Given:
        - dig output
    When:
        - running regex_result function
    Then:
        - validate the output is as expected
    """
    from Dig import regex_result
    dig_output = "0.0.0.0, 1.1.1.1"
    resolved_addresses, dns_server = regex_result(dig_output, reverse_lookup=False)
    assert resolved_addresses, dns_server == (['0.0.0.0'], '1.1.1.1')

    resolved_addresses, dns_server = regex_result(dig_output, reverse_lookup=True)
    assert resolved_addresses, dns_server == (['0.0.0.0'], '1.1.1.1')


def test_dig_result(mocker):
    """
    Given:
        - server and name
    When:
        - running dig_result function
    Then:
        - validate the output is as expected
    """
    import Dig
    import subprocess
    from Dig import dig_result
    mocker.patch.object(Dig, 'regex_result', return_value=(['0.0.0.0'], '1.1.1.1'))
    mocker.patch.object(subprocess, 'check_output', return_value="OK")
    dig_result('server', 'name') == {'name': 'name', 'resolvedaddresses': ['0.0.0.0'], 'nameserver': '1.1.1.1'}
    dig_result('', 'name') == {'name': 'name', 'resolvedaddresses': ['0.0.0.0'], 'nameserver': '1.1.1.1'}


def test_reverse_dig_result(mocker):
    """
    Given:
        - server and name
    When:
        - running reverse_dig_result function
    Then:
        - validate the output is as expected
    """
    import Dig
    import subprocess
    from Dig import reverse_dig_result
    mocker.patch.object(Dig, 'regex_result', return_value=(['0.0.0.0'], '1.1.1.1'))
    mocker.patch.object(subprocess, 'check_output', return_value="OK")
    reverse_dig_result('server', 'name') == {'name': 'name', 'resolvedaddresses': ['0.0.0.0'], 'nameserver': '1.1.1.1'}
    reverse_dig_result('', 'name') == {'name': 'name', 'resolvedaddresses': ['0.0.0.0'], 'nameserver': '1.1.1.1'}


''' COMMAND FUNCTION UNIT TESTS'''


def test_dig_command(mocker):
    """
    Given:
        - server, name and reverseLookup as arguments
    When:
        - running dig_command function
    Then:
        - validate the returned XSOAR CommandResults is as expected
    """
    import Dig
    from Dig import dig_command
    dig_result_return_value = {'name': 'name', 'resolvedaddresses': ['0.0.0.0'], 'nameserver': '1.1.1.1'}
    mocker.patch.object(Dig, 'dig_result', return_value=dig_result_return_value)
    mocker.patch.object(Dig, 'reverse_dig_result', return_value=dig_result_return_value)
    command_result = dig_command({'server': 'server', 'name': 'name', 'reverseLookup': False})
    command_result.outputs = dig_result_return_value

    command_result = dig_command({'server': 'server', 'name': 'name', 'reverseLookup': True})
    command_result.outputs = dig_result_return_value
