import demistomock as demisto


def test_main_malicious_ratio_reputation(mocker):
    """
    Given:
        - The script args.
    When:
        - Running the main with valid indicator.
    Then:
        - Validating calling to 'demisto.results'.
    """
    import MaliciousRatioReputation
    args = {'input': '8.8.8.8', 'threshold': '-2'}
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(MaliciousRatioReputation, 'get_indicator_from_value',
                        return_value=1)
    mocker.patch.object(MaliciousRatioReputation, 'get_indicator_result',
                        return_value={'Type': 'type', 'EntryContext': 'ec'})
    execute_mock = mocker.patch.object(demisto, 'results', return_value=1)
    MaliciousRatioReputation.main()
    assert execute_mock.call_count == 1


def test_malicious_ratio_reputation(mocker):
    """
    Given:
        - The script args.
    When:
        - Running the command.
    Then:
        - Validating the outputs as expected.
        - Validating the filtered args that was sent to the api is as expected.
    """
    from MaliciousRatioReputation import get_indicator_result
    args = {'input': '8.8.8.8', 'threshold': '-2'}
    mocker.patch.object(demisto, 'args', return_value=args)
    indicator = {'value': '8.8.8.8', 'indicator_type': 'ip'}
    execute_command_res = [{'Contents': [{'maliciousRatio': -1}]}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    entry = get_indicator_result(indicator)
    assert execute_mock.call_count == 1
    assert len(entry['EntryContext']) > 0


def test_get_indicator_from_value(mocker):
    """
    Given:
        The function args.
    When:
        Running the get_indicator_from_value function.
    Then:
        - Validating the outputs as expected.
        - Validating the filtered args that was sent to the api is as expected.
    """
    from MaliciousRatioReputation import get_indicator_from_value

    execute_command_res = [{'Contents': [1]}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    indicator = get_indicator_from_value(1)
    assert execute_mock.call_count == 1
    assert indicator == 1
