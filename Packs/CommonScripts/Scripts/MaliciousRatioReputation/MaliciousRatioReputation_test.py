import demistomock as demisto


def test_main_malicious_ratio_reputation(mocker):
    """
    Given:
        - The script args.
    When:
        - Running the main with valid indicator.
    Then:
        - Validating after calling the helper functions the results is as expected.
    """
    import MaliciousRatioReputation
    args = {'input': 'value_a', 'threshold': '-2'}
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(MaliciousRatioReputation, 'get_indicator_from_value',
                        return_value={'value': 'value_a', 'indicator_type': 'IP'})
    res_get_indicator_result = {'Type': 1, 'EntryContext': {'DBotScore': {'Type': 'ip',
                                                                          'Score': 2, 'Vendor': 'DBot-MaliciousRatio',
                                                                          'Indicator': 'value_a'}},
                                'Contents': 2,
                                'ContentsFormat': 'text',
                                'HumanReadable': 'Malicious ratio for value_a is -1.00',
                                'ReadableContentsFormat': 'markdown'}
    mocker.patch.object(MaliciousRatioReputation, 'get_indicator_result',
                        return_value=res_get_indicator_result)
    res_mock = mocker.patch.object(demisto, 'results')
    MaliciousRatioReputation.main()
    assert res_mock.call_count == 1
    assert res_mock.call_args[0][0] == res_get_indicator_result


def test_get_indicator_result(mocker):
    """
    Given:
        - The script args and indicator with mr_score > given threshold.
    When:
        - Running the get_indicator_result function.
    Then:
        - Validating that the function returns entry to the context.
    """
    from MaliciousRatioReputation import get_indicator_result
    args = {'input': '8.8.8.8', 'threshold': '-2'}
    mocker.patch.object(demisto, 'args', return_value=args)
    indicator = {'value': '8.8.8.8', 'indicator_type': 'IP'}
    execute_command_res = [{'Contents': [{'maliciousRatio': -1}]}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    entry = get_indicator_result(indicator)
    assert execute_mock.call_count == 1
    assert len(entry['EntryContext']) > 0


def test_get_indicator_result_with_smaller_mr_score(mocker):
    """
    Given:
        - The script args and indicator with mr_score < given threshold.
    When:
        - Running the get_indicator_result function.
    Then:
        - Validating that the function doesn't return entry.
    """
    from MaliciousRatioReputation import get_indicator_result
    mocker.patch.object(demisto, 'args', return_value={'input': '8.8.8.8', 'threshold': '0.3'})
    indicator = {'value': '8.8.8.8', 'indicator_type': 'IP'}
    execute_command_res = [{'Contents': [{'maliciousRatio': -1}]}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    assert get_indicator_result(indicator) is None
    assert execute_mock.call_count == 1


def test_get_indicator_from_value(mocker):
    """
    Given:
        - The function args.
    When:
        - Running the get_indicator_from_value function.
    Then:
        - Validating that the return value after calling to "findIndicators" command is as expected.
    """
    from MaliciousRatioReputation import get_indicator_from_value

    execute_command_res = [{'Contents': [{'id': 'a', 'investigationIDs': ['1', '2', '10'], 'value': 'value_a',
                                          'indicator_type': 'File'}], 'Type': 'note'}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    indicator = get_indicator_from_value('value_a')
    assert execute_mock.call_count == 1
    assert indicator == execute_command_res[0]['Contents'][0]
