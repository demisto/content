from GetSendEmailInstances import *

INTEGRATION_COMMANDS = [{'name': 'SendMailIntegration', 'commands': [{'name': 'send-mail'}, {'name': 'some-command'}]},
                        {'name': 'NoMailIntegration', 'commands': [{'name': 'no-mail'}, {'name': 'some-command'}]},
                        {'name': 'SomeIntegration', 'commands': [{'name': 'send-mail'}, {'name': 'some-command'}]}]
INTEGRATION_INSTANCES = [{'name': 'SendMailIntegration_instance1',
                          'brand': 'SendMailIntegration',
                          'enabled': 'true'},
                         {'name': 'SendMailIntegration_instance2',
                          'brand': 'SendMailIntegration',
                          'enabled': 'true'},
                         {'name': 'SendMailIntegration_instance3',
                          'brand': 'SendMailIntegration',
                          'enabled': 'false'},
                         {'name': 'NoMailIntegration_instance1',
                          'brand': 'NoMailIntegration',
                          'enabled': 'true'},
                         {'name': 'NoMailIntegration_instance2',
                          'brand': 'NoMailIntegration',
                          'enabled': 'false'},
                         {'name': 'SomeIntegration_instance1',
                          'brand': 'SomeIntegration',
                          'enabled': 'false'}
                         ]


def test_get_enabled_instances(mocker):
    """

    Given:
        - The "Email Sender Instance" single select field try to populate the available instances

    When:
        - Get the integration instances that can 'send-mail' as option

    Then:
        - Validate the instances returned as options format for single select field

    """
    mocker.patch.object(demisto, 'results')
    mocker.patch('GetSendEmailInstances.get_all_integrations_commands', return_value=INTEGRATION_COMMANDS)
    mocker.patch('GetSendEmailInstances.get_all_instances', return_value=INTEGRATION_INSTANCES)

    result = get_enabled_instances()

    instances = result['options']
    hidden = result['hidden']

    assert hidden is False
    assert set(instances) == {'SendMailIntegration_instance1', 'SendMailIntegration_instance2'}


def test_get_all_integrations_commands_failure(mocker):
    """
    Given:
        - The "Email Sender Instance" single select field try to populate the available instances

    When:
        - Get the integration commands

    Then:
        - Validate that when no results, empty list returned

    """
    mocker.patch.object(demisto, 'internalHttpRequest', return_value={'statusCode': 400})
    assert get_all_integrations_commands() == []


def test_get_all_instances_failure(mocker):
    """
    Given:
        - The "Email Sender Instance" single select field try to populate the available instances

    When:
        - Get the integrations instances

    Then:
        - Validate that when no results, empty list returned

    """
    mocker.patch.object(demisto, 'internalHttpRequest', return_value={'statusCode': 400})
    assert get_all_instances() == []
