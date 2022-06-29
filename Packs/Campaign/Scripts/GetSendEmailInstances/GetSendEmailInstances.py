import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_all_integrations_commands():
    """ Send API request with demisto rest api, to get all integration instances configured in the demisto. """
    integration_commands_res = demisto.internalHttpRequest('GET', '/settings/integration-commands')
    if integration_commands_res and integration_commands_res['statusCode'] == 200:
        return json.loads(integration_commands_res.get('body', '{}'))
    demisto.debug('Did not receive expected response from Demisto API: /settings/integration-commands')
    return []


def get_all_instances():
    """ Send API request with demisto rest api, to get all integration instances configured in the demisto."""
    integration_search_res = demisto.internalHttpRequest('POST', '/settings/integration/search', '{\"size\":1000}')
    if integration_search_res and integration_search_res['statusCode'] == 200:
        integration_search = json.loads(integration_search_res.get('body', '{}'))
        return integration_search['instances']
    demisto.debug('Did not receive expected response from Demisto API: /settings/integration/search')
    return []


def get_sendmail_instances():
    """
        Get the enabled instances that has send-mail command

        :rtype: ``list``
        :return: list of enabled instances
    """
    integration_commands = get_all_integrations_commands()

    # if we only want to search enabled integrations, we must fetch that list from another API
    integration_instances = get_all_instances()

    send_mail_integrations = [integration['name'] for integration in integration_commands if 'send-mail' in
                              [cmd['name'] for cmd in integration.get('commands', [])]]

    integration_instances_enabled = [instance for instance in integration_instances
                                     if instance['enabled'] == 'true']

    relevant_instances = [instance['name'] for instance in integration_instances_enabled
                          if instance['brand'] in send_mail_integrations]

    return relevant_instances


def get_enabled_instances():
    """
        Collect the enabled instances that has send-mail command, for SingleSelect field

        :rtype: ``dict``
        :return: dict with the ids as options for SingleSelect field e.g
        {"hidden": False, "options": send_mail_instances}
    """
    send_mail_instances = get_sendmail_instances()
    return {"hidden": False, "options": send_mail_instances}


def main():

    try:
        result = get_enabled_instances()
        return_results(result)

    except Exception as err:
        return_error(str(err), error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
