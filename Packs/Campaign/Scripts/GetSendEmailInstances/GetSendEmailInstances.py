import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

NO_SENDMAIL_INSTANCES_MSG = 'There is no enabled instances to send-mail'


def get_all_integrations_commands():
    integration_commands_args = {"uri": "/settings/integration-commands"}
    integration_commands_res = demisto.executeCommand("demisto-api-get", integration_commands_args)
    try:
        integration_commands = integration_commands_res[0]['Contents']['response']
        return integration_commands
    except KeyError:
        demisto.debug('Did not receive expected response from Demisto API: /settings/integration-commands')
        return []


def get_all_instances():
    integration_search_args = {
        "uri": "/settings/integration/search",
        "body": {"size": 1000}
    }
    integration_search_res = demisto.executeCommand("demisto-api-post", integration_search_args)
    try:
        integration_search = integration_search_res[0]['Contents']['response']
        integration_instances = integration_search['instances']
        return integration_instances
    except KeyError:
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

    integration_instances_enabled: Dict[str, list] = dict()

    for integration in integration_instances:
        if integration['enabled'] == 'true':
            if not integration_instances_enabled.get(integration['brand']):
                integration_instances_enabled[integration['brand']] = []

            integration_instances_enabled[integration['brand']].append(integration['name'])

    integrations_that_send_mail = []

    for integration in integration_commands:

        integration_name = integration['name']  # integration brand name

        if 'commands' in integration:
            for command in integration['commands']:

                if command['name'] == 'send-mail':
                    if integration_name in integration_instances_enabled.keys():
                        integrations_that_send_mail.extend(integration_instances_enabled[integration_name])

    if len(integrations_that_send_mail) == 0:
        return []
    else:
        return integrations_that_send_mail


def get_enabled_instances():
    """
        Collect the enabled instances that has send-mail command, for SingleSelect field

        :rtype: ``dict``
        :return: dict with the ids as options for SingleSelect field e.g
        {"hidden": False, "options": send_mail_instances}
    """
    send_mail_instances = get_sendmail_instances()
    # send_mail_instances.insert(0, NO_SENDMAIL_INSTANCES_MSG)   # todo: maybe need this?
    return {"hidden": False, "options": send_mail_instances}


def main():

    try:
        result = get_enabled_instances()
        return_results(result)

    except Exception as err:
        return_error(str(err), error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
