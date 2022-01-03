import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

NO_SENDMAIL_INCTANCES_MSG = 'There is no enabled instances to send-mail'


def get_sendmail_instances():
    """
        Get the enabled instances that has send-mail command

        :rtype: ``list``
        :return: list of enabled instances
    """

    integration_commands_args = {"uri": "/settings/integration-commands"}
    integration_commands_res = demisto.executeCommand("demisto-api-get", integration_commands_args)
    try:
        integration_commands = integration_commands_res[0]['Contents']['response']
    except KeyError:
        demisto.debug('Did not receive expected response from Demisto API: /settings/integration-commands')
        return []

    # if we only want to search enabled integrations, we must fetch that list from another API
    integration_search_args = {
        "uri": "/settings/integration/search",
        "body": {"size": 1000}
    }
    integration_search_res = demisto.executeCommand("demisto-api-post", integration_search_args)
    try:
        integration_search = integration_search_res[0]['Contents']['response']
    except KeyError:
        demisto.debug('Did not receive expected response from Demisto API: /settings/integration/search')
        return []

    integration_instances = integration_search['instances']

    # todd: change to -> brand: [instances]
    integration_instances_enabled = {integration['brand']: integration['name'] for integration in integration_instances
                                     if integration['enabled'] == 'true'}

    integrations_that_send_mail = []

    for integration in integration_commands:

        integration_name = integration['name']  # integration brand name

        if 'commands' in integration:
            for command in integration['commands']:

                command_name = command['name']
                if command_name == 'send-mail':
                    if integration_name in integration_instances_enabled:
                        integrations_that_send_mail.append(integration_name)

    if len(integrations_that_send_mail) == 0:
        return []
    else:
        demisto.results(','.join(integrations_that_implement))


def get_incident_ids_as_options(incidents):
    """
        Collect the campaign incidents ids form the context and return them as options for MultiSelect field

        :type incidents: ``list``
        :param incidents: the campaign incidents to collect ids from

        :rtype: ``dict``
        :return: dict with the ids as options for MultiSelect field e.g {"hidden": False, "options": ids}
    """
    return {"hidden": False, "options": ['4', '5', '6']}


def main():

    try:
        # incidents = get_campaign_incidents()
        # if incidents:
        #     result = get_incident_ids_as_options(incidents)
        # else:
        #     result = NO_CAMPAIGN_INCIDENTS_MSG
        #
        result = get_sendmail_instances()
        results = CommandResults(
            readable_output='markdown',
            outputs_prefix='TestGetSendEmail',
            outputs_key_field='',
            outputs=result
        )
        return_results(results)

    except Exception as err:
        return_error(str(err), error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
