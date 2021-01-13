from CommonServerPython import *


def main():
    channel_type = demisto.args().get('type')
    channel_name = demisto.args().get('name')
    channel_desc = demisto.args().get('description')
    channel_team = demisto.args().get('team')

    errors = []
    integrations_to_create = []
    channels_created = []

    for brand in ['SlackV2', 'Microsoft Teams']:
        res = demisto.executeCommand('IsIntegrationAvailable', {'brandname': brand})
        if res[0].get('Contents') == 'yes':
            integrations_to_create.append(brand)

    if not integrations_to_create:
        return_error('Microsoft Teams and Slack are not available, please configure at least one of them.')

    for integration in integrations_to_create:
        res = None
        if integration == 'SlackV2':
            res = demisto.executeCommand('slack-create-channel', {'type': channel_type, 'name': channel_name})

        elif integration == 'Microsoft Teams':
            if channel_team:
                res = demisto.executeCommand('microsoft-teams-create-channel',
                                             {'channel_name': channel_name, 'description': channel_desc, 'team': channel_team})
            else:
                errors.append('Failed to create channel in Microsoft Teams: team argument is missing')

        if is_error(res):
            errors.append(f'Failed to create channel in {integration}: {res[0].get("Contents")}')
        elif res:
            channels_created.append(integration)

    errors_str = '\n'.join(errors)

    # in case of no channel created
    if len(channels_created) == 0:
        return_error(errors_str)
    # in case of channel created in all the available brands(Microsoft Teams and Slack)
    elif len(channels_created) == len(integrations_to_create):
        return_results(f'Channel {channel_name} created successfully.')
    # in case of only one channel created
    else:
        return_results(f'Channel {channel_name} created successfully.\n{errors_str}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
