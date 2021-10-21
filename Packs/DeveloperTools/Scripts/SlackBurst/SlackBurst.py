import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():

    args = demisto.args()
    slack_instance = demisto.get(args, 'slack_instance')
    slack_channel = demisto.get(args, 'slack_channel')
    dos_endurance = argToBoolean(demisto.get(args, 'endurance', False))

    quantity = int(demisto.get(demisto.args(), 'quantity'))

    for i in range(quantity):
        try:
            args = {
                'ignoreAddURL': 'true',
                'using': slack_instance,
                'message': "This is a BurstTest from Instance - {}.".format(slack_instance),
                'channel': slack_channel
            }

            demisto.results(demisto.executeCommand('send-notification', args))
            if dos_endurance:
                time.sleep(1)
        except ValueError as e:
            return_error('An error has occurred while executing the send-notification command',
                         error=e)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
