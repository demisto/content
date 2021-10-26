import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import time


class SlackSender:
    def __init__(self, args: dict):
        """
        Instantiates a SlackSender object using the inputs from demisto.args()
        :param args: demisto.args() dictionary
        """
        self.slack_instance = demisto.get(args, 'slack_instance')
        self.slack_channel = demisto.get(args, 'slack_channel')
        self.endurance = argToBoolean(demisto.get(args, 'endurance', False))
        self.quantity = int(demisto.get(demisto.args(), 'quantity'))

    def fire_command(self):
        """
        Fires a send-notification command preformatted for testing.
        :return: None
        """
        args = {
            'ignoreAddURL': 'true',
            'using': self.slack_instance,
            'message': f"This is a BurstTest from Instance - {self.slack_instance}.",
            'channel': self.slack_channel
        }
        demisto.results(demisto.executeCommand('send-notification', args))
        if self.endurance:
            time.sleep(1)


def main():
    args = demisto.args()
    slack_sender = SlackSender(args=args)
    for i in range(slack_sender.quantity):
        try:
            slack_sender.fire_command()
        except ValueError as e:
            return_error('An error has occurred while executing the send-notification command', error=e)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
