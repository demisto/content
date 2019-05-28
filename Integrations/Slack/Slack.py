import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import slack


TOKEN = demisto.params()['bot_token']


@slack.RTMClient.run_on(event='message')
def listen(**payload):
    data = payload['data']
    web_client = payload['web_client']
    rtm_client = payload['rtm_client']

    demisto.results(str(data))

    if 'Hello' in data['text']:
        channel_id = data['channel']
        thread_ts = data['ts']
        user = data['user']

        web_client.chat_postMessage(
            channel=channel_id,
            text=f"Hi <@{user}>!",
            thread_ts=thread_ts
        )


# The command demisto.command() holds the command sent from the user.
if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    demisto.results('ok')
    sys.exit(0)

if demisto.command() == 'long-running-execution':
    slack_token = TOKEN
    rtm_client = slack.RTMClient(token=slack_token)
    while True:
        rtm_client.start()

