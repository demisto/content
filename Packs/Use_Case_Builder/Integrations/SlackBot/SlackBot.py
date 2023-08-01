import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# from slack_bolt import App
import os
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler


def run_long_running(params, app):
    # app = App(token="xapp-1-A04KBAB8WH1-4643783938039-e5ad24dd512252981ac3de84785f5c035e9381b1a639a2d73798bc48c609cbf8", bot_token="xoxb-2700273429121-4658356427058-J3KImm73zh08kyWDGBqAeBEE")
    # @app.command("/get_help")
    SocketModeHandler(app, "xapp-1-A04KBAB8WH1-4643783938039-e5ad24dd512252981ac3de84785f5c035e9381b1a639a2d73798bc48c609cbf8").start()


async def handle_command(ack, command, respond):
    await ack("Got it, processing your command...")
    try:
        # Your code to handle the command
        await respond(f"Command processed successfully. You said {command['text']}")
        demisto.debug("Message sent to slack")
    except Exception as e:
        await respond(f"An error occurred while processing your command: {e}")
        demisto.debug(f"Error while processing: {e}")


def main():
    app = App(token="xoxb-2700273429121-4658356427058-J3KImm73zh08kyWDGBqAeBEE")
    try:
        if command == 'long-running-execution':
            run_long_running(params, app)
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as e:
        demisto.error(traceback.format_exc())
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)
