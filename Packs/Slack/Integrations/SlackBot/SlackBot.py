import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from multiprocessing import Process
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk import WebClient
import demisto_sdk
import json
import logging
import os
import random
import re
import requests
import subprocess
import sys
from demisto_sdk.commands.common.clients import get_client_from_server_type


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# Set default logging
logging.basicConfig(level=logging.INFO)

# Set integration parameters
SLACK_BOT_TOKEN = demisto.params().get("bot_token", {}).get("password", "")
SLACK_APP_TOKEN = demisto.params().get("app_token", {}).get("password", "")
DEDICATED_CHANNEL = demisto.params().get("dedicated_slack_channel_name")
DEMISTO_API_KEY = demisto.params().get("api_key", {}).get("password", "")
DEMISTO_BASE_URL = demisto.params().get("base_url")
XSIAM_AUTH_ID = demisto.params().get("api_key_id")
TRUST = argToBoolean(demisto.params().get("insecure", False))

# Instantiate the App Class
try:
    app = App(token=SLACK_BOT_TOKEN)
except Exception as e:
    return_error("Invalid Bot Token.")

# Set OS environment variables for Demisto SDK
os.environ["DEMISTO_API_KEY"] = DEMISTO_API_KEY
os.environ["DEMISTO_KEY"] = DEMISTO_API_KEY
os.environ["DEMISTO_BASE_URL"] = DEMISTO_BASE_URL
if TRUST == False:
    DEMISTO_VERIFY_SSL = True
    os.environ["DEMISTO_VERIFY_SSL"] = str(True)
else:
    DEMISTO_VERIFY_SSL = False
    os.environ["DEMISTO_VERIFY_SSL"] = str(False)

if XSIAM_AUTH_ID:
    os.environ["XSIAM_AUTH_ID"] = XSIAM_AUTH_ID


########################
### MODULE FUNCTIONS ###
########################


"""
    Helper function used to run the `demisto-sdk run` command.
    Utilizes the subprocess Python library and collects input from end users via the /xsoar-run-command modal.

    Args:
      cmd: str -> Command selected by the user while running the /xsoar-run-command slash command.

      arguments: str -> Arguments entered by the user while running the /xsoar-run-command slash command.

      incident_id: str -> If specified by the user while running the /xsoar-run-command, runs the command against an incident instead of the playground.
"""
def demisto_sdk_run(cmd, arguments, incident_id=None, should_return=True, is_xsoar_list=False):
    try:
        c = get_client_from_server_type(base_url=DEMISTO_BASE_URL, api_key=DEMISTO_API_KEY,
                                        auth_id=XSIAM_AUTH_ID, verify_ssl=DEMISTO_VERIFY_SSL)
        entries, context = c.run_cli_command(f"{cmd} {arguments}", investigation_id=incident_id, should_delete_context=False)

        if should_return:
            war_room_entries = []

            if is_xsoar_list:
                for entry in entries:
                    war_room_entry = entry.__dict__
                    war_room_entry = war_room_entry.get("_contents")
                    final_str = war_room_entry.split("\n",2)[2]
                    return final_str
            else:
                for entry in entries:
                    modified_entry = entry.__dict__
                    war_room_entries.append(modified_entry.get("_contents"))

            return war_room_entries

    except Exception as e:
        logging.error(e)
        error = "Command did not run successfully. Please verify that you have submitted the command with the correct arguments and required syntax."
        return error


"""
    Helper function used to run the `demisto-sdk run` command.
    Utilizes the subprocess Python library and collects input from end users via the /xsoar-run-command modal.

    Args:
      cmd: str -> Command selected by the user while running the /xsoar-run-command slash command.

      arguments: str -> Arguments entered by the user while running the /xsoar-run-command slash command.

      incident_id: str -> If specified by the user while running the /xsoar-run-command, runs the command against an incident instead of the playground.
"""
def demisto_sdk_run_playbook(playbook, timeout="90 seconds", wait=False):
    try:
        # Convert the timeout value
        timeout_conversion = convert_playbook_timeout(timeout=timeout)

        cmd_list = ["demisto-sdk", "run-playbook", "-p", f"{playbook}", "-t", f"{timeout_conversion}"]

        if wait:
            cmd_list.append("-w")
        else:
            cmd_list.append("-n")

        if TRUST:
            cmd_list.append("--insecure")

        result = subprocess.run(
            cmd_list,
            stdout = subprocess.PIPE,
            stderr = subprocess.STDOUT,
            text = True
        )

        # Remove ANSI color coded output via regex matching
        if result:
            pattern = "(?<=\[32m)([\s\S]*)(?=\[0m)"
            regex_result = re.search(pattern, result.stdout)

            if regex_result.group():
                parsed = regex_result.group()
                return parsed.replace("[32m", "").replace("[0m", "").replace("[INFO]", "").strip()

    except Exception as e:
        logging.error(e)
        error = "Command did not run successfully. Please verify that you have submitted the command with the correct arguments and required syntax."
        return error


"""
    Sends a test message to the dedicated slack channel (if configured).
    Runs a test command in the API user's playground to test the Demisto SDK functionality
"""
def test_module():
    if not SLACK_BOT_TOKEN.startswith("xoxb"):
        return_error("Invalid Bot Token.")
    if not SLACK_APP_TOKEN.startswith("xapp"):
        return_error("Invalid App Token.")
    if DEDICATED_CHANNEL:
        message = "Hello from the XSOAR SlackBot! Please use the `/xsoar-help` slash command to get started."
        try:
            # Call the conversations.list method using the WebClient
            result = app.client.chat_postMessage(
                channel=DEDICATED_CHANNEL,
                text=message
            )

        except Exception as e:
            return_error(f"Error while sending message to dedicated Slack channel. {e}")
    # Test the demisto-sdk
    sdk_result = demisto_sdk_run(cmd="Print", arguments="value=\"Test from the SlackBot integration\"")
    if not sdk_result:
        return_error("Please ensure the API Key and Base URL are set appropriately for the demisto-sdk to function.")

    demisto.results('ok')


########################
### HELPER FUNCTIONS ###
########################


"""
    Helper function used to convert the numerical value of an XSOAR incident status to the associated str representation.

    Args:
      status_code: str -> status code returned from the demisto.createIncidents() command in int format.
"""
def map_status_code(status_code):
    try:
        status_codes = {
            0: "Pending",
            1: "Active",
            2: "Closed"
        }

        return status_codes.get("status_code", "Pending")

    except Exception as e:
        logging.error(e)


"""
    Helper function used to convert the str value of the submitted playbook timeout value to the associated int representation.

    Args:
      timeout: str -> Slack modal view submission input represented in str format. Defaults to '90 seconds'.
"""
def convert_playbook_timeout(timeout="90 seconds"):
    try:
        if timeout == "10 seconds":
            conversion = 10
        elif timeout == "30 seconds":
            conversion = 30
        elif timeout == "1 minute":
            conversion = 60
        elif timeout == "90 seconds":
            conversion = 90
        elif timeout == "2 minutes":
            conversion = 120
        elif timeout == "5 minutes":
            conversion = 300
        elif timeout == "10 minutes":
            conversion = 600
        else:
            conversion = 90

        return conversion

    except Exception as e:
        logging.error(e)


"""
    Helper function used to import XSOAR lists via the demisto-sdk run command, and convert JSON to a Slack modal view.

    Args:
      list_name: str -> Provide an XSOAR list name in str format.
      include_list: bool -> Used primarily when loading XSOAR lists that contain a list of dictionaries (i.e., success/failure response blocks). Defaults to False.
"""
def get_xsoar_list(list_name):
    try:
        return demisto_sdk_run(cmd="getList", arguments=f"listName={list_name}", incident_id=None, should_return=True, is_xsoar_list=True)

    except Exception as e:
        logging.error(e)


"""
    Helper function used to download the modal view submission as a JSON file to be used for classification and mapping.

    Args:
      filename: str -> Provide a name for the JSON mapper file.
      data: dict -> Use the view submission results as the file contents.
"""
def create_json_mapper_file(filename, data):
    try:
        demisto_sdk_run("FileCreateAndUploadV2", f"filename={filename} data=`{data}`", should_return=False)

    except Exception as e:
        logging.error(e)


"""
    Helper function used to load the success message XSOAR JSON list template and replace dynamic values to send back a custom Slack message to user/channel.

    Args:
      created_incident: list -> List object returned from running the demisto.createIncidents() command.
"""
def craft_incident_trigger_success_message(created_incident):
    try:
        # Define incident variables from created incident
        incident_name = created_incident[0].get("name")
        incident_id = created_incident[0].get("id")
        incident_type = created_incident[0].get("type")
        submitted_by = created_incident[0].get("CustomFields").get("slackdisplayname")
        created_at = created_incident[0].get("created")
        incident_status = map_status_code(created_incident[0].get("status"))

        # Load the success message XSOAR list template
        success_message = get_xsoar_list(list_name="SlackIncidentTriggerSuccess")

        # Parse through template and replace dynamic variables
        success_message = json.loads(success_message)
        success_message[2]["fields"][0]["text"] = f"*Incident Name:*\n{incident_name}"
        success_message[2]["fields"][1]["text"] = f"*Incident ID:*\n{incident_id}"
        success_message[3]["fields"][0]["text"] = f"*Incident Type:*\n{incident_type}"
        success_message[3]["fields"][1]["text"] = f"*Submitted By:*\n@{submitted_by}"
        success_message[4]["fields"][0]["text"] = f"*Created At:*\n{created_at}"
        success_message[4]["fields"][1]["text"] = f"*Incident Status:*\n{incident_status}"

        return success_message

    except Exception as e:
        logging.error(e)


"""
    Helper function used to query playbooks in XSOAR and return the available playbooks.

    Args:
      slack_object: str -> Returns either options (static select in Slack), playbook descriptions.

      parameters: options,comments_only
"""
def get_available_playbooks(slack_object):
    try:
        playbook_request = demisto.internalHttpRequest(method="GET", uri="/playbooks/metadata")
        playbooks = json.loads(playbook_request.get("body"))
        available_playbooks = []
        value = 1

        for playbook in playbooks:
            if slack_object == "options":
                if playbook.get("name"):
                    playbook_name = playbook.get("name")
                    slack_playbook_option_object = {
                        "text": {
                            "type": "plain_text",
                            "text": playbook_name
                        },
                        "value": f"playbook-{value}"
                    }
                    available_playbooks.append(slack_playbook_option_object)

                    value += 1

            if slack_object == "comments_only":
                arg_object = {
                    "playbook": playbook.get("name"),
                    "comment": playbook.get("comment", "No description defined.")
                }

                available_playbooks.append(arg_object)



        # Create the option groups in Slack that will populate with available playbooks
        if available_playbooks:
            if slack_object == "options":
                option_groups = []
                count = 1

                for i in range(0, len(available_playbooks), 100):
                    option_group = {
                        "label": {
                            "type": "plain_text",
                            "text": f"Group {count}"
                        },
                        "options": available_playbooks[i:i+100]
                    }

                    option_groups.append(option_group)

                    count += 1

                if option_groups:
                    return option_groups

            else:
                return available_playbooks

    except Exception as e:
        logging.error(e)


"""
    Helper function used to query integrations in XSOAR and return the available commands.

    Args:
      slack_object: str -> Returns either options (static select in Slack), command arguments, or command descriptions.

      parameters: options,arguments,comments_only
"""
def get_available_integrations(slack_object):
    try:
        integration_command_request = demisto.internalHttpRequest(method="POST", uri="/integration/search", body='{\"query\":\"\"}')
        integration_commands = json.loads(integration_command_request.get("body"))

        enabled_instances = []
        available_commands = []

        # Parse integration command search results
        if integration_commands:
            instances = integration_commands.get("instances")

            for instance in instances:
                if instance.get("enabled") == "true":
                    enabled_instances.append(instance.get("brand"))

            configurations = integration_commands.get("configurations")


            for config in configurations:
                if config.get("name") in enabled_instances:
                    if config.get("integrationScript"):
                        commands = config.get("integrationScript").get("commands")

                        # Used for returning commands to the /xsoar-run-command Slack modal
                        if slack_object == "options":
                            if commands:
                                for integration in commands:
                                    if integration.get("name") not in available_commands:
                                        integration_command_name = integration.get("name")
                                        custom_slack_option = {
                                            "text": {
                                                "type": "plain_text",
                                                "text": integration_command_name
                                            },
                                            "value": f"command-value-{integration_command_name}"
                                        }

                                        available_commands.append(custom_slack_option)

                        # Used for returning command arguments to the /xsoar-run-command Slack modal
                        if slack_object == "arguments":
                            if commands:
                                for integration in commands:
                                    if integration.get("arguments"):
                                        for arg in integration.get("arguments"):
                                            arg_object = {
                                                "command": integration.get("name"),
                                                "arg_name": arg.get("name"),
                                                "arg_desc": arg.get("description"),
                                                "arg_required": arg.get("required"),
                                                "arg_predefined": arg.get("predefined", "No predefined argument options")
                                            }

                                            available_commands.append(arg_object)

                        # Used for returning command comments (descriptions) to the /xsoar-run-command Slack modal
                        if slack_object == "comments_only":
                            if commands:
                                for integration in commands:
                                    arg_object = {
                                        "command": integration.get("name"),
                                        "comment": integration.get("description", "No description defined.")
                                    }

                                    available_commands.append(arg_object)

        if available_commands:
            if slack_object == "arguments":
                # Sort the commands so that the required arguments will always be displayed first
                available_commands_sorted = sorted(available_commands, key=lambda x: x["arg_required"], reverse=True)
                return available_commands_sorted
            else:
                return available_commands

    except Exception as e:
        # logging.error(e)
        logging.error(e)


"""
    Helper function used to query integrations in XSOAR and return the available commands.

    Args:
      slack_object: str -> Returns either options (static select in Slack), command arguments, or command descriptions.

      parameters: options,arguments,comments_only

"""
def get_available_automations(slack_object):
    try:
        automation_command_request = demisto.internalHttpRequest(method="GET", uri="/automation/metadata")
        automation_commands = json.loads(automation_command_request.get("body"))
        available_commands = []

        # Parse automation command search results
        if automation_commands:
            for automation in automation_commands:

                # Used for returning commands to the /xsoar-run-command Slack modal
                if slack_object == "options":
                    automation_command_name = automation.get("name")
                    custom_slack_option = {
                        "text": {
                            "type": "plain_text",
                            "text": automation_command_name
                        },
                        "value": f"command-value-{automation_command_name}"
                    }

                    available_commands.append(custom_slack_option)

                # Used for returning command arguments to the /xsoar-run-command Slack modal
                if slack_object == "arguments":
                    if automation.get("arguments"):
                        for arg in automation.get("arguments"):
                            arg_object = {
                                "command": automation.get("name"),
                                "arg_name": arg.get("name"),
                                "arg_desc": arg.get("description"),
                                "arg_required": arg.get("required"),
                                "arg_predefined": arg.get("predefined", "No predefined argument options")
                            }

                            available_commands.append(arg_object)

                # Used for returning command comments (descriptions) to the /xsoar-run-command Slack modal
                if slack_object == "comments_only":
                    arg_object = {
                        "command": automation.get("name"),
                        "comment": automation.get("comment", "No description defined.")
                    }

                    available_commands.append(arg_object)

        if available_commands:
            if slack_object == "arguments":
                # Sort the commands so that the required arguments will always be displayed first
                available_commands_sorted = sorted(available_commands, key=lambda x: x["arg_required"], reverse=True)
                return available_commands_sorted
            else:
                return available_commands

    except Exception as e:
        logging.error(e)


"""
    Helper function used to parse through XSOAR automations and integrations and presents the options in Slack via an options group object.
"""
def get_available_commands():
    try:
        integrations = get_available_integrations(slack_object="options")
        automations = get_available_automations(slack_object="options")

        available_commands = integrations + automations

        # Deduplicate all commands
        if available_commands:
            deduped_commands = [i for n, i in enumerate(available_commands) if i not in available_commands[:n]]

        # Create the option groups in Slack that will populate with available commands
        if deduped_commands:
            option_groups = []
            count = 1

            for i in range(0, len(deduped_commands), 100):
                option_group = {
                    "label": {
                        "type": "plain_text",
                        "text": f"Group {count}"
                    },
                    "options": deduped_commands[i:i+100]
                }

                option_groups.append(option_group)

                count += 1

            if option_groups:
                return option_groups

    except Exception as e:
        logging.error(e)


"""
    Helper function used to parse through XSOAR automations and integrations and gather command comments (descriptions).

    Args:
      cmd: str -> Command selected by the user while running the /xsoar-run-command slash command.
"""
def get_command_comments(cmd):
    try:
        integrations = get_available_integrations(slack_object="comments_only")
        automations = get_available_automations(slack_object="comments_only")
        available_command_comments = integrations + automations

        if available_command_comments:
            deduped_command_comments = [i for n, i in enumerate(available_command_comments) if i not in available_command_comments[:n]]
            if deduped_command_comments:
                xsoar_cmd_comment = [d for d in deduped_command_comments if d["command"] == cmd]
                if xsoar_cmd_comment:
                    return xsoar_cmd_comment[0].get("comment")

    except Exception as e:
        logging.error(e)


"""
    Helper function used to parse through XSOAR playbooks and gather playbook comments (descriptions).

    Args:
      playbook: str -> Playbook selected by the user while running the /xsoar-run-playbook slash command.
"""
def get_playbook_comments(playbook):
    try:
        available_playbooks = get_available_playbooks(slack_object="comments_only")

        if available_playbooks:
            deduped_playbook_comments = [i for n, i in enumerate(available_playbooks) if i not in available_playbooks[:n]]
            if deduped_playbook_comments:
                xsoar_playbook_comment = [d for d in deduped_playbook_comments if d["playbook"] == playbook]
                if xsoar_playbook_comment:
                    return xsoar_playbook_comment[0].get("comment")

    except Exception as e:
        logging.error(e)


"""
    Helper function used to parse through XSOAR automations and integrations and gather command arguments.
"""
def get_command_arg_details():
    try:
        integrations = get_available_integrations(slack_object="arguments")
        automations = get_available_automations(slack_object="arguments")
        available_command_args = integrations + automations

        if available_command_args:
            deduped_command_args = [i for n, i in enumerate(available_command_args) if i not in available_command_args[:n]]
            if deduped_command_args:
                return deduped_command_args

    except Exception as e:
        logging.error(e)


"""
    Helper function that formats the results from the `get_command_arg_details` function for presentation in a Slack code block.

    Args:
      cmd: str -> Command selected by the user while running the /xsoar-run-command slash command.

      get_required_args: bool -> Set this to 'True' when you want to only return a list of required arguments rather than the entire arg object.
"""
def get_command_args_for_slack(cmd, get_required_args=False):
    try:
        command_arg_details = get_command_arg_details()
        commands_with_arguments = []
        required_args = []
        duplicate_key_names = []

        xsoar_cmd_args = [d for d in command_arg_details if d["command"] == cmd]

        if xsoar_cmd_args:
            for cmd_args in xsoar_cmd_args:
                if get_required_args:
                    if cmd_args.get("arg_required") == True:
                        required_args.append(cmd_args.get("arg_name"))
                else:
                    if cmd_args.get("arg_name") not in duplicate_key_names:
                        arg_name = cmd_args.get("arg_name")
                        arg_desc = cmd_args.get("arg_desc")
                        arg_required = cmd_args.get("arg_required")
                        arg_predefined = cmd_args.get("arg_predefined")
                        arg_to_return = f"Name: {arg_name}\nDescription: {arg_desc}\nRequired: {arg_required}\nPredefined: {arg_predefined}\n\n"

                        duplicate_key_names.append(arg_name)
                        commands_with_arguments.append(arg_to_return)

        if get_required_args:
            required_args = list(set(required_args))
            return required_args

        else:
            if commands_with_arguments:
                slack_cmd_args_block = "".join(commands_with_arguments)
                return slack_cmd_args_block

    except Exception as e:
        logging.error(e)


#############
### VIEWS ###
#############


def load_new_template():
    try:
        # Can add to this list or create your own loading screen messages/quips
        loading_screen_texts = [
            ":magic_wand: _Managing all the mischief..._ :zap:",
            ":shark: _Dun dun... Dun dun..._ :boat:\n\t\t\t - Insider Threat",
            ":new_moon: _Waiting... we are..._ :star:",
            ":anchor: _By the beard of Zeus!_ :man:",
            ":handball: _If you can dodge a wrench, *you can dodge a ransomware attack*_ :wrench:",
            ":email: _'You've been promoted to CEO, congratulations!_'\n\t\t\t\t\t\t - CEO\n\n *You sit on a throne of lies* :hook:",
            ":robot_face: _Come with me, if you want to quarantine some endpoints_:skull:"
        ]

        # Load the template as a Slack block and randomize the texts above
        loading_template = {
            "type": "modal",
            "title": {
                "type": "plain_text",
                "text": "Loading Slack Modal"
            },
            "close": {
                "type": "plain_text",
                "text": "Cancel"
            },
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": random.choice(loading_screen_texts)
                    }
                }
            ]
        }

        return loading_template

    except Exception as e:
        logging.error(e)


################
### APP HOME ###
################


# Default interface shown when opening the XSOAR Self Service App home page in Slack
@app.event("app_home_opened")
def update_home_tab(client, event):
    try:
        # # Acknowledge the request -- DO NOT REMOVE
        # ack()

        app_home_template = get_xsoar_list(list_name="SlackAppHome")

        res = client.views_publish(
            user_id = event.get("user"),
            view = app_home_template
        )

    except Exception as e:
        logging.error(e)


@app.action("xsoar-help-app-home-button-click")
def xsoar_help_app_home_button_click(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_open(
            trigger_id = body.get("trigger_id"),
            view = load_new_template()
        )

        help_view_template = get_xsoar_list(list_name="SlackHelp")

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = help_view_template
        )

    except Exception as e:
        logging.error(e)


@app.action("xsoar-run-command-app-home-button-click")
def xsoar_run_command_app_home(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_open(
            trigger_id = body.get("trigger_id"),
            view = load_new_template()
        )

        # Get available integration/automation commands
        command_options = get_available_commands()

        xsoar_run_command_template = get_xsoar_list(list_name="SlackRunCommand")
        xsoar_run_command_template = json.loads(xsoar_run_command_template)
        xsoar_run_command_template["blocks"][1]["accessory"]["option_groups"] = command_options

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = xsoar_run_command_template
        )

    except Exception as e:
        logging.error(e)


@app.action("xsoar-run-playbook-app-home-button-click")
def xsoar_run_playbook_app_home(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_open(
            trigger_id = body.get("trigger_id"),
            view = load_new_template()
        )

        # Get available scripts
        playbook_options = get_available_playbooks(slack_object="options")

        xsoar_run_playbook_template = get_xsoar_list("SlackRunPlaybook")
        xsoar_run_playbook_template = json.loads(xsoar_run_playbook_template)
        xsoar_run_playbook_template["blocks"][1]["accessory"]["option_groups"] = playbook_options

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = xsoar_run_playbook_template
        )

    except Exception as e:
        logging.error(e)


@app.action("xsoar-create-ticket-app-home-button-click")
def xsoar_create_ticket_app_home(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_open(
            trigger_id = body.get("trigger_id"),
            view = load_new_template()
        )

        ticket_template = get_xsoar_list(list_name="SlackTicket")

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = get_xsoar_list(list_name="SlackTicket")
        )

    except Exception as e:
        logging.error(e)


@app.action("xsoar-indicator-actions-app-home-button-click")
def xsoar_indicator_actions_app_home(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_open(
            trigger_id = body.get("trigger_id"),
            view = load_new_template()
        )

        indicator_actions_view_template = get_xsoar_list("SlackIndicatorActions")

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = indicator_actions_view_template
        )

    except Exception as e:
        logging.error(e)


######################
### MESSAGE EVENTS ###
######################


@app.message(":wave:")
def say_wave(ack, message, say, body):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        user = message["user"]
        say(text=f"Hi there, <@{user}>! Right back at ya! :wave:")

    except Exception as e:
        logging.error(e)


@app.message("hello|hi|hey")
def say_hello(ack, message, say, body):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        user = message["user"]
        say(text=f"Hi there, <@{user}>! Thanks for the greeting!")

    except Exception as e:
        logging.error(e)


@app.message("help|need help|I need help")
def say_help(ack, message, say, body):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        user = message["user"]
        help_blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Hi there, <@{user}>! Please use the `/help` command to open the Help modal."
                }
            }
        ]

        say(blocks=help_blocks)

    except Exception as e:
        logging.error(e)


######################
### MENTION EVENTS ###
######################


# Responds to the user when the app is mentioned in a channel
@app.event("app_mention")
def say_mention(event, body, say):
    try:
        say(f"Hi there, thanks for thinking of me! :)")

    except Exception as e:
        logging.error(e)


##############################################################################
                        ######################
                        ### SLASH COMMANDS ###
                        ######################
##############################################################################

###################
### /XSOAR-HELP ###
###################


# The /help command will open the help modal to aid in application usage
@app.command("/xsoar-help")
def xsoar_help(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_open(
            trigger_id = body.get("trigger_id"),
            view = load_new_template()
        )

        help_view_template = get_xsoar_list(list_name="SlackHelp")

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = help_view_template
        )

    except Exception as e:
        logging.error(e)


@app.action("xsoar-integration-docs-button-click")
def xsoar_integration_docs_button_click(ack, body):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

    except Exception as e:
        logging.error(e)


@app.action("slack-bolt-docs-button-click")
def slack_bolt_docs_button_click(ack, body):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

    except Exception as e:
        logging.error(e)


@app.action("block-kit-builder-button-click")
def block_kit_builder_button_click(ack, body):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

    except Exception as e:
        logging.error(e)


@app.action("xsoar-aha-button-click")
def xsoar_aha_button_click(ack, body):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

    except Exception as e:
        logging.error(e)


@app.action("xsoar-indicator-actions-help-button-click")
def xsoar_indication_actions_button_click(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_update(
            view_id = body.get("view").get("id"),
            hash = body.get("view").get("hash"),
            view = load_new_template()
        )

        indicator_actions_view_template = get_xsoar_list("SlackIndicatorActions")

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = indicator_actions_view_template
        )

    except Exception as e:
        logging.error(e)


@app.action("xsoar-create-ticket-help-button-click")
def xsoar_create_ticket_button_click(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_update(
            view_id = body.get("view").get("id"),
            hash = body.get("view").get("hash"),
            view = load_new_template()
        )

        ticket_template = get_xsoar_list(list_name="SlackTicket")

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = get_xsoar_list(list_name="SlackTicket")
        )

    except Exception as e:
        logging.error(e)


@app.action("xsoar-run-command-help-button-click")
def xsoar_run_command_button_click(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_update(
            view_id = body.get("view").get("id"),
            hash = body.get("view").get("hash"),
            view = load_new_template()
        )

        # Get available integration/automation commands
        command_options = get_available_commands()

        xsoar_run_command_template = get_xsoar_list(list_name="SlackRunCommand")
        xsoar_run_command_template = json.loads(xsoar_run_command_template)
        xsoar_run_command_template["blocks"][1]["accessory"]["option_groups"] = command_options

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = xsoar_run_command_template
        )

    except Exception as e:
        logging.error(e)


@app.action("xsoar-run-playbook-help-button-click")
def xsoar_run_playbook_button_click(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_update(
            view_id = body.get("view").get("id"),
            hash = body.get("view").get("hash"),
            view = load_new_template()
        )

        # Get available scripts
        playbook_options = get_available_playbooks(slack_object="options")

        xsoar_run_playbook_template = get_xsoar_list("SlackRunPlaybook")
        xsoar_run_playbook_template = json.loads(xsoar_run_playbook_template)
        xsoar_run_playbook_template["blocks"][1]["accessory"]["option_groups"] = playbook_options

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = xsoar_run_playbook_template
        )

    except Exception as e:
        logging.error(e)


##############################################################################

##########################
### /XSOAR-RUN-COMMAND ###
##########################

# The /xsoar-run-command will use the demisto-sdk to run a command in the Playground CLI
@app.command("/xsoar-run-command")
def xsoar_run_command(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_open(
            trigger_id = body.get("trigger_id"),
            view = load_new_template()
        )

        # Get available integration/automation commands
        command_options = get_available_commands()

        xsoar_run_command_template = get_xsoar_list(list_name="SlackRunCommand")
        xsoar_run_command_template = json.loads(xsoar_run_command_template)
        xsoar_run_command_template["blocks"][1]["accessory"]["option_groups"] = command_options

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = xsoar_run_command_template
        )

    except Exception as e:
        logging.error(e)


@app.action("xsoar-playground-cmd")
def xsoar_playground_cmd_selection(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        # Store the Slack form input parameters in a list
        action_keys = list(body["view"]["state"]["values"].keys())

        cmd_selection_field = action_keys[0]

        cmd_selected = body["view"]["state"]["values"][cmd_selection_field]["xsoar-playground-cmd"]["selected_option"]["text"]["text"]
        cmd_value_selected = body["view"]["state"]["values"][cmd_selection_field]["xsoar-playground-cmd"]["selected_option"]["value"]

        # Get available integration commands / automation scripts
        command_options = get_available_commands()

        # Get available cmd arguments
        slack_cmd_args = get_command_args_for_slack(cmd=cmd_selected)

        # Retrieve required arguments
        required_args = get_command_args_for_slack(cmd=cmd_selected, get_required_args=True)

        # Get available cmd comment (description)
        slack_cmd_comment = get_command_comments(cmd=cmd_selected)

        # Set flag for arguments if optional (by command)
        # Slack modal will display optional if no args are mandatory for the selected command
        if required_args:
            # No mandatory command args
            cmd_args_optional = False
        else:
            # Mandatory command args exist
            cmd_args_optional = True

        # Update the modal to reflect the command description, arguments, and inputs
        xsoar_run_command_update = get_xsoar_list("SlackRunCommandUpdate")
        xsoar_run_command_update = json.loads(xsoar_run_command_update)
        xsoar_run_command_update["blocks"][1]["accessory"]["initial_option"]["text"]["text"] = cmd_selected
        xsoar_run_command_update["blocks"][1]["accessory"]["initial_option"]["value"] = cmd_value_selected
        xsoar_run_command_update["blocks"][1]["accessory"]["option_groups"] = command_options
        xsoar_run_command_update["blocks"][2]["elements"][1]["elements"][0]["text"] = slack_cmd_comment
        xsoar_run_command_update["blocks"][3]["elements"][1]["elements"][0]["text"] = str(required_args)
        xsoar_run_command_update["blocks"][5]["elements"][1]["elements"][0]["text"] = slack_cmd_args
        xsoar_run_command_update["blocks"][6]["optional"] = cmd_args_optional

        res = client.views_update(
            view_id = body["view"]["id"],
            hash = body["view"]["hash"],
            trigger_id = body["trigger_id"],
            view = xsoar_run_command_update
        )

    except Exception as e:
        logging.error(e)


@app.view("xsoar-run-command")
def view_xsoar_run_command_submission(ack, body, client, say):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        # Set any necessary variable(s)
        user_id = body["user"]["id"]
        user_name = body["user"]["name"]

        # Store the Slack form input parameters in a list
        action_keys = list(body["view"]["state"]["values"].keys())

        playground_cmd = action_keys[0]
        playground_cmd_args = action_keys[1]
        xsoar_incident_id = action_keys[2]

        """
        The first key (index 0) will always be the playground cmd entered by the end user
        The second key (index 1) will always be the cmd args entered by the end user
        """

        playground_cmd_selected = body["view"]["state"]["values"][playground_cmd]["xsoar-playground-cmd"]["selected_option"]["text"]["text"]
        playground_cmd_args_selected = body["view"]["state"]["values"][playground_cmd_args]["xsoar-playground-cmd-args"]["value"]
        xsoar_incident_id_selected = body["view"]["state"]["values"][xsoar_incident_id]["xsoar-incident-id"]["value"]

        notification_block = [
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"@{user_name} is attempting to run the following command in the XSOAR playground: `{playground_cmd_selected} {playground_cmd_args_selected}`"
                }
            }
        ]

        if xsoar_incident_id_selected:
            notification_block[1]["text"]["text"] = f"{user_name} is attempting to run the following command in the Incident `{xsoar_incident_id_selected}` War Room: `{playground_cmd_selected} {playground_cmd_args_selected}`"

        if not playground_cmd_args_selected:
            notification_block[1]["text"]["text"] = f"@{user_name} is attempting to run the following command in the XSOAR playground: `{playground_cmd_selected}`"

        # Grab the integration parameter for a dedicated slack channel
        # If statement exists to check if the dedicated slack channel param is set
        if DEDICATED_CHANNEL:
            say(channel=DEDICATED_CHANNEL, blocks=notification_block)

        # Else, send it to the originating user
        else:
            say(channel=user_id, blocks=notification_block)

        # Attempt to run the command and send a success message (if successful)
        result = demisto_sdk_run(cmd=playground_cmd_selected, arguments=playground_cmd_args_selected, incident_id=xsoar_incident_id_selected)

        success_cmd_block = [
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":arrow_down_small: Here are the results from the `!{playground_cmd_selected}` command:\n\n```{result}```"
                }
            }
        ]

        failure_response_blocks = [
            {
                "type": "divider"
            },
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Oh No!",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":x: Your request to run `{playground_cmd_selected}` could not be submitted successfully, we _*sincerely* apologize for the inconvenience_. :disappointed:\n\n Please try submitting your request again using `/xsoar-run-command`. Thank you!"
                }
            },
            {
                "type": "divider"
            }
        ]

        if result:
            # Due to larger output from some commands (such as VirusTotal) -- we will split the commands into separate code blocks
            # This greatly improves readability over sending a large text block
            if len(result) > 3000:
                # result = slice(0, 2999)
                for i in range(0, len(result), 2499):
                    formatted_result = result[i:i+2499]

                    success_cmd_block = [
                        {
                            "type": "divider"
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f":arrow_down_small: Here are the results from your command:\n\n```{formatted_result}```"
                            }
                        }
                    ]

                    say(channel=user_id, blocks=success_cmd_block)

            # If the message is less than 3000 characters, then send a single message as a code block
            else:
                say(channel=user_id, blocks=success_cmd_block)

    # The command did not run successfully -- recommend double checking that valid arguments were passed in the specified format
    # Check server logs for debugging
    except Exception as e:
        say(channel=user_id, blocks=failure_response_blocks)
        logging.error(e)


##############################################################################

###########################
### /XSOAR-RUN-PLAYBOOK ###
###########################


# The /xsoar-run-command will use the demisto-sdk to run a command in the Playground CLI
@app.command("/xsoar-run-playbook")
def xsoar_run_playbook(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_open(
            trigger_id = body.get("trigger_id"),
            view = load_new_template()
        )

        # Get available playbooks
        playbook_options = get_available_playbooks(slack_object="options")

        xsoar_run_playbook_template = get_xsoar_list("SlackRunPlaybook")
        xsoar_run_playbook_template = json.loads(xsoar_run_playbook_template)
        xsoar_run_playbook_template["blocks"][1]["accessory"]["option_groups"] = playbook_options

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = xsoar_run_playbook_template
        )

    except Exception as e:
        logging.error(e)


@app.action("xsoar-playbook-selection")
def xsoar_playground_cmd_selection(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        # Store the Slack form input parameters in a list
        action_keys = list(body["view"]["state"]["values"].keys())

        playbook_selection_field = action_keys[0]

        playbook_selected = body["view"]["state"]["values"][playbook_selection_field]["xsoar-playbook-selection"]["selected_option"]["text"]["text"]
        playbook_value_selected = body["view"]["state"]["values"][playbook_selection_field]["xsoar-playbook-selection"]["selected_option"]["value"]

        # Get available integration commands / automation scripts
        playbook_options = get_available_playbooks(slack_object="options")

        # Retrieve the playbook comment (description) for the selected playbook
        slack_playbook_comment = get_playbook_comments(playbook=playbook_selected)

        # Update the modal to reflect the playbook description and inputs
        xsoar_run_playbook_update = get_xsoar_list("SlackRunPlaybookUpdate")
        xsoar_run_playbook_update = json.loads(xsoar_run_playbook_update)
        xsoar_run_playbook_update["blocks"][1]["accessory"]["initial_option"]["text"]["text"] = playbook_selected
        xsoar_run_playbook_update["blocks"][1]["accessory"]["initial_option"]["value"] = playbook_value_selected
        xsoar_run_playbook_update["blocks"][1]["accessory"]["option_groups"] = playbook_options
        xsoar_run_playbook_update["blocks"][2]["elements"][1]["elements"][0]["text"] = slack_playbook_comment

        res = client.views_update(
            view_id = body["view"]["id"],
            hash = body["view"]["hash"],
            trigger_id = body["trigger_id"],
            view = xsoar_run_playbook_update
        )

    except Exception as e:
        logging.error(e)


@app.view("xsoar-run-playbook")
def view_xsoar_run_command_submission(ack, body, client, say):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        # Set any necessary variable(s)
        user_id = body["user"]["id"]
        user_name = body["user"]["name"]

        # Store the Slack form input parameters in a list
        action_keys = list(body["view"]["state"]["values"].keys())

        playbook_selection_field = action_keys[0]
        playbook_timeout_field = action_keys[1]
        playbook_wait_field = action_keys[2]


        """
        The first key (index 0) will always be the ticket type selected by the end user
        """

        playbook_selected = body["view"]["state"]["values"][playbook_selection_field]["xsoar-playbook-selection"]["selected_option"]["text"]["text"]
        timeout_selected = body["view"]["state"]["values"][playbook_timeout_field]["playbook-timeout-selection"]["selected_option"]["text"]["text"]
        wait_selected = body["view"]["state"]["values"][playbook_wait_field]["playbook-wait-selection"]["selected_option"]["text"]["text"]

        notification_block = [
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"@{user_name} is attempting to run the following playbook: `{playbook_selected}`"
                }
            }
        ]

        # Grab the integration parameter for a dedicated slack channel
        # If statement exists to check if the dedicated slack channel param is set
        if DEDICATED_CHANNEL:
            say(channel=DEDICATED_CHANNEL, blocks=notification_block)

        # Else, send it to the originating user
        else:
            say(channel=user_id, blocks=notification_block)

        if wait_selected == "True":
            wait_selected = True
        else:
            wait_selected = False

        result = demisto_sdk_run_playbook(playbook=playbook_selected, timeout=timeout_selected, wait=wait_selected)

        success_response_blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":arrow_down_small: Here are the results from your command:\n\n```{result}```"
                }
            }
        ]


        say(channel=user_id, blocks=success_response_blocks)

    except Exception as e:
        say(channel=user_id, text=f"Error: {e}")
        logging.error(f"Error: {e}")


##############################################################################

############################
### /XSOAR-CREATE-TICKET ###
############################


# The /xsoar-create-ticket command will open the help modal to aid in application usage
@app.command("/xsoar-create-ticket")
def xsoar_create_ticket(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_open(
            trigger_id = body.get("trigger_id"),
            view = load_new_template()
        )

        ticket_template = get_xsoar_list(list_name="SlackTicket")

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = ticket_template
        )

    except Exception as e:
        logging.error(e)


@app.action("vendor-ticket-selection")
def vendor_ticket_selection(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        # Store the Slack form input parameters in a list
        action_keys = list(body["view"]["state"]["values"].keys())

        ticket_selection_field = action_keys[0]

        ticket_type_selected = body["view"]["state"]["values"][ticket_selection_field]["vendor-ticket-selection"]["selected_option"]["text"]["text"]

        if ticket_type_selected == "ServiceNow":
            selected_view = get_xsoar_list(list_name="SlackServiceNowTicket")
        elif ticket_type_selected == "Jira":
            selected_view = get_xsoar_list(list_name="SlackJiraTicket")
        elif ticket_type_selected == "Zendesk":
            selected_view = get_xsoar_list(list_name="SlackZendeskTicket")
        else:
            selected_view = get_xsoar_list(list_name="SlackTicket")

        if selected_view:
            res = client.views_update(
                view_id = body["view"]["id"],
                hash = body["view"]["hash"],
                trigger_id = body["trigger_id"],
                view = selected_view
            )

    except Exception as e:
        logging.error(e)


@app.view("xsoar-create-ticket")
def view_xsoar_create_tickets_submission(ack, body, client, say):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        # Set any necessary variable(s)
        user_id = body["user"]["id"]

        # Store the Slack form input parameters in a list
        action_keys = list(body["view"]["state"]["values"].keys())

        """
        Each index below is relative to each form input within the Slack modal

        The first key (index 0) will always be the ticket type selected by the end user
        The third key (index 2) will always be the ticket subject (Short Description for ServiceNow and Summary for Jira)
        """

        ticket_selection_field = action_keys[0]
        ticket_subject = action_keys[2]

        ticket_type_selected = body["view"]["state"]["values"][ticket_selection_field]["vendor-ticket-selection"]["selected_option"]["text"]["text"]

        if ticket_type_selected == "ServiceNow" or ticket_type_selected == "Zendesk":
            """
            Selects the appropriate index to identify the Download JSON Mapper option

            This will be relative to each ticket type, as the Jira ticket has one additional input which extends the index by one
            """
            download_json_mapper_file_value = action_keys[5] # Can specify -1 for index if it will always be the last element
        elif ticket_type_selected == "Jira":
            download_json_mapper_file_value = action_keys[6]
        else:
            download_json_mapper_file_value = action_keys[5]

        subject = body["view"]["state"]["values"][ticket_subject]["ticket-subject"]["value"]
        download_json_mapper_file = body["view"]["state"]["values"][download_json_mapper_file_value]["download-json-mapper-file"]["selected_option"]["text"]["text"]


        incidents = []
        create_ticket_incident = {
            "name": f"SlackBot Create {ticket_type_selected} Ticket - {subject}",
            "rawJSON": json.dumps(body)
        }
        incidents.append(create_ticket_incident)

        # Create the new incident
        new_incident = demisto.createIncidents(incidents=incidents)

        # Craft the success message and send to channel or user
        success_response_blocks = craft_incident_trigger_success_message(created_incident=new_incident)

        # Grab the integration parameter for a dedicated slack channel
        # If statement exists to check if the dedicated slack channel param is set
        if DEDICATED_CHANNEL:
            say(channel=DEDICATED_CHANNEL, blocks=success_response_blocks)

        # Else, send it to the originating user
        else:
            say(channel=user_id, blocks=success_response_blocks)


        # Create the JSON mapper file if the user selected this option
        if download_json_mapper_file == "Yes":
            filename = f"SlackBot_Create_{ticket_type_selected}_Ticket_Mapper.json"
            create_json_mapper_file(filename=filename, data=json.dumps(body))


    except Exception as e:
        # Craft the failure message and send to user
        failure_response_blocks = get_xsoar_list(list_name="SlackIncidentTriggerFailure")
        say(channel=user_id, blocks=failure_response_blocks)
        logging.error(f"Error: {e}")


##############################################################################
# The /indicator-actions command will allow users to perform actions on indicators in XSOAR

################################
### /XSOAR-INDICATOR-ACTIONS ###
################################


@app.command('/xsoar-indicator-actions')
def indicator_actions_command(ack, body, client, logger):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_open(
            trigger_id = body.get("trigger_id"),
            view = load_new_template()
        )

        indicator_actions_view_template = get_xsoar_list("SlackIndicatorActions")

        res = client.views_update(
            view_id = load.get("view").get("id"),
            hash = load.get("view").get("hash"),
            view = indicator_actions_view_template
        )

    except Exception as e:
        logging.error(e)


@app.action("indicator-select-action")
def indicator_action_selection(ack, body, logger):
    try:
        ack()

    except Exception as e:
        logging.error(e)


@app.action("update-on-demand-only-action")
def update_on_demand_selection(ack, body, logger):
    try:
        ack()

    except Exception as e:
        logging.error(e)


@app.view("xsoar-indicator-actions")
def view_xsoar_indicator_actions_submission(ack, body, client, say):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        # Set any necessary variable(s)
        user_id = body["user"]["id"]

        # Store the Slack form input parameters in a list
        action_keys = list(body["view"]["state"]["values"].keys())

        """
        Each index below is relative to each form input within the Slack modal

        The first key (index 0) will always be the indicator value entered by the end user (first input of modal)
        The second key (index 1) will always be the indicator action selected by the end user (second input of modal)
        The third key (index 2) will always be the indicator tag name entered by the end user (third input of modal)
        The fourth key (index 4) will always be the Update on Demand Only action selected by the end user (fourth input of modal)
        The fifth key (index 5) will always be the JSON mapper option selected by the end user (fifth input of modal)
        """
        indicator_value = action_keys[0]
        indicator_action = action_keys[1]
        indicator_tag_name = action_keys[2]
        indicator_update_on_demand_only = action_keys[3]
        download_json_mapper_file_value = action_keys[4] # Can specify -1 for index if it will always be the last element

        # Set human readable variables for the Slack form inputs
        indicator = body["view"]["state"]["values"][indicator_value]["indicator-value"]["value"]
        action = body["view"]["state"]["values"][indicator_action]["indicator-select-action"]["selected_option"]["text"]["text"]
        tag_name = body["view"]["state"]["values"][indicator_tag_name]["indicator-tag-action"]["value"]
        update_on_demand_only = body["view"]["state"]["values"][indicator_update_on_demand_only]["update-on-demand-only-action"]["selected_option"]["text"]["text"]
        download_json_mapper_file = body["view"]["state"]["values"][download_json_mapper_file_value]["download-json-mapper-file"]["selected_option"]["text"]["text"]

        incidents = []
        indicator_actions_incident = {
            "name": f"SlackBot Indicator Actions - {action} {indicator}",
            "rawJSON": json.dumps(body)
        }
        incidents.append(indicator_actions_incident)

        # Create the new incident
        new_incident = demisto.createIncidents(incidents=incidents)

        # Craft the success message and send to channel or user
        success_response_blocks = craft_incident_trigger_success_message(created_incident=new_incident)

        # Grab the integration parameter for a dedicated slack channel
        # If statement exists to check if the dedicated slack channel param is set
        if DEDICATED_CHANNEL:
            say(channel=DEDICATED_CHANNEL, blocks=success_response_blocks)

        # Else, send it to the originating user
        else:
            say(channel=user_id, blocks=success_response_blocks)

        # Create the JSON mapper file if the user selected this option
        if download_json_mapper_file == "Yes":
            filename = "SlackBot_Indicator_Actions_Mapper.json"
            create_json_mapper_file(filename=filename, data=json.dumps(body))

    except Exception as e:
        # Craft the failure message and send to user
        failure_response_blocks = get_xsoar_list(list_name="SlackIncidentTriggerFailure")
        say(channel=user_id, blocks=failure_response_blocks)
        logging.error(f"Error: {e}")


###############################################################################################################################################################################################################

                                                                                        ##################################
                                                                                        ### START NEW DEVELOPMENT HERE ###
                                                                                        ##################################

###############################################################################################################################################################################################################


#####################
### MAIN FUNCTION ###
#####################


# Main function that handles the Slack Bot application handler
def main():
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration Test button.
        result = test_module()
        return_results(result)
    else:
        handler = SocketModeHandler(app, SLACK_APP_TOKEN)
        Process(target=handler)
        handler.start()


# Run the Slack Bot application
main()
