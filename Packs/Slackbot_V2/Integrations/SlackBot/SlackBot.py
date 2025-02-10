import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from multiprocessing import Process
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk import WebClient
import json
import os
import random
import requests
import subprocess
import sys
import demisto_client
import ast
from demisto_client.demisto_api.rest import ApiException

class StatusCode(Enum):
    PENDING = 0
    ACTIVE = 1
    CLOSED = 2

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# Set integration parameters
SLACK_BOT_TOKEN = demisto.params().get("bot_token", {}).get("password", "")
SLACK_APP_TOKEN = demisto.params().get("app_token", {}).get("password", "")
DEDICATED_CHANNEL = demisto.params().get("dedicated_slack_channel_name")
DEMISTO_API_KEY = demisto.params().get("api_key", {}).get("password", "")
DEMISTO_BASE_URL = demisto.params().get("base_url")
XSIAM_AUTH_ID = demisto.params().get("api_key_id")
ALLOWED_ROLES = demisto.params().get("roles").split(",")
# TRUST = argToBoolean(demisto.params().get("insecure", False))

# Instantiate the App Class
try:
    app = App(token=SLACK_BOT_TOKEN)
except Exception:
    return_error("Invalid Bot Token.")

# Instantiate the Demisto Client
api_instance = demisto_client.configure(base_url=DEMISTO_BASE_URL, api_key=DEMISTO_API_KEY, auth_id=XSIAM_AUTH_ID)


########################
### MODULE FUNCTIONS ###
########################


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
    # Test the demisto_client
    api_response = demisto_client.generic_request_func(self=api_instance, path="/xsoar/lists", method="GET")
    if api_response[1] != 200:
        return_error("Please ensure the API Key, Base URL and API key ID are set appropriately for the demisto_client to function.")

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
        status_mapping = {
        StatusCode.PENDING: "Pending",
        StatusCode.ACTIVE: "Active",
        StatusCode.CLOSED: "Closed"
        }
        return status_mapping.get(StatusCode(status_code), "Pending")

    except Exception as e:
        demisto.error(e)


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
        demisto.error(e)


"""Helper function is """


def find_list_by_listname(list_output, list_name):
    # Step 1: Attempt to safely evaluate the input string to a Python data structure
    try:
        data_list = ast.literal_eval(list_output)
    except (ValueError, SyntaxError) as e:
        demisto.error(f"Error evaluating data: {e}")
        return None  # Return None if there's an issue with parsing

    # Step 2: Search for the item with the matching id
    for item in data_list:
        if item.get('id') == list_name:
            return item.get('data')  # Return the 'data' field if the id matches

    return None  # Return None if the ID is not found


"""
    Helper function used to import XSOAR lists via demisto_client, and convert JSON to a Slack modal view.

    Args:
      list_name: str -> Provide an XSOAR list name in str format.
      include_list: bool -> Used primarily when loading XSOAR lists that contain a list of dictionaries (i.e., success/failure response blocks). Defaults to False.
"""


def get_xsoar_list(list_name):
    try:
        api_response = demisto_client.generic_request_func(self=api_instance, path="/xsoar/lists", method="GET")
        return (find_list_by_listname(api_response[0], list_name))
    except ApiException as e:
        demisto.error("Exception when calling generic api: %s\n" % e)


"""
Helper function to get channel id for uploading of files.
"""


def get_channel_id(channel_name, client):
    try:
        # Call the conversations.list method using the WebClient
        response = client.conversations_list()
        demisto.debug(f"Result from conv:{response}")

        # Check the channels in the response
        for channel in response["channels"]:
            if channel["name"] == channel_name:
                return channel["id"]

        demisto.debug("Channel not found")
        return None

    except Exception as e:
        demisto.error(f"Error fetching channels: {e}")
        return None


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
        if not created_incident[0].get("type"):
            incident_type = "Unclassified"
        else:
            incident_type = created_incident[0].get("type")
        submitted_by = json.loads(created_incident[0].get("rawJSON")).get("user").get("username")
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
        demisto.error(e)


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
        demisto.error(e)


################
### APP HOME ###
################


# Default interface shown when opening the XSOAR Self Service App home page in Slack
@app.event("app_home_opened")
def update_home_tab(client, event):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        app_home_template = get_xsoar_list(list_name="SlackAppHome")

        res = client.views_publish(
            user_id=event.get("user"),
            view=app_home_template
        )

    except Exception as e:
        demisto.error(e)


@app.action("xsoar-help-app-home-button-click")
def xsoar_help_app_home_button_click(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_open(
            trigger_id=body.get("trigger_id"),
            view=load_new_template()
        )

        help_view_template = get_xsoar_list(list_name="SlackHelp")

        res = client.views_update(
            view_id=load.get("view").get("id"),
            hash=load.get("view").get("hash"),
            view=help_view_template
        )

    except Exception as e:
        demisto.error(e)


@app.action("xsoar-create-ticket-app-home-button-click")
def xsoar_create_ticket_app_home(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_open(
            trigger_id=body.get("trigger_id"),
            view=load_new_template()
        )

        ticket_template = get_xsoar_list(list_name="SlackTicket")

        res = client.views_update(
            view_id=load.get("view").get("id"),
            hash=load.get("view").get("hash"),
            view=get_xsoar_list(list_name="SlackTicket")
        )

    except Exception as e:
        demisto.error(e)


@app.action("xsoar-indicator-actions-app-home-button-click")
def xsoar_indicator_actions_app_home(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_open(
            trigger_id=body.get("trigger_id"),
            view=load_new_template()
        )

        indicator_actions_view_template = get_xsoar_list("SlackIndicatorActions")

        res = client.views_update(
            view_id=load.get("view").get("id"),
            hash=load.get("view").get("hash"),
            view=indicator_actions_view_template
        )

    except Exception as e:
        demisto.error(e)


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
        demisto.error(e)


@app.message("hello|hi|hey")
def say_hello(ack, message, say, body):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        user = message["user"]
        say(text=f"Hi there, <@{user}>! Thanks for the greeting!")

    except Exception as e:
        demisto.error(e)


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
        demisto.error(e)


######################
### MENTION EVENTS ###
######################


# Responds to the user when the app is mentioned in a channel
@app.event("app_mention")
def say_mention(event, body, say):
    try:
        say(f"Hi there, thanks for thinking of me! :)")

    except Exception as e:
        demisto.error(e)


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
            trigger_id=body.get("trigger_id"),
            view=load_new_template()
        )

        help_view_template = get_xsoar_list(list_name="SlackHelp")

        res = client.views_update(
            view_id=load.get("view").get("id"),
            hash=load.get("view").get("hash"),
            view=help_view_template
        )

    except Exception as e:
        demisto.error(e)


@app.action("xsoar-integration-docs-button-click")
def xsoar_integration_docs_button_click(ack, body):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

    except Exception as e:
        demisto.error(e)


@app.action("slack-bolt-docs-button-click")
def slack_bolt_docs_button_click(ack, body):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

    except Exception as e:
        demisto.error(e)


@app.action("block-kit-builder-button-click")
def block_kit_builder_button_click(ack, body):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

    except Exception as e:
        demisto.error(e)


@app.action("xsoar-aha-button-click")
def xsoar_aha_button_click(ack, body):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

    except Exception as e:
        demisto.error(e)


@app.action("xsoar-indicator-actions-help-button-click")
def xsoar_indication_actions_button_click(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_update(
            view_id=body.get("view").get("id"),
            hash=body.get("view").get("hash"),
            view=load_new_template()
        )

        indicator_actions_view_template = get_xsoar_list("SlackIndicatorActions")

        res = client.views_update(
            view_id=load.get("view").get("id"),
            hash=load.get("view").get("hash"),
            view=indicator_actions_view_template
        )

    except Exception as e:
        demisto.error(e)


@app.action("xsoar-create-ticket-help-button-click")
def xsoar_create_ticket_button_click(ack, body, client):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        load = client.views_update(
            view_id=body.get("view").get("id"),
            hash=body.get("view").get("hash"),
            view=load_new_template()
        )

        ticket_template = get_xsoar_list(list_name="SlackTicket")

        res = client.views_update(
            view_id=load.get("view").get("id"),
            hash=load.get("view").get("hash"),
            view=get_xsoar_list(list_name="SlackTicket")
        )

    except Exception as e:
        demisto.error(e)

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
            trigger_id=body.get("trigger_id"),
            view=load_new_template()
        )
        global TRIGGERED_SLACK_CHANNEL
        TRIGGERED_SLACK_CHANNEL = body.get("channel_id")
        demisto.debug(f'Triggered channel:{TRIGGERED_SLACK_CHANNEL}')

        ticket_template = get_xsoar_list(list_name="SlackTicket")

        res = client.views_update(
            view_id=load.get("view").get("id"),
            hash=load.get("view").get("hash"),
            view=ticket_template
        )

    except Exception as e:
        demisto.error(e)


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
                view_id=body["view"]["id"],
                hash=body["view"]["hash"],
                trigger_id=body["trigger_id"],
                view=selected_view
            )

    except Exception as e:
        demisto.error(e)


@app.view("xsoar-create-ticket")
def view_xsoar_create_tickets_submission(ack, body, client, say):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        # Set any necessary variable(s)
        user_id = body["user"]["id"]
        global TRIGGERED_SLACK_CHANNEL
        user_email = app.client.users_profile_get(user=user_id)["profile"]["email"]
        # demisto.debug(f"user email:{user_email}")
        user_roles = demisto.findUser("", user_email).get("allRoles") or "['']"

        if any(element in user_roles for element in Allowed_roles):
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
                download_json_mapper_file_value = action_keys[5]  # Can specify -1 for index if it will always be the last element
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
            # demisto.debug(f"XSOAR raw incident:{new_incident}")
            # Craft the success message and send to channel or user
            success_response_blocks = craft_incident_trigger_success_message(created_incident=new_incident)

            # Grab the integration parameter for a dedicated slack channel
            # If statement exists to check if the dedicated slack channel param is set
            if DEDICATED_CHANNEL:
                say(channel=DEDICATED_CHANNEL, blocks=success_response_blocks)

            elif TRIGGERED_SLACK_CHANNEL:
                say(channel=TRIGGERED_SLACK_CHANNEL, blocks=success_response_blocks)

            # Else, send it to the originating user
            # else:
            #     say(channel=user_id, blocks=success_response_blocks)

            # Create the JSON mapper file if the user selected this option
            if download_json_mapper_file == "Yes":
                demisto.debug("File created")
                try:
                    if DEDICATED_CHANNEL:
                        channel = get_channel_id(DEDICATED_CHANNEL, client)
                    else:
                        channel = TRIGGERED_SLACK_CHANNEL
                        TRIGGERED_SLACK_CHANNEL = ''
                    filename = f"SlackBot_Create_{ticket_type_selected}_Ticket_Mapper.json"
                    result = client.files_upload_v2(
                        channel=channel,
                        initial_comment="Here's the json file :smile:",
                        title=filename,
                        filename=filename,
                        content=json.dumps(body),
                    )
                    demisto.debug(result)
                    # logger.info(result)

                except Exception as e:
                    demisto.debug(f"Upload Error:{e}")
                    logger.error("Error uploading file: {}".format(e))

        else:
            failure_response_blocks = get_xsoar_list(list_name="SlackPermissionsFailure")
            say(channel=user_id, blocks=failure_response_blocks)

    except Exception as e:
        # Craft the failure message and send to user
        failure_response_blocks = get_xsoar_list(list_name="SlackIncidentTriggerFailure")
        say(channel=user_id, blocks=failure_response_blocks)
        demisto.error(f"Error: {e}")


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
            trigger_id=body.get("trigger_id"),
            view=load_new_template()
        )
        global TRIGGERED_SLACK_CHANNEL
        TRIGGERED_SLACK_CHANNEL = body.get("channel_id")

        indicator_actions_view_template = get_xsoar_list("SlackIndicatorActions")

        res = client.views_update(
            view_id=load.get("view").get("id"),
            hash=load.get("view").get("hash"),
            view=indicator_actions_view_template
        )

    except Exception as e:
        demisto.error(e)


@app.action("indicator-select-action")
def indicator_action_selection(ack, body, logger):
    try:
        ack()

    except Exception as e:
        demisto.error(e)


@app.action("update-on-demand-only-action")
def update_on_demand_selection(ack, body, logger):
    try:
        ack()

    except Exception as e:
        demisto.error(e)


@app.view("xsoar-indicator-actions")
def view_xsoar_indicator_actions_submission(ack, body, client, say):
    try:
        # Acknowledge the request -- DO NOT REMOVE
        ack()

        # Set any necessary variable(s)
        user_id = body["user"]["id"]
        global TRIGGERED_SLACK_CHANNEL

        user_email = app.client.users_profile_get(user=user_id)["profile"]["email"]
        # demisto.debug(f"user email:{user_email}")
        user_roles = demisto.findUser("", user_email).get("allRoles") or "['']"

        if any(element in user_roles for element in Allowed_roles):
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
            download_json_mapper_file_value = action_keys[4]  # Can specify -1 for index if it will always be the last element

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

            elif TRIGGERED_SLACK_CHANNEL:
                say(channel=TRIGGERED_SLACK_CHANNEL, blocks=success_response_blocks)

            # Else, send it to the originating user
            # else:
            #     say(channel=user_id, blocks=success_response_blocks)

            # Create the JSON mapper file if the user selected this option
            if download_json_mapper_file == "Yes":
                demisto.debug("File created")
                try:
                    if DEDICATED_CHANNEL:
                        channel = get_channel_id(DEDICATED_CHANNEL, client)
                    else:
                        channel = TRIGGERED_SLACK_CHANNEL
                        TRIGGERED_SLACK_CHANNEL = ''
                    filename = f"SlackBot_Create_{ticket_type_selected}_Ticket_Mapper.json"
                    result = client.files_upload_v2(
                        channel=channel,
                        initial_comment="Here's the json file :smile:",
                        title=filename,
                        filename=filename,
                        content=json.dumps(body),
                    )
                    demisto.debug(result)
                    # logger.info(result)
                except Exception as e:
                    demisto.debug(f"Upload Error:{e}")
                    logger.error("Error uploading file: {}".format(e))

        else:
            failure_response_blocks = get_xsoar_list(list_name="SlackPermissionsFailure")
            say(channel=user_id, blocks=failure_response_blocks)

    except Exception as e:
        # Craft the failure message and send to user
        failure_response_blocks = get_xsoar_list(list_name="SlackIncidentTriggerFailure")
        say(channel=user_id, blocks=failure_response_blocks)
        demisto.error(f"Error: {e}")


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
