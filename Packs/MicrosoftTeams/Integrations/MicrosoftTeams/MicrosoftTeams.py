import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import re
import time
import urllib.parse
from distutils.util import strtobool
from enum import Enum
from re import Match
from ssl import PROTOCOL_TLSv1_2, SSLContext, SSLError
from tempfile import NamedTemporaryFile
from threading import Thread
from traceback import format_exc
from typing import Any, cast

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from flask import Flask, Response, request
from gevent.pywsgi import WSGIServer
from jwt.algorithms import RSAAlgorithm

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type: ignore


class FormType(Enum):  # Used for 'send-message', and by the MicrosoftTeamsAsk script
    PREDEFINED_OPTIONS = 'predefined-options'
    OPEN_ANSWER = 'open-answer'


''' GLOBAL VARIABLES'''
EXTERNAL_FORM_URL_DEFAULT_HEADER = 'Microsoft Teams Form'
PARAMS: dict = demisto.params()
BOT_ID: str = PARAMS.get('credentials', {}).get('identifier', '') or PARAMS.get('bot_id', '')
BOT_PASSWORD: str = PARAMS.get('credentials', {}).get('password', '') or PARAMS.get('bot_password', '')
TENANT_ID: str = PARAMS.get('tenant_id', '')
APP: Flask = Flask('demisto-teams')
PLAYGROUND_INVESTIGATION_TYPE: int = 9
GRAPH_BASE_URL: str = 'https://graph.microsoft.com'
CERTIFICATE = replace_spaces_in_credential(PARAMS.get('creds_certificate', {}).get('identifier', '')) \
    or demisto.params().get('certificate', '')
PRIVATE_KEY = replace_spaces_in_credential(PARAMS.get('creds_certificate', {}).get('password', '')) \
    or demisto.params().get('key', '')

INCIDENT_TYPE: str = PARAMS.get('incidentType', '')
URL_REGEX = r'(?<!\]\()https?://[^\s]*'
XSOAR_ENGINE_URL_REGEX = r'\bhttps?://(?:\w+[\w.-]*\w+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+(?:/(?:\w+/)*\w+)?'
ENTITLEMENT_REGEX: str = \
    r'(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}'
MENTION_REGEX = r'^@([^@;]+);| @([^@;]+);'
ENTRY_FOOTER: str = 'From Microsoft Teams'
INCIDENT_NOTIFICATIONS_CHANNEL = 'incidentNotificationChannel'

MESSAGE_TYPES: dict = {
    'mirror_entry': 'mirrorEntry',
    'incident_opened': 'incidentOpened',
    'status_changed': 'incidentStatusChanged'
}

NEW_INCIDENT_WELCOME_MESSAGE: str = "Successfully created incident <incident_name>.\nView it on: <incident_link>"
MISS_CONFIGURATION_ERROR_MESSAGE = "Did not receive a tenant ID from Microsoft Teams. Verify that the messaging endpoint in the "\
                                   "Demisto bot configuration in Microsoft Teams is configured correctly.\nUse the "\
                                   "`microsoft-teams-create-messaging-endpoint` command to get the correct messaging endpoint "\
                                   "based on the server URL, the server version, and the instance configurations.\n"\
                                   "For more information See - "\
                                   "https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams#troubleshooting."

CLIENT_CREDENTIALS_FLOW = 'Client Credentials'
AUTHORIZATION_CODE_FLOW = 'Authorization Code'
AUTH_TYPE = PARAMS.get('auth_type', CLIENT_CREDENTIALS_FLOW)

AUTH_CODE: str = PARAMS.get('auth_code_creds', {}).get('password')
REDIRECT_URI: str = PARAMS.get('redirect_uri', '')
SESSION_STATE = 'session_state'
REFRESH_TOKEN = 'refresh_token'

CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'

CHANNEL_SPECIAL_MARKDOWN_HEADERS: dict = {
    'id': 'Membership id',
    'roles': 'User roles',
    'visibleHistoryStartDateTime': 'Start DateTime',
}

CHAT_SPECIAL_MARKDOWN_HEADERS: dict = {
    'id': 'Chat Id',
    'topic': 'Chat name',
    'webUrl': 'webUrl',
    'roles': 'User roles',
    'displayName': 'Name',
}

USER_TYPE_TO_USER_ROLE = {
    "Guest": "guest",
    "Member": "owner"
}

GROUP_CHAT_ID_SUFFIX = "@thread.v2"
ONEONONE_CHAT_ID_SUFFIX = "@unq.gbl.spaces"
MAX_ITEMS_PER_RESPONSE = 50

EXTERNAL_FORM = "external/form"
MAX_SAMPLES = 10

TOKEN_EXPIRED_ERROR_CODES = {50173, 700082, }  # See: https://login.microsoftonline.com/error?code=
REGEX_SEARCH_ERROR_DESC = r"^[^:]*:\s(?P<desc>.*?\.)"

# must be synced with ones in TeamsAsk
MS_TEAMS_ASK_MESSAGE_KEYS = {'message_text', 'options', 'entitlement', 'investigation_id', 'task_id', 'form_type'}


class Handler:
    @staticmethod
    def write(msg: str):
        demisto.info(msg)


class ErrorHandler:
    @staticmethod
    def write(msg: str):
        demisto.error(f'wsgi error: {msg}')


DEMISTO_LOGGER: Handler = Handler()
ERROR_LOGGER: ErrorHandler = ErrorHandler()


def handle_teams_proxy_and_ssl():
    proxies = None
    use_ssl = not PARAMS.get('insecure', False)
    if not is_demisto_version_ge('8.0.0'):
        return proxies, use_ssl
    CRTX_HTTP_PROXY = os.environ.get('CRTX_HTTP_PROXY', None)
    if CRTX_HTTP_PROXY:
        proxies = {
            "http": CRTX_HTTP_PROXY,
            "https": CRTX_HTTP_PROXY
        }
        use_ssl = True
    return proxies, use_ssl


PROXIES, USE_SSL = handle_teams_proxy_and_ssl()


''' HELPER FUNCTIONS '''


def epoch_seconds(d: datetime = None) -> int:
    """
    Return the number of seconds for given date. If no date, return current.
    :param d: timestamp datetime object
    :return: timestamp in epoch
    """
    if not d:
        d = datetime.utcnow()
    return int((d - datetime.utcfromtimestamp(0)).total_seconds())


def error_parser(resp_err: requests.Response, api: str = 'graph') -> str:
    """
    Parses Microsoft API error message from Requests response
    :param resp_err: response with error
    :param api: API to query (graph/bot)
    :return: string of error
    """
    try:
        response: dict = resp_err.json()
        demisto.debug(f"Error response from {api=}: {response=}")
        if api == 'graph':
            error_codes = response.get("error_codes", [""])
            if set(error_codes).issubset(TOKEN_EXPIRED_ERROR_CODES):
                reset_graph_auth(error_codes, response.get('error_description', ''))

            error = response.get('error', {})
            err_str = (f"{error.get('code', '')}: {error.get('message', '')}" if isinstance(error, dict)
                       else response.get('error_description', ''))
            if err_str:
                return err_str
        elif api == 'bot':
            error_description: str = response.get('error_description', '')
            if error_description:
                return error_description
        # If no error message
        raise ValueError
    except ValueError:
        return resp_err.text


def reset_graph_auth(error_codes: list = [], error_desc: str = ""):
    """
    Reset the Graph API authorization in the integration context.
    This function clears the current graph authorization data: current_refresh_token, graph_access_token, graph_valid_until
    """

    integration_context: dict = get_integration_context()
    integration_context['current_refresh_token'] = ''
    integration_context['graph_access_token'] = ''
    integration_context['graph_valid_until'] = ''
    set_integration_context(integration_context)

    if error_codes or error_desc:
        demisto.debug(f"Detected Error: {error_codes}, Successfully reset the current_refresh_token and graph_access_token.")
        re_search = re.search(REGEX_SEARCH_ERROR_DESC, error_desc)
        err_str = re_search['desc'] if re_search else ""
        raise DemistoException(f"{err_str} Please regenerate the 'Authorization code' "
                               "parameter and then run !microsoft-teams-auth-test to re-authenticate")

    demisto.debug("Successfully reset the current_refresh_token, graph_access_token and graph_valid_until.")


def reset_graph_auth_command():
    """
    A wrapper function for the reset_graph_auth() which resets the Graph API authorization in the integration context.
    """
    reset_graph_auth()
    return_results(CommandResults(readable_output='Authorization was reset successfully.'))


def translate_severity(severity: str) -> float:
    """
    Translates Demisto text severity to int severity
    :param severity: Demisto text severity
    :return: Demisto integer severity
    """
    severity_dictionary = {
        'Unknown': 0.0,
        'Informational': 0.5,
        'Low': 1.0,
        'Medium': 2.0,
        'High': 3.0,
        'Critical': 4.0
    }
    return severity_dictionary.get(severity, 0.0)


def create_incidents(demisto_user: dict, incidents: list) -> dict:
    """
    Creates incidents according to a provided JSON object
    :param demisto_user: The demisto user associated with the request (if exists)
    :param incidents: The incidents JSON
    :return: The creation result
    """
    if demisto_user:
        data = demisto.createIncidents(incidents, userID=demisto_user.get('id', ''))
    else:
        data = demisto.createIncidents(incidents)
    return data


def remove_private_info_from_body(object_to_sanitize: dict):
    """
    Some items like tenant ID are confidential and therefore should be removed from the metadata
    """
    if object_to_sanitize.get('conversation', {}).get('tenantId'):
        del object_to_sanitize['conversation']['tenantId']
    if object_to_sanitize.get('channelData', {}).get('tenant', {}).get('id'):
        del object_to_sanitize['channelData']['tenant']['id']


def add_req_data_to_incidents(incidents: list, request_body: dict) -> list:
    """
    Adds the request_body as a rawJSON to every created incident for further information on the incident
    """
    remove_private_info_from_body(request_body)
    for incident in incidents:
        incident['rawJSON'] = json.dumps(request_body)
    return incidents


def process_incident_create_message(demisto_user: dict, message: str, request_body: dict) -> str:
    """
    Processes an incident creation message
    :param demisto_user: The Demisto user associated with the message (if exists)
    :param message: The creation message
    :param request_body: The original API request body
    :return: Creation result
    """
    json_pattern: str = r'(?<=json=).*'
    name_pattern: str = r'(?<=name=).*'
    type_pattern: str = r'(?<=type=).*'
    json_match: Match[str] | None = re.search(json_pattern, message)
    created_incident: dict | list = []
    data = ''
    if json_match:
        if re.search(name_pattern, message) or re.search(type_pattern, message):
            data = 'No other properties other than json should be specified.'
        else:
            incidents_json: str = json_match.group()
            incidents: dict | list = json.loads(incidents_json.replace('“', '"').replace('”', '"'))
            if not isinstance(incidents, list):
                incidents = [incidents]

            add_req_data_to_incidents(incidents, request_body)  # type: ignore[arg-type]
            created_incident = create_incidents(demisto_user, incidents)    # type: ignore[arg-type]
            if not created_incident:
                data = 'Failed creating incidents.'
    else:
        name_match: Match[str] | None = re.search(name_pattern, message)
        if not name_match:
            data = 'Please specify arguments in the following manner: name=<name> type=[type] or json=<json>.'
        else:
            incident_name: str = re.sub('type=.*', '', name_match.group()).strip()
            incident_type = ''

            type_match: Match[str] | None = re.search(type_pattern, message)
            if type_match:
                incident_type = re.sub('name=.*', '', type_match.group()).strip()

            incident: dict = {'name': incident_name}

            incident_type = incident_type or INCIDENT_TYPE
            if incident_type:
                incident['type'] = incident_type

            incidents = add_req_data_to_incidents([incident], request_body)
            created_incident = create_incidents(demisto_user, incidents)
            if not created_incident:
                data = 'Failed creating incidents.'
    if created_incident:
        update_integration_context_samples(incidents)   # type: ignore[arg-type]
        if isinstance(created_incident, list):
            created_incident = created_incident[0]
        created_incident = cast(dict[Any, Any], created_incident)
        server_links: dict = demisto.demistoUrls()
        server_link: str = server_links.get('server', '')
        server_link = server_link + '/#' if not is_demisto_version_ge('8.0.0') else server_link
        newIncidentWelcomeMessage = demisto.params().get('new_incident_welcome_message', '')
        if not newIncidentWelcomeMessage:
            newIncidentWelcomeMessage = NEW_INCIDENT_WELCOME_MESSAGE
        elif newIncidentWelcomeMessage == "no_welcome_message":
            newIncidentWelcomeMessage = ""

        if (
            newIncidentWelcomeMessage
            and ("<incident_name>" in newIncidentWelcomeMessage)
            and ("<incident_link>" in newIncidentWelcomeMessage)
        ):
            newIncidentWelcomeMessage = newIncidentWelcomeMessage.replace(
                "<incident_name>", f"{created_incident.get('name', '')}"
            ).replace("<incident_link>", f"{server_link}/WarRoom/{created_incident.get('id', '')}")
        data = newIncidentWelcomeMessage

    return data


def is_investigation_mirrored(investigation_id: str, mirrored_channels: list) -> int:
    """
    Checks if investigation is already mirrored
    :param investigation_id: Investigation ID to check if mirrored
    :param mirrored_channels: List of mirrored channels to check if investigation is mirrored in
    :return: Index in mirrored channels list if mirrored, else -1
    """
    for index, channel in enumerate(mirrored_channels):
        if channel.get('investigation_id') == investigation_id:
            return index
    return -1


def urlify_hyperlinks(message: str, url_header: str | None = EXTERNAL_FORM_URL_DEFAULT_HEADER) -> str:
    """
    Converts URLs to Markdown-format hyperlinks.
    e.g. https://www.demisto.com -> [https://www.demisto.com](https://www.demisto.com)
    :param message: Message to look for URLs in
    :return: Formatted message with hyperlinks.
    """
    url_header = url_header or EXTERNAL_FORM_URL_DEFAULT_HEADER

    def replace_url(match):
        url = match.group()
        # is the url is a survey link coming from Data Collection task
        return f'[{url_header if EXTERNAL_FORM in url else url}]({url})'

    # Replace all URLs that are not already part of markdown links
    formatted_message: str = re.sub(URL_REGEX, replace_url, message)

    return formatted_message


def get_team_member(integration_context: dict, team_member_id: str) -> dict:
    """
    Searches for a team member
    :param integration_context: Cached object to search for team member in
    :param team_member_id: Team member ID to search for
    :return: Found team member object
    """
    team_member = {}
    teams: list = json.loads(integration_context.get('teams', '[]'))

    for team in teams:
        team_members: list = team.get('team_members', [])
        for member in team_members:
            if member.get('id') == team_member_id:
                demisto.debug(f'get_team_member details: {member=}')
                team_member['username'] = member.get('name', '')
                team_member['user_email'] = member.get('email', '')
                team_member['user_principal_name'] = member.get('userPrincipalName', '')
                return team_member

    raise ValueError('Team member was not found')


def get_team_member_id(requested_team_member: str, integration_context: dict) -> str:
    """
    Gets team member ID based on name, email or principal name
    :param requested_team_member: Team member name / principal name / email to look for
    :param integration_context: Cached object to search for team member in
    :return: Team member ID
    """
    demisto.debug(f"Requested team member: {requested_team_member}")
    teams: list = json.loads(integration_context.get('teams', '[]'))
    demisto.debug(f"We've got {len(teams)} teams saved in integration context")
    for team in teams:
        team_members: list = team.get('team_members', [])
        for team_member in team_members:
            member_properties = [team_member.get('email', '').lower(), team_member.get(
                'userPrincipalName', '').lower(), team_member.get('name', '').lower()]
            if requested_team_member.lower() in [value.lower() for value in member_properties]:
                return team_member.get("id")
    raise ValueError(f'Team member {requested_team_member} was not found')


def create_adaptive_card(body: list, actions: list | None = None) -> dict:
    """
    Creates Microsoft Teams adaptive card object given body and actions
    :param body: Adaptive card data
    :param actions: Adaptive card actions
    :return: Adaptive card object
    """
    adaptive_card: dict = {
        'contentType': 'application/vnd.microsoft.card.adaptive',
        'content': {
            '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
            'version': '1.0',
            'type': 'AdaptiveCard',
            'msteams': {
                'width': 'Full'
            },
            'body': body
        }
    }
    if actions:
        adaptive_card['content']['actions'] = actions
    return adaptive_card


def process_tasks_list(data_by_line: list) -> dict:
    """
    Processes tasks list assigned to user given from Demisto server and creates adaptive card
    :param data_by_line: List of tasks to process
    :return: Adaptive card of assigned tasks
    """
    body = []
    for line in data_by_line[2:]:
        split_data: list = [stat.strip() for stat in line.split('|')]
        body.append({
            'type': 'FactSet',
            'facts': [
                {
                    'title': 'Task:',
                    'value': split_data[0]
                },
                {
                    'title': 'Incident:',
                    'value': split_data[1]
                },
                {
                    'title': 'Due:',
                    'value': split_data[2]
                },
                {
                    'title': 'Link:',
                    'value': f'[{split_data[3]}]({split_data[3]})'
                }
            ]
        })
    return create_adaptive_card(body)


def process_incidents_list(data_by_line: list) -> dict:
    """
    Processes incidents list assigned to user given from Demisto server and creates adaptive card
    :param data_by_line: List of incidents to process
    :return: Adaptive card of assigned incidents
    """
    body = []
    for line in data_by_line[2:]:
        split_data: list = [stat.strip() for stat in line.split('|')]
        body.append({
            'type': 'FactSet',
            'facts': [
                {
                    'title': 'ID:',
                    'value': split_data[0]
                },
                {
                    'title': 'Name:',
                    'value': split_data[1]
                },
                {
                    'title': 'Status:',
                    'value': split_data[2]
                },
                {
                    'title': 'Type:',
                    'value': split_data[3]
                },
                {
                    'title': 'Owner:',
                    'value': split_data[4]
                },
                {
                    'title': 'Created:',
                    'value': split_data[5]
                },
                {
                    'title': 'Link:',
                    'value': f'[{split_data[6]}]({split_data[6]})'
                }
            ]
        })
    return create_adaptive_card(body)


def process_mirror_or_unknown_message(message: str) -> dict:
    """
    Processes mirror investigation command or unknown direct message and creates adaptive card
    :param message: The direct message to process
    :return: Adaptive card of mirror response / unknown message
    """
    body: list = [{
        'type': 'TextBlock',
        'text': message.replace('\n', '\n\n'),
        'wrap': True
    }]
    return create_adaptive_card(body)


def is_teams_ask_message(msg: str) -> bool:
    try:
        message: dict = json.loads(msg)
        return message.keys() == MS_TEAMS_ASK_MESSAGE_KEYS
    except json.decoder.JSONDecodeError:
        return False


def process_ask_user(message: str) -> dict:
    """
    Processes ask user message and creates adaptive card
    :param message: The question object
    :return: Adaptive card of the question to send
    """
    message_object: dict = json.loads(message)
    text: str = message_object.get('message_text', '')
    entitlement: str = message_object.get('entitlement', '')
    form_type: FormType = FormType(message_object.get('form_type', FormType.PREDEFINED_OPTIONS.value))
    options: list = message_object.get('options', [])
    investigation_id: str = message_object.get('investigation_id', '')
    task_id: str = message_object.get('task_id', '')

    body: list[dict] = []
    actions: list[dict] = []

    if form_type == FormType.PREDEFINED_OPTIONS:
        body.append({
            'type': 'TextBlock',
            'text': text,
            'wrap': True
        })

        for option in options:
            actions.append({
                'type': 'Action.Submit',
                'title': option,
                'data': {
                    'response': option,
                    'entitlement': entitlement,
                    'investigation_id': investigation_id,
                    'task_id': task_id
                }
            })

    elif form_type == FormType.OPEN_ANSWER:
        body.extend([
            {
                'type': 'TextBlock',
                'text': 'Form',
                'id': 'Title',
                'spacing': 'Medium',
                'horizontalAlignment': 'Center',
                'size': 'Medium',
                'weight': 'Bolder',
                'color': 'Accent',
                'wrap': True
            },
            {
                'type': 'Container',
                'items': [
                    {
                        'type': 'TextBlock',
                        'text': text,
                        'wrap': True,
                        'spacing': 'Medium',
                    },
                    {
                        'type': 'Input.Text',
                        'placeholder': 'Enter an answer',
                        'id': 'response',
                        'isMultiline': True,
                    }
                ]
            },
        ])

        actions.append({
            'type': 'Action.Submit',
            'title': 'Submit',
            'data': {
                'entitlement': entitlement,
                'investigation_id': investigation_id,
                'task_id': task_id
            }
        })

    return create_adaptive_card(body, actions)


def add_data_to_actions(card_json, data_value):

    # If the current item is a list, iterate over it
    if isinstance(card_json, list):
        for item in card_json:
            add_data_to_actions(item, data_value)

    # If the current item is a dictionary
    elif isinstance(card_json, dict):
        # Check if this dictionary is an Action.Submit or Action.Execute
        if card_json.get("type") in ["Action.Submit", "Action.Execute"]:
            # Add the 'data' key with the provided value
            card_json["data"] = data_value

        # Only check nested elements within 'actions'
        if "actions" in card_json:
            add_data_to_actions(card_json["actions"], data_value)

        # Handle nested card inside Action.ShowCard
        if card_json.get("type") == "Action.ShowCard" and "card" in card_json:
            add_data_to_actions(card_json["card"], data_value)


def process_adaptive_card(adaptive_card_obj: dict) -> dict:
    """
    Processes adaptive cards coming from MicrosoftTeamsAsk. It will find all action elements
    of type Action.Submit or Action.Execute within adaptive_card_obj['adaptive_card'] and add entitlement,
    investigation_id and task_id to them.
    :param adaptive_card_obj: The adaptive card object.
    :return: Adaptive card with entitlement.
    """

    adaptive_card = adaptive_card_obj.get('adaptive_card', '')
    data_obj: dict = {}
    data_obj["entitlement"] = str(adaptive_card_obj.get('entitlement', ''))
    data_obj["investigation_id"] = str(adaptive_card_obj.get('investigation_id', ''))
    data_obj["task_id"] = str(adaptive_card_obj.get('task_id', ''))

    add_data_to_actions(adaptive_card.get('content', ''), data_obj)
    return adaptive_card


def get_bot_access_token() -> str:
    """
    Retrieves Bot Framework API access token, either from cache or from Microsoft
    :return: The Bot Framework API access token
    """
    integration_context: dict = get_integration_context()
    access_token: str = integration_context.get('bot_access_token', '')
    valid_until: int = integration_context.get('bot_valid_until', int)
    if access_token and valid_until and epoch_seconds() < valid_until:
        return access_token
    url: str = 'https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token'
    data: dict = {
        'grant_type': 'client_credentials',
        'client_id': BOT_ID,
        'client_secret': BOT_PASSWORD,
        'scope': 'https://api.botframework.com/.default'
    }
    response: requests.Response = requests.post(
        url,
        data=data,
        verify=USE_SSL,
        proxies=PROXIES
    )
    if not response.ok:
        error = error_parser(response, 'bot')
        raise ValueError(f'Failed to get bot access token [{response.status_code}] - {error}')
    try:
        response_json: dict = response.json()
        access_token = response_json.get('access_token', '')
        expires_in: int = response_json.get('expires_in', 3595)
        time_now: int = epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            expires_in -= time_buffer
        integration_context['bot_access_token'] = access_token
        integration_context['bot_valid_until'] = time_now + expires_in
        set_integration_context(integration_context)
        return access_token
    except ValueError:
        raise ValueError('Failed to get bot access token')


def get_refresh_token_from_auth_code_param() -> str:
    """
    The function is based on MicrosoftClient._get_refresh_token_from_auth_code_param() from 'MicrosoftApiModule'
    """
    refresh_prefix = "refresh_token:"
    if AUTH_CODE.startswith(refresh_prefix):  # for testing we allow setting the refresh token directly
        demisto.debug("Using refresh token set as auth_code")
        return AUTH_CODE[len(refresh_prefix):]
    return ''


def get_graph_access_token() -> str:
    """
    Retrieves Microsoft Graph API access token, either from cache or from Microsoft
    :return: The Microsoft Graph API access token
    """
    integration_context: dict = get_integration_context()

    refresh_token = integration_context.get('current_refresh_token', '')
    access_token: str = integration_context.get('graph_access_token', '')
    valid_until: int = integration_context.get('graph_valid_until', int)
    if access_token and valid_until and epoch_seconds() < valid_until:
        demisto.debug('Using access token from integration context')
        return access_token
    tenant_id = integration_context.get('tenant_id')
    if not tenant_id:
        raise ValueError(MISS_CONFIGURATION_ERROR_MESSAGE)
    headers = None
    url: str = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    data: dict = {
        'grant_type': CLIENT_CREDENTIALS,
        'client_id': BOT_ID,
        'scope': 'https://graph.microsoft.com/.default',
        'client_secret': BOT_PASSWORD
    }
    if AUTH_TYPE == AUTHORIZATION_CODE_FLOW:
        data['redirect_uri'] = REDIRECT_URI
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if refresh_token := refresh_token or get_refresh_token_from_auth_code_param():
            demisto.debug('Using refresh token from integration context')
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            if SESSION_STATE in AUTH_CODE:
                raise ValueError('Malformed auth_code parameter: Please copy the auth code from the redirected uri '
                                 'without any additional info and without the "session_state" query parameter.')
            data['grant_type'] = AUTHORIZATION_CODE
            data['code'] = AUTH_CODE

    response: requests.Response = requests.post(
        url,
        data=data,
        verify=USE_SSL,
        proxies=PROXIES,
        headers=headers
    )
    if not response.ok:
        error = error_parser(response)
        raise ValueError(f'Failed to get Graph access token [{response.status_code}] - {error}')
    try:
        response_json: dict = response.json()
        access_token = response_json.get('access_token', '')
        expires_in: int = response_json.get('expires_in', 3595)
        refresh_token = response_json.get('refresh_token', '')

        time_now: int = epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            expires_in -= time_buffer
        integration_context['current_refresh_token'] = refresh_token
        integration_context['graph_access_token'] = access_token
        integration_context['graph_valid_until'] = time_now + expires_in
        set_integration_context(integration_context)
        return access_token
    except ValueError:
        raise ValueError('Failed to get Graph access token')


def http_request(
        method: str, url: str = '', json_: dict = None, api: str = 'graph', params: dict | None = None
) -> dict | list:
    """A wrapper for requests lib to send our requests and handle requests and responses better
    Headers to be sent in requests

    Args:
        method (str): any restful method
        url (str): URL to query
        json_ (dict): HTTP JSON body
        api (str): API to query (graph/bot)
        params (dict): Object of key-value URL query parameters

    Returns:
        Union[dict, list]: The response in list or dict format.
    """
    access_token = get_graph_access_token() if api == 'graph' else get_bot_access_token()  # Bot Framework API

    headers: dict = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    try:
        response: requests.Response = requests.request(
            method,
            url,
            headers=headers,
            json=json_,
            verify=USE_SSL,
            proxies=PROXIES,
            params=params,
        )

        if not response.ok:
            error: str = error_parser(response, api)
            raise ValueError(f'Error in API call to Microsoft Teams: [{response.status_code}] - {error}')

        if response.status_code in {202, 204}:
            # Delete channel or remove user from channel return 204 if successful
            # Update message returns 202 if the request has been accepted for processing
            # Create channel with a membershipType value of shared, returns 202 and a link to the teamsAsyncOperation.
            return {}
        if response.status_code == 201 and not response.content:
            # For channel creation query (with a membershipType value of standard or private), chat creation,
            # Send message in a chat, and Add member returns 201 if successful
            return {}
        try:
            return response.json()
        except ValueError:
            raise ValueError(f'Error in API call to Microsoft Teams: {response.text}')
    except requests.exceptions.ConnectTimeout:
        error_message = 'Connection Timeout Error - potential reason may be that Microsoft Teams is not ' \
                        'accessible from your host.'
        raise ConnectionError(error_message)
    except requests.exceptions.SSLError:
        error_message = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' in ' \
                        'the integration configuration.'
        raise ConnectionError(error_message)
    except requests.exceptions.ProxyError:
        error_message = 'Proxy Error - if \'Use system proxy settings\' in the integration configuration has been ' \
                        'selected, try deselecting it.'
        raise ConnectionError(error_message)


def integration_health():
    bot_framework_api_health = 'Operational'
    graph_api_health = 'Operational'

    try:
        get_bot_access_token()
    except ValueError as e:
        bot_framework_api_health = f'Non operational - {str(e)}'

    try:
        get_graph_access_token()
    except ValueError as e:
        graph_api_health = f'Non operational - {str(e)}'

    api_health_output: list = [{
        'Bot Framework API Health': bot_framework_api_health,
        'Graph API Health': graph_api_health
    }]

    adi_health_human_readable: str = tableToMarkdown('Microsoft API Health', api_health_output)

    mirrored_channels_output = []
    integration_context: dict = get_integration_context()
    teams: list = json.loads(integration_context.get('teams', '[]'))
    for team in teams:
        mirrored_channels: list = team.get('mirrored_channels', [])
        for channel in mirrored_channels:
            mirrored_channels_output.append({
                'Team': team.get('team_name'),
                'Channel': channel.get('channel_name'),
                'Investigation ID': channel.get('investigation_id')
            })

    mirrored_channels_human_readable: str

    if mirrored_channels_output:
        mirrored_channels_human_readable = tableToMarkdown(
            'Microsoft Teams Mirrored Channels', mirrored_channels_output
        )
    else:
        mirrored_channels_human_readable = 'No mirrored channels.'

    demisto.results({
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'HumanReadable': adi_health_human_readable + mirrored_channels_human_readable,
        'Contents': adi_health_human_readable + mirrored_channels_human_readable
    })


def validate_auth_header(headers: dict) -> bool:
    """
    Validated authorization header provided in the bot activity object
    :param headers: Bot activity headers
    :return: True if authorized, else False
    """
    parts: list = headers.get('Authorization', '').split(' ')
    if len(parts) != 2:
        return False
    scehma: str = parts[0]
    jwt_token: str = parts[1]
    if scehma != 'Bearer' or not jwt_token:
        demisto.info('Authorization header validation - failed to verify schema')
        return False

    decoded_payload: dict = jwt.decode(jwt=jwt_token, options={'verify_signature': False})
    issuer: str = decoded_payload.get('iss', '')
    if issuer != 'https://api.botframework.com':
        demisto.info('Authorization header validation - failed to verify issuer')
        return False

    integration_context: dict = get_integration_context()
    open_id_metadata: dict = json.loads(integration_context.get('open_id_metadata', '{}'))
    keys: list = open_id_metadata.get('keys', [])

    unverified_headers: dict = jwt.get_unverified_header(jwt_token)
    key_id: str = unverified_headers.get('kid', '')
    key_object = {}

    # Check if we got the requested key in cache
    for key in keys:
        if key.get('kid') == key_id:
            key_object = key
            break

    if not key_object:
        # Didn't find requested key in cache, getting new keys
        try:
            open_id_url: str = 'https://login.botframework.com/v1/.well-known/openidconfiguration'
            response: requests.Response = requests.get(open_id_url, verify=USE_SSL, proxies=PROXIES)
            if not response.ok:
                demisto.info(f'Authorization header validation failed to fetch open ID config - {response.reason}')
                return False
            response_json: dict = response.json()
            jwks_uri: str = response_json.get('jwks_uri', '')
            keys_response: requests.Response = requests.get(jwks_uri, verify=USE_SSL, proxies=PROXIES)
            if not keys_response.ok:
                demisto.info(f'Authorization header validation failed to fetch keys - {response.reason}')
                return False
            keys_response_json: dict = keys_response.json()
            keys = keys_response_json.get('keys', [])
            open_id_metadata['keys'] = keys
        except ValueError:
            demisto.info('Authorization header validation - failed to parse keys response')
            return False

    if not keys:
        # Didn't get new keys
        demisto.info('Authorization header validation - failed to get keys')
        return False

    # Find requested key in new keys
    for key in keys:
        if key.get('kid') == key_id:
            key_object = key
            break

    if not key_object:
        # Didn't find requested key in new keys
        demisto.info('Authorization header validation - failed to find relevant key')
        return False

    endorsements: list = key_object.get('endorsements', [])
    if not endorsements or 'msteams' not in endorsements:
        demisto.info('Authorization header validation - failed to verify endorsements')
        return False

    public_key = RSAAlgorithm.from_jwk(json.dumps(key_object))
    public_key: RSAPublicKey = cast(RSAPublicKey, public_key)

    options = {
        'verify_aud': False,
        'verify_exp': True,
        'verify_signature': False,
    }
    decoded_payload = jwt.decode(jwt_token, public_key, options=options)

    audience_claim: str = decoded_payload.get('aud', '')
    if audience_claim != BOT_ID:
        demisto.debug(f"failed to verify audience_claim: {audience_claim} with BOT_ID: {BOT_ID}.")
        demisto.info('Authorization header validation - failed to verify audience_claim')
        return False

    integration_context['open_id_metadata'] = json.dumps(open_id_metadata)
    set_integration_context(integration_context)
    return True


''' COMMANDS + REQUESTS FUNCTIONS '''


def get_team_aad_id(team_name: str) -> str:
    """
    Gets Team AAD ID
    :param team_name: Team name to get AAD ID of
    :return: team AAD ID
    """
    demisto.debug(f'Team String {team_name}')
    integration_context: dict = get_integration_context()
    if integration_context.get('teams'):
        teams: list = json.loads(integration_context['teams'])
        for team in teams:
            if team_name == team.get('team_name', ''):
                return team.get('team_aad_id', '')
    url: str = (f"{GRAPH_BASE_URL}/v1.0/groups?$filter=displayName eq '{urllib.parse.quote(team_name)}' "
                f"and resourceProvisioningOptions/Any(x:x eq 'Team')")
    response: dict = cast(dict[Any, Any], http_request('GET', url))
    demisto.debug(f'Response {response}')
    teams = response.get('value', [])
    for team in teams:
        if team.get('displayName', '') == team_name:
            return team.get('id', '')
    raise ValueError('Could not find requested team.')


def get_chat_id_and_type(chat: str) -> tuple[str, str]:
    """
    :param chat: Represents the identity of the chat - chat_name, chat_id or member in case of "oneOnOne" chat_type.
    :return: chat_id, chat_type
    """
    demisto.debug(f'Given chat: {chat}')
    url = f"{GRAPH_BASE_URL}/v1.0/chats/"

    # case1 - chat = chat_id
    if chat.endswith((GROUP_CHAT_ID_SUFFIX, ONEONONE_CHAT_ID_SUFFIX)):
        demisto.debug(f"Received chat id as chat: {chat=}")
        response: dict = cast(dict[Any, Any], http_request('GET', url + chat))  # raise 404 if the chat id was not found
        return response.get('id', ''), response.get('chatType', '')

    # case2 - chat = chat_name (topic) in case of "group" chat_type
    params = {'$filter': f"topic eq '{chat}'", '$select': 'id, chatType', '$top': MAX_ITEMS_PER_RESPONSE}
    chats_response = cast(dict[Any, Any], http_request('GET', url, params=params))
    chats, _ = pages_puller(chats_response)
    if chats and chats[0]:
        demisto.debug(f"Received chat's topic as chat: {chat=}")
        return chats[0].get('id', ''), chats[0].get('chatType', '')

    # case3 - chat = member in case of "oneOnOne" chat_type.
    # Check if the given "chat" argument is representing an existing member
    user_data: list = get_user(chat)
    if not (user_data and user_data[0].get('id')):
        raise ValueError(f'Could not find chat: {chat}')
    demisto.debug(f"Received member as chat: {chat=}")
    # Find the chat_id in case of 'oneOnOne' chat by calling "create_chat"
    # If a one-on-one chat already exists, this operation will return the existing chat and not create a new one
    chat_data: dict = create_chat("oneOnOne", [(user_data[0].get('id'), user_data[0].get('userType'))])
    return chat_data.get('id', ''), chat_data.get('chatType', '')


# def add_member_to_team(user_principal_name: str, team_id: str):
#     url: str = f'{GRAPH_BASE_URL}/v1.0/groups/{team_id}/members/$ref'
#     requestjson_: dict = {
#          '@odata.id': f'{GRAPH_BASE_URL}/v1.0/directoryObjects/{user_principal_name}'
#     }
#     http_request('POST', url, json_=requestjson_)


def get_user(user: str) -> list:
    """Retrieves the AAD ID of requested user and the userType

    Args:
        user (str): Display name/mail/UPN of user to get ID of.

    Return:
        list: List containing the requsted user object
    """
    demisto.debug(f"Given user = {user}")
    url: str = f'{GRAPH_BASE_URL}/v1.0/users'
    params = {
        '$filter': f"displayName eq '{user}' or mail eq '{user}' or userPrincipalName eq '{user}'",
        '$select': 'id, userType'
    }
    users = cast(dict[Any, Any], http_request('GET', url, params=params))
    return users.get('value', [])


def add_user_to_channel(team_aad_id: str, channel_id: str, user_id: str, is_owner: bool = False):
    """
    Request for adding user to channel
    """
    url = f'{GRAPH_BASE_URL}/v1.0/teams/{team_aad_id}/channels/{channel_id}/members'
    user_role = ["owner"] if is_owner else []
    request_json: dict = create_conversation_member(user_id, user_role)
    http_request('POST', url, json_=request_json)


def add_user_to_channel_command():
    """
    Add user to channel
    This operation is allowed only for channels with a membershipType value of private or shared.
    """
    channel_name: str = demisto.args().get('channel', '')
    team_name: str = demisto.args().get('team', '')
    member = demisto.args().get('member', '')
    is_owner: bool = argToBoolean(demisto.args().get('owner', False))

    user: list = get_user(member)
    if not (user and user[0].get('id')):
        raise ValueError(f'User {member} was not found')

    team_aad_id = get_team_aad_id(team_name)
    channel_id = get_channel_id(channel_name, team_aad_id, investigation_id=None)
    if get_channel_type(channel_id, team_aad_id) == 'standard':
        raise ValueError('Adding a member is allowed only for private or shared channels.')

    add_user_to_channel(team_aad_id, channel_id, user[0].get('id'), is_owner)

    demisto.results(f'The User "{member}" has been added to channel "{channel_name}" successfully.')


# def create_group_request(
#         display_name: str, mail_enabled: bool, mail_nickname: str, security_enabled: bool,
#         owners_ids: list, members_ids: list = None
# ) -> str:
#     url = f'{GRAPH_BASE_URL}/v1.0/groups'
#     data: dict = {
#         'displayName': display_name,
#         'groupTypes': ['Unified'],
#         'mailEnabled': mail_enabled,
#         'mailNickname': mail_nickname,
#         'securityEnabled': security_enabled,
#         'owners@odata.bind': owners_ids,
#         'members@odata.bind': members_ids or owners_ids
#     }
#     group_creation_response: dict = cast(Dict[Any, Any], http_request('POST', url, json_=data))
#     group_id: str = group_creation_response.get('id', '')
#     return group_id
#
#
# def create_team_request(group_id: str) -> str:
#     url = f'{GRAPH_BASE_URL}/v1.0/groups/{group_id}/team'
#     team_creation_response: dict = cast(Dict[Any, Any], http_request('PUT', url, json_={}))
#     team_id: str = team_creation_response.get('id', '')
#     return team_id
#
#
# def add_bot_to_team(team_id: str):
#     url: str = f'{GRAPH_BASE_URL}/v1.0/teams/{team_id}/installedApps'
#     bot_app_id: str = ''
#     data: dict = {
#         'teamsApp@odata.bind': f'https://graph.microsoft.com/v1.0/appCatalogs/teamsApps/{bot_app_id}'
#     }
#     print(http_request('POST', url, json_=data))
#
#
# def create_team():
#     display_name: str = demisto.args().get('display_name', '')
#     mail_enabled: bool = bool(strtobool(demisto.args().get('mail_enabled', True)))
#     mail_nickname: str = demisto.args().get('mail_nickname', '')
#     security_enabled: bool = bool(strtobool(demisto.args().get('security_enabled', True)))
#     owners = argToList(demisto.args().get('owner', ''))
#     members = argToList(demisto.args().get('members', ''))
#     owners_ids: list = list()
#     members_ids: list = list()
#     users: list = get_users()
#     user_id: str = str()
#     for member in members:
#         found_member: bool = False
#         for user in users:
#             if member in {user.get('displayName', ''), user.get('mail'), user.get('userPrincipalName')}:
#                 found_member = True
#                 user_id = user.get('id', '')
#                 members_ids.append(f'https://graph.microsoft.com/v1.0/users/{user_id}')
#                 break
#         if not found_member:
#             demisto.results({
#                 'Type': entryTypes['warning'],
#                 'Contents': f'User {member} was not found',
#                 'ContentsFormat': formats['text']
#             })
#     for owner in owners:
#         found_owner: bool = False
#         for user in users:
#             if owner in {user.get('displayName', ''), user.get('mail'), user.get('userPrincipalName')}:
#                 found_owner = True
#                 user_id = user.get('id', '')
#                 owners_ids.append(f'https://graph.microsoft.com/v1.0/users/{user_id}')
#                 break
#         if not found_owner:
#             demisto.results({
#                 'Type': entryTypes['warning'],
#                 'Contents': f'User {owner} was not found',
#                 'ContentsFormat': formats['text']
#             })
#     if not owners_ids:
#         raise ValueError('Could not find given users to be Team owners.')
#     group_id: str = create_group_request(
#         display_name, mail_enabled, mail_nickname, security_enabled, owners_ids, members_ids
#     )
#     team_id: str = create_team_request(group_id)
#     add_bot_to_team(team_id)
#     demisto.results(f'Team {display_name} was created successfully')

def create_conversation_member(user_id: str, user_role: list) -> dict:
    """
    Create a conversation member dictionary for the specified user ID.
    """
    return {
        "@odata.type": '#microsoft.graph.aadUserConversationMember',
        "user@odata.bind": f"https://graph.microsoft.com/v1.0/users('{user_id}')",
        "roles": user_role
    }


def create_channel(team_aad_id: str, channel_name: str, channel_description: str = '',
                   membership_type: str = 'standard', owner_id: str = "") -> str:
    """
    Creates a Microsoft Teams channel
    :param team_aad_id: Team AAD ID to create channel in
    :param channel_name: Name of channel to create
    :param channel_description: Description of channel to create
    :param membership_type: Channel membership type, Standard, Private or Shared. default is 'standard'
    :param owner_id: The channel owner id.
    :return: ID of created channel
    """
    url: str = f'{GRAPH_BASE_URL}/v1.0/teams/{team_aad_id}/channels'
    request_json: dict = {
        'displayName': channel_name,
        'description': channel_description,
        'membershipType': membership_type
    }

    if owner_id:
        request_json["members"] = [create_conversation_member(owner_id, ["owner"])]

    # For membershipType: standard or private - returns 201 in successful and a channel object
    # For shared, returns 202 Accepted response code and a link to the teamsAsyncOperation.
    channel_data: dict = cast(dict[Any, Any], http_request('POST', url, json_=request_json))
    channel_id: str = channel_data.get('id', '')
    return channel_id


def create_meeting(user_id: str, subject: str, start_date_time: str, end_date_time: str) -> dict:
    """
    Creates a Microsoft Teams meeting
    :param user_id: The User's ID
    :param subject: The meeting's subject
    :param start_date_time: The meeting's start time
    :param end_date_time: The meeting's end time
    :return: Dict with info about the created meeting.
    """
    url: str = f'{GRAPH_BASE_URL}/v1.0/users/{user_id}/onlineMeetings'
    request_json: dict = {
        'subject': subject
    }
    if start_date_time:
        request_json['startDateTime'] = start_date_time
    if end_date_time:
        request_json['endDateTime'] = end_date_time

    channel_data: dict = cast(dict[Any, Any], http_request('POST', url, json_=request_json))
    return channel_data


def send_message_in_chat(content: str, message_type: str, chat_id: str, content_type: str) -> dict:
    """
    Sends an HTTP request to send message in chat to Microsoft Teams
    :param content: The content of the chat message.
    :param message_type: The type of chat message.
    :param chat_id: The chat id
    :param content_type: The content type: html/text
    :return: dict of the chatMessage object
    """
    url = f'{GRAPH_BASE_URL}/v1.0/chats/{chat_id}/messages'
    request_json = {
        "body": {
            "content": content,
            "contentType": content_type
        },
        "messageType": message_type
    }

    response: dict = cast(dict[Any, Any], http_request('POST', url, json_=request_json))
    return response


def chat_update_name(chat_id: str, topic: str):
    """
    Updates the chat name
    :param chat_id: The chat id
    :param topic: The new chat name
    """
    url = f"{GRAPH_BASE_URL}/v1.0/chats/{chat_id}"
    request_json = {'topic': topic}
    http_request('PATCH', url, json_=request_json)


def add_user_to_chat(chat_id: str, user_type: str, user_id: str, share_history: bool):
    """
    Adds member to given chat
    :param chat_id: The chat id
    :param user_type: The user_type: guest/member
    :param user_id: The user id
    :param share_history: whether to share history
    """

    url = f"{GRAPH_BASE_URL}/v1.0/chats/{chat_id}/members"

    request_json = {
        '@odata.type': '#microsoft.graph.aadUserConversationMember',
        'roles': [USER_TYPE_TO_USER_ROLE.get(user_type)],
        'user@odata.bind': f"https://graph.microsoft.com/v1.0/users/{user_id}",
        'visibleHistoryStartDateTime': '0001-01-01T00:00:00Z' if share_history else ''
    }

    http_request('POST', url, json_=request_json)


def pages_puller(response: dict[str, Any], limit: int = 1) -> tuple[list, str | None]:
    """
    Retrieves a limited number of pages by repeatedly making requests to the API using the nextLink URL
    until it has reached the specified limit or there are no more pages to retrieve,
    :param response: response body, contains collection of chat/message objects
    :param limit: the requested limit
    :return: tuple of the limited response_data and the last nextLink URL.
    """

    response_data = response.get('value', [])
    while (next_link := response.get('@odata.nextLink')) and len(response_data) < limit:
        demisto.debug(f"Using response {next_link=}")
        response = cast(dict[str, Any], http_request('GET', next_link))
        response_data.extend(response.get('value', []))
    demisto.debug(f'The limited response contains: {len(response_data[:limit])}')
    return response_data[:limit], next_link


def get_chats_list(odata_params: dict, chat_id: str | None = None) -> dict[str, Any]:
    """
    :param odata_params: The OData query parameters.
    :param chat_id: when chat argument was provided - Retrieve a single chat
    :return: The response body - collection of chat objects.
    """
    url = f"{GRAPH_BASE_URL}/v1.0/chats/"
    if chat_id:
        url += chat_id
    return cast(dict[str, Any], http_request('GET', url, params=odata_params))


def get_messages_list(chat_id: str, odata_params: dict) -> dict[str, Any]:
    """
    Retrieve the list of messages in a chat.
    :param chat_id: The chat_id
    :param odata_params: The OData query parameters.
    :return: The response body - collection of chatMessage objects.
    """
    url = f"{GRAPH_BASE_URL}/v1.0/chats/{chat_id}/messages"
    return cast(dict[str, Any], http_request('GET', url, params=odata_params))


def get_chat_members(chat_id: str) -> list[dict[str, Any]]:
    """
    Retrieves chat members given a chat
    :param chat_id: ID of the chat
    :return: List of chat members
    """

    url = f"{GRAPH_BASE_URL}/v1.0/chats/{chat_id}/members"
    response: dict = cast(dict[Any, Any], http_request('GET', url))
    return response.get('value', [])


def get_signed_in_user() -> dict[str, str]:
    """
    Get the properties of the signed-in user
    :return: the properties of the signed-in user
    """
    url = f"{GRAPH_BASE_URL}/v1.0/me"
    return cast(dict[str, str], http_request('GET', url))


def create_chat(chat_type: str, users: list, chat_name: str = "") -> dict:
    """
    Create a new chat object.
    :param chat_type: Specifies the type of chat. Possible values are: group and oneOnOne.
    :param chat_name: The title of the chat. The chat title can be provided only if the chat is of group type.
    :param users: List of conversation members that should be added, contains the (user_id, user_type)
    :return: The chat data
    """
    demisto.debug(f'create {chat_type} chat with users = {users}')
    url = f'{GRAPH_BASE_URL}/v1.0/chats'

    # Add the caller as owner member
    caller_id: str = get_signed_in_user().get('id', '')
    members: list = [create_conversation_member(caller_id, ["owner"])]

    members += [create_conversation_member(user_id, [USER_TYPE_TO_USER_ROLE.get(user_type)])
                for user_id, user_type in users]

    request_json: dict = {
        "chatType": chat_type,
        "members": members,
    }

    if chat_type == 'group' and chat_name:  # The chat title can be provided only if the chat is of group type.
        request_json["topic"] = chat_name
    chat_data: dict = cast(dict[Any, Any], http_request('POST', url, json_=request_json))
    return chat_data


def create_channel_command():
    channel_name: str = demisto.args().get('channel_name', '')
    channel_description: str = demisto.args().get('description', '')
    team_name: str = demisto.args().get('team', '')
    membership_type: str = demisto.args().get('membership_type', 'standard')

    owner_user = demisto.args().get("owner_user")
    if not owner_user and membership_type != "standard" and AUTH_TYPE == CLIENT_CREDENTIALS_FLOW:
        raise ValueError("When using the 'Client Credentials flow', you must specify an 'owner_user'.")

    owner_id: str = ""
    if owner_user:
        owner: list = get_user(owner_user)
        if not (owner and owner[0].get('id')):
            raise ValueError(f'The given owner_user "{owner_user}" was not found')
        owner_id = owner[0].get('id')

    team_aad_id = get_team_aad_id(team_name)
    channel_id: str = create_channel(team_aad_id, channel_name, channel_description, membership_type, owner_id)
    if channel_id or membership_type == 'shared':
        demisto.results(f'The channel "{channel_name}" was created successfully')


def create_meeting_command():
    subject: str = demisto.args().get('subject', '')
    start_date_time: str = demisto.args().get('start_time', '')
    end_date_time: str = demisto.args().get('end_time', '')
    member = demisto.args().get('member', '')

    user: list = get_user(member)
    if not (user and user[0].get('id')):
        raise ValueError(f'User {member} was not found')
    meeting_data: dict = create_meeting(user[0].get('id'), subject, start_date_time, end_date_time)

    thread_id = ''
    message_id = ''
    if chat_info := meeting_data.get('chatInfo', {}):
        thread_id = chat_info.get('threadId', '')
        message_id = chat_info.get('messageId', '')

    participant_id, participant_display_name = get_participant_info(meeting_data.get('participants', {}))

    outputs = {
        'creationDateTime': meeting_data.get('creationDateTime', ''),
        'threadId': thread_id,
        'messageId': message_id,
        'id': meeting_data.get('id', ''),
        'joinWebUrl': meeting_data.get('joinWebUrl', ''),
        'participantId': participant_id,
        'participantDisplayName': participant_display_name
    }
    result = CommandResults(
        readable_output=f'The meeting "{subject}" was created successfully',
        outputs_prefix='MicrosoftTeams.CreateMeeting',
        outputs_key_field='id',
        outputs=outputs
    )
    return_results(result)


def channel_user_list_command():
    """
    Retrieve a list of conversationMembers from a channel.
    """
    channel_name: str = demisto.args().get('channel_name', '')
    team_name: str = demisto.args().get('team', '')
    team_aad_id = get_team_aad_id(team_name)

    channel_id = get_channel_id(channel_name, team_aad_id, investigation_id=None)
    channel_members: list = get_channel_members(team_aad_id, channel_id)
    [member.pop('@odata.type', None) for member in channel_members]
    result = CommandResults(
        readable_output=tableToMarkdown(
            f'Channel "{channel_name}" Members List:',
            channel_members,
            headers=['userId', 'email', 'tenantId', 'id', 'roles', 'displayName', 'visibleHistoryStartDateTime'],
            headerTransform=lambda h: CHANNEL_SPECIAL_MARKDOWN_HEADERS.get(h, pascalToSpace(h)),
        ),
        outputs_prefix='MicrosoftTeams.ChannelList',
        outputs_key_field='channelId',
        outputs={'members': channel_members, 'channelName': channel_name, 'channelId': channel_id}
    )
    return_results(result)


def is_bot_in_chat(chat_id: str) -> bool:
    """
    check if the bot is already in the chat.
    """

    url_suffix = f"v1.0/chats/{chat_id}/installedApps"
    res = http_request('GET', urljoin(GRAPH_BASE_URL, url_suffix),
                       params={"$expand": "teamsApp,teamsAppDefinition",
                               "$filter": f"teamsApp/externalId eq '{BOT_ID}'"})
    return bool(res.get('value'))   # type: ignore


def add_bot_to_chat(chat_id: str):
    """
    Add the Dbot to a chat.
    :param chat_id: chat id which to add the bot to.
    """

    demisto.debug(f'adding bot with id {BOT_ID} to chat')

    # bot is already part of the chat
    if is_bot_in_chat(chat_id):
        return
    res = http_request('GET', f"{GRAPH_BASE_URL}/v1.0/appCatalogs/teamsApps",
                       params={"$filter": f"externalId eq '{BOT_ID}'"})
    app_data = res.get('value')[0]      # type: ignore
    bot_internal_id = app_data.get('id')

    request_json = {"teamsApp@odata.bind": f"https://graph.microsoft.com/v1.0/appCatalogs/teamsApps/{bot_internal_id}"}
    http_request('POST', f'{GRAPH_BASE_URL}/v1.0/chats/{chat_id}/installedApps', json_=request_json)

    demisto.debug(f"Bot {app_data.get('displayName')} with {BOT_ID} ID was added to chat successfully")


def chat_create_command():
    """
    Create a new chat object.
    Note: Only one one-on-one chat can exist between two members.
    If a one-on-one chat already exists, this operation will return the existing chat and not create a new one.
    """
    args = demisto.args()
    chat_type: str = args.get('chat_type', 'group')
    chat_name: str = args.get('chat_name', '')
    members: list = argToList(args.get('member', ''))

    # get users ids and userTypes:
    users, invalid_members = [], []
    for member in members:
        user_data: list = get_user(member)
        if not (user_data and user_data[0].get('id')):
            invalid_members.append(member)
        else:
            users.append((user_data[0].get('id'), user_data[0].get('userType')))

    if invalid_members:
        return_warning(f'The following members were not found: {", ".join(invalid_members)}')
    if chat_type == 'oneOnOne' and len(users) != 1:
        raise ValueError("Creation of 'oneOnOne' chat requires 2 members. Please enter one 'member'.")

    chat_data: dict = create_chat(chat_type, users, chat_name)
    chat_data.pop('@odata.context', '')
    chat_data['chatId'] = chat_data.pop('id', '')

    add_bot_to_chat(chat_data.get("chatId", ''))

    hr_title = f"The chat '{chat_name}' was created successfully" if chat_type == 'group' else \
        f'The chat with "{members[0]}" was created successfully'

    result = CommandResults(
        readable_output=tableToMarkdown(
            hr_title,
            chat_data,
            headers=['chatId', 'topic', 'createdDateTime', 'lastUpdatedDateTime', 'webUrl', 'tenantId'],
            url_keys=['webUrl'],
            headerTransform=lambda h: CHAT_SPECIAL_MARKDOWN_HEADERS.get(h, pascalToSpace(h)),
        ),
        outputs_prefix='MicrosoftTeams.ChatList',
        outputs_key_field='chatId',
        outputs=chat_data
    )
    return_results(result)


def message_send_to_chat_command():
    """
    Send a new chatMessage in the specified chat.
    """
    args = demisto.args()
    content: str = args.get('content', '')
    content_type: str = args.get('content_type', 'text')
    message_type: str = args.get('message_type', 'message')
    chat: str = args.get('chat', '')
    chat_id, _ = get_chat_id_and_type(chat)

    add_bot_to_chat(chat_id)

    message_data: dict = send_message_in_chat(content, message_type, chat_id, content_type)
    message_data.pop('@odata.context', '')
    hr = get_message_human_readable(message_data)
    result = CommandResults(
        readable_output=tableToMarkdown(
            f"Message was sent successfully in the '{chat}' chat.",
            hr,
            removeNull=True
        ),
        outputs_prefix='MicrosoftTeams.ChatList',
        outputs_key_field='chatId',
        outputs={"messages": message_data, "chatId": chat_id}
    )
    return_results(result)


def get_message_human_readable(message_data: dict) -> dict:
    """
    Get Message human-readable.
    :param message_data: The message data
    :return: message human readable.
    """
    return {'Message id': message_data.get('id'),
            'Message Type': message_data.get('messageType'),
            "Etag": message_data.get('etag'),
            'Created DateTime': message_data.get('createdDateTime'),
            'lastModified DateTime': message_data.get('lastModifiedDateTime'),
            'Subject': message_data.get('subject'),
            'Chat Id': message_data.get('chatId'),
            'Importance': message_data.get('importance'),
            'Message Content': demisto.get(message_data, 'body.content'),
            'Message contentType': demisto.get(message_data, 'body.contentType'),
            'Initiator application': demisto.get(message_data, 'eventDetail.initiator.application'),
            'Initiator device': demisto.get(message_data, 'eventDetail.initiator.device'),
            'Initiator user id': demisto.get(message_data, 'eventDetail.initiator.user.id'),
            'Initiator displayName': demisto.get(message_data, 'eventDetail.initiator.user.displayName'),
            'Initiator userIdentityType': demisto.get(message_data, 'eventDetail.initiator.user.userIdentityType'),
            'From application': demisto.get(message_data, 'application'),
            'From device': demisto.get(message_data, 'device'),
            'From user id': demisto.get(message_data, 'from.user.id'),
            'From user': demisto.get(message_data, 'from.user.displayName'),
            'From user userIdentityType': demisto.get(message_data, 'from.user.userIdentityType'),
            'From user tenantId': demisto.get(message_data, 'from.user.tenantId'),
            }


def chat_add_user_command():
    """
    Add a conversationMember to a chat.
    """
    args = demisto.args()
    chat: str = args.get('chat', '')
    chat_id, chat_type = get_chat_id_and_type(chat)
    if chat_type != 'group':
        raise ValueError("Adding a member is allowed only on group chat.")
    members: list = argToList(args.get('member', ''))
    share_history = argToBoolean(args.get('share_history', True))

    invalid_members, hr_members = [], []
    for member in members:
        user_data: list = get_user(member)
        if not (user_data and user_data[0].get('id')):
            invalid_members.append(member)
        else:
            add_user_to_chat(chat_id, user_data[0].get('userType'), user_data[0].get('id'), share_history)
            hr_members.append(member)

    if invalid_members:
        return_warning(f'The following members were not found: {", ".join(invalid_members)}',
                       exit=len(members) == len(invalid_members))

    hr: str = f'The Users "{", ".join(hr_members)}" have been added to chat "{chat}" successfully.' \
        if len(hr_members) > 1 else f'The User "{", ".join(hr_members)}" has been added to chat "{chat}" successfully.'
    demisto.results(hr)


def chat_message_list_command():
    """
    Retrieve the list of messages in a chat.
    """
    args = demisto.args()
    chat = args.get('chat')
    chat_id, _ = get_chat_id_and_type(chat)
    next_link = args.get('next_link', '')

    limit = arg_to_number(args.get('limit')) or MAX_ITEMS_PER_RESPONSE
    page_size = arg_to_number(args.get('page_size')) or MAX_ITEMS_PER_RESPONSE

    top = MAX_ITEMS_PER_RESPONSE if limit >= MAX_ITEMS_PER_RESPONSE else limit

    if next_link and page_size:
        limit = page_size
        messages_list_response: dict = cast(dict[str, Any], http_request('GET', next_link))
    else:
        messages_list_response = get_messages_list(chat_id=chat_id,
                                                   odata_params={'$orderBy': args.get('order_by') + " desc",
                                                                 '$top': top})
    messages_data, next_link = pages_puller(messages_list_response, limit)

    hr = [get_message_human_readable(message) for message in messages_data]
    result = CommandResults(
        readable_output=tableToMarkdown(
            f'Messages list in "{chat}" chat:',
            hr,
            url_keys=['webUrl'],
            removeNull=True) + (f"\nThere are more results than shown. "
                                f"For more data please enter the next_link argument:\n "
                                f"next_link={next_link}" if next_link else ""),
        outputs_key_field='chatId',
        outputs={'MicrosoftTeams(true)': {'MessageListNextLink': next_link},
                 'MicrosoftTeams.ChatList(val.chatId && val.chatId === obj.chatId)': {'messages': messages_data,
                                                                                      'chatId': chat_id}}

    )
    return_results(result)


def chat_list_command():
    """
    Retrieve the list of chats that the user is part of.
    """
    args = demisto.args()
    chat = args.get('chat')
    filter_query = args.get('filter')
    next_link = args.get('next_link')
    page_size = arg_to_number(args.get('page_size')) or MAX_ITEMS_PER_RESPONSE
    limit = arg_to_number(args.get('limit')) or MAX_ITEMS_PER_RESPONSE

    if chat:
        if filter_query:
            raise ValueError("Retrieve a single chat does not support the 'filter' ODate query parameter.")
        chat_id = chat if chat.endswith((GROUP_CHAT_ID_SUFFIX, ONEONONE_CHAT_ID_SUFFIX)) else \
            get_chat_id_and_type(chat)[0]
        chats_list_response: dict = get_chats_list(odata_params={'$expand': args.get('expand')}, chat_id=chat_id)
        chats_list_response.pop('@odata.context', '')
        chats_data = [chats_list_response]
    else:
        if next_link and page_size:
            demisto.debug(f"Get chat-list using the given arguments: {next_link=} and {page_size=}")
            limit = page_size
            # the $top in the request will be as in the previous query.
            chats_list_response = cast(dict[str, Any], http_request('GET', next_link))
        else:
            demisto.debug(f"Get chat-list using the given arguments: {limit=}")
            top = MAX_ITEMS_PER_RESPONSE if limit >= MAX_ITEMS_PER_RESPONSE else limit
            chats_list_response = get_chats_list(odata_params={'$filter': filter_query,
                                                               '$expand': args.get('expand'),
                                                               '$top': top})

        chats_data, next_link = pages_puller(chats_list_response, limit)

    hr = [{**chat_data, 'lastMessageReadDateTime': demisto.get(chat_data, "viewpoint.lastMessageReadDateTime")}
          for chat_data in chats_data]
    for chat_data in chats_data:
        chat_data['chatId'] = chat_data.pop('id', '')
    result = CommandResults(
        readable_output=tableToMarkdown(
            ("Chat Data:" if chat else "Chats List:"),
            hr,
            url_keys=['webUrl'],
            removeNull=True,
            headers=['id', 'topic', 'createdDateTime', 'lastUpdatedDateTime', 'chatType', 'webUrl', 'onlineMeetingInfo',
                     'tenantId', 'lastMessageReadDateTime'],
            headerTransform=lambda h: CHAT_SPECIAL_MARKDOWN_HEADERS.get(h, pascalToSpace(h))
        ) + (f"\nThere are more results than shown. "
             f"For more data please enter the next_link argument:\n next_link={next_link}" if next_link else ""),
        outputs_key_field='chatId',
        outputs={'MicrosoftTeams(true)': {'ChatListNextLink': next_link},
                 'MicrosoftTeams.ChatList(val.chatId && val.chatId == obj.chatId)': chats_data}
    )
    return_results(result)


def chat_member_list_command():
    """
    List all conversation members in a chat.
    """

    chat: str = demisto.args().get('chat', '')
    chat_id, _ = get_chat_id_and_type(chat)

    chat_members: list = get_chat_members(chat_id)
    [member.pop('@odata.type', None) for member in chat_members]
    result = CommandResults(
        readable_output=tableToMarkdown(
            f'Chat "{chat}" Members List:',
            chat_members,
            headers=['userId', 'roles', 'displayName', 'email', 'tenantId'],
            headerTransform=lambda h: CHAT_SPECIAL_MARKDOWN_HEADERS.get(h, pascalToSpace(h)),
        ),
        outputs_prefix='MicrosoftTeams.ChatList',
        outputs_key_field='chatId',
        outputs={"members": chat_members, "chatId": chat_id}
    )
    return_results(result)


def chat_update_command():
    """
    Update the title of the chat.
    """
    chat: str = demisto.args().get('chat', '')
    new_name: str = demisto.args().get('chat_name', '')

    chat_id, chat_type = get_chat_id_and_type(chat)
    if chat_type != 'group':
        raise ValueError("Setting chat name is allowed only on group chats.")

    chat_update_name(chat_id, new_name)
    hr = f"The name of chat '{chat}' has been successfully changed to '{new_name}'."
    return_results(hr)


def remove_user_from_channel(team_id: str, channel_id: str, membership_id: str):
    """
    Request for removing user from channel
    :param team_id: The team id
    :param channel_id: The channel id
    :param membership_id: the user membership_id
    """
    url = f'{GRAPH_BASE_URL}/v1.0/teams/{team_id}/channels/{channel_id}/members/{membership_id}'
    http_request('DELETE', url)


def get_user_membership_id(member: str, team_id: str, channel_id: str) -> str:
    """
    Searches for the given member in the channel's members and returns its membership id
    :param member: The display name of the user
    :param team_id: The team id
    :param channel_id: The channel id
    :return: the user membership_id
    """
    channel_members: list[dict[str, Any]] = get_channel_members(team_id, channel_id)
    return next(
        (
            user.get('id', '') for user in channel_members if user.get('displayName') == member
        ),
        '',
    )


def user_remove_from_channel_command():
    """
    remove user from channel
    This operation is allowed only for channels with a membershipType value of private or shared.
    """
    args = demisto.args()
    channel_name: str = args.get('channel_name', '')
    team_name: str = args.get('team', '')
    member = args.get('member', '')
    team_id = get_team_aad_id(team_name)
    channel_id = get_channel_id(channel_name, team_id, investigation_id=None)
    if get_channel_type(channel_id, team_id) == 'standard':
        raise ValueError('Removing a member is allowed only for private or shared channels.')

    user_membership_id = get_user_membership_id(member, team_id, channel_id)
    if not user_membership_id:
        raise ValueError(f'User "{member}" was not found in channel "{channel_name}".')

    remove_user_from_channel(team_id, channel_id, user_membership_id)
    return_results(f'The user "{member}" has been removed from channel "{channel_name}" successfully.')


def get_participant_info(participants: dict) -> tuple[str, str]:
    """
    Retrieves the participant ID and name
    :param participants: The participants in the Team meeting
    :return: The participant ID and name
    """
    participant_id = ''
    participant_display_name = ''

    if participants:
        user = participants.get('organizer', {}).get('identity', {}).get('user', {})
        if user:
            participant_id = user.get('id')
            participant_display_name = user.get('displayName')

    return participant_id, participant_display_name


def get_channel_id(channel_name: str, team_aad_id: str, investigation_id: str = None) -> str:
    """
    Retrieves Microsoft Teams channel ID
    :param channel_name: Name of channel to get ID of
    :param team_aad_id: AAD ID of team to search channel in
    :param investigation_id: Demisto investigation ID to search mirrored channel of
    :return: Requested channel ID
    """
    investigation_id = investigation_id or ''
    integration_context: dict = get_integration_context()
    teams: list = json.loads(integration_context.get('teams', '[]'))
    for team in teams:
        mirrored_channels: list = team.get('mirrored_channels', [])
        for channel in mirrored_channels:
            if channel.get('channel_name') == channel_name or channel.get('investigation_id') == investigation_id:
                return channel.get('channel_id')
    url: str = f'{GRAPH_BASE_URL}/v1.0/teams/{team_aad_id}/channels'
    response: dict = cast(dict[Any, Any], http_request('GET', url))
    channel_id: str = ''
    channels: list = response.get('value', [])
    for channel in channels:
        channel_display_name: str = channel.get('displayName', '')
        if channel_display_name == channel_name:
            channel_id = channel.get('id', '')
            break
    if not channel_id:
        raise ValueError(f'Could not find channel: {channel_name}')
    return channel_id


def get_channel_type(channel_id, team_id) -> str:
    """
    Returns the channel membershipType
    :param channel_id: The name of the channel
    :param team_id: ID of the channel's team
    :return: The channel's membershipType
    """
    url = f'{GRAPH_BASE_URL}/v1.0/teams/{team_id}/channels/{channel_id}'
    response: dict = cast(dict[Any, Any], http_request('GET', url))
    demisto.debug(f"The channel membershipType = {response.get('membershipType')}")
    return response.get('membershipType', 'standard')


def get_team_members(service_url: str, team_id: str) -> list:
    """
    Retrieves team members given a team
    :param team_id: ID of team to get team members of
    :param service_url: Bot service URL to query
    :return: List of team members
    """
    url = f'{service_url}/v3/conversations/{team_id}/members'
    response: list = cast(list[Any], http_request('GET', url, api='bot'))
    return response


def update_integration_context_with_all_team_members(integration_context):
    """
    Retrieves all members from all teams and updates members in integration context.
    """
    service_url: str = integration_context.get('service_url', '')
    teams: list = json.loads(integration_context.get('teams', '[]'))
    for team in teams:
        team_id = team.get('team_id', '')
        team_name = team.get('team_name', '')
        demisto.debug(f'Request members for {team_id=} {team_name=}')
        url = f'{service_url}/v3/conversations/{team_id}/members'
        team_members: list = cast(list[Any], http_request('GET', url, api='bot'))
        demisto.debug(f'Updating {team_name=} with {team_members=}')
        team['team_members'] = team_members
    demisto.debug(f'Setting integration_context with {teams=}')
    integration_context['teams'] = json.dumps(teams)
    set_integration_context(integration_context)


def get_channel_members(team_id: str, channel_id: str) -> list[dict[str, Any]]:
    """
    Retrieves channel members given a channel
    :param team_id: ID of the channel's team
    :param channel_id: ID of channel to get channel members of
    :return: List of channel members
    """
    url = f'{GRAPH_BASE_URL}/v1.0/teams/{team_id}/channels/{channel_id}/members'
    response: dict = cast(dict[Any, Any], http_request('GET', url))
    return response.get('value', [])


def update_message(service_url: str, conversation_id: str, activity_id: str, text: str):
    """
    Updates a message in Microsoft Teams channel
    :param service_url: Bot service URL to query
    :param conversation_id: Conversation ID of message to update
    :param activity_id: Activity ID of message to update
    :param text: Text to update in the message
    :return: None
    """
    body = [{
        'type': 'TextBlock',
        'text': text
    }]
    adaptive_card: dict = create_adaptive_card(body=body)
    conversation = {
        'type': 'message',
        'attachments': [adaptive_card]
    }
    url: str = f'{service_url}/v3/conversations/{conversation_id}/activities/{activity_id}'
    http_request('PUT', url, json_=conversation, api='bot')


def close_channel_request(team_aad_id: str, channel_id: str):
    """
    Sends an HTTP request to close a Microsoft Teams channel
    :param team_aad_id: AAD ID of team to close the channel in
    :param channel_id: ID of channel to close
    :return: None
    """
    url: str = f'{GRAPH_BASE_URL}/v1.0/teams/{team_aad_id}/channels/{channel_id}'
    http_request('DELETE', url)


def close_channel():
    """
    Deletes a mirrored Microsoft Teams channel
    """
    integration_context: dict = get_integration_context()
    channel_name: str = demisto.args().get('channel', '')
    investigation: dict = demisto.investigation()
    investigation_id: str = investigation.get('id', '')
    channel_id = ''
    team_aad_id: str
    mirrored_channels: list
    if not channel_name:
        # Closing channel as part of autoclose in mirroring process
        teams: list = json.loads(integration_context.get('teams', '[]'))
        for team in teams:
            team_aad_id = team.get('team_aad_id', '')
            mirrored_channels = team.get('mirrored_channels', [])
            for channel_index, channel in enumerate(mirrored_channels):
                if channel.get('investigation_id') == investigation_id:
                    channel_id = channel.get('channel_id', '')
                    close_channel_request(team_aad_id, channel_id)
                    mirrored_channels.pop(channel_index)
                    team['mirrored_channels'] = mirrored_channels
                    break
        if not channel_id:
            raise ValueError('Could not find Microsoft Teams channel to close.')
        integration_context['teams'] = json.dumps(teams)
        set_integration_context(integration_context)
    else:
        team_name: str = demisto.args().get('team') or demisto.params().get('team')
        team_aad_id = get_team_aad_id(team_name)
        channel_id = get_channel_id(channel_name, team_aad_id, investigation_id)
        close_channel_request(team_aad_id, channel_id)
    demisto.results('Channel was successfully closed.')


def create_personal_conversation(integration_context: dict, team_member_id: str) -> str:
    """
    Create a personal conversation with a team member
    :param integration_context: Cached object to retrieve relevant data for the conversation creation
    :param team_member_id: ID of team member to create a conversation with
    :return: ID of created conversation
    """
    bot_id: str = BOT_ID
    bot_name: str = integration_context.get('bot_name', '')
    tenant_id: str = integration_context.get('tenant_id', '')
    conversation: dict = {
        'bot': {
            'id': f'28:{bot_id}',
            'name': bot_name
        },
        'members': [{
            'id': team_member_id
        }],
        'channelData': {
            'tenant': {
                'id': tenant_id
            }
        }
    }
    service_url: str = integration_context.get('service_url', '')
    if not service_url:
        raise ValueError('Did not find service URL. Try messaging the bot on Microsoft Teams')
    url: str = f'{service_url}/v3/conversations'
    response: dict = cast(dict[Any, Any], http_request('POST', url, json_=conversation, api='bot'))
    return response.get('id', '')


def send_message_request(service_url: str, channel_id: str, conversation: dict):
    """
    Sends an HTTP request to send message to Microsoft Teams
    :param channel_id: ID of channel to send message in
    :param conversation: Conversation message object to send
    :param service_url: Bot service URL to query
    :return: None
    """
    url: str = f'{service_url}/v3/conversations/{channel_id}/activities'
    http_request('POST', url, json_=conversation, api='bot')


def process_mentioned_users_in_message(message: str) -> tuple[list, str]:
    """
    Processes the message to include all mentioned users in the right format. For example:
    Input: 'good morning @Demisto'
    Output (Formatted message): 'good morning <at>@Demisto</at>'
    :param message: The message to be processed
    :return: A list of the mentioned users, The processed message
    """
    mentioned_users: list = [''.join(user) for user in re.findall(MENTION_REGEX, message)]
    for user in mentioned_users:
        message = message.replace(f'@{user};', f'<at>@{user}</at>')
    return mentioned_users, message


def mentioned_users_to_entities(mentioned_users: list, integration_context: dict) -> list:
    """
    Returns a list of entities built from the mentioned users
    :param mentioned_users: A list of mentioned users in the message
    :param integration_context: Cached object to retrieve relevant data from
    :return: A list of entities
    """
    return [{'type': 'mention', 'mentioned': {'id': get_team_member_id(user, integration_context), 'name': user},
             'text': f'<at>@{user}</at>'} for user in mentioned_users]


def send_message():
    message_type: str = demisto.args().get('messageType', '')
    original_message: str = demisto.args().get('originalMessage', '')
    message: str = demisto.args().get('message', '')
    external_form_url_header: str | None = demisto.args().get(
        'external_form_url_header') or demisto.params().get('external_form_url_header')
    demisto.debug(f"In send message with message type: {message_type}, and channel name:{demisto.args().get('channel')}")
    try:
        adaptive_card: dict = json.loads(demisto.args().get('adaptive_card', '{}'))
    except ValueError:
        raise ValueError('Given adaptive card is not in valid JSON format.')

    if message_type == MESSAGE_TYPES['mirror_entry'] and ENTRY_FOOTER in original_message:
        demisto.debug(f"the message '{message}' was already mirrored, skipping it")
        # Got a message which was already mirrored - skipping it
        return
    channel_name: str = demisto.args().get('channel', '')

    if (not channel_name and message_type in {MESSAGE_TYPES['status_changed'], MESSAGE_TYPES['incident_opened']}) \
            or channel_name == INCIDENT_NOTIFICATIONS_CHANNEL:
        demisto.debug("Got a notification from server.")
        # Got a notification from server
        channel_name = demisto.params().get('incident_notifications_channel', 'General')
        severity: float = float(demisto.args().get('severity'))

        # Adding disable and not enable because of adding new boolean parameter always defaults to false value in server
        if (disable_auto_notifications := demisto.params().get('auto_notifications')) is not None:
            disable_auto_notifications = argToBoolean(disable_auto_notifications)
        else:
            disable_auto_notifications = False

        if not disable_auto_notifications:
            severity_threshold: float = translate_severity(demisto.params().get('min_incident_severity', 'Low'))
            if severity < severity_threshold:
                return
        else:
            return

    team_member: str = demisto.args().get('team_member', '') or demisto.args().get('to', '')
    if re.match(r'\b[^@]+@[^@]+\.[^@]+\b', team_member):  # team member is an email
        team_member = team_member.lower()

    if not (team_member or channel_name):
        raise ValueError('No channel or team member to send message were provided.')

    if team_member and channel_name:
        raise ValueError('Provide either channel or team member to send message to, not both.')

    if not (message or adaptive_card):
        raise ValueError('No message or adaptive card to send were provided.')

    if message and adaptive_card:
        raise ValueError('Provide either message or adaptive to send, not both.')

    integration_context: dict = get_integration_context()
    channel_id = ''
    personal_conversation_id = ''
    if channel_name:
        channel_id = get_channel_id_for_send_notification(channel_name, message_type)
    elif team_member:
        try:
            team_member_id: str = get_team_member_id(team_member, integration_context)
        except Exception:
            demisto.debug(f"Did not find '{team_member=}' will update integration context with all team members.")
            update_integration_context_with_all_team_members(integration_context)
            team_member_id = get_team_member_id(team_member, integration_context)
        personal_conversation_id = create_personal_conversation(integration_context, team_member_id)

    recipient: str = channel_id or personal_conversation_id

    conversation: dict = {}

    if message:
        entitlement_match_msg: Match[str] | None = re.search(ENTITLEMENT_REGEX, message)
        if entitlement_match_msg and is_teams_ask_message(message):
            # In TeamsAsk process
            adaptive_card = process_ask_user(message)
            conversation = {
                'type': 'message',
                'attachments': [adaptive_card]
            }
            demisto.debug(f"The following Adaptive Card will be used:\n{json.dumps(adaptive_card)}")
        else:
            # Sending regular message
            formatted_message: str = urlify_hyperlinks(message, external_form_url_header)
            mentioned_users, formatted_message_with_mentions = process_mentioned_users_in_message(formatted_message)
            entities = mentioned_users_to_entities(mentioned_users, integration_context)
            demisto.info(f'msg: {formatted_message_with_mentions}, ent: {entities}')
            conversation = {
                'type': 'message',
                'text': formatted_message_with_mentions,
                'entities': entities
            }
    else:  # Adaptive card
        entitlement_match_ac: Match[str] | None = re.search(ENTITLEMENT_REGEX, adaptive_card.get('entitlement', ''))
        if entitlement_match_ac:
            adaptive_card_processed = process_adaptive_card(adaptive_card)
            conversation = {
                'type': 'message',
                'attachments': [adaptive_card_processed]
            }

    service_url: str = integration_context.get('service_url', '')
    if not service_url:
        raise ValueError('Did not find service URL. Try messaging the bot on Microsoft Teams')

    send_message_request(service_url, recipient, conversation)
    demisto.results('Message was sent successfully.')


def get_channel_id_for_send_notification(channel_name: str, message_type: str):
    """
    Returns the channel ID to send the message to
    :param channel_name: The name of the channel.
    :param message_type: The type of message to be sent.
    :return: the channel ID
    """
    team_name: str = demisto.args().get('team', '') or demisto.params().get('team', '')
    team_aad_id: str = get_team_aad_id(team_name)
    investigation_id = ''
    if message_type == MESSAGE_TYPES['mirror_entry']:
        # Got an entry from the War Room to mirror to Teams
        # Getting investigation ID in case channel name is custom and not the default
        investigation: dict = demisto.investigation()
        investigation_id = investigation.get('id', '')
    channel_id = get_channel_id(channel_name, team_aad_id, investigation_id)
    if get_channel_type(channel_id, team_aad_id) != 'standard':
        raise ValueError('Posting a message or adaptive card to a private/shared channel is currently '
                         'not supported.')
    return channel_id


def mirror_investigation():
    """
    Updates the integration context with a new or existing mirror.
    """
    investigation: dict = demisto.investigation()

    if investigation.get('type') == PLAYGROUND_INVESTIGATION_TYPE:
        raise ValueError('Can not perform this action in playground.')

    integration_context: dict = get_integration_context()

    mirror_type: str = demisto.args().get('mirror_type', 'all')
    auto_close: str = demisto.args().get('autoclose', 'true')
    mirror_direction: str = demisto.args().get('direction', 'both').lower()
    team_name: str = demisto.args().get('team', '')
    if not team_name:
        team_name = demisto.params().get('team', '')
    team_aad_id: str = get_team_aad_id(team_name)
    mirrored_channels = []
    teams: list = json.loads(integration_context.get('teams', '[]'))
    team = {}
    for team in teams:
        if team.get('team_aad_id', '') == team_aad_id:
            if team.get('mirrored_channels'):
                mirrored_channels = team['mirrored_channels']
            break
    if mirror_direction != 'both':
        mirror_type = f'{mirror_type}:{mirror_direction}'

    investigation_id: str = investigation.get('id', '')
    investigation_mirrored_index: int = is_investigation_mirrored(investigation_id, mirrored_channels)

    if investigation_mirrored_index > -1:
        # Updating channel mirror configuration
        mirrored_channels[investigation_mirrored_index]['mirror_type'] = mirror_type
        mirrored_channels[investigation_mirrored_index]['mirror_direction'] = mirror_direction
        mirrored_channels[investigation_mirrored_index]['auto_close'] = auto_close
        mirrored_channels[investigation_mirrored_index]['mirrored'] = False
        demisto.results('Investigation mirror was updated successfully.')
    else:
        channel_name: str = demisto.args().get('channel_name', '') or f'incident-{investigation_id}'
        channel_description: str = f'Channel to mirror incident {investigation_id}'
        channel_id: str = create_channel(team_aad_id, channel_name, channel_description)
        service_url: str = integration_context.get('service_url', '')
        server_links: dict = demisto.demistoUrls()
        server_link: str = server_links.get('server', '')
        server_link = server_link + '/#' if not is_demisto_version_ge('8.0.0') else server_link
        warroom_link = f"{server_link}/WarRoom/{investigation_id}"
        conversation: dict = {
            'type': 'message',
            'text': f'This channel was created to mirror [incident {investigation_id}]({warroom_link}) '
                    f'between Teams and Demisto. In order for your Teams messages to be mirrored in Demisto, '
                    f'you need to mention the Demisto Bot in the message.'
        }
        send_message_request(service_url, channel_id, conversation)
        mirrored_channels.append({
            'channel_id': channel_id,
            'investigation_id': investigation_id,
            'mirror_type': mirror_type,
            'mirror_direction': mirror_direction,
            'auto_close': auto_close,
            'mirrored': False,
            'channel_name': channel_name
        })
        demisto.results(f'Investigation mirrored successfully in channel {channel_name}.')
    team['mirrored_channels'] = mirrored_channels
    integration_context['teams'] = json.dumps(teams)
    set_integration_context(integration_context)


def channel_mirror_loop():
    """
    Runs in a long running container - checking for newly mirrored investigations.
    """
    while True:
        found_channel_to_mirror: bool = False
        integration_context = {}
        try:
            integration_context = get_integration_context()
            teams: list = json.loads(integration_context.get('teams', '[]'))
            for team in teams:
                mirrored_channels = team.get('mirrored_channels', [])
                channel: dict
                for channel in mirrored_channels:
                    investigation_id = channel.get('investigation_id', '')
                    if not channel['mirrored']:
                        demisto.info(f'Mirroring incident: {investigation_id} in Microsoft Teams')
                        channel_to_update: dict = channel
                        if channel_to_update['mirror_direction'] and channel_to_update['mirror_type']:
                            demisto.mirrorInvestigation(
                                channel_to_update['investigation_id'],
                                channel_to_update['mirror_type'],
                                bool(strtobool(channel_to_update['auto_close']))
                            )
                            channel_to_update['mirrored'] = True
                            demisto.info(f'Mirrored incident: {investigation_id} to Microsoft Teams successfully')
                        else:
                            demisto.info(f'Could not mirror {investigation_id}')
                        team['mirrored_channels'] = mirrored_channels
                        integration_context['teams'] = json.dumps(teams)
                        set_integration_context(integration_context)
                        found_channel_to_mirror = True
                        break
                if found_channel_to_mirror:
                    break
        except json.decoder.JSONDecodeError as json_decode_error:
            demisto.error(
                f'An error occurred in channel mirror loop while trying to deserialize teams from cache: '
                f'{str(json_decode_error)}'
            )
            demisto.updateModuleHealth(f'An error occurred: {str(json_decode_error)}')
        except Exception as e:
            demisto.error(f'An error occurred in channel mirror loop: {str(e)}')
            demisto.updateModuleHealth(f'An error occurred: {str(e)}')
        finally:
            time.sleep(5)


def member_added_handler(integration_context: dict, request_body: dict, channel_data: dict):
    """
    Handles member added activity
    :param integration_context: Cached object to retrieve relevant data from
    :param request_body: Activity payload
    :param channel_data: Microsoft Teams tenant, team and channel details
    :return: None
    """
    bot_id = BOT_ID

    team: dict = channel_data.get('team', {})
    team_id: str = team.get('id', '')
    team_aad_id: str = team.get('aadGroupId', '')
    team_name: str = team.get('name', '')

    tenant: dict = channel_data.get('tenant', {})
    tenant_id: str = tenant.get('id', '')

    recipient: dict = request_body.get('recipient', {})
    recipient_name: str = recipient.get('name', '')

    members_added: list = request_body.get('membersAdded', [])

    teams: list = json.loads(integration_context.get('teams', '[]'))

    service_url: str = integration_context.get('service_url', '')
    if not service_url:
        raise ValueError('Did not find service URL. Try messaging the bot on Microsoft Teams')

    for member in members_added:
        member_id = member.get('id', '')
        if bot_id in member_id:
            # The bot was added to a team, caching team ID and team members
            demisto.info(f'The bot was added to team {team_name}')
        else:
            demisto.info(f'Someone was added to team {team_name}')
        integration_context['tenant_id'] = tenant_id
        integration_context['bot_name'] = recipient_name
        break

    team_members: list = get_team_members(service_url, team_id)

    found_team: bool = False
    for team in teams:
        if team.get('team_aad_id', '') == team_aad_id:
            team['team_members'] = team_members
            found_team = True
            break
    if not found_team:
        # Didn't found an existing team, adding new team object
        teams.append({
            'team_aad_id': team_aad_id,
            'team_id': team_id,
            'team_name': team_name,
            'team_members': team_members
        })
    integration_context['teams'] = json.dumps(teams)
    set_integration_context(integration_context)


def handle_external_user(user_identifier: str, allow_create_incident: bool, create_incident: bool) -> str:
    """
    Handles message from non xsoar user
    :param user_identifier: the user name or email
    :param allow_create_incident: if external user is allowed to create incidents or not
    :param create_incident: if the message (command) sent by the user is "new incident"
    :return: data: the response from the bot the user
    """
    # external user is not allowed to run any command
    if not allow_create_incident:
        data = f"I'm sorry but I was unable to find you as a Cortex XSOAR user " \
               f"for {user_identifier}. You're not allowed to run any command"

    # allowed creating new incident, but the command sent is not new incident
    elif not create_incident:
        data = "As a non Cortex XSOAR user, you're only allowed to run command:\nnew incident [details]"
    # allowed to create incident, and tried to create incident
    else:
        data = ""

    return data


def direct_message_handler(integration_context: dict, request_body: dict, conversation: dict, message: str):
    """
    Handles a direct message sent to the bot
    :param integration_context: Cached object to retrieve relevant data from
    :param request_body: Activity payload
    :param conversation: Conversation object sent
    :param message: The direct message sent
    :return: None
    """
    conversation_id: str = conversation.get('id', '')

    from_property: dict = request_body.get('from', {})
    user_id: str = from_property.get('id', '')

    team_member: dict = get_team_member(integration_context, user_id)
    if team_member:
        # enrich our data with the sender info
        demisto.debug(f'direct_message_handler for: {team_member=}')
        request_body['from'].update(team_member)

    username: str = team_member.get('username', '')
    user_email: str = team_member.get('user_email', '')
    user_upn = team_member.get('user_principal_name', '')
    demisto_user = demisto.findUser(email=user_email)
    if not demisto_user:
        demisto_user = demisto.findUser(username=username)
    if not demisto_user:
        demisto_user = demisto.findUser(email=user_upn)
    if not demisto_user:
        demisto.debug('direct_message_handler Failed to find user by email, username and UPN')

    formatted_message = ''

    attachment = {}

    return_card: bool = False

    allow_external_incidents_creation: bool = demisto.params().get('allow_external_incidents_creation', False)

    lowered_message = message.lower()
    # the command is to create new incident
    create_incident = 'incident' in lowered_message and ('create' in lowered_message
                                                         or 'open' in lowered_message
                                                         or 'new' in lowered_message)
    data = ("" if demisto_user else handle_external_user(user_email or username,
                                                         allow_external_incidents_creation,
                                                         create_incident,))
    # internal user or external who's trying to create incident
    if not data:
        if create_incident:
            data = process_incident_create_message(demisto_user, message, request_body)
            formatted_message = urlify_hyperlinks(data)
        else:   # internal user running any command except for new incident
            try:
                data = demisto.directMessage(message, username, user_email, allow_external_incidents_creation)
                return_card = True
                if data.startswith('`'):  # We got a list of incidents/tasks:
                    data_by_line: list = data.replace('```', '').strip().split('\n')
                    return_card = True
                    if data_by_line[0].startswith('Task'):
                        attachment = process_tasks_list(data_by_line)
                    else:
                        attachment = process_incidents_list(data_by_line)
                else:  # Mirror investigation command / unknown direct message
                    attachment = process_mirror_or_unknown_message(data)
            except Exception as e:
                data = str(e)

    if return_card:
        conversation = {
            'type': 'message',
            'attachments': [attachment]
        }
    else:
        formatted_message = formatted_message or data
        conversation = {
            'type': 'message',
            'text': formatted_message
        }

    service_url: str = integration_context.get('service_url', '')
    if not service_url:
        raise ValueError('Did not find service URL. Try messaging the bot on Microsoft Teams')

    send_message_request(service_url, conversation_id, conversation)


def entitlement_handler(integration_context: dict, request_body: dict, value: dict, conversation_id: str):
    """
    Handles activity the bot received as part of TeamsAsk flow, which includes entitlement
    :param integration_context: Cached object to retrieve relevant data from
    :param request_body: Activity payload
    :param value: Object which includes
    :param conversation_id: Message conversation ID
    :return: None
    """
    response: str = value.get('response', '')
    if not response:
        # Adaptive Card Response Received
        remove_keys = ['entitlement', 'investigation_id', 'task_id']
        response_dict = {key: value for key, value in value.items() if key not in remove_keys}
        response = tableToMarkdown("Response", response_dict, headers=list(response_dict.keys()))

    demisto.debug(f"Entitlement Response Received\n{value}")
    entitlement_guid: str = value.get('entitlement', '')
    investigation_id: str = value.get('investigation_id', '')
    task_id: str = value.get('task_id', '')
    from_property: dict = request_body.get('from', {})
    team_members_id: str = from_property.get('id', '')
    team_member: dict = get_team_member(integration_context, team_members_id)
    demisto.handleEntitlementForUser(
        incidentID=investigation_id,
        guid=entitlement_guid,
        taskID=task_id,
        email=team_member.get('user_email', ''),
        content=response
    )
    activity_id: str = request_body.get('replyToId', '')
    service_url: str = integration_context.get('service_url', '')
    if not service_url:
        raise ValueError('Did not find service URL. Try messaging the bot on Microsoft Teams')
    update_message(service_url, conversation_id, activity_id, 'Your response was submitted successfully.')


def message_handler(integration_context: dict, request_body: dict, channel_data: dict, message: str):
    """
    Handles a message in which the bot was mentioned
    :param integration_context: Cached object to retrieve relevant data from
    :param request_body: Activity payload
    :param channel_data: Microsoft Teams tenant, team and channel details
    :param message: The message which was sent mentioning the bot
    :return: None
    """
    channel: dict = channel_data.get('channel', {})
    channel_id: str = channel.get('id', '')
    team_id: str = channel_data.get('team', {}).get('id', '')

    from_property: dict = request_body.get('from', {})
    team_member_id: str = from_property.get('id', '')

    if integration_context.get('teams'):
        teams: list = json.loads(integration_context['teams'])
        for team in teams:
            if team.get('team_id', '') == team_id:
                mirrored_channels: list = team.get('mirrored_channels', [])
                for mirrored_channel in mirrored_channels:
                    if mirrored_channel.get('channel_id') == channel_id:
                        if mirrored_channel.get('mirror_direction', '') != 'FromDemisto' \
                                and 'none' not in mirrored_channel.get('mirror_type', ''):
                            investigation_id: str = mirrored_channel.get('investigation_id', '')
                            username: str = from_property.get('name', '')
                            user_email: str = get_team_member(integration_context, team_member_id).get('user_email', '')
                            demisto.debug(f"Adding Entry {message} to investigation {investigation_id}")
                            demisto.addEntry(
                                id=investigation_id,
                                # when pasting the message into the chat, it contains leading and trailing whitespaces
                                entry=message.strip(),
                                username=username,
                                email=user_email,
                                footer=f'\n**{ENTRY_FOOTER}**'
                            )
                        return


@APP.route('/health', methods=['GET'])
def health_check():
    demisto.debug("Microsoft Teams Integration received a local health check")
    return Response('Microsoft Teams long running integration server is up.', status=200, mimetype='text/plain')


@APP.route('/', methods=['POST'])
def messages() -> Response:
    """
    Main handler for messages sent to the bot
    """
    try:
        demisto.debug("Microsoft Teams Integration received a message from Teams")
        demisto.debug('Processing POST query...')
        headers: dict = cast(dict[Any, Any], request.headers)

        if validate_auth_header(headers) is False:
            demisto.info(f'Authorization header failed: {str(headers)}')
        else:
            request_body: dict = request.json   # type: ignore[assignment]
            integration_context: dict = get_integration_context()
            service_url: str = request_body.get('serviceUrl', '')
            if service_url:
                service_url = service_url[:-1] if service_url.endswith('/') else service_url
                integration_context['service_url'] = service_url
                set_integration_context(integration_context)

            channel_data: dict = request_body.get('channelData', {})
            event_type: str = channel_data.get('eventType', '')
            demisto.debug(f"Event Type is: {event_type}")

            conversation: dict = request_body.get('conversation', {})
            conversation_type: str = conversation.get('conversationType', '')
            conversation_id: str = conversation.get('id', '')
            demisto.debug(f"conversation type is: {conversation_type}")

            message_text: str = request_body.get('text', '')

            # Remove bot mention
            bot_name = integration_context.get('bot_name', '')
            formatted_message: str = message_text.replace(f'<at>{bot_name}</at>', '')

            value: dict = request_body.get('value', {})

            if event_type == 'teamMemberAdded':
                demisto.info('New Microsoft Teams team member was added')
                member_added_handler(integration_context, request_body, channel_data)
                demisto.debug(f'Updated team in the integration context. '
                              f'Current saved teams: {json.dumps(get_integration_context().get("teams"))}')
            elif value:
                # In TeamsAsk process
                demisto.info('Got response from user in MicrosoftTeamsAsk process')
                entitlement_handler(integration_context, request_body, value, conversation_id)
            elif conversation_type == 'personal':
                demisto.info('Got direct message to the bot')
                demisto.debug(f"Text is : {request_body.get('text')}")
                if request_body.get("membersAdded", []):
                    demisto.debug("the bot was added to a one-to-one chat")
                direct_message_handler(integration_context, request_body, conversation, formatted_message)
            else:
                demisto.info('Got message mentioning the bot')
                demisto.debug(f"the message is from: {request_body.get('from', {})}")
                message_handler(integration_context, request_body, channel_data, formatted_message)
        demisto.info('Finished processing Microsoft Teams activity successfully')
        demisto.updateModuleHealth('')
        return Response(status=200)
    except Exception as e:
        err_msg = f'Error occurred when handling incoming message {str(e)}'
        demisto.error(err_msg)
        return Response(response=err_msg, status=400)


def ring_user_request(call_request_data):
    return http_request(method='POST', url=f'{GRAPH_BASE_URL}/v1.0/communications/calls',
                        json_=call_request_data)


def ring_user():
    """Rings a user on Teams.

    Notes:
        This is a ring only! no media plays in case the generated call is answered.

    Returns:
        None.
    """
    if AUTH_TYPE == AUTHORIZATION_CODE_FLOW:
        raise DemistoException("In order to use the 'microsoft-teams-ring-user' command, you need to use "
                               "the 'Client Credentials flow'.")

    bot_id = BOT_ID
    integration_context: dict = get_integration_context()
    tenant_id: str = integration_context.get('tenant_id', '')
    if not tenant_id:
        raise ValueError(MISS_CONFIGURATION_ERROR_MESSAGE)
    # get user to call name and id
    username_to_call = demisto.args().get('username')
    user: list = get_user(username_to_call)
    if not (user and user[0].get('id')):
        raise ValueError(f'User {username_to_call} was not found')

    call_request_data = {
        "@odata.type": "#microsoft.graph.call",
        "callbackUri": 'https://callback.url',
        "direction": "outgoing",
        "source": {
            "@odata.type": "#microsoft.graph.participantInfo",
            "identity": {
                "@odata.type": "#microsoft.graph.identitySet",
                "application": {
                    "@odata.type": "#microsoft.graph.identity",
                    "id": bot_id
                }
            }
        },
        "targets": [
            {
                "@odata.type": "#microsoft.graph.invitationParticipantInfo",
                "identity": {
                    "@odata.type": "#microsoft.graph.identitySet",
                    "user": {
                        "@odata.type": "#microsoft.graph.identity",
                        "displayName": username_to_call,
                        "id": user[0].get('id')
                    }
                }
            }
        ],
        "requestedModalities": [
            "audio"
        ],
        "mediaConfig": {
            "@odata.type": "#microsoft.graph.serviceHostedMediaConfig",
        },
        "tenantId": tenant_id
    }
    response = ring_user_request(call_request_data)

    return_outputs(f"Calling {username_to_call}", {}, response)


def update_integration_context_samples(incidents: list, max_samples: int = MAX_SAMPLES):
    """
    Updates the integration context samples with the newly created incident.
    If the size of the samples has reached `MAX_SAMPLES`, will pop out the latest sample.
    Args:
        incidents (list): The list of the newly created incidents.
        max_samples (int): Max samples size.
    """
    ctx = get_integration_context()
    updated_samples_list: list[dict] = incidents + ctx.get('samples', [])
    ctx['samples'] = updated_samples_list[:max_samples]
    set_integration_context(ctx)


def long_running_loop():
    """
    The infinite loop which runs the mirror loop and the bot app in two different threads
    """
    while True:
        certificate: str = CERTIFICATE
        private_key: str = PRIVATE_KEY

        certificate_path = ''
        private_key_path = ''

        server = None

        try:
            port_mapping: str = PARAMS.get('longRunningPort', '')
            port: int
            if port_mapping:
                port = int(port_mapping.split(':')[1]) if ':' in port_mapping else int(port_mapping)
            else:
                raise ValueError('No port mapping was provided')
            Thread(target=channel_mirror_loop, daemon=True).start()
            demisto.info('Started channel mirror loop thread')

            ssl_args = {}

            if certificate and private_key:
                certificate_file = NamedTemporaryFile(delete=False)
                certificate_path = certificate_file.name
                certificate_file.write(bytes(certificate, 'utf-8'))
                certificate_file.close()

                private_key_file = NamedTemporaryFile(delete=False)
                private_key_path = private_key_file.name
                private_key_file.write(bytes(private_key, 'utf-8'))
                private_key_file.close()

                context = SSLContext(PROTOCOL_TLSv1_2)
                context.load_cert_chain(certificate_path, private_key_path)
                ssl_args['ssl_context'] = context

                demisto.info('Starting HTTPS Server')
            else:
                demisto.info('Starting HTTP Server')

            server = WSGIServer(('0.0.0.0', port), APP, log=DEMISTO_LOGGER, error_log=ERROR_LOGGER, **ssl_args)
            demisto.updateModuleHealth('')
            server.serve_forever()
        except SSLError as e:
            ssl_err_message = f'Failed to validate certificate and/or private key: {str(e)}'
            demisto.error(ssl_err_message)
            raise ValueError(ssl_err_message) from e
        except Exception as e:
            error_message = str(e)
            demisto.error(f'An error occurred in long running loop: {error_message} - {format_exc()}')
            demisto.updateModuleHealth(f'An error occurred: {error_message}')
        finally:
            if certificate_path:
                os.unlink(certificate_path)
            if private_key_path:
                os.unlink(private_key_path)
            if server:
                server.stop()
            time.sleep(5)


def token_permissions_list_command():
    """
    Gets the Graph access token stored in the integration context and displays the token's API permissions in the war room.

    Use-case:
    This command is ideal for users encountering insufficient permissions errors when attempting to
    execute an integration command.
    By utilizing this command, the user can identify the current permissions associated with their token (app), compare them to
    the required permissions for executing the desired command (detailed in the integration's docs), and determine any additional
    permissions needed to be added to their application.
    """
    # Get the used token from the integration context:
    access_token: str = get_graph_access_token()

    # Decode the token and extract the roles:
    if access_token:
        decoded_token = jwt.decode(access_token, options={"verify_signature": False})

        if AUTH_TYPE == CLIENT_CREDENTIALS_FLOW:
            roles = decoded_token.get('roles', [])

        else:  # Authorization code flow
            roles = decoded_token.get('scp', '')
            roles = roles.split()

        if roles:
            hr = tableToMarkdown(f'The current API permissions in the Teams application are: ({len(roles)})',
                                 sorted(roles), headers=['Permission'])
        else:
            hr = 'No permissions obtained for the used graph access token.'

    else:
        hr = 'Graph access token is not set.'

    demisto.debug(f"'microsoft-teams-token-permissions-list' command result is: {hr}. Authorization type is: {AUTH_TYPE}.")

    result = CommandResults(
        readable_output=hr
    )

    return_results(result)


def create_messaging_endpoint_command():
    """
    Generates the messaging endpoint, based on the server url, the server version and the instance configurations.

    The messaging endpoint should be added to the Demisto bot configuration in Microsoft Teams as part of the Prerequisites of
    the integration's set-up.
    Link to documentation: https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams#1-using-cortex-xsoar-or-cortex-xsiam-rerouting
    """
    server_address = ''
    messaging_endpoint = ''

    # Get instance name and server url:
    urls = demisto.demistoUrls()
    instance_name = demisto.integrationInstance()
    xsoar_url = urls.get('server', '')
    engine_url = demisto.args().get('engine_url', '')

    if is_using_engine():  # In case of an XSOAR engine user - The user must provide the engine address.
        if not engine_url:
            raise ValueError("Your instance configuration involves a Cortex XSOAR engine.\nIn that case the messaging endpoint "
                             "that should be added to the Demisto bot configuration in Microsoft Teams is the engine's IP "
                             "(or DNS name) and the port in use, in the following format - `https://IP:port` or `http://IP:port`."
                             " For example - `https://my-engine.name:443`, `http://1.1.1.1:443`.\nTo test the format validity run"
                             " this command with your engine's URL set as the value of the `engine_url` argument.")

        elif engine_url and not re.search(XSOAR_ENGINE_URL_REGEX, engine_url):  # engine url is not valid
            raise ValueError("Invalid engine URL - Please ensure that the `engine_url` includes the IP (or DNS name)"
                             " and the port in use, and that it is in the correct format: `https://IP:port` or `http://IP:port`.")
        else:
            messaging_endpoint = engine_url

    elif engine_url:  # engine_url was unnecessarily set
        raise ValueError("Your instance configuration doesn't involve a Cortex XSOAR engine, but an `engine_url` was set.\n"
                         "If you wish to run on an engine - set this option in the instance configuration. Otherwise, delete "
                         "the value of the `engine_url` argument.")

    elif is_xsoar_on_prem():
        messaging_endpoint = urljoin(urljoin(xsoar_url, 'instance/execute'), instance_name)

    else:  # XSIAM or XSOAR SAAS
        if is_xsiam():
            # Replace the 'xdr' with 'crtx' in the hostname of XSIAM tenants
            # This substitution is related to this platform ticket: https://jira-dc.paloaltonetworks.com/browse/CIAC-12256.
            xsoar_url = xsoar_url.replace('xdr', 'crtx', 1)

        # Add the 'ext-' prefix to the xsoar url
        if xsoar_url.startswith('http://'):
            server_address = xsoar_url.replace('http://', 'http://ext-', 1)
        elif xsoar_url.startswith('https://'):
            server_address = xsoar_url.replace('https://', 'https://ext-', 1)

        messaging_endpoint = urljoin(urljoin(server_address, 'xsoar/instance/execute'), instance_name)

    hr = f"The messaging endpoint is:\n `{messaging_endpoint}`\n\n The messaging endpoint should be added to the Demisto bot"\
         f" configuration in Microsoft Teams as part of the prerequisites of the integration's setup.\n"\
         f"For more information see: [Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams#create-the-demisto-bot-in-microsoft-teams)."

    demisto.debug(
        f"The messaging endpoint that should be added to the Demisto bot configuration in Microsoft Teams is:"
        f" {messaging_endpoint}")

    result = CommandResults(
        readable_output=hr
    )

    return_results(result)


def validate_auth_code_flow_params(command: str = ''):
    """
    Validates that the necessary parameters for the Authorization Code flow have been received.
    Raises a DemistoException if a required parameter is missing.
    :param command: the command that should be executed
    """
    if not all([AUTH_CODE, REDIRECT_URI, AUTH_TYPE == AUTHORIZATION_CODE_FLOW]):
        err = f"In order to use the '{command}' command, "
        if not AUTH_CODE and not REDIRECT_URI and AUTH_TYPE != AUTHORIZATION_CODE_FLOW:
            raise DemistoException(err + "Please set the necessary parameters for the Authorization Code flow in the "
                                         "integration configuration.")
        elif AUTH_TYPE != AUTHORIZATION_CODE_FLOW:
            raise DemistoException(err + "you must set the 'Authentication Type' parameter to 'Authorization Code' in "
                                         "the integration configuration.")
        else:  # not all([AUTH_CODE, REDIRECT_URI]):
            raise DemistoException(err + "you must provide both 'Application redirect URI' and 'Authorization code' in "
                                         "the integration configuration for the Authorization Code flow.")


def test_connection():
    """
    Test connectivity in the Authorization Code flow mode.
    """
    get_graph_access_token()  # If fails, get_graph_access_token returns an error
    return_results(CommandResults(readable_output='✅ Success!'))


def test_module():
    """Tests API connectivity and authentication for Bot Framework API only.
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    :return: 'ok' if test passed.
    :rtype: ``str``
    """
    if not BOT_ID or not BOT_PASSWORD:
        raise DemistoException("Bot ID and Bot Password must be provided.")
    if 'Client' not in AUTH_TYPE:
        raise DemistoException(
            "Test module is available for Client Credentials only."
            " For other authentication types use the !microsoft-teams-auth-test command")

    get_bot_access_token()  # Tests token retrieval for Bot Framework API
    return_results('ok')


def generate_login_url_command():
    tenant_id = get_integration_context().get('tenant_id')
    if not tenant_id:
        raise Exception("Tenant ID is missing, please make sure that the messaging endpoint is configured correctly,"
                        " and the bot is added to a team.")
    login_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?' \
                f'response_type=code&scope=offline_access%20https://graph.microsoft.com/.default' \
                f'&client_id={BOT_ID}&redirect_uri={REDIRECT_URI}'

    result_msg = f"""### Authorization instructions
1. Click on the [login URL]({login_url}) to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
and paste it in your instance configuration under the **Authorization code** parameter.
    """
    return_results(CommandResults(readable_output=result_msg))


def fetch_samples():
    """
    The integration fetches incidents in the long-running-execution command. Fetch incidents is called
    only when "Pull From Instance" is clicked in create new classifier section in Cortex XSOAR.
    The fetch incidents returns samples of incidents generated by the long-running-execution.
    """
    demisto.incidents(get_integration_context().get('samples'))


def auth_type_switch_handling():
    """
    Handling cases where the user switches the auth type in the integration instance (from the client credentials flow to the
    auth code flow and vice versa), by auto-resetting the Graph API authorization in the integration context.
    """
    integration_context = get_integration_context()
    current_auth_type = integration_context.get('current_auth_type', '')
    if current_auth_type:
        demisto.debug(f'current_auth_type is: {current_auth_type}')
    else:
        # current_auth_type is not set - First run of the integration instance
        demisto.debug(f'This is the first run of the integration instance.\n'
                      f'Setting the current_auth_type in the integration context to {AUTH_TYPE}.')
        integration_context['current_auth_type'] = AUTH_TYPE
        set_integration_context(integration_context)
        current_auth_type = AUTH_TYPE

    if current_auth_type != AUTH_TYPE:
        # First run after the user switched the authentication type
        demisto.debug(f'The user switched the instance authentication type from {current_auth_type} to {AUTH_TYPE}.\n'
                      f'Resetting the integration context.')
        reset_graph_auth()
        integration_context = get_integration_context()
        demisto.debug(f'Setting the current_auth_type in the integration context to {AUTH_TYPE}.')
        integration_context['current_auth_type'] = AUTH_TYPE
        set_integration_context(integration_context)


def main():   # pragma: no cover
    """ COMMANDS MANAGER / SWITCH PANEL """
    demisto.debug("Main started...")
    commands: dict = {
        'test-module': test_module,
        'long-running-execution': long_running_loop,
        'send-notification': send_message,
        'mirror-investigation': mirror_investigation,
        'close-channel': close_channel,
        'microsoft-teams-integration-health': integration_health,
        'create-channel': create_channel_command,
        'add-user-to-channel': add_user_to_channel_command,
        'fetch-incidents': fetch_samples,
        # 'microsoft-teams-create-team': create_team,
        # 'microsoft-teams-send-file': send_file,
        'microsoft-teams-ring-user': ring_user,
        'microsoft-teams-create-channel': create_channel_command,
        'microsoft-teams-add-user-to-channel': add_user_to_channel_command,
        'microsoft-teams-create-meeting': create_meeting_command,
        'microsoft-teams-channel-user-list': channel_user_list_command,
        'microsoft-teams-user-remove-from-channel': user_remove_from_channel_command,
        'microsoft-teams-generate-login-url': generate_login_url_command,
        'microsoft-teams-auth-reset': reset_graph_auth_command,
        'microsoft-teams-token-permissions-list': token_permissions_list_command,
        'microsoft-teams-create-messaging-endpoint': create_messaging_endpoint_command
    }

    commands_auth_code: dict = {
        'microsoft-teams-auth-test': test_connection,
        'microsoft-teams-chat-create': chat_create_command,
        'microsoft-teams-message-send-to-chat': message_send_to_chat_command,
        'microsoft-teams-chat-add-user': chat_add_user_command,
        'microsoft-teams-chat-list': chat_list_command,
        'microsoft-teams-chat-member-list': chat_member_list_command,
        'microsoft-teams-chat-message-list': chat_message_list_command,
        'microsoft-teams-chat-update': chat_update_command,
    }

    ''' EXECUTION '''
    command: str = demisto.command()

    if command != 'test-module':  # skipping test-module since it doesn't have integration context
        auth_type_switch_handling()  # handles auth type switch cases

    try:
        support_multithreading()
        handle_proxy()
        LOG(f'Command being called is {command}')
        if command in commands:
            commands[command]()
        elif command in commands_auth_code:
            validate_auth_code_flow_params(command)  # raises error in case one of the required params is missing
            commands_auth_code[command]()
        else:
            raise NotImplementedError(f"command {command} is not implemented.")
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
