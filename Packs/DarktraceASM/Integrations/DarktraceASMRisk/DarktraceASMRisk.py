import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
'''Imports'''

import json
import traceback
from datetime import datetime
from typing import Any
import dateparser
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

'''CONSTANTS'''
URL = demisto.params().get('url')
ASM_URI = "/graph/v1.0/api"
ASM_RISK_QUERY = '''
                    id
                    type
                    startedAt
                    endedAt
                    title
                    description
                    evidence
                    proposedAction
                    securityRating
                    mitigatedAt
                    asset {
                        id
                        state
                        brand
                        createdAt
                        updatedAt
                        securityrating
                        isMalicious
                        tags
                        }
                    comments {
                        edges {
                            node {
                                id
                                text
                            }
                        }
                    }
                    '''
ASM_ASSET_QUERY = '''
                    id
                    state
                    brand
                    createdAt
                    updatedAt
                    securityrating
                    isMalicious
                    tags
                    comments {
                        id
                        text
                    }
                    discoverySources {
                        id
                        description
                    }
                    risks {
                        id
                        title
                    }
                '''
ASM_ASSET_QUERY_DICT = {
    'application': ASM_ASSET_QUERY + '''
            protocol
            uri
            fqdns {
                id
                name
            }
            ipaddresses {
                id
                address
            }
            screenshot
            technologies {
                id
                name
            }
            ''', 'fqdn': ASM_ASSET_QUERY + '''
            name
            dnsRecords
            resolvesTo {
                id
                address
            }
            whois
            registeredDomain {
                id
                name
            }
            ''', 'ipaddress': ASM_ASSET_QUERY + '''
            lat
            lon
            geoCity
            geoCountry
            address
            netblock {
                id
                netname
            }
            ''', 'netblock': ASM_ASSET_QUERY + '''
            netname
            ipAddresses {
                id
                address
            }
            '''
}

SEVERITY_MAP = {"Low": 1,
                "Medium": 2,
                "High": 3,
                "Critical": 4
                }

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'
MIN_SEVERITY_TO_FETCH = 1
MAX_INCIDENTS_TO_FETCH = 50
ALERT_TYPES = ['gdpr', 'informational', 'misconfiguration', 'reported', 'ssl', 'vulnerable software']
PLEASE_CONTACT = "Please contact your Darktrace representative."

DARKTRACE_API_ERRORS = {
    'SIGNATURE_ERROR': 'API Signature Error. You have invalid credentials in your config.',
    'DATE_ERROR': 'API Date Error. Check that the time on this machine matches that of the Darktrace instance.',
    'ENDPOINT_ERROR': f'Invalid Endpoint. - {PLEASE_CONTACT}',
    'PRIVILEGE_ERROR': 'User has insufficient permissions to access the API endpoint.',
    'UNDETERMINED_ERROR': f'Darktrace was unable to process your request - {PLEASE_CONTACT}',
    'FAILED_TO_PARSE': 'N/A'
}

"""*****CUSTOM EXCEPTIONS*****"""


class InvalidAssetStateError(Exception):
    def __init__(self, state: str):
        super().__init__(f'{state} is not a valid state.  Valid states include "Confirmed" and "Unconfirmed".')


class InvalidAssetID(Exception):
    def __init__(self, asset_id: Optional[str] = None):
        super().__init__(f"ASM Asset ID \"{asset_id}\" is not a valid ID.")


class AssetNotFound(Exception):
    def __init__(self, asset_type: str, id: Optional[str] = None, message: Optional[str] = None):
        super().__init__(f"ASM {asset_type} Asset with id \"{id}\" not found. {message}")


class MitigationError(Exception):
    def __init__(self, risk_id: str, message: Optional[str] = ""):
        super().__init__(f"Could not mitigate ASM Risk \"{risk_id}\" due to the following:\n{message}")


class TagError(Exception):
    def __init__(self, action: str, name: str, id: Optional[str] = "", message: Optional[str] = ""):
        if action == 'create':
            super().__init__(f"Could not create ASM Tag \"{name}\" due to the following:\n{message}")
        if action == 'assign':
            super().__init__(f"Could not assign ASM Tag \"{name}\" to ASM object \"{id}\" due to the following:\n{message}")
        if action == 'unassign':
            super().__init__(f"Could not unassign ASM Tag \"{name}\" from ASM object \"{id}\" due to the following:\n{message}")


class CommentError(Exception):
    def __init__(self, action: str, id: Optional[str] = "", message: Optional[str] = ""):
        if action == 'post':
            super().__init__(f"Could not post comment to ASM object \"{id}\" due to the following:\n{message}")
        elif action == 'edit':
            super().__init__(f"Could not edit comment \"{id}\" due to the following:\n{message}")
        elif action == 'delete':
            super().__init__(f"Could not delete comment \"{id}\" due to the following:\n{message}")


"""*****CLIENT CLASS*****
Wraps all the code that interacts with the Darktrace API."""


class Client(BaseClient):
    """Client class to interact with the Darktrace API
    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def asm_post(self, query_uri: str, json: Optional[dict] = None):
        headers = self._headers
        return self._asm_api_call(query_uri, method='POST', json=json, headers=headers)

    def _asm_api_call(
        self,
        query_uri: str,
        method: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        headers: Optional[dict[str, str]] = None,
    ):
        """Handles Darktrace API calls"""
        try:
            res = self._http_request(
                method,
                url_suffix=query_uri,
                params=params,
                data=data,
                json_data=json,
                resp_type='response',
                headers=headers,
                error_handler=self.error_handler,
            )

            if res.status_code not in [200, 204]:
                raise Exception('Your request failed with the following error: ' + str(res.content)
                                + '. Response Status code: ' + str(res.status_code))
        except Exception as e:
            raise Exception(e)
        try:
            return res.json()
        except Exception as e:
            raise ValueError(
                f'Failed to process the API response - {str(e)}'
            )

    def error_handler(self, res: requests.Response):
        """Handles authentication errors"""
        if res.status_code == 400:
            raise_message = 'Invalid field names in query:\n'
            for error in res.json()['errors']:
                error_message = error['message']
                error_location = f"Line {error['locations'][0]['line']}, column {error['locations'][0]['column']}."
                raise_message += f"{error_message} {error_location}\n"
            raise ValueError(raise_message)
        elif res.status_code == 401:
            raise PermissionError(f"Authentication issue: {res.json()['detail']}")
        elif res.status_code == 404:
            raise ValueError("Error 404. Page not found." + PLEASE_CONTACT)
        elif res.status_code == 500:
            raise ValueError("Error 500. Possibly malformed GraphQL query.")

    def get_asm_risk(self, risk_id: str):
        """Function to query for specific Risk using a Risk ID.
        :type risk_id: ``str``
        :param risk_id: Unique ID of Risk to query for.
        :return: dict containing Risk info.
        :rtype: ``Dict[str, Any]``
        """
        query = f'''query risk {{
                        risk(id:"{risk_id}") {{
                            id
                            type
                            startedAt
                            endedAt
                            title
                            description
                            evidence
                            proposedAction
                            securityRating
                            mitigatedAt
                            asset {{
                                id
                                state
                                brand
                                createdAt
                                updatedAt
                                securityrating
                                isMalicious
                                tags
                            }}
                            comments {{
                                edges {{
                                    node {{
                                        id
                                        text
                                    }}
                                }}
                            }}
                        }}
                    }}
                    '''
        payload = {"query": query}
        response = self.asm_post(ASM_URI, payload)
        return response["data"]["risk"]

    def mitigate_asm_risk(self, risk_id: str):
        """Function to manually mitigate a Risk given a specific Risk ID.
        :type risk_id: ``str``
        :param risk_id: Unique ID of Risk to mitigate.
        :return: dict containing status of mitigation.
        :rtype: ``Dict[str, Any]``
        """
        mutation = f'''mutation MyMutation {{
                    closeRisk(id:"{risk_id}") {{
                        success
                        }}
                    }}
                    '''
        payload = {"query": mutation}
        response = self.asm_post(ASM_URI, payload)
        if not response["data"]["closeRisk"]:
            errors = [error.get("message", '') for error in response.get("errors", {})]
            errors_string = '\n'.join(errors)
            raise MitigationError(risk_id, errors_string)
        return response["data"]["closeRisk"]

    def get_asm_asset(self, asset_id: str):
        """Function to query for a specific Asset using the Asset's ID.
        :type asset_id: ``str``
        :param asset_id: Unique ID of Asset to query for.
        :return: dict containing Asset info.
        :rtype: ``Dict[str, Any]``
        """
        if asset_id[0] == 'Q':
            asset_type = 'application'
        elif asset_id[0] == 'R':
            asset_type = 'fqdn'
        elif asset_id[0] == 'T':
            asset_type = 'netblock'
        elif asset_id[0] == 'S':
            asset_type = 'ipaddress'
        else:
            raise InvalidAssetID(asset_id)
        query_type = ASM_ASSET_QUERY_DICT[asset_type]
        query = f'''query {asset_type} {{ {asset_type}(id:"{asset_id}") {{
                {query_type}
                }}
            }}'''
        payload = {"query": query}
        response = self.asm_post(ASM_URI, payload)
        if not response["data"][asset_type]:
            message = response["errors"][0]["message"]
            raise AssetNotFound(asset_type, asset_id, message)
        asset = response["data"][asset_type]
        asset["type"] = asset_type
        return asset

    def post_asm_comment(self, id: str, comment: str):
        """Function to post a comment to a Risk or Asset given a specific ID and comment string.
        :type id: ``str``
        :param id: Unique ID of Risk or Asset to comment on.
        :type comment: ``str``
        :param comment: Text of comment.
        :return: dict containing status of comment.
        :rtype: ``Dict[str, Any]``
        """
        mutation = f'''mutation MyMutation {{
                    placeComment(text:"{comment}", objectId:"{id}") {{
                        success
                        comment {{
                            id
                            text
                            }}
                        }}
                    }}
                    '''
        payload = {"query": mutation}
        response = self.asm_post(ASM_URI, payload)
        if not response['data']['placeComment']:
            errors = [error.get("message", '') for error in response.get("errors", {})]
            errors_string = '\n'.join(errors)
            raise CommentError('post', id, errors_string)
        return response["data"]["placeComment"]

    def edit_asm_comment(self, comment_id: str, comment: str):
        """Function to edit an existing comment given the comment's ID and a new comment string.
        :type comment_id: ``str``
        :param comment_id: Unique ID of Comment to edit.
        :type comment: ``str``
        :param comment: New text to replace old Comment.
        :return: dict containing status of comment edit.
        :rtype: ``Dict[str, Any]``
        """
        mutation = f'''mutation MyMutation {{
                    editComment(text:"{comment}", id:"{comment_id}") {{
                        success
                        comment {{
                            id
                            text
                            }}
                        }}
                    }}
                    '''
        payload = {"query": mutation}
        response = self.asm_post(ASM_URI, payload)
        if not response['data']['editComment']:
            errors = [error.get("message", '') for error in response.get("errors", {})]
            errors_string = '\n'.join(errors)
            raise CommentError('edit', comment_id, errors_string)
        return response["data"]["editComment"]

    def delete_asm_comment(self, comment_id: str):
        """Function to delete an existing comment given the comment's ID.
        :type comment_id: ``str``
        :param comment_id: Unique ID of Comment to delete.
        :return: dict containing status of comment deletion.
        :rtype: ``Dict[str, Any]``
        """
        mutation = f'''mutation MyMutation {{
                    deleteComment(id:"{comment_id}") {{
                        success
                        }}
                    }}
                    '''
        payload = {"query": mutation}
        response = self.asm_post(ASM_URI, payload)
        if not response['data']['deleteComment']:
            errors = [error.get("message", '') for error in response.get("errors", {})]
            errors_string = '\n'.join(errors)
            raise CommentError('delete', comment_id, errors_string)
        return response["data"]["deleteComment"]

    def create_asm_tag(self, tag_name: str):
        """Function to create a new Tag.
        :type tag_name: ``str``
        :param tag_name: Label of new Tag.
        :return: dict including the status and info of the new Tag.
        :rtype: ``Dict[str, Any]``
        """
        mutation = f'''mutation MyMutation {{
                    createTag(name:"{tag_name}") {{
                        success
                        tag {{
                            id
                            name
                            }}
                        }}
                    }}
                    '''
        payload = {"query": mutation}
        response = self.asm_post(ASM_URI, payload)
        if not response['data']['createTag']:
            errors = [error.get("message", '') for error in response.get("errors", {})]
            errors_string = '\n'.join(errors)
            raise TagError('create', name=tag_name, message=errors_string)
        return response['data']['createTag']

    def assign_asm_tag(self, tag_name: str, asset_id: str):
        """Function to assign an existing tag to an Asset.
        :type tag_name: ``str``
        :param tag_name: Label of Tag to assign.
        :type asset_id: ``str``
        :param asset_id: Unique ID of Asset to apply Tag to.
        :return: dict including the status of assignment and info on Asset.
        :rtype: ``Dict[str, Any]``
        """
        mutation = f'''mutation MyMutation {{
                    assignTag(id:"{asset_id}", tagName:"{tag_name}") {{
                        success
                        asset {{
                            id
                            tags
                            }}
                        }}
                    }}
                    '''
        payload = {"query": mutation}
        response = self.asm_post(ASM_URI, payload)
        if not response['data']['assignTag']:
            errors = [error.get("message", '') for error in response.get("errors", {})]
            errors_string = '\n'.join(errors)
            raise TagError('assign', id=asset_id, name=tag_name, message=errors_string)
        return response['data']['assignTag']

    def unassign_asm_tag(self, tag_name: str, asset_id: str):
        """Function to unassign an existing tag from an Asset.
        :type tag_name: ``str``
        :param tag_name: Label of Tag to unassign.
        :type asset_id: ``str``
        :param asset_id: Unique ID of Asset to remove Tag from.
        :return: dict including the status of unassignment and info on Asset.
        :rtype: ``Dict[str, Any]``
        """
        mutation = f'''mutation MyMutation {{
                    unassignTag(id:"{asset_id}", tagName:"{tag_name}") {{
                        success
                        asset {{
                            id
                            tags
                            }}
                        }}
                    }}
                    '''
        payload = {"query": mutation}
        response = self.asm_post(ASM_URI, payload)
        if not response['data']['unassignTag']:
            errors = [error.get("message", '') for error in response.get("errors", {})]
            errors_string = '\n'.join(errors)
            raise TagError('unassign', id=asset_id, name=tag_name, message=errors_string)
        return response['data']['unassignTag']

    def get_asm_risks(self, start_time) -> List[Dict[str, Any]]:
        """Function to pull all Risks after a given start time.
        :type start_time: ``datetime``
        :param start_time: Date to start pulling Risks from.
        :return: list of Risk dicts.
        :rtype: ``List[Dict[str, Any]]``
        """
        start_string = start_time.strftime(DATE_FORMAT)
        query = f'''query allRisks {{
                        allRisks(startedAt:"{start_string}", orderBy:"startedAt") {{
                            edges {{
                                node {{
                                    {ASM_RISK_QUERY}
                                    }}
                                }}
                            }}
                        }}
                    '''
        payload = {"query": query}
        response = self.asm_post(ASM_URI, payload)
        return response["data"]["allRisks"]["edges"]


"""*****HELPER FUNCTIONS****"""


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> float:
    """Converts an XSOAR argument to a timestamp (seconds from epoch)
    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.
    :type arg: ``Any``
    :param arg: argument to convert
    :type arg_name: ``str``
    :param arg_name: argument name
    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None
    :return:
        returns a ``float`` containing a timestamp (seconds from epoch) if conversion works
        otherwise throws an Exception
    :rtype: ``float``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing \'{arg_name}\'')
        raise ValueError(f"'{arg_name}' cannot be None.")

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return float(date.timestamp())
    if isinstance(arg, int):
        # Convert to float if the input is an int
        return float(arg)
    raise ValueError(f'Invalid date: \'{arg_name}\'')


def check_required_fields(args, *fields):
    """Checks that required fields are found, raises a value error otherwise.
    :type args: ``Dict[str, Any]``
    :param args: dict of arguments to search for given fields within.
    :type fields: ``str``
    :param fields: Required fields to check for.
    :raise: ValueError if any fields not in args.
    """
    for field in fields:
        if field not in args:
            raise ValueError(f'Argument error could not find {field} in {args}')


def format_JSON_for_risk(risk: dict[str, Any]) -> dict[str, Any]:
    """Formats JSON for get_risk command, specifically reformat comments from API response.
    :type risk: ``Dict[str, Any]``
    :param risk: JSON risk as returned by API for fetch incident.
    :return: Reformatted JSON risk.
    :rtype: ``Dict[str, Any]``
    """
    new_json: Dict[str, Any] = {}
    for key in risk:
        if key == 'comments':
            if risk[key] is None:
                new_json[key] = {}
            else:
                comments = {comment['node']['id']: comment['node']['text'] for comment in risk[key]['edges']}
                new_json[key] = comments
        else:
            new_json[key] = risk[key]
    decoded_risk_id = decode_asm_id(risk['id'])
    decoded_asset_id = decode_asm_id(risk['asset']['id'])
    new_json['risk_url'] = f'{URL}/app/#/detail/direct-risks/{decoded_asset_id}?risk_id={decoded_risk_id}'
    new_json['asset']['asset_url'] = f'{URL}/app/#/detail/overview/{decoded_asset_id}'
    return new_json


def format_JSON_for_asset(asset: dict[str, Any]) -> dict[str, Any]:
    """Formats JSON for get_asm command, specifically lists of dicts.
    :type asset: ``Dict[str, Any]``
    :param asset: JSON asset as returned by API.
    :return: Reformatted JSON asset.
    :rtype: ``Dict[str, Any]``
    """
    new_json: Dict[str, Any] = {}
    for key in asset:
        if key == 'comments':
            if asset[key] is None:
                new_json[key] = {}
            else:
                comments = {comment['id']: comment['text'] for comment in asset[key]}
                new_json[key] = comments
        elif key == 'discoverySources':
            if asset[key] is None:
                new_json[key] = {}
            else:
                sources = {source["id"]: source["description"] for source in asset[key]}
                new_json[key] = sources
        elif key == 'risks':
            if asset[key] is None:
                new_json[key] = {}
            else:
                risks = {risk["id"]: risk["title"] for risk in asset[key]}
                new_json[key] = risks
        elif key in ['fqdns', 'technologies']:
            if asset[key] is None:
                new_json[key] = {}
            else:
                values = {value["id"]: value["name"] for value in asset[key]}
                new_json[key] = values
        elif key in ['ipaddresses', 'ipAddresses', 'resolvesTo']:
            if asset[key] is None:
                new_json[key] = {}
            else:
                addresses = {ip["id"]: ip["address"] for ip in asset[key]}
                new_json[key] = addresses
        else:
            new_json[key] = asset[key]
    decoded_asset_id = decode_asm_id(asset['id'])
    new_json['asset_url'] = f'{URL}/app/#/detail/overview/{decoded_asset_id}'
    return new_json


def _compute_xsoar_severity(security_rating: str) -> int:
    """Translates Darktrace ASM security rating into XSOAR Severity.
    :type security_rating: ``str``
    :param security_rating: ASM security rating to convert.
    :return: Integer equivalent of XSOAR severity scores.
    :rtype: ``int``
    """
    if security_rating in ['c', 'd']:
        return 2
    if security_rating in ['e']:
        return 3
    if security_rating in ['f']:
        return 4
    return 1


def decode_asm_id(id: str):
    """Given a base64 encoded ASM ID returns the decoded id.
    Works for both Risk and Asset IDs.
    :type id: ``str``
    :param id: Base64 encoded ASM ID.
    :return: Decoded ID of ASM object used in UI.
    :rtype: ``str``
    """
    decoded = str(base64.b64decode(id), encoding='utf-8').split(':')[1]
    return decoded


"""*****COMMAND FUNCTIONS****"""


def test_module(client: Client, first_fetch_time: float) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    :type client: ``Client``
    :param client:
        Darktrace Client.
    :type first_fetch_time: ``float``
    :param first_fetch_time:
        First fetch time.
    :return:
        A message to indicate the integration works as it is supposed to.
    :rtype: ``str``
    """
    try:
        first_fetch_datetime = datetime.fromtimestamp(first_fetch_time)
        client.get_asm_risks(start_time=first_fetch_datetime)

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def fetch_incidents(client: Client,
                    last_run: dict[str, str],
                    first_fetch_time: float,
                    max_alerts: int,
                    min_severity: int,
                    alert_types: list[str]) -> tuple[dict[str, Any], list[dict]]:
    """Function used to pull incidents into XSOAR every few minutes.  """
    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)
    first_fetch_datetime = datetime.fromtimestamp(first_fetch_time)
    # Handle first fetch time
    if last_fetch is None:
        last_fetch_datetime = first_fetch_datetime
    else:
        last_fetch_datetime = datetime.strptime(last_fetch, DATE_FORMAT)

    latest_created_time = last_fetch_datetime

    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    asm_risks: List[Dict[str, Any]] = client.get_asm_risks(start_time=last_fetch_datetime)

    for alert in asm_risks:
        # Convert startedAt time to datetime object and add to alert
        # grabbing first 26 characters from start time since that provides ms resolution
        incident_created_time = datetime.strptime(alert['node']['startedAt'][:26], DATE_FORMAT)

        # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if last_fetch_datetime and incident_created_time <= last_fetch_datetime:
            demisto.debug(
                f'''Incident created time: {incident_created_time} was part of a previous poll cycle.
                Last fetch time: {last_fetch_datetime}''')
            continue

        brand = alert.get('node', {}).get('asset', {}).get('brand')
        title = alert['node']['title']
        incident_name = f'Darktrace ASM | Risk Title: {title} | Brand: {brand}'

        xsoar_severity = _compute_xsoar_severity(alert['node']['securityRating'])

        # Skip incidents with a lower severity score than the desired minimum
        if xsoar_severity < min_severity:
            demisto.debug(f"Incident severity: {xsoar_severity} is lower than chosen minimum threshold: {min_severity}")
            continue

        incident_type = alert['node']['type'].lower()

        # Skip incidents with a type not included in the chosen alert types to ingest
        if incident_type not in alert_types:
            demisto.debug(f"Alert type {incident_type} is not part of chosen alerts: {alert_types}")
            continue

        incident = {
            'name': incident_name,
            'occurred': alert['node']['startedAt'],
            'rawJSON': json.dumps(alert['node']),
            'severity': xsoar_severity
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

        if len(incidents) >= max_alerts:
            break

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
    return next_run, incidents


def get_asm_risk_command(client: Client, args: dict[str, Any]) -> CommandResults:
    check_required_fields(args, 'risk_id')
    risk_id = str(args.get('risk_id', None))

    response = client.get_asm_risk(risk_id)

    formatted_response = format_JSON_for_risk(response)

    readable_output = tableToMarkdown('Darktrace ASM Risk', formatted_response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.risk',
        outputs_key_field='id',
        outputs=response
    )


def mitigate_asm_risk_command(client: Client, args: dict[str, Any]) -> str:
    check_required_fields(args, 'risk_id')
    risk_id = str(args.get('risk_id', None))

    client.mitigate_asm_risk(risk_id)

    readable_output = f'Successfully mitigated risk. Risk ID: {risk_id}'
    return readable_output


def get_asm_asset_command(client: Client, args: dict[str, Any]) -> CommandResults:
    check_required_fields(args, 'asset_id')
    asset_id = str(args.get('asset_id', None))

    response = client.get_asm_asset(asset_id)

    formatted_response = format_JSON_for_asset(response)

    readable_output = tableToMarkdown('Darktrace ASM Asset', formatted_response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.asset',
        outputs_key_field='id',
        outputs=response
    )


def post_asm_comment_command(client: Client, args: dict[str, Any]) -> str:
    check_required_fields(args, 'id', 'comment')
    id = str(args.get('id', None))
    comment = str(args.get('comment', None))

    response = client.post_asm_comment(id, comment)

    if response.get("success", False):
        comment_dict = response.get("comment", {})
        readable_output = 'Comment successful.\n'\
            f'Comment ID: {comment_dict.get("id", "Failed to get comment ID.")}\n'\
            f'Comment Text: {comment_dict.get("text", "Failed to get comment text.")}'
    else:
        errors = [error.get("message", '') for error in response.get("errors", {})]
        errors_string = '\n'.join(errors)
        readable_output = f'Comment failed due to following errors:\n{errors_string}'
    return readable_output


def edit_asm_comment_command(client: Client, args: dict[str, Any]) -> str:
    check_required_fields(args, 'comment_id', 'comment')
    comment_id = str(args.get('comment_id', None))
    comment = str(args.get('comment', None))

    response = client.edit_asm_comment(comment_id, comment)

    if response.get("success", False):
        comment_dict = response.get("comment", {})
        readable_output = 'Comment successfully edited.\n'\
            f'Comment ID: {comment_dict.get("id", "Failed to get comment ID.")}\n'\
            f'Comment Text: {comment_dict.get("text", "Failed to get comment text.")}'
    else:
        errors = [error.get("message", '') for error in response.get("errors", {})]
        errors_string = '\n'.join(errors)
        readable_output = f'Failed to edit comment due to following errors:\n{errors_string}'
    return readable_output


def delete_asm_comment_command(client: Client, args: dict[str, Any]) -> str:
    check_required_fields(args, 'comment_id')
    comment_id = str(args.get('comment_id', None))

    response = client.delete_asm_comment(comment_id)

    if response.get("success", False):
        readable_output = f'Comment successfully deleted. Comment ID: {comment_id}'
    else:
        errors = [error.get("message", '') for error in response.get("errors", {})]
        errors_string = '\n'.join(errors)
        readable_output = f'Comment deletion failed due to following errors:\n{errors_string}'
    return readable_output


def create_asm_tag_command(client: Client, args: dict[str, Any]) -> str:
    check_required_fields(args, 'tag_name')
    tag_name = str(args.get('tag_name', None))

    client.create_asm_tag(tag_name)

    # TODO: add error handling depending on XSOAR response on best practice

    readable_output = f'Successfully created tag {tag_name}.'
    return readable_output


def assign_asm_tag_command(client: Client, args: dict[str, Any]) -> str:
    check_required_fields(args, 'tag_name', 'asset_id')
    tag_name = str(args.get('tag_name', None))
    asset_id = str(args.get('asset_id', None))

    response = client.assign_asm_tag(tag_name, asset_id)

    asset = response.get("asset")
    tags = asset.get("tags")
    tags_string = "\n".join(tags)

    readable_output = f'Successfully assigned tag {tag_name} to asset {asset_id}.  Tags applied to asset:\n{tags_string}'
    return readable_output


def unassign_asm_tag_command(client: Client, args: dict[str, Any]) -> str:
    check_required_fields(args, 'tag_name', 'asset_id')
    tag_name = str(args.get('tag_name', None))
    asset_id = str(args.get('asset_id', None))

    response = client.unassign_asm_tag(tag_name, asset_id)

    asset = response.get("asset")
    tags = asset.get("tags")
    tags_string = "\n".join(tags)

    readable_output = f'Successfully unassigned tag {tag_name} from asset {asset_id}.  Tags applied to asset:\n{tags_string}'
    return readable_output


"""*****MAIN FUNCTIONS****
Takes care of reading the integration parameters via
the ``demisto.params()`` function, initializes the Client class and checks the
different options provided to ``demisto.commands()``, to invoke the correct
command function passing to it ``demisto.args()`` and returning the data to
``return_results()``. If implemented, ``main()`` also invokes the function
``fetch_incidents()``with the right parameters and passes the outputs to the
``demisto.incidents()`` function. ``main()`` also catches exceptions and
returns an error message via ``return_error()``.
"""


def main() -> None:     # pragma: no cover
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """

    # Collect Darktrace URL
    base_url = demisto.params().get('url')

    # API key
    api_token = (demisto.params().get('apikey', ''))
    headers = {"Authorization": f"Token {api_token}"}

    # Client class inherits from BaseClient, so SSL verification is
    # handled out of the box by it. Pass ``verify_certificate`` to
    # the Client constructor.
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_timestamp(
        arg=demisto.params().get('first_fetch', '1 day'),
        arg_name='First fetch time',
        required=True
    )

    # Client class inherits from BaseClient, so system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    # ``demisto.debug()``, ``demisto.info()``, prints information in the XSOAR server log.
    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, first_fetch_time))

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.

            # Convert the argument to an int using helper map or set to MIN_SEVERITY_TO_FETCH
            min_severity = SEVERITY_MAP.get(demisto.params().get('min_severity', None), None)
            if not min_severity or min_severity < MIN_SEVERITY_TO_FETCH:
                min_severity = MIN_SEVERITY_TO_FETCH

            # Get the list of alert types to ingest and make sure each item is all lower case or set to ALERT_TYPES
            alert_types = demisto.params().get('alert_type', None)
            if not alert_types:
                alert_types = ALERT_TYPES
            else:
                alert_types = [item.lower() for item in alert_types]

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_alerts = arg_to_number(
                arg=demisto.params().get('max_fetch', MAX_INCIDENTS_TO_FETCH),
                arg_name='max_fetch',
                required=False
            )
            if not max_alerts or max_alerts > MAX_INCIDENTS_TO_FETCH:
                max_alerts = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_alerts=max_alerts,
                min_severity=min_severity,
                alert_types=alert_types,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_time
            )

            # Use the variables defined above as the outputs of fetch_incidents to set up the next call and create incidents:
            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

        elif demisto.command() == 'darktrace-asm-get-risk':
            return_results(get_asm_risk_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-asm-mitigate-risk':
            return_results(mitigate_asm_risk_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-asm-post-comment':
            return_results(post_asm_comment_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-asm-edit-comment':
            return_results(edit_asm_comment_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-asm-delete-comment':
            return_results(delete_asm_comment_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-asm-get-asset':
            return_results(get_asm_asset_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-asm-create-tag':
            return_results(create_asm_tag_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-asm-assign-tag':
            return_results(assign_asm_tag_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-asm-unassign-tag':
            return_results(unassign_asm_tag_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


"""*****ENTRY POINT****"""
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
