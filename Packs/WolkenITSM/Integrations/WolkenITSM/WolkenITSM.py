import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

'''IMPORTS'''
import traceback
from typing import Any
import urllib3


# from _collections import defaultdict


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth, clientId, domain, serviceAccount, refresh_token):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def add_internal_notes_request(self, incidentId, clientId, domain, serviceAccount, Authorization, formData):

        formData = assign_params(formData=formData)
        headers = self._headers
        headers.update({
            'Authorization': 'Bearer ' + Authorization
        })

        response = self._http_request('post', f'api/v1/incidents/{incidentId}/addInternalNotes', data=formData,
                                      headers=headers)
        return response

    def create_incident_requestv1_request(self, clientId, domain, serviceAccount, Authorization, formData, file):
        formData = assign_params(formData=formData)
        formData = str(formData)
        headers = self._headers
        headers.update({
            'Authorization': 'Bearer ' + Authorization
        })

        headers['accept'] = 'application/json'
        response = self._http_request('post', 'api/v1/incidents', data=formData, headers=headers)
        return response

    def get_access_token_request(self, Authorization, domain, grant_type, refresh_token):
        """
        Generate a refresh token using the given client credentials and save it in the integration context.
        """
        data = assign_params(grant_type=grant_type, refresh_token=refresh_token, domain=domain)
        headers = self._headers
        headers['accept'] = 'application/json'

        try:
            res = self._http_request('POST', 'oauth/token', data=data, headers=headers)
            time_now = date_to_timestamp(datetime.now())

            TokenParam = {
                'domain': domain,
                'grant_type': grant_type,
                'Authorization': Authorization,
                'refresh_token': res.get('refresh_token'),
                'access_token': res.get('access_token'),
                'expires_in': res.get('expires_in'),
                'scope': res.get('scope'),
                'token_type': res.get('token_type'),
                'time_now1': time_now
            }

            set_integration_context(TokenParam)

        except Exception as e:
            return_error(
                f'Login failed. Please check instance configuration and given domain,authorization,refresh_token.\n'
                f'{e.args[0]}')

    def get_incident_by_id_request(self, incidentId, clientId, domain, serviceAccount, Authorization):
        headers = self._headers
        headers.update({
            'Authorization': 'Bearer ' + Authorization
        })

        response = self._http_request('get', f'api/incidents/{incidentId}', headers=headers)

        return response

    def post_api_v1_incidents_add_attachments_request(self, incidentId, clientId, domain, serviceAccount, Authorization,
                                                      file):
        headers = self._headers
        headers.update({
            'Authorization': 'Bearer ' + Authorization
        })

        Data: dict[str, Any] = {}

        res = self._http_request('post', f'api/v1/incidents/{incidentId}/addAttachments', data=Data, file=file,
                                 headers=headers)
        return res

    def add_outbound_notes_request(self, incidentId, clientId, domain, serviceAccount, Authorization, formData):
        formData = assign_params(formData=formData)
        headers = self._headers

        headers.update({
            'Authorization': 'Bearer ' + Authorization
        })

        response = self._http_request('post', f'api/v1/incidents/{incidentId}/addOutboundNotes', data=formData,
                                      headers=headers)
        return response

    def incident_id_request(self, incidentId, clientId, domain, serviceAccount, Authorization, formData, file):
        formData = assign_params(formData=formData)
        headers = self._headers

        headers.update({
            'Authorization': 'Bearer ' + Authorization
        })

        headers['accept'] = 'application/json'

        response = self._http_request('post', f'api/v1/incidents/{incidentId}', data=formData, headers=headers)
        return response

    def post_api_v1_incidents_close_request(self, incidentId, clientId, domain, serviceAccount, Authorization,
                                            formData):
        formData = assign_params(formData=formData)
        headers = self._headers

        headers.update({
            'Authorization': 'Bearer ' + Authorization
        })

        headers['accept'] = 'application/json'

        response = self._http_request('post', f'api/v1/incidents/{incidentId}', data=formData, headers=headers)

        return response

    def put_api_v1_incidents_cancel_request(self, incidentId, clientId, domain, serviceAccount, Authorization,
                                            formData):
        Data = assign_params(formData=formData)

        headers = self._headers
        headers.update({
            'Authorization': 'Bearer ' + Authorization
        })

        res = self._http_request('put', f'api/v1/incidents/{incidentId}/cancel', data=Data, headers=headers)
        return res

    def SearchRequest(self, limit, offset, userPsNo, statusId, subStatusId, teamId, unitId, creatorId, requesterId,
                      itemId, priorityId, assignedUserId, createdTimeGTE, createdTimeLT, updatedTimeGTE, updatedTimeLT,
                      updatedByUserId, clientId, domain, serviceAccount, Authorization):
        params = assign_params(userPsNo=userPsNo, statusId=statusId, subStatusId=subStatusId, teamId=teamId,
                               unitId=unitId, creatorId=creatorId, requesterId=requesterId, itemId=itemId,
                               priorityId=priorityId,
                               assignedUserId=assignedUserId, createdTimeGTE=createdTimeGTE,
                               createdTimeLT=createdTimeLT, updatedTimeGTE=updatedTimeGTE, updatedTimeLT=updatedTimeLT,
                               updatedByUserId=updatedByUserId)
        headers = self._headers
        headers.update({
            'Authorization': 'Bearer ' + Authorization
        })

        response = self._http_request('get', f'api/incidents/{limit}/{offset}', params=params, headers=headers)

        return response

    def get_access_token(self):
        """
        Get an access token that was previously created if it is still valid, else, generate a new access token from
        the client id, client secret and refresh token.
        """
        # ok_codes = (200, 201, 401)
        previous_token = get_integration_context()

        time_now2 = date_to_timestamp(datetime.now())
        time_now1 = previous_token.get('time_now1')
        time_now3 = time_now2 - time_now1
        time_now3 = time_now3 // 1000

        if previous_token.get('access_token') and previous_token.get('expires_in') > time_now3:
            return previous_token.get('access_token')
        else:
            data = assign_params(grant_type=previous_token.get('grant_type'), refresh_token=previous_token.get(
                'refresh_token'), domain=previous_token.get('domain'))
            headers = {
                'accept': 'application/json',
                'Authorization': previous_token.get('Authorization')
            }
            if previous_token.get('refresh_token'):
                pass
            else:
                raise Exception('Could not create an access token. User might be not logged in. Try running the'
                                ' wolken-get-access-token command first.')
            try:
                res = self._http_request('POST', 'oauth/token', data=data, headers=headers)
                time_now = date_to_timestamp(datetime.now())

                TokenParam = {
                    'domain': previous_token.get('domain'),
                    'grant_type': previous_token.get('grant_type'),
                    'Authorization': previous_token.get('Authorization'),
                    'refresh_token': res.get('refresh_token'),
                    'access_token': res.get('access_token'),
                    'expires_in': res.get('expires_in'),
                    'scope': res.get('scope'),
                    'token_type': res.get('token_type'),
                    'time_now1': time_now
                }

                set_integration_context(TokenParam)
                return TokenParam.get('access_token')

            except Exception as e:
                return_error(f'Error occurred while creating an access token. Please check the instance configuration.'
                             f'\n\n{e.args[0]}')

    def get_parameters(self):
        params: dict[str, Any] = demisto.params()
        # previous_token2 = get_integration_context()
        # clientId = previous_token2.get('clientId')
        clientId = params.get('Client Id')
        domain = params.get('Domain')
        serviceAccount = params.get('Service Account')
        return clientId, domain, serviceAccount


'''Command Functions'''


def create_incident_requestv1_command(client: Client, args: dict[str, Any]) -> CommandResults:
    clientId, domain, serviceAccount = client.get_parameters()
    access_token = client.get_access_token()
    Authorization = access_token

    formData = {}
    if args.get('Subject'):
        formData['Subject'] = args.get('Subject')
    if args.get('Description'):
        formData['Description'] = args.get('Description')
    if args.get('SubCategoryName'):
        formData['SubCategoryName'] = args.get('SubCategoryName')
    if args.get('ItemName'):
        formData['ItemName'] = args.get('ItemName')
    if args.get('PriorityId'):
        formData['PriorityId'] = args.get('PriorityId')
    if args.get('RequestorEmail'):
        formData['RequestorEmail'] = args.get('RequestorEmail')
    if args.get('PreferredContactModeNumber'):
        formData['PreferredContactModeNumber'] = args.get('PreferredContactModeNumber')
    if args.get('ContactTypeId'):
        formData['ContactTypeId'] = args.get('ContactTypeId')
    if args.get('Category'):
        formData['Category'] = args.get('Category')
    if args.get('Sub_Category'):
        formData['Sub Category'] = args.get('Sub_Category')
    if args.get('TeamId'):
        formData['TeamId'] = args.get('TeamId')
    if args.get('Reminder'):
        formData['Reminder'] = args.get('Reminder')
    if args.get('Reminder_Notes'):
        formData['Reminder Notes'] = args.get('Reminder_Notes')
    if args.get('ImpactId'):
        formData['ImpactId'] = args.get('ImpactId')
    if args.get('UrgencyId'):
        formData['UrgencyId'] = args.get('UrgencyId')
    if args.get('Location'):
        formData['Location'] = args.get('Location')
    if args.get('Configuration_Item'):
        formData['Configuration Item'] = args.get('Configuration_Item')
    if args.get('SourceId'):
        formData['SourceId'] = args.get('SourceId')

    formData = str(formData)
    file = []
    filename = None
    filetype = None
    fileentryId = None
    if args.get('file_name'):
        filename = args.get('file_name')
        filename = str(filename)
    if args.get('file_type'):
        filetype = args.get('file_type')
        filetype = str(filetype)
    if args.get('file_entryId'):
        fileentryId = args.get('file_entryId')

    if filename is not None and filetype is not None and fileentryId is not None:
        file = [
            ('file', (filename, fileentryId, filetype))
        ]

    response = client.create_incident_requestv1_request(clientId, domain, serviceAccount, Authorization, formData, file)

    command_results = CommandResults(
        outputs_prefix='Wolken.CreateIncidents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def add_internal_notes_command(client: Client, args: dict[str, Any]) -> CommandResults:
    clientId, domain, serviceAccount = client.get_parameters()
    access_token = client.get_access_token()
    Authorization = access_token
    incidentId = args.get('incidentId')

    if incidentId is not None and incidentId.startswith('INC'):
        incidentId = incidentId[3:]

    formData = {}

    formData['Notes'] = args.get('Notes')

    formData = str(formData)
    response = client.add_internal_notes_request(incidentId, clientId, domain, serviceAccount, Authorization, formData)
    command_results = CommandResults(
        outputs_prefix='Wolken.UpdateIncidents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_access_token_command(client: Client, args: dict[str, Any]) -> CommandResults:
    params: dict[str, Any] = demisto.params()
    Authorization = params.get('credentials', {}).get('password')
    domain = params.get('Domain')
    grant_type = str(args.get('grant_type', 'refresh_token'))
    refresh_token = params.get('Refresh Token')

    try:
        client.get_access_token_request(Authorization, domain, grant_type, refresh_token)
        hr = '### Logged in successfully.\n A refresh token was saved to the integration context and will be ' \
             'used to generate a new access token once the current one expires.'
    except Exception as e:
        return_error(f'Failed to login. Please verify that the provided username and password are correct, and that you'
                     f' entered the correct client id and client secret in the instance configuration (see ? for'
                     f'correct usage when using OAuth).\n\n{e}')

    command_results = CommandResults(
        raw_response=hr
    )

    return command_results


def get_incident_by_id_command(client: Client, args: dict[str, Any]) -> CommandResults:
    clientId, domain, serviceAccount = client.get_parameters()
    access_token = client.get_access_token()
    Authorization = access_token

    incidentId = args.get('incidentId')

    if incidentId is not None and incidentId.startswith('INC'):
        incidentId = incidentId[3:]

    response = client.get_incident_by_id_request(incidentId, clientId, domain, serviceAccount, Authorization)
    command_results = CommandResults(
        outputs_prefix='Wolken.GetIncidents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def post_api_v1_incidents_add_attachments_command(client: Client, args: dict[str, Any]) -> CommandResults:
    clientId, domain, serviceAccount = client.get_parameters()
    access_token = client.get_access_token()
    Authorization = access_token

    incidentId = args.get('incidentId')

    if incidentId is not None and incidentId.startswith('INC'):
        incidentId = incidentId[3:]

    file = []
    filename = None
    filetype = None
    fileentryId = None
    if args.get('file_name'):
        filename = args.get('file_name')
        filename = str(filename)
    if args.get('file_type'):
        filetype = args.get('file_type')
        filetype = str(filetype)
    if args.get('file_entryId'):
        fileentryId = args.get('file_entryId')

    if filename is not None and filetype is not None and fileentryId is not None:
        file = [
            ('file', (filename, fileentryId, filetype))
        ]

    response = client.post_api_v1_incidents_add_attachments_request(
        incidentId, clientId, domain, serviceAccount, Authorization, file)
    command_results = CommandResults(
        outputs_prefix='Wolken.UpdateIncidents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def post_api_v1_incidents_add_outbound_notes_command(client: Client, args: dict[str, Any]) -> CommandResults:
    clientId, domain, serviceAccount = client.get_parameters()
    access_token = client.get_access_token()
    Authorization = access_token

    incidentId = args.get('incidentId')

    if incidentId is not None and incidentId.startswith('INC'):
        incidentId = incidentId[3:]

    formData = {}
    formData['Notes'] = args.get('Notes')
    formData = str(formData)

    response = client.add_outbound_notes_request(incidentId, clientId, domain, serviceAccount, Authorization, formData)
    command_results = CommandResults(
        outputs_prefix='Wolken.UpdateIncidents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )
    return command_results


def post_api_v1_incidents_by_incident_id_command(client: Client, args: dict[str, Any]) -> CommandResults:
    incidentId = str(args.get('incidentId', ''))
    if incidentId.startswith('INC'):
        incidentId = incidentId[3:]
    clientId, domain, serviceAccount = client.get_parameters()
    access_token = client.get_access_token()
    Authorization = access_token
    formData = {}
    if args.get('SourceId'):
        formData['SourceId'] = args.get('SourceId')
    if args.get('Subject'):
        formData['Subject'] = args.get('Subject')
    if args.get('Description'):
        formData['Description'] = args.get('Description')

    formData = str(formData)
    file = str(args.get('file', ''))
    response = client.incident_id_request(incidentId, clientId, domain, serviceAccount, Authorization, formData, file)
    command_results = CommandResults(
        outputs_prefix='Wolken.UpdateIncidents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )
    return command_results


def post_api_v1_incidents_close_command(client: Client, args: dict[str, Any]) -> CommandResults:
    incidentId = str(args.get('incidentId', ''))
    if incidentId.startswith('INC'):
        incidentId = incidentId[3:]
    clientId, domain, serviceAccount = client.get_parameters()
    access_token = client.get_access_token()
    Authorization = access_token
    formData = {}
    if args.get('Owner'):
        formData['AssignedUserPsNo'] = args.get('Owner')
    if args.get('Resolution_Code'):
        formData['Resolution Code'] = args.get('Resolution_Code')
    if args.get('Resolution_Notes'):
        formData['Resolution Notes'] = args.get('Resolution_Notes')
    if args.get('Closure_Description'):
        formData['Closure Description'] = args.get('Closure_Description')
    if args.get('StatusId'):
        formData['StatusId'] = args.get('StatusId')
    if args.get('SubStatusId'):
        formData['SubStatusId'] = args.get('SubStatusId')
    formData = str(formData)
    response = client.post_api_v1_incidents_close_request(incidentId, clientId, domain, serviceAccount, Authorization,
                                                          formData)
    command_results = CommandResults(
        outputs_prefix='Wolken.UpdateIncidents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )
    return command_results


def put_api_v1_incidents_cancel_command(client: Client, args: dict[str, Any]) -> CommandResults:
    incidentId = str(args.get('incidentId', ''))
    clientId, domain, serviceAccount = client.get_parameters()
    access_token = client.get_access_token()
    Authorization = access_token
    if incidentId.startswith('INC'):
        incidentId = incidentId[3:]
    formData = {}
    formData['Description'] = args.get('Description')
    formData = str(formData)
    response = client.put_api_v1_incidents_cancel_request(incidentId, clientId, domain, serviceAccount, Authorization,
                                                          formData)
    command_results = CommandResults(
        outputs_prefix='Wolken.UpdateIncidents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )
    return command_results


def search_incidents_by_params_command(client: Client, args: dict[str, Any]) -> CommandResults:
    limit = str(args.get('limit', ''))
    offset = str(args.get('offset', ''))
    userPsNo = str(args.get('userPsNo', ''))
    statusId = args.get('statusId', None)
    subStatusId = args.get('subStatusId', None)
    teamId = args.get('teamId', None)
    unitId = args.get('unitId', None)
    creatorId = args.get('creatorId', None)
    requesterId = args.get('requesterId', None)
    itemId = args.get('itemId', None)
    priorityId = args.get('priorityId', None)
    assignedUserId = args.get('assignedUserId', None)
    createdTimeGTE = args.get('createdTimeGTE', None)
    createdTimeLT = args.get('createdTimeLT', None)
    updatedTimeGTE = args.get('updatedTimeGTE', None)
    updatedTimeLT = args.get('updatedTimeLT', None)
    updatedByUserId = args.get('updatedByUserId', None)

    clientId, domain, serviceAccount = client.get_parameters()
    access_token = client.get_access_token()
    Authorization = access_token
    response = client.SearchRequest(limit, offset, userPsNo, statusId, subStatusId, teamId, unitId, creatorId,
                                    requesterId, itemId, priorityId,
                                    assignedUserId, createdTimeGTE, createdTimeLT, updatedTimeGTE, updatedTimeLT,
                                    updatedByUserId, clientId, domain, serviceAccount, Authorization)
    command_results = CommandResults(
        outputs_prefix='Wolken.GetIncidents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )
    return command_results


def test_module(client: Client) -> None:
    args: dict[str, Any] = demisto.args()
    get_access_token_command(client, args)
    # Test functions here
    return_results('ok')


def main() -> None:
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    url = params.get('url')
    clientId = params.get('Client Id')
    serviceAccount = params.get('Service Account')
    domain = params.get('Domain')
    refresh_token = params.get('Refresh Token')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {}
    headers['Authorization'] = params.get('credentials', {}).get('password')
    headers['clientId'] = clientId
    headers['serviceAccount'] = serviceAccount
    headers['domain'] = domain

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client: Client = Client(urljoin(url, '/wolken-secure/'), verify_certificate, proxy, headers=headers,
                                auth=None, clientId=clientId, domain=domain, serviceAccount=serviceAccount,
                                refresh_token=refresh_token)

        commands = {
            'wolken-add-internal-notes': add_internal_notes_command,

            'wolken-create-incident-requestv1': create_incident_requestv1_command,

            'wolken-get-access-token': get_access_token_command,

            'wolken-get-incident-by-id': get_incident_by_id_command,

            'wolken-post-api-v1-incidents-add-attachments': post_api_v1_incidents_add_attachments_command,

            'wolken-post-api-v1-incidents-add-outbound-notes': post_api_v1_incidents_add_outbound_notes_command,

            'wolken-post-api-v1-incidents-by-incident-id': post_api_v1_incidents_by_incident_id_command,

            'wolken-post-api-v1-incidents-close': post_api_v1_incidents_close_command,

            'wolken-put-api-v1-incidents-cancel': put_api_v1_incidents_cancel_command,

            'wolken-search-incidents-by-params': search_incidents_by_params_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
