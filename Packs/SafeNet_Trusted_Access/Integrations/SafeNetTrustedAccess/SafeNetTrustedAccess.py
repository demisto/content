import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import re
import traceback
from datetime import datetime
from typing import Any
from urllib.parse import quote_plus
import urllib3
import copy

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''


NO_RESULT_MSG = 'No results found for the command.'

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    # Sends request to API Endpoint URL using _http_request() method.
    def http_request(self, method, url_suffix, data=None, headers=None, json_data=None, params=None, full_url=None,
                     resp_type='response'):

        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            data=data,
            headers=headers,
            resp_type=resp_type,
            json_data=json_data,
            params=params,
            full_url=full_url
        )

    # Validate limit value
    def validate_limit_sta(self, limit):

        limit = arg_to_number(arg=limit)
        if limit not in range(1, 10001):
            raise Exception("Limit must be between 1 to 10000.")
        return limit

    # Validate date value
    def validate_date_sta(self, datestring):

        pattern = re.compile("[0-9]{4}-[0-9]{2}-[0-9]{2}T([0-9]{2}:){2}[0-9]{2}.[0-9]{3}Z")
        if re.match(pattern, datestring):
            try:
                datetime.fromisoformat(datestring.replace('Z', '+00:00'))
                return datestring
            except DemistoException as e:
                raise Exception(f"Please enter a valid date. \nError:\n{str(e)}")
        raise Exception("Date must be in format yyyy-mm-ddTHH:mm:ss.fffZ \nExample: 2021-05-16T02:30:00.234Z")

    # Validate mandatory argument.
    def validate_mandatory_argument_sta(self, fields={}):

        for key, value in fields.items():
            if not value or value == "":
                raise Exception(f"Please provide the value for {key}.")

    # Get paginated results from API endpoint URL.
    def get_paged_results_sta(self, uri, query_params=None, limit=None):

        response = self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )
        request_count = 1
        quotient = 0
        if limit:
            items_count = len(response.json()['page']['items'])
            quotient = limit // items_count
            reminder = limit % items_count
        else:
            reminder = 0
            demisto.debug(f"{limit=} -> {reminder=}")
        paged_results = response.json()['page']['items']

        while "next" in response.json()['links'] and len(response.json()['page']['items']) > 0:
            if request_count >= 10:
                raise Exception("You have reached the maximum number of request attempts."
                                " Please use the limit argument to get the required result.")

            next_page = response.json()['links']["next"]
            if quotient == request_count:
                query_params = (
                    ('pageIndex', quotient),
                    ('pageSize', reminder),
                )
                response = self.http_request(
                    method="GET",
                    url_suffix=uri,
                    params=query_params
                )
                paged_results += response.json()['page']['items']
                break

            response = self.http_request(
                method="GET",
                full_url=next_page,
                url_suffix='',
                params=query_params
            )
            request_count = request_count + 1
            paged_results += response.json()['page']['items']

        return paged_results

    # Get list of all the users in the tenant.
    def get_userlist_sta(self, limit=None):

        uri = '/users'
        if limit:
            limit = self.validate_limit_sta(limit)
            if limit <= 100:
                query_params = (
                    ('pageIndex', 0),
                    ('pageSize', limit),
                )
                return self.http_request(
                    method='GET',
                    url_suffix=uri,
                    params=query_params,
                ).json()['page']['items']
            else:
                return self.get_paged_results_sta(uri=uri, limit=limit)
        else:
            return self.get_paged_results_sta(uri=uri)

    # Get profile information of a specific user.
    def get_user_info_sta(self, userName):

        self.validate_mandatory_argument_sta(fields={"username": userName})
        return self.http_request(
            method='GET',
            url_suffix=urljoin('/users/', quote_plus(userName)),
        ).json()

    # Get information of a group in a tenant.
    def get_group_info_sta(self, groupName):

        self.validate_mandatory_argument_sta(fields={"group": groupName})
        response = self.http_request(
            method='GET',
            url_suffix='/groups',
        )
        paged_results = response.json()['page']['items']
        while "next" in response.json()['links'] and len(response.json()['page']['items']) > 0:
            next_page = response.json()['links']["next"]
            response = self.http_request(
                method="GET",
                full_url=next_page,
                url_suffix='',
            )
            paged_results += response.json()['page']['items']
        for group in paged_results:
            if group['name'] == groupName:
                return group
        raise Exception(f'The group {groupName} was not found.')

    # Create a new user in the tenant.
    def create_user_sta(self, args):

        data = {
            "userName": args.get('userName'),
            "firstName": args.get('first_name'),
            "lastName": args.get('last_name'),
            "email": args.get('email'),
            "mobileNumber": args.get('mobile_number'),
            "alias1": args.get('alias1'),
            "alias2": args.get('alias2'),
            "custom1": args.get('custom1'),
            "custom2": args.get('custom2'),
            "custom3": args.get('custom3'),
            "address": args.get('address'),
            "city": args.get('city'),
            "state": args.get('state'),
            "country": args.get('country'),
            "postalCode": args.get('postal_code'),
            "isSynchronized": args.get('synchronized')
        }

        return self.http_request(
            method='POST',
            url_suffix='/users',
            data=json.dumps(data)
        ).json()

    # Update profile of a specific user.
    def update_user_sta(self, args):

        data = {}
        if args.get('userName_new') is not None:
            data['userName'] = args.get('userName_new')
        if args.get('first_name') is not None:
            data['firstName'] = args.get('first_name')
        if args.get('last_name') is not None:
            data['lastName'] = args.get('last_name')
        if args.get('email') is not None:
            data['email'] = args.get('email')
        if args.get('mobile_number') is not None:
            data['mobileNumber'] = args.get('mobile_number')
        if args.get('alias1') is not None:
            data['alias1'] = args.get('alias1')
        if args.get('alias2') is not None:
            data['alias2'] = args.get('alias2')
        if args.get('address') is not None:
            data['address'] = args.get('address')
        if args.get('city') is not None:
            data['city'] = args.get('city')
        if args.get('state') is not None:
            data['state'] = args.get('state')
        if args.get('country') is not None:
            data['country'] = args.get('country')
        if args.get('postal_code') is not None:
            data['postalCode'] = args.get('postal_code')

        return self.http_request(
            method='PATCH',
            url_suffix=urljoin('/users/', quote_plus(args.get('userName'))),
            data=json.dumps(data)
        ).json()

    # Get user ID from username.
    def get_user_id_sta(self, userName):

        return self.get_user_info_sta(userName=userName)['id']

    # Get group ID from groupname.
    def get_group_id_sta(self, groupName):

        return self.get_group_info_sta(groupName=groupName)['id']

    # Delete user from the tenant.
    def delete_user_sta(self, userName):

        user_id = self.get_user_id_sta(userName=userName)
        self.http_request(
            method='DELETE',
            url_suffix=urljoin('/users/', quote_plus(userName)),
        )
        return {"id": user_id, "userName": userName, "Deleted": True}

    # Get all the groups associated with a specific user.
    def get_user_groups_sta(self, userName, limit=None):

        user_id = self.get_user_id_sta(userName=userName)
        uri = urljoin(urljoin('/users/', quote_plus(user_id)), '/groups')

        if limit:
            limit = self.validate_limit_sta(limit)
            if limit <= 100:
                query_params = (
                    ('pageIndex', 0),
                    ('pageSize', limit),
                )
                return self.http_request(
                    method='GET',
                    url_suffix=uri,
                    params=query_params,
                ).json()['page']['items']

            else:
                return self.get_paged_results_sta(uri=uri, limit=limit)

        else:
            return self.get_paged_results_sta(uri=uri)

    # Returns output data for group members.
    def user_groups_data(self, userName, limit=None):

        response = self.get_user_groups_sta(userName=userName, limit=limit)
        data = self.get_user_info_sta(userName=userName)
        data['groups'] = response

        return response, data

    # Get list of groups in the tenant.
    def get_group_list_sta(self, limit=None):

        uri = '/groups'
        if limit:
            limit = self.validate_limit_sta(limit)
            if limit <= 100:
                query_params = (
                    ('pageIndex', 0),
                    ('pageSize', limit),
                )
                return self.http_request(
                    method='GET',
                    url_suffix=uri,
                    params=query_params,
                ).json()['page']['items']
            else:
                return self.get_paged_results_sta(uri=uri, limit=limit)
        else:
            return self.get_paged_results_sta(uri=uri)

    # Get list of all the users in a group.
    def get_group_members_sta(self, groupName, limit=None):

        group_id = self.get_group_id_sta(groupName=groupName)
        uri = urljoin(urljoin('/groups/', quote_plus(group_id)), '/members')

        if limit:
            limit = self.validate_limit_sta(limit)
            if limit <= 100:
                query_params = (
                    ('pageIndex', 0),
                    ('pageSize', limit),
                )
                return self.http_request(
                    method='GET',
                    url_suffix=uri,
                    params=query_params,
                ).json()['page']['items']
            else:
                return self.get_paged_results_sta(uri=uri, limit=limit)
        else:
            return self.get_paged_results_sta(uri=uri)

    # Returns output data for group members.
    def group_members_data(self, groupName, limit=None):

        response = self.get_group_members_sta(groupName=groupName, limit=limit)
        data = self.get_group_info_sta(groupName=groupName)
        data['users'] = response

        return response, data

    # Create a group in the tenant.
    def create_group_sta(self, args):

        data = {
            "name": args.get('groupName'),
            "description": args.get('description'),
            "isSynchronized": args.get('synchronized'),
        }

        return self.http_request(
            method='POST',
            url_suffix='/groups',
            data=json.dumps(data)
        ).json()

    # Delete a group from the tenant.
    def delete_group_sta(self, groupName):

        group_id = self.get_group_id_sta(groupName=groupName)
        self.http_request(
            method='DELETE',
            url_suffix=urljoin('/groups/', quote_plus(group_id)),
        )
        return {"id": group_id, "groupName": groupName, "Deleted": True}

    # Update information of a specific group.
    def update_group_sta(self, args):

        group_id = self.get_group_id_sta(groupName=args.get('groupName'))
        data = {}
        if args.get('groupName_new') is not None:
            data['name'] = args.get('groupName_new')
        if args.get('description') is not None:
            data['description'] = args.get('description')

        return self.http_request(
            method='PATCH',
            url_suffix=urljoin('/groups/', quote_plus(group_id)),
            data=json.dumps(data)
        ).json()

    # Check if a user exist in a group.
    def user_exist_group_sta(self, userName, groupName):

        user_id = self.get_user_id_sta(userName=userName)
        group_id = self.get_group_id_sta(groupName=groupName)

        user_groups = self.http_request(
            method='GET',
            url_suffix=urljoin(urljoin('/users/', quote_plus(user_id)), '/groups'),
        ).json()['page']['items']

        if user_groups is not None:
            for group in user_groups:
                if group['id'] == group_id:
                    return True

        return False

    # Add user in a group.
    def add_user_group_sta(self, userName, groupName):

        if self.user_exist_group_sta(userName=userName, groupName=groupName) is False:
            user_id = self.get_user_id_sta(userName=userName)
            group_id = self.get_group_id_sta(groupName=groupName)
            data = {
                "id": user_id,
                "type": "User",
            }
            self.http_request(
                method='POST',
                url_suffix=urljoin(urljoin('/groups/', quote_plus(group_id)), '/members'),
                data=json.dumps(data),
            )
            return {"user_id": user_id, "userName": userName, "group_id": group_id, "groupName": groupName,
                    "status": True}
        else:
            raise Exception(f"Username - {userName} is already a member of the group - {groupName}.")

    # Remove user from a group.
    def remove_user_group_sta(self, userName, groupName):

        if self.user_exist_group_sta(userName=userName, groupName=groupName) is True:
            user_id = self.get_user_id_sta(userName=userName)
            group_id = self.get_group_id_sta(groupName=groupName)

            self.http_request(
                method='DELETE',
                url_suffix=urljoin(urljoin(urljoin('/groups/', quote_plus(group_id)), '/members/'),
                                   quote_plus(user_id)),
            )
            return {"user_id": user_id, "userName": userName, "group_id": group_id, "groupName": groupName,
                    "status": False}
        else:
            raise Exception(f"Username - {userName} is not a member of the group - {groupName}.")

    # Creates a log's attribute dictionary from API's response data.
    def logs_attributes_sta(self, response):

        logs_attributes = {'timeStamp': response['timeStamp'], 'userName': response['context']['principalId'],
                           'logType': response['details']['type'], 'ip': response['context']['originatingAddress'],
                           "credentialType": "", "resultText": "", "actionText": "", "applicationName": "",
                           "policyName": "", "state": "", "operationType": "", "operationObjectType": "",
                           "operationObjectName": "", "message": "", "serial": ""}
        if 'credentialType' in response['details']:
            logs_attributes['credentialType'] = response['details']['credentialType']
        elif 'credentials' in response['details']:
            logs_attributes['credentialType'] = response['details']['credentials'][0]['type']
        if 'resultText' in response['details']:
            logs_attributes['resultText'] = response['details']['resultText']
        if 'actionText' in response['details']:
            logs_attributes['actionText'] = response['details']['actionText']
        if 'applicationName' in response['context']:
            logs_attributes['applicationName'] = response['context']['applicationName']
        if 'policyName' in response['context']:
            logs_attributes['policyName'] = response['context']['policyName']
        if 'state' in response['details']:
            logs_attributes['state'] = response['details']['state']
        if 'operationType' in response['details']:
            logs_attributes['operationType'] = response['details']['operationType']
        if 'operationObjectType' in response['details']:
            logs_attributes['operationObjectType'] = response['details']['operationObjectType']
        if 'operationObjectName' in response['details']:
            logs_attributes['operationObjectName'] = response['details']['operationObjectName']
        if 'message' in response['details']:
            logs_attributes['message'] = response['details']['message']
        elif 'description' in response['details']:
            logs_attributes['message'] = response['details']['description']
        if 'serial' in response['details']:
            logs_attributes['serial'] = response['details']['serial']

        return logs_attributes

    # Filter out the required data from total items as per limit and userName argument.
    def logs_data_filter_sta(self, total_items, userName=None, limit=None, count=1, logs_items=None):

        if logs_items is None:
            logs_items = []
        if userName:
            for response in total_items:
                if 'principalId' in response['context'] and response['context']['principalId'] == userName:
                    if limit:
                        if limit >= count:
                            count = count + 1
                        else:
                            break
                    logs_items.append(self.logs_attributes_sta(response=response))

        else:
            for response in total_items:
                if 'principalId' in response['context']:
                    if limit:
                        if limit >= count:
                            count = count + 1
                        else:
                            break
                    logs_items.append(self.logs_attributes_sta(response=response))

        return logs_items, count

    # Get user's logs.
    def get_logs_sta(self, userName=None, since=None, until=None, limit=None):

        uri = '/logs'
        query_params = {}
        if userName:
            self.get_user_info_sta(userName=userName)
        if since:
            query_params['since'] = self.validate_date_sta(datestring=since)
        if until:
            query_params['until'] = self.validate_date_sta(datestring=until)
        if since and until and until <= since:
            raise Exception("Until argument's date and time must be greater than since.")
        if not since and until:
            raise Exception("Use until argument only while using since.")

        query_params = tuple(query_params.items())
        response = self.http_request(
            method='GET',
            url_suffix=uri,
            params=query_params,
        )
        if since and not limit:
            limit = 10000

        if limit:
            limit = self.validate_limit_sta(limit)
            request_count = 1
            paged_results, count = self.logs_data_filter_sta(response.json()['page']['items'], userName=userName,
                                                             limit=limit)
            while "next" in response.json()['links'] and len(response.json()['page']['items']) > 0 and limit >= count:
                if request_count >= 10:
                    if userName:
                        break
                    raise Exception("You have reached the maximum number of request attempts."
                                    " Please use either the since or until argument to get the required result.")

                next_page = response.json()['links']["next"]
                response = self.http_request(
                    method="GET",
                    full_url=next_page,
                    url_suffix='',
                )

                request_count = request_count + 1
                paged_results, count = self.logs_data_filter_sta(response.json()['page']['items'], userName=userName,
                                                                 limit=limit, count=count, logs_items=paged_results)
        else:
            paged_results = self.logs_data_filter_sta(response.json()['page']['items'], userName)[0]

        return paged_results

    # Validate tenant and permission.
    def validate_tenant_sta(self):

        return self.http_request(
            method='GET',
            url_suffix='/authorized'
        )

    # Get list of all the applications in the tenant.
    def get_application_list_sta(self, limit=None):

        uri = '/applications'
        if limit:
            limit = self.validate_limit_sta(limit)
            if limit <= 100:
                query_params = (
                    ('pageIndex', 0),
                    ('pageSize', limit),
                )
                return self.http_request(
                    method='GET',
                    url_suffix=uri,
                    params=query_params,
                ).json()['page']['items']
            else:
                return self.get_paged_results_sta(uri=uri, limit=limit)
        else:
            return self.get_paged_results_sta(uri=uri)

    # Returns basic information of an application if exist in the tenant.
    def get_basic_application_info_sta(self, applicationName):

        self.validate_mandatory_argument_sta(fields={"applicationName": applicationName})
        response = self.http_request(
            method='GET',
            url_suffix='/applications',
        )
        paged_results = response.json()['page']['items']
        while "next" in response.json()['links'] and len(response.json()['page']['items']) > 0:
            next_page = response.json()['links']["next"]
            response = self.http_request(
                method="GET",
                full_url=next_page,
                url_suffix='',
            )
            paged_results += response.json()['page']['items']
        for application in paged_results:
            if application['name'] == applicationName:
                return application
        raise Exception(f'The application - {application} was not found.')

    # Get application id of an application.
    def get_application_id_sta(self, applicationName):

        return self.get_basic_application_info_sta(applicationName=applicationName)['id']

    # Get information for a specific application.
    def get_application_info_sta(self, applicationName):

        application_id = self.get_application_id_sta(applicationName=applicationName)
        response = self.http_request(
            method="GET",
            url_suffix=urljoin('/applications/', quote_plus(application_id))
        ).json()

        context_data = {
            'id': response['id'],
            'name': response['name'],
            'status': response['status'],
            'applicationType': response['applicationType'],
            'templateName': response['templateName'],
            'assignment': response['assignment'],
            'schemaVersionNumber': response['schemaVersionNumber'],
            'lastModified': response['lastModified']
        }
        readable_output = dict(context_data)
        if 'everyone' in readable_output['assignment']:
            if readable_output['assignment']['everyone'] is True:
                readable_output['assignment'] = 'All'
            else:
                readable_output['assignment'] = 'None'
        elif 'groups' in readable_output['assignment']:
            readable_output['assignment'] = ', '.join(readable_output['assignment']['groups'])

        return readable_output, context_data

    # Get the list of applications assigned to a user.
    def get_user_applications_sta(self, userName, limit=None):

        user_id = self.get_user_id_sta(userName=userName)
        uri = urljoin(urljoin('/users/', quote_plus(user_id)), '/applications')

        if limit:
            limit = self.validate_limit_sta(limit)
            if limit <= 1000:
                query_params = (
                    ('pageIndex', 0),
                    ('pageSize', limit),
                )
                return self.http_request(
                    method='GET',
                    url_suffix=uri,
                    params=query_params,
                ).json()['page']['items']

            else:
                return self.get_paged_results_sta(uri=uri, limit=limit)

        else:
            return self.get_paged_results_sta(uri=uri)

    # Returns output data for group members.
    def user_applications_data(self, userName, limit=None):

        response = self.get_user_applications_sta(userName=userName, limit=limit)
        data = self.get_user_info_sta(userName=userName)
        data['applications'] = response

        return response, data

    # Get the sessions for a specific user.
    def get_user_sessions_sta(self, userName):

        user_id = self.get_user_id_sta(userName=userName)
        uri = urljoin(urljoin('/users/', quote_plus(user_id)), '/sessions')

        return self.http_request(
            method='GET',
            url_suffix=uri,
        ).json()['sessions']

    # Returns output data for group members.
    def user_sessions_data(self, userName):

        data = self.get_user_info_sta(userName=userName)
        response = self.get_user_sessions_sta(userName=userName)
        data['sessions'] = copy.deepcopy(response)
        if response:
            numb = 0
            for session in response:
                session['start'] = datetime.fromtimestamp(session['start']).strftime('%Y-%m-%dT%H:%M:%S.000Z')
                session['expiry'] = datetime.fromtimestamp(session['expiry']).strftime('%Y-%m-%dT%H:%M:%S.000Z')
                applications = []
                for application in session['applications']:
                    applications.append(application['name'])

                if applications:
                    response[numb]['applications'] = ', '.join(applications)
                else:
                    response[numb]['applications'] = 'No applications.'
                numb = numb + 1

        return response, data

    # Delete all the IDP session for a specific user.
    def delete_sessions_sta(self, userName):

        user_id = self.get_user_id_sta(userName=userName)
        self.http_request(
            method='DELETE',
            url_suffix=urljoin(urljoin('/users/', quote_plus(user_id)), '/sessions'),
        )
        data = {
            "id": user_id,
            "userName": userName,
            "sessions": {
                "Deleted": True
            }
        }

        return data


''' COMMAND FUNCTIONS '''


def test_module(client, args):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: SafeNet Trusted Access

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    try:
        client._http_request(method='GET', url_suffix='/users')
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: Ensure that the API key is correct.'
        else:
            raise e
    return 'ok'


def get_userlist_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-get-user-list command. Get list of all the users in the tenant. """

    response = client.get_userlist_sta(limit=args.get('limit'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ["id", "schemaVersionNumber", "userName", "firstName", "lastName", "email", "mobileNumber",
                       "alias1", "alias2", "alias3", "alias4", "address", "city", "state", "country", "postalCode",
                       "isSynchronized"]
    return CommandResults(
        readable_output=tableToMarkdown("List of users in the tenant :", response, headers=header_sequence,
                                        headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='STA.USER',
        outputs_key_field=['id'],
        outputs=response
    )


def get_user_info_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-get-user-info command. Get profile information of a specific user."""

    response = client.get_user_info_sta(userName=args.get('userName'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ["id", "schemaVersionNumber", "userName", "firstName", "lastName", "email", "mobileNumber",
                       "alias1", "alias2", "alias3", "alias4", "custom1", "custom2", "custom3", "address", "city",
                       "state", "country", "postalCode", "isSynchronized"]

    return CommandResults(
        readable_output=tableToMarkdown(f"Information for user - {args.get('userName')} :",
                                        response, headers=header_sequence, headerTransform=pascalToSpace,
                                        removeNull=True),
        outputs_prefix='STA.USER',
        outputs_key_field=['id'],
        outputs=response
    )


def create_user_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-create-user command. Create a new user in the tenant. """

    response = client.create_user_sta(args=args)
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ["id", "schemaVersionNumber", "userName", "firstName", "lastName", "email", "mobileNumber",
                       "alias1", "alias2", "custom1", "custom2", "custom3", "address", "city", "state", "country",
                       "postalCode", "isSynchronized"]

    return CommandResults(
        readable_output=tableToMarkdown("STA user successfully created :", response, headers=header_sequence,
                                        headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='STA.USER',
        outputs_key_field=['id'],
        outputs=response
    )


def update_user_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-update-user-info command. Update profile of a specific user. """

    response = client.update_user_sta(args=args)
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ["id", "schemaVersionNumber", "userName", "firstName", "lastName", "email", "mobileNumber",
                       "alias1", "alias2", "custom1", "custom2", "custom3", "address", "city", "state", "country",
                       "postalCode", "isSynchronized"]

    return CommandResults(
        readable_output=tableToMarkdown("STA user successfully updated:", response,
                                        headers=header_sequence, headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='STA.USER',
        outputs_key_field=['id'],
        outputs=response
    )


def delete_user_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-delete-user command. Delete user from the tenant. """

    response = client.delete_user_sta(userName=args.get('userName'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    return CommandResults(
        readable_output=f"## STA user - {args.get('userName')} successfully deleted.",
        outputs_prefix='STA.USER',
        outputs_key_field=['id'],
        outputs=response
    )


def get_user_groups_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-get-user-groups command. Get all the groups associated with a specific user. """

    response, output_data = client.user_groups_data(userName=args.get('userName'), limit=args.get('limit'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ['id', 'schemaVersionNumber', 'name', 'description', 'isSynchronized']
    return CommandResults(
        readable_output=tableToMarkdown(
            f"Groups associated with user - {args.get('userName')} : ", response, headers=header_sequence,
            headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='STA.USER',
        outputs_key_field=['id'],
        outputs=output_data
    )


def get_group_list_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-get-group-list command. Get list of all the groups in the tenant. """

    response = client.get_group_list_sta(limit=args.get('limit'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ['id', 'schemaVersionNumber', 'name', 'description', 'isSynchronized']
    return CommandResults(
        readable_output=tableToMarkdown("STA groups in the tenant : ", response,
                                        headers=header_sequence, headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='STA.GROUP',
        outputs_key_field=['id'],
        outputs=response
    )


def get_group_info_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-get-group-info command. Get information of a specific group. """

    response = client.get_group_info_sta(groupName=args.get('groupName'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ['id', 'schemaVersionNumber', 'name', 'description', 'isSynchronized']
    return CommandResults(
        readable_output=tableToMarkdown(f"Group - {args.get('groupName')} :", response,
                                        headers=header_sequence, headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='STA.GROUP',
        outputs_key_field=['id'],
        outputs=response
    )


def get_group_members_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-get-group-members command. Get list of users in a specific group. """

    response, output_data = client.group_members_data(groupName=args.get('groupName'), limit=args.get('limit'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ['id', 'name', 'type']

    return CommandResults(
        readable_output=tableToMarkdown(f"Members of group - {args.get('groupName')} : ", response,
                                        headers=header_sequence, headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='STA.GROUP',
        outputs_key_field=['id'],
        outputs=output_data
    )


def create_group_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-create-group command. Create a new group in the tenant. """

    response = client.create_group_sta(args=args)
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ['id', 'schemaVersionNumber', 'name', 'description', 'isSynchronized']
    return CommandResults(
        readable_output=tableToMarkdown(
            f"STA group - {args.get('groupName')} successfully created:", response, headers=header_sequence,
            headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='STA.GROUP',
        outputs_key_field=['id'],
        outputs=response
    )


def delete_group_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-delete-group command. Delete group from the tenant. """

    response = client.delete_group_sta(groupName=args.get('groupName'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    return CommandResults(
        readable_output=f"## STA group - {args.get('groupName')} successfully deleted.",
        outputs_prefix='STA.GROUP',
        outputs_key_field=['id'],
        outputs=response
    )


def update_group_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-update-group-info command. Update information of a specific group. """

    response = client.update_group_sta(args=args)
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ['id', 'schemaVersionNumber', 'name', 'description', 'isSynchronized']
    return CommandResults(
        readable_output=tableToMarkdown("STA user successfully updated :", response, headers=header_sequence,
                                        headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='STA.GROUP',
        outputs_key_field=['id'],
        outputs=response
    )


def user_exist_group_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-user-exist-group command. Checks if a user is a member of a specific group."""

    response = client.user_exist_group_sta(userName=args.get('userName'), groupName=args.get('groupName'))
    if response is True:
        return CommandResults(
            readable_output=f"## Yes, user - {args.get('userName')} is a member of group - {args.get('groupName')}.",
            outputs_prefix='STA.EXIST.USER.GROUP',
            outputs=response
        )
    else:
        return CommandResults(
            readable_output=f"## No, user - {args.get('userName')} is not a member of group - {args.get('groupName')}.",
            outputs_prefix='STA.EXIST.USER.GROUP',
            outputs=response
        )


def add_user_group_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-add-user-group command. Add user to a specific group. """

    response = client.add_user_group_sta(userName=args.get('userName'), groupName=args.get('groupName'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )

    return CommandResults(
        readable_output=f"## User - {args.get('userName')} successfully added to the group - {args.get('groupName')}.",
        outputs_prefix='STA.UPDATE.USER.GROUP',
        outputs_key_field=['user_id', 'group_id'],
        outputs=response
    )


def remove_user_group_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-remove-user-group command. Remove user from a specific group. """

    response = client.remove_user_group_sta(userName=args.get('userName'), groupName=args.get('groupName'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )

    return CommandResults(
        readable_output=f"## User - {args.get('userName')} successfully removed from the group - {args.get('groupName')}.",
        outputs_prefix='STA.UPDATE.USER.GROUP',
        outputs_key_field=['user_id', 'group_id'],
        outputs=response
    )


def get_logs_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-get-logs command. Get user's logs. """

    response = client.get_logs_sta(userName=args.get('userName'), since=args.get('since'),
                                   until=args.get('until'), limit=args.get('limit'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ['timeStamp', 'userName', 'logType', 'credentialType', 'actionText', 'resultText', 'message',
                       'applicationName', 'policyName', 'state', 'operationType', 'operationObjectType',
                       'operationObjectName', 'serial', 'ip']

    return CommandResults(
        readable_output=tableToMarkdown("Logs : ", response, headers=header_sequence,
                                        headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='STA.LOGS',
        outputs=response
    )


def validate_tenant_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-validate-tenant command. Validate key and permissions. """

    client.validate_tenant_sta()
    return CommandResults(
        readable_output="## The requested tenant is accessible.",
        outputs_prefix='STA.VALIDATE.TENANT',
        outputs=True
    )


def get_application_list_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-get-application-list command. Get list of all the applications in the tenant. """

    response = client.get_application_list_sta(limit=args.get('limit'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ["id", "name", "status"]
    return CommandResults(
        readable_output=tableToMarkdown("List of applications in the tenant :", response, headers=header_sequence,
                                        headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='STA.APPLICATION',
        outputs_key_field=['id'],
        outputs=response
    )


def get_application_info_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-get-application-info command. Get profile information of a specific application."""

    readable_output, context_data = client.get_application_info_sta(applicationName=args.get('applicationName'))
    if not context_data:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ["id", "name", "status", "applicationType", "templateName", "assignment", "schemaVersionNumber",
                       "lastModified"]

    return CommandResults(
        readable_output=tableToMarkdown(f"Information of application - {args.get('applicationName')} :",
                                        readable_output, headers=header_sequence, headerTransform=pascalToSpace,
                                        removeNull=True),
        outputs_prefix='STA.APPLICATION',
        outputs_key_field=['id'],
        outputs=context_data
    )


def get_user_applications_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-get-user-applications. Get all the applications associated with a specific user. """

    response, output_data = client.user_applications_data(userName=args.get('userName'), limit=args.get('limit'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    header_sequence = ["id", "name", "status"]
    return CommandResults(
        readable_output=tableToMarkdown(
            f"Applications associated with user - {args.get('userName')} : ", response, headers=header_sequence,
            headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='STA.USER',
        outputs_key_field=['id'],
        outputs=output_data
    )


def get_user_sessions_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-get-user-sessions command. Get all the sessions associated with a specific user. """

    response, output_data = client.user_sessions_data(userName=args.get('userName'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    session_header = ["id", "start", "expiry", "applications"]
    session_data = tableToMarkdown(
        f"Sessions associated with user - {args.get('userName')} : ", response, headers=session_header,
        headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=session_data,
        outputs_prefix='STA.USER',
        outputs_key_field=['id'],
        outputs=output_data
    )


def delete_user_sessions_sta_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Function for sta-delete-user-sessions command. Delete all the IDP sessions associated with a specific user. """

    response = client.delete_sessions_sta(userName=args.get('userName'))
    if not response:
        return CommandResults(
            readable_output=NO_RESULT_MSG,
        )
    return CommandResults(
        readable_output=f"## IDP Sessions for the user - {args.get('userName')} successfully deleted.",
        outputs_prefix='STA.USER',
        outputs_key_field=['id'],
        outputs=response
    )


''' MAIN FUNCTION '''


def main() -> None:
    """
        main function, parses params and runs command functions
    """

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    base_url = urljoin(urljoin(demisto.params()['url'], 'api/v1/tenants/'), demisto.params()['tenant_code'])
    api_key = demisto.params().get('api_key')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'accept': 'application/json',
            'Object-Id-Format': 'base64',
            'Content-Type': 'application/json',
            'apikey': api_key
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            ok_codes=(200, 201, 204))

        commands = {
            'test-module': test_module,
            'sta-get-user-list': get_userlist_sta_command,
            'sta-get-user-info': get_user_info_sta_command,
            'sta-create-user': create_user_sta_command,
            'sta-update-user-info': update_user_sta_command,
            'sta-delete-user': delete_user_sta_command,
            'sta-get-user-groups': get_user_groups_sta_command,
            'sta-get-group-list': get_group_list_sta_command,
            'sta-get-group-info': get_group_info_sta_command,
            'sta-get-group-members': get_group_members_sta_command,
            'sta-create-group': create_group_sta_command,
            'sta-delete-group': delete_group_sta_command,
            'sta-update-group-info': update_group_sta_command,
            'sta-user-exist-group': user_exist_group_sta_command,
            'sta-add-user-group': add_user_group_sta_command,
            'sta-remove-user-group': remove_user_group_sta_command,
            'sta-get-logs': get_logs_sta_command,
            'sta-validate-tenant': validate_tenant_sta_command,
            'sta-get-application-list': get_application_list_sta_command,
            'sta-get-application-info': get_application_info_sta_command,
            'sta-get-user-applications': get_user_applications_sta_command,
            'sta-get-user-sessions': get_user_sessions_sta_command,
            'sta-delete-user-sessions': delete_user_sessions_sta_command
        }

        command = demisto.command()

        if command in commands:
            return_results(commands[command](client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
