"""
An integration to MS Graph Identity and Access endpoint.
https://docs.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0
"""

import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


class Client:
    def __init__(self, app_id: str, verify: bool, proxy: bool,
                 azure_ad_endpoint: str = 'https://login.microsoftonline.com'):
        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context['current_refresh_token'] = refresh_token
            set_integration_context(integration_context)

        self.ms_client = MicrosoftClient(
            self_deployed=True,
            auth_id=app_id,
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            grant_type=DEVICE_CODE,
            base_url='https://graph.microsoft.com',
            verify=verify,
            proxy=proxy,
            scope='offline_access RoleManagement.ReadWrite.Directory',
            azure_ad_endpoint=azure_ad_endpoint
        )

    def get_directory_roles(self, limit: int) -> list:
        """Get all service principals.

        Args:
            limit: Maximum of services to get.

        Returns:
            All given service principals

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-list?view=graph-rest-1.0&tabs=http
        """
        results = list()
        res = self.ms_client.http_request(
            'GET', 'v1.0/directoryRoles')
        results.extend(res.get('value'))
        while (next_link := res.get('@odata.nextLink')) and len(results) < limit:
            res = self.ms_client.http_request('GET', '', next_link)
            results.extend(res.get('value'))
        return results[:limit]

    def get_role_members(self, role_id: str, limit: int) -> dict:
        """Get all members of a specific role

        Args:
            role_id: a role id to get its members.
            limit: Maximum roles to get.

        Returns:
            directoryObject

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-list-members?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request(
            'GET', f'v1.0/directoryRoles/{role_id}/members')['value'][:limit]

    def get_ip_named_location(self, ip_id: str) -> dict:
        """Get an IP named location by id

        Args:
            ip_id: the id of the requested IP named location.

        Returns:
            a dictionary with the object from the api

        Docs:
            https://docs.microsoft.com/en-us/graph/api/ipnamedlocation-get?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request(
            'GET', f'v1.0/identity/conditionalAccess/namedLocations/{ip_id}')

    def update_ip_named_location(self, ip_id: str, data: dict) -> dict:
        """Update an IP named location by id

        Args:
            data: the request necessary to create the IP named location, json body.
            ip_id: the id of the IP named location to update.

        Returns:
            None

        Docs:
            https://docs.microsoft.com/en-us/graph/api/ipnamedlocation-update?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request(
            'PUT', f'v1.0/identity/conditionalAccess/namedLocations/{ip_id}', return_empty_response=True,
            json_data=data)

    def delete_ip_named_location(self, ip_id: str) -> dict:
        """Delete an IP named location by id

        Args:
            ip_id: the id of the requested IP named location.

        Returns:
            None

        Docs:
            https://docs.microsoft.com/en-us/graph/api/ipnamedlocation-delete?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request(
            'DELETE', f'v1.0/identity/conditionalAccess/namedLocations/{ip_id}', return_empty_response=True)

    def create_ip_named_location(self, data: dict) -> dict:
        """Create an IP named location

        Args:
            data: the request necessary to create the IP named location, json body.

        Returns:
            THe created IP named location

        Docs:
            https://docs.microsoft.com/en-us/graph/api/conditionalaccessroot-post-namedlocations?view=graph-rest-1.0&tabs=http # noqa
        """
        return self.ms_client.http_request(
            'POST', 'v1.0/identity/conditionalAccess/namedLocations', json_data=data)

    def compromise_users(self, data: dict) -> dict:
        """Compromise users in active directory

        Args:
            data: the request necessary to compromise the users, json body.

        Returns:


        Docs:
            https://docs.microsoft.com/en-us/graph/api/riskyuser-confirmcompromised?view=graph-rest-1.0&tabs=http # noqa
        """
        return self.ms_client.http_request(
            'POST', 'v1.0/identityProtection/riskyUsers/confirmCompromised', json_data=data, return_empty_response=True)

    def dismiss_users(self, data: dict) -> dict:
        """dismiss users in active directory

        Args:
            data: the request necessary to dismiss the users, json body.

        Returns:


        Docs:
            https://docs.microsoft.com/en-us/graph/api/riskyuser-dismiss?view=graph-rest-1.0&tabs=http # noqa
        """
        return self.ms_client.http_request(
            'POST', 'v1.0/identityProtection/riskyUsers/dismiss', json_data=data, return_empty_response=True)

    def list_ip_named_location(self, limit: str, page: str, odata: str) -> list:
        """Get a list of all IP named locations

        Args:
            limit: Maximum IP named locations to get.
            page: The page to take the data from.
            odata: An odata query to use in the api call.

        Returns:
            a list of dictionaries with the object from the api

        Docs:
            https://docs.microsoft.com/en-us/graph/api/conditionalaccessroot-list-namedlocations?view=graph-rest-1.0&tabs=http # noqa
        """
        odata_query = '?'
        if limit:
            odata_query += f'$top={limit}&'
        if page:
            odata_query += f'$skip={page}&'
        if odata:
            odata_query += odata
        return self.ms_client.http_request(
            'GET', f'v1.0/identity/conditionalAccess/namedLocations{odata_query}')['value']

    def list_risk_detections(self, limit: str, page: str, odata: str) -> list:
        """Get a list of all risk detections

        Args:
            limit: Maximum IP named locations to get.
            page: The page to take the data from.
            odata: An odata query to use in the api call.

        Returns:
            a list of dictionaries with the object from the api

        Docs:
            https://docs.microsoft.com/en-us/graph/api/riskdetection-list?view=graph-rest-1.0&tabs=http # noqa
        """
        odata_query = '?'
        if limit:
            odata_query += f'$top={limit}&'
        if page:
            odata_query += f'$skip={page}&'
        if odata:
            odata_query += odata
        return self.ms_client.http_request(
            'GET', f'v1.0/identityProtection/riskDetections{odata_query}')['value']

    def list_risky_users(self, limit: str, page: str, odata: str) -> list:
        """Get a list of all risky users

        Args:
            limit: Maximum IP named locations to get.
            page: The page to take the data from.
            odata: An odata query to use in the api call.

        Returns:
            a list of dictionaries with the object from the api

        Docs:
            https://docs.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0&tabs=http
        """
        odata_query = '?'
        if limit:
            odata_query += f'$top={limit}&'
        if page:
            odata_query += f'$skip={page}&'
        if odata:
            odata_query += odata
        return self.ms_client.http_request(
            'GET', f'v1.0/identityProtection/riskyUsers{odata_query}')['value']

    def list_risky_users_history(self, limit: str, page: str, odata: str, user_id) -> list:
        """Get a list of all risky user history

        Args:
            limit: Maximum IP named locations to get.
            page: The page to take the data from.
            odata: An odata query to use in the api call.
            user_id: The user id to get the history for.

        Returns:
            a list of dictionaries with the object from the api

        Docs:
            https://docs.microsoft.com/en-us/graph/api/riskyuser-list-history?view=graph-rest-1.0&tabs=http
        """
        odata_query = '?'
        if limit:
            odata_query += f'$top={limit}&'
        if page:
            odata_query += f'$skip={page}&'
        if odata:
            odata_query += odata
        return self.ms_client.http_request(
            'GET', f'v1.0/identityProtection/riskyUsers/{user_id}/history{odata_query}')['value']

    def activate_directory_role(self, template_id: str) -> dict:
        """Activating a role in the directory.
        Args:
            template_id: A template id to activate

        Returns:
            directoryRole object.

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-post-directoryroles?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request(
            'POST',
            'v1.0/directoryRoles',
            json_data={'roleTemplateId': template_id}
        )

    def add_member_to_role(self, role_object_id: str, user_id: str):
        """Adds a member to a specific role.

        Args:
            role_object_id: A role to add the user to.
            user_id: The user to add to the role.

        Return:
            True if succeeded.

        Raises:
            Error on failed add (as long with requests errors).

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-post-members?view=graph-rest-1.0&tabs=http
        """
        body = {
            '@odata.id': f'https://graph.microsoft.com/v1.0/directoryObjects/{user_id}'
        }
        self.ms_client.http_request(
            'POST',
            f'v1.0/directoryRoles/{role_object_id}/members/$ref',
            json_data=body,
            return_empty_response=True
        )

    def remove_member_from_role(self, role_object_id: str, user_id: str):
        """Removing a member from a specific role.

        Args:
            role_object_id: A role to remove the user from.
            user_id: The user to remove from the role.

        Return:
            True if succeeded.

        Raises:
            Error on failed removal (as long with requests errors).

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-delete-member?view=graph-rest-1.0&tabs=http
        """
        self.ms_client.http_request(
            'DELETE',
            f'v1.0/directoryRoles/{role_object_id}/members/{user_id}/$ref',
            return_empty_response=True
        )


''' COMMAND FUNCTIONS '''


def start_auth(client: Client) -> CommandResults:
    result = client.ms_client.start_auth('!msgraph-identity-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client: Client) -> str:
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def test_connection(client: Client) -> str:
    client.ms_client.get_access_token()
    return '✅ Success!'


def reset_auth() -> CommandResults:
    set_integration_context({})
    return CommandResults(
        readable_output='Authorization was reset successfully. Run **!msgraph-identity-auth-start** to '
                        'start the authentication process.'
    )


def list_directory_roles(ms_client: Client, args: dict) -> CommandResults:
    """Lists all service principals

    Args:
        ms_client: The Client
        args: demisto.args()

    Returns:
        Results to post in demisto
    """
    limit_str = args.get('limit', '')
    try:
        limit = int(limit_str)
    except ValueError:
        raise DemistoException(f'Limit must be an integer, not "{limit_str}"')
    results = ms_client.get_directory_roles(limit)
    return CommandResults(
        "MSGraphIdentity.Role",
        "id",
        outputs=results,
        readable_output=tableToMarkdown(
            'Directory roles:',
            results,
            ['id', 'displayName', 'description', 'roleTemplateId', 'deletedDateTime'],
            removeNull=True
        )
    )


def list_role_members_command(ms_client: Client, args: dict) -> CommandResults:
    """Lists all service principals

    Args:
        ms_client: The Client
        args: demisto.args()

    Returns:
        Results to post in demisto
    """
    limit_str = args.get('limit', '')
    try:
        limit = int(limit_str)
    except ValueError:
        raise DemistoException(f'Limit must be an integer, not "{limit_str}"')
    role_id = args['role_id']
    if results := ms_client.get_role_members(role_id, limit):
        ids = [member['id'] for member in results]
        context = {
            'role_id': role_id,
            'user_id': ids
        }
        return CommandResults(
            'MSGraphIdentity.RoleMember',
            'role_id',
            outputs=context,
            raw_response=results,
            readable_output=tableToMarkdown(
                f'Role \'{role_id}\' members:',
                context
            )
        )
    else:
        return CommandResults(readable_output=f"No members found in {role_id}")


def activate_directory_role_command(ms_client: Client, args: dict) -> CommandResults:
    template_id = args['role_template_id']
    results = ms_client.activate_directory_role(template_id)
    return CommandResults(
        "MSGraphIdentity.Role",
        "id",
        outputs=results,
        readable_output=tableToMarkdown(
            'Role has been activated',
            results,
            ['id', 'roleTemplateId', 'displayName', 'description', 'deletedDateTime']
        )
    )


def add_member_to_role_command(client: Client, args: dict) -> str:
    user_id = args['user_id']
    role_object_id = args['role_id']
    client.add_member_to_role(role_object_id, user_id)
    return f"User ID {user_id} has been added to role {role_object_id}"


def remove_member_from_role(client: Client, args: dict) -> str:
    role_object_id = args['role_id']
    user_id = args['user_id']
    client.remove_member_from_role(role_object_id, user_id)
    return f"User ID {user_id} has been removed from role {role_object_id}"


def ip_named_location_get(ms_client: Client, args: dict) -> CommandResults:
    ip_id = args.get('ip_id')
    if results := ms_client.get_ip_named_location(ip_id):  # type: ignore
        context = {
            'id': ip_id,
            'display_name': results.get('displayName'),
            'time_created': results.get('createdDateTime'),
            'time_modified': results.get('modifiedDateTime'),
            'is_trusted': results.get('isTrusted'),
            'ip_ranges': results.get('ipRanges')
        }
        return CommandResults(
            'MSGraph.conditionalAccess.namedIpLocations',
            'namedIpLocations',
            outputs=context,
            raw_response=results,
            ignore_auto_extract=True,
            readable_output=tableToMarkdown(
                f'IP named location \'{ip_id}\':',
                context
            )
        )
    return CommandResults(readable_output=f"No IP location found for {ip_id}")


def ip_named_location_update(ms_client: Client, args: dict) -> CommandResults:
    ip_id = args.get('ip_id')
    if results := ms_client.get_ip_named_location(ip_id):  # type: ignore
        data = {
            '@odata.type': '#microsoft.graph.ipNamedLocation',
            'displayName': results.get('displayName'),
            'isTrusted': results.get('isTrusted'),
            'ipRanges': results.get('ipRanges')
        }
        ips = args.get('ips')
        is_trusted = args.get('is_trusted')
        display_name = args.get('display_name')
        if ips:
            ips = ms_ip_string_to_list(ips)
            data['ipRanges'] = ips
        if is_trusted:
            data['isTrusted'] = is_trusted
        if display_name:
            data['displayName'] = display_name
        ms_client.update_ip_named_location(ip_id, data)  # type: ignore
        return CommandResults(
            'MSGraph.conditionalAccess.namedIpLocations',
            'namedIpLocations',
            outputs={},
            raw_response={},
            ignore_auto_extract=True,
            readable_output=f'Successfully  updated IP named location \'{ip_id}\''
        )
    return CommandResults(readable_output=f'Could not update IP named location \'{ip_id}\'')


def ip_named_location_create(ms_client: Client, args: dict) -> CommandResults:
    ips = args.get('ips')
    is_trusted = args.get('is_trusted')
    display_name = args.get('display_name')
    if ips and display_name and is_trusted:
        is_trusted = str(is_trusted).lower() == 'true'
        ips_arr = ms_ip_string_to_list(ips)
        data = {
            '@odata.type': '#microsoft.graph.ipNamedLocation',
            'displayName': display_name,
            'isTrusted': is_trusted,
            'ipRanges': ips_arr
        }
        if results := ms_client.create_ip_named_location(data):
            id = results.get('id')
            context = {
                'id': id,
                'display_name': results.get('displayName'),
                'time_created': results.get('createdDateTime'),
                'time_modified': results.get('modifiedDateTime'),
                'is_trusted': results.get('isTrusted'),
                'ip_ranges': results.get('ipRanges')
            }
            return CommandResults(
                'MSGraph.conditionalAccess.namedIpLocations',
                'namedIpLocations',
                outputs=context,
                raw_response=results,
                ignore_auto_extract=True,
                readable_output=tableToMarkdown(
                    f'created IP named location \'{id}\':',
                    context
                )
            )
    return CommandResults(readable_output="Could not create IP named location")


def azure_ad_identity_protection_confirm_compromised_command(ms_client: Client, args: dict) -> CommandResults:
    user_ids = str(args.get('user_ids')).split(',')
    print(f'ids: {user_ids}')
    data = {
        'userIds': user_ids
    }
    try:
        ms_client.compromise_users(data)
        return CommandResults(
            'MSGraph.identityProtection.compromiseUsers',
            'compromiseUsers',
            outputs={},
            raw_response={},
            ignore_auto_extract=True,
            readable_output=f'Successfully compromised {str(user_ids)}'
        )
    except Exception as e:
        return CommandResults(readable_output=f"Could not compromised {str(user_ids)}:\n{e}")

def azure_ad_identity_protection_risky_users_dismiss_command(ms_client: Client, args: dict) -> CommandResults:
    user_ids = str(args.get('user_ids')).split(',')
    print(f'ids: {user_ids}')
    data = {
        'userIds': user_ids
    }
    try:
        ms_client.dismiss_users(data)
        return CommandResults(
            'MSGraph.identityProtection.compromiseUsers',
            'compromiseUsers',
            outputs={},
            raw_response={},
            ignore_auto_extract=True,
            readable_output=f'Successfully dismissed {str(user_ids)}'
        )
    except Exception as e:
        return CommandResults(readable_output=f"Could not dismiss {str(user_ids)}:\n{e}")


def ip_named_location_delete(ms_client: Client, args: dict) -> CommandResults:
    ip_id = args.get('ip_id')
    if results := ms_client.delete_ip_named_location(ip_id):  # type: ignore
        return CommandResults(
            'MSGraph.conditionalAccess.namedIpLocations',
            'namedIpLocations',
            outputs={},
            raw_response={},
            ignore_auto_extract=True,
            readable_output=f'Successfully deleted IP named location \'{ip_id}\''
        )
    return CommandResults(readable_output=f'Could not delete IP named location \'{ip_id}\'')


def ip_named_location_list(ms_client: Client, args: dict) -> CommandResults:
    limit = args.get('limit')
    page = args.get('page')
    odata = args.get('odata_query')
    if results := ms_client.list_ip_named_location(limit, page, odata):
        ip_named_locations = []
        for result in results:
            ip_named_location = {
                'id': result['id'],
                'display_name': result['displayName'],
                'time_created': result['createdDateTime'],
                'time_modified': result['modifiedDateTime'],
                'is_trusted': result['isTrusted'],
                'ip_ranges': result['ipRanges']
            }
            ip_named_locations.append(ip_named_location)
        context = {
            'ip_named_locations': ip_named_locations
        }
        return CommandResults(
            'MSGraph.conditionalAccess.namedIpLocations',
            'namedIpLocations',
            outputs=context,
            raw_response=results,
            ignore_auto_extract=True,
            readable_output=tableToMarkdown(
                'IP named locations:',
                ip_named_locations,
            )
        )
    else:
        return CommandResults(readable_output="could not list IP named locations")


def azure_ad_identity_protection_risky_users_list(ms_client: Client, args: dict) -> CommandResults:
    limit = args.get('limit')
    page = args.get('page')
    odata = args.get('odata_query')
    if results := ms_client.list_risky_users(limit, page, odata):
        risky_users = []
        for result in results:
            risky_user = {
                'id': result['id'],
                'isDeleted': result['isDeleted'],
                'isProcessing': result['isProcessing'],
                'riskLevel': result['riskLevel'],
                'riskState': result['riskState'],
                'riskDetail': result['riskDetail'],
                'riskLastUpdatedDateTime': result['riskLastUpdatedDateTime'],
                'userDisplayName': result['userDisplayName'],
                'userPrincipalName': result['userPrincipalName'],
            }
            risky_users.append(risky_user)
        context = {
            'riskyUsers': risky_users
        }
        return CommandResults(
            'MSGraph.identityProtection.riskyUsers',
            'riskyUsers',
            outputs=context,
            raw_response=results,
            ignore_auto_extract=True,
            readable_output=tableToMarkdown(
                'Risky users:',
                risky_users,
            )
        )
    else:
        return CommandResults(readable_output="could not list IP named locations")


def azure_ad_identity_protection_risky_users_history_list(ms_client: Client, args: dict) -> CommandResults:
    limit = args.get('limit')
    page = args.get('page')
    odata = args.get('odata_query')
    user_id = args.get('user_id')
    if results := ms_client.list_risky_users_history(limit, page, odata, user_id):
        risky_users = []
        for result in results:
            risky_user = {
                'id': result['id'],
                'isDeleted': result['isDeleted'],
                'isProcessing': result['isProcessing'],
                'riskLevel': result['riskLevel'],
                'riskState': result['riskState'],
                'riskDetail': result['riskDetail'],
                'riskLastUpdatedDateTime': result['riskLastUpdatedDateTime'],
                'userDisplayName': result['userDisplayName'],
                'userPrincipalName': result['userPrincipalName'],
                'userId': result['userId'],
                'initiatedBy': result['initiatedBy'],
                'activity': result['activity'],
            }
            risky_users.append(risky_user)
        context = {
            'riskyUsers': risky_users
        }
        return CommandResults(
            'MSGraph.identityProtection.riskyUsers',
            'riskyUsers',
            outputs=context,
            raw_response=results,
            ignore_auto_extract=True,
            readable_output=tableToMarkdown(
                'Risky users history:',
                risky_users,
            )
        )
    else:
        return CommandResults(readable_output="could not list IP named locations")


def azure_ad_identity_protection_risk_detection_list(ms_client: Client, args: dict) -> CommandResults:
    limit = args.get('limit')
    page = args.get('page')
    odata = args.get('odata_query')
    if results := ms_client.list_risk_detections(limit, page, odata):
        risks = []
        for result in results:
            risk = {
                'id': result['id'],
                'requestId': result['requestId'],
                'correlationId': result['correlationId'],
                'riskEventType': result['riskEventType'],
                'riskState': result['riskState'],
                'riskLevel': result['riskLevel'],
                'riskDetail': result['riskDetail'],
                'source': result['source'],
                'detectionTimingType': result['detectionTimingType'],
                'activity': result['activity'],
                'ipAddress': result['ipAddress'],
                'activityDateTime': result['activityDateTime'],
                'detectedDateTime': result['detectedDateTime'],
                'lastUpdatedDateTime': result['lastUpdatedDateTime'],
                'userId': result['userId'],
                'userDisplayName': result['userDisplayName'],
                'userPrincipalName': result['userPrincipalName'],
                'additionalInfo': result['additionalInfo'],
                'location': result['location']
            }
            risks.append(risk)
        context = {
            'riskDetections': risks
        }
        return CommandResults(
            'MSGraph.identityProtection.risks',
            'riskDetections',
            outputs=context,
            raw_response=results,
            ignore_auto_extract=True,
            readable_output=tableToMarkdown(
                'Risks detected:',
                risks,
            )
        )
    else:
        return CommandResults(readable_output="could not list IP named locations")


def ms_ip_string_to_list(ips: str) -> list:
    ips_arr = []
    ips = ips.split(',')
    for ip in ips:
        temp = {'cidrAddress': ip}
        # ipv4 check
        if '.' in ip:
            temp['@odata.type'] = '#microsoft.graph.iPv4CidrRange'
        # ipv6 check
        elif ':' in ip:
            temp['@odata.type'] = '#microsoft.graph.iPv6CidrRange'
        else:
            continue
        ips_arr.append(temp)
    return ips_arr


def main():
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        command = demisto.command()
        params = demisto.params()
        args = demisto.args()
        handle_proxy()
        client = Client(
            app_id=params['app_id'],
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            azure_ad_endpoint=params.get('azure_ad_endpoint',
                                         'https://login.microsoftonline.com') or 'https://login.microsoftonline.com'
        )
        if command == 'test-module':
            return_results('The test module is not functional, run the msgraph-identity-auth-start command instead.')
        elif command == 'msgraph-identity-auth-start':
            return_results(start_auth(client))
        elif command == 'msgraph-identity-auth-complete':
            return_results(complete_auth(client))
        elif command == 'msgraph-identity-auth-test':
            return_results(test_connection(client))
        elif command == 'msgraph-identity-auth-reset':
            return_results(test_connection(client))
        elif command == 'msgraph-identity-directory-roles-list':
            return_results(list_directory_roles(client, args))
        elif command == 'msgraph-identity-directory-role-members-list':
            return_results(list_role_members_command(client, args))
        elif command == 'msgraph-identity-directory-role-activate':
            return_results(activate_directory_role_command(client, args))
        elif command == 'msgraph-identity-directory-role-member-add':
            return_results(add_member_to_role_command(client, args))
        elif command == 'msgraph-identity-directory-role-member-remove':
            return_results(remove_member_from_role(client, args))
        elif command == 'msgraph-identity-ip-named-locations-create':
            return_results(ip_named_location_create(client, args))
        elif command == 'msgraph-identity-ip-named-locations-get':
            return_results(ip_named_location_get(client, args))
        elif command == 'msgraph-identity-ip-named-locations-update':
            return_results(ip_named_location_update(client, args))
        elif command == 'msgraph-identity-ip-named-locations-delete':
            return_results(ip_named_location_delete(client, args))
        elif command == 'msgraph-identity-ip-named-locations-list':
            return_results(ip_named_location_list(client, args))
        elif command == 'msgraph-identity-protection-risks-list':
            return_results(azure_ad_identity_protection_risk_detection_list(client, args))
        elif command == 'msgraph-identity-protection-risky-user-list':
            return_results(azure_ad_identity_protection_risky_users_list(client, args))
        elif command == 'msgraph-identity-protection-risky-user-history-list':
            return_results(azure_ad_identity_protection_risky_users_history_list(client, args))
        elif command == 'msgraph-identity-protection-risky-user-confirm-compromised':
            return_results(azure_ad_identity_protection_confirm_compromised_command(client, args))
        elif command == 'msgraph-identity-protection-risky-user-dismiss':
            return_results(azure_ad_identity_protection_risky_users_dismiss_command(client, args))
        # elif command == 'fetch-incidents':
        #     incidents, last_run = fetch_incidents(client, params)
        #     demisto.incidents(incidents)
        #     demisto.setLastRun(last_run)
        else:
            raise NotImplementedError(f"Command '{command}' not found.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

from MicrosoftApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
