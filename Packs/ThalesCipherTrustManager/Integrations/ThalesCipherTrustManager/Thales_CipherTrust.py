import urllib3
from urllib.parse import quote
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

metadata_collector = YMLMetadataCollector(integration_name="CipherTrust",
                                          description="Manage Secrets and Protect Sensitive Data through HashiCorp Vault.",
                                          display="Thales CipherTrust Manager",
                                          category="Authentication & Identity Management",
                                          docker_image="demisto/python3:3.10.13.86272",
                                          is_fetch=True,
                                          long_running=False,
                                          long_running_port=False,
                                          is_runonce=False,
                                          integration_subtype="python3",
                                          integration_type="python",
                                          fromversion="6.0.0",
                                          conf=[ConfKey(name="server_url",
                                                        key_type=ParameterTypes.STRING,
                                                        required=True),
                                                ConfKey(name="credentials",
                                                        key_type=ParameterTypes.AUTH,
                                                        required=True)], )

''' IMPORTS '''

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
CONTEXT_OUTPUT_PREFIX = "CipherTrust."
GROUP_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Group"
BASE_URL_SUFFIX = '/api/v1'
AUTHENTICATION_URL_SUFFIX = '/auth/tokens'
USER_MANAGEMENT_GROUPS_URL_SUFFIX = '/usermgmt/groups/'
USER_MANAGEMENT_USERS_URL_SUFFIX = '/usermgmt/users/'
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 2000
DEFAULT_LIMIT = 50


class CommandArguments:
    PAGE = 'page'
    PAGE_SIZE = 'page_size'
    LIMIT = 'limit'
    GROUP_NAME = 'group_name'
    USER_ID = 'user_id'
    CONNECTION = 'connection'
    CLIENT_ID = 'client_id'
    NAME = 'name'
    DESCRIPTION = 'description'
    FORCE = 'force'


'''CLIENT CLASS'''


class CipherTrustClient(BaseClient):
    """ A client class to interact with the Thales CipherTrust API """

    def __init__(self, username: str, password: str, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        res = self._create_auth_token(username, password)
        self._headers = {'Authorization': f'Bearer {res.get("jwt")}', 'accept': 'application/json'}

    def _create_auth_token(self, username, password):  # todo: before each request to make sure isn't expired?
        return self._http_request(
            method='POST',
            url_suffix=AUTHENTICATION_URL_SUFFIX,
            json_data={
                'grant_type': 'password',
                'username': username,
                'password': password
            }
        )

    def get_groups_list(self, params: dict):
        return self._http_request(
            method='GET',
            url_suffix=USER_MANAGEMENT_GROUPS_URL_SUFFIX,
            params=params
        )

    def create_group(self, request_data: dict):
        return self._http_request(
            method='POST',
            url_suffix=USER_MANAGEMENT_GROUPS_URL_SUFFIX,
            json_data=request_data
        )

    def delete_group(self, group_name: str, request_data: dict):
        return self._http_request(
            method='DELETE',
            url_suffix=urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, quote(group_name)),
            json_data=request_data,
            return_empty_response=True
        )

    def update_group(self, group_name: str, request_data: dict):
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, quote(group_name)),
            json_data=request_data,
        )

    def add_user_to_group(self, group_name: str, user_id: str):
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, quote(group_name))}/users/{user_id}',
        )

    def remove_user_from_group(self, group_name: str, user_id: str):
        return self._http_request(
            method='DELETE',
            url_suffix=f'{urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, quote(group_name))}/users/{user_id}',
            return_empty_response=True
        )


''' HELPER FUNCTIONS '''


def derive_skip_and_limit_for_pagination(limit, page, page_size):
    if page:
        page_size = arg_to_number(page_size) or DEFAULT_PAGE_SIZE
        if page_size > MAX_PAGE_SIZE:
            raise ValueError(f'Page size cannot exceed {MAX_PAGE_SIZE}')
        return (arg_to_number(page) - 1) * page_size, page_size
    return 0, arg_to_number(limit)


''' COMMAND FUNCTIONS '''


@metadata_collector.command(command_name='test_module')
def test_module(client: CipherTrustClient):
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``CipherTrustClient``
    :param client: CipherTrust client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    client.get_groups_list({})
    return 'ok'


GROUPS_LIST_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, description='Group name to filter by.'),
                      InputArgument(name=CommandArguments.USER_ID,
                                    description='User id to filter by membership. “nil” will return groups with no members.'),
                      InputArgument(name=CommandArguments.CONNECTION, description='Connection id or name to filter by.'),
                      InputArgument(name=CommandArguments.CLIENT_ID,
                                    description='Client id to filter by membership. “nil” will return groups with no members.'),
                      InputArgument(name=CommandArguments.PAGE, description='page to return.'),
                      InputArgument(name=CommandArguments.PAGE_SIZE,
                                    description='number of entries per page. defaults to 50 in case only page was provided.'),
                      InputArgument(name=CommandArguments.LIMIT,
                                    description='The max number of resources to return. defaults to 50', default=DEFAULT_LIMIT)
                      ]


@metadata_collector.command(command_name='ciphertrust-group-list', outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
                            inputs_list=GROUPS_LIST_INPUTS)
def groups_list_command(client: CipherTrustClient, args: dict) -> CommandResults:
    """
    """
    skip, limit = derive_skip_and_limit_for_pagination(args.get(CommandArguments.LIMIT), args.get(CommandArguments.PAGE),
                                                       args.get(CommandArguments.PAGE_SIZE))
    params = assign_params(
        skip=skip,
        limit=limit,
        name=args.get(CommandArguments.GROUP_NAME),
        users=args.get(CommandArguments.USER_ID),
        connection=args.get(CommandArguments.CONNECTION),
        clients=args.get(CommandArguments.CLIENT_ID)
    )
    raw_response = client.get_groups_list(params)
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


GROUP_CREATE_INPUTS = [InputArgument(name=CommandArguments.NAME, required=True, description='Name of the group.'),
                       InputArgument(name=CommandArguments.DESCRIPTION, description='description of the group.')]


@metadata_collector.command(command_name='ciphertrust-group-create', inputs_list=GROUP_CREATE_INPUTS,
                            outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX)
def group_create_command(client: CipherTrustClient, args: dict):
    """

        client (CipherTrustClient): CipherTrust client to use.
        name (str): Name of the group. required=True
        description(str): description of the group.

    Context Outputs:
        {'name': 'maya test', 'created_at': '2024-05-15T14:16:03.088821Z', 'updated_at': '2024-05-15T14:16:03.088821Z', 'description': 'mayatest'}

    """
    request_data = assign_params(name=args.get(CommandArguments.NAME),
                                 description=args.get(CommandArguments.DESCRIPTION))
    raw_response = client.create_group(request_data)
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


GROUP_DELETE_INPUTS = [InputArgument(name=CommandArguments.NAME, required=True, description='Name of the group'),
                       InputArgument(name=CommandArguments.FORCE,
                                     description='When set to true, groupmaps within this group will be deleted')]


@metadata_collector.command(command_name='ciphertrust-group-delete', inputs_list=GROUP_DELETE_INPUTS)
def group_delete_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(force=args.get(CommandArguments.FORCE))
    client.delete_group(args[CommandArguments.GROUP_NAME], request_data)
    return CommandResults(
        readable_output=f'{args.get(CommandArguments.GROUP_NAME)} has been deleted successfully!'
    )


GROUP_UPDATE_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, required=True, description='Name of the group.'),
                       InputArgument(name=CommandArguments.DESCRIPTION, description='description of the group.')]


@metadata_collector.command(command_name='ciphertrust-group-update', inputs_list=GROUP_UPDATE_INPUTS,
                            outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX)
def group_update_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(description=args.get(CommandArguments.DESCRIPTION))
    raw_response = client.update_group(args[CommandArguments.GROUP_NAME], request_data)
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


USER_TO_GROUP_ADD_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, required=True,
                                          description='Name of the group.By default it will be added to the Key Users Group.'),
                            InputArgument(name=CommandArguments.USER_ID, required=True,
                                          description='User id. Can be retrieved by using the command ciphertrust-users-list')]


@metadata_collector.command(command_name='ciphertrust-user-to-group-add', inputs_list=USER_TO_GROUP_ADD_INPUTS,
                            outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX)
def user_to_group_add_command(client: CipherTrustClient, args: dict):
    raw_response = client.add_user_to_group(args[CommandArguments.GROUP_NAME], args[CommandArguments.USER_ID])
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


USER_TO_GROUP_REMOVE_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, required=True,
                                             description='Name of the group.By default it will be added to the Key Users Group.'),
                               InputArgument(name=CommandArguments.USER_ID, required=True,
                                             description='User id. Can be retrieved by using the command ciphertrust-users-list')]


@metadata_collector.command(command_name='ciphertrust-user-to-group-remove', inputs_list=USER_TO_GROUP_REMOVE_INPUTS)
def user_to_group_remove_command(client: CipherTrustClient, args: dict):
    client.remove_user_from_group(args[CommandArguments.GROUP_NAME], args[CommandArguments.USER_ID])
    return CommandResults(
        readable_output=f'{args[CommandArguments.USER_ID]} has been deleted successfully from {args[CommandArguments.GROUP_NAME]}'
    )

@metadata_collector.command(command_name='ciphertrust-users-list')
def users_list_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-user-create')
def user_create_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-user-update')
def user_update_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-user-delete')
def user_delete_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-user-password-change')
def user_password_change_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-local-ca-create')
def local_ca_create_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-local-ca-list')
def local_ca_list_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-local-ca-update')
def local_ca_update_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-local-ca-delete')
def local_ca_delete_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-local-ca-self-sign')
def local_ca_self_sign_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-local-ca-install')
def local_ca_install_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-certificate-issue')
def certificate_issue_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-certificate-list')
def certificate_list_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-local-certificate-delete')
def local_certificate_delete_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-certificate-revoke')
def certificate_revoke_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-certificate-resume')
def certificate_resume_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-external-certificate-upload')
def external_certificate_upload_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-external-certificate-delete')
def external_certificate_delete_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-external-certificate-update')
def external_certificate_update_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-external-certificate-list')
def external_certificate_list_command(client: CipherTrustClient, args: dict):
    pass


''' MAIN FUNCTION '''


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    server_url = params.get('server_url')
    base_url = urljoin(server_url, BASE_URL_SUFFIX)

    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')

    verify = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    commands = {
        'ciphertrust-groups-list': groups_list_command,
        'ciphertrust-group-create': group_create_command,
        'ciphertrust-group-delete': group_delete_command,
        'ciphertrust-group-update': group_update_command,
        'ciphertrust-user-to-group-add': user_to_group_add_command,
        'ciphertrust-user-to-group-remove': user_to_group_remove_command,
        'ciphertrust-users-list': users_list_command,
        'ciphertrust-user-create': user_create_command,
        'ciphertrust-user-update': user_update_command,
        'ciphertrust-user-delete': user_delete_command,
        'ciphertrust-user-password-change': user_password_change_command,
        'ciphertrust-local-ca-create': local_ca_create_command,
        'ciphertrust-local-ca-list': local_ca_list_command,
        'ciphertrust-local-ca-update': local_ca_update_command,
        'ciphertrust-local-ca-delete': local_ca_delete_command,
        'ciphertrust-local-ca-self-sign': local_ca_self_sign_command,
        'ciphertrust-local-ca-install': local_ca_install_command,
        'ciphertrust-certificate-issue': certificate_issue_command,
        'ciphertrust-certificate-list': certificate_list_command,
        'ciphertrust-local-certificate-delete': local_certificate_delete_command,
        'ciphertrust-certificate-revoke': certificate_revoke_command,
        'ciphertrust-certificate-resume': certificate_resume_command,
        'ciphertrust-external-certificate-upload': external_certificate_upload_command,
        'ciphertrust-external-certificate-delete': external_certificate_delete_command,
        'ciphertrust-external-certificate-update': external_certificate_update_command,
        'ciphertrust-external-certificate-list': external_certificate_list_command,
    }

    try:
        client = CipherTrustClient(
            username=username,
            password=password,
            base_url=base_url,
            verify=verify,
            proxy=proxy)

        demisto.debug(f'Command being called is {command}')

        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, args))

    except Exception as e:
        msg = f"Exception thrown calling command '{demisto.command()}' {e.__class__.__name__}: {e}"
        demisto.error(traceback.format_exc())
        return_error(message=msg, error=str(e))


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
