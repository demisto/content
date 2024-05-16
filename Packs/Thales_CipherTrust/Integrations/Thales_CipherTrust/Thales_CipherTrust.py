import urllib3
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

metadata_collector = YMLMetadataCollector(integration_name="CipherTrust",
                                          conf=[ConfKey(name="server_url",
                                                        key_type=ParameterTypes.STRING,
                                                        required=True),
                                                ConfKey(name="credentials",
                                                        key_type=ParameterTypes.AUTH,
                                                        required=True)])

''' IMPORTS '''

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
PA_OUTPUT_PREFIX = "CipherTrust."
BASE_URL_SUFFIX = '/api/v1'
AUTHENTICATION_URL_SUFFIX = '/auth/tokens'
USER_MANAGEMENT_GROUPS_URL_SUFFIX = '/usermgmt/groups/'
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 2000
DEFAULT_LIMIT = 50


class ArgAndParamNames:
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
        url_suffix = urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, group_name)
        self._http_request(
            method='DELETE',
            url_suffix=url_suffix,
            json_data=request_data
        )


''' HELPER FUNCTIONS '''


def calculate_skip_and_limit_for_pagination(limit, page, page_size):
    if page:
        page_size = arg_to_number(page_size) or DEFAULT_PAGE_SIZE
        if page_size > MAX_PAGE_SIZE:
            raise ValueError(f'Page size cannot exceed {MAX_PAGE_SIZE}')
        return (arg_to_number(page) - 1) * page_size, page_size
    return 0, arg_to_number(limit)


''' COMMAND FUNCTIONS '''


@metadata_collector.command(command_name='test_module')
def test_module(client: CipherTrustClient):
    """Tests connectivity with the client.
    Takes as an argument all client arguments to create a new client
    """
    client.get_groups_list({})
    return 'ok'


@metadata_collector.command(command_name='ciphertrust-group-list', outputs_prefix=f'{PA_OUTPUT_PREFIX}Group')
def groups_list_command(client: CipherTrustClient, args: dict) -> CommandResults:
    """


    Args:
        client (CipherTrustClient): CipherTrust client to use.
        group_name (str): Group name to filter by.
        user_id (str): User id to filter by membership. “nil” will return groups with no members.
        connection (str): Connection id or name to filter by.
        client_id (str): Client id to filter by membership. “nil” will return groups with no members.
        page(int): page to return. default=1
        page_size(int): number of entries per page. default=50
        limit(int): The max number of resources to return. default=50

    Returns:
       A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an groups list.
    Context Outputs:
        skip (int):
        limit (int):
        total (int):
        resources.created_at (datetime):

    "resources": [
        {
            "created_at": "2024-02-14T10:08:19.228482Z",
            "email": "admin@local",
            "last_login": "2024-05-15T13:50:42.891227Z",
            "logins_count": 98,
            "name": "admin",
            "nickname": "admin",
            "updated_at": "2024-05-15T13:50:42.891557Z",
            "user_id": "local|1e83aa21-0141-458a-8d77-e7d21192a82f",
            "username": "admin",
            "user_metadata": {
                "current_domain": {
                    "id": "00000000-0000-0000-0000-000000000000",
                    "name": "root"
                }
            },
            "failed_logins_count": 0,
            "account_lockout_at": null,
            "failed_logins_initial_attempt_at": null,
            "last_failed_login_at": null,
            "password_changed_at": "2024-02-14T11:36:13.102117Z",
            "password_change_required": false,
            "certificate_subject_dn": "",
            "enable_cert_auth": false,
            "auth_domain": "00000000-0000-0000-0000-000000000000",
            "login_flags": {
                "prevent_ui_login": false
            },
            "auth_domain_name": "root",
            "allowed_auth_methods": [
                "password"
            ],
            "allowed_client_types": [
                "unregistered",
                "public",
                "confidential"
            ]
        }
    ]
    """
    skip, limit = calculate_skip_and_limit_for_pagination(args.get(ArgAndParamNames.LIMIT), args.get(ArgAndParamNames.PAGE),
                                                          args.get(ArgAndParamNames.PAGE_SIZE))
    params = assign_params(
        skip=skip,
        limit=limit,
        name=args.get(ArgAndParamNames.GROUP_NAME),
        users=args.get(ArgAndParamNames.USER_ID),
        connection=args.get(ArgAndParamNames.CONNECTION),
        clients=args.get(ArgAndParamNames.CLIENT_ID)
    )
    raw_response = client.get_groups_list(params)
    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}Group',
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-group-create', outputs_prefix=f'{PA_OUTPUT_PREFIX}Group')
def group_create_command(client: CipherTrustClient, args: dict):
    """
    Args:
        client (CipherTrustClient): CipherTrust client to use.
        name (str): Name of the group. required=True
        description(str): description of the group.

    Context Outputs:
        {'name': 'maya test', 'created_at': '2024-05-15T14:16:03.088821Z', 'updated_at': '2024-05-15T14:16:03.088821Z', 'description': 'mayatest'}

    """
    # todo: how to handle required args
    request_data = assign_params(name=args.get(ArgAndParamNames.NAME),
                                 description=args.get(ArgAndParamNames.DESCRIPTION))
    raw_response = client.create_group(request_data)
    return CommandResults(
        outputs_prefix=f'{PA_OUTPUT_PREFIX}Group',
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-group-delete')
def group_delete_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(force=args.get(ArgAndParamNames.FORCE))
    client.delete_group(args.get(ArgAndParamNames.GROUP_NAME), request_data)
    return CommandResults(
        readable_output=f'{args.get(ArgAndParamNames.GROUP_NAME)} has been deleted successfully!'
    )


@metadata_collector.command(command_name='ciphertrust-group-update')
def group_update_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-user-to-group-add')
def user_to_group_add_command(client: CipherTrustClient, args: dict):
    pass


@metadata_collector.command(command_name='ciphertrust-user-to-group-remove')
def user_to_group_remove_command(client: CipherTrustClient, args: dict):
    pass


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
def certifcate_list_command(client: CipherTrustClient, args: dict):
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
        'ciphertrust-group-list': groups_list_command,
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
        'ciphertrust-certificate-list': certifcate_list_command,
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
