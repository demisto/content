import enum

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
USER_EXPIRES_AT_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
CONTEXT_OUTPUT_PREFIX = "CipherTrust."
GROUP_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Group"
USERS_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Users"
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
    USERNAME = 'username'
    EMAIL = 'email'
    GROUPS = 'groups'
    EXCLUDE_GROUPS = 'exclude_groups'
    AUTH_DOMAIN_NAME = 'auth_domain_name'
    ACCOUNT_EXPIRED = 'account_expired'
    ALLOWED_AUTH_METHODS = 'allowed_auth_methods'
    ALLOWED_CLIENT_TYPES = 'allowed_client_types'
    PASSWORD_POLICY = 'password_policy'
    RETURN_GROUPS = 'return_groups'
    CERTIFICATE_SUBJECT_DN = 'certificate_subject_dn'
    EXPIRES_AT = 'expires_at'
    IS_DOMAIN_USER = 'is_domain_user'
    PREVENT_UI_LOGIN = 'prevent_ui_login'
    PASSWORD_CHANGE_REQUIRED = 'password_change_required'
    PASSWORD = 'password'
    FAILED_LOGINS_COUNT = 'failed_logins_count'


class AllowedAuthMethods(enum.Enum):
    PASSWORD = "password"
    USER_CERTIFICATE = "user_certificate"
    TWO_FACTOR = 'password_with_user_certificate'
    EMPTY = 'empty'


class AllowedClientTypes(enum.Enum):
    UNREGISTERED = "unregistered"
    PUBLIC = "public"
    CONFIDENTIAL = "confidential"


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
            },
        )

    def get_groups_list(self, params: dict):
        return self._http_request(
            method='GET',
            url_suffix=USER_MANAGEMENT_GROUPS_URL_SUFFIX,
            params=params,
        )

    def create_group(self, request_data: dict):
        return self._http_request(
            method='POST',
            url_suffix=USER_MANAGEMENT_GROUPS_URL_SUFFIX,
            json_data=request_data,
        )

    def delete_group(self, group_name: str, request_data: dict):
        return self._http_request(
            method='DELETE',
            url_suffix=urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, quote(group_name)),
            json_data=request_data,
            return_empty_response=True,
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
            return_empty_response=True,
        )

    def get_users_list(self, params: dict):
        return self._http_request(
            method='GET',
            url_suffix=USER_MANAGEMENT_USERS_URL_SUFFIX,
            params=params,
        )

    def get_user(self, user_id: str):
        return self._http_request(
            method='GET',
            url_suffix=urljoin(USER_MANAGEMENT_USERS_URL_SUFFIX, user_id),
        )

    def create_user(self, request_data: dict):
        return self._http_request(
            method='POST',
            url_suffix=USER_MANAGEMENT_USERS_URL_SUFFIX,
            json_data=request_data,
        )

    def update_user(self, user_id: str, request_data: dict):
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(USER_MANAGEMENT_USERS_URL_SUFFIX, user_id),
            json_data=request_data,
        )


''' HELPER FUNCTIONS '''


def derive_skip_and_limit_for_pagination(limit, page, page_size):
    if page:
        page_size = arg_to_number(page_size) or DEFAULT_PAGE_SIZE
        if page_size > MAX_PAGE_SIZE:
            raise ValueError(f'Page size cannot exceed {MAX_PAGE_SIZE}')
        return (arg_to_number(page) - 1) * page_size, page_size
    return 0, arg_to_number(limit)


def optional_arg_to_bool(arg):
    return argToBoolean(arg) if arg is not None else arg


''' COMMAND FUNCTIONS '''

PAGINATION_INPUTS = [InputArgument(name=CommandArguments.PAGE, description='page to return.'),
                     InputArgument(name=CommandArguments.PAGE_SIZE,
                                   description=f'number of entries per page. defaults to {MAX_PAGE_SIZE} in case only page was provided. max is {MAX_PAGE_SIZE}'),
                     InputArgument(name=CommandArguments.LIMIT,
                                   description='The max number of resources to return. defaults to 50', default=DEFAULT_LIMIT), ]


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
    client.get_groups_list(params={})
    return 'ok'


GROUPS_LIST_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, description='Group name to filter by.'),
                      InputArgument(name=CommandArguments.USER_ID,
                                    description='User id to filter by membership. “nil” will return groups with no members.'),
                      InputArgument(name=CommandArguments.CONNECTION, description='Connection id or name to filter by.'),
                      InputArgument(name=CommandArguments.CLIENT_ID,
                                    description='Client id to filter by membership. “nil” will return groups with no members.'),
                      ] + PAGINATION_INPUTS


@metadata_collector.command(command_name='ciphertrust-groups-list', outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
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
    raw_response = client.get_groups_list(params=params)
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        readable_output=tableToMarkdown('groups', raw_response.get('resources'))
    )


GROUP_CREATE_INPUTS = [InputArgument(name=CommandArguments.NAME, required=True, description='Name of the group.'),
                       InputArgument(name=CommandArguments.DESCRIPTION, description='description of the group.'), ]


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
    raw_response = client.create_group(request_data=request_data)
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


GROUP_DELETE_INPUTS = [InputArgument(name=CommandArguments.NAME, required=True, description='Name of the group'),
                       InputArgument(name=CommandArguments.FORCE,
                                     description='When set to true, groupmaps within this group will be deleted'), ]


@metadata_collector.command(command_name='ciphertrust-group-delete', inputs_list=GROUP_DELETE_INPUTS)
def group_delete_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(force=args.get(CommandArguments.FORCE))
    client.delete_group(group_name=args[CommandArguments.GROUP_NAME], request_data=request_data)
    return CommandResults(
        readable_output=f'{args.get(CommandArguments.GROUP_NAME)} has been deleted successfully!'
    )


GROUP_UPDATE_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, required=True, description='Name of the group.'),
                       InputArgument(name=CommandArguments.DESCRIPTION, description='description of the group.'), ]


@metadata_collector.command(command_name='ciphertrust-group-update', inputs_list=GROUP_UPDATE_INPUTS,
                            outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX)
def group_update_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(description=args.get(CommandArguments.DESCRIPTION))
    raw_response = client.update_group(group_name=args[CommandArguments.GROUP_NAME], request_data=request_data)
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


USER_TO_GROUP_ADD_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, required=True,
                                          description='Name of the group.By default it will be added to the Key Users Group.'),
                            InputArgument(name=CommandArguments.USER_ID, required=True,
                                          description='User id. Can be retrieved by using the command ciphertrust-users-list'), ]


@metadata_collector.command(command_name='ciphertrust-user-to-group-add', inputs_list=USER_TO_GROUP_ADD_INPUTS,
                            outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX)
def user_to_group_add_command(client: CipherTrustClient, args: dict):
    raw_response = client.add_user_to_group(group_name=args[CommandArguments.GROUP_NAME], user_id=args[CommandArguments.USER_ID])
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


USER_TO_GROUP_REMOVE_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, required=True,
                                             description='Name of the group.By default it will be added to the Key Users Group.'),
                               InputArgument(name=CommandArguments.USER_ID, required=True,
                                             description='User id. Can be retrieved by using the command ciphertrust-users-list'), ]


@metadata_collector.command(command_name='ciphertrust-user-to-group-remove', inputs_list=USER_TO_GROUP_REMOVE_INPUTS)
def user_to_group_remove_command(client: CipherTrustClient, args: dict):
    client.remove_user_from_group(group_name=args[CommandArguments.GROUP_NAME], user_id=args[CommandArguments.USER_ID])
    return CommandResults(
        readable_output=f'{args[CommandArguments.USER_ID]} has been deleted successfully from {args[CommandArguments.GROUP_NAME]}'
    )


USERS_LIST_INPUTS = [InputArgument(name=CommandArguments.NAME, description='User’s name'),
                     InputArgument(name=CommandArguments.USER_ID, description='If provided, get the user with the specified id'),
                     InputArgument(name=CommandArguments.USERNAME, description='username'),
                     InputArgument(name=CommandArguments.EMAIL, description='User’s email'),
                     InputArgument(name=CommandArguments.GROUPS, is_array=True,
                                   description='Filter by users in the given group name. Provide multiple groups  to get users '
                                               'in all of those groups. Using nil as the group name will return users that are '
                                               'not part of any group.'),
                     InputArgument(name=CommandArguments.EXCLUDE_GROUPS, is_array=True,
                                   description='User associated with certain group will be excluded'),
                     InputArgument(name=CommandArguments.AUTH_DOMAIN_NAME, description='Filter by user’s auth domain'),
                     InputArgument(name=CommandArguments.ACCOUNT_EXPIRED, description='Filter the expired users (Boolean)'),
                     InputArgument(name=CommandArguments.ALLOWED_AUTH_METHODS, is_array=True, input_type=AllowedAuthMethods,
                                   description='Filter by the login'
                                               'authentication '
                                               'method allowed to '
                                               'the users. It is a '
                                               'list of values. A '
                                               '[]'
                                               'can be'
                                               'specified to get '
                                               'users to whom no '
                                               'authentication '
                                               'method is allowed.'),
                     InputArgument(name=CommandArguments.ALLOWED_CLIENT_TYPES, is_array=True, input_type=AllowedClientTypes,
                                   description=""),
                     InputArgument(name=CommandArguments.PASSWORD_POLICY, description='Filter based on assigned password policy'),
                     InputArgument(name=CommandArguments.RETURN_GROUPS,
                                   description='If set to ‘true’ it will return the group’s name in which user is associated, Boolean'),
                     ] + PAGINATION_INPUTS


@metadata_collector.command(command_name='ciphertrust-users-list', inputs_list=USERS_LIST_INPUTS,
                            outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX)
def users_list_command(client: CipherTrustClient, args: dict):
    if user_id := args.get(CommandArguments.USER_ID):
        raw_response = client.get_user(user_id=user_id)
    else:
        skip, limit = derive_skip_and_limit_for_pagination(args.get(CommandArguments.LIMIT), args.get(CommandArguments.PAGE),
                                                           args.get(CommandArguments.PAGE_SIZE))
        params = assign_params(
            skip=skip,
            limit=limit,
            name=args.get(CommandArguments.NAME),
            username=args.get(CommandArguments.USERNAME),
            email=args.get(CommandArguments.EMAIL),
            groups=args.get(CommandArguments.GROUPS),
            exclude_groups=args.get(CommandArguments.EXCLUDE_GROUPS),
            auth_domain_name=args.get(CommandArguments.AUTH_DOMAIN_NAME),
            account_expired=optional_arg_to_bool(args.get(CommandArguments.ACCOUNT_EXPIRED)),
            allowed_auth_methods=args.get(CommandArguments.ALLOWED_AUTH_METHODS),
            allowed_client_types=args.get(CommandArguments.ALLOWED_CLIENT_TYPES),
            password_policy=args.get(CommandArguments.PASSWORD_POLICY),
            return_groups=optional_arg_to_bool(args.get(CommandArguments.RETURN_GROUPS)), )
        raw_response = client.get_users_list(params=params)
    return CommandResults(
        outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        readable_output=tableToMarkdown(name='users list', t=raw_response.get('resources')),
    )


USER_CREATE_INPUTS = [InputArgument(name=CommandArguments.NAME, description='User’s name'),
                      InputArgument(name=CommandArguments.USER_ID),
                      InputArgument(name=CommandArguments.USERNAME),
                      InputArgument(name=CommandArguments.PASSWORD),
                      InputArgument(name=CommandArguments.EMAIL, description='Users email'),
                      InputArgument(name=CommandArguments.ALLOWED_AUTH_METHODS, is_array=True, input_type=AllowedAuthMethods,
                                    description='Filter by the login'
                                                'authentication '
                                                'method allowed to '
                                                'the users. It is a '
                                                'list of values. A '
                                                '[]'
                                                'can be'
                                                'specified to get '
                                                'users to whom no '
                                                'authentication '
                                                'method is allowed.'),
                      InputArgument(name=CommandArguments.ALLOWED_CLIENT_TYPES, is_array=True, input_type=AllowedClientTypes,
                                    description=""),
                      InputArgument(name=CommandArguments.CERTIFICATE_SUBJECT_DN,
                                    description='The Distinguished Name of the user in certificate'),
                      InputArgument(name=CommandArguments.CONNECTION, default='local_account',
                                    description='Can be the name of a connection or "local_account" for a local user'),
                      InputArgument(name=CommandArguments.EXPIRES_AT,
                                    description="The expires_at field is applicable only for local user account. Only members "
                                                "of the 'admin' and 'User Admins' groups can add expiration to an existing "
                                                "local user account or modify the expiration date. Once the expires_at date is "
                                                "reached, the user account gets disabled and the user is not able to perform "
                                                "any actions. Setting the expires_at field to empty, removes the expiration "
                                                "date of the user account.The supported date-time format is "
                                                "2025-03-02T06:13:27.71402Z"),
                      InputArgument(name=CommandArguments.IS_DOMAIN_USER, description="This flag can be used to create the user "
                                                                                      "in a non-root domain where user "
                                                                                      "management is allowed."),
                      InputArgument(name=CommandArguments.PREVENT_UI_LOGIN, default='false',
                                    description='If true, user is not allowed to login from Web UI. '),
                      InputArgument(name=CommandArguments.PASSWORD_CHANGE_REQUIRED, description='Password change required '
                                                                                                'flag. If set to true, '
                                                                                                'user will be required to '
                                                                                                'change their password on '
                                                                                                'next successful login.'),
                      InputArgument(name=CommandArguments.PASSWORD_POLICY,
                                    description='The password policy applies only to local user accounts and overrides the '
                                                'global password policy. By default, the global password policy is applied to '
                                                'the users.')

                      ]

USER_CREATE_DESCRIPTION = ('Create a new user in a domain(including root), or add an existing domain user to a sub-domain. Users '
                           'are always created in the local, internal user database, but might have references to external '
                           'identity providers.')


@metadata_collector.command(command_name='ciphertrust-user-create', description=USER_CREATE_DESCRIPTION,
                            inputs_list=USER_CREATE_INPUTS, outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX)
def user_create_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(
        allowed_auth_methods=argToList(args.get(CommandArguments.ALLOWED_AUTH_METHODS)),
        allowed_client_types=argToList(args.get(CommandArguments.ALLOWED_CLIENT_TYPES)),
        certificate_subject_dn=args.get(CommandArguments.CERTIFICATE_SUBJECT_DN),
        connection=args.get(CommandArguments.CONNECTION),
        email=args.get(CommandArguments.EMAIL),
        expires_at=arg_to_datetime(args.get(CommandArguments.EXPIRES_AT)),
        is_domain_user=optional_arg_to_bool(args.get(CommandArguments.IS_DOMAIN_USER)),
        login_flags={"prevent_ui_login": optional_arg_to_bool(args.get(CommandArguments.PREVENT_UI_LOGIN))},
        name=args.get(CommandArguments.NAME),
        password=args.get(CommandArguments.PASSWORD),
        password_change_required=optional_arg_to_bool(args.get(CommandArguments.PASSWORD_CHANGE_REQUIRED)),
        password_policy=args.get(CommandArguments.PASSWORD_POLICY),
        user_id=args.get(CommandArguments.USER_ID),
        username=args.get(CommandArguments.USERNAME),
    )
    raw_response = client.create_user(request_data=request_data)
    return CommandResults(
        outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


USER_UPDATE_DESCRIPTION = 'Change the properties of a user. For instance the name, the password, or metadata. Permissions would normally restrict this route to users with admin privileges. Non admin users wishing to change their own passwords should use the change password route. The user will not be able to change their password to the same password.'
UPDATE_USER_INPUTS = [InputArgument(name=CommandArguments.NAME, description='User’s name'),
                      InputArgument(name=CommandArguments.USER_ID, required=True),
                      InputArgument(name=CommandArguments.USERNAME, description='username'),
                      InputArgument(name=CommandArguments.PASSWORD,
                                    description="The password used to secure the user's account."),
                      InputArgument(name=CommandArguments.EMAIL, description='Users email'),
                      InputArgument(name=CommandArguments.PASSWORD_CHANGE_REQUIRED,
                                    description='Password change required flag. If set to true, '
                                                'user will be required to '
                                                'change their password on '
                                                'next successful login.'),
                      InputArgument(name=CommandArguments.ALLOWED_AUTH_METHODS, is_array=True, input_type=AllowedAuthMethods,
                                    description='Filter by the login'
                                                'authentication '
                                                'method allowed to '
                                                'the users. It is a '
                                                'list of values. A '
                                                '[]'
                                                'can be'
                                                'specified to get '
                                                'users to whom no '
                                                'authentication '
                                                'method is allowed.'),
                      InputArgument(name=CommandArguments.ALLOWED_CLIENT_TYPES, is_array=True, input_type=AllowedClientTypes,
                                    description=""),
                      InputArgument(name=CommandArguments.CERTIFICATE_SUBJECT_DN,
                                    description='The Distinguished Name of the user in certificate'),
                      InputArgument(name=CommandArguments.EXPIRES_AT,
                                    description="The expires_at field is applicable only for local user account. Only members "
                                                "of the 'admin' and 'User Admins' groups can add expiration to an existing "
                                                "local user account or modify the expiration date. Once the expires_at date is "
                                                "reached, the user account gets disabled and the user is not able to perform "
                                                "any actions. Setting the expires_at field to empty, removes the expiration "
                                                "date of the user account.The supported date-time format is "
                                                "2025-03-02T06:13:27.71402Z"),
                      InputArgument(name=CommandArguments.FAILED_LOGINS_COUNT,
                                    description='Set it to 0 to unlock a locked user account.'),
                      InputArgument(name=CommandArguments.PREVENT_UI_LOGIN, default='false',
                                    description='If true, user is not allowed to login from Web UI.'),

                      InputArgument(name=CommandArguments.PASSWORD_POLICY,
                                    description='The password policy applies only to local user accounts and overrides the '
                                                'global password policy. By default, the global password policy is applied to '
                                                'the users.'),

                      ]


@metadata_collector.command(command_name='ciphertrust-user-update', description=USER_UPDATE_DESCRIPTION,
                            inputs_list=UPDATE_USER_INPUTS, outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX)
#
def user_update_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(
        allowed_auth_methods=argToList(args.get(CommandArguments.ALLOWED_AUTH_METHODS)),
        allowed_client_types=argToList(args.get(CommandArguments.ALLOWED_CLIENT_TYPES)),
        certificate_subject_dn=args.get(CommandArguments.CERTIFICATE_SUBJECT_DN),
        email=args.get(CommandArguments.EMAIL),
        expires_at=arg_to_datetime(args.get(CommandArguments.EXPIRES_AT)),
        failed_logins_count=arg_to_number(args.get(CommandArguments.FAILED_LOGINS_COUNT)),
        login_flags={"prevent_ui_login": optional_arg_to_bool(args.get(CommandArguments.PREVENT_UI_LOGIN))},
        name=args.get(CommandArguments.NAME),
        password=args.get(CommandArguments.PASSWORD),
        password_change_required=optional_arg_to_bool(args.get(CommandArguments.PASSWORD_CHANGE_REQUIRED)),
        password_policy=args.get(CommandArguments.PASSWORD_POLICY),
        username=args.get(CommandArguments.USERNAME),
    )
    raw_response = client.update_user(user_id=args[CommandArguments.USER_ID], request_data=request_data)
    return CommandResults(
        outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


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
