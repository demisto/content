import enum

import urllib3
from urllib.parse import quote
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import datetime

from typing import Dict, Any

''''''' YML IGNORE START '''''''
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

''''''' YML IGNORE END '''''''

''' IMPORTS '''

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

CONTEXT_OUTPUT_PREFIX = "CipherTrust."
GROUP_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Group"
USERS_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Users"
LOCAL_CA_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}LocalCA"
CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CASelfSign"
CA_INSTALL_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CAInstall"
CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CACertificate"
EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}ExternalCertificate"

AUTHENTICATION_URL_SUFFIX = '/auth/tokens'
CHANGE_PASSWORD_URL_SUFFIX = '/auth/changepw'
USER_MANAGEMENT_GROUPS_URL_SUFFIX = '/usermgmt/groups/'
USER_MANAGEMENT_USERS_URL_SUFFIX = '/usermgmt/users/'
LOCAL_CAS_URL_SUFFIX = '/ca/local-cas/'
EXTERNAL_CAS_URL_SUFFIX = '/ca/external-cas/'

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 2000
DEFAULT_LIMIT = 50


#todo: hr to include total
class CommandArguments:
    PAGE = 'page'
    PAGE_SIZE = 'page_size'
    LIMIT = 'limit'
    GROUP_NAME = 'group_name'
    NEW_GROUP_NAME = 'new_group_name'
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
    NEW_PASSWORD = 'new_password'
    AUTH_DOMAIN = 'auth_domain'
    CN = 'cn'
    ALGORITHM = 'algorithm'
    COPY_FROM_CA = 'copy_from_ca'
    DNS_NAMES = 'dns_names'
    IP = 'ip'
    NAME_FIELDS_RAW_JSON = 'name_fields_raw_json'
    NAME_FIELDS_JSON_ENTRY_ID = 'name_fields_json_entry_id'
    SIZE = 'size'
    SUBJECT = 'subject'
    LOCAL_CA_ID = 'local_ca_id'
    CHAINED = 'chained'
    ISSUER = 'issuer'
    STATE = 'state'
    CERT = 'cert'
    CERT_ENTRY_ID = 'cert_entry_id'
    ALLOW_CLIENT_AUTHENTICATION = 'allow_client_authentication'
    ALLOW_USER_AUTHENTICATION = 'allow_user_authentication'
    DURATION = 'duration'
    NOT_AFTER = 'not_after'
    NOT_BEFORE = 'not_before'
    PARENT_ID = 'partent_id'
    CA_ID = 'ca_id'
    CSR = 'csr'
    PURPOSE = 'purpose'
    ID = 'id'
    CERT_ID = 'cert_id'
    REASON = 'reason'
    PARENT = 'parent'
    EXTERNAL_CA_ID = 'external_ca_id'
    SERIAL_NUMBER = 'serial_number'


''' YML CONSTANTS START '''


class BooleanStr(enum.Enum):
    TRUE = 'true'
    FALSE = 'false'


class AllowedAuthMethods(enum.Enum):
    PASSWORD = "password"
    USER_CERTIFICATE = "user_certificate"
    TWO_FACTOR = 'password_with_user_certificate'
    EMPTY = 'empty'


class AllowedClientTypes(enum.Enum):
    UNREGISTERED = "unregistered"
    PUBLIC = "public"
    CONFIDENTIAL = "confidential"


class LocalCAState(enum.Enum):
    PENDING = 'pending'
    ACTIVE = 'active'


class CACertificatePurpose(enum.Enum):
    SERVER = 'server'
    CLIENT = 'client'
    CA = 'ca'


class CertificateRevokeReason(enum.Enum):
    UNSPECIFIED = 'unspecified'
    KEY_COMPROMISE = 'keyCompromise'
    CA_COMPROMISE = 'cACompromise'
    AFFILIATION_CHANGED = 'affiliationChanged'
    SUPERSEDED = 'superseded'
    CESSATION_OF_OPERATION = 'cessationOfOperation'
    CERTIFICATE_HOLD = 'certificateHold'
    REMOVE_FROM_CRL = 'removeFromCRL'
    PRIVILEGE_WITHDRAWN = 'privilegeWithdrawn'
    AA_COMPROMISE = 'aACompromise'


''' DESCRIPTIONS '''
GROUP_LIST_DESCRIPTION = 'Returns a list of group resources. Command arguments can be used to filter the results.Groups can be filtered for user or client membership. Connection filter applies only to user group membership and NOT to clients.'
GROUP_CREATE_DESCRIPTION = 'Create a new group. The group name is required.'
GROUP_DELETE_DESCRIPTION = 'Deletes a group given the group name.'
GROUP_UPDATE_DESCRIPTION = 'Update the properties of a group given the group name.'
USER_TO_GROUP_ADD_DESCRIPTION = 'Add a user to a group. This command is idempotent: calls to add a user to a group in which they already belong will return an identical, OK response.'
USER_TO_GROUP_REMOVE_DESCRIPTION = 'Removes a user from a group.'
USERS_LIST_DESCRIPTION = 'Returns a list of user resources. Command arguments can be used to filter the results. The results can be filtered, using the command arguments. '
USER_CREATE_DESCRIPTION = "Create a new user in a domain(including root), or add an existing domain user to a sub-domain. Users are always created in the local, internal user database, but might have references to external identity providers.\nThe connection property is optional. If this property is specified when creating new users, it can be the name of a connection or local_account for a local user.\nThe connection property is only used in the body of the create-user request. It is not present in either request or response bodies of the other user endpoints.\nTo create a user - username is mandatory. And password is required in most cases except when certificate authentication is used and certificate subject dn is provided.\nTo enable certificate based authentication for a user, it is required to set certificate_subject_dn and add \"user_certificate\" authentication method in allowed_auth_methods. This functionality is available only for local users.\nTo assign a root domain user to a sub-domain - the users are added to the domain of the user who is logging in, and the connection property should be left empty. The user_id or username fields are the only ones that are used while adding existing users to sub-domains; all other fields are ignored.\nTo enable the two-factor authentication based on username-password and user certificate for a user, it is required to set \"certificate_subject_dn\" and add \"password_with_user_certificate\" authentication method in \"allowed_auth_methods\". For authentication, the user will require both username-password and user certificate. This functionality applies only to local users."
USER_UPDATE_DESCRIPTION = 'Change the properties of a user. For instance the name, the password, or metadata. Permissions would normally restrict this route to users with admin privileges. Non admin users wishing to change their own passwords should use the ciphertrust-user-password-change command.'
USER_DELETE_DESCRIPTION = "Deletes a user given the user's user-id. If the current user is logged into a sub-domain, the user is deleted from that sub-domain. If the current user is logged into the root domain, the user is deleted from all domains it belongs to."
USER_PASSWORD_CHANGE_DESCRIPTION = "Change the current user's password. Can only be used to change the password of the currently authenticated user. The user will not be able to change their password to the same password."
LOCAL_CA_CREATE_DESCRIPTION = "Creates a pending local CA. This operation returns a CSR that either can be self-signed by calling the ciphertrust-local-ca-self-sign command or signed by another CA and installed by calling the ciphertrust-local-ca-install command. A local CA keeps the corresponding private key inside the system and can issue certificates for clients, servers or intermediate CAs. The local CA can also be trusted by services inside the system for verification of client certificates."
LOCAL_CA_LIST_DESCRIPTION = "Returns a list of local CA certificates. The results can be filtered, using the command arguments."
LOCAL_CA_UPDATE_DESCRIPTION = "Update a local CA."
LOCAL_CA_DELETE_DESCRIPTION = "Deletes a local CA certificate."
LOCAL_CA_SELF_SIGN_DESCRIPTION = "Self-sign a local CA certificate. This is used to create a root CA. Either duration or notAfter date must be specified. If both notAfter and duration are given, then notAfter date takes precedence over duration. If duration is given without notBefore date, certificate is issued starting from server's current time for the specified duration."
LOCAL_CA_INSTALL_DESCRIPTION = 'Installs a certificate signed by other CA to act as a local CA. Issuer can be both local or external CA. Typically used for intermediate CAs. The CA certificate must match the earlier created CA CSR, have "CA:TRUE" as part of the "X509v3 Basic Constraints", and have "Certificate Signing" as part of "X509v3 Key Usage" in order to be accepted.'
CERTIFICATE_ISSUE_DESCRIPTION = 'Issues a certificate by signing the provided CSR with the CA. This is typically used to issue server, client or intermediate CA certificates.'
CERTIFICATE_LIST_DESCRIPTION = 'Returns a list of certificates issued by the specified CA. The results can be filtered, using the query parameters.'
CERTIFICATE_DELETE_DESCRIPTION = 'Deletes a local certificate.'
CERTIFICATE_REVOKE_DESCRIPTION = 'Revoke certificate with a given specific reason.'
CERTIFICATE_RESUME_DESCRIPTION = 'Certificate can be resumed only if it is revoked with reason certificatehold.'
EXTERNAL_CERTIFICATE_UPLOAD_DESCRIPTION = 'Uploads an external CA certificate. These certificates can later be trusted by services inside the system for verification of client certificates. The uploaded certificate must have "CA:TRUE" as part of the "X509v3 Basic Constraints" to be accepted.'
EXTERNAL_CERTIFICATE_DELETE_DESCRIPTION = 'Deletes an external CA certificate.'
EXTERNAL_CERTIFICATE_UPDATE_DESCRIPTION = 'Update an external CA.'
EXTERNAL_CERTIFICATE_LIST_DESCRIPTION = 'Returns a list of external CA certificates. The results can be filtered, using the query parameters.'

''' CONSTANTS END'''
''' YML METADATA START'''
PAGINATION_INPUTS = [InputArgument(name=CommandArguments.PAGE, description='Page to return.'),
                     InputArgument(name=CommandArguments.PAGE_SIZE,
                                   description=f'Number of entries per page. Defaults to {MAX_PAGE_SIZE} (in case only page was '
                                               f'provided). Maximum entries per page is {MAX_PAGE_SIZE}'),
                     InputArgument(name=CommandArguments.LIMIT,
                                   description='The max number of entries to return. Defaults to 50',
                                   default=DEFAULT_LIMIT), ]
GROUP_LIST_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, description='Filter by group name.'),
                     InputArgument(name=CommandArguments.USER_ID,
                                   description="Filter by user membership. Using the username 'nil' will return groups with no members. Accepts only user id. Using '-' at the beginning of user_id will return groups that the user is not part of."),
                     InputArgument(name=CommandArguments.CONNECTION,
                                   description='Filter by connection name or ID.'),
                     InputArgument(name=CommandArguments.CLIENT_ID,
                                   description="Filter by client membership. Using the client name 'nil' will return groups with no members. Using '-' at the beginning of client id will return groups that the client is not part of."),
                     ] + PAGINATION_INPUTS
GROUP_CREATE_INPUTS = [InputArgument(name=CommandArguments.NAME, required=True, description='Name of the group.'),
                       InputArgument(name=CommandArguments.DESCRIPTION, description='Description of the group.'), ]
GROUP_DELETE_INPUTS = [InputArgument(name=CommandArguments.NAME, required=True, description='Name of the group'),
                       InputArgument(name=CommandArguments.FORCE,
                                     description='When set to true, groupmaps within this group will be deleted'), ]
GROUP_UPDATE_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, required=True, description='Name of the group to update.'),
                       InputArgument(name=CommandArguments.NEW_GROUP_NAME, description='New name of the group.'),
                       InputArgument(name=CommandArguments.DESCRIPTION, description='New description of the group.'), ]
USER_TO_GROUP_ADD_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, required=True,
                                          default='Key Users',
                                          description='Name of the group. By default it will be added to the Key Users Group.'),
                            InputArgument(name=CommandArguments.USER_ID, required=True,
                                          description='The user_id of the user. Can be retrieved by using the command '
                                                      'ciphertrust-users-list'), ]
USER_TO_GROUP_REMOVE_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, required=True,
                                             description='Name of the group.'),
                               InputArgument(name=CommandArguments.USER_ID, required=True,
                                             description='The user_id of the user. Can be retrieved by using the command '
                                                         'ciphertrust-users-list'), ]
USERS_LIST_INPUTS = [InputArgument(name=CommandArguments.NAME, description="Filter by the user's name"),
                     InputArgument(name=CommandArguments.USER_ID,
                                   description="If provided, gets the user with the specified user_id.  If the user_id 'self' is provided, it will return the current user's information."),
                     InputArgument(name=CommandArguments.USERNAME, description='Filter by the user’s username'),
                     InputArgument(name=CommandArguments.EMAIL, description='Filter by the user’s email'),
                     InputArgument(name=CommandArguments.GROUPS, is_array=True,
                                   description="Filter by users in the given group name. Provide multiple groups separated by comma (',') to get users in all of those groups. Using 'nil' as the group name will return users that are not part of any group."),
                     InputArgument(name=CommandArguments.EXCLUDE_GROUPS, is_array=True,
                                   description="Users associated with given group will be excluded from the result. Provide multiple groups separated by comma (',') to exclude multiple groups in the result."),
                     InputArgument(name=CommandArguments.AUTH_DOMAIN_NAME, description='Filter by user’s auth domain'),
                     InputArgument(name=CommandArguments.ACCOUNT_EXPIRED,
                                   input_type=BooleanStr,
                                   description='Filters the list of users whose expiration time has passed.'),
                     InputArgument(name=CommandArguments.ALLOWED_AUTH_METHODS, is_array=True,
                                   input_type=AllowedAuthMethods,
                                   description="Filter by the login authentication method allowed to the users. It is a comma "
                                               "seperated list of values. A special value `empty` can be specified to get users "
                                               "to whom no authentication method is allowed."),
                     InputArgument(name=CommandArguments.ALLOWED_CLIENT_TYPES, is_array=True,
                                   input_type=AllowedClientTypes,
                                   description="Filter by the client types that can authenticate the user. It is a comma separated list of values."),
                     InputArgument(name=CommandArguments.PASSWORD_POLICY,
                                   description='Filter the list of users based on assigned password policy'),
                     InputArgument(name=CommandArguments.RETURN_GROUPS,
                                   input_type=BooleanStr,
                                   description="If set to 'true', it returns the group's name in which user is associated along with all users information."),
                     ] + PAGINATION_INPUTS
USER_CREATE_INPUTS = [InputArgument(name=CommandArguments.NAME, description='Full name of the user'),
                      InputArgument(name=CommandArguments.USER_ID,
                                    description='The user_id is the ID of an existing root domain user. This field is used only when adding an existing root domain user to a different domain.'),
                      InputArgument(name=CommandArguments.USERNAME,
                                    description='The login name of the user. This is the identifier used to login. This attribute is required to create a user, but is omitted when getting or listing user resources. It cannot be updated. This attribute may also be used (instead of the user_id) when adding an existing root domain user to a different domain.'),
                      InputArgument(name=CommandArguments.PASSWORD,
                                    description='The password used to secure the users account. Allowed passwords are defined by the password policy.Password is optional when "certificate_subject_dn" is set and "user_certificate" is in allowed_auth_methods.In all other cases, password is required. It is not included in user resource responses.'),
                      InputArgument(name=CommandArguments.EMAIL, description='E-mail of the user'),
                      InputArgument(name=CommandArguments.ALLOWED_AUTH_METHODS, is_array=True,
                                    input_type=AllowedAuthMethods,
                                    description='Comma seperated login authentication methods allowed to the user. Default '
                                                'value - "password" i.e. Password Authentication is allowed by default. '
                                                'Setting it to empty, i.e "empty", means no authentication method is allowed to the '
                                                'user. If both enable_cert_auth and allowed_auth_methods are provided in the '
                                                'request, enable_cert_auth is ignored. Setting it to '
                                                '"password_with_user_certificate", means two-factor authentication is enabled '
                                                'for the user. The user will require both username-password and '
                                                'user_certificate for authentication. Valid values are: password '
                                                'user_certificate password_with_user_certificate This property does not control '
                                                'login behavior for users in admin group.'),
                      InputArgument(name=CommandArguments.ALLOWED_CLIENT_TYPES, is_array=True,
                                    input_type=AllowedClientTypes,
                                    description="List of client types that can authenticate using the user's credentials. "
                                                "Default value - \"unregistered,public,confidential\" i.e. all clients can "
                                                "authenticate the user using user's credentials. Setting it to empty, \"empty\", "
                                                "authenticate the user using user's credentials. Setting it to empty, \"empty\", "
                                                "means no client can authenticate this user, which effectively means no one can "
                                                "login into this user. Valid values in the array are: unregistered public "
                                                "confidential This property does not control login behavior for users in admin "
                                                "group."),
                      InputArgument(name=CommandArguments.CERTIFICATE_SUBJECT_DN,
                                    description='The Distinguished Name of the user in certificate'),
                      InputArgument(name=CommandArguments.CONNECTION, default='local_account',
                                    description='Can be the name of a connection or "local_account" for a local user'),
                      InputArgument(name=CommandArguments.EXPIRES_AT,
                                    description="The expires_at field is applicable only for local user account. Only members "
                                                "of the 'admin' and 'User Admins' groups can add expiration to an existing "
                                                "local user account or modify the expiration date. Once the expires_at date is "
                                                "reached, the user account gets disabled and the user is not able to perform "
                                                "any actions. Setting the expires_at field to \"empty\", removes the expiration "
                                                "date of the user account."),
                      InputArgument(name=CommandArguments.IS_DOMAIN_USER,
                                    input_type=BooleanStr,
                                    description="This flag can be used to create the user "
                                                "in a non-root domain where user "
                                                "management is allowed."),
                      InputArgument(name=CommandArguments.PREVENT_UI_LOGIN, default='false',
                                    input_type=BooleanStr,
                                    description='If true, user is not allowed to login from Web UI.'),
                      InputArgument(name=CommandArguments.PASSWORD_CHANGE_REQUIRED,
                                    input_type=BooleanStr,
                                    description='Password change required '
                                                'flag. If set to true, '
                                                'user will be required to '
                                                'change their password on '
                                                'next successful login.'),
                      InputArgument(name=CommandArguments.PASSWORD_POLICY,
                                    description='The password policy applies only to local user accounts and overrides the '
                                                'global password policy. By default, the global password policy is applied to '
                                                'the users.')
                      ]
UPDATE_USER_INPUTS = [InputArgument(name=CommandArguments.NAME, description="The user's full name."),
                      InputArgument(name=CommandArguments.USER_ID, required=True, description="The user_id of the user."),
                      InputArgument(name=CommandArguments.USERNAME, description='The login name of the user.'),
                      InputArgument(name=CommandArguments.PASSWORD,
                                    description="The password used to secure the user's account."),
                      InputArgument(name=CommandArguments.EMAIL, description='The email of the user'),
                      InputArgument(name=CommandArguments.PASSWORD_CHANGE_REQUIRED,
                                    input_type=BooleanStr,
                                    description='Password change required flag. If set to true, '
                                                'user will be required to '
                                                'change their password on '
                                                'next successful login.'),
                      InputArgument(name=CommandArguments.ALLOWED_AUTH_METHODS, is_array=True,
                                    input_type=AllowedAuthMethods,
                                    description="List of login authentication methods allowed to the user. Setting it to empty, "
                                                "i.e \"empty\", means no authentication method is allowed to the user. If both "
                                                "enable_cert_auth and allowed_auth_methods are provided in the request, "
                                                "enable_cert_auth is ignored. Setting it to "
                                                "\"password_with_user_certificate\", means two-factor authentication is "
                                                "enabled for the user. The user will require both username-password and "
                                                "user_certificate for authentication. User cannot have \"password\" or "
                                                "\"user_certificate\" with \"password_with_user_certificate\" in "
                                                "allowed_auth_methods. Valid values in the array are: password user_certificate "
                                                "password_with_user_certificate This property does not control login behavior "
                                                "for users in admin group."),
                      InputArgument(name=CommandArguments.ALLOWED_CLIENT_TYPES, is_array=True,
                                    input_type=AllowedClientTypes,
                                    description="List of client types that can authenticate using the user's credentials. "
                                                "Setting it to empty, i.e \"empty\", means no client can authenticate this user, "
                                                "which effectively means no one can login into this user. Valid values in the "
                                                "array are: unregistered public confidential This property does not control "
                                                "login behavior for users in admin group."),
                      InputArgument(name=CommandArguments.CERTIFICATE_SUBJECT_DN,
                                    description='The Distinguished Name of the user in certificate. e.g.OU=organization unit,'
                                                'O=organization,L=location,ST=state,C=country.'),
                      InputArgument(name=CommandArguments.EXPIRES_AT,
                                    description="The \"expires_at\" field is applicable only for local user account. Only "
                                                "members of the 'admin' and 'User Admins' groups can add expiration to an "
                                                "existing local user account or modify the expiration date. Once the "
                                                "\"expires_at\" date is reached, the user account gets disabled and the user is "
                                                "not able to perform any actions. Setting the \"expires_at\" argument to "
                                                "\"empty\", removes the expiration date of the user account."),
                      InputArgument(name=CommandArguments.FAILED_LOGINS_COUNT,
                                    description='Set it to 0 to unlock a locked user account.'),
                      InputArgument(name=CommandArguments.PREVENT_UI_LOGIN, default='false',
                                    input_type=BooleanStr,
                                    description='If true, user is not allowed to login from Web UI.'),

                      InputArgument(name=CommandArguments.PASSWORD_POLICY,
                                    description='The password policy applies only to local user accounts and overrides the '
                                                'global password policy. By default, the global password policy is applied to '
                                                'the users.'),

                      ]
USER_DELETE_INPUTS = [InputArgument(name=CommandArguments.USER_ID, required=True, description='The user_id of the user'), ]

USER_PASSWORD_CHANGE_INPUTS = [InputArgument(name=CommandArguments.NEW_PASSWORD, required=True, description='The new password.'),
                               InputArgument(name=CommandArguments.PASSWORD, required=True, description="The own user's current "
                                                                                                        "password."),
                               InputArgument(name=CommandArguments.USERNAME, required=True,
                                             description='The login name of the current user.'),
                               InputArgument(name=CommandArguments.AUTH_DOMAIN, description='The domain where user needs to '
                                                                                            'be authenticated. This is the '
                                                                                            'domain where user is created. '
                                                                                            'Defaults to the root domain.'), ]

LOCAL_CA_CREATE_INPUTS = [InputArgument(name=CommandArguments.CN, required=True, description='Common name'),
                          InputArgument(name=CommandArguments.ALGORITHM,
                                        description='RSA or ECDSA (default) algorithms are supported. Signature algorithm (SHA512WithRSA, SHA384WithRSA, SHA256WithRSA, SHA1WithRSA, ECDSAWithSHA512, ECDSAWithSHA384, ECDSAWithSHA256) is selected based on the algorithm and size.'),
                          InputArgument(name=CommandArguments.COPY_FROM_CA,
                                        description='ID of any Local CA. If given, the csr properties are copied from the given CA.'),
                          InputArgument(name=CommandArguments.DNS_NAMES, is_array=True,
                                        description='Subject Alternative Names (SAN) values (comma seperated string)'),
                          InputArgument(name=CommandArguments.EMAIL, is_array=True,
                                        description='E-mail addresses (comma seperated string)'),
                          InputArgument(name=CommandArguments.IP, is_array=True,
                                        description='IP addresses (comma seperated string)'),
                          InputArgument(name=CommandArguments.NAME,
                                        description='A unique name of CA, if not provided, will be set to localca-<id>.'),
                          InputArgument(name=CommandArguments.NAME_FIELDS_RAW_JSON, is_array=True,
                                        description='Name fields are "O=organization, OU=organizational unit, L=location, ST=state/province, C=country". Fields can be duplicated if present in different objects. This is a raw json string, for example: "[{"O": "Thales", "OU": "RnD", "C": "US", "ST": "MD", "L": "Belcamp"}, {"OU": "Thales Group Inc."}]"'),
                          InputArgument(name=CommandArguments.NAME_FIELDS_JSON_ENTRY_ID,
                                        description='Entry Id of the file that contains JSON representation of the name_fields_raw_json'),
                          InputArgument(name=CommandArguments.SIZE,
                                        description='Key size. RSA: 1024 - 4096 (default: 2048), ECDSA: 256 (default), 384, 521'), ]

LOCAL_CA_LIST_INPUTS = [InputArgument(name=CommandArguments.SUBJECT, description='Filter by subject'),
                        InputArgument(name=CommandArguments.LOCAL_CA_ID,
                                      description='An identifier of the resource. This can be either the ID (a UUIDv4),the Name, the URI, or the slug (which is the last component of the URI).'),
                        InputArgument(name=CommandArguments.CHAINED,
                                      input_type=BooleanStr,
                                      description='When set to ‘true’ the full CA chain is returned with the certificate.Must be used '
                                                  'with the local CA ID.'),
                        InputArgument(name=CommandArguments.ISSUER, description='Filter by issuer'),
                        InputArgument(name=CommandArguments.STATE, input_type=LocalCAState, description='Filter by state'),
                        InputArgument(name=CommandArguments.CERT, description='Filter by cert'),
                        ] + PAGINATION_INPUTS

LOCAL_CA_UPDATE_INPUTS = [
    InputArgument(name=CommandArguments.LOCAL_CA_ID, required=True,
                  description='An identifier of the resource. This can be either the ID (a UUIDv4),the Name, the URI, or the slug (which is the last component of the URI).'),
    InputArgument(name=CommandArguments.ALLOW_CLIENT_AUTHENTICATION,
                  input_type=BooleanStr,
                  description='If set to true, the certificates signed by the specified CA can be used '
                              'for client authentication.'),
    InputArgument(name=CommandArguments.ALLOW_USER_AUTHENTICATION,
                  input_type=BooleanStr,
                  description='If set to true, the certificates signed by the specified CA can be used '
                              'for user authentication.'),
]
LOCAL_CA_DELETE_INPUTS = [
    InputArgument(name=CommandArguments.LOCAL_CA_ID, required=True,
                  description='An identifier of the resource. This can be either the ID (a UUIDv4),the Name, the URI, or the slug (which is the last component of the URI).'),
]

LOCAL_CA_SELF_SIGN_INPUTS = [
    InputArgument(name=CommandArguments.LOCAL_CA_ID, required=True, description='An identifier of the resource. This can be '
                                                                                'either the ID (a UUIDv4),the Name, the URI, or the slug (which is the last component of the URI).'),
    InputArgument(name=CommandArguments.DURATION,
                  description='End date of certificate. Either notAfter date or duration must be specified. notAfter overrides '
                              'duration if both are given.'),
    InputArgument(name=CommandArguments.NOT_AFTER,
                  description='End date of certificate. Either notAfter date or duration must be specified. notAfter overrides duration if both are given.'),
    InputArgument(name=CommandArguments.NOT_BEFORE, description='Start date of certificate.'),

]

LOCAL_CA_INSTALL_INPUTS = [
    InputArgument(name=CommandArguments.LOCAL_CA_ID, required=True, description='An identifier of the resource. This can be '
                                                                                'either the ID (a UUIDv4),the Name, the URI, or the slug (which is the last component of the URI).'),
    InputArgument(name=CommandArguments.CERT_ENTRY_ID, required=True,
                  description='The entry ID of the file to upload that contains the signed certificate in PEM format to install '
                              'as a local CA'),
    InputArgument(name=CommandArguments.PARENT_ID, required=True,
                  description='An identifier of the parent resource. The resource can be either a local or an external CA. The identifier can be either the ID (a UUIDv4) or the URI.')]

CERTIFICATE_ISSUE_INPUTS = [
    InputArgument(name=CommandArguments.CA_ID, required=True, description='An identifier of the issuer CA resource'),
    InputArgument(name=CommandArguments.CSR, required=True, description='CSR in PEM format'),
    InputArgument(name=CommandArguments.PURPOSE, required=True, input_type=CACertificatePurpose,
                  description='Purpose of the certificate. Possible values: server, client or ca'),
    InputArgument(name=CommandArguments.DURATION,
                  description='Duration in days of certificate. Either duration or notAfter date must be specified.'),
    InputArgument(name=CommandArguments.NAME,
                  description='A unique name of Certificate, if not provided, will be set to cert-<id>.'),
    InputArgument(name=CommandArguments.NOT_AFTER,
                  description='End date of certificate. Either notAfter date or duration must be specified. notAfter overrides duration if both are given.'),
    InputArgument(name=CommandArguments.NOT_BEFORE,
                  description='Start date of certificate. ISO 8601 format for notBefore date. Either duration or notAfter date must be specified. If duration is given without notBefore date, certificate is issued starting from server\'s current time for the specified duration.'),
]

CERTIFICATE_LIST_INPUTS = [InputArgument(name=CommandArguments.CA_ID, required=True,
                                         description='An identifier of the issuer CA resource'),
                           InputArgument(name=CommandArguments.SUBJECT, description='Filter by subject'),
                           InputArgument(name=CommandArguments.ISSUER, description='Filter by issuer'),
                           InputArgument(name=CommandArguments.CERT, description='Filter by cert'),
                           InputArgument(name=CommandArguments.ID, description='Filter by id or URI'),
                           ] + PAGINATION_INPUTS

LOCAL_CERTIFICATE_DELETE_INPUTS = [
    InputArgument(name=CommandArguments.CA_ID, required=True, description='An identifier of the issuer CA resource'),
    InputArgument(name=CommandArguments.LOCAL_CA_ID, required=True, description='The identifier of the certificate resource'),
]

CERTIFICATE_REVOKE_INPUTS = [
    InputArgument(name=CommandArguments.CA_ID, required=True, description='An identifier of the issuer CA resource'),
    InputArgument(name=CommandArguments.CERT_ID, required=True, description='The identifier of the certificate resource'),
    InputArgument(name=CommandArguments.REASON, required=True, input_type=CertificateRevokeReason,
                  description='Specify one of the reason. Reasons to revoke a certificate according to RFC 5280 '),
]

CERTIFICATE_RESUME_INPUTS = [
    InputArgument(name=CommandArguments.CA_ID, required=True, description='An identifier of the issuer CA resource'),
    InputArgument(name=CommandArguments.CERT_ID, required=True, description='The identifier of the certificate resource'),
]

EXTERNAL_CERTIFICATE_UPLOAD_INPUTS = [
    InputArgument(name=CommandArguments.CERT, required=True, description='External CA certificate in PEM format'),
    InputArgument(name=CommandArguments.NAME,
                  description='A unique name of CA, if not provided, will be set to externalca-<id>.'),
    InputArgument(name=CommandArguments.PARENT,
                  description='URI reference to a parent external CA certificate. This information can be used to build a certificate hierarchy.'),
]

EXTERNAL_CERTIFICATE_DELETE_INPUTS = [
    InputArgument(name=CommandArguments.EXTERNAL_CA_ID, required=True, description='The identifier of the certificate resource'),
]

EXTERNAL_CERTIFICATE_UPDATE_INPUTS = [
    InputArgument(name=CommandArguments.EXTERNAL_CA_ID, required=True, description='The identifier of the certificate resource'),
    InputArgument(name=CommandArguments.ALLOW_CLIENT_AUTHENTICATION,
                  input_type=BooleanStr,
                  description='If set to true, the certificates signed by the specified CA can be used for client authentication.'),
    InputArgument(name=CommandArguments.ALLOW_USER_AUTHENTICATION,
                  input_type=BooleanStr,
                  description='If set to true, the certificates signed by the specified CA can be used for user authentication.'),
]

EXTERNAL_CERTIFICATE_LIST_INPUTS = [
                                       InputArgument(name=CommandArguments.SUBJECT, description='Filter by subject'),
                                       InputArgument(name=CommandArguments.ISSUER, description='Filter by issuer'),
                                       InputArgument(name=CommandArguments.SERIAL_NUMBER, description='Filter by serial number'),
                                       InputArgument(name=CommandArguments.CERT, description='Filter by cert'),
                                   ] + PAGINATION_INPUTS

''' OUTPUTS '''

GROUP_LIST_OUTPUT = [
    OutputArgument(name="limit", output_type=int,
                   description="The max number of records returned. Equivalent to 'limit' in SQL."),
    OutputArgument(name="skip", output_type=int,
                   description="The index of the first record returned. Equivalent to 'offset' in SQL."),
    OutputArgument(name="total", output_type=int, description="The total records matching the query."),
    OutputArgument(name="messages", output_type=list,
                   description="An optional list of warning messages, usually used to note when unsupported query parameters "
                               "were ignored."),
    OutputArgument(name="resources.name", output_type=str, description="name of the group"),
    OutputArgument(name="resources.created_at", output_type=datetime.datetime, description="The time the group was created."),
    OutputArgument(name="resources.updated_at", output_type=datetime.datetime,
                   description="The time the group was last updated."),
    OutputArgument(name="resources.user_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences."),
    OutputArgument(name="resources.app_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles."),
    OutputArgument(name="resources.client_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. client_metadata is typically used by applications to store information about the resource, such as client preferences."),
    OutputArgument(name="resources.description", output_type=str, description="description of the group"),
    OutputArgument(name="resources.users_count", output_type=int,
                   description="It returns the total user count associated with the group"),
]

GROUP_CREATE_OUTPUT = [
    OutputArgument(name="name", output_type=str, description="The name of the group."),
    OutputArgument(name="created_at", output_type=datetime.datetime, description="The time the group was created."),
    OutputArgument(name="updated_at", output_type=datetime.datetime, description="The time the group was last updated."),
    OutputArgument(name="user_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences."),
    OutputArgument(name="app_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles."),
    OutputArgument(name="client_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. client_metadata is typically used by applications to store information about the resource, such as client preferences."),
    OutputArgument(name="description", output_type=str, description="The description of the group."),
    OutputArgument(name="users_count", output_type=int, description="The total user count associated with the group."),
]

GROUP_UPDATE_OUTPUT = [
    OutputArgument(name="name", output_type=str, description="The name of the group."),
    OutputArgument(name="created_at", output_type=datetime.datetime, description="The time the group was created."),
    OutputArgument(name="updated_at", output_type=datetime.datetime, description="The time the group was last updated."),
    OutputArgument(name="user_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences."),
    OutputArgument(name="app_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles."),
    OutputArgument(name="client_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. client_metadata is typically used by applications to store information about the resource, such as client preferences."),
    OutputArgument(name="description", output_type=str, description="The description of the group."),
    OutputArgument(name="users_count", output_type=int, description="The total user count associated with the group."),
]

USER_TO_GROUP_ADD_OUTPUT = [
    OutputArgument(name="name", output_type=str, description="The name of the group."),
    OutputArgument(name="created_at", output_type=datetime.datetime, description="The time the group was created."),
    OutputArgument(name="updated_at", output_type=datetime.datetime, description="The time the group was last updated."),
    OutputArgument(name="user_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences."),
    OutputArgument(name="app_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles."),
    OutputArgument(name="client_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. client_metadata is typically used by applications to store information about the resource, such as client preferences."),
    OutputArgument(name="description", output_type=str, description="The description of the group."),
    OutputArgument(name="users_count", output_type=int, description="The total user count associated with the group."),
]
'''
I've added the fields nickname, user_id, password_changed_at, password_change_required, groups, auth_domain, login_flags, and auth_domain_name based on the provided JSON response.
'''
USERS_LIST_OUTPUT = [
    OutputArgument(name="limit", output_type=int,
                   description="The max number of records returned. Equivalent to 'limit' in SQL."),
    OutputArgument(name="skip", output_type=int,
                   description="The index of the first record returned. Equivalent to 'offset' in SQL."),
    OutputArgument(name="total", output_type=int, description="The total records matching the query."),
    OutputArgument(name="messages", output_type=list,
                   description="An optional list of warning messages, usually used to note when unsupported query parameters were ignored."),
    OutputArgument(name="resources.userid", output_type=str, description="A unique identifier for API call usage."),
    OutputArgument(name="resources.username", output_type=str,
                   description="The login name of the user. This is the identifier used to login. This attribute is required to "
                               "create a user, but is omitted when getting or listing user resources. It cannot be updated."),
    OutputArgument(name="resources.connection", output_type=str,
                   description="This attribute is required to create a user, but is not included in user resource responses. Can be the name of a connection or 'local_account' for a local user, defaults to 'local_account'."),
    OutputArgument(name="resources.email", output_type=str, description="E-mail of the user"),
    OutputArgument(name="resources.name", output_type=str, description="Full name of the user"),
    OutputArgument(name="resources.certificate_subject_dn", output_type=str,
                   description="The Distinguished Name of the user in certificate"),
    OutputArgument(name="resources.enable_cert_auth", output_type=bool,
                   description="Deprecated: Use allowed_auth_methods instead. Enable certificate based authentication flag. If set to true, the user will be able to login using certificate."),
    OutputArgument(name="resources.user_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences."),
    OutputArgument(name="resources.app_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles."),
    OutputArgument(name="resources.logins_count", output_type=int, description="Count for the number of logins"),
    OutputArgument(name="resources.last_login", output_type=datetime.datetime, description="Timestamp of last login"),
    OutputArgument(name="resources.created_at", output_type=datetime.datetime, description="Timestamp of when user was created"),
    OutputArgument(name="resources.updated_at", output_type=datetime.datetime,
                   description="Timestamp of last update of the user"),
    OutputArgument(name="resources.allowed_auth_methods", output_type=list,
                   description="List of login authentication methods allowed to the user."),
    OutputArgument(name="resources.expires_at", output_type=datetime.datetime,
                   description="The expires_at is applicable only for local user accounts. The admin or a user who is part of the admin group can add expiration to an existing local user account or modify the expiration date. Once the expires_at date is reached, the user account gets disabled and the user is not able to perform any actions."),
    OutputArgument(name="resources.password_policy", output_type=str,
                   description="The password policy applies only to local user accounts and overrides the global password policy. By default, the global password policy is applied to the users."),
    OutputArgument(name="resources.allowed_client_types", output_type=list,
                   description="List of client types allowed to the user."),
    OutputArgument(name="resources.last_failed_login_at", output_type=datetime.datetime,
                   description="Timestamp of last failed login"),
    OutputArgument(name="resources.failed_logins_count", output_type=int, description="Count of failed logins"),
    OutputArgument(name="resources.failed_logins_initial_attempt_at", output_type=datetime.datetime,
                   description="Timestamp of first failed login"),
    OutputArgument(name="resources.account_lockout_at", output_type=datetime.datetime,
                   description="Timestamp of account lockout"),
    OutputArgument(name="resources.nickname", output_type=str, description="Nickname of the user"),
    OutputArgument(name="resources.user_id", output_type=str, description="The user's unique identifier"),
    OutputArgument(name="resources.password_changed_at", output_type=datetime.datetime,
                   description="Timestamp of when the password was last changed"),
    OutputArgument(name="resources.password_change_required", output_type=bool,
                   description="Flag indicating if password change is required"),
    OutputArgument(name="resources.groups", output_type=list, description="List of groups the user belongs to"),
    OutputArgument(name="resources.auth_domain", output_type=str, description="Authentication domain ID"),
    OutputArgument(name="resources.login_flags", output_type=dict,
                   description="Flags related to user login"),
    OutputArgument(name="resources.auth_domain_name", output_type=str,
                   description="Name of the authentication domain"),
]

USER_CREATE_OUTPUT = [
    OutputArgument(name="user_id", output_type=str, description="A unique identifier for API call usage."),
    OutputArgument(name="username", output_type=str,
                   description="The login name of the user. This is the identifier used to login. This attribute is required to create a user, but is omitted when getting or listing user resources. It cannot be updated."),
    OutputArgument(name="connection", output_type=str,
                   description="This attribute is required to create a user, but is not included in user resource responses. Can be the name of a connection or 'local_account' for a local user, defaults to 'local_account'."),
    OutputArgument(name="email", output_type=str, description="E-mail of the user"),
    OutputArgument(name="name", output_type=str, description="Full name of the user"),
    OutputArgument(name="certificate_subject_dn", output_type=str,
                   description="The Distinguished Name of the user in certificate"),
    OutputArgument(name="enable_cert_auth", output_type=bool,
                   description="Deprecated: Use allowed_auth_methods instead. Enable certificate based authentication flag. If set to true, the user will be able to login using certificate."),
    OutputArgument(name="user_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences."),
    OutputArgument(name="app_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles."),
    OutputArgument(name="logins_count", output_type=int, description="Count for the number of logins"),
    OutputArgument(name="last_login", output_type=datetime.datetime, description="Timestamp of last login"),
    OutputArgument(name="created_at", output_type=datetime.datetime, description="Timestamp of when user was created"),
    OutputArgument(name="updated_at", output_type=datetime.datetime, description="Timestamp of last update of the user"),
    OutputArgument(name="allowed_auth_methods", output_type=list,
                   description="List of login authentication methods allowed to the user."),
    OutputArgument(name="expires_at", output_type=datetime.datetime,
                   description="The expires_at is applicable only for local user accounts. The admin or a user who is part of the admin group can add expiration to an existing local user account or modify the expiration date. Once the expires_at date is reached, the user account gets disabled and the user is not able to perform any actions."),
    OutputArgument(name="password_policy", output_type=str,
                   description="The password policy applies only to local user accounts and overrides the global password policy. By default, the global password policy is applied to the users."),
    OutputArgument(name="allowed_client_types", output_type=list, description="List of client types allowed to the user."),

    # Additional fields from provided examples
    OutputArgument(name="nickname", output_type=str, description="Nickname of the user"),
    OutputArgument(name="failed_logins_count", output_type=int, description="Count of failed login attempts"),
    OutputArgument(name="account_lockout_at", output_type=datetime.datetime,
                   description="Timestamp when the account was locked out"),
    OutputArgument(name="failed_logins_initial_attempt_at", output_type=datetime.datetime,
                   description="Timestamp of the initial failed login attempt"),
    OutputArgument(name="last_failed_login_at", output_type=datetime.datetime,
                   description="Timestamp of the last failed login attempt"),
    OutputArgument(name="password_changed_at", output_type=datetime.datetime,
                   description="Timestamp of when the password was last changed"),
    OutputArgument(name="password_change_required", output_type=bool, description="Indicates if a password change is required"),
    OutputArgument(name="auth_domain", output_type=str, description="Authentication domain of the user"),
    OutputArgument(name="login_flags", output_type=dict, description="Flags related to login permissions"),
]

USER_UPDATE_OUTPUT = [
    OutputArgument(name="user_id", output_type=str, description="A unique identifier for API call usage."),
    OutputArgument(name="username", output_type=str,
                   description="The login name of the user. This is the identifier used to login. This attribute is required to create a user, but is omitted when getting or listing user resources. It cannot be updated."),
    OutputArgument(name="connection", output_type=str,
                   description="This attribute is required to create a user, but is not included in user resource responses. Can be the name of a connection or 'local_account' for a local user, defaults to 'local_account'."),
    OutputArgument(name="email", output_type=str, description="E-mail of the user"),
    OutputArgument(name="name", output_type=str, description="Full name of the user"),
    OutputArgument(name="nickname", output_type=str, description="Nickname of the user"),
    OutputArgument(name="certificate_subject_dn", output_type=str,
                   description="The Distinguished Name of the user in certificate"),
    OutputArgument(name="enable_cert_auth", output_type=bool,
                   description="Deprecated: Use allowed_auth_methods instead. Enable certificate based authentication flag. If set to true, the user will be able to login using certificate."),
    OutputArgument(name="user_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences."),
    OutputArgument(name="app_metadata", output_type=dict,
                   description="A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles."),
    OutputArgument(name="logins_count", output_type=int, description="Count for the number of logins"),
    OutputArgument(name="last_login", output_type=datetime.datetime, description="Timestamp of last login"),
    OutputArgument(name="created_at", output_type=datetime.datetime, description="Timestamp of when user was created"),
    OutputArgument(name="updated_at", output_type=datetime.datetime, description="Timestamp of last update of the user"),
    OutputArgument(name="allowed_auth_methods", output_type=list,
                   description="List of login authentication methods allowed to the user."),
    OutputArgument(name="expires_at", output_type=datetime.datetime,
                   description="The expires_at is applicable only for local user accounts. The admin or a user who is part of the admin group can add expiration to an existing local user account or modify the expiration date. Once the expires_at date is reached, the user account gets disabled and the user is not able to perform any actions."),
    OutputArgument(name="password_policy", output_type=str,
                   description="The password policy applies only to local user accounts and overrides the global password policy. By default, the global password policy is applied to the users."),
    OutputArgument(name="allowed_client_types", output_type=list, description="List of client types allowed to the user."),
    OutputArgument(name="failed_logins_count", output_type=int,
                   description="Count of failed login attempts"),
    OutputArgument(name="failed_logins_initial_attempt_at", output_type=datetime.datetime,
                   description="Timestamp of the initial failed login attempt."),
    OutputArgument(name="account_lockout_at", output_type=datetime.datetime,
                   description="Timestamp of when the account was locked."),
    OutputArgument(name="last_failed_login_at", output_type=datetime.datetime,
                   description="Timestamp of the last failed login attempt."),
    OutputArgument(name="password_changed_at", output_type=datetime.datetime,
                   description="Timestamp of when the password was last changed."),
    OutputArgument(name="password_change_required", output_type=bool,
                   description="Indicates if a password change is required at next login."),
    OutputArgument(name="login_flags", output_type=dict, description="Flags related to login, such as prevent_ui_login."),
]

LOCAL_CA_CREATE_OUTPUT = [
    OutputArgument(name="id", output_type=str, description="Unique identifier for the CA."),
    OutputArgument(name="uri", output_type=str, description="Uniform Resource Identifier for the CA."),
    OutputArgument(name="account", output_type=str, description="Account associated with the CA."),
    OutputArgument(name="application", output_type=str, description="Application associated with the CA."),
    OutputArgument(name="devAccount", output_type=str, description="Developer account associated with the CA."),
    OutputArgument(name="createdAt", output_type=datetime.datetime, description="Timestamp when the CA was created."),
    OutputArgument(name="updatedAt", output_type=datetime.datetime, description="Timestamp when the CA was last updated."),
    OutputArgument(name="name", output_type=str, description="Name of the CA."),
    OutputArgument(name="state", output_type=str, description="State of the CA."),
    OutputArgument(name="csr", output_type=str, description="Certificate Signing Request (CSR) for the CA."),
    OutputArgument(name="subject", output_type=str, description="Distinguished Name (DN) of the CA subject."),
    OutputArgument(name="notBefore", output_type=datetime.datetime,
                   description="Timestamp before which the certificate is not valid."),
    OutputArgument(name="notAfter", output_type=datetime.datetime,
                   description="Timestamp after which the certificate is not valid."),
    OutputArgument(name="sha1Fingerprint", output_type=str, description="SHA-1 fingerprint of the CA certificate."),
    OutputArgument(name="sha256Fingerprint", output_type=str, description="SHA-256 fingerprint of the CA certificate."),
    OutputArgument(name="sha512Fingerprint", output_type=str, description="SHA-512 fingerprint of the CA certificate."),
]

LOCAL_CA_LIST_OUTPUT = [
    OutputArgument(name="limit", output_type=int,
                   description="The max number of records returned. Equivalent to 'limit' in SQL."),
    OutputArgument(name="skip", output_type=int,
                   description="The index of the first record returned. Equivalent to 'offset' in SQL."),
    OutputArgument(name="total", output_type=int, description="The total records matching the query."),
    OutputArgument(name="messages", output_type=list,
                   description="An optional list of warning messages, usually used to note when unsupported query parameters were ignored."),
    OutputArgument(name="resources.id", output_type=str, description="A unique identifier for the certificate authority (CA)."),
    OutputArgument(name="resources.uri", output_type=str, description="Uniform Resource Identifier associated with the CA."),
    OutputArgument(name="resources.account", output_type=str, description="Account associated with the CA."),
    OutputArgument(name="resources.name", output_type=str, description="Name of the CA."),
    OutputArgument(name="resources.state", output_type=str, description="Current state of the CA (e.g., pending, active)."),
    OutputArgument(name="resources.createdAt", output_type=datetime.datetime,
                   description="Timestamp of when the CA was created."),
    OutputArgument(name="resources.updatedAt", output_type=datetime.datetime, description="Timestamp of last update of the CA."),
    OutputArgument(name="resources.csr", output_type=str, description="Certificate Signing Request for the CA."),
    OutputArgument(name="resources.cert", output_type=str, description="Certificate associated with the CA."),
    OutputArgument(name="resources.serialNumber", output_type=str, description="Serial number of the CA's certificate."),
    OutputArgument(name="resources.subject", output_type=str, description="Subject of the CA's certificate."),
    OutputArgument(name="resources.issuer", output_type=str, description="Issuer of the CA's certificate."),
    OutputArgument(name="resources.notBefore", output_type=datetime.datetime,
                   description="Start date of the CA's certificate validity."),
    OutputArgument(name="resources.notAfter", output_type=datetime.datetime,
                   description="End date of the CA's certificate validity."),
    OutputArgument(name="resources.sha1Fingerprint", output_type=str, description="SHA1 fingerprint of the CA's certificate."),
    OutputArgument(name="resources.sha256Fingerprint", output_type=str,
                   description="SHA256 fingerprint of the CA's certificate."),
    OutputArgument(name="resources.sha512Fingerprint", output_type=str,
                   description="SHA512 fingerprint of the CA's certificate."),
    OutputArgument(name="resources.purpose.client_authentication", output_type=str,
                   description="Indicates if client authentication is enabled for the CA."),
    OutputArgument(name="resources.purpose.user_authentication", output_type=str,
                   description="Indicates if user authentication is enabled for the CA.")
]

LOCAL_CA_UPDATE_OUTPUTS = [
    OutputArgument(name="id", output_type=str, description="A unique identifier for the certificate authority (CA)."),
    OutputArgument(name="uri", output_type=str, description="Uniform Resource Identifier associated with the CA."),
    OutputArgument(name="account", output_type=str, description="Account associated with the CA."),
    OutputArgument(name="name", output_type=str, description="Name of the CA."),
    OutputArgument(name="state", output_type=str, description="Current state of the CA (e.g., pending, active)."),
    OutputArgument(name="createdAt", output_type=datetime.datetime, description="Timestamp of when the CA was created."),
    OutputArgument(name="updatedAt", output_type=datetime.datetime, description="Timestamp of the last update of the CA."),
    OutputArgument(name="csr", output_type=str, description="Certificate Signing Request for the CA, if updated."),
    OutputArgument(name="cert", output_type=str, description="Certificate associated with the CA."),
    OutputArgument(name="serialNumber", output_type=str, description="Serial number of the CA's certificate."),
    OutputArgument(name="subject", output_type=str, description="Subject of the CA's certificate."),
    OutputArgument(name="issuer", output_type=str, description="Issuer of the CA's certificate."),
    OutputArgument(name="notBefore", output_type=datetime.datetime, description="Start date of the CA's certificate validity."),
    OutputArgument(name="notAfter", output_type=datetime.datetime, description="End date of the CA's certificate validity."),
    OutputArgument(name="sha1Fingerprint", output_type=str, description="SHA1 fingerprint of the CA's certificate."),
    OutputArgument(name="sha256Fingerprint", output_type=str, description="SHA256 fingerprint of the CA's certificate."),
    OutputArgument(name="sha512Fingerprint", output_type=str, description="SHA512 fingerprint of the CA's certificate."),
    OutputArgument(name="purpose.client_authentication", output_type=str,
                   description="Indicates if client authentication is enabled for the CA."),
    OutputArgument(name="purpose.user_authentication", output_type=str,
                   description="Indicates if user authentication is enabled for the CA.")
]

LOCAL_CA_SELF_SIGN_OUTPUT = [
    OutputArgument(name="id", output_type=str, description="A unique identifier for the certificate authority (CA)."),
    OutputArgument(name="uri", output_type=str, description="Uniform Resource Identifier associated with the CA."),
    OutputArgument(name="account", output_type=str, description="Account associated with the CA."),
    OutputArgument(name="application", output_type=str, description="Application associated with the CA."),
    OutputArgument(name="devAccount", output_type=str, description="Developer account associated with the CA."),
    OutputArgument(name="name", output_type=str, description="Name of the CA."),
    OutputArgument(name="state", output_type=str, description="Current state of the CA (e.g., pending, active)."),
    OutputArgument(name="createdAt", output_type=datetime.datetime, description="Timestamp of when the CA was created."),
    OutputArgument(name="updatedAt", output_type=datetime.datetime, description="Timestamp of the last update of the CA."),
    OutputArgument(name="csr", output_type=str, description="Certificate Signing Request for the CA, if updated."),
    OutputArgument(name="cert", output_type=str, description="Certificate associated with the CA."),
    OutputArgument(name="serialNumber", output_type=str, description="Serial number of the CA's certificate."),
    OutputArgument(name="subject", output_type=str, description="Subject of the CA's certificate."),
    OutputArgument(name="issuer", output_type=str, description="Issuer of the CA's certificate."),
    OutputArgument(name="notBefore", output_type=datetime.datetime, description="Start date of the CA's certificate validity."),
    OutputArgument(name="notAfter", output_type=datetime.datetime, description="End date of the CA's certificate validity."),
    OutputArgument(name="sha1Fingerprint", output_type=str, description="SHA1 fingerprint of the CA's certificate."),
    OutputArgument(name="sha256Fingerprint", output_type=str, description="SHA256 fingerprint of the CA's certificate."),
    OutputArgument(name="sha512Fingerprint", output_type=str, description="SHA512 fingerprint of the CA's certificate."),
    OutputArgument(name="purpose.client_authentication", output_type=str,
                   description="Indicates if client authentication is enabled for the CA."),
    OutputArgument(name="purpose.user_authentication", output_type=str,
                   description="Indicates if user authentication is enabled for the CA.")
]

LOCAL_CA_INSTALL_OUTPUT = [
    OutputArgument(name="id", output_type=str, description="A unique identifier for the certificate authority (CA)."),
    OutputArgument(name="uri", output_type=str, description="Uniform Resource Identifier associated with the CA."),
    OutputArgument(name="account", output_type=str, description="Account associated with the CA."),
    OutputArgument(name="application", output_type=str, description="Application associated with the CA."),
    OutputArgument(name="devAccount", output_type=str, description="Developer account associated with the CA."),
    OutputArgument(name="name", output_type=str, description="Name of the CA."),
    OutputArgument(name="state", output_type=str, description="Current state of the CA (e.g., active, pending)."),
    OutputArgument(name="createdAt", output_type=datetime.datetime, description="Timestamp of when the CA was created."),
    OutputArgument(name="updatedAt", output_type=datetime.datetime, description="Timestamp of the last update of the CA."),
    OutputArgument(name="cert", output_type=str, description="Certificate associated with the CA."),
    OutputArgument(name="serialNumber", output_type=str, description="Serial number of the CA's certificate."),
    OutputArgument(name="subject", output_type=str, description="Subject of the CA's certificate."),
    OutputArgument(name="issuer", output_type=str, description="Issuer of the CA's certificate."),
    OutputArgument(name="notBefore", output_type=datetime.datetime, description="Start date of the CA's certificate validity."),
    OutputArgument(name="notAfter", output_type=datetime.datetime, description="End date of the CA's certificate validity."),
    OutputArgument(name="sha1Fingerprint", output_type=str, description="SHA1 fingerprint of the CA's certificate."),
    OutputArgument(name="sha256Fingerprint", output_type=str, description="SHA256 fingerprint of the CA's certificate."),
    OutputArgument(name="sha512Fingerprint", output_type=str, description="SHA512 fingerprint of the CA's certificate."),
    OutputArgument(name="purpose.client_authentication", output_type=str, description="Indicates if client authentication is enabled for the CA."),
    OutputArgument(name="purpose.user_authentication", output_type=str, description="Indicates if user authentication is enabled for the CA.")
]


'''' YML METADATA END  '''

'''CLIENT CLASS'''


class CipherTrustClient(BaseClient):
    """ A client class to interact with the Thales CipherTrust API """

    def __init__(self, username: str, password: str, server_url: str, proxy: bool, verify: bool, api_version='v1'):
        base_url = urljoin(server_url, f'api/{api_version}')
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        res = self.create_auth_token(username, password)
        self._headers = {'Authorization': f'Bearer {res.get("jwt")}', 'accept': 'application/json'}

    def create_auth_token(self, username: str, password: str):
        return self._http_request(
            method='POST',
            url_suffix=AUTHENTICATION_URL_SUFFIX,
            json_data={
                'grant_type': 'password',
                'username': username,
                'password': password
            },
        )

    def get_group_list(self, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=USER_MANAGEMENT_GROUPS_URL_SUFFIX,
            params=params,
        )

    def create_group(self, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=USER_MANAGEMENT_GROUPS_URL_SUFFIX,
            json_data=request_data,
        )

    def delete_group(self, group_name: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix=urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, quote(group_name)),
            json_data=request_data,
            return_empty_response=True,
        )

    def update_group(self, group_name: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, quote(group_name)),
            json_data=request_data,
        )

    def add_user_to_group(self, group_name: str, user_id: str) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, quote(group_name))}/users/{user_id}',
        )

    def remove_user_from_group(self, group_name: str, user_id: str) -> dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix=f'{urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, quote(group_name))}/users/{user_id}',
            return_empty_response=True,
        )

    def get_users_list(self, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=USER_MANAGEMENT_USERS_URL_SUFFIX,
            params=params,
        )

    def get_user(self, user_id: str) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=urljoin(USER_MANAGEMENT_USERS_URL_SUFFIX, user_id),
        )

    def create_user(self, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=USER_MANAGEMENT_USERS_URL_SUFFIX,
            json_data=request_data,
        )

    def update_user(self, user_id: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(USER_MANAGEMENT_USERS_URL_SUFFIX, user_id),
            json_data=request_data,
        )

    def delete_user(self, user_id: str) -> dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(USER_MANAGEMENT_USERS_URL_SUFFIX, user_id),
            return_empty_response=True,
        )

    def change_current_user_password(self, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix=CHANGE_PASSWORD_URL_SUFFIX,
            json_data=request_data,
            return_empty_response=True,
        )

    def create_local_ca(self, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=LOCAL_CAS_URL_SUFFIX,
            json_data=request_data,
        )

    def get_local_ca_list(self, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=LOCAL_CAS_URL_SUFFIX,
            params=params,
        )

    def get_local_ca(self, local_ca_id: str, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id),
            params=params,
        )

    def update_local_ca(self, local_ca_id: str, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id),
            params=params,
        )

    def delete_local_ca(self, local_ca_id: str) -> dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix=urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id),
            return_empty_response=True,
        )

    def self_sign_local_ca(self, local_ca_id: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id)}/self-sign',
            json_data=request_data,
        )

    def install_local_ca(self, local_ca_id: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id)}/install',
            json_data=request_data,
        )

    def issue_certificate(self, ca_id: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs',
            json_data=request_data,
        )

    def get_certificates_list(self, ca_id: str, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs',
            params=params,
        )

    def delete_certificate(self, ca_id: str, local_ca_id: str) -> dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs/{local_ca_id}',
            return_empty_response=True,
        )

    def revoke_certificate(self, ca_id: str, cert_id: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs/{cert_id}/revoke',
            json_data=request_data,
            return_empty_response=True,
            empty_valid_codes=[200],
        )

    def resume_certificate(self, ca_id: str, cert_id: str) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs/{cert_id}/resume',
            return_empty_response=True,
            empty_valid_codes=[200],
        )

    def upload_external_certificate(self, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=EXTERNAL_CAS_URL_SUFFIX,
            json_data=request_data,
        )

    def delete_external_certificate(self, external_ca_id: str) -> dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix=urljoin(EXTERNAL_CAS_URL_SUFFIX, external_ca_id),
            return_empty_response=True,
        )

    def update_external_certificate(self, external_ca_id: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(EXTERNAL_CAS_URL_SUFFIX, external_ca_id),
            json_data=request_data,
        )

    def get_external_certificates_list(self, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=EXTERNAL_CAS_URL_SUFFIX,
            params=params,
        )


''' HELPER FUNCTIONS '''


def derive_skip_and_limit_for_pagination(limit: str, page: str | None, page_size: str | None):
    if page:
        page_size = arg_to_number(page_size) or DEFAULT_PAGE_SIZE
        if page_size > MAX_PAGE_SIZE:
            raise ValueError(f'Page size cannot exceed {MAX_PAGE_SIZE}')
        return (arg_to_number(page) - 1) * page_size, page_size
    return 0, arg_to_number(limit)


def optional_arg_to_bool(arg: str | None):
    return argToBoolean(arg) if arg is not None else arg


def optional_arg_to_datetime_string(arg: str | None, date_format: str = DATE_FORMAT):
    datetime_object = arg_to_datetime(arg)
    return datetime_object.strftime(date_format) if datetime_object is not None else datetime_object


def add_empty_date_param(request_data: dict, argument_value: str | None, param_name: str, empty_arg_value: str = "empty"):
    if argument_value is not None:
        request_data[param_name] = "" if argument_value == empty_arg_value else optional_arg_to_datetime_string(argument_value)


def add_empty_list_param(request_data: dict, argument_value: str | None, param_name: str, empty_arg_value: str = "empty"):
    if argument_value is not None:
        request_data[param_name] = [] if argument_value == empty_arg_value else argToList(argument_value)


def add_login_flags(request_data: dict, argument_value: str | None, flag_name: str):
    if argument_value is not None:
        if 'login_flags' not in request_data:
            request_data['login_flags'] = {}
        request_data['login_flags'][flag_name] = argument_value


def optional_safe_load_json(raw_json_string: str | None, json_entry_id: str | None):
    json_object = json_entry_id if json_entry_id else raw_json_string
    if json_object:
        return safe_load_json(json_object)
    return {}


def load_content_from_file(entry_id: str) -> str:
    try:
        path = demisto.getFilePath(entry_id)
        with open(path.get('path'), 'r') as file:
            return file.read()
    except Exception as e:
        raise ValueError(f'Failed to load the file {entry_id}: {str(e)}')



''' COMMAND FUNCTIONS '''


@metadata_collector.command(command_name='test_module')
def test_module(client: CipherTrustClient) -> str:
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``CipherTrustClient``
    :param client: CipherTrust client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    client.get_group_list(params={})
    return 'ok'


@metadata_collector.command(command_name='ciphertrust-group-list', outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
                            inputs_list=GROUP_LIST_INPUTS, outputs_list=GROUP_LIST_OUTPUT, description=GROUP_LIST_DESCRIPTION)
def group_list_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    skip, limit = derive_skip_and_limit_for_pagination(args.get(CommandArguments.LIMIT),
                                                       args.get(CommandArguments.PAGE),
                                                       args.get(CommandArguments.PAGE_SIZE))
    params = assign_params(
        skip=skip,
        limit=limit,
        name=args.get(CommandArguments.GROUP_NAME),
        users=args.get(CommandArguments.USER_ID),
        connection=args.get(CommandArguments.CONNECTION),
        clients=args.get(CommandArguments.CLIENT_ID)
    )
    raw_response = client.get_group_list(params=params)
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        readable_output=tableToMarkdown('group', raw_response.get('resources'))
    )


@metadata_collector.command(command_name='ciphertrust-group-create', inputs_list=GROUP_CREATE_INPUTS,
                            outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX, outputs_list=GROUP_CREATE_OUTPUT,
                            description=GROUP_CREATE_DESCRIPTION)
def group_create_command(client: CipherTrustClient, args: Dict[str, Any]) -> CommandResults:
    request_data = assign_params(name=args.get(CommandArguments.NAME),
                                 description=args.get(CommandArguments.DESCRIPTION))
    raw_response = client.create_group(request_data=request_data)
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-group-delete', inputs_list=GROUP_DELETE_INPUTS,
                            description=GROUP_DELETE_DESCRIPTION)
def group_delete_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(force=args.get(CommandArguments.FORCE))
    client.delete_group(group_name=args.get(CommandArguments.GROUP_NAME), request_data=request_data)
    return CommandResults(
        readable_output=f'{args.get(CommandArguments.GROUP_NAME)} has been deleted successfully!'
    )


@metadata_collector.command(command_name='ciphertrust-group-update', inputs_list=GROUP_UPDATE_INPUTS,
                            outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX, outputs_list=GROUP_UPDATE_OUTPUT,
                            description=GROUP_UPDATE_DESCRIPTION)
def group_update_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(description=args.get(CommandArguments.DESCRIPTION),
                                 name=args.get(CommandArguments.NEW_GROUP_NAME))
    raw_response = client.update_group(group_name=args.get(CommandArguments.GROUP_NAME), request_data=request_data)
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-user-to-group-add', inputs_list=USER_TO_GROUP_ADD_INPUTS,
                            outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX, outputs_list=USER_TO_GROUP_ADD_OUTPUT,
                            description=USER_TO_GROUP_ADD_DESCRIPTION)
def user_to_group_add_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    raw_response = client.add_user_to_group(group_name=args.get(CommandArguments.GROUP_NAME),
                                            user_id=args.get(CommandArguments.USER_ID))
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-user-to-group-remove', inputs_list=USER_TO_GROUP_REMOVE_INPUTS,
                            description=USER_TO_GROUP_REMOVE_DESCRIPTION)
def user_to_group_remove_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    client.remove_user_from_group(group_name=args.get(CommandArguments.GROUP_NAME), user_id=args.get(CommandArguments.USER_ID))
    return CommandResults(
        readable_output=f'{args.get(CommandArguments.USER_ID)} has been deleted successfully from {args.get(CommandArguments.GROUP_NAME)}'
    )


@metadata_collector.command(command_name='ciphertrust-users-list', inputs_list=USERS_LIST_INPUTS,
                            outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX, outputs_list=USERS_LIST_OUTPUT,
                            description=USERS_LIST_DESCRIPTION)
def users_list_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    if user_id := args.get(CommandArguments.USER_ID):
        raw_response = client.get_user(user_id=user_id)
        outputs = {'resources': [raw_response]}
    else:
        skip, limit = derive_skip_and_limit_for_pagination(args.get(CommandArguments.LIMIT),
                                                           args.get(CommandArguments.PAGE),
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
        outputs = raw_response
    return CommandResults(
        outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=tableToMarkdown(name='users list',
                                        t=raw_response.get('resources') if raw_response.get('resources') else raw_response),
    )


#todo - if resources is empty, return empty list?


@metadata_collector.command(command_name='ciphertrust-user-create', description=USER_CREATE_DESCRIPTION,
                            inputs_list=USER_CREATE_INPUTS, outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
                            outputs_list=USER_CREATE_OUTPUT)
def user_create_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        certificate_subject_dn=args.get(CommandArguments.CERTIFICATE_SUBJECT_DN),
        connection=args.get(CommandArguments.CONNECTION),
        email=args.get(CommandArguments.EMAIL),
        is_domain_user=optional_arg_to_bool(args.get(CommandArguments.IS_DOMAIN_USER)),
        name=args.get(CommandArguments.NAME),
        password=args.get(CommandArguments.PASSWORD),
        password_change_required=optional_arg_to_bool(args.get(CommandArguments.PASSWORD_CHANGE_REQUIRED)),
        password_policy=args.get(CommandArguments.PASSWORD_POLICY),
        user_id=args.get(CommandArguments.USER_ID),
        username=args.get(CommandArguments.USERNAME),
    )
    add_empty_date_param(request_data, args.get(CommandArguments.EXPIRES_AT), "expires_at")
    add_empty_list_param(request_data, args.get(CommandArguments.ALLOWED_AUTH_METHODS), "allowed_auth_methods")
    add_empty_list_param(request_data, args.get(CommandArguments.ALLOWED_CLIENT_TYPES), "allowed_client_types")
    add_login_flags(request_data, optional_arg_to_bool(args.get(CommandArguments.PREVENT_UI_LOGIN)), "prevent_ui_login")
    raw_response = client.create_user(request_data=request_data)
    return CommandResults(
        outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-user-update', description=USER_UPDATE_DESCRIPTION,
                            inputs_list=UPDATE_USER_INPUTS, outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
                            outputs_list=USER_UPDATE_OUTPUT)
def user_update_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        certificate_subject_dn=args.get(CommandArguments.CERTIFICATE_SUBJECT_DN),
        email=args.get(CommandArguments.EMAIL),
        failed_logins_count=arg_to_number(args.get(CommandArguments.FAILED_LOGINS_COUNT)),
        name=args.get(CommandArguments.NAME),
        password=args.get(CommandArguments.PASSWORD),
        password_change_required=optional_arg_to_bool(args.get(CommandArguments.PASSWORD_CHANGE_REQUIRED)),
        password_policy=args.get(CommandArguments.PASSWORD_POLICY),
        username=args.get(CommandArguments.USERNAME),
    )
    add_empty_date_param(request_data, args.get(CommandArguments.EXPIRES_AT), "expires_at")
    add_empty_list_param(request_data, args.get(CommandArguments.ALLOWED_AUTH_METHODS), "allowed_auth_methods")
    add_empty_list_param(request_data, args.get(CommandArguments.ALLOWED_CLIENT_TYPES), "allowed_client_types")
    add_login_flags(request_data, optional_arg_to_bool(args.get(CommandArguments.PREVENT_UI_LOGIN)), "prevent_ui_login")
    raw_response = client.update_user(user_id=args.get(CommandArguments.USER_ID), request_data=request_data)
    return CommandResults(
        outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-user-delete', description=USER_DELETE_DESCRIPTION,
                            inputs_list=USER_DELETE_INPUTS)
def user_delete_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    client.delete_user(args.get(CommandArguments.USER_ID))
    return CommandResults(
        readable_output=f'{args.get(CommandArguments.USER_ID)} has been deleted successfully!'
    )


@metadata_collector.command(command_name='ciphertrust-user-password-change', description=USER_PASSWORD_CHANGE_DESCRIPTION,
                            inputs_list=USER_PASSWORD_CHANGE_INPUTS)
def user_password_change_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        new_password=args.get(CommandArguments.NEW_PASSWORD),
        password=args.get(CommandArguments.PASSWORD),
        username=args.get(CommandArguments.USERNAME),
        auth_domain=args.get(CommandArguments.AUTH_DOMAIN)
    )
    client.change_current_user_password(request_data=request_data)
    return CommandResults(
        readable_output=f'Password has been changed successfully for {args.get(CommandArguments.USERNAME)}!'
    )


@metadata_collector.command(command_name='ciphertrust-local-ca-create', description=LOCAL_CA_CREATE_DESCRIPTION,
                            inputs_list=LOCAL_CA_CREATE_INPUTS, outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
                            outputs_list=LOCAL_CA_CREATE_OUTPUT)
def local_ca_create_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        cn=args.get(CommandArguments.CN),
        algorithm=args.get(CommandArguments.ALGORITHM),
        copy_from_ca=args.get(CommandArguments.COPY_FROM_CA),
        dnsNames=argToList(args.get(CommandArguments.DNS_NAMES)),
        emailAddresses=argToList(args.get(CommandArguments.EMAIL)),
        ipAddresses=argToList(args.get(CommandArguments.IP)),
        name=args.get(CommandArguments.NAME),
        names=optional_safe_load_json(args.get(CommandArguments.NAME_FIELDS_RAW_JSON),
                                      args.get(CommandArguments.NAME_FIELDS_JSON_ENTRY_ID)),
        size=arg_to_number(args.get(CommandArguments.SIZE)),
    )
    raw_response = client.create_local_ca(request_data=request_data)
    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-local-ca-list', inputs_list=LOCAL_CA_LIST_INPUTS,
                            outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX, description=LOCAL_CA_LIST_DESCRIPTION,
                            outputs_list=LOCAL_CA_LIST_OUTPUT)
def local_ca_list_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    if args.get(CommandArguments.CHAINED) is not None and args.get(CommandArguments.LOCAL_CA_ID) is None:
        raise ValueError('The "chained" argument can only be used with the "local_ca_id" argument.')
    if local_ca_id := args.get(CommandArguments.LOCAL_CA_ID):
        params = assign_params(
            chained=optional_arg_to_bool(args.get(CommandArguments.CHAINED)),
        )
        raw_response = client.get_local_ca(local_ca_id=local_ca_id, params=params)
        outputs = {'resources': [raw_response]}
    else:
        skip, limit = derive_skip_and_limit_for_pagination(args.get(CommandArguments.LIMIT),
                                                           args.get(CommandArguments.PAGE),
                                                           args.get(CommandArguments.PAGE_SIZE))
        params = assign_params(
            skip=skip,
            limit=limit,
            subject=args.get(CommandArguments.SUBJECT),
            issuer=args.get(CommandArguments.ISSUER),
            state=args.get(CommandArguments.STATE),
            cert=args.get(CommandArguments.CERT),
        )
        raw_response = client.get_local_ca_list(params=params)
        outputs = raw_response
    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        # todo: name?
        readable_output=tableToMarkdown('local CAs',
                                        raw_response.get('resources') if raw_response.get('resources') else raw_response),
    )


@metadata_collector.command(command_name='ciphertrust-local-ca-update', inputs_list=LOCAL_CA_UPDATE_INPUTS,
                            outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX, description=LOCAL_CA_UPDATE_DESCRIPTION,
                            outputs_list=LOCAL_CA_UPDATE_OUTPUTS)
def local_ca_update_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    params = assign_params(
        allow_client_authentication=optional_arg_to_bool(args.get(CommandArguments.ALLOW_CLIENT_AUTHENTICATION)),
        allow_user_authentication=optional_arg_to_bool(args.get(CommandArguments.ALLOW_USER_AUTHENTICATION))
    )
    raw_response = client.update_local_ca(local_ca_id=args.get(CommandArguments.LOCAL_CA_ID), params=params)
    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-local-ca-delete', inputs_list=LOCAL_CA_DELETE_INPUTS,
                            description=LOCAL_CA_DELETE_DESCRIPTION)
def local_ca_delete_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    client.delete_local_ca(local_ca_id=args.get(CommandArguments.LOCAL_CA_ID))
    return CommandResults(
        readable_output=f'{args.get(CommandArguments.LOCAL_CA_ID)} has been deleted successfully!'
    )


@metadata_collector.command(command_name='ciphertrust-local-ca-self-sign', inputs_list=LOCAL_CA_SELF_SIGN_INPUTS,
                            description=LOCAL_CA_SELF_SIGN_DESCRIPTION, outputs_prefix=CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX,
                            outputs_list=LOCAL_CA_SELF_SIGN_OUTPUT)
def local_ca_self_sign_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    if args.get(CommandArguments.NOT_AFTER) is None and args.get(CommandArguments.DURATION) is None:
        raise ValueError('Either the "not_after" or "duration" argument must be provided.')
    request_data = assign_params(
        duration=arg_to_number(args.get(CommandArguments.DURATION)),
        notAfter=optional_arg_to_datetime_string(args.get(CommandArguments.NOT_AFTER)),
        notBefore=optional_arg_to_datetime_string(args.get(CommandArguments.NOT_BEFORE)),
    )
    raw_response = client.self_sign_local_ca(local_ca_id=args.get(CommandArguments.LOCAL_CA_ID), request_data=request_data)
    return CommandResults(
        outputs_prefix=CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-local-ca-install', inputs_list=LOCAL_CA_INSTALL_INPUTS,
                            description=LOCAL_CA_INSTALL_DESCRIPTION, outputs_prefix=CA_INSTALL_CONTEXT_OUTPUT_PREFIX, outputs_list=LOCAL_CA_INSTALL_OUTPUT)
def local_ca_install_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    cert = load_content_from_file(args.get(CommandArguments.CERT_ENTRY_ID))
    request_data = assign_params(
        cert=cert,
        parent_id=args.get(CommandArguments.PARENT_ID),
    )
    raw_response = client.install_local_ca(local_ca_id=args.get(CommandArguments.LOCAL_CA_ID), request_data=request_data)
    return CommandResults(
        outputs_prefix=CA_INSTALL_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-certificate-issue', inputs_list=CERTIFICATE_ISSUE_INPUTS,
                            outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX, description=CERTIFICATE_ISSUE_DESCRIPTION)
def certificate_issue_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        csr=args.get(CommandArguments.CSR),
        purpose=args.get(CommandArguments.PURPOSE),
        duration=arg_to_number(args.get(CommandArguments.DURATION)),
        name=args.get(CommandArguments.NAME),
        notAfter=optional_arg_to_datetime_string(args.get(CommandArguments.NOT_AFTER)),
        notBefore=optional_arg_to_datetime_string(args.get(CommandArguments.NOT_BEFORE)),
    )
    raw_response = client.issue_certificate(ca_id=args.get(CommandArguments.CA_ID), request_data=request_data)
    return CommandResults(
        outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-certificate-list', inputs_list=CERTIFICATE_LIST_INPUTS,
                            description=CERTIFICATE_LIST_DESCRIPTION, outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX)
def certificate_list_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    skip, limit = derive_skip_and_limit_for_pagination(args.get(CommandArguments.LIMIT),
                                                       args.get(CommandArguments.PAGE),
                                                       args.get(CommandArguments.PAGE_SIZE))
    params = assign_params(
        skip=skip,
        limit=limit,
        subject=args.get(CommandArguments.SUBJECT),
        issuer=args.get(CommandArguments.ISSUER),
        cert=args.get(CommandArguments.CERT),
        id=args.get(CommandArguments.ID),
    )
    raw_response = client.get_certificates_list(ca_id=args.get(CommandArguments.CA_ID), params=params)
    return CommandResults(
        outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        #todo: name?
        readable_output=tableToMarkdown('certificates',
                                        raw_response.get('resources')),
    )


@metadata_collector.command(command_name='ciphertrust-local-certificate-delete', inputs_list=LOCAL_CERTIFICATE_DELETE_INPUTS,
                            description=CERTIFICATE_DELETE_DESCRIPTION)
def local_certificate_delete_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    client.delete_certificate(ca_id=args.get(CommandArguments.CA_ID), local_ca_id=args.get(CommandArguments.LOCAL_CA_ID))
    return CommandResults(
        readable_output=f'{args.get(CommandArguments.LOCAL_CA_ID)} has been deleted successfully!'
    )


@metadata_collector.command(command_name='ciphertrust-certificate-revoke', inputs_list=CERTIFICATE_REVOKE_INPUTS,
                            description=CERTIFICATE_REVOKE_DESCRIPTION)
def certificate_revoke_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        reason=args.get(CommandArguments.REASON),
    )
    client.revoke_certificate(ca_id=args.get(CommandArguments.CA_ID), cert_id=args.get(CommandArguments.CERT_ID),
                              request_data=request_data)
    return CommandResults(
        readable_output=f'{args.get(CommandArguments.CERT_ID)} has been revoked'
    )


@metadata_collector.command(command_name='ciphertrust-certificate-resume', inputs_list=CERTIFICATE_RESUME_INPUTS,
                            description=CERTIFICATE_RESUME_DESCRIPTION)
def certificate_resume_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    client.resume_certificate(ca_id=args.get(CommandArguments.CA_ID), cert_id=args.get(CommandArguments.CERT_ID))
    return CommandResults(
        readable_output=f'{args.get(CommandArguments.CERT_ID)} has been resumed'
    )


@metadata_collector.command(command_name='ciphertrust-external-certificate-upload',
                            inputs_list=EXTERNAL_CERTIFICATE_UPLOAD_INPUTS, description=EXTERNAL_CERTIFICATE_UPLOAD_DESCRIPTION,
                            outputs_prefix=EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX)
def external_certificate_upload_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        cert=args.get(CommandArguments.CERT),
        name=args.get(CommandArguments.NAME),
        parent=args.get(CommandArguments.PARENT),
    )
    raw_response = client.upload_external_certificate(request_data=request_data)
    return CommandResults(
        outputs_prefix=EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-external-certificate-delete',
                            inputs_list=EXTERNAL_CERTIFICATE_DELETE_INPUTS, description=EXTERNAL_CERTIFICATE_DELETE_DESCRIPTION)
def external_certificate_delete_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    client.delete_external_certificate(external_ca_id=args.get(CommandArguments.EXTERNAL_CA_ID))
    return CommandResults(
        readable_output=f'{args.get(CommandArguments.EXTERNAL_CA_ID)} has been deleted successfully!'
    )


@metadata_collector.command(command_name='ciphertrust-external-certificate-update',
                            inputs_list=EXTERNAL_CERTIFICATE_UPDATE_INPUTS, description=EXTERNAL_CERTIFICATE_UPDATE_DESCRIPTION,
                            outputs_prefix=EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX)
def external_certificate_update_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        allow_client_authentication=optional_arg_to_bool(args.get(CommandArguments.ALLOW_CLIENT_AUTHENTICATION)),
        allow_user_authentication=optional_arg_to_bool(args.get(CommandArguments.ALLOW_USER_AUTHENTICATION))
    )
    raw_response = client.update_external_certificate(external_ca_id=args.get(CommandArguments.EXTERNAL_CA_ID),
                                                      request_data=request_data)
    return CommandResults(
        outputs_prefix=EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-external-certificate-list', inputs_list=EXTERNAL_CERTIFICATE_LIST_INPUTS,
                            description=EXTERNAL_CERTIFICATE_LIST_DESCRIPTION,
                            outputs_prefix=EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX)
def external_certificate_list_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    skip, limit = derive_skip_and_limit_for_pagination(args.get(CommandArguments.LIMIT),
                                                       args.get(CommandArguments.PAGE),
                                                       args.get(CommandArguments.PAGE_SIZE))
    params = assign_params(
        skip=skip,
        limit=limit,
        subject=args.get(CommandArguments.SUBJECT),
        issuer=args.get(CommandArguments.ISSUER),
        serialNumber=args.get(CommandArguments.SERIAL_NUMBER),
        cert=args.get(CommandArguments.CERT),
    )

    raw_response = client.get_external_certificates_list(params=params)
    return CommandResults(
        outputs_prefix=EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        readable_output=tableToMarkdown('external certificates',
                                        raw_response.get('resources')),
    )


''' MAIN FUNCTION '''


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    server_url = params.get('server_url')

    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')

    verify = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    commands = {
        'ciphertrust-group-list': group_list_command,
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
            server_url=server_url,
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
