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
ISO_8601 = '%Y-%m-%dT%H:%M:%S.%fZ'

CONTEXT_OUTPUT_PREFIX = "CipherTrust."
GROUP_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Group"
USERS_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Users"
LOCAL_CA_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}LocalCA"
CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CASelfSign"
CA_INSTALL_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CAInstall"
CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CACertificate"
EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}ExternalCertificate"

BASE_URL_SUFFIX = '/api/v1'
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
    NAME_FIELDS = 'name_fields'
    SIZE = 'size'
    SUBJECT = 'subject'
    LOCAL_CA_ID = 'local_ca_id'
    CHAINED = 'chained'
    ISSUER = 'issuer'
    STATE = 'state'
    CERT = 'cert'
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

''' YML METADATA '''
PAGINATION_INPUTS = [InputArgument(name=CommandArguments.PAGE, description='page to return.'),
                     InputArgument(name=CommandArguments.PAGE_SIZE,
                                   description=f'number of entries per page. defaults to {MAX_PAGE_SIZE} in case only page was provided. max is {MAX_PAGE_SIZE}'),
                     InputArgument(name=CommandArguments.LIMIT,
                                   description='The max number of resources to return. defaults to 50',
                                   default=DEFAULT_LIMIT), ]
GROUPS_LIST_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, description='Group name to filter by.'),
                      InputArgument(name=CommandArguments.USER_ID,
                                    description='User id to filter by membership. “nil” will return groups with no members.'),
                      InputArgument(name=CommandArguments.CONNECTION,
                                    description='Connection id or name to filter by.'),
                      InputArgument(name=CommandArguments.CLIENT_ID,
                                    description='Client id to filter by membership. “nil” will return groups with no members.'),
                      ] + PAGINATION_INPUTS
GROUP_CREATE_INPUTS = [InputArgument(name=CommandArguments.NAME, required=True, description='Name of the group.'),
                       InputArgument(name=CommandArguments.DESCRIPTION, description='description of the group.'), ]
GROUP_DELETE_INPUTS = [InputArgument(name=CommandArguments.NAME, required=True, description='Name of the group'),
                       InputArgument(name=CommandArguments.FORCE,
                                     description='When set to true, groupmaps within this group will be deleted'), ]
GROUP_UPDATE_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, required=True, description='Name of the group.'),
                       InputArgument(name=CommandArguments.DESCRIPTION, description='description of the group.'), ]
USER_TO_GROUP_ADD_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, required=True,
                                          description='Name of the group.By default it will be added to the Key Users Group.'),
                            InputArgument(name=CommandArguments.USER_ID, required=True,
                                          description='User id. Can be retrieved by using the command ciphertrust-users-list'), ]
USER_TO_GROUP_REMOVE_INPUTS = [InputArgument(name=CommandArguments.GROUP_NAME, required=True,
                                             description='Name of the group.By default it will be added to the Key Users Group.'),
                               InputArgument(name=CommandArguments.USER_ID, required=True,
                                             description='User id. Can be retrieved by using the command ciphertrust-users-list'), ]
USERS_LIST_INPUTS = [InputArgument(name=CommandArguments.NAME, description='User’s name'),
                     InputArgument(name=CommandArguments.USER_ID,
                                   description='If provided, get the user with the specified id'),
                     InputArgument(name=CommandArguments.USERNAME, description='username'),
                     InputArgument(name=CommandArguments.EMAIL, description='User’s email'),
                     InputArgument(name=CommandArguments.GROUPS, is_array=True,
                                   description='Filter by users in the given group name. Provide multiple groups  to get users '
                                               'in all of those groups. Using nil as the group name will return users that are '
                                               'not part of any group.'),
                     InputArgument(name=CommandArguments.EXCLUDE_GROUPS, is_array=True,
                                   description='User associated with certain group will be excluded'),
                     InputArgument(name=CommandArguments.AUTH_DOMAIN_NAME, description='Filter by user’s auth domain'),
                     InputArgument(name=CommandArguments.ACCOUNT_EXPIRED,
                                   description='Filter the expired users (Boolean)'),
                     InputArgument(name=CommandArguments.ALLOWED_AUTH_METHODS, is_array=True,
                                   input_type=AllowedAuthMethods,
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
                     InputArgument(name=CommandArguments.ALLOWED_CLIENT_TYPES, is_array=True,
                                   input_type=AllowedClientTypes,
                                   description=""),
                     InputArgument(name=CommandArguments.PASSWORD_POLICY,
                                   description='Filter based on assigned password policy'),
                     InputArgument(name=CommandArguments.RETURN_GROUPS,
                                   description='If set to ‘true’ it will return the group’s name in which user is associated, Boolean'),
                     ] + PAGINATION_INPUTS
USER_CREATE_INPUTS = [InputArgument(name=CommandArguments.NAME, description='User’s name'),
                      InputArgument(name=CommandArguments.USER_ID),
                      InputArgument(name=CommandArguments.USERNAME),
                      InputArgument(name=CommandArguments.PASSWORD),
                      InputArgument(name=CommandArguments.EMAIL, description='Users email'),
                      InputArgument(name=CommandArguments.ALLOWED_AUTH_METHODS, is_array=True,
                                    input_type=AllowedAuthMethods,
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
                      InputArgument(name=CommandArguments.ALLOWED_CLIENT_TYPES, is_array=True,
                                    input_type=AllowedClientTypes,
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
                      InputArgument(name=CommandArguments.IS_DOMAIN_USER,
                                    description="This flag can be used to create the user "
                                                "in a non-root domain where user "
                                                "management is allowed."),
                      InputArgument(name=CommandArguments.PREVENT_UI_LOGIN, default='false',
                                    description='If true, user is not allowed to login from Web UI. '),
                      InputArgument(name=CommandArguments.PASSWORD_CHANGE_REQUIRED,
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
                      InputArgument(name=CommandArguments.ALLOWED_AUTH_METHODS, is_array=True,
                                    input_type=AllowedAuthMethods,
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
                      InputArgument(name=CommandArguments.ALLOWED_CLIENT_TYPES, is_array=True,
                                    input_type=AllowedClientTypes,
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
USER_DELETE_INPUTS = [InputArgument(name=CommandArguments.USER_ID, required=True), ]
USER_PASSWORD_CHANGE_INPUTS = [InputArgument(name=CommandArguments.NEW_PASSWORD, required=True),
                               InputArgument(name=CommandArguments.PASSWORD, required=True),
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
                                        description='Subject Alternative Names (SAN) values'),
                          InputArgument(name=CommandArguments.EMAIL, is_array=True, description='E-mail addresses'),
                          InputArgument(name=CommandArguments.IP, is_array=True, description='IP addresses'),
                          InputArgument(name=CommandArguments.NAME, default='localca-<id>',
                                        description='A unique name of CA, if not provided, will be set to localca-<id>.'),
                          InputArgument(name=CommandArguments.NAME_FIELDS, is_array=True,
                                        description='Name fields are "O=organization, OU=organizational unit, L=location, ST=state/province, C=country". Fields can be duplicated if present in different objects. O=organization, OU=organizational unit, L=location, ST=state/province, C=country'),
                          InputArgument(name=CommandArguments.SIZE,
                                        description='Key size. RSA: 1024 - 4096 (default: 2048), ECDSA: 256 (default), 384, 521'), ]

LOCAL_CA_LIST = [InputArgument(name=CommandArguments.SUBJECT, description='Filter by subject'),
                 InputArgument(name=CommandArguments.LOCAL_CA_ID, description='Filter by local CA ID'),
                 InputArgument(name=CommandArguments.CHAINED,
                               description='When set to ‘true’ the full CA chain is returned with the certificate'),
                 InputArgument(name=CommandArguments.ISSUER, description='Filter by issuer'),
                 InputArgument(name=CommandArguments.STATE, input_type=LocalCAState, description='Filter by state'),
                 InputArgument(name=CommandArguments.CERT, description='Filter by cert'),
                 ] + PAGINATION_INPUTS

LOCAL_CA_UPDATE_INPUTS = [
    InputArgument(name=CommandArguments.LOCAL_CA_ID, required=True, description='local CA ID'),
    InputArgument(name=CommandArguments.ALLOW_CLIENT_AUTHENTICATION,
                  description='If set to true, the certificates signed by the specified CA can be used '
                              'for client authentication.'),
    InputArgument(name=CommandArguments.ALLOW_USER_AUTHENTICATION,
                  description='If set to true, the certificates signed by the specified CA can be used '
                              'for user authentication.'),
]
LOCAL_CA_DELETE_INPUTS = [
    InputArgument(name=CommandArguments.LOCAL_CA_ID, required=True, description='local CA ID'),
]

LOCAL_CA_SELF_SIGN_INPUTS = [
    InputArgument(name=CommandArguments.LOCAL_CA_ID, required=True, description='local CA ID'),
    InputArgument(name=CommandArguments.DURATION,
                  description='Duration in days of certificate. Either duration or notAfter date must be specified.'),
    InputArgument(name=CommandArguments.NOT_AFTER,
                  description='End date of certificate. Either notAfter date or duration must be specified. notAfter overrides duration if both are given.'),
    InputArgument(name=CommandArguments.NOT_BEFORE, description='Start date of certificate. ISO 8601 format'),

]

LOCAL_CA_INSTALL_INPUTS = [InputArgument(name=CommandArguments.LOCAL_CA_ID, required=True, description='local CA ID'),
                           InputArgument(name=CommandArguments.CERT, required=True,
                                         description='Signed certificate in PEM format to install as a local CA'),
                           InputArgument(name=CommandArguments.PARENT_ID, required=True,
                                         description='An identifier of the parent resource. The resource can be either a local or an external CA. The identifier can be either the ID (a UUIDv4) or the URI.')]

CERTIFICATE_ISSUE_INPUTS = [
    InputArgument(name=CommandArguments.CA_ID, required=True, description='An identifier of the issuer CA resource'),
    InputArgument(name=CommandArguments.CSR, required=True, description='CSR in PEM format'),
    InputArgument(name=CommandArguments.PURPOSE, required=True, input_type=CACertificatePurpose,
                  description='Purpose of the certificate. Possible values: server, client or ca'),
    InputArgument(name=CommandArguments.DURATION,
                  description='Duration in days of certificate. Either duration or notAfter date must be specified.'),
    #todo: cert-<id> as default value elsewhere is a mistake, go through and fix
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
    InputArgument(name=CommandArguments.REASON, required=True, input_type=CertificateRevokeReason, description='Specify one of the reason. Reasons to revoke a certificate according to RFC 5280 '),
]

CERTIFICATE_RESUME_INPUTS = [
    InputArgument(name=CommandArguments.CA_ID, required=True, description='An identifier of the issuer CA resource'),
    InputArgument(name=CommandArguments.CERT_ID, required=True, description='The identifier of the certificate resource'),
]

EXTERNAL_CERTIFICATE_UPLOAD_INPUTS =[
    InputArgument(name=CommandArguments.CERT, required=True, description='External CA certificate in PEM format'),
    InputArgument(name=CommandArguments.NAME, description='A unique name of CA, if not provided, will be set to externalca-<id>.'),
    InputArgument(name=CommandArguments.PARENT, description='URI reference to a parent external CA certificate. This information can be used to build a certificate hierarchy.'),
]


EXTERNAL_CERTIFICATE_DELETE_INPUTS = [
    InputArgument(name=CommandArguments.EXTERNAL_CA_ID, required=True, description='The identifier of the certificate resource'),
]

''' OUTPUTS '''
''' DESCRIPTIONS '''
USER_UPDATE_DESCRIPTION = 'Change the properties of a user. For instance the name, the password, or metadata. Permissions would normally restrict this route to users with admin privileges. Non admin users wishing to change their own passwords should use the change password route. The user will not be able to change their password to the same password.'
USER_CREATE_DESCRIPTION = (
    'Create a new user in a domain(including root), or add an existing domain user to a sub-domain. Users '
    'are always created in the local, internal user database, but might have references to external '
    'identity providers.')
USER_DELETE_DESCRIPTION = "Deletes a user given the user's user-id. If the current user is logged into a sub-domain, the user is deleted from that sub-domain. If the current user is logged into the root domain, the user is deleted from all domains it belongs to."
USER_PASSWORD_CHANGE_DESCRIPTION = "Change the current user's password. Can only be used to change the password of the currently authenticated user. The user will not be able to change their password to the same password."
LOCAL_CA_CREATE_DESCRIPTION = "Creates a pending local CA. This operation returns a CSR that either can be self-signed by calling local-cas/{id}/self-sign or signed by another CA and installed by calling local-cas/{id}/install. A local CA keeps the corresponding private key inside the system and can issue certificates for clients, servers or intermediate CAs. The local CA can also be trusted by services inside the system for verification of client certificates."
LOCAL_CA_LIST_DESCRIPTION = "Returns a list of local CA certificates. The results can be filtered, using the query parameters."
LOCAL_CA_UPDATE_DESCRIPTION = "Update the properties of a local CA. For instance, the name, the password, or metadata. Permissions would normally restrict this route to users with admin privileges."
LOCAL_CA_DELETE_DESCRIPTION = "Deletes a local CA given the local CA's ID."
LOCAL_CA_SELF_SIGN_DESCRIPTION = "Self-sign a local CA certificate. This is used to create a root CA. Either duration or notAfter date must be specified. If both notAfter and duration are given, then notAfter date takes precedence over duration. If duration is given without notBefore date, certificate is issued starting from server's current time for the specified duration."
LOCAL_CA_INSTALL_DESCRIPTION = 'Installs a certificate signed by another CA to act as a local CA. Issuers can be both local or external CA. Typically used for intermediate CAs.The CA certificate must match the earlier created CA CSR, have "CA:TRUE" as part of the "X509v3 Basic Constraints", and have "Certificate Signing" as part of "X509v3 Key Usage" in order to be accepted.'
CERTIFICATE_ISSUE_DESCRIPTION = 'Issues a certificate by signing the provided CSR with the CA. This is typically used to issue server, client or intermediate CA certificates.'
CERTIFICATE_LIST_DESCRIPTION = 'Returns a list of certificates issued by the specified CA. The results can be filtered, using the query parameters.'
CERTIFICATE_DELETE_DESCRIPTION = 'Deletes a local certificate.'
CERTIFICATE_REVOKE_DESCRIPTION = 'Revoke certificate with a given specific reason.'
CERTIFICATE_RESUME_DESCRIPTION = 'Certificate can be resumed only if it is revoked with reason certificatehold.'
EXTERNAL_CERTIFICATE_UPLOAD_DESCRIPTION = 'Uploads an external CA certificate. These certificates can later be trusted by services inside the system for verification of client certificates. The uploaded certificate must have "CA:TRUE" as part of the "X509v3 Basic Constraints" to be accepted.'
EXTERNAL_CERTIFICATE_DELETE_DESCRIPTION = 'Deletes an external CA certificate.'

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

    def delete_user(self, user_id: str):
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(USER_MANAGEMENT_USERS_URL_SUFFIX, user_id),
            return_empty_response=True,
        )

    def change_current_user_password(self, request_data: dict):
        return self._http_request(
            method='PATCH',
            url_suffix=CHANGE_PASSWORD_URL_SUFFIX,
            json_data=request_data,
            return_empty_response=True,
        )

    def create_local_ca(self, request_data: dict):
        return self._http_request(
            method='POST',
            url_suffix=LOCAL_CAS_URL_SUFFIX,
            json_data=request_data,
            return_empty_response=True,
            empty_valid_codes=[201],
        )

    def get_local_ca_list(self, params: dict):
        return self._http_request(
            method='GET',
            url_suffix=LOCAL_CAS_URL_SUFFIX,
            params=params,
        )

    def get_local_ca(self, local_ca_id: str, params: dict):
        return self._http_request(
            method='GET',
            url_suffix=urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id),
            params=params,
        )

    def update_local_ca(self, local_ca_id: str, request_data: dict):
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id),
            json_data=request_data,
        )

    def delete_local_ca(self, local_ca_id: str):
        return self._http_request(
            method='DELETE',
            url_suffix=urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id),
            return_empty_response=True,
        )

    def self_sign_local_ca(self, local_ca_id: str, request_data: dict):
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id)}/self-sign',
            json_data=request_data,
            return_empty_response=True,
            empty_valid_codes=[201],
        )

    def install_local_ca(self, local_ca_id: str, request_data: dict):
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id)}/install',
            json_data=request_data,
            return_empty_response=True,
            empty_valid_codes=[201],
        )

    def issue_certificate(self, ca_id: str, request_data: dict):
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs',
            json_data=request_data,
            return_empty_response=True,
            empty_valid_codes=[201],
        )

    def get_certificates_list(self, ca_id: str, params: dict):
        return self._http_request(
            method='GET',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs',
            params=params,
        )

    def delete_certificate(self, ca_id: str, local_ca_id: str):
        return self._http_request(
            method='DELETE',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs/{local_ca_id}',
            return_empty_response=True,
        )

    def revoke_certificate(self, ca_id: str, cert_id: str, request_data: dict):
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs/{cert_id}/revoke',
            json_data=request_data,
            return_empty_response=True,
            empty_valid_codes=[200],
        )

    def resume_certificate(self, ca_id: str, cert_id: str):
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs/{cert_id}/resume',
            return_empty_response=True,
            empty_valid_codes=[200],
        )

    def upload_external_certificate(self, request_data: dict):
        return self._http_request(
            method='POST',
            url_suffix=EXTERNAL_CAS_URL_SUFFIX,
            json_data=request_data,
            return_empty_response=True,
            empty_valid_codes=[201],
        )

    def delete_external_certificate(self, external_ca_id: str):
        return self._http_request(
            method='DELETE',
            url_suffix=urljoin(EXTERNAL_CAS_URL_SUFFIX, external_ca_id),
            return_empty_response=True,
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


def optional_arg_to_datetime_string(arg, date_format=ISO_8601):
    datetime_object = arg_to_datetime(arg)
    return datetime_object.strftime(date_format) if datetime_object is not None else datetime_object


def add_expires_at_param(request_data: dict, expires_at_arg: str):
    if expires_at_arg == "":
        request_data['expires_at'] = expires_at_arg
    else:
        request_data['expires_at'] = optional_arg_to_datetime_string(expires_at_arg)


def parse_name_fields_string_to_list(name_fields: str):
    if name_fields:
        return [json.loads(f'{{{name_fields}}}')]


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
    client.get_groups_list(params={})
    return 'ok'


@metadata_collector.command(command_name='ciphertrust-groups-list', outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
                            inputs_list=GROUPS_LIST_INPUTS)
def groups_list_command(client: CipherTrustClient, args: dict) -> CommandResults:
    """
    """
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
    raw_response = client.get_groups_list(params=params)
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        readable_output=tableToMarkdown('groups', raw_response.get('resources'))
    )


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


@metadata_collector.command(command_name='ciphertrust-group-delete', inputs_list=GROUP_DELETE_INPUTS)
def group_delete_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(force=args.get(CommandArguments.FORCE))
    client.delete_group(group_name=args[CommandArguments.GROUP_NAME], request_data=request_data)
    return CommandResults(
        readable_output=f'{args.get(CommandArguments.GROUP_NAME)} has been deleted successfully!'
    )


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


@metadata_collector.command(command_name='ciphertrust-user-to-group-add', inputs_list=USER_TO_GROUP_ADD_INPUTS,
                            outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX)
def user_to_group_add_command(client: CipherTrustClient, args: dict):
    raw_response = client.add_user_to_group(group_name=args[CommandArguments.GROUP_NAME],
                                            user_id=args[CommandArguments.USER_ID])
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-user-to-group-remove', inputs_list=USER_TO_GROUP_REMOVE_INPUTS)
def user_to_group_remove_command(client: CipherTrustClient, args: dict):
    client.remove_user_from_group(group_name=args[CommandArguments.GROUP_NAME], user_id=args[CommandArguments.USER_ID])
    return CommandResults(
        readable_output=f'{args[CommandArguments.USER_ID]} has been deleted successfully from {args[CommandArguments.GROUP_NAME]}'
    )


@metadata_collector.command(command_name='ciphertrust-users-list', inputs_list=USERS_LIST_INPUTS,
                            outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX)
def users_list_command(client: CipherTrustClient, args: dict):
    if user_id := args.get(CommandArguments.USER_ID):
        raw_response = client.get_user(user_id=user_id)
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
    return CommandResults(
        outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        readable_output=tableToMarkdown(name='users list',
                                        t=raw_response.get('resources') if raw_response.get('resources') else raw_response),
    )


@metadata_collector.command(command_name='ciphertrust-user-create', description=USER_CREATE_DESCRIPTION,
                            inputs_list=USER_CREATE_INPUTS, outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX)
def user_create_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(
        allowed_auth_methods=argToList(args.get(CommandArguments.ALLOWED_AUTH_METHODS)),
        allowed_client_types=argToList(args.get(CommandArguments.ALLOWED_CLIENT_TYPES)),
        certificate_subject_dn=args.get(CommandArguments.CERTIFICATE_SUBJECT_DN),
        connection=args.get(CommandArguments.CONNECTION),
        email=args.get(CommandArguments.EMAIL),
        is_domain_user=optional_arg_to_bool(args.get(CommandArguments.IS_DOMAIN_USER)),
        login_flags={"prevent_ui_login": optional_arg_to_bool(args.get(CommandArguments.PREVENT_UI_LOGIN))},
        name=args.get(CommandArguments.NAME),
        password=args.get(CommandArguments.PASSWORD),
        password_change_required=optional_arg_to_bool(args.get(CommandArguments.PASSWORD_CHANGE_REQUIRED)),
        password_policy=args.get(CommandArguments.PASSWORD_POLICY),
        user_id=args.get(CommandArguments.USER_ID),
        username=args.get(CommandArguments.USERNAME),
    )
    add_expires_at_param(request_data, args.get(CommandArguments.EXPIRES_AT))
    raw_response = client.create_user(request_data=request_data)
    return CommandResults(
        outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-user-update', description=USER_UPDATE_DESCRIPTION,
                            inputs_list=UPDATE_USER_INPUTS, outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX)
def user_update_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(
        allowed_auth_methods=argToList(args.get(CommandArguments.ALLOWED_AUTH_METHODS)),
        allowed_client_types=argToList(args.get(CommandArguments.ALLOWED_CLIENT_TYPES)),
        certificate_subject_dn=args.get(CommandArguments.CERTIFICATE_SUBJECT_DN),
        email=args.get(CommandArguments.EMAIL),
        failed_logins_count=arg_to_number(args.get(CommandArguments.FAILED_LOGINS_COUNT)),
        login_flags={"prevent_ui_login": optional_arg_to_bool(args.get(CommandArguments.PREVENT_UI_LOGIN))},
        name=args.get(CommandArguments.NAME),
        password=args.get(CommandArguments.PASSWORD),
        password_change_required=optional_arg_to_bool(args.get(CommandArguments.PASSWORD_CHANGE_REQUIRED)),
        password_policy=args.get(CommandArguments.PASSWORD_POLICY),
        username=args.get(CommandArguments.USERNAME),
    )
    add_expires_at_param(request_data, args.get(CommandArguments.EXPIRES_AT))
    raw_response = client.update_user(user_id=args[CommandArguments.USER_ID], request_data=request_data)
    return CommandResults(
        outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-user-delete', description=USER_DELETE_DESCRIPTION,
                            inputs_list=USER_DELETE_INPUTS)
def user_delete_command(client: CipherTrustClient, args: dict):
    client.delete_user(args[CommandArguments.USER_ID])
    return CommandResults(
        readable_output=f'{args[CommandArguments.USER_ID]} has been deleted successfully!'
    )


@metadata_collector.command(command_name='ciphertrust-user-password-change', description=USER_PASSWORD_CHANGE_DESCRIPTION,
                            inputs_list=USER_PASSWORD_CHANGE_INPUTS)
def user_password_change_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(
        new_password=args[CommandArguments.NEW_PASSWORD],
        password=args[CommandArguments.PASSWORD],
        username=args[CommandArguments.USERNAME],
        auth_domain=args.get(CommandArguments.AUTH_DOMAIN)
    )
    client.change_current_user_password(request_data=request_data)
    return CommandResults(
        readable_output=f'Password has been changed successfully for {args[CommandArguments.USERNAME]}!'
    )


#todo: response 201, will be in header?
@metadata_collector.command(command_name='ciphertrust-local-ca-create', description=LOCAL_CA_CREATE_DESCRIPTION,
                            inputs_list=LOCAL_CA_CREATE_INPUTS, outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX)
def local_ca_create_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(
        cn=args[CommandArguments.CN],
        algorithm=args.get(CommandArguments.ALGORITHM),
        copy_from_ca=args.get(CommandArguments.COPY_FROM_CA),
        dnsNames=argToList(args.get(CommandArguments.DNS_NAMES)),
        emailAddresses=argToList(args.get(CommandArguments.EMAIL)),
        ipAddresses=argToList(args.get(CommandArguments.IP)),
        name=args.get(CommandArguments.NAME),
        names=argToList(args.get(CommandArguments.NAME_FIELDS)),  #todo: name fields formatting
        size=arg_to_number(args.get(CommandArguments.SIZE)),
    )
    raw_response = client.create_local_ca(request_data=request_data)
    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-local-ca-list', inputs_list=LOCAL_CA_LIST,
                            outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX, description=LOCAL_CA_LIST_DESCRIPTION)
def local_ca_list_command(client: CipherTrustClient, args: dict):
    if local_ca_id := args.get(CommandArguments.LOCAL_CA_ID):
        params = assign_params(
            #todo: test chained - how does it look like?
            chained=optional_arg_to_bool(args.get(CommandArguments.CHAINED)),
        )
        raw_response = client.get_local_ca(local_ca_id=local_ca_id, params=params)
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
    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        # todo: name?
        readable_output=tableToMarkdown('local CAs',
                                        raw_response.get('resources') if raw_response.get('resources') else raw_response),
    )


@metadata_collector.command(command_name='ciphertrust-local-ca-update', inputs_list=LOCAL_CA_UPDATE_INPUTS,
                            outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX)
def local_ca_update_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(
        allow_client_authentication=optional_arg_to_bool(args.get(CommandArguments.ALLOW_CLIENT_AUTHENTICATION)),
        allow_user_authentication=optional_arg_to_bool(args.get(CommandArguments.ALLOW_USER_AUTHENTICATION))
    )
    raw_response = client.update_local_ca(local_ca_id=args[CommandArguments.LOCAL_CA_ID], request_data=request_data)
    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-local-ca-delete', inputs_list=LOCAL_CA_DELETE_INPUTS,
                            description=LOCAL_CA_DELETE_DESCRIPTION)
def local_ca_delete_command(client: CipherTrustClient, args: dict):
    client.delete_local_ca(local_ca_id=args[CommandArguments.LOCAL_CA_ID])
    return CommandResults(
        readable_output=f'{args[CommandArguments.LOCAL_CA_ID]} has been deleted successfully!'
    )


@metadata_collector.command(command_name='ciphertrust-local-ca-self-sign', inputs_list=LOCAL_CA_SELF_SIGN_INPUTS,
                            description=LOCAL_CA_SELF_SIGN_DESCRIPTION, outputs_prefix=CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX)
def local_ca_self_sign_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(
        duration=arg_to_number(args.get(CommandArguments.DURATION)),
        notAfter=optional_arg_to_datetime_string(args.get(CommandArguments.NOT_AFTER)),
        notBefore=optional_arg_to_datetime_string(args.get(CommandArguments.NOT_BEFORE)),
    )
    raw_response = client.self_sign_local_ca(local_ca_id=args[CommandArguments.LOCAL_CA_ID], request_data=request_data)
    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


#todo: figure out how to properly test + what does install exactly mean
@metadata_collector.command(command_name='ciphertrust-local-ca-install', inputs_list=LOCAL_CA_INSTALL_INPUTS,
                            description=LOCAL_CA_INSTALL_DESCRIPTION, outputs_prefix=CA_INSTALL_CONTEXT_OUTPUT_PREFIX)
def local_ca_install_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(
        cert=args[CommandArguments.CERT],
        parent_id=args[CommandArguments.PARENT_ID],
    )
    raw_response = client.install_local_ca(local_ca_id=args[CommandArguments.LOCAL_CA_ID], request_data=request_data)
    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-certificate-issue', inputs_list=CERTIFICATE_ISSUE_INPUTS,
                            outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX, description=CERTIFICATE_ISSUE_DESCRIPTION)
def certificate_issue_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(
        csr=args[CommandArguments.CSR],
        purpose=args[CommandArguments.PURPOSE],
        duration=arg_to_number(args.get(CommandArguments.DURATION)),
        name=args.get(CommandArguments.NAME),
        notAfter=optional_arg_to_datetime_string(args.get(CommandArguments.NOT_AFTER)),
        notBefore=optional_arg_to_datetime_string(args.get(CommandArguments.NOT_BEFORE)),
    )
    raw_response = client.issue_certificate(ca_id=args[CommandArguments.CA_ID], request_data=request_data)
    return CommandResults(
        outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-certificate-list', inputs_list=CERTIFICATE_LIST_INPUTS, description=CERTIFICATE_LIST_DESCRIPTION, outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX)
def certificate_list_command(client: CipherTrustClient, args: dict):
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
    raw_response = client.get_certificates_list(ca_id=args[CommandArguments.CA_ID], params=params)
    return CommandResults(
        outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        #todo: name?
        readable_output=tableToMarkdown('certificates',
                                        raw_response.get('resources')),
    )


@metadata_collector.command(command_name='ciphertrust-local-certificate-delete', inputs_list=LOCAL_CERTIFICATE_DELETE_INPUTS, description=CERTIFICATE_DELETE_DESCRIPTION)
def local_certificate_delete_command(client: CipherTrustClient, args: dict):
    client.delete_certificate(ca_id=args[CommandArguments.CA_ID], local_ca_id=args[CommandArguments.LOCAL_CA_ID])
    return CommandResults(
        readable_output=f'{args[CommandArguments.LOCAL_CA_ID]} has been deleted successfully!'
    )


@metadata_collector.command(command_name='ciphertrust-certificate-revoke', inputs_list=CERTIFICATE_REVOKE_INPUTS, description=CERTIFICATE_REVOKE_DESCRIPTION)
def certificate_revoke_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(
        reason=args[CommandArguments.REASON],
    )
    client.revoke_certificate(ca_id=args[CommandArguments.CA_ID], cert_id=args[CommandArguments.CERT_ID],
                              request_data=request_data)
    return CommandResults(
        readable_output=f'{args[CommandArguments.CERT_ID]} has been revoked'
    )


@metadata_collector.command(command_name='ciphertrust-certificate-resume', inputs_list=CERTIFICATE_RESUME_INPUTS, description=CERTIFICATE_RESUME_DESCRIPTION)
def certificate_resume_command(client: CipherTrustClient, args: dict):
    client.resume_certificate(ca_id=args[CommandArguments.CA_ID], cert_id=args[CommandArguments.CERT_ID])
    return CommandResults(
        readable_output=f'{args[CommandArguments.CERT_ID]} has been resumed'
    )


@metadata_collector.command(command_name='ciphertrust-external-certificate-upload', inputs_list=EXTERNAL_CERTIFICATE_UPLOAD_INPUTS, description=EXTERNAL_CERTIFICATE_UPLOAD_DESCRIPTION, outputs_prefix=EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX)
def external_certificate_upload_command(client: CipherTrustClient, args: dict):
    request_data = assign_params(
        cert=args[CommandArguments.CERT],
        name=args.get(CommandArguments.NAME),
        parent=args.get(CommandArguments.PARENT),
    )
    raw_response = client.upload_external_certificate(request_data=request_data)
    return CommandResults(
        outputs_prefix=EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


@metadata_collector.command(command_name='ciphertrust-external-certificate-delete', inputs_list=EXTERNAL_CERTIFICATE_DELETE_INPUTS, description=EXTERNAL_CERTIFICATE_DELETE_DESCRIPTION)
def external_certificate_delete_command(client: CipherTrustClient, args: dict):
    client.delete_external_certificate(external_ca_id=args[CommandArguments.EXTERNAL_CA_ID])
    return CommandResults(
        readable_output=f'{args[CommandArguments.EXTERNAL_CA_ID]} has been deleted successfully!'
    )


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
