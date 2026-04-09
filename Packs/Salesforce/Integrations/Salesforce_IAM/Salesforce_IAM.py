import demistomock as demisto
import urllib3
from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()


DEFAULT_OUTGOING_MAPPER = "User Profile - Salesforce (Outgoing)"
DEFAULT_INCOMING_MAPPER = "User Profile - Salesforce (Incoming)"
URI_PREFIX = "/services/data/v44.0/"
GENERATE_TOKEN_URL = "https://login.salesforce.com/services/oauth2/token"

# setting defaults for mandatory fields
DEFAULT_FIELDS = ["localesidkey", "emailencodingkey", "languagelocalekey"]


class Client(BaseClient):
    """Salesforce IAM API client.

    Auth handling:
    - UCP mode: BaseClient injects BE-managed OAuth2 token per-request
      via _apply_ucp_credentials. No token exchange needed.
    - Legacy mode: Client performs OAuth2 password grant at init
      via setup_legacy_auth().
    """

    def __init__(self, demisto_params, base_url, ok_codes,
                 verify=True, proxy=False):
        super().__init__(
            base_url,
            verify=verify,
            proxy=proxy,
            ok_codes=ok_codes,
            headers={'Content-Type': 'application/json'},
        )
        self.demisto_params = demisto_params

    def setup_legacy_auth(self):
        """Extract credentials from params and perform OAuth2 password grant token exchange.

        In UCP mode, this method is never called — the BE provides
        a ready-to-use access token via demisto.getUCPCredentials().
        """
        demisto.debug("Salesforce IAM: setup_legacy_auth: ENTRY — extracting credentials from demisto_params")
        username = self.demisto_params.get("credentials", {}).get("identifier")
        password = self.demisto_params.get("credentials", {}).get("password")
        client_id = (
            self.demisto_params.get("credentials_consumer", {}).get("identifier")
            or self.demisto_params.get("consumer_key")
        )
        client_secret = (
            self.demisto_params.get("credentials_consumer", {}).get("password")
            or self.demisto_params.get("consumer_secret")
        )
        demisto.debug(
            "Salesforce IAM: setup_legacy_auth: Extracted credentials. "
            "username={}, has_password={}, client_id={}, has_client_secret={}".format(
                username, bool(password), client_id, bool(client_secret)
            )
        )
        if not (client_id and client_secret):
            demisto.debug("Salesforce IAM: setup_legacy_auth: MISSING consumer credentials — raising error")
            raise DemistoException(
                "Consumer Key and Consumer Secret must be provided."
            )

        demisto.debug(
            "Salesforce IAM: setup_legacy_auth: Performing OAuth2 password grant. "
            "token_url={}, username={}, client_id={}".format(
                GENERATE_TOKEN_URL, username, client_id
            )
        )

        token_params = {
            "client_id": client_id,
            "client_secret": client_secret,
            "username": username,
            "password": password,
            "grant_type": "password",
        }
        res = self._http_request(
            method="POST", full_url=GENERATE_TOKEN_URL, params=token_params
        )
        demisto.debug(
            "Salesforce IAM: setup_legacy_auth: Token response received. "
            "response_keys={}, has_access_token={}, token_type={}".format(
                list(res.keys()) if isinstance(res, dict) else type(res).__name__,
                bool(res.get("access_token")) if isinstance(res, dict) else "N/A",
                res.get("token_type", "N/A") if isinstance(res, dict) else "N/A",
            )
        )
        access_token = res.get("access_token", "")
        token_preview = access_token[:10] + "..." if access_token else "<empty>"
        demisto.debug(
            "Salesforce IAM: setup_legacy_auth: Setting Authorization header. "
            "token_preview={}".format(token_preview)
        )
        self._headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(access_token),
        }
        demisto.debug("Salesforce IAM: setup_legacy_auth: COMPLETE — headers set successfully")

    def get_user(self, user_term):
        uri = URI_PREFIX + "sobjects/User/{}".format(user_term)
        return self._http_request(method="GET", url_suffix=uri)

    def search_user_profile(self, user_term, user_where):
        uri = URI_PREFIX + "parameterizedSearch/"
        params = {
            "q": user_term,
            "sobject": "User",
            "User.where": user_where,
            "User.fields": "Id, IsActive, FirstName, LastName, Email, Username",
        }
        return self._http_request(method="GET", url_suffix=uri, params=params)

    def get_user_id_and_activity_by_mail(self, email):
        user_id = ""
        active = ""
        user_where = "Email='{}'".format(email)
        res = self.search_user_profile(email, user_where)

        search_records = res.get("searchRecords")
        if len(search_records) > 0:
            for search_record in search_records:
                user_id = search_record.get("Id")
                active = search_record.get("IsActive") == "true"

        return user_id, active

    def create_user(self, data):
        uri = URI_PREFIX + "sobjects/User"
        return self._http_request(method="POST", url_suffix=uri, json_data=data)

    def update_user(self, user_term, data):
        uri = URI_PREFIX + "sobjects/User/{}".format(user_term)
        params = {"_HttpMethod": "PATCH"}
        return self._http_request(
            method="POST", url_suffix=uri, params=params,
            json_data=data, resp_type="text",
        )

    def get_all_users(self):
        uri = URI_PREFIX + "parameterizedSearch/"
        params = {
            "q": "User",
            "sobject": "User",
        }
        return self._http_request(method="GET", url_suffix=uri, params=params)


def handle_exception(e):
    if e.__class__ is DemistoException and hasattr(e, "res") and e.res is not None:
        error_code = e.res.status_code
        error_message = e.res.text
    else:
        error_code = ""
        error_message = str(e)

    demisto.error(traceback.format_exc())
    return error_message, error_code


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: SalesforceITAdmin client
        args  : SalesforceITAdmin arguments passed

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    demisto.info("Testing connection to Salesforce IAM with provided parameters.")
    client.get_user_id_and_activity_by_mail("test@test.com")
    return "ok"


def get_user_command(client, args, mapper_in, mapper_out):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(
            user_profile=user_profile, mapper=mapper_out, incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE
        )

        email = iam_user_profile.get_attribute("email")
        user_id, _ = client.get_user_id_and_activity_by_mail(email)

        if not user_id:
            error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
            iam_user_profile.set_result(
                success=False, error_message=error_message, error_code=error_code, action=IAMActions.GET_USER
            )
        else:
            github_user = client.get_user(user_id)
            iam_user_profile.update_with_app_data(github_user, mapper_in)

            iam_user_profile.set_result(
                success=True,
                iden=github_user.get("Id"),
                email=github_user.get("Email"),
                username=github_user.get("Username"),
                action=IAMActions.GET_USER,
                details=github_user,
                active=github_user.get("IsActive") == "true",
            )

        return iam_user_profile

    except Exception as e:
        message, code = handle_exception(e)
        iam_user_profile.set_result(success=False, error_message=message, error_code=code, action=IAMActions.GET_USER)
        return iam_user_profile


def create_user_command(client, args, mapper_out, is_create_enabled, is_update_enabled, is_enable_enabled):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(
            user_profile=user_profile, mapper=mapper_out, incident_type=IAMUserProfile.CREATE_INCIDENT_TYPE
        )

        if not is_create_enabled:
            iam_user_profile.set_result(action=IAMActions.CREATE_USER, skip=True, skip_reason="Command is disabled.")

        else:
            email = iam_user_profile.get_attribute("email")
            user_id, _ = client.get_user_id_and_activity_by_mail(email)

            if user_id:
                create_if_not_exists = False
                iam_user_profile = update_user_command(
                    client, args, mapper_out, is_update_enabled, is_enable_enabled, is_create_enabled, create_if_not_exists
                )

            else:
                salesforce_user = iam_user_profile.map_object(
                    mapper_name=mapper_out, incident_type=IAMUserProfile.CREATE_INCIDENT_TYPE
                )
                salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}
                salesforce_user = check_and_set_manndatory_fields(salesforce_user, client.demisto_params)
                res = client.create_user(salesforce_user)
                iam_user_profile.set_result(
                    success=True,
                    iden=res.get("id"),
                    email=salesforce_user.get("email"),
                    username=salesforce_user.get("userName"),
                    action=IAMActions.CREATE_USER,
                    details=res,
                    active=True,
                )

        return iam_user_profile

    except Exception as e:
        message, code = handle_exception(e)
        iam_user_profile.set_result(success=False, error_message=message, error_code=code, action=IAMActions.CREATE_USER)
        return iam_user_profile


def update_user_command(
    client, args, mapper_out, is_command_enabled, is_enable_enabled, is_create_user_enabled, create_if_not_exists
):
    try:
        iam_user_profile = IAMUserProfile(
            user_profile=args.get("user-profile"), mapper=mapper_out, incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE
        )
        allow_enable = args.get("allow-enable") == "true"

        if not is_command_enabled:
            iam_user_profile.set_result(action=IAMActions.UPDATE_USER, skip=True, skip_reason="Command is disabled.")
        else:
            email = iam_user_profile.get_attribute("email")
            user_id, active = client.get_user_id_and_activity_by_mail(email)

            if not user_id:
                if create_if_not_exists:
                    iam_user_profile = create_user_command(client, args, mapper_out, is_create_user_enabled, False, False)
                else:
                    error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
                    iam_user_profile.set_result(
                        action=IAMActions.UPDATE_USER, error_code=error_code, skip=True, skip_reason=error_message
                    )
            else:
                salesforce_user = iam_user_profile.map_object(
                    mapper_name=mapper_out, incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE
                )
                salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}
                if allow_enable and is_enable_enabled:
                    salesforce_user["IsActive"] = True

                res = client.update_user(user_term=user_id, data=salesforce_user)

                iam_user_profile.set_result(success=True, iden=user_id, active=True, action=IAMActions.UPDATE_USER, details=res)

        return iam_user_profile

    except Exception as e:
        message, code = handle_exception(e)
        iam_user_profile.set_result(success=False, error_message=message, error_code=code, action=IAMActions.UPDATE_USER)
        return iam_user_profile


def disable_user_command(client, args, mapper_out, is_command_enabled):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(
            user_profile=user_profile, mapper=mapper_out, incident_type=IAMUserProfile.DISABLE_INCIDENT_TYPE
        )

        if not is_command_enabled:
            iam_user_profile.set_result(action=IAMActions.DISABLE_USER, skip=True, skip_reason="Command is disabled.")

        else:
            email = iam_user_profile.get_attribute("email")
            user_id, _ = client.get_user_id_and_activity_by_mail(email)

            if not user_id:
                error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
                iam_user_profile.set_result(
                    action=IAMActions.DISABLE_USER, error_code=error_code, skip=True, skip_reason=error_message
                )
            else:
                salesforce_user = iam_user_profile.map_object(
                    mapper_name=mapper_out, incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE
                )
                salesforce_user["IsActive"] = False
                salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}
                res = client.update_user(user_term=user_id, data=salesforce_user)

                iam_user_profile.set_result(success=True, iden=user_id, active=False, action=IAMActions.DISABLE_USER, details=res)

        return iam_user_profile

    except Exception as e:
        message, code = handle_exception(e)
        iam_user_profile.set_result(success=False, error_message=message, error_code=code, action=IAMActions.DISABLE_USER)
        return iam_user_profile


def check_and_set_manndatory_fields(salesforce_user, demisto_params):
    for field in DEFAULT_FIELDS:
        if not salesforce_user.get(field):
            salesforce_user[field] = demisto_params.get(field)

    return salesforce_user


def get_all_user_attributes(client):
    """
    This command gets all users, chooses the first
    then, run a second get command that returns all the users attributes
    """
    user_id = ""
    attributes = []

    all_users = client.get_all_users()
    users_list = all_users.get("searchRecords")
    if isinstance(users_list, list):
        user = users_list[0]
        user_id = user.get("Id")

    if user_id:
        user_data = client.get_user(user_id)
        attributes = list(user_data.keys())
    return attributes


def get_mapping_fields_command(client):
    scheme = get_all_user_attributes(client)
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.DEFAULT_INCIDENT_TYPE)

    for field in scheme:
        incident_type_scheme.add_field(field, "Field")

    return GetMappingFieldsResponse([incident_type_scheme])


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.info("Salesforce IAM: Starting. command={}".format(command))
    demisto.debug("Salesforce IAM: Raw params: {}".format(params))

    # get the service API url
    base_url = params.get("url", "")
    if not base_url:
        return_error("Instance URL must be provided.")
    # checks for '/' at the end url, if it is not available add it
    if base_url[-1] != "/":
        base_url += "/"

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    mapper_in = params.get("mapper-in", DEFAULT_INCOMING_MAPPER)
    mapper_out = params.get("mapper-out", DEFAULT_OUTGOING_MAPPER)

    is_create_enabled = params.get("create_user_enabled")
    is_update_enabled = params.get("update_user_enabled")
    is_disable_enabled = params.get("disable_user_enabled")
    is_enable_enabled = params.get("enable_user_enabled")
    create_if_not_exists = params.get("create_if_not_exists")

    demisto.debug(
        "Salesforce IAM: config: base_url={}, verify={}, proxy={}, "
        "mapper_in={}, mapper_out={}".format(
            base_url, verify_certificate, proxy, mapper_in, mapper_out
        )
    )

    try:
        demisto.debug("Salesforce IAM: Creating Client instance (BaseClient will detect UCP mode)...")
        client = Client(
            demisto_params=params,
            base_url=base_url,
            ok_codes=(200, 201, 204),
            verify=verify_certificate,
            proxy=proxy,
        )
        demisto.debug(
            "Salesforce IAM: Client created. _ucp_enabled={}, _ucp_method_unique_id={}, "
            "_ucp_creds_cache={}, _ucp_creds_expiry={}".format(
                client._is_ucp_enabled(),
                getattr(client, '_ucp_method_unique_id', 'N/A'),
                type(client._ucp_creds_cache).__name__ if client._ucp_creds_cache else 'None',
                getattr(client, '_ucp_creds_expiry', 'N/A'),
            )
        )

        # Legacy mode: extract credentials and perform token exchange.
        # In UCP mode, BaseClient handles auth transparently —
        # skip credential extraction entirely.
        if not client._is_ucp_enabled():
            demisto.info(
                "Salesforce IAM: UCP not enabled — running in legacy auth mode."
            )
            client.setup_legacy_auth()
            demisto.info("Salesforce IAM: Legacy OAuth2 token exchange completed successfully.")
        else:
            demisto.info(
                "Salesforce IAM: UCP mode enabled (method_unique_id={}). "
                "Skipping legacy credential extraction — BaseClient will inject auth per-request.".format(
                    client._ucp_method_unique_id
                )
            )
            demisto.debug(
                "Salesforce IAM: UCP mode details — _ucp_info keys={}, "
                "base_url={}, headers={}".format(
                    list(client._ucp_info.keys()) if hasattr(client, '_ucp_info') else 'N/A',
                    client._base_url,
                    list(client._headers.keys()) if client._headers else 'None',
                )
            )

        demisto.debug("Salesforce IAM: Dispatching command={}".format(command))

        if command == "test-module":
            demisto.info("Salesforce IAM: Running test-module command.")
            return_results(test_module(client))

        elif command == "iam-get-user":
            demisto.debug("Salesforce IAM: Executing iam-get-user")
            user_profile = get_user_command(client, args, mapper_in, mapper_out)
            return_results(user_profile)

        elif command == "iam-create-user":
            demisto.debug("Salesforce IAM: Executing iam-create-user")
            user_profile = create_user_command(
                client, args, mapper_out,
                is_create_enabled, is_update_enabled, is_enable_enabled,
            )
            return_results(user_profile)

        elif command == "iam-update-user":
            demisto.debug("Salesforce IAM: Executing iam-update-user")
            user_profile = update_user_command(
                client, args, mapper_out,
                is_update_enabled, is_enable_enabled,
                is_create_enabled, create_if_not_exists,
            )
            return_results(user_profile)

        elif command == "iam-disable-user":
            demisto.debug("Salesforce IAM: Executing iam-disable-user")
            user_profile = disable_user_command(
                client, args, mapper_out, is_disable_enabled,
            )
            return_results(user_profile)

        elif command == "get-mapping-fields":
            demisto.debug("Salesforce IAM: Executing get-mapping-fields")
            return_results(get_mapping_fields_command(client))

        demisto.info("Salesforce IAM: command={} completed successfully.".format(command))

    except Exception as e:
        demisto.error("Salesforce IAM: command={} failed with error: {}".format(command, e))
        return_error("Failed to execute {} command. Error: {}.".format(command, e))


from IAMApiModule import *  # noqa: E402

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
