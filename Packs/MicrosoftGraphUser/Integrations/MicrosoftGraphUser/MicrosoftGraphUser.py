import demistomock as demisto
from CommonServerUserPython import *
from urllib.parse import quote
import urllib3
from CommonServerPython import *
from MicrosoftApiModule import *  # noqa: E402
from pyzipper import AESZipFile, ZIP_DEFLATED, WZ_AES

# disable insecure warnings

urllib3.disable_warnings()

""" CONSTANTS """
BLOCK_ACCOUNT_JSON = '{"accountEnabled": false}'
UNBLOCK_ACCOUNT_JSON = '{"accountEnabled": true}'
NO_OUTPUTS: dict = {}
APP_NAME = "ms-graph-user"
INVALID_USER_CHARS_REGEX = re.compile(r"[%&*+/=?`{|}]")
API_VERSION: str = "v1.0"
DEFAULT_LIMIT = 50
AUTH_METHODS_FIELD_MAPPING = {
    "OWNED_DEVICES": {
        "id": "Device Id",
        "deviceId": "Azure Device Registration Id",
        "displayName": "Device Display Name",
    },
    "FIDO2": {
        "id": "Authentication method ID",
        "displayName": "The display name of the key",
        "aaGuid": "Authenticator Attestation GUID",
    },
    "AUTHENTICATOR": {
        "id": "Authentication method ID",
        "displayName": "Device Name",
        "phoneAppVersion": "Version of the Authenticator app",
    },
    "PHONE": {
        "id": "Phone ID",
        "phoneNumber": "Phone Number",
        "phoneType": "Phone Type",
        "smsSignInState": "Sms SignIn State",
    },
    "SOFTWARE_OATH": {
        "id": "Authentication method ID",
    },
    "TEMP_ACCESS_PASS": {
        "id": "Temporary Access Pass ID",
        "isUsable": "Authentication method state",
    },
    "WINDOWS_HELLO": {
        "id": "Windows Hello Method ID",
        "displayName": "Display Name",
        "keyStrength": "Method Key Strength",
    },
}
MFA_APP_ID = "981f26a1-7f43-403b-a875-f8b09b8cd720"  # MFA app ID (not a secret, same app ID for all azure tenants)
MAX_TIMEOUT_LIMIT = 60


def camel_case_to_readable(text):
    """
    'camelCase' -> 'Camel Case'
    """
    if text == "id":
        return "ID"
    return "".join(" " + char if char.isupper() else char.strip() for char in text).strip().title()


def parse_outputs(users_data):
    """
    Parse user data as received from Microsoft Graph API into Demisto's conventions
    """
    if isinstance(users_data, list):
        users_readable, users_outputs = [], []
        for user_data in users_data:
            user_readable = {camel_case_to_readable(k): v for k, v in user_data.items() if k != "@removed"}
            if "@removed" in user_data:
                user_readable["Status"] = "deleted"
            users_readable.append(user_readable)
            users_outputs.append({k.replace(" ", ""): v for k, v in user_readable.copy().items()})

        return users_readable, users_outputs

    else:
        user_readable = {camel_case_to_readable(k): v for k, v in users_data.items() if k != "@removed"}
        if "@removed" in users_data:
            user_readable["Status"] = "deleted"
        user_outputs = {k.replace(" ", ""): v for k, v in user_readable.copy().items()}

        return user_readable, user_outputs


def create_account_outputs(users_outputs: (list[dict[str, Any]] | dict[str, Any])) -> list:
    if not isinstance(users_outputs, list):
        users_outputs = [users_outputs]

    accounts = []
    for user_outputs in users_outputs:
        accounts.append(
            {
                "Type": "Azure AD",
                "DisplayName": user_outputs.get("DisplayName"),
                "Username": user_outputs.get("UserPrincipalName"),
                "JobTitle": user_outputs.get("JobTitle"),
                "Email": {"Address": user_outputs.get("Mail")},
                "TelephoneNumber": user_outputs.get("MobilePhone"),
                "ID": user_outputs.get("ID"),
                "Office": user_outputs.get("OfficeLocation"),
            }
        )

    return accounts


def get_unsupported_chars_in_user(user: Optional[str]) -> set:
    """
    Extracts the invalid user characters found in the provided string.
    """
    if not user:
        return set()
    return set(INVALID_USER_CHARS_REGEX.findall(user))


class MsGraphClient:
    """
    Microsoft Graph Mail Client enables authorized access to a user's Office 365 mail data in a personal account.
    """

    def __init__(
        self,
        tenant_id,
        auth_id,
        enc_key,
        app_name,
        base_url,
        verify,
        proxy,
        self_deployed,
        redirect_uri,
        auth_code,
        handle_error,
        azure_cloud: AzureCloud,
        certificate_thumbprint: Optional[str] = None,
        private_key: Optional[str] = None,
        managed_identities_client_id: Optional[str] = None,
    ):
        grant_type = AUTHORIZATION_CODE if auth_code and redirect_uri else CLIENT_CREDENTIALS
        resource = None if self_deployed else ""
        client_args = {
            "tenant_id": tenant_id,
            "auth_id": auth_id,
            "enc_key": enc_key,
            "app_name": app_name,
            "base_url": base_url,
            "verify": verify,
            "proxy": proxy,
            "self_deployed": self_deployed,
            "redirect_uri": redirect_uri,
            "auth_code": auth_code,
            "grant_type": grant_type,
            "resource": resource,
            "certificate_thumbprint": certificate_thumbprint,
            "private_key": private_key,
            "azure_cloud": azure_cloud,
            "managed_identities_client_id": managed_identities_client_id,
            "managed_identities_resource_uri": Resources.graph,
            "command_prefix": "msgraph-user",
        }
        self.ms_client = MicrosoftClient(**client_args)
        self.handle_error = handle_error

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def disable_user_account_session(self, user):
        self.ms_client.http_request(method="PATCH", url_suffix=f"users/{quote(user)}", data=BLOCK_ACCOUNT_JSON, resp_type="text")

    #  Using resp_type=text to avoid parsing error.
    def unblock_user(self, user):
        self.ms_client.http_request(
            method="PATCH", url_suffix=f"users/{quote(user)}", data=UNBLOCK_ACCOUNT_JSON, resp_type="text"
        )

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def delete_user(self, user):
        self.ms_client.http_request(method="DELETE", url_suffix=f"users/{quote(user)}", resp_type="text")

    def create_user(self, properties):
        self.ms_client.http_request(method="POST", url_suffix="users", json_data=properties)

    def get_sign_in_preferences(self, user: str):  # pragma: no cover
        """
        Retrieves the sign-in preferences for a user, which includes the preferred method.
        API Reference: https://learn.microsoft.com/en-us/graph/api/authentication-get?view=graph-rest-beta
        Note: This uses the beta endpoint as it's not available in v1.0 yet.
        """
        url_suffix = f"users/{quote(user)}/authentication/signInPreferences"
        # We need to use beta for this specific call
        original_base_url = self.ms_client._base_url
        try:
            self.ms_client._base_url = original_base_url.replace("/v1.0/", "/beta/")
            res = self.ms_client.http_request(method="GET", url_suffix=url_suffix)
            return res
        finally:
            self.ms_client._base_url = original_base_url

    def request_mfa_app_secret(self) -> dict:  # pragma: no cover
        """
        The function utilizes the MFA application ID (981f26a1-7f43-403b-a875-f8b09b8cd720) to retrieve the service principal ID.
        Which then uses the service principal ID to retrieve the client secret.
        The client secret has an expiration of 2 years.

        Args:
            None.

        Returns:
            (str): the MFA application client secret.
        """

        # if not exist, generate a new client secret.
        # Search for the service principal with the MFA application ID.
        sp_endpoint_url_suffix = f"servicePrincipals?$filter=appId eq '{MFA_APP_ID}'&$select=id"
        demisto.debug(f"Searching for Service Principal with appId: {MFA_APP_ID}...")
        sp_data = self.ms_client.http_request(method="GET", url_suffix=sp_endpoint_url_suffix)

        if not sp_data.get("value"):
            raise DemistoException(f"Error: Service Principal with appId {MFA_APP_ID} not found.")

        # Extract the Service Principal Object ID
        service_principal_id = sp_data["value"][0]["id"]
        demisto.debug(f"Service Principal ID (Object ID) found: {service_principal_id}")

        # Send request for new client secret.
        SECRET_DISPLAY_NAME = "MFA App Secret"

        # Endpoint to add a password credential to the service principal
        secret_genertion_endpoint_url_suffix = f"servicePrincipals/{service_principal_id}/addPassword"

        # Request body for adding the secret
        secret_body = {
            "passwordCredential": {
                "displayName": SECRET_DISPLAY_NAME  # The display name for the secret, not mandatory
            }
        }

        demisto.debug(f"Adding new client secret with display name '{SECRET_DISPLAY_NAME}'")
        secret_result = self.ms_client.http_request(
            method="POST", url_suffix=secret_genertion_endpoint_url_suffix, data=json.dumps(secret_body)
        )

        demisto.debug(
            f"A new client secret with the name {secret_result.get('displayName')} was created successfully. the"
            f"secret is valid until {secret_result.get('endDateTime')}"
        )

        return secret_result

    def get_mfa_app_client_token(self, client_secret: str) -> dict:  # pragma: no cover
        demisto.debug("Creating new MFA access token.")

        # Hardcoded endpoints
        RESOURCE = "https://adnotifications.windowsazure.com/StrongAuthenticationService.svc/Connector"
        AUTH_ENDPOINT = f"https://login.microsoftonline.com/{self.ms_client.tenant_id}/oauth2/token"

        # Generating MFA app access token.
        demisto.debug("Getting MFA Client Access Token...")

        token_body = {
            "resource": RESOURCE,
            "client_id": MFA_APP_ID,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
            "scope": "openid",
        }

        try:
            token_response = requests.post(AUTH_ENDPOINT, data=token_body)
            token_response.raise_for_status()
            res = token_response.json()
            demisto.debug("Access token obtained successfully.")
            access_token = res.get("access_token")
            valid_until = res.get("expires_on")
            mfa_access_token = {"ValidUntil": valid_until, "AccessToken": access_token}
            return mfa_access_token

        except requests.exceptions.HTTPError as e:
            raise DemistoException(f"Error obtaining access token: {e}\nResponse: {token_response.text}")

    def push_mfa_notification(self, user_principal_name: str, timeout: int, access_token: str) -> str:  # pragma: no cover
        """
        Send a synchronous MFA push notification to the user with the given UPN.
        This is a blocking call that waits for user response or timeout.

        Args:
            user_principal_name (str): The user principal name of the user to send the MFA notification to.
            timeout (int): The timeout in seconds for the request.
            auth_method_id (str, optional): The specific authentication method ID to use.

        Returns:
            str: Status message indicating the result of the MFA challenge.
        """
        import uuid

        # Hardcoded endpoints
        MFA_SERVICE_URI = "https://strongauthenticationservice.auth.microsoft.com/StrongAuthenticationService.svc/Connector//BeginTwoWayAuthentication"

        demisto.debug("Sending synchronous MFA challenge to the user...")

        # Generate a unique GUID for ContextId
        context_id = str(uuid.uuid4())

        # Define the XML payload with SyncCall=true for blocking behavior
        xml_payload = f"""
        <BeginTwoWayAuthenticationRequest>
            <Version>1.0</Version>
            <UserPrincipalName>{user_principal_name}</UserPrincipalName>
            <Lcid>en-us</Lcid>
            <AuthenticationMethodProperties xmlns:a="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
                <a:KeyValueOfstringstring>
                    <a:Key>OverrideVoiceOtp</a:Key>
                    <a:Value>false</a:Value>
                </a:KeyValueOfstringstring>
            </AuthenticationMethodProperties>
            <ContextId>{context_id}</ContextId>
            <SyncCall>true</SyncCall>
            <RequireUserMatch>true</RequireUserMatch>
            <CallerName>radius</CallerName>
            <CallerIP>UNKNOWN:</CallerIP>
        </BeginTwoWayAuthenticationRequest>
        """

        return self._send_mfa_request_and_parse_response(MFA_SERVICE_URI, xml_payload, timeout, access_token)

    def _send_mfa_request_and_parse_response(
        self, mfa_service_uri: str, xml_payload: str, timeout: int, mfa_client_token: str
    ) -> str:  # pragma: no cover
        """
        Helper method to send MFA request and parse the XML response.

        Args:
            mfa_service_uri (str): The MFA service endpoint URL.
            xml_payload (str): The XML payload to send.
            timeout (int): Request timeout in seconds.

        Returns:
            str: Status message indicating the result.
        """
        import xml.etree.ElementTree as ET

        headers = {"Authorization": f"Bearer {mfa_client_token}", "Content-Type": "application/xml"}

        try:
            mfa_result = requests.post(
                mfa_service_uri, headers=headers, data=xml_payload.strip().encode("utf-8"), timeout=timeout
            )
            mfa_result.raise_for_status()

            demisto.debug("MFA Challenge Request Sent. Waiting for response...")

            # Parse the XML response
            root = ET.fromstring(mfa_result.text)

            result_node = root.find("./Result")
            auth_result_node = root.find("./AuthenticationResult")

            if result_node is not None and auth_result_node is not None:
                value_node = result_node.find("./Value")
                result_value = value_node.text if value_node is not None else ""
                mfa_challenge_received = (auth_result_node.text or "").lower() == "true"

                message_node = result_node.find("./Message")
                is_nil = message_node is not None and message_node.get("{http://www.w3.org/2001/XMLSchema-instance}nil") == "true"
                result_message = message_node.text if message_node is not None and not is_nil else "No specific message"

                mfa_challenge_approved = result_value == "Success"
                mfa_challenge_denied = result_value == "PhoneAppDenied"
                mfa_challenge_timeout = result_value == "PhoneAppNoResponse"

                demisto.debug(f"MFA Result - Value: {result_value}, Message: {result_message}")

                if mfa_challenge_approved and mfa_challenge_received:
                    return "Status: User Approved MFA Request"
                elif mfa_challenge_denied:
                    raise DemistoException("Status: User Denied Request")
                elif mfa_challenge_timeout:
                    raise DemistoException("Status: MFA Request Timed Out")
                else:
                    raise DemistoException(f"Status: MFA Request Failed - {result_message}")
            else:
                raise DemistoException(f"Error: Could not parse MFA response.\nRaw Response:\n{mfa_result.text}")

        except requests.exceptions.HTTPError as e:
            raise DemistoException(f"Error sending MFA challenge: {e}\nResponse: {mfa_result.text}")
        except ET.ParseError as e:
            raise DemistoException(f"XML Parse Error: {e}\nRaw Response: {mfa_result.text}")
        except DemistoException:
            raise
        except Exception as e:
            raise DemistoException(f"An unexpected error occurred: {e}")

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def update_user(self, user: str, updated_fields: str, delimiter: str = ","):
        body = {}
        for key_value in updated_fields.split(delimiter):
            field, value = key_value.split("=", 2)
            body[field] = value
        self.ms_client.http_request(method="PATCH", url_suffix=f"users/{quote(user)}", json_data=body, resp_type="text")

    def force_reset_password(self, user):
        body = {"passwordProfile": {"forceChangePasswordNextSignIn": True}}
        self.ms_client.http_request(method="PATCH", url_suffix=f"users/{quote(user)}", json_data=body, resp_type="text")

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def password_change_user_saas(
        self, user: str, password: str, force_change_password_next_sign_in: bool, force_change_password_with_mfa: bool
    ):
        body = {
            "passwordProfile": {
                "forceChangePasswordNextSignIn": force_change_password_next_sign_in,
                "forceChangePasswordNextSignInWithMfa": force_change_password_with_mfa,
                "password": password,
            }
        }
        self.ms_client.http_request(method="PATCH", url_suffix=f"users/{quote(user)}", json_data=body, resp_type="text")

    def fetch_password_method_id(self, user: str) -> str:
        """
        fetches the password method ID, to be used later. See API docs for reference:
         https://learn.microsoft.com/en-us/graph/api/authentication-list-passwordmethods?view=graph-rest-1.0&tabs=http
        """
        password_method_id_response = None
        try:
            password_method_id_response = self.ms_client.http_request(
                method="GET", url_suffix=f"users/{quote(user)}/authentication/passwordMethods"
            )
            password_method_id = password_method_id_response.get("value", [])[0]["id"]  # There is only one password method object
            demisto.debug("Got the password method id")
        except (IndexError, KeyError) as e:
            raise DemistoException("Failed getting passwordMethod id", exception=e, res=password_method_id_response)
        return password_method_id

    def password_change_user_on_premise(self, user: str, password: str, password_method_id: str) -> str:
        """
        changes the password of a user on premise.
        """
        response = self.ms_client.http_request(
            method="POST",
            url_suffix=f"users/{quote(user)}/authentication/methods/{password_method_id}/resetPassword",
            ok_codes=(202,),
            empty_valid_codes=[202],
            json_data={"newPassword": password},
            return_empty_response=True,
            resp_type="response",  # the response is empty, this ensures the http_request function will not try to parse it
        )

        polling_url = response.headers.get("Location", "")

        if not polling_url:
            raise ValueError(f"Failed to get polling URL (Location header) from the API response for user {user}.")

        return polling_url

    def get_delta(self, properties):
        users = self.ms_client.http_request(method="GET", url_suffix="users/delta", params={"$select": properties})
        return users.get("value", "")

    def get_user(self, user, properties):
        try:
            user_data = self.ms_client.http_request(
                method="GET", url_suffix=f"users/{quote(user)}", params={"$select": properties}
            )
            user_data.pop("@odata.context", None)
            return user_data
        except NotFoundError as e:
            LOG(f"User {user} was not found")
            return {"NotFound": e.message}
        except Exception as e:
            raise e

    def get_groups(self, user):
        group_data = self.ms_client.http_request(method="GET", url_suffix=f"users/{quote(user)}/memberOf")
        group_data.pop("@odata.context", None)
        return group_data

    def get_auth_methods(self, user):
        data = self.ms_client.http_request(method="GET", url_suffix=f"users/{quote(user)}/authentication/methods")
        data.pop("@odata.context", None)
        return data.get("value", [])

    def list_users(self, properties, page_url, filters):
        if page_url:
            response = self.ms_client.http_request(method="GET", url_suffix="users", full_url=page_url)
        else:
            response = self.ms_client.http_request(
                method="GET",
                url_suffix="users",
                headers={"ConsistencyLevel": "eventual"},
                params={"$filter": filters, "$select": properties, "$count": "true"},
            )

        next_page_url = response.get("@odata.nextLink")
        users = response.get("value")
        return users, next_page_url

    def get_direct_reports(self, user):
        res = self.ms_client.http_request(method="GET", url_suffix=f"users/{quote(user)}/directReports")

        res.pop("@odata.context", None)
        return res.get("value", [])

    def get_manager(self, user):
        manager_data = self.ms_client.http_request(method="GET", url_suffix=f"users/{quote(user)}/manager")
        manager_data.pop("@odata.context", None)
        manager_data.pop("@odata.type", None)
        return manager_data

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def assign_manager(self, user, manager):
        manager_ref = f"{self.ms_client._base_url}users/{manager}"
        body = {"@odata.id": manager_ref}
        self.ms_client.http_request(
            method="PUT", url_suffix=f"users/{quote(user)}/manager/$ref", json_data=body, resp_type="text"
        )

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def revoke_user_session(self, user):
        self.ms_client.http_request(method="POST", url_suffix=f"users/{quote(user)}/revokeSignInSessions", resp_type="text")

    #  If successful, this method returns 200
    def list_tap_policy(self, user_id):
        """
        Args:
            user_id (str): The Azure AD user ID.

        Returns:
            list: A list that contains a dictionary representing the TAP policy info with the following keys:
            - id (str): The unique identifier for the TAP policy.
            - isUsable (bool): Indicates whether the TAP is currently usable.
            - methodUsabilityReason (str): Explanation of why the TAP is or is not usable (e.g., 'Expired', 'NotYetValid).
            - temporaryAccessPass (str or None): The generated password for the TAP policy.
            - createdDateTime (str): The ISO 8601 timestamp when the TAP was created.
            - startDateTime (str): The ISO 8601 timestamp when the TAP becomes valid.
            - lifetimeInMinutes (int): The validity duration of the TAP in minutes.
            - isUsableOnce (bool): Indicates whether the TAP can be used only once.

        API Reference:
            https://graph.microsoft.com/v1.0/users/[user_id]/authentication/temporaryAccessPassMethods
        """
        url_suffix = f"users/{quote(user_id)}/authentication/temporaryAccessPassMethods"

        res = self.ms_client.http_request(method="GET", url_suffix=url_suffix)
        return res.get("value", [])

    #  If successful, this method returns 201
    def create_tap_policy(self, user_id, body):
        """
        Args:
            user_id (str): The Azure AD user ID.
            body (dict): A dictionary containing the input arguments.

        Returns:
            dict: A dictionary representing the newly created TAP policy with the following keys:
            - id (str): The unique identifier for the TAP policy.
            - isUsable (bool): Indicates whether the TAP is currently usable.
            - methodUsabilityReason (str): Explanation of why the TAP is or is not usable (e.g., 'Expired', 'NotYetValid).
            - temporaryAccessPass (str): The generated password for the TAP policy.
            - createdDateTime (str): The ISO 8601 timestamp when the TAP was created.
            - startDateTime (str): The ISO 8601 timestamp when the TAP becomes valid.
            - lifetimeInMinutes (int): The validity duration of the TAP in minutes.
            - isUsableOnce (bool): Indicates whether the TAP can be used only once.

        API Reference:
            https://graph.microsoft.com/v1.0/users/[user_id]/authentication/temporaryAccessPassMethods
        """
        url_suffix = f"users/{quote(user_id)}/authentication/temporaryAccessPassMethods"
        res = self.ms_client.http_request(method="POST", url_suffix=url_suffix, json_data=body)
        res.pop("@odata.context", None)
        return res

    #  If successful, this method returns 204 - no content
    def delete_tap_policy(self, user_id, policy_id):
        """
        Args:
            user_id (str): The Azure AD user ID.
            policy_id (str): TAP Policy ID.

        Returns:
            None.

        API Reference:
            https://graph.microsoft.com/v1.0/users/[user_id]/authentication/temporaryAccessPassMethods/[policy_id]
        """
        url_suffix = f"users/{quote(user_id)}/authentication/temporaryAccessPassMethods/{quote(policy_id)}"
        self.ms_client.http_request(method="DELETE", url_suffix=url_suffix, resp_type="text")

    def list_fido2_methods(self, user_id: str) -> list:
        """
        Lists the FIDO2 authentication methods registered to a user, or retrieves a specific method.

        Args:
            user_id (str): The Azure AD user ID.

        API Reference:
            List: https://learn.microsoft.com/en-us/graph/api/fido2authenticationmethod-list?view=graph-rest-1.0&tabs=http
        """

        url_suffix = f"users/{quote(user_id)}/authentication/fido2Methods"
        res = self.ms_client.http_request(method="GET", url_suffix=url_suffix)
        return res.get("value", [])

    def get_fido2_method(self, user_id: str, method_id: str) -> dict:
        """
        Gets the FIDO2 authentication method registered to a user.

        Args:
            user_id (str): The Azure AD user ID.
            method_id (str, optional): The ID of a specific FIDO2 authentication method to retrieve.
            limit (int, optional): Maximum number of results to return when listing all methods.

        API Reference:
            Get: https://learn.microsoft.com/en-us/graph/api/fido2authenticationmethod-get?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/fido2Methods/{method_id}"
        res = self.ms_client.http_request(method="GET", url_suffix=url_suffix)
        res.pop("@odata.context", None)
        return res

    def delete_fido2_method(self, user_id: str, method_id: str):
        """
        Deletes a FIDO2 authentication method from a user.

        Args:
            user_id (str): The Azure AD user ID.
            method_id (str): The ID of the FIDO2 authentication method to delete.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/fido2authenticationmethod-delete?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/fido2Methods/{quote(method_id)}"
        self.ms_client.http_request(method="DELETE", url_suffix=url_suffix, return_empty_response=True)

    def list_email_methods(self, user_id: str):
        """
        Lists the email authentication methods registered to a user.

        Args:
            user_id (str): The Azure AD user ID.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/authentication-list-emailmethods?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/emailMethods"
        res = self.ms_client.http_request(method="GET", url_suffix=url_suffix)
        return res.get("value", [])

    def get_email_method(self, user_id: str, method_id: str) -> dict:
        """
        Retrieves a specific email authentication method for a user.

        Args:
            user_id (str): The Azure AD user ID.
            method_id (str): The ID of a specific email authentication method to retrieve.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/emailauthenticationmethod-get?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/emailMethods/{quote(method_id)}"
        res = self.ms_client.http_request(method="GET", url_suffix=url_suffix)
        res.pop("@odata.context", None)
        return res

    def delete_email_method(self, user_id: str, method_id: str):
        """
        Deletes an email authentication method from a user.

        Args:
            user_id (str): The Azure AD user ID.
            method_id (str): The ID of the email authentication method to delete.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/emailauthenticationmethod-delete?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/emailMethods/{quote(method_id)}"
        self.ms_client.http_request(method="DELETE", url_suffix=url_suffix, return_empty_response=True)

    def list_authenticator_methods(self, user_id: str, limit: int = DEFAULT_LIMIT, page_url: str = ""):
        """
        Lists the Microsoft Authenticator authentication methods registered to a user.

        Args:
            user_id (str): The Azure AD user ID.
            limit (int, optional): Maximum number of results to return.
            page_url (str, optional): URL for the next page of results.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/microsoftauthenticatorauthenticationmethod-list?view=graph-rest-1.0&tabs=http
        """
        if page_url:
            response = self.ms_client.http_request(method="GET", full_url=page_url)
        else:
            url_suffix = f"users/{quote(user_id)}/authentication/microsoftAuthenticatorMethods"
            params = {}
            if limit:
                params["$top"] = limit
            response = self.ms_client.http_request(method="GET", url_suffix=url_suffix, params=params)

        next_page_url = response.get("@odata.nextLink")
        methods = response.get("value", [])
        return methods, next_page_url

    def get_authenticator_method(self, user_id: str, method_id: str) -> dict:
        """
        Retrieves a specific Microsoft Authenticator authentication method for a user.

        Args:
            user_id (str): The Azure AD user ID.
            method_id (str): The ID of a specific authenticator method to retrieve.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/microsoftauthenticatorauthenticationmethod-get?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/microsoftAuthenticatorMethods/{quote(method_id)}"
        res = self.ms_client.http_request(method="GET", url_suffix=url_suffix)
        res.pop("@odata.context", None)
        return res

    def delete_authenticator_method(self, user_id: str, method_id: str) -> None:
        """
        Deletes a Microsoft Authenticator authentication method from a user.

        Args:
            user_id (str): The Azure AD user ID.
            method_id (str): The ID of the Microsoft Authenticator authentication method to delete.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/microsoftauthenticatorauthenticationmethod-delete?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/microsoftAuthenticatorMethods/{quote(method_id)}"
        self.ms_client.http_request(method="DELETE", url_suffix=url_suffix, return_empty_response=True)

    def list_phone_methods(self, user_id: str, page_url: str = ""):
        """
        Lists the phone authentication methods registered to a user.

        Args:
            user_id (str): The Azure AD user ID.
            page_url (str, optional): URL for the next page of results.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/authentication-list-phonemethods?view=graph-rest-1.0&tabs=http
        """
        if page_url:
            response = self.ms_client.http_request(method="GET", full_url=page_url)
        else:
            url_suffix = f"users/{quote(user_id)}/authentication/phoneMethods"
            response = self.ms_client.http_request(method="GET", url_suffix=url_suffix)

        next_page_url = response.get("@odata.nextLink")
        methods = response.get("value", [])
        return methods, next_page_url

    def get_phone_method(self, user_id: str, method_id: str) -> dict:
        """
        Retrieves a specific phone authentication method for a user.

        Args:
            user_id (str): The Azure AD user ID.
            method_id (str): The ID of a specific phone method to retrieve.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/phoneauthenticationmethod-get?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/phoneMethods/{quote(method_id)}"
        res = self.ms_client.http_request(method="GET", url_suffix=url_suffix)
        res.pop("@odata.context", None)
        return res

    def delete_phone_method(self, user_id: str, method_id: str):
        """
        Deletes a phone authentication method from a user.

        Args:
            user_id (str): The Azure AD user ID.
            method_id (str): The ID of the phone authentication method to delete.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/phoneauthenticationmethod-delete?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/phoneMethods/{quote(method_id)}"
        self.ms_client.http_request(method="DELETE", url_suffix=url_suffix, return_empty_response=True)

    def list_software_oath_methods(self, user_id: str):
        """
        Lists the software OATH authentication methods registered to a user.

        Args:
            user_id (str): The Azure AD user ID.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/authentication-list-softwareoathmethods?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/softwareOathMethods"
        res = self.ms_client.http_request(method="GET", url_suffix=url_suffix)
        return res.get("value", [])

    def get_software_oath_method(self, user_id: str, method_id: str) -> dict:
        """
        Retrieves a specific software OATH authentication method for a user.

        Args:
            user_id (str): The Azure AD user ID.
            method_id (str): The ID of a specific software OATH method to retrieve.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/softwareoathauthenticationmethod-get?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/softwareOathMethods/{quote(method_id)}"
        res = self.ms_client.http_request(method="GET", url_suffix=url_suffix)
        res.pop("@odata.context", None)
        return res

    def delete_software_oath_method(self, user_id: str, method_id: str):
        """
        Deletes a software OATH authentication method from a user.

        Args:
            user_id (str): The Azure AD user ID.
            method_id (str): The ID of the software OATH authentication method to delete.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/softwareoathauthenticationmethod-delete?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/softwareOathMethods/{quote(method_id)}"
        self.ms_client.http_request(method="DELETE", url_suffix=url_suffix, return_empty_response=True)

    def list_windows_hello_methods(self, user_id: str):
        """
        Lists the Windows Hello for Business authentication methods registered to a user.

        Args:
            user_id (str): The Azure AD user ID.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/windowshelloforbusinessauthenticationmethod-list?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/windowsHelloForBusinessMethods"
        res = self.ms_client.http_request(method="GET", url_suffix=url_suffix)
        return res.get("value", [])

    def get_windows_hello_method(self, user_id: str, method_id: str) -> dict:
        """
        Retrieves a specific Windows Hello for Business authentication method for a user.

        Args:
            user_id (str): The Azure AD user ID.
            method_id (str): The ID of a specific Windows Hello for Business method to retrieve.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/windowshelloforbusinessauthenticationmethod-get?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/windowsHelloForBusinessMethods/{quote(method_id)}"
        res = self.ms_client.http_request(method="GET", url_suffix=url_suffix)
        res.pop("@odata.context", None)
        return res

    def delete_windows_hello_method(self, user_id: str, method_id: str):
        """
        Deletes a Windows Hello for Business authentication method from a user.

        Args:
            user_id (str): The Azure AD user ID.
            method_id (str): The ID of the Windows Hello for Business authentication method to delete.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/windowshelloforbusinessauthenticationmethod-delete?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/windowsHelloForBusinessMethods/{quote(method_id)}"
        self.ms_client.http_request(method="DELETE", url_suffix=url_suffix, return_empty_response=True)

    def get_temp_access_pass_method(self, user_id: str, method_id: str) -> dict:
        """
        Retrieves a specific temporary access pass authentication method for a user.

        Args:
            user_id (str): The Azure AD user ID.
            method_id (str): The ID of a specific temporary access pass method to retrieve.

        Returns:
            dict: A temporary access pass method object.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/temporaryaccesspassauthenticationmethod-get?view=graph-rest-1.0&tabs=http
        """
        url_suffix = f"users/{quote(user_id)}/authentication/temporaryAccessPassMethods/{quote(method_id)}"
        res = self.ms_client.http_request(method="GET", url_suffix=url_suffix)
        res.pop("@odata.context", None)
        return res

    def list_owned_devices(self, page_url: str, user_id: str, filters: str, page_size: int):
        """
        Lists the devices owned by a user.

        Args:
            page_url (str): URL for the next page of results (optional).
            user_id (str): The Azure AD user ID or user principal name.
            filters (str): OData filter to apply to the results (optional).
            page_size (int): Maximum number of results to return per page.

        API Reference:
            https://learn.microsoft.com/en-us/graph/api/user-list-owneddevices?view=graph-rest-1.0&tabs=http
        """
        if page_url:
            response = self.ms_client.http_request(method="GET", full_url=page_url)
        else:
            suffix_url = f"users/{quote(user_id)}/ownedDevices"
            response = self.ms_client.http_request(
                method="GET",
                url_suffix=suffix_url,
                headers={"ConsistencyLevel": "eventual"},
                params={"$filter": filters, "$count": "true", "$top": page_size},
            )

        next_page_url = response.get("@odata.nextLink")
        users = response.get("value")
        return users, next_page_url


def suppress_errors_with_404_code(func):
    def wrapper(client: MsGraphClient, args: dict):
        try:
            return func(client, args)
        except NotFoundError as e:
            if client.handle_error:
                if (user := args.get("user", "___")) in str(e):
                    if "A key with identifier" in str(e) and (method_id := args.get("method_id")):
                        human_readable = f"#### Did not find the method_id {method_id} for user {user}"
                    else:
                        human_readable = f"#### User -> {user} does not exist"
                    return human_readable
                elif (manager := args.get("manager", "___")) in str(e):
                    human_readable = f"#### Manager -> {manager} does not exist"
                    return human_readable
                elif "The specified user could not be found." in str(e.message):
                    user = args.get("user_id") or args.get("user", "___")
                    human_readable = f"#### User -> {user} does not exist"
                    return human_readable
            raise

    return wrapper


def test_function(client, _):
    """
    Performs basic GET request to check if the API is reachable and authentication is successful.
    Returns ok if successful.
    """
    response = "ok"
    if demisto.params().get("self_deployed", False):
        if demisto.command() == "test-module":
            if client.ms_client.grant_type != CLIENT_CREDENTIALS:
                # cannot use test module due to the lack of ability to set refresh token to integration context
                # for self deployed app
                raise Exception(
                    "When using a self-deployed configuration with authorization code and redirect uri, "
                    "Please enable the integration and run the !msgraph-user-test command in order to test it"
                )
        else:
            response = "```✅ Success!```"

    client.ms_client.http_request(method="GET", url_suffix="users/")
    return response


@suppress_errors_with_404_code
def disable_user_account_command(client: MsGraphClient, args: dict):
    user = args.get("user")
    client.disable_user_account_session(user)
    human_readable = f'user: "{user}" account has been disabled successfully.'

    return CommandResults(readable_output=human_readable)


@suppress_errors_with_404_code
def unblock_user_command(client: MsGraphClient, args: dict):
    user = args.get("user")
    client.unblock_user(user)
    human_readable = f'"{user}" unblocked. It might take several minutes for the changes to take effect across all applications.'

    return CommandResults(readable_output=human_readable)


@suppress_errors_with_404_code
def delete_user_command(client: MsGraphClient, args: dict):
    user = args.get("user")
    client.delete_user(user)
    human_readable = f'user: "{user}" was deleted successfully.'

    return CommandResults(readable_output=human_readable)


def create_user_command(client: MsGraphClient, args: dict):
    required_properties = {
        "accountEnabled": args.get("account_enabled"),
        "displayName": args.get("display_name"),
        "onPremisesImmutableId": args.get("on_premises_immutable_id"),
        "mailNickname": args.get("mail_nickname"),
        "passwordProfile": {"forceChangePasswordNextSignIn": "true", "password": args.get("password")},
        "userPrincipalName": args.get("user_principal_name"),
    }
    other_properties = {}
    if args.get("other_properties"):
        for key_value in args.get("other_properties", "").split(","):
            key, value = key_value.split("=", 2)
            other_properties[key] = value
        required_properties.update(other_properties)

    # create the user
    client.create_user(required_properties)

    # display the new user and it's properties
    user = required_properties.get("userPrincipalName")
    user_data = client.get_user(user, "*")

    user_readable, user_outputs = parse_outputs(user_data)
    human_readable = tableToMarkdown(name=f"{user} was created successfully:", t=user_readable, removeNull=True)
    accounts = create_account_outputs(user_outputs)
    outputs = {"MSGraphUser": user_outputs, "Account": accounts[0] if accounts else []}

    return CommandResults(outputs=outputs, outputs_key_field="ID", readable_output=human_readable, raw_response=user_data)


@suppress_errors_with_404_code
def update_user_command(client: MsGraphClient, args: dict):
    user: str = args["user"]
    updated_fields: str = args["updated_fields"]
    delimiter: str = args.get("updated_fields_delimiter", ",")

    client.update_user(user, updated_fields, delimiter)
    return get_user_command(client, args)


@suppress_errors_with_404_code
def change_password_user_saas_command(client: MsGraphClient, args: dict):
    """
    changes password for SaaS accounts. See change_password_user_on_prem_command for the on-premise equivalent.
    """
    user = str(args.get("user"))
    password = str(args.get("password"))
    force_change_password_next_sign_in = args.get("force_change_password_next_sign_in", "true") == "true"
    force_change_password_with_mfa = args.get("force_change_password_with_mfa", False) == "true"

    client.password_change_user_saas(user, password, force_change_password_next_sign_in, force_change_password_with_mfa)
    human_readable = f"User {user} password was changed successfully."

    return CommandResults(readable_output=human_readable)


def force_reset_password(client: MsGraphClient, args: dict):
    user = args.get("user")
    client.force_reset_password(user)
    return CommandResults(readable_output=f"User {args['user']} will be required to change his password.")


def validate_input_password(args: dict[str, Any]) -> str:
    """
    Get the user's password argument inserted by the user. The password can be inserted either in the sensitive
    argument (named 'password') or nonsensitive argument (named 'nonsensitive_password'). This function validates
    that these arguments are used properly and raises an error if both are provided with different values.

    Args:
        args: script's arguments

    Returns:
        str: the password provided by the user

    Raises:
        ValueError: if no password is provided or if both passwords are provided with different values
    """
    sensitive_password = args.get("password", "")
    nonsensitive_password = args.get("nonsensitive_password", "")

    if not sensitive_password and not nonsensitive_password:
        raise DemistoException(
            "Password is required. Please provide either 'password' (sensitive) or 'nonsensitive_password' argument."
        )

    if sensitive_password and nonsensitive_password and sensitive_password != nonsensitive_password:
        raise DemistoException(
            "Conflicting passwords provided. The 'password' and 'nonsensitive_password' arguments must have the same value, "
            "or use only one of them."
        )

    return sensitive_password or nonsensitive_password


@polling_function(
    "msgraph-user-change-password-on-premise",  # The specified command name
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", 600)) or 600,
    requires_polling_arg=False,
)
def change_password_user_on_premise_command(
    args: Dict[str, Any],
    client: MsGraphClient,
) -> Union[PollResult, CommandResults]:
    """
    Handles initiation and polling for the on-premise password reset operation.
    """
    user = str(args.get("user", ""))
    polling_url = args.get("polling_url")

    # --- 1. Initiation (First Run) ---
    if not polling_url:
        new_password = validate_input_password(args)
        password_method_id = client.fetch_password_method_id(user)

        demisto.debug(f"Initiating password reset for user: {user}")
        try:
            polling_url = client.password_change_user_on_premise(
                user=user, password=new_password, password_method_id=password_method_id
            )
            demisto.debug(f"Got polling url: {polling_url}")

            # Prepare context for the next poll run
            args_for_next_run = {
                "user": user,
                "polling_url": polling_url,
            }
            demisto.debug(f"{args_for_next_run=}")

            return PollResult(
                continue_to_poll=True,
                args_for_next_run=args_for_next_run,
                response=None,
                partial_result=CommandResults(readable_output=f"Password reset initiated for **{user}**. Polling for status..."),
            )

        except Exception as e:
            raise DemistoException(f"Failed to initiate password reset for {user}: {e}")

    # --- 2. Polling Loop (Subsequent Runs) ---
    else:
        demisto.debug(f"Checking status for {user} at: {polling_url}")

        # Poll the status URL (returns the longRunningOperation object)
        status_response = client.ms_client.http_request(method="GET", full_url=polling_url, resp_type="json")
        demisto.debug(f"Got {status_response=}")

        operation_status = status_response.get("status", "unknown")

        outputs = {"user": user, "status": operation_status, "polling_url": polling_url}

        if operation_status == "succeeded":
            # Success: Stop polling
            readable_output = f"Password reset **succeeded** for user **{user}**."
            results = CommandResults(
                readable_output=readable_output,
                raw_response=status_response,
                outputs=outputs,
                outputs_prefix="MSGraphUser.PasswordResetOperation",
            )
            return PollResult(response=results)

        elif operation_status in ("failed", "canceled"):
            # Failure: Stop polling
            error_details = (
                status_response.get("error", {}).get("message")
                or status_response.get("statusDetail")
                or "No specific error message."
            )  # noqa: E501
            outputs["error"] = error_details
            readable_output = f"Password reset **failed** for user **{user}**. Details: {error_details}"

            raise DemistoException(f"Password reset **failed** for user **{user}**. Details: {error_details}")

        else:  # 'running' or 'notStarted'
            # Pending: Continue polling
            return PollResult(
                continue_to_poll=True,
                args_for_next_run={"user_id": user, "polling_url": polling_url},
                response=None,
                partial_result=CommandResults(
                    readable_output=f"Password reset status for **{user}** is **{operation_status}**. Still waiting..."
                ),
            )


def get_delta_command(client: MsGraphClient, args: dict):
    properties = args.get("properties", "") + ",userPrincipalName"
    users_data = client.get_delta(properties)
    headers = list(set([camel_case_to_readable(p) for p in argToList(properties)] + ["ID", "User Principal Name"]))

    users_readable, users_outputs = parse_outputs(users_data)
    human_readable = tableToMarkdown(name="All Graph Users", headers=headers, t=users_readable, removeNull=True)

    return CommandResults(
        outputs_prefix="MSGraphUser",
        outputs_key_field="ID",
        outputs=users_outputs,
        readable_output=human_readable,
        raw_response=users_data,
    )


def get_user_command(client: MsGraphClient, args: dict):
    user = args.get("user")
    properties = args.get("properties", "*")
    try:
        user_data = client.get_user(user, properties)
    except DemistoException as e:
        if "Bad request. Please fix the request before retrying" in e.args[0]:
            invalid_chars = get_unsupported_chars_in_user(user)
            if len(invalid_chars) > 0:
                error = f"Request failed because the user contains unsupported characters: {invalid_chars}\n{e!s}"
                return CommandResults(readable_output=error, raw_response=error)
        raise e

    # In case the request returned a 404 error display a proper message to the war room
    if user_data.get("NotFound", ""):
        error_message = user_data.get("NotFound")
        human_readable = f"### User {user} was not found.\nMicrosoft Graph Response: {error_message}"

        return CommandResults(readable_output=human_readable, raw_response=error_message)

    user_readable, user_outputs = parse_outputs(user_data)
    accounts = create_account_outputs(user_outputs)
    human_readable = tableToMarkdown(name=f"{user} data", t=user_readable, removeNull=True)
    outputs = {"MSGraphUser": user_outputs, "Account": accounts[0] if accounts else []}

    return CommandResults(outputs_key_field="ID", outputs=outputs, readable_output=human_readable, raw_response=user_data)


@suppress_errors_with_404_code
def get_groups_command(client: MsGraphClient, args: Dict):
    user = args.get("user")
    group_data = client.get_groups(user)

    user_readable, user_outputs = parse_outputs(group_data.get("value", []))
    human_readable = tableToMarkdown(name=f"{user} group data", t=user_readable, removeNull=True)
    outputs = {"ID": user, "Groups": user_outputs}

    return CommandResults(
        outputs_prefix="MSGraphUserGroups",
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=human_readable,
        raw_response=group_data,
    )


@suppress_errors_with_404_code
def get_auth_methods_command(client: MsGraphClient, args: Dict):
    user = args.get("user")
    data = client.get_auth_methods(user)
    readable, outputs = parse_outputs(data)
    human_readable = tableToMarkdown(name=f"{user} - auth methods", t=readable, removeNull=True)
    outputs = {"ID": user, "Methods": outputs}

    return CommandResults(
        outputs_prefix="MSGraphUserAuthMethods",
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=human_readable,
        raw_response=data,
    )


def list_users_command(client: MsGraphClient, args: dict):
    properties = args.get("properties", "id,displayName,jobTitle,mobilePhone,mail")
    next_page = args.get("next_page", None)
    filters = args.get("filter", None)
    users_data, result_next_page = client.list_users(properties, next_page, filters)
    users_readable, users_outputs = parse_outputs(users_data)
    accounts = create_account_outputs(users_outputs)
    metadata = None

    outputs = {"MSGraphUser": users_outputs, "Account": accounts}

    if result_next_page:
        metadata = "To get further results, enter this to the next_page parameter:\n" + str(result_next_page)
        # Ensures the NextPage token is inserted as the first element only if it's a valid URL
        outputs["MSGraphUser"].insert(0, {"NextPage": result_next_page})
    human_readable = tableToMarkdown(name="All Graph Users", t=users_readable, removeNull=True, metadata=metadata)

    return CommandResults(outputs_key_field="ID", outputs=outputs, readable_output=human_readable, raw_response=users_data)


@suppress_errors_with_404_code
def get_direct_reports_command(client: MsGraphClient, args: dict):
    user = args.get("user")

    raw_reports = client.get_direct_reports(user)

    reports_readable, reports = parse_outputs(raw_reports)
    human_readable = tableToMarkdown(name=f"{user} - direct reports", t=reports_readable, removeNull=True)
    outputs = {"Manager": user, "Reports": reports}
    return CommandResults(
        outputs_prefix="MSGraphUserDirectReports",
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=human_readable,
        raw_response=raw_reports,
    )


@suppress_errors_with_404_code
def get_manager_command(client: MsGraphClient, args: dict):
    user = args.get("user")
    manager_data = client.get_manager(user)
    manager_readable, manager_outputs = parse_outputs(manager_data)
    human_readable = tableToMarkdown(name=f"{user} - manager", t=manager_readable, removeNull=True)
    outputs = {"User": user, "Manager": manager_outputs}

    return CommandResults(
        outputs_prefix="MSGraphUserManager",
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=human_readable,
        raw_response=manager_data,
    )


@suppress_errors_with_404_code
def assign_manager_command(client: MsGraphClient, args: dict):
    user = args.get("user")
    manager = args.get("manager")
    client.assign_manager(user, manager)
    human_readable = (
        f'A manager was assigned to user "{user}". It might take several minutes for the changes '
        "to take affect across all applications."
    )

    return CommandResults(readable_output=human_readable)


@suppress_errors_with_404_code
def revoke_user_session_command(client: MsGraphClient, args: dict):
    user = args.get("user")
    client.revoke_user_session(user)
    human_readable = f'User: "{user}" sessions have been revoked successfully.'

    return CommandResults(readable_output=human_readable)


@suppress_errors_with_404_code
def list_tap_policy_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Lists the Temporary Access Pass (TAP) policies associated with a specific user.
    Returns a single object in the collection as a user can have only one Temporary Access Pass (TAP) method.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments, including 'user_id' (required)

    Returns:
        CommandResults: The Temporary Access Pass (TAP) policies associated with a specific user.
    """
    user_id = args.get("user_id")
    tap_data = client.list_tap_policy(user_id)
    if not tap_data:
        return CommandResults(readable_output=f"Failed to get TAP policy for the user {user_id}.")

    tap_readable, tap_policy_output = parse_outputs(tap_data)

    tap_readable_dict = tap_readable[0]  # type: ignore
    tap_policy_output_dict = tap_policy_output[0]  # type: ignore

    # Remove the 'temporaryAccessPass' value as it confidential and thus should be removed from context
    tap_policy_output_dict.pop("TemporaryAccessPass")
    # change HR from ID to Policy ID
    tap_readable_dict["Policy ID"] = tap_readable_dict.pop("ID")

    headers = ["Policy ID", "Start Date Time", "Lifetime In Minutes", "Is Usable Once", "Is Usable", "Method Usability Reason"]
    human_readable = tableToMarkdown(name=f"TAP Policy for User ID {user_id}:", headers=headers, t=tap_readable_dict)

    return CommandResults(
        outputs_prefix="MSGraphUser.TAPPolicy",
        outputs_key_field="ID",
        outputs=tap_policy_output_dict,
        readable_output=human_readable,
    )


@suppress_errors_with_404_code
def create_tap_policy_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Creates a Temporary Access Pass (TAP) policy for a Microsoft Graph user.
    Generates a password-protected ZIP file containing the TAP password.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary of arguments which may include:
            - user_id (str): The ID of the user to assign the TAP policy to.
            - zip_password (str): Password to encrypt the ZIP file.
            - lifetime_in_minutes (int. optional): Lifetime of the TAP in minutes.
            - is_usable_once (bool, optional): Whether the TAP can only be used once.
            - start_time (str, optional): ISO 8601 formatted start time for the TAP.

    Returns:
        CommandResults: New Temporary Access Pass (TAP) policies created for a specific user.
    """
    user_id = args.get("user_id")
    zip_password = args.get("zip_password", "")
    lifetime_in_minutes = arg_to_number(args.get("lifetime_in_minutes"))
    is_usable_once = argToBoolean(args.get("is_usable_once", False))
    start_time = args.get("start_time")
    start_time_iso = arg_to_datetime(start_time, required=False)

    fields = {
        "lifetimeInMinutes": lifetime_in_minutes,
        "isUsableOnce": is_usable_once,
        "startDateTime": start_time_iso.strftime("%Y-%m-%dT%H:%M:%S.000Z") if start_time_iso else None,
    }
    res = client.create_tap_policy(user_id, fields)
    if not res:
        return CommandResults(readable_output=f"Failed to create TAP policy for user: {user_id}.")

    # Remove the 'temporaryAccessPass' value as it confidential and thus should be removed from context
    generated_password = res.pop("temporaryAccessPass")

    create_zip_with_password(generated_tap_password=generated_password, zip_password=zip_password)
    human_readable = f"Temporary Access Pass Authentication methods policy for user: {user_id} was successfully created."
    _, tap_policy_output = parse_outputs(res)

    return CommandResults(
        outputs_prefix="MSGraphUser.TAPPolicy", outputs_key_field="ID", outputs=tap_policy_output, readable_output=human_readable
    )


def create_access_token_command(client: MsGraphClient, args: dict, params: dict) -> CommandResults:
    if not argToBoolean(params.get("allow_secret_generators", "False")):
        raise DemistoException(
            '"Allow secret generators commands execution" parameter is not marked, Cannot run this command.'
            "For more information please refer to the integration configuration."
        )
    client_secret = args.get("client_secret", "")
    mfa_client_token = client.get_mfa_app_client_token(client_secret)
    outputs = mfa_client_token
    return CommandResults(
        outputs=outputs, readable_output="A new access token has been created.", outputs_prefix="MSGraphUser.MFAAccessToken"
    )


@suppress_errors_with_404_code
def get_default_auth_methods_command(client: MsGraphClient, args: dict) -> CommandResults:
    user = str(args.get("user"))
    sign_in_preferences = client.get_sign_in_preferences(user)
    # Priority: userPreferredMethodForSecondaryAuthentication -> systemPreferredAuthenticationMethod
    default_method = (
        sign_in_preferences.get("userPreferredMethodForSecondaryAuthentication")
        or sign_in_preferences.get("systemPreferredAuthenticationMethod")
        or "Unknown"
    )

    default_auth_method = {
        "User": user,
        "DefaultMethod": default_method,
        "IsSystemPreferredAuthenticationMethodEnabled": sign_in_preferences.get("isSystemPreferredAuthenticationMethodEnabled"),
        "UserPreferredMethodForSecondaryAuthentication": sign_in_preferences.get("userPreferredMethodForSecondaryAuthentication"),
        "SystemPreferredAuthenticationMethod": sign_in_preferences.get("systemPreferredAuthenticationMethod"),
    }

    human_readable = tableToMarkdown(name=f"Authentication Preferences for {user}", t=default_auth_method, removeNull=True)
    human_readable += f"\n**Default Auth Method:** {default_method}"

    outputs = {"MSGraphUser.AuthMethod(val.User === obj.User)": default_auth_method}

    return CommandResults(outputs=outputs, readable_output=human_readable, raw_response=sign_in_preferences)


def create_client_secret_command(client: MsGraphClient, args: dict, params: dict) -> CommandResults:
    if not argToBoolean(params.get("allow_secret_generators", "False")):
        raise DemistoException(
            '"Allow secret generators commands execution" parameter is not marked, Cannot run this command.'
            "For more information please refer to the integration configuration."
        )
    mfa_app_secret = client.request_mfa_app_secret()
    new_secret_value = mfa_app_secret.get("secretText")
    valid_from = mfa_app_secret.get("startDateTime")
    valid_until = mfa_app_secret.get("endDateTime")
    outputs = {"MFAClientSecret": new_secret_value, "ValidFrom": valid_from, "ValidUntil": valid_until}
    output = "A new client secret has been added. Note you might need to wait 30-60 seconds before the secret will be activated."
    return CommandResults(
        readable_output=output,
        outputs=outputs,
        outputs_prefix="MSGraphUser.MFAClientSecret",
    )


def request_mfa_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Pops a synchronous MFA request for the given user.
    This is the original blocking implementation that waits for user response.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary of arguments, which must include:
            - user_mail (str): The mail of the user to pop the MFA to.
            - timeout (int, optional): Timeout in seconds. Default is 60 seconds.

    Returns:
        CommandResults: Result of the MFA request.
    """
    user_mail = args.get("user_mail", "")
    timeout_val = arg_to_number(args.get("timeout", MAX_TIMEOUT_LIMIT))
    timeout = min(MAX_TIMEOUT_LIMIT, timeout_val) if timeout_val else MAX_TIMEOUT_LIMIT
    access_token = args.get("access_token", "")
    try:
        result = client.push_mfa_notification(user_mail, timeout, access_token)
        return CommandResults(readable_output=result)
    except Exception as e:
        raise DemistoException(f"Failed to pop MFA request for user {user_mail}: {e}")


@suppress_errors_with_404_code
def delete_tap_policy_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Deletes a Temporary Access Pass (TAP) policy for a specified user.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary of arguments, which must include:
            - user_id (str): The ID of the user whose TAP policy is to be deleted.
            - policy_id (str): The ID of the TAP policy to be deleted.

    Returns:
        CommandResults: Delete the Temporary Access Pass (TAP) police associated with a specific user.
    """
    user_id = args.get("user_id")
    policy_id = args.get("policy_id") or args.get(
        "method_id"
    )  # using the same function for msgraph-user-temp-access-pass-method-delete command  # noqa: E501
    client.delete_tap_policy(user_id, policy_id)
    if args.get("policy_id"):
        human_readable = f"Temporary Access Pass Authentication methods policy {policy_id} was successfully deleted."
    else:
        human_readable = (
            f"The user's Temporary Access Pass Authentication Method object id {policy_id} has been successfully deleted."  # noqa: E501
        )

    return CommandResults(readable_output=human_readable)


@suppress_errors_with_404_code
def list_owned_device_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Lists the devices owned by a user.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user_id (str, required): The user ID or user principal name
            - limit (int, optional): Maximum number of results to return
            - next_page (str, optional): URL for the next page of results
            - filter (str, optional): Filter to apply to the results

    Returns:
        CommandResults: The devices owned by the specified user.
    """
    user_id = args.get("user", "")
    next_page = args.get("next_page", "")
    filters = args.get("filter", "")
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))

    devices_data, result_next_page = client.list_owned_devices(next_page, user_id, filters, limit)  # type: ignore

    if not devices_data:
        return CommandResults(readable_output=f"No owned devices found for user {user_id}.")
    devices_readable, devices_outputs = parse_outputs(devices_data)
    # Map the field names to custom headers for human readable output
    field_mapping = AUTH_METHODS_FIELD_MAPPING.get("OWNED_DEVICES", {})
    devices_readable = map_auth_method_fields_to_readable(devices_data, field_mapping)

    headers = ["Device Id", "Azure Device Registration Id", "Device Display Name"]

    metadata = None
    if result_next_page:
        metadata = "To get further results, enter this to the next_page argument:\n" + str(result_next_page)
        # Add NextPage to outputs if it's a list
        if isinstance(devices_outputs, list):
            devices_outputs.insert(0, {"NextPage": result_next_page})

    human_readable = tableToMarkdown(
        name=f"Owned Devices for User {user_id}:", headers=headers, t=devices_readable, removeNull=True, metadata=metadata
    )

    return CommandResults(
        outputs_prefix="MSGraphUser",
        outputs_key_field="ID",
        outputs={"OwnedDevice": devices_outputs, "Id": user_id},
        readable_output=human_readable,
        raw_response=devices_data,
    )


def map_auth_method_fields_to_readable(data, field_mapping: dict):
    """
    Maps authentication method field names to custom human-readable headers.
    Creates a new dictionary/list to avoid modifying the original data.

    Args:
        data: A dictionary or list of dictionaries containing authentication method data.
        field_mapping: A dictionary mapping original field names to custom header names.

    Returns:
        A new data structure with renamed fields for better readability.
    """

    def map_single_item(item):
        """Helper function to map a single dictionary item."""
        mapped_item = {}
        for key, value in item.items():
            # Use the mapping if it exists, otherwise keep the original key
            mapped_item[field_mapping.get(key, key)] = value
        return mapped_item

    if isinstance(data, list):
        return [map_single_item(item) for item in data]
    else:
        return map_single_item(data)


@suppress_errors_with_404_code
def list_fido2_method_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Lists the FIDO2 authentication methods registered to a user, or retrieves a specific method.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user (str, required): The user ID or user principal name
            - method_id (str, optional): The ID of a specific FIDO2 method to retrieve
            - limit (int, optional): Maximum number of results to return when listing

    Returns:
        CommandResults: The FIDO2 authentication methods registered to the specified user.
    """
    user = args.get("user", "")
    method_id = args.get("method_id", "")

    if method_id:
        fido2_data = client.get_fido2_method(user, method_id)
    else:
        fido2_data = client.list_fido2_methods(user)  # type: ignore

    if not fido2_data:
        return CommandResults(readable_output=f"No FIDO2 authentication methods found for user {user}.")

    fido2_readable, fido2_outputs = parse_outputs(fido2_data)

    field_mapping = AUTH_METHODS_FIELD_MAPPING.get("FIDO2", {})
    fido2_readable = map_auth_method_fields_to_readable(fido2_data, field_mapping)

    headers = ["Authentication method ID", "The display name of the key", "Authenticator Attestation GUID"]

    if method_id:
        title = f"FIDO2 Authentication Method {method_id} for User {user}:"
    else:
        title = f"FIDO2 Authentication Methods for User {user}:"

    human_readable = tableToMarkdown(name=title, headers=headers, t=fido2_readable, removeNull=True)

    return CommandResults(
        outputs_prefix="MSGraphUser.FIDO2Method",
        outputs_key_field="ID",
        outputs=fido2_outputs,
        readable_output=human_readable,
        raw_response=fido2_data,
    )


@suppress_errors_with_404_code
def delete_fido2_method_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Deletes a FIDO2 authentication method from a user.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user (str, required): The user ID or user principal name
            - method_id (str, required): The ID of the FIDO2 method to delete

    Returns:
        CommandResults: Confirmation message of the deletion.
    """
    user = args.get("user", "")
    method_id = args.get("method_id", "")

    client.delete_fido2_method(user, method_id)
    human_readable = f"The user's FIDO2 Security Key Authentication Method {method_id} has been successfully deleted."

    return CommandResults(readable_output=human_readable)


@suppress_errors_with_404_code
def list_email_method_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Lists the email authentication methods registered to a user, or retrieves a specific method.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user (str, required): The user ID or user principal name
            - method_id (str, optional): The ID of a specific email method to retrieve

    Returns:
        CommandResults: The email authentication methods registered to the specified user.
    """
    user = args.get("user", "")
    method_id = args.get("method_id", "")

    if method_id:
        email_data = client.get_email_method(user, method_id)
    else:
        email_data = client.list_email_methods(user)

    if not email_data:
        return CommandResults(readable_output=f"No email authentication methods found for user {user}.")

    email_readable, email_outputs = parse_outputs(email_data)

    headers = ["ID", "Email Address"]

    if method_id:
        title = f"Email Authentication Method {method_id} for User {user}:"
    else:
        title = f"Email Authentication Methods for User {user}:"

    human_readable = tableToMarkdown(name=title, headers=headers, t=email_readable, removeNull=True)

    return CommandResults(
        outputs_prefix="MSGraphUser.EmailAuthMethod",
        outputs_key_field="ID",
        outputs=email_outputs,
        readable_output=human_readable,
        raw_response=email_data,
    )


@suppress_errors_with_404_code
def delete_email_method_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Deletes an email authentication method from a user.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user (str, required): The user ID or user principal name
            - method_id (str, required): The ID of the email method to delete

    Returns:
        CommandResults: Confirmation message of the deletion.
    """
    user = args.get("user", "")
    method_id = args.get("method_id", "")

    client.delete_email_method(user, method_id)
    human_readable = f"The user's Email Authentication Method object {method_id} has been successfully deleted."

    return CommandResults(readable_output=human_readable)


@suppress_errors_with_404_code
def list_authenticator_method_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Lists the Microsoft Authenticator authentication methods registered to a user, or retrieves a specific method.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user (str, required): The user ID or user principal name
            - method_id (str, optional): The ID of a specific authenticator method to retrieve
            - limit (int, optional): Maximum number of results to return when listing
            - next_page (str, optional): URL for the next page of results

    Returns:
        CommandResults: The Microsoft Authenticator authentication methods registered to the specified user.
    """
    user = args.get("user", "")
    method_id = args.get("method_id", "")
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    next_page = args.get("next_page", "")

    if method_id:
        authenticator_data = client.get_authenticator_method(user, method_id)
        result_next_page = None
    else:
        authenticator_data, result_next_page = client.list_authenticator_methods(user, limit, next_page)  # type: ignore

    if not authenticator_data:
        return CommandResults(readable_output=f"No Microsoft Authenticator authentication methods found for user {user}.")

    authenticator_readable, authenticator_outputs = parse_outputs(authenticator_data)

    # Map the field names to custom headers for human readable output
    field_mapping = AUTH_METHODS_FIELD_MAPPING.get("AUTHENTICATOR", {})
    authenticator_readable = map_auth_method_fields_to_readable(authenticator_data, field_mapping)

    headers = ["Authentication method ID", "Device Name", "Version of the Authenticator app"]

    if method_id:
        title = f"Microsoft Authenticator Authentication Method {method_id} for User {user}:"
    else:
        title = f"Microsoft Authenticator Authentication Methods for User {user}:"

    metadata = None
    if result_next_page:
        metadata = "To get further results, enter this to the next_page argument:\n" + str(result_next_page)
        # Add NextPage to outputs if it's a list
        if isinstance(authenticator_outputs, list):
            authenticator_outputs.insert(0, {"NextPage": result_next_page})

    human_readable = tableToMarkdown(name=title, headers=headers, t=authenticator_readable, removeNull=True, metadata=metadata)

    return CommandResults(
        outputs_prefix="MSGraphUser.UserAuthMethod",
        outputs_key_field="ID",
        outputs=authenticator_outputs,
        readable_output=human_readable,
        raw_response=authenticator_data,
    )


@suppress_errors_with_404_code
def delete_authenticator_method_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Deletes a Microsoft Authenticator authentication method from a user.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user (str, required): The user ID or user principal name
            - method_id (str, required): The ID of the authenticator method to delete

    Returns:
        CommandResults: Confirmation message of the deletion.
    """
    user = args.get("user", "")
    method_id = args.get("method_id", "")

    client.delete_authenticator_method(user, method_id)
    human_readable = f"Microsoft Authenticator authentication method {method_id} was successfully deleted for user {user}."

    return CommandResults(readable_output=human_readable)


@suppress_errors_with_404_code
def list_phone_method_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Lists the phone authentication methods registered to a user, or retrieves a specific method.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user (str, required): The user ID or user principal name
            - method_id (str, optional): The ID of a specific phone method to retrieve
            - next_page (str, optional): URL for the next page of results

    Returns:
        CommandResults: The phone authentication methods registered to the specified user.
    """
    user = args.get("user", "")
    method_id = args.get("method_id", "")
    next_page = args.get("next_page", "")

    if method_id:
        phone_data = client.get_phone_method(user, method_id)
        result_next_page = None
    else:
        phone_data, result_next_page = client.list_phone_methods(user, next_page)

    if not phone_data:
        return CommandResults(readable_output=f"No phone authentication methods found for user {user}.")

    phone_readable, phone_outputs = parse_outputs(phone_data)

    # Map the field names to custom headers for human readable output
    field_mapping = AUTH_METHODS_FIELD_MAPPING.get("PHONE", {})
    phone_readable = map_auth_method_fields_to_readable(phone_data, field_mapping)

    headers = ["Phone ID", "Phone Number", "Phone Type", "Sms SignIn State"]

    if method_id:
        title = f"Phone Authentication Method {method_id} for User {user}:"
    else:
        title = f"Phone Authentication Methods for User {user}:"

    metadata = None
    if result_next_page:
        metadata = "To get further results, enter this to the next_page argument:\n" + str(result_next_page)
        # Add NextPage to outputs if it's a list
        if isinstance(phone_outputs, list):
            phone_outputs.insert(0, {"NextPage": result_next_page})

    human_readable = tableToMarkdown(name=title, headers=headers, t=phone_readable, removeNull=True, metadata=metadata)

    return CommandResults(
        outputs_prefix="MSGraphUser.PhoneAuthMethod",
        outputs_key_field="Id",
        outputs=phone_outputs,
        readable_output=human_readable,
        raw_response=phone_data,
    )


@suppress_errors_with_404_code
def delete_phone_method_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Deletes a phone authentication method from a user.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user (str, required): The user ID or user principal name
            - method_id (str, required): The ID of the phone method to delete

    Returns:
        CommandResults: Confirmation message of the deletion.
    """
    user = args.get("user", "")
    method_id = args.get("method_id", "")

    client.delete_phone_method(user, method_id)
    human_readable = f"The user's phone authentication method object id {method_id} has been successfully deleted."

    return CommandResults(readable_output=human_readable)


@suppress_errors_with_404_code
def list_software_oath_method_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Lists the software OATH authentication methods registered to a user, or retrieves a specific method.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user (str, required): The user ID or user principal name
            - method_id (str, optional): The ID of a specific software OATH method to retrieve

    Returns:
        CommandResults: The software OATH authentication methods registered to the specified user.
    """
    user = args.get("user", "")
    method_id = args.get("method_id", "")

    if method_id:
        software_oath_data = client.get_software_oath_method(user, method_id)
    else:
        software_oath_data = client.list_software_oath_methods(user)

    if not software_oath_data:
        return CommandResults(readable_output=f"No software OATH authentication methods found for user {user}.")

    software_oath_readable, software_oath_outputs = parse_outputs(software_oath_data)

    # Map the field names to custom headers for human readable output
    field_mapping = AUTH_METHODS_FIELD_MAPPING.get("SOFTWARE_OATH", {})
    software_oath_readable = map_auth_method_fields_to_readable(software_oath_data, field_mapping)

    headers = ["Authentication method ID"]

    if method_id:
        title = f"Software OATH Authentication Method {method_id} for User {user}:"
    else:
        title = f"Software OATH Authentication Methods for User {user}:"

    human_readable = tableToMarkdown(name=title, headers=headers, t=software_oath_readable, removeNull=True)

    return CommandResults(
        outputs_prefix="MSGraphUser.SoftOathAuthMethod",
        outputs_key_field="ID",
        outputs=software_oath_outputs,
        readable_output=human_readable,
        raw_response=software_oath_data,
    )


@suppress_errors_with_404_code
def delete_software_oath_method_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Deletes a software OATH authentication method from a user.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user (str, required): The user ID or user principal name
            - method_id (str, required): The ID of the software OATH method to delete

    Returns:
        CommandResults: Confirmation message of the deletion.
    """
    user = args.get("user", "")
    method_id = args.get("method_id", "")

    client.delete_software_oath_method(user, method_id)
    human_readable = f"The user's Software OATH token authentication method object id {method_id} has been successfully deleted."

    return CommandResults(readable_output=human_readable)


@suppress_errors_with_404_code
def list_temp_access_pass_method_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Lists the temporary access passwords method from a user.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user_id (str, required): The user ID or user principal name
            - method_id (str, optional): The ID of a specific software OATH method to retrieve

    Returns:
        CommandResults: The devices owned by the specified user.
    """
    user_id = args.get("user", "")
    method_id = args.get("method_id", "")

    if method_id:
        temp_access_pass_data = client.get_temp_access_pass_method(user_id, method_id)
    else:
        temp_access_pass_data = client.list_tap_policy(user_id)

    if not temp_access_pass_data:
        return CommandResults(readable_output=f"No Windows Hello for Business authentication methods found for user {user_id}.")

    temp_access_pass_readable, temp_access_pass_outputs = parse_outputs(temp_access_pass_data)

    # Map the field names to custom headers for human readable output
    field_mapping = AUTH_METHODS_FIELD_MAPPING.get("TEMP_ACCESS_PASS", {})
    temp_access_pass_readable = map_auth_method_fields_to_readable(temp_access_pass_data, field_mapping)

    headers = ["Temporary Access Pass ID", "Authentication method state"]

    if method_id:
        title = f"WTemporary Access Pass Method {method_id} for User {user_id}:"
    else:
        title = f"Temporary Access Pass Methods for User {user_id}:"

    human_readable = tableToMarkdown(name=title, headers=headers, t=temp_access_pass_readable, removeNull=True)

    return CommandResults(
        outputs_prefix="MSGraphUser.TempAccessPassAuthMethod",
        outputs_key_field="ID",
        outputs=temp_access_pass_outputs,
        readable_output=human_readable,
        raw_response=temp_access_pass_data,
    )


@suppress_errors_with_404_code
def list_windows_hello_method_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Lists the Windows Hello for Business authentication methods registered to a user, or retrieves a specific method.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user (str, required): The user ID or user principal name
            - method_id (str, optional): The ID of a specific Windows Hello method to retrieve

    Returns:
        CommandResults: The Windows Hello for Business authentication methods registered to the specified user.
    """
    user = args.get("user", "")
    method_id = args.get("method_id", "")

    if method_id:
        windows_hello_data = client.get_windows_hello_method(user, method_id)
    else:
        windows_hello_data = client.list_windows_hello_methods(user)

    if not windows_hello_data:
        return CommandResults(readable_output=f"No Windows Hello for Business authentication methods found for user {user}.")

    windows_hello_readable, windows_hello_outputs = parse_outputs(windows_hello_data)

    # Map the field names to custom headers for human readable output
    field_mapping = AUTH_METHODS_FIELD_MAPPING.get("WINDOWS_HELLO", {})
    windows_hello_readable = map_auth_method_fields_to_readable(windows_hello_data, field_mapping)

    headers = ["Windows Hello Method ID", "Display Name", "Method Key Strength"]

    if method_id:
        title = f"Windows Hello for Business Authentication Method {method_id} for User {user}:"
    else:
        title = f"Windows Hello for Business Authentication Methods for User {user}:"

    human_readable = tableToMarkdown(name=title, headers=headers, t=windows_hello_readable, removeNull=True)

    return CommandResults(
        outputs_prefix="MSGraphUser.WindowsHelloAuthMethod",
        outputs_key_field="ID",
        outputs=windows_hello_outputs,
        readable_output=human_readable,
        raw_response=windows_hello_data,
    )


@suppress_errors_with_404_code
def delete_windows_hello_method_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Deletes a Windows Hello for Business authentication method from a user.

    Args:
        client (MsGraphClient): The Microsoft Graph client used to make the API request.
        args (dict): A dictionary containing the input arguments:
            - user (str, required): The user ID or user principal name
            - method_id (str, required): The ID of the Windows Hello method to delete

    Returns:
        CommandResults: Confirmation message of the deletion.
    """
    user = args.get("user", "")
    method_id = args.get("method_id", "")

    client.delete_windows_hello_method(user, method_id)
    human_readable = f"The Windows Hello For Business Authentication Method object id {method_id} has been successfully deleted."

    return CommandResults(readable_output=human_readable)


def create_zip_with_password(generated_tap_password: str, zip_password: str):
    """
    Creates a password-protected zip file containing the TAP policy password.

    Args:
        generated_tap_password (str): The TAP policy password (confidential).
        zip_password (str): A password for the password-protected zip file that will include the password of the new TAP.

    Returns:
        return_results
    """
    zip_file_name = "TAPPolicyInfo.zip"

    try:
        demisto.debug("Creating password-protected zip file")
        file_res = generate_password_protected_zip(zip_file_name, zip_password, generated_tap_password)

    except Exception as e:
        raise DemistoException(f"Could not generate zip file. Error:\n{str(e)}")

    finally:
        if os.path.exists(zip_file_name):
            os.remove(zip_file_name)

    return_results(file_res)


def generate_password_protected_zip(zip_file_name, zip_password, generated_tap_password) -> dict:
    """
    Generates a password-protected ZIP file containing the TAP policy password.

    Args:
        zip_file_name (str): The name of the ZIP file to be created.
        zip_password (str): The password for the password-protected ZIP file.
        generated_tap_password (str): The TAP policy password to include in the ZIP file.

    Returns:
        dict: A file result object containing the ZIP file content.
    """
    with AESZipFile(zip_file_name, mode="w", compression=ZIP_DEFLATED, encryption=WZ_AES) as zf:
        zf.pwd = bytes(zip_password, "utf-8")
        zf.writestr("TAPPolicyPass.txt", generated_tap_password)

    with open(zip_file_name, "rb") as zip_file:
        zip_content = zip_file.read()

    return fileResult(zip_file_name, zip_content)


def main():  # pragma: no cover
    params: dict = demisto.params()
    azure_cloud = get_azure_cloud(params, "MicrosoftGraphUser")
    url = urljoin(azure_cloud.endpoints.microsoft_graph_resource_id, f"/{API_VERSION}/")
    tenant = params.get("creds_tenant_id", {}).get("password", "") or params.get("tenant_id", "")
    auth_and_token_url = params.get("creds_auth_id", {}).get("password", "") or params.get("auth_id", "")
    enc_key = params.get("creds_enc_key", {}).get("password", "") or params.get("enc_key", "")
    verify = not params.get("insecure", False)
    redirect_uri = params.get("redirect_uri", "")
    auth_code = params.get("creds_auth_code", {}).get("password", "") or params.get("auth_code", "")
    proxy = params.get("proxy", False)
    handle_error = argToBoolean(params.get("handle_error", "true"))
    certificate_thumbprint = params.get("creds_certificate", {}).get("identifier", "") or params.get("certificate_thumbprint", "")
    private_key = replace_spaces_in_credential(params.get("creds_certificate", {}).get("password", "")) or params.get(
        "private_key", ""
    )
    managed_identities_client_id = get_azure_managed_identities_client_id(params)
    self_deployed: bool = params.get("self_deployed", False) or managed_identities_client_id is not None

    if not managed_identities_client_id:
        if not self_deployed and not enc_key:
            raise DemistoException(
                "Key must be provided. For further information see "
                "https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication"
            )
        if self_deployed and auth_code and not redirect_uri:
            raise DemistoException(
                "Please provide both Application redirect URI and Authorization code "
                "for Authorization Code flow, or None for the Client Credentials flow"
            )
        elif not enc_key and not (certificate_thumbprint and private_key):
            raise DemistoException("Key or Certificate Thumbprint and Private Key must be provided.")

    commands = {
        "msgraph-user-test": test_function,
        "test-module": test_function,
        "msgraph-user-unblock": unblock_user_command,
        "msgraph-user-terminate-session": disable_user_account_command,
        "msgraph-user-account-disable": disable_user_account_command,
        "msgraph-user-update": update_user_command,
        "msgraph-user-force-reset-password": force_reset_password,
        "msgraph-user-change-password": change_password_user_saas_command,
        "msgraph-user-change-password-on-premise": change_password_user_on_premise_command,
        "msgraph-user-delete": delete_user_command,
        "msgraph-user-create": create_user_command,
        "msgraph-user-get-delta": get_delta_command,
        "msgraph-user-get": get_user_command,
        "msgraph-user-get-groups": get_groups_command,
        "msgraph-user-get-auth-methods": get_auth_methods_command,
        "msgraph-user-list": list_users_command,
        "msgraph-direct-reports": get_direct_reports_command,
        "msgraph-user-get-manager": get_manager_command,
        "msgraph-user-assign-manager": assign_manager_command,
        "msgraph-user-session-revoke": revoke_user_session_command,
        "msgraph-user-tap-policy-list": list_tap_policy_command,
        "msgraph-user-tap-policy-create": create_tap_policy_command,
        "msgraph-user-tap-policy-delete": delete_tap_policy_command,
        "msgraph-user-owned-devices-list": list_owned_device_command,
        "msgraph-user-fido2-method-list": list_fido2_method_command,
        "msgraph-user-fido2-method-delete": delete_fido2_method_command,
        "msgraph-user-email-method-list": list_email_method_command,
        "msgraph-user-email-method-delete": delete_email_method_command,
        "msgraph-user-authenticator-method-list": list_authenticator_method_command,
        "msgraph-user-authenticator-method-delete": delete_authenticator_method_command,
        "msgraph-user-phone-method-list": list_phone_method_command,
        "msgraph-user-phone-method-delete": delete_phone_method_command,
        "msgraph-user-software-oath-method-list": list_software_oath_method_command,
        "msgraph-user-software-oath-method-delete": delete_software_oath_method_command,
        "msgraph-user-temp-access-pass-method-list": list_temp_access_pass_method_command,
        "msgraph-user-temp-access-pass-method-delete": delete_tap_policy_command,  # Points to an existing command due to design choices CIAC-12953  # noqa: E501
        "msgraph-user-windows-hello-method-list": list_windows_hello_method_command,
        "msgraph-user-windows-hello-method-delete": delete_windows_hello_method_command,
        "msgraph-user-request-mfa": request_mfa_command,
        "msgraph-user-get-user-default-auth-method": get_default_auth_methods_command,
    }
    command = demisto.command()
    LOG(f"Command being called is {command}")

    try:
        client: MsGraphClient = MsGraphClient(
            tenant_id=tenant,
            auth_id=auth_and_token_url,
            enc_key=enc_key,
            app_name=APP_NAME,
            base_url=url,
            verify=verify,
            proxy=proxy,
            self_deployed=self_deployed,
            redirect_uri=redirect_uri,
            auth_code=auth_code,
            handle_error=handle_error,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            azure_cloud=azure_cloud,
            managed_identities_client_id=managed_identities_client_id,
        )
        args = demisto.args()
        if command == "msgraph-user-generate-login-url":
            return_results(generate_login_url(client.ms_client))
        elif command == "msgraph-user-auth-reset":
            return_results(reset_auth())
        elif command == "msgraph-user-change-password-on-premise":  # polling command needs (args, client)
            return_results(commands[command](args, client))
        elif command == "msgraph-user-create-mfa-client-secret":
            return_results(create_client_secret_command(client, args, params))
        elif command == "msgraph-user-create-mfa-client-access-token":
            return_results(create_access_token_command(client, args, params))
        else:
            return_results(commands[command](client, args))

    except Exception as err:
        return_error(str(err))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
