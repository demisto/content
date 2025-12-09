import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
import json
import urllib3
from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class AuthenticationModel:
    def __init__(self, username="", password="", server_url="", error=None, platform_login=False, token=None,
                 token_expiration=None, vault_url=None, vault_type=None):
        self.user_name = username
        self.password = password
        self.server_url = server_url
        self.error = error
        self.platform_login = platform_login
        self.token = token
        self.token_expiration = token_expiration
        self.vault_url = vault_url
        self.vault_type = vault_type

    def set_platform_login(self, platform_login: bool):
        self.platform_login = platform_login

    def set_error(self, error: str):
        self.error = error

    def set_token(self, token: str):
        self.token = token

    def set_token_expiration(self, token_expiration):
        self.token_expiration = token_expiration

    def set_vault_url(self, vault_url: str):
        self.vault_url = vault_url

    def set_vault_type(self, vault_type: str):
        self.vault_type = vault_type


class AuthenticationService:

    def authenticate_async(self, auth_model: AuthenticationModel):
        try:
            base = auth_model.server_url.rstrip("/")
            ss_url = f"{base}/api/v1/healthcheck"
            pf_url = f"{base}/health"

            if self.check_json_response_async(ss_url):
                auth_model.set_platform_login(False)
                return auth_model
            if self.check_json_response_async(pf_url):
                auth_model.set_platform_login(True)
                return PlatformLogin().platform_authentication(auth_model)
            error_model = AuthenticationModel()
            error_model.set_error(f"Invalid Server URL {auth_model.server_url}")
            return error_model

        except Exception as e:
            raise RuntimeError(f"Authentication failed: {str(e)}")

    def check_json_response_async(self, url):
        try:
            response = requests.get(url, timeout=3)

            if not response.text:
                return False

            body = response.text
            try:
                json_data = response.json()
                if isinstance(json_data, dict) and json_data.get("healthy") is True:
                    return True
            except Exception:
                pass
            return "Healthy" in body or "healthy" in body
        except Exception:
            return False


class PlatformLogin:
    def __init__(self):
        pass

    def platform_authentication(self, auth_model: AuthenticationModel):
        try:
            # 1. ACCESS TOKEN
            response = self.get_access_token(auth_model)
            if response.status_code != 200:
                return self.handle_error_response(response.text)

            auth_data = response.json()
            auth_model.set_token(auth_data.get("access_token"))
            auth_model.set_token_expiration(auth_data.get("expires_in"))

            # 2. GET VAULTS
            response = self.get_vaults(auth_model, auth_model.token)
            if response.status_code != 200:
                return self.handle_error_response(response.text)

            vaults = response.json().get("vaults", [])
            vault = next((v for v in vaults if v["isDefault"] and v["isActive"]), None)

            if not vault:
                return self.handle_error_response("No active default vault found")

            auth_model.set_vault_url(vault["connection"]["url"])
            auth_model.set_vault_type(vault["type"])
            return auth_model

        except Exception as e:
            raise Exception(f"Platform authentication error: {e}")

    def handle_error_response(self, msg):
        return AuthenticationModel(error=msg, platform_login=True)

    def get_access_token(self, auth_model: AuthenticationModel):
        url = auth_model.server_url.rstrip("/") + "/identity/api/oauth2/token/xpmplatform"
        body = (
            f"grant_type=client_credentials&client_id={auth_model.user_name}"
            f"&client_secret={auth_model.password}&scope=xpmheadless"
        )
        return requests.post(url, headers={"Content-Type": "application/x-www-form-urlencoded"}, data=body, verify=True)

    def get_vaults(self, auth_model: AuthenticationModel, token):
        url = auth_model.server_url.rstrip("/") + "/vaultbroker/api/vaults"
        headers = {"Authorization": f"Bearer {token}"}
        return requests.get(url, headers=headers, verify=True)


def is_platform_or_ss(url, username, password):
    model = AuthenticationModel(username, password, url)
    service = AuthenticationService()
    return service.authenticate_async(model)


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, server_url: str, username: str, password: str, proxy: bool, verify: bool):
        super().__init__(base_url=server_url, proxy=proxy, verify=verify)
        self._username = username
        self._password = password
        self._platform_url = None
        self._headers = {}
        self._token = self.authenticate()

    def authenticate(self):
        authentication_model = is_platform_or_ss(self._base_url, self._username, self._password)
        if authentication_model.platform_login:
            if authentication_model.error:
                raise Exception(authentication_model.error)
            self._platform_url = self._base_url
            self._token = authentication_model.token
            self._base_url = authentication_model.vault_url
            self._headers = {'Authorization': f'Bearer {self._token}', 'Content-Type': 'application/json'}
            return self._token
        else:
            self._token = self._generate_token()
            self._headers = {'Authorization': self._token, 'Content-Type': 'application/json'}
            return self._token

    def _generate_token(self) -> str:
        """Generate an Access token using the user name and password
        :return: valid token
        """
        body = {
            "username": self._username,
            "password": self._password,
            "grant_type": "password"
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        return "Bearer " + (self._http_request("POST", "/oauth2/token", headers=headers, data=body)).get('access_token')

    def getPasswordById(self, secret_id: str, autoComment: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/fields/password"
        params = {
            "autoComment": autoComment
        }
        return self._http_request("GET", url_suffix, params=params)

    def getUsernameById(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/fields/username"
        return self._http_request("GET", url_suffix)

    def getSecret(self, secret_id: str, autocommit: str = '') -> str:
        params = {
            "autocomment": autocommit
        }
        url_suffix = "/api/v1/secrets/" + str(secret_id)
        retries = 3
        return self._http_request("GET", url_suffix, params=params, retries=retries)

    def searchSecretIdByName(self, search_name: str) -> list:
        url_suffix = "/api/v1/secrets/lookup?filter.searchText=" + search_name
        response = self._http_request("GET", url_suffix).get('records')
        idSecret = argToList(response)
        search_id = []

        if idSecret:
            for element in idSecret:
                getID = element.get('id')
                search_id.append(getID)

        return search_id

    def searchSecret(self, **kwargs) -> list:
        count_params = len(kwargs)
        params = {}
        if count_params > 0:
            for key, value in kwargs.items():
                key = key.replace('_', '.')
                key = key.replace("sortBy_", "sortBy[0]_")
                params[key] = value

        response = self._http_request("GET", url_suffix="/api/v1/secrets", params=params).get("records")
        idSecret = list(map(lambda x: x.get('id'), response))
        return idSecret

    def updateSecretPassword(self, secret_id: str, new_password: str, auto_comment: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/fields/password"
        body = {
            "id": secret_id,
            "value": new_password
        }
        params = {
            "autoComment": auto_comment
        }
        return self._http_request("PUT", url_suffix, params=params, json_data=body)

    def secret_checkout(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/check-out"
        return self._http_request("POST", url_suffix)

    def secret_checkin(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/check-in"

        return self._http_request("POST", url_suffix)

    def secretChangePassword(self, secret_id: str, newPassword: str, autoComment: str) -> str:
        body = {
            "newPassword": newPassword
        }
        params = {
            "autoComment": autoComment
        }

        return self._http_request("POST", url_suffix="/api/v1/secrets/" + str(
            secret_id) + "/change-password", params=params, json_data=body)

    def secretCreate(self, name: str, secret_template_id: str, **kwargs) -> str:
        secretjson = {'name': name, 'secretTemplateId': secret_template_id, 'items': []}  # type: Dict[str, Any]

        for key, value in kwargs.items():
            JSON = {}
            if key == 'domain_item':
                JSON['fieldName'] = 'Domain'
                JSON['itemValue'] = value
                JSON['slug'] = 'domain'
                secretjson['items'].append(JSON)

            elif key == 'machine_item':
                JSON['fieldName'] = 'Machine'
                JSON['itemValue'] = value
                JSON['slug'] = 'machine'
                secretjson['items'].append(JSON)

            elif key == 'username_item':
                JSON['fieldName'] = 'Username'
                JSON['itemValue'] = value
                JSON['slug'] = 'username'
                secretjson['items'].append(JSON)

            elif key == 'password_item':
                JSON['fieldName'] = 'Password'
                JSON['itemValue'] = value
                JSON['slug'] = 'password'
                JSON['isPassword'] = "true"
                secretjson['items'].append(JSON)

            elif key == 'notes_item':
                JSON['fieldName'] = 'Notes'
                JSON['itemValue'] = value
                JSON['slug'] = 'notes'
                JSON['isNotes'] = "true"
                secretjson['items'].append(JSON)

            else:
                secretjson[key] = value

        return self._http_request("POST", url_suffix="/api/v1/secrets", json_data=secretjson)

    def secretDelete(self, id: int, auto_comment: str) -> str:
        params = {
            "autoComment": auto_comment
        }

        return self._http_request("DELETE", url_suffix="/api/v1/secrets/" + str(id), params=params)

    def folderCreate(self, name: str, type: int, parent: int, **kwargs) -> str:
        url_suffix = "/api/v1/folders"

        body = {
            "folderName": name,
            "folderTypeId": type,
            "parentFolderId": parent,
        }

        for key, value in kwargs.items():
            body[key] = value
        return self._http_request("POST", url_suffix, json_data=body)

    def searchFolder(self, search_folder: str) -> list:
        url_suffix = "/api/v1/folders/lookup?filter.searchText=" + search_folder

        response_records = self._http_request("GET", url_suffix).get('records')
        idfolder = list(map(lambda x: x.get('id'), response_records))
        return idfolder

    def folderDelete(self, folder_id: str) -> str:
        url_suffix = "/api/v1/folders/" + folder_id

        return self._http_request("DELETE", url_suffix)

    def folderUpdate(self, id: str, **kwargs) -> str:
        # Get exist folder
        response = self._http_request("GET", url_suffix="/api/v1/folders/" + str(id))

        for key, value in kwargs.items():
            response[key] = value
        return self._http_request("PUT", url_suffix="/api/v1/folders/" + str(id), json_data=response)

    def userCreate(self, **kwargs) -> str:
        if self._platform_url:
            raise DemistoException(
                "Secret Server commands cannot run against a Delinea Platform tenant URL."
                "Please configure a Secret Server instance URL (cloud or on-prem) to use Secret Server operations"
            )
        bodyJSON = {}

        for key, value in kwargs.items():
            bodyJSON[key] = value

        return self._http_request("POST", url_suffix="/api/v1/users", json_data=bodyJSON)

    def userSearch(self, **kwargs) -> str:
        if self._platform_url:
            raise DemistoException(
                "Secret Server commands cannot run against a Delinea Platform tenant URL."
                "Please configure a Secret Server instance URL (cloud or on-prem) to use Secret Server operations"
            )
        params = {}
        count_params = len(kwargs)
        if count_params > 0:
            for key, value in kwargs.items():
                key = key.replace('_', '.')
                key = key.replace("sortBy_", "sortBy[0]_")
                params[key] = value

        return (self._http_request("GET", url_suffix="/api/v1/users", params=params)).get('records')

    def userUpdate(self, id: str, **kwargs) -> str:
        if self._platform_url:
            raise DemistoException(
                "Secret Server commands cannot run against a Delinea Platform tenant URL."
                "Please configure a Secret Server instance URL (cloud or on-prem) to use Secret Server operations"
            )
        # 2 method
        response = self._http_request("GET", url_suffix="/api/v1/users/" + str(id))

        for key, value in kwargs.items():
            response[key] = value

        return self._http_request("PUT", url_suffix="/api/v1/users/" + str(id), json_data=response)

    def userDelete(self, id: str) -> str:
        if self._platform_url:
            raise DemistoException(
                "Secret Server commands cannot run against a Delinea Platform tenant URL."
                "Please configure a Secret Server instance URL (cloud or on-prem) to use Secret Server operations"
            )
        return self._http_request("DELETE", url_suffix="/api/v1/users/" + str(id))

    def getuser(self) -> str:
        if self._platform_url:
            raise DemistoException(
                "Secret Server commands cannot run against a Delinea Platform tenant URL."
                "Please configure a Secret Server instance URL (cloud or on-prem) to use Secret Server operations"
            )
        url_suffix = "/api/v1/users"
        return self._http_request("GET", url_suffix)

    def platform_user_create(self, **kwargs) -> str:
        if not self._platform_url:
            raise DemistoException(
                "Platform commands cannot run against a Secret Server URL."
                "Please configure a valid Delinea Platform tenant URL to use Platform operations"
            )
        bodyJSON = {}

        for key, value in kwargs.items():
            bodyJSON[key] = value
        return self._http_request("POST", json_data=bodyJSON,
                                  full_url=f"{self._platform_url}/identity/api/CDirectoryService/CreateUser")

    def platform_user_update(self, **kwargs) -> str:
        if not self._platform_url:
            raise DemistoException(
                "Platform commands cannot run against a Secret Server URL."
                "Please configure a valid Delinea Platform tenant URL to use Platform operations"
            )
        bodyJSON = {}

        for key, value in kwargs.items():
            bodyJSON[key] = value
        return self._http_request("POST", json_data=bodyJSON,
                                  full_url=f"{self._platform_url}/identity/api/CDirectoryService/ChangeUser")

    def platform_user_delete(self, id: str) -> str:
        if not self._platform_url:
            raise DemistoException(
                "Platform commands cannot run against a Secret Server URL."
                "Please configure a valid Delinea Platform tenant URL to use Platform operations"
            )
        return self._http_request("POST", full_url=f"{self._platform_url}/identity/api/UserMgmt/RemoveUser",
                                  params={"id": str(id)})

    def get_platform_user(self, user_id: str) -> dict:
        if not self._platform_url:
            raise DemistoException(
                "Platform commands cannot run against a Secret Server URL."
                "Please configure a valid Delinea Platform tenant URL to use Platform operations"
            )
        full_url = f"{self._platform_url}/identity/api/users/{user_id}"
        return self._http_request(
            "GET",
            full_url=full_url,
            params={"api-version": "3.0"}
        )

    def get_all_platform_users(self, **kwargs) -> dict:
        if not self._platform_url:
            raise DemistoException(
                "Platform commands cannot run against a Secret Server URL."
                "Please configure a valid Delinea Platform tenant URL to use Platform operations"
            )
        params = {}
        params["pageSize"] = kwargs.get("pageSize", 1000)
        for key, value in kwargs.items():
            if value is None or key == "pageSize":
                continue
            formatted_key = key.replace("_", ".")
            params[formatted_key] = value
        params["api-version"] = "3.0"
        return self._http_request("GET", full_url=f"{self._platform_url}/identity/api/users", params=params)

    def get_platform_user_searchbytext(self, **kwargs) -> dict:
        if not self._platform_url:
            raise DemistoException(
                "Platform commands cannot run against a Secret Server URL."
                "Please configure a valid Delinea Platform tenant URL to use Platform operations"
            )
        params = {}
        params["pageSize"] = kwargs.get("pageSize", 1000)
        for key, value in kwargs.items():
            if value is None or key == "pageSize":
                continue
            formatted_key = key.replace("_", ".")
            params[formatted_key] = value
        params["api-version"] = "3.0"
        return self._http_request("GET", full_url=f"{self._platform_url}/identity/api/users", params=params)


def test_module(client) -> str:
    # Test for get authority
    if client._token == '':
        return "Failed to get authorization token. Check you credential and access to Secret Server.'"

    return "ok"


def secret_password_get_command(client, secret_id: str = '', autoComment: str = ''):
    secret_password = client.getPasswordById(secret_id, autoComment)
    markdown = tableToMarkdown('Password for secret',
                               {'Secret ID': secret_id, 'Password': secret_password})

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Delinea.Secret.Password',
        outputs_key_field="secret_password",
        raw_response=secret_password,
        outputs=secret_password
    )


def secret_username_get_command(client, secret_id: str = ''):
    secret_username = client.getUsernameById(secret_id)
    markdown = tableToMarkdown('Username for secret',
                               {'Secret ID': secret_id, 'Password': secret_username})

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Delinea.Secret.Username',
        outputs_key_field="secret_username",
        raw_response=secret_username,
        outputs=secret_username
    )


def secret_get_command(client, secret_id: str = '', autoComment: str = ''):
    secret = client.getSecret(secret_id, autoComment)
    markdown = tableToMarkdown('Full secret object', secret)
    markdown += tableToMarkdown('Items for secret', secret['items'])

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Delinea.Secret',
        outputs_key_field="secret",
        raw_response=secret,
        outputs=secret
    )


def secret_server_user_get_command(client):
    user = client.getuser()
    markdown = tableToMarkdown('All user list', user)
    markdown += tableToMarkdown('Records for user', user['records'])

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Delinea.Secret.Server.User',
        outputs_key_field="user",
        raw_response=user,
        outputs=user
    )


def secret_search_name_command(client, search_name: str = ''):
    search_id = client.searchSecretIdByName(search_name)
    markdown = tableToMarkdown('Retrieves IDs for secret name', search_id, headers=['Secret id'])

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Id",
        outputs_key_field="search_id",
        raw_response=search_id,
        outputs=search_id
    )


def secret_search_command(client, **kwargs):
    search_result = client.searchSecret(**kwargs)
    if not search_result:
        markdown = "No secrets found matching the provided search criteria."
    else:
        markdown = tableToMarkdown(
            'Secret Search Results',
            search_result,
            headers=['id''name']
        )

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Secret",
        outputs_key_field="search_secret",
        raw_response=search_result,
        outputs=search_result
    )


def secret_password_update_command(client, secret_id: str = '', newpassword: str = '', autoComment: str = ''):
    secret_newpassword = client.updateSecretPassword(secret_id, newpassword, autoComment)
    markdown = tableToMarkdown('New password is set for secret',
                               {'Secret ID': secret_id, 'New password': newpassword})

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Newpassword",
        outputs_key_field="secret_newpassword",
        raw_response=secret_newpassword,
        outputs=secret_newpassword
    )


def secret_checkout_command(client, secret_id: str = ''):
    secret_checkout = client.secret_checkout(secret_id)
    if len(secret_checkout.get('responseCodes')) == 0:
        markdown = 'Checkout Success\n'
    else:
        markdown = tableToMarkdown('Check out secret', secret_checkout)
    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Checkout",
        outputs_key_field="secret_checkout",
        raw_response=secret_checkout,
        outputs=secret_checkout
    )


def secret_checkin_command(client, secret_id: str = ''):
    secret_checkin = client.secret_checkin(secret_id)
    markdown = tableToMarkdown('Check in secret detail', secret_checkin)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Checkin",
        outputs_key_field="secret_checkin",
        raw_response=secret_checkin,
        outputs=secret_checkin
    )


def secret_create_command(client, name: str = '', secretTemplateId: int = 0, **kwargs):
    secret = client.secretCreate(name, secretTemplateId, **kwargs)
    markdown = tableToMarkdown('New secret created', secret)
    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Create",
        outputs_key_field="secret",
        raw_response=secret,
        outputs=secret
    )


def secret_delete_command(client, id: int = 0, autoComment: str = ''):
    delete = client.secretDelete(id, autoComment)
    markdown = tableToMarkdown('Secret deleted', delete)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Deleted",
        outputs_key_field="delete",
        raw_response=delete,
        outputs=delete
    )


def folder_create_command(client, foldername: str = '', foldertypeid: int = 1, parentfolderid: int = 1, **kwargs):
    folder = client.folderCreate(foldername, foldertypeid, parentfolderid, **kwargs)
    markdown = tableToMarkdown('New folder created', folder)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Folder.Create",
        outputs_key_field="folder",
        raw_response=folder,
        outputs=folder
    )


def folder_search_command(client, foldername: str = ''):
    folder_id = client.searchFolder(foldername)
    markdown = tableToMarkdown('Folder Search Results', folder_id, headers=['id'])

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Folder.Id",
        outputs_key_field="folder_id",
        raw_response=folder_id,
        outputs=folder_id
    )


def folder_update_command(client, id: str = '', **kwargs):
    folder = client.folderUpdate(id, **kwargs)
    markdown = tableToMarkdown('Folder Updated', folder)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Folder.Update",
        outputs_key_field="folder",
        raw_response=folder,
        outputs=folder
    )


def folder_delete_command(client, folder_id: str = ''):
    folder = client.folderDelete(folder_id)
    markdown = tableToMarkdown('Folder deleted', folder)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Folder.Delete",
        outputs_key_field="folder",
        raw_response=folder,
        outputs=folder
    )


def secret_server_user_create_command(client, **kwargs):
    user = client.userCreate(**kwargs)
    markdown = tableToMarkdown('New user created in Secret Server', user)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Server.User.Create",
        outputs_key_field="user",
        raw_response=user,
        outputs=user
    )


def secret_server_user_search_command(client, **kwargs):
    user = client.userSearch(**kwargs)
    markdown = tableToMarkdown('Search Secret Server user', user)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Server.User.Search",
        outputs_key_field="user",
        raw_response=user,
        outputs=user
    )


def secret_server_user_update_command(client, id: str = '', **kwargs):
    user = client.userUpdate(id, **kwargs)
    markdown = tableToMarkdown('Updated Secret Server user', user)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Server.User.Update",
        outputs_key_field="user",
        raw_response=user,
        outputs=user
    )


def platform_user_create_command(client, **kwargs):
    user = client.platform_user_create(**kwargs)
    success = user.get("success", False)
    if success:
        markdown = tableToMarkdown('New user created in Platform', user)
    else:
        error_message = user.get("Message") or "Unknown error occurred."
        markdown = f"user creation failed.\n**Reason:** {error_message}"

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Platform.User.Create",
        outputs_key_field="user",
        raw_response=user,
        outputs=user
    )


def platform_user_get_command(client, userUuidOrUpn: str = ""):
    user = client.get_platform_user(userUuidOrUpn)
    markdown = tableToMarkdown('User details', user)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Delinea.Platform.User.Get',
        outputs_key_field='uuid',
        raw_response=user,
        outputs=user
    )


def platform_get_all_users_command(client, **kwargs):
    users = client.get_all_platform_users(**kwargs)
    user_list = users.get("_embedded", {}).get("users", [])
    markdown = tableToMarkdown('Platform User Search Results', user_list)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Delinea.Platform.Get.All.Users',
        outputs_key_field='uuid',
        raw_response=users,
        outputs=user_list
    )


def platform_get_user_searchbytext_command(client, **kwargs):
    users = client.get_platform_user_searchbytext(**kwargs)
    user_list = users.get("_embedded", {}).get("users", [])

    markdown = tableToMarkdown('Platform User Search by Text Results', user_list)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Delinea.Platform.Get.User.Searchbytext',
        outputs_key_field='uuid',
        raw_response=users,
        outputs=user_list
    )


def platform_user_delete_command(client, id: str = ''):
    user = client.platform_user_delete(id)
    success = user.get("success", False)
    if success:
        markdown = tableToMarkdown('Deleted user from Platform', user)
    else:
        error_message = user.get("Message") or "Unknown error occurred."
        markdown = f"Failed to delete platform user.\n**Reason:** {error_message}"

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Platform.User.Delete",
        outputs_key_field="user",
        raw_response=user,
        outputs=user
    )


def platform_user_update_command(client, **kwargs):
    user = client.platform_user_update(**kwargs)
    success = user.get("success", False)
    if success:
        markdown = tableToMarkdown('Updated Platform user', user)
    else:
        error_message = user.get("Message") or "Unknown error occurred."
        markdown = f"Failed to update platform user.\n**Reason:** {error_message}"

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Platform.User.Update",
        outputs_key_field="user",
        raw_response=user,
        outputs=user
    )


def secret_server_user_delete_command(client, id: str = ''):
    user = client.userDelete(id)
    markdown = tableToMarkdown('Deleted user from Secret Server', user)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Server.User.Delete",
        outputs_key_field="user",
        raw_response=user,
        outputs=user
    )


def secret_rpc_changepassword_command(client, secret_id: str = '', newpassword: str = '', autoComment: str = ''):
    secret = client.secretChangePassword(secret_id, newpassword, autoComment)
    markdown = tableToMarkdown('Change password for remote machine', secret)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.ChangePassword",
        outputs_key_field="secret",
        raw_response=secret,
        outputs=secret
    )


def get_credentials(client, secret_id):
    obj = {}
    secret = client.getSecret(secret_id, 'XSOAR Fetch Credential')
    items = secret.get('items')
    username = None
    password = None
    for item in items:
        if item.get('fieldName') == 'Username':
            username = item.get('itemValue')
        if item.get('fieldName') == 'Password':
            password = item.get('itemValue')
        obj = {
            "user": username,
            "password": password,
            "name": str(secret.get('id'))
        }
    return obj


def fetch_credentials_command(client, secretids):
    credentials: List[Any] = []
    args: dict = demisto.args()
    credentials_name: Any = args.get('identifier')

    try:
        secretsid = argToList(secretids)
    except Exception as e:
        demisto.debug(f"Could not fetch credentials: Provide valid secret id.{e}")
        credentials = []

    for id in secretsid:
        if id not in secretsid:
            secretsid.append(id)

    if len(secretsid) == 0:
        demisto.credentials(credentials)
        demisto.debug(
            "Could not fetch credentials: Enter valid secret ID to fetch credentials.\n For multiple ID use ,(e.g. 1,2)")
        credentials = []
    else:
        if credentials_name:
            try:
                credentials = [get_credentials(client, credentials_name)]
            except Exception as e:
                demisto.debug(f"Could not fetch credentials: {credentials_name}. Error: {e}")
                credentials = []
        else:
            for secret_id in secretsid:
                obj = get_credentials(client, secret_id)
                credentials.append(obj)

    demisto.credentials(credentials)
    markdown = tableToMarkdown('Fetched Credentials', credentials)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Fetch.Credentials",
        outputs_key_field="credentials",
        raw_response=credentials,
        outputs=credentials
    )


def main():
    params = demisto.params()

    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    # get the service API url
    url = params.get('url')
    proxy = params.get('proxy', False)
    verify = not params.get('insecure', False)
    secretids = params.get('secrets')

    demisto.info(f'Command being called is {demisto.command()}')

    delinea_commands = {
        'delinea-secret-password-get': secret_password_get_command,
        'delinea-secret-username-get': secret_username_get_command,
        'delinea-secret-get': secret_get_command,
        'delinea-secret-search-name': secret_search_name_command,
        'delinea-secret-search': secret_search_command,
        'delinea-secret-password-update': secret_password_update_command,
        'delinea-secret-checkout': secret_checkout_command,
        'delinea-secret-checkin': secret_checkin_command,
        'delinea-secret-create': secret_create_command,
        'delinea-secret-delete': secret_delete_command,
        'delinea-secret-rpc-changepassword': secret_rpc_changepassword_command,
        'delinea-folder-create': folder_create_command,
        'delinea-folder-search': folder_search_command,
        'delinea-folder-update': folder_update_command,
        'delinea-folder-delete': folder_delete_command,
        'delinea-secret-server-user-create': secret_server_user_create_command,
        'delinea-secret-server-user-search': secret_server_user_search_command,
        'delinea-secret-server-user-update': secret_server_user_update_command,
        'delinea-secret-server-user-delete': secret_server_user_delete_command,
        'delinea-secret-server-user-get': secret_server_user_get_command,
        'delinea-platform-user-create': platform_user_create_command,
        'delinea-platform-user-update': platform_user_update_command,
        'delinea-platform-user-delete': platform_user_delete_command,
        'delinea-platform-user-get': platform_user_get_command,
        'delinea-platform-get-all-users': platform_get_all_users_command,
        'delinea-platform-get-user-searchbytext': platform_get_user_searchbytext_command
    }
    command = demisto.command()
    try:
        client = Client(server_url=url,
                        username=username,
                        password=password,
                        proxy=proxy,
                        verify=verify)
        if command in delinea_commands:
            return_results(
                delinea_commands[command](client, **demisto.args())  # type: ignore[operator]
            )
        if command == 'fetch-credentials':
            return_results(
                fetch_credentials_command(client, secretids)
            )
        elif command == 'test-module':
            result = test_module(client)
            demisto.results(result)
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
