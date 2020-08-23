from requests_ntlm import HttpNtlmAuth

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, server_url: str, use_ssl: bool, proxy: bool, app_id: str, folder: str, safe: str,
                 credential_object: str, username: str, password: str):
        super().__init__(base_url=server_url, verify=use_ssl, proxy=proxy)
        self._app_id = app_id
        self._folder = folder
        self._safe = safe
        self._credential_object = credential_object
        self._username = username
        self._password = password

    def list_credentials(self):
        url_suffix = f'/AIMWebService/api/Accounts?AppID={self._app_id}&Safe=' \
                     f'{self._safe}&Folder={self._folder}&Object={self._credential_object}'
        params = {
            "AppID": self._app_id,
            "Safe": self._safe,
            "Folder": self._folder,
            "Object": self._credential_object,
        }

        auth = None
        if self._username:
            # if username and password were added - use ntlm authentication
            auth = HttpNtlmAuth(self._username, self._password)

        return self._http_request("GET", url_suffix, params=params, auth=auth)


def list_credentials_command(client):
    res = client.list_credentials()
    # the password value in the json appears under the key "Content"
    if "Content" in res:
        del res["Content"]
    return res


def fetch_credentials(client):
    res = client.list_credentials()

    credentials = {
        "user": res.get("UserName"),
        "password": res.get("Content"),
        "name": res.get("Name"),
    }
    demisto.credentials([credentials])


def test_module(client: Client) -> str:
    # try to get to the aim server with the current params
    client.list_credentials()
    return "ok"


def main():

    params = demisto.params()

    url = params.get('url', "")
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    app_id = params.get('app_id', "")
    folder = params.get('folder', "")
    safe = params.get('safe', "")
    credential_object = params.get('credential_names', "")

    username = ""
    password = ""
    if params.get('credentials'):
        # credentials are not mandatory in this integration
        username = params.get('credentials').get('identifier')
        password = params.get('credentials').get('password')

    client = Client(server_url=url, use_ssl=use_ssl, proxy=proxy, app_id=app_id, folder=folder, safe=safe,
                    credential_object=credential_object, username=username, password=password)

    command = demisto.command()
    LOG(f'Command being called in CyberArk AIM is: {command}')

    commands = {
        'test-module': test_module,
        'cyberark-aim-list-credentials': list_credentials_command,
        'fetch-credentials': fetch_credentials
    }
    if command in commands:
        return_results(commands[command](client))  # type: ignore[operator]


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
