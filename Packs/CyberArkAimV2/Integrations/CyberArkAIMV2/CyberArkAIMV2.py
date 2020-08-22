import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


class Client(BaseClient):
    def __init__(self, server_url: str, use_ssl: bool, proxy: bool, app_id: str, folder: str,
                 safe: str, credential_object: str, ntlm_username: str, ntlm_password: str, ntlm_auto: str,
                 ntlm_domain: str):
        super().__init__(base_url=server_url, verify=use_ssl, proxy=proxy)
        self.app_id = app_id
        self.folder = folder
        self.safe = safe
        self.credential_object = credential_object
        self.ntlm_username = ntlm_username
        self.ntlm_password = ntlm_password
        self.ntlm_auto = ntlm_auto
        self.ntlm_domain = ntlm_domain

    def list_credentials(self):
        url_suffix = f'/AIMWebService/api/Accounts?AppID={self.app_id}&Safe=' \
                     f'{self.safe}&Folder={self.folder}&Object={self.credential_object}'
        params = {
            "AppID": self.app_id,
            "Safe": self.safe,
            "Folder": self.folder,
            "Object": self.credential_object,
        }

        if self.ntlm_auto == "NTLM":
            auth = (f'{self.ntlm_domain}\\{self.ntlm_username}', self.ntlm_password)
            return self._http_request("GET", url_suffix, params=params, auth=auth)

        return self._http_request("GET", url_suffix, params=params)


def list_credentials_command(client):
    res = client.list_credentials()
    return res


def test_module(client: Client) -> str:
    # if an error will be raised there is an issue with the params
    client.list_credentials()
    return "ok"


def main():

    params = demisto.params()

    url = params.get('url', "")
    port = params.get('port', "")
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    if port:
        url = f'{url}:{port}'

    app_id = params.get('app_id', "")
    folder = params.get('folder', "")
    safe = params.get('safe', "")
    credential_object = params.get('credential_names', "")

    ntlm_username = ""
    ntlm_password = ""
    if params.get('ntlm'):
        ntlm_username = params.get('ntlm').get('identifier')
        ntlm_password = params.get('ntlm').get('password')

    ntlm_domain = params.get('ntlm_domain')
    ntlm_auto = params.get('ntlm_auto')

    client = Client(server_url=url, use_ssl=use_ssl, proxy=proxy, app_id=app_id, folder=folder, safe=safe,
                    credential_object=credential_object, ntlm_username=ntlm_username, ntlm_password=ntlm_password,
                    ntlm_auto=ntlm_auto, ntlm_domain=ntlm_domain)

    command = demisto.command()
    LOG(f'Command being called in CyberArk AIM is: {command}')
    commands = {
        'test-module': test_module,
        'cyberarkaim-list-credentials': list_credentials_command,
    }
    if command in commands:
        return_results(commands[command](client))  # type: ignore[operator]


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
