import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from CommonServerUserPython import *
#   from typing import Dict

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, server_url: str, client_id: str, client_secret: str, proxy: bool, verify: bool):
        super().__init__(base_url=server_url, proxy=proxy, verify=verify)
        self._client_id = client_id
        self._client_secret = client_secret
        self._token = self._generate_token()
        self._headers = {'Authorization': self._token, 'Content-Type': 'application/json'}

    def _generate_token(self) -> str:
        body = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "client_credentials",
            "provider": "thy-one"
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        return "Bearer " + (self._http_request("POST", "/v1/token", headers=headers, data=body)).get('accessToken')

    def getSecret(self, name: str) -> str:
        return self._http_request("GET", url_suffix="/v1/secrets/" + str(name))


def dsv_secret_get_command(client, name: str = ''):
    secret = client.getSecret(name)
    markdown = tableToMarkdown("Information", secret)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="DSV.Secret",
        outputs_key_field="secret",
        raw_response=secret,
        outputs=secret
    )


def test_module(client) -> str:
    if client._token == '':
        raise Exception('Failed to get authorization token. Check you credential and access to DSV.')

    return 'ok'


def main():
    client_id = demisto.params().get('client_id')
    client_secret = demisto.params().get('client_secret')

    # get the service API url
    url = demisto.params().get('url')
    proxy = demisto.params().get('proxy', False)
    verify = not demisto.params().get('insecure', False)
#    credential_objects = demisto.params().get('credentialobjects')

    LOG(f'Command being called is {demisto.command()}')

    thycotic_commands = {
        'dsv-secret-get': dsv_secret_get_command
    }

    try:
        client = Client(server_url=url,
                        client_id=client_id,
                        client_secret=client_secret,
                        proxy=proxy,
                        verify=verify)

        if demisto.command() in thycotic_commands:
            return_results(
                thycotic_commands[demisto.command()](client, **demisto.args())  # type: ignore[operator]
            )

        elif demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
