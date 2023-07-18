import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' IMPORTS '''


import json
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' GLOBAL Variables '''


DISABLE_SSL = demisto.params().get('insecure', False)
PROXY = demisto.params().get('proxy')
PROMPT = demisto.params().get('prompt')
SERVICE_SCOPES = "https://www.googleapis.com/auth/cloud-platform"
REDIRECT_URI = 'https://oproxy.demisto.ninja/authcode'
AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
ACCESS_TOKEN_URL = 'https://oauth2.googleapis.com/token'
PROJECT_ID = demisto.params().get('ProjectID')
URL = 'https://us-central1-aiplatform.googleapis.com/v1/projects/'
AI_Model = 'chat-bison:predict'
TOKEN = demisto.params().get('token')
CLIENT_ID = demisto.params().get('ID')
CLIENT_SECRET = demisto.params().get('Secret')
AUTH_CODE = demisto.params().get('Authentication_Code')
ERROR_MSG = ("ERROR: The authentication code has been reset"
             "Please reset integration cache for Vetex AI Instance"
             "in XSOAR and regenerate the 'Authorization code'")


''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with Google Vertex AI API
    """

    def __init__(self, token_str: str, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=URL, proxy=PROXY, verify=verify)
        self.token_str = token_str
        self.base_url = base_url
        self.proxy = proxy
        self.headers = {'Authorization': f"Bearer {self.token_str}", "Content-Type": "application/json"}

    def PaLMModel(self, prompt: str):
        options = {"instances": [{"messages": [{"content": prompt}]}]}
        return self._http_request(method='POST',
                                  url_suffix=f'{PROJECT_ID}/locations/us-central1/publishers/google/models/{AI_Model}',
                                  json_data=options, headers=self.headers)


''' MAIN FUNCTIONS '''


def createAuthorizationURL():
    # The client ID and access scopes are required.
    partOne = f"{AUTH_URL}/oauthchooseaccount?scope={SERVICE_SCOPES}&access_type=offline&prompt=consent"
    partTwo = f"&response_type=code&state=state_parameter_passthrough_value&redirect_uri={REDIRECT_URI}&client_id={CLIENT_ID}"
    authorization_url = partOne + partTwo
    return authorization_url


def check_access_token_validation():
    """
    Access tokens expires in 1 hour, then using refresh_access_token function we will request for a new access token
    """

    demisto.debug("Start Token Validation")

    integration_context: dict = get_integration_context()
    access_token: str = integration_context.get('access_token', '')
    valid_until: int = integration_context.get('valid_until', int)
    time_now = epoch_seconds()

    if access_token and (time_now < valid_until):
        demisto.debug("Access Token still valid")
        return access_token
    elif access_token and (time_now > valid_until):
        demisto.debug("Access Token is expired, using refresh token")
        access_token = refresh_access_token()
        return access_token
    else:
        access_token = get_access_token()
        return access_token


def get_access_token():

    """
    Generate a new Access Token using ClientID, ClientSecret and configured Authentication Code
    """

    demisto.debug("Generate a new access token")

    integration_context: dict = get_integration_context()

    data: dict = {
        'code': AUTH_CODE,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'
    }

    response: requests.Response = requests.post(
        ACCESS_TOKEN_URL,
        data=data,
        verify=DISABLE_SSL
    )

    if not response.ok:
        error = error_parser(response)
        raise ValueError(f'Failed to get access token [{response.status_code}] - {error}')

    response_json: dict = response.json()
    access_token = response_json.get('access_token', '')
    expires_in: int = response_json.get('expires_in', 3595)
    refresh_token = response_json.get('refresh_token', '')

    time_now: int = epoch_seconds()
    time_buffer = 5  # seconds by which to shorten the validity period
    if expires_in - time_buffer > 0:
        expires_in -= time_buffer
    integration_context['refresh_token'] = refresh_token
    integration_context['access_token'] = access_token
    integration_context['valid_until'] = time_now + expires_in
    set_integration_context(integration_context)

    return access_token


def refresh_access_token():
    """
    A refresh token might stop working for one of these reasons:
    The user has revoked your app's access. The refresh token has not been used for six months
    https://developers.google.com/identity/protocols/oauth2#:~:text=Refresh%20token%20expiration,
    -You%20must%20write&text=A%20refresh%20token%20might%20stop,been%20used%20for%20six%20months.
    """

    demisto.debug("Refresh Access token using refresh_token from integration_context")

    integration_context: dict = get_integration_context()
    refresh_token: str = integration_context.get('refresh_token', '')

    data: dict = {
        'refresh_token': refresh_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'refresh_token'
    }

    response: requests.Response = requests.post(
        ACCESS_TOKEN_URL,
        data=data,
        verify=DISABLE_SSL
    )

    if not response.ok:
        error = error_parser(response)
        raise ValueError(f'Failed to get refresh token [{response.status_code}] - {error}')

    response_json: dict = response.json()
    access_token = response_json.get('access_token', '')
    expires_in: int = response_json.get('expires_in', 3595)

    time_now: int = epoch_seconds()
    time_buffer = 5  # seconds by which to shorten the validity period
    if expires_in - time_buffer > 0:
        expires_in -= time_buffer
    integration_context['refresh_token'] = refresh_token
    integration_context['access_token'] = access_token
    integration_context['valid_until'] = time_now + expires_in
    set_integration_context(integration_context)

    return access_token


def epoch_seconds(d: datetime = None) -> int:
    """
    Return the number of seconds for given date. If no date, return current.
    :param d: timestamp datetime object
    :return: timestamp in epoch
    """

    if not d:
        d = datetime.utcnow()
    return int((d - datetime.utcfromtimestamp(0)).total_seconds())


def resetIntegrationContext():
    """
    In case of error related to authentication or authorization, the cached context will be reseted
    """

    demisto.debug(ERROR_MSG)

    integration_context: dict = get_integration_context()
    integration_context['refresh_token'] = ""
    integration_context['access_token'] = ""
    integration_context['valid_until'] = ""
    set_integration_context(integration_context)
    return True


def error_parser(resp_err: requests.Response) -> str:
    """
    Parse Error
    """

    try:
        response: dict = resp_err.json()
        if "Unauthorized" in response.get('error_description', ''):
            resetIntegrationContext()
            raise ValueError(ERROR_MSG)
        elif "invalid authentication credentials" in response.get('error_description', ''):
            resetIntegrationContext()
            raise ValueError(ERROR_MSG)
        elif "Bad" in response.get('error_description', ''):
            resetIntegrationContext()
            raise ValueError(ERROR_MSG)
        else:
            error = response.get('error', {})
            err_str = (f"{error.get('code', '')}: {error.get('message', '')}" if isinstance(error, dict)
                       else response.get('error_description', ''))
            if err_str:
                demisto.debug(err_str)
                return err_str
            # If no error message
            raise ValueError()
    except ValueError:
        return resp_err.text


def test_module(client: Client):
    """
    This is the call made when pressing the integration test button.
    """

    promptText = "Hi, what is your name"
    status = ''
    try:
        response = client.PaLMModel(promptText)
        rep = json.dumps(response)
        repJSON = json.loads(rep)
        PaLMResp = repJSON.get('predictions', [])[0].get('candidates', [])[0].get('content', "")
        if PaLMResp:
            status = 'ok'
            return status
        else:
            status = ("There is an error in communciating with Google Vertex AI API"
                      "- Please regenerate the Authentication Code again")
    except Exception as e:
        exception_text = str(e).lower()
        if 'Bad Request' in exception_text or 'invalid_grant' in exception_text:
            status = ERROR_MSG
            return status
        else:
            raise e
    return status


def send_prompts_PaLM_command(client: Client, prompt: str) -> CommandResults:
    """
    Send Text to Bard
    """

    PaLM_response = client.PaLMModel(prompt)

    return PaLM_output(PaLM_response)


def PaLM_output(response) -> CommandResults:
    """
    Convert response from ChatGPT to a human readable format in markdown table

    :return: CommandResults return output of ChatGPT response
    :rtype: ``CommandResults``
    """

    if response and isinstance(response, dict):
        rep = json.dumps(response)
        repJSON = json.loads(rep)
        PaLMResp = repJSON.get('predictions', [])[0].get('candidates', [])[0].get('content', "")
        context = [{'PaLM Model Response': PaLMResp}]

        markdown = tableToMarkdown(
            'Google Vertex AI API Response',
            context,
        )

        results = CommandResults(
            readable_output=markdown,
            outputs_prefix='GoogleVertexAIResponse',
            outputs_key_field='predictions',
            outputs=context
        )

        return results
    else:
        raise DemistoException('Error in results')


''' MAIN FUNCTION '''


def main():
    """
    Main function, runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    verify = not params.get('insecure', False)

    try:
        if command == 'test-module':
            access_token = check_access_token_validation()
            client = Client(token_str=access_token, base_url=URL, verify=verify, proxy=PROXY)
            return_results(test_module(client))
        elif command == 'google-vertex-PaLM-chat':
            access_token = check_access_token_validation()
            client = Client(token_str=access_token, base_url=URL, verify=verify, proxy=PROXY)
            return_results(send_prompts_PaLM_command(client, **args))
        elif command == 'google-vertex-ai-generate-auth-url':
            return_results(createAuthorizationURL())
    except Exception as e:
        if 'Quota exceeded for quota metric' in str(e):
            return_error('Quota for Google Vertex API exceeded')
        else:
            return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
