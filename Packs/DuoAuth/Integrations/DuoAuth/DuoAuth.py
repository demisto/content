from typing import Dict
import hashlib
import hmac
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


class Client(BaseClient):
    def __init__(self, integration_key: str, secret_key: str, base_url: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.integration_key = integration_key
        self.secret_key = secret_key

    def _generate_signature(self, method: str, path: str, params: Dict[str, str]) -> Dict[str, str]:
        """
        Generate the signature and headers required for Duo API authentication.
        """
        # 1. Define the current timestamp
        date_header = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S %z')

        # 2. Encode parameters into query string format
        params_encoded = urllib.parse.urlencode(sorted(params.items()))

        # 3. Construct the canonical string
        canonical_string = f"{date_header}\n{method.upper()}\n{self._base_url.replace('https://', '').rstrip('/')}\n{path}\n" \
                           f"{params_encoded}"

        # 4. Generate the HMAC signature
        signature = hmac.new(
            key=self.secret_key.encode('utf-8'),
            msg=canonical_string.encode('utf-8'),
            digestmod=hashlib.sha512
        ).hexdigest()

        # 5. Base64 encode the Authorization header
        auth_header = base64.b64encode(f"{self.integration_key}:{signature}".encode("utf-8")).decode("utf-8")

        # 6. Return headers
        return {
            "Date": date_header,
            "Authorization": f"Basic {auth_header}"
        }

    def call_duo_api(self, method: str, path: str, params: Dict[str, str]) -> Dict:
        """
        Executes a call to the Duo API with proper headers and signature.
        """
        headers = self._generate_signature(method, path, params)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        return self._http_request(
            method=method,
            url_suffix=path,
            headers=headers,
            params=params,
            resp_type='json',
        )

    def test_connectivity(self) -> str:
        """
        Calls the '/check' endpoint to verify credentials.
        """
        response = self.call_duo_api("POST", "/auth/v2/check", {})
        if response.get("stat") == "OK":
            return "ok"
        raise DemistoException(f"Failed to connect to Duo: {response.get('message', 'Unknown error')}")

    def send_push_notification(self, username: str, factor: str, pushinfo: str, type: str) -> Dict:
        """
        Calls the '/auth' endpoint to send a push notification.
        """
        params = {
            "username": username,
            "factor": factor,
            "device": "auto",
            "pushinfo": pushinfo,
            "type": type
        }
        return self.call_duo_api("POST", "/auth/v2/auth", params)


def test_module(client: Client) -> str:
    """
    Tests API connectivity and credentials.
    """
    return client.test_connectivity()


def duo_push_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Executes the 'duo-auth' command to perform second-factor authentication (send push in our case).
    """
    username = args.get("username")
    factor = "push"  # Default to "push"
    pushinfo = args.get("pushinfo", "")
    type = args.get("type", "Activities")  # Default value if not provided

    if not username:
        raise DemistoException("Missing required argument: username.")

    # Send the push notification
    response = client.send_push_notification(username, factor, pushinfo, type)
    status = response.get("response", {}).get("result")
    status_message = response.get("response", {}).get("status_msg", "")

    if not status:
        raise DemistoException(f"Failed to send push: {response.get('message', 'Unknown error')}")

    outputs = {
        "Status": status,
        "Message": status_message,
        "User": username,
    }

    human_readable = f"### Duo Push Result\n" \
                     f"**User**: {username}\n" \
                     f"**Status**: {status}\n" \
                     f"**Message**: {status_message}"

    return CommandResults(
        outputs_prefix="DuoAuth.PushNotification",
        outputs_key_field="User",
        outputs=outputs,
        raw_response=response,
        readable_output=human_readable,
    )


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_hostname = params.get("api_hostname", "").strip()
    integration_key = params.get("integration_key", {}).get("password", "").strip()
    secret_key = params.get("secret_key", {}).get("password", "").strip()
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    if not api_hostname or not integration_key or not secret_key:
        raise ValueError("Missing required parameters: API Hostname, Integration Key, or Secret Key.")

    base_url = f"https://{api_hostname}"

    demisto.debug(f"Command being executed: {command}")

    try:
        client = Client(
            integration_key=integration_key,
            secret_key=secret_key,
            base_url=base_url,
            verify=verify,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command == "duoauth-push-notification":
            return_results(duo_push_command(client, args))
        else:
            raise NotImplementedError(f"The command '{command}' is not implemented.")
    except Exception as e:
        demisto.error(f"Error executing command {command}: {str(e)}")
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "builtin", "builtins"):
    main()
