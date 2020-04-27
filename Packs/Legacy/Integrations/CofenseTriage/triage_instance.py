import demistomock as demisto
from CommonServerPython import return_error

import json
import requests


TRIAGE_INSTANCE = None  # This will contain the global TriageInstance object


def init():
    global TRIAGE_INSTANCE
    TRIAGE_INSTANCE = TriageInstance(
        host=demisto.getParam('host').rstrip('/'),
        token=demisto.getParam('token'),
        user=demisto.getParam('user'),
        disable_tls_verification=demisto.params().get('insecure', False),
    )


class TriageInstance:
    def __init__(self, *, host, token, user, disable_tls_verification=False):
        self.host = host
        self.token = token
        self.user = user
        self.disable_tls_verification = disable_tls_verification

    def request(self, endpoint, params=None, body=None, raw_response=False):
        """
        Make a request to the configured Triage instance and return the result.
        """
        # TODO automatic rate-limiting
        response = requests.get(
            self.api_url(endpoint),
            headers={
                "Authorization": f"Token token={self.user}:{self.token}",
                "Accept": "application/json",
            },
            params=params,
            data=body,
            verify=not self.disable_tls_verification,
        )

        if not response.ok:
            return return_error(
                f"Call to Cofense Triage failed ({response.status_code}): {response.text}"
            )

        if response.status_code == 206:
            # 206 indicates Partial Content. The reason will be in the warning header.
            demisto.debug(str(response.headers))

        if raw_response:
            # TODO refactor to get rid of this?
            return response

        if not response.text or response.text == "[]":
            return {}

        try:
            return response.json()
        except json.decoder.JSONDecodeError as ex:
            demisto.debug(str(ex))
            return return_error(
                f"Could not parse result from Cofense Triage ({response.status_code})"
            )

    def api_url(self, endpoint):
        """Return a full URL for the configured Triage host and the specified endpoint"""

        endpoint = endpoint.lstrip("/")
        return f"{self.host}/api/public/v1/{endpoint}"
