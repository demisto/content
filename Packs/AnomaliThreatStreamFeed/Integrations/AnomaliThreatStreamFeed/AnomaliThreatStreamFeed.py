"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DEFAULT_MALICIOUS_THRESHOLD = 65
DEFAULT_SUSPICIOUS_THRESHOLD = 25
THREAT_STREAM = "ThreatStream"
RETRY_COUNT = 2

RELATIONSHIPS_MAPPING = {
    "ip": [
        {"name": EntityRelationship.Relationships.RESOLVES_TO, "raw_field": "rdns", "entity_b_type": FeedIndicatorType.Domain},
        {"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"},
    ],
    "domain": [
        {"name": EntityRelationship.Relationships.RESOLVED_FROM, "raw_field": "ip", "entity_b_type": FeedIndicatorType.IP},
        {"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"},
    ],
    "url": [
        {"name": EntityRelationship.Relationships.RESOLVED_FROM, "raw_field": "ip", "entity_b_type": FeedIndicatorType.IP},
        {"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"},
    ],
    "file": [{"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"}],
    "email": [{"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"}],
}

""" CLIENT CLASS """
class Client(BaseClient):
    """
    Client to use in the Anomali ThreatStream Feed integration. Overrides BaseClient
    """

    def __init__(self, base_url, user_name, api_key, verify, reliability, should_create_relationships):
        super().__init__(base_url=base_url, verify=verify, ok_codes=(200, 201, 202))
        self.reliability = reliability
        self.should_create_relationships = should_create_relationships
        self.credentials = {
            "Authorization": f"apikey {user_name}:{api_key}",
        }

    def http_request(
        self,
        method,
        url_suffix,
        params=None,
        data=None,
        headers=None,
        files=None,
        json=None,
        without_credentials=False,
        resp_type="json",
    ):
        """
        A wrapper for requests lib to send our requests and handle requests and responses better.
        """
        headers = headers or {}
        if not without_credentials:
            headers.update(self.credentials)
        res = super()._http_request(
            method=method,
            url_suffix=url_suffix,
            headers=headers,
            params=params,
            data=data,
            json_data=json,
            files=files,
            resp_type=resp_type,
            error_handler=self.error_handler,
            retries=RETRY_COUNT,
        )
        return res

    def error_handler(self, res: requests.Response):  # pragma: no cover
        """
        Error handler to call by super().http_request in case an error was occurred
        """
        # Handle error responses gracefully
        if res.status_code == 401:
            raise DemistoException(f"{THREAT_STREAM} - Got unauthorized from the server. Check the credentials.")
        elif res.status_code == 204:
            return
        elif res.status_code == 404:
            raise DemistoException(f"{THREAT_STREAM} - The resource was not found.")
        raise DemistoException(f"{THREAT_STREAM} - Error in API call {res.status_code} - {res.text}")


class DBotScoreCalculator:
    """
    Class for DBot score calculation based on thresholds and confidence
    """

    def __init__(self, params: Dict):
        self.instance_defined_thresholds = {
            DBotScoreType.IP: arg_to_number(params.get("ip_threshold")),
            DBotScoreType.URL: arg_to_number(params.get("url_threshold")),
            DBotScoreType.FILE: arg_to_number(params.get("file_threshold")),
            DBotScoreType.DOMAIN: arg_to_number(params.get("domain_threshold")),
            DBotScoreType.EMAIL: arg_to_number(params.get("email_threshold")),
        }
        fetch_by = params.get("fetchBy", "modified")
        feed_fetch_interval = arg_to_number(params.get("feedFetchInterval", "240"))
        confidence_threshold = arg_to_number(params.get('confidenceThreshold', -1))
        reliability = params.get("sourceReliability", "C - Fairly reliable")
        tlp_color = params.get("tlp_color", "WHITE")
        reputation = params.get("feedReputation", "Unknown")
        ExpirationMethod = params.get("indicatorExpirationMethod", "Indicator Type")

        indicator_default_score = params.get("indicator_default_score")
        if indicator_default_score and indicator_default_score == "Unknown":
            self.default_score = Common.DBotScore.NONE
        else:
            self.default_score = Common.DBotScore.GOOD

    def calculate_score(self, ioc_type: str, indicator, threshold=None):
        """
        Calculate the DBot score according the indicator's confidence and thresholds if exist
        """
        # in case threshold was defined in the instance or passed as argument
        # we have only two scores levels - malicious or good
        # if threshold wasn't defined we have three score levels malicious suspicious and good
        confidence = indicator.get("confidence", Common.DBotScore.NONE)
        defined_threshold = threshold or self.instance_defined_thresholds.get(ioc_type)
        if defined_threshold:
            return Common.DBotScore.BAD if confidence >= defined_threshold else self.default_score
        else:
            if confidence > DEFAULT_MALICIOUS_THRESHOLD:
                return Common.DBotScore.BAD
            if confidence > DEFAULT_SUSPICIOUS_THRESHOLD:
                return Common.DBotScore.SUSPICIOUS
            else:
                return self.default_score


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        Client: client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    client.http_request("GET", "v2/intelligence/", params={"limit": 1})
    return "ok"


def get_indicators_command(client: Client, args: dict) -> CommandResults:
    """
    Fetch and process threat indicators from Anomali ThreatStream

    Args:
        client (Client): Configured API client for Anomali ThreatStream
        args (dict):
            - limit: Maximum number of indicators to retrieve (optional)
            - type: Type of indicators to fetch (optional)
            - confidence: Minimum confidence threshold (optional)
            - since: Retrieve indicators updated since this timestamp (optional)

    Returns:
        CommandResults
    """
    return CommandResults(
        outputs_prefix="AnomaliThreatStream.Indicators",
        outputs_key_field="id",
    )


def main():
    """
    Initiate integration command
    """
    command = demisto.command()
    LOG(f"Command being called is {command}")

    params = demisto.params()

    # init credentials
    user_name = params.get("credentials", {}).get("identifier")
    api_key = params.get("credentials", {}).get("password")
    server_url = params.get("url", "").strip("/")
    reliability = params.get("integrationReliability", DBotScoreReliability.B)
    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        Exception("Please provide a valid value for the Source Reliability parameter.")

    commands = {
        # reputation commands
        "threatstream-feed-get-indicators": get_indicators_command,
    }

    try:
        client = Client(
            base_url=f"{server_url}/api/",
            user_name=user_name,
            api_key=api_key,
            verify=not params.get("insecure", False),
            reliability=reliability,
            should_create_relationships=params.get("createRelationships", True),
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
        elif command in commands:
            result = commands[command](client, demisto.args())
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

        return_results(result)

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
