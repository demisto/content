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

# RELATIONSHIPS_MAPPING = {
#     "ip": [
#         {"name": EntityRelationship.Relationships.RESOLVES_TO, "raw_field": "rdns", "entity_b_type": FeedIndicatorType.Domain},
#         {"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"},
#     ],
#     "domain": [
#         {"name": EntityRelationship.Relationships.RESOLVED_FROM, "raw_field": "ip", "entity_b_type": FeedIndicatorType.IP},
#         {"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"},
#     ],
#     "url": [
#         {"name": EntityRelationship.Relationships.RESOLVED_FROM, "raw_field": "ip", "entity_b_type": FeedIndicatorType.IP},
#         {"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"},
#     ],
#     "file": [{"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"}],
#     "email": [{"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"}],
# }

# IOC_ARGS_TO_INDICATOR_KEY_MAP = {
#     "domain": {
#         "domain": "value",
#         "dns": "ip",
#         "organization": "org",
#         "traffic_light_protocol": "tlp",
#         "geo_country": "country",
#         "creation_date": "created_ts",
#         "updated_date": "modified_ts",
#         "registrant_name": "meta.registrant_name",
#         "registrant_email": "meta.registrant_email",
#         "registrant_phone": "meta.registrant_phone",
#     },
#     "url": {"url": "value", "asn": "asn", "organization": "org", "geo_country": "country", "traffic_light_protocol": "tlp"},
#     "ip": {
#         "ip": "value",
#         "asn": "asn",
#         "geo_latitude": "latitude",
#         "geo_longitude": "longitude",
#         "geo_country": "country",
#         "traffic_light_protocol": "tlp",
#     },
#     "file": {"organization": "org", "traffic_light_protocol": "tlp"},
# }

# INDICATOR_EXTENDED_MAPPING = {
#     "Value": "value",
#     "ID": "id",
#     "IType": "itype",
#     "Confidence": "confidence",
#     "Country": "country",
#     "Organization": "org",
#     "ASN": "asn",
#     "Status": "status",
#     "Tags": "tags",
#     "Modified": "modified_ts",
#     "Source": "source",
#     "Type": "type",
#     "Severity": "severity",
# }

""" CLIENT CLASS """
class Client(BaseClient):
    """
    Client to use in the Anomali ThreatStream Feed integration. Overrides BaseClient
    """

    def __init__(self, base_url, user_name, api_key, verify):
        super().__init__(base_url=base_url, verify=verify, ok_codes=(200, 201, 202))
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


def get_indicators_command(client: Client, args: dict[str, Any]):# -> CommandResults:
    # TODO HERE
    """Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """
  
    indicator_type = str(args.get("indicator_type"))
    limit = int(demisto.args().get("limit")) if "limit" in demisto.args() else 10
    
    params = {
        "limit": limit
    }
    if indicator_type:
        params["itype"] = f"apt_{indicator_type}"
        
    res = client.http_request(method="GET", url_suffix="v2/intelligence", params=params)
 
    parsed_indicators = parse_indicators_for_get_command(res.get("objects"))
    demisto.debug(f"Anomali ThreatStream Feed got {len(parsed_indicators)} indicators")

    human_readable = tableToMarkdown(
        name="Indicators from Anomali ThreatStream Feed:",
        t=parsed_indicators,
        headers=[
            "TargetIndustries",
            "Source",
            "ThreatStreamID",
            "Country Code",
            "ip/domain/email", #TODO find solution
            "Description",
            "Modified",
            "Organization",
            "Confidence",
            "Creation",
            "Expiration",
            "Tags",
            "TrafficLightProtocol",
            "Location",
            "ASN"
        ],
        removeNull=True,
        is_auto_json_transform=True,
    )

    return CommandResults(readable_output=human_readable)
    # return CommandResults(readable_output=human_readable, raw_response=indicators)
    # return human_readable, {}, {"raw_response": indicators}


def parse_indicators_for_get_command(indicators) -> List[dict[str, Any]]:
    """Parses the list of indicators returned from the api to indicators that can be returned to the war room.

    Args:
        indicators (list): list of indicators from api raw response.

    Returns:
        List[dict[str, Any]]: List of indicators that can be returned to the war room.
    """
    res = []
    # indicators = [indicators] if type(indicators) is not list else indicators
    for indicator in indicators:
        indicator_type = indicator.get("type")  # ip/domain/email
        indicator_value = indicator.get("value") # type's value
        
        dynamic_field = {}
        dynamic_field[indicator_type] = indicator_value
        
        res.append(
            assign_params(
                TargetIndustries=indicator.get("target_industry"),
                Source=indicator.get("source"),
                ThreatStreamID=indicator.get("id"),
                CountryCode=indicator.get("country"),
                **dynamic_field,  # Unpack the dynamic field into the params
                Description=indicator.get("description"),
                Modified=indicator.get("modified_ts"),
                Organization=indicator.get("org"),
                Confidence=indicator.get("confidence"),
                Creation=indicator.get("created_ts"),
                Expiration=indicator.get("expires_ts"),
                Tags=indicator.get("tags"),
                TrafficLightProtocol=indicator.get("tlp"),
                Location=indicator.get("locations"),
                ASN=indicator.get("asn")
            )
        )
    return res


def fetch_indicators_command(client: Client, params: dict, last_run: dict):# -> list[dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: Client object with request

    Returns:
        Indicators.
    """
    feed_fetch_interval = arg_to_number(params.get("feedFetchInterval", "240"))
    fetch_by = params.get("fetchBy", "modified")
    status = "active"
    order_by = "modified_ts"
    # confidence_threshold = arg_to_number(params.get('confidenceThreshold', "-1"))
    confidence_threshold = 75  # Default confidence threshold
    tlp_color = params.get("tlp_color", "WHITE")
    reputation = params.get("feedReputation", "Unknown")
    expiration_method = params.get("indicatorExpirationMethod", "Indicator Type")
    relationships = params.get("createRelationships", True)
    reliability = params.get("integrationReliability", DBotScoreReliability.C)
    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        Exception("Please provide a valid value for the Source Reliability parameter.")

    now = datetime.now(timezone.utc)
    days_for_query = int(feed_fetch_interval / 1440)  # The interval is validated already in the main

    if last_run:
        last_successful_run = dateparser.parse(
            last_run["last_successful_run"], settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True}
        )
        if last_successful_run:
            time_delta = now - last_successful_run
            days_for_query = time_delta.days + 1
        else:
            raise DemistoException("failed to fetch indicators")
        
    # handling case of more than 7 days history, as the API fail longer-fetching queries.
    if days_for_query > 7:  # api can get up to 7 days
        days_for_query = 7


    # TODO cont from here!!!!!!!
    response = client.get_indicators_request({"query": "get_iocs", "days": days_for_query})

    if response.get("query_status") != "ok":
        raise DemistoException(f"couldn't fetch, {response.get('query_status')}")

    indicators = response["data"]
    demisto.debug(f"{THREAT_STREAM} got {len(indicators)}")

    results = []


    # TODO this is the filtering
    for indicator in indicators:
        if indicator.get("ioc_type") == "sha3_384_hash":
            demisto.debug(f'{THREAT_STREAM} got indicator of indicator type "sha3" skipping it')
            continue
        if (arg_to_number(indicator.get("confidence_level")) or 75) < confidence_threshold:
            demisto.debug(f"{THREAT_STREAM} got indicator with low confidence level, skipping it")
            continue

        results.append(parse_indicator_for_fetch(indicator, with_ports, create_relationship, tlp_color))

    return now.strftime("%Y-%m-%dT%H:%M:%SZ"), results



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

    # commands = {
    #     # reputation commands
    #     "test-module": test_module,
    #     "threatstream-feed-get-indicators": get_indicators_command,
    # }

    try:
        client = Client(
            base_url=f"{server_url}/api/",
            user_name=user_name,
            api_key=api_key,
            verify=not params.get("insecure", False),
            # reliability=reliability,
            # should_create_relationships=relationships,
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
            
        elif command == 'threatstream-feed-get-indicators':
            # TODO add the arguments from the run line - demisto arg
            return_results(get_indicators_command(client, demisto.args()))
            
        elif command == "fetch-indicators":
            next_run, res = fetch_indicators_command(client, params, demisto.getLastRun())
            for b in batch(res, batch_size=2000):
                demisto.debug(f"{THREAT_STREAM} {b=}")
                demisto.createIndicators(b)
            demisto.setLastRun({"last_successful_run": next_run})

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()


# https://svlpartner-optic-api.threatstream.com/api/
# https://svlpartner-optic-api.threatstream.com/api/v2/intelligence?limit=1000&status=active&order_by=modified_ts&confidence__gt=75&modified_ts__gte=2023-08-04T11:57:00