import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
DEFAULT_MALICIOUS_THRESHOLD = 65
DEFAULT_SUSPICIOUS_THRESHOLD = 25
THREAT_STREAM = "Anomali ThreatStream Feed"
RETRY_COUNT = 2
LIMIT = 1000
STATUS = "active"

RELATIONSHIPS_MAPPING = {
    "ip": [
        {
            "name": EntityRelationship.Relationships.RESOLVES_TO,
            "raw_field": "rdns",
            "entity_b_type": FeedIndicatorType.Domain
        },
        {
            "name": EntityRelationship.Relationships.INDICATOR_OF,
            "raw_field": "meta.maltype",
            "entity_b_type": "Malware"
        },
    ],
    "domain": [
        {
            "name": EntityRelationship.Relationships.RESOLVED_FROM,
            "raw_field": "ip",
            "entity_b_type": FeedIndicatorType.IP
        },
        {
            "name": EntityRelationship.Relationships.INDICATOR_OF,
            "raw_field": "meta.maltype",
            "entity_b_type": "Malware"
        },
    ],
    "url": [
        {
            "name": EntityRelationship.Relationships.RESOLVED_FROM,
            "raw_field": "ip",
            "entity_b_type": FeedIndicatorType.IP
        },
        {
            "name": EntityRelationship.Relationships.INDICATOR_OF,
            "raw_field": "meta.maltype",
            "entity_b_type": "Malware"
        },
    ],
    "file": [
        {
            "name": EntityRelationship.Relationships.INDICATOR_OF,
            "raw_field": "meta.maltype",
            "entity_b_type": "Malware"
        }
    ],
    "email": [
        {
            "name": EntityRelationship.Relationships.INDICATOR_OF,
            "raw_field": "meta.maltype",
            "entity_b_type": "Malware"
        }
    ]
}

# TODO find usage for this
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
        params["type"] = indicator_type
        
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
            str(args.get("indicator_type")),
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

def get_past_time(minutes_interval):
    """
    Calculates the time that is now minus the given time interval in minutes,
    and returns it in the format 'YYYY-MM-DDTHH%3AMM%3ASS'.

    Args:
        minutes_interval (int): The time interval in minutes.

    Returns:
        str: The calculated past time in the specified format.
    """
    now = datetime.now()
    past_time = now - timedelta(minutes=minutes_interval)
    
    # Format the datetime object as a string
    formatted_time = past_time.strftime('%Y-%m-%dT%H:%M:%S')
    return formatted_time

def fetch_indicators_command(client: Client, params: dict, last_run: dict):
    """Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: Client object with request

    Returns:
        Indicators.
    """
    # TODO what to do with them
    reputation = params.get("feedReputation", "Unknown")
    expiration_method = params.get("indicatorExpirationMethod", "Indicator Type")
    
    create_relationship = params.get("createRelationships", True)
    tlp_color = params.get("tlp_color", "WHITE")
    reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(params.get("integrationReliability", DBotScoreReliability.C))

    now = datetime.now(timezone.utc)
    order_by = params.get("fetchBy", "modified")+"_ts"
    confidence_threshold = arg_to_number(params.get('confidenceThreshold', "65"))
    
    query = assign_params(limit=LIMIT, status=STATUS, order_by=order_by, confidence__gt=confidence_threshold)
    feed_fetch_interval = arg_to_number(params.get("feedFetchInterval", "240"))
    if order_by == "modified_ts":
        query['modified_ts__gte'] =  "2023-08-04T11:57:00.080Z" # TODO rollback -> get_past_time(feed_fetch_interval)
    else: # order_by == "created_ts"
        query['created_ts__gte'] = get_past_time(feed_fetch_interval)
    
    response = client.http_request(method="GET", url_suffix="v2/intelligence", params=query)
    # if response.status_code == 400: # once the order by is jibrish
    #     return f"No indicators found for {query}"

    indicators = response.get('objects', [])
    if not indicators:
        raise DemistoException("No indicators found from ThreatStream")
    
    results = {}
    results = parse_indicator_for_fetch(indicators, tlp_color, create_relationship, reliability)
    
    next_page = response.get("meta", {}).get("next", None)
    while next_page:
        next_page = next_page.replace("api/", "")
        response = client.http_request(method="GET", url_suffix=next_page)
        indicators = response.get("objects", [])
        next_page = response.get("meta", {}).get("next", None)
        if indicators:
            results.append(parse_indicator_for_fetch(indicators, tlp_color, create_relationship, reliability))
        else:
            break
   
    return now.strftime("%Y-%m-%dT%H:%M:%SZ"), results


def create_relationships(create_relationships: bool, reliability, indicator: dict):
    """Returns a list of relationships of the indicator.

    Args:
        # TODO  fix docstring

    Returns:
        list: List of relationships.
    """
    relationships = []

    if not create_relationships:
        return relationships

    type = indicator.get("type")
    for relation in RELATIONSHIPS_MAPPING.get(type):
        entity_b = demisto.get(indicator, relation["raw_field"])
        relationships.append(
            EntityRelationship(
                entity_a=indicator["value"],
                entity_a_type=type,
                name=relation["name"],
                entity_b=entity_b,
                entity_b_type=relation["entity_b_type"],
                source_reliability=reliability,
                brand=THREAT_STREAM,
            ).to_indicator()
        )
    return relationships


def parse_indicator_for_fetch(indicator: dict, tlp_color: str, create_relationship: bool, reliability) -> dict[str, Any]:
    """Parses the indicator given from the api to an indicator that can be sent to TIM XSOAR.

    Args:
        indicator (dict): The raw data of the indicator.
        tlp_color (str): The tlp color of the indicator.
        create_relationship (bool): Whether to create the indicator with relationships.

    Returns:
        dict[str, Any]: An indicator that can be sent to TIM.
    """
    
    relationships = create_relationships(create_relationship, reliability, indicator)

    indicator_type = indicator.get("type")  # ip/domain/email
    indicator_value = indicator.get("value") # type's value
    
    dynamic_field = {}
    dynamic_field[str(indicator_type)] = indicator_value
    
    fields = assign_params(
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
                TrafficLightProtocol=tlp_color,
                Location=indicator.get("locations"),
                ASN=indicator.get("asn")
            )

    # TODO check
    return assign_params(value=indicator_value, type=indicator_type, fields=fields, relationships=relationships, rawJSON=indicator,
                         score=1) # todo add score


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
    
    try:
        client = Client(
            base_url=f"{server_url}/api/",
            user_name=user_name,
            api_key=api_key,
            verify=not params.get("insecure", False),
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
            
        elif command == 'threatstream-feed-get-indicators':
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
        demisto.error(traceback.format_exc())  # Print the traceback stack
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
