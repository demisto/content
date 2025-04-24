import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url: str, headers: dict, proxy: bool = False, verify: bool = False):
        super().__init__(base_url=base_url, headers=headers, proxy=proxy, verify=verify)

    def query(self, suffix: str) -> Dict[str, Any]:
        return self._http_request(method="GET", url_suffix=suffix)


def test_module(client: Client, query: str) -> str:
    result = client.query(query)
    if result:
        return "ok"
    else:
        return "Test failed: " + str(result)


def create_indicator_output(results: Dict[str, Any], indicator: str, indicatortype: str, reliability: str) -> CommandResults:
    if indicatortype == "ip":
        indicator_type = DBotScoreType.IP
    else:
        indicator_type = DBotScoreType.EMAIL

    if "is associated" in results["message"]:
        dbot_score_object = Common.DBotScore(
            indicator=indicator, indicator_type=indicator_type, integration_name="Hudsonrock", score=3, reliability=reliability
        )
    else:
        dbot_score_object = Common.DBotScore(
            indicator=indicator, indicator_type=indicator_type, integration_name="Hudsonrock", score=0, reliability=reliability
        )
    indicator_to_return: Union[Common.IP, Common.EMAIL]
    if indicatortype == "ip":
        indicator_to_return = Common.IP(dbot_score=dbot_score_object, ip=indicator)
        outputs_prefix_end = "IP"
        results["ip"] = indicator
    else:
        indicator_to_return = Common.EMAIL(dbot_score=dbot_score_object, address=indicator)
        outputs_prefix_end = "Email"
        results["email"] = indicator

    human_readable = tableToMarkdown("Hudsonrock results", results)
    return CommandResults(
        outputs_prefix=f"Hudsonrock.{outputs_prefix_end}",
        outputs_key_field="indicator",
        outputs=results,
        indicator=indicator_to_return,
        readable_output=human_readable,
    )


def create_output(results: Dict[str, Any], endpoint: str, keyfield: str = "") -> CommandResults:
    human_readable = tableToMarkdown("Hudsonrock results", results)
    return CommandResults(
        outputs_prefix=f"Hudsonrock.{endpoint}", outputs_key_field=keyfield, outputs=results, readable_output=human_readable
    )


def main():
    base_url = demisto.params()["url"]
    full_url = f"{base_url}api/json/v2/osint-tools/"

    verify_certificate = not demisto.params().get("insecure", False)

    proxy = demisto.params().get("proxy", False)

    headers = {"Accept": "application/json"}
    reliability = demisto.params().get("integrationReliability", DBotScoreReliability.B)

    demisto.info(f"Command being called is {demisto.command()}")

    try:
        client = Client(base_url=full_url, verify=verify_certificate, headers=headers, proxy=proxy)
        args = demisto.args()

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            query = "/search-by-ip?ip=127.0.0.1"
            testresult = test_module(client, query)
            return_results(testresult)
        elif demisto.command() == "ip":
            ip = argToList(args.get("ip"))
            for item in ip:
                query = f"/search-by-ip?ip={item}"
                result = client.query(query)
                return_results(create_indicator_output(result, item, "ip", reliability))
        elif demisto.command() == "email":
            email = argToList(args.get("email"))
            for item in email:
                query = f"/search-by-email?email={item}"
                result = client.query(query)
                return_results(create_indicator_output(result, item, "email", reliability))
        elif demisto.command() == "hudsonrock-get-username":
            username = args.get("username")
            query = f"/search-by-username?username={username}"
            result = client.query(query)
            return_results(create_output(result, username, "Username"))

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
