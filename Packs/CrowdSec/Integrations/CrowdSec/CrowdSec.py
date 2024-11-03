import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""
    Cortex XSOAR CrowdSec Integration
"""

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

TABLE_HEADERS = [
    "IP",
    "IP Range",
    "AS Name",
    "AS Num",
    "Country",
    "Reverse DNS",
    "Behaviors",
    "First Seen",
    "Last Seen",
    "Activity in days",
    "Attacks Details",
    "Confidence",
    "CrowdSec Score",
    "Background Noise Score",
    "CrowdSec Console Link",
    "CrowdSec Taxonomy"
]

CROWDSEC_CTI_API_URL = "https://cti.api.crowdsec.net/v2/"

""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def get_ip_information(self, ip: str) -> dict:
        """
        Returns a simple python dict with the enriched information
        about the provided IP.

        :type ip: ``str``
        :param ip: ip to check against CrowdSec CTI

        :return: dict as {"ip": ip, "ip_range": ip_range ...}
        """
        response = self._http_request(
            method="GET", url_suffix=f"/smoke/{ip}", resp_type="response", ok_codes=(200, 404)
        )

        if response.status_code == 429:
            raise Exception(
                "You have been rate limited by CrowdSec CTI API. Please upgrade to Pro or wait."
            )

        return response.json()

    def test_module(self, ip: str):
        return self._http_request(
            method="GET", url_suffix=f"/smoke/{ip}", resp_type="response", ok_codes=(200, 403, 404)
        )


""" HELPER FUNCTIONS """


def format_readable(ip: str, data: dict, status: int) -> str:
    behaviors_readable = ""
    for behavior in data.get("behaviors", list()):
        behaviors_readable += behavior["label"] + "\n"

    cves_readable = ""
    for attack_detail in data.get("attack_details", list()):
        cves_readable += attack_detail["label"] + "\n"

    history = data.get("history", {})
    overall_score = data.get("scores", {}).get("overall", {})
    table_data = [
        {
            "IP": ip,
            "Status": status,
            "IP Range": data.get("ip_range"),
            "AS Name": data.get("as_name"),
            "AS Num": data.get("as_num"),
            "AS Country": data.get("location", {}).get("country"),
            "Reverse DNS": data.get("reverse_dns"),
            "Behaviors": behaviors_readable,
            "First Seen": history.get("first_seen", None),
            "Last Seen": history.get("last_seen", None),
            "Activity in days": history.get("days_age", None),
            "Attacks Details": cves_readable,
            "Confidence": f'{overall_score.get("trust", "0")}/5',
            "CrowdSec Score": f'{overall_score.get("total", "0")}/5',
            "Background Noise Score": f'{data.get("background_noise_score", 0)}/10',
            "CrowdSec Console Link": f"https://app.crowdsec.net/cti/{ip}",
            "CrowdSec Taxonomy": "https://docs.crowdsec.net/docs/next/cti_api/taxonomy"
        }
    ]

    ret = f"### IP {ip} status: {scoreToReputation(status)}\n"
    ret += tableToMarkdown(
        name="CrowdSec IP Enrichment",
        t=table_data,
        headers=TABLE_HEADERS,
        removeNull=True,
    )

    return ret


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    For this we use a random IP to check if we can query and authenticate against
    the CrowdSec CTI API.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    test_ip = "1.1.1.1"
    message: str = ""
    try:
        response = client.test_module(test_ip)
        if response.status_code in [200, 404]:
            message = "ok"
        elif response.status_code == 403:
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            message = "Something went wrong"
    except DemistoException as e:
        raise e
    return message


def ip_command(
    client: Client, reliability: str, args: dict[str, Any]
) -> List[CommandResults]:

    ips = argToList(args.get('ip'))
    if not ips or len(ips) == 0:
        raise ValueError("'ip' argument not specified")

    command_results: List[CommandResults] = []
    for ip in ips:
        if not is_ip_valid(ip):
            raise ValueError(f"Invalid IP '{ip}'")

        # Call the Client function and get the raw response
        result = client.get_ip_information(ip)
        if "message" in result and result["message"] == "IP address information not found":
            score = Common.DBotScore.NONE
        elif result["scores"]["overall"]["total"] > 3:
            score = Common.DBotScore.BAD
        elif result["scores"]["overall"]["total"] >= 2:
            score = Common.DBotScore.SUSPICIOUS
        else:
            score = Common.DBotScore.GOOD

        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name="CrowdSec",
            score=score,
            malicious_description="IP detected by CrowdSec",
            reliability=reliability,
        )

        if score == Common.DBotScore.NONE:
            ip_indicator = Common.IP(
                ip=ip,
                dbot_score=dbot_score,
            )
        else:
            tags = [behavior["name"] for behavior in result.get("behaviors", list())]
            tags.extend(
                [
                    classification["name"]
                    for classification in result["classifications"].get(
                        "classifications", list()
                    )
                ]
            )
            ip_indicator = Common.IP(
                ip=ip,
                dbot_score=dbot_score,
                asn=result["as_num"],
                as_owner=result["as_name"],
                hostname=result["reverse_dns"],
                geo_country=result["location"]["country"],
                geo_latitude=result["location"]["latitude"],
                geo_longitude=result["location"]["longitude"],
                tags=",".join(tags),
                publications=[
                    Common.Publications(
                        title="CrowdSec CTI",
                        source="CrowdSec",
                        timestamp=datetime.now().strftime(DATE_FORMAT),
                        link=f"https://app.crowdsec.net/cti/{ip}",
                    ),
                    Common.Publications(
                        title="CrowdSec CTI Taxonomy",
                        source="CrowdSec",
                        timestamp=datetime.now().strftime(DATE_FORMAT),
                        link="https://docs.crowdsec.net/docs/next/cti_api/taxonomy",
                    )
                ],
            )

        command_results.append(CommandResults(
            outputs_prefix="CrowdSec.Info",
            outputs_key_field="ip",
            outputs=result,
            indicator=ip_indicator,
            readable_output=format_readable(ip, result, score),
        ))

    return command_results


""" MAIN FUNCTION """


def main() -> None:
    api_key = demisto.params().get("apikey")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    demisto.debug(
        f"Command being called is {demisto.command()} with args {demisto.args()} and params {demisto.params()}"
    )
    try:
        reliability = demisto.params().get(
            "integrationReliability", "B - Usually reliable"
        )
        if DBotScoreReliability.is_valid_type(reliability):
            reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(
                reliability
            )
        else:
            raise Exception(
                "Please provide a valid value for the Source Reliability parameter."
            )

        headers: dict = {"x-api-key": api_key}

        client = Client(
            base_url=CROWDSEC_CTI_API_URL,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
        )

        if demisto.command() == "test-module":
            result = test_module(client)
            return_results(result)
        elif demisto.command() == "ip":
            return_results(ip_command(client, reliability, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{demisto.command()}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
