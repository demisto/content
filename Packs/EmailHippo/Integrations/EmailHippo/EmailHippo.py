import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3
import dateparser
from requests import Response
from functools import partial
from typing import Any


# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
TRUST_LEVEL_TO_DBOT_SCORE_MAPPING = {
    "None": Common.DBotScore.NONE,
    "High": Common.DBotScore.GOOD,
    "Medium": Common.DBotScore.SUSPICIOUS,
    "Low": Common.DBotScore.BAD,
}


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, more_api_key, whois_api_key, more_server_url, whois_server_url, **kwargs):
        self._more_api_key = more_api_key
        self._whois_api_key = whois_api_key
        self._more_server_url = more_server_url.rstrip("/")
        self._whois_server_url = f'{whois_server_url.rstrip("/")}/v1/{whois_api_key}'

        super().__init__(base_url="", **kwargs)

    def get_email_reputation(self, email: str) -> dict[str, Any]:
        """Gets the Email reputation using the hippoapi '/email' API endpoint

        Args:
            email (str): Email address to get the reputation for.

        Returns:
            dict: dict containing the Email reputation as returned from the API
        """

        return self._http_request(
            method="GET",
            full_url=f"{self._more_server_url}/v3/more/json/{self._more_api_key}/{email}",
            with_metrics=True,
        )

    def get_domain_reputation(self, domain: str) -> dict[str, Any]:
        """
        Gets the Domain reputation using the whoishippo '/domain' API endpoint.

        Args:
            domain (str): Domain name to get the reputation for.

        Returns:
            dict: dict containing the domain reputation as returned from the API.
        """

        return self._http_request(
            method="GET",
            full_url=f"{self._whois_server_url}/{domain}",
            with_metrics=True,
        )

    def get_email_quota(self) -> dict[str, Any]:
        """
        Get the email quota remaining for the API key
        """
        return self._http_request(
            method="GET",
            full_url=f"{self._more_server_url}/customer/reports/v3/quota/{self._more_api_key}",
            with_metrics=True,
        )

    def determine_error_type(self, res: Response):
        """Determines the error type based on response.

        Args:
            res (Response): The response object from the http request.

        Returns:
            (ErrorTypes): The error type determined.
        """
        if "Insufficient quota" in res.text:
            return ErrorTypes.QUOTA_ERROR
        return super().determine_error_type(res)


def parse_domain_date(domain_date: list[str] | str, date_format: str = "%Y-%m-%dT%H:%M:%S.000Z") -> str | None:
    """
    Converts whois date format to an ISO8601 string.
    Converts the domain WHOIS date (YYYY-mm-dd HH:MM:SS) format
    in a datetime. If a list is returned with multiple elements, takes only
    the first one.

    Args:
        domain_date (str/list): a string or list of strings with the format 'YYYY-mm-DD HH:MM:SS'
        date_format (int): The format date to which the function will convert the given date.

    Returns:
        str: Parsed time, default in ISO8601 format.
    """

    if isinstance(domain_date, str):
        # if str parse the value
        domain_date_dt = dateparser.parse(domain_date)
        if domain_date_dt:
            return domain_date_dt.strftime(date_format)
    elif isinstance(domain_date, list) and len(domain_date) > 0 and isinstance(domain_date[0], str):
        # if list with at least one element, parse the first element
        domain_date_dt = dateparser.parse(domain_date[0])
        if domain_date_dt:
            return domain_date_dt.strftime(date_format)
    # in any other case return nothing
    return None


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication for both, EmailHippo and WHOIS.
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): EmailHippo client to use.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    test_methods: dict[str, Any] = {
        "MORE": partial(client.get_email_reputation, "test@test.com"),
        "WHOIS": partial(client.get_domain_reputation, "google.com"),
    }

    for key_vendor in test_methods:
        try:
            test_methods[key_vendor]()
        except DemistoException as e:
            if "Unauthorized" in str(e):
                return f"Authorization Error: make sure {key_vendor} API Key is correctly set"
            else:
                raise e
    return "ok"


def get_email_quota_command(client: Client) -> CommandResults:
    """
    email-hippo-email-quota-get command: Returns the email quota.

    Args:
        client (Client): EmailHippo client to use.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``.
    """

    quota = client.get_email_quota()
    quota.pop("licenseKey", None)  # delete the licenseKey as this are secret

    readable_output = tableToMarkdown(
        "Email quota", {"Email Quota used": quota.get("quotaUsed"), "Email Quota remaining": quota.get("quotaRemaining")}
    )
    return CommandResults(
        readable_output=readable_output, outputs_prefix="EmailHippo.Quota", outputs_key_field="accountId", outputs=quota
    )


def email_reputation_command(
    client: Client, args: dict[str, Any], reliability: DBotScoreReliability, create_relationships: bool = False
) -> list[CommandResults]:
    """
    email command: Returns Email reputation for a list of Emails

    Args:
        client (Client): EmailHippo client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
        reliability (DBotScoreReliability): reliability of the source providing the intelligence data.
        create_relationships (bool): whether to create relationships between the email and domain.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains Emails.
    """

    emails = argToList(args.get("email"))
    if len(emails) == 0:
        raise ValueError("Email(s) not specified")

    command_results: list[CommandResults] = []

    for email in emails:
        email_data = client.get_email_reputation(email)
        email_data["Address"] = email

        domain = demisto.get(email_data, "meta.domain")
        level = demisto.get(email_data, "hippoTrust.level")
        reputation = TRUST_LEVEL_TO_DBOT_SCORE_MAPPING.get(level, Common.DBotScore.NONE)

        dbot_score = Common.DBotScore(
            indicator=email,
            indicator_type=DBotScoreType.EMAIL,
            integration_name="Email Hippo",
            score=reputation,
            malicious_description=f"Email Hippo returned reputation {reputation}",
            reliability=reliability,
        )
        relationships = []
        if create_relationships:
            relationships.append(
                EntityRelationship(
                    entity_a=email,
                    entity_a_type=FeedIndicatorType.Email,
                    name="related-to",
                    entity_b=domain,
                    entity_b_type=FeedIndicatorType.Domain,
                    brand="Email Hippo",
                )
            )

        email_indicator = Common.EMAIL(address=email, dbot_score=dbot_score, domain=domain, relationships=relationships)

        email_readable = {
            "Result": demisto.get(email_data, "emailVerification.mailboxVerification"),
            "Hippo Trust Score": demisto.get(email_data, "hippoTrust.level"),
            "Inbox quality score": demisto.get(email_data, "sendAssess.sendRecommendation"),
            "Spam risk score": demisto.get(email_data, "spamAssess.actionRecomendation"),
        }
        readable_output = tableToMarkdown(f"Email {email}", email_readable)

        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix="EmailHippo.Email",
                outputs_key_field="Address",
                outputs=email_data,
                indicator=email_indicator,
                relationships=relationships,
            )
        )
    return command_results


def domain_reputation_command(client: Client, args: dict[str, Any], reliability: DBotScoreReliability) -> list[CommandResults]:
    """
    domain command: Returns domain reputation for a list of domains.

    Args:
        client (Client): EmailHippo client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
        reliability (DBotScoreReliability): reliability of the source providing the intelligence data.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains Domains.
    """

    domains = argToList(args.get("domain"))
    if len(domains) == 0:
        raise ValueError("domain(s) not specified")

    command_results: list[CommandResults] = []

    for domain in domains:
        domain_data = client.get_domain_reputation(domain)
        domain_data["domain"] = domain

        # convert the dates to ISO8601 as Cortex XSOAR customers use this format by default
        if creation_date := demisto.get(domain_data, "meta.recordCreatedDate"):
            domain_data["creation_date"] = parse_domain_date(creation_date)
        if updated_date := demisto.get(domain_data, "meta.recordUpdatedDate"):
            domain_data["updated_date"] = parse_domain_date(updated_date)

        dbot_score = Common.DBotScore(
            indicator=domain,
            integration_name="Email Hippo",
            indicator_type=DBotScoreType.DOMAIN,
            score=Common.DBotScore.NONE,
            reliability=reliability,
        )

        domain_indicator = Common.Domain(
            domain=domain,
            creation_date=domain_data.get("creation_date", None),
            updated_date=domain_data.get("updated_date", None),
            # organization=domain_data.get('org', None),
            name_servers=demisto.get(domain_data, "whoisServerRecord.nameServers"),
            registrar_name=demisto.get(domain_data, "whoisServerRecord.registrar.name"),
            registrar_abuse_phone=demisto.get(domain_data, "whoisServerRecord.registrar.abusePhone"),
            registrar_abuse_email=demisto.get(domain_data, "whoisServerRecord.registrar.abuseEmail"),
            admin_name=demisto.get(domain_data, "whoisServerRecord.adminContact.name"),
            admin_country=demisto.get(domain_data, "whoisServerRecord.adminContact.country"),
            admin_email=demisto.get(domain_data, "whoisServerRecord.adminContact.email"),
            admin_phone=demisto.get(domain_data, "whoisServerRecord.adminContact.phoneNumber"),
            tech_country=demisto.get(domain_data, "whoisServerRecord.techContact.country"),
            tech_name=demisto.get(domain_data, "whoisServerRecord.techContact.name"),
            tech_organization=demisto.get(domain_data, "whoisServerRecord.techContact.organization"),
            tech_email=demisto.get(domain_data, "whoisServerRecord.techContact.email"),
            dbot_score=dbot_score,
        )

        domain_readable = {
            "Registrar": demisto.get(domain_data, "whoisServerRecord.registrar.name"),
            "Registered On": demisto.get(domain_data, "whoisServerRecord.created"),
            "Domain Age": demisto.get(domain_data, "meta.domainAge"),
            "Expires On": demisto.get(domain_data, "whoisServerRecord.expiry"),
            "Time To Expiry": demisto.get(domain_data, "meta.timeToExpiry"),
            "Updated On": demisto.get(domain_data, "whoisServerRecord.changed"),
            "Status": demisto.get(domain_data, "whoisServerRecord.domainStati"),
            "Name servers": demisto.get(domain_data, "whoisServerRecord.nameServers"),
        }
        readable_output = tableToMarkdown(f"Domain {domain}", domain_readable)
        # delete the rawResponse key from the output
        domain_data.get("whoisServerRecord", {}).pop("rawResponse", None)
        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix="EmailHippo.Domain",
                outputs_key_field="domain",
                outputs=domain_data,
                indicator=domain_indicator,
            )
        )
    return command_results


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    more_api_key = params.get("more_credentials", {}).get("password")
    whois_api_key = params.get("whois_credentials", {}).get("password")
    more_server_url = params.get("more_server_url", "https://api.hippoapi.com")
    whois_server_url = params.get("whois_server_url", "https://api.whoishippo.com")

    reliability = params.get("integrationReliability", DBotScoreReliability.C)

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    res: list[CommandResults] = []
    client = None
    try:
        client = Client(
            more_api_key=more_api_key,
            whois_api_key=whois_api_key,
            more_server_url=more_server_url,
            whois_server_url=whois_server_url,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "email":
            res = email_reputation_command(client, args, reliability)

        elif command == "domain":
            res = domain_reputation_command(client, args, reliability)

        elif command == "email-hippo-email-quota-get":
            res = [get_email_quota_command(client)]

        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        if res:
            return_results(res)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
