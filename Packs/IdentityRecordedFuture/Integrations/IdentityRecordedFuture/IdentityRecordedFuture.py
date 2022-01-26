"""Recorded Future Integration for Demisto."""
from typing import Dict, Any, List, Union
import requests
import json
import re
import dateparser
from datetime import datetime, timedelta

# flake8: noqa: F402,F405 lgtm
import demistomock as demisto
from CommonServerPython import *

STATUS_TO_RETRY = [500, 501, 502, 503, 504]
LIMIT_IDENTITIES = 10_000

ISO_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


# disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint:disable=no-member

__version__ = "1.0"


def period_to_date(period):
    current_time = datetime.now()
    periods_to_date = {
        "Last 24 Hours": (current_time - timedelta(days=1)).strftime(
            ISO_DATE_FORMAT
        ),
        "Last 7 Days": (current_time - timedelta(weeks=1)).strftime(
            ISO_DATE_FORMAT
        ),
        "Last Month": (current_time - timedelta(days=31)).strftime(
            ISO_DATE_FORMAT
        ),
        "Last 3 Months": (current_time - timedelta(3 * 30)).strftime(
            ISO_DATE_FORMAT
        ),
        "Last 6 Months": (current_time - timedelta(6 * 30)).strftime(
            ISO_DATE_FORMAT
        ),
        "Last Year": (current_time - timedelta(365)).strftime(ISO_DATE_FORMAT),
        "All time": None,
    }
    return periods_to_date[period]


class Client(BaseClient):
    def whoami(self) -> Dict[str, Any]:
        """Entity lookup."""
        return self._http_request(
            method="get",
            url_suffix="info/whoami",
            timeout=60,
        )

    def identity_search(
        self,
        domains: List[str],
        date_period: str,
        domain_type: List[str],
        password_properties: List[str],
        limit: int,
    ) -> Dict[str, Any]:
        """Identity search."""
        return self._http_request(
            method="post",
            url_suffix="identity/credentials/search",
            json_data={
                "domains": domains,
                "domain_types": domain_type,
                "filter": {
                    "properties": password_properties,
                    "latest_downloaded_gte": date_period,
                },
                "limit": limit,
            },
            timeout=120,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
        )

    def identity_lookup(
        self,
        email_identities: List[str],
        authorization_identities: List[dict],
        sha1_identities: List[str],
        date_period: str,
        password_properties: List[str],
    ) -> Dict[str, Any]:
        """Identity Lookup."""
        return self._http_request(
            method="post",
            url_suffix="identity/credentials/lookup",
            json_data={
                "subjects": email_identities,
                "subjects_login": authorization_identities,
                "subjects_sha1": sha1_identities,
                "filter": {
                    "first_downloaded_gte": date_period,
                    "properties": password_properties,
                },
            },
            timeout=120,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
        )


#####################
#    Actions        #
#####################


class Actions:
    def __init__(self, rf_client: Client):
        self.client = rf_client

    def identity_search_command(
        self,
        domains: List[str],
        latest_downloaded: str,
        domain_type: Union[list, str],
        password_properties: List[str],
        limit_identities: int,
    ):
        """Search command for identities"""
        if domain_type == "All" or not domain_type:
            # If no domain type was specified API requires both of them.
            domain_type = ["Email", "Authorization"]
        else:
            domain_type = [domain_type]
        date_period = period_to_date(latest_downloaded)
        response = self.client.identity_search(
            domains,
            date_period,
            domain_type,
            password_properties,
            limit_identities,
        )
        command_results = self.__build_search_context(response, domains)
        return command_results

    def __build_search_markdown(self, search_data, domains):
        if search_data:
            markdown = [
                f'## This is search results for {", ".join(domains)} :'
            ]
            for identity in search_data:
                if isinstance(identity, dict):
                    markdown.append(
                        f"- **{identity['login']}**  in domain  {identity['domain']}"
                    )
                else:
                    markdown.append(f"- **{identity}**")
        else:
            markdown = [
                f'## There is no data for {", ".join(domains)} in selected period'
            ]
        return "\n".join(markdown)

    def __build_search_context(self, search_data, domains):
        result = CommandResults(
            readable_output=self.__build_search_markdown(search_data, domains),
            outputs_prefix="RecordedFuture.Credentials.SearchIdentities",
            outputs=search_data,
        )
        return result

    def identity_lookup_command(
        self,
        identities: Union[List, str],
        first_downloaded: str,
        password_properties: List[str],
        domains: List[str],
    ):
        """Lookup comand for identities"""
        email_identities = []
        authorization_identities = []
        sha1_identities = []
        # We can get data from user input (command) or in playbook directly from Search.
        # We get a string of identities divided with semicolon from command.
        # From playbook we can get a dict that represents authorization identity.

        if isinstance(identities, str):
            identities = identities.replace(" ", "").split(";")
            for identity in identities:
                if re.fullmatch(emailRegex, identity):
                    email_identities.append(identity)
                # If user used sha1 value for lookup try to find it in authorization data and email data
                elif re.fullmatch(sha1Regex, identity):
                    sha1_identities.append(identity)
                    for domain in domains:
                        authorization_identities.append(
                            {
                                "login_sha1": identity,
                                "domain": domain,
                            }
                        )
                else:
                    for domain in domains:
                        authorization_identities.append(
                            {
                                "login": identity,
                                "domain": domain,
                            }
                        )
        elif isinstance(identities, dict):
            authorization_identities.append(identities)
        else:
            raise DemistoException(
                f"Failed due to - Received unexpected data in Lookup command: {identities}"
            )

        date_period = period_to_date(first_downloaded)
        response = self.client.identity_lookup(
            email_identities,
            authorization_identities,
            sha1_identities,
            date_period,
            password_properties,
        )
        identities_data = response.get("identities", [])
        command_results = self.__build_lookup_context(
            identities_data, identities
        )
        return command_results

    def __build_lookup_markdown(self, lookup_data, identities):
        if lookup_data:
            markdown = ["## Credentials Lookup"]
            markdown.append("*****")
            for identity in lookup_data:
                markdown.append(
                    f'### Identity __{identity["identity"]["subjects"][0]}__:'
                )
                markdown.append("*****")
                credentials = identity["credentials"]
                passwords_section = []
                dumps_section = []
                breaches_section = []
                for idx, credential in enumerate(credentials):
                    exposed_secret = credential["exposed_secret"]
                    password_number_text = f"__Password {idx + 1}__"
                    passwords_section.append(f"{password_number_text}:")
                    if exposed_secret.get("details", {}).get("rank"):
                        passwords_section.append(
                            f"__Rank__: {exposed_secret['details']['rank']}"
                        )
                    if exposed_secret.get(
                        "effectively_clear", False
                    ) and exposed_secret.get("details", {}).get(
                        "clear_text_hint"
                    ):
                        passwords_section.append(
                            f"{exposed_secret['details']['clear_text_hint']} (__{exposed_secret['type']}__)"
                        )
                    if exposed_secret.get("hashes"):
                        for hash_password in exposed_secret["hashes"]:
                            # When user do not have permissions for domain
                            # we will receive hash_prefix instead of full hash.
                            hash_value = hash_password.get(
                                "hash"
                            ) or hash_password.get("hash_prefix")
                            hash_algorithm = hash_password["algorithm"]
                            passwords_section.append(
                                f"{hash_value} (__{hash_algorithm}__)"
                            )
                    if credential.get("authorization_service"):
                        passwords_section.append(
                            f"Authorization service url: {credential['authorization_service']['url']}\n"
                        )
                    if credential.get("exfiltration_date"):
                        exfiltration_date = dateparser.parse(
                            credential["exfiltration_date"]
                        ).strftime("%b %Y")
                        passwords_section.append(
                            f"Exfiltration date: {exfiltration_date}"
                        )
                    for dump in credential["dumps"]:
                        dump_downloaded = dump.get("downloaded", "")
                        if dump_downloaded:
                            dump_downloaded = dateparser.parse(
                                dump_downloaded
                            ).strftime("%b %Y")
                            dump_text = f"__{dump['name']}__, {dump_downloaded},  {password_number_text}"
                        else:
                            dump_text = (
                                f"__{dump['name']}__, {password_number_text}"
                            )
                        # There might be the same dumps in the response so we show only one.
                        if dump_text not in dumps_section:
                            dumps_section.append(dump_text)
                            if dump.get("type"):
                                dumps_section.append(
                                    f"__Dump type:__ {dump['type']}"
                                )
                            dumps_section.append(
                                f"{dump.get('description', '')}"
                            )
                        for breach in dump.get("breaches", []):
                            breach_date = breach.get("breached")
                            if breach_date:
                                breach_date = dateparser.parse(
                                    breach_date
                                ).strftime("%b %Y")
                                breaches_section.append(
                                    f"__{breach['name']}__, {breach_date}, {password_number_text}"
                                )
                            else:
                                breaches_section.append(
                                    f"__{breach['name']}__, {password_number_text}"
                                )
                            if breach.get("type"):
                                breaches_section.append(
                                    f"__Breach type:__ {breach['type']}"
                                )
                            breaches_section.append(
                                breach.get("description", "")
                            )

                markdown.append("### Exposed Password Data")
                markdown.extend(passwords_section)
                markdown.append("*****")
                if breaches_section:
                    # Authentication data do not have breaches
                    markdown.append("### Breaches")
                    markdown.extend(breaches_section)
                    markdown.append("*****")
                markdown.append("### Dumps")
                markdown.extend(dumps_section)
        else:
            if isinstance(identities, dict):
                identities = identities.get("login")
            markdown = [
                f'## There is no data for {", ".join(identities)} in selected period'
            ]

        return "\n".join(markdown)

    def __build_lookup_context(self, lookup_data, identities):
        result = CommandResults(
            readable_output=self.__build_lookup_markdown(
                lookup_data, identities
            ),
            outputs_prefix="RecordedFuture.Credentials.Identities",
            outputs=lookup_data,
        )
        return result


def main() -> None:
    """Main method used to run actions."""
    try:
        demisto_params = demisto.params()
        demisto_args = demisto.args()
        base_url = demisto_params.get("server_url", "").rstrip("/")
        verify_ssl = not demisto_params.get("unsecure", False)
        proxy = demisto_params.get("proxy", False)
        # Clean the input from the user and split string
        domains = (
            demisto_params.get("domains", "")
            .rstrip(";")
            .replace(" ", "")
            .split(";")
        )
        # If user has not set password properties we will get empty string but client require empty list
        password_properties = demisto_params.get("password_properties") or []
        try:
            limit_identities = int(
                demisto_params.get("limit_identities", LIMIT_IDENTITIES)
            )
            # We can't do that on UI, so set the limit here.
            if limit_identities > LIMIT_IDENTITIES:
                limit_identities = LIMIT_IDENTITIES
        except ValueError:
            limit_identities = LIMIT_IDENTITIES

        headers = {
            "X-RFToken": demisto_params["token"],
            "X-RF-User-Agent": f"xsoar-identity/{__version__} rfclient (Cortex_XSOAR_"
            f'{demisto.demistoVersion()["version"]})',
        }
        client = Client(
            base_url=base_url,
            verify=verify_ssl,
            headers=headers,
            proxy=proxy,
        )
        command = demisto.command()
        actions = Actions(client)
        if command == "test-module":
            try:
                client.whoami()
                return_results("ok")
            except Exception as err:
                message = str(err)
                try:
                    error = json.loads(str(err).split("\n")[1])
                    if "fail" in error.get("result", {}).get("status", ""):
                        message = error.get("result", {})["message"]
                except Exception:
                    message = (
                        "Unknown error. Please verify that the API"
                        f" URL and Token are correctly configured. RAW Error: {err}"
                    )
                raise DemistoException(f"Failed due to - {message}")

        elif command == "recordedfuture-identity-search":
            return_results(
                actions.identity_search_command(
                    domains,
                    demisto_args.get("latest-downloaded", "All time"),
                    demisto_args.get("domain-type"),
                    password_properties,
                    limit_identities,
                )
            )
        elif command == "recordedfuture-identity-lookup":
            return_results(
                actions.identity_lookup_command(
                    demisto_args.get("identities"),
                    demisto_args.get("first-downloaded", "All time"),
                    password_properties,
                    domains,
                )
            )

    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command. "
            f"Error: {str(e)}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
