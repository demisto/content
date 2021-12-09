"""Recorded Future Integration for Demisto."""
from typing import Dict, Any, List, Tuple
from urllib import parse
import requests
import json
import re
from datetime import datetime, timedelta

# flake8: noqa: F402,F405 lgtm
import demistomock as demisto
from CommonServerPython import *

STATUS_TO_RETRY = [500, 501, 502, 503, 504]
LIMIT_IDENTITIES = 10_000

EMAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
ISO_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


# disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint:disable=no-member

__version__ = '1.0'


def period_to_date(period):
    current_time = datetime.now()
    periods_to_date = {
        'Last 24 Hours': (current_time - timedelta(days=1)).strftime(ISO_DATE_FORMAT),
        'Last 7 Days': (current_time - timedelta(weeks=1)).strftime(ISO_DATE_FORMAT),
        'Last Month': (current_time - timedelta(days=31)).strftime(ISO_DATE_FORMAT),
        'Last 3 Months': (current_time - timedelta(3*30)).strftime(ISO_DATE_FORMAT),
        'Last 6 Months': (current_time - timedelta(6*30)).strftime(ISO_DATE_FORMAT),
        'Last Year': (current_time - timedelta(365)).strftime(ISO_DATE_FORMAT),
        'All time': None,
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
        limit: int
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
                "limit": limit
            },
            timeout=120,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY
        )

    def identity_lookup(
        self,
        email_identities: List[str],
        authorization_identities: List[dict],
        date_period: str,
        password_properties: List[str]
    ) -> Dict[str, Any]:
        """Identity Lookup."""
        return self._http_request(
            method="post",
            url_suffix="identity/credentials/lookup",
            json_data={
                "subjects": email_identities,
                "subjects_login": authorization_identities,
                "filter": {
                    "first_downloaded_gte": date_period,
                    "properties": password_properties,
                }
            },
            timeout=120,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY
        )


#####################
#    Actions        #
#####################


class Actions():

    def __init__(self, rf_client: Client):
        self.client = rf_client

    def identity_search_command(
        self,
        domains: List[str],
        latest_downloaded: str,
        domain_type: str,
        password_properties: List[str],
        limit_identities: int
    ):
        """Search command for identities"""
        if domain_type == "All" or not domain_type:
            # If no domain type was specified API requires both of them.
            domain_type = ["Email", "Authorization"]
        else:
            domain_type = [domain_type]
        date_period = period_to_date(latest_downloaded)
        response = self.client.identity_search(domains, date_period, domain_type, password_properties, limit_identities)
        command_results = self.__build_search_context(response, domains)
        return command_results

    def __build_search_markdown(self, search_data, domains):
        if search_data:
            markdown=[f'## This is search results for {", ".join(domains)} :']
            for identity in search_data:
                if isinstance(identity, dict):
                    markdown.append(f"- **{identity['login']}**  in domain  {identity['domain']}")
                else:
                    markdown.append(f'- **{identity}**')
        else:
            markdown=[f'## There is no data for {", ".join(domains)} in selected period']
        return "\n".join(markdown)

    def __build_search_context(self, search_data, domains):
        result = CommandResults(
                readable_output=self.__build_search_markdown(search_data, domains),
                outputs_prefix='RecordedFuture.Credentials.SearchIdentities',
                outputs=search_data,
            )
        return result

    def identity_lookup_command(
        self,
        identities: str,
        first_downloaded: str,
        password_properties: List[str],
        domains: List[str],
    ):
        """Lookup comand for identities"""
        email_identities = []
        authorization_identities = []
        # We can get data from user input (command) or in playbook directly from Search.
        # We get a string of identities divided with semicolon from command.
        # From playbook we can get a dict that represents authorization identity.

        if isinstance(identities, str):
            identities = identities.split(';')
            for identity in identities:
                identity = identity.strip()
                if re.fullmatch(EMAIL_REGEX, identity):
                    email_identities.append(identity)
                else:
                    for domain in domains:
                        authorization_identities.append({
                            "login": identity,
                            "domain": domain,
                        })
        elif isinstance(identities, dict):
            authorization_identities.append(identities)
        else:
            raise DemistoException(f"Failed due to - Received unexpected data in Lookup command: {identities}")

        date_period = period_to_date(first_downloaded)
        response = self.client.identity_lookup(email_identities, authorization_identities, date_period, password_properties)
        identities_data = response.get('identities', [])
        command_results = self.__build_lookup_context(identities_data, identities)
        return command_results

    def __build_lookup_markdown(self, lookup_data, identities):
        if lookup_data:
            markdown=['## Credentials Lookup']
            markdown.append("*****")
            for identity in lookup_data:
                markdown.append(f'### Identity __{identity["identity"]["subjects"][0]}__:')
                markdown.append("*****")
                credentials = identity['credentials']
                passwords = []
                dumps = []
                breaches = []
                authorization_service_text = ''
                exfiltration_date_text = ''
                for idx, credential in  enumerate(credentials):
                    exposed_secret = credential["exposed_secret"]
                    password_number_text = f"Password {idx + 1}"
                    if exposed_secret["effectively_clear"] and exposed_secret['details'].get('clear_text_hint'):
                        passwords.append(
                            f"{password_number_text}: {exposed_secret['details']['clear_text_hint']} ({exposed_secret['type']})"
                        )
                    elif exposed_secret['hashes']:
                        hash_value = exposed_secret['hashes'][0]['hash']
                        hash_algorithm = exposed_secret['hashes'][0]['algorithm']
                        passwords.append(
                            f"{password_number_text}: {hash_value} ({hash_algorithm})"
                        )
                    if credential.get('authorization_service'):
                        authorization_service_text = f"Authorization service url: {credential['authorization_service']['url']}\n"
                    if credential.get('exfiltration_date'):
                        exfiltration_date = datetime.strptime(credential['exfiltration_date'], ISO_DATE_FORMAT).strftime("%b %Y")
                        exfiltration_date_text = f"Exfiltration date: {exfiltration_date}"
                    for dump in credential['dumps']:
                        dump_downloaded = dump.get('downloaded', '')
                        if dump_downloaded:
                            dump_downloaded = datetime.strptime(dump_downloaded, ISO_DATE_FORMAT).strftime("%b %Y")
                            dump_text = f"__{dump['name']}__, {dump_downloaded},  {password_number_text}"
                        else:
                            dump_text = f"__{dump['name']}__, {password_number_text}"
                        #There might be the same dumps in the response so we show only one.
                        if dump_text not in dumps:
                            dumps.append(dump_text)
                        dumps.append(f"{dump.get('description', '')}")
                        for breach in dump.get('breaches', []):
                            breach_date = breach.get('breached')
                            if breach_date:
                                breach_date = datetime.strptime(breach_date, ISO_DATE_FORMAT).strftime("%b %Y")
                                breaches.append(f"__{breach['name']}__, {breach_date}, {password_number_text}")
                            else:
                                breach_date = breaches.append(f"__{breach['name']}__, {password_number_text}")
                            breaches.append(breach.get('description', ''))


                markdown.append("### Exposed Password Data")
                markdown.extend(passwords)
                markdown.append(authorization_service_text)
                markdown.append(exfiltration_date_text)
                markdown.append("*****")
                if breaches:
                    # Authentication data do not have breaches
                    markdown.append("### Breaches")
                    markdown.extend(breaches)
                    markdown.append("*****")
                markdown.append("### Dumps")
                markdown.extend(dumps)
        else:
            if isinstance(identities, dict):
                identities = identities.get('login')
            markdown=[f'## There is no data for {", ".join(identities)} in selected period']

        return "\n".join(markdown)

    def __build_lookup_context(self, lookup_data, identities):
        result = CommandResults(
                readable_output=self.__build_lookup_markdown(lookup_data, identities),
                outputs_prefix='RecordedFuture.Credentials.Identities',
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
        domains =  demisto_params.get("domains", "").replace(' ', '').split(';')
        # If user has not set password properties we will get empty string but client require empty list
        password_properties = demisto_params.get("password_properties") or []
        try:
            limit_identities = int(demisto_params.get("limit_identities", LIMIT_IDENTITIES))
            # We can't do that on UI, so set the limit here.
            if limit_identities > LIMIT_IDENTITIES:
                limit_identities = LIMIT_IDENTITIES
        except ValueError:
            limit_identities = LIMIT_IDENTITIES

        headers = {
            "X-RFToken": demisto_params["token"],
            "X-RF-User-Agent": f"Cortex_XSOAR_Identity/{__version__} Cortex_XSOAR_"
            f'{demisto.demistoVersion()["version"]}',
        }
        client = Client(
            base_url=base_url, verify=verify_ssl, headers=headers, proxy=proxy,
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
                    demisto_args.get("latest-downloaded"),
                    demisto_args.get("domain_type"),
                    password_properties,
                    limit_identities,
                )
            )
        elif command == "recordedfuture-identity-lookup":
            return_results(
                actions.identity_lookup_command(
                    demisto_args.get("identities"),
                    demisto_args.get("first-downloaded"),
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
