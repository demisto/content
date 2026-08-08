import json
from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

''' CONSTANTS '''

DEFAULT_BASE_URL = "https://api.darkwebscan.app/v1"
DEFAULT_PAGE_SIZE = 50

INTEGRATION_NAME = "BechtleDarkWebScan"
INTEGRATION_VERSION = "1.0.0"

VENDOR = "Bechtle"

SENSITIVE_FIELDS_FOR_REDACTION = {"password", "password_hash", "cvv", "card_number"}

CONTEXT_SEEN_LEAK_IDS_KEY = "seen_leak_ids"
CONTEXT_LAST_FETCH_KEY = "last_leak_fetch"
MAX_SEEN_IDS_TO_RETAIN = 5000
MAX_SEEN_IDS_PER_COMPANY = 1000


''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the DarkWebScan API.
    All API-specific logic (auth, pagination, request shaping) lives here.
    Command functions should call this client rather than using requests directly.
    """

    def __init__(self, base_url: str, api_key: str, additional_request_headers: str, verify: bool, proxy: bool):
        headers = {
            "apiKey": f"{api_key}",
            "Content-Type": "application/json",
            "User-Agent": f"{INTEGRATION_NAME}-PANW-XSOAR/{INTEGRATION_VERSION}"
        }

        if additional_request_headers:
            for line in additional_request_headers.strip().splitlines():
                if ":" in line:
                    key, val = line.split(":",1)
                    headers[key.strip()] = val.strip()
        
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_companies(self, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE) -> dict:
        """
        Retrieve the list of companies/assets currently being monitored.
        """
        params = {
            "page": page,
            "page_size": page_size,
        }
        
        response = self._http_request(
            method="GET",
            url_suffix="/user/companies",
            params=params,
            resp_type="response" 
        )
        
        if not response.text or response.status_code == 204:
            return {}
            
        try:
            return response.json()
        except ValueError:
            raise DemistoException(
                f"API endpoint returned invalid, non-JSON text data (Status {response.status_code}): {response.text}"
            )


    def get_leaks(
            self, 
            company_id: int = 0, 
            since: Optional[str] = None,
            page: int = 1, 
            page_size: int = DEFAULT_PAGE_SIZE
        ) -> dict:
        """
        Retrieve leaked credentials for a given company_id.
        """
        try:
            params = {
                "companyId": company_id,
                "page": page,
                "amount": page_size,
            }
            return self._http_request(
                method="GET",
                url_suffix="/user/lookout/my-leaked-data",
                params=params,
            )
        except Exception as e:
            demisto.error(f"get_leaks: {e}")
            return {}
    
    def get_email_security(
            self, 
            company_id: int = 0, 
        ) -> dict:
        """
        Retrieve information about the email security of the domain from a given company_id.
        """
        params = {
            "companyId": company_id
        }
        return self._http_request(
            method="GET",
            url_suffix="/scan/email-security",
            params=params,
        )
    
    def get_osint(
            self, 
            company_id: int = 0, 
        ) -> dict:
        """
        Retrieve OSINT information about the associated domain of a given company_id.
        """
        params = {
            "companyId": company_id
        }
        return self._http_request(
            method="GET",
            url_suffix="/scan/osint",
            params=params,
        )
    
    def get_waf(
            self, 
            company_id: int = 0, 
        ) -> dict:
        """
        Retrieve Web Application Firewall Status information about the associated domain of a given company_id.
        """
        params = {
            "companyId": company_id
        }
        return self._http_request(
            method="GET",
            url_suffix="/scan/waf",
            params=params,
        )


''' HELPER FUNCTIONS '''


def _redact_rows(rows: list[dict[str, Any]], redact: bool) -> list[dict[str, Any]]:
    """
    Mask sensitive fields (e.g. plaintext passwords) before they hit the
    War Room / context unless the integration is explicitly configured not to.
    """
    if not redact:
        return rows
    return [
        {k: ("***" if k in SENSITIVE_FIELDS_FOR_REDACTION and v not in (None, "", []) else v) for k, v in row.items()}
        for row in rows
    ]


def _should_redact_secrets(params: dict) -> bool:
    raw = params.get("redact_secrets")
    if raw is None:
        return True
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in {"true", "1", "yes", "on"}


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Called when clicking the 'Test' button in the integration configuration.
    Validates the API key / connectivity by making a lightweight call.
    """
    client.get_companies(page=1, page_size=1)
    return "ok"


def _color_tag(text: str, color: str) -> str:
    """
    Wrap text in XSOAR-flavored markdown color syntax.
    """
    if not color:
        return text
    return f"{{{{color:{color}}}}}({text})"


def _get_all_company_ids(client: Client) -> list[int]:
    """
    Fetch all monitored companies in a single call.
    """
    response = client.get_companies(page=1, page_size=DEFAULT_PAGE_SIZE)
    if isinstance(response, list):
        companies = response
    else:
        companies = response.get("companies", response.get("results", []))
    return [c["company_id"] for c in companies if c.get("company_id") is not None]


def _to_iso8601(date_str: Optional[str]) -> str:
    """
    Normalize a date/datetime string to full ISO 8601 (YYYY-MM-DDTHH:MM:SSZ),
    as required by the 'occurred' field in incident dicts.
    """
    if not date_str:
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    dt = arg_to_datetime(date_str)
    if dt is None:
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_company_id_arg(args: dict) -> int:
    """
    Extracts, validates, and explicitly casts 'company_id' from command arguments.
    Raises a ValueError if missing or invalid.
    """
    company_id_raw = args.get("company_id")
    
    if company_id_raw is None:
        raise ValueError("Missing required argument: 'company_id'")
        
    company_id = arg_to_number(company_id_raw)
    
    if company_id is None:
        raise ValueError(f"Invalid integer value provided for 'company_id': {company_id_raw}")
        
    return int(company_id)


def darkwebscan_getcompanies_command(client: Client, args: dict) -> CommandResults:
    """
    darkwebscan-getcompanies
    Lists the companies/assets currently monitored by BechtleDarkWebScan.
    """
    page = arg_to_number(args.get("page")) or 1
    page_size = arg_to_number(args.get("page_size")) or DEFAULT_PAGE_SIZE

    companies = client.get_companies(page=page, page_size=page_size)
    
    if not isinstance(companies, list):
        companies_list = [companies] if companies else []
    else:
        companies_list = companies

    # Map the exact keys returned by the API to the markdown table headers
    readable_output = tableToMarkdown(
        name="DarkWebScan Companies",
        t=companies_list,
        headers=["company_id", "printableName", "fqdn", "scanCreditsAmount"],
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="BechtleDarkWebScan.Companies",
        outputs_key_field="id",
        outputs=companies_list,
        readable_output=readable_output,
        raw_response=companies_list,
    )


def darkwebscan_getleaks_command(client: Client, args: dict) -> CommandResults:
    """
    darkwebscan-getleaks
    Retrieves leaked-credential records, optionally filtered by company and/or
    a start date, with optional redaction of sensitive fields.
    """
    only_new = argToBoolean(args.get("only_new", "false"))
    company_id = get_company_id_arg(args)
    since = args.get("since")
    page = arg_to_number(args.get("page")) or 1
    page_size = arg_to_number(args.get("page_size")) or DEFAULT_PAGE_SIZE
    redact = argToBoolean(args.get("redact_secrets", "true"))

    if args.get("company_id") is not None and company_id is None:
        raise ValueError(f"Invalid 'company_id' value: {args.get('company_id')}. Must be an integer.")
    
    integration_context = get_integration_context()
    seen_ids = set(integration_context.get(CONTEXT_SEEN_LEAK_IDS_KEY, []))
    last_fetch = integration_context.get(CONTEXT_LAST_FETCH_KEY)

    response = client.get_leaks(company_id=company_id, since=since, page=page, page_size=page_size)
    leaks = response.get("searchResults", None)

    if only_new:
        new_leaks = [leak for leak in leaks if leak.get("id") not in seen_ids]
    else:
        new_leaks = leaks

    # Update context: remember these IDs
    if new_leaks:
        newest_timestamp = max(
            (leak.get("date") for leak in new_leaks if leak.get("date")),
            default=last_fetch,
        )
        seen_ids.update(leak.get("id") for leak in new_leaks if leak.get("id"))
        if len(seen_ids) > MAX_SEEN_IDS_TO_RETAIN:
            seen_ids = set(list(seen_ids)[-MAX_SEEN_IDS_TO_RETAIN:])

        set_integration_context({
            CONTEXT_SEEN_LEAK_IDS_KEY: list(seen_ids),
            CONTEXT_LAST_FETCH_KEY: newest_timestamp
        })
    
    new_leaks = _redact_rows(new_leaks, redact)

    readable_output = tableToMarkdown(
        name="DarkWebScan Leaked Credentials (only new)" if only_new else "DarkWebScan Leaked Credentials",
        t=new_leaks,
        headers=["id", "domain", "links", "stealer", "source", "username", "price", "size", "date"],
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="BechtleDarkWebScan.LeakedCredentials",
        outputs_key_field="id",
        outputs=new_leaks,
        readable_output=readable_output,
        raw_response=response,
    )

def format_subdomains_and_emails(api_response: dict) -> str:
    """
    Transforms the API JSON response into two human-readable Markdown tables.
    """
    markdown_outputs = []
    
    subdomains_list = api_response.get('subdomains', [])
    if subdomains_list:
        subdomains_table = tableToMarkdown(
            name='Monitored Subdomains',
            t=subdomains_list,
            headers=['subdomain', 'description'],
            headerTransform=pascalToSpace           
        )
        markdown_outputs.append(subdomains_table)
        
    
    emails_list = api_response.get('emailAddresses', [])
    if emails_list:
        emails_table = tableToMarkdown(
            name='Monitored Email Addresses',
            t=emails_list,
            headers=['email'],
            headerTransform=string_to_table_header
        )
        markdown_outputs.append(emails_table)
        
    if markdown_outputs:
        return '\n\n'.join(markdown_outputs)
    
    return 'No subdomains or email addresses found.'

def darkwebscan_getosint_command(client: Client, args: dict) -> CommandResults:
    """
    darkwebscan-getosint
    Returns OSINT information about the associated domain of a given company_id.
    """
    company_id = get_company_id_arg(args)
    response = client.get_osint(company_id=company_id)

    return CommandResults(
        outputs_prefix="BechtleDarkWebScan.OSINT",
        outputs_key_field="domain",
        outputs=response,
        readable_output=format_subdomains_and_emails(response),
        raw_response=response,
    )



def darkwebscan_getemailsecurity_command(client: Client, args: dict) -> CommandResults:
    """
    darkwebscan-getemailsecurity
    Returns information about the email security for the associated domain of a given company_id.
    """
    company_id = get_company_id_arg(args)
    response = client.get_email_security(company_id=company_id)

    spf = response.get("spf",{})
    dmarc = response.get("dmarc",{})
    dane = response.get("dane",{})

    output = {
        "SPF": {
            "Record": spf.get("spfRecord"),
            "Info": spf.get("warning"),
            "Summary": spf.get("summary")
        },
        "DMARC": {
            "Record": dmarc.get("dmarcRecord"),
            "Info": dmarc.get("warning"),
            "Summary": dmarc.get("summary")
        },
        "DANE": {
            "EmailHosts": dane.get("emailHosts"),
            "Info": dane.get("warning"),
            "Summary": dane.get("summary")
        }
    }

    summary_rows = [
        {"Check": "SPF", "Status": _color_tag(spf.get("summary"), spf.get('warningColor'))},
        {"Check": "DMARC", "Status": _color_tag(dmarc.get("summary"), dmarc.get('warningColor'))},
        {"Check": "DANE", "Status": _color_tag(dane.get("summary"), dane.get('warningColor'))}
    ]

    # Map the exact keys returned by the API to the markdown table headers
    readable_output = tableToMarkdown(
        name="DarkWebScan Email Security",
        t=summary_rows,
        headers=["Check", "Status"],
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="BechtleDarkWebScan.EmailSecurity",
        outputs_key_field="SPF",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


def darkwebscan_getwaf_command(client: Client, args: dict) -> CommandResults:
    """
    darkwebscan-getosint
    Returns OSINT information about the associated domain of a given company_id.
    """
    company_id = get_company_id_arg(args)
    response = client.get_waf(company_id=company_id)

    summary = {
        "product": response.get('product'),
        "summary": response.get('summary'),
        "warning": _color_tag(response.get('warning'), response.get('warningColor')),
    }

    # Map the exact keys returned by the API to the markdown table headers
    readable_output = tableToMarkdown(
        name="DarkWebScan Web Application Firewall Status",
        t=summary,
        headers=["product", "summary", "warning"],
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="BechtleDarkWebScan.WAF",
        outputs_key_field="summary",
        outputs=response,
        readable_output=readable_output,
        raw_response=response,
    )


def fetch_incidents(client: Client, last_run: dict, first_fetch: str, max_fetch: int) -> tuple[dict, list]:
    default_since = arg_to_datetime(first_fetch).strftime("%Y-%m-%dT%H:%M:%SZ")
    companies_state = last_run.get("companies", {})

    company_ids = _get_all_company_ids(client)

    incidents = []
    next_companies_state = {}

    for cid in company_ids:
        demisto.debug(f"cid: {cid}")
        cid_key = str(cid)
        state = companies_state.get(cid_key, {})
        since = state.get("last_fetch", default_since)
        seen_ids = set(state.get("seen_ids", []))

        demisto.debug(f"Getting leaks for company ID {cid}")

        response = client.get_leaks(company_id=cid, since=since, page=1, page_size=DEFAULT_BASE_URL)
        leaks = response.get("searchResults", [])

        newest_timestamp = since
        demisto.debug("Iterating leaks...")
        for leak in leaks:
            leak_id = leak.get("id")
            if leak_id in seen_ids:
                demisto.debug("Already seen a leak with this ID. Ignoring...")
                continue
            if len(incidents) >= max_fetch:
                demisto.debug("Reached max_fetch. Skipping...")
                break

            alertJSON = {
                "id": leak.get('id', None), 
                "date": leak.get('date', 'Unknown'),
                "domain": leak.get('domain', 'Unknown'),
                "links": leak.get('links', 'Unknown'),
                "username": leak.get('username', 'Username not included with initial offer'),
                "price": leak.get('price', ''), 
                "size": leak.get('size', None),
                "source": leak.get('source', None),
                "stealer": leak.get('stealer', None) 
            }

            occurred = _to_iso8601(leak.get("date") or None)
            demisto.debug("Preparing leak info...")
            incidents.append({
                "name": (
                    f"DarkWebScan Leak: {leak.get('links', 'unknown')} "
                    f"({leak.get('source', leak.get('stealer', 'unknown source'))})"
                ),
                "type": "DarkWebScan Leak",
                "details": (
                    f"New Dark Web Leak: {leak.get('links', 'unknown URL')}, "
                    f"Username: {leak.get('username', 'Username not included with initial offer')}, "
                    f"Price: {leak.get('price', 'Unknown')}, "
                    f"Source: {leak.get('source', leak.get('stealer', 'unknown') + ' Stealer')}"
                ),
                "occurred": occurred,
                "severity": 2,
                "rawJSON": json.dumps(alertJSON),
            })
            demisto.debug("Adding this leak's id to the known leak ids...")
            seen_ids.add(leak_id)
            if occurred > newest_timestamp:
                newest_timestamp = occurred
        
        if len(seen_ids) > MAX_SEEN_IDS_PER_COMPANY:
            seen_ids = set(list(seen_ids)[-MAX_SEEN_IDS_PER_COMPANY:])
        
        demisto.debug("Setting next_companies_state...")
        next_companies_state[cid_key] = {
            "last_fetch": newest_timestamp,
            "seen_ids": list(seen_ids)
        }
    
    return {"companies": next_companies_state}, incidents


def darkwebscan_resetcontext_command() -> CommandResults:
    set_integration_context({})
    return CommandResults(readable_output="Integration context cleared.")


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get("apikey")
    additional_request_headers = params.get("addreqheaders")
    base_url = params.get("url", DEFAULT_BASE_URL).rstrip("/")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            additional_request_headers=additional_request_headers,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command in ('test-module', ''):
            return_results(test_module(client))
        
        elif command == "fetch-incidents":
            first_fetch = params.get("first_fetch", "6 months")
            max_fetch = arg_to_number(params.get("max_fetch")) or 50
            next_run, incidents = fetch_incidents(client, demisto.getLastRun(), first_fetch, max_fetch)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == "darkwebscan-getcompanies":
            return_results(darkwebscan_getcompanies_command(client, args))

        elif command == "darkwebscan-getleaks":
            return_results(darkwebscan_getleaks_command(client, args))

        elif command == "darkwebscan-getemailsecurity":
            return_results(darkwebscan_getemailsecurity_command(client,args))

        elif command == "darkwebscan-getosint":
            return_results(darkwebscan_getosint_command(client, args))

        elif command == "darkwebscan-getwaf":
            return_results(darkwebscan_getwaf_command(client, args))

        elif command == "darkwebscan-resetcontext":
            return_results(darkwebscan_resetcontext_command())

        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


''' ENTRY POINT '''

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
