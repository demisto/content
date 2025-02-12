import demistomock as demisto
from CommonServerPython import *
import requests
import traceback
from typing import Dict, Any, Optional, List
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

SECURITYSCORECARD_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

""" CLIENT CLASS """


class SecurityScorecardClient(BaseClient):
    """Client class that interacts with the SecurityScorecard API

    Attributes:
        ``username`` (``str``): SecurityScorecard username/email.
        ``api_key`` (``str``): SecurityScorecard API token.
        ``max_fetch`` (``int``): Maximum alerts to fetch.
    """

    def __init__(self, base_url, verify, proxy, headers, username, api_key, max_fetch=50):
        """
        Args:
            base_url (str): SecurityScorecard base URL.
            verify (bool): Whether to verify certificates.
            proxy (bool): Whether to use Cortex XSOAR proxy.
            headers (dict): Dictionary holding the HTTP headers.
        """
        super().__init__(
            base_url,
            verify=verify,
            proxy=proxy,
            headers=headers
        )
        self.username = username
        self.api_key = api_key
        self.max_fetch = max_fetch

    def get_portfolios(self) -> Dict[str, Any]:
        return self.http_request_wrapper(
            method='GET',
            url_suffix='portfolios'
        )

    def get_companies_in_portfolio(
        self,
        portfolio: str,
        grade: Optional[str],
        industry: Optional[str],
        vulnerability: Optional[str],
        issue_type: Optional[str],
        had_breach_within_last_days: Optional[int]
    ) -> Dict[str, Any]:

        request_params: Dict[str, Any] = assign_params(
            grade=grade,
            industry=industry,
            vulnerability=vulnerability,
            issue_type=issue_type,
            had_breach_within_last_days=had_breach_within_last_days
        )

        return self.http_request_wrapper(
            method='GET',
            url_suffix=f'portfolios/{portfolio}/companies',
            params=request_params
        )

    def get_company_score(self, domain: str) -> Dict[str, Any]:

        return self.http_request_wrapper(
            method='GET',
            url_suffix=f'companies/{domain}'
        )

    def get_company_factor_score(self, domain: str, severity_in: Optional[List[str]]) -> Dict[str, Any]:

        request_params: Optional[Dict[str, Any]] = {
            "severity_in": severity_in
        } if severity_in else None

        return self.http_request_wrapper(
            method='GET',
            url_suffix=f'companies/{domain}/factors',
            params=request_params
        )

    def get_company_events(self, domain: str, date_from: str, date_to: str) -> Dict[str, Any]:

        request_params: Dict[str, Any] = assign_params(
            date_from=date_from,
            date_to=date_to
        )

        return self.http_request_wrapper(
            method='GET',
            url_suffix=f'companies/{domain}/history/events',
            params=request_params
        )

    def get_company_event_findings(self, domain: str, date: str, issue_type: str, status: str) -> Dict[str, Any]:

        request_params: Dict[str, Any] = assign_params(
            group_status=status
        )

        return self.http_request_wrapper(
            method='GET',
            url_suffix=f'companies/{domain}/history/events/{date}/issues/{issue_type}',
            params=request_params
        )

    def get_company_issue_findings(self, domain: str, issue_type: str) -> Dict[str, Any]:

        return self.http_request_wrapper(
            method='GET',
            url_suffix=f'companies/{domain}/issues/{issue_type}')

    def get_company_historical_scores(self, domain: str, _from: str, to: str, timing: str) -> Dict[str, Any]:

        request_params: Dict[str, Any] = assign_params(
            to=to,
            timing=timing,
            domain=domain
        )

        # assign_params cannot accept 'from' as a parameter since it's a Python keyword
        if _from:
            request_params['from'] = _from

        return self.http_request_wrapper(
            method='GET',
            url_suffix=f'companies/{domain}/history/score',
            params=request_params)

    def get_company_historical_factor_scores(self, domain: str, _from: str, to: str, timing: str) -> Dict[str, Any]:

        request_params: Dict[str, Any] = assign_params(
            to=to,
            timing=timing
        )

        # Cannot use assign_params with reserved Python keyword 'from'
        if _from:
            request_params['from'] = _from

        return self.http_request_wrapper(
            method='GET',
            url_suffix=f'companies/{domain}/history/factors/score',
            params=request_params
        )

    def get_issue_metadata(self, issue_type: str) -> Dict[str, Any]:

        return self.http_request_wrapper(
            method='GET',
            url_suffix=f'metadata/issue-types/{issue_type}'
        )

    def create_alert_subscription(
        self,
        event_type: str,
        delivery: Dict[str, Any],
    ) -> Dict[str, Any]:

        payload: Dict[str, Any] = assign_params(
            event_type=event_type,
            delivery=delivery,
        )

        return self.http_request_wrapper(
            method='POST',
            url_suffix="subscriptions",
            json_data=payload
        )

    def delete_alert(self, id: str) -> None:

        return self.http_request_wrapper(
            method="DELETE",
            url_suffix=f"subscriptions/{id}",
            return_empty_response=True
        )

    def get_subscriptions(self) -> Dict[str, Any]:

        query_params: Dict[str, Any] = assign_params(
            username=self.username,
        )

        return self.http_request_wrapper(
            method="GET",
            url_suffix="subscriptions",
            params=query_params
        )

    def get_alerts_last_week(self, email: str, portfolio_id: Optional[str]) -> Dict[str, Any]:

        query_params: Dict[str, Any] = assign_params(
            portfolio=portfolio_id
        )

        return self.http_request_wrapper(
            method="GET",
            url_suffix=f"users/by-username/{email}/notifications/recent",
            params=query_params
        )

    def get_domain_services(self, domain: str) -> Dict[str, Any]:

        return self.http_request_wrapper(
            method='GET',
            url_suffix=f"companies/{domain}/services"
        )

    def fetch_alerts(self, page_size: int, page: int) -> Dict[str, Any]:

        query_params: Dict[str, Any] = assign_params(
            username=self.username,
            page_size=page_size,
            sort="date",
            order="asc",
            page=page
        )

        return self.http_request_wrapper(
            method="GET",
            url_suffix=f"users/by-username/{self.username}/notifications/recent",
            params=query_params
        )

    def http_request_wrapper(
        self,
        method: str,
        url_suffix: Optional[str] = None,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
        return_empty_response: Optional[bool] = False
    ):
        """Wrapper for the ``http_request`` function

        Args:
            ``self`` (``SecurityScorecardClient``).
            ``method`` (``str``): The HTTP method.
            ``url_suffix`` (``Optional[str]``): The URL suffix, appended to the base URL. Defaults to None.
            ``params`` (``Optional[dict]``): The query parameters sent in the HTTP request. Defaults to None.
            ``json_data`` (``Optional[dict]``): The payload to be sent in the HTTP request in JSON format. Defaults to None.

        Return:
            ``dict`` or ``str`` or ``requests.Response``
        """

        return super()._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            json_data=json_data,
            error_handler=self.error_handler,
            return_empty_response=return_empty_response
        )

    @staticmethod
    def error_handler(response: requests.Response):
        """
        Error handler for the API requests

        Args:
            response (requests.Response): The server's response to the HTTP request.
        """

        try:
            error_response_json = response.json().get("error")
            raise DemistoException(f'{error_response_json.get("message")} ({error_response_json.get("statusCode")})')
        except ValueError:
            raise DemistoException(f'Error parsing response as JSON. Response: {response.status_code} {str(response.content)}')


""" HELPER FUNCTIONS """


def get_last_run(
    last_run: str = demisto.getLastRun().get("last_run"),
    first_fetch: str = demisto.params().get("first_fetch", "2 days")
) -> datetime:
    """
    Helper function to return the last incident fetch runtime as a `datetime` object.
    It uses the datetime of last_run from the demisto instance and first_fetch parameter.

    Args:
        ``last_run`` (``str``): last run datetime string of fetch
        ``first_fetch`` (``str``): first fetch from integration parameters

    Returns:
        ``datetime`` representing the last fetch occurred.
    """

    # Check for existence of last run
    # When integration runs for the first time, it will not exist
    # Set 2 days by default if the first fetch parameter is not set

    if last_run:
        demisto.debug(f"Last run already exists: '{last_run}'")
        return arg_to_datetime(last_run).replace(tzinfo=None)  # type: ignore
    else:

        demisto.debug(f"First fetch is defined as '{first_fetch}'")
        days_ago = first_fetch

        fetch_days_ago = arg_to_datetime(arg=days_ago, arg_name="first_fetch", required=False)

        demisto.debug(f"getLastRun is 'None' in Integration context, using parameter '{days_ago}' value '{fetch_days_ago}'")

        return fetch_days_ago.replace(tzinfo=None)  # type: ignore


def incidents_to_import(alerts: List[Dict[str, Any]], last_run: datetime = get_last_run()) -> List[Dict[str, Any]]:
    """
    Helper function to filter events that need to be imported.
    It filters the events based on the `created_at` timestamp.
    Function will only be called if the SecurityScorecard API returns more than one alert.

    Args:
        ``alerts``(``List[Dict[str, Any]]``): A list of alerts to sort through.
    Returns:
        ``List[Dict[str, Any]]``: Alerts to import
    """

    incidents: List[Dict[str, Any]] = []

    # Check if there are more than 0 alerts
    if alerts:

        # The alerts are sorted by ascending date so last alert is the most recent
        most_recent_alert = alerts[-1]

        most_recent_alert_created_date = most_recent_alert.get("created_at")

        most_recent_alert_datetime = arg_to_datetime(most_recent_alert_created_date).replace(tzinfo=None)  # type: ignore

        for alert in alerts:

            demisto.debug(f"iterating alert id '{alert}'...")
            alert_id = alert.get("id")
            alert_created_at = alert.get("created_at")

            # alert_created_at includes a timezone whereas arg_to_datetime doesn't
            # therefore we need to eliminate tz info and set seconds=0
            # preventing err "can't compare offset-naive and offset-aware datetimes"
            alert_datetime = arg_to_datetime(alert_created_at).replace(tzinfo=None).replace(second=0)  # type: ignore
            company_name: str = alert.get("company_name")  # type: ignore
            change_type: str = alert.get("change_type")  # type: ignore
            demisto.debug(f"alert_created_at: {alert_created_at}")
            demisto.debug(f"alert_datetime: {alert_datetime}")
            demisto.debug(f"last_run: {last_run}")
            debug_msg = f"import alert '{alert_id}'? (last_run < alert_datetime): {(last_run < alert_datetime)}"  # type: ignore

            demisto.debug(debug_msg)

            if alert_datetime > last_run:  # type: ignore
                incident = {}
                incident["name"] = f"{company_name} {change_type.replace('_', ' ').title()}"
                incident["occurred"] = alert_datetime.strftime(format=DATE_FORMAT)  # type: ignore
                incident["rawJSON"] = json.dumps(alert)
                incidents.append(incident)

                demisto.debug(
                    f"Setting setLastRun as alert most recent: \
                        {most_recent_alert_datetime.strftime(format=DATE_FORMAT)}"  # type: ignore
                )

                demisto.setLastRun({
                    'last_run': most_recent_alert_datetime.strftime(format=DATE_FORMAT)  # type: ignore
                })
                demisto.debug("Finished setLastRun")

    # If there are no alerts then we can't use the most recent alert timestamp
    # So we'll use the last run timestamp (last alert fetch modified date)
    else:
        demisto.debug(f"No alerts retrieved, setting last_run to last modified time ({last_run})")
        demisto.setLastRun(last_run)

    return incidents


""" COMMAND FUNCTIONS """


def test_module(
    client: SecurityScorecardClient,
    incident_fetch_interval: Optional[str]
) -> str:
    """Tests API connectivity and authentication

    Runs the fetch-alerts mechanism to validate all integration parameters

    Args:
        ``client`` (``SecurityScorecardClient``): SecurityScorecard client

    Returns:
        ``str``: 'ok' if test passed, anything else will fail the test.
    """
    demisto.debug("Initialized test module...")

    interval = arg_to_number(arg=incident_fetch_interval, arg_name="incident_fetch_interval", required=False)

    if interval > 1440 * 2:  # type: ignore
        return "Test failed. Incident Fetch Interval is greater than 2 days."

    max_incidents = int(client.max_fetch)
    if max_incidents > 50:
        return "Test failed. Max Fetch is larger than 50."

    client.fetch_alerts(page_size=1, page=1)
    demisto.debug("Test module successful")
    return ('ok')

# region Methods
# ---------------


def portfolios_list_command(client: SecurityScorecardClient, args: Dict[str, str]) -> CommandResults:
    """List all Portfolios you have access to.

    See https://securityscorecard.readme.io/reference#get_portfolios

    Args:
        ``client`` (``SecurityScorecardClient``): SecurityScorecard client
        ``args`` (``Dict[str, str]``): Portfolio fetch limit

    Returns:
        ``CommandResults``: The results of the command.
    """

    limit = arg_to_number(  # type: ignore
        arg=args.get("limit", "50"),
        arg_name="limit",
        required=False
    )

    portfolios = client.get_portfolios()

    portfolios_total = int(portfolios.get("total"))  # type: ignore

    # Check that API returned more than 0 portfolios
    if portfolios_total == 0:
        return CommandResults(
            readable_output="No Portfolios were found in your account. Please create a new one and try again.",
            outputs_prefix=None,
            outputs=None,
            raw_response=portfolios,
            outputs_key_field=None
        )

    # API response is a dict with 'entries'
    entries = portfolios.get('entries')

    # If the number of portfolios returned is larger than the configured limit
    # filter the first elements
    if portfolios_total > limit:  # type: ignore
        demisto.debug(f"portfolios_total ({portfolios_total}) > limit ({limit}), slicing number of entries")
        entries = entries[:limit]  # type: ignore

    markdown = tableToMarkdown(
        f'Your SecurityScorecard Portfolios (first {limit})',
        entries,
        headers=['id', 'name', 'privacy']
    )

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='SecurityScorecard.Portfolio',
        outputs_key_field='id',
        outputs=entries,
        raw_response=portfolios
    )

    return results


def portfolio_list_companies_command(
    client: SecurityScorecardClient,
    args: Dict[str, Any]
) -> CommandResults:
    """Retrieve all companies in portfolio.

    https://securityscorecard.readme.io/reference#get_portfolios-portfolio-id-companies

    Args:
        ``client`` (``SecurityScorecardClient``): SecurityScorecard client
        ``args`` (``Dict[str, Any]``): Includes
            - portfolio ID
            - Grade filter
            - Industry filter
            - Vulnerability filter
            - Issue type filter
            - Filter breach days back
    Returns:
        ``CommandResults``: The results of the command.
    """

    portfolio_id = args.get("portfolio_id")  # type: ignore
    grade = args.get("grade")
    industry_arg = args.get("industry")
    vulnerability = args.get("vulnerability")
    issue_type = args.get("issue_type")

    # We need to capitalize the industry to conform to API
    industry = str.upper(industry_arg) if industry_arg else None  # type: ignore

    had_breach_within_last_days = arg_to_number(  # type: ignore
        arg=args.get("had_breach_within_last_days"),
        arg_name='had_breach_within_last_days',
        required=False
    )

    response = client.get_companies_in_portfolio(
        portfolio=portfolio_id,  # type: ignore
        grade=grade,
        industry=industry,
        vulnerability=vulnerability,
        issue_type=issue_type,
        had_breach_within_last_days=had_breach_within_last_days  # type: ignore
    )

    # Check if the portfolio has more than 1 company
    total_portfolios = int(response.get('total'))  # type: ignore
    if not total_portfolios > 0:
        return CommandResults(
            readable_output=f"No companies found in Portfolio '{portfolio_id}'. Please add a company to it and retry.",
            raw_response=response,
            outputs_key_field=None
        )

    companies = response.get('entries')

    title = f"**{total_portfolios}** companies found in Portfolio {portfolio_id}\n"
    markdown = tableToMarkdown(
        title,
        companies,
        headers=['domain', 'name', 'score', 'last30days_score_change', 'industry', 'size']
    )

    results = CommandResults(
        outputs_prefix="SecurityScorecard.Portfolio.Company",
        readable_output=markdown,
        outputs=companies,
        raw_response=response,
        outputs_key_field='name'
    )

    return results


def company_score_get_command(client: SecurityScorecardClient, args: Dict[str, str]) -> CommandResults:
    """Retrieve company overall score.

    See https://securityscorecard.readme.io/reference#get_companies-scorecard-identifier-factors

    Args:
        ``client`` (``SecurityScorecardClient``): SecurityScorecard client
        ``args`` (``Dict[str, str]``): The domain to get the score for.

    Returns:
        ``CommandResults``: The results of the command.
    """

    domain = args.get("domain")

    score = client.get_company_score(domain=domain)  # type: ignore

    markdown = tableToMarkdown(
        f"Domain {domain} Scorecard",
        score,
        headers=['name', 'grade', 'score', 'industry', 'last30day_score_change', 'size']
    )

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="SecurityScorecard.Company.Score",
        outputs=score,
        raw_response=score,
        outputs_key_field='name'
    )

    return results


def company_factor_score_get_command(
    client: SecurityScorecardClient,
    args: Dict[str, Any]
) -> CommandResults:
    """Retrieve company factor score and scores

    See https://securityscorecard.readme.io/reference#get_companies-scorecard-identifier-factors

    Args:
        ``client`` (``SecurityScorecardClient``): SecurityScorecard client
        ``args`` (``Dict[str, Any]``): The domain and severity filter

    Returns:
        ``CommandResults``: The results of the command.
    """

    domain = args.get("domain")
    severity = args.get("severity")

    response = client.get_company_factor_score(domain=domain, severity_in=severity)  # type: ignore

    entries = response['entries']

    factor_scores = []
    for entry in entries:
        score = {
            "name": entry.get("name"),
            "grade": entry.get("grade"),
            "score": entry.get("score"),
            "issues": len(entry.get("issue_summary")),
            "issue details": entry.get("issue_summary")
        }

        factor_scores.append(score)

    markdown = tableToMarkdown(
        f"Domain {domain} Scorecard",
        factor_scores,
        headers=['name', 'grade', 'score', 'issues']
    )

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="SecurityScorecard.Company.Factor",
        outputs=entries,
        raw_response=response,
        outputs_key_field='name'
    )

    return results


def company_history_score_get_command(client: SecurityScorecardClient, args: Dict[str, str]) -> CommandResults:
    """Retrieve company historical scores

    See https://securityscorecard.readme.io/reference/get_companies-scorecard-identifier-history-score

    Args:
        ``client`` (``SecurityScorecardClient``): SecurityScorecard client.
        ``args`` (``Dict[str, str]``): Domain, start date, end date, timing.

    Returns:
        ``CommandResults``: The results of the command.
    """

    domain = args.get("domain")
    _from = args.get("from")
    to = args.get("to")
    timing = args.get("timing")

    response = client.get_company_historical_scores(domain=domain, _from=_from, to=to, timing=timing)  # type: ignore

    entries = response.get('entries')

    markdown = tableToMarkdown(
        f"Historical Scores for Domain [`{domain}`](https://{domain})",
        entries,
        headers=['date', 'score']
    )

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="SecurityScorecard.Company.ScoreHistory",
        outputs=entries,
        raw_response=response,
        outputs_key_field="date"
    )

    return results


def company_events_get_command(
    client: SecurityScorecardClient,
    args: Dict[str, Any]
) -> CommandResults:
    """Retrieve company events

    See https://securityscorecard.readme.io/reference/get_companies-scorecard-identifier-history-events

    Args:
        ``client`` (``SecurityScorecardClient``): SecurityScorecard client
        ``args`` (``Dict[str, Any]``): The domain, the initial date and the end (date_from, date_to)

    Returns:
        ``CommandResults``: The results of the command.
    """

    domain = args.get("domain")
    date_from = args.get("date_from")
    date_to = args.get("date_to")

    response = client.get_company_events(domain=domain, date_to=date_to, date_from=date_from)  # type: ignore

    entries = response['entries']

    events = []
    for entry in entries:
        event = {
            "ssc_event_id": entry.get("id"),
            "date": entry.get("date"),
            "status": entry.get("group_status"),
            "issue_count": entry.get("issue_count"),
            "score_impact": entry.get("total_score_impact"),
            "issue_type": entry.get("issue_type"),
            "severity": entry.get("severity"),
            "factor": entry.get("factor"),
            "ssc_detail_url": entry.get("detail_url")
        }

        events.append(event)

    markdown = tableToMarkdown(
        f"Domain {domain} Events",
        events,
        headers=['ssc_event_id', 'date', 'status', 'factor', 'issue_type',
                 'severity', 'issue_count', 'score_impact', 'ssc_detail_url']
    )

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="SecurityScorecard.Company.Events",
        outputs=entries,
        raw_response=response,
        outputs_key_field='ssc_event_id'
    )

    return results


def company_event_findings_get_command(
    client: SecurityScorecardClient,
    args: Dict[str, Any]
) -> CommandResults:
    """Get an issue_type's historical findings in a scorecard

    See (example issue_type): https://securityscorecard.readme.io/reference/get_companies-scorecard-identifier-history-events-effective-date-issues-active-cve-exploitation-attempted-1

    Args:
        ``client`` (``SecurityScorecardClient``): SecurityScorecard client
        ``args`` (``Dict[str, Any]``): domain, date, issue_type, status

    Returns:
        ``CommandResults``: The results of the command.
    """

    domain = args.get("domain")
    date = args.get("date")
    issue_type = args.get("issue_type")
    status = args.get("status")

    response = client.get_company_event_findings(domain=domain, date=date, issue_type=issue_type, status=status)  # type: ignore

    entries = response['entries']

    events = []
    for entry in entries:

        # some issue types have domains, IPs and/or ports, but not all of them do
        if "domain" in entry:
            domain = entry.get("domain")
        elif "target" in entry:
            domain = entry.get("target")
        else:
            domain = ""

        if "ip" in entry:
            ip = entry.get("ip")
        elif "src_ip" in entry:
            ip = entry.get("src_ip")
        elif "ip_address" in entry:
            ip = entry.get("ip_address")
        elif "connection_attributes" in entry:
            ip = entry.get("connection_attributes").get("dst_ip")
        else:
            ip = ""

        if "protocol" in entry:
            protocol = entry.get("protocol")
        elif "scheme" in entry:
            protocol = entry.get("scheme")
        elif "connection_attributes" in entry:
            protocol = entry.get("connection_attributes").get("protocol")
        else:
            protocol = ""

        if "port" in entry:
            port = entry.get("port")
        elif "connection_attributes" in entry:
            port = entry.get("connection_attributes").get("dst_port")
        else:
            port = ""

        event = {
            "parent_domain": entry.get("parent_domain"),
            "count": entry.get("count"),
            "status": entry.get("group_status"),
            "first_seen_time": entry.get("first_seen_time"),
            "last_seen_time": entry.get("last_seen_time"),
            # the following details may or may not be populated
            "port": port,
            "domain_name": domain,
            "ip_address": ip,
            "protocol": protocol,
            "observations": entry.get("observations"),
            "issue_type": issue_type
        }

        events.append(event)

    markdown = tableToMarkdown(
        f"Domain {domain} Findings for {issue_type}",
        events,
        headers=['parent_domain', 'issue_type', 'count', 'status', 'first_seen_time',
                 'last_seen_time', 'port', 'domain_name', 'ip_address', 'protocol', 'observations']
    )

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="SecurityScorecard.Company.Findings",
        outputs=entries,
        raw_response=response,
        outputs_key_field='issue_id'
    )

    return results


def company_history_factor_score_get_command(client: SecurityScorecardClient, args: Dict[str, str]) -> CommandResults:
    """Retrieve company historical factor scores

    See https://securityscorecard.readme.io/reference#get_companies-scorecard-identifier-history-factors-score

    Args:
        ``client`` (``SecurityScorecardClient``): SecurityScorecard client.
        ``args`` (``Dict[str, str]``): Domain, start date, end date, timing.


    Returns:
        ``CommandResults``: The results of the command.
    """

    domain = args.get("domain")
    _from = args.get("from")
    to = args.get("to")
    timing = args.get("timing")

    response = client.get_company_historical_factor_scores(domain=domain, _from=_from, to=to, timing=timing)  # type: ignore

    entries = response['entries']

    factor_scores = []

    for entry in entries:
        factors = entry.get("factors")
        factor_row = ''
        for factor in factors:
            factor_name = factor.get("name").title().replace("_", " ")
            factor_score = factor.get("score")

            factor_row = factor_row + f"{factor_name}: {factor_score}\n"

        score = {
            "date": entry.get("date").split("T")[0],
            "factors": factor_row
        }

        factor_scores.append(score)

    markdown = tableToMarkdown(f"Historical Factor Scores for Domain {domain})", factor_scores)

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="SecurityScorecard.Company.FactorHistory",
        outputs=entries,
        raw_response=response,
        outputs_key_field='date'
    )

    return results


def issue_metadata_get_command(client: SecurityScorecardClient, args: Dict[str, str]) -> CommandResults:
    """Retrieve description and recommendation for an issue.

    See https://securityscorecard.readme.io/reference/get_metadata-issue-types-type-1

    Args:
        ``client`` (``SecurityScorecardClient``): SecurityScorecard client
        ``args`` (``Dict[str, str]``): The issue type to retrieve metadata for.

    Returns:
        ``CommandResults``: The results of the command.
    """

    issue_type = args.get("issue_type")

    metadata = client.get_issue_metadata(issue_type=issue_type)  # type: ignore

    markdown = tableToMarkdown(
        f"Issue Type {issue_type}",
        metadata,
        headers=['key', 'severity', 'factor', 'title', 'short_description', 'long_description', 'recommendation']
    )

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="SecurityScorecard.Metadata.Issues",
        outputs=metadata,
        raw_response=metadata,
        outputs_key_field='key'
    )

    return results


@logger
def alert_grade_change_create_command(client: SecurityScorecardClient, args: Dict[str, str]) -> CommandResults:
    """Create an alert based on grade change.
    This function creates an alert subscription for grade changes in SecurityScorecard.
    It supports alerts for both overall and factor-specific grade changes.

    See POST /subscriptions

    Args:
        client (SecurityScorecardClient): The SecurityScorecard client instance.
        args (Dict[str, str]): The command arguments containing:
            - change_direction (str): The direction of the grade change ('drops' or 'raises').
            - score_types (str): The types of scores to monitor (e.g., 'overall', 'network_security').
            - target (str): The target entity for the alert (e.g., 'any_followed_company', 'my_scorecard').
            - portfolio (str): The portfolio ID to monitor.

    Returns:
        CommandResults: The results of the command, including the created alert ID.

    Raises:
        DemistoException: If both 'portfolio' and 'target' are set, or if neither is set.
    """
    change_direction = args.get("change_direction")
    score_types = argToList(args.get('score_types'))
    target = args.get('target')
    portfolio = args.get('portfolio')

    # Only one argument between portfolio and target should be defined
    # Return error if neither of them is defined or if both are defined
    if portfolio and target:
        raise DemistoException("Both 'portfolio' and 'target' argument have been set. Please remove one of them and try again.")
    elif not (target or portfolio):
        raise DemistoException("Either 'portfolio' or 'target' argument must be given")

    filters_changes_value = (
        "factor_grade_drop" if change_direction == "drops" else "factor_grade_raise"
    ) if "overall" not in score_types else (
        "grade_drop" if change_direction == "drops" else "grade_raise"
    )
    name = (
        f"Alert me when {target or 'portfolio'} {change_direction} in "
        f"{'factor(s) ' if 'overall' not in score_types else ''}grade"
    )
    delivery: Dict[str, Any] = {
        "workflow": {
            "steps": [
                {
                    "action": {
                        "value": "alert_teammate",
                        "recipientType": {
                            "value": "self",
                        },
                    },
                },
            ],
            "name": name,
            "filters": {
                "changes": {
                    "value": filters_changes_value,
                    "grade": {
                        "value": "any",
                    },
                    "factor": {
                        "value": [],
                    },
                },
                "scorecards": {
                    "value": (
                        "followed" if target == "any_followed_company"
                        else "my_scorecard" if target == "my_scorecard"
                        else "in_portfolio"
                    ),
                    "portfolio_id": {
                        "value": portfolio
                    },
                },
            },
        },
    }

    if not portfolio:
        del delivery["workflow"]["filters"]["scorecards"]["portfolio_id"]

    if "overall" not in score_types:
        if "any_factor_score" in score_types:
            delivery["workflow"]["filters"]["changes"]["factor"]["value"] = [
                'network_security', 'dns_health', 'patching_cadence', 'endpoint_security',
                'ip_reputation', 'application_security', 'cubit_score', 'hacker_chatter',
                'leaked_information', 'social_engineering'
            ]
        else:
            delivery["workflow"]["filters"]["changes"]["factor"]["value"] = score_types
    else:
        del delivery["workflow"]["filters"]["changes"]["factor"]

    response = client.create_alert_subscription(
        event_type="scorecard.changed",
        delivery=delivery,
    )
    demisto.debug(f"Response received: {response}")
    alert_id = response.get("id")

    markdown = f"Alert **{alert_id}** created"

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="SecurityScorecard.Alerts.GradeChangeAlert",
        outputs=alert_id,
        raw_response=response,
        outputs_key_field="id"
    )

    return results


def alert_score_threshold_create_command(client: SecurityScorecardClient, args: Dict[str, Any]) -> CommandResults:
    """
    Create an alert based on a score threshold being met.
    This function creates an alert subscription in SecurityScorecard when a specified score threshold is met.
    The alert can be configured to trigger on changes in overall score or specific factor scores, and can be
    targeted to a specific portfolio or a general target.

    See POST /subscriptions

    Args:
        client (SecurityScorecardClient): The SecurityScorecard client instance used to interact with the API.
        args (Dict[str, Any]): A dictionary of arguments for the command.
            - change_direction (str): The direction of the score change ('rises_above' or 'drops_below').
            - threshold (int): The score threshold value.
            - score_types (List[str]): The types of scores to monitor (e.g., 'overall', 'network_security').
            - target (str): The target for the alert (e.g., 'any_followed_company', 'my_scorecard').
            - portfolio (str): The portfolio ID to monitor.

    Returns:
        CommandResults: The results of the command, including the alert ID and raw response from the API.

    Raises:
        DemistoException: If both 'portfolio' and 'target' are provided, or if neither is provided.
    """

    change_direction = args.get("change_direction")
    threshold = arg_to_number(args.get("threshold"))
    score_types = argToList(args.get("score_types"))
    target = args.get('target')
    portfolio = args.get('portfolio')

    # Only one argument between portfolio and target should be defined
    # Return error if neither of them is defined or if both are defined
    if portfolio and target:
        raise DemistoException("Both 'portfolio' and 'target' argument have been set. Please remove one of them and try again.")
    elif not (target or portfolio):
        raise DemistoException("Either 'portfolio' or 'target' argument must be given")

    # filters_changes_value can be
    # 'score_rise_threshold', 'score_drop_threshold', 'factor_score_rise_threshold', 'factor_score_drop_threshold'
    filters_changes_value = (
        "factor_score_drop_threshold" if change_direction == "drops_below" else "factor_score_rise_threshold"
    ) if "overall" not in score_types else (
        "score_drop_threshold" if change_direction == "drops_below" else "score_rise_threshold"
    )

    name = (
        f"Alert me when {target or 'portfolio'} "
        f"{'factor(s)' if 'overall' not in score_types else 'overall'} score {change_direction} {threshold} pts"
    )

    delivery: Dict[str, Any] = {
        "workflow": {
            "steps": [
                {
                    "action": {
                        "value": "alert_teammate",
                        "recipientType": {
                            "value": "self",
                        },
                    },
                },
            ],
            "name": name,
            "filters": {
                "changes": {
                    "value": filters_changes_value,
                    "threshold": {
                        "value": f"{threshold}",
                    },
                    "factor": {
                        "value": [],
                    },
                },
                "scorecards": {
                    "value": (
                        "followed" if target == "any_followed_company"
                        else "my_scorecard" if target == "my_scorecard"
                        else "in_portfolio"
                    ),
                    "portfolio_id": {
                        "value": portfolio
                    },
                },
            },
        },
    }

    if not portfolio:
        del delivery["workflow"]["filters"]["scorecards"]["portfolio_id"]

    if "overall" not in score_types:
        if "any_factor_score" in score_types:
            delivery["workflow"]["filters"]["changes"]["factor"]["value"] = [
                'network_security', 'dns_health', 'patching_cadence', 'endpoint_security',
                'ip_reputation', 'application_security', 'cubit_score', 'hacker_chatter',
                'leaked_information', 'social_engineering'
            ]
        else:
            delivery["workflow"]["filters"]["changes"]["factor"]["value"] = score_types
    else:
        del delivery["workflow"]["filters"]["changes"]["factor"]

    response = client.create_alert_subscription(
        event_type="scorecard.changed",
        delivery=delivery,
    )
    demisto.debug(f"Response received: {response}")
    alert_id = response.get("id")

    markdown = f"Alert **{alert_id}** created"

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="SecurityScorecard.Alerts.ScoreThresholdAlert",
        outputs=alert_id,
        raw_response=response,
        outputs_key_field="id"
    )

    return results


def alert_delete_command(client: SecurityScorecardClient, args: Dict[str, Any]) -> CommandResults:
    """Delete an alert

    See DELETE /subscriptions/:id
    Args:
        client (SecurityScorecardClient): SecurityScorecard client
        args (Dict[str, Any]): Dictionary of arguments specified in the command

    Returns:
        CommandResults: The results of the command.
    """

    alert_id = args.get("alert_id")
    client.delete_alert(id=alert_id)  # type: ignore

    markdown = f"Alert **{alert_id}** deleted"  # type: ignore

    results = CommandResults(
        readable_output=markdown,
        raw_response=None,
        outputs_key_field=None
    )

    return results


def alerts_list_command(client: SecurityScorecardClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve alerts triggered in the last week

    See https://securityscorecard.readme.io/reference/get_users-by-username-username-notifications-recent-1

    Args:
        client (SecurityScorecardClient): SecurityScorecard client
        args (Dict[str, Any]): Dictionary of arguments specified in the command

    Returns:
        CommandResults: The results of the command.
    """

    email = client.username
    demisto.debug(f"email: {email}")
    portfolio_id = args.get('portfolio_id')
    demisto.debug(f"Sending request to retrieve alerts with arguments {args}")
    response = client.get_alerts_last_week(email=email, portfolio_id=portfolio_id)

    entries = response.get("entries")  # type: ignore

    alerts: List[Dict[str, str]] = []

    for entry in entries:  # type: ignore
        content: Dict[str, str] = {
            "company": entry.get("company_name"),
            "domain": entry.get("domain"),
            "datetime": entry.get("created_at"),
        }

        change_data = entry.get("change_data")

        if change_data:
            try:
                for change in change_data:
                    # content["change data"] = change
                    content["alert id"] = change.get("workflow", {}).get("id", "N/A")
                    content["trigger"] = change.get("score_change", {}).get("trigger_value", "N/A")
                    content["grade"] = change.get("score_change", {}).get("grade", "N/A")
                    content["score"] = change.get("score_change", {}).get("score", "N/A")

                    # Handle additional optional fields
                    content["factors"] = change.get("score_change", {}).get("factors", "N/A")
                    content["issues"] = change.get("score_change", {}).get("issues", "N/A")
            except (json.JSONDecodeError, TypeError, KeyError) as e:
                demisto.error(f"Error processing change_data: {str(e)}")

        # Old alerts system had the possibility of multiple portfolios, new rules system allows one
        portfolios = entry.get("portfolios")

        if portfolios:
            try:
                for portfolio in portfolios:
                    content["target portfolio"] = portfolio.get("id")
            except (json.JSONDecodeError, TypeError, KeyError) as e:
                demisto.error(f"Error processing change_data: {str(e)}")

        alerts.append(content)

    markdown = tableToMarkdown(f"Latest Alerts for user {email}", alerts)

    results = CommandResults(
        outputs_prefix="SecurityScorecard.Alerts.Alert",
        outputs_key_field="id",
        readable_output=markdown,
        outputs=alerts,
        raw_response=response
    )

    return results


def company_services_get_command(client: SecurityScorecardClient, args: Dict[str, str]) -> CommandResults:
    """Retrieve the service providers of a domain

    See https://securityscorecard.readme.io/reference#get_companies-domain-services

    Args:
        ``client`` (``SecurityScorecardClient``): SecurityScorecard client
        ``args`` (``Dict[str, str]``): Domain.

    Returns:
        ``CommandResults``: The results of the command.
    """

    domain = args.get("domain")

    response = client.get_domain_services(domain=domain)  # type: ignore

    entries = response.get("entries")

    services = []

    if entries:
        for entry in entries:  # type: ignore
            categories = entry.get("categories")
            for category in categories:
                service = {}
                service["vendor_domain"] = entry.get("vendor_domain")
                service["category"] = category
                services.append(service)

        markdown = tableToMarkdown(f"Services for domain [{domain}](https://{domain})", services)

        results = CommandResults(
            outputs_prefix="SecurityScorecard.Company.Services",
            outputs=entries,
            readable_output=markdown,
            raw_response=response,
            outputs_key_field='category'
        )
    else:
        results = CommandResults(
            readable_output=f"Error returning services for domain '{domain}'",
            raw_response=response
        )

    return results


def fetch_alerts(client: SecurityScorecardClient):
    """
    Fetch incidents/alerts from SecurityScorecard API

    See https://securityscorecard.readme.io/reference#get_users-by-username-username-notifications-recent

    The API is updated on a daily basis therefore `incidentFetchInterval` is set to 1440 (minutes per day)
    The API returns all alerts received in the last week.

    Every alert has a `"created_at"` parameter to notify when the alert was triggered.
    This method will create incidents only for alerts that occurred on the day the alert was created.

    Args:
        client (SecurityScorecardClient): SecurityScorecard client

    Returns:
        None: It calls demisto.incidents() to import incidents.
    """

    # Set the query size
    max_incidents = arg_to_number(client.max_fetch)  # type: ignore

    # Set initial page
    initial_page = 1

    # Initial call will request the first page.
    results = client.fetch_alerts(page_size=max_incidents, page=initial_page)  # type: ignore

    first_fetch_alerts = results.get("entries")
    size = results.get("size")

    # The number of fetches needed to retrieve all alerts
    # is the total number of alerts divided by the max fetch size
    fetches_required = int(size / max_incidents)  # type: ignore

    demisto.debug(f"API returned {size} alerts. Fetches required to retrieve all alerts: {fetches_required}")

    # Check if the API returned any alerts
    if size > 0:  # type: ignore

        # If there are no fetches required, import the alerts pulled from the initial request
        if fetches_required == 0:
            incidents = incidents_to_import(alerts=first_fetch_alerts)  # type: ignore

            # Check if any incidents should be imported according to last run time timestamp
            if incidents:
                demisto.debug(f"{len(incidents)} Incidents will be imported")
                demisto.debug(f"Incidents: {incidents}")
                demisto.incidents(incidents)
            else:
                demisto.debug("No incidents will be imported.")
                demisto.incidents([])

        # In case we cannot import all alerts in one go,
        # we paginate.
        if fetches_required > 0:
            alerts_to_import = []

            # Add the alerts from the first fetch.
            first_fetch_incidents = incidents_to_import(alerts=first_fetch_alerts)  # type: ignore
            if first_fetch_incidents:
                alerts_to_import.extend(first_fetch_incidents)
                demisto.debug(f"Adding {len(first_fetch_incidents)} alerts from first fetch to total alerts to import")
                demisto.debug(f"Total alerts currently in list: {len(alerts_to_import)}")

            # Iterate to bring the rest of the alerts
            for fetch_iteration in range(initial_page + 1, fetches_required + 2):
                demisto.debug(f"Fetch iteration {fetch_iteration} started...")

                results = client.fetch_alerts(page_size=max_incidents, page=fetch_iteration)  # type: ignore
                alerts = results.get("entries")

                incidents = incidents_to_import(alerts=alerts)  # type: ignore

                # Check if any incidents should be imported according to last run time timestamp
                if incidents:
                    demisto.debug(f"Adding {len(incidents)} to total alerts to import")
                    alerts_to_import.extend(incidents)
                    demisto.debug(f"Total alerts currently in list: {len(alerts_to_import)}")
                else:
                    demisto.debug("No incidents will be imported in this iteration.")
                demisto.debug(f"Fetch iteration {fetch_iteration} finished")

            demisto.debug(f"Total alerts to import: {len(alerts_to_import)}")
            demisto.debug(alerts_to_import)
            demisto.incidents(alerts_to_import)
    # Return no incidents if API returned no alerts
    else:
        demisto.debug("API returned no alerts. Returning empty incident list")
        demisto.incidents([])


def alert_rules_list_command(client: SecurityScorecardClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve alert subscriptions for the user

    See https://securityscorecard.readme.io/reference/subscriptions (not available right now)

    Args:
        client (SecurityScorecardClient): SecurityScorecard client
        args (Dict[str, Any]): Dictionary of arguments specified in the command

    Returns:
        CommandResults: The results of the command.
    """

    response = client.get_subscriptions()
    demisto.debug(f"Response received: {response}")
    entries = response.get("entries")

    alert_rules: List[Dict[str, str]] = []

    if entries:
        for entry in entries:
            target = entry.get("delivery", {}).get("workflow", {}).get("filters", {}).get("scorecards", {}).get("value", "N/A")
            if target == "by_id":
                target = "single scorecard"
            elif target == "in_portfolio":
                portfolio_id = entry.get("delivery", {}).get("workflow", {}).get(
                    "filters", {}).get("scorecards", {}).get("portfolio_id", {}).get("value", "N/A")
                target = f"portfolio with id {portfolio_id}"
            elif target == "followed":
                target = "all followed scorecards"
            elif target == "my_scorecard":
                target = "my scorecard"

            content: Dict[str, str] = {
                "Alert Rule ID": entry.get("id"),
                "Target": target,
                "Name": entry.get("delivery", {}).get("workflow", {}).get("name", "N/A"),
                "Updated At": entry.get("updated_at", "N/A"),
                "Paused At": entry.get("paused_at", "N/A"),
            }

            alert_rules.append(content)

    markdown = tableToMarkdown("Alert Rules", alert_rules)

    results = CommandResults(
        outputs_prefix="SecurityScorecard.AlertRules.Rule",
        outputs_key_field="id",
        readable_output=markdown,
        outputs=alert_rules,
        raw_response=response
    )

    return results


def issue_details_get_command(
    client: SecurityScorecardClient,
    args: Dict[str, Any]
) -> CommandResults:
    """Retrieve issue details for a specific issue type and domain.

    Args:
        ``client`` (``SecurityScorecardClient``): SecurityScorecard client
        ``args`` (``Dict[str, Any]``): The domain and issue type

    Returns:
        ``CommandResults``: The results of the command.
    """

    domain = args.get("domain")
    issue_type = args.get("issue_type")

    if not issue_type or not domain:
        raise ValueError("Both 'issue_type' and 'domain' arguments are required and cannot be None.")

    response = client.get_company_issue_findings(domain=domain, issue_type=issue_type)

    entries = response.get('entries', [])

    events = []
    for entry in entries:

        # some issue types have domains, IPs and/or ports, but not all of them do
        if "domain" in entry:
            domain = entry.get("domain")
        elif "target" in entry:
            domain = entry.get("target")
        else:
            domain = ""

        if "ip" in entry:
            ip = entry.get("ip")
        elif "src_ip" in entry:
            ip = entry.get("src_ip")
        elif "ip_address" in entry:
            ip = entry.get("ip_address")
        elif "connection_attributes" in entry:
            ip = entry.get("connection_attributes").get("dst_ip")
        else:
            ip = ""

        if "protocol" in entry:
            protocol = entry.get("protocol")
        elif "scheme" in entry:
            protocol = entry.get("scheme")
        elif "connection_attributes" in entry:
            protocol = entry.get("connection_attributes").get("protocol")
        else:
            protocol = ""

        if "port" in entry:
            port = entry.get("port")
        elif "connection_attributes" in entry:
            port = entry.get("connection_attributes").get("dst_port")
        else:
            port = ""

        event = {
            "parent_domain": entry.get("parent_domain"),
            "count": entry.get("count"),
            "status": entry.get("group_status"),
            "first_seen_time": entry.get("first_seen_time"),
            "last_seen_time": entry.get("last_seen_time"),
            # the following details may or may not be populated
            "port": port,
            "domain_name": domain,
            "ip_address": ip,
            "protocol": protocol,
            "observations": entry.get("observations"),
            "issue_type": issue_type
        }

        events.append(event)

    if not events:
        return CommandResults(
            readable_output=f"No findings were found for domain {domain} and issue type {issue_type}.",
            outputs_prefix="SecurityScorecard.IssueDetails",
            outputs_key_field="issue_id",
            outputs=[]
        )

    markdown = tableToMarkdown(
        f"Domain {domain} Findings for {issue_type}",
        events,
        headers=['parent_domain', 'issue_type', 'count', 'status', 'first_seen_time',
                 'last_seen_time', 'port', 'domain_name', 'ip_address', 'protocol', 'observations']
    )

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="SecurityScorecard.IssueDetails",
        outputs=entries,
        raw_response=response,
        outputs_key_field='issue_id'
    )

    return results


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    Args:
        None

    Returns:
        None
    """

    params = demisto.params()

    # Credentials
    api_key = params.get('username').get("password")
    username = params.get('username').get("identifier")

    # SecurityScorecard API URL
    base_url = params.get('base_url', "https://api.securityscorecard.io/")

    # Default configuration
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    # Fetch configuration
    max_fetch = params.get("max_fetch")
    incident_fetch_interval = params.get("incidentFetchInterval")

    args: Dict[str, str] = demisto.args()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        headers: Dict = {"Authorization": f"Token {api_key}", "X-SSC-Application-Name": "Cortex XSOAR", "X-SSC-Application-Version": "1.0.8"}  # noqa: E501

        client = SecurityScorecardClient(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            api_key=api_key,
            username=username,
            max_fetch=max_fetch
        )

        if demisto.command() == 'test-module':
            return_results(test_module(client=client, incident_fetch_interval=incident_fetch_interval))
        elif demisto.command() == "fetch-incidents":
            fetch_alerts(client=client)
        elif demisto.command() == 'securityscorecard-portfolios-list':
            return_results(portfolios_list_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-portfolio-list-companies':
            return_results(portfolio_list_companies_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-company-score-get':
            return_results(company_score_get_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-company-factor-score-get':
            return_results(company_factor_score_get_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-company-history-score-get':
            return_results(company_history_score_get_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-company-events-get':
            return_results(company_events_get_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-company-findings-get':
            return_results(company_event_findings_get_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-company-history-factor-score-get':
            return_results(company_history_factor_score_get_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-alert-grade-change-create':
            return_results(alert_grade_change_create_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-alert-score-threshold-create':
            return_results(alert_score_threshold_create_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-alert-delete':
            return_results(alert_delete_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-alerts-list':
            return_results(alerts_list_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-company-services-get':
            return_results(company_services_get_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-issue-metadata':
            return_results(issue_metadata_get_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-alert-rules-list':
            return_results(alert_rules_list_command(client=client, args=args))
        elif demisto.command() == 'securityscorecard-issue-details-get':
            return_results(issue_details_get_command(client=client, args=args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


""" ENTRY POINT """

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
