import demistomock as demisto
from CommonServerPython import *

import requests
import traceback
from typing import Dict, Any
from datetime import datetime

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


""" CONSTANTS """

SECURITYSCORECARD_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

""" CLIENT CLASS """


class SecurityScorecardClient(BaseClient):
    """Client class that interacts with the SecurityScorecard API

    Attributes:
        username (str): SecurityScorecard username/email.
        api_key (str): SecurityScorecard API token.
        max_fetch (int): Maximum alerts to fetch.
    """

    def __init__(self, base_url, verify, proxy, headers, username, api_key, max_fetch):
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

    def create_grade_change_alert(
        self,
        email: str,
        change_direction: str,
        score_types: List[str],
        target: List[str]
    ) -> Dict[str, Any]:

        payload: Dict[str, Any] = assign_params(
            change_direction=change_direction,
            score_types=score_types,
            target=target
        )
        return self.http_request_wrapper(
            method='POST',
            url_suffix=f"users/by-username/{email}/alerts/grade",
            json_data=payload
        )

    def create_score_threshold_alert(
        self,
        email: str,
        change_direction: str,
        threshold: int,
        score_types: List[str],
        target: List[str]
    ) -> Dict[str, Any]:

        payload: Dict[str, Any] = assign_params(
            change_direction=change_direction,
            threshold=arg_to_number(arg=threshold, arg_name='threshold', required=True),
            score_types=score_types,
            target=target
        )

        return self.http_request_wrapper(
            method='POST',
            url_suffix=f"users/by-username/{email}/alerts/score",
            json_data=payload
        )

    def delete_alert(self, email: str, alert_id: str, alert_type: str) -> None:

        return self.http_request_wrapper(
            method="DELETE",
            url_suffix=f"users/by-username/{email}/alerts/{alert_type}/{alert_id}",
            return_empty_response=True
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

    def fetch_alerts(self, page_size: int):

        query_params: Dict[str, Any] = assign_params(
            username=self.username,
            page_size=page_size,
            sort="sort",
            order="order"
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
        """Wrapper for the http_request function

        Args:
            self (SecurityScorecardClient).
            method (str): The HTTP method.
            url_suffix (Optional[str]): The URL suffix, appended to the base URL. Defaults to None.
            params (Optional[dict]): The query parameters sent in the HTTP request. Defaults to None.
            json_data (Optional[dict]): The payload to be sent in the HTTP request in JSON format. Defaults to None.

        Return:
            None
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
            error_message: str = f'{error_response_json.get("message")} ({error_response_json.get("statusCode")})'
            demisto.error(error_message)
            raise DemistoException(error_message)
        except ValueError:
            raise DemistoException(f'Error parsing response as JSON. Response: {response.status_code} {str(response.content)}')


""" HELPER FUNCTIONS """


def incidents_to_import(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

    """
    Helper function to filter events that need to be imported.
    It filters the events based on the `created_at` timestamp.
    Function will only be called if the SecurityScorecard API returns more than one alert.

    Args:
        ``alerts``(``List[Dict[str, Any]]``): A list of alerts to sort through.

    Returns:
        ``List[Dict[str, Any]]``: Events to import
    """

    # Check for existence of last run
    # When integration runs for the first time, it will not exist
    # Set 3 days by default if the first fetch parameter is not set
    if demisto.getLastRun().get("last_run"):
        last_run = int(demisto.getLastRun().get("last_run"))
    else:
        days_ago_arg = demisto.params().get("first_fetch")

        if not days_ago_arg:
            days_ago_str = "3 days"
        else:
            days_ago_str = days_ago_arg

        fetch_days_ago = arg_to_datetime(days_ago_str, arg_name="first_fetch", required=False)

        # to prevent mypy incompatible assignment
        assert fetch_days_ago is not None
        valid_fetch_days_ago: datetime = fetch_days_ago

        demisto.debug(f"getLastRun is None in integration context, using parameter 'first_fetch' value '{days_ago_arg}'")
        demisto.debug(f"{days_ago_str} => {valid_fetch_days_ago}")

        last_run = int(valid_fetch_days_ago.timestamp())

    demisto.debug(f"Last run timestamp: {last_run}")

    incidents_to_import: List[Dict[str, Any]] = []

    alerts_returned = len(alerts)
    demisto.debug(f"Number of alerts found: {alerts_returned}")
    # Check if there are more than 0 alerts
    if alerts_returned > 0:

        # The alerts are sorted by descending date so first alert is the most recent
        most_recent_alert = alerts[0]

        most_recent_alert_created_date = most_recent_alert.get("created_at")

        most_recent_alert_timestamp = \
            int(datetime.strptime(most_recent_alert_created_date, SECURITYSCORECARD_DATE_FORMAT).timestamp())  # type: ignore
        demisto.debug(f"Setting last runtime as alert most recent timestamp: {most_recent_alert_timestamp}")
        demisto.setLastRun({
            'last_run': most_recent_alert_timestamp
        })

        for alert in alerts:

            alert_created_at = alert.get("created_at")
            alert_timestamp = int(datetime.strptime(alert_created_at, SECURITYSCORECARD_DATE_FORMAT).timestamp())  # type: ignore

            alert_id = alert.get("id")

            debug_msg = f"""
            last_run: {last_run}, alert_timestamp: {alert_timestamp},
            should import alert '{alert_id}'? (last_run < alert_timestamp): {(last_run < alert_timestamp)}
            """
            demisto.debug(debug_msg)

            if alert_timestamp > last_run:
                incident = {}
                incident["name"] = f"SecurityScorecard '{alert.get('change_type')}' Incident"
                incident["occurred"] = \
                    datetime.strptime(alert_created_at, SECURITYSCORECARD_DATE_FORMAT).strftime(DATE_FORMAT)  # type: ignore
                incident["rawJSON"] = json.dumps(alert)
                incidents_to_import.append(incident)
    # If there are no alerts then we can't use the most recent alert timestamp
    # So we'll use now as the last run timestamp
    else:
        now = int(datetime.utcnow().timestamp())
        demisto.debug(f"No alerts retrieved, setting last_run to now ({now})")
        demisto.setLastRun({
            'last_run': now
        })

    return incidents_to_import


""" COMMAND FUNCTIONS """


def test_module(client: SecurityScorecardClient) -> str:
    """Tests API connectivity and authentication

    Runs the fetch-alerts mechanism to validate all integration parameters

    Args:
        client (SecurityScorecardClient): SecurityScorecard client

    Returns:
        str: 'ok' if test passed, anything else will fail the test.
    """
    demisto.debug("Initialized test module...")

    try:
        client.fetch_alerts(page_size=1)
        demisto.debug("Test module successful")
        return('ok')
    except DemistoException as e:
        if 'Unauthorized' in str(e):
            return('Authorization Error: make sure API Key is correctly set')
        else:
            raise e

# region Methods
# ---------------


def portfolios_list_command(client: SecurityScorecardClient, args: Dict[str, Any]) -> CommandResults:
    """List all Portfolios you have access to.

    See https://securityscorecard.readme.io/reference#get_portfolios

    Args:
        client (SecurityScorecardClient): SecurityScorecard client
        args (Dict[str, Any]): Dictionary of arguments specified in the command

    Returns:
        CommandResults: The results of the command.
    """

    limit = arg_to_number(
        arg=args.get("limit"),
        arg_name="limit",
        required=False
    )

    # Enforce default if limit is not specified
    if not limit:
        limit = 50

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


def portfolio_list_companies_command(client: SecurityScorecardClient, args: Dict[str, str]) -> CommandResults:
    """Retrieve all companies in portfolio.

    https://securityscorecard.readme.io/reference#get_portfolios-portfolio-id-companies

    Args:
        client (SecurityScorecardClient): SecurityScorecard client
        args (Dict[str, Any]): Dictionary of arguments specified in the command

    Returns:
        CommandResults: The results of the command.
    """

    portfolio_id = args.get('portfolio_id')
    grade = args.get('grade')

    # We need to capitalize the industry to conform to API
    industry_arg = args.get('industry')
    industry = str.upper(industry_arg) if args.get("industry") else None  # type: ignore

    vulnerability = args.get('vulnerability')
    issue_type = args.get('issue_type')

    had_breach_within_last_days = arg_to_number(
        arg=args.get('had_breach_within_last_days'),
        arg_name='had_breach_within_last_days',
        required=False
    )

    response = client.get_companies_in_portfolio(
        portfolio=portfolio_id,  # type: ignore
        grade=grade,
        industry=industry,
        vulnerability=vulnerability,
        issue_type=issue_type,
        had_breach_within_last_days=had_breach_within_last_days
    )

    # Check if the portfolio has more than 1 company
    total_portfolios = int(response.get('total'))  # type: ignore
    if not total_portfolios > 0:
        return CommandResults(
            readable_output=f"No companies found in Portfolio {portfolio_id}. Please add a company to it and retry.",
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


def company_score_get_command(client: SecurityScorecardClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve company overall score.

    See https://securityscorecard.readme.io/reference#get_companies-scorecard-identifier-factors

    Args:
        client (SecurityScorecardClient): SecurityScorecard client
        args (Dict[str, Any]): Dictionary of arguments specified in the command

    Returns:
        CommandResults: The results of the command.
    """

    domain = args.get('domain')

    score = client.get_company_score(domain=domain)  # type: ignore
    score["domain"] = domain

    industry = score.get("industry").title().replace("_", " ")  # type: ignore
    score["industry"] = industry

    markdown = tableToMarkdown(
        f"Domain {domain} Scorecard",
        score,
        headers=['name', 'domain', 'grade', 'score', 'industry', 'last30day_score_change', 'size']
    )

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="SecurityScorecard.Company.Score",
        outputs=score,
        raw_response=score,
        outputs_key_field='name'
    )

    return results


def company_factor_score_get_command(client: SecurityScorecardClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve company factor score and scores

    See https://securityscorecard.readme.io/reference#get_companies-scorecard-identifier-factors

    Args:
        client (SecurityScorecardClient): SecurityScorecard client
        args (Dict[str, Any]): Dictionary of arguments specified in the command

    Returns:
        CommandResults: The results of the command.
    """

    domain = args.get('domain')

    severity_in = args.get('severity')

    response = client.get_company_factor_score(domain, severity_in)  # type: ignore

    entries = response['entries']

    factor_scores = []
    for entry in entries:
        score = {
            "name": entry.get("name").title().replace("_", " "),
            "grade": entry.get("grade"),
            "score": entry.get("score"),
            "issues": len(entry.get("issue_summary")),
            "issue details": entry.get("issue_summary")
        }

        factor_scores.append(score)

    markdown = tableToMarkdown(
        f"Domain {domain} Scorecard",
        factor_scores,
        headers=['Name', 'Grade', 'Score', 'Issues']
    )

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="SecurityScorecard.Company.Factor",
        outputs=factor_scores,
        raw_response=response,
        outputs_key_field='name'
    )

    return results


def company_history_score_get_command(client: SecurityScorecardClient, args: Dict[str, Any]) -> CommandResults:

    """Retrieve company historical scores

    See https://securityscorecard.readme.io/reference#get_companies-scorecard-identifier-history-score

    Args:
        client (SecurityScorecardClient): SecurityScorecard client
        args (Dict[str, Any]): Dictionary of arguments specified in the command

    Returns:
        CommandResults: The results of the command.
    """

    domain = args.get('domain')

    _from = args.get('from')
    to = args.get('to')
    timing = args.get('timing')

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


def company_history_factor_score_get_command(client: SecurityScorecardClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve company historical factor scores

    See https://securityscorecard.readme.io/reference#get_companies-scorecard-identifier-history-factors-score

    Args:
        client (SecurityScorecardClient): SecurityScorecard client
        args (Dict[str, Any]): Dictionary of arguments specified in the command

    Returns:
        CommandResults: The results of the command.
    """

    domain = args.get('domain')
    _from = args.get('from')
    to = args.get('to')
    timing = args.get('timing')

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
        outputs=factor_scores,
        raw_response=response,
        outputs_key_field='date'
    )

    return results


def alert_grade_change_create_command(client: SecurityScorecardClient, args: Dict[str, Any]) -> CommandResults:
    """Create alert based on grade

    See https://securityscorecard.readme.io/reference#post_users-by-username-username-alerts-grade

    Args:
        client (SecurityScorecardClient): SecurityScorecard client
        args (Dict[str, Any]): Dictionary of arguments specified in the command

    Returns:
        CommandResults: The results of the command.
    """

    email = client.username
    change_direction = args.get('change_direction')
    score_types = argToList(args.get('score_types'))
    target_arg = args.get('target')
    portfolios = args.get('portfolios')

    # Only one argument between portfolios and target should be defined
    # Return error if neither of them is defined or if both are defined
    # Else choose the one that is defined and use it as the target
    if portfolios and target_arg:
        raise DemistoException("Both 'portfolio' and 'target' argument have been set. Please remove one of them and try again.")
    else:
        target = target_arg or portfolios
    if not target:
        raise DemistoException("Either 'portfolio' or 'target' argument must be given")

    demisto.debug(f"Attempting to create alert with body {args}")
    response = client.create_grade_change_alert(
        email=email,
        change_direction=change_direction,  # type: ignore
        score_types=score_types,
        target=argToList(target)
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
    """Create alert based threshold met

    See https://securityscorecard.readme.io/reference#post_users-by-username-username-alerts-score

    Args:
        client (SecurityScorecardClient): SecurityScorecard client
        args (Dict[str, Any]): Dictionary of arguments specified in the command

    Returns:
        CommandResults: The results of the command.
    """

    email = client.username
    change_direction = args.get('change_direction')
    threshold = arg_to_number(args.get('threshold'))
    score_types = argToList(args.get('score_types'))
    target_arg = args.get('target')
    portfolios = args.get('portfolios')

    # Only one argument between portfolios and target should be defined
    # Return error if neither of them is defined or if both are defined
    # Else choose the one that is defined and use it as the target
    if portfolios and target_arg:
        raise DemistoException("Both 'portfolio' and 'target' argument have been set. Please remove one of them and try again.")
    else:
        target = target_arg or portfolios
    if not target:
        raise DemistoException("Either 'portfolio' or 'target' argument must be given")

    demisto.debug(f"Attempting to create alert with body {args}")
    response = client.create_score_threshold_alert(
        email=email,
        change_direction=change_direction,  # type: ignore
        threshold=threshold,  # type: ignore
        score_types=score_types,
        target=argToList(target)
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

    See https://securityscorecard.readme.io/reference#delete_users-by-username-username-alerts-grade-alert

    Args:
        client (SecurityScorecardClient): SecurityScorecard client
        args (Dict[str, Any]): Dictionary of arguments specified in the command

    Returns:
        CommandResults: The results of the command.
    """

    email = client.username
    alert_id = args.get("alert_id")
    alert_type = args.get("alert_type")
    client.delete_alert(email=email, alert_id=alert_id, alert_type=alert_type)  # type: ignore

    markdown = f"{str.capitalize(alert_type)} alert **{alert_id}** deleted"  # type: ignore

    results = CommandResults(
        readable_output=markdown,
        raw_response=None,
        outputs_key_field=None
    )

    return results


def alerts_list_command(client: SecurityScorecardClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve alerts triggered in the last week

    See https://securityscorecard.readme.io/reference#get_users-by-username-username-notifications-recent

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

    entries = response.get("entries")

    # Retrieve the alert metadata (direction, score, factor, grade_letter, score_impact)
    alerts = []

    for entry in entries:  # type: ignore
        # change_data is a list that includes all alert metadata that triggered the event
        changes = entry.get("change_data")
        for change in changes:
            alert = {}
            alert["id"] = entry.get("id")
            alert["change_type"] = entry.get("change_type")
            alert["domain"] = entry.get("domain")
            alert["company"] = entry.get("company_name")
            alert["created"] = entry.get("created_at")
            alert["direction"] = change.get("direction")
            alert["score"] = change.get("score")
            alert["factor"] = change.get("factor")
            alert["grade_letter"] = change.get("grade_letter")
            alert["score_impact"] = change.get("score_impact")
            alerts.append(alert)

    markdown = tableToMarkdown(f"Latest Alerts for user {email}", alerts)

    results = CommandResults(
        outputs_prefix="SecurityScorecard.Alerts.Alert",
        outputs_key_field="id",
        readable_output=markdown,
        outputs=alerts,
        raw_response=response
    )

    return results


def company_services_get_command(client: SecurityScorecardClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve the service providers of a domain

    See https://securityscorecard.readme.io/reference#get_companies-domain-services

    Args:
        client (SecurityScorecardClient): SecurityScorecard client
        args (Dict[str, Any]): Dictionary of arguments specified in the command

    Returns:
        CommandResults: The results of the command.
    """

    domain = args.get("domain")
    response = client.get_domain_services(domain=domain)  # type: ignore

    entries = response.get("entries")

    services = []

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
        outputs=services,
        readable_output=markdown,
        raw_response=response,
        outputs_key_field='category'
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

    if not client.max_fetch:
        max_incidents = 50
    else:
        max_incidents = arg_to_number(client.max_fetch)  # type: ignore

    results = client.fetch_alerts(page_size=max_incidents)

    alerts = results.get("entries")

    demisto.debug(f"API returned {len(alerts)} alerts")

    # Check if the API returned any alerts
    if len(alerts) > 0:
        incidents = incidents_to_import(alerts=alerts)

        # Check if any incidents should be imported according to last run time timestamp
        if len(incidents) > 0:
            demisto.debug(f"{len(incidents)} Incidents will be imported")
            demisto.debug(f"Incidents: {incidents}")
            demisto.incidents(incidents)
        else:
            demisto.debug("No incidents will be imported.")
            demisto.incidents([])
    # Return no incidents if API returned no alerts
    else:
        demisto.debug("API returned no alerts. Returning empty incident list")
        demisto.incidents([])


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

    args: Dict[str, str] = demisto.args()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        headers: Dict = {"Authorization": f"Token {api_key}"}

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
            return_results(test_module(client))
        elif demisto.command() == "fetch-incidents":
            fetch_alerts(client)
        elif demisto.command() == 'securityscorecard-portfolios-list':
            return_results(portfolios_list_command(client, args))
        elif demisto.command() == 'securityscorecard-portfolio-list-companies':
            return_results(portfolio_list_companies_command(client, args))
        elif demisto.command() == 'securityscorecard-company-score-get':
            return_results(company_score_get_command(client, demisto.args()))
        elif demisto.command() == 'securityscorecard-company-factor-score-get':
            return_results(company_factor_score_get_command(client, demisto.args()))
        elif demisto.command() == 'securityscorecard-company-history-score-get':
            return_results(company_history_score_get_command(client, demisto.args()))
        elif demisto.command() == 'securityscorecard-company-history-factor-score-get':
            return_results(company_history_factor_score_get_command(client, demisto.args()))
        elif demisto.command() == 'securityscorecard-alert-grade-change-create':
            return_results(alert_grade_change_create_command(client, demisto.args()))
        elif demisto.command() == 'securityscorecard-alert-score-threshold-create':
            return_results(alert_score_threshold_create_command(client, demisto.args()))
        elif demisto.command() == 'securityscorecard-alert-delete':
            return_results(alert_delete_command(client, demisto.args()))
        elif demisto.command() == 'securityscorecard-alerts-list':
            return_results(alerts_list_command(client, demisto.args()))
        elif demisto.command() == 'securityscorecard-company-services-get':
            return_results(company_services_get_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


""" ENTRY POINT """

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
