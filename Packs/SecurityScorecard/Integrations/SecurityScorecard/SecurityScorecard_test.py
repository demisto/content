from CommonServerPython import *
from SecurityScorecard import \
    SecurityScorecardClient, \
    SECURITYSCORECARD_DATE_FORMAT, \
    incidents_to_import, \
    get_last_run, \
    portfolios_list_command, \
    portfolio_list_companies_command, \
    company_score_get_command, \
    company_factor_score_get_command, \
    company_history_score_get_command, \
    company_history_factor_score_get_command, \
    alert_grade_change_create_command, \
    alert_score_threshold_create_command, \
    company_services_get_command

import json
import io
import datetime  # type: ignore
import pytest


""" TEST CONSTANTS """


USERNAME = "user@domain.com"
PORTFOLIO_ID = "1"
PORTFOLIO_ID_NE = "2"
DOMAIN = "domain1.com"
DOMAIN_NE = "domain2.com"


""" Load test data """


def load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.load(f)


test_data = load_json("./test_data/data.json")


""" Helper Functions Unit Tests"""

FROZEN_DATE = "2021-09-23T00:00:00"
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'


@pytest.mark.freeze_time(FROZEN_DATE)
@pytest.mark.parametrize(
    'last_run, first_fetch',
    [(FROZEN_DATE, None), (None, "3 days"), (None, "7 days"), (FROZEN_DATE, "7 days")]
)
def test_get_last_run(last_run, first_fetch):

    """
    Given:
        - The last run time of the fetch mechanism
        - The first fetch interval

    When:
        - Case A: Last run date is defined and first fetch is undefined.
        - Case B: Last run date is undefined and first fetch is defined to 3 days.
        - Case C: Last run date is undefined and first fetch is defined to 7 days.
        - Case D: Last run date is defined and first fetch is defined to 7 days.

    Then:
        - Case A: Last run date Unix timestamp will be returned.
        - Case B: Last run date will be set to to now and Unix timestamp will be set to most recent alert.
        - Case C: Last run date will be set to to now and Unix timestamp will be set to most recent alert.
        - Case D: Last run date Unix timestamp will be returned.
    """

    if last_run:
        last_run_timestamp = datetime.datetime.strptime(last_run, DATE_FORMAT).timestamp()

        assert last_run_timestamp == get_last_run(last_run=last_run_timestamp, first_fetch=None)
    else:
        assert int(arg_to_datetime(arg=first_fetch, arg_name="first_fetch", required=False).timestamp()) == \
            get_last_run(last_run=None, first_fetch=first_fetch)


alerts_mock = test_data.get("alerts")
incidents_to_import_test_inputs = [
    ([], None),
    ([], 1),
    (alerts_mock, 0),
    (alerts_mock, 1),
    (alerts_mock, 2),
    (alerts_mock, 3),
    (alerts_mock, 4),
]


@pytest.mark.freeze_time('2021-07-27')
@pytest.mark.parametrize('alerts, days_ago', incidents_to_import_test_inputs)
def test_incidents_to_import(alerts: list, days_ago: int):

    """
    Given:
        - List of alerts
        - Days ago

    When:
        - Case A: No alerts supplied, no days ago specified.
        - Case B: No alerts supplied, 1 day ago.
        - Case C: 3 alerts supplied, 0 days ago.
        - Case D: 3 alerts supplied, 1 day ago.
        - Case E: 3 alerts supplied, 2 days ago.
        - Case F: 3 alerts supplied, 3 days ago.
        - Case G: 3 alerts supplied, 4 days ago.

    Then:
        - Case A : No alerts imported.
        - Case B: No alerts imported.
        - Case C: 0 alerts imported.
        - Case D: 1 alerts imported.
        - Case E: 2 alerts imported.
        - Case F: 3 alerts imported.
        - Case G: 4 alerts imported.

    """
    days_ago_str = f"{days_ago} days"

    DAYS_AGO = 3
    freeze_date = datetime.datetime(2021, 7, 27)  # type: ignore
    date_days_ago_timestamp = (freeze_date - datetime.timedelta(days=DAYS_AGO)).timestamp()  # type: ignore

    incidents = incidents_to_import(alerts=alerts, last_run=date_days_ago_timestamp, first_fetch=days_ago_str)
    if not alerts:
        assert not incidents
    else:
        filtered_alerts = [alert for alert in alerts if datetime.datetime.strptime(  # type: ignore
            alert["created_at"], SECURITYSCORECARD_DATE_FORMAT).timestamp() > date_days_ago_timestamp
        ]

        assert len(incidents) == len(filtered_alerts)


""" Client Unit Tests """


MOCK_URL = "mock://securityscorecard-mock-url"

client = SecurityScorecardClient(
    base_url=MOCK_URL,
    verify=False,
    proxy=False,
    headers={},
    username=USERNAME,
    api_key="API_KEY",
    max_fetch=100
)


@pytest.mark.parametrize("args", [({}), ({"limit": "1"}), ({"limit": "60"})])
def test_portfolios_list(mocker, args):

    """
    Given:
        - A limit
        - 3 alerts total
    When:
        - Case A: limit undefined
        - Case B: limit defined as 1 (less than the total)
        - Case C: limit defined as 60

    Then:
        - Case A: All portfolios returned
        - Case B: 1 portfolio returned
        - Case C: All portfolios returned
    """

    portfolios_mock = test_data.get("portfolios")
    portfolio_entries = portfolios_mock.get("entries")

    mocker.patch.object(client, "get_portfolios", return_value=portfolios_mock)

    portfolios_cmd_res: CommandResults = portfolios_list_command(client=client, args=args)
    portfolios_returned = portfolios_cmd_res.outputs

    if not args:
        assert portfolio_entries == portfolios_returned


companies_list_test_inputs = [
    (PORTFOLIO_ID),
    ("1"),
    ("x")
]


@pytest.mark.parametrize("portfolio_id", companies_list_test_inputs)
def test_portfolio_list_companies(mocker, portfolio_id):

    """
    Given:
        - A portfolio ID

    When:
        - Portfolio exists

    Then:
        - 10 companies retrieved
    """

    companies_mock = test_data.get("companies")
    mocker.patch.object(client, "get_companies_in_portfolio", return_value=companies_mock)

    companies_cmd_res: CommandResults = portfolio_list_companies_command(
        client=client,
        portfolio_id=portfolio_id,
        grade=None,
        industry_arg=None,
        vulnerability=None,
        issue_type=None,
        had_breach_within_last_days=None
    )

    companies = companies_cmd_res.outputs

    assert len(companies) == companies_mock.get("total")


def test_portfolio_list_companies_portfolio_not_found(mocker):

    """
    Given:
        - A portfolio ID

    When:
        - Portfolio ID doesn't exist

    Then:
        - Throw 404, 'portfolio not found'
    """

    portfolio_not_found = test_data.get("portfolio_not_exist")
    mocker.patch.object(client, "get_companies_in_portfolio", return_value=portfolio_not_found)

    with pytest.raises(Exception):
        portfolio_list_companies_command(
            client=client,
            portfolio_id=PORTFOLIO_ID_NE,
            grade=None,
            industry_arg=None,
            vulnerability=None,
            issue_type=None,
            had_breach_within_last_days=None
        )


company_score_test_input = [
    (DOMAIN),
    ("google.com"),
    ("GOOGLE.COM")
]


@pytest.mark.parametrize("domain", company_score_test_input)
def test_get_company_score(mocker, domain):

    """
    Given:
        - A domain

    When:
        - Case A: domain is domain1.com
        - Case B: domain is lowercase
        - Case C: domain is uppercase

    Then:
        - Case A: score returned for domain
        - Case B: score returned for domain
        - Case C: score returned for domain
    """

    score_mock = test_data.get("score")
    mocker.patch.object(client, "get_company_score", return_value=score_mock)

    response_cmd_res: CommandResults = company_score_get_command(client=client, domain=domain)

    score = response_cmd_res.outputs

    assert score == score_mock


def test_get_company_score_not_found(mocker):
    """
    Given:
        - A company domain

    When:
        - Company domain doesn't exist

    Then:
        - company not found: nonexistentdomain.com (404)
    """

    company_not_found = test_data.get("company_not_found")
    mocker.patch.object(client, "get_company_score", return_value=company_not_found)

    cmd_res: CommandResults = company_score_get_command(client=client, domain=DOMAIN_NE)

    status = cmd_res.outputs.get("error").get("statusCode")
    message = cmd_res.outputs.get("error").get("message")

    assert status == 404
    assert message == f"company not found: {DOMAIN_NE}"


factor_score_test_inputs = [
    (DOMAIN, None),
    (DOMAIN, "high"),
    (DOMAIN, "high,low")
]


@pytest.mark.parametrize("domain, severity", factor_score_test_inputs)
def test_get_company_factor_score(mocker, domain, severity):

    """
    Given:
        - A domain
        - A severity filter
    When:
        - Case A: Domain is valid, severity unspecified
        - Case B: Domain is valid, severity is high
        - Case C: Domain is valid, severity is low
    Then:
        - Case A: Results in all severity factor scores for domain
        - Case B: Results only in high severity factor scores for domain
        - Case C: Results in high and low severity factor scores for domain
    """

    factor_score_mock = test_data.get("factor_score")
    mocker.patch.object(client, "get_company_factor_score", return_value=factor_score_mock)

    response: CommandResults = company_factor_score_get_command(
        client=client,
        domain=domain,
        severity=severity
    )

    assert len(response.outputs) == factor_score_mock.get("total")
    assert response.outputs == factor_score_mock.get("entries")


company_historical_scores_test_inputs = [
    (DOMAIN, None, None, None),
    (DOMAIN, "2021-07-01", "2021-07-31", "daily"),
    (DOMAIN, "2021-07-01", "2021-07-31", "weekly"),
]


@pytest.mark.parametrize("domain,_from,to,timing", company_historical_scores_test_inputs)
def test_get_company_historical_scores(mocker, domain, _from, to, timing):

    """
    Given:
        - A domain
        - Date range
        - Timing
    When:
        - Case A: Domain is valid, no range, no resolution
        - Case B: Domain is valid, from 2021-07-01 to 2021-07-31, daily
        - Case C: Domain is valid, from 2021-07-01 to 2021-07-31, weekly
    Then:
        - Case A: Score received for 1 year ago on weekly bases
        - Case B: Score received for 2021-07-01 to 2021-07-31 on daily basis
        - Case B: Score received for 2021-07-01 to 2021-07-31 on weekly
    """

    historical_score_mock = test_data.get("historical_score")
    mocker.patch.object(client, "get_company_historical_scores", return_value=historical_score_mock)

    response: CommandResults = company_history_score_get_command(
        client=client,
        domain=domain,
        _from=_from,
        to=to,
        timing=timing
    )

    cmd_output = response.outputs

    assert cmd_output == historical_score_mock.get("entries")


company_historical_factor_scores_test_inputs = [
    (DOMAIN, None, None, None),
    (DOMAIN, "2021-07-01", "2021-07-31", "daily"),
    (DOMAIN, "2021-07-01", "2021-07-31", "weekly"),
]


@pytest.mark.parametrize("domain,_from,to,timing", company_historical_factor_scores_test_inputs)
def test_get_company_historical_factor_scores(mocker, domain, _from, to, timing):

    """
    Given:
        - A domain
        - Date range
        - Timing
    When:
        - Case A: Domain is valid, no range, no resolution
        - Case B: Domain is valid, from 2021-07-01 to 2021-07-31, daily
        - Case C: Domain is valid, from 2021-07-01 to 2021-07-31, weekly
    Then:
        - Case A: Score received for 1 year ago on weekly bases
        - Case B: Score received for 2021-07-01 to 2021-07-31 on daily basis
        - Case C: Score received for 2021-07-01 to 2021-07-31 on weekly basis
    """

    historical_factor_score_mock = test_data.get("historical_factor_score")
    mocker.patch.object(client, "get_company_historical_factor_scores", return_value=historical_factor_score_mock)

    cmd_res: CommandResults = company_history_factor_score_get_command(
        client=client,
        domain=domain,
        _from=_from,
        to=to,
        timing=timing
    )

    factor_scores = cmd_res.outputs
    assert factor_scores == historical_factor_score_mock.get("entries")


grade_alert_test_input = [
    (USERNAME, "rises", "overall", None, PORTFOLIO_ID),
    (USERNAME, "drops", "overall,cubit_score", None, PORTFOLIO_ID),
    (USERNAME, "rises", "application_security", "my_scorecard", None),
    (USERNAME, "rises", "application_security", "my_scorecard", "1"),
    (USERNAME, "rises", "application_security", None, None)
]


@pytest.mark.parametrize("username, change_direction, score_types, target, portfolios", grade_alert_test_input)
def test_create_grade_change_alert(mocker, username, change_direction, score_types, target, portfolios):
    """
    Given:
        - A username
        - Direction change
        - Score type(s)
        - Target or Portfolio(s)
    When:
        - Case A: Username is valid, rising grade, overall score type, to portfolio
        - Case B: Username is valid, dropping grade, overall and cubit score score types, to portfolio
        - Case C: Username is valid, rising grade, application security score type to my scorecard
        - Case D: Both portfolio and target are specified
        - Case E: Neither portfolio and target are specified
    Then:
        - Case A: Alert created
        - Case B: Alert created
        - Case C: Alert created
        - Case D: DemistoException thrown
        - Case E: DemistoException thrown
    """

    create_grade_alert_mock = test_data.get("create_grade_alert")
    mocker.patch.object(client, "create_grade_change_alert", return_value=create_grade_alert_mock)

    if target and portfolios:
        with pytest.raises(DemistoException) as exc:
            alert_grade_change_create_command(
                client=client,
                username=username,
                change_direction=change_direction,
                score_types=score_types,
                target=target,
                portfolios=portfolios
            )

        assert "Both 'portfolio' and 'target' argument have been set" in str(exc.value)
    elif not target and not portfolios:
        with pytest.raises(DemistoException) as exc:
            alert_grade_change_create_command(
                client=client,
                username=username,
                change_direction=change_direction,
                score_types=score_types,
                target=target,
                portfolios=portfolios
            )

        assert "Either 'portfolio' or 'target' argument must be given" in str(exc.value)
    else:

        cmd_res: CommandResults = alert_grade_change_create_command(
            client=client,
            username=username,
            change_direction=change_direction,
            score_types=score_types,
            target=target,
            portfolios=portfolios
        )

        assert cmd_res.outputs == create_grade_alert_mock.get("id")


score_alert_test_input = [
    (USERNAME, "rises_above", "overall", 90, None, PORTFOLIO_ID),
    (USERNAME, "drops_below", "overall,cubit_score", 90, None, PORTFOLIO_ID),
    (USERNAME, "rises_above", "application_security", 90, "my_scorecard", None),
    (USERNAME, "rises_above", "application_security", 90, "my_scorecard", "1"),
    (USERNAME, "rises_above", "application_security", 90, None, None),
    (USERNAME, "rises_above", "overall", "ninety", None, "1")
]


@pytest.mark.parametrize("username, change_direction, score_types, threshold, target, portfolios", score_alert_test_input)
def test_create_score_change_alert(mocker, username, change_direction, score_types, threshold, target, portfolios):
    """
    Given:
        - A username
        - Direction change
        - Score type(s)
        - A threshold
        - Target or Portfolio(s)
    When:
        - Case A: Username is valid, rising grade, overall score type, to portfolio
        - Case B: Username is valid, dropping grade, overall and cubit score score types, to portfolio
        - Case C: Username is valid, rising grade, application security score type to my scorecard
        - Case D: Both portfolio and target are specified
        - Case E: Neither portfolio and target are specified
        - Case E: Threshold supplied is not a number
    Then:
        - Case A: Alert created
        - Case B: Alert created
        - Case C: Alert created
        - Case D: DemistoException thrown
        - Case E: DemistoException thrown
        - Case F: ValueError thrown
    """

    create_score_alert_mock = test_data.get("create_score_alert")
    mocker.patch.object(client, "create_score_threshold_alert", return_value=create_score_alert_mock)

    if not isinstance(threshold, int):
        with pytest.raises(ValueError) as exc:
            alert_score_threshold_create_command(
                client=client,
                username=username,
                change_direction=change_direction,
                score_types=score_types,
                threshold=int(threshold),
                target=target,
                portfolios=portfolios
            )

        assert f"invalid literal for int() with base 10: '{threshold}" in str(exc.value)
    elif target and portfolios:
        with pytest.raises(DemistoException) as exc:
            alert_score_threshold_create_command(
                client=client,
                username=username,
                change_direction=change_direction,
                score_types=score_types,
                threshold=threshold,
                target=target,
                portfolios=portfolios
            )

        assert "Both 'portfolio' and 'target' argument have been set" in str(exc.value)
    elif not target and not portfolios:
        with pytest.raises(DemistoException) as exc:
            alert_score_threshold_create_command(
                client=client,
                username=username,
                change_direction=change_direction,
                score_types=score_types,
                threshold=threshold,
                target=target,
                portfolios=portfolios
            )

        assert "Either 'portfolio' or 'target' argument must be given" in str(exc.value)
    else:

        cmd_res: CommandResults = alert_score_threshold_create_command(
            client=client,
            username=username,
            change_direction=change_direction,
            score_types=score_types,
            threshold=threshold,
            target=target,
            portfolios=portfolios
        )

        assert cmd_res.outputs == create_score_alert_mock.get("id")


services_test_input = (
    (DOMAIN),
    (DOMAIN_NE)
)


@pytest.mark.parametrize("domain", services_test_input)
def test_get_domain_services(mocker, domain):

    """
    Given:
        - A domain
    When:
        - Domain is valid
    Then:
        - List of services is returned
    """

    services_mock = test_data.get("services")
    mocker.patch.object(client, "get_domain_services", return_value=services_mock)

    cmd_res: CommandResults = company_services_get_command(client=client, domain=domain)
    services = cmd_res.outputs

    assert services == services_mock.get("entries")
