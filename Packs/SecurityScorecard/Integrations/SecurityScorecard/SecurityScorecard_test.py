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
ALERT_ID = "1"
ALERT_ID_NE = "2"

""" Endpoints """

PORTFOLIO_ROOT_EP = "/portfolios"
PORTFOLIO_FOUND_EP = f"{PORTFOLIO_ROOT_EP}/1/companies"
PORTFOLIO_FOUND_EP = f"{PORTFOLIO_ROOT_EP}/2/companies"

COMPANIES_ROOT_EP = "/companies"
COMPANIES_SCORE_EP = f"{COMPANIES_ROOT_EP}/{DOMAIN}"
COMPANIES_FACTOR_SCORE_EP = f"{COMPANIES_ROOT_EP}/{DOMAIN}/factors"
COMPANIES_HISTORY_SCORE_EP = f"{COMPANIES_ROOT_EP}/{DOMAIN}/history/score"
COMPANIES_HISTORY_FACTOR_SCORE_EP = f"{COMPANIES_ROOT_EP}/{DOMAIN}/history/factor/score"
COMPANIES_SERVICES_EP = f"{COMPANIES_ROOT_EP}/{DOMAIN}/services"

ALERTS_ROOT_EP = f"/users/by-username/{USERNAME}/alerts"
ALERTS_TYPE_SCORE = "score"
ALERTS_TYPE_GRADE = "grade"
ALERTS_GRADE_EP = f"{ALERTS_ROOT_EP}/grade"
ALERTS_SCORE_EP = f"{ALERTS_ROOT_EP}/score"
ALERTS_DELETE_SCORE_EP = f"{ALERTS_ROOT_EP}/{ALERTS_TYPE_SCORE}/{ALERT_ID}"
ALERTS_DELETE_GRADE_EP = f"{ALERTS_ROOT_EP}/{ALERTS_TYPE_GRADE}/{ALERT_ID}"
NOTIFICATIONS_ROOT_EP = f"/users/by-username/{USERNAME}/notifications/recent"


""" Helper Functions Test Data"""


def load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


test_data = load_json("./test_data/data.json")

# test_get_last_run
FREEZE_DATE = '2021-07-27'
DAYS_AGO = 3
DAYS_BEFORE_FREEZE_TIMESTAMP = int(datetime.datetime(2021, 7, 24).timestamp())  # type: ignore
freeze_date = datetime.datetime(2021, 7, 27)  # type: ignore
date_days_ago_timestamp = (freeze_date - datetime.timedelta(days=DAYS_AGO)).timestamp()  # type: ignore

# test_get_last_run_test
get_last_run_test_inputs = [
    (date_days_ago_timestamp, f"{DAYS_AGO} days"),
    (date_days_ago_timestamp, None),
    (None, f"{DAYS_AGO} days")
]

# test_incidents_to_import
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

# test_portfolios_list
portfolios_mock = test_data.get("portfolios")
portfolios_list_test_inputs = [
    (None),
    (1),
    (2)
]

# test_portfolio_list_companies
companies_mock = test_data.get("companies")
companies_list_test_inputs = [
    (PORTFOLIO_ID),
    ("1"),
    ("x")
]

# test_portfolio_list_companies_not_exist
portfolio_not_found = test_data.get("portfolio_not_exist")
companies_list_not_exist_test_inputs = [
    (PORTFOLIO_ID_NE)
]

# test_get_company_score
score_mock = test_data.get("score")
company_score_test_input = [
    (DOMAIN),
    ("google.com"),
    ("GOOGLE.COM")
]
company_not_found = test_data.get("company_not_found")

# test_get_company_factor_score
factor_score_mock = test_data.get("factor_score")
factor_score_test_inputs = [
    (DOMAIN, None),
    (DOMAIN, "high"),
    (DOMAIN, "high,low")
]

# test_get_company_historical_scores
historical_score_mock = test_data.get("historical_score")
company_historical_scores_test_inputs = [
    (DOMAIN, None, None, None),
    (DOMAIN, "2021-07-01", "2021-07-31", "daily"),
    (DOMAIN, "2021-07-01", "2021-07-31", "weekly"),
]

#  test_get_company_historical_factor_scores
historical_factor_score_mock = test_data.get("historical_factor_score")
company_historical_factor_scores_test_inputs = [
    (DOMAIN, None, None, None),
    (DOMAIN, "2021-07-01", "2021-07-31", "daily"),
    (DOMAIN, "2021-07-01", "2021-07-31", "weekly"),
]


# test_create_grade_change_alert
create_grade_alert_mock = test_data.get("create_grade_alert")
grade_alert_test_input = [
    (USERNAME, "rises", "overall", None, PORTFOLIO_ID),
    (USERNAME, "drops", "overall,cubit_score", None, PORTFOLIO_ID),
    (USERNAME, "rises", "application_security", "my_scorecard", None),
    (USERNAME, "rises", "application_security", "my_scorecard", "1"),
    (USERNAME, "rises", "application_security", None, None)
]

# test_create_score_change_alert
create_score_alert_mock = test_data.get("create_score_alert")
score_alert_test_input = [
    (USERNAME, "rises_above", "overall", 90, None, PORTFOLIO_ID),
    (USERNAME, "drops_below", "overall,cubit_score", 90, None, PORTFOLIO_ID),
    (USERNAME, "rises_above", "application_security", 90, "my_scorecard", None),
    (USERNAME, "rises_above", "application_security", 90, "my_scorecard", "1"),
    (USERNAME, "rises_above", "application_security", 90, None, None),
    (USERNAME, "rises_above", "overall", "ninety", None, "1")
]

# test_get_domain_services
services_mock = test_data.get("services")
services_test_input = (
    (DOMAIN),
    (DOMAIN_NE)
)

""" Helper Functions Unit Tests"""

FROZEN_DATE = "2021-09-23T00:00:00"
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'


@pytest.mark.freeze_time(FROZEN_DATE)
@pytest.mark.parametrize(
    'last_run, first_fetch',
    [(FROZEN_DATE, None), (None, "3 days"), (None, "7 days"), (FROZEN_DATE, "7 days")]
)
def test_get_last_run(last_run, first_fetch):

    assert datetime.date.today() == datetime.date(2021, 9, 23)

    if last_run:
        last_run_timestamp = datetime.datetime.strptime(last_run, DATE_FORMAT).timestamp()

        assert last_run_timestamp == get_last_run(last_run=last_run_timestamp, first_fetch=None)
    else:
        assert int(arg_to_datetime(arg=first_fetch, arg_name="first_fetch", required=False).timestamp()) == \
            get_last_run(last_run=None, first_fetch=first_fetch)


@pytest.mark.freeze_time(FREEZE_DATE)
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

    incidents = incidents_to_import(alerts=alerts, last_run=date_days_ago_timestamp, first_fetch=days_ago_str)
    if not alerts:
        assert len(alerts) == len(incidents)
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


@pytest.mark.parametrize("limit", [(1), (2)])
def test_portfolios_list(mocker, limit):

    """
    Given:
        - A limit

    When:
        - Case A: limit undefined
        - Case B: limit defined as 1
        - Case C: limit defined as 2

    Then:
        - Case A: All (3) portfolios are returned
        - Case B: 1 portfolio returned
        - Case C: 2 portfolios returned
    """

    mocker.patch.object(client, "get_portfolios", return_value=portfolios_mock)

    portfolios_cmd_res: CommandResults = portfolios_list_command(client=client, limit=limit)
    portfolios = portfolios_cmd_res.outputs

    assert len(portfolios) == limit


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

    mocker.patch.object(client, "get_company_score", return_value=company_not_found)

    cmd_res: CommandResults = company_score_get_command(client=client, domain=DOMAIN_NE)

    status = cmd_res.outputs.get("error").get("statusCode")
    message = cmd_res.outputs.get("error").get("message")

    assert status == 404
    assert message == f"company not found: {DOMAIN_NE}"


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

    mocker.patch.object(client, "get_company_factor_score", return_value=factor_score_mock)

    response: CommandResults = company_factor_score_get_command(
        client=client,
        domain=domain,
        severity=severity
    )

    assert len(response.outputs) == factor_score_mock.get("total")
    assert response.outputs == factor_score_mock.get("entries")


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

        assert cmd_res.outputs == create_grade_alert_mock.get("id")


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

    mocker.patch.object(client, "get_domain_services", return_value=services_mock)

    cmd_res: CommandResults = company_services_get_command(client=client, domain=domain)
    services = cmd_res.outputs

    assert services == services_mock.get("entries")
