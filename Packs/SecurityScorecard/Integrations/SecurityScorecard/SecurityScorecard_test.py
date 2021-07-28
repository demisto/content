from CommonServerPython import *
from SecurityScorecard import \
    SecurityScorecardClient, \
    SECURITYSCORECARD_DATE_FORMAT, \
    incidents_to_import, \
    get_last_run, \
    portfolios_list_command

import json
import io
import datetime  # type: ignore
import pytest

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

get_last_run_test_inputs = [
    (date_days_ago_timestamp, f"{DAYS_AGO} days"),
    (date_days_ago_timestamp, None)
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


companies_mock = load_json("./test_data/portfolios/companies.json")
portfolio_not_found = load_json("./test_data/portfolios/portfolio_not_found.json")
score_mock = load_json("./test_data/companies/score.json")
factor_score_mock = load_json("./test_data/companies/factor_score.json")
historical_score_mock = load_json("./test_data/companies/historical_score.json")
historical_factor_score_mock = load_json("./test_data/companies/historical_factor_score.json")
create_grade_alert_mock = load_json("./test_data/alerts/create_grade_alert.json")
create_score_alert_mock = load_json("./test_data/alerts/create_score_alert.json")
services_mock = load_json("./test_data/companies/services.json")

""" Helper Functions Unit Tests"""


@pytest.mark.freeze_time(FREEZE_DATE)
@pytest.mark.parametrize('last_run, first_fetch', get_last_run_test_inputs)
def test_get_last_run(last_run: str, first_fetch: str):

    """
    Given:
        - Last fetch run timestamp
        - First fetch parameter

    When:
        - Case A: last fetch timestamp is 24/07/2021, first fetch is 3 days ago
        - Case B: last fetch timestamp is 24/07/2021, first fetch is not suppplied

    Then:
        - Case A and B: Last runtime timestamp is 2021-07-24 00:00:00
    """

    time_result = get_last_run(last_run=last_run, first_fetch=first_fetch)
    print(time_result, DAYS_BEFORE_FREEZE_TIMESTAMP)
    assert time_result == DAYS_BEFORE_FREEZE_TIMESTAMP


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
        print(f"len(filtered_alerts): {len(filtered_alerts)}, len(incidents): {len(incidents)}", days_ago_str)


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


@pytest.mark.parametrize("limit", portfolios_list_test_inputs)
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

    if not limit:
        assert len(portfolios) == portfolios_mock.get("total")
    else:
        assert len(portfolios) == limit


def test_portfolio_list_companies(mocker):

    """
        Checks cases where the portfolio exists and doesn't exist
    """

    # 1. Exiting Portfolio
    mocker.patch.object(client, "get_companies_in_portfolio", return_value=companies_mock)
    response_portfolio = client.get_companies_in_portfolio(PORTFOLIO_ID)

    assert response_portfolio.get("entries")

    companies = response_portfolio.get("entries")

    assert len(companies) == 3

    # 2. Portfolio doesn't exist
    mocker.patch.object(client, "get_companies_in_portfolio", return_value=portfolio_not_found)
    portfolio_not_exist_response = client.get_companies_in_portfolio(PORTFOLIO_ID_NE)

    assert portfolio_not_exist_response["error"]["message"] == "portfolio not found"


def test_get_company_score(mocker):

    mocker.patch.object(client, "get_company_score", return_value=score_mock)

    response_score = client.get_company_score(domain=DOMAIN)

    assert response_score == score_mock
    assert response_score["domain"] == DOMAIN
    assert isinstance(response_score["score"], int)
    assert isinstance(response_score["last30day_score_change"], int)


def test_get_company_factor_score(mocker):

    mocker.patch.object(client, "get_company_factor_score", return_value=factor_score_mock)

    response_factor_score = client.get_company_factor_score(domain=DOMAIN)

    assert response_factor_score == factor_score_mock

    assert response_factor_score["total"] == len(response_factor_score["entries"])

    sample_factor = response_factor_score["entries"][0]

    assert isinstance(sample_factor["score"], int)


def test_get_company_historical_scores(mocker):

    mocker.patch.object(client, "get_company_historical_scores", return_value=historical_score_mock)

    response_historical_score = client.get_company_historical_scores(
        domain=DOMAIN,
        _from="2021-07-01",
        to="2021-07-08",
        timing="daily"
    )

    assert response_historical_score == historical_score_mock
    assert len(response_historical_score["entries"]) == 8
    assert isinstance(response_historical_score["entries"][0]["score"], int)


def test_get_company_historical_factor_scores(mocker):

    mocker.patch.object(client, "get_company_historical_factor_scores", return_value=historical_factor_score_mock)

    response_historical_factor_score = client.get_company_historical_factor_scores(
        domain=DOMAIN,
        _from="2021-07-01",
        to="2021-07-08",
        timing="daily"
    )

    assert response_historical_factor_score == historical_factor_score_mock
    assert len(response_historical_factor_score["entries"]) == 8
    assert len(response_historical_factor_score["entries"][0]["factors"]) == 10
    assert isinstance(response_historical_factor_score["entries"][0]["factors"][0]["score"], int)


def test_create_grade_change_alert(mocker):

    mocker.patch.object(client, "create_grade_change_alert", return_value=create_grade_alert_mock)

    response = client.create_grade_change_alert(
        email=USERNAME,
        change_direction="drops",
        score_types="application_security",
        target="any_followed_company"
    )

    assert response == create_grade_alert_mock


def test_create_score_threshold_alert(mocker):

    mocker.patch.object(client, "create_score_threshold_alert", return_value=create_score_alert_mock)

    response = client.create_score_threshold_alert(
        email=USERNAME,
        change_direction="drops_below",
        threshold=70,
        score_types="application_security",
        target="any_followed_company"
    )

    assert response == create_score_alert_mock


def test_get_alerts_last_week(mocker):

    mocker.patch.object(client, "get_alerts_last_week", return_value=alerts_mock)

    response = client.get_alerts_last_week(email=USERNAME)

    assert response == alerts_mock
    assert response["size"] == 2
    assert isinstance(response["entries"][0]["my_scorecard"], bool)


def test_get_domain_services(mocker):

    mocker.patch.object(client, "get_domain_services", return_value=services_mock)

    response = client.get_domain_services(domain=DOMAIN)

    assert response == services_mock
    assert response["total"] == len(response["entries"])


def test_fetch_alerts(mocker):

    mocker.patch.object(client, "fetch_alerts", return_value=alerts_mock)

    response = client.fetch_alerts(
        username=USERNAME
    )

    assert response == alerts_mock
    assert response["size"] == 2
    assert isinstance(response["entries"][0]["my_scorecard"], bool)
