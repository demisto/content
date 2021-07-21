from SecurityScorecard import \
    SecurityScorecardClient, \
    DATE_FORMAT, \
    incidents_to_import

import json
import io
import datetime

""" Helper Functions Test Data"""


def load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


domain_test_data = [("google.com", True), ("sometestdomain", False)]
date_test_data = [("2021-12-31", True), ("2021-13-31", False), ("202-12-31", False)]
email_test_data = [("username@domain.com", True), ("username.com", False), ("username@", False)]
alerts_mock = load_json("./test_data/alerts/alerts.json")
portfolios_mock = load_json("./test_data/portfolios/portfolios.json")
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


def test_incidents_to_import(mocker):

    mocker.patch.object(client, "get_alerts_last_week", return_value=alerts_mock)

    response = client.get_alerts_last_week(email="some@email.com")

    assert response.get('entries')

    entries = response.get('entries')

    assert len(entries) == 2

    # 3 day in seconds
    seconds_ago = 3 * 86400

    # Set runtime
    now = int(datetime.datetime(2021, 7, 12).timestamp()) - seconds_ago

    incidents = incidents_to_import(entries)

    assert len(incidents) == 0

    # Iterate over each incident and ensure they
    # were supposed to be imported
    for incident in incidents:
        incident_time = incident["occurred"]
        incident_timestamp = int(datetime.datetime.strptime(incident_time, DATE_FORMAT).timestamp())
        assert incident_timestamp > now


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


def test_portfolios_list(mocker):

    mocker.patch.object(client, "get_portfolios", return_value=portfolios_mock)

    response = client.get_portfolios()

    assert response == portfolios_mock


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
