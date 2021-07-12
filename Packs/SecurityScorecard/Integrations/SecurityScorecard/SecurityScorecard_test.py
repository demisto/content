from SecurityScorecard import Client, \
    is_valid_domain, \
    is_email_valid, \
    is_date_valid, \
    incidents_to_import
# securityscorecard_portfolios_list_command, \
# securityscorecard_portfolio_list_companies_command, \
# securityscorecard_company_factor_score_get_command,  \
# securityscorecard_company_history_score_get_command,  \
# securityscorecard_company_services_get_command,  \
# securityscorecard_company_score_get_command,  \
# securityscorecard_company_history_factor_score_get_command,  \
# securityscorecard_alert_grade_change_create_command, \
# securityscorecard_alert_score_threshold_create_command, \
# securityscorecard_alerts_list_command, \

import requests_mock
import requests
import json
import io
import demistomock as demisto
import datetime

MOCK_URL = "mock://securityscorecard-mock-url"
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

client = Client(
    base_url=MOCK_URL,
    verify=False,
    proxy=False
)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_is_valid_domain():
    assert is_valid_domain("google.com")
    assert not is_valid_domain("sometestdomain")


def test_is_email_valid():
    assert is_email_valid("someuser@somedomain.com")
    assert not is_email_valid("someuser.com")


def test_is_date_valid():
    assert is_date_valid("2021-12-31")
    assert not is_date_valid("2021-13-31")
    assert not is_date_valid("202-12-31")


def test_incidents_to_import(mocker):

    raw_response = util_load_json('./test_data/alerts.json')
    mocker.patch.object(client, "get_alerts_last_week", return_value=raw_response)

    response = client.get_alerts_last_week(email="some@email.com")

    assert response.get('entries')

    entries = response.get('entries')

    assert len(entries) == 9

    # 3 day in seconds
    seconds_ago = 3 * 86400

    # Set runtime
    now = int(datetime.datetime(2021, 7, 12).timestamp()) - seconds_ago
    demisto.setLastRun({
        'last_run': now
    })

    incidents = incidents_to_import(entries)

    assert len(incidents) == 6

    # Iterate over each incident and ensure they
    # were supposed to be imported
    for incident in incidents:
        incident_time = incident["occurred"]
        incident_timestamp = int(datetime.datetime.strptime(incident_time, DATE_FORMAT).timestamp())
        assert incident_timestamp > now


def test_securityscorecard_portfolios_list(mocker):

    raw_response = util_load_json("./test_data/portfolios/portfolios.json")
    mocker.patch.object(client, "get_portfolios", return_value=raw_response)

    response = client.get_portfolios()

    assert response.get('entries')

    entries = response.get('entries')

    assert len(entries) == 3
    first_entry = entries[0]
    assert first_entry.get('id') == '1'
    assert first_entry.get('name') == 'portfolio_1'
    assert first_entry.get('privacy') == 'private'
    assert first_entry.get('read_only') == 'true'

    return entries


def test_securityscorecard_portfolio_list_companies(mocker):

    """
        Checks cases where the portfolio exists and doesn't exist
    """

    portfolios = test_securityscorecard_portfolios_list(mocker)

    # 1. Portfolio that exists
    portfolio_exists = portfolios[0]

    raw_response = util_load_json("./test_data/portfolios/companies.json")
    mocker.patch.object(client, "get_companies_in_portfolio", return_value=raw_response)
    response_portfolio = client.get_companies_in_portfolio(portfolio_exists)

    assert response_portfolio.get("entries")

    companies = response_portfolio.get("entries")

    assert len(companies) == 3

    # 2. Portfolio doesn't exist
    non_exist_portfolio = "portfolio4"
    url = "{0}/portfolios/{1}/companies".format(MOCK_URL, non_exist_portfolio)
    portfolio_not_exist_raw_response = util_load_json("./test_data/portfolios/portfolio_not_found.json")

    with requests_mock.mock() as mocker2:
        mocker2.get(url, json=portfolio_not_exist_raw_response)
        portfolio_not_exist_response = requests.get(url)

        assert portfolio_not_exist_response.json()["error"]["message"] == "portfolio not found"


# def test_securityscorecard_company_factor_score_get():

# def test_securityscorecard_company_history_score_get():

# def test_securityscorecard_alert_grade_change_create():

# def test_securityscorecard_alert_score_threshold_create():

# def test_securityscorecard_alerts_list():

# def test_securityscorecard_company_services_get():

# def test_securityscorecard_company_score_get():

# def test_securityscorecard_company_history_factor_score_get():


def main() -> None:
    pass


if __name__ == "builtins":
    main()
