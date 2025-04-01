from CommonServerPython import *
from SecurityScorecard import \
    SecurityScorecardClient, \
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
    company_services_get_command, \
    issue_metadata_get_command, \
    company_events_get_command, \
    company_event_findings_get_command, \
    alert_rules_list_command

from unittest.mock import MagicMock

import json
import io
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

FROZEN_DATE = "2021-10-09T22:38:02.560Z"


@pytest.mark.freeze_time(FROZEN_DATE)
@pytest.mark.parametrize(
    'last_run, first_fetch',
    [
        (FROZEN_DATE, None),
        (None, "3 days"),
        (None, "7 days"),
        (FROZEN_DATE, "7 days")
    ]
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

    last_run_dt = get_last_run(last_run=last_run, first_fetch=first_fetch)

    if last_run:
        assert last_run_dt.replace(microsecond=0, second=0, minute=0, hour=0) == \
            arg_to_datetime(arg_name="last_run", arg=last_run).replace(microsecond=0, second=0, minute=0, hour=0, tzinfo=None)
    else:
        # resetting microsecond as causes failure:
        # E             +datetime.datetime(2021, 10, 3, 14, 50, 3, 242595)
        # E             -datetime.datetime(2021, 10, 3, 14, 50, 3, 244008)
        assert last_run_dt.replace(microsecond=0, second=0, minute=0, hour=0, tzinfo=None) == \
            arg_to_datetime(
                arg_name="first_fetch",
                arg=first_fetch
        ).replace(microsecond=0, second=0, minute=0, hour=0, tzinfo=None)


alerts_mock = test_data.get("alerts")
incidents_mock = test_data.get("incidents")
incidents_to_import_test_inputs = [
    ([]),
    (alerts_mock),
]


@pytest.mark.parametrize('alerts', incidents_to_import_test_inputs)
def test_incidents_to_import(alerts: list):
    """
    Given:
        - List of alerts

    When:
        - Case A: No alerts supplied
        - Case B: alerts supplied

    Then:
        - Case A : No alerts imported
        - Case B: alerts imported

    """

    # Need to remove tz info to deal with tz awareness with arg_to_datetime
    incidents = incidents_to_import(
        alerts=alerts,
        last_run=arg_to_datetime("2021-07-25T00:00:00.000Z").replace(tzinfo=None)  # type: ignore
    )
    if not alerts:
        assert not incidents
    else:
        assert incidents == incidents_mock


""" Command Unit Tests """


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
    (
        {
            "portfolio_id": PORTFOLIO_ID,
            "grade": None,
            "industry": None,
            "vulnerability": None,
            "issue_type": None,
            "had_breach_within_last_days": None
        }
    ),
    (
        {
            "portfolio_id": PORTFOLIO_ID,
            "grade": "A",
            "industry": None,
            "vulnerability": None,
            "issue_type": None,
            "had_breach_within_last_days": None
        }
    ),
    (
        {
            "portfolio_id": PORTFOLIO_ID,
            "grade": "A",
            "industry": "food",
            "vulnerability": None,
            "issue_type": None,
            "had_breach_within_last_days": None
        }
    ),
    (
        {
            "portfolio_id": PORTFOLIO_ID,
            "grade": None,
            "industry": None,
            "vulnerability": None,
            "issue_type": None,
            "had_breach_within_last_days": "7"
        }
    )
]


@pytest.mark.parametrize("args", companies_list_test_inputs)
def test_portfolio_list_companies(mocker, args: Dict[str, Any]):
    """
    Given:
        - A portfolio ID
        - 3 portfolios in test data
    When:
        - Case A: no filters supplied
        - Case B: grade filter supplied
        - Case C: grade filter and an industry filter supplied
        - Case D: invalid had breach within last days filter supplied
    Then:
        - Case A: All 3 portfolios returned
        - Case B: 2 portfolios returned
        - Case C: 1 portfolio returned
        - Case D: All 3 portfolios returned
    """

    if args.get("grade"):
        if args.get("industry"):
            companies_mock: Dict[str, str] = test_data.get("companies_A_grade_food_industry")
        else:
            companies_mock = test_data.get("companies_A_grade")

    else:
        companies_mock = test_data.get("companies")

    companies_entries: List[Dict[str, Any]] = companies_mock.get("entries")  # type: ignore

    mocker.patch.object(client, "get_companies_in_portfolio", return_value=companies_mock)

    companies_cmd_res: CommandResults = portfolio_list_companies_command(client=client, args=args)

    companies = companies_cmd_res.outputs

    assert companies == companies_entries


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
    ({"domain": DOMAIN}),
    ({"domain": "google.com"}),
    ({"domain": "GOOGLE.COM"}),
    ({"domain": "nonexistantdomain.com"})
]


@pytest.mark.parametrize("args", company_score_test_input)
def test_get_company_score(mocker, args):
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

    response_cmd_res: CommandResults = company_score_get_command(client=client, args=args)

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

    cmd_res: CommandResults = company_score_get_command(client=client, args={"domain": DOMAIN_NE})

    status = cmd_res.outputs.get("error").get("statusCode")
    message = cmd_res.outputs.get("error").get("message")

    assert status == 404
    assert message == f"company not found: {DOMAIN_NE}"


factor_score_test_inputs = [
    ({"domain": DOMAIN, "severity": None}),
    ({"domain": DOMAIN, "severity": "positive"}),
    ({"domain": DOMAIN, "severity": "high,low"})
]


@pytest.mark.parametrize("args", factor_score_test_inputs)
def test_get_company_factor_score(mocker, args):
    """
    Given:
        - A domain
        - A severity filter
    When:
        - Case A: Domain is valid, severity unspecified
        - Case B: Domain is valid, severity is positive
        - Case C: Domain is valid, severity is low and high
    Then:
        - Case A: Results in all severity factor scores for domain
        - Case B: Results only in positive severity factor scores for domain
        - Case C: Results in high and low severity factor scores for domain
    """

    if args.get("severity") == "positive":
        factor_score_mock = test_data.get("factor_score_severity_positive")
    elif args.get("severity") == "high,low":
        factor_score_mock = test_data.get("factor_score_severity_low_high")
    else:
        factor_score_mock = test_data.get("factor_score")

    mocker.patch.object(client, "get_company_factor_score", return_value=factor_score_mock)

    response: CommandResults = company_factor_score_get_command(client=client, args=args)

    assert response.outputs == factor_score_mock.get("entries")


company_historical_scores_test_inputs = [
    ({"domain": DOMAIN, "from": None, "to": None, "timing": None}),
    ({"domain": DOMAIN, "from": "2021-07-01", "to": "2021-07-31", "timing": "daily"}),
    ({"domain": DOMAIN, "from": "2021-07-01", "to": "2021-07-31", "timing": None}),
    ({"domain": DOMAIN, "from": "2021-07-01", "to": "2021-07-31", "timing": "weekly"})
]


@pytest.mark.parametrize("args", company_historical_scores_test_inputs)
def test_get_company_historical_scores(mocker, args):
    """
    Given:
        - A domain
        - Date range
        - Timing
    When:
        - Case A: no range, no resolution
        - Case B: range 2021-07-01 to 2021-07-04, daily
        - Case C: range 2021-07-01 to 2021-07-04, no resolution
        - Case D: range 2021-07-01 to 2021-07-31, weekly
    Then:
        - Case A: Return all scores
        - Case B: Return scores received for 2021-07-01 to 2021-07-04 on daily basis
        - Case C: Return scores received for 2021-07-01 to 2021-07-04 on daily basis
        - Case D: Score received for 2021-07-01 to 2021-07-31 on weekly basis
    """

    if args.get("daily"):
        historical_score_mock = test_data.get("historical_score_daily")
    elif args.get("weekly"):
        historical_score_mock = test_data.get("historical_scores_weekly")
    else:
        historical_score_mock = test_data.get("historical_score")

    mocker.patch.object(client, "get_company_historical_scores", return_value=historical_score_mock)

    response: CommandResults = company_history_score_get_command(
        client=client,
        args=args
    )

    cmd_output = response.outputs

    assert cmd_output == historical_score_mock.get("entries")


company_historical_factor_scores_test_inputs = [
    ({"domain": DOMAIN, "from": None, "to": None, "timing": None}),
    ({"domain": DOMAIN, "from": "2021-07-01", "to": "2021-07-31", "timing": "daily"}),
    ({"domain": DOMAIN, "from": "2021-07-01", "to": "2021-07-31", "timing": None}),
    ({"domain": DOMAIN, "from": "2021-07-01", "to": "2021-07-31", "timing": "weekly"})
]


@pytest.mark.parametrize("args", company_historical_factor_scores_test_inputs)
def test_get_company_historical_factor_scores(mocker, args):
    """
    Given:
        - A domain
        - Date range
        - Timing
    When:
        - Case A: no range, no resolution
        - Case B: range 2021-07-01 to 2021-07-04, daily
        - Case C: range 2021-07-01 to 2021-07-04, no resolution
        - Case D: range 2021-07-01 to 2021-07-31, weekly
    Then:
        - Case A: Return all scores
        - Case B: Return scores received for 2021-07-01 to 2021-07-04 on daily basis
        - Case C: Return scores received for 2021-07-01 to 2021-07-04 on daily basis
        - Case D: Score received for 2021-07-01 to 2021-07-31 on weekly basis
    """

    if args.get("daily"):
        historical_factor_score_mock = test_data.get("historical_factor_score_daily")
    elif args.get("weekly"):
        historical_factor_score_mock = test_data.get("historical_factor_scores_weekly")
    else:
        historical_factor_score_mock = test_data.get("historical_factor_score")

    historical_factor_score_mock = test_data.get("historical_factor_score")
    mocker.patch.object(client, "get_company_historical_factor_scores", return_value=historical_factor_score_mock)

    cmd_res: CommandResults = company_history_factor_score_get_command(client=client, args=args)

    factor_scores = cmd_res.outputs
    assert factor_scores == historical_factor_score_mock.get("entries")


alert_creation_inputs = [
    ({
        "change_direction": "drops",
        "score_types": "overall",
        "target": "my_scorecard",
        "portfolio": None
    }),
    ({
        "change_direction": "drops",
        "score_types": ["application_security"],
        "target": None,
        "portfolio": "1"
    }),
    ({
        "change_direction": "rises",
        "score_types": "application_security",
        "target": None,
        "portfolio": "1"
    }),
    ({
        "change_direction": "rises",
        "score_types": ["overall"],
        "target": "any_followed_company",
        "portfolio": None
    }),
]


@pytest.mark.parametrize("args, expected_delivery", zip(alert_creation_inputs, test_data.get("delivery_objects").get("entries")))
def test_create_grade_alert_subscription_delivery_object(mocker, args, expected_delivery):
    """
    Test the creation of a grade alert subscription delivery object.
    This test mocks the `create_alert_subscription` method of the `client` object
    to return a predefined alert subscription. It then verifies that the delivery
    object created by the `alert_grade_change_create_command` function matches the
    expected delivery structure and that the result outputs the correct alert ID.
    Args:
        mocker (MockerFixture): The mocker fixture used to patch methods.
        args (dict): The arguments for the alert creation.
        expected_delivery (dict): The expected delivery object.
    Raises:
        AssertionError: If the delivery object or result outputs do not match the expected values.
    """

    create_grade_alert_mock = {"id": "test_alert_id"}
    mocker.patch.object(client, "create_alert_subscription", return_value=create_grade_alert_mock)

    result = alert_grade_change_create_command(client, args)

    actual_delivery = client.create_alert_subscription.call_args[1]['delivery']

    assert actual_delivery == expected_delivery
    assert result.outputs == "test_alert_id"


# Define the test data for score threshold alert creation tests
threshold_alert_creation_inputs = [
    {
        "change_direction": "drops_below",
        "threshold": 85,
        "score_types": ["overall"],
        "target": "any_followed_company",
        "portfolio": None
    },
    {
        "change_direction": "rises_above",
        "threshold": 70,
        "score_types": ["application_security", "test_factor"],
        "target": None,
        "portfolio": "1"
    },
]


@pytest.mark.parametrize(
    "args, expected_delivery",
    zip(threshold_alert_creation_inputs, test_data.get("threshold_delivery_objects").get("entries"))
)
def test_create_score_threshold_alert_subscription_delivery_object(mocker, args, expected_delivery):
    """
    Test the creation of a score threshold alert subscription delivery object.
    This test mocks the `create_alert_subscription` method of the `client` object
    to return a predefined alert subscription. It then verifies that the delivery
    object created by the `alert_score_threshold_create_command` function matches the
    expected delivery structure and that the result outputs the correct alert ID.
    Args:
        mocker (MockerFixture): The mocker fixture used to patch methods.
        args (dict): The arguments for the alert creation.
        expected_delivery (dict): The expected delivery object.
    Raises:
        AssertionError: If the delivery object or result outputs do not match the expected values.
    """

    create_score_threshold_alert_mock = {"id": "test_alert_id"}
    mocker.patch.object(client, "create_alert_subscription", return_value=create_score_threshold_alert_mock)

    result = alert_score_threshold_create_command(client, args)
    actual_delivery = client.create_alert_subscription.call_args[1]['delivery']

    assert actual_delivery == expected_delivery
    assert result.outputs == "test_alert_id"


grade_alert_test_input = [
    ({"change_direction": "rises", "score_types": "overall", "target": None, "portfolio": PORTFOLIO_ID}),
    ({"change_direction": "rises", "score_types": "application_security", "target": "my_scorecard", "portfolio": "1"}),
    ({"change_direction": "rises", "score_types": "application_security", "target": None, "portfolio": None})
]


@pytest.mark.parametrize("args", grade_alert_test_input)
def test_create_grade_change_alert(mocker, args):
    """
    Given:
        - Direction change
        - Score type(s)
        - Target or Portfolio
    When:
        - Case A: rising grade, overall score type, to portfolio
        - Case B: Both portfolio and target are specified
        - Case C: Neither portfolio and target are specified
    Then:
        - Case A: Alert created
        - Case D: DemistoException thrown
        - Case E: DemistoException thrown
    """

    create_grade_alert_mock = test_data.get("create_grade_alert")
    mocker.patch.object(client, "create_alert_subscription", return_value=create_grade_alert_mock)

    if args.get("target") and args.get("portfolio"):
        with pytest.raises(DemistoException) as exc:
            alert_grade_change_create_command(
                client=client,
                args=args
            )

        assert "Both 'portfolio' and 'target' argument have been set" in str(exc.value)
    elif not args.get("target") and not args.get("portfolio"):
        with pytest.raises(DemistoException) as exc:
            alert_grade_change_create_command(
                client=client,
                args=args
            )

        assert "Either 'portfolio' or 'target' argument must be given" in str(exc.value)
    else:
        cmd_res: CommandResults = alert_grade_change_create_command(
            client=client,
            args=args
        )

        assert cmd_res.outputs == create_grade_alert_mock.get("id")


score_alert_test_input = [
    ({"change_direction": "rises", "threshold": 90, "score_types": "overall", "target": None, "portfolio": PORTFOLIO_ID}),
    ({"change_direction": "rises", "threshold": 90, "score_types": "application_security", "target": "my_scorecard",
        "portfolio": "1"}),
    ({"change_direction": "rises", "threshold": 90, "score_types": "application_security", "target": None,
        "portfolio": None}),
    ({"change_direction": "rises", "threshold": "A", "score_types": "application_security", "target": None, "portfolio": None}),
]


@pytest.mark.parametrize("args", score_alert_test_input)
def test_create_score_change_alert(mocker, args):
    """
    Given:
        - A username
        - Direction change
        - Score type(s)
        - A threshold
        - Target or Portfolio
    When:
        - Case A: Username is valid, rising grade, overall score type, to portfolio
        - Case B: Both portfolio and target are specified
        - Case C: Neither portfolio and target are specified
        - Case D: Threshold supplied is not a number
    Then:
        - Case A: Alert created
        - Case B: DemistoException thrown
        - Case C: DemistoException thrown
        - Case D: ValueError thrown
    """

    create_score_alert_mock = test_data.get("create_score_alert")
    mocker.patch.object(client, "create_alert_subscription", return_value=create_score_alert_mock)

    if not isinstance(args.get("threshold"), int):
        with pytest.raises(ValueError) as exc:
            alert_score_threshold_create_command(client=client, args=args)

        assert "is not a valid number" in str(exc.value)
    elif args.get("target") and args.get("portfolio"):
        with pytest.raises(DemistoException) as exc:
            alert_score_threshold_create_command(client=client, args=args)

        assert "Both 'portfolio' and 'target' argument have been set" in str(exc.value)
    elif not args.get("target") and not args.get("portfolio"):
        with pytest.raises(DemistoException) as exc:
            alert_score_threshold_create_command(client=client, args=args)

        assert "Either 'portfolio' or 'target' argument must be given" in str(exc.value)
    else:

        cmd_res: CommandResults = alert_score_threshold_create_command(client=client, args=args)

        assert cmd_res.outputs == create_score_alert_mock.get("id")


services_test_input = (
    ({"domain": DOMAIN}),
    ({"domain": DOMAIN_NE})
)


@pytest.mark.parametrize("args", services_test_input)
def test_get_domain_services(mocker, args):
    """
    Given:
        - A domain
    When:
        - Case A: Domain is valid
        - Case B: Domain is invalid
    Then:
        - Case A: List of services is returned
        - Case B: Bad request
    """

    if args.get("domain") == DOMAIN_NE:
        services_mock = test_data.get("company_not_found")
        mocker.patch.object(client, "get_domain_services", return_value=services_mock)

        cmd_res: CommandResults = company_services_get_command(client=client, args=args)

        error = cmd_res.readable_output

        assert f"Error returning services for domain '{args.get('domain')}'" == error

    else:
        services_mock = test_data.get("services")
        mocker.patch.object(client, "get_domain_services", return_value=services_mock)

        cmd_res: CommandResults = company_services_get_command(client=client, args=args)
        services = cmd_res.outputs

        assert services == services_mock.get("entries")


def test_incidents_to_import_empty_alerts_future_last_run():
    """
    Given:
        - An empty list of alerts
        - A last run date in the future
    When:
        - incidents_to_import is called
    Then:
        - An empty list of incidents is returned
    """
    alerts = []
    last_run = arg_to_datetime("2022-01-01T00:00:00.000Z").replace(tzinfo=None)
    incidents = incidents_to_import(alerts=alerts, last_run=last_run)
    assert isinstance(incidents, list)
    assert len(incidents) == 0


@pytest.mark.parametrize("limit", ["0"])
def test_portfolios_list_limit_zero(mocker, limit):
    """
    Given:
        - A limit of 0
    When:
        - portfolios_list is called
    Then:
        - An empty list of portfolios is returned
    """
    mocker.patch.object(client, "get_portfolios", return_value=[])
    portfolios = client.get_portfolios(limit=limit)
    assert isinstance(portfolios, list)
    assert len(portfolios) == 0


def test_incidents_to_import_alerts_last_run_in_past():
    """
    Given:
        - A list of alerts
        - A last run date in the past
    When:
        - incidents_to_import is called
    Then:
        - A list of incidents is returned
    """
    mock = [{
        "id": "27",
        "username": "user@domain.com",
        "change_type": "score_change",
        "domain": "domain1.co.il",
        "company_name": "Domain1",
        "portfolios": [{
            "id": "a",
            "name": "test_portfolio"
        }],
        "my_scorecard": False,  # corrected false to False
        "created_at": "2021-07-27T00:00:00.000Z",
        "change_data": [{
            "score": 77,
            "factor": "network_security",
            "direction": "drops",
            "grade_letter": "C",
            "score_impact": -3
        }, {
            "score": 69,
            "factor": "ip_reputation",
            "direction": "drops",
            "grade_letter": "D",
            "score_impact": -3
        }]
    }]
    last_run = arg_to_datetime("2020-01-01T00:00:00.000Z").replace(tzinfo=None)
    incidents = incidents_to_import(alerts=mock, last_run=last_run)
    assert isinstance(incidents, list)
    assert len(incidents) > 0


@pytest.fixture
def mocked_security_scorecard_client():
    mocked_security_scorecard_client = SecurityScorecardClient(
        base_url="https://api.securityscorecard.io",
        verify=True,
        proxy=None,
        headers={"Content-Type": "application/json"},
        username="your_username",
        api_key="your_api_key"
    )
    mocked_security_scorecard_client.get_issue_metadata = MagicMock(return_value={
        "key": "issue_type",
        "severity": "high",
        "factor": "network_security",
        "title": "Issue Title",
        "short_description": "Short description",
        "long_description": "Long description",
        "recommendation": "Recommendation"
    })
    mocked_security_scorecard_client.get_company_events = MagicMock(return_value={
        "entries": [
            {
                "id": "1",
            }
        ]
    })
    mocked_security_scorecard_client.get_company_event_findings = MagicMock(return_value={
        "entries": [
            {
                "id": "1",
            }
        ]
    })
    return mocked_security_scorecard_client


def test_issue_metadata_get_command_success(mocked_security_scorecard_client):
    # Call the issue_metadata_get_command function with a valid issue type
    args = {"issue_type": "issue_type"}
    result = issue_metadata_get_command(mocked_security_scorecard_client, args)

    # Assert that the result is a CommandResults object with the expected attributes
    assert isinstance(result, CommandResults)
    assert result.readable_output.startswith("### Issue Type issue_type")
    assert "key|severity|factor|title|short_description|long_description|recommendation" in result.readable_output
    assert "| issue_type | high | network_security | Issue Title | Short description | Long description | Recommendation" in result.readable_output  # noqa: E501
    assert result.outputs == {
        "key": "issue_type",
        "severity": "high",
        "factor": "network_security",
        "title": "Issue Title",
        "short_description": "Short description",
        "long_description": "Long description",
        "recommendation": "Recommendation"
    }
    assert result.raw_response == {
        "key": "issue_type",
        "severity": "high",
        "factor": "network_security",
        "title": "Issue Title",
        "short_description": "Short description",
        "long_description": "Long description",
        "recommendation": "Recommendation"
    }
    assert result.outputs_key_field == "key"

    # Assert that the client's get_issue_metadata method was called with the expected arguments
    mocked_security_scorecard_client.get_issue_metadata.assert_called_with(issue_type="issue_type")


def test_company_events_get_command_success(mocked_security_scorecard_client):
    # Call the company_events_get_command function with valid arguments
    args = {"domain": "example.com"}
    result = company_events_get_command(mocked_security_scorecard_client, args)

    # Assert that the result is a CommandResults object with the expected attributes
    assert isinstance(result, CommandResults)
    # assert result.outputs == output.COMPANY_EVENTS_GET_OUTPUTS
    # assert result.raw_response == output.COMPANY_EVENTS_GET_RAW_RESPONSE
    assert result.outputs_prefix == "SecurityScorecard.Company.Events"
    assert result.outputs_key_field == "ssc_event_id"

    # Assert that the mocked_security_scorecard_client's get_company_events method was called with the expected arguments
    mocked_security_scorecard_client.get_company_events.assert_called_with(domain="example.com", date_to=None, date_from=None)


def test_company_event_findings_get_command_success(mocked_security_scorecard_client):
    # Call the company_event_findings_get_command function with valid arguments
    args = {"domain": "example.com", "event_id": "example_event_id"}
    result = company_event_findings_get_command(mocked_security_scorecard_client, args)

    # Assert that the result is a CommandResults object with the expected attributes
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SecurityScorecard.Company.Findings"
    assert result.outputs_key_field == "issue_id"

    # Assert that the mocked_security_scorecard_client's get_company_event_findings method was called with the expected arguments
    mocked_security_scorecard_client.get_company_event_findings.assert_called()


def test_alert_rules_list_command(mocker):
    """
    Given:
        - No specific arguments
    When:
        - Retrieving alert rules
    Then:
        - Ensure the alert rules are returned correctly
    """

    alert_rules_mock = test_data.get("alert_rules")
    mocker.patch.object(client, "http_request_wrapper", return_value=alert_rules_mock)

    response_cmd_res: CommandResults = alert_rules_list_command(client=client, args={})

    alert_rules = response_cmd_res.raw_response.get("entries")

    assert alert_rules == alert_rules_mock.get("entries")
    assert response_cmd_res.outputs_prefix == "SecurityScorecard.AlertRules.Rule"
    assert response_cmd_res.outputs_key_field == "id"
