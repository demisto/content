import demistomock as demisto
import pytest
import ShowCampaignLastIncidentOccurred

MULTIPLE_INCIDENTS = [
    {"id": "1", "occurred": "2021-07-27T15:09:35.269187268Z", "created": "2021-08-05T15:09:35.269187268Z"},
    {"id": "2", "occurred": "2021-07-28T15:06:33.100736309Z", "created": "2021-08-05T15:06:33.100736309Z"},
    {"id": "3", "occurred": "2021-07-29T14:42:38.945010982Z", "created": "2021-08-05T14:42:38.945010982Z"},
    {"id": "4", "occurred": "2021-07-29T14:09:22.708160443Z", "created": "2021-08-05T14:09:22.708160443Z"},
]
ONE_INCIDENT = [{"id": "1", "occurred": "2021-07-28T15:06:33.100736309Z", "created": "2021-08-05T15:06:33.100736309Z"}]
INCIDENTS_WITHOUT_OCCURRED = [{"id": "1", "created": "2021-08-05T15:06:33.100736309Z"}]
INCIDENTS_WITH_PARTIAL_OCCURRED = [
    {"id": "1", "occurred": "2021-07-27T15:09:35.269187268Z"},
    {"id": "2", "occurred": ""},
    {"id": "3", "occurred": "0001-01-01T00:00:00Z"},
    {"id": "4", "occurred": "not-a-date"},
    {"id": "5", "occurred": 1627398575},
]
INCIDENTS_WITH_MIXED_TZ_AWARENESS = [
    {"id": "1", "occurred": "2021-07-27T15:09:35.269187268Z"},
    {"id": "2", "occurred": "2021-07-30T10:00:00"},
]

EXPECTED_HTML = (
    "<div style='text-align:center; font-size:17px; padding: 15px;'>Last Incident Occurred</br> "
    "<div style='font-size:24px;'> {value} </div></div>"
)


@pytest.mark.parametrize(
    "campaign_incidents, expected_result",
    [
        pytest.param(MULTIPLE_INCIDENTS, "July 29, 2021", id="multiple incidents"),
        pytest.param(ONE_INCIDENT, "July 28, 2021", id="single incident"),
        pytest.param(INCIDENTS_WITH_PARTIAL_OCCURRED, "July 27, 2021", id="only some incidents have a valid occurred"),
        pytest.param(INCIDENTS_WITH_MIXED_TZ_AWARENESS, "July 30, 2021", id="mixed timezone awareness"),
        pytest.param(ONE_INCIDENT[0], "July 28, 2021", id="a single incident given as a dict and not as a list"),
        pytest.param([], "No last incident occurred found.", id="no campaign incidents"),
        pytest.param(None, "No last incident occurred found.", id="no campaign context"),
        pytest.param(INCIDENTS_WITHOUT_OCCURRED, "No last incident occurred found.", id="incidents without occurred"),
    ],
)
def test_show_last_incident_occurred(mocker, campaign_incidents, expected_result):
    """
    Given:
        - Campaign incidents in the context.
    When:
        - Running the show last incident occurred script main function.
    Then:
        - Ensure the last incident occurred date is taken from the occurred field and appears in the html format.
    """
    mocker.patch.object(demisto, "context", return_value={"EmailCampaign": {"incidents": campaign_incidents}})
    mocker.patch.object(demisto, "results")

    ShowCampaignLastIncidentOccurred.main()

    res = demisto.results.call_args[0][0]["Contents"]

    assert EXPECTED_HTML.format(value=expected_result) == res


def test_occurred_is_used_and_not_created(mocker):
    """
    Given:
        - Campaign incidents whose created date is later than their occurred date.
    When:
        - Running the show last incident occurred script main function.
    Then:
        - Ensure the displayed date is derived from occurred and not from created.
    """
    mocker.patch.object(demisto, "context", return_value={"EmailCampaign": {"incidents": MULTIPLE_INCIDENTS}})
    mocker.patch.object(demisto, "results")

    ShowCampaignLastIncidentOccurred.main()

    res = demisto.results.call_args[0][0]["Contents"]

    assert "July 29, 2021" in res
    assert "August 05, 2021" not in res


def test_no_commands_are_executed(mocker):
    """
    Given:
        - Campaign incidents in the context.
    When:
        - Running the show last incident occurred script main function.
    Then:
        - Ensure no redundant command (such as GetIncidentsByQuery) is executed.
    """
    mocker.patch.object(demisto, "context", return_value={"EmailCampaign": {"incidents": MULTIPLE_INCIDENTS}})
    mocker.patch.object(demisto, "results")
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")

    ShowCampaignLastIncidentOccurred.main()

    assert execute_command_mock.call_count == 0
