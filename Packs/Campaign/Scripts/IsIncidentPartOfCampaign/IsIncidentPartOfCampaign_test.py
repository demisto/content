import pytest
import re

import demistomock as demisto
from IsIncidentPartOfCampaign import main

INCIDENTS: list[dict] = [
    {'id': '1', 'type': 'Phishing Campaign'},
    {'id': '2', 'type': 'Phishing Campaign'},
    {'id': '3', 'type': 'Phishing'},
    {'id': '4', 'type': 'Phishing', 'partofcampaign': '1'},
    {'id': '5', 'type': 'Phishing', 'partofcampaign': '2'},
    {'id': '6', 'type': 'Phishing'},
]


def get_incidents_by_query_func(args):
    query = args["query"]
    match = re.search(r"incident.id:\(([^\)]*)\)", query)
    incident_ids = set(match.group(1).split(" ") if match and match.group(1) else [])
    return [i for i in INCIDENTS if i.get("id") in incident_ids and i.get("partofcampaign")]


@pytest.fixture(autouse=True)
def mock_get_incidents_by_query(mocker):
    mocker.patch(
        "IsIncidentPartOfCampaign.get_incidents_by_query",
        side_effect=get_incidents_by_query_func,
    )


def test_success(mocker):
    """Given a list of incident IDs that are part of a campaign, make sure results are returned"""
    mocker.patch.object(demisto, "args", return_value={"IncidentIDs": "3,5"})
    results = main()
    assert "Found campaign with ID" in results.readable_output
    assert results.outputs["ExistingCampaignID"] in ["1", "2"]


def test_no_results(mocker):
    """Given a list of incident IDs, but they are not part of a campaign, make sure no results are returned"""
    mocker.patch.object(demisto, "args", return_value={"IncidentIDs": "1"})
    results = main()
    assert "No campaign was found" in results.readable_output
    assert not results.outputs["ExistingCampaignID"]
