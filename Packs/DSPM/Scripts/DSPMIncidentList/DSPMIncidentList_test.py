from unittest.mock import patch
from DSPMIncidentList import get_incident_time, timeDifferenceInHours, get_incident_list, delete_incident_list, add_incident_list


def test_get_incident_time():
    incident_list = [
        {"incident_id": "1", "incident_created": "2024-11-01T00:00:00Z"},
        {"incident_id": "2", "incident_created": "2024-11-02T00:00:00Z"},
        {"incident_id": "3", "incident_created": "2024-11-03T00:00:00Z"},
    ]
    incident_id = "2"
    result = get_incident_time(incident_list, incident_id)

    # Assert
    assert result == "2024-11-02T00:00:00Z"


def test_timeDifferenceInHours():
    given_timestamp = "2024-11-04 08:00:00.000000"
    rerun_time = 4
    result = timeDifferenceInHours(given_timestamp, rerun_time)
    assert result is True


def test_get_incident_list():
    incident_object = {}
    mock_response = [{"Contents": ["Incident1", "Incident2", "Incident3"]}]

    with patch("DSPMIncidentList.demisto.executeCommand", return_value=mock_response):
        result = get_incident_list(incident_object)

        # Assert
        assert result == ["Incident1", "Incident2", "Incident3"]


def test_delete_incident_list():
    args = {
        "rerun_time": "48",
        "incident_data": {"id": 1},
        "incident_list": '{"incident_id": 1, "incident_created": "2024-01-01T00:00:00Z"}'
    }

    with patch("DSPMIncidentList.get_incident_time", return_value="2024-01-01T00:00:00Z"), \
            patch("DSPMIncidentList.timeDifferenceInHours", return_value=True):
        result = delete_incident_list(args)

        # Assert
        assert result == "Delete incident data with incident id 1 from the list."


def test_add_incident_list():
    args = {
        "incident_data": {"id": "1", "incidentCreated": "2024-11-01T00:00:00Z"},
        "incident_list": '{"incident_id": "2", "incident_created": "2024-11-02T00:00:00Z"}'
    }
    result = add_incident_list(args)

    # Assert
    assert result == "Successfully added incident data with incident id 1 in the list."
