import pytest
from unittest.mock import patch
from VectraRUXGetIncidents import (
    check_if_found_incident,
    add_incidents_link,
)


# ==================== Tests for check_if_found_incident ====================


class TestCheckIfFoundIncident:
    def test_incident_found_returns_true(self):
        res = [{"Contents": {"data": [{"id": "1", "name": "Test Incident"}]}}]
        assert check_if_found_incident(res) is True

    def test_incident_not_found_data_is_none_returns_false(self):
        res = [{"Contents": {"data": None}}]
        assert check_if_found_incident(res) is False

    def test_raises_exception_when_data_key_missing(self):
        res = [{"Contents": {"error": "something went wrong"}}]
        with pytest.raises(Exception):
            check_if_found_incident(res)

    def test_raises_exception_when_res_is_empty_list(self):
        res: list = []
        with pytest.raises(Exception):
            check_if_found_incident(res)

    def test_raises_exception_when_contents_is_not_dict(self):
        res = [{"Contents": "some string"}]
        with pytest.raises(Exception):
            check_if_found_incident(res)

    def test_raises_exception_when_res_is_not_list(self):
        res = "invalid response"
        with pytest.raises(Exception):
            check_if_found_incident(res)  # type: ignore

    def test_raises_exception_with_correct_message_when_contents_has_error(self):
        error_contents = {"message": "Unauthorized"}
        res = [{"Contents": error_contents}]
        with pytest.raises(Exception, match="Unauthorized"):
            check_if_found_incident(res)

    def test_raises_exception_when_res_is_none(self):
        with pytest.raises(Exception):
            check_if_found_incident(None)  # type: ignore


# ==================== Tests for add_incidents_link ====================


class TestAddIncidentsLink:
    @patch("VectraRUXGetIncidents.demisto")
    @patch("VectraRUXGetIncidents.is_demisto_version_ge", return_value=True)
    def test_adds_incident_link_version_ge_8_4(self, mock_version, mock_demisto):
        mock_demisto.demistoUrls.return_value = {"server": "https://xsoar.example.com"}
        data = [{"id": "100"}]
        result = add_incidents_link(data)
        assert "incidentLink" in result[0]
        assert "/Details/100" in result[0]["incidentLink"]
        assert "#" not in result[0]["incidentLink"]

    @patch("VectraRUXGetIncidents.demisto")
    @patch("VectraRUXGetIncidents.is_demisto_version_ge", return_value=False)
    def test_adds_incident_link_with_hash_prefix_below_8_4(self, mock_version, mock_demisto):
        mock_demisto.demistoUrls.return_value = {"server": "https://xsoar.example.com"}
        data = [{"id": "200"}]
        result = add_incidents_link(data)
        assert "incidentLink" in result[0]
        assert "#/Details/200" in result[0]["incidentLink"]

    @patch("VectraRUXGetIncidents.demisto")
    @patch("VectraRUXGetIncidents.is_demisto_version_ge", return_value=True)
    def test_multiple_incidents(self, mock_version, mock_demisto):
        mock_demisto.demistoUrls.return_value = {"server": "https://xsoar.example.com"}
        data = [{"id": "10"}, {"id": "20"}]
        result = add_incidents_link(data)
        assert all("incidentLink" in inc for inc in result)
        assert "/Details/10" in result[0]["incidentLink"]
        assert "/Details/20" in result[1]["incidentLink"]

    @patch("VectraRUXGetIncidents.demisto")
    @patch("VectraRUXGetIncidents.is_demisto_version_ge", return_value=True)
    def test_returns_same_data_list(self, mock_version, mock_demisto):
        mock_demisto.demistoUrls.return_value = {"server": "https://xsoar.example.com"}
        data = [{"id": "xyz"}]
        result = add_incidents_link(data)
        assert result is data

    @patch("VectraRUXGetIncidents.demisto")
    @patch("VectraRUXGetIncidents.is_demisto_version_ge", return_value=True)
    def test_incident_link_contains_server_url(self, mock_version, mock_demisto):
        mock_demisto.demistoUrls.return_value = {"server": "https://xsoar.example.com"}
        data = [{"id": "42"}]
        result = add_incidents_link(data)
        assert "xsoar.example.com" in result[0]["incidentLink"]
