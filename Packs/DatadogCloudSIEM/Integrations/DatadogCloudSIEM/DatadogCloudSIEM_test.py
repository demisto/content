"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
import os
import pytest
from typing import Optional
from unittest.mock import MagicMock
from CommonServerPython import CommandResults, DemistoException
from DatadogCloudSIEM import (
    get_tags_command,
    create_event_command,
    add_tags_to_host_command,
    get_events_command,
    create_incident_command,
    update_incident_command,
    update_host_tags_command,
    get_incident_command,
    update_metric_metadata_command,
    metrics_search_command,
    get_metric_metadata_command,
    active_metrics_list_command,
    get_host_tags_command,
    delete_incident_command,
    metric_command_results,
    delete_host_tags_command,
    query_timeseries_points_command,
    get_paginated_results,
    table_header,
    is_within_time,
    event_for_lookup,
    incident_for_lookup,
    pagination,
    PAGE_SIZE_ERROR_MSG,
    PAGE_NUMBER_ERROR_MSG,
    DEFAULT_PAGE_SIZE,
    convert_datetime_to_str,
    tags_context_and_readable_output,
    module_test,
    fetch_incidents,
)
from datadog_api_client.v1.model.metrics_list_response import MetricsListResponse
from datadog_api_client.v1.model.metric_search_response import MetricSearchResponse
from datadog_api_client.v1.model.metric_search_response_results import (
    MetricSearchResponseResults,
)
from datadog_api_client.v1.model.metric_metadata import MetricMetadata
from test_data.inputs import *
import datetime
import demistomock as demisto


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


DATADOG_API_CLIENT_MOCK = MagicMock()

TAGS_LIST_RESPONSE = util_load_json("test_data/tag-list.json")
HOST_TAG_CREATE_RESPONSE = util_load_json("test_data/host-tag-create.json")
HOST_TAG_GET_RESPONSE = util_load_json("test_data/host-tag-get.json")
HOST_TAG_UPDATE_RESPONSE = util_load_json("test_data/host-tag-update.json")


class Datadog:
    """
    A class representing a Datadog object, which stores key-value pairs as attributes.

    Attributes:
    **kwargs (key-value pairs): The key-value pairs to store as attributes of the Datadog object.

    Methods:
    to_dict(): Converts the Datadog object to a dictionary, where the keys are the attribute names
    and the values are the attribute values.
    """

    def __init__(self, **kwargs):
        """
        Initializes the Datadog object with the given key-value pairs as attributes.

        Args:
        **kwargs (key-value pairs): The key-value pairs to store as attributes of the Datadog object.
        """
        for key, value in kwargs.items():
            setattr(self, key, value)

    def to_dict(self):
        """
        Converts the Datadog object to a dictionary, where the keys are the attribute names and
        the values are the attribute values.

        Returns:
        dict: A dictionary representation of the Datadog object.
        """
        return {
            attr: getattr(self, attr)
            for attr in dir(self)
            if not callable(getattr(self, attr)) and not attr.startswith("__")
        }


@pytest.fixture
def configuration():
    return MagicMock()


@pytest.mark.parametrize(
    "raw_resp, expected", [(EVENT_CREATE_RESPONSE, EVENT_CREATE_CONTEXT)]
)
def test_create_event_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the create_event_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the create_event_command function against the expected output.
    """
    args = {
        "title": "Event Title",
        "text": "Event Text",
        "alert_type": "info",
        "date_happened": "1 hour ago",
        "device_name": "DESKTOP-IIQVPJ7",
        "host_name": "DESKTOP-IIQVPJ7",
        "tags": "test:123",
    }
    raw_obj = Datadog(**EVENT_CREATE_RESPONSE)
    DATADOG_API_CLIENT_MOCK.create_event.return_value = raw_obj
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.EventsApi", return_value=DATADOG_API_CLIENT_MOCK)
    with open(
        os.path.join("test_data", "readable_outputs/create_event_command_readable.md"),
        "r",
    ) as f:
        readable_output = f.read()
    result = create_event_command(configuration, args)
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected", [(EVENT_LIST_RESPONSE, EVENT_LIST_CONTEXT)]
)
def test_list_events_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the list_events function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the list_events function against the expected output.
    """
    args = {
        "start_date": "1 month ago",
        "end_date": "now",
        "priority": "low",
        "sources": "dotnet",
        "tags": "test:123",
        "limit": "2",
    }
    new_raw = [Datadog(**obj) for obj in raw_resp.get("events")]
    DATADOG_API_CLIENT_MOCK.list_events.return_value = {"events": new_raw}
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.EventsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = get_events_command(configuration, args)
    with open(
        os.path.join("test_data", "readable_outputs/list_events_command_readable.md"),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected", [(EVENT_GET_RESPONSE, EVENT_GET_CONTEXT)]
)
def test_get_events_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the get_events_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the get_events_command function against the expected output.
    """
    args = {"event_id": "6995647921883593635"}
    new_raw = Datadog(**raw_resp.get("event"))
    DATADOG_API_CLIENT_MOCK.get_event.return_value = {"event": new_raw}
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.EventsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = get_events_command(configuration, args)
    with open(
        os.path.join("test_data", "readable_outputs/get_events_command_readable.md"),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected", [(HOST_TAG_CREATE_RESPONSE, HOST_TAG_CREATE_CONTEXT)]
)
def test_add_tags_to_host_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the add_tags_to_host_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the add_tags_to_host_command function against the expected output.
    """
    args = {
        "host_name": "DESKTOP-IIQVPJ7",
        "tags": "env:prod,environment:production12,environment:production13,region:east,source:my_apps,test:123",
    }

    DATADOG_API_CLIENT_MOCK.create_host_tags.return_value = raw_resp
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.TagsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = add_tags_to_host_command(configuration, args)
    with open(
        os.path.join(
            "test_data", "readable_outputs/add_tags_to_host_command_readable.md"
        ),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected", [(HOST_TAG_GET_RESPONSE, HOST_TAG_GET_CONTEXT)]
)
def test_get_host_tags_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the get_host_tags_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the get_host_tags_command function against the expected output.
    """
    args = {"host_name": "DESKTOP-IIQVPJ7"}

    DATADOG_API_CLIENT_MOCK.get_host_tags.return_value = HOST_TAG_GET_RESPONSE
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.TagsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = get_host_tags_command(configuration, args)
    with open(
        os.path.join("test_data", "readable_outputs/get_host_tags_command_readable.md"),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected", [(HOST_TAG_UPDATE_RESPONSE, HOST_TAG_UPDATE_CONTEXT)]
)
def test_update_host_tags_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the update_host_tags_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the update_host_tags_command function against the expected output.
    """
    args = {
        "host_name": "DESKTOP-IIQVPJ7",
        "tags": "env:prod,environment:production1234,environment:production1354,region:west,source:my_apps,test:123",
    }

    DATADOG_API_CLIENT_MOCK.update_host_tags.return_value = HOST_TAG_UPDATE_RESPONSE
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.TagsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = update_host_tags_command(configuration, args)
    with open(
        os.path.join(
            "test_data", "readable_outputs/update_host_tags_command_readable.md"
        ),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected", [(ACTIVE_METRIC_LIST_RESPONSE, ACTIVE_METRIC_LIST_CONTEXT)]
)
def test_active_metrics_list_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the active_metrics_list_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the active_metrics_list_command function against the expected output.
    """
    args = {"from": "2 days ago"}
    resp_obj = MetricsListResponse(
        _from=raw_resp.get("_from"), metrics=raw_resp.get("metrics")
    )
    DATADOG_API_CLIENT_MOCK.list_active_metrics.return_value = resp_obj
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.MetricsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = active_metrics_list_command(configuration, args)
    with open(
        os.path.join(
            "test_data", "readable_outputs/active_metrics_list_command_readable.md"
        ),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


# check readable output
@pytest.mark.parametrize(
    "raw_resp, expected", [(METRIC_SEARCH_RESPONSE, METRIC_SEARCH_CONTEXT)]
)
def test_metrics_search_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the metrics_search_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the metrics_search_command function against the expected output.
    """
    args = {"query": "datadog.agent.python.version"}
    resp_obj = MetricSearchResponse(
        results=MetricSearchResponseResults(metrics=raw_resp["results"]["metrics"])
    )
    DATADOG_API_CLIENT_MOCK.list_metrics.return_value = resp_obj
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.MetricsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = metrics_search_command(configuration, args)
    with open(
        os.path.join(
            "test_data", "readable_outputs/metrics_search_command_readable.md"
        ),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected", [(METRIC_METADATA_GET_RESPONSE, METRIC_METADATA_GET_CONTEXT)]
)
def test_get_metric_metadata_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the get_metric_metadata_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the get_metric_metadata_command function against the expected output.
    """
    args = {"metric_name": "datadog.agent.python.version"}

    resp_obj = MetricMetadata(**raw_resp)
    DATADOG_API_CLIENT_MOCK.get_metric_metadata.return_value = resp_obj
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.MetricsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = get_metric_metadata_command(configuration, args)
    with open(
        os.path.join(
            "test_data", "readable_outputs/get_metric_metadata_command_readable.md"
        ),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected",
    [(METRIC_METADATA_UPDATE_RESPONSE, METRIC_METADATA_UPDATE_CONTEXT)],
)
def test_update_metric_metadata_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the update_metric_metadata_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the update_metric_metadata_command function against the expected output.
    """
    args = {
        "metric_name": "datadog.agent.python.version",
        "description": "description",
        "per_unit": "instance",
        "short_name": "python",
        "statsd_interval": 60,
        "type": "gauge",
    }

    resp_obj = MetricMetadata(**raw_resp)
    DATADOG_API_CLIENT_MOCK.update_metric_metadata.return_value = resp_obj
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.MetricsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = update_metric_metadata_command(configuration, args)
    with open(
        os.path.join(
            "test_data", "readable_outputs/update_metric_metadata_command_readable.md"
        ),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected", [(TAGS_LIST_RESPONSE, TAGS_LIST_CONTEXT)]
)
def test_get_tags_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the get_tags_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the get_tags_command function against the expected output.
    """
    args = {
        "page": "1",
        "page_size": "50",
        "limit": "100",
        "source": "test",
    }
    DATADOG_API_CLIENT_MOCK.list_host_tags.return_value = raw_resp
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.TagsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = get_tags_command(configuration, args)
    with open(
        os.path.join("test_data", "readable_outputs/get_tags_command_readable.md"), "r"
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected",
    [(TIME_SERIES_POINT_QUERY_RESPONSE, TIME_SERIES_POINT_QUERY_CONTEXT)],
)
def test_query_timeseries_points_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the query_timeseries_points_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the query_timeseries_points_command function against the expected output.
    """
    args = {"from": "2 days ago", "query": "datadog.agent.running", "to": "now"}
    resp_obj = Datadog(**raw_resp)
    DATADOG_API_CLIENT_MOCK.query_metrics.return_value = resp_obj
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.MetricsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = query_timeseries_points_command(configuration, args)
    with open(
        os.path.join(
            "test_data", "readable_outputs/query_timeseries_points_command_readable.md"
        ),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result[0], CommandResults)
    assert isinstance(result[1], dict)
    assert result[0].readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected", [(None, "### Host tags deleted successfully!\n")]
)
def test_delete_host_tags_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the delete_host_tags_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the delete_host_tags_command function against the expected output.
    """
    args = {"host_name": "DESKTOP-IIQVPJ7"}
    DATADOG_API_CLIENT_MOCK.delete_host_tags.return_value = raw_resp
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.TagsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = delete_host_tags_command(configuration, args)
    assert isinstance(result, CommandResults)
    assert result.readable_output == expected


@pytest.mark.parametrize(
    "raw_resp, expected", [(None, "### Incident deleted successfully!\n")]
)
def test_delete_incident_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the delete_incident_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the delete_incident_command function against the expected output.
    """
    args = {"incident_id": "8d00d025-6d73-50f3-b93d-c9c3e40afce3"}
    DATADOG_API_CLIENT_MOCK.delete_incident.return_value = raw_resp
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.IncidentsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = delete_incident_command(configuration, args)
    assert isinstance(result, CommandResults)
    assert result.readable_output == expected


@pytest.mark.parametrize(
    "raw_resp, expected", [(CREATE_INCIDENT_RESPONSE, CREATE_INCIDENT_CONTEXT)]
)
def test_create_incident_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the create_incident_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the create_incident_command function against the expected output.
    """
    args = {
        "customer_impacted": False,
        "title": "Incident title",
        "content": "Incident content",
        "detection_method": "customer",
        "display_name": "datadog",
        "handle": "abc@domain.com",
        "important": True,
        "root_cause": "cause",
        "severity": "SEV-1",
        "state": "active",
        "summary": "summary",
    }
    resp_obj = Datadog(**raw_resp)
    DATADOG_API_CLIENT_MOCK.create_incident.return_value = resp_obj
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.IncidentsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = create_incident_command(configuration, args)
    with open(
        os.path.join(
            "test_data", "readable_outputs/create_incident_command_readable.md"
        ),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected", [(UPDATE_INCIDENT_RESPONSE, UPDATE_INCIDENT_CONTEXT)]
)
def test_update_incident_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the update_incident_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the update_incident_command function against the expected output.
    """
    args = {
        "customer_impact_end": "now",
        "customer_impact_scope": "impact scope",
        "customer_impact_start": "1 day ago",
        "customer_impacted": True,
        "detected": "now",
        "detection_method": "monitor",
        "display_name": "datadog",
        "handle": "xyz@domain.com",
        "root_cause": "the root cause",
        "severity": "SEV-2",
        "state": "active",
        "summary": "summary text",
        "title": "updated title",
    }
    resp_obj = Datadog(**raw_resp)
    DATADOG_API_CLIENT_MOCK.update_incident.return_value = resp_obj
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.IncidentsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = update_incident_command(configuration, args)
    with open(
        os.path.join(
            "test_data", "readable_outputs/update_incident_command_readable.md"
        ),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected", [(GET_INCIDENT_RESPONSE, GET_INCIDENT_CONTEXT)]
)
def test_get_incident_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the get_incident_command function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the get_incident_command function against the expected output.
    """
    args = {"incident_id": "37ad8b5b-b251-5d46-9978-2edbdac3cdb1"}
    resp_obj = Datadog(**raw_resp)
    DATADOG_API_CLIENT_MOCK.get_incident.return_value = resp_obj
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.IncidentsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = get_incident_command(configuration, args)
    with open(
        os.path.join("test_data", "readable_outputs/get_incident_command_readable.md"),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected", [(LIST_INCIDENT_RESPONSE, LIST_INCIDENT_CONTEXT)]
)
def test_list_incident_command(mocker, raw_resp, expected, configuration):
    """
    Test function for the incident list function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the incident list function against the expected output.
    """
    args = {"limit": 2}
    resp_obj = Datadog(**raw_resp)
    DATADOG_API_CLIENT_MOCK.search_incidents.return_value = resp_obj
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.IncidentsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = get_incident_command(configuration, args)
    with open(
        os.path.join("test_data", "readable_outputs/list_incident_command_readable.md"),
        "r",
    ) as f:
        readable_output = f.read()
    assert isinstance(result, CommandResults)
    assert result.outputs == expected
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_resp, expected", [(LIST_INCIDENT_RESPONSE, LIST_INCIDENT_CONTEXT)]
)
def test_fetch_incidents(mocker, raw_resp, expected, configuration):
    """
    Test function for the fetch_incidents function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the fetch_incidents function against the expected output.
    """
    args = {"first_fetch_time": "3 days", "fetch_limit": 50}
    resp_obj = Datadog(**raw_resp)
    mocker.patch.object(
        demisto, "getLastRun", return_value={"lastRun": "2023-04-27 10:41:04.316926"}
    )
    DATADOG_API_CLIENT_MOCK.search_incidents.return_value = resp_obj
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch("DatadogCloudSIEM.IncidentsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = fetch_incidents(configuration, args)
    assert result == "OK"


def test_test_module(mocker, configuration):
    """
    Test function for the test_module function in DatadogCloudSIEM.

    Args:
    mocker: The mocker object used for mocking API calls.
    raw_resp: The raw response to be returned by the mocked API call.
    expected: The expected result of the command.
    configuration: The configuration to be used for the command.

    Returns:
    None. The function asserts the output of the test_module function against the expected output.
    """
    DATADOG_API_CLIENT_MOCK.list_events.return_value = {}
    mocker.patch("DatadogCloudSIEM.ApiClient", return_value=DATADOG_API_CLIENT_MOCK)
    mocker.patch(
        "DatadogCloudSIEM.AuthenticationApi", return_value=DATADOG_API_CLIENT_MOCK
    )
    mocker.patch("DatadogCloudSIEM.EventsApi", return_value=DATADOG_API_CLIENT_MOCK)
    result = module_test(configuration)
    assert result == "ok"
    assert isinstance(result, str)


@pytest.mark.parametrize(
    "results, offset, limit, expected",
    [
        ([1, 2, 3, 4, 5], 0, 3, [1, 2, 3]),
        ([1, 2, 3, 4, 5], 2, 2, [3, 4]),
        ([1, 2, 3, 4, 5], 5, 10, []),
        ([], 0, 5, []),
    ],
)
def test_get_paginated_results(results, offset, limit, expected):
    """
    Test function for the get_paginated_results function in DatadogCloudSIEM.

    Args:
    results: The list of object.
    limit: Records per page.
    offset: The number of records to be skipped.
    expected: The expected result of the command.

    Returns:
    None. The function asserts the output of the get_paginated_results function against the expected output.
    """
    assert get_paginated_results(results, offset, limit) == expected


@pytest.mark.parametrize(
    "sub_context, page, page_size, expected",
    [
        ("Test", None, None, "Test"),
        (
            "Test",
            1,
            10,
            "Test List\nCurrent page size: 10\nShowing page 1 out of others that may exist",
        ),
        (
            "Test",
            2,
            20,
            "Test List\nCurrent page size: 20\nShowing page 2 out of others that may exist",
        ),
        ("Test", -1, 10, "Test"),
        ("Test", 1, -1, "Test"),
        ("Test", -1, -1, "Test"),
    ],
)
def test_table_header(sub_context, page, page_size, expected):
    """
    Test function for the table_header function in DatadogCloudSIEM.

    Args:
    sub_context: The sub-context of the results to display in the table header.
    page: The page number of the results.
    page_size: The number of results per page.
    expected: The expected result of the table_header function.

    Returns:
    None. The function asserts the output of the table_header function against the expected output.
    """
    assert table_header(sub_context, page, page_size) == expected


@pytest.mark.parametrize(
    "timestamp, time, expected",
    [
        (
            int((datetime.datetime.now() - datetime.timedelta(hours=12)).timestamp()),
            14,
            True,
        ),
        (
            int((datetime.datetime.now() - datetime.timedelta(hours=4)).timestamp()),
            6,
            True,
        ),
        (
            int((datetime.datetime.now() - datetime.timedelta(hours=2)).timestamp()),
            10,
            True,
        ),
        (
            int((datetime.datetime.now() - datetime.timedelta(hours=12)).timestamp()),
            1,
            False,
        ),
    ],
)
def test_is_within_time(timestamp, time, expected):
    """
    Test function for the is_within_time function in DatadogCloudSIEM.

    Args:
    timestamp: The timestamp to check if it's within the given time window.
    time: The time window to check against, in minutes.
    expected: The expected result of the is_within_time function.

    Returns:
    None. The function asserts the output of the is_within_time function against the expected output.
    """
    assert is_within_time(timestamp, time) == expected


@pytest.mark.parametrize("raw, expected", [(EVENT_MOCK, EXPECTED_EVENT_MOCK)])
def test_event_for_lookup(raw, expected):
    """
    Test function for the event_for_lookup function in DatadogCloudSIEM.

    Args:
    raw: The raw event data to be processed.
    expected: The expected output of the event_for_lookup function.

    Returns:
    None. The function asserts the output of the event_for_lookup function against the expected output.
    """
    assert event_for_lookup(raw) == expected


@pytest.mark.parametrize(
    "raw, expected", [(INCIDENT_LOOKUP_DATA, INCIDENT_LOOKUP_DATA_EXPECTED)]
)
def test_incident_for_lookup(raw, expected):
    """
    Test function for the incident_for_lookup function in DatadogCloudSIEM.

    Args:
    raw: The raw event data to be processed.
    expected: The expected output of the event_for_lookup function.

    Returns:
    None. The function asserts the output of the incident_for_lookup function against the expected output.
    """
    assert incident_for_lookup(raw) == expected


@pytest.mark.parametrize(
    "limit, page, page_size, expected",
    [
        (50, 1, 10, (10, 0)),
        (None, 2, 5, (5, 5)),
        (10, 3, None, (10, 100)),
        (20, 4, -1, DemistoException(PAGE_SIZE_ERROR_MSG)),
        (50, -1, -3, DemistoException(PAGE_NUMBER_ERROR_MSG)),
        (None, None, None, (DEFAULT_PAGE_SIZE, 0)),
    ],
)
def test_pagination(
    limit: Optional[int], page: Optional[int], page_size: Optional[int], expected
):
    """
    Test function for the pagination function in DatadogCloudSIEM.

    Args:
    limit: The maximum number of results to retrieve.
    page: The page number of the results to retrieve.
    page_size: The number of results per page.
    expected: The expected output of the pagination function.
    If an exception is expected, the value should be an Exception object.

    Returns:
    None. The function asserts the output of the pagination function against the expected output.
    """
    if isinstance(expected, Exception):
        with pytest.raises(DemistoException):
            pagination(limit, page, page_size)
    else:
        assert pagination(limit, page, page_size) == expected


@pytest.mark.parametrize(
    "raw, metric_name, expected",
    [(METRIC_COMMAND_RESULT_INPUT, "system.cpu.idle", METRIC_COMMAND_RESULT_OUTPUT)],
)
def test_metric_command_results(raw, metric_name, expected):
    """
    Test function for the 'metric_command_results' function.

    Args:
        raw (dict): A dictionary of Datadog API credentials.
        metric_name (str): The name of the metric to search for.
        expected (Any): The expected result of the function.

    Raises:
        AssertionError: If the result of the function is not an instance of CommandResults, or if the
        'Contents' key of the result's context dictionary is not equal to the expected value.

    Returns:
        None
    """
    result = metric_command_results(Datadog(**raw), metric_name)
    assert isinstance(result, CommandResults)
    assert result.to_context()["Contents"] == expected


@pytest.mark.parametrize(
    "raw, expected",
    [
        (
            {"date": datetime.datetime(2022, 4, 13, 12, 0, 0)},
            {'date': '2022-04-13T12:00:00+00:00'},
        ),
        (
            {
                "date1": datetime.datetime(2022, 4, 13, 12, 0, 0),
                "date2": datetime.datetime(2022, 4, 14, 12, 0, 0),
            },
            {'date1': '2022-04-13T12:00:00+00:00', 'date2': '2022-04-14T12:00:00+00:00'},
        ),
        ({"name": "John", "age": 30}, {"name": "John", "age": 30}),
        (
            {
                "date": datetime.datetime(2022, 4, 13, 12, 0, 0),
                "nested": {"date": datetime.datetime(2022, 4, 14, 12, 0, 0)},
            },
            {'date': '2022-04-13T12:00:00+00:00',
             'nested': {'date': '2022-04-14T12:00:00+00:00'}},
        ),
    ],
)
def test_convert_datetime_to_str(raw, expected):
    """
    Test the `convert_datetime_to_str` function with the given datetime object and expected string value.
    The function should convert the datetime object to a string in ISO 8601 format and
    return the expected string.

    :param raw: The datetime object to be converted to a string.
    :type raw: datetime
    :param expected: The expected string value of the converted datetime object.
    :type expected: str
    """
    assert convert_datetime_to_str(raw) == expected


@pytest.mark.parametrize(
    "raw, expected", [(HOST_TAG_CREATE_RESPONSE, TAGS_CONTEXT_READABLE_OUTPUT)]
)
def test_tags_context_and_readable_output(raw, expected):
    """
    Test the `tags_context_and_readable_output` function with the given raw data and
    expected results. The function should parse the input data, create a context object
    and a readable output object with the appropriate format, and return a dictionary
    that matches the expected value.

    :param raw: A dictionary containing raw data to be parsed and formatted.
    :type raw: dict
    :param expected: The expected output of the function, as a dictionary.
    :type expected: dict
    """
    assert tags_context_and_readable_output(raw) == expected
