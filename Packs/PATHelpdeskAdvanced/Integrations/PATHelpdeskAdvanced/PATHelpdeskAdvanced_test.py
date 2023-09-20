from PATHelpdeskAdvanced import convert_response_dates, paginate, Field
import pytest
from datetime import datetime


@pytest.mark.parametrize(
    "kwargs, expected_start, expected_limit",
    [
        ({"limit": 10}, 0, 10),
        ({"page": 2, "page_size": 20, "limit": 30}, 40, 20),
    ],
)
def test_paginate(kwargs, expected_start, expected_limit):
    """
    Given the keyword arguments `kwargs`, `expected_start`, and `expected_limit`.
    When the `paginate` function is called with the provided keyword arguments.
    Then the result of the pagination should have the expected values.
    """
    result = paginate(**kwargs)
    assert result.start == expected_start
    assert result.limit == expected_limit


@pytest.mark.parametrize(
    "demisto_name, expected_demisto_name, expected_hda_name",
    [
        ("incident_id", "incident_id", "IncidentID"),
        ("unread_email_html", "unread_email_html", "UnReadEmailHTML"),
        ("task", "task", "Task"),
        ("unread", "unread", "UnRead"),
        ("user_id_html", "user_id_html", "UserIDHTML"),
    ],
)
def test_field(demisto_name, expected_demisto_name, expected_hda_name):
    """
    Given a Demisto name, when initializing an instance of MyClass,
    then the demisto_name attribute should be set to the given Demisto name,
    and the hda_name attribute should be set to the expected HDA name.

    Args:
        demisto_name (str): The Demisto name.
        expected_demisto_name (str): The expected value of the demisto_name attribute.
        expected_hda_name (str): The expected value of the hda_name attribute.

    Returns:
        None
    """
    field = Field(demisto_name)
    assert field.demisto_name == expected_demisto_name
    assert field.hda_name == expected_hda_name


def test_converts_date_fields():
    """
    Given a response dict with date fields
    When convert_response_dates is called
    Then date fields are converted to datetime, and others are untouched
    """
    EPOCH_2023_INT = 1693573200000
    EPOCH_2022_INT = 1641042000000

    STR_2023 = str(datetime.fromtimestamp(EPOCH_2023_INT / 1000))
    STR_2022 = str(datetime.fromtimestamp(EPOCH_2022_INT / 1000))

    raw = {
        "Date1": f"/Date({EPOCH_2023_INT})/",
        "Date2": [f"/Date({EPOCH_2023_INT})/", f"/Date({EPOCH_2022_INT})/", "🕒"],
        "other": [EPOCH_2023_INT, STR_2023]
    }

    result = convert_response_dates(raw)

    assert result["Date1"] == STR_2023
    assert result["Date2"] == [STR_2023, STR_2022, "🕒"]
    assert result["other"] == raw["other"]
