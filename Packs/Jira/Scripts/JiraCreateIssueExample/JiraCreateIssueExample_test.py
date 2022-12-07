from JiraCreateIssueExample import \
    DATE_FORMAT \
    , validate_date_field \
    # , parse_custom_fields \
    # , add_custom_fields \
    # , rm_custom_field_from_args
import pytest


@pytest.mark.parametrize("due_date", [
    ("2022-01-01"),
    ("2022-12-12T13:00:00")
])
def test_validate_date_field_data_remains(due_date):

    try:
        validate_date_field(due_date)
    except ValueError as ve:
        assert "unconverted data remains" in str(ve)


@pytest.mark.parametrize("due_date", [
    ("2022-01-01"),
    ("2022-31-31")
])
def test_validate_date_field_format(due_date):

    try:
        validate_date_field(due_date)
    except ValueError as ve:
        assert f"time data '{due_date}' does not match format '{DATE_FORMAT}'" in str(ve)

