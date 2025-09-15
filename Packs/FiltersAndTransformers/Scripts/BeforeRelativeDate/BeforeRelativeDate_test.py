import pytest
from BeforeRelativeDate import check_date

TEST_INPUTS = [
    ("2025-09-12T12:00:00", "1 day ago", True, "sanity 1"),
    ("2025-09-12T12:00:00", "19 years ago", False, "sanity 2"),
]


@pytest.mark.parametrize("left, right, expected_result, test_title", TEST_INPUTS)
def test_check_date(left, right, expected_result, test_title):
    assert check_date(left, right) == expected_result, test_title
