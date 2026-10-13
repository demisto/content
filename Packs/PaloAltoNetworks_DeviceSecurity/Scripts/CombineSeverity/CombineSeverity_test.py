from typing import Any

import pytest
from pytest_mock import MockerFixture

import CombineSeverity


@pytest.mark.parametrize(
    "value,expected",
    [
        ({"severity": "info", "display_severity": "low"}, "info / low"),
        ({"severity": "critical", "display_severity": "high"}, "critical / high"),
        ({"severity": "medium"}, "medium / N/A"),
        ({"display_severity": "low"}, "N/A / low"),
        ({"severity": "", "display_severity": None}, "N/A / N/A"),
        ({}, "N/A / N/A"),
    ],
)
def test_main_formats_severity(mocker: MockerFixture, value: dict, expected: str) -> None:
    mocker.patch.object(CombineSeverity.demisto, "args", return_value={"value": value})
    results = mocker.patch.object(CombineSeverity, "return_results")

    CombineSeverity.main()

    results.assert_called_once_with(expected)


@pytest.mark.parametrize("value", [None, "high", [], 3])
def test_main_rejects_non_object_input(mocker: MockerFixture, value: Any) -> None:
    mocker.patch.object(CombineSeverity.demisto, "args", return_value={"value": value})
    error = mocker.patch.object(CombineSeverity, "return_error", side_effect=ValueError("Invalid input"))
    results = mocker.patch.object(CombineSeverity, "return_results")

    with pytest.raises(ValueError, match="Invalid input"):
        CombineSeverity.main()

    error.assert_called_once_with("CombineSeverity requires the object containing severity and display_severity.")
    results.assert_not_called()
