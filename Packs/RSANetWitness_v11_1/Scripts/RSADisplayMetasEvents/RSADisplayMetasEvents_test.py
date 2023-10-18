import pytest
from RSADisplayMetasEvents import CamelCaseToDotCase, display_metas


def test_CamelCaseToDotCase():
    assert CamelCaseToDotCase("eventSource") == "event.source"


@pytest.mark.parametrize(
    "alerts_incident, expected_results",
    [
        ({"CustomFields": {"rsametasevents": [{"ip": "ip", "host": "host"}]}},
         {'Contents': '|ip|host|\n|---|---|\n| ip | host |\n', 'ContentsFormat': 'markdown', 'Type': 1}),
    ],
)
def test_display_metas(
    mocker, alerts_incident, expected_results
):
    mocker.patch(
        "RSADisplayMetasEvents.demisto.incident", return_value=alerts_incident
    )
    assert display_metas() == expected_results
