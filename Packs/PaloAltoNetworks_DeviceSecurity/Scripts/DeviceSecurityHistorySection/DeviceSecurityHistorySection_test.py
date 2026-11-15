import json
from typing import Any

from pytest_mock import MockerFixture

import pytest
import DeviceSecurityHistorySection as script


@pytest.mark.parametrize("history", [None, [], "", "  ", "[]", "null"])
def test_empty_history(history: Any) -> None:
    assert script.render_history(history) == "No detection or resolution history available."


@pytest.mark.parametrize("encode", [False, True])
def test_render_history(encode: bool) -> None:
    events = [{"action": "resolved", "reason": "a|b\r\nc", "evidence": {"verified": True}, "system_event": False}]
    rendered = script.render_history(json.dumps(events) if encode else events)
    assert "resolved" in rendered
    assert r"a\|b  c" in rendered
    assert '{"verified": true}' in rendered
    assert "false" in rendered
    assert len(rendered.splitlines()) == 3


def test_single_event() -> None:
    assert "detected" in script.render_history({"action": "detected"})


@pytest.mark.parametrize("history", ["invalid JSON", 42, False, ["invalid"]])
def test_invalid_history(history: Any) -> None:
    with pytest.raises(ValueError):
        script.render_history(history)


def test_main(mocker: MockerFixture) -> None:
    mocker.patch.object(
        script.demisto, "incidents", return_value=[{"CustomFields": {"reasonhistory": '[{"action":"resolved"}]'}}]
    )
    results = mocker.patch.object(script, "return_results")
    script.main()
    assert "resolved" in results.call_args.args[0].readable_output


def test_main_invalid_history(mocker: MockerFixture) -> None:
    mocker.patch.object(script.demisto, "incidents", return_value=[{"CustomFields": {"reasonhistory": "bad JSON"}}])
    error = mocker.patch.object(script, "return_error")
    script.main()
    assert error.call_args.args[0].startswith("Failed to display detection and resolution history:")


def test_main_without_incident(mocker: MockerFixture) -> None:
    mocker.patch.object(script.demisto, "incidents", return_value=[])
    results = mocker.patch.object(script, "return_results")
    script.main()
    assert "No detection" in results.call_args.args[0].readable_output
