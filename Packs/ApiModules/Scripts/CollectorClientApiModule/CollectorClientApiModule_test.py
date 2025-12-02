from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import importlib.util
import sys
import types

ROOT = Path(__file__).resolve().parents[4]
sys.path.append(str(ROOT / "Tests"))
sys.path.append(str(ROOT / "Packs" / "Base" / "Scripts" / "CommonServerPython"))
sys.path.append(str(ROOT / "Packs" / "Base" / "Scripts" / "CommonServerUserPython"))
sys.path.append(str(ROOT / "Packs" / "ApiModules" / "Scripts" / "DemistoClassApiModule"))

sys.modules.setdefault("CommonServerUserPython", types.ModuleType("CommonServerUserPython"))


def _load_demisto_mock():
    module_path = ROOT / "Tests" / "demistomock" / "demistomock.py"
    spec = importlib.util.spec_from_file_location("demistomock", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    sys.modules["demistomock"] = module
    return module


import pytest
import respx
from httpx import Response

demisto = _load_demisto_mock()
from CollectorClientApiModule import (
    APIKeyAuthHandler,
    CollectorBlueprint,
    CollectorClient,
    CollectorRequest,
    CollectorState,
    PaginationConfig,
    RateLimitPolicy,
    RetryPolicy,
    TimeoutSettings,
)


@pytest.fixture(autouse=True)
def integration_context(mocker):
    store: Dict[str, Any] = {}

    def get_context():
        return json.loads(json.dumps(store))

    def set_context(value: Dict[str, Any]):
        store.clear()
        store.update(value)

    mocker.patch.object(demisto, "getIntegrationContext", side_effect=get_context)
    mocker.patch.object(demisto, "setIntegrationContext", side_effect=set_context)
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    yield store


def build_blueprint(**kwargs) -> CollectorBlueprint:
    base_request = kwargs.pop("request")
    defaults = dict(
        name="TestCollector",
        base_url="https://api.example.com",
        auth_handler=kwargs.pop("auth_handler", None),
        retry_policy=RetryPolicy(max_attempts=3, initial_delay=0.01, max_delay=0.02),
        rate_limit=RateLimitPolicy(rate_per_second=0.0),
        timeout=TimeoutSettings(execution=30),
        default_strategy="sequential",
    )
    defaults.update(kwargs)
    return CollectorBlueprint(request=base_request, **defaults)


@respx.mock
def test_api_key_auth_header():
    route = respx.get("https://api.example.com/v1/events").mock(
        return_value=Response(200, json={"data": {"events": []}, "meta": {"next_cursor": None}})
    )

    request = CollectorRequest(endpoint="/v1/events", data_path="data.events")
    blueprint = build_blueprint(request=request, auth_handler=APIKeyAuthHandler("secret", header_name="X-Key"))
    client = CollectorClient(blueprint)

    result = client.collect_events_sync()

    assert route.called
    sent_headers = route.calls[0].request.headers
    assert sent_headers["X-Key"] == "secret"
    assert result.metrics.success == 1


@respx.mock
def test_retry_logic_on_429():
    responses = [
        Response(429, json={"error": "Too Many"}),
        Response(200, json={"data": {"events": [{"id": 1}]}, "meta": {"next_cursor": None}}),
    ]
    respx.get("https://api.example.com/v1/events").mock(side_effect=responses)

    request = CollectorRequest(endpoint="/v1/events", data_path="data.events")
    blueprint = build_blueprint(request=request)
    client = CollectorClient(blueprint)

    result = client.collect_events_sync(strategy="sequential")

    assert len(result.events) == 1
    assert client.metrics.quota_error == 1
    assert client.metrics.retry_error == 1


@respx.mock
def test_cursor_pagination_state_persistence(integration_context):
    respx.get("https://api.example.com/v1/events").mock(
        side_effect=[
            Response(200, json={"data": {"events": [{"id": 1}]}, "meta": {"next_cursor": "abc"}}),
            Response(200, json={"data": {"events": [{"id": 2}]}, "meta": {"next_cursor": None}}),
        ]
    )

    pagination = PaginationConfig(
        mode="cursor",
        cursor_param="cursor",
        next_cursor_path="meta.next_cursor",
        page_size=1,
        page_size_param="limit",
    )
    request = CollectorRequest(endpoint="/v1/events", data_path="data.events", pagination=pagination, params={"limit": 1})
    blueprint = build_blueprint(request=request)
    client = CollectorClient(blueprint)

    result = client.collect_events_sync()

    assert [event["id"] for event in result.events] == [1, 2]
    stored_state = integration_context["collector_client"]["TestCollector"]["/v1/events"]
    assert stored_state["cursor"] is None


@respx.mock
def test_concurrent_shards_collect_in_parallel():
    def responder(request):
        region = request.url.params.get("region", "default")
        payload = {
            "default": {"data": {"events": [{"id": "default"}]}, "meta": {"next_cursor": None}},
            "us": {"data": {"events": [{"id": "us"}]}, "meta": {"next_cursor": None}},
            "eu": {"data": {"events": [{"id": "eu"}]}, "meta": {"next_cursor": None}},
        }[region]
        return Response(200, json=payload)

    route = respx.get("https://api.example.com/v1/events").mock(side_effect=responder)

    request = CollectorRequest(
        endpoint="/v1/events",
        data_path="data.events",
        shards=[
            {"params": {"region": "us"}, "state_key": "events-us"},
            {"params": {"region": "eu"}, "state_key": "events-eu"},
        ],
    )
    blueprint = build_blueprint(request=request, default_strategy="concurrent")
    client = CollectorClient(blueprint)

    result = client.collect_events_sync()

    ids = sorted(event["id"] for event in result.events)
    assert ids == ["default", "eu", "us"]
    assert route.call_count == 3
    metadata = result.state.metadata["requests"]
    assert set(metadata.keys()) == {"events-us", "events-eu", "/v1/events"}


@respx.mock
def test_resume_from_state_snapshot():
    state = CollectorState(
        metadata={
            "requests": {
                "/v1/events": {
                    "cursor": "next-cursor",
                    "page": None,
                    "offset": None,
                    "last_event_id": None,
                    "partial_results": [],
                    "metadata": {},
                }
            }
        }
    )

    pagination = PaginationConfig(mode="cursor", cursor_param="cursor", next_cursor_path="meta.next")
    request = CollectorRequest(endpoint="/v1/events", data_path="data.events", pagination=pagination)
    blueprint = build_blueprint(request=request)
    client = CollectorClient(blueprint)

    route = respx.get("https://api.example.com/v1/events").mock(
        return_value=Response(200, json={"data": {"events": []}, "meta": {"next": None}})
    )

    client.collect_events_sync(resume_state=state)

    assert route.called
    sent_params = dict(route.calls[0].request.url.params)
    assert sent_params["cursor"] == "next-cursor"

