"""PrometheusClient for Cortex XSOAR - Unit Tests file"""

from CommonServerPython import Optional
import Packs.Prometheus.Integrations.Prometheus.Prometheus as mod
import pytest
import json


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


class TestClient(mod.PrometheusClient):
    def __init__(self, response=None, raise_exc: Exception = None):
        self._response = response
        self._raise = raise_exc
        self.timeout = 30

    def instant_query(self, query: str, at_time: Optional[str] = None):
        if self._raise:
            raise self._raise
        self._last_query = query
        self._last_time = at_time
        return self._response


@pytest.fixture
def sample_vector_response():
    # Matches Prometheus /api/v1/query vector response shape
    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {"metric": {"__name__": "co2", "host": "wattle"}, "value": [str(1_700_000_000), "412.7"]},
                {"metric": {"__name__": "temperature", "room": "garage"}, "value": [str(1_700_000_005), "23.1"]},
            ],
        },
    }


@pytest.fixture
def sample_empty_vector_response():
    return {"status": "success", "data": {"resultType": "vector", "result": []}}


@pytest.fixture
def sample_error_response():
    return {"status": "error", "errorType": "bad_data", "error": "parse error"}


def test_build_name_regex_anchor_true():
    regex = mod.build_name_regex("co2| solar |load", anchor=True)
    assert regex == "^(co2|solar|load)$"


def test_build_name_regex_anchor_false():
    regex = mod.build_name_regex("co2|solar|load", anchor=False)
    assert regex == "co2|solar|load"


def test_build_name_regex_empty_raises():
    with pytest.raises(ValueError):
        mod.build_name_regex("   ||  |  ", anchor=True)


def test_format_result_rows_parses_vector(sample_vector_response):
    rows = mod.format_result_rows(sample_vector_response)
    assert len(rows) == 2

    # Row 1 checks
    r0 = rows[0]
    assert r0["name"] == "co2"
    assert isinstance(r0["value"], float)
    assert r0["value"] == pytest.approx(412.7)
    assert r0["labels"] == {"host": "wattle"}
    assert r0["ts_unix"] == 1_700_000_000
    # ISO 8601 with UTC tz
    assert r0["ts"].endswith("+00:00")

    # Row 2 checks
    r1 = rows[1]
    assert r1["name"] == "temperature"
    assert r1["labels"] == {"room": "garage"}
    assert r1["ts_unix"] == 1_700_000_005


def test_format_result_rows_non_vector_type_returns_empty():
    non_vector = {"status": "success", "data": {"resultType": "matrix", "result": []}}
    rows = mod.format_result_rows(non_vector)
    assert rows == []


def test_prometheus_query_builds_query_from_fields(sample_vector_response):
    client = TestClient(response=sample_vector_response)
    args = {"fields": "co2|temperature", "anchor": "true", "time": "2025-09-03T09:00:00Z"}

    response = mod.prometheus_query_command(client, args, default_fields=None)
    assert client._last_query == '{__name__=~"^(co2|temperature)$"}'
    assert client._last_time == "2025-09-03T09:00:00Z"
    assert response.outputs_prefix == "Prometheus.Metrics"
    assert isinstance(response.outputs, list)
    assert len(response.outputs) == 2
    assert {r["name"] for r in response.outputs} == {"co2", "temperature"}


def test_prometheus_query_uses_default_fields_when_not_in_args(sample_vector_response):
    client = TestClient(response=sample_vector_response)
    args = {"anchor": "false"}
    default_fields = "co2|temperature"
    response = mod.prometheus_query_command(client, args, default_fields=default_fields)

    assert client._last_query == '{__name__=~"co2|temperature"}'
    assert len(response.outputs) == 2


def test_prometheus_query_uses_raw_query_when_provided(sample_vector_response):
    client = TestClient(response=sample_vector_response)
    args = {"query": '{__name__=~"(co2|temperature)"}', "time": "1700000000"}
    response = mod.prometheus_query_command(client, args, default_fields=None)
    assert client._last_query == '{__name__=~"(co2|temperature)"}'
    assert client._last_time == "1700000000"
    assert len(response.outputs) == 2


def test_prometheus_query_raises_when_no_fields_and_no_default():
    client = TestClient(response={"status": "success", "data": {"resultType": "vector", "result": []}})
    with pytest.raises(mod.DemistoException) as exc:
        mod.prometheus_query_command(client, args={}, default_fields=None)
    assert 'You must provide "fields"' in str(exc.value)


def test_prometheus_query_raises_on_api_error(sample_error_response):
    client = TestClient(response=sample_error_response)
    with pytest.raises(mod.DemistoException) as exc:
        mod.prometheus_query_command(client, args={"fields": "co2"}, default_fields=None)
    assert "Prometheus API error" in str(exc.value)


def test_prometheus_raw_happy_path(sample_vector_response):
    client = TestClient(response=sample_vector_response)
    response = mod.prometheus_raw_command(client, args={"query": "vector(1)"})
    assert client._last_query == "vector(1)"
    assert len(response.outputs) == 2
    names = {r["name"] for r in response.outputs}
    assert "co2" in names
    assert "temperature" in names


def test_prometheus_raw_requires_query_arg():
    client = TestClient(response={"status": "success", "data": {"resultType": "vector", "result": []}})
    with pytest.raises(mod.DemistoException):
        mod.prometheus_raw_command(client, args={})


def test_prometheus_raw_raises_on_api_error(sample_error_response):
    client = TestClient(response=sample_error_response)
    with pytest.raises(mod.DemistoException):
        mod.prometheus_raw_command(client, args={"query": "up"})


def test_test_module_ok():
    client = TestClient(response={"status": "success", "data": {"resultType": "vector", "result": []}})
    assert mod.test_module(client) == "ok"


def test_test_module_failure_message():
    client = TestClient(response={"status": "error", "error": "boom"})
    assert mod.test_module(client).startswith("Failed:")


def test_test_module_exception_is_caught():
    client = TestClient(response=None, raise_exc=RuntimeError("network down"))
    out = mod.test_module(client)
    assert out.startswith("Failed:")
    assert "network down" in out
