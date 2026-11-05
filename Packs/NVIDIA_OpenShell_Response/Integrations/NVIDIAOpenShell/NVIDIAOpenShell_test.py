"""Unit tests for the NVIDIA OpenShell integration.

The SDK client and the generated gRPC stub are replaced with mocks. Real protobuf messages
are used for responses, so field names are checked against the SDK in the Docker image.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import grpc
import pytest
from CommonServerPython import DemistoException
from openshell._proto import datamodel_pb2, openshell_pb2, sandbox_pb2

import NVIDIAOpenShell as integration
from NVIDIAOpenShell import (
    COMMANDS,
    Client,
    egress_block_host_command,
    format_error,
    gateway_info_command,
    normalize_pem,
    phase_name,
    policy_binary_remove_command,
    policy_endpoint_remove_command,
    policy_get_command,
    policy_history_command,
    policy_rule_remove_command,
    provider_detach_command,
    provider_list_command,
    sandbox_delete_command,
    sandbox_get_command,
    sandbox_lifecycle_command,
    sandbox_list_command,
    sandbox_logs_command,
    test_module as run_test_module,
)

READY = openshell_pb2.SandboxPhase.Value("SANDBOX_PHASE_READY")
STOPPED = openshell_pb2.SandboxPhase.Value("SANDBOX_PHASE_STOPPED")


def make_ref(name="agent-1", phase=READY, version=3):
    return SimpleNamespace(
        id=f"id-{name}", name=name, workspace="default", phase=phase, current_policy_version=version, labels={"team": "ml"}
    )


def make_policy():
    policy = sandbox_pb2.SandboxPolicy()
    rule = policy.network_policies["agent_egress"]
    ep = rule.endpoints.add()
    ep.host = "files.example.com"
    ep.ports.extend([443, 8443])
    ep.protocol = "https"
    rule.binaries.add().path = "/usr/bin/curl"
    other = policy.network_policies["model_api"]
    other.endpoints.add(host="api.example.com", port=443)
    return policy


@pytest.fixture
def client(mocker):
    mocker.patch.object(integration, "SandboxClient")
    c = Client(endpoint="https://127.0.0.1:17670", workspace="default", timeout=10, plaintext=True)
    c.sdk = MagicMock()
    c.stub = MagicMock()
    return c


def test_client_strips_scheme_and_writes_tls_files(mocker, tmp_path):
    sdk_cls = mocker.patch.object(integration, "SandboxClient")
    tls_cls = mocker.patch.object(integration, "TlsConfig")
    pem = "-----BEGIN CERTIFICATE-----" + "A" * 100 + "-----END CERTIFICATE-----"
    c = Client(endpoint="https://gw:17670/", workspace="", timeout=5, ca_cert=pem, client_cert=pem, client_key=pem)
    assert c.endpoint == "gw:17670"
    assert c.workspace == "default"
    kwargs = tls_cls.call_args.kwargs
    for key in ("ca_path", "cert_path", "key_path"):
        content = kwargs[key].read_text()
        assert content.startswith("-----BEGIN CERTIFICATE-----\n")
        assert (kwargs[key].stat().st_mode & 0o777) == 0o600
    assert sdk_cls.call_args.args[0] == "gw:17670"


def test_client_plaintext_has_no_tls(mocker):
    sdk_cls = mocker.patch.object(integration, "SandboxClient")
    Client(endpoint="gw:1", workspace="ws", timeout=5, plaintext=True, bearer_token="tok")
    assert sdk_cls.call_args.kwargs["tls"] is None
    assert sdk_cls.call_args.kwargs["bearer_token"] == "tok"


@pytest.mark.parametrize(
    "raw, expected_lines",
    [
        ("-----BEGIN CERTIFICATE-----  " + "B" * 70 + " -----END CERTIFICATE-----", 4),
        ("no pem here", 1),
        ("", 1),
    ],
)
def test_normalize_pem(raw, expected_lines):
    assert len(normalize_pem(raw).strip("\n").split("\n")) == expected_lines


def test_phase_name():
    assert phase_name(READY) == "READY"
    assert phase_name(9999) == "9999"


def test_test_module(client):
    assert run_test_module(client) == "ok"
    client.sdk.health.assert_called_once()
    assert isinstance(client.stub.GetGatewayInfo.call_args.args[0], openshell_pb2.GetGatewayInfoRequest)


def test_gateway_info(client):
    client.sdk.health.return_value = SimpleNamespace(version="0.1.7")
    client.stub.GetGatewayInfo.return_value = openshell_pb2.GetGatewayInfoResponse()
    res = gateway_info_command(client, {})
    assert res.outputs["Version"] == "0.1.7"
    assert res.outputs["Endpoint"] == "127.0.0.1:17670"


def test_sandbox_list_uses_workspace_and_limit(client):
    client.sdk.list_all.return_value = [make_ref("a"), make_ref("b"), make_ref("c")]
    res = sandbox_list_command(client, {"workspace": "ml", "label_selector": "team=ml", "limit": "2"})
    client.sdk.list_all.assert_called_once_with(workspace="ml", label_selector="team=ml")
    assert [r["Name"] for r in res.outputs] == ["a", "b"]
    assert res.outputs[0]["Phase"] == "READY"


def test_sandbox_list_all_workspaces(client):
    client.sdk.list_all_for_all_workspaces.return_value = [make_ref()]
    sandbox_list_command(client, {"all_workspaces": "true"})
    client.sdk.list_all_for_all_workspaces.assert_called_once_with(label_selector=None)
    client.sdk.list_all.assert_not_called()


def test_sandbox_get(client):
    client.sdk.get.return_value = make_ref("agent-1")
    res = sandbox_get_command(client, {"name": "agent-1"})
    client.sdk.get.assert_called_once_with("agent-1", workspace="default")
    assert res.outputs["ID"] == "id-agent-1"


def test_sandbox_stop_waits_and_refreshes(client):
    client.sdk.stop.return_value = make_ref(phase=READY)
    client.sdk.get.return_value = make_ref(phase=STOPPED)
    res = sandbox_lifecycle_command(client, {"name": "agent-1", "timeout_seconds": "30"}, "stop")
    client.sdk.wait_stopped.assert_called_once_with("agent-1", workspace="default", timeout_seconds=30)
    assert res.outputs["Phase"] == "STOPPED"
    assert res.outputs["Action"] == "stop"


def test_sandbox_stop_no_wait(client):
    client.sdk.stop.return_value = make_ref(phase=READY)
    sandbox_lifecycle_command(client, {"name": "agent-1", "wait": "false"}, "stop")
    client.sdk.wait_stopped.assert_not_called()


@pytest.mark.parametrize("action", ["start", "suspend", "resume"])
def test_sandbox_other_lifecycle(client, action):
    getattr(client.sdk, action).return_value = make_ref()
    res = sandbox_lifecycle_command(client, {"name": "agent-1"}, action)
    getattr(client.sdk, action).assert_called_once_with("agent-1", workspace="default")
    assert res.outputs["Action"] == action


def test_sandbox_lifecycle_unknown_action(client):
    with pytest.raises(DemistoException):
        sandbox_lifecycle_command(client, {"name": "agent-1"}, "explode")


def test_sandbox_delete_requires_confirm(client):
    with pytest.raises(DemistoException, match="confirm=yes"):
        sandbox_delete_command(client, {"name": "agent-1", "confirm": "no"})
    client.sdk.delete.assert_not_called()


def test_sandbox_delete(client):
    client.sdk.delete.return_value = SimpleNamespace(sandbox_id="id-1", outcome=SimpleNamespace(name="DELETED"))
    res = sandbox_delete_command(client, {"name": "agent-1", "confirm": "yes", "allow_missing": "true"})
    client.sdk.delete.assert_called_once_with("agent-1", workspace="default", allow_missing=True)
    assert res.outputs["Outcome"] == "DELETED"


def test_sandbox_logs(client):
    resp = openshell_pb2.GetSandboxLogsResponse()
    line = resp.logs.add(level="WARN", source="network", target="egress", message="denied files.example.com:443")
    line.event_time.FromJsonString("2026-11-04T10:00:00Z")
    client.stub.GetSandboxLogs.return_value = resp
    res = sandbox_logs_command(client, {"name": "agent-1", "lines": "5", "min_level": "WARN", "sources": "network,process"})
    req = client.stub.GetSandboxLogs.call_args.args[0]
    assert req.sandbox == "agent-1"
    assert req.lines == 5
    assert list(req.sources) == ["network", "process"]
    assert req.workspace_scope == datamodel_pb2.WorkspaceSelector(workspace="default")
    assert res.outputs[0]["Message"] == "denied files.example.com:443"
    assert res.outputs[0]["Time"] == "2026-11-04T10:00:00Z"


def test_policy_get(client):
    client.stub.GetSandboxConfig.return_value = sandbox_pb2.GetSandboxConfigResponse(
        policy=make_policy(), version=4, policy_hash="h4"
    )
    res = policy_get_command(client, {"name": "agent-1"})
    rules = {r["Rule"]: r for r in res.outputs["NetworkRules"]}
    assert rules["agent_egress"]["Ports"] == [443, 8443]
    assert rules["agent_egress"]["Binaries"] == ["/usr/bin/curl"]
    assert rules["model_api"]["Ports"] == [443]
    assert res.outputs["Version"] == 4


def test_policy_history(client):
    resp = openshell_pb2.ListSandboxPoliciesResponse()
    resp.revisions.add(version=4, policy_hash="h4")
    client.stub.ListSandboxPolicies.return_value = resp
    res = policy_history_command(client, {"name": "agent-1", "limit": "5"})
    assert client.stub.ListSandboxPolicies.call_args.args[0].page_size == 5
    assert res.outputs[0]["Version"] == 4


def _assert_merge_request(client, field):
    req = client.stub.UpdateConfig.call_args.args[0]
    assert req.sandbox == "agent-1"
    assert req.request_id
    assert req.annotations["cortex.reason"] == "case 42"
    assert req.merge_operations[0].WhichOneof("operation") == field
    return req.merge_operations[0]


def test_policy_rule_remove(client):
    client.stub.UpdateConfig.return_value = openshell_pb2.UpdateConfigResponse(version=5, policy_hash="h5")
    res = policy_rule_remove_command(client, {"name": "agent-1", "rule_name": "agent_egress", "reason": "case 42"})
    op = _assert_merge_request(client, "remove_rule")
    assert op.remove_rule.rule_name == "agent_egress"
    assert res.outputs["NewVersion"] == 5


def test_policy_endpoint_remove(client):
    client.stub.UpdateConfig.return_value = openshell_pb2.UpdateConfigResponse(version=5)
    policy_endpoint_remove_command(
        client, {"name": "agent-1", "rule_name": "r", "host": "h.example.com", "port": "443", "reason": "case 42"}
    )
    op = _assert_merge_request(client, "remove_endpoint")
    assert (op.remove_endpoint.host, op.remove_endpoint.port) == ("h.example.com", 443)


def test_policy_binary_remove(client):
    client.stub.UpdateConfig.return_value = openshell_pb2.UpdateConfigResponse(version=5)
    policy_binary_remove_command(
        client, {"name": "agent-1", "rule_name": "r", "binary_path": "/usr/bin/curl", "reason": "case 42"}
    )
    op = _assert_merge_request(client, "remove_binary")
    assert op.remove_binary.binary_path == "/usr/bin/curl"


def test_egress_block_host_removes_every_port(client):
    client.stub.GetSandboxConfig.return_value = sandbox_pb2.GetSandboxConfigResponse(policy=make_policy(), version=4)
    client.stub.UpdateConfig.return_value = openshell_pb2.UpdateConfigResponse(version=5)
    results = egress_block_host_command(client, {"name": "agent-1", "host": "FILES.example.com"})
    assert len(results) == 2
    ports = sorted(c.args[0].merge_operations[0].remove_endpoint.port for c in client.stub.UpdateConfig.call_args_list)
    assert ports == [443, 8443]


def test_egress_block_host_not_allowed(client):
    client.stub.GetSandboxConfig.return_value = sandbox_pb2.GetSandboxConfigResponse(policy=make_policy())
    results = egress_block_host_command(client, {"name": "agent-1", "host": "other.example.com"})
    assert "Nothing to remove" in results[0].readable_output
    client.stub.UpdateConfig.assert_not_called()


def test_provider_list(client):
    resp = openshell_pb2.ListSandboxProvidersResponse()
    p = resp.providers.add(type="github", profile_workspace="default")
    p.metadata.name = "gh-token"
    client.stub.ListSandboxProviders.return_value = resp
    res = provider_list_command(client, {"name": "agent-1"})
    assert res.outputs == [{"Sandbox": "agent-1", "Name": "gh-token", "Type": "github", "Workspace": "default"}]


def test_provider_detach_requires_confirm(client):
    with pytest.raises(DemistoException):
        provider_detach_command(client, {"name": "agent-1", "provider": "gh-token"})
    client.stub.DetachSandboxProvider.assert_not_called()


def test_provider_detach(client):
    res = provider_detach_command(client, {"name": "agent-1", "provider": "gh-token", "confirm": "yes"})
    req = client.stub.DetachSandboxProvider.call_args.args[0]
    assert (req.sandbox, req.provider) == ("agent-1", "gh-token")
    assert res.outputs["Action"] == "detach"


def test_format_error_grpc():
    class FakeRpcError(grpc.RpcError):
        def code(self):
            return grpc.StatusCode.NOT_FOUND

        def details(self):
            return "sandbox not found"

    assert format_error(FakeRpcError()) == "OpenShell gateway returned NOT_FOUND: sandbox not found"
    assert format_error(ValueError("boom")) == "boom"


def test_every_yml_command_is_implemented():
    import os

    import yaml

    with open(os.path.join(os.path.dirname(__file__), "NVIDIAOpenShell.yml")) as f:
        yml_commands = {c["name"] for c in yaml.safe_load(f)["script"]["commands"]}
    assert yml_commands == set(COMMANDS)
