"""Unit tests for the NVIDIA OpenShell integration.

The SDK client and its gRPC stub are mocked. Responses are real protobuf messages from the SDK
in the Docker image, so request and response field names are checked against the SDK.
"""

from pathlib import Path
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
    gateway_info_get_command,
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
)
from NVIDIAOpenShell import test_module as run_test_module

READY = openshell_pb2.SandboxPhase.Value("SANDBOX_PHASE_READY")
STOPPED = openshell_pb2.SandboxPhase.Value("SANDBOX_PHASE_STOPPED")
PEM = "-----BEGIN CERTIFICATE-----" + "A" * 100 + "-----END CERTIFICATE-----"


def make_ref(name: str = "agent-1", phase: int = READY, version: int = 3) -> SimpleNamespace:
    return SimpleNamespace(
        id=f"id-{name}", name=name, workspace="default", phase=phase, current_policy_version=version, labels={"team": "ml"}
    )


def make_policy() -> sandbox_pb2.SandboxPolicy:
    policy = sandbox_pb2.SandboxPolicy()
    rule = policy.network_policies["agent_egress"]
    endpoint = rule.endpoints.add()
    endpoint.host = "files.example.com"
    endpoint.ports.extend([443, 8443])
    endpoint.protocol = "https"
    rule.binaries.add().path = "/usr/bin/curl"
    policy.network_policies["model_api"].endpoints.add(host="api.example.com", port=443)
    return policy


@pytest.fixture
def client(mocker) -> Client:
    sdk = MagicMock()
    mocker.patch.object(integration, "SandboxClient", return_value=sdk)
    return Client(endpoint="https://127.0.0.1:17670", workspace="default", timeout=10, plaintext=True)


def test_client_tls_files_are_written_then_removed(mocker):
    """
    Given: mTLS credentials pasted as single-line PEM values and an endpoint with a scheme.
    When: the client is created.
    Then: the SDK receives readable PEM files with mode 600, the files are deleted afterwards,
          and the scheme is stripped from the endpoint.
    """
    seen: dict[str, tuple[str, int]] = {}

    def capture(endpoint, tls, bearer_token, timeout):
        for key in ("ca_path", "cert_path", "key_path"):
            path = getattr(tls, key)
            seen[key] = (path.read_text(), path.stat().st_mode & 0o777)
        return MagicMock()

    tls_paths = []
    real_tls = integration.TlsConfig
    mocker.patch.object(integration, "TlsConfig", side_effect=lambda **kw: tls_paths.append(kw) or real_tls(**kw))
    mocker.patch.object(integration, "SandboxClient", side_effect=capture)

    client = Client(endpoint="https://gw:17670/", workspace="", timeout=5, ca_cert=PEM, client_cert=PEM, client_key=PEM)

    assert client.endpoint == "gw:17670"
    assert client.workspace == "default"
    for content, mode in seen.values():
        assert content.startswith("-----BEGIN CERTIFICATE-----\n")
        assert mode == 0o600
    assert all(not Path(p).exists() for p in tls_paths[0].values())


def test_client_plaintext_has_no_tls(mocker):
    """
    Given: a plaintext gateway and an OIDC bearer token.
    When: the client is created.
    Then: the SDK is created without TLS and with the bearer token.
    """
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
    """
    Given: a PEM value with flattened line breaks, a non-PEM value, or an empty value.
    When: normalize_pem is called.
    Then: PEM bodies are re-wrapped at 64 characters and other values are returned unchanged.
    """
    assert len(normalize_pem(raw).strip("\n").split("\n")) == expected_lines


def test_phase_name():
    """
    Given: a known and an unknown sandbox phase value.
    When: phase_name is called.
    Then: the known phase is returned without its prefix and the unknown one as a number string.
    """
    assert phase_name(READY) == "READY"
    assert phase_name(9999) == "9999"


def test_test_module(client):
    """
    Given: a reachable gateway.
    When: test-module runs.
    Then: it makes an authenticated gateway call and returns ok.
    """
    assert run_test_module(client) == "ok"
    client.sdk.health.assert_called_once()
    assert isinstance(client.stub.GetGatewayInfo.call_args.args[0], openshell_pb2.GetGatewayInfoRequest)


def test_gateway_info_get(client):
    """
    Given: a gateway that reports version 0.1.7.
    When: openshell-gateway-info-get runs.
    Then: the endpoint and version are returned under OpenShell.Gateway.
    """
    client.sdk.health.return_value = SimpleNamespace(version="0.1.7")
    client.stub.GetGatewayInfo.return_value = openshell_pb2.GetGatewayInfoResponse()
    result = gateway_info_get_command(client, {})
    assert result.outputs_prefix == "OpenShell.Gateway"
    assert result.outputs_key_field == "Endpoint"
    assert result.outputs["Version"] == "0.1.7"
    assert result.outputs["Endpoint"] == "127.0.0.1:17670"


def test_sandbox_list_uses_workspace_and_limit(client):
    """
    Given: three sandboxes in a workspace.
    When: openshell-sandbox-list runs with a workspace, a label selector and limit 2.
    Then: the SDK is called with the workspace and selector, and two sandboxes are returned.
    """
    client.sdk.list_all.return_value = [make_ref("a"), make_ref("b"), make_ref("c")]
    result = sandbox_list_command(client, {"workspace": "ml", "label_selector": "team=ml", "limit": "2"})
    client.sdk.list_all.assert_called_once_with(workspace="ml", label_selector="team=ml")
    assert result.outputs_prefix == "OpenShell.Sandbox"
    assert result.outputs_key_field == "ID"
    assert [r["Name"] for r in result.outputs] == ["a", "b"]
    assert result.outputs[0]["Phase"] == "READY"


def test_sandbox_list_all_workspaces(client):
    """
    Given: all_workspaces=true.
    When: openshell-sandbox-list runs.
    Then: sandboxes are listed across all workspaces.
    """
    client.sdk.list_all_for_all_workspaces.return_value = [make_ref()]
    sandbox_list_command(client, {"all_workspaces": "true"})
    client.sdk.list_all_for_all_workspaces.assert_called_once_with(label_selector=None)
    client.sdk.list_all.assert_not_called()


def test_sandbox_get(client):
    """
    Given: an existing sandbox.
    When: openshell-sandbox-get runs without a workspace.
    Then: the instance workspace is used and the sandbox is returned.
    """
    client.sdk.get.return_value = make_ref("agent-1")
    result = sandbox_get_command(client, {"name": "agent-1"})
    client.sdk.get.assert_called_once_with("agent-1", workspace="default")
    assert result.outputs["ID"] == "id-agent-1"


def test_sandbox_stop_waits_and_refreshes(client):
    """
    Given: a running sandbox.
    When: openshell-sandbox-stop runs with the default wait.
    Then: the command waits for STOPPED and returns the refreshed phase.
    """
    client.sdk.stop.return_value = make_ref(phase=READY)
    client.sdk.get.return_value = make_ref(phase=STOPPED)
    result = sandbox_lifecycle_command(client, {"name": "agent-1", "timeout_seconds": "30"}, "stop")
    client.sdk.wait_stopped.assert_called_once_with("agent-1", workspace="default", timeout_seconds=30)
    assert result.outputs["Phase"] == "STOPPED"
    assert result.outputs["Action"] == "stop"


def test_sandbox_stop_no_wait(client):
    """
    Given: wait=false.
    When: openshell-sandbox-stop runs.
    Then: the command does not wait for the sandbox to stop.
    """
    client.sdk.stop.return_value = make_ref(phase=READY)
    sandbox_lifecycle_command(client, {"name": "agent-1", "wait": "false"}, "stop")
    client.sdk.wait_stopped.assert_not_called()


@pytest.mark.parametrize("action", ["start", "suspend", "resume"])
def test_sandbox_other_lifecycle(client, action):
    """
    Given: a sandbox.
    When: openshell-sandbox-start, -suspend or -resume runs.
    Then: the matching SDK method is called and the action is returned.
    """
    getattr(client.sdk, action).return_value = make_ref()
    result = sandbox_lifecycle_command(client, {"name": "agent-1"}, action)
    getattr(client.sdk, action).assert_called_once_with("agent-1", workspace="default")
    assert result.outputs["Action"] == action


def test_sandbox_lifecycle_unknown_action(client):
    """
    Given: an unsupported action.
    When: sandbox_lifecycle_command runs.
    Then: an error is raised.
    """
    with pytest.raises(DemistoException):
        sandbox_lifecycle_command(client, {"name": "agent-1"}, "explode")


def test_sandbox_delete_requires_confirm(client):
    """
    Given: confirm=no.
    When: openshell-sandbox-delete runs.
    Then: an error is raised and the sandbox is not deleted.
    """
    with pytest.raises(DemistoException, match="confirm=yes"):
        sandbox_delete_command(client, {"name": "agent-1", "confirm": "no"})
    client.sdk.delete.assert_not_called()


def test_sandbox_delete(client):
    """
    Given: confirm=yes and allow_missing=true.
    When: openshell-sandbox-delete runs.
    Then: the sandbox is deleted and the outcome is returned.
    """
    client.sdk.delete.return_value = SimpleNamespace(sandbox_id="id-1", outcome=SimpleNamespace(name="DELETED"))
    result = sandbox_delete_command(client, {"name": "agent-1", "confirm": "yes", "allow_missing": "true"})
    client.sdk.delete.assert_called_once_with("agent-1", workspace="default", allow_missing=True)
    assert result.outputs["Outcome"] == "DELETED"


def test_sandbox_logs(client):
    """
    Given: a sandbox with a denied network event in its log.
    When: openshell-sandbox-logs runs with lines, min_level and sources.
    Then: the request carries the arguments and the log line is returned.
    """
    response = openshell_pb2.GetSandboxLogsResponse()
    line = response.logs.add(level="WARN", source="network", target="egress", message="denied files.example.com:443")
    line.event_time.FromJsonString("2026-11-04T10:00:00Z")
    client.stub.GetSandboxLogs.return_value = response
    result = sandbox_logs_command(client, {"name": "agent-1", "lines": "5", "min_level": "WARN", "sources": "network,process"})
    request = client.stub.GetSandboxLogs.call_args.args[0]
    assert request.sandbox == "agent-1"
    assert request.lines == 5
    assert list(request.sources) == ["network", "process"]
    assert request.workspace_scope == datamodel_pb2.WorkspaceSelector(workspace="default")
    assert result.outputs_prefix == "OpenShell.Log"
    assert result.outputs[0]["Message"] == "denied files.example.com:443"
    assert result.outputs[0]["Time"] == "2026-11-04T10:00:00Z"


def test_policy_get(client):
    """
    Given: a sandbox policy with two network rules.
    When: openshell-policy-get runs.
    Then: every rule is returned with its hosts, ports and binaries.
    """
    client.stub.GetSandboxConfig.return_value = sandbox_pb2.GetSandboxConfigResponse(
        policy=make_policy(), version=4, policy_hash="h4"
    )
    result = policy_get_command(client, {"name": "agent-1"})
    rules = {r["Rule"]: r for r in result.outputs["NetworkRules"]}
    assert rules["agent_egress"]["Ports"] == [443, 8443]
    assert rules["agent_egress"]["Binaries"] == ["/usr/bin/curl"]
    assert rules["model_api"]["Ports"] == [443]
    assert result.outputs["Version"] == 4


def test_policy_history(client):
    """
    Given: a sandbox with a loaded policy revision.
    When: openshell-policy-history runs with limit 5.
    Then: the page size is 5 and the status is returned as a name.
    """
    response = openshell_pb2.ListSandboxPoliciesResponse()
    response.revisions.add(version=4, policy_hash="h4", status=openshell_pb2.PolicyStatus.Value("POLICY_STATUS_LOADED"))
    client.stub.ListSandboxPolicies.return_value = response
    result = policy_history_command(client, {"name": "agent-1", "limit": "5"})
    assert client.stub.ListSandboxPolicies.call_args.args[0].page_size == 5
    assert result.outputs_key_field == ["Sandbox", "Version"]
    assert result.outputs[0]["Version"] == 4
    assert result.outputs[0]["Status"] == "LOADED"


def assert_merge_request(client: Client, field: str) -> openshell_pb2.PolicyMergeOperation:
    request = client.stub.UpdateConfig.call_args.args[0]
    assert request.sandbox == "agent-1"
    assert request.request_id
    assert request.annotations["cortex.reason"] == "case 42"
    assert request.merge_operations[0].WhichOneof("operation") == field
    return request.merge_operations[0]


def test_policy_rule_remove(client):
    """
    Given: a sandbox and a network rule name.
    When: openshell-policy-rule-remove runs.
    Then: a remove_rule merge operation is sent and the new policy version is returned.
    """
    client.stub.UpdateConfig.return_value = openshell_pb2.UpdateConfigResponse(version=5, policy_hash="h5")
    result = policy_rule_remove_command(client, {"name": "agent-1", "rule_name": "agent_egress", "reason": "case 42"})
    operation = assert_merge_request(client, "remove_rule")
    assert operation.remove_rule.rule_name == "agent_egress"
    assert result.outputs_prefix == "OpenShell.PolicyChange"
    assert result.outputs["NewVersion"] == 5


def test_policy_endpoint_remove(client):
    """
    Given: a sandbox, a rule, a host and a port.
    When: openshell-policy-endpoint-remove runs.
    Then: a remove_endpoint merge operation is sent for that host and port.
    """
    client.stub.UpdateConfig.return_value = openshell_pb2.UpdateConfigResponse(version=5)
    policy_endpoint_remove_command(
        client, {"name": "agent-1", "rule_name": "r", "host": "h.example.com", "port": "443", "reason": "case 42"}
    )
    operation = assert_merge_request(client, "remove_endpoint")
    assert (operation.remove_endpoint.host, operation.remove_endpoint.port) == ("h.example.com", 443)


def test_policy_binary_remove(client):
    """
    Given: a sandbox, a rule and a binary path.
    When: openshell-policy-binary-remove runs.
    Then: a remove_binary merge operation is sent for that binary.
    """
    client.stub.UpdateConfig.return_value = openshell_pb2.UpdateConfigResponse(version=5)
    policy_binary_remove_command(
        client, {"name": "agent-1", "rule_name": "r", "binary_path": "/usr/bin/curl", "reason": "case 42"}
    )
    operation = assert_merge_request(client, "remove_binary")
    assert operation.remove_binary.binary_path == "/usr/bin/curl"


def test_egress_block_host_removes_every_port(client):
    """
    Given: a policy that allows a host on two ports.
    When: openshell-egress-block-host runs with the host in a different case.
    Then: both host and port entries are removed.
    """
    client.stub.GetSandboxConfig.return_value = sandbox_pb2.GetSandboxConfigResponse(policy=make_policy(), version=4)
    client.stub.UpdateConfig.return_value = openshell_pb2.UpdateConfigResponse(version=5)
    results = egress_block_host_command(client, {"name": "agent-1", "host": "FILES.example.com"})
    assert len(results) == 2
    ports = sorted(c.args[0].merge_operations[0].remove_endpoint.port for c in client.stub.UpdateConfig.call_args_list)
    assert ports == [443, 8443]


def test_egress_block_host_not_allowed(client):
    """
    Given: a policy that does not allow the host.
    When: openshell-egress-block-host runs.
    Then: no policy change is made.
    """
    client.stub.GetSandboxConfig.return_value = sandbox_pb2.GetSandboxConfigResponse(policy=make_policy())
    results = egress_block_host_command(client, {"name": "agent-1", "host": "other.example.com"})
    assert "Nothing to remove" in results[0].readable_output
    client.stub.UpdateConfig.assert_not_called()


def test_provider_list(client):
    """
    Given: a sandbox with one credential provider.
    When: openshell-provider-list runs.
    Then: the provider is returned.
    """
    response = openshell_pb2.ListSandboxProvidersResponse()
    provider = response.providers.add(type="github", profile_workspace="default")
    provider.metadata.name = "gh-token"
    client.stub.ListSandboxProviders.return_value = response
    result = provider_list_command(client, {"name": "agent-1"})
    assert result.outputs_key_field == ["Sandbox", "Name"]
    assert result.outputs == [{"Sandbox": "agent-1", "Name": "gh-token", "Type": "github", "Workspace": "default"}]


def test_provider_detach_requires_confirm(client):
    """
    Given: no confirm argument.
    When: openshell-provider-detach runs.
    Then: an error is raised and the provider is not detached.
    """
    with pytest.raises(DemistoException):
        provider_detach_command(client, {"name": "agent-1", "provider": "gh-token"})
    client.stub.DetachSandboxProvider.assert_not_called()


def test_provider_detach(client):
    """
    Given: confirm=yes.
    When: openshell-provider-detach runs.
    Then: the provider is detached from the sandbox.
    """
    result = provider_detach_command(client, {"name": "agent-1", "provider": "gh-token", "confirm": "yes"})
    request = client.stub.DetachSandboxProvider.call_args.args[0]
    assert (request.sandbox, request.provider) == ("agent-1", "gh-token")
    assert result.outputs["Action"] == "detach"


def test_format_error_grpc():
    """
    Given: a gRPC error from the gateway and a generic error.
    When: format_error is called.
    Then: the gRPC status code and details are shown for the gateway error.
    """

    class FakeRpcError(grpc.RpcError):
        def code(self):
            return grpc.StatusCode.NOT_FOUND

        def details(self):
            return "sandbox not found"

    assert format_error(FakeRpcError()) == "OpenShell gateway returned NOT_FOUND: sandbox not found"
    assert format_error(ValueError("boom")) == "boom"


def test_every_yml_command_is_implemented():
    """
    Given: the integration YAML.
    When: its commands are compared with the command map.
    Then: every YAML command is implemented and every implemented command is in the YAML.
    """
    import yaml

    with open(Path(__file__).parent / "NVIDIAOpenShell.yml") as f:
        yml_commands = {c["name"] for c in yaml.safe_load(f)["script"]["commands"]}
    assert yml_commands == set(COMMANDS)
