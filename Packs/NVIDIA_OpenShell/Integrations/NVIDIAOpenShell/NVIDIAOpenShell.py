import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any

import grpc
from google.protobuf.json_format import MessageToDict
from openshell import SandboxClient, TlsConfig
from openshell._proto import datamodel_pb2, openshell_pb2, sandbox_pb2

""" CONSTANTS """

PREFIX = "OpenShell"
DEFAULT_ENDPOINT = "127.0.0.1:17670"
DEFAULT_WORKSPACE = "default"
DEFAULT_TIMEOUT = 30

""" HELPERS """


def normalize_pem(content: str) -> str:
    """Rebuild PEM line breaks.

    Credential fields can flatten newlines, which turns a valid PEM into one line that TLS libraries reject.
    """
    content = (content or "").strip()
    blocks = re.findall(r"(-----BEGIN [A-Z0-9 ]+-----)(.*?)(-----END [A-Z0-9 ]+-----)", content, re.S)
    if not blocks:
        return content
    rebuilt = []
    for head, body, foot in blocks:
        b64 = re.sub(r"\s+", "", body)
        rebuilt.append("\n".join([head] + [b64[i : i + 64] for i in range(0, len(b64), 64)] + [foot]))
    return "\n".join(rebuilt) + "\n"


def write_secret_file(directory: str, content: str, filename: str) -> Path:
    """Write a PEM credential to a file readable only by the integration, inside a directory removed on close."""
    path = Path(directory) / filename
    path.write_text(normalize_pem(content))
    os.chmod(path, 0o600)
    return path


def get_secret(params: dict, name: str) -> str:
    """Return the value of a type 9 credential parameter."""
    value = params.get(name)
    if isinstance(value, dict):
        return value.get("password") or ""
    return value or ""


def enum_name(enum: Any, value: int, prefix: str) -> str:
    """Return a protobuf enum value as a short name, for example SANDBOX_PHASE_READY as READY."""
    try:
        return enum.Name(value).replace(prefix, "")
    except ValueError:
        return str(value)


def phase_name(phase: int) -> str:
    return enum_name(openshell_pb2.SandboxPhase, phase, "SANDBOX_PHASE_")


def sandbox_to_dict(ref: Any) -> dict:
    return {
        "ID": ref.id,
        "Name": ref.name,
        "Workspace": ref.workspace,
        "Phase": phase_name(ref.phase),
        "PolicyVersion": ref.current_policy_version,
        "Labels": dict(ref.labels or {}),
    }


def workspace_scope(workspace: str):
    return datamodel_pb2.WorkspaceSelector(workspace=workspace)


def require_confirm(args: dict, action: str) -> None:
    if str(args.get("confirm", "")).lower() != "yes":
        raise DemistoException(f"{action} is irreversible. Run the command again with confirm=yes.")


def policy_rows(policy: Any) -> list[dict]:
    rows = []
    for rule_name, rule in policy.network_policies.items():
        binaries = [b.path for b in rule.binaries]
        for ep in rule.endpoints:
            ports = list(ep.ports) or ([ep.port] if ep.port else [])
            rows.append(
                {
                    "Rule": rule_name,
                    "Host": ep.host,
                    "Ports": ports,
                    "Protocol": ep.protocol,
                    "Path": ep.path,
                    "Binaries": binaries,
                }
            )
        if not rule.endpoints:
            rows.append({"Rule": rule_name, "Host": "", "Ports": [], "Protocol": "", "Path": "", "Binaries": binaries})
    return rows


""" CLIENT """


class Client:
    """Connects to the OpenShell gateway through the OpenShell SDK."""

    def __init__(
        self,
        endpoint: str,
        workspace: str,
        timeout: float,
        ca_cert: str = "",
        client_cert: str = "",
        client_key: str = "",
        bearer_token: str = "",
        plaintext: bool = False,
    ):
        self.endpoint = re.sub(r"^https?://", "", endpoint or DEFAULT_ENDPOINT).rstrip("/")
        self.workspace = workspace or DEFAULT_WORKSPACE
        self.timeout = timeout
        # The SDK reads the TLS files once while it builds the channel, so they are deleted right after.
        with tempfile.TemporaryDirectory() as tls_dir:
            tls = None
            if not plaintext:
                tls = TlsConfig(
                    ca_path=write_secret_file(tls_dir, ca_cert, "ca.crt") if ca_cert else None,
                    cert_path=write_secret_file(tls_dir, client_cert, "tls.crt") if client_cert else None,
                    key_path=write_secret_file(tls_dir, client_key, "tls.key") if client_key else None,
                )
            self.sdk = SandboxClient(self.endpoint, tls=tls, bearer_token=bearer_token or None, timeout=timeout)

    @property
    def stub(self) -> Any:
        """The generated gRPC stub of the SDK client.

        The SDK does not wrap the policy, log and provider RPCs yet, so they are called through the stub
        the SDK already authenticated. This is the only place the integration reaches into the SDK.
        """
        return self.sdk._stub

    def close(self) -> None:
        self.sdk.close()

    def ws(self, args: dict) -> str:
        """Return the workspace argument, or the instance workspace."""
        return args.get("workspace") or self.workspace


""" COMMANDS """


def test_module(client: Client) -> str:
    """Checks the connection and the credentials with an authenticated gateway call."""
    client.sdk.health()
    client.stub.GetGatewayInfo(openshell_pb2.GetGatewayInfoRequest(), timeout=client.timeout)
    return "ok"


def gateway_info_get_command(client: Client, args: dict) -> CommandResults:
    health = client.sdk.health()
    info = client.stub.GetGatewayInfo(openshell_pb2.GetGatewayInfoRequest(), timeout=client.timeout)
    out = {"Endpoint": client.endpoint, "Version": health.version, "Info": MessageToDict(info)}
    return CommandResults(
        outputs_prefix=f"{PREFIX}.Gateway",
        outputs_key_field="Endpoint",
        outputs=out,
        readable_output=tableToMarkdown("OpenShell gateway", out, ["Endpoint", "Version"]),
    )


def sandbox_list_command(client: Client, args: dict) -> CommandResults:
    selector = args.get("label_selector") or None
    if argToBoolean(args.get("all_workspaces", False)):
        refs = client.sdk.list_all_for_all_workspaces(label_selector=selector)
    else:
        refs = client.sdk.list_all(workspace=client.ws(args), label_selector=selector)
    limit = arg_to_number(args.get("limit")) or 50
    rows = [sandbox_to_dict(r) for r in refs][:limit]
    return CommandResults(
        outputs_prefix=f"{PREFIX}.Sandbox",
        outputs_key_field="ID",
        outputs=rows,
        readable_output=tableToMarkdown(
            f"OpenShell sandboxes ({len(rows)})", rows, ["Name", "Workspace", "Phase", "PolicyVersion", "ID"]
        ),
    )


def sandbox_get_command(client: Client, args: dict) -> CommandResults:
    row = sandbox_to_dict(client.sdk.get(args["name"], workspace=client.ws(args)))
    return CommandResults(
        outputs_prefix=f"{PREFIX}.Sandbox",
        outputs_key_field="ID",
        outputs=row,
        readable_output=tableToMarkdown(f"Sandbox {row['Name']}", row, ["Name", "Workspace", "Phase", "PolicyVersion", "ID"]),
    )


def sandbox_lifecycle_command(client: Client, args: dict, action: str) -> CommandResults:
    name, ws = args["name"], client.ws(args)
    if action == "stop":
        ref = client.sdk.stop(name, workspace=ws)
        if argToBoolean(args.get("wait", True)):
            client.sdk.wait_stopped(name, workspace=ws, timeout_seconds=arg_to_number(args.get("timeout_seconds")) or 120)
            ref = client.sdk.get(name, workspace=ws)
    elif action == "start":
        ref = client.sdk.start(name, workspace=ws)
    elif action == "suspend":
        ref = client.sdk.suspend(name, workspace=ws)
    elif action == "resume":
        ref = client.sdk.resume(name, workspace=ws)
    else:
        raise DemistoException(f"Unknown sandbox action: {action}")
    row = sandbox_to_dict(ref)
    row["Action"] = action
    return CommandResults(
        outputs_prefix=f"{PREFIX}.Sandbox",
        outputs_key_field="ID",
        outputs=row,
        readable_output=f"### Sandbox {name}: {action} requested. Phase is now {row['Phase']}.",
    )


def sandbox_delete_command(client: Client, args: dict) -> CommandResults:
    require_confirm(args, "Deleting a sandbox")
    res = client.sdk.delete(args["name"], workspace=client.ws(args), allow_missing=argToBoolean(args.get("allow_missing", False)))
    out = {
        "Name": args["name"],
        "ID": res.sandbox_id,
        "Outcome": getattr(res.outcome, "name", str(res.outcome)),
        "Action": "delete",
    }
    return CommandResults(
        outputs_prefix=f"{PREFIX}.Sandbox",
        outputs_key_field="Name",
        outputs=out,
        readable_output=tableToMarkdown("Sandbox deleted", out),
    )


def sandbox_logs_command(client: Client, args: dict) -> CommandResults:
    req = openshell_pb2.GetSandboxLogsRequest(
        workspace_scope=workspace_scope(client.ws(args)),
        sandbox=args["name"],
        lines=arg_to_number(args.get("lines")) or 200,
        min_level=args.get("min_level") or "",
        sources=argToList(args.get("sources")),
    )
    resp = client.stub.GetSandboxLogs(req, timeout=client.timeout)
    rows = [
        {
            "Sandbox": args["name"],
            "Time": line.event_time.ToJsonString() if line.HasField("event_time") else "",
            "Level": line.level,
            "Source": line.source,
            "Target": line.target,
            "Message": line.message,
        }
        for line in resp.logs
    ]
    return CommandResults(
        outputs_prefix=f"{PREFIX}.Log",
        outputs_key_field=["Sandbox", "Time", "Message"],
        outputs=rows,
        readable_output=tableToMarkdown(
            f"Last {len(rows)} log lines for {args['name']}", rows, ["Time", "Level", "Source", "Message"]
        ),
    )


def get_sandbox_config(client: Client, args: dict) -> Any:
    req = sandbox_pb2.GetSandboxConfigRequest(workspace_scope=workspace_scope(client.ws(args)), name=args["name"])
    return client.stub.GetSandboxConfig(req, timeout=client.timeout)


def policy_get_command(client: Client, args: dict) -> CommandResults:
    resp = get_sandbox_config(client, args)
    rows = policy_rows(resp.policy)
    out = {"Sandbox": args["name"], "Version": resp.version, "PolicyHash": resp.policy_hash, "NetworkRules": rows}
    return CommandResults(
        outputs_prefix=f"{PREFIX}.Policy",
        outputs_key_field="Sandbox",
        outputs=out,
        readable_output=tableToMarkdown(
            f"Network policy v{resp.version} for {args['name']}", rows, ["Rule", "Host", "Ports", "Protocol", "Path", "Binaries"]
        ),
    )


def policy_history_command(client: Client, args: dict) -> CommandResults:
    req = openshell_pb2.ListSandboxPoliciesRequest(
        workspace_scope=workspace_scope(client.ws(args)), sandbox=args["name"], page_size=arg_to_number(args.get("limit")) or 20
    )
    resp = client.stub.ListSandboxPolicies(req, timeout=client.timeout)
    rows = [
        {
            "Sandbox": args["name"],
            "Version": r.version,
            "Status": enum_name(openshell_pb2.PolicyStatus, r.status, "POLICY_STATUS_"),
            "Hash": r.policy_hash,
            "LoadError": r.load_error,
            "Created": r.created_time.ToJsonString() if r.HasField("created_time") else "",
        }
        for r in resp.revisions
    ]
    return CommandResults(
        outputs_prefix=f"{PREFIX}.PolicyRevision",
        outputs_key_field=["Sandbox", "Version"],
        outputs=rows,
        readable_output=tableToMarkdown(
            f"Policy history for {args['name']}", rows, ["Version", "Status", "Created", "LoadError"]
        ),
    )


def merge_policy(client: Client, args: dict, operation: Any, summary: str) -> CommandResults:
    req = openshell_pb2.UpdateConfigRequest(
        workspace_scope=workspace_scope(client.ws(args)),
        sandbox=args["name"],
        merge_operations=[operation],
        request_id=str(uuid.uuid4()),
        annotations={"cortex.reason": (args.get("reason") or "Cortex response")[:250]},
    )
    resp = client.stub.UpdateConfig(req, timeout=client.timeout)
    out = {"Sandbox": args["name"], "NewVersion": resp.version, "PolicyHash": resp.policy_hash, "Change": summary}
    return CommandResults(
        outputs_prefix=f"{PREFIX}.PolicyChange",
        outputs_key_field=["Sandbox", "NewVersion"],
        outputs=out,
        readable_output=f"### Policy updated on {args['name']}\n{summary}\nNew policy version: {resp.version}",
    )


def policy_rule_remove_command(client: Client, args: dict) -> CommandResults:
    op = openshell_pb2.PolicyMergeOperation(remove_rule=openshell_pb2.RemoveNetworkRule(rule_name=args["rule_name"]))
    return merge_policy(client, args, op, f"Removed network rule {args['rule_name']}.")


def policy_endpoint_remove_command(client: Client, args: dict) -> CommandResults:
    port = arg_to_number(args.get("port")) or 0
    op = openshell_pb2.PolicyMergeOperation(
        remove_endpoint=openshell_pb2.RemoveNetworkEndpoint(rule_name=args["rule_name"], host=args["host"], port=port)
    )
    return merge_policy(client, args, op, f"Removed {args['host']}:{port or '*'} from rule {args['rule_name']}.")


def policy_binary_remove_command(client: Client, args: dict) -> CommandResults:
    op = openshell_pb2.PolicyMergeOperation(
        remove_binary=openshell_pb2.RemoveNetworkBinary(rule_name=args["rule_name"], binary_path=args["binary_path"])
    )
    return merge_policy(client, args, op, f"Binary {args['binary_path']} removed from rule {args['rule_name']}.")


def egress_block_host_command(client: Client, args: dict) -> list[CommandResults]:
    """Remove every allow entry for a host, across all network rules of the sandbox."""
    host = args["host"].lower()
    hits = [r for r in policy_rows(get_sandbox_config(client, args).policy) if r["Host"].lower() == host]
    if not hits:
        return [CommandResults(readable_output=f"{host} is not allowed by any rule on {args['name']}. Nothing to remove.")]
    results = []
    for row in hits:
        for port in row["Ports"] or [0]:
            results.append(policy_endpoint_remove_command(client, dict(args, rule_name=row["Rule"], port=port)))
    return results


def provider_list_command(client: Client, args: dict) -> CommandResults:
    req = openshell_pb2.ListSandboxProvidersRequest(workspace_scope=workspace_scope(client.ws(args)), sandbox=args["name"])
    resp = client.stub.ListSandboxProviders(req, timeout=client.timeout)
    rows = [
        {"Sandbox": args["name"], "Name": p.metadata.name, "Type": p.type, "Workspace": p.profile_workspace}
        for p in resp.providers
    ]
    return CommandResults(
        outputs_prefix=f"{PREFIX}.Provider",
        outputs_key_field=["Sandbox", "Name"],
        outputs=rows,
        readable_output=tableToMarkdown(f"Credential providers attached to {args['name']}", rows, ["Name", "Type", "Workspace"]),
    )


def provider_detach_command(client: Client, args: dict) -> CommandResults:
    require_confirm(args, "Detaching a credential provider")
    req = openshell_pb2.DetachSandboxProviderRequest(
        workspace_scope=workspace_scope(client.ws(args)),
        sandbox=args["name"],
        provider=args["provider"],
        request_id=str(uuid.uuid4()),
    )
    client.stub.DetachSandboxProvider(req, timeout=client.timeout)
    out = {"Sandbox": args["name"], "Name": args["provider"], "Action": "detach"}
    return CommandResults(
        outputs_prefix=f"{PREFIX}.Provider",
        outputs_key_field=["Sandbox", "Name"],
        outputs=out,
        readable_output=f"### Provider {args['provider']} detached from {args['name']}.",
    )


COMMANDS = {
    "openshell-gateway-info-get": gateway_info_get_command,
    "openshell-sandbox-list": sandbox_list_command,
    "openshell-sandbox-get": sandbox_get_command,
    "openshell-sandbox-stop": lambda c, a: sandbox_lifecycle_command(c, a, "stop"),
    "openshell-sandbox-start": lambda c, a: sandbox_lifecycle_command(c, a, "start"),
    "openshell-sandbox-suspend": lambda c, a: sandbox_lifecycle_command(c, a, "suspend"),
    "openshell-sandbox-resume": lambda c, a: sandbox_lifecycle_command(c, a, "resume"),
    "openshell-sandbox-delete": sandbox_delete_command,
    "openshell-sandbox-logs": sandbox_logs_command,
    "openshell-policy-get": policy_get_command,
    "openshell-policy-history": policy_history_command,
    "openshell-policy-rule-remove": policy_rule_remove_command,
    "openshell-policy-endpoint-remove": policy_endpoint_remove_command,
    "openshell-policy-binary-remove": policy_binary_remove_command,
    "openshell-egress-block-host": egress_block_host_command,
    "openshell-provider-list": provider_list_command,
    "openshell-provider-detach": provider_detach_command,
}


def format_error(e: Exception) -> str:
    """Return a readable error, including the gRPC status code for gateway errors."""
    if isinstance(e, grpc.RpcError):
        return f"OpenShell gateway returned {e.code().name}: {e.details()}"
    return str(e)


""" MAIN """


def main() -> None:  # pragma: no cover
    params, args, command = demisto.params(), demisto.args(), demisto.command()
    demisto.debug(f"Command being called is {command}")
    client = None
    try:
        client = Client(
            endpoint=params.get("gateway_endpoint") or DEFAULT_ENDPOINT,
            workspace=params.get("workspace") or DEFAULT_WORKSPACE,
            timeout=float(arg_to_number(params.get("timeout"), arg_name="Timeout") or DEFAULT_TIMEOUT),
            ca_cert=get_secret(params, "ca_cert"),
            client_cert=get_secret(params, "client_cert"),
            client_key=get_secret(params, "client_key"),
            bearer_token=get_secret(params, "bearer_token"),
            plaintext=argToBoolean(params.get("plaintext", False)),
        )
        if command == "test-module":
            return_results(test_module(client))
        elif command in COMMANDS:
            return_results(COMMANDS[command](client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{format_error(e)}")
    finally:
        if client:
            client.close()


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
