import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DEFAULT_PROTOCOL_TYPE = "tcp"


def build_protocols_json(ports: list, protocol_type: str) -> str:
    if not ports:
        return ""
    protocols = [{"type": protocol_type, "port": port} for port in ports]
    return json.dumps(protocols)


def main() -> None:
    try:
        args = demisto.args()
        ports = [p.strip() for p in argToList(args.get("ports")) if p.strip()]
        protocol_type = (args.get("protocol_type") or DEFAULT_PROTOCOL_TYPE).strip().lower()

        protocols_json = build_protocols_json(ports, protocol_type)
        if not protocols_json:
            readable_output = "No ports provided - ProtocolsJson left empty (leaves protocols unset)."
        else:
            readable_output = f"Built protocols JSON for {len(ports)} port(s): {protocols_json}"

        return_results(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix="Netskope.BuiltProtocols",
                outputs={"ProtocolsJson": protocols_json},
            )
        )
    except Exception as e:
        return_error(f"Failed to build protocols JSON: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
