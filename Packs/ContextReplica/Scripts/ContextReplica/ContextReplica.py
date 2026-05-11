import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import traceback
from typing import Dict, Any


def resolve_root_key() -> str:

    env_metadata: Dict[str, Any] = demisto.demistoVersion() or {}

    sys_platform: str = env_metadata.get("platform", "").lower()
    sys_module: str = env_metadata.get("module", "").lower()

    if sys_module in ["agentix", "x5", "x2"] or sys_platform == "x2":
        return "issue"

    return "incident"


def main() -> None:

    try:
        global_ctx: Dict[str, Any] = demisto.context() or {}
        record_data: Dict[str, Any] = demisto.incident() or {}

        root_key: str = resolve_root_key()

        custom_fields: Any = record_data.get('CustomFields')
        if isinstance(custom_fields, dict):
            record_data.update(custom_fields)
            record_data.pop('CustomFields', None)

        global_ctx[root_key] = record_data

        serialized_payload: str = json.dumps(global_ctx, indent=4, default=str)

        return_results(fileResult("full_context.json", serialized_payload))

    except Exception as err:

        demisto.error(f"Context extraction failed. Traceback: {traceback.format_exc()}")
        return_error(f"Failed to generate context artifact. Exception: {str(err)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
