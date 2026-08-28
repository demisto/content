"""Local end-to-end test harness for the Idira Identity Response integration.

NOT part of the deployed integration - this is a developer convenience for
exercising the real Client against a live Idira Identity tenant with
credentials from a local ``.env`` file (which is git-ignored).

Usage:
    1. cp .env.local .env  and fill in real credentials.
    2. pip install python-dotenv requests   (if not already installed)
    3. python main.py                        # runs test-module + resolves a user
       python main.py lock-user u-123        # runs a single action
       python main.py get-user-by-name jdoe@corp

Available actions map 1:1 to the integration commands:
    test-module
    get-user-by-name <username>
    lock-user <user_id>
    disable-user <user_id>
    unlock-user <user_id>
    force-logout <user_id>
    expire-password <username>
    remove-role <role_id> <user_id[,user_id...]>

WARNING: these are REAL response actions against a live tenant. lock/disable
will block a real user from authenticating. Use a dedicated test user and run
``unlock-user`` to reverse.
"""
import json
import os
import sys

# ---------------------------------------------------------------------------
# The integration imports `demistomock as demisto` and CommonServerPython. When
# run as a standalone script (outside the XSOAR docker harness) we point demisto
# at env-driven params/args before importing the integration module so its
# module-level `from CommonServerPython import *` works against the local mock.
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    print("Tip: `pip install python-dotenv` to auto-load a .env file. Falling back to process env.")

import demistomock as demisto  # noqa: E402


def _load_params() -> dict:
    """Build the integration params dict from environment variables."""
    identity_url = os.environ.get("IDIRA_IDENTITY_URL", "")
    client_id = os.environ.get("IDIRA_CLIENT_ID", "")
    client_secret = os.environ.get("IDIRA_CLIENT_SECRET", "")
    insecure = os.environ.get("IDIRA_INSECURE", "false").lower() in ("1", "true", "yes")

    missing = [
        name
        for name, val in (
            ("IDIRA_IDENTITY_URL", identity_url),
            ("IDIRA_CLIENT_ID", client_id),
            ("IDIRA_CLIENT_SECRET", client_secret),
        )
        if not val
    ]
    if missing:
        sys.exit(f"Missing required env var(s): {', '.join(missing)}. See .env.local.")

    return {
        "identity_url": identity_url,
        "client_id": client_id,
        # type-9 credentials param is a dict with a "password" key.
        "credentials": {"password": client_secret},
        "insecure": insecure,
        "proxy": False,
    }


# Command name -> (integration command string, positional-arg names).
_ACTIONS = {
    "test-module": ("test-module", []),
    "get-user-by-name": ("idira-identity-response-get-user-by-name", ["username"]),
    "lock-user": ("idira-identity-response-lock-user", ["user_id"]),
    "disable-user": ("idira-identity-response-disable-user", ["user_id"]),
    "unlock-user": ("idira-identity-response-unlock-user", ["user_id"]),
    "force-logout": ("idira-identity-response-force-logout", ["user_id"]),
    "expire-password": ("idira-identity-response-expire-password", ["username"]),
    "remove-role": ("idira-identity-response-remove-role", ["role_id", "user_ids"]),
}


def main() -> None:
    argv = sys.argv[1:]
    action = argv[0] if argv else "test-module"
    if action not in _ACTIONS:
        sys.exit(f"Unknown action '{action}'. Choose one of: {', '.join(_ACTIONS)}")

    command, arg_names = _ACTIONS[action]
    positional = argv[1:]
    args = dict(zip(arg_names, positional))
    if len(positional) < len(arg_names):
        sys.exit(f"Action '{action}' expects arguments: {' '.join(arg_names)}")

    params = _load_params()

    # Wire up the demisto mock so the integration's main() reads our values.
    demisto.callingContext = {"context": {}}
    demisto._integration_context = {}
    demisto.params = lambda: params
    demisto.args = lambda: args
    demisto.command = lambda: command
    demisto.getIntegrationContext = lambda: demisto._integration_context
    demisto.setIntegrationContext = lambda ctx: demisto._integration_context.update(ctx)

    captured: list = []
    demisto.results = lambda r: captured.append(r)

    # Import AFTER demisto is configured so module-level code sees the mock.
    import IdiraIdentityResponse

    print(f"==> Running '{command}' with args={args}")
    IdiraIdentityResponse.main()

    for result in captured:
        print("---- result ----")
        print(json.dumps(result, indent=2))

# TODO: Remove from branch before PR
if __name__ == "__main__":
    main()
