\
from typing import Any, Dict

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403


class Client(BaseClient):
    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "api_key": api_key,
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def snapshot_critical_paths(self) -> Dict[str, Any]:
        return self._http_request(
            method="POST",
            url_suffix="/sera/v2/ransomware/criticalpaths",
            json_data={},
        )

    def lockout_user(self, username: str) -> Dict[str, Any]:
        return self._http_request(
            method="POST",
            url_suffix=f"/sera/v2/ransomware/lockout/{username}",
            json_data={},
        )

    def unlock_user(self, username: str) -> Dict[str, Any]:
        return self._http_request(
            method="POST",
            url_suffix=f"/sera/v2/ransomware/unlock/{username}",
            json_data={},
        )

    def healthcheck(self) -> Dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix="/sera/v1/healthcheck",
        )


def test_module(client: Client) -> str:
    client.healthcheck()
    return "ok"


def snapshot_cmd(client: Client) -> CommandResults:
    try:
        res = client.snapshot_critical_paths()
        return CommandResults(
            outputs_prefix="SupernaZeroTrust.Snapshot",
            outputs={
                "Status": "Success",
                "Message": "Snapshot created successfully",
                "Result": res
            },
            readable_output="✅ Snapshot created successfully",
            raw_response=res,
        )
    except DemistoException as e:
        # Check if it's a 429 error (rate limit / recent snapshot exists)
        if "429" in str(e) or "Too Many Requests" in str(e):
            return CommandResults(
                outputs_prefix="SupernaZeroTrust.Snapshot",
                outputs={
                    "Status": "AlreadyExists",
                    "Message": "Snapshot already created within the last hour. Please wait before creating another snapshot."
                },
                readable_output="⚠️ Snapshot already created within the last hour. Please wait before creating another snapshot.",
                raw_response={"error": str(e)},
            )
        else:
            # Re-raise other errors
            raise


def lockout_cmd(client: Client, args: Dict[str, Any]) -> CommandResults:
    username = args.get("username")
    if not username:
        raise DemistoException("Missing required argument: username")
    res = client.lockout_user(username)
    return CommandResults(
        outputs_prefix="SupernaZeroTrust.Lockout",
        outputs={"Username": username, "Result": res},
        raw_response=res,
    )


def unlock_cmd(client: Client, args: Dict[str, Any]) -> CommandResults:
    username = args.get("username")
    if not username:
        raise DemistoException("Missing required argument: username")
    res = client.unlock_user(username)
    return CommandResults(
        outputs_prefix="SupernaZeroTrust.Unlock",
        outputs={"Username": username, "Result": res},
        raw_response=res,
    )


def main():  # pragma: no cover
    params = demisto.params()
    base_url = (params.get("base_url") or "").rstrip("/")
    creds = params.get("credentials") or {}
    api_key = creds.get("password")  # Authentication param: password holds the secret
    insecure = bool(params.get("insecure"))
    proxy = bool(params.get("proxy"))

    if not base_url:
        return_error("Missing required integration parameter: base_url")
    if not api_key:
        return_error("Missing required integration parameter: credentials (API key)")

    client = Client(base_url=base_url, api_key=api_key, verify=not insecure, proxy=proxy)

    try:
        cmd = demisto.command()
        if cmd == "test-module":
            return_results(test_module(client))
        elif cmd == "superna-zt-snapshot-critical-paths":
            return_results(snapshot_cmd(client))
        elif cmd == "superna-zt-lockout-user":
            return_results(lockout_cmd(client, demisto.args()))
        elif cmd == "superna-zt-unlock-user":
            return_results(unlock_cmd(client, demisto.args()))
        else:
            raise NotImplementedError(f"Command not implemented: {cmd}")
    except Exception as e:
        return_error(str(e), error=e)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
