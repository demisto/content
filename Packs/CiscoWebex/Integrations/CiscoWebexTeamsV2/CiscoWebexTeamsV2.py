import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

ARRAY_ARGS = {"emails", "roles", "licenses", "files"}
BOOL_ARGS = {"isModerator"}

# command name -> (method, url template, list context key or None)
COMMANDS: dict[str, tuple[str, str, str | None]] = {
    "cisco-webex-teams-v2-list-people": ("GET", "people", "People"),
    "cisco-webex-teams-v2-create-person": ("POST", "people", None),
    "cisco-webex-teams-v2-get-person-details": ("GET", "people/{personId}", None),
    "cisco-webex-teams-v2-update-person": ("PUT", "people/{personId}", None),
    "cisco-webex-teams-v2-delete-person": ("DELETE", "people/{personId}", None),
    "cisco-webex-teams-v2-get-own-details": ("GET", "people/me", None),
    "cisco-webex-teams-v2-list-rooms": ("GET", "rooms", "Rooms"),
    "cisco-webex-teams-v2-create-room": ("POST", "rooms", None),
    "cisco-webex-teams-v2-get-room-details": ("GET", "rooms/{roomId}", None),
    "cisco-webex-teams-v2-update-room": ("PUT", "rooms/{roomId}", None),
    "cisco-webex-teams-v2-delete-room": ("DELETE", "rooms/{roomId}", None),
    "cisco-webex-teams-v2-list-memberships": ("GET", "memberships", "Memberships"),
    "cisco-webex-teams-v2-create-membership": ("POST", "memberships", None),
    "cisco-webex-teams-v2-get-membership-details": ("GET", "memberships/{membershipId}", None),
    "cisco-webex-teams-v2-update-membership": ("PUT", "memberships/{membershipId}", None),
    "cisco-webex-teams-v2-delete-membership": ("DELETE", "memberships/{membershipId}", None),
    "cisco-webex-teams-v2-list-messages": ("GET", "messages", "Messages"),
    "cisco-webex-teams-v2-create-message": ("POST", "messages", None),
    "cisco-webex-teams-v2-get-message-details": ("GET", "messages/{messageId}", None),
    "cisco-webex-teams-v2-delete-message": ("DELETE", "messages/{messageId}", None),
    "cisco-webex-teams-v2-list-teams": ("GET", "teams", "Teams"),
    "cisco-webex-teams-v2-create-team": ("POST", "teams", None),
    "cisco-webex-teams-v2-get-team-details": ("GET", "teams/{teamId}", None),
    "cisco-webex-teams-v2-update-team": ("PUT", "teams/{teamId}", None),
    "cisco-webex-teams-v2-delete-team": ("DELETE", "teams/{teamId}", None),
    "cisco-webex-teams-v2-list-team-memberships": ("GET", "team/memberships", "TeamMemberships"),
    "cisco-webex-teams-v2-create-team-membership": ("POST", "team/memberships", None),
    "cisco-webex-teams-v2-get-team-membership-details": ("GET", "team/memberships/{membershipId}", None),
    "cisco-webex-teams-v2-update-team-membership": ("PUT", "team/memberships/{membershipId}", None),
    "cisco-webex-teams-v2-delete-team-membership": ("DELETE", "team/memberships/{membershipId}", None),
    "cisco-webex-teams-v2-list-webhooks": ("GET", "webhooks", "Webhooks"),
    "cisco-webex-teams-v2-create-webhook": ("POST", "webhooks", None),
    "cisco-webex-teams-v2-get-webhook-details": ("GET", "webhooks/{webhookId}", None),
    "cisco-webex-teams-v2-update-webhook": ("PUT", "webhooks/{webhookId}", None),
    "cisco-webex-teams-v2-delete-webhook": ("DELETE", "webhooks/{webhookId}", None),
    "cisco-webex-teams-v2-list-organizations": ("GET", "organizations", "Organizations"),
    "cisco-webex-teams-v2-get-organization-details": ("GET", "organizations/{orgId}", None),
    "cisco-webex-teams-v2-list-licenses": ("GET", "licenses", "Licenses"),
    "cisco-webex-teams-v2-get-license-details": ("GET", "licenses/{licenseId}", None),
    "cisco-webex-teams-v2-list-roles": ("GET", "roles", "Roles"),
    "cisco-webex-teams-v2-get-role-details": ("GET", "roles/{roleId}", None),
}


class Client(BaseClient):
    def call(self, method: str, url_template: str, args: dict) -> dict | None:
        """Fill path args into the template; send the rest as query (GET) or JSON body."""
        rest = dict(args)
        path_args = {k: rest.pop(k) for k in list(rest) if "{" + k + "}" in url_template}
        url = url_template.format(**path_args)
        for key in ARRAY_ARGS & rest.keys():
            rest[key] = argToList(rest[key])
        for key in BOOL_ARGS & rest.keys():
            rest[key] = argToBoolean(rest[key])
        if method == "GET":
            return self._http_request(method, url, params=rest)
        res = self._http_request(method, url, json_data=rest, resp_type="response")
        return res.json() if res.content else None


def to_results(res: dict | None, context_key: str | None) -> CommandResults | str:
    if not res:
        return "Command successful."
    outputs = res.get("items", []) if context_key else res
    if not outputs:
        return "Response is empty."
    return CommandResults(
        readable_output=tableToMarkdown("Cisco Webex Teams Results", outputs),
        outputs_prefix=f"CiscoSpark.{context_key}" if context_key else None,
        outputs=[{k[:1].upper() + k[1:]: v for k, v in item.items()} for item in outputs] if context_key else None,
        raw_response=res,
    )


def send_message_to_person(client: Client, args: dict) -> dict | None:
    if not args.get("toPersonEmail") and not args.get("toPersonId"):
        raise DemistoException("Either email or personId must be provided.")
    return client.call("POST", "messages", args)


def send_message_to_room(client: Client, args: dict) -> dict | None:
    args = dict(args)
    if room_name := args.pop("toRoomName", None):
        rooms = (client.call("GET", "rooms", {}) or {}).get("items", [])
        matches = [room["id"] for room in rooms if room_name in room.get("title", "")]
        if len(matches) > 1:
            raise DemistoException(f"More than one room starts with the given name: {room_name}")
        if not matches:
            raise DemistoException(f"A room with the given name was not found: {room_name}")
        args["roomId"] = matches[0]
    elif not args.get("roomId"):
        raise DemistoException("Either room name or roomId must be provided.")
    return client.call("POST", "messages", args)


def test_module(client: Client) -> str:
    try:
        client.call("GET", "people/me", {})
    except DemistoException as e:
        if e.res is not None and e.res.status_code == 401:
            raise DemistoException("Authentication failure: Invalid API token (401).")
        raise
    return "ok"


def main() -> None:  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")
    try:
        api_key = (params.get("apikey_creds") or {}).get("password")
        if not api_key:
            raise DemistoException("API Key is required. Provide a Webex Bot or Personal access token.")
        client = Client(
            base_url=urljoin(params.get("server", "https://webexapis.com").rstrip("/"), "/v1/"),
            verify=not argToBoolean(params.get("insecure", False)),
            proxy=argToBoolean(params.get("proxy", False)),
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        )
        if command == "test-module":
            return_results(test_module(client))
        elif command == "cisco-webex-teams-v2-send-message-to-person":
            return_results(to_results(send_message_to_person(client, args), None))
        elif command == "cisco-webex-teams-v2-send-message-to-room":
            return_results(to_results(send_message_to_room(client, args), None))
        elif command in COMMANDS:
            method, url, context_key = COMMANDS[command]
            return_results(to_results(client.call(method, url, args), context_key))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
