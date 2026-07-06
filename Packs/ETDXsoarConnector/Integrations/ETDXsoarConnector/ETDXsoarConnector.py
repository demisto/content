from dateparser import parse
import json
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

register_module_line('ETDXsoarConnector', 'start', __line__())
CONSTANT_PACK_VERSION = '1.0.0'
demisto.debug('pack id = ETDXsoarConnector, pack version = 1.0.0')
"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""


class ETDClient(BaseClient):

    def __init__(self, base_url: str, params: dict):

        self.params = params

        super().__init__(
            base_url=base_url,
            headers={},
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False)
        )

    def get_access_token(self):

        api_key = get_credential(
            self.params.get("api_key")
        )

        client_secret = get_credential(
            self.params.get("client_secret")
        )

        headers = {"x-api-key": api_key}

        res = self._http_request(
            method="POST",
            url_suffix="/v1/oauth/token",
            headers=headers,
            auth=(
                self.params.get("client_id"),
                client_secret
            ),
            timeout=30
        )

        token = res.get("accessToken")

        if not token:
            raise DemistoException(
                f"Token not found: {res}"
            )

        return token

    def request_log_export(
        self,
        token: str,
        start: str,
        end: str
    ):

        headers = {
            "Authorization": f"Bearer {token}",
            "x-api-key": get_credential(self.params.get("api_key")),
            "Content-Type": "application/json",
        }

        body = {
            "timeRange": [start, end],
            "logTypes": ["message"]
        }

        return self._http_request(
            method="POST",
            url_suffix="/v1/logs/downloadLinks",
            headers=headers,
            json_data=body
        )

    # GET LINKS
    def get_links(self, response):
        data = response.get("data", {})
        return data.get("message", [])

    # DOWNLOAD LOGS
    def download_logs(self, links):

        events = []
        for link in links:

            res = self._http_request(
                method="GET",
                full_url=link,
                resp_type="text"
            )

            for line in res.splitlines():

                if not line.strip():
                    continue

                try:
                    ev = json.loads(line)

                    # ONLY MESSAGE LOGS
                    if ev.get("logType") != "message":
                        continue

                    events.append(ev)

                except Exception:
                    continue

        return events

    def move_message(self, token, message_id, verdict, folder):

        headers = {

            "Authorization": f"Bearer {token}",
            "x-api-key": get_credential(self.params.get("api_key")),
            "Content-Type": "application/json"
        }

        body = {
            "folder": folder,
            "verdict": verdict,
            "ids": [message_id]
        }

        return self._http_request(

            method="POST",
            url_suffix="/v1/messages/move",
            headers=headers,
            json_data=body
        )

# HELPERS


def get_credential(param):

    if isinstance(param, dict):

        return (
            param.get("password")
            or param.get(
                "credentials",
                {}
            ).get("password")
        )

    return param


def generate_intervals(start_dt, end_dt):

    intervals = []

    current = start_dt

    while current < end_dt:

        next_t = current + timedelta(hours=3)

        if next_t > end_dt:
            next_t = end_dt

        intervals.append((current, next_t))

        current = next_t

    return intervals


# FETCH INCIDENTS
def fetch_incidents(client: ETDClient, params: dict):

    demisto.debug("ETD fetch-incidents started")

    now = datetime.now(timezone.utc)

    last_run = demisto.getLastRun() or {}
    last_fetch = last_run.get("last_fetch")

    # -----------------------------------
    # DETERMINE FETCH WINDOW
    # -----------------------------------
    if not last_fetch:

        first_fetch = params.get("first_fetch", "7 days")

        parsed_time = parse(first_fetch)

        if not parsed_time:
            raise DemistoException(
                f"Invalid first fetch value: {first_fetch}"
            )

        start_dt = parsed_time.astimezone(timezone.utc)
        # ETD API workaround
        if first_fetch.strip().lower() == "30 days":
            start_dt += timedelta(hours=1)

    else:

        start_dt = datetime.fromisoformat(
            last_fetch.replace("Z", "+00:00")
        )

    backlog_days = (now - start_dt).days

    # If backlog >= 6 days, process only 5 days
    if backlog_days >= 6:

        end_dt = start_dt + timedelta(days=5)

        if end_dt > now:
            end_dt = now

    else:

        # We're almost caught up
        end_dt = now

    demisto.info(
        f"Fetching ETD logs from "
        f"{start_dt.isoformat()} "
        f"to "
        f"{end_dt.isoformat()}"
    )

    incidents = []

    token = client.get_access_token()

    intervals = generate_intervals(
        start_dt,
        end_dt
    )

    demisto.info(
        f"Processing {len(intervals)} intervals"
    )

    # -----------------------------------
    # PROCESS INTERVALS
    # -----------------------------------
    for start, end in intervals:

        start_time = start.strftime("%Y-%m-%dT%H")
        end_time = end.strftime("%Y-%m-%dT%H")

        try:

            demisto.debug(
                f"Fetching interval "
                f"{start_time} -> {end_time}"
            )

            response = client.request_log_export(
                token,
                start_time,
                end_time
            )

            links = client.get_links(response)

            if not links:

                demisto.debug(
                    f"No logs found for "
                    f"{start_time} -> {end_time}"
                )

                continue

            events = client.download_logs(links)

            demisto.debug(
                f"Downloaded {len(events)} events"
            )

            for event in events:

                msg = event.get("message", {})

                sender = msg.get(
                    "fromAddresses",
                    "unknown"
                )

                verdict = (
                    msg.get("verdict", {})
                    .get("verdict", "")
                    .lower()
                )

                timestamp = (
                    msg.get("timestamp")
                    or msg.get(
                        "verdict",
                        {}
                    ).get("timestamp")
                )

                incident = {
                    "name": (
                        f"[ETD] "
                        f"{verdict.upper()} "
                        f"Email - {sender}"
                    ),
                    "occurred": timestamp,
                    "rawJSON": json.dumps(event),
                    "severity": 3,
                    "type": "ETD Malicious Email",
                    "CustomFields": {
                        "etdmessageid": msg.get("id")
                    }
                }

                incidents.append(incident)

        except Exception as ex:

            demisto.error(
                f"Interval failed "
                f"{start_time} -> {end_time}: "
                f"{str(ex)}"
            )

    # -----------------------------------
    # SAVE CHECKPOINT
    # -----------------------------------
    demisto.setLastRun({
        "last_fetch": end_dt.isoformat()
    })

    demisto.info(
        f"Checkpoint saved: "
        f"{end_dt.isoformat()}"
    )

    demisto.info(
        f"Total incidents created: "
        f"{len(incidents)}"
    )

    demisto.incidents(incidents)

    return incidents

def etd_move_message_command(client, args):

    token = client.get_access_token()
    result = client.move_message(
        token=token,
        message_id=args.get("message_id"),
        verdict=args.get("verdict"),
        folder=args.get("folder")
    )

    return CommandResults(

        readable_output=(
            f"ETD message updated\n\n"
            f"Verdict: {args.get('verdict')}\n"
            f"Folder: {args.get('folder')}"
        ),

        outputs=result
    )


# TEST MODULE
def test_module(client):

    token = client.get_access_token()
    if not token:
        raise DemistoException("Authentication failed")

    return "ok"


def test_fetch_command(client):
    incidents = fetch_incidents(client, demisto.params())
    return CommandResults(
        readable_output=f"Created {len(incidents)} incidents"
    )


# MAIN
def main():

    params = demisto.params()

    command = demisto.command()

    client = ETDClient(
        base_url=params.get("etd_base_url"),
        params=params
    )

    try:

        if command == "test-module":
            return_results(test_module(client))

        elif command == "test-fetch":
            return_results(
                test_fetch_command(client)
            )

        elif command == "fetch-incidents":
            fetch_incidents(client, params)

        elif command == "etd-move-message":
            return_results(
                etd_move_message_command(client, demisto.args())
            )

    except Exception as e:
        demisto.error(str(e))
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

register_module_line('ETDXsoarConnector', 'end', __line__())
