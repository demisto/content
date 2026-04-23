import json
import sys
from collections import deque
from copy import copy
from json import JSONDecodeError
from secrets import compare_digest
from tempfile import NamedTemporaryFile
from traceback import format_exc

import demistomock as demisto  # noqa: F401
import uvicorn
from CommonServerPython import *  # noqa: F401
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKey, APIKeyHeader
from uvicorn.logging import AccessFormatter

sample_events_to_store = deque(maxlen=20)  # type: ignore[var-annotated]

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name="Authorization")

MIRROR_DIRECTION = {
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}
MAX_FOUND_IDS = 5000


def get_mirroring() -> dict:
    """
    Get the mirroring configuration parameters from the integration parameters.

    Returns:
        dict: mirror_direction, mirror_tags, mirror_instance keys ready to be
              merged into a fetched incident dict.
    """
    params = demisto.params()
    mirror_direction = params.get("mirror_direction", "None").strip()
    mirror_tags = params.get("mirror_tags", "").strip()
    mirror_instance = params.get("mirror_instance", "").strip()
    return {
        "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
        "mirror_tags": mirror_tags,
        "mirror_instance": mirror_instance,
    }


def get_duplication_keys() -> list[str]:
    """
    Get the duplication keys from the integration parameters.

    Returns:
        list[str]: duplication keys
    """
    raw = (demisto.params().get("duplication_key", "")).strip()
    if not raw:
        return []
    return [k.strip() for k in raw.split(",") if k.strip()]


def filter_duplicate_incidents(
    incidents: list[dict], duplication_keys: list[str], integration_context: dict, context: dict
) -> list[dict]:
    """
    Filter incidents already seen based on duplication keys stored in integration context.
    A composite key of `fieldName:value` is stored so different fields with the same
    value don't collide (e.g. incidentId:123).
    Keeps at most MAX_FOUND_IDS entries, evicting the oldest when the limit is exceeded.
    """
    parsed_ids: list = json.loads(integration_context.get("found_ids", "[]"))
    seen_ids: set = set(parsed_ids)

    unique_incidents: list[dict] = []
    new_ids: list = []

    for incident in incidents:
        raw_json = incident.get("rawJson") or {}
        composite = None

        # check if any of the duplication keys are present in the raw json
        for key in duplication_keys:
            value = demisto.get(raw_json, key)
            if value is not None:
                composite = f"{key}:{value}"
                break

        # check if the composite key is already seen
        if composite and composite in seen_ids:
            demisto.debug(f"Skipping duplicate incident having ID: {composite}")
            continue

        # add the composite key to the set of seen keys
        if composite:
            new_ids.append(composite)
            seen_ids.add(composite)
        unique_incidents.append(incident)

    # update the integration context with new unique keys, capped at MAX_FOUND_IDS
    if new_ids:
        updated_ids = new_ids + parsed_ids
        if len(updated_ids) > MAX_FOUND_IDS:
            updated_ids = updated_ids[:MAX_FOUND_IDS]
        context["found_ids"] = updated_ids

    return unique_incidents


async def parse_incidents(request: Request) -> list[dict]:
    json_body = await request.json()
    demisto.debug(f"received body {sys.getsizeof(json_body)=}")
    incidents = json_body if isinstance(json_body, list) else [json_body]
    demisto.debug(f"received create incidents request of length {len(incidents)}")
    for incident in incidents:
        raw_json = incident.get("rawJson") or incident.get("raw_json") or copy(incident)
        mirroring = get_mirroring()
        if mirroring.get("mirror_direction"):
            raw_json.update(mirroring)
        if not incident.get("rawJson"):
            incident.pop("raw_json", None)
            incident["rawJson"] = raw_json
    return incidents


class GenericWebhookAccessFormatter(AccessFormatter):
    def get_user_agent(self, scope: dict) -> str:
        headers = scope.get("headers", [])
        user_agent_header = list(filter(lambda header: header[0].decode() == "user-agent", headers))
        user_agent = ""
        if len(user_agent_header) == 1:
            user_agent = user_agent_header[0][1].decode()
        return user_agent

    def formatMessage(self, record):
        recordcopy = copy(record)
        scope = recordcopy.__dict__["scope"]
        user_agent = self.get_user_agent(scope)
        recordcopy.__dict__.update({"user_agent": user_agent})
        return super().formatMessage(recordcopy)


@app.post("/")
async def handle_post(
    request: Request, credentials: HTTPBasicCredentials = Depends(basic_auth), token: APIKey = Depends(token_auth)
):
    demisto.debug("generic webhook handling request")
    try:
        incidents = await parse_incidents(request)
    except JSONDecodeError as e:
        demisto.error(f"could not decode request {e}")
        return Response(
            status_code=status.HTTP_400_BAD_REQUEST, content="Request, and rawJson field if exists must be in JSON format"
        )
    header_name = None
    request_headers = dict(request.headers)

    credentials_param = demisto.params().get("credentials")

    if credentials_param and (username := credentials_param.get("identifier")):
        password = credentials_param.get("password", "")
        auth_failed = False
        if username.startswith("_header"):
            header_name = username.split(":")[1]
            if not token or not compare_digest(token, password):
                auth_failed = True
        elif (not credentials) or (
            not (compare_digest(credentials.username, username) and compare_digest(credentials.password, password))
        ):
            auth_failed = True
        if auth_failed:
            secret_header = (header_name or "Authorization").lower()
            if secret_header in request_headers:
                request_headers[secret_header] = "***"
            demisto.debug(f"Authorization failed - request headers {request_headers}")
            return Response(status_code=status.HTTP_401_UNAUTHORIZED, content="Authorization failed.")

    secret_header = (header_name or "Authorization").lower()
    request_headers.pop(secret_header, None)
    integration_context = get_integration_context()
    context: dict = {}

    if not incidents:
        demisto.debug("Not having incidents to create before filtering")
        return None

    for incident in incidents:
        incident.get("rawJson", {})["headers"] = request_headers
        demisto.debug(f"{incident=}")

    duplication_keys = get_duplication_keys()
    if duplication_keys:
        demisto.debug(f"Using duplication keys: {duplication_keys}")
        incidents = filter_duplicate_incidents(incidents, duplication_keys, integration_context, context)

    if not incidents:
        demisto.debug("Not having incidents to create after filtering")
        return None

    incidents = [
        {
            "name": incident.get("name") or "Generic webhook triggered incident",
            "type": incident.get("type") or demisto.params().get("incidentType"),
            "occurred": incident.get("occurred"),
            "rawJSON": json.dumps(incident.get("rawJson")),
            "details": json.dumps(incident.get("rawJson")),
        }
        for incident in incidents
    ]

    demisto.debug("creating incidents")
    return_incidents = demisto.createIncidents(incidents)
    demisto.debug("created incidents")
    if demisto.params().get("store_samples"):
        try:
            sample_events_to_store.extend(incidents)
            demisto.debug(f"old events {len(sample_events_to_store)=}")
            sample_events = deque(json.loads(integration_context.get("sample_events", "[]")), maxlen=20)
            sample_events += sample_events_to_store
            demisto.debug(f"new events {len(sample_events_to_store)=}")
            context["sample_events"] = list(sample_events)

            demisto.debug("finished setting sample events")
        except Exception as e:
            demisto.error(f"Failed storing sample events - {e}")

    if context:
        set_to_integration_context_with_retries(context=context)
    demisto.debug(f"Integration context: {get_integration_context()}")
    return return_incidents


def setup_credentials():
    if credentials_param := demisto.params().get("credentials"):
        username = credentials_param.get("identifier")
        if username and username.startswith("_header:"):
            header_name = username.split(":")[1]
            demisto.debug(f"Overwriting Authorization parameter with {username}")
            token_auth.model.name = header_name


def fetch_samples() -> None:
    """Extracts sample events stored in the integration context and returns them as incidents

    Returns:
        None: No data returned.
    """
    integration_context = get_integration_context()
    sample_events = json.loads(integration_context.get("sample_events", "[]"))
    demisto.incidents(sample_events)


def test_module(params: dict):
    """
    Assigns a temporary port for longRunningPort and returns 'ok'.
    """
    if not params.get("longRunningPort"):
        params["longRunningPort"] = "1111"
    return_results("ok")


def main() -> None:
    params = demisto.params()
    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        if demisto.command() == "test-module":
            return test_module(params)
        try:
            port = int(params.get("longRunningPort"))
        except ValueError as e:
            raise ValueError(f"Invalid listen port - {e}")
        if demisto.command() == "fetch-incidents":
            fetch_samples()
        elif demisto.command() == "long-running-execution":
            while True:
                certificate = demisto.params().get("certificate", "")
                private_key = demisto.params().get("key", "")

                certificate_path = ""
                private_key_path = ""
                try:
                    ssl_args = {}

                    if certificate and private_key:
                        certificate_file = NamedTemporaryFile(delete=False)
                        certificate_path = certificate_file.name
                        certificate_file.write(bytes(certificate, "utf-8"))
                        certificate_file.close()
                        ssl_args["ssl_certfile"] = certificate_path

                        private_key_file = NamedTemporaryFile(delete=False)
                        private_key_path = private_key_file.name
                        private_key_file.write(bytes(private_key, "utf-8"))
                        private_key_file.close()
                        ssl_args["ssl_keyfile"] = private_key_path

                        demisto.debug("Starting HTTPS Server")
                    else:
                        demisto.debug("Starting HTTP Server")

                    integration_logger = IntegrationLogger()
                    integration_logger.buffering = False
                    log_config = dict(uvicorn.config.LOGGING_CONFIG)
                    log_config["handlers"]["default"]["stream"] = integration_logger
                    log_config["handlers"]["access"]["stream"] = integration_logger
                    log_config["formatters"]["access"] = {
                        "()": GenericWebhookAccessFormatter,
                        "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"',
                    }
                    setup_credentials()
                    uvicorn.run(app, host="0.0.0.0", port=port, log_config=log_config, **ssl_args)  # type: ignore[arg-type]
                except Exception as e:
                    demisto.error(f"An error occurred in the long running loop: {e!s} - {format_exc()}")
                    demisto.updateModuleHealth(f"An error occurred: {e!s}")
                finally:
                    if certificate_path:
                        os.unlink(certificate_path)
                    if private_key_path:
                        os.unlink(private_key_path)
                    time.sleep(5)
    except Exception as e:
        demisto.error(format_exc())
        return_error(f"Failed to execute {demisto.command()} command. Error: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
