import asyncio
import json
import random
import sys
from collections import defaultdict, deque
from copy import copy
from json import JSONDecodeError
from secrets import compare_digest
from tempfile import NamedTemporaryFile
from time import sleep
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
TEST = 1
STEP_1_DICT = defaultdict(int)
STEP_2_DICT = defaultdict(int)
STEP_3_DICT = defaultdict(dict)
FINISH_LIST = []
lock_example_6 = asyncio.Lock()
lock_1 = asyncio.Lock()
lock_2 = asyncio.Lock()
lock_3 = asyncio.Lock()


async def parse_incidents(request: Request) -> list[dict]:
    json_body = await request.json()
    demisto.debug(f"received body {sys.getsizeof(json_body)=}")
    incidents = json_body if isinstance(json_body, list) else [json_body]
    demisto.debug(f"received create incidents request of length {len(incidents)}")
    for incident in incidents:
        raw_json = incident.get("rawJson") or incident.get("raw_json") or copy(incident)
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

    for incident in incidents:
        incident.get("rawJson", {})["headers"] = request_headers
        demisto.debug(f"{incident=}")

    incidents = [
        {
            "name": incident.get("name") or "Generic webhook triggered incident",
            "type": incident.get("type") or demisto.params().get("incidentType"),
            "occurred": incident.get("occurred"),
            "rawJSON": json.dumps(incident.get("rawJson")),
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
            integration_context = get_integration_context()
            sample_events = deque(json.loads(integration_context.get("sample_events", "[]")), maxlen=20)
            sample_events += sample_events_to_store
            demisto.debug(f"new events {len(sample_events_to_store)=}")
            integration_context["sample_events"] = list(sample_events)
            set_to_integration_context_with_retries(integration_context)
            demisto.debug("finished setting sample events")
        except Exception as e:
            demisto.error(f"Failed storing sample events - {e}")

    return return_incidents


@app.get('/example_6')
async def handle_get_request_example_6():
    """
        for example 6.
    """
    global TEST
    global lock_example_6
    async with lock_example_6:
        val = TEST
        TEST += 1
    await asyncio.sleep(2)
    async with lock_example_6:
        TEST -= 1
    return Response(status_code=status.HTTP_200_OK, content=str(val), media_type="application/json")


@app.get('/example_5')
async def handle_get_request_example_5(query):
    """
        for example 5.
    """
    answer = "Your query doesn't match any of my templates.. I'll just mention that Arad is a naknik..."
    if query == "Arad is a?":
        answer = "naknik!"
    elif query == "Who's a naknik?":
        answer = "Arad!"
    return Response(status_code=status.HTTP_200_OK, content=answer, media_type="application/json")


@app.get('/step_1')
async def handle_get_request_step_1(name=""):
    """
        for step 1.
    """
    global STEP_1_DICT
    global lock_1
    async with lock_1:
        STEP_1_DICT[name] += 1
        if STEP_1_DICT[name] == 3:
            response = "You passed the first step! you know how to get instructions for the second step, this time, add arad (str) field to your request."
        else:
            response = str(STEP_1_DICT[name])
    await asyncio.sleep(3)
    async with lock_1:
        STEP_1_DICT[name] -= 1
    if not name:
        response = "Make sure to add your name to the params."
    return Response(status_code=status.HTTP_200_OK, content=str(response), media_type="application/json")


@app.get('/step_2')
async def handle_get_request_step_2(name=""):
    """
        for step 2.
    """
    global STEP_2_DICT
    global lock_2
    await asyncio.sleep(2)
    async with lock_2:
        STEP_2_DICT[name] += 1
    await asyncio.sleep(3)
    async with lock_2:
        STEP_2_DICT[name] -= 1
    response = 'well, I was not going to give it easily.. to obtain the password, send your name to the "step_3/get_pass" endpoint.'
    return Response(status_code=status.HTTP_200_OK, content=response, media_type="application/json")


@app.get('/step_2_completion_attempt')
async def handle_get_request_step_2_completion_attempt(name=""):
    """
        for step 1.
    """
    global STEP_2_DICT
    global lock_2
    async with lock_2:
        if not STEP_2_DICT[name]:
            response = 'You have to make the call in the time window that is 2 seconds after the first call and before 5 seconds the first call.'
        elif STEP_2_DICT[name] == 1:
            response = "Congrats! your made it to the right time window!\n get get your instructions for the third step."
        else:
            response = "Make sure there's exactly one call to step_2 endpoint at a time."
    return Response(status_code=status.HTTP_200_OK, content=response, media_type="application/json")


@app.get('/step_3')
async def handle_get_request_step_3(name=""):
    """
        for step 3.
    """
    global STEP_3_DICT
    global lock_3
    async with lock_3:
        STEP_3_DICT[name]["counter"] = STEP_3_DICT[name].get("counter", 0) + 1
        password = random.randint(0,1000)
        STEP_3_DICT[name]["password"] = password
    await asyncio.sleep(3)
    async with lock_3:
        STEP_3_DICT[name]["counter"] -= 1
    response = 'well, I was not going to give it easily.. to obtain the password, send your name to the "step_3/get_pass" endpoint.'
    return Response(status_code=status.HTTP_200_OK, content=response, media_type="application/json")


@app.get('/step_3/get_pass')
async def handle_get_request_step_3_get_pass(name=""):
    """
        for step 3.
    """
    global STEP_3_DICT
    global lock_3
    password = ""
    async with lock_3:
        password = STEP_3_DICT[name].get("password", "")
    if password:
        response = f'Your password is: "{password}". Make sure to send it to the "step_3/enter_password" endpoints before it expire.'
    else:
        response = "There's no password saved for you. Make sure you managed to complete the whole flow within 3 seconds."
    return Response(status_code=status.HTTP_200_OK, content=response, media_type="application/json")


@app.get('/step_3_enter_password')
async def handle_get_request_step_3_enter_password(name="", password=""):
    """
        for step 3.
    """
    global STEP_3_DICT
    global lock_3
    global FINISH_LIST
    async with lock_3:
        counter = STEP_3_DICT[name].get("counter", 0)
        expected_password = STEP_3_DICT[name].get("password", "")
        password = random.randint(0,1000)
    if counter != 1:
        response = f"your current call count is {counter}, it must be 1."
    elif password == expected_password:
        response = f'password is correct! your exercise is over! to get your place, send your name to the "finish_line/get_place" endpoint.'
        FINISH_LIST.append(name)
    elif password != expected_password:
        response = f"{password=} doesn't match the {expected_password=}."
    return Response(status_code=status.HTTP_200_OK, content=str(response), media_type="application/json")


@app.get('/finish_line/get_place')
async def handle_get_request_finish_line_get_place(name=""):
    global FINISH_LIST
    if name in FINISH_LIST:
        index = FINISH_LIST.index(name)
        if index == 0:
            suffix = "st"
        elif index == 1:
            suffix = "nd"
        elif index == 2:
            suffix = "rd"
        else:
            suffix = "th"
        response = f"Congratulations! you're the {index + 1}{suffix} developer to finish the exercise."
    else:
        response = f'Your name "{name}" does not appear in the finishers list.'
    return Response(status_code=status.HTTP_200_OK, content=str(response), media_type="application/json")


@app.get('/finish_line/list_results')
async def handle_get_request_finish_line_list_results():
    global FINISH_LIST
    response = f"There has been a total of {len(FINISH_LIST)} developers who finished all steps:\n"
    for i, name in enumerate(FINISH_LIST):
        if i == 0:
            suffix = "st"
        elif i == 1:
            suffix = "nd"
        elif i == 2:
            suffix = "rd"
        else:
            suffix = "th"
        response = f"{name} Finished in {i+1}{suffix} place."
    return Response(status_code=status.HTTP_200_OK, content=response, media_type="application/json")

@app.get('/instructions')
async def handle_get_request_instructions(hint=False, arad="", step_number=0):
    answer = ""
    if not step_number:
        answer = """Welcome to the asyncio workshop exercise!
        During the exercise We'll practice what we learned in the workshop and have some fun with asyncio.
        Here are some general instructions:
        1. There are 3 steps
        2. The initial instructions for each step are contained in this endpoint, use the following params to move along the instructions:
            - hint (bool) - boolean flag whether you need a hint for this step or not.
            - step_number (int) - the step number of the exercise you need instructions for.
        3. Make sure to print the response you get for further instructions and completion messages.
        4. Remember, arad=naknik.
        5. Have fun!"""
    elif step_number == 1:
        answer = "Send your name 3 times to the step_1 endpoint."
        if hint:
            answer = "Your name is being kept for only 5 seconds. Think about a way to send multiple requests simultaneously."
    elif step_number == 2:
        if hint:
            answer = """If you're still trying to figure out how to get the instructions, send a param less request to this endpoint.
            If you're trying to figure out how to solve it, go to sleep."""
        elif arad == "naknik":
            answer = "Nice! you figured the password.. To move on to the next step"
    elif step_number == 3:
        answer = ""
        if hint:
            answer = """You may want to use while loops."""
    # step two: send to two different endpoints.
    # step three: obtain password and send it to another endpoint - this will add your name to the winners list
    # Create winners endpoint
    return Response(status_code=status.HTTP_200_OK, content=answer, media_type="application/json")

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
