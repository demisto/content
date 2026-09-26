import json
from typing import Any

import demistomock as demisto
from CommonServerPython import *  # noqa: F401,F403


DEFAULT_BASE_URL = "https://api.typesafe.ai"
DEFAULT_MODEL = "jev-latest"


class Client(BaseClient):
    """HTTP client for the TypeSafe System One API."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str = DEFAULT_MODEL,
        verify: bool = True,
        proxy: bool = False,
        timeout: int = 30,
    ) -> None:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        super().__init__(
            base_url=base_url.rstrip("/"),
            verify=verify,
            proxy=proxy,
            headers=headers,
            timeout=timeout,
        )
        self.model = model

    def evaluate(self, state: Any, questions: dict[str, Any], model: str | None = None) -> dict[str, Any]:
        payload = {
            "state": state,
            "model": model or self.model,
            "questions": questions,
        }
        return self._http_request(
            method="POST",
            url_suffix="/v1/systemone",
            json_data=payload,
            resp_type="json",
            retries=3,
            status_list_to_retry=(429, 529),
            backoff_factor=1,
        )

    def list_models(self) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix="/v1/models",
            resp_type="json",
            retries=3,
            status_list_to_retry=(429, 529),
            backoff_factor=1,
        )


def parse_state(value: Any) -> Any:
    """Interpret valid JSON as JSON; otherwise preserve the input as text."""
    if not isinstance(value, str):
        return value
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, (str, dict, list)) else value
    except (TypeError, ValueError):
        return value


def parse_json_argument(value: Any, name: str, expected_type: type) -> Any:
    if isinstance(value, expected_type):
        parsed = value
    else:
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise DemistoException(f"The {name} argument must be valid JSON: {exc}") from exc
    if not isinstance(parsed, expected_type):
        raise DemistoException(f"The {name} argument must decode to {expected_type.__name__}.")
    return parsed


def model_from_args(client: Client, args: dict[str, Any]) -> str:
    return args.get("model") or client.model


def answer_summary_rows(response: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for question_id, answer in response.get("answers", {}).items():
        answer_type = answer.get("type", "")
        if answer_type == "noul":
            value = answer.get("noul")
        elif answer_type == "choice":
            value = answer.get("choice")
        elif answer_type == "score":
            value = answer.get("score")
        else:
            value = answer
        rows.append(
            {
                "Question ID": question_id,
                "Type": answer_type,
                "Answer": value,
                "Confidence": answer.get("confidence"),
            }
        )
    return rows


def evaluate_command(client: Client, args: dict[str, Any]) -> CommandResults:
    state = parse_state(args.get("state", ""))
    questions = parse_json_argument(args.get("questions"), "questions", dict)
    response = client.evaluate(state, questions, model_from_args(client, args))
    rows = answer_summary_rows(response)
    return CommandResults(
        outputs_prefix="TypeSafeJev.Evaluation",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown("TypeSafe Jev evaluation", rows, removeNull=True),
    )


def noul_command(client: Client, args: dict[str, Any]) -> CommandResults:
    question: dict[str, Any] = {
        "type": "noul",
        "instructions": parse_state(args["instructions"]),
    }
    true_criteria = args.get("true_criteria")
    false_criteria = args.get("false_criteria")
    if true_criteria or false_criteria:
        criteria: dict[str, Any] = {}
        if true_criteria:
            criteria["true"] = parse_state(true_criteria)
        if false_criteria:
            criteria["false"] = parse_state(false_criteria)
        question["criteria"] = criteria

    response = client.evaluate(
        parse_state(args.get("state", "")),
        {"result": question},
        model_from_args(client, args),
    )
    answer = response["answers"]["result"]
    output = {
        "model": response.get("model"),
        "probability": answer.get("noul"),
        "usage": response.get("usage"),
    }
    return CommandResults(
        outputs_prefix="TypeSafeJev.Noul",
        outputs=output,
        raw_response=response,
        readable_output=tableToMarkdown("TypeSafe Jev Noul", output, removeNull=True),
    )


def choice_command(client: Client, args: dict[str, Any]) -> CommandResults:
    criteria = parse_json_argument(args.get("criteria"), "criteria", dict)
    if len(criteria) < 2:
        raise DemistoException("Choice criteria must contain at least two options.")
    if len(criteria) > 255:
        raise DemistoException("Choice criteria cannot contain more than 255 options.")
    response = client.evaluate(
        parse_state(args.get("state", "")),
        {
            "result": {
                "type": "choice",
                "instructions": parse_state(args["instructions"]),
                "criteria": criteria,
            }
        },
        model_from_args(client, args),
    )
    answer = response["answers"]["result"]
    output = {
        "model": response.get("model"),
        "choice": answer.get("choice"),
        "probabilities": answer.get("probabilities"),
        "confidence": answer.get("confidence"),
        "usage": response.get("usage"),
    }
    return CommandResults(
        outputs_prefix="TypeSafeJev.Choice",
        outputs=output,
        raw_response=response,
        readable_output=tableToMarkdown("TypeSafe Jev Choice", output, removeNull=True),
    )


def score_command(client: Client, args: dict[str, Any]) -> CommandResults:
    criteria = parse_json_argument(args.get("criteria"), "criteria", list)
    if not 2 <= len(criteria) <= 10:
        raise DemistoException("Score criteria must contain between two and ten ordered levels.")
    response = client.evaluate(
        parse_state(args.get("state", "")),
        {
            "result": {
                "type": "score",
                "instructions": parse_state(args["instructions"]),
                "criteria": criteria,
            }
        },
        model_from_args(client, args),
    )
    answer = response["answers"]["result"]
    output = {
        "model": response.get("model"),
        "score": answer.get("score"),
        "legend": answer.get("legend"),
        "probabilities": answer.get("probabilities"),
        "confidence": answer.get("confidence"),
        "usage": response.get("usage"),
    }
    return CommandResults(
        outputs_prefix="TypeSafeJev.Score",
        outputs=output,
        raw_response=response,
        readable_output=tableToMarkdown("TypeSafe Jev Score", output, removeNull=True),
    )


def list_models_command(client: Client) -> CommandResults:
    response = client.list_models()
    models = response.get("models", [])
    return CommandResults(
        outputs_prefix="TypeSafeJev.Model",
        outputs_key_field="name",
        outputs=models,
        raw_response=response,
        readable_output=tableToMarkdown("TypeSafe Jev models", models, removeNull=True),
    )


def test_module(client: Client) -> str:
    client.list_models()
    return "ok"


def main() -> None:
    params = demisto.params()
    api_key_param = params.get("apikey")
    api_key = api_key_param.get("password") if isinstance(api_key_param, dict) else api_key_param
    if not api_key:
        return_error("API Key is required.")
        return

    selected_model = params.get("model-freetext") or params.get("model-select") or DEFAULT_MODEL
    client = Client(
        base_url=params.get("url", DEFAULT_BASE_URL),
        api_key=api_key,
        model=selected_model,
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
        timeout=int(params.get("timeout", 30)),
    )

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        if command == "test-module":
            return_results(test_module(client))
        elif command == "jev-evaluate":
            return_results(evaluate_command(client, demisto.args()))
        elif command == "jev-noul":
            return_results(noul_command(client, demisto.args()))
        elif command == "jev-choice":
            return_results(choice_command(client, demisto.args()))
        elif command == "jev-score":
            return_results(score_command(client, demisto.args()))
        elif command == "jev-list-models":
            return_results(list_models_command(client))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as exc:
        return_error(f"Failed to execute {command}: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
