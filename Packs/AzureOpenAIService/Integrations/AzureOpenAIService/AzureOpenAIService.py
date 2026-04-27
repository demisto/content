import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Cortex XSOAR Integration for Azure OpenAI
"""

import traceback
import json


# --- CONSTANTS ---
API_VERSION = "2024-02-01"  # Using a stable, recent API version
DEFAULT_DEPLOYMENT = "gpt-4o"


class Client(BaseClient):
    """
    Client class to interact with the Azure OpenAI service.
    Inherits from BaseClient from CommonServerPython to handle SSL verification, etc.
    """

    def __init__(self, server_url, api_key, deployment_name, instruction, verify):
        # Ensure the URL ends with a /
        base_url = server_url if server_url.endswith("/") else f"{server_url}/"
        super().__init__(base_url=base_url, verify=verify)
        self.api_key = api_key
        self.deployment_name = deployment_name
        self.instruction = instruction

    # FIX: Added 'require_json' parameter to conditionally request JSON format.
    def send_message(self, message: str, require_json: bool = False) -> dict:
        """
        Sends a message to the Azure OpenAI 'chat completions' endpoint.

        :param message: The user message to send.
        :param require_json: If True, requests the response in JSON object format.
        :return: The full JSON response from the API.
        """
        full_url_path = f"openai/deployments/{self.deployment_name}/chat/completions?api-version={API_VERSION}"
        headers = {"Content-Type": "application/json", "api-key": self.api_key}
        payload = {
            "messages": [{"role": "system", "content": self.instruction}, {"role": "user", "content": message}],
            "max_tokens": 2000,
            "temperature": 0.5,
            "top_p": 0.95,
            "frequency_penalty": 0,
            "presence_penalty": 0,
            "stop": None,
            "stream": False,
        }

        # FIX: Only add the 'response_format' parameter when it's explicitly required.
        if require_json:
            payload["response_format"] = {"type": "json_object"}

        # The _http_request method handles the HTTP request
        response = self._http_request(
            method="POST", url_suffix=full_url_path, headers=headers, json_data=payload, resp_type="json"
        )
        return response


# --- COMMAND FUNCTIONS ---


def test_module(client: Client) -> str:
    """
    Tests API connectivity by sending a simple message.
    """
    try:
        # Use a simple instruction for the test.
        client.instruction = "You are a helpful assistant. Respond with 'ok' if you are working."
        # FIX: Call send_message without requiring a JSON response.
        client.send_message("This is a connection test.", require_json=False)
        return "ok"
    except DemistoException as e:
        if "401" in str(e):
            return "Authentication Error: Check your API Key."
        elif "404" in str(e):
            return "Connection Error: Check the Endpoint URL and Deployment Name."
        else:
            # Provide the specific error message from the API for easier debugging.
            return f"An API error occurred: {str(e)}"


def send_message_command(client: Client, args: dict) -> CommandResults:
    """
    Executes the command to send a message and process the structured response.
    """
    message = args.get("message", "")

    demisto.debug(f"Sending message to Azure OpenAI: '{message}'")
    # FIX: Call send_message *with* the requirement for a JSON response.
    raw_response = client.send_message(message, require_json=True)

    # Extract the response content
    raw_answer = ""
    if raw_response.get("choices") and isinstance(raw_response["choices"], list) and len(raw_response["choices"]) > 0:
        first_choice = raw_response["choices"][0]
        if first_choice.get("message") and first_choice.get("message").get("content"):
            raw_answer = first_choice["message"]["content"]

    if not raw_answer:
        raise DemistoException("Could not get a valid response from the API.", res=raw_response)

    # Logic to handle the structured JSON response
    try:
        # Attempt to parse the response as JSON
        parsed_data = json.loads(raw_answer)

        # Map the parsed data to the desired output keys
        outputs = {
            "IncidentAIVerdict": parsed_data.get("IncidentAIVerdict"),
            "AISummary": parsed_data.get("AISummary"),
            "Justification": parsed_data.get("Justification"),
            "ConfidenceScore": parsed_data.get("ConfidenceScore"),
            "EmailHeaderAIAnalysis": parsed_data.get("EmailHeaderAIAnalysis"),
            "EmailAISummary": parsed_data.get("EmailAISummary"),
            "EmailAIVerdict": parsed_data.get("EmailAIVerdict"),
            "Answer": parsed_data,
        }

        # Create a formatted, human-readable output
        readable_output = "## 🤖 AI Analysis\n\n"
        readable_output += f"**Verdict:** {outputs.get('IncidentAIVerdict', 'N/A')}\n"
        readable_output += f"**Confidence:** {outputs.get('ConfidenceScore', 'N/A')}\n"
        readable_output += f"**Summary:**\n---\n{outputs.get('AISummary', 'N/A')}\n\n"
        readable_output += f"**Justification:**\n---\n{outputs.get('Justification', 'N/A')}\n\n"
        readable_output += "### Detailed Email Analysis\n"
        readable_output += f"**Email Verdict:** {outputs.get('EmailAIVerdict', 'N/A')}\n"
        readable_output += f"**Email Summary:**\n---\n{outputs.get('EmailAISummary', 'N/A')}\n\n"
        readable_output += f"**Header Analysis:**\n---\n{outputs.get('EmailHeaderAIAnalysis', 'N/A')}\n"

        # Update the incident's custom fields
        custom_fields_to_set = {
            "incidentaiverdict": outputs.get("IncidentAIVerdict"),
            "aisummary": outputs.get("AISummary"),
            "justification": outputs.get("Justification"),
            "confidencescore": outputs.get("ConfidenceScore"),
            "emailheaderaianalysis": outputs.get("EmailHeaderAIAnalysis"),
            "emailaisummary": outputs.get("EmailAISummary"),
            "emailaiverdict": outputs.get("EmailAIVerdict"),
        }
        filtered_custom_fields = {k: v for k, v in custom_fields_to_set.items() if v is not None}
        if filtered_custom_fields:
            try:
                demisto.executeCommand("setIncident", {"customFields": filtered_custom_fields})
            except Exception as e:
                demisto.debug(f"Could not set incident fields. Error: {e}")

    except json.JSONDecodeError:
        demisto.debug("AI response was not valid JSON. Treating as raw text.")
        outputs = {"Answer": raw_answer}
        readable_output = f"## Azure OpenAI Response (Raw Text)\n\n**Response:**\n---\n{raw_answer}\n"
        try:
            demisto.executeCommand("setIncident", {"customFields": {"aianswer": raw_answer}})
        except Exception as e:
            demisto.debug(f"Could not set the 'aianswer' incident field. Error: {e}")

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="AzureOpenAI.Analysis",
        outputs_key_field="IncidentAIVerdict",
        outputs=outputs,
        raw_response=raw_response,
    )


# --- MAIN FUNCTION ---


def main() -> None:
    """
    Main function, parses parameters and executes commands.
    """
    params = demisto.params()
    server_url = params.get("url")

    api_key_details = params.get("credentials").get("password")
    api_key = api_key_details.get("password") if isinstance(api_key_details, dict) else api_key_details

    instruction = params.get("instruction")
    if not instruction or "{" not in instruction:
        demisto.debug("Instruction does not seem to request JSON. Using a default prompt for email analysis.")
        instruction = """
        You are an expert cybersecurity analyst. Analyze the provided data.
        Your response MUST be a single, valid JSON object. Do NOT provide ANY text outside of the JSON object.
        The JSON format must be as follows:
        {
          "IncidentAIVerdict": "string (Malicious, Suspicious, Benign, Informational)",
          "AISummary": "string (A 2-3 sentence global summary of the incident.)",
          "Justification": "string (The primary reason for the verdict, based on the strongest evidence.)",
          "ConfidenceScore": "integer (A confidence score from 0 to 100 for the verdict.)",
          "EmailHeaderAIAnalysis": "string (A detailed analysis of the email headers, including SPF/DKIM/DMARC and routing.)",
          "EmailAISummary": "string (A summary of the analysis of the email body, URLs, and attachments.)",
          "EmailAIVerdict": "string (Phishing, Malware, Spam, BEC, Safe)"
        }
        """

    deployment_name = params.get("deployment_name") or DEFAULT_DEPLOYMENT
    verify_certificate = not params.get("insecure", False)

    command = demisto.command()
    args = demisto.args()
    demisto.debug(f"Command being executed is {command}")

    try:
        client = Client(
            server_url=server_url,
            api_key=api_key,
            deployment_name=deployment_name,
            instruction=instruction,
            verify=verify_certificate,
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command == "azure-openai-send-message":
            return_results(send_message_command(client, args))
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


# --- ENTRY POINT ---

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
