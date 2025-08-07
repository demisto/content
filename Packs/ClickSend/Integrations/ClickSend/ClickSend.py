import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
import json
import base64


def text_to_voice(api_key, username, phoneNumber, Message, require_input, voice):
    url = "https://rest.clicksend.com/v3/voice/send"
    if require_input is False or require_input == "False":
        require_input = "0"
    elif require_input is True or require_input == "True":
        require_input = "1"
    else:
        require_input = "0"
    data = {
        "messages": [
            {
                "source": "php",
                "body": Message,
                "to": phoneNumber,
                "lang": "en-au",
                "voice": voice,
                "custom_string": "My MSG",
                "require_input": require_input,
                "machine_detection": require_input,
            }
        ]
    }
    # Combine the username and the API key with a colon
    credentials = f"{username}:{api_key}"
    # Encode the credentials in Base64
    credentials_encoded = base64.b64encode(credentials.encode("utf-8"))
    # Convert the result to a string and remove any trailing newlines
    credentials_encoded_str = credentials_encoded.decode("utf-8").replace("\n", "")
    headers = {"Authorization": "Basic " + credentials_encoded_str, "Content-Type": "application/json"}
    response = requests.post(url, headers=headers, data=json.dumps(data))
    message_id = response.json()["data"]["messages"][0]["message_id"]
    response_code = response.json()["response_code"]
    response_msg = response.json()["response_msg"]
    alerts = [
        {"id": message_id, "responseCode": response_code, "responseMsg": response_msg},
    ]
    command_results = CommandResults(outputs_prefix="Voice.MSG", outputs_key_field="id", outputs=alerts)
    return_results(command_results)


def voice_history(api_key, username):
    url = "https://rest.clicksend.com/v3/voice/history?limit=1000"
    # Combine the username and the API key with a colon
    credentials = f"{username}:{api_key}"
    # Encode the credentials in Base64
    credentials_encoded = base64.b64encode(credentials.encode("utf-8"))
    # Convert the result to a string and remove any trailing newlines
    credentials_encoded_str = credentials_encoded.decode("utf-8").replace("\n", "")
    headers = {"Authorization": "Basic " + credentials_encoded_str, "Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    history = response.json()["data"]
    command_results = CommandResults(outputs_prefix="Voice.History", outputs_key_field="message_id", outputs=history)
    return_results(command_results)


def test_module(api_key, username):
    url = "https://rest.clicksend.com/v3/voice/history"
    # Combine the username and the API key with a colon
    credentials = f"{username}:{api_key}"
    # Encode the credentials in Base64
    credentials_encoded = base64.b64encode(credentials.encode("utf-8"))
    # Convert the result to a string and remove any trailing newlines
    credentials_encoded_str = credentials_encoded.decode("utf-8").replace("\n", "")
    headers = {"Authorization": "Basic " + credentials_encoded_str, "Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    if response.json()["http_code"] == 200:
        return "ok"
    else:
        return "Please check your credit balance or make sure api_key and username are correct."


def main():
    params = demisto.params()
    api_key = params.get("api_key")
    username = params.get("username")
    try:
        if demisto.command() == "clicksend-text-to-voice":
            phoneNumber = demisto.args()["phoneNumber"]
            Message = demisto.args()["Message"]
            require_input = demisto.args()["require_input"]
            voice = demisto.args()["voice"]
            text_to_voice(api_key, username, phoneNumber, Message, require_input, voice)
        elif demisto.command() == "clicksend-voice-history":
            voice_history(api_key, username)
        elif demisto.command() == "test-module":
            return_results(test_module(api_key, username))
    except Exception as err:
        return_error(str(err))


if __name__ in ["__builtin__", "builtins", "__main__"]:
    main()
