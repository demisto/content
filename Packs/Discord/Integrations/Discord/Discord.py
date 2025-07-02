import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
import json


def send_message(api_key, channel_id, text):
    url = f"https://discord.com/api/v9/channels/{channel_id}/messages"
    headers = {"Authorization": "Bot " + api_key, "Content-Type": "application/json"}
    payload = {
        "content": text,
    }
    response = requests.post(url, headers=headers, data=json.dumps(payload))
    if not response.ok:
        raise DemistoException(
            f"Error in API call to Discord: {response.status_code} - {response.reason}.\nFull response: {response.text}"
        )
    message_id = response.json()["id"]
    content = response.json()["content"]
    channel_id = response.json()["channel_id"]
    alerts = {"id": message_id, "content": content, "channel_id": channel_id}

    command_results = CommandResults(outputs_prefix="Discord.Message", outputs_key_field="id", outputs=alerts)
    return_results(command_results)


def get_message(api_key, channel_id, message_id):
    url = f"https://discord.com/api/v9/channels/{channel_id}/messages/{message_id}"

    headers = {"Authorization": "Bot " + api_key, "Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    if not response.ok:
        raise DemistoException(
            f"Error in API call to Discord: {response.status_code} - {response.reason}.\nFull response: {response.text}"
        )
    details = response.json()
    msg_id = details["id"]
    msg = details["content"]
    channel_id = details["channel_id"]
    author_id = details["author"]["id"]
    author_user = details["author"]["username"]
    alert = {"id": msg_id, "content": msg, "channel_id": channel_id, "author": {"id": author_id, "username": author_user}}
    command_results = CommandResults(outputs_prefix="Discord.Details", outputs_key_field="id", outputs=alert)
    return_results(command_results)


def test_module(api_key):
    url = "https://discord.com/api/v9/users/@me"
    headers = {"Authorization": "Bot " + api_key, "Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return "ok"
    else:
        return "Please check your API key or connection"


def main():
    params = demisto.params()
    api_key = params.get("credentials", {}).get("password") or params.get("api_key")
    if not api_key:
        return_error("Please provide a valid API key")
    channel_id = params.get("channel_id")
    try:
        if demisto.command() == "discord-send-message":
            text = demisto.args()["text"]
            send_message(api_key, channel_id, text)
        elif demisto.command() == "discord-get-message":
            message_id = demisto.args()["message_id"]
            get_message(api_key, channel_id, message_id)
        elif demisto.command() == "test-module":
            return_results(test_module(api_key))
    except Exception as err:
        return_error(str(err))


if __name__ in ["__builtin__", "builtins", "__main__"]:
    main()
