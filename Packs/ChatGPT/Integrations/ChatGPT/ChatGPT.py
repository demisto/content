import json

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401


def ask_chatgpt(token, args):
    try:
        prompt = args['prompt']
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
        data = {
            "prompt": prompt,
            "model": "text-davinci-002",
            "max_tokens": 1024
        }
        response = requests.post("https://api.openai.com/v1/completions", json=data, headers=headers)
        generated_text = response.json()["choices"][0]["text"]
        alerts = [
            {
                'Question': prompt,
                'Answer': generated_text
            },
        ]
        command_results = CommandResults(
            outputs_prefix='ChatGPT.MSG',
            outputs_key_field='Question',
            outputs=alerts
        )
        return_results(command_results)
    except:
        print("Please make sure your token is valid and your usage is not expired.")


def test_module(token):
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
        data = {
            "prompt": "How are you?",
            "model": "text-davinci-002",
            "max_tokens": 1024
        }
        response = requests.post("https://api.openai.com/v1/completions", json=data, headers=headers)
        if "error" in response.json():
            return response.json()['error']['message']
        else:
            return 'ok'
    except Exception as err:
        print("error")


def main():
    params = demisto.params()
    token = params.get('token')
    args = demisto.args()
    try:
        if demisto.command() == 'ask-chatgpt':
            ask_chatgpt(token, args)
        elif demisto.command() == 'test-module':
            return_results(test_module(token))
    except Exception as err:
        return_error(str(err))


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
