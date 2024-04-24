"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""
import importlib
import json
import io

OpenAIGPT = importlib.import_module("OpenAIGPT")


class OpenAiClient:
    def get_chat_completions(self):
        pass


def test_extract_assistant_message():
    """Tests extraction from a valid response with choices and message."""

    from OpenAIGPT import extract_assistant_message

    mock_response = {
        'id': 'chatcmpl-XXXX',
        'object': 'chat.completion',
        'created': 1717171717,
        'model': 'gpt-4-turbo-2024-04-09',
        'choices': [
            {
                'index': 0,
                'message': {
                    'role': 'assistant',
                    'content': 'Hello! How can I assist you today?'},
                'logprobs': None,
                'finish_reason': 'stop'
            }
        ],
        'usage': {
            'prompt_tokens': 9,
            'completion_tokens': 9,
            'total_tokens': 18
        },
        'system_fingerprint': 'fp_76f018034d'
    }

    conversation = []
    extracted_message = extract_assistant_message(response=mock_response, conversation=conversation)

    assert extracted_message == "Hello! How can I assist you today?"
    assert conversation == [{'role': 'assistant', 'content': 'Hello! How can I assist you today?'}]

    # assert response.outputs == mock_response
# TODO: ADD HERE unit tests for every command
