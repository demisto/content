import io
import json
import pytest


def util_load_json(path: str):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


ADF_TEXT_CASES = [
    ('Hello there', {
        'type': 'doc',
        'version': 1,
        'content': [
            {
                'type': 'paragraph',
                'content': [
                    {
                        'text': 'Hello there',
                        'type': 'text'
                    }
                ]
            }
        ]
    }
    )
]


@pytest.mark.parametrize('text, expected_adf_text', ADF_TEXT_CASES)
def test_text_to_adf(text, expected_adf_text):
    from JiraV3 import text_to_adf
    result = text_to_adf(text=text)
    assert expected_adf_text == result
