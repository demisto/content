from GoogleCloudTranslate import supported_languages, translate_text  # noqa


MOCK_GET_SUPPORTED_LANGUAGES = [
    {
        'language_code': 'aa',
        'support_source': True,
        'support_target': False
    },
    {
        'language_code': 'bb',
        'support_source': False,
        'support_target': True
    }
]


MOCK_TRANSLATE_TEXT = {
    'translated_text': 'foo',
    'detected_language_code': 'aa'
}


class MockClient():
    def get_supported_languages(self):
        return MOCK_GET_SUPPORTED_LANGUAGES

    def translate_text(self, text, target, source=None):
        if source is None:
            return MOCK_TRANSLATE_TEXT

        result = MOCK_TRANSLATE_TEXT.copy()
        result.update({
            'detected_language_code': None
        })

        return result


def test_supported_languages(mocker):
    mclient = MockClient()

    readable, outputs, result = supported_languages(mclient)

    assert isinstance(readable, str)
    assert outputs == {'GoogleCloudTranslate': {'SupportedLanguages': MOCK_GET_SUPPORTED_LANGUAGES}}
    assert result == MOCK_GET_SUPPORTED_LANGUAGES


def test_translate_text_1(mocker):
    mclient = MockClient()

    readable, outputs, result = translate_text(
        mclient,
        {'text': 'bar'}
    )

    mock_result = {
        'ID': '95040f0a44fd692842831b107dfa9d92',
        'text': 'bar',
        'translated_text': 'foo',
        'source_language_code': None,
        'detected_language_code': 'aa',
        'target_language_code': 'en'
    }

    assert isinstance(readable, str)
    assert outputs == {
        'GoogleCloudTranslate.TranslateText(val.ID && val.ID==obj.ID)': mock_result
    }
    assert result == MOCK_TRANSLATE_TEXT


def test_translate_text_2(mocker):
    mclient = MockClient()

    readable, outputs, result = translate_text(
        mclient,
        {'text': 'bar', 'target': 'it'}
    )

    mock_result = {
        'ID': '2bda6ec4740ec87b49e90dbe6587fd14',
        'text': 'bar',
        'translated_text': 'foo',
        'source_language_code': None,
        'detected_language_code': 'aa',
        'target_language_code': 'it'
    }

    assert isinstance(readable, str)
    assert outputs == {
        'GoogleCloudTranslate.TranslateText(val.ID && val.ID==obj.ID)': mock_result
    }
    assert result == MOCK_TRANSLATE_TEXT


def test_translate_text_3(mocker):
    mclient = MockClient()

    readable, outputs, result = translate_text(
        mclient,
        {'text': 'bar', 'target': 'it', 'source': 'hr'}
    )

    mock_result = {
        'ID': 'd2124c37f6b3c436a3f18a7920227a22',
        'text': 'bar',
        'translated_text': 'foo',
        'source_language_code': 'hr',
        'detected_language_code': None,
        'target_language_code': 'it'
    }

    assert isinstance(readable, str)
    assert outputs == {
        'GoogleCloudTranslate.TranslateText(val.ID && val.ID==obj.ID)': mock_result
    }
    assert result == {'translated_text': 'foo', 'detected_language_code': None}
