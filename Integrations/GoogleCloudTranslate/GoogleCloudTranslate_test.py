from GoogleCloudTranslate import supported_languages, translate_text  # noqa


MOCK_GET_SUPPORTED_LANGUAGES = [
    dict(
        language_code='aa',
        support_source=True,
        support_target=False
    ),
    dict(
        language_code='bb',
        support_source=False,
        support_target=True
    )
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
    assert outputs == dict(GoogleCloudTranslate=dict(SupportedLanguages=MOCK_GET_SUPPORTED_LANGUAGES))
    assert result == MOCK_GET_SUPPORTED_LANGUAGES


def test_translate_text_1(mocker):
    mclient = MockClient()

    readable, outputs, result = translate_text(
        mclient,
        dict(text='bar')
    )

    mock_result = {
        'text': 'bar',
        'translated_text': 'foo',
        'source_language_code': None,
        'detected_language_code': 'aa',
        'target_language_code': 'en'
    }

    assert isinstance(readable, str)
    assert outputs == dict(GoogleCloudTranslate=dict(TranslateText=mock_result))
    assert result == MOCK_TRANSLATE_TEXT


def test_translate_text_2(mocker):
    mclient = MockClient()

    readable, outputs, result = translate_text(
        mclient,
        dict(text='bar', target='it')
    )

    mock_result = {
        'text': 'bar',
        'translated_text': 'foo',
        'source_language_code': None,
        'detected_language_code': 'aa',
        'target_language_code': 'it'
    }

    assert isinstance(readable, str)
    assert outputs == dict(GoogleCloudTranslate=dict(TranslateText=mock_result))
    assert result == MOCK_TRANSLATE_TEXT


def test_translate_text_3(mocker):
    mclient = MockClient()

    readable, outputs, result = translate_text(
        mclient,
        dict(text='bar', target='it', source='hr')
    )

    mock_result = {
        'text': 'bar',
        'translated_text': 'foo',
        'source_language_code': 'hr',
        'detected_language_code': None,
        'target_language_code': 'it'
    }

    assert isinstance(readable, str)
    assert outputs == dict(GoogleCloudTranslate=dict(TranslateText=mock_result))
    assert result == {'translated_text': 'foo', 'detected_language_code': None}
