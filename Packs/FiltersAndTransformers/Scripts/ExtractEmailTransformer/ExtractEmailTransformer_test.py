from ExtractEmailTransformer import extract
import pytest

TEST_EXTRACT__ARGUMENTS = (
    (['example@example.com'], ['example@example.com']),
    (['example@example.com', 'foo'], ['example@example.com']),
    (['example@example.com', 'notanem@il'], ['example@example.com']),
    (['Example@example.com'], ['example@example.com']),
    (['EXAMPLE@example.com'], ['example@example.com']),
    (['example1@example.com'], ['example1@example.com']),
    (['example1@example.com', 'example2@example.com'], ['example1@example.com', 'example2@example.com']),
    (['EXAMPLE1@example.com', 'example2@example.com'], ['example1@example.com', 'example2@example.com']),
)


@pytest.mark.parametrize('inputs, expected', TEST_EXTRACT__ARGUMENTS)
def test_extract_email_transformer(inputs: list[str], expected: list[str]):
    assert extract(inputs) == expected


@pytest.mark.parametrize('inputs', ([''],
                                    [],
                                    [None],
                                    ['hello'],
                                    ['hello', 'world'],
                                    ['hello@world'],
                                    ['hello@'],
                                    ['hello@example'],
                                    ['hello@example.'],
                                    ['😎@example.com'],
                                    ['😎@example.com'],
                                    ))
def test_extract_email_transformer__no_email(inputs):
    assert extract(inputs) == []
