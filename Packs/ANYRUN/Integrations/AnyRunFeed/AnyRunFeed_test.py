import pytest
from AnyRunFeed import extract_indicator_data, convert_indicators


@pytest.fixture(scope="module")
def indicators() -> list[dict]:
    indicators = [
        {
            "created": "2022-02-23T07:34:19.000Z",
            "modified": "2025-05-17T20:15:39.130Z",
            "pattern": "[url:value = 'https://some_url']",
        }
    ]

    yield indicators
    del indicators


def test_extract_indicator_data_return_a_valid_type_and_value():
    indicator = {"pattern": "[url:value = 'https://some_url']"}
    assert extract_indicator_data(indicator) == ("url", "https://some_url")


def test_convert_indicators_returns_valid_demisto_indicators(indicators: list[dict]):
    assert convert_indicators(indicators) == [
        {
            "value": "https://some_url",
            "type": "URL",
            "fields": {
                "firstseenbysource": "2022-02-23T07:34:19.000Z",
                "first_seen": "2022-02-23T07:34:19.000Z",
                "modified": "2025-05-17T20:15:39.130Z",
                "last_seen": "2025-05-17T20:15:39.130Z",
                "vendor": "ANY.RUN",
                "source": "ANY.RUN TI Feed",
            },
        }
    ]
