import json
import pytest
from FeedCofense import Client, fetch_indicators_command
from CommonServerPython import FeedIndicatorType

with open("TestData/search_output.json") as f:
    raw: dict = json.load(f)

data = raw["data"]
threats = data["threats"]
client = Client("https://www.threathq.com", ("username", "password"), tags=['tag1', 'tag2'])


class TestFetchIndicators:
    process_items_params = [
        (threats[0], "http://example.com/mal.exe", FeedIndicatorType.URL, 0, 5),
        (threats[0], "example.com", FeedIndicatorType.Domain, 3, 5),
        (threats[0], "*example.com", FeedIndicatorType.DomainGlob, 4, 5),
        ({}, "", "", 0, 0),
    ]

    @pytest.mark.parametrize("threat, value, _type, indicator_index, length", process_items_params)
    def test_process_item(self, threat, value, _type, indicator_index, length):
        ans = client.process_item(threat)
        if length:
            first_obj = ans[indicator_index]
            assert len(ans) == length
            assert first_obj["value"] == value
            assert first_obj["type"] == _type
            assert first_obj['fields']['tags'] == client.tags
        else:
            assert not ans

    fetch_items_params = [
        (threats, ["http://example.com/mal.exe"], ["URL"], 1),
        (
            threats,
            [
                "http://example.com/mal.exe",
                "5.5.5.111",
                "https://example.com/raw/malp",
                "example.com",
                "*example.com",
                "user@example.com",
            ],
            [
                FeedIndicatorType.URL,
                FeedIndicatorType.IP,
                FeedIndicatorType.URL,
                FeedIndicatorType.Domain,
                FeedIndicatorType.DomainGlob,
                FeedIndicatorType.Email,
            ],
            None,
        ),
        ([], [], [], 100),
    ]

    @pytest.mark.parametrize(
        "iterator_value, expected_value, expected_type, limit",
        fetch_items_params,
    )
    def test_fetch_indicators_command(
            self, mocker, iterator_value, expected_value, expected_type, limit
    ):
        mocker.patch.object(Client, "build_iterator", return_value=iterator_value)
        results = fetch_indicators_command(client, limit=limit)
        if expected_value and expected_type:
            for i, res in enumerate(results):
                assert expected_value[i] in res["value"]
                assert expected_type[i] in res["type"]
                assert res['fields']['tags'] == client.tags
        else:
            assert not results
