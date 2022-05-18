import json
import pytest
from FeedCofense import Client, fetch_indicators_command
from CommonServerPython import FeedIndicatorType

with open("test_data/search_output.json") as f:
    raw: dict = json.load(f)

data = raw["data"]
threats = data["threats"]
client = Client("https://www.threathq.com", ("username", "password"), tags=['tag1', 'tag2'], tlp_color='RED')


class TestFetchIndicators:
    process_items_params = [
        (threats[0], "https://example.com/mal.exe", FeedIndicatorType.URL, 0, 5),
        (threats[0], "example.com", FeedIndicatorType.Domain, 3, 5),
        (threats[0], "*example.com", FeedIndicatorType.DomainGlob, 4, 5),
        ({}, "", "", 0, 0),
    ]

    @pytest.mark.parametrize("threat, value, _type, indicator_index, length", process_items_params)
    def test_process_item(self, threat, value, _type, indicator_index, length):
        """
        Test process_item function for success cases.
        Given
            - A valid response
        When
            - run process_item function
        Then
            - Verify value, type, tags and tlp for indicator
        """
        ans = client.process_item(threat)
        if length:
            first_obj = ans[indicator_index]
            assert len(ans) == length
            assert first_obj["value"] == value
            assert first_obj["type"] == _type
            assert first_obj['fields']['tags'] == client.tags
            assert first_obj['fields']['trafficlightprotocol'] == client.tlp_color
        else:
            assert not ans

    fetch_items_params = [
        (threats, ["https://example.com/mal.exe"], ["URL"], 1),
        (
            threats,
            [
                "https://example.com/mal.exe",
                "127.0.0.1",
                "https://example.com/raw/malp",
                "example.com",
                "*example.com",
                "randommd5",
                "randommd5",
                "6ad00a19ab3e47e4b54b2792a7b47a13",
                "d2c65700c107b637eafe34b203b6f712",
                "user@example.com",
                "random md5"
            ],
            [
                FeedIndicatorType.URL,
                FeedIndicatorType.IP,
                FeedIndicatorType.URL,
                FeedIndicatorType.Domain,
                FeedIndicatorType.DomainGlob,
                FeedIndicatorType.File,
                FeedIndicatorType.File,
                FeedIndicatorType.File,
                FeedIndicatorType.File,
                FeedIndicatorType.Email,
                FeedIndicatorType.File,
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
        """
        Test fetch_indicators_command for success cases.
        Given
            - A valid response
        When
            - run fetch_indicators_command
        Then
            - Verify value, type, tags and tlp for indicator
        """
        mocker.patch.object(Client, "build_iterator", return_value=iterator_value)
        results = fetch_indicators_command(client, limit=limit)
        if expected_value and expected_type:
            for i, res in enumerate(results):
                assert expected_value[i] in res["value"]
                assert expected_type[i] in res["type"]
                assert res['fields']['tags'] == client.tags
                assert res['fields']['trafficlightprotocol'] == client.tlp_color
        else:
            assert not results

    process_items_params = [
        (threats[0], "randommd5", FeedIndicatorType.File, 0, 4),
        (threats[0], "6ad00a19ab3e47e4b54b2792a7b47a13", FeedIndicatorType.File, 2, 4),
        ({}, "", "", 0, 0),
    ]

    @pytest.mark.parametrize("threat, value, _type, indicator_index, length", process_items_params)
    def test_process_file_item(self, threat, value, _type, indicator_index, length):
        """
        Test process_file_item function for success cases.
        Given
            - A valid response
        When
            - run process_file_item function
        Then
            - Verify value, type, tags and tlp for indicator
        """
        ans = client.process_file_item(threat)
        if length:
            first_obj = ans[indicator_index]
            assert len(ans) == length
            assert first_obj["value"] == value
            assert first_obj["type"] == _type
            assert first_obj['fields']['tags'] == client.tags
            assert first_obj['fields']['trafficlightprotocol'] == client.tlp_color
        else:
            assert not ans

    def test_indicator_fields_for_fetch_indicators_command(self, mocker):
        """
        Test indicator fields for fetch_indicators_command.
        Given
            - A valid response
        When
            - run fetch_indicators_command
        Then
            - Verify indicator fields
        """
        with open("test_data/fetch_indicators.json") as file:
            indicators = json.load(file)

        mocker.patch.object(Client, "build_iterator", return_value=[threats[1]])
        results = fetch_indicators_command(client)

        assert results == indicators['indicators']
