import pytest

import GitLabEventCollector


@pytest.fixture()
def client() -> GitLabEventCollector.Client:
    return GitLabEventCollector.Client('https://example.com')


class TestGetGroupEvents:
    @staticmethod
    def test_no_events(client, mocker):
        mocker.patch.object(client, '_http_request', side_effect=[
            [],
        ])

        events, _, page = client.get_group_events(1, '2022-01-01T00:00', [])
        assert page == 1
        assert len(events) == 0

    @staticmethod
    def test_dedup_run(client, mocker):
        pass

    @staticmethod
    def test_stopping_before_last_page(client, mocker):
        mocker.patch.object(client, '_http_request', side_effect=[
            [{'id': f'event_1_{i + 1}'} for i in range(100)],
            [{'id': f'event_2_{i + 1}'} for i in range(100)],
        ])

        events, _, page = client.get_group_events(1, '2022-01-01T00:00', [], limit=150)
        assert page == 2
        assert len(events) == 150
        assert {'id': 'event_1_1'} in events
        assert {'id': 'event_1_100'} in events
        assert {'id': 'event_2_1'} in events
        assert {'id': 'event_2_50'} in events
        assert {'id': 'event_2_51'} not in events

    @staticmethod
    def test_dedup_run2(client, mocker):
        mocker.patch.object(client, '_http_request', side_effect=[
            [{'id': f'event_1_{i + 1}'} for i in range(100)],
            [{'id': f'event_2_{i + 1}'} for i in range(100)],
            [{'id': f'event_3_{i + 1}'} for i in range(30)],
            # []
        ])

        events, _, page = client.get_group_events(1, '2022-01-01T00:00', [{'id': f'event_1_{i + 1}'} for i in range(30)])
        assert page == 3
        assert len(events) == 200
        assert {'id': 'event_1_1'} not in events
        assert {'id': 'event_1_30'} not in events
        assert {'id': 'event_1_31'} in events
        assert {'id': 'event_1_100'} in events
        assert {'id': 'event_2_1'} in events
        assert {'id': 'event_2_100'} in events
        assert {'id': 'event_3_1'} in events
        assert {'id': 'event_3_30'} in events

    @staticmethod
    def test_getting_all_pages(client: GitLabEventCollector.Client, mocker):
        mocker.patch.object(client, '_http_request', side_effect=[
            [{'id': f'event_1_{i + 1}'} for i in range(100)],
            [{'id': f'event_2_{i + 1}'} for i in range(100)],
            [{'id': f'event_3_{i + 1}'} for i in range(30)],
            # []
        ])

        events, _, page = client.get_group_events(1, '2022-01-01T00:00', [])
        assert page == 3
        assert len(events) == 230
        assert {'id': 'event_1_1'} in events
        assert {'id': 'event_1_100'} in events
        assert {'id': 'event_2_1'} in events
        assert {'id': 'event_2_100'} in events
        assert {'id': 'event_3_1'} in events
        assert {'id': 'event_3_30'} in events
