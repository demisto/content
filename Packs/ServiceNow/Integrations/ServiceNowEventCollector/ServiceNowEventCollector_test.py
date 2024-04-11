import json
from datetime import datetime, timedelta
from freezegun import freeze_time

import pytest
from ServiceNowEventCollector import Client, LOGS_DATE_FORMAT


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


class TestFetchActivity:
    @pytest.fixture(autouse=True)
    def create_client(self):
        self.base_url = "https://test.com"
        self.client = Client(
            use_oauth=True,
            credentials={"username": "test", "password": "test"},
            client_id="test_id",
            client_secret="test_secret",
            url=self.base_url,
            verify=False,
            proxy=False,
            fetch_limit=10,
            api_server_url=f"{self.base_url}/api/now",
        )

    @staticmethod
    def create_response_by_limit(from_time, limit, offset):
        single_response = util_load_json("test_data/single_audit_log.json")
        return [single_response.copy() for _ in range(limit)]

    @staticmethod
    def create_response_with_duplicates(request_time, limit, number_of_different_time, id_to_start_from):
        """
        Creates response with different sys_created_on and sys_id.
        Args:
            request_time: request time to start from.
            limit: number of responses
            number_of_different_time: number of responses with different sys_created_on
            id_to_start_from: id to start from

        """
        single_response = util_load_json("test_data/single_audit_log.json")
        request_time_date_time = datetime.strptime(request_time, LOGS_DATE_FORMAT)
        output = []

        def create_single(single_response, time, id, output):
            single_response["sys_created_on"] = time
            single_response["sys_id"] = str(id)
            output.append(single_response)
            id += 1
            return output, id

        for _i in range(limit - number_of_different_time):
            output, id_to_start_from = create_single(single_response.copy(), request_time, id_to_start_from, output)
        for _i in range(limit - number_of_different_time, limit):
            new_time = datetime.strftime(request_time_date_time + timedelta(seconds=10), LOGS_DATE_FORMAT)
            output, id_to_start_from = create_single(single_response.copy(), new_time, id_to_start_from, output)
        return output

    @pytest.mark.parametrize("logs_to_fetch", [1, 4, 6], ids=["Single", "Part", "All"])
    def test_get_max_fetch_activity_logging(self, logs_to_fetch, mocker):
        """
        Given: number of logging to fetch.
        When: running get activity logging command or fetch.
        Then: return the correct number of loggings.

        """
        from ServiceNowEventCollector import get_audit_logs_command

        mocker.patch.object(Client, "get_audit_logs", side_effect=self.create_response_by_limit)
        res, _ = get_audit_logs_command(client=self.client, args={"limit": logs_to_fetch})
        assert len(res) == logs_to_fetch

    DUPLICATED_AUDIT_LOGS = [
        (("2023-04-15 07:00:00", 5, 2, 0), 5, 2, {"last_fetch_time": "2023-04-15 07:00:00", "previous_run_ids": set()}),
        (("2023-04-15 07:00:00", 5, 0, 0), 3, 5, {"last_fetch_time": "2023-04-15 07:00:00", "previous_run_ids": {"1", "2"}}),
    ]

    @pytest.mark.parametrize("args, len_of_audit_logs, len_of_previous, last_run", DUPLICATED_AUDIT_LOGS)
    def test_remove_duplicated_activity_logging(self, args, len_of_audit_logs, len_of_previous, last_run):
        """
        Given: responses with potential duplications from last fetch.
        When: running fetch command.
        Then: return last responses with the latest requestTime to check if there are duplications.

        """
        from ServiceNowEventCollector import process_and_filter_events

        loggings = self.create_response_with_duplicates(*args)

        activity_loggings, previous_run_ids = process_and_filter_events(
            loggings, last_run.get('previous_run_ids'), "2023-04-15 07:00:00")
        assert len(activity_loggings) == len_of_audit_logs
        assert len(previous_run_ids) == len_of_previous

    def test_get_activity_logging_command(self, mocker):
        """
        Given: params to run get_activity_logging_command
        When: running the command
        Then: Accurate response and readable output is returned.
        """
        from ServiceNowEventCollector import get_audit_logs_command

        mocker.patch.object(Client, "get_audit_logs", side_effect=self.create_response_by_limit)
        activity_loggings, res = get_audit_logs_command(client=self.client, args={"from_date": "2023-04-15 07:00:00", "limit": 4})
        assert len(activity_loggings) == 4
        assert "Audit Logs List" in res.readable_output

    @freeze_time("2023-04-12 07:01:00")
    def test_fetch_activity_logging(self, mocker):
        """
        Tests the fetch_events function

        Given:
            - first_fetch_time
        When:
            - Running the 'fetch_activity_logging' function.
        Then:
            - Validates that the function generates the correct API requests with the expected parameters.
            - Validates that the function returns the expected events and next_run timestamps.
        """
        from ServiceNowEventCollector import fetch_events_command

        fetched_events = util_load_json("test_data/fetch_audit_logs.json")
        http_responses = mocker.patch.object(
            Client,
            "get_audit_logs",
            return_value=fetched_events.get("fetch_logs"),
        )

        audit_logs, new_last_run = fetch_events_command(self.client, last_run={})

        assert http_responses.call_args[0][0] == "2023-04-12 07:00:00"

        assert audit_logs == fetched_events.get("fetched_events")
        assert new_last_run.get("last_fetch_time") == "2023-04-15 07:00:00"
        assert "2"
        assert "3" in new_last_run.get("previous_run_ids")

        # assert no new results when given the last_run:
        http_responses = mocker.patch.object(Client, "get_audit_logs", return_value=fetched_events.get("fetch_loggings"))

        audit_logs, new_last_run = fetch_events_command(self.client, last_run=new_last_run)

        assert http_responses.call_args[0][0] == "2023-04-15 07:00:00"
        assert audit_logs == []
        assert new_last_run.get("last_fetch_time") == "2023-04-15 07:00:00"
        assert "2"
        assert "3" in new_last_run.get("previous_run_ids")
