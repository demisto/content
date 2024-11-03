from InfobloxBloxOneThreatDefense import *
from pathlib import Path
import pytest
import json
from freezegun import freeze_time

TEST_PATH = Path(__file__).parent / "test_data"


def load_json_file(file_description):
    file_path = TEST_PATH / f"{file_description}.json"
    with open(file_path) as f:
        return f.read()


@pytest.fixture
def blox_client() -> BloxOneTDClient:
    return BloxOneTDClient("")


@pytest.fixture
def mock_results(mocker):
    return mocker.patch.object(demisto, "results")


@pytest.fixture(autouse=True)
def mock_demisto_version(mocker):
    return mocker.patch.object(
        demisto, "demistoVersion",
        return_value={
            'version': '6.5.0',
            'buildNumber': '12345'
        }
    )


def patch_command_args_and_params(mocker, command, args):
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "command", return_value=command)
    mocker.patch.object(
        demisto, "params", return_value={"credentials": {"password": ""}}
    )


class TestE2E:
    def test_dossier_source_list_command(self, requests_mock, mocker, mock_results):
        patch_command_args_and_params(mocker, "bloxone-td-dossier-source-list", {})
        request_call = requests_mock.get(
            "https://csp.infoblox.com/tide/api/services/intel/lookup/sources",
            text=load_json_file("bloxone-td-dossier-source-list"),
        )
        res_list = ["dns", "geo", "ptr", "whois", "ssl_cert", "urlhaus"]
        main()
        assert (
            mock_results.call_args[0][0]["EntryContext"]["BloxOneTD"]["DossierSource"]
            == res_list
        )
        assert mock_results.call_args[0][0]["Contents"]["DossierSource"] == res_list
        assert request_call.called_once

    def test_lookalike_domain_list_command(self, requests_mock, mocker, mock_results):
        patch_command_args_and_params(
            mocker, "bloxone-td-lookalike-domain-list", {"target_domain": "test.com"}
        )
        request_call = requests_mock.get(
            "https://csp.infoblox.com/api/tdlad/v1/lookalike_domains",
            text=load_json_file("bloxone-td-lookalike-domain-list"),
        )

        main()
        assert request_call.called_once
        assert (
            request_call.request_history[0].qs["_filter"][0].startswith("target_domain")
        )
        raw = mock_results.call_args[0][0]["Contents"]
        assert raw
        assert (
            mock_results.call_args[0][0]["EntryContext"]["BloxOneTD.LookalikeDomain"]
            == raw
        )

    def test_lookalike_domain_list_command_with_invalid_args(
        self, mocker, mock_results
    ):
        patch_command_args_and_params(
            mocker,
            "bloxone-td-lookalike-domain-list",
            {"target_domain": "test.com", "filter": "test"},
        )
        with pytest.raises(SystemExit):
            main()
        assert mock_results.call_args[0][0]["Type"] == 4
        assert (
            "Exactly one of them, more than one is argument is not accepted"
            in mock_results.call_args[0][0]["Contents"]
        )

    def test_dossier_lookup_get_command(self, requests_mock, mocker, mock_results):
        job_id = "c924d233-ddeb-8877-1234-fedd6a9bb070"
        create_job_request_mock = requests_mock.get(
            "https://csp.infoblox.com/tide/api/services/intel/lookup/indicator/ip",
            text=load_json_file("bloxone-td-dossier-lookup-get_create-job"),
        )
        results_request_mock = requests_mock.get(
            "https://csp.infoblox.com/tide/api/services/intel/lookup/jobs/c924d233-ddeb-8877-1234-fedd6a9bb070/results",
            text=load_json_file("bloxone-td-dossier-lookup-get_results"),
        )
        pending_request_mock_data = [
            {"state": "created", "status": "pending"},
            {"state": "created", "status": "pending"},
            {"state": "completed", "status": "success"},
        ]
        pending_request_mock = requests_mock.get(
            "https://csp.infoblox.com/tide/api/services/intel/lookup/jobs/c924d233-ddeb-8877-1234-fedd6a9bb070/pending",
            text=lambda _x, _y: json.dumps(pending_request_mock_data.pop(0)),
        )

        patch_command_args_and_params(
            mocker,
            "bloxone-td-dossier-lookup-get",
            {
                "indicator_type": "ip",
                "value": "11.22.33.44",
                "sources": "urlhaus,atp,geo",
            },
        )
        # first time the command is running (creating the job + one poll)
        main()
        polling_args = mock_results.call_args[0][0]["PollingArgs"]
        assert mock_results.call_count == 1
        assert isinstance(mock_results.call_args[0][0]["HumanReadable"], str)
        assert polling_args["job_id"] == job_id
        assert polling_args["timeout"] == 590
        assert pending_request_mock.call_count == 1

        patch_command_args_and_params(
            mocker, "bloxone-td-dossier-lookup-get", polling_args
        )

        # second time the command is running (second poll)
        main()
        polling_args = mock_results.call_args[0][0]["PollingArgs"]
        assert mock_results.call_count == 2
        assert mock_results.call_args[0][0].get("HumanReadable") is None
        assert polling_args["job_id"] == job_id
        assert polling_args["timeout"] == 580
        assert pending_request_mock.call_count == 2

        # third time the command is running (third poll + get results)
        main()
        assert "PollingArgs" not in mock_results.call_args[0][0]
        assert mock_results.call_count == 3
        assert mock_results.call_args[0][0]["HumanReadable"]
        assert pending_request_mock.call_count == 3

        assert create_job_request_mock.called_once
        assert results_request_mock.called_once

    def test_command_test_module_401(self, requests_mock, mocker, mock_results):
        patch_command_args_and_params(mocker, "test-module", {})
        requests_mock.get(
            "https://csp.infoblox.com/tide/api/services/intel/lookup/sources",
            status_code=401,
            text="{}",
        )
        with pytest.raises(SystemExit):
            main()

        assert mock_results.call_args[0][0]["Type"] == 4
        assert mock_results.call_args[0][0]["Contents"] == "authentication error"

    def test_command_test_module(self, requests_mock, mocker, mock_results):
        patch_command_args_and_params(mocker, "test-module", {})
        request_call = requests_mock.get(
            "https://csp.infoblox.com/tide/api/services/intel/lookup/sources", text="{}"
        )
        main()

        assert request_call.called_once
        assert mock_results.call_args[0][0] == "ok"

    def test_not_implemented_command(self, mocker):
        patch_command_args_and_params(mocker, "not-implemented-command", {})
        with pytest.raises(SystemExit):
            main()


class TestBloxOneTDClient:
    def test_dossier_source_list(self, blox_client, requests_mock):
        requests_mock.get(
            "https://csp.infoblox.com/tide/api/services/intel/lookup/sources",
            text=load_json_file("bloxone-td-dossier-source-list"),
        )
        assert blox_client.dossier_source_list() == [
            "dns",
            "geo",
            "ptr",
            "whois",
            "ssl_cert",
            "urlhaus",
        ]
        assert "rlabs" not in blox_client.dossier_source_list()

    def test_lookalike_domain_list_with_filter(self, blox_client, requests_mock):
        lookalike_request_mock = requests_mock.get(
            "https://csp.infoblox.com/api/tdlad/v1/lookalike_domains",
            text=load_json_file("bloxone-td-lookalike-domain-list"),
        )
        blox_client.lookalike_domain_list(user_filter="test-filter")
        assert (
            lookalike_request_mock.request_history[0].qs["_filter"][0] == "test-filter"
        )

    def test_lookalike_domain_list_with_target_domain(self, blox_client, requests_mock):
        lookalike_request_mock = requests_mock.get(
            "https://csp.infoblox.com/api/tdlad/v1/lookalike_domains",
            text=load_json_file("bloxone-td-lookalike-domain-list"),
        )
        blox_client.lookalike_domain_list(target_domain="target.domain")
        assert (
            lookalike_request_mock.request_history[0].qs["_filter"][0]
            == 'target_domain=="target.domain"'
        )

    def test_lookalike_domain_list_with_detected_at(self, blox_client, requests_mock):
        lookalike_request_mock = requests_mock.get(
            "https://csp.infoblox.com/api/tdlad/v1/lookalike_domains",
            text=load_json_file("bloxone-td-lookalike-domain-list"),
        )
        blox_client.lookalike_domain_list(detected_at="2023-02-21T00:00:00Z")
        assert (
            'detected_at>="2023-02-21T00:00:00Z"'.lower()
            == lookalike_request_mock.request_history[0].qs["_filter"][0]
        )

    def test_dossier_lookup_get_create(self, blox_client, requests_mock):
        lookup_get_create_request_mock = requests_mock.get(
            "https://csp.infoblox.com/tide/api/services/intel/lookup/indicator/ip",
            text=load_json_file("bloxone-td-dossier-lookup-get_create-job"),
        )
        job_id = blox_client.dossier_lookup_get_create(
            indicator_type="ip", value="11.22.33.44"
        )
        assert (
            "11.22.33.44"
            in lookup_get_create_request_mock.request_history[0].qs["value"]
        )
        assert job_id == "c924d233-ddeb-8877-1234-fedd6a9bb070"

    def test_dossier_lookup_get_is_done_check_when_not_done(
        self, blox_client, requests_mock
    ):
        requests_mock.get(
            "https://csp.infoblox.com/tide/api/services/intel/lookup/jobs/c924d233-ddeb-8877-1234-fedd6a9bb070/pending",
            text=json.dumps({"state": "created", "status": "pending"}),
        )
        is_done = blox_client.dossier_lookup_get_is_done(
            "c924d233-ddeb-8877-1234-fedd6a9bb070"
        )
        assert is_done is False

    def test_dossier_lookup_get_is_done_check_when_job_failed(
        self, blox_client, requests_mock
    ):
        requests_mock.get(
            "https://csp.infoblox.com/tide/api/services/intel/lookup/jobs/c924d233-ddeb-8877-1234-fedd6a9bb070/pending",
            text=json.dumps({"state": "completed", "status": "error"}),
        )
        with pytest.raises(DemistoException):
            blox_client.dossier_lookup_get_is_done(
                "c924d233-ddeb-8877-1234-fedd6a9bb070"
            )

    def test_dossier_lookup_get_is_done_check_when_done(
        self, blox_client, requests_mock
    ):
        requests_mock.get(
            "https://csp.infoblox.com/tide/api/services/intel/lookup/jobs/c924d233-ddeb-8877-1234-fedd6a9bb070/pending",
            text=json.dumps({"state": "completed", "status": "success"}),
        )
        is_done = blox_client.dossier_lookup_get_is_done(
            "c924d233-ddeb-8877-1234-fedd6a9bb070"
        )
        assert is_done is True

    def test_dossier_lookup_get_results(self, blox_client, requests_mock):
        dossier_lookup_get_results_request_mock = requests_mock.get(
            "https://csp.infoblox.com/tide/api/services/intel/lookup/jobs/c924d233-ddeb-8877-1234-fedd6a9bb070/results",
            text=load_json_file("bloxone-td-dossier-lookup-get_results"),
        )
        blox_client.dossier_lookup_get_results("c924d233-ddeb-8877-1234-fedd6a9bb070")
        assert dossier_lookup_get_results_request_mock.called_once


class TestUnitTests:
    def test_dossier_lookup_task_output(self):
        task_data = json.loads(load_json_file("bloxone-td-dossier-lookup-get_results"))[
            "results"
        ][0]
        expected_outputs = {
            "Source": "urlhaus",
            "Target": "11.22.33.44",
            "Task Id": "d4e24d99-1f98-4a1f-8434-cbf4c284c7d0",
            "Type": "ip",
        }
        assert dossier_lookup_task_output(task_data) == expected_outputs

    data_test_validate_and_format_lookalike_domain_list_args_with_multiple_filters = [
        {},
        {"filter": "filter", "target_domain": "target_domain"},
        {
            "filter": "filter",
            "target_domain": "target_domain",
            "detected_at": "detected_at",
        },
    ]

    @pytest.mark.parametrize(
        "args",
        data_test_validate_and_format_lookalike_domain_list_args_with_multiple_filters,
    )
    def test_validate_and_format_lookalike_domain_list_args_with_multiple_filters(
        self, args
    ):
        with pytest.raises(DemistoException):
            validate_and_format_lookalike_domain_list_args(args)

    data_test_validate_and_format_lookalike_domain_list_args_with_a_single_filter = [
        {"filter": "filter"},
        {"target_domain": "target_domain"},
    ]

    @pytest.mark.parametrize(
        "args",
        data_test_validate_and_format_lookalike_domain_list_args_with_a_single_filter,
    )
    def test_validate_and_format_lookalike_domain_list_args_with_a_single_filter(
        self, args
    ):
        assert validate_and_format_lookalike_domain_list_args(args) == args

    data_test_validate_and_format_lookalike_domain_list_args_with_detected_at_filter = [
        ("2023-02-20T00:00:00.000Z", "2023-02-20T00:00:00.000"),
        ("1 day", "2023-02-19T00:00:00.000"),
        ("1y", "2022-02-20T00:00:00.000"),
    ]

    @freeze_time("2023-02-20T00:00:00.000Z")
    @pytest.mark.parametrize(
        "detected_at, expected",
        data_test_validate_and_format_lookalike_domain_list_args_with_detected_at_filter,
    )
    def test_validate_and_format_lookalike_domain_list_args_with_detected_at_filter(
        self, detected_at, expected
    ):
        out_args = validate_and_format_lookalike_domain_list_args(
            {"detected_at": detected_at}
        )
        assert out_args["detected_at"] == expected

    def test_validate_and_format_lookalike_domain_list_args_with_invalid_detected_at_filter(
        self,
    ):
        with pytest.raises(DemistoException):
            validate_and_format_lookalike_domain_list_args({"detected_at": "test"})

    def test_dossier_lookup_get_command_results(self):
        data = json.loads(load_json_file("bloxone-td-dossier-lookup-get_results"))
        command_results = dossier_lookup_get_command_results(data)
        assert command_results.outputs == data["results"]
        assert command_results.raw_response == data
        assert command_results.readable_output.count("11.22.33.44") == 4
        assert "\n|Task Id|Type|Target|Source|\n" in command_results.readable_output

    def test_dossier_lookup_get_schedule_polling_result_with_first_time_true(self):
        command_results = dossier_lookup_get_schedule_polling_result(
            {"job_id": "1"}, first_time=True
        )
        assert command_results.readable_output

    def test_dossier_lookup_get_schedule_polling_result_without_first_time(self):
        command_results = dossier_lookup_get_schedule_polling_result({"job_id": "1"})
        assert command_results.readable_output is None

    def test_dossier_lookup_get_schedule_polling_result_polling_args_default(self):
        command_results = dossier_lookup_get_schedule_polling_result({"job_id": "1"})
        assert command_results.scheduled_command._args["timeout"] == 590
        assert (
            command_results.scheduled_command._command
            == "bloxone-td-dossier-lookup-get"
        )

    def test_dossier_lookup_get_schedule_polling_result_polling_args(self):
        command_results = dossier_lookup_get_schedule_polling_result(
            {"job_id": "1", "interval_in_seconds": 30, "timeout": 300}
        )
        assert command_results.scheduled_command._args["timeout"] == 270
        assert int(command_results.scheduled_command._next_run) == 30
        assert int(command_results.scheduled_command._timeout) == 300
        assert (
            command_results.scheduled_command._command
            == "bloxone-td-dossier-lookup-get"
        )
