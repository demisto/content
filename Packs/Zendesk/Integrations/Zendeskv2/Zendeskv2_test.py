from pathlib import Path

import pytest
import Zendeskv2
from freezegun import freeze_time
from Zendeskv2 import *

BASE_URL = "https://test.zendesk.com"
URL_PREFIX = f"{BASE_URL}/api/v2/"


def full_url(suffix):
    return f"{URL_PREFIX}{suffix}"


@pytest.fixture
def zendesk_client():
    return ZendeskClient(BASE_URL)


@pytest.fixture
def cache_manager(zendesk_client):
    return CacheManager(zendesk_client)


def get_json_file(file_data_type: str):
    full_file_path = Path(__file__).parent / "test_data" / f"{file_data_type}.json"
    with open(full_file_path) as json_file:
        return json.load(json_file)


class TestCacheManager:
    def test_zendesk_clear_cache(self, cache_manager, mocker):
        set_integration_context = mocker.patch.object(demisto, "setIntegrationContext")
        cache_manager.zendesk_clear_cache()
        set_integration_context.assert_called_once_with({})

    class TestSave:
        def test_with_data(self, mocker, cache_manager):
            set_integration_context = mocker.patch.object(demisto, "setIntegrationContext")
            cache_manager._data = {"data": "some_data"}
            cache_manager.save()
            set_integration_context.assert_called_once_with({"data": "some_data"})

        def test_without_data(self, mocker, cache_manager):
            set_integration_context = mocker.patch.object(demisto, "setIntegrationContext")
            cache_manager.save()
            set_integration_context.assert_not_called()

    class TestReplaceIdsChange:
        @staticmethod
        def user_id_to_name(user_id):
            return {1: "first user", 2: "second user"}[user_id]

        @staticmethod
        def organization_id_to_name(organization_id):
            return {100: "first organization", 200: "second organization"}[organization_id]

        def test_with_user_fields(self, cache_manager, mocker):
            mocker.patch.object(cache_manager, "user", side_effect=self.user_id_to_name)

            data = {"test_id": 1, "test_str": "unchanged", "test_ids": [1, 2]}
            expected_data = {
                "test_id": 1,
                "test_str": "unchanged",
                "test_ids": [1, 2],
                "test": "first user",
                "tests": ["first user", "second user"],
            }
            final_data = cache_manager.replace_ids_change(data, user_fields=["test_id", "test_ids"])

            assert final_data == expected_data

        def test_with_organization_fields(self, cache_manager, mocker):
            mocker.patch.object(cache_manager, "organization", side_effect=self.organization_id_to_name)

            data = {"test_id": 100, "test_str": "unchanged", "test_ids": [100, 200]}
            expected_data = {
                "test_id": 100,
                "test_str": "unchanged",
                "test_ids": [100, 200],
                "test": "first organization",
                "tests": ["first organization", "second organization"],
            }
            final_data = cache_manager.replace_ids_change(data, organization_fields=["test_id", "test_ids"])

            assert final_data == expected_data

        def test_both(self, cache_manager, mocker):
            mocker.patch.object(cache_manager, "user", side_effect=self.user_id_to_name)
            mocker.patch.object(cache_manager, "organization", side_effect=self.organization_id_to_name)

            data = {
                "user_id": 1,
                "test_str": "unchanged",
                "user_ids": [1, 2],
                "organization_id": 100,
                "organization_ids": [100, 200],
            }
            expected_data = {
                "user_id": 1,
                "test_str": "unchanged",
                "user_ids": [1, 2],
                "user": "first user",
                "users": ["first user", "second user"],
                "organization_id": 100,
                "organization_ids": [100, 200],
                "organization": "first organization",
                "organizations": ["first organization", "second organization"],
            }
            final_data = cache_manager.replace_ids_change(
                data, organization_fields=["organization_id", "organization_ids"], user_fields=["user_id", "user_ids"]
            )

            assert final_data == expected_data

    def test_data_property(self, cache_manager, mocker):
        data_is_not_empty = "data is not empty"
        assert cache_manager._data is None
        mocker.patch.object(demisto, "getIntegrationContext", return_value=data_is_not_empty)
        assert cache_manager.data == data_is_not_empty

    class TestUsage:
        class TestUser:
            def test_get_when_missing_localy(self, cache_manager, requests_mock):
                requests_mock.get(full_url("users/1"), json=get_json_file("single_user"))
                assert cache_manager.user(1) == "single_user@example.com"

            def test_get_when_existing_localy(self, cache_manager, mocker):
                mocker.patch.object(demisto, "getIntegrationContext", return_value={"users": {1: "single_user@example.com"}})
                assert cache_manager.user(1) == "single_user@example.com"

            def test_when_something_is_flacky(self, cache_manager):
                assert cache_manager.user(10) == 10

        class TestOrganization:
            def test_get_when_missing_localy(self, cache_manager, requests_mock):
                requests_mock.get(full_url("organizations/100"), json=get_json_file("single_organization"))
                assert cache_manager.organization(100) == "single_organization"

            def test_get_when_existing_localy(self, cache_manager, mocker):
                mocker.patch.object(
                    demisto, "getIntegrationContext", return_value={"organizations": {100: "single_organization"}}
                )
                assert cache_manager.organization(100) == "single_organization"

        class TestOrganizationName:
            def test_when_one_orgainzation_exist(self, cache_manager, requests_mock):
                requests_mock.get(full_url("organizations/autocomplete"), json=get_json_file("one_orgainzation"))
                assert cache_manager.organization_name("first") == 100

            def test_when_more_than_one_orgainzation_exist(self, cache_manager, requests_mock):
                organizations_mock = requests_mock.get(
                    full_url("organizations/autocomplete"), json=get_json_file("two_orgainzations")
                )
                with pytest.raises(AssertionError):
                    cache_manager.organization_name("first")
                assert organizations_mock.called_once

            def test_when_orgainzation_dosnt_exist(self, cache_manager, requests_mock):
                organizations_mock = requests_mock.get(
                    full_url("organizations/autocomplete"), json=get_json_file("no_orgainzations")
                )
                with pytest.raises(AssertionError):
                    cache_manager.organization_name("first")
                assert organizations_mock.called_once


@freeze_time(datetime.fromtimestamp(1640995200))
def test_datetime_to_iso():
    assert datetime_to_iso(datetime.now()) == "2022-01-01T00:00:00Z"


class TestPrepareKwargs:
    json_args: Optional[Union[str, List[str]]] = []

    def test_ignore_args(self):
        data = {"test": [[[[["test"]]]]]}
        expected = {"test": [[[[["test"]]]]]}
        assert expected == prepare_kwargs(data, ignore_args="test")
        assert expected == prepare_kwargs(data, ignore_args=["test"])
        assert prepare_kwargs({}, ignore_args=["test", "test2", "test3"]) == {}

    def test_str_args(self):
        data = {"test": 1}
        expected = {"test": "1"}
        assert expected == prepare_kwargs(data, str_args="test")
        data = {"test": 1, "test2": "2"}
        expected = {"test": "1", "test2": "2"}
        assert expected == prepare_kwargs(data, str_args=["test", "test2"])
        assert prepare_kwargs({}, str_args=["test", "test2", "test3"]) == {}

    def test_list_args(self):
        data = {"test": "1"}
        expected = {"test": ["1"]}
        assert expected == prepare_kwargs(data, list_args="test")
        data = {"test": "1", "test2": "1,2", "test3": [1, 2, 3]}
        expected = {"test": ["1"], "test2": ["1", "2"], "test3": [1, 2, 3]}
        assert expected == prepare_kwargs(data, list_args=["test", "test2", "test3"])
        assert prepare_kwargs({}, list_args=["test", "test2", "test3"]) == {}

    def test_bool_args(self):
        data = {"test": "yes"}
        expected = {"test": True}
        assert expected == prepare_kwargs(data, bool_args="test")
        data = {"test": "yes", "test2": "false", "test3": True}
        expected = {"test": True, "test2": False, "test3": True}
        assert expected == prepare_kwargs(data, bool_args=["test", "test2", "test3"])
        assert prepare_kwargs({}, bool_args=["test", "test2", "test3"]) == {}

    def test_int_args(self):
        data = {"test": "1"}
        expected = {"test": 1}
        assert expected == prepare_kwargs(data, int_args="test")
        data = {"test": 1, "test2": "2", "test3": 3.0}
        expected = {"test": 1, "test2": 2, "test3": 3}
        assert expected == prepare_kwargs(data, int_args=["test", "test2", "test3"])
        assert prepare_kwargs({}, int_args=["test", "test2", "test3"]) == {}

    def test_json_args(self):
        data = {"test": "{}"}
        expected = {"test": {}}
        assert expected == prepare_kwargs(data, json_args="test")
        data = {"test": {"test": "test"}, "test2": '{"test": "test"}'}
        expected = {"test": {"test": "test"}, "test2": {"test": "test"}}
        assert expected == prepare_kwargs(data, json_args=["test", "test2"])
        assert prepare_kwargs({}, json_args=["test", "test2", "test3"]) == {}


def test_error_entry():
    msg = "the error"
    expected_entry = {
        "Type": EntryType.ERROR,
        "ContentsFormat": EntryFormat.TEXT,
        "Contents": msg,
    }
    assert expected_entry == error_entry(msg)


class TestValidators:
    data_test__validate_with_valid = [
        ("test", ["test", "not", "relevant"]),
        ("test,relevant", ["test", "relevant"]),
        (["test", "relevant"], ["test", "relevant"]),
    ]

    @pytest.mark.parametrize("val, aloowed", data_test__validate_with_valid)
    def test__validate_with_valid(self, val, aloowed):
        Validators._validate(val, "not relevant", aloowed)

    def test__validate_with_invalid(self):
        msg_part = "this should be also in the error."
        with pytest.raises(AssertionError, match=msg_part):
            Validators._validate("not valid", msg_part, ["this", "will", "be", "invalid"])

    data_test_all_valid = [
        ("end-user", Validators.validate_role),
        ("custom_agent", Validators.validate_role_type),
        ("assigned", Validators.validate_ticket_filter),
        ("urgent", Validators.validate_ticket_priority),
        ("id_asc", Validators.validate_ticket_sort),
        ("open", Validators.validate_ticket_status),
        ("problem", Validators.validate_ticket_type),
    ]

    @pytest.mark.parametrize("value, function", data_test_all_valid)
    def test_all_valid(self, value, function):
        function(value)

    @pytest.mark.parametrize("function", (x[1] for x in data_test_all_valid))
    def test_all_invalid(self, function):
        with pytest.raises(AssertionError):
            function("invalid")


class TestUpdatedTickets:
    def test_first_run(self, zendesk_client):
        updated_tickets = UpdatedTickets(zendesk_client, int(datetime.now().timestamp()))
        assert "start_time" in updated_tickets.query_params()
        assert "after_cursor" not in updated_tickets.query_params()

    def test_tickets_without_data(self, zendesk_client, requests_mock):
        requests_mock.get(full_url("incremental/tickets/cursor"), json=get_json_file("ticket_events/no_ticket_events"))
        updated_tickets = UpdatedTickets(zendesk_client, int(datetime.now().timestamp()))
        assert len(list(updated_tickets.tickets())) == 0

    def test_tickets_with_updated_only(self, zendesk_client, requests_mock):
        requests_mock.get(full_url("incremental/tickets/cursor"), json=get_json_file("ticket_events/updated_only_ticket_events"))
        updated_tickets = UpdatedTickets(zendesk_client, int(datetime.now().timestamp()))
        assert len(list(updated_tickets.tickets())) == 2
        assert (
            updated_tickets.query_params()["cursor"] == get_json_file("ticket_events/updated_only_ticket_events")["after_cursor"]
        )

    def test_tickets_with_mixed_events(self, zendesk_client, requests_mock):
        requests_mock.get(full_url("incremental/tickets/cursor"), json=get_json_file("ticket_events/mixed_ticket_events"))
        updated_tickets = UpdatedTickets(zendesk_client, int(datetime.now().timestamp()))
        assert len(list(updated_tickets.tickets())) == 1
        assert updated_tickets.query_params()["cursor"] == get_json_file("ticket_events/mixed_ticket_events")["after_cursor"]


class TestZendeskClient:
    class TestHTTPRequest:
        @staticmethod
        @pytest.fixture
        def default_kwargs():
            return {
                "data": None,
                "full_url": None,
                "json_data": None,
                "resp_type": "json",
                "return_empty_response": False,
                "url_suffix": "",
                "error_handler": ZendeskClient.error_handler,
            }

        def test_without_params(self, zendesk_client, mocker, default_kwargs):
            base_client_http = mocker.patch.object(BaseClient, "_http_request")
            zendesk_client._http_request("GET", url_suffix="test_without_params")
            default_kwargs = default_kwargs | {"url_suffix": "test_without_params"}
            base_client_http.assert_called_once_with("GET", **default_kwargs)

        def test_with_params(self, zendesk_client, mocker, default_kwargs):
            base_client_http = mocker.patch.object(BaseClient, "_http_request")
            zendesk_client._http_request("GET", url_suffix="test_without_params", params={"test": "test"})
            default_kwargs = default_kwargs | {"url_suffix": "test_without_params?test=test"}
            base_client_http.assert_called_once_with("GET", **default_kwargs)

        def test_with_list_in_params(self, zendesk_client, mocker, default_kwargs):
            base_client_http = mocker.patch.object(BaseClient, "_http_request")
            zendesk_client._http_request("GET", url_suffix="test_without_params", params={"test": ["test", "test2"]})
            default_kwargs = default_kwargs | {"url_suffix": "test_without_params?test[]=test&test[]=test2"}
            base_client_http.assert_called_once_with("GET", **default_kwargs)

        def test_with_params_in_full_url(self, zendesk_client, mocker, default_kwargs):
            base_client_http = mocker.patch.object(BaseClient, "_http_request")
            zendesk_client._http_request("GET", full_url=full_url("test_without_params"), params={"test": "test"})
            default_kwargs = default_kwargs | {"full_url": full_url("test_without_params?test=test")}
            base_client_http.assert_called_once_with("GET", **default_kwargs)

    class TestCursorPagination:
        def test_without_data(self, zendesk_client, requests_mock, mocker):
            cursor_request = mocker.patch.object(
                zendesk_client, "_ZendeskClient__cursor_pagination", side_effect=zendesk_client._ZendeskClient__cursor_pagination
            )
            requests_mock.get(full_url("cursor"), json={"data_type": [], "links": {"next": None}, "meta": {"has_more": False}})
            data = list(zendesk_client._paged_request("cursor", "data_type"))
            assert data == []
            cursor_request.assert_called_once()

        def test_with_multiple_pages_with_unlimited_data(self, zendesk_client, requests_mock, mocker):
            cursor_request = mocker.patch.object(
                zendesk_client, "_ZendeskClient__cursor_pagination", side_effect=zendesk_client._ZendeskClient__cursor_pagination
            )
            requests_mock.get(
                full_url("cursor"),
                json={"data_type": ["data"], "links": {"next": full_url("cursor2")}, "meta": {"has_more": True}},
            )
            requests_mock.get(full_url("cursor2"), json={"data_type": ["data2", "data3"]})
            data = list(zendesk_client._paged_request("cursor", "data_type"))
            assert data == ["data", "data2", "data3"]
            cursor_request.assert_called_once()

        def test_with_single_page_and_unlimited_data(self, zendesk_client, requests_mock, mocker):
            cursor_request = mocker.patch.object(
                zendesk_client, "_ZendeskClient__cursor_pagination", side_effect=zendesk_client._ZendeskClient__cursor_pagination
            )
            requests_mock.get(
                full_url("cursor"),
                json={
                    "data_type": ["data"] * 3,
                },
            )
            data = list(zendesk_client._paged_request("cursor", "data_type"))
            assert data == ["data", "data", "data"]
            cursor_request.assert_called_once()

        def test_with_single_page_and_limited_data(self, zendesk_client, requests_mock, mocker):
            cursor_request = mocker.patch.object(
                zendesk_client, "_ZendeskClient__cursor_pagination", side_effect=zendesk_client._ZendeskClient__cursor_pagination
            )
            requests_mock.get(
                full_url("cursor"),
                json={
                    "data_type": ["data"] * 3,
                },
            )
            data = list(zendesk_client._paged_request("cursor", "data_type", limit=2))
            assert data == ["data", "data"]
            cursor_request.assert_called_once()

        def test_with_multiple_pages_with_limited_data(self, zendesk_client, requests_mock, mocker):
            cursor_request = mocker.patch.object(
                zendesk_client, "_ZendeskClient__cursor_pagination", side_effect=zendesk_client._ZendeskClient__cursor_pagination
            )
            requests_mock.get(
                full_url("cursor"),
                json={"data_type": ["data"], "links": {"next": full_url("cursor2")}, "meta": {"has_more": True}},
            )
            requests_mock.get(full_url("cursor2"), json={"data_type": ["data2", "data3"]})
            data = list(zendesk_client._paged_request("cursor", "data_type", limit=2))
            assert data == ["data", "data2"]
            cursor_request.assert_called_once()

    class TestOffsetPagination:
        def test_without_data(self, zendesk_client, requests_mock, mocker):
            offset_request = mocker.patch.object(
                zendesk_client, "_ZendeskClient__get_spesific_page", side_effect=zendesk_client._ZendeskClient__get_spesific_page
            )
            requests_mock.get(
                full_url("offset"),
                json={
                    "data_type": [],
                },
            )
            data = list(zendesk_client._paged_request("offset", "data_type", page_size=50, page_number=0))
            assert data == []
            offset_request.assert_called_once()

        def test_with_single_page_and_unlimited_data(self, zendesk_client, requests_mock, mocker):
            offset_request = mocker.patch.object(
                zendesk_client, "_ZendeskClient__get_spesific_page", side_effect=zendesk_client._ZendeskClient__get_spesific_page
            )
            requests_mock.get(
                full_url("offset"),
                json={
                    "data_type": ["data"] * 3,
                },
            )
            data = list(zendesk_client._paged_request("offset", "data_type", page_size=50, page_number=0))
            assert data == ["data", "data", "data"]
            offset_request.assert_called_once()

    def test_paged_request_with_invalid_args(self, zendesk_client):
        with pytest.raises(AssertionError):
            zendesk_client._paged_request("offset", "data_type", page_number=0)

        with pytest.raises(AssertionError):
            zendesk_client._paged_request("offset", "data_type", page_size=50)

    def test_command_results_zendesk_users(self, mocker, cache_manager):
        Zendeskv2.CACHE = cache_manager
        mocker.patch.object(Zendeskv2.CACHE, "replace_ids_change", side_effect=lambda x, *args: x)
        assert (
            Zendeskv2.ZendeskClient._ZendeskClient__command_results_zendesk_users([{"role_type": 0}]).outputs[0]["role_type"]
            == "custom_agent"
        )

    class TestZendeskUserList:
        def test_with_specific_user(self, zendesk_client, requests_mock, mocker):
            demisto_error = mocker.patch.object(demisto, "error")
            requests_mock.get(full_url("users/1"), json=get_json_file("users/1"))
            outputs = zendesk_client.zendesk_user_list(user_id=1)[0].outputs
            demisto_error.assert_not_called()
            assert len(outputs) == 1
            assert outputs[0]["id"] == 1

        def test_error_with_specific_user(self, zendesk_client, requests_mock, mocker):
            demisto_error = mocker.patch.object(demisto, "error")
            requests_mock.get(full_url("users/1"), status_code=404, reason="Not found")
            outputs = zendesk_client.zendesk_user_list(user_id=1)
            demisto_error.assert_called()
            assert len(outputs) == 1
            assert outputs[0]["Type"] == EntryType.ERROR

        def test_with_list_of_users(self, zendesk_client, requests_mock, mocker):
            demisto_error = mocker.patch.object(demisto, "error")
            requests_mock.get(full_url("users/1"), json=get_json_file("users/1"))
            requests_mock.get(full_url("users/2"), json=get_json_file("users/2"))
            outputs = zendesk_client.zendesk_user_list(user_id="1,2")[0].outputs
            demisto_error.assert_not_called()
            assert len(outputs) == 2
            assert outputs[0]["id"] == 1
            assert outputs[1]["id"] == 2

        def test_with_list_of_users_end_mixed_errors(self, zendesk_client, requests_mock, mocker):
            demisto_error = mocker.patch.object(demisto, "error")
            requests_mock.get(full_url("users/1"), json=get_json_file("users/1"))
            requests_mock.get(full_url("users/2"), json=get_json_file("users/2"))
            outputs = zendesk_client.zendesk_user_list(user_id="1,2,3")
            demisto_error.assert_called_once()
            assert len(outputs) == 2
            assert outputs[0].outputs[0]["id"] == 1
            assert outputs[0].outputs[1]["id"] == 2
            assert outputs[1]["Type"] == EntryType.ERROR

        def test_general_call_with_empty_response(self, zendesk_client, requests_mock, mocker):
            demisto_error = mocker.patch.object(demisto, "error")
            requests_mock.get(full_url("users"), json={"users": []})
            output = zendesk_client.zendesk_user_list()
            assert output == "No outputs."
            demisto_error.assert_not_called()

        def test_general_call(self, zendesk_client, requests_mock, mocker):
            demisto_error = mocker.patch.object(demisto, "error")
            user_1 = get_json_file("users/1")["user"]
            user_2 = get_json_file("users/2")["user"]
            requests_mock.get(full_url("users"), json={"users": [user_1, user_2]})
            outputs = zendesk_client.zendesk_user_list()[0].outputs
            demisto_error.assert_not_called()
            assert len(outputs) == 2
            assert outputs[0]["id"] == 1
            assert outputs[1]["id"] == 2

        def test_with_user_name(self, zendesk_client, requests_mock):
            mocked_request = requests_mock.get(full_url("users/autocomplete"), json={"users": []})
            zendesk_client.zendesk_user_list(user_name="test")
            assert mocked_request.called_once

        def test_general_with_specific_roles(self, zendesk_client, requests_mock):
            mocked_request = requests_mock.get(full_url("users"), json={"users": []})
            zendesk_client.zendesk_user_list(role="admin")
            assert "role=admin" in mocked_request.last_request.query

    class TestZendeskUserOperations:
        def test_zendesk_user_create(self, zendesk_client, requests_mock):
            post_users = requests_mock.post(full_url("users/create_or_update"), json=get_json_file("users/1"))
            zendesk_client.zendesk_user_create(name="user name", email="user@email.com")
            assert post_users.called_once

        def test_zendesk_user_create_and_check_if_user_exists(self, zendesk_client, requests_mock):
            post_users = requests_mock.post(full_url("users/create"), json=get_json_file("users/1"))
            zendesk_client.zendesk_user_create(name="user name", email="user@email.com", check_if_user_exists=True)
            assert post_users.called_once

        def test_zendesk_user_create_with_specifict_role(self, zendesk_client, requests_mock, mocker):
            validate_role_mock = mocker.patch.object(Validators, "validate_role")
            post_users = requests_mock.post(full_url("users/create_or_update"), json=get_json_file("users/1"))
            zendesk_client.zendesk_user_create(name="user name", email="user@email.com", role="admin")
            validate_role_mock.assert_called_once_with("admin")
            assert post_users.called_once

        def test_zendesk_user_create_with_specifict_role_type(self, zendesk_client, requests_mock):
            post_users = requests_mock.post(full_url("users/create_or_update"), json=get_json_file("users/1"))
            zendesk_client.zendesk_user_create(name="user name", email="user@email.com", role="agent", role_type="chat_agent")
            assert post_users.called_once

        def test_zendesk_user_create_with_specifict_invalid_role_type(self, zendesk_client):
            with pytest.raises(AssertionError):
                zendesk_client.zendesk_user_create(name="user name", email="user@email.com", role="agent", role_type="invalid")

        def test_zendesk_user_create_with_org_name(self, zendesk_client, requests_mock, mocker, cache_manager):
            post_users = requests_mock.post(full_url("users/create_or_update"), json=get_json_file("users/1"))
            Zendeskv2.CACHE = cache_manager
            org_id = 100
            mocker.patch.object(Zendeskv2.CACHE, "organization_name", return_value=org_id)
            zendesk_client.zendesk_user_create(name="user name", email="user@email.com", organization_name="org_name")
            assert post_users.called_once
            assert post_users.last_request.json()["user"]["organization_id"] == org_id

        def test_assert_raise_for_org_name_and_id_zendesk_user_create(self, zendesk_client):
            with pytest.raises(AssertionError):
                zendesk_client.zendesk_user_create(
                    name="user name", email="user@email.com", organization_name="org_name", organization_id="org_id"
                )

        def test_assert_raise_for_org_name_and_id_zendesk_user_update(self, zendesk_client):
            with pytest.raises(AssertionError):
                zendesk_client.zendesk_user_update(user_id=1, organization_name="org_name", organization_id="org_id")

        def test_zendesk_user_update_with_specifict_role_type(self, zendesk_client, requests_mock):
            post_users = requests_mock.put(full_url("users/1"), json=get_json_file("users/1"))
            zendesk_client.zendesk_user_update(user_id=1, role="agent", role_type="chat_agent")
            assert post_users.called_once

        def test_zendesk_user_update_with_org_name(self, zendesk_client, requests_mock, mocker, cache_manager):
            post_users = requests_mock.put(full_url("users/1"), json=get_json_file("users/1"))
            Zendeskv2.CACHE = cache_manager
            org_id = 100
            mocker.patch.object(Zendeskv2.CACHE, "organization_name", return_value=org_id)
            zendesk_client.zendesk_user_update(user_id=1, organization_name="org_name")
            assert post_users.called_once
            assert post_users.last_request.json()["user"]["organization_id"] == org_id

        def test_zendesk_organization_list_with_org_id(self, zendesk_client, mocker):
            mock_zendesk_organization_by_id = mocker.patch.object(zendesk_client, "_get_organization_by_id")
            mocker.patch.object(zendesk_client, "_ZendeskClient__command_results_zendesk_organizations")
            zendesk_client.zendesk_organization_list(organization_id=100)
            mock_zendesk_organization_by_id.assert_called_once_with(100)

        def test_zendesk_organization_list_general(self, zendesk_client, mocker):
            mock_zendesk_organization_general = mocker.patch.object(zendesk_client, "_paged_request")
            mocker.patch.object(zendesk_client, "_ZendeskClient__command_results_zendesk_organizations")
            zendesk_client.zendesk_organization_list()
            mock_zendesk_organization_general.assert_called_once()

        def test_zendesk_group_users_list_general(self, zendesk_client, mocker):
            mock_zendesk_organization_general = mocker.patch.object(zendesk_client, "_paged_request")
            mocker.patch.object(zendesk_client, "_ZendeskClient__command_results_zendesk_group_users")
            zendesk_client.list_group_users(group_id=100)
            mock_zendesk_organization_general.assert_called_once()

    class TestTicketList:
        def test_with_ticket_id(self, zendesk_client, requests_mock):
            ticket_mock = requests_mock.get(full_url("tickets/10"), json=get_json_file("tickets/10"))
            out = zendesk_client.zendesk_ticket_list(ticket_id="10")
            assert ticket_mock.called_once
            assert len(out) == 1
            assert out[0].outputs[0]["id"] == 10

        def test_with_multiple_ticket_ids(self, zendesk_client, requests_mock):
            ticket_mock_10 = requests_mock.get(full_url("tickets/10"), json=get_json_file("tickets/10"))
            ticket_mock_20 = requests_mock.get(full_url("tickets/20"), json=get_json_file("tickets/20"))
            out = zendesk_client.zendesk_ticket_list(ticket_id="10,20")
            assert ticket_mock_10.called_once
            assert ticket_mock_20.called_once
            assert len(out) == 1
            assert out[0].outputs[0]["id"] == 10
            assert out[0].outputs[1]["id"] == 20

        def test_with_multiple_ticket_ids_and_mixed_errors(self, zendesk_client, requests_mock, mocker):
            demisto_error = mocker.patch.object(demisto, "error")
            ticket_mock_10 = requests_mock.get(full_url("tickets/10"), json=get_json_file("tickets/10"))
            ticket_mock_20 = requests_mock.get(full_url("tickets/20"), status_code=404, reason="Not found")
            out = zendesk_client.zendesk_ticket_list(ticket_id="10,20")
            assert ticket_mock_10.called_once
            assert ticket_mock_20.called_once
            assert len(out) == 2
            assert out[0].outputs[0]["id"] == 10
            demisto_error.assert_called_once()

        filters = [
            (None, None, "tickets"),
            ("recent", None, "tickets/recent"),
            ("assigned", 10, "users/10/tickets/assigned"),
            ("requested", 10, "users/10/tickets/requested"),
            ("ccd", 10, "users/10/tickets/ccd"),
            ("followed", 10, "users/10/tickets/followed"),
        ]

        @pytest.mark.parametrize("filter_,user_id,url", filters)
        def test_with_filters(self, zendesk_client, requests_mock, filter_, user_id, url):
            url_mock = requests_mock.get(full_url(url), json={"tickets": []})
            zendesk_client.zendesk_ticket_list(user_id=user_id, filter=filter_)
            assert url_mock.called_once

        def test_with_invalid_filter(self, zendesk_client):
            with pytest.raises(AssertionError):
                zendesk_client.zendesk_ticket_list(user_id=10, filter="filter_")

        filters_that_requires_user_id = ["assigned", "requested", "ccd", "followed"]

        @pytest.mark.parametrize("filter_", filters_that_requires_user_id)
        def test_with_filter_that_requires_user_id_without_providing(self, zendesk_client, filter_):
            with pytest.raises(AssertionError):
                zendesk_client.zendesk_ticket_list(filter=filter_)

        sorts_with_cursor = [
            ("id_asc", "id"),
            ("status_asc", "status"),
            ("updated_at_asc", "updated_at"),
            ("id_desc", "-id"),
            ("status_desc", "-status"),
            ("updated_at_desc", "-updated_at"),
        ]

        @pytest.mark.parametrize("sort,api_sort", sorts_with_cursor)
        def test_sort_ticket_list_with_cursor(self, zendesk_client, requests_mock, sort, api_sort):
            request_mock = requests_mock.get(full_url("tickets"), json={"tickets": []})
            zendesk_client.zendesk_ticket_list(sort=sort)
            assert api_sort in request_mock.last_request.query

        def test_invalid_sort_ticket_list_with_page_size(self, zendesk_client):
            with pytest.raises(AssertionError):
                zendesk_client.zendesk_ticket_list(sort="invalid")

        sorts_with_offset = [
            ("id_asc", "sort_by=id&sort_order=asc"),
            ("status_asc", "sort_by=status&sort_order=asc"),
            ("updated_at_asc", "sort_by=updated_at&sort_order=asc"),
            ("id_desc", "sort_by=id&sort_order=desc"),
            ("status_desc", "sort_by=status&sort_order=desc"),
            ("updated_at_desc", "sort_by=updated_at&sort_order=desc"),
        ]

        @pytest.mark.parametrize("sort,api_sort", sorts_with_offset)
        def test_sort_ticket_list_with_offset(self, zendesk_client, requests_mock, sort, api_sort):
            request_mock = requests_mock.get(full_url("tickets"), json={"tickets": []})
            zendesk_client.zendesk_ticket_list(page_number=0, page_size=1, sort=sort)
            assert api_sort in request_mock.last_request.query

        def test_invalid_sort_ticket_list_with_page_offset(self, zendesk_client):
            with pytest.raises(AssertionError):
                zendesk_client.zendesk_ticket_list(page_number=0, page_size=1, sort="invalid")

    class TestTicketClass:
        def test__iter__(self):
            data = {"test": "test", "test2": "test2"}
            ticket = ZendeskClient.Ticket()
            ticket._data = data
            assert dict(ticket) == data

        @pytest.mark.parametrize("intable_one", [1, 1.1, "1"])
        def test_try_int_with_intable(self, intable_one):
            assert isinstance(ZendeskClient.Ticket.try_int(intable_one), int)

        @pytest.mark.parametrize("not_intable_val", ["test", ZendeskClient.Ticket()])
        def test_try_int_with_not_intable(self, not_intable_val):
            assert not isinstance(ZendeskClient.Ticket.try_int(not_intable_val), int)

        data_test_follower_and_email_cc_parsed = [
            ("10", {"user_id": "10"}),
            ("10:put", {"user_id": "10", "action": "put"}),
            ("email", {"user_email": "email"}),
            ("email:put", {"user_email": "email", "action": "put"}),
        ]

        @pytest.mark.parametrize("input_str, expected_output", data_test_follower_and_email_cc_parsed)
        def test_follower_and_email_cc_parsed(self, input_str, expected_output):
            assert ZendeskClient.Ticket.follower_and_email_cc_parse(input_str) == expected_output


class TestFetchIncidents:
    """ticket_priority: str = None, ticket_status: str = None, ticket_types: str = None, **_)"""

    data_test_fetch_query_builder = [
        ({}, ""),
        ({"ticket_priority": "all"}, ""),
        ({"ticket_priority": "all", "ticket_status": "all", "ticket_types": "all"}, ""),
        ({"test": "test"}, ""),
        ({"ticket_priority": "low,high"}, "priority:low priority:high"),
        ({"ticket_priority": "low"}, "priority:low"),
        ({"ticket_status": "new,open"}, "status:new status:open"),
        ({"ticket_status": "new"}, "status:new"),
        ({"ticket_types": "question,incident"}, "ticket_type:question ticket_type:incident"),
        ({"ticket_types": "incident"}, "ticket_type:incident"),
        ({"ticket_types": "question,incident", "ticket_priority": "all"}, "ticket_type:question ticket_type:incident"),
    ]

    @pytest.mark.parametrize("args, expected_outputs", data_test_fetch_query_builder)
    def test_fetch_query_builder(self, args, expected_outputs):
        assert ZendeskClient._fetch_query_builder(**args) == expected_outputs

    data_test_fetch_args = [
        ({}, {}, deque([]), "2023-01-12T12:00:00Z", "created", "", 50, 1),
        ({}, {"fetched_tickets": [1, 2]}, deque([1, 2]), "2023-01-12T12:00:00Z", "created", "", 50, 1),
        ({"first_fetch": "1 year"}, {"fetched_tickets": [1, 2]}, deque([1, 2]), "2022-01-15T12:00:00Z", "created", "", 50, 1),
        ({}, {"fetched_tickets": [1, 2], "query": "status:open"}, deque([1, 2]), "2023-01-12T12:00:00Z", "created", "", 50, 1),
        (
            {},
            {"fetched_tickets": [1, 2], "query": "status:open", "page_number": 2},
            deque([1, 2]),
            "2023-01-12T12:00:00Z",
            "created",
            "",
            50,
            1,
        ),
        (
            {"fetch_query": "status:open"},
            {"fetched_tickets": [1, 2], "query": "status:open", "time_filter": "created", "page_number": 2},
            deque([1, 2]),
            "2023-01-12T12:00:00Z",
            "created",
            "status:open",
            50,
            2,
        ),
        (
            {"fetch_query": "status:open"},
            {"fetched_tickets": [1, 2], "query": "status:open", "time_filter": "updated", "page_number": 2},
            deque([1, 2]),
            "2023-01-12T12:00:00Z",
            "created",
            "status:open",
            50,
            1,
        ),
        (
            {"fetch_query": "status:open", "time_filter": "updated-at"},
            {"fetched_tickets": [1, 2], "query": "status:open", "time_filter": "updated", "page_number": 2},
            deque([1, 2]),
            "2023-01-12T12:00:00Z",
            "updated",
            "status:open",
            50,
            2,
        ),
        (
            {"fetch_query": "status:open", "time_filter": "updated-at"},
            {"fetched_tickets": [1, 2], "query": "status:open", "time_filter": "updated", "page_number": 2, "max_fetch": 3},
            deque([1, 2]),
            "2023-01-12T12:00:00Z",
            "updated",
            "status:open",
            3,
            2,
        ),
        (
            {"fetch_query": "status:open", "time_filter": "updated-at", "max_fetch": 4},
            {"fetched_tickets": [1, 2], "query": "status:open", "time_filter": "updated", "page_number": 2, "max_fetch": 3},
            deque([1, 2]),
            "2023-01-12T12:00:00Z",
            "updated",
            "status:open",
            3,
            2,
        ),
    ]
    test_fetch_args_parametrize_str = (
        "params, last_run, expected_fetched_tickets, expected_last_fetch, "
        "expected_time_filter, expected_query, expected_max_fetch, expected_page_number"
    )

    @freeze_time("2023-01-15T12:00:00Z")
    @pytest.mark.parametrize(test_fetch_args_parametrize_str, data_test_fetch_args)
    def test_fetch_args(
        self,
        params,
        last_run,
        expected_fetched_tickets,
        expected_last_fetch,
        expected_time_filter,
        expected_query,
        expected_max_fetch,
        expected_page_number,
    ):
        fetched_tickets, last_fetch, time_filter, query, max_fetch, page_number, get_attachments = ZendeskClient._fetch_args(
            params, last_run
        )
        assert fetched_tickets == expected_fetched_tickets
        assert last_fetch == expected_last_fetch
        assert time_filter == expected_time_filter
        assert query == expected_query
        assert max_fetch == expected_max_fetch
        assert page_number == expected_page_number

    def test_invalid_first_fetch(self):
        with pytest.raises(DemistoException):
            ZendeskClient._fetch_args({"first_fetch": "invalid"}, {})

    data_test_next_fetch_args = [
        (
            deque([]),
            [1, 2],
            "",
            "created",
            50,
            1,
            {
                "fetch_time": "2023-01-15T12:00:00Z",
                "fetched_tickets": [],
            },
        ),
        (
            deque([1, 2]),
            [1, 2],
            "",
            "created",
            50,
            1,
            {
                "fetch_time": "2023-01-15T12:00:00Z",
                "fetched_tickets": [1, 2],
            },
        ),
        (
            deque([1, 2]),
            [1, 2],
            "",
            "created",
            2,
            1,
            {
                "fetch_time": "2023-01-15T11:00:00Z",
                "fetched_tickets": [1, 2],
                "query": "",
                "time_filter": "created",
                "max_fetch": 2,
                "page_number": 2,
            },
        ),
        (
            deque([1, 2]),
            [1, 2],
            "a query",
            "created",
            50,
            1,
            {
                "fetch_time": "2023-01-15T12:00:00Z",
                "fetched_tickets": [1, 2],
            },
        ),
        (
            deque([1, 2]),
            [1, 2],
            "a query",
            "created",
            2,
            1,
            {
                "fetch_time": "2023-01-15T11:00:00Z",
                "fetched_tickets": [1, 2],
                "query": "a query",
                "time_filter": "created",
                "max_fetch": 2,
                "page_number": 2,
            },
        ),
        (
            deque(list(range(2000))),
            [1, 2],
            "a query",
            "created",
            2,
            1,
            {
                "fetch_time": "2023-01-15T11:00:00Z",
                "fetched_tickets": list(range(1000, 2000)),
                "query": "a query",
                "time_filter": "created",
                "max_fetch": 2,
                "page_number": 2,
            },
        ),
    ]
    test_next_fetch_args_parametrize_str = (
        "fetched_tickets, search_results_ids, query, time_filter, max_fetch, page_number, expected_next_run_args"
    )

    @pytest.mark.parametrize(test_next_fetch_args_parametrize_str, data_test_next_fetch_args)
    def test_next_fetch_args(
        self, fetched_tickets, search_results_ids, query, time_filter, max_fetch, page_number, expected_next_run_args
    ):
        assert (
            ZendeskClient._next_fetch_args(
                fetched_tickets,
                search_results_ids,
                dateparser.parse("2023-01-15T12:00:00Z", settings={"TIMEZONE": "UTC"}),
                query,
                time_filter,
                max_fetch,
                page_number,
                "2023-01-15T11:00:00Z",
            )
            == expected_next_run_args
        )

    class TestFetchFlow:
        @freeze_time("2023-01-15T12:00:00Z")
        def test_initial_flow(self, mocker, zendesk_client, requests_mock):
            ticket_mock_10 = requests_mock.get(full_url("tickets/10"), json=get_json_file("tickets/10"))
            ticket_mock_20 = requests_mock.get(full_url("tickets/20"), json=get_json_file("tickets/20"))
            mocker.patch.object(demisto, "getLastRun", return_value=None)
            mocker.patch.object(zendesk_client, "_ZendeskClient__zendesk_search_results", return_value=[{"id": 10}, {"id": 20}])
            mocker.patch.object(zendesk_client, "_get_comments", return_value=[])
            mocker.patch.object(zendesk_client, "get_attachment_entries", return_value=[])
            demisto_incidents_mock = mocker.patch.object(demisto, "incidents")
            demisto_set_lust_run_mock = mocker.patch.object(demisto, "setLastRun")
            zendesk_client.fetch_incidents({}, {})
            assert ticket_mock_10.called_once
            assert ticket_mock_20.called_once
            demisto_incidents_mock.assert_called_once()
            assert [json.loads(x["rawJSON"])["id"] for x in demisto_incidents_mock.call_args[0][0]] == [10, 20]
            assert demisto_set_lust_run_mock.call_args[0][0] == {
                "fetched_tickets": [10, 20],
                "fetch_time": "2023-01-15T11:59:00Z",
            }

        @freeze_time("2023-01-15T12:00:00Z")
        def test_continues_fetch_first_part(self, mocker, zendesk_client, requests_mock):
            ticket_mock_10 = requests_mock.get(full_url("tickets/10"), json=get_json_file("tickets/10"))
            ticket_mock_20 = requests_mock.get(full_url("tickets/20"), json=get_json_file("tickets/20"))
            mocker.patch.object(demisto, "getLastRun", return_value=None)
            mocker.patch.object(zendesk_client, "_ZendeskClient__zendesk_search_results", return_value=[{"id": 10}])
            mocker.patch.object(zendesk_client, "_get_comments", return_value=[])
            mocker.patch.object(zendesk_client, "get_attachment_entries", return_value=[])
            demisto_incidents_mock = mocker.patch.object(demisto, "incidents")
            demisto_set_lust_run_mock = mocker.patch.object(demisto, "setLastRun")
            zendesk_client.fetch_incidents({"max_fetch": 1}, {})
            assert ticket_mock_20.call_count == 0
            assert ticket_mock_10.called_once
            demisto_incidents_mock.assert_called_once()
            assert [json.loads(x["rawJSON"])["id"] for x in demisto_incidents_mock.call_args[0][0]] == [10]
            assert demisto_set_lust_run_mock.call_args[0][0] == {
                "max_fetch": 1,
                "page_number": 2,
                "fetched_tickets": [10],
                "query": "",
                "fetch_time": "2023-01-12T12:00:00Z",
                "time_filter": "created",
            }

        @freeze_time("2023-01-15T12:00:00Z")
        def test_continues_fetch_second_part(self, mocker, zendesk_client, requests_mock):
            ticket_mock_10 = requests_mock.get(full_url("tickets/10"), json=get_json_file("tickets/10"))
            ticket_mock_20 = requests_mock.get(full_url("tickets/20"), json=get_json_file("tickets/20"))
            mocker.patch.object(demisto, "getLastRun", return_value=None)
            mocker.patch.object(zendesk_client, "_ZendeskClient__zendesk_search_results", return_value=[{"id": 20}])
            mocker.patch.object(zendesk_client, "_get_comments", return_value=[])
            mocker.patch.object(zendesk_client, "get_attachment_entries", return_value=[])
            demisto_incidents_mock = mocker.patch.object(demisto, "incidents")
            demisto_set_lust_run_mock = mocker.patch.object(demisto, "setLastRun")
            zendesk_client.fetch_incidents(
                {"max_fetch": 1},
                json.dumps(
                    {
                        "max_fetch": 1,
                        "page_number": 3,
                        "fetched_tickets": [10],
                        "query": "",
                        "fetch_time": "2023-01-12T12:00:00Z",
                        "time_filter": "created",
                    }
                ),
            )
            assert ticket_mock_10.call_count == 0
            assert ticket_mock_20.called_once
            demisto_incidents_mock.assert_called_once()
            assert [json.loads(x["rawJSON"])["id"] for x in demisto_incidents_mock.call_args[0][0]] == [20]
            assert demisto_set_lust_run_mock.call_args[0][0] == {
                "max_fetch": 1,
                "page_number": 4,
                "fetched_tickets": [10, 20],
                "query": "",
                "fetch_time": "2023-01-12T12:00:00Z",
                "time_filter": "created",
            }

        @freeze_time("2023-01-15T12:00:00Z")
        def test_continues_fetch_last_part(self, mocker, zendesk_client, requests_mock):
            ticket_mock_10 = requests_mock.get(full_url("tickets/10"), json=get_json_file("tickets/10"))
            ticket_mock_20 = requests_mock.get(full_url("tickets/20"), json=get_json_file("tickets/20"))
            mocker.patch.object(demisto, "getLastRun", return_value=None)
            mocker.patch.object(zendesk_client, "_ZendeskClient__zendesk_search_results", return_value=[])
            mocker.patch.object(zendesk_client, "_get_comments", return_value=[])
            mocker.patch.object(zendesk_client, "get_attachment_entries", return_value=[])
            demisto_incidents_mock = mocker.patch.object(demisto, "incidents")
            demisto_set_lust_run_mock = mocker.patch.object(demisto, "setLastRun")
            zendesk_client.fetch_incidents(
                {"max_fetch": 1},
                json.dumps(
                    {
                        "max_fetch": 1,
                        "page_number": 4,
                        "fetched_tickets": [10, 20],
                        "fetch_time": "2023-01-12T12:00:00Z",
                        "query": "",
                        "time_filter": "created",
                    }
                ),
            )
            assert ticket_mock_10.call_count == ticket_mock_20.call_count == 0
            demisto_incidents_mock.assert_called_once_with([])
            assert demisto_set_lust_run_mock.call_args[0][0] == {
                "fetched_tickets": [10, 20],
                "fetch_time": "2023-01-15T11:59:00Z",
            }

        @freeze_time("2023-01-15T12:00:00Z")
        def test_usual_fetch(self, mocker, zendesk_client, requests_mock):
            ticket_mock_10 = requests_mock.get(full_url("tickets/10"), json=get_json_file("tickets/10"))
            ticket_mock_20 = requests_mock.get(full_url("tickets/20"), json=get_json_file("tickets/20"))
            mocker.patch.object(demisto, "getLastRun", return_value=None)
            mocker.patch.object(zendesk_client, "_ZendeskClient__zendesk_search_results", return_value=[{"id": 20}])
            mocker.patch.object(zendesk_client, "_get_comments", return_value=[])
            mocker.patch.object(zendesk_client, "get_attachment_entries", return_value=[])
            demisto_incidents_mock = mocker.patch.object(demisto, "incidents")
            demisto_set_lust_run_mock = mocker.patch.object(demisto, "setLastRun")
            zendesk_client.fetch_incidents({}, json.dumps({"fetched_tickets": [10], "fetch_time": "2023-01-12T12:00:00Z"}))
            assert ticket_mock_10.call_count == 0
            assert ticket_mock_20.called_once
            demisto_incidents_mock.assert_called_once()
            assert [json.loads(x["rawJSON"])["id"] for x in demisto_incidents_mock.call_args[0][0]] == [20]
            assert demisto_set_lust_run_mock.call_args[0][0] == {
                "fetched_tickets": [10, 20],
                "fetch_time": "2023-01-15T11:59:00Z",
            }

        @freeze_time("2023-01-15T12:00:00Z")
        def test_usual_fetch_with_attachment(self, mocker, zendesk_client, requests_mock):
            fetched_args = ([10], "2023-01-12T12:00:00Z", "2023-01-12T12:00:00Z", "", 50, 1, True)
            ticket_mock_10 = requests_mock.get(full_url("tickets/10"), json=get_json_file("tickets/10"))
            ticket_mock_20 = requests_mock.get(full_url("tickets/20"), json=get_json_file("tickets/20"))
            mocker.patch.object(zendesk_client, "_fetch_args", return_value=fetched_args)
            mocker.patch.object(demisto, "getLastRun", return_value=None)
            mocker.patch.object(zendesk_client, "_ZendeskClient__zendesk_search_results", return_value=[{"id": 20}])
            mocker.patch.object(zendesk_client, "get_attachments_ids", return_value=[1234])
            mocker.patch.object(
                zendesk_client,
                "zendesk_attachment_get",
                return_value={
                    "url": "testurl/api/v2/attachments/11656206786333.json",
                    "id": 11656206786333,
                    "file_name": "TestFile.json",
                    "content_url": "testurl/attachments/token/1234/?name=TestFile.json",
                    "mapped_content_url": "testurl/attachments/token/1234/?name=TestFile.json",
                    "content_type": "application/x-yaml",
                    "size": 44726,
                    "width": None,
                    "height": None,
                    "inline": False,
                    "deleted": False,
                    "malware_access_override": False,
                    "malware_scan_result": "malware_not_found",
                },
            )
            mocker.patch.object(
                zendesk_client,
                "get_file_entries",
                return_value=[
                    {
                        "Contents": "",
                        "ContentsFormat": "text",
                        "Type": 9,
                        "File": "TestFile.json",
                        "FileID": "77fe1c6d-3096-4f1c-80c7-4e7c8573d580",
                    }
                ],
            )
            mocker.patch.object(
                zendesk_client,
                "get_attachment_entries",
                return_value=[{"path": "77fe1c6d-3096-4f1c-80c7-4e7c8573d580", "name": "TestFile.json"}],
            )
            demisto_incidents_mock = mocker.patch.object(demisto, "incidents")
            zendesk_client.fetch_incidents({}, json.dumps({"fetched_tickets": [10], "fetch_time": "2023-01-12T12:00:00Z"}))
            assert ticket_mock_10.call_count == 0
            assert ticket_mock_20.called_once
            demisto_incidents_mock.assert_called_once()
            assert [json.loads(x["rawJSON"])["id"] for x in demisto_incidents_mock.call_args[0][0]] == [20]
            assert demisto_incidents_mock.call_args[0][0][0]["attachment"] == [
                {"path": "77fe1c6d-3096-4f1c-80c7-4e7c8573d580", "name": "TestFile.json"}
            ]


class TestCommandArgumentHandling:
    """Verifies that command methods which accept ``**kwargs`` tolerate the
    canonical, redundant and unexpected keyword arguments that ``demisto.args()``
    may forward when a command is invoked from the platform.
    """

    EXTRA_REDUNDANT_ARGS = {"verbose": "true", "using": "default"}
    EXTRA_UNEXPECTED_ARGS = {"nonexistent_param": "value", "another_unknown": 42}

    @pytest.mark.parametrize(
        "func_name, required_args",
        [
            pytest.param(
                "zendesk_user_delete",
                {"user_id": "1"},
                id="zendesk-user-delete",
            ),
            pytest.param(
                "zendesk_ticket_delete",
                {"ticket_id": "10"},
                id="zendesk-ticket-delete",
            ),
            pytest.param(
                "zendesk_attachment_get_command",
                {"attachment_id": 123},
                id="zendesk-attachment-get",
            ),
            pytest.param(
                "zendesk_search",
                {"query": "type:ticket"},
                id="zendesk-search",
            ),
        ],
    )
    class TestSimpleClientCommands:
        """Commands invoked on the ZendeskClient instance with all I/O mocked."""

        @staticmethod
        @pytest.fixture
        def stub_http(mocker, zendesk_client):
            """Mock ``_http_request`` and the search-results helper so command
            methods can be invoked without any real network I/O."""
            mocker.patch.object(zendesk_client, "_http_request", return_value={})
            mocker.patch.object(
                zendesk_client,
                "_ZendeskClient__zendesk_search_results",
                return_value=[],
            )
            mocker.patch.object(
                zendesk_client,
                "zendesk_attachment_get",
                return_value=[],
            )
            mocker.patch.object(zendesk_client, "get_file_entries", return_value=[])

        def test_with_required_args_only(self, zendesk_client, stub_http, func_name, required_args):
            """Calling the command with only the canonical/required args must succeed."""
            func = getattr(zendesk_client, func_name)
            func(**required_args)

        def test_with_redundant_args(self, zendesk_client, stub_http, func_name, required_args):
            """Extra args that are not declared parameters but are commonly passed by
            ``demisto.args()`` (e.g. ``verbose``, ``using``) must be tolerated via
            ``**kwargs`` and not raise ``TypeError``."""
            func = getattr(zendesk_client, func_name)
            args = {**required_args, **TestCommandArgumentHandling.EXTRA_REDUNDANT_ARGS}
            func(**args)

        def test_with_unexpected_args(self, zendesk_client, stub_http, func_name, required_args):
            """Completely unknown keyword arguments must be swallowed by ``**kwargs``
            and not raise ``TypeError``."""
            func = getattr(zendesk_client, func_name)
            args = {**required_args, **TestCommandArgumentHandling.EXTRA_UNEXPECTED_ARGS}
            func(**args)

    class TestZendeskTicketAttachmentAdd:
        @staticmethod
        @pytest.fixture
        def stub_attachment_add(mocker, zendesk_client, tmp_path):
            file_on_disk = tmp_path / "uploaded.txt"
            file_on_disk.write_bytes(b"payload")
            mocker.patch.object(
                demisto,
                "getFilePath",
                return_value={"path": str(file_on_disk), "name": "uploaded.txt"},
            )
            mocker.patch.object(
                zendesk_client,
                "_http_request",
                return_value={"upload": {"token": "tok"}},
            )

        REQUIRED_ARGS = {"file_id": "fid", "ticket_id": 10, "comment": "hi"}

        def test_with_required_args_only(self, zendesk_client, stub_attachment_add):
            zendesk_client.zendesk_ticket_attachment_add(**self.REQUIRED_ARGS)

        def test_with_filename_arg(self, zendesk_client, stub_attachment_add):
            """The renamed ``filename`` param (was ``file_name`` on master) must be
            accepted as a keyword arg."""
            zendesk_client.zendesk_ticket_attachment_add(filename="custom.txt", **self.REQUIRED_ARGS)

        def test_with_redundant_args(self, zendesk_client, stub_attachment_add):
            zendesk_client.zendesk_ticket_attachment_add(**self.REQUIRED_ARGS, **TestCommandArgumentHandling.EXTRA_REDUNDANT_ARGS)

        def test_with_unexpected_args(self, zendesk_client, stub_attachment_add):
            zendesk_client.zendesk_ticket_attachment_add(
                **self.REQUIRED_ARGS, **TestCommandArgumentHandling.EXTRA_UNEXPECTED_ARGS
            )

    class TestGetModifiedRemoteData:
        @staticmethod
        @pytest.fixture
        def stub_modified_remote(mocker, zendesk_client):
            mocker.patch.object(demisto, "getIntegrationContext", return_value={})
            mocker.patch.object(demisto, "setIntegrationContext")
            mocker.patch.object(
                Zendeskv2,
                "UpdatedTickets",
                return_value=mocker.Mock(tickets=list, next_run=dict),
            )
            mocker.patch.object(Zendeskv2, "get_last_mirror_run", return_value={})
            mocker.patch.object(Zendeskv2, "set_last_mirror_run")
            mocker.patch.object(Zendeskv2, "return_results")

        def test_with_required_args_only(self, zendesk_client, stub_modified_remote):
            zendesk_client.get_modified_remote_data(lastUpdate="2024-01-01T00:00:00Z")

        def test_with_redundant_args(self, zendesk_client, stub_modified_remote):
            zendesk_client.get_modified_remote_data(
                lastUpdate="2024-01-01T00:00:00Z", **TestCommandArgumentHandling.EXTRA_REDUNDANT_ARGS
            )

        def test_with_unexpected_args(self, zendesk_client, stub_modified_remote):
            zendesk_client.get_modified_remote_data(
                lastUpdate="2024-01-01T00:00:00Z", **TestCommandArgumentHandling.EXTRA_UNEXPECTED_ARGS
            )


class TestOAuthAuthentication:
    TOKEN_URL = f"{BASE_URL}/oauth/tokens"
    CLIENT_ID = "test_client"
    CLIENT_SECRET = "test_secret"
    FROZEN_TIME = "2026-01-01T00:00:00Z"
    FROZEN_TIMESTAMP = datetime.fromisoformat(FROZEN_TIME).timestamp()

    @staticmethod
    @pytest.fixture
    def integration_context(mocker):
        """Patches the integration context get/set and returns the setter mock."""
        mocker.patch.object(demisto, "getIntegrationContext", return_value={})
        return mocker.patch.object(demisto, "setIntegrationContext")

    def _oauth_client(self, scope: str | None = None, **kwargs) -> ZendeskClient:
        return ZendeskClient(BASE_URL, client_id=self.CLIENT_ID, client_secret=self.CLIENT_SECRET, scope=scope, **kwargs)

    @freeze_time(FROZEN_TIME)
    def test_init_when_oauth_configured_requests_token_and_sets_bearer_header(self, requests_mock, integration_context):
        """
        Given:
            - Client ID and Client Secret are configured, and no token is cached.
        When:
            - The client is created and an API call is made.
        Then:
            - A client_credentials token request is sent as a form body with the configured scope.
            - The API call uses the access token as a Bearer token, without basic auth.
            - The token is cached with an expiry of expires_in minus the buffer.
        """
        token_mock = requests_mock.post(
            self.TOKEN_URL, json={"access_token": "new_token", "token_type": "bearer", "expires_in": 1800}
        )
        users_mock = requests_mock.get(full_url("users/1"), json=get_json_file("users/1"))

        client = self._oauth_client(scope="tickets:read users:read")
        client._get_user_by_id("1")

        assert token_mock.call_count == 1
        assert token_mock.last_request.headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert urllib.parse.parse_qs(token_mock.last_request.text) == {
            "grant_type": ["client_credentials"],
            "client_id": [self.CLIENT_ID],
            "client_secret": [self.CLIENT_SECRET],
            "scope": ["tickets:read users:read"],
            "expires_in": [str(OAUTH_TOKEN_EXPIRES_IN_SECONDS)],
        }
        assert client._auth is None
        assert users_mock.last_request.headers["Authorization"] == "Bearer new_token"
        integration_context.assert_called_once_with(
            {
                OAUTH_TOKEN_CONTEXT_KEY: {
                    "access_token": "new_token",
                    "client_id": self.CLIENT_ID,
                    "scope": "tickets:read users:read",
                    "expires_at": self.FROZEN_TIMESTAMP + 1800 - OAUTH_TOKEN_EXPIRY_BUFFER_SECONDS,
                }
            }
        )

    @pytest.mark.usefixtures("integration_context")
    @pytest.mark.parametrize("scope", [None, ""])
    def test_init_when_scope_empty_requests_default_scope(self, requests_mock, scope):
        """
        Given:
            - OAuth is configured and the Scope parameter is empty.
        When:
            - The client is created.
        Then:
            - The token request uses the default scope "read write".
        """
        token_mock = requests_mock.post(self.TOKEN_URL, json={"access_token": "new_token", "expires_in": 1800})

        self._oauth_client(scope=scope)

        assert urllib.parse.parse_qs(token_mock.last_request.text)["scope"] == [OAUTH_DEFAULT_SCOPE]

    def test_init_when_only_credentials_configured_uses_basic_auth(self, requests_mock):
        """
        Given:
            - Only Username / Password credentials are configured.
        When:
            - The client is created.
        Then:
            - Basic auth is used and no token request is made.
        """
        token_mock = requests_mock.post(self.TOKEN_URL, json={"access_token": "new_token"})

        client = ZendeskClient(BASE_URL, username="user@example.com", password="password")

        assert client._auth == ("user@example.com", "password")
        assert token_mock.call_count == 0

    @freeze_time(FROZEN_TIME)
    def test_get_oauth_access_token_when_valid_token_cached_reuses_it(self, mocker, requests_mock):
        """
        Given:
            - A cached token for the same client ID and scope that has not expired.
        When:
            - The client is created.
        Then:
            - The cached token is used and no token request is made.
        """
        mocker.patch.object(
            demisto,
            "getIntegrationContext",
            return_value={
                OAUTH_TOKEN_CONTEXT_KEY: {
                    "access_token": "cached_token",
                    "client_id": self.CLIENT_ID,
                    "scope": OAUTH_DEFAULT_SCOPE,
                    "expires_at": self.FROZEN_TIMESTAMP + 100,
                }
            },
        )
        set_context = mocker.patch.object(demisto, "setIntegrationContext")
        token_mock = requests_mock.post(self.TOKEN_URL, json={"access_token": "new_token", "expires_in": 1800})

        client = self._oauth_client()

        assert client._headers == {"Authorization": "Bearer cached_token"}
        assert token_mock.call_count == 0
        set_context.assert_not_called()

    @freeze_time(FROZEN_TIME)
    @pytest.mark.parametrize(
        "cached_overrides",
        [
            pytest.param({"expires_at": FROZEN_TIMESTAMP - 1}, id="expired"),
            pytest.param({"expires_at": 0}, id="no expiry"),
            pytest.param({"client_id": "other_client"}, id="different client id"),
            pytest.param({"scope": "read"}, id="different scope"),
        ],
    )
    def test_get_oauth_access_token_when_cached_token_unusable_requests_new_token(self, mocker, requests_mock, cached_overrides):
        """
        Given:
            - A cached token that is expired, has no expiry, or belongs to a different client ID or scope.
        When:
            - The client is created.
        Then:
            - A new token is requested and replaces the cached one, keeping other context data.
        """
        cached_token = {
            "access_token": "cached_token",
            "client_id": self.CLIENT_ID,
            "scope": OAUTH_DEFAULT_SCOPE,
            "expires_at": self.FROZEN_TIMESTAMP + 100,
        } | cached_overrides
        mocker.patch.object(
            demisto,
            "getIntegrationContext",
            return_value={"users": {"1": "user@example.com"}, OAUTH_TOKEN_CONTEXT_KEY: cached_token},
        )
        set_context = mocker.patch.object(demisto, "setIntegrationContext")
        token_mock = requests_mock.post(self.TOKEN_URL, json={"access_token": "new_token", "expires_in": 1800})

        client = self._oauth_client()

        assert token_mock.call_count == 1
        assert client._headers == {"Authorization": "Bearer new_token"}
        saved_context = set_context.call_args[0][0]
        assert saved_context["users"] == {"1": "user@example.com"}
        assert saved_context[OAUTH_TOKEN_CONTEXT_KEY]["access_token"] == "new_token"

    @freeze_time(FROZEN_TIME)
    def test_get_oauth_access_token_when_no_expires_in_uses_requested_expiry(self, requests_mock, integration_context):
        """
        Given:
            - A token response without expires_in.
        When:
            - The client is created.
        Then:
            - The token is used and cached with the explicitly requested expiry, so it is reused on later runs.
        """
        requests_mock.post(self.TOKEN_URL, json={"access_token": "new_token"})

        client = self._oauth_client()

        assert client._headers == {"Authorization": "Bearer new_token"}
        assert (
            integration_context.call_args[0][0][OAUTH_TOKEN_CONTEXT_KEY]["expires_at"]
            == self.FROZEN_TIMESTAMP + OAUTH_TOKEN_EXPIRES_IN_SECONDS - OAUTH_TOKEN_EXPIRY_BUFFER_SECONDS
        )

    def test_get_oauth_access_token_when_response_has_no_access_token_raises(self, requests_mock, integration_context):
        """
        Given:
            - A token response without an access_token.
        When:
            - The client is created.
        Then:
            - A DemistoException is raised and nothing is cached.
        """
        requests_mock.post(self.TOKEN_URL, json={"token_type": "bearer"})

        with pytest.raises(DemistoException, match="no access_token in the response"):
            self._oauth_client()
        integration_context.assert_not_called()

    @pytest.mark.usefixtures("integration_context")
    def test_get_oauth_access_token_when_token_request_fails_raises_api_error(self, requests_mock):
        """
        Given:
            - The token endpoint rejects the request (e.g. a scope outside the client's allowed scopes).
        When:
            - The client is created.
        Then:
            - A DemistoException containing the Zendesk error body is raised.
        """
        requests_mock.post(self.TOKEN_URL, status_code=400, json={"error": "invalid_scope"})

        with pytest.raises(DemistoException, match="invalid_scope"):
            self._oauth_client()

    @pytest.mark.parametrize(
        "params",
        [
            pytest.param({"base_url": BASE_URL}, id="no auth params"),
            pytest.param(
                {"base_url": BASE_URL, "credentials": {"identifier": "user@example.com"}, "oauth_credentials": {}},
                id="username without password",
            ),
            pytest.param(
                {"base_url": BASE_URL, "oauth_credentials": {"identifier": "test_client"}},
                id="client id without secret",
            ),
        ],
    )
    def test_main_when_no_auth_configured_returns_error(self, mocker, requests_mock, params):
        """
        Given:
            - Neither OAuth (Client ID and Client Secret) nor a password is configured.
        When:
            - main() runs any command.
        Then:
            - A readable error is returned and no request is sent.
        """
        mocker.patch.object(demisto, "params", return_value=params)
        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(Zendeskv2, "CACHE", None)
        return_error_mock = mocker.patch.object(Zendeskv2, "return_error")

        main()

        assert "No authentication method is configured" in return_error_mock.call_args[0][0]
        assert requests_mock.call_count == 0

    @pytest.mark.parametrize(
        "credentials, oauth_credentials",
        [
            pytest.param(
                {"identifier": "user@example.com", "password": "password"},
                {"identifier": CLIENT_ID, "password": CLIENT_SECRET},
                id="both methods fully configured",
            ),
            pytest.param(
                {"identifier": "user@example.com"}, {"identifier": CLIENT_ID, "password": CLIENT_SECRET}, id="username only"
            ),
            pytest.param(
                {"identifier": "user@example.com", "password": "password"}, {"identifier": CLIENT_ID}, id="client id only"
            ),
        ],
    )
    def test_main_when_multiple_auth_methods_configured_returns_error(
        self, mocker, requests_mock, credentials, oauth_credentials
    ):
        """
        Given:
            - Fields of both OAuth and Username / Password credentials are configured.
        When:
            - main() runs any command.
        Then:
            - A readable error is returned and no request is sent.
        """
        mocker.patch.object(
            demisto,
            "params",
            return_value={"base_url": BASE_URL, "credentials": credentials, "oauth_credentials": oauth_credentials},
        )
        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(Zendeskv2, "CACHE", None)
        return_error_mock = mocker.patch.object(Zendeskv2, "return_error")

        main()

        assert "More than one authentication method is configured" in return_error_mock.call_args[0][0]
        assert requests_mock.call_count == 0

    def test_main_when_oauth_configured_passes_oauth_params_to_client(self, mocker):
        """
        Given:
            - OAuth credentials and a scope are configured, with no Username / Password credentials.
        When:
            - main() runs test-module.
        Then:
            - The client is created with the Client ID, Client Secret and Scope from the params.
        """
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "base_url": BASE_URL,
                "oauth_credentials": {"identifier": self.CLIENT_ID, "password": self.CLIENT_SECRET},
                "scope": "read",
            },
        )
        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(Zendeskv2, "CACHE", None)
        client_mock = mocker.patch.object(Zendeskv2, "ZendeskClient")
        mocker.patch.object(Zendeskv2, "CacheManager")
        mocker.patch.object(Zendeskv2, "return_results")

        main()

        client_kwargs = client_mock.call_args.kwargs
        assert client_kwargs["client_id"] == self.CLIENT_ID
        assert client_kwargs["client_secret"] == self.CLIENT_SECRET
        assert client_kwargs["scope"] == "read"
        assert client_kwargs["password"] is None
