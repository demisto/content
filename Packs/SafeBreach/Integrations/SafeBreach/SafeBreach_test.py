import pytest
from CommonServerPython import *
from SafeBreach import (
    Client,
    get_indicators_command,
    get_services_status,
    get_all_users,
    get_user_id_by_name_or_email,
    main,
    create_user,
    update_user_with_details,
    delete_user_with_details,
    create_deployment,
    update_deployment,
    delete_deployment,
    create_api_key,
    apikey_transformer,
    delete_api_key,
    return_rotated_verification_token,
    get_all_tests_summary,
    get_all_tests_summary_with_scenario_id,
    delete_test_result_of_test,
    get_all_integration_error_logs,
    delete_integration_error_logs,
    get_all_running_tests_summary,
    get_all_running_simulations_summary,
    pause_resume_tests_and_simulations,
    get_schedules,
    delete_schedules,
    get_prebuilt_scenarios,
    get_custom_scenarios,
    get_verification_token,
    rerun_test,
    get_simulator_quota_with_table,
    get_all_simulator_details,
    get_simulator_with_name,
    delete_simulator_with_given_name,
    approve_simulator,
    get_simulations,
    get_simulators_versions_list,
    update_simulator_with_id,
    get_installation_links,
)
from importlib import import_module

SERVER_URL = "https://test_url.com"

safebreach = import_module("SafeBreach")


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(api_key="test", account_id=None, base_url=SERVER_URL, verify=True)


def deployment_transformer(header):
    return_map = {
        "id": "id",
        "accountId": "accountId",
        "name": "name",
        "createdAt": "createdAt",
        "description": "description",
        "nodes": "simulators",
        "updatedAt": "updatedAt",
    }

    return return_map.get(header, header)


def test_get_indicators_command(client, mocker):
    # Mocking the response of the API call
    expected_result = util_load_json(
        path="./test_data/outputs/safebreach_get_indicator_outputs.json"
    )
    mocker.patch.object(client, "get_indicators_command", return_value=expected_result)

    # Running the command
    result = get_indicators_command(client)

    # Verifying the result
    assert result.outputs == expected_result
    assert result.outputs_prefix == "SafeBreach.Indicator"


def test_get_users_list(client, mocker):
    # Mocking the response of the API call
    expected_result = util_load_json(
        path="./test_data/outputs/safebreach_get_services_status_outputs.json"
    )
    mocker.patch.object(client, "get_services_status", return_value=expected_result)

    # Running the command
    result = get_services_status(client)

    # Verifying the result
    assert result.outputs == expected_result
    assert result.outputs_prefix == "SafeBreach.Service"


def modify_mocker_with_common_data(mocker, test_input_data, test_output_data):
    mocker.patch.object(demisto, "command", return_value=test_input_data.get("command"))
    mocker.patch.object(demisto, "args", return_value=test_input_data.get("args"))

    mocker.patch.object(safebreach, "return_results")
    mocker.patch.object(Client, "get_response", return_value=test_output_data)

    return mocker


def test_get_all_users(client, mocker):
    input_type = util_load_json(
        path="./test_data/inputs/safebreach_get_all_users_inputs.json"
    )
    expected_result = util_load_json(
        path="./test_data/outputs/safebreach_get_all_users_outputs.json"
    )

    for key in input_type:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=input_type[key], test_output_data=expected_result["outputs"][key]
        )
        main()
        # Running the command
        result = get_all_users(client)

        assert result.outputs_prefix == "SafeBreach.User"

        assert result.outputs == expected_result["outputs"][key].get("data")
        assert result.readable_output == tableToMarkdown(
            name="user data", t=result.outputs, headers=["id", "name", "email"]
        )
        assert len(result.outputs) == 2
        if key == "details_and_deleted":
            assert expected_result["outputs"][key].get("data")[0]["deletedAt"] is None
            assert expected_result["outputs"][key].get("data")[1]["deletedAt"] is not None
        elif key == "just_details":
            assert expected_result["outputs"][key].get("data")[0]["deletedAt"] is None
            assert expected_result["outputs"][key].get("data")[1]["deletedAt"] is None
        else:
            with pytest.raises(KeyError) as key_err:
                expected_result["outputs"][key].get("data")[0]["deletedAt"]
            assert key_err.type is KeyError


def test_get_user_id_by_name_or_email(client, mocker):
    input_type = util_load_json(
        path="./test_data/inputs/safebreach_get_named_user_inputs.json"
    )
    expected_result = util_load_json(
        path="./test_data/outputs/safebreach_get_named_user_outputs.json"
    )
    # mocker.patch.object(client, 'get_users_list', return_value=expected_result)
    for key in input_type:
        # Running the command
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=input_type[key], test_output_data=expected_result["outputs"][key]
        )
        main()

        command_results = get_user_id_by_name_or_email(client)

        assert command_results.outputs_prefix == "SafeBreach.User"
        assert command_results.readable_output == tableToMarkdown(
            name="user data", t=command_results.outputs, headers=["id", "name", "email"]
        )
        assert command_results.outputs == expected_result["outputs"][key].get("data")
        assert len(command_results.outputs) in [0, 1]
        if key in ["not_deleted_with_name", "not_deleted_without_name"]:
            assert expected_result["outputs"][key].get("data")[0]["deletedAt"] is None
        elif key in ["deleted_with_name", "deleted_without_name"]:
            assert expected_result["outputs"][key].get("data")[0]["deletedAt"] is not None
            assert type(expected_result["outputs"][key].get("data")[0]["deletedAt"]) is str
        else:
            assert isinstance(expected_result["outputs"][key].get("data"), types.FunctionType)


def test_create_user(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_create_user_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_create_user_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()

        command_results = create_user(client)
        assert command_results.outputs_prefix == "SafeBreach.User"
        assert command_results.readable_output == tableToMarkdown(
            name="Created User Data",
            t=command_results.outputs,
            headers=[
                "id",
                "name",
                "email",
                "mustChangePassword",
                "roles",
                "description",
                "role",
                "is_active",
                "deployments",
                "created_at",
            ],
        )
        assert command_results.outputs == test_output["outputs"][key].get("data")

        if key == "successful_creation":
            assert test_output["outputs"][key].get("data") is not None
            assert test_output["outputs"][key].get("data")["name"] == test_input[key]["args"]["name"]
            assert test_output["outputs"][key].get("data")["email"] == test_input[key]["args"]["email"]

        elif key == "weak_password":
            assert callable(test_output["outputs"][key]["data"]) is False

        else:
            assert callable(test_output["outputs"][key]["data"]) is False


def test_update_user_with_details(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_update_user_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_update_user_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        mocker.patch.object(Client, "get_users_list", return_value=[test_output["outputs"][key]["data"]])
        if key in ["failed_update", "weak_password"]:
            try:
                update_user_with_details(client)
            except DemistoException as error:
                assert f"User with {test_input[key]['args']['user_id']} not found" == str(error)
            continue
        else:
            main()
        command_results = update_user_with_details(client)

        assert command_results.outputs_prefix == "SafeBreach.User"
        assert command_results.readable_output == tableToMarkdown(
            name="Updated User Data",
            t=command_results.outputs,
            headers=[
                "id",
                "name",
                "email",
                "deletedAt",
                "roles",
                "description",
                "role",
                "deployments",
                "createdAt",
                "updatedAt",
            ],
        )
        assert command_results.outputs == test_output["outputs"][key].get("data")

        assert test_output["outputs"][key].get("data") is not None
        assert test_output["outputs"][key].get("data")["name"] == test_input[key]["args"]["name"]
        assert test_output["outputs"][key].get("data")["description"] == test_input[key]["args"]["user_description"]


def test_delete_user_with_details(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_delete_user_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_delete_user_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )
        mocker.patch.object(Client, "get_users_list", return_value=[test_output["outputs"][key]["data"]])
        if key == "failed_delete":
            try:
                delete_user_with_details(client)
            except DemistoException as error:
                assert (
                    f"User with {test_input[key]['args']['user_id']} or {test_input[key]['args']['email']} not found"
                    == str(error)
                )
            continue
        else:
            main()
        command_results = delete_user_with_details(client)

        assert command_results.outputs_prefix == "SafeBreach.User"
        assert command_results.readable_output == tableToMarkdown(
            name="Deleted User Data",
            t=command_results.outputs,
            headers=["id", "name", "email", "deletedAt", "roles", "description", "role", "deployments", "createdAt"],
        )
        assert command_results.outputs == test_output["outputs"][key].get("data")

        assert test_output["outputs"][key].get("data") is not None
        assert test_output["outputs"][key].get("data")["name"] == test_input[key]["args"]["name"]
        assert test_output["outputs"][key].get("data")["email"] == test_input[key]["args"]["email"]
        assert test_output["outputs"][key].get("data")["description"] == test_input[key]["args"]["user_description"]


def test_create_deployment(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_create_deployment_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_create_deployment_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = create_deployment(client)

        assert command_results.outputs_prefix == "SafeBreach.Deployment"
        assert command_results.readable_output == tableToMarkdown(
            name="Created Deployment",
            headerTransform=deployment_transformer,
            t=command_results.outputs,
            headers=["id", "accountId", "name", "createdAt", "description", "nodes"],
        )

        if key == "successful_creation":
            assert command_results.outputs == test_output["outputs"][key].get("data")
            assert test_output["outputs"][key].get("data") is not None
            assert test_output["outputs"][key].get("data")["name"] == test_input[key]["args"]["name"]
            assert test_output["outputs"][key].get("data")["description"] == test_input[key]["args"]["description"]
            assert test_output["outputs"][key].get("data")["deletedAt"] is None

        else:
            assert isinstance(test_output["outputs"][key]["error"], dict)


def test_update_deployment(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_update_deployment_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_update_deployment_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = update_deployment(client)

        assert command_results.outputs_prefix == "SafeBreach.Deployment"
        assert command_results.readable_output == tableToMarkdown(
            name="Updated Deployment",
            headerTransform=deployment_transformer,
            t=command_results.outputs,
            headers=["id", "accountId", "name", "createdAt", "description", "nodes", "updatedAt"],
        )

        if key != "failed_update":
            assert command_results.outputs == test_output["outputs"][key].get("data")
            assert test_output["outputs"][key].get("data") is not None
            assert test_output["outputs"][key].get("data")["name"] == test_input[key]["args"]["updated_deployment_name"]
            assert (
                test_output["outputs"][key].get("data")["description"]
                == test_input[key]["args"]["updated_deployment_description"]
            )
            assert test_output["outputs"][key].get("data")["deletedAt"] is None

        else:
            assert test_output["outputs"][key].get("data").get("updated_deployment_name") is None


def test_delete_deployment(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_delete_deployment_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_delete_deployment_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = delete_deployment(client)

        assert command_results.outputs_prefix == "SafeBreach.Deployment"
        assert command_results.readable_output == tableToMarkdown(
            name="Deleted Deployment",
            headerTransform=deployment_transformer,
            t=command_results.outputs,
            headers=["id", "accountId", "name", "createdAt", "description", "nodes", "updatedAt"],
        )

        if key != "failed_delete":
            assert key == key
            assert command_results.outputs == test_output["outputs"][key].get("data")
            assert test_output["outputs"][key].get("data") is not None
            assert test_output["outputs"][key].get("data")["deletedAt"] is not None

        else:
            assert test_output["outputs"][key].get("data").get("deletedAt") is None


def test_create_api_key(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_create_api_key_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_create_api_key_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = create_api_key(client)

        assert command_results.outputs_prefix == "SafeBreach.API"
        assert command_results.readable_output == tableToMarkdown(
            name="Generated API key Data",
            t=command_results.outputs,
            headerTransform=apikey_transformer,
            headers=["name", "description", "createdBy", "createdAt", "key"],
        )

        if key == "successful_creation":
            assert command_results.outputs == test_output["outputs"][key].get("data")
            assert test_output["outputs"][key].get("data") is not None
            assert test_output["outputs"][key].get("data")["name"] == test_input[key]["args"]["name"]
            assert test_output["outputs"][key].get("data")["description"] == test_input[key]["args"]["description"]
            assert test_output["outputs"][key].get("data")["deletedAt"] is None
        else:
            assert isinstance(test_output["outputs"][key]["error"], dict)
            assert test_output["outputs"][key]["error"].get("errors") is not None


def test_delete_api_key(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_delete_api_key_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_delete_api_key_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        mocker.patch.object(
            Client,
            "get_all_active_api_keys_with_details",
            return_value=test_input[key]["all_active_api_keys_data"],
        )
        if key == "successful_delete_just_name":
            main()
        else:
            try:
                delete_api_key(client)
            except DemistoException as err:
                assert f"couldn't find API key with given name: {test_input[key]['args']['key_name']}" == str(err)
            continue
        command_results = delete_api_key(client)

        assert command_results.outputs_prefix == "SafeBreach.API"
        assert command_results.readable_output == tableToMarkdown(
            name="Deleted API key Data",
            t=command_results.outputs,
            headerTransform=apikey_transformer,
            headers=["name", "description", "createdBy", "createdAt", "deletedAt"],
        )

        assert command_results.outputs == test_output["outputs"][key].get("data")
        assert test_output["outputs"][key].get("data") is not None
        assert test_output["outputs"][key].get("data")["name"] == test_input[key]["args"]["key_name"]
        assert test_output["outputs"][key].get("data")["deletedAt"] is not None


def test_return_rotated_verification_token(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_rotate_token_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_rotate_token_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = return_rotated_verification_token(client)

        assert command_results.outputs_prefix == "SafeBreach.Token"
        assert command_results.readable_output == tableToMarkdown(
            name="New Token Details", t=command_results.outputs, headers=["secret"]
        )

        assert command_results.outputs == test_output["outputs"][key].get("data").get("secret")
        assert test_output["outputs"][key].get("data") is not None


def test_get_all_tests_summary(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_all_tests_summary_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_all_tests_summary_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = get_all_tests_summary(client)

        assert command_results.outputs_prefix == "SafeBreach.Test"
        assert command_results.outputs == {"tests_data": test_output["outputs"][key]}
        for test in test_output["outputs"][key]:
            assert test["status"] == test_input[key]["args"]["status"]
        assert len(test_output["outputs"][key]) <= test_input[key]["args"]["entries_per_page"]


def test_get_all_tests_summary_with_scenario_id(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_all_tests_summary_with_plan_id_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_all_tests_summary_with_plan_id_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = get_all_tests_summary_with_scenario_id(client)
        if key == "success":
            assert bool(test_input[key]["args"]["plan_id"]) is True
        else:
            assert bool(test_input[key]["args"]["plan_id"]) is False
        assert command_results.outputs_prefix == "SafeBreach.Test"
        assert command_results.outputs == {"tests_data": test_output["outputs"][key]}
        for test in test_output["outputs"][key]:
            assert test["status"] == test_input[key]["args"]["status"]
        assert len(test_output["outputs"][key]) <= test_input[key]["args"]["entries_per_page"]


def test_delete_test_result_of_test(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_delete_test_results_of_test_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_delete_test_results_of_test_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = delete_test_result_of_test(client)
        if key == "success":
            assert bool(test_input[key]["args"]["test_id"]) is True
        else:
            assert bool(test_input[key]["args"]["test_id"]) is False
            continue
        assert command_results.outputs_prefix == "SafeBreach.Test"
        assert command_results.readable_output == tableToMarkdown(
            name="Deleted Test", t=command_results.outputs, headers=["id"]
        )
        assert command_results.outputs == [test_output["outputs"][key].get("data", {})]


def test_get_all_integration_error_logs(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_integration_logs_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_integration_logs_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = get_all_integration_error_logs(client)
        assert test_output["outputs"][key].get("error") is not None
        assert command_results.outputs_prefix == "SafeBreach.Integration"
        assert len(test_output["outputs"][key].keys()) == 2


def test_delete_integration_error_logs(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_delete_integration_connector_logs_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_delete_integration_connector_logs_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = delete_integration_error_logs(client)
        if key == "fail":
            assert test_output["outputs"][key].get("errorCode") is not None
            assert test_input[key]["args"]["connector_id"] in test_output["outputs"][key].get("errorMessage")
            continue
        else:
            assert test_output["outputs"][key].get("error") is not None
        assert command_results.outputs_prefix == "SafeBreach.Integration"
        assert command_results.readable_output == tableToMarkdown(
            name="Integration errors status", t=command_results.outputs, headers=["result", "error"]
        )


def test_get_all_running_tests_summary(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_all_running_tests_summary_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_all_running_tests_summary_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = get_all_running_tests_summary(client)
        if key == "success":
            assert command_results.outputs_prefix == "SafeBreach.Test"
            assert command_results.outputs == test_output["outputs"][key]
        else:
            assert bool(test_output["outputs"][key]) is False


def test_get_all_running_simulations_summary(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_all_running_simulations_summary_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_all_running_simulations_summary_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = get_all_running_simulations_summary(client)
        assert command_results.outputs_prefix == "SafeBreach.Test"
        assert command_results.outputs == test_output["outputs"][key]
        if key == "success_with_data":
            assert test_output["outputs"][key].get("data").get("RUNNING") is not None
        elif key == "success_without_data":
            assert bool(test_output["outputs"][key].get("data").get("RUNNING")) is False
        else:
            assert bool(test_output["outputs"][key]) is False


def test_pause_resume_tests_and_simulations(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_pause_resume_tests_and_simulations_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_pause_resume_tests_and_simulations_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = pause_resume_tests_and_simulations(client)
        assert command_results.outputs_prefix == "SafeBreach.Test"
        assert command_results.outputs == test_output["outputs"][key].get("data")
        if key != "fail":
            assert test_output["outputs"][key].get("data").get("status") == "OK"
        else:
            assert bool(test_output["outputs"][key]) is False


def test_get_schedules(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_schedules_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_schedules_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = get_schedules(client)
        assert command_results.outputs_prefix == "SafeBreach.Schedules"
        assert command_results.outputs == test_output["outputs"][key].get("data")
        if key != "fail":
            assert test_output["outputs"][key].get("data") is not None
            if key in ("success_no_deleted_no_details", "success_deleted_no_details"):
                assert isinstance(test_output["outputs"][key].get("data")[0], dict) is True
                assert len(test_output["outputs"][key].get("data")[0]) == 2
            elif key in ("success_deleted_details", "success_no_deleted_details"):
                assert isinstance(test_output["outputs"][key].get("data")[0], dict) is True
                assert len(test_output["outputs"][key].get("data")[0]) > 2
        else:
            assert bool(test_output["outputs"][key]) is False


def test_delete_schedules(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_delete_schedules_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_delete_schedules_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        mocker.patch.object(Client, "append_cron_to_schedule", returns=test_output["outputs"][key])
        if key != "fail":
            assert test_output["outputs"][key].get("data") is not None
            main()
            command_results = delete_schedules(client)
            assert command_results.outputs_prefix == "SafeBreach.Scenario"
            assert command_results.outputs == test_output["outputs"][key]["data"]
        else:
            main()


def test_get_prebuilt_scenarios(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_prebuilt_scenarios_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_prebuilt_scenarios_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = get_prebuilt_scenarios(client)
        assert command_results.outputs_prefix == "SafeBreach.Scenario"
        assert command_results.outputs == test_output["outputs"][key]
        if key != "fail":
            assert bool(test_output["outputs"][key]) is True
            assert all(item["createdBy"] == "SafeBreach" for item in test_output["outputs"][key])
        else:
            assert bool(test_output["outputs"][key]) is False


def test_get_custom_scenarios(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_custom_scenarios_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_custom_scenarios_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = get_custom_scenarios(client)
        assert command_results.outputs_prefix == "SafeBreach.Scenario"
        assert command_results.outputs == test_output["outputs"][key]
        if key != "fail":
            assert bool(test_output["outputs"][key].get("data")) is True
            assert all(item.get("createdBy") is None for item in test_output["outputs"][key].get("data"))
            if key == "success_with_details":
                assert all(item.get("createdAt") is not None for item in test_output["outputs"][key].get("data"))
        else:
            assert bool(test_output["outputs"][key]) is False


def test_get_services_status(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_services_status_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_services_status_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = get_services_status(client)
        assert command_results.outputs_prefix == "SafeBreach.Service"
        assert command_results.outputs == test_output["outputs"][key]
        assert bool(test_output["outputs"][key]) is True
        if key == "success":
            assert all(item.get("isUp") is True for item in test_output["outputs"][key])
        else:
            assert any(item.get("isUp") is False for item in test_output["outputs"][key])


def test_get_verification_token(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_verification_token_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_verification_token_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = get_verification_token(client)
        assert command_results.outputs_prefix == "SafeBreach.Token"
        assert command_results.outputs == test_output["outputs"][key]
        if key != "fail":
            assert test_output["outputs"][key].get("data", {}).get("secret") is not None


def test_rerun_test(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_rerun_test_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_rerun_test_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = rerun_test(client)
        assert command_results.outputs_prefix == "SafeBreach.Test"
        assert command_results.outputs == test_output["outputs"][key]
        if key != "fail":
            assert isinstance(test_output["outputs"][key]["data"]["planRunId"], str)
            assert test_output["outputs"][key]["data"]["name"] == test_input[key]["args"]["test_name"]


def test_get_simulator_quota_with_table(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_simulator_quota_with_table_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_simulator_quota_with_table_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        if key == "success":
            main()
            command_results = get_simulator_quota_with_table(client)
            assert command_results.outputs_prefix == "SafeBreach.Account"
            assert command_results.outputs.get("account_details") == test_output["outputs"][key].get("data")
            assert command_results.outputs.get("simulator_quota") == test_output["outputs"][key].get("data").get(
                "nodesQuota"
            )


def test_get_all_simulator_details(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_all_simulator_details_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_all_simulator_details_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        main()
        command_results = get_all_simulator_details(client)
        assert command_results.outputs_prefix == "SafeBreach.Simulator"
        assert command_results.outputs == test_output["outputs"][key].get("data").get("rows")
        assert len(test_output["outputs"][key].get("data").get("rows")) == test_output["outputs"][key].get("data").get(
            "count"
        )


def test_get_simulator_with_name(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_simulator_with_name_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_simulator_with_name_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        mocker.patch.object(Client, "get_simulators_details", returns=test_output["outputs"][key])
        main()
        command_results = get_simulator_with_name(client)
        assert command_results.outputs_prefix == "SafeBreach.Simulator"
        assert command_results.outputs == test_output["outputs"][key].get("data")


def test_delete_simulator_with_given_name(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_delete_simulator_with_given_name_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_delete_simulator_with_given_name_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        mocker.patch.object(Client, "get_simulators_details", returns=test_output["outputs"][key])
        main()
        command_results = delete_simulator_with_given_name(client)
        assert command_results.outputs_prefix == "SafeBreach.Simulator"
        assert command_results.outputs == test_output["outputs"][key].get("data")


def test_approve_simulator(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_approve_simulator_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_approve_simulator_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        if key == "success":
            main()
            command_results = approve_simulator(client)
            assert command_results.outputs_prefix == "SafeBreach.Simulator"
            assert command_results.outputs == test_output["outputs"][key].get("data")


def test_get_simulations(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_simulations_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_simulations_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        if key == "success":
            main()
            command_results = get_simulations(client)
            assert command_results.outputs_prefix == "SafeBreach.Simulation"
            assert command_results.outputs == test_output["outputs"][key]


def test_get_simulators_versions_list(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_simulators_versions_list_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_simulators_versions_list_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        if key == "success":
            main()
            command_results = get_simulators_versions_list(client)
            assert command_results.outputs_prefix == "SafeBreach.Simulator"
            assert command_results.outputs == test_output["outputs"][key]


def test_update_simulator_with_id(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_upgrade_simulator_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_upgrade_simulator_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        if key == "success":
            main()
            command_results = update_simulator_with_id(client)
            assert command_results.outputs_prefix == "SafeBreach.Simulator"
            assert command_results.outputs == test_output["outputs"][key]


def test_get_installation_links(client, mocker):
    test_input = util_load_json(
        path="./test_data/inputs/safebreach_get_simulator_download_links_inputs.json"
    )
    test_output = util_load_json(
        path="./test_data/outputs/safebreach_get_simulator_download_links_outputs.json"
    )

    for key in test_input:
        mocker = modify_mocker_with_common_data(
            mocker=mocker, test_input_data=test_input[key], test_output_data=test_output["outputs"][key]
        )

        if key == "success":
            main()
            command_results = get_installation_links(client)
            assert command_results.outputs_prefix == "SafeBreach.Installation"
            assert command_results.outputs == test_output["outputs"][key]
