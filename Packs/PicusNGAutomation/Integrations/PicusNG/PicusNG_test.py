import json
import io

# flake8: noqa


def util_load_json(path: str):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_get_agent_list_command(mocker):
    from PicusNG import Client, get_agent_list_command

    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/get_AgentList.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = get_agent_list_command(client).outputs
    assert result[2]["name"] == "test3"


def test_get_agent_detail_command(mocker):
    from PicusNG import Client, get_agent_detail_command

    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"
    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/get_AgentDetail.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = get_agent_detail_command(client).outputs
    assert result["ip"] == "1.2.3.4"


def test_get_integration_agent_list_command(mocker):
    from PicusNG import Client, get_integration_agent_list_command

    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/get_IntegrationAgentList.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = get_integration_agent_list_command(client).outputs
    assert result[0]["name"] == "testcortex"


def test_get_template_list_command(mocker):
    from PicusNG import Client, get_template_list_command

    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/get_TemplateList.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = get_template_list_command(client).outputs
    assert result[1]["name"] == "Top Threats"


def test_create_simulation_command(mocker):
    from PicusNG import Client, create_simulation_command

    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.side_effect = ["1", "1", "1", "1", "1"]
    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/createSimulation.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = create_simulation_command(client).outputs
    assert result["name"] == "cortex-test2"


def test_get_simulation_list_command(mocker):
    from PicusNG import Client, get_simulation_list_command

    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/get_SimulationList.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = get_simulation_list_command(client).outputs
    assert result[2]["simulation_id"] == 8633


def test_simulate_now_command(mocker):
    from PicusNG import Client, simulate_now_command

    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"
    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/simulateNow.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = simulate_now_command(client).outputs
    assert result["id"] == 24084


def test_get_simulation_detail_command(mocker):
    from PicusNG import Client, get_simulation_detail_command

    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"
    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/get_SimulationDetail.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = get_simulation_detail_command(client).outputs
    assert result[2]["id"] == "19660"


def test_get_latest_simulation_result_command(mocker):
    from PicusNG import Client, get_latest_simulation_result_command

    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"
    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/get_LatestSimulationResult.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = get_latest_simulation_result_command(client).outputs
    assert result["results"]["prevention"]["security_score"] == 35


def test_get_simulation_result_command(mocker):
    from PicusNG import Client, get_simulation_result_command

    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"
    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/get_SimulationResult.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = get_simulation_result_command(client).outputs
    assert result["prevention_blocked_threat"] == 15


def test_get_simulation_threats_command(mocker):
    from PicusNG import Client, get_simulation_threats_command

    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"
    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/get_SimulationThreats.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = get_simulation_threats_command(client).outputs
    assert result == "10141,10143"


def test_get_simulation_actions_command(mocker):
    from PicusNG import Client, get_simulation_actions_command

    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"
    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/get_SimulationActions.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = get_simulation_actions_command(client).outputs
    assert result == "3061=unblocked,3062=unblocked,22743=blocked"


def test_get_mitigation_devices_command(mocker):
    from PicusNG import Client, get_mitigation_devices_command

    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"
    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/get_MitigationDevices.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = get_mitigation_devices_command(client).outputs
    assert result[2]["device_name"] == "Forcepoint NGFW"


def test_get_signature_list_command(mocker):
    from PicusNG import Client, get_signature_list_command

    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"
    mocker.patch("PicusNG.Client.get_access_token", return_value="access_token")
    client = Client(api_key="foo", base_url="base_url", verify=False, proxy=False)
    mock_response = util_load_json("test_data/get_SignatureList.json")
    mocker.patch("PicusNG.Client.http_request", return_value=mock_response)
    result = get_signature_list_command(client).outputs
    assert result[2]["id"] == 145546


def test_filterInsecureAttacks(mocker):
    from PicusNG import filterInsecureAttacks

    threatinfo_mock = mocker.patch("PicusNG.demisto")
    threatinfo_mock.args.return_value.get.return_value = "111=unblocked,222=blocked,333=unblocked"
    result = filterInsecureAttacks().outputs
    assert result == "111,333"
