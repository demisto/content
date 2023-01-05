import json
import io
from unittest.mock import MagicMock

from requests import Response


# flake8: noqa

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())

def test_getAccessToken(mocker):
    from PicusNG import getAccessToken
    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.params.return_value.get.return_value = "picus_server"
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = json.dumps({'token': 'test'})

    requests_mock = mocker.patch("PicusNG.requests")
    requests_mock.Session.return_value.post.return_value = mock_response
    res = getAccessToken()
    assert res == 'test'

def test_getAgentList(mocker):
    from PicusNG import getAgentList
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/get_AgentList.json")).encode("ascii")

    mocker.patch("PicusNG.requests.get", return_value=mock_response)
    result = getAgentList().outputs
    assert result[2]["name"] == "test3"

def test_getAgentDetail(mocker):
    from PicusNG import getAgentDetail
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))
    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/get_AgentDetail.json")).encode("ascii")

    mocker.patch("PicusNG.requests.get", return_value=mock_response)
    result = getAgentDetail().outputs
    assert result["ip"] == "1.2.3.4"
    
def test_getIntegrationAgentList(mocker):
    from PicusNG import getIntegrationAgentList
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))
    
    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/get_IntegrationAgentList.json")).encode("ascii")

    mocker.patch("PicusNG.requests.get", return_value=mock_response)
    result = getIntegrationAgentList().outputs
    assert result[0]["name"] == "testcortex"

def test_getTemplateList(mocker):
    from PicusNG import getTemplateList
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/get_TemplateList.json")).encode("ascii")

    mocker.patch("PicusNG.requests.get", return_value=mock_response)
    result = getTemplateList().outputs
    assert result[1]["name"] == "Top Threats"

def test_createSimulation(mocker):
    from PicusNG import createSimulation
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))
    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.side_effect = ["1","1","1","1","1"]

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/createSimulation.json")).encode("ascii")

    mocker.patch("PicusNG.requests.post", return_value=mock_response)
    result = createSimulation().outputs
    assert result["name"] == "cortex-test2"
    
def test_getSimulationList(mocker):
    from PicusNG import getSimulationList
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/get_SimulationList.json")).encode("ascii")

    mocker.patch("PicusNG.requests.get", return_value=mock_response)
    result = getSimulationList().outputs
    assert result[2]["simulation_id"] == 8633

def test_simulateNow(mocker):
    from PicusNG import simulateNow
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))
    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/simulateNow.json")).encode("ascii")

    mocker.patch("PicusNG.requests.post", return_value=mock_response)
    result = simulateNow().outputs
    assert result["id"] == 24084
    
def test_getSimulationDetail(mocker):
    from PicusNG import getSimulationDetail
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))
    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/get_SimulationDetail.json")).encode("ascii")

    mocker.patch("PicusNG.requests.get", return_value=mock_response)
    result = getSimulationDetail().outputs
    assert result[2]["id"] == "19660"
    
def test_getLatestSimulationResult(mocker):
    from PicusNG import getLatestSimulationResult
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))
    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/get_LatestSimulationResult.json")).encode("ascii")

    mocker.patch("PicusNG.requests.get", return_value=mock_response)
    result = getLatestSimulationResult().outputs
    assert result["results"]["prevention"]["security_score"] == 35
    
def test_getSimulationResult(mocker):
    from PicusNG import getSimulationResult
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))
    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/get_SimulationResult.json")).encode("ascii")

    mocker.patch("PicusNG.requests.get", return_value=mock_response)
    result = getSimulationResult().outputs
    assert result["prevention_blocked_threat"] == 15
    
def test_getSimulationThreats(mocker):
    from PicusNG import getSimulationThreats
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))
    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/get_SimulationThreats.json")).encode("ascii")

    mocker.patch("PicusNG.requests.get", return_value=mock_response)
    result = getSimulationThreats().outputs
    assert result == "10141,10143"
    
def test_getSimulationActions(mocker):
    from PicusNG import getSimulationActions
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))
    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/get_SimulationActions.json")).encode("ascii")

    mocker.patch("PicusNG.requests.get", return_value=mock_response)
    result = getSimulationActions().outputs
    assert result == "3061=unblocked,3062=unblocked,22743=blocked"
    
def test_getMitigationDevices(mocker):
    from PicusNG import getMitigationDevices
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))
    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/get_MitigationDevices.json")).encode("ascii")

    mocker.patch("PicusNG.requests.get", return_value=mock_response)
    result = getMitigationDevices().outputs
    assert result[2]["device_name"] == "Forcepoint NGFW"
    
def test_getSignatureList(mocker):
    from PicusNG import getSignatureList
    mocker.patch("PicusNG.getAccessToken", return_value="test")
    mocker.patch("PicusNG.generateEndpointURL", return_value=("1", "1"))
    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.args.return_value.get.return_value = "1"

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = json.dumps(util_load_json("test_data/get_SignatureList.json")).encode("ascii")

    mocker.patch("PicusNG.requests.get", return_value=mock_response)
    result = getSignatureList().outputs
    assert result[2]["id"] == 145546

def test_generateEndpointURL(mocker):
    from PicusNG import generateEndpointURL
    demisto_mock = mocker.patch("PicusNG.demisto")
    demisto_mock.params.return_value.get.return_value = "picus_server"
    res = generateEndpointURL("test", "test")
    assert res == ('picus_servertest', {"Content-Type": "application/json","Authorization":"Bearer test"})

def test_filterInsecureAttacks(mocker):
    from PicusNG import filterInsecureAttacks
    threatinfo_mock = mocker.patch("PicusNG.demisto")
    threatinfo_mock.args.return_value.get.return_value = "111=unblocked,222=blocked,333=unblocked"
    result = filterInsecureAttacks().outputs
    assert result == "111,333"