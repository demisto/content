import json
import io
from unittest.mock import MagicMock

from requests import Response


# flake8: noqa

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_getAccessToken(mocker):
    from Picus import getAccessToken
    params_mock = mocker.patch("Picus.demisto")
    params_mock.params.return_value.get.return_value = "picus_server"
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = json.dumps({'data': {'access_token': 'test'}})

    requests_mock = mocker.patch("Picus.requests")
    requests_mock.Session.return_value.post.return_value = mock_response
    res = getAccessToken()
    assert res == 'test'


def test_generateEndpointURL(mocker):
    from Picus import generateEndpointURL
    params_mock = mocker.patch("Picus.demisto")
    params_mock.params.return_value.get.return_value = "picus_server"
    res = generateEndpointURL("test", "test")
    assert res == ('picus_servertest', {'X-Api-Token': 'Bearer test', 'Content-Type': 'application/json'})

def test_filterInsecureAttacks(mocker):
    from Picus import filterInsecureAttacks
    threatinfo_mock = mocker.patch("Picus.demisto")
    threatinfo_mock.args.return_value.get.return_value = "111=Insecure,222=Secure,333=Insecure"
    result = filterInsecureAttacks().outputs
    assert result == "111,333"


def test_getMitigationList(mocker):
    from Picus import getMitigationList
    mocker.patch("Picus.getAccessToken", return_value="test")
    mocker.patch("Picus.generateEndpointURL", return_value=(1, 1))
    args_mock = mocker.patch("Picus.demisto")
    args_mock.args.return_value.get.return_value = "1"
    mock_response = Response()
    mock_response.status_code = "200"
    mock_response._content = json.dumps(util_load_json("test_data/get_mitigations.json")).encode("ascii")
    mocker.patch("Picus.requests.post", return_value=mock_response)
    result = getMitigationList().outputs
    assert result[0]["signature_id"] == "1357"
    assert result[1]["signature_name"] == "test2_signature"


def test_getAttackResults(mocker):
    from Picus import getAttackResults
    mocker.patch("Picus.getAccessToken", return_value="test")
    mocker.patch("Picus.generateEndpointURL", return_value=(1, 1))
    args_mock = mocker.patch("Picus.demisto")
    args_mock.args.return_value.get.return_value = "all"
    mocker.patch("Picus.int", return_value=1)
    mocker.patch("Picus.any", return_value=True)

    mock_secure_response = Response()
    mock_insecure_response = Response()
    mock_secure_response.status_code = "200"
    mock_insecure_response.status_code = "200"
    mock_secure_response._content = json.dumps(util_load_json("test_data/get_secureAttackResults.json")).encode("ascii")
    mock_insecure_response._content = json.dumps(util_load_json("test_data/get_insecureAttackResults.json")).encode(
        "ascii")

    mocker.patch("Picus.requests.post", side_effect=[mock_secure_response, mock_insecure_response])
    result = getAttackResults().outputs
    assert result["results"][0][
               "threat_ids"] == "351578,674267,850468,773109,428692,768048,826183,692856,476996,587400,376491,723488"


def test_getThreatResults(mocker):
    from Picus import getThreatResults
    mocker.patch("Picus.getAccessToken", return_value="test")
    mocker.patch("Picus.generateEndpointURL", return_value=(1, 1))
    demisto_mock = mocker.patch("Picus.demisto")
    demisto_mock.args.return_value.get.side_effect = ["587400", "Picus_Attacker_3", "Win10-Det1", "HTTP"]

    mock_response = Response()
    mock_response.status_code = "200"
    mock_response._content = json.dumps(util_load_json("test_data/get_threatResults.json")).encode("ascii")

    mocker.patch("Picus.requests.post", return_value=mock_response)
    result = getThreatResults().outputs
    assert result["results"][0]["threat_results"] == "587400=Insecure"


def test_getPicusVersion(mocker):
    from Picus import getPicusVersion
    mocker.patch("Picus.getAccessToken", return_value="test")
    mocker.patch("Picus.generateEndpointURL", return_value=(1, 1))

    mock_response = Response()
    mock_response.status_code = "200"
    mock_response._content = json.dumps(util_load_json("test_data/get_versionInfo.json")).encode("ascii")

    mocker.patch("Picus.requests.post", return_value=mock_response)
    result = getPicusVersion().outputs
    assert result["version"] == 4074


def test_getPeerList(mocker):
    from Picus import getPeerList
    mocker.patch("Picus.getAccessToken", return_value="test")
    mocker.patch("Picus.generateEndpointURL", return_value=(1, 1))

    mock_response = Response()
    mock_response.status_code = "200"
    mock_response._content = json.dumps(util_load_json("test_data/get_peerList.json")).encode("ascii")

    mocker.patch("Picus.requests.post", return_value=mock_response)
    result = getPeerList().outputs
    assert result[2]["name"] == "Win10-Det2"


def test_getVectorList(mocker):
    from Picus import getVectorList
    mocker.patch("Picus.getAccessToken", return_value="test")
    mocker.patch("Picus.generateEndpointURL", return_value=(1, 1))

    mock_response = Response()
    mock_response.status_code = "200"
    mock_response._content = json.dumps(util_load_json("test_data/get_vectorList.json")).encode("ascii")

    mocker.patch("Picus.requests.post", return_value=mock_response)
    result = getVectorList().outputs
    assert result[0]["name"] == "Picus_Attacker_1 - Win10-Det1"


def test_runAttacks(mocker):
    from Picus import runAttacks
    mocker.patch("Picus.getAccessToken", return_value="test")
    mocker.patch("Picus.generateEndpointURL", return_value=(1, 1))
    demisto_mock = mocker.patch("Picus.demisto")
    demisto_mock.args.return_value.get.side_effect = ["561365", "PicusPeerEXT", "PicusPeerINT", "HTTP"]

    mock_response = Response()
    mock_response.status_code = "200"
    mock_response._content = json.dumps(util_load_json("test_data/runAttacks.json")).encode("ascii")

    mocker.patch("Picus.requests.post", return_value=mock_response)
    result = runAttacks().outputs
    assert result == "561365"


def test_triggerUpdate(mocker):
    from Picus import triggerUpdate
    mocker.patch("Picus.getAccessToken", return_value="test")
    mocker.patch("Picus.generateEndpointURL", return_value=(1, 1))

    mock_response = Response()
    mock_response.status_code = "200"
    mock_response._content = json.dumps(util_load_json("test_data/triggerUpdate.json")).encode("ascii")

    mocker.patch("Picus.requests.post", return_value=mock_response)
    result = triggerUpdate().outputs
    assert result["success"] == True


def test_getVectorCompare(mocker):
    from Picus import getVectorCompare
    mocker.patch("Picus.getAccessToken", return_value="test")
    mocker.patch("Picus.generateEndpointURL", return_value=(1, 1))
    demisto_mock = mocker.patch("Picus.demisto")
    demisto_mock.args.return_value.get.side_effect = ["PicusPeerEXT", "PicusPeerINT", 10]

    mock_response = Response()
    mock_response.status_code = "200"
    mock_response._content = json.dumps(util_load_json("test_data/get_vectorCompare.json")).encode("ascii")

    mocker.patch("Picus.requests.post", return_value=mock_response)
    result = getVectorCompare().outputs
    assert result[1]["name"] == "Jellyfin Server Side Request Forgery (SSRF) Vulnerability Variant-1"