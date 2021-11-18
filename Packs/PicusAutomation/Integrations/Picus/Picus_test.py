import json
import io
from requests import Response

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())

def test_filterInsecureAttacks(mocker):
    from Picus import filterInsecureAttacks
    threatinfo_mock = mocker.patch("Picus.demisto")
    threatinfo_mock.args.return_value.get.return_value="111=Insecure,222=Secure,333=Insecure"
    result = filterInsecureAttacks().outputs
    assert result == "111,333"

def test_getMitigationList(mocker):
    from Picus import getMitigationList
    mocker.patch("Picus.getAccessToken",return_value="test")
    mocker.patch("Picus.generateEndpointURL",return_value=(1,1))
    args_mock = mocker.patch("Picus.demisto")
    args_mock.args.return_value.get.return_value = "1"
    mock_response = Response()
    mock_response.status_code = "200"
    mock_response._content = json.dumps(util_load_json("test_data/get_mitigations.json")).encode("ascii")
    mocker.patch("Picus.requests.post",return_value=mock_response)
    result = getMitigationList().outputs
    assert result[0]["signature_id"] == "1357"
    assert result[1]["signature_name"] == "test2_signature"

def test_getAttackResults(mocker):
    from Picus import getAttackResults
    mocker.patch("Picus.getAccessToken",return_value="test")
    mocker.patch("Picus.generateEndpointURL",return_value=(1,1))
    args_mock = mocker.patch("Picus.demisto")
    args_mock.args.return_value.get.return_value = "all"
    mocker.patch("Picus.int", return_value=1)
    mocker.patch("Picus.any",return_value=True)

    mock_secure_response = Response()
    mock_insecure_response = Response()
    mock_secure_response.status_code = "200"
    mock_insecure_response.status_code = "200"
    mock_secure_response._content = json.dumps(util_load_json("test_data/get_secureAttackResults.json")).encode("ascii")
    mock_insecure_response._content = json.dumps(util_load_json("test_data/get_insecureAttackResults.json")).encode("ascii")

    mocker.patch("Picus.requests.post",side_effect=[mock_secure_response, mock_insecure_response])
    result = getAttackResults().outputs
    assert result["results"][0]["threat_ids"] == "351578,674267,850468,773109,428692,768048,826183,692856,476996,587400,376491,723488"

def test_getThreatResults(mocker):
    from Picus import getThreatResults
    mocker.patch("Picus.getAccessToken",return_value="test")
    mocker.patch("Picus.generateEndpointURL",return_value=(1,1))
    demisto_mock = mocker.patch("Picus.demisto")
    demisto_mock.args.return_value.get.side_effect = ["587400","Picus_Attacker_3","Win10-Det1","HTTP"]

    mock_response = Response()
    mock_response.status_code = "200"
    mock_response._content = json.dumps(util_load_json("test_data/get_threatResults.json")).encode("ascii")

    mocker.patch("Picus.requests.post",return_value=mock_response)
    result =getThreatResults().outputs
    assert result["results"][0]["threat_results"] == "587400=Insecure"

def test_getPicusVersion(mocker):
    from Picus import getPicusVersion
    mocker.patch("Picus.getAccessToken",return_value="test")
    mocker.patch("Picus.generateEndpointURL",return_value=(1,1))

    mock_response = Response()
    mock_response.status_code = "200"
    mock_response._content = json.dumps(util_load_json("test_data/get_versionInfo.json")).encode("ascii")

    mocker.patch("Picus.requests.post",return_value=mock_response)
    result = getPicusVersion().outputs
    assert result["version"] == 4074