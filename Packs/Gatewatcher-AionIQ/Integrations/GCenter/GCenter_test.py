"""Unit Tests file"""

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from GCenter import (
    gw_get_alert,
    gw_get_malcore_list_entry,
    gw_add_malcore_list_entry,
    gw_del_malcore_list_entry,
    gw_get_dga_list_entry,
    gw_add_dga_list_entry,
    gw_del_dga_list_entry,
    gw_es_query,
    gw_es_wrapper,
    gw_get_file_infected,
    gw_get_ignore_asset_name,
    gw_get_ignore_kuser_ip,
    gw_get_ignore_kuser_name,
    gw_get_ignore_mac_address,
    gw_add_ignore_asset_name,
    gw_add_ignore_kuser_ip,
    gw_add_ignore_kuser_name,
    gw_add_ignore_mac_address,
    gw_del_ignore_asset_name,
    gw_del_ignore_kuser_ip,
    gw_del_ignore_kuser_name,
    gw_del_ignore_mac_address,
    gw_send_malware,
    gw_send_powershell,
    gw_send_shellcode,
    GwClient,
    GwAPIException
)
import inspect
import json
import pytest


def load_json(file):
    with open(file) as f:
        return json.load(f)


@pytest.fixture
def raw_alerts_read():
    return load_json("test_data/raw_alerts_read.json")


@pytest.fixture
def get_dga_list():
    return load_json("test_data/get_dga_list.json")


@pytest.fixture
def add_dga_list():
    return load_json("test_data/add_dga_list.json")


@pytest.fixture
def get_malcore_list():
    return load_json("test_data/get_malcore_list.json")


@pytest.fixture
def add_malcore_list():
    return load_json("test_data/add_malcore_list.json")


@pytest.fixture
def es_query():
    return load_json("test_data/es_query.json")


@pytest.fixture
def es_wrapper_src_ip():
    return load_json("test_data/es_wrapper_src_ip.json")


@pytest.fixture
def es_wrapper_sha256():
    return load_json("test_data/es_wrapper_sha256.json")


@pytest.fixture
def get_file_infected_es():
    return load_json("test_data/get_file_infected_es.json")


@pytest.fixture
def get_ignore_asset_name():
    return load_json("test_data/get_ignore_asset_name.json")


@pytest.fixture
def get_ignore_kuser_name():
    return load_json("test_data/get_ignore_kuser_name.json")


@pytest.fixture
def get_ignore_kuser_ip():
    return load_json("test_data/get_ignore_kuser_ip.json")


@pytest.fixture
def get_ignore_mac_address():
    return load_json("test_data/get_ignore_mac_address.json")


@pytest.fixture
def ignore_asset_name():
    return load_json("test_data/ignore_asset_name.json")


@pytest.fixture
def ignore_kuser_name():
    return load_json("test_data/ignore_kuser_name.json")


@pytest.fixture
def ignore_kuser_ip():
    return load_json("test_data/ignore_kuser_ip.json")


@pytest.fixture
def ignore_mac_address():
    return load_json("test_data/ignore_mac_address.json")


@pytest.fixture
def send_malware():
    return load_json("test_data/send_malware.json")


@pytest.fixture
def send_powershell():
    return load_json("test_data/send_powershell.json")


@pytest.fixture
def send_shellcode():
    return load_json("test_data/send_shellcode.json")


@pytest.fixture
def prefix_mapping():
    return {
        "gw_get_alert": "GCenter.Alert.Single",
        "gw_get_malcore_list_entry": "GCenter.Malcore.List",
        "gw_add_malcore_list_entry": "GCenter.Malcore",
        "gw_del_malcore_list_entry": "GCenter.Malcore",
        "gw_get_dga_list_entry": "GCenter.Dga.List",
        "gw_add_dga_list_entry": "GCenter.Dga",
        "gw_del_dga_list_entry": "GCenter.Dga",
        "gw_es_query": "GCenter.Elastic",
        "gw_es_wrapper": "GCenter.Elastic.Wrapper",
        "gw_get_file_infected": "GCenter.File",
        "gw_get_ignore_asset_name": "GCenter.Ignore.AssetName.List",
        "gw_get_ignore_kuser_ip": "GCenter.Ignore.KuserIP.List",
        "gw_get_ignore_kuser_name": "GCenter.Ignore.KuserName.List",
        "gw_get_ignore_mac_address": "GCenter.Ignore.MacAddress.List",
        "gw_add_ignore_asset_name": "GCenter.Ignore.AssetName",
        "gw_add_ignore_kuser_ip": "GCenter.Ignore.KuserIP",
        "gw_add_ignore_kuser_name": "GCenter.Ignore.KuserName",
        "gw_add_ignore_mac_address": "GCenter.Ignore.MacAddress",
        "gw_del_ignore_asset_name": "GCenter.Ignore.AssetName",
        "gw_del_ignore_kuser_ip": "GCenter.Ignore.KuserIP",
        "gw_del_ignore_kuser_name": "GCenter.Ignore.KuserName",
        "gw_del_ignore_mac_address": "GCenter.Ignore.MacAddress",
        "gw_send_malware": "GCenter.Gscan.Malware",
        "gw_send_powershell": "GCenter.Gscan.Powershell",
        "gw_send_shellcode": "GCenter.Gscan.Shellcode"
    }


@pytest.fixture
def client(requests_mock):
    requests_mock.post(
        "https://10.10.10.10/api/auth/login",
        json={"token": "XZXZXZXZXZXZXZXXZ"}
    )
    client = GwClient(ip="10.10.10.10")
    client.auth(user="testuser", password="testpass")
    return client


@pytest.mark.parametrize("uid", ["xxx", "yyy"])
def test_gw_get_alert(client, requests_mock, uid, prefix_mapping, raw_alerts_read):
    args = {
        "uid": uid
    }
    requests_mock.get(
        f"https://{client.ip}/api/raw-alerts/{uid}/",
        json=raw_alerts_read,
        status_code=200
    )
    response = gw_get_alert(client, args)
    assert response.outputs == raw_alerts_read
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.get(
        f"https://{client.ip}/api/raw-alerts/{uid}/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_get_alert(client, args)


@pytest.mark.parametrize("ltype", ["white", "black"], ids=["test-white-list", "test-black-list"])
def test_gw_get_malcore_list_entry(client, requests_mock, ltype, prefix_mapping, get_malcore_list):
    args = {
        "type": ltype
    }
    requests_mock.get(
        f"https://{client.ip}/api/malcore/{ltype}-list/",
        json=get_malcore_list,
        status_code=200
    )
    response = gw_get_malcore_list_entry(client, args)
    assert response.outputs == get_malcore_list["results"]
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.get(
        f"https://{client.ip}/api/malcore/{ltype}-list/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_get_malcore_list_entry(client, args)


@pytest.mark.parametrize("ltype", ["white", "black"], ids=["test-white-list", "test-black-list"])
def test_gw_add_malcore_list_entry(client, requests_mock, ltype, prefix_mapping, add_malcore_list):
    args = {
        "type": ltype,
        "sha256": "yyyyyyyyyyyyyyyyyy",
        "comment": "test",
        "threat": "test"
    }
    requests_mock.post(
        f"https://{client.ip}/api/malcore/{ltype}-list/",
        json=add_malcore_list,
        status_code=201
    )
    response = gw_add_malcore_list_entry(client, args)
    assert response.outputs == add_malcore_list
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.post(
        f"https://{client.ip}/api/malcore/{ltype}-list/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_add_malcore_list_entry(client, args)


@pytest.mark.parametrize("ltype", ["white", "black"], ids=["test-white-list", "test-black-list"])
def test_gw_del_malcore_list_entry(client, requests_mock, ltype, prefix_mapping):
    args = {
        "type": ltype,
        "sha256": "yyyyyyyyyyyyyyyyyy"
    }
    requests_mock.delete(
        f"https://{client.ip}/api/malcore/{ltype}-list/yyyyyyyyyyyyyyyyyy",
        status_code=204
    )
    response = gw_del_malcore_list_entry(client, args)
    assert response.outputs is None
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.delete(
        f"https://{client.ip}/api/malcore/{ltype}-list/yyyyyyyyyyyyyyyyyy",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_del_malcore_list_entry(client, args)


@pytest.mark.parametrize("ltype", ["white", "black"], ids=["test-white-list", "test-black-list"])
def test_gw_get_dga_list_entry(client, requests_mock, ltype, prefix_mapping, get_dga_list):
    args = {
        "type": ltype
    }
    requests_mock.get(
        f"https://{client.ip}/api/dga-detection/{ltype}-list/",
        json=get_dga_list,
        status_code=200
    )
    response = gw_get_dga_list_entry(client, args)
    assert response.outputs == get_dga_list["results"]
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.get(
        f"https://{client.ip}/api/dga-detection/{ltype}-list/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_get_dga_list_entry(client, args)


@pytest.mark.parametrize("ltype", ["white", "black"], ids=["test-white-list", "test-black-list"])
def test_gw_add_dga_list_entry(client, requests_mock, ltype, prefix_mapping, add_dga_list):
    args = {
        "type": ltype,
        "domain": "yyyyyyyyyyyyyyyyyy",
        "comment": "test"
    }
    requests_mock.post(
        f"https://{client.ip}/api/dga-detection/{ltype}-list/",
        json=add_dga_list,
        status_code=201
    )
    response = gw_add_dga_list_entry(client, args)
    assert response.outputs == add_dga_list
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.post(
        f"https://{client.ip}/api/dga-detection/{ltype}-list/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_add_dga_list_entry(client, args)


@pytest.mark.parametrize("ltype", ["white", "black"], ids=["test-white-list", "test-black-list"])
def test_gw_del_dga_list_entry(client, requests_mock, ltype, prefix_mapping):
    args = {
        "type": ltype,
        "domain": "yyyyyyyyyyyyyyyyyy"
    }
    requests_mock.delete(
        f"https://{client.ip}/api/dga-detection/{ltype}-list/yyyyyyyyyyyyyyyyyy",
        status_code=204
    )
    response = gw_del_dga_list_entry(client, args)
    assert response.outputs is None
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.delete(
        f"https://{client.ip}/api/dga-detection/{ltype}-list/yyyyyyyyyyyyyyyyyy",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_del_dga_list_entry(client, args)


@pytest.mark.parametrize("index", ["suricata", "codebreaker"])
def test_gw_es_query(client, requests_mock, index, prefix_mapping, es_query):
    args = {
        "index": index,
        "query": "{}"
    }
    requests_mock.post(
        f"https://{client.ip}/api/data/es/search/?index={index}",
        json=es_query,
        status_code=200
    )
    response = gw_es_query(client, args)
    assert response.outputs == es_query
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.post(
        f"https://{client.ip}/api/data/es/search/?index={index}",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_es_query(client, args)


@pytest.mark.parametrize("aggs_term", ["src_ip", "SHA256"])
def test_gw_es_wrapper(client, requests_mock, aggs_term, prefix_mapping, es_wrapper_src_ip, es_wrapper_sha256):
    args = {
        "index": "malware",
        "aggs_term": aggs_term,
        "must_match": "state=Infectected",
        "timerange": "24",
        "size": "100",
        "formatted": "True"
    }
    data = es_wrapper_src_ip if aggs_term == "src_ip" else es_wrapper_sha256
    requests_mock.post(
        f"https://{client.ip}/api/data/es/search/?index=malware",
        json=data,
        status_code=200
    )
    response = gw_es_wrapper(client, args)
    data = {
        aggs_term: [
            bucket['key'] for bucket in
            data['aggregations'][aggs_term]["buckets"]
        ]
    }
    assert response.outputs == data
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.post(
        f"https://{client.ip}/api/data/es/search/?index=malware",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_es_wrapper(client, args)


@pytest.mark.parametrize("uuid", ["85658c43-56d2-453d-9042-ee6b78930b0d", "b134c3d7-1871-4f96-ba80-7d0b44291a48"])
def test_gw_get_file_infected(client, requests_mock, uuid, prefix_mapping, get_file_infected_es):
    args = {
        "timerange": "24",
        "size": "100"
    }
    get_file_infected_es["aggregations"]["uuid"]["buckets"][0]["key"] = uuid
    requests_mock.post(
        f"https://{client.ip}/api/data/es/search/?index=malware",
        json=get_file_infected_es,
        status_code=200
    )
    requests_mock.get(
        f"https://{client.ip}/api/raw-alerts/{uuid}/file",
        headers={'Content-Type': 'application/zip',
                 'Content-Disposition': f'attachment; filename={uuid}.zip'
                 },
        status_code=200
    )
    response = gw_get_file_infected(client, args)
    assert response.outputs[0]['File'] == f'{uuid}.zip'
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.get(
        f"https://{client.ip}/api/raw-alerts/{uuid}/file",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_get_file_infected(client, args)


@pytest.mark.parametrize("name", ["test1", "test3"])
def test_gw_get_ignore_asset_name(client, requests_mock, name, prefix_mapping, get_ignore_asset_name):
    args = {}
    requests_mock.get(
        f"https://{client.ip}/api/ignore-lists/asset-names/",
        json=get_ignore_asset_name,
        status_code=200
    )
    response = gw_get_ignore_asset_name(client, args)
    assert response.outputs == get_ignore_asset_name["results"]
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.get(
        f"https://{client.ip}/api/ignore-lists/asset-names/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_get_ignore_asset_name(client, args)


@pytest.mark.parametrize("ip", ["10.10.10.10", "20.20.20.20"])
def test_gw_get_ignore_kuser_ip(client, requests_mock, ip, prefix_mapping, get_ignore_kuser_ip):
    args = {}
    requests_mock.get(
        f"https://{client.ip}/api/ignore-lists/kuser-ips/",
        json=get_ignore_kuser_ip,
        status_code=200
    )
    response = gw_get_ignore_kuser_ip(client, args)
    assert response.outputs == get_ignore_kuser_ip["results"]
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.get(
        f"https://{client.ip}/api/ignore-lists/kuser-ips/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_get_ignore_kuser_ip(client, args)


@pytest.mark.parametrize("name", ["test1", "test3"])
def test_gw_get_ignore_kuser_name(client, requests_mock, name, prefix_mapping, get_ignore_kuser_name):
    args = {}
    requests_mock.get(
        f"https://{client.ip}/api/ignore-lists/kuser-names/",
        json=get_ignore_kuser_name,
        status_code=200
    )
    response = gw_get_ignore_kuser_name(client, args)
    assert response.outputs == get_ignore_kuser_name["results"]
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.get(
        f"https://{client.ip}/api/ignore-lists/kuser-names/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_get_ignore_kuser_name(client, args)


@pytest.mark.parametrize("mac", ["00:50:50:50:50:50", "00:50:50:50:50:51"])
def test_gw_get_ignore_mac_address(client, requests_mock, mac, prefix_mapping, get_ignore_mac_address):
    args = {}
    requests_mock.get(
        f"https://{client.ip}/api/ignore-lists/mac-addresses/",
        json=get_ignore_mac_address,
        status_code=200
    )
    response = gw_get_ignore_mac_address(client, args)
    assert response.outputs == get_ignore_mac_address["results"]
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.get(
        f"https://{client.ip}/api/ignore-lists/mac-addresses/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_get_ignore_mac_address(client, args)


@pytest.mark.parametrize("name", ["test1", "test3"])
def test_gw_add_ignore_asset_name(client, requests_mock, name, prefix_mapping, ignore_asset_name):
    args = {
        "name": name,
        "start": True,
        "end": False
    }
    ignore_asset_name["name"] = name
    requests_mock.post(
        f"https://{client.ip}/api/ignore-lists/asset-names/",
        json=ignore_asset_name,
        status_code=201
    )
    response = gw_add_ignore_asset_name(client, args)
    assert response.outputs == ignore_asset_name
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.post(
        f"https://{client.ip}/api/ignore-lists/asset-names/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_add_ignore_asset_name(client, args)


@pytest.mark.parametrize("ip", ["10.10.10.10", "20.20.20.20"])
def test_gw_add_ignore_kuser_ip(client, requests_mock, ip, prefix_mapping, ignore_kuser_ip):
    args = {
        "ip": ip
    }
    ignore_kuser_ip["ip"] = ip
    requests_mock.post(
        f"https://{client.ip}/api/ignore-lists/kuser-ips/",
        json=ignore_kuser_ip,
        status_code=201
    )
    response = gw_add_ignore_kuser_ip(client, args)
    assert response.outputs == ignore_kuser_ip
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.post(
        f"https://{client.ip}/api/ignore-lists/kuser-ips/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_add_ignore_kuser_ip(client, args)


@pytest.mark.parametrize("name", ["test1", "test3"])
def test_gw_add_ignore_kuser_name(client, requests_mock, name, prefix_mapping, ignore_kuser_name):
    args = {
        "name": name,
        "start": True,
        "end": False
    }
    ignore_kuser_name["name"] = name
    requests_mock.post(
        f"https://{client.ip}/api/ignore-lists/kuser-names/",
        json=ignore_kuser_name,
        status_code=201
    )
    response = gw_add_ignore_kuser_name(client, args)
    assert response.outputs == ignore_kuser_name
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.post(
        f"https://{client.ip}/api/ignore-lists/kuser-names/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_add_ignore_kuser_name(client, args)


@pytest.mark.parametrize("mac", ["00:50:50:50:50:50", "00:50:50:50:50:51"])
def test_gw_add_ignore_mac_address(client, requests_mock, mac, prefix_mapping, ignore_mac_address):
    args = {
        "mac": mac,
        "start": True
    }
    ignore_mac_address["address"] = mac
    requests_mock.post(
        f"https://{client.ip}/api/ignore-lists/mac-addresses/",
        json=ignore_mac_address,
        status_code=201
    )
    response = gw_add_ignore_mac_address(client, args)
    assert response.outputs == ignore_mac_address
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.post(
        f"https://{client.ip}/api/ignore-lists/mac-addresses/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_add_ignore_mac_address(client, args)


@pytest.mark.parametrize("ignore_id", [1, 2])
def test_gw_del_ignore_asset_name(client, requests_mock, ignore_id, prefix_mapping):
    args = {
        "ignore_id": ignore_id
    }
    requests_mock.delete(
        f"https://{client.ip}/api/ignore-lists/asset-names/{ignore_id}/",
        status_code=204
    )
    response = gw_del_ignore_asset_name(client, args)
    assert response.outputs is None
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.delete(
        f"https://{client.ip}/api/ignore-lists/asset-names/{ignore_id}/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_del_ignore_asset_name(client, args)


@pytest.mark.parametrize("ignore_id", [1, 2])
def test_gw_del_ignore_kuser_ip(client, requests_mock, ignore_id, prefix_mapping):
    args = {
        "ignore_id": ignore_id
    }
    requests_mock.delete(
        f"https://{client.ip}/api/ignore-lists/kuser-ips/{ignore_id}/",
        status_code=204
    )
    response = gw_del_ignore_kuser_ip(client, args)
    assert response.outputs is None
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.delete(
        f"https://{client.ip}/api/ignore-lists/kuser-ips/{ignore_id}/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_del_ignore_kuser_ip(client, args)


@pytest.mark.parametrize("ignore_id", [1, 2])
def test_gw_del_ignore_kuser_name(client, requests_mock, ignore_id, prefix_mapping):
    args = {
        "ignore_id": ignore_id
    }
    requests_mock.delete(
        f"https://{client.ip}/api/ignore-lists/kuser-names/{ignore_id}/",
        status_code=204
    )
    response = gw_del_ignore_kuser_name(client, args)
    assert response.outputs is None
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.delete(
        f"https://{client.ip}/api/ignore-lists/kuser-names/{ignore_id}/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_del_ignore_kuser_name(client, args)


@pytest.mark.parametrize("ignore_id", [1, 2])
def test_gw_del_ignore_mac_address(client, requests_mock, ignore_id, prefix_mapping):
    args = {
        "ignore_id": ignore_id
    }
    requests_mock.delete(
        f"https://{client.ip}/api/ignore-lists/mac-addresses/{ignore_id}/",
        status_code=204
    )
    response = gw_del_ignore_mac_address(client, args)
    assert response.outputs is None
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.delete(
        f"https://{client.ip}/api/ignore-lists/mac-addresses/{ignore_id}/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_del_ignore_mac_address(client, args)


@pytest.mark.parametrize("filename, fileid", [
    ("test1", "332@dfca9ea2-5198-4d64-8c36-5282ac3b2dc5"),
    ("test2", "332@dfca9ea2-5198-4d64-8c36-5282ac3b2dc6")
])
def test_gw_send_malware(client, mocker, requests_mock, filename, fileid, prefix_mapping, send_malware):
    args = {
        "name": filename,
        "content": "this is a dummy response"
    }
    send_malware["file_name"] = filename
    mocker.patch("CommonServerPython.demisto.getFilePath", mocker.MagicMock(
        **{"return_value": {'id': fileid, 'path': filename, 'name': filename}}
    ))
    mocker.patch("builtins.open", mocker.mock_open())
    requests_mock.post(
        f"https://{client.ip}/api/gscan/malcore/",
        json=send_malware,
        status_code=201
    )
    response = gw_send_malware(client, args)
    assert response.outputs == send_malware
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    assert open.mock_calls[0][1] == (filename, 'rb')
    requests_mock.post(
        f"https://{client.ip}/api/gscan/malcore/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_send_malware(client, args)


@pytest.mark.parametrize("filename, fileid", [
    ("test1", "332@dfca9ea2-5198-4d64-8c36-5282ac3b2dc5"),
    ("test2", "332@dfca9ea2-5198-4d64-8c36-5282ac3b2dc6")
])
def test_gw_send_powershell(client, mocker, requests_mock, filename, fileid, prefix_mapping, send_powershell):
    args = {
        "name": filename,
        "content": "this is a dummy response"
    }
    send_powershell["file_name"] = filename
    mocker.patch("CommonServerPython.demisto.getFilePath", mocker.MagicMock(
        **{"return_value": {'id': fileid, 'path': filename, 'name': filename}}
    ))
    mocker.patch("builtins.open", mocker.mock_open())
    requests_mock.post(
        f"https://{client.ip}/api/gscan/powershell/",
        json=send_powershell,
        status_code=201
    )
    response = gw_send_powershell(client, args)
    assert response.outputs == send_powershell
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    assert open.mock_calls[0][1] == (filename, 'rb')
    requests_mock.post(
        f"https://{client.ip}/api/gscan/powershell/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_send_powershell(client, args)


@pytest.mark.parametrize("filename, fileid", [
    ("test1", "332@dfca9ea2-5198-4d64-8c36-5282ac3b2dc5"),
    ("test2", "332@dfca9ea2-5198-4d64-8c36-5282ac3b2dc6")
])
def test_gw_send_shellcode(client, mocker, requests_mock, filename, fileid, prefix_mapping, send_shellcode):
    args = {
        "name": filename,
        "content": "this is a dummy response",
        "deep": False,
        "timeout": 120
    }
    send_shellcode["file_name"] = filename
    mocker.patch("CommonServerPython.demisto.getFilePath", mocker.MagicMock(
        **{"return_value": {'id': fileid, 'path': filename, 'name': filename}}
    ))
    mocker.patch("builtins.open", mocker.mock_open())
    requests_mock.post(
        f"https://{client.ip}/api/gscan/shellcode/",
        json=send_shellcode,
        status_code=201
    )
    response = gw_send_shellcode(client, args)
    assert response.outputs == send_shellcode
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    assert open.mock_calls[0][1] == (filename, 'rb')
    requests_mock.post(
        f"https://{client.ip}/api/gscan/shellcode/",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        gw_send_shellcode(client, args)
