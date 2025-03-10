import json

import pytest

from appNovi import (
    Client,
    find_server_by_ip_command,
    search_appnovi_cve_servers_command,
    search_appnovi_connected_command,
    search_appnovi_prop_command,
    search_appnovi_command,
)


def generate_connected_components_call(load_file, post_req):
    def matchme(request, context):
        context.headers["Content-Type"] = "application/json"

        js = request.json()
        if not js:
            context.status_code = 400
        elif js != post_req:
            return []
        else:
            return util_load_json(load_file)

    return matchme


@pytest.fixture()
def client():
    return Client("https://13.37.13.37/api/v1")


@pytest.fixture()
def create_search_appnovi_mock(requests_mock):
    URL = "https://13.37.13.37/api/v1/components/"

    def _create(search_type, querystring, test_data):
        url = URL + search_type + "?" + querystring

        requests_mock.get(
            url,
            json=util_load_json(test_data),
            complete_qs=True,
        )

    return _create


@pytest.fixture()
def create_connected_components_mock(requests_mock):
    URL = "https://13.37.13.37/api/v1/components/connected"

    def _create(querystring, post_req, test_data):
        url = URL + "?" + querystring

        requests_mock.post(
            url,
            json=generate_connected_components_call(test_data, post_req),
            complete_qs=True,
        )

    return _create


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_search_appnovi_command(client, create_search_appnovi_mock):
    create_search_appnovi_mock(
        search_type="search",
        querystring="max_results=25&string=cve-2016&include_properties=true",
        test_data="test_data/search-appnovi-search-term-cve-2016.json",
    )

    create_search_appnovi_mock(
        search_type="search",
        querystring="max_results=25&string=blahblahempty&include_properties=true",
        test_data="test_data/search-appnovi-empty-components.json",
    )

    res = search_appnovi_command(client, args={"search_term": "cve-2016"})

    assert isinstance(res.outputs["components"], list)
    component = res.outputs["components"][0]

    assert component["u"]["userProperties"]["cve_name"] == "Update for Microsoft OneDrive for Business (KB3115163) 64-Bit Edition"

    res = search_appnovi_command(client, args={"search_term": "blahblahempty"})
    assert len(res.outputs["components"]) == 0


def test_search_appnovi_prop_command(client, create_search_appnovi_mock):
    create_search_appnovi_mock(
        search_type="propsearch",
        querystring="max_results=25&include_properties=true&prop=type&value=ec2",
        test_data="test_data/search-appnovi-prop-type-ec2.json",
    )

    create_search_appnovi_mock(
        search_type="propsearch",
        querystring="max_results=25&prop=forescout_awsInstanceType&value=t2.micro&include_properties=true",
        test_data="test_data/search-appnovi-prop-forescout_awsInstanceType.json",
    )
    create_search_appnovi_mock(
        search_type="propsearch",
        querystring="max_results=25&prop=nonexistentprop&value=nonexistent&include_properties=true",
        test_data="test_data/search-appnovi-empty-components.json",
    )

    res = search_appnovi_prop_command(client, args={"property": "type", "value": "ec2"})
    assert isinstance(res.outputs["components"], list)
    assert len(res.outputs["components"]) > 0
    assert res.outputs["components"][1]["name"] == "i-00dcd8ae659de6478"

    res = search_appnovi_prop_command(client, args={"property": "forescout_awsInstanceType", "value": "t2.micro"})

    assert isinstance(res.outputs["components"], list)
    assert len(res.outputs["components"]) > 0
    assert res.outputs["components"][1]["name"] == "i-0168be9037a2db5bf"

    res = search_appnovi_prop_command(client, args={"property": "nonexistentprop", "value": "nonexistent"})

    assert isinstance(res.outputs["components"], list)
    assert len(res.outputs["components"]) == 0


def test_search_appnovi_connected_command(client, create_connected_components_mock):
    create_connected_components_mock(
        querystring="max_results=25",
        post_req=["Things/40045"],
        test_data="test_data/connected-things-all-40045.json",
    )

    create_connected_components_mock(
        querystring="max_results=25&category=Interface",
        post_req=["Things/40045"],
        test_data="test_data/connected-things-interfaces-40045.json",
    )

    create_connected_components_mock(
        querystring="max_results=25&category=Interface&category=IPAddress",
        post_req=["Things/40045"],
        test_data="test_data/connected-things-ips,interfaces-40045.json",
    )

    create_connected_components_mock(
        querystring="max_results=25&type=mac",
        post_req=["Things/40045"],
        test_data="test_data/connected-things-mac-40045.json",
    )

    res = search_appnovi_connected_command(client, args={"identity": {"_id": "Things/40045"}})
    assert res.outputs[0]["_key"] == "4607"

    res = search_appnovi_connected_command(client, args={"identity": {"_id": "Things/40045"}, "category": "Interface"})
    assert res.outputs[0]["name"] == "48:16:76:47:40:1e"

    res = search_appnovi_connected_command(
        client,
        args={"identity": {"_id": "Things/40045"}, "category": "IPAddress,Interface"},
    )
    assert res.outputs[1]["name"] == "10.106.47.153"

    res = search_appnovi_connected_command(client, args={"identity": {"_id": "Things/40045"}, "type": "mac"})
    assert res.outputs[0]["_key"] == "4607"


def test_search_appnovi_cve_servers_command(client, create_connected_components_mock):
    create_connected_components_mock(
        querystring="max_results=25&category=Server",
        post_req=[{"type": "cve", "value": "CVE-2016-72473"}],
        test_data="test_data/search-appnovi-cve-servers.json",
    )

    res = search_appnovi_cve_servers_command(client, args={"cve": "cve-2016-72473"})
    assert len(res.outputs) == 7
    assert res.outputs[0]["name"] == "nakcorp-web-srv22c"

    res = search_appnovi_cve_servers_command(client, args={"cve": "cve-2016-723"})
    assert not res.outputs


def test_find_server_by_ip_command(client, create_connected_components_mock):
    create_connected_components_mock(
        querystring="max_results=25&category=Server&category=Interface",
        post_req=[{"type": "ip", "value": "10.142.45.111"}],
        test_data="test_data/server-by-ip-interfaces.json",
    )

    create_connected_components_mock(
        querystring="max_results=25&category=Server",
        post_req=["Things/4856"],
        test_data="test_data/server-by-ip-server.json",
    )

    res = find_server_by_ip_command(client, args={"ip": "10.142.45.111"})
    assert res.outputs[0]["name"] == "vm-4864371498218"

    res = find_server_by_ip_command(client, args={"ip": "11.34.34.34"})
    assert not res.outputs
