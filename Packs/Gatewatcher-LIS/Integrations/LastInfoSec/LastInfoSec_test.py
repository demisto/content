from LastInfoSec import (
    lis_get_by_minute,
    lis_get_by_value,
    generic_reputation_command,
    lis_is_email_leaked,
    lis_get_leaked_email_by_domain,
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
def get_generic_reputation_command():
    return load_json("test_data/generic_reputation_command.json")


@pytest.fixture
def get_generic_reputation_command_result():
    return load_json("test_data/generic_reputation_command_result.json")


@pytest.fixture
def get_by_minute():
    return load_json("test_data/get_by_minute.json")


@pytest.fixture
def get_by_minute_result():
    return load_json("test_data/get_by_minute_result.json")


@pytest.fixture
def get_by_value():
    return load_json("test_data/get_by_value.json")


@pytest.fixture
def get_by_value_result():
    return load_json("test_data/get_by_value_result.json")


@pytest.fixture
def get_leaked_email_by_domain():
    return load_json("test_data/get_leaked_email_by_domain.json")


@pytest.fixture
def get_leaked_email_by_domain_result():
    return load_json("test_data/get_leaked_email_by_domain_result.json")


@pytest.fixture
def is_email_leaked():
    return load_json("test_data/is_email_leaked.json")


@pytest.fixture
def is_email_leaked_result():
    return load_json("test_data/is_email_leaked_result.json")


@pytest.fixture
def prefix_mapping():
    return {
        "lis_get_by_minute": "LIS.GetByMinute",
        "lis_get_by_minute_with_filter": "LIS.GetByMinute",
        "lis_get_by_value": "LIS.GetByValue",
        "lis_get_leaked_email_by_domain": "LIS.LeakedEmail.GetByDomain",
        "lis_is_email_leaked": "LIS.LeakedEmail.GetByEmail",
    }


@pytest.fixture
def client():
    client = GwClient(token="XZXZXZXZXZXZXZXXZ")
    return client


@pytest.mark.parametrize("index,cmd_type,val,rel", [
    (0, "file", "DRAFT_BL_114172022.pdf.vbs", "C - Fairly reliable"),
    (1, "domain", "pttpostu.xyz", "C - Fairly reliable"),
    (2, "url", "http://103.38.236.46/ntpvip.exe", "C - Fairly reliable"),
])
def test_lis_generic_reputation_command(
    client,
    requests_mock,
    cmd_type,
    index,
    val,
    rel,
    get_generic_reputation_command,
    get_generic_reputation_command_result
):
    output_prefixes = {
        "file": "LIS.File",
        "domain": "LIS.Domain",
        "url": "LIS.URL",
    }
    args = {
        cmd_type: val,
    }
    requests_mock.post(
        f"https://api.client.lastinfosec.com/v2/lis/search?api_key={client.token}&headers=false",
        json=get_generic_reputation_command,
        status_code=200
    )
    response = generic_reputation_command(client, args, cmd_type, rel)
    assert response[0].outputs == get_generic_reputation_command_result[index]
    assert response[0].outputs_prefix == output_prefixes[cmd_type]
    requests_mock.post(
        f"https://api.client.lastinfosec.com/v2/lis/search?api_key={client.token}&headers=false",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        generic_reputation_command(client, args, cmd_type, rel)


@pytest.mark.parametrize("error", [{"Minute": "error"}, {"Minute": "2", "Type": "Filename"},
                                   {"Minute": "2", "Risk": "Informational"}])
def test_lis_get_by_minute_with_error(client, prefix_mapping, error, get_by_minute, get_by_minute_result):
    with pytest.raises(ValueError):
        lis_get_by_minute(client, error)


def test_lis_get_by_minute_with_filter(client, requests_mock, prefix_mapping, get_by_minute, get_by_minute_result):
    args = {
        "Minute": "2",
        "Type": "SHA1",
        "Risk": "Suspicious",
        "TLP": "white",
        "Categories": "malware"
    }
    requests_mock.get(
        f"https://api.client.lastinfosec.com/v2/lis/getbyminutes/2?api_key={client.token}&headers=false",
        json=get_by_minute,
        status_code=200
    )
    response = lis_get_by_minute(client, args)
    assert response.outputs == [get_by_minute_result[0]]
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.get(
        f"https://api.client.lastinfosec.com/v2/lis/getbyminutes/2?api_key={client.token}&headers=false",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        lis_get_by_minute(client, args)


def test_lis_get_by_minute(client, requests_mock, prefix_mapping, get_by_minute, get_by_minute_result):
    args = {
        "Minute": "2"
    }
    requests_mock.get(
        f"https://api.client.lastinfosec.com/v2/lis/getbyminutes/2?api_key={client.token}&headers=false",
        json=get_by_minute,
        status_code=200
    )
    response = lis_get_by_minute(client, args)
    assert response.outputs == get_by_minute_result
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.get(
        f"https://api.client.lastinfosec.com/v2/lis/getbyminutes/2?api_key={client.token}&headers=false",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        lis_get_by_minute(client, args)


def test_lis_get_by_value(client, requests_mock, prefix_mapping, get_by_value, get_by_value_result):
    args = {"Value": "b71c7db7c4b20c354f63820df1f5cd94dbec97849afa690675d221964b8176b5"}
    requests_mock.post(
        f"https://api.client.lastinfosec.com/v2/lis/search?api_key={client.token}&headers=false",
        json=get_by_value,
        status_code=200
    )
    response = lis_get_by_value(client, args)
    assert response.outputs == get_by_value_result
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.post(
        f"https://api.client.lastinfosec.com/v2/lis/search?api_key={client.token}&headers=false",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        lis_get_by_value(client, args)


@pytest.mark.parametrize("index,args,code", [
    (0, {"Domain": "baz.test"}, 200),
    (1, {"Domain": "baz.test"}, 200),
    (2, {"Domain": "baz.test", "After": "2021-08-01T00:00:00"}, 200),
    (3, {"Domain": "baz.test", "After": "]"}, 422),
])
def test_lis_get_leaked_email_by_domain(
    client,
    requests_mock,
    index,
    args,
    code,
    get_leaked_email_by_domain,
    get_leaked_email_by_domain_result,
    prefix_mapping
):
    domain = args.get("Domain", None)
    after = args.get("After", None)

    url = f"https://api.client.lastinfosec.com/v2/lis/leaked_emails/get_by_domain/{domain}?api_key={client.token}&headers=false"
    url += f"&added_after={after}" if after else ""

    requests_mock.get(
        url,
        json=get_leaked_email_by_domain[index],
        status_code=code,
    )

    if code != 200:
        with pytest.raises(GwAPIException):
            lis_get_leaked_email_by_domain(client, args)
        return

    response = lis_get_leaked_email_by_domain(client, args)
    assert response.outputs == get_leaked_email_by_domain_result[index]
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]


@pytest.mark.parametrize("index,args,code", [
    (0, {"Email": "foo.bar@baz.test"}, 200),
    (1, {"Email": "foo.bar@baz.test"}, 200),
    (2, {"Email": "foo.bar@baz.test", "After": "2021-08-01T00:00:00"}, 200),
    (3, {"Email": "foo.bar@baz.test", "After": "]"}, 422),
])
def test_lis_is_email_leaked(
    client,
    requests_mock,
    index,
    args,
    code,
    is_email_leaked,
    is_email_leaked_result,
    prefix_mapping
):
    email = args.get("Email", None)
    after = args.get("After", None)

    url = f"https://api.client.lastinfosec.com/v2/lis/leaked_emails/get_by_email/{email}?api_key={client.token}&headers=false"
    url += f"&added_after={after}" if after else ""

    requests_mock.get(
        url,
        json=is_email_leaked[index],
        status_code=code,
    )

    if code != 200:
        with pytest.raises(GwAPIException):
            lis_is_email_leaked(client, args)
        return

    response = lis_is_email_leaked(client, args)
    assert response.outputs == is_email_leaked_result[index]
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
