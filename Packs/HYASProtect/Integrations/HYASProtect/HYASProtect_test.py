import pytest
import json
import io

from HYASProtect import Client, get_domain_verdict, get_ip_verdict, \
    get_fqdn_verdict, get_nameserver_verdict

client = Client(
    base_url="http://test.com",
    apikey="test"
)


def load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


DOMAIN_VERDICT_RECORD = load_json("test_data/domain_verdict.json")
IP_VERDICT_RECORD = load_json("test_data/ip_verdict.json")
FQDN_VERDICT_RECORD = load_json("test_data/fqdn_verdict.json")
NAMESERVER_VERDICT_RECORD = load_json("test_data/nameserver_verdict.json")


@pytest.mark.parametrize('raw_response, expected_output',
                         [(DOMAIN_VERDICT_RECORD, DOMAIN_VERDICT_RECORD)])
def test_get_domain_verdict(mocker, raw_response, expected_output):
    mocker.patch.object(client, 'query', side_effect=[raw_response])
    args = {
        "domain": "google.com"
    }

    output = get_domain_verdict(client, args)

    context_domain_verdict = output.to_context()["Contents"]
    assert context_domain_verdict == [expected_output]

    with pytest.raises(ValueError):
        get_domain_verdict(client, {"domain": "87327"})


@pytest.mark.parametrize('raw_response, expected_output',
                         [(IP_VERDICT_RECORD, IP_VERDICT_RECORD)])
def test_get_ip_verdict(mocker, raw_response, expected_output):
    mocker.patch.object(client, 'query', side_effect=[raw_response])
    args = {
        "ip": "8.8.8.8"
    }

    output = get_ip_verdict(client, args)

    context_ip_verdict = output.to_context()["Contents"]
    assert context_ip_verdict == [expected_output]

    with pytest.raises(ValueError):
        get_ip_verdict(client, {"ip": "aaaa"})


@pytest.mark.parametrize('raw_response, expected_output',
                         [(FQDN_VERDICT_RECORD, FQDN_VERDICT_RECORD)])
def test_get_fqdn_verdict(mocker, raw_response, expected_output):
    mocker.patch.object(client, 'query', side_effect=[raw_response])
    args = {
        "fqdn": "www.google.com"
    }

    output = get_fqdn_verdict(client, args)

    context_fqdn_verdict = output.to_context()["Contents"]
    assert context_fqdn_verdict == [expected_output]


@pytest.mark.parametrize('raw_response, expected_output',
                         [(NAMESERVER_VERDICT_RECORD, NAMESERVER_VERDICT_RECORD)])
def test_get_nameserver_verdict(mocker, raw_response, expected_output):
    mocker.patch.object(client, 'query', side_effect=[raw_response])
    args = {
        "nameserver": "ns1.example.com"
    }

    output = get_nameserver_verdict(client, args)

    context_nameserver_verdict = output.to_context()["Contents"]
    assert context_nameserver_verdict == [expected_output]
