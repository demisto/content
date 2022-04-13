import json
import io


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_authenticate_user(requests_mock):
    from FireMonSecurityManager import Client, authenticate_command

    mock_response = util_load_json("test_data/get_authentication.json")
    requests_mock.post("https://example.test.com/securitymanager/api/authentication/login", json=mock_response)

    client = Client(base_url="https://example.test.com", verify=False, proxy=False, username="test", password="test")

    response = authenticate_command(client)
    assert response is not None
    assert response.raw_response["authorized"] is True


def test_create_pp_ticket_command(requests_mock):
    from FireMonSecurityManager import Client, create_pp_ticket_command

    mock_response = util_load_json("test_data/get_authentication.json")
    requests_mock.post("https://example.test.com/securitymanager/api/authentication/login", json=mock_response)

    mock_response = util_load_json("test_data/get_workflows.json")
    requests_mock.get(
        "https://example.test.com/policyplanner/api/domain/1/workflow/version/latest/all", json=mock_response
    )

    mock_response = util_load_json("test_data/get_pp_ticket.json")
    requests_mock.post("https://example.test.com/policyplanner/api/domain/1/workflow/3/packet", json=mock_response)

    client = Client(base_url="https://example.test.com", verify=False, proxy=False, username="test", password="test")
    args = {
        "domain_id": 1,
        "workflow_name": "Access Req WF",
        "requirement": [{"action": "ACCEPT", "destinations": "2.2.2.2", "services": "http", "sources": "1.1.1.1"}],
        "priority": "Low",
        "due_date": "2021-08-26T03:50:17-04:00",
    }
    response = create_pp_ticket_command(client, args=args)
    assert response is not None
    assert response.outputs_prefix == "FireMonSecurityManager.CreatePPTicket"


def test_pca_new_command(requests_mock):
    from FireMonSecurityManager import Client, pca_command

    mock_response = util_load_json("test_data/get_authentication.json")
    requests_mock.post("https://example.test.com/securitymanager/api/authentication/login", json=mock_response)

    mock_response = util_load_json("test_data/get_rule_rec.json")
    requests_mock.post("https://example.test.com/orchestration/api/domain/1/change/rulerec", json=mock_response)

    mock_response = util_load_json("test_data/get_pca.json")
    requests_mock.post("https://example.test.com/orchestration/api/domain/1/change/device/9/pca", json=mock_response)

    client = Client(base_url="https://example.test.com", verify=False, proxy=False, username="test", password="test")

    args = {
        "sources": "10.1.1.1",
        "destinations": "1.1.1.1",
        "services": "tcp/8080",
        "action": "ACCEPT",
        "domain_id": 1,
        "device_group_id": 1,
    }

    response = pca_command(client, args=args)
    assert response is not None
    assert response.outputs_prefix == "FireMonSecurityManager.PCA"


def test_secrule_search_command(requests_mock):
    from FireMonSecurityManager import Client, secmgr_secrule_search_command

    mock_response = util_load_json("test_data/get_authentication.json")
    requests_mock.post("https://example.test.com/securitymanager/api/authentication/login", json=mock_response)

    mock_response = util_load_json("test_data/get_paged_search_secrule.json")
    requests_mock.get("https://example.test.com/securitymanager/api/siql/secrule/paged-search", json=mock_response)

    client = Client(base_url="https://example.test.com", verify=False, proxy=False, username="test", password="test")

    args = {"q": "test_query"}

    response = secmgr_secrule_search_command(client, args=args)
    assert response is not None
    assert response.outputs_prefix == "FireMonSecurityManager.SIQL"
