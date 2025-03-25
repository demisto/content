import json
from ZeroFox_Key_Incidents import ZFClient

BASE_URL = "https://api.zerofox.com"
OK_CODES = (200, 201)
TOKEN = "token"

KEY_INCIDENTS_ENDPOINT = "/cti/key-incidents/"
CTI_TOKEN_ENDPOINT = "/auth/token/"

def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())

def build_zf_client(token=TOKEN) -> ZFClient:
    return ZFClient(
        base_url=BASE_URL,
        ok_codes=OK_CODES,
        username='',
        token=token,
    )

def test_toy(mocker):
    """
    Given:
        - An valid token and user
    When:
        - Getting a CTI token
    Then:
        - It should return a CTI token
    """
    client = build_zf_client()
    fake_token = "valid_token"

    mock_post = mocker.patch.object(client._session, "request", return_value=mocker.Mock(status_code=200, json=lambda: {"access": fake_token}))

    token = client.get_cti_authorization_token()

    assert token == fake_token
    mock_post.assert_called_once_with("POST", f"{BASE_URL}{CTI_TOKEN_ENDPOINT}", verify=True, params=None, data=None, json={'username': '', 'password': 'token'}, files=None, headers=None, auth=None, timeout=60.0)