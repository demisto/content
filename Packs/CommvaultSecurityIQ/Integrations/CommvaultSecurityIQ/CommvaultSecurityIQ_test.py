from CommvaultSecurityIQ import (
    disable_data_aging,
    copy_files_to_war_room,
    generate_access_token,
    fetch_and_disable_saml_identity_provider,
    disable_user
)


class CommvaultClientMock:
    def __init__(self, base_url: str, verify: bool, proxy: bool):
        """
        Constructor to initialize the Commvault client object
        """
        self.qsdk_token = None

    def disable_data_aging(self):
        """
        Function to disable DA
        """
        return "Successfully disabled data aging on the client"

    def generate_access_token(self, token):
        return True

    def fetch_and_disable_saml_identity_provider(self):
        return True

    def http_request(
        self,
        method,
        endpoint,
        params,
        json_data,
        ignore_empty_response,
        headers,
    ) :
        return {"identityServers": None}

    def validate_session_or_generate_token(self, token):
        return

    def disable_user(self, user_email: str) -> bool:
        return True


def test_disable_data_aging():
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    response = disable_data_aging(client)
    
    expected_resp = {"Response":"Successfully disabled data aging on the client"}
    assert response.raw_response["Response"] == expected_resp["Response"]


def test_copy_files_to_war_room():
    response = copy_files_to_war_room()
    expected_resp = None
    assert response == expected_resp


def test_generate_access_token():
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    resp = generate_access_token(client, "")
    expected_resp = {"Response":"Successfully generated access token"}
    assert resp.raw_response["Response"] == expected_resp["Response"]


def test_fetch_and_disable_saml_identity_provider():
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    resp = fetch_and_disable_saml_identity_provider(client)
    expected_resp = {"Response":"Successfully disabled SAML identity provider"}
    assert resp.raw_response["Response"] == expected_resp["Response"]

def test_disable_user():
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    resp = disable_user(client,"dummy@email.com")
    expected_resp = {"Response":"Successfully disabled user"}
    assert resp.raw_response["Response"] == expected_resp["Response"]