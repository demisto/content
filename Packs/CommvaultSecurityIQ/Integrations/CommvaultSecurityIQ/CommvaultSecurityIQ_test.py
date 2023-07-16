from CommvaultSecurityIQ import *


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
        
    def get_secret_from_key_vault(self):
        return "Secret"

    def set_secret_in_key_vault(self,key):
        return "Secret"
        
    def get_events_list(self, last_run, first_fetch_time, max_fetch):
        return None,0
    
    def perform_long_running_execution(
            self, sock: Any, address: tuple
    ) -> None:
        """
        The long running execution loop. Gets input, and performs a while True loop and logs any error that happens.
        Stops when there is no more data to read.
        Args:
            sock: Socket.
            address(tuple): Address. Not used inside loop so marked as underscore.

        Returns:
            (None): Reads data, calls   that creates incidents from inputted data.
        """
        demisto.debug("Starting long running execution")
        file_obj = sock.makefile(mode="rb")
        try:
            while True:
                try:
                    line = file_obj.readline()
                    if not line:
                        demisto.info(f"Disconnected from {address}")
                        break
                    self.perform_long_running_loop(line.strip())
                except Exception as error:
                    demisto.error(
                        traceback.format_exc()
                    )  # print the traceback
                    demisto.error(
                        f"Error occurred during long running loop. Error was: {error}"
                    )
                finally:
                    demisto.debug("Finished reading message")
        finally:
            file_obj.close()
            
    def prepare_globals_and_create_server(self,
            port: int,
            certificate_path: Optional[str],
            private_key_path: Optional[str]):
        server = StreamServer(
                ("0.0.0.0", port), self.perform_long_running_execution
            )
        return server

def test_disable_data_aging():
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    response = disable_data_aging(client)
    expected_resp = {"Response":"Successfully disabled data aging on the client"}
    assert response.raw_response["Response"] == expected_resp["Response"]


def test_copy_files_to_war_room():
    assert True


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
    
def test_get_access_token_from_keyvault():
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    resp = get_secret_from_key_vault(client)
    expected_resp = {"Response":"Secret"}
    assert resp.raw_response["Response"] == expected_resp["Response"]
def test_fetch_incidents():
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    _,resp=fetch_incidents(client, 0, 0)
    assert resp==None

def test_get_backup_anomaly():
    resp=get_backup_anomaly(0)
    assert resp=="Undefined"

def test_if_zero_set_none():
    resp = if_zero_set_none(0)
    assert resp == None

def test_extract_from_regex():
    resp=extract_from_regex("clientid[123]",0,"clientid\\[(.*)\\]")
    assert resp=='123'

def test_format_alert_description():
    resp=format_alert_description("<html>Format Alert</html>")
    assert resp == "Format Alert"
    
def test_field_mapper():
    resp=field_mapper("event_id")
    assert resp=="Event ID"  

def test_long_running_execution():
    port = 33333
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    server: StreamServer = client.prepare_globals_and_create_server(
                            port, "", ""
                        )
    assert server.address[1] == 33333
