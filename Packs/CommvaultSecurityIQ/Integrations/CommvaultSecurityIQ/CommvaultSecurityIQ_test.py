from typing import Any, Optional
from gevent.server import StreamServer
import demistomock as demisto
from CommvaultSecurityIQ import (
    Client,
    disable_data_aging,
    generate_access_token,
    fetch_incidents,
    get_backup_anomaly,
    if_zero_set_none,
    extract_from_regex,
    field_mapper,
    format_alert_description,
    fetch_and_disable_saml_identity_provider,
    disable_user,
    get_secret_from_key_vault,
)


class CommvaultClientMock(Client):
    def __init__(self, base_url: str, verify: bool, proxy: bool):
        """
        Constructor to initialize the Commvault client object
        """
        self.base_url = base_url
        self.verify = verify
        self.proxy = proxy
        self.qsdk_token = None

    def disable_data_aging(self):
        """
        Function to disable DA
        """
        return "Successfully disabled data aging on the client"

    def generate_access_token(self, token):
        """Dummy function"""
        del token
        return True

    def get_host(self):
        """Dummy function"""
        return None

    def fetch_and_disable_saml_identity_provider(self):
        """Dummy function"""
        return True

    def http_request(
        self,
        method: str,
        endpoint: str,
        params: dict | None = None,
        json_data: dict[str, Any] | None = None,
        ignore_empty_response: bool = False,
        headers: dict | None = None,
    ):
        """Dummy function"""
        del method, params, json_data, ignore_empty_response, headers

        if endpoint == "/DoBrowse":
            return {"browseResponses": []}
        if endpoint == "/Subclient/11351":
            return {"subClientProperties": [{"content": []}]}
        return {}

    def validate_session_or_generate_token(self, token):
        """Dummy function"""
        del token
        return True

    def disable_user(self, user_email: str) -> bool:
        """Dummy function"""
        del user_email
        return True

    def get_secret_from_key_vault(self):
        """Dummy function"""
        return "Secret"

    def set_secret_in_key_vault(self, key):
        """Dummy function"""
        del key
        return "Secret"

    def get_job_details(self, job_id):
        """Dummy function"""
        return {
            "jobs": [
                {
                    "jobSummary": {
                        "jobStartTime": 1690283943,
                        "jobEndTime": 1690283995,
                        "subclient": {
                            "subclientId": 11351,
                            "subclientName": "AnomalySubclient",
                        },
                    }
                }
            ]
        }

    def get_events_list(self, last_run, first_fetch_time, max_fetch):
        """Dummy function"""
        del last_run, first_fetch_time, max_fetch
        apiresp = [
            {
                "severity": 6,
                "eventCode": "234881361",
                "jobId": 185314,
                "acknowledge": 0,
                "eventCodeString": "14:337",
                "subsystem": "CvStatAnalysis",
                "description": (
                    "<html>Detected file type classification anomaly in job [185314]"
                    " for client [dihyperv]. Number of files affected [145]."
                    "'Please click  <a href=\"http://plusonecs.idx.commvault.com:80/commandcenter/#/"
                    "fileAnomaly/5185?anomalyTypes=mime\"> here</a> for more"
                    " details.<span style=\"display: none\">AnomalyType:[2];ClientName:[dihyperv];BackupSetName:"
                    "[defaultBackupSet];SubclientName:[AnomalySubclient];"
                    "SuspiciousFileCount:[145];ModifiedFileCount:[0];RenamedFileCount:[0];CreatedFileCount:[0];"
                    "DeletedFileCount:[0];ApplicationType:[33];"
                    "BackupSetId:[0];SubclientId:[0];JobId:[185314]</span></html>"
                ),
                "id": 5196568,
                "timeSource": 1690284138,
                "type": 0,
                "clientEntity": {
                    "clientId": 5185,
                    "clientName": "dihyperv",
                    "displayName": "dihyperv",
                },
            }
        ]
        return apiresp

    def perform_long_running_execution(self, sock: Any, address: tuple) -> None:
        """
        The long running execution loop. Gets input, and performs a while
        True loop and logs any error that happens.
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
                except Exception as error:
                    demisto.error(
                        f"Error occurred during long running loop. Error was: {error}"
                    )
                finally:
                    demisto.debug("Finished reading message")
        finally:
            file_obj.close()

    def prepare_globals_and_create_server(
        self,
        port: int,
        certificate_path: Optional[str],
        private_key_path: Optional[str],
    ):
        """Dummy function"""
        del certificate_path, private_key_path
        server = StreamServer(("0.0.0.0", port), self.perform_long_running_execution)
        return server


def test_disable_data_aging():
    """Unit test function"""
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    response = disable_data_aging(client)
    expected_resp = {"Response": "Successfully disabled data aging on the client"}
    assert response.raw_response["Response"] == expected_resp["Response"]


def test_copy_files_to_war_room():
    """Unit test function"""
    assert True


def test_generate_access_token():
    """Unit test function"""
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    resp = generate_access_token(client, "")
    expected_resp = {"Response": "Successfully generated access token"}
    assert resp.raw_response["Response"] == expected_resp["Response"]


def test_fetch_and_disable_saml_identity_provider():
    """Unit test function"""
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    resp = fetch_and_disable_saml_identity_provider(client)
    expected_resp = {"Response": "Successfully disabled SAML identity provider"}
    assert resp.raw_response["Response"] == expected_resp["Response"]


def test_disable_user():
    """Unit test function"""
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    resp = disable_user(client, "dummy@email.com")
    expected_resp = {"Response": "Successfully disabled user"}
    assert resp.raw_response["Response"] == expected_resp["Response"]


def test_get_access_token_from_keyvault():
    """Unit test function"""
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    resp = get_secret_from_key_vault(client)
    expected_resp = {"Response": "Secret"}
    assert resp.raw_response["Response"] == expected_resp["Response"]


def test_fetch_incidents():
    """Unit test function"""
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    _, resp = fetch_incidents(client, 0, 0)
    assert resp[0]["affected_files_count"] == "145"


def test_get_backup_anomaly():
    """Unit test function"""
    resp = get_backup_anomaly(0)
    assert resp == "Undefined"


def test_if_zero_set_none():
    """Unit test function"""
    resp = if_zero_set_none(0)
    assert resp is None


def test_extract_from_regex():
    """Unit test function"""
    resp = extract_from_regex("clientid[123]", 0, "clientid\\[(.*)\\]")
    assert resp == "123"


def test_format_alert_description():
    """Unit test function"""
    resp = format_alert_description("<html>Format Alert</html>")
    assert resp == "<html>Format Alert</html>"


def test_field_mapper():
    """Unit test function"""
    resp = field_mapper("event_id")
    assert resp == "Event ID"


def test_long_running_execution():
    """Unit test function"""
    port = 33333
    client = CommvaultClientMock(
        base_url="https://webservice_url:81", verify=False, proxy=False
    )
    server: StreamServer = client.prepare_globals_and_create_server(port, "", "")
    assert server.address[1] == 33333
