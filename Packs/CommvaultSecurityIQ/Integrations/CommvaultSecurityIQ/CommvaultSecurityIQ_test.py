from typing import Any
from gevent.server import StreamServer
import demistomock as demisto
import pytest
from datetime import datetime
from fastapi.security import HTTPBasicCredentials
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
    handle_post_helper,
    parse_no_length_limit,
    GenericWebhookAccessFormatter,
    copy_files_to_war_room,
    get_params,
    validate_inputs,
    add_vm_to_cleanroom,
    _authenticate_webhook_request,
    setup_credentials,
    token_auth,
)


class CommvaultClientMock(Client):
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
        del method, params, json_data, ignore_empty_response
        headers = self.headers
        del headers
        if endpoint == "/DoBrowse":
            return {
                "browseResponses": [
                    {
                        "respType": 0,
                        "browseResult": {
                            "dataResultSet": [
                                {
                                    "path": "C:\\Program Files\\Some file.txt",
                                    "size": "12023",
                                    "displayName": "Some file.txt",
                                }
                            ]
                        },
                    }
                ]
            }
        elif endpoint == "/Subclient/11351":
            return {"subClientProperties": [{"content": []}]}
        elif endpoint == "/V4/recoverytargets":
            return {"recoveryTargets": [{"id": "123", "applicationType": "CLEAN_ROOM"}]}
        elif endpoint == "/recoverygroup/recid/entity":
            return {"errorCode": 0, "errorMessage": ""}
        elif endpoint == "/v4/virtualmachines":
            return {
                "virtualMachines": [
                    {
                        "name": "vm_name",
                        "vmGroup": {"id": "id"},
                        "hypervisor": {"id": "id"},
                        "UUID": "UUID",
                        "backupset": {"backupSetId": "backupSetId"},
                    }
                ]
            }
        elif endpoint == "/User/":
            return {"subClientProperties": [{"content": [{"path": "C:\\Folder"}]}]}
        elif endpoint == "/recoverygroup":
            return {"recoveryGroup": {"id": "recid"}}
        elif endpoint.startswith("/events"):
            return {
                "commservEvents": [
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
                            "'Please click  <a hre"
                            'f="http://someaddress.commvault.com:80/commandcenter/#/'  # disable-secrets-detection
                            'fileAnomaly/5185?anomalyTypes=mime"> here</a> for more'
                            ' details.<span style="display: none">AnomalyType:[2];ClientName:[dihyperv];BackupSetName:'
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
            }
        elif endpoint.startswith("/User?level=10"):
            return {"users": [{"email": "dummy@email.com", "userEntity": {"userId": 1}}]}
        elif endpoint.startswith("/ApiToken/User"):
            return {"token": "keyvaulturl"}
        elif endpoint.startswith("/recoverygroups"):
            return {"recoveryGroups": [{"name": "recgid", "id": "id"}]}
        elif endpoint == "/User/1":
            return {"users": [{"enableUser": True}]}
        elif endpoint == "/User/1/Disable":
            return {"response": [{"errorCode": 0}]}
        elif endpoint.startswith("https://login.microsoftonline.com/"):
            return {"access_token": "access_token"}
        elif endpoint.startswith("/IdentityServers"):
            return {
                "identityServers": [
                    {"type": 1, "IdentityServerName": "name1"},
                    {"type": 1, "IdentityServerName": "name2"},
                ]
            }
        elif endpoint.startswith("/V4/SAML/name1"):
            return {"errorString": "Some error"}
        elif endpoint.startswith("/V4/SAML/name2"):
            return {"enabled": 1}
        elif endpoint.startswith("Job/"):
            return {
                "totalRecordsWithoutPaging": 10,
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
                ],
            }
        return {}

    def get_job_details(self, job_id):
        """Dummy function"""
        super().get_job_details(job_id)
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

    def get_secret_from_key_vault(self):
        return "secret"

    def set_secret_in_key_vault(self, key):
        """Dummy function"""
        del key
        return "Secret"

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
                    demisto.error(f"Error occurred during long running loop. Error was: {error}")
                finally:
                    demisto.debug("Finished reading message")
        finally:
            file_obj.close()


def test_disable_data_aging():
    """Unit test function"""
    client = CommvaultClientMock(
        base_url="https://webservice_url:81",
        verify=False,
        proxy=False,  # disable-secrets-detection
    )
    response = disable_data_aging(client)
    expected_resp = {"DisableDataAgingResponse": "Error disabling data aging on the client"}
    assert response.raw_response["DisableDataAgingResponse"] == expected_resp["DisableDataAgingResponse"]


def test_copy_files_to_war_room():
    """Unit test function"""
    copy_files_to_war_room()
    assert True


def test_generate_access_token():
    """Unit test function"""
    client = CommvaultClientMock(
        base_url="https://webservice_url:81",
        verify=False,
        proxy=False,  # disable-secrets-detection
    )
    resp = generate_access_token(client, "")
    expected_resp = {"GenerateTokenResponse": "Successfully generated access token"}
    assert resp.raw_response["GenerateTokenResponse"] == expected_resp["GenerateTokenResponse"]


def test_fetch_and_disable_saml_identity_provider():
    """Unit test function"""
    client = CommvaultClientMock(
        base_url="https://webservice_url:81",
        verify=False,
        proxy=False,  # disable-secrets-detection
    )
    resp = fetch_and_disable_saml_identity_provider(client)
    expected_resp = {"DisableSamlResponse": "Successfully disabled SAML identity provider"}
    assert resp.raw_response["DisableSamlResponse"] == expected_resp["DisableSamlResponse"]


def test_disable_user():
    """Unit test function"""
    client = CommvaultClientMock(
        base_url="https://webservice_url:81",
        verify=False,
        proxy=False,  # disable-secrets-detection
    )
    resp = disable_user(client, "dummy@email.com")
    expected_resp = {"DisableUserResponse": "Successfully disabled user"}
    assert resp.raw_response["DisableUserResponse"] == expected_resp["DisableUserResponse"]


def test_get_access_token_from_keyvault():
    """Unit test function"""
    client = CommvaultClientMock(base_url="https://webservice_url:81", verify=False, proxy=False)
    resp = get_secret_from_key_vault(client)
    expected_resp = {"GetAccessTokenResponse": "secret"}
    assert resp.raw_response["GetAccessTokenResponse"] == expected_resp["GetAccessTokenResponse"]


def test_fetch_incidents():
    """Unit test function"""
    client = CommvaultClientMock(
        base_url="https://webservice_url:81",
        verify=False,
        proxy=False,  # disable-secrets-detection
    )
    _, resp = fetch_incidents(client, {}, "2 Days")
    _, resp = fetch_incidents(client, {"last_fetch": 0}, "2 Days")
    assert resp[0]["affected_files_count"] == "145"  # type: ignore


def test_get_backup_anomaly():
    """Unit test function"""
    resp0 = get_backup_anomaly(0)
    resp1 = get_backup_anomaly(1)
    resp2 = get_backup_anomaly(2)
    assert resp0 == "Undefined"
    assert resp1 == "File Activity"
    assert resp2 == "File Type"


def test_if_zero_set_none():
    """Unit test function"""
    resp = if_zero_set_none(0)
    assert resp is None


def test_extract_from_regex():
    """Unit test function"""
    resp = extract_from_regex("clientid[123]", "0", "clientid\\[(.*)\\]")
    assert resp == "123"


def test_format_alert_description():
    """Unit test function"""
    resp = format_alert_description("<html>Detected file  Please click  </html>")
    assert resp == "<html>Detected file  Please click  </html>"


def test_field_mapper():
    """Unit test function"""
    resp = field_mapper("event_id")
    assert resp == "Event ID"


def test_long_running_execution():
    """Unit test function"""
    port = 33333
    client = CommvaultClientMock(
        base_url="https://webservice_url:81",
        verify=False,
        proxy=False,  # disable-secrets-detection
    )
    server: StreamServer = client.prepare_globals_and_create_server(port, "", "")
    assert server.address[1] == 33333


def test_add_vm_to_cleanroom(capfd):
    """Unit test function"""
    with capfd.disabled():
        client = CommvaultClientMock(
            base_url="https://webservice_url:81",
            verify=False,
            proxy=False,  # disable-secrets-detection
        )
        resp = add_vm_to_cleanroom(client, "vm_name", "02:12:2024 21:00:00")
        assert resp.raw_response["AddEntityToCleanroomResponse"] == "Successfully added entity to clean room."

        try:
            _ = client.get_point_in_time_timestamp("invalid date")
        except Exception as e:
            assert str(e) == "Invalid recovery point format. Use format dd:mm:yyyy hh:mm:ss"


def test_webhook():
    """Unit test function"""
    req = {
        "Alert": "File Activity Anomaly Alert",
        "Event ID": "38715891",
        "Job ID": "79037346",
        "Event Date": "Mon May  8 05: 05: 27 2023",
        "Event Code": "14: 337",
        "Program": "CvStatAnalysis",
        "Client": "dihyperv_fda",
        "Description": (
            "<html>Detected file type classification anomaly in job [171069] for client [dihyperv_fda]. "
            "Number of files affected [294]. Please click  <a href='http://Someaddress"  # disable-secrets-detection
            "SV11:80/commandcenter/#/fileAnomaly/44180?anomalyTypes=mime'> here</a> for "  # disable-secrets-detection
            "more details.<span style='display: none'>AnomalyType:[2];ClientName:[dihyperv_fda];"
            "BackupSetName:[defaultBackupSet];SubclientName:[AnomalySubclient];SuspiciousFileCount:[294];ModifiedFileCount:[0]"
            ";RenamedFileCount:[0];CreatedFileCount:[0];DeletedFileCount:[0];ApplicationType:[33];"
            "BackupSetId:[0];SubclientId:[0];JobId:[79037346]</span></html>"
        ),
    }
    client = CommvaultClientMock(base_url="https://webservice_url:81", verify=False, proxy=False)
    incident_body = handle_post_helper(client, req, None)
    client.create_incident(
        incident_body,
        datetime.fromtimestamp((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds()),
        "Commvault Suspicious File Activity",
        False,
    )
    client.create_incident(
        incident_body,
        datetime.fromtimestamp((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds()),
        "Commvault Suspicious File Activity",
        True,
    )
    assert incident_body["job_id"] == "171069"


def test_misc_functions():
    """Unit test"""
    string = "<133>Feb 25 14:09:07 webserver syslogd: restart"
    string = bytes(string, "utf-8")
    resp = parse_no_length_limit(string)
    assert resp.message.decode("utf-8") == "syslogd: restart"

    string = (
        "<133>Jul 25 08:55:19 someaddress.abc.commvault.com Jobid = {185348} Utctimestamp = {1690289280}"
        "Alertdescription = {  #011 Event ID: 5196807  #011 Event Date: Tue Jul 25 08:47:46 2023     #011"
        " Program: CvStatAnalysis     #011 Client: dihyperv     #011 Description: <html>Detected"
        " file type classification anomaly in job [185348] for client [dihyperv]. Number of "
        "files affected [132]..<span style='display: none'>AnomalyType:[2];ClientName"
        ":[dihyperv];BackupSetName:[defaultBackupSet];SubclientName:"
        "[AnomalySubclient];SuspiciousFileCount:[132];ModifiedFileCount:[0];RenamedFileCount:[0]"
        ";CreatedFileCount:[0];DeletedFileCount:[0];ApplicationType:[33];BackupSetId:[0];"
        "SubclientId:[0];JobId:[185348]</span></html>     #011}"
    )
    string = bytes(string, "utf-8")
    client = CommvaultClientMock(base_url="https://webservice_url:81", verify=False, proxy=False)
    client.set_props({"AzureKeyVaultUrl": {"password": "password"}})
    key = client.get_key_vault_access_token()

    assert key is None

    t = GenericWebhookAccessFormatter()
    t.get_user_agent({})

    resp = client.parse_incoming_message(string)
    assert resp["affected_files_count"] == "132"  # type: ignore

    resp = client.perform_long_running_loop(string)  # type: ignore

    resp = client.fetch_file_details(None, 0)
    assert resp[0] == []

    resp = client.define_severity("File Activity")
    assert resp == "Informational"

    resp = client.get_client_id()
    assert resp == "0"

    resp = client.is_port_in_use(0)
    assert not resp

    client.disable_data_aging()
    client.run_uvicorn_server(0, "", "")
    client.run_uvicorn_server(0, "/home", "/home")

    resp = get_params({})

    assert resp[0] == "1 day"

    client.ws_url = None
    resp = client.get_host()

    assert resp is None


def test_validate_inputs():
    client = CommvaultClientMock(base_url="https://webservice_url:81", verify=False, proxy=False)
    validate_inputs(0, client, True, True, False, "")


def test_validate_inputs_webhook_requires_listener_credentials(mocker):
    """
    Given: Forwarding Rule = Webhook is selected, but no Webhook Listener Credentials are configured.
    When:  validate_inputs is called (from test-module).
    Then:  An exception is raised demanding the credentials be set.
    """
    client = CommvaultClientMock(base_url="https://webservice_url:81", verify=False, proxy=False)
    mocker.patch.object(demisto, "params", return_value={})
    with pytest.raises(Exception, match="Webhook Listener Credentials"):
        validate_inputs(0, client, True, False, True, "webhook")


def test_validate_inputs_webhook_passes_when_credentials_present(mocker):
    """
    Given: Forwarding Rule = Webhook with Webhook Listener Credentials configured.
    When:  validate_inputs is called.
    Then:  No exception is raised (assuming Azure KeyVault validation passes).
    """
    client = CommvaultClientMock(base_url="https://webservice_url:81", verify=False, proxy=False)
    mocker.patch.object(
        demisto,
        "params",
        return_value={"credentials": {"identifier": "webhook-user", "password": "s3cret"}},
    )
    validate_inputs(0, client, True, False, True, "webhook")


def test_authenticate_webhook_request_rejects_missing_credentials_param(mocker):
    """
    Given: No listener credentials are configured on the instance.
    When:  _authenticate_webhook_request runs (defense-in-depth path).
    Then:  A 401 Response is returned regardless of what the client sent.
    """
    mocker.patch.object(demisto, "params", return_value={})
    resp = _authenticate_webhook_request(credentials=None, token=None)
    assert resp is not None
    assert resp.status_code == 401


def test_authenticate_webhook_request_rejects_bad_basic_auth(mocker):
    """
    Given: Listener configured with Basic Auth and a bad username/password is supplied.
    When:  _authenticate_webhook_request runs.
    Then:  A 401 Response is returned.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={"credentials": {"identifier": "user", "password": "pass"}},
    )
    bad = HTTPBasicCredentials(username="user", password="WRONG")
    resp = _authenticate_webhook_request(credentials=bad, token=None)
    assert resp is not None
    assert resp.status_code == 401


def test_authenticate_webhook_request_accepts_good_basic_auth(mocker):
    """
    Given: Listener configured with Basic Auth and matching credentials are supplied.
    When:  _authenticate_webhook_request runs.
    Then:  None is returned (request allowed through).
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={"credentials": {"identifier": "user", "password": "pass"}},
    )
    good = HTTPBasicCredentials(username="user", password="pass")
    assert _authenticate_webhook_request(credentials=good, token=None) is None


def test_authenticate_webhook_request_rejects_missing_basic_auth_when_configured(mocker):
    """
    Given: Listener configured with Basic Auth but the request carries no credentials at all.
    When:  _authenticate_webhook_request runs.
    Then:  A 401 Response is returned.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={"credentials": {"identifier": "user", "password": "pass"}},
    )
    resp = _authenticate_webhook_request(credentials=None, token=None)
    assert resp is not None
    assert resp.status_code == 401


def test_authenticate_webhook_request_header_token_modes(mocker):
    """
    Given: Listener configured with username `_header:X-Token`.
    When:  _authenticate_webhook_request runs with a wrong token, then a matching token.
    Then:  401 for wrong token, None for matching token.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={"credentials": {"identifier": "_header:X-Token", "password": "secret-token"}},
    )
    bad = _authenticate_webhook_request(credentials=None, token="WRONG")
    assert bad is not None
    assert bad.status_code == 401

    assert _authenticate_webhook_request(credentials=None, token="secret-token") is None


def test_setup_credentials_rebinds_token_header(mocker):
    """
    Given: Listener configured with username `_header:X-Custom-Header`.
    When:  setup_credentials runs at startup.
    Then:  The APIKeyHeader name is rebound to read from X-Custom-Header.
    """
    original_name = token_auth.model.name
    try:
        mocker.patch.object(
            demisto,
            "params",
            return_value={"credentials": {"identifier": "_header:X-Custom-Header", "password": "t"}},
        )
        setup_credentials()
        assert token_auth.model.name == "X-Custom-Header"
    finally:
        token_auth.model.name = original_name


def test_authenticate_webhook_request_header_mode_rejects_missing_token(mocker):
    """
    Given: Listener configured with username `_header:X-Token` (custom-header token mode).
    When:  A request arrives with no token header at all (token=None) - the attacker case.
    Then:  A 401 Response is returned (the listener is never left open when no header is sent).
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={"credentials": {"identifier": "_header:X-Token", "password": "secret-token"}},
    )
    resp = _authenticate_webhook_request(credentials=None, token=None)
    assert resp is not None
    assert resp.status_code == 401


def test_authenticate_webhook_request_header_mode_ignores_basic_auth(mocker):
    """
    Given: Listener configured in custom-header token mode (`_header:X-Token`).
    When:  An attacker presents valid-looking HTTP Basic Auth but no matching token header.
    Then:  A 401 Response is returned - Basic Auth cannot bypass the token requirement
           (no cross-mode confusion).
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={"credentials": {"identifier": "_header:X-Token", "password": "secret-token"}},
    )
    spoofed_basic = HTTPBasicCredentials(username="_header:X-Token", password="secret-token")
    resp = _authenticate_webhook_request(credentials=spoofed_basic, token=None)
    assert resp is not None
    assert resp.status_code == 401


def test_authenticate_webhook_request_header_mode_empty_password_rejects_all(mocker):
    """
    Given: Listener misconfigured with `_header:X-Token` but an EMPTY password (token).
    When:  A request arrives with a non-empty token, and again with an empty token.
    Then:  Both are rejected with 401 - an empty configured token never authorizes a request.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={"credentials": {"identifier": "_header:X-Token", "password": ""}},
    )
    non_empty = _authenticate_webhook_request(credentials=None, token="anything")
    assert non_empty is not None
    assert non_empty.status_code == 401

    empty = _authenticate_webhook_request(credentials=None, token="")
    assert empty is not None
    assert empty.status_code == 401


def test_authenticate_webhook_request_basic_mode_empty_password_rejects(mocker):
    """
    Given: Listener configured for Basic Auth with an EMPTY password.
    When:  A request supplies a wrong password, and again an empty password.
    Then:  Both are rejected with 401 - an empty configured password never authorizes.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={"credentials": {"identifier": "user", "password": ""}},
    )
    wrong = _authenticate_webhook_request(credentials=HTTPBasicCredentials(username="user", password="WRONG"), token=None)
    assert wrong is not None
    assert wrong.status_code == 401


def test_setup_credentials_basic_auth_leaves_default_header(mocker):
    """
    Given: Listener configured for plain Basic Auth (no `_header:` prefix).
    When:  setup_credentials runs at startup.
    Then:  The APIKeyHeader name is left at its default ("Authorization") - no rebind occurs.
    """
    original_name = token_auth.model.name
    try:
        token_auth.model.name = "Authorization"
        mocker.patch.object(
            demisto,
            "params",
            return_value={"credentials": {"identifier": "webhook-user", "password": "s3cret"}},
        )
        setup_credentials()
        assert token_auth.model.name == "Authorization"
    finally:
        token_auth.model.name = original_name
