import demistomock as demisto
import pytest
from CommonServerPython import DemistoException
from MicrosoftGraphSearch import main


@pytest.mark.parametrize(
    "id_params, expected_auth_id",
    [
        ({"_auth_id": "new-id"}, "new-id"),
        ({"_auth_id": "new-id", "creds_auth_id": {"password": "masked-id"}}, "new-id"),
        ({"creds_auth_id": {"password": "masked-id"}}, "masked-id"),
    ],
)
def test_main_auth_id_precedence(mocker, id_params, expected_auth_id):
    """
    Given:
        - Different combinations of the plain-text '_auth_id' param and the masked 'creds_auth_id' param.
    When:
        - main() is called with the test-module command.
    Then:
        - MsGraphClient is instantiated with auth_and_token_url (2nd positional argument) by precedence:
          '_auth_id' > 'creds_auth_id.password'.
    """
    import MicrosoftGraphSearch

    params = {"creds_enc_key": {"password": "enc-key"}, **id_params}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(MicrosoftGraphSearch, "get_integration_context", return_value={})
    mock_client_cls = mocker.patch("MicrosoftGraphSearch.MsGraphClient")
    mocker.patch.object(MicrosoftGraphSearch, "return_results")
    mocker.patch.object(MicrosoftGraphSearch, "return_error")

    main()

    assert mock_client_cls.call_args[0][1] == expected_auth_id


def test_main_raises_when_auth_id_missing(mocker):
    """
    Given:
        - Neither the '_auth_id' param nor the masked 'creds_auth_id' param is provided.
    When:
        - main() is called.
    Then:
        - A DemistoException "ID or Client ID must be provided." is raised and no client is created.
    """
    params = {"creds_enc_key": {"password": "enc-key"}}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_client_cls = mocker.patch("MicrosoftGraphSearch.MsGraphClient")

    with pytest.raises(DemistoException, match="ID or Client ID must be provided."):
        main()
    mock_client_cls.assert_not_called()
