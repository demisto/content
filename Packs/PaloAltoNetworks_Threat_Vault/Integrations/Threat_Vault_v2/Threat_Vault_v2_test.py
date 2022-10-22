import pytest

from Threat_Vault_v2 import Client, threat_batch_search_command, release_note_get_command, threat_signature_get_command


@pytest.mark.parametrize(
    'command, demisto_args, expected_results',
    [
        (
            threat_batch_search_command,
            {'id': '123', 'md5': '52463745'},
            'There can only be one argument from the following list in the command -> [id, md5, sha256, name]'
        ),
        (
            threat_batch_search_command,
            {},
            'One of following arguments is required -> [id, sha256, md5]'
        ),
        (
            release_note_get_command,
            {'version': '20.7'},
            'The following arguments are required -> [type, version]'
        ),
        (
            threat_signature_get_command,
            {},
            'One of following arguments is required -> [signature_id, sha256, md5]'
        )
    ]
)
def test_commands_failure(command, demisto_args, expected_results):

    client = ''

    with pytest.raises(Exception) as e:
        command(client, demisto_args)
    assert expected_results in str(e)
