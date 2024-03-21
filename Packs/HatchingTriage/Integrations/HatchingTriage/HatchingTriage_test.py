import json
import io
import demistomock as demisto
import HatchingTriage


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_sample_summary(mocker, requests_mock):
    """
    Given:
    - SampleID from previous file or url submission.

    When:
    - Running the !triage-get-sample-summary command

    Then:
    - Validate the returned data.
    """
    import CommonServerPython
    # Setup Mocks
    sample_id = '240321-t3mwmagds3'
    mocker.patch.object(demisto, 'args', return_value={'sample_id': sample_id})
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    client = HatchingTriage.Client(
        'https://test.com/api/v0',
        verify=True,
        headers={
            'Authorization': 'Bearer 123456'
        },
        proxy='proxy'
    )

    mock_response = util_load_json('test_data/sample_summary.json')
    requests_mock.get(f'https://test.com/api/v0/samples/{sample_id}/summary',
                      json=mock_response)

    results = HatchingTriage.get_sample_summary(client, **demisto.args())

    assert results[0].outputs.get('sample') == sample_id
    assert results[0].outputs.get('sha256') == 'c80004016d79c91b95a7e3001080e99a72ce98b24a77b76f6e4c98eaf1550620'
