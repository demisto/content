import json
import io
import demistomock as demisto
import HatchingTriage


client = HatchingTriage.Client(
    'https://test.com/api/v0',
    verify=True,
    headers={
        'Authorization': 'Bearer 123456'
    },
    proxy='proxy'
)


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
    sample_id = '240321-t3mwmagds3'
    mocker.patch.object(demisto, 'args', return_value={'sample_id': sample_id})
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    mock_response = util_load_json('test_data/sample_summary.json')
    requests_mock.get(f'https://test.com/api/v0/samples/{sample_id}/summary', json=mock_response)

    results = HatchingTriage.get_sample_summary(client, **demisto.args())

    assert results[0].outputs.get('sample') == sample_id
    assert results[0].outputs.get('sha256') == 'c80004016d79c91b95a7e3001080e99a72ce98b24a77b76f6e4c98eaf1550620'


def test_get_sample(mocker, requests_mock):
    """
    Given:
    - SampleID from previous file or url submission.

    When:
    - Running the !triage-get-sample command

    Then:
    - Validate the returned data.
    """
    import CommonServerPython
    sample_id = '240321-1ret7sdp6d'
    mocker.patch.object(demisto, 'args', return_value={'sample_id': sample_id})
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    mock_response = util_load_json('test_data/sample.json')
    requests_mock.get(f'https://test.com/api/v0/samples/{sample_id}', json=mock_response)

    results = HatchingTriage.get_sample(client, **demisto.args())

    assert results.outputs.get('id') == sample_id
    assert results.outputs.get('sha256') == 'c80004016da9c91b95a7e3001080e99aa2ce98b24a77b76f6e4c9deaf1550660'


def test_query_sample(mocker, requests_mock):
    """
    Given:
    - Subset either owned or public.

    When:
    - Running the !triage-query-samples command

    Then:
    - Validate the returned data.
    """
    import CommonServerPython
    subset = 'owned'
    mocker.patch.object(demisto, 'args', return_value={'subset': subset})
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    mock_response = util_load_json('test_data/query_sample.json')
    requests_mock.get('https://test.com/api/v0/samples', json=mock_response)

    results = HatchingTriage.query_samples(client, **demisto.args())

    assert results.outputs[0].get('id') == '240322-swytwacaqy6'
    assert results.outputs[0].get('sha256') == '7ed6d98694d10f3fa3944a7faf7de71efdc0d7b377279b1f2ba7928bcfbf9676'


def test_get_static_report(mocker, requests_mock):
    """
    Given:
    - SampleID from previous file or url submission.

    When:
    - Running the !triage-get-static-report

    Then:
    - Validate the returned data.
    """
    import CommonServerPython
    sample_id = '240322-swytwacqy6'
    mocker.patch.object(demisto, 'args', return_value={'sample_id': sample_id})
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    mock_response = util_load_json('test_data/static_report.json')
    requests_mock.get(f'https://test.com/api/v0/samples/{sample_id}/reports/static', json=mock_response)

    results = HatchingTriage.get_static_report(client, **demisto.args())

    assert results.outputs.get('sample').get('sample') == sample_id
    assert results.outputs.get('sample').get('size') == 435894
