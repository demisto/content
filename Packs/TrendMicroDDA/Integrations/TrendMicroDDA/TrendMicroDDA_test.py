import pytest
import demistomock as demisto


@pytest.mark.parametrize('sample_url', ["https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DgrBFMP3HDZA"])
def test_simple_upload_sample_url(mocker, requests_mock, sample_url):

    mocker.patch.object(demisto, 'params', return_value={'apiKey': 'my_apikey', 'protocol_version': 'TEST',
                                                         'server': 'https://www.example.com',
                                                         'ip_address': '1.1.1.1'})

    requests_mock.get('https://www.example.com/web_service/sample_upload/register')
    requests_mock.get('https://www.example.com/web_service/sample_upload/unregister')
    requests_mock.post('https://www.example.com/web_service/sample_upload/simple_upload_sample')
    from TrendMicroDDA import simple_upload_sample_url
    assert simple_upload_sample_url(sample_url)
