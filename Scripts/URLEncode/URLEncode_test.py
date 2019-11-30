from URLEncode import urlencode


def test_urlencode():
    human_readable, outputs, raw_response = urlencode('http://example.com/')
    assert human_readable == 'http%3A%2F%2Fexample.com%2F' == human_readable
    assert outputs == {'EncodedURL': 'http%3A%2F%2Fexample.com%2F'}
