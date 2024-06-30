from CommonServerPython import *  # noqa: F401
import Hey as hey
import pytest


def test_try_re():
    # Too many extracted values -> None
    assert hey.try_re(hey.INT_RE, '7 days and not 8 or 6', 0) is None

    # Expected extracted values -> value
    assert hey.try_re(hey.INT_RE, '7 days exactly', 0) == '7'
    assert hey.try_re(hey.INT_RE, '7 days and not 8', 1) == '8'
    assert hey.try_re(hey.FLOAT_RE, 'give 100.1% and not any less', 0) == '100.1'
    assert hey.try_re(hey.BYTES_RE, 'disk size is 1337 bytes', 0) == '1337 bytes'

    # No value found -> None
    assert hey.try_re(hey.BYTES_RE, 'disk size is 1337 byte', 0) is None


def test_try_name_value_arg_to_dict():
    test_str = 'a=1'
    assert hey.name_value_arg_to_dict(test_str) == {'a': '1'}

    test_str = 'a==1'
    assert hey.name_value_arg_to_dict(test_str) == {'a': '=1'}

    test_str = 'a_invalid,b=1'
    with pytest.raises(DemistoException):
        hey.name_value_arg_to_dict(test_str)

    test_str = 'nothing to extract'
    with pytest.raises(DemistoException):
        hey.name_value_arg_to_dict(test_str)


def test_construct_hey_query():
    url = "http://mock.com"
    res = hey.construct_hey_query(url)
    assert res[0] == {}
    assert res[1] == ["hey", url]

    requests_number = "2"
    res = hey.construct_hey_query(url, requests_number=requests_number)
    assert res[0] == {"n": "2"}
    assert res[1] == ["hey", "-n", "2", url]

    timeout = "2"
    res = hey.construct_hey_query(url, timeout=timeout)
    assert res[0] == {"t": "2"}
    assert res[1] == ["hey", "-t", "2", url]

    concurrency = "2"
    res = hey.construct_hey_query(url, concurrency=concurrency)
    assert res[0] == {"c": "2"}
    assert res[1] == ["hey", "-c", "2", url]

    duration = "2"
    res = hey.construct_hey_query(url, duration=duration)
    assert res[0] == {"z": "2s"}
    assert res[1] == ["hey", "-z", "2s", url]

    method = "POST"
    res = hey.construct_hey_query(url, method=method)
    assert res[0] == {"m": method}
    assert res[1] == ["hey", "-m", method, url]

    disable_compression = "false"
    res = hey.construct_hey_query(url, disable_compression=disable_compression)
    assert res[0] == {}
    assert res[1] == ["hey", url]

    disable_compression = "true"
    res = hey.construct_hey_query(url, disable_compression=disable_compression)
    assert res[0] == {}
    assert res[1] == ["hey", "--disable-compression", url]
    headers = "a=1,b=2,c=3 4"
    res = hey.construct_hey_query(url, headers=headers)
    assert res[0] == {}
    assert res[1] == ["hey", "-H", "a:1", "-H", "b:2", "-H", "c:3 4", url]

    body = "{}"
    res = hey.construct_hey_query(url, body=body)
    assert res[0] == {"d": body}
    assert res[1] == ["hey", "-d", body, url]

    proxy = "a:1"
    res = hey.construct_hey_query(url, proxy=proxy)
    assert res[0] == {"x": proxy}
    assert res[1] == ["hey", "-x", proxy, url]

    enable_http2 = "true"
    res = hey.construct_hey_query(url, enable_http2=enable_http2)
    assert res[0] == {}
    assert res[1] == ["hey", "-h2", url]

    disable_redirects = "true"
    res = hey.construct_hey_query(url, disable_redirects=disable_redirects)
    assert res[0] == {}
    assert res[1] == ["hey", "-disable-redirects", url]

    res = hey.construct_hey_query(
        url=url,
        requests_number=requests_number,
        timeout=timeout,
        concurrency=concurrency,
        duration=duration,
        method=method,
        disable_compression=disable_compression,
        headers=headers,
        body=body,
        proxy=proxy,
        enable_http2=enable_http2,
        disable_redirects=disable_redirects,
    )
    assert res[0] == {
        "t": timeout,
        "n": requests_number,
        "c": concurrency,
        "m": method,
        "z": duration + "s",
        "d": body,
        "x": proxy,
    }
    assert res[1] == [
        "hey",
        "--disable-compression",
        "-h2",
        "-disable-redirects",
        "-H",
        "a:1",
        "-H",
        "b:2",
        "-H",
        "c:3 4",
        "-t",
        "2",
        "-n",
        "2",
        "-c",
        "2",
        "-m",
        "POST",
        "-z",
        "2s",
        "-d",
        "{}",
        "-x",
        "a:1",
        "http://mock.com",
    ]


def test_run_hey_test(mocker):
    """
    Given:
        mocker
    When:
        Running the run_hey_test function.
    Then:
        Assert the message returned is as expected.
    """
    import subprocess
    url = 'http://mock.com'
    ret_value = f'hey {url}'
    expected_raw = {'SuccessfulResponses': 0, 'TimeoutPerRequest': 20, 'Concurrency': 50, 'Requests': 200}
    mocker.patch.object(subprocess, 'check_output', return_value=ret_value)
    results = hey.run_hey_test(url)
    assert results.readable_output == ret_value
    assert results.raw_response == expected_raw
