import socket
import pytest
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from URLNumberOfAds import ads, is_ip_internal_or_restricted, validate_url_safe, safe_get, main, MAX_REDIRECTS

HTML_TEXT = """<!doctype html>
<html lang="en">
<head>
<script src="https://ad_url" async></script>
</html>"""

PUBLIC_ADDR_INFO = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]


class RedirectResponse:
    def __init__(self, location):
        self.headers = {"Location": location}
        self.is_redirect = True
        self.text = ""


def test_ads():
    term_list = "  \n||ad_url\n##another_url\n"
    res = ads(HTML_TEXT, term_list)
    assert res == {"ad_ur": 1}


@pytest.mark.parametrize(
    "ip_str, expected",
    [
        ("127.0.0.1", True),
        ("10.0.0.1", True),
        ("172.16.0.1", True),
        ("172.17.0.1", True),
        ("172.31.255.255", True),
        ("192.168.1.1", True),
        ("169.254.169.254", True),
        ("0.0.0.0", True),
        ("::1", True),
        ("::ffff:127.0.0.1", True),
        ("::ffff:169.254.169.254", True),
        ("::ffff:8.8.8.8", False),
        ("fe80::1", True),
        ("fc00::1", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("not-an-ip", False),
    ],
)
def test_is_ip_internal_or_restricted(ip_str, expected):
    assert is_ip_internal_or_restricted(ip_str) == expected


@pytest.mark.parametrize(
    "invalid_url, err_substr",
    [
        ("", "Invalid URL provided"),
        ("ftp://example.com/file", "Only HTTP and HTTPS"),
        ("file:///etc/passwd", "Only HTTP and HTTPS"),
        ("gopher://127.0.0.1:80", "Only HTTP and HTTPS"),
        ("http://", "Could not extract hostname"),
        ("http://127.0.0.1:8080/test", "internal or restricted IP address"),
        ("http://172.17.0.1:8888/una-url", "internal or restricted IP address"),
        ("http://10.1.2.3/path", "internal or restricted IP address"),
        ("http://192.168.1.100/resource", "internal or restricted IP address"),
        ("http://169.254.169.254/latest/meta-data/", "internal or restricted IP address"),
        ("http://[::1]/test", "internal or restricted IP address"),
        ("http://[::ffff:169.254.169.254]/latest/meta-data/", "internal or restricted IP address"),
    ],
)
def test_validate_url_safe_blocked_urls(invalid_url, err_substr):
    with pytest.raises(ValueError, match=err_substr):
        validate_url_safe(invalid_url)


def test_validate_url_safe_resolves_to_internal_ip(mocker):
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ],
    )
    with pytest.raises(ValueError, match="resolves to an internal or restricted IP address"):
        validate_url_safe("http://internal.service.local/api")


def test_validate_url_safe_dns_failure(mocker):
    mocker.patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known"))
    with pytest.raises(ValueError, match="Unable to resolve hostname"):
        validate_url_safe("http://nonexistent.domain.xyz/ads")


def test_validate_url_safe_public_url(mocker):
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ],
    )
    url = "https://www.example.com/page"
    assert validate_url_safe(url) == url


def test_main_success(mocker):
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ],
    )

    class MockResponse:
        def __init__(self, text):
            self.text = text
            self.headers: dict = {}
            self.is_redirect = False

    def mock_requests_get(url, **kwargs):
        if "easylist" in url:
            return MockResponse("||ad_url^\n")
        return MockResponse(HTML_TEXT)

    mocker.patch("requests.get", side_effect=mock_requests_get)
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "url": "https://example.com/test",
            "easylist": "https://easylist.github.io/easylist/easylist.txt",
        },
    )
    results_mock = mocker.patch.object(demisto, "results")

    main()

    results_mock.assert_called_once()
    result_data = results_mock.call_args[0][0]
    assert result_data["EntryContext"]["URL(val.Data == obj.Data)"]["Data"] == "https://example.com/test"
    assert result_data["EntryContext"]["URL(val.Data == obj.Data)"]["AdsCount"] == 1


def test_main_ssrf_blocked_url(mocker):
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "url": "http://172.17.0.1:8888/una-url",
            "easylist": "https://easylist.github.io/easylist/easylist.txt",
        },
    )
    return_error_mock = mocker.patch("URLNumberOfAds.return_error")

    main()

    return_error_mock.assert_called_once()
    assert "internal or restricted IP address" in return_error_mock.call_args[0][0]


def test_main_ssrf_blocked_easylist(mocker):
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ],
    )
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "url": "https://example.com/test",
            "easylist": "http://169.254.169.254/latest/meta-data/",
        },
    )
    return_error_mock = mocker.patch("URLNumberOfAds.return_error")

    main()

    return_error_mock.assert_called_once()
    assert "internal or restricted IP address" in return_error_mock.call_args[0][0]


def test_safe_get_uses_timeout_and_disables_auto_redirects(mocker):
    mocker.patch("socket.getaddrinfo", return_value=PUBLIC_ADDR_INFO)
    get_mock = mocker.patch("requests.get", return_value=RedirectResponse(""))
    get_mock.return_value.is_redirect = False
    safe_get("https://example.com/test")
    assert get_mock.call_args.kwargs["timeout"] == 30
    assert get_mock.call_args.kwargs["allow_redirects"] is False


def test_safe_get_follows_safe_redirect(mocker):
    mocker.patch("socket.getaddrinfo", return_value=PUBLIC_ADDR_INFO)
    final = RedirectResponse("")
    final.is_redirect = False
    get_mock = mocker.patch("requests.get", side_effect=[RedirectResponse("/next"), final])
    assert safe_get("https://example.com/test") is final
    assert get_mock.call_args_list[1].args[0] == "https://example.com/next"


def test_safe_get_blocks_redirect_to_internal_ip(mocker):
    mocker.patch("socket.getaddrinfo", return_value=PUBLIC_ADDR_INFO)
    get_mock = mocker.patch("requests.get", return_value=RedirectResponse("http://169.254.169.254/latest/meta-data/"))
    with pytest.raises(ValueError, match="internal or restricted IP address"):
        safe_get("https://example.com/test")
    assert get_mock.call_count == 1


def test_safe_get_too_many_redirects(mocker):
    mocker.patch("socket.getaddrinfo", return_value=PUBLIC_ADDR_INFO)
    get_mock = mocker.patch("requests.get", return_value=RedirectResponse("https://example.com/loop"))
    with pytest.raises(ValueError, match="Too many redirects"):
        safe_get("https://example.com/test")
    assert get_mock.call_count == MAX_REDIRECTS + 1


def test_main_error_passes_exception_object(mocker):
    mocker.patch.object(demisto, "args", return_value={"url": "ftp://example.com"})
    return_error_mock = mocker.patch("URLNumberOfAds.return_error")
    main()
    assert isinstance(return_error_mock.call_args.kwargs["error"], ValueError)
