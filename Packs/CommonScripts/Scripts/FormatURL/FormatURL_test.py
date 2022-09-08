import pytest
from FormatURL import *

TEST_URL_HTTP = 'http://www.test.com'
TEST_URL_HTTPS = 'https://www.test.com'

NOT_FORMAT_TO_FORMAT = [  # Start of http:/ replacements.
    ('http:/www.test.com', TEST_URL_HTTP),
    ('https:/www.test.com', TEST_URL_HTTPS),
    ('http:\\\\www.test.com', TEST_URL_HTTP),
    ('https:\\\\www.test.com', TEST_URL_HTTPS),
    ('http:\\www.test.com', TEST_URL_HTTP),
    ('https:\\www.test.com', TEST_URL_HTTPS),
    ('http:www.test.com', TEST_URL_HTTP),
    ('https:www.test.com', TEST_URL_HTTPS),
    # End of http/s replacements.

    # Start of hxxp/s replacements.
    ('hxxp:/www.test.com', TEST_URL_HTTP),
    ('hxxps:/www.test.com', TEST_URL_HTTPS),
    ('hXXp:/www.test.com', TEST_URL_HTTP),
    ('hXXps:/www.test.com', TEST_URL_HTTPS),

    ('hxxp:\\www.test.com', TEST_URL_HTTP),
    ('hxxps:\\www.test.com', TEST_URL_HTTPS),
    ('hXXp:\\www.test.com', TEST_URL_HTTP),
    ('hXXps:\\www.test.com', TEST_URL_HTTPS),

    ('hxxp:\\\\www.test.com', TEST_URL_HTTP),
    ('hxxps:\\\\www.test.com', TEST_URL_HTTPS),
    ('hXXp:\\\\www.test.com', TEST_URL_HTTP),
    ('hXXps:\\\\www.test.com', TEST_URL_HTTPS),
    # End of hxxp/s replacements.

    # start of meow/s replacements.
    ('meow:/www.test.com', TEST_URL_HTTP),
    ('meows:/www.test.com', TEST_URL_HTTPS),
    ('meow:\\\\www.test.com', TEST_URL_HTTP),
    ('meows:\\\\www.test.com', TEST_URL_HTTPS),
    ('meow:\\www.test.com', TEST_URL_HTTP),
    ('meows:\\www.test.com', TEST_URL_HTTPS),
    # end of meow/s replacements.

    # Start of Sanity test, no replacement should be done.
    (TEST_URL_HTTP, TEST_URL_HTTP),
    (TEST_URL_HTTPS, TEST_URL_HTTPS),
    # End of Sanity test, no replacement should be done.
]

BRACKETS_URL_TO_FORMAT = [
    ('https://test1.test-api.com/test1/test2/s.testing]', 'https://test1.test-api.com/test1/test2/s.testing'),
    ('https://test1.test-api.com/test1/test2/s]testing]', 'https://test1.test-api.com/test1/test2/s]testing'),
    ('https://test1.test-api.com/test1/test2/s]testing', 'https://test1.test-api.com/test1/test2/s]testing'),
    ('https://test1.test-api.com]', 'https://test1.test-api.com'),
    ('https://test1.test-api.com[', 'https://test1.test-api.com'),
    ('https://test1.test-api.com', 'https://test1.test-api.com'),
]

ATP_REDIRECTS = [
    ('https://na01.safelinks.protection.outlook.com/?url=https%3A%2F%2Foffice.memoriesflower.com'
     '%2FPermission%2Foffice.php&data=01%7C01%7Cdavid.levin%40mheducation.com'
     '%7C0ac9a3770fe64fbb21fb08d50764c401%7Cf919b1efc0c347358fca0928ec39d8d5%7C0&sdata=PEoDOerQnha'
     '%2FACafNx8JAep8O9MdllcKCsHET2Ye%2B4%3D&reserved=0',
     'https://office.memoriesflower.com/Permission/office.php'),
    ('https://na01.safelinks.protection.outlook.com/?url=https%3A//urldefense.com/v3/__'
     'https%3A//google.com%3A443/search%3Fq%3Da%2Atest%26gs%3Dps__%3BKw%21-612Flbf0JvQ3kNJkRi5Jg&',
     'https://google.com:443/search?q=a*test&gs=ps'),
]

PROOF_POINT_REDIRECTS = [
    ('https://urldefense.proofpoint.com/v2/url?u=https-3A__example.com_something.html',
     'https://example.com/something.html'),
    ('https://urldefense.proofpoint.com/v2/url?u=http-3A__links.mkt3337.com_ctt-3Fkn-3D3-26ms-3DMzQ3OTg3MDQS1-26r'
     '-3DMzkxNzk3NDkwMDA0S0-26b-3D0-26j-3DMTMwMjA1ODYzNQS2-26mt-3D1-26rt-3D0&d=DwMFaQ&c'
     '=Vxt5e0Osvvt2gflwSlsJ5DmPGcPvTRKLJyp031rXjhg&r=MujLDFBJstxoxZI_GKbsW7wxGM7nnIK__qZvVy6j9Wc&m'
     '=QJGhloAyfD0UZ6n8r6y9dF-khNKqvRAIWDRU_K65xPI&s=ew-rOtBFjiX1Hgv71XQJ5BEgl9TPaoWRm_Xp9Nuo8bk&e=',
     'http://links.mkt3337.com/ctt?kn=3&ms=MzQ3OTg3MDQS1&r=MzkxNzk3NDkwMDA0S0&b=0&j=MTMwMjA1ODYzNQS2&mt=1&rt=0'),
    ('https://urldefense.proofpoint.com/v1/url?u=http://www.bouncycastle.org/&amp;k=oIvRg1%2BdGAgOoM1BIlLLqw%3D%3D%0A'
     '&amp;r=IKM5u8%2B%2F%2Fi8EBhWOS%2BqGbTqCC%2BrMqWI%2FVfEAEsQO%2F0Y%3D%0A&amp;m'
     '=Ww6iaHO73mDQpPQwOwfLfN8WMapqHyvtu8jM8SjqmVQ%3D%0A&amp;s'
     '=d3583cfa53dade97025bc6274c6c8951dc29fe0f38830cf8e5a447723b9f1c9a',
     'http://www.bouncycastle.org/'),
    ('https://urldefense.com/v3/__https://google.com:443/search?q=a*test&gs=ps__;Kw!-612Flbf0JvQ3kNJkRi5Jg'
     '!Ue6tQudNKaShHg93trcdjqDP8se2ySE65jyCIe2K1D_uNjZ1Lnf6YLQERujngZv9UWf66ujQIQ$',
     'https://google.com:443/search?q=a*test&gs=ps'),
    ('https://urldefense.us/v3/__https://google.com:443/search?q=a*test&gs=ps__;Kw!-612Flbf0JvQ3kNJkRi5Jg'
     '!Ue6tQudNKaShHg93trcdjqDP8se2ySE65jyCIe2K1D_uNjZ1Lnf6YLQERujngZv9UWf66ujQIQ$',
     'https://google.com:443/search?q=a*test&gs=ps')
]

FORMAT_URL_ADDITIONAL_TEST_CASES = [
    ('https://test.co.uk/test.html', 'https://test.co.uk/test.html'),
    ('www.test.test.com/test.html?paramaters=testagain', 'www.test.test.com/test.html?paramaters=testagain'),
    ('http://ötest.com/', 'http://ötest.com/'),
    ('https://testö.com/test.html', 'https://testö.com/test.html'),
    ('www.testö.com/test.aspx', 'www.testö.com/test.aspx'),
    ('https://www.teöst.com/', 'https://www.teöst.com/'),
    ('www.test.com/check', 'www.test.com/check'),
    ('http://xn--t1e2s3t4.com/testagain.aspx', 'http://xn--t1e2s3t4.com/testagain.aspx'),
    ('https://www.xn--t1e2s3t4.com', 'https://www.xn--t1e2s3t4.com'),
    ('www.test.com:443/path/to/file.html', 'www.test.com:443/path/to/file.html'),
    ('https://1.2.3.4/path/to/file.html', 'https://1.2.3.4/path/to/file.html'),
    ('1.2.3.4/path', '1.2.3.4/path'),
    ('1.2.3.4/path/to/file.html', '1.2.3.4/path/to/file.html'),
    ('http://142.42.1.1:8080/', 'http://142.42.1.1:8080/'),
    ('http://142.42.1.1:8080', 'http://142.42.1.1:8080'),
    ('http://☺.damowmow.com/', 'http://☺.damowmow.com/'),
    ('http://223.255.255.254', 'http://223.255.255.254'),
    ('ftp://foo.bar/baz', 'ftp://foo.bar/baz'),
    ('ftps://foo.bar/baz', 'ftps://foo.bar/baz'),
    ('hxxps://www[.]cortex-xsoar[.]com', 'https://www.cortex-xsoar.com'),
    ('ftps://foo.bar/baz%20%21%22%23%24%25%26', 'ftps://foo.bar/baz !"#$%&'),
    ('ftps://foo.bar/baz%27%28%29%2A%2B,', "ftps://foo.bar/baz'()*+"),  # comma is removed
    ('https://test.com#fragment3', 'https://test.com#fragment3'),
    ('http://_23_11.redacted.com./#redactedredactedredacted', 'http://_23_11.redacted.com./#redactedredactedredacted'),
    ('[http://[2001:db8:3333:4444:5555:6666:7777:8888]]',  # disable-secrets-detection
     'http://[2001:db8:3333:4444:5555:6666:7777:8888]'),  # disable-secrets-detection
    ('[2001:db8:3333:4444:5555:6666:7777:8888]',  # disable-secrets-detection
     '[2001:db8:3333:4444:5555:6666:7777:8888]'),  # disable-secrets-detection
    ('2001:db8:3333:4444:5555:6666:7777:8888',  # disable-secrets-detection
     '[2001:db8:3333:4444:5555:6666:7777:8888]'),  # disable-secrets-detection
]

FAILS = [
    ('[http://2001:db8:3333:4444:5555:6666:7777:8888]',
     pytest.raises(URLError)),  # disable-secrets-detection IPv6 must have square brackets
    ('http://142.42.1.1:aaa8080', pytest.raises(URLError)),  # invalid port
    ('http://142.42.1.1:aaa', pytest.raises(URLError)),  # invalid port  # disable-secrets-detection
    ('https://test.com#fragment3#fragment3', pytest.raises(URLError)),  # Only one fragment allowed
]

REDIRECT_TEST_DATA = ATP_REDIRECTS + PROOF_POINT_REDIRECTS

FORMAT_URL_TEST_DATA = NOT_FORMAT_TO_FORMAT + FORMAT_URL_ADDITIONAL_TEST_CASES


class TestFormatURL:
    @pytest.mark.parametrize('non_formatted_url, expected', NOT_FORMAT_TO_FORMAT)
    def test_replace_protocol(self, non_formatted_url: str, expected: str):
        """
        Given:
        - non_formatted_url: A URL.

        When:
        - Replacing protocol to http:// or https://.

        Then:
        - Ensure for every expected protocol given, it is replaced with the expected value.
        """
        url = URLFormatter('https://www.test.com/')
        assert url.correct_and_refang_url(non_formatted_url) == expected.lower()

    @pytest.mark.parametrize('url_, expected', FORMAT_URL_TEST_DATA)
    def test_format_url(self, url_: str, expected: str):
        """
        Given:
        - URL.

        When:
        - Given URL needs to be formatted.

        Then:
        - Ensure URL is formatted as expected
        """

        assert URLFormatter(url_).__str__() == expected.lower()

    @pytest.mark.parametrize('url_, expected', FAILS)
    def test_exceptions(self, url_: str, expected):
        """
        Checks the formatter raises the correct exception.
        """

        with expected:
            assert URLFormatter(url_) is not None

    @pytest.mark.parametrize('url_, expected', REDIRECT_TEST_DATA)
    def test_wrappers(self, url_: str, expected: str):
        """
        Given:
        - URL with redirect URL Proof Point v2.

        When:
        - Given URL with redirect URL is valid.

        Then:
        - Ensure redirected URL is returned.
        """

        assert URLFormatter(url_).__str__() == expected.lower()

    @pytest.mark.parametrize('url_, expected', [
        ('[https://urldefense.com/v3/__https://google.com:443/search?66ujQIQ$]',
         'https://urldefense.com/v3/__https://google.com:443/search?66ujQIQ$'),
        ('(https://urldefense.us/v3/__https://google.com:443/searchERujngZv9UWf66ujQIQ$)',
         'https://urldefense.us/v3/__https://google.com:443/searchERujngZv9UWf66ujQIQ$'),
        ('[https://testURL.com)', 'https://testURL.com'),
        ('[https://testURL.com', 'https://testURL.com'),
        ('[(https://testURL.com)]', 'https://testURL.com')
    ])
    def test_remove_special_chars_from_start_and_end_of_url(self, url_, expected):
        """
        Given:
        - A URL to format.

        When:
        - executing remove_special_chars_from_start_and_end_of_url function.

        Then:
        - Ensure formatted URL is returned.
        """
        assert URLFormatter(url_).__str__() == expected.lower()

    def test_url_class(self):
        url = URLType('https://www.test.com')

        assert url.raw == 'https://www.test.com'
        assert url.__str__() == ("Scheme = \nUser_info = \nHostname = \nPort = \n"
                                 "Path = \nQuery = \nFragment = ")
