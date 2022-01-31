from typing import List, Union
from urllib.parse import urlparse

import pytest

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

ATP_REDIRECTS = [('https://na01.safelinks.protection.outlook.com/?url=https%3A%2F%2Foffice.memoriesflower.com'
                  '%2FPermission%2Foffice.php&data=01%7C01%7Cdavid.levin%40mheducation.com'
                  '%7C0ac9a3770fe64fbb21fb08d50764c401%7Cf919b1efc0c347358fca0928ec39d8d5%7C0&sdata=PEoDOerQnha'
                  '%2FACafNx8JAep8O9MdllcKCsHET2Ye%2B4%3D&reserved=0',
                  'https://office.memoriesflower.com/Permission/office.php')]

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

REDIRECT_TEST_DATA = ATP_REDIRECTS + PROOF_POINT_REDIRECTS

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
    ('http://☺.damowmow.com/', 'http://☺.damowmow.com/'),
    ('http://223.255.255.254', 'http://223.255.255.254'),
    ('ftp://foo.bar/baz', 'ftp://foo.bar/baz'),
    ('ftps://foo.bar/baz', 'ftps://foo.bar/baz'),
    ('hxxps://www[.]cortex-xsoar[.]com', 'https://www.cortex-xsoar.com'),
    ('ftps://foo.bar/baz%20%21%22%23%24%25%26', 'ftps://foo.bar/baz !"#$%&'),
    ('ftps://foo.bar/baz%27%28%29%2A%2B,', "ftps://foo.bar/baz'()*+,"),
]

REDIRECT_NON_ATP_PROOF_POINT = [('https://www.test.test.com/test.html?redirectURL=https://evil.com/mal.html',
                                 ['https://www.test.test.com/test.html?redirectURL=https://evil.com/mal.html',
                                  'https://evil.com/mal.html'])]

REDIRECT_TEST_CASES = PROOF_POINT_REDIRECTS + REDIRECT_NON_ATP_PROOF_POINT

FORMAT_URL_TEST_DATA = NOT_FORMAT_TO_FORMAT + REDIRECT_TEST_CASES + FORMAT_URL_ADDITIONAL_TEST_CASES


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
        from FormatURL import replace_protocol
        assert replace_protocol(non_formatted_url) == expected

    @pytest.mark.parametrize('url_, expected', FORMAT_URL_TEST_DATA)
    def test_format_url(self, url_: str, expected: Union[List[str], str]):
        """
        Given:
        - URL.

        When:
        - Given URL needs to be formatted.

        Then:
        - Ensure URL is formatted as expected
        """
        from FormatURL import format_urls
        if not isinstance(expected, list):
            expected = [expected]
        assert format_urls([url_])[0]['Contents'] == expected

    @pytest.mark.parametrize('url_, expected', [
        ('https://urldefense.proofpoint.com/v2/url?u=http-3A__links.mkt3337.com_ctt-3Fkn-3D3-26ms-3DMzQ3OTg3MDQS1-26r'
         '-3DMzkxNzk3NDkwMDA0S0-26b-3D0-26j-3DMTMwMjA1ODYzNQS2-26mt-3D1-26rt-3D0&d=DwMFaQ&c'
         '=Vxt5e0Osvvt2gflwSlsJ5DmPGcPvTRKLJyp031rXjhg&r=MujLDFBJstxoxZI_GKbsW7wxGM7nnIK__qZvVy6j9Wc&m'
         '=QJGhloAyfD0UZ6n8r6y9dF-khNKqvRAIWDRU_K65xPI&s=ew-rOtBFjiX1Hgv71XQJ5BEgl9TPaoWRm_Xp9Nuo8bk&e=',
         'http%3A//links.mkt3337.com/ctt%3Fkn%3D3%26ms%3DMzQ3OTg3MDQS1%26r%3DMzkxNzk3NDkwMDA0S0%26b%3D0%26j'
         '%3DMTMwMjA1ODYzNQS2%26mt%3D1%26rt%3D0')
    ])
    def test_get_redirect_url_proof_point_v2(self, url_: str, expected: str):
        """
        Given:
        - URL with redirect URL Proof Point v2.

        When:
        - Given URL with redirect URL is valid.

        Then:
        - Ensure redirected URL is returned.
        """
        from FormatURL import get_redirect_url_proof_point_v2
        assert get_redirect_url_proof_point_v2(url_, urlparse(url_)) == expected

    @pytest.mark.parametrize('url_, expected', [
        ('https://urldefense.com/v3/__https://google.com:443/search?q=a*test&gs=ps__;Kw!-612Flbf0JvQ3kNJkRi5Jg'
         '!Ue6tQudNKaShHg93trcdjqDP8se2ySE65jyCIe2K1D_uNjZ1Lnf6YLQERujngZv9UWf66ujQIQ$',
         'https://google.com:443/search?q=a*test&gs=ps'),
        ('https://urldefense.us/v3/__https://google.com:443/search?q=a*test&gs=ps__;Kw!-612Flbf0JvQ3kNJkRi5Jg'
         '!Ue6tQudNKaShHg93trcdjqDP8se2ySE65jyCIe2K1D_uNjZ1Lnf6YLQERujngZv9UWf66ujQIQ$',
         'https://google.com:443/search?q=a*test&gs=ps')
    ])
    def test_get_redirect_url_proof_point_v3(self, url_: str, expected: str):
        """
        Given:
        - URL with redirect URL Proof Point v3.

        When:
        - Given URL with redirect URL is valid.

        Then:
        - Ensure redirected URL is returned.
        """
        from FormatURL import get_redirect_url_proof_point_v3
        assert get_redirect_url_proof_point_v3(url_) == expected

    @pytest.mark.parametrize('non_formatted_url, redirect_param_name, expected', [
        ('https://urldefense.proofpoint.com/v1/url?u=http://www.bouncycastle.org/&amp;k=oIvRg1%2BdGAgOoM1BIlLLqw%3D%3D'
         '%0A&amp;r=IKM5u8%2B%2F%2Fi8EBhWOS%2BqGbTqCC%2BrMqWI%2FVfEAEsQO%2F0Y%3D%0A&amp;m'
         '=Ww6iaHO73mDQpPQwOwfLfN8WMapqHyvtu8jM8SjqmVQ%3D%0A&amp;s'
         '=d3583cfa53dade97025bc6274c6c8951dc29fe0f38830cf8e5a447723b9f1c9a', 'u',
         'http://www.bouncycastle.org/'),
        ('https://na01.safelinks.protection.outlook.com/?url=https%3A%2F%2Foffice.memoriesflower.com'
         '%2FPermission%2Foffice.php&data=01%7C01%7Cdavid.levin%40mheducation.com'
         '%7C0ac9a3770fe64fbb21fb08d50764c401%7Cf919b1efc0c347358fca0928ec39d8d5%7C0&sdata=PEoDOerQnha'
         '%2FACafNx8JAep8O9MdllcKCsHET2Ye%2B4%3D&reserved=0', 'url',
         'https://office.memoriesflower.com/Permission/office.php')
    ])
    def test_get_redirect_url_from_query(self, non_formatted_url: str, redirect_param_name: str, expected: str):
        """
        Given:
        - URL with redirect URL (Proof Point / ATP).

        When:
        - Given URL with redirect URL is valid.

        Then:
        - Ensure redirected URL is returned.
        """
        from FormatURL import get_redirect_url_from_query
        assert get_redirect_url_from_query(non_formatted_url, urlparse(non_formatted_url),
                                           redirect_param_name) == expected

    @pytest.mark.parametrize('non_formatted_url, redirect_param_name, expected', [
        ('https://protect2.fireeye.com/v1/url?k=d7c23005-88590c48-d7c31221-0cc47aa886f2-ae4b7c793165343e'
         '&amp;q=1'
         '&amp;e=c6beb47c-b5f9-4870-ab14-f6de1a85f4f2'
         '&amp;u=https%3A%2F%2Fu24529037.ct.sendgrid.net%2Fls%2Fclick', 'amp;u',
         'https://u24529037.ct.sendgrid.net/ls/click'),
        ('https://protect2.fireeye.com/v1/url?k=00bf92e9-5f24adeb-00beb0cd-0cc47aa88f82-a1f32e4f84d91cbe'
         '&q=1'
         '&e=221919da-9d68-429a-a70e-9d8d836ca107'
         '&u=https%3A%2F%2Fwww.facebook.com%2FNamshiOfficial', 'u',
         'https://www.facebook.com/NamshiOfficial')
    ])
    def test_get_redirect_url_from_query(self, non_formatted_url: str, redirect_param_name: str, expected: str):
        """
        Given:
        - URL with redirect URL (Proof Point / ATP / FireEye).

        When:
        - Given URL with redirect URL is valid.

        Then:
        - Ensure redirected URL is returned.
        """
        from FormatURL import get_redirect_url_from_query
        assert get_redirect_url_from_query(non_formatted_url, urlparse(non_formatted_url),
                                           redirect_param_name) == expected
    #  Invalid cases
    @pytest.mark.parametrize('url_', [
        'https://urldefense.com/v3/__https://google.com:443/search?66ujQIQ$',
        'https://urldefense.us/v3/__https://google.com:443/searchERujngZv9UWf66ujQIQ$'
    ])
    def test_get_redirect_url_proof_point_v3_invalid(self, mocker, url_):
        """
        Given:
        - Proof Point v3 URL.

        When:
        - Given URL is invalid and does not contain redirect URL.

        Then:
        - Ensure the full URL is returned.
        - Ensure a call to demisto.error is made.
        """
        import demistomock as demisto
        mocker.patch.object(demisto, 'error')
        from FormatURL import get_redirect_url_proof_point_v3
        assert get_redirect_url_proof_point_v3(url_) == url_
        assert demisto.error.called

    def test_get_redirect_url_from_query_no_url_query_param(self, mocker):
        """
        Given:
        - Proof Point v1 URL.

        When:
        - Given URL is invalid and does not contain redirect URL query parameter.

        Then:
        - Ensure the full URL is returned.
        - Ensure a call to demisto.error is made.
        """
        from FormatURL import get_redirect_url_from_query
        import demistomock as demisto
        url_ = 'https://urldefense.proofpoint.com/v1/url?x=bla'
        mocker.patch.object(demisto, 'error')
        assert get_redirect_url_from_query(url_, urlparse(url_), 'q') == url_
        assert demisto.error.called

    def test_get_redirect_url_from_query_duplicate_url_query_param(self, mocker):
        """
        Given:
        - Proof Point v1 URL.

        When:
        - Given URL is invalid and contains duplicate redirect URL parameters.

        Then:
        - Ensure the full URL is returned.
        - Ensure a call to demisto.debug is made.
        """
        from FormatURL import get_redirect_url_from_query
        import demistomock as demisto
        url_ = 'https://urldefense.proofpoint.com/v1/url?u=url_1&u=url_2'
        mocker.patch.object(demisto, 'debug')
        assert get_redirect_url_from_query(url_, urlparse(url_), 'u') == 'url_1'
        assert demisto.debug.called

    def test_main_flow_valid(self, mocker):
        """
        Given:
        - Cortex XSOAR arguments.

        When:
        - Formatting URLs

        Then:
        - Ensure URL are formatted as expected.
        """
        from FormatURL import main
        import demistomock as demisto
        mocker.patch.object(demisto, 'args', return_value={'input': f'{TEST_URL_HTTP}'})
        mock_results = mocker.patch.object(demisto, 'results')
        main()
        result_ = mock_results.call_args.args[0]
        assert result_['Contents'] == [TEST_URL_HTTP]
