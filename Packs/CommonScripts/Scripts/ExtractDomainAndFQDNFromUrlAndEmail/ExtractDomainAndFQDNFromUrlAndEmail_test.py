import demistomock as demisto
from ExtractDomainAndFQDNFromUrlAndEmail import extract_fqdn, main
import pytest


@pytest.mark.parametrize('input,fqdn', [  # noqa: E501 disable-secrets-detection
    # no processing needed
    ('www.static.attackiqtes.com', 'www.static.attackiqtes.com'),
    ('attackiqtes.co.il', 'attackiqtes.co.il'),
    ('this.is.test.com', 'this.is.test.com'),
    ('www.bücher.de', 'www.bücher.de'),

    # no fqdn extracted
    ('www.test.fake', ''),
    ('https://emea01.safelinks.protection.outlook.com/', ''),
    ('https://urldefense.proofpoint.com/', ''),
    ('https://urldefense.com/', ''),  # noqa: E501

    # remove protocol prefixes
    ('ftp://www.test.com/test2/dev', 'www.test.com'),
    ('http://www.test.com/test2/dev', 'www.test.com'),
    ('hxxps://path.test.com/check', 'path.test.com'),
    ('hxxps://path.test.com/check', 'path.test.com'),
    ('hxxps://path.hxxp.com/check', 'path.hxxp.com'),
    ('hxXps://path.hxxp.com/check', 'path.hxxp.com'),
    ('meow://path.meow.com/check', 'path.meow.com'),
    ('meow://path.mEow.com/check', 'path.meow.com'),
    ('meOw://path.mEow.com/check', 'path.meow.com'),
    ('http-3A__go.getpostman.com_', 'go.getpostman.com'),
    ('http://survey.lavulcamktg.cl/index.php/', 'survey.lavulcamktg.cl'),

    # unquote protocol prefixes
    ('https%3A%2F%2Fdulunggakada40[.]com', 'dulunggakada40.com'),
    ('https%3A%2F%2Fpath.test.com', 'path.test.com'),
    ('https%3A%2F%2Ftwitter.com%2F', 'twitter.com'),
    ('hxxps%3A%2F%2Ftwitter.com%2F', 'twitter.com'),

    # handle special charecter
    ('www[.]demisto[.]com', 'www.demisto.com'),
    ('hxxp://www[.]demisto[.]com', 'www.demisto.com'),
    ('www[.]demisto.test[.]com', 'www.demisto.test.com'),
    ('www[.]demisto[.]test2.com', 'www.demisto.test2.com'),

    # lowercase charecter
    ('AAA23.1105test.com', 'aaa23.1105test.com'),

    # excessive charecters test
    ('test[.]com. ', 'test.com'),
    ('ftp://www.test.com/', 'www.test.com'),
    ('testing.com.com,', 'testing.com.com'),
    ('nowwwtest.com"', 'nowwwtest.com'),
    ('test.co.il ', 'test.co.il'),
    ('test.co.il)', 'test.co.il'),
    ('/evil3.com', 'evil3.com'),  # noqa: E501 disable-secrets-detection
    ('<br>kasai.qlmsourcing.com', 'kasai.qlmsourcing.com'),  # disable-secrets-detection
    ('test.com@', ''),  # disable-secrets-detection
    ('%40subdomain.domain.com', 'subdomain.domain.com'),  # disable-secrets-detection
])  # noqa: E124
def test_extract_fqdn_or_domain(input, fqdn):
    extracted_fqdn = extract_fqdn(input)
    # extracted_domain = extract_fqdn_or_domain(input, is_domain=True)

    assert extracted_fqdn == fqdn
    # assert extracted_domain == domain


def test_extract_fqdn_or_domain_empty_indicators(mocker):
    mocker.patch.object(demisto, 'args', return_value={'input': '1Ab.Vt'})
    mocker.patch.object(demisto, 'results')

    main()
    results = demisto.results.call_args[0]

    assert results[0] == [{'Contents': [], 'ContentsFormat': 'json', 'Type': 1, 'EntryContext': {'Domain': '1Ab.Vt'}}]
