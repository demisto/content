import pytest
from CommonServerPython import DemistoException


test_data = [
    ('[{"Sha1Hash"},{"437"},{"Sha1Hash"}]', '\{".*?"(\},\{)".*?"\}', '@@@', '[{"Sha1Hash"@@@"437"},{"Sha1Hash"}]'),
    ('{"1"},{"2"},{"3"},{"4"}', '\{".*?"\}(,)\{".*?"\}', ':', '{"1"}:{"2"},{"3"}:{"4"}'),
    ('this is a test, this is another test.', '.*?(,).*?(\.)', '!', 'this is a test! this is another test!'),
    ('a, b. c,.', '.*?(,|\.)', '!', 'a! b! c!!'),
    ('.this is a test, this is another test.', '(\.).*?(,).*?(\.)', '!', '!this is a test! this is another test!'),
    ('[{"UrlValue:https://sslmanageamazones.ddns.net/info.ppl.service.access/paypal"}, '
     '{"UrlValue:https://sslmanageamazones.ddns.net/info.ppl.service.access/paypal"}, '
     '{"UrlValue:https://sslmanageamazones.ddns.net/info.ppl.service.access/paypal"}]', '.*?(:).*?:\\/\\/', '":"',
     '[{"UrlValue":"https://sslmanageamazones.ddns.net/info.ppl.service.access/paypal"}, '
     '{"UrlValue":"https://sslmanageamazones.ddns.net/info.ppl.service.access/paypal"}, '
     '{"UrlValue":"https://sslmanageamazones.ddns.net/info.ppl.service.access/paypal"}]'),
    ('string', '', 'wow', 'string'),
    ('a, b. c,.', '.*?(!|\^)', '!', 'a, b. c,.'),
]

test_exception_data = [('string', 3, 'a'), ('string', 'hel(o', 'a')]


@pytest.mark.parametrize('value, regex, replace, expected_result', test_data)
def test_main(value, regex, replace, expected_result):
    from ReplaceMatchGroup import main
    result = main({
        'value': value,
        'regex': regex,
        'replace_with': replace
    })
    assert result == expected_result


@pytest.mark.parametrize('value, regex, replace', test_exception_data)
def test_main_exception(value, regex, replace):
    from ReplaceMatchGroup import main
    with pytest.raises(DemistoException, match='Could not compile regex.'):
        main({
            'value': value,
            'regex': regex,
            'replace_with': replace
        })
