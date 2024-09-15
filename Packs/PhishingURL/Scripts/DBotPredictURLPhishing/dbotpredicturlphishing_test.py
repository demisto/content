from DBotPredictURLPhishing import *
import pytest
import DBotPredictURLPhishing
from pytest_mock import MockerFixture

DBotPredictURLPhishing.isCommandAvailable = lambda _: True
CORRECT_DOMAINS = ['google.com']
NEW_DOMAINS = ['psg.fr']


class PhishingURLModelMock:
    def __init__(self, top_domains=None):
        self.top_domains = top_domains


def executeCommand(command, args=None):
    from datetime import date
    if command == 'whois':
        domain = args.get('query')[0]
        if not domain:
            return []
        if domain in NEW_DOMAINS:
            today = date.today().strftime('%d-%m-%Y')
            return [{'EntryContext': {
                'Domain(val.Name && val.Name == obj.Name)': {
                    'WHOIS': {
                        'CreationDate': today}}}, "Type": "note"}]
        else:
            _date = "22-03-1989"
            return [{'EntryContext': {
                'Domain(val.Name && val.Name == obj.Name)': {
                    'WHOIS': {
                        'CreationDate': _date}}}, "Type": "note"}]

    elif command == 'rasterize':
        url = args.get('url')
        html_data = "" if url == "bad_url.com" else "html"
        return [{'Contents': {KEY_IMAGE_RASTERIZE: "iVBORwrkJggg==",
                              KEY_IMAGE_HTML: html_data},
                 'Type': 'note'}]

    elif command == 'getMLModel':
        return [{'Contents':
                {'modelData': "ModelDataML", 'model':
                    {'type': {'type': ''}, 'extra':
                        {OOB_MAJOR_VERSION_INFO_KEY: MAJOR_VERSION, OOB_MINOR_VERSION_INFO_KEY:
                            MINOR_DEFAULT_VERSION}}}, 'Type': 'note'}]

    elif command == 'createMLModel':
        return None
    elif command == 'UnEscapeURLs':
        url = args.get('input')
        return [{'Contents': url[0]}]
    return None


def test_regular_malicious_new_domain(mocker):
    model_prediction = {MODEL_KEY_URL_SCORE: 0.9,
                        MODEL_KEY_LOGO_FOUND: True,
                        MODEL_KEY_SEO: True,
                        MODEL_KEY_LOGO_IMAGE_BYTES: "",
                        MODEL_KEY_LOGIN_FORM: True}
    model_mock = PhishingURLModelMock()
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'urls': 'psg.fr', 'numberDetailedReports': '1'})
    mocker.patch('DBotPredictURLPhishing.decode_model_data', return_value=model_mock, create=True)
    mocker.patch.object(model_mock, 'top_domains', return_value=("", 0), create=True)
    mocker.patch.object(model_mock, 'major', return_value=0, create=True)
    mocker.patch.object(model_mock, 'minor', return_value=0, create=True)
    mocker.patch.object(model_mock, 'predict', return_value=model_prediction, create=True)
    mocker.patch.object(model_mock, 'logos_dict', return_value={}, create=True)
    return_results_mock = mocker.patch.object(DBotPredictURLPhishing, 'return_results', return_value=None)
    general_summary, detailed_summary, msg_list = main()
    assert general_summary[0][KEY_FINAL_VERDICT] == VERDICT_MALICIOUS_COLOR.format(MALICIOUS_VERDICT)
    assert detailed_summary[0][KEY_CONTENT_DOMAIN] == 'psg.fr'
    assert detailed_summary[0][KEY_CONTENT_URL] == 'psg.fr'
    assert detailed_summary[0][KEY_CONTENT_LOGO] == 'True'
    assert detailed_summary[0][KEY_CONTENT_LOGIN] == 'True'
    assert detailed_summary[0][KEY_CONTENT_SEO] == 'True'
    assert detailed_summary[0][KEY_CONTENT_AGE] == 'True'
    assert detailed_summary[0][KEY_CONTENT_URL_SCORE] == model_prediction[MODEL_KEY_URL_SCORE]
    assert MSG_NO_ACTION_ON_MODEL in msg_list

    # assert default reliability
    entry_context = return_results_mock.mock_calls[1].args[0]['EntryContext']
    assert entry_context[KEY_CONTENT_DBOT_SCORE]['Reliability'] == "A+ - 3rd party enrichment"


@pytest.mark.parametrize('provided_reliability', ['A+ - 3rd party enrichment', 'A - Completely reliable',
                                                  'B - Usually reliable', 'D - Not usually reliable'])
def test_regular_malicious_reliability_change(mocker, provided_reliability):
    """
    Given:
        - url
        - provided source reliability
    When:
        - running DBotPredictUrlPhishing on a non-benign verdict.
    Then:
        - Assert the outcome reliability is the provided one.
    """
    model_prediction = {MODEL_KEY_URL_SCORE: 0.9,
                        MODEL_KEY_LOGO_FOUND: True,
                        MODEL_KEY_SEO: True,
                        MODEL_KEY_LOGO_IMAGE_BYTES: "",
                        MODEL_KEY_LOGIN_FORM: True}
    model_mock = PhishingURLModelMock()
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'urls': 'psg.fr', 'numberDetailedReports': '1',
                                                       'reliability': provided_reliability})
    mocker.patch('DBotPredictURLPhishing.decode_model_data', return_value=model_mock, create=True)
    mocker.patch.object(model_mock, 'top_domains', return_value=("", 0), create=True)
    mocker.patch.object(model_mock, 'major', return_value=0, create=True)
    mocker.patch.object(model_mock, 'minor', return_value=0, create=True)
    mocker.patch.object(model_mock, 'predict', return_value=model_prediction, create=True)
    mocker.patch.object(model_mock, 'logos_dict', return_value={}, create=True)
    return_results_mock = mocker.patch.object(DBotPredictURLPhishing, 'return_results', return_value=None)
    main()
    entry_context = return_results_mock.mock_calls[1].args[0]['EntryContext']
    assert entry_context[KEY_CONTENT_DBOT_SCORE]['Reliability'] == provided_reliability


def test_regular_malicious_reliability_invalid(mocker):
    """
    Given:
        - url
        - invalid source reliability
    When:
        - running DBotPredictUrlPhishing.
    Then:
        - Assert Fails and valid reliability is requested.
    """
    model_mock = PhishingURLModelMock()
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'urls': 'psg.fr', 'numberDetailedReports': '1',
                                                       'reliability': 'some_invalid_reliability'})
    mocker.patch('DBotPredictURLPhishing.decode_model_data', return_value=model_mock, create=True)
    return_error_mock = mocker.patch.object(DBotPredictURLPhishing, 'return_error', return_value=None)
    mocker.patch.object(demisto, 'error', return_value=None)

    main()
    assert "Please use supported reliability only." in return_error_mock.mock_calls[0].args[0]


def test_regular_benign(mocker):
    url = 'google.com'
    model_prediction = {MODEL_KEY_URL_SCORE: 0.01,
                        MODEL_KEY_LOGO_FOUND: False,
                        MODEL_KEY_SEO: False,
                        MODEL_KEY_LOGO_IMAGE_BYTES: "",
                        MODEL_KEY_LOGIN_FORM: True
                        }
    model_mock = PhishingURLModelMock()
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'urls': url, 'numberDetailedReports': '1'})
    mocker.patch('DBotPredictURLPhishing.decode_model_data', return_value=model_mock, create=True)
    mocker.patch.object(model_mock, 'top_domains', return_value=("", 0), create=True)
    mocker.patch.object(model_mock, 'major', return_value=0, create=True)
    mocker.patch.object(model_mock, 'minor', return_value=0, create=True)
    mocker.patch.object(model_mock, 'predict', return_value=model_prediction, create=True)
    mocker.patch.object(model_mock, 'logos_dict', return_value={}, create=True)
    general_summary, detailed_summary, msg_list = main()
    assert general_summary[0][KEY_FINAL_VERDICT] == VERDICT_BENIGN_COLOR.format(BENIGN_VERDICT)
    assert detailed_summary[0][KEY_CONTENT_DOMAIN] == 'google.com'
    assert detailed_summary[0][KEY_CONTENT_URL] == 'google.com'
    assert detailed_summary[0][KEY_CONTENT_LOGO] == 'False'
    assert detailed_summary[0][KEY_CONTENT_LOGIN] == 'True'
    assert detailed_summary[0][KEY_CONTENT_SEO] == 'False'
    assert detailed_summary[0][KEY_CONTENT_AGE] == 'False'
    assert detailed_summary[0][KEY_CONTENT_URL_SCORE] == model_prediction[MODEL_KEY_URL_SCORE]
    assert MSG_NO_ACTION_ON_MODEL in msg_list


def test_missing_url(mocker):
    url = 'missing_url.com'
    model_prediction = {MODEL_KEY_URL_SCORE: 0.01,
                        MODEL_KEY_LOGO_FOUND: False,
                        MODEL_KEY_SEO: False,
                        MODEL_KEY_LOGO_IMAGE_BYTES: "",
                        MODEL_KEY_LOGIN_FORM: True
                        }
    model_mock = PhishingURLModelMock()
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'urls': url, 'numberDetailedReports': '1'})
    mocker.patch('DBotPredictURLPhishing.decode_model_data', return_value=model_mock, create=True)
    mocker.patch.object(model_mock, 'top_domains', return_value=("", 0), create=True)
    mocker.patch.object(model_mock, 'major', return_value=0, create=True)
    mocker.patch.object(model_mock, 'minor', return_value=0, create=True)
    mocker.patch.object(model_mock, 'predict', return_value=model_prediction, create=True)
    mocker.patch.object(model_mock, 'logos_dict', return_value={}, create=True)
    general_summary, detailed_summary, msg_list = main()
    assert MSG_NO_ACTION_ON_MODEL in msg_list


def test_white_list_not_force(mocker):
    url = 'google.com'
    model_prediction = {MODEL_KEY_URL_SCORE: 0.01,
                        MODEL_KEY_LOGO_FOUND: False,
                        MODEL_KEY_SEO: False,
                        MODEL_KEY_LOGO_IMAGE_BYTES: "",
                        MODEL_KEY_LOGIN_FORM: True
                        }
    model_mock = PhishingURLModelMock(top_domains={url: 0})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'urls': url, 'numberDetailedReports': '1'})
    mocker.patch('DBotPredictURLPhishing.decode_model_data', return_value=model_mock, create=True)
    # mocker.patch.object(model_mock, 'top_domains', return_value={'google.com':0}, create=True)
    mocker.patch.object(model_mock, 'major', return_value=0, create=True)
    mocker.patch.object(model_mock, 'minor', return_value=0, create=True)
    mocker.patch.object(model_mock, 'predict', return_value=model_prediction, create=True)
    mocker.patch.object(model_mock, 'logos_dict', return_value={}, create=True)
    general_summary, detailed_summary, msg_list = main()
    assert general_summary[0][KEY_FINAL_VERDICT] == VERDICT_BENIGN_COLOR.format(BENIGN_VERDICT_WHITELIST)
    assert MSG_NO_ACTION_ON_MODEL in msg_list


def test_white_list_force(mocker):
    url = 'google.com'
    model_prediction = {MODEL_KEY_URL_SCORE: 0.01,
                        MODEL_KEY_LOGO_FOUND: False,
                        MODEL_KEY_SEO: False,
                        MODEL_KEY_LOGO_IMAGE_BYTES: "",
                        MODEL_KEY_LOGIN_FORM: True
                        }
    model_mock = PhishingURLModelMock(top_domains={url: 0})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'urls': url, 'numberDetailedReports': '1', 'forceModel': 'True'})
    mocker.patch('DBotPredictURLPhishing.decode_model_data', return_value=model_mock, create=True)
    mocker.patch.object(model_mock, 'major', return_value=0, create=True)
    mocker.patch.object(model_mock, 'minor', return_value=0, create=True)
    mocker.patch.object(model_mock, 'predict', return_value=model_prediction, create=True)
    mocker.patch.object(model_mock, 'logos_dict', return_value={}, create=True)
    general_summary, detailed_summary, msg_list = main()

    assert general_summary[0][KEY_FINAL_VERDICT] == VERDICT_BENIGN_COLOR.format(BENIGN_VERDICT)
    assert not detailed_summary
    assert MSG_NO_ACTION_ON_MODEL in msg_list


def test_new_major_version(mocker):
    url = 'google.com'
    model_prediction = {MODEL_KEY_URL_SCORE: 0.01,
                        MODEL_KEY_LOGO_FOUND: False,
                        MODEL_KEY_SEO: False,
                        MODEL_KEY_LOGO_IMAGE_BYTES: "",
                        MODEL_KEY_LOGIN_FORM: True
                        }
    model_mock = PhishingURLModelMock(top_domains={url: 0})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'urls': url, 'numberDetailedReports': '1', 'forceModel': 'True'})
    mocker.patch('DBotPredictURLPhishing.decode_model_data', return_value=model_mock, create=True)
    mocker.patch('DBotPredictURLPhishing.oob_model_exists_and_updated', return_value=(True, 0, 0, 'ModelData'),
                 create=True)
    mocker.patch('DBotPredictURLPhishing.load_oob', return_value=b'test', create=True)
    mocker.patch.object(model_mock, 'major', return_value=0, create=True)
    mocker.patch.object(model_mock, 'minor', return_value=0, create=True)
    mocker.patch.object(model_mock, 'predict', return_value=model_prediction, create=True)
    mocker.patch.object(model_mock, 'logos_dict', return_value={}, create=True)
    mocker.patch('DBotPredictURLPhishing.MAJOR_VERSION', 1)
    _, _, msg_list = main()
    assert MSG_UPDATE_MODEL.format(1, 0) in msg_list


def test_get_colored_pred_json():
    pred_json_1 = {
        MODEL_KEY_SEO: True,
        MODEL_KEY_LOGO_FOUND: True,
        MODEL_KEY_LOGIN_FORM: True,
        DOMAIN_AGE_KEY: True
    }
    pred_json_2 = {
        MODEL_KEY_SEO: False,
        MODEL_KEY_LOGO_FOUND: False,
        MODEL_KEY_LOGIN_FORM: False,
        DOMAIN_AGE_KEY: False
    }

    res_1 = get_colored_pred_json(pred_json_1)
    res_2 = get_colored_pred_json(pred_json_2)

    assert res_1[MODEL_KEY_SEO] == RED_COLOR.format('Bad')
    assert res_1[MODEL_KEY_LOGO_FOUND] == RED_COLOR.format('Suspicious')
    assert res_1[MODEL_KEY_LOGIN_FORM] == RED_COLOR.format('Yes')
    assert res_1[DOMAIN_AGE_KEY] == RED_COLOR.format('Less than 6 months ago')

    assert res_2[MODEL_KEY_SEO] == GREEN_COLOR.format('Good')
    assert res_2[MODEL_KEY_LOGO_FOUND] == GREEN_COLOR.format('Not Suspicious')
    assert res_2[MODEL_KEY_LOGIN_FORM] == GREEN_COLOR.format('No')
    assert res_2[DOMAIN_AGE_KEY] == GREEN_COLOR.format('More than 6 months ago')


def test_get_score():
    pred_json_1 = {
        MODEL_KEY_SEO: True,
        MODEL_KEY_LOGO_FOUND: True,
        MODEL_KEY_LOGIN_FORM: False,
        DOMAIN_AGE_KEY: True,
        MODEL_KEY_URL_SCORE: 0.4
    }
    assert round(get_score(pred_json_1), 2) == 0.72
    pred_json_2 = {
        MODEL_KEY_SEO: True,
        MODEL_KEY_LOGO_FOUND: False,
        MODEL_KEY_LOGIN_FORM: False,
        DOMAIN_AGE_KEY: False,
        MODEL_KEY_URL_SCORE: 0.6
    }
    assert round(get_score(pred_json_2), 2) == 0.55


def test_extract_created_date_with_empty_entry():
    """
    Given: entry that does not contain anything
    When: running extract_created_date function
    Then: Make sure None is returned
    """
    from DBotPredictURLPhishing import extract_created_date
    assert not extract_created_date({"EntryContext": None, "Type": 1})


def test_weed_rasterize_errors(mocker: MockerFixture):
    """
    Given: the results from calling rasterize include errors.
    When: looking for rasterize error responses in the weed_rasterize_errors function.
    Then: Make sure the correct errors are weeded out and returned to the user and the rest are used.
    """
    return_results_mock = mocker.patch('DBotPredictURLPhishing.return_results')
    urls = ['1', '2', '3']
    res_rasterize = ['error 1', {'success': True}, 'error 3']

    weed_rasterize_errors(urls, res_rasterize)

    assert urls == ['2']
    assert res_rasterize == [{'success': True}]
    assert 'error 1' in return_results_mock.call_args_list[0].args[0].readable_output
    assert 'error 3' in return_results_mock.call_args_list[0].args[0].readable_output


def test_return_entry_summary(mocker: MockerFixture):

    mock_return_results = mocker.patch('DBotPredictURLPhishing.return_results')
    pred_json = {
        'seo': True, 'login_form': False, 'debug_top_words': "['access']",
        'debug_found_domains_list': "['example.com']",
        'logo_name': float('nan'), 'logo_found': True, 'image_bytes': '',
        'debug_image': '{"example.png": "Less than MIN_MATCH_COUNT: 2"}',
        'url_score': 0.55, 'New domain (less than 6 months)': True
    }
    res = return_entry_summary(
        pred_json=pred_json,
        url='https://example.com', is_white_listed=False, output_rasterize={'image_b64': '1234'},
        verdict='Benign - Top domains from Majestic', reliability=DBotScoreReliability.A_PLUS
    )

    assert res == {
        'BadSEOQuality': 'True', 'Domain': 'example.com', 'FinalVerdict': 'Benign', 'HasLoginForm': 'False', 'NewDomain': 'True',
        'TopMajesticDomain': 'False', 'URL': 'https://example.com', 'URLStaticScore': 0.55, 'UseOfSuspiciousLogo': 'True'}
    assert mock_return_results.mock_calls[0].args[0]['HumanReadable'].startswith('### Phishing prediction evidence | example.com')
    assert mock_return_results.mock_calls[1].args[0]['File'] == 'Logo detection engine'
    assert mock_return_results.mock_calls[1].args[0]['Tags'] == ['DBOT_URL_PHISHING_MALICIOUS']


def test_rasterize_urls_bad_rasterize_response(mocker: MockerFixture):
    """
    Given: the results from calling rasterize are less than the amount of URLs given.
    When: looking for rasterize error responses in the weed_rasterize_errors function.
    Then: Make sure the command is called for each URL.
    """
    rasterize_command_mock = mocker.patch(
        'DBotPredictURLPhishing.rasterize_command', return_value=[{}]
    )

    res = rasterize_urls(['1', '2'], 0)

    assert res == [{}, {}]
    assert rasterize_command_mock.call_count == 3
