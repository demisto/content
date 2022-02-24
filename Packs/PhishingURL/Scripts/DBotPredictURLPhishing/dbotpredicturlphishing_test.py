from DBotPredictURLPhishing import *

CORRECT_DOMAINS = ['google.com']
NEW_DOMAINS = ['psg.fr']


class PhishingURLModelMock:
    def __init__(self, top_domains=None):
        self.top_domains = top_domains


def executeCommand(command, args=None):
    from datetime import date
    if command == 'whois':
        domain = args.get('query')
        if not domain:
            return []
        if domain in NEW_DOMAINS:
            today = date.today().strftime('%d-%m-%Y')
            return [{'EntryContext': {
                'Domain(val.Name && val.Name == obj.Name)': {
                    'WHOIS': {
                        'CreationDate': today}}}, "Type": "note"}]
        else:
            date = "22-03-1989"
            return [{'EntryContext': {
                'Domain(val.Name && val.Name == obj.Name)': {
                    'WHOIS': {
                        'CreationDate': date}}}, "Type": "note"}]

    elif command == 'rasterize':
        return [{'Contents': {'image_b64': "",
                              'html': "html", },
                 'Type': 'note'}]

    elif command == 'getMLModel':
        return [{'Contents':
                {'modelData': "ModelDataML", 'model':
                    {'type': {'type': ''}, 'extra':
                        {OOB_MAJOR_VERSION_INFO_KEY: 0, OOB_MINOR_VERSION_INFO_KEY: 0}}}, 'Type': 'note'}]

    elif command == 'createMLModel':
        return None
    elif command == 'UnEscapeURLs':
        url = args.get('input')
        return [{'Contents': url}]


def test_regular_malicious_new_domain(mocker):
    model_prediction = {MODEL_KEY_URL_SCORE: 0.9,
                        MODEL_KEY_LOGO_FOUND: True,
                        MODEL_KEY_SEO: True,
                        MODEL_KEY_LOGO_IMAGE_BYTES: "",
                        MODEL_KEY_LOGIN_FORM: True
                        }
    model_mock = PhishingURLModelMock()
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'urls': 'psg.fr', 'numberDetailedReports': '1'})
    mocker.patch('DBotPredictURLPhishing.decode_model_data', return_value=model_mock, create=True)
    mocker.patch.object(model_mock, 'top_domains', return_value=("", 0), create=True)
    mocker.patch.object(model_mock, 'major', return_value=0, create=True)
    mocker.patch.object(model_mock, 'minor', return_value=0, create=True)
    mocker.patch.object(model_mock, 'predict', return_value=model_prediction, create=True)
    mocker.patch.object(model_mock, 'logos_dict', return_value={}, create=True)
    general_summary, detailed_summary, msg_list = main()
    assert general_summary[0][KEY_FINAL_VERDICT] == VERDICT_MALICIOUS_COLOR % MALICIOUS_VERDICT
    assert detailed_summary[0][KEY_CONTENT_DOMAIN] == 'psg.fr'
    assert detailed_summary[0][KEY_CONTENT_URL] == 'psg.fr'
    assert detailed_summary[0][KEY_CONTENT_LOGO] == 'True'
    assert detailed_summary[0][KEY_CONTENT_LOGIN] == 'True'
    assert detailed_summary[0][KEY_CONTENT_SEO] == 'True'
    assert detailed_summary[0][KEY_CONTENT_AGE] == 'True'
    assert detailed_summary[0][KEY_CONTENT_URL_SCORE] == model_prediction[MODEL_KEY_URL_SCORE]
    assert MSG_NO_ACTION_ON_MODEL in msg_list


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
    assert general_summary[0][KEY_FINAL_VERDICT] == VERDICT_BENIGN_COLOR % BENIGN_VERDICT
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
    assert MSG_INVALID_URL % (MSG_IMPOSSIBLE_CONNECTION, UNKNOWN) in general_summary[0][KEY_FINAL_VERDICT]
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
    assert general_summary[0][KEY_FINAL_VERDICT] == VERDICT_BENIGN_COLOR % BENIGN_VERDICT_WHITELIST
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
    assert general_summary[0][KEY_FINAL_VERDICT] == VERDICT_BENIGN_COLOR % BENIGN_VERDICT
    assert not detailed_summary
    # assert detailed_summary[0][KEY_CONTENT_DOMAIN] == 'google.com'
    # assert detailed_summary[0][KEY_CONTENT_URL] == 'google.com'
    # assert detailed_summary[0][KEY_CONTENT_LOGO] == 'False'
    # assert detailed_summary[0][KEY_CONTENT_LOGIN] == 'True'
    # assert detailed_summary[0][KEY_CONTENT_SEO] == 'False'
    # assert detailed_summary[0][KEY_CONTENT_AGE] == 'False'
    # assert detailed_summary[0][KEY_CONTENT_URL_SCORE] == SCORE_BENIGN
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
    mocker.patch('DBotPredictURLPhishing.load_oob', return_value='test'.encode('utf-8'), create=True)
    mocker.patch.object(model_mock, 'major', return_value=0, create=True)
    mocker.patch.object(model_mock, 'minor', return_value=0, create=True)
    mocker.patch.object(model_mock, 'predict', return_value=model_prediction, create=True)
    mocker.patch.object(model_mock, 'logos_dict', return_value={}, create=True)
    mocker.patch('DBotPredictURLPhishing.MAJOR_VERSION', 1)
    general_summary, detailed_summary, msg_list = main()
    assert MSG_UPDATE_MODEL % (1, 0) in msg_list


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

    assert res_1[MODEL_KEY_SEO] == RED_COLOR % 'Bad'
    assert res_1[MODEL_KEY_LOGO_FOUND] == RED_COLOR % 'Suspicious'
    assert res_1[MODEL_KEY_LOGIN_FORM] == RED_COLOR % 'Yes'
    assert res_1[DOMAIN_AGE_KEY] == RED_COLOR % 'Less than 6 months ago'

    assert res_2[MODEL_KEY_SEO] == GREEN_COLOR % 'Good'
    assert res_2[MODEL_KEY_LOGO_FOUND] == GREEN_COLOR % 'Not Suspicious'
    assert res_2[MODEL_KEY_LOGIN_FORM] == GREEN_COLOR % 'No'
    assert res_2[DOMAIN_AGE_KEY] == GREEN_COLOR % 'More than 6 months ago'


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
