from DBotPredictURLPhishing import *

CORRECT_DOMAINS = ['google.com', 'facebook.com']




class PhishingURLModelMock:

    def __init__(self, filter_words_res=None, explain_model_words_res=None):
        pass



def executeCommand(command, args=None):
    if command == 'whois':
        domain = args.get('query')
        if not domain:
            return []
        else:
            date = "22-03-1989"
            return [{'EntryContext': {
                'Domain(val.Name && val.Name == obj.Name)': {
                    'WHOIS': {
                        'CreationDate': date}}}, "Type": "note"}]

    elif command == 'rasterize':
        return [{'Contents': {'image_b64': "",
                              'html': "html",},
                 'Type': 'note'}]

    elif command == 'getMLModel':
        return [{'Contents':
                     {'modelData': "ModelDataML",
                      'model':
                          {'type':
                               {'type': ''},
                           'extra': {OOB_MAJOR_VERSION_INFO_KEY:0, OOB_MINOR_VERSION_INFO_KEY:0}
                           }
                      },
                 'Type': 'note'}]

    elif command == 'createMLModel':
        return None


def test_regular(mocker):
    model_prediction = {MODEL_KEY_URL_SCORE:0.5,
                       MODEL_KEY_LOGO_FOUND:True,
                       MODEL_KEY_SEO:True,
                       MODEL_KEY_LOGO_IMAGE_BYTES:"",
                       MODEL_KEY_LOGO_LOGIN_FORM:True
                        }
    model_mock = PhishingURLModelMock()
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'urls': 'google.com', 'numberEntryToReturn': '1'})
    mocker.patch('DBotPredictURLPhishing.decode_model_data', return_value=model_mock, create=True)
    mocker.patch.object(model_mock, 'top_domains', return_value=("", 0), create=True)
    mocker.patch.object(model_mock, 'major', return_value=0, create=True)
    mocker.patch.object(model_mock, 'minor', return_value=0, create=True)
    mocker.patch.object(model_mock, 'predict', return_value=model_prediction, create=True)
    mocker.patch.object(model_mock, 'logos_dict', return_value={}, create=True)
    general_summary, detailed_summary, msg_list = main()
    a=1












def test_get_colored_pred_json():
    pred_json_1 = {
        MODEL_KEY_SEO: True,
        MODEL_KEY_LOGO_FOUND: True,
        MODEL_KEY_LOGO_LOGIN_FORM: True,
        DOMAIN_AGE_KEY: True
    }
    pred_json_2 = {
        MODEL_KEY_SEO: False,
        MODEL_KEY_LOGO_FOUND: False,
        MODEL_KEY_LOGO_LOGIN_FORM: False,
        DOMAIN_AGE_KEY: False
    }

    res_1 = get_colored_pred_json(pred_json_1)
    res_2 = get_colored_pred_json(pred_json_2)

    assert res_1[MODEL_KEY_SEO] == RED_COLOR %'Malicious'
    assert res_1[MODEL_KEY_LOGO_FOUND] == RED_COLOR %'Suspicious'
    assert res_1[MODEL_KEY_LOGO_LOGIN_FORM] ==RED_COLOR %'Yes'
    assert res_1[DOMAIN_AGE_KEY] == RED_COLOR %'Less than 6 months ago'

    assert res_2[MODEL_KEY_SEO] == GREEN_COLOR %'Benign'
    assert res_2[MODEL_KEY_LOGO_FOUND] == GREEN_COLOR %'Not Suspicious'
    assert res_2[MODEL_KEY_LOGO_LOGIN_FORM] == GREEN_COLOR %'No'
    assert res_2[DOMAIN_AGE_KEY] == GREEN_COLOR %'More than 6 months ago'

def test_get_score():
    pred_json_1 = {
        MODEL_KEY_SEO: True,
        MODEL_KEY_LOGO_FOUND:True,
        MODEL_KEY_LOGO_LOGIN_FORM: False,
        DOMAIN_AGE_KEY: True,
        MODEL_KEY_URL_SCORE:0.4
    }
    assert get_score(pred_json_1) == 0.725
    pred_json_2 = {
        MODEL_KEY_SEO: True,
        MODEL_KEY_LOGO_FOUND:False,
        MODEL_KEY_LOGO_LOGIN_FORM: False,
        DOMAIN_AGE_KEY: False,
        MODEL_KEY_URL_SCORE:0.6
    }
    assert get_score(pred_json_2) == 0.55