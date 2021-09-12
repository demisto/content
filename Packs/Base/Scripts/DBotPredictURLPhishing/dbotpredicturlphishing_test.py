from DBotPredictURLPhishing import *


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
    get_score(pred_json_1) = 0.95
    pred_json_2 = {
        MODEL_KEY_SEO: True,
        MODEL_KEY_LOGO_FOUND:False,
        MODEL_KEY_LOGO_LOGIN_FORM: False,
        DOMAIN_AGE_KEY: False,
        MODEL_KEY_URL_SCORE:0.6
    }
    get_score(pred_json_2) = 0.55