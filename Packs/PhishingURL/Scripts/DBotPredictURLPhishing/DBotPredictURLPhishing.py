import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib
import pandas as pd
import base64
import dill
import copy
import numpy as np
import urllib3
from tldextract import TLDExtract
from bs4 import BeautifulSoup

urllib3.disable_warnings()

dill.settings['recurse'] = True

no_fetch_extract = TLDExtract(suffix_list_urls=None, cache_dir=False)

VERSION = get_demisto_version_as_str()
NEW_DEMISTO_VERSION = VERSION[0] + '.' + VERSION[2] >= '6.5'

OOB_MAJOR_VERSION_INFO_KEY = 'major'
OOB_MINOR_VERSION_INFO_KEY = 'minor'
MAJOR_VERSION = 1
MINOR_DEFAULT_VERSION = 0

KEY_IMAGE_RASTERIZE = "image_b64"
KEY_IMAGE_HTML = "html"
KEY_CURRENT_URL_RASTERIZE = 'current_url'

MSG_MISSING_INFORMATION_RASTERIZE = f"Missing required Rastarize data ({KEY_IMAGE_HTML} / {KEY_IMAGE_RASTERIZE})."
MSG_SOMETHING_WRONG_IN_RASTERIZE = "Something went wrong with rasterize"
MSG_ENABLE_WHOIS = "Please enable whois integration for more accurate prediction"
MSG_MODEL_VERSION_IN_DEMISTO = "Model version in demisto: %s.%s"
MSG_NO_MODEL_IN_DEMISTO = "There is no existing model version in demisto"
MSG_NO_URL_GIVEN = "Please input at least one URL"
MSG_FAILED_RASTERIZE = "Rasterize error: ERR_NAME_NOT_RESOLVED"
MSG_FAILED_RASTERIZE_TIMEOUT = "Timeout rasterize"
MSG_IMPOSSIBLE_CONNECTION = "Failed to establish a new connection - Name or service not known"
MSG_UPDATE_MODEL = "Update demisto model from docker model version %s.%s"
MSG_UPDATE_LOGO = "Update demisto model from docker model version %s.%s and transfering logos from demisto version %s.%s"
MSG_WRONG_CONFIG_MODEL = 'Wrong configuration of the model'
MSG_NO_ACTION_ON_MODEL = "Use current model"
MSG_WHITE_LIST = "White List"
MSG_REDIRECT = 'Prediction will be made on the last URL'
MSG_NEED_TO_UPDATE_RASTERIZE = "Please install and/or update rasterize pack"
EMPTY_STRING = ""
URL_PHISHING_MODEL_NAME = "url_phishing_model"
OUT_OF_THE_BOX_MODEL_PATH = '/model/model_docker.pkl'
UNKNOWN_MODEL_TYPE = 'UNKNOWN_MODEL_TYPE'
THRESHOLD_NEW_DOMAIN_MONTHS = 6
DOMAIN_AGE_KEY = 'New domain (less than %s months)' % str(THRESHOLD_NEW_DOMAIN_MONTHS)

MALICIOUS_VERDICT = "Malicious"
BENIGN_VERDICT = "Benign"
SUSPICIOUS_VERDICT = "Suspicious"
BENIGN_VERDICT_WHITELIST = "Benign - Top domains from Majestic"
UNKNOWN = 'Unknown'

BENIGN_THRESHOLD = 0.5
SUSPICIOUS_THRESHOLD = 0.7

SCORE_INVALID_URL = -1.0
SCORE_BENIGN = 0.0  # type: float

GREEN_COLOR = "{{color:#1DB846}}(%s)" if NEW_DEMISTO_VERSION else "**%s**"
RED_COLOR = "{{color:#D13C3C}}(%s)" if NEW_DEMISTO_VERSION else "**%s**"

VERDICT_MALICIOUS_COLOR = "{{color:#D13C3C}}(**%s**)" if NEW_DEMISTO_VERSION else "**%s**"
VERDICT_SUSPICIOUS_COLOR = "{{color:#EF9700}}(**%s**)" if NEW_DEMISTO_VERSION else "**%s**"
VERDICT_BENIGN_COLOR = "{{color:#1DB846}}(**%s**)" if NEW_DEMISTO_VERSION else "**%s**"
VERDICT_ERROR_COLOR = "{{color:#D13C3C}}(**%s**)" if NEW_DEMISTO_VERSION else "**%s**"
MAPPING_VERDICT_COLOR = {MALICIOUS_VERDICT: VERDICT_MALICIOUS_COLOR, BENIGN_VERDICT: VERDICT_BENIGN_COLOR,
                         SUSPICIOUS_VERDICT: VERDICT_SUSPICIOUS_COLOR, BENIGN_VERDICT_WHITELIST: VERDICT_BENIGN_COLOR}

SCORE_THRESHOLD = 0.6  # type: float

STATUS_CODE_VALID = 200

MODEL_KEY_URL_SCORE = 'url_score'
MODEL_KEY_LOGO_FOUND = 'logo_found'
MODEL_KEY_SEO = 'seo'
MODEL_KEY_LOGO_IMAGE_BYTES = 'image_bytes'
MODEL_KEY_LOGIN_FORM = 'login_form'

KEY_CONTENT_DOMAIN = "Domain"
KEY_CONTENT_URL = "URL"
KEY_CONTENT_LOGO = "UseOfSuspiciousLogo"
KEY_CONTENT_LOGIN = "HasLoginForm"
KEY_CONTENT_URL_SCORE = "URLStaticScore"
KEY_CONTENT_SEO = "BadSEOQuality"
KEY_CONTENT_AGE = "NewDomain"
KEY_CONTENT_VERDICT = "FinalVerdict"
KEY_CONTENT_IS_WHITELISTED = "TopMajesticDomain"
KEY_CONTENT_DBOT_SCORE = 'DBotScore'

KEY_HR_DOMAIN = "Domain"
KEY_HR_URL = 'Url'
KEY_HR_SEO = "Search engine optimisation"
KEY_HR_LOGIN = "Is there a Login form ?"
KEY_HR_LOGO = "Suspicious use of company logo"
KEY_HR_URL_SCORE = "URL severity score (from 0 to 1)"

KEY_CONTENT_SUMMARY_URL = 'URL'
KEY_CONTENT_SUMMARY_FINAL_VERDICT = 'FinalVerdict'

KEY_FINAL_VERDICT = "Final Verdict"

WEIGHT_HEURISTIC = {DOMAIN_AGE_KEY: 3, MODEL_KEY_LOGIN_FORM: 1, MODEL_KEY_SEO: 1,
                    MODEL_KEY_URL_SCORE: 2, MODEL_KEY_LOGO_FOUND: 1}

MAPPING_VERDICT_TO_DISPLAY_VERDICT = {
    MODEL_KEY_SEO: {True: RED_COLOR % 'Bad', False: GREEN_COLOR % 'Good'},
    MODEL_KEY_LOGO_FOUND: {True: RED_COLOR % 'Suspicious', False: GREEN_COLOR % 'Not Suspicious'},
    MODEL_KEY_LOGIN_FORM: {True: RED_COLOR % 'Yes', False: GREEN_COLOR % 'No'},
    DOMAIN_AGE_KEY: {True: RED_COLOR % 'Less than 6 months ago', False: GREEN_COLOR % 'More than 6 months ago',
                     None: None}
}  # type: Dict

TIMEOUT_REQUESTS = 5
WAIT_TIME_RASTERIZE = 5
TIMEOUT_RASTERIZE = 120

DOMAIN_CHECK_RASTERIZE = 'google.com'


def get_model_data(model_name: str):
    """
    Return model data saved in demisto (string of encoded base 64)
    :param model_name: name of the model to load from demisto
    :return: str, str
    """
    res_model = demisto.executeCommand("getMLModel", {"modelName": model_name})[0]
    if is_error(res_model):
        raise DemistoException("Error reading model %s from Demisto" % model_name)
    else:
        model_data = res_model['Contents']['modelData']
        try:
            model_type = res_model['Contents']['model']["type"]["type"]
            return model_data, model_type
        except Exception:
            return model_data, UNKNOWN_MODEL_TYPE


def decode_model_data(model_data: str):
    """
    Decode the base 64 version of the model
    :param model_data: string of the encoded based 64 model
    :return: Model
    """
    return dill.loads(base64.b64decode(model_data.encode('utf-8')))  # guardrails-disable-line


def load_oob(path=OUT_OF_THE_BOX_MODEL_PATH):
    """
    Load pickle model from the docker
    :param path: path of the model saved in the docker
    :return: bytes
    """
    with open(path, 'rb') as f:
        model_b = f.read()
        model_64 = base64.b64encode(model_b)
    return model_64


def load_model_from_docker(path=OUT_OF_THE_BOX_MODEL_PATH):
    model = dill.load(open(path, 'rb'))  # guardrails-disable-line
    return model


def load_oob_model(path: str):
    """
    Load and save model from the model in the docker
    :return: None
    """
    try:
        encoded_model = load_oob(path)
    except Exception:
        raise DemistoException(traceback.format_exc())
    res = demisto.executeCommand('createMLModel', {'modelData': encoded_model.decode('utf-8'),
                                                   'modelName': URL_PHISHING_MODEL_NAME,
                                                   'modelLabels': [MALICIOUS_VERDICT, BENIGN_VERDICT,
                                                                   SUSPICIOUS_VERDICT],
                                                   'modelOverride': 'true',
                                                   'modelHidden': True,
                                                   'modelType': 'url_phishing',
                                                   'modelExtraInfo': {
                                                       OOB_MAJOR_VERSION_INFO_KEY: MAJOR_VERSION,
                                                       OOB_MINOR_VERSION_INFO_KEY: MINOR_DEFAULT_VERSION}})
    if is_error(res):
        raise DemistoException(get_error(res))
    return MSG_UPDATE_MODEL % (MAJOR_VERSION, MINOR_DEFAULT_VERSION)


def oob_model_exists_and_updated() -> tuple[bool, int, int, str]:
    """
    Check is the model exist and is updated in demisto
    :return: book
    """
    res_model = demisto.executeCommand("getMLModel", {"modelName": URL_PHISHING_MODEL_NAME})[0]
    if is_error(res_model):
        return False, -1, -1, ''
    model_data = res_model['Contents']['modelData']
    existing_model_version_major = res_model['Contents']['model']['extra'].get(OOB_MAJOR_VERSION_INFO_KEY, -1)
    existing_model_version_minor = res_model['Contents']['model']['extra'].get(OOB_MINOR_VERSION_INFO_KEY, -1)
    return True, existing_model_version_major, existing_model_version_minor, model_data


def image_from_base64_to_bytes(base64_message: str):
    """
    Transform image from base64 string into bytes
    :param base64_message:
    :return:
    """
    base64_bytes = base64_message.encode('utf-8')
    message_bytes = base64.b64decode(base64_bytes)
    return message_bytes


def extract_domainv2(url):
    ext = no_fetch_extract(url)
    return ext.domain + "." + ext.suffix


def in_white_list(model, url: str) -> bool:
    """
    Check if url belongs to the Model whitelist
    :param model: model which contains top_domains attribute
    :param url: url to check
    :return:
    """
    return extract_domainv2(url) in model.top_domains


def get_colored_pred_json(pred_json: dict) -> dict:
    """
    Create copy and color json values according to their values.
    :param pred_json: json to color
    :return: json
    """
    pred_json_colored = copy.deepcopy(pred_json)
    pred_json_colored[MODEL_KEY_SEO] = MAPPING_VERDICT_TO_DISPLAY_VERDICT[MODEL_KEY_SEO][pred_json[MODEL_KEY_SEO]]
    pred_json_colored[MODEL_KEY_LOGO_FOUND] = MAPPING_VERDICT_TO_DISPLAY_VERDICT[MODEL_KEY_LOGO_FOUND][
        pred_json[MODEL_KEY_LOGO_FOUND]]
    pred_json_colored[MODEL_KEY_LOGIN_FORM] = MAPPING_VERDICT_TO_DISPLAY_VERDICT[MODEL_KEY_LOGIN_FORM][
        pred_json[MODEL_KEY_LOGIN_FORM]]
    pred_json_colored[DOMAIN_AGE_KEY] = MAPPING_VERDICT_TO_DISPLAY_VERDICT[DOMAIN_AGE_KEY][pred_json[DOMAIN_AGE_KEY]]
    return pred_json_colored


def create_x_pred(output_rasterize: dict, url: str) -> pd.DataFrame:
    """
    Create dataframe to predict from the rasterize output
    :param output_rasterize: Dict from the output of rasterize command
    :param url: url to examine
    :return: pd.DataFrame
    """
    website64 = output_rasterize.get(KEY_IMAGE_RASTERIZE, None)
    html = output_rasterize.get(KEY_IMAGE_HTML, None)
    X_pred = pd.DataFrame(columns=['name', 'image', 'html'])
    X_pred.loc[0] = [url, website64, html]
    return X_pred


def prepend_protocol(url: str, protocol: str, www: bool = True) -> str:
    """forceModel
    Append a protocol name (usually http or https) and www to a url
    :param url: url
    :param protocol: protocol we want to add (usually http or https)
    :return: str
    """
    p = urllib.parse.urlparse(url, protocol)  # type: ignore
    netloc = p.netloc or p.path
    path = p.path if p.netloc else ''
    if not netloc.startswith('www.') and www:
        netloc = 'www.' + netloc
    p = urllib.parse.ParseResult(protocol, netloc, path, *p[3:])  # type: ignore
    return p.geturl()


def verdict_to_int(verdict):
    if verdict == MALICIOUS_VERDICT:
        return 3
    if verdict in (BENIGN_VERDICT, BENIGN_VERDICT_WHITELIST):
        return 1
    if verdict == SUSPICIOUS_VERDICT:
        return 2
    return None


def return_entry_summary(pred_json: dict, url: str, whitelist: bool, output_rasterize: dict, verdict: str,
                         reliability: str = DBotScoreReliability.A_PLUS):
    """
    Return entry to demisto
    :param pred_json: json with output of the model
    :param url: url
    :param whitelist: if url belongs to whitelist of the model
    :param reliability: reliability of the source providing the intelligence data.
    :return: entry to demisto
    """
    if whitelist:
        return None
    if verdict == BENIGN_VERDICT_WHITELIST:
        verdict = BENIGN_VERDICT
    if whitelist or not pred_json:
        url_score = SCORE_BENIGN
        url_score_colored = GREEN_COLOR % str(url_score) if url_score < SCORE_THRESHOLD else RED_COLOR % str(
            url_score)
    else:
        url_score = round(pred_json[MODEL_KEY_URL_SCORE], 2)
        url_score_colored = GREEN_COLOR % str(url_score) if url_score < SCORE_THRESHOLD else RED_COLOR % str(
            url_score)  # type: ignore
    pred_json_colored = get_colored_pred_json(pred_json) if pred_json else {}
    domain = extract_domainv2(url)
    explain = {
        KEY_CONTENT_DOMAIN: domain,
        KEY_CONTENT_URL: url,
        KEY_CONTENT_LOGO: str(pred_json.get(MODEL_KEY_LOGO_FOUND, UNKNOWN)),
        KEY_CONTENT_LOGIN: str(pred_json.get(MODEL_KEY_LOGIN_FORM, UNKNOWN)),
        KEY_CONTENT_URL_SCORE: url_score,
        KEY_CONTENT_SEO: str(pred_json.get(MODEL_KEY_SEO, UNKNOWN)),
        KEY_CONTENT_VERDICT: verdict,
        KEY_CONTENT_IS_WHITELISTED: str(whitelist)
    }
    dbot_score = Common.DBotScore(indicator=url,
                                  indicator_type=DBotScoreType.URL,
                                  integration_name='DBotPhishingURL',
                                  score=verdict_to_int(verdict),
                                  reliability=reliability)
    context_DBot_score = dbot_score.to_context().get(dbot_score.get_context_path())

    if pred_json and pred_json[DOMAIN_AGE_KEY] is not None:
        explain[KEY_CONTENT_AGE] = str(pred_json[DOMAIN_AGE_KEY])
    explain_hr = {
        KEY_HR_URL: url,
        KEY_HR_SEO: str(pred_json_colored.get(MODEL_KEY_SEO, UNKNOWN)),
        KEY_HR_LOGIN: str(pred_json_colored.get(MODEL_KEY_LOGIN_FORM, UNKNOWN)),
        KEY_HR_LOGO: str(pred_json_colored.get(MODEL_KEY_LOGO_FOUND, UNKNOWN)),
        KEY_HR_URL_SCORE: url_score_colored
    }
    if pred_json and pred_json[DOMAIN_AGE_KEY] is not None:
        explain_hr[DOMAIN_AGE_KEY] = str(pred_json_colored[DOMAIN_AGE_KEY])
    if verdict == BENIGN_VERDICT:
        return_entry = {
            "Type": entryTypes["note"],
            "ContentsFormat": formats['json'],
            "HumanReadable": tableToMarkdown("Phishing prediction evidence | %s" % domain, explain_hr),
            "Contents": explain,
            "EntryContext": {'DBotPredictURLPhishing': explain}
        }
    else:
        return_entry = {
            "Type": entryTypes["note"],
            "ContentsFormat": formats['json'],
            "HumanReadable": tableToMarkdown("Phishing prediction evidence | %s" % domain, explain_hr),
            "Contents": explain,
            "EntryContext": {'DBotPredictURLPhishing': explain, KEY_CONTENT_DBOT_SCORE: context_DBot_score},
            "Tags": ['DBOT_URL_PHISHING_MALICIOUS']
        }
    return_results(return_entry)
    # Get rasterize image or logo detection if logo was found
    if pred_json:
        image = pred_json[MODEL_KEY_LOGO_IMAGE_BYTES]
        if not image:
            image = image_from_base64_to_bytes(output_rasterize.get(KEY_IMAGE_RASTERIZE, None))
        res = fileResult(filename='Logo detection engine', data=image)
        res['Type'] = entryTypes['image']
        if pred_json[MODEL_KEY_LOGO_FOUND]:
            res["Tags"] = ['DBOT_URL_PHISHING_MALICIOUS']
        return_results(res)
    return explain


def return_entry_white_list(url):
    """
    Create syntethci entry when url belongs to whitelist
    :param url: url
    :return:
    """
    explain = {
        KEY_CONTENT_DOMAIN: extract_domainv2(url),
        KEY_CONTENT_URL: url,
        KEY_CONTENT_AGE: MSG_WHITE_LIST,
        KEY_CONTENT_LOGO: MSG_WHITE_LIST,
        KEY_CONTENT_LOGIN: MSG_WHITE_LIST,
        KEY_CONTENT_URL_SCORE: MSG_WHITE_LIST,
        KEY_CONTENT_SEO: MSG_WHITE_LIST
    }
    explain_hr = {
        KEY_HR_URL: url,
        KEY_HR_SEO: MSG_WHITE_LIST,
        DOMAIN_AGE_KEY: MSG_WHITE_LIST,
        KEY_HR_LOGIN: MSG_WHITE_LIST,
        KEY_HR_LOGO: MSG_WHITE_LIST,
        KEY_HR_URL_SCORE: MSG_WHITE_LIST
    }
    verdict_hr = {
        "Verdict": BENIGN_VERDICT,
        "URL": url
    }
    return_entry = {
        "Type": entryTypes["note"],
        "ContentsFormat": formats['json'],
        "HumanReadable": tableToMarkdown("Verdict", verdict_hr) + tableToMarkdown("Report", explain_hr),
        "Contents": explain,
        "EntryContext": {'DBotPredictURLPhishing': explain}
    }
    return_results(return_entry)


def get_score(pred_json):
    use_age = False
    use_logo = False
    if pred_json[DOMAIN_AGE_KEY]:
        use_age = True
    if pred_json[MODEL_KEY_LOGO_FOUND]:
        use_logo = True
    domain_age_key = 0 if pred_json[DOMAIN_AGE_KEY] is None else pred_json[DOMAIN_AGE_KEY]
    total_weight_used = WEIGHT_HEURISTIC[DOMAIN_AGE_KEY] * use_age + WEIGHT_HEURISTIC[MODEL_KEY_LOGIN_FORM] \
        + WEIGHT_HEURISTIC[MODEL_KEY_SEO] + WEIGHT_HEURISTIC[MODEL_KEY_URL_SCORE] \
        + WEIGHT_HEURISTIC[MODEL_KEY_LOGO_FOUND] * use_logo
    score = (use_age * WEIGHT_HEURISTIC[DOMAIN_AGE_KEY] * domain_age_key
             + WEIGHT_HEURISTIC[MODEL_KEY_LOGIN_FORM] * pred_json[MODEL_KEY_LOGIN_FORM]
             + WEIGHT_HEURISTIC[MODEL_KEY_SEO] * pred_json[MODEL_KEY_SEO]
             + WEIGHT_HEURISTIC[MODEL_KEY_URL_SCORE] * pred_json[MODEL_KEY_URL_SCORE]
             + use_logo * WEIGHT_HEURISTIC[MODEL_KEY_LOGO_FOUND] * pred_json[MODEL_KEY_LOGO_FOUND]) / total_weight_used
    return score


def get_verdict(pred_json: dict, is_white_listed: bool) -> tuple[float, str]:
    """
    Return verdict of the url based on the output of the model
    :param pred_json: output from the model
    :return:
    """
    if is_white_listed:
        return SCORE_BENIGN, BENIGN_VERDICT
    score = get_score(pred_json)
    if pred_json[MODEL_KEY_LOGO_FOUND]:
        return score, MALICIOUS_VERDICT
    else:
        if score < BENIGN_THRESHOLD:
            return score, BENIGN_VERDICT
        elif score < SUSPICIOUS_THRESHOLD:
            return score, SUSPICIOUS_VERDICT
        else:
            return score, MALICIOUS_VERDICT


def create_dict_context(url, last_url, verdict, pred_json, score, is_white_listed, output_rasterize):
    return {'url_redirect': url, 'url': last_url, 'verdict': verdict, 'pred_json': pred_json, 'score': score,
            'is_white_listed': is_white_listed,
            'output_rasterize': output_rasterize}


def extract_created_date(entry_list: list):
    """
    Check if domain age is younger than THRESHOLD_NEW_DOMAIN_YEAR year
    :param entry_list: output of the whois command
    :return: bool
    """
    for entry in entry_list:
        if is_error(entry):
            continue
        else:
            date_str = (
                entry.get('EntryContext') or {}
            ).get('Domain(val.Name && val.Name == obj.Name)', {}).get('WHOIS', {}).get('CreationDate')
            if date_str:
                date = datetime.strptime(date_str, '%d-%m-%Y')
                threshold_date = datetime.now() - timedelta(days=THRESHOLD_NEW_DOMAIN_MONTHS * 30)
                return date > threshold_date
    return None


def get_prediction_single_url(model, url, force_model, who_is_enabled, debug, rasterize_timeout):
    is_white_listed = False
    # Rasterize html and image
    res_rasterize = demisto.executeCommand('rasterize', {'type': 'json',
                                                         'url': url,
                                                         'wait_time': WAIT_TIME_RASTERIZE,
                                                         'execution-timeout': rasterize_timeout
                                                         })

    demisto.debug('Rasterize Data: ' + json.dumps(res_rasterize))

    if is_error(res_rasterize):
        demisto.debug(f'Rasterize Error: {res_rasterize}')
        error = get_error(res_rasterize)

        if 'disabled' in error or 'enabled' in error:
            raise DemistoException(MSG_NEED_TO_UPDATE_RASTERIZE)

        elif 'timeout' in error:
            return create_dict_context(url, url, MSG_FAILED_RASTERIZE_TIMEOUT, {}, SCORE_INVALID_URL, is_white_listed, {})

        elif 'ERR_NAME_NOT_RESOLVED' in error:
            return create_dict_context(url, url, MSG_FAILED_RASTERIZE, {}, SCORE_INVALID_URL, is_white_listed, {})

        else:
            return create_dict_context(url, url, error, {}, SCORE_INVALID_URL, is_white_listed, {})

    if len(res_rasterize) > 0 and isinstance(res_rasterize[0]['Contents'], str):
        return create_dict_context(url, url, MSG_FAILED_RASTERIZE, {}, SCORE_INVALID_URL, is_white_listed, {})

    if not all((res_rasterize[0]['Contents'].get(KEY_IMAGE_RASTERIZE), res_rasterize[0]['Contents'].get(KEY_IMAGE_HTML))):
        return create_dict_context(url, url, MSG_MISSING_INFORMATION_RASTERIZE, {}, SCORE_INVALID_URL, is_white_listed, {})

    if len(res_rasterize) > 0:
        output_rasterize = res_rasterize[0]['Contents']

    else:
        create_dict_context(url, url, MSG_SOMETHING_WRONG_IN_RASTERIZE, {}, SCORE_INVALID_URL, is_white_listed, {})

    if KEY_CURRENT_URL_RASTERIZE not in output_rasterize.keys():
        raise DemistoException(MSG_NEED_TO_UPDATE_RASTERIZE)

    # Get final url and redirection
    final_url = output_rasterize.get(KEY_CURRENT_URL_RASTERIZE, url)

    url_redirect = f'{url} -> {final_url}   ({MSG_REDIRECT})' if final_url != url else final_url

    # Check domain age from WHOIS command
    domain = extract_domainv2(final_url)

    # Check is domain in white list -  If yes we don't run the model
    if in_white_list(model, final_url):
        if not force_model:
            is_white_listed = True
            return create_dict_context(url_redirect, final_url, BENIGN_VERDICT_WHITELIST, {}, SCORE_BENIGN, is_white_listed, {})
        else:
            is_white_listed = True

    res_whois = []

    if who_is_enabled:
        try:
            res_whois = demisto.executeCommand('whois', {'query': domain, 'execution-timeout': 5})

        except Exception:
            res_whois = []

    is_new_domain = extract_created_date(res_whois)

    x_pred = create_x_pred(output_rasterize, final_url)

    pred_json = model.predict(x_pred)

    if debug:
        return_results(pred_json['debug_top_words'])
        return_results(pred_json['debug_found_domains_list'])
        return_results(pred_json['seo'])
        return_results(pred_json['debug_image'])

    pred_json[DOMAIN_AGE_KEY] = is_new_domain

    score, verdict = get_verdict(pred_json, is_white_listed)
    return create_dict_context(url_redirect, final_url, verdict, pred_json, score, is_white_listed, output_rasterize)


def return_general_summary(results, tag="Summary"):
    df_summary = pd.DataFrame()
    df_summary['URL'] = [x.get('url_redirect') for x in results]
    df_summary[KEY_FINAL_VERDICT] = [MAPPING_VERDICT_COLOR[x.get('verdict')] % x.get('verdict')
                                     if x.get('verdict') in MAPPING_VERDICT_COLOR
                                     else VERDICT_ERROR_COLOR % x.get('verdict') for x in results]
    summary_context = [
        {KEY_CONTENT_SUMMARY_URL: x.get('url_redirect'), KEY_CONTENT_SUMMARY_FINAL_VERDICT: BENIGN_VERDICT,
         KEY_CONTENT_IS_WHITELISTED: 'True'} for x in results if x.get('is_white_listed')]
    df_summary_json = df_summary.to_dict(orient='records')
    return_entry = {
        "Type": entryTypes["note"],
        "ContentsFormat": formats['json'],
        "HumanReadable": tableToMarkdown("Phishing prediction summary for URLs", df_summary_json,
                                         headers=['URL', KEY_FINAL_VERDICT]),
        "Contents": summary_context,
        "EntryContext": {'DBotPredictURLPhishing': summary_context}
    }
    if tag is not None:
        return_entry["Tags"] = [f'DBOT_URL_PHISHING_{tag}']
    return_results(return_entry)
    return df_summary_json


def return_detailed_summary(results, reliability: str):
    outputs = []
    severity_list = [x.get('score') for x in results]
    indice_descending_severity = np.argsort(-np.array(severity_list), kind='mergesort')
    for i in range(len(results)):
        index = indice_descending_severity[i]
        if results[index].get('score') == SCORE_INVALID_URL:
            continue
        verdict = results[index].get('verdict')
        pred_json = results[index].get('pred_json')
        url = results[index].get('url')
        is_white_listed = results[index].get('is_white_listed')
        output_rasterize = results[index].get('output_rasterize')
        summary_json = return_entry_summary(pred_json, url, is_white_listed, output_rasterize, verdict, reliability)
        outputs.append(summary_json)
        outputs = [x for x in outputs if x]
    return outputs


def save_model_in_demisto(model):
    encoded_model = base64.b64encode(dill.dumps(model))  # guardrails-disable-line
    res = demisto.executeCommand('createMLModel', {'modelData': encoded_model.decode('utf-8'),
                                                   'modelName': URL_PHISHING_MODEL_NAME,
                                                   'modelLabels': [MALICIOUS_VERDICT, BENIGN_VERDICT],
                                                   'modelOverride': 'true',
                                                   'modelHidden': True,
                                                   'modelType': 'url_phishing',
                                                   'modelExtraInfo': {
                                                       OOB_MAJOR_VERSION_INFO_KEY: model.major,
                                                       OOB_MINOR_VERSION_INFO_KEY: model.minor}})
    if is_error(res):
        raise DemistoException(get_error(res))


def extract_urls(text):
    res = demisto.executeCommand("extractIndicators", {"text": text})
    if is_error(res):
        raise DemistoException(get_error(res))
    return list(set(json.loads(res[0]["Contents"]).get("URL", [])))


def load_demisto_model():
    model_64_str = get_model_data(URL_PHISHING_MODEL_NAME)[0]
    model = decode_model_data(model_64_str)
    return model


def get_final_urls(urls, max_urls, model):
    final_url = []
    seen = []
    low_priority_urls = []
    i = 0
    for url in urls:
        if i < max_urls:
            if extract_domainv2(url) in seen or extract_domainv2(url) in model.top_domains:
                low_priority_urls.append(url)
            else:
                final_url.append(url)
                seen.append(extract_domainv2(url))
                i += 1
    if len(final_url) < max_urls:
        final_url = final_url + low_priority_urls[:min(len(low_priority_urls), max_urls - len(final_url))]
    return final_url


def extract_embedded_urls_from_html(html):
    embedded_urls = []
    soup = BeautifulSoup(html)
    for a in soup.findAll('a'):
        if a.has_attr('href') and a['href'] not in a.get_text():
            embedded_urls.append(a['href'])
    return embedded_urls


def get_urls_to_run(email_body, email_html, urls_argument, max_urls, model, msg_list, debug):
    if email_body:
        urls_email_body = extract_urls(email_body)
    else:
        if not email_body and email_html:
            urls_email_body = extract_urls(BeautifulSoup(email_html).get_text())
        else:
            urls_email_body = []
    if email_html:
        urls_email_html = extract_embedded_urls_from_html(email_html)
    else:
        urls_email_html = []
    if isinstance(urls_argument, list):
        urls_only = urls_argument
    else:
        urls_only = [x.strip() for x in urls_argument.split(' ') if x]
    urls = urls_email_body + urls_only + urls_email_html
    urls = list(set(urls))
    if not urls:
        msg_list.append(MSG_NO_URL_GIVEN)
        return_results(MSG_NO_URL_GIVEN)
        return [], msg_list
    urls = get_final_urls(urls, max_urls, model)
    urls = [demisto.executeCommand("UnEscapeURLs", {"input": x})[0]['Contents'] for x in urls]
    if debug:
        return_results(urls)
    return urls, msg_list


def update_model_docker_from_model(model_docker, model):
    model_docker.logos_dict = model.logos_dict
    model_docker.top_domains = model.top_domains

    model_docker.clf.named_steps.preprocessor.named_transformers_[
        'image'].named_steps.trans.logo_dict = model.logos_dict

    model_docker.clf.named_steps.preprocessor.named_transformers_[
        'url'].named_steps.trans.d_top_domains = model.top_domains

    model_docker.clf.named_steps.preprocessor.named_transformers_[
        'image'].named_steps.trans.top_domains = model.logos_dict

    return model_docker


def update_and_load_model(debug, exist, reset_model, msg_list, demisto_major_version, demisto_minor_version,
                          model_data):
    if debug:
        if exist:
            msg_list.append(MSG_MODEL_VERSION_IN_DEMISTO % (demisto_major_version, demisto_minor_version))
        else:
            msg_list.append(MSG_NO_MODEL_IN_DEMISTO)

    if reset_model or not exist or (
            demisto_major_version < MAJOR_VERSION and demisto_minor_version == MINOR_DEFAULT_VERSION):
        msg_list.append(load_oob_model(OUT_OF_THE_BOX_MODEL_PATH))
        model_64_str = get_model_data(URL_PHISHING_MODEL_NAME)[0]
        model = decode_model_data(model_64_str)

    elif demisto_major_version == MAJOR_VERSION:
        model = decode_model_data(model_data)
        msg_list.append(MSG_NO_ACTION_ON_MODEL)

    elif (demisto_major_version < MAJOR_VERSION) and (demisto_minor_version > MINOR_DEFAULT_VERSION):
        model_docker = load_model_from_docker()
        model_docker_minor = model_docker.minor
        model = load_demisto_model()
        model_docker = update_model_docker_from_model(model_docker, model)
        model_docker.minor += 1
        save_model_in_demisto(model_docker)
        msg_list.append(MSG_UPDATE_LOGO % (MAJOR_VERSION, model_docker_minor, model.major, model.minor))
        model_64_str = get_model_data(URL_PHISHING_MODEL_NAME)[0]
        model = decode_model_data(model_64_str)
    else:
        msg_list.append(MSG_WRONG_CONFIG_MODEL)
        raise DemistoException(MSG_WRONG_CONFIG_MODEL)
    return model, msg_list


def check_if_whois_installed():
    try:
        demisto.executeCommand('whois', {'query': DOMAIN_CHECK_RASTERIZE, 'execution-timeout': 5
                                         })
        return True
    except ValueError:
        return_results(MSG_ENABLE_WHOIS)
        return False


def main():
    who_is_enabled = check_if_whois_installed()
    try:
        msg_list = []  # type: List

        # Check existing version of the model in demisto
        exist, demisto_major_version, demisto_minor_version, model_data = oob_model_exists_and_updated()

        # Load arguments
        reset_model = demisto.args().get('resetModel', 'False') == 'True'
        debug = demisto.args().get('debug', 'False') == 'True'
        force_model = demisto.args().get('forceModel', 'False') == 'True'
        email_body = demisto.args().get('emailBody', "")
        email_html = demisto.args().get('emailHTML', "")
        max_urls = int(demisto.args().get('maxNumberOfURL', 5))
        urls_argument = demisto.args().get('urls', '')
        reliability = demisto.args().get("reliability", DBotScoreReliability.A_PLUS)
        rasterize_timeout = arg_to_number(demisto.args().get('rasterize_timeout', TIMEOUT_RASTERIZE))
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(
            reliability
        )

        # Update model if necessary and load the model
        model, msg_list = update_and_load_model(debug, exist, reset_model, msg_list, demisto_major_version,
                                                demisto_minor_version, model_data)

        # Get all the URLs on which we will run the model
        urls, msg_list = get_urls_to_run(email_body, email_html, urls_argument, max_urls, model, msg_list, debug)
        if not urls:
            return None

        # Run the model and get predictions
        results = [get_prediction_single_url(model, x, force_model, who_is_enabled, debug, rasterize_timeout) for x in urls]

        # Return outputs
        general_summary = return_general_summary(results)
        detailed_summary = return_detailed_summary(results, reliability)
        if debug:
            return_results(msg_list)
        return general_summary, detailed_summary, msg_list
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute URL Phishing script. Error: {str(ex)}')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
