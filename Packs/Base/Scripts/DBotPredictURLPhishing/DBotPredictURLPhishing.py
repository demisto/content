import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib
from typing import List, Dict, Tuple
import pandas as pd
import base64
import requests
import dill
import copy
import numpy as np
from tldextract import TLDExtract
requests.packages.urllib3.disable_warnings()

dill.settings['recurse'] = True

NO_FETCH_EXTRACT = TLDExtract(suffix_list_urls=None, cache_dir=False)

OOB_MAJOR_VERSION_INFO_KEY = 'major'
OOB_MINOR_VERSION_INFO_KEY = 'minor'
MAJOR_VERSION = 0
MINOR_DEFAULT_VERSION = 0

MSG_INVALID_URL = "Error: "
MSG_NO_URL_GIVEN = "Please input at least one URL"
MSG_FAILED_RASTERIZE = "Rasterize for this url did not work correctly"
MSG_IMPOSSIBLE_CONNECTION = "Failed to establish a new connection - Name or service not known"
MSG_UPDATE_MODEL = "Update demisto model from docker model version %s.%s"
MSG_UPDATE_LOGO = "Update demisto model from docker model version %s.%s and transfering logos from demisto version %s.%s"
MSG_WRONG_CONFIG_MODEL = 'Wrong configuration of the model'
MSG_NO_ACTION_ON_MODEL = "Use current model"
MSG_WHITE_LIST = "White List"
EMPTY_STRING = ""
URL_PHISHING_MODEL_NAME = "phishing_model"
OUT_OF_THE_BOX_MODEL_PATH = '/model/model_docker.pkl'
UNKNOWN_MODEL_TYPE = 'UNKNOWN_MODEL_TYPE'
THRESHOLD_NEW_DOMAIN_MONTHS = 6
DOMAIN_AGE_KEY = 'New domain (less than %s months)' % str(THRESHOLD_NEW_DOMAIN_MONTHS)

MALICIOUS_VERDICT = "Malicious"
BENIGN_VERDICT = "Benign"
SUSPICIOUS_VERDICT = "Suspicious"
BENIGN_VERDICT_WHITELIST = "Benign - whitelisted"

BENIGN_THRESHOLD = 0.5
SUSPICIOUS_THRESHOLD = 0.7

SCORE_INVALID_URL = -1.0
SCORE_BENIGN = 0.0  # type: float

GREEN_COLOR = "{{color:#1DB846}}(%s)"
RED_COLOR = "{{color:#D13C3C}}(%s)"

VERDICT_MALICIOUS_COLOR = "{{color:#D13C3C}}(**%s**)"
VERDICT_SUSPICIOUS_COLOR = "{{color:#EF9700}}(**%s**)"
VERDICT_BENIGN_COLOR = "{{color:#1DB846}}(**%s**)"
VERDICT_ERROR_COLOR = "{{color:#D13C3C}}(**%s**)"
MAPPING_VERDICT_COLOR = {MALICIOUS_VERDICT: VERDICT_MALICIOUS_COLOR, BENIGN_VERDICT: VERDICT_BENIGN_COLOR,
                         SUSPICIOUS_VERDICT: VERDICT_SUSPICIOUS_COLOR, BENIGN_VERDICT_WHITELIST: VERDICT_BENIGN_COLOR}

SCORE_THRESHOLD = 0.7  # type: float

STATUS_CODE_VALID = 200

MODEL_KEY_URL_SCORE = 'url_score'
MODEL_KEY_LOGO_FOUND = 'logo_found'
MODEL_KEY_SEO = 'seo'
MODEL_KEY_LOGO_IMAGE_BYTES = 'image_bytes'
MODEL_KEY_LOGIN_FORM = 'login_form'

KEY_CONTENT_DOMAIN = "Domain"
KEY_CONTENT_URL = "URL"
KEY_CONTENT_LOGO = "SuspiciousLogo"
KEY_CONTENT_LOGIN = "LoginForm"
KEY_CONTENT_URL_SCORE = "URLScore"
KEY_CONTENT_SEO = "ContentBasedVerdict"
KEY_CONTENT_AGE = "DomainAge"

KEY_FINAL_VERDICT = "Final Verdict"

WEIGHT_HEURISTIC = {DOMAIN_AGE_KEY: 3, MODEL_KEY_LOGIN_FORM: 1, MODEL_KEY_SEO: 1,
                    MODEL_KEY_URL_SCORE: 1, MODEL_KEY_LOGO_FOUND: 1}

MAPPING_VERDICT_TO_DISPLAY_VERDICT = {
    MODEL_KEY_SEO: {True: RED_COLOR % 'Malicious', False: GREEN_COLOR % 'Benign'},
    MODEL_KEY_LOGO_FOUND: {True: RED_COLOR % 'Suspicious', False: GREEN_COLOR % 'Not Suspicious'},
    MODEL_KEY_LOGIN_FORM: {True: RED_COLOR % 'Yes', False: GREEN_COLOR % 'No'},
    DOMAIN_AGE_KEY: {True: RED_COLOR % 'Less than 6 months ago', False: GREEN_COLOR % 'More than 6 months ago',
                     None: None}
}  # type: Dict


def get_model_data(model_name: str):
    """
    Return model data saved in demisto (string of encoded base 64)
    :param model_name: name of the model to load from demisto
    :return: str, str
    """
    res_model = demisto.executeCommand("getMLModel", {"modelName": model_name})[0]
    if is_error(res_model):
        return_error("Error reading model %s from Demisto" % model_name)
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
    return dill.loads(base64.b64decode(model_data.encode('utf-8')))


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
    model = dill.load(open(path, 'rb'))
    return model


def load_oob_model(path: str):
    """
    Load and save model from the model in the docker
    :return: None
    """
    try:
        encoded_model = load_oob(path)
    except Exception:
        return_error(traceback.format_exc())
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
        return_error(get_error(res))
    return MSG_UPDATE_MODEL % (MAJOR_VERSION, MINOR_DEFAULT_VERSION)


def oob_model_exists_and_updated() -> Tuple[bool, int, int]:
    """
    Check is the model exist and is updated in demisto
    :return: book
    """
    res_model = demisto.executeCommand("getMLModel", {"modelName": URL_PHISHING_MODEL_NAME})[0]
    if is_error(res_model):
        return False, -1, -1
    existing_model_version_major = res_model['Contents']['model']['extra'].get(OOB_MAJOR_VERSION_INFO_KEY, -1)
    existing_model_version_minor = res_model['Contents']['model']['extra'].get(OOB_MINOR_VERSION_INFO_KEY, -1)
    return True, existing_model_version_major, existing_model_version_minor


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
    ext = NO_FETCH_EXTRACT(url)
    return ext.domain + "." + ext.suffix


def in_white_list(model, url: str) -> bool:
    """
    Check if url belongs to the Model whitelist
    :param model: model which contains top_domains attribute
    :param url: url to check
    :return:
    """
    if (extract_domainv2(url) in model.top_domains):
        return True
    else:
        return False


def get_colored_pred_json(pred_json: Dict) -> Dict:
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


def create_X_pred(output_rasterize: Dict, url: str) -> pd.DataFrame:
    """
    Create dataframe to predict from the rasterize output
    :param output_rasterize: Dict from the output of rasterize command
    :param url: url to examine
    :return: pd.DataFrame
    """
    website64 = output_rasterize.get('image_b64', None)
    html = output_rasterize.get('html', None)
    X_pred = pd.DataFrame(columns=['name', 'image', 'html'])
    X_pred.loc[0] = [url, website64, html]
    return X_pred


def prepend_protocol(url: str, protocol: str, www: bool = True) -> str:
    """
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


def is_valid_url(url: str) -> Tuple[bool, str]:
    """
    Check is an url is valid by requesting it using different protocol
    :param url: url
    :return: bool
    """
    try:
        response = requests.get(url, verify=False)  # nosec
    except requests.exceptions.RequestException:
        prepend_url = prepend_protocol(url, 'http', True)
        try:
            response = requests.get(prepend_url, verify=False)  # nosec
        except requests.exceptions.RequestException:
            prepend_url = prepend_protocol(url, 'https', True)
            try:
                response = requests.get(prepend_url, verify=False)  # nosec
            except requests.exceptions.RequestException:
                prepend_url = prepend_protocol(url, 'http', False)
                try:
                    response = requests.get(prepend_url, verify=False)  # nosec
                except requests.exceptions.RequestException:
                    prepend_url = prepend_protocol(url, 'https', False)
                    try:
                        response = requests.get(prepend_url, verify=False)  # nosec
                    except requests.exceptions.RequestException:
                        return False, MSG_IMPOSSIBLE_CONNECTION
    if response.status_code == 200:
        return True, EMPTY_STRING
    else:
        return False, response.reason


def return_entry_summary(pred_json: Dict, url: str, whitelist: bool, output_rasterize: Dict):
    """
    Return entry to demisto
    :param pred_json: json with output of the model
    :param url: url
    :param whitelist: if url belongs to whitelist of the model
    :return: entry to demisto
    """
    if not pred_json:
        return
    if whitelist:
        url_score = SCORE_BENIGN
        url_score = GREEN_COLOR % str(url_score) if url_score < SCORE_THRESHOLD else RED_COLOR % str(
            url_score)
    else:
        url_score = round(pred_json[MODEL_KEY_URL_SCORE], 2)
        url_score = GREEN_COLOR % str(url_score) if url_score < SCORE_THRESHOLD else RED_COLOR % str(url_score)  # type: ignore
    pred_json_colored = get_colored_pred_json(pred_json)
    domain = extract_domainv2(url)
    explain = {
        KEY_CONTENT_DOMAIN: domain,
        KEY_CONTENT_URL: url,
        KEY_CONTENT_LOGO: str(pred_json[MODEL_KEY_LOGO_FOUND]),
        KEY_CONTENT_LOGIN: str(pred_json[MODEL_KEY_LOGIN_FORM]),
        KEY_CONTENT_URL_SCORE: url_score,
        KEY_CONTENT_SEO: str(pred_json[MODEL_KEY_SEO])
    }
    if pred_json[DOMAIN_AGE_KEY] is not None:
        explain[KEY_CONTENT_AGE] = str(pred_json[DOMAIN_AGE_KEY])
    explain_hr = {
        "Domain": domain,
        "Domain reputation": str(pred_json_colored[MODEL_KEY_SEO]),
        "Is there a Login form ?": str(pred_json_colored[MODEL_KEY_LOGIN_FORM]),
        "Suspiscious use of company logo": str(pred_json_colored[MODEL_KEY_LOGO_FOUND]),
        "URL severity score (from 0 to 1)": url_score
    }
    if pred_json[DOMAIN_AGE_KEY] is not None:
        explain_hr[DOMAIN_AGE_KEY] = str(pred_json_colored[DOMAIN_AGE_KEY])
    return_entry = {
        "Type": entryTypes["note"],
        "ContentsFormat": formats['json'],
        "HumanReadable": tableToMarkdown("Phishing prediction evidence | %s" % domain, explain_hr),
        "Contents": explain,
        "EntryContext": {'DBotPredictURLPhishing': explain}
    }
    demisto.results(return_entry)
    # Get rasterize image or logo detection if logo was found
    image = pred_json[MODEL_KEY_LOGO_IMAGE_BYTES]
    if not image:
        image = image_from_base64_to_bytes(output_rasterize.get('image_b64', None))
    res = fileResult(filename='Logo detection engine', data=image)
    res['Type'] = entryTypes['image']
    demisto.results(res)
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
        "Domain": extract_domainv2(url),
        "Has the domain good SEO ?": MSG_WHITE_LIST,
        DOMAIN_AGE_KEY: MSG_WHITE_LIST,
        "Has the website a login page?": MSG_WHITE_LIST,
        "Logo found that does not correspond to the given domain": MSG_WHITE_LIST,
        "URL severity score (from 0 to 1)": MSG_WHITE_LIST
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
    demisto.results(return_entry)


def get_score(pred_json):
    use_age = False
    use_logo = False
    if pred_json[DOMAIN_AGE_KEY]:
        use_age = True
    if pred_json[MODEL_KEY_LOGO_FOUND]:
        use_logo = True
    if pred_json[DOMAIN_AGE_KEY] is None:
        domain_age_key = 0
    else:
        domain_age_key = pred_json[DOMAIN_AGE_KEY]
    total_weight_used = WEIGHT_HEURISTIC[DOMAIN_AGE_KEY] * use_age + WEIGHT_HEURISTIC[MODEL_KEY_LOGIN_FORM] \
        + WEIGHT_HEURISTIC[MODEL_KEY_SEO] + WEIGHT_HEURISTIC[MODEL_KEY_URL_SCORE] \
        + WEIGHT_HEURISTIC[MODEL_KEY_LOGO_FOUND] * use_logo
    score = (use_age * WEIGHT_HEURISTIC[DOMAIN_AGE_KEY] * domain_age_key
             + WEIGHT_HEURISTIC[MODEL_KEY_LOGIN_FORM] * pred_json[MODEL_KEY_LOGIN_FORM]
             + WEIGHT_HEURISTIC[MODEL_KEY_SEO] * pred_json[MODEL_KEY_SEO]
             + WEIGHT_HEURISTIC[MODEL_KEY_URL_SCORE] * pred_json[MODEL_KEY_URL_SCORE]
             + use_logo * WEIGHT_HEURISTIC[MODEL_KEY_LOGO_FOUND] * pred_json[MODEL_KEY_LOGO_FOUND]) / total_weight_used
    return score


def get_verdict(pred_json: Dict, is_white_listed: bool) -> Tuple[float, str]:
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


def create_dict_context(url, verdict, pred_json, score, is_white_listed, output_rasterize):
    return {'url': url, 'verdict': verdict, 'pred_json': pred_json, 'score': score, 'is_white_listed': is_white_listed,
            'output_rasterize': output_rasterize}


def extract_created_date(entry_list: List):
    """
    Check if domain age is younger than THRESHOLD_NEW_DOMAIN_YEAR year
    :param entry_list: output of the whois command
    :return: bool
    """
    for entry in entry_list:
        if is_error(entry):
            continue
        else:
            date_str = entry['EntryContext'].get('Domain(val.Name && val.Name == obj.Name)', {}).get('WHOIS', {}).get(
                'CreationDate', None)
            if date_str:
                date = datetime.strptime(date_str, '%d-%m-%Y')
                threshold_date = datetime.now() - timedelta(days=THRESHOLD_NEW_DOMAIN_MONTHS * 30)
                return date > threshold_date
    return None


def get_prediction_single_url(model, url, force_model):
    is_white_listed = False
    valid_url, error = is_valid_url(url)

    if not valid_url:
        return create_dict_context(url, MSG_INVALID_URL + error, {}, SCORE_INVALID_URL, is_white_listed, {})

    # Check domain age from WHOIS command
    domain = extract_domainv2(url)
    res = demisto.executeCommand('whois', {'query': domain,
                                           })
    is_new_domain = extract_created_date(res)

    # Check is domain in white list -  If yes we don't run the model
    if in_white_list(model, url):
        if not force_model:
            return create_dict_context(url, BENIGN_VERDICT_WHITELIST, {}, SCORE_BENIGN, is_white_listed, {})
        else:
            is_white_listed = True
    # sys.exit(0)
    # Rasterize html and image
    res = demisto.executeCommand('rasterize', {'type': 'json',
                                               'url': url,
                                               })
    if len(res) > 0:
        output_rasterize = res[0]['Contents']
    else:
        return_error(MSG_FAILED_RASTERIZE)

    # Create X_pred
    if isinstance(output_rasterize, str):
        return_error(output_rasterize)
    X_pred = create_X_pred(output_rasterize, url)

    pred_json = model.predict(X_pred)

    pred_json[DOMAIN_AGE_KEY] = is_new_domain

    score, verdict = get_verdict(pred_json, is_white_listed)

    return create_dict_context(url, verdict, pred_json, score, is_white_listed, output_rasterize)


def return_general_summary(results, tag="Summary"):
    df_summary = pd.DataFrame()
    df_summary['Url'] = [x.get('url') for x in results]
    df_summary[KEY_FINAL_VERDICT] = [MAPPING_VERDICT_COLOR[x.get('verdict')] % x.get('verdict')
                                     if x.get('verdict') in MAPPING_VERDICT_COLOR.keys()
                                     else VERDICT_ERROR_COLOR % x.get('verdict') for x in results]
    df_summary_json = df_summary.to_dict(orient='records')
    return_entry = {
        "Type": entryTypes["note"],
        "ContentsFormat": formats['json'],
        "HumanReadable": tableToMarkdown("Phishing prediction summary for URLs", df_summary_json,
                                         headers=['Url', KEY_FINAL_VERDICT]),
        "Contents": df_summary_json,
        "EntryContext": {'DBotPredictURLPhishing': df_summary_json}
    }
    if tag is not None:
        return_entry["Tags"] = ['SimilarIncidents_{}'.format(tag)]
    demisto.results(return_entry)
    return df_summary_json


def return_detailed_summary(results, number_entries_to_return):
    outputs = []
    severity_list = [x.get('score') for x in results]
    indice_descending_severity = np.argsort(-np.array(severity_list), kind='mergesort')
    for i in range(min(number_entries_to_return, len(results))):
        index = indice_descending_severity[i]
        pred_json = results[index].get('pred_json')
        url = results[index].get('url')
        is_white_listed = results[index].get('is_white_listed')
        output_rasterize = results[index].get('output_rasterize')
        summary_json = return_entry_summary(pred_json, url, is_white_listed, output_rasterize)
        outputs.append(summary_json)
        outputs = [x for x in outputs if x]
    return outputs


def save_model_in_demisto(model):
    encoded_model = base64.b64encode(dill.dumps(model))
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
        return_error(get_error(res))


def load_demisto_model():
    model_64_str = get_model_data(URL_PHISHING_MODEL_NAME)[0]
    model = decode_model_data(model_64_str)
    return model


def main():
    msg_list = []
    exist, demisto_major_version, demisto_minor_version = oob_model_exists_and_updated()
    reset_model = demisto.args().get('resetModel', 'False') == 'True'
    if exist:
        demisto.results("Model version in demisto: %s.%s" % (demisto_major_version, demisto_minor_version))
    else:
        demisto.results("There is no existing model version in demisto")

    if reset_model or not exist or (
            demisto_major_version < MAJOR_VERSION and demisto_minor_version == MINOR_DEFAULT_VERSION):
        msg_list.append(load_oob_model(OUT_OF_THE_BOX_MODEL_PATH))

    elif (demisto_major_version == MAJOR_VERSION):
        msg_list.append(MSG_NO_ACTION_ON_MODEL)
    elif (demisto_major_version < MAJOR_VERSION) and (demisto_minor_version > MINOR_DEFAULT_VERSION):
        model_docker = load_model_from_docker()
        model_docker_minor = model_docker.minor
        model = load_demisto_model()
        model_docker.logos_dict = model.logos_dict
        model_docker.clf.named_steps.preprocessor.named_transformers_[
            'image'].named_steps.trans.logo_dict = model.logos_dict
        model_docker.minor += 1
        save_model_in_demisto(model_docker)
        msg_list.append(MSG_UPDATE_LOGO)
        demisto.results(MSG_UPDATE_LOGO % (MAJOR_VERSION, model_docker_minor, model.major, model.minor))
    else:
        msg_list.append(MSG_WRONG_CONFIG_MODEL)
        return_error(MSG_WRONG_CONFIG_MODEL)
    model_64_str = get_model_data(URL_PHISHING_MODEL_NAME)[0]
    model = decode_model_data(model_64_str)
    force_model = demisto.args().get('forceModel', 'False') == 'True'
    urls = [x.strip() for x in demisto.args().get('urls', '').split(',') if x]
    if not urls:
        msg_list.append(MSG_NO_URL_GIVEN)
        return_error(MSG_NO_URL_GIVEN)
    number_entries_to_return = int(demisto.args().get('numberDetailedReports'))
    results = [get_prediction_single_url(model, x, force_model) for x in urls]
    general_summary = return_general_summary(results)
    detailed_summary = return_detailed_summary(results, number_entries_to_return)
    return general_summary, detailed_summary, msg_list


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
