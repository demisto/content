import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from urllib.parse import urlparse
import urllib.parse
from tldextract import extract
from typing import Type, Tuple, List, Dict
import dill
dill.settings['recurse'] = True
import pandas as pd
import base64
import requests
import math

MSG_INVALID_URL = "URL does not seem to be valid. Reason: "
MSG_NO_URL_GIVEN = "Please input one URL"
MSG_FAILED_RASTERIZE = "Rasterize for this url did not work correctly"
MSG_IMPOSSIBLE_CONNECTION = "Failed to establish a new connection - Name or service not known"
MSG_WHITE_LIST = "White List"
EMPTY_STRING = ""
URL_PHISHING_MODEL_NAME = "phishing_model"
OUT_OF_THE_BOX_MODEL_PATH = '/ml/encrypted_model.b'
SCRIPT_MODEL_VERSION = '0.0'
OOB_VERSION_INFO_KEY = 'oob_version'


MALICIOUS_VERDICT = "malicious"
BENIGN_VERDICT = "benign"

STATUS_CODE_VALID = 200


def load_oob_model():
    try:
        encoded_model = load_oob(OUT_OF_THE_BOX_MODEL_PATH)
    except Exception:
        return_error(traceback.format_exc())
    res = demisto.executeCommand('createMLModel', {'modelData': encoded_model.decode('utf8'),
                                                   'modelName': URL_PHISHING_MODEL_NAME,
                                                   'modelLabels': [MALICIOUS_VERDICT, BENIGN_VERDICT],
                                                   'modelOverride': 'true',
                                                   'modelType': 'url_phishing',
                                                   'modelExtraInfo': {
                                                                    OOB_VERSION_INFO_KEY: SCRIPT_MODEL_VERSION
                                                                      }
                                                   })
    if is_error(res):
        return_error(get_error(res))


def oob_model_exists_and_updated():
    res_model = demisto.executeCommand("getMLModel", {"modelName": URL_PHISHING_MODEL_NAME})[0]
    if is_error(res_model):
        return False
    existing_model_version = res_model['Contents']['model']['extra'].get(OOB_VERSION_INFO_KEY, -1)
    return existing_model_version == SCRIPT_MODEL_VERSION



def image_from_base64_to_bytes(base64_message):
    base64_bytes = base64_message.encode('utf-8')
    message_bytes = base64.b64decode(base64_bytes)
    return message_bytes


def extract_domainv2(url: str):
    """
    Return domain (SLD + TLD)
    :param url: URL from which to extract domain name
    :return:str
    """
    parts = extract(url)
    return parts.domain + "." + parts.suffix

def in_white_list(model, url):
    if (extract_domainv2(url)  in model.top_domains):
        return True
    else:
        return False

def create_X_pred(output_rasterize, url):
    website64 = output_rasterize.get('image_b64', None)
    html = output_rasterize.get('html', None)
    X_pred = pd.DataFrame(columns=['name', 'image', 'html'])
    X_pred.loc[0] = [url, website64, html]
    return X_pred

def prepend_protocol(url: str, protocol: str, www: bool=True) -> str:
    """
    Append a protocol name (usually http or https) and www to a url
    :param url: url
    :param protocol: protocol we want to add (usually http or https)
    :return: str
    """
    p = urllib.parse.urlparse(url, protocol)
    netloc = p.netloc or p.path
    path = p.path if p.netloc else ''
    if not netloc.startswith('www.') and www:
        netloc = 'www.' + netloc
    p = urllib.parse.ParseResult(protocol, netloc, path, *p[3:])
    return p.geturl()


def is_valid_url(url):
    try:
        response = requests.get(url, verify=False)
    except requests.exceptions.RequestException as e:
        prepend_url = prepend_protocol(url, 'http', True)
        try:
            response = requests.get(prepend_url, verify=False)
        except requests.exceptions.RequestException as e:
            prepend_url = prepend_protocol(url, 'https', True)
            try:
                response = requests.get(prepend_url, verify=False)
            except requests.exceptions.RequestException as e:
                prepend_url = prepend_protocol(url, 'http', False)
                try:
                    response = requests.get(prepend_url, verify=False)
                except requests.exceptions.RequestException as e:
                    prepend_url = prepend_protocol(url, 'https', False)
                    try:
                        response = requests.get(prepend_url, verify=False)
                    except requests.exceptions.RequestException as e:
                        return False, MSG_IMPOSSIBLE_CONNECTION
    if response.status_code == 200:
        return True, EMPTY_STRING
    else:
        return False, response.reason


def return_entry_summary(pred_json, url, verdict, whitelist):
    if whitelist:
        verdict = BENIGN_VERDICT
        url_score = '0'
    else:
        url_score = str(pred_json['url_score'])
    explain = {
            "Domain": extract_domainv2(url),
            "URL": url,
            "LogoFound": str(pred_json['logo_found']),
            "LoginForm": str(pred_json['login_form']),
            "URLScore": url_score,
            "ContentBasedVerdict":  str(pred_json['seo'])
    }
    explain_hr = {
            "{{color:#fd0800}}(Domain from the URL)": extract_domainv2(url),
            "Has the domain bad SEO ?": str(pred_json['seo']),
            "Has the website a login form?": str(pred_json['login_form']),
            "Logo found that does not correspond to the given domain": str(pred_json['logo_found']),
            "URL severity score (from 0 to 1)": url_score
    }
    verdict__hr = {
        "Verdict": verdict,
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


def return_entry_white_list(url):
    explain = {
        "Domain": extract_domainv2(url),
        "URL": url,
        "LogoFound": MSG_WHITE_LIST,
        "LoginPage": MSG_WHITE_LIST,
        "URLScore": MSG_WHITE_LIST,
        "ContentBasedVerdict": MSG_WHITE_LIST
    }
    explain_hr = {
        "Domain": extract_domainv2(url),
        "Has the domain good SEO ?": MSG_WHITE_LIST,
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

def get_verdict(pred):
    return "Malicious"


def main():
    whitelist = False
    model = dill.load(open('/model/model_docker.pkl', 'rb'))
    url = demisto.args().get('url', None)
    force_model = bool(demisto.args().get('forceModel', 'False'))
    if not url:
        return_error(MSG_NO_URL_GIVEN)


    # Check if URL is valid and accessible
    valid_url, error = is_valid_url(url)
    if not valid_url:
        return_error(MSG_INVALID_URL + error)

    # Check is domain in white list -  If yes we don't run the model
    if in_white_list(model, url):
        if not force_model:
            return_entry_white_list(url)
            return
        else:
            whitelist = True

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

    # Prediction of the model
    pred_json = model.predict(X_pred)

    verdict = get_verdict(pred_json)

    # Return entry of the script
    return_entry_summary(pred_json, url, verdict, whitelist)

    # Get rasterize image or logo detection if logo was found
    image = pred_json['image_bytes']
    if not image:
        image = image_from_base64_to_bytes(output_rasterize.get('image_b64', None))
    res = fileResult(filename='Logo detection engine', data=image)
    res['Type'] = entryTypes['image']
    demisto.results(res)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
