import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import cv2 as cv
import re
from urllib.parse import urlparse
from collections import Counter
import numpy as np
from itertools import islice
from bs4 import BeautifulSoup
import urllib.parse
import math
from tldextract import extract
from typing import Type, Tuple, List, Dict
import pickle
import dill
dill.settings['recurse'] = True

from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.base import BaseEstimator, TransformerMixin
from urllib.parse import urlparse
import glob
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV
import pandas as pd
import base64
import requests

MSG_INVALID_URL = "URL does not seem to be valid. Reason: "
MSG_NO_URL_GIVEN = "Please input one URL"
MSG_FAILED_RASTERIZE = "Rasterize for this url did not work correctly"
EMPTY_STRING = ""
STATUS_CODE_VALID = 200


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

def prepend_protocol(url: str, protocol: str) -> str:
    """
    Append a protocol name (usually http or https) and www to a url
    :param url: url
    :param protocol: protocol we want to add (usually http or https)
    :return: str
    """
    p = urllib.parse.urlparse(url, protocol)
    netloc = p.netloc or p.path
    path = p.path if p.netloc else ''
    if not netloc.startswith('www.'):
        netloc = 'www.' + netloc
    p = urllib.parse.ParseResult(protocol, netloc, path, *p[3:])
    return p.geturl()


def is_valid_url(url):
    prepend_url = prepend_protocol(url, 'http')
    response = requests.get('https://google.com', verify=False)
    if response.status_code == STATUS_CODE_VALID:
        return True, EMPTY_STRING
    else:
        return False, response.reason


def return_entry_summary(pred, url, verdict):
    pred_df = pd.DataFrame(pred).fillna('')
    explain = {
            "Domain": extract_domainv2(url),
            "URL": url,
            "LogoFound": str(pred_df.iloc[0, 3]),
            "LoginPage": str(pred_df.iloc[0, 1]),
            "URLScore": str(pred_df.iloc[0, 4]),
            "ContentBasedVerdict":  str(pred_df.iloc[0, 0])
    }
    explain_hr = {
            "Domain from the URL": extract_domainv2(url),
            "Has the domain good SEO ?": str(pred_df.iloc[0, 0]),
            "Has the website a login page?": str(pred_df.iloc[0, 1]),
            "Logo found that does not correspond to the given domain": str(pred_df.iloc[0, 3]),
            "URL severity score (from 0 to 1)": str(pred_df.iloc[0, 4])
    }
    verdict_hr = {
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


def return_entry_white_list():
    pass

def get_verdict(pred):
    return "Malicious"


def main():
    model = dill.load(open('/model/model_docker.pkl', 'rb'))
    global_msg = []
    url = demisto.args().get('url', None)
    if not url:
        return_error(MSG_NO_URL_GIVEN)

    valid_url, error = is_valid_url(url)
    if not valid_url:
        return_error(MSG_INVALID_URL + error)

    # Check is domain in white list -  If yes we don't run the model
    if in_white_list(model, url):
        return_entry_white_list(url)

    res = demisto.executeCommand('rasterize', {'type': 'json',
                                               'url': url,
                                               })

    # Check if rasterize return some outputs
    if len(res) > 0:
        output_rasterize = res[0]['Contents']
    else:
        return_error(MSG_FAILED_RASTERIZE)


    # Create X_pred
    X_pred = create_X_pred(output_rasterize, url)

    # Get rasterize image or logo detection if logo was found
    output = image_from_base64_to_bytes(output_rasterize.get('image_b64', None))
    res = fileResult(filename='image', data=output)
    res['Type'] = entryTypes['image']
    #demisto.results(res)


    # Prediction of the model
    pred = model.clf.transform(X_pred)

    verdict = get_verdict(pred)

    # Return entry of the script
    return_entry_summary(pred, url, verdict)





if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
