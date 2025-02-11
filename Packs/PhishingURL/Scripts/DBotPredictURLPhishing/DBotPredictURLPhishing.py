import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib
import pandas as pd
import base64
import dill
import copy
from tldextract import TLDExtract
from bs4 import BeautifulSoup
from typing import Literal

dill.settings['recurse'] = True

no_fetch_extract = TLDExtract(suffix_list_urls=None, cache_dir=False)  # type: ignore

KEY_IMAGE_RASTERIZE = "image_b64"
KEY_IMAGE_HTML = "html"

MSG_SOMETHING_WRONG_IN_RASTERIZE = "Something went wrong with rasterize"
MSG_ENABLE_WHOIS = "Please enable whois integration for more accurate prediction"
MSG_MODEL_VERSION_IN_DEMISTO = "Model version in demisto: {}.{}"
MSG_NO_MODEL_IN_DEMISTO = "There is no existing model version in demisto"
MSG_NO_URL_GIVEN = "Please input at least one URL"
MSG_FAILED_RASTERIZE = "Rasterize error: ERR_NAME_NOT_RESOLVED"
MSG_FAILED_RASTERIZE_TIMEOUT = "Timeout rasterize"
MSG_IMPOSSIBLE_CONNECTION = "Failed to establish a new connection - Name or service not known"
MSG_UPDATE_MODEL = "Update demisto model from docker model version {}.{}"
MSG_UPDATE_LOGO = "Update demisto model from docker model version {}.{} and transfering logos from demisto version {}.{}"
MSG_WRONG_CONFIG_MODEL = 'Wrong configuration of the model'
MSG_NO_ACTION_ON_MODEL = "Use current model"
MSG_WHITE_LIST = "White List"
MSG_NEED_TO_UPDATE_RASTERIZE = "Please install and/or update rasterize pack"
URL_PHISHING_MODEL_NAME = "url_phishing_model"
OUT_OF_THE_BOX_MODEL_PATH = '/model/model_docker.pkl'
UNKNOWN_MODEL_TYPE = 'UNKNOWN_MODEL_TYPE'
THRESHOLD_NEW_DOMAIN_MONTHS = 6
DOMAIN_AGE_KEY = f'New domain (less than {THRESHOLD_NEW_DOMAIN_MONTHS} months)'

MALICIOUS_VERDICT = "Malicious"
BENIGN_VERDICT = "Benign"
SUSPICIOUS_VERDICT = "Suspicious"
BENIGN_VERDICT_WHITELIST = "Benign - Top domains from Majestic"
UNKNOWN = 'Unknown'

BENIGN_THRESHOLD = 0.5
SUSPICIOUS_THRESHOLD = 0.7

SCORE_INVALID_URL = -1.0
SCORE_BENIGN = 0.0  # type: float

GREEN_COLOR = RED_COLOR = VERDICT_MALICIOUS_COLOR = VERDICT_SUSPICIOUS_COLOR = \
    VERDICT_BENIGN_COLOR = VERDICT_ERROR_COLOR = "**{}**"
MAPPING_VERDICT_COLOR = {MALICIOUS_VERDICT: VERDICT_MALICIOUS_COLOR, BENIGN_VERDICT: VERDICT_BENIGN_COLOR,
                         SUSPICIOUS_VERDICT: VERDICT_SUSPICIOUS_COLOR, BENIGN_VERDICT_WHITELIST: VERDICT_BENIGN_COLOR}

SCORE_THRESHOLD = 0.6  # type: float

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
KEY_HR_SEO = "Search engine optimization"
KEY_HR_LOGIN = "Is there a Login form?"
KEY_HR_LOGO = "Suspicious use of company logo"
KEY_HR_URL_SCORE = "URL severity score (from 0 to 1)"

KEY_CONTENT_SUMMARY_URL = 'URL'
KEY_CONTENT_SUMMARY_FINAL_VERDICT = 'FinalVerdict'

KEY_FINAL_VERDICT = "Final Verdict"

WEIGHT_HEURISTIC = {
    DOMAIN_AGE_KEY: 3, MODEL_KEY_LOGIN_FORM: 1, MODEL_KEY_SEO: 1,
    MODEL_KEY_URL_SCORE: 2, MODEL_KEY_LOGO_FOUND: 1
}

MAPPING_VERDICT_TO_DISPLAY_VERDICT = {
    MODEL_KEY_SEO: {True: RED_COLOR.format('Bad'), False: GREEN_COLOR.format('Good')},
    MODEL_KEY_LOGO_FOUND: {True: RED_COLOR.format('Suspicious'), False: GREEN_COLOR.format('Not Suspicious')},
    MODEL_KEY_LOGIN_FORM: {True: RED_COLOR.format('Yes'), False: GREEN_COLOR.format('No')},
    DOMAIN_AGE_KEY: {True: RED_COLOR.format('Less than 6 months ago'), False: GREEN_COLOR.format('More than 6 months ago'),
                     None: None}
}  # type: Dict

VERDICT_TO_INT = {
    MALICIOUS_VERDICT: 3,
    BENIGN_VERDICT: 1,
    BENIGN_VERDICT_WHITELIST: 1,
    SUSPICIOUS_VERDICT: 2
}

WAIT_TIME_RASTERIZE = 5
TIMEOUT_RASTERIZE = 120


class Model:
    '''Abstract class that represents the class of the built-in phishing model.'''

    clf: Any  # sklearn.pipeline.Pipeline
    df_voc: dict
    top_domains: dict
    logos_dict: dict
    custom_logo_associated_domain: dict

    def predict(self, x_pred: pd.DataFrame) -> dict:
        ...

    def update_model(
        self,
        top_domains: dict,
        logos_dict: dict,
        custom_logo_associated_domain: dict,
    ):
        ...


class ModelData(dict[Literal['top_domains', 'logos_dict', 'custom_logo_associated_domain'], dict]):
    '''Abstract class that represents the format of the data stored in the server.'''


def delete_model():
    res = demisto.executeCommand('deleteMLModel', {'modelName': URL_PHISHING_MODEL_NAME})
    demisto.debug(f'Deleted model. server response: {res}')


def save_model_data(model_data: ModelData):
    """
    Load and save model from the model in the docker
    :return: None
    """
    res = demisto.executeCommand(
        'createMLModel',
        {
            'modelData': b64encode_string(json.dumps(model_data)),
            'modelName': URL_PHISHING_MODEL_NAME,
            'modelLabels': [MALICIOUS_VERDICT, BENIGN_VERDICT, SUSPICIOUS_VERDICT],
            'modelOverride': 'true',
            'modelHidden': True,
            'modelType': 'url_phishing',
            'modelExtraInfo': {}
        }
    )
    if is_error(res):
        raise DemistoException(get_error(res))


def extract_and_save_old_model_data(model_data: str, minor_version: int) -> Optional[ModelData]:
    '''Update the model to the new version. This will be eventually deleted.'''
    if minor_version == 0:  # no changes were made to the model by the user
        demisto.debug('Old version is unchanged, deleting')
        delete_model()
        return None

    import warnings
    warnings.filterwarnings("ignore", module='sklearn')

    old_import = dill._dill._import_module
    dill._dill._import_module = lambda x, safe=False: old_import(x, safe=True)
    model = cast(Model, dill.loads(base64_to_bytes(model_data)))
    dill._dill._import_module = old_import

    model_data = cast(ModelData, {
        'top_domains': model.top_domains,
        'logos_dict': model.logos_dict,
        'custom_logo_associated_domain': model.custom_logo_associated_domain,
    })
    save_model_data(model_data)
    return model_data


def get_model_data() -> Optional[ModelData]:
    res = demisto.executeCommand("getMLModel", {"modelName": URL_PHISHING_MODEL_NAME})[0]
    if is_error(res):
        demisto.debug(f'Model not found: {get_error(res)}')
        return None

    extra_data = dict_safe_get(res, ('Contents', 'model', 'extra'))
    model_data = dict_safe_get(res, ('Contents', 'modelData'))

    if isinstance(extra_data, dict) and 'minor' in extra_data:  # this means the old model exists as a pickled object
        demisto.debug(f'Old model found. {extra_data=}')
        return extract_and_save_old_model_data(model_data, extra_data['minor'])
    return cast(ModelData, json.loads(b64decode_string(model_data)))


def load_model_from_docker(path: str = OUT_OF_THE_BOX_MODEL_PATH) -> Model:
    with open(path, 'rb') as f:
        return cast(Model, dill.load(f))  # guardrails-disable-line


def load_model() -> Model:
    model = load_model_from_docker()
    model_data = get_model_data()
    if model_data:
        model.update_model(**model_data)  # type: ignore[misc]
    return model


def b64encode_string(string: str) -> str:
    return base64.b64encode(string.encode()).decode()


def b64decode_string(string: str) -> str:
    return base64_to_bytes(string).decode()


def base64_to_bytes(base64_string: str) -> bytes:
    """
    Transform a base64 string into bytes
    :param base64_string:
    :return:
    """
    return base64.b64decode(base64_string.encode())


def extract_domainv2(url: str) -> str:
    ext = no_fetch_extract(url)
    return ext.domain + "." + ext.suffix


def in_white_list(model: Model, url: str) -> bool:
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
    return copy.deepcopy(pred_json) | {
        MODEL_KEY_SEO: MAPPING_VERDICT_TO_DISPLAY_VERDICT[MODEL_KEY_SEO][pred_json[MODEL_KEY_SEO]],
        MODEL_KEY_LOGO_FOUND: MAPPING_VERDICT_TO_DISPLAY_VERDICT[MODEL_KEY_LOGO_FOUND][pred_json[MODEL_KEY_LOGO_FOUND]],
        MODEL_KEY_LOGIN_FORM: MAPPING_VERDICT_TO_DISPLAY_VERDICT[MODEL_KEY_LOGIN_FORM][pred_json[MODEL_KEY_LOGIN_FORM]],
        DOMAIN_AGE_KEY: MAPPING_VERDICT_TO_DISPLAY_VERDICT[DOMAIN_AGE_KEY][pred_json[DOMAIN_AGE_KEY]],
    }


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


def return_entry_summary(
    pred_json: dict, url: str, is_white_listed: bool, output_rasterize: dict,
    verdict: str, reliability: str = DBotScoreReliability.A_PLUS, **_
) -> Optional[dict[str, Any]]:
    """
    Return entry to demisto
    :param pred_json: json with output of the model
    :param url: url
    :param whitelist: if url belongs to whitelist of the model
    :param reliability: reliability of the source providing the intelligence data.
    :return: entry to demisto
    """
    if is_white_listed:
        return None
    if verdict == BENIGN_VERDICT_WHITELIST:
        verdict = BENIGN_VERDICT
    if not pred_json:
        url_score = SCORE_BENIGN
        url_score_colored = (GREEN_COLOR if url_score < SCORE_THRESHOLD else RED_COLOR).format(url_score)
    else:
        url_score = round(pred_json[MODEL_KEY_URL_SCORE], 2)
        url_score_colored = (GREEN_COLOR if url_score < SCORE_THRESHOLD else RED_COLOR).format(url_score)
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
        KEY_CONTENT_IS_WHITELISTED: str(is_white_listed)
    }
    dbot_score = Common.DBotScore(indicator=url,
                                  indicator_type=DBotScoreType.URL,
                                  integration_name='DBotPhishingURL',
                                  score=VERDICT_TO_INT.get(verdict),
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
            "HumanReadable": tableToMarkdown(f"Phishing prediction evidence | {domain}", explain_hr),
            "Contents": explain,
            "EntryContext": {'DBotPredictURLPhishing': explain}
        }
    else:
        return_entry = {
            "Type": entryTypes["note"],
            "ContentsFormat": formats['json'],
            "HumanReadable": tableToMarkdown(f"Phishing prediction evidence | {domain}", explain_hr),
            "Contents": explain,
            "EntryContext": {'DBotPredictURLPhishing': explain, KEY_CONTENT_DBOT_SCORE: context_DBot_score},
            "Tags": ['DBOT_URL_PHISHING_MALICIOUS']
        }
    return_results(return_entry)
    # Get rasterize image or logo detection if logo was found
    if pred_json:
        image = pred_json[MODEL_KEY_LOGO_IMAGE_BYTES]
        if not image:
            image = base64_to_bytes(output_rasterize.get(KEY_IMAGE_RASTERIZE))  # type: ignore[arg-type]
        res = fileResult(filename='Logo detection engine', data=image)
        res['Type'] = entryTypes['image']
        if pred_json[MODEL_KEY_LOGO_FOUND]:
            res["Tags"] = ['DBOT_URL_PHISHING_MALICIOUS']
        return_results(res)
    return explain


def return_entry_white_list(url: str):
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


def get_score(pred_json: dict) -> int:
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
    if score < BENIGN_THRESHOLD:
        return score, BENIGN_VERDICT
    if score < SUSPICIOUS_THRESHOLD:
        return score, SUSPICIOUS_VERDICT
    return score, MALICIOUS_VERDICT


def create_dict_context(url, verdict, pred_json, score, is_white_listed, output_rasterize) -> dict:
    return {
        'url_redirect': url, 'url': url, 'verdict': verdict, 'pred_json': pred_json,
        'score': score, 'is_white_listed': is_white_listed, 'output_rasterize': output_rasterize
    }


def extract_created_date(entry: dict) -> Union[bool, None]:
    """
    Check if domain age is younger than THRESHOLD_NEW_DOMAIN_YEAR year
    :param entry_list: output of the whois command
    :return: bool
    """
    if not is_error(entry):
        date_str = dict_safe_get(entry, ('EntryContext', 'Domain(val.Name && val.Name == obj.Name)', 'WHOIS', 'CreationDate'))
        if date_str:
            date = datetime.strptime(date_str, '%d-%m-%Y')
            threshold_date = datetime.now() - timedelta(days=THRESHOLD_NEW_DOMAIN_MONTHS * 30)
            return date > threshold_date
    return None


def return_and_remove_additional_results(results: list, from_index: int):
    '''Return and remove the extra unneeded results returned from a command call.
    In XSOAR 8 log results are usually returned with sub-commands if debug-mode=true'''
    if results[from_index:]:
        return_results(results[from_index:])
        del results[from_index:]
        demisto.debug(f'removed and returned {from_index} outputs')


def weed_rasterize_errors(urls: list[str], res_rasterize: list[Union[dict, str]]):
    '''Remove the URLs that failed rasterization and return them.'''
    error_idx = [
        i for (i, res) in enumerate(res_rasterize)
        if not isinstance(res, dict)
    ][::-1]  # reverse the list as it will be used to remove elements.
    if error_idx:
        return_results(CommandResults(readable_output=tableToMarkdown(
            'The following URLs failed rasterize and were skipped:',
            [{'URL': urls.pop(i), 'Message': res_rasterize.pop(i)} for i in error_idx],
            ['URL', 'Message']
        )))


def rasterize_command(urls: Union[list[str], str], rasterize_timeout: int) -> list[Union[dict, str]]:
    res_rasterize: list[dict] = demisto.executeCommand(  # type: ignore
        'rasterize',
        {
            'type': 'json',
            'url': urls,
            'wait_time': WAIT_TIME_RASTERIZE,
            'execution-timeout': rasterize_timeout
        }
    )
    demisto.debug(f'Rasterize Data: {res_rasterize}')
    return_and_remove_additional_results(res_rasterize, len(urls) if isinstance(urls, list) else 1)
    return [res['Contents'] or res['HumanReadable'] for res in res_rasterize]


def rasterize_urls(urls: list[str], rasterize_timeout: int) -> list[dict]:
    urls = [url.removeprefix('http://') for url in urls]
    res_rasterize = rasterize_command(urls, rasterize_timeout)
    if len(res_rasterize) < len(urls):  # check for errors in the response
        demisto.info(f'Rasterize response is too short, running command for each URL\n{res_rasterize=}\n{urls=}')
        rasterize_runs = map(rasterize_command, urls, [rasterize_timeout] * len(urls))
        res_rasterize = sum(rasterize_runs, [])
    weed_rasterize_errors(urls, res_rasterize)
    return cast(list[dict], res_rasterize)


def get_whois_verdict(domains: list[str]) -> list:
    '''Check domain age from WHOIS command'''
    default = [None] * len(domains)
    if isCommandAvailable('whois'):
        try:
            res = demisto.executeCommand('whois', {'query': domains, 'execution-timeout': 5})
            return_and_remove_additional_results(res, len(domains))
            return res or default
        except Exception as e:
            demisto.debug(str(e))
    else:
        return_results(MSG_ENABLE_WHOIS)
    return default


def get_predictions_for_urls(
    model: Model, urls: list[str], force_model: bool, debug: bool, rasterize_timeout: int, protocol: str
) -> Optional[list[dict]]:

    domains = list(map(extract_domainv2, urls))

    rasterize_outputs = rasterize_urls(urls, rasterize_timeout)

    if not rasterize_outputs:
        return_results('All URLs failed to be rasterized. Skipping prediction.')
        return None

    whois_results = get_whois_verdict(domains)

    results = []
    for url, res_whois, output_rasterize in zip(urls, whois_results, rasterize_outputs):

        # Check is domain in white list -  If yes we don't run the model
        if in_white_list(model, url):
            is_white_listed = True
            if not force_model:
                results.append(create_dict_context(
                    url, BENIGN_VERDICT_WHITELIST,
                    {}, SCORE_BENIGN, is_white_listed, {}
                ))
                continue
        else:
            is_white_listed = False

        x_pred = create_x_pred(
            output_rasterize,
            prepend_protocol(url, protocol)
        )

        pred_json = model.predict(x_pred)
        if debug:
            return_results(pred_json['debug_top_words'])
            return_results(pred_json['debug_found_domains_list'])
            return_results(pred_json['seo'])
            return_results(pred_json['debug_image'])

        pred_json[DOMAIN_AGE_KEY] = extract_created_date(res_whois)

        score, verdict = get_verdict(pred_json, is_white_listed)
        results.append(create_dict_context(url, verdict, pred_json, score, is_white_listed, output_rasterize))
    return results


def return_general_summary(results: list[dict], tag: str = "Summary") -> list[dict]:
    df_summary = pd.DataFrame()
    df_summary['URL'] = [x.get('url_redirect') for x in results]
    df_summary[KEY_FINAL_VERDICT] = [MAPPING_VERDICT_COLOR.get(
        x.get('verdict'), VERDICT_ERROR_COLOR).format(x.get('verdict')) for x in results]  # type: ignore
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


def return_detailed_summary(results: list, reliability: str) -> list[dict[str, str]]:
    outputs = []
    results.sort(key=lambda x: x['score'])
    for result in results:
        if result.get('score') == SCORE_INVALID_URL:
            continue
        summary_json = return_entry_summary(**result, reliability=reliability)
        if summary_json:
            outputs.append(summary_json)
    return outputs


def extract_urls(text: str) -> list[str]:
    res = demisto.executeCommand("extractIndicators", {"text": text})
    if is_error(res):
        raise DemistoException(get_error(res))
    return list(set(json.loads(res[0]["Contents"]).get("URL", [])))


def get_final_urls(urls: list[str], max_urls: int, model: Model) -> list[str]:
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
        final_url += low_priority_urls[:min(len(low_priority_urls), max_urls - len(final_url))]
    return final_url


def extract_embedded_urls_from_html(html: str) -> list[str]:
    embedded_urls = []
    soup = BeautifulSoup(html)
    for a in soup.findAll('a'):
        if a.has_attr('href') and a['href'] not in a.get_text():
            embedded_urls.append(a['href'])
    return embedded_urls


def get_urls_to_run(
    email_body: str, email_html: str, urls_argument: Union[list, str],
    max_urls: int, model: Model, msg_list: list[str], debug: bool
) -> tuple[list[str], list[str]]:
    if email_body:
        urls_email_body = extract_urls(email_body)
    else:
        if email_html:
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
        urls_only = urls_argument.split()
    urls = list(set(urls_email_body + urls_only + urls_email_html))

    # create a list with all the paths that start with "mailto:"
    mailto_urls = [url for url in urls if url.startswith("mailto:")]

    # remove the mailto urls from urls list
    urls = [item for item in urls if item not in mailto_urls]

    if mailto_urls:
        return_results(CommandResults(
            readable_output=f'URLs that start with "mailto:" cannot be rasterized.\nURL: {mailto_urls}'))

    if not urls:
        msg_list.append(MSG_NO_URL_GIVEN)
        return_results(MSG_NO_URL_GIVEN)
        return [], msg_list
    urls = get_final_urls(urls, max_urls, model)
    urls = [res['Contents'] for res in demisto.executeCommand("UnEscapeURLs", {"input": urls})]  # type: ignore
    if debug:
        return_results(urls)
    return urls, msg_list


def main():
    msg_list: list = []
    try:
        args = demisto.args()
        reset_model = args.get('resetModel') == 'True'
        debug = args.get('debug') == 'True'
        force_model = args.get('forceModel') == 'True'
        email_body = args.get('emailBody', "")
        email_html = args.get('emailHTML', "")
        max_urls = arg_to_number(args.get('maxNumberOfURL')) or 5
        urls_argument = args.get('urls', '')
        rasterize_timeout = arg_to_number(args.get('rasterize_timeout', TIMEOUT_RASTERIZE)) or 0
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(
            args.get("reliability", DBotScoreReliability.A_PLUS)
        )
        protocol = demisto.args().get('defaultRequestProtocol', 'HTTP').lower()

        if reset_model:
            delete_model()

        model = load_model()

        # Get all the URLs on which we will run the model
        urls, msg_list = get_urls_to_run(email_body, email_html, urls_argument, max_urls, model, msg_list, debug)

        if urls:
            # Run the model and get predictions
            results = get_predictions_for_urls(model, urls, force_model, debug, rasterize_timeout, protocol)
            if results:
                general_summary = return_general_summary(results)
                detailed_summary = return_detailed_summary(results, reliability)
                if debug:
                    return_results(msg_list)
                return general_summary, detailed_summary, msg_list

    except Exception as e:
        return_error(f'Failed to execute URL Phishing script. Error: {e}')

    finally:
        demisto.debug(f'{msg_list=}')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
