import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import dill

# remove patch version 0,0

MAJOR_VERSION = 1
MINOR_DEFAULT_VERSION = 0

URL_PHISHING_MODEL_NAME = "url_phishing_model"
MSG_EMPTY_NAME_OR_URL = "Empty logo name or logo image ID"
OOB_VERSION_INFO_KEY = 'oob_version'
OOB_MAJOR_VERSION_INFO_KEY = 'major'
OOB_MINOR_VERSION_INFO_KEY = 'minor'
OUT_OF_THE_BOX_MODEL_PATH = '/model/model_docker.pkl'
MALICIOUS_VERDICT = "malicious"
BENIGN_VERDICT = "benign"
SUSPICIOUS_VERDICT = "suspicious"

MSG_WRONG_CONFIGURATION = "Wrong configuration of the model"
MSG_SAVE_MODEL_IN_DEMISTO = "Saved model version %s.%s"
MSG_TRANSFER_LOGO = "Transfer logo from demisto model into new docker model"
MSG_ERROR_READING_MODEL = "Error reading model %s from Demisto"
MSG_NEED_TO_KNOW_WHICH_ACTION = "Need to choose one of the action: Add/Remove logo"
UNKNOWN_MODEL_TYPE = 'UNKNOWN_MODEL_TYPE'

KEY_ADD_LOGO = 'AddLogo'

def get_minor_version_upgrade(model):
    model.minor = model.minor + 1
    return model.minor, model


def load_oob_model_from_model64(encoded_model, major, minor):
    """
    Save model in demisto
    :param encoded_model: model base64
    :param major:  major version
    :param minor: minor version
    :return: msg
    """
    res = demisto.executeCommand('createMLModel', {'modelData': encoded_model.decode('utf-8'),
                                                   'modelName': URL_PHISHING_MODEL_NAME,
                                                   'modelLabels': [MALICIOUS_VERDICT, BENIGN_VERDICT],
                                                   'modelOverride': 'true',
                                                   'modelHidden': True,
                                                   'modelType': 'url_phishing',
                                                   'modelExtraInfo': {
                                                       OOB_MAJOR_VERSION_INFO_KEY: major,
                                                       OOB_MINOR_VERSION_INFO_KEY: minor
    }})
    if is_error(res):
        return_error(get_error(res))
    return MSG_SAVE_MODEL_IN_DEMISTO % (str(major), str(minor))


def save_upgraded_version_model(model):
    """
    Encode base 64 the model and call load_oob_model_from_model64
    :param model: URL Phishing model
    :return: msg
    """
    model_bytes = dill.dumps(model)  # guardrails-disable-line
    model_64 = base64.b64encode(model_bytes)
    msg = load_oob_model_from_model64(model_64, model.major, model.minor)
    return msg


def get_model_data(model_name: str):
    """
    Return model data saved in demisto (string of encoded base 64)
    :param model_name: name of the model to load from demisto
    :return: str, str
    """
    res_model = demisto.executeCommand("getMLModel", {"modelName": model_name})[0]
    if is_error(res_model):
        return_error(MSG_ERROR_READING_MODEL % model_name)
    else:
        model_data = res_model['Contents']['modelData']
        try:
            model_type = res_model['Contents']['model']["type"]["type"]
            return model_data, model_type
        except Exception:
            return model_data, UNKNOWN_MODEL_TYPE


def oob_model_exists_and_updated():
    """
    Check is the model exist and is updated in demisto
    :return: bool, int, int
    """
    res_model = demisto.executeCommand("getMLModel", {"modelName": URL_PHISHING_MODEL_NAME})[0]
    if is_error(res_model):
        return False, -1, -1
    existing_model_version_major = res_model['Contents']['model']['extra'].get(OOB_MAJOR_VERSION_INFO_KEY, -1)
    existing_model_version_minor = res_model['Contents']['model']['extra'].get(OOB_MINOR_VERSION_INFO_KEY, -1)
    return True, existing_model_version_major, existing_model_version_minor


def load_demisto_model():
    """
    Load base64 demisto model and decode it
    :return: URL Phishing model
    """
    model_64_str = get_model_data(URL_PHISHING_MODEL_NAME)[0]
    model = decode_model_data(model_64_str)
    return model


def decode_model_data(model_data: str):
    """
    Decode the base 64 version of the model
    :param model_data: string of the encoded based 64 model
    :return: URL Phishing model
    """
    return dill.loads(base64.b64decode(model_data.encode('utf-8')))  # guardrails-disable-line


def load_model_from_docker(path=OUT_OF_THE_BOX_MODEL_PATH):
    """
    Load model from docker
    :param path: path of the model in the docker
    :return: URL Phishing model
    """
    model = dill.load(open(path, 'rb'))  # guardrails-disable-line
    return model

def image_from_base64_to_bytes(base64_message: str):
    """
    Transform image from base64 string into bytes
    :param base64_message:
    :return:
    """
    base64_bytes = base64_message.encode('utf-8')
    message_bytes = base64.b64decode(base64_bytes)
    return message_bytes


def display_all_logos(model):
    demisto.results(model.custom_logo_associated_domain)
    demisto.results(model.logos_dict)
    for name, logo in model.logos_dict.items():
        custom_associated_logo = model.custom_logo_associated_domain.get(name, '')
        if name in model.custom_logo_associated_domain.keys():
            description = 'Custom Logo with name %s is associated with domains: %s' %(name, ','.join(custom_associated_logo))
        else:
            description = 'This logo is not custom and cannot be changed'
        filename = "Logo name: %s" %name
        res = fileResult(filename=filename, data=image_from_base64_to_bytes(logo))
        res['Type'] = entryTypes['image']
        return_results(res)
        demisto.results(description)


def main():
    msg_list = []
    logo_image_id = demisto.args().get('logo_image_id', '')
    logo_name = demisto.args().get('logoName', '')
    debug = demisto.args().get('debug', 'False') == 'True'
    display_logos = demisto.args().get('displayLogos', 'False') == 'True'
    associated_domains = demisto.args().get('associatedDomains', '').split(',')
    action = demisto.args().get('action', None)

    if not action and not display_logos:
        demisto.results(MSG_NEED_TO_KNOW_WHICH_ACTION)
        return

    if display_logos:
        exist, _, _ = oob_model_exists_and_updated()
        if exist:
            model = load_demisto_model()
        else:
            model = load_model_from_docker()
        display_all_logos(model)
        return

    if not logo_image_id or not logo_name:
        return_error(MSG_EMPTY_NAME_OR_URL)

    res = demisto.getFilePath(logo_image_id)
    path = res['path']
    with open(path, 'rb') as file:
        logo_content = file.read()

    exist, demisto_major_version, demisto_minor_version = oob_model_exists_and_updated()

    # Case 1: model in demisto does not exist OR new major released but no logo were added -> load from docker
    if not exist or (demisto_major_version < MAJOR_VERSION and demisto_minor_version == MINOR_DEFAULT_VERSION):
        model = load_model_from_docker()
        if action == KEY_ADD_LOGO:
            success, msg = model.add_new_logo(logo_name, logo_content, associated_domains)
        else:
            success, msg = model.remove_logo(logo_name)
        msg_list.append(msg)
        if success:
            minor, model = get_minor_version_upgrade(model)
            msg = save_upgraded_version_model(model)
            msg_list.append(msg)
        else:
            return_error(msg)

    # Case where there were new new model release -> load model from demisto
    elif (demisto_major_version == MAJOR_VERSION):
        model = load_demisto_model()
        if action == KEY_ADD_LOGO:
            success, msg = model.add_new_logo(logo_name, logo_content, associated_domains)
        else:
            success, msg = model.remove_logo(logo_name)
        msg_list.append(msg)
        if success:
            minor, model = get_minor_version_upgrade(model)
            msg = save_upgraded_version_model(model)
            msg_list.append(msg)
        else:
            return_error(msg)

    # Case where new model release and logo were added -> transfer logo from model in demisto to new model in docker
    elif (demisto_major_version < MAJOR_VERSION) and (demisto_minor_version > MINOR_DEFAULT_VERSION):
        model_docker = load_model_from_docker()
        model_demisto = load_demisto_model()
        model_docker.logos_dict = model_demisto.logos_dict
        model_docker.custom_logo_associated_domain = model_demisto.custom_logo_associated_domain
        model_docker.top_domains = model_demisto.top_domains
        msg_list.append(MSG_TRANSFER_LOGO)
        if action == KEY_ADD_LOGO:
            success, msg = model_docker.add_new_logo(logo_name, logo_content, associated_domains)
        else:
            success, msg = model_docker.remove_logo(logo_name)
        msg_list.append(msg)
        if success:
            model_docker.minor = demisto_minor_version
            minor, model_docker = get_minor_version_upgrade(model_docker)
            msg = save_upgraded_version_model(model_docker)
            msg_list.append(msg)
        else:
            return_error(msg)
            msg_list.append(msg)

    else:
        msg_list.append(MSG_WRONG_CONFIGURATION)
        return_error(MSG_WRONG_CONFIGURATION)
    if debug:
        demisto.results(msg_list)
    return msg_list


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
