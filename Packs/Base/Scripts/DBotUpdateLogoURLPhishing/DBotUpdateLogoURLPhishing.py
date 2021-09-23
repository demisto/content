import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import dill

# remove patch version 0,0

MAJOR_VERSION = 3

URL_PHISHING_MODEL_NAME = "phishing_model"
MSG_EMPTY_NAME_OR_URL = "Empty logo name or URL"
MINOR_DEFAULT_VERSION = 0
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
UNKNOWN_MODEL_TYPE = 'UNKNOWN_MODEL_TYPE'


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


def main():
    msg_list = []
    logo_url = demisto.args().get('logoImageURL', '')
    logo_name = demisto.args().get('logoName', '')

    if not logo_url or not logo_name:
        return_error(MSG_EMPTY_NAME_OR_URL)

    exist, demisto_major_version, demisto_minor_version = oob_model_exists_and_updated()

    if not exist or (demisto_major_version < MAJOR_VERSION and demisto_minor_version == MINOR_DEFAULT_VERSION):
        model = load_model_from_docker()
        success, msg = model.add_new_logo(logo_name, logo_url)
        msg_list.append(msg)
        if success:
            minor, model = get_minor_version_upgrade(model)
            msg = save_upgraded_version_model(model)
            msg_list.append(msg)
        else:
            return_error(msg)

    elif (demisto_major_version == MAJOR_VERSION):
        model = load_demisto_model()
        success, msg = model.add_new_logo(logo_name, logo_url)
        msg_list.append(msg)
        if success:
            minor, model = get_minor_version_upgrade(model)
            msg = save_upgraded_version_model(model)
            msg_list.append(msg)
        else:
            return_error(msg)

    elif (demisto_major_version < MAJOR_VERSION) and (demisto_minor_version > MINOR_DEFAULT_VERSION):
        model_docker = load_model_from_docker()
        model_demisto = load_demisto_model()
        model_docker.logos_dict = model_demisto.logos_dict
        msg_list.append(MSG_TRANSFER_LOGO)
        success, msg = model_docker.add_new_logo(logo_name, logo_url)
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
    return msg_list


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
