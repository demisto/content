import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import dill
#remove patch version 0,0

MAJOR_VERSION = 0

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


def get_minor_version_upgrade(model):
    model.minor = model.minor + 1
    return model.minor, model

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
                                                   'modelLabels': [MALICIOUS_VERDICT, BENIGN_VERDICT, SUSPICIOUS_VERDICT],
                                                   'modelOverride': 'true',
                                                   'modelHidden': True,
                                                   'modelType': 'url_phishing',
                                                   'modelExtraInfo': {
                                                       OOB_MAJOR_VERSION_INFO_KEY: MAJOR_VERSION,
                                                       OOB_MINOR_VERSION_INFO_KEY: MINOR_DEFAULT_VERSION
                                                   }
                                                   })
    if is_error(res):
        return_error(get_error(res))



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

def load_oob_model_from_model64(encoded_model, major=MAJOR_VERSION, minor=MINOR_DEFAULT_VERSION):
    """
    Load and save model from the model in the docker
    :return: None
    """
    res = demisto.executeCommand('createMLModel', {'modelData': encoded_model.decode('utf-8'),
                                                   'modelName': URL_PHISHING_MODEL_NAME,
                                                   'modelLabels': [MALICIOUS_VERDICT, BENIGN_VERDICT],
                                                   'modelOverride': 'true',
                                                   'modelHidden': True,
                                                   'modelType': 'url_phishing',
                                                   'modelExtraInfo': {
                                                       OOB_MAJOR_VERSION_INFO_KEY: major,
                                                       OOB_MINOR_VERSION_INFO_KEY: MINOR_DEFAULT_VERSION
                                                   }
                                                   })
    if is_error(res):
        return_error(get_error(res))

def save_upgraded_minor_model(model, new_minor_version):
    model_bytes = dill.dumps(model)
    model_64 = base64.b64encode(model_bytes)
    load_oob_model_from_model64(model_64, model.major, new_minor_version)


def get_model_data(model_name: str) -> Union[str, str]:
    """
    Return model data saved in demisto (string of encoded base 64)
    :param model_name: name of the model to load from demisto
    :return: str, str
    """
    res_model = demisto.executeCommand("getMLModel", {"modelName": model_name})[0]
    if is_error(res_model):
        handle_error("error reading model %s from Demisto" % model_name)
    else:
        model_data = res_model['Contents']['modelData']
        try:
            model_type = res_model['Contents']['model']["type"]["type"]
            return model_data, model_type
        except Exception:
            return model_data, UNKNOWN_MODEL_TYPE




def oob_model_exists_and_updated() -> bool:
    """
    Check is the model exist and is updated in demisto
    :return: book
    """
    res_model = demisto.executeCommand("getMLModel", {"modelName": URL_PHISHING_MODEL_NAME})[0]
    if is_error(res_model):
        return False, None, None
    existing_model_version_major = 0#res_model['Contents']['model']['extra'].get(OOB_MAJOR_VERSION_INFO_KEY, -1)
    existing_model_version_minor = 0#res_model['Contents']['model']['extra'].get(OOB_MINOR_VERSION_INFO_KEY, -1)
    return True, existing_model_version_major, existing_model_version_minor



def load_demisto_model():
    model_64_str = get_model_data(URL_PHISHING_MODEL_NAME)[0]
    model = decode_model_data(model_64_str)
    return model


def decode_model_data(model_data: str):
    """
    Decode the base 64 version of the model
    :param model_data: string of the encoded based 64 model
    :return: Model
    """
    return dill.loads(base64.b64decode(model_data.encode('utf-8')))


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
                                                   OOB_MINOR_VERSION_INFO_KEY: model.minor
                                               }
                                               })
    if is_error(res):
        return_error(get_error(res))


def load_model_from_docker(path=OUT_OF_THE_BOX_MODEL_PATH):
    model = dill.load(open(path, 'rb'))
    return model



def main():
    # model = load_demisto_model()
    # demisto.results(model.logos_dict)
    # sys.exit(0)


    logo_url = demisto.args().get('logoImageURL', '')
    logo_name = demisto.args().get('logoName', '')

    if not logo_url or not logo_name:
        return_error(MSG_EMPTY_NAME_OR_URL)

    exist, demisto_major_version, demisto_minor_version = oob_model_exists_and_updated()

    demisto.results(exist)
    demisto.results(demisto_major_version)
    demisto.results(demisto_minor_version)




    if not exist or (demisto_major_version < MAJOR_VERSION and demisto_minor_version == MINOR_DEFAULT_VERSION):
        model = load_model_from_docker()
        success, msg = model.add_new_logo(logo_name, logo_url)
        if success:
            minor, model = get_minor_version_upgrade(model)
            save_upgraded_minor_model(model, minor)
        else:
            return_error(msg)
        save_model_in_demisto(model)
        demisto.results(msg)


    elif (demisto_major_version == MAJOR_VERSION):
        model = load_demisto_model()
        success, msg = model.add_new_logo(logo_name, logo_url)
        demisto.results(success)
        #demisto.results(list(model.logos_dict.keys()))
        if success:
            minor, model = get_minor_version_upgrade(model)
            save_upgraded_minor_model(model, minor)
        else:
            return_error(msg)
        save_model_in_demisto(model)
        demisto.results(msg)



    elif (demisto_major_version < MAJOR_VERSION) and (demisto_minor_version > MINOR_DEFAULT_VERSION):
        model_docker = load_model_from_docker()
        model =  load_demisto_model()
        model_docker.logos_dict = model.logos_dict
        success,msg = model.add_new_logo(logo_name, logo_url)
        if success:
            minor, model = get_minor_version_upgrade(model)
            save_upgraded_minor_model(model, minor)
        else:
            return_error(msg)
        save_model_in_demisto(model)
        demisto.results(msg)

    else:
        return_error('Wrong configuration of the model')



if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()